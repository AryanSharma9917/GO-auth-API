package auth

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"golang-auth/internal/domain"
	"golang-auth/internal/password"
	"golang-auth/internal/store"

	"go.mongodb.org/mongo-driver/v2/bson"
)

var (
	ErrInvalidInput        = errors.New("invalid input")
	ErrConflict            = errors.New("account or organization already exists")
	ErrInvalidCredentials  = errors.New("invalid email, password, or organization")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrRefreshTokenReuse   = errors.New("refresh token reuse detected")
	ErrSessionNotFound     = errors.New("session not found")
)

var slugPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

type PasswordHasher interface {
	Hash(string) (string, error)
	Matches(string, string) bool
}

type AccessTokenIssuer interface {
	Issue(userID, organizationID string, role domain.Role) (string, error)
}

type RefreshTokenManager interface {
	Generate() (raw string, hash string, err error)
	Hash(string) string
}

type Service struct {
	users         store.UserRepository
	organizations store.OrganizationRepository
	memberships   store.MembershipRepository
	sessions      store.SessionRepository
	passwords     PasswordHasher
	tokens        AccessTokenIssuer
	refreshTokens RefreshTokenManager
	refreshTTL    time.Duration
	now           func() time.Time
}

type RegisterInput struct {
	OrganizationName string
	OrganizationSlug string
	Email            string
	DisplayName      string
	Password         string
	IPAddress        string
	UserAgent        string
}

type LoginInput struct {
	OrganizationSlug string
	Email            string
	Password         string
	IPAddress        string
	UserAgent        string
}

type Result struct {
	AccessToken      string
	RefreshToken     string
	ExpiresIn        time.Duration
	RefreshExpiresIn time.Duration
	User             domain.User
	Organization     domain.Organization
	Membership       domain.Membership
	Session          domain.Session
}

func NewService(users store.UserRepository, organizations store.OrganizationRepository, memberships store.MembershipRepository, sessions store.SessionRepository, passwords PasswordHasher, tokens AccessTokenIssuer, refreshTokens RefreshTokenManager, refreshTTL time.Duration) *Service {
	return &Service{users: users, organizations: organizations, memberships: memberships, sessions: sessions, passwords: passwords, tokens: tokens, refreshTokens: refreshTokens, refreshTTL: refreshTTL, now: time.Now}
}

func (s *Service) Register(ctx context.Context, input RegisterInput, accessTokenTTL time.Duration) (Result, error) {
	input.OrganizationName = strings.TrimSpace(input.OrganizationName)
	input.OrganizationSlug = strings.ToLower(strings.TrimSpace(input.OrganizationSlug))
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	if input.OrganizationName == "" || input.DisplayName == "" || !slugPattern.MatchString(input.OrganizationSlug) || !validEmail(input.Email) {
		return Result{}, ErrInvalidInput
	}

	passwordHash, err := s.passwords.Hash(input.Password)
	if err != nil {
		if errors.Is(err, password.ErrInvalidLength) {
			return Result{}, ErrInvalidInput
		}
		return Result{}, fmt.Errorf("hash password: %w", err)
	}

	now := s.now().UTC()
	organization, err := s.organizations.Create(ctx, domain.Organization{Name: input.OrganizationName, Slug: input.OrganizationSlug, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		return Result{}, registrationError("create organization", err)
	}

	user, err := s.users.Create(ctx, domain.User{Email: input.Email, DisplayName: input.DisplayName, PasswordHash: passwordHash, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		cleanupErr := s.organizations.Delete(context.WithoutCancel(ctx), organization.ID)
		return Result{}, errors.Join(registrationError("create user", err), cleanupErr)
	}

	membership, err := s.memberships.Create(ctx, domain.Membership{OrganizationID: organization.ID, UserID: user.ID, Role: domain.RoleOwner, State: domain.MembershipActive, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		cleanupCtx := context.WithoutCancel(ctx)
		return Result{}, errors.Join(registrationError("create owner membership", err), s.users.Delete(cleanupCtx, user.ID), s.organizations.Delete(cleanupCtx, organization.ID))
	}

	accessToken, err := s.tokens.Issue(user.ID.Hex(), organization.ID.Hex(), membership.Role)
	if err != nil {
		return Result{}, fmt.Errorf("issue access token: %w", err)
	}
	refreshToken, session, err := s.createSession(ctx, user.ID, organization.ID, input.IPAddress, input.UserAgent)
	if err != nil {
		cleanupCtx := context.WithoutCancel(ctx)
		return Result{}, errors.Join(err, s.memberships.Delete(cleanupCtx, membership.ID), s.users.Delete(cleanupCtx, user.ID), s.organizations.Delete(cleanupCtx, organization.ID))
	}
	return Result{AccessToken: accessToken, RefreshToken: refreshToken, ExpiresIn: accessTokenTTL, RefreshExpiresIn: s.refreshTTL, User: user, Organization: organization, Membership: membership, Session: session}, nil
}

func (s *Service) Login(ctx context.Context, input LoginInput, accessTokenTTL time.Duration) (Result, error) {
	email := strings.ToLower(strings.TrimSpace(input.Email))
	slug := strings.ToLower(strings.TrimSpace(input.OrganizationSlug))
	organization, err := s.organizations.BySlug(ctx, slug)
	if err != nil {
		return Result{}, loginError("find organization", err)
	}
	user, err := s.users.ByEmail(ctx, email)
	if err != nil {
		return Result{}, loginError("find user", err)
	}
	if user.DisabledAt != nil || !s.passwords.Matches(user.PasswordHash, input.Password) {
		return Result{}, ErrInvalidCredentials
	}
	membership, err := s.memberships.ByUserAndOrganization(ctx, user.ID, organization.ID)
	if err != nil {
		return Result{}, loginError("find membership", err)
	}
	if membership.State != domain.MembershipActive {
		return Result{}, ErrInvalidCredentials
	}
	accessToken, err := s.tokens.Issue(user.ID.Hex(), organization.ID.Hex(), membership.Role)
	if err != nil {
		return Result{}, fmt.Errorf("issue access token: %w", err)
	}
	refreshToken, session, err := s.createSession(ctx, user.ID, organization.ID, input.IPAddress, input.UserAgent)
	if err != nil {
		return Result{}, err
	}
	return Result{AccessToken: accessToken, RefreshToken: refreshToken, ExpiresIn: accessTokenTTL, RefreshExpiresIn: s.refreshTTL, User: user, Organization: organization, Membership: membership, Session: session}, nil
}

func (s *Service) Refresh(ctx context.Context, rawToken string, accessTokenTTL time.Duration) (Result, error) {
	if rawToken == "" {
		return Result{}, ErrInvalidRefreshToken
	}
	hash := s.refreshTokens.Hash(rawToken)
	session, err := s.sessions.ByRefreshTokenHash(ctx, hash)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Result{}, ErrInvalidRefreshToken
		}
		return Result{}, fmt.Errorf("find session: %w", err)
	}
	now := s.now().UTC()
	if contains(session.UsedTokenHashes, hash) {
		_ = s.sessions.Revoke(context.WithoutCancel(ctx), session.ID, now, "refresh token reuse")
		return Result{}, ErrRefreshTokenReuse
	}
	if session.RefreshTokenHash != hash || session.RevokedAt != nil || !session.ExpiresAt.After(now) {
		return Result{}, ErrInvalidRefreshToken
	}

	user, organization, membership, err := s.sessionPrincipal(ctx, session)
	if err != nil {
		return Result{}, err
	}
	replacementToken, replacementHash, err := s.refreshTokens.Generate()
	if err != nil {
		return Result{}, err
	}
	accessToken, err := s.tokens.Issue(user.ID.Hex(), organization.ID.Hex(), membership.Role)
	if err != nil {
		return Result{}, fmt.Errorf("issue access token: %w", err)
	}
	if err := s.sessions.Rotate(ctx, session.ID, hash, replacementHash, now); err != nil {
		if errors.Is(err, store.ErrConflict) {
			_ = s.sessions.Revoke(context.WithoutCancel(ctx), session.ID, now, "concurrent refresh token reuse")
			return Result{}, ErrRefreshTokenReuse
		}
		return Result{}, fmt.Errorf("rotate session: %w", err)
	}
	session.UsedTokenHashes = append(session.UsedTokenHashes, hash)
	session.RefreshTokenHash = replacementHash
	session.LastUsedAt = now
	return Result{AccessToken: accessToken, RefreshToken: replacementToken, ExpiresIn: accessTokenTTL, RefreshExpiresIn: session.ExpiresAt.Sub(now), User: user, Organization: organization, Membership: membership, Session: session}, nil
}

func (s *Service) Logout(ctx context.Context, rawToken string) error {
	if rawToken == "" {
		return nil
	}
	session, err := s.sessions.ByRefreshTokenHash(ctx, s.refreshTokens.Hash(rawToken))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("find session: %w", err)
	}
	if err := s.sessions.Revoke(ctx, session.ID, s.now().UTC(), "logout"); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

func (s *Service) LogoutAll(ctx context.Context, userID, organizationID string) error {
	userObjectID, organizationObjectID, err := parsePrincipalIDs(userID, organizationID)
	if err != nil {
		return err
	}
	if err := s.sessions.RevokeAll(ctx, userObjectID, organizationObjectID, s.now().UTC(), "logout all"); err != nil {
		return fmt.Errorf("revoke all sessions: %w", err)
	}
	return nil
}

func (s *Service) Sessions(ctx context.Context, userID, organizationID string) ([]domain.Session, error) {
	userObjectID, organizationObjectID, err := parsePrincipalIDs(userID, organizationID)
	if err != nil {
		return nil, err
	}
	sessions, err := s.sessions.ListForPrincipal(ctx, userObjectID, organizationObjectID)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	return sessions, nil
}

func (s *Service) RevokeSession(ctx context.Context, sessionID, userID, organizationID string) error {
	id, err := bson.ObjectIDFromHex(sessionID)
	if err != nil {
		return ErrSessionNotFound
	}
	userObjectID, organizationObjectID, err := parsePrincipalIDs(userID, organizationID)
	if err != nil {
		return err
	}
	session, err := s.sessions.ByIDForPrincipal(ctx, id, userObjectID, organizationObjectID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrSessionNotFound
		}
		return fmt.Errorf("find session: %w", err)
	}
	if err := s.sessions.Revoke(ctx, session.ID, s.now().UTC(), "session revoked by user"); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

func (s *Service) createSession(ctx context.Context, userID, organizationID bson.ObjectID, ipAddress, userAgent string) (string, domain.Session, error) {
	raw, hash, err := s.refreshTokens.Generate()
	if err != nil {
		return "", domain.Session{}, err
	}
	_, familyID, err := s.refreshTokens.Generate()
	if err != nil {
		return "", domain.Session{}, err
	}
	now := s.now().UTC()
	session, err := s.sessions.Create(ctx, domain.Session{
		UserID: userID, OrganizationID: organizationID, RefreshTokenHash: hash, TokenFamilyID: familyID,
		IPAddress: ipAddress, UserAgent: userAgent, ExpiresAt: now.Add(s.refreshTTL), CreatedAt: now, LastUsedAt: now,
	})
	if err != nil {
		return "", domain.Session{}, fmt.Errorf("create session: %w", err)
	}
	return raw, session, nil
}

func (s *Service) sessionPrincipal(ctx context.Context, session domain.Session) (domain.User, domain.Organization, domain.Membership, error) {
	user, err := s.users.ByID(ctx, session.UserID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return domain.User{}, domain.Organization{}, domain.Membership{}, ErrInvalidRefreshToken
		}
		return domain.User{}, domain.Organization{}, domain.Membership{}, fmt.Errorf("find session user: %w", err)
	}
	if user.DisabledAt != nil {
		return domain.User{}, domain.Organization{}, domain.Membership{}, ErrInvalidRefreshToken
	}
	organization, err := s.organizations.ByID(ctx, session.OrganizationID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return domain.User{}, domain.Organization{}, domain.Membership{}, ErrInvalidRefreshToken
		}
		return domain.User{}, domain.Organization{}, domain.Membership{}, fmt.Errorf("find session organization: %w", err)
	}
	membership, err := s.memberships.ByUserAndOrganization(ctx, user.ID, organization.ID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return domain.User{}, domain.Organization{}, domain.Membership{}, ErrInvalidRefreshToken
		}
		return domain.User{}, domain.Organization{}, domain.Membership{}, fmt.Errorf("find session membership: %w", err)
	}
	if membership.State != domain.MembershipActive {
		return domain.User{}, domain.Organization{}, domain.Membership{}, ErrInvalidRefreshToken
	}
	return user, organization, membership, nil
}

func parsePrincipalIDs(userID, organizationID string) (bson.ObjectID, bson.ObjectID, error) {
	userObjectID, err := bson.ObjectIDFromHex(userID)
	if err != nil {
		return bson.NilObjectID, bson.NilObjectID, ErrInvalidInput
	}
	organizationObjectID, err := bson.ObjectIDFromHex(organizationID)
	if err != nil {
		return bson.NilObjectID, bson.NilObjectID, ErrInvalidInput
	}
	return userObjectID, organizationObjectID, nil
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func validEmail(value string) bool {
	address, err := mail.ParseAddress(value)
	return err == nil && address.Address == value
}

func registrationError(operation string, err error) error {
	if errors.Is(err, store.ErrConflict) {
		return ErrConflict
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func loginError(operation string, err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return ErrInvalidCredentials
	}
	return fmt.Errorf("%s: %w", operation, err)
}
