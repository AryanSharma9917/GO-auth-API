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
)

var (
	ErrInvalidInput       = errors.New("invalid input")
	ErrConflict           = errors.New("account or organization already exists")
	ErrInvalidCredentials = errors.New("invalid email, password, or organization")
)

var slugPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

type PasswordHasher interface {
	Hash(string) (string, error)
	Matches(string, string) bool
}

type AccessTokenIssuer interface {
	Issue(userID, organizationID string, role domain.Role) (string, error)
}

type Service struct {
	users         store.UserRepository
	organizations store.OrganizationRepository
	memberships   store.MembershipRepository
	passwords     PasswordHasher
	tokens        AccessTokenIssuer
	now           func() time.Time
}

type RegisterInput struct {
	OrganizationName string
	OrganizationSlug string
	Email            string
	DisplayName      string
	Password         string
}

type LoginInput struct {
	OrganizationSlug string
	Email            string
	Password         string
}

type Result struct {
	AccessToken  string
	ExpiresIn    time.Duration
	User         domain.User
	Organization domain.Organization
	Membership   domain.Membership
}

func NewService(users store.UserRepository, organizations store.OrganizationRepository, memberships store.MembershipRepository, passwords PasswordHasher, tokens AccessTokenIssuer) *Service {
	return &Service{users: users, organizations: organizations, memberships: memberships, passwords: passwords, tokens: tokens, now: time.Now}
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
	return Result{AccessToken: accessToken, ExpiresIn: accessTokenTTL, User: user, Organization: organization, Membership: membership}, nil
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
	return Result{AccessToken: accessToken, ExpiresIn: accessTokenTTL, User: user, Organization: organization, Membership: membership}, nil
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
