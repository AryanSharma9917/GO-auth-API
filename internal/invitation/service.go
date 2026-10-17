package invitation

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"golang-auth/internal/domain"
	"golang-auth/internal/mailer"
	"golang-auth/internal/password"
	"golang-auth/internal/store"

	"go.mongodb.org/mongo-driver/v2/bson"
)

var (
	ErrInvalidInput      = errors.New("invalid input")
	ErrForbidden         = errors.New("operation is not permitted")
	ErrConflict          = errors.New("pending invitation or membership already exists")
	ErrNotFound          = errors.New("invitation not found")
	ErrInvalidInvitation = errors.New("invitation is invalid or expired")
)

type UserRepository interface {
	Create(context.Context, domain.User) (domain.User, error)
	ByID(context.Context, bson.ObjectID) (domain.User, error)
	ByEmail(context.Context, string) (domain.User, error)
	Delete(context.Context, bson.ObjectID) error
}

type OrganizationRepository interface {
	ByID(context.Context, bson.ObjectID) (domain.Organization, error)
}

type MembershipRepository interface {
	Create(context.Context, domain.Membership) (domain.Membership, error)
	ByUserAndOrganization(context.Context, bson.ObjectID, bson.ObjectID) (domain.Membership, error)
	Delete(context.Context, bson.ObjectID) error
}

type InvitationRepository interface {
	Create(context.Context, domain.Invitation) (domain.Invitation, error)
	ByIDForOrganization(context.Context, bson.ObjectID, bson.ObjectID) (domain.Invitation, error)
	ListForOrganization(context.Context, bson.ObjectID, bson.ObjectID, int64) ([]domain.Invitation, error)
	Claim(context.Context, string, time.Time) (domain.Invitation, error)
	Complete(context.Context, bson.ObjectID, time.Time) error
	Release(context.Context, bson.ObjectID) error
	Revoke(context.Context, bson.ObjectID, time.Time) error
}

type PasswordHasher interface {
	Hash(string) (string, error)
	Matches(string, string) bool
}

type TokenManager interface {
	Generate() (raw string, hash string, err error)
	Hash(string) string
}

type Service struct {
	users         UserRepository
	organizations OrganizationRepository
	memberships   MembershipRepository
	invitations   InvitationRepository
	passwords     PasswordHasher
	tokens        TokenManager
	mailer        mailer.Sender
	ttl           time.Duration
	now           func() time.Time
}

type Actor struct {
	UserID         string
	OrganizationID string
}

type CreateInput struct {
	Email string
	Role  domain.Role
}

type AcceptInput struct {
	DisplayName string
	Password    string
}

type Page struct {
	Invitations []domain.Invitation
	NextCursor  string
}

type Acceptance struct {
	User         domain.User
	Organization domain.Organization
	Membership   domain.Membership
}

func NewService(users UserRepository, organizations OrganizationRepository, memberships MembershipRepository, invitations InvitationRepository, passwords PasswordHasher, tokens TokenManager, sender mailer.Sender, ttl time.Duration) *Service {
	return &Service{users: users, organizations: organizations, memberships: memberships, invitations: invitations, passwords: passwords, tokens: tokens, mailer: sender, ttl: ttl, now: time.Now}
}

func (s *Service) Create(ctx context.Context, actor Actor, input CreateInput) (domain.Invitation, error) {
	organizationID, actorMembership, err := s.authorize(ctx, actor)
	if err != nil {
		return domain.Invitation{}, err
	}
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	if !validEmail(input.Email) || (input.Role != domain.RoleMember && input.Role != domain.RoleAdmin) {
		return domain.Invitation{}, ErrInvalidInput
	}
	if actorMembership.Role == domain.RoleAdmin && input.Role != domain.RoleMember {
		return domain.Invitation{}, ErrForbidden
	}
	if user, err := s.users.ByEmail(ctx, input.Email); err == nil {
		if _, err := s.memberships.ByUserAndOrganization(ctx, user.ID, organizationID); err == nil {
			return domain.Invitation{}, ErrConflict
		} else if !errors.Is(err, store.ErrNotFound) {
			return domain.Invitation{}, fmt.Errorf("find existing membership: %w", err)
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		return domain.Invitation{}, fmt.Errorf("find invited user: %w", err)
	}
	rawToken, tokenHash, err := s.tokens.Generate()
	if err != nil {
		return domain.Invitation{}, err
	}
	now := s.now().UTC()
	invitation, err := s.invitations.Create(ctx, domain.Invitation{
		OrganizationID: organizationID, Email: input.Email, Role: input.Role, Status: domain.InvitationPending, TokenHash: tokenHash,
		InvitedBy: actorMembership.UserID, ExpiresAt: now.Add(s.ttl), CreatedAt: now,
	})
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			return domain.Invitation{}, ErrConflict
		}
		return domain.Invitation{}, fmt.Errorf("create invitation: %w", err)
	}
	organization, err := s.organizations.ByID(ctx, organizationID)
	if err != nil {
		_ = s.invitations.Revoke(context.WithoutCancel(ctx), invitation.ID, now)
		return domain.Invitation{}, fmt.Errorf("find organization: %w", err)
	}
	inviter, err := s.users.ByID(ctx, actorMembership.UserID)
	if err != nil {
		_ = s.invitations.Revoke(context.WithoutCancel(ctx), invitation.ID, now)
		return domain.Invitation{}, fmt.Errorf("find inviter: %w", err)
	}
	if err := s.mailer.SendInvitation(ctx, mailer.Invitation{Recipient: invitation.Email, OrganizationName: organization.Name, InviterName: inviter.DisplayName, Role: string(invitation.Role), Token: rawToken}); err != nil {
		_ = s.invitations.Revoke(context.WithoutCancel(ctx), invitation.ID, now)
		return domain.Invitation{}, fmt.Errorf("send invitation: %w", err)
	}
	return invitation, nil
}

func (s *Service) List(ctx context.Context, actor Actor, cursor string, limit int) (Page, error) {
	organizationID, _, err := s.authorize(ctx, actor)
	if err != nil {
		return Page{}, err
	}
	if limit == 0 {
		limit = 20
	}
	if limit < 1 || limit > 100 {
		return Page{}, ErrInvalidInput
	}
	var after bson.ObjectID
	if cursor != "" {
		after, err = bson.ObjectIDFromHex(cursor)
		if err != nil {
			return Page{}, ErrInvalidInput
		}
	}
	items, err := s.invitations.ListForOrganization(ctx, organizationID, after, int64(limit+1))
	if err != nil {
		return Page{}, fmt.Errorf("list invitations: %w", err)
	}
	next := ""
	if len(items) > limit {
		next = items[limit-1].ID.Hex()
		items = items[:limit]
	}
	return Page{Invitations: items, NextCursor: next}, nil
}

func (s *Service) Revoke(ctx context.Context, actor Actor, invitationID string) error {
	organizationID, _, err := s.authorize(ctx, actor)
	if err != nil {
		return err
	}
	id, err := bson.ObjectIDFromHex(invitationID)
	if err != nil {
		return ErrNotFound
	}
	invitation, err := s.invitations.ByIDForOrganization(ctx, id, organizationID)
	if err != nil {
		return mapNotFound(err)
	}
	if err := s.invitations.Revoke(ctx, invitation.ID, s.now().UTC()); err != nil {
		return mapNotFound(err)
	}
	return nil
}

func (s *Service) Accept(ctx context.Context, rawToken string, input AcceptInput) (Acceptance, error) {
	if rawToken == "" {
		return Acceptance{}, ErrInvalidInvitation
	}
	now := s.now().UTC()
	invitation, err := s.invitations.Claim(ctx, s.tokens.Hash(rawToken), now)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Acceptance{}, ErrInvalidInvitation
		}
		return Acceptance{}, fmt.Errorf("claim invitation: %w", err)
	}
	completed := false
	defer func() {
		if !completed {
			_ = s.invitations.Release(context.WithoutCancel(ctx), invitation.ID)
		}
	}()

	user, newUser, err := s.resolveUser(ctx, invitation.Email, input)
	if err != nil {
		return Acceptance{}, err
	}
	if _, err := s.memberships.ByUserAndOrganization(ctx, user.ID, invitation.OrganizationID); err == nil {
		if newUser {
			_ = s.users.Delete(context.WithoutCancel(ctx), user.ID)
		}
		return Acceptance{}, ErrConflict
	} else if !errors.Is(err, store.ErrNotFound) {
		return Acceptance{}, fmt.Errorf("find membership: %w", err)
	}
	membership, err := s.memberships.Create(ctx, domain.Membership{
		OrganizationID: invitation.OrganizationID, UserID: user.ID, Role: invitation.Role,
		State: domain.MembershipActive, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		if newUser {
			_ = s.users.Delete(context.WithoutCancel(ctx), user.ID)
		}
		return Acceptance{}, fmt.Errorf("create membership: %w", err)
	}
	if err := s.invitations.Complete(ctx, invitation.ID, now); err != nil {
		cleanupCtx := context.WithoutCancel(ctx)
		_ = s.memberships.Delete(cleanupCtx, membership.ID)
		if newUser {
			_ = s.users.Delete(cleanupCtx, user.ID)
		}
		return Acceptance{}, fmt.Errorf("complete invitation: %w", err)
	}
	completed = true
	organization, err := s.organizations.ByID(ctx, invitation.OrganizationID)
	if err != nil {
		return Acceptance{}, fmt.Errorf("find organization: %w", err)
	}
	return Acceptance{User: user, Organization: organization, Membership: membership}, nil
}

func (s *Service) resolveUser(ctx context.Context, email string, input AcceptInput) (domain.User, bool, error) {
	user, err := s.users.ByEmail(ctx, email)
	if err == nil {
		if !s.passwords.Matches(user.PasswordHash, input.Password) {
			return domain.User{}, false, ErrInvalidInvitation
		}
		return user, false, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return domain.User{}, false, fmt.Errorf("find invited user: %w", err)
	}
	displayName := strings.TrimSpace(input.DisplayName)
	if displayName == "" {
		return domain.User{}, false, ErrInvalidInput
	}
	passwordHash, err := s.passwords.Hash(input.Password)
	if err != nil {
		if errors.Is(err, password.ErrInvalidLength) {
			return domain.User{}, false, ErrInvalidInput
		}
		return domain.User{}, false, fmt.Errorf("hash password: %w", err)
	}
	user, err = s.users.Create(ctx, domain.User{Email: email, DisplayName: displayName, PasswordHash: passwordHash, EmailVerified: true, CreatedAt: s.now().UTC(), UpdatedAt: s.now().UTC()})
	if err != nil {
		return domain.User{}, false, fmt.Errorf("create invited user: %w", err)
	}
	return user, true, nil
}

func (s *Service) authorize(ctx context.Context, actor Actor) (bson.ObjectID, domain.Membership, error) {
	userID, err := bson.ObjectIDFromHex(actor.UserID)
	if err != nil {
		return bson.NilObjectID, domain.Membership{}, ErrForbidden
	}
	organizationID, err := bson.ObjectIDFromHex(actor.OrganizationID)
	if err != nil {
		return bson.NilObjectID, domain.Membership{}, ErrForbidden
	}
	membership, err := s.memberships.ByUserAndOrganization(ctx, userID, organizationID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return bson.NilObjectID, domain.Membership{}, ErrForbidden
		}
		return bson.NilObjectID, domain.Membership{}, fmt.Errorf("find actor membership: %w", err)
	}
	if membership.State != domain.MembershipActive || (membership.Role != domain.RoleOwner && membership.Role != domain.RoleAdmin) {
		return bson.NilObjectID, domain.Membership{}, ErrForbidden
	}
	return organizationID, membership, nil
}

func validEmail(value string) bool {
	address, err := mail.ParseAddress(value)
	return err == nil && address.Address == value
}

func mapNotFound(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotFound
	}
	return err
}
