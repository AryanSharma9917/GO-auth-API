package organization

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang-auth/internal/domain"
	"golang-auth/internal/store"

	"go.mongodb.org/mongo-driver/v2/bson"
)

var (
	ErrInvalidInput = errors.New("invalid input")
	ErrForbidden    = errors.New("operation is not permitted")
	ErrNotFound     = errors.New("organization member not found")
	ErrLastOwner    = errors.New("organization must retain an active owner")
)

const (
	defaultPageSize = 20
	maximumPageSize = 100
)

type Service struct {
	users         UserRepository
	organizations OrganizationRepository
	memberships   MembershipRepository
	sessions      SessionRepository
	now           func() time.Time
}

type UserRepository interface {
	ByID(context.Context, bson.ObjectID) (domain.User, error)
	ByIDs(context.Context, []bson.ObjectID) ([]domain.User, error)
}

type OrganizationRepository interface {
	ByID(context.Context, bson.ObjectID) (domain.Organization, error)
	UpdateName(context.Context, bson.ObjectID, string, time.Time) (domain.Organization, error)
}

type MembershipRepository interface {
	ByUserAndOrganization(context.Context, bson.ObjectID, bson.ObjectID) (domain.Membership, error)
	ByIDForOrganization(context.Context, bson.ObjectID, bson.ObjectID) (domain.Membership, error)
	ListForOrganization(context.Context, bson.ObjectID, bson.ObjectID, int64) ([]domain.Membership, error)
	CountActiveOwners(context.Context, bson.ObjectID) (int64, error)
	Update(context.Context, bson.ObjectID, domain.Role, domain.MembershipState, time.Time) (domain.Membership, error)
	Delete(context.Context, bson.ObjectID) error
}

type SessionRepository interface {
	RevokeAll(context.Context, bson.ObjectID, bson.ObjectID, time.Time, string) error
}

type Actor struct {
	UserID         string
	OrganizationID string
}

type Member struct {
	Membership domain.Membership
	User       domain.User
}

type MemberPage struct {
	Members    []Member
	NextCursor string
}

type UpdateMemberInput struct {
	Role  *domain.Role
	State *domain.MembershipState
}

func NewService(users UserRepository, organizations OrganizationRepository, memberships MembershipRepository, sessions SessionRepository) *Service {
	return &Service{users: users, organizations: organizations, memberships: memberships, sessions: sessions, now: time.Now}
}

func (s *Service) Current(ctx context.Context, actor Actor) (domain.Organization, domain.Membership, error) {
	organizationID, membership, err := s.authorize(ctx, actor)
	if err != nil {
		return domain.Organization{}, domain.Membership{}, err
	}
	organization, err := s.organizations.ByID(ctx, organizationID)
	if err != nil {
		return domain.Organization{}, domain.Membership{}, mapNotFound("find organization", err)
	}
	return organization, membership, nil
}

func (s *Service) UpdateName(ctx context.Context, actor Actor, name string) (domain.Organization, error) {
	organizationID, membership, err := s.authorize(ctx, actor)
	if err != nil {
		return domain.Organization{}, err
	}
	if membership.Role != domain.RoleOwner {
		return domain.Organization{}, ErrForbidden
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 120 {
		return domain.Organization{}, ErrInvalidInput
	}
	organization, err := s.organizations.UpdateName(ctx, organizationID, name, s.now().UTC())
	if err != nil {
		return domain.Organization{}, mapNotFound("update organization", err)
	}
	return organization, nil
}

func (s *Service) Members(ctx context.Context, actor Actor, cursor string, limit int) (MemberPage, error) {
	organizationID, _, err := s.authorize(ctx, actor)
	if err != nil {
		return MemberPage{}, err
	}
	if limit == 0 {
		limit = defaultPageSize
	}
	if limit < 1 || limit > maximumPageSize {
		return MemberPage{}, ErrInvalidInput
	}
	var after bson.ObjectID
	if cursor != "" {
		after, err = bson.ObjectIDFromHex(cursor)
		if err != nil {
			return MemberPage{}, ErrInvalidInput
		}
	}
	memberships, err := s.memberships.ListForOrganization(ctx, organizationID, after, int64(limit+1))
	if err != nil {
		return MemberPage{}, fmt.Errorf("list memberships: %w", err)
	}
	nextCursor := ""
	if len(memberships) > limit {
		nextCursor = memberships[limit-1].ID.Hex()
		memberships = memberships[:limit]
	}
	userIDs := make([]bson.ObjectID, len(memberships))
	for index, membership := range memberships {
		userIDs[index] = membership.UserID
	}
	users, err := s.users.ByIDs(ctx, userIDs)
	if err != nil {
		return MemberPage{}, fmt.Errorf("find member users: %w", err)
	}
	usersByID := make(map[bson.ObjectID]domain.User, len(users))
	for _, user := range users {
		usersByID[user.ID] = user
	}
	members := make([]Member, 0, len(memberships))
	for _, membership := range memberships {
		user, ok := usersByID[membership.UserID]
		if ok {
			members = append(members, Member{Membership: membership, User: user})
		}
	}
	return MemberPage{Members: members, NextCursor: nextCursor}, nil
}

func (s *Service) UpdateMember(ctx context.Context, actor Actor, membershipID string, input UpdateMemberInput) (Member, error) {
	organizationID, actorMembership, err := s.authorize(ctx, actor)
	if err != nil {
		return Member{}, err
	}
	target, err := s.membershipByID(ctx, membershipID, organizationID)
	if err != nil {
		return Member{}, err
	}
	role, state := target.Role, target.State
	if input.Role != nil {
		role = *input.Role
	}
	if input.State != nil {
		state = *input.State
	}
	if !validRole(role) || !validState(state) || (input.Role == nil && input.State == nil) {
		return Member{}, ErrInvalidInput
	}
	if err := canManage(actorMembership, target, role); err != nil {
		return Member{}, err
	}
	if target.Role == domain.RoleOwner && target.State == domain.MembershipActive && (role != domain.RoleOwner || state != domain.MembershipActive) {
		if err := s.requireAnotherOwner(ctx, organizationID); err != nil {
			return Member{}, err
		}
	}
	updated, err := s.memberships.Update(ctx, target.ID, role, state, s.now().UTC())
	if err != nil {
		return Member{}, mapNotFound("update membership", err)
	}
	if state == domain.MembershipDisabled {
		if err := s.sessions.RevokeAll(ctx, target.UserID, organizationID, s.now().UTC(), "membership disabled"); err != nil {
			return Member{}, fmt.Errorf("revoke member sessions: %w", err)
		}
	}
	user, err := s.users.ByID(ctx, target.UserID)
	if err != nil {
		return Member{}, mapNotFound("find member user", err)
	}
	return Member{Membership: updated, User: user}, nil
}

func (s *Service) RemoveMember(ctx context.Context, actor Actor, membershipID string) error {
	organizationID, actorMembership, err := s.authorize(ctx, actor)
	if err != nil {
		return err
	}
	target, err := s.membershipByID(ctx, membershipID, organizationID)
	if err != nil {
		return err
	}
	if err := canManage(actorMembership, target, target.Role); err != nil {
		return err
	}
	if target.Role == domain.RoleOwner && target.State == domain.MembershipActive {
		if err := s.requireAnotherOwner(ctx, organizationID); err != nil {
			return err
		}
	}
	if err := s.sessions.RevokeAll(ctx, target.UserID, organizationID, s.now().UTC(), "membership removed"); err != nil {
		return fmt.Errorf("revoke member sessions: %w", err)
	}
	if err := s.memberships.Delete(ctx, target.ID); err != nil {
		return mapNotFound("delete membership", err)
	}
	return nil
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
	if membership.State != domain.MembershipActive {
		return bson.NilObjectID, domain.Membership{}, ErrForbidden
	}
	return organizationID, membership, nil
}

func (s *Service) membershipByID(ctx context.Context, value string, organizationID bson.ObjectID) (domain.Membership, error) {
	id, err := bson.ObjectIDFromHex(value)
	if err != nil {
		return domain.Membership{}, ErrNotFound
	}
	membership, err := s.memberships.ByIDForOrganization(ctx, id, organizationID)
	if err != nil {
		return domain.Membership{}, mapNotFound("find membership", err)
	}
	return membership, nil
}

func (s *Service) requireAnotherOwner(ctx context.Context, organizationID bson.ObjectID) error {
	count, err := s.memberships.CountActiveOwners(ctx, organizationID)
	if err != nil {
		return fmt.Errorf("count organization owners: %w", err)
	}
	if count <= 1 {
		return ErrLastOwner
	}
	return nil
}

func canManage(actor, target domain.Membership, requestedRole domain.Role) error {
	switch actor.Role {
	case domain.RoleOwner:
		return nil
	case domain.RoleAdmin:
		if target.Role == domain.RoleMember && requestedRole == domain.RoleMember {
			return nil
		}
	}
	return ErrForbidden
}

func validRole(role domain.Role) bool {
	return role == domain.RoleOwner || role == domain.RoleAdmin || role == domain.RoleMember
}

func validState(state domain.MembershipState) bool {
	return state == domain.MembershipActive || state == domain.MembershipDisabled
}

func mapNotFound(operation string, err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotFound
	}
	return fmt.Errorf("%s: %w", operation, err)
}
