package organization

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"golang-auth/internal/domain"
	"golang-auth/internal/store"

	"go.mongodb.org/mongo-driver/v2/bson"
)

type userRepositoryStub struct {
	users map[bson.ObjectID]domain.User
}

func (r *userRepositoryStub) ByID(_ context.Context, id bson.ObjectID) (domain.User, error) {
	user, ok := r.users[id]
	if !ok {
		return domain.User{}, store.ErrNotFound
	}
	return user, nil
}
func (r *userRepositoryStub) ByIDs(_ context.Context, ids []bson.ObjectID) ([]domain.User, error) {
	users := make([]domain.User, 0, len(ids))
	for _, id := range ids {
		if user, ok := r.users[id]; ok {
			users = append(users, user)
		}
	}
	return users, nil
}

type organizationRepositoryStub struct {
	organization domain.Organization
}

func (r *organizationRepositoryStub) ByID(_ context.Context, id bson.ObjectID) (domain.Organization, error) {
	if r.organization.ID != id {
		return domain.Organization{}, store.ErrNotFound
	}
	return r.organization, nil
}
func (r *organizationRepositoryStub) UpdateName(_ context.Context, id bson.ObjectID, name string, updatedAt time.Time) (domain.Organization, error) {
	if r.organization.ID != id {
		return domain.Organization{}, store.ErrNotFound
	}
	r.organization.Name = name
	r.organization.UpdatedAt = updatedAt
	return r.organization, nil
}

type membershipRepositoryStub struct {
	memberships map[bson.ObjectID]domain.Membership
}

func (r *membershipRepositoryStub) ByUserAndOrganization(_ context.Context, userID, organizationID bson.ObjectID) (domain.Membership, error) {
	for _, membership := range r.memberships {
		if membership.UserID == userID && membership.OrganizationID == organizationID {
			return membership, nil
		}
	}
	return domain.Membership{}, store.ErrNotFound
}
func (r *membershipRepositoryStub) ByIDForOrganization(_ context.Context, id, organizationID bson.ObjectID) (domain.Membership, error) {
	membership, ok := r.memberships[id]
	if !ok || membership.OrganizationID != organizationID {
		return domain.Membership{}, store.ErrNotFound
	}
	return membership, nil
}
func (r *membershipRepositoryStub) ListForOrganization(_ context.Context, organizationID, after bson.ObjectID, limit int64) ([]domain.Membership, error) {
	memberships := make([]domain.Membership, 0)
	for _, membership := range r.memberships {
		if membership.OrganizationID == organizationID && (after.IsZero() || bytes.Compare(membership.ID[:], after[:]) > 0) {
			memberships = append(memberships, membership)
		}
	}
	if int64(len(memberships)) > limit {
		memberships = memberships[:limit]
	}
	return memberships, nil
}
func (r *membershipRepositoryStub) CountActiveOwners(_ context.Context, organizationID bson.ObjectID) (int64, error) {
	var count int64
	for _, membership := range r.memberships {
		if membership.OrganizationID == organizationID && membership.Role == domain.RoleOwner && membership.State == domain.MembershipActive {
			count++
		}
	}
	return count, nil
}
func (r *membershipRepositoryStub) Update(_ context.Context, id bson.ObjectID, role domain.Role, state domain.MembershipState, updatedAt time.Time) (domain.Membership, error) {
	membership, ok := r.memberships[id]
	if !ok {
		return domain.Membership{}, store.ErrNotFound
	}
	membership.Role = role
	membership.State = state
	membership.UpdatedAt = updatedAt
	r.memberships[id] = membership
	return membership, nil
}
func (r *membershipRepositoryStub) Delete(_ context.Context, id bson.ObjectID) error {
	if _, ok := r.memberships[id]; !ok {
		return store.ErrNotFound
	}
	delete(r.memberships, id)
	return nil
}

type sessionRepositoryStub struct {
	revokedUser bson.ObjectID
}

func (r *sessionRepositoryStub) RevokeAll(_ context.Context, userID, _ bson.ObjectID, _ time.Time, _ string) error {
	r.revokedUser = userID
	return nil
}

type testFixture struct {
	service      *Service
	organization domain.Organization
	owner        domain.Membership
	admin        domain.Membership
	member       domain.Membership
	memberships  *membershipRepositoryStub
	sessions     *sessionRepositoryStub
}

func newFixture() testFixture {
	organizationValue := domain.Organization{ID: bson.NewObjectID(), Name: "Example", Slug: "example"}
	ownerUser := domain.User{ID: bson.NewObjectID(), Email: "owner@example.com"}
	adminUser := domain.User{ID: bson.NewObjectID(), Email: "admin@example.com"}
	memberUser := domain.User{ID: bson.NewObjectID(), Email: "member@example.com"}
	owner := domain.Membership{ID: bson.NewObjectID(), OrganizationID: organizationValue.ID, UserID: ownerUser.ID, Role: domain.RoleOwner, State: domain.MembershipActive}
	admin := domain.Membership{ID: bson.NewObjectID(), OrganizationID: organizationValue.ID, UserID: adminUser.ID, Role: domain.RoleAdmin, State: domain.MembershipActive}
	member := domain.Membership{ID: bson.NewObjectID(), OrganizationID: organizationValue.ID, UserID: memberUser.ID, Role: domain.RoleMember, State: domain.MembershipActive}
	users := &userRepositoryStub{users: map[bson.ObjectID]domain.User{ownerUser.ID: ownerUser, adminUser.ID: adminUser, memberUser.ID: memberUser}}
	memberships := &membershipRepositoryStub{memberships: map[bson.ObjectID]domain.Membership{owner.ID: owner, admin.ID: admin, member.ID: member}}
	sessions := &sessionRepositoryStub{}
	service := NewService(users, &organizationRepositoryStub{organization: organizationValue}, memberships, sessions)
	return testFixture{service: service, organization: organizationValue, owner: owner, admin: admin, member: member, memberships: memberships, sessions: sessions}
}

func actorFor(membership domain.Membership) Actor {
	return Actor{UserID: membership.UserID.Hex(), OrganizationID: membership.OrganizationID.Hex()}
}

func TestMemberCannotManageRoles(t *testing.T) {
	fixture := newFixture()
	role := domain.RoleAdmin
	_, err := fixture.service.UpdateMember(context.Background(), actorFor(fixture.member), fixture.member.ID.Hex(), UpdateMemberInput{Role: &role})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected forbidden error, got %v", err)
	}
}

func TestAdminCanDisableMemberButCannotPromoteThem(t *testing.T) {
	fixture := newFixture()
	disabled := domain.MembershipDisabled
	updated, err := fixture.service.UpdateMember(context.Background(), actorFor(fixture.admin), fixture.member.ID.Hex(), UpdateMemberInput{State: &disabled})
	if err != nil {
		t.Fatalf("disable member: %v", err)
	}
	if updated.Membership.State != domain.MembershipDisabled || fixture.sessions.revokedUser != fixture.member.UserID {
		t.Fatal("expected disabled membership and revoked sessions")
	}
	adminRole := domain.RoleAdmin
	if _, err := fixture.service.UpdateMember(context.Background(), actorFor(fixture.admin), fixture.member.ID.Hex(), UpdateMemberInput{Role: &adminRole}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected admin promotion to be forbidden, got %v", err)
	}
}

func TestFinalOwnerCannotBeDemotedOrRemoved(t *testing.T) {
	fixture := newFixture()
	memberRole := domain.RoleMember
	if _, err := fixture.service.UpdateMember(context.Background(), actorFor(fixture.owner), fixture.owner.ID.Hex(), UpdateMemberInput{Role: &memberRole}); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("expected last-owner error when demoting, got %v", err)
	}
	if err := fixture.service.RemoveMember(context.Background(), actorFor(fixture.owner), fixture.owner.ID.Hex()); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("expected last-owner error when removing, got %v", err)
	}
}

func TestCrossOrganizationMembershipIsNotVisible(t *testing.T) {
	fixture := newFixture()
	otherMembership := domain.Membership{ID: bson.NewObjectID(), OrganizationID: bson.NewObjectID(), UserID: bson.NewObjectID(), Role: domain.RoleMember, State: domain.MembershipActive}
	fixture.memberships.memberships[otherMembership.ID] = otherMembership
	if err := fixture.service.RemoveMember(context.Background(), actorFor(fixture.owner), otherMembership.ID.Hex()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not-found error, got %v", err)
	}
}
