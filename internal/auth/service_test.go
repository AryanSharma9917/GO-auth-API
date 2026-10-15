package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang-auth/internal/domain"
	"golang-auth/internal/store"

	"go.mongodb.org/mongo-driver/v2/bson"
)

type userRepositoryStub struct {
	created domain.User
	user    domain.User
	err     error
	deleted bool
}

func (r *userRepositoryStub) Create(_ context.Context, user domain.User) (domain.User, error) {
	if r.err != nil {
		return domain.User{}, r.err
	}
	user.ID = bson.NewObjectID()
	r.created = user
	r.user = user
	return user, nil
}
func (r *userRepositoryStub) ByID(context.Context, bson.ObjectID) (domain.User, error) {
	return r.user, r.err
}
func (r *userRepositoryStub) ByEmail(context.Context, string) (domain.User, error) {
	return r.user, r.err
}
func (r *userRepositoryStub) Delete(context.Context, bson.ObjectID) error {
	r.deleted = true
	return nil
}

type organizationRepositoryStub struct {
	created domain.Organization
	org     domain.Organization
	deleted bool
}

func (r *organizationRepositoryStub) Create(_ context.Context, organization domain.Organization) (domain.Organization, error) {
	organization.ID = bson.NewObjectID()
	r.created = organization
	r.org = organization
	return organization, nil
}
func (r *organizationRepositoryStub) ByID(context.Context, bson.ObjectID) (domain.Organization, error) {
	return r.org, nil
}
func (r *organizationRepositoryStub) BySlug(context.Context, string) (domain.Organization, error) {
	return r.org, nil
}
func (r *organizationRepositoryStub) Delete(context.Context, bson.ObjectID) error {
	r.deleted = true
	return nil
}

type membershipRepositoryStub struct {
	created    domain.Membership
	membership domain.Membership
}

func (r *membershipRepositoryStub) Create(_ context.Context, membership domain.Membership) (domain.Membership, error) {
	membership.ID = bson.NewObjectID()
	r.created = membership
	r.membership = membership
	return membership, nil
}
func (r *membershipRepositoryStub) ByUserAndOrganization(context.Context, bson.ObjectID, bson.ObjectID) (domain.Membership, error) {
	return r.membership, nil
}
func (r *membershipRepositoryStub) Delete(context.Context, bson.ObjectID) error { return nil }

type passwordStub struct{}

func (passwordStub) Hash(value string) (string, error) { return "hashed:" + value, nil }
func (passwordStub) Matches(hash, value string) bool   { return hash == "hashed:"+value }

type tokenStub struct{}

func (tokenStub) Issue(string, string, domain.Role) (string, error) { return "access-token", nil }

func TestRegisterCreatesNormalizedOwner(t *testing.T) {
	users := &userRepositoryStub{}
	organizations := &organizationRepositoryStub{}
	memberships := &membershipRepositoryStub{}
	service := NewService(users, organizations, memberships, passwordStub{}, tokenStub{})

	result, err := service.Register(context.Background(), RegisterInput{
		OrganizationName: " Example Company ", OrganizationSlug: " Example-Company ",
		Email: " Owner@Example.com ", DisplayName: " Example Owner ", Password: "a-secure-password",
	}, 15*time.Minute)
	if err != nil {
		t.Fatalf("register owner: %v", err)
	}
	if result.Membership.Role != domain.RoleOwner || result.Membership.State != domain.MembershipActive {
		t.Fatalf("unexpected membership: %+v", result.Membership)
	}
	if users.created.Email != "owner@example.com" || users.created.PasswordHash != "hashed:a-secure-password" {
		t.Fatalf("unexpected user: %+v", users.created)
	}
	if organizations.created.Slug != "example-company" {
		t.Fatalf("unexpected organization slug: %s", organizations.created.Slug)
	}
}

func TestRegisterRollsBackOrganizationWhenUserConflicts(t *testing.T) {
	users := &userRepositoryStub{err: store.ErrConflict}
	organizations := &organizationRepositoryStub{}
	service := NewService(users, organizations, &membershipRepositoryStub{}, passwordStub{}, tokenStub{})

	_, err := service.Register(context.Background(), RegisterInput{
		OrganizationName: "Example", OrganizationSlug: "example", Email: "owner@example.com",
		DisplayName: "Owner", Password: "a-secure-password",
	}, 15*time.Minute)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	if !organizations.deleted {
		t.Fatal("expected organization rollback")
	}
}

func TestLoginRejectsUnknownUser(t *testing.T) {
	users := &userRepositoryStub{err: store.ErrNotFound}
	organizations := &organizationRepositoryStub{org: domain.Organization{ID: bson.NewObjectID(), Slug: "example"}}
	service := NewService(users, organizations, &membershipRepositoryStub{}, passwordStub{}, tokenStub{})

	_, err := service.Login(context.Background(), LoginInput{OrganizationSlug: "example", Email: "missing@example.com", Password: "a-secure-password"}, 15*time.Minute)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
}
