package store

import (
	"context"
	"errors"
	"time"

	"golang-auth/internal/domain"

	"go.mongodb.org/mongo-driver/v2/bson"
)

var ErrNotFound = errors.New("record not found")
var ErrConflict = errors.New("record already exists")

type UserRepository interface {
	Create(context.Context, domain.User) (domain.User, error)
	ByID(context.Context, bson.ObjectID) (domain.User, error)
	ByEmail(context.Context, string) (domain.User, error)
	ByIDs(context.Context, []bson.ObjectID) ([]domain.User, error)
	Delete(context.Context, bson.ObjectID) error
}

type OrganizationRepository interface {
	Create(context.Context, domain.Organization) (domain.Organization, error)
	ByID(context.Context, bson.ObjectID) (domain.Organization, error)
	BySlug(context.Context, string) (domain.Organization, error)
	UpdateName(context.Context, bson.ObjectID, string, time.Time) (domain.Organization, error)
	Delete(context.Context, bson.ObjectID) error
}

type MembershipRepository interface {
	Create(context.Context, domain.Membership) (domain.Membership, error)
	ByUserAndOrganization(context.Context, bson.ObjectID, bson.ObjectID) (domain.Membership, error)
	ByIDForOrganization(context.Context, bson.ObjectID, bson.ObjectID) (domain.Membership, error)
	ListForOrganization(context.Context, bson.ObjectID, bson.ObjectID, int64) ([]domain.Membership, error)
	CountActiveOwners(context.Context, bson.ObjectID) (int64, error)
	Update(context.Context, bson.ObjectID, domain.Role, domain.MembershipState, time.Time) (domain.Membership, error)
	Delete(context.Context, bson.ObjectID) error
}

type SessionRepository interface {
	Create(context.Context, domain.Session) (domain.Session, error)
	ByRefreshTokenHash(context.Context, string) (domain.Session, error)
	ByIDForPrincipal(context.Context, bson.ObjectID, bson.ObjectID, bson.ObjectID) (domain.Session, error)
	ListForPrincipal(context.Context, bson.ObjectID, bson.ObjectID) ([]domain.Session, error)
	Rotate(context.Context, bson.ObjectID, string, string, time.Time) error
	Revoke(context.Context, bson.ObjectID, time.Time, string) error
	RevokeAll(context.Context, bson.ObjectID, bson.ObjectID, time.Time, string) error
}

type InvitationRepository interface {
	Create(context.Context, domain.Invitation) (domain.Invitation, error)
	ByTokenHash(context.Context, string) (domain.Invitation, error)
	ByIDForOrganization(context.Context, bson.ObjectID, bson.ObjectID) (domain.Invitation, error)
	ListForOrganization(context.Context, bson.ObjectID, bson.ObjectID, int64) ([]domain.Invitation, error)
	Claim(context.Context, string, time.Time) (domain.Invitation, error)
	Complete(context.Context, bson.ObjectID, time.Time) error
	Release(context.Context, bson.ObjectID) error
	Revoke(context.Context, bson.ObjectID, time.Time) error
}

type AuditRepository interface {
	Create(context.Context, domain.AuditEvent) (domain.AuditEvent, error)
}
