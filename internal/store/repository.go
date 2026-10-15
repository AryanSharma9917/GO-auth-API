package store

import (
	"context"
	"errors"

	"golang-auth/internal/domain"

	"go.mongodb.org/mongo-driver/v2/bson"
)

var ErrNotFound = errors.New("record not found")
var ErrConflict = errors.New("record already exists")

type UserRepository interface {
	Create(context.Context, domain.User) (domain.User, error)
	ByID(context.Context, bson.ObjectID) (domain.User, error)
	ByEmail(context.Context, string) (domain.User, error)
	Delete(context.Context, bson.ObjectID) error
}

type OrganizationRepository interface {
	Create(context.Context, domain.Organization) (domain.Organization, error)
	ByID(context.Context, bson.ObjectID) (domain.Organization, error)
	BySlug(context.Context, string) (domain.Organization, error)
	Delete(context.Context, bson.ObjectID) error
}

type MembershipRepository interface {
	Create(context.Context, domain.Membership) (domain.Membership, error)
	ByUserAndOrganization(context.Context, bson.ObjectID, bson.ObjectID) (domain.Membership, error)
	Delete(context.Context, bson.ObjectID) error
}

type SessionRepository interface {
	Create(context.Context, domain.Session) (domain.Session, error)
	ByRefreshTokenHash(context.Context, string) (domain.Session, error)
}

type InvitationRepository interface {
	Create(context.Context, domain.Invitation) (domain.Invitation, error)
	ByTokenHash(context.Context, string) (domain.Invitation, error)
}

type AuditRepository interface {
	Create(context.Context, domain.AuditEvent) (domain.AuditEvent, error)
}
