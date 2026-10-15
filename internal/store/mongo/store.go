package mongo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang-auth/internal/domain"
	basestore "golang-auth/internal/store"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const (
	usersCollection         = "users"
	organizationsCollection = "organizations"
	membershipsCollection   = "memberships"
	sessionsCollection      = "sessions"
	invitationsCollection   = "invitations"
	auditEventsCollection   = "audit_events"
)

type Store struct {
	database         *mongo.Database
	operationTimeout time.Duration
	Users            *UserRepository
	Organizations    *OrganizationRepository
	Memberships      *MembershipRepository
	Sessions         *SessionRepository
	Invitations      *InvitationRepository
	AuditEvents      *AuditRepository
}

func New(client *mongo.Client, databaseName string, operationTimeout time.Duration) *Store {
	database := client.Database(databaseName)
	return &Store{
		database:         database,
		operationTimeout: operationTimeout,
		Users:            &UserRepository{collection: database.Collection(usersCollection), timeout: operationTimeout},
		Organizations:    &OrganizationRepository{collection: database.Collection(organizationsCollection), timeout: operationTimeout},
		Memberships:      &MembershipRepository{collection: database.Collection(membershipsCollection), timeout: operationTimeout},
		Sessions:         &SessionRepository{collection: database.Collection(sessionsCollection), timeout: operationTimeout},
		Invitations:      &InvitationRepository{collection: database.Collection(invitationsCollection), timeout: operationTimeout},
		AuditEvents:      &AuditRepository{collection: database.Collection(auditEventsCollection), timeout: operationTimeout},
	}
}

func Connect(ctx context.Context, uri string) (*mongo.Client, error) {
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		return nil, fmt.Errorf("connect to MongoDB: %w", err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(ctx)
		return nil, fmt.Errorf("ping MongoDB: %w", err)
	}
	return client, nil
}

func (s *Store) EnsureIndexes(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()

	indexes := map[string][]mongo.IndexModel{
		usersCollection: {
			{Keys: bson.D{{Key: "email", Value: 1}}, Options: options.Index().SetUnique(true).SetPartialFilterExpression(bson.M{"email": bson.M{"$type": "string"}}).SetName("users_email_unique")},
		},
		organizationsCollection: {
			{Keys: bson.D{{Key: "slug", Value: 1}}, Options: options.Index().SetUnique(true).SetName("organizations_slug_unique")},
		},
		membershipsCollection: {
			{Keys: bson.D{{Key: "organizationId", Value: 1}, {Key: "userId", Value: 1}}, Options: options.Index().SetUnique(true).SetName("memberships_organization_user_unique")},
			{Keys: bson.D{{Key: "organizationId", Value: 1}, {Key: "role", Value: 1}}, Options: options.Index().SetName("memberships_organization_role")},
		},
		sessionsCollection: {
			{Keys: bson.D{{Key: "refreshTokenHash", Value: 1}}, Options: options.Index().SetUnique(true).SetName("sessions_refresh_token_hash_unique")},
			{Keys: bson.D{{Key: "usedTokenHashes", Value: 1}}, Options: options.Index().SetName("sessions_used_token_hashes")},
			{Keys: bson.D{{Key: "userId", Value: 1}, {Key: "organizationId", Value: 1}}, Options: options.Index().SetName("sessions_user_organization")},
			{Keys: bson.D{{Key: "expiresAt", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0).SetName("sessions_expiry_ttl")},
		},
		invitationsCollection: {
			{Keys: bson.D{{Key: "tokenHash", Value: 1}}, Options: options.Index().SetUnique(true).SetName("invitations_token_hash_unique")},
			{Keys: bson.D{{Key: "organizationId", Value: 1}, {Key: "email", Value: 1}}, Options: options.Index().SetName("invitations_organization_email")},
			{Keys: bson.D{{Key: "expiresAt", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0).SetName("invitations_expiry_ttl")},
		},
		auditEventsCollection: {
			{Keys: bson.D{{Key: "organizationId", Value: 1}, {Key: "createdAt", Value: -1}}, Options: options.Index().SetName("audit_events_organization_created")},
		},
	}

	for collectionName, models := range indexes {
		if _, err := s.database.Collection(collectionName).Indexes().CreateMany(ctx, models); err != nil {
			return fmt.Errorf("create indexes for %s: %w", collectionName, err)
		}
	}
	return nil
}

type UserRepository struct {
	collection *mongo.Collection
	timeout    time.Duration
}

func (r *UserRepository) Create(ctx context.Context, user domain.User) (domain.User, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	if user.ID.IsZero() {
		user.ID = bson.NewObjectID()
	}
	if _, err := r.collection.InsertOne(ctx, user); err != nil {
		return domain.User{}, repositoryError("insert user", err)
	}
	return user, nil
}

func (r *UserRepository) ByID(ctx context.Context, id bson.ObjectID) (domain.User, error) {
	return r.findOne(ctx, bson.M{"_id": id})
}

func (r *UserRepository) ByEmail(ctx context.Context, email string) (domain.User, error) {
	return r.findOne(ctx, bson.M{"email": email})
}

func (r *UserRepository) Delete(ctx context.Context, id bson.ObjectID) error {
	return deleteByID(ctx, r.collection, r.timeout, id, "user")
}

func (r *UserRepository) findOne(ctx context.Context, filter any) (domain.User, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	var user domain.User
	if err := r.collection.FindOne(ctx, filter).Decode(&user); err != nil {
		return user, repositoryError("find user", err)
	}
	return user, nil
}

type OrganizationRepository struct {
	collection *mongo.Collection
	timeout    time.Duration
}

func (r *OrganizationRepository) Create(ctx context.Context, organization domain.Organization) (domain.Organization, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	if organization.ID.IsZero() {
		organization.ID = bson.NewObjectID()
	}
	if _, err := r.collection.InsertOne(ctx, organization); err != nil {
		return domain.Organization{}, repositoryError("insert organization", err)
	}
	return organization, nil
}

func (r *OrganizationRepository) ByID(ctx context.Context, id bson.ObjectID) (domain.Organization, error) {
	return r.findOne(ctx, bson.M{"_id": id})
}

func (r *OrganizationRepository) BySlug(ctx context.Context, slug string) (domain.Organization, error) {
	return r.findOne(ctx, bson.M{"slug": slug})
}

func (r *OrganizationRepository) Delete(ctx context.Context, id bson.ObjectID) error {
	return deleteByID(ctx, r.collection, r.timeout, id, "organization")
}

func (r *OrganizationRepository) findOne(ctx context.Context, filter any) (domain.Organization, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	var organization domain.Organization
	if err := r.collection.FindOne(ctx, filter).Decode(&organization); err != nil {
		return organization, repositoryError("find organization", err)
	}
	return organization, nil
}

type MembershipRepository struct {
	collection *mongo.Collection
	timeout    time.Duration
}

func (r *MembershipRepository) Create(ctx context.Context, membership domain.Membership) (domain.Membership, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	if membership.ID.IsZero() {
		membership.ID = bson.NewObjectID()
	}
	if _, err := r.collection.InsertOne(ctx, membership); err != nil {
		return domain.Membership{}, repositoryError("insert membership", err)
	}
	return membership, nil
}

func (r *MembershipRepository) ByUserAndOrganization(ctx context.Context, userID, organizationID bson.ObjectID) (domain.Membership, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	var membership domain.Membership
	err := r.collection.FindOne(ctx, bson.M{"userId": userID, "organizationId": organizationID}).Decode(&membership)
	if err != nil {
		return membership, repositoryError("find membership", err)
	}
	return membership, nil
}

func (r *MembershipRepository) Delete(ctx context.Context, id bson.ObjectID) error {
	return deleteByID(ctx, r.collection, r.timeout, id, "membership")
}

type SessionRepository struct {
	collection *mongo.Collection
	timeout    time.Duration
}

func (r *SessionRepository) Create(ctx context.Context, session domain.Session) (domain.Session, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	if session.ID.IsZero() {
		session.ID = bson.NewObjectID()
	}
	if _, err := r.collection.InsertOne(ctx, session); err != nil {
		return domain.Session{}, repositoryError("insert session", err)
	}
	return session, nil
}

func (r *SessionRepository) ByRefreshTokenHash(ctx context.Context, hash string) (domain.Session, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	var session domain.Session
	filter := bson.M{"$or": bson.A{bson.M{"refreshTokenHash": hash}, bson.M{"usedTokenHashes": hash}}}
	if err := r.collection.FindOne(ctx, filter).Decode(&session); err != nil {
		return session, repositoryError("find session", err)
	}
	return session, nil
}

func (r *SessionRepository) ByIDForPrincipal(ctx context.Context, id, userID, organizationID bson.ObjectID) (domain.Session, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	var session domain.Session
	filter := bson.M{"_id": id, "userId": userID, "organizationId": organizationID}
	if err := r.collection.FindOne(ctx, filter).Decode(&session); err != nil {
		return session, repositoryError("find session", err)
	}
	return session, nil
}

func (r *SessionRepository) ListForPrincipal(ctx context.Context, userID, organizationID bson.ObjectID) ([]domain.Session, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	filter := bson.M{"userId": userID, "organizationId": organizationID}
	cursor, err := r.collection.Find(ctx, filter, options.Find().SetSort(bson.D{{Key: "lastUsedAt", Value: -1}}))
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var sessions []domain.Session
	if err := cursor.All(ctx, &sessions); err != nil {
		return nil, fmt.Errorf("decode sessions: %w", err)
	}
	return sessions, nil
}

func (r *SessionRepository) Rotate(ctx context.Context, id bson.ObjectID, currentHash, replacementHash string, usedAt time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	filter := bson.M{
		"_id": id, "refreshTokenHash": currentHash,
		"revokedAt": bson.M{"$exists": false}, "expiresAt": bson.M{"$gt": usedAt},
	}
	update := bson.M{
		"$set":  bson.M{"refreshTokenHash": replacementHash, "lastUsedAt": usedAt},
		"$push": bson.M{"usedTokenHashes": currentHash},
	}
	result, err := r.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("rotate session: %w", err)
	}
	if result.ModifiedCount != 1 {
		return fmt.Errorf("rotate session: %w", basestore.ErrConflict)
	}
	return nil
}

func (r *SessionRepository) Revoke(ctx context.Context, id bson.ObjectID, revokedAt time.Time, reason string) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	filter := bson.M{"_id": id, "revokedAt": bson.M{"$exists": false}}
	update := bson.M{"$set": bson.M{"revokedAt": revokedAt, "revocationReason": reason}}
	if _, err := r.collection.UpdateOne(ctx, filter, update); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

func (r *SessionRepository) RevokeAll(ctx context.Context, userID, organizationID bson.ObjectID, revokedAt time.Time, reason string) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	filter := bson.M{"userId": userID, "organizationId": organizationID, "revokedAt": bson.M{"$exists": false}}
	update := bson.M{"$set": bson.M{"revokedAt": revokedAt, "revocationReason": reason}}
	if _, err := r.collection.UpdateMany(ctx, filter, update); err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}
	return nil
}

type InvitationRepository struct {
	collection *mongo.Collection
	timeout    time.Duration
}

func (r *InvitationRepository) Create(ctx context.Context, invitation domain.Invitation) (domain.Invitation, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	if invitation.ID.IsZero() {
		invitation.ID = bson.NewObjectID()
	}
	if _, err := r.collection.InsertOne(ctx, invitation); err != nil {
		return domain.Invitation{}, repositoryError("insert invitation", err)
	}
	return invitation, nil
}

func (r *InvitationRepository) ByTokenHash(ctx context.Context, hash string) (domain.Invitation, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	var invitation domain.Invitation
	if err := r.collection.FindOne(ctx, bson.M{"tokenHash": hash}).Decode(&invitation); err != nil {
		return invitation, repositoryError("find invitation", err)
	}
	return invitation, nil
}

type AuditRepository struct {
	collection *mongo.Collection
	timeout    time.Duration
}

func (r *AuditRepository) Create(ctx context.Context, event domain.AuditEvent) (domain.AuditEvent, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	if event.ID.IsZero() {
		event.ID = bson.NewObjectID()
	}
	if _, err := r.collection.InsertOne(ctx, event); err != nil {
		return domain.AuditEvent{}, fmt.Errorf("insert audit event: %w", err)
	}
	return event, nil
}

func repositoryError(operation string, err error) error {
	if errors.Is(err, mongo.ErrNoDocuments) {
		return fmt.Errorf("%s: %w", operation, basestore.ErrNotFound)
	}
	if mongo.IsDuplicateKeyError(err) {
		return fmt.Errorf("%s: %w", operation, basestore.ErrConflict)
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func deleteByID(ctx context.Context, collection *mongo.Collection, timeout time.Duration, id bson.ObjectID, entity string) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result, err := collection.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		return fmt.Errorf("delete %s: %w", entity, err)
	}
	if result.DeletedCount == 0 {
		return fmt.Errorf("delete %s: %w", entity, basestore.ErrNotFound)
	}
	return nil
}

var (
	_ basestore.UserRepository         = (*UserRepository)(nil)
	_ basestore.OrganizationRepository = (*OrganizationRepository)(nil)
	_ basestore.MembershipRepository   = (*MembershipRepository)(nil)
	_ basestore.SessionRepository      = (*SessionRepository)(nil)
	_ basestore.InvitationRepository   = (*InvitationRepository)(nil)
	_ basestore.AuditRepository        = (*AuditRepository)(nil)
)
