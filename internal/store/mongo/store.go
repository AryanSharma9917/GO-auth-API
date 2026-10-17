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
	usersCollection          = "users"
	organizationsCollection  = "organizations"
	membershipsCollection    = "memberships"
	sessionsCollection       = "sessions"
	invitationsCollection    = "invitations"
	auditEventsCollection    = "audit_events"
	passwordResetsCollection = "password_resets"
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
	PasswordResets   *PasswordResetRepository
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
		PasswordResets:   &PasswordResetRepository{collection: database.Collection(passwordResetsCollection), timeout: operationTimeout},
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
			{Keys: bson.D{{Key: "organizationId", Value: 1}, {Key: "email", Value: 1}}, Options: options.Index().SetUnique(true).SetPartialFilterExpression(bson.M{"status": domain.InvitationPending}).SetName("invitations_pending_organization_email_unique")},
			{Keys: bson.D{{Key: "expiresAt", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0).SetName("invitations_expiry_ttl")},
		},
		auditEventsCollection: {
			{Keys: bson.D{{Key: "organizationId", Value: 1}, {Key: "createdAt", Value: -1}}, Options: options.Index().SetName("audit_events_organization_created")},
		},
		passwordResetsCollection: {
			{Keys: bson.D{{Key: "tokenHash", Value: 1}}, Options: options.Index().SetUnique(true).SetName("password_resets_token_hash_unique")},
			{Keys: bson.D{{Key: "expiresAt", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0).SetName("password_resets_expiry_ttl")},
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

func (r *UserRepository) ByIDs(ctx context.Context, ids []bson.ObjectID) ([]domain.User, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	if len(ids) == 0 {
		return []domain.User{}, nil
	}
	cursor, err := r.collection.Find(ctx, bson.M{"_id": bson.M{"$in": ids}})
	if err != nil {
		return nil, fmt.Errorf("find users: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var users []domain.User
	if err := cursor.All(ctx, &users); err != nil {
		return nil, fmt.Errorf("decode users: %w", err)
	}
	return users, nil
}

func (r *UserRepository) Delete(ctx context.Context, id bson.ObjectID) error {
	return deleteByID(ctx, r.collection, r.timeout, id, "user")
}

func (r *UserRepository) UpdatePassword(ctx context.Context, id bson.ObjectID, passwordHash string, updatedAt time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	result, err := r.collection.UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": bson.M{"passwordHash": passwordHash, "updatedAt": updatedAt}})
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	if result.MatchedCount != 1 {
		return fmt.Errorf("update password: %w", basestore.ErrNotFound)
	}
	return nil
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

func (r *OrganizationRepository) UpdateName(ctx context.Context, id bson.ObjectID, name string, updatedAt time.Time) (domain.Organization, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	var organization domain.Organization
	result := r.collection.FindOneAndUpdate(ctx, bson.M{"_id": id}, bson.M{"$set": bson.M{"name": name, "updatedAt": updatedAt}}, options.FindOneAndUpdate().SetReturnDocument(options.After))
	if err := result.Decode(&organization); err != nil {
		return organization, repositoryError("update organization", err)
	}
	return organization, nil
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

func (r *MembershipRepository) ByIDForOrganization(ctx context.Context, id, organizationID bson.ObjectID) (domain.Membership, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	var membership domain.Membership
	if err := r.collection.FindOne(ctx, bson.M{"_id": id, "organizationId": organizationID}).Decode(&membership); err != nil {
		return membership, repositoryError("find membership", err)
	}
	return membership, nil
}

func (r *MembershipRepository) ListForOrganization(ctx context.Context, organizationID, after bson.ObjectID, limit int64) ([]domain.Membership, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	filter := bson.M{"organizationId": organizationID}
	if !after.IsZero() {
		filter["_id"] = bson.M{"$gt": after}
	}
	cursor, err := r.collection.Find(ctx, filter, options.Find().SetSort(bson.D{{Key: "_id", Value: 1}}).SetLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("list memberships: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var memberships []domain.Membership
	if err := cursor.All(ctx, &memberships); err != nil {
		return nil, fmt.Errorf("decode memberships: %w", err)
	}
	return memberships, nil
}

func (r *MembershipRepository) CountActiveOwners(ctx context.Context, organizationID bson.ObjectID) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	count, err := r.collection.CountDocuments(ctx, bson.M{"organizationId": organizationID, "role": domain.RoleOwner, "state": domain.MembershipActive})
	if err != nil {
		return 0, fmt.Errorf("count active owners: %w", err)
	}
	return count, nil
}

func (r *MembershipRepository) Update(ctx context.Context, id bson.ObjectID, role domain.Role, state domain.MembershipState, updatedAt time.Time) (domain.Membership, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	var membership domain.Membership
	update := bson.M{"$set": bson.M{"role": role, "state": state, "updatedAt": updatedAt}}
	result := r.collection.FindOneAndUpdate(ctx, bson.M{"_id": id}, update, options.FindOneAndUpdate().SetReturnDocument(options.After))
	if err := result.Decode(&membership); err != nil {
		return membership, repositoryError("update membership", err)
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

func (r *SessionRepository) RevokeAllForUser(ctx context.Context, userID bson.ObjectID, revokedAt time.Time, reason string) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	_, err := r.collection.UpdateMany(ctx, bson.M{"userId": userID, "revokedAt": bson.M{"$exists": false}}, bson.M{"$set": bson.M{"revokedAt": revokedAt, "revocationReason": reason}})
	if err != nil {
		return fmt.Errorf("revoke user sessions: %w", err)
	}
	return nil
}

type PasswordResetRepository struct {
	collection *mongo.Collection
	timeout    time.Duration
}

func (r *PasswordResetRepository) Create(ctx context.Context, reset domain.PasswordReset) (domain.PasswordReset, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	if reset.ID.IsZero() {
		reset.ID = bson.NewObjectID()
	}
	if _, err := r.collection.InsertOne(ctx, reset); err != nil {
		return domain.PasswordReset{}, repositoryError("insert password reset", err)
	}
	return reset, nil
}

func (r *PasswordResetRepository) Consume(ctx context.Context, tokenHash string, usedAt time.Time) (domain.PasswordReset, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	filter := bson.M{"tokenHash": tokenHash, "expiresAt": bson.M{"$gt": usedAt}, "usedAt": bson.M{"$exists": false}}
	var reset domain.PasswordReset
	if err := r.collection.FindOneAndUpdate(ctx, filter, bson.M{"$set": bson.M{"usedAt": usedAt}}, options.FindOneAndUpdate().SetReturnDocument(options.After)).Decode(&reset); err != nil {
		return reset, repositoryError("consume password reset", err)
	}
	return reset, nil
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

func (r *InvitationRepository) ByIDForOrganization(ctx context.Context, id, organizationID bson.ObjectID) (domain.Invitation, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	var invitation domain.Invitation
	if err := r.collection.FindOne(ctx, bson.M{"_id": id, "organizationId": organizationID}).Decode(&invitation); err != nil {
		return invitation, repositoryError("find invitation", err)
	}
	return invitation, nil
}

func (r *InvitationRepository) ListForOrganization(ctx context.Context, organizationID, after bson.ObjectID, limit int64) ([]domain.Invitation, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	filter := bson.M{"organizationId": organizationID}
	if !after.IsZero() {
		filter["_id"] = bson.M{"$gt": after}
	}
	cursor, err := r.collection.Find(ctx, filter, options.Find().SetSort(bson.D{{Key: "_id", Value: 1}}).SetLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("list invitations: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var invitations []domain.Invitation
	if err := cursor.All(ctx, &invitations); err != nil {
		return nil, fmt.Errorf("decode invitations: %w", err)
	}
	return invitations, nil
}

func (r *InvitationRepository) Claim(ctx context.Context, hash string, claimedAt time.Time) (domain.Invitation, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	filter := bson.M{
		"tokenHash": hash, "expiresAt": bson.M{"$gt": claimedAt},
		"status": domain.InvitationPending,
		"$or": bson.A{
			bson.M{"claimedAt": bson.M{"$exists": false}},
			bson.M{"claimedAt": bson.M{"$lt": claimedAt.Add(-5 * time.Minute)}},
		},
	}
	var invitation domain.Invitation
	result := r.collection.FindOneAndUpdate(ctx, filter, bson.M{"$set": bson.M{"claimedAt": claimedAt}}, options.FindOneAndUpdate().SetReturnDocument(options.After))
	if err := result.Decode(&invitation); err != nil {
		return invitation, repositoryError("claim invitation", err)
	}
	return invitation, nil
}

func (r *InvitationRepository) Complete(ctx context.Context, id bson.ObjectID, acceptedAt time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	filter := bson.M{"_id": id, "claimedAt": bson.M{"$exists": true}, "status": domain.InvitationPending}
	update := bson.M{"$set": bson.M{"acceptedAt": acceptedAt, "status": domain.InvitationAccepted}, "$unset": bson.M{"claimedAt": ""}}
	result, err := r.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("complete invitation: %w", err)
	}
	if result.ModifiedCount != 1 {
		return fmt.Errorf("complete invitation: %w", basestore.ErrConflict)
	}
	return nil
}

func (r *InvitationRepository) Release(ctx context.Context, id bson.ObjectID) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	if _, err := r.collection.UpdateOne(ctx, bson.M{"_id": id, "status": domain.InvitationPending}, bson.M{"$unset": bson.M{"claimedAt": ""}}); err != nil {
		return fmt.Errorf("release invitation: %w", err)
	}
	return nil
}

func (r *InvitationRepository) Revoke(ctx context.Context, id bson.ObjectID, revokedAt time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	filter := bson.M{"_id": id, "status": domain.InvitationPending}
	update := bson.M{"$set": bson.M{"revokedAt": revokedAt, "status": domain.InvitationRevoked}, "$unset": bson.M{"claimedAt": ""}}
	result, err := r.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("revoke invitation: %w", err)
	}
	if result.MatchedCount != 1 {
		return fmt.Errorf("revoke invitation: %w", basestore.ErrNotFound)
	}
	return nil
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

func (r *AuditRepository) ListForOrganization(ctx context.Context, organizationID, before bson.ObjectID, action string, limit int64) ([]domain.AuditEvent, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	filter := bson.M{"organizationId": organizationID}
	if !before.IsZero() {
		filter["_id"] = bson.M{"$lt": before}
	}
	if action != "" {
		filter["action"] = action
	}
	cursor, err := r.collection.Find(ctx, filter, options.Find().SetSort(bson.D{{Key: "_id", Value: -1}}).SetLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()
	var events []domain.AuditEvent
	if err := cursor.All(ctx, &events); err != nil {
		return nil, fmt.Errorf("decode audit events: %w", err)
	}
	return events, nil
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
	_ basestore.UserRepository          = (*UserRepository)(nil)
	_ basestore.OrganizationRepository  = (*OrganizationRepository)(nil)
	_ basestore.MembershipRepository    = (*MembershipRepository)(nil)
	_ basestore.SessionRepository       = (*SessionRepository)(nil)
	_ basestore.InvitationRepository    = (*InvitationRepository)(nil)
	_ basestore.AuditRepository         = (*AuditRepository)(nil)
	_ basestore.PasswordResetRepository = (*PasswordResetRepository)(nil)
)
