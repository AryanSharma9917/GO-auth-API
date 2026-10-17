package mongo_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"golang-auth/internal/auth"
	"golang-auth/internal/domain"
	organizationservice "golang-auth/internal/organization"
	"golang-auth/internal/password"
	basestore "golang-auth/internal/store"
	mongostore "golang-auth/internal/store/mongo"
	"golang-auth/internal/token"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

func TestStoreIndexesAndUniqueness(t *testing.T) {
	uri := os.Getenv("MONGODB_TEST_URI")
	if uri == "" {
		t.Skip("MONGODB_TEST_URI is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatalf("connect to MongoDB: %v", err)
	}
	defer func() {
		if err := client.Disconnect(context.Background()); err != nil {
			t.Errorf("disconnect MongoDB: %v", err)
		}
	}()

	databaseName := "go_auth_test_" + bson.NewObjectID().Hex()
	defer func() {
		if err := client.Database(databaseName).Drop(context.Background()); err != nil {
			t.Errorf("drop test database: %v", err)
		}
	}()

	repositories := mongostore.New(client, databaseName, 5*time.Second)
	if err := repositories.EnsureIndexes(ctx); err != nil {
		t.Fatalf("ensure indexes: %v", err)
	}

	now := time.Now().UTC()
	user := domain.User{
		Email:        "owner@example.com",
		DisplayName:  "Owner",
		PasswordHash: "not-a-real-password-hash",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if _, err := repositories.Users.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := repositories.Users.Create(ctx, user); !errors.Is(err, basestore.ErrConflict) {
		t.Fatalf("expected duplicate email error, got %v", err)
	}

	assertIndexExists(t, ctx, client.Database(databaseName).Collection("sessions"), "sessions_expiry_ttl")
	assertIndexExists(t, ctx, client.Database(databaseName).Collection("invitations"), "invitations_expiry_ttl")

	hasher, err := password.NewHasher(bcrypt.MinCost)
	if err != nil {
		t.Fatalf("create password hasher: %v", err)
	}
	signer, err := token.NewSigner("a-secret-that-is-at-least-32-characters", "test-issuer", "test-audience", 15*time.Minute)
	if err != nil {
		t.Fatalf("create token signer: %v", err)
	}
	refreshManager := token.NewRefreshManager()
	authService := auth.NewService(repositories.Users, repositories.Organizations, repositories.Memberships, repositories.Sessions, hasher, signer, refreshManager, 30*24*time.Hour)
	registered, err := authService.Register(ctx, auth.RegisterInput{
		OrganizationName: "Registered Company", OrganizationSlug: "registered-company",
		Email: "registered@example.com", DisplayName: "Registered Owner", Password: "a-secure-password",
	}, 15*time.Minute)
	if err != nil {
		t.Fatalf("register organization owner: %v", err)
	}
	loggedIn, err := authService.Login(ctx, auth.LoginInput{
		OrganizationSlug: "registered-company", Email: "registered@example.com", Password: "a-secure-password",
	}, 15*time.Minute)
	if err != nil {
		t.Fatalf("log in organization owner: %v", err)
	}
	claims, err := signer.Parse(loggedIn.AccessToken)
	if err != nil {
		t.Fatalf("parse login access token: %v", err)
	}
	if claims.Subject != registered.User.ID.Hex() || claims.OrganizationID != registered.Organization.ID.Hex() || claims.Role != domain.RoleOwner {
		t.Fatalf("unexpected login claims: %+v", claims)
	}

	refreshed, err := authService.Refresh(ctx, registered.RefreshToken, 15*time.Minute)
	if err != nil {
		t.Fatalf("rotate refresh token: %v", err)
	}
	if refreshed.RefreshToken == registered.RefreshToken {
		t.Fatal("refresh token was not rotated")
	}
	if _, err := authService.Refresh(ctx, registered.RefreshToken, 15*time.Minute); !errors.Is(err, auth.ErrRefreshTokenReuse) {
		t.Fatalf("expected refresh token reuse detection, got %v", err)
	}
	if _, err := authService.Refresh(ctx, refreshed.RefreshToken, 15*time.Minute); !errors.Is(err, auth.ErrInvalidRefreshToken) {
		t.Fatalf("expected token family revocation after reuse, got %v", err)
	}

	wrongOrganizationID := bson.NewObjectID().Hex()
	if err := authService.RevokeSession(ctx, loggedIn.Session.ID.Hex(), loggedIn.User.ID.Hex(), wrongOrganizationID); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("expected cross-organization session revocation to fail, got %v", err)
	}
	sessions, err := authService.Sessions(ctx, loggedIn.User.ID.Hex(), loggedIn.Organization.ID.Hex())
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(sessions) < 2 {
		t.Fatalf("expected registration and login sessions, got %d", len(sessions))
	}
	if err := authService.LogoutAll(ctx, loggedIn.User.ID.Hex(), loggedIn.Organization.ID.Hex()); err != nil {
		t.Fatalf("logout all sessions: %v", err)
	}
	if _, err := authService.Refresh(ctx, loggedIn.RefreshToken, 15*time.Minute); !errors.Is(err, auth.ErrInvalidRefreshToken) {
		t.Fatalf("expected logged-out refresh token to be invalid, got %v", err)
	}

	organizationService := organizationservice.NewService(repositories.Users, repositories.Organizations, repositories.Memberships, repositories.Sessions)
	ownerActor := organizationservice.Actor{UserID: registered.User.ID.Hex(), OrganizationID: registered.Organization.ID.Hex()}
	updatedOrganization, err := organizationService.UpdateName(ctx, ownerActor, "Renamed Company")
	if err != nil || updatedOrganization.Name != "Renamed Company" {
		t.Fatalf("update organization name: %v, organization: %+v", err, updatedOrganization)
	}
	memberUser, err := repositories.Users.Create(ctx, domain.User{
		Email: "member@example.com", DisplayName: "Member", PasswordHash: "not-a-real-password-hash", CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create member user: %v", err)
	}
	memberMembership, err := repositories.Memberships.Create(ctx, domain.Membership{
		OrganizationID: registered.Organization.ID, UserID: memberUser.ID, Role: domain.RoleMember,
		State: domain.MembershipActive, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create member membership: %v", err)
	}
	page, err := organizationService.Members(ctx, ownerActor, "", 1)
	if err != nil {
		t.Fatalf("list organization members: %v", err)
	}
	if len(page.Members) != 1 || page.NextCursor == "" {
		t.Fatalf("expected a one-member page with a next cursor: %+v", page)
	}
	memberRole := domain.RoleMember
	if _, err := organizationService.UpdateMember(ctx, ownerActor, registered.Membership.ID.Hex(), organizationservice.UpdateMemberInput{Role: &memberRole}); !errors.Is(err, organizationservice.ErrLastOwner) {
		t.Fatalf("expected final owner demotion to fail, got %v", err)
	}
	otherMembership, err := repositories.Memberships.Create(ctx, domain.Membership{
		OrganizationID: bson.NewObjectID(), UserID: bson.NewObjectID(), Role: domain.RoleMember,
		State: domain.MembershipActive, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("create other organization membership: %v", err)
	}
	if err := organizationService.RemoveMember(ctx, ownerActor, otherMembership.ID.Hex()); !errors.Is(err, organizationservice.ErrNotFound) {
		t.Fatalf("expected cross-organization member to remain hidden, got %v", err)
	}
	ownerRole := domain.RoleOwner
	if _, err := organizationService.UpdateMember(ctx, ownerActor, memberMembership.ID.Hex(), organizationservice.UpdateMemberInput{Role: &ownerRole}); err != nil {
		t.Fatalf("promote second owner: %v", err)
	}
	if _, err := organizationService.UpdateMember(ctx, ownerActor, registered.Membership.ID.Hex(), organizationservice.UpdateMemberInput{Role: &memberRole}); err != nil {
		t.Fatalf("demote owner after adding replacement: %v", err)
	}
	if err := organizationService.RemoveMember(ctx, ownerActor, memberMembership.ID.Hex()); !errors.Is(err, organizationservice.ErrForbidden) {
		t.Fatalf("expected demoted actor to lose authorization immediately, got %v", err)
	}
}

func assertIndexExists(t *testing.T, ctx context.Context, collection *mongo.Collection, expected string) {
	t.Helper()
	cursor, err := collection.Indexes().List(ctx)
	if err != nil {
		t.Fatalf("list indexes for %s: %v", collection.Name(), err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	var indexes []bson.M
	if err := cursor.All(ctx, &indexes); err != nil {
		t.Fatalf("decode indexes for %s: %v", collection.Name(), err)
	}
	for _, index := range indexes {
		if index["name"] == expected {
			return
		}
	}
	t.Fatalf("index %q was not created on %s", expected, collection.Name())
}
