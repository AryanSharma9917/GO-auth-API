package mongo_test

import (
	"context"
	"os"
	"testing"
	"time"

	"golang-auth/internal/domain"
	mongostore "golang-auth/internal/store/mongo"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
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
	if _, err := repositories.Users.Create(ctx, user); !mongo.IsDuplicateKeyError(err) {
		t.Fatalf("expected duplicate email error, got %v", err)
	}

	assertIndexExists(t, ctx, client.Database(databaseName).Collection("sessions"), "sessions_expiry_ttl")
	assertIndexExists(t, ctx, client.Database(databaseName).Collection("invitations"), "invitations_expiry_ttl")
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
