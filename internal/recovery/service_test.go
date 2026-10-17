package recovery

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"golang-auth/internal/domain"
	"golang-auth/internal/mailer"
	"golang-auth/internal/password"
	"golang-auth/internal/store"
)

type usersStub struct {
	user        domain.User
	err         error
	updatedID   bson.ObjectID
	updatedHash string
}

func (s *usersStub) ByID(context.Context, bson.ObjectID) (domain.User, error) { return s.user, s.err }
func (s *usersStub) ByEmail(context.Context, string) (domain.User, error)     { return s.user, s.err }
func (s *usersStub) UpdatePassword(_ context.Context, id bson.ObjectID, hash string, _ time.Time) error {
	s.updatedID, s.updatedHash = id, hash
	return nil
}

type resetsStub struct {
	created      domain.PasswordReset
	consumed     domain.PasswordReset
	err          error
	consumedHash string
}

func (s *resetsStub) Create(_ context.Context, reset domain.PasswordReset) (domain.PasswordReset, error) {
	s.created = reset
	return reset, s.err
}
func (s *resetsStub) Consume(_ context.Context, hash string, _ time.Time) (domain.PasswordReset, error) {
	s.consumedHash = hash
	return s.consumed, s.err
}

type sessionsStub struct {
	userID bson.ObjectID
	reason string
}

func (s *sessionsStub) RevokeAllForUser(_ context.Context, userID bson.ObjectID, _ time.Time, reason string) error {
	s.userID, s.reason = userID, reason
	return nil
}

type hasherStub struct {
	hash    string
	hashErr error
	matches bool
}

func (s hasherStub) Hash(string) (string, error) { return s.hash, s.hashErr }
func (s hasherStub) Matches(string, string) bool { return s.matches }

type tokensStub struct{}

func (tokensStub) Generate() (string, string, error) { return "raw-token", "stored-hash", nil }
func (tokensStub) Hash(string) string                { return "submitted-hash" }

type mailerStub struct{ sent mailer.PasswordReset }

func (s *mailerStub) SendPasswordReset(_ context.Context, reset mailer.PasswordReset) error {
	s.sent = reset
	return nil
}

func TestRequestDoesNotRevealMissingAccount(t *testing.T) {
	service := NewService(&usersStub{err: store.ErrNotFound}, &resetsStub{}, &sessionsStub{}, hasherStub{}, tokensStub{}, &mailerStub{}, time.Hour)
	if err := service.Request(context.Background(), "missing@example.com"); err != nil {
		t.Fatalf("missing account returned error: %v", err)
	}
}

func TestConfirmConsumesTokenUpdatesPasswordAndRevokesSessions(t *testing.T) {
	userID := bson.NewObjectID()
	users, resets, sessions := &usersStub{}, &resetsStub{consumed: domain.PasswordReset{UserID: userID}}, &sessionsStub{}
	service := NewService(users, resets, sessions, hasherStub{hash: "new-hash"}, tokensStub{}, &mailerStub{}, time.Hour)
	if err := service.Confirm(context.Background(), "raw-token", "long-enough-password"); err != nil {
		t.Fatalf("confirm reset: %v", err)
	}
	if resets.consumedHash != "submitted-hash" || users.updatedID != userID || users.updatedHash != "new-hash" {
		t.Fatal("reset did not update the expected user")
	}
	if sessions.userID != userID || sessions.reason != "password reset" {
		t.Fatal("sessions were not revoked")
	}
}

func TestConfirmRejectsMissingExpiredAndWeakTokens(t *testing.T) {
	service := NewService(&usersStub{}, &resetsStub{}, &sessionsStub{}, hasherStub{hash: "hash"}, tokensStub{}, &mailerStub{}, time.Hour)
	if err := service.Confirm(context.Background(), "", "long-enough-password"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected invalid token, got %v", err)
	}
	service.resets = &resetsStub{err: store.ErrNotFound}
	if err := service.Confirm(context.Background(), "expired", "long-enough-password"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected expired token error, got %v", err)
	}
	service.passwords = hasherStub{hashErr: password.ErrInvalidLength}
	if err := service.Confirm(context.Background(), "token", "short"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected invalid password, got %v", err)
	}
}

func TestChangeRequiresCurrentPassword(t *testing.T) {
	userID := bson.NewObjectID()
	service := NewService(&usersStub{user: domain.User{ID: userID, PasswordHash: "old-hash"}}, &resetsStub{}, &sessionsStub{}, hasherStub{matches: false}, tokensStub{}, &mailerStub{}, time.Hour)
	if err := service.Change(context.Background(), userID.Hex(), "wrong", "long-enough-password"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected unauthorized, got %v", err)
	}
}
