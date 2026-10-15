package token

import (
	"testing"
	"time"

	"golang-auth/internal/domain"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestSignerIssueAndParse(t *testing.T) {
	signer, err := NewSigner("a-secret-that-is-at-least-32-characters", "issuer", "audience", 15*time.Minute)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	fixed := time.Date(2026, time.October, 15, 12, 0, 0, 0, time.UTC)
	signer.now = func() time.Time { return fixed }

	userID := bson.NewObjectID().Hex()
	organizationID := bson.NewObjectID().Hex()
	value, err := signer.Issue(userID, organizationID, domain.RoleOwner)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	claims, err := signer.Parse(value)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if claims.Subject != userID || claims.OrganizationID != organizationID || claims.Role != domain.RoleOwner {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestSignerRejectsUnexpectedAlgorithm(t *testing.T) {
	signer, err := NewSigner("a-secret-that-is-at-least-32-characters", "issuer", "audience", 15*time.Minute)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	now := time.Now().UTC()
	value, err := jwt.NewWithClaims(jwt.SigningMethodNone, Claims{
		OrganizationID: bson.NewObjectID().Hex(),
		Role:           domain.RoleOwner,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "issuer", Subject: bson.NewObjectID().Hex(), Audience: jwt.ClaimStrings{"audience"},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)), IssuedAt: jwt.NewNumericDate(now), ID: "token-id",
		},
	}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("create unsigned token: %v", err)
	}
	if _, err := signer.Parse(value); err == nil {
		t.Fatal("expected unexpected algorithm to be rejected")
	}
}

func TestSignerRejectsExpiredToken(t *testing.T) {
	signer, err := NewSigner("a-secret-that-is-at-least-32-characters", "issuer", "audience", time.Minute)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	issuedAt := time.Date(2026, time.October, 15, 12, 0, 0, 0, time.UTC)
	signer.now = func() time.Time { return issuedAt }
	value, err := signer.Issue(bson.NewObjectID().Hex(), bson.NewObjectID().Hex(), domain.RoleMember)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	signer.now = func() time.Time { return issuedAt.Add(2 * time.Minute) }
	if _, err := signer.Parse(value); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}

func TestSignerRejectsWrongAudience(t *testing.T) {
	issuer, err := NewSigner("a-secret-that-is-at-least-32-characters", "issuer", "audience", time.Minute)
	if err != nil {
		t.Fatalf("create issuer: %v", err)
	}
	value, err := issuer.Issue(bson.NewObjectID().Hex(), bson.NewObjectID().Hex(), domain.RoleMember)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	parser, err := NewSigner("a-secret-that-is-at-least-32-characters", "issuer", "different-audience", time.Minute)
	if err != nil {
		t.Fatalf("create parser: %v", err)
	}
	if _, err := parser.Parse(value); err == nil {
		t.Fatal("expected token with wrong audience to be rejected")
	}
}
