package password

import (
	"errors"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHasher(t *testing.T) {
	hasher, err := NewHasher(bcrypt.MinCost)
	if err != nil {
		t.Fatalf("create hasher: %v", err)
	}

	hash, err := hasher.Hash("a-secure-password")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if !hasher.Matches(hash, "a-secure-password") {
		t.Fatal("expected password to match")
	}
	if hasher.Matches(hash, "a-different-password") {
		t.Fatal("expected different password not to match")
	}
	if _, err := hasher.Hash("short"); !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("expected invalid length error, got %v", err)
	}
}
