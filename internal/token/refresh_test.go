package token

import "testing"

func TestRefreshManagerGeneratesOpaqueHashedTokens(t *testing.T) {
	manager := NewRefreshManager()
	first, firstHash, err := manager.Generate()
	if err != nil {
		t.Fatalf("generate first token: %v", err)
	}
	second, secondHash, err := manager.Generate()
	if err != nil {
		t.Fatalf("generate second token: %v", err)
	}
	if first == firstHash || second == secondHash {
		t.Fatal("raw refresh token must not equal its stored hash")
	}
	if first == second || firstHash == secondHash {
		t.Fatal("refresh tokens must be unique")
	}
	if manager.Hash(first) != firstHash {
		t.Fatal("refresh token hash is not deterministic")
	}
}
