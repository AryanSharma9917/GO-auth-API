package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

const refreshTokenBytes = 32

type RefreshManager struct {
	random io.Reader
}

func NewRefreshManager() *RefreshManager {
	return &RefreshManager{random: rand.Reader}
}

func (m *RefreshManager) Generate() (raw string, hash string, err error) {
	value := make([]byte, refreshTokenBytes)
	if _, err := io.ReadFull(m.random, value); err != nil {
		return "", "", fmt.Errorf("generate refresh token: %w", err)
	}
	raw = base64.RawURLEncoding.EncodeToString(value)
	return raw, m.Hash(raw), nil
}

func (m *RefreshManager) Hash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
