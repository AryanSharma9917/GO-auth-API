package password

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const (
	MinimumLength = 12
	MaximumLength = 72
)

var ErrInvalidLength = errors.New("password must contain between 12 and 72 bytes")

type Hasher struct {
	cost int
}

func NewHasher(cost int) (*Hasher, error) {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return nil, fmt.Errorf("bcrypt cost must be between %d and %d", bcrypt.MinCost, bcrypt.MaxCost)
	}
	return &Hasher{cost: cost}, nil
}

func (h *Hasher) Hash(value string) (string, error) {
	if len(value) < MinimumLength || len(value) > MaximumLength {
		return "", ErrInvalidLength
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(value), h.cost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hash), nil
}

func (h *Hasher) Matches(hash, value string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(value)) == nil
}
