package recovery

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"golang-auth/internal/domain"
	"golang-auth/internal/mailer"
	"golang-auth/internal/password"
	"golang-auth/internal/store"
)

var (
	ErrInvalidInput = errors.New("invalid password input")
	ErrInvalidToken = errors.New("invalid password reset token")
	ErrUnauthorized = errors.New("current password is invalid")
)

type Users interface {
	ByID(context.Context, bson.ObjectID) (domain.User, error)
	ByEmail(context.Context, string) (domain.User, error)
	UpdatePassword(context.Context, bson.ObjectID, string, time.Time) error
}
type Resets interface {
	Create(context.Context, domain.PasswordReset) (domain.PasswordReset, error)
	Consume(context.Context, string, time.Time) (domain.PasswordReset, error)
}
type Sessions interface {
	RevokeAllForUser(context.Context, bson.ObjectID, time.Time, string) error
}
type Hasher interface {
	Hash(string) (string, error)
	Matches(string, string) bool
}
type Tokens interface {
	Generate() (string, string, error)
	Hash(string) string
}
type Mailer interface {
	SendPasswordReset(context.Context, mailer.PasswordReset) error
}

type Service struct {
	users     Users
	resets    Resets
	sessions  Sessions
	passwords Hasher
	tokens    Tokens
	mailer    Mailer
	ttl       time.Duration
	now       func() time.Time
}

func NewService(users Users, resets Resets, sessions Sessions, passwords Hasher, tokens Tokens, sender Mailer, ttl time.Duration) *Service {
	return &Service{users: users, resets: resets, sessions: sessions, passwords: passwords, tokens: tokens, mailer: sender, ttl: ttl, now: time.Now}
}

func (s *Service) Request(ctx context.Context, email string) error {
	user, err := s.users.ByEmail(ctx, strings.ToLower(strings.TrimSpace(email)))
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("find reset user: %w", err)
	}
	raw, hash, err := s.tokens.Generate()
	if err != nil {
		return err
	}
	now := s.now().UTC()
	if _, err := s.resets.Create(ctx, domain.PasswordReset{UserID: user.ID, TokenHash: hash, ExpiresAt: now.Add(s.ttl), CreatedAt: now}); err != nil {
		return fmt.Errorf("create password reset: %w", err)
	}
	if err := s.mailer.SendPasswordReset(ctx, mailer.PasswordReset{Recipient: user.Email, Token: raw}); err != nil {
		return fmt.Errorf("send password reset: %w", err)
	}
	return nil
}

func (s *Service) Confirm(ctx context.Context, rawToken, newPassword string) error {
	passwordHash, err := s.passwords.Hash(newPassword)
	if errors.Is(err, password.ErrInvalidLength) {
		return ErrInvalidInput
	}
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	now := s.now().UTC()
	reset, err := s.resets.Consume(ctx, s.tokens.Hash(rawToken), now)
	if errors.Is(err, store.ErrNotFound) {
		return ErrInvalidToken
	}
	if err != nil {
		return fmt.Errorf("consume password reset: %w", err)
	}
	if err := s.users.UpdatePassword(ctx, reset.UserID, passwordHash, now); err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	if err := s.sessions.RevokeAllForUser(ctx, reset.UserID, now, "password reset"); err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}
	return nil
}

func (s *Service) Change(ctx context.Context, userID, currentPassword, newPassword string) error {
	id, err := bson.ObjectIDFromHex(userID)
	if err != nil {
		return ErrInvalidInput
	}
	user, err := s.users.ByID(ctx, id)
	if err != nil {
		return ErrUnauthorized
	}
	if !s.passwords.Matches(user.PasswordHash, currentPassword) {
		return ErrUnauthorized
	}
	passwordHash, err := s.passwords.Hash(newPassword)
	if errors.Is(err, password.ErrInvalidLength) {
		return ErrInvalidInput
	}
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	now := s.now().UTC()
	if err := s.users.UpdatePassword(ctx, id, passwordHash, now); err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	return s.sessions.RevokeAllForUser(ctx, id, now, "password changed")
}
