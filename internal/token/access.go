package token

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"golang-auth/internal/domain"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/v2/bson"
)

var ErrInvalid = errors.New("invalid access token")

type Claims struct {
	OrganizationID string      `json:"organization_id"`
	Role           domain.Role `json:"role"`
	jwt.RegisteredClaims
}

type Signer struct {
	secret   []byte
	issuer   string
	audience string
	ttl      time.Duration
	now      func() time.Time
	random   io.Reader
}

func NewSigner(secret, issuer, audience string, ttl time.Duration) (*Signer, error) {
	if len(secret) < 32 {
		return nil, errors.New("token secret must contain at least 32 characters")
	}
	if issuer == "" || audience == "" || ttl <= 0 {
		return nil, errors.New("token issuer, audience, and positive TTL are required")
	}
	return &Signer{secret: []byte(secret), issuer: issuer, audience: audience, ttl: ttl, now: time.Now, random: rand.Reader}, nil
}

func (s *Signer) Issue(userID, organizationID string, role domain.Role) (string, error) {
	now := s.now().UTC()
	id, err := randomID(s.random)
	if err != nil {
		return "", fmt.Errorf("generate token ID: %w", err)
	}
	claims := Claims{
		OrganizationID: organizationID,
		Role:           role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{s.audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(s.ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        id,
		},
	}
	value, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.secret)
	if err != nil {
		return "", fmt.Errorf("sign access token: %w", err)
	}
	return value, nil
}

func (s *Signer) Parse(value string) (Claims, error) {
	claims := Claims{}
	parsed, err := jwt.ParseWithClaims(value, &claims, func(parsedToken *jwt.Token) (any, error) {
		if parsedToken.Method != jwt.SigningMethodHS256 {
			return nil, ErrInvalid
		}
		return s.secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), jwt.WithIssuer(s.issuer), jwt.WithAudience(s.audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithTimeFunc(s.now))
	if err != nil || !parsed.Valid || claims.ID == "" || !validRole(claims.Role) {
		return Claims{}, ErrInvalid
	}
	if _, err := bson.ObjectIDFromHex(claims.Subject); err != nil {
		return Claims{}, ErrInvalid
	}
	if _, err := bson.ObjectIDFromHex(claims.OrganizationID); err != nil {
		return Claims{}, ErrInvalid
	}
	return claims, nil
}

func validRole(role domain.Role) bool {
	return role == domain.RoleOwner || role == domain.RoleAdmin || role == domain.RoleMember
}

func randomID(reader io.Reader) (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(reader, value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
