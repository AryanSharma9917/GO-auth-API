package configs

import (
	"testing"
	"time"
)

func TestConfigValidate(t *testing.T) {
	valid := Config{
		MongoURI:              "mongodb://localhost:27017",
		MongoConnectTimeout:   10 * time.Second,
		MongoOperationTimeout: 5 * time.Second,
		JWTSecret:             "a-secret-that-is-at-least-32-characters",
		JWTIssuer:             "go-auth-api",
		JWTAudience:           "go-auth-clients",
		AccessTokenTTL:        15 * time.Minute,
		RefreshTokenTTL:       30 * 24 * time.Hour,
		PasswordBcryptCost:    12,
		ShutdownTimeout:       10 * time.Second,
	}

	tests := []struct {
		name   string
		change func(*Config)
	}{
		{name: "missing MongoDB URI", change: func(c *Config) { c.MongoURI = "" }},
		{name: "short JWT secret", change: func(c *Config) { c.JWTSecret = "too-short" }},
		{name: "missing JWT issuer", change: func(c *Config) { c.JWTIssuer = "" }},
		{name: "missing JWT audience", change: func(c *Config) { c.JWTAudience = "" }},
		{name: "invalid MongoDB connect timeout", change: func(c *Config) { c.MongoConnectTimeout = 0 }},
		{name: "invalid MongoDB operation timeout", change: func(c *Config) { c.MongoOperationTimeout = 0 }},
		{name: "invalid access token TTL", change: func(c *Config) { c.AccessTokenTTL = 0 }},
		{name: "short refresh token TTL", change: func(c *Config) { c.RefreshTokenTTL = c.AccessTokenTTL }},
		{name: "weak bcrypt cost", change: func(c *Config) { c.PasswordBcryptCost = 9 }},
		{name: "invalid shutdown timeout", change: func(c *Config) { c.ShutdownTimeout = 0 }},
	}

	if err := valid.Validate(); err != nil {
		t.Fatalf("valid configuration returned an error: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid
			tt.change(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}
