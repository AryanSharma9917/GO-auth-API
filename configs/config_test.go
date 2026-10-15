package configs

import (
	"testing"
	"time"
)

func TestConfigValidate(t *testing.T) {
	valid := Config{
		MongoURI:        "mongodb://localhost:27017",
		JWTSecret:       "a-secret-that-is-at-least-32-characters",
		AccessTokenTTL:  15 * time.Minute,
		ShutdownTimeout: 10 * time.Second,
	}

	tests := []struct {
		name   string
		change func(*Config)
	}{
		{name: "missing MongoDB URI", change: func(c *Config) { c.MongoURI = "" }},
		{name: "short JWT secret", change: func(c *Config) { c.JWTSecret = "too-short" }},
		{name: "invalid access token TTL", change: func(c *Config) { c.AccessTokenTTL = 0 }},
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
