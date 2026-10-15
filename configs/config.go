package configs

import (
	"errors"
	"fmt"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Environment           string        `env:"APP_ENV" env-default:"development"`
	Host                  string        `env:"HOST" env-default:"0.0.0.0"`
	Port                  string        `env:"PORT" env-default:"8080"`
	MongoURI              string        `env:"MONGODB_URI" env-required:"true"`
	DatabaseName          string        `env:"MONGODB_DATABASE" env-default:"goapi-auth"`
	MongoConnectTimeout   time.Duration `env:"MONGODB_CONNECT_TIMEOUT" env-default:"10s"`
	MongoOperationTimeout time.Duration `env:"MONGODB_OPERATION_TIMEOUT" env-default:"5s"`
	JWTSecret             string        `env:"JWT_SECRET" env-required:"true"`
	JWTIssuer             string        `env:"JWT_ISSUER" env-default:"go-auth-api"`
	JWTAudience           string        `env:"JWT_AUDIENCE" env-default:"go-auth-clients"`
	AccessTokenTTL        time.Duration `env:"ACCESS_TOKEN_TTL" env-default:"15m"`
	RefreshTokenTTL       time.Duration `env:"REFRESH_TOKEN_TTL" env-default:"720h"`
	PasswordBcryptCost    int           `env:"PASSWORD_BCRYPT_COST" env-default:"12"`
	ShutdownTimeout       time.Duration `env:"SHUTDOWN_TIMEOUT" env-default:"10s"`
}

func Load() (Config, error) {
	var cfg Config
	if err := cleanenv.ReadEnv(&cfg); err != nil {
		return Config{}, fmt.Errorf("read configuration: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("validate configuration: %w", err)
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.MongoURI == "" {
		return errors.New("MONGODB_URI is required")
	}
	if len(c.JWTSecret) < 32 {
		return errors.New("JWT_SECRET must contain at least 32 characters")
	}
	if c.JWTIssuer == "" {
		return errors.New("JWT_ISSUER is required")
	}
	if c.JWTAudience == "" {
		return errors.New("JWT_AUDIENCE is required")
	}
	if c.MongoConnectTimeout <= 0 {
		return errors.New("MONGODB_CONNECT_TIMEOUT must be positive")
	}
	if c.MongoOperationTimeout <= 0 {
		return errors.New("MONGODB_OPERATION_TIMEOUT must be positive")
	}
	if c.AccessTokenTTL <= 0 {
		return errors.New("ACCESS_TOKEN_TTL must be positive")
	}
	if c.RefreshTokenTTL <= c.AccessTokenTTL {
		return errors.New("REFRESH_TOKEN_TTL must be greater than ACCESS_TOKEN_TTL")
	}
	if c.PasswordBcryptCost < 10 || c.PasswordBcryptCost > 31 {
		return errors.New("PASSWORD_BCRYPT_COST must be between 10 and 31")
	}
	if c.ShutdownTimeout <= 0 {
		return errors.New("SHUTDOWN_TIMEOUT must be positive")
	}
	return nil
}

func (c Config) Address() string {
	return c.Host + ":" + c.Port
}
