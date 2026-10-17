package app

import (
	"context"
	"fmt"
	"net/http"

	"golang-auth/configs"
	"golang-auth/internal/auth"
	"golang-auth/internal/httpapi"
	"golang-auth/internal/invitation"
	"golang-auth/internal/mailer"
	"golang-auth/internal/organization"
	"golang-auth/internal/password"
	mongostore "golang-auth/internal/store/mongo"
	"golang-auth/internal/token"

	"github.com/labstack/echo/v4"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

type healthChecker interface {
	Ping(context.Context, *readpref.ReadPref) error
}

type App struct {
	server *echo.Echo
	mongo  *mongo.Client
}

func New(cfg configs.Config) (*App, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.MongoConnectTimeout)
	defer cancel()

	client, err := mongostore.Connect(ctx, cfg.MongoURI)
	if err != nil {
		return nil, fmt.Errorf("connect to MongoDB: %w", err)
	}
	store := mongostore.New(client, cfg.DatabaseName, cfg.MongoOperationTimeout)
	if err := store.EnsureIndexes(ctx); err != nil {
		_ = client.Disconnect(ctx)
		return nil, fmt.Errorf("ensure MongoDB indexes: %w", err)
	}
	passwordHasher, err := password.NewHasher(cfg.PasswordBcryptCost)
	if err != nil {
		_ = client.Disconnect(ctx)
		return nil, fmt.Errorf("configure password hashing: %w", err)
	}
	tokenSigner, err := token.NewSigner(cfg.JWTSecret, cfg.JWTIssuer, cfg.JWTAudience, cfg.AccessTokenTTL)
	if err != nil {
		_ = client.Disconnect(ctx)
		return nil, fmt.Errorf("configure access tokens: %w", err)
	}
	refreshManager := token.NewRefreshManager()
	authService := auth.NewService(store.Users, store.Organizations, store.Memberships, store.Sessions, passwordHasher, tokenSigner, refreshManager, cfg.RefreshTokenTTL)
	organizationService := organization.NewService(store.Users, store.Organizations, store.Memberships, store.Sessions)
	developmentMailer, err := mailer.NewDevelopment(cfg.Environment, cfg.ApplicationBaseURL)
	if err != nil {
		_ = client.Disconnect(ctx)
		return nil, fmt.Errorf("configure invitation mailer: %w", err)
	}
	invitationService := invitation.NewService(store.Users, store.Organizations, store.Memberships, store.Invitations, passwordHasher, refreshManager, developmentMailer, cfg.InvitationTokenTTL)

	server := echo.New()
	server.HideBanner = true
	registerHealthRoutes(server, client)
	httpapi.NewHandler(authService, tokenSigner, cfg.AccessTokenTTL, organizationService).WithInvitationService(invitationService).RegisterRoutes(server)

	return &App{server: server, mongo: client}, nil
}

func (a *App) Start(address string) error {
	return a.server.Start(address)
}

func (a *App) Shutdown(ctx context.Context) error {
	serverErr := a.server.Shutdown(ctx)
	databaseErr := a.mongo.Disconnect(ctx)
	if serverErr != nil {
		return fmt.Errorf("shut down HTTP server: %w", serverErr)
	}
	if databaseErr != nil {
		return fmt.Errorf("disconnect MongoDB: %w", databaseErr)
	}
	return nil
}

func registerHealthRoutes(server *echo.Echo, checker healthChecker) {
	server.GET("/health/live", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})
	server.GET("/health/ready", func(c echo.Context) error {
		if err := checker.Ping(c.Request().Context(), nil); err != nil {
			return c.JSON(http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		}
		return c.JSON(http.StatusOK, map[string]string{"status": "ready"})
	})
}
