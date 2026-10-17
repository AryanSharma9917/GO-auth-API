package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"golang-auth/configs"
	"golang-auth/internal/audit"
	"golang-auth/internal/auth"
	"golang-auth/internal/httpapi"
	"golang-auth/internal/invitation"
	"golang-auth/internal/mailer"
	"golang-auth/internal/observability"
	"golang-auth/internal/organization"
	"golang-auth/internal/password"
	"golang-auth/internal/recovery"
	mongostore "golang-auth/internal/store/mongo"
	"golang-auth/internal/token"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
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
	var sender interface {
		mailer.Sender
		recovery.Mailer
	}
	if cfg.Environment == "production" {
		sender, err = mailer.NewSMTP(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPFrom, cfg.ApplicationBaseURL)
	} else {
		sender, err = mailer.NewDevelopment(cfg.Environment, cfg.ApplicationBaseURL)
	}
	if err != nil {
		_ = client.Disconnect(ctx)
		return nil, fmt.Errorf("configure mailer: %w", err)
	}
	invitationService := invitation.NewService(store.Users, store.Organizations, store.Memberships, store.Invitations, passwordHasher, refreshManager, sender, cfg.InvitationTokenTTL)
	auditService := audit.NewService(store.AuditEvents, store.Memberships)
	recoveryService := recovery.NewService(store.Users, store.PasswordResets, store.Sessions, passwordHasher, refreshManager, sender, cfg.PasswordResetTTL)

	server := echo.New()
	server.HideBanner = true
	server.IPExtractor = echo.ExtractIPDirect()
	metrics := observability.NewMetrics()
	server.Use(middleware.RequestID(), middleware.Recover(), middleware.BodyLimit(cfg.RequestBodyLimit))
	server.Use(middleware.SecureWithConfig(middleware.SecureConfig{XFrameOptions: "DENY", ContentSecurityPolicy: "default-src 'none'; frame-ancestors 'none'", ReferrerPolicy: "no-referrer"}))
	server.Use(middleware.CORSWithConfig(middleware.CORSConfig{AllowOrigins: splitCSV(cfg.CORSAllowedOrigins), AllowMethods: []string{http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodDelete, http.MethodOptions}, AllowHeaders: []string{echo.HeaderAuthorization, echo.HeaderContentType, echo.HeaderXRequestID}, ExposeHeaders: []string{echo.HeaderXRequestID}, MaxAge: 300}))
	server.Use(metrics.Middleware)
	server.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{LogRequestID: true, LogRemoteIP: true, LogMethod: true, LogRoutePath: true, LogStatus: true, LogLatency: true, LogError: true, LogValuesFunc: func(_ echo.Context, values middleware.RequestLoggerValues) error {
		slog.Info("http request", "request_id", values.RequestID, "remote_ip", values.RemoteIP, "method", values.Method, "route", values.RoutePath, "status", values.Status, "latency_ms", values.Latency.Milliseconds(), "error", values.Error)
		return nil
	}}))
	server.GET("/metrics", metrics.Handler)
	registerHealthRoutes(server, client)
	httpapi.NewHandler(authService, tokenSigner, cfg.AccessTokenTTL, organizationService).WithInvitationService(invitationService).WithAuditService(auditService).WithRecoveryService(recoveryService).WithSensitiveRateLimit(cfg.SensitiveRateLimit).RegisterRoutes(server)

	return &App{server: server, mongo: client}, nil
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
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
