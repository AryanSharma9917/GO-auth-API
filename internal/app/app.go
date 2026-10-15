package app

import (
	"context"
	"fmt"
	"net/http"

	"golang-auth/configs"
	"golang-auth/db"
	"golang-auth/routes"

	"github.com/labstack/echo/v4"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

type healthChecker interface {
	Ping(context.Context, *readpref.ReadPref) error
}

type App struct {
	server *echo.Echo
	mongo  *mongo.Client
}

func New(cfg configs.Config) (*App, error) {
	client, err := db.ConnectDB(cfg.MongoURI)
	if err != nil {
		return nil, fmt.Errorf("connect to MongoDB: %w", err)
	}

	server := echo.New()
	server.HideBanner = true
	registerHealthRoutes(server, client)
	routes.InitRoutes(server, client, cfg)

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
