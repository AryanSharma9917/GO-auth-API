package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

type stubHealthChecker struct {
	err error
}

func (s stubHealthChecker) Ping(context.Context, *readpref.ReadPref) error {
	return s.err
}

func TestLiveness(t *testing.T) {
	server := echo.New()
	registerHealthRoutes(server, stubHealthChecker{})

	request := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, response.Code)
	}
}

func TestReadiness(t *testing.T) {
	tests := []struct {
		name       string
		checker    stubHealthChecker
		wantStatus int
	}{
		{name: "ready", checker: stubHealthChecker{}, wantStatus: http.StatusOK},
		{name: "database unavailable", checker: stubHealthChecker{err: errors.New("unavailable")}, wantStatus: http.StatusServiceUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := echo.New()
			registerHealthRoutes(server, tt.checker)

			request := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
			response := httptest.NewRecorder()
			server.ServeHTTP(response, request)

			if response.Code != tt.wantStatus {
				t.Fatalf("expected status %d, got %d", tt.wantStatus, response.Code)
			}
		})
	}
}
