package observability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestMetricsRecordsRouteWithoutSensitiveValues(t *testing.T) {
	server := echo.New()
	metrics := NewMetrics()
	server.Use(metrics.Middleware)
	server.GET("/users/:id", func(c echo.Context) error { return c.NoContent(http.StatusNoContent) })
	server.GET("/metrics", metrics.Handler)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/users/secret-user-id?token=secret", nil))
	metricsResponse := httptest.NewRecorder()
	server.ServeHTTP(metricsResponse, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := metricsResponse.Body.String()
	if !strings.Contains(body, `path="/users/:id"`) {
		t.Fatalf("route metric missing: %s", body)
	}
	if strings.Contains(body, "secret-user-id") || strings.Contains(body, "token=secret") {
		t.Fatalf("metric leaked request data: %s", body)
	}
}
