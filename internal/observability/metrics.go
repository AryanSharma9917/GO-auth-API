package observability

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
)

type Metrics struct {
	mu       sync.RWMutex
	requests map[string]uint64
	duration map[string]float64
}

func NewMetrics() *Metrics {
	return &Metrics{requests: make(map[string]uint64), duration: make(map[string]float64)}
}

func (m *Metrics) Middleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		started := time.Now()
		err := next(c)
		status := c.Response().Status
		if status == 0 {
			status = http.StatusOK
		}
		route := c.Path()
		if route == "" {
			route = "unmatched"
		}
		key := fmt.Sprintf("method=%q,path=%q,status=%q", c.Request().Method, route, fmt.Sprint(status))
		m.mu.Lock()
		m.requests[key]++
		m.duration[key] += time.Since(started).Seconds()
		m.mu.Unlock()
		return err
	}
}

func (m *Metrics) Handler(c echo.Context) error {
	m.mu.RLock()
	keys := make([]string, 0, len(m.requests))
	for key := range m.requests {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	body := "# HELP http_requests_total Total HTTP requests.\n# TYPE http_requests_total counter\n"
	for _, key := range keys {
		body += fmt.Sprintf("http_requests_total{%s} %d\n", key, m.requests[key])
	}
	body += "# HELP http_request_duration_seconds_total Total HTTP request duration.\n# TYPE http_request_duration_seconds_total counter\n"
	for _, key := range keys {
		body += fmt.Sprintf("http_request_duration_seconds_total{%s} %g\n", key, m.duration[key])
	}
	m.mu.RUnlock()
	return c.Blob(http.StatusOK, "text/plain; version=0.0.4; charset=utf-8", []byte(body))
}
