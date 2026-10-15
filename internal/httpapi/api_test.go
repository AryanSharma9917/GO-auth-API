package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang-auth/internal/auth"
	"golang-auth/internal/domain"
	"golang-auth/internal/token"

	"github.com/labstack/echo/v4"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type authServiceStub struct {
	result auth.Result
	err    error
}

func (s authServiceStub) Register(context.Context, auth.RegisterInput, time.Duration) (auth.Result, error) {
	return s.result, s.err
}
func (s authServiceStub) Login(context.Context, auth.LoginInput, time.Duration) (auth.Result, error) {
	return s.result, s.err
}

func TestRegisterResponseDoesNotExposePasswordHash(t *testing.T) {
	result := auth.Result{
		AccessToken: "access-token", ExpiresIn: 15 * time.Minute,
		User:         domain.User{ID: bson.NewObjectID(), Email: "owner@example.com", DisplayName: "Owner", PasswordHash: "secret-hash"},
		Organization: domain.Organization{ID: bson.NewObjectID(), Name: "Example", Slug: "example"},
		Membership:   domain.Membership{ID: bson.NewObjectID(), Role: domain.RoleOwner, State: domain.MembershipActive},
	}
	server := echo.New()
	NewHandler(authServiceStub{result: result}, nil, 15*time.Minute).RegisterRoutes(server)
	body := `{"organization_name":"Example","organization_slug":"example","email":"owner@example.com","display_name":"Owner","password":"a-secure-password"}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/register", strings.NewReader(body))
	request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d: %s", http.StatusCreated, response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "secret-hash") || strings.Contains(response.Body.String(), "password") {
		t.Fatalf("response exposed password data: %s", response.Body.String())
	}
}

func TestRegisterRejectsUnknownJSONFields(t *testing.T) {
	server := echo.New()
	NewHandler(authServiceStub{}, nil, 15*time.Minute).RegisterRoutes(server)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/register", strings.NewReader(`{"unknown":true}`))
	request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, response.Code)
	}
}

func TestAuthenticationMiddleware(t *testing.T) {
	signer, err := token.NewSigner("a-secret-that-is-at-least-32-characters", "issuer", "audience", 15*time.Minute)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	userID := bson.NewObjectID().Hex()
	organizationID := bson.NewObjectID().Hex()
	accessToken, err := signer.Issue(userID, organizationID, domain.RoleOwner)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	server := echo.New()
	NewHandler(authServiceStub{}, signer, 15*time.Minute).RegisterRoutes(server)

	unauthorized := httptest.NewRecorder()
	server.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("expected missing token status %d, got %d", http.StatusUnauthorized, unauthorized.Code)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	request.Header.Set(echo.HeaderAuthorization, "Bearer "+accessToken)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected valid token status %d, got %d", http.StatusOK, response.Code)
	}
	var principal Principal
	if err := json.Unmarshal(response.Body.Bytes(), &principal); err != nil {
		t.Fatalf("decode principal: %v", err)
	}
	if principal.UserID != userID || principal.OrganizationID != organizationID {
		t.Fatalf("unexpected principal: %+v", principal)
	}
}
