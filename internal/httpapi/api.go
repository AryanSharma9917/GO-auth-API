package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"golang-auth/internal/auth"
	"golang-auth/internal/domain"
	"golang-auth/internal/token"

	"github.com/labstack/echo/v4"
)

const principalContextKey = "authenticated-principal"

type AuthService interface {
	Register(context.Context, auth.RegisterInput, time.Duration) (auth.Result, error)
	Login(context.Context, auth.LoginInput, time.Duration) (auth.Result, error)
	Refresh(context.Context, string, time.Duration) (auth.Result, error)
	Logout(context.Context, string) error
	LogoutAll(context.Context, string, string) error
	Sessions(context.Context, string, string) ([]domain.Session, error)
	RevokeSession(context.Context, string, string, string) error
}

type TokenParser interface {
	Parse(string) (token.Claims, error)
}

type Handler struct {
	authService    AuthService
	tokens         TokenParser
	accessTokenTTL time.Duration
}

type Principal struct {
	UserID         string      `json:"user_id"`
	OrganizationID string      `json:"organization_id"`
	Role           domain.Role `json:"role"`
	TokenID        string      `json:"token_id"`
}

type registerRequest struct {
	OrganizationName string `json:"organization_name"`
	OrganizationSlug string `json:"organization_slug"`
	Email            string `json:"email"`
	DisplayName      string `json:"display_name"`
	Password         string `json:"password"`
}

type loginRequest struct {
	OrganizationSlug string `json:"organization_slug"`
	Email            string `json:"email"`
	Password         string `json:"password"`
}

type refreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type authResponse struct {
	AccessToken      string               `json:"access_token"`
	TokenType        string               `json:"token_type"`
	ExpiresIn        int64                `json:"expires_in"`
	RefreshToken     string               `json:"refresh_token"`
	RefreshExpiresIn int64                `json:"refresh_expires_in"`
	User             userResponse         `json:"user"`
	Organization     organizationResponse `json:"organization"`
	Membership       membershipResponse   `json:"membership"`
}

type userResponse struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	DisplayName   string `json:"display_name"`
	EmailVerified bool   `json:"email_verified"`
}

type organizationResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type membershipResponse struct {
	ID    string      `json:"id"`
	Role  domain.Role `json:"role"`
	State string      `json:"state"`
}

type sessionResponse struct {
	ID               string     `json:"id"`
	IPAddress        string     `json:"ip_address,omitempty"`
	UserAgent        string     `json:"user_agent,omitempty"`
	ExpiresAt        time.Time  `json:"expires_at"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevocationReason string     `json:"revocation_reason,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	LastUsedAt       time.Time  `json:"last_used_at"`
}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func NewHandler(authService AuthService, tokens TokenParser, accessTokenTTL time.Duration) *Handler {
	return &Handler{authService: authService, tokens: tokens, accessTokenTTL: accessTokenTTL}
}

func (h *Handler) RegisterRoutes(server *echo.Echo) {
	server.POST("/api/v1/organizations/register", h.register)
	server.POST("/api/v1/auth/login", h.login)
	server.POST("/api/v1/auth/refresh", h.refresh)
	server.POST("/api/v1/auth/logout", h.logout)
	server.GET("/api/v1/auth/me", h.me, h.authenticate)
	server.POST("/api/v1/auth/logout-all", h.logoutAll, h.authenticate)
	server.GET("/api/v1/auth/sessions", h.sessions, h.authenticate)
	server.DELETE("/api/v1/auth/sessions/:sessionId", h.revokeSession, h.authenticate)
}

func (h *Handler) register(c echo.Context) error {
	var request registerRequest
	if err := decodeJSON(c, &request); err != nil {
		return writeError(c, http.StatusBadRequest, "invalid_request", "Request body must contain one valid JSON object")
	}
	result, err := h.authService.Register(c.Request().Context(), auth.RegisterInput{
		OrganizationName: request.OrganizationName,
		OrganizationSlug: request.OrganizationSlug,
		Email:            request.Email,
		DisplayName:      request.DisplayName,
		Password:         request.Password,
		IPAddress:        c.RealIP(),
		UserAgent:        c.Request().UserAgent(),
	}, h.accessTokenTTL)
	if err != nil {
		return h.writeAuthError(c, err)
	}
	return writeAuthResponse(c, http.StatusCreated, result)
}

func (h *Handler) login(c echo.Context) error {
	var request loginRequest
	if err := decodeJSON(c, &request); err != nil {
		return writeError(c, http.StatusBadRequest, "invalid_request", "Request body must contain one valid JSON object")
	}
	result, err := h.authService.Login(c.Request().Context(), auth.LoginInput{
		OrganizationSlug: request.OrganizationSlug,
		Email:            request.Email,
		Password:         request.Password,
		IPAddress:        c.RealIP(),
		UserAgent:        c.Request().UserAgent(),
	}, h.accessTokenTTL)
	if err != nil {
		return h.writeAuthError(c, err)
	}
	return writeAuthResponse(c, http.StatusOK, result)
}

func (h *Handler) refresh(c echo.Context) error {
	var request refreshTokenRequest
	if err := decodeJSON(c, &request); err != nil {
		return writeError(c, http.StatusBadRequest, "invalid_request", "Request body must contain one valid JSON object")
	}
	result, err := h.authService.Refresh(c.Request().Context(), request.RefreshToken, h.accessTokenTTL)
	if err != nil {
		return h.writeAuthError(c, err)
	}
	return writeAuthResponse(c, http.StatusOK, result)
}

func (h *Handler) logout(c echo.Context) error {
	var request refreshTokenRequest
	if err := decodeJSON(c, &request); err != nil {
		return writeError(c, http.StatusBadRequest, "invalid_request", "Request body must contain one valid JSON object")
	}
	if err := h.authService.Logout(c.Request().Context(), request.RefreshToken); err != nil {
		return h.writeAuthError(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *Handler) logoutAll(c echo.Context) error {
	principal, _ := PrincipalFromContext(c)
	if err := h.authService.LogoutAll(c.Request().Context(), principal.UserID, principal.OrganizationID); err != nil {
		return h.writeAuthError(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *Handler) sessions(c echo.Context) error {
	principal, _ := PrincipalFromContext(c)
	sessions, err := h.authService.Sessions(c.Request().Context(), principal.UserID, principal.OrganizationID)
	if err != nil {
		return h.writeAuthError(c, err)
	}
	response := make([]sessionResponse, 0, len(sessions))
	for _, session := range sessions {
		response = append(response, sessionResponseFromDomain(session))
	}
	return c.JSON(http.StatusOK, map[string]any{"sessions": response})
}

func (h *Handler) revokeSession(c echo.Context) error {
	principal, _ := PrincipalFromContext(c)
	if err := h.authService.RevokeSession(c.Request().Context(), c.Param("sessionId"), principal.UserID, principal.OrganizationID); err != nil {
		return h.writeAuthError(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *Handler) me(c echo.Context) error {
	principal, ok := PrincipalFromContext(c)
	if !ok {
		return writeError(c, http.StatusUnauthorized, "unauthorized", "A valid access token is required")
	}
	return c.JSON(http.StatusOK, principal)
}

func (h *Handler) authenticate(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		header := c.Request().Header.Get(echo.HeaderAuthorization)
		parts := strings.Fields(header)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			return writeError(c, http.StatusUnauthorized, "unauthorized", "A valid access token is required")
		}
		claims, err := h.tokens.Parse(parts[1])
		if err != nil {
			return writeError(c, http.StatusUnauthorized, "unauthorized", "A valid access token is required")
		}
		c.Set(principalContextKey, Principal{UserID: claims.Subject, OrganizationID: claims.OrganizationID, Role: claims.Role, TokenID: claims.ID})
		return next(c)
	}
}

func PrincipalFromContext(c echo.Context) (Principal, bool) {
	principal, ok := c.Get(principalContextKey).(Principal)
	return principal, ok
}

func decodeJSON(c echo.Context, destination any) error {
	decoder := json.NewDecoder(c.Request().Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON object")
	}
	return nil
}

func (h *Handler) writeAuthError(c echo.Context, err error) error {
	switch {
	case errors.Is(err, auth.ErrInvalidInput):
		return writeError(c, http.StatusUnprocessableEntity, "validation_failed", "One or more fields are invalid")
	case errors.Is(err, auth.ErrConflict):
		return writeError(c, http.StatusConflict, "resource_conflict", "The account or organization already exists")
	case errors.Is(err, auth.ErrInvalidCredentials):
		return writeError(c, http.StatusUnauthorized, "invalid_credentials", "Invalid email, password, or organization")
	case errors.Is(err, auth.ErrInvalidRefreshToken):
		return writeError(c, http.StatusUnauthorized, "invalid_refresh_token", "The refresh token is invalid or expired")
	case errors.Is(err, auth.ErrRefreshTokenReuse):
		return writeError(c, http.StatusUnauthorized, "refresh_token_reuse", "Refresh token reuse was detected and the session was revoked")
	case errors.Is(err, auth.ErrSessionNotFound):
		return writeError(c, http.StatusNotFound, "session_not_found", "The session was not found")
	default:
		return writeError(c, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
	}
}

func writeError(c echo.Context, status int, code, message string) error {
	return c.JSON(status, errorEnvelope{Error: apiError{Code: code, Message: message}})
}

func writeAuthResponse(c echo.Context, status int, result auth.Result) error {
	c.Response().Header().Set(echo.HeaderCacheControl, "no-store")
	c.Response().Header().Set("Pragma", "no-cache")
	return c.JSON(status, responseFromResult(result))
}

func responseFromResult(result auth.Result) authResponse {
	return authResponse{
		AccessToken:      result.AccessToken,
		TokenType:        "Bearer",
		ExpiresIn:        int64(result.ExpiresIn.Seconds()),
		RefreshToken:     result.RefreshToken,
		RefreshExpiresIn: int64(result.RefreshExpiresIn.Seconds()),
		User:             userResponse{ID: result.User.ID.Hex(), Email: result.User.Email, DisplayName: result.User.DisplayName, EmailVerified: result.User.EmailVerified},
		Organization:     organizationResponse{ID: result.Organization.ID.Hex(), Name: result.Organization.Name, Slug: result.Organization.Slug},
		Membership:       membershipResponse{ID: result.Membership.ID.Hex(), Role: result.Membership.Role, State: string(result.Membership.State)},
	}
}

func sessionResponseFromDomain(session domain.Session) sessionResponse {
	return sessionResponse{
		ID: session.ID.Hex(), IPAddress: session.IPAddress, UserAgent: session.UserAgent,
		ExpiresAt: session.ExpiresAt, RevokedAt: session.RevokedAt, RevocationReason: session.RevocationReason,
		CreatedAt: session.CreatedAt, LastUsedAt: session.LastUsedAt,
	}
}
