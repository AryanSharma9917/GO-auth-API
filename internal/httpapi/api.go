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

type authResponse struct {
	AccessToken  string               `json:"access_token"`
	TokenType    string               `json:"token_type"`
	ExpiresIn    int64                `json:"expires_in"`
	User         userResponse         `json:"user"`
	Organization organizationResponse `json:"organization"`
	Membership   membershipResponse   `json:"membership"`
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
	server.GET("/api/v1/auth/me", h.me, h.authenticate)
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
	}, h.accessTokenTTL)
	if err != nil {
		return h.writeAuthError(c, err)
	}
	return c.JSON(http.StatusCreated, responseFromResult(result))
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
	}, h.accessTokenTTL)
	if err != nil {
		return h.writeAuthError(c, err)
	}
	return c.JSON(http.StatusOK, responseFromResult(result))
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
	default:
		return writeError(c, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
	}
}

func writeError(c echo.Context, status int, code, message string) error {
	return c.JSON(status, errorEnvelope{Error: apiError{Code: code, Message: message}})
}

func responseFromResult(result auth.Result) authResponse {
	return authResponse{
		AccessToken:  result.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(result.ExpiresIn.Seconds()),
		User:         userResponse{ID: result.User.ID.Hex(), Email: result.User.Email, DisplayName: result.User.DisplayName, EmailVerified: result.User.EmailVerified},
		Organization: organizationResponse{ID: result.Organization.ID.Hex(), Name: result.Organization.Name, Slug: result.Organization.Slug},
		Membership:   membershipResponse{ID: result.Membership.ID.Hex(), Role: result.Membership.Role, State: string(result.Membership.State)},
	}
}
