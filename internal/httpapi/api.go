package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang-auth/internal/audit"
	"golang-auth/internal/auth"
	"golang-auth/internal/domain"
	"golang-auth/internal/invitation"
	"golang-auth/internal/organization"
	"golang-auth/internal/recovery"
	"golang-auth/internal/token"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/time/rate"
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

type OrganizationService interface {
	Current(context.Context, organization.Actor) (domain.Organization, domain.Membership, error)
	UpdateName(context.Context, organization.Actor, string) (domain.Organization, error)
	Members(context.Context, organization.Actor, string, int) (organization.MemberPage, error)
	UpdateMember(context.Context, organization.Actor, string, organization.UpdateMemberInput) (organization.Member, error)
	RemoveMember(context.Context, organization.Actor, string) error
}

type InvitationService interface {
	Create(context.Context, invitation.Actor, invitation.CreateInput) (domain.Invitation, error)
	List(context.Context, invitation.Actor, string, int) (invitation.Page, error)
	Revoke(context.Context, invitation.Actor, string) error
	Accept(context.Context, string, invitation.AcceptInput) (invitation.Acceptance, error)
}

type AuditService interface {
	Record(context.Context, audit.RecordInput) error
	List(context.Context, audit.Actor, string, string, int) (audit.Page, error)
}

type RecoveryService interface {
	Request(context.Context, string) error
	Confirm(context.Context, string, string) error
	Change(context.Context, string, string, string) error
}

type Handler struct {
	authService    AuthService
	tokens         TokenParser
	accessTokenTTL time.Duration
	organizations  OrganizationService
	invitations    InvitationService
	audit          AuditService
	rateLimit      rate.Limit
	recovery       RecoveryService
}

func (h *Handler) WithSensitiveRateLimit(requestsPerSecond float64) *Handler {
	h.rateLimit = rate.Limit(requestsPerSecond)
	return h
}

func (h *Handler) WithRecoveryService(service RecoveryService) *Handler {
	h.recovery = service
	return h
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

type updateOrganizationRequest struct {
	Name string `json:"name"`
}

type updateMemberRequest struct {
	Role  *domain.Role            `json:"role"`
	State *domain.MembershipState `json:"state"`
}

type createInvitationRequest struct {
	Email string      `json:"email"`
	Role  domain.Role `json:"role"`
}

type acceptInvitationRequest struct {
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
}

type passwordResetRequest struct {
	Email string `json:"email"`
}
type passwordResetConfirmRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}
type passwordChangeRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
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

type memberResponse struct {
	Membership membershipResponse `json:"membership"`
	User       userResponse       `json:"user"`
}

type invitationResponse struct {
	ID        string      `json:"id"`
	Email     string      `json:"email"`
	Role      domain.Role `json:"role"`
	Status    string      `json:"status"`
	ExpiresAt time.Time   `json:"expires_at"`
	CreatedAt time.Time   `json:"created_at"`
}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

func NewHandler(authService AuthService, tokens TokenParser, accessTokenTTL time.Duration, organizations ...OrganizationService) *Handler {
	handler := &Handler{authService: authService, tokens: tokens, accessTokenTTL: accessTokenTTL}
	if len(organizations) > 0 {
		handler.organizations = organizations[0]
	}
	return handler
}

func (h *Handler) WithInvitationService(service InvitationService) *Handler {
	h.invitations = service
	return h
}

func (h *Handler) WithAuditService(service AuditService) *Handler {
	h.audit = service
	return h
}

func (h *Handler) RegisterRoutes(server *echo.Echo) {
	var sensitive []echo.MiddlewareFunc
	if h.rateLimit > 0 {
		sensitive = []echo.MiddlewareFunc{middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(h.rateLimit))}
	}
	server.POST("/api/v1/organizations/register", h.register, sensitive...)
	server.POST("/api/v1/auth/login", h.login, sensitive...)
	server.POST("/api/v1/auth/refresh", h.refresh, sensitive...)
	server.POST("/api/v1/auth/logout", h.logout)
	if h.recovery != nil {
		server.POST("/api/v1/auth/password/reset-request", h.requestPasswordReset, sensitive...)
		server.POST("/api/v1/auth/password/reset-confirm", h.confirmPasswordReset, sensitive...)
		server.POST("/api/v1/auth/password/change", h.changePassword, h.authenticate)
	}
	server.GET("/api/v1/auth/me", h.me, h.authenticate)
	server.POST("/api/v1/auth/logout-all", h.logoutAll, h.authenticate)
	server.GET("/api/v1/auth/sessions", h.sessions, h.authenticate)
	server.DELETE("/api/v1/auth/sessions/:sessionId", h.revokeSession, h.authenticate)
	if h.organizations != nil {
		server.GET("/api/v1/organizations/current", h.currentOrganization, h.authenticate)
		server.PATCH("/api/v1/organizations/current", h.updateOrganization, h.authenticate)
		server.GET("/api/v1/organizations/current/members", h.members, h.authenticate)
		server.PATCH("/api/v1/organizations/current/members/:memberId", h.updateMember, h.authenticate)
		server.DELETE("/api/v1/organizations/current/members/:memberId", h.removeMember, h.authenticate)
	}
	if h.invitations != nil {
		server.POST("/api/v1/organizations/current/invitations", h.createInvitation, append([]echo.MiddlewareFunc{h.authenticate}, sensitive...)...)
		server.GET("/api/v1/organizations/current/invitations", h.invitationsList, h.authenticate)
		server.DELETE("/api/v1/organizations/current/invitations/:invitationId", h.revokeInvitation, h.authenticate)
		server.POST("/api/v1/invitations/:token/accept", h.acceptInvitation, sensitive...)
	}
	if h.audit != nil {
		server.GET("/api/v1/organizations/current/audit-events", h.auditEvents, h.authenticate)
	}
}

func (h *Handler) requestPasswordReset(c echo.Context) error {
	var request passwordResetRequest
	if err := decodeJSON(c, &request); err != nil {
		return writeError(c, http.StatusBadRequest, "invalid_request", "Request body must contain one valid JSON object")
	}
	if err := h.recovery.Request(c.Request().Context(), request.Email); err != nil {
		return writeError(c, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
	}
	return c.JSON(http.StatusAccepted, map[string]string{"message": "If the account exists, reset instructions will be sent"})
}

func (h *Handler) confirmPasswordReset(c echo.Context) error {
	var request passwordResetConfirmRequest
	if err := decodeJSON(c, &request); err != nil {
		return writeError(c, http.StatusBadRequest, "invalid_request", "Request body must contain one valid JSON object")
	}
	if err := h.recovery.Confirm(c.Request().Context(), request.Token, request.NewPassword); err != nil {
		if errors.Is(err, recovery.ErrInvalidInput) {
			return writeError(c, http.StatusUnprocessableEntity, "validation_failed", "The new password is invalid")
		}
		if errors.Is(err, recovery.ErrInvalidToken) {
			return writeError(c, http.StatusUnauthorized, "invalid_reset_token", "The reset token is invalid or expired")
		}
		return writeError(c, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *Handler) changePassword(c echo.Context) error {
	var request passwordChangeRequest
	if err := decodeJSON(c, &request); err != nil {
		return writeError(c, http.StatusBadRequest, "invalid_request", "Request body must contain one valid JSON object")
	}
	principal, _ := PrincipalFromContext(c)
	if err := h.recovery.Change(c.Request().Context(), principal.UserID, request.CurrentPassword, request.NewPassword); err != nil {
		if errors.Is(err, recovery.ErrInvalidInput) {
			return writeError(c, http.StatusUnprocessableEntity, "validation_failed", "The new password is invalid")
		}
		if errors.Is(err, recovery.ErrUnauthorized) {
			return writeError(c, http.StatusUnauthorized, "invalid_credentials", "The current password is invalid")
		}
		return writeError(c, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
	}
	h.recordAudit(c, principal.OrganizationID, principal.UserID, "password.changed", "user", principal.UserID, nil)
	return c.NoContent(http.StatusNoContent)
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
	h.recordAudit(c, result.Organization.ID.Hex(), result.User.ID.Hex(), "organization.registered", "organization", result.Organization.ID.Hex(), nil)
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
	h.recordAudit(c, result.Organization.ID.Hex(), result.User.ID.Hex(), "auth.login", "session", result.Session.ID.Hex(), nil)
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
	h.recordAudit(c, principal.OrganizationID, principal.UserID, "session.revoked_all", "user", principal.UserID, nil)
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
	h.recordAudit(c, principal.OrganizationID, principal.UserID, "session.revoked", "session", c.Param("sessionId"), nil)
	return c.NoContent(http.StatusNoContent)
}

func (h *Handler) currentOrganization(c echo.Context) error {
	principal, _ := PrincipalFromContext(c)
	organizationValue, membership, err := h.organizations.Current(c.Request().Context(), actorFromPrincipal(principal))
	if err != nil {
		return h.writeOrganizationError(c, err)
	}
	return c.JSON(http.StatusOK, map[string]any{
		"organization": organizationResponse{ID: organizationValue.ID.Hex(), Name: organizationValue.Name, Slug: organizationValue.Slug},
		"membership":   membershipResponseFromDomain(membership),
	})
}

func (h *Handler) updateOrganization(c echo.Context) error {
	var request updateOrganizationRequest
	if err := decodeJSON(c, &request); err != nil {
		return writeError(c, http.StatusBadRequest, "invalid_request", "Request body must contain one valid JSON object")
	}
	principal, _ := PrincipalFromContext(c)
	organizationValue, err := h.organizations.UpdateName(c.Request().Context(), actorFromPrincipal(principal), request.Name)
	if err != nil {
		return h.writeOrganizationError(c, err)
	}
	h.recordAudit(c, principal.OrganizationID, principal.UserID, "organization.updated", "organization", principal.OrganizationID, nil)
	return c.JSON(http.StatusOK, organizationResponse{ID: organizationValue.ID.Hex(), Name: organizationValue.Name, Slug: organizationValue.Slug})
}

func (h *Handler) members(c echo.Context) error {
	limit := 0
	if value := c.QueryParam("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return writeError(c, http.StatusUnprocessableEntity, "validation_failed", "The pagination limit is invalid")
		}
		limit = parsed
	}
	principal, _ := PrincipalFromContext(c)
	page, err := h.organizations.Members(c.Request().Context(), actorFromPrincipal(principal), c.QueryParam("cursor"), limit)
	if err != nil {
		return h.writeOrganizationError(c, err)
	}
	members := make([]memberResponse, 0, len(page.Members))
	for _, member := range page.Members {
		members = append(members, memberResponseFromDomain(member))
	}
	return c.JSON(http.StatusOK, map[string]any{"members": members, "next_cursor": page.NextCursor})
}

func (h *Handler) updateMember(c echo.Context) error {
	var request updateMemberRequest
	if err := decodeJSON(c, &request); err != nil {
		return writeError(c, http.StatusBadRequest, "invalid_request", "Request body must contain one valid JSON object")
	}
	principal, _ := PrincipalFromContext(c)
	member, err := h.organizations.UpdateMember(c.Request().Context(), actorFromPrincipal(principal), c.Param("memberId"), organization.UpdateMemberInput{Role: request.Role, State: request.State})
	if err != nil {
		return h.writeOrganizationError(c, err)
	}
	h.recordAudit(c, principal.OrganizationID, principal.UserID, "membership.updated", "membership", c.Param("memberId"), map[string]any{"role": member.Membership.Role, "state": member.Membership.State})
	return c.JSON(http.StatusOK, memberResponseFromDomain(member))
}

func (h *Handler) removeMember(c echo.Context) error {
	principal, _ := PrincipalFromContext(c)
	if err := h.organizations.RemoveMember(c.Request().Context(), actorFromPrincipal(principal), c.Param("memberId")); err != nil {
		return h.writeOrganizationError(c, err)
	}
	h.recordAudit(c, principal.OrganizationID, principal.UserID, "membership.removed", "membership", c.Param("memberId"), nil)
	return c.NoContent(http.StatusNoContent)
}

func (h *Handler) createInvitation(c echo.Context) error {
	var request createInvitationRequest
	if err := decodeJSON(c, &request); err != nil {
		return writeError(c, http.StatusBadRequest, "invalid_request", "Request body must contain one valid JSON object")
	}
	principal, _ := PrincipalFromContext(c)
	value, err := h.invitations.Create(c.Request().Context(), invitationActor(principal), invitation.CreateInput{Email: request.Email, Role: request.Role})
	if err != nil {
		return h.writeInvitationError(c, err)
	}
	h.recordAudit(c, principal.OrganizationID, principal.UserID, "invitation.created", "invitation", value.ID.Hex(), map[string]any{"email": value.Email, "role": value.Role})
	return c.JSON(http.StatusCreated, invitationResponseFromDomain(value, time.Now().UTC()))
}

func (h *Handler) invitationsList(c echo.Context) error {
	limit := 0
	if value := c.QueryParam("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return writeError(c, http.StatusUnprocessableEntity, "validation_failed", "The pagination limit is invalid")
		}
		limit = parsed
	}
	principal, _ := PrincipalFromContext(c)
	page, err := h.invitations.List(c.Request().Context(), invitationActor(principal), c.QueryParam("cursor"), limit)
	if err != nil {
		return h.writeInvitationError(c, err)
	}
	items := make([]invitationResponse, 0, len(page.Invitations))
	now := time.Now().UTC()
	for _, value := range page.Invitations {
		items = append(items, invitationResponseFromDomain(value, now))
	}
	return c.JSON(http.StatusOK, map[string]any{"invitations": items, "next_cursor": page.NextCursor})
}

func (h *Handler) revokeInvitation(c echo.Context) error {
	principal, _ := PrincipalFromContext(c)
	if err := h.invitations.Revoke(c.Request().Context(), invitationActor(principal), c.Param("invitationId")); err != nil {
		return h.writeInvitationError(c, err)
	}
	h.recordAudit(c, principal.OrganizationID, principal.UserID, "invitation.revoked", "invitation", c.Param("invitationId"), nil)
	return c.NoContent(http.StatusNoContent)
}

func (h *Handler) acceptInvitation(c echo.Context) error {
	var request acceptInvitationRequest
	if err := decodeJSON(c, &request); err != nil {
		return writeError(c, http.StatusBadRequest, "invalid_request", "Request body must contain one valid JSON object")
	}
	accepted, err := h.invitations.Accept(c.Request().Context(), c.Param("token"), invitation.AcceptInput{DisplayName: request.DisplayName, Password: request.Password})
	if err != nil {
		return h.writeInvitationError(c, err)
	}
	h.recordAudit(c, accepted.Organization.ID.Hex(), accepted.User.ID.Hex(), "invitation.accepted", "membership", accepted.Membership.ID.Hex(), nil)
	return c.JSON(http.StatusCreated, map[string]any{
		"user":         userResponse{ID: accepted.User.ID.Hex(), Email: accepted.User.Email, DisplayName: accepted.User.DisplayName, EmailVerified: accepted.User.EmailVerified},
		"organization": organizationResponse{ID: accepted.Organization.ID.Hex(), Name: accepted.Organization.Name, Slug: accepted.Organization.Slug},
		"membership":   membershipResponseFromDomain(accepted.Membership),
	})
}

func (h *Handler) auditEvents(c echo.Context) error {
	limit := 0
	if value := c.QueryParam("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return writeError(c, http.StatusUnprocessableEntity, "validation_failed", "The pagination limit is invalid")
		}
		limit = parsed
	}
	principal, _ := PrincipalFromContext(c)
	page, err := h.audit.List(c.Request().Context(), audit.Actor{UserID: principal.UserID, OrganizationID: principal.OrganizationID}, c.QueryParam("cursor"), c.QueryParam("action"), limit)
	if err != nil {
		switch {
		case errors.Is(err, audit.ErrInvalidInput):
			return writeError(c, http.StatusUnprocessableEntity, "validation_failed", "The audit query is invalid")
		case errors.Is(err, audit.ErrForbidden):
			return writeError(c, http.StatusForbidden, "forbidden", "You do not have permission to view audit events")
		default:
			return writeError(c, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
		}
	}
	return c.JSON(http.StatusOK, map[string]any{"events": page.Events, "next_cursor": page.NextCursor})
}

func (h *Handler) recordAudit(c echo.Context, organizationID, actorUserID, action, targetType, targetID string, metadata map[string]any) {
	if h.audit == nil {
		return
	}
	err := h.audit.Record(context.WithoutCancel(c.Request().Context()), audit.RecordInput{
		OrganizationID: organizationID, ActorUserID: actorUserID, Action: action, TargetType: targetType,
		TargetID: targetID, RequestID: c.Response().Header().Get(echo.HeaderXRequestID), IPAddress: c.RealIP(), Metadata: metadata,
	})
	if err != nil {
		slog.Error("failed to record audit event", "action", action, "error", err)
	}
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

func (h *Handler) writeOrganizationError(c echo.Context, err error) error {
	switch {
	case errors.Is(err, organization.ErrInvalidInput):
		return writeError(c, http.StatusUnprocessableEntity, "validation_failed", "One or more fields are invalid")
	case errors.Is(err, organization.ErrForbidden):
		return writeError(c, http.StatusForbidden, "forbidden", "You do not have permission to perform this operation")
	case errors.Is(err, organization.ErrNotFound):
		return writeError(c, http.StatusNotFound, "member_not_found", "The organization member was not found")
	case errors.Is(err, organization.ErrLastOwner):
		return writeError(c, http.StatusConflict, "last_owner", "The organization must retain at least one active owner")
	default:
		return writeError(c, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
	}
}

func (h *Handler) writeInvitationError(c echo.Context, err error) error {
	switch {
	case errors.Is(err, invitation.ErrInvalidInput):
		return writeError(c, http.StatusUnprocessableEntity, "validation_failed", "One or more fields are invalid")
	case errors.Is(err, invitation.ErrForbidden):
		return writeError(c, http.StatusForbidden, "forbidden", "You do not have permission to manage invitations")
	case errors.Is(err, invitation.ErrConflict):
		return writeError(c, http.StatusConflict, "invitation_conflict", "A pending invitation or membership already exists")
	case errors.Is(err, invitation.ErrNotFound):
		return writeError(c, http.StatusNotFound, "invitation_not_found", "The invitation was not found")
	case errors.Is(err, invitation.ErrInvalidInvitation):
		return writeError(c, http.StatusUnauthorized, "invalid_invitation", "The invitation is invalid or expired")
	default:
		return writeError(c, http.StatusInternalServerError, "internal_error", "An unexpected error occurred")
	}
}

func writeError(c echo.Context, status int, code, message string) error {
	requestID := c.Response().Header().Get(echo.HeaderXRequestID)
	if requestID == "" {
		requestID = c.Request().Header.Get(echo.HeaderXRequestID)
	}
	return c.JSON(status, errorEnvelope{Error: apiError{Code: code, Message: message, RequestID: requestID}})
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

func actorFromPrincipal(principal Principal) organization.Actor {
	return organization.Actor{UserID: principal.UserID, OrganizationID: principal.OrganizationID}
}

func membershipResponseFromDomain(membership domain.Membership) membershipResponse {
	return membershipResponse{ID: membership.ID.Hex(), Role: membership.Role, State: string(membership.State)}
}

func memberResponseFromDomain(member organization.Member) memberResponse {
	return memberResponse{
		Membership: membershipResponseFromDomain(member.Membership),
		User:       userResponse{ID: member.User.ID.Hex(), Email: member.User.Email, DisplayName: member.User.DisplayName, EmailVerified: member.User.EmailVerified},
	}
}

func invitationActor(principal Principal) invitation.Actor {
	return invitation.Actor{UserID: principal.UserID, OrganizationID: principal.OrganizationID}
}

func invitationResponseFromDomain(value domain.Invitation, now time.Time) invitationResponse {
	status := value.Status
	if status == domain.InvitationPending && !value.ExpiresAt.After(now) {
		status = "expired"
	}
	return invitationResponse{ID: value.ID.Hex(), Email: value.Email, Role: value.Role, Status: status, ExpiresAt: value.ExpiresAt, CreatedAt: value.CreatedAt}
}
