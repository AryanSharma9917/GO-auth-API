# Production Implementation Plan

## 1. Goal

Turn the existing authentication prototype into a production-oriented, multi-tenant team access service for small organizations and internal tools.

The first usable release will let an organization:

- create a workspace;
- invite and manage members;
- assign owner, admin, and member roles;
- authenticate users with short-lived access tokens;
- manage and revoke refresh-token sessions; and
- review an audit trail of security-sensitive activity.

The API will remain written in Go and will continue to use MongoDB. The current endpoints and data model are prototypes, so backward compatibility is not a requirement for the first production release.

## 2. Working and Commit Process

Implementation will be divided into small checkpoints. At each checkpoint:

1. The planned files are changed.
2. Formatting, tests, and relevant static checks are run.
3. A concise summary and the exact changed files are presented for review.
4. The repository is left uncommitted.
5. The project owner reviews, commits, and pushes the work.

No commits, pushes, contributor trailers, co-author lines, or AI attribution will be added by the implementation assistant.

Suggested commit messages are intentionally simple and can be changed before committing.

## 3. Product Scope

### Included in the first release

- Versioned REST API under `/api/v1`
- Organization registration and initial owner creation
- Email and password login
- Access and refresh tokens
- Refresh-token rotation and reuse protection
- Logout from one session or all sessions
- Organization-scoped member management
- Owner, admin, and member roles
- Invitations with expiring, single-use tokens
- User deactivation
- Audit events
- Health and readiness checks
- OpenAPI documentation
- Local Docker Compose environment
- Production container image
- Continuous integration and security checks

### Deferred until after the API MVP

- Web administration dashboard
- OAuth or social login
- SAML/OIDC enterprise single sign-on
- Multi-factor authentication
- SCIM provisioning
- Fine-grained custom permission policies
- Billing and subscription management
- Transactional email provider integration beyond an interface and development adapter

## 4. Architecture

The code will be organized around explicit dependencies rather than package-level globals.

```text
cmd/api                 application entry point
internal/config         environment configuration and validation
internal/http           router, middleware, handlers, and API DTOs
internal/auth           authentication and token business logic
internal/organization   organizations, memberships, roles, and invitations
internal/audit          audit event creation and querying
internal/store          MongoDB repositories and index setup
internal/password       password hashing and policy
internal/token          access-token signing and refresh-token generation
internal/clock          controllable time source for tests
```

Handlers will only perform HTTP concerns: decoding, validation, calling a service, and encoding a response. Services will enforce authorization and business rules. Repositories will encapsulate MongoDB operations.

Dependencies will be constructed in `main` and passed explicitly. Startup will validate configuration, connect to MongoDB, create required indexes, start the HTTP server, and handle graceful shutdown.

## 5. Domain Model

### User

- ID
- Email (normalized and unique)
- Display name
- Password hash
- Email verification state
- Global account state
- Created and updated timestamps

Passwords will never appear in API response models.

### Organization

- ID
- Name
- Slug
- Created and updated timestamps

### Membership

- ID
- Organization ID
- User ID
- Role: `owner`, `admin`, or `member`
- State: `active` or `disabled`
- Created and updated timestamps

Authorization will always use the authenticated user ID and organization ID. A request parameter will never be trusted as the caller's identity.

### Session

- ID
- User ID
- Organization ID
- Hash of the current refresh token
- Token family ID
- Expiry and revocation timestamps
- Creation and last-used timestamps
- Optional client metadata such as IP address and user agent

Raw refresh tokens will not be stored in MongoDB. A rotated token will invalidate its predecessor. Reuse of an invalidated token will revoke its token family.

### Invitation

- ID
- Organization ID
- Normalized email
- Intended role
- Hash of the invitation token
- Inviter user ID
- Expiry, accepted, and revoked timestamps

### Audit Event

- ID
- Organization ID
- Actor user ID
- Action
- Target type and ID
- Request ID
- IP address and selected metadata
- Creation timestamp

Audit records must not contain passwords, raw tokens, secrets, or full authorization headers.

## 6. API Outline

```text
POST   /api/v1/organizations/register
POST   /api/v1/auth/login
POST   /api/v1/auth/refresh
POST   /api/v1/auth/logout
POST   /api/v1/auth/logout-all
GET    /api/v1/auth/sessions
DELETE /api/v1/auth/sessions/{sessionId}

GET    /api/v1/organizations/current
PATCH  /api/v1/organizations/current
GET    /api/v1/organizations/current/members
PATCH  /api/v1/organizations/current/members/{memberId}
DELETE /api/v1/organizations/current/members/{memberId}

POST   /api/v1/organizations/current/invitations
GET    /api/v1/organizations/current/invitations
DELETE /api/v1/organizations/current/invitations/{invitationId}
POST   /api/v1/invitations/{token}/accept

GET    /api/v1/organizations/current/audit-events

GET    /health/live
GET    /health/ready
```

All JSON endpoints will use typed request and response bodies. Errors will use a consistent structure containing a stable machine-readable code, a safe message, and the request ID.

Pagination will be cursor-based for members, invitations, sessions, and audit events.

## 7. Security Baseline

- No default production secrets
- Minimum secret/key validation at startup
- Explicit JWT algorithm, issuer, audience, subject, expiry, issued-at, and token-ID validation
- Short-lived access tokens
- Cryptographically random opaque refresh and invitation tokens
- Hash-only storage for opaque tokens
- Refresh-token rotation and family revocation
- Configurable password policy and bcrypt cost
- Generic login failures to limit account discovery
- Rate limits for authentication and invitation endpoints
- Request body limits and strict JSON decoding
- Configurable CORS allowlist
- Secure HTTP headers
- Request-scoped database timeouts
- Organization scope applied in service and repository queries
- Role checks centralized in authorization middleware/services
- Unique and TTL MongoDB indexes
- Structured logs with secret redaction
- No internal database errors exposed to clients

## 8. Implementation Checkpoints

### Checkpoint 1: Repository foundation

Work:

- Add `.gitignore` and remove the tracked build artifact from the repository.
- Introduce the new directory structure and application constructor.
- Move startup work out of `init()`.
- Add validated environment configuration.
- Add graceful shutdown and basic liveness/readiness endpoints.
- Update to a currently supported Go toolchain and compatible dependencies.

Verification:

- Application builds.
- Configuration tests pass.
- Server tests cover health endpoints and shutdown behavior where practical.
- No secret has a production default.

Suggested commit message: `Set up the application foundation`

### Checkpoint 2: MongoDB storage foundation

Work:

- Add repository interfaces and MongoDB implementations.
- Define the new domain documents.
- Configure connection and operation timeouts.
- Create unique, compound, and TTL indexes idempotently.
- Add a Docker Compose environment for MongoDB and the API.

Verification:

- Repository integration tests run against MongoDB.
- Duplicate identities and memberships are rejected.
- Expiring records have the expected TTL indexes.

Suggested commit message: `Add the MongoDB data layer`

### Checkpoint 3: Registration and login

Work:

- Add organization registration with its initial owner.
- Add password hashing and validation.
- Add login and signed access tokens.
- Add authentication middleware and current-principal context.
- Return typed, sanitized responses.

Verification:

- Handler and service tests cover success and failure cases.
- Tokens with the wrong issuer, audience, algorithm, signature, or expiry are rejected.
- Password hashes never appear in responses or logs.

Suggested commit message: `Add registration and login`

### Checkpoint 4: Session lifecycle

Work:

- Add opaque refresh tokens and hash-only persistence.
- Rotate refresh tokens on every successful refresh.
- Detect refresh-token reuse and revoke the token family.
- Add single-session logout, all-session logout, session listing, and session revocation.

Verification:

- Rotation and replay scenarios have tests.
- Logging out makes the relevant refresh session unusable.
- Expired and revoked sessions cannot refresh access.

Suggested commit message: `Add secure session management`

### Checkpoint 5: Organizations and roles

Work:

- Add current-organization and member endpoints.
- Centralize owner, admin, and member permissions.
- Add role-change, member-disable, and member-removal rules.
- Prevent removal or demotion of the final organization owner.

Verification:

- Cross-organization access tests cover every protected operation.
- Each role's allowed and denied operations are tested.
- Caller identity always comes from authenticated claims.

Suggested commit message: `Add organization member management`

### Checkpoint 6: Invitations

Work:

- Add invitation creation, listing, revocation, and acceptance.
- Store only token hashes.
- Enforce expiry and one-time acceptance.
- Add a mailer interface and a local development implementation.

Verification:

- Expired, revoked, reused, and cross-organization invitations fail safely.
- Invitation emails can be inspected locally without an external provider.

Suggested commit message: `Add member invitations`

### Checkpoint 7: Audit trail

Work:

- Record login, logout, session, invitation, role, membership, and organization changes.
- Add organization-scoped audit-event queries with filtering and pagination.
- Define a metadata allowlist to avoid recording secrets.

Verification:

- Sensitive actions generate audit events.
- Audit records cannot be queried across organizations.
- Secret values are absent from audit metadata.

Suggested commit message: `Add organization audit logs`

### Checkpoint 8: API protection and observability

Work:

- Add request IDs, structured logging, panic recovery, security headers, and body limits.
- Add configurable CORS and trusted-proxy handling.
- Add route-specific rate limiting.
- Add Prometheus-compatible metrics and tracing hooks.

Verification:

- Logs correlate with response request IDs.
- Authentication endpoints enforce their limits.
- Logs and metrics do not expose credentials or tokens.

Suggested commit message: `Add API safeguards and monitoring`

### Checkpoint 9: Documentation and delivery

Work:

- Replace inaccurate project documentation.
- Add an OpenAPI specification and examples.
- Document local setup, configuration, security decisions, and deployment.
- Add a multi-stage Dockerfile running as a non-root user.
- Expand CI to run formatting, vetting, tests, race checks, vulnerability checks, and builds.
- Add dependency update automation.

Verification:

- A new developer can run the service from the README.
- OpenAPI validation passes.
- The container starts, reports readiness, and shuts down cleanly.
- CI passes from a clean checkout.

Suggested commit message: `Prepare the API for deployment`

### Checkpoint 10: Production review

Work:

- Perform an authorization-boundary review.
- Document the threat model, backup/restore procedure, key rotation, and incident response basics.
- Run load tests for login, refresh, and member listing.
- Establish initial service-level objectives.

Verification:

- All release acceptance criteria below are met.
- Known limitations are documented.
- A tagged release can be built reproducibly.

Suggested commit message: `Complete the production readiness review`

## 9. Testing Strategy

- Unit tests for password, token, validation, and authorization logic
- Table-driven service tests for roles and business rules
- HTTP tests for status codes, response schemas, middleware, and error handling
- MongoDB integration tests for repositories and indexes
- End-to-end tests for registration, login, refresh, invitations, and member administration
- Race detector in CI
- Fuzz tests for token parsing and selected request decoders
- Load tests kept outside the normal unit-test suite

External systems such as time, randomness, email, token signing, and persistence will be represented by narrow interfaces when doing so improves deterministic testing.

## 10. Release Acceptance Criteria

The API MVP is ready for a production pilot when:

- all protected routes require a verified access token;
- authorization and organization boundaries have automated negative tests;
- no password, raw refresh token, invitation token, or secret is persisted or logged unsafely;
- refresh rotation, reuse detection, and revocation work end to end;
- configuration fails fast when required values are missing or unsafe;
- health checks, graceful shutdown, logs, metrics, and request IDs work;
- MongoDB indexes and backup/restore steps are documented;
- the OpenAPI contract matches the implemented API;
- a clean checkout passes CI and produces the production container; and
- local setup and a deployment path are documented and reproducible.

## 11. Later Product Milestones

After the API MVP is stable:

1. Build a small web dashboard for owners and administrators.
2. Integrate a transactional email provider.
3. Add email verification and password recovery.
4. Add MFA using TOTP and recovery codes.
5. Publish a small Go or TypeScript client SDK.
6. Run a private pilot with one or two organizations.
7. Use pilot feedback to decide whether SSO, custom roles, or hosted operations should be the next paid capability.

The implementation should favor a narrow, dependable product over adding many identity features before the core authorization and session model has been proven.
