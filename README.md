# Go Auth API

A production-oriented, multi-tenant authentication and organization access API built with Go, Echo, and MongoDB.

## What it provides

- Organization registration with an initial owner
- Email/password login and role-based organization access
- Short-lived JWT access tokens and rotating opaque refresh tokens
- Session listing, revocation, logout-all, and refresh-token reuse detection
- Owner/admin/member management with final-owner protection
- Expiring, single-use member invitations
- Password change and password reset with session revocation
- Organization audit logs, request IDs, structured logs, rate limits, and metrics

## Run locally

Requirements: Docker with Compose.

```bash
cp .env.example .env
docker compose up --build
curl http://localhost:8080/health/ready
```

The development mailer writes invitation and password-reset URLs to the API logs. Production mode requires SMTP configuration and never logs these tokens.

## Development

```bash
go test ./...
go test -race ./...
go vet ./...
```

Protected requests use `Authorization: Bearer <access-token>`. The HTTP contract is in [openapi.yaml](openapi.yaml), and implementation and operating notes are in [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md).

## Operational endpoints

- `GET /health/live` — process liveness
- `GET /health/ready` — MongoDB readiness
- `GET /metrics` — Prometheus text metrics

Configuration is environment-only. Copy `.env.example`, use a random JWT secret of at least 32 characters, restrict `CORS_ALLOWED_ORIGINS`, and never commit `.env`.

## Production

Build with `docker build -t go-auth-api .`. The image is multi-stage and runs as a non-root user. See `compose.production.yaml` and [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md).
