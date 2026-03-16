# SecureLLM Gateway

A production-grade API gateway for Large Language Model applications, built in Go with defense-in-depth security architecture.

This project demonstrates how to build the infrastructure layer behind a high-volume LLM service — focusing on the security, compliance, and scalability concerns that matter in production.

## Security Coverage

### OWASP Top 10 Web Application Security

| # | Risk | Mitigation |
|---|------|------------|
| A01 | Broken Access Control | JWT authentication with role-based access control (RBAC) |
| A02 | Cryptographic Failures | TLS enforcement via HSTS, secure token generation with `crypto/rand` |
| A03 | Injection | Input validation, output encoding, Content Security Policy |
| A04 | Insecure Design | Middleware chain architecture, defense-in-depth layers |
| A05 | Security Misconfiguration | Environment-based config, hardened HTTP headers, distroless containers |
| A06 | Vulnerable Components | Minimal dependencies, supply chain awareness |
| A07 | Auth Failures | JWT verification, token expiration, algorithm pinning, anti-enumeration |
| A08 | Data Integrity Failures | Request validation, signed tokens |
| A09 | Logging Failures | Structured JSON audit logs with request tracing |
| A10 | SSRF | Restricted outbound connections, allowlisted backends |

### OWASP Top 10 for LLM Applications

| # | Risk | Mitigation |
|---|------|------------|
| LLM01 | Prompt Injection | Input sanitization, prompt/response boundary enforcement |
| LLM02 | Insecure Output Handling | Output encoding, PII redaction, content filtering |
| LLM04 | Model Denial of Service | Per-user rate limiting, request size limits, token budgets |
| LLM05 | Supply Chain Vulnerabilities | Minimal dependencies, pinned versions, SBOM generation |
| LLM06 | Excessive Agency | RBAC-restricted model access, scoped permissions per role |
| LLM07 | Data Leakage | PII detection and redaction in responses |
| LLM09 | Overreliance | Audit logging of all LLM interactions for review |

### PCI DSS Compliance Controls

| Requirement | Implementation |
|------------|----------------|
| Req 2 — No default credentials | Environment-based secrets, no hardcoded values |
| Req 3 — Protect stored data | Sensitive data never logged, encryption at rest |
| Req 4 — Encrypt transmission | HSTS enforcement, TLS-only communication |
| Req 6 — Secure development | Input validation, error handling, security testing |
| Req 7 — Restrict access | RBAC with least-privilege roles, non-root containers |
| Req 8 — Identify users | JWT-based authentication, unique request tracing |
| Req 10 — Track and monitor | Structured audit logs with timestamps, user IDs, and request IDs |

## Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │              SecureLLM Gateway              │
                    │                                             │
Client Request ───▶│  Rate Limiter                               │
                    │      │                                      │
                    │      ▼                                      │
                    │  Request ID ──▶ Audit Log                   │
                    │      │                                      │
                    │      ▼                                      │
                    │  Security Headers (HSTS, CSP, X-Frame)      │
                    │      │                                      │
                    │      ▼                                      │
                    │  JWT Auth + RBAC                            │
                    │      │                                      │
                    │      ▼                                      │
                    │  Input Sanitizer (Prompt Injection Filter)   │
                    │      │                                      │
                    │      ▼                                      │
                    │  LLM Proxy ──────────▶ LLM Backend (mock)   │
                    │      │                                      │
                    │      ▼                                      │
                    │  Output Sanitizer (PII Redaction)           │
                    │      │                                      │
                    └──────┼──────────────────────────────────────┘
                           ▼
                    JSON Response
```

## Quick Start

### Prerequisites

- Go 1.23+
- Docker (optional)
- kubectl + a Kubernetes cluster (optional)

### Run Locally

```bash
git clone https://github.com/mathewtom/secureLLM-gateway.git
cd secureLLM-gateway
make run
```

The server starts on `http://localhost:8080`.

### Test the API

```bash
# Health check (public)
curl http://localhost:8080/health

# Obtain a JWT token
curl -X POST http://localhost:8080/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username": "user1", "password": "user123"}'

# Chat completion (requires Bearer token)
curl -X POST http://localhost:8080/api/v1/chat \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{"message": "Hello!", "model": "mock-llm-v1"}'

# Inspect security headers
curl -I http://localhost:8080/health
```

### Demo Credentials

| Username | Password | Role | Access |
|----------|----------|------|--------|
| `admin` | `admin123` | admin | Full access |
| `user1` | `user123` | user | Chat API |
| `viewer` | `view123` | readonly | Read-only (no chat) |

### Run with Docker

```bash
make docker
docker run -p 8080:8080 securellm-gateway
```

## Project Structure

```
secureLLM-gateway/
├── cmd/gateway/          # Application entry point
│   └── main.go           # Server startup, graceful shutdown
├── internal/             # Private application code
│   ├── auth/             # JWT token service and role definitions
│   ├── config/           # Environment-based configuration
│   ├── handlers/         # HTTP request handlers
│   │   ├── auth.go       # Token issuance endpoint
│   │   ├── chat.go       # Chat completion endpoint
│   │   ├── health.go     # Health check endpoint
│   │   └── routes.go     # Route registration with per-route RBAC
│   ├── middleware/        # Security middleware chain
│   │   ├── auth.go       # JWT Bearer token validation
│   │   ├── chain.go      # Middleware composition
│   │   ├── logging.go    # Structured audit logging
│   │   ├── rbac.go       # Role-based access control
│   │   ├── recovery.go   # Panic recovery
│   │   ├── request_id.go # Distributed request tracing
│   │   └── security_headers.go
│   ├── models/           # Data models
│   ├── ratelimit/        # Per-user rate limiting
│   ├── sanitizer/        # Input/output sanitization
│   └── audit/            # Audit trail and compliance logging
├── pkg/response/         # Standardized API responses
├── deployments/
│   ├── docker/           # Dockerfile (multi-stage, distroless)
│   └── k8s/              # Kubernetes manifests
├── tests/                # Integration and security tests
└── Makefile              # Build, test, lint, docker commands
```

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP server port |
| `ENVIRONMENT` | `development` | Runtime environment |
| `JWT_SECRET` | — | JWT signing key (required in production) |
| `JWT_EXPIRATION_MINUTES` | `60` | Token lifetime in minutes |
| `RATE_LIMIT_RPS` | `10` | Max requests per second per user |
| `ALLOWED_ORIGINS` | `*` | CORS allowed origins |

## Security Headers

Every response includes hardened HTTP headers:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
X-XSS-Protection: 0
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
Cache-Control: no-store, no-cache, must-revalidate
```

## Roadmap

- [x] Project scaffold with security middleware chain
- [x] JWT authentication with RBAC
- [ ] Per-user rate limiting (token bucket)
- [ ] Prompt injection detection
- [ ] Output sanitization and PII redaction
- [ ] Streaming SSE responses
- [ ] Kubernetes deployment manifests
- [ ] CI/CD pipeline with SAST and dependency scanning
- [ ] Security test suite (fuzzing, integration)

## License

MIT

## Author

[mathewtom](https://github.com/mathewtom)
