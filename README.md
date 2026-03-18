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

### OWASP Top 10 for LLM Applications (2025)

| # | Risk | Mitigation | Scope |
|---|------|------------|-------|
| LLM01 | Prompt Injection | Scoring-based regex detection across 6 attack categories, validated against regex101.com | Gateway — implemented |
| LLM02 | Sensitive Information Disclosure | PII redaction (SSN, CC, email, phone, AWS keys, IBAN) with Luhn validation | Gateway — implemented |
| LLM03 | Supply Chain | Minimal dependencies (single external dep), pinned versions, distroless containers | Gateway — implemented |
| LLM04 | Data and Model Poisoning | Training data integrity — out of scope for gateway layer | Model-level |
| LLM05 | Improper Output Handling | HTML output encoding, content filtering (destructive commands, script injection, exfiltration) | Gateway — implemented |
| LLM06 | Excessive Agency | RBAC-restricted model access, scoped permissions per role | Gateway — implemented |
| LLM07 | System Prompt Leakage | Prompt extraction detection in input filter; system prompt treated as discoverable | Gateway — implemented |
| LLM08 | Vector and Embedding Weaknesses | RAG/embedding-specific — out of scope for gateway layer | Model-level |
| LLM09 | Misinformation | Audit logging of all LLM interactions for downstream review | Gateway — partial |
| LLM10 | Unbounded Consumption | Per-user token bucket rate limiting, request body size limits, server timeouts | Gateway — implemented |

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
                    │  Output Sanitizer (PII / Encoding / Filter)  │
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
│   │   └── routes.go     # Route registration with per-route middleware
│   ├── middleware/        # Security middleware chain
│   │   ├── auth.go       # JWT Bearer token validation
│   │   ├── body_limit.go # Request body size enforcement
│   │   ├── chain.go      # Middleware composition
│   │   ├── logging.go    # Structured audit logging
│   │   ├── output_sanitizer.go # PII redaction, encoding, content filter
│   │   ├── prompt_guard.go # Prompt injection detection
│   │   ├── ratelimit.go  # Per-user rate limiting
│   │   ├── rbac.go       # Role-based access control
│   │   ├── recovery.go   # Panic recovery
│   │   ├── request_id.go # Distributed request tracing
│   │   └── security_headers.go
│   ├── models/           # Data models
│   ├── ratelimit/        # Token bucket rate limiter
│   ├── sanitizer/        # Input/output security filters
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
| `RATE_LIMIT_ADMIN_RPS` | `50` | Rate limit for admin role (req/s) |
| `RATE_LIMIT_USER_RPS` | `20` | Rate limit for user role (req/s) |
| `RATE_LIMIT_READONLY_RPS` | `10` | Rate limit for readonly role (req/s) |
| `RATE_LIMIT_BURST` | `10` | Token bucket burst capacity |
| `PROMPT_GUARD_THRESHOLD` | `8` | Prompt injection scoring threshold (lower = stricter) |
| `OUTPUT_HTML_ENCODING` | `true` | HTML-encode LLM output to prevent XSS |
| `MAX_BODY_BYTES` | `65536` | Maximum request body size in bytes (64KB) |
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
- [x] Per-user rate limiting (token bucket, role-based)
- [x] Prompt injection detection (scoring-based, OWASP LLM01)
- [x] Output sanitization — PII redaction, HTML encoding, content filtering (OWASP LLM02/LLM05)
- [x] Request body size limits (OWASP LLM10)
- [ ] Kubernetes deployment manifests
- [ ] CI/CD pipeline with SAST and dependency scanning
- [ ] Security test suite (fuzzing, integration)

## License

MIT

## Author

[mathewtom](https://github.com/mathewtom)
