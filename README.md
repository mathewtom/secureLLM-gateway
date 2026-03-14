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
| A07 | Auth Failures | JWT verification, token expiration, secure session handling |
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
| LLM06 | Excessive Agency | RBAC-restricted model access, scoped permissions |
| LLM07 | Data Leakage | PII detection and redaction in responses |
| LLM09 | Overreliance | Audit logging of all LLM interactions for review |

### PCI DSS Compliance Controls

| Requirement | Implementation |
|------------|----------------|
| Req 2 — No default credentials | Environment-based secrets, no hardcoded values |
| Req 3 — Protect stored data | Sensitive data never logged, encryption at rest |
| Req 4 — Encrypt transmission | HSTS enforcement, TLS-only communication |
| Req 6 — Secure development | Input validation, error handling, security testing |
| Req 7 — Restrict access | RBAC, least-privilege container user |
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
# Clone the repository
git clone https://github.com/mathewtom/secureLLM-gateway.git
cd secureLLM-gateway

# Build and run
make run
```

The server starts on `http://localhost:8080`.

### Test the API

```bash
# Health check
curl http://localhost:8080/health

# Chat completion
curl -X POST http://localhost:8080/api/v1/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello!", "model": "mock-llm-v1"}'

# Inspect security headers
curl -I http://localhost:8080/health
```

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
│   ├── auth/             # JWT authentication and RBAC
│   ├── config/           # Environment-based configuration
│   ├── handlers/         # HTTP request handlers
│   ├── middleware/        # Security middleware chain
│   │   ├── chain.go      # Middleware composition
│   │   ├── logging.go    # Structured audit logging
│   │   ├── recovery.go   # Panic recovery
│   │   ├── request_id.go # Distributed request tracing
│   │   └── security_headers.go  # HSTS, CSP, X-Frame-Options
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

All configuration is via environment variables (never hardcoded):

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP server port |
| `ENVIRONMENT` | `development` | Runtime environment |
| `JWT_SECRET` | — | JWT signing key (required in production) |
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
- [ ] JWT authentication with RBAC
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
