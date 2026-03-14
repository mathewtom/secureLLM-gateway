# Multi-stage Dockerfile for SecureLLM Gateway
#
# SECURITY CONTEXT:
#   This Dockerfile follows container security best practices:
#   - Multi-stage build: Build tools (compiler, source code) don't ship in the final image
#   - Distroless base: Minimal attack surface (no shell, no package manager)
#   - Non-root user: Container runs as unprivileged user (PCI DSS Req 7)
#   - No secrets in image: All secrets come from environment variables at runtime
#
# OWASP A05 (Security Misconfiguration):
#   Common Docker mistakes we avoid here:
#   - Running as root (we use USER nonroot)
#   - Including build tools in the final image (we use multi-stage)
#   - Using latest tag (we pin specific versions)
#   - Exposing unnecessary ports (we only EXPOSE 8080)

# ============================================================================
# Stage 1: BUILD
# ============================================================================
# We use a full Go image to compile our application.
# This stage is thrown away — only the compiled binary moves to Stage 2.
FROM golang:1.23-alpine AS builder

# Set the working directory inside the container.
# All subsequent commands run from this directory.
WORKDIR /app

# Copy go.mod and go.sum first (dependency manifests).
# Docker caches each layer. By copying dependency files first:
#   1. Dependencies are downloaded and cached in their own layer
#   2. If only source code changes (not dependencies), Docker reuses the cached layer
#   3. This makes rebuilds MUCH faster (dependency download is the slowest step)
COPY go.mod go.sum* ./
RUN go mod download

# Copy the rest of the source code.
COPY . .

# Build the binary.
# CGO_ENABLED=0: Static binary (no C library dependencies)
# -ldflags="-s -w": Strip debug symbols (smaller binary, harder to reverse engineer)
# GOOS=linux: Cross-compile for Linux (even if building on macOS)
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /securellm-gateway ./cmd/gateway

# ============================================================================
# Stage 2: RUNTIME
# ============================================================================
# Google's distroless images contain ONLY the application and its runtime dependencies.
# No shell, no package manager, no OS utilities.
#
# WHY DISTROLESS?
#   - Minimal attack surface: An attacker who compromises the container can't
#     run shell commands, install tools, or pivot to other systems
#   - Smaller image size: ~2MB base vs ~5MB for alpine, ~80MB for debian
#   - No CVEs from OS packages: Fewer packages = fewer vulnerabilities to patch
#   - PCI DSS Req 2.2: Remove unnecessary functionality from systems
#
# The "nonroot" variant runs as a non-root user by default.
FROM gcr.io/distroless/static-debian12:nonroot

# Copy ONLY the compiled binary from the builder stage.
# Nothing else from the build stage (source code, compiler, tools) is included.
COPY --from=builder /securellm-gateway /securellm-gateway

# Document which port the application listens on.
# EXPOSE doesn't actually publish the port — it's documentation.
# The actual port mapping happens at runtime with `docker run -p 8080:8080`.
EXPOSE 8080

# Run as non-root user (UID 65534, provided by the distroless nonroot variant).
# SECURITY: Running as root in a container is dangerous because:
#   - Container escape vulnerabilities often require root
#   - Root in the container = root on the host (without user namespaces)
#   - PCI DSS Req 7: Limit access to system resources to only what is needed
USER nonroot:nonroot

# ENTRYPOINT defines the command that runs when the container starts.
# We use the exec form (JSON array) instead of shell form (string) because:
#   - Exec form runs the binary directly (PID 1) — receives signals properly
#   - Shell form runs via /bin/sh -c, which doesn't forward signals
#   - Proper signal handling is required for graceful shutdown in Kubernetes
ENTRYPOINT ["/securellm-gateway"]
