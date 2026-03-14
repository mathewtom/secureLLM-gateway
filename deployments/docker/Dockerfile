# Stage 1: Build
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /securellm-gateway ./cmd/gateway

# Stage 2: Runtime — distroless for minimal attack surface (no shell, no pkg manager).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /securellm-gateway /securellm-gateway
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/securellm-gateway"]
