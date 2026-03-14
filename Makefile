# Makefile for SecureLLM Gateway
#
# Usage:
#   make build    - Compile the binary
#   make run      - Build and run the server
#   make test     - Run all tests
#   make lint     - Run the linter
#   make docker   - Build the Docker image
#   make clean    - Remove build artifacts

# Go parameters
BINARY_NAME=securellm-gateway
MAIN_PATH=./cmd/gateway
DOCKER_IMAGE=securellm-gateway

# Go build flags
# CGO_ENABLED=0: Disables C bindings, producing a fully static binary.
#   This is important for Docker because:
#   - Static binaries don't need system libraries at runtime
#   - We can use a minimal "scratch" or "distroless" base image (smaller attack surface)
#   - No dependency on glibc version in the container
# -ldflags="-s -w": Strips debug symbols and DWARF information
#   -s: Omit the symbol table (saves ~30% binary size)
#   -w: Omit DWARF debugging info
#   Security benefit: Makes reverse engineering slightly harder
BUILD_FLAGS=CGO_ENABLED=0 go build -ldflags="-s -w"

.PHONY: build run test lint docker clean

build:
	$(BUILD_FLAGS) -o bin/$(BINARY_NAME) $(MAIN_PATH)

run: build
	./bin/$(BINARY_NAME)

test:
	go test -v -race -cover ./...

lint:
	golangci-lint run ./...

docker:
	docker build -t $(DOCKER_IMAGE) -f deployments/docker/Dockerfile .

clean:
	rm -rf bin/
	go clean
