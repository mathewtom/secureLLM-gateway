BINARY_NAME=securellm-gateway
MAIN_PATH=./cmd/gateway
DOCKER_IMAGE=securellm-gateway
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
