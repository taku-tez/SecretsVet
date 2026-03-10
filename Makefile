ROOT_PACKAGE := github.com/SecretsVet/secretsvet
VERSION_PACKAGE := $(ROOT_PACKAGE)/internal/version
APP := secretsvet
BIN_DIR := bin

VERSION := $(shell git describe --tags --always 2>/dev/null || echo "0.1.0-dev")
LDFLAGS := -w -s -X $(VERSION_PACKAGE).version=$(VERSION)

.PHONY: build test lint tidy clean

build:
	mkdir -p $(BIN_DIR)
	go build -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(APP) ./main.go

test:
	go test -v -race ./...

lint:
	golangci-lint run ./...

tidy:
	go mod tidy

clean:
	rm -rf $(BIN_DIR)

install:
	go install -ldflags="$(LDFLAGS)" ./...
