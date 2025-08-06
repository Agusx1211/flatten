# Makefile for flatten

.PHONY: build build-all clean test install help

BINARY_NAME := flatten
PKG_PATH := ./cmd/flatten
BUILD_DIR := build
LOCAL_BIN := bin

# Get version from git or use dev
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Build flags
LDFLAGS := -s -w -X main.version=$(VERSION)
BUILD_FLAGS := -ldflags="$(LDFLAGS)"

# Default target
help:
	@echo "Available targets:"
	@echo "  build      - Build for current platform"
	@echo "  build-all  - Build for all platforms"
	@echo "  test       - Run tests"
	@echo "  clean      - Clean build artifacts"
	@echo "  install    - Install to GOPATH/bin"

# Build for current platform
build:
	@echo "Building $(BINARY_NAME) for current platform (version: $(VERSION))..."
	@mkdir -p $(LOCAL_BIN)
	@CGO_ENABLED=0 go build $(BUILD_FLAGS) -o $(LOCAL_BIN)/$(BINARY_NAME) $(PKG_PATH)
	@echo "Build complete: $(LOCAL_BIN)/$(BINARY_NAME)"

# Build for all platforms using the shell script
build-all:
	@./build.sh $(VERSION)

# Run tests
test:
	@echo "Running tests..."
	@go test -v ./...

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR) $(LOCAL_BIN)

# Install to GOPATH/bin
install:
	@echo "Installing $(BINARY_NAME)..."
	@CGO_ENABLED=0 go install $(BUILD_FLAGS) $(PKG_PATH)
