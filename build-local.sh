#!/bin/bash

# Quick build script for current platform only
# Usage: ./build-local.sh

set -e

BINARY_NAME="flatten"
OUTPUT_DIR="./bin"
PKG_PATH="./cmd/flatten"

# Get version from git if available, otherwise use "dev"
if git rev-parse --is-inside-work-tree > /dev/null 2>&1; then
    VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
else
    VERSION="dev"
fi

echo "Building $BINARY_NAME for current platform (version: $VERSION)..."

# Clean and create output directory
rm -rf $OUTPUT_DIR
mkdir -p $OUTPUT_DIR

# Build for current platform
go build \
    -ldflags="-s -w -X main.version=$VERSION" \
    -o "$OUTPUT_DIR/$BINARY_NAME" \
    $PKG_PATH

echo "Build complete: $OUTPUT_DIR/$BINARY_NAME"
echo "Run with: $OUTPUT_DIR/$BINARY_NAME --help"
