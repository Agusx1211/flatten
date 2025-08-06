#!/bin/bash

# Build script for flatten - builds for all platforms and architectures
# Usage: ./build.sh [version]

set -e

VERSION=${1:-"dev"}
BINARY_NAME="flatten"
BUILD_DIR="build"
PKG_PATH="./cmd/flatten"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Building $BINARY_NAME version: $VERSION${NC}"

# Clean build directory
rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR

# Platform and architecture combinations
PLATFORMS=(
    "linux/amd64"
    "linux/386"
    "linux/arm64"
    "linux/arm"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/386"
    "windows/arm64"
    "freebsd/amd64"
    "freebsd/386"
    "freebsd/arm64"
    "freebsd/arm"
)

# Build for each platform
for PLATFORM in "${PLATFORMS[@]}"; do
    GOOS=$(echo $PLATFORM | cut -d'/' -f1)
    GOARCH=$(echo $PLATFORM | cut -d'/' -f2)
    
    OUTPUT_NAME="$BINARY_NAME-$VERSION-$GOOS-$GOARCH"
    
    # Add .exe extension for Windows
    if [ "$GOOS" = "windows" ]; then
        OUTPUT_NAME="$OUTPUT_NAME.exe"
    fi
    
    OUTPUT_PATH="$BUILD_DIR/$OUTPUT_NAME"
    
    echo -e "${YELLOW}Building for $GOOS/$GOARCH...${NC}"
    
    CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build \
        -ldflags="-s -w -X main.version=$VERSION" \
        -o $OUTPUT_PATH \
        $PKG_PATH
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Built: $OUTPUT_NAME${NC}"
        
        # Create compressed archive
        cd $BUILD_DIR
        if [ "$GOOS" = "windows" ]; then
            if command -v zip >/dev/null 2>&1; then
                zip -q "${OUTPUT_NAME%.exe}.zip" "$OUTPUT_NAME"
                echo -e "${GREEN}✓ Created: ${OUTPUT_NAME%.exe}.zip${NC}"
            else
                echo -e "${YELLOW}⚠ zip not found, skipping archive creation for Windows binary${NC}"
            fi
        else
            tar -czf "$OUTPUT_NAME.tar.gz" "$OUTPUT_NAME"
            echo -e "${GREEN}✓ Created: $OUTPUT_NAME.tar.gz${NC}"
        fi
        cd ..
    else
        echo -e "${RED}✗ Failed to build for $GOOS/$GOARCH${NC}"
        exit 1
    fi
done

echo -e "${GREEN}Build complete! Artifacts are in the $BUILD_DIR directory.${NC}"
