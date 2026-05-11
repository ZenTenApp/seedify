#!/bin/bash
# Build script for seedify - creates binaries for multiple platforms

set -e

VERSION=${1:-"dev"}
BUILD_DIR="dist"

# Create build directory
mkdir -p "$BUILD_DIR"

echo "Building seedify binaries..."

# Build for current platform
echo "Building for current platform..."
go build -ldflags "-X main.version=$VERSION" -o "$BUILD_DIR/seedify" ./cmd/seedify

# Build for Linux
echo "Building for Linux (amd64)..."
GOOS=linux GOARCH=amd64 go build -ldflags "-X main.version=$VERSION" -o "$BUILD_DIR/seedify-linux-amd64" ./cmd/seedify

# Build for Windows
echo "Building for Windows (amd64)..."
GOOS=windows GOARCH=amd64 go build -ldflags "-X main.version=$VERSION" -o "$BUILD_DIR/seedify-windows-amd64.exe" ./cmd/seedify

# Build for macOS Intel
echo "Building for macOS (Intel)..."
GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.version=$VERSION" -o "$BUILD_DIR/seedify-darwin-amd64" ./cmd/seedify

# Build for macOS ARM64
echo "Building for macOS (ARM64)..."
GOOS=darwin GOARCH=arm64 go build -ldflags "-X main.version=$VERSION" -o "$BUILD_DIR/seedify-darwin-arm64" ./cmd/seedify

echo "Build complete! Binaries are in $BUILD_DIR/"
ls -lh "$BUILD_DIR/"

