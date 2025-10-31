#!/bin/bash

# SMCP Security Go Module Publishing Script
# This script tags and publishes the Go module

set -e

echo "🐹 Publishing SMCP Security Go Module"
echo "==================================="

# Change to Go library directory
cd "$(dirname "$0")/../libraries/go"

# Check if we're in the right directory
if [ ! -f "go.mod" ]; then
    echo "❌ Error: go.mod not found. Are you in the right directory?"
    exit 1
fi

# Run tests
echo "🧪 Running tests..."
go test ./... -v -race -coverprofile=coverage.out

if [ $? -ne 0 ]; then
    echo "❌ Tests failed. Aborting publish."
    exit 1
fi

# Run linting
echo "🔍 Running linter..."
if command -v golangci-lint &> /dev/null; then
    golangci-lint run
else
    echo "⚠️  golangci-lint not found, skipping linting"
fi

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    echo "❌ Not in a git repository. Go modules require git tags."
    exit 1
fi

# Get the version from go.mod or use default
VERSION="v1.0.0"
if [ ! -z "$1" ]; then
    VERSION="$1"
fi

echo "📋 Module details:"
echo "   - Module: github.com/wizardscurtain/SMCPv1/libraries/go"
echo "   - Version: $VERSION"

# Check if tag already exists
if git tag -l | grep -q "^$VERSION$"; then
    echo "⚠️  Tag $VERSION already exists."
    read -p "Do you want to delete and recreate it? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        git tag -d "$VERSION"
        git push origin --delete "$VERSION" 2>/dev/null || true
    else
        echo "❌ Aborting publish."
        exit 1
    fi
fi

# Create and push tag
echo "🏷️  Creating tag $VERSION..."
git tag "$VERSION"
git push origin "$VERSION"

if [ $? -eq 0 ]; then
    echo "✅ Successfully published SMCP Security Go module!"
    echo "📋 Module details:"
    echo "   - Module: github.com/wizardscurtain/SMCPv1/libraries/go"
    echo "   - Version: $VERSION"
    echo "   - Install: go get github.com/wizardscurtain/SMCPv1/libraries/go@$VERSION"
    echo "   - Docs: https://pkg.go.dev/github.com/wizardscurtain/SMCPv1/libraries/go@$VERSION"
else
    echo "❌ Failed to publish module."
    exit 1
fi
