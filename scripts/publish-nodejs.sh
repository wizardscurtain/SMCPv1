#!/bin/bash

# SMCP Security Node.js Package Publishing Script
# This script builds and publishes the Node.js package to npm

set -e

echo "📦 Publishing SMCP Security Node.js Package to npm"
echo "================================================"

# Change to Node.js library directory
cd "$(dirname "$0")/../libraries/nodejs"

# Check if we're in the right directory
if [ ! -f "package.json" ]; then
    echo "❌ Error: package.json not found. Are you in the right directory?"
    exit 1
fi

# Install dependencies
echo "📥 Installing dependencies..."
yarn install

# Run linting
echo "🔍 Running linter..."
yarn lint

if [ $? -ne 0 ]; then
    echo "❌ Linting failed. Aborting publish."
    exit 1
fi

# Run tests
echo "🧪 Running tests..."
yarn test

if [ $? -ne 0 ]; then
    echo "❌ Tests failed. Aborting publish."
    exit 1
fi

# Build the package
echo "🔨 Building package..."
yarn build

if [ $? -ne 0 ]; then
    echo "❌ Build failed. Aborting publish."
    exit 1
fi

# Check npm authentication
echo "🔐 Checking npm authentication..."
npm whoami

if [ $? -ne 0 ]; then
    echo "❌ Not logged in to npm. Please run 'npm login' first."
    exit 1
fi

# Publish to npm
echo "🚀 Publishing to npm..."
if [ "$1" = "--tag" ]; then
    echo "📤 Publishing with tag: $2"
    npm publish --tag "$2"
elif [ "$1" = "--dry-run" ]; then
    echo "🧪 Dry run - not actually publishing"
    npm publish --dry-run
else
    echo "📤 Publishing to npm..."
    npm publish
fi

if [ $? -eq 0 ]; then
    echo "✅ Successfully published SMCP Security Node.js package!"
    echo "📋 Package details:"
    echo "   - Name: smcp-security"
    echo "   - Version: 1.0.0"
    echo "   - Install: npm install smcp-security"
    echo "   - npm: https://www.npmjs.com/package/smcp-security"
else
    echo "❌ Failed to publish package."
    exit 1
fi
