#!/bin/bash

# SMCP Security VS Code Extension Publishing Script
# This script builds and publishes the VS Code extension to the marketplace

set -e

echo "🎨 Publishing SMCP Security VS Code Extension"
echo "============================================"

# Change to VS Code extension directory
cd "$(dirname "$0")/../libraries/vscode-extension"

# Check if we're in the right directory
if [ ! -f "package.json" ]; then
    echo "❌ Error: package.json not found. Are you in the right directory?"
    exit 1
fi

# Check if vsce is installed
if ! command -v vsce &> /dev/null; then
    echo "📥 Installing vsce (Visual Studio Code Extension manager)..."
    npm install -g @vscode/vsce
fi

# Install dependencies
echo "📥 Installing dependencies..."
yarn install

if [ $? -ne 0 ]; then
    echo "❌ Dependency installation failed. Aborting publish."
    exit 1
fi

# Compile TypeScript
echo "🔨 Compiling TypeScript..."
yarn compile

if [ $? -ne 0 ]; then
    echo "❌ TypeScript compilation failed. Aborting publish."
    exit 1
fi

# Run linting
echo "🔍 Running linter..."
yarn lint

if [ $? -ne 0 ]; then
    echo "❌ Linting failed. Aborting publish."
    exit 1
fi

# Package the extension
echo "📦 Packaging extension..."
vsce package

if [ $? -ne 0 ]; then
    echo "❌ Extension packaging failed. Aborting publish."
    exit 1
fi

# Check if publisher token is available
if [ -z "$VSCE_PAT" ]; then
    echo "⚠️  VSCE_PAT environment variable not set."
    echo "Please set it with your Visual Studio Marketplace Personal Access Token."
    if [ ! -z "$1" ]; then
        VSCE_PAT="$1"
    else
        read -p "Enter your VS Code Marketplace PAT: " -s VSCE_PAT
        echo
    fi
fi

# Publish to VS Code Marketplace
echo "🚀 Publishing to VS Code Marketplace..."
if [ "$2" = "--dry-run" ] || [ "$1" = "--dry-run" ]; then
    echo "🧪 Dry run - not actually publishing"
    echo "Would publish: $(ls *.vsix)"
else
    echo "📤 Publishing to VS Code Marketplace..."
    vsce publish --pat "$VSCE_PAT"
fi

if [ $? -eq 0 ]; then
    echo "✅ Successfully published SMCP Security VS Code Extension!"
    echo "📋 Extension details:"
    echo "   - Name: SMCP Security"
    echo "   - Publisher: smcp-security"
    echo "   - Version: 1.0.0"
    echo "   - Marketplace: https://marketplace.visualstudio.com/items?itemName=smcp-security.smcp-security"
    echo "   - Install: Search for 'SMCP Security' in VS Code Extensions"
else
    echo "❌ Failed to publish extension."
    exit 1
fi

# Clean up
rm -f *.vsix
