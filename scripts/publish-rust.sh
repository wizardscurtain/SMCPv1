#!/bin/bash

# SMCP Security Rust Crate Publishing Script
# This script builds and publishes the Rust crate to crates.io

set -e

echo "🦀 Publishing SMCP Security Rust Crate to crates.io"
echo "================================================="

# Change to Rust library directory
cd "$(dirname "$0")/../libraries/rust"

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    echo "❌ Error: Cargo.toml not found. Are you in the right directory?"
    exit 1
fi

# Check if cargo is installed
if ! command -v cargo &> /dev/null; then
    echo "❌ Cargo not found. Please install Rust."
    exit 1
fi

# Run clippy (linter)
echo "🔍 Running clippy..."
cargo clippy --all-targets --all-features -- -D warnings

if [ $? -ne 0 ]; then
    echo "❌ Clippy failed. Aborting publish."
    exit 1
fi

# Run tests
echo "🧪 Running tests..."
cargo test --all-features

if [ $? -ne 0 ]; then
    echo "❌ Tests failed. Aborting publish."
    exit 1
fi

# Check formatting
echo "📐 Checking formatting..."
cargo fmt --check

if [ $? -ne 0 ]; then
    echo "❌ Code is not formatted. Run 'cargo fmt' first."
    exit 1
fi

# Build the package
echo "🔨 Building package..."
cargo build --release --all-features

if [ $? -ne 0 ]; then
    echo "❌ Build failed. Aborting publish."
    exit 1
fi

# Check the package
echo "🔍 Checking package..."
cargo package --allow-dirty

if [ $? -ne 0 ]; then
    echo "❌ Package check failed. Aborting publish."
    exit 1
fi

# Check if logged in to crates.io
echo "🔐 Checking crates.io authentication..."
if ! cargo login --help &> /dev/null; then
    echo "❌ Please login to crates.io first with 'cargo login <token>'"
    exit 1
fi

# Publish to crates.io
echo "🚀 Publishing to crates.io..."
if [ "$1" = "--dry-run" ]; then
    echo "🧪 Dry run - not actually publishing"
    cargo publish --dry-run --allow-dirty
else
    echo "📤 Publishing to crates.io..."
    cargo publish --allow-dirty
fi

if [ $? -eq 0 ]; then
    echo "✅ Successfully published SMCP Security Rust crate!"
    echo "📋 Crate details:"
    echo "   - Name: smcp-security"
    echo "   - Version: 1.0.0"
    echo "   - Install: cargo add smcp-security"
    echo "   - Crates.io: https://crates.io/crates/smcp-security"
    echo "   - Docs: https://docs.rs/smcp-security"
else
    echo "❌ Failed to publish crate."
    exit 1
fi
