#!/bin/bash

# SMCP Security Python Package Publishing Script
# This script builds and publishes the Python package to PyPI

set -e

echo "🐍 Publishing SMCP Security Python Package to PyPI"
echo "================================================="

# Change to Python library directory
cd "$(dirname "$0")/../libraries/python"

# Check if we're in the right directory
if [ ! -f "pyproject.toml" ]; then
    echo "❌ Error: pyproject.toml not found. Are you in the right directory?"
    exit 1
fi

# Install build dependencies
echo "📦 Installing build dependencies..."
pip install --upgrade pip build twine

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf dist/ build/ *.egg-info/

# Run tests
echo "🧪 Running tests..."
pytest tests/ -v --cov=smcp_security --cov-report=term-missing

if [ $? -ne 0 ]; then
    echo "❌ Tests failed. Aborting publish."
    exit 1
fi

# Build the package
echo "🔨 Building package..."
python -m build

if [ $? -ne 0 ]; then
    echo "❌ Build failed. Aborting publish."
    exit 1
fi

# Check the package
echo "🔍 Checking package..."
twine check dist/*

if [ $? -ne 0 ]; then
    echo "❌ Package check failed. Aborting publish."
    exit 1
fi

# Upload to PyPI
echo "🚀 Uploading to PyPI..."
if [ "$1" = "--test" ]; then
    echo "📤 Uploading to Test PyPI..."
    twine upload --repository testpypi dist/*
else
    echo "📤 Uploading to PyPI..."
    twine upload dist/*
fi

if [ $? -eq 0 ]; then
    echo "✅ Successfully published SMCP Security Python package!"
    echo "📋 Package details:"
    echo "   - Name: smcp-security"
    echo "   - Version: 1.0.0"
    echo "   - Install: pip install smcp-security"
    echo "   - PyPI: https://pypi.org/project/smcp-security/"
else
    echo "❌ Failed to publish package."
    exit 1
fi
