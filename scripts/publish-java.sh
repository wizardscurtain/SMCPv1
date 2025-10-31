#!/bin/bash

# SMCP Security Java Package Publishing Script
# This script builds and publishes the Java package to Maven Central

set -e

echo "☕ Publishing SMCP Security Java Package to Maven Central"
echo "======================================================"

# Change to Java library directory
cd "$(dirname "$0")/../libraries/java"

# Check if we're in the right directory
if [ ! -f "pom.xml" ]; then
    echo "❌ Error: pom.xml not found. Are you in the right directory?"
    exit 1
fi

# Check if Maven is installed
if ! command -v mvn &> /dev/null; then
    echo "❌ Maven not found. Please install Maven."
    exit 1
fi

# Clean and compile
echo "🧹 Cleaning and compiling..."
mvn clean compile

if [ $? -ne 0 ]; then
    echo "❌ Compilation failed. Aborting publish."
    exit 1
fi

# Run tests
echo "🧪 Running tests..."
mvn test

if [ $? -ne 0 ]; then
    echo "❌ Tests failed. Aborting publish."
    exit 1
fi

# Run code quality checks
echo "🔍 Running code quality checks..."
mvn verify

if [ $? -ne 0 ]; then
    echo "❌ Code quality checks failed. Aborting publish."
    exit 1
fi

# Build the package
echo "🔨 Building package..."
mvn package

if [ $? -ne 0 ]; then
    echo "❌ Package build failed. Aborting publish."
    exit 1
fi

# Deploy to Maven Central
echo "🚀 Deploying to Maven Central..."
if [ "$1" = "--snapshot" ]; then
    echo "📤 Deploying snapshot version..."
    mvn deploy
elif [ "$1" = "--release" ]; then
    echo "📤 Deploying release version..."
    mvn deploy -P release
else
    echo "📤 Deploying to staging repository..."
    mvn deploy -P release
fi

if [ $? -eq 0 ]; then
    echo "✅ Successfully published SMCP Security Java package!"
    echo "📋 Package details:"
    echo "   - GroupId: com.smcp"
    echo "   - ArtifactId: smcp-security"
    echo "   - Version: 1.0.0"
    echo "   - Maven Central: https://search.maven.org/artifact/com.smcp/smcp-security"
    echo "   - Maven dependency:"
    echo "     <dependency>"
    echo "       <groupId>com.smcp</groupId>"
    echo "       <artifactId>smcp-security</artifactId>"
    echo "       <version>1.0.0</version>"
    echo "     </dependency>"
else
    echo "❌ Failed to publish package."
    exit 1
fi
