#!/bin/bash

# SMCP Security C# Package Publishing Script
# This script builds and publishes the C# package to NuGet

set -e

echo "🔷 Publishing SMCP Security C# Package to NuGet"
echo "==============================================="

# Change to C# library directory
cd "$(dirname "$0")/../libraries/csharp"

# Check if we're in the right directory
if [ ! -f "SMCP.Security.csproj" ]; then
    echo "❌ Error: SMCP.Security.csproj not found. Are you in the right directory?"
    exit 1
fi

# Check if .NET is installed
if ! command -v dotnet &> /dev/null; then
    echo "❌ .NET CLI not found. Please install .NET 6.0 or later."
    exit 1
fi

# Restore dependencies
echo "📥 Restoring dependencies..."
dotnet restore

if [ $? -ne 0 ]; then
    echo "❌ Dependency restoration failed. Aborting publish."
    exit 1
fi

# Build the project
echo "🔨 Building project..."
dotnet build --configuration Release --no-restore

if [ $? -ne 0 ]; then
    echo "❌ Build failed. Aborting publish."
    exit 1
fi

# Run tests
echo "🧪 Running tests..."
dotnet test --configuration Release --no-build --verbosity normal

if [ $? -ne 0 ]; then
    echo "❌ Tests failed. Aborting publish."
    exit 1
fi

# Pack the package
echo "📦 Packing NuGet package..."
dotnet pack --configuration Release --no-build --output ./nupkg

if [ $? -ne 0 ]; then
    echo "❌ Package creation failed. Aborting publish."
    exit 1
fi

# Check if NuGet API key is set
if [ -z "$NUGET_API_KEY" ]; then
    echo "⚠️  NUGET_API_KEY environment variable not set."
    echo "Please set it with your NuGet API key or pass it as an argument."
    if [ ! -z "$1" ]; then
        NUGET_API_KEY="$1"
    else
        read -p "Enter your NuGet API key: " -s NUGET_API_KEY
        echo
    fi
fi

# Publish to NuGet
echo "🚀 Publishing to NuGet..."
if [ "$2" = "--dry-run" ] || [ "$1" = "--dry-run" ]; then
    echo "🧪 Dry run - not actually publishing"
    echo "Would publish: $(ls ./nupkg/*.nupkg)"
else
    echo "📤 Publishing to NuGet..."
    dotnet nuget push ./nupkg/*.nupkg --api-key "$NUGET_API_KEY" --source https://api.nuget.org/v3/index.json
fi

if [ $? -eq 0 ]; then
    echo "✅ Successfully published SMCP Security C# package!"
    echo "📋 Package details:"
    echo "   - Name: SMCP.Security"
    echo "   - Version: 1.0.0"
    echo "   - Install: dotnet add package SMCP.Security"
    echo "   - NuGet: https://www.nuget.org/packages/SMCP.Security/"
else
    echo "❌ Failed to publish package."
    exit 1
fi

# Clean up
rm -rf ./nupkg
