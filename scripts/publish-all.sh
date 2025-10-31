#!/bin/bash

# SMCP Security - Publish All Libraries Script
# This script publishes all SMCP Security libraries to their respective package registries

set -e

echo "🚀 Publishing All SMCP Security Libraries"
echo "========================================"
echo

# Get script directory
SCRIPT_DIR="$(dirname "$0")"

# Function to run a publish script with error handling
run_publish() {
    local script_name="$1"
    local library_name="$2"
    
    echo "📦 Publishing $library_name..."
    echo "────────────────────────────────────────"
    
    if [ -f "$SCRIPT_DIR/$script_name" ]; then
        chmod +x "$SCRIPT_DIR/$script_name"
        if "$SCRIPT_DIR/$script_name" "$3" "$4"; then
            echo "✅ $library_name published successfully!"
        else
            echo "❌ Failed to publish $library_name"
            return 1
        fi
    else
        echo "❌ Script $script_name not found"
        return 1
    fi
    
    echo
}

# Parse command line arguments
DRY_RUN=false
SKIP_TESTS=false
LIBRARIES="all"

while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        --libraries)
            LIBRARIES="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --dry-run      Perform a dry run without actually publishing"
            echo "  --skip-tests   Skip running tests before publishing"
            echo "  --libraries    Comma-separated list of libraries to publish (default: all)"
            echo "                 Available: python,nodejs,go,rust,java,csharp,vscode"
            echo "  --help         Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Convert libraries string to array
IFS=',' read -ra LIBRARY_ARRAY <<< "$LIBRARIES"

# Function to check if library should be published
should_publish() {
    local lib="$1"
    if [ "$LIBRARIES" = "all" ]; then
        return 0
    fi
    
    for selected_lib in "${LIBRARY_ARRAY[@]}"; do
        if [ "$selected_lib" = "$lib" ]; then
            return 0
        fi
    done
    
    return 1
}

# Set dry run flag for scripts
DRY_RUN_FLAG=""
if [ "$DRY_RUN" = true ]; then
    DRY_RUN_FLAG="--dry-run"
    echo "🧪 DRY RUN MODE - No packages will actually be published"
    echo
fi

# Track success/failure
SUCCESS_COUNT=0
FAILURE_COUNT=0
SKIPPED_COUNT=0
FAILED_LIBRARIES=()

# Publish Python package to PyPI
if should_publish "python"; then
    if run_publish "publish-python.sh" "Python (PyPI)" "$DRY_RUN_FLAG"; then
        ((SUCCESS_COUNT++))
    else
        ((FAILURE_COUNT++))
        FAILED_LIBRARIES+=("Python")
    fi
else
    echo "⏭️  Skipping Python library"
    ((SKIPPED_COUNT++))
    echo
fi

# Publish Node.js package to npm
if should_publish "nodejs"; then
    if run_publish "publish-nodejs.sh" "Node.js (npm)" "$DRY_RUN_FLAG"; then
        ((SUCCESS_COUNT++))
    else
        ((FAILURE_COUNT++))
        FAILED_LIBRARIES+=("Node.js")
    fi
else
    echo "⏭️  Skipping Node.js library"
    ((SKIPPED_COUNT++))
    echo
fi

# Publish Go module
if should_publish "go"; then
    if run_publish "publish-go.sh" "Go (Module)" "v1.0.0"; then
        ((SUCCESS_COUNT++))
    else
        ((FAILURE_COUNT++))
        FAILED_LIBRARIES+=("Go")
    fi
else
    echo "⏭️  Skipping Go library"
    ((SKIPPED_COUNT++))
    echo
fi

# Publish Rust crate to crates.io
if should_publish "rust"; then
    if run_publish "publish-rust.sh" "Rust (crates.io)" "$DRY_RUN_FLAG"; then
        ((SUCCESS_COUNT++))
    else
        ((FAILURE_COUNT++))
        FAILED_LIBRARIES+=("Rust")
    fi
else
    echo "⏭️  Skipping Rust library"
    ((SKIPPED_COUNT++))
    echo
fi

# Publish Java package to Maven Central
if should_publish "java"; then
    if run_publish "publish-java.sh" "Java (Maven Central)" "--release"; then
        ((SUCCESS_COUNT++))
    else
        ((FAILURE_COUNT++))
        FAILED_LIBRARIES+=("Java")
    fi
else
    echo "⏭️  Skipping Java library"
    ((SKIPPED_COUNT++))
    echo
fi

# Publish C# package to NuGet
if should_publish "csharp"; then
    if run_publish "publish-csharp.sh" "C# (NuGet)" "$DRY_RUN_FLAG"; then
        ((SUCCESS_COUNT++))
    else
        ((FAILURE_COUNT++))
        FAILED_LIBRARIES+=("C#")
    fi
else
    echo "⏭️  Skipping C# library"
    ((SKIPPED_COUNT++))
    echo
fi

# Publish VS Code extension
if should_publish "vscode"; then
    if run_publish "publish-vscode.sh" "VS Code Extension" "$DRY_RUN_FLAG"; then
        ((SUCCESS_COUNT++))
    else
        ((FAILURE_COUNT++))
        FAILED_LIBRARIES+=("VS Code Extension")
    fi
else
    echo "⏭️  Skipping VS Code extension"
    ((SKIPPED_COUNT++))
    echo
fi

# Summary
echo "📊 Publishing Summary"
echo "═══════════════════"
echo "✅ Successful: $SUCCESS_COUNT"
echo "❌ Failed: $FAILURE_COUNT"
echo "⏭️  Skipped: $SKIPPED_COUNT"

if [ $FAILURE_COUNT -gt 0 ]; then
    echo
    echo "❌ Failed libraries:"
    for lib in "${FAILED_LIBRARIES[@]}"; do
        echo "   - $lib"
    done
    echo
    echo "Please check the error messages above and retry failed publications."
    exit 1
else
    echo
    if [ "$DRY_RUN" = true ]; then
        echo "🧪 Dry run completed successfully! All libraries are ready for publishing."
    else
        echo "🎉 All libraries published successfully!"
        echo
        echo "📋 Installation Commands:"
        echo "   Python:  pip install smcp-security"
        echo "   Node.js: npm install smcp-security"
        echo "   Go:      go get github.com/wizardscurtain/SMCPv1/libraries/go@v1.0.0"
        echo "   Rust:    cargo add smcp-security"
        echo "   Java:    Add Maven dependency com.smcp:smcp-security:1.0.0"
        echo "   C#:      dotnet add package SMCP.Security"
        echo "   VS Code: Search 'SMCP Security' in Extensions"
    fi
fi
