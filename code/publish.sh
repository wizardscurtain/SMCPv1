#!/bin/bash
# SMCP Publishing Script
# Run this to publish to TestPyPI and PyPI

set -e  # Exit on error

echo "🚀 SMCP Publishing Script"
echo "========================"
echo ""

# Check we're in the right directory
if [ ! -f "pyproject.toml" ]; then
    echo "❌ Error: Must be run from code/ directory"
    exit 1
fi

# Step 1: Clean old builds
echo "Step 1: Cleaning old builds..."
rm -rf build/ dist/ *.egg-info
echo "✅ Old builds cleaned"
echo ""

# Step 2: Build the package
echo "Step 2: Building package..."
python -m build
echo "✅ Package built"
echo ""

# Step 3: Check the package
echo "Step 3: Checking package..."
twine check dist/*
echo "✅ Package check passed"
echo ""

# List what we built
echo "📦 Built files:"
ls -lh dist/
echo ""

# Step 4: Upload to TestPyPI
echo "Step 4: Upload to TestPyPI..."
echo "You'll need to enter your TestPyPI credentials:"
echo "  Username: __token__"
echo "  Password: [your TestPyPI token]"
echo ""
read -p "Press Enter to upload to TestPyPI (or Ctrl+C to cancel)..."

python -m twine upload --repository testpypi dist/*

echo ""
echo "✅ Uploaded to TestPyPI!"
echo ""
echo "📝 Test installation with:"
echo "   pip install --index-url https://test.pypi.org/simple/ smcp-security"
echo ""
read -p "Press Enter when you've tested the package and are ready to upload to PyPI..."

# Step 5: Upload to PyPI
echo ""
echo "Step 5: Upload to PyPI (PRODUCTION)..."
echo "You'll need to enter your PyPI credentials:"
echo "  Username: __token__"
echo "  Password: [your PyPI token]"
echo ""
read -p "Press Enter to upload to PyPI (or Ctrl+C to cancel)..."

python -m twine upload dist/*

echo ""
echo "✅ Uploaded to PyPI!"
echo ""
echo "🎉 SUCCESS! Your package is now live!"
echo ""
echo "📝 Install with:"
echo "   pip install smcp-security"
echo ""
echo "🔗 Check it out at:"
echo "   https://pypi.org/project/smcp-security/"
echo ""
