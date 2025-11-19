# How to Publish SMCP to PyPI

You have your accounts set up! Here's exactly what to do:

---

## Quick Method (Use the Script)

```bash
cd /home/user/SMCPv1/code
./publish.sh
```

The script will guide you through each step.

---

## Manual Method (Step-by-Step)

### Step 1: Get Your API Tokens

#### For TestPyPI:
1. Go to https://test.pypi.org/manage/account/token/
2. Click "Add API token"
3. Token name: "smcp-security-upload"
4. Scope: "Entire account" (for first upload)
5. Copy the token (starts with `pypi-...`)
6. Save it somewhere safe!

#### For PyPI:
1. Go to https://pypi.org/manage/account/token/
2. Click "Add API token"
3. Token name: "smcp-security-upload"
4. Scope: "Entire account" (for first upload)
5. Copy the token (starts with `pypi-...`)
6. Save it somewhere safe!

---

### Step 2: Install Publishing Tools

```bash
pip install twine build
```

---

### Step 3: Build the Package

```bash
cd /home/user/SMCPv1/code

# Clean old builds
rm -rf build/ dist/ *.egg-info

# Build
python -m build

# You should see:
# Successfully built smcp_security-1.0.0b1.tar.gz
# Successfully built smcp_security-1.0.0b1-py3-none-any.whl
```

---

### Step 4: Check the Package

```bash
twine check dist/*

# Should say: Checking distribution dist/...
#             PASSED
```

---

### Step 5: Upload to TestPyPI (Test First!)

```bash
twine upload --repository testpypi dist/*

# You'll be prompted:
# Enter your username: __token__
# Enter your password: [paste your TestPyPI token here]

# Should see:
# Uploading smcp_security-1.0.0b1-py3-none-any.whl
# Uploading smcp_security-1.0.0b1.tar.gz
# View at: https://test.pypi.org/project/smcp-security/
```

---

### Step 6: Test Installation from TestPyPI

```bash
# In a new terminal or virtual environment
pip install --index-url https://test.pypi.org/simple/ --no-deps smcp-security

# Note: Use --no-deps because dependencies might not be on TestPyPI
# Then install dependencies separately:
pip install cryptography PyJWT argon2-cffi bcrypt pyotp qrcode jsonschema pydantic python-dateutil

# Test it works:
python -c "from smcp_security import protect; print('✅ SMCP installed successfully!')"
```

If that works, you're ready for production!

---

### Step 7: Upload to PyPI (Production!)

```bash
cd /home/user/SMCPv1/code

twine upload dist/*

# You'll be prompted:
# Enter your username: __token__
# Enter your password: [paste your PyPI token here]

# Should see:
# Uploading smcp_security-1.0.0b1-py3-none-any.whl
# Uploading smcp_security-1.0.0b1.tar.gz
# View at: https://pypi.org/project/smcp-security/
```

---

### Step 8: Test Installation from PyPI

```bash
# Create fresh virtual environment
python -m venv test_env
source test_env/bin/activate

# Install from PyPI
pip install smcp-security

# Test it works
python -c "from smcp_security import protect, secure_mcp; print('✅ Success!')"

# Run an example
cd /home/user/SMCPv1/code
python examples/simple_usage.py
```

---

## Troubleshooting

### Error: "The user '...' isn't allowed to upload to project 'smcp-security'"

**Solution:** This happens if someone else already claimed the name.
- Try a different name in `pyproject.toml` (e.g., `smcp-security-v1`)
- Or contact PyPI support

### Error: "File already exists"

**Solution:** You can't reupload the same version.
1. Bump version in `pyproject.toml` (e.g., `1.0.0b2`)
2. Update version in `smcp_security/__init__.py`
3. Rebuild: `python -m build`
4. Upload again

### Error: "Invalid distribution"

**Solution:** Run `twine check dist/*` and fix any issues shown.

---

## After Publishing

### Update GitHub

1. Create a release tag:
```bash
git tag v1.0.0-beta
git push origin v1.0.0-beta
```

2. Create GitHub Release:
- Go to https://github.com/wizardscurtain/SMCPv1/releases/new
- Tag: v1.0.0-beta
- Title: "SMCP v1.0.0-beta1 - First Beta Release"
- Description: Copy from below

```markdown
## SMCP v1.0.0-beta1 - First Beta Release

🎉 **SMCP is now available on PyPI!**

Install with: `pip install smcp-security`

### What is SMCP?

SMCP makes securing MCP servers as easy as adding 'HTTPS' to 'HTTP' - just 1-2 lines of code:

```python
from smcp_security import protect

@protect
async def my_tool(args):
    return execute(args)  # Now secure!
```

### Features

- ✅ Command injection protection
- ✅ Path traversal prevention
- ✅ Prompt injection detection
- ✅ SQL/XSS injection blocking
- ✅ Rate limiting & DoS protection
- ✅ Audit logging

### Documentation

- [Quick Start](QUICKSTART.md) - Get started in 5 minutes
- [Complete Guide](COMPLETE_GUIDE.md) - Full documentation
- [API Reference](API_REFERENCE.md) - Complete API docs
- [Examples](code/examples/) - Working code examples

### Installation

```bash
pip install smcp-security
```

### Quick Example

See it in action:
```bash
git clone https://github.com/wizardscurtain/SMCPv1.git
cd SMCPv1/code
python examples/simple_usage.py
```

### Beta Notice

This is a beta release. Please report any issues at:
https://github.com/wizardscurtain/SMCPv1/issues

### What's Next

- Gather community feedback
- Performance optimization
- Security audit
- v1.0.0 stable release

Made with 🔒 by the SMCP Security Team
```

### Announce Release

1. **Anthropic Discord** (MCP channel)
2. **Reddit** - r/MachineLearning
3. **Hacker News** - Show HN
4. **Twitter/X**

---

## Quick Reference

```bash
# Build
cd /home/user/SMCPv1/code
python -m build

# Upload to TestPyPI
twine upload --repository testpypi dist/*

# Upload to PyPI
twine upload dist/*

# Test install
pip install smcp-security
```

---

## You're Ready!

Everything is set up. Just run the commands above and you'll have your package live on PyPI!

🚀 Good luck with the launch!
