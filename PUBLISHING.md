# Publishing SMCP to PyPI

This guide explains how to publish SMCP to PyPI (Python Package Index).

## Prerequisites

### 1. PyPI Account
1. Create account at https://pypi.org
2. Enable 2FA (required)
3. Create API token at https://pypi.org/manage/account/token/
   - Scope: "Entire account" (for first publish) or specific to smcp-security project
   - Copy the token (starts with `pypi-`)

### 2. TestPyPI Account (for testing)
1. Create account at https://test.pypi.org
2. Create API token at https://test.pypi.org/manage/account/token/
   - Copy the token

### 3. GitHub Secrets (for automated publishing)
1. Go to https://github.com/wizardscurtain/SMCPv1/settings/secrets/actions
2. Add secrets:
   - `PYPI_TOKEN`: Your PyPI API token
   - `TEST_PYPI_TOKEN`: Your TestPyPI API token

---

## Manual Publishing

### Option 1: Publish to TestPyPI (recommended first)

```bash
# From project root
cd code

# Build the package
python -m build

# Upload to TestPyPI
python -m twine upload --repository testpypi dist/*

# Test installation
pip install --index-url https://test.pypi.org/simple/ smcp-security
```

### Option 2: Publish to PyPI (production)

```bash
# From project root
cd code

# Build the package
python -m build

# Upload to PyPI
python -m twine upload dist/*

# Test installation
pip install smcp-security
```

---

## Automated Publishing (via GitHub Actions)

The CI/CD workflow automatically publishes when you create a git tag.

### For Beta Releases (TestPyPI)

```bash
# Create a beta tag
git tag v1.0.0-beta
git push origin v1.0.0-beta

# GitHub Actions will:
# 1. Run tests
# 2. Build package
# 3. Publish to TestPyPI
```

### For Stable Releases (PyPI)

```bash
# Create a stable tag
git tag v1.0.0
git push origin v1.0.0

# GitHub Actions will:
# 1. Run tests
# 2. Build package
# 3. Publish to PyPI
```

---

## Version Numbering

### Beta Releases
- Format: `1.0.0b1`, `1.0.0b2`, etc.
- Git tag: `v1.0.0-beta`, `v1.0.0-beta2`, etc.
- Published to: TestPyPI
- Install: `pip install --index-url https://test.pypi.org/simple/ smcp-security`

### Release Candidates
- Format: `1.0.0rc1`, `1.0.0rc2`, etc.
- Git tag: `v1.0.0-rc1`, `v1.0.0-rc2`, etc.
- Published to: TestPyPI (configure in workflow if needed)
- Install: `pip install --index-url https://test.pypi.org/simple/ smcp-security`

### Stable Releases
- Format: `1.0.0`, `1.1.0`, `2.0.0`, etc.
- Git tag: `v1.0.0`, `v1.1.0`, `v2.0.0`, etc.
- Published to: PyPI
- Install: `pip install smcp-security`

---

## Publishing Checklist

Before publishing a release:

### Pre-Release
- [ ] All tests passing locally
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version bumped in:
  - [ ] `code/pyproject.toml`
  - [ ] `code/smcp_security/__init__.py`
- [ ] Examples tested
- [ ] README accurate

### Beta Release (to TestPyPI)
- [ ] Run `python -m build` successfully
- [ ] Run `twine check dist/*` - no errors
- [ ] Test local installation: `pip install dist/*.whl`
- [ ] Publish to TestPyPI
- [ ] Test installation from TestPyPI
- [ ] Test basic functionality works
- [ ] Gather feedback

### Stable Release (to PyPI)
- [ ] Beta tested by multiple users
- [ ] Critical bugs fixed
- [ ] Security audit complete (recommended)
- [ ] Performance benchmarks documented
- [ ] All checklist items from Beta Release
- [ ] Announce release:
  - [ ] GitHub Release notes
  - [ ] Anthropic Discord
  - [ ] Reddit (r/MachineLearning)
  - [ ] Hacker News (Show HN)
  - [ ] Twitter/X

---

## Troubleshooting

### Error: "The user 'username' isn't allowed to upload to project 'smcp-security'"

**Solution:** You need to:
1. Publish v1.0.0b1 manually first to claim the project name
2. Then add your GitHub Actions token to the project

### Error: "File already exists"

**Solution:**
1. Bump the version number in pyproject.toml and __init__.py
2. Rebuild: `python -m build`
3. Upload again

### Error: "Invalid distribution file"

**Solution:**
1. Check `twine check dist/*` output
2. Fix any issues in pyproject.toml
3. Rebuild

### Package not installing dependencies

**Solution:**
1. Verify dependencies in pyproject.toml `[project.dependencies]`
2. Test locally: `pip install -e .`
3. Rebuild and republish

---

## Post-Publishing

After publishing:

1. **Test installation immediately:**
   ```bash
   pip install smcp-security
   python -c "from smcp_security import protect; print('Success!')"
   ```

2. **Check PyPI page:**
   - https://pypi.org/project/smcp-security/
   - Verify description renders correctly
   - Check metadata is accurate

3. **Update documentation:**
   - Add installation instructions
   - Update version badges
   - Announce the release

4. **Monitor:**
   - GitHub issues for bug reports
   - PyPI download statistics
   - User feedback

---

## Current Status

**Latest Version:** 1.0.0b1 (Beta 1)
**Published to:** Not yet published
**Next Step:** Manual publish to TestPyPI for testing

---

## Quick Commands Reference

```bash
# Build
cd code && python -m build

# Check build
twine check dist/*

# Publish to TestPyPI
twine upload --repository testpypi dist/*

# Publish to PyPI
twine upload dist/*

# Test installation (TestPyPI)
pip install --index-url https://test.pypi.org/simple/ smcp-security

# Test installation (PyPI)
pip install smcp-security

# Clean build artifacts
rm -rf build/ dist/ *.egg-info
```

---

## Support

- Issues: https://github.com/wizardscurtain/SMCPv1/issues
- PyPI Help: https://pypi.org/help/

---

*Last updated: 2025-11-19*
