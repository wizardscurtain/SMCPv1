# SMCP Complete Guide

**Everything you need to know to use SMCP effectively.**

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Installation](#installation)
3. [Basic Usage](#basic-usage)
4. [Advanced Configuration](#advanced-configuration)
5. [Real-World Examples](#real-world-examples)
6. [Best Practices](#best-practices)
7. [API Reference](#api-reference)
8. [Troubleshooting](#troubleshooting)
9. [FAQ](#faq)

---

## Quick Start

**Goal:** Secure your MCP server in 5 minutes.

### Step 1: Install
```bash
pip install smcp-security
```

### Step 2: Import and Use
```python
from smcp_security import protect

@server.call_tool()
@protect
async def my_tool(arguments):
    return execute(arguments)  # Now secure!
```

### Step 3: Done!
Your tool is now protected against:
- ✅ Command injection
- ✅ Path traversal
- ✅ SQL injection
- ✅ XSS attacks
- ✅ Prompt injection
- ✅ Rate limit abuse

---

## Installation

### From PyPI (Recommended)
```bash
# Minimal installation
pip install smcp-security

# With ML threat detection
pip install smcp-security[ml]

# With FastAPI integration
pip install smcp-security[fastapi]

# Everything
pip install smcp-security[all]
```

### From Source
```bash
git clone https://github.com/wizardscurtain/SMCPv1.git
cd SMCPv1/code
pip install -r requirements.txt
```

### Verify Installation
```python
python -c "from smcp_security import protect; print('✓ SMCP installed successfully')"
```

---

## Basic Usage

### Three Ways to Use SMCP

#### 1. Decorator Style (Recommended)
Best for: Individual tool protection

```python
from smcp_security import protect

@protect
async def dangerous_tool(args):
    return execute(args)
```

#### 2. One-Liner Style (Simplest)
Best for: Protecting entire server

```python
from smcp_security import secure_mcp

server = Server("my-tools")
server = secure_mcp(server)  # All tools now protected!
```

#### 3. Middleware Style
Best for: Web frameworks (FastAPI, etc.)

```python
from smcp_security import SMCPMiddleware

app.add_middleware(SMCPMiddleware)
```

---

## Advanced Configuration

### Custom Security Settings

```python
from smcp_security import SecurityConfig, secure_mcp

config = SecurityConfig(
    # Validation
    validation_strictness="maximum",  # "minimal", "standard", "maximum"

    # Rate limiting
    default_rate_limit=200,  # requests per minute
    enable_rate_limiting=True,

    # AI threat detection
    enable_ai_immune=True,
    anomaly_threshold=0.9,  # 0.0 to 1.0

    # Authentication
    enable_mfa=True,
    jwt_expiry_seconds=3600,

    # Authorization
    enable_rbac=True,

    # Logging
    log_level="INFO",  # "DEBUG", "INFO", "WARNING", "ERROR"
    enable_audit_logging=True
)

server = secure_mcp(server, config)
```

### Environment-Specific Configs

```python
# Development
dev_config = SecurityConfig(
    validation_strictness="minimal",
    default_rate_limit=1000,
    enable_mfa=False,
    log_level="DEBUG"
)

# Production
prod_config = SecurityConfig(
    validation_strictness="maximum",
    default_rate_limit=100,
    enable_mfa=True,
    log_level="WARNING"
)

config = prod_config if IS_PRODUCTION else dev_config
server = secure_mcp(server, config)
```

---

## Real-World Examples

### Example 1: File Operations
```python
from smcp_security import protect

@protect
async def read_file(args):
    """Read a file - protected against path traversal."""
    filepath = args["path"]

    # SMCP already validated:
    # - No path traversal (../)
    # - No command injection
    # - Rate limited

    with open(filepath) as f:
        return f.read()
```

### Example 2: Database Queries
```python
@protect
async def query_database(args):
    """Query database - protected against SQL injection."""
    query = args["query"]

    # SMCP already validated:
    # - No SQL injection patterns
    # - No malicious commands

    return db.execute(query)
```

### Example 3: Code Execution
```python
@protect
async def run_code(args):
    """Execute code - protected against injection."""
    code = args["code"]

    # SMCP validated input
    # Add your own sandboxing
    return safe_exec(code)
```

See `code/examples/` for complete runnable examples.

---

## Best Practices

### 1. Always Use Protection
```python
# ✅ Good
@protect
async def tool(args):
    return process(args)

# ❌ Bad
async def tool(args):
    return process(args)  # Unprotected!
```

### 2. Configure for Your Environment
```python
# ✅ Good: Different configs for dev/prod
config = prod_config if IS_PRODUCTION else dev_config

# ❌ Bad: Same config everywhere
config = SecurityConfig()
```

### 3. Monitor Security Metrics
```python
# ✅ Good: Regular monitoring
from smcp_security import get_default_security

security = get_default_security()
metrics = security.get_security_metrics()

if metrics["threats_detected"] > 10:
    alert_team(metrics)
```

### 4. Handle Errors Gracefully
```python
# ✅ Good: User-friendly errors
from smcp_security.exceptions import ValidationError

@protect
async def tool(args):
    try:
        return process(args)
    except ValidationError as e:
        return {"error": "Invalid input"}
```

### 5. Test Security
```python
# ✅ Good: Test attack scenarios
def test_command_injection_blocked():
    with pytest.raises(ValidationError):
        await tool({"cmd": "ls; rm -rf /"})
```

See [SECURITY_BEST_PRACTICES.md](SECURITY_BEST_PRACTICES.md) for complete guide.

---

## API Reference

### Simple Integration API

```python
from smcp_security import protect, secure_mcp, SMCPMiddleware, get_default_security

# Decorator
@protect
async def tool(args): ...

# One-liner
server = secure_mcp(server, config=None)

# Middleware
app.add_middleware(SMCPMiddleware, config=None)

# Get security instance
security = get_default_security()
```

### Core Framework API

```python
from smcp_security import SMCPSecurityFramework, SecurityConfig

# Create instance
config = SecurityConfig(...)
security = SMCPSecurityFramework(config)

# Process request
result = await security.process_request(request_data, user_context)

# Get metrics
metrics = security.get_security_metrics()

# Health check
health = security.health_check()
```

See [API_REFERENCE.md](API_REFERENCE.md) for complete documentation.

---

## Troubleshooting

### Installation Issues

**Problem:** `pip install smcp-security` fails
```bash
# Solution: Update pip
python -m pip install --upgrade pip
pip install smcp-security
```

### Import Issues

**Problem:** `ModuleNotFoundError: No module named 'smcp_security'`
```bash
# Solution: Check installation
pip list | grep smcp-security

# Reinstall if needed
pip install --force-reinstall smcp-security
```

### Configuration Issues

**Problem:** Settings not taking effect
```python
# Solution: Pass config explicitly
from smcp_security import secure_mcp, SecurityConfig

config = SecurityConfig(default_rate_limit=200)
server = secure_mcp(server, config)  # ← Pass config here
```

### Performance Issues

**Problem:** Requests too slow
```python
# Solution: Reduce validation strictness
config = SecurityConfig(
    validation_strictness="standard",  # Not "maximum"
    enable_ai_immune=False  # Disable ML if not needed
)
```

### Rate Limiting Issues

**Problem:** Getting rate limited too quickly
```python
# Solution: Increase rate limit
config = SecurityConfig(default_rate_limit=500)
```

---

## FAQ

### Q: Do I need to use `@protect` on every tool?
**A:** Yes, for maximum security. But you can also use `secure_mcp()` to protect all tools at once.

### Q: What's the performance impact?
**A:** Minimal. Typically <10ms per request. Exact impact depends on configuration.

### Q: Can I use SMCP with existing security?
**A:** Yes! SMCP adds an additional layer. It works alongside your existing security.

### Q: Does SMCP work with any MCP framework?
**A:** Yes! SMCP is framework-agnostic. Works with any MCP implementation.

### Q: What if I need custom validation?
**A:** Add your own validation after `@protect`. SMCP handles security, you handle business logic.

```python
@protect
async def tool(args):
    # SMCP validated security issues
    # Add your business logic validation
    if not args["field"]:
        raise ValueError("Field required")
    return process(args)
```

### Q: How do I update SMCP?
```bash
pip install --upgrade smcp-security
```

### Q: Is SMCP production-ready?
**A:** v1.0.0-beta1 is suitable for testing. v1.0.0 (stable) will be production-ready after security audit and community testing.

### Q: Where can I get help?
- GitHub Issues: https://github.com/wizardscurtain/SMCPv1/issues
- Discussions: https://github.com/wizardscurtain/SMCPv1/discussions
- Documentation: All `.md` files in the repo

---

## Additional Resources

### Documentation
- [QUICKSTART.md](QUICKSTART.md) - 5-minute guide
- [API_REFERENCE.md](API_REFERENCE.md) - Complete API docs
- [SECURITY_BEST_PRACTICES.md](SECURITY_BEST_PRACTICES.md) - Security guide
- [PUBLISHING.md](PUBLISHING.md) - For maintainers

### Examples
- `code/examples/01_basic_protection.py` - Basic usage
- `code/examples/02_file_operations.py` - File operations
- `code/examples/simple_usage.py` - Quick demo

### Community
- GitHub: https://github.com/wizardscurtain/SMCPv1
- Issues: https://github.com/wizardscurtain/SMCPv1/issues
- Discussions: https://github.com/wizardscurtain/SMCPv1/discussions

---

## Summary

**SMCP makes MCP secure in 1-2 lines of code:**

```python
from smcp_security import protect

@protect
async def tool(args):
    return execute(args)
```

**Just like HTTPS made HTTP secure, SMCP makes MCP secure.**

**Get started:** `pip install smcp-security`

---

*Version: 1.0.0b1 | Last updated: 2025-11-19*
