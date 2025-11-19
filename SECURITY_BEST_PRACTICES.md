# SMCP Security Best Practices

Essential security practices when using SMCP to secure your MCP servers.

---

## Quick Start: The Basics

### ✅ DO: Use SMCP for All Tools

```python
# Good: All tools protected
from smcp_security import protect

@server.call_tool()
@protect
async def read_file(args):
    return read(args["path"])

@server.call_tool()
@protect
async def execute_command(args):
    return execute(args["command"])
```

### ❌ DON'T: Leave Tools Unprotected

```python
# Bad: Vulnerable to attacks
@server.call_tool()
async def read_file(args):
    return read(args["path"])  # No protection!
```

---

## Input Validation

### ✅ DO: Trust SMCP's Validation

```python
@protect
async def my_tool(args):
    # SMCP already validated inputs before reaching here
    # Safe to use directly
    return process(args)
```

### ❌ DON'T: Skip Validation

```python
# Bad: Bypassing SMCP
async def my_tool(args):
    # Process without validation
    return process(args)  # Vulnerable!
```

### ✅ DO: Add Application-Specific Validation

```python
@protect
async def read_file(args):
    # SMCP validates general security issues
    # Add your own business logic validation
    filepath = args["path"]

    if not filepath.endswith(('.txt', '.md')):
        raise ValueError("Only .txt and .md files allowed")

    return read_file(filepath)
```

---

## Rate Limiting

### ✅ DO: Set Appropriate Limits

```python
from smcp_security import secure_mcp, SecurityConfig

# For public APIs
config = SecurityConfig(default_rate_limit=60)  # 60 req/min

# For internal tools
config = SecurityConfig(default_rate_limit=200)  # 200 req/min

server = secure_mcp(server, config)
```

### ✅ DO: Monitor Rate Limit Events

```python
from smcp_security import get_default_security

security = get_default_security()
metrics = security.get_security_metrics()

if metrics["blocked_requests"] > 100:
    alert_team("High rate of blocked requests")
```

---

## Authentication & Authorization

### ✅ DO: Enable MFA for Sensitive Operations

```python
config = SecurityConfig(
    enable_mfa=True,  # Enable multi-factor auth
    enable_rbac=True  # Enable role-based access
)
```

### ✅ DO: Use RBAC for Multi-User Systems

```python
from smcp_security import RBACManager

rbac = RBACManager()

# Define roles
rbac.create_role("admin", permissions=["*"])
rbac.create_role("user", permissions=["read", "write"])
rbac.create_role("guest", permissions=["read"])

# Assign roles
rbac.assign_role("alice@example.com", "admin")
rbac.assign_role("bob@example.com", "user")
```

---

## Error Handling

### ✅ DO: Handle Security Exceptions Gracefully

```python
from smcp_security import protect
from smcp_security.exceptions import (
    ValidationError,
    RateLimitError,
    SecurityError
)

@protect
async def my_tool(args):
    try:
        return process(args)
    except ValidationError as e:
        # Return user-friendly error
        return {"error": "Invalid input", "message": str(e)}
    except RateLimitError as e:
        return {"error": "Rate limited", "retry_after": 60}
    except SecurityError as e:
        # Log but don't expose details to user
        logger.error(f"Security error: {e}")
        return {"error": "Security violation detected"}
```

### ❌ DON'T: Expose Security Details

```python
# Bad: Exposes internal security logic
@protect
async def my_tool(args):
    try:
        return process(args)
    except Exception as e:
        return {"error": str(e)}  # Too much information!
```

---

## Logging & Monitoring

### ✅ DO: Monitor Security Events

```python
from smcp_security import get_default_security

security = get_default_security()

# Regular health checks
async def security_health_check():
    health = security.health_check()
    metrics = security.get_security_metrics()

    if not health["healthy"]:
        alert_team("Security system unhealthy", health)

    if metrics["threats_detected"] > 10:
        alert_team("High threat activity", metrics)
```

### ✅ DO: Review Audit Logs

```python
# Get recent security events
events = security.audit_logger.get_recent_events(limit=100)

# Look for patterns
failed_auths = [e for e in events if e.category == "AUTHENTICATION_FAILURE"]
if len(failed_auths) > 10:
    alert_team("Multiple failed authentication attempts")
```

---

## Configuration

### ✅ DO: Use Strict Settings for Production

```python
from smcp_security import SecurityConfig

prod_config = SecurityConfig(
    validation_strictness="maximum",  # Strictest validation
    default_rate_limit=100,           # Conservative limit
    anomaly_threshold=0.9,            # High threshold
    enable_mfa=True,                  # Require MFA
    enable_rbac=True,                 # Enforce RBAC
    log_level="WARNING"               # Only log issues
)
```

### ✅ DO: Use Relaxed Settings for Development

```python
dev_config = SecurityConfig(
    validation_strictness="minimal",  # More permissive
    default_rate_limit=1000,          # Higher limit
    enable_mfa=False,                 # Skip MFA
    enable_rbac=False,                # Skip RBAC
    log_level="DEBUG"                 # Verbose logging
)
```

---

## Common Pitfalls

### ❌ DON'T: Disable Security Features

```python
# Bad: Defeats the purpose
config = SecurityConfig(
    enable_input_validation=False,  # Don't do this!
    enable_rate_limiting=False,     # Don't do this!
)
```

### ❌ DON'T: Use Same Config for Dev and Prod

```python
# Bad: Production should be stricter
if ENV == "production":
    config = SecurityConfig()  # Same as dev!
```

### ❌ DON'T: Ignore Security Metrics

```python
# Bad: Not monitoring
@protect
async def my_tool(args):
    return process(args)
# No monitoring of security events!
```

---

## Security Checklist

Before deploying to production:

### Pre-Deployment
- [ ] All tools protected with `@protect` or `secure_mcp()`
- [ ] Production configuration with strict settings
- [ ] MFA enabled for sensitive operations
- [ ] RBAC configured for multi-user access
- [ ] Rate limits set appropriately
- [ ] Error handling implemented
- [ ] Logging configured
- [ ] Security monitoring set up

### Post-Deployment
- [ ] Monitor security metrics daily
- [ ] Review audit logs weekly
- [ ] Update dependencies regularly
- [ ] Test security with pen-testing
- [ ] Have incident response plan
- [ ] Document security procedures

---

## Incident Response

### If Attack Detected

1. **Immediate:**
   - Block attacker IP/user
   - Review recent actions
   - Check for data exfiltration

2. **Short-term:**
   - Investigate attack vector
   - Fix vulnerability
   - Update security rules
   - Notify affected users

3. **Long-term:**
   - Conduct security audit
   - Update procedures
   - Train team
   - Document lessons learned

### Example Response Code

```python
from smcp_security import get_default_security

async def handle_security_incident(user_id: str):
    security = get_default_security()

    # Block user
    security.rate_limiter.block_user(user_id, duration=3600)

    # Get their recent activity
    events = security.audit_logger.get_user_events(user_id, limit=100)

    # Alert team
    alert_team({
        "user": user_id,
        "events": len(events),
        "timestamp": datetime.now()
    })

    # Log incident
    security.audit_logger.log_event(
        category="INCIDENT",
        severity="CRITICAL",
        message=f"Security incident: {user_id}",
        details={"action": "user_blocked"}
    )
```

---

## Performance Considerations

### ✅ DO: Monitor Performance Impact

```python
import time

@protect
async def my_tool(args):
    start = time.time()
    result = await process(args)
    duration = time.time() - start

    if duration > 1.0:  # Slow request
        logger.warning(f"Slow request: {duration}s")

    return result
```

### ✅ DO: Cache Validation Results (if appropriate)

```python
# SMCP includes built-in caching
# You can add application-level caching too
from functools import lru_cache

@lru_cache(maxsize=1000)
def validate_user_permission(user_id: str, permission: str) -> bool:
    return rbac.check_permission(user_id, permission)
```

---

## Testing Security

### ✅ DO: Test Attack Scenarios

```python
import pytest
from smcp_security.exceptions import ValidationError

@pytest.mark.asyncio
async def test_command_injection_blocked():
    server = ProtectedServer()

    with pytest.raises(ValidationError):
        await server.execute_command({
            "command": "ls; rm -rf / #"
        })

@pytest.mark.asyncio
async def test_path_traversal_blocked():
    server = ProtectedServer()

    with pytest.raises(ValidationError):
        await server.read_file({
            "path": "../../../../etc/passwd"
        })
```

### ✅ DO: Test Rate Limiting

```python
@pytest.mark.asyncio
async def test_rate_limiting():
    server = ProtectedServer()

    # Make requests up to limit
    for i in range(100):
        await server.my_tool({"arg": "value"})

    # 101st request should be rate limited
    with pytest.raises(RateLimitError):
        await server.my_tool({"arg": "value"})
```

---

## Summary

**Key Principles:**
1. **Always use `@protect`** - It's one line, no excuse not to
2. **Configure for your environment** - Dev vs prod settings
3. **Monitor actively** - Security metrics and audit logs
4. **Handle errors gracefully** - Don't expose internals
5. **Test security** - Include attack scenarios in tests
6. **Have a response plan** - Know what to do when attacked

**Remember:** SMCP makes MCP secure, but security is a practice, not a feature. Stay vigilant!

---

*Last updated: 2025-11-19 | Version: 1.0.0b1*
