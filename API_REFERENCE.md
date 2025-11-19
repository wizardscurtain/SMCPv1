# SMCP API Reference

Complete reference for the SMCP Security Framework.

---

## Simple Integration API

These are the recommended APIs for most users. They provide security in 1-2 lines of code.

### `protect` Decorator

**Import:**
```python
from smcp_security import protect
```

**Usage:**
```python
@protect
async def my_tool(arguments: dict) -> str:
    # Your tool implementation
    return result
```

**Description:**
Decorator that adds SMCP security to an individual MCP tool. Validates inputs, checks rate limits, detects threats, and logs security events.

**What it does:**
- ✅ Input validation (command injection, XSS, SQL injection, path traversal)
- ✅ Prompt injection detection
- ✅ Rate limiting (100 requests/minute per user by default)
- ✅ Threat detection and scoring
- ✅ Audit logging

**Parameters:** None (uses global default security configuration)

**Returns:** Async function wrapper

**Raises:**
- `ValidationError` - Input validation failed
- `RateLimitError` - Rate limit exceeded
- `SecurityError` - Security violation detected

**Example:**
```python
from smcp_security import protect

@server.call_tool()
@protect
async def read_file(arguments: dict) -> str:
    """Read a file - protected against path traversal."""
    filepath = arguments["path"]
    with open(filepath) as f:
        return f.read()

# Legitimate request - works
result = await read_file({"path": "/home/user/doc.txt"})

# Attack - blocked
result = await read_file({"path": "../../../../etc/passwd"})
# Raises: ValidationError: Path traversal detected
```

---

### `secure_mcp()` Function

**Import:**
```python
from smcp_security import secure_mcp
```

**Signature:**
```python
def secure_mcp(
    server: Any,
    config: Optional[SecurityConfig] = None
) -> Any
```

**Description:**
One-liner to add SMCP security to an entire MCP server. All tools registered after calling this will be automatically protected.

**Parameters:**
- `server` (Any): Your MCP server instance (any framework)
- `config` (SecurityConfig, optional): Custom security configuration. If not provided, uses sensible defaults.

**Returns:**
The server instance with security middleware attached

**Example:**
```python
from mcp.server import Server
from smcp_security import secure_mcp

# Create server
server = Server("my-tools")

# Add security (one line!)
server = secure_mcp(server)

# All tools now protected
@server.call_tool()
async def dangerous_tool(args):
    return execute(args)  # Automatically protected!
```

**With custom configuration:**
```python
from smcp_security import secure_mcp, SecurityConfig

config = SecurityConfig(
    validation_strictness="maximum",
    default_rate_limit=200,  # 200 req/min
    enable_mfa=True
)

server = secure_mcp(server, config)
```

---

### `SMCPMiddleware` Class

**Import:**
```python
from smcp_security import SMCPMiddleware
```

**Usage:**
```python
app.add_middleware(SMCPMiddleware)
```

**Description:**
ASGI middleware for adding SMCP security to web frameworks (FastAPI, Starlette, etc.)

**Constructor:**
```python
SMCPMiddleware(
    app: Any,
    config: Optional[SecurityConfig] = None
)
```

**Parameters:**
- `app` (Any): ASGI application
- `config` (SecurityConfig, optional): Custom security configuration

**Example with FastAPI:**
```python
from fastapi import FastAPI
from smcp_security import SMCPMiddleware

app = FastAPI()
app.add_middleware(SMCPMiddleware)

@app.post("/tool")
async def execute_tool(request: dict):
    # Protected by SMCP middleware
    return {"result": "success"}
```

---

### `get_default_security()` Function

**Import:**
```python
from smcp_security import get_default_security
```

**Signature:**
```python
def get_default_security() -> SMCPSecurityFramework
```

**Description:**
Returns the global default security instance. Useful for accessing metrics, audit logs, or customizing behavior.

**Returns:**
SMCPSecurityFramework instance

**Example:**
```python
from smcp_security import get_default_security

security = get_default_security()

# Get metrics
metrics = security.get_security_metrics()
print(f"Total requests: {metrics['total_requests']}")
print(f"Blocked: {metrics['blocked_requests']}")

# Get recent security events
events = security.audit_logger.get_recent_events(limit=10)
for event in events:
    print(f"{event.timestamp}: {event.message}")
```

---

## Core Framework API

Advanced API for users who need fine-grained control.

### `SMCPSecurityFramework` Class

**Import:**
```python
from smcp_security import SMCPSecurityFramework, SecurityConfig
```

**Constructor:**
```python
SMCPSecurityFramework(config: SecurityConfig = None)
```

**Description:**
Main security framework that orchestrates all security layers.

**Methods:**

#### `async process_request(request_data, user_context=None)`
Process a request through all security layers.

**Parameters:**
- `request_data` (dict): Request data to validate
- `user_context` (dict, optional): User context (user_id, roles, etc.)

**Returns:**
dict: Processed request with security metadata

**Raises:**
- `ValidationError` - Input validation failed
- `AuthenticationError` - Authentication failed
- `AuthorizationError` - Authorization failed
- `RateLimitError` - Rate limit exceeded
- `SecurityError` - Security violation

**Example:**
```python
from smcp_security import SMCPSecurityFramework, SecurityConfig

config = SecurityConfig(
    enable_input_validation=True,
    enable_rate_limiting=True,
    default_rate_limit=100
)

security = SMCPSecurityFramework(config)

# Process a request
request = {
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {"command": "ls -la"}
}

result = await security.process_request(
    request_data=request,
    user_context={"user_id": "user123"}
)
```

#### `get_security_metrics()`
Get current security metrics.

**Returns:**
dict with keys:
- `total_requests` (int)
- `blocked_requests` (int)
- `threats_detected` (int)
- `average_security_score` (float)
- `layers_active` (list)

#### `health_check()`
Check health status of all security components.

**Returns:**
dict with keys:
- `healthy` (bool)
- `components` (dict): Status of each component
- `timestamp` (str)

#### `async shutdown()`
Gracefully shut down the security framework.

---

### `SecurityConfig` Class

**Import:**
```python
from smcp_security import SecurityConfig
```

**Constructor:**
```python
@dataclass
class SecurityConfig:
    # Input validation settings
    enable_input_validation: bool = True
    validation_strictness: str = "standard"  # "minimal", "standard", "maximum"

    # Authentication settings
    enable_mfa: bool = False
    jwt_expiry_seconds: int = 3600
    session_timeout_seconds: int = 7200

    # Authorization settings
    enable_rbac: bool = False
    default_permissions: List[str] = None

    # Rate limiting settings
    enable_rate_limiting: bool = True
    default_rate_limit: int = 100  # requests per minute
    adaptive_limits: bool = True

    # Cryptographic settings
    enable_encryption: bool = True
    key_rotation_interval: int = 86400  # 24 hours

    # AI immune system settings
    enable_ai_immune: bool = True
    anomaly_threshold: float = 0.7
    learning_mode: bool = False

    # Audit settings
    enable_audit_logging: bool = True
    log_level: str = "INFO"
```

**Description:**
Configuration for the SMCP Security Framework.

**Validation Strictness Levels:**

| Level | Description | Use Case |
|-------|-------------|----------|
| `minimal` | Basic validation, permissive | Development, testing |
| `standard` | Balanced security/usability | Most production use cases |
| `maximum` | Strictest validation | High-security environments |

**Example:**
```python
from smcp_security import SecurityConfig

# Development config
dev_config = SecurityConfig(
    validation_strictness="minimal",
    enable_mfa=False,
    enable_rbac=False,
    log_level="DEBUG"
)

# Production config
prod_config = SecurityConfig(
    validation_strictness="maximum",
    enable_mfa=True,
    enable_rbac=True,
    default_rate_limit=200,
    anomaly_threshold=0.9,
    log_level="WARNING"
)
```

---

## Security Layer APIs

Advanced APIs for specific security components.

### Input Validation

#### `InputValidator` Class

**Import:**
```python
from smcp_security import InputValidator
```

**Methods:**

##### `async validate_request(request_data, strictness="standard")`
Validate MCP request for security issues.

**Parameters:**
- `request_data` (dict): Request to validate
- `strictness` (str): Validation level ("minimal", "standard", "maximum")

**Returns:**
dict: Validated and sanitized request

**Raises:**
- `ValidationError` - Validation failed

**Example:**
```python
from smcp_security import InputValidator

validator = InputValidator()

request = {
    "method": "tools/call",
    "params": {"command": "ls -la"}
}

# Valid request
validated = await validator.validate_request(request)

# Malicious request
malicious = {
    "method": "tools/call",
    "params": {"command": "ls; rm -rf / #"}
}
validated = await validator.validate_request(malicious)
# Raises: ValidationError: Command injection detected
```

#### `CommandInjectionPrevention` Class

**Import:**
```python
from smcp_security import CommandInjectionPrevention
```

**Methods:**

##### `detect_command_injection(text: str) -> bool`
Detect command injection attempts.

**Returns:**
bool: True if injection detected

**Example:**
```python
from smcp_security import CommandInjectionPrevention

detector = CommandInjectionPrevention()

detector.detect_command_injection("ls -la")  # False
detector.detect_command_injection("ls; rm -rf /")  # True
detector.detect_command_injection("cat /etc/passwd")  # True
```

---

### Authentication

#### `JWTAuthenticator` Class

**Import:**
```python
from smcp_security import JWTAuthenticator
```

**Methods:**

##### `generate_token(user_id: str, **claims) -> str`
Generate JWT token.

**Parameters:**
- `user_id` (str): User identifier
- `**claims`: Additional JWT claims

**Returns:**
str: JWT token

##### `validate_token(token: str) -> dict`
Validate JWT token.

**Parameters:**
- `token` (str): JWT token to validate

**Returns:**
dict: Token claims

**Raises:**
- `AuthenticationError` - Token invalid or expired

**Example:**
```python
from smcp_security import JWTAuthenticator

auth = JWTAuthenticator(secret_key="your-secret-key")

# Generate token
token = auth.generate_token(
    user_id="user123",
    roles=["user", "admin"]
)

# Validate token
claims = auth.validate_token(token)
print(claims["user_id"])  # "user123"
print(claims["roles"])    # ["user", "admin"]
```

#### `MFAManager` Class

**Import:**
```python
from smcp_security import MFAManager
```

**Methods:**

##### `setup_totp(user_id: str) -> dict`
Set up TOTP (Time-based One-Time Password) for a user.

**Returns:**
dict with keys:
- `secret` (str): TOTP secret
- `qr_code` (str): QR code data URL
- `backup_codes` (list): Backup codes

##### `verify_totp(user_id: str, code: str) -> bool`
Verify TOTP code.

**Returns:**
bool: True if valid

**Example:**
```python
from smcp_security import MFAManager

mfa = MFAManager()

# Setup MFA for user
setup = mfa.setup_totp("user123")
print(f"Secret: {setup['secret']}")
print(f"QR Code: {setup['qr_code']}")  # Display to user

# Verify code
is_valid = mfa.verify_totp("user123", "123456")
```

---

### Authorization

#### `RBACManager` Class

**Import:**
```python
from smcp_security import RBACManager
```

**Methods:**

##### `assign_role(user_id: str, role: str)`
Assign role to user.

##### `check_permission(user_id: str, permission: str) -> bool`
Check if user has permission.

**Example:**
```python
from smcp_security import RBACManager

rbac = RBACManager()

# Define roles
rbac.create_role("admin", permissions=["*"])
rbac.create_role("user", permissions=["read", "write"])
rbac.create_role("guest", permissions=["read"])

# Assign roles
rbac.assign_role("alice", "admin")
rbac.assign_role("bob", "user")

# Check permissions
rbac.check_permission("alice", "delete")  # True
rbac.check_permission("bob", "delete")    # False
```

---

### Rate Limiting

#### `AdaptiveRateLimiter` Class

**Import:**
```python
from smcp_security import AdaptiveRateLimiter
```

**Methods:**

##### `async check_rate_limit(user_id: str, weight: int = 1) -> bool`
Check if request is within rate limit.

**Returns:**
bool: True if allowed

**Raises:**
- `RateLimitError` - Rate limit exceeded

**Example:**
```python
from smcp_security import AdaptiveRateLimiter

limiter = AdaptiveRateLimiter(default_limit=100)

# Check rate limit
try:
    await limiter.check_rate_limit("user123")
    # Process request
except RateLimitError as e:
    print(f"Rate limited: {e}")
```

---

### Audit Logging

#### `SMCPAuditLogger` Class

**Import:**
```python
from smcp_security import SMCPAuditLogger
```

**Methods:**

##### `log_event(category: str, severity: str, message: str, details: dict = None)`
Log security event.

##### `get_recent_events(limit: int = 100) -> List[SecurityEvent]`
Get recent security events.

**Example:**
```python
from smcp_security import SMCPAuditLogger

logger = SMCPAuditLogger()

# Log security event
logger.log_event(
    category="AUTHENTICATION",
    severity="WARNING",
    message="Failed login attempt",
    details={"user_id": "user123", "ip": "1.2.3.4"}
)

# Get recent events
events = logger.get_recent_events(limit=10)
for event in events:
    print(f"{event.timestamp}: {event.message}")
```

---

### AI Immune System

#### `AIImmuneSystem` Class

**Import:**
```python
from smcp_security import AIImmuneSystem
```

**Methods:**

##### `async analyze_request(request_data: dict) -> dict`
Analyze request for anomalies and threats.

**Returns:**
dict with keys:
- `is_anomaly` (bool)
- `threat_score` (float)
- `threat_category` (str)
- `features` (dict)

**Example:**
```python
from smcp_security import AIImmuneSystem

ai_immune = AIImmuneSystem(threshold=0.8)

request = {"method": "tools/call", "params": {...}}
analysis = await ai_immune.analyze_request(request)

if analysis["is_anomaly"]:
    print(f"Threat detected: {analysis['threat_category']}")
    print(f"Score: {analysis['threat_score']}")
```

---

## Exceptions

All SMCP exceptions inherit from `SecurityError`.

### Exception Hierarchy

```python
SecurityError (base)
├── ValidationError
│   ├── CommandInjectionError
│   ├── PromptInjectionError
│   └── PathTraversalError
├── AuthenticationError
│   ├── InvalidTokenError
│   └── TokenExpiredError
├── AuthorizationError
│   └── PermissionDeniedError
├── RateLimitError
├── CryptographicError
└── AnomalyDetectionError
```

### Import and Usage

```python
from smcp_security.exceptions import (
    SecurityError,
    ValidationError,
    AuthenticationError,
    AuthorizationError,
    RateLimitError
)

try:
    result = await security.process_request(request)
except ValidationError as e:
    print(f"Validation failed: {e}")
except RateLimitError as e:
    print(f"Rate limited: {e}")
except SecurityError as e:
    print(f"Security error: {e}")
```

---

## Best Practices

### 1. Use Simple API for Most Cases
```python
# Good: Simple and secure
from smcp_security import protect

@protect
async def my_tool(args):
    return execute(args)
```

### 2. Custom Config for Production
```python
# Good: Production-ready configuration
from smcp_security import secure_mcp, SecurityConfig

config = SecurityConfig(
    validation_strictness="maximum",
    default_rate_limit=200,
    enable_mfa=True,
    enable_rbac=True,
    log_level="WARNING"
)

server = secure_mcp(server, config)
```

### 3. Monitor Security Metrics
```python
# Good: Regular monitoring
from smcp_security import get_default_security

security = get_default_security()
metrics = security.get_security_metrics()

if metrics["blocked_requests"] > 100:
    alert_security_team(metrics)
```

### 4. Handle Exceptions Gracefully
```python
# Good: Proper error handling
from smcp_security import protect
from smcp_security.exceptions import ValidationError, RateLimitError

@protect
async def my_tool(args):
    try:
        return execute(args)
    except ValidationError as e:
        return {"error": "Invalid input", "details": str(e)}
    except RateLimitError as e:
        return {"error": "Rate limited", "retry_after": e.retry_after}
```

---

## Full Example

Complete example combining multiple features:

```python
from smcp_security import (
    SMCPSecurityFramework,
    SecurityConfig,
    protect,
    get_default_security
)
from smcp_security.exceptions import SecurityError

# Configure security
config = SecurityConfig(
    validation_strictness="maximum",
    enable_mfa=True,
    enable_rbac=True,
    default_rate_limit=200,
    anomaly_threshold=0.9
)

# Create framework instance
security = SMCPSecurityFramework(config)

# Protect individual tools
@protect
async def read_file(args):
    """Protected file reading."""
    return open(args["path"]).read()

# Process requests manually
async def handle_request(request, user):
    try:
        result = await security.process_request(
            request_data=request,
            user_context={"user_id": user["id"], "roles": user["roles"]}
        )
        return {"status": "success", "data": result}
    except SecurityError as e:
        return {"status": "error", "message": str(e)}

# Monitor security
def check_security_health():
    metrics = security.get_security_metrics()
    health = security.health_check()

    return {
        "metrics": metrics,
        "health": health,
        "timestamp": datetime.now().isoformat()
    }
```

---

## Support

- **Documentation:** https://github.com/wizardscurtain/SMCPv1#readme
- **Issues:** https://github.com/wizardscurtain/SMCPv1/issues
- **Discussions:** https://github.com/wizardscurtain/SMCPv1/discussions

---

*Last updated: 2025-11-19 | Version: 1.0.0b1*
