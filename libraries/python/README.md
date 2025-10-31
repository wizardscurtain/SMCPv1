# SMCP Security - Python Library

[![PyPI version](https://badge.fury.io/py/smcp-security.svg)](https://badge.fury.io/py/smcp-security)
[![Python Support](https://img.shields.io/pypi/pyversions/smcp-security.svg)](https://pypi.org/project/smcp-security/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Downloads](https://pepy.tech/badge/smcp-security)](https://pepy.tech/project/smcp-security)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=smcp-security&metric=security_rating)](https://sonarcloud.io/dashboard?id=smcp-security)

Secure Model Context Protocol (SMCP) v1 - A production-ready security framework for Model Context Protocol implementations.

## Features

- 🔐 **Multi-layered Security**: Input validation, authentication, authorization, and encryption
- 🛡️ **AI-Immune System**: Machine learning-based threat detection and prevention
- 🚀 **High Performance**: Optimized for production workloads with minimal overhead
- 📊 **Comprehensive Auditing**: Detailed security event logging and monitoring
- 🔄 **Rate Limiting**: Adaptive rate limiting with DoS protection
- 🎯 **Easy Integration**: Simple API with middleware patterns for popular frameworks

## Quick Start

### Installation

```bash
# Basic installation
pip install smcp-security

# With FastAPI support
pip install smcp-security[fastapi]

# With machine learning features
pip install smcp-security[ml]

# Full installation with all features
pip install smcp-security[all]
```

### Basic Usage

```python
from smcp_security import SMCPSecurityFramework, SecurityConfig

# Initialize with default configuration
security = SMCPSecurityFramework()

# Validate and secure an MCP request
request_data = {
    "method": "tools/list",
    "params": {},
    "id": "req-123"
}

try:
    # Validate the request
    validated_request = security.validate_request(request_data)
    
    # Process with security checks
    result = security.process_secure_request(
        request=validated_request,
        user_id="user-123",
        session_token="jwt-token-here"
    )
    
    print("Request processed securely:", result)
except SecurityError as e:
    print(f"Security violation: {e}")
```

### FastAPI Integration

```python
from fastapi import FastAPI, Depends
from smcp_security import SMCPSecurityFramework
from smcp_security.middleware import SMCPSecurityMiddleware

app = FastAPI()
security = SMCPSecurityFramework()

# Add security middleware
app.add_middleware(SMCPSecurityMiddleware, security_framework=security)

@app.post("/mcp/request")
async def handle_mcp_request(
    request: dict,
    user_context = Depends(security.get_user_context)
):
    # Request is automatically validated and secured
    return await process_mcp_request(request, user_context)
```

### Custom Configuration

```python
from smcp_security import SMCPSecurityFramework, SecurityConfig

# Custom security configuration
config = SecurityConfig(
    enable_mfa=True,
    validation_strictness="maximum",
    enable_ai_immune=True,
    anomaly_threshold=0.8,
    default_rate_limit=50,  # requests per minute
    enable_audit_logging=True
)

security = SMCPSecurityFramework(config=config)
```

## Advanced Features

### AI-Immune System

```python
from smcp_security import AIImmuneSystem, ThreatClassifier

# Initialize AI immune system
ai_immune = AIImmuneSystem()

# Analyze potential threats
threat_score = ai_immune.analyze_request(request_data)
if threat_score > 0.7:
    print("High-risk request detected!")

# Train on new attack patterns
ai_immune.learn_from_attack(attack_data)
```

### Rate Limiting

```python
from smcp_security import AdaptiveRateLimiter

# Create adaptive rate limiter
rate_limiter = AdaptiveRateLimiter(
    base_limit=100,  # requests per minute
    burst_limit=200,
    adaptive=True
)

# Check rate limit
if rate_limiter.is_allowed(user_id="user-123"):
    # Process request
    pass
else:
    # Rate limit exceeded
    raise RateLimitError("Too many requests")
```

### Cryptographic Operations

```python
from smcp_security import SMCPCrypto

# Initialize crypto module
crypto = SMCPCrypto()

# Encrypt sensitive data
encrypted_data = crypto.encrypt("sensitive information")

# Decrypt data
decrypted_data = crypto.decrypt(encrypted_data)

# Generate secure tokens
token = crypto.generate_secure_token(32)
```

## Security Features

### Input Validation
- Command injection prevention
- SQL injection protection
- XSS prevention
- Path traversal protection
- Schema validation
- Content sanitization

### Authentication & Authorization
- JWT token management
- Multi-factor authentication (MFA)
- Role-based access control (RBAC)
- Session management
- Token refresh and rotation

### Threat Detection
- Real-time anomaly detection
- Machine learning-based threat classification
- Behavioral analysis
- Attack pattern recognition
- Adaptive defense mechanisms

### Audit & Monitoring
- Comprehensive security event logging
- Real-time monitoring
- Compliance reporting
- Performance metrics
- Security analytics

## API Reference

### Core Classes

#### SMCPSecurityFramework
Main security framework class that orchestrates all security components.

```python
class SMCPSecurityFramework:
    def __init__(self, config: SecurityConfig = None)
    def validate_request(self, request: dict) -> dict
    def authenticate_user(self, credentials: dict) -> str
    def authorize_action(self, user_id: str, action: str) -> bool
    def process_secure_request(self, request: dict, user_id: str, session_token: str) -> dict
    def get_security_metrics(self) -> dict
```

#### SecurityConfig
Configuration class for customizing security behavior.

```python
@dataclass
class SecurityConfig:
    enable_input_validation: bool = True
    validation_strictness: str = "standard"
    enable_mfa: bool = True
    enable_rbac: bool = True
    enable_rate_limiting: bool = True
    enable_ai_immune: bool = True
    enable_audit_logging: bool = True
```

### Middleware

#### FastAPI Middleware
```python
from smcp_security.middleware import SMCPSecurityMiddleware

app.add_middleware(SMCPSecurityMiddleware, security_framework=security)
```

#### Flask Middleware
```python
from smcp_security.middleware import SMCPFlaskMiddleware

app.wsgi_app = SMCPFlaskMiddleware(app.wsgi_app, security_framework=security)
```

## Examples

See the [examples](https://github.com/wizardscurtain/SMCPv1/tree/main/examples/python) directory for complete implementation examples:

- [Basic Usage](examples/basic_usage.py)
- [FastAPI Integration](examples/fastapi_example.py)
- [Flask Integration](examples/flask_example.py)
- [Custom Security Policies](examples/custom_policies.py)
- [AI Immune System](examples/ai_immune_example.py)

## Testing

```bash
# Run tests
pytest

# Run with coverage
pytest --cov=smcp_security

# Run security tests
pytest -m security

# Run performance tests
pytest -m performance
```

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## Security

For security issues, please email security@smcp.dev instead of using the issue tracker.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- 📖 [Documentation](https://smcp-security.readthedocs.io)
- 💬 [Discussions](https://github.com/wizardscurtain/SMCPv1/discussions)
- 🐛 [Issues](https://github.com/wizardscurtain/SMCPv1/issues)
- 📧 [Email Support](mailto:support@smcp.dev)

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and updates.
