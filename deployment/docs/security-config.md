# SMCP Security Framework - Security Configuration Guide

## 🛡️ Security Configuration Overview

The SMCP Security Framework provides comprehensive security controls through a flexible configuration system. This guide covers all security settings and best practices for different environments.

## 📋 Configuration Methods

### 1. Environment Variables (Recommended for Production)

```bash
# Core Security Settings
export SMCP_VALIDATION_STRICTNESS=maximum     # minimal, standard, maximum
export SMCP_ENABLE_MFA=true                   # Enable multi-factor authentication
export SMCP_ENABLE_RBAC=true                  # Enable role-based access control
export SMCP_ENABLE_RATE_LIMITING=true         # Enable rate limiting
export SMCP_DEFAULT_RATE_LIMIT=50             # Requests per minute
export SMCP_ENABLE_ENCRYPTION=true            # Enable encryption
export SMCP_ENABLE_AI_IMMUNE=true             # Enable AI immune system
export SMCP_ANOMALY_THRESHOLD=0.8             # Anomaly detection threshold (0.0-1.0)
export SMCP_ENABLE_AUDIT_LOGGING=true         # Enable audit logging
export SMCP_LOG_LEVEL=INFO                    # DEBUG, INFO, WARNING, ERROR, CRITICAL

# Advanced Settings
export SMCP_JWT_EXPIRY_SECONDS=3600           # JWT token expiry (1 hour)
export SMCP_SESSION_TIMEOUT_SECONDS=7200      # Session timeout (2 hours)
export SMCP_KEY_ROTATION_INTERVAL=86400       # Key rotation interval (24 hours)
```

### 2. Configuration File

```json
{
  "security": {
    "validation_strictness": "maximum",
    "enable_mfa": true,
    "enable_rbac": true,
    "enable_rate_limiting": true,
    "default_rate_limit": 50,
    "adaptive_limits": true,
    "enable_encryption": true,
    "enable_ai_immune": true,
    "anomaly_threshold": 0.8,
    "learning_mode": false,
    "enable_audit_logging": true,
    "log_level": "INFO",
    "jwt_expiry_seconds": 3600,
    "session_timeout_seconds": 7200,
    "key_rotation_interval": 86400,
    "default_permissions": ["mcp:read"]
  },
  "server": {
    "host": "0.0.0.0",
    "port": 8080,
    "workers": 2
  },
  "api": {
    "enable_cors": false,
    "cors_origins": ["https://yourdomain.com"],
    "enable_docs": false
  }
}
```

### 3. Programmatic Configuration

```python
from smcp_security import SecurityConfig, SMCPSecurityFramework

# Create configuration
config = SecurityConfig(
    validation_strictness="maximum",
    enable_mfa=True,
    enable_rbac=True,
    enable_rate_limiting=True,
    default_rate_limit=50,
    enable_encryption=True,
    enable_ai_immune=True,
    anomaly_threshold=0.8,
    enable_audit_logging=True,
    log_level="INFO"
)

# Initialize security framework
security = SMCPSecurityFramework(config)
```

## 🔧 Security Settings Explained

### Input Validation

#### Validation Strictness
- **minimal**: Basic validation, fastest performance
- **standard**: Balanced validation and performance (recommended for most use cases)
- **maximum**: Comprehensive validation, highest security

```python
# Configuration impact
validation_strictness = "maximum"
# Enables:
# - Deep JSON structure validation
# - Advanced command injection detection
# - SQL injection prevention
# - Path traversal protection
# - XSS prevention
# - Advanced pattern matching
```

### Authentication & Authorization

#### Multi-Factor Authentication (MFA)
```python
enable_mfa = True
# Requires:
# - Primary authentication (JWT token)
# - Secondary factor (TOTP, SMS, or hardware key)
# - Increases security but adds complexity
```

#### Role-Based Access Control (RBAC)
```python
enable_rbac = True
default_permissions = ["mcp:read", "mcp:execute:safe_tools"]

# Define custom roles
rbac_manager.define_role("analyst", [
    "mcp:read",
    "mcp:execute:data_tools",
    "mcp:execute:analysis_tools"
])

rbac_manager.define_role("admin", [
    "mcp:*",
    "system:*",
    "security:*"
])
```

### Rate Limiting & DoS Protection

#### Basic Rate Limiting
```python
enable_rate_limiting = True
default_rate_limit = 100  # requests per minute

# Per-user rate limiting
rate_limiter.set_user_limit("power_user", 200)
rate_limiter.set_user_limit("basic_user", 50)
```

#### Adaptive Rate Limiting
```python
adaptive_limits = True
# Automatically adjusts limits based on:
# - User behavior patterns
# - System load
# - Detected anomalies
# - Historical usage
```

### Cryptographic Security

#### Encryption Settings
```python
enable_encryption = True
# Uses ChaCha20-Poly1305 AEAD encryption
# Argon2 key derivation
# Automatic key rotation

key_rotation_interval = 86400  # 24 hours
# Regular key rotation for enhanced security
```

### AI Immune System

#### Anomaly Detection
```python
enable_ai_immune = True
anomaly_threshold = 0.8  # 0.0 (permissive) to 1.0 (strict)

# Learning mode for training
learning_mode = False  # Set to True for initial training period
```

#### Threat Classification
```python
# AI immune system detects:
# - Unusual request patterns
# - Potential attack signatures
# - Behavioral anomalies
# - Zero-day attack attempts
```

### Audit & Logging

#### Audit Logging
```python
enable_audit_logging = True
log_level = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL

# Audit events include:
# - All security decisions
# - Authentication attempts
# - Authorization failures
# - Rate limit violations
# - Anomaly detections
```

## 🌍 Environment-Specific Configurations

### Development Environment

```python
development_config = SecurityConfig(
    validation_strictness="standard",
    enable_mfa=False,  # Disabled for easier development
    enable_rbac=True,
    enable_rate_limiting=True,
    default_rate_limit=200,  # Higher limit for testing
    enable_encryption=True,
    enable_ai_immune=True,
    anomaly_threshold=0.6,  # Lower threshold for testing
    learning_mode=True,  # Enable learning for AI training
    enable_audit_logging=True,
    log_level="DEBUG"  # Verbose logging for debugging
)
```

### Staging Environment

```python
staging_config = SecurityConfig(
    validation_strictness="standard",
    enable_mfa=True,
    enable_rbac=True,
    enable_rate_limiting=True,
    default_rate_limit=100,
    enable_encryption=True,
    enable_ai_immune=True,
    anomaly_threshold=0.7,
    learning_mode=False,
    enable_audit_logging=True,
    log_level="INFO"
)
```

### Production Environment

```python
production_config = SecurityConfig(
    validation_strictness="maximum",  # Highest security
    enable_mfa=True,
    enable_rbac=True,
    enable_rate_limiting=True,
    default_rate_limit=50,  # Conservative limit
    adaptive_limits=True,  # Enable adaptive limiting
    enable_encryption=True,
    enable_ai_immune=True,
    anomaly_threshold=0.9,  # High threshold for production
    learning_mode=False,
    enable_audit_logging=True,
    log_level="WARNING",  # Less verbose logging
    jwt_expiry_seconds=1800,  # Shorter token expiry (30 minutes)
    session_timeout_seconds=3600,  # Shorter session timeout (1 hour)
    key_rotation_interval=43200  # More frequent rotation (12 hours)
)
```

### High-Security Environment

```python
high_security_config = SecurityConfig(
    validation_strictness="maximum",
    enable_mfa=True,
    enable_rbac=True,
    enable_rate_limiting=True,
    default_rate_limit=25,  # Very conservative
    adaptive_limits=True,
    enable_encryption=True,
    enable_ai_immune=True,
    anomaly_threshold=0.95,  # Very high threshold
    learning_mode=False,
    enable_audit_logging=True,
    log_level="INFO",
    jwt_expiry_seconds=900,  # 15 minutes
    session_timeout_seconds=1800,  # 30 minutes
    key_rotation_interval=21600,  # 6 hours
    default_permissions=[]  # No default permissions
)
```

## 🎯 Use Case Specific Configurations

### Public API

```python
public_api_config = SecurityConfig(
    validation_strictness="maximum",
    enable_mfa=False,  # Not practical for public API
    enable_rbac=True,
    enable_rate_limiting=True,
    default_rate_limit=30,  # Conservative for public use
    adaptive_limits=True,
    enable_encryption=True,
    enable_ai_immune=True,
    anomaly_threshold=0.85,
    enable_audit_logging=True,
    log_level="INFO"
)
```

### Internal Enterprise

```python
enterprise_config = SecurityConfig(
    validation_strictness="standard",
    enable_mfa=True,
    enable_rbac=True,
    enable_rate_limiting=True,
    default_rate_limit=100,
    adaptive_limits=True,
    enable_encryption=True,
    enable_ai_immune=True,
    anomaly_threshold=0.7,
    enable_audit_logging=True,
    log_level="INFO"
)
```

### Research/Academic

```python
research_config = SecurityConfig(
    validation_strictness="standard",
    enable_mfa=False,
    enable_rbac=True,
    enable_rate_limiting=True,
    default_rate_limit=500,  # Higher for research workloads
    adaptive_limits=False,
    enable_encryption=True,
    enable_ai_immune=True,
    anomaly_threshold=0.5,  # Lower for experimental use
    learning_mode=True,  # Enable for research
    enable_audit_logging=True,
    log_level="DEBUG"
)
```

## 🔍 Security Monitoring & Alerting

### Metrics Configuration

```python
# Enable comprehensive metrics
metrics_config = {
    "enable_prometheus": True,
    "metrics_port": 9090,
    "enable_health_checks": True,
    "health_check_interval": 30,
    "enable_performance_monitoring": True
}
```

### Alert Thresholds

```python
alert_config = {
    "security_violations_per_minute": 10,
    "failed_authentications_per_minute": 5,
    "rate_limit_violations_per_minute": 20,
    "anomaly_detections_per_hour": 5,
    "system_error_rate_threshold": 0.01  # 1%
}
```

## 🧪 Testing Security Configuration

### Configuration Validation

```python
def validate_security_config(config: SecurityConfig) -> bool:
    """Validate security configuration"""
    
    # Check for insecure settings
    if config.validation_strictness == "minimal":
        print("WARNING: Minimal validation may not be secure enough")
    
    if not config.enable_encryption:
        print("ERROR: Encryption should be enabled in production")
        return False
    
    if config.default_rate_limit > 1000:
        print("WARNING: Very high rate limit may allow DoS attacks")
    
    if config.anomaly_threshold < 0.5:
        print("WARNING: Low anomaly threshold may cause false positives")
    
    return True

# Test configuration
if validate_security_config(production_config):
    print("Configuration is valid")
else:
    print("Configuration has security issues")
```

### Security Testing

```python
async def test_security_configuration():
    """Test security configuration with various scenarios"""
    
    security = SMCPSecurityFramework(production_config)
    
    # Test 1: Valid request
    valid_request = {
        "jsonrpc": "2.0",
        "method": "tools/list",
        "id": 1
    }
    
    context = {
        "user_id": "test_user",
        "ip_address": "192.168.1.100"
    }
    
    try:
        result = await security.process_request(valid_request, context)
        print("✅ Valid request processed successfully")
    except Exception as e:
        print(f"❌ Valid request failed: {e}")
    
    # Test 2: Malicious request
    malicious_request = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "shell",
            "arguments": {"command": "rm -rf /"}
        },
        "id": 2
    }
    
    try:
        result = await security.process_request(malicious_request, context)
        print("❌ Malicious request was not blocked!")
    except SecurityError:
        print("✅ Malicious request blocked successfully")
    
    # Test 3: Rate limiting
    for i in range(100):
        try:
            await security.process_request(valid_request, context)
        except RateLimitError:
            print(f"✅ Rate limiting activated after {i} requests")
            break
    else:
        print("❌ Rate limiting not working")

# Run security tests
await test_security_configuration()
```

## 📊 Performance Impact Analysis

### Configuration Performance Matrix

| Setting | Performance Impact | Security Benefit | Recommendation |
|---------|-------------------|------------------|----------------|
| `validation_strictness="minimal"` | Low (1-2ms) | Low | Development only |
| `validation_strictness="standard"` | Medium (3-5ms) | High | Most use cases |
| `validation_strictness="maximum"` | High (5-10ms) | Very High | High-security environments |
| `enable_mfa=True` | Medium (50-100ms) | Very High | Production recommended |
| `enable_ai_immune=True` | Medium (2-5ms) | High | Recommended |
| `anomaly_threshold=0.9` | Low | High | Production setting |
| `enable_encryption=True` | Low (1-2ms) | Very High | Always enable |

### Optimization Tips

```python
# Optimize for performance while maintaining security
optimized_config = SecurityConfig(
    validation_strictness="standard",  # Good balance
    enable_mfa=True,
    enable_rbac=True,
    enable_rate_limiting=True,
    default_rate_limit=100,
    adaptive_limits=True,  # Reduces false positives
    enable_encryption=True,
    enable_ai_immune=True,
    anomaly_threshold=0.8,  # Balanced threshold
    enable_audit_logging=True,
    log_level="INFO"  # Avoid DEBUG in production
)
```

## 🚨 Security Hardening Checklist

### Pre-Production Checklist

- [ ] `validation_strictness` set to "standard" or "maximum"
- [ ] `enable_mfa=True` for user-facing applications
- [ ] `enable_rbac=True` with proper role definitions
- [ ] `enable_rate_limiting=True` with appropriate limits
- [ ] `enable_encryption=True` always
- [ ] `enable_ai_immune=True` for anomaly detection
- [ ] `anomaly_threshold` >= 0.7 for production
- [ ] `enable_audit_logging=True` for compliance
- [ ] `log_level` set to "INFO" or "WARNING"
- [ ] JWT expiry <= 1 hour for sensitive applications
- [ ] Session timeout <= 2 hours
- [ ] Key rotation enabled (daily or more frequent)
- [ ] CORS properly configured (not "*" in production)
- [ ] API documentation disabled in production
- [ ] Security monitoring and alerting configured
- [ ] Regular security testing implemented

### Compliance Configurations

#### GDPR Compliance
```python
gdpr_config = SecurityConfig(
    validation_strictness="maximum",
    enable_mfa=True,
    enable_rbac=True,
    enable_rate_limiting=True,
    enable_encryption=True,
    enable_audit_logging=True,
    log_level="INFO",
    jwt_expiry_seconds=1800,  # 30 minutes
    key_rotation_interval=21600  # 6 hours
)
```

#### HIPAA Compliance
```python
hipaa_config = SecurityConfig(
    validation_strictness="maximum",
    enable_mfa=True,
    enable_rbac=True,
    enable_rate_limiting=True,
    default_rate_limit=25,
    enable_encryption=True,
    enable_ai_immune=True,
    anomaly_threshold=0.95,
    enable_audit_logging=True,
    log_level="INFO",
    jwt_expiry_seconds=900,  # 15 minutes
    session_timeout_seconds=1800,  # 30 minutes
    key_rotation_interval=10800  # 3 hours
)
```

---

**Remember**: Security is a balance between protection and usability. Choose configurations that meet your security requirements while maintaining acceptable performance and user experience.
