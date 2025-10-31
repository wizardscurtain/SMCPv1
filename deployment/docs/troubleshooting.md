# SMCP Security Framework - Troubleshooting Guide

## 🔍 Common Issues and Solutions

### Installation Issues

#### Python Version Error
```
ERROR: Python 3.11+ required
```

**Solution:**
```bash
# Check Python version
python3 --version

# Install Python 3.11+ (Ubuntu/Debian)
sudo apt update
sudo apt install python3.11 python3.11-pip

# Install Python 3.11+ (macOS with Homebrew)
brew install python@3.11

# Install Python 3.11+ (Windows)
# Download from https://python.org/downloads/
```

#### Package Installation Fails
```
ERROR: Could not install packages due to an EnvironmentError
```

**Solution:**
```bash
# Use virtual environment
python3 -m venv smcp-env
source smcp-env/bin/activate  # Linux/macOS
# or
smcp-env\Scripts\activate  # Windows

# Upgrade pip
pip install --upgrade pip

# Install with user flag if needed
pip install --user smcp-security
```

#### Import Error
```python
ImportError: No module named 'smcp_security'
```

**Solution:**
```python
# Check installation
import sys
print(sys.path)

# Verify package is installed
pip list | grep smcp-security

# Reinstall if necessary
pip uninstall smcp-security
pip install smcp-security
```

### Configuration Issues

#### Invalid Configuration Error
```
ValueError: Invalid validation strictness: invalid_value
```

**Solution:**
```python
# Valid strictness values
valid_strictness = ["minimal", "standard", "maximum"]

# Correct configuration
config = SecurityConfig(
    validation_strictness="standard"  # Use valid value
)
```

#### Environment Variable Not Recognized
```bash
# Check environment variables
env | grep SMCP

# Set correctly
export SMCP_VALIDATION_STRICTNESS=standard
export SMCP_LOG_LEVEL=INFO

# Verify
echo $SMCP_VALIDATION_STRICTNESS
```

#### Configuration File Not Found
```
FileNotFoundError: Configuration file not found
```

**Solution:**
```bash
# Create default configuration
smcp-security --init --config ./smcp-config.json

# Or specify absolute path
smcp-security --config /full/path/to/config.json
```

### Runtime Issues

#### Security Validation Fails
```
SecurityError: Input validation failed
```

**Diagnosis:**
```python
# Enable debug logging
config = SecurityConfig(log_level="DEBUG")
security = SMCPSecurityFramework(config)

# Check what's being validated
result = await security.process_request(request, context)
```

**Common Causes:**
1. **Malformed JSON-RPC request**
   ```python
   # Incorrect
   request = {"method": "tools/list"}  # Missing jsonrpc and id
   
   # Correct
   request = {
       "jsonrpc": "2.0",
       "method": "tools/list",
       "id": 1
   }
   ```

2. **Invalid method name**
   ```python
   # Check allowed methods
   allowed_methods = ["tools/list", "tools/call", "resources/list"]
   ```

3. **Missing required context**
   ```python
   # Ensure context has required fields
   context = {
       "user_id": "user123",
       "ip_address": "192.168.1.100"
   }
   ```

#### Authentication Errors
```
AuthenticationError: Invalid JWT token
```

**Solution:**
```python
# Check token format
token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."

# Verify token is not expired
import jwt
try:
    payload = jwt.decode(token, verify=False)
    print(f"Token expires at: {payload.get('exp')}")
except jwt.InvalidTokenError as e:
    print(f"Token error: {e}")

# Generate new token
auth = JWTAuthenticator(auth_config)
token = auth.generate_token(
    user_id="user123",
    roles=["user"],
    permissions=["mcp:read"]
)
```

#### Authorization Errors
```
AuthorizationError: Permission denied
```

**Solution:**
```python
# Check user permissions
rbac = RBACManager()
user_permissions = rbac.get_user_permissions("user123")
print(f"User permissions: {user_permissions}")

# Grant required permission
rbac.assign_role("user123", "power_user")

# Or add specific permission
rbac.grant_permission("user123", "mcp:execute:specific_tool")
```

#### Rate Limiting Issues
```
RateLimitError: Rate limit exceeded
```

**Solution:**
```python
# Check current rate limit status
rate_limiter = AdaptiveRateLimiter()
status = rate_limiter.get_user_status("user123")
print(f"Requests remaining: {status['remaining']}")
print(f"Reset time: {status['reset_time']}")

# Adjust rate limits
rate_limiter.set_user_limit("user123", 200)  # Increase limit

# Or implement backoff
import time
time.sleep(60)  # Wait for rate limit reset
```

### Performance Issues

#### Slow Response Times
```
Processing time > 1000ms
```

**Diagnosis:**
```python
# Enable performance monitoring
metrics = security.get_security_metrics()
print(f"Average processing time: {metrics['avg_processing_time_ms']}ms")

# Check individual components
print(f"Validation time: {metrics['validation_time_ms']}ms")
print(f"Authentication time: {metrics['auth_time_ms']}ms")
print(f"AI immune time: {metrics['ai_immune_time_ms']}ms")
```

**Optimization:**
```python
# Reduce validation strictness
config = SecurityConfig(
    validation_strictness="standard"  # Instead of "maximum"
)

# Disable expensive features if not needed
config = SecurityConfig(
    enable_ai_immune=False,  # Saves 2-5ms per request
    enable_mfa=False,       # Saves 50-100ms per request
    log_level="WARNING"     # Reduces logging overhead
)

# Use caching for repeated validations
from functools import lru_cache

@lru_cache(maxsize=1000)
def cached_validation(request_hash):
    return security.validate_request_structure(request)
```

#### High Memory Usage
```
Memory usage > 500MB
```

**Solution:**
```python
# Monitor memory usage
import psutil
process = psutil.Process()
print(f"Memory usage: {process.memory_info().rss / 1024 / 1024:.2f} MB")

# Reduce AI model size
config = SecurityConfig(
    enable_ai_immune=False  # Saves ~100MB
)

# Clear caches periodically
security.clear_caches()

# Limit audit log retention
config = SecurityConfig(
    audit_log_max_size=1000  # Limit log entries
)
```

### Network Issues

#### Hosted API Connection Fails
```
ConnectionError: Failed to connect to SMCP API
```

**Solution:**
```python
# Check API status
import requests

try:
    response = requests.get('https://smcp-security-api.onrender.com/health')
    print(f"API Status: {response.json()}")
except requests.ConnectionError:
    print("API is unreachable")

# Use retry logic
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

session = requests.Session()
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504]
)
adapter = HTTPAdapter(max_retries=retry_strategy)
session.mount("https://", adapter)

# Test with retry
response = session.post('https://smcp-security-api.onrender.com/validate', json=data)
```

#### API Key Issues
```
HTTPError: 401 Unauthorized
```

**Solution:**
```python
# Verify API key format
api_key = "demo_key_123"  # Should be valid format

# Check headers
headers = {
    'Authorization': f'Bearer {api_key}',
    'Content-Type': 'application/json'
}

# Test authentication
response = requests.get(
    'https://smcp-security-api.onrender.com/config',
    headers=headers
)
print(f"Auth test: {response.status_code}")
```

### Docker Issues

#### Container Won't Start
```
docker: Error response from daemon: container failed to start
```

**Solution:**
```bash
# Check logs
docker logs smcp-security

# Run with debug
docker run -it --rm smcp-security:latest /bin/bash

# Check port conflicts
docker ps -a
netstat -tulpn | grep 8080

# Use different port
docker run -p 8081:8080 smcp-security:latest
```

#### Permission Denied in Container
```
PermissionError: [Errno 13] Permission denied
```

**Solution:**
```dockerfile
# In Dockerfile, ensure proper user setup
RUN useradd -m -u 1000 smcp
USER smcp

# Or run with user flag
docker run --user 1000:1000 smcp-security:latest
```

### Integration Issues

#### FastAPI Middleware Not Working
```python
# Middleware not processing requests
```

**Solution:**
```python
# Ensure correct middleware order
from fastapi import FastAPI
from smcp_security import SMCPMiddleware

app = FastAPI()

# Add SMCP middleware BEFORE other middleware
app.add_middleware(SMCPMiddleware)
app.add_middleware(CORSMiddleware, allow_origins=["*"])

# Check middleware is active
@app.get("/debug")
async def debug_middleware(request: Request):
    return {"middleware_stack": [m.__class__.__name__ for m in app.user_middleware]}
```

#### Node.js Client Issues
```javascript
// Module not found error
```

**Solution:**
```bash
# Install dependencies
npm install axios

# Check Node.js version
node --version  # Should be 16+

# Use ES modules or CommonJS consistently
// package.json
{
  "type": "module"  // For ES modules
}

// Or use require() for CommonJS
const { SMCPSecurityClient } = require('./smcp-client');
```

## 🛠️ Debugging Tools

### Enable Debug Mode

```python
# Maximum debugging
config = SecurityConfig(
    log_level="DEBUG",
    enable_audit_logging=True
)

security = SMCPSecurityFramework(config)

# Process with full logging
result = await security.process_request(request, context)
```

### System Diagnostics

```bash
# Run built-in diagnostics
smcp-security --diagnose

# Check system requirements
smcp-security --check-system

# Validate configuration
smcp-security --validate-config

# Test connectivity
smcp-security --test-connection
```

### Performance Profiling

```python
import cProfile
import pstats

# Profile security processing
def profile_security():
    profiler = cProfile.Profile()
    profiler.enable()
    
    # Your security code here
    result = await security.process_request(request, context)
    
    profiler.disable()
    stats = pstats.Stats(profiler)
    stats.sort_stats('cumulative')
    stats.print_stats(10)  # Top 10 functions

profile_security()
```

### Memory Profiling

```python
from memory_profiler import profile

@profile
async def memory_test():
    security = SMCPSecurityFramework()
    
    # Process multiple requests
    for i in range(100):
        await security.process_request(request, context)

# Run with: python -m memory_profiler script.py
```

## 📊 Monitoring and Alerting

### Health Checks

```python
# Implement health check endpoint
@app.get("/health")
async def health_check():
    try:
        # Test security framework
        test_request = {"jsonrpc": "2.0", "method": "ping", "id": 1}
        test_context = {"user_id": "health_check"}
        
        await security.process_request(test_request, test_context)
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": security.version
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }
```

### Metrics Collection

```python
from prometheus_client import Counter, Histogram, Gauge

# Define metrics
REQUESTS_TOTAL = Counter('smcp_requests_total', 'Total requests', ['status'])
REQUEST_DURATION = Histogram('smcp_request_duration_seconds', 'Request duration')
SECURITY_VIOLATIONS = Counter('smcp_violations_total', 'Security violations', ['type'])
ACTIVE_SESSIONS = Gauge('smcp_active_sessions', 'Active sessions')

# Instrument your code
class MonitoredSMCPSecurity:
    async def process_request(self, request, context):
        with REQUEST_DURATION.time():
            try:
                result = await self.security.process_request(request, context)
                REQUESTS_TOTAL.labels(status='success').inc()
                return result
            except SecurityError as e:
                REQUESTS_TOTAL.labels(status='blocked').inc()
                SECURITY_VIOLATIONS.labels(type=type(e).__name__).inc()
                raise
```

### Log Analysis

```bash
# Analyze security logs
grep "SECURITY_VIOLATION" /var/log/smcp-security.log | tail -10

# Count violations by type
grep "ValidationError" /var/log/smcp-security.log | wc -l

# Find suspicious patterns
grep -E "(rm -rf|DROP TABLE|<script)" /var/log/smcp-security.log

# Monitor rate limiting
grep "RateLimitError" /var/log/smcp-security.log | \
  awk '{print $1, $2}' | uniq -c
```

## 🆘 Getting Help

### Before Asking for Help

1. **Check the logs**
   ```bash
   smcp-security --logs
   tail -f /var/log/smcp-security.log
   ```

2. **Run diagnostics**
   ```bash
   smcp-security --diagnose
   smcp-security --check-system
   ```

3. **Test with minimal configuration**
   ```python
   config = SecurityConfig()  # Use all defaults
   security = SMCPSecurityFramework(config)
   ```

4. **Verify your request format**
   ```python
   # Ensure proper JSON-RPC 2.0 format
   request = {
       "jsonrpc": "2.0",
       "method": "tools/list",
       "id": 1
   }
   ```

### Support Channels

1. **GitHub Issues**: https://github.com/wizardscurtain/SMCPv1/issues
   - Include error messages, logs, and configuration
   - Provide minimal reproduction case

2. **Community Discord**: https://discord.gg/smcp-security
   - Real-time help from community
   - Share code snippets and get quick feedback

3. **Documentation**: https://smcp-security.dev
   - Comprehensive guides and examples
   - API reference and tutorials

4. **Email Support**: support@smcp-security.dev
   - For enterprise customers
   - Security-related inquiries

### Issue Report Template

```markdown
## Issue Description
[Brief description of the problem]

## Environment
- OS: [e.g., Ubuntu 22.04]
- Python version: [e.g., 3.11.2]
- SMCP version: [e.g., 1.0.0]
- Installation method: [pip/docker/source]

## Configuration
```python
# Your SecurityConfig here
```

## Error Message
```
[Full error message and stack trace]
```

## Steps to Reproduce
1. [First step]
2. [Second step]
3. [Third step]

## Expected Behavior
[What you expected to happen]

## Actual Behavior
[What actually happened]

## Additional Context
[Any other relevant information]
```

---

**Remember**: Most issues can be resolved by checking logs, verifying configuration, and ensuring proper request format. When in doubt, start with the simplest possible configuration and gradually add complexity.
