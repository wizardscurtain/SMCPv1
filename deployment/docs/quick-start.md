# SMCP Security Framework - Quick Start Guide

## 🚀 Get Started in 30 Seconds

### Option 1: One-Command Installation (Recommended)
```bash
curl -sSL https://get.smcp-security.dev | bash
```

### Option 2: PyPI Package
```bash
pip install smcp-security
```

### Option 3: Hosted API (No Installation)
```bash
curl -X POST https://smcp-security-api.onrender.com/validate \
  -H "Content-Type: application/json" \
  -d '{"request": {...}, "context": {...}}'
```

## 📋 Basic Usage Examples

### Python Integration
```python
from smcp_security import SMCPSecurityFramework

# Initialize with defaults
security = SMCPSecurityFramework()

# Secure your MCP request
result = await security.process_request(mcp_request, user_context)
```

### FastAPI Middleware
```python
from smcp_security import SMCPMiddleware

app.add_middleware(SMCPMiddleware)  # That's it!
```

### Node.js Client
```javascript
const { SMCPSecurityClient } = require('smcp-security-client');

const client = new SMCPSecurityClient({
  apiUrl: 'https://smcp-security-api.onrender.com',
  apiKey: 'demo_key_123'
});

const result = await client.validateRequest(mcpRequest, context);
```

### CLI Usage
```bash
# Start security server
smcp-security --server

# Run security scan
smcp-security --scan

# Generate security report
smcp-security --report
```

## 🔧 Configuration

### Environment Variables
```bash
export SMCP_VALIDATION_STRICTNESS=standard  # minimal, standard, maximum
export SMCP_RATE_LIMIT=100
export SMCP_LOG_LEVEL=INFO
```

### Configuration File
```json
{
  "security": {
    "validation_strictness": "standard",
    "enable_rbac": true,
    "enable_rate_limiting": true,
    "default_rate_limit": 100
  }
}
```

## 🧪 Test Your Setup

```bash
# Check system requirements
smcp-security --check-system

# Run self-test
smcp-security --self-test

# Test with demo request
curl -X POST http://localhost:8080/validate \
  -H "Content-Type: application/json" \
  -d '{
    "request": {
      "jsonrpc": "2.0",
      "method": "tools/list",
      "id": 1
    },
    "context": {
      "user_id": "demo_user",
      "ip_address": "127.0.0.1"
    }
  }'
```

## 📚 Next Steps

1. **Read the [Integration Guide](integration-guide.md)** for your platform
2. **Check [Security Configuration](security-config.md)** for production settings
3. **Browse [Examples](../examples/)** for your use case
4. **Join our [Community](https://discord.gg/smcp-security)** for support

## 🆘 Need Help?

- **Documentation**: https://smcp-security.dev
- **GitHub Issues**: https://github.com/wizardscurtain/SMCPv1/issues
- **Discord**: https://discord.gg/smcp-security
- **Email**: support@smcp-security.dev

---

**Made with ❤️ for the AI security community**
