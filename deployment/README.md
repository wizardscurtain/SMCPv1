# SMCPv1 Easy Deployment Guide

This directory contains multiple deployment options for the SMCPv1 security framework, designed to make integration as simple as possible for developers.

## Available Deployment Options

### 1. PyPI Package Installation (Recommended)
```bash
pip install smcp-security
```

### 2. Hosted Security-as-a-Service API
```bash
curl -X POST https://smcp-security-api.onrender.com/validate \
  -H "Content-Type: application/json" \
  -d '{"request": {...}, "context": {...}}'
```

### 3. Docker Container
```bash
docker run -p 8080:8080 smcp-security:latest
```

### 4. MCP Middleware Integration
```python
from smcp_security import SMCPMiddleware

# Add to your MCP server
app.add_middleware(SMCPMiddleware)
```

### 5. One-Command Setup Script
```bash
curl -sSL https://get.smcp-security.dev | bash
```

## Quick Start Examples

See the `examples/` directory for integration examples with popular MCP implementations:

- FastAPI MCP Server
- Express.js MCP Server  
- Python MCP Client
- Node.js MCP Client
- Claude Desktop Integration
- VS Code Extension Integration

## Documentation

- [Installation Guide](installation.md)
- [Integration Examples](examples/)
- [API Reference](api-reference.md)
- [Security Configuration](security-config.md)
- [Troubleshooting](troubleshooting.md)

## Support

- GitHub Issues: https://github.com/wizardscurtain/SMCPv1/issues
- Documentation: https://smcp-security.dev
- Community: https://discord.gg/smcp-security
