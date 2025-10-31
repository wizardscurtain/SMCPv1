# SMCPv1 Installation Guide

## Method 1: PyPI Package (Recommended)

### Basic Installation
```bash
pip install smcp-security
```

### With Optional Dependencies
```bash
# For advanced ML features
pip install smcp-security[ml]

# For all features
pip install smcp-security[all]
```

### Quick Start
```python
from smcp_security import SMCPSecurityFramework, SecurityConfig

# Basic setup with defaults
security = SMCPSecurityFramework()

# Process MCP requests
result = await security.process_request(request_data, user_context)
```

## Method 2: Hosted API Service

### No Installation Required
Use our hosted security service without any local installation:

```python
import requests

response = requests.post(
    'https://smcp-security-api.onrender.com/validate',
    json={
        'request': your_mcp_request,
        'context': user_context,
        'config': security_config  # optional
    },
    headers={'Authorization': 'Bearer YOUR_API_KEY'}
)

secure_result = response.json()
```

### Get API Key
1. Visit https://smcp-security.dev/signup
2. Create free account (1000 requests/month)
3. Copy your API key
4. Set environment variable: `export SMCP_API_KEY=your_key`

## Method 3: Docker Container

### Pull and Run
```bash
# Pull the image
docker pull smcp-security:latest

# Run with default config
docker run -p 8080:8080 smcp-security:latest

# Run with custom config
docker run -p 8080:8080 -v ./config.json:/app/config.json smcp-security:latest
```

### Docker Compose
```yaml
version: '3.8'
services:
  smcp-security:
    image: smcp-security:latest
    ports:
      - "8080:8080"
    environment:
      - SMCP_LOG_LEVEL=INFO
      - SMCP_RATE_LIMIT=100
    volumes:
      - ./logs:/app/logs
```

## Method 4: One-Command Setup

### Linux/macOS
```bash
curl -sSL https://get.smcp-security.dev | bash
```

### Windows (PowerShell)
```powershell
iwr -useb https://get.smcp-security.dev/install.ps1 | iex
```

### What it does:
1. Detects your environment (Python version, OS)
2. Installs smcp-security package
3. Creates sample configuration
4. Runs basic security test
5. Provides next steps

## Method 5: Source Installation

### For Development
```bash
# Clone repository
git clone https://github.com/wizardscurtain/SMCPv1.git
cd SMCPv1/code

# Install in development mode
pip install -e .

# Or using poetry
poetry install
```

## Verification

### Test Installation
```python
# Test basic functionality
from smcp_security import SMCPSecurityFramework

security = SMCPSecurityFramework()
print(f"SMCPv1 Security Framework v{security.version} ready!")

# Run built-in security test
security.run_self_test()
```

### Check System Requirements
```bash
# Check if your system meets requirements
smcp-security --check-system

# View configuration
smcp-security --show-config

# Run diagnostics
smcp-security --diagnose
```

## Configuration

### Environment Variables
```bash
# Security settings
export SMCP_VALIDATION_STRICTNESS=standard  # minimal, standard, maximum
export SMCP_ENABLE_MFA=true
export SMCP_RATE_LIMIT=100
export SMCP_LOG_LEVEL=INFO

# Hosted API settings
export SMCP_API_KEY=your_api_key
export SMCP_API_URL=https://smcp-security-api.onrender.com
```

### Configuration File
```json
{
  "security": {
    "validation_strictness": "standard",
    "enable_mfa": true,
    "enable_rbac": true,
    "enable_rate_limiting": true,
    "default_rate_limit": 100,
    "anomaly_threshold": 0.7
  },
  "logging": {
    "level": "INFO",
    "file": "/var/log/smcp-security.log"
  }
}
```

## Troubleshooting

### Common Issues

1. **Import Error**: Ensure Python 3.11+ is installed
2. **Permission Denied**: Run with appropriate permissions
3. **Port Conflicts**: Change default port in configuration
4. **Memory Issues**: Reduce ML features if running on limited resources

### Get Help
```bash
# View help
smcp-security --help

# Check logs
smcp-security --logs

# Report issue
smcp-security --report-issue
```

### Support Channels
- GitHub Issues: https://github.com/wizardscurtain/SMCPv1/issues
- Documentation: https://smcp-security.dev/docs
- Community Discord: https://discord.gg/smcp-security
- Email: support@smcp-security.dev
