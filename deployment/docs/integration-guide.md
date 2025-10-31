# SMCP Security Framework - Integration Guide

## 🎯 Choose Your Integration Method

### 1. PyPI Package Integration (Recommended)

**Best for**: Python applications, direct integration, maximum control

#### Installation
```bash
pip install smcp-security
```

#### Basic Integration
```python
from smcp_security import SMCPSecurityFramework, SecurityConfig

# Initialize security framework
config = SecurityConfig(
    validation_strictness="standard",
    enable_rate_limiting=True,
    default_rate_limit=100
)
security = SMCPSecurityFramework(config)

# Process MCP requests
async def handle_mcp_request(request, context):
    result = await security.process_request(request, context)
    return result
```

#### FastAPI Integration
```python
from fastapi import FastAPI
from smcp_security import SMCPMiddleware

app = FastAPI()

# Add SMCP security middleware
app.add_middleware(SMCPMiddleware, 
    config=SecurityConfig(validation_strictness="maximum"),
    mcp_paths=["/mcp", "/api/mcp"]
)

@app.post("/mcp")
async def mcp_endpoint(request: dict):
    # Request is automatically secured by middleware
    return {"result": "success"}
```

### 2. Hosted API Service

**Best for**: Any language, microservices, quick setup, no maintenance

#### API Endpoint
```
https://smcp-security-api.onrender.com
```

#### Authentication
```bash
# Get free API key (1000 requests/month)
curl -X POST https://smcp-security-api.onrender.com/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email": "your@email.com", "name": "Your Name"}'
```

#### Usage Examples

**Python**
```python
import requests

def validate_mcp_request(request, context, api_key):
    response = requests.post(
        'https://smcp-security-api.onrender.com/validate',
        json={'request': request, 'context': context},
        headers={'Authorization': f'Bearer {api_key}'}
    )
    return response.json()
```

**Node.js**
```javascript
const axios = require('axios');

async function validateMCPRequest(request, context, apiKey) {
    const response = await axios.post(
        'https://smcp-security-api.onrender.com/validate',
        { request, context },
        { headers: { Authorization: `Bearer ${apiKey}` } }
    );
    return response.data;
}
```

**cURL**
```bash
curl -X POST https://smcp-security-api.onrender.com/validate \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "request": {
      "jsonrpc": "2.0",
      "method": "tools/call",
      "params": {"name": "echo", "arguments": {"message": "hello"}}
    },
    "context": {
      "user_id": "user123",
      "ip_address": "192.168.1.100"
    }
  }'
```

### 3. Docker Container

**Best for**: Containerized environments, Kubernetes, self-hosted

#### Quick Start
```bash
# Pull and run
docker run -p 8080:8080 smcp-security:latest

# With custom config
docker run -p 8080:8080 -v ./config.json:/app/config.json smcp-security:latest
```

#### Docker Compose
```yaml
version: '3.8'
services:
  smcp-security:
    image: smcp-security:latest
    ports:
      - "8080:8080"
    environment:
      - SMCP_VALIDATION_STRICTNESS=standard
      - SMCP_RATE_LIMIT=100
    volumes:
      - ./logs:/app/logs
```

#### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: smcp-security
spec:
  replicas: 2
  selector:
    matchLabels:
      app: smcp-security
  template:
    metadata:
      labels:
        app: smcp-security
    spec:
      containers:
      - name: smcp-security
        image: smcp-security:latest
        ports:
        - containerPort: 8080
        env:
        - name: SMCP_VALIDATION_STRICTNESS
          value: "maximum"
        - name: SMCP_RATE_LIMIT
          value: "200"
---
apiVersion: v1
kind: Service
metadata:
  name: smcp-security-service
spec:
  selector:
    app: smcp-security
  ports:
  - port: 80
    targetPort: 8080
  type: LoadBalancer
```

### 4. Middleware Integration

**Best for**: Existing applications, gradual adoption, minimal changes

#### Express.js Middleware
```javascript
const express = require('express');
const { SMCPSecurityClient } = require('smcp-security-client');

const app = express();
const security = new SMCPSecurityClient({
    apiUrl: 'https://smcp-security-api.onrender.com',
    apiKey: process.env.SMCP_API_KEY
});

// SMCP Security Middleware
app.use('/mcp', async (req, res, next) => {
    try {
        const context = {
            userId: req.user?.id || 'anonymous',
            ipAddress: req.ip,
            userAgent: req.get('User-Agent')
        };
        
        const result = await security.validateRequest(req.body, context);
        
        if (!result.success) {
            return res.status(403).json({ error: result.error });
        }
        
        req.body = result.request; // Use validated request
        req.securityMetadata = result.security_metadata;
        next();
    } catch (error) {
        res.status(500).json({ error: 'Security validation failed' });
    }
});
```

#### Django Middleware
```python
import json
from django.http import JsonResponse
from smcp_security import SMCPSecurityFramework, SecurityConfig

class SMCPSecurityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.security = SMCPSecurityFramework(SecurityConfig())
    
    def __call__(self, request):
        # Only process MCP endpoints
        if request.path.startswith('/mcp/'):
            try:
                body = json.loads(request.body)
                context = {
                    'user_id': getattr(request.user, 'id', 'anonymous'),
                    'ip_address': request.META.get('REMOTE_ADDR'),
                    'user_agent': request.META.get('HTTP_USER_AGENT')
                }
                
                result = await self.security.process_request(body, context)
                request._body = json.dumps(result['request']).encode()
                
            except Exception as e:
                return JsonResponse({'error': str(e)}, status=403)
        
        return self.get_response(request)
```

## 🔧 Platform-Specific Integrations

### Claude Desktop

**Configuration** (`~/.config/claude-desktop/config.json`):
```json
{
  "mcpServers": {
    "secure-server": {
      "command": "smcp-security",
      "args": ["--server", "--config", "/path/to/security.json"]
    }
  }
}
```

### VS Code Extension

**Extension Integration**:
```typescript
import { SMCPSecurityClient } from 'smcp-security-client';

class SecureMCPProvider {
    private security: SMCPSecurityClient;
    
    constructor() {
        this.security = new SMCPSecurityClient({
            apiUrl: 'https://smcp-security-api.onrender.com',
            apiKey: vscode.workspace.getConfiguration().get('smcp.apiKey')
        });
    }
    
    async executeCommand(command: string, args: any[]): Promise<any> {
        const mcpRequest = {
            jsonrpc: '2.0',
            method: 'tools/call',
            params: { name: command, arguments: args }
        };
        
        const context = {
            userId: 'vscode-user',
            workspace: vscode.workspace.name
        };
        
        const result = await this.security.validateRequest(mcpRequest, context);
        
        if (!result.success) {
            throw new Error(`Security validation failed: ${result.error}`);
        }
        
        // Execute validated command
        return this.executeValidatedCommand(result.request);
    }
}
```

### Jupyter Notebook

**Magic Command Integration**:
```python
from IPython.core.magic import Magics, magics_class, line_magic
from smcp_security import SMCPSecurityFramework

@magics_class
class SMCPMagics(Magics):
    def __init__(self, shell):
        super().__init__(shell)
        self.security = SMCPSecurityFramework()
    
    @line_magic
    def smcp_secure(self, line):
        """Secure MCP command execution"""
        import json
        
        try:
            request = json.loads(line)
            context = {'user_id': 'jupyter-user', 'notebook': True}
            
            result = await self.security.process_request(request, context)
            return result
            
        except Exception as e:
            print(f"Security validation failed: {e}")
            return None

# Register the magic
get_ipython().register_magic_function(SMCPMagics)
```

## 🚀 Deployment Patterns

### Microservices Architecture

```yaml
# API Gateway with SMCP Security
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: mcp-security-gateway
spec:
  http:
  - match:
    - uri:
        prefix: "/mcp"
    route:
    - destination:
        host: smcp-security-service
        port:
          number: 80
      weight: 100
    fault:
      abort:
        percentage:
          value: 0.1
        httpStatus: 403
```

### Serverless Functions

**AWS Lambda**:
```python
import json
from smcp_security import SMCPSecurityFramework

security = SMCPSecurityFramework()

def lambda_handler(event, context):
    try:
        request_body = json.loads(event['body'])
        user_context = {
            'user_id': event['requestContext']['authorizer']['user_id'],
            'ip_address': event['requestContext']['identity']['sourceIp']
        }
        
        result = await security.process_request(request_body, user_context)
        
        return {
            'statusCode': 200,
            'body': json.dumps(result)
        }
        
    except Exception as e:
        return {
            'statusCode': 403,
            'body': json.dumps({'error': str(e)})
        }
```

**Vercel Function**:
```javascript
import { SMCPSecurityClient } from 'smcp-security-client';

const security = new SMCPSecurityClient({
    apiUrl: process.env.SMCP_API_URL,
    apiKey: process.env.SMCP_API_KEY
});

export default async function handler(req, res) {
    try {
        const context = {
            userId: req.headers['x-user-id'] || 'anonymous',
            ipAddress: req.headers['x-forwarded-for'] || req.connection.remoteAddress
        };
        
        const result = await security.validateRequest(req.body, context);
        
        if (!result.success) {
            return res.status(403).json({ error: result.error });
        }
        
        res.status(200).json(result);
        
    } catch (error) {
        res.status(500).json({ error: 'Security validation failed' });
    }
}
```

## 📊 Monitoring and Observability

### Metrics Collection

```python
from prometheus_client import Counter, Histogram, start_http_server

# Define metrics
REQUESTS_TOTAL = Counter('smcp_requests_total', 'Total SMCP requests', ['status'])
REQUEST_DURATION = Histogram('smcp_request_duration_seconds', 'Request duration')
SECURITY_VIOLATIONS = Counter('smcp_security_violations_total', 'Security violations', ['type'])

# Instrument your SMCP integration
class MonitoredSMCPSecurity:
    def __init__(self):
        self.security = SMCPSecurityFramework()
    
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

# Start metrics server
start_http_server(8000)
```

### Logging Integration

```python
import structlog
from smcp_security import SMCPSecurityFramework

logger = structlog.get_logger()

class LoggingSMCPSecurity:
    def __init__(self):
        self.security = SMCPSecurityFramework()
    
    async def process_request(self, request, context):
        logger.info("Processing SMCP request", 
                   user_id=context.get('user_id'),
                   method=request.get('method'))
        
        try:
            result = await self.security.process_request(request, context)
            
            logger.info("SMCP request processed successfully",
                       security_level=result['security_metadata']['security_level'],
                       processing_time=result['security_metadata']['processing_time_ms'])
            
            return result
            
        except SecurityError as e:
            logger.warning("SMCP security violation",
                          error=str(e),
                          error_type=type(e).__name__,
                          user_id=context.get('user_id'))
            raise
```

## 🔒 Security Best Practices

### Production Configuration

```python
# Production security configuration
production_config = SecurityConfig(
    validation_strictness="maximum",
    enable_mfa=True,
    enable_rbac=True,
    enable_rate_limiting=True,
    default_rate_limit=50,  # Lower for production
    enable_encryption=True,
    enable_ai_immune=True,
    anomaly_threshold=0.9,  # Higher threshold for production
    enable_audit_logging=True,
    log_level="WARNING"  # Less verbose in production
)
```

### Environment-Specific Settings

```bash
# Development
export SMCP_VALIDATION_STRICTNESS=standard
export SMCP_ENABLE_MFA=false
export SMCP_LOG_LEVEL=DEBUG

# Staging
export SMCP_VALIDATION_STRICTNESS=standard
export SMCP_ENABLE_MFA=true
export SMCP_LOG_LEVEL=INFO

# Production
export SMCP_VALIDATION_STRICTNESS=maximum
export SMCP_ENABLE_MFA=true
export SMCP_LOG_LEVEL=WARNING
export SMCP_RATE_LIMIT=25
```

## 🆘 Troubleshooting

### Common Issues

1. **Import Error**: Ensure Python 3.11+ and proper installation
2. **Permission Denied**: Check RBAC configuration and user roles
3. **Rate Limiting**: Adjust rate limits or implement backoff
4. **Performance**: Tune security settings for your use case

### Debug Mode

```python
# Enable debug mode
config = SecurityConfig(log_level="DEBUG")
security = SMCPSecurityFramework(config)

# Check system status
status = security.get_security_metrics()
print(f"Security status: {status}")

# Run diagnostics
diagnostics = security.run_diagnostics()
print(f"Diagnostics: {diagnostics}")
```

### Support Channels

- **GitHub Issues**: https://github.com/wizardscurtain/SMCPv1/issues
- **Documentation**: https://smcp-security.dev
- **Community Discord**: https://discord.gg/smcp-security
- **Email Support**: support@smcp-security.dev

---

**Ready to secure your MCP implementation? Choose your integration method and get started!**
