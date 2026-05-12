# SMCP Security - VS Code Extension

[![Visual Studio Marketplace Version](https://img.shields.io/visual-studio-marketplace/v/smcp-security.smcp-security)](https://marketplace.visualstudio.com/items?itemName=smcp-security.smcp-security)
[![Visual Studio Marketplace Downloads](https://img.shields.io/visual-studio-marketplace/d/smcp-security.smcp-security)](https://marketplace.visualstudio.com/items?itemName=smcp-security.smcp-security)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Secure Model Context Protocol (SMCP) v1 - VS Code extension for seamless integration of SMCP security into your development workflow.

## Features

- 🔐 **One-Click Integration**: Initialize SMCP security in any MCP project
- 📝 **Smart Snippets**: Code snippets for all supported languages (Python, Node.js, Go, Rust, Java, C#)
- ⚙️ **Configuration UI**: Visual configuration editor for security policies
- 📊 **Real-time Validation**: Automatic security validation as you code
- 🛠️ **Request Testing**: Built-in MCP request tester with security validation
- 📊 **Audit Viewer**: View and analyze security audit logs
- 🔑 **Key Generation**: Generate secure keys and certificates
- 🎯 **Multi-Language Support**: Works with Python, Node.js, Go, Rust, Java, and C#

## Quick Start

### Installation

1. Open VS Code
2. Go to Extensions (Ctrl+Shift+X)
3. Search for "SMCP Security"
4. Click Install

### Initialize a Project

1. Open your MCP project in VS Code
2. Right-click on the project folder in Explorer
3. Select "Initialize SMCP Security"
4. Choose your preferred language and configuration
5. The extension will generate all necessary security files

### Use Code Snippets

Type any of these prefixes and press Tab:

- `smcp-init` - Initialize SMCP security framework
- `smcp-validate` - Add request validation
- `smcp-auth` - Add authentication
- `smcp-rbac` - Add role-based access control
- `smcp-rate-limit` - Add rate limiting
- `smcp-crypto` - Add encryption
- `smcp-audit` - Add audit logging
- `smcp-ai-immune` - Add AI immune system
- `smcp-middleware` - Add framework middleware

## Features in Detail

### 1. Project Initialization

The extension can automatically set up SMCP security for your project:

- **Language Detection**: Automatically detects your project language
- **Dependency Installation**: Adds SMCP security packages to your project
- **Configuration Generation**: Creates security configuration files
- **Example Code**: Generates example implementation code
- **Documentation**: Creates README with security setup instructions

### 2. Smart Code Snippets

#### Python Snippets

```python
# smcp-init
from smcp_security import SMCPSecurityFramework, SecurityConfig

security = SMCPSecurityFramework(SecurityConfig(
    enable_mfa=True,
    validation_strictness="maximum",
    enable_ai_immune=True,
    anomaly_threshold=0.8
))

# smcp-validate
try:
    validated_request = security.validate_request(request)
except SecurityError as e:
    logger.error(f"Security validation failed: {e}")
    return error_response(e)
```

#### TypeScript Snippets

```typescript
// smcp-init
import { SMCPSecurityFramework, SecurityConfig } from 'smcp-security';

const security = new SMCPSecurityFramework({
  enableMFA: true,
  validationStrictness: 'maximum',
  enableAIImmune: true,
  anomalyThreshold: 0.8
});

// smcp-middleware
app.use(createExpressMiddleware(security));
```

#### Go Snippets

```go
// smcp-init
import "github.com/wizardscurtain/SMCPv1/libraries/go/smcp"

security, err := smcp.NewSecurityFramework(&smcp.SecurityConfig{
    EnableMFA:            true,
    ValidationStrictness: smcp.ValidationMaximum,
    EnableAIImmune:       true,
    AnomalyThreshold:     0.8,
})

// smcp-middleware
r.Use(middleware.SMCPSecurity(security))
```

#### Rust Snippets

```rust
// smcp-init
use smcp_security::{SecurityFramework, SecurityConfig, ValidationStrictness};

let security = SecurityFramework::new(SecurityConfig {
    enable_mfa: true,
    validation_strictness: ValidationStrictness::Maximum,
    enable_ai_immune: true,
    anomaly_threshold: 0.8,
    ..Default::default()
}).await?;

// smcp-middleware
let app = Router::new()
    .layer(SMCPSecurityLayer::new(security));
```

### 3. Configuration Editor

Visual configuration editor with:

- **Security Policies**: Configure validation, authentication, authorization
- **Rate Limiting**: Set up adaptive rate limiting rules
- **AI Immune System**: Configure threat detection parameters
- **Audit Settings**: Configure logging and monitoring
- **Cryptographic Settings**: Configure encryption and key management
- **Real-time Validation**: Validate configuration as you edit

### 4. Request Testing Tool

Built-in MCP request tester:

- **Request Builder**: Visual request builder with validation
- **Security Testing**: Test requests against security policies
- **Response Analysis**: Analyze responses and security metrics
- **Batch Testing**: Run multiple test scenarios
- **Performance Metrics**: Monitor request performance and security overhead

### 5. Audit Log Viewer

Comprehensive audit log viewer:

- **Real-time Logs**: View logs in real-time as they're generated
- **Filtering**: Filter by user, action, result, time range
- **Search**: Full-text search across all log entries
- **Export**: Export logs in various formats (JSON, CSV, PDF)
- **Visualization**: Charts and graphs for security metrics

### 6. Security Validation

Real-time security validation:

- **Code Analysis**: Analyze code for security vulnerabilities
- **Configuration Validation**: Validate security configurations
- **Dependency Scanning**: Scan dependencies for known vulnerabilities
- **Best Practices**: Suggest security best practices
- **Compliance Checking**: Check against security standards

## Commands

### Available Commands

- **SMCP: Initialize SMCP Security** - Set up SMCP security in your project
- **SMCP: Generate Security Configuration** - Generate security configuration files
- **SMCP: Test MCP Request** - Test MCP requests with security validation
- **SMCP: View Audit Logs** - Open the audit log viewer
- **SMCP: Validate Security Configuration** - Validate current security setup
- **SMCP: Generate Security Keys** - Generate cryptographic keys and certificates

### Keyboard Shortcuts

- `Ctrl+Shift+S, I` - Initialize SMCP Security
- `Ctrl+Shift+S, T` - Test MCP Request
- `Ctrl+Shift+S, A` - View Audit Logs
- `Ctrl+Shift+S, V` - Validate Security Configuration

## Configuration

### Extension Settings

Configure the extension through VS Code settings:

```json
{
  "smcp.enableAutoValidation": true,
  "smcp.validationStrictness": "standard",
  "smcp.enableMFA": true,
  "smcp.defaultRateLimit": 100,
  "smcp.enableAIImmune": true,
  "smcp.anomalyThreshold": 0.7,
  "smcp.serverUrl": "http://localhost:8000",
  "smcp.logLevel": "INFO"
}
```

### Project Configuration

The extension generates project-specific configuration files:

- `.smcp/config.json` - Main security configuration
- `.smcp/policies.json` - Security policies
- `.smcp/keys/` - Cryptographic keys (gitignored)
- `.smcp/audit.log` - Audit logs

## Language Support

### Python
- Package: `smcp-security`
- Frameworks: FastAPI, Flask, Django
- Features: Full async support, type hints

### Node.js/TypeScript
- Package: `smcp-security`
- Frameworks: Express, Fastify, Koa
- Features: Full TypeScript support, ESM/CommonJS

### Go
- Module: `github.com/wizardscurtain/SMCPv1/libraries/go`
- Frameworks: Gorilla Mux, Gin, Echo
- Features: Idiomatic Go, high performance

### Rust
- Crate: `smcp-security`
- Frameworks: Axum, Warp, Actix-web
- Features: Zero-cost abstractions, memory safety

### Java
- Package: `com.smcp.security`
- Frameworks: Spring Boot, Quarkus
- Features: Annotation-based configuration

### C#
- Package: `SMCP.Security`
- Frameworks: ASP.NET Core, Minimal APIs
- Features: Dependency injection, async/await

## Examples

### Initialize a Python FastAPI Project

1. Create a new Python project
2. Run "SMCP: Initialize SMCP Security"
3. Select "Python" and "FastAPI"
4. The extension generates:

```python
# main.py
from fastapi import FastAPI
from smcp_security import SMCPSecurityFramework
from smcp_security.middleware import SMCPSecurityMiddleware

app = FastAPI()
security = SMCPSecurityFramework()
app.add_middleware(SMCPSecurityMiddleware, security_framework=security)

@app.post("/mcp/request")
async def handle_mcp_request(request: dict):
    # Request is automatically secured
    return {"result": "success"}
```

### Initialize a Node.js Express Project

1. Create a new Node.js project
2. Run "SMCP: Initialize SMCP Security"
3. Select "Node.js" and "Express"
4. The extension generates:

```typescript
// server.ts
import express from 'express';
import { SMCPSecurityFramework, createExpressMiddleware } from 'smcp-security';

const app = express();
const security = new SMCPSecurityFramework();

app.use(createExpressMiddleware(security));

app.post('/mcp/request', (req, res) => {
  // Request is automatically secured
  res.json({ result: 'success' });
});
```

## Troubleshooting

### Common Issues

1. **Extension not activating**
   - Ensure you have a supported language file open
   - Check the Output panel for error messages

2. **Snippets not working**
   - Verify the language mode is correct
   - Check if IntelliSense is enabled

3. **Configuration validation errors**
   - Check the Problems panel for detailed error messages
   - Ensure all required fields are filled

4. **Request testing fails**
   - Verify the server URL is correct
   - Check if the server is running
   - Ensure proper authentication credentials

### Getting Help

- 📖 [Documentation](https://github.com/wizardscurtain/SMCPv1/tree/main/libraries/vscode-extension)
- 💬 [Discussions](https://github.com/wizardscurtain/SMCPv1/discussions)
- 🐛 [Issues](https://github.com/wizardscurtain/SMCPv1/issues)
- 📧 [Email Support](mailto:support@smcp.dev)

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## Security

For security issues, please email security@smcp.dev instead of using the issue tracker.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Changelog

### 1.0.0

- Initial release
- Multi-language support (Python, Node.js, Go, Rust, Java, C#)
- Smart code snippets
- Configuration editor
- Request testing tool
- Audit log viewer
- Real-time security validation
- One-click project initialization
