# SMCP Security - Node.js/TypeScript Library

[![npm version](https://badge.fury.io/js/smcp-security.svg)](https://badge.fury.io/js/smcp-security)
[![Node.js Support](https://img.shields.io/node/v/smcp-security.svg)](https://www.npmjs.com/package/smcp-security)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Downloads](https://img.shields.io/npm/dm/smcp-security.svg)](https://www.npmjs.com/package/smcp-security)

Secure Model Context Protocol (SMCP) v1 - A production-ready security framework for Model Context Protocol implementations in Node.js and TypeScript.

## Features

- 🔐 **Multi-layered Security**: Input validation, authentication, authorization, and encryption
- 🛡️ **AI-Immune System**: Machine learning-based threat detection and prevention
- 🚀 **High Performance**: Optimized for production workloads with minimal overhead
- 📊 **Comprehensive Auditing**: Detailed security event logging and monitoring
- 🔄 **Rate Limiting**: Adaptive rate limiting with DoS protection
- 🎯 **Easy Integration**: Middleware for Express.js, Fastify, and other frameworks
- 📝 **TypeScript First**: Full TypeScript support with comprehensive type definitions

## Quick Start

### Installation

```bash
# Using npm
npm install smcp-security

# Using yarn
yarn add smcp-security

# Using pnpm
pnpm add smcp-security
```

### Basic Usage

```typescript
import { SMCPSecurityFramework, SecurityConfig } from 'smcp-security';

// Initialize with default configuration
const security = new SMCPSecurityFramework();

// Validate and secure an MCP request
const mcpRequest = {
  jsonrpc: '2.0',
  id: 'req-123',
  method: 'tools/list',
  params: {}
};

try {
  // Validate the request
  const validatedRequest = await security.validateRequest(mcpRequest);
  
  // Process with security checks
  const result = await security.processSecureRequest({
    request: validatedRequest,
    userId: 'user-123',
    sessionToken: 'jwt-token-here'
  });
  
  console.log('Request processed securely:', result);
} catch (error) {
  console.error('Security violation:', error.message);
}
```

### Express.js Integration

```typescript
import express from 'express';
import { SMCPSecurityFramework, createExpressMiddleware } from 'smcp-security';

const app = express();
const security = new SMCPSecurityFramework();

// Add security middleware
app.use(createExpressMiddleware(security));

app.post('/mcp/request', async (req, res) => {
  // Request is automatically validated and secured
  const userContext = req.smcpSecurity?.userContext;
  const result = await processMCPRequest(req.body, userContext);
  res.json(result);
});

app.listen(3000, () => {
  console.log('Secure MCP server running on port 3000');
});
```

### Fastify Integration

```typescript
import Fastify from 'fastify';
import { SMCPSecurityFramework, createFastifyPlugin } from 'smcp-security';

const fastify = Fastify({ logger: true });
const security = new SMCPSecurityFramework();

// Register security plugin
fastify.register(createFastifyPlugin(security));

fastify.post('/mcp/request', async (request, reply) => {
  // Request is automatically validated and secured
  const userContext = request.smcpSecurity?.userContext;
  const result = await processMCPRequest(request.body, userContext);
  return result;
});

fastify.listen({ port: 3000 }, (err) => {
  if (err) throw err;
  console.log('Secure MCP server running on port 3000');
});
```

### Custom Configuration

```typescript
import { SMCPSecurityFramework, SecurityConfig } from 'smcp-security';

// Custom security configuration
const config: SecurityConfig = {
  enableMFA: true,
  validationStrictness: 'maximum',
  enableAIImmune: true,
  anomalyThreshold: 0.8,
  defaultRateLimit: 50, // requests per minute
  enableAuditLogging: true,
  jwtExpirySeconds: 3600,
  sessionTimeoutSeconds: 7200
};

const security = new SMCPSecurityFramework(config);
```

## Advanced Features

### AI-Immune System

```typescript
import { AIImmuneSystem, ThreatClassifier } from 'smcp-security';

// Initialize AI immune system
const aiImmune = new AIImmuneSystem();

// Analyze potential threats
const threatScore = await aiImmune.analyzeRequest(requestData);
if (threatScore > 0.7) {
  console.log('High-risk request detected!');
}

// Train on new attack patterns
await aiImmune.learnFromAttack(attackData);
```

### Rate Limiting

```typescript
import { AdaptiveRateLimiter } from 'smcp-security';

// Create adaptive rate limiter
const rateLimiter = new AdaptiveRateLimiter({
  baseLimit: 100, // requests per minute
  burstLimit: 200,
  adaptive: true
});

// Check rate limit
const isAllowed = await rateLimiter.isAllowed('user-123');
if (!isAllowed) {
  throw new Error('Rate limit exceeded');
}
```

### Cryptographic Operations

```typescript
import { SMCPCrypto } from 'smcp-security';

// Initialize crypto module
const crypto = new SMCPCrypto();

// Encrypt sensitive data
const encryptedData = await crypto.encrypt('sensitive information');

// Decrypt data
const decryptedData = await crypto.decrypt(encryptedData);

// Generate secure tokens
const token = crypto.generateSecureToken(32);
```

### Authentication & Authorization

```typescript
import { JWTAuthenticator, MFAManager, RBACManager } from 'smcp-security';

// JWT Authentication
const jwtAuth = new JWTAuthenticator({
  secret: 'your-secret-key',
  expiresIn: '1h'
});

const token = await jwtAuth.generateToken({ userId: 'user-123', role: 'admin' });
const payload = await jwtAuth.verifyToken(token);

// Multi-Factor Authentication
const mfa = new MFAManager();
const secret = mfa.generateSecret('user-123');
const qrCode = await mfa.generateQRCode(secret, 'user@example.com');
const isValid = mfa.verifyToken(secret, '123456');

// Role-Based Access Control
const rbac = new RBACManager();
rbac.addRole('admin', ['read', 'write', 'delete']);
rbac.addRole('user', ['read']);
rbac.assignRole('user-123', 'admin');

const hasPermission = rbac.hasPermission('user-123', 'write');
```

## API Reference

### Core Classes

#### SMCPSecurityFramework

```typescript
class SMCPSecurityFramework {
  constructor(config?: SecurityConfig);
  
  async validateRequest(request: MCPRequest): Promise<MCPRequest>;
  async authenticateUser(credentials: AuthCredentials): Promise<string>;
  async authorizeAction(userId: string, action: string): Promise<boolean>;
  async processSecureRequest(options: SecureRequestOptions): Promise<any>;
  getSecurityMetrics(): SecurityMetrics;
}
```

#### SecurityConfig

```typescript
interface SecurityConfig {
  enableInputValidation?: boolean;
  validationStrictness?: 'minimal' | 'standard' | 'maximum';
  enableMFA?: boolean;
  enableRBAC?: boolean;
  enableRateLimiting?: boolean;
  enableAIImmune?: boolean;
  enableAuditLogging?: boolean;
  jwtExpirySeconds?: number;
  sessionTimeoutSeconds?: number;
  defaultRateLimit?: number;
  anomalyThreshold?: number;
}
```

### Middleware

#### Express Middleware

```typescript
import { createExpressMiddleware } from 'smcp-security';

const middleware = createExpressMiddleware(security, {
  skipPaths: ['/health', '/metrics'],
  enableCORS: true
});

app.use(middleware);
```

#### Fastify Plugin

```typescript
import { createFastifyPlugin } from 'smcp-security';

const plugin = createFastifyPlugin(security, {
  skipRoutes: ['/health', '/metrics'],
  enableCORS: true
});

fastify.register(plugin);
```

## Examples

See the [examples](https://github.com/wizardscurtain/SMCPv1/tree/main/examples/nodejs) directory for complete implementation examples:

- [Basic Usage](examples/basic-usage.ts)
- [Express.js Integration](examples/express-example.ts)
- [Fastify Integration](examples/fastify-example.ts)
- [Custom Security Policies](examples/custom-policies.ts)
- [AI Immune System](examples/ai-immune-example.ts)
- [Microservices Architecture](examples/microservices-example.ts)

## Testing

```bash
# Run tests
npm test

# Run with coverage
npm run test:coverage

# Run in watch mode
npm run test:watch

# Lint code
npm run lint

# Format code
npm run format
```

## TypeScript Support

This library is written in TypeScript and provides comprehensive type definitions:

```typescript
import type {
  SMCPSecurityFramework,
  SecurityConfig,
  MCPRequest,
  MCPResponse,
  AuthCredentials,
  UserContext,
  SecurityMetrics,
  ThreatAnalysis
} from 'smcp-security';
```

## Performance

- **Minimal Overhead**: < 1ms latency impact
- **High Throughput**: Handles 10,000+ requests/second
- **Memory Efficient**: < 50MB memory footprint
- **Scalable**: Horizontal scaling support
- **Async/Await**: Full async support for non-blocking operations

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
