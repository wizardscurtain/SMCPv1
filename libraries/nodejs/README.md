[![npm version](https://img.shields.io/npm/v/smcp-security.svg)](https://www.npmjs.com/package/smcp-security)
[![Node.js >=16](https://img.shields.io/node/v/smcp-security.svg)](https://www.npmjs.com/package/smcp-security)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)

# smcp-security

SMCPv1 security middleware for Model Context Protocol servers.

## Installation

```bash
npm install smcp-security
```

## Usage

```typescript
import { SMCPSecurityFramework, SecurityConfig } from 'smcp-security';

const framework = new SMCPSecurityFramework(SecurityConfig.production());
const result = await framework.processRequest(mcpRequest, { token: bearerToken });
```

## API Reference

See [./docs/api-reference.md](./docs/api-reference.md) for full documentation.

Full source and additional examples are available on [GitHub](https://github.com/wizardscurtain/SMCPv1).

## License

MIT
