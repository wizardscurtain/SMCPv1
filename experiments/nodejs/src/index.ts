/**
 * SMCP Security - Node.js/TypeScript Library
 * 
 * Secure Model Context Protocol (SMCP) v1 - Production-ready security framework
 * for Model Context Protocol implementations in Node.js and TypeScript.
 */

// Core exports
export { SMCPSecurityFramework } from './core/SMCPSecurityFramework';
export { SecurityConfig } from './core/SecurityConfig';

// Security components
export { InputValidator } from './validation/InputValidator';
export { CommandInjectionPrevention } from './validation/CommandInjectionPrevention';
export { JWTAuthenticator } from './auth/JWTAuthenticator';
export { MFAManager } from './auth/MFAManager';
export { RBACManager } from './auth/RBACManager';
export { AdaptiveRateLimiter } from './ratelimit/AdaptiveRateLimiter';
export { DoSProtection } from './ratelimit/DoSProtection';
export { SMCPCrypto } from './crypto/SMCPCrypto';
export { Argon2KeyDerivation } from './crypto/Argon2KeyDerivation';
export { SMCPAuditLogger } from './audit/SMCPAuditLogger';
export { AIImmuneSystem } from './ai/AIImmuneSystem';
export { ThreatClassifier } from './ai/ThreatClassifier';

// Middleware
export { createExpressMiddleware } from './middleware/ExpressMiddleware';
export { createFastifyPlugin } from './middleware/FastifyMiddleware';

// Types
export type {
  MCPRequest,
  MCPResponse,
  AuthCredentials,
  UserContext,
  SecurityMetrics,
  ThreatAnalysis,
  ValidationResult,
  AuditEvent,
  RateLimitOptions,
  CryptoOptions
} from './types';

// Exceptions
export {
  SecurityError,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  RateLimitError,
  CryptographicError
} from './exceptions';

// Version
export const VERSION = '1.0.0';
