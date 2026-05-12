/**
 * Type definitions for SMCP Security
 */

// Core MCP types
export interface MCPRequest {
  jsonrpc: string;
  id: string;
  method: string;
  params?: Record<string, any>;
}

export interface MCPResponse {
  jsonrpc: string;
  id: string;
  result?: any;
  error?: {
    code: number;
    message: string;
    data?: any;
  };
}

// Authentication types
export interface AuthCredentials {
  username: string;
  password: string;
  mfaCode?: string;
}

export interface UserContext {
  userId: string;
  username: string;
  role: string;
  permissions: string[];
  sessionId: string;
  lastActivity: Date;
}

// Security configuration
export interface SecurityConfig {
  enableInputValidation?: boolean;
  validationStrictness?: 'minimal' | 'standard' | 'maximum';
  enableMFA?: boolean;
  jwtExpirySeconds?: number;
  sessionTimeoutSeconds?: number;
  enableRBAC?: boolean;
  defaultPermissions?: string[];
  enableRateLimiting?: boolean;
  defaultRateLimit?: number;
  adaptiveLimits?: boolean;
  enableEncryption?: boolean;
  keyRotationInterval?: number;
  enableAIImmune?: boolean;
  anomalyThreshold?: number;
  learningMode?: boolean;
  enableAuditLogging?: boolean;
  logLevel?: 'DEBUG' | 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL';
}

// Validation types
export interface ValidationResult {
  isValid: boolean;
  errors: string[];
  sanitizedData?: any;
  riskScore: number;
}

// Security metrics
export interface SecurityMetrics {
  totalRequests: number;
  blockedRequests: number;
  threatsDetected: number;
  averageResponseTime: number;
  activeUsers: number;
  rateLimitHits: number;
  authenticationFailures: number;
  lastThreatDetected?: Date;
}

// Threat analysis
export interface ThreatAnalysis {
  riskScore: number;
  threatType: string;
  confidence: number;
  indicators: string[];
  recommendedAction: 'allow' | 'block' | 'monitor';
}

// Audit event
export interface AuditEvent {
  id: string;
  timestamp: Date;
  userId?: string;
  action: string;
  resource: string;
  result: 'success' | 'failure' | 'blocked';
  riskScore: number;
  metadata: Record<string, any>;
}

// Rate limiting
export interface RateLimitOptions {
  baseLimit: number;
  burstLimit?: number;
  windowMs?: number;
  adaptive?: boolean;
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
}

// Cryptography
export interface CryptoOptions {
  algorithm?: string;
  keySize?: number;
  iterations?: number;
  saltLength?: number;
}

// Secure request processing
export interface SecureRequestOptions {
  request: MCPRequest;
  userId: string;
  sessionToken: string;
  clientIP?: string;
  userAgent?: string;
}

// MFA types
export interface MFASecret {
  secret: string;
  qrCode: string;
  backupCodes: string[];
}

// RBAC types
export interface Role {
  name: string;
  permissions: string[];
  description?: string;
}

export interface Permission {
  name: string;
  resource: string;
  action: string;
  description?: string;
}

// AI Immune System types
export interface AIModel {
  name: string;
  version: string;
  accuracy: number;
  lastTrained: Date;
}

export interface LearningData {
  features: number[];
  label: 'benign' | 'malicious';
  confidence: number;
  timestamp: Date;
}
