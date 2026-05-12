/**
 * Security configuration class
 */

import { SecurityConfig as ISecurityConfig } from '../types';

export class SecurityConfig implements ISecurityConfig {
  // Input validation settings
  public enableInputValidation: boolean;
  public validationStrictness: 'minimal' | 'standard' | 'maximum';
  
  // Authentication settings
  public enableMFA: boolean;
  public jwtExpirySeconds: number;
  public sessionTimeoutSeconds: number;
  
  // Authorization settings
  public enableRBAC: boolean;
  public defaultPermissions: string[];
  
  // Rate limiting settings
  public enableRateLimiting: boolean;
  public defaultRateLimit: number;
  public adaptiveLimits: boolean;
  
  // Cryptographic settings
  public enableEncryption: boolean;
  public keyRotationInterval: number;
  
  // AI immune system settings
  public enableAIImmune: boolean;
  public anomalyThreshold: number;
  public learningMode: boolean;
  
  // Audit settings
  public enableAuditLogging: boolean;
  public logLevel: 'DEBUG' | 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL';

  constructor(config: Partial<ISecurityConfig> = {}) {
    // Set defaults
    this.enableInputValidation = config.enableInputValidation ?? true;
    this.validationStrictness = config.validationStrictness ?? 'standard';
    
    this.enableMFA = config.enableMFA ?? true;
    this.jwtExpirySeconds = config.jwtExpirySeconds ?? 3600;
    this.sessionTimeoutSeconds = config.sessionTimeoutSeconds ?? 7200;
    
    this.enableRBAC = config.enableRBAC ?? true;
    this.defaultPermissions = config.defaultPermissions ?? ['read'];
    
    this.enableRateLimiting = config.enableRateLimiting ?? true;
    this.defaultRateLimit = config.defaultRateLimit ?? 100;
    this.adaptiveLimits = config.adaptiveLimits ?? true;
    
    this.enableEncryption = config.enableEncryption ?? true;
    this.keyRotationInterval = config.keyRotationInterval ?? 86400;
    
    this.enableAIImmune = config.enableAIImmune ?? true;
    this.anomalyThreshold = config.anomalyThreshold ?? 0.7;
    this.learningMode = config.learningMode ?? false;
    
    this.enableAuditLogging = config.enableAuditLogging ?? true;
    this.logLevel = config.logLevel ?? 'INFO';

    // Validate configuration
    this.validateConfig();
  }

  private validateConfig(): void {
    // Validate validation strictness
    const validStrictness = ['minimal', 'standard', 'maximum'];
    if (!validStrictness.includes(this.validationStrictness)) {
      throw new Error(`Invalid validation strictness: ${this.validationStrictness}`);
    }

    // Validate log level
    const validLogLevels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'];
    if (!validLogLevels.includes(this.logLevel)) {
      throw new Error(`Invalid log level: ${this.logLevel}`);
    }

    // Validate rate limit
    if (this.defaultRateLimit <= 0) {
      throw new Error('Rate limit must be positive');
    }

    // Validate anomaly threshold
    if (this.anomalyThreshold < 0.0 || this.anomalyThreshold > 1.0) {
      throw new Error('Anomaly threshold must be between 0.0 and 1.0');
    }

    // Validate JWT expiry
    if (this.jwtExpirySeconds <= 0) {
      throw new Error('JWT expiry must be positive');
    }

    // Validate session timeout
    if (this.sessionTimeoutSeconds <= 0) {
      throw new Error('Session timeout must be positive');
    }

    // Validate key rotation interval
    if (this.keyRotationInterval <= 0) {
      throw new Error('Key rotation interval must be positive');
    }
  }

  /**
   * Create a configuration for development environment
   */
  static development(): SecurityConfig {
    return new SecurityConfig({
      enableMFA: false,
      validationStrictness: 'minimal',
      enableAIImmune: false,
      anomalyThreshold: 0.9,
      defaultRateLimit: 1000,
      learningMode: true,
      logLevel: 'DEBUG'
    });
  }

  /**
   * Create a configuration for production environment
   */
  static production(): SecurityConfig {
    return new SecurityConfig({
      enableMFA: true,
      validationStrictness: 'maximum',
      enableAIImmune: true,
      anomalyThreshold: 0.7,
      defaultRateLimit: 100,
      learningMode: false,
      logLevel: 'INFO'
    });
  }

  /**
   * Create a configuration for testing environment
   */
  static testing(): SecurityConfig {
    return new SecurityConfig({
      enableMFA: false,
      validationStrictness: 'standard',
      enableAIImmune: false,
      enableRateLimiting: false,
      enableAuditLogging: false,
      logLevel: 'ERROR'
    });
  }
}
