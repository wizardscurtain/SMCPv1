/**
 * Custom exception classes for SMCP Security
 */

export class SecurityError extends Error {
  public readonly code: string;
  public readonly statusCode: number;
  
  constructor(message: string, code: string = 'SECURITY_ERROR', statusCode: number = 403) {
    super(message);
    this.name = 'SecurityError';
    this.code = code;
    this.statusCode = statusCode;
    
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, SecurityError);
    }
  }
}

export class ValidationError extends SecurityError {
  public readonly validationErrors: string[];
  
  constructor(message: string, validationErrors: string[] = []) {
    super(message, 'VALIDATION_ERROR', 400);
    this.name = 'ValidationError';
    this.validationErrors = validationErrors;
  }
}

export class AuthenticationError extends SecurityError {
  constructor(message: string = 'Authentication failed') {
    super(message, 'AUTHENTICATION_ERROR', 401);
    this.name = 'AuthenticationError';
  }
}

export class AuthorizationError extends SecurityError {
  public readonly requiredPermission?: string;
  
  constructor(message: string = 'Access denied', requiredPermission?: string) {
    super(message, 'AUTHORIZATION_ERROR', 403);
    this.name = 'AuthorizationError';
    this.requiredPermission = requiredPermission;
  }
}

export class RateLimitError extends SecurityError {
  public readonly retryAfter: number;
  
  constructor(message: string = 'Rate limit exceeded', retryAfter: number = 60) {
    super(message, 'RATE_LIMIT_ERROR', 429);
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
  }
}

export class CryptographicError extends SecurityError {
  constructor(message: string = 'Cryptographic operation failed') {
    super(message, 'CRYPTOGRAPHIC_ERROR', 500);
    this.name = 'CryptographicError';
  }
}

export class AIImmuneError extends SecurityError {
  public readonly threatScore: number;
  
  constructor(message: string = 'AI immune system detected threat', threatScore: number = 1.0) {
    super(message, 'AI_IMMUNE_ERROR', 403);
    this.name = 'AIImmuneError';
    this.threatScore = threatScore;
  }
}
