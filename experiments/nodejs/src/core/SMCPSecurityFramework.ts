/**
 * Main SMCP Security Framework implementation
 */

import { SecurityConfig } from './SecurityConfig';
import { InputValidator } from '../validation/InputValidator';
import { JWTAuthenticator } from '../auth/JWTAuthenticator';
import { MFAManager } from '../auth/MFAManager';
import { RBACManager } from '../auth/RBACManager';
import { AdaptiveRateLimiter } from '../ratelimit/AdaptiveRateLimiter';
import { SMCPCrypto } from '../crypto/SMCPCrypto';
import { SMCPAuditLogger } from '../audit/SMCPAuditLogger';
import { AIImmuneSystem } from '../ai/AIImmuneSystem';
import {
  MCPRequest,
  MCPResponse,
  AuthCredentials,
  UserContext,
  SecurityMetrics,
  SecureRequestOptions,
  ValidationResult
} from '../types';
import {
  SecurityError,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  RateLimitError
} from '../exceptions';

export class SMCPSecurityFramework {
  private config: SecurityConfig;
  private inputValidator: InputValidator;
  private jwtAuth: JWTAuthenticator;
  private mfaManager: MFAManager;
  private rbacManager: RBACManager;
  private rateLimiter: AdaptiveRateLimiter;
  private crypto: SMCPCrypto;
  private auditLogger: SMCPAuditLogger;
  private aiImmune: AIImmuneSystem;
  private metrics: SecurityMetrics;

  constructor(config?: Partial<SecurityConfig>) {
    this.config = new SecurityConfig(config);
    this.initializeComponents();
    this.initializeMetrics();
  }

  private initializeComponents(): void {
    // Initialize input validator
    if (this.config.enableInputValidation) {
      this.inputValidator = new InputValidator({
        strictness: this.config.validationStrictness
      });
    }

    // Initialize JWT authenticator
    this.jwtAuth = new JWTAuthenticator({
      secret: process.env.JWT_SECRET || 'default-secret',
      expiresIn: this.config.jwtExpirySeconds
    });

    // Initialize MFA manager
    if (this.config.enableMFA) {
      this.mfaManager = new MFAManager();
    }

    // Initialize RBAC manager
    if (this.config.enableRBAC) {
      this.rbacManager = new RBACManager();
      this.setupDefaultRoles();
    }

    // Initialize rate limiter
    if (this.config.enableRateLimiting) {
      this.rateLimiter = new AdaptiveRateLimiter({
        baseLimit: this.config.defaultRateLimit,
        adaptive: this.config.adaptiveLimits
      });
    }

    // Initialize crypto
    if (this.config.enableEncryption) {
      this.crypto = new SMCPCrypto();
    }

    // Initialize audit logger
    if (this.config.enableAuditLogging) {
      this.auditLogger = new SMCPAuditLogger({
        logLevel: this.config.logLevel
      });
    }

    // Initialize AI immune system
    if (this.config.enableAIImmune) {
      this.aiImmune = new AIImmuneSystem({
        anomalyThreshold: this.config.anomalyThreshold,
        learningMode: this.config.learningMode
      });
    }
  }

  private initializeMetrics(): void {
    this.metrics = {
      totalRequests: 0,
      blockedRequests: 0,
      threatsDetected: 0,
      averageResponseTime: 0,
      activeUsers: 0,
      rateLimitHits: 0,
      authenticationFailures: 0
    };
  }

  private setupDefaultRoles(): void {
    if (!this.rbacManager) return;

    // Setup default roles
    this.rbacManager.addRole('admin', [
      'read', 'write', 'delete', 'admin',
      'tools:*', 'resources:*', 'prompts:*'
    ]);
    
    this.rbacManager.addRole('user', [
      'read', 'tools:list', 'tools:call',
      'resources:list', 'resources:read',
      'prompts:list', 'prompts:get'
    ]);
    
    this.rbacManager.addRole('readonly', [
      'read', 'tools:list', 'resources:list', 'prompts:list'
    ]);
  }

  /**
   * Validate an MCP request
   */
  async validateRequest(request: MCPRequest): Promise<MCPRequest> {
    const startTime = Date.now();
    
    try {
      this.metrics.totalRequests++;

      // Input validation
      if (this.config.enableInputValidation && this.inputValidator) {
        const validationResult = await this.inputValidator.validate(request);
        
        if (!validationResult.isValid) {
          this.metrics.blockedRequests++;
          throw new ValidationError(
            'Request validation failed',
            validationResult.errors
          );
        }

        // Use sanitized data
        request = validationResult.sanitizedData || request;
      }

      // AI immune system check
      if (this.config.enableAIImmune && this.aiImmune) {
        const threatAnalysis = await this.aiImmune.analyzeRequest(request);
        
        if (threatAnalysis.riskScore > this.config.anomalyThreshold) {
          this.metrics.threatsDetected++;
          this.metrics.blockedRequests++;
          
          if (this.auditLogger) {
            await this.auditLogger.logThreat({
              request,
              threatAnalysis,
              action: 'blocked'
            });
          }
          
          throw new SecurityError(
            `High-risk request detected: ${threatAnalysis.threatType}`,
            'THREAT_DETECTED'
          );
        }
      }

      // Update metrics
      const processingTime = Date.now() - startTime;
      this.updateAverageResponseTime(processingTime);

      return request;
    } catch (error) {
      if (this.auditLogger) {
        await this.auditLogger.logError({
          error: error.message,
          request,
          processingTime: Date.now() - startTime
        });
      }
      throw error;
    }
  }

  /**
   * Authenticate user credentials
   */
  async authenticateUser(credentials: AuthCredentials): Promise<string> {
    try {
      // Basic credential validation
      if (!credentials.username || !credentials.password) {
        this.metrics.authenticationFailures++;
        throw new AuthenticationError('Username and password required');
      }

      // In a real implementation, verify credentials against database
      const isValidUser = await this.verifyCredentials(credentials);
      
      if (!isValidUser) {
        this.metrics.authenticationFailures++;
        throw new AuthenticationError('Invalid credentials');
      }

      // MFA verification if enabled
      if (this.config.enableMFA && this.mfaManager) {
        if (!credentials.mfaCode) {
          throw new AuthenticationError('MFA code required');
        }
        
        const mfaValid = await this.mfaManager.verifyToken(
          credentials.username,
          credentials.mfaCode
        );
        
        if (!mfaValid) {
          this.metrics.authenticationFailures++;
          throw new AuthenticationError('Invalid MFA code');
        }
      }

      // Generate JWT token
      const userContext = await this.getUserContext(credentials.username);
      const token = await this.jwtAuth.generateToken(userContext);

      if (this.auditLogger) {
        await this.auditLogger.logAuthentication({
          userId: credentials.username,
          success: true,
          mfaUsed: !!credentials.mfaCode
        });
      }

      return token;
    } catch (error) {
      if (this.auditLogger) {
        await this.auditLogger.logAuthentication({
          userId: credentials.username,
          success: false,
          error: error.message
        });
      }
      throw error;
    }
  }

  /**
   * Authorize user action
   */
  async authorizeAction(userId: string, action: string): Promise<boolean> {
    if (!this.config.enableRBAC || !this.rbacManager) {
      return true; // Authorization disabled
    }

    try {
      const hasPermission = await this.rbacManager.hasPermission(userId, action);
      
      if (this.auditLogger) {
        await this.auditLogger.logAuthorization({
          userId,
          action,
          granted: hasPermission
        });
      }

      return hasPermission;
    } catch (error) {
      if (this.auditLogger) {
        await this.auditLogger.logError({
          error: error.message,
          context: { userId, action }
        });
      }
      return false;
    }
  }

  /**
   * Process a secure request with full security checks
   */
  async processSecureRequest(options: SecureRequestOptions): Promise<any> {
    const { request, userId, sessionToken, clientIP, userAgent } = options;
    const startTime = Date.now();

    try {
      // Validate JWT token
      const tokenPayload = await this.jwtAuth.verifyToken(sessionToken);
      
      if (tokenPayload.userId !== userId) {
        throw new AuthenticationError('Token user mismatch');
      }

      // Rate limiting check
      if (this.config.enableRateLimiting && this.rateLimiter) {
        const isAllowed = await this.rateLimiter.isAllowed(userId);
        
        if (!isAllowed) {
          this.metrics.rateLimitHits++;
          throw new RateLimitError('Rate limit exceeded');
        }
      }

      // Validate the request
      const validatedRequest = await this.validateRequest(request);

      // Authorization check
      const action = `${request.method}`;
      const isAuthorized = await this.authorizeAction(userId, action);
      
      if (!isAuthorized) {
        throw new AuthorizationError(`Access denied for action: ${action}`);
      }

      // Process the request (this would be implemented by the MCP server)
      const result = await this.processRequest(validatedRequest, tokenPayload);

      // Log successful request
      if (this.auditLogger) {
        await this.auditLogger.logRequest({
          userId,
          request: validatedRequest,
          result,
          processingTime: Date.now() - startTime,
          clientIP,
          userAgent
        });
      }

      return result;
    } catch (error) {
      if (this.auditLogger) {
        await this.auditLogger.logError({
          error: error.message,
          userId,
          request,
          processingTime: Date.now() - startTime
        });
      }
      throw error;
    }
  }

  /**
   * Create a user session
   */
  async createUserSession(userId: string): Promise<string> {
    const userContext = await this.getUserContext(userId);
    return await this.jwtAuth.generateToken(userContext);
  }

  /**
   * Authenticate a JWT token
   */
  async authenticateToken(token: string): Promise<UserContext> {
    try {
      const payload = await this.jwtAuth.verifyToken(token);
      return payload as UserContext;
    } catch (error) {
      throw new AuthenticationError('Invalid or expired token');
    }
  }

  /**
   * Get security metrics
   */
  getSecurityMetrics(): SecurityMetrics {
    return { ...this.metrics };
  }

  /**
   * Get audit logger instance
   */
  get auditLogger(): SMCPAuditLogger {
    return this.auditLogger;
  }

  /**
   * Get rate limiter instance
   */
  get rateLimiter(): AdaptiveRateLimiter {
    return this.rateLimiter;
  }

  // Private helper methods
  private async verifyCredentials(credentials: AuthCredentials): Promise<boolean> {
    // In a real implementation, this would check against a database
    // For demo purposes, accept any non-empty credentials
    return credentials.username.length > 0 && credentials.password.length > 0;
  }

  private async getUserContext(userId: string): Promise<UserContext> {
    // In a real implementation, this would fetch from database
    return {
      userId,
      username: userId,
      role: 'user',
      permissions: this.config.defaultPermissions || ['read'],
      sessionId: this.generateSessionId(),
      lastActivity: new Date()
    };
  }

  private generateSessionId(): string {
    return Math.random().toString(36).substring(2, 15) + 
           Math.random().toString(36).substring(2, 15);
  }

  private async processRequest(request: MCPRequest, userContext: UserContext): Promise<any> {
    // This is a placeholder - in a real implementation, this would
    // delegate to the actual MCP server implementation
    return {
      jsonrpc: '2.0',
      id: request.id,
      result: {
        message: 'Request processed successfully',
        method: request.method,
        user: userContext.userId
      }
    };
  }

  private updateAverageResponseTime(newTime: number): void {
    const totalRequests = this.metrics.totalRequests;
    const currentAverage = this.metrics.averageResponseTime;
    
    this.metrics.averageResponseTime = 
      ((currentAverage * (totalRequests - 1)) + newTime) / totalRequests;
  }
}
