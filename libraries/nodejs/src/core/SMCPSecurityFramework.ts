/**
 * Main SMCP Security Framework implementation
 * 6-layer pipeline: Input Validation → Auth/Authz → Rate Limiting →
 *   Cryptography → AI Immune System → Audit Logging
 */

import * as crypto from 'crypto';
import { SecurityConfig } from './SecurityConfig';
import { InputValidator } from '../validation/InputValidator';
import { JWTAuthenticator, TokenPayload } from '../auth/JWTAuthenticator';
import { MFAManager } from '../auth/MFAManager';
import { RBACManager } from '../auth/RBACManager';
import { AdaptiveRateLimiter } from '../ratelimit/AdaptiveRateLimiter';
import { DoSProtection } from '../ratelimit/DoSProtection';
import { SMCPCrypto } from '../crypto/SMCPCrypto';
import { SMCPAuditLogger, EventCategory, EventSeverity } from '../audit/SMCPAuditLogger';
import { AIImmuneSystem } from '../ai/AIImmuneSystem';
import {
  SecurityError,
  AuthenticationError,
  AuthorizationError,
  RateLimitError,
} from '../exceptions';

export interface ProcessedResult {
  request: Record<string, unknown>;
  context: Record<string, unknown>;
  securityMetadata: SecurityMetadata;
}

interface SecurityMetadata {
  processingTimeMs: number;
  securityLevel: string;
  threatScore: number;
  layersProcessed: string[];
  timestamp: string;
  userRoles: string[];
  userPermissions: string[];
  rateLimitStatus: Record<string, unknown> | null;
  aiAnalysis: { threatScore: number; recommendation: string };
  encryptionApplied: boolean;
  errors?: Record<string, string>;
}

interface FrameworkMetrics {
  requestsProcessed: number;
  attacksBlocked: number;
  authenticationFailures: number;
  authorizationFailures: number;
  rateLimitViolations: number;
  anomaliesDetected: number;
  falsePositives: number;
}

const METHOD_PERMISSION_MAP: Record<string, string> = {
  'tools/list': 'mcp:read',
  'tools/call': 'mcp:read',
  'resources/list': 'mcp:read',
  'resources/read': 'mcp:read',
  'resources/write': 'mcp:write',
  'prompts/list': 'mcp:read',
  'prompts/get': 'mcp:read',
  'system/config': 'system:config',
};

export class SMCPSecurityFramework {
  public readonly config: SecurityConfig;

  // Optional components are T | null — never instantiated if feature disabled
  private readonly inputValidator: InputValidator | null;
  readonly jwtAuth: JWTAuthenticator;
  private readonly mfaManager: MFAManager | null;
  private readonly rbacManager: RBACManager | null;
  readonly rateLimiter: AdaptiveRateLimiter | null;
  private readonly dosProtection: DoSProtection | null;
  private readonly cryptoManager: SMCPCrypto | null;
  readonly auditLogger: SMCPAuditLogger | null;
  private readonly aiImmune: AIImmuneSystem | null;

  private readonly metrics: FrameworkMetrics;
  private readonly processingTimes: number[] = [];

  constructor(config?: Partial<SecurityConfig> | SecurityConfig) {
    this.config = config instanceof SecurityConfig
      ? config
      : new SecurityConfig(config);

    // JWT authenticator — secret from env
    const jwtSecret = process.env.SMCP_JWT_SECRET;
    this.jwtAuth = new JWTAuthenticator({
      secret: jwtSecret,
      expiresIn: this.config.jwtExpirySeconds,
      requireMFA: this.config.enableMFA,
    });

    this.inputValidator = this.config.enableInputValidation
      ? new InputValidator({ strictness: this.config.validationStrictness })
      : null;

    this.mfaManager = this.config.enableMFA ? new MFAManager() : null;

    this.rbacManager = this.config.enableRBAC ? new RBACManager() : null;
    if (this.rbacManager) this._setupDefaultRoles(this.rbacManager);

    this.rateLimiter = this.config.enableRateLimiting
      ? new AdaptiveRateLimiter({
          baseLimit: this.config.defaultRateLimit,
          adaptive: this.config.adaptiveLimits,
        })
      : null;

    this.dosProtection = this.config.enableRateLimiting ? new DoSProtection() : null;

    if (this.config.enableEncryption) {
      const c = new SMCPCrypto();
      c.setMasterKey(crypto.randomBytes(32));
      this.cryptoManager = c;
    } else {
      this.cryptoManager = null;
    }

    this.auditLogger = this.config.enableAuditLogging
      ? new SMCPAuditLogger({ logLevel: this.config.logLevel })
      : null;

    this.aiImmune = this.config.enableAIImmune
      ? new AIImmuneSystem({
          threshold: this.config.anomalyThreshold,
          learningMode: this.config.learningMode,
        })
      : null;

    this.metrics = {
      requestsProcessed: 0,
      attacksBlocked: 0,
      authenticationFailures: 0,
      authorizationFailures: 0,
      rateLimitViolations: 0,
      anomaliesDetected: 0,
      falsePositives: 0,
    };
  }

  async processRequest(
    requestData: Record<string, unknown>,
    userContext?: Record<string, unknown>
  ): Promise<ProcessedResult> {
    const startTime = Date.now();
    const layersProcessed: string[] = [];
    const errors: Record<string, string> = {};

    try {
      this.metrics.requestsProcessed++;

      // Layer 1: Input Validation
      let validatedRequest = requestData;
      if (this.config.enableInputValidation && this.inputValidator) {
        validatedRequest = this.inputValidator.validateRequest(requestData);
        layersProcessed.push('input_validation');
      }

      // Layer 2: Auth + Authz (sequential — authz depends on auth output)
      const authContext = await this._authenticateAndAuthorize(validatedRequest, userContext);
      layersProcessed.push('authentication', 'authorization');

      // Layer 3: Rate Limiting
      if (this.config.enableRateLimiting && this.rateLimiter) {
        await this._checkRateLimits(authContext, validatedRequest);
        layersProcessed.push('rate_limiting');
      }

      // Layer 4: Cryptography (degraded mode — soft errors)
      let processedRequest = validatedRequest;
      if (this.config.enableEncryption && this.cryptoManager) {
        try {
          processedRequest = await this._processCryptography(
            validatedRequest,
            authContext,
            userContext ?? {}
          );
          layersProcessed.push('encryption');
        } catch (e) {
          errors['crypto_manager'] = (e as Error).message;
        }
      }

      // Layer 5: AI Immune System (SecurityError propagates, others are soft)
      let threatScore = 0.0;
      if (this.config.enableAIImmune && this.aiImmune) {
        try {
          threatScore = await this._aiImmuneAnalysis(processedRequest, authContext);
          layersProcessed.push('ai_immune');
        } catch (e) {
          if (e instanceof SecurityError) throw e;
          errors['ai_immune'] = (e as Error).message;
        }
      }

      // Layer 6: Audit (soft errors — never fail the request)
      if (this.config.enableAuditLogging && this.auditLogger) {
        try {
          await this._auditRequest(processedRequest, authContext, 'SUCCESS');
          layersProcessed.push('audit');
        } catch (e) {
          errors['audit'] = (e as Error).message;
        }
      }

      const processingTimeMs = Date.now() - startTime;
      this.processingTimes.push(processingTimeMs);

      const securityLevel = this._calculateSecurityLevel(authContext);
      const finalThreatScore = (authContext.threatScore as number | undefined) ?? threatScore;

      const securityMetadata: SecurityMetadata = {
        processingTimeMs,
        securityLevel,
        threatScore: finalThreatScore,
        layersProcessed,
        timestamp: new Date().toISOString(),
        userRoles: (authContext.roles as string[] | undefined) ?? [],
        userPermissions: (authContext.permissions as string[] | undefined) ?? [],
        rateLimitStatus: this._getRateLimitStatus(authContext),
        aiAnalysis: { threatScore: finalThreatScore, recommendation: 'allow' },
        encryptionApplied: this.config.enableEncryption,
        ...(Object.keys(errors).length > 0 ? { errors } : {}),
      };

      // Propagate user_context fields into authContext
      if (userContext) {
        if (!authContext.ip_address) authContext.ip_address = userContext.ip_address;
        if (!authContext.user_agent) authContext.user_agent = userContext.user_agent;
        authContext.security_level = securityLevel;
      }

      return { request: processedRequest, context: authContext, securityMetadata };
    } catch (e) {
      // Audit failure
      if (this.config.enableAuditLogging && this.auditLogger) {
        try {
          await this._auditRequest(requestData, userContext ?? {}, 'FAILURE', (e as Error).message);
        } catch {
          // swallow
        }
      }

      // Metric + IP flagging
      const ip = (userContext as Record<string, unknown> | undefined)?.ip_address as string | undefined;
      if (e instanceof AuthenticationError) {
        this.metrics.authenticationFailures++;
        if (ip) this.rateLimiter?.flagSuspiciousIP(ip);
      } else if (e instanceof AuthorizationError) {
        this.metrics.authorizationFailures++;
        if (ip) this.rateLimiter?.flagSuspiciousIP(ip);
      } else if (e instanceof RateLimitError) {
        this.metrics.rateLimitViolations++;
      } else {
        this.metrics.attacksBlocked++;
        if (ip) this.rateLimiter?.flagSuspiciousIP(ip);
      }

      throw e;
    }
  }

  private async _authenticateAndAuthorize(
    requestData: Record<string, unknown>,
    userContext?: Record<string, unknown>
  ): Promise<Record<string, unknown>> {
    const ctx = userContext ?? {};
    const token = ctx.token as string | undefined;

    if (!token) {
      throw new AuthenticationError('No authentication token provided');
    }

    let payload: TokenPayload;
    try {
      payload = this.jwtAuth.validateToken(token);
    } catch (e) {
      throw e instanceof AuthenticationError
        ? e
        : new AuthenticationError(`Token validation failed: ${(e as Error).message}`);
    }

    const userId = payload.user_id;
    const roles = payload.roles ?? [];
    const permissions = payload.permissions ?? [];
    const sessionId = crypto.randomBytes(8).toString('hex');

    // Authorization: check if user has permission for the requested method
    // Permission check uses both the RBAC role assignments AND the token's embedded permissions
    if (this.rbacManager && this.config.enableRBAC) {
      const method = (requestData.method as string) ?? '';
      const requiredPerm = this._getRequiredPermission(method);

      // Check RBAC role assignments first
      let hasPermission = this.rbacManager.checkPermission(userId, requiredPerm);

      // Also check token's embedded permissions directly
      if (!hasPermission) {
        hasPermission = permissions.some((p) => this._permissionMatches(p, requiredPerm));
      }

      if (!hasPermission) {
        throw new AuthorizationError(
          `Access denied: user '${userId}' lacks permission '${requiredPerm}' for '${method}'`,
          requiredPerm
        );
      }
    }

    return {
      user_id: userId,
      roles,
      permissions,
      mfa_verified: payload.mfa_verified,
      session_id: sessionId,
      threat_score: 0.0,
      security_level: 'LOW_RISK',
    };
  }

  private async _checkRateLimits(
    authContext: Record<string, unknown>,
    _requestData: Record<string, unknown>
  ): Promise<void> {
    if (!this.rateLimiter) return;

    const userId = authContext.user_id as string;
    this.rateLimiter.checkRateLimit(userId);
  }

  private async _processCryptography(
    requestData: Record<string, unknown>,
    _authContext: Record<string, unknown>,
    userContext: Record<string, unknown>
  ): Promise<Record<string, unknown>> {
    if (!this.cryptoManager) return requestData;

    // Only encrypt payload if explicitly requested
    if (!userContext.encryptPayload) return requestData;

    const data = Buffer.from(JSON.stringify(requestData));
    const encrypted = this.cryptoManager.encrypt(data);

    return { ...requestData, _encrypted: encrypted };
  }

  private async _aiImmuneAnalysis(
    requestData: Record<string, unknown>,
    authContext: Record<string, unknown>
  ): Promise<number> {
    if (!this.aiImmune) return 0.0;

    const result = this.aiImmune.analyzeRequest(requestData, authContext);
    this.metrics.anomaliesDetected += result.recommendation !== 'allow' ? 1 : 0;
    return result.overallRiskScore;
  }

  private async _auditRequest(
    requestData: Record<string, unknown>,
    authContext: Record<string, unknown>,
    status: 'SUCCESS' | 'FAILURE',
    errorMessage?: string
  ): Promise<void> {
    if (!this.auditLogger) return;

    const userId = (authContext.user_id as string | undefined) ?? 'anonymous';
    const method = (requestData.method as string | undefined) ?? 'unknown';

    this.auditLogger.logEvent(
      EventCategory.AUDIT,
      status === 'SUCCESS' ? EventSeverity.LOW : EventSeverity.HIGH,
      `Request ${status}: method=${method}, user=${userId}${errorMessage ? `, error=${errorMessage}` : ''}`,
      { userId, method, status, errorMessage }
    );
  }

  private _calculateSecurityLevel(authContext: Record<string, unknown>): string {
    const threatScore = (authContext.threat_score as number) ?? 0.0;
    if (threatScore > 0.9) return 'CRITICAL_RISK';
    if (threatScore > 0.8) return 'HIGH_RISK';
    if (threatScore > 0.5) return 'MEDIUM_RISK';
    return 'LOW_RISK';
  }

  private _getRateLimitStatus(authContext: Record<string, unknown>): Record<string, unknown> | null {
    if (!this.config.enableRateLimiting || !this.rateLimiter) return null;

    const userId = authContext.user_id as string | undefined;
    if (!userId) return null;

    const requests = this.rateLimiter.requestCounts.get(userId) ?? [];
    return {
      user_id: userId,
      requests_in_window: requests.length,
    };
  }

  private _getRequiredPermission(method: string): string {
    for (const [key, perm] of Object.entries(METHOD_PERMISSION_MAP)) {
      if (method === key || method.startsWith(key)) {
        return perm;
      }
    }
    return 'mcp:read'; // default
  }

  private _permissionMatches(stored: string, required: string): boolean {
    if (stored === '*') return true;
    if (stored === required) return true;
    if (stored.endsWith(':*')) {
      const prefix = stored.slice(0, -1);
      if (required.startsWith(prefix)) return true;
    }
    const regexPattern = '^' + stored.replace(/\*/g, '.*') + '$';
    return new RegExp(regexPattern).test(required);
  }

  private _setupDefaultRoles(rbac: RBACManager): void {
    rbac.defineRole('user', ['mcp:read', 'mcp:execute:safe_tools']);
    rbac.defineRole('power_user', ['mcp:read', 'mcp:write', 'mcp:execute:all_tools']);
    rbac.defineRole('admin', ['mcp:*', 'system:*', 'security:*']);
  }

  getSecurityMetrics(): FrameworkMetrics & { averageProcessingTimeMs: number } {
    const avg =
      this.processingTimes.length > 0
        ? this.processingTimes.reduce((a, b) => a + b, 0) / this.processingTimes.length
        : 0;

    return {
      ...this.metrics,
      averageProcessingTimeMs: avg,
    };
  }

  /**
   * Assign a role to a user (for setup/testing)
   */
  assignUserRole(userId: string, roleName: string): void {
    this.rbacManager?.assignRole(userId, roleName);
  }

  /**
   * Generate a token for a user (delegation to jwtAuth)
   */
  generateToken(
    userId: string,
    roles: string[] = [],
    permissions: string[] = [],
    mfaVerified = false
  ): string {
    return this.jwtAuth.generateToken(userId, roles, permissions, mfaVerified);
  }
}
