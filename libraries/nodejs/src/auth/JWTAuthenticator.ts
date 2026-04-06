/**
 * JWT Authenticator
 * JWT-based authentication system for SMCP.
 */

import * as jwt from 'jsonwebtoken';
import * as crypto from 'crypto';
import { AuthenticationError } from '../exceptions';

export interface TokenPayload {
  user_id: string;
  roles: string[];
  permissions: string[];
  mfa_verified: boolean;
  iat: number;
  exp: number;
  jti: string;
  iss: string;
  aud: string;
  [key: string]: unknown;
}

export interface JWTOptions {
  secret?: string;
  expiresIn?: number;
  algorithm?: string;
  requireMFA?: boolean;
}

export class JWTAuthenticator {
  private readonly secret: string;
  private readonly expiresIn: number;
  private readonly algorithm: string;
  private readonly requireMFA: boolean;
  private readonly revokedTokens: Set<string> = new Set();

  constructor(options: JWTOptions = {}) {
    // JWT secret from env — never a hardcoded default in production paths
    const envSecret = process.env.SMCP_JWT_SECRET;
    if (options.secret) {
      // Testing/development override — log a warning
      if (process.env.NODE_ENV === 'production') {
        console.warn('[SMCP] WARNING: JWT secret passed via constructor options in production. Use SMCP_JWT_SECRET env var instead.');
      }
      this.secret = options.secret;
    } else if (envSecret) {
      this.secret = envSecret;
    } else {
      throw new Error(
        'SMCP_JWT_SECRET environment variable is required. Set it before initializing JWTAuthenticator.'
      );
    }

    this.expiresIn = options.expiresIn ?? 3600;
    this.algorithm = options.algorithm ?? 'HS256';
    this.requireMFA = options.requireMFA ?? false;
  }

  generateToken(
    userId: string,
    roles: string[] = [],
    permissions: string[] = [],
    mfaVerified = false
  ): string {
    const jti = crypto.randomBytes(16).toString('base64url');
    const now = Math.floor(Date.now() / 1000);

    const payload: Omit<TokenPayload, 'iat' | 'exp'> & { iat: number; exp: number } = {
      user_id: userId,
      roles,
      permissions,
      mfa_verified: mfaVerified,
      iat: now,
      exp: now + this.expiresIn,
      jti,
      iss: 'smcp-security',
      aud: 'smcp-client',
    };

    return jwt.sign(payload, this.secret, {
      algorithm: this.algorithm as jwt.Algorithm,
      noTimestamp: true, // We set iat manually
    });
  }

  validateToken(token: string): TokenPayload {
    try {
      const payload = jwt.verify(token, this.secret, {
        algorithms: [this.algorithm as jwt.Algorithm],
        audience: 'smcp-client',
        issuer: 'smcp-security',
      }) as TokenPayload;

      // Check if token is revoked
      if (payload.jti && this.revokedTokens.has(payload.jti)) {
        throw new AuthenticationError('Token has been revoked');
      }

      // Check MFA requirement
      if (this.requireMFA && !payload.mfa_verified) {
        throw new AuthenticationError('Multi-factor authentication required');
      }

      return payload;
    } catch (e) {
      if (e instanceof AuthenticationError) throw e;
      if (e instanceof jwt.TokenExpiredError) {
        throw new AuthenticationError('Token has expired');
      }
      if (e instanceof jwt.JsonWebTokenError) {
        throw new AuthenticationError(`Invalid token: ${(e as Error).message}`);
      }
      throw new AuthenticationError(`Token validation failed: ${(e as Error).message}`);
    }
  }

  revokeToken(token: string): void {
    try {
      const payload = jwt.verify(token, this.secret, {
        algorithms: [this.algorithm as jwt.Algorithm],
        audience: 'smcp-client',
        ignoreExpiration: true,
      }) as TokenPayload;
      if (payload.jti) {
        this.revokedTokens.add(payload.jti);
      }
    } catch {
      // Token is already invalid, no need to revoke
    }
  }

  isTokenRevoked(tokenId: string): boolean {
    return this.revokedTokens.has(tokenId);
  }
}
