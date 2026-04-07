/**
 * Auth module tests
 */

import { JWTAuthenticator } from '../src/auth/JWTAuthenticator';
import { RBACManager } from '../src/auth/RBACManager';
import { MFAManager } from '../src/auth/MFAManager';
import { AuthenticationError } from '../src/exceptions';

const TEST_SECRET = 'test-secret-jwt-auth-32bytes!!!!!';

describe('JWTAuthenticator', () => {
  let auth: JWTAuthenticator;

  beforeEach(() => {
    auth = new JWTAuthenticator({ secret: TEST_SECRET });
  });

  it('generates and validates a token', () => {
    const token = auth.generateToken('user1', ['user'], ['mcp:read'], false);
    expect(typeof token).toBe('string');
    expect(token.split('.').length).toBe(3);

    const payload = auth.validateToken(token);
    expect(payload.user_id).toBe('user1');
    expect(payload.roles).toEqual(['user']);
    expect(payload.permissions).toEqual(['mcp:read']);
    expect(payload.mfa_verified).toBe(false);
    expect(payload.iss).toBe('smcp-security');
    expect(payload.aud).toBe('smcp-client');
  });

  it('generates token with correct iss and aud claims', () => {
    const token = auth.generateToken('user2', [], []);
    const payload = auth.validateToken(token);
    expect(payload.iss).toBe('smcp-security');
    expect(payload.aud).toBe('smcp-client');
  });

  it('throws AuthenticationError for expired token', () => {
    const shortLivedAuth = new JWTAuthenticator({ secret: TEST_SECRET, expiresIn: -1 });
    const token = shortLivedAuth.generateToken('user1', [], []);
    expect(() => shortLivedAuth.validateToken(token)).toThrow(AuthenticationError);
  });

  it('throws AuthenticationError for invalid token', () => {
    expect(() => auth.validateToken('invalid.token.here')).toThrow(AuthenticationError);
  });

  it('throws AuthenticationError for token signed with wrong secret', () => {
    const otherAuth = new JWTAuthenticator({ secret: 'completely-different-secret-here!!' });
    const token = otherAuth.generateToken('user1', [], []);
    expect(() => auth.validateToken(token)).toThrow(AuthenticationError);
  });

  it('revokes a token and rejects it afterward', () => {
    const token = auth.generateToken('user1', [], []);
    auth.revokeToken(token);
    expect(() => auth.validateToken(token)).toThrow(AuthenticationError);
  });

  it('isTokenRevoked returns true for revoked token id', () => {
    const token = auth.generateToken('user1', [], []);
    const payload = auth.validateToken(token);
    const jti = payload.jti;
    auth.revokeToken(token);
    expect(auth.isTokenRevoked(jti)).toBe(true);
  });

  it('throws when SMCP_JWT_SECRET is absent and no secret passed', () => {
    const originalSecret = process.env.SMCP_JWT_SECRET;
    delete process.env.SMCP_JWT_SECRET;
    expect(() => new JWTAuthenticator()).toThrow(/SMCP_JWT_SECRET/);
    if (originalSecret !== undefined) {
      process.env.SMCP_JWT_SECRET = originalSecret;
    }
  });

  it('requires MFA when configured', () => {
    const mfaAuth = new JWTAuthenticator({ secret: TEST_SECRET, requireMFA: true });
    const token = mfaAuth.generateToken('user1', [], [], false); // mfa_verified=false
    expect(() => mfaAuth.validateToken(token)).toThrow(AuthenticationError);
  });

  it('accepts token with MFA verified when MFA required', () => {
    const mfaAuth = new JWTAuthenticator({ secret: TEST_SECRET, requireMFA: true });
    const token = mfaAuth.generateToken('user1', [], [], true); // mfa_verified=true
    const payload = mfaAuth.validateToken(token);
    expect(payload.mfa_verified).toBe(true);
  });
});

describe('RBACManager', () => {
  let rbac: RBACManager;

  beforeEach(() => {
    rbac = new RBACManager();
    rbac.defineRole('user', ['mcp:read', 'mcp:execute:safe_tools']);
    rbac.defineRole('admin', ['mcp:*', 'system:*', 'security:*']);
    rbac.defineRole('power_user', ['mcp:read', 'mcp:write', 'mcp:execute:all_tools']);
  });

  it('grants assigned permission to user', () => {
    rbac.assignRole('alice', 'user');
    expect(rbac.checkPermission('alice', 'mcp:read')).toBe(true);
  });

  it('denies permission for unassigned role', () => {
    expect(rbac.checkPermission('bob', 'mcp:read')).toBe(false);
  });

  it('denies permission not in assigned role', () => {
    rbac.assignRole('alice', 'user');
    expect(rbac.checkPermission('alice', 'mcp:write')).toBe(false);
  });

  it('wildcard mcp:* matches mcp:read', () => {
    rbac.assignRole('admin1', 'admin');
    expect(rbac.checkPermission('admin1', 'mcp:read')).toBe(true);
  });

  it('wildcard mcp:* matches mcp:write', () => {
    rbac.assignRole('admin1', 'admin');
    expect(rbac.checkPermission('admin1', 'mcp:write')).toBe(true);
  });

  it('wildcard mcp:* matches mcp:execute:anything', () => {
    rbac.assignRole('admin1', 'admin');
    expect(rbac.checkPermission('admin1', 'mcp:execute:all_tools')).toBe(true);
  });

  it('system:* matches system:config', () => {
    rbac.assignRole('admin1', 'admin');
    expect(rbac.checkPermission('admin1', 'system:config')).toBe(true);
  });

  it('getUserRoles returns assigned roles', () => {
    rbac.assignRole('alice', 'user');
    rbac.assignRole('alice', 'power_user');
    const roles = rbac.getUserRoles('alice');
    expect(roles).toContain('user');
    expect(roles).toContain('power_user');
  });

  it('getUserPermissions returns all permissions from all roles', () => {
    rbac.assignRole('alice', 'user');
    const perms = rbac.getUserPermissions('alice');
    expect(perms).toContain('mcp:read');
  });

  it('revokeRole removes role', () => {
    rbac.assignRole('alice', 'user');
    rbac.revokeRole('alice', 'user');
    expect(rbac.checkPermission('alice', 'mcp:read')).toBe(false);
  });

  it('assignRole is noop for undefined role', () => {
    expect(() => rbac.assignRole('alice', 'nonexistent')).not.toThrow();
    expect(rbac.getUserRoles('alice')).toHaveLength(0);
  });

  it('defineRole is idempotent', () => {
    rbac.defineRole('user', ['mcp:read']);
    rbac.assignRole('alice', 'user');
    expect(rbac.checkPermission('alice', 'mcp:read')).toBe(true);
    // Only mcp:read now (was redefined)
    expect(rbac.checkPermission('alice', 'mcp:execute:safe_tools')).toBe(false);
  });
});

describe('MFAManager', () => {
  let mfa: MFAManager;

  beforeEach(() => {
    mfa = new MFAManager();
  });

  it('setupMFA returns secret, qrCode, and backupCodes', async () => {
    const result = await mfa.setupMFA('user1');
    expect(result.secret).toBeTruthy();
    expect(result.qrCode).toMatch(/^data:image\/png;base64,/);
    expect(result.backupCodes).toHaveLength(10);
  });

  it('backup code works once then fails', async () => {
    await mfa.setupMFA('user1');
    const codes = mfa.generateBackupCodes('user1');
    const code = codes[0];

    // First use should succeed
    expect(mfa.verifyBackupCode('user1', code)).toBe(true);

    // Second use should fail (single use)
    expect(mfa.verifyBackupCode('user1', code)).toBe(false);
  });

  it('generateBackupCodes returns 10 codes by default', () => {
    const codes = mfa.generateBackupCodes('user2');
    expect(codes).toHaveLength(10);
    // Each code should be 8 uppercase letters
    for (const code of codes) {
      expect(code).toMatch(/^[A-Z]{8}$/);
    }
  });

  it('wrong backup code returns false', async () => {
    await mfa.setupMFA('user1');
    expect(mfa.verifyBackupCode('user1', 'WRONGCOD')).toBe(false);
  });

  it('verifyToken returns false for unknown user', () => {
    expect(mfa.verifyToken('unknown_user', '000000')).toBe(false);
  });
});
