/**
 * MFA Manager
 * Multi-Factor Authentication using TOTP (speakeasy) and QR codes.
 */

import * as speakeasy from 'speakeasy';
import * as QRCode from 'qrcode';
import * as crypto from 'crypto';

export interface MFASetupResult {
  secret: string;
  qrCode: string;
  backupCodes: string[];
}

interface UserMFAData {
  secret: string;
  backupCodes: Set<string>;
  backupCodeHashes: Map<string, string>; // hash -> original not stored; stored: original -> hash
}

export class MFAManager {
  private readonly userSecrets: Map<string, UserMFAData> = new Map();

  async setupMFA(userId: string): Promise<MFASetupResult> {
    const secretObj = speakeasy.generateSecret({
      name: `SMCP:${userId}`,
      issuer: 'SMCP Security',
    });

    const secret = secretObj.base32;
    const otpAuthUrl = secretObj.otpauth_url ?? '';

    // Generate QR code as data URL
    const qrCode = await QRCode.toDataURL(otpAuthUrl);

    // Generate backup codes
    const backupCodes = this.generateBackupCodes(userId);

    // Store secret
    const existing = this.userSecrets.get(userId);
    const backupCodeHashes: Map<string, string> = existing?.backupCodeHashes ?? new Map();
    const backupCodeSet: Set<string> = new Set(backupCodes);

    this.userSecrets.set(userId, {
      secret,
      backupCodes: backupCodeSet,
      backupCodeHashes,
    });

    return { secret, qrCode, backupCodes };
  }

  verifyToken(userId: string, token: string): boolean {
    const userData = this.userSecrets.get(userId);
    if (!userData) return false;

    return speakeasy.totp.verify({
      secret: userData.secret,
      encoding: 'base32',
      token,
      window: 1,
    });
  }

  generateBackupCodes(userId: string, count = 10): string[] {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const codes: string[] = [];

    for (let i = 0; i < count; i++) {
      let code = '';
      for (let j = 0; j < 8; j++) {
        code += alphabet[crypto.randomInt(0, alphabet.length)];
      }
      codes.push(code);
    }

    // Store hashed backup codes
    let userData = this.userSecrets.get(userId);
    if (!userData) {
      // Create a placeholder entry if user doesn't have MFA set up yet
      userData = {
        secret: '',
        backupCodes: new Set(codes),
        backupCodeHashes: new Map(),
      };
    } else {
      userData.backupCodes = new Set(codes);
    }

    // Store hash map: hash -> code (for lookup during verify)
    const hashMap = new Map<string, string>();
    for (const code of codes) {
      const hash = crypto.createHash('sha256').update(code).digest('hex');
      hashMap.set(hash, code);
    }
    userData.backupCodeHashes = hashMap;
    this.userSecrets.set(userId, userData);

    return codes;
  }

  verifyBackupCode(userId: string, code: string): boolean {
    const userData = this.userSecrets.get(userId);
    if (!userData) return false;

    const codeHash = crypto.createHash('sha256').update(code).digest('hex');

    // Check if the hash exists in our map
    if (userData.backupCodeHashes.has(codeHash)) {
      // Remove used code (single use)
      userData.backupCodeHashes.delete(codeHash);
      userData.backupCodes.delete(code);
      return true;
    }

    return false;
  }
}
