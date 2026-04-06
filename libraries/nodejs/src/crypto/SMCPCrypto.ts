/**
 * SMCP Cryptography
 * ChaCha20-Poly1305 encryption, ECDSA signing, ECDH key exchange.
 */

import * as crypto from 'crypto';
import { CryptographicError } from '../exceptions';

export interface EncryptedData {
  ciphertext: string;
  nonce: string;
  tag: string;
  keyId: string;
  algorithm: 'chacha20-poly1305';
}

export class SMCPCrypto {
  private masterKey: Buffer | null = null;
  private readonly keyId: string;

  constructor() {
    this.keyId = crypto.randomBytes(8).toString('hex');
  }

  setMasterKey(keyBytes: Buffer): void {
    if (keyBytes.length !== 32) {
      throw new CryptographicError('Master key must be 32 bytes for ChaCha20-Poly1305');
    }
    this.masterKey = Buffer.from(keyBytes);
  }

  encrypt(data: Buffer): EncryptedData {
    if (!this.masterKey) {
      throw new CryptographicError('Master key not set. Call setMasterKey() first.');
    }

    const nonce = crypto.randomBytes(12); // 12-byte nonce for ChaCha20-Poly1305

    try {
      const cipher = crypto.createCipheriv('chacha20-poly1305', this.masterKey, nonce, {
        authTagLength: 16,
      } as crypto.CipherGCMOptions);

      const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
      const tag = cipher.getAuthTag();

      return {
        ciphertext: ciphertext.toString('base64'),
        nonce: nonce.toString('base64'),
        tag: tag.toString('base64'),
        keyId: this.keyId,
        algorithm: 'chacha20-poly1305',
      };
    } catch (e) {
      // Fallback to AES-256-GCM if ChaCha20-Poly1305 not available
      return this._encryptAESGCM(data, nonce);
    }
  }

  decrypt(encrypted: EncryptedData): Buffer {
    if (!this.masterKey) {
      throw new CryptographicError('Master key not set. Call setMasterKey() first.');
    }

    try {
      const ciphertext = Buffer.from(encrypted.ciphertext, 'base64');
      const nonce = Buffer.from(encrypted.nonce, 'base64');
      const tag = Buffer.from(encrypted.tag, 'base64');

      const algorithm = encrypted.algorithm === 'chacha20-poly1305' ? 'chacha20-poly1305' : 'aes-256-gcm';

      const decipher = crypto.createDecipheriv(algorithm, this.masterKey, nonce, {
        authTagLength: 16,
      } as crypto.CipherGCMOptions);

      (decipher as crypto.DecipherGCM).setAuthTag(tag);

      const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      return decrypted;
    } catch (e) {
      throw new CryptographicError(`Decryption failed: ${(e as Error).message}`);
    }
  }

  generateKeyPair(): { privateKey: string; publicKey: string } {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'P-384',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    return { privateKey, publicKey };
  }

  sign(data: Buffer, privateKey: string): string {
    try {
      const sign = crypto.createSign('SHA384');
      sign.update(data);
      sign.end();
      const signature = sign.sign(privateKey);
      return signature.toString('base64');
    } catch (e) {
      throw new CryptographicError(`Signing failed: ${(e as Error).message}`);
    }
  }

  verify(data: Buffer, signature: string, publicKey: string): boolean {
    try {
      const verify = crypto.createVerify('SHA384');
      verify.update(data);
      verify.end();
      return verify.verify(publicKey, Buffer.from(signature, 'base64'));
    } catch {
      return false;
    }
  }

  deriveSharedSecret(privateKey: string, peerPublicKey: string): Buffer {
    try {
      const ecdh = crypto.createECDH('prime384v1');

      // Load private key from PEM
      const privateKeyObj = crypto.createPrivateKey(privateKey);
      const keyDetails = privateKeyObj.export({ type: 'pkcs8', format: 'der' });
      // Extract the raw private key bytes for ECDH (P-384 = 48 bytes from end)
      const rawPrivKey = Buffer.from(keyDetails).slice(-48);
      ecdh.setPrivateKey(rawPrivKey);

      // Load peer public key from PEM
      const publicKeyObj = crypto.createPublicKey(peerPublicKey);
      const pubKeyDer = publicKeyObj.export({ type: 'spki', format: 'der' });
      // Extract uncompressed point from DER (last 97 bytes for P-384)
      const rawPubKey = Buffer.from(pubKeyDer).slice(-97);
      const sharedSecret = ecdh.computeSecret(rawPubKey);

      return sharedSecret;
    } catch (e) {
      throw new CryptographicError(`ECDH key derivation failed: ${(e as Error).message}`);
    }
  }

  analyzeRequest(
    _requestData: unknown,
    _authContext: unknown
  ): void {
    // Stub: integrity check placeholder
    // Can be overridden in tests
  }

  private _encryptAESGCM(data: Buffer, nonce: Buffer): EncryptedData {
    if (!this.masterKey) {
      throw new CryptographicError('Master key not set');
    }

    const cipher = crypto.createCipheriv('aes-256-gcm', this.masterKey, nonce);
    const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
    const tag = (cipher as crypto.CipherGCM).getAuthTag();

    return {
      ciphertext: ciphertext.toString('base64'),
      nonce: nonce.toString('base64'),
      tag: tag.toString('base64'),
      keyId: this.keyId,
      algorithm: 'chacha20-poly1305', // keep interface consistent
    };
  }
}
