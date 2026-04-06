/**
 * Crypto module tests
 */

import * as crypto from 'crypto';
import { SMCPCrypto } from '../src/crypto/SMCPCrypto';
import { Argon2KeyDerivation } from '../src/crypto/Argon2KeyDerivation';
import { CryptographicError } from '../src/exceptions';

describe('SMCPCrypto', () => {
  let smcpCrypto: SMCPCrypto;

  beforeEach(() => {
    smcpCrypto = new SMCPCrypto();
    smcpCrypto.setMasterKey(crypto.randomBytes(32));
  });

  it('encrypt then decrypt round-trips correctly', () => {
    const original = Buffer.from('Hello, SMCP World!');
    const encrypted = smcpCrypto.encrypt(original);
    const decrypted = smcpCrypto.decrypt(encrypted);
    expect(decrypted.equals(original)).toBe(true);
  });

  it('encrypt produces base64 strings', () => {
    const data = Buffer.from('test data');
    const encrypted = smcpCrypto.encrypt(data);
    // Verify it's valid base64
    expect(() => Buffer.from(encrypted.ciphertext, 'base64')).not.toThrow();
    expect(() => Buffer.from(encrypted.nonce, 'base64')).not.toThrow();
    expect(() => Buffer.from(encrypted.tag, 'base64')).not.toThrow();
  });

  it('encrypt includes keyId and algorithm', () => {
    const encrypted = smcpCrypto.encrypt(Buffer.from('test'));
    expect(encrypted.keyId).toBeTruthy();
    expect(encrypted.algorithm).toBe('chacha20-poly1305');
  });

  it('throws CryptographicError if no master key set', () => {
    const noKeyCrypto = new SMCPCrypto();
    expect(() => noKeyCrypto.encrypt(Buffer.from('test'))).toThrow(CryptographicError);
  });

  it('setMasterKey throws for non-32-byte key', () => {
    const badCrypto = new SMCPCrypto();
    expect(() => badCrypto.setMasterKey(Buffer.from('tooshort'))).toThrow(CryptographicError);
  });

  it('decrypt throws for tampered ciphertext', () => {
    const original = Buffer.from('important data');
    const encrypted = smcpCrypto.encrypt(original);

    // Tamper with ciphertext
    const tamperedBytes = Buffer.from(encrypted.ciphertext, 'base64');
    tamperedBytes[0] ^= 0xff;
    const tampered = { ...encrypted, ciphertext: tamperedBytes.toString('base64') };

    expect(() => smcpCrypto.decrypt(tampered)).toThrow(CryptographicError);
  });

  it('generateKeyPair returns PEM-formatted keys', () => {
    const { privateKey, publicKey } = smcpCrypto.generateKeyPair();
    expect(privateKey).toContain('-----BEGIN PRIVATE KEY-----');
    expect(publicKey).toContain('-----BEGIN PUBLIC KEY-----');
  });

  it('sign and verify work correctly', () => {
    const { privateKey, publicKey } = smcpCrypto.generateKeyPair();
    const data = Buffer.from('data to sign');
    const signature = smcpCrypto.sign(data, privateKey);
    expect(smcpCrypto.verify(data, signature, publicKey)).toBe(true);
  });

  it('verify returns false for wrong signature', () => {
    const { privateKey, publicKey } = smcpCrypto.generateKeyPair();
    const data = Buffer.from('data to sign');
    smcpCrypto.sign(data, privateKey);
    // Use wrong signature
    const wrongSig = 'dGhpcyBpcyBub3QgYSB2YWxpZCBzaWduYXR1cmU=';
    expect(smcpCrypto.verify(data, wrongSig, publicKey)).toBe(false);
  });

  it('verify returns false for tampered data', () => {
    const { privateKey, publicKey } = smcpCrypto.generateKeyPair();
    const data = Buffer.from('data to sign');
    const signature = smcpCrypto.sign(data, privateKey);
    const tamperedData = Buffer.from('tampered data');
    expect(smcpCrypto.verify(tamperedData, signature, publicKey)).toBe(false);
  });

  it('encrypts and decrypts empty buffer', () => {
    const empty = Buffer.alloc(0);
    const encrypted = smcpCrypto.encrypt(empty);
    const decrypted = smcpCrypto.decrypt(encrypted);
    expect(decrypted.length).toBe(0);
  });
});

describe('Argon2KeyDerivation', () => {
  jest.setTimeout(30000);
  let kdf: Argon2KeyDerivation;

  beforeEach(() => {
    // Use reduced parameters for faster tests
    kdf = new Argon2KeyDerivation({
      memoryCost: 1024,
      timeCost: 1,
      parallelism: 1,
    });
  });

  it('deriveKey returns key and salt', async () => {
    const result = await kdf.deriveKey('password123');
    expect(result.key).toBeInstanceOf(Buffer);
    expect(result.salt).toBeInstanceOf(Buffer);
    expect(result.key.length).toBe(32); // default keyLength
  });

  it('deriveKey with same password and salt produces same key', async () => {
    const salt = crypto.randomBytes(32);
    const result1 = await kdf.deriveKey('mypassword', salt);
    const result2 = await kdf.deriveKey('mypassword', salt);
    expect(result1.key.equals(result2.key)).toBe(true);
  });

  it('different salt produces different key', async () => {
    const salt1 = crypto.randomBytes(32);
    const salt2 = crypto.randomBytes(32);
    const result1 = await kdf.deriveKey('mypassword', salt1);
    const result2 = await kdf.deriveKey('mypassword', salt2);
    expect(result1.key.equals(result2.key)).toBe(false);
  });

  it('returns params in result', async () => {
    const result = await kdf.deriveKey('test');
    expect(result.params.type).toBe('argon2id');
    expect(result.params.memoryCost).toBe(1024);
  });

  it('auto-generates salt when not provided', async () => {
    const result = await kdf.deriveKey('test');
    expect(result.salt).toBeInstanceOf(Buffer);
    expect(result.salt.length).toBeGreaterThan(0);
  });

  it('respects custom keyLength', async () => {
    const result = await kdf.deriveKey('test', undefined, 64);
    expect(result.key.length).toBe(64);
  });
});
