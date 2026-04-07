/**
 * Argon2 Key Derivation
 * Password-based key derivation using Argon2id.
 */

import * as argon2 from 'argon2';
import * as crypto from 'crypto';

export interface DerivedKeyResult {
  key: Buffer;
  salt: Buffer;
  params: {
    type: string;
    memoryCost: number;
    timeCost: number;
    parallelism: number;
    keyLength: number;
  };
}

export class Argon2KeyDerivation {
  private readonly memoryCost: number;
  private readonly timeCost: number;
  private readonly parallelism: number;

  constructor(options: {
    memoryCost?: number;
    timeCost?: number;
    parallelism?: number;
  } = {}) {
    this.memoryCost = options.memoryCost ?? 65536; // 64 MiB
    this.timeCost = options.timeCost ?? 3;
    this.parallelism = options.parallelism ?? 1;
  }

  async deriveKey(
    password: string,
    salt?: Buffer,
    keyLength = 32
  ): Promise<DerivedKeyResult> {
    const actualSalt = salt ?? crypto.randomBytes(32);

    const hash = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: this.memoryCost,
      timeCost: this.timeCost,
      parallelism: this.parallelism,
      salt: actualSalt,
      hashLength: keyLength,
      raw: true,
    });

    return {
      key: Buffer.from(hash),
      salt: actualSalt,
      params: {
        type: 'argon2id',
        memoryCost: this.memoryCost,
        timeCost: this.timeCost,
        parallelism: this.parallelism,
        keyLength,
      },
    };
  }
}
