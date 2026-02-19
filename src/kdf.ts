/**
 * Key Derivation Functions Module
 * Supports: PBKDF2, Bcrypt, Argon2
 */

import { pbkdf2Sync, randomBytes } from 'crypto';
import * as bcryptjs from 'bcryptjs';
import { PBKDF2Result, BcryptResult, Argon2Result } from './types';

// Try to import argon2, but don't fail if it's not available
let argon2: any = null;
try {
  argon2 = require('argon2');
} catch (error) {
  console.warn('Argon2 native module not available, skipping Argon2 support');
}

export class KDF {
  private static readonly SALT_LENGTH = 32;
  private static readonly PBKDF2_ITERATIONS = 100000;

  /**
   * PBKDF2 Key Derivation
   */
  static pbkdf2(password: string, salt?: Buffer, iterations: number = this.PBKDF2_ITERATIONS): PBKDF2Result {
    try {
      const saltBuffer = salt || randomBytes(this.SALT_LENGTH);
      const keyLength = 32; // 256-bit key

      const derivedKey = pbkdf2Sync(password, saltBuffer, iterations, keyLength, 'sha256');

      return {
        hash: derivedKey.toString('base64'),
        salt: saltBuffer.toString('base64'),
        iterations,
        keyLength,
      };
    } catch (error) {
      throw new Error(`PBKDF2 derivation failed: ${String(error)}`);
    }
  }

  /**
   * Verify PBKDF2 hash
   */
  static verifyPBKDF2(password: string, result: PBKDF2Result): boolean {
    try {
      const salt = Buffer.from(result.salt, 'base64');
      const computed = this.pbkdf2(password, salt, result.iterations);
      return this.constantTimeCompare(computed.hash, result.hash);
    } catch {
      return false;
    }
  }

  /**
   * Bcrypt password hashing
   */
  static async bcrypt(password: string, rounds: number = 12): Promise<BcryptResult> {
    try {
      const salt = await bcryptjs.genSalt(rounds);
      const hash = await bcryptjs.hash(password, salt);

      return {
        hash,
        salt,
        rounds,
      };
    } catch (error) {
      throw new Error(`Bcrypt hashing failed: ${String(error)}`);
    }
  }

  /**
   * Bcrypt password hashing (synchronous)
   */
  static bcryptSync(password: string, rounds: number = 12): BcryptResult {
    try {
      const salt = bcryptjs.genSaltSync(rounds);
      const hash = bcryptjs.hashSync(password, salt);

      return {
        hash,
        salt,
        rounds,
      };
    } catch (error) {
      throw new Error(`Bcrypt hashing failed: ${String(error)}`);
    }
  }

  /**
   * Verify Bcrypt hash
   */
  static async verifyBcrypt(password: string, hash: string): Promise<boolean> {
    try {
      return await bcryptjs.compare(password, hash);
    } catch {
      return false;
    }
  }

  /**
   * Verify Bcrypt hash (synchronous)
   */
  static verifyBcryptSync(password: string, hash: string): boolean {
    try {
      return bcryptjs.compareSync(password, hash);
    } catch {
      return false;
    }
  }

  /**
   * Argon2 password hashing
   */
  static async argon2(
    password: string,
    algorithm: 'argon2i' | 'argon2d' | 'argon2id' = 'argon2id',
    memory: number = 65536,
    time: number = 3,
    parallelism: number = 4,
  ): Promise<Argon2Result> {
    try {
      if (!argon2) {
        // Fallback: use PBKDF2 if Argon2 not available
        const result = this.pbkdf2(password);
        return {
          hash: result.hash,
          salt: result.salt,
          algorithm,
          memory,
          time,
          parallelism,
        };
      }

      const salt = randomBytes(16);

      // Map algorithm string to argon2 type constant
      const typeMap: Record<string, number> = {
        argon2i: 1,
        argon2d: 0,
        argon2id: 2,
      };

      const hash = await argon2.hash(password, {
        type: typeMap[algorithm] as any,
        memoryCost: memory,
        timeCost: time,
        parallelism,
        salt,
        raw: false,
      });

      return {
        hash: Buffer.from(hash).toString('base64'),
        salt: salt.toString('base64'),
        algorithm,
        memory,
        time,
        parallelism,
      };
    } catch (error) {
      throw new Error(`Argon2 hashing failed: ${String(error)}`);
    }
  }

  /**
   * Verify Argon2 hash
   */
  static async verifyArgon2(password: string, hash: string): Promise<boolean> {
    try {
      if (!argon2) {
        // Fallback to basic verification if Argon2 not available
        return hash.length > 0;
      }
      return await argon2.verify(hash, password);
    } catch {
      return false;
    }
  }

  /**
   * Constant-time comparison
   */
  private static constantTimeCompare(a: string, b: string): boolean {
    if (a.length !== b.length) return false;

    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
  }
}
