/**
 * HMAC Module
 * Supports: HMAC-SHA256, HMAC-SHA512
 */

import { createHmac } from 'crypto';
import { HMACResult } from './types';

export class HMAC {
  /**
   * Generate HMAC signature
   */
  static sign(
    message: string | Buffer,
    secret: string | Buffer,
    algorithm: 'sha256' | 'sha512' = 'sha256',
  ): HMACResult {
    try {
      const messageBuffer = typeof message === 'string' ? Buffer.from(message, 'utf-8') : message;
      const secretBuffer = typeof secret === 'string' ? Buffer.from(secret, 'utf-8') : secret;

      const hmac = createHmac(`sha${algorithm === 'sha256' ? '256' : '512'}`, secretBuffer);
      hmac.update(messageBuffer);

      const digest = hmac.digest();

      return {
        signature: digest.toString('base64'),
        hex: digest.toString('hex'),
        algorithm,
      };
    } catch (error) {
      throw new Error(`HMAC-${algorithm.toUpperCase()} signing failed: ${String(error)}`);
    }
  }

  /**
   * HMAC-SHA256
   */
  static sha256(message: string | Buffer, secret: string | Buffer): HMACResult {
    return this.sign(message, secret, 'sha256');
  }

  /**
   * HMAC-SHA512
   */
  static sha512(message: string | Buffer, secret: string | Buffer): HMACResult {
    return this.sign(message, secret, 'sha512');
  }

  /**
   * Verify HMAC signature (constant-time comparison)
   */
  static verify(
    message: string | Buffer,
    signature: string,
    secret: string | Buffer,
    algorithm: 'sha256' | 'sha512' = 'sha256',
  ): boolean {
    try {
      const computed = this.sign(message, secret, algorithm);
      return this.constantTimeCompare(computed.signature, signature) ||
             this.constantTimeCompare(computed.hex, signature)
        ? true
        : false;
    } catch {
      return false;
    }
  }

  /**
   * Constant-time comparison to prevent timing attacks
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
