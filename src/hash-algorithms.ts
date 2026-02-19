/**
 * Hash Algorithms Module
 * Supports: MD5, SHA1, SHA256, SHA512
 */

import { createHash } from 'crypto';
import { HashResult, HashAlgorithm } from './types';

export class HashAlgorithms {
  /**
   * Hash data using specified algorithm
   */
  static hash(data: string | Buffer, algorithm: HashAlgorithm): HashResult {
    try {
      const input = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
      const hash = createHash(algorithm);
      hash.update(input);
      const digest = hash.digest();

      return {
        algorithm,
        hash: digest.toString('binary'),
        hex: digest.toString('hex'),
        base64: digest.toString('base64'),
      };
    } catch (error) {
      throw new Error(`Hash operation failed with ${algorithm}: ${String(error)}`);
    }
  }

  /**
   * MD5 Hash (128-bit)
   * ⚠️ Not cryptographically secure, use for compatibility only
   */
  static md5(data: string | Buffer): HashResult {
    return this.hash(data, 'md5');
  }

  /**
   * SHA1 Hash (160-bit)
   * ⚠️ Deprecated, consider SHA256+ instead
   */
  static sha1(data: string | Buffer): HashResult {
    return this.hash(data, 'sha1');
  }

  /**
   * SHA256 Hash (256-bit)
   * ✅ Recommended for most applications
   */
  static sha256(data: string | Buffer): HashResult {
    return this.hash(data, 'sha256');
  }

  /**
   * SHA512 Hash (512-bit)
   * ✅ Recommended for high-security applications
   */
  static sha512(data: string | Buffer): HashResult {
    return this.hash(data, 'sha512');
  }

  /**
   * Verify hash matches original data
   */
  static verify(data: string | Buffer, hash: string, algorithm: HashAlgorithm): boolean {
    try {
      const computed = this.hash(data, algorithm);
      return computed.hex === hash || computed.base64 === hash;
    } catch {
      return false;
    }
  }

  /**
   * File hashing (simulated)
   */
  static hashString(data: string, algorithm: HashAlgorithm): string {
    return this.hash(data, algorithm).hex;
  }

  /**
   * Compare two hashes
   */
  static compareHashes(hash1: string, hash2: string): boolean {
    try {
      // Constant-time comparison to prevent timing attacks
      if (hash1.length !== hash2.length) return false;

      let result = 0;
      for (let i = 0; i < hash1.length; i++) {
        result |= hash1.charCodeAt(i) ^ hash2.charCodeAt(i);
      }
      return result === 0;
    } catch {
      return false;
    }
  }
}
