/**
 * AES Encryption Module
 * Supports: AES-256 CBC and GCM modes
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { AESEncrypted, AESDecrypted, AESMode, AESKeySize } from './types';

export class AESCipher {
  private static readonly SALT_LENGTH = 32;

  /**
   * Generate random key for AES
   */
  static generateKey(keySize: AESKeySize = 256): Buffer {
    const keySizeBytes = keySize / 8;
    return randomBytes(keySizeBytes);
  }

  /**
   * Generate random IV (Initialization Vector)
   */
  static generateIV(): Buffer {
    return randomBytes(16);
  }

  /**
   * Encrypt plaintext using AES-CBC
   */
  static encryptCBC(plaintext: string, key: Buffer | string): AESEncrypted {
    try {
      const keyBuffer = typeof key === 'string' ? Buffer.from(key, 'base64') : key;
      const iv = this.generateIV();

      // Ensure key is 32 bytes (256-bit)
      if (keyBuffer.length !== 32) {
        throw new Error(`Invalid key size: expected 32 bytes, got ${keyBuffer.length}`);
      }

      const cipher = createCipheriv('aes-256-cbc', keyBuffer, iv);
      let ciphertext = cipher.update(plaintext, 'utf-8', 'base64');
      ciphertext += cipher.final('base64');

      return {
        mode: 'cbc',
        keySize: 256,
        iv: iv.toString('base64'),
        ciphertext,
      };
    } catch (error) {
      throw new Error(`AES-CBC encryption failed: ${String(error)}`);
    }
  }

  /**
   * Decrypt ciphertext using AES-CBC
   */
  static decryptCBC(encrypted: AESEncrypted, key: Buffer | string): AESDecrypted {
    try {
      const keyBuffer = typeof key === 'string' ? Buffer.from(key, 'base64') : key;
      const iv = Buffer.from(encrypted.iv, 'base64');

      if (keyBuffer.length !== 32) {
        throw new Error(`Invalid key size: expected 32 bytes, got ${keyBuffer.length}`);
      }

      const decipher = createDecipheriv('aes-256-cbc', keyBuffer, iv);
      let plaintext = decipher.update(encrypted.ciphertext, 'base64', 'utf-8');
      plaintext += decipher.final('utf-8');

      return {
        plaintext,
        success: true,
      };
    } catch (error) {
      return {
        plaintext: '',
        success: false,
        error: String(error),
      };
    }
  }

  /**
   * Encrypt plaintext using AES-GCM
   */
  static encryptGCM(plaintext: string, key: Buffer | string, aad?: string): AESEncrypted {
    try {
      const keyBuffer = typeof key === 'string' ? Buffer.from(key, 'base64') : key;
      const iv = randomBytes(12); // GCM typically uses 96-bit IV
      const aadBuffer = aad ? Buffer.from(aad, 'utf-8') : undefined;

      if (keyBuffer.length !== 32) {
        throw new Error(`Invalid key size: expected 32 bytes, got ${keyBuffer.length}`);
      }

      const cipher = createCipheriv('aes-256-gcm', keyBuffer, iv);

      if (aadBuffer) {
        cipher.setAAD(aadBuffer);
      }

      let ciphertext = cipher.update(plaintext, 'utf-8', 'base64');
      ciphertext += cipher.final('base64');

      const tag = cipher.getAuthTag();

      return {
        mode: 'gcm',
        keySize: 256,
        iv: iv.toString('base64'),
        ciphertext,
        tag: tag.toString('base64'),
        aad: aad ? Buffer.from(aad, 'utf-8').toString('base64') : undefined,
      };
    } catch (error) {
      throw new Error(`AES-GCM encryption failed: ${String(error)}`);
    }
  }

  /**
   * Decrypt ciphertext using AES-GCM
   */
  static decryptGCM(encrypted: AESEncrypted, key: Buffer | string): AESDecrypted {
    try {
      const keyBuffer = typeof key === 'string' ? Buffer.from(key, 'base64') : key;
      const iv = Buffer.from(encrypted.iv, 'base64');
      const tag = encrypted.tag ? Buffer.from(encrypted.tag, 'base64') : undefined;
      const aadBuffer = encrypted.aad
        ? Buffer.from(Buffer.from(encrypted.aad, 'base64').toString('utf-8'), 'utf-8')
        : undefined;

      if (keyBuffer.length !== 32) {
        throw new Error(`Invalid key size: expected 32 bytes, got ${keyBuffer.length}`);
      }

      if (!tag) {
        throw new Error('Missing authentication tag for GCM mode');
      }

      const decipher = createDecipheriv('aes-256-gcm', keyBuffer, iv);
      decipher.setAuthTag(tag);

      if (aadBuffer) {
        decipher.setAAD(aadBuffer);
      }

      let plaintext = decipher.update(encrypted.ciphertext, 'base64', 'utf-8');
      plaintext += decipher.final('utf-8');

      return {
        plaintext,
        success: true,
      };
    } catch (error) {
      return {
        plaintext: '',
        success: false,
        error: String(error),
      };
    }
  }

  /**
   * Derive key from password using PBKDF2
   */
  static deriveKeyFromPassword(password: string, salt?: Buffer): { key: Buffer; salt: Buffer } {
    const crypto = require('crypto');
    const saltBuffer = salt || randomBytes(this.SALT_LENGTH);
    const derivedKey = crypto.pbkdf2Sync(password, saltBuffer, 100000, 32, 'sha256');
    return { key: derivedKey, salt: saltBuffer };
  }
}
