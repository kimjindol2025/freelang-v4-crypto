/**
 * RSA Encryption Module
 * Supports: RSA 2048-bit encryption and digital signatures
 */

import { generateKeyPairSync, publicEncrypt, privateDecrypt, createSign, createVerify } from 'crypto';
import { RSAKeyPair, RSAEncrypted, RSADecrypted, RSASignature, RSAVerified } from './types';

export class RSACipher {
  /**
   * Generate RSA 2048-bit key pair
   */
  static generateKeyPair(): RSAKeyPair {
    try {
      const { publicKey, privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem',
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem',
        },
      });

      return {
        publicKey,
        privateKey,
      };
    } catch (error) {
      throw new Error(`RSA key generation failed: ${String(error)}`);
    }
  }

  /**
   * Encrypt plaintext using RSA public key (OAEP padding)
   */
  static encryptOAEP(plaintext: string, publicKey: string): RSAEncrypted {
    try {
      const buffer = Buffer.from(plaintext, 'utf-8');
      const encrypted = publicEncrypt(
        {
          key: publicKey,
          padding: require('crypto').constants.RSA_PKCS1_OAEP_PADDING,
        },
        buffer,
      );

      return {
        ciphertext: encrypted.toString('base64'),
        padding: 'oaep',
      };
    } catch (error) {
      throw new Error(`RSA-OAEP encryption failed: ${String(error)}`);
    }
  }

  /**
   * Encrypt plaintext using RSA public key (PKCS1 padding)
   */
  static encryptPKCS1(plaintext: string, publicKey: string): RSAEncrypted {
    try {
      const buffer = Buffer.from(plaintext, 'utf-8');
      const encrypted = publicEncrypt(
        {
          key: publicKey,
          padding: require('crypto').constants.RSA_PKCS1_PADDING,
        },
        buffer,
      );

      return {
        ciphertext: encrypted.toString('base64'),
        padding: 'pkcs1',
      };
    } catch (error) {
      throw new Error(`RSA-PKCS1 encryption failed: ${String(error)}`);
    }
  }

  /**
   * Decrypt ciphertext using RSA private key
   */
  static decrypt(encrypted: RSAEncrypted, privateKey: string): RSADecrypted {
    try {
      const buffer = Buffer.from(encrypted.ciphertext, 'base64');
      const paddingConstant =
        encrypted.padding === 'oaep'
          ? require('crypto').constants.RSA_PKCS1_OAEP_PADDING
          : require('crypto').constants.RSA_PKCS1_PADDING;

      const decrypted = privateDecrypt(
        {
          key: privateKey,
          padding: paddingConstant,
        },
        buffer,
      );

      return {
        plaintext: decrypted.toString('utf-8'),
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
   * Sign message using RSA private key
   */
  static sign(message: string, privateKey: string, algorithm: 'sha256' | 'sha512' = 'sha256'): RSASignature {
    try {
      const signer = createSign(`RSA-SHA${algorithm === 'sha256' ? '256' : '512'}`);
      signer.update(message, 'utf-8');
      const signature = signer.sign(privateKey, 'base64');

      return {
        signature,
        algorithm,
      };
    } catch (error) {
      throw new Error(`RSA signing failed: ${String(error)}`);
    }
  }

  /**
   * Verify RSA signature
   */
  static verify(message: string, signature: RSASignature, publicKey: string): RSAVerified {
    try {
      const verifier = createVerify(
        `RSA-SHA${signature.algorithm === 'sha256' ? '256' : '512'}`,
      );
      verifier.update(message, 'utf-8');
      const valid = verifier.verify(publicKey, Buffer.from(signature.signature, 'base64'));

      return {
        valid,
      };
    } catch (error) {
      return {
        valid: false,
        error: String(error),
      };
    }
  }

  /**
   * Extract public key from private key
   */
  static extractPublicKey(privateKey: string): string {
    try {
      const { publicKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
      });

      // This is a simplified version - in production, parse the private key properly
      // For now, we'll use a helper approach
      const crypto = require('crypto');
      const privateKeyObject = crypto.createPrivateKey(privateKey);
      const publicKeyObject = crypto.createPublicKey(privateKeyObject);

      return publicKeyObject.export({
        type: 'spki',
        format: 'pem',
      });
    } catch (error) {
      throw new Error(`Failed to extract public key: ${String(error)}`);
    }
  }
}
