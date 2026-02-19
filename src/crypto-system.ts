/**
 * Unified Cryptography & Security System
 * Combines all crypto modules into a single API
 */

import { HashAlgorithms } from './hash-algorithms';
import { AESCipher } from './aes-cipher';
import { RSACipher } from './rsa-cipher';
import { HMAC } from './hmac';
import { KDF } from './kdf';
import { CertificateManager } from './certificate';
import { TLSManager } from './tls-manager';
import { CryptoStatistics } from './types';

export class CryptoSystem {
  private statistics: CryptoStatistics = {
    totalHashOperations: 0,
    totalEncryptOperations: 0,
    totalDecryptOperations: 0,
    totalSignOperations: 0,
    totalVerifyOperations: 0,
    averageHashTime: 0,
    averageEncryptTime: 0,
    averageDecryptTime: 0,
    operationsByAlgorithm: {},
  };

  /**
   * Hash Algorithms
   */
  readonly hash = {
    md5: (data: string | Buffer) => {
      const start = Date.now();
      const result = HashAlgorithms.md5(data);
      this.updateStats('hash', Date.now() - start, 'md5');
      return result;
    },
    sha1: (data: string | Buffer) => {
      const start = Date.now();
      const result = HashAlgorithms.sha1(data);
      this.updateStats('hash', Date.now() - start, 'sha1');
      return result;
    },
    sha256: (data: string | Buffer) => {
      const start = Date.now();
      const result = HashAlgorithms.sha256(data);
      this.updateStats('hash', Date.now() - start, 'sha256');
      return result;
    },
    sha512: (data: string | Buffer) => {
      const start = Date.now();
      const result = HashAlgorithms.sha512(data);
      this.updateStats('hash', Date.now() - start, 'sha512');
      return result;
    },
  };

  /**
   * AES Encryption
   */
  readonly aes = {
    generateKey: AESCipher.generateKey,
    generateIV: AESCipher.generateIV,
    encryptCBC: (plaintext: string, key: Buffer | string) => {
      const start = Date.now();
      const result = AESCipher.encryptCBC(plaintext, key);
      this.updateStats('encrypt', Date.now() - start, 'aes-cbc');
      return result;
    },
    decryptCBC: (encrypted: any, key: Buffer | string) => {
      const start = Date.now();
      const result = AESCipher.decryptCBC(encrypted, key);
      this.updateStats('decrypt', Date.now() - start, 'aes-cbc');
      return result;
    },
    encryptGCM: (plaintext: string, key: Buffer | string, aad?: string) => {
      const start = Date.now();
      const result = AESCipher.encryptGCM(plaintext, key, aad);
      this.updateStats('encrypt', Date.now() - start, 'aes-gcm');
      return result;
    },
    decryptGCM: (encrypted: any, key: Buffer | string) => {
      const start = Date.now();
      const result = AESCipher.decryptGCM(encrypted, key);
      this.updateStats('decrypt', Date.now() - start, 'aes-gcm');
      return result;
    },
    deriveKeyFromPassword: AESCipher.deriveKeyFromPassword,
  };

  /**
   * RSA Encryption
   */
  readonly rsa = {
    generateKeyPair: RSACipher.generateKeyPair,
    encryptOAEP: (plaintext: string, publicKey: string) => {
      const start = Date.now();
      const result = RSACipher.encryptOAEP(plaintext, publicKey);
      this.updateStats('encrypt', Date.now() - start, 'rsa-oaep');
      return result;
    },
    encryptPKCS1: (plaintext: string, publicKey: string) => {
      const start = Date.now();
      const result = RSACipher.encryptPKCS1(plaintext, publicKey);
      this.updateStats('encrypt', Date.now() - start, 'rsa-pkcs1');
      return result;
    },
    decrypt: (encrypted: any, privateKey: string) => {
      const start = Date.now();
      const result = RSACipher.decrypt(encrypted, privateKey);
      this.updateStats('decrypt', Date.now() - start, 'rsa');
      return result;
    },
    sign: (message: string, privateKey: string, algorithm?: 'sha256' | 'sha512') => {
      const start = Date.now();
      const result = RSACipher.sign(message, privateKey, algorithm);
      this.updateStats('sign', Date.now() - start, 'rsa-sign');
      return result;
    },
    verify: (message: string, signature: any, publicKey: string) => {
      const start = Date.now();
      const result = RSACipher.verify(message, signature, publicKey);
      this.updateStats('verify', Date.now() - start, 'rsa-verify');
      return result;
    },
    extractPublicKey: RSACipher.extractPublicKey,
  };

  /**
   * HMAC
   */
  readonly hmac = {
    sign: (message: string | Buffer, secret: string | Buffer, algorithm?: 'sha256' | 'sha512') => {
      const start = Date.now();
      const result = HMAC.sign(message, secret, algorithm);
      this.updateStats('sign', Date.now() - start, 'hmac');
      return result;
    },
    sha256: (message: string | Buffer, secret: string | Buffer) => {
      const start = Date.now();
      const result = HMAC.sha256(message, secret);
      this.updateStats('sign', Date.now() - start, 'hmac-sha256');
      return result;
    },
    sha512: (message: string | Buffer, secret: string | Buffer) => {
      const start = Date.now();
      const result = HMAC.sha512(message, secret);
      this.updateStats('sign', Date.now() - start, 'hmac-sha512');
      return result;
    },
    verify: HMAC.verify,
  };

  /**
   * KDF
   */
  readonly kdf = {
    pbkdf2: KDF.pbkdf2,
    verifyPBKDF2: KDF.verifyPBKDF2,
    bcrypt: KDF.bcrypt,
    bcryptSync: KDF.bcryptSync,
    verifyBcrypt: KDF.verifyBcrypt,
    verifyBcryptSync: KDF.verifyBcryptSync,
    argon2: KDF.argon2,
    verifyArgon2: KDF.verifyArgon2,
  };

  /**
   * Certificates
   */
  readonly certificates = {
    generateSelfSigned: CertificateManager.generateSelfSignedCertificate,
    parse: CertificateManager.parseCertificate,
    verify: CertificateManager.verifyCertificateChain,
    isExpired: CertificateManager.isExpired,
    getDaysUntilExpiration: CertificateManager.getDaysUntilExpiration,
  };

  /**
   * TLS/SSL
   */
  readonly tls = {
    createServer: TLSManager.createServer,
    createClient: TLSManager.createClient,
    getSessionInfo: TLSManager.getSessionInfo,
    validateConfig: TLSManager.validateConfig,
    getSupportedVersions: TLSManager.getSupportedVersions,
    getSupportedCiphers: TLSManager.getSupportedCiphers,
    toHttpsOptions: TLSManager.toHttpsOptions,
    checkCertificateExpiration: TLSManager.checkCertificateExpiration,
  };

  /**
   * Get cryptography statistics
   */
  getStatistics(): CryptoStatistics {
    return { ...this.statistics };
  }

  /**
   * Reset statistics
   */
  resetStatistics(): void {
    this.statistics = {
      totalHashOperations: 0,
      totalEncryptOperations: 0,
      totalDecryptOperations: 0,
      totalSignOperations: 0,
      totalVerifyOperations: 0,
      averageHashTime: 0,
      averageEncryptTime: 0,
      averageDecryptTime: 0,
      operationsByAlgorithm: {},
    };
  }

  /**
   * Internal: Update statistics
   */
  private updateStats(type: string, time: number, algorithm: string): void {
    this.statistics.operationsByAlgorithm[algorithm] =
      (this.statistics.operationsByAlgorithm[algorithm] || 0) + 1;

    switch (type) {
      case 'hash':
        this.statistics.totalHashOperations++;
        this.statistics.averageHashTime =
          (this.statistics.averageHashTime * (this.statistics.totalHashOperations - 1) + time) /
          this.statistics.totalHashOperations;
        break;
      case 'encrypt':
        this.statistics.totalEncryptOperations++;
        this.statistics.averageEncryptTime =
          (this.statistics.averageEncryptTime *
            (this.statistics.totalEncryptOperations - 1) +
            time) /
          this.statistics.totalEncryptOperations;
        break;
      case 'decrypt':
        this.statistics.totalDecryptOperations++;
        this.statistics.averageDecryptTime =
          (this.statistics.averageDecryptTime *
            (this.statistics.totalDecryptOperations - 1) +
            time) /
          this.statistics.totalDecryptOperations;
        break;
      case 'sign':
        this.statistics.totalSignOperations++;
        break;
      case 'verify':
        this.statistics.totalVerifyOperations++;
        break;
    }
  }
}

export default new CryptoSystem();
