/**
 * Cryptography & Security System Types
 */

// Hash Algorithm Types
export type HashAlgorithm = 'md5' | 'sha1' | 'sha256' | 'sha512';

export interface HashResult {
  algorithm: HashAlgorithm;
  hash: string;
  hex: string;
  base64: string;
}

// AES Cipher Types
export type AESMode = 'cbc' | 'gcm';
export type AESKeySize = 128 | 192 | 256;

export interface AESEncrypted {
  mode: AESMode;
  keySize: AESKeySize;
  iv: string; // base64
  ciphertext: string; // base64
  tag?: string; // base64 (GCM only)
  aad?: string; // base64 (GCM only)
}

export interface AESDecrypted {
  plaintext: string;
  success: boolean;
  error?: string;
}

// RSA Types
export interface RSAKeyPair {
  publicKey: string; // PEM format
  privateKey: string; // PEM format
}

export interface RSAEncrypted {
  ciphertext: string; // base64
  padding: 'pkcs1' | 'oaep';
}

export interface RSADecrypted {
  plaintext: string;
  success: boolean;
  error?: string;
}

export interface RSASignature {
  signature: string; // base64
  algorithm: 'sha256' | 'sha512';
}

export interface RSAVerified {
  valid: boolean;
  error?: string;
}

// HMAC Types
export interface HMACResult {
  signature: string; // base64
  hex: string;
  algorithm: 'sha256' | 'sha512';
}

// KDF Types (PBKDF2, Bcrypt, Argon2)
export interface PBKDF2Result {
  hash: string; // base64
  salt: string; // base64
  iterations: number;
  keyLength: number;
}

export interface BcryptResult {
  hash: string;
  salt: string;
  rounds: number;
}

export interface Argon2Result {
  hash: string; // base64
  salt: string; // base64
  algorithm: 'argon2i' | 'argon2d' | 'argon2id';
  memory: number; // KiB
  time: number; // iterations
  parallelism: number;
}

// X509 Certificate Types
export interface X509Certificate {
  subject: string;
  issuer: string;
  validFrom: Date;
  validTo: Date;
  fingerprint: string;
  publicKey: string; // PEM format
  serialNumber: string;
  version: number;
  extensions: Record<string, unknown>;
}

export interface CertificateRequest {
  commonName: string;
  organization?: string;
  organizationUnit?: string;
  locality?: string;
  state?: string;
  country?: string;
  emailAddress?: string;
  validityDays?: number;
}

export interface SignedCertificate extends X509Certificate {
  certificate: string; // PEM format
  privateKey: string; // PEM format
}

// TLS/SSL Types
export interface TLSConfig {
  key: string; // PEM format
  cert: string; // PEM format
  ca?: string[]; // PEM format array
  ciphers?: string;
  minVersion?: 'TLSv1.2' | 'TLSv1.3';
  maxVersion?: 'TLSv1.2' | 'TLSv1.3';
}

export interface TLSServerOptions {
  port: number;
  hostname?: string;
  config: TLSConfig;
  rejectUnauthorized?: boolean;
  requestCert?: boolean;
}

export interface TLSClientOptions {
  host: string;
  port: number;
  rejectUnauthorized?: boolean;
}

// Crypto System Statistics
export interface CryptoStatistics {
  totalHashOperations: number;
  totalEncryptOperations: number;
  totalDecryptOperations: number;
  totalSignOperations: number;
  totalVerifyOperations: number;
  averageHashTime: number;
  averageEncryptTime: number;
  averageDecryptTime: number;
  operationsByAlgorithm: Record<string, number>;
}

// Error Types
export class CryptoError extends Error {
  constructor(
    public code: string,
    message: string,
    public details?: unknown,
  ) {
    super(message);
    this.name = 'CryptoError';
  }
}
