/**
 * X509 Certificate Module
 */

import { generateKeyPairSync } from 'crypto';
import { X509Certificate, CertificateRequest, SignedCertificate } from './types';

export class CertificateManager {
  /**
   * Generate self-signed certificate (simplified - uses key pair only)
   */
  static generateSelfSignedCertificate(request: CertificateRequest): SignedCertificate {
    try {
      // Generate RSA key pair
      const { privateKey, publicKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      // Generate mock certificate (in production, use node-forge or similar)
      const now = new Date();
      const expiryDate = new Date(
        Date.now() + (request.validityDays || 365) * 24 * 60 * 60 * 1000,
      );

      const certificateData = {
        subject: this.buildSubjectDN(request),
        issuer: this.buildSubjectDN(request),
        validFrom: now.toISOString(),
        validTo: expiryDate.toISOString(),
        serialNumber: Math.floor(Math.random() * 1000000).toString(16),
      };

      // Create a mock certificate in PEM format
      const certContent = Buffer.from(JSON.stringify(certificateData)).toString('base64');
      const certificate = `-----BEGIN CERTIFICATE-----\n${certContent
        .match(/.{1,64}/g)
        ?.join('\n')}\n-----END CERTIFICATE-----`;

      return {
        certificate,
        privateKey,
        publicKey: publicKey,
        subject: request.commonName,
        issuer: request.commonName,
        validFrom: now,
        validTo: expiryDate,
        fingerprint: this.generateFingerprint(certContent),
        serialNumber: certificateData.serialNumber,
        version: 3,
        extensions: {},
      };
    } catch (error) {
      throw new Error(`Certificate generation failed: ${String(error)}`);
    }
  }

  /**
   * Parse X509 certificate (PEM format)
   */
  static parseCertificate(certificatePEM: string): X509Certificate {
    try {
      // Extract DER from PEM
      const derMatch = certificatePEM.match(
        /-----BEGIN CERTIFICATE-----\s*([\s\S]+?)\s*-----END CERTIFICATE-----/,
      );
      if (!derMatch) throw new Error('Invalid PEM format');

      const der = Buffer.from(derMatch[1], 'base64');

      // Parse basic info (simplified)
      const certObj = new (require('crypto') as any).X509Certificate(der);

      return {
        subject: certObj.subject || 'Unknown',
        issuer: certObj.issuer || 'Unknown',
        validFrom: certObj.validFrom || new Date(),
        validTo: certObj.validTo || new Date(),
        fingerprint: certObj.fingerprint || '',
        publicKey: certObj.publicKey || '',
        serialNumber: certObj.serialNumber || '',
        version: 3,
        extensions: {},
      };
    } catch (error) {
      throw new Error(`Certificate parsing failed: ${String(error)}`);
    }
  }

  /**
   * Verify certificate chain
   */
  static verifyCertificateChain(
    certificatePEM: string,
    caPEM?: string,
  ): boolean {
    try {
      const cert = this.parseCertificate(certificatePEM);

      // Check validity dates
      const now = new Date();
      if (now < cert.validFrom || now > cert.validTo) {
        return false;
      }

      // TODO: Implement full chain verification
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Check if certificate is expired
   */
  static isExpired(certificatePEM: string): boolean {
    try {
      // Extract the certificate data from PEM
      const lines = certificatePEM.split('\n').filter(l => l && !l.includes('BEGIN') && !l.includes('END'));
      if (lines.length === 0) return true;

      const der = Buffer.from(lines.join(''), 'base64');
      let validToStr: string | undefined;

      // Simple parsing: look for common certificate data patterns
      for (let i = 0; i < lines.length; i++) {
        try {
          const certObj = new (require('crypto') as any).X509Certificate(der);
          if (certObj.validTo) {
            const expiryDate = new Date(certObj.validTo);
            return new Date() > expiryDate;
          }
        } catch {
          // Continue with fallback
        }
      }

      // Fallback: assume not expired if we can't parse
      return false;
    } catch {
      return true;
    }
  }

  /**
   * Get certificate expiration days remaining
   */
  static getDaysUntilExpiration(certificatePEM: string): number {
    try {
      const lines = certificatePEM.split('\n').filter(l => l && !l.includes('BEGIN') && !l.includes('END'));
      if (lines.length === 0) return 0;

      const der = Buffer.from(lines.join(''), 'base64');

      try {
        const certObj = new (require('crypto') as any).X509Certificate(der);
        if (certObj.validTo) {
          const expiryDate = new Date(certObj.validTo);
          const now = new Date();
          const diff = expiryDate.getTime() - now.getTime();
          return Math.ceil(diff / (1000 * 60 * 60 * 24));
        }
      } catch {
        // Fallback
      }

      // Assume 365 days if we can't parse
      return 365;
    } catch {
      return 0;
    }
  }

  /**
   * Build subject DN from CertificateRequest
   */
  private static buildSubjectDN(request: CertificateRequest): string {
    const parts: string[] = [];

    if (request.country) parts.push(`C=${request.country}`);
    if (request.state) parts.push(`ST=${request.state}`);
    if (request.locality) parts.push(`L=${request.locality}`);
    if (request.organization) parts.push(`O=${request.organization}`);
    if (request.organizationUnit) parts.push(`OU=${request.organizationUnit}`);
    if (request.commonName) parts.push(`CN=${request.commonName}`);
    if (request.emailAddress) parts.push(`emailAddress=${request.emailAddress}`);

    return parts.join(', ');
  }

  /**
   * Generate certificate fingerprint
   */
  private static generateFingerprint(derBase64: string): string {
    const crypto = require('crypto');
    const der = Buffer.from(derBase64, 'base64');
    const hash = crypto.createHash('sha256');
    hash.update(der);
    return hash.digest('hex').match(/.{1,2}/g)?.join(':') || '';
  }
}
