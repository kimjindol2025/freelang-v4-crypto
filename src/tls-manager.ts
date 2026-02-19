/**
 * TLS/SSL Manager Module
 */

import * as tls from 'tls';
import { TLSConfig, TLSServerOptions, TLSClientOptions } from './types';

export class TLSManager {
  private static readonly DEFAULT_CIPHERS = [
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_GCM_SHA256',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-RSA-CHACHA20-POLY1305',
    'ECDHE-RSA-AES128-GCM-SHA256',
  ];

  /**
   * Create TLS server
   */
  static createServer(options: TLSServerOptions): tls.Server {
    try {
      const serverOptions: any = {
        key: options.config.key,
        cert: options.config.cert,
        ca: options.config.ca,
        ciphers: options.config.ciphers || this.DEFAULT_CIPHERS.join(':'),
        minVersion: options.config.minVersion || 'TLSv1.2',
        maxVersion: options.config.maxVersion,
        rejectUnauthorized: options.rejectUnauthorized !== false,
        requestCert: options.requestCert || false,
      };

      const server = tls.createServer(serverOptions);

      server.on('secureConnection', (socket: tls.TLSSocket) => {
        console.log('Client connected');
      });

      server.on('clientError', (err: Error) => {
        console.error('Client error:', err);
      });

      server.listen(options.port, options.hostname, () => {
        console.log(`TLS Server listening on ${options.hostname || 'localhost'}:${options.port}`);
      });

      return server;
    } catch (error) {
      throw new Error(`TLS server creation failed: ${String(error)}`);
    }
  }

  /**
   * Create TLS client connection
   */
  static createClient(options: TLSClientOptions): tls.TLSSocket {
    try {
      const socket = tls.connect(
        options.port,
        options.host,
        {
          rejectUnauthorized: options.rejectUnauthorized !== false,
        },
        () => {
          console.log('Connected to TLS server');
        },
      );

      socket.on('error', (err: Error) => {
        console.error('Connection error:', err);
      });

      socket.on('close', () => {
        console.log('Connection closed');
      });

      return socket;
    } catch (error) {
      throw new Error(`TLS client creation failed: ${String(error)}`);
    }
  }

  /**
   * Get TLS session info
   */
  static getSessionInfo(socket: tls.TLSSocket): {
    protocol: string | undefined;
    cipher: string | undefined;
    peerCertificate: any;
    sessionReused: boolean;
  } {
    const protocol = socket.getProtocol?.();
    const cipherName = socket.getCipher?.()?.name;

    return {
      protocol: protocol || undefined,
      cipher: cipherName || undefined,
      peerCertificate: socket.getPeerCertificate?.(),
      sessionReused: socket.isSessionReused?.() || false,
    };
  }

  /**
   * Validate TLS configuration
   */
  static validateConfig(config: TLSConfig): boolean {
    try {
      if (!config.key || !config.cert) {
        throw new Error('Missing key or certificate');
      }

      // Validate PEM format
      if (!config.key.includes('-----BEGIN') || !config.cert.includes('-----BEGIN')) {
        throw new Error('Invalid PEM format');
      }

      return true;
    } catch (error) {
      console.error('TLS config validation failed:', error);
      return false;
    }
  }

  /**
   * Get supported TLS versions
   */
  static getSupportedVersions(): string[] {
    return ['TLSv1.2', 'TLSv1.3'];
  }

  /**
   * Get supported ciphers
   */
  static getSupportedCiphers(): string[] {
    return this.DEFAULT_CIPHERS;
  }

  /**
   * Create HTTPS server options from TLSConfig
   */
  static toHttpsOptions(config: TLSConfig): any {
    return {
      key: config.key,
      cert: config.cert,
      ca: config.ca,
      ciphers: config.ciphers || this.DEFAULT_CIPHERS.join(':'),
      minVersion: config.minVersion || 'TLSv1.2',
      maxVersion: config.maxVersion,
    };
  }

  /**
   * Check TLS certificate expiration
   */
  static checkCertificateExpiration(cert: string): { expired: boolean; expiryDate: Date } {
    try {
      const crypto = require('crypto');
      const certObj = new crypto.X509Certificate(
        Buffer.from(cert.split('\n').slice(1, -2).join(''), 'base64'),
      );

      const expiryDate = new Date(certObj.validTo);
      const now = new Date();

      return {
        expired: now > expiryDate,
        expiryDate,
      };
    } catch (error) {
      throw new Error(`Certificate expiration check failed: ${String(error)}`);
    }
  }
}
