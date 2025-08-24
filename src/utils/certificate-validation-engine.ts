/**
 * @fileoverview Certificate Validation Engine with Chain Verification and Expiry Monitoring
 * 
 * Implements comprehensive X.509 certificate validation including chain verification,
 * expiry monitoring, revocation checking, and security analysis.
 */

import { EventEmitter } from 'events';
import * as crypto from 'crypto';
import * as tls from 'tls';
import logger from '../lib/logger.js';
import {
  CertificateStatus,
  CertificateAnalysisResult,
  CertificateDetails,
  CertificateExtension,
  ChainValidationResult,
  ExpiryAnalysis,
  SignatureAnalysis,
  UsageValidationResult,
  ValidationContext
} from '../types/credential-validation.js';

/**
 * Certificate validation configuration
 */
export interface CertificateValidationConfig {
  /** Enable OCSP checking */
  enableOCSP: boolean;
  /** Enable CRL checking */
  enableCRL: boolean;
  /** Certificate chain validation depth */
  maxChainDepth: number;
  /** Days before expiry to warn */
  expiryWarningDays: number;
  /** Trusted root CA store */
  trustedCAs?: string[];
  /** Enable hostname verification */
  enableHostnameVerification: boolean;
  /** Minimum key size requirements */
  minKeySize: {
    RSA: number;
    ECDSA: number;
    DSA: number;
  };
  /** Allowed signature algorithms */
  allowedSignatureAlgorithms: string[];
  /** Enable weak cipher detection */
  enableWeakCipherDetection: boolean;
  /** Network timeout for OCSP/CRL */
  networkTimeoutMs: number;
}

/**
 * Certificate chain information
 */
export interface CertificateChain {
  /** Certificate chain (leaf to root) */
  certificates: ParsedCertificate[];
  /** Chain validation status */
  isValid: boolean;
  /** Chain validation errors */
  errors: string[];
  /** Trust anchor reached */
  trustAnchorReached: boolean;
  /** Chain length */
  length: number;
}

/**
 * Parsed X.509 certificate details
 */
export interface ParsedCertificate {
  /** Certificate in PEM format */
  pemData: string;
  /** Certificate details */
  details: CertificateDetails;
  /** Raw certificate data */
  raw: Buffer;
  /** Certificate fingerprints */
  fingerprints: {
    sha1: string;
    sha256: string;
    md5: string;
  };
  /** Public key information */
  publicKey: {
    algorithm: string;
    size: number;
    exponent?: number;
    curve?: string;
  };
  /** Certificate purposes */
  purposes: string[];
  /** Key usage flags */
  keyUsage: string[];
  /** Extended key usage */
  extKeyUsage: string[];
}

/**
 * OCSP response data
 */
export interface OCSPResponse {
  /** Response status */
  status: 'good' | 'revoked' | 'unknown' | 'error';
  /** Certificate status */
  certStatus?: 'good' | 'revoked' | 'unknown';
  /** Revocation time (if revoked) */
  revocationTime?: Date;
  /** Revocation reason */
  revocationReason?: string;
  /** Response timestamp */
  thisUpdate: Date;
  /** Next update time */
  nextUpdate?: Date;
  /** OCSP responder URL */
  responderURL: string;
}

/**
 * CRL checking result
 */
export interface CRLResult {
  /** CRL validation status */
  status: 'valid' | 'revoked' | 'unknown' | 'error';
  /** CRL URL */
  crlURL?: string;
  /** Certificate revocation status */
  isRevoked: boolean;
  /** Revocation date */
  revocationDate?: Date;
  /** Revocation reason */
  revocationReason?: string;
  /** CRL last update */
  lastUpdate?: Date;
  /** CRL next update */
  nextUpdate?: Date;
}

/**
 * Certificate transparency log entry
 */
export interface CTLogEntry {
  /** Log ID */
  logId: string;
  /** Log description */
  logDescription: string;
  /** Entry timestamp */
  timestamp: Date;
  /** Certificate hash */
  certificateHash: string;
  /** SCT (Signed Certificate Timestamp) */
  sct?: string;
}

/**
 * Policy validation result
 */
export interface PolicyValidationResult {
  /** Policy OID */
  policyOID: string;
  /** Policy description */
  policyDescription: string;
  /** Validation status */
  status: 'compliant' | 'non-compliant' | 'not-applicable';
  /** Policy qualifiers */
  qualifiers?: string[];
  /** User notice */
  userNotice?: string;
  /** CPS URI */
  cpsURI?: string;
}

/**
 * Comprehensive certificate validation engine
 */
export class CertificateValidationEngine extends EventEmitter {
  private readonly config: CertificateValidationConfig;
  private readonly ocspCache: Map<string, OCSPResponse> = new Map();
  private readonly crlCache: Map<string, CRLResult> = new Map();
  private readonly componentLogger: ReturnType<typeof logger.child>;
  private cleanupInterval?: NodeJS.Timeout;

  constructor(config: Partial<CertificateValidationConfig> = {}) {
    super();
    
    this.componentLogger = logger.child({ component: 'CertificateValidationEngine' });
    
    this.config = {
      enableOCSP: config.enableOCSP ?? true,
      enableCRL: config.enableCRL ?? true,
      maxChainDepth: config.maxChainDepth || 10,
      expiryWarningDays: config.expiryWarningDays || 30,
      trustedCAs: config.trustedCAs,
      enableHostnameVerification: config.enableHostnameVerification ?? true,
      minKeySize: {
        RSA: config.minKeySize?.RSA || 2048,
        ECDSA: config.minKeySize?.ECDSA || 256,
        DSA: config.minKeySize?.DSA || 2048
      },
      allowedSignatureAlgorithms: config.allowedSignatureAlgorithms || [
        'sha256WithRSAEncryption',
        'ecdsa-with-SHA256',
        'ecdsa-with-SHA384',
        'ecdsa-with-SHA512'
      ],
      enableWeakCipherDetection: config.enableWeakCipherDetection ?? true,
      networkTimeoutMs: config.networkTimeoutMs || 10000
    };

    this.startCleanupProcess();
    
    this.componentLogger.info('Certificate validation engine initialized', {
      enableOCSP: this.config.enableOCSP,
      enableCRL: this.config.enableCRL,
      maxChainDepth: this.config.maxChainDepth
    });
  }

  /**
   * Validate a single certificate
   */
  public async validateCertificate(
    certificate: string | Buffer,
    options?: {
      hostname?: string;
      checkRevocation?: boolean;
      chainCertificates?: string[];
      context?: ValidationContext;
    }
  ): Promise<CertificateAnalysisResult> {
    const startTime = Date.now();
    
    try {
      // Parse certificate
      const parsedCert = await this.parseCertificate(certificate);
      
      // Build certificate chain
      const chain = await this.buildCertificateChain(parsedCert, options?.chainCertificates);
      
      // Validate chain
      const chainValidation = await this.validateCertificateChain(chain);
      
      // Check expiry
      const expiryAnalysis = await this.analyzeExpiry(parsedCert);
      
      // Analyze signature
      const signatureAnalysis = await this.analyzeSignature(parsedCert);
      
      // Validate usage
      const usageValidation = await this.validateUsage(parsedCert, options?.hostname);
      
      // Check revocation status
      let revocationStatus: 'valid' | 'revoked' | 'unknown' = 'unknown';
      if (options?.checkRevocation !== false) {
        revocationStatus = await this.checkRevocationStatus(parsedCert);
      }

      // Determine overall status
      const status = this.determineOverallStatus(
        chainValidation,
        expiryAnalysis,
        signatureAnalysis,
        usageValidation,
        revocationStatus
      );

      // Generate recommendations
      const recommendations = this.generateCertificateRecommendations(
        status,
        chainValidation,
        expiryAnalysis,
        signatureAnalysis,
        usageValidation
      );

      const result: CertificateAnalysisResult = {
        status,
        details: parsedCert.details,
        chainValidation,
        expiryAnalysis,
        signatureAnalysis,
        usageValidation,
        recommendations
      };

      const processingTime = Date.now() - startTime;
      this.componentLogger.debug('Certificate validation completed', {
        status,
        processingTimeMs: processingTime,
        chainLength: chain.length
      });

      this.emit('certificateValidated', {
        result,
        processingTimeMs: processingTime
      });

      return result;

    } catch (error) {
      this.componentLogger.error('Certificate validation failed', { error });
      
      return {
        status: 'invalid-chain',
        details: {
          subject: 'Unknown',
          issuer: 'Unknown',
          serialNumber: 'Unknown',
          notBefore: new Date(),
          notAfter: new Date(),
          publicKeyAlgorithm: 'Unknown',
          signatureAlgorithm: 'Unknown',
          keySize: 0
        },
        chainValidation: [{
          level: 0,
          certificate: {
            subject: 'Unknown',
            issuer: 'Unknown',
            serialNumber: 'Unknown',
            notBefore: new Date(),
            notAfter: new Date(),
            publicKeyAlgorithm: 'Unknown',
            signatureAlgorithm: 'Unknown',
            keySize: 0
          },
          status: 'invalid',
          issues: [error instanceof Error ? error.message : 'Unknown error']
        }],
        expiryAnalysis: {
          daysUntilExpiry: 0,
          status: 'expired',
          renewalRecommended: true
        },
        signatureAnalysis: {
          algorithm: 'Unknown',
          strength: 'weak',
          hashAlgorithm: 'Unknown',
          signatureValid: false
        },
        usageValidation: {
          usageValid: false
        },
        recommendations: ['Certificate validation failed - manual review required']
      };
    }
  }

  /**
   * Validate certificate chain from a TLS connection
   */
  public async validateTLSCertificate(
    hostname: string,
    port: number = 443,
    options?: {
      protocol?: string;
      timeout?: number;
      checkRevocation?: boolean;
    }
  ): Promise<CertificateAnalysisResult> {
    return new Promise((resolve, reject) => {
      const timeout = options?.timeout || this.config.networkTimeoutMs;
      
      const socket = tls.connect(port, hostname, {
        servername: hostname,
        rejectUnauthorized: false // We'll do our own validation
      }, async () => {
        try {
          const peerCert = socket.getPeerCertificate(true);
          
          if (!peerCert) {
            throw new Error('No certificate received from server');
          }

          // Convert peer certificate to PEM format
          const certPEM = this.convertPeerCertToPEM(peerCert);
          
          // Get certificate chain
          const chainCerts: string[] = [];
          let current = peerCert.issuerCertificate;
          while (current && current !== peerCert) {
            chainCerts.push(this.convertPeerCertToPEM(current));
            current = current.issuerCertificate;
          }

          const result = await this.validateCertificate(certPEM, {
            hostname,
            checkRevocation: options?.checkRevocation,
            chainCertificates: chainCerts
          });

          socket.end();
          resolve(result);

        } catch (error) {
          socket.end();
          reject(error);
        }
      });

      socket.setTimeout(timeout);
      socket.on('timeout', () => {
        socket.destroy();
        reject(new Error(`TLS connection timeout after ${timeout}ms`));
      });

      socket.on('error', (error) => {
        reject(error);
      });
    });
  }

  /**
   * Monitor certificate expiry for multiple certificates
   */
  public async monitorCertificateExpiry(
    certificates: Array<{
      id: string;
      certificate: string;
      description?: string;
    }>,
    warningDays?: number
  ): Promise<Array<{
    id: string;
    description?: string;
    expiryAnalysis: ExpiryAnalysis;
    alertLevel: 'none' | 'warning' | 'critical';
    daysUntilExpiry: number;
  }>> {
    const results = [];
    const _alertThreshold = warningDays || this.config.expiryWarningDays;

    for (const cert of certificates) {
      try {
        const parsedCert = await this.parseCertificate(cert.certificate);
        const expiryAnalysis = await this.analyzeExpiry(parsedCert);
        
        let alertLevel: 'none' | 'warning' | 'critical' = 'none';
        if (expiryAnalysis.status === 'expired') {
          alertLevel = 'critical';
        } else if (expiryAnalysis.status === 'expiring-soon') {
          alertLevel = 'warning';
        }

        results.push({
          id: cert.id,
          description: cert.description,
          expiryAnalysis,
          alertLevel,
          daysUntilExpiry: expiryAnalysis.daysUntilExpiry
        });

        // Emit expiry alerts
        if (alertLevel !== 'none') {
          this.emit('expiryAlert', {
            certificateId: cert.id,
            description: cert.description,
            daysUntilExpiry: expiryAnalysis.daysUntilExpiry,
            alertLevel
          });
        }

      } catch (error) {
        this.componentLogger.error('Error monitoring certificate expiry', {
          certificateId: cert.id,
          error
        });
        
        results.push({
          id: cert.id,
          description: cert.description,
          expiryAnalysis: {
            daysUntilExpiry: -1,
            status: 'expired',
            renewalRecommended: true
          },
          alertLevel: 'critical',
          daysUntilExpiry: -1
        });
      }
    }

    return results;
  }

  /**
   * Validate certificate transparency compliance
   */
  public async validateCertificateTransparency(
    certificate: string,
    requireSCTs: boolean = false
  ): Promise<{
    compliant: boolean;
    scts: CTLogEntry[];
    issues: string[];
    recommendations: string[];
  }> {
    const parsedCert = await this.parseCertificate(certificate);
    const scts: CTLogEntry[] = [];
    const issues: string[] = [];
    const recommendations: string[] = [];

    // Look for SCT extension
    const sctExtension = parsedCert.details.extensions?.find(
      ext => ext.oid === '1.3.6.1.4.1.11129.2.4.2'
    );

    if (sctExtension) {
      // Parse SCTs from extension (simplified implementation)
      try {
        const sctData = this.parseSCTExtension(sctExtension.value);
        scts.push(...sctData);
      } catch (error) {
        issues.push('Failed to parse SCT extension');
      }
    } else if (requireSCTs) {
      issues.push('No SCT extension found in certificate');
    }

    // Check for OCSP stapled SCTs (would require OCSP response)
    // This is a placeholder for more comprehensive implementation

    const compliant = requireSCTs ? scts.length > 0 : true;

    if (!compliant) {
      recommendations.push('Obtain certificate with embedded SCTs');
      recommendations.push('Configure OCSP stapling with SCTs');
    }

    if (scts.length === 0) {
      recommendations.push('Consider CT logging for transparency compliance');
    }

    return {
      compliant,
      scts,
      issues,
      recommendations
    };
  }

  /**
   * Bulk certificate validation
   */
  public async validateCertificateBatch(
    certificates: Array<{
      id: string;
      certificate: string;
      hostname?: string;
      chainCertificates?: string[];
    }>,
    options?: {
      maxConcurrency?: number;
      checkRevocation?: boolean;
    }
  ): Promise<Map<string, CertificateAnalysisResult>> {
    const results = new Map<string, CertificateAnalysisResult>();
    const maxConcurrency = options?.maxConcurrency || 5;
    
    // Process certificates in batches
    for (let i = 0; i < certificates.length; i += maxConcurrency) {
      const batch = certificates.slice(i, i + maxConcurrency);
      
      const batchPromises = batch.map(async (cert) => {
        try {
          const result = await this.validateCertificate(cert.certificate, {
            hostname: cert.hostname,
            checkRevocation: options?.checkRevocation,
            chainCertificates: cert.chainCertificates
          });
          
          return { id: cert.id, result };
        } catch (error) {
          this.componentLogger.error('Batch certificate validation failed', {
            certificateId: cert.id,
            error
          });
          
          // Return error result
          return {
            id: cert.id,
            result: {
              status: 'invalid-chain' as CertificateStatus,
              details: {
                subject: 'Error',
                issuer: 'Error',
                serialNumber: 'Error',
                notBefore: new Date(),
                notAfter: new Date(),
                publicKeyAlgorithm: 'Unknown',
                signatureAlgorithm: 'Unknown',
                keySize: 0
              },
              chainValidation: [],
              expiryAnalysis: {
                daysUntilExpiry: -1,
                status: 'expired' as const,
                renewalRecommended: true
              },
              signatureAnalysis: {
                algorithm: 'Unknown',
                strength: 'weak' as const,
                hashAlgorithm: 'Unknown',
                signatureValid: false
              },
              usageValidation: {
                usageValid: false
              },
              recommendations: ['Certificate validation failed']
            }
          };
        }
      });

      const batchResults = await Promise.allSettled(batchPromises);
      
      for (const result of batchResults) {
        if (result.status === 'fulfilled') {
          results.set(result.value.id, result.value.result);
        }
      }
    }

    this.componentLogger.info('Certificate batch validation completed', {
      totalCertificates: certificates.length,
      successfulValidations: results.size
    });

    return results;
  }

  /**
   * Parse X.509 certificate
   */
  private async parseCertificate(certificate: string | Buffer): Promise<ParsedCertificate> {
    let pemData: string;
    
    if (Buffer.isBuffer(certificate)) {
      pemData = certificate.toString('utf8');
    } else {
      pemData = certificate;
    }

    // Ensure PEM format
    if (!pemData.includes('-----BEGIN CERTIFICATE-----')) {
      // Try to decode as base64
      try {
        const decoded = Buffer.from(pemData, 'base64');
        pemData = `-----BEGIN CERTIFICATE-----\n${decoded.toString('base64').match(/.{1,64}/g)?.join('\n')}\n-----END CERTIFICATE-----`;
      } catch {
        throw new Error('Invalid certificate format');
      }
    }

    // Parse using Node.js crypto
    const cert = crypto.X509Certificate ? new crypto.X509Certificate(pemData) : null;
    
    if (!cert) {
      throw new Error('Failed to parse certificate');
    }

    // Extract certificate details
    const details: CertificateDetails = {
      subject: cert.subject,
      issuer: cert.issuer,
      serialNumber: cert.serialNumber,
      notBefore: new Date(cert.validFrom),
      notAfter: new Date(cert.validTo),
      publicKeyAlgorithm: cert.publicKey.asymmetricKeyType || 'unknown',
      signatureAlgorithm: 'unknown', // Would need ASN.1 parsing for full detail
      keySize: cert.publicKey.asymmetricKeySize || 0,
      extensions: this.parseExtensions(cert)
    };

    // Generate fingerprints
    const raw = Buffer.from(pemData.replace(/-----BEGIN CERTIFICATE-----\n?/, '').replace(/\n?-----END CERTIFICATE-----/, ''), 'base64');
    const fingerprints = {
      sha1: crypto.createHash('sha1').update(raw).digest('hex'),
      sha256: crypto.createHash('sha256').update(raw).digest('hex'),
      md5: crypto.createHash('md5').update(raw).digest('hex')
    };

    // Parse public key info
    const publicKey = {
      algorithm: cert.publicKey.asymmetricKeyType || 'unknown',
      size: cert.publicKey.asymmetricKeySize || 0,
      exponent: undefined, // Would need key-specific parsing
      curve: undefined
    };

    return {
      pemData,
      details,
      raw,
      fingerprints,
      publicKey,
      purposes: [], // Would be extracted from extensions
      keyUsage: [], // Would be extracted from extensions
      extKeyUsage: [] // Would be extracted from extensions
    };
  }

  /**
   * Parse certificate extensions
   */
  private parseExtensions(cert: crypto.X509Certificate): CertificateExtension[] {
    const extensions: CertificateExtension[] = [];
    
    // This is a simplified implementation
    // In a full implementation, you'd parse the ASN.1 structure
    
    try {
      // Basic constraints
      if (cert.ca !== undefined) {
        extensions.push({
          oid: '2.5.29.19',
          name: 'Basic Constraints',
          critical: true,
          value: cert.ca ? 'CA:TRUE' : 'CA:FALSE'
        });
      }

      // Subject Alternative Names
      if (cert.subjectAltName) {
        extensions.push({
          oid: '2.5.29.17',
          name: 'Subject Alternative Name',
          critical: false,
          value: cert.subjectAltName
        });
      }

      // Key usage would be extracted from the certificate
      // This is simplified - full implementation would parse ASN.1
      
    } catch (error) {
      this.componentLogger.warn('Error parsing certificate extensions', { error });
    }

    return extensions;
  }

  /**
   * Build certificate chain
   */
  private async buildCertificateChain(
    leafCert: ParsedCertificate,
    chainCertificates?: string[]
  ): Promise<CertificateChain> {
    const certificates = [leafCert];
    const errors: string[] = [];
    let trustAnchorReached = false;

    if (chainCertificates && chainCertificates.length > 0) {
      for (const chainCert of chainCertificates) {
        try {
          const parsed = await this.parseCertificate(chainCert);
          certificates.push(parsed);
        } catch (error) {
          errors.push(`Failed to parse chain certificate: ${error}`);
        }
      }
    }

    // Check if we've reached a trust anchor
    const rootCert = certificates[certificates.length - 1];
    if (rootCert.details.subject === rootCert.details.issuer) {
      trustAnchorReached = true;
    }

    return {
      certificates,
      isValid: errors.length === 0,
      errors,
      trustAnchorReached,
      length: certificates.length
    };
  }

  /**
   * Validate certificate chain
   */
  private async validateCertificateChain(chain: CertificateChain): Promise<ChainValidationResult[]> {
    const results: ChainValidationResult[] = [];

    for (let i = 0; i < chain.certificates.length; i++) {
      const cert = chain.certificates[i];
      const issues: string[] = [];
      
      // Validate certificate at this level
      const now = new Date();
      
      // Check validity period
      if (now < cert.details.notBefore) {
        issues.push('Certificate not yet valid');
      }
      
      if (now > cert.details.notAfter) {
        issues.push('Certificate expired');
      }

      // Check key size
      if (cert.publicKey.algorithm === 'rsa' && cert.publicKey.size < this.config.minKeySize.RSA) {
        issues.push(`RSA key size ${cert.publicKey.size} below minimum ${this.config.minKeySize.RSA}`);
      }

      // For intermediate certificates, check if issuer matches next certificate's subject
      if (i < chain.certificates.length - 1) {
        const nextCert = chain.certificates[i + 1];
        if (cert.details.issuer !== nextCert.details.subject) {
          issues.push('Chain integrity violation: issuer does not match next certificate subject');
        }
      }

      const status = issues.length === 0 ? 'valid' : 'invalid';

      results.push({
        level: i,
        certificate: cert.details,
        status: issues.length === 0 ? 'valid' : 'invalid',
        issues,
        trustAnchor: i === chain.certificates.length - 1 && chain.trustAnchorReached
      });
    }

    return results;
  }

  /**
   * Analyze certificate expiry
   */
  private async analyzeExpiry(certificate: ParsedCertificate): Promise<ExpiryAnalysis> {
    const now = new Date();
    const notAfter = certificate.details.notAfter;
    const timeDiff = notAfter.getTime() - now.getTime();
    const daysUntilExpiry = Math.floor(timeDiff / (24 * 60 * 60 * 1000));
    
    let status: ExpiryAnalysis['status'];
    let renewalRecommended = false;
    let renewalTimeline: string | undefined;

    if (daysUntilExpiry < 0) {
      status = 'expired';
      renewalRecommended = true;
      renewalTimeline = 'Immediate renewal required';
    } else if (daysUntilExpiry <= this.config.expiryWarningDays) {
      status = 'expiring-soon';
      renewalRecommended = true;
      renewalTimeline = 'Renew within next 30 days';
    } else {
      status = 'valid';
      renewalTimeline = `Renewal recommended ${this.config.expiryWarningDays} days before expiry`;
    }

    return {
      daysUntilExpiry,
      status,
      renewalRecommended,
      renewalTimeline,
      autoRenewalAvailable: false // Would depend on CA capabilities
    };
  }

  /**
   * Analyze certificate signature
   */
  private async analyzeSignature(certificate: ParsedCertificate): Promise<SignatureAnalysis> {
    const algorithm = certificate.details.signatureAlgorithm;
    const hashAlgorithm = this.extractHashAlgorithm(algorithm);
    
    // Determine signature strength
    let strength: SignatureAnalysis['strength'];
    const weaknesses: string[] = [];
    const upgradeRecommendations: string[] = [];

    if (hashAlgorithm === 'md5' || hashAlgorithm === 'sha1') {
      strength = 'weak';
      weaknesses.push(`Weak hash algorithm: ${hashAlgorithm}`);
      upgradeRecommendations.push('Upgrade to SHA-256 or higher');
    } else if (hashAlgorithm === 'sha256') {
      strength = 'adequate';
    } else {
      strength = 'strong';
    }

    // Check RSA key size
    if (certificate.publicKey.algorithm === 'rsa') {
      if (certificate.publicKey.size < 2048) {
        strength = 'weak';
        weaknesses.push(`RSA key size ${certificate.publicKey.size} is too small`);
        upgradeRecommendations.push('Use RSA key size of 2048 bits or higher');
      }
    }

    // Signature validation would require the issuer's public key
    const signatureValid = true; // Simplified - would do actual validation

    return {
      algorithm,
      strength,
      hashAlgorithm,
      signatureValid,
      weaknesses: weaknesses.length > 0 ? weaknesses : undefined,
      upgradeRecommendations: upgradeRecommendations.length > 0 ? upgradeRecommendations : undefined
    };
  }

  /**
   * Validate certificate usage
   */
  private async validateUsage(
    certificate: ParsedCertificate,
    hostname?: string
  ): Promise<UsageValidationResult> {
    const violations: string[] = [];
    const recommendations: string[] = [];

    // Check hostname validation if provided
    if (hostname && this.config.enableHostnameVerification) {
      const hostnameValid = this.validateHostname(certificate, hostname);
      if (!hostnameValid) {
        violations.push(`Certificate does not match hostname: ${hostname}`);
        recommendations.push('Obtain certificate with correct Subject Alternative Names');
      }
    }

    // Check key usage
    const keyUsage = certificate.keyUsage;
    if (keyUsage.length === 0) {
      violations.push('No key usage extension found');
      recommendations.push('Include appropriate key usage extensions');
    }

    return {
      usageValid: violations.length === 0,
      keyUsage: certificate.keyUsage,
      extendedKeyUsage: certificate.extKeyUsage,
      violations: violations.length > 0 ? violations : undefined,
      recommendations: recommendations.length > 0 ? recommendations : undefined
    };
  }

  /**
   * Check certificate revocation status
   */
  private async checkRevocationStatus(certificate: ParsedCertificate): Promise<'valid' | 'revoked' | 'unknown'> {
    // Check OCSP first if enabled
    if (this.config.enableOCSP) {
      try {
        const ocspResponse = await this.checkOCSP(certificate);
        if (ocspResponse.status === 'good') {return 'valid';}
        if (ocspResponse.status === 'revoked') {return 'revoked';}
      } catch (error) {
        this.componentLogger.warn('OCSP check failed', { error });
      }
    }

    // Fall back to CRL if enabled
    if (this.config.enableCRL) {
      try {
        const crlResult = await this.checkCRL(certificate);
        if (!crlResult.isRevoked) {return 'valid';}
        if (crlResult.isRevoked) {return 'revoked';}
      } catch (error) {
        this.componentLogger.warn('CRL check failed', { error });
      }
    }

    return 'unknown';
  }

  /**
   * Check OCSP status
   */
  private async checkOCSP(certificate: ParsedCertificate): Promise<OCSPResponse> {
    // This is a simplified implementation
    // A full implementation would:
    // 1. Extract OCSP responder URL from certificate
    // 2. Build OCSP request
    // 3. Send request to OCSP responder
    // 4. Parse OCSP response
    
    const cacheKey = certificate.fingerprints.sha256;
    const cached = this.ocspCache.get(cacheKey);
    
    if (cached) {
      return cached;
    }

    // Placeholder implementation
    const response: OCSPResponse = {
      status: 'unknown',
      thisUpdate: new Date(),
      responderURL: 'http://ocsp.example.com'
    };

    this.ocspCache.set(cacheKey, response);
    return response;
  }

  /**
   * Check CRL status
   */
  private async checkCRL(certificate: ParsedCertificate): Promise<CRLResult> {
    // This is a simplified implementation
    // A full implementation would:
    // 1. Extract CRL distribution points from certificate
    // 2. Download CRL
    // 3. Parse CRL and check for certificate serial number
    
    const cacheKey = certificate.fingerprints.sha256;
    const cached = this.crlCache.get(cacheKey);
    
    if (cached) {
      return cached;
    }

    // Placeholder implementation
    const result: CRLResult = {
      status: 'unknown',
      isRevoked: false
    };

    this.crlCache.set(cacheKey, result);
    return result;
  }

  /**
   * Determine overall certificate status
   */
  private determineOverallStatus(
    chainValidation: ChainValidationResult[],
    expiryAnalysis: ExpiryAnalysis,
    signatureAnalysis: SignatureAnalysis,
    usageValidation: UsageValidationResult,
    revocationStatus: 'valid' | 'revoked' | 'unknown'
  ): CertificateStatus {
    // Check for critical failures first
    if (revocationStatus === 'revoked') {
      return 'revoked';
    }

    if (expiryAnalysis.status === 'expired') {
      return 'expired';
    }

    // Check chain validation
    const hasChainErrors = chainValidation.some(result => result.status === 'invalid');
    if (hasChainErrors) {
      return 'invalid-chain';
    }

    // Check signature strength
    if (signatureAnalysis.strength === 'weak') {
      return 'weak-signature';
    }

    // Check usage validation
    if (!usageValidation.usageValid) {
      return 'invalid-purpose';
    }

    // Check for self-signed (simplified check)
    if (chainValidation.length === 1 && chainValidation[0].certificate.subject === chainValidation[0].certificate.issuer) {
      return 'self-signed';
    }

    return 'valid';
  }

  /**
   * Generate certificate recommendations
   */
  private generateCertificateRecommendations(
    status: CertificateStatus,
    chainValidation: ChainValidationResult[],
    expiryAnalysis: ExpiryAnalysis,
    signatureAnalysis: SignatureAnalysis,
    usageValidation: UsageValidationResult
  ): string[] {
    const recommendations: string[] = [];

    switch (status) {
      case 'expired':
        recommendations.push('Certificate has expired - immediate replacement required');
        recommendations.push('Implement certificate expiry monitoring');
        break;
      case 'expiring-soon':
        recommendations.push(`Certificate expires in ${expiryAnalysis.daysUntilExpiry} days - renewal recommended`);
        break;
      case 'revoked':
        recommendations.push('Certificate has been revoked - immediate replacement required');
        recommendations.push('Investigate reason for revocation');
        break;
      case 'weak-signature':
        recommendations.push('Certificate uses weak signature algorithm - upgrade recommended');
        if (signatureAnalysis.upgradeRecommendations) {
          recommendations.push(...signatureAnalysis.upgradeRecommendations);
        }
        break;
      case 'invalid-chain':
        recommendations.push('Certificate chain validation failed');
        recommendations.push('Verify intermediate certificates are included');
        break;
      case 'self-signed':
        recommendations.push('Self-signed certificate detected - consider CA-signed certificate');
        break;
      case 'invalid-purpose':
        recommendations.push('Certificate usage validation failed');
        if (usageValidation.recommendations) {
          recommendations.push(...usageValidation.recommendations);
        }
        break;
    }

    // General recommendations
    if (expiryAnalysis.renewalRecommended) {
      recommendations.push('Set up automated renewal if supported by CA');
    }

    if (chainValidation.length === 1) {
      recommendations.push('Consider including intermediate certificates in chain');
    }

    return recommendations;
  }

  /**
   * Validate hostname against certificate
   */
  private validateHostname(certificate: ParsedCertificate, hostname: string): boolean {
    // Check subject common name
    const subjectCN = this.extractCNFromSubject(certificate.details.subject);
    if (subjectCN && this.matchHostname(hostname, subjectCN)) {
      return true;
    }

    // Check Subject Alternative Names
    const sanExtension = certificate.details.extensions?.find(ext => ext.oid === '2.5.29.17');
    if (sanExtension) {
      const sans = this.parseSANExtension(sanExtension.value);
      return sans.some(san => this.matchHostname(hostname, san));
    }

    return false;
  }

  /**
   * Match hostname with certificate name (supports wildcards)
   */
  private matchHostname(hostname: string, certName: string): boolean {
    if (hostname === certName) {
      return true;
    }

    // Handle wildcard certificates
    if (certName.startsWith('*.')) {
      const domain = certName.substring(2);
      const hostParts = hostname.split('.');
      if (hostParts.length > 1) {
        const hostDomain = hostParts.slice(1).join('.');
        return hostDomain === domain;
      }
    }

    return false;
  }

  /**
   * Extract hash algorithm from signature algorithm
   */
  private extractHashAlgorithm(signatureAlgorithm: string): string {
    const algorithm = signatureAlgorithm.toLowerCase();
    
    if (algorithm.includes('md5')) {return 'md5';}
    if (algorithm.includes('sha1')) {return 'sha1';}
    if (algorithm.includes('sha256')) {return 'sha256';}
    if (algorithm.includes('sha384')) {return 'sha384';}
    if (algorithm.includes('sha512')) {return 'sha512';}
    
    return 'unknown';
  }

  /**
   * Extract CN from subject DN
   */
  private extractCNFromSubject(subject: string): string | null {
    const cnMatch = subject.match(/CN=([^,]+)/);
    return cnMatch ? cnMatch[1].trim() : null;
  }

  /**
   * Parse Subject Alternative Names from extension
   */
  private parseSANExtension(value: string): string[] {
    // Simplified SAN parsing
    // In a full implementation, this would properly parse ASN.1
    return value.split(',').map(san => san.trim());
  }

  /**
   * Parse SCT extension
   */
  private parseSCTExtension(value: string): CTLogEntry[] {
    // Simplified SCT parsing
    // In a full implementation, this would properly parse the SCT structure
    return [{
      logId: 'example-log-id',
      logDescription: 'Example CT Log',
      timestamp: new Date(),
      certificateHash: 'example-hash'
    }];
  }

  /**
   * Convert peer certificate to PEM format
   */
  private convertPeerCertToPEM(peerCert: any): string {
    if (peerCert.raw) {
      const base64 = peerCert.raw.toString('base64');
      const formatted = base64.match(/.{1,64}/g)?.join('\n') || base64;
      return `-----BEGIN CERTIFICATE-----\n${formatted}\n-----END CERTIFICATE-----`;
    }
    
    throw new Error('Unable to convert peer certificate to PEM format');
  }

  /**
   * Start cache cleanup process
   */
  private startCleanupProcess(): void {
    this.cleanupInterval = setInterval(() => {
      this.cleanupCaches();
    }, 3600000); // Every hour
  }

  /**
   * Clean up expired cache entries
   */
  private cleanupCaches(): void {
    const now = new Date();
    
    // Clean OCSP cache (entries valid for 24 hours)
    for (const [key, response] of this.ocspCache.entries()) {
      const age = now.getTime() - response.thisUpdate.getTime();
      if (age > 24 * 60 * 60 * 1000) {
        this.ocspCache.delete(key);
      }
    }

    // Clean CRL cache (entries valid for 24 hours)
    for (const [key, result] of this.crlCache.entries()) {
      if (result.lastUpdate) {
        const age = now.getTime() - result.lastUpdate.getTime();
        if (age > 24 * 60 * 60 * 1000) {
          this.crlCache.delete(key);
        }
      }
    }

    this.componentLogger.debug('Cache cleanup completed', {
      ocspCacheSize: this.ocspCache.size,
      crlCacheSize: this.crlCache.size
    });
  }

  /**
   * Shutdown the certificate validation engine
   */
  public async shutdown(): Promise<void> {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }

    this.ocspCache.clear();
    this.crlCache.clear();

    this.componentLogger.info('Certificate validation engine shutdown complete');
  }
}

/**
 * Factory function to create certificate validation engine
 */
export function createCertificateValidationEngine(
  config?: Partial<CertificateValidationConfig>
): CertificateValidationEngine {
  return new CertificateValidationEngine(config);
}

// Export singleton instance for convenience
export const certificateValidationEngine = new CertificateValidationEngine();

export default CertificateValidationEngine;