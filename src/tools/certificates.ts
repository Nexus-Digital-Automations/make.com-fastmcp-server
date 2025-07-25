/**
 * Certificate and Key Management Tools for Make.com FastMCP Server
 * Comprehensive tools for managing certificates, keys, and cryptographic assets
 */

import { FastMCP, UserError } from 'fastmcp';
import { z } from 'zod';
import MakeApiClient from '../lib/make-api-client.js';
import logger from '../lib/logger.js';

// Certificate and key management types
export interface MakeCertificate {
  id: number;
  name: string;
  description?: string;
  type: 'ssl' | 'client' | 'ca' | 'signing' | 'encryption';
  format: 'pem' | 'der' | 'pkcs12' | 'jks';
  organizationId?: number;
  teamId?: number;
  status: 'active' | 'inactive' | 'expired' | 'revoked' | 'pending';
  certificate: {
    data: string; // Base64 encoded certificate data
    fingerprint: string;
    serialNumber: string;
    subject: {
      commonName: string;
      organization?: string;
      organizationalUnit?: string;
      country?: string;
      state?: string;
      locality?: string;
    };
    issuer: {
      commonName: string;
      organization?: string;
      organizationalUnit?: string;
      country?: string;
      state?: string;
      locality?: string;
    };
    validity: {
      notBefore: string;
      notAfter: string;
      daysUntilExpiry: number;
    };
    extensions: {
      keyUsage?: string[];
      extendedKeyUsage?: string[];
      subjectAltNames?: string[];
      isCA: boolean;
    };
  };
  privateKey?: {
    hasPrivateKey: boolean;
    keyType?: 'rsa' | 'ecdsa' | 'ed25519';
    keySize?: number;
    isEncrypted: boolean;
  };
  usage: {
    connections: number;
    scenarios: number;
    lastUsed?: string;
  };
  security: {
    isSecure: boolean;
    vulnerabilities: Array<{
      severity: 'low' | 'medium' | 'high' | 'critical';
      type: string;
      description: string;
    }>;
    complianceStatus: {
      fips: boolean;
      commonCriteria: boolean;
      customCompliance?: string[];
    };
  };
  createdAt: string;
  updatedAt: string;
  createdBy: number;
  createdByName: string;
}

export interface MakeKey {
  id: number;
  name: string;
  description?: string;
  type: 'rsa' | 'ecdsa' | 'ed25519' | 'aes' | 'hmac';
  keyUsage: 'signing' | 'encryption' | 'key_agreement' | 'authentication';
  format: 'pem' | 'der' | 'jwk' | 'raw';
  organizationId?: number;
  teamId?: number;
  status: 'active' | 'inactive' | 'compromised' | 'rotated';
  keyMaterial: {
    hasPublicKey: boolean;
    hasPrivateKey: boolean;
    keySize: number;
    isEncrypted: boolean;
    encryptionAlgorithm?: string;
  };
  metadata: {
    algorithm: string;
    curve?: string; // For ECDSA keys
    hashAlgorithm?: string;
    saltLength?: number; // For RSA-PSS
  };
  rotation: {
    rotationSchedule?: {
      enabled: boolean;
      intervalDays: number;
      nextRotation?: string;
    };
    rotationHistory: Array<{
      rotatedAt: string;
      reason: string;
      oldKeyId: string;
      rotatedBy: number;
    }>;
  };
  permissions: {
    read: string[];
    use: string[];
    admin: string[];
  };
  usage: {
    operations: number;
    connections: number;
    lastUsed?: string;
  };
  createdAt: string;
  updatedAt: string;
  createdBy: number;
}

// Input validation schemas
const CertificateCreateSchema = z.object({
  name: z.string().min(1).max(100).describe('Certificate name (1-100 characters)'),
  description: z.string().max(500).optional().describe('Certificate description (max 500 characters)'),
  type: z.enum(['ssl', 'client', 'ca', 'signing', 'encryption']).describe('Certificate type'),
  format: z.enum(['pem', 'der', 'pkcs12', 'jks']).default('pem').describe('Certificate format'),
  organizationId: z.number().min(1).optional().describe('Organization ID (for organization certificates)'),
  teamId: z.number().min(1).optional().describe('Team ID (for team certificates)'),
  certificateData: z.string().min(1).describe('Certificate data (Base64 encoded or PEM format)'),
  privateKeyData: z.string().optional().describe('Private key data (Base64 encoded or PEM format)'),
  password: z.string().optional().describe('Password for encrypted private key or PKCS12'),
  chainCertificates: z.array(z.string()).optional().describe('Certificate chain (intermediate certificates)'),
  validateCertificate: z.boolean().default(true).describe('Validate certificate before storing'),
  autoRotation: z.object({
    enabled: z.boolean().default(false).describe('Enable automatic rotation'),
    daysBeforeExpiry: z.number().min(1).max(365).default(30).describe('Days before expiry to rotate'),
  }).optional().describe('Auto-rotation settings'),
}).strict();


const CertificateListSchema = z.object({
  type: z.enum(['ssl', 'client', 'ca', 'signing', 'encryption', 'all']).default('all').describe('Filter by certificate type'),
  status: z.enum(['active', 'inactive', 'expired', 'revoked', 'pending', 'all']).default('all').describe('Filter by certificate status'),
  organizationId: z.number().min(1).optional().describe('Filter by organization ID'),
  teamId: z.number().min(1).optional().describe('Filter by team ID'),
  expiringDays: z.number().min(0).max(365).optional().describe('Filter certificates expiring within N days'),
  searchQuery: z.string().max(100).optional().describe('Search in certificate names and subjects'),
  includePrivateKeys: z.boolean().default(false).describe('Include private key information'),
  includeChain: z.boolean().default(false).describe('Include certificate chain information'),
  limit: z.number().min(1).max(1000).default(100).describe('Maximum number of certificates to return'),
  offset: z.number().min(0).default(0).describe('Number of certificates to skip for pagination'),
  sortBy: z.enum(['name', 'createdAt', 'expiryDate', 'usage', 'status']).default('name').describe('Sort field'),
  sortOrder: z.enum(['asc', 'desc']).default('asc').describe('Sort order'),
}).strict();

const KeyCreateSchema = z.object({
  name: z.string().min(1).max(100).describe('Key name (1-100 characters)'),
  description: z.string().max(500).optional().describe('Key description (max 500 characters)'),
  type: z.enum(['rsa', 'ecdsa', 'ed25519', 'aes', 'hmac']).describe('Key type'),
  usage: z.enum(['signing', 'encryption', 'key_agreement', 'authentication']).describe('Key usage'),
  format: z.enum(['pem', 'der', 'jwk', 'raw']).default('pem').describe('Key format'),
  organizationId: z.number().min(1).optional().describe('Organization ID (for organization keys)'),
  teamId: z.number().min(1).optional().describe('Team ID (for team keys)'),
  keyMaterial: z.object({
    generate: z.boolean().default(false).describe('Generate new key pair'),
    keySize: z.number().min(256).max(4096).optional().describe('Key size in bits (for RSA/AES)'),
    curve: z.enum(['P-256', 'P-384', 'P-521', 'secp256k1']).optional().describe('Curve for EC keys'),
    publicKeyData: z.string().optional().describe('Public key data (if importing)'),
    privateKeyData: z.string().optional().describe('Private key data (if importing)'),
    symmetricKeyData: z.string().optional().describe('Symmetric key data (for AES/HMAC)'),
    password: z.string().optional().describe('Password for encrypted key'),
  }).describe('Key material configuration'),
  metadata: z.object({
    hashAlgorithm: z.enum(['SHA256', 'SHA384', 'SHA512']).default('SHA256').describe('Hash algorithm'),
    saltLength: z.number().min(0).optional().describe('Salt length for RSA-PSS'),
  }).optional().describe('Key metadata'),
  rotation: z.object({
    enabled: z.boolean().default(false).describe('Enable automatic rotation'),
    intervalDays: z.number().min(30).max(365).default(90).describe('Rotation interval in days'),
  }).optional().describe('Key rotation settings'),
  permissions: z.object({
    read: z.array(z.string()).default([]).describe('User/team IDs with read access'),
    use: z.array(z.string()).default([]).describe('User/team IDs with usage access'),
    admin: z.array(z.string()).default([]).describe('User/team IDs with admin access'),
  }).default({}).describe('Key permissions'),
}).strict();

const CertificateValidateSchema = z.object({
  certificateData: z.string().min(1).describe('Certificate data to validate'),
  privateKeyData: z.string().optional().describe('Private key data (if available)'),
  chainCertificates: z.array(z.string()).optional().describe('Certificate chain to validate'),
  checkRevocation: z.boolean().default(true).describe('Check certificate revocation status'),
  checkHostname: z.string().optional().describe('Hostname to validate against certificate'),
  customValidations: z.array(z.enum(['key_usage', 'extended_key_usage', 'basic_constraints', 'san'])).optional().describe('Custom validation checks'),
}).strict();

/**
 * Add certificate and key management tools to FastMCP server
 */
export function addCertificateTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'CertificateTools' });
  
  componentLogger.info('Adding certificate and key management tools');

  // Create certificate
  server.addTool({
    name: 'create-certificate',
    description: 'Create and store a new certificate with optional private key',
    parameters: CertificateCreateSchema,
    execute: async (input, { log, reportProgress }) => {
      const { name, description, type, format, organizationId, teamId, certificateData, privateKeyData, password, chainCertificates, validateCertificate, autoRotation } = input;

      log.info('Creating certificate', {
        name,
        type,
        format,
        hasPrivateKey: !!privateKeyData,
        hasChain: !!chainCertificates?.length,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        // Validate certificate data if requested
        if (validateCertificate) {
          log.info('Validating certificate data');
          const validationResponse = await apiClient.post('/certificates/validate', {
            certificateData,
            privateKeyData,
            chainCertificates,
          });

          if (!validationResponse.success) {
            throw new UserError(`Certificate validation failed: ${validationResponse.error?.message || 'Invalid certificate'}`);
          }

          reportProgress({ progress: 25, total: 100 });
        }

        const certificateCreateData = {
          name,
          description,
          type,
          format,
          organizationId,
          teamId,
          certificateData,
          privateKeyData,
          password,
          chainCertificates,
          autoRotation: autoRotation || { enabled: false, daysBeforeExpiry: 30 },
        };

        reportProgress({ progress: 50, total: 100 });

        let endpoint = '/certificates';
        if (organizationId) {
          endpoint = `/organizations/${organizationId}/certificates`;
        } else if (teamId) {
          endpoint = `/teams/${teamId}/certificates`;
        }

        const response = await apiClient.post(endpoint, certificateCreateData);

        if (!response.success) {
          throw new UserError(`Failed to create certificate: ${response.error?.message || 'Unknown error'}`);
        }

        const certificate = response.data as MakeCertificate;
        if (!certificate) {
          throw new UserError('Certificate creation failed - no data returned');
        }

        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully created certificate', {
          certificateId: certificate.id,
          name: certificate.name,
          type: certificate.type,
          expiryDays: certificate.certificate.validity.daysUntilExpiry,
        });

        return JSON.stringify({
          certificate: {
            ...certificate,
            certificate: {
              ...certificate.certificate,
              data: '[CERTIFICATE_DATA_STORED]', // Mask the actual certificate data
            },
            privateKey: certificate.privateKey ? {
              ...certificate.privateKey,
              data: '[PRIVATE_KEY_STORED]', // Never expose private key data
            } : undefined,
          },
          message: `Certificate "${name}" created successfully`,
          analysis: {
            type: certificate.type,
            format: certificate.format,
            subject: certificate.certificate.subject.commonName,
            issuer: certificate.certificate.issuer.commonName,
            validity: {
              notBefore: certificate.certificate.validity.notBefore,
              notAfter: certificate.certificate.validity.notAfter,
              daysUntilExpiry: certificate.certificate.validity.daysUntilExpiry,
            },
            hasPrivateKey: certificate.privateKey?.hasPrivateKey || false,
            isCA: certificate.certificate.extensions.isCA,
            keyUsage: certificate.certificate.extensions.keyUsage,
          },
          security: {
            isSecure: certificate.security.isSecure,
            vulnerabilityCount: certificate.security.vulnerabilities.length,
            compliance: certificate.security.complianceStatus,
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error creating certificate', { name, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to create certificate: ${errorMessage}`);
      }
    },
  });

  // List certificates
  server.addTool({
    name: 'list-certificates',
    description: 'List and filter certificates with comprehensive information and security analysis',
    parameters: CertificateListSchema,
    execute: async (input, { log }) => {
      const { type, status, organizationId, teamId, expiringDays, searchQuery, includePrivateKeys, includeChain, limit, offset, sortBy, sortOrder } = input;

      log.info('Listing certificates', {
        type,
        status,
        expiringDays,
        searchQuery,
        limit,
        offset,
      });

      try {
        const params: Record<string, unknown> = {
          limit,
          offset,
          sortBy,
          sortOrder,
          includePrivateKeys,
          includeChain,
        };

        if (type !== 'all') params.type = type;
        if (status !== 'all') params.status = status;
        if (organizationId) params.organizationId = organizationId;
        if (teamId) params.teamId = teamId;
        if (expiringDays !== undefined) params.expiringDays = expiringDays;
        if (searchQuery) params.search = searchQuery;

        const response = await apiClient.get('/certificates', { params });

        if (!response.success) {
          throw new UserError(`Failed to list certificates: ${response.error?.message || 'Unknown error'}`);
        }

        const certificates = response.data as MakeCertificate[] || [];
        const metadata = response.metadata;

        log.info('Successfully retrieved certificates', {
          count: certificates.length,
          total: metadata?.total,
        });

        // Create security and expiry analysis
        const securityAnalysis = {
          totalCertificates: metadata?.total || certificates.length,
          typeBreakdown: certificates.reduce((acc: Record<string, number>, cert) => {
            acc[cert.type] = (acc[cert.type] || 0) + 1;
            return acc;
          }, {}),
          statusBreakdown: certificates.reduce((acc: Record<string, number>, cert) => {
            acc[cert.status] = (acc[cert.status] || 0) + 1;
            return acc;
          }, {}),
          expiryAnalysis: {
            expiringSoon: certificates.filter(c => c.certificate.validity.daysUntilExpiry <= 30).length,
            expiredCount: certificates.filter(c => c.status === 'expired').length,
            validCount: certificates.filter(c => c.status === 'active').length,
            averageDaysUntilExpiry: certificates.length > 0 ? 
              certificates.reduce((sum, c) => sum + c.certificate.validity.daysUntilExpiry, 0) / certificates.length : 0,
          },
          securitySummary: {
            secureCertificates: certificates.filter(c => c.security.isSecure).length,
            vulnerableCertificates: certificates.filter(c => c.security.vulnerabilities.length > 0).length,
            highRiskCertificates: certificates.filter(c => 
              c.security.vulnerabilities.some(v => v.severity === 'high' || v.severity === 'critical')
            ).length,
            certificatesWithPrivateKeys: certificates.filter(c => c.privateKey?.hasPrivateKey).length,
          },
          complianceStatus: {
            fipsCompliant: certificates.filter(c => c.security.complianceStatus.fips).length,
            commonCriteriaCompliant: certificates.filter(c => c.security.complianceStatus.commonCriteria).length,
          },
          mostUsedCertificates: certificates
            .sort((a, b) => (b.usage.connections + b.usage.scenarios) - (a.usage.connections + a.usage.scenarios))
            .slice(0, 5)
            .map(c => ({
              id: c.id,
              name: c.name,
              totalUsage: c.usage.connections + c.usage.scenarios,
              connections: c.usage.connections,
              scenarios: c.usage.scenarios,
            })),
        };

        return JSON.stringify({
          certificates: certificates.map(cert => ({
            ...cert,
            certificate: {
              ...cert.certificate,
              data: '[CERTIFICATE_DATA_HIDDEN]',
            },
            privateKey: cert.privateKey ? {
              ...cert.privateKey,
              data: '[PRIVATE_KEY_HIDDEN]',
            } : undefined,
          })),
          analysis: securityAnalysis,
          pagination: {
            total: metadata?.total || certificates.length,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + certificates.length),
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error listing certificates', { error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to list certificates: ${errorMessage}`);
      }
    },
  });

  // Get certificate details
  server.addTool({
    name: 'get-certificate',
    description: 'Get detailed information about a specific certificate',
    parameters: z.object({
      certificateId: z.number().min(1).describe('Certificate ID to retrieve'),
      includePrivateKey: z.boolean().default(false).describe('Include private key information (not data)'),
      includeChain: z.boolean().default(false).describe('Include certificate chain'),
      includeUsage: z.boolean().default(true).describe('Include usage statistics'),
      performSecurityCheck: z.boolean().default(true).describe('Perform security vulnerability check'),
    }),
    execute: async (input, { log }) => {
      const { certificateId, includePrivateKey, includeChain, includeUsage, performSecurityCheck } = input;

      log.info('Getting certificate details', { certificateId });

      try {
        const params: Record<string, unknown> = {
          includePrivateKey,
          includeChain,
          includeUsage,
          performSecurityCheck,
        };

        const response = await apiClient.get(`/certificates/${certificateId}`, { params });

        if (!response.success) {
          throw new UserError(`Failed to get certificate: ${response.error?.message || 'Unknown error'}`);
        }

        const certificate = response.data as MakeCertificate;
        if (!certificate) {
          throw new UserError(`Certificate with ID ${certificateId} not found`);
        }

        log.info('Successfully retrieved certificate', {
          certificateId,
          name: certificate.name,
          type: certificate.type,
          status: certificate.status,
          expiryDays: certificate.certificate.validity.daysUntilExpiry,
        });

        const responseData: Record<string, unknown> = {
          certificate: {
            ...certificate,
            certificate: {
              ...certificate.certificate,
              data: '[CERTIFICATE_DATA_HIDDEN]',
            },
            privateKey: certificate.privateKey && includePrivateKey ? {
              ...certificate.privateKey,
              data: '[PRIVATE_KEY_HIDDEN]',
            } : undefined,
          },
          metadata: {
            canUse: certificate.status === 'active',
            canRotate: certificate.status === 'active' && certificate.certificate.validity.daysUntilExpiry > 0,
            canRevoke: certificate.status === 'active',
            needsRenewal: certificate.certificate.validity.daysUntilExpiry <= 30,
            isExpired: certificate.status === 'expired',
            securityRisk: certificate.security.vulnerabilities.length > 0,
            complianceStatus: certificate.security.complianceStatus,
          },
        };

        if (includeUsage) {
          responseData.usage = certificate.usage;
        }

        if (performSecurityCheck) {
          responseData.securityReport = {
            isSecure: certificate.security.isSecure,
            vulnerabilities: certificate.security.vulnerabilities,
            recommendations: generateSecurityRecommendations(certificate),
          };
        }

        return JSON.stringify(responseData, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error getting certificate', { certificateId, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to get certificate details: ${errorMessage}`);
      }
    },
  });

  // Validate certificate
  server.addTool({
    name: 'validate-certificate',
    description: 'Validate certificate data, chain, and configuration',
    parameters: CertificateValidateSchema,
    execute: async (input, { log, reportProgress }) => {
      const { certificateData, privateKeyData, chainCertificates, checkRevocation, checkHostname, customValidations } = input;

      log.info('Validating certificate', {
        hasPrivateKey: !!privateKeyData,
        hasChain: !!chainCertificates?.length,
        checkRevocation,
        checkHostname,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        const validationData = {
          certificateData,
          privateKeyData,
          chainCertificates,
          checkRevocation,
          checkHostname,
          customValidations: customValidations || ['key_usage', 'extended_key_usage', 'basic_constraints'],
        };

        reportProgress({ progress: 25, total: 100 });

        const response = await apiClient.post('/certificates/validate', validationData);

        if (!response.success) {
          throw new UserError(`Certificate validation failed: ${response.error?.message || 'Unknown error'}`);
        }

        const validationResult = response.data as Record<string, unknown>;
        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully validated certificate', {
          isValid: validationResult?.isValid,
          errorCount: validationResult?.errors?.length || 0,
          warningCount: validationResult?.warnings?.length || 0,
        });

        return JSON.stringify({
          validation: validationResult,
          summary: {
            isValid: validationResult?.isValid || false,
            certificateInfo: validationResult?.certificateInfo,
            errors: validationResult?.errors || [],
            warnings: validationResult?.warnings || [],
            checksSummary: {
              syntaxValid: validationResult?.checks?.syntax || false,
              keyPairMatch: validationResult?.checks?.keyPairMatch || false,
              chainValid: validationResult?.checks?.chainValid || false,
              revocationStatus: validationResult?.checks?.revocationStatus || 'not_checked',
              hostnameMatch: validationResult?.checks?.hostnameMatch || false,
              customValidationsPassed: validationResult?.checks?.customValidations || 0,
            },
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error validating certificate', { error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to validate certificate: ${errorMessage}`);
      }
    },
  });

  // Create cryptographic key
  server.addTool({
    name: 'create-key',
    description: 'Create or import a cryptographic key for signing, encryption, or authentication',
    parameters: KeyCreateSchema,
    execute: async (input, { log, reportProgress }) => {
      const { name, description, type, usage, format, organizationId, teamId, keyMaterial, metadata, rotation, permissions } = input;

      log.info('Creating cryptographic key', {
        name,
        type,
        usage,
        format,
        generate: keyMaterial.generate,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        const keyCreateData = {
          name,
          description,
          type,
          usage,
          format,
          organizationId,
          teamId,
          keyMaterial,
          metadata: metadata || { hashAlgorithm: 'SHA256' },
          rotation: rotation || { enabled: false, intervalDays: 90 },
          permissions: {
            ...permissions,
            read: permissions?.read ?? [],
            use: permissions?.use ?? [],
            admin: permissions?.admin ?? [],
          },
        };

        reportProgress({ progress: 50, total: 100 });

        let endpoint = '/keys';
        if (organizationId) {
          endpoint = `/organizations/${organizationId}/keys`;
        } else if (teamId) {
          endpoint = `/teams/${teamId}/keys`;
        }

        const response = await apiClient.post(endpoint, keyCreateData);

        if (!response.success) {
          throw new UserError(`Failed to create key: ${response.error?.message || 'Unknown error'}`);
        }

        const key = response.data as MakeKey;
        if (!key) {
          throw new UserError('Key creation failed - no data returned');
        }

        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully created cryptographic key', {
          keyId: key.id,
          name: key.name,
          type: key.type,
          usage: key.usage,
          keySize: key.keyMaterial.keySize,
        });

        return JSON.stringify({
          key: {
            ...key,
            keyMaterial: {
              ...key.keyMaterial,
              // Never expose actual key material
              publicKeyData: key.keyMaterial.hasPublicKey ? '[PUBLIC_KEY_STORED]' : undefined,
              privateKeyData: key.keyMaterial.hasPrivateKey ? '[PRIVATE_KEY_STORED]' : undefined,
            },
          },
          message: `Cryptographic key "${name}" created successfully`,
          configuration: {
            type: key.type,
            usage: key.usage,
            format: key.format,
            keySize: key.keyMaterial.keySize,
            algorithm: key.metadata.algorithm,
            hasPublicKey: key.keyMaterial.hasPublicKey,
            hasPrivateKey: key.keyMaterial.hasPrivateKey,
            isEncrypted: key.keyMaterial.isEncrypted,
          },
          rotation: {
            enabled: key.rotation.rotationSchedule?.enabled || false,
            nextRotation: key.rotation.rotationSchedule?.nextRotation,
            intervalDays: key.rotation.rotationSchedule?.intervalDays,
          },
          permissions: {
            readAccess: key.permissions.read.length,
            useAccess: key.permissions.use.length,
            adminAccess: key.permissions.admin.length,
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error creating key', { name, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to create cryptographic key: ${errorMessage}`);
      }
    },
  });

  // Rotate certificate or key
  server.addTool({
    name: 'rotate-certificate',
    description: 'Rotate a certificate or key with optional backup of the old version',
    parameters: z.object({
      resourceId: z.number().min(1).describe('Certificate or key ID to rotate'),
      resourceType: z.enum(['certificate', 'key']).describe('Type of resource to rotate'),
      rotationMethod: z.enum(['automatic', 'manual', 'emergency']).describe('Rotation method'),
      newData: z.object({
        certificateData: z.string().optional().describe('New certificate data (for manual rotation)'),
        privateKeyData: z.string().optional().describe('New private key data (for manual rotation)'),
        keyMaterial: z.object({
          publicKeyData: z.string().optional(),
          privateKeyData: z.string().optional(),
          symmetricKeyData: z.string().optional(),
        }).optional().describe('New key material (for manual key rotation)'),
      }).optional().describe('New certificate/key data for manual rotation'),
      backupOldVersion: z.boolean().default(true).describe('Create backup of old version'),
      reason: z.string().max(500).describe('Reason for rotation'),
      notifyUsers: z.boolean().default(true).describe('Notify users about the rotation'),
    }),
    execute: async (input, { log, reportProgress }) => {
      const { resourceId, resourceType, rotationMethod, newData, backupOldVersion, reason, notifyUsers } = input;

      log.info('Rotating certificate/key', {
        resourceId,
        resourceType,
        rotationMethod,
        reason,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        const rotationData = {
          resourceType,
          rotationMethod,
          newData,
          backupOldVersion,
          reason,
          notifyUsers,
        };

        reportProgress({ progress: 25, total: 100 });

        const response = await apiClient.post(`/${resourceType}s/${resourceId}/rotate`, rotationData);

        if (!response.success) {
          throw new UserError(`Failed to rotate ${resourceType}: ${response.error?.message || 'Unknown error'}`);
        }

        const rotationResult = response.data;
        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully rotated certificate/key', {
          resourceId,
          resourceType,
          newResourceId: rotationResult?.newResourceId,
          backupId: rotationResult?.backupId,
        });

        return JSON.stringify({
          rotation: rotationResult,
          message: `${resourceType} ${resourceId} rotated successfully`,
          summary: {
            oldResourceId: resourceId,
            newResourceId: rotationResult?.newResourceId,
            backupId: backupOldVersion ? rotationResult?.backupId : null,
            rotationMethod,
            reason,
            rotatedAt: rotationResult?.rotatedAt,
            affectedConnections: rotationResult?.affectedConnections || 0,
            affectedScenarios: rotationResult?.affectedScenarios || 0,
          },
          nextSteps: [
            'Update applications to use the new certificate/key',
            'Test all affected connections and scenarios',
            'Monitor for any issues in the next 24 hours',
            backupOldVersion ? 'Old version backed up and can be restored if needed' : null,
          ].filter(Boolean),
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error rotating certificate/key', { resourceId, resourceType, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to rotate ${resourceType}: ${errorMessage}`);
      }
    },
  });

  componentLogger.info('Certificate and key management tools added successfully');
}

// Helper function to generate security recommendations
function generateSecurityRecommendations(certificate: MakeCertificate): string[] {
  const recommendations: string[] = [];

  if (certificate.certificate.validity.daysUntilExpiry <= 30) {
    recommendations.push('Certificate expires soon - consider renewal or rotation');
  }

  if (certificate.security.vulnerabilities.length > 0) {
    const criticalVulns = certificate.security.vulnerabilities.filter(v => v.severity === 'critical').length;
    const highVulns = certificate.security.vulnerabilities.filter(v => v.severity === 'high').length;
    
    if (criticalVulns > 0) {
      recommendations.push(`Address ${criticalVulns} critical security vulnerabilities immediately`);
    }
    if (highVulns > 0) {
      recommendations.push(`Address ${highVulns} high-severity security vulnerabilities`);
    }
  }

  if (!certificate.security.complianceStatus.fips && certificate.type === 'encryption') {
    recommendations.push('Consider using FIPS-compliant cryptographic algorithms');
  }

  if (certificate.privateKey?.hasPrivateKey && !certificate.privateKey.isEncrypted) {
    recommendations.push('Private key should be encrypted for enhanced security');
  }

  if (certificate.usage.connections === 0 && certificate.usage.scenarios === 0) {
    recommendations.push('Certificate is not being used - consider removing if no longer needed');
  }

  return recommendations;
}

export default addCertificateTools;