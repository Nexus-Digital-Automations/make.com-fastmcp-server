/**
 * @fileoverview HSM (Hardware Security Module) related type definitions
 * Contains interfaces and types for HSM integration across various providers
 */

export interface HSMStatus {
  provider: string;
  connected: boolean;
  certified: boolean;
  fipsLevel: string;
  keyCount: number;
  operationsPerSecond: number;
  lastHealthCheck: Date;
  errorMessages: string[];
  complianceStatus: {
    fips140: boolean;
    commonCriteria: boolean;
    customCertifications: string[];
  };
}

/**
 * HSM provider types
 */
export type HSMProvider = 'aws_cloudhsm' | 'azure_keyvault' | 'pkcs11' | 'gemalto' | 'thales' | 'safenet';

/**
 * FIPS compliance levels
 */
export type FIPSLevel = 'level1' | 'level2' | 'level3' | 'level4';

/**
 * Encryption algorithms supported by HSMs
 */
export type EncryptionAlgorithm = 'aes256-gcm' | 'rsa-2048' | 'rsa-4096' | 'ecc-p256' | 'ecc-p384';

/**
 * Signing algorithms supported by HSMs
 */
export type SigningAlgorithm = 'rsa-pss' | 'ecdsa-p256' | 'ecdsa-p384';