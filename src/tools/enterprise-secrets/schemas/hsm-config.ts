/**
 * @fileoverview HSM configuration schemas for enterprise secrets management
 * Contains Zod schemas for Hardware Security Module integration
 */

import { z } from 'zod';

/**
 * HSM Configuration Schema
 */
export const HSMConfigSchema = z.object({
  provider: z.enum(['aws_cloudhsm', 'azure_keyvault', 'pkcs11', 'gemalto', 'thales', 'safenet']),
  config: z.object({
    // PKCS#11 Configuration
    library: z.string().optional(),
    slot: z.number().optional(),
    pin: z.string().optional(),
    keyLabel: z.string().optional(),
    mechanism: z.string().optional(),
    
    // Azure Key Vault Configuration
    tenantId: z.string().optional(),
    clientId: z.string().optional(),
    clientSecret: z.string().optional(),
    vaultName: z.string().optional(),
    keyName: z.string().optional(),
    
    // AWS CloudHSM Configuration
    region: z.string().optional(),
    endpoint: z.string().optional(),
    accessKeyId: z.string().optional(),
    secretAccessKey: z.string().optional(),
    
    // General HSM Configuration
    encryptionAlgorithm: z.enum(['aes256-gcm', 'rsa-2048', 'rsa-4096', 'ecc-p256', 'ecc-p384']).optional(),
    signingAlgorithm: z.enum(['rsa-pss', 'ecdsa-p256', 'ecdsa-p384']).optional(),
  }),
  compliance: z.object({
    fipsLevel: z.enum(['level1', 'level2', 'level3', 'level4']).optional(),
    commonCriteria: z.string().optional(),
    certifications: z.array(z.string()).optional(),
  }),
});