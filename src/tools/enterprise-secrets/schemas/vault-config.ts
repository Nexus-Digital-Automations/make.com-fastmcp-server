/**
 * @fileoverview Vault configuration schemas for enterprise secrets management
 * Contains Zod schemas for HashiCorp Vault server configuration
 */

import { z } from 'zod';

/**
 * Vault Server Configuration Schema
 */
export const VaultServerConfigSchema = z.object({
  clusterId: z.string().min(1, 'Cluster ID is required'),
  nodeId: z.string().min(1, 'Node ID is required'),
  config: z.object({
    storage: z.object({
      type: z.enum(['consul', 'raft', 'postgresql', 'mysql']),
      config: z.record(z.unknown()),
    }),
    listener: z.object({
      type: z.enum(['tcp', 'unix']),
      address: z.string(),
      tlsConfig: z.object({
        certFile: z.string(),
        keyFile: z.string(),
        caFile: z.string().optional(),
        minVersion: z.string().optional().default('tls12'),
      }),
    }),
    seal: z.object({
      type: z.enum(['shamir', 'auto', 'hsm', 'cloud_kms']),
      config: z.record(z.unknown()),
    }),
    telemetry: z.object({
      prometheusEnabled: z.boolean().optional().default(true),
      statsdAddress: z.string().optional(),
      dogstatsdAddress: z.string().optional(),
    }),
  }),
  highAvailability: z.object({
    enabled: z.boolean().default(true),
    redirectAddress: z.string(),
    clusterAddress: z.string(),
    replicationMode: z.enum(['dr', 'performance', 'both']).optional(),
  }),
});

/**
 * Secret Engine Configuration Schema
 */
export const SecretEngineConfigSchema = z.object({
  engineType: z.enum(['kv', 'database', 'pki', 'transit', 'aws', 'azure', 'gcp', 'ssh', 'totp']),
  path: z.string().min(1, 'Engine path is required'),
  description: z.string().optional(),
  config: z.object({
    // KV Engine Configuration
    version: z.number().optional(),
    maxVersions: z.number().optional(),
    casRequired: z.boolean().optional(),
    deleteVersionAfter: z.string().optional(),
    
    // Database Engine Configuration
    connectionUrl: z.string().optional(),
    username: z.string().optional(),
    password: z.string().optional(),
    databaseType: z.enum(['postgresql', 'mysql', 'mongodb', 'mssql', 'oracle']).optional(),
    
    // PKI Engine Configuration
    commonName: z.string().optional(),
    organization: z.string().optional(),
    country: z.string().optional(),
    ttl: z.string().optional(),
    keyType: z.enum(['rsa', 'ec']).optional(),
    keyBits: z.number().optional(),
    
    // Transit Engine Configuration
    convergentEncryption: z.boolean().optional(),
    deletionAllowed: z.boolean().optional(),
    derived: z.boolean().optional(),
    exportable: z.boolean().optional(),
    
    // Cloud Provider Configuration
    credentialsFile: z.string().optional(),
    project: z.string().optional(),
    region: z.string().optional(),
  }),
});

/**
 * Key Rotation Policy Schema
 */
export const KeyRotationPolicySchema = z.object({
  policyName: z.string().min(1, 'Policy name is required'),
  targetPaths: z.array(z.string()).min(1, 'At least one target path is required'),
  rotationType: z.enum(['scheduled', 'usage_based', 'event_driven', 'compliance_driven']),
  schedule: z.object({
    cronExpression: z.string().optional(),
    intervalHours: z.number().min(1).optional(),
    rotationWindow: z.object({
      start: z.string(),
      end: z.string(),
    }).optional(),
  }),
  rotationCriteria: z.object({
    maxUsageCount: z.number().optional(),
    maxAgeHours: z.number().optional(),
    complianceRequirement: z.string().optional(),
    securityEvents: z.array(z.string()).optional(),
  }),
  rotationStrategy: z.object({
    strategy: z.enum(['graceful', 'immediate', 'versioned', 'blue_green']),
    gracePeriodHours: z.number().optional(),
    rollbackEnabled: z.boolean().optional().default(true),
    notificationEnabled: z.boolean().optional().default(true),
  }),
});

/**
 * Dynamic Secret Generation Schema
 */
export const DynamicSecretConfigSchema = z.object({
  secretType: z.enum(['database', 'aws', 'azure', 'gcp', 'ssh', 'certificate', 'api_token']),
  name: z.string().min(1, 'Secret configuration name is required'),
  config: z.object({
    // Database Dynamic Secrets
    connectionName: z.string().optional(),
    creationStatements: z.array(z.string()).optional(),
    revocationStatements: z.array(z.string()).optional(),
    rollbackStatements: z.array(z.string()).optional(),
    renewStatements: z.array(z.string()).optional(),
    
    // Cloud Provider Dynamic Secrets
    roleArn: z.string().optional(),
    credentialType: z.enum(['iam_user', 'assumed_role', 'federation_token', 'session_token']).optional(),
    policyArns: z.array(z.string()).optional(),
    
    // Certificate Dynamic Secrets
    role: z.string().optional(),
    commonName: z.string().optional(),
    altNames: z.array(z.string()).optional(),
    ipSans: z.array(z.string()).optional(),
    ttl: z.string().optional(),
    
    // SSH Dynamic Secrets
    keyType: z.enum(['otp', 'ca']).optional(),
    defaultUser: z.string().optional(),
    cidrList: z.array(z.string()).optional(),
  }),
  leaseConfig: z.object({
    defaultTtl: z.string().default('1h'),
    maxTtl: z.string().default('24h'),
    renewable: z.boolean().default(true),
  }),
});

/**
 * RBAC Policy Schema
 */
export const RBACPolicySchema = z.object({
  policyName: z.string().min(1, 'Policy name is required'),
  description: z.string().optional(),
  rules: z.array(z.object({
    path: z.string().min(1, 'Path is required'),
    capabilities: z.array(z.enum(['create', 'read', 'update', 'delete', 'list', 'sudo', 'deny'])),
    requiredParameters: z.array(z.string()).optional(),
    allowedParameters: z.record(z.array(z.string())).optional(),
    deniedParameters: z.array(z.string()).optional(),
    minWrappingTtl: z.string().optional(),
    maxWrappingTtl: z.string().optional(),
  })),
  metadata: z.object({
    tenant: z.string().optional(),
    environment: z.enum(['development', 'staging', 'production']).optional(),
    department: z.string().optional(),
    owner: z.string().optional(),
  }).optional(),
});