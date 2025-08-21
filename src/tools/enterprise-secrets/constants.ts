/**
 * @fileoverview Enterprise Secrets Management Constants
 * Centralized configuration and constants for the enterprise secrets module
 */

/**
 * Supported Vault versions and compatibility
 */
export const VAULT_VERSIONS = {
  MINIMUM_SUPPORTED: '1.10.0',
  RECOMMENDED: '1.15.0',
  TESTED_VERSIONS: ['1.15.0', '1.14.6', '1.13.10']
} as const;

/**
 * HSM provider configurations
 */
export const HSM_PROVIDERS = {
  AWS_CLOUDHSM: {
    name: 'aws_cloudhsm',
    displayName: 'AWS CloudHSM',
    supportedRegions: ['us-east-1', 'us-west-2', 'eu-west-1'],
    fipsCompliant: true
  },
  AZURE_KEYVAULT: {
    name: 'azure_keyvault',
    displayName: 'Azure Key Vault HSM',
    supportedRegions: ['eastus', 'westus2', 'westeurope'],
    fipsCompliant: true
  },
  PKCS11: {
    name: 'pkcs11',
    displayName: 'PKCS#11 Hardware Token',
    supportedSlots: 'variable',
    fipsCompliant: true
  }
} as const;

/**
 * Security policy defaults and limits
 */
export const SECURITY_POLICIES = {
  PASSWORD: {
    MIN_LENGTH: 12,
    MAX_LENGTH: 128,
    REQUIRE_UPPERCASE: true,
    REQUIRE_LOWERCASE: true,
    REQUIRE_NUMBERS: true,
    REQUIRE_SPECIAL_CHARS: true,
    MAX_AGE_DAYS: 90,
    HISTORY_COUNT: 12
  },
  API_KEYS: {
    MIN_LENGTH: 32,
    MAX_LENGTH: 256,
    DEFAULT_LENGTH: 64,
    ROTATION_INTERVAL_DAYS: 30
  },
  CERTIFICATES: {
    MIN_KEY_SIZE: 2048,
    RECOMMENDED_KEY_SIZE: 4096,
    MAX_VALIDITY_DAYS: 730,
    DEFAULT_VALIDITY_DAYS: 365
  }
} as const;

/**
 * Encryption standards and algorithms
 */
export const ENCRYPTION_STANDARDS = {
  APPROVED_ALGORITHMS: ['AES', 'ChaCha20', 'RSA', 'ECDSA'] as const,
  AES: {
    KEY_SIZES: [128, 192, 256] as const,
    MODES: ['GCM', 'CBC', 'CTR'] as const,
    RECOMMENDED_KEY_SIZE: 256,
    RECOMMENDED_MODE: 'GCM'
  },
  RSA: {
    MIN_KEY_SIZE: 2048,
    RECOMMENDED_KEY_SIZE: 4096,
    MAX_KEY_SIZE: 8192
  },
  HASH_ALGORITHMS: ['SHA-256', 'SHA-384', 'SHA-512'] as const
} as const;

/**
 * Network security configuration
 */
export const NETWORK_SECURITY = {
  TLS: {
    MIN_VERSION: '1.2',
    RECOMMENDED_VERSION: '1.3',
    SUPPORTED_VERSIONS: ['1.2', '1.3'] as const
  },
  CIPHER_SUITES: {
    APPROVED: [
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES128-GCM-SHA256',
      'ECDHE-RSA-CHACHA20-POLY1305'
    ] as const,
    PROHIBITED: ['RC4', 'DES', '3DES', 'MD5'] as const
  }
} as const;

/**
 * Compliance framework requirements
 */
export const COMPLIANCE_FRAMEWORKS = {
  SOC2: {
    name: 'SOC 2',
    auditRequired: true,
    encryptionRequired: true,
    accessControlRequired: true,
    retentionPeriod: 2555 // 7 years in days
  },
  PCI_DSS: {
    name: 'PCI DSS',
    auditRequired: true,
    encryptionRequired: true,
    keyRotationRequired: true,
    retentionPeriod: 1095 // 3 years in days
  },
  GDPR: {
    name: 'GDPR',
    auditRequired: true,
    dataMinimizationRequired: true,
    rightToErasure: true,
    retentionPeriod: 'varies'
  },
  FIPS_140_2: {
    name: 'FIPS 140-2',
    cryptoModuleRequired: true,
    levels: ['level1', 'level2', 'level3', 'level4'] as const,
    recommendedLevel: 'level2'
  }
} as const;

/**
 * Default timeouts and limits
 */
export const OPERATION_LIMITS = {
  TIMEOUTS: {
    VAULT_CONNECT: 30000, // 30 seconds
    HSM_CONNECT: 60000,   // 60 seconds
    KEY_GENERATION: 120000, // 2 minutes
    AUDIT_LOG_WRITE: 5000   // 5 seconds
  },
  RETRIES: {
    MAX_ATTEMPTS: 3,
    BACKOFF_MS: 1000,
    MAX_BACKOFF_MS: 10000
  },
  RATE_LIMITS: {
    API_REQUESTS_PER_MINUTE: 1000,
    KEY_OPERATIONS_PER_HOUR: 100,
    AUDIT_EVENTS_PER_SECOND: 10
  }
} as const;

/**
 * Secret engine configurations
 */
export const SECRET_ENGINES = {
  KV: {
    name: 'kv',
    version: 2,
    description: 'Key-Value secrets engine',
    maxVersions: 10
  },
  DATABASE: {
    name: 'database',
    description: 'Dynamic database credentials',
    supportedDatabases: ['postgresql', 'mysql', 'mongodb', 'redis'] as const
  },
  PKI: {
    name: 'pki',
    description: 'Public Key Infrastructure',
    maxTtl: '8760h', // 1 year
    defaultTtl: '720h' // 30 days
  },
  AWS: {
    name: 'aws',
    description: 'AWS dynamic credentials',
    supportedCredentialTypes: ['iam_user', 'assumed_role', 'federation_token'] as const
  }
} as const;

/**
 * Audit event severity levels
 */
export const AUDIT_SEVERITY = {
  LOW: {
    level: 'low',
    color: 'green',
    requiresImmediateAction: false
  },
  MEDIUM: {
    level: 'medium',
    color: 'yellow',
    requiresImmediateAction: false
  },
  HIGH: {
    level: 'high',
    color: 'orange',
    requiresImmediateAction: true
  },
  CRITICAL: {
    level: 'critical',
    color: 'red',
    requiresImmediateAction: true
  }
} as const;

/**
 * Error codes for enterprise secrets operations
 */
export const ERROR_CODES = {
  VAULT: {
    CONNECTION_FAILED: 'VAULT_001',
    AUTHENTICATION_FAILED: 'VAULT_002',
    CONFIGURATION_INVALID: 'VAULT_003',
    CLUSTER_UNREACHABLE: 'VAULT_004'
  },
  HSM: {
    CONNECTION_FAILED: 'HSM_001',
    PROVIDER_UNSUPPORTED: 'HSM_002',
    KEY_GENERATION_FAILED: 'HSM_003',
    COMPLIANCE_VIOLATION: 'HSM_004'
  },
  SECURITY: {
    POLICY_VIOLATION: 'SEC_001',
    WEAK_ENCRYPTION: 'SEC_002',
    CERTIFICATE_INVALID: 'SEC_003',
    ACCESS_DENIED: 'SEC_004'
  },
  AUDIT: {
    LOG_WRITE_FAILED: 'AUD_001',
    COMPLIANCE_CHECK_FAILED: 'AUD_002',
    RETENTION_VIOLATION: 'AUD_003'
  }
} as const;

/**
 * Module metadata and versioning
 */
export const MODULE_METADATA = {
  NAME: 'Enterprise Secrets Management',
  VERSION: '2.0.0',
  API_VERSION: 'v2',
  AUTHOR: 'FastMCP Enterprise Team',
  LICENSE: 'Enterprise',
  COMPATIBILITY: {
    MINIMUM_NODE_VERSION: '18.0.0',
    MINIMUM_TYPESCRIPT_VERSION: '5.0.0'
  },
  FEATURES: {
    VAULT_INTEGRATION: true,
    HSM_SUPPORT: true,
    COMPLIANCE_REPORTING: true,
    AUDIT_LOGGING: true,
    KEY_ROTATION: true,
    RBAC: true,
    SECRET_SCANNING: true,
    BREACH_DETECTION: true
  }
} as const;

/**
 * Environment variable names
 */
export const ENV_VARS = {
  VAULT_ADDR: 'VAULT_ADDR',
  VAULT_TOKEN: 'VAULT_TOKEN',
  HSM_PROVIDER: 'HSM_PROVIDER',
  AUDIT_LOG_LEVEL: 'AUDIT_LOG_LEVEL',
  COMPLIANCE_MODE: 'COMPLIANCE_MODE',
  ENCRYPTION_KEY: 'ENTERPRISE_ENCRYPTION_KEY'
} as const;