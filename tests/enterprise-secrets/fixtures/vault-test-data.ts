/**
 * Test fixture data for enterprise-secrets module
 * Provides secure test data for HSM, Vault, and compliance testing
 */

/**
 * Mock Vault configuration data
 */
export const VAULT_TEST_CONFIG = {
  address: 'https://vault.test.local:8200',
  token: 'test-token-12345',
  namespace: 'test-namespace',
  version: 'v2',
  authMethod: 'token',
  transitEngine: 'transit',
  kvEngine: 'secret',
};

/**
 * Mock HSM configuration data
 */
export const HSM_TEST_CONFIG = {
  pkcs11: {
    library: '/opt/test/lib/libpkcs11.so',
    slot: 0,
    pin: 'test-pin-123',
    label: 'test-hsm-token',
  },
  cloudHsm: {
    clusterId: 'cluster-test12345',
    region: 'us-west-2',
    customerCA: 'test-ca-cert.pem',
    userType: 'CRYPTO_USER',
  },
  azureKeyVault: {
    vaultUrl: 'https://test-vault.vault.azure.net/',
    tenantId: 'test-tenant-id',
    clientId: 'test-client-id',
    keyName: 'test-key',
  },
};

/**
 * Sample secret data for testing
 */
export const SAMPLE_SECRETS = {
  database: {
    type: 'database',
    name: 'test-db-secret',
    data: {
      username: 'db_user',
      password: 'secure_password_123',
      host: 'db.test.local',
      port: 5432,
      database: 'testdb',
    },
    metadata: {
      created: '2025-08-21T18:00:00.000Z',
      version: 1,
      tags: ['database', 'test'],
    },
  },
  apiKey: {
    type: 'api_key',
    name: 'test-api-key',
    data: {
      key: 'test-api-key-abcd1234',
      endpoint: 'https://api.test.local',
      permissions: ['read', 'write'],
    },
    metadata: {
      created: '2025-08-21T18:00:00.000Z',
      version: 1,
      tags: ['api', 'external'],
    },
  },
  certificate: {
    type: 'certificate',
    name: 'test-tls-cert',
    data: {
      certificate: '-----BEGIN CERTIFICATE-----\nTEST_CERT_DATA\n-----END CERTIFICATE-----',
      privateKey: '-----BEGIN PRIVATE KEY-----\nTEST_KEY_DATA\n-----END PRIVATE KEY-----',
      chain: '-----BEGIN CERTIFICATE-----\nTEST_CHAIN_DATA\n-----END CERTIFICATE-----',
    },
    metadata: {
      created: '2025-08-21T18:00:00.000Z',
      version: 1,
      tags: ['tls', 'certificate'],
      expiresAt: '2026-08-21T18:00:00.000Z',
    },
  },
};

/**
 * Mock RBAC policies for testing
 */
export const RBAC_POLICIES = {
  admin: {
    name: 'admin-policy',
    description: 'Full access to all secrets',
    rules: [
      {
        path: 'secret/*',
        capabilities: ['create', 'read', 'update', 'delete', 'list'],
      },
      {
        path: 'auth/*',
        capabilities: ['create', 'read', 'update', 'delete'],
      },
    ],
  },
  developer: {
    name: 'developer-policy',
    description: 'Read access to development secrets',
    rules: [
      {
        path: 'secret/dev/*',
        capabilities: ['read', 'list'],
      },
      {
        path: 'secret/shared/*',
        capabilities: ['read'],
      },
    ],
  },
  auditor: {
    name: 'auditor-policy',
    description: 'Read-only access for compliance auditing',
    rules: [
      {
        path: 'secret/+',
        capabilities: ['read', 'list'],
      },
      {
        path: 'auth/+',
        capabilities: ['read'],
      },
      {
        path: 'sys/audit/*',
        capabilities: ['read', 'list'],
      },
    ],
  },
};

/**
 * Mock audit log entries
 */
export const AUDIT_LOG_ENTRIES = [
  {
    time: '2025-08-21T18:00:01.000Z',
    type: 'response',
    auth: {
      client_token: 'hmac-sha256:test-token-hash',
      accessor: 'test-accessor-123',
      display_name: 'test-user',
      policies: ['default', 'developer-policy'],
    },
    request: {
      id: 'req-123456',
      operation: 'read',
      path: 'secret/data/dev/database',
      remote_address: '192.168.1.100',
    },
    response: {
      status_code: 200,
      data: { metadata: { version: 1 } },
    },
  },
  {
    time: '2025-08-21T18:00:02.000Z',
    type: 'request',
    auth: {
      client_token: 'hmac-sha256:test-token-hash-2',
      accessor: 'test-accessor-456',
      display_name: 'admin-user',
      policies: ['default', 'admin-policy'],
    },
    request: {
      id: 'req-123457',
      operation: 'create',
      path: 'secret/data/prod/api-key',
      remote_address: '192.168.1.101',
      data: { data: { key: 'hmac-sha256:encrypted-key' } },
    },
  },
  {
    time: '2025-08-21T18:00:03.000Z',
    type: 'response',
    auth: null, // Unauthenticated attempt
    request: {
      id: 'req-123458',
      operation: 'read',
      path: 'secret/data/prod/database',
      remote_address: '10.0.0.50',
    },
    response: {
      status_code: 403,
      errors: ['permission denied'],
    },
  },
];

/**
 * Compliance test scenarios
 */
export const COMPLIANCE_SCENARIOS = {
  soc2: {
    name: 'SOC 2 Type II Compliance',
    requirements: [
      'Encryption at rest and in transit',
      'Access logging and monitoring',
      'Role-based access control',
      'Regular security audits',
      'Incident response procedures',
    ],
    testCases: [
      {
        name: 'Secret encryption validation',
        requirement: 'All secrets must be encrypted using approved algorithms',
        test: 'verify_secret_encryption',
      },
      {
        name: 'Access control validation',
        requirement: 'Access to secrets must be role-based and logged',
        test: 'verify_rbac_enforcement',
      },
      {
        name: 'Audit trail completeness',
        requirement: 'All access must be logged with user, time, and action',
        test: 'verify_audit_completeness',
      },
    ],
  },
  pciDss: {
    name: 'PCI DSS Compliance',
    requirements: [
      'Strong cryptography and security protocols',
      'Protect stored cardholder data',
      'Encrypt transmission of cardholder data',
      'Maintain secure systems and applications',
      'Implement strong access control measures',
    ],
    testCases: [
      {
        name: 'Encryption strength validation',
        requirement: 'Use strong cryptography (AES-256, RSA-2048+)',
        test: 'verify_encryption_strength',
      },
      {
        name: 'Key rotation validation',
        requirement: 'Cryptographic keys must be rotated regularly',
        test: 'verify_key_rotation',
      },
      {
        name: 'Access restriction validation',
        requirement: 'Restrict access to cardholder data by business need',
        test: 'verify_access_restrictions',
      },
    ],
  },
  gdpr: {
    name: 'GDPR Compliance',
    requirements: [
      'Data encryption and pseudonymization',
      'Right to be forgotten (data deletion)',
      'Data portability',
      'Privacy by design',
      'Breach notification within 72 hours',
    ],
    testCases: [
      {
        name: 'Data deletion validation',
        requirement: 'Personal data must be deletable upon request',
        test: 'verify_data_deletion',
      },
      {
        name: 'Data encryption validation',
        requirement: 'Personal data must be encrypted or pseudonymized',
        test: 'verify_personal_data_protection',
      },
      {
        name: 'Breach detection validation',
        requirement: 'System must detect and report data breaches',
        test: 'verify_breach_detection',
      },
    ],
  },
};

/**
 * Mock HSM operation responses
 */
export const HSM_MOCK_RESPONSES = {
  generateKey: {
    success: true,
    keyId: 'hsm-key-123456',
    keyType: 'AES-256',
    created: '2025-08-21T18:00:00.000Z',
    attributes: {
      encrypt: true,
      decrypt: true,
      wrap: true,
      unwrap: true,
    },
  },
  encrypt: {
    success: true,
    ciphertext: 'hsm:encrypted:abcd1234567890',
    keyId: 'hsm-key-123456',
    algorithm: 'AES-256-GCM',
    iv: 'random-iv-12345',
  },
  decrypt: {
    success: true,
    plaintext: 'decrypted-secret-data',
    keyId: 'hsm-key-123456',
  },
  sign: {
    success: true,
    signature: 'hsm:signature:xyz789',
    algorithm: 'RSA-PSS-SHA256',
    keyId: 'hsm-signing-key-456',
  },
};

/**
 * Mock Vault API responses
 */
export const VAULT_MOCK_RESPONSES = {
  health: {
    initialized: true,
    sealed: false,
    standby: false,
    performance_standby: false,
    replication_performance_mode: 'disabled',
    replication_dr_mode: 'disabled',
    server_time_utc: 1755800000,
    version: '1.15.0',
  },
  auth: {
    client_token: 'test-token-authenticated',
    accessor: 'test-accessor-auth',
    policies: ['default', 'developer-policy'],
    token_policies: ['default', 'developer-policy'],
    lease_duration: 3600,
    renewable: true,
  },
  secretEngines: {
    'secret/': {
      type: 'kv',
      description: 'key/value secret storage',
      config: { version: 2 },
    },
    'transit/': {
      type: 'transit',
      description: 'encryption as a service',
    },
    'pki/': {
      type: 'pki',
      description: 'certificate authority',
    },
  },
  policies: Object.values(RBAC_POLICIES),
};

/**
 * Security breach simulation data
 */
export const BREACH_SIMULATION_DATA = {
  scenarios: [
    {
      name: 'Unauthorized access attempt',
      description: 'Multiple failed authentication attempts from suspicious IP',
      events: [
        { type: 'auth_failure', ip: '10.0.0.100', count: 5, timespan: '60s' },
        { type: 'auth_failure', ip: '10.0.0.100', count: 10, timespan: '120s' },
        { type: 'account_lockout', user: 'test-user', reason: 'too_many_failures' },
      ],
      expectedAlerts: ['rate_limit', 'account_lockout', 'security_incident'],
    },
    {
      name: 'Data exfiltration attempt',
      description: 'Unusual bulk secret access pattern',
      events: [
        { type: 'bulk_access', user: 'test-user', secrets: 50, timespan: '300s' },
        { type: 'data_export', user: 'test-user', volume: '10MB', format: 'json' },
      ],
      expectedAlerts: ['bulk_access', 'data_export', 'anomaly_detection'],
    },
    {
      name: 'Privilege escalation attempt',
      description: 'User attempting to access secrets beyond permissions',
      events: [
        { type: 'access_denied', user: 'dev-user', path: '/secret/prod/*', count: 3 },
        { type: 'policy_violation', user: 'dev-user', attempted_action: 'admin_operation' },
      ],
      expectedAlerts: ['privilege_escalation', 'policy_violation'],
    },
  ],
};

/**
 * Performance benchmarks for security operations
 */
export const SECURITY_PERFORMANCE_BENCHMARKS = {
  encryption: {
    aes256: { maxLatency: 10, minThroughput: 1000 }, // 10ms max, 1000 ops/sec min
    rsa2048: { maxLatency: 50, minThroughput: 100 }, // 50ms max, 100 ops/sec min
    rsa4096: { maxLatency: 200, minThroughput: 20 }, // 200ms max, 20 ops/sec min
  },
  hashing: {
    sha256: { maxLatency: 5, minThroughput: 5000 }, // 5ms max, 5000 ops/sec min
    bcrypt: { maxLatency: 100, minThroughput: 50 }, // 100ms max, 50 ops/sec min
  },
  vaultOperations: {
    read: { maxLatency: 100, minThroughput: 500 },
    write: { maxLatency: 200, minThroughput: 200 },
    list: { maxLatency: 50, minThroughput: 1000 },
    delete: { maxLatency: 150, minThroughput: 300 },
  },
};