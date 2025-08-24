/**
 * Advanced Encryption Types for Concurrent Processing
 * Supports FIPS 140-2 compliant cryptographic operations with HSM integration
 */

export interface CryptoAlgorithmSpec {
  algorithm: 'aes-256-gcm' | 'aes-256-cbc' | 'rsa-4096' | 'ecdsa-p384';
  keyLength: number;
  ivLength?: number;
  tagLength?: number;
  saltLength?: number;
  mode?: 'encrypt' | 'decrypt' | 'sign' | 'verify';
}

export interface EncryptionJobRequest {
  id: string;
  operation: 'encrypt' | 'decrypt' | 'hash' | 'sign' | 'verify' | 'derive_key';
  algorithm: CryptoAlgorithmSpec;
  data: string | Buffer;
  key?: string | Buffer;
  metadata?: {
    userId?: string;
    context?: string;
    priority?: 'low' | 'medium' | 'high' | 'critical';
    timeout?: number;
  };
  hsm?: {
    enabled: boolean;
    keyId?: string;
    provider?: 'aws-kms' | 'azure-keyvault' | 'hashicorp-vault' | 'pkcs11';
  };
}

export interface EncryptionJobResult {
  id: string;
  success: boolean;
  result?: string | Buffer;
  metadata?: {
    algorithm: string;
    keyId?: string;
    processingTime: number;
    workerId: string;
    hsm?: boolean;
  };
  error?: {
    code: string;
    message: string;
    stack?: string;
  };
}

export interface BatchEncryptionRequest {
  batchId: string;
  jobs: EncryptionJobRequest[];
  options: {
    maxConcurrency: number;
    timeout: number;
    failFast?: boolean;
    retryAttempts?: number;
  };
}

export interface BatchEncryptionResult {
  batchId: string;
  totalJobs: number;
  completedJobs: number;
  failedJobs: number;
  processingTime: number;
  results: EncryptionJobResult[];
  errors?: Array<{
    jobId: string;
    error: string;
  }>;
}

export interface ConcurrentWorkerConfig {
  maxWorkers: number;
  queueSize: number;
  workerTimeout: number;
  resourceLimits?: {
    maxOldGenerationSizeMb?: number;
    maxYoungGenerationSizeMb?: number;
    codeRangeSizeMb?: number;
    stackSizeMb?: number;
  };
  isolatedContext: boolean;
}

export interface HSMIntegrationConfig {
  provider: 'aws-kms' | 'azure-keyvault' | 'hashicorp-vault' | 'pkcs11';
  endpoint?: string;
  credentials?: {
    accessKey?: string;
    secretKey?: string;
    region?: string;
    vaultToken?: string;
    clientId?: string;
    clientSecret?: string;
  };
  keyStore?: {
    encryptionKeys: string[];
    signingKeys: string[];
    derivationKeys: string[];
  };
  options?: {
    timeout?: number;
    retryAttempts?: number;
    fallbackToSoftware?: boolean;
  };
}

export interface KeyDerivationParams {
  algorithm: 'pbkdf2' | 'argon2id' | 'scrypt' | 'hkdf';
  salt: Buffer;
  iterations?: number;
  memory?: number; // For Argon2
  parallelism?: number; // For Argon2
  keyLength: number;
  info?: Buffer; // For HKDF
}

export interface DigitalSignatureParams {
  algorithm: 'ecdsa-p384' | 'rsa-pss-4096' | 'ed25519';
  hashAlgorithm: 'sha256' | 'sha384' | 'sha3-256' | 'blake2b';
  encoding: 'der' | 'pem' | 'raw';
}

export interface CryptographicPerformanceMetrics {
  operationType: string;
  algorithm: string;
  dataSize: number;
  processingTime: number;
  throughput: number; // operations per second
  cpuUsage: number;
  memoryUsage: number;
  workerId: string;
  timestamp: Date;
  hsm: boolean;
}

export interface SecurityValidationResult {
  isValid: boolean;
  securityLevel: 'low' | 'medium' | 'high' | 'fips-140-2';
  validations: {
    keyStrength: boolean;
    algorithmCompliance: boolean;
    randomnessQuality: boolean;
    timingAttackResistance: boolean;
    sideChannelResistance: boolean;
  };
  recommendations?: string[];
  warnings?: string[];
}

export interface EncryptionWorkerMessage {
  type: 'job' | 'batch' | 'health_check' | 'shutdown';
  payload: EncryptionJobRequest | BatchEncryptionRequest | { ping: boolean } | { graceful: boolean };
}

export interface WorkerHealthStatus {
  workerId: string;
  status: 'idle' | 'busy' | 'error' | 'offline';
  activeJobs: number;
  totalJobsProcessed: number;
  errorCount: number;
  uptime: number;
  performance: {
    avgProcessingTime: number;
    throughput: number;
    cpuUsage: number;
    memoryUsage: number;
  };
  lastHeartbeat: Date;
}

export interface EncryptionPoolStatus {
  totalWorkers: number;
  activeWorkers: number;
  idleWorkers: number;
  queuedJobs: number;
  processingJobs: number;
  totalJobsProcessed: number;
  successRate: number;
  avgProcessingTime: number;
  peakThroughput: number;
  workerHealthStatus: WorkerHealthStatus[];
}

export interface RandomnessQualityTest {
  source: 'crypto.randomBytes' | 'crypto.webcrypto' | 'hardware-rng' | 'hsm';
  testSuite: 'nist-sp-800-22' | 'diehard' | 'testu01' | 'ent';
  results: {
    monobitTest: { passed: boolean; pValue: number };
    frequencyTest: { passed: boolean; pValue: number };
    runsTest: { passed: boolean; pValue: number };
    longestRunTest: { passed: boolean; pValue: number };
    spectralTest: { passed: boolean; pValue: number };
    serialTest: { passed: boolean; pValue: number };
    approximateEntropyTest: { passed: boolean; pValue: number };
  };
  overallScore: number; // 0-100
  recommendation: 'approved' | 'conditional' | 'rejected';
}

export interface CryptographicAuditLog {
  timestamp: Date;
  operation: string;
  algorithm: string;
  keyId?: string;
  userId?: string;
  sourceIp?: string;
  success: boolean;
  duration: number;
  dataSize?: number;
  securityLevel: string;
  hsm: boolean;
  errorCode?: string;
  metadata?: Record<string, unknown>;
}

export interface KeyManagementLifecycle {
  keyId: string;
  keyType: 'symmetric' | 'asymmetric' | 'derivation';
  algorithm: string;
  keyLength: number;
  status: 'pending' | 'active' | 'rotating' | 'deprecated' | 'compromised' | 'destroyed';
  createdAt: Date;
  activatedAt?: Date;
  lastUsed?: Date;
  rotationSchedule?: {
    interval: number;
    nextRotation: Date;
    gracePeriod: number;
  };
  securityContext: {
    origin: 'software' | 'hsm' | 'external';
    extractable: boolean;
    usage: string[];
    clientPermissions: string[];
  };
  auditTrail: CryptographicAuditLog[];
}

export interface EncryptionAgentConfig {
  name: string;
  specialization: 'symmetric' | 'asymmetric' | 'hashing' | 'key_derivation' | 'digital_signatures';
  maxConcurrentJobs: number;
  supportedAlgorithms: CryptoAlgorithmSpec[];
  hsmIntegration: HSMIntegrationConfig;
  securityProfile: {
    fipsCompliant: boolean;
    quantumResistant: boolean;
    sideChannelProtection: boolean;
    timingAttackMitigation: boolean;
  };
  resourceLimits: {
    maxMemoryMb: number;
    maxCpuPercent: number;
    maxJobsPerSecond: number;
    maxJobSize: number;
  };
  monitoring: {
    performanceMetrics: boolean;
    securityAuditing: boolean;
    randomnessQuality: boolean;
    errorTracking: boolean;
  };
}

export interface MultiAgentEncryptionSystem {
  agents: EncryptionAgentConfig[];
  loadBalancer: {
    algorithm: 'round-robin' | 'least-connections' | 'weighted' | 'performance-based';
    healthCheckInterval: number;
    failoverTimeout: number;
  };
  security: {
    interAgentAuthentication: boolean;
    messageEncryption: boolean;
    auditLogging: boolean;
    accessControl: {
      rbac: boolean;
      permissions: string[];
    };
  };
  performance: {
    globalRateLimit: number;
    priorityQueuing: boolean;
    adaptiveScaling: boolean;
    resourceSharing: boolean;
  };
}

export type CryptographicOperation = 
  | 'encrypt'
  | 'decrypt' 
  | 'hash'
  | 'sign'
  | 'verify'
  | 'derive_key'
  | 'generate_key_pair'
  | 'generate_random'
  | 'validate_key_strength'
  | 'test_randomness_quality';

export type EncryptionAlgorithm = 
  | 'aes-256-gcm'
  | 'aes-256-cbc'
  | 'aes-256-ctr'
  | 'chacha20-poly1305'
  | 'rsa-4096'
  | 'rsa-oaep-4096'
  | 'rsa-pss-4096'
  | 'ecdsa-p384'
  | 'ecdh-p384'
  | 'ed25519'
  | 'x25519';

export type HashAlgorithm = 
  | 'sha256'
  | 'sha384'
  | 'sha512'
  | 'sha3-256'
  | 'sha3-384'
  | 'sha3-512'
  | 'blake2b'
  | 'blake2s';

export type KeyDerivationAlgorithm = 
  | 'pbkdf2'
  | 'argon2id'
  | 'scrypt'
  | 'hkdf'
  | 'bcrypt';

export type HSMProvider = 
  | 'aws-kms'
  | 'azure-keyvault'
  | 'gcp-kms'
  | 'hashicorp-vault'
  | 'pkcs11'
  | 'luna-sa'
  | 'thales-dpod';

export type SecurityLevel = 
  | 'basic'
  | 'standard'
  | 'enhanced' 
  | 'fips-140-2-level-1'
  | 'fips-140-2-level-2'
  | 'fips-140-2-level-3'
  | 'common-criteria-eal4'
  | 'quantum-resistant';