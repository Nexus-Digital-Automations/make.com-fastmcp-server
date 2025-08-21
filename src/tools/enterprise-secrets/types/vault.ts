/**
 * @fileoverview Vault-related type definitions for enterprise secrets management
 * Contains interfaces and types for HashiCorp Vault integration
 */

export interface VaultClusterInfo {
  clusterId: string;
  nodes: Array<{
    nodeId: string;
    address: string;
    status: 'active' | 'standby' | 'sealed' | 'uninitialized' | 'error';
    version: string;
    lastHeartbeat: Date;
  }>;
  leaderNode: string;
  sealStatus: {
    sealed: boolean;
    threshold: number;
    shares: number;
    progress: number;
  };
  initializationStatus: boolean;
  performanceMetrics: {
    requestsPerSecond: number;
    averageLatencyMs: number;
    errorRate: number;
    activeConnections: number;
  };
}

export interface SecretEngineStatus {
  path: string;
  type: string;
  version: string;
  description: string;
  uuid: string;
  config: Record<string, unknown>;
  local: boolean;
  sealWrap: boolean;
  externalEntropyAccess: boolean;
  health: {
    status: 'healthy' | 'degraded' | 'unhealthy';
    lastCheck: Date;
    metrics: {
      operationsPerSecond: number;
      averageLatencyMs: number;
      errorRate: number;
    };
  };
}

export interface KeyRotationStatus {
  policyName: string;
  lastRotation: Date;
  nextScheduledRotation: Date;
  rotationCount: number;
  status: 'active' | 'paused' | 'failed' | 'pending';
  affectedPaths: string[];
  rotationHistory: Array<{
    timestamp: Date;
    triggerType: string;
    success: boolean;
    details: string;
  }>;
}

/**
 * Type definitions for secret engine configurations
 */
export type SecretEngineType = 'kv' | 'database' | 'pki' | 'transit' | 'aws' | 'azure' | 'gcp' | 'ssh' | 'totp';
export type DatabaseType = 'postgresql' | 'mysql' | 'mongodb' | 'mssql' | 'oracle';
export type KeyType = 'rsa' | 'ec';
export type StorageType = 'consul' | 'raft' | 'postgresql' | 'mysql';
export type ListenerType = 'tcp' | 'unix';
export type SealType = 'shamir' | 'auto' | 'hsm' | 'cloud_kms';
export type ReplicationMode = 'dr' | 'performance' | 'both';

/**
 * Type definitions for key rotation
 */
export type RotationType = 'scheduled' | 'usage_based' | 'event_driven' | 'compliance_driven';
export type RotationStrategy = 'graceful' | 'immediate' | 'versioned' | 'blue_green';

/**
 * Type definitions for dynamic secrets
 */
export type DynamicSecretType = 'database' | 'aws' | 'azure' | 'gcp' | 'ssh' | 'certificate' | 'api_token';
export type AWSCredentialType = 'iam_user' | 'assumed_role' | 'federation_token' | 'session_token';
export type SSHKeyType = 'otp' | 'ca';

/**
 * Type definitions for RBAC capabilities
 */
export type VaultCapability = 'create' | 'read' | 'update' | 'delete' | 'list' | 'sudo' | 'deny';
export type Environment = 'development' | 'staging' | 'production';