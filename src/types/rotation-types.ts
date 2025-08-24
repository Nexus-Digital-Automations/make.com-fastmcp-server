/**
 * TypeScript types for comprehensive credential rotation framework
 * Supports concurrent processing, lifecycle management, and external integration
 */

import type { CredentialMetadata } from "../utils/encryption.js";

/**
 * Rotation policy types and scheduling
 */
export interface RotationPolicy {
  id: string;
  name: string;
  type:
    | "time_based"
    | "usage_based"
    | "risk_based"
    | "emergency"
    | "coordinated";
  enabled: boolean;

  // Time-based rotation
  interval?: number; // milliseconds
  schedulePattern?: string; // cron-like pattern

  // Usage-based rotation
  maxOperations?: number;
  maxDataVolume?: number; // bytes

  // Risk-based rotation
  riskThreshold?: number; // 0-100 scale
  securityEventTriggers?: string[];

  // Coordinated rotation
  coordinationGroup?: string;
  dependentServices?: string[];

  // Grace period and transition
  gracePeriod: number; // milliseconds
  notifyBeforeExpiry: number; // milliseconds
  maxAge: number; // maximum credential age before forced rotation

  // Retry and fallback
  maxRetries: number;
  retryInterval: number; // milliseconds
  fallbackPolicy?: string;
}

/**
 * Credential rotation request for batch processing
 */
export interface CredentialRotationRequest {
  credentialId: string;
  policyId: string;
  priority: "low" | "normal" | "high" | "critical" | "emergency";

  // Rotation specifics
  newValue?: string;
  gracePeriod?: number;
  userId?: string;

  // External service integration
  externalServices?: ExternalServiceConfig[];

  // Scheduling
  scheduledFor?: Date;
  dependencies?: string[]; // other credential IDs that must rotate first

  // Validation
  preRotationValidation?: ValidationRule[];
  postRotationValidation?: ValidationRule[];
}

/**
 * External service configuration for credential propagation
 */
export interface ExternalServiceConfig {
  serviceId: string;
  serviceName: string;
  type:
    | "database"
    | "api"
    | "oauth"
    | "certificate"
    | "cloud_service"
    | "custom";

  // Connection details
  endpoint?: string;
  authMethod: "bearer" | "basic" | "oauth2" | "certificate" | "custom";
  authCredentials?: string; // credential ID for service authentication

  // Update configuration
  updateMethod:
    | "rest_api"
    | "database_update"
    | "file_replacement"
    | "custom_script";
  updateEndpoint?: string;
  updatePayload?: Record<string, unknown>;
  customScript?: string;

  // Validation
  healthCheckEndpoint?: string;
  validationTimeout: number; // milliseconds

  // Rollback
  rollbackSupported: boolean;
  rollbackMethod?: string;
}

/**
 * Validation rules for pre/post rotation checks
 */
export interface ValidationRule {
  id: string;
  name: string;
  type: "connectivity" | "authentication" | "authorization" | "custom";

  // Test configuration
  testEndpoint?: string;
  testMethod?: "GET" | "POST" | "PUT" | "DELETE";
  testPayload?: Record<string, unknown>;
  expectedResponse?: Record<string, unknown>;

  // Custom validation
  customValidator?: string; // function name or script

  // Timing
  timeout: number; // milliseconds
  maxRetries: number;
  retryInterval: number; // milliseconds
}

/**
 * Rotation batch for concurrent processing
 */
export interface RotationBatch {
  batchId: string;
  createdAt: Date;
  status:
    | "pending"
    | "processing"
    | "completed"
    | "failed"
    | "partially_failed";

  // Batch configuration
  requests: CredentialRotationRequest[];
  concurrency: number; // max concurrent rotations
  priority: "low" | "normal" | "high" | "critical";

  // Scheduling
  scheduledFor?: Date;
  dependencies?: string[]; // other batch IDs

  // Processing tracking
  startedAt?: Date;
  completedAt?: Date;
  processedCount: number;
  successCount: number;
  failedCount: number;

  // Results
  results?: RotationBatchResult[];
  errors?: RotationError[];
}

/**
 * Result of a rotation batch operation
 */
export interface RotationBatchResult {
  batchId: string;
  totalRequests: number;
  successfulRotations: RotationResult[];
  failedRotations: RotationError[];

  // Performance metrics
  processingTimeMs: number;
  averageRotationTimeMs: number;
  concurrencyAchieved: number;

  // Resource usage
  memoryUsageMB: number;
  cpuUsagePercent: number;

  // Audit information
  auditEvents: AuditEvent[];
}

/**
 * Individual rotation operation result
 */
export interface RotationResult {
  credentialId: string;
  oldCredentialId: string;
  newCredentialId: string;

  // Timing
  startedAt: Date;
  completedAt: Date;
  processingTimeMs: number;

  // External services
  externalServiceUpdates: ExternalServiceUpdate[];

  // Validation results
  preValidationResults: ValidationResult[];
  postValidationResults: ValidationResult[];

  // Audit
  auditEventIds: string[];
}

/**
 * Rotation error information
 */
export interface RotationError {
  credentialId: string;
  errorCode: string;
  errorMessage: string;

  // Error context
  phase:
    | "validation"
    | "rotation"
    | "external_update"
    | "post_validation"
    | "cleanup";
  attemptNumber: number;
  timestamp: Date;

  // Technical details
  stack?: string;
  context?: Record<string, unknown>;

  // Recovery
  recoverable: boolean;
  retryAfter?: Date;
  rollbackRequired: boolean;
  rollbackCompleted?: boolean;
}

/**
 * External service update result
 */
export interface ExternalServiceUpdate {
  serviceId: string;
  serviceName: string;

  // Operation details
  updateMethod: string;
  requestPayload?: Record<string, unknown>;
  responsePayload?: Record<string, unknown>;

  // Timing
  startedAt: Date;
  completedAt: Date;
  responseTimeMs: number;

  // Status
  success: boolean;
  errorMessage?: string;
  httpStatusCode?: number;

  // Rollback
  rollbackId?: string;
  rollbackSupported: boolean;
}

/**
 * Validation result for pre/post rotation checks
 */
export interface ValidationResult {
  ruleId: string;
  ruleName: string;
  success: boolean;

  // Test details
  testEndpoint?: string;
  requestPayload?: Record<string, unknown>;
  responsePayload?: Record<string, unknown>;

  // Timing
  startedAt: Date;
  completedAt: Date;
  responseTimeMs: number;

  // Error information
  errorMessage?: string;
  errorCode?: string;

  // Retry information
  attemptNumber: number;
  finalAttempt: boolean;
}

/**
 * Audit event for rotation operations
 */
export interface AuditEvent {
  id: string;
  timestamp: Date;
  eventType:
    | "rotation_started"
    | "rotation_completed"
    | "rotation_failed"
    | "validation_performed"
    | "external_service_updated"
    | "rollback_initiated"
    | "rollback_completed"
    | "policy_applied";

  // Context
  credentialId: string;
  batchId?: string;
  userId?: string;
  agentId: string;

  // Event details
  description: string;
  metadata: Record<string, unknown>;

  // Security
  ipAddress?: string;
  userAgent?: string;
  sessionId?: string;

  // Correlation
  correlationId: string;
  parentEventId?: string;
}

/**
 * Worker thread message types for inter-agent communication
 */
export interface WorkerMessage {
  type:
    | "rotation_request"
    | "validation_request"
    | "external_update_request"
    | "audit_event"
    | "error_notification"
    | "status_update"
    | "shutdown";

  // Message identification
  messageId: string;
  correlationId: string;
  timestamp: Date;

  // Source and destination
  sourceAgent: string;
  targetAgent: string;

  // Payload
  payload: Record<string, unknown>;

  // Response handling
  requiresResponse: boolean;
  responseTimeout?: number; // milliseconds
  retryCount?: number;
}

/**
 * Worker thread response message
 */
export interface WorkerResponse {
  messageId: string;
  correlationId: string;
  timestamp: Date;

  // Source
  sourceAgent: string;

  // Result
  success: boolean;
  result?: Record<string, unknown>;
  error?: {
    code: string;
    message: string;
    stack?: string;
    context?: Record<string, unknown>;
  };

  // Performance
  processingTimeMs: number;
  resourceUsage?: {
    memoryMB: number;
    cpuPercent: number;
  };
}

/**
 * Rotation agent status and health information
 */
export interface AgentStatus {
  agentId: string;
  agentType:
    | "rotation"
    | "validation"
    | "encryption"
    | "security_monitor"
    | "integration";

  // Status
  status: "starting" | "healthy" | "busy" | "error" | "shutting_down";
  lastHeartbeat: Date;
  startedAt: Date;

  // Performance
  activeOperations: number;
  totalOperationsProcessed: number;
  averageProcessingTimeMs: number;
  errorRate: number; // 0-1 scale

  // Resources
  memoryUsageMB: number;
  cpuUsagePercent: number;
  workerThreadCount: number;

  // Queue status
  pendingMessages: number;
  processedMessages: number;
  failedMessages: number;

  // Health indicators
  lastSuccessfulOperation?: Date;
  lastError?: {
    timestamp: Date;
    message: string;
    code: string;
  };
}

/**
 * Rotation queue configuration and status
 */
export interface RotationQueue {
  queueId: string;
  name: string;
  type: "immediate" | "scheduled" | "batch" | "priority";

  // Configuration
  concurrency: number;
  maxRetries: number;
  retryDelay: number; // milliseconds

  // Status
  status: "active" | "paused" | "draining" | "stopped";
  pendingJobs: number;
  activeJobs: number;
  completedJobs: number;
  failedJobs: number;

  // Performance
  jobsPerMinute: number;
  averageJobTimeMs: number;

  // Health
  lastProcessedJob?: Date;
  lastFailedJob?: Date;
  consecutiveFailures: number;
}

/**
 * Credential lifecycle event
 */
export interface CredentialLifecycleEvent {
  eventId: string;
  credentialId: string;
  eventType:
    | "created"
    | "rotated"
    | "accessed"
    | "expired"
    | "revoked"
    | "migrated";

  // Timing
  timestamp: Date;
  scheduledFor?: Date;

  // Context
  triggeredBy: "policy" | "schedule" | "user" | "system" | "security_event";
  userId?: string;
  systemId?: string;

  // Details
  previousState?: Partial<CredentialMetadata>;
  newState?: Partial<CredentialMetadata>;
  metadata: Record<string, unknown>;

  // Correlation
  batchId?: string;
  policyId?: string;
  parentEventId?: string;
}

/**
 * Configuration for rotation management system
 */
export interface RotationManagerConfig {
  // Worker thread configuration
  maxWorkerThreads: number;
  workerTimeoutMs: number;
  workerHealthCheckIntervalMs: number;

  // Queue configuration
  defaultConcurrency: number;
  maxQueueSize: number;
  priorityLevels: number;

  // Batch processing
  defaultBatchSize: number;
  maxBatchSize: number;
  batchTimeoutMs: number;

  // External service integration
  externalServiceTimeoutMs: number;
  maxExternalServiceRetries: number;
  externalServiceHealthCheckIntervalMs: number;

  // Audit and logging
  auditRetentionDays: number;
  logLevel: "debug" | "info" | "warn" | "error";

  // Performance monitoring
  metricsCollectionIntervalMs: number;
  performanceThresholds: {
    maxRotationTimeMs: number;
    maxMemoryUsageMB: number;
    maxCpuUsagePercent: number;
    maxErrorRate: number;
  };

  // Security
  encryptionKeyRotationIntervalMs: number;
  auditLogEncryption: boolean;
  secureMemoryWipe: boolean;
}

// Export all types as a namespace for organized imports
export namespace RotationTypes {
  export type Policy = RotationPolicy;
  export type Request = CredentialRotationRequest;
  export type Batch = RotationBatch;
  export type Result = RotationResult;
  export type Error = RotationError;
  export type Audit = AuditEvent;
  export type Message = WorkerMessage;
  export type Response = WorkerResponse;
  export type Agent = AgentStatus;
  export type Queue = RotationQueue;
  export type LifecycleEvent = CredentialLifecycleEvent;
  export type Config = RotationManagerConfig;
}

export default RotationTypes;
