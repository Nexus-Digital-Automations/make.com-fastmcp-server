/**
 * Integration Management Types
 * Comprehensive types for cross-service coordination, API integration, and service health monitoring
 */

import { EventEmitter } from 'events';
import { ApiResponse } from './index.js';

// =====================================
// Core Integration Types
// =====================================

/**
 * Service configuration for integration management
 */
export interface ServiceConfig {
  /** Unique service identifier */
  id: string;
  /** Human-readable service name */
  name: string;
  /** Service type classification */
  type: 'database' | 'api' | 'webhook' | 'storage' | 'messaging' | 'auth' | 'monitoring';
  /** Service version */
  version: string;
  /** Service endpoints configuration */
  endpoints: ServiceEndpoint[];
  /** Authentication configuration */
  authentication: AuthConfig;
  /** Health check configuration */
  healthCheck: HealthCheckConfig;
  /** Circuit breaker configuration */
  circuitBreaker: CircuitBreakerConfig;
  /** Rate limiting configuration */
  rateLimiting: RateLimitConfig;
  /** Timeout configurations */
  timeouts: TimeoutConfig;
  /** Retry configuration */
  retry: RetryConfig;
  /** Service metadata */
  metadata: Record<string, unknown>;
  /** Service tags for categorization */
  tags: string[];
  /** Whether service is enabled */
  enabled: boolean;
  /** Service priority for resource allocation */
  priority: 'low' | 'medium' | 'high' | 'critical';
  /** Service region/location */
  region?: string;
  /** Service SLA requirements */
  sla: ServiceSLA;
}

/**
 * Service endpoint configuration
 */
export interface ServiceEndpoint {
  /** Endpoint identifier */
  id: string;
  /** Endpoint URL */
  url: string;
  /** HTTP method supported */
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  /** Endpoint description */
  description?: string;
  /** Request/response schemas */
  schema?: {
    request?: Record<string, unknown>;
    response?: Record<string, unknown>;
  };
  /** Whether endpoint is active */
  active: boolean;
  /** Endpoint-specific timeout */
  timeout?: number;
  /** Endpoint weight for load balancing */
  weight: number;
  /** Health check path for this endpoint */
  healthCheckPath?: string;
}

/**
 * Authentication configuration
 */
export interface AuthConfig {
  /** Authentication type */
  type: 'none' | 'api_key' | 'oauth2' | 'jwt' | 'basic' | 'custom';
  /** Authentication configuration details */
  config: Record<string, unknown>;
  /** Credential rotation requirements */
  rotation?: {
    enabled: boolean;
    intervalDays: number;
    warningDays: number;
  };
}

/**
 * Health check configuration
 */
export interface HealthCheckConfig {
  /** Whether health checking is enabled */
  enabled: boolean;
  /** Health check interval in milliseconds */
  intervalMs: number;
  /** Health check timeout */
  timeoutMs: number;
  /** Health check endpoint path */
  path: string;
  /** Expected HTTP status codes for healthy service */
  expectedStatusCodes: number[];
  /** Health check method */
  method: 'GET' | 'POST' | 'HEAD';
  /** Custom health check headers */
  headers?: Record<string, string>;
  /** Health check retry attempts */
  retries: number;
  /** Failure threshold before marking unhealthy */
  failureThreshold: number;
  /** Success threshold for recovery */
  recoveryThreshold: number;
}

/**
 * Circuit breaker configuration
 */
export interface CircuitBreakerConfig {
  /** Whether circuit breaker is enabled */
  enabled: boolean;
  /** Failure threshold to open circuit */
  failureThreshold: number;
  /** Success threshold to close circuit */
  successThreshold: number;
  /** Open state timeout in milliseconds */
  openTimeoutMs: number;
  /** Half-open state timeout */
  halfOpenTimeoutMs: number;
  /** Request volume threshold before evaluating failures */
  requestVolumeThreshold: number;
  /** Error percentage threshold */
  errorThresholdPercentage: number;
  /** Monitoring window duration */
  monitoringWindowMs: number;
}

/**
 * Rate limiting configuration
 */
export interface RateLimitConfig {
  /** Whether rate limiting is enabled */
  enabled: boolean;
  /** Maximum requests per window */
  maxRequests: number;
  /** Time window in milliseconds */
  windowMs: number;
  /** Rate limiting strategy */
  strategy: 'fixed_window' | 'sliding_window' | 'token_bucket';
  /** Burst allowance */
  burstSize?: number;
  /** Rate limiting key generator */
  keyGenerator?: string;
}

/**
 * Timeout configuration
 */
export interface TimeoutConfig {
  /** Connection timeout in milliseconds */
  connectionMs: number;
  /** Request timeout in milliseconds */
  requestMs: number;
  /** Keep-alive timeout */
  keepAliveMs: number;
  /** DNS lookup timeout */
  dnsLookupMs?: number;
}

/**
 * Retry configuration
 */
export interface RetryConfig {
  /** Whether retries are enabled */
  enabled: boolean;
  /** Maximum retry attempts */
  maxAttempts: number;
  /** Base delay in milliseconds */
  baseDelayMs: number;
  /** Maximum delay in milliseconds */
  maxDelayMs: number;
  /** Backoff strategy */
  strategy: 'fixed' | 'exponential' | 'linear';
  /** Jitter configuration */
  jitter: {
    enabled: boolean;
    maxMs: number;
  };
  /** Retryable error conditions */
  retryableErrors: string[];
}

/**
 * Service Level Agreement requirements
 */
export interface ServiceSLA {
  /** Target availability percentage */
  availability: number;
  /** Maximum response time in milliseconds */
  maxResponseTimeMs: number;
  /** Target throughput requests per second */
  throughput: number;
  /** Maximum error rate percentage */
  errorRate: number;
  /** Recovery time objective in minutes */
  rtoMinutes: number;
  /** Recovery point objective in minutes */
  rpoMinutes: number;
}

// =====================================
// Service Dependency Management
// =====================================

/**
 * Service dependency graph
 */
export interface ServiceDependencyGraph {
  /** Service nodes in the dependency graph */
  nodes: Map<string, ServiceNode>;
  /** Dependency edges */
  edges: DependencyEdge[];
  /** Update order for coordinated changes */
  updateOrder: string[][];
  /** Critical path services */
  criticalPath: string[];
}

/**
 * Service node in dependency graph
 */
export interface ServiceNode {
  /** Service ID */
  serviceId: string;
  /** Service configuration */
  config: ServiceConfig;
  /** Incoming dependencies */
  dependencies: string[];
  /** Outgoing dependents */
  dependents: string[];
  /** Node criticality score */
  criticality: number;
}

/**
 * Dependency relationship between services
 */
export interface DependencyEdge {
  /** Source service ID */
  from: string;
  /** Target service ID */
  to: string;
  /** Dependency type */
  type: 'hard' | 'soft' | 'optional';
  /** Dependency weight */
  weight: number;
  /** Whether dependency is critical */
  critical: boolean;
}

// =====================================
// Service Health Monitoring
// =====================================

/**
 * Service health status
 */
export interface ServiceHealthStatus {
  /** Service ID */
  serviceId: string;
  /** Current health state */
  status: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  /** Health score (0-100) */
  score: number;
  /** Last health check timestamp */
  lastChecked: Date;
  /** Health check duration */
  responseTime: number;
  /** Health check details */
  details: {
    /** HTTP status code if applicable */
    statusCode?: number;
    /** Response message */
    message?: string;
    /** Additional metrics */
    metrics?: Record<string, number>;
  };
  /** Health trend */
  trend: 'improving' | 'stable' | 'degrading';
  /** Consecutive failure count */
  consecutiveFailures: number;
  /** Consecutive success count */
  consecutiveSuccesses: number;
  /** Health history */
  history: HealthCheckResult[];
}

/**
 * Individual health check result
 */
export interface HealthCheckResult {
  /** Timestamp of health check */
  timestamp: Date;
  /** Health status */
  status: 'healthy' | 'degraded' | 'unhealthy';
  /** Response time in milliseconds */
  responseTime: number;
  /** Error message if unhealthy */
  error?: string;
  /** Additional metrics */
  metrics?: Record<string, number>;
}

/**
 * Service metrics collection
 */
export interface ServiceMetrics {
  /** Service ID */
  serviceId: string;
  /** Metrics timestamp */
  timestamp: Date;
  /** Request metrics */
  requests: {
    total: number;
    successful: number;
    failed: number;
    rate: number;
  };
  /** Response time metrics */
  responseTime: {
    mean: number;
    p50: number;
    p95: number;
    p99: number;
    max: number;
  };
  /** Error metrics */
  errors: {
    total: number;
    rate: number;
    types: Record<string, number>;
  };
  /** Availability metrics */
  availability: {
    uptime: number;
    downtime: number;
    percentage: number;
  };
  /** Circuit breaker metrics */
  circuitBreaker?: {
    state: 'closed' | 'open' | 'half_open';
    failureRate: number;
    requestCount: number;
  };
}

// =====================================
// API Coordination Types
// =====================================

/**
 * API request context for coordination
 */
export interface ApiRequestContext {
  /** Request ID for tracking */
  id: string;
  /** Service ID for the request */
  serviceId: string;
  /** Endpoint ID */
  endpointId: string;
  /** Request priority */
  priority: 'low' | 'normal' | 'high' | 'urgent';
  /** Request timeout */
  timeout: number;
  /** Retry configuration */
  retry?: RetryConfig;
  /** Correlation ID for tracking */
  correlationId?: string;
  /** User/session context */
  userContext?: {
    userId?: string;
    sessionId?: string;
    organizationId?: string;
  };
  /** Request metadata */
  metadata: Record<string, unknown>;
}

/**
 * Batch API operation
 */
export interface BatchApiOperation {
  /** Batch ID */
  id: string;
  /** Individual requests in batch */
  requests: ApiRequestContext[];
  /** Batch execution strategy */
  strategy: 'parallel' | 'sequential' | 'pipeline';
  /** Maximum concurrent requests */
  maxConcurrency: number;
  /** Batch timeout */
  timeout: number;
  /** Failure handling strategy */
  failureStrategy: 'fail_fast' | 'continue_on_error' | 'partial_success';
}

/**
 * API response coordination
 */
export interface ApiResponseContext {
  /** Original request context */
  request: ApiRequestContext;
  /** Response data */
  response: ApiResponse<unknown>;
  /** Response timestamp */
  timestamp: Date;
  /** Response time in milliseconds */
  responseTime: number;
  /** Whether response was cached */
  cached: boolean;
  /** Cache TTL if cached */
  cacheTtl?: number;
  /** Error information if failed */
  error?: {
    code: string;
    message: string;
    retryable: boolean;
    retryAfter?: number;
  };
}

// =====================================
// Integration Context
// =====================================

/**
 * Integration management context
 */
export interface IntegrationContext {
  /** Registered services */
  services: Map<string, ServiceConfig>;
  /** Service dependency graph */
  dependencies: ServiceDependencyGraph;
  /** Credential metadata */
  credentials: Map<string, CredentialMetadata>;
  /** Service health status */
  healthStatus: Map<string, ServiceHealthStatus>;
  /** Circuit breaker states */
  circuitBreakers: Map<string, CircuitBreakerState>;
  /** Active API connections */
  connections: Map<string, ConnectionPool>;
  /** Performance metrics */
  metrics: Map<string, ServiceMetrics>;
  /** Configuration cache */
  configCache: Map<string, unknown>;
}

/**
 * Credential metadata for integration
 */
export interface CredentialMetadata {
  /** Credential ID */
  id: string;
  /** Associated service IDs */
  serviceIds: string[];
  /** Credential type */
  type: string;
  /** Last rotation timestamp */
  lastRotated: Date;
  /** Next rotation due date */
  nextRotation: Date;
  /** Credential status */
  status: 'active' | 'rotating' | 'expired' | 'disabled';
  /** Validation status */
  validated: boolean;
  /** Last validation timestamp */
  lastValidated?: Date;
}

/**
 * Circuit breaker state
 */
export interface CircuitBreakerState {
  /** Service ID */
  serviceId: string;
  /** Current state */
  state: 'closed' | 'open' | 'half_open';
  /** Failure count in current window */
  failureCount: number;
  /** Success count in half-open state */
  successCount: number;
  /** Last state change timestamp */
  lastStateChange: Date;
  /** Next evaluation timestamp */
  nextEvaluation: Date;
  /** Monitoring window start */
  windowStart: Date;
  /** Request count in current window */
  requestCount: number;
}

/**
 * Connection pool for service endpoints
 */
export interface ConnectionPool {
  /** Service ID */
  serviceId: string;
  /** Active connections count */
  activeConnections: number;
  /** Maximum pool size */
  maxPoolSize: number;
  /** Connection pool statistics */
  stats: {
    created: number;
    destroyed: number;
    reused: number;
    timeouts: number;
  };
  /** Pool configuration */
  config: {
    maxIdleTime: number;
    keepAlive: boolean;
    maxSockets: number;
  };
}

// =====================================
// Worker Thread Types
// =====================================

/**
 * Worker message types for integration operations
 */
export interface IntegrationWorkerMessage {
  /** Message type */
  type: 'api_request' | 'health_check' | 'batch_operation' | 'credential_sync' | 'service_discovery';
  /** Message data */
  data: unknown;
  /** Message ID for response correlation */
  id: string;
  /** Worker ID */
  workerId?: string;
  /** Message priority */
  priority: 'low' | 'normal' | 'high' | 'urgent';
  /** Message timeout */
  timeout: number;
}

/**
 * Worker response for integration operations
 */
export interface IntegrationWorkerResponse {
  /** Response type matching request */
  type: string;
  /** Response data */
  data: unknown;
  /** Original message ID */
  id: string;
  /** Worker ID that processed the message */
  workerId: string;
  /** Processing duration */
  duration: number;
  /** Error information if failed */
  error?: {
    code: string;
    message: string;
    details?: unknown;
  };
}

// =====================================
// Event Types
// =====================================

/**
 * Integration events
 */
export type IntegrationEvent =
  | ServiceHealthEvent
  | CircuitBreakerEvent
  | CredentialEvent
  | ApiOperationEvent
  | DependencyEvent;

/**
 * Service health change event
 */
export interface ServiceHealthEvent {
  type: 'service_health_change';
  serviceId: string;
  oldStatus: string;
  newStatus: string;
  timestamp: Date;
  details: ServiceHealthStatus;
}

/**
 * Circuit breaker state change event
 */
export interface CircuitBreakerEvent {
  type: 'circuit_breaker_state_change';
  serviceId: string;
  oldState: string;
  newState: string;
  timestamp: Date;
  reason: string;
  details: CircuitBreakerState;
}

/**
 * Credential-related event
 */
export interface CredentialEvent {
  type: 'credential_rotation' | 'credential_validation' | 'credential_sync';
  credentialId: string;
  serviceIds: string[];
  timestamp: Date;
  details: Record<string, unknown>;
}

/**
 * API operation event
 */
export interface ApiOperationEvent {
  type: 'api_request' | 'api_response' | 'api_error' | 'batch_complete';
  operationId: string;
  serviceId: string;
  timestamp: Date;
  details: Record<string, unknown>;
}

/**
 * Service dependency event
 */
export interface DependencyEvent {
  type: 'dependency_health_change' | 'cascade_failure' | 'recovery';
  affectedServices: string[];
  timestamp: Date;
  details: Record<string, unknown>;
}

// =====================================
// Configuration Types
// =====================================

/**
 * Integration agent configuration
 */
export interface IntegrationAgentConfig {
  /** Agent name */
  name: string;
  /** Maximum number of worker threads */
  maxWorkers: number;
  /** Worker pool configuration */
  workerPool: {
    minWorkers: number;
    maxWorkers: number;
    idleTimeoutMs: number;
    taskTimeoutMs: number;
  };
  /** Service discovery configuration */
  serviceDiscovery: {
    enabled: boolean;
    intervalMs: number;
    sources: string[];
  };
  /** Health monitoring configuration */
  healthMonitoring: {
    enabled: boolean;
    defaultIntervalMs: number;
    batchSize: number;
    concurrency: number;
  };
  /** Metrics collection configuration */
  metrics: {
    enabled: boolean;
    collectionIntervalMs: number;
    retentionPeriodMs: number;
  };
  /** Caching configuration */
  cache: {
    enabled: boolean;
    maxSize: number;
    defaultTtlMs: number;
  };
  /** Logging configuration */
  logging: {
    level: 'debug' | 'info' | 'warn' | 'error';
    includeMetrics: boolean;
    includePerformance: boolean;
  };
}

// =====================================
// Integration Agent Interface
// =====================================

/**
 * Integration Management Agent interface
 */
export interface IIntegrationAgent extends EventEmitter {
  /** Initialize the integration agent */
  initialize(): Promise<void>;
  
  /** Register a service with the integration agent */
  registerService(config: ServiceConfig): Promise<void>;
  
  /** Unregister a service */
  unregisterService(serviceId: string): Promise<void>;
  
  /** Execute API request through the integration layer */
  executeApiRequest(context: ApiRequestContext, data?: unknown): Promise<ApiResponseContext>;
  
  /** Execute batch API operations */
  executeBatchOperation(batch: BatchApiOperation): Promise<ApiResponseContext[]>;
  
  /** Get service health status */
  getServiceHealth(serviceId: string): Promise<ServiceHealthStatus>;
  
  /** Get all service health statuses */
  getAllServiceHealth(): Promise<Map<string, ServiceHealthStatus>>;
  
  /** Synchronize credentials across services */
  synchronizeCredentials(credentialId: string, serviceIds: string[]): Promise<void>;
  
  /** Get service metrics */
  getServiceMetrics(serviceId: string, timeRange?: { start: Date; end: Date }): Promise<ServiceMetrics[]>;
  
  /** Get integration agent status */
  getStatus(): Promise<{
    healthy: boolean;
    services: number;
    activeWorkers: number;
    pendingTasks: number;
    uptime: number;
  }>;
  
  /** Shutdown the integration agent */
  shutdown(): Promise<void>;
}

// =====================================
// Utility Types
// =====================================

/**
 * Service operation result
 */
export interface ServiceOperationResult<T = unknown> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: unknown;
  };
  duration: number;
  timestamp: Date;
}

/**
 * Load balancing strategy
 */
export type LoadBalancingStrategy = 'round_robin' | 'weighted' | 'least_connections' | 'health_based';

/**
 * Service discovery source
 */
export interface ServiceDiscoverySource {
  type: 'static' | 'dns' | 'consul' | 'etcd' | 'kubernetes';
  config: Record<string, unknown>;
  enabled: boolean;
}

/**
 * Performance benchmark
 */
export interface PerformanceBenchmark {
  serviceId: string;
  operation: string;
  expectedResponseTimeMs: number;
  expectedThroughput: number;
  expectedErrorRate: number;
  lastBenchmark: Date;
  results: {
    responseTime: number;
    throughput: number;
    errorRate: number;
    score: number;
  };
}

// Types are already exported above - no need to re-export