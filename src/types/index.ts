/**
 * Type definitions for Make.com FastMCP Server
 * Comprehensive types for Make.com API integration
 */

import { FastMCP } from 'fastmcp';
import { z } from 'zod';

// FastMCP Server Types
export type FastMCPSessionAuth = Record<string, unknown> | undefined;
export type FastMCPServer = FastMCP<FastMCPSessionAuth>;
export type ToolParameters = z.ZodType<Record<string, unknown>>;

// Tool creation function type
export type ToolCreationFunction<T = Record<string, unknown>> = (apiClient: T) => {
  name: string;
  description: string;
  parameters: ToolParameters;
  execute: (args: Record<string, unknown>, context?: ToolExecutionContext) => Promise<string>;
};

// Server interface for tool registration
export interface ToolServer {
  addTool: <Params extends ToolParameters>(tool: {
    name: string;
    description: string;
    parameters: Params;
    execute: (args: z.infer<Params>, context?: ToolExecutionContext) => Promise<string>;
  }) => void;
}

export interface MakeApiConfig {
  apiKey: string;
  baseUrl: string;
  teamId?: string;
  organizationId?: string;
  timeout?: number;
  retries?: number;
}

export interface RateLimitConfig {
  maxRequests: number;
  windowMs: number;
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
}

export interface ServerConfig {
  name: string;
  version: string;
  port?: number;
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
  authentication?: {
    enabled: boolean;
    secret?: string;
  };
  rateLimit?: RateLimitConfig;
  make: MakeApiConfig;
}

export interface MakeScenario {
  id: number;
  name: string;
  teamId: number;
  folderId?: number;
  blueprint: Record<string, unknown>;
  scheduling: {
    type: 'immediate' | 'indefinitely' | 'on-demand';
    interval?: number;
  };
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface MakeConnection {
  id: number;
  name: string;
  accountName: string;
  service: string;
  metadata: Record<string, unknown>;
  isValid: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface MakeTemplate {
  id: number;
  name: string;
  description?: string;
  category?: string;
  blueprint: Record<string, unknown>;
  tags: string[];
  isPublic: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface MakeExecution {
  id: number;
  scenarioId: number;
  status: 'success' | 'error' | 'warning' | 'incomplete';
  startedAt: string;
  finishedAt?: string;
  operations: number;
  dataTransfer: number;
  error?: {
    message: string;
    code?: string;
    details?: Record<string, unknown>;
  };
}

export interface MakeUser {
  id: number;
  name: string;
  email: string;
  role: 'admin' | 'member' | 'viewer';
  teamId: number;
  organizationId?: number;
  permissions: string[];
  isActive: boolean;
}

export interface MakeWebhook {
  id: number;
  name: string;
  url: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  headers?: Record<string, string>;
  isActive: boolean;
  scenarioId?: number;
  createdAt: string;
}

export interface MakeVariable {
  id: number;
  name: string;
  value: unknown;
  type: 'string' | 'number' | 'boolean' | 'json';
  scope: 'global' | 'team' | 'scenario';
  isEncrypted: boolean;
  createdAt: string;
}

export interface ApiResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: {
    message: string;
    code?: string;
    details?: Record<string, unknown>;
  };
  metadata?: {
    total?: number;
    page?: number;
    limit?: number;
  };
}

export interface ToolExecutionContext {
  log: {
    debug: (message: string, data?: unknown) => void;
    info: (message: string, data?: unknown) => void;
    warn: (message: string, data?: unknown) => void;
    error: (message: string, data?: unknown) => void;
  };
  reportProgress: (progress: { progress: number; total: number }) => void;
  session?: FastMCPSessionAuth;
}

export interface MakeApiError extends Error {
  code?: string;
  status?: number;
  details?: Record<string, unknown>;
  retryable: boolean;
}

export interface MakeAnalytics {
  organizationId: number;
  period: {
    startDate: string;
    endDate: string;
  };
  usage: {
    operations: number;
    dataTransfer: number;
    executions: number;
    successfulExecutions: number;
    failedExecutions: number;
  };
  performance: {
    averageExecutionTime: number;
    averageOperationsPerExecution: number;
    topScenarios: Array<{
      scenarioId: number;
      name: string;
      executions: number;
      operations: number;
    }>;
  };
  billing: {
    operationsUsed: number;
    operationsLimit: number;
    dataTransferUsed: number;
    dataTransferLimit: number;
  };
}

export interface MakeAuditLog {
  id: number;
  timestamp: string;
  userId: number;
  userName: string;
  action: string;
  resource: string;
  resourceId?: number;
  details: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
  organizationId?: number;
  teamId?: number;
}

export interface MakeScenarioLog {
  id: number;
  scenarioId: number;
  executionId: number;
  timestamp: string;
  level: 'info' | 'warning' | 'error' | 'debug';
  message: string;
  moduleId?: number;
  moduleName?: string;
  data?: Record<string, unknown>;
}

export interface MakeIncompleteExecution {
  id: number;
  scenarioId: number;
  scenarioName: string;
  startedAt: string;
  stoppedAt: string;
  reason: string;
  status: 'waiting' | 'paused' | 'failed';
  operations: number;
  dataTransfer: number;
  lastModuleId?: number;
  lastModuleName?: string;
  error?: {
    message: string;
    code?: string;
    details?: Record<string, unknown>;
  };
  canResume: boolean;
}

export interface MakeHookLog {
  id: number;
  hookId: number;
  timestamp: string;
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: unknown;
  response?: {
    status: number;
    headers: Record<string, string>;
    body?: unknown;
  };
  processingTime: number;
  success: boolean;
  error?: string;
}

export interface MakeCustomApp {
  id: number;
  name: string;
  description?: string;
  version: string;
  status: 'draft' | 'testing' | 'published' | 'deprecated' | 'suspended';
  organizationId?: number;
  teamId?: number;
  configuration: {
    type: 'connector' | 'trigger' | 'action' | 'transformer' | 'full_app';
    runtime: 'nodejs' | 'python' | 'php' | 'custom';
    environment: {
      variables: Record<string, string>;
      secrets: string[];
      dependencies: Record<string, string>;
    };
    endpoints: Array<{
      name: string;
      method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
      path: string;
      description?: string;
      parameters: Record<string, unknown>;
      responses: Record<string, unknown>;
    }>;
    authentication: {
      type: 'none' | 'api_key' | 'oauth2' | 'basic_auth' | 'custom';
      configuration: Record<string, unknown>;
    };
    ui: {
      icon?: string;
      color?: string;
      description?: string;
      category?: string;
    };
  };
  usage: {
    installations: number;
    executions: number;
    averageResponseTime: number;
    errorRate: number;
    lastUsed?: string;
  };
  createdAt: string;
  updatedAt: string;
  createdBy: number;
  createdByName: string;
}

export interface MakeSDKApp {
  id: number;
  name: string;
  description?: string;
  version: string;
  publisher: string;
  category: 'productivity' | 'integration' | 'automation' | 'analytics' | 'communication' | 'utility' | 'custom';
  status: 'available' | 'installed' | 'updating' | 'deprecated' | 'suspended';
  organizationId?: number;
  teamId?: number;
  installation: {
    installedAt?: string;
    installedBy?: number;
    installedByName?: string;
    version: string;
    autoUpdate: boolean;
    configuration: Record<string, unknown>;
    permissions: {
      granted: string[];
      requested: string[];
      denied: string[];
    };
  };
  usage: {
    installations: number;
    rating: number;
    reviews: number;
    activeUsers: number;
    executions: number;
    lastUsed?: string;
  };
  security: {
    verified: boolean;
    sandboxed: boolean;
    permissions: string[];
    dataAccess: 'none' | 'read' | 'write' | 'full';
    networkAccess: boolean;
  };
  createdAt: string;
  updatedAt: string;
  publishedAt: string;
}

export interface MakeBillingAccount {
  id: number;
  organizationId: number;
  organizationName: string;
  accountStatus: 'active' | 'suspended' | 'cancelled' | 'pending';
  billingPlan: {
    name: string;
    type: 'free' | 'starter' | 'professional' | 'team' | 'enterprise';
    price: number;
    currency: string;
    billingCycle: 'monthly' | 'annual';
  };
  usage: {
    currentPeriod: {
      startDate: string;
      endDate: string;
      operations: {
        used: number;
        limit: number;
        percentage: number;
      };
    };
  };
  billing: {
    nextBillingDate: string;
    currentBalance: number;
    paymentStatus: 'current' | 'overdue' | 'failed' | 'processing';
    autoRenewal: boolean;
  };
  createdAt: string;
  updatedAt: string;
}

export interface MakeNotification {
  id: number;
  type: 'system' | 'billing' | 'security' | 'scenario' | 'team' | 'marketing' | 'custom';
  category: 'info' | 'warning' | 'error' | 'success' | 'reminder' | 'alert';
  priority: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  message: string;
  status: 'draft' | 'scheduled' | 'sent' | 'delivered' | 'failed' | 'cancelled';
  channels: {
    email: boolean;
    inApp: boolean;
    sms: boolean;
    webhook: boolean;
  };
  delivery: {
    totalRecipients: number;
    successfulDeliveries: number;
    failedDeliveries: number;
  };
  createdAt: string;
  updatedAt: string;
  createdBy: number;
}

// =====================================
// Log Streaming Types
// =====================================

/**
 * Enhanced log entry structure for Make.com API log streaming
 */
export interface MakeLogEntry {
  /** Unique log entry identifier */
  id: string;
  /** Execution ID this log entry belongs to */
  executionId: string;
  /** Scenario ID */
  scenarioId: number;
  /** Organization ID */
  organizationId: number;
  /** Team ID */
  teamId: number;
  /** Log entry timestamp */
  timestamp: string;
  /** Execution start time */
  executionStartTime: string;
  /** Module start time if applicable */
  moduleStartTime?: string;
  /** Module end time if applicable */
  moduleEndTime?: string;
  /** Log level */
  level: 'info' | 'warning' | 'error' | 'debug';
  /** Log category */
  category: 'execution' | 'module' | 'connection' | 'validation' | 'system';
  /** Log message */
  message: string;
  /** Additional log details */
  details?: Record<string, unknown>;
  /** Module information */
  module: {
    id: string;
    name: string;
    type: string;
    version: string;
    position?: { x: number; y: number };
  };
  /** Performance metrics */
  metrics: {
    inputBundles: number;
    outputBundles: number;
    operations: number;
    dataSize: number;
    processingTime: number;
    memoryUsage?: number;
  };
  /** Error information if applicable */
  error?: {
    code: string;
    type: string;
    message: string;
    stack?: string;
    module?: string;
    retryable: boolean;
    cause?: Record<string, unknown>;
  };
  /** Request details if applicable */
  request?: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: unknown;
  };
  /** Response details if applicable */
  response?: {
    status: number;
    headers: Record<string, string>;
    body?: unknown;
    size: number;
  };
}

/**
 * Log streaming configuration options
 */
export interface LogStreamingConfig {
  /** Real-time filtering options */
  realTimeFiltering: {
    logLevels: ('debug' | 'info' | 'warn' | 'error' | 'critical')[];
    components: string[];
    correlationIds: string[];
    userSessions: string[];
    timeWindows: {
      start: Date;
      end: Date;
      live: boolean;
    };
  };
  /** Aggregation strategy */
  aggregationStrategy: {
    batchingEnabled: boolean;
    batchSize: number;
    batchTimeoutMs: number;
    compressionEnabled: boolean;
    deduplicationEnabled: boolean;
  };
  /** Buffering strategy */
  bufferingStrategy: {
    enabled: boolean;
    maxBufferSize: number;
    bufferTimeoutMs: number;
    persistToRedis: boolean;
    replayOnReconnect: boolean;
  };
}

/**
 * Log streaming session information
 */
export interface LogStreamingSession {
  /** Session ID */
  sessionId: string;
  /** Client connection information */
  client: {
    id: string;
    ip: string;
    userAgent?: string;
  };
  /** Active filters */
  filters: {
    scenarioIds?: number[];
    logLevels?: string[];
    timeRange?: {
      start: Date;
      end: Date;
    };
  };
  /** Session metrics */
  metrics: {
    connectedAt: Date;
    lastActivity: Date;
    messagesStreamed: number;
    bytesTransferred: number;
  };
  /** Session status */
  status: 'connected' | 'disconnected' | 'error';
}

/**
 * Log export configuration
 */
export interface LogExportConfig {
  /** Export format */
  format: 'json' | 'csv' | 'plain' | 'structured';
  /** Time range for export */
  timeRange: {
    start: Date;
    end: Date;
  };
  /** Filters to apply */
  filters: {
    scenarioIds?: number[];
    logLevels?: string[];
    categories?: string[];
    modules?: string[];
  };
  /** Export options */
  options: {
    includeMetadata: boolean;
    compressionEnabled: boolean;
    maxRecords?: number;
    sortOrder: 'asc' | 'desc';
  };
}

// =====================================
// Performance Analysis Types
// =====================================

/**
 * Performance analysis options
 */
export interface PerformanceAnalysisOptions {
  /** Time range to analyze in hours */
  timeRangeHours: number;
  /** Include bottleneck detection analysis */
  includeBottleneckDetection?: boolean;
  /** Include performance metrics collection */
  includePerformanceMetrics?: boolean;
  /** Include trend analysis over time */
  includeTrendAnalysis?: boolean;
  /** Include optimization recommendations */
  includeOptimizationRecommendations?: boolean;
  /** Include cost impact analysis */
  includeCostAnalysis?: boolean;
  /** Compare against industry benchmarks */
  performanceBenchmarking?: boolean;
  /** Include detailed component-level breakdown */
  detailedBreakdown?: boolean;
  /** Include system-wide performance metrics */
  includeSystemMetrics?: boolean;
  /** Include API performance metrics */
  includeApiMetrics?: boolean;
  /** Include webhook performance metrics */
  includeWebhookMetrics?: boolean;
  /** Include scenario execution metrics */
  includeScenarioMetrics?: boolean;
  /** Generate optimization recommendations */
  generateRecommendations?: boolean;
  /** Compare against industry benchmarks */
  benchmarkComparison?: boolean;
  /** Duration to monitor in minutes for live analysis */
  durationMinutes?: number;
  /** Sampling interval in seconds for live analysis */
  samplingIntervalSeconds?: number;
  /** Alert thresholds for live analysis */
  alertThresholds?: AlertThresholds;
}

/**
 * Performance analysis filters
 */
export interface PerformanceAnalysisFilters {
  /** Minimum execution time to consider (ms) */
  minExecutionTime?: number;
  /** Error rate threshold for concern (0-1) */
  errorThreshold: number;
  /** Minimum severity to include */
  severityFilter: 'all' | 'warning' | 'error' | 'critical';
}

/**
 * Alert thresholds for performance monitoring
 */
export interface AlertThresholds {
  /** Response time threshold in ms */
  responseTime: number;
  /** Error rate threshold (0-1) */
  errorRate: number;
  /** CPU usage threshold (0-1) */
  cpuUsage: number;
  /** Memory usage threshold (0-1) */
  memoryUsage: number;
}

/**
 * Performance metrics collection
 */
export interface PerformanceMetrics {
  /** Response time metrics */
  responseTime?: {
    average: number;
    p50: number;
    p95: number;
    p99: number;
    trend: 'improving' | 'stable' | 'degrading';
  } | number;
  /** Throughput metrics */
  throughput?: {
    requestsPerSecond: number;
    requestsPerMinute: number;
    trend: 'improving' | 'stable' | 'degrading';
  };
  /** Reliability metrics */
  reliability?: {
    uptime: number;
    errorRate: number;
    successRate: number;
    trend: 'improving' | 'stable' | 'degrading';
  };
  /** Resource utilization metrics */
  resources?: {
    cpuUsage: number;
    memoryUsage: number;
    networkUtilization: number;
    trend: 'improving' | 'stable' | 'degrading';
  };
}

/**
 * System memory metrics
 */
export interface SystemMemoryMetrics {
  /** Used memory in bytes */
  used: number;
  /** Total memory available in bytes */
  total: number;
  /** Memory usage percentage (0-1) */
  percentage?: number;
  /** Memory utilization ratio (0-1) - alias for percentage */
  utilization?: number;
  /** Free memory in bytes */
  free?: number;
}

/**
 * CPU metrics
 */
export interface CpuMetrics {
  /** User CPU time */
  user: number;
  /** System CPU time */
  system: number;
  /** CPU usage percentage (0-1) */
  percentage?: number;
  /** CPU utilization ratio (0-1) - alias for percentage */
  utilization?: number;
  /** Load average */
  loadAverage?: number[];
}

/**
 * Performance bottleneck information
 */
export interface PerformanceBottleneck {
  /** Bottleneck type */
  type: 'cpu' | 'memory' | 'network' | 'database' | 'api' | 'module' | 'webhook';
  /** Severity level */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Description of the bottleneck */
  description: string;
  /** Location or component affected */
  location: string;
  /** Impact assessment */
  impact: {
    performanceDecrease: number; // percentage
    affectedOperations: number;
    estimatedCost?: number;
  };
  /** Recommendations to resolve */
  recommendations: string[];
  /** Detection timestamp */
  detectedAt: string;
  /** Confidence score (0-1) */
  confidence: number;
}

/**
 * Performance analysis result
 */
export interface PerformanceAnalysisResult {
  /** Analysis timestamp */
  analysisTimestamp: string;
  /** Target type analyzed */
  targetType: string;
  /** Target ID if applicable */
  targetId?: string;
  /** Time range analyzed */
  timeRange: {
    startTime: string;
    endTime: string;
    durationHours: number;
  };
  /** Overall health score (0-100) */
  overallHealthScore: number;
  /** Performance grade */
  performanceGrade: 'A' | 'B' | 'C' | 'D' | 'F';
  /** Detected bottlenecks */
  bottlenecks: PerformanceBottleneck[];
  /** Performance metrics */
  metrics: PerformanceMetrics;
  /** Performance trends */
  trends: {
    performanceDirection: 'improving' | 'stable' | 'degrading';
    predictionConfidence: number;
    projectedIssues: string[];
  };
  /** Benchmark comparison */
  benchmarkComparison: {
    industryStandard: string;
    currentPerformance: string;
    gap: string;
    ranking: 'below_average' | 'average' | 'above_average' | 'excellent';
  };
  /** Optimization recommendations */
  recommendations: {
    immediate: string[];
    shortTerm: string[];
    longTerm: string[];
    estimatedImpact: number;
  };
  /** Cost analysis if requested */
  costAnalysis?: {
    currentCost: number;
    optimizationPotential: number;
    recommendedActions: string[];
  };
}

// =====================================
// Scenario Analysis Types
// =====================================

/**
 * Scenario analysis result
 */
export interface ScenarioAnalysis {
  /** Scenario ID */
  scenarioId: string;
  /** Scenario name */
  scenarioName: string;
  /** Diagnostic report */
  diagnosticReport: unknown; // Will be typed in diagnostics.ts
  /** Performance analysis results */
  performanceAnalysis?: PerformanceAnalysisResult;
  /** Errors found during analysis */
  errors: string[];
}

/**
 * Consolidated findings from scenario analysis
 */
export interface ConsolidatedFindings {
  /** Total number of scenarios analyzed */
  totalScenarios: number;
  /** Number of healthy scenarios */
  healthyScenarios: number;
  /** Number of scenarios with warnings */
  warningScenarios: number;
  /** Number of critical scenarios */
  criticalScenarios: number;
  /** Common issues found across scenarios */
  commonIssues: Array<{
    /** Issue type */
    type: string;
    /** Number of scenarios affected */
    count: number;
    /** Issue description */
    description: string;
    /** Severity level */
    severity: 'info' | 'warning' | 'error' | 'critical';
    /** Affected scenario IDs */
    affectedScenarios: string[];
  }>;
  /** Overall performance summary */
  performanceSummary: {
    averageHealthScore: number;
    averageExecutionTime: number;
    overallSuccessRate: number;
    totalOperationsAnalyzed: number;
  };
  /** Recommendations summary */
  recommendationsSummary: {
    highPriorityRecommendations: string[];
    estimatedImprovementPotential: number;
    estimatedCostSavings?: number;
  };
}

// =====================================
// API Response Enhancement Types
// =====================================

/**
 * Enhanced API response with better error handling
 */
export interface EnhancedApiResponse<T = unknown> extends ApiResponse<T> {
  /** Response timestamp */
  timestamp: string;
  /** Request ID for tracking */
  requestId?: string;
  /** Response time in milliseconds */
  responseTime?: number;
  /** Rate limit information */
  rateLimit?: {
    limit: number;
    remaining: number;
    resetTime: string;
  };
  /** Warning messages */
  warnings?: string[];
}

// =====================================
// Utility Types for Better Type Safety
// =====================================

/**
 * Utility type for non-empty arrays
 */
export type NonEmptyArray<T> = [T, ...T[]];

/**
 * Utility type for string literals
 */
export type StringLiteral<T> = T extends string ? T : never;

/**
 * Utility type for numeric values
 */
export type NumericValue = number | `${number}`;

/**
 * Utility type for timestamp values
 */
export type Timestamp = string | number | Date;

/**
 * Utility type for nullable values
 */
export type Nullable<T> = T | null;

/**
 * Utility type for optional properties
 */
export type OptionalKeys<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;

/**
 * Utility type for deep partial
 */
export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends Record<string, unknown>
    ? DeepPartial<T[P]>
    : T[P];
};

/**
 * Utility type for JSON-safe values
 */
export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

/**
 * Utility type for record with string keys
 */
export type StringRecord<T = unknown> = Record<string, T>;

/**
 * Utility type for unknown record (safer than any)
 */
export type UnknownRecord = Record<string, unknown>;

/**
 * Type guard for checking if value is a record
 */
export function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Type guard for checking if value is a non-empty string
 */
export function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

/**
 * Type guard for checking if value is a number
 */
export function isNumber(value: unknown): value is number {
  return typeof value === 'number' && !isNaN(value);
}

/**
 * Type guard for checking if array is non-empty
 */
export function isNonEmptyArray<T>(array: T[]): array is NonEmptyArray<T> {
  return array.length > 0;
}

// =====================================
// Event and Stream Types
// =====================================

/**
 * Base event interface for streaming
 */
export interface BaseEvent {
  /** Event type identifier */
  type: string;
  /** Event timestamp */
  timestamp: string;
  /** Event ID */
  id: string;
  /** Event source */
  source?: string;
}

/**
 * Log streaming event
 */
export interface LogStreamEvent extends BaseEvent {
  type: 'log';
  /** Log entry data */
  data: MakeLogEntry;
}

/**
 * Performance metrics event
 */
export interface PerformanceEvent extends BaseEvent {
  type: 'performance';
  /** Performance data */
  data: PerformanceMetrics;
}

/**
 * Error event
 */
export interface ErrorEvent extends BaseEvent {
  type: 'error';
  /** Error information */
  data: {
    error: string;
    details?: UnknownRecord;
    recoverable?: boolean;
  };
}

/**
 * Status update event
 */
export interface StatusEvent extends BaseEvent {
  type: 'status';
  /** Status information */
  data: {
    status: 'connected' | 'disconnected' | 'reconnecting' | 'error';
    message?: string;
    details?: UnknownRecord;
  };
}

/**
 * Union of all streaming events
 */
export type StreamingEvent = LogStreamEvent | PerformanceEvent | ErrorEvent | StatusEvent;

/**
 * Event emitter callback type
 */
export type EventCallback<T = UnknownRecord> = (data: T) => void | Promise<void>;

/**
 * Event listener configuration
 */
export interface EventListenerConfig {
  /** Event type to listen for */
  event: string;
  /** Callback function */
  callback: EventCallback;
  /** Options */
  options?: {
    once?: boolean;
    priority?: number;
  };
}

// =====================================
// Advanced Query and Filter Types
// =====================================

/**
 * Query operators for advanced filtering
 */
export type QueryOperator = 
  | 'eq'    // equals
  | 'ne'    // not equals
  | 'gt'    // greater than
  | 'gte'   // greater than or equal
  | 'lt'    // less than
  | 'lte'   // less than or equal
  | 'in'    // in array
  | 'nin'   // not in array
  | 'regex' // regex match
  | 'exists' // field exists
  | 'contains'; // string contains

/**
 * Query condition for filtering
 */
export interface QueryCondition {
  /** Field name to query */
  field: string;
  /** Query operator */
  operator: QueryOperator;
  /** Value to compare against */
  value: JsonValue | JsonValue[];
}

/**
 * Complex query with logical operators
 */
export interface ComplexQuery {
  /** AND conditions - all must match */
  and?: QueryCondition[];
  /** OR conditions - any must match */
  or?: QueryCondition[];
  /** NOT conditions - none must match */
  not?: QueryCondition[];
}

/**
 * Sort configuration
 */
export interface SortConfig {
  /** Field to sort by */
  field: string;
  /** Sort direction */
  direction: 'asc' | 'desc';
  /** Sort priority (for multi-field sorting) */
  priority?: number;
}

/**
 * Pagination configuration
 */
export interface PaginationConfig {
  /** Page number (1-based) */
  page: number;
  /** Items per page */
  limit: number;
  /** Total items (for response) */
  total?: number;
  /** Total pages (for response) */
  totalPages?: number;
}

/**
 * Advanced search configuration
 */
export interface AdvancedSearchConfig {
  /** Query conditions */
  query?: ComplexQuery;
  /** Sort configuration */
  sort?: SortConfig[];
  /** Pagination */
  pagination?: PaginationConfig;
  /** Fields to include in response */
  fields?: string[];
  /** Fields to exclude from response */
  excludeFields?: string[];
}

// =====================================
// Cache and Storage Types
// =====================================

/**
 * Cache entry metadata
 */
export interface CacheEntry<T = JsonValue> {
  /** Cached value */
  value: T;
  /** Cache key */
  key: string;
  /** Expiration timestamp */
  expiresAt?: number;
  /** Creation timestamp */
  createdAt: number;
  /** Last accessed timestamp */
  lastAccessed?: number;
  /** Access count */
  accessCount?: number;
  /** Cache tags for invalidation */
  tags?: string[];
}

/**
 * Cache configuration
 */
export interface CacheConfig {
  /** Maximum number of entries */
  maxSize?: number;
  /** Default TTL in milliseconds */
  defaultTtl?: number;
  /** Enable LRU eviction */
  enableLru?: boolean;
  /** Enable statistics collection */
  enableStats?: boolean;
}

/**
 * Cache statistics
 */
export interface CacheStats {
  /** Number of cache hits */
  hits: number;
  /** Number of cache misses */
  misses: number;
  /** Hit rate percentage */
  hitRate: number;
  /** Total entries */
  size: number;
  /** Memory usage estimate */
  memoryUsage?: number;
}

// =====================================
// Monitoring and Observability Types
// =====================================

/**
 * Health check status
 */
export type HealthStatus = 'healthy' | 'degraded' | 'unhealthy' | 'unknown';

/**
 * Health check result
 */
export interface HealthCheckResult {
  /** Component name */
  component: string;
  /** Health status */
  status: HealthStatus;
  /** Status message */
  message?: string;
  /** Response time in ms */
  responseTime?: number;
  /** Additional details */
  details?: UnknownRecord;
  /** Timestamp */
  timestamp: string;
}

/**
 * System health overview
 */
export interface SystemHealth {
  /** Overall status */
  status: HealthStatus;
  /** Individual component results */
  components: HealthCheckResult[];
  /** System uptime in seconds */
  uptime: number;
  /** Health check timestamp */
  timestamp: string;
  /** System metadata */
  metadata?: {
    version: string;
    environment: string;
    nodeId?: string;
  };
}

/**
 * Metric data point
 */
export interface MetricDataPoint {
  /** Metric name */
  name: string;
  /** Metric value */
  value: number;
  /** Data point timestamp */
  timestamp: number;
  /** Metric labels/tags */
  labels?: StringRecord<string>;
  /** Metric unit */
  unit?: string;
}

/**
 * Time series data
 */
export interface TimeSeriesData {
  /** Metric name */
  metric: string;
  /** Data points */
  dataPoints: MetricDataPoint[];
  /** Time range */
  timeRange: {
    start: number;
    end: number;
  };
  /** Aggregation type */
  aggregation?: 'avg' | 'sum' | 'min' | 'max' | 'count';
}

// =====================================
// Security and Authentication Types
// =====================================

/**
 * Security context
 */
export interface SecurityContext {
  /** User ID */
  userId?: string;
  /** Session ID */
  sessionId?: string;
  /** User roles */
  roles?: string[];
  /** User permissions */
  permissions?: string[];
  /** Authentication method */
  authMethod?: 'api_key' | 'oauth' | 'jwt' | 'basic';
  /** Authentication timestamp */
  authenticatedAt?: string;
  /** IP address */
  ipAddress?: string;
  /** User agent */
  userAgent?: string;
}

/**
 * Rate limiting information
 */
export interface RateLimitInfo {
  /** Current limit */
  limit: number;
  /** Remaining requests */
  remaining: number;
  /** Reset time */
  resetTime: number;
  /** Window duration in ms */
  windowMs: number;
  /** Rate limit key */
  key?: string;
}

/**
 * Audit log entry
 */
export interface AuditLogEntry {
  /** Log entry ID */
  id: string;
  /** Timestamp */
  timestamp: string;
  /** User context */
  user?: SecurityContext;
  /** Action performed */
  action: string;
  /** Resource affected */
  resource?: string;
  /** Resource ID */
  resourceId?: string;
  /** Action result */
  result: 'success' | 'failure' | 'partial';
  /** Error message if failure */
  error?: string;
  /** Additional details */
  details?: UnknownRecord;
  /** Request/response metadata */
  metadata?: {
    requestId?: string;
    duration?: number;
    bytesSent?: number;
    bytesReceived?: number;
  };
}

// =====================================
// Error and Exception Types
// =====================================

/**
 * Standard error codes used across the application
 */
export type ErrorCode = 
  | 'VALIDATION_ERROR'
  | 'AUTHENTICATION_ERROR'
  | 'AUTHORIZATION_ERROR'
  | 'NOT_FOUND_ERROR'
  | 'CONFLICT_ERROR'
  | 'RATE_LIMIT_ERROR'
  | 'API_ERROR'
  | 'NETWORK_ERROR'
  | 'TIMEOUT_ERROR'
  | 'INTERNAL_ERROR'
  | 'CONFIGURATION_ERROR'
  | 'RESOURCE_ERROR'
  | 'DEPENDENCY_ERROR';

/**
 * Enhanced error interface with context
 */
export interface EnhancedError extends Error {
  /** Error code for categorization */
  code: ErrorCode;
  /** HTTP status code if applicable */
  statusCode?: number;
  /** Additional error context */
  context?: UnknownRecord;
  /** Whether the error is retryable */
  retryable?: boolean;
  /** Timestamp when error occurred */
  timestamp?: string;
  /** Request ID for tracing */
  requestId?: string;
  /** Component that generated the error */
  component?: string;
}

/**
 * Validation error details
 */
export interface ValidationError {
  /** Field path that failed validation */
  field: string;
  /** Validation rule that failed */
  rule: string;
  /** Error message */
  message: string;
  /** Received value */
  value?: JsonValue;
  /** Expected value or format */
  expected?: string;
}

/**
 * Batch validation result
 */
export interface ValidationResult {
  /** Whether validation passed */
  valid: boolean;
  /** Array of validation errors */
  errors: ValidationError[];
  /** Number of fields validated */
  fieldCount?: number;
  /** Validation duration in ms */
  duration?: number;
}

// =====================================
// Configuration and Settings Types
// =====================================

/**
 * Environment configuration
 */
export interface EnvironmentConfig {
  /** Environment name */
  environment: 'development' | 'staging' | 'production' | 'test';
  /** Debug mode enabled */
  debug: boolean;
  /** Log level */
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  /** Node environment */
  nodeEnv: string;
  /** Application version */
  version: string;
  /** Build timestamp */
  buildTime?: string;
  /** Git commit hash */
  gitHash?: string;
}

/**
 * Feature flags configuration
 */
export interface FeatureFlags {
  /** Feature flag name and status */
  [key: string]: boolean | string | number;
}

/**
 * Application settings
 */
export interface ApplicationSettings {
  /** Environment configuration */
  environment: EnvironmentConfig;
  /** Server configuration */
  server: ServerConfig;
  /** Feature flags */
  features: FeatureFlags;
  /** External service configurations */
  services?: StringRecord<UnknownRecord>;
  /** Custom application settings */
  custom?: UnknownRecord;
}

// =====================================
// Webhook and Integration Types
// =====================================

/**
 * Webhook payload
 */
export interface WebhookPayload {
  /** Event type */
  event: string;
  /** Event data */
  data: UnknownRecord;
  /** Webhook timestamp */
  timestamp: string;
  /** Webhook ID */
  id: string;
  /** Source system */
  source?: string;
  /** Event version */
  version?: string;
}

/**
 * Webhook delivery status
 */
export interface WebhookDelivery {
  /** Delivery ID */
  id: string;
  /** Webhook URL */
  url: string;
  /** HTTP method used */
  method: string;
  /** Response status code */
  statusCode: number;
  /** Response headers */
  responseHeaders?: StringRecord<string>;
  /** Response body */
  responseBody?: string;
  /** Delivery attempt number */
  attempt: number;
  /** Delivery timestamp */
  deliveredAt: string;
  /** Response time in ms */
  responseTime: number;
  /** Whether delivery was successful */
  success: boolean;
  /** Error message if failed */
  error?: string;
}

/**
 * Integration configuration
 */
export interface IntegrationConfig {
  /** Integration name */
  name: string;
  /** Integration type */
  type: 'webhook' | 'api' | 'database' | 'queue' | 'storage';
  /** Whether integration is enabled */
  enabled: boolean;
  /** Connection configuration */
  connection: UnknownRecord;
  /** Authentication configuration */
  auth?: UnknownRecord;
  /** Retry configuration */
  retry?: {
    maxAttempts: number;
    backoffMs: number;
    exponentialBackoff: boolean;
  };
  /** Timeout configuration */
  timeout?: {
    connectionMs: number;
    requestMs: number;
  };
}

// =====================================
// Exported Type Collections
// =====================================

/**
 * Re-export all diagnostic types for convenience
 */
export type * from './diagnostics.js';

/**
 * Collection of all Make.com entity types
 */
export type MakeEntity = 
  | MakeScenario
  | MakeConnection
  | MakeTemplate
  | MakeExecution
  | MakeUser
  | MakeWebhook
  | MakeVariable
  | MakeCustomApp
  | MakeSDKApp;

/**
 * Collection of all performance-related types
 */
export type PerformanceType =
  | PerformanceMetrics
  | PerformanceAnalysisResult
  | PerformanceBottleneck
  | SystemMemoryMetrics
  | CpuMetrics;

/**
 * Collection of all streaming-related types
 */
export type StreamingType =
  | StreamingEvent
  | LogStreamEvent
  | PerformanceEvent
  | ErrorEvent
  | StatusEvent
  | LogStreamingSession;

/**
 * Collection of all configuration-related types
 */
export type ConfigurationType =
  | ServerConfig
  | MakeApiConfig
  | RateLimitConfig
  | EnvironmentConfig
  | ApplicationSettings
  | IntegrationConfig;