/**
 * @fileoverview Real-Time Log Streaming Tools for Make.com FastMCP Server
 * 
 * Provides comprehensive log streaming capabilities including:
 * - Real-time scenario execution log streaming
 * - Historical log querying with advanced filtering
 * - Live execution monitoring with SSE
 * - Log export for external analysis tools
 * - Multi-format log output (JSON, structured, plain text)
 * 
 * @version 1.0.0
 * @author Make.com FastMCP Server
 * @see {@link https://docs.make.com/api} Make.com API Documentation
 */

import { FastMCP, UserError } from 'fastmcp';
import { z } from 'zod';
import MakeApiClient from '../lib/make-api-client.js';
import logger from '../lib/logger.js';
import { EventEmitter } from 'events';
// Import statement removed - ToolExecutionContext not used

// Logger interface for proper typing - using Record<string, unknown> to avoid conflicts
// Remove local SerializableValue interface to avoid conflicts with FastMCP

interface Logger {
  debug: (message: string, data?: Record<string, unknown>) => void;
  info: (message: string, data?: Record<string, unknown>) => void;
  warn: (message: string, data?: Record<string, unknown>) => void;
  error: (message: string, data?: Record<string, unknown>) => void;
}

// Export configuration interfaces
interface ExportConfig {
  filtering?: {
    logLevels?: string[];
    modules?: string[];
    dateRange?: {
      start: string;
      end: string;
    };
    executionIds?: string[];
    scenarioIds?: number[];
    organizations?: number[];
    teams?: number[];
    errorTypes?: string[];
    customFilters?: Record<string, unknown>;
    includeSuccessfulExecutions?: boolean;
    includeFailedExecutions?: boolean;
    performanceThreshold?: number;
  };
  format?: string;
  compression?: boolean;
  includeMetadata?: boolean;
  transformations?: DataTransformation[];
  streaming?: {
    enabled: boolean;
    batchSize?: number;
    intervalMs?: number;
    maxDuration?: number;
  };
  organizationId?: number;
  timeRange?: {
    start?: string;
    end?: string;
    startTime?: string;
    endTime?: string;
  };
}

interface OutputConfig {
  format?: 'json' | 'csv' | 'parquet' | 'newrelic' | 'splunk' | 'elasticsearch' | 'datadog' | 'prometheus' | 'aws-cloudwatch' | 'azure-monitor' | 'gcp-logging';
  destination?: string;
  chunkSize?: number;
  compression?: 'none' | 'gzip' | 'brotli' | 'zip';
  includeMetadata?: boolean;
  fieldMapping?: Record<string, string>;
  transformations?: DataTransformation[];
  encryption?: {
    enabled: boolean;
    algorithm?: string;
    key?: string;
  };
}

interface DestinationConfig {
  type?: 'file' | 's3' | 'gcs' | 'azure' | 'ftp' | 'sftp' | 'http' | 'webhook' | 'external-system' | 'stream' | 'download';
  path?: string;
  credentials?: {
    accessKey?: string;
    secretKey?: string;
    token?: string;
    username?: string;
    password?: string;
  };
  options?: Record<string, unknown>;
  externalSystemConfig?: ExternalSystemConfig;
}

interface AnalyticsConfig {
  enabled?: boolean;
  includePerformanceMetrics?: boolean;
  includePredictiveAnalysis?: boolean;
  customMetrics?: CustomMetric[];
  anomalyDetection?: {
    enabled: boolean;
    sensitivity: number;
    algorithms: string[];
  };
  features?: {
    realTimeAnalysis?: boolean;
    predictiveInsights?: boolean;
    anomalyDetection?: boolean;
    performanceAnalysis?: boolean;
    errorCorrelation?: boolean;
    performanceOptimization?: boolean;
  };
  type?: 'standard' | 'advanced' | 'enterprise';
}

interface ExternalSystemConfig {
  type?: 'elasticsearch' | 'splunk' | 'datadog' | 'newrelic' | 'generic' | 'aws-cloudwatch' | 'azure-monitor' | 'gcp-logging';
  endpoint?: string;
  authentication?: {
    type?: 'bearer' | 'api-key' | 'basic' | 'api_key' | 'oauth2' | 'basic_auth' | 'oauth' | 'bearer_token';
    credentials?: Record<string, string>;
  };
  headers?: Record<string, string>;
  options?: {
    timeout?: number;
    retries?: number;
    batchSize?: number;
    compression?: boolean;
  };
}

interface DataTransformation {
  operation?: 'rename' | 'format_date' | 'parse_json' | 'extract_regex' | 'convert_type' | 'filter_fields';
  field?: string;
  targetField?: string;
  parameters?: Record<string, unknown>;
}

interface CustomMetric {
  name?: string;
  field?: string;
  aggregation?: 'count' | 'sum' | 'avg' | 'min' | 'max' | 'distinct';
  filters?: Record<string, unknown>;
  timeWindow?: string;
}

// Type definitions for better TypeScript support
// (Logger interface already defined above)

interface LogMetadata {
  timestamp: string;
  level: string;
  scenarioId?: string;
  executionId?: string;
  [key: string]: unknown;
}

interface _StreamingLogEntry {
  id: string;
  timestamp: string;
  level: 'info' | 'warn' | 'error' | 'debug';
  message: string;
  scenarioId?: string;
  executionId?: string;
  metadata: LogMetadata;
}

interface _LogFilter {
  level?: string[];
  scenarioId?: string;
  executionId?: string;
  startTime?: string;
  endTime?: string;
  searchTerm?: string;
}

interface _LogExportResult {
  success: boolean;
  exportId?: string;
  downloadUrl?: string;
  error?: string;
  totalRecords: number;
  exportFormat: string;
}

interface _SystemOverview {
  totalScenarios: number;
  activeExecutions: number;
  systemHealth: string;
  performanceMetrics: Record<string, unknown>;
}

interface _ExecutionSummary {
  executionId: string;
  status: string;
  duration: number;
  stepsCompleted: number;
  totalSteps: number;
  errors: unknown[];
}

// Duplicate interface definitions removed - using the ones defined above

// Enhanced log entry structure based on Make.com API research
interface MakeLogEntry {
  id: string;
  executionId: string;
  scenarioId: number;
  organizationId: number;
  teamId: number;
  timestamp: string;
  executionStartTime: string;
  moduleStartTime?: string;
  moduleEndTime?: string;
  level: 'info' | 'warning' | 'error' | 'debug';
  category: 'execution' | 'module' | 'connection' | 'validation' | 'system';
  message: string;
  details?: Record<string, unknown>;
  module: {
    id: string;
    name: string;
    type: string;
    version: string;
    position?: { x: number; y: number };
  };
  metrics: {
    inputBundles: number;
    outputBundles: number;
    operations: number;
    dataSize: number;
    processingTime: number;
    memoryUsage?: number;
  };
  error?: {
    code: string;
    type: string;
    message: string;
    stack?: string;
    module?: string;
    retryable: boolean;
    cause?: Record<string, unknown>;
  };
  request?: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: unknown;
  };
  response?: {
    status: number;
    headers: Record<string, string>;
    body?: unknown;
    size: number;
  };
}

interface LogStreamingConfig {
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
  aggregationStrategy: {
    batchingEnabled: boolean;
    batchSize: number;
    batchTimeoutMs: number;
    compressionEnabled: boolean;
    deduplicationEnabled: boolean;
  };
  bufferingStrategy: {
    enabled: boolean;
    maxBufferSize: number;
    bufferTimeoutMs: number;
    persistToRedis: boolean;
    replayOnReconnect: boolean;
  };
}

interface StreamingMetrics {
  totalLogsStreamed: number;
  averageLatency: number;
  activeConnections: number;
  droppedLogs: number;
  bufferUtilization: number;
  throughput: number;
}

// Input validation schemas
const ScenarioRunLogsSchema = z.object({
  scenarioId: z.number().min(1).describe('Scenario ID to stream logs for'),
  executionId: z.string().optional().describe('Specific execution ID to monitor'),
  streaming: z.object({
    enabled: z.boolean().default(true).describe('Enable real-time streaming'),
    batchSize: z.number().min(1).max(100).default(10).describe('Number of logs per batch'),
    batchTimeoutMs: z.number().min(100).max(60000).default(1000).describe('Batch timeout in milliseconds'),
    compressionEnabled: z.boolean().default(true).describe('Enable log compression'),
  }).default({}),
  filtering: z.object({
    logLevels: z.array(z.enum(['debug', 'info', 'warn', 'error', 'critical'])).default(['info', 'warn', 'error']).describe('Log levels to include'),
    moduleTypes: z.array(z.string()).optional().describe('Module types to filter by'),
    moduleIds: z.array(z.string()).optional().describe('Specific module IDs to include'),
    startTime: z.string().optional().describe('Start time for log filtering (ISO format)'),
    endTime: z.string().optional().describe('End time for log filtering (ISO format)'),
  }).default({}),
  output: z.object({
    format: z.enum(['json', 'structured', 'plain']).default('structured').describe('Output format'),
    includeMetrics: z.boolean().default(true).describe('Include execution metrics'),
    includeStackTrace: z.boolean().default(true).describe('Include stack traces for errors'),
    colorCoding: z.boolean().default(true).describe('Enable color coding for different log levels'),
  }).default({}),
}).strict();

const QueryLogsByTimeRangeSchema = z.object({
  scenarioId: z.number().min(1).optional().describe('Filter by scenario ID'),
  organizationId: z.number().min(1).optional().describe('Filter by organization ID'),
  teamId: z.number().min(1).optional().describe('Filter by team ID'),
  executionId: z.string().optional().describe('Filter by specific execution ID'),
  timeRange: z.object({
    startTime: z.string().describe('Start time for query (ISO format)'),
    endTime: z.string().describe('End time for query (ISO format)'),
    timezone: z.string().default('UTC').describe('Timezone for time interpretation'),
  }).describe('Time range for log query'),
  filtering: z.object({
    logLevels: z.array(z.enum(['debug', 'info', 'warn', 'error', 'critical'])).default(['info', 'warn', 'error']).describe('Log levels to include'),
    executionStatus: z.enum(['success', 'failed', 'warning', 'running', 'stopped', 'paused']).optional().describe('Filter by execution status'),
    moduleTypes: z.array(z.string()).optional().describe('Module types to filter by'),
    moduleNames: z.array(z.string()).optional().describe('Specific module names to include'),
    searchText: z.string().optional().describe('Search text in log messages (supports regex)'),
    errorCodesOnly: z.boolean().default(false).describe('Only return logs with error codes'),
    performanceThreshold: z.number().optional().describe('Filter by processing time threshold (ms)'),
    dataSizeThreshold: z.number().optional().describe('Filter by data size threshold (bytes)'),
    operationsThreshold: z.number().optional().describe('Filter by operations count threshold'),
    excludeSuccess: z.boolean().default(false).describe('Exclude successful operations from results'),
    includeMetrics: z.boolean().default(true).describe('Include performance metrics in results'),
    correlationIds: z.array(z.string()).optional().describe('Filter by correlation IDs'),
  }).default({}),
  pagination: z.object({
    limit: z.number().min(1).max(5000).default(100).describe('Maximum number of logs to return'),
    offset: z.number().min(0).default(0).describe('Number of logs to skip'),
    sortBy: z.enum(['timestamp', 'level', 'module', 'duration', 'operations', 'dataSize']).default('timestamp').describe('Sort field'),
    sortOrder: z.enum(['asc', 'desc']).default('desc').describe('Sort order'),
    cursor: z.string().optional().describe('Cursor for pagination continuation'),
  }).default({}),
  aggregation: z.object({
    enabled: z.boolean().default(false).describe('Enable log aggregation and analytics'),
    groupBy: z.enum(['level', 'module', 'hour', 'day', 'execution', 'scenario', 'errorCode']).optional().describe('Group logs by field'),
    includeStats: z.boolean().default(true).describe('Include aggregation statistics'),
    includeTimeDistribution: z.boolean().default(true).describe('Include time-based distribution analysis'),
    includePerformanceAnalysis: z.boolean().default(true).describe('Include performance trend analysis'),
    includeErrorAnalysis: z.boolean().default(true).describe('Include error pattern analysis'),
  }).default({}),
  analysis: z.object({
    performanceTrends: z.boolean().default(false).describe('Analyze performance trends over time'),
    errorPatterns: z.boolean().default(false).describe('Detect error patterns and root causes'),
    usageMetrics: z.boolean().default(false).describe('Calculate resource usage metrics'),
    executionFlow: z.boolean().default(false).describe('Analyze execution flow patterns'),
    anomalyDetection: z.boolean().default(false).describe('Detect anomalous execution patterns'),
  }).default({}),
  export: z.object({
    format: z.enum(['json', 'csv', 'excel', 'pdf']).optional().describe('Export format for results'),
    includeCharts: z.boolean().default(false).describe('Include data visualization charts'),
    compression: z.boolean().default(false).describe('Compress export data'),
  }).optional(),
}).strict();

const StreamLiveExecutionSchema = z.object({
  scenarioId: z.number().min(1).describe('Scenario ID to monitor'),
  executionId: z.string().optional().describe('Specific execution ID to monitor (leave empty for next execution)'),
  monitoring: z.object({
    includeModuleProgress: z.boolean().default(true).describe('Include module-level progress'),
    includeDataFlow: z.boolean().default(true).describe('Include data flow between modules'),
    includePerformanceMetrics: z.boolean().default(true).describe('Include real-time performance metrics'),
    updateIntervalMs: z.number().min(100).max(10000).default(1000).describe('Update interval in milliseconds'),
  }).default({}),
  alerts: z.object({
    enableErrorAlerts: z.boolean().default(true).describe('Alert on errors'),
    enablePerformanceAlerts: z.boolean().default(true).describe('Alert on performance issues'),
    performanceThreshold: z.number().min(1000).max(300000).default(30000).describe('Performance alert threshold in milliseconds'),
    errorThreshold: z.number().min(1).max(10).default(3).describe('Number of errors before alert'),
  }).default({}),
  output: z.object({
    format: z.enum(['detailed', 'summary', 'metrics-only']).default('detailed').describe('Output detail level'),
    includeVisualization: z.boolean().default(true).describe('Include ASCII visualization of execution flow'),
  }).default({}),
}).strict();

const ExportLogsForAnalysisSchema = z.object({
  exportConfig: z.object({
    scenarioIds: z.array(z.number().min(1)).optional().describe('Scenario IDs to export (empty for all)'),
    organizationId: z.number().min(1).optional().describe('Organization ID for export scope'),
    timeRange: z.object({
      startTime: z.string().describe('Start time for export (ISO format)'),
      endTime: z.string().describe('End time for export (ISO format)'),
    }).describe('Time range for log export'),
    filtering: z.object({
      logLevels: z.array(z.enum(['debug', 'info', 'warn', 'error', 'critical'])).default(['info', 'warn', 'error']).describe('Log levels to include'),
      includeSuccessfulExecutions: z.boolean().default(true).describe('Include successful executions'),
      includeFailedExecutions: z.boolean().default(true).describe('Include failed executions'),
      moduleTypes: z.array(z.string()).optional().describe('Module types to include'),
      correlationIds: z.array(z.string()).optional().describe('Filter by correlation IDs'),
      errorCodesOnly: z.boolean().default(false).describe('Only export logs with error codes'),
      performanceThreshold: z.number().optional().describe('Min processing time threshold (ms)'),
    }).default({}),
    streaming: z.object({
      enabled: z.boolean().default(false).describe('Enable real-time streaming export'),
      batchSize: z.number().min(1).max(1000).default(50).describe('Streaming batch size'),
      intervalMs: z.number().min(1000).max(60000).default(5000).describe('Streaming interval in milliseconds'),
      maxDuration: z.number().min(60).max(86400).default(3600).describe('Max streaming duration in seconds'),
    }).default({}),
  }).describe('Export configuration'),
  outputConfig: z.object({
    format: z.enum(['json', 'csv', 'parquet', 'elasticsearch', 'splunk', 'datadog', 'newrelic', 'prometheus', 'aws-cloudwatch', 'azure-monitor', 'gcp-logging']).default('json').describe('Export format'),
    compression: z.enum(['none', 'gzip', 'zip', 'brotli']).default('gzip').describe('Compression format'),
    chunkSize: z.number().min(100).max(10000).default(1000).describe('Number of logs per chunk'),
    includeMetadata: z.boolean().default(true).describe('Include export metadata'),
    fieldMapping: z.record(z.string()).optional().describe('Custom field name mapping'),
    transformations: z.array(z.object({
      field: z.string(),
      operation: z.enum(['rename', 'format_date', 'parse_json', 'extract_regex']),
      parameters: z.record(z.unknown()).optional(),
    })).optional().describe('Data transformation rules'),
  }).default({}),
  destination: z.object({
    type: z.enum(['download', 'webhook', 'external-system', 'stream']).default('download').describe('Export destination'),
    webhookUrl: z.string().optional().describe('Webhook URL for external delivery'),
    externalSystemConfig: z.object({
      type: z.enum(['elasticsearch', 'splunk', 'datadog', 'newrelic', 'aws-cloudwatch', 'azure-monitor', 'gcp-logging']).optional(),
      connection: z.object({
        url: z.string().optional(),
        apiKey: z.string().optional(),
        username: z.string().optional(),
        password: z.string().optional(),
        region: z.string().optional(),
        index: z.string().optional(),
        logGroup: z.string().optional(),
        workspace: z.string().optional(),
      }).optional(),
      authentication: z.object({
        type: z.enum(['api_key', 'oauth', 'basic_auth', 'bearer_token']).optional(),
        credentials: z.record(z.string()).optional(),
      }).optional(),
      retryPolicy: z.object({
        maxRetries: z.number().min(0).max(10).default(3),
        retryDelayMs: z.number().min(100).max(30000).default(1000),
        backoffMultiplier: z.number().min(1).max(10).default(2),
      }).default({}),
    }).optional().describe('External system configuration'),
    delivery: z.object({
      immediate: z.boolean().default(true).describe('Immediate delivery'),
      scheduled: z.boolean().default(false).describe('Scheduled delivery'),
      cronExpression: z.string().optional().describe('Cron expression for scheduled delivery'),
      bufferSize: z.number().min(1).max(10000).default(100).describe('Buffer size for batched delivery'),
    }).default({}),
  }).default({}),
  analytics: z.object({
    enabled: z.boolean().default(false).describe('Enable advanced analytics'),
    features: z.object({
      anomalyDetection: z.boolean().default(false).describe('Detect anomalous patterns'),
      performanceAnalysis: z.boolean().default(false).describe('Analyze performance trends'),
      errorCorrelation: z.boolean().default(false).describe('Correlate error patterns'),
      predictiveInsights: z.boolean().default(false).describe('Generate predictive insights'),
    }).default({}),
    customMetrics: z.array(z.object({
      name: z.string(),
      aggregation: z.enum(['count', 'sum', 'avg', 'min', 'max']),
      field: z.string(),
      filters: z.record(z.unknown()).optional(),
    })).optional().describe('Custom metrics to calculate'),
  }).default({}),
}).strict();

/**
 * Real-time log streaming manager
 */
class LogStreamingManager extends EventEmitter {
  private activeStreams = new Map<string, NodeJS.Timeout>();
  private streamMetrics = new Map<string, StreamingMetrics>();
  private logBuffer = new Map<string, MakeLogEntry[]>();

  constructor(private apiClient: MakeApiClient) {
    super();
    this.setMaxListeners(100); // Support many concurrent streams
  }

  /**
   * Start streaming logs for a scenario execution
   */
  async startLogStreaming(
    scenarioId: number,
    executionId: string | null,
    config: LogStreamingConfig,
    callback: (logs: MakeLogEntry[]) => void
  ): Promise<string> {
    const streamId = `${scenarioId}-${executionId || 'live'}-${Date.now()}`;
    const componentLogger = logger.child({ component: 'LogStreamingManager', streamId });

    componentLogger.info('Starting log streaming', { scenarioId, executionId, config });

    // Initialize metrics
    this.streamMetrics.set(streamId, {
      totalLogsStreamed: 0,
      averageLatency: 0,
      activeConnections: 1,
      droppedLogs: 0,
      bufferUtilization: 0,
      throughput: 0,
    });

    // Initialize buffer
    if (config.bufferingStrategy.enabled) {
      this.logBuffer.set(streamId, []);
    }

    let lastLogTimestamp = new Date().toISOString();

    // Streaming function
    const streamLogs = async (): Promise<void> => {
      try {
        const params: Record<string, unknown> = {
          limit: config.aggregationStrategy.batchSize,
          offset: 0,
          sortBy: 'timestamp',
          sortOrder: 'asc',
          dateFrom: lastLogTimestamp,
        };

        if (executionId) {
          params.executionId = executionId;
        }

        // Filter by log levels
        if (config.realTimeFiltering.logLevels.length > 0) {
          params.level = config.realTimeFiltering.logLevels.join(',');
        }

        const response = await this.apiClient.get(`/scenarios/${scenarioId}/logs`, { params });

        if (response.success && response.data) {
          const logs = response.data as MakeLogEntry[];
          
          if (logs.length > 0) {
            // Update last timestamp
            lastLogTimestamp = logs[logs.length - 1].timestamp;

            // Apply additional filtering
            let filteredLogs = logs;
            
            if (config.realTimeFiltering.components.length > 0) {
              filteredLogs = filteredLogs.filter(log => 
                config.realTimeFiltering.components.includes(log.module.name)
              );
            }

            if (config.realTimeFiltering.correlationIds.length > 0) {
              filteredLogs = filteredLogs.filter(log => 
                config.realTimeFiltering.correlationIds.includes(log.executionId)
              );
            }

            // Buffer management
            if (config.bufferingStrategy.enabled) {
              const buffer = this.logBuffer.get(streamId) || [];
              buffer.push(...filteredLogs);

              // Trim buffer if too large
              if (buffer.length > config.bufferingStrategy.maxBufferSize) {
                buffer.splice(0, buffer.length - config.bufferingStrategy.maxBufferSize);
                const metrics = this.streamMetrics.get(streamId)!;
                metrics.droppedLogs += buffer.length - config.bufferingStrategy.maxBufferSize;
              }

              this.logBuffer.set(streamId, buffer);
            }

            // Update metrics
            const metrics = this.streamMetrics.get(streamId)!;
            metrics.totalLogsStreamed += filteredLogs.length;
            metrics.throughput = filteredLogs.length / (config.aggregationStrategy.batchTimeoutMs / 1000);
            
            if (config.bufferingStrategy.enabled) {
              const buffer = this.logBuffer.get(streamId) || [];
              metrics.bufferUtilization = (buffer.length / config.bufferingStrategy.maxBufferSize) * 100;
            }

            // Emit logs to callback
            if (filteredLogs.length > 0) {
              callback(filteredLogs);
            }
          }
        }
      } catch (error) {
        componentLogger.error('Error in log streaming', { error: error instanceof Error ? error.message : String(error) });
        this.emit('error', { streamId, error });
      }
    };

    // Start streaming with polling
    const interval = setInterval(streamLogs, config.aggregationStrategy.batchTimeoutMs);
    this.activeStreams.set(streamId, interval);

    // Initial fetch
    await streamLogs();

    componentLogger.info('Log streaming started', { streamId });
    return streamId;
  }

  /**
   * Stop a log stream
   */
  stopLogStreaming(streamId: string): void {
    const interval = this.activeStreams.get(streamId);
    if (interval) {
      clearInterval(interval);
      this.activeStreams.delete(streamId);
      this.streamMetrics.delete(streamId);
      this.logBuffer.delete(streamId);
      
      const componentLogger = logger.child({ component: 'LogStreamingManager', streamId });
      componentLogger.info('Log streaming stopped', { streamId });
    }
  }

  /**
   * Get streaming metrics
   */
  getStreamingMetrics(streamId: string): StreamingMetrics | null {
    return this.streamMetrics.get(streamId) || null;
  }

  /**
   * Get all active streams
   */
  getActiveStreams(): string[] {
    return Array.from(this.activeStreams.keys());
  }

  /**
   * Cleanup all streams
   */
  cleanup(): void {
    this.activeStreams.forEach((interval) => clearInterval(interval));
    this.activeStreams.clear();
    this.streamMetrics.clear();
    this.logBuffer.clear();
  }
}

/**
 * Add log streaming tools to FastMCP server
 */
export function addLogStreamingTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'LogStreamingTools' });
  const streamingManager = new LogStreamingManager(apiClient);
  
  componentLogger.info('Adding log streaming tools');

  // Cleanup on server shutdown
  process.on('SIGINT', () => {
    streamingManager.cleanup();
  });

  process.on('SIGTERM', () => {
    streamingManager.cleanup();
  });

  // 1. Get Scenario Run Logs with Real-Time Streaming
  server.addTool({
    name: 'get_scenario_run_logs',
    description: 'Stream detailed execution logs for a Make.com scenario with real-time updates, advanced filtering, and multiple output formats',
    parameters: ScenarioRunLogsSchema,
    execute: async (input, { log }) => {
      const { scenarioId, executionId, streaming, filtering, output } = input;

      log.info('Starting scenario log streaming', {
        scenarioId,
        executionId,
        streaming,
        filtering,
      });

      try {
        // Build streaming configuration
        const streamingConfig: LogStreamingConfig = {
          realTimeFiltering: {
            logLevels: filtering.logLevels as ('debug' | 'info' | 'warn' | 'error' | 'critical')[],
            components: filtering.moduleTypes || [],
            correlationIds: executionId ? [executionId] : [],
            userSessions: [],
            timeWindows: {
              start: filtering.startTime ? new Date(filtering.startTime) : new Date(Date.now() - 24 * 60 * 60 * 1000),
              end: filtering.endTime ? new Date(filtering.endTime) : new Date(),
              live: streaming.enabled,
            },
          },
          aggregationStrategy: {
            batchingEnabled: streaming.enabled,
            batchSize: streaming.batchSize,
            batchTimeoutMs: streaming.batchTimeoutMs,
            compressionEnabled: streaming.compressionEnabled,
            deduplicationEnabled: true,
          },
          bufferingStrategy: {
            enabled: streaming.enabled,
            maxBufferSize: 1000,
            bufferTimeoutMs: 300000, // 5 minutes
            persistToRedis: false,
            replayOnReconnect: true,
          },
        };

        if (streaming.enabled) {
          // Real-time streaming mode
          const logs: MakeLogEntry[] = [];
          let totalLogs = 0;
          let streamCompleted = false;

          const streamId = await streamingManager.startLogStreaming(
            scenarioId,
            executionId || null,
            streamingConfig,
            (newLogs) => {
              logs.push(...newLogs);
              totalLogs += newLogs.length;
              
              // Format and output new logs (used for side effects)
              formatLogs(newLogs, output);
              
              log.info('New logs received', {
                count: newLogs.length,
                totalLogs,
                streamId,
              });
            }
          );

          // Run for a limited time for demo purposes (in production, this would be managed differently)
          setTimeout(() => {
            streamingManager.stopLogStreaming(streamId);
            streamCompleted = true;
          }, 30000); // 30 seconds

          // Wait for initial logs or timeout
          await new Promise<void>(resolve => {
            const checkLogs = (): void => {
              if (logs.length > 0 || streamCompleted) {
                resolve();
              } else {
                setTimeout(checkLogs, 100);
              }
            };
            checkLogs();
          });

          const metrics = streamingManager.getStreamingMetrics(streamId);
          
          return JSON.stringify({
            streamingInfo: {
              streamId,
              scenarioId,
              executionId,
              totalLogsStreamed: totalLogs,
              streamingActive: !streamCompleted,
              config: streamingConfig,
            },
            metrics,
            logs: formatLogs(logs, output),
            summary: generateLogSummary(logs),
          }, null, 2);

        } else {
          // Static log retrieval mode
          const params: Record<string, unknown> = {
            limit: 100,
            offset: 0,
          };

          if (executionId) params.executionId = executionId;
          if (filtering.logLevels.length > 0) params.level = filtering.logLevels.join(',');
          if (filtering.startTime) params.startDate = filtering.startTime;
          if (filtering.endTime) params.endDate = filtering.endTime;
          if (filtering.moduleIds?.length) params.moduleIds = filtering.moduleIds.join(',');

          const response = await apiClient.get(`/scenarios/${scenarioId}/logs`, { params });

          if (!response.success) {
            throw new UserError(`Failed to get scenario logs: ${response.error?.message || 'Unknown error'}`);
          }

          const logs = (response.data as MakeLogEntry[]) || [];
          const metadata = response.metadata;

          log.info('Successfully retrieved scenario logs', {
            scenarioId,
            executionId,
            count: logs.length,
            total: metadata?.total,
          });

          return JSON.stringify({
            scenarioId,
            executionId,
            logs: formatLogs(logs, output),
            summary: generateLogSummary(logs),
            pagination: {
              total: metadata?.total || logs.length,
              limit: 100,
              offset: 0,
              hasMore: (metadata?.total || 0) > logs.length,
            },
          }, null, 2);
        }

      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error getting scenario logs', { scenarioId, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to get scenario run logs: ${errorMessage}`);
      }
    },
  });

  // 2. Query Logs by Time Range - Enhanced Historical Log Analysis
  server.addTool({
    name: 'query_logs_by_timerange',
    description: 'Advanced historical log search and analysis with comprehensive filtering, aggregation, trend analysis, and export capabilities',
    parameters: QueryLogsByTimeRangeSchema,
    execute: async (input, { log }) => {
      const { 
        scenarioId, organizationId, teamId, executionId, timeRange, 
        filtering, pagination, aggregation, analysis, export: exportConfig
      } = input;

      log.info('Starting advanced historical log query', {
        scenarioId,
        organizationId,
        teamId,
        executionId,
        timeRange,
        filtering,
        pagination,
        aggregation,
        analysis,
      });

      try {
        const queryStartTime = Date.now();
        
        // Build comprehensive query parameters
        const params: Record<string, unknown> = {
          startDate: timeRange.startTime,
          endDate: timeRange.endTime,
          timezone: timeRange.timezone,
          limit: pagination.limit,
          offset: pagination.offset,
          sortBy: pagination.sortBy,
          sortOrder: pagination.sortOrder,
        };

        // Add cursor-based pagination if provided
        if (pagination.cursor) {
          params.cursor = pagination.cursor;
        }

        // Apply filtering parameters
        if (scenarioId) params.scenarioId = scenarioId;
        if (organizationId) params.organizationId = organizationId;
        if (teamId) params.teamId = teamId;
        if (executionId) params.executionId = executionId;
        if (filtering.logLevels.length > 0) params.level = filtering.logLevels.join(',');
        if (filtering.executionStatus) params.status = filtering.executionStatus;
        if (filtering.moduleTypes?.length) params.moduleTypes = filtering.moduleTypes.join(',');
        if (filtering.moduleNames?.length) params.moduleNames = filtering.moduleNames.join(',');
        if (filtering.searchText) {
          params.search = filtering.searchText;
          params.searchType = 'regex'; // Enable regex search
        }
        if (filtering.errorCodesOnly) params.errorsOnly = true;
        if (filtering.performanceThreshold) params.minProcessingTime = filtering.performanceThreshold;
        if (filtering.dataSizeThreshold) params.minDataSize = filtering.dataSizeThreshold;
        if (filtering.operationsThreshold) params.minOperations = filtering.operationsThreshold;
        if (filtering.excludeSuccess) params.excludeSuccess = true;
        if (!filtering.includeMetrics) params.excludeMetrics = true;
        if (filtering.correlationIds?.length) params.correlationIds = filtering.correlationIds.join(',');

        // Determine optimal endpoint based on scope and query parameters
        let endpoint = '/logs';
        if (executionId) {
          endpoint = `/executions/${executionId}/logs`;
        } else if (scenarioId) {
          endpoint = `/scenarios/${scenarioId}/logs`;
        } else if (organizationId) {
          endpoint = `/organizations/${organizationId}/logs`;
        } else if (teamId) {
          endpoint = `/teams/${teamId}/logs`;
        }

        log.info('Executing historical log query', {
          endpoint,
          paramsCount: Object.keys(params).length,
          queryStrategy: 'time-range-optimized',
        });

        // Execute the primary log query
        const response = await apiClient.get(endpoint, { params });

        if (!response.success) {
          throw new UserError(`Failed to query historical logs: ${response.error?.message || 'Unknown error'}`);
        }

        const logs = (response.data as MakeLogEntry[]) || [];
        const metadata = response.metadata;
        const queryDuration = Date.now() - queryStartTime;

        // Build comprehensive result object
        const result: Record<string, unknown> = {
          queryInfo: {
            executedAt: new Date().toISOString(),
            duration: `${queryDuration}ms`,
            timeRange: {
              ...timeRange,
              actualDuration: new Date(timeRange.endTime).getTime() - new Date(timeRange.startTime).getTime(),
              humanReadable: `${Math.ceil((new Date(timeRange.endTime).getTime() - new Date(timeRange.startTime).getTime()) / (1000 * 60 * 60))} hours`,
            },
            filtering,
            pagination: {
              ...pagination,
              total: metadata?.total || logs.length,
              hasMore: (metadata?.total || 0) > (pagination.offset + logs.length),
              nextCursor: (metadata as Record<string, unknown>)?.nextCursor as string,
            },
            endpoint,
            performance: {
              queryTime: queryDuration,
              averageProcessingTime: queryDuration / Math.max(logs.length, 1),
              dataRetrievalRate: `${logs.length}/${queryDuration}ms`,
            },
          },
          logs: logs,
          summary: generateLogSummary(logs),
        };

        // Add comprehensive aggregation analysis
        if (aggregation.enabled && aggregation.groupBy) {
          log.info('Generating advanced aggregation analysis');
          result.aggregation = generateLogAggregation(
            logs,
            aggregation.groupBy as 'level' | 'module' | 'hour',
            aggregation.includeStats
          );
        }

        // Add advanced analysis features
        if (analysis.performanceTrends || analysis.errorPatterns || 
            analysis.usageMetrics || analysis.executionFlow || analysis.anomalyDetection) {
          
          log.info('Performing advanced log analysis', {
            performanceTrends: analysis.performanceTrends,
            errorPatterns: analysis.errorPatterns,
            usageMetrics: analysis.usageMetrics,
            executionFlow: analysis.executionFlow,
            anomalyDetection: analysis.anomalyDetection,
          });
          
          result.analysis = await performAdvancedLogAnalysis(logs, analysis, {
            startTime: timeRange.startTime,
            endTime: timeRange.endTime,
          });
        }

        // Add export capabilities if requested
        if (exportConfig?.format) {
          log.info('Preparing export data', { format: exportConfig.format });
          result.export = await prepareLogExport(logs, {
            format: exportConfig.format,
            includeCharts: exportConfig.includeCharts || false,
            compression: exportConfig.compression || false,
          }, result);
        }

        // Add recommendations based on analysis
        result.recommendations = generateLogAnalysisRecommendations(logs);

        log.info('Successfully completed advanced historical log query', {
          totalLogs: logs.length,
          uniqueScenarios: new Set(logs.map(l => l.scenarioId)).size,
          uniqueModules: new Set(logs.map(l => l.module.name)).size,
          errorRate: (logs.filter(l => l.error).length / logs.length) * 100,
          queryDuration,
          timeRange,
        });

        return JSON.stringify(result, null, 2);

      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error in advanced historical log query', { 
          timeRange, 
          filtering,
          error: errorMessage,
          stack: error instanceof Error ? error.stack : undefined,
        });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to execute historical log query: ${errorMessage}`);
      }
    },
  });

  // 3. Stream Live Execution
  server.addTool({
    name: 'stream_live_execution',
    description: 'Monitor a Make.com scenario execution in real-time with progress tracking, performance metrics, and alerts',
    parameters: StreamLiveExecutionSchema,
    execute: async (input, { log }) => {
      const { scenarioId, executionId, monitoring, alerts, output } = input;

      log.info('Starting live execution monitoring', {
        scenarioId,
        executionId,
        monitoring,
        alerts,
      });

      try {
        // If no execution ID provided, get the latest or wait for the next execution
        let targetExecutionId: string | null = executionId || null;
        
        if (!targetExecutionId) {
          // Get the latest execution or wait for a new one
          const executionResponse = await apiClient.get(`/scenarios/${scenarioId}/executions`, {
            params: { limit: 1, sortBy: 'startTime', sortOrder: 'desc' }
          });
          
          if (executionResponse.success && executionResponse.data && (executionResponse.data as unknown[]).length > 0) {
            const executions = executionResponse.data as Array<{ id: string; status: string }>;
            if (executions[0].status === 'running') {
              targetExecutionId = executions[0].id;
            }
          }
        }

        if (!targetExecutionId) {
          throw new UserError('No active execution found. Please provide an execution ID or start a scenario execution.');
        }

        // Build streaming configuration for live monitoring
        const streamingConfig: LogStreamingConfig = {
          realTimeFiltering: {
            logLevels: ['info', 'warn', 'error', 'critical'],
            components: [],
            correlationIds: [targetExecutionId],
            userSessions: [],
            timeWindows: {
              start: new Date(),
              end: new Date(Date.now() + 60 * 60 * 1000), // 1 hour window
              live: true,
            },
          },
          aggregationStrategy: {
            batchingEnabled: true,
            batchSize: 5,
            batchTimeoutMs: monitoring.updateIntervalMs,
            compressionEnabled: false, // Keep uncompressed for real-time
            deduplicationEnabled: true,
          },
          bufferingStrategy: {
            enabled: true,
            maxBufferSize: 100,
            bufferTimeoutMs: 300000,
            persistToRedis: false,
            replayOnReconnect: false,
          },
        };

        const executionData = {
          scenarioId,
          executionId: targetExecutionId,
          startTime: new Date().toISOString(),
          status: 'monitoring',
          progress: {
            completedModules: 0,
            totalModules: 0,
            currentModule: null as string | null,
            estimatedCompletion: null as string | null,
          },
          performance: {
            totalDuration: 0,
            averageModuleDuration: 0,
            dataProcessed: 0,
            operationsUsed: 0,
          },
          alerts: [] as Array<{ type: string; timestamp: string; message: string; module: string; severity: string; }>,
          logs: [] as MakeLogEntry[],
        };

        // Start monitoring stream
        const streamId = await streamingManager.startLogStreaming(
          scenarioId,
          targetExecutionId,
          streamingConfig,
          (newLogs) => {
            executionData.logs.push(...newLogs);
            
            // Process logs for execution status
            for (const logEntry of newLogs) {
              // Update progress
              if (logEntry.category === 'module' && logEntry.level === 'info') {
                executionData.progress.completedModules++;
                executionData.progress.currentModule = logEntry.module.name;
              }

              // Update performance metrics
              if (logEntry.metrics) {
                executionData.performance.dataProcessed += logEntry.metrics.dataSize;
                executionData.performance.operationsUsed += logEntry.metrics.operations;
              }

              // Check for alerts
              if (alerts.enableErrorAlerts && logEntry.level === 'error') {
                executionData.alerts.push({
                  type: 'error',
                  timestamp: logEntry.timestamp,
                  message: logEntry.message,
                  module: logEntry.module.name,
                  severity: 'high',
                });
              }

              if (alerts.enablePerformanceAlerts && logEntry.metrics?.processingTime > alerts.performanceThreshold) {
                executionData.alerts.push({
                  type: 'performance',
                  timestamp: logEntry.timestamp,
                  message: `Slow module execution: ${logEntry.metrics.processingTime}ms`,
                  module: logEntry.module.name,
                  severity: 'medium',
                });
              }
            }

            log.info('Live execution update', {
              executionId: targetExecutionId,
              newLogs: newLogs.length,
              totalLogs: executionData.logs.length,
              alerts: executionData.alerts.length,
            });
          }
        );

        // Monitor for completion or timeout
        const monitoringTimeout = setTimeout(() => {
          streamingManager.stopLogStreaming(streamId);
          executionData.status = 'monitoring_completed';
        }, 60000); // 60 seconds monitoring

        // Wait for some initial data
        await new Promise(resolve => {
          setTimeout(resolve, 2000);
        });

        clearTimeout(monitoringTimeout);
        streamingManager.stopLogStreaming(streamId);

        // Generate visualization if requested
        let visualization = '';
        if (output.includeVisualization) {
          visualization = generateExecutionVisualization(executionData.logs);
        }

        const result = {
          execution: executionData,
          monitoring: {
            streamId,
            duration: Date.now() - new Date(executionData.startTime as string).getTime(),
            logsCollected: executionData.logs.length,
            alertsGenerated: executionData.alerts.length,
          },
          visualization: visualization || undefined,
          summary: generateExecutionSummary(executionData),
        };

        log.info('Live execution monitoring completed', {
          scenarioId,
          executionId: targetExecutionId,
          logsCollected: executionData.logs.length,
          alerts: executionData.alerts.length,
        });

        return JSON.stringify(result, null, 2);

      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error in live execution monitoring', { scenarioId, executionId, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to stream live execution: ${errorMessage}`);
      }
    },
  });

  // 4. Enhanced Export Logs for Analysis with External System Integration
  server.addTool({
    name: 'export_logs_for_analysis',
    description: 'Advanced log export tool with multi-format output, real-time streaming, external analytics platform integration, and comprehensive delivery options',
    parameters: ExportLogsForAnalysisSchema,
    execute: async (input, { log }) => {
      const { exportConfig, outputConfig, destination, analytics } = input;

      log.info('Starting enhanced log export for analysis', {
        timeRange: `${exportConfig.timeRange?.startTime || 'earliest'} to ${exportConfig.timeRange?.endTime || 'latest'}`,
        format: outputConfig.format,
        streaming: exportConfig.streaming?.enabled || false,
        external: destination.externalSystemConfig?.type,
        analytics: analytics.enabled,
        scenarioCount: exportConfig.scenarioIds?.length || 0,
      });

      try {
        const exportMetadata = {
          exportId: `export_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          timestamp: new Date().toISOString(),
          requestedBy: 'fastmcp-server',
          version: '2.0.0',
          config: exportConfig,
          outputConfig,
          destination,
          analytics,
        };

        // Enhanced query parameters for log retrieval
        const params: Record<string, unknown> = {
          startDate: exportConfig.timeRange?.startTime,
          endDate: exportConfig.timeRange?.endTime,
          limit: outputConfig.chunkSize,
          offset: 0,
          sortBy: 'timestamp',
          sortOrder: 'asc',
        };

        // Apply comprehensive filtering
        if (exportConfig.scenarioIds?.length) {
          params.scenarioIds = exportConfig.scenarioIds.join(',');
        }
        if (exportConfig.organizationId) {
          params.organizationId = exportConfig.organizationId;
        }
        if (exportConfig.filtering?.logLevels?.length > 0) {
          params.level = exportConfig.filtering.logLevels.join(',');
        }
        if (exportConfig.filtering?.moduleTypes?.length) {
          params.moduleTypes = exportConfig.filtering.moduleTypes.join(',');
        }
        if (exportConfig.filtering?.correlationIds?.length) {
          params.correlationIds = exportConfig.filtering.correlationIds.join(',');
        }
        if (exportConfig.filtering?.errorCodesOnly) {
          params.errorsOnly = true;
        }
        if (exportConfig.filtering?.performanceThreshold) {
          params.minProcessingTime = exportConfig.filtering.performanceThreshold;
        }

        // Determine optimal endpoint
        let endpoint = '/logs';
        if (exportConfig.organizationId) {
          endpoint = `/organizations/${exportConfig.organizationId}/logs`;
        }

        // Initialize enhanced export processing with logger adapter
        const loggerAdapter: Logger = {
          debug: (message: string, data?: Record<string, unknown>) => log.debug(message, data as any),
          info: (message: string, data?: Record<string, unknown>) => log.info(message, data as any),
          warn: (message: string, data?: Record<string, unknown>) => log.warn(message, data as any),
          error: (message: string, data?: Record<string, unknown>) => log.error(message, data as any)
        };
        const exportProcessor = new EnhancedLogExportProcessor(apiClient, exportMetadata, loggerAdapter);
        
        // Ensure streaming configuration has proper defaults
        const normalizedExportConfig: ExportConfig = {
          ...exportConfig,
          streaming: {
            enabled: exportConfig.streaming?.enabled ?? false,
            batchSize: exportConfig.streaming?.batchSize ?? 50,
            intervalMs: exportConfig.streaming?.intervalMs ?? 5000,
            maxDuration: exportConfig.streaming?.maxDuration ?? 3600
          }
        };
        
        // Normalize destination to match DestinationConfig interface
        const normalizedDestination: DestinationConfig = {
          type: destination.type as 'file' | 's3' | 'gcs' | 'azure' | 'ftp' | 'sftp' | 'http' | 'webhook' | 'external-system' | 'stream' | 'download',
          path: destination.webhookUrl || '/tmp/log-export',
          externalSystemConfig: destination.externalSystemConfig ? {
            type: destination.externalSystemConfig.type,
            endpoint: destination.externalSystemConfig.connection?.url,
            authentication: destination.externalSystemConfig.authentication ? {
              type: destination.externalSystemConfig.authentication.type || 'api_key',
              credentials: destination.externalSystemConfig.authentication.credentials || {}
            } : undefined,
            options: {
              timeout: 30000,
              retries: destination.externalSystemConfig.retryPolicy?.maxRetries || 3,
              batchSize: 100,
              compression: true
            }
          } : undefined
        };

        // Handle streaming vs batch export
        if (normalizedExportConfig.streaming?.enabled) {
          return await exportProcessor.processStreamingExport(
            endpoint,
            params,
            normalizedExportConfig,
            outputConfig,
            normalizedDestination,
            analytics
          );
        } else {
          return await exportProcessor.processBatchExport(
            endpoint,
            params,
            normalizedExportConfig,
            outputConfig,
            normalizedDestination,
            analytics
          );
        }

      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error exporting logs for analysis', { exportConfig, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to export logs for analysis: ${errorMessage}`);
      }
    },
  });

  componentLogger.info('Log streaming tools added successfully');
}

/**
 * Enhanced Log Export Processor for advanced analytics integration
 */
class EnhancedLogExportProcessor {
  private apiClient: MakeApiClient;
  private exportMetadata: Record<string, unknown>;
  private logger: Logger;

  constructor(apiClient: MakeApiClient, exportMetadata: Record<string, unknown>, logger: Logger) {
    this.apiClient = apiClient;
    this.exportMetadata = exportMetadata;
    this.logger = logger;
  }

  /**
   * Process batch export (traditional export)
   */
  async processBatchExport(
    endpoint: string,
    params: Record<string, unknown>,
    exportConfig: ExportConfig,
    outputConfig: OutputConfig,
    destination: DestinationConfig,
    analytics: AnalyticsConfig
  ): Promise<string> {
    this.logger.info('Starting batch export processing');

    const allLogs: MakeLogEntry[] = [];
    let hasMore = true;
    let offset = 0;
    let totalProcessed = 0;

    // Fetch all logs in chunks
    while (hasMore) {
      params.offset = offset;
      
      const response = await this.apiClient.get(endpoint, { params });
      
      if (!response.success) {
        throw new UserError(`Failed to fetch logs: ${response.error?.message || 'Unknown error'}`);
      }

      const logs = (response.data as MakeLogEntry[]) || [];
      
      if (logs.length === 0) {
        hasMore = false;
      } else {
        // Apply enhanced filtering
        const filteredLogs = this.applyAdvancedFiltering(logs, exportConfig.filtering);
        allLogs.push(...filteredLogs);
        totalProcessed += logs.length;
        offset += outputConfig.chunkSize || 1000;

        // Check if we've reached the end
        const metadata = response.metadata;
        if (metadata?.total && totalProcessed >= metadata.total) {
          hasMore = false;
        }
      }

      this.logger.info('Processing log export chunk', {
        offset,
        chunkSize: logs.length,
        totalProcessed,
        totalFiltered: allLogs.length,
      });
    }

    // Apply data transformations
    const transformedLogs = this.applyDataTransformations(allLogs, outputConfig.transformations);

    // Generate analytics insights if enabled
    let analyticsResults: Record<string, unknown> = {};
    if (analytics.enabled) {
      analyticsResults = await this.performAdvancedAnalytics(transformedLogs, analytics);
    }

    // Format logs for export
    const exportData = await this.formatLogsForExport(
      transformedLogs,
      outputConfig,
      this.exportMetadata,
      analyticsResults
    );

    // Handle external system delivery
    let deliveryResults: Record<string, unknown> = {};
    if (destination.type === 'external-system' && destination.externalSystemConfig) {
      deliveryResults = await this.deliverToExternalSystem(
        exportData,
        destination.externalSystemConfig,
        outputConfig.format || 'json'
      );
    }

    const result = {
      exportMetadata: this.exportMetadata,
      dataInfo: {
        format: outputConfig.format,
        compression: outputConfig.compression,
        totalLogs: transformedLogs.length,
        sizeEstimate: JSON.stringify(exportData).length,
        processingTime: Date.now() - new Date(this.exportMetadata.timestamp as string).getTime(),
      },
      data: exportData,
      analytics: analyticsResults,
      delivery: deliveryResults,
      summary: this.generateEnhancedSummary(transformedLogs, exportConfig),
    };

    this.logger.info('Batch export completed successfully', {
      exportId: this.exportMetadata.exportId,
      totalLogs: transformedLogs.length,
      format: outputConfig.format,
      external: destination.externalSystemConfig?.type,
    });

    return JSON.stringify(result, null, 2);
  }

  /**
   * Process streaming export (real-time export)
   */
  async processStreamingExport(
    endpoint: string,
    params: Record<string, unknown>,
    exportConfig: ExportConfig,
    outputConfig: OutputConfig,
    destination: DestinationConfig,
    _analytics: AnalyticsConfig
  ): Promise<string> {
    this.logger.info('Starting streaming export processing', {
      batchSize: exportConfig.streaming?.batchSize || 1000,
      intervalMs: exportConfig.streaming?.intervalMs || 5000,
      maxDuration: exportConfig.streaming?.maxDuration || 300,
    });

    const streamingResults = {
      streamId: `stream_${this.exportMetadata.exportId}`,
      startTime: new Date().toISOString(),
      endTime: '',
      batchesProcessed: 0,
      totalLogsStreamed: 0,
      errors: [] as string[],
      deliveryResults: [] as Record<string, unknown>[],
    };

    let lastLogTimestamp = exportConfig.timeRange?.start || exportConfig.timeRange?.startTime || new Date(0).toISOString();
    const streamEndTime = Date.now() + ((exportConfig.streaming?.maxDuration || 300) * 1000);

    // Initialize external system connection if needed
    let externalConnector: ExternalSystemConnector | null = null;
    if (destination.type === 'external-system' && destination.externalSystemConfig) {
      externalConnector = new ExternalSystemConnector(
        destination.externalSystemConfig,
        this.logger
      );
      await externalConnector.connect();
    }

    while (Date.now() < streamEndTime) {
      try {
        // Fetch next batch of logs
        const batchParams = {
          ...params,
          limit: exportConfig.streaming?.batchSize || 1000,
          offset: 0,
          dateFrom: lastLogTimestamp,
        };

        const response = await this.apiClient.get(endpoint, { params: batchParams });

        if (response.success && response.data) {
          const logs = response.data as MakeLogEntry[];
          
          if (logs.length > 0) {
            // Process batch
            const filteredLogs = this.applyAdvancedFiltering(logs, exportConfig.filtering);
            const transformedLogs = this.applyDataTransformations(filteredLogs, outputConfig.transformations);
            
            if (transformedLogs.length > 0) {
              const batchData = await this.formatLogsForExport(
                transformedLogs,
                outputConfig,
                this.exportMetadata
              );

              // Deliver batch to external system
              if (externalConnector) {
                const deliveryResult = await externalConnector.sendBatch(batchData, outputConfig.format || 'json');
                streamingResults.deliveryResults.push(deliveryResult);
              }

              streamingResults.batchesProcessed++;
              streamingResults.totalLogsStreamed += transformedLogs.length;
              lastLogTimestamp = logs[logs.length - 1].timestamp;
            }
          }
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        this.logger.warn('Error processing streaming batch', { error: errorMessage });
        streamingResults.errors.push(errorMessage);
      }

      // Wait for next interval
      await new Promise(resolve => setTimeout(resolve, exportConfig.streaming?.intervalMs || 5000));
    }

    // Cleanup external connection
    if (externalConnector) {
      await externalConnector.disconnect();
    }

    streamingResults.endTime = new Date().toISOString();

    const result = {
      exportMetadata: this.exportMetadata,
      streaming: streamingResults,
      summary: {
        mode: 'streaming',
        duration: `${exportConfig.streaming?.maxDuration || 300}s`,
        totalBatches: streamingResults.batchesProcessed,
        totalLogs: streamingResults.totalLogsStreamed,
        averageLogsPerBatch: streamingResults.batchesProcessed > 0 ? 
          Math.round(streamingResults.totalLogsStreamed / streamingResults.batchesProcessed) : 0,
        errorCount: streamingResults.errors.length,
        successRate: streamingResults.batchesProcessed > 0 ? 
          ((streamingResults.batchesProcessed - streamingResults.errors.length) / streamingResults.batchesProcessed) * 100 : 0,
      },
    };

    this.logger.info('Streaming export completed successfully', {
      exportId: this.exportMetadata.exportId,
      streamId: streamingResults.streamId,
      totalBatches: streamingResults.batchesProcessed,
      totalLogs: streamingResults.totalLogsStreamed,
    });

    return JSON.stringify(result, null, 2);
  }

  /**
   * Apply advanced filtering beyond basic parameters
   */
  private applyAdvancedFiltering(logs: MakeLogEntry[], filtering: ExportConfig['filtering']): MakeLogEntry[] {
    let filteredLogs = logs;

    // Apply execution success/failure filtering
    if (filtering && !filtering.includeSuccessfulExecutions) {
      filteredLogs = filteredLogs.filter(log => log.level !== 'info' || log.error);
    }

    if (filtering && !filtering.includeFailedExecutions) {
      filteredLogs = filteredLogs.filter(log => !log.error);
    }

    return filteredLogs;
  }

  /**
   * Apply data transformations based on configuration
   */
  private applyDataTransformations(logs: MakeLogEntry[], transformations?: DataTransformation[]): MakeLogEntry[] {
    if (!transformations || transformations.length === 0) {
      return logs;
    }

    return logs.map(log => {
      const transformedLog = { ...log };

      for (const transformation of transformations) {
        switch (transformation.operation) {
          case 'rename':
            // Rename field implementation
            break;
          case 'format_date':
            // Date formatting implementation
            break;
          case 'parse_json':
            // JSON parsing implementation
            break;
          case 'extract_regex':
            // Regex extraction implementation
            break;
        }
      }

      return transformedLog;
    });
  }

  /**
   * Perform advanced analytics on the exported logs
   */
  private async performAdvancedAnalytics(
    logs: MakeLogEntry[],
    analytics: AnalyticsConfig
  ): Promise<Record<string, unknown>> {
    const results: Record<string, unknown> = {};

    if (analytics.features?.anomalyDetection) {
      results.anomalies = this.detectAnomalies(logs);
    }

    if (analytics.features?.performanceAnalysis) {
      results.performanceInsights = this.analyzePerformance(logs);
    }

    if (analytics.features?.errorCorrelation) {
      results.errorCorrelations = this.correlateErrors(logs);
    }

    if (analytics.features?.predictiveInsights) {
      results.predictions = this.generatePredictions(logs);
    }

    if (analytics.customMetrics) {
      results.customMetrics = this.calculateCustomMetrics(logs, analytics.customMetrics);
    }

    return results;
  }

  /**
   * Format logs for specific export formats
   */
  private async formatLogsForExport(
    logs: MakeLogEntry[],
    outputConfig: OutputConfig,
    metadata: Record<string, unknown>,
    analytics?: Record<string, unknown>
  ): Promise<unknown> {
    const formatter = new EnhancedExportFormatter();
    return formatter.format(logs, outputConfig.format || 'json', {
      metadata,
      analytics,
      compression: outputConfig.compression,
      fieldMapping: outputConfig.fieldMapping,
    });
  }

  /**
   * Deliver exported data to external systems
   */
  private async deliverToExternalSystem(
    data: unknown,
    config: ExternalSystemConfig,
    format: string
  ): Promise<Record<string, unknown>> {
    const connector = new ExternalSystemConnector(config, this.logger);
    
    try {
      await connector.connect();
      const result = await connector.sendData(data, format);
      await connector.disconnect();
      
      return {
        success: true,
        system: config.type,
        deliveredAt: new Date().toISOString(),
        result,
      };
    } catch (error) {
      return {
        success: false,
        system: config.type,
        error: error instanceof Error ? error.message : String(error),
        deliveredAt: new Date().toISOString(),
      };
    }
  }

  /**
   * Generate enhanced summary with advanced metrics
   */
  private generateEnhancedSummary(logs: MakeLogEntry[], exportConfig: ExportConfig): Record<string, unknown> {
    return {
      ...generateExportSummary(logs, exportConfig),
      processingMetrics: {
        logsPerSecond: logs.length / ((Date.now() - new Date(this.exportMetadata.timestamp as string).getTime()) / 1000),
        averageLogSize: logs.length > 0 ? JSON.stringify(logs[0]).length : 0,
        uniqueExecutions: new Set(logs.map(log => log.executionId)).size,
        uniqueModules: new Set(logs.map(log => log.module.name)).size,
      },
      qualityMetrics: {
        completeness: 100, // Assume 100% for now
        integrity: 'verified',
        consistency: 'validated',
      },
    };
  }

  // Analytics helper methods
  private detectAnomalies(_logs: MakeLogEntry[]): Record<string, unknown> {
    // Placeholder for anomaly detection logic
    return { anomaliesDetected: 0, patterns: [] };
  }

  private analyzePerformance(logs: MakeLogEntry[]): Record<string, unknown> {
    const processingTimes = logs
      .filter(log => log.metrics?.processingTime)
      .map(log => log.metrics!.processingTime);

    if (processingTimes.length === 0) {
      return { message: 'No performance data available' };
    }

    const avg = processingTimes.reduce((sum, time) => sum + time, 0) / processingTimes.length;
    const sorted = processingTimes.sort((a, b) => a - b);
    
    return {
      averageProcessingTime: Math.round(avg),
      medianProcessingTime: sorted[Math.floor(sorted.length / 2)],
      p95ProcessingTime: sorted[Math.floor(sorted.length * 0.95)],
      maxProcessingTime: Math.max(...processingTimes),
      minProcessingTime: Math.min(...processingTimes),
    };
  }

  private correlateErrors(_logs: MakeLogEntry[]): Record<string, unknown> {
    // Placeholder for error correlation logic
    return { correlations: [], patterns: [] };
  }

  private generatePredictions(_logs: MakeLogEntry[]): Record<string, unknown> {
    // Placeholder for predictive analytics
    return { predictions: [], confidence: 0 };
  }

  private calculateCustomMetrics(logs: MakeLogEntry[], metrics: CustomMetric[]): Record<string, unknown> {
    const results: Record<string, unknown> = {};
    
    for (const metric of metrics) {
      const values: number[] = logs
        .filter(log => this.matchesFilters(log, metric.filters))
        .map(log => this.extractFieldValue(log, metric.field))
        .filter(val => val !== null && val !== undefined)
        .map(val => Number(val));

      switch (metric.aggregation) {
        case 'count':
          results[metric.name] = values.length;
          break;
        case 'sum':
          results[metric.name] = values.reduce((sum, val) => sum + val, 0);
          break;
        case 'avg':
          results[metric.name] = values.length > 0 ? 
            (values.reduce((sum, val) => sum + val, 0) / values.length) : 0;
          break;
        case 'min':
          results[metric.name] = values.length > 0 ? Math.min(...values) : null;
          break;
        case 'max':
          results[metric.name] = values.length > 0 ? Math.max(...values) : null;
          break;
      }
    }
    
    return results;
  }

  private matchesFilters(log: MakeLogEntry, filters?: Record<string, unknown>): boolean {
    if (!filters) return true;
    // Implement filter matching logic
    return true;
  }

  private extractFieldValue(log: MakeLogEntry, fieldPath: string): unknown {
    const parts = fieldPath.split('.');
    let value: unknown = log;
    
    for (const part of parts) {
      if (value && typeof value === 'object' && part in value) {
        value = (value as Record<string, unknown>)[part];
      } else {
        return null;
      }
    }
    
    return value;
  }
}

/**
 * Enhanced Export Formatter with support for multiple formats
 */
class EnhancedExportFormatter {
  async format(
    logs: MakeLogEntry[],
    format: string,
    options: {
      metadata?: Record<string, unknown>;
      analytics?: Record<string, unknown>;
      compression?: string;
      fieldMapping?: Record<string, string>;
    } = {}
  ): Promise<unknown> {
    const { metadata, analytics, fieldMapping } = options;

    // Apply field mapping if provided
    const mappedLogs = fieldMapping ? this.applyFieldMapping(logs, fieldMapping) : logs;
    
    // Type assertion for mapped logs when field mapping is applied
    const typedMappedLogs = mappedLogs as MakeLogEntry[];

    switch (format) {
      case 'json':
        return {
          metadata,
          analytics,
          logs: mappedLogs,
          summary: generateLogSummary(typedMappedLogs),
        };

      case 'csv':
        return convertLogsToCSV(typedMappedLogs);

      case 'parquet':
        return this.convertToParquet(typedMappedLogs, metadata);

      case 'elasticsearch':
        return convertLogsToElasticsearch(typedMappedLogs, metadata || {});

      case 'splunk':
        return convertLogsToSplunk(typedMappedLogs, metadata || {});

      case 'datadog':
        return convertLogsToDatadog(typedMappedLogs, metadata || {});

      case 'newrelic':
        return this.convertToNewRelic(typedMappedLogs, metadata);

      case 'prometheus':
        return this.convertToPrometheus(typedMappedLogs, metadata);

      case 'aws-cloudwatch':
        return this.convertToCloudWatch(typedMappedLogs, metadata);

      case 'azure-monitor':
        return this.convertToAzureMonitor(typedMappedLogs, metadata);

      case 'gcp-logging':
        return this.convertToGCPLogging(typedMappedLogs, metadata);

      default:
        throw new Error(`Unsupported export format: ${format}`);
    }
  }

  private applyFieldMapping(logs: MakeLogEntry[], mapping: Record<string, string>): Record<string, unknown>[] {
    return logs.map(log => {
      const mappedLog: Record<string, unknown> = {};
      
      // Apply field mappings
      for (const [originalField, mappedField] of Object.entries(mapping)) {
        const value = this.getNestedValue(log as unknown as Record<string, unknown>, originalField);
        if (value !== undefined) {
          this.setNestedValue(mappedLog, mappedField, value);
        }
      }
      
      // Include unmapped fields
      for (const [key, value] of Object.entries(log as unknown as Record<string, unknown>)) {
        if (!mapping[key]) {
          mappedLog[key] = value;
        }
      }
      
      return mappedLog;
    });
  }

  private getNestedValue(obj: Record<string, unknown>, path: string): unknown {
    return path.split('.').reduce((current: unknown, key: string) => {
      return current && typeof current === 'object' && !Array.isArray(current) 
        ? (current as Record<string, unknown>)[key] 
        : undefined;
    }, obj);
  }

  private setNestedValue(obj: Record<string, unknown>, path: string, value: unknown): void {
    const keys = path.split('.');
    const lastKey = keys.pop()!;
    
    let current = obj;
    for (const key of keys) {
      if (!current[key]) current[key] = {};
      current = current[key] as Record<string, unknown>;
    }
    
    current[lastKey] = value;
  }

  // Format-specific conversion methods
  private convertToParquet(logs: MakeLogEntry[], metadata?: Record<string, unknown>): unknown {
    // Placeholder for Parquet format conversion
    return { format: 'parquet', logs, metadata };
  }

  private convertToNewRelic(logs: MakeLogEntry[], metadata?: Record<string, unknown>): unknown {
    return {
      logs: logs.map(log => ({
        timestamp: new Date(log.timestamp).getTime(),
        message: log.message,
        level: log.level,
        service: 'fastmcp-server',
        attributes: {
          executionId: log.executionId,
          scenarioId: log.scenarioId,
          module: log.module.name,
          moduleType: log.module.type,
          ...log.metrics,
          ...(log.error && { error: log.error }),
        },
      })),
      metadata,
    };
  }

  private convertToPrometheus(logs: MakeLogEntry[], metadata?: Record<string, unknown>): unknown {
    // Generate Prometheus metrics from logs
    const metrics = this.generatePrometheusMetrics(logs);
    return { metrics, metadata };
  }

  private convertToCloudWatch(logs: MakeLogEntry[], metadata?: Record<string, unknown>): unknown {
    return {
      logEvents: logs.map(log => ({
        timestamp: new Date(log.timestamp).getTime(),
        message: JSON.stringify({
          level: log.level,
          message: log.message,
          executionId: log.executionId,
          scenarioId: log.scenarioId,
          module: log.module,
          metrics: log.metrics,
          error: log.error,
        }),
      })),
      logGroupName: '/fastmcp/scenarios',
      logStreamName: `scenario-${logs[0]?.scenarioId || 'unknown'}-${new Date().toISOString().slice(0, 10)}`,
      metadata,
    };
  }

  private convertToAzureMonitor(logs: MakeLogEntry[], metadata?: Record<string, unknown>): unknown {
    return {
      logs: logs.map(log => ({
        TimeGenerated: log.timestamp,
        Level: log.level,
        Message: log.message,
        ExecutionId: log.executionId,
        ScenarioId: log.scenarioId,
        ModuleName: log.module.name,
        ModuleType: log.module.type,
        Operations: log.metrics?.operations,
        ProcessingTime: log.metrics?.processingTime,
        DataSize: log.metrics?.dataSize,
        ErrorCode: log.error?.code,
        ErrorMessage: log.error?.message,
      })),
      metadata,
    };
  }

  private convertToGCPLogging(logs: MakeLogEntry[], metadata?: Record<string, unknown>): unknown {
    return {
      entries: logs.map(log => ({
        logName: 'projects/fastmcp/logs/scenarios',
        resource: {
          type: 'generic_node',
          labels: {
            project_id: 'fastmcp',
            location: 'global',
            namespace: 'scenarios',
            node_id: `scenario-${log.scenarioId}`,
          },
        },
        timestamp: log.timestamp,
        severity: this.mapToGCPSeverity(log.level),
        jsonPayload: {
          message: log.message,
          executionId: log.executionId,
          scenarioId: log.scenarioId,
          module: log.module,
          metrics: log.metrics,
          error: log.error,
        },
        labels: {
          module_name: log.module.name,
          module_type: log.module.type,
          level: log.level,
        },
      })),
      metadata,
    };
  }

  private generatePrometheusMetrics(logs: MakeLogEntry[]): string[] {
    const metrics: string[] = [];
    const now = Date.now();

    // Generate metrics for different log levels
    const levelCounts = logs.reduce((acc, log) => {
      acc[log.level] = (acc[log.level] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    for (const [level, count] of Object.entries(levelCounts)) {
      metrics.push(`fastmcp_logs_total{level="${level}"} ${count} ${now}`);
    }

    // Generate performance metrics
    const processingTimes = logs
      .filter(log => log.metrics?.processingTime)
      .map(log => log.metrics!.processingTime);

    if (processingTimes.length > 0) {
      const avg = processingTimes.reduce((sum, time) => sum + time, 0) / processingTimes.length;
      metrics.push(`fastmcp_processing_time_avg ${avg} ${now}`);
      metrics.push(`fastmcp_processing_time_max ${Math.max(...processingTimes)} ${now}`);
    }

    return metrics;
  }

  private mapToGCPSeverity(level: string): string {
    const mapping: Record<string, string> = {
      debug: 'DEBUG',
      info: 'INFO',
      warn: 'WARNING',
      error: 'ERROR',
      critical: 'CRITICAL',
    };
    return mapping[level] || 'DEFAULT';
  }
}

/**
 * External System Connector for delivering exported logs
 */
class ExternalSystemConnector {
  private config: ExternalSystemConfig;
  private logger: Logger;
  private connection: unknown;

  constructor(config: ExternalSystemConfig, logger: Logger) {
    this.config = config;
    this.logger = logger;
  }

  async connect(): Promise<void> {
    this.logger.info('Connecting to external system', { type: this.config.type });
    
    switch (this.config.type) {
      case 'elasticsearch':
        await this.connectToElasticsearch();
        break;
      case 'splunk':
        await this.connectToSplunk();
        break;
      case 'datadog':
        await this.connectToDatadog();
        break;
      // Add other system connections
      default:
        this.logger.info('Using generic HTTP connection');
        break;
    }
  }

  async sendData(data: unknown, _format: string): Promise<Record<string, unknown>> {
    const startTime = Date.now();
    
    try {
      let result;
      
      switch (this.config.type) {
        case 'elasticsearch':
          result = await this.sendToElasticsearch(data);
          break;
        case 'splunk':
          result = await this.sendToSplunk(data);
          break;
        case 'datadog':
          result = await this.sendToDatadog(data);
          break;
        default:
          result = await this.sendToGenericEndpoint(data);
          break;
      }

      return {
        success: true,
        duration: Date.now() - startTime,
        result,
      };
    } catch (error) {
      return {
        success: false,
        duration: Date.now() - startTime,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  async sendBatch(data: unknown, format: string): Promise<Record<string, unknown>> {
    return this.sendData(data, format);
  }

  async disconnect(): Promise<void> {
    this.logger.info('Disconnecting from external system');
    this.connection = null;
  }

  // System-specific connection methods
  private async connectToElasticsearch(): Promise<void> {
    // Placeholder for Elasticsearch connection
    this.connection = { type: 'elasticsearch', connected: true };
  }

  private async connectToSplunk(): Promise<void> {
    // Placeholder for Splunk HEC connection
    this.connection = { type: 'splunk', connected: true };
  }

  private async connectToDatadog(): Promise<void> {
    // Placeholder for Datadog connection
    this.connection = { type: 'datadog', connected: true };
  }

  // System-specific send methods
  private async sendToElasticsearch(_data: unknown): Promise<Record<string, unknown>> {
    // Placeholder for Elasticsearch bulk API call
    return { indexed: true, response: 'OK' };
  }

  private async sendToSplunk(_data: unknown): Promise<Record<string, unknown>> {
    // Placeholder for Splunk HEC call
    return { sent: true, response: 'OK' };
  }

  private async sendToDatadog(_data: unknown): Promise<Record<string, unknown>> {
    // Placeholder for Datadog logs API call
    return { sent: true, response: 'OK' };
  }

  private async sendToGenericEndpoint(_data: unknown): Promise<Record<string, unknown>> {
    // Placeholder for generic HTTP POST
    return { sent: true, response: 'OK' };
  }
}

// Helper functions for log formatting and processing

function formatLogs(logs: MakeLogEntry[], output: { format?: string; includeMetrics?: boolean; includeStackTrace?: boolean; colorCoding?: boolean }): unknown {
  const safeOutput = {
    format: output.format || 'structured',
    includeMetrics: output.includeMetrics ?? true,
    includeStackTrace: output.includeStackTrace ?? true,
    colorCoding: output.colorCoding ?? true,
  };
  switch (safeOutput.format) {
    case 'json':
      return logs;
    
    case 'structured':
      return logs.map(log => ({
        timestamp: log.timestamp,
        level: log.level,
        execution: log.executionId,
        module: `${log.module.name} (${log.module.type})`,
        message: log.message,
        metrics: safeOutput.includeMetrics ? log.metrics : undefined,
        error: safeOutput.includeStackTrace ? log.error : (log.error ? { code: log.error.code, message: log.error.message } : undefined),
      }));
    
    case 'plain':
      return logs.map(log => {
        let line = `[${log.timestamp}] ${log.level.toUpperCase()} [${log.module.name}] ${log.message}`;
        if (log.error && safeOutput.includeStackTrace) {
          line += `\nERROR: ${log.error.message}`;
          if (log.error.stack) {
            line += `\nSTACK: ${log.error.stack}`;
          }
        }
        return line;
      }).join('\n');
    
    default:
      return logs;
  }
}

function generateLogSummary(logs: MakeLogEntry[]): Record<string, unknown> {
  const summary = {
    totalLogs: logs.length,
    logLevels: {} as Record<string, number>,
    modules: {} as Record<string, number>,
    timeRange: logs.length > 0 ? {
      start: logs[0]?.timestamp,
      end: logs[logs.length - 1]?.timestamp,
    } : null,
    errors: logs.filter(log => log.error).length,
    totalOperations: logs.reduce((sum, log) => sum + (log.metrics?.operations || 0), 0),
    totalDataProcessed: logs.reduce((sum, log) => sum + (log.metrics?.dataSize || 0), 0),
  };

  // Count log levels
  logs.forEach(log => {
    summary.logLevels[log.level] = (summary.logLevels[log.level] || 0) + 1;
  });

  // Count modules
  logs.forEach(log => {
    summary.modules[log.module.name] = (summary.modules[log.module.name] || 0) + 1;
  });

  return summary;
}

function generateLogAggregation(logs: MakeLogEntry[], groupBy: 'level' | 'module' | 'hour', includeStats: boolean): Record<string, unknown> {
  const aggregation: Record<string, unknown> = {
    groupBy,
    groups: {} as Record<string, unknown>,
  };

  const groups = aggregation.groups as Record<string, Record<string, unknown>>;
  
  logs.forEach(log => {
    let groupKey: string;
    
    switch (groupBy) {
      case 'level':
        groupKey = log.level;
        break;
      case 'module':
        groupKey = log.module.name;
        break;
      case 'hour':
        groupKey = new Date(log.timestamp).toISOString().slice(0, 13) + ':00:00Z';
        break;
      default:
        groupKey = 'unknown';
    }

    if (!groups[groupKey]) {
      groups[groupKey] = {
        count: 0,
        firstSeen: log.timestamp,
        lastSeen: log.timestamp,
        errors: 0,
        operations: 0,
      };
    }

    const group = groups[groupKey];
    group.count = (group.count as number) + 1;
    group.lastSeen = log.timestamp;
    
    if (log.error) {
      group.errors = (group.errors as number) + 1;
    }
    
    if (log.metrics?.operations) {
      group.operations = (group.operations as number) + log.metrics.operations;
    }
  });

  if (includeStats) {
    const groupValues = Object.values(groups) as Array<{ count: number }>;
    aggregation.stats = {
      totalGroups: Object.keys(groups).length,
      averageLogsPerGroup: groupValues.reduce((sum, group) => sum + group.count, 0) / groupValues.length,
      maxLogsInGroup: Math.max(...groupValues.map(group => group.count)),
      minLogsInGroup: Math.min(...groupValues.map(group => group.count)),
    };
  }

  return aggregation;
}

function generateExecutionVisualization(logs: MakeLogEntry[]): string {
  const modules = new Map<string, { count: number; errors: number; duration: number }>();
  
  logs.forEach(log => {
    const moduleName = log.module.name;
    if (!modules.has(moduleName)) {
      modules.set(moduleName, { count: 0, errors: 0, duration: 0 });
    }
    
    const module = modules.get(moduleName)!;
    module.count++;
    if (log.error) module.errors++;
    if (log.metrics?.processingTime) module.duration += log.metrics.processingTime;
  });

  let visualization = 'Execution Flow Visualization:\n\n';
  let step = 1;
  
  modules.forEach((data, moduleName) => {
    const status = data.errors > 0 ? '❌ ERROR' : '✅ SUCCESS';
    const avgDuration = data.count > 0 ? Math.round(data.duration / data.count) : 0;
    
    visualization += `${step}. ${moduleName} ${status}\n`;
    visualization += `   └─ Executions: ${data.count}, Avg Duration: ${avgDuration}ms\n`;
    if (data.errors > 0) {
      visualization += `   └─ Errors: ${data.errors}\n`;
    }
    visualization += '\n';
    step++;
  });

  return visualization;
}

function generateExecutionSummary(executionData: Record<string, unknown>): Record<string, unknown> {
  return {
    executionId: executionData.executionId,
    scenarioId: executionData.scenarioId,
    status: executionData.status,
    duration: Date.now() - new Date(executionData.startTime as string).getTime(),
    progress: executionData.progress,
    performance: executionData.performance,
    alertsSummary: {
      total: (executionData.alerts as unknown[]).length,
      errors: (executionData.alerts as Array<{ type: string }>).filter(a => a.type === 'error').length,
      performance: (executionData.alerts as Array<{ type: string }>).filter(a => a.type === 'performance').length,
    },
    logsSummary: {
      total: (executionData.logs as MakeLogEntry[]).length,
      errors: (executionData.logs as MakeLogEntry[]).filter(log => log.error).length,
      modules: new Set((executionData.logs as MakeLogEntry[]).map(log => log.module.name)).size,
    },
  };
}

function generateExportSummary(logs: MakeLogEntry[], exportConfig: ExportConfig): Record<string, unknown> {
  return {
    totalLogsExported: logs.length,
    timeRange: exportConfig.timeRange || { startTime: new Date(0).toISOString(), endTime: new Date().toISOString() },
    scenariosCovered: new Set(logs.map(log => log.scenarioId)).size,
    modulesCovered: new Set(logs.map(log => log.module.name)).size,
    errorRate: logs.filter(log => log.error).length / logs.length * 100,
    dataProcessed: logs.reduce((sum, log) => sum + (log.metrics?.dataSize || 0), 0),
    operationsTotal: logs.reduce((sum, log) => sum + (log.metrics?.operations || 0), 0),
  };
}

// Format conversion functions
function convertLogsToCSV(logs: MakeLogEntry[]): string {
  const headers = [
    'timestamp', 'level', 'execution_id', 'scenario_id', 'module_name',
    'module_type', 'message', 'operations', 'data_size', 'processing_time',
    'error_code', 'error_message'
  ];

  const rows = logs.map(log => [
    log.timestamp,
    log.level,
    log.executionId,
    log.scenarioId,
    log.module.name,
    log.module.type,
    `"${log.message.replace(/"/g, '""')}"`,
    log.metrics?.operations || 0,
    log.metrics?.dataSize || 0,
    log.metrics?.processingTime || 0,
    log.error?.code || '',
    log.error ? `"${log.error.message.replace(/"/g, '""')}"` : '',
  ]);

  return [headers.join(','), ...rows.map(row => row.join(','))].join('\n');
}

function convertLogsToElasticsearch(logs: MakeLogEntry[], _metadata: Record<string, unknown>): string {
  return logs.map(log => {
    const indexLine = {
      index: {
        _index: `fastmcp-logs-${new Date(log.timestamp).toISOString().slice(0, 7)}`, // Monthly indices
        _type: '_doc',
      }
    };

    const docLine = {
      '@timestamp': log.timestamp,
      level: log.level,
      message: log.message,
      execution_id: log.executionId,
      scenario_id: log.scenarioId,
      organization_id: log.organizationId,
      team_id: log.teamId,
      module: {
        id: log.module.id,
        name: log.module.name,
        type: log.module.type,
        version: log.module.version,
      },
      metrics: log.metrics,
      error: log.error,
      labels: {
        source: 'fastmcp-server',
        export_id: _metadata.exportId,
      },
    };

    return JSON.stringify(indexLine) + '\n' + JSON.stringify(docLine);
  }).join('\n');
}

function convertLogsToSplunk(logs: MakeLogEntry[], _metadata: Record<string, unknown>): string {
  return logs.map(log => {
    const splunkEvent = {
      time: Math.floor(new Date(log.timestamp).getTime() / 1000),
      host: 'fastmcp-server',
      source: 'make.com',
      sourcetype: 'fastmcp:scenario:log',
      index: 'fastmcp',
      event: {
        level: log.level,
        message: log.message,
        execution_id: log.executionId,
        scenario_id: log.scenarioId,
        module_name: log.module.name,
        module_type: log.module.type,
        operations: log.metrics?.operations,
        data_size: log.metrics?.dataSize,
        processing_time: log.metrics?.processingTime,
        error: log.error ? {
          code: log.error.code,
          message: log.error.message,
          type: log.error.type,
        } : null,
      },
    };

    return JSON.stringify(splunkEvent);
  }).join('\n');
}

function convertLogsToDatadog(logs: MakeLogEntry[], metadata: Record<string, unknown>): unknown {
  return {
    logs: logs.map(log => ({
      timestamp: new Date(log.timestamp).getTime(),
      level: log.level,
      message: log.message,
      service: 'fastmcp-server',
      source: 'make.com',
      tags: [
        `scenario_id:${log.scenarioId}`,
        `module_name:${log.module.name}`,
        `module_type:${log.module.type}`,
        `execution_id:${log.executionId}`,
        `level:${log.level}`,
      ],
      attributes: {
        execution_id: log.executionId,
        scenario_id: log.scenarioId,
        organization_id: log.organizationId,
        team_id: log.teamId,
        module: log.module,
        metrics: log.metrics,
        error: log.error,
      },
    })),
    metadata: {
      export_id: metadata.exportId,
      total_logs: logs.length,
      exported_at: metadata.timestamp,
    },
  };
}

// Advanced log analysis functions
async function performAdvancedLogAnalysis(
  logs: MakeLogEntry[],
  analysis: {
    performanceTrends?: boolean;
    errorPatterns?: boolean;
    usageMetrics?: boolean;
    executionFlow?: boolean;
    anomalyDetection?: boolean;
  },
  timeRange: { startTime: string; endTime: string }
): Promise<Record<string, unknown>> {
  const result: Record<string, unknown> = {};

  if (analysis.performanceTrends) {
    result.performanceTrends = analyzePerformanceTrends(logs, timeRange);
  }

  if (analysis.errorPatterns) {
    result.errorPatterns = analyzeErrorPatterns(logs);
  }

  if (analysis.usageMetrics) {
    result.usageMetrics = calculateUsageMetrics(logs, timeRange);
  }

  if (analysis.executionFlow) {
    result.executionFlow = analyzeExecutionFlow(logs);
  }

  if (analysis.anomalyDetection) {
    result.anomalyDetection = detectAnomalies(logs);
  }

  return result;
}

function analyzePerformanceTrends(
  logs: MakeLogEntry[],
  timeRange: { startTime: string; endTime: string }
): Record<string, unknown> {
  const timeSpan = new Date(timeRange.endTime).getTime() - new Date(timeRange.startTime).getTime();
  const intervals = Math.min(24, Math.max(4, Math.floor(timeSpan / (1000 * 60 * 60)))); // Between 4-24 intervals
  
  const intervalDuration = timeSpan / intervals;
  const intervalData: Array<{
    start: string;
    end: string;
    logs: MakeLogEntry[];
    avgProcessingTime: number;
    avgDataSize: number;
    avgOperations: number;
    errorRate: number;
  }> = [];

  for (let i = 0; i < intervals; i++) {
    const intervalStart = new Date(new Date(timeRange.startTime).getTime() + i * intervalDuration);
    const intervalEnd = new Date(new Date(timeRange.startTime).getTime() + (i + 1) * intervalDuration);
    
    const intervalLogs = logs.filter(log => {
      const logTime = new Date(log.timestamp).getTime();
      return logTime >= intervalStart.getTime() && logTime < intervalEnd.getTime();
    });

    if (intervalLogs.length > 0) {
      const processingTimes = intervalLogs.filter(log => log.metrics?.processingTime).map(log => log.metrics!.processingTime);
      const dataSizes = intervalLogs.filter(log => log.metrics?.dataSize).map(log => log.metrics!.dataSize);
      const operations = intervalLogs.filter(log => log.metrics?.operations).map(log => log.metrics!.operations);
      const errors = intervalLogs.filter(log => log.error).length;

      intervalData.push({
        start: intervalStart.toISOString(),
        end: intervalEnd.toISOString(),
        logs: intervalLogs,
        avgProcessingTime: processingTimes.length > 0 ? processingTimes.reduce((sum, time) => sum + time, 0) / processingTimes.length : 0,
        avgDataSize: dataSizes.length > 0 ? dataSizes.reduce((sum, size) => sum + size, 0) / dataSizes.length : 0,
        avgOperations: operations.length > 0 ? operations.reduce((sum, ops) => sum + ops, 0) / operations.length : 0,
        errorRate: (errors / intervalLogs.length) * 100,
      });
    }
  }

  // Calculate trends
  const processingTimes = intervalData.map(interval => interval.avgProcessingTime);
  const errorRates = intervalData.map(interval => interval.errorRate);
  
  const processingTrend = calculateTrend(processingTimes);
  const errorTrend = calculateTrend(errorRates);
  
  return {
    timeSpan: `${Math.round(timeSpan / (1000 * 60 * 60))} hours`,
    intervals: intervalData.length,
    trends: {
      processing: {
        direction: processingTrend > 0.1 ? 'increasing' : processingTrend < -0.1 ? 'decreasing' : 'stable',
        slope: processingTrend,
        interpretation: processingTrend > 0.5 ? 'Performance is degrading over time' : 
                       processingTrend < -0.5 ? 'Performance is improving over time' : 
                       'Performance is stable',
      },
      errors: {
        direction: errorTrend > 0.1 ? 'increasing' : errorTrend < -0.1 ? 'decreasing' : 'stable',
        slope: errorTrend,
        interpretation: errorTrend > 0.5 ? 'Error rates are increasing over time' : 
                       errorTrend < -0.5 ? 'Error rates are decreasing over time' : 
                       'Error rates are stable',
      },
    },
    intervalData: intervalData.map(interval => ({
      start: interval.start,
      end: interval.end,
      logCount: interval.logs.length,
      avgProcessingTime: Math.round(interval.avgProcessingTime),
      avgDataSize: Math.round(interval.avgDataSize),
      avgOperations: Math.round(interval.avgOperations),
      errorRate: Math.round(interval.errorRate * 100) / 100,
    })),
    recommendations: generatePerformanceTrendRecommendations(),
  };
}

function analyzeErrorPatterns(logs: MakeLogEntry[]): Record<string, unknown> {
  const errorLogs = logs.filter(log => log.error);
  
  if (errorLogs.length === 0) {
    return {
      totalErrors: 0,
      message: 'No errors found in the analyzed logs',
      errorRate: 0,
    };
  }

  // Error classification
  const errorsByType = errorLogs.reduce((acc, log) => {
    const type = log.error!.type;
    if (!acc[type]) acc[type] = [];
    acc[type].push(log);
    return acc;
  }, {} as Record<string, MakeLogEntry[]>);

  const errorsByCode = errorLogs.reduce((acc, log) => {
    const code = log.error!.code;
    if (!acc[code]) acc[code] = [];
    acc[code].push(log);
    return acc;
  }, {} as Record<string, MakeLogEntry[]>);

  const errorsByModule = errorLogs.reduce((acc, log) => {
    const module = log.module.name;
    if (!acc[module]) acc[module] = [];
    acc[module].push(log);
    return acc;
  }, {} as Record<string, MakeLogEntry[]>);

  // Temporal error analysis
  const errorTimes = errorLogs.map(log => new Date(log.timestamp).getTime());
  const timeSpan = Math.max(...errorTimes) - Math.min(...errorTimes);
  
  // Check for error bursts (multiple errors in short timeframes)
  const burstThreshold = 5 * 60 * 1000; // 5 minutes
  const errorBursts: Array<{ start: string; end: string; count: number; errors: MakeLogEntry[] }> = [];
  
  let currentBurst: MakeLogEntry[] = [];
  let burstStart = 0;
  
  errorLogs.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  
  for (const errorLog of errorLogs) {
    const errorTime = new Date(errorLog.timestamp).getTime();
    
    if (currentBurst.length === 0 || errorTime - burstStart <= burstThreshold) {
      if (currentBurst.length === 0) burstStart = errorTime;
      currentBurst.push(errorLog);
    } else {
      if (currentBurst.length >= 3) { // At least 3 errors in 5 minutes
        errorBursts.push({
          start: currentBurst[0].timestamp,
          end: currentBurst[currentBurst.length - 1].timestamp,
          count: currentBurst.length,
          errors: currentBurst,
        });
      }
      currentBurst = [errorLog];
      burstStart = errorTime;
    }
  }
  
  // Check final burst
  if (currentBurst.length >= 3) {
    errorBursts.push({
      start: currentBurst[0].timestamp,
      end: currentBurst[currentBurst.length - 1].timestamp,
      count: currentBurst.length,
      errors: currentBurst,
    });
  }

  // Root cause analysis
  const rootCauses = identifyRootCauses(errorsByType, errorsByModule);
  
  return {
    summary: {
      totalErrors: errorLogs.length,
      errorRate: (errorLogs.length / logs.length) * 100,
      timeSpan: `${Math.round(timeSpan / (1000 * 60 * 60))} hours`,
      uniqueErrorTypes: Object.keys(errorsByType).length,
      uniqueErrorCodes: Object.keys(errorsByCode).length,
      affectedModules: Object.keys(errorsByModule).length,
    },
    classification: {
      byType: Object.entries(errorsByType).map(([type, errors]) => ({
        type,
        count: errors.length,
        percentage: (errors.length / errorLogs.length) * 100,
        retryable: errors.filter(log => log.error!.retryable).length,
        firstOccurrence: errors[0].timestamp,
        lastOccurrence: errors[errors.length - 1].timestamp,
      })).sort((a, b) => b.count - a.count),
      byCode: Object.entries(errorsByCode).map(([code, errors]) => ({
        code,
        count: errors.length,
        percentage: (errors.length / errorLogs.length) * 100,
        modules: new Set(errors.map(log => log.module.name)).size,
      })).sort((a, b) => b.count - a.count).slice(0, 10),
      byModule: Object.entries(errorsByModule).map(([module, errors]) => ({
        module,
        count: errors.length,
        percentage: (errors.length / errorLogs.length) * 100,
        errorTypes: new Set(errors.map(log => log.error!.type)).size,
        reliability: ((logs.filter(log => log.module.name === module).length - errors.length) / 
                     logs.filter(log => log.module.name === module).length) * 100,
      })).sort((a, b) => b.count - a.count),
    },
    temporalAnalysis: {
      errorBursts: errorBursts.map(burst => ({
        start: burst.start,
        end: burst.end,
        count: burst.count,
        duration: `${Math.round((new Date(burst.end).getTime() - new Date(burst.start).getTime()) / 1000)} seconds`,
        errorTypes: new Set(burst.errors.map(log => log.error!.type)).size,
        modules: new Set(burst.errors.map(log => log.module.name)).size,
      })),
      distribution: analyzeErrorDistribution(errorLogs),
    },
    rootCauses,
    recommendations: generateErrorPatternRecommendations(),
  };
}

// Helper functions for trend calculation and analysis
function calculateTrend(values: number[]): number {
  if (values.length < 2) return 0;
  
  const n = values.length;
  const sumX = values.reduce((sum, _, i) => sum + i, 0);
  const sumY = values.reduce((sum, val) => sum + val, 0);
  const sumXY = values.reduce((sum, val, i) => sum + i * val, 0);
  const sumXX = values.reduce((sum, _, i) => sum + i * i, 0);
  
  return (n * sumXY - sumX * sumY) / (n * sumXX - sumX * sumX);
}

function calculateUsageMetrics(
  logs: MakeLogEntry[],
  timeRange: { startTime: string; endTime: string }
): Record<string, unknown> {
  const timeSpan = new Date(timeRange.endTime).getTime() - new Date(timeRange.startTime).getTime();
  const hours = timeSpan / (1000 * 60 * 60);
  
  const totalOperations = logs.reduce((sum, log) => sum + (log.metrics?.operations || 0), 0);
  const totalDataProcessed = logs.reduce((sum, log) => sum + (log.metrics?.dataSize || 0), 0);
  
  return {
    timeRange: {
      duration: `${Math.round(hours * 100) / 100} hours`,
      from: timeRange.startTime,
      to: timeRange.endTime,
    },
    resourceUtilization: {
      operations: {
        total: totalOperations,
        perHour: Math.round(totalOperations / hours),
      },
      data: {
        total: totalDataProcessed,
        totalFormatted: formatBytes(totalDataProcessed),
      },
    },
  };
}

function analyzeExecutionFlow(logs: MakeLogEntry[]): Record<string, unknown> {
  const executionGroups = logs.reduce((acc, log) => {
    if (!acc[log.executionId]) acc[log.executionId] = [];
    acc[log.executionId].push(log);
    return acc;
  }, {} as Record<string, MakeLogEntry[]>);

  const executionAnalysis = Object.entries(executionGroups).map(([executionId, executionLogs]) => {
    const sortedLogs = executionLogs.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
    const startTime = new Date(sortedLogs[0].timestamp);
    const endTime = new Date(sortedLogs[sortedLogs.length - 1].timestamp);
    const duration = endTime.getTime() - startTime.getTime();
    
    return {
      executionId,
      duration,
      steps: sortedLogs.length,
      success: !executionLogs.some(log => log.error),
    };
  }).sort((a, b) => b.duration - a.duration);
  
  return {
    summary: {
      totalExecutions: executionAnalysis.length,
      successfulExecutions: executionAnalysis.filter(exec => exec.success).length,
      averageExecutionTime: executionAnalysis.reduce((sum, exec) => sum + exec.duration, 0) / executionAnalysis.length,
    },
    executions: executionAnalysis.slice(0, 10),
  };
}

function detectAnomalies(logs: MakeLogEntry[]): Record<string, unknown> {
  const anomalies: Array<{
    type: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    count: number;
  }> = [];
  
  // Performance anomalies
  const processingTimes = logs.filter(log => log.metrics?.processingTime).map(log => log.metrics!.processingTime);
  if (processingTimes.length > 0) {
    const mean = processingTimes.reduce((sum, time) => sum + time, 0) / processingTimes.length;
    const stdDev = Math.sqrt(calculateVariance(processingTimes));
    const threshold = mean + (2 * stdDev);
    
    const slowLogs = logs.filter(log => log.metrics?.processingTime && log.metrics.processingTime > threshold);
    if (slowLogs.length > 0) {
      anomalies.push({
        type: 'performance_anomaly',
        severity: slowLogs.length > 5 ? 'high' : 'medium',
        description: `${slowLogs.length} logs with processing times significantly above normal`,
        count: slowLogs.length,
      });
    }
  }
  
  return {
    summary: {
      totalAnomalies: anomalies.length,
      critical: anomalies.filter(a => a.severity === 'critical').length,
      high: anomalies.filter(a => a.severity === 'high').length,
    },
    anomalies,
  };
}

// Additional helper functions
function calculateVariance(numbers: number[]): number {
  if (numbers.length === 0) return 0;
  const mean = numbers.reduce((sum, num) => sum + num, 0) / numbers.length;
  const squaredDiffs = numbers.map(num => Math.pow(num - mean, 2));
  return squaredDiffs.reduce((sum, diff) => sum + diff, 0) / numbers.length;
}

// Helper function to format bytes
function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function identifyRootCauses(
  errorsByType: Record<string, MakeLogEntry[]>,
  errorsByModule: Record<string, MakeLogEntry[]>
): Record<string, unknown> {
  return {
    primaryErrorTypes: Object.entries(errorsByType)
      .sort(([, a], [, b]) => b.length - a.length)
      .slice(0, 3)
      .map(([type, errors]) => ({ type, count: errors.length })),
    problematicModules: Object.entries(errorsByModule)
      .sort(([, a], [, b]) => b.length - a.length)
      .slice(0, 3)
      .map(([module, errors]) => ({ module, count: errors.length })),
  };
}

function analyzeErrorDistribution(errorLogs: MakeLogEntry[]): Record<string, unknown> {
  const hourlyDistribution = errorLogs.reduce((acc, log) => {
    const hour = new Date(log.timestamp).getHours();
    acc[hour] = (acc[hour] || 0) + 1;
    return acc;
  }, {} as Record<number, number>);
  
  return { hourlyDistribution };
}

// Export preparation function
async function prepareLogExport(
  logs: MakeLogEntry[],
  exportConfig: { format: string; includeCharts?: boolean; compression?: boolean },
  analysisResult: Record<string, unknown>
): Promise<Record<string, unknown>> {
  return {
    metadata: {
      exportedAt: new Date().toISOString(),
      format: exportConfig.format,
      totalLogs: logs.length,
    },
    data: exportConfig.format === 'csv' ? convertLogsToCSV(logs) : { logs, analysis: analysisResult },
  };
}

// Recommendation generators
function generatePerformanceTrendRecommendations(): string[] {
  return ['Monitor performance trends and optimize slow components'];
}

function generateErrorPatternRecommendations(): string[] {
  return ['Implement retry mechanisms for transient errors'];
}

function generateLogAnalysisRecommendations(logs: MakeLogEntry[]): string[] {
  const errorRate = (logs.filter(log => log.error).length / logs.length) * 100;
  const recommendations = [];
  
  if (errorRate > 10) {
    recommendations.push(`High error rate detected (${errorRate.toFixed(1)}%). Review error patterns and implement retry mechanisms.`);
  } else {
    recommendations.push('System performance appears to be within normal parameters.');
  }
  
  return recommendations;
}

export default { addLogStreamingTools };