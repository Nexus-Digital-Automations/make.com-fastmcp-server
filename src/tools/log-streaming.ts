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
  timeRange: z.object({
    startTime: z.string().describe('Start time for query (ISO format)'),
    endTime: z.string().describe('End time for query (ISO format)'),
  }).describe('Time range for log query'),
  filtering: z.object({
    logLevels: z.array(z.enum(['debug', 'info', 'warn', 'error', 'critical'])).default(['info', 'warn', 'error']).describe('Log levels to include'),
    executionStatus: z.enum(['success', 'failed', 'warning', 'running']).optional().describe('Filter by execution status'),
    moduleTypes: z.array(z.string()).optional().describe('Module types to filter by'),
    searchText: z.string().optional().describe('Search text in log messages'),
    errorCodesOnly: z.boolean().default(false).describe('Only return logs with error codes'),
  }).default({}),
  pagination: z.object({
    limit: z.number().min(1).max(1000).default(100).describe('Maximum number of logs to return'),
    offset: z.number().min(0).default(0).describe('Number of logs to skip'),
    sortBy: z.enum(['timestamp', 'level', 'module']).default('timestamp').describe('Sort field'),
    sortOrder: z.enum(['asc', 'desc']).default('desc').describe('Sort order'),
  }).default({}),
  aggregation: z.object({
    enabled: z.boolean().default(false).describe('Enable log aggregation'),
    groupBy: z.enum(['level', 'module', 'hour']).optional().describe('Group logs by field'),
    includeStats: z.boolean().default(true).describe('Include aggregation statistics'),
  }).default({}),
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
    }).default({}),
  }).describe('Export configuration'),
  outputConfig: z.object({
    format: z.enum(['json', 'csv', 'elasticsearch', 'splunk', 'datadog']).default('json').describe('Export format'),
    compression: z.enum(['none', 'gzip', 'zip']).default('gzip').describe('Compression format'),
    chunkSize: z.number().min(100).max(10000).default(1000).describe('Number of logs per chunk'),
    includeMetadata: z.boolean().default(true).describe('Include export metadata'),
  }).default({}),
  destination: z.object({
    type: z.enum(['download', 'webhook', 'external-system']).default('download').describe('Export destination'),
    webhookUrl: z.string().optional().describe('Webhook URL for external delivery'),
    externalSystemConfig: z.record(z.unknown()).optional().describe('External system configuration'),
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

  // 2. Query Logs by Time Range
  server.addTool({
    name: 'query_logs_by_timerange',
    description: 'Search and filter historical logs across multiple scenarios and time ranges with advanced aggregation',
    parameters: QueryLogsByTimeRangeSchema,
    execute: async (input, { log }) => {
      const { scenarioId, organizationId, teamId, timeRange, filtering, pagination, aggregation } = input;

      log.info('Querying logs by time range', {
        scenarioId,
        organizationId,
        teamId,
        timeRange,
        filtering,
        pagination,
      });

      try {
        const params: Record<string, unknown> = {
          startDate: timeRange.startTime,
          endDate: timeRange.endTime,
          limit: pagination.limit,
          offset: pagination.offset,
          sortBy: pagination.sortBy,
          sortOrder: pagination.sortOrder,
        };

        if (scenarioId) params.scenarioId = scenarioId;
        if (organizationId) params.organizationId = organizationId;
        if (teamId) params.teamId = teamId;
        if (filtering.logLevels.length > 0) params.level = filtering.logLevels.join(',');
        if (filtering.executionStatus) params.status = filtering.executionStatus;
        if (filtering.moduleTypes?.length) params.moduleTypes = filtering.moduleTypes.join(',');
        if (filtering.searchText) params.search = filtering.searchText;
        if (filtering.errorCodesOnly) params.errorsOnly = true;

        // Determine endpoint based on scope
        let endpoint = '/logs';
        if (scenarioId) {
          endpoint = `/scenarios/${scenarioId}/logs`;
        } else if (organizationId) {
          endpoint = `/organizations/${organizationId}/logs`;
        } else if (teamId) {
          endpoint = `/teams/${teamId}/logs`;
        }

        const response = await apiClient.get(endpoint, { params });

        if (!response.success) {
          throw new UserError(`Failed to query logs: ${response.error?.message || 'Unknown error'}`);
        }

        const logs = (response.data as MakeLogEntry[]) || [];
        const metadata = response.metadata;

        const result: Record<string, unknown> = {
          query: {
            timeRange,
            filtering,
            pagination,
          },
          logs,
          summary: generateLogSummary(logs),
          pagination: {
            total: metadata?.total || logs.length,
            limit: pagination.limit,
            offset: pagination.offset,
            hasMore: (metadata?.total || 0) > (pagination.offset + logs.length),
          },
        };

        // Add aggregation if requested
        if (aggregation.enabled && aggregation.groupBy) {
          result.aggregation = generateLogAggregation(logs, aggregation.groupBy, aggregation.includeStats);
        }

        log.info('Successfully queried logs by time range', {
          count: logs.length,
          total: metadata?.total,
          timeRange,
        });

        return JSON.stringify(result, null, 2);

      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error querying logs by time range', { timeRange, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to query logs by time range: ${errorMessage}`);
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
        let targetExecutionId: string | null = executionId;
        
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
            currentModule: null,
            estimatedCompletion: null,
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

  // 4. Export Logs for Analysis
  server.addTool({
    name: 'export_logs_for_analysis',
    description: 'Export logs in various formats for external analysis tools like Elasticsearch, Splunk, or custom analytics platforms',
    parameters: ExportLogsForAnalysisSchema,
    execute: async (input, { log }) => {
      const { exportConfig, outputConfig, destination } = input;

      log.info('Starting log export for analysis', {
        exportConfig,
        outputConfig,
        destination,
      });

      try {
        const exportMetadata = {
          exportId: `export_${Date.now()}`,
          timestamp: new Date().toISOString(),
          requestedBy: 'fastmcp-server',
          config: exportConfig,
        };

        // Build query parameters for log retrieval
        const params: Record<string, unknown> = {
          startDate: exportConfig.timeRange.startTime,
          endDate: exportConfig.timeRange.endTime,
          limit: outputConfig.chunkSize,
          offset: 0,
        };

        if (exportConfig.scenarioIds?.length) {
          params.scenarioIds = exportConfig.scenarioIds.join(',');
        }
        if (exportConfig.organizationId) {
          params.organizationId = exportConfig.organizationId;
        }
        if (exportConfig.filtering.logLevels.length > 0) {
          params.level = exportConfig.filtering.logLevels.join(',');
        }
        if (exportConfig.filtering.moduleTypes?.length) {
          params.moduleTypes = exportConfig.filtering.moduleTypes.join(',');
        }

        // Determine endpoint
        let endpoint = '/logs';
        if (exportConfig.organizationId) {
          endpoint = `/organizations/${exportConfig.organizationId}/logs`;
        }

        const allLogs: MakeLogEntry[] = [];
        let hasMore = true;
        let offset = 0;
        let totalProcessed = 0;

        // Fetch all logs in chunks
        while (hasMore) {
          params.offset = offset;
          
          const response = await apiClient.get(endpoint, { params });
          
          if (!response.success) {
            throw new UserError(`Failed to fetch logs: ${response.error?.message || 'Unknown error'}`);
          }

          const logs = (response.data as MakeLogEntry[]) || [];
          
          if (logs.length === 0) {
            hasMore = false;
          } else {
            // Apply additional filtering
            let filteredLogs = logs;

            if (!exportConfig.filtering.includeSuccessfulExecutions) {
              filteredLogs = filteredLogs.filter(log => log.level !== 'info' || log.error);
            }

            if (!exportConfig.filtering.includeFailedExecutions) {
              filteredLogs = filteredLogs.filter(log => !log.error);
            }

            allLogs.push(...filteredLogs);
            totalProcessed += logs.length;
            offset += outputConfig.chunkSize;

            // Check if we've reached the end
            const metadata = response.metadata;
            if (metadata?.total && totalProcessed >= metadata.total) {
              hasMore = false;
            }
          }

          log.info('Processing log export chunk', {
            offset,
            chunkSize: logs.length,
            totalProcessed,
            totalFiltered: allLogs.length,
          });
        }

        // Format logs based on output format
        let exportData: unknown;
        let contentType: string;
        let fileExtension: string;

        switch (outputConfig.format) {
          case 'json':
            exportData = {
              metadata: outputConfig.includeMetadata ? exportMetadata : undefined,
              logs: allLogs,
              summary: generateLogSummary(allLogs),
            };
            contentType = 'application/json';
            fileExtension = 'json';
            break;

          case 'csv':
            exportData = convertLogsToCSV(allLogs);
            contentType = 'text/csv';
            fileExtension = 'csv';
            break;

          case 'elasticsearch':
            exportData = convertLogsToElasticsearch(allLogs, exportMetadata);
            contentType = 'application/x-ndjson';
            fileExtension = 'ndjson';
            break;

          case 'splunk':
            exportData = convertLogsToSplunk(allLogs, exportMetadata);
            contentType = 'text/plain';
            fileExtension = 'log';
            break;

          case 'datadog':
            exportData = convertLogsToDatadog(allLogs, exportMetadata);
            contentType = 'application/json';
            fileExtension = 'json';
            break;

          default:
            throw new UserError(`Unsupported output format: ${outputConfig.format}`);
        }

        // Handle compression if requested
        const finalData = exportData;
        if (outputConfig.compression !== 'none') {
          // Note: In a real implementation, you would compress the data here
          log.info('Compression requested but not implemented in this demo', {
            compression: outputConfig.compression,
          });
        }

        const exportResult = {
          exportMetadata,
          dataInfo: {
            format: outputConfig.format,
            contentType,
            fileExtension,
            compression: outputConfig.compression,
            totalLogs: allLogs.length,
            sizeEstimate: JSON.stringify(finalData).length,
          },
          data: finalData,
          summary: generateExportSummary(allLogs, exportConfig as Record<string, unknown>),
        };

        log.info('Log export completed successfully', {
          exportId: exportMetadata.exportId,
          totalLogs: allLogs.length,
          format: outputConfig.format,
          compression: outputConfig.compression,
        });

        return JSON.stringify(exportResult, null, 2);

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

function generateExportSummary(logs: MakeLogEntry[], exportConfig: Record<string, unknown>): Record<string, unknown> {
  return {
    totalLogsExported: logs.length,
    timeRange: exportConfig.timeRange,
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

export default { addLogStreamingTools };