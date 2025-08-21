/**
 * @fileoverview Streaming configuration schemas for log streaming tools
 * Zod schema definitions for real-time log streaming
 */

import { z } from 'zod';

export const ScenarioRunLogsSchema = z.object({
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

export const StreamLiveExecutionSchema = z.object({
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

export const QueryLogsByTimeRangeSchema = z.object({
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