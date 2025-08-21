/**
 * @fileoverview Export configuration schemas for log streaming tools
 * Zod schema definitions for log export functionality
 */

import { z } from 'zod';

export const ExportLogsForAnalysisSchema = z.object({
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