/**
 * @fileoverview Export configuration types for log streaming tools
 * Type definitions for log export functionality and configurations
 */

export interface DataTransformation {
  type?: 'field_mapping' | 'aggregation' | 'filtering';
  operation?: 'rename' | 'format_date' | 'parse_json' | 'extract_regex' | 'convert_type' | 'filter_fields';
  field?: string;
  targetField?: string;
  parameters?: Record<string, unknown>;
  config?: Record<string, unknown>;
}

export interface ExportConfig {
  scenarioIds?: number[];
  organizationId?: number;
  timeRange?: {
    start?: string;
    end?: string;
    startTime?: string;
    endTime?: string;
  };
  filtering?: {
    logLevels?: string[];
    modules?: string[];
    moduleTypes?: string[];
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
    correlationIds?: string[];
    errorCodesOnly?: boolean;
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
}

export interface OutputConfig {
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

export interface DestinationConfig {
  type?: 'file' | 's3' | 'gcs' | 'azure' | 'ftp' | 'sftp' | 'http' | 'webhook' | 'external-system' | 'stream' | 'download';
  path?: string;
  webhookUrl?: string;
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

export interface ExternalSystemConfig {
  type?: 'elasticsearch' | 'splunk' | 'datadog' | 'newrelic' | 'generic' | 'aws-cloudwatch' | 'azure-monitor' | 'gcp-logging';
  endpoint?: string;
  connection?: {
    url?: string;
    apiKey?: string;
    username?: string;
    password?: string;
    region?: string;
    index?: string;
    logGroup?: string;
    workspace?: string;
  };
  authentication?: {
    type?: 'bearer' | 'api-key' | 'basic' | 'api_key' | 'oauth2' | 'basic_auth' | 'oauth' | 'bearer_token';
    credentials?: Record<string, string>;
  };
  headers?: Record<string, string>;
  retryPolicy?: {
    maxRetries?: number;
    retryDelayMs?: number;
    backoffMultiplier?: number;
  };
  options?: {
    timeout?: number;
    retries?: number;
    batchSize?: number;
    compression?: boolean;
  };
}

export interface AnalyticsConfig {
  enabled: boolean;
  performanceAnalysis?: boolean;
  errorAnalysis?: boolean;
  usagePatterns?: boolean;
  trendAnalysis?: boolean;
  features?: {
    anomalyDetection?: boolean;
    performanceAnalysis?: boolean;
    errorCorrelation?: boolean;
    predictiveInsights?: boolean;
  };
  customMetrics?: Array<{
    name: string;
    aggregation: 'count' | 'sum' | 'avg' | 'min' | 'max';
    field: string;
    filters?: Record<string, unknown>;
  }>;
}

export interface LogExportResult {
  success: boolean;
  exportId?: string;
  downloadUrl?: string;
  error?: string;
  totalRecords: number;
  exportFormat: string;
}