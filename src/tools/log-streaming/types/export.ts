/**
 * @fileoverview Export configuration types for log streaming tools
 * Type definitions for log export functionality and configurations
 */

export interface DataTransformation {
  operation?: 'rename' | 'format_date' | 'parse_json' | 'extract_regex' | 'convert_type' | 'filter_fields';
  field?: string;
  targetField?: string;
  parameters?: Record<string, unknown>;
}

export interface ExportConfig {
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

export interface LogExportResult {
  success: boolean;
  exportId?: string;
  downloadUrl?: string;
  error?: string;
  totalRecords: number;
  exportFormat: string;
}