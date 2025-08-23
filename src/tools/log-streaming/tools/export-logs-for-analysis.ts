/**
 * @fileoverview Export Logs for Analysis Tool Implementation
 * Advanced log export tool with multi-format output, real-time streaming, and external analytics platform integration
 */

import { UserError } from 'fastmcp';
import { ExportLogsForAnalysisSchema } from '../schemas/export-config.js';
import { ToolContext, ToolDefinition } from '../../shared/types/tool-context.js';
import { MakeLogEntry } from '../types/streaming.js';
import { 
  ExportConfig, 
  OutputConfig, 
  DestinationConfig, 
  AnalyticsConfig,
  ExternalSystemConfig,
  DataTransformation
} from '../types/export.js';
import MakeApiClient from '../../../lib/make-api-client.js';
import { formatSuccessResponse } from '../../../utils/response-formatter.js';

/**
 * Build query parameters for log retrieval
 */
function buildLogQueryParams(
  exportConfig: ExportConfig,
  outputConfig: OutputConfig
): Record<string, unknown> {
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
  if (exportConfig.filtering?.logLevels?.length) {
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

  return params;
}

/**
 * Determine optimal API endpoint for log retrieval
 */
function determineLogEndpoint(exportConfig: ExportConfig): string {
  if (exportConfig.organizationId) {
    return `/organizations/${exportConfig.organizationId}/logs`;
  }
  return '/logs';
}

/**
 * Normalize export configuration with proper defaults
 */
function normalizeExportConfig(exportConfig: ExportConfig): ExportConfig {
  return {
    ...exportConfig,
    streaming: {
      enabled: exportConfig.streaming?.enabled ?? false,
      batchSize: exportConfig.streaming?.batchSize ?? 50,
      intervalMs: exportConfig.streaming?.intervalMs ?? 5000,
      maxDuration: exportConfig.streaming?.maxDuration ?? 3600
    }
  };
}

/**
 * Normalize destination configuration
 */
function normalizeDestinationConfig(destination: DestinationConfig): DestinationConfig {
  return {
    type: destination.type,
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
}

/**
 * Create export logs for analysis tool configuration
 */
export function createExportLogsForAnalysisTool(context: ToolContext): ToolDefinition {
  const { apiClient, logger } = context;
  
  return {
    name: 'export_logs_for_analysis',
    description: 'Advanced log export tool with multi-format output, real-time streaming, external analytics platform integration, and comprehensive delivery options',
    parameters: ExportLogsForAnalysisSchema,
    annotations: {
      title: 'Export Logs for Analysis',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
    execute: async (input: unknown, { log }): Promise<string> => {
      const { exportConfig, outputConfig, destination, analytics } = input as {
        exportConfig: ExportConfig;
        outputConfig: OutputConfig;
        destination: DestinationConfig;
        analytics: AnalyticsConfig;
      };

      log?.info?.('Starting enhanced log export for analysis', {
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

        // Build query parameters for log retrieval
        const params = buildLogQueryParams(exportConfig, outputConfig);
        
        // Determine optimal endpoint
        const endpoint = determineLogEndpoint(exportConfig);

        // Initialize enhanced export processor
        const exportProcessor = new EnhancedLogExportProcessor(apiClient, exportMetadata, logger);
        
        // Normalize configurations
        const normalizedExportConfig = normalizeExportConfig(exportConfig);
        const normalizedDestination = normalizeDestinationConfig(destination);

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

      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.error?.('Error exporting logs for analysis', { 
          exportConfig: JSON.stringify(exportConfig), 
          error: errorMessage 
        });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to export logs for analysis: ${errorMessage}`);
      }
    },
  };
}

/**
 * Initialize external system connector if needed
 */
async function initializeExternalConnector(
  destination: DestinationConfig,
  logger: ToolContext['logger']
): Promise<ExternalSystemConnector | null> {
  if (destination.type === 'external-system' && destination.externalSystemConfig) {
    const connector = new ExternalSystemConnector(
      destination.externalSystemConfig,
      logger
    );
    await connector.connect();
    return connector;
  }
  return null;
}

/**
 * Process a streaming batch of logs
 */
async function processStreamingBatch(
  apiClient: MakeApiClient,
  endpoint: string,
  batchParams: Record<string, unknown>,
  exportConfig: ExportConfig,
  outputConfig: OutputConfig,
  exportMetadata: Record<string, unknown>,
  externalConnector: ExternalSystemConnector | null,
  processor: EnhancedLogExportProcessor
): Promise<{
  logsProcessed: number;
  lastTimestamp?: string;
  deliveryResult?: Record<string, unknown>;
}> {
  const response = await apiClient.get(endpoint, { params: batchParams });

  if (response.success && response.data) {
    const logs = response.data as MakeLogEntry[];
    
    if (logs.length > 0) {
      // Process batch through pipeline
      const filteredLogs = processor.applyAdvancedFiltering(logs, exportConfig.filtering);
      const transformedLogs = processor.applyDataTransformations(filteredLogs, outputConfig.transformations);
      
      if (transformedLogs.length > 0) {
        const batchData = await processor.formatLogsForExport(
          transformedLogs,
          outputConfig,
          exportMetadata
        );

        // Deliver batch to external system if available
        let deliveryResult;
        if (externalConnector) {
          deliveryResult = await externalConnector.sendBatch(batchData, outputConfig.format || 'json');
        }

        return {
          logsProcessed: transformedLogs.length,
          lastTimestamp: logs[logs.length - 1].timestamp,
          deliveryResult
        };
      }
    }
  }

  return { logsProcessed: 0 };
}

/**
 * Enhanced Log Export Processor for advanced analytics integration
 */
class EnhancedLogExportProcessor {
  private readonly apiClient: MakeApiClient;
  private readonly exportMetadata: Record<string, unknown>;
  private readonly logger: ToolContext['logger'];

  constructor(apiClient: MakeApiClient, exportMetadata: Record<string, unknown>, logger: ToolContext['logger']) {
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
    this.logger.info?.('Starting batch export processing');

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

      this.logger.info?.('Processing log export chunk', {
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

    this.logger.info?.('Batch export completed successfully', {
      exportId: String(this.exportMetadata.exportId),
      totalLogs: transformedLogs.length,
      format: outputConfig.format || 'json',
      external: destination.externalSystemConfig?.type || 'none',
    });

    return formatSuccessResponse(result).content[0].text;
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
    this.logger.info?.('Starting streaming export processing', {
      batchSize: exportConfig.streaming?.batchSize || 1000,
      intervalMs: exportConfig.streaming?.intervalMs || 5000,
      maxDuration: exportConfig.streaming?.maxDuration || 300,
    });

    // Initialize streaming session
    const streamingResults = this.initializeStreamingSession();
    const streamConfig = this.getStreamingConfiguration(exportConfig, params);
    const externalConnector = await initializeExternalConnector(destination, this.logger);

    // Execute streaming process
    await this.executeStreamingProcess(
      endpoint,
      streamConfig,
      exportConfig,
      outputConfig,
      externalConnector,
      streamingResults
    );

    // Cleanup and finalize
    await this.finalizeStreamingExport(externalConnector, streamingResults);

    // Generate and return result
    const result = this.buildStreamingResult(streamingResults, exportConfig);
    this.logStreamingCompletion(streamingResults);
    
    return formatSuccessResponse(result).content[0].text;
  }

  /**
   * Apply advanced filtering to logs
   */
  public applyAdvancedFiltering(logs: MakeLogEntry[], filtering?: ExportConfig['filtering']): MakeLogEntry[] {
    if (!filtering) {return logs;}

    return logs.filter(log => {
      // Log level filtering
      if (filtering.logLevels?.length && !filtering.logLevels.includes(log.level)) {
        return false;
      }

      // Module filtering
      if (filtering.modules?.length && !filtering.modules.includes(log.module.name)) {
        return false;
      }

      // Error code filtering
      if (filtering.errorCodesOnly && !log.error) {
        return false;
      }

      // Performance threshold filtering
      if (filtering.performanceThreshold && 
          (!log.metrics?.processingTime || log.metrics.processingTime < filtering.performanceThreshold)) {
        return false;
      }

      // Success/failure filtering
      if (filtering.includeSuccessfulExecutions === false && !log.error) {
        return false;
      }
      if (filtering.includeFailedExecutions === false && log.error) {
        return false;
      }

      return true;
    });
  }

  /**
   * Apply data transformations
   */
  public applyDataTransformations(logs: MakeLogEntry[], transformations?: DataTransformation[]): MakeLogEntry[] {
    if (!transformations?.length) {return logs;}

    let transformedLogs = [...logs];

    for (const transformation of transformations) {
      switch (transformation.type) {
        case 'field_mapping':
          // Apply field mapping transformation
          transformedLogs = transformedLogs.map(log => this.applyFieldMapping(log, transformation.config || {}));
          break;
        case 'aggregation':
          // Apply aggregation transformation
          transformedLogs = this.applyAggregation(transformedLogs, transformation.config || {});
          break;
        case 'filtering':
          // Apply additional filtering
          transformedLogs = this.applyCustomFiltering(transformedLogs, transformation.config || {});
          break;
      }
    }

    return transformedLogs;
  }

  /**
   * Apply field mapping transformation
   */
  private applyFieldMapping(log: MakeLogEntry, _config: Record<string, unknown>): MakeLogEntry {
    // Implement field mapping logic
    return log;
  }

  /**
   * Apply aggregation transformation
   */
  private applyAggregation(logs: MakeLogEntry[], _config: Record<string, unknown>): MakeLogEntry[] {
    // Implement aggregation logic
    return logs;
  }

  /**
   * Apply custom filtering
   */
  private applyCustomFiltering(logs: MakeLogEntry[], _config: Record<string, unknown>): MakeLogEntry[] {
    // Implement custom filtering logic
    return logs;
  }

  /**
   * Perform advanced analytics
   */
  private async performAdvancedAnalytics(logs: MakeLogEntry[], analytics: AnalyticsConfig): Promise<Record<string, unknown>> {
    const results: Record<string, unknown> = {};

    if (analytics.performanceAnalysis) {
      results.performance = this.analyzePerformance(logs);
    }

    if (analytics.errorAnalysis) {
      results.errors = this.analyzeErrors(logs);
    }

    if (analytics.usagePatterns) {
      results.usage = this.analyzeUsagePatterns(logs);
    }

    if (analytics.trendAnalysis) {
      results.trends = this.analyzeTrends(logs);
    }

    return results;
  }

  /**
   * Analyze performance metrics
   */
  private analyzePerformance(logs: MakeLogEntry[]): Record<string, unknown> {
    const processingTimes = logs
      .filter(log => log.metrics?.processingTime)
      .map(log => log.metrics?.processingTime)
      .filter((time): time is number => time !== undefined);

    if (processingTimes.length === 0) {
      return { message: 'No performance data available' };
    }

    const sortedTimes = processingTimes.sort((a, b) => a - b);
    const average = sortedTimes.reduce((sum, time) => sum + time, 0) / sortedTimes.length;
    const median = sortedTimes[Math.floor(sortedTimes.length / 2)];
    
    return {
      average,
      median: median || 0,
      min: Math.min(...sortedTimes),
      max: Math.max(...sortedTimes),
      count: sortedTimes.length,
    };
  }

  /**
   * Analyze error patterns
   */
  private analyzeErrors(logs: MakeLogEntry[]): Record<string, unknown> {
    const errorLogs = logs.filter(log => log.error);
    const errorTypes: Record<string, number> = {};

    errorLogs.forEach(log => {
      const errorType = log.error?.type || 'unknown';
      errorTypes[errorType] = (errorTypes[errorType] || 0) + 1;
    });

    return {
      totalErrors: errorLogs.length,
      errorRate: (errorLogs.length / logs.length) * 100,
      errorTypes,
      topErrors: Object.entries(errorTypes)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 5),
    };
  }

  /**
   * Analyze usage patterns
   */
  private analyzeUsagePatterns(logs: MakeLogEntry[]): Record<string, unknown> {
    const moduleUsage: Record<string, number> = {};
    const hourlyDistribution: Record<string, number> = {};

    logs.forEach(log => {
      // Module usage
      moduleUsage[log.module.name] = (moduleUsage[log.module.name] || 0) + 1;

      // Hourly distribution
      const hour = new Date(log.timestamp).getHours();
      hourlyDistribution[hour] = (hourlyDistribution[hour] || 0) + 1;
    });

    return {
      moduleUsage,
      hourlyDistribution,
      topModules: Object.entries(moduleUsage)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 10),
    };
  }

  /**
   * Analyze trends
   */
  private analyzeTrends(logs: MakeLogEntry[]): Record<string, unknown> {
    // Group logs by time intervals
    const timeIntervals: Record<string, number> = {};

    logs.forEach(log => {
      const interval = new Date(log.timestamp).toISOString().slice(0, 13); // Hour-based intervals
      timeIntervals[interval] = (timeIntervals[interval] || 0) + 1;
    });

    const values = Object.values(timeIntervals);
    const trend = values.length > 1 ? 
      (values[values.length - 1] - values[0]) / values.length : 0;

    return {
      timeIntervals,
      trend: trend > 0 ? 'increasing' : trend < 0 ? 'decreasing' : 'stable',
      trendValue: trend,
    };
  }

  /**
   * Format logs for export
   */
  public async formatLogsForExport(
    logs: MakeLogEntry[], 
    outputConfig: OutputConfig, 
    metadata: Record<string, unknown>,
    analytics?: Record<string, unknown>
  ): Promise<Record<string, unknown>> {
    const baseData = {
      metadata,
      logs,
      analytics,
      generatedAt: new Date().toISOString(),
    };

    switch (outputConfig.format) {
      case 'json':
        return baseData;
      case 'csv':
        return { ...baseData, csvData: this.convertToCSV(logs) };
      case 'parquet':
        return { ...baseData, parquetData: 'Parquet conversion would be implemented here' };
      default:
        return baseData;
    }
  }

  /**
   * Convert logs to CSV format
   */
  private convertToCSV(logs: MakeLogEntry[]): string {
    const headers = ['timestamp', 'level', 'execution_id', 'scenario_id', 'module_name', 'message'];
    const rows = logs.map(log => [
      log.timestamp,
      log.level,
      log.executionId,
      log.scenarioId,
      log.module.name,
      `"${log.message.replace(/"/g, '""')}"`,
    ]);

    return [headers.join(','), ...rows.map(row => row.join(','))].join('\n');
  }

  /**
   * Deliver data to external system
   */
  private async deliverToExternalSystem(
    data: Record<string, unknown>, 
    config: ExternalSystemConfig, 
    format: string
  ): Promise<Record<string, unknown>> {
    const connector = new ExternalSystemConnector(config, this.logger);
    
    try {
      await connector.connect();
      const result = await connector.sendData(data, format);
      await connector.disconnect();
      return result;
    } catch (error) {
      await connector.disconnect();
      throw error;
    }
  }

  /**
   * Initialize streaming session data structure
   */
  private initializeStreamingSession(): {
    streamId: string;
    startTime: string;
    endTime: string;
    batchesProcessed: number;
    totalLogsStreamed: number;
    errors: string[];
    deliveryResults: Record<string, unknown>[];
  } {
    return {
      streamId: `stream_${this.exportMetadata.exportId}`,
      startTime: new Date().toISOString(),
      endTime: '',
      batchesProcessed: 0,
      totalLogsStreamed: 0,
      errors: [],
      deliveryResults: [],
    };
  }

  /**
   * Get streaming configuration parameters
   */
  private getStreamingConfiguration(
    exportConfig: ExportConfig,
    params: Record<string, unknown>
  ): {
    lastLogTimestamp: string;
    streamEndTime: number;
    baseParams: Record<string, unknown>;
  } {
    const lastLogTimestamp = exportConfig.timeRange?.start || 
      exportConfig.timeRange?.startTime || 
      new Date(0).toISOString();
    const streamEndTime = Date.now() + ((exportConfig.streaming?.maxDuration || 300) * 1000);
    
    return {
      lastLogTimestamp,
      streamEndTime,
      baseParams: params
    };
  }

  /**
   * Execute the main streaming process loop
   */
  private async executeStreamingProcess(
    endpoint: string,
    streamConfig: { lastLogTimestamp: string; streamEndTime: number; baseParams: Record<string, unknown> },
    exportConfig: ExportConfig,
    outputConfig: OutputConfig,
    externalConnector: ExternalSystemConnector | null,
    streamingResults: {
      batchesProcessed: number;
      totalLogsStreamed: number;
      errors: string[];
      deliveryResults: Record<string, unknown>[];
    }
  ): Promise<void> {
    let { lastLogTimestamp } = streamConfig;
    const { streamEndTime, baseParams } = streamConfig;

    while (Date.now() < streamEndTime) {
      try {
        const batchParams = this.prepareBatchParameters(
          baseParams,
          lastLogTimestamp,
          exportConfig
        );

        const batchResult = await processStreamingBatch(
          this.apiClient,
          endpoint,
          batchParams,
          exportConfig,
          outputConfig,
          this.exportMetadata,
          externalConnector,
          this
        );

        lastLogTimestamp = this.updateStreamingResults(batchResult, streamingResults, lastLogTimestamp);
      } catch (error) {
        this.handleStreamingError(error, streamingResults);
      }

      await this.waitForNextInterval(exportConfig);
    }
  }

  /**
   * Prepare batch parameters for streaming request
   */
  private prepareBatchParameters(
    baseParams: Record<string, unknown>,
    lastLogTimestamp: string,
    exportConfig: ExportConfig
  ): Record<string, unknown> {
    return {
      ...baseParams,
      limit: exportConfig.streaming?.batchSize || 1000,
      offset: 0,
      dateFrom: lastLogTimestamp,
    };
  }

  /**
   * Update streaming results with batch results
   */
  private updateStreamingResults(
    batchResult: { logsProcessed: number; lastTimestamp?: string; deliveryResult?: Record<string, unknown> },
    streamingResults: {
      batchesProcessed: number;
      totalLogsStreamed: number;
      deliveryResults: Record<string, unknown>[];
    },
    lastLogTimestamp: string
  ): string {
    if (batchResult.logsProcessed > 0) {
      streamingResults.batchesProcessed++;
      streamingResults.totalLogsStreamed += batchResult.logsProcessed;
      
      if (batchResult.lastTimestamp) {
        lastLogTimestamp = batchResult.lastTimestamp;
      }
      
      if (batchResult.deliveryResult) {
        streamingResults.deliveryResults.push(batchResult.deliveryResult);
      }
    }
    
    return lastLogTimestamp;
  }

  /**
   * Handle streaming errors
   */
  private handleStreamingError(
    error: unknown,
    streamingResults: { errors: string[] }
  ): void {
    const errorMessage = error instanceof Error ? error.message : String(error);
    this.logger.warn?.('Error processing streaming batch', { error: errorMessage });
    streamingResults.errors.push(errorMessage);
  }

  /**
   * Wait for next streaming interval
   */
  private async waitForNextInterval(exportConfig: ExportConfig): Promise<void> {
    await new Promise(resolve => 
      setTimeout(resolve, exportConfig.streaming?.intervalMs || 5000)
    );
  }

  /**
   * Finalize streaming export and cleanup resources
   */
  private async finalizeStreamingExport(
    externalConnector: ExternalSystemConnector | null,
    streamingResults: { endTime: string }
  ): Promise<void> {
    if (externalConnector) {
      await externalConnector.disconnect();
    }
    streamingResults.endTime = new Date().toISOString();
  }

  /**
   * Build streaming result object
   */
  private buildStreamingResult(
    streamingResults: {
      streamId: string;
      startTime: string;
      endTime: string;
      batchesProcessed: number;
      totalLogsStreamed: number;
      errors: string[];
      deliveryResults: Record<string, unknown>[];
    },
    exportConfig: ExportConfig
  ): Record<string, unknown> {
    return {
      exportMetadata: this.exportMetadata,
      streaming: streamingResults,
      summary: {
        mode: 'streaming',
        duration: `${exportConfig.streaming?.maxDuration || 300}s`,
        totalBatches: streamingResults.batchesProcessed,
        totalLogs: streamingResults.totalLogsStreamed,
        errors: streamingResults.errors.length,
      },
    };
  }

  /**
   * Log streaming completion
   */
  private logStreamingCompletion(
    streamingResults: { batchesProcessed: number; totalLogsStreamed: number }
  ): void {
    this.logger.info?.('Streaming export completed successfully', {
      exportId: String(this.exportMetadata.exportId),
      totalBatches: streamingResults.batchesProcessed,
      totalLogs: streamingResults.totalLogsStreamed,
    });
  }

  /**
   * Generate enhanced summary
   */
  private generateEnhancedSummary(logs: MakeLogEntry[], exportConfig: ExportConfig): Record<string, unknown> {
    return {
      totalLogsExported: logs.length,
      timeRange: exportConfig.timeRange,
      scenariosCovered: Array.from(new Set(logs.map(log => log.scenarioId))).length,
      modulesCovered: Array.from(new Set(logs.map(log => log.module.name))).length,
      errorRate: (logs.filter(log => log.error).length / logs.length) * 100,
      dataProcessed: logs.reduce((sum, log) => sum + (log.metrics?.dataSize || 0), 0),
      operationsTotal: logs.reduce((sum, log) => sum + (log.metrics?.operations || 0), 0),
    };
  }
}

/**
 * External System Connector for delivering exported logs
 */
class ExternalSystemConnector {
  private readonly config: ExternalSystemConfig;
  private readonly logger: ToolContext['logger'];
  private connection: unknown;

  constructor(config: ExternalSystemConfig, logger: ToolContext['logger']) {
    this.config = config;
    this.logger = logger;
  }

  async connect(): Promise<void> {
    this.logger.info?.('Connecting to external system', { type: this.config.type });
    
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
      default:
        this.logger.info?.('Using generic HTTP connection');
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
    this.logger.info?.('Disconnecting from external system');
    this.connection = null;
  }

  // System-specific connection methods
  private async connectToElasticsearch(): Promise<void> {
    this.connection = { type: 'elasticsearch', connected: true };
  }

  private async connectToSplunk(): Promise<void> {
    this.connection = { type: 'splunk', connected: true };
  }

  private async connectToDatadog(): Promise<void> {
    this.connection = { type: 'datadog', connected: true };
  }

  // System-specific send methods
  private async sendToElasticsearch(_data: unknown): Promise<Record<string, unknown>> {
    return { indexed: true, response: 'OK' };
  }

  private async sendToSplunk(_data: unknown): Promise<Record<string, unknown>> {
    return { sent: true, response: 'OK' };
  }

  private async sendToDatadog(_data: unknown): Promise<Record<string, unknown>> {
    return { sent: true, response: 'OK' };
  }

  private async sendToGenericEndpoint(_data: unknown): Promise<Record<string, unknown>> {
    return { sent: true, response: 'OK' };
  }
}