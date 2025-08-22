/**
 * @fileoverview Query Logs by Time Range Tool Implementation
 * Advanced historical log search and analysis with comprehensive filtering, aggregation, trend analysis
 */

import { UserError } from 'fastmcp';
import { QueryLogsByTimeRangeSchema } from '../schemas/stream-config.js';
import { ToolContext, ToolDefinition } from '../../shared/types/tool-context.js';
import { MakeLogEntry } from '../types/streaming.js';
import { formatSuccessResponse } from '../../../utils/response-formatter.js';

// Types for better organization
interface QueryParams {
  scenarioId?: number;
  organizationId?: number;
  teamId?: number;
  executionId?: string;
  timeRange: {
    startTime: string;
    endTime: string;
    timezone: string;
  };
  filtering: {
    logLevels: string[];
    executionStatus?: string;
    moduleTypes?: string[];
    moduleNames?: string[];
    searchText?: string;
    errorCodesOnly: boolean;
    performanceThreshold?: number;
    dataSizeThreshold?: number;
    operationsThreshold?: number;
    excludeSuccess: boolean;
    includeMetrics: boolean;
    correlationIds?: string[];
  };
  pagination: {
    limit: number;
    offset: number;
    sortBy: string;
    sortOrder: string;
    cursor?: string;
  };
  aggregation: {
    enabled: boolean;
    groupBy?: string;
    includeStats: boolean;
    includeTimeDistribution: boolean;
    includePerformanceAnalysis: boolean;
    includeErrorAnalysis: boolean;
  };
  analysis: {
    performanceTrends: boolean;
    errorPatterns: boolean;
    usageMetrics: boolean;
    executionFlow: boolean;
    anomalyDetection: boolean;
  };
  export?: {
    format: string;
    includeCharts: boolean;
    compression: boolean;
  };
}

/**
 * Build query parameters for the API request
 */
function buildQueryParameters(params: QueryParams): Record<string, unknown> {
  const { scenarioId, organizationId, teamId, executionId, timeRange, filtering, pagination } = params;
  
  const queryParams: Record<string, unknown> = {
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
    queryParams.cursor = pagination.cursor;
  }

  // Apply filtering parameters
  if (scenarioId) {queryParams.scenarioId = scenarioId;}
  if (organizationId) {queryParams.organizationId = organizationId;}
  if (teamId) {queryParams.teamId = teamId;}
  if (executionId) {queryParams.executionId = executionId;}
  if (filtering.logLevels.length > 0) {queryParams.level = filtering.logLevels.join(',');}
  if (filtering.executionStatus) {queryParams.status = filtering.executionStatus;}
  if (filtering.moduleTypes?.length) {queryParams.moduleTypes = filtering.moduleTypes.join(',');}
  if (filtering.moduleNames?.length) {queryParams.moduleNames = filtering.moduleNames.join(',');}
  if (filtering.searchText) {
    queryParams.search = filtering.searchText;
    queryParams.searchType = 'regex'; // Enable regex search
  }
  if (filtering.errorCodesOnly) {queryParams.errorsOnly = true;}
  if (filtering.performanceThreshold) {queryParams.minProcessingTime = filtering.performanceThreshold;}
  if (filtering.dataSizeThreshold) {queryParams.minDataSize = filtering.dataSizeThreshold;}
  if (filtering.operationsThreshold) {queryParams.minOperations = filtering.operationsThreshold;}
  if (filtering.excludeSuccess) {queryParams.excludeSuccess = true;}
  if (!filtering.includeMetrics) {queryParams.excludeMetrics = true;}
  if (filtering.correlationIds?.length) {queryParams.correlationIds = filtering.correlationIds.join(',');}

  return queryParams;
}

/**
 * Determine the optimal API endpoint based on scope
 */
function determineEndpoint(params: QueryParams): string {
  const { executionId, scenarioId, organizationId, teamId } = params;
  
  if (executionId) {
    return `/executions/${executionId}/logs`;
  } else if (scenarioId) {
    return `/scenarios/${scenarioId}/logs`;
  } else if (organizationId) {
    return `/organizations/${organizationId}/logs`;
  } else if (teamId) {
    return `/teams/${teamId}/logs`;
  }
  
  return '/logs';
}

/**
 * Build comprehensive result object with query info
 */
function buildQueryResult(logs: MakeLogEntry[], metadata: unknown, queryDuration: number, params: QueryParams): Record<string, unknown> {
  const { timeRange, filtering, pagination } = params;
  
  return {
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
        total: (metadata as Record<string, unknown>)?.total || logs.length,
        hasMore: ((metadata as Record<string, unknown>)?.total || 0) > (pagination.offset + logs.length),
        nextCursor: (metadata as Record<string, unknown>)?.nextCursor as string,
      },
      endpoint: determineEndpoint(params),
      performance: {
        queryTime: queryDuration,
        averageProcessingTime: queryDuration / Math.max(logs.length, 1),
        dataRetrievalRate: `${logs.length}/${queryDuration}ms`,
      },
    },
    logs: logs,
    summary: generateLogSummary(logs),
  };
}

/**
 * Add aggregation analysis to the result
 */
async function addAggregationAnalysis(
  result: Record<string, unknown>, 
  logs: MakeLogEntry[], 
  aggregation: QueryParams['aggregation'],
  log?: unknown
): Promise<void> {
  if (aggregation.enabled && aggregation.groupBy) {
    (log as { info?: (msg: string) => void })?.info?.('Generating advanced aggregation analysis');
    result.aggregation = generateLogAggregation(
      logs,
      aggregation.groupBy as 'level' | 'module' | 'hour',
      aggregation.includeStats
    );
  }
}

/**
 * Add advanced analysis features to the result
 */
async function addAdvancedAnalysis(
  result: Record<string, unknown>,
  logs: MakeLogEntry[],
  analysis: QueryParams['analysis'],
  timeRange: QueryParams['timeRange'],
  log?: unknown
): Promise<void> {
  if (analysis.performanceTrends || analysis.errorPatterns || 
      analysis.usageMetrics || analysis.executionFlow || analysis.anomalyDetection) {
    
    (log as { info?: (msg: string, data?: unknown) => void })?.info?.('Performing advanced log analysis', {
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
}

/**
 * Add export capabilities to the result
 */
async function addExportCapabilities(
  result: Record<string, unknown>,
  logs: MakeLogEntry[],
  exportConfig: QueryParams['export'],
  log?: unknown
): Promise<void> {
  if (exportConfig?.format) {
    (log as { info?: (msg: string, data?: unknown) => void })?.info?.('Preparing export data', { format: exportConfig.format });
    result.export = await prepareLogExport(logs, {
      format: exportConfig.format,
      includeCharts: exportConfig.includeCharts,
      compression: exportConfig.compression,
    });
  }
}

/**
 * Create query logs by time range tool configuration
 */
export function createQueryLogsByTimeRangeTool(context: ToolContext): ToolDefinition {
  const { apiClient, logger } = context;
  
  return {
    name: 'query_logs_by_timerange',
    description: 'Advanced historical log search and analysis with comprehensive filtering, aggregation, trend analysis, and export capabilities',
    parameters: QueryLogsByTimeRangeSchema,
    annotations: {
      title: 'Query Logs by Time Range',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input: unknown, { log }): Promise<string> => {
      const params = input as QueryParams;

      log?.info?.('Starting advanced historical log query', {
        scenarioId: params.scenarioId,
        organizationId: params.organizationId,
        teamId: params.teamId,
        executionId: params.executionId,
        timeRange: params.timeRange,
        filtering: params.filtering,
        pagination: params.pagination,
        aggregation: params.aggregation,
        analysis: params.analysis,
      });

      try {
        const queryStartTime = Date.now();
        
        // Build query parameters and determine endpoint
        const queryParams = buildQueryParameters(params);
        const endpoint = determineEndpoint(params);

        log?.info?.('Executing historical log query', {
          endpoint,
          paramsCount: Object.keys(queryParams).length,
          queryStrategy: 'time-range-optimized',
        });

        // Execute the primary log query
        const response = await apiClient.get(endpoint, { params: queryParams });

        if (!response.success) {
          throw new UserError(`Failed to query historical logs: ${response.error?.message || 'Unknown error'}`);
        }

        const logs = (response.data as MakeLogEntry[]) || [];
        const metadata = response.metadata;
        const queryDuration = Date.now() - queryStartTime;

        // Build comprehensive result object
        const result = buildQueryResult(logs, metadata, queryDuration, params);

        // Add optional features
        await addAggregationAnalysis(result, logs, params.aggregation, log);
        await addAdvancedAnalysis(result, logs, params.analysis, params.timeRange, log);
        await addExportCapabilities(result, logs, params.export, log);

        log?.info?.('Historical log query completed successfully', {
          logsReturned: logs.length,
          queryDuration: `${queryDuration}ms`,
          aggregationEnabled: params.aggregation.enabled,
          analysisEnabled: Object.values(params.analysis).some(Boolean),
          exportEnabled: !!params.export?.format,
        });

        return formatSuccessResponse(result).content[0].text;

      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.error?.('Error querying historical logs', {
          error: errorMessage,
          scenarioId: params.scenarioId,
          organizationId: params.organizationId,
          teamId: params.teamId,
          executionId: params.executionId,
          timeRange: params.timeRange,
        });
        
        if (error instanceof UserError) {
          throw error;
        }
        
        throw new UserError(`Failed to query historical logs: ${errorMessage}`);
      }
    },
  };
}

/**
 * Generate log summary statistics
 */
function generateLogSummary(logs: MakeLogEntry[]): Record<string, unknown> {
  const summary = {
    totalLogs: logs.length,
    logLevels: {} as Record<string, number>,
    modules: {} as Record<string, number>,
    executionStates: {} as Record<string, number>,
    timeRange: {
      earliest: logs[0]?.timestamp,
      latest: logs[logs.length - 1]?.timestamp,
    },
    performance: {
      averageProcessingTime: 0,
      totalProcessingTime: 0,
      minProcessingTime: Number.MAX_VALUE,
      maxProcessingTime: 0,
    },
  };

  let totalProcessingTime = 0;
  let processedLogs = 0;

  logs.forEach(log => {
    // Count log levels
    summary.logLevels[log.level] = (summary.logLevels[log.level] || 0) + 1;
    
    // Count modules
    summary.modules[log.module.name] = (summary.modules[log.module.name] || 0) + 1;
    
    // Count execution states
    const state = log.execution?.scenarioName || 'unknown';
    summary.executionStates[state] = (summary.executionStates[state] || 0) + 1;
    
    // Performance metrics
    if (log.performance?.processingTime) {
      const processingTime = log.performance.processingTime;
      totalProcessingTime += processingTime;
      processedLogs++;
      summary.performance.minProcessingTime = Math.min(summary.performance.minProcessingTime, processingTime);
      summary.performance.maxProcessingTime = Math.max(summary.performance.maxProcessingTime, processingTime);
    }
  });

  if (processedLogs > 0) {
    summary.performance.averageProcessingTime = totalProcessingTime / processedLogs;
    summary.performance.totalProcessingTime = totalProcessingTime;
  }

  if (summary.performance.minProcessingTime === Number.MAX_VALUE) {
    summary.performance.minProcessingTime = 0;
  }

  return summary;
}

/**
 * Generate log aggregation based on grouping criteria
 */
function generateLogAggregation(
  logs: MakeLogEntry[], 
  groupBy: 'level' | 'module' | 'hour', 
  includeStats: boolean
): Record<string, unknown> {
  const groups: Record<string, MakeLogEntry[]> = {};

  logs.forEach(log => {
    let key: string;
    switch (groupBy) {
      case 'level':
        key = log.level;
        break;
      case 'module':
        key = log.module.name;
        break;
      case 'hour':
        key = new Date(log.timestamp).toISOString().substring(0, 13); // YYYY-MM-DDTHH
        break;
      default:
        key = 'unknown';
    }

    if (!groups[key]) {
      groups[key] = [];
    }
    groups[key].push(log);
  });

  const aggregation: Record<string, unknown> = {
    groupBy,
    groups: {},
    summary: {
      totalGroups: Object.keys(groups).length,
      totalLogs: logs.length,
    },
  };

  Object.entries(groups).forEach(([key, groupLogs]) => {
    const groupData: Record<string, unknown> = {
      count: groupLogs.length,
      percentage: (groupLogs.length / logs.length) * 100,
    };

    if (includeStats) {
      groupData.stats = generateLogSummary(groupLogs);
    }

    (aggregation.groups as Record<string, unknown>)[key] = groupData;
  });

  return aggregation;
}

/**
 * Perform advanced log analysis
 */
async function performAdvancedLogAnalysis(
  logs: MakeLogEntry[], 
  analysis: {
    performanceTrends: boolean;
    errorPatterns: boolean;
    usageMetrics: boolean;
    executionFlow: boolean;
    anomalyDetection: boolean;
  },
  timeRange: { startTime: string; endTime: string }
): Promise<Record<string, unknown>> {
  const result: Record<string, unknown> = {};

  if (analysis.performanceTrends) {
    result.performanceTrends = analyzePerformanceTrends(logs);
  }

  if (analysis.errorPatterns) {
    result.errorPatterns = analyzeErrorPatterns(logs);
  }

  if (analysis.usageMetrics) {
    result.usageMetrics = analyzeUsageMetrics(logs, timeRange);
  }

  if (analysis.executionFlow) {
    result.executionFlow = analyzeExecutionFlow(logs);
  }

  if (analysis.anomalyDetection) {
    result.anomalyDetection = detectAnomalies(logs);
  }

  return result;
}

/**
 * Analyze performance trends in logs
 */
function analyzePerformanceTrends(logs: MakeLogEntry[]): Record<string, unknown> {
  const trends = logs
    .filter(log => log.performance?.processingTime)
    .map(log => ({
      timestamp: log.timestamp,
      processingTime: log.performance.processingTime,
      module: log.module.name,
    }));

  return {
    totalSamples: trends.length,
    averageProcessingTime: trends.reduce((sum, t) => sum + t.processingTime, 0) / trends.length || 0,
    trends: trends.slice(-20), // Last 20 samples
  };
}

/**
 * Analyze error patterns in logs
 */
function analyzeErrorPatterns(logs: MakeLogEntry[]): Record<string, unknown> {
  const errorLogs = logs.filter(log => log.level === 'error' && log.error);
  const patterns: Record<string, number> = {};

  errorLogs.forEach(log => {
    if (log.error?.type) {
      patterns[log.error.type] = (patterns[log.error.type] || 0) + 1;
    }
  });

  return {
    totalErrors: errorLogs.length,
    errorTypes: patterns,
    topErrors: Object.entries(patterns)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 5),
  };
}

/**
 * Analyze usage metrics
 */
function analyzeUsageMetrics(logs: MakeLogEntry[], timeRange: { startTime: string; endTime: string }): Record<string, unknown> {
  const duration = new Date(timeRange.endTime).getTime() - new Date(timeRange.startTime).getTime();
  const hours = duration / (1000 * 60 * 60);

  return {
    logsPerHour: logs.length / hours,
    totalLogs: logs.length,
    timeRange: {
      duration: `${hours.toFixed(1)} hours`,
      start: timeRange.startTime,
      end: timeRange.endTime,
    },
  };
}

/**
 * Analyze execution flow
 */
function analyzeExecutionFlow(logs: MakeLogEntry[]): Record<string, unknown> {
  const executions: Record<string, MakeLogEntry[]> = {};

  logs.forEach(log => {
    if (!executions[log.executionId]) {
      executions[log.executionId] = [];
    }
    executions[log.executionId].push(log);
  });

  return {
    totalExecutions: Object.keys(executions).length,
    averageLogsPerExecution: logs.length / Object.keys(executions).length || 0,
    executionSample: Object.entries(executions).slice(0, 3).map(([id, execLogs]) => ({
      executionId: id,
      logCount: execLogs.length,
      modules: [...new Set(execLogs.map(log => log.module.name))],
    })),
  };
}

/**
 * Detect anomalies in logs
 */
function detectAnomalies(logs: MakeLogEntry[]): Record<string, unknown> {
  const processingTimes = logs
    .filter(log => log.performance?.processingTime)
    .map(log => log.performance.processingTime);

  if (processingTimes.length === 0) {
    return { anomalies: [], message: 'No performance data available for anomaly detection' };
  }

  const mean = processingTimes.reduce((sum, time) => sum + time, 0) / processingTimes.length;
  const variance = processingTimes.reduce((sum, time) => sum + Math.pow(time - mean, 2), 0) / processingTimes.length;
  const stdDev = Math.sqrt(variance);
  const threshold = mean + (2 * stdDev); // 2 standard deviations

  const anomalies = logs.filter(log => 
    log.performance?.processingTime && log.performance.processingTime > threshold
  );

  return {
    threshold: `${threshold.toFixed(2)}ms`,
    anomalies: anomalies.length,
    samples: anomalies.slice(0, 5).map(log => ({
      timestamp: log.timestamp,
      executionId: log.executionId,
      module: log.module.name,
      processingTime: log.performance?.processingTime,
      deviation: log.performance?.processingTime ? (log.performance.processingTime - mean).toFixed(2) : 0,
    })),
  };
}

/**
 * Prepare log export data
 */
async function prepareLogExport(
  logs: MakeLogEntry[], 
  config: { format: string; includeCharts: boolean; compression: boolean }
): Promise<Record<string, unknown>> {
  return {
    format: config.format,
    totalRecords: logs.length,
    exportSize: `${JSON.stringify(logs).length} bytes`,
    compression: config.compression ? 'enabled' : 'disabled',
    charts: config.includeCharts ? 'included' : 'not included',
    status: 'prepared',
    message: `Export prepared with ${logs.length} log records in ${config.format} format`,
  };
}