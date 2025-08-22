/**
 * @fileoverview Stream Live Execution Tool Implementation
 * Real-time scenario execution monitoring with progress tracking, performance metrics, and alerts
 */

import { UserError } from 'fastmcp';
import { StreamLiveExecutionSchema } from '../schemas/stream-config.js';
import { ToolContext, ToolDefinition } from '../../shared/types/tool-context.js';
import { MakeLogEntry } from '../types/streaming.js';
import { formatSuccessResponse } from '../../../utils/response-formatter.js';
import MakeApiClient from '../../../lib/make-api-client.js';
import logger from '../../../lib/logger.js';

// Type definitions
interface LogInterface {
  info: (message: string, meta?: unknown) => void;
  error: (message: string, meta?: unknown) => void;
  warn: (message: string, meta?: unknown) => void;
  debug: (message: string, meta?: unknown) => void;
}

interface MonitoringConfig {
  polling: {
    enabled: boolean;
    interval: number;
    maxDuration: number;
    enableRealtime: boolean;
  };
  alertThresholds: {
    duration: number;
    errorCount: number;
    performanceThreshold: number;
  };
  includeMetrics: boolean;
  includeProgress: boolean;
}

interface AlertConfig {
  enabled: boolean;
  conditions: Array<{
    type: string;
    threshold: unknown;
    action: string;
  }>;
  notifications: {
    email: boolean;
    webhook: boolean;
    inApp: boolean;
  };
}

/**
 * Resolve execution ID for monitoring
 */
async function resolveExecutionId(
  scenarioId: number,
  executionId: string | undefined,
  apiClient: MakeApiClient
): Promise<string> {
  let targetExecutionId: string | null = executionId || null;
  
  if (!targetExecutionId) {
    const executionResponse = await apiClient.get(`/scenarios/${scenarioId}/executions`, {
      params: { limit: 1, sortBy: 'startTime', sortOrder: 'desc' }
    });
    
    if (executionResponse.success && executionResponse.data && (executionResponse.data as unknown[]).length > 0) {
      const executions = executionResponse.data as Array<{ id: string; status: string }>;
      const latestExecution = executions[0];
      
      if (latestExecution.status === 'running' || latestExecution.status === 'pending') {
        targetExecutionId = latestExecution.id;
      }
    }
  }

  if (!targetExecutionId) {
    throw new UserError('No active execution found to monitor. Please provide an execution ID or start a scenario execution.');
  }

  return targetExecutionId;
}

/**
 * Initialize execution data structure
 */
function initializeExecutionData(
  targetExecutionId: string,
  scenarioId: number
): Record<string, unknown> {
  return {
    executionId: targetExecutionId,
    scenarioId,
    startTime: new Date().toISOString(),
    status: 'monitoring',
    progress: 0,
    logs: [] as MakeLogEntry[],
    alerts: [] as Array<{ type: string; severity: string; message: string; timestamp: string }>,
    performance: {
      totalProcessingTime: 0,
      operationsCompleted: 0,
      dataProcessed: 0,
      modulePerformance: {} as Record<string, { avgTime: number; count: number; errors: number }>,
    },
    modules: [] as Array<{ id: string; name: string; status: string; processingTime?: number }>,
  };
}

/**
 * Execute monitoring loop
 */
async function executeMonitoringLoop(
  targetExecutionId: string,
  executionData: Record<string, unknown>,
  monitoring: MonitoringConfig,
  alerts: AlertConfig,
  apiClient: MakeApiClient,
  streamLogger: typeof logger,
  log: LogInterface,
  startTime: number,
  endTime: number
): Promise<void> {
  while (Date.now() < endTime) {
    try {
      // Get execution status
      const statusResponse = await apiClient.get(`/executions/${targetExecutionId}`);
      
      if (statusResponse.success && statusResponse.data) {
        const execution = statusResponse.data as Record<string, unknown>;
        executionData.status = execution.status;
        executionData.progress = execution.progress || 0;
      }

      // Get latest logs
      const logsResponse = await apiClient.get(`/executions/${targetExecutionId}/logs`, {
        params: {
          limit: 20,
          sortBy: 'timestamp',
          sortOrder: 'desc',
          dateFrom: new Date(Date.now() - monitoring.updateIntervalMs * 2).toISOString(),
        }
      });

      if (logsResponse.success && logsResponse.data) {
        const newLogs = logsResponse.data as MakeLogEntry[];
        processNewLogs(newLogs, executionData, monitoring, alerts);
      }

      // Update module status if enabled
      if (monitoring.includeModuleDetails) {
        const modulesResponse = await apiClient.get(`/executions/${targetExecutionId}/modules`);
        if (modulesResponse.success && modulesResponse.data) {
          executionData.modules = modulesResponse.data;
        }
      }

      // Check if execution is complete
      if (executionData.status === 'completed' || executionData.status === 'failed') {
        log?.info?.('Execution completed, ending monitoring', {
          status: executionData.status,
          duration: Date.now() - startTime,
        });
        break;
      }

    } catch (monitoringError) {
      const errorMessage = monitoringError instanceof Error ? monitoringError.message : String(monitoringError);
      logger.warn?.('Error during monitoring iteration', { error: errorMessage });
      
      if (alerts.enabled) {
        const alertList = executionData.alerts as Array<Record<string, unknown>>;
        alertList.push({
          type: 'monitoring_error',
          severity: 'medium',
          message: `Monitoring error: ${errorMessage}`,
          timestamp: new Date().toISOString(),
        });
      }
    }

    // Wait for next update
    await new Promise(resolve => setTimeout(resolve, monitoring.updateIntervalMs));
  }
}

/**
 * Process new logs and update metrics
 */
function processNewLogs(
  newLogs: MakeLogEntry[],
  executionData: Record<string, unknown>,
  monitoring: any,
  alerts: any
): void {
  for (const logEntry of newLogs) {
    const existingLogs = executionData.logs as MakeLogEntry[];
    if (!existingLogs.find(existing => existing.id === logEntry.id)) {
      existingLogs.push(logEntry);

      // Update performance metrics
      if (monitoring.includePerformanceMetrics && logEntry.metrics) {
        updatePerformanceMetrics(executionData, logEntry);
      }

      // Generate alerts
      if (alerts.enabled) {
        generateAlerts(executionData, logEntry, alerts, existingLogs);
      }
    }
  }
}

/**
 * Update performance metrics from log entry
 */
function updatePerformanceMetrics(
  executionData: Record<string, unknown>,
  logEntry: MakeLogEntry
): void {
  const performance = executionData.performance as Record<string, unknown>;
  performance.totalProcessingTime = (performance.totalProcessingTime as number) + (logEntry.metrics!.processingTime || 0);
  performance.operationsCompleted = (performance.operationsCompleted as number) + (logEntry.metrics!.operations || 0);
  performance.dataProcessed = (performance.dataProcessed as number) + (logEntry.metrics!.dataSize || 0);

  // Module-specific performance
  const modulePerf = performance.modulePerformance as Record<string, Record<string, number>>;
  const moduleName = logEntry.module.name;
  if (!modulePerf[moduleName]) {
    modulePerf[moduleName] = { avgTime: 0, count: 0, errors: 0 };
  }
  
  const module = modulePerf[moduleName];
  module.count++;
  module.avgTime = ((module.avgTime * (module.count - 1)) + (logEntry.metrics!.processingTime || 0)) / module.count;
  if (logEntry.error) {
    module.errors++;
  }
}

/**
 * Generate alerts based on log entry
 */
function generateAlerts(
  executionData: Record<string, unknown>,
  logEntry: MakeLogEntry,
  alerts: any,
  existingLogs: MakeLogEntry[]
): void {
  const alertList = executionData.alerts as Array<Record<string, unknown>>;
  
  // Error threshold alert
  if (logEntry.error && alerts.errorThreshold > 0) {
    const errorCount = existingLogs.filter(log => log.error).length;
    if (errorCount >= alerts.errorThreshold) {
      alertList.push({
        type: 'error',
        severity: 'high',
        message: `Error threshold exceeded: ${errorCount} errors detected`,
        timestamp: new Date().toISOString(),
      });
    }
  }

  // Performance threshold alert
  if (alerts.performanceThreshold > 0 && logEntry.metrics?.processingTime && 
      logEntry.metrics.processingTime > alerts.performanceThreshold) {
    alertList.push({
      type: 'performance',
      severity: 'medium',
      message: `Performance threshold exceeded: ${logEntry.metrics.processingTime}ms > ${alerts.performanceThreshold}ms`,
      timestamp: new Date().toISOString(),
    });
  }

  // Module failure alert
  if (alerts.moduleFailureAlert && logEntry.error) {
    alertList.push({
      type: 'module_failure',
      severity: 'high',
      message: `Module ${logEntry.module.name} failed: ${logEntry.error.message}`,
      timestamp: new Date().toISOString(),
    });
  }
}

/**
 * Generate final monitoring result
 */
function generateMonitoringResult(
  executionData: Record<string, unknown>,
  streamId: string,
  startTime: number,
  output: any
): Record<string, unknown> {
  let visualization: string | undefined;
  if (output.includeVisualization) {
    visualization = generateExecutionVisualization(executionData.logs as MakeLogEntry[]);
  }

  return {
    execution: executionData,
    monitoring: {
      streamId,
      duration: Date.now() - startTime,
      logsCollected: (executionData.logs as MakeLogEntry[]).length,
      alertsGenerated: (executionData.alerts as Array<unknown>).length,
    },
    visualization: visualization || undefined,
    summary: generateExecutionSummary(executionData),
  };
}

/**
 * Create stream live execution tool configuration
 */
export function createStreamLiveExecutionTool(context: ToolContext): ToolDefinition {
  const { apiClient, logger } = context;
  
  return {
    name: 'stream_live_execution',
    description: 'Monitor a Make.com scenario execution in real-time with progress tracking, performance metrics, and alerts',
    parameters: StreamLiveExecutionSchema,
    annotations: {
      title: 'Stream Live Execution',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input: unknown, { log }): Promise<string> => {
      const { scenarioId, executionId, monitoring, alerts, output } = input as {
        scenarioId: number;
        executionId?: string;
        monitoring: {
          updateIntervalMs: number;
          maxDuration: number;
          includePerformanceMetrics: boolean;
          includeModuleDetails: boolean;
          trackProgress: boolean;
        };
        alerts: {
          enabled: boolean;
          errorThreshold: number;
          performanceThreshold: number;
          moduleFailureAlert: boolean;
          executionTimeAlert: boolean;
          customThresholds?: Record<string, number>;
        };
        output: {
          format: 'json' | 'structured' | 'streaming';
          includeVisualization: boolean;
          realTimeUpdate: boolean;
        };
      };

      log?.info?.('Starting live execution monitoring', {
        scenarioId,
        executionId,
        monitoring,
        alerts,
      });

      try {
        // Resolve execution ID for monitoring
        const targetExecutionId = await resolveExecutionId(scenarioId, executionId, apiClient);

        // Initialize monitoring
        const streamId = `stream_${scenarioId}_${targetExecutionId}_${Date.now()}`;
        const startTime = Date.now();
        const endTime = startTime + (monitoring.maxDuration * 1000);

        // Initialize execution data
        const executionData = initializeExecutionData(targetExecutionId, scenarioId);

        log?.info?.('Monitoring execution', {
          executionId: targetExecutionId,
          streamId,
          maxDuration: monitoring.maxDuration,
          updateInterval: monitoring.updateIntervalMs,
        });

        // Execute monitoring loop
        await executeMonitoringLoop(
          targetExecutionId,
          executionData,
          monitoring,
          alerts,
          apiClient,
          logger,
          log,
          startTime,
          endTime
        );

        // Generate final result
        const result = generateMonitoringResult(executionData, streamId, startTime, output);

        log?.info?.('Live execution monitoring completed', {
          scenarioId,
          executionId: targetExecutionId,
          logsCollected: (executionData.logs as MakeLogEntry[]).length,
          alerts: (executionData.alerts as Array<unknown>).length,
        });

        return formatSuccessResponse(result).content[0].text;

      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.error?.('Error in live execution monitoring', { scenarioId, executionId, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to stream live execution: ${errorMessage}`);
      }
    },
  };
}

/**
 * Generate execution flow visualization
 */
function generateExecutionVisualization(logs: MakeLogEntry[]): string {
  const modules = new Map<string, { count: number; errors: number; duration: number }>();
  
  logs.forEach(log => {
    const moduleName = log.module.name;
    if (!modules.has(moduleName)) {
      modules.set(moduleName, { count: 0, errors: 0, duration: 0 });
    }
    
    const module = modules.get(moduleName);
    if (module) {
      module.count++;
      if (log.error) { module.errors++; }
      if (log.metrics?.processingTime) { module.duration += log.metrics.processingTime; }
    }
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

/**
 * Generate execution summary
 */
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
      modules: Array.from(new Set((executionData.logs as MakeLogEntry[]).map(log => log.module.name))).length,
    },
  };
}