/**
 * @fileoverview Get Scenario Run Logs Tool Implementation
 * Stream detailed execution logs with real-time updates, advanced filtering, and multiple output formats
 */

import { UserError } from 'fastmcp';
import { ScenarioRunLogsSchema } from '../schemas/stream-config.js';
import { ToolContext, ToolDefinition } from '../../shared/types/tool-context.js';
import { LogStreamingManager, LogStreamingConfig } from '../utils/stream-processor.js';
import { MakeLogEntry } from '../types/streaming.js';
import { formatSuccessResponse } from '../../../utils/response-formatter.js';

/**
 * Create get scenario run logs tool configuration
 */
export function createGetScenarioRunLogsTool(context: ToolContext): ToolDefinition {
  const { apiClient, logger } = context;
  const streamingManager = new LogStreamingManager(apiClient);
  
  return {
    name: 'get_scenario_run_logs',
    description: 'Stream detailed execution logs for a Make.com scenario with real-time updates, advanced filtering, and multiple output formats',
    parameters: ScenarioRunLogsSchema,
    annotations: {
      title: 'Get Scenario Run Logs',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input: unknown, { log }): Promise<string> => {
      const { scenarioId, executionId, streaming, filtering, output } = input as {
        scenarioId: number;
        executionId?: string;
        streaming: {
          enabled: boolean;
          batchSize: number;
          batchTimeoutMs: number;
          compressionEnabled: boolean;
        };
        filtering: {
          logLevels: string[];
          moduleTypes?: string[];
          moduleIds?: string[];
          startTime?: string;
          endTime?: string;
        };
        output: {
          format: 'json' | 'structured' | 'plain';
          includeMetrics: boolean;
          includeStackTrace: boolean;
          colorCoding: boolean;
        };
      };

      log?.info?.('Starting scenario log streaming', {
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

          const streamId = await streamingManager.startLogStreaming(
            scenarioId,
            executionId || null,
            streamingConfig,
            (newLogs) => {
              logs.push(...newLogs);
              totalLogs += newLogs.length;
              
              // Format and output new logs (used for side effects)
              formatLogs(newLogs, output);
              
              log?.info?.('New logs received', {
                count: newLogs.length,
                totalLogs,
                streamId,
              });
            }
          );

          // Run for a limited time for demo purposes (in production, this would be managed differently)
          await new Promise(resolve => setTimeout(resolve, 30000)); // 30 seconds

          // Stop streaming
          streamingManager.stopLogStreaming(streamId);

          const result = {
            summary: {
              totalLogs,
              streamId,
              scenarioId,
              executionId: executionId || 'live',
              duration: '30 seconds',
              format: output.format,
            },
            metrics: streaming.enabled ? streamingManager.getStreamingMetrics(streamId) : undefined,
            recentLogs: logs.slice(-10), // Show last 10 logs
            status: 'completed',
            message: `Streamed ${totalLogs} logs successfully`,
          };

          return formatSuccessResponse(result).content[0].text;

        } else {
          // Static log retrieval
          const params: Record<string, unknown> = {
            limit: 100,
            offset: 0,
            sortBy: 'timestamp',
            sortOrder: 'desc',
          };

          if (executionId) {
            params.executionId = executionId;
          }

          if (filtering.logLevels?.length > 0) {
            params.level = filtering.logLevels.join(',');
          }

          if (filtering.startTime) {
            params.dateFrom = filtering.startTime;
          }

          if (filtering.endTime) {
            params.dateTo = filtering.endTime;
          }

          const response = await apiClient.get(`/scenarios/${scenarioId}/logs`, { params });

          if (!response.success) {
            throw new UserError(`Failed to retrieve logs: ${response.error || 'Unknown error'}`);
          }

          const logs = response.data as MakeLogEntry[];
          const formattedLogs = formatLogs(logs, output);

          const result = {
            summary: {
              totalLogs: logs.length,
              scenarioId,
              executionId: executionId || 'all',
              format: output.format,
              timeRange: {
                start: filtering.startTime,
                end: filtering.endTime,
              },
            },
            logs: formattedLogs,
            status: 'completed',
            message: `Retrieved ${logs.length} logs successfully`,
          };

          return formatSuccessResponse(result).content[0].text;
        }

      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.error?.('Error retrieving scenario logs', { error: errorMessage, scenarioId, executionId });
        
        if (error instanceof UserError) {
          throw error;
        }
        
        throw new UserError(`Failed to retrieve scenario logs: ${errorMessage}`);
      }
    },
  };
}

/**
 * Format logs according to output configuration
 */
function formatLogs(logs: MakeLogEntry[], output: { 
  format: 'json' | 'structured' | 'plain';
  includeMetrics: boolean;
  includeStackTrace: boolean;
  colorCoding: boolean;
}): unknown[] {
  return logs.map(log => {
    switch (output.format) {
      case 'json':
        return log;
        
      case 'structured':
        return {
          timestamp: log.timestamp,
          level: log.level,
          message: log.message,
          module: log.module.name,
          execution: {
            id: log.executionId,
            scenario: log.execution.scenarioName,
          },
          ...(output.includeMetrics && { performance: log.performance }),
          ...(output.includeStackTrace && log.error && { error: log.error }),
        };
        
      case 'plain': {
        const timestamp = new Date(log.timestamp).toISOString();
        const level = log.level.toUpperCase().padEnd(5);
        const module = log.module.name.padEnd(15);
        return `${timestamp} [${level}] ${module} ${log.message}`;
      }
        
      default:
        return log;
    }
  });
}