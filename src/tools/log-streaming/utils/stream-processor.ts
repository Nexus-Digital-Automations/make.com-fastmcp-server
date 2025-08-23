/**
 * @fileoverview Stream processing logic for log streaming tools
 * Real-time log streaming manager and utilities
 */

import { EventEmitter } from 'events';
import MakeApiClient from '../../../lib/make-api-client.js';
import logger from '../../../lib/logger.js';
import { MakeLogEntry } from '../types/streaming.js';

export interface LogStreamingConfig {
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

export interface StreamingMetrics {
  totalLogsStreamed: number;
  averageLatency: number;
  activeConnections: number;
  droppedLogs: number;
  bufferUtilization: number;
  throughput: number;
}

/**
 * Real-time log streaming manager
 */
export class LogStreamingManager extends EventEmitter {
  private readonly activeStreams = new Map<string, NodeJS.Timeout>();
  private readonly streamMetrics = new Map<string, StreamingMetrics>();
  private readonly logBuffer = new Map<string, MakeLogEntry[]>();

  constructor(private readonly apiClient: MakeApiClient) {
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
              this.handleLogBuffering(streamId, filteredLogs, config.bufferingStrategy.maxBufferSize);
            }

            // Update metrics
            const metrics = this.streamMetrics.get(streamId);
            if (metrics) {
              metrics.totalLogsStreamed += filteredLogs.length;
              this.streamMetrics.set(streamId, metrics);
            }

            // Call callback with filtered logs
            if (filteredLogs.length > 0) {
              callback(filteredLogs);
            }
          }
        }

        // Schedule next streaming iteration
        if (this.activeStreams.has(streamId)) {
          const timeout = setTimeout(streamLogs, config.aggregationStrategy.batchTimeoutMs);
          this.activeStreams.set(streamId, timeout);
        }

      } catch (error) {
        componentLogger.error('Error in log streaming', { error: error instanceof Error ? error.message : String(error) });
        this.emit('error', error, streamId);
      }
    };

    // Start streaming
    const timeout = setTimeout(streamLogs, 0);
    this.activeStreams.set(streamId, timeout);

    return streamId;
  }

  /**
   * Stop streaming logs
   */
  stopLogStreaming(streamId: string): void {
    const timeout = this.activeStreams.get(streamId);
    if (timeout) {
      clearTimeout(timeout);
      this.activeStreams.delete(streamId);
    }

    // Clean up metrics and buffer
    this.streamMetrics.delete(streamId);
    this.logBuffer.delete(streamId);

    logger.info('Log streaming stopped', { streamId });
  }

  /**
   * Get streaming metrics
   */
  getStreamingMetrics(streamId: string): StreamingMetrics | undefined {
    return this.streamMetrics.get(streamId);
  }

  /**
   * Get buffered logs
   */
  getBufferedLogs(streamId: string): MakeLogEntry[] | undefined {
    return this.logBuffer.get(streamId);
  }

  /**
   * Handle log buffering with trimming if necessary
   */
  private handleLogBuffering(streamId: string, filteredLogs: MakeLogEntry[], maxBufferSize: number): void {
    const buffer = this.logBuffer.get(streamId) || [];
    buffer.push(...filteredLogs);

    // Trim buffer if too large
    if (buffer.length > maxBufferSize) {
      const droppedCount = buffer.length - maxBufferSize;
      buffer.splice(0, droppedCount);
      const metrics = this.streamMetrics.get(streamId);
      if (metrics) {
        metrics.droppedLogs += droppedCount;
        this.streamMetrics.set(streamId, metrics);
      }
    }

    this.logBuffer.set(streamId, buffer);
  }

  /**
   * Clean up all streams
   */
  cleanup(): void {
    const streamIds = Array.from(this.activeStreams.keys());
    for (const streamId of streamIds) {
      this.stopLogStreaming(streamId);
    }
    logger.info('Log streaming manager cleaned up');
  }
}