/**
 * @fileoverview Real-Time Execution Monitoring System for Make.com FastMCP Server
 * 
 * Provides comprehensive real-time monitoring capabilities including:
 * - Live execution tracking with module-level progress
 * - Real-time performance metrics and alerts
 * - Data flow visualization between modules
 * - Predictive performance analysis
 * - SSE-based real-time streaming
 * - Advanced alerting with correlation analysis
 * 
 * @version 2.0.0
 * @author Make.com FastMCP Server
 * @see {@link https://docs.make.com/api} Make.com API Documentation
 */

import { FastMCP, UserError } from 'fastmcp';
import { z } from 'zod';
import { EventEmitter } from 'events';
import MakeApiClient from '../lib/make-api-client.js';
import logger from '../lib/logger.js';
import { SSETransportEnhancer } from '../lib/sse-transport-enhancer.js';
import PerformanceMonitor from '../lib/performance-monitor.js';
import { formatSuccessResponse, ToolResponse } from '../utils/response-formatter.js';

// Core interfaces for real-time monitoring
interface ExecutionState {
  executionId: string;
  scenarioId: number;
  status: 'initializing' | 'running' | 'completed' | 'failed' | 'paused' | 'cancelled';
  startTime: string;
  endTime?: string;
  duration?: number;
  progress: {
    totalModules: number;
    completedModules: number;
    currentModule: ModuleProgress | null;
    estimatedCompletion: Date | null;
    completionPercentage: number;
  };
  performance: RealTimePerformanceMetrics;
  alerts: RealTimeAlert[];
  dataFlow: DataFlowState[];
  metadata: {
    organizationId: number;
    teamId: number;
    userId?: number;
    scenarioName: string;
    blueprintId?: string;
    triggerType: 'manual' | 'scheduled' | 'webhook';
  };
}

interface ModuleProgress {
  moduleId: string;
  moduleName: string;
  moduleType: string;
  position: { x: number; y: number };
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
  startTime?: string;
  endTime?: string;
  duration?: number;
  inputBundles: number;
  outputBundles: number;
  operations: number;
  dataSize: number;
  error?: {
    code: string;
    message: string;
    type: string;
    retryable: boolean;
  };
}

interface RealTimePerformanceMetrics {
  totalDuration: number;
  averageModuleDuration: number;
  totalDataProcessed: number;
  totalOperations: number;
  throughputOpsPerSec: number;
  memoryUsage: number;
  cpuUsage: number;
  networkLatency: number;
  errorRate: number;
  successRate: number;
  resourceEfficiency: number;
  trends: {
    performance: 'improving' | 'stable' | 'degrading';
    reliability: 'improving' | 'stable' | 'degrading';
    efficiency: 'improving' | 'stable' | 'degrading';
  };
}

interface RealTimeAlert {
  id: string;
  type: 'performance' | 'error' | 'resource' | 'threshold' | 'prediction';
  severity: 'info' | 'warning' | 'critical' | 'fatal';
  timestamp: string;
  message: string;
  details: Record<string, unknown>;
  moduleId?: string;
  correlationId?: string;
  resolved: boolean;
  resolvedAt?: string;
  actions: string[];
}

interface DataFlowState {
  sourceModuleId: string;
  targetModuleId: string;
  dataSize: number;
  transferTime: number;
  status: 'pending' | 'transferring' | 'completed' | 'failed';
  error?: string;
}

interface MonitoringSession {
  monitorId: string;
  scenarioId: number;
  executionId?: string;
  startTime: Date;
  config: RealTimeMonitoringConfig;
  state: ExecutionState | null;
  sseConnection?: string;
  alertThresholds: AlertThresholds;
  isActive: boolean;
  lastUpdate: Date;
  updateCount: number;
  errorCount: number;
}

interface RealTimeMonitoringConfig {
  updateInterval: number;
  enableProgressVisualization: boolean;
  enablePerformanceAlerts: boolean;
  enableDataFlowTracking: boolean;
  enablePredictiveAnalysis: boolean;
  enableSSEStreaming: boolean;
  alertThresholds: AlertThresholds;
  visualization: {
    format: 'ascii' | 'structured' | 'compact';
    colorEnabled: boolean;
    includeMetrics: boolean;
    includeDataFlow: boolean;
  };
}

interface AlertThresholds {
  performance: {
    maxModuleDuration: number;
    maxTotalDuration: number;
    minThroughput: number;
    maxErrorRate: number;
  };
  resource: {
    maxMemoryUsage: number;
    maxCpuUsage: number;
    maxNetworkLatency: number;
  };
  execution: {
    maxStuckTime: number;
    maxRetries: number;
    minSuccessRate: number;
  };
}

// Type definitions for function parameters
interface MonitoringConfigInput {
  updateInterval: number;
  monitorDuration: number;
  enableProgressVisualization: boolean;
  enablePerformanceAlerts: boolean;
  enableDataFlowTracking: boolean;
  enablePredictiveAnalysis: boolean;
  enableSSEStreaming: boolean;
}

interface AlertThresholdsInput {
  performance?: {
    maxModuleDuration?: number;
    maxTotalDuration?: number;
    minThroughput?: number;
    maxErrorRate?: number;
  };
  resource?: {
    maxMemoryUsage?: number;
    maxCpuUsage?: number;
    maxNetworkLatency?: number;
  };
  execution?: {
    maxStuckTime?: number;
    maxRetries?: number;
    minSuccessRate?: number;
  };
}

interface VisualizationInput {
  format?: 'ascii' | 'structured' | 'compact';
  colorEnabled?: boolean;
  includeMetrics?: boolean;
  includeDataFlow?: boolean;
  includeTimeline?: boolean;
  includePredictions?: boolean;
}

interface _StartMonitoringResponseData {
  monitorId: string;
  scenarioId: number;
  executionId: string | undefined;
  status: string;
  configuration: RealTimeMonitoringConfig;
  monitoring: Record<string, unknown>;
}

// Input validation schemas
const RealTimeMonitoringSchema = z.object({
  scenarioId: z.number().min(1).describe('Scenario ID to monitor in real-time'),
  executionId: z.string().optional().describe('Specific execution ID to monitor (leave empty to monitor next execution)'),
  monitoringConfig: z.object({
    updateInterval: z.number().min(500).max(10000).default(1000).describe('Update interval in milliseconds'),
    monitorDuration: z.number().min(10000).max(3600000).default(300000).describe('Maximum monitoring duration in milliseconds'),
    enableProgressVisualization: z.boolean().default(true).describe('Enable real-time progress visualization'),
    enablePerformanceAlerts: z.boolean().default(true).describe('Enable performance-based alerts'),
    enableDataFlowTracking: z.boolean().default(true).describe('Track data flow between modules'),
    enablePredictiveAnalysis: z.boolean().default(false).describe('Enable predictive performance analysis'),
    enableSSEStreaming: z.boolean().default(true).describe('Enable Server-Sent Events streaming'),
  }).default(() => ({
    updateInterval: 1000,
    monitorDuration: 60000,
    enableProgressVisualization: true,
    enablePerformanceAlerts: true,
    enableDataFlowTracking: true,
    enablePredictiveAnalysis: false,
    enableSSEStreaming: true,
  })),
  alertThresholds: z.object({
    performance: z.object({
      maxModuleDuration: z.number().min(1000).default(60000).describe('Maximum acceptable module duration (ms)'),
      maxTotalDuration: z.number().min(5000).default(300000).describe('Maximum acceptable total duration (ms)'),
      minThroughput: z.number().min(0.1).default(1.0).describe('Minimum acceptable throughput (ops/sec)'),
      maxErrorRate: z.number().min(0).max(1).default(0.1).describe('Maximum acceptable error rate (0-1)'),
    }).default(() => ({
      maxModuleDuration: 10000,
      maxTotalDuration: 60000,
      minThroughput: 10,
      maxErrorRate: 0.1,
    })),
    resource: z.object({
      maxMemoryUsage: z.number().min(0).max(1).default(0.8).describe('Maximum memory usage threshold (0-1)'),
      maxCpuUsage: z.number().min(0).max(1).default(0.8).describe('Maximum CPU usage threshold (0-1)'),
      maxNetworkLatency: z.number().min(100).default(2000).describe('Maximum network latency threshold (ms)'),
    }).default(() => ({
      maxMemoryUsage: 0.8,
      maxCpuUsage: 0.8,
      maxNetworkLatency: 2000,
    })),
    execution: z.object({
      maxStuckTime: z.number().min(5000).default(30000).describe('Maximum time module can be stuck (ms)'),
      maxRetries: z.number().min(1).default(3).describe('Maximum retry attempts before alert'),
      minSuccessRate: z.number().min(0).max(1).default(0.95).describe('Minimum success rate threshold (0-1)'),
    }).default(() => ({
      maxStuckTime: 30000,
      maxRetries: 3,
      minSuccessRate: 0.95,
    })),
  }).default(() => ({
    performance: {
      maxModuleDuration: 60000,
      maxTotalDuration: 300000,
      minThroughput: 1.0,
      maxErrorRate: 0.1,
    },
    resource: {
      maxMemoryUsage: 0.8,
      maxCpuUsage: 0.8,
      maxNetworkLatency: 2000,
    },
    execution: {
      maxStuckTime: 30000,
      maxRetries: 3,
      minSuccessRate: 0.95,
    },
  })),
  visualization: z.object({
    format: z.enum(['ascii', 'structured', 'compact']).default('structured').describe('Visualization format'),
    colorEnabled: z.boolean().default(true).describe('Enable color coding in visualization'),
    includeMetrics: z.boolean().default(true).describe('Include performance metrics in output'),
    includeDataFlow: z.boolean().default(true).describe('Include data flow visualization'),
    includeTimeline: z.boolean().default(true).describe('Include execution timeline'),
    includePredictions: z.boolean().default(false).describe('Include predictive analysis'),
  }).default(() => ({
    format: 'structured' as const,
    colorEnabled: true,
    includeMetrics: true,
    includeDataFlow: true,
    includeTimeline: true,
    includePredictions: false,
  })),
}).strict();

const StopMonitoringSchema = z.object({
  monitorId: z.string().describe('Monitor session ID to stop'),
  reason: z.string().optional().describe('Reason for stopping monitoring'),
}).strict();

const GetMonitoringStatusSchema = z.object({
  monitorId: z.string().optional().describe('Specific monitor ID to get status for'),
  includeHistory: z.boolean().default(false).describe('Include historical monitoring data'),
}).strict();

/**
 * Real-time execution monitoring manager
 */
class RealTimeExecutionMonitor extends EventEmitter {
  private readonly activeSessions = new Map<string, MonitoringSession>();
  private sseTransport: SSETransportEnhancer | null = null;
  private readonly performanceMonitor: PerformanceMonitor;
  private readonly componentLogger: ReturnType<typeof logger.child>;

  constructor(private readonly apiClient: MakeApiClient) {
    super();
    this.componentLogger = logger.child({ component: 'RealTimeExecutionMonitor' });
    this.performanceMonitor = new PerformanceMonitor();
    this.setMaxListeners(100); // Support many concurrent monitoring sessions

    // Initialize SSE transport for real-time streaming
    this.initializeSSETransport();
  }

  /**
   * Initialize SSE transport for real-time streaming
   */
  private initializeSSETransport(): void {
    try {
      this.sseTransport = new SSETransportEnhancer({
        endpoint: '/monitoring/sse',
        heartbeatInterval: 15000,
        security: {
          rateLimitEnabled: true,
          maxConnections: 50,
          connectionTimeout: 300000, // 5 minutes
          maxMessageSize: 1048576, // 1MB
        },
      });
      this.componentLogger.info('SSE transport initialized for real-time monitoring');
    } catch (error) {
      this.componentLogger.warn('Failed to initialize SSE transport', { error });
    }
  }

  /**
   * Start real-time monitoring session
   */
  async startMonitoring(
    scenarioId: number,
    executionId: string | undefined,
    config: RealTimeMonitoringConfig
  ): Promise<string> {
    const monitorId = `monitor_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const componentLogger = this.componentLogger.child({ monitorId, scenarioId, executionId });

    componentLogger.info('Starting real-time execution monitoring', { config });

    // Resolve execution ID if not provided
    let targetExecutionId = executionId;
    if (!targetExecutionId) {
      const foundExecutionId = await this.findOrWaitForExecution(scenarioId);
      if (!foundExecutionId) {
        throw new UserError('No active or recent execution found for monitoring');
      }
      targetExecutionId = foundExecutionId;
    }

    // Create monitoring session
    const session: MonitoringSession = {
      monitorId,
      scenarioId,
      executionId: targetExecutionId,
      startTime: new Date(),
      config,
      state: null,
      alertThresholds: config.alertThresholds,
      isActive: true,
      lastUpdate: new Date(),
      updateCount: 0,
      errorCount: 0,
    };

    // Initialize SSE connection if enabled
    if (config.enableSSEStreaming && this.sseTransport) {
      try {
        const sseConnectionId = await this.createSSEConnection(session);
        session.sseConnection = sseConnectionId;
      } catch (error) {
        componentLogger.warn('Failed to create SSE connection', { error });
      }
    }

    this.activeSessions.set(monitorId, session);

    // Start monitoring loop
    this.startMonitoringLoop(session);

    componentLogger.info('Real-time monitoring session started', {
      monitorId,
      executionId: targetExecutionId,
      sseEnabled: !!session.sseConnection,
    });

    return monitorId;
  }

  /**
   * Stop monitoring session
   */
  stopMonitoring(monitorId: string, reason?: string): boolean {
    const session = this.activeSessions.get(monitorId);
    if (!session) {
      return false;
    }

    session.isActive = false;
    
    // Close SSE connection if exists
    if (session.sseConnection && this.sseTransport) {
      this.sseTransport.disconnect(session.sseConnection);
    }

    this.activeSessions.delete(monitorId);

    this.componentLogger.info('Monitoring session stopped', {
      monitorId,
      reason,
      duration: Date.now() - session.startTime.getTime(),
      updateCount: session.updateCount,
    });

    return true;
  }

  /**
   * Get current monitoring status
   */
  getMonitoringStatus(monitorId?: string): Record<string, unknown> {
    if (monitorId) {
      const session = this.activeSessions.get(monitorId);
      if (!session) {
        return { error: 'Monitoring session not found' };
      }
      return this.formatSessionStatus(session);
    }

    // Return all active sessions
    const sessions = Array.from(this.activeSessions.values()).map(session => 
      this.formatSessionStatus(session)
    );

    return {
      totalActiveSessions: sessions.length,
      sessions,
      systemStatus: {
        sseTransportActive: !!this.sseTransport,
        totalConnections: this.sseTransport?.getStatistics?.()?.activeConnections || 0,
        performanceMonitorActive: true,
      },
    };
  }

  /**
   * Find or wait for execution to monitor
   */
  private async findOrWaitForExecution(scenarioId: number): Promise<string | null> {
    // First, try to find a running execution
    const runningResponse = await this.apiClient.get(`/scenarios/${scenarioId}/executions`, {
      params: { 
        limit: 5, 
        sortBy: 'startTime', 
        sortOrder: 'desc',
        status: 'running',
      }
    });

    if (runningResponse.success && runningResponse.data) {
      const executions = runningResponse.data as Array<{ id: string; status: string }>;
      const runningExecution = executions.find(exec => exec.status === 'running');
      if (runningExecution) {
        return runningExecution.id;
      }
    }

    // If no running execution, get the most recent one
    const recentResponse = await this.apiClient.get(`/scenarios/${scenarioId}/executions`, {
      params: { 
        limit: 1, 
        sortBy: 'startTime', 
        sortOrder: 'desc',
      }
    });

    if (recentResponse.success && recentResponse.data) {
      const executions = recentResponse.data as Array<{ id: string }>;
      if (executions.length > 0) {
        return executions[0].id;
      }
    }

    return null;
  }

  /**
   * Start monitoring loop for a session
   */
  private startMonitoringLoop(session: MonitoringSession): void {
    const monitoringInterval = setInterval(async () => {
      if (!session.isActive) {
        clearInterval(monitoringInterval);
        return;
      }

      try {
        await this.updateExecutionState(session);
        session.updateCount++;
        session.lastUpdate = new Date();
      } catch (error) {
        session.errorCount++;
        this.componentLogger.error('Error updating execution state', {
          monitorId: session.monitorId,
          error: error instanceof Error ? error.message : String(error),
          errorCount: session.errorCount,
        });

        // Stop monitoring after too many errors
        if (session.errorCount >= 5) {
          this.stopMonitoring(session.monitorId, 'Too many consecutive errors');
        }
      }
    }, session.config.updateInterval);

    // Set timeout for maximum monitoring duration
    setTimeout(() => {
      if (session.isActive) {
        this.stopMonitoring(session.monitorId, 'Maximum monitoring duration reached');
      }
    }, 300000); // 5 minutes maximum
  }

  /**
   * Update execution state for a monitoring session
   */
  private async updateExecutionState(session: MonitoringSession): Promise<void> {
    if (!session.executionId) {return;}

    // Get execution details
    const executionResponse = await this.apiClient.get(`/executions/${session.executionId}`);
    if (!executionResponse.success) {
      throw new Error(`Failed to get execution details: ${executionResponse.error?.message}`);
    }

    const executionData = executionResponse.data as Record<string, unknown>;

    // Get execution logs for module progress
    const logsResponse = await this.apiClient.get(`/executions/${session.executionId}/logs`, {
      params: {
        limit: 100,
        sortBy: 'timestamp',
        sortOrder: 'desc',
        level: 'info,warning,error',
      }
    });

    const logs = logsResponse.success ? (logsResponse.data as Array<Record<string, unknown>>) : [];

    // Build execution state
    const newState = await this.buildExecutionState(session, executionData, logs);
    
    // Check for alerts
    if (session.config.enablePerformanceAlerts) {
      await this.checkAlerts(session, newState);
    }

    // Update session state
    session.state = newState;

    // Send real-time update via SSE
    if (session.sseConnection && this.sseTransport) {
      const update = this.formatRealtimeUpdate(session, newState);
      this.sseTransport.sendMessage(session.sseConnection, {
        event: 'execution_update',
        data: JSON.stringify(update),
      });
    }

    // Emit update event
    this.emit('execution_update', {
      monitorId: session.monitorId,
      state: newState,
    });
  }

  /**
   * Build execution state from API data and logs
   */
  private async buildExecutionState(
    session: MonitoringSession,
    executionData: Record<string, unknown>,
    logs: Array<Record<string, unknown>>
  ): Promise<ExecutionState> {
    const startTime = executionData.startTime as string || new Date().toISOString();
    const endTime = executionData.endTime as string || undefined;
    const status = (executionData.status as string || 'running') as ExecutionState['status'];
    
    // Analyze logs to determine module progress
    const moduleProgress = this.analyzeModuleProgress(logs);
    const performance = this.calculatePerformanceMetrics(executionData, logs);
    const dataFlow = this.analyzeDataFlow(logs);

    // Calculate progress percentage
    const totalModules = moduleProgress.length || 1;
    const completedModules = moduleProgress.filter(m => m.status === 'completed').length;
    const completionPercentage = (completedModules / totalModules) * 100;

    // Find current module
    const currentModule = moduleProgress.find(m => m.status === 'running') || null;

    // Estimate completion time
    const estimatedCompletion = this.estimateCompletion(
      startTime,
      completionPercentage,
      performance.averageModuleDuration
    );

    return {
      executionId: session.executionId || '',
      scenarioId: session.scenarioId,
      status,
      startTime,
      endTime,
      duration: endTime ? new Date(endTime).getTime() - new Date(startTime).getTime() : 
                Date.now() - new Date(startTime).getTime(),
      progress: {
        totalModules,
        completedModules,
        currentModule,
        estimatedCompletion,
        completionPercentage,
      },
      performance,
      alerts: session.state?.alerts || [],
      dataFlow,
      metadata: {
        organizationId: executionData.organizationId as number || 0,
        teamId: executionData.teamId as number || 0,
        userId: executionData.userId as number || undefined,
        scenarioName: executionData.scenarioName as string || `Scenario ${session.scenarioId}`,
        blueprintId: executionData.blueprintId as string || undefined,
        triggerType: executionData.triggerType as ExecutionState['metadata']['triggerType'] || 'manual',
      },
    };
  }

  /**
   * Analyze module progress from logs
   */
  private analyzeModuleProgress(logs: Array<Record<string, unknown>>): ModuleProgress[] {
    const moduleMap = new Map<string, ModuleProgress>();

    for (const log of logs) {
      const module = this.extractModuleFromLog(log);
      const moduleId = module.id;

      if (!moduleMap.has(moduleId)) {
        moduleMap.set(moduleId, this.createInitialModuleProgress(module));
      }

      const moduleProgress = moduleMap.get(moduleId);
      if (!moduleProgress) {
        continue;
      }
      
      this.updateModuleProgress(moduleProgress, log);
    }

    return Array.from(moduleMap.values());
  }

  /**
   * Extract module information from log entry
   */
  private extractModuleFromLog(log: Record<string, unknown>): {
    id: string;
    name: string;
    type: string;
    position: { x: number; y: number };
  } {
    const module = log.module as Record<string, unknown> || {};
    return {
      id: module.id as string || 'unknown',
      name: module.name as string || 'Unknown Module',
      type: module.type as string || 'unknown',
      position: (module.position as { x: number; y: number }) || { x: 0, y: 0 },
    };
  }

  /**
   * Create initial module progress entry
   */
  private createInitialModuleProgress(module: {
    id: string;
    name: string;
    type: string;
    position: { x: number; y: number };
  }): ModuleProgress {
    return {
      moduleId: module.id,
      moduleName: module.name,
      moduleType: module.type,
      position: module.position,
      status: 'pending',
      inputBundles: 0,
      outputBundles: 0,
      operations: 0,
      dataSize: 0,
    };
  }

  /**
   * Update module progress based on log information
   */
  private updateModuleProgress(moduleProgress: ModuleProgress, log: Record<string, unknown>): void {
    const metrics = log.metrics as Record<string, unknown> || {};
    const error = log.error as Record<string, unknown> || null;

    if (error) {
      this.handleModuleError(moduleProgress, error);
    } else {
      this.updateModuleStatus(moduleProgress, log);
    }

    this.updateModuleMetrics(moduleProgress, metrics);
  }

  /**
   * Handle module error status update
   */
  private handleModuleError(moduleProgress: ModuleProgress, error: Record<string, unknown>): void {
    moduleProgress.status = 'failed';
    moduleProgress.error = {
      code: error.code as string || 'UNKNOWN_ERROR',
      message: error.message as string || 'Unknown error',
      type: error.type as string || 'runtime',
      retryable: error.retryable as boolean || false,
    };
  }

  /**
   * Update module status based on log level and content
   */
  private updateModuleStatus(moduleProgress: ModuleProgress, log: Record<string, unknown>): void {
    const timestamp = log.timestamp as string;
    const level = log.level as string;
    
    if (level === 'info' && log.message) {
      if (!moduleProgress.startTime) {
        moduleProgress.startTime = timestamp;
        moduleProgress.status = 'running';
      } else if (log.message.toString().includes('completed') || level === 'info') {
        moduleProgress.endTime = timestamp;
        moduleProgress.status = 'completed';
        if (moduleProgress.startTime) {
          moduleProgress.duration = new Date(timestamp).getTime() - new Date(moduleProgress.startTime).getTime();
        }
      }
    }
  }

  /**
   * Update module metrics from log data
   */
  private updateModuleMetrics(moduleProgress: ModuleProgress, metrics: Record<string, unknown>): void {
    moduleProgress.inputBundles += (metrics.inputBundles as number) || 0;
    moduleProgress.outputBundles += (metrics.outputBundles as number) || 0;
    moduleProgress.operations += (metrics.operations as number) || 0;
    moduleProgress.dataSize += (metrics.dataSize as number) || 0;
  }

  /**
   * Calculate real-time performance metrics
   */
  private calculatePerformanceMetrics(
    executionData: Record<string, unknown>,
    logs: Array<Record<string, unknown>>
  ): RealTimePerformanceMetrics {
    const startTime = new Date(executionData.startTime as string || new Date());
    const currentTime = new Date();
    const totalDuration = currentTime.getTime() - startTime.getTime();

    // Calculate metrics from logs
    const processedLogs = logs.filter(log => log.metrics);
    const totalOperations = processedLogs.reduce((sum, log) => {
      const metrics = log.metrics as Record<string, unknown> || {};
      return sum + ((metrics.operations as number) || 0);
    }, 0);

    const totalDataProcessed = processedLogs.reduce((sum, log) => {
      const metrics = log.metrics as Record<string, unknown> || {};
      return sum + ((metrics.dataSize as number) || 0);
    }, 0);

    const processingTimes = processedLogs
      .map(log => (log.metrics as Record<string, unknown>)?.processingTime as number)
      .filter(time => typeof time === 'number' && time > 0);

    const averageModuleDuration = processingTimes.length > 0 
      ? processingTimes.reduce((sum, time) => sum + time, 0) / processingTimes.length
      : 0;

    const errorLogs = logs.filter(log => log.error);
    const errorRate = logs.length > 0 ? (errorLogs.length / logs.length) : 0;
    const successRate = 1 - errorRate;

    const throughputOpsPerSec = totalDuration > 0 ? (totalOperations / (totalDuration / 1000)) : 0;

    // Get system metrics
    const memUsage = process.memoryUsage();
    const memoryUsage = memUsage.heapUsed / memUsage.heapTotal;
    const cpuUsage = process.cpuUsage();
    const cpuUsagePercent = (cpuUsage.user + cpuUsage.system) / 1000000 / 1000; // Simplified

    return {
      totalDuration,
      averageModuleDuration,
      totalDataProcessed,
      totalOperations,
      throughputOpsPerSec,
      memoryUsage,
      cpuUsage: cpuUsagePercent,
      networkLatency: 0, // Would need actual network measurements
      errorRate,
      successRate,
      resourceEfficiency: Math.min(1, (throughputOpsPerSec / 10) * (1 - errorRate)), // Simplified efficiency score
      trends: {
        performance: 'stable', // Would need historical data for trend analysis
        reliability: errorRate < 0.1 ? 'stable' : 'degrading',
        efficiency: 'stable',
      },
    };
  }

  /**
   * Analyze data flow between modules
   */
  private analyzeDataFlow(logs: Array<Record<string, unknown>>): DataFlowState[] {
    const dataFlows: DataFlowState[] = [];
    
    // This is a simplified implementation - in reality, you'd need to analyze
    // the actual data transfer patterns between modules
    const moduleIds = [...new Set(logs.map(log => {
      const module = log.module as Record<string, unknown> || {};
      return module.id as string;
    }).filter(Boolean))];

    for (let i = 0; i < moduleIds.length - 1; i++) {
      const sourceModuleId = moduleIds[i];
      const targetModuleId = moduleIds[i + 1];
      
      // Find logs related to data transfer between these modules
      const transferLogs = logs.filter(log => {
        const module = log.module as Record<string, unknown> || {};
        return module.id === sourceModuleId || module.id === targetModuleId;
      });

      if (transferLogs.length > 0) {
        const totalDataSize = transferLogs.reduce((sum, log) => {
          const metrics = log.metrics as Record<string, unknown> || {};
          return sum + ((metrics.dataSize as number) || 0);
        }, 0);

        dataFlows.push({
          sourceModuleId,
          targetModuleId,
          dataSize: totalDataSize,
          transferTime: 0, // Would need actual timing measurements
          status: 'completed',
        });
      }
    }

    return dataFlows;
  }

  /**
   * Check for alerts based on thresholds and performance
   */
  private async checkAlerts(session: MonitoringSession, state: ExecutionState): Promise<void> {
    const alerts: RealTimeAlert[] = [...(state.alerts || [])];
    const thresholds = session.alertThresholds;
    const timestamp = new Date().toISOString();

    // Performance alerts
    if (state.performance.averageModuleDuration > thresholds.performance.maxModuleDuration) {
      alerts.push({
        id: `alert_${Date.now()}_perf_module_duration`,
        type: 'performance',
        severity: 'warning',
        timestamp,
        message: `Average module duration (${Math.round(state.performance.averageModuleDuration)}ms) exceeds threshold (${thresholds.performance.maxModuleDuration}ms)`,
        details: {
          averageDuration: state.performance.averageModuleDuration,
          threshold: thresholds.performance.maxModuleDuration,
          trend: state.performance.trends.performance,
        },
        resolved: false,
        actions: ['Optimize slow modules', 'Check resource constraints', 'Review module configuration'],
      });
    }

    // Error rate alerts
    if (state.performance.errorRate > thresholds.performance.maxErrorRate) {
      alerts.push({
        id: `alert_${Date.now()}_error_rate`,
        type: 'error',
        severity: state.performance.errorRate > 0.2 ? 'critical' : 'warning',
        timestamp,
        message: `Error rate (${(state.performance.errorRate * 100).toFixed(1)}%) exceeds threshold (${(thresholds.performance.maxErrorRate * 100).toFixed(1)}%)`,
        details: {
          errorRate: state.performance.errorRate,
          threshold: thresholds.performance.maxErrorRate,
          totalErrors: Math.round(state.performance.errorRate * (state.progress.completedModules || 1)),
        },
        resolved: false,
        actions: ['Review error patterns', 'Implement retry logic', 'Check external service availability'],
      });
    }

    // Resource usage alerts
    if (state.performance.memoryUsage > thresholds.resource.maxMemoryUsage) {
      alerts.push({
        id: `alert_${Date.now()}_memory_usage`,
        type: 'resource',
        severity: state.performance.memoryUsage > 0.9 ? 'critical' : 'warning',
        timestamp,
        message: `Memory usage (${(state.performance.memoryUsage * 100).toFixed(1)}%) exceeds threshold (${(thresholds.resource.maxMemoryUsage * 100).toFixed(1)}%)`,
        details: {
          memoryUsage: state.performance.memoryUsage,
          threshold: thresholds.resource.maxMemoryUsage,
        },
        resolved: false,
        actions: ['Review memory-intensive operations', 'Optimize data processing', 'Consider resource scaling'],
      });
    }

    // Update state with new alerts
    state.alerts = alerts;
  }

  /**
   * Estimate completion time
   */
  private estimateCompletion(
    startTime: string,
    completionPercentage: number,
    _averageModuleDuration: number
  ): Date | null {
    if (completionPercentage === 0) {return null;}

    const elapsed = Date.now() - new Date(startTime).getTime();
    const totalEstimated = (elapsed / completionPercentage) * 100;
    const remaining = totalEstimated - elapsed;

    return new Date(Date.now() + remaining);
  }

  /**
   * Create SSE connection for real-time updates
   */
  private async createSSEConnection(session: MonitoringSession): Promise<string> {
    if (!this.sseTransport) {
      throw new Error('SSE transport not available');
    }

    // This would typically be handled by the SSE transport layer
    // For now, we'll return a mock connection ID
    const connectionId = `sse_${session.monitorId}_${Date.now()}`;
    
    this.componentLogger.debug('SSE connection created for monitoring', {
      monitorId: session.monitorId,
      connectionId,
    });

    return connectionId;
  }

  /**
   * Format real-time update for SSE streaming
   */
  private formatRealtimeUpdate(session: MonitoringSession, state: ExecutionState): Record<string, unknown> {
    return {
      monitorId: session.monitorId,
      timestamp: new Date().toISOString(),
      executionId: state.executionId,
      scenarioId: state.scenarioId,
      status: state.status,
      progress: state.progress,
      performance: {
        duration: state.performance.totalDuration,
        throughput: state.performance.throughputOpsPerSec,
        errorRate: state.performance.errorRate,
        completionPercentage: state.progress.completionPercentage,
      },
      alerts: state.alerts.filter(alert => !alert.resolved),
      currentModule: state.progress.currentModule,
      visualization: session.config.enableProgressVisualization ? 
        this.generateVisualization(state, session.config.visualization) : undefined,
    };
  }

  /**
   * Format session status
   */
  private formatSessionStatus(session: MonitoringSession): Record<string, unknown> {
    return {
      monitorId: session.monitorId,
      scenarioId: session.scenarioId,
      executionId: session.executionId,
      startTime: session.startTime.toISOString(),
      isActive: session.isActive,
      updateCount: session.updateCount,
      errorCount: session.errorCount,
      lastUpdate: session.lastUpdate.toISOString(),
      config: session.config,
      state: session.state,
      sseConnected: !!session.sseConnection,
    };
  }

  /**
   * Generate visualization based on current state
   */
  private generateVisualization(state: ExecutionState, config: Record<string, unknown>): string {
    const { format, colorEnabled } = config;
    
    if (format === 'ascii') {
      return this.generateASCIIVisualization(state, Boolean(colorEnabled));
    } else if (format === 'compact') {
      return this.generateCompactVisualization(state);
    } else {
      return this.generateStructuredVisualization(state, config);
    }
  }

  /**
   * Generate ASCII art visualization
   */
  private generateASCIIVisualization(state: ExecutionState, _colorEnabled: boolean): string {
    const { progress } = state;
    const width = 50;
    const filled = Math.round((progress.completionPercentage / 100) * width);
    const empty = width - filled;
    
    const progressBar = '█'.repeat(filled) + '░'.repeat(empty);
    const percentage = `${progress.completionPercentage.toFixed(1)}%`;
    
    let visualization = `
┌─ Execution Progress ────────────────────────────────────┐
│ ${progressBar} ${percentage.padStart(6)} │
│ Status: ${state.status.toUpperCase().padEnd(12)} Modules: ${progress.completedModules}/${progress.totalModules} │
└─────────────────────────────────────────────────────────┘
`;

    if (state.progress.currentModule) {
      visualization += `
Current Module: ${state.progress.currentModule.moduleName} (${state.progress.currentModule.status})
`;
    }

    if (state.alerts.filter(a => !a.resolved).length > 0) {
      visualization += `
⚠️  Active Alerts: ${state.alerts.filter(a => !a.resolved).length}
`;
    }

    return visualization;
  }

  /**
   * Generate compact visualization
   */
  private generateCompactVisualization(state: ExecutionState): string {
    const { progress, performance } = state;
    return `${state.status.toUpperCase()} | ${progress.completionPercentage.toFixed(1)}% | ${progress.completedModules}/${progress.totalModules} modules | ${Math.round(performance.totalDuration/1000)}s | ${performance.errorRate > 0 ? `${(performance.errorRate * 100).toFixed(1)}% errors` : 'no errors'}`;
  }

  /**
   * Generate structured visualization
   */
  private generateStructuredVisualization(state: ExecutionState, config: Record<string, unknown>): string {
    const { progress, performance, metadata } = state;
    
    let visualization = `
Real-Time Execution Monitor
==========================

Scenario: ${metadata.scenarioName} (ID: ${state.scenarioId})
Execution: ${state.executionId}
Status: ${state.status.toUpperCase()}
Duration: ${Math.round(performance.totalDuration / 1000)}s

Progress Overview:
  Completion: ${progress.completionPercentage.toFixed(1)}% (${progress.completedModules}/${progress.totalModules} modules)
  Current: ${progress.currentModule ? progress.currentModule.moduleName : 'None'}
  ETA: ${progress.estimatedCompletion ? new Date(progress.estimatedCompletion).toLocaleTimeString() : 'Unknown'}
`;

    if (config.includeMetrics) {
      visualization += `
Performance Metrics:
  Throughput: ${performance.throughputOpsPerSec.toFixed(2)} ops/sec
  Avg Module Duration: ${Math.round(performance.averageModuleDuration)}ms
  Error Rate: ${(performance.errorRate * 100).toFixed(1)}%
  Success Rate: ${(performance.successRate * 100).toFixed(1)}%
  Resource Efficiency: ${(performance.resourceEfficiency * 100).toFixed(1)}%
`;
    }

    const activeAlerts = state.alerts.filter(alert => !alert.resolved);
    if (activeAlerts.length > 0) {
      visualization += `
Active Alerts (${activeAlerts.length}):
`;
      activeAlerts.slice(0, 3).forEach(alert => {
        visualization += `  ${alert.severity.toUpperCase()}: ${alert.message}\n`;
      });
    }

    return visualization;
  }

  /**
   * Cleanup monitoring resources
   */
  async cleanup(): Promise<void> {
    this.componentLogger.info('Cleaning up real-time monitoring resources');

    // Stop all active sessions
    const activeSessionIds = Array.from(this.activeSessions.keys());
    for (const sessionId of activeSessionIds) {
      this.stopMonitoring(sessionId, 'System cleanup');
    }

    // Shutdown SSE transport
    if (this.sseTransport) {
      await this.sseTransport.shutdown();
    }

    this.componentLogger.info('Real-time monitoring cleanup completed', {
      stoppedSessions: activeSessionIds.length,
    });
  }
}

/**
 * Build monitoring configuration from input parameters
 */
function buildMonitoringConfig(
  monitoringConfig: MonitoringConfigInput,
  alertThresholds: AlertThresholdsInput,
  visualization: VisualizationInput
): RealTimeMonitoringConfig {
  return {
    updateInterval: monitoringConfig.updateInterval,
    enableProgressVisualization: monitoringConfig.enableProgressVisualization,
    enablePerformanceAlerts: monitoringConfig.enablePerformanceAlerts,
    enableDataFlowTracking: monitoringConfig.enableDataFlowTracking,
    enablePredictiveAnalysis: monitoringConfig.enablePredictiveAnalysis,
    enableSSEStreaming: monitoringConfig.enableSSEStreaming,
    alertThresholds: buildAlertThresholds(alertThresholds),
    visualization: buildVisualizationConfig(visualization),
  };
}

/**
 * Build alert thresholds configuration
 */
function buildAlertThresholds(alertThresholds: AlertThresholdsInput): AlertThresholds {
  return {
    performance: {
      maxModuleDuration: alertThresholds.performance?.maxModuleDuration || 60000,
      maxTotalDuration: alertThresholds.performance?.maxTotalDuration || 300000,
      minThroughput: alertThresholds.performance?.minThroughput || 1.0,
      maxErrorRate: alertThresholds.performance?.maxErrorRate || 0.1,
    },
    resource: {
      maxMemoryUsage: alertThresholds.resource?.maxMemoryUsage || 0.8,
      maxCpuUsage: alertThresholds.resource?.maxCpuUsage || 0.8,
      maxNetworkLatency: alertThresholds.resource?.maxNetworkLatency || 2000,
    },
    execution: {
      maxStuckTime: alertThresholds.execution?.maxStuckTime || 30000,
      maxRetries: alertThresholds.execution?.maxRetries || 3,
      minSuccessRate: alertThresholds.execution?.minSuccessRate || 0.95,
    },
  };
}

/**
 * Build visualization configuration
 */
function buildVisualizationConfig(visualization: VisualizationInput): RealTimeMonitoringConfig['visualization'] {
  return {
    format: visualization.format || 'structured',
    colorEnabled: visualization.colorEnabled !== false,
    includeMetrics: visualization.includeMetrics !== false,
    includeDataFlow: visualization.includeDataFlow !== false,
  };
}

/**
 * Build start monitoring response
 */
function buildStartMonitoringResponse(
  monitorId: string,
  scenarioId: number,
  executionId: string | undefined,
  config: RealTimeMonitoringConfig,
  status: Record<string, unknown>
): ToolResponse {
  return formatSuccessResponse({
    monitorId,
    scenarioId,
    executionId: executionId || 'auto-detected',
    startTime: new Date().toISOString(),
    config,
    initialStatus: status,
    message: 'Real-time monitoring started successfully',
    instructions: {
      sse: 'Connect to /monitoring/sse endpoint for real-time updates',
      stop: `Use stop_monitoring tool with monitorId: ${monitorId}`,
      status: `Use get_monitoring_status tool with monitorId: ${monitorId}`,
    },
  });
}

/**
 * Add real-time monitoring tools to FastMCP server
 */
export function addRealTimeMonitoringTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'RealTimeMonitoringTools' });
  const monitor = new RealTimeExecutionMonitor(apiClient);
  
  componentLogger.info('Adding real-time monitoring tools');

  // Cleanup on server shutdown
  process.on('SIGINT', () => monitor.cleanup());
  process.on('SIGTERM', () => monitor.cleanup());

  // 1. Start Real-Time Monitoring
  server.addTool({
    name: 'stream_live_execution',
    description: 'Start comprehensive real-time monitoring of Make.com scenario execution with advanced progress tracking, performance alerts, and SSE streaming',
    parameters: RealTimeMonitoringSchema,
    annotations: {
      title: 'Start Real-Time Execution Monitoring',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { scenarioId, executionId, monitoringConfig, alertThresholds, visualization } = input;

      log.info('Starting real-time execution monitoring', {
        scenarioId,
        executionId,
        config: monitoringConfig,
      });

      try {
        const config = buildMonitoringConfig(monitoringConfig, alertThresholds, visualization);
        const monitorId = await monitor.startMonitoring(scenarioId, executionId, config);
        
        // Wait for initial state update
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        const status = monitor.getMonitoringStatus(monitorId);
        
        return buildStartMonitoringResponse(monitorId, scenarioId, executionId, config, status);

      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error starting real-time monitoring', { scenarioId, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to start real-time monitoring: ${errorMessage}`);
      }
    },
  });

  // 2. Stop Monitoring
  server.addTool({
    name: 'stop_monitoring',
    description: 'Stop an active real-time monitoring session',
    parameters: StopMonitoringSchema,
    annotations: {
      title: 'Stop Monitoring Session',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { monitorId, reason } = input;

      log.info('Stopping monitoring session', { monitorId, reason });

      try {
        const stopped = monitor.stopMonitoring(monitorId, reason);
        
        if (!stopped) {
          throw new UserError(`Monitoring session ${monitorId} not found or already stopped`);
        }

        return formatSuccessResponse({
          monitorId,
          stopped: true,
          reason: reason || 'Manual stop',
          timestamp: new Date().toISOString(),
          message: 'Monitoring session stopped successfully',
        });

      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error stopping monitoring', { monitorId, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to stop monitoring: ${errorMessage}`);
      }
    },
  });

  // 3. Get Monitoring Status
  server.addTool({
    name: 'get_monitoring_status',
    description: 'Get current status of monitoring sessions',
    parameters: GetMonitoringStatusSchema,
    annotations: {
      title: 'Get Monitoring Status',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { monitorId, includeHistory } = input;

      log.info('Getting monitoring status', { monitorId, includeHistory });

      try {
        const status = monitor.getMonitoringStatus(monitorId);
        
        return formatSuccessResponse({
          requestedAt: new Date().toISOString(),
          monitorId: monitorId || 'all',
          status,
          includeHistory,
        });

      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error getting monitoring status', { monitorId, error: errorMessage });
        throw new UserError(`Failed to get monitoring status: ${errorMessage}`);
      }
    },
  });

  componentLogger.info('Real-time monitoring tools added successfully');
}

export default { addRealTimeMonitoringTools };