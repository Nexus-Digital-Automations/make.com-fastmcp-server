/**
 * Monitoring middleware for FastMCP Server
 * Integrates metrics collection and monitoring with server operations
 */

import { FastMCP } from 'fastmcp';
import metrics from '../lib/metrics.js';
import logger from '../lib/logger.js';

interface MonitoringContext {
  tool?: string;
  operation?: string;
  sessionId?: string;
  userId?: string;
  correlationId?: string;
}

export interface ToolMetrics {
  startTime: number;
  endTime?: number;
  duration?: number;
  status?: 'success' | 'error' | 'timeout';
  errorType?: string;
}

class MonitoringMiddleware {
  private componentLogger: ReturnType<typeof logger.child>;
  private activeConnections: number = 0;
  private toolExecutions: Map<string, ToolMetrics> = new Map();

  constructor() {
    this.componentLogger = logger.child({ component: 'MonitoringMiddleware' });
  }

  /**
   * Initialize monitoring for FastMCP server
   */
  public initializeServerMonitoring(server: FastMCP): void {
    this.componentLogger.info('Initializing server monitoring');

    // Monitor connection events
    server.on('connect', (event) => {
      this.activeConnections++;
      metrics.setActiveConnections(this.activeConnections);
      
      const sessionId = this.extractSessionId(event.session);
      
      this.componentLogger.info('Client connected', { 
        sessionId,
        activeConnections: this.activeConnections 
      });

      metrics.recordRequest('connect', 'client_connect', 'success', 0);
    });

    server.on('disconnect', (event) => {
      this.activeConnections = Math.max(0, this.activeConnections - 1);
      metrics.setActiveConnections(this.activeConnections);
      
      const sessionId = this.extractSessionId(event.session);
      
      this.componentLogger.info('Client disconnected', { 
        sessionId,
        activeConnections: this.activeConnections 
      });

      metrics.recordRequest('disconnect', 'client_disconnect', 'success', 0);
    });

    this.componentLogger.info('Server monitoring initialized');
  }

  /**
   * Create a monitoring wrapper for tool execution
   */
  public wrapToolExecution<T>(
    toolName: string,
    operation: string,
    execution: () => Promise<T>,
    context: MonitoringContext = {}
  ): () => Promise<T> {
    return async (): Promise<T> => {
      const executionId = `${toolName}_${Date.now()}_${Math.random()}`;
      const timer = metrics.createTimer();
      
      const toolMetrics: ToolMetrics = {
        startTime: Date.now()
      };
      
      this.toolExecutions.set(executionId, toolMetrics);

      const contextLogger = this.componentLogger.child({
        tool: toolName,
        operation,
        executionId,
        ...context
      });

      contextLogger.info('Tool execution started', {
        tool: toolName,
        operation
      });

      try {
        const result = await execution();
        
        const duration = timer();
        toolMetrics.endTime = Date.now();
        toolMetrics.duration = duration;
        toolMetrics.status = 'success';

        metrics.recordToolExecution(toolName, 'success', duration, context.userId);

        contextLogger.info('Tool execution completed successfully', {
          duration: `${duration.toFixed(3)}s`,
          tool: toolName,
          operation
        });

        this.toolExecutions.delete(executionId);
        return result;

      } catch (error) {
        const duration = timer();
        const errorType = this.classifyError(error);
        
        toolMetrics.endTime = Date.now();
        toolMetrics.duration = duration;
        toolMetrics.status = 'error';
        toolMetrics.errorType = errorType;

        metrics.recordToolExecution(toolName, 'error', duration, context.userId);
        metrics.recordError(errorType, operation, toolName);

        contextLogger.error('Tool execution failed', {
          duration: `${duration.toFixed(3)}s`,
          error: error instanceof Error ? error.message : String(error),
          errorType,
          tool: toolName,
          operation
        });

        this.toolExecutions.delete(executionId);
        throw error;
      }
    };
  }

  /**
   * Monitor authentication attempts
   */
  public monitorAuthentication<T>(
    execution: () => Promise<T>,
    context: MonitoringContext = {}
  ): () => Promise<T> {
    return async (): Promise<T> => {
      const timer = metrics.createTimer();
      
      const contextLogger = this.componentLogger.child({
        operation: 'authentication',
        ...context
      });

      contextLogger.info('Authentication attempt started');

      try {
        const result = await execution();
        const duration = timer();
        
        metrics.recordAuthAttempt('success');
        metrics.recordAuthDuration(duration);

        contextLogger.info('Authentication successful', {
          duration: `${duration.toFixed(3)}s`
        });

        return result;

      } catch (error) {
        const duration = timer();
        const errorType = this.classifyError(error);
        
        metrics.recordAuthAttempt('failure', errorType);
        metrics.recordAuthDuration(duration);
        metrics.recordError(errorType, 'authentication');

        contextLogger.error('Authentication failed', {
          duration: `${duration.toFixed(3)}s`,
          error: error instanceof Error ? error.message : String(error),
          errorType
        });

        throw error;
      }
    };
  }

  /**
   * Monitor Make.com API calls
   */
  public monitorMakeApiCall<T>(
    endpoint: string,
    method: string,
    execution: () => Promise<T>,
    context: MonitoringContext = {}
  ): () => Promise<T> {
    return async (): Promise<T> => {
      const timer = metrics.createTimer();
      
      const contextLogger = this.componentLogger.child({
        operation: 'make_api_call',
        endpoint,
        method,
        ...context
      });

      contextLogger.info('Make.com API call started', {
        endpoint,
        method
      });

      try {
        const result = await execution();
        const duration = timer();
        
        metrics.recordMakeApiCall(endpoint, method, 'success', duration);

        contextLogger.info('Make.com API call completed', {
          endpoint,
          method,
          duration: `${duration.toFixed(3)}s`
        });

        return result;

      } catch (error) {
        const duration = timer();
        const errorType = this.classifyError(error);
        
        metrics.recordMakeApiCall(endpoint, method, 'error', duration);
        metrics.recordError(errorType, 'make_api_call', endpoint);

        contextLogger.error('Make.com API call failed', {
          endpoint,
          method,
          duration: `${duration.toFixed(3)}s`,
          error: error instanceof Error ? error.message : String(error),
          errorType
        });

        throw error;
      }
    };
  }

  /**
   * Get current monitoring statistics
   */
  public getMonitoringStats(): {
    activeConnections: number;
    activeToolExecutions: number;
    metricsHealth: Promise<{ healthy: boolean; metricsCount: number }>;
  } {
    return {
      activeConnections: this.activeConnections,
      activeToolExecutions: this.toolExecutions.size,
      metricsHealth: metrics.healthCheck()
    };
  }

  /**
   * Get detailed tool execution metrics
   */
  public getToolExecutionMetrics(): Array<{
    executionId: string;
    startTime: number;
    duration?: number;
    status?: string;
  }> {
    return Array.from(this.toolExecutions.entries()).map(([id, metrics]) => ({
      executionId: id,
      startTime: metrics.startTime,
      duration: metrics.duration,
      status: metrics.status
    }));
  }

  /**
   * Extract session ID from session object
   */
  private extractSessionId(session: unknown): string {
    if (session && typeof session === 'object' && 'id' in session) {
      return String((session as { id: unknown }).id);
    }
    return 'unknown';
  }

  /**
   * Classify error types for metrics
   */
  private classifyError(error: unknown): string {
    if (error instanceof Error) {
      // Check for specific error types
      if (error.name === 'AuthenticationError') return 'authentication';
      if (error.name === 'UserError') return 'user_error';
      if (error.name === 'MakeServerError') return 'make_server_error';
      if (error.message.includes('timeout')) return 'timeout';
      if (error.message.includes('network')) return 'network';
      if (error.message.includes('rate limit')) return 'rate_limit';
      if (error.message.includes('permission')) return 'permission';
      
      return 'generic_error';
    }
    
    return 'unknown_error';
  }

  /**
   * Health check for monitoring system
   */
  public async healthCheck(): Promise<{
    healthy: boolean;
    activeConnections: number;
    activeToolExecutions: number;
    metricsSystem: { healthy: boolean; metricsCount: number };
  }> {
    try {
      const metricsHealth = await metrics.healthCheck();
      
      return {
        healthy: metricsHealth.healthy,
        activeConnections: this.activeConnections,
        activeToolExecutions: this.toolExecutions.size,
        metricsSystem: metricsHealth
      };
    } catch (error) {
      this.componentLogger.error('Monitoring health check failed', {
        error: error instanceof Error ? error.message : String(error)
      });
      
      return {
        healthy: false,
        activeConnections: this.activeConnections,
        activeToolExecutions: this.toolExecutions.size,
        metricsSystem: { healthy: false, metricsCount: 0 }
      };
    }
  }

  /**
   * Shutdown monitoring system
   */
  public shutdown(): void {
    this.componentLogger.info('Shutting down monitoring middleware');
    this.toolExecutions.clear();
    this.activeConnections = 0;
    metrics.setActiveConnections(0);
  }
}

// Create and export singleton instance
export const monitoring = new MonitoringMiddleware();
export default monitoring;