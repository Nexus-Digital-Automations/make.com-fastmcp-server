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
  traceId?: string;
  spanId?: string;
  [key: string]: unknown; // Allow additional context fields
}

export interface ToolMetrics {
  startTime: number;
  endTime?: number;
  duration?: number;
  status?: 'success' | 'error' | 'timeout';
  errorType?: string;
}

class MonitoringMiddleware {
  private readonly componentLogger: ReturnType<typeof logger.child>;
  private activeConnections: number = 0;
  private readonly toolExecutions: Map<string, ToolMetrics> = new Map();

  constructor() {
    // Robust logger initialization for both production and test environments
    try {
      if (logger && typeof logger.child === 'function') {
        this.componentLogger = logger.child({ component: 'MonitoringMiddleware' });
      } else {
        // Fallback for test environments when logger.child is not available
        this.componentLogger = logger;
      }
    } catch (error) {
      // Ultimate fallback for test environments
      // Use stderr for logger initialization failures to avoid interfering with application output
      process.stderr.write(`MonitoringMiddleware logger initialization failed, using fallback: ${error}\n`);
      this.componentLogger = this.createFallbackLogger();
    }

    // Additional safety check for test environments
    if (!this.componentLogger || typeof this.componentLogger.info !== 'function') {
      this.componentLogger = this.createFallbackLogger();
    }
  }

  /**
   * Create a fallback logger that's compatible with the Logger interface
   */
  private createFallbackLogger(): ReturnType<typeof logger.child> {
    const fallbackLogger = {
      info: (..._args: unknown[]): void => {},
      debug: (..._args: unknown[]): void => {},
      warn: (..._args: unknown[]): void => {},
      error: (..._args: unknown[]): void => {},
      child: (): typeof fallbackLogger => fallbackLogger,
      // Add required Logger properties to match the interface
      logLevel: 'info' as const,
      logLevels: { debug: 0, info: 1, warn: 2, error: 3 },
      shouldLog: (): boolean => true,
      formatLogEntry: (): string => '',
      log: (): void => {},
      logWithCorrelation: (): string => 'fallback_correlation_id',
      logDuration: (): void => {},
      setLogLevel: (): void => {},
      getLogLevel: (): 'info' => 'info' as const,
      generateCorrelationId: (): string => 'fallback_correlation_id',
      generateTraceId: (): string => 'fallback_trace_id',
      generateSpanId: (): string => 'fallback_span_id',
      generateRequestId: (): string => 'fallback_request_id'
    };
    return fallbackLogger as unknown as ReturnType<typeof logger.child>;
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
   * Enhanced to work with FastMCP UserError patterns
   */
  private classifyError(error: unknown): string {
    if (error instanceof Error) {
      // Check for specific error types by name
      if (error.name === 'AuthenticationError') {return 'authentication';}
      if (error.name === 'UserError') {return 'user_error';}
      if (error.name === 'MakeServerError') {return 'make_server_error';}
      
      // Check for UserError with embedded error codes
      if (error.name === 'UserError' && error.message.includes('[AUTHENTICATION_ERROR:')) {return 'authentication';}
      if (error.name === 'UserError' && error.message.includes('[VALIDATION_ERROR:')) {return 'validation';}
      if (error.name === 'UserError' && error.message.includes('[NOT_FOUND:')) {return 'not_found';}
      if (error.name === 'UserError' && error.message.includes('[RATE_LIMIT:')) {return 'rate_limit';}
      if (error.name === 'UserError' && error.message.includes('[TIMEOUT:')) {return 'timeout';}
      if (error.name === 'UserError' && error.message.includes('[EXTERNAL_SERVICE_ERROR:')) {return 'external_service';}
      
      // Fallback to message content analysis
      if (error.message.includes('timeout')) {return 'timeout';}
      if (error.message.includes('network')) {return 'network';}
      if (error.message.includes('rate limit')) {return 'rate_limit';}
      if (error.message.includes('permission')) {return 'permission';}
      if (error.message.includes('authentication')) {return 'authentication';}
      if (error.message.includes('validation')) {return 'validation';}
      
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
    
    try {
      this.toolExecutions.clear();
      this.activeConnections = 0;
      metrics.setActiveConnections(0);
    } catch (error) {
      this.componentLogger.error('Error during monitoring middleware shutdown', {
        error: error instanceof Error ? error.message : String(error)
      });
      // Continue shutdown process despite errors
    }
  }
}

// Export class for direct instantiation
export { MonitoringMiddleware };

// Lazy singleton pattern to avoid constructor issues in tests
let monitoringInstance: MonitoringMiddleware | null = null;

export function getMonitoringInstance(): MonitoringMiddleware {
  if (!monitoringInstance) {
    try {
      monitoringInstance = new MonitoringMiddleware();
    } catch (error) {
      // Use stderr for critical initialization errors
      process.stderr.write(`Failed to create MonitoringMiddleware instance: ${error}\n`);
      throw error;
    }
  }
  return monitoringInstance;
}

/**
 * Reset the monitoring singleton - for testing purposes only
 * @internal
 */
export function resetMonitoringInstance(): void {
  if (monitoringInstance) {
    try {
      monitoringInstance.shutdown();
    } catch (error) {
      // Use stderr for shutdown errors to avoid interfering with application output
      process.stderr.write(`Error during monitoring middleware shutdown: ${error}\n`);
    }
    monitoringInstance = null;
  }
}

// Create and export singleton instance
export const monitoring = getMonitoringInstance();
export default monitoring;