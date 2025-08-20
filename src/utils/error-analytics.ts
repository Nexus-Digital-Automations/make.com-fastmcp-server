/**
 * Error analytics and monitoring integration for Make.com FastMCP Server
 * Provides error tracking, metrics collection, and performance monitoring
 */

import { randomUUID } from 'crypto';
import { MakeServerError, ErrorContext, UserError, EnhancedUserError, getErrorCode, getErrorStatusCode, getErrorCorrelationId } from './errors.js';
import logger from '../lib/logger.js';

export interface ErrorMetrics {
  totalErrors: number;
  errorsByCode: Record<string, number>;
  errorsByComponent: Record<string, number>;
  errorsByStatusCode: Record<string, number>;
  recentErrors: ErrorEvent[];
  averageResponseTime: number;
  errorRate: number;
  uptime: number;
}

export interface ErrorEvent {
  id: string;
  timestamp: string;
  correlationId: string;
  code: string;
  message: string;
  statusCode: number;
  component?: string;
  operation?: string;
  userId?: string;
  sessionId?: string;
  duration?: number;
  context?: ErrorContext;
  resolved?: boolean;
  resolvedAt?: string;
}

export interface PerformanceMetrics {
  averageResponseTime: number;
  p95ResponseTime: number;
  p99ResponseTime: number;
  throughput: number;
  concurrentRequests: number;
  memoryUsage: NodeJS.MemoryUsage;
  cpuUsage: NodeJS.CpuUsage;
}

/**
 * Error Analytics and Monitoring Service
 */
export class ErrorAnalytics {
  private static instance: ErrorAnalytics;
  private errors: ErrorEvent[] = [];
  private performanceData: Array<{ timestamp: number; duration: number }> = [];
  private readonly maxEvents = 1000;
  private readonly componentLogger: ReturnType<typeof logger.child>;
  private startTime = Date.now();

  private constructor() {
    this.componentLogger = logger.child({
      component: 'ErrorAnalytics',
    });

    // Clean up old events periodically
    setInterval(() => {
      this.cleanupOldEvents();
    }, 300000); // 5 minutes
  }

  public static getInstance(): ErrorAnalytics {
    if (!ErrorAnalytics.instance) {
      ErrorAnalytics.instance = new ErrorAnalytics();
    }
    return ErrorAnalytics.instance;
  }

  /**
   * Record an error event
   * Now supports FastMCP UserError and maintains backward compatibility
   */
  public recordError(
    error: Error | MakeServerError | UserError,
    context?: {
      component?: string;
      operation?: string;
      userId?: string;
      sessionId?: string;
      duration?: number;
      correlationId?: string;
    }
  ): void {
    const correlationId = context?.correlationId || getErrorCorrelationId(error) || randomUUID();
    const code = getErrorCode(error);
    const statusCode = getErrorStatusCode(error);
    
    // Get context from error if available
    let errorContext: ErrorContext | undefined;
    if (error instanceof MakeServerError) {
      errorContext = error.context;
    } else if (error instanceof UserError && 'context' in error) {
      errorContext = (error as EnhancedUserError).context;
    }

    const errorEvent: ErrorEvent = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      correlationId,
      code,
      message: error.message,
      statusCode,
      component: context?.component,
      operation: context?.operation,
      userId: context?.userId,
      sessionId: context?.sessionId,
      duration: context?.duration,
      context: errorContext,
      resolved: false,
    };

    this.errors.push(errorEvent);

    // Keep only the most recent events
    if (this.errors.length > this.maxEvents) {
      this.errors = this.errors.slice(-this.maxEvents);
    }

    this.componentLogger.info('Error event recorded', {
      errorId: errorEvent.id,
      correlationId: errorEvent.correlationId,
      code: errorEvent.code,
      component: errorEvent.component,
    });
  }

  /**
   * Record performance data
   */
  public recordPerformance(duration: number): void {
    this.performanceData.push({
      timestamp: Date.now(),
      duration,
    });

    // Keep only recent performance data (last hour)
    const oneHourAgo = Date.now() - 3600000;
    this.performanceData = this.performanceData.filter(
      (data) => data.timestamp > oneHourAgo
    );
  }

  /**
   * Mark an error as resolved
   */
  public resolveError(errorId: string): void {
    const error = this.errors.find((e) => e.id === errorId);
    if (error && !error.resolved) {
      error.resolved = true;
      error.resolvedAt = new Date().toISOString();

      this.componentLogger.info('Error marked as resolved', {
        errorId,
        correlationId: error.correlationId,
        code: error.code,
      });
    }
  }

  /**
   * Get comprehensive error metrics
   */
  public getErrorMetrics(): ErrorMetrics {
    const now = Date.now();
    const oneHourAgo = now - 3600000;
    const recentErrors = this.errors.filter(
      (error) => new Date(error.timestamp).getTime() > oneHourAgo
    );

    // Calculate error counts by different dimensions
    const errorsByCode: Record<string, number> = {};
    const errorsByComponent: Record<string, number> = {};
    const errorsByStatusCode: Record<string, number> = {};

    recentErrors.forEach((error) => {
      errorsByCode[error.code] = (errorsByCode[error.code] || 0) + 1;
      
      if (error.component) {
        errorsByComponent[error.component] = 
          (errorsByComponent[error.component] || 0) + 1;
      }
      
      errorsByStatusCode[error.statusCode.toString()] = 
        (errorsByStatusCode[error.statusCode.toString()] || 0) + 1;
    });

    // Calculate average response time from performance data
    const recentPerformanceData = this.performanceData.filter(
      (data) => data.timestamp > oneHourAgo
    );
    
    const averageResponseTime = recentPerformanceData.length > 0
      ? recentPerformanceData.reduce((sum, data) => sum + data.duration, 0) / 
        recentPerformanceData.length
      : 0;

    // Calculate error rate (errors per minute)
    const errorRate = recentErrors.length / 60;

    // Calculate uptime
    const uptime = (now - this.startTime) / 1000;

    return {
      totalErrors: this.errors.length,
      errorsByCode,
      errorsByComponent,
      errorsByStatusCode,
      recentErrors: recentErrors.slice(-50), // Last 50 recent errors
      averageResponseTime,
      errorRate,
      uptime,
    };
  }

  /**
   * Get performance metrics
   */
  public getPerformanceMetrics(): PerformanceMetrics {
    const oneHourAgo = Date.now() - 3600000;
    const recentData = this.performanceData.filter(
      (data) => data.timestamp > oneHourAgo
    );

    if (recentData.length === 0) {
      return {
        averageResponseTime: 0,
        p95ResponseTime: 0,
        p99ResponseTime: 0,
        throughput: 0,
        concurrentRequests: 0,
        memoryUsage: process.memoryUsage(),
        cpuUsage: process.cpuUsage(),
      };
    }

    // Sort durations for percentile calculations
    const sortedDurations = recentData
      .map((data) => data.duration)
      .sort((a, b) => a - b);

    const averageResponseTime = 
      sortedDurations.reduce((sum, duration) => sum + duration, 0) / 
      sortedDurations.length;

    const p95Index = Math.floor(sortedDurations.length * 0.95);
    const p99Index = Math.floor(sortedDurations.length * 0.99);

    const p95ResponseTime = sortedDurations[p95Index] || 0;
    const p99ResponseTime = sortedDurations[p99Index] || 0;

    // Calculate throughput (requests per second)
    const throughput = recentData.length / 3600; // per hour, convert to per second

    return {
      averageResponseTime,
      p95ResponseTime,
      p99ResponseTime,
      throughput,
      concurrentRequests: 0, // This would need to be tracked separately
      memoryUsage: process.memoryUsage(),
      cpuUsage: process.cpuUsage(),
    };
  }

  /**
   * Get error trends over time
   */
  public getErrorTrends(timeRangeHours = 24): Array<{
    hour: string;
    errorCount: number;
    errorRate: number;
  }> {
    const now = Date.now();
    const timeRangeMs = timeRangeHours * 3600000;
    const startTime = now - timeRangeMs;

    const relevantErrors = this.errors.filter(
      (error) => new Date(error.timestamp).getTime() > startTime
    );

    // Group errors by hour
    const errorsByHour: Record<string, number> = {};
    
    relevantErrors.forEach((error) => {
      const errorTime = new Date(error.timestamp);
      const hourKey = errorTime.toISOString().substring(0, 13) + ':00:00.000Z';
      errorsByHour[hourKey] = (errorsByHour[hourKey] || 0) + 1;
    });

    // Create time series data
    const trends: Array<{ hour: string; errorCount: number; errorRate: number }> = [];
    
    for (let i = 0; i < timeRangeHours; i++) {
      const hourTime = new Date(startTime + (i * 3600000));
      const hourKey = hourTime.toISOString().substring(0, 13) + ':00:00.000Z';
      const errorCount = errorsByHour[hourKey] || 0;
      const errorRate = errorCount / 60; // errors per minute

      trends.push({
        hour: hourKey,
        errorCount,
        errorRate,
      });
    }

    return trends;
  }

  /**
   * Get top error patterns
   */
  public getTopErrorPatterns(limit = 10): Array<{
    pattern: string;
    count: number;
    percentage: number;
    lastOccurrence: string;
    components: string[];
  }> {
    const patterns: Record<string, {
      count: number;
      lastOccurrence: string;
      components: Set<string>;
    }> = {};

    this.errors.forEach((error) => {
      const pattern = `${error.code}: ${error.message}`;
      
      if (!patterns[pattern]) {
        patterns[pattern] = {
          count: 0,
          lastOccurrence: error.timestamp,
          components: new Set(),
        };
      }

      patterns[pattern].count++;
      patterns[pattern].lastOccurrence = error.timestamp;
      
      if (error.component) {
        patterns[pattern].components.add(error.component);
      }
    });

    const totalErrors = this.errors.length;
    
    return Object.entries(patterns)
      .map(([pattern, data]) => ({
        pattern,
        count: data.count,
        percentage: totalErrors > 0 ? (data.count / totalErrors) * 100 : 0,
        lastOccurrence: data.lastOccurrence,
        components: Array.from(data.components),
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, limit);
  }

  /**
   * Export analytics data for external monitoring systems
   */
  public exportAnalytics(): {
    timestamp: string;
    metrics: ErrorMetrics;
    performance: PerformanceMetrics;
    trends: ReturnType<ErrorAnalytics['getErrorTrends']>;
    patterns: ReturnType<ErrorAnalytics['getTopErrorPatterns']>;
  } {
    return {
      timestamp: new Date().toISOString(),
      metrics: this.getErrorMetrics(),
      performance: this.getPerformanceMetrics(),
      trends: this.getErrorTrends(),
      patterns: this.getTopErrorPatterns(),
    };
  }

  /**
   * Clean up old events to prevent memory leaks
   */
  private cleanupOldEvents(): void {
    const oneDayAgo = Date.now() - 86400000; // 24 hours
    const initialCount = this.errors.length;
    
    this.errors = this.errors.filter(
      (error) => new Date(error.timestamp).getTime() > oneDayAgo
    );

    const removedCount = initialCount - this.errors.length;
    
    if (removedCount > 0) {
      this.componentLogger.info('Cleaned up old error events', {
        removedCount,
        remainingCount: this.errors.length,
      });
    }
  }

  /**
   * Reset all analytics data (useful for testing)
   */
  public reset(): void {
    this.errors = [];
    this.performanceData = [];
    this.startTime = Date.now();
    
    this.componentLogger.info('Analytics data reset');
  }
}

/**
 * Global error analytics instance
 */
export const errorAnalytics = ErrorAnalytics.getInstance();

/**
 * Middleware for automatic error recording
 */
export function createErrorAnalyticsMiddleware() {
  return (error: Error, context?: {
    component?: string;
    operation?: string;
    userId?: string;
    sessionId?: string;
    duration?: number;
    correlationId?: string;
  }): void => {
    errorAnalytics.recordError(error, context);
  };
}

/**
 * Performance monitoring decorator
 */
export function monitorPerformance<T extends (...args: unknown[]) => Promise<unknown>>(
  fn: T,
  context?: {
    component?: string;
    operation?: string;
  }
): T {
  return (async (...args: Parameters<T>) => {
    const startTime = Date.now();
    
    try {
      const result = await fn(...args);
      const duration = Date.now() - startTime;
      
      errorAnalytics.recordPerformance(duration);
      
      return result;
    } catch (error) {
      const duration = Date.now() - startTime;
      
      errorAnalytics.recordError(error as Error, {
        ...context,
        duration,
      });
      
      throw error;
    }
  }) as T;
}