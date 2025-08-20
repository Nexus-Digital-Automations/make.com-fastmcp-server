/**
 * Error Handling Integration Example for Make.com FastMCP Server
 * Demonstrates comprehensive error handling with correlation IDs, recovery, and analytics
 */

import { MakeServerError, UserError, createValidationError, createExternalServiceError } from '../utils/errors.js';
import { extractCorrelationId, createToolErrorResponse } from '../utils/error-response.js';
import { retryWithBackoff, CircuitBreakerFactory, BulkheadFactory } from '../utils/error-recovery.js';
import { errorAnalytics, monitorPerformance } from '../utils/error-analytics.js';
import logger from '../lib/logger.js';

/**
 * Example: Make.com API Client with comprehensive error handling
 */
export class EnhancedMakeApiClient {
  private circuitBreaker = CircuitBreakerFactory.getOrCreate('make-api', {
    failureThreshold: 5,
    resetTimeout: 60000,
  });

  private bulkhead = BulkheadFactory.getOrCreate('make-api-requests', 10, 50);
  private componentLogger = logger.child({ component: 'EnhancedMakeApiClient' });

  /**
   * Enhanced API request with full error handling
   */
  @monitorPerformance
  async makeRequest<T>(
    endpoint: string,
    options: {
      method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
      data?: unknown;
      timeout?: number;
      correlationId?: string;
    } = {}
  ): Promise<T> {
    const correlationId = options.correlationId || extractCorrelationId({});
    const operationLogger = this.componentLogger.child({
      correlationId,
      operation: 'makeRequest',
      endpoint,
    });

    operationLogger.info('Starting API request', {
      method: options.method || 'GET',
      endpoint,
    });

    try {
      // Use bulkhead for request isolation
      const result = await this.bulkhead.execute(async () => {
        // Use circuit breaker for failure protection
        return await this.circuitBreaker.execute(async () => {
          // Use retry with backoff for resilience
          return await retryWithBackoff(
            async () => {
              return await this.performActualRequest<T>(endpoint, options);
            },
            {
              maxRetries: 3,
              baseDelay: 1000,
              onRetry: (error, attempt) => {
                operationLogger.warn('Retrying API request', {
                  attempt,
                  error: error.message,
                  endpoint,
                });
              },
            },
            correlationId
          );
        }, correlationId);
      }, correlationId);

      operationLogger.info('API request completed successfully', {
        endpoint,
        hasData: !!result,
      });

      return result;
    } catch (error) {
      const enhancedError = this.enhanceError(error as Error, {
        endpoint,
        correlationId,
        operation: 'makeRequest',
      });

      // Record error for analytics
      errorAnalytics.recordError(enhancedError, {
        component: 'EnhancedMakeApiClient',
        operation: 'makeRequest',
        correlationId,
      });

      operationLogger.error('API request failed', {
        endpoint,
        errorCode: enhancedError instanceof MakeServerError ? enhancedError.code : 'UNKNOWN_ERROR',
        correlationId: enhancedError instanceof MakeServerError ? enhancedError.correlationId : correlationId,
      });

      throw enhancedError;
    }
  }

  /**
   * Simulated actual API request (replace with real implementation)
   */
  private async performActualRequest<T>(
    endpoint: string
  ): Promise<T> {
    // Simulate network request
    await new Promise(resolve => setTimeout(resolve, Math.random() * 1000));

    // Simulate occasional failures for demonstration
    if (Math.random() < 0.1) {
      throw new Error('Network timeout');
    }

    if (Math.random() < 0.05) {
      throw new Error('Service unavailable');
    }

    // Return mock successful response
    return { success: true, data: `Response from ${endpoint}` } as T;
  }

  /**
   * Enhance errors with additional context and correlation IDs
   */
  private enhanceError(
    error: Error,
    context: {
      endpoint: string;
      correlationId: string;
      operation: string;
    }
  ): UserError | MakeServerError {
    if (error instanceof MakeServerError || error instanceof UserError) {
      return error;
    }

    // Map common error types to appropriate UserError types
    if (error.message.includes('timeout')) {
      return createExternalServiceError(
        'Make.com API',
        'Request timeout occurred',
        error,
        {
          endpoint: context.endpoint,
          originalError: error.message,
        },
        {
          correlationId: context.correlationId,
          operation: context.operation,
          component: 'EnhancedMakeApiClient',
        }
      );
    }

    if (error.message.includes('unavailable')) {
      return createExternalServiceError(
        'Make.com API',
        'Service temporarily unavailable',
        error,
        {
          endpoint: context.endpoint,
          originalError: error.message,
        },
        {
          correlationId: context.correlationId,
          operation: context.operation,
          component: 'EnhancedMakeApiClient',
        }
      );
    }

    // Default to generic external service error
    return createExternalServiceError(
      'Make.com API',
      `API request failed: ${error.message}`,
      error,
      {
        endpoint: context.endpoint,
        originalError: error.message,
      },
      {
        correlationId: context.correlationId,
        operation: context.operation,
        component: 'EnhancedMakeApiClient',
      }
    );
  }
}

/**
 * Example: Enhanced Tool Implementation with Error Handling
 */
export function createEnhancedTool(apiClient: EnhancedMakeApiClient): {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
  execute: (args: Record<string, unknown>, context: Record<string, unknown>) => Promise<string>;
} {
  return {
    name: 'enhanced-make-request',
    description: 'Make API request with comprehensive error handling',
    parameters: {
      type: 'object',
      properties: {
        endpoint: { type: 'string', description: 'API endpoint to call' },
        method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'DELETE'], default: 'GET' },
        data: { type: 'object', description: 'Request payload' },
      },
      required: ['endpoint'],
    },
    execute: async (args: {
      endpoint: string;
      method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
      data?: unknown;
    }, context: {
      session?: Record<string, unknown>;
      log: {
        info: (message: string, data?: Record<string, unknown>) => void;
        error: (message: string, data?: Record<string, unknown>) => void;
      };
    }): Promise<string> => {
      const correlationId = extractCorrelationId({ session: context.session });
      const operationLogger = logger.child({
        component: 'EnhancedTool',
        operation: 'enhanced-make-request',
        correlationId,
      });

      try {
        // Validate input parameters
        if (!args.endpoint || typeof args.endpoint !== 'string') {
          throw createValidationError(
            'Invalid endpoint parameter',
            {
              field: 'endpoint',
              value: args.endpoint,
              expected: 'non-empty string',
            },
            {
              correlationId,
              operation: 'enhanced-make-request',
              component: 'EnhancedTool',
            }
          );
        }

        operationLogger.info('Executing enhanced Make.com API request', {
          endpoint: args.endpoint,
          method: args.method || 'GET',
        });

        context.log.info('Starting API request with error handling', {
          endpoint: args.endpoint,
          correlationId,
        });

        // Make the API request with comprehensive error handling
        const result = await apiClient.makeRequest(args.endpoint, {
          method: args.method,
          data: args.data,
          correlationId,
        });

        operationLogger.info('Tool execution completed successfully', {
          endpoint: args.endpoint,
          correlationId,
        });

        context.log.info('API request completed successfully', {
          endpoint: args.endpoint,
          correlationId,
        });

        // Return success response with proper formatting
        return JSON.stringify({
          success: true,
          data: result,
          correlationId,
          timestamp: new Date().toISOString(),
        }, null, 2);

      } catch (error) {
        operationLogger.error('Tool execution failed', {
          endpoint: args.endpoint,
          error: error instanceof Error ? error.message : String(error),
          correlationId,
        });

        context.log.error('API request failed', {
          endpoint: args.endpoint,
          error: error instanceof Error ? error.message : String(error),
          correlationId,
        });

        // Return formatted error response
        return createToolErrorResponse(
          error as Error,
          'enhanced-make-request',
          correlationId
        );
      }
    },
  };
}

/**
 * Example: Error Analytics Dashboard Data
 */
export function getErrorAnalyticsDashboard(): {
  metrics: ReturnType<typeof errorAnalytics.getErrorMetrics>;
  performance: ReturnType<typeof errorAnalytics.getPerformanceMetrics>;
  trends: ReturnType<typeof errorAnalytics.getErrorTrends>;
  patterns: ReturnType<typeof errorAnalytics.getTopErrorPatterns>;
  circuitBreakers: Record<string, unknown>;
  bulkheads: Record<string, unknown>;
} {
  return {
    metrics: errorAnalytics.getErrorMetrics(),
    performance: errorAnalytics.getPerformanceMetrics(),
    trends: errorAnalytics.getErrorTrends(24), // Last 24 hours
    patterns: errorAnalytics.getTopErrorPatterns(10),
    circuitBreakers: CircuitBreakerFactory.getAllStats(),
    bulkheads: BulkheadFactory.getAllStats(),
  };
}

/**
 * Example: Health Check with Error Handling Integration
 */
export async function performEnhancedHealthCheck(): Promise<{
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  services: Record<string, {
    status: 'healthy' | 'degraded' | 'unhealthy';
    responseTime?: number;
    error?: string;
  }>;
  analytics: ReturnType<typeof getErrorAnalyticsDashboard>;
}> {
  const correlationId = extractCorrelationId({});
  const healthLogger = logger.child({
    component: 'HealthCheck',
    operation: 'enhanced-health-check',
    correlationId,
  });

  const services: Record<string, {
    status: 'healthy' | 'degraded' | 'unhealthy';
    responseTime?: number;
    error?: string;
  }> = {};

  const apiClient = new EnhancedMakeApiClient();

  // Check API connectivity
  try {
    const startTime = Date.now();
    await apiClient.makeRequest('/health', { correlationId });
    const responseTime = Date.now() - startTime;
    
    services.makeApi = {
      status: responseTime > 5000 ? 'degraded' : 'healthy',
      responseTime,
    };
  } catch (error) {
    services.makeApi = {
      status: 'unhealthy',
      error: error instanceof Error ? error.message : String(error),
    };
  }

  // Check circuit breaker states
  const circuitBreakers = CircuitBreakerFactory.getAllStats();
  const hasOpenCircuits = Object.values(circuitBreakers).some(
    (stats) => stats.state === 'OPEN'
  );

  services.circuitBreakers = {
    status: hasOpenCircuits ? 'degraded' : 'healthy',
  };

  // Determine overall status
  const serviceStatuses = Object.values(services).map(s => s.status);
  const overallStatus = serviceStatuses.includes('unhealthy') 
    ? 'unhealthy' 
    : serviceStatuses.includes('degraded') 
    ? 'degraded' 
    : 'healthy';

  healthLogger.info('Health check completed', {
    overallStatus,
    serviceCount: Object.keys(services).length,
    correlationId,
  });

  return {
    status: overallStatus,
    timestamp: new Date().toISOString(),
    services,
    analytics: getErrorAnalyticsDashboard(),
  };
}

/**
 * Example usage demonstration
 */
export async function demonstrateErrorHandling(): Promise<void> {
  const correlationId = extractCorrelationId({});
  const demoLogger = logger.child({
    component: 'ErrorHandlingDemo',
    correlationId,
  });

  demoLogger.info('Starting error handling demonstration');

  try {
    const apiClient = new EnhancedMakeApiClient();
    
    // Successful request
    const result1 = await apiClient.makeRequest('/scenarios', {
      method: 'GET',
      correlationId,
    });
    demoLogger.info('Successful request completed', { result: !!result1 });

    // Request that will likely fail and trigger retry/circuit breaker
    try {
      await apiClient.makeRequest('/failing-endpoint', {
        method: 'POST',
        data: { test: 'data' },
        correlationId,
      });
    } catch (error) {
      demoLogger.info('Expected failure handled gracefully', {
        error: error instanceof Error ? error.message : String(error),
      });
    }

    // Get analytics after some operations
    const analytics = getErrorAnalyticsDashboard();
    demoLogger.info('Analytics collected', {
      totalErrors: analytics.metrics.totalErrors,
      errorRate: analytics.metrics.errorRate,
    });

  } catch (error) {
    demoLogger.error('Demonstration failed', {
      error: error instanceof Error ? error.message : String(error),
    });
  }

  demoLogger.info('Error handling demonstration completed');
}