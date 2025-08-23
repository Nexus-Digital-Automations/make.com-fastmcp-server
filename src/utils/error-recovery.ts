/**
 * Error recovery mechanisms and retry logic for Make.com FastMCP Server
 * Implements circuit breaker patterns, exponential backoff, and resilience strategies
 */

import { randomUUID } from 'crypto';
import { MakeServerError, UserError, createExternalServiceError, createTimeoutError, getErrorStatusCode, getErrorCode } from './errors.js';
import logger from '../lib/logger.js';

export interface RetryOptions {
  maxRetries?: number;
  baseDelay?: number;
  maxDelay?: number;
  exponentialBase?: number;
  jitter?: boolean;
  retryCondition?: (error: Error) => boolean;
  onRetry?: (error: Error, attempt: number) => void;
}

export interface CircuitBreakerOptions {
  failureThreshold?: number;
  successThreshold?: number;
  timeout?: number;
  resetTimeout?: number;
  onStateChange?: (state: CircuitBreakerState) => void;
}

export type CircuitBreakerState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

/**
 * Circuit Breaker implementation for external service calls
 */
export class CircuitBreaker {
  private state: CircuitBreakerState = 'CLOSED';
  private failureCount = 0;
  private successCount = 0;
  private nextAttempt = 0;
  private readonly options: Required<CircuitBreakerOptions>;
  private readonly componentLogger: ReturnType<typeof logger.child>;

  constructor(
    private readonly name: string,
    options: CircuitBreakerOptions = {}
  ) {
    this.options = {
      failureThreshold: options.failureThreshold ?? 5,
      successThreshold: options.successThreshold ?? 3,
      timeout: options.timeout ?? 30000,
      resetTimeout: options.resetTimeout ?? 60000,
      onStateChange: options.onStateChange ?? ((): void => {}),
    };

    this.componentLogger = logger.child({
      component: 'CircuitBreaker',
      circuitName: name,
    });
  }

  async execute<T>(
    operation: () => Promise<T>,
    correlationId?: string
  ): Promise<T> {
    const operationLogger = this.componentLogger.child({
      correlationId: correlationId || randomUUID(),
      operation: 'circuit-breaker-execute',
    });

    if (this.state === 'OPEN') {
      if (Date.now() < this.nextAttempt) {
        const error = createExternalServiceError(
          this.name,
          'Circuit breaker is OPEN - requests blocked',
          undefined,
          {
            circuitState: this.state,
            nextAttempt: new Date(this.nextAttempt).toISOString(),
            failureCount: this.failureCount,
          },
          {
            correlationId,
            component: 'CircuitBreaker',
            operation: 'circuit-breaker-execute',
          }
        );

        operationLogger.warn('Circuit breaker blocking request', {
          state: this.state,
          nextAttempt: new Date(this.nextAttempt).toISOString(),
        });

        throw error;
      } else {
        this.setState('HALF_OPEN');
        operationLogger.info('Circuit breaker transitioning to HALF_OPEN');
      }
    }

    try {
      const startTime = Date.now();
      const result = await Promise.race([
        operation(),
        this.createTimeoutPromise<T>(),
      ]);
      
      const duration = Date.now() - startTime;
      this.onSuccess();
      
      operationLogger.info('Circuit breaker operation succeeded', {
        duration,
        state: this.state,
      });

      return result;
    } catch (error) {
      this.onFailure();
      
      operationLogger.error('Circuit breaker operation failed', {
        error: error instanceof Error ? error.message : String(error),
        state: this.state,
        failureCount: this.failureCount,
      });

      throw error;
    }
  }

  private createTimeoutPromise<T>(): Promise<T> {
    return new Promise((_, reject) => {
      setTimeout(() => {
        reject(createTimeoutError(
          `Circuit breaker operation for ${this.name}`,
          this.options.timeout
        ));
      }, this.options.timeout);
    });
  }

  private onSuccess(): void {
    this.failureCount = 0;
    
    if (this.state === 'HALF_OPEN') {
      this.successCount++;
      if (this.successCount >= this.options.successThreshold) {
        this.setState('CLOSED');
        this.successCount = 0;
      }
    }
  }

  private onFailure(): void {
    this.failureCount++;
    this.successCount = 0;

    if (this.failureCount >= this.options.failureThreshold) {
      this.setState('OPEN');
      this.nextAttempt = Date.now() + this.options.resetTimeout;
    }
  }

  private setState(newState: CircuitBreakerState): void {
    const oldState = this.state;
    this.state = newState;
    
    this.componentLogger.info('Circuit breaker state changed', {
      oldState,
      newState,
      failureCount: this.failureCount,
      successCount: this.successCount,
    });

    this.options.onStateChange(newState);
  }

  public getState(): CircuitBreakerState {
    return this.state;
  }

  public getStats(): {
    state: CircuitBreakerState;
    failureCount: number;
    successCount: number;
    nextAttempt: number;
  } {
    return {
      state: this.state,
      failureCount: this.failureCount,
      successCount: this.successCount,
      nextAttempt: this.nextAttempt,
    };
  }
}

/**
 * Retry mechanism with exponential backoff and jitter
 */
export async function retryWithBackoff<T>(
  operation: () => Promise<T>,
  options: RetryOptions = {},
  correlationId?: string
): Promise<T> {
  const {
    maxRetries = 3,
    baseDelay = 1000,
    maxDelay = 30000,
    exponentialBase = 2,
    jitter = true,
    retryCondition = defaultRetryCondition,
    onRetry,
  } = options;

  const getOperationLogger = () => {
    try {
      return logger.child({
        component: 'RetryMechanism',
        correlationId: correlationId || randomUUID(),
        operation: 'retry-with-backoff',
      });
    } catch (error) {
      // Fallback for test environments
      return logger as any;
    }
  };
  const operationLogger = getOperationLogger();

  let lastError: Error = new Error('No attempts made');
  
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const result = await operation();
      
      if (attempt > 0) {
        operationLogger.info('Operation succeeded after retries', {
          attempt,
          totalAttempts: attempt + 1,
        });
      }
      
      return result;
    } catch (error) {
      lastError = error as Error;
      
      operationLogger.warn('Operation failed, evaluating retry', {
        attempt,
        error: lastError.message,
        isLastAttempt: attempt === maxRetries,
      });

      // Don't retry on the last attempt or if retry condition is not met
      if (attempt === maxRetries || !retryCondition(lastError)) {
        break;
      }

      // Calculate delay with exponential backoff and optional jitter
      const delay = Math.min(
        baseDelay * Math.pow(exponentialBase, attempt),
        maxDelay
      );
      
      const finalDelay = jitter 
        ? delay + Math.random() * 1000 
        : delay;

      operationLogger.info('Retrying operation after delay', {
        attempt: attempt + 1,
        delay: finalDelay,
        nextAttempt: attempt + 1,
      });

      // Call retry callback if provided
      if (onRetry) {
        try {
          onRetry(lastError, attempt + 1);
        } catch (callbackError) {
          operationLogger.warn('Retry callback failed', {
            error: callbackError instanceof Error ? callbackError.message : String(callbackError),
          });
        }
      }

      await new Promise(resolve => setTimeout(resolve, finalDelay));
    }
  }

  // All retries exhausted, throw the last error
  operationLogger.error('All retry attempts exhausted', {
    totalAttempts: maxRetries + 1,
    finalError: lastError.message,
  });

  throw lastError;
}

/**
 * Default retry condition - retries on network and timeout errors
 * Now compatible with UserError and maintains backward compatibility
 */
export function defaultRetryCondition(error: Error): boolean {
  // Retry on network errors
  if ('code' in error) {
    const networkErrors = ['ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'ENOTFOUND'];
    if (networkErrors.includes(error.code as string)) {
      return true;
    }
  }

  // Get status code using helper function
  const statusCode = getErrorStatusCode(error);
  const errorCode = getErrorCode(error);

  // Retry on specific HTTP status codes for all error types
  if (statusCode) {
    const retryableStatusCodes = [408, 429, 500, 502, 503, 504];
    if (retryableStatusCodes.includes(statusCode)) {
      return true;
    }
  }

  // Retry on timeout errors (by error code)
  if (errorCode === 'TIMEOUT') {
    return true;
  }

  // Retry on external service errors
  if (errorCode === 'EXTERNAL_SERVICE_ERROR') {
    return true;
  }

  // Don't retry on client errors (4xx) or specific server errors
  if (error instanceof MakeServerError) {
    return error.statusCode >= 500 && error.statusCode !== 501;
  }

  // For UserError, check status code
  if (error instanceof UserError) {
    return statusCode >= 500 && statusCode !== 501;
  }

  return false;
}

/**
 * Bulkhead pattern implementation for resource isolation
 */
export class Bulkhead {
  private activeRequests = 0;
  private readonly queue: Array<{
    operation: () => Promise<unknown>;
    resolve: (value: unknown) => void;
    reject: (error: Error) => void;
    correlationId: string;
  }> = [];

  private readonly componentLogger: ReturnType<typeof logger.child>;

  constructor(
    private readonly name: string,
    private readonly maxConcurrency: number = 10,
    private readonly maxQueue: number = 100,
    private readonly timeout: number = 30000
  ) {
    this.componentLogger = logger.child({
      component: 'Bulkhead',
      bulkheadName: name,
    });
  }

  async execute<T>(
    operation: () => Promise<T>,
    correlationId?: string
  ): Promise<T> {
    const requestId = correlationId || randomUUID();
    const operationLogger = this.componentLogger.child({
      correlationId: requestId,
      operation: 'bulkhead-execute',
    });

    return new Promise<T>((resolve, reject) => {
      if (this.activeRequests < this.maxConcurrency) {
        this.executeImmediate(operation, resolve, reject, requestId);
      } else if (this.queue.length < this.maxQueue) {
        operationLogger.info('Request queued due to bulkhead limit', {
          activeRequests: this.activeRequests,
          queueLength: this.queue.length,
        });

        this.queue.push({
          operation: operation as () => Promise<unknown>,
          resolve: resolve as (value: unknown) => void,
          reject,
          correlationId: requestId,
        });
      } else {
        const error = createExternalServiceError(
          this.name,
          'Bulkhead capacity exceeded - request rejected',
          undefined,
          {
            activeRequests: this.activeRequests,
            queueLength: this.queue.length,
            maxConcurrency: this.maxConcurrency,
            maxQueue: this.maxQueue,
          },
          {
            correlationId: requestId,
            component: 'Bulkhead',
            operation: 'bulkhead-execute',
          }
        );

        operationLogger.error('Bulkhead capacity exceeded', {
          activeRequests: this.activeRequests,
          queueLength: this.queue.length,
        });

        reject(error);
      }
    });
  }

  private async executeImmediate<T>(
    operation: () => Promise<T>,
    resolve: (value: T) => void,
    reject: (error: Error) => void,
    correlationId: string
  ): Promise<void> {
    this.activeRequests++;
    
    const operationLogger = this.componentLogger.child({
      correlationId,
      operation: 'bulkhead-execute-immediate',
    });

    const timeoutId = setTimeout(() => {
      const timeoutError = createTimeoutError(
        `Bulkhead operation for ${this.name}`,
        this.timeout
      );
      reject(timeoutError);
    }, this.timeout);

    try {
      const result = await operation();
      clearTimeout(timeoutId);
      resolve(result);
      
      operationLogger.info('Bulkhead operation completed successfully', {
        activeRequests: this.activeRequests - 1,
      });
    } catch (error) {
      clearTimeout(timeoutId);
      reject(error as Error);
      
      operationLogger.error('Bulkhead operation failed', {
        error: error instanceof Error ? error.message : String(error),
        activeRequests: this.activeRequests - 1,
      });
    } finally {
      this.activeRequests--;
      this.processQueue();
    }
  }

  private processQueue(): void {
    if (this.queue.length > 0 && this.activeRequests < this.maxConcurrency) {
      const next = this.queue.shift();
      if (next) {
        this.executeImmediate(
          next.operation as () => Promise<unknown>,
          next.resolve,
          next.reject,
          next.correlationId
        );
      }
    }
  }

  public getStats(): {
    activeRequests: number;
    queueLength: number;
    maxConcurrency: number;
    maxQueue: number;
  } {
    return {
      activeRequests: this.activeRequests,
      queueLength: this.queue.length,
      maxConcurrency: this.maxConcurrency,
      maxQueue: this.maxQueue,
    };
  }
}

/**
 * Factory for creating circuit breakers for different services
 */
export class CircuitBreakerFactory {
  private static readonly breakers = new Map<string, CircuitBreaker>();

  static getOrCreate(
    name: string,
    options?: CircuitBreakerOptions
  ): CircuitBreaker {
    if (!this.breakers.has(name)) {
      this.breakers.set(name, new CircuitBreaker(name, options));
    }
    const breaker = this.breakers.get(name);
    if (!breaker) {
      throw new Error(`Failed to create or retrieve circuit breaker: ${name}`);
    }
    return breaker;
  }

  static getAllStats(): Record<string, ReturnType<CircuitBreaker['getStats']>> {
    const stats: Record<string, ReturnType<CircuitBreaker['getStats']>> = {};
    for (const [name, breaker] of this.breakers) {
      stats[name] = breaker.getStats();
    }
    return stats;
  }
}

/**
 * Factory for creating bulkheads for different resource pools
 */
export class BulkheadFactory {
  private static readonly bulkheads = new Map<string, Bulkhead>();

  static getOrCreate(
    name: string,
    maxConcurrency?: number,
    maxQueue?: number,
    timeout?: number
  ): Bulkhead {
    if (!this.bulkheads.has(name)) {
      this.bulkheads.set(
        name,
        new Bulkhead(name, maxConcurrency, maxQueue, timeout)
      );
    }
    const bulkhead = this.bulkheads.get(name);
    if (!bulkhead) {
      throw new Error(`Failed to create or retrieve bulkhead: ${name}`);
    }
    return bulkhead;
  }

  static getAllStats(): Record<string, ReturnType<Bulkhead['getStats']>> {
    const stats: Record<string, ReturnType<Bulkhead['getStats']>> = {};
    for (const [name, bulkhead] of this.bulkheads) {
      stats[name] = bulkhead.getStats();
    }
    return stats;
  }
}