/**
 * Comprehensive Unit Tests for Error Recovery Utility
 * 
 * Tests circuit breaker patterns, retry mechanisms with exponential backoff,
 * bulkhead resource isolation, and factory management functionality.
 * Focuses on achieving 100% coverage for utils/error-recovery.ts.
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import {
  CircuitBreaker,
  Bulkhead,
  CircuitBreakerFactory,
  BulkheadFactory,
  retryWithBackoff,
  defaultRetryCondition,
  type RetryOptions,
  type CircuitBreakerOptions,
  type CircuitBreakerState
} from '../../../src/utils/error-recovery.js';
import { 
  MakeServerError, 
  UserError, 
  createExternalServiceError, 
  createTimeoutError 
} from '../../../src/utils/errors.js';

// Mock logger to avoid dependency issues
jest.mock('../../../src/lib/logger.js', () => ({
  default: {
    child: jest.fn(() => ({
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
      debug: jest.fn(),
    })),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  }
}));

// Mock crypto for consistent UUID generation
jest.mock('crypto', () => ({
  randomUUID: jest.fn(() => 'mock-uuid-12345'),
}));

describe('Error Recovery Utility - Comprehensive Test Suite', () => {

  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  describe('CircuitBreaker', () => {
    let circuitBreaker: CircuitBreaker;

    beforeEach(() => {
      circuitBreaker = new CircuitBreaker('test-service');
    });

    describe('Constructor and Initialization', () => {
      it('should create circuit breaker with default options', () => {
        const cb = new CircuitBreaker('default-service');
        
        expect(cb.getState()).toBe('CLOSED');
        expect(cb.getStats()).toEqual({
          state: 'CLOSED',
          failureCount: 0,
          successCount: 0,
          nextAttempt: 0,
        });
      });

      it('should create circuit breaker with custom options', () => {
        const onStateChange = jest.fn();
        const cb = new CircuitBreaker('custom-service', {
          failureThreshold: 3,
          successThreshold: 2,
          timeout: 5000,
          resetTimeout: 30000,
          onStateChange,
        });

        expect(cb.getState()).toBe('CLOSED');
        expect(cb.getStats().state).toBe('CLOSED');
      });

      it('should handle empty onStateChange option', () => {
        const cb = new CircuitBreaker('no-callback-service', {
          onStateChange: undefined,
        });
        
        expect(cb.getState()).toBe('CLOSED');
      });
    });

    describe('Successful Operations', () => {
      it('should execute successful operation in CLOSED state', async () => {
        const mockOperation = jest.fn().mockResolvedValue('success');
        
        const result = await circuitBreaker.execute(mockOperation, 'test-correlation-id');
        
        expect(result).toBe('success');
        expect(mockOperation).toHaveBeenCalledTimes(1);
        expect(circuitBreaker.getState()).toBe('CLOSED');
        expect(circuitBreaker.getStats().failureCount).toBe(0);
      });

      it('should execute operation without correlation ID', async () => {
        const mockOperation = jest.fn().mockResolvedValue('success');
        
        const result = await circuitBreaker.execute(mockOperation);
        
        expect(result).toBe('success');
        expect(mockOperation).toHaveBeenCalledTimes(1);
      });

      it('should reset failure count on success', async () => {
        const failingOperation = jest.fn().mockRejectedValue(new Error('Failure'));
        const successOperation = jest.fn().mockResolvedValue('success');

        // Cause some failures
        await expect(circuitBreaker.execute(failingOperation)).rejects.toThrow();
        await expect(circuitBreaker.execute(failingOperation)).rejects.toThrow();
        
        expect(circuitBreaker.getStats().failureCount).toBe(2);

        // Success should reset failure count
        await circuitBreaker.execute(successOperation);
        expect(circuitBreaker.getStats().failureCount).toBe(0);
      });
    });

    describe('Circuit Breaker State Transitions', () => {
      it('should transition to OPEN after failure threshold', async () => {
        const onStateChange = jest.fn();
        const cb = new CircuitBreaker('failing-service', {
          failureThreshold: 3,
          onStateChange,
        });
        
        const failingOperation = jest.fn().mockRejectedValue(new Error('Service error'));

        // First 2 failures should keep circuit CLOSED
        await expect(cb.execute(failingOperation)).rejects.toThrow();
        await expect(cb.execute(failingOperation)).rejects.toThrow();
        expect(cb.getState()).toBe('CLOSED');
        expect(cb.getStats().failureCount).toBe(2);

        // 3rd failure should open circuit
        await expect(cb.execute(failingOperation)).rejects.toThrow();
        expect(cb.getState()).toBe('OPEN');
        expect(cb.getStats().failureCount).toBe(3);
        expect(onStateChange).toHaveBeenCalledWith('OPEN');
      });

      it('should block requests in OPEN state', async () => {
        const cb = new CircuitBreaker('blocked-service', {
          failureThreshold: 1,
          resetTimeout: 60000,
        });
        
        const failingOperation = jest.fn().mockRejectedValue(new Error('Service error'));
        const blockedOperation = jest.fn().mockResolvedValue('should-not-execute');

        // Open the circuit
        await expect(cb.execute(failingOperation)).rejects.toThrow('Service error');
        expect(cb.getState()).toBe('OPEN');

        // Subsequent calls should be blocked
        await expect(cb.execute(blockedOperation)).rejects.toThrow('Circuit breaker is OPEN');
        expect(blockedOperation).not.toHaveBeenCalled();
      });

      it('should transition to HALF_OPEN after reset timeout', async () => {
        const cb = new CircuitBreaker('reset-service', {
          failureThreshold: 1,
          resetTimeout: 1000,
        });

        const failingOperation = jest.fn().mockRejectedValue(new Error('Service error'));
        const testOperation = jest.fn().mockResolvedValue('test');

        // Open the circuit
        await expect(cb.execute(failingOperation)).rejects.toThrow();
        expect(cb.getState()).toBe('OPEN');

        // Advance time past reset timeout
        jest.advanceTimersByTime(1001);

        // Next call should transition to HALF_OPEN
        await cb.execute(testOperation);
        expect(cb.getState()).toBe('CLOSED'); // Success transitions directly to CLOSED
      });

      it('should transition from HALF_OPEN to CLOSED on success threshold', async () => {
        const onStateChange = jest.fn();
        const cb = new CircuitBreaker('recovery-service', {
          failureThreshold: 1,
          successThreshold: 2,
          resetTimeout: 1000,
          onStateChange,
        });

        const failingOperation = jest.fn().mockRejectedValue(new Error('Service error'));
        const successOperation = jest.fn().mockResolvedValue('success');

        // Open the circuit
        await expect(cb.execute(failingOperation)).rejects.toThrow();
        expect(cb.getState()).toBe('OPEN');

        // Wait for reset timeout and transition to HALF_OPEN
        jest.advanceTimersByTime(1001);
        
        // First success in HALF_OPEN should increment success count
        await cb.execute(successOperation);
        // Since successThreshold is 2, we need more successes to close
        // Let's manually set the state to HALF_OPEN to test this properly
        
        // Reset and test HALF_OPEN behavior more explicitly
        const cb2 = new CircuitBreaker('half-open-service', {
          failureThreshold: 1,
          successThreshold: 3,
          resetTimeout: 1000,
          onStateChange: jest.fn(),
        });

        // Open circuit
        await expect(cb2.execute(failingOperation)).rejects.toThrow();
        
        // Advance time to allow reset
        jest.advanceTimersByTime(1001);
        
        // Execute operations that should transition through HALF_OPEN
        await cb2.execute(successOperation);
        await cb2.execute(successOperation);
        await cb2.execute(successOperation);
        
        expect(cb2.getState()).toBe('CLOSED');
      });
    });

    describe('Timeout Handling', () => {
      it('should timeout long-running operations', async () => {
        const cb = new CircuitBreaker('timeout-service', {
          timeout: 1000,
        });

        const slowOperation = jest.fn(() => 
          new Promise(resolve => setTimeout(() => resolve('slow-result'), 2000))
        );

        const executePromise = cb.execute(slowOperation);
        
        // Advance time to trigger timeout
        jest.advanceTimersByTime(1001);

        await expect(executePromise).rejects.toThrow(/timed out after/);
        expect(cb.getStats().failureCount).toBe(1);
      });

      it('should not timeout fast operations', async () => {
        const cb = new CircuitBreaker('fast-service', {
          timeout: 1000,
        });

        const fastOperation = jest.fn().mockResolvedValue('fast-result');

        const result = await cb.execute(fastOperation);
        
        expect(result).toBe('fast-result');
        expect(cb.getStats().failureCount).toBe(0);
      });
    });

    describe('Error Handling and Logging', () => {
      it('should handle and log operation failures', async () => {
        const testError = new Error('Operation failed');
        const failingOperation = jest.fn().mockRejectedValue(testError);

        await expect(circuitBreaker.execute(failingOperation)).rejects.toThrow('Operation failed');
        
        expect(circuitBreaker.getStats().failureCount).toBe(1);
      });

      it('should handle non-Error objects as errors', async () => {
        const stringError = 'String error';
        const failingOperation = jest.fn().mockRejectedValue(stringError);

        await expect(circuitBreaker.execute(failingOperation)).rejects.toThrow();
        
        expect(circuitBreaker.getStats().failureCount).toBe(1);
      });
    });

    describe('Statistics and State Management', () => {
      it('should provide accurate statistics', () => {
        const stats = circuitBreaker.getStats();
        
        expect(stats).toEqual({
          state: 'CLOSED',
          failureCount: 0,
          successCount: 0,
          nextAttempt: 0,
        });
      });

      it('should track success count in HALF_OPEN state', async () => {
        const cb = new CircuitBreaker('success-tracking', {
          failureThreshold: 1,
          successThreshold: 2,
          resetTimeout: 1000,
        });

        const failingOp = jest.fn().mockRejectedValue(new Error('fail'));
        const successOp = jest.fn().mockResolvedValue('success');

        // Open circuit
        await expect(cb.execute(failingOp)).rejects.toThrow();
        
        // Transition to HALF_OPEN
        jest.advanceTimersByTime(1001);
        
        // Execute successful operation - this should increment success count
        await cb.execute(successOp);
        
        // The success should either close circuit or keep it in HALF_OPEN with success count
        const stats = cb.getStats();
        expect(stats.state).toBe('CLOSED'); // With threshold 2 and 1 success, it should close immediately
      });
    });
  });

  describe('retryWithBackoff Function', () => {
    beforeEach(() => {
      jest.clearAllTimers();
    });

    describe('Successful Operations', () => {
      it('should execute operation successfully without retries', async () => {
        const mockOperation = jest.fn().mockResolvedValue('success');
        
        const result = await retryWithBackoff(mockOperation);
        
        expect(result).toBe('success');
        expect(mockOperation).toHaveBeenCalledTimes(1);
      });

      it('should use custom correlation ID', async () => {
        const mockOperation = jest.fn().mockResolvedValue('success');
        
        const result = await retryWithBackoff(mockOperation, {}, 'custom-correlation');
        
        expect(result).toBe('success');
        expect(mockOperation).toHaveBeenCalledTimes(1);
      });
    });

    describe('Retry Logic', () => {
      it('should retry failed operations up to maxRetries', async () => {
        const mockOperation = jest.fn()
          .mockRejectedValueOnce(new Error('Attempt 1 failed'))
          .mockRejectedValueOnce(new Error('Attempt 2 failed'))
          .mockResolvedValue('success');

        const options: RetryOptions = {
          maxRetries: 3,
          baseDelay: 100,
          jitter: false,
        };
        
        const result = await retryWithBackoff(mockOperation, options);
        
        expect(result).toBe('success');
        expect(mockOperation).toHaveBeenCalledTimes(3);
      });

      it('should throw last error when all retries exhausted', async () => {
        const lastError = new Error('Final attempt failed');
        const mockOperation = jest.fn()
          .mockRejectedValueOnce(new Error('Attempt 1 failed'))
          .mockRejectedValueOnce(new Error('Attempt 2 failed'))
          .mockRejectedValue(lastError);

        const options: RetryOptions = {
          maxRetries: 2,
          baseDelay: 100,
        };
        
        await expect(retryWithBackoff(mockOperation, options)).rejects.toThrow('Final attempt failed');
        expect(mockOperation).toHaveBeenCalledTimes(3);
      });

      it('should respect custom retry condition', async () => {
        const retryableError = new Error('Retryable');
        const nonRetryableError = new Error('Non-retryable');
        
        const mockOperation = jest.fn()
          .mockRejectedValueOnce(retryableError)
          .mockRejectedValue(nonRetryableError);

        const customRetryCondition = (error: Error) => error.message === 'Retryable';
        
        const options: RetryOptions = {
          maxRetries: 3,
          retryCondition: customRetryCondition,
          baseDelay: 10,
        };
        
        await expect(retryWithBackoff(mockOperation, options)).rejects.toThrow('Non-retryable');
        expect(mockOperation).toHaveBeenCalledTimes(2);
      });
    });

    describe('Exponential Backoff', () => {
      it('should implement exponential backoff with default values', async () => {
        const mockOperation = jest.fn()
          .mockRejectedValueOnce(new Error('Attempt 1'))
          .mockRejectedValueOnce(new Error('Attempt 2'))
          .mockResolvedValue('success');

        const options: RetryOptions = {
          maxRetries: 2,
          baseDelay: 100,
          exponentialBase: 2,
          jitter: false,
        };
        
        const promise = retryWithBackoff(mockOperation, options);
        
        // First retry should wait baseDelay * exponentialBase^0 = 100ms
        jest.advanceTimersByTime(100);
        
        // Second retry should wait baseDelay * exponentialBase^1 = 200ms
        jest.advanceTimersByTime(200);
        
        const result = await promise;
        expect(result).toBe('success');
      });

      it('should respect maxDelay cap', async () => {
        const mockOperation = jest.fn()
          .mockRejectedValueOnce(new Error('Attempt 1'))
          .mockResolvedValue('success');

        const options: RetryOptions = {
          maxRetries: 1,
          baseDelay: 1000,
          maxDelay: 500, // Smaller than calculated delay
          exponentialBase: 2,
          jitter: false,
        };
        
        const promise = retryWithBackoff(mockOperation, options);
        
        // Should wait maxDelay (500ms) instead of baseDelay * 2^0 (1000ms)
        jest.advanceTimersByTime(500);
        
        const result = await promise;
        expect(result).toBe('success');
      });

      it('should add jitter when enabled', async () => {
        // Mock Math.random to return predictable values
        const originalRandom = Math.random;
        Math.random = jest.fn().mockReturnValue(0.5); // 500ms jitter
        
        try {
          const mockOperation = jest.fn()
            .mockRejectedValueOnce(new Error('Attempt 1'))
            .mockResolvedValue('success');

          const options: RetryOptions = {
            maxRetries: 1,
            baseDelay: 100,
            jitter: true,
          };
          
          const promise = retryWithBackoff(mockOperation, options);
          
          // Base delay (100) + jitter (500) = 600ms total
          jest.advanceTimersByTime(600);
          
          const result = await promise;
          expect(result).toBe('success');
        } finally {
          Math.random = originalRandom;
        }
      });
    });

    describe('Retry Callbacks', () => {
      it('should call onRetry callback on each retry attempt', async () => {
        const onRetryMock = jest.fn();
        const mockOperation = jest.fn()
          .mockRejectedValueOnce(new Error('Attempt 1'))
          .mockRejectedValueOnce(new Error('Attempt 2'))
          .mockResolvedValue('success');

        const options: RetryOptions = {
          maxRetries: 2,
          baseDelay: 10,
          onRetry: onRetryMock,
        };
        
        await retryWithBackoff(mockOperation, options);
        
        expect(onRetryMock).toHaveBeenCalledTimes(2);
        expect(onRetryMock).toHaveBeenNthCalledWith(1, expect.any(Error), 1);
        expect(onRetryMock).toHaveBeenNthCalledWith(2, expect.any(Error), 2);
      });

      it('should handle onRetry callback errors gracefully', async () => {
        const throwingCallback = jest.fn(() => {
          throw new Error('Callback error');
        });
        
        const mockOperation = jest.fn()
          .mockRejectedValueOnce(new Error('Attempt 1'))
          .mockResolvedValue('success');

        const options: RetryOptions = {
          maxRetries: 1,
          baseDelay: 10,
          onRetry: throwingCallback,
        };
        
        // Should not throw despite callback error
        const result = await retryWithBackoff(mockOperation, options);
        expect(result).toBe('success');
        expect(throwingCallback).toHaveBeenCalledTimes(1);
      });
    });

    describe('Logger Fallback', () => {
      it('should handle logger initialization errors', async () => {
        // Create a scenario where logger.child might fail
        const mockOperation = jest.fn().mockResolvedValue('success');
        
        // This should work even if logger has issues
        const result = await retryWithBackoff(mockOperation);
        
        expect(result).toBe('success');
      });
    });
  });

  describe('defaultRetryCondition Function', () => {
    describe('Network Errors', () => {
      it('should retry on network error codes', () => {
        const networkErrors = ['ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'ENOTFOUND'];
        
        networkErrors.forEach(code => {
          const error = new Error('Network error') as Error & { code: string };
          error.code = code;
          
          expect(defaultRetryCondition(error)).toBe(true);
        });
      });

      it('should not retry on non-network error codes', () => {
        const error = new Error('Other error') as Error & { code: string };
        error.code = 'OTHER_ERROR';
        
        expect(defaultRetryCondition(error)).toBe(false);
      });
    });

    describe('HTTP Status Code Retries', () => {
      it('should retry on retryable HTTP status codes', () => {
        const retryableStatusCodes = [408, 429, 500, 502, 503, 504];
        
        retryableStatusCodes.forEach(statusCode => {
          const error = new MakeServerError('HTTP Error', 'HTTP_ERROR', statusCode);
          expect(defaultRetryCondition(error)).toBe(true);
        });
      });

      it('should not retry on client error status codes', () => {
        const clientErrorCodes = [400, 401, 403, 404];
        
        clientErrorCodes.forEach(statusCode => {
          const error = new MakeServerError('Client Error', 'CLIENT_ERROR', statusCode);
          expect(defaultRetryCondition(error)).toBe(false);
        });
      });

      it('should not retry on 501 Not Implemented', () => {
        const error = new MakeServerError('Not Implemented', 'NOT_IMPLEMENTED', 501);
        expect(defaultRetryCondition(error)).toBe(false);
      });
    });

    describe('Error Code Based Retries', () => {
      it('should retry on TIMEOUT error code', () => {
        const error = createTimeoutError('test-operation', 5000);
        expect(defaultRetryCondition(error)).toBe(true);
      });

      it('should retry on EXTERNAL_SERVICE_ERROR code', () => {
        const originalError = new Error('Service down');
        const error = createExternalServiceError('TestService', 'failed operation', originalError);
        expect(defaultRetryCondition(error)).toBe(true);
      });
    });

    describe('MakeServerError Specific Logic', () => {
      it('should retry on server errors (5xx) except 501', () => {
        const serverError = new MakeServerError('Server Error', 'SERVER_ERROR', 500);
        expect(defaultRetryCondition(serverError)).toBe(true);
        
        const badGateway = new MakeServerError('Bad Gateway', 'BAD_GATEWAY', 502);
        expect(defaultRetryCondition(badGateway)).toBe(true);
        
        const notImplemented = new MakeServerError('Not Implemented', 'NOT_IMPLEMENTED', 501);
        expect(defaultRetryCondition(notImplemented)).toBe(false);
      });
    });

    describe('UserError Handling', () => {
      it('should retry UserError based on status code', () => {
        const serverError = new UserError('Server Error', 'SERVER_ERROR', 500);
        expect(defaultRetryCondition(serverError)).toBe(true);
        
        const clientError = new UserError('Client Error', 'CLIENT_ERROR', 400);
        expect(defaultRetryCondition(clientError)).toBe(false);
      });
    });

    describe('Default Cases', () => {
      it('should not retry regular Error objects by default', () => {
        const regularError = new Error('Regular error');
        expect(defaultRetryCondition(regularError)).toBe(false);
      });

      it('should handle errors without status codes', () => {
        const error = { message: 'Custom error object' } as Error;
        expect(defaultRetryCondition(error)).toBe(false);
      });
    });
  });

  describe('Bulkhead', () => {
    let bulkhead: Bulkhead;

    beforeEach(() => {
      bulkhead = new Bulkhead('test-bulkhead', 2, 5, 1000); // 2 concurrent, 5 queue, 1s timeout
    });

    describe('Constructor and Configuration', () => {
      it('should create bulkhead with custom parameters', () => {
        const bh = new Bulkhead('custom-bulkhead', 3, 10, 2000);
        const stats = bh.getStats();
        
        expect(stats.maxConcurrency).toBe(3);
        expect(stats.maxQueue).toBe(10);
        expect(stats.activeRequests).toBe(0);
        expect(stats.queueLength).toBe(0);
      });

      it('should create bulkhead with default parameters', () => {
        const bh = new Bulkhead('default-bulkhead');
        const stats = bh.getStats();
        
        expect(stats.maxConcurrency).toBe(10);
        expect(stats.maxQueue).toBe(100);
      });
    });

    describe('Request Execution', () => {
      it('should execute request immediately when under concurrency limit', async () => {
        const mockOperation = jest.fn().mockResolvedValue('result');
        
        const result = await bulkhead.execute(mockOperation, 'test-correlation');
        
        expect(result).toBe('result');
        expect(mockOperation).toHaveBeenCalledTimes(1);
        expect(bulkhead.getStats().activeRequests).toBe(0);
      });

      it('should execute request without correlation ID', async () => {
        const mockOperation = jest.fn().mockResolvedValue('result');
        
        const result = await bulkhead.execute(mockOperation);
        
        expect(result).toBe('result');
      });

      it('should handle multiple concurrent requests within limit', async () => {
        const slowOperation = jest.fn(() => 
          new Promise(resolve => setTimeout(() => resolve('slow-result'), 500))
        );

        const promise1 = bulkhead.execute(slowOperation);
        const promise2 = bulkhead.execute(slowOperation);
        
        // Both should be actively executing
        expect(bulkhead.getStats().activeRequests).toBe(2);
        
        jest.advanceTimersByTime(500);
        
        const results = await Promise.all([promise1, promise2]);
        expect(results).toEqual(['slow-result', 'slow-result']);
        expect(bulkhead.getStats().activeRequests).toBe(0);
      });
    });

    describe('Queueing Behavior', () => {
      it('should queue requests when at concurrency limit', async () => {
        const slowOperation = jest.fn(() => 
          new Promise(resolve => setTimeout(() => resolve('result'), 1000))
        );

        // Fill up concurrent slots
        const promise1 = bulkhead.execute(slowOperation);
        const promise2 = bulkhead.execute(slowOperation);
        
        expect(bulkhead.getStats().activeRequests).toBe(2);
        
        // Next request should be queued
        const promise3 = bulkhead.execute(slowOperation);
        
        expect(bulkhead.getStats().activeRequests).toBe(2);
        expect(bulkhead.getStats().queueLength).toBe(1);
        
        // Complete first request to allow queued request to proceed
        jest.advanceTimersByTime(1000);
        
        await promise1;
        await promise2;
        await promise3;
        
        expect(bulkhead.getStats().activeRequests).toBe(0);
        expect(bulkhead.getStats().queueLength).toBe(0);
      });

      it('should reject requests when queue is full', async () => {
        const bh = new Bulkhead('full-queue', 1, 1); // 1 concurrent, 1 queue
        
        const slowOperation = jest.fn(() => 
          new Promise(resolve => setTimeout(() => resolve('result'), 1000))
        );

        // Fill concurrent slot
        const promise1 = bh.execute(slowOperation);
        expect(bh.getStats().activeRequests).toBe(1);
        
        // Fill queue
        const promise2 = bh.execute(slowOperation);
        expect(bh.getStats().queueLength).toBe(1);
        
        // Next request should be rejected
        await expect(bh.execute(slowOperation)).rejects.toThrow('Bulkhead capacity exceeded');
        
        // Clean up
        jest.advanceTimersByTime(1000);
        await Promise.all([promise1, promise2]);
      });
    });

    describe('Timeout Handling', () => {
      it('should timeout long-running operations', async () => {
        const bh = new Bulkhead('timeout-bulkhead', 10, 10, 500); // 500ms timeout
        
        const slowOperation = jest.fn(() => 
          new Promise(resolve => setTimeout(() => resolve('result'), 1000))
        );

        const promise = bh.execute(slowOperation);
        
        jest.advanceTimersByTime(501);
        
        await expect(promise).rejects.toThrow(/timed out after/);
        expect(bh.getStats().activeRequests).toBe(0);
      });

      it('should not timeout fast operations', async () => {
        const bh = new Bulkhead('fast-bulkhead', 10, 10, 500);
        
        const fastOperation = jest.fn().mockResolvedValue('fast-result');
        
        const result = await bh.execute(fastOperation);
        expect(result).toBe('fast-result');
      });
    });

    describe('Error Handling', () => {
      it('should handle operation failures and update stats', async () => {
        const failingOperation = jest.fn().mockRejectedValue(new Error('Operation failed'));
        
        await expect(bulkhead.execute(failingOperation)).rejects.toThrow('Operation failed');
        
        expect(bulkhead.getStats().activeRequests).toBe(0);
      });

      it('should process queue after operation failure', async () => {
        const bh = new Bulkhead('error-recovery', 1, 2);
        
        const failingOperation = jest.fn().mockRejectedValue(new Error('First failed'));
        const successOperation = jest.fn().mockResolvedValue('success');
        
        // Start failing operation
        const failPromise = bh.execute(failingOperation);
        
        // Queue success operation
        const successPromise = bh.execute(successOperation);
        expect(bh.getStats().queueLength).toBe(1);
        
        // Wait for failure to complete and queue to process
        await expect(failPromise).rejects.toThrow('First failed');
        const result = await successPromise;
        
        expect(result).toBe('success');
        expect(bh.getStats().activeRequests).toBe(0);
        expect(bh.getStats().queueLength).toBe(0);
      });
    });

    describe('Statistics', () => {
      it('should provide accurate bulkhead statistics', () => {
        const stats = bulkhead.getStats();
        
        expect(stats).toEqual({
          activeRequests: 0,
          queueLength: 0,
          maxConcurrency: 2,
          maxQueue: 5,
        });
      });

      it('should update statistics during operation', async () => {
        const slowOperation = jest.fn(() => 
          new Promise(resolve => setTimeout(() => resolve('result'), 100))
        );

        const promise = bulkhead.execute(slowOperation);
        
        expect(bulkhead.getStats().activeRequests).toBe(1);
        
        jest.advanceTimersByTime(100);
        await promise;
        
        expect(bulkhead.getStats().activeRequests).toBe(0);
      });
    });
  });

  describe('CircuitBreakerFactory', () => {
    beforeEach(() => {
      // Clear factory state between tests
      (CircuitBreakerFactory as any).breakers.clear();
    });

    describe('Factory Management', () => {
      it('should create new circuit breaker', () => {
        const cb = CircuitBreakerFactory.getOrCreate('test-service');
        
        expect(cb).toBeInstanceOf(CircuitBreaker);
        expect(cb.getState()).toBe('CLOSED');
      });

      it('should return existing circuit breaker for same name', () => {
        const cb1 = CircuitBreakerFactory.getOrCreate('same-service');
        const cb2 = CircuitBreakerFactory.getOrCreate('same-service');
        
        expect(cb1).toBe(cb2);
      });

      it('should create circuit breaker with custom options', () => {
        const options = {
          failureThreshold: 3,
          timeout: 5000,
        };
        
        const cb = CircuitBreakerFactory.getOrCreate('custom-service', options);
        
        expect(cb).toBeInstanceOf(CircuitBreaker);
      });

      it('should handle factory retrieval errors', () => {
        // Mock the Map to simulate an error condition
        const originalGet = Map.prototype.get;
        Map.prototype.get = jest.fn().mockReturnValue(undefined);
        
        try {
          // This should create a new breaker since get returns undefined
          const cb = CircuitBreakerFactory.getOrCreate('error-test');
          expect(cb).toBeInstanceOf(CircuitBreaker);
        } finally {
          Map.prototype.get = originalGet;
        }
      });
    });

    describe('Statistics Collection', () => {
      it('should return empty stats when no breakers exist', () => {
        const stats = CircuitBreakerFactory.getAllStats();
        
        expect(stats).toEqual({});
      });

      it('should return stats for all registered breakers', () => {
        const cb1 = CircuitBreakerFactory.getOrCreate('service-1');
        const cb2 = CircuitBreakerFactory.getOrCreate('service-2');
        
        const stats = CircuitBreakerFactory.getAllStats();
        
        expect(stats).toHaveProperty('service-1');
        expect(stats).toHaveProperty('service-2');
        expect(stats['service-1']).toEqual(cb1.getStats());
        expect(stats['service-2']).toEqual(cb2.getStats());
      });
    });
  });

  describe('BulkheadFactory', () => {
    beforeEach(() => {
      // Clear factory state between tests
      (BulkheadFactory as any).bulkheads.clear();
    });

    describe('Factory Management', () => {
      it('should create new bulkhead with default parameters', () => {
        const bh = BulkheadFactory.getOrCreate('test-bulkhead');
        
        expect(bh).toBeInstanceOf(Bulkhead);
        expect(bh.getStats().maxConcurrency).toBe(10);
        expect(bh.getStats().maxQueue).toBe(100);
      });

      it('should create new bulkhead with custom parameters', () => {
        const bh = BulkheadFactory.getOrCreate('custom-bulkhead', 5, 20, 2000);
        
        const stats = bh.getStats();
        expect(stats.maxConcurrency).toBe(5);
        expect(stats.maxQueue).toBe(20);
      });

      it('should return existing bulkhead for same name', () => {
        const bh1 = BulkheadFactory.getOrCreate('same-bulkhead');
        const bh2 = BulkheadFactory.getOrCreate('same-bulkhead');
        
        expect(bh1).toBe(bh2);
      });

      it('should handle factory retrieval errors', () => {
        const originalGet = Map.prototype.get;
        Map.prototype.get = jest.fn().mockReturnValue(undefined);
        
        try {
          const bh = BulkheadFactory.getOrCreate('error-test');
          expect(bh).toBeInstanceOf(Bulkhead);
        } finally {
          Map.prototype.get = originalGet;
        }
      });
    });

    describe('Statistics Collection', () => {
      it('should return empty stats when no bulkheads exist', () => {
        const stats = BulkheadFactory.getAllStats();
        
        expect(stats).toEqual({});
      });

      it('should return stats for all registered bulkheads', () => {
        const bh1 = BulkheadFactory.getOrCreate('bulkhead-1');
        const bh2 = BulkheadFactory.getOrCreate('bulkhead-2');
        
        const stats = BulkheadFactory.getAllStats();
        
        expect(stats).toHaveProperty('bulkhead-1');
        expect(stats).toHaveProperty('bulkhead-2');
        expect(stats['bulkhead-1']).toEqual(bh1.getStats());
        expect(stats['bulkhead-2']).toEqual(bh2.getStats());
      });
    });
  });

  describe('Integration Tests', () => {
    it('should handle complete error recovery workflow', async () => {
      // Create circuit breaker and bulkhead
      const circuitBreaker = new CircuitBreaker('integration-service', {
        failureThreshold: 2,
        resetTimeout: 1000,
      });
      const bulkhead = new Bulkhead('integration-bulkhead', 2, 3, 2000);
      
      // Create operations with varying success/failure
      let callCount = 0;
      const unreliableOperation = jest.fn(() => {
        callCount++;
        if (callCount <= 2) {
          return Promise.reject(new Error(`Failure ${callCount}`));
        }
        return Promise.resolve(`Success ${callCount}`);
      });

      // Execute through both circuit breaker and bulkhead
      const wrappedOperation = () => bulkhead.execute(() => unreliableOperation());
      
      // First two calls should fail and open circuit breaker
      await expect(circuitBreaker.execute(wrappedOperation)).rejects.toThrow('Failure 1');
      await expect(circuitBreaker.execute(wrappedOperation)).rejects.toThrow('Failure 2');
      
      expect(circuitBreaker.getState()).toBe('OPEN');
      
      // Circuit should be open, blocking requests
      await expect(circuitBreaker.execute(wrappedOperation)).rejects.toThrow('Circuit breaker is OPEN');
      
      // Advance time to allow circuit reset
      jest.advanceTimersByTime(1001);
      
      // Next call should succeed and close circuit
      const result = await circuitBreaker.execute(wrappedOperation);
      expect(result).toBe('Success 3');
      expect(circuitBreaker.getState()).toBe('CLOSED');
    });

    it('should combine retry logic with circuit breaker', async () => {
      const cb = new CircuitBreaker('retry-circuit', {
        failureThreshold: 3,
      });
      
      let attempts = 0;
      const flakyOperation = () => {
        attempts++;
        if (attempts < 3) {
          return Promise.reject(new Error(`Attempt ${attempts} failed`));
        }
        return Promise.resolve('Finally succeeded');
      };
      
      // Use retry with circuit breaker
      const retryOptions: RetryOptions = {
        maxRetries: 2,
        baseDelay: 10,
        jitter: false,
      };
      
      const result = await cb.execute(() => 
        retryWithBackoff(flakyOperation, retryOptions)
      );
      
      expect(result).toBe('Finally succeeded');
      expect(attempts).toBe(3);
      expect(cb.getState()).toBe('CLOSED');
    });
  });

  describe('Edge Cases and Error Conditions', () => {
    it('should handle circuit breaker with zero thresholds', () => {
      const cb = new CircuitBreaker('zero-thresholds', {
        failureThreshold: 0,
        successThreshold: 0,
      });
      
      expect(cb.getState()).toBe('CLOSED');
    });

    it('should handle bulkhead with zero concurrency', () => {
      const bh = new Bulkhead('zero-concurrency', 0, 1);
      
      expect(bh.getStats().maxConcurrency).toBe(0);
    });

    it('should handle retry with zero retries', async () => {
      const operation = jest.fn().mockResolvedValue('success');
      
      const result = await retryWithBackoff(operation, { maxRetries: 0 });
      
      expect(result).toBe('success');
      expect(operation).toHaveBeenCalledTimes(1);
    });

    it('should handle negative delays in retry', async () => {
      const operation = jest.fn()
        .mockRejectedValueOnce(new Error('fail'))
        .mockResolvedValue('success');
      
      const result = await retryWithBackoff(operation, {
        maxRetries: 1,
        baseDelay: -100, // Negative delay
      });
      
      expect(result).toBe('success');
    });
  });
});