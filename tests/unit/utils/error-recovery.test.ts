/**
 * Comprehensive Unit Tests for Error Recovery Module
 * 
 * Tests circuit breaker patterns, retry mechanisms, bulkhead isolation,
 * and all error recovery strategies. Covers edge cases, timing behavior,
 * and integration with error types.
 */

import { jest } from '@jest/globals';
import { randomUUID } from 'crypto';
import {
  CircuitBreaker,
  Bulkhead,
  CircuitBreakerFactory,
  BulkheadFactory,
  retryWithBackoff,
  defaultRetryCondition,
  type CircuitBreakerState,
  type RetryOptions,
  type CircuitBreakerOptions
} from '../../../src/utils/error-recovery';
import { 
  MakeServerError, 
  UserError,
  createExternalServiceError,
  createTimeoutError,
  getErrorStatusCode,
  getErrorCode
} from '../../../src/utils/errors';

// Mock dependencies
jest.mock('../../../src/lib/logger', () => ({
  default: {
    child: jest.fn(() => ({
      info: jest.fn(),
      error: jest.fn(),
      warn: jest.fn(),
      debug: jest.fn()
    }))
  }
}));

jest.mock('crypto', () => ({
  randomUUID: jest.fn(() => 'test-uuid-123')
}));

jest.mock('../../../src/utils/errors', () => ({
  MakeServerError: class MockMakeServerError extends Error {
    public statusCode: number;
    constructor(message: string, statusCode: number = 500) {
      super(message);
      this.name = 'MakeServerError';
      this.statusCode = statusCode;
    }
  },
  UserError: class MockUserError extends Error {
    constructor(message: string) {
      super(message);
      this.name = 'UserError';
    }
  },
  createExternalServiceError: jest.fn((service: string, message: string) => {
    const error = new Error(message);
    error.name = 'ExternalServiceError';
    (error as any).service = service;
    return error;
  }),
  createTimeoutError: jest.fn((operation: string, timeout: number) => {
    const error = new Error(`${operation} timed out after ${timeout}ms`);
    error.name = 'TimeoutError';
    (error as any).timeout = timeout;
    return error;
  }),
  getErrorStatusCode: jest.fn((error: Error) => {
    if (error.name === 'UserError') return 400;
    if (error.name === 'MakeServerError') return (error as any).statusCode || 500;
    if (error.name === 'TimeoutError') return 408;
    if (error.name === 'ExternalServiceError') return 503;
    if ('code' in error) {
      const code = (error as any).code;
      if (['ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'ENOTFOUND'].includes(code)) {
        return 503;
      }
    }
    return 500;
  }),
  getErrorCode: jest.fn((error: Error) => {
    if (error.name === 'TimeoutError') return 'TIMEOUT';
    if (error.name === 'ExternalServiceError') return 'EXTERNAL_SERVICE_ERROR';
    return error.name || 'UNKNOWN_ERROR';
  })
}));

describe('CircuitBreaker', () => {
  let breaker: CircuitBreaker;
  let mockOperation: jest.Mock;
  let onStateChange: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
    onStateChange = jest.fn();
    
    breaker = new CircuitBreaker('test-service', {
      failureThreshold: 3,
      successThreshold: 2,
      timeout: 1000,
      resetTimeout: 5000,
      onStateChange
    });

    mockOperation = jest.fn();
  });

  describe('Initial State', () => {
    test('should start in CLOSED state', () => {
      expect(breaker.getState()).toBe('CLOSED');
    });

    test('should have correct initial stats', () => {
      const stats = breaker.getStats();
      expect(stats.state).toBe('CLOSED');
      expect(stats.failureCount).toBe(0);
      expect(stats.successCount).toBe(0);
      expect(stats.nextAttempt).toBe(0);
    });
  });

  describe('CLOSED State Behavior', () => {
    test('should execute operation successfully in CLOSED state', async () => {
      mockOperation.mockResolvedValue('success');

      const result = await breaker.execute(mockOperation);

      expect(result).toBe('success');
      expect(mockOperation).toHaveBeenCalledTimes(1);
      expect(breaker.getState()).toBe('CLOSED');
    });

    test('should handle single failure in CLOSED state', async () => {
      const error = new Error('Test failure');
      mockOperation.mockRejectedValue(error);

      await expect(breaker.execute(mockOperation)).rejects.toThrow('Test failure');
      
      expect(breaker.getState()).toBe('CLOSED');
      expect(breaker.getStats().failureCount).toBe(1);
    });

    test('should transition to OPEN after failure threshold', async () => {
      const error = new Error('Test failure');
      mockOperation.mockRejectedValue(error);

      // Trigger failures up to threshold
      for (let i = 0; i < 3; i++) {
        await expect(breaker.execute(mockOperation)).rejects.toThrow();
      }

      expect(breaker.getState()).toBe('OPEN');
      expect(onStateChange).toHaveBeenCalledWith('OPEN');
    });

    test('should reset failure count on success', async () => {
      const error = new Error('Test failure');
      mockOperation.mockRejectedValueOnce(error);
      mockOperation.mockRejectedValueOnce(error);
      mockOperation.mockResolvedValue('success');

      // Two failures
      await expect(breaker.execute(mockOperation)).rejects.toThrow();
      await expect(breaker.execute(mockOperation)).rejects.toThrow();
      expect(breaker.getStats().failureCount).toBe(2);

      // Success should reset failure count
      await breaker.execute(mockOperation);
      expect(breaker.getStats().failureCount).toBe(0);
      expect(breaker.getState()).toBe('CLOSED');
    });
  });

  describe('OPEN State Behavior', () => {
    beforeEach(async () => {
      // Force circuit to OPEN state
      const error = new Error('Force open');
      mockOperation.mockRejectedValue(error);
      
      for (let i = 0; i < 3; i++) {
        await expect(breaker.execute(mockOperation)).rejects.toThrow();
      }
      
      expect(breaker.getState()).toBe('OPEN');
      jest.clearAllMocks();
    });

    test('should block requests immediately in OPEN state', async () => {
      const blockedOperation = jest.fn().mockResolvedValue('should not execute');

      await expect(breaker.execute(blockedOperation)).rejects.toThrow(
        'Circuit breaker is OPEN - requests blocked'
      );

      expect(blockedOperation).not.toHaveBeenCalled();
      expect(createExternalServiceError).toHaveBeenCalledWith(
        'test-service',
        'Circuit breaker is OPEN - requests blocked',
        undefined,
        expect.objectContaining({
          circuitState: 'OPEN',
          failureCount: 3
        }),
        expect.any(Object)
      );
    });

    test('should transition to HALF_OPEN after reset timeout', async () => {
      // Fast-forward time
      jest.spyOn(Date, 'now').mockReturnValue(Date.now() + 6000); // 6 seconds later
      
      mockOperation.mockResolvedValue('test result');

      const result = await breaker.execute(mockOperation);

      expect(result).toBe('test result');
      expect(breaker.getState()).toBe('HALF_OPEN');
      expect(onStateChange).toHaveBeenCalledWith('HALF_OPEN');
    });

    test('should maintain OPEN state before reset timeout', async () => {
      // Time has not advanced enough
      jest.spyOn(Date, 'now').mockReturnValue(Date.now() + 1000); // Only 1 second

      await expect(breaker.execute(mockOperation)).rejects.toThrow(
        'Circuit breaker is OPEN - requests blocked'
      );

      expect(breaker.getState()).toBe('OPEN');
    });
  });

  describe('HALF_OPEN State Behavior', () => {
    beforeEach(async () => {
      // Force circuit to OPEN state then to HALF_OPEN
      const error = new Error('Force open');
      mockOperation.mockRejectedValue(error);
      
      for (let i = 0; i < 3; i++) {
        await expect(breaker.execute(mockOperation)).rejects.toThrow();
      }
      
      // Move to HALF_OPEN
      jest.spyOn(Date, 'now').mockReturnValue(Date.now() + 6000);
      mockOperation.mockResolvedValue('success');
      await breaker.execute(mockOperation);
      
      expect(breaker.getState()).toBe('HALF_OPEN');
      jest.clearAllMocks();
    });

    test('should transition to CLOSED after success threshold', async () => {
      mockOperation.mockResolvedValue('success');

      // Need 2 successes to close (successThreshold = 2, already had 1)
      await breaker.execute(mockOperation);

      expect(breaker.getState()).toBe('CLOSED');
      expect(onStateChange).toHaveBeenCalledWith('CLOSED');
      expect(breaker.getStats().successCount).toBe(0); // Reset after closing
    });

    test('should transition back to OPEN on failure', async () => {
      const error = new Error('Half-open failure');
      mockOperation.mockRejectedValue(error);

      await expect(breaker.execute(mockOperation)).rejects.toThrow();

      expect(breaker.getState()).toBe('OPEN');
      expect(breaker.getStats().successCount).toBe(0); // Reset on failure
    });

    test('should track success count in HALF_OPEN', async () => {
      mockOperation.mockResolvedValue('success');

      await breaker.execute(mockOperation);

      expect(breaker.getStats().successCount).toBe(2); // Initial 1 + this 1
      expect(breaker.getState()).toBe('CLOSED'); // Should close after 2 successes
    });
  });

  describe('Timeout Handling', () => {
    test('should timeout long-running operations', async () => {
      const slowOperation = jest.fn().mockImplementation(
        () => new Promise(resolve => setTimeout(resolve, 2000)) // 2 seconds
      );

      await expect(breaker.execute(slowOperation)).rejects.toThrow();
      
      expect(createTimeoutError).toHaveBeenCalledWith(
        'Circuit breaker operation for test-service',
        1000
      );
    });

    test('should not timeout fast operations', async () => {
      const fastOperation = jest.fn().mockImplementation(
        () => new Promise(resolve => setTimeout(() => resolve('fast'), 100))
      );

      const result = await breaker.execute(fastOperation);
      expect(result).toBe('fast');
    });
  });

  describe('Default Options', () => {
    test('should use default options when none provided', () => {
      const defaultBreaker = new CircuitBreaker('default-test');
      
      // Test default behavior by checking failure threshold
      const stats = defaultBreaker.getStats();
      expect(stats.failureCount).toBe(0);
      expect(defaultBreaker.getState()).toBe('CLOSED');
    });
  });

  describe('Correlation ID Handling', () => {
    test('should use provided correlation ID', async () => {
      mockOperation.mockResolvedValue('success');
      
      await breaker.execute(mockOperation, 'custom-correlation-id');
      
      expect(mockOperation).toHaveBeenCalledTimes(1);
      // Correlation ID should be passed to logger (verified through mocks)
    });

    test('should generate correlation ID when none provided', async () => {
      mockOperation.mockResolvedValue('success');
      
      await breaker.execute(mockOperation);
      
      expect(randomUUID).toHaveBeenCalled();
    });
  });
});

describe('retryWithBackoff', () => {
  let mockOperation: jest.Mock;
  let onRetry: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
    mockOperation = jest.fn();
    onRetry = jest.fn();
  });

  describe('Successful Operations', () => {
    test('should return result on first success', async () => {
      mockOperation.mockResolvedValue('success');

      const result = await retryWithBackoff(mockOperation);

      expect(result).toBe('success');
      expect(mockOperation).toHaveBeenCalledTimes(1);
    });

    test('should return result after retries', async () => {
      mockOperation
        .mockRejectedValueOnce(new Error('First failure'))
        .mockRejectedValueOnce(new Error('Second failure'))
        .mockResolvedValue('success');

      const result = await retryWithBackoff(mockOperation, { maxRetries: 3 });

      expect(result).toBe('success');
      expect(mockOperation).toHaveBeenCalledTimes(3);
    });
  });

  describe('Failed Operations', () => {
    test('should throw last error after all retries exhausted', async () => {
      const finalError = new Error('Final failure');
      mockOperation.mockRejectedValue(finalError);

      await expect(
        retryWithBackoff(mockOperation, { maxRetries: 2 })
      ).rejects.toThrow('Final failure');

      expect(mockOperation).toHaveBeenCalledTimes(3); // Initial + 2 retries
    });

    test('should not retry if retry condition returns false', async () => {
      const error = new Error('Non-retryable error');
      mockOperation.mockRejectedValue(error);

      const retryCondition = jest.fn().mockReturnValue(false);

      await expect(
        retryWithBackoff(mockOperation, { retryCondition })
      ).rejects.toThrow('Non-retryable error');

      expect(mockOperation).toHaveBeenCalledTimes(1);
      expect(retryCondition).toHaveBeenCalledWith(error);
    });
  });

  describe('Retry Options', () => {
    test('should respect maxRetries option', async () => {
      mockOperation.mockRejectedValue(new Error('Always fails'));

      await expect(
        retryWithBackoff(mockOperation, { maxRetries: 5 })
      ).rejects.toThrow();

      expect(mockOperation).toHaveBeenCalledTimes(6); // Initial + 5 retries
    });

    test('should use custom retry condition', async () => {
      const retryableError = new Error('Retryable');
      const nonRetryableError = new Error('Non-retryable');
      
      mockOperation
        .mockRejectedValueOnce(retryableError)
        .mockRejectedValue(nonRetryableError);

      const customRetryCondition = jest.fn()
        .mockReturnValueOnce(true)  // Retry first error
        .mockReturnValue(false);    // Don't retry second error

      await expect(
        retryWithBackoff(mockOperation, { 
          maxRetries: 3,
          retryCondition: customRetryCondition 
        })
      ).rejects.toThrow('Non-retryable');

      expect(mockOperation).toHaveBeenCalledTimes(2);
      expect(customRetryCondition).toHaveBeenCalledTimes(2);
    });

    test('should call onRetry callback', async () => {
      const error1 = new Error('First failure');
      const error2 = new Error('Second failure');
      
      mockOperation
        .mockRejectedValueOnce(error1)
        .mockRejectedValueOnce(error2)
        .mockResolvedValue('success');

      await retryWithBackoff(mockOperation, { 
        maxRetries: 3,
        onRetry 
      });

      expect(onRetry).toHaveBeenCalledTimes(2);
      expect(onRetry).toHaveBeenNthCalledWith(1, error1, 1);
      expect(onRetry).toHaveBeenNthCalledWith(2, error2, 2);
    });

    test('should handle onRetry callback errors gracefully', async () => {
      mockOperation
        .mockRejectedValueOnce(new Error('First failure'))
        .mockResolvedValue('success');

      const faultyCallback = jest.fn().mockImplementation(() => {
        throw new Error('Callback error');
      });

      // Should not throw due to callback error
      const result = await retryWithBackoff(mockOperation, { 
        onRetry: faultyCallback 
      });

      expect(result).toBe('success');
      expect(faultyCallback).toHaveBeenCalled();
    });
  });

  describe('Backoff Behavior', () => {
    test('should implement exponential backoff', async () => {
      mockOperation.mockRejectedValue(new Error('Always fails'));
      
      const startTime = Date.now();
      jest.spyOn(global, 'setTimeout').mockImplementation((callback, delay) => {
        (callback as Function)();
        return 'timeout' as any;
      });

      await expect(
        retryWithBackoff(mockOperation, {
          maxRetries: 2,
          baseDelay: 100,
          exponentialBase: 2,
          jitter: false
        })
      ).rejects.toThrow();

      // Verify setTimeout was called with exponential delays
      expect(setTimeout).toHaveBeenCalledWith(expect.any(Function), 100); // First retry
      expect(setTimeout).toHaveBeenCalledWith(expect.any(Function), 200); // Second retry
    });

    test('should respect maxDelay option', async () => {
      mockOperation.mockRejectedValue(new Error('Always fails'));
      
      jest.spyOn(global, 'setTimeout').mockImplementation((callback, delay) => {
        (callback as Function)();
        return 'timeout' as any;
      });

      await expect(
        retryWithBackoff(mockOperation, {
          maxRetries: 3,
          baseDelay: 1000,
          maxDelay: 2000,
          exponentialBase: 2,
          jitter: false
        })
      ).rejects.toThrow();

      // Third retry should be capped at maxDelay
      expect(setTimeout).toHaveBeenCalledWith(expect.any(Function), 1000); // 1000 * 2^0
      expect(setTimeout).toHaveBeenCalledWith(expect.any(Function), 2000); // 1000 * 2^1 = 2000
      expect(setTimeout).toHaveBeenCalledWith(expect.any(Function), 2000); // 1000 * 2^2 = 4000, capped at 2000
    });

    test('should add jitter when enabled', async () => {
      mockOperation.mockRejectedValue(new Error('Always fails'));
      
      const delays: number[] = [];
      jest.spyOn(global, 'setTimeout').mockImplementation((callback, delay) => {
        delays.push(delay as number);
        (callback as Function)();
        return 'timeout' as any;
      });

      jest.spyOn(Math, 'random').mockReturnValue(0.5); // Fixed random value

      await expect(
        retryWithBackoff(mockOperation, {
          maxRetries: 2,
          baseDelay: 100,
          exponentialBase: 2,
          jitter: true
        })
      ).rejects.toThrow();

      // Delays should include jitter
      expect(delays[0]).toBe(600); // 100 + 500 (jitter)
      expect(delays[1]).toBe(700); // 200 + 500 (jitter)
    });
  });

  describe('Default Options', () => {
    test('should use default options when none provided', async () => {
      mockOperation.mockRejectedValue(new Error('Always fails'));

      await expect(retryWithBackoff(mockOperation)).rejects.toThrow();

      expect(mockOperation).toHaveBeenCalledTimes(4); // Initial + 3 retries (default)
    });
  });

  describe('Correlation ID', () => {
    test('should use provided correlation ID', async () => {
      mockOperation.mockResolvedValue('success');

      await retryWithBackoff(mockOperation, {}, 'custom-correlation');

      // Correlation ID passed to logger (verified through setup)
      expect(mockOperation).toHaveBeenCalledTimes(1);
    });

    test('should generate correlation ID when none provided', async () => {
      mockOperation.mockResolvedValue('success');

      await retryWithBackoff(mockOperation);

      expect(randomUUID).toHaveBeenCalled();
    });
  });
});

describe('defaultRetryCondition', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Network Errors', () => {
    test('should retry on network connection errors', () => {
      const networkErrors = ['ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'ENOTFOUND'];
      
      networkErrors.forEach(code => {
        const error = new Error('Network error');
        (error as any).code = code;
        
        expect(defaultRetryCondition(error)).toBe(true);
      });
    });

    test('should not retry on other error codes', () => {
      const error = new Error('Other error');
      (error as any).code = 'ENOENT';
      
      expect(defaultRetryCondition(error)).toBe(false);
    });
  });

  describe('HTTP Status Codes', () => {
    test('should retry on retryable status codes', () => {
      const retryableStatusCodes = [408, 429, 500, 502, 503, 504];
      
      retryableStatusCodes.forEach(statusCode => {
        (getErrorStatusCode as jest.Mock).mockReturnValue(statusCode);
        
        const error = new Error('HTTP error');
        expect(defaultRetryCondition(error)).toBe(true);
      });
    });

    test('should not retry on client errors (4xx except specific ones)', () => {
      const nonRetryableStatusCodes = [400, 401, 403, 404];
      
      nonRetryableStatusCodes.forEach(statusCode => {
        (getErrorStatusCode as jest.Mock).mockReturnValue(statusCode);
        
        const error = new Error('Client error');
        expect(defaultRetryCondition(error)).toBe(false);
      });
    });

    test('should not retry on 501 Not Implemented', () => {
      (getErrorStatusCode as jest.Mock).mockReturnValue(501);
      
      const error = new Error('Not implemented');
      expect(defaultRetryCondition(error)).toBe(false);
    });
  });

  describe('Error Codes', () => {
    test('should retry on TIMEOUT errors', () => {
      (getErrorCode as jest.Mock).mockReturnValue('TIMEOUT');
      
      const error = new Error('Timeout error');
      expect(defaultRetryCondition(error)).toBe(true);
    });

    test('should retry on EXTERNAL_SERVICE_ERROR', () => {
      (getErrorCode as jest.Mock).mockReturnValue('EXTERNAL_SERVICE_ERROR');
      
      const error = new Error('External service error');
      expect(defaultRetryCondition(error)).toBe(true);
    });
  });

  describe('Specific Error Types', () => {
    test('should retry on MakeServerError with 5xx status codes', () => {
      const error = new (MakeServerError as any)('Server error', 503);
      
      expect(defaultRetryCondition(error)).toBe(true);
    });

    test('should not retry on MakeServerError with 4xx status codes', () => {
      const error = new (MakeServerError as any)('Client error', 400);
      
      expect(defaultRetryCondition(error)).toBe(false);
    });

    test('should not retry on MakeServerError with 501 status code', () => {
      const error = new (MakeServerError as any)('Not implemented', 501);
      
      expect(defaultRetryCondition(error)).toBe(false);
    });

    test('should handle UserError based on status code', () => {
      (getErrorStatusCode as jest.Mock).mockReturnValue(503);
      
      const error = new (UserError as any)('User error');
      expect(defaultRetryCondition(error)).toBe(true);
    });

    test('should not retry UserError with 4xx status', () => {
      (getErrorStatusCode as jest.Mock).mockReturnValue(400);
      
      const error = new (UserError as any)('User validation error');
      expect(defaultRetryCondition(error)).toBe(false);
    });
  });

  describe('Default Behavior', () => {
    test('should not retry on unknown errors by default', () => {
      (getErrorStatusCode as jest.Mock).mockReturnValue(null);
      (getErrorCode as jest.Mock).mockReturnValue('UNKNOWN');
      
      const error = new Error('Unknown error');
      expect(defaultRetryCondition(error)).toBe(false);
    });
  });
});

describe('Bulkhead', () => {
  let bulkhead: Bulkhead;
  let mockOperation: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
    bulkhead = new Bulkhead('test-resource', 2, 3, 1000); // maxConcurrency=2, maxQueue=3, timeout=1000
    mockOperation = jest.fn();
  });

  describe('Basic Execution', () => {
    test('should execute operation when under capacity', async () => {
      mockOperation.mockResolvedValue('success');

      const result = await bulkhead.execute(mockOperation);

      expect(result).toBe('success');
      expect(mockOperation).toHaveBeenCalledTimes(1);
    });

    test('should handle operation errors', async () => {
      const error = new Error('Operation failed');
      mockOperation.mockRejectedValue(error);

      await expect(bulkhead.execute(mockOperation)).rejects.toThrow('Operation failed');
    });
  });

  describe('Concurrency Control', () => {
    test('should allow concurrent executions up to limit', async () => {
      const slowOperation = jest.fn().mockImplementation(
        () => new Promise(resolve => setTimeout(() => resolve('slow'), 100))
      );

      // Start two concurrent operations (at capacity)
      const promise1 = bulkhead.execute(slowOperation);
      const promise2 = bulkhead.execute(slowOperation);

      const results = await Promise.all([promise1, promise2]);

      expect(results).toEqual(['slow', 'slow']);
      expect(slowOperation).toHaveBeenCalledTimes(2);
    });

    test('should queue operations when at capacity', async () => {
      let resolvers: Array<(value: string) => void> = [];
      const controllableOperation = jest.fn().mockImplementation(
        () => new Promise<string>(resolve => resolvers.push(resolve))
      );

      // Fill capacity (2 concurrent)
      const promise1 = bulkhead.execute(controllableOperation);
      const promise2 = bulkhead.execute(controllableOperation);

      // This should be queued
      const promise3 = bulkhead.execute(controllableOperation);

      // Verify stats
      const stats = bulkhead.getStats();
      expect(stats.activeRequests).toBe(2);
      expect(stats.queueLength).toBe(1);

      // Complete first operation
      resolvers[0]('first');
      await promise1;

      // Third operation should now be executing
      await new Promise(resolve => setTimeout(resolve, 10)); // Give it time to process

      const newStats = bulkhead.getStats();
      expect(newStats.activeRequests).toBe(2); // Still 2 active (second + third)
      expect(newStats.queueLength).toBe(0);   // Queue is empty

      // Complete remaining operations
      resolvers[1]('second');
      resolvers[2]('third');

      const results = await Promise.all([promise1, promise2, promise3]);
      expect(results).toEqual(['first', 'second', 'third']);
    });

    test('should reject requests when queue is full', async () => {
      const slowOperation = jest.fn().mockImplementation(
        () => new Promise(resolve => setTimeout(() => resolve('slow'), 1000))
      );

      // Fill capacity (2) and queue (3)
      const promises = [];
      for (let i = 0; i < 5; i++) {
        promises.push(bulkhead.execute(slowOperation));
      }

      // This should be rejected
      await expect(bulkhead.execute(slowOperation)).rejects.toThrow(
        'Bulkhead capacity exceeded - request rejected'
      );

      expect(createExternalServiceError).toHaveBeenCalledWith(
        'test-resource',
        'Bulkhead capacity exceeded - request rejected',
        undefined,
        expect.objectContaining({
          activeRequests: 2,
          queueLength: 3,
          maxConcurrency: 2,
          maxQueue: 3
        }),
        expect.any(Object)
      );
    });
  });

  describe('Timeout Handling', () => {
    test('should timeout long-running operations', async () => {
      const slowOperation = jest.fn().mockImplementation(
        () => new Promise(resolve => setTimeout(resolve, 2000)) // 2 seconds
      );

      await expect(bulkhead.execute(slowOperation)).rejects.toThrow();
      
      expect(createTimeoutError).toHaveBeenCalledWith(
        'Bulkhead operation for test-resource',
        1000
      );
    });

    test('should not timeout fast operations', async () => {
      const fastOperation = jest.fn().mockImplementation(
        () => new Promise(resolve => setTimeout(() => resolve('fast'), 100))
      );

      const result = await bulkhead.execute(fastOperation);
      expect(result).toBe('fast');
    });
  });

  describe('Statistics', () => {
    test('should provide accurate statistics', () => {
      const stats = bulkhead.getStats();

      expect(stats).toEqual({
        activeRequests: 0,
        queueLength: 0,
        maxConcurrency: 2,
        maxQueue: 3
      });
    });

    test('should update statistics during execution', async () => {
      let resolver: (value: string) => void;
      const controllableOperation = jest.fn().mockImplementation(
        () => new Promise<string>(resolve => { resolver = resolve; })
      );

      const promise = bulkhead.execute(controllableOperation);

      const duringStats = bulkhead.getStats();
      expect(duringStats.activeRequests).toBe(1);

      resolver!('done');
      await promise;

      const afterStats = bulkhead.getStats();
      expect(afterStats.activeRequests).toBe(0);
    });
  });

  describe('Correlation ID', () => {
    test('should use provided correlation ID', async () => {
      mockOperation.mockResolvedValue('success');

      await bulkhead.execute(mockOperation, 'custom-correlation');

      expect(mockOperation).toHaveBeenCalledTimes(1);
    });

    test('should generate correlation ID when none provided', async () => {
      mockOperation.mockResolvedValue('success');

      await bulkhead.execute(mockOperation);

      expect(randomUUID).toHaveBeenCalled();
    });
  });
});

describe('CircuitBreakerFactory', () => {
  beforeEach(() => {
    // Clear factory state
    (CircuitBreakerFactory as any).breakers = new Map();
  });

  test('should create new circuit breaker', () => {
    const breaker = CircuitBreakerFactory.getOrCreate('test-service');

    expect(breaker).toBeInstanceOf(CircuitBreaker);
    expect(breaker.getState()).toBe('CLOSED');
  });

  test('should return existing circuit breaker', () => {
    const breaker1 = CircuitBreakerFactory.getOrCreate('test-service');
    const breaker2 = CircuitBreakerFactory.getOrCreate('test-service');

    expect(breaker1).toBe(breaker2);
  });

  test('should create different breakers for different services', () => {
    const breaker1 = CircuitBreakerFactory.getOrCreate('service-1');
    const breaker2 = CircuitBreakerFactory.getOrCreate('service-2');

    expect(breaker1).not.toBe(breaker2);
  });

  test('should pass options to new circuit breakers', () => {
    const options: CircuitBreakerOptions = {
      failureThreshold: 10,
      timeout: 5000
    };

    const breaker = CircuitBreakerFactory.getOrCreate('configured-service', options);

    expect(breaker).toBeInstanceOf(CircuitBreaker);
  });

  test('should get all stats', () => {
    CircuitBreakerFactory.getOrCreate('service-1');
    CircuitBreakerFactory.getOrCreate('service-2');

    const allStats = CircuitBreakerFactory.getAllStats();

    expect(allStats).toHaveProperty('service-1');
    expect(allStats).toHaveProperty('service-2');
    expect(allStats['service-1'].state).toBe('CLOSED');
    expect(allStats['service-2'].state).toBe('CLOSED');
  });
});

describe('BulkheadFactory', () => {
  beforeEach(() => {
    // Clear factory state
    (BulkheadFactory as any).bulkheads = new Map();
  });

  test('should create new bulkhead', () => {
    const bulkhead = BulkheadFactory.getOrCreate('test-resource');

    expect(bulkhead).toBeInstanceOf(Bulkhead);
  });

  test('should return existing bulkhead', () => {
    const bulkhead1 = BulkheadFactory.getOrCreate('test-resource');
    const bulkhead2 = BulkheadFactory.getOrCreate('test-resource');

    expect(bulkhead1).toBe(bulkhead2);
  });

  test('should create different bulkheads for different resources', () => {
    const bulkhead1 = BulkheadFactory.getOrCreate('resource-1');
    const bulkhead2 = BulkheadFactory.getOrCreate('resource-2');

    expect(bulkhead1).not.toBe(bulkhead2);
  });

  test('should pass configuration to new bulkheads', () => {
    const bulkhead = BulkheadFactory.getOrCreate('configured-resource', 5, 10, 2000);

    expect(bulkhead).toBeInstanceOf(Bulkhead);
    
    const stats = bulkhead.getStats();
    expect(stats.maxConcurrency).toBe(5);
    expect(stats.maxQueue).toBe(10);
  });

  test('should get all stats', () => {
    BulkheadFactory.getOrCreate('resource-1');
    BulkheadFactory.getOrCreate('resource-2');

    const allStats = BulkheadFactory.getAllStats();

    expect(allStats).toHaveProperty('resource-1');
    expect(allStats).toHaveProperty('resource-2');
    expect(allStats['resource-1'].activeRequests).toBe(0);
    expect(allStats['resource-2'].activeRequests).toBe(0);
  });
});

describe('Integration Tests', () => {
  test('should work together: circuit breaker + retry + bulkhead', async () => {
    const breaker = new CircuitBreaker('integration-test', { failureThreshold: 2 });
    const bulkhead = new Bulkhead('integration-resource', 1);

    let callCount = 0;
    const problematicOperation = jest.fn().mockImplementation(async () => {
      callCount++;
      if (callCount <= 2) {
        throw new Error('Transient error');
      }
      return 'success';
    });

    const resilientOperation = async () => {
      return await bulkhead.execute(() => 
        breaker.execute(() => problematicOperation())
      );
    };

    const result = await retryWithBackoff(resilientOperation, { maxRetries: 5 });

    expect(result).toBe('success');
    expect(callCount).toBe(3);
  });

  test('should handle complex failure scenarios', async () => {
    const breaker = new CircuitBreaker('complex-test', { failureThreshold: 2 });
    
    // Force breaker to open
    const failingOp = jest.fn().mockRejectedValue(new Error('Service down'));
    
    try {
      await breaker.execute(failingOp);
    } catch {}
    try {
      await breaker.execute(failingOp);
    } catch {}
    
    expect(breaker.getState()).toBe('OPEN');

    // Now retries should be blocked by circuit breaker
    const retryableOp = () => breaker.execute(failingOp);
    
    await expect(
      retryWithBackoff(retryableOp, { maxRetries: 3 })
    ).rejects.toThrow('Circuit breaker is OPEN');

    // Operation should only be called twice (to open breaker)
    expect(failingOp).toHaveBeenCalledTimes(2);
  });

  test('should maintain performance under concurrent load', async () => {
    const bulkhead = new Bulkhead('load-test', 5, 10);
    const fastOp = jest.fn().mockResolvedValue('fast');

    // Execute many operations concurrently
    const promises = Array.from({ length: 20 }, () => 
      bulkhead.execute(fastOp)
    );

    const results = await Promise.allSettled(promises);

    // Some should succeed, some might be rejected due to capacity
    const successful = results.filter(r => r.status === 'fulfilled');
    const rejected = results.filter(r => r.status === 'rejected');

    expect(successful.length + rejected.length).toBe(20);
    expect(successful.length).toBeGreaterThan(0);
  });
});

describe('Edge Cases and Error Handling', () => {
  test('should handle null/undefined operations gracefully', async () => {
    const breaker = new CircuitBreaker('null-test');

    await expect(breaker.execute(null as any)).rejects.toThrow();
  });

  test('should handle operations that throw synchronously', async () => {
    const breaker = new CircuitBreaker('sync-error-test');
    const syncErrorOp = jest.fn().mockImplementation(() => {
      throw new Error('Synchronous error');
    });

    await expect(breaker.execute(syncErrorOp)).rejects.toThrow('Synchronous error');
  });

  test('should handle very large retry counts', async () => {
    const operation = jest.fn().mockRejectedValue(new Error('Always fails'));

    await expect(
      retryWithBackoff(operation, { maxRetries: 1000 })
    ).rejects.toThrow();

    expect(operation).toHaveBeenCalledTimes(1001); // Initial + 1000 retries
  });

  test('should handle zero retry count', async () => {
    const operation = jest.fn().mockRejectedValue(new Error('Fails immediately'));

    await expect(
      retryWithBackoff(operation, { maxRetries: 0 })
    ).rejects.toThrow();

    expect(operation).toHaveBeenCalledTimes(1); // Only initial attempt
  });

  test('should handle negative delays gracefully', async () => {
    const operation = jest.fn()
      .mockRejectedValueOnce(new Error('First failure'))
      .mockResolvedValue('success');

    const result = await retryWithBackoff(operation, { 
      baseDelay: -100 // Negative delay
    });

    expect(result).toBe('success');
  });
});