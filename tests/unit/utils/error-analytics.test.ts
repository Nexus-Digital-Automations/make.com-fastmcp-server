/**
 * Comprehensive Unit Tests for Error Analytics Module
 * 
 * Tests all functionality including error recording, performance monitoring,
 * analytics data generation, metrics calculation, and singleton behavior.
 * Covers edge cases, error scenarios, and integration with error types.
 */

import { jest } from '@jest/globals';
import { randomUUID } from 'crypto';
import {
  ErrorAnalytics,
  errorAnalytics,
  createErrorAnalyticsMiddleware,
  monitorPerformance,
  type ErrorMetrics,
  type ErrorEvent,
  type PerformanceMetrics
} from '../../../src/utils/error-analytics';
import { 
  MakeServerError, 
  UserError, 
  EnhancedUserError,
  ErrorContext,
  getErrorCode,
  getErrorStatusCode,
  getErrorCorrelationId
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
    public context?: any;
    constructor(message: string, context?: any) {
      super(message);
      this.name = 'MakeServerError';
      this.context = context;
    }
  },
  UserError: class MockUserError extends Error {
    constructor(message: string) {
      super(message);
      this.name = 'UserError';
    }
  },
  EnhancedUserError: class MockEnhancedUserError extends Error {
    public context?: any;
    constructor(message: string, context?: any) {
      super(message);
      this.name = 'EnhancedUserError';
      this.context = context;
    }
  },
  getErrorCode: jest.fn((error: Error) => error.name || 'UNKNOWN_ERROR'),
  getErrorStatusCode: jest.fn((error: Error) => {
    if (error.name === 'UserError') return 400;
    if (error.name === 'MakeServerError') return 500;
    return 500;
  }),
  getErrorCorrelationId: jest.fn((error: Error) => {
    if ('correlationId' in error) return (error as any).correlationId;
    return null;
  })
}));

describe('ErrorAnalytics', () => {
  let analytics: ErrorAnalytics;
  
  beforeEach(() => {
    // Reset singleton instance
    (ErrorAnalytics as any).instance = undefined;
    analytics = ErrorAnalytics.getInstance();
    
    // Reset analytics data
    analytics.reset();
    
    // Clear all mocks
    jest.clearAllMocks();
    
    // Mock Date.now to control time
    jest.spyOn(Date, 'now').mockReturnValue(1000000000); // Fixed timestamp
    jest.spyOn(global, 'setInterval').mockImplementation((callback: any, delay: number) => {
      return 'mock-interval' as any;
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Singleton Pattern', () => {
    test('should return the same instance', () => {
      const instance1 = ErrorAnalytics.getInstance();
      const instance2 = ErrorAnalytics.getInstance();
      
      expect(instance1).toBe(instance2);
    });

    test('should maintain data across getInstance calls', () => {
      const instance1 = ErrorAnalytics.getInstance();
      instance1.recordError(new Error('Test error'));
      
      const instance2 = ErrorAnalytics.getInstance();
      const metrics = instance2.getErrorMetrics();
      
      expect(metrics.totalErrors).toBe(1);
    });
  });

  describe('Error Recording', () => {
    test('should record basic Error successfully', () => {
      const error = new Error('Basic error message');
      
      analytics.recordError(error);
      
      const metrics = analytics.getErrorMetrics();
      expect(metrics.totalErrors).toBe(1);
      expect(metrics.recentErrors).toHaveLength(1);
      
      const recordedError = metrics.recentErrors[0];
      expect(recordedError.message).toBe('Basic error message');
      expect(recordedError.code).toBe('Error');
      expect(recordedError.statusCode).toBe(500);
      expect(recordedError.correlationId).toBe('test-uuid-123');
      expect(recordedError.resolved).toBe(false);
    });

    test('should record MakeServerError with context', () => {
      const context: ErrorContext = {
        userId: 'user123',
        operation: 'test-operation',
        timestamp: new Date().toISOString()
      };
      const error = new (MakeServerError as any)('Server error', context);
      
      analytics.recordError(error, {
        component: 'test-component',
        operation: 'server-operation',
        userId: 'user456',
        sessionId: 'session123',
        duration: 150
      });
      
      const metrics = analytics.getErrorMetrics();
      const recordedError = metrics.recentErrors[0];
      
      expect(recordedError.message).toBe('Server error');
      expect(recordedError.code).toBe('MakeServerError');
      expect(recordedError.statusCode).toBe(500);
      expect(recordedError.component).toBe('test-component');
      expect(recordedError.operation).toBe('server-operation');
      expect(recordedError.userId).toBe('user456');
      expect(recordedError.sessionId).toBe('session123');
      expect(recordedError.duration).toBe(150);
      expect(recordedError.context).toEqual(context);
    });

    test('should record UserError correctly', () => {
      const error = new (UserError as any)('User input error');
      
      analytics.recordError(error);
      
      const metrics = analytics.getErrorMetrics();
      const recordedError = metrics.recentErrors[0];
      
      expect(recordedError.message).toBe('User input error');
      expect(recordedError.code).toBe('UserError');
      expect(recordedError.statusCode).toBe(400);
    });

    test('should record EnhancedUserError with context', () => {
      const errorContext: ErrorContext = {
        userId: 'user789',
        operation: 'validation',
        timestamp: new Date().toISOString()
      };
      const error = new (EnhancedUserError as any)('Enhanced user error', errorContext);
      
      analytics.recordError(error);
      
      const metrics = analytics.getErrorMetrics();
      const recordedError = metrics.recentErrors[0];
      
      expect(recordedError.message).toBe('Enhanced user error');
      expect(recordedError.code).toBe('EnhancedUserError');
      expect(recordedError.context).toEqual(errorContext);
    });

    test('should use existing correlationId from error', () => {
      const error = new Error('Test error');
      (error as any).correlationId = 'existing-correlation-123';
      
      // Mock getErrorCorrelationId to return the existing ID
      (getErrorCorrelationId as jest.Mock).mockReturnValue('existing-correlation-123');
      
      analytics.recordError(error);
      
      const metrics = analytics.getErrorMetrics();
      const recordedError = metrics.recentErrors[0];
      
      expect(recordedError.correlationId).toBe('existing-correlation-123');
    });

    test('should generate new correlationId if none exists', () => {
      const error = new Error('Test error');
      
      // Mock getErrorCorrelationId to return null
      (getErrorCorrelationId as jest.Mock).mockReturnValue(null);
      
      analytics.recordError(error);
      
      const metrics = analytics.getErrorMetrics();
      const recordedError = metrics.recentErrors[0];
      
      expect(recordedError.correlationId).toBe('test-uuid-123');
    });

    test('should limit stored events to maxEvents', () => {
      // Record more than maxEvents (1000) errors
      for (let i = 0; i < 1005; i++) {
        analytics.recordError(new Error(`Error ${i}`));
      }
      
      const metrics = analytics.getErrorMetrics();
      expect(metrics.totalErrors).toBe(1000); // Should be limited to maxEvents
    });

    test('should handle null/undefined context gracefully', () => {
      const error = new Error('Test error');
      
      analytics.recordError(error, undefined);
      
      const metrics = analytics.getErrorMetrics();
      expect(metrics.totalErrors).toBe(1);
      expect(metrics.recentErrors[0].component).toBeUndefined();
    });
  });

  describe('Performance Recording', () => {
    test('should record performance data successfully', () => {
      analytics.recordPerformance(150);
      analytics.recordPerformance(200);
      analytics.recordPerformance(120);
      
      const metrics = analytics.getPerformanceMetrics();
      expect(metrics.averageResponseTime).toBe((150 + 200 + 120) / 3);
      expect(metrics.throughput).toBeGreaterThan(0);
    });

    test('should calculate percentiles correctly', () => {
      // Record performance data with known values
      const durations = [100, 150, 200, 250, 300, 350, 400, 450, 500, 1000];
      durations.forEach(duration => analytics.recordPerformance(duration));
      
      const metrics = analytics.getPerformanceMetrics();
      
      // Check that percentiles are calculated
      expect(metrics.p95ResponseTime).toBeGreaterThan(metrics.averageResponseTime);
      expect(metrics.p99ResponseTime).toBeGreaterThan(metrics.p95ResponseTime);
    });

    test('should filter old performance data', () => {
      // Mock Date.now to simulate time passing
      let currentTime = 1000000000;
      jest.spyOn(Date, 'now').mockImplementation(() => currentTime);
      
      // Record performance data
      analytics.recordPerformance(100);
      
      // Move time forward by more than 1 hour (3600000ms)
      currentTime += 3700000;
      
      // Record new performance data
      analytics.recordPerformance(200);
      
      const metrics = analytics.getPerformanceMetrics();
      
      // Should only include recent data
      expect(metrics.averageResponseTime).toBe(200);
    });

    test('should handle empty performance data', () => {
      const metrics = analytics.getPerformanceMetrics();
      
      expect(metrics.averageResponseTime).toBe(0);
      expect(metrics.p95ResponseTime).toBe(0);
      expect(metrics.p99ResponseTime).toBe(0);
      expect(metrics.throughput).toBe(0);
      expect(metrics.memoryUsage).toBeDefined();
      expect(metrics.cpuUsage).toBeDefined();
    });
  });

  describe('Error Resolution', () => {
    test('should resolve error successfully', () => {
      const error = new Error('Test error');
      analytics.recordError(error);
      
      const metrics = analytics.getErrorMetrics();
      const errorId = metrics.recentErrors[0].id;
      
      analytics.resolveError(errorId);
      
      const updatedMetrics = analytics.getErrorMetrics();
      const resolvedError = updatedMetrics.recentErrors[0];
      
      expect(resolvedError.resolved).toBe(true);
      expect(resolvedError.resolvedAt).toBeDefined();
    });

    test('should not resolve already resolved error', () => {
      const error = new Error('Test error');
      analytics.recordError(error);
      
      const metrics = analytics.getErrorMetrics();
      const errorId = metrics.recentErrors[0].id;
      
      // Resolve once
      analytics.resolveError(errorId);
      const firstResolveTime = analytics.getErrorMetrics().recentErrors[0].resolvedAt;
      
      // Try to resolve again
      analytics.resolveError(errorId);
      const secondResolveTime = analytics.getErrorMetrics().recentErrors[0].resolvedAt;
      
      expect(firstResolveTime).toBe(secondResolveTime);
    });

    test('should handle non-existent error ID gracefully', () => {
      analytics.resolveError('non-existent-id');
      
      // Should not throw error
      expect(() => analytics.resolveError('non-existent-id')).not.toThrow();
    });
  });

  describe('Error Metrics', () => {
    beforeEach(() => {
      // Setup test data
      const errors = [
        { error: new Error('Network error'), context: { component: 'network' } },
        { error: new (UserError as any)('Validation error'), context: { component: 'validation' } },
        { error: new Error('Network error'), context: { component: 'network' } },
        { error: new (MakeServerError as any)('Server error'), context: { component: 'server' } }
      ];
      
      errors.forEach(({ error, context }) => {
        analytics.recordError(error, context);
      });
    });

    test('should calculate error counts by code correctly', () => {
      const metrics = analytics.getErrorMetrics();
      
      expect(metrics.errorsByCode['Error']).toBe(2);
      expect(metrics.errorsByCode['UserError']).toBe(1);
      expect(metrics.errorsByCode['MakeServerError']).toBe(1);
    });

    test('should calculate error counts by component correctly', () => {
      const metrics = analytics.getErrorMetrics();
      
      expect(metrics.errorsByComponent['network']).toBe(2);
      expect(metrics.errorsByComponent['validation']).toBe(1);
      expect(metrics.errorsByComponent['server']).toBe(1);
    });

    test('should calculate error counts by status code correctly', () => {
      const metrics = analytics.getErrorMetrics();
      
      expect(metrics.errorsByStatusCode['500']).toBe(3); // Error and MakeServerError
      expect(metrics.errorsByStatusCode['400']).toBe(1); // UserError
    });

    test('should calculate error rate correctly', () => {
      const metrics = analytics.getErrorMetrics();
      
      expect(metrics.errorRate).toBe(4 / 60); // 4 errors per minute
    });

    test('should calculate uptime correctly', () => {
      // Mock start time to be 10 seconds ago
      const analytics2 = new (ErrorAnalytics as any)();
      analytics2.reset();
      
      jest.spyOn(Date, 'now').mockReturnValue(1000000000 + 10000); // 10 seconds later
      
      const metrics = analytics2.getErrorMetrics();
      expect(metrics.uptime).toBe(10); // 10 seconds
    });

    test('should limit recent errors to 50', () => {
      // Add many errors
      for (let i = 0; i < 60; i++) {
        analytics.recordError(new Error(`Error ${i}`));
      }
      
      const metrics = analytics.getErrorMetrics();
      expect(metrics.recentErrors.length).toBe(50);
    });
  });

  describe('Error Trends', () => {
    test('should calculate error trends correctly', () => {
      // Mock time to a specific point
      const baseTime = 1609459200000; // Jan 1, 2021 00:00:00 UTC
      jest.spyOn(Date, 'now').mockReturnValue(baseTime);
      
      // Record errors at different times
      const errorTimes = [
        baseTime - 3600000, // 1 hour ago
        baseTime - 1800000, // 30 minutes ago
        baseTime - 1800000, // 30 minutes ago (same hour)
        baseTime - 900000,  // 15 minutes ago
      ];
      
      errorTimes.forEach((time, index) => {
        jest.spyOn(Date, 'now').mockReturnValue(time);
        analytics.recordError(new Error(`Error ${index}`));
      });
      
      // Reset time to current
      jest.spyOn(Date, 'now').mockReturnValue(baseTime);
      
      const trends = analytics.getErrorTrends(2); // Last 2 hours
      
      expect(trends).toHaveLength(2);
      expect(trends.some(trend => trend.errorCount > 0)).toBe(true);
    });

    test('should handle empty time ranges', () => {
      const trends = analytics.getErrorTrends(1);
      
      expect(trends).toHaveLength(1);
      expect(trends[0].errorCount).toBe(0);
      expect(trends[0].errorRate).toBe(0);
    });

    test('should group errors by hour correctly', () => {
      const baseTime = 1609459200000; // Jan 1, 2021 00:00:00 UTC
      
      // Record multiple errors in the same hour
      [0, 1800000, 3000000].forEach((offset) => {
        jest.spyOn(Date, 'now').mockReturnValue(baseTime + offset);
        analytics.recordError(new Error('Same hour error'));
      });
      
      jest.spyOn(Date, 'now').mockReturnValue(baseTime + 3600000); // 1 hour later
      
      const trends = analytics.getErrorTrends(1);
      
      expect(trends[0].errorCount).toBe(3);
    });
  });

  describe('Error Patterns', () => {
    test('should identify top error patterns correctly', () => {
      // Record errors with different patterns
      analytics.recordError(new Error('Network timeout'), { component: 'api' });
      analytics.recordError(new Error('Network timeout'), { component: 'db' });
      analytics.recordError(new Error('Network timeout'), { component: 'api' });
      analytics.recordError(new Error('Validation failed'), { component: 'input' });
      analytics.recordError(new Error('Validation failed'), { component: 'form' });
      
      const patterns = analytics.getTopErrorPatterns();
      
      expect(patterns).toHaveLength(2);
      
      // Most frequent pattern should be first
      expect(patterns[0].pattern).toBe('Error: Network timeout');
      expect(patterns[0].count).toBe(3);
      expect(patterns[0].percentage).toBe(60); // 3/5 * 100
      expect(patterns[0].components).toEqual(['api', 'db']);
      
      expect(patterns[1].pattern).toBe('Error: Validation failed');
      expect(patterns[1].count).toBe(2);
      expect(patterns[1].percentage).toBe(40); // 2/5 * 100
      expect(patterns[1].components).toEqual(['input', 'form']);
    });

    test('should respect limit parameter', () => {
      // Record many different errors
      for (let i = 0; i < 15; i++) {
        analytics.recordError(new Error(`Unique error ${i}`));
      }
      
      const patterns = analytics.getTopErrorPatterns(5);
      expect(patterns).toHaveLength(5);
    });

    test('should handle empty error list', () => {
      const patterns = analytics.getTopErrorPatterns();
      expect(patterns).toHaveLength(0);
    });

    test('should update last occurrence correctly', () => {
      const error = new Error('Test error');
      
      // Record error at different times
      jest.spyOn(Date, 'now').mockReturnValue(1000000000);
      analytics.recordError(error);
      
      jest.spyOn(Date, 'now').mockReturnValue(1000001000);
      analytics.recordError(error);
      
      const patterns = analytics.getTopErrorPatterns();
      
      expect(patterns[0].count).toBe(2);
      expect(new Date(patterns[0].lastOccurrence).getTime()).toBe(1000001000);
    });
  });

  describe('Export Analytics', () => {
    test('should export complete analytics data', () => {
      // Setup test data
      analytics.recordError(new Error('Test error'));
      analytics.recordPerformance(100);
      
      const exported = analytics.exportAnalytics();
      
      expect(exported).toHaveProperty('timestamp');
      expect(exported).toHaveProperty('metrics');
      expect(exported).toHaveProperty('performance');
      expect(exported).toHaveProperty('trends');
      expect(exported).toHaveProperty('patterns');
      
      expect(exported.metrics.totalErrors).toBe(1);
      expect(exported.performance.averageResponseTime).toBe(100);
    });

    test('should include timestamp in ISO format', () => {
      const exported = analytics.exportAnalytics();
      
      expect(exported.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    });
  });

  describe('Cleanup Functionality', () => {
    test('should clean up old events', () => {
      // Mock initial time
      const oldTime = 1000000000;
      jest.spyOn(Date, 'now').mockReturnValue(oldTime);
      
      // Record old errors
      analytics.recordError(new Error('Old error 1'));
      analytics.recordError(new Error('Old error 2'));
      
      // Move time forward by more than 24 hours
      const newTime = oldTime + 86400000 + 1000; // 24 hours + 1 second
      jest.spyOn(Date, 'now').mockReturnValue(newTime);
      
      // Record new error
      analytics.recordError(new Error('New error'));
      
      // Manually trigger cleanup
      (analytics as any).cleanupOldEvents();
      
      const metrics = analytics.getErrorMetrics();
      expect(metrics.totalErrors).toBe(1); // Only new error should remain
      expect(metrics.recentErrors[0].message).toBe('New error');
    });

    test('should not clean up recent events', () => {
      // Record recent errors
      analytics.recordError(new Error('Recent error 1'));
      analytics.recordError(new Error('Recent error 2'));
      
      // Trigger cleanup (events are recent, so should not be removed)
      (analytics as any).cleanupOldEvents();
      
      const metrics = analytics.getErrorMetrics();
      expect(metrics.totalErrors).toBe(2);
    });
  });

  describe('Reset Functionality', () => {
    test('should reset all data', () => {
      // Setup data
      analytics.recordError(new Error('Test error'));
      analytics.recordPerformance(100);
      
      // Verify data exists
      let metrics = analytics.getErrorMetrics();
      let performance = analytics.getPerformanceMetrics();
      expect(metrics.totalErrors).toBe(1);
      expect(performance.averageResponseTime).toBe(100);
      
      // Reset
      analytics.reset();
      
      // Verify data is cleared
      metrics = analytics.getErrorMetrics();
      performance = analytics.getPerformanceMetrics();
      expect(metrics.totalErrors).toBe(0);
      expect(performance.averageResponseTime).toBe(0);
    });

    test('should reset start time', () => {
      const oldStartTime = Date.now();
      
      // Advance time
      jest.spyOn(Date, 'now').mockReturnValue(oldStartTime + 10000);
      
      analytics.reset();
      
      const metrics = analytics.getErrorMetrics();
      expect(metrics.uptime).toBe(0);
    });
  });
});

describe('Global Error Analytics Instance', () => {
  test('should export singleton instance', () => {
    expect(errorAnalytics).toBeInstanceOf(ErrorAnalytics);
    expect(errorAnalytics).toBe(ErrorAnalytics.getInstance());
  });
});

describe('Error Analytics Middleware', () => {
  test('should create middleware function', () => {
    const middleware = createErrorAnalyticsMiddleware();
    
    expect(typeof middleware).toBe('function');
  });

  test('should record error when middleware is called', () => {
    const middleware = createErrorAnalyticsMiddleware();
    const error = new Error('Middleware error');
    
    // Reset analytics to get clean state
    errorAnalytics.reset();
    
    middleware(error, {
      component: 'middleware-test',
      operation: 'test-operation'
    });
    
    const metrics = errorAnalytics.getErrorMetrics();
    expect(metrics.totalErrors).toBe(1);
    expect(metrics.recentErrors[0].message).toBe('Middleware error');
    expect(metrics.recentErrors[0].component).toBe('middleware-test');
  });

  test('should handle middleware without context', () => {
    const middleware = createErrorAnalyticsMiddleware();
    const error = new Error('No context error');
    
    errorAnalytics.reset();
    
    middleware(error);
    
    const metrics = errorAnalytics.getErrorMetrics();
    expect(metrics.totalErrors).toBe(1);
    expect(metrics.recentErrors[0].component).toBeUndefined();
  });
});

describe('Performance Monitor Decorator', () => {
  test('should monitor successful async function', async () => {
    const mockFn = jest.fn().mockResolvedValue('success');
    const monitoredFn = monitorPerformance(mockFn, {
      component: 'test-component',
      operation: 'test-operation'
    });
    
    errorAnalytics.reset();
    
    const result = await monitoredFn('arg1', 'arg2');
    
    expect(result).toBe('success');
    expect(mockFn).toHaveBeenCalledWith('arg1', 'arg2');
    
    // Should record performance
    const performance = errorAnalytics.getPerformanceMetrics();
    expect(performance.averageResponseTime).toBeGreaterThan(0);
  });

  test('should monitor and record error from async function', async () => {
    const testError = new Error('Function failed');
    const mockFn = jest.fn().mockRejectedValue(testError);
    const monitoredFn = monitorPerformance(mockFn, {
      component: 'test-component',
      operation: 'test-operation'
    });
    
    errorAnalytics.reset();
    
    await expect(monitoredFn('arg1')).rejects.toThrow('Function failed');
    
    // Should record both error and performance
    const metrics = errorAnalytics.getErrorMetrics();
    const performance = errorAnalytics.getPerformanceMetrics();
    
    expect(metrics.totalErrors).toBe(1);
    expect(metrics.recentErrors[0].message).toBe('Function failed');
    expect(metrics.recentErrors[0].component).toBe('test-component');
    expect(metrics.recentErrors[0].operation).toBe('test-operation');
    expect(metrics.recentErrors[0].duration).toBeGreaterThan(0);
    expect(performance.averageResponseTime).toBeGreaterThan(0);
  });

  test('should work without context', async () => {
    const mockFn = jest.fn().mockResolvedValue('no-context');
    const monitoredFn = monitorPerformance(mockFn);
    
    const result = await monitoredFn();
    
    expect(result).toBe('no-context');
  });

  test('should preserve function signature and parameters', async () => {
    const mockFn = jest.fn().mockImplementation((a: string, b: number) => 
      Promise.resolve(`${a}-${b}`)
    );
    const monitoredFn = monitorPerformance(mockFn);
    
    const result = await monitoredFn('test', 123);
    
    expect(result).toBe('test-123');
    expect(mockFn).toHaveBeenCalledWith('test', 123);
  });

  test('should measure actual execution time', async () => {
    const delay = 100;
    const mockFn = jest.fn().mockImplementation(() => 
      new Promise(resolve => setTimeout(() => resolve('delayed'), delay))
    );
    const monitoredFn = monitorPerformance(mockFn);
    
    errorAnalytics.reset();
    
    await monitoredFn();
    
    const performance = errorAnalytics.getPerformanceMetrics();
    expect(performance.averageResponseTime).toBeGreaterThanOrEqual(delay - 10); // Allow some tolerance
  });
});

describe('Integration Tests', () => {
  test('should handle mixed error types correctly', () => {
    errorAnalytics.reset();
    
    const errors = [
      new Error('Standard error'),
      new (UserError as any)('User error'),
      new (MakeServerError as any)('Server error'),
      new (EnhancedUserError as any)('Enhanced error', { userId: 'test' })
    ];
    
    errors.forEach((error, index) => {
      errorAnalytics.recordError(error, {
        component: `component-${index}`,
        operation: `operation-${index}`
      });
    });
    
    const metrics = errorAnalytics.getErrorMetrics();
    const patterns = errorAnalytics.getTopErrorPatterns();
    
    expect(metrics.totalErrors).toBe(4);
    expect(metrics.errorsByCode['Error']).toBe(1);
    expect(metrics.errorsByCode['UserError']).toBe(1);
    expect(metrics.errorsByCode['MakeServerError']).toBe(1);
    expect(metrics.errorsByCode['EnhancedUserError']).toBe(1);
    expect(patterns).toHaveLength(4);
  });

  test('should handle concurrent error recording', () => {
    errorAnalytics.reset();
    
    // Simulate concurrent error recording
    const promises = Array.from({ length: 10 }, (_, i) => 
      Promise.resolve().then(() => 
        errorAnalytics.recordError(new Error(`Concurrent error ${i}`))
      )
    );
    
    return Promise.all(promises).then(() => {
      const metrics = errorAnalytics.getErrorMetrics();
      expect(metrics.totalErrors).toBe(10);
    });
  });

  test('should maintain performance under load', () => {
    errorAnalytics.reset();
    
    const startTime = Date.now();
    
    // Record many errors and performance data
    for (let i = 0; i < 500; i++) {
      errorAnalytics.recordError(new Error(`Load test error ${i}`));
      errorAnalytics.recordPerformance(Math.random() * 1000);
    }
    
    const endTime = Date.now();
    const duration = endTime - startTime;
    
    // Should complete quickly
    expect(duration).toBeLessThan(1000); // Less than 1 second
    
    const metrics = errorAnalytics.getErrorMetrics();
    expect(metrics.totalErrors).toBe(500);
  });
});

describe('Edge Cases and Error Handling', () => {
  test('should handle invalid error objects gracefully', () => {
    const invalidError = { message: 'Not a real error' } as any;
    
    expect(() => {
      errorAnalytics.recordError(invalidError);
    }).not.toThrow();
  });

  test('should handle extremely large error messages', () => {
    const largeMessage = 'A'.repeat(10000);
    const error = new Error(largeMessage);
    
    errorAnalytics.recordError(error);
    
    const metrics = errorAnalytics.getErrorMetrics();
    expect(metrics.recentErrors[0].message).toBe(largeMessage);
  });

  test('should handle negative performance durations', () => {
    errorAnalytics.recordPerformance(-100);
    
    const metrics = errorAnalytics.getPerformanceMetrics();
    // Should still record the data (might be useful for debugging)
    expect(metrics.averageResponseTime).toBe(-100);
  });

  test('should handle zero performance durations', () => {
    errorAnalytics.recordPerformance(0);
    
    const metrics = errorAnalytics.getPerformanceMetrics();
    expect(metrics.averageResponseTime).toBe(0);
  });

  test('should handle circular references in error context', () => {
    const circularContext: any = { 
      userId: 'test',
      self: null
    };
    circularContext.self = circularContext;
    
    const error = new (MakeServerError as any)('Circular error', circularContext);
    
    // Should not throw when recording error with circular context
    expect(() => {
      errorAnalytics.recordError(error);
    }).not.toThrow();
  });
});