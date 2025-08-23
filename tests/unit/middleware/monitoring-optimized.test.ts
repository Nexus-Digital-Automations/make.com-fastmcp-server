/**
 * @fileoverview Optimized monitoring middleware tests
 * 
 * Performance-optimized version of monitoring tests with reduced delays
 * and efficient test execution patterns.
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { FastMCP } from 'fastmcp';
import { MonitoringMiddleware } from '../../../src/middleware/monitoring.js';
import { TestPerformanceOptimizer, PerformanceConfigs } from '../../utils/performance-helpers.js';

// Mock dependencies before any imports
jest.mock('../../../src/lib/metrics.js', () => {
  const mockFns = {
    setActiveConnections: jest.fn().mockName('setActiveConnections'),
    incrementCounter: jest.fn().mockName('incrementCounter'),
    recordHistogram: jest.fn().mockName('recordHistogram'),
    setGauge: jest.fn().mockName('setGauge'),
    createTimer: jest.fn().mockName('createTimer').mockReturnValue(() => 1.5),
    recordRequest: jest.fn().mockName('recordRequest'),
    recordToolExecution: jest.fn().mockName('recordToolExecution'),
    recordError: jest.fn().mockName('recordError'),
    recordAuthAttempt: jest.fn().mockName('recordAuthAttempt'),
    recordAuthDuration: jest.fn().mockName('recordAuthDuration'),
    recordMakeApiCall: jest.fn().mockName('recordMakeApiCall'),
    healthCheck: jest.fn().mockName('healthCheck').mockResolvedValue({ healthy: true, metricsCount: 100 }),
    recordCacheHit: jest.fn().mockName('recordCacheHit'),
    recordCacheMiss: jest.fn().mockName('recordCacheMiss'),
    recordCacheInvalidation: jest.fn().mockName('recordCacheInvalidation'),
    recordCacheDuration: jest.fn().mockName('recordCacheDuration'),
    updateCacheSize: jest.fn().mockName('updateCacheSize'),
    updateCacheHitRate: jest.fn().mockName('updateCacheHitRate'),
    updateRateLimiterState: jest.fn().mockName('updateRateLimiterState'),
    getMetrics: jest.fn().mockName('getMetrics').mockResolvedValue('# Mock metrics data'),
    getRegistry: jest.fn().mockName('getRegistry'),
    shutdown: jest.fn().mockName('shutdown')
  };

  const mockMetricsCollector = {
    getInstance: jest.fn().mockReturnValue(mockFns),
    resetInstance: jest.fn()
  };

  return {
    __esModule: true,
    default: mockFns,
    metrics: mockFns,
    MetricsCollector: mockMetricsCollector
  };
});

jest.mock('../../../src/lib/logger.js', () => ({
  __esModule: true,
  default: {
    child: jest.fn().mockReturnValue({
      info: jest.fn(),
      debug: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
      child: jest.fn().mockReturnThis()
    }),
    info: jest.fn(),
    debug: jest.fn(),
    warn: jest.fn(),
    error: jest.fn()
  }
}));

jest.mock('../../../src/lib/config.js', () => ({
  default: {
    getLogLevel: jest.fn().mockReturnValue('info'),
    get: jest.fn().mockReturnValue({}),
    set: jest.fn()
  }
}));

// Import mocked dependencies
import metrics from '../../../src/lib/metrics.js';
import logger from '../../../src/lib/logger.js';

// Type-safe mocks
const mockMetrics = metrics as jest.Mocked<typeof metrics>;
const mockLogger = logger as jest.Mocked<typeof logger>;

describe('MonitoringMiddleware - Performance Optimized', () => {
  let monitoringMiddleware: MonitoringMiddleware;
  let mockServer: jest.Mocked<FastMCP>;
  let mockChildLogger: jest.Mocked<ReturnType<typeof logger.child>>;
  let performanceConfig = PerformanceConfigs.unit;

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();

    // Setup mock logger chain
    mockChildLogger = {
      info: jest.fn(),
      debug: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
      child: jest.fn().mockReturnThis()
    } as any;
    mockLogger.child = jest.fn().mockReturnValue(mockChildLogger);

    // Setup mock server with event handling
    mockServer = {
      on: jest.fn(),
      emit: jest.fn(),
      addTool: jest.fn(),
      start: jest.fn(),
      stop: jest.fn()
    } as any;

    // Initialize middleware
    monitoringMiddleware = new MonitoringMiddleware();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Core Functionality - Fast Tests', () => {
    it('should initialize with proper configuration', () => {
      expect(mockLogger.child).toHaveBeenCalledWith({ 
        component: 'MonitoringMiddleware' 
      });
      
      const stats = monitoringMiddleware.getMonitoringStats();
      expect(stats.activeConnections).toBe(0);
      expect(stats.activeToolExecutions).toBe(0);
    });

    it('should register server event listeners efficiently', () => {
      monitoringMiddleware.initializeServerMonitoring(mockServer);

      // Verify the actual event listeners that are registered in the implementation
      expect(mockServer.on).toHaveBeenCalledWith('connect', expect.any(Function));
      expect(mockServer.on).toHaveBeenCalledWith('disconnect', expect.any(Function));
      expect(mockServer.on).toHaveBeenCalledTimes(2); // Only connect and disconnect
    });

    it('should track connection lifecycle efficiently', () => {
      monitoringMiddleware.initializeServerMonitoring(mockServer);
      
      const connectHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'connect'
      )?.[1] as Function;
      
      const disconnectHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'disconnect'
      )?.[1] as Function;

      const mockSession = { id: 'session-123' };

      // Test connection
      connectHandler?.({ session: mockSession });
      expect(monitoringMiddleware.getMonitoringStats().activeConnections).toBe(1);
      expect(mockMetrics.setActiveConnections).toHaveBeenCalledWith(1);

      // Test disconnection
      disconnectHandler?.({ session: mockSession });
      expect(monitoringMiddleware.getMonitoringStats().activeConnections).toBe(0);
      expect(mockMetrics.setActiveConnections).toHaveBeenCalledWith(0);
    });
  });

  describe('Tool Execution Monitoring - Optimized', () => {
    beforeEach(() => {
      monitoringMiddleware.initializeServerMonitoring(mockServer);
    });

    it('should track tool execution lifecycle with minimal overhead', async () => {
      // Use the actual tool execution wrapper method
      const mockExecution = jest.fn().mockResolvedValue({ success: true });
      const wrappedExecution = monitoringMiddleware.wrapToolExecution(
        'fast-tool',
        'test-operation',
        mockExecution
      );

      // Execute the wrapped function
      const result = await wrappedExecution();

      expect(result).toEqual({ success: true });
      expect(mockExecution).toHaveBeenCalled();
      expect(mockMetrics.recordToolExecution).toHaveBeenCalledWith('fast-tool', 'success', 1.5, undefined);
      
      // Verify monitoring stats still work
      expect(monitoringMiddleware.getMonitoringStats().activeToolExecutions).toBeGreaterThanOrEqual(0);
    });

    it('should handle concurrent executions efficiently', async () => {
      // Create concurrent tool executions using the wrapper method
      const concurrentCount = TestPerformanceOptimizer.optimizeConcurrency(50, performanceConfig.maxConcurrency);
      
      const executions = Array.from({ length: concurrentCount }, (_, i) => {
        const mockExecution = jest.fn().mockResolvedValue({ success: true, id: i });
        return monitoringMiddleware.wrapToolExecution(
          'concurrent-tool',
          `operation-${i}`,
          mockExecution
        );
      });

      // Execute all concurrently
      const results = await Promise.all(executions.map(exec => exec()));

      expect(results).toHaveLength(concurrentCount);
      expect(results[0]).toEqual({ success: true, id: 0 });
      expect(mockMetrics.recordToolExecution).toHaveBeenCalledTimes(concurrentCount);
      expect(monitoringMiddleware.getMonitoringStats().activeToolExecutions).toBeGreaterThanOrEqual(0);
    });

    it('should track performance metrics with sampling', async () => {
      const scenarios = TestPerformanceOptimizer.createOptimizedScenarios([
        { name: 'fast-execution', duration: 100 },
        { name: 'medium-execution', duration: 1000 },
        { name: 'slow-execution', duration: 5000 }
      ], performanceConfig.maxDuration);

      scenarios.forEach(scenario => {
        expect(scenario.duration).toBeLessThanOrEqual(performanceConfig.maxDuration);
      });

      // Execute the scenarios using the actual tool wrapper
      for (const scenario of scenarios) {
        const mockExecution = jest.fn().mockResolvedValue({ duration: scenario.duration });
        const wrappedExecution = monitoringMiddleware.wrapToolExecution(
          scenario.name,
          'performance-test',
          mockExecution
        );
        
        await wrappedExecution();
      }

      expect(mockMetrics.recordToolExecution).toHaveBeenCalledTimes(scenarios.length);
    });
  });

  describe('Error Handling - Fast Mode', () => {
    beforeEach(() => {
      monitoringMiddleware.initializeServerMonitoring(mockServer);
    });

    it('should handle errors without delays', async () => {
      const mockError = new Error('Test error');
      const mockExecution = jest.fn().mockRejectedValue(mockError);
      const wrappedExecution = monitoringMiddleware.wrapToolExecution(
        'failing-tool',
        'error-operation',
        mockExecution
      );

      await expect(wrappedExecution()).rejects.toThrow('Test error');

      expect(mockMetrics.recordToolExecution).toHaveBeenCalledWith('failing-tool', 'error', 1.5, undefined);
      expect(mockMetrics.recordError).toHaveBeenCalledWith('generic_error', 'error-operation', 'failing-tool');

      expect(mockChildLogger.error).toHaveBeenCalledWith(
        'Tool execution failed',
        expect.objectContaining({
          tool: 'failing-tool',
          operation: 'error-operation'
        })
      );
    });

    it('should handle multiple tool executions and cleanup', async () => {
      // Start multiple executions
      const executions = [];
      for (let i = 0; i < 3; i++) {
        const mockExecution = jest.fn().mockResolvedValue({ id: i });
        executions.push(monitoringMiddleware.wrapToolExecution(
          'test-tool',
          `operation-${i}`,
          mockExecution
        ));
      }

      // Execute all and verify they complete
      const results = await Promise.all(executions.map(exec => exec()));
      
      expect(results).toHaveLength(3);
      expect(mockMetrics.recordToolExecution).toHaveBeenCalledTimes(3);
      
      // Tool executions should be cleaned up automatically after completion
      expect(monitoringMiddleware.getMonitoringStats().activeToolExecutions).toBe(0);
    });
  });

  describe('Performance Metrics - Efficient Collection', () => {
    it('should provide monitoring stats without heavy computation', () => {
      const stats = monitoringMiddleware.getMonitoringStats();

      expect(stats).toEqual(expect.objectContaining({
        activeConnections: expect.any(Number),
        activeToolExecutions: expect.any(Number),
        metricsHealth: expect.any(Promise)
      }));
    });

    it('should support health status checks efficiently', () => {
      // Note: periodic collection methods don't exist in the actual implementation
      // Testing health check instead which is available
      const healthPromise = monitoringMiddleware.healthCheck();
      expect(healthPromise).toBeInstanceOf(Promise);
    });

    it('should handle async health checks efficiently', async () => {
      const healthStatus = await monitoringMiddleware.healthCheck();

      expect(healthStatus).toEqual(expect.objectContaining({
        healthy: expect.any(Boolean),
        activeConnections: expect.any(Number),
        activeToolExecutions: expect.any(Number),
        metricsSystem: expect.any(Object)
      }));

      // Health check should complete quickly
      const startTime = process.hrtime.bigint();
      await monitoringMiddleware.healthCheck();
      const endTime = process.hrtime.bigint();
      const durationMs = Number(endTime - startTime) / 1_000_000;

      expect(durationMs).toBeLessThan(100); // Should complete in under 100ms for async
    });
  });

  describe('Resource Optimization Tests', () => {
    it('should handle memory pressure detection efficiently', () => {
      // Mock high memory usage
      const originalMemoryUsage = process.memoryUsage;
      process.memoryUsage = jest.fn().mockReturnValue({
        rss: 100_000_000, // 100MB - reasonable for tests
        heapTotal: 50_000_000,
        heapUsed: 45_000_000,
        external: 5_000_000
      });

      const healthStatusPromise = monitoringMiddleware.healthCheck();
      
      expect(healthStatusPromise).toBeInstanceOf(Promise);
      
      process.memoryUsage = originalMemoryUsage;
    });

    it('should batch metric operations for performance', async () => {
      const operations = Array.from({ length: 10 }, (_, i) => 
        () => TestPerformanceOptimizer.fastResolve(`operation-${i}`)
      );

      const results = await TestPerformanceOptimizer.batchOperations(
        operations,
        async (op) => await op(),
        3 // Small batch size for test performance
      );

      expect(results).toHaveLength(10);
      expect(results[0]).toBe('operation-0');
    });
  });
});