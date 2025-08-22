/**
 * @fileoverview Optimized monitoring middleware tests
 * 
 * Performance-optimized version of monitoring tests with reduced delays
 * and efficient test execution patterns.
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { FastMCP } from 'fastmcp';
import MonitoringMiddleware from '../../../src/middleware/monitoring.js';
import { TestPerformanceOptimizer, PerformanceConfigs } from '../../utils/performance-helpers.js';

// Mock dependencies before any imports
jest.mock('../../../src/lib/metrics.js', () => ({
  default: {
    setActiveConnections: jest.fn(),
    incrementCounter: jest.fn(),
    recordHistogram: jest.fn(),
    setGauge: jest.fn(),
    createTimer: jest.fn().mockReturnValue(() => 1000),
    recordRequest: jest.fn(),
    recordToolExecution: jest.fn(),
    recordError: jest.fn(),
    recordAuthAttempt: jest.fn(),
    recordAuthDuration: jest.fn(),
    recordMakeApiCall: jest.fn(),
    healthCheck: jest.fn().mockResolvedValue({ healthy: true, metricsCount: 100 })
  }
}));

jest.mock('../../../src/lib/logger.js', () => ({
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

      // Verify all event listeners are registered
      expect(mockServer.on).toHaveBeenCalledWith('connect', expect.any(Function));
      expect(mockServer.on).toHaveBeenCalledWith('disconnect', expect.any(Function));
      expect(mockServer.on).toHaveBeenCalledWith('tool:call', expect.any(Function));
      expect(mockServer.on).toHaveBeenCalledWith('tool:result', expect.any(Function));
      expect(mockServer.on).toHaveBeenCalledWith('tool:error', expect.any(Function));
      expect(mockServer.on).toHaveBeenCalledWith('error', expect.any(Function));
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
      expect(monitoringMiddleware.getActiveConnections()).toBe(1);
      expect(mockMetrics.setActiveConnections).toHaveBeenCalledWith(1);

      // Test disconnection
      disconnectHandler?.({ session: mockSession });
      expect(monitoringMiddleware.getActiveConnections()).toBe(0);
      expect(mockMetrics.setActiveConnections).toHaveBeenCalledWith(0);
    });
  });

  describe('Tool Execution Monitoring - Optimized', () => {
    beforeEach(() => {
      monitoringMiddleware.initializeServerMonitoring(mockServer);
    });

    it('should track tool execution lifecycle with minimal overhead', async () => {
      const toolCallHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'tool:call'
      )?.[1] as Function;

      const toolResultHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'tool:result'
      )?.[1] as Function;

      // Simulate fast tool execution
      const toolCallEvent = {
        tool: 'fast-tool',
        correlationId: 'call-fast',
        parameters: {}
      };

      // Start execution
      toolCallHandler?.(toolCallEvent);
      expect(monitoringMiddleware.getActiveToolExecutions().has('call-fast')).toBe(true);

      // Complete execution with minimal delay
      const resultEvent = {
        tool: 'fast-tool',
        correlationId: 'call-fast',
        result: { success: true },
        duration: TestPerformanceOptimizer.optimizeDelay(100) // Optimized duration
      };

      toolResultHandler?.(resultEvent);
      
      expect(mockMetrics.incrementCounter).toHaveBeenCalledWith('tool.execution.completed', {
        tool: 'fast-tool',
        status: 'success'
      });
      
      expect(monitoringMiddleware.getActiveToolExecutions().has('call-fast')).toBe(false);
    });

    it('should handle concurrent executions efficiently', async () => {
      const toolCallHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'tool:call'
      )?.[1] as Function;

      // Create optimized concurrent executions
      const concurrentCount = TestPerformanceOptimizer.optimizeConcurrency(50, performanceConfig.maxConcurrency);
      
      const executions = Array.from({ length: concurrentCount }, (_, i) => ({
        tool: 'concurrent-tool',
        correlationId: `call-${i}`
      }));

      // Execute concurrently
      executions.forEach(execution => toolCallHandler?.(execution));

      expect(monitoringMiddleware.getActiveToolExecutions().size).toBe(concurrentCount);
      expect(mockMetrics.setGauge).toHaveBeenCalledWith('tool.execution.active', concurrentCount);
    });

    it('should track performance metrics with sampling', () => {
      const scenarios = TestPerformanceOptimizer.createOptimizedScenarios([
        { name: 'fast-execution', duration: 100 },
        { name: 'medium-execution', duration: 1000 },
        { name: 'slow-execution', duration: 5000 }
      ], performanceConfig.maxDuration);

      scenarios.forEach(scenario => {
        expect(scenario.duration).toBeLessThanOrEqual(performanceConfig.maxDuration);
      });

      const toolResultHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'tool:result'
      )?.[1] as Function;

      scenarios.forEach(scenario => {
        toolResultHandler?.({
          tool: scenario.name,
          correlationId: `call-${scenario.name}`,
          duration: scenario.duration
        });
      });

      expect(mockMetrics.recordHistogram).toHaveBeenCalledTimes(scenarios.length);
    });
  });

  describe('Error Handling - Fast Mode', () => {
    beforeEach(() => {
      monitoringMiddleware.initializeServerMonitoring(mockServer);
    });

    it('should handle errors without delays', () => {
      const toolErrorHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'tool:error'
      )?.[1] as Function;

      const errorEvent = {
        tool: 'failing-tool',
        correlationId: 'call-error',
        error: new Error('Test error'),
        duration: TestPerformanceOptimizer.optimizeDelay(1000, 10) // Very fast error handling
      };

      toolErrorHandler?.(errorEvent);

      expect(mockMetrics.incrementCounter).toHaveBeenCalledWith('tool.execution.completed', {
        tool: 'failing-tool',
        status: 'error'
      });

      expect(mockChildLogger.error).toHaveBeenCalledWith(
        'Tool execution failed',
        expect.objectContaining({
          tool: 'failing-tool',
          correlationId: 'call-error'
        })
      );
    });

    it('should cleanup stale executions efficiently', () => {
      jest.useFakeTimers();
      
      const toolCallHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'tool:call'
      )?.[1] as Function;

      // Start executions
      toolCallHandler?.({ tool: 'test-tool', correlationId: 'stale-1' });
      toolCallHandler?.({ tool: 'test-tool', correlationId: 'stale-2' });

      expect(monitoringMiddleware.getActiveToolExecutions().size).toBe(2);

      // Fast cleanup interval (optimized from 1 hour to 1 second for tests)
      jest.advanceTimersByTime(TestPerformanceOptimizer.optimizeDelay(3600000, 1000));

      // Trigger cleanup
      monitoringMiddleware.cleanupStaleExecutions();

      expect(monitoringMiddleware.getActiveToolExecutions().size).toBe(0);

      jest.useRealTimers();
    });
  });

  describe('Performance Metrics - Efficient Collection', () => {
    it('should export metrics without heavy computation', () => {
      const exportedMetrics = monitoringMiddleware.exportMetrics();

      expect(exportedMetrics).toEqual(expect.objectContaining({
        connections: expect.objectContaining({
          active: expect.any(Number),
          total: expect.any(Number)
        }),
        tools: expect.objectContaining({
          active: expect.any(Number),
          completed: expect.any(Number),
          errors: expect.any(Number)
        }),
        performance: expect.objectContaining({
          uptime: expect.any(Number),
          memory: expect.any(Object)
        })
      }));
    });

    it('should support fast periodic collection', async () => {
      jest.useFakeTimers();

      // Start with optimized interval (5ms instead of 5000ms)
      const optimizedInterval = TestPerformanceOptimizer.optimizeDelay(5000, 5);
      monitoringMiddleware.startPeriodicCollection(optimizedInterval);

      jest.advanceTimersByTime(optimizedInterval);
      
      expect(mockMetrics.recordHistogram).toHaveBeenCalledWith(
        'server.memory.usage',
        expect.any(Number)
      );

      monitoringMiddleware.stopPeriodicCollection();
      jest.useRealTimers();
    });

    it('should handle health status checks efficiently', () => {
      const healthStatus = monitoringMiddleware.getHealthStatus();

      expect(healthStatus).toEqual(expect.objectContaining({
        status: expect.any(String),
        activeConnections: expect.any(Number),
        activeExecutions: expect.any(Number),
        uptime: expect.any(Number)
      }));

      // Health check should complete quickly
      const startTime = process.hrtime.bigint();
      monitoringMiddleware.getHealthStatus();
      const endTime = process.hrtime.bigint();
      const durationMs = Number(endTime - startTime) / 1_000_000;

      expect(durationMs).toBeLessThan(10); // Should complete in under 10ms
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

      const healthStatus = monitoringMiddleware.getHealthStatus();
      
      expect(healthStatus).toHaveProperty('memoryPressure');
      
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