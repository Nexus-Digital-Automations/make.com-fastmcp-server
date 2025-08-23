/**
 * @fileoverview Comprehensive unit tests for monitoring middleware
 * 
 * Tests following production-ready patterns from research report:
 * - FastMCP server event monitoring
 * - Metrics collection and validation
 * - Performance tracking and analysis
 * - Error monitoring and alerting
 * - Session and tool execution tracking
 * 
 * Coverage target: 95%+ for critical monitoring functionality
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { FastMCP } from 'fastmcp';
import { MonitoringMiddleware } from '../../../src/middleware/monitoring.js';

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

describe('MonitoringMiddleware', () => {
  let monitoringMiddleware: MonitoringMiddleware;
  let mockServer: jest.Mocked<FastMCP>;
  let mockChildLogger: jest.Mocked<ReturnType<typeof logger.child>>;

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

  describe('Constructor and Initialization', () => {
    it('should initialize with proper logger configuration', () => {
      expect(mockLogger.child).toHaveBeenCalledWith({ 
        component: 'MonitoringMiddleware' 
      });
    });

    it('should initialize with zero active connections', () => {
      const stats = monitoringMiddleware.getMonitoringStats();
      expect(stats.activeConnections).toBe(0);
    });

    it('should initialize with empty tool executions map', () => {
      const stats = monitoringMiddleware.getMonitoringStats();
      expect(stats.activeToolExecutions).toBe(0);
    });
  });

  describe('Server Monitoring Initialization', () => {
    it('should register all required server event listeners', () => {
      monitoringMiddleware.initializeServerMonitoring(mockServer);

      // Verify all event listeners are registered
      expect(mockServer.on).toHaveBeenCalledWith('connect', expect.any(Function));
      expect(mockServer.on).toHaveBeenCalledWith('disconnect', expect.any(Function));
      expect(mockServer.on).toHaveBeenCalledWith('tool:call', expect.any(Function));
      expect(mockServer.on).toHaveBeenCalledWith('tool:result', expect.any(Function));
      expect(mockServer.on).toHaveBeenCalledWith('tool:error', expect.any(Function));
      expect(mockServer.on).toHaveBeenCalledWith('error', expect.any(Function));
      
      expect(mockChildLogger.info).toHaveBeenCalledWith('Initializing server monitoring');
    });

    it('should not initialize monitoring twice for same server', () => {
      monitoringMiddleware.initializeServerMonitoring(mockServer);
      monitoringMiddleware.initializeServerMonitoring(mockServer);

      // Should only register listeners once
      expect(mockServer.on).toHaveBeenCalledTimes(6); // 6 unique events
    });
  });

  describe('Connection Monitoring', () => {
    beforeEach(() => {
      monitoringMiddleware.initializeServerMonitoring(mockServer);
    });

    it('should track connection events', () => {
      const connectHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'connect'
      )?.[1] as Function;

      const mockSession = {
        id: 'session-123',
        clientCapabilities: { tools: {} },
        serverCapabilities: { logging: {} }
      };

      const connectEvent = { session: mockSession };
      connectHandler?.(connectEvent);

      expect(monitoringMiddleware.getActiveConnections()).toBe(1);
      expect(mockMetrics.setActiveConnections).toHaveBeenCalledWith(1);
      expect(mockChildLogger.info).toHaveBeenCalledWith(
        'Client connected',
        expect.objectContaining({
          sessionId: 'session-123',
          clientCapabilities: mockSession.clientCapabilities
        })
      );
    });

    it('should track disconnection events', () => {
      // First connect
      const connectHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'connect'
      )?.[1] as Function;
      
      connectHandler?.({ session: { id: 'session-123' } });
      expect(monitoringMiddleware.getActiveConnections()).toBe(1);

      // Then disconnect
      const disconnectHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'disconnect'
      )?.[1] as Function;

      const disconnectEvent = { 
        session: { id: 'session-123' },
        reason: 'client_closed'
      };
      disconnectHandler?.(disconnectEvent);

      expect(monitoringMiddleware.getActiveConnections()).toBe(0);
      expect(mockMetrics.setActiveConnections).toHaveBeenCalledWith(0);
      expect(mockChildLogger.info).toHaveBeenCalledWith(
        'Client disconnected',
        expect.objectContaining({
          sessionId: 'session-123',
          reason: 'client_closed'
        })
      );
    });

    it('should handle connection events with invalid session data', () => {
      const connectHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'connect'
      )?.[1] as Function;

      // Test with null/undefined session
      connectHandler?.({ session: null });
      
      expect(mockChildLogger.warn).toHaveBeenCalledWith(
        'Connection event with invalid session data'
      );
      expect(monitoringMiddleware.getActiveConnections()).toBe(0);
    });

    it('should measure connection duration', () => {
      const connectHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'connect'
      )?.[1] as Function;
      const disconnectHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'disconnect'
      )?.[1] as Function;

      // Connect
      const connectTime = Date.now();
      connectHandler?.({ session: { id: 'session-123' } });

      // Wait and disconnect
      jest.advanceTimersByTime(5000); // 5 seconds
      disconnectHandler?.({ session: { id: 'session-123' } });

      expect(mockMetrics.recordHistogram).toHaveBeenCalledWith(
        'connection.duration',
        expect.any(Number),
        { sessionId: 'session-123' }
      );
    });
  });

  describe('Tool Execution Monitoring', () => {
    beforeEach(() => {
      monitoringMiddleware.initializeServerMonitoring(mockServer);
    });

    it('should track tool call events', () => {
      const toolCallHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'tool:call'
      )?.[1] as Function;

      const toolCallEvent = {
        tool: 'list-scenarios',
        parameters: { filter: 'active' },
        session: { id: 'session-123' },
        correlationId: 'call-456'
      };

      toolCallHandler?.(toolCallEvent);

      const executions = monitoringMiddleware.getActiveToolExecutions();
      expect(executions.has('call-456')).toBe(true);
      
      const execution = executions.get('call-456');
      expect(execution).toEqual(expect.objectContaining({
        tool: 'list-scenarios',
        startTime: expect.any(Number),
        sessionId: 'session-123'
      }));

      expect(mockMetrics.incrementCounter).toHaveBeenCalledWith('tool.execution.started', {
        tool: 'list-scenarios'
      });
    });

    it('should track successful tool results', () => {
      // First start a tool call
      const toolCallHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'tool:call'
      )?.[1] as Function;

      toolCallHandler?.({
        tool: 'list-scenarios',
        correlationId: 'call-456'
      });

      // Then track the result
      const toolResultHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'tool:result'
      )?.[1] as Function;

      const resultEvent = {
        tool: 'list-scenarios',
        correlationId: 'call-456',
        result: { scenarios: [] },
        duration: 250
      };

      toolResultHandler?.(resultEvent);

      expect(mockMetrics.incrementCounter).toHaveBeenCalledWith('tool.execution.completed', {
        tool: 'list-scenarios',
        status: 'success'
      });

      expect(mockMetrics.recordHistogram).toHaveBeenCalledWith(
        'tool.execution.duration',
        250,
        { tool: 'list-scenarios' }
      );

      // Execution should be removed from active map
      expect(monitoringMiddleware.getActiveToolExecutions().has('call-456')).toBe(false);
    });

    it('should track tool execution errors', () => {
      // First start a tool call
      const toolCallHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'tool:call'
      )?.[1] as Function;

      toolCallHandler?.({
        tool: 'get-scenario',
        correlationId: 'call-789'
      });

      // Then track the error
      const toolErrorHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'tool:error'
      )?.[1] as Function;

      const errorEvent = {
        tool: 'get-scenario',
        correlationId: 'call-789',
        error: new Error('API rate limit exceeded'),
        duration: 100
      };

      toolErrorHandler?.(errorEvent);

      expect(mockMetrics.incrementCounter).toHaveBeenCalledWith('tool.execution.completed', {
        tool: 'get-scenario',
        status: 'error'
      });

      expect(mockMetrics.incrementCounter).toHaveBeenCalledWith('tool.execution.error', {
        tool: 'get-scenario',
        errorType: 'Error'
      });

      expect(mockChildLogger.error).toHaveBeenCalledWith(
        'Tool execution failed',
        expect.objectContaining({
          tool: 'get-scenario',
          correlationId: 'call-789',
          error: 'API rate limit exceeded'
        })
      );
    });

    it('should detect and alert on long-running tool executions', () => {
      jest.useFakeTimers();

      const toolCallHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'tool:call'
      )?.[1] as Function;

      toolCallHandler?.({
        tool: 'slow-operation',
        correlationId: 'call-slow'
      });

      // Advance time beyond warning threshold (30 seconds)
      jest.advanceTimersByTime(35000);

      expect(mockChildLogger.warn).toHaveBeenCalledWith(
        'Long-running tool execution detected',
        expect.objectContaining({
          tool: 'slow-operation',
          correlationId: 'call-slow',
          duration: expect.any(Number)
        })
      );

      jest.useRealTimers();
    });

    it('should handle concurrent tool executions', () => {
      const toolCallHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'tool:call'
      )?.[1] as Function;

      // Start multiple concurrent executions
      const executions = [
        { tool: 'list-scenarios', correlationId: 'call-1' },
        { tool: 'get-scenario', correlationId: 'call-2' },
        { tool: 'list-scenarios', correlationId: 'call-3' }
      ];

      executions.forEach(execution => toolCallHandler?.(execution));

      expect(monitoringMiddleware.getActiveToolExecutions().size).toBe(3);
      expect(mockMetrics.setGauge).toHaveBeenCalledWith('tool.execution.active', 3);
    });
  });

  describe('Performance Metrics Collection', () => {
    beforeEach(() => {
      monitoringMiddleware.initializeServerMonitoring(mockServer);
    });

    it('should collect server performance metrics', () => {
      const metrics = monitoringMiddleware.getPerformanceMetrics();

      expect(metrics).toEqual(expect.objectContaining({
        activeConnections: expect.any(Number),
        activeToolExecutions: expect.any(Number),
        uptime: expect.any(Number),
        memoryUsage: expect.objectContaining({
          rss: expect.any(Number),
          heapTotal: expect.any(Number),
          heapUsed: expect.any(Number)
        })
      }));
    });

    it('should track tool execution performance statistics', () => {
      // Simulate multiple tool executions
      const toolCallHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'tool:call'
      )?.[1] as Function;
      const toolResultHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'tool:result'
      )?.[1] as Function;

      // Execute multiple tools with different performance characteristics
      const executions = [
        { correlationId: 'fast-1', tool: 'list-scenarios', duration: 100 },
        { correlationId: 'fast-2', tool: 'list-scenarios', duration: 150 },
        { correlationId: 'slow-1', tool: 'generate-report', duration: 5000 }
      ];

      executions.forEach(exec => {
        toolCallHandler?.({ tool: exec.tool, correlationId: exec.correlationId });
        toolResultHandler?.({ 
          tool: exec.tool, 
          correlationId: exec.correlationId,
          duration: exec.duration 
        });
      });

      const toolStats = monitoringMiddleware.getToolExecutionStatistics();
      
      expect(toolStats['list-scenarios']).toEqual(expect.objectContaining({
        totalExecutions: 2,
        averageDuration: 125,
        minDuration: 100,
        maxDuration: 150
      }));

      expect(toolStats['generate-report']).toEqual(expect.objectContaining({
        totalExecutions: 1,
        averageDuration: 5000
      }));
    });

    it('should track error rates by tool', () => {
      const toolCallHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'tool:call'
      )?.[1] as Function;
      const toolResultHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'tool:result'
      )?.[1] as Function;
      const toolErrorHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'tool:error'
      )?.[1] as Function;

      // Simulate mixed success/error executions
      ['success-1', 'success-2', 'error-1'].forEach(id => {
        toolCallHandler?.({ tool: 'test-tool', correlationId: id });
      });

      toolResultHandler?.({ tool: 'test-tool', correlationId: 'success-1' });
      toolResultHandler?.({ tool: 'test-tool', correlationId: 'success-2' });
      toolErrorHandler?.({ 
        tool: 'test-tool', 
        correlationId: 'error-1',
        error: new Error('Test error')
      });

      const errorStats = monitoringMiddleware.getErrorStatistics();
      
      expect(errorStats['test-tool']).toEqual(expect.objectContaining({
        totalExecutions: 3,
        errorCount: 1,
        errorRate: 0.33
      }));
    });
  });

  describe('Health Check Integration', () => {
    it('should provide health status information', () => {
      const healthStatus = monitoringMiddleware.getHealthStatus();

      expect(healthStatus).toEqual(expect.objectContaining({
        status: 'healthy',
        activeConnections: expect.any(Number),
        activeExecutions: expect.any(Number),
        uptime: expect.any(Number),
        lastError: null
      }));
    });

    it('should report unhealthy status when too many errors', () => {
      // Simulate high error rate
      const toolErrorHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'tool:error'
      )?.[1] as Function;

      // Generate multiple errors quickly
      Array(10).fill(0).forEach((_, i) => {
        toolErrorHandler?.({
          tool: 'failing-tool',
          correlationId: `error-${i}`,
          error: new Error(`Error ${i}`)
        });
      });

      const healthStatus = monitoringMiddleware.getHealthStatus();
      
      expect(healthStatus.status).toBe('unhealthy');
      expect(healthStatus.lastError).toBeTruthy();
    });

    it('should report degraded performance for slow tools', () => {
      const toolResultHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'tool:result'
      )?.[1] as Function;

      // Simulate very slow execution
      toolResultHandler?.({
        tool: 'slow-tool',
        correlationId: 'slow-1',
        duration: 30000 // 30 seconds
      });

      const healthStatus = monitoringMiddleware.getHealthStatus();
      
      expect(healthStatus.status).toBe('degraded');
      expect(healthStatus.slowTools).toContain('slow-tool');
    });
  });

  describe('Error Handling and Edge Cases', () => {
    beforeEach(() => {
      monitoringMiddleware.initializeServerMonitoring(mockServer);
    });

    it('should handle events with missing correlation IDs', () => {
      const toolResultHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'tool:result'
      )?.[1] as Function;

      // Result without corresponding call
      toolResultHandler?.({
        tool: 'orphan-tool',
        correlationId: 'missing-call',
        result: {}
      });

      expect(mockChildLogger.warn).toHaveBeenCalledWith(
        'Tool result without corresponding execution record',
        expect.objectContaining({
          correlationId: 'missing-call'
        })
      );
    });

    it('should handle server error events', () => {
      const errorHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'error'
      )?.[1] as Function;

      const serverError = new Error('Server connection lost');
      errorHandler?.(serverError);

      expect(mockMetrics.incrementCounter).toHaveBeenCalledWith('server.error', {
        errorType: 'Error'
      });

      expect(mockChildLogger.error).toHaveBeenCalledWith(
        'Server error occurred',
        expect.objectContaining({
          error: 'Server connection lost'
        })
      );
    });

    it('should cleanup stale execution records', () => {
      jest.useFakeTimers();
      
      const toolCallHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'tool:call'
      )?.[1] as Function;

      // Start executions
      toolCallHandler?.({ tool: 'test-tool', correlationId: 'stale-1' });
      toolCallHandler?.({ tool: 'test-tool', correlationId: 'stale-2' });

      expect(monitoringMiddleware.getActiveToolExecutions().size).toBe(2);

      // Advance time significantly (1 hour)
      jest.advanceTimersByTime(3600000);

      // Trigger cleanup
      monitoringMiddleware.cleanupStaleExecutions();

      expect(monitoringMiddleware.getActiveToolExecutions().size).toBe(0);
      expect(mockChildLogger.info).toHaveBeenCalledWith(
        'Cleaned up stale execution records',
        expect.objectContaining({ cleanedCount: 2 })
      );

      jest.useRealTimers();
    });

    it('should handle memory pressure gracefully', () => {
      // Mock memory usage detection
      const originalMemoryUsage = process.memoryUsage;
      process.memoryUsage = jest.fn().mockReturnValue({
        rss: 2000000000, // 2GB - high memory usage
        heapTotal: 1500000000,
        heapUsed: 1400000000,
        external: 100000000
      });

      const healthStatus = monitoringMiddleware.getHealthStatus();
      
      expect(healthStatus.memoryPressure).toBe(true);
      expect(mockChildLogger.warn).toHaveBeenCalledWith(
        'High memory usage detected',
        expect.objectContaining({
          heapUsed: expect.any(Number),
          heapTotal: expect.any(Number)
        })
      );

      process.memoryUsage = originalMemoryUsage;
    });
  });

  describe('Metrics Export and Reporting', () => {
    it('should export comprehensive metrics in standard format', () => {
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

    it('should support custom metrics collection intervals', () => {
      jest.useFakeTimers();

      monitoringMiddleware.startPeriodicCollection(5000); // 5 second intervals

      jest.advanceTimersByTime(5000);
      
      expect(mockMetrics.recordHistogram).toHaveBeenCalledWith(
        'server.memory.usage',
        expect.any(Number)
      );

      monitoringMiddleware.stopPeriodicCollection();
      jest.useRealTimers();
    });
  });
});