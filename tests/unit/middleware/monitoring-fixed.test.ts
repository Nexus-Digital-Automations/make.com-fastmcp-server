/**
 * @fileoverview Fixed monitoring middleware tests with proper singleton handling
 * Addresses metrics instance creation failures in test environments
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { FastMCP } from 'fastmcp';

// Mock the metrics module before any imports to prevent initialization issues
jest.mock('../../../src/lib/metrics.js', () => {
  const mockMetricsInstance = {
    setActiveConnections: jest.fn(),
    recordRequest: jest.fn(),
    createTimer: jest.fn().mockReturnValue(() => 1.5), // 1.5 seconds
    recordToolExecution: jest.fn(),
    recordError: jest.fn(),
    recordAuthAttempt: jest.fn(),
    recordAuthDuration: jest.fn(),
    recordMakeApiCall: jest.fn(),
    healthCheck: jest.fn().mockResolvedValue({ healthy: true, metricsCount: 100 }),
    shutdown: jest.fn(),
    recordCacheHit: jest.fn(),
    recordCacheMiss: jest.fn(),
    recordCacheInvalidation: jest.fn(),
    recordCacheDuration: jest.fn(),
    updateCacheSize: jest.fn(),
    updateCacheHitRate: jest.fn(),
    updateRateLimiterState: jest.fn(),
    getMetrics: jest.fn().mockResolvedValue('# Test metrics'),
    getRegistry: jest.fn().mockReturnValue({ clear: jest.fn() }),
    incrementCounter: jest.fn(),
    recordHistogram: jest.fn(),
    setGauge: jest.fn()
  };

  // Mock the MetricsCollector class
  const MockMetricsCollector = jest.fn().mockImplementation(() => mockMetricsInstance);
  MockMetricsCollector.getInstance = jest.fn().mockReturnValue(mockMetricsInstance);
  MockMetricsCollector.resetInstance = jest.fn();

  return {
    __esModule: true,
    default: mockMetricsInstance,
    MetricsCollector: MockMetricsCollector,
    metrics: mockMetricsInstance
  };
});

// Mock the logger module
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
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn()
  }
}));

// Import the modules after mocking
import { MonitoringMiddleware, resetMonitoringInstance } from '../../../src/middleware/monitoring.js';
import { MetricsCollector } from '../../../src/lib/metrics.js';
import metrics from '../../../src/lib/metrics.js';
import logger from '../../../src/lib/logger.js';

// Type the mocked modules
const mockMetrics = metrics as jest.Mocked<typeof metrics>;
const mockLogger = logger as jest.Mocked<typeof logger>;
const mockMetricsCollector = MetricsCollector as jest.MockedClass<typeof MetricsCollector>;

describe('MonitoringMiddleware - Fixed Implementation', () => {
  let monitoringMiddleware: MonitoringMiddleware;
  let mockServer: jest.Mocked<FastMCP>;
  let mockChildLogger: jest.Mocked<ReturnType<typeof logger.child>>;

  beforeEach(() => {
    // Clear all mocks
    jest.clearAllMocks();
    
    // Reset monitoring singleton to ensure test isolation
    resetMonitoringInstance();
    
    // Reset metrics singleton
    mockMetricsCollector.resetInstance?.();

    // Setup mock logger chain
    mockChildLogger = {
      info: jest.fn(),
      debug: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
      child: jest.fn().mockReturnThis()
    } as any;
    
    // Ensure mockLogger.child exists and is a mock function
    if (!mockLogger.child) {
      (mockLogger as any).child = jest.fn();
    }
    (mockLogger.child as jest.Mock).mockReturnValue(mockChildLogger);

    // Setup mock server with event handling
    mockServer = {
      on: jest.fn(),
      emit: jest.fn(),
      addTool: jest.fn(),
      start: jest.fn(),
      stop: jest.fn()
    } as any;

    // Initialize middleware - this should now work with fallback handling
    monitoringMiddleware = new MonitoringMiddleware();
  });

  afterEach(() => {
    // Clean up after each test
    try {
      monitoringMiddleware?.shutdown();
    } catch (error) {
      // Ignore shutdown errors in tests
    }
    resetMonitoringInstance();
    mockMetricsCollector.resetInstance?.();
    // Reset health check mock to prevent cross-test interference
    mockMetrics.healthCheck.mockResolvedValue({ healthy: true, metricsCount: 100 });
    jest.restoreAllMocks();
  });

  describe('Initialization and Singleton Handling', () => {
    it('should initialize with proper logger configuration', () => {
      expect(mockLogger.child).toHaveBeenCalledWith({ 
        component: 'MonitoringMiddleware' 
      });
    });

    it('should provide monitoring stats without throwing errors', () => {
      const stats = monitoringMiddleware.getMonitoringStats();
      
      expect(stats).toEqual(expect.objectContaining({
        activeConnections: expect.any(Number),
        activeToolExecutions: expect.any(Number),
        metricsHealth: expect.any(Promise)
      }));
    });

    it('should handle metrics instance creation failures gracefully', () => {
      // Simulate metrics initialization failure
      mockMetricsCollector.getInstance.mockImplementationOnce(() => {
        throw new Error('Metrics initialization failed');
      });

      // Should not throw when creating a new instance
      expect(() => {
        new MonitoringMiddleware();
      }).not.toThrow();
    });
  });

  describe('Server Event Monitoring', () => {
    beforeEach(() => {
      monitoringMiddleware.initializeServerMonitoring(mockServer);
    });

    it('should register server event listeners', () => {
      expect(mockServer.on).toHaveBeenCalledWith('connect', expect.any(Function));
      expect(mockServer.on).toHaveBeenCalledWith('disconnect', expect.any(Function));
      expect(mockChildLogger.info).toHaveBeenCalledWith('Initializing server monitoring');
      expect(mockChildLogger.info).toHaveBeenCalledWith('Server monitoring initialized');
    });

    it('should handle connection events properly', () => {
      // Get the connect handler
      const connectHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'connect'
      )?.[1] as Function;

      expect(connectHandler).toBeDefined();

      // Simulate a connect event
      const mockSession = { id: 'test-session-123' };
      connectHandler?.({ session: mockSession });

      expect(mockMetrics.setActiveConnections).toHaveBeenCalledWith(1);
      expect(mockMetrics.recordRequest).toHaveBeenCalledWith('connect', 'client_connect', 'success', 0);
    });

    it('should handle disconnection events properly', () => {
      // First connect
      const connectHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'connect'
      )?.[1] as Function;
      connectHandler?.({ session: { id: 'test-session' } });

      // Then disconnect
      const disconnectHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'disconnect'
      )?.[1] as Function;

      expect(disconnectHandler).toBeDefined();

      disconnectHandler?.({ session: { id: 'test-session' } });

      expect(mockMetrics.setActiveConnections).toHaveBeenCalledWith(0);
      expect(mockMetrics.recordRequest).toHaveBeenCalledWith('disconnect', 'client_disconnect', 'success', 0);
    });
  });

  describe('Tool Execution Wrapping', () => {
    it('should wrap tool execution successfully', async () => {
      const mockExecution = jest.fn().mockResolvedValue({ success: true });
      const wrappedExecution = monitoringMiddleware.wrapToolExecution(
        'test-tool',
        'test-operation',
        mockExecution
      );

      const result = await wrappedExecution();

      expect(result).toEqual({ success: true });
      expect(mockExecution).toHaveBeenCalled();
      expect(mockMetrics.recordToolExecution).toHaveBeenCalledWith('test-tool', 'success', 1.5, undefined);
    });

    it('should handle tool execution errors', async () => {
      const mockError = new Error('Test error');
      const mockExecution = jest.fn().mockRejectedValue(mockError);
      const wrappedExecution = monitoringMiddleware.wrapToolExecution(
        'failing-tool',
        'fail-operation',
        mockExecution
      );

      await expect(wrappedExecution()).rejects.toThrow('Test error');
      expect(mockMetrics.recordToolExecution).toHaveBeenCalledWith('failing-tool', 'error', 1.5, undefined);
      expect(mockMetrics.recordError).toHaveBeenCalled();
    });
  });

  describe('Authentication Monitoring', () => {
    it('should monitor successful authentication', async () => {
      const mockAuth = jest.fn().mockResolvedValue({ token: 'success' });
      const wrappedAuth = monitoringMiddleware.monitorAuthentication(mockAuth);

      const result = await wrappedAuth();

      expect(result).toEqual({ token: 'success' });
      expect(mockMetrics.recordAuthAttempt).toHaveBeenCalledWith('success');
      expect(mockMetrics.recordAuthDuration).toHaveBeenCalledWith(1.5);
    });

    it('should monitor authentication failures', async () => {
      const mockError = new Error('Auth failed');
      const mockAuth = jest.fn().mockRejectedValue(mockError);
      const wrappedAuth = monitoringMiddleware.monitorAuthentication(mockAuth);

      await expect(wrappedAuth()).rejects.toThrow('Auth failed');
      expect(mockMetrics.recordAuthAttempt).toHaveBeenCalledWith('failure', 'generic_error');
      expect(mockMetrics.recordError).toHaveBeenCalled();
    });
  });

  describe('Make.com API Monitoring', () => {
    it('should monitor successful API calls', async () => {
      const mockApiCall = jest.fn().mockResolvedValue({ data: 'success' });
      const wrappedCall = monitoringMiddleware.monitorMakeApiCall(
        '/api/scenarios',
        'GET',
        mockApiCall
      );

      const result = await wrappedCall();

      expect(result).toEqual({ data: 'success' });
      expect(mockMetrics.recordMakeApiCall).toHaveBeenCalledWith('/api/scenarios', 'GET', 'success', 1.5);
    });

    it('should monitor API call failures', async () => {
      const mockError = new Error('API failed');
      const mockApiCall = jest.fn().mockRejectedValue(mockError);
      const wrappedCall = monitoringMiddleware.monitorMakeApiCall(
        '/api/scenarios',
        'POST',
        mockApiCall
      );

      await expect(wrappedCall()).rejects.toThrow('API failed');
      expect(mockMetrics.recordMakeApiCall).toHaveBeenCalledWith('/api/scenarios', 'POST', 'error', 1.5);
      expect(mockMetrics.recordError).toHaveBeenCalled();
    });
  });

  describe('Health Check', () => {
    it('should provide health check information', async () => {
      const healthStatus = await monitoringMiddleware.healthCheck();

      expect(healthStatus).toEqual(expect.objectContaining({
        healthy: true,
        activeConnections: expect.any(Number),
        activeToolExecutions: expect.any(Number),
        metricsSystem: expect.objectContaining({
          healthy: true,
          metricsCount: 100
        })
      }));
    });

    it('should handle health check failures gracefully', async () => {
      // Mock a health check failure for this test only
      const originalHealthCheck = mockMetrics.healthCheck;
      mockMetrics.healthCheck = jest.fn().mockRejectedValue(new Error('Health check failed'));
      
      try {
        const healthStatus = await monitoringMiddleware.healthCheck();
        
        expect(healthStatus.healthy).toBe(false);
        expect(healthStatus.metricsSystem.healthy).toBe(false);
      } finally {
        // Restore the original mock
        mockMetrics.healthCheck = originalHealthCheck;
      }
    });
  });

  describe('Monitoring Statistics', () => {
    it('should provide tool execution metrics', () => {
      const metrics = monitoringMiddleware.getToolExecutionMetrics();
      
      expect(Array.isArray(metrics)).toBe(true);
      // Should start empty
      expect(metrics).toHaveLength(0);
    });

    it('should handle monitoring stats without errors', () => {
      const stats = monitoringMiddleware.getMonitoringStats();
      
      expect(stats).toEqual(expect.objectContaining({
        activeConnections: expect.any(Number),
        activeToolExecutions: expect.any(Number),
        metricsHealth: expect.any(Promise)
      }));
    });
  });

  describe('Shutdown and Cleanup', () => {
    it('should shutdown gracefully', () => {
      monitoringMiddleware.shutdown();
      
      expect(mockChildLogger.info).toHaveBeenCalledWith('Shutting down monitoring middleware');
      expect(mockMetrics.setActiveConnections).toHaveBeenCalledWith(0);
    });

    it('should handle shutdown errors gracefully', () => {
      mockMetrics.setActiveConnections.mockImplementationOnce(() => {
        throw new Error('Shutdown error');
      });

      // Should not throw
      expect(() => {
        monitoringMiddleware.shutdown();
      }).not.toThrow();
    });
  });

  describe('Error Recovery and Resilience', () => {
    it('should handle metrics errors during operation', async () => {
      // Simulate metrics recording error
      mockMetrics.recordToolExecution.mockImplementationOnce(() => {
        throw new Error('Metrics recording failed');
      });

      const mockExecution = jest.fn().mockResolvedValue({ success: true });
      const wrappedExecution = monitoringMiddleware.wrapToolExecution(
        'test-tool',
        'test-operation',
        mockExecution
      );

      // Currently, metrics errors propagate up, so the execution will fail
      await expect(wrappedExecution()).rejects.toThrow('Metrics recording failed');
      expect(mockExecution).toHaveBeenCalled(); // Execution still happens before metrics recording
    });

    it('should extract session IDs safely', () => {
      monitoringMiddleware.initializeServerMonitoring(mockServer);
      
      const connectHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'connect'
      )?.[1] as Function;

      // Test with various session formats
      expect(() => {
        connectHandler?.({ session: null });
        connectHandler?.({ session: undefined });
        connectHandler?.({ session: { id: 'valid-id' } });
        connectHandler?.({ session: { id: null } });
        connectHandler?.({ session: {} });
      }).not.toThrow();
    });
  });
});