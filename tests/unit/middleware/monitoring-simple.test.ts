/**
 * @fileoverview Simplified unit tests for monitoring middleware
 * Tests core functionality that exists in the actual implementation
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { FastMCP } from 'fastmcp';

// The module mocks are now handled by Jest's moduleNameMapper configuration

import { MonitoringMiddleware } from '../../../src/middleware/monitoring.js';
import metrics from '../../../src/lib/metrics.js';
import logger from '../../../src/lib/logger.js';

// Assert that the imported modules are actually mocked
const mockMetrics = metrics as jest.MockedObject<typeof metrics>;
const mockLogger = logger as jest.MockedObject<typeof logger>;

describe('MonitoringMiddleware', () => {
  it('should verify logger mock is working', () => {
    console.log('Logger mock:', logger);
    console.log('Logger.child:', logger.child);
    expect(logger.child).toBeDefined();
    expect(typeof logger.child).toBe('function');
  });

  it('should verify metrics mock is working', () => {
    console.log('Metrics mock:', metrics);
    console.log('Metrics.setActiveConnections:', metrics.setActiveConnections);
    console.log('Type of setActiveConnections:', typeof metrics.setActiveConnections);
    console.log('Is jest function:', jest.isMockFunction(metrics.setActiveConnections));
    console.log('mockMetrics === metrics:', mockMetrics === metrics);
    console.log('Is mockMetrics.setActiveConnections a Jest fn:', jest.isMockFunction(mockMetrics.setActiveConnections));
    
    expect(metrics.setActiveConnections).toBeDefined();
    expect(typeof metrics.setActiveConnections).toBe('function');
    expect(jest.isMockFunction(metrics.setActiveConnections)).toBe(true);
    
    // Test that the mock function can be called and tracked
    metrics.setActiveConnections(1);
    expect(metrics.setActiveConnections).toHaveBeenCalledWith(1);
  });

  let monitoringMiddleware: MonitoringMiddleware;
  let mockServer: jest.Mocked<FastMCP>;
  let mockChildLogger: jest.Mocked<ReturnType<typeof logger.child>>;

  beforeEach(() => {
    jest.clearAllMocks();

    // Reset metrics mock functions explicitly after clearAllMocks
    Object.values(mockMetrics).forEach(mockFn => {
      if (typeof mockFn === 'function' && jest.isMockFunction(mockFn)) {
        mockFn.mockClear();
      }
    });

    mockChildLogger = {
      info: jest.fn(),
      debug: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
      child: jest.fn().mockReturnThis()
    } as any;
    mockLogger.child = jest.fn().mockReturnValue(mockChildLogger);

    mockServer = {
      on: jest.fn(),
      emit: jest.fn(),
      addTool: jest.fn(),
      start: jest.fn(),
      stop: jest.fn()
    } as any;

    monitoringMiddleware = new MonitoringMiddleware();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Initialization', () => {
    it('should initialize with proper logger configuration', () => {
      expect(mockLogger.child).toHaveBeenCalledWith({ 
        component: 'MonitoringMiddleware' 
      });
    });

    it('should provide monitoring stats', () => {
      const stats = monitoringMiddleware.getMonitoringStats();
      
      expect(stats).toEqual(expect.objectContaining({
        activeConnections: expect.any(Number),
        activeToolExecutions: expect.any(Number),
        metricsHealth: expect.any(Promise)
      }));
    });
  });

  describe('Server Monitoring', () => {
    it('should initialize server monitoring and register event listeners', () => {
      monitoringMiddleware.initializeServerMonitoring(mockServer);

      expect(mockServer.on).toHaveBeenCalledWith('connect', expect.any(Function));
      expect(mockServer.on).toHaveBeenCalledWith('disconnect', expect.any(Function));
      expect(mockChildLogger.info).toHaveBeenCalledWith('Initializing server monitoring');
    });

    it('should handle connection events', () => {
      monitoringMiddleware.initializeServerMonitoring(mockServer);

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

    it('should handle disconnection events', () => {
      monitoringMiddleware.initializeServerMonitoring(mockServer);

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

  describe('Tool Execution Monitoring', () => {
    it('should create tool execution wrapper', async () => {
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

    it('should handle health check failures', async () => {
      mockMetrics.healthCheck.mockRejectedValue(new Error('Health check failed'));

      const healthStatus = await monitoringMiddleware.healthCheck();

      expect(healthStatus.healthy).toBe(false);
      expect(healthStatus.metricsSystem.healthy).toBe(false);
    });
  });

  describe('Tool Execution Metrics', () => {
    it('should provide detailed tool execution metrics', () => {
      const metrics = monitoringMiddleware.getToolExecutionMetrics();
      
      expect(Array.isArray(metrics)).toBe(true);
      // Should start empty
      expect(metrics).toHaveLength(0);
    });
  });

  describe('Shutdown', () => {
    it('should shutdown gracefully', () => {
      monitoringMiddleware.shutdown();
      
      expect(mockChildLogger.info).toHaveBeenCalledWith('Shutting down monitoring middleware');
      expect(mockMetrics.setActiveConnections).toHaveBeenCalledWith(0);
    });
  });
});