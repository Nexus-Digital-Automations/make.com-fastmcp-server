/**
 * @fileoverview Working middleware integration tests - Practical scenarios
 * Tests middleware functionality with simplified, robust mocking patterns
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';

// Simple mock implementations that work with Jest
const mockLogger = {
  child: jest.fn().mockReturnValue({
    info: jest.fn(),
    debug: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    trace: jest.fn()
  }),
  info: jest.fn(),
  debug: jest.fn(),
  warn: jest.fn(),
  error: jest.fn()
};

const mockMetrics = {
  setActiveConnections: jest.fn(),
  recordRequest: jest.fn(),
  createTimer: jest.fn().mockReturnValue(() => 1.5),
  recordToolExecution: jest.fn(),
  recordError: jest.fn(),
  recordAuthAttempt: jest.fn(),
  recordAuthDuration: jest.fn(),
  recordMakeApiCall: jest.fn(),
  recordCacheHit: jest.fn(),
  recordCacheMiss: jest.fn(),
  healthCheck: jest.fn().mockResolvedValue({ 
    healthy: true, 
    metricsCount: 100 
  })
};

const mockCacheInstance = {
  get: jest.fn(),
  set: jest.fn(),
  generateKey: jest.fn((prefix: string, key: string) => `${prefix}:${key}`),
  getStats: jest.fn().mockResolvedValue({ 
    hits: 100, 
    misses: 20, 
    totalEntries: 500 
  }),
  healthCheck: jest.fn().mockResolvedValue({ 
    healthy: true, 
    connected: true 
  }),
  invalidate: jest.fn().mockResolvedValue(5),
  warmUp: jest.fn().mockResolvedValue(10),
  shutdown: jest.fn().mockResolvedValue(undefined)
};

const MockRedisCache = jest.fn().mockImplementation(() => mockCacheInstance);

// Mock modules before importing middleware
jest.mock('../../../src/lib/logger.js', () => ({ default: mockLogger }));
jest.mock('../../../src/lib/metrics.js', () => ({ default: mockMetrics }));
jest.mock('../../../src/lib/cache.js', () => ({
  default: MockRedisCache,
  defaultCacheConfig: {
    redis: { host: 'localhost', port: 6379 },
    compression: { enabled: true, threshold: 1024, level: 6 },
    ttl: { default: 1800 },
    keyPrefix: 'test:'
  }
}));

// Mock FastMCP with essential functionality
const mockServer = {
  addTool: jest.fn(),
  on: jest.fn(),
  start: jest.fn(),
  shutdown: jest.fn()
};

jest.mock('fastmcp', () => ({
  FastMCP: jest.fn().mockImplementation(() => mockServer)
}));

// Import middleware after mocks are set up
import { CachingMiddleware } from '../../../src/middleware/caching.js';
import { monitoring } from '../../../src/middleware/monitoring.js';

describe('Middleware Integration Tests - Working Implementation', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('CachingMiddleware', () => {
    it('should initialize with default configuration', () => {
      const middleware = new CachingMiddleware();
      expect(middleware).toBeDefined();
      expect(MockRedisCache).toHaveBeenCalledWith(expect.objectContaining({
        redis: expect.objectContaining({ host: 'localhost' })
      }));
    });

    it('should apply caching to FastMCP server', () => {
      const middleware = new CachingMiddleware();
      
      middleware.apply(mockServer as any);
      
      // Verify server interactions
      expect(mockLogger.child).toHaveBeenCalledWith({ component: 'CachingMiddleware' });
      expect(mockServer.addTool).toHaveBeenCalledTimes(3); // cache-status, cache-invalidate, cache-warmup
    });

    it('should wrap operations with caching logic', async () => {
      const middleware = new CachingMiddleware();
      
      // Mock cache miss scenario
      mockCacheInstance.get.mockResolvedValueOnce(null);
      mockCacheInstance.set.mockResolvedValueOnce(undefined);
      
      const mockExecutor = jest.fn().mockResolvedValue({ data: 'test result' });
      
      const result = await middleware.wrapWithCache(
        'test_operation',
        { param: 'value' },
        mockExecutor
      );
      
      expect(result).toEqual({ data: 'test result' });
      expect(mockExecutor).toHaveBeenCalledTimes(1);
      expect(mockCacheInstance.get).toHaveBeenCalled();
      expect(mockCacheInstance.set).toHaveBeenCalled();
      expect(mockMetrics.recordCacheMiss).toHaveBeenCalled();
    });

    it('should return cached data on cache hit', async () => {
      const middleware = new CachingMiddleware();
      
      const cachedData = {
        data: { cached: 'result' },
        timestamp: Date.now() - 1000,
        etag: '"cached"',
        operation: 'test_operation',
        params: { param: 'value' }
      };
      
      mockCacheInstance.get.mockResolvedValueOnce(cachedData);
      
      const mockExecutor = jest.fn();
      
      const result = await middleware.wrapWithCache(
        'test_operation',
        { param: 'value' },
        mockExecutor
      );
      
      expect(result).toEqual({ cached: 'result' });
      expect(mockExecutor).not.toHaveBeenCalled();
      expect(mockMetrics.recordCacheHit).toHaveBeenCalled();
    });

    it('should handle cache errors gracefully', async () => {
      const middleware = new CachingMiddleware();
      
      mockCacheInstance.get.mockRejectedValueOnce(new Error('Cache error'));
      
      const mockExecutor = jest.fn().mockResolvedValue({ data: 'fallback result' });
      
      const result = await middleware.wrapWithCache(
        'test_operation',
        { param: 'value' },
        mockExecutor
      );
      
      expect(result).toEqual({ data: 'fallback result' });
      expect(mockExecutor).toHaveBeenCalledTimes(1);
    });

    it('should provide operation statistics', () => {
      const middleware = new CachingMiddleware();
      
      const stats = middleware.getOperationStats();
      
      expect(stats).toEqual(expect.objectContaining({}));
    });

    it('should perform health check', async () => {
      const middleware = new CachingMiddleware();
      
      const health = await middleware.healthCheck();
      
      expect(health).toEqual({
        healthy: true,
        cache: true,
        middleware: true
      });
      expect(mockCacheInstance.healthCheck).toHaveBeenCalled();
    });

    it('should shutdown gracefully', async () => {
      const middleware = new CachingMiddleware();
      
      await middleware.shutdown();
      
      expect(mockCacheInstance.shutdown).toHaveBeenCalled();
    });
  });

  describe('MonitoringMiddleware', () => {
    it('should initialize server monitoring', () => {
      monitoring.initializeServerMonitoring(mockServer as any);
      
      expect(mockServer.on).toHaveBeenCalledWith('connect', expect.any(Function));
      expect(mockServer.on).toHaveBeenCalledWith('disconnect', expect.any(Function));
    });

    it('should wrap tool execution with monitoring', async () => {
      const mockExecution = jest.fn().mockResolvedValue('success');
      
      const wrappedExecution = monitoring.wrapToolExecution(
        'test-tool',
        'test-operation',
        mockExecution,
        { userId: 'user123' }
      );
      
      const result = await wrappedExecution();
      
      expect(result).toBe('success');
      expect(mockExecution).toHaveBeenCalledTimes(1);
      expect(mockMetrics.createTimer).toHaveBeenCalled();
      expect(mockMetrics.recordToolExecution).toHaveBeenCalledWith(
        'test-tool', 
        'success', 
        1.5, 
        'user123'
      );
    });

    it('should handle tool execution errors', async () => {
      const mockExecution = jest.fn().mockRejectedValue(new Error('Tool failed'));
      
      const wrappedExecution = monitoring.wrapToolExecution(
        'test-tool',
        'test-operation',
        mockExecution
      );
      
      await expect(wrappedExecution()).rejects.toThrow('Tool failed');
      expect(mockMetrics.recordToolExecution).toHaveBeenCalledWith(
        'test-tool', 
        'error', 
        1.5, 
        undefined
      );
      expect(mockMetrics.recordError).toHaveBeenCalled();
    });

    it('should monitor authentication attempts', async () => {
      const mockAuth = jest.fn().mockResolvedValue('authenticated');
      
      const wrappedAuth = monitoring.monitorAuthentication(mockAuth, { 
        userId: 'user123' 
      });
      
      const result = await wrappedAuth();
      
      expect(result).toBe('authenticated');
      expect(mockMetrics.recordAuthAttempt).toHaveBeenCalledWith('success');
      expect(mockMetrics.recordAuthDuration).toHaveBeenCalledWith(1.5);
    });

    it('should monitor Make.com API calls', async () => {
      const mockApiCall = jest.fn().mockResolvedValue({ data: 'api result' });
      
      const wrappedApiCall = monitoring.monitorMakeApiCall(
        '/scenarios',
        'GET',
        mockApiCall,
        { correlationId: 'abc123' }
      );
      
      const result = await wrappedApiCall();
      
      expect(result).toEqual({ data: 'api result' });
      expect(mockMetrics.recordMakeApiCall).toHaveBeenCalledWith(
        '/scenarios',
        'GET', 
        'success', 
        1.5
      );
    });

    it('should provide monitoring statistics', () => {
      const stats = monitoring.getMonitoringStats();
      
      expect(stats).toEqual({
        activeConnections: 0,
        activeToolExecutions: 0,
        metricsHealth: expect.any(Promise)
      });
    });

    it('should provide tool execution metrics', () => {
      const metrics = monitoring.getToolExecutionMetrics();
      
      expect(Array.isArray(metrics)).toBe(true);
    });

    it('should perform health check', async () => {
      const health = await monitoring.healthCheck();
      
      expect(health).toEqual({
        healthy: true,
        activeConnections: 0,
        activeToolExecutions: 0,
        metricsSystem: { healthy: true, metricsCount: 100 }
      });
    });

    it('should shutdown gracefully', () => {
      monitoring.shutdown();
      
      expect(mockMetrics.setActiveConnections).toHaveBeenCalledWith(0);
    });
  });

  describe('Middleware Integration', () => {
    it('should work together for comprehensive monitoring and caching', async () => {
      const cachingMiddleware = new CachingMiddleware();
      const monitoringMiddleware = monitoring;
      
      // Apply caching middleware
      cachingMiddleware.apply(mockServer as any);
      
      // Initialize monitoring
      monitoringMiddleware.initializeServerMonitoring(mockServer as any);
      
      // Simulate a tool execution with both caching and monitoring
      const mockTool = jest.fn().mockResolvedValue({ result: 'integrated test' });
      
      // Wrap with monitoring first, then caching
      const monitoredTool = monitoringMiddleware.wrapToolExecution(
        'integrated-tool',
        'integration-test',
        mockTool
      );
      
      mockCacheInstance.get.mockResolvedValueOnce(null); // Cache miss
      mockCacheInstance.set.mockResolvedValueOnce(undefined);
      
      const cachedAndMonitoredResult = await cachingMiddleware.wrapWithCache(
        'integrated-tool',
        { test: 'params' },
        monitoredTool
      );
      
      expect(cachedAndMonitoredResult).toEqual({ result: 'integrated test' });
      
      // Verify both monitoring and caching were involved
      expect(mockMetrics.recordToolExecution).toHaveBeenCalled();
      expect(mockMetrics.recordCacheMiss).toHaveBeenCalled();
      expect(mockCacheInstance.set).toHaveBeenCalled();
    });

    it('should handle errors in integrated middleware stack', async () => {
      const cachingMiddleware = new CachingMiddleware();
      
      const mockFailingTool = jest.fn().mockRejectedValue(new Error('Tool error'));
      
      const monitoredTool = monitoring.wrapToolExecution(
        'failing-tool',
        'error-test',
        mockFailingTool
      );
      
      mockCacheInstance.get.mockResolvedValueOnce(null); // Ensure cache miss
      
      await expect(
        cachingMiddleware.wrapWithCache(
          'failing-tool',
          { test: 'error' },
          monitoredTool
        )
      ).rejects.toThrow('Tool error');
      
      // Verify error was recorded by monitoring
      expect(mockMetrics.recordToolExecution).toHaveBeenCalledWith(
        'failing-tool',
        'error',
        expect.any(Number),
        undefined
      );
      expect(mockMetrics.recordError).toHaveBeenCalled();
    });
  });
});