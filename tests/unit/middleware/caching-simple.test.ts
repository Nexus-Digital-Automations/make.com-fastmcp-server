/**
 * @fileoverview Simplified unit tests for caching middleware
 * Tests core functionality that exists in the actual implementation
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { FastMCP } from 'fastmcp';

// Mock dependencies before any imports
const mockCacheInstance = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
  generateKey: jest.fn(),
  isConnected: jest.fn().mockReturnValue(true),
  getStats: jest.fn().mockResolvedValue({ hits: 0, misses: 0 }),
  healthCheck: jest.fn().mockResolvedValue({ healthy: true }),
  invalidate: jest.fn().mockResolvedValue(0),
  warmUp: jest.fn().mockResolvedValue(0),
  shutdown: jest.fn().mockResolvedValue(undefined)
};

jest.mock('../../../src/lib/cache.js', () => ({
  default: jest.fn().mockImplementation(() => mockCacheInstance),
  defaultCacheConfig: {
    host: 'localhost',
    port: 6379,
    keyPrefix: 'test:',
    ttl: 300
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
    })
  }
}));

jest.mock('../../../src/lib/metrics.js', () => ({
  default: {
    recordCacheHit: jest.fn(),
    recordCacheMiss: jest.fn(),
    recordToolExecution: jest.fn(),
    recordError: jest.fn()
  }
}));

jest.mock('../../../src/lib/config.js', () => ({
  default: {
    getLogLevel: jest.fn().mockReturnValue('info')
  }
}));

// Mock types to avoid import issues
jest.mock('../../../src/types/index.js', () => ({}));

import { CachingMiddleware } from '../../../src/middleware/caching.js';
import metrics from '../../../src/lib/metrics.js';
import logger from '../../../src/lib/logger.js';

const mockMetrics = metrics as jest.Mocked<typeof metrics>;
const mockLogger = logger as jest.Mocked<typeof logger>;

describe('CachingMiddleware', () => {
  let cachingMiddleware: CachingMiddleware;
  let mockServer: jest.Mocked<FastMCP>;
  let mockChildLogger: jest.Mocked<ReturnType<typeof logger.child>>;

  beforeEach(() => {
    jest.clearAllMocks();

    // Reset cache mock
    Object.values(mockCacheInstance).forEach(mock => {
      if (typeof mock === 'function') {
        mock.mockClear();
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
      addTool: jest.fn(),
      on: jest.fn(),
      emit: jest.fn()
    } as any;

    cachingMiddleware = new CachingMiddleware();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Initialization', () => {
    it('should initialize with default configuration', () => {
      expect(mockLogger.child).toHaveBeenCalledWith({ component: 'CachingMiddleware' });
    });

    it('should initialize with custom configuration', () => {
      const customConfig = {
        cache: {
          host: 'custom-host',
          port: 6380,
          keyPrefix: 'custom:',
          ttl: 600
        }
      };

      const customMiddleware = new CachingMiddleware(customConfig);
      expect(customMiddleware).toBeDefined();
    });
  });

  describe('Cache Operations', () => {
    it('should execute operation without caching when strategy disabled', async () => {
      const mockExecutor = jest.fn().mockResolvedValue({ success: true, data: 'test' });
      
      const result = await cachingMiddleware.wrapWithCache(
        'disabled-operation',
        { param: 'value' },
        mockExecutor
      );

      expect(result).toEqual({ success: true, data: 'test' });
      expect(mockExecutor).toHaveBeenCalled();
    });

    it('should handle cache miss and store result', async () => {
      const mockExecutor = jest.fn().mockResolvedValue({ success: true, data: 'fresh-data' });
      
      // Mock cache miss
      mockCacheInstance.get.mockResolvedValue(null);
      mockCacheInstance.generateKey.mockReturnValue('test-cache-key');
      
      const result = await cachingMiddleware.wrapWithCache(
        'list_scenarios', // This has a strategy defined
        { limit: 50 },
        mockExecutor
      );

      expect(result).toEqual({ success: true, data: 'fresh-data' });
      expect(mockExecutor).toHaveBeenCalled();
      expect(mockCacheInstance.get).toHaveBeenCalled();
      expect(mockCacheInstance.set).toHaveBeenCalled();
      expect(mockMetrics.recordToolExecution).toHaveBeenCalled();
    });

    it('should handle cache hit and return cached data', async () => {
      const mockExecutor = jest.fn();
      const cachedData = {
        data: { success: true, data: 'cached-data' },
        etag: 'abc123',
        timestamp: Date.now() - 1000,
        operation: 'list_scenarios',
        params: { limit: 50 }
      };
      
      // Mock cache hit
      mockCacheInstance.get.mockResolvedValue(cachedData);
      mockCacheInstance.generateKey.mockReturnValue('test-cache-key');
      
      const result = await cachingMiddleware.wrapWithCache(
        'list_scenarios',
        { limit: 50 },
        mockExecutor
      );

      expect(result).toEqual({ success: true, data: 'cached-data' });
      expect(mockExecutor).not.toHaveBeenCalled(); // Should not execute when cached
      expect(mockMetrics.recordCacheHit).toHaveBeenCalled();
    });

    it('should handle cache errors gracefully', async () => {
      const mockExecutor = jest.fn().mockResolvedValue({ success: true, data: 'fallback-data' });
      
      // Mock cache error
      mockCacheInstance.get.mockRejectedValue(new Error('Cache connection failed'));
      
      const result = await cachingMiddleware.wrapWithCache(
        'list_scenarios',
        { param: 'value' },
        mockExecutor
      );

      expect(result).toEqual({ success: true, data: 'fallback-data' });
      expect(mockExecutor).toHaveBeenCalled();
      expect(mockChildLogger.error).toHaveBeenCalledWith(
        'Cache operation error',
        expect.objectContaining({
          operation: 'list_scenarios'
        })
      );
    });
  });

  describe('Server Integration', () => {
    it('should apply caching middleware to FastMCP server', () => {
      // Store original addTool to verify it gets wrapped
      const originalAddTool = mockServer.addTool;
      
      cachingMiddleware.apply(mockServer);

      // Should wrap the addTool method
      expect(mockServer.addTool).not.toBe(originalAddTool);
      expect(mockChildLogger.info).toHaveBeenCalledWith('Applying caching middleware to FastMCP server');
    });

    it('should add cache management tools', () => {
      cachingMiddleware.apply(mockServer);

      // Should register cache management tools
      expect(mockServer.addTool).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'cache-status'
        })
      );
      expect(mockServer.addTool).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'cache-invalidate'
        })
      );
      expect(mockServer.addTool).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'cache-warmup'
        })
      );
    });
  });

  describe('Cache Statistics', () => {
    it('should provide operation statistics', () => {
      const stats = cachingMiddleware.getOperationStats();
      
      expect(typeof stats).toBe('object');
      // Should have stats for configured strategies
      expect(stats).toEqual(expect.objectContaining({
        list_scenarios: expect.objectContaining({
          hits: expect.any(Number),
          misses: expect.any(Number),
          errors: expect.any(Number),
          hitRate: expect.any(Number)
        })
      }));
    });
  });

  describe('Cache Invalidation', () => {
    it('should invalidate operation cache', async () => {
      mockCacheInstance.invalidate.mockResolvedValue(5); // 5 entries deleted
      
      const deletedCount = await cachingMiddleware.invalidateOperationCache('list_scenarios');
      
      expect(deletedCount).toBeGreaterThanOrEqual(0);
      expect(mockChildLogger.info).toHaveBeenCalledWith(
        'Operation cache invalidated',
        expect.objectContaining({
          operation: 'list_scenarios'
        })
      );
    });
  });

  describe('Health Check', () => {
    it('should provide health check information', async () => {
      const healthStatus = await cachingMiddleware.healthCheck();

      expect(healthStatus).toEqual(expect.objectContaining({
        healthy: expect.any(Boolean),
        cache: expect.any(Boolean),
        middleware: expect.any(Boolean)
      }));
    });

    it('should handle health check failures', async () => {
      mockCacheInstance.healthCheck.mockRejectedValue(new Error('Health check failed'));

      const healthStatus = await cachingMiddleware.healthCheck();

      expect(healthStatus.healthy).toBe(false);
      expect(healthStatus.cache).toBe(false);
      expect(healthStatus.middleware).toBe(false);
    });
  });

  describe('Shutdown', () => {
    it('should shutdown gracefully', async () => {
      await cachingMiddleware.shutdown();
      
      expect(mockChildLogger.info).toHaveBeenCalledWith('Shutting down caching middleware');
      expect(mockCacheInstance.shutdown).toHaveBeenCalled();
    });
  });
});