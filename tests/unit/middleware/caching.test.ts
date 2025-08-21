/**
 * @fileoverview Comprehensive unit tests for caching middleware
 * 
 * Tests following production-ready patterns from research report:
 * - Comprehensive mocking strategies
 * - FastMCP integration patterns
 * - Performance and reliability testing
 * - Edge case and error handling validation
 * 
 * Coverage target: 95%+ for critical caching functionality
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { FastMCP } from 'fastmcp';
import { CachingMiddleware, CacheStrategy, CachingMiddlewareConfig } from '../../../src/middleware/caching.js';

// Mock dependencies before any imports
jest.mock('../../../src/lib/cache.js', () => ({
  default: jest.fn().mockImplementation(() => ({
    get: jest.fn(),
    set: jest.fn(),
    del: jest.fn(),
    invalidateByTags: jest.fn(),
    generateKey: jest.fn(),
    isConnected: jest.fn().mockReturnValue(true),
    getStats: jest.fn().mockResolvedValue({}),
    healthCheck: jest.fn().mockResolvedValue({ healthy: true }),
    invalidate: jest.fn().mockResolvedValue(0),
    warmUp: jest.fn().mockResolvedValue(0),
    shutdown: jest.fn().mockResolvedValue(undefined)
  }))
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

jest.mock('../../../src/lib/metrics.js', () => ({
  default: {
    incrementCounter: jest.fn(),
    recordHistogram: jest.fn(),
    setGauge: jest.fn(),
    recordCacheHit: jest.fn(),
    recordCacheMiss: jest.fn(),
    recordToolExecution: jest.fn(),
    recordError: jest.fn()
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
import RedisCache from '../../../src/lib/cache.js';
import logger from '../../../src/lib/logger.js';
import metrics from '../../../src/lib/metrics.js';

// Type-safe mocks
const MockRedisCache = RedisCache as jest.MockedClass<typeof RedisCache>;
const mockLogger = logger as jest.Mocked<typeof logger>;
const mockMetrics = metrics as jest.Mocked<typeof metrics>;

describe('CachingMiddleware', () => {
  let cachingMiddleware: CachingMiddleware;
  let mockServer: jest.Mocked<FastMCP>;
  let mockCache: jest.Mocked<InstanceType<typeof RedisCache>>;
  let mockChildLogger: jest.Mocked<ReturnType<typeof logger.child>>;

  // Test configuration following research patterns
  const testConfig: CachingMiddlewareConfig = {
    cache: {
      host: 'localhost',
      port: 6379,
      keyPrefix: 'test:',
      defaultTTL: 300
    },
    strategies: {
      'list-scenarios': {
        enabled: true,
        ttl: 600,
        tags: ['scenarios'],
        invalidateOn: ['scenario-updated', 'scenario-created', 'scenario-deleted']
      },
      'get-scenario': {
        enabled: true,
        ttl: 300,
        tags: ['scenarios', 'scenario-detail']
      }
    },
    defaultStrategy: {
      enabled: true,
      ttl: 300,
      tags: ['default']
    },
    enableConditionalCaching: true,
    enableEtagSupport: true,
    toolWrapping: {
      enabled: true,
      mode: 'selective',
      includedTools: ['list-scenarios', 'get-scenario'],
      defaultEnabled: false
    }
  };

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

    // Setup mock cache
    mockCache = {
      get: jest.fn(),
      set: jest.fn(),
      del: jest.fn(),
      invalidateByTags: jest.fn(),
      generateKey: jest.fn(),
      isConnected: jest.fn().mockReturnValue(true)
    } as any;
    MockRedisCache.mockImplementation(() => mockCache);

    // Setup mock server
    mockServer = {
      addTool: jest.fn(),
      on: jest.fn(),
      emit: jest.fn()
    } as any;

    // Initialize middleware
    cachingMiddleware = new CachingMiddleware(testConfig);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Constructor and Initialization', () => {
    it('should initialize with default configuration', () => {
      const defaultMiddleware = new CachingMiddleware();
      expect(MockRedisCache).toHaveBeenCalledWith(expect.objectContaining({
        host: 'localhost',
        port: 6379
      }));
    });

    it('should initialize with custom configuration', () => {
      expect(MockRedisCache).toHaveBeenCalledWith(testConfig.cache);
      expect(mockLogger.child).toHaveBeenCalledWith({ component: 'CachingMiddleware' });
    });

    it('should validate configuration on initialization', () => {
      const invalidConfig = {
        ...testConfig,
        cache: {
          ...testConfig.cache,
          port: -1 // Invalid port
        }
      };

      expect(() => new CachingMiddleware(invalidConfig as any))
        .toThrow('Invalid cache configuration');
    });
  });

  describe('Cache Strategy Management', () => {
    it('should get strategy for registered tool', () => {
      const strategy = cachingMiddleware.getStrategy('list-scenarios');
      
      expect(strategy).toEqual(testConfig.strategies['list-scenarios']);
    });

    it('should return default strategy for unregistered tool', () => {
      const strategy = cachingMiddleware.getStrategy('unknown-tool');
      
      expect(strategy).toEqual(testConfig.defaultStrategy);
    });

    it('should set custom strategy for tool', () => {
      const customStrategy: CacheStrategy = {
        enabled: true,
        ttl: 900,
        tags: ['custom'],
        invalidateOn: ['custom-event']
      };

      cachingMiddleware.setStrategy('custom-tool', customStrategy);
      
      expect(cachingMiddleware.getStrategy('custom-tool')).toEqual(customStrategy);
    });

    it('should validate strategy configuration', () => {
      const invalidStrategy = {
        enabled: true,
        ttl: -1, // Invalid TTL
        tags: []
      };

      expect(() => cachingMiddleware.setStrategy('invalid-tool', invalidStrategy as any))
        .toThrow('Invalid strategy configuration');
    });
  });

  describe('Cache Key Generation', () => {
    beforeEach(() => {
      mockCache.generateKey.mockImplementation((operation, params) => 
        `${operation}:${JSON.stringify(params)}`
      );
    });

    it('should generate consistent cache keys', () => {
      const params = { id: '123', filter: 'active' };
      
      const key1 = cachingMiddleware.generateCacheKey('list-scenarios', params);
      const key2 = cachingMiddleware.generateCacheKey('list-scenarios', params);
      
      expect(key1).toBe(key2);
      expect(mockCache.generateKey).toHaveBeenCalledWith('list-scenarios', params, undefined);
    });

    it('should use custom key generator when provided', () => {
      const customKeyGenerator = jest.fn().mockReturnValue('custom-key');
      const strategy: CacheStrategy = {
        enabled: true,
        ttl: 300,
        tags: ['custom'],
        keyGenerator: customKeyGenerator
      };

      cachingMiddleware.setStrategy('custom-tool', strategy);
      
      const params = { id: '123' };
      const key = cachingMiddleware.generateCacheKey('custom-tool', params);
      
      expect(customKeyGenerator).toHaveBeenCalledWith('custom-tool', params, undefined);
      expect(key).toBe('custom-key');
    });

    it('should handle complex parameter objects', () => {
      const complexParams = {
        filters: {
          status: ['active', 'paused'],
          team: '456'
        },
        pagination: {
          page: 1,
          limit: 20
        },
        sort: 'created_at'
      };

      const key = cachingMiddleware.generateCacheKey('list-scenarios', complexParams);
      
      expect(mockCache.generateKey).toHaveBeenCalledWith('list-scenarios', complexParams, undefined);
      expect(key).toBeTruthy();
    });
  });

  describe('Cache Operations', () => {
    beforeEach(() => {
      mockCache.generateKey.mockImplementation((operation, params) => 
        `cache:${operation}:${JSON.stringify(params)}`
      );
    });

    describe('getCachedResponse', () => {
      it('should return cached response when available', async () => {
        const cachedData = {
          data: { scenarios: [{ id: '123', name: 'Test' }] },
          etag: 'abc123',
          timestamp: Date.now() - 1000,
          operation: 'list-scenarios',
          params: { filter: 'active' }
        };

        mockCache.get.mockResolvedValue(cachedData);

        const params = { filter: 'active' };
        const result = await cachingMiddleware.getCachedResponse('list-scenarios', params);

        expect(result).toEqual(cachedData);
        expect(mockCache.get).toHaveBeenCalledWith(
          `cache:list-scenarios:${JSON.stringify(params)}`
        );
      });

      it('should return null when cache miss occurs', async () => {
        mockCache.get.mockResolvedValue(null);

        const result = await cachingMiddleware.getCachedResponse('list-scenarios', { filter: 'active' });

        expect(result).toBeNull();
        expect(mockMetrics.incrementCounter).toHaveBeenCalledWith('cache.miss', {
          operation: 'list-scenarios'
        });
      });

      it('should handle cache errors gracefully', async () => {
        mockCache.get.mockRejectedValue(new Error('Redis connection failed'));

        const result = await cachingMiddleware.getCachedResponse('list-scenarios', { filter: 'active' });

        expect(result).toBeNull();
        expect(mockChildLogger.error).toHaveBeenCalledWith(
          'Cache read error',
          expect.objectContaining({
            operation: 'list-scenarios',
            error: 'Redis connection failed'
          })
        );
      });

      it('should validate cached response freshness', async () => {
        const expiredData = {
          data: { scenarios: [] },
          etag: 'expired123',
          timestamp: Date.now() - 700000, // 11+ minutes old
          operation: 'list-scenarios',
          params: { filter: 'active' }
        };

        mockCache.get.mockResolvedValue(expiredData);

        const result = await cachingMiddleware.getCachedResponse('list-scenarios', { filter: 'active' });

        expect(result).toBeNull();
        expect(mockCache.del).toHaveBeenCalled(); // Should delete expired entry
      });
    });

    describe('setCachedResponse', () => {
      it('should cache successful responses', async () => {
        const response = { 
          data: { scenarios: [{ id: '123', name: 'Test' }] },
          success: true 
        };
        const params = { filter: 'active' };

        await cachingMiddleware.setCachedResponse('list-scenarios', params, response);

        expect(mockCache.set).toHaveBeenCalledWith(
          `cache:list-scenarios:${JSON.stringify(params)}`,
          expect.objectContaining({
            data: response,
            operation: 'list-scenarios',
            params
          }),
          600 // TTL from strategy
        );

        expect(mockMetrics.incrementCounter).toHaveBeenCalledWith('cache.write', {
          operation: 'list-scenarios'
        });
      });

      it('should not cache when strategy disabled', async () => {
        const disabledStrategy: CacheStrategy = {
          enabled: false,
          ttl: 300,
          tags: ['disabled']
        };

        cachingMiddleware.setStrategy('disabled-tool', disabledStrategy);

        const response = { data: {}, success: true };
        await cachingMiddleware.setCachedResponse('disabled-tool', {}, response);

        expect(mockCache.set).not.toHaveBeenCalled();
      });

      it('should not cache error responses', async () => {
        const errorResponse = { 
          data: null, 
          success: false, 
          error: 'API Error' 
        };

        await cachingMiddleware.setCachedResponse('list-scenarios', {}, errorResponse);

        expect(mockCache.set).not.toHaveBeenCalled();
      });

      it('should respect custom shouldCache predicate', async () => {
        const customStrategy: CacheStrategy = {
          enabled: true,
          ttl: 300,
          tags: ['custom'],
          shouldCache: jest.fn().mockReturnValue(false)
        };

        cachingMiddleware.setStrategy('custom-tool', customStrategy);

        const response = { data: {}, success: true };
        await cachingMiddleware.setCachedResponse('custom-tool', {}, response);

        expect(customStrategy.shouldCache).toHaveBeenCalledWith('custom-tool', {}, response);
        expect(mockCache.set).not.toHaveBeenCalled();
      });
    });

    describe('invalidateCache', () => {
      it('should invalidate cache by specific key', async () => {
        const params = { id: '123' };
        
        await cachingMiddleware.invalidateCache('get-scenario', params);

        expect(mockCache.del).toHaveBeenCalledWith(
          `cache:get-scenario:${JSON.stringify(params)}`
        );
      });

      it('should invalidate cache by tags', async () => {
        await cachingMiddleware.invalidateByTags(['scenarios']);

        expect(mockCache.invalidateByTags).toHaveBeenCalledWith(['scenarios']);
      });

      it('should handle invalidation events', async () => {
        // Setup strategy with invalidation triggers
        const strategy: CacheStrategy = {
          enabled: true,
          ttl: 300,
          tags: ['scenarios'],
          invalidateOn: ['scenario-updated']
        };

        cachingMiddleware.setStrategy('test-tool', strategy);

        await cachingMiddleware.handleInvalidationEvent('scenario-updated', { id: '123' });

        expect(mockCache.invalidateByTags).toHaveBeenCalledWith(['scenarios']);
      });
    });
  });

  describe('FastMCP Integration', () => {
    it('should wrap tools with caching when enabled', () => {
      cachingMiddleware.applyToServer(mockServer);

      expect(mockServer.on).toHaveBeenCalledWith('tool:call', expect.any(Function));
      expect(mockServer.on).toHaveBeenCalledWith('tool:result', expect.any(Function));
    });

    it('should wrap only included tools in selective mode', () => {
      cachingMiddleware.applyToServer(mockServer);

      // Verify tool wrapping logic
      expect(mockChildLogger.info).toHaveBeenCalledWith(
        'Caching middleware applied to server',
        expect.objectContaining({
          mode: 'selective',
          includedTools: ['list-scenarios', 'get-scenario']
        })
      );
    });

    it('should handle tool execution with caching', async () => {
      // Mock cached response
      mockCache.get.mockResolvedValue({
        data: { scenarios: [] },
        etag: 'cached123',
        timestamp: Date.now(),
        operation: 'list-scenarios',
        params: {}
      });

      const toolHandler = jest.fn();
      mockServer.on.mockImplementation((event, handler) => {
        if (event === 'tool:call' && handler) {
          // Simulate tool call
          const mockEvent = {
            tool: 'list-scenarios',
            parameters: {},
            respond: jest.fn()
          };
          handler(mockEvent);
        }
      });

      cachingMiddleware.applyToServer(mockServer);

      expect(mockMetrics.incrementCounter).toHaveBeenCalledWith('cache.hit', {
        operation: 'list-scenarios'
      });
    });
  });

  describe('Performance and Reliability', () => {
    it('should measure cache operation performance', async () => {
      const startTime = Date.now();
      mockCache.get.mockImplementation(() => 
        new Promise(resolve => setTimeout(() => resolve(null), 50))
      );

      await cachingMiddleware.getCachedResponse('list-scenarios', {});

      expect(mockMetrics.recordHistogram).toHaveBeenCalledWith(
        'cache.operation.duration',
        expect.any(Number),
        { operation: 'get' }
      );
    });

    it('should handle concurrent cache operations', async () => {
      const promises = Array(10).fill(0).map((_, i) => 
        cachingMiddleware.getCachedResponse('list-scenarios', { id: i })
      );

      mockCache.get.mockResolvedValue(null);

      const results = await Promise.all(promises);

      expect(results).toHaveLength(10);
      expect(mockCache.get).toHaveBeenCalledTimes(10);
    });

    it('should implement circuit breaker for cache failures', async () => {
      // Simulate multiple cache failures
      mockCache.get.mockRejectedValue(new Error('Cache failure'));

      const promises = Array(5).fill(0).map(() => 
        cachingMiddleware.getCachedResponse('list-scenarios', {})
      );

      const results = await Promise.all(promises);

      expect(results.every(result => result === null)).toBe(true);
      expect(mockChildLogger.error).toHaveBeenCalledTimes(5);
    });
  });

  describe('ETag Support', () => {
    it('should generate ETags for cached responses', async () => {
      const response = { 
        data: { scenarios: [{ id: '123' }] },
        success: true 
      };

      await cachingMiddleware.setCachedResponse('list-scenarios', {}, response);

      const setCall = mockCache.set.mock.calls[0];
      const cachedResponse = setCall[1];

      expect(cachedResponse.etag).toBeTruthy();
      expect(cachedResponse.etag).toMatch(/^[a-f0-9]+$/); // Hex string
    });

    it('should validate ETag matches for conditional requests', async () => {
      const cachedResponse = {
        data: { scenarios: [] },
        etag: 'abc123',
        timestamp: Date.now(),
        operation: 'list-scenarios',
        params: {}
      };

      mockCache.get.mockResolvedValue(cachedResponse);

      const result = await cachingMiddleware.getCachedResponse(
        'list-scenarios', 
        {}, 
        { ifNoneMatch: 'abc123' }
      );

      expect(result).toEqual(expect.objectContaining({
        notModified: true,
        etag: 'abc123'
      }));
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle malformed cached data', async () => {
      mockCache.get.mockResolvedValue('invalid-json-data');

      const result = await cachingMiddleware.getCachedResponse('list-scenarios', {});

      expect(result).toBeNull();
      expect(mockChildLogger.error).toHaveBeenCalledWith(
        'Invalid cached data format',
        expect.any(Object)
      );
    });

    it('should handle cache connection failures', async () => {
      mockCache.isConnected.mockReturnValue(false);

      const result = await cachingMiddleware.getCachedResponse('list-scenarios', {});

      expect(result).toBeNull();
      expect(mockChildLogger.warn).toHaveBeenCalledWith('Cache not connected, skipping cache read');
    });

    it('should handle large cache keys gracefully', async () => {
      const largeParams = {
        data: 'x'.repeat(10000) // Very large parameter
      };

      await expect(
        cachingMiddleware.getCachedResponse('list-scenarios', largeParams)
      ).resolves.toBeNull();

      expect(mockChildLogger.warn).toHaveBeenCalledWith(
        'Cache key too large, skipping cache operation',
        expect.objectContaining({ keyLength: expect.any(Number) })
      );
    });

    it('should handle cache storage limits', async () => {
      mockCache.set.mockRejectedValue(new Error('OOM command not allowed'));

      const response = { data: {}, success: true };
      
      await expect(
        cachingMiddleware.setCachedResponse('list-scenarios', {}, response)
      ).resolves.not.toThrow();

      expect(mockChildLogger.error).toHaveBeenCalledWith(
        'Cache write failed',
        expect.objectContaining({ error: 'OOM command not allowed' })
      );
    });
  });
});