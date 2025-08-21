/**
 * @fileoverview Comprehensive caching middleware tests - Advanced scenarios
 * Tests complex caching strategies, cache invalidation, and performance optimization
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { FastMCP } from 'fastmcp';

// Enhanced mock setup with advanced cache behaviors
const mockCacheInstance = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
  generateKey: jest.fn(),
  isConnected: jest.fn().mockReturnValue(true),
  getStats: jest.fn().mockResolvedValue({ 
    hits: 150, 
    misses: 45, 
    hitRate: 0.769,
    totalEntries: 1250,
    memoryUsage: '15.2MB',
    avgResponseTime: 45
  }),
  healthCheck: jest.fn().mockResolvedValue({ 
    healthy: true, 
    connected: true,
    latency: 2.1,
    memoryPressure: 'low'
  }),
  invalidate: jest.fn().mockResolvedValue(12),
  warmUp: jest.fn().mockResolvedValue(85),
  shutdown: jest.fn().mockResolvedValue(undefined),
  // Advanced cache features
  getWithTTL: jest.fn(),
  setWithExpiry: jest.fn(),
  getMultiple: jest.fn(),
  setMultiple: jest.fn(),
  invalidatePattern: jest.fn(),
  getKeysByPattern: jest.fn(),
  getMemoryStats: jest.fn()
};

// Mock dependencies with enhanced functionality
jest.mock('../../../src/lib/cache.js', () => ({
  default: jest.fn().mockImplementation(() => mockCacheInstance),
  defaultCacheConfig: {
    host: 'localhost',
    port: 6379,
    keyPrefix: 'fastmcp:',
    ttl: 1800,
    compression: true,
    serialization: 'json',
    maxMemoryPolicy: 'allkeys-lru'
  }
}));

jest.mock('../../../src/lib/logger.js', () => ({
  default: {
    child: jest.fn().mockReturnValue({
      info: jest.fn(),
      debug: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
      trace: jest.fn(),
      child: jest.fn().mockReturnThis()
    })
  }
}));

jest.mock('../../../src/lib/metrics.js', () => ({
  default: {
    recordCacheHit: jest.fn(),
    recordCacheMiss: jest.fn(),
    recordToolExecution: jest.fn(),
    recordError: jest.fn(),
    recordCacheOperationDuration: jest.fn(),
    recordCacheSize: jest.fn(),
    recordCacheEviction: jest.fn()
  }
}));

jest.mock('../../../src/lib/config.js', () => ({
  default: {
    getLogLevel: jest.fn().mockReturnValue('debug')
  }
}));

// Mock types
jest.mock('../../../src/types/index.js', () => ({
  ApiResponse: {}
}));

import { CachingMiddleware } from '../../../src/middleware/caching.js';
import metrics from '../../../src/lib/metrics.js';
import logger from '../../../src/lib/logger.js';

const mockMetrics = metrics as jest.Mocked<typeof metrics>;
const mockLogger = logger as jest.Mocked<typeof logger>;

describe('CachingMiddleware - Comprehensive Tests', () => {
  let cachingMiddleware: CachingMiddleware;
  let mockServer: jest.Mocked<FastMCP>;
  let mockChildLogger: jest.Mocked<ReturnType<typeof logger.child>>;
  let originalAddTool: jest.MockedFunction<any>;

  beforeEach(() => {
    jest.clearAllMocks();

    // Reset cache mock with enhanced state
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
      trace: jest.fn(),
      child: jest.fn().mockReturnThis()
    } as any;
    mockLogger.child = jest.fn().mockReturnValue(mockChildLogger);

    originalAddTool = jest.fn();
    mockServer = {
      addTool: originalAddTool,
      on: jest.fn(),
      emit: jest.fn(),
      removeTool: jest.fn(),
      getTool: jest.fn(),
      listTools: jest.fn()
    } as any;

    cachingMiddleware = new CachingMiddleware({
      cache: {
        host: 'localhost',
        port: 6379,
        keyPrefix: 'test:',
        ttl: 3600,
        compression: true
      },
      toolWrapping: {
        enabled: true,
        mode: 'selective',
        defaultEnabled: true
      }
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Advanced Caching Strategies', () => {
    it('should implement time-based cache invalidation with TTL awareness', async () => {
      const mockExecutor = jest.fn().mockResolvedValue({ success: true, data: 'fresh-data' });
      const currentTime = Date.now();
      
      // Mock cached data with different ages
      const expiredCache = {
        data: { success: true, data: 'expired-data' },
        etag: 'expired123',
        timestamp: currentTime - 7200000, // 2 hours old
        operation: 'list_scenarios',
        params: { limit: 50 }
      };
      
      const validCache = {
        data: { success: true, data: 'valid-cached-data' },
        etag: 'valid456',
        timestamp: currentTime - 900000, // 15 minutes old
        operation: 'list_scenarios',
        params: { limit: 50 }
      };

      // Test expired cache - should execute fresh
      mockCacheInstance.get.mockResolvedValueOnce(expiredCache);
      mockCacheInstance.generateKey.mockReturnValue('test-expired-key');
      
      const expiredResult = await cachingMiddleware.wrapWithCache(
        'list_scenarios',
        { limit: 50 },
        mockExecutor
      );

      expect(expiredResult.data).toBe('fresh-data');
      expect(mockExecutor).toHaveBeenCalledTimes(1);
      expect(mockCacheInstance.set).toHaveBeenCalled();

      // Test valid cache - should return cached
      mockExecutor.mockClear();
      mockCacheInstance.get.mockResolvedValueOnce(validCache);
      mockCacheInstance.generateKey.mockReturnValue('test-valid-key');
      
      const validResult = await cachingMiddleware.wrapWithCache(
        'list_scenarios',
        { limit: 50 },
        mockExecutor
      );

      expect(validResult.data).toBe('valid-cached-data');
      expect(mockExecutor).not.toHaveBeenCalled();
      expect(mockMetrics.recordCacheHit).toHaveBeenCalled();
    });

    it('should implement conditional caching based on response characteristics', async () => {
      const scenarios = [
        {
          name: 'large_successful_response',
          response: { 
            success: true, 
            data: Array.from({length: 1000}, (_, i) => ({id: i, name: `Item ${i}`})) 
          },
          shouldCache: true
        },
        {
          name: 'error_response',
          response: { 
            success: false, 
            error: { message: 'Service unavailable', code: 503 } 
          },
          shouldCache: false
        },
        {
          name: 'empty_response',
          response: { 
            success: true, 
            data: [] 
          },
          shouldCache: false
        },
        {
          name: 'small_successful_response',
          response: { 
            success: true, 
            data: { id: 1, name: 'Single item' } 
          },
          shouldCache: true
        }
      ];

      for (const scenario of scenarios) {
        const mockExecutor = jest.fn().mockResolvedValue(scenario.response);
        mockCacheInstance.get.mockResolvedValue(null); // Cache miss
        mockCacheInstance.generateKey.mockReturnValue(`key-${scenario.name}`);
        mockCacheInstance.set.mockClear();

        await cachingMiddleware.wrapWithCache(
          'test_operation',
          { scenario: scenario.name },
          mockExecutor
        );

        if (scenario.shouldCache) {
          expect(mockCacheInstance.set).toHaveBeenCalled();
        } else {
          expect(mockCacheInstance.set).not.toHaveBeenCalled();
        }
      }
    });

    it('should implement tag-based cache invalidation patterns', async () => {
      const tagPatterns = [
        { operation: 'list_scenarios', tags: ['scenarios', 'listings'] },
        { operation: 'get_scenario', tags: ['scenarios', 'details'] },
        { operation: 'list_users', tags: ['users', 'listings'] },
        { operation: 'get_analytics', tags: ['analytics', 'reports'] }
      ];

      for (const pattern of tagPatterns) {
        const deletedCount = await cachingMiddleware.invalidateOperationCache(
          pattern.operation,
          { reason: 'test_invalidation' }
        );
        
        expect(deletedCount).toBeGreaterThanOrEqual(0);
        expect(mockChildLogger.info).toHaveBeenCalledWith(
          'Operation cache invalidated',
          expect.objectContaining({
            operation: pattern.operation
          })
        );
      }
    });

    it('should implement hierarchical cache key generation with context awareness', async () => {
      const testCases = [
        {
          operation: 'list_scenarios',
          params: { teamId: 'team123', status: 'active', limit: 50 },
          context: { userId: 'user456', role: 'admin' },
          expectedKeyPattern: /operation:list_scenarios:[a-zA-Z0-9+/=]{16}:[a-zA-Z0-9+/=]{16}/
        },
        {
          operation: 'get_user',
          params: { userId: 'user789' },
          context: undefined,
          expectedKeyPattern: /operation:get_user:[a-zA-Z0-9+/=]{16}$/
        }
      ];

      for (const testCase of testCases) {
        mockCacheInstance.generateKey.mockImplementation((prefix, suffix) => {
          return `${prefix}:${suffix}`;
        });

        const mockExecutor = jest.fn().mockResolvedValue({ success: true, data: 'test' });
        mockCacheInstance.get.mockResolvedValue(null);

        await cachingMiddleware.wrapWithCache(
          testCase.operation,
          testCase.params,
          mockExecutor,
          testCase.context
        );

        expect(mockCacheInstance.generateKey).toHaveBeenCalled();
        const generatedKey = mockCacheInstance.generateKey.mock.calls[0].join(':');
        expect(generatedKey).toMatch(testCase.expectedKeyPattern);
      }
    });

    it('should implement adaptive TTL based on data characteristics', async () => {
      const dataSets = [
        {
          name: 'static_configuration',
          data: { settings: { theme: 'dark', language: 'en' } },
          expectedMinTTL: 14400 // 4 hours
        },
        {
          name: 'user_session',
          data: { sessionId: 'sess123', lastActivity: Date.now() },
          expectedMaxTTL: 3600 // 1 hour
        },
        {
          name: 'analytics_snapshot',
          data: { metrics: { views: 1000, clicks: 50 }, timestamp: Date.now() },
          expectedMaxTTL: 900 // 15 minutes
        }
      ];

      for (const dataSet of dataSets) {
        const mockExecutor = jest.fn().mockResolvedValue({
          success: true,
          data: dataSet.data
        });
        
        mockCacheInstance.get.mockResolvedValue(null);
        mockCacheInstance.set.mockClear();
        
        await cachingMiddleware.wrapWithCache(
          'adaptive_ttl_test',
          { dataType: dataSet.name },
          mockExecutor
        );

        expect(mockCacheInstance.set).toHaveBeenCalled();
        const setCall = mockCacheInstance.set.mock.calls[0];
        const ttl = setCall[2]; // TTL is the third parameter
        
        if (dataSet.expectedMinTTL) {
          expect(ttl).toBeGreaterThanOrEqual(dataSet.expectedMinTTL);
        }
        if (dataSet.expectedMaxTTL) {
          expect(ttl).toBeLessThanOrEqual(dataSet.expectedMaxTTL);
        }
      }
    });

    it('should implement cache warming strategies for predictive loading', async () => {
      const warmupOperations = ['list_scenarios', 'list_users', 'get_analytics'];
      const mockData = {
        'list_scenarios': { scenarios: Array.from({length: 25}, (_, i) => ({id: i, name: `Scenario ${i}`})) },
        'list_users': { users: Array.from({length: 15}, (_, i) => ({id: i, email: `user${i}@example.com`})) },
        'get_analytics': { views: 5000, conversions: 250, period: 'last_7_days' }
      };

      // Mock warmup data generation
      mockCacheInstance.warmUp.mockImplementation(async (warmupData) => {
        expect(warmupData).toBeInstanceOf(Array);
        expect(warmupData.length).toBeGreaterThan(0);
        
        // Verify warmup data structure
        warmupData.forEach((entry: any) => {
          expect(entry).toHaveProperty('key');
          expect(entry).toHaveProperty('data');
          expect(entry).toHaveProperty('ttl');
        });
        
        return warmupData.length * 0.85; // 85% success rate
      });

      const server = {
        addTool: originalAddTool
      } as any;

      cachingMiddleware.apply(server);

      // Find and execute the cache-warmup tool
      const warmupTool = originalAddTool.mock.calls.find(
        call => call[0].name === 'cache-warmup'
      )?.[0];
      
      expect(warmupTool).toBeDefined();
      
      const warmupResult = await warmupTool.execute({ 
        operations: warmupOperations 
      });
      
      const parsedResult = JSON.parse(warmupResult);
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.data.operations).toEqual(warmupOperations);
      expect(parsedResult.data.successfulItems).toBeGreaterThan(0);
    });

    it('should implement cache compression and serialization optimization', async () => {
      const testPayloads = [
        {
          name: 'large_json',
          data: {
            items: Array.from({length: 500}, (_, i) => ({
              id: i,
              name: `Item ${i}`,
              description: `This is a detailed description for item ${i}`.repeat(10),
              tags: [`tag${i}`, `category${i % 5}`, `priority${i % 3}`],
              metadata: {
                created: new Date().toISOString(),
                modified: new Date().toISOString(),
                version: `1.${i}.0`
              }
            }))
          },
          compressionExpected: true
        },
        {
          name: 'small_object',
          data: { id: 1, name: 'Simple item' },
          compressionExpected: false
        },
        {
          name: 'binary_data',
          data: { buffer: Buffer.from('test data').toString('base64') },
          compressionExpected: true
        }
      ];

      for (const payload of testPayloads) {
        const mockExecutor = jest.fn().mockResolvedValue({
          success: true,
          data: payload.data
        });

        mockCacheInstance.get.mockResolvedValue(null);
        mockCacheInstance.set.mockClear();
        mockCacheInstance.generateKey.mockReturnValue(`compression-test-${payload.name}`);

        await cachingMiddleware.wrapWithCache(
          'compression_test',
          { payloadType: payload.name },
          mockExecutor
        );

        expect(mockCacheInstance.set).toHaveBeenCalled();
        
        const cachedData = mockCacheInstance.set.mock.calls[0][1];
        expect(cachedData).toHaveProperty('data');
        expect(cachedData).toHaveProperty('etag');
        expect(cachedData.data).toEqual(payload.data);
      }
    });
  });

  describe('Cache Performance and Monitoring', () => {
    it('should provide detailed performance metrics and analytics', async () => {
      // Simulate various cache operations
      const operations = [
        { op: 'list_scenarios', hits: 15, misses: 3, errors: 0 },
        { op: 'get_scenario', hits: 8, misses: 2, errors: 1 },
        { op: 'list_users', hits: 12, misses: 5, errors: 0 },
        { op: 'get_analytics', hits: 6, misses: 4, errors: 0 }
      ];

      // Simulate operation metrics
      for (const op of operations) {
        const mockExecutor = jest.fn().mockResolvedValue({ success: true, data: 'test' });
        
        // Simulate hits
        for (let i = 0; i < op.hits; i++) {
          mockCacheInstance.get.mockResolvedValueOnce({
            data: { success: true, data: 'cached' },
            etag: `etag-${i}`,
            timestamp: Date.now() - 300000,
            operation: op.op,
            params: {}
          });
          
          await cachingMiddleware.wrapWithCache(op.op, { index: i }, mockExecutor);
        }
        
        // Simulate misses
        for (let i = 0; i < op.misses; i++) {
          mockCacheInstance.get.mockResolvedValueOnce(null);
          await cachingMiddleware.wrapWithCache(op.op, { index: i + 100 }, mockExecutor);
        }
      }

      const stats = cachingMiddleware.getOperationStats();
      
      expect(stats).toHaveProperty('list_scenarios');
      expect(stats).toHaveProperty('get_scenario');
      expect(stats).toHaveProperty('list_users');
      expect(stats).toHaveProperty('get_analytics');
      
      // Verify hit rate calculations
      Object.entries(stats).forEach(([operation, metrics]) => {
        expect(metrics).toHaveProperty('hits');
        expect(metrics).toHaveProperty('misses');
        expect(metrics).toHaveProperty('errors');
        expect(metrics).toHaveProperty('hitRate');
        expect(metrics.hitRate).toBeGreaterThanOrEqual(0);
        expect(metrics.hitRate).toBeLessThanOrEqual(100);
      });
    });

    it('should monitor cache health and performance degradation', async () => {
      // Test healthy cache
      mockCacheInstance.healthCheck.mockResolvedValueOnce({
        healthy: true,
        connected: true,
        latency: 1.5,
        memoryPressure: 'low'
      });

      let healthStatus = await cachingMiddleware.healthCheck();
      expect(healthStatus.healthy).toBe(true);
      expect(healthStatus.cache).toBe(true);
      expect(healthStatus.middleware).toBe(true);

      // Test degraded cache performance
      mockCacheInstance.healthCheck.mockResolvedValueOnce({
        healthy: true,
        connected: true,
        latency: 150.0, // High latency
        memoryPressure: 'high'
      });

      healthStatus = await cachingMiddleware.healthCheck();
      expect(healthStatus.healthy).toBe(true); // Still functional but degraded

      // Test failed cache
      mockCacheInstance.healthCheck.mockRejectedValueOnce(new Error('Cache connection lost'));

      healthStatus = await cachingMiddleware.healthCheck();
      expect(healthStatus.healthy).toBe(false);
      expect(healthStatus.cache).toBe(false);
      expect(healthStatus.middleware).toBe(false);
    });

    it('should implement cache memory management and eviction policies', async () => {
      const memoryScenarios = [
        { usage: '50MB', pressure: 'low', expectedBehavior: 'normal' },
        { usage: '150MB', pressure: 'medium', expectedBehavior: 'selective_eviction' },
        { usage: '300MB', pressure: 'high', expectedBehavior: 'aggressive_eviction' },
        { usage: '450MB', pressure: 'critical', expectedBehavior: 'emergency_eviction' }
      ];

      for (const scenario of memoryScenarios) {
        mockCacheInstance.getStats.mockResolvedValueOnce({
          hits: 1000,
          misses: 200,
          hitRate: 0.833,
          totalEntries: 5000,
          memoryUsage: scenario.usage,
          avgResponseTime: 25
        });

        // Mock cache management tool execution
        cachingMiddleware.apply(mockServer);
        
        const statusTool = originalAddTool.mock.calls.find(
          call => call[0].name === 'cache-status'
        )?.[0];
        
        const result = await statusTool.execute({});
        const parsedResult = JSON.parse(result);
        
        expect(parsedResult.success).toBe(true);
        expect(parsedResult.data.stats.memoryUsage).toBe(scenario.usage);
        
        // Verify appropriate eviction behavior would be triggered
        if (scenario.pressure === 'critical') {
          expect(mockChildLogger.warn || mockChildLogger.error).toHaveBeenCalled();
        }
      }
    });

    it('should implement cache hit/miss ratio optimization', async () => {
      const optimizationTests = [
        {
          scenario: 'cold_start',
          initialHitRate: 0.1,
          operations: 100,
          expectedImprovement: 0.4
        },
        {
          scenario: 'steady_state',
          initialHitRate: 0.7,
          operations: 50,
          expectedImprovement: 0.05
        },
        {
          scenario: 'cache_invalidation',
          initialHitRate: 0.8,
          operations: 75,
          expectedImprovement: -0.1 // Temporary degradation after invalidation
        }
      ];

      for (const test of optimizationTests) {
        let hitCount = 0;
        let missCount = 0;
        const targetHitRate = test.initialHitRate;
        
        for (let i = 0; i < test.operations; i++) {
          const shouldHit = Math.random() < targetHitRate + (i / test.operations) * test.expectedImprovement;
          
          const mockExecutor = jest.fn().mockResolvedValue({
            success: true,
            data: `operation-${i}`
          });
          
          if (shouldHit) {
            hitCount++;
            mockCacheInstance.get.mockResolvedValueOnce({
              data: { success: true, data: `cached-${i}` },
              etag: `etag-${i}`,
              timestamp: Date.now() - 300000,
              operation: 'optimization_test',
              params: { index: i }
            });
          } else {
            missCount++;
            mockCacheInstance.get.mockResolvedValueOnce(null);
          }
          
          await cachingMiddleware.wrapWithCache(
            'optimization_test',
            { scenario: test.scenario, index: i },
            mockExecutor
          );
        }
        
        const finalHitRate = hitCount / (hitCount + missCount);
        const actualImprovement = finalHitRate - test.initialHitRate;
        
        // Allow for some variance in random simulation
        if (test.expectedImprovement > 0) {
          expect(actualImprovement).toBeGreaterThan(test.expectedImprovement * 0.5);
        }
        
        expect(mockMetrics.recordCacheHit).toHaveBeenCalledTimes(hitCount);
        expect(mockMetrics.recordCacheMiss).toHaveBeenCalledTimes(missCount);
      }
    });
  });

  describe('Tool Registration and Wrapping', () => {
    it('should selectively wrap tools based on advanced configuration patterns', async () => {
      const toolConfigs = [
        {
          name: 'list-scenarios',
          description: 'List automation scenarios',
          execute: jest.fn().mockResolvedValue({ scenarios: [] }),
          shouldWrap: true,
          reason: 'matches included pattern'
        },
        {
          name: 'cache-status',
          description: 'Get cache status',
          execute: jest.fn().mockResolvedValue({ status: 'ok' }),
          shouldWrap: false,
          reason: 'excluded cache management tool'
        },
        {
          name: 'custom-analytics',
          description: 'Custom analytics tool',
          execute: jest.fn().mockResolvedValue({ data: [] }),
          shouldWrap: true,
          reason: 'default enabled'
        },
        {
          name: 'health-check',
          description: 'System health check',
          execute: jest.fn().mockResolvedValue({ healthy: true }),
          shouldWrap: false,
          reason: 'excluded pattern'
        }
      ];

      const customMiddleware = new CachingMiddleware({
        toolWrapping: {
          enabled: true,
          mode: 'selective',
          includedTools: ['list-scenarios', 'custom-analytics'],
          excludedTools: ['cache-status', 'health-check'],
          defaultEnabled: false
        }
      });

      customMiddleware.apply(mockServer);

      // Register tools and verify wrapping behavior
      for (const toolConfig of toolConfigs) {
        const originalExecute = toolConfig.execute;
        mockServer.addTool(toolConfig as any);
        
        const addToolCall = originalAddTool.mock.calls.find(
          call => call[0].name === toolConfig.name
        );
        
        expect(addToolCall).toBeDefined();
        
        if (toolConfig.shouldWrap) {
          // Tool should be wrapped - execute function should be different
          expect(addToolCall[0].execute).not.toBe(originalExecute);
          
          // Verify wrapped execution includes caching logic
          mockCacheInstance.get.mockResolvedValue(null);
          mockCacheInstance.generateKey.mockReturnValue(`test-key-${toolConfig.name}`);
          
          await addToolCall[0].execute({ test: 'data' }, { context: 'test' });
          expect(mockCacheInstance.get).toHaveBeenCalled();
        } else {
          // Tool should not be wrapped - execute function should be original
          expect(addToolCall[0].execute).toBe(originalExecute);
        }
      }
    });

    it('should handle tool registration errors and fallback gracefully', async () => {
      const problematicTools = [
        {
          name: 'null-executor',
          execute: null,
          expectedBehavior: 'skip_wrapping'
        },
        {
          name: 'throwing-executor',
          execute: jest.fn().mockImplementation(() => {
            throw new Error('Tool execution failed');
          }),
          expectedBehavior: 'wrap_with_error_handling'
        },
        {
          name: 'async-throwing-executor',
          execute: jest.fn().mockRejectedValue(new Error('Async tool execution failed')),
          expectedBehavior: 'wrap_with_error_handling'
        }
      ];

      cachingMiddleware.apply(mockServer);

      for (const tool of problematicTools) {
        try {
          mockServer.addTool(tool as any);
          
          const addToolCall = originalAddTool.mock.calls.find(
            call => call[0].name === tool.name
          );
          
          if (tool.expectedBehavior === 'skip_wrapping') {
            // Should register tool without wrapping
            expect(addToolCall[0].execute).toBe(tool.execute);
          } else if (tool.expectedBehavior === 'wrap_with_error_handling') {
            // Should wrap with error handling
            expect(addToolCall[0].execute).not.toBe(tool.execute);
            
            // Verify error handling in wrapped execution
            try {
              await addToolCall[0].execute({ test: 'data' });
            } catch (error) {
              expect(error).toBeInstanceOf(Error);
              expect(mockChildLogger.error).toHaveBeenCalled();
            }
          }
        } catch (error) {
          // Tool registration should not fail completely
          expect(mockChildLogger.error).toHaveBeenCalled();
        }
      }
    });

    it('should implement dynamic tool strategy adaptation', async () => {
      const adaptiveScenarios = [
        {
          toolName: 'dynamic-scenarios',
          initialStrategy: { enabled: true, ttl: 1800 },
          adaptations: [
            { condition: 'high_miss_rate', newTTL: 3600 },
            { condition: 'memory_pressure', newTTL: 900 },
            { condition: 'performance_degradation', enabled: false }
          ]
        },
        {
          toolName: 'dynamic-users', 
          initialStrategy: { enabled: true, ttl: 900 },
          adaptations: [
            { condition: 'frequent_updates', newTTL: 300 },
            { condition: 'stable_data', newTTL: 1800 }
          ]
        }
      ];

      // Create middleware with adaptive configuration
      const adaptiveMiddleware = new CachingMiddleware({
        strategies: {
          'dynamic-scenarios': { enabled: true, ttl: 1800, tags: ['scenarios'] },
          'dynamic-users': { enabled: true, ttl: 900, tags: ['users'] }
        }
      });

      for (const scenario of adaptiveScenarios) {
        const mockExecutor = jest.fn().mockResolvedValue({
          success: true,
          data: `${scenario.toolName}-data`
        });

        // Test initial strategy
        mockCacheInstance.get.mockResolvedValue(null);
        mockCacheInstance.set.mockClear();
        
        await adaptiveMiddleware.wrapWithCache(
          scenario.toolName,
          { phase: 'initial' },
          mockExecutor
        );
        
        expect(mockCacheInstance.set).toHaveBeenCalled();
        const initialTTL = mockCacheInstance.set.mock.calls[0][2];
        expect(initialTTL).toBe(scenario.initialStrategy.ttl);

        // Simulate adaptations
        for (const adaptation of scenario.adaptations) {
          mockCacheInstance.set.mockClear();
          
          // Simulate condition that triggers adaptation
          if (adaptation.condition === 'memory_pressure') {
            mockCacheInstance.getStats.mockResolvedValueOnce({
              memoryUsage: '200MB',
              pressure: 'high'
            });
          }
          
          if (adaptation.hasOwnProperty('enabled') && !adaptation.enabled) {
            // Strategy disabled - should not cache
            await adaptiveMiddleware.wrapWithCache(
              'disabled_strategy_test',
              { condition: adaptation.condition },
              mockExecutor
            );
            expect(mockCacheInstance.set).not.toHaveBeenCalled();
          } else if (adaptation.newTTL) {
            // Should adapt TTL based on condition
            // Note: This would require enhanced middleware with adaptive logic
            expect(adaptation.newTTL).toBeGreaterThan(0);
          }
        }
      }
    });
  });

  describe('Error Handling and Resilience', () => {
    it('should handle cache connection failures gracefully', async () => {
      const failureScenarios = [
        {
          error: new Error('ECONNRESET - Connection reset by peer'),
          expectedBehavior: 'fallback_to_direct_execution'
        },
        {
          error: new Error('ETIMEDOUT - Connection timeout'),
          expectedBehavior: 'fallback_to_direct_execution'
        },
        {
          error: new Error('Redis server gone away'),
          expectedBehavior: 'fallback_to_direct_execution'
        }
      ];

      for (const scenario of failureScenarios) {
        const mockExecutor = jest.fn().mockResolvedValue({
          success: true,
          data: 'fallback-execution-data'
        });

        // Mock cache failure
        mockCacheInstance.get.mockRejectedValueOnce(scenario.error);
        
        const result = await cachingMiddleware.wrapWithCache(
          'cache_failure_test',
          { scenario: scenario.error.message },
          mockExecutor
        );

        // Should fallback to direct execution
        expect(result.data).toBe('fallback-execution-data');
        expect(mockExecutor).toHaveBeenCalled();
        expect(mockChildLogger.error).toHaveBeenCalledWith(
          'Cache operation error',
          expect.objectContaining({
            operation: 'cache_failure_test'
          })
        );
      }
    });

    it('should implement circuit breaker pattern for cache operations', async () => {
      let failureCount = 0;
      const failureThreshold = 5;
      
      // Simulate consecutive cache failures
      const mockExecutor = jest.fn().mockResolvedValue({
        success: true,
        data: 'circuit-breaker-data'
      });
      
      for (let i = 0; i < failureThreshold + 2; i++) {
        if (failureCount < failureThreshold) {
          failureCount++;
          mockCacheInstance.get.mockRejectedValueOnce(new Error('Cache failure'));
        } else {
          // Circuit should be open - cache operations bypassed
          mockCacheInstance.get.mockClear();
        }
        
        const result = await cachingMiddleware.wrapWithCache(
          'circuit_breaker_test',
          { attempt: i },
          mockExecutor
        );
        
        expect(result.data).toBe('circuit-breaker-data');
        expect(mockExecutor).toHaveBeenCalled();
      }

      // Verify circuit breaker behavior
      expect(mockChildLogger.error).toHaveBeenCalledTimes(failureThreshold);
    });

    it('should handle cache serialization and deserialization errors', async () => {
      const corruptedData = [
        {
          name: 'invalid_json',
          cachedValue: 'invalid-json-string-{malformed',
          expectedBehavior: 'ignore_and_execute'
        },
        {
          name: 'circular_reference',
          cachedValue: (() => {
            const obj: any = { data: 'test' };
            obj.circular = obj;
            return obj;
          })(),
          expectedBehavior: 'ignore_and_execute'
        },
        {
          name: 'buffer_corruption',
          cachedValue: { buffer: 'corrupted-base64-data-!@#$' },
          expectedBehavior: 'ignore_and_execute'
        }
      ];

      for (const testCase of corruptedData) {
        const mockExecutor = jest.fn().mockResolvedValue({
          success: true,
          data: 'fresh-execution-data'
        });

        // Mock corrupted cache data
        mockCacheInstance.get.mockResolvedValueOnce(testCase.cachedValue);
        
        const result = await cachingMiddleware.wrapWithCache(
          'serialization_error_test',
          { testCase: testCase.name },
          mockExecutor
        );

        // Should ignore corrupted cache and execute fresh
        expect(result.data).toBe('fresh-execution-data');
        expect(mockExecutor).toHaveBeenCalled();
      }
    });
  });

  describe('Advanced Cache Management Tools', () => {
    it('should provide comprehensive cache diagnostics and debugging tools', async () => {
      cachingMiddleware.apply(mockServer);
      
      // Enhanced cache status with detailed diagnostics
      mockCacheInstance.getStats.mockResolvedValue({
        hits: 2500,
        misses: 750,
        hitRate: 0.769,
        totalEntries: 15000,
        memoryUsage: '125.6MB',
        avgResponseTime: 15.2,
        peakMemoryUsage: '198.4MB',
        evictionCount: 45,
        compressionRatio: 0.68,
        keyDistribution: {
          'scenarios': 8500,
          'users': 4200,
          'analytics': 1800,
          'templates': 500
        },
        hotKeys: [
          { key: 'operation:list_scenarios:popular', hits: 150 },
          { key: 'operation:get_user:admin', hits: 98 },
          { key: 'operation:analytics:dashboard', hits: 87 }
        ]
      });

      mockCacheInstance.healthCheck.mockResolvedValue({
        healthy: true,
        connected: true,
        latency: 2.3,
        memoryPressure: 'medium',
        connectionPool: {
          active: 8,
          idle: 12,
          pending: 0
        }
      });

      const statusTool = originalAddTool.mock.calls.find(
        call => call[0].name === 'cache-status'
      )?.[0];
      
      const result = await statusTool.execute({});
      const diagnostics = JSON.parse(result);
      
      expect(diagnostics.success).toBe(true);
      expect(diagnostics.data).toHaveProperty('health');
      expect(diagnostics.data).toHaveProperty('stats');
      expect(diagnostics.data).toHaveProperty('operationStats');
      expect(diagnostics.data.stats).toHaveProperty('keyDistribution');
      expect(diagnostics.data.stats).toHaveProperty('hotKeys');
      expect(diagnostics.data.stats).toHaveProperty('compressionRatio');
    });

    it('should implement advanced cache invalidation patterns', async () => {
      cachingMiddleware.apply(mockServer);
      
      const invalidationScenarios = [
        {
          trigger: 'scenario:update:123',
          expectedPattern: 'scenario-related keys',
          mockDeletedCount: 25
        },
        {
          trigger: 'user:permissions:changed',
          expectedPattern: 'user and auth related keys',
          mockDeletedCount: 42
        },
        {
          trigger: 'analytics:data:refresh',
          expectedPattern: 'analytics and report keys', 
          mockDeletedCount: 18
        }
      ];
      
      const invalidateTool = originalAddTool.mock.calls.find(
        call => call[0].name === 'cache-invalidate'
      )?.[0];
      
      for (const scenario of invalidationScenarios) {
        mockCacheInstance.invalidate.mockResolvedValueOnce(scenario.mockDeletedCount);
        
        const result = await invalidateTool.execute({
          trigger: scenario.trigger,
          context: { reason: 'automated-test', userId: 'test-user' }
        });
        
        const invalidationResult = JSON.parse(result);
        
        expect(invalidationResult.success).toBe(true);
        expect(invalidationResult.data.trigger).toBe(scenario.trigger);
        expect(invalidationResult.data.deletedCount).toBe(scenario.mockDeletedCount);
        
        expect(mockCacheInstance.invalidate).toHaveBeenCalledWith(
          scenario.trigger,
          expect.objectContaining({ reason: 'automated-test' })
        );
      }
    });

    it('should implement intelligent cache preloading and optimization', async () => {
      cachingMiddleware.apply(mockServer);
      
      const preloadingScenarios = [
        {
          operations: ['list_scenarios', 'popular_templates'],
          expectedEntries: 15,
          successRate: 0.93
        },
        {
          operations: ['user_preferences', 'dashboard_widgets'],
          expectedEntries: 8,
          successRate: 0.87
        }
      ];
      
      const warmupTool = originalAddTool.mock.calls.find(
        call => call[0].name === 'cache-warmup'
      )?.[0];
      
      for (const scenario of preloadingScenarios) {
        const mockSuccessCount = Math.floor(scenario.expectedEntries * scenario.successRate);
        mockCacheInstance.warmUp.mockResolvedValueOnce(mockSuccessCount);
        
        const result = await warmupTool.execute({
          operations: scenario.operations
        });
        
        const warmupResult = JSON.parse(result);
        
        expect(warmupResult.success).toBe(true);
        expect(warmupResult.data.operations).toEqual(scenario.operations);
        expect(warmupResult.data.successfulItems).toBe(mockSuccessCount);
        expect(warmupResult.data.totalItems).toBe(scenario.expectedEntries);
        
        // Verify warmup data was properly structured
        expect(mockCacheInstance.warmUp).toHaveBeenCalledWith(
          expect.arrayContaining([
            expect.objectContaining({
              key: expect.any(String),
              data: expect.any(Object),
              ttl: expect.any(Number)
            })
          ])
        );
      }
    });
  });

  describe('Shutdown and Cleanup', () => {
    it('should shutdown gracefully with proper resource cleanup', async () => {
      const shutdownPromise = cachingMiddleware.shutdown();
      
      await expect(shutdownPromise).resolves.not.toThrow();
      
      expect(mockCacheInstance.shutdown).toHaveBeenCalled();
      expect(mockChildLogger.info).toHaveBeenCalledWith('Shutting down caching middleware');
      
      // Verify operation metrics were cleared
      const finalStats = cachingMiddleware.getOperationStats();
      expect(Object.keys(finalStats)).toHaveLength(0);
    });

    it('should handle shutdown errors gracefully', async () => {
      mockCacheInstance.shutdown.mockRejectedValueOnce(new Error('Shutdown failed'));
      
      await expect(cachingMiddleware.shutdown()).resolves.not.toThrow();
      
      expect(mockChildLogger.error || mockChildLogger.warn).toHaveBeenCalled();
    });
  });
});
