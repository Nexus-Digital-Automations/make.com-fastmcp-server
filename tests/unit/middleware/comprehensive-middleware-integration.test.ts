/**
 * @fileoverview Comprehensive middleware integration test suite
 * Tests caching, monitoring, error handling, and performance middleware
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { cachingMiddleware } from '../../../src/middleware/caching.js';
import { monitoringMiddleware } from '../../../src/middleware/monitoring.js';
import { ToolContext } from '../../../src/tools/shared/types/tool-context.js';

// Mock dependencies
const mockApiClient = {
  post: jest.fn(),
  get: jest.fn(),
  put: jest.fn(),
  delete: jest.fn(),
};

const mockLogger = {
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
};

const mockServer = {
  addTool: jest.fn(),
  addMiddleware: jest.fn(),
};

// Mock cache implementation
const mockCache = {
  get: jest.fn(),
  set: jest.fn(),
  del: jest.fn(),
  clear: jest.fn(),
  has: jest.fn(),
  keys: jest.fn(),
  stats: jest.fn().mockReturnValue({
    hits: 100,
    misses: 25,
    hitRate: 0.8,
    size: 125
  })
};

// Mock metrics collector
const mockMetrics = {
  increment: jest.fn(),
  histogram: jest.fn(),
  gauge: jest.fn(),
  timer: jest.fn().mockReturnValue(() => {}),
  getMetrics: jest.fn().mockReturnValue({
    requestCount: 1000,
    averageResponseTime: 150,
    errorRate: 0.02
  })
};

describe('Comprehensive Middleware Integration', () => {
  let toolContext: ToolContext;

  beforeEach(() => {
    toolContext = {
      server: mockServer as any,
      apiClient: mockApiClient as any,
      logger: mockLogger,
    };
    
    // Reset all mocks
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('Caching Middleware', () => {
    describe('Basic Caching Operations', () => {
      it('should cache successful tool responses', async () => {
        mockCache.has.mockResolvedValue(false);
        mockCache.set.mockResolvedValue(true);
        
        const middleware = cachingMiddleware({
          cache: mockCache as any,
          ttl: 300,
          keyPrefix: 'tool:',
          enabled: true
        });

        const mockToolExecution = jest.fn().mockResolvedValue('success result');
        const wrappedExecution = middleware(mockToolExecution);

        const result = await wrappedExecution('test-tool', { param: 'value' }, { log: mockLogger });

        expect(result).toBe('success result');
        expect(mockCache.has).toHaveBeenCalledWith('tool:test-tool:' + expect.any(String));
        expect(mockCache.set).toHaveBeenCalledWith(
          expect.stringContaining('tool:test-tool:'),
          'success result',
          300
        );
      });

      it('should return cached results when available', async () => {
        mockCache.has.mockResolvedValue(true);
        mockCache.get.mockResolvedValue('cached result');
        
        const middleware = cachingMiddleware({
          cache: mockCache as any,
          ttl: 300,
          keyPrefix: 'tool:',
          enabled: true
        });

        const mockToolExecution = jest.fn();
        const wrappedExecution = middleware(mockToolExecution);

        const result = await wrappedExecution('test-tool', { param: 'value' }, { log: mockLogger });

        expect(result).toBe('cached result');
        expect(mockToolExecution).not.toHaveBeenCalled();
        expect(mockCache.get).toHaveBeenCalledWith('tool:test-tool:' + expect.any(String));
      });

      it('should not cache error responses', async () => {
        mockCache.has.mockResolvedValue(false);
        
        const middleware = cachingMiddleware({
          cache: mockCache as any,
          ttl: 300,
          keyPrefix: 'tool:',
          enabled: true
        });

        const mockToolExecution = jest.fn().mockRejectedValue(new Error('Tool error'));
        const wrappedExecution = middleware(mockToolExecution);

        await expect(wrappedExecution('test-tool', { param: 'value' }, { log: mockLogger }))
          .rejects.toThrow('Tool error');

        expect(mockCache.set).not.toHaveBeenCalled();
      });

      it('should support cache invalidation patterns', async () => {
        mockCache.keys.mockResolvedValue(['tool:scenarios:key1', 'tool:scenarios:key2']);
        mockCache.del.mockResolvedValue(true);
        
        const middleware = cachingMiddleware({
          cache: mockCache as any,
          ttl: 300,
          keyPrefix: 'tool:',
          enabled: true,
          invalidationPatterns: {
            'create-scenario': ['scenarios:*'],
            'update-scenario': ['scenarios:*'],
            'delete-scenario': ['scenarios:*']
          }
        });

        const mockToolExecution = jest.fn().mockResolvedValue('scenario created');
        const wrappedExecution = middleware(mockToolExecution);

        mockCache.has.mockResolvedValue(false);
        await wrappedExecution('create-scenario', { name: 'test' }, { log: mockLogger });

        expect(mockCache.keys).toHaveBeenCalledWith('tool:scenarios:*');
        expect(mockCache.del).toHaveBeenCalledTimes(2);
      });
    });

    describe('Advanced Caching Features', () => {
      it('should support selective caching based on tool types', async () => {
        const middleware = cachingMiddleware({
          cache: mockCache as any,
          ttl: 300,
          keyPrefix: 'tool:',
          enabled: true,
          cacheableTools: ['list-scenarios', 'get-scenario'],
          nonCacheableTools: ['create-scenario', 'delete-scenario']
        });

        const mockToolExecution = jest.fn().mockResolvedValue('result');
        const wrappedExecution = middleware(mockToolExecution);

        // Cacheable tool
        mockCache.has.mockResolvedValue(false);
        await wrappedExecution('list-scenarios', {}, { log: mockLogger });
        expect(mockCache.set).toHaveBeenCalled();

        // Non-cacheable tool
        jest.clearAllMocks();
        await wrappedExecution('create-scenario', { name: 'test' }, { log: mockLogger });
        expect(mockCache.set).not.toHaveBeenCalled();
      });

      it('should support time-based cache warming', async () => {
        const middleware = cachingMiddleware({
          cache: mockCache as any,
          ttl: 300,
          keyPrefix: 'tool:',
          enabled: true,
          warmupSchedule: {
            'list-scenarios': '*/5 * * * *', // Every 5 minutes
            'get-budget-status': '0 */1 * * *' // Every hour
          }
        });

        // Test cache warming invocation
        const mockToolExecution = jest.fn().mockResolvedValue('warmed result');
        const wrappedExecution = middleware(mockToolExecution);

        // Simulate cache warming call
        mockCache.has.mockResolvedValue(false);
        await wrappedExecution('list-scenarios', {}, { 
          log: mockLogger, 
          warmup: true 
        });

        expect(mockCache.set).toHaveBeenCalled();
        expect(mockToolExecution).toHaveBeenCalled();
      });

      it('should handle cache compression for large responses', async () => {
        const largeResponse = 'x'.repeat(10000); // 10KB response
        
        const middleware = cachingMiddleware({
          cache: mockCache as any,
          ttl: 300,
          keyPrefix: 'tool:',
          enabled: true,
          compression: {
            enabled: true,
            threshold: 1024, // 1KB
            algorithm: 'gzip'
          }
        });

        const mockToolExecution = jest.fn().mockResolvedValue(largeResponse);
        const wrappedExecution = middleware(mockToolExecution);

        mockCache.has.mockResolvedValue(false);
        await wrappedExecution('get-large-data', {}, { log: mockLogger });

        expect(mockCache.set).toHaveBeenCalledWith(
          expect.any(String),
          expect.objectContaining({
            compressed: true,
            data: expect.any(String)
          }),
          300
        );
      });
    });

    describe('Cache Performance and Monitoring', () => {
      it('should track cache hit/miss statistics', async () => {
        const middleware = cachingMiddleware({
          cache: mockCache as any,
          ttl: 300,
          keyPrefix: 'tool:',
          enabled: true,
          enableMetrics: true,
          metricsCollector: mockMetrics as any
        });

        const mockToolExecution = jest.fn().mockResolvedValue('result');
        const wrappedExecution = middleware(mockToolExecution);

        // Cache miss
        mockCache.has.mockResolvedValue(false);
        await wrappedExecution('test-tool', {}, { log: mockLogger });
        expect(mockMetrics.increment).toHaveBeenCalledWith('cache.miss', ['tool:test-tool']);

        // Cache hit
        mockCache.has.mockResolvedValue(true);
        mockCache.get.mockResolvedValue('cached result');
        await wrappedExecution('test-tool', {}, { log: mockLogger });
        expect(mockMetrics.increment).toHaveBeenCalledWith('cache.hit', ['tool:test-tool']);
      });

      it('should monitor cache performance metrics', async () => {
        const middleware = cachingMiddleware({
          cache: mockCache as any,
          ttl: 300,
          keyPrefix: 'tool:',
          enabled: true,
          enableMetrics: true,
          metricsCollector: mockMetrics as any
        });

        const stats = await middleware.getStats();

        expect(stats).toEqual({
          hits: 100,
          misses: 25,
          hitRate: 0.8,
          size: 125,
          efficiency: expect.any(Number)
        });
      });
    });
  });

  describe('Monitoring Middleware', () => {
    describe('Basic Monitoring Operations', () => {
      it('should track tool execution metrics', async () => {
        const middleware = monitoringMiddleware({
          metricsCollector: mockMetrics as any,
          enabled: true,
          trackLatency: true,
          trackErrors: true,
          trackThroughput: true
        });

        const mockToolExecution = jest.fn().mockResolvedValue('success');
        const wrappedExecution = middleware(mockToolExecution);

        await wrappedExecution('test-tool', { param: 'value' }, { log: mockLogger });

        expect(mockMetrics.increment).toHaveBeenCalledWith('tool.executions', ['tool:test-tool']);
        expect(mockMetrics.histogram).toHaveBeenCalledWith(
          'tool.execution_time',
          expect.any(Number),
          ['tool:test-tool']
        );
      });

      it('should track error rates and types', async () => {
        const middleware = monitoringMiddleware({
          metricsCollector: mockMetrics as any,
          enabled: true,
          trackErrors: true,
          errorClassification: true
        });

        const mockToolExecution = jest.fn().mockRejectedValue(new Error('Validation error'));
        const wrappedExecution = middleware(mockToolExecution);

        await expect(wrappedExecution('test-tool', {}, { log: mockLogger }))
          .rejects.toThrow('Validation error');

        expect(mockMetrics.increment).toHaveBeenCalledWith('tool.errors', [
          'tool:test-tool',
          'error_type:Error'
        ]);
        expect(mockMetrics.gauge).toHaveBeenCalledWith(
          'tool.error_rate',
          expect.any(Number),
          ['tool:test-tool']
        );
      });

      it('should monitor resource usage', async () => {
        const middleware = monitoringMiddleware({
          metricsCollector: mockMetrics as any,
          enabled: true,
          trackResourceUsage: true,
          resourceMetrics: ['memory', 'cpu']
        });

        const mockToolExecution = jest.fn().mockImplementation(async () => {
          // Simulate some work
          await new Promise(resolve => setTimeout(resolve, 100));
          return 'result';
        });
        const wrappedExecution = middleware(mockToolExecution);

        await wrappedExecution('resource-intensive-tool', {}, { log: mockLogger });

        expect(mockMetrics.gauge).toHaveBeenCalledWith(
          'tool.memory_usage',
          expect.any(Number),
          ['tool:resource-intensive-tool']
        );
      });
    });

    describe('Advanced Monitoring Features', () => {
      it('should support custom metric collection', async () => {
        const customMetrics = {
          dataProcessed: (amount: number) => mockMetrics.histogram('data.processed', amount),
          apiCallsCount: (count: number) => mockMetrics.gauge('api.calls', count)
        };

        const middleware = monitoringMiddleware({
          metricsCollector: mockMetrics as any,
          enabled: true,
          customMetrics
        });

        const mockToolExecution = jest.fn().mockImplementation(async (toolName, args, context) => {
          // Tool reports custom metrics
          context.metrics?.dataProcessed(1024);
          context.metrics?.apiCallsCount(5);
          return 'processed';
        });
        const wrappedExecution = middleware(mockToolExecution);

        await wrappedExecution('data-processor', {}, { 
          log: mockLogger,
          metrics: customMetrics
        });

        expect(mockMetrics.histogram).toHaveBeenCalledWith('data.processed', 1024);
        expect(mockMetrics.gauge).toHaveBeenCalledWith('api.calls', 5);
      });

      it('should support alerting thresholds', async () => {
        const alertHandler = jest.fn();
        
        const middleware = monitoringMiddleware({
          metricsCollector: mockMetrics as any,
          enabled: true,
          alerting: {
            enabled: true,
            thresholds: {
              errorRate: 0.05, // 5%
              latency: 1000, // 1 second
              throughput: 100 // requests/minute
            },
            alertHandler
          }
        });

        const mockToolExecution = jest.fn().mockImplementation(async () => {
          // Simulate slow execution
          await new Promise(resolve => setTimeout(resolve, 1100));
          return 'slow result';
        });
        const wrappedExecution = middleware(mockToolExecution);

        await wrappedExecution('slow-tool', {}, { log: mockLogger });

        expect(alertHandler).toHaveBeenCalledWith({
          metric: 'latency',
          value: expect.any(Number),
          threshold: 1000,
          tool: 'slow-tool',
          timestamp: expect.any(Date)
        });
      });

      it('should support distributed tracing', async () => {
        const tracer = {
          startSpan: jest.fn().mockReturnValue({
            setTag: jest.fn(),
            setStatus: jest.fn(),
            finish: jest.fn()
          }),
          inject: jest.fn(),
          extract: jest.fn()
        };

        const middleware = monitoringMiddleware({
          metricsCollector: mockMetrics as any,
          enabled: true,
          tracing: {
            enabled: true,
            tracer: tracer as any,
            spanOperationName: 'tool.execution'
          }
        });

        const mockToolExecution = jest.fn().mockResolvedValue('traced result');
        const wrappedExecution = middleware(mockToolExecution);

        await wrappedExecution('traced-tool', {}, { 
          log: mockLogger,
          traceId: 'trace-123',
          spanId: 'span-456'
        });

        expect(tracer.startSpan).toHaveBeenCalledWith('tool.execution', {
          childOf: expect.any(Object),
          tags: {
            'tool.name': 'traced-tool',
            'component': 'fastmcp-tool'
          }
        });
      });
    });

    describe('Performance Analytics', () => {
      it('should generate performance reports', async () => {
        const middleware = monitoringMiddleware({
          metricsCollector: mockMetrics as any,
          enabled: true,
          analytics: {
            enabled: true,
            reportingInterval: 60000, // 1 minute
            includeBreakdowns: true
          }
        });

        const report = await middleware.generateReport({
          timeRange: '1h',
          includeBreakdowns: true,
          tools: ['test-tool', 'other-tool']
        });

        expect(report).toEqual({
          timeRange: '1h',
          totalExecutions: expect.any(Number),
          averageLatency: expect.any(Number),
          errorRate: expect.any(Number),
          toolBreakdowns: expect.any(Object),
          trends: expect.any(Object)
        });
      });

      it('should identify performance bottlenecks', async () => {
        const middleware = monitoringMiddleware({
          metricsCollector: mockMetrics as any,
          enabled: true,
          performanceAnalysis: {
            enabled: true,
            bottleneckDetection: true,
            thresholds: {
              latency: 500,
              errorRate: 0.02
            }
          }
        });

        const bottlenecks = await middleware.analyzeBottlenecks({
          timeRange: '1h',
          analysisDepth: 'detailed'
        });

        expect(bottlenecks).toEqual(
          expect.arrayContaining([
            expect.objectContaining({
              tool: expect.any(String),
              issue: expect.any(String),
              severity: expect.any(String),
              recommendations: expect.any(Array)
            })
          ])
        );
      });
    });
  });

  describe('Middleware Integration and Chaining', () => {
    it('should chain multiple middleware correctly', async () => {
      const caching = cachingMiddleware({
        cache: mockCache as any,
        ttl: 300,
        enabled: true
      });

      const monitoring = monitoringMiddleware({
        metricsCollector: mockMetrics as any,
        enabled: true
      });

      const mockToolExecution = jest.fn().mockResolvedValue('chained result');
      
      // Chain middleware: monitoring -> caching -> tool
      const chainedExecution = monitoring(caching(mockToolExecution));

      mockCache.has.mockResolvedValue(false);
      const result = await chainedExecution('chained-tool', {}, { log: mockLogger });

      expect(result).toBe('chained result');
      expect(mockMetrics.increment).toHaveBeenCalledWith('tool.executions', ['tool:chained-tool']);
      expect(mockCache.set).toHaveBeenCalled();
    });

    it('should handle middleware errors gracefully', async () => {
      const errorMiddleware = (execution: Function) => {
        return async (toolName: string, args: any, context: any) => {
          if (toolName === 'error-tool') {
            throw new Error('Middleware error');
          }
          return execution(toolName, args, context);
        };
      };

      const monitoring = monitoringMiddleware({
        metricsCollector: mockMetrics as any,
        enabled: true,
        trackErrors: true
      });

      const mockToolExecution = jest.fn().mockResolvedValue('success');
      const chainedExecution = monitoring(errorMiddleware(mockToolExecution));

      await expect(chainedExecution('error-tool', {}, { log: mockLogger }))
        .rejects.toThrow('Middleware error');

      expect(mockMetrics.increment).toHaveBeenCalledWith('tool.errors', [
        'tool:error-tool',
        'error_type:Error'
      ]);
    });

    it('should preserve execution context through middleware chain', async () => {
      const contextMiddleware = (execution: Function) => {
        return async (toolName: string, args: any, context: any) => {
          const enhancedContext = {
            ...context,
            requestId: 'req-123',
            userId: 'user-456'
          };
          return execution(toolName, args, enhancedContext);
        };
      };

      const monitoring = monitoringMiddleware({
        metricsCollector: mockMetrics as any,
        enabled: true,
        contextExtraction: ['requestId', 'userId']
      });

      const mockToolExecution = jest.fn().mockImplementation((toolName, args, context) => {
        expect(context.requestId).toBe('req-123');
        expect(context.userId).toBe('user-456');
        return 'context preserved';
      });

      const chainedExecution = monitoring(contextMiddleware(mockToolExecution));
      const result = await chainedExecution('context-tool', {}, { log: mockLogger });

      expect(result).toBe('context preserved');
      expect(mockMetrics.increment).toHaveBeenCalledWith('tool.executions', [
        'tool:context-tool',
        'requestId:req-123',
        'userId:user-456'
      ]);
    });
  });

  describe('Middleware Configuration and Management', () => {
    it('should support dynamic middleware configuration', async () => {
      let cacheEnabled = true;
      
      const dynamicCaching = cachingMiddleware({
        cache: mockCache as any,
        ttl: 300,
        enabled: () => cacheEnabled // Dynamic enable/disable
      });

      const mockToolExecution = jest.fn().mockResolvedValue('dynamic result');
      const wrappedExecution = dynamicCaching(mockToolExecution);

      // Cache enabled
      mockCache.has.mockResolvedValue(false);
      await wrappedExecution('test-tool', {}, { log: mockLogger });
      expect(mockCache.set).toHaveBeenCalled();

      // Cache disabled
      jest.clearAllMocks();
      cacheEnabled = false;
      await wrappedExecution('test-tool', {}, { log: mockLogger });
      expect(mockCache.set).not.toHaveBeenCalled();
    });

    it('should support middleware health checks', async () => {
      const caching = cachingMiddleware({
        cache: mockCache as any,
        ttl: 300,
        enabled: true,
        healthCheck: {
          enabled: true,
          interval: 30000
        }
      });

      const monitoring = monitoringMiddleware({
        metricsCollector: mockMetrics as any,
        enabled: true,
        healthCheck: {
          enabled: true,
          interval: 30000
        }
      });

      const cachingHealth = await caching.healthCheck();
      const monitoringHealth = await monitoring.healthCheck();

      expect(cachingHealth).toEqual({
        healthy: true,
        cache: {
          connected: true,
          responseTime: expect.any(Number)
        }
      });

      expect(monitoringHealth).toEqual({
        healthy: true,
        metrics: {
          collecting: true,
          storage: 'healthy'
        }
      });
    });
  });
});