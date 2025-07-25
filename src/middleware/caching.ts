/**
 * Caching middleware for FastMCP server with intelligent response caching
 * Integrates with Redis cache and provides automatic cache management for API responses
 */

import { FastMCP } from 'fastmcp';
import RedisCache, { CacheConfig, defaultCacheConfig } from '../lib/cache.js';
import logger from '../lib/logger.js';
import metrics from '../lib/metrics.js';
import { ApiResponse } from '../types/index.js';

export interface CachingMiddlewareConfig {
  cache: CacheConfig;
  strategies: {
    [operation: string]: CacheStrategy;
  };
  defaultStrategy: CacheStrategy;
  enableConditionalCaching: boolean;
  enableEtagSupport: boolean;
}

export interface CacheStrategy {
  enabled: boolean;
  ttl: number;
  tags: string[];
  keyGenerator?: (operation: string, params: Record<string, unknown>, context?: Record<string, unknown>) => string;
  shouldCache?: (operation: string, params: Record<string, unknown>, response: ApiResponse<unknown>) => boolean;
  invalidateOn?: string[];
}

export interface CachedResponse<T = unknown> {
  data: T;
  etag: string;
  timestamp: number;
  operation: string;
  params: Record<string, unknown>;
}

export class CachingMiddleware {
  private cache: RedisCache;
  private config: CachingMiddlewareConfig;
  private componentLogger: ReturnType<typeof logger.child>;
  private operationMetrics = new Map<string, { hits: number; misses: number; errors: number }>();

  constructor(config?: Partial<CachingMiddlewareConfig>) {
    this.config = {
      cache: defaultCacheConfig,
      strategies: {
        // Scenario operations - medium TTL, scenario tags
        'list_scenarios': {
          enabled: true,
          ttl: 1800, // 30 minutes
          tags: ['scenarios'],
          invalidateOn: ['scenario:create', 'scenario:update', 'scenario:delete']
        },
        'get_scenario': {
          enabled: true,
          ttl: 3600, // 1 hour
          tags: ['scenarios'],
          invalidateOn: ['scenario:update', 'scenario:delete']
        },
        
        // User operations - short TTL due to permissions
        'list_users': {
          enabled: true,
          ttl: 900, // 15 minutes
          tags: ['users'],
          invalidateOn: ['user:update', 'user:create', 'user:delete']
        },
        'get_user': {
          enabled: true,
          ttl: 1800, // 30 minutes
          tags: ['users'],
          invalidateOn: ['user:update', 'user:delete']
        },
        
        // Analytics - very short TTL due to frequent updates
        'get_analytics': {
          enabled: true,
          ttl: 300, // 5 minutes
          tags: ['analytics'],
          invalidateOn: ['scenario:execute', 'data:update']
        },
        'get_execution_history': {
          enabled: true,
          ttl: 600, // 10 minutes
          tags: ['analytics', 'executions'],
          invalidateOn: ['scenario:execute']
        },
        
        // Connection operations - medium TTL
        'list_connections': {
          enabled: true,
          ttl: 1800, // 30 minutes
          tags: ['connections'],
          invalidateOn: ['connection:create', 'connection:update', 'connection:delete']
        },
        'get_connection': {
          enabled: true,
          ttl: 3600, // 1 hour
          tags: ['connections'],
          invalidateOn: ['connection:update', 'connection:delete']
        },
        
        // Template operations - long TTL, rarely change
        'list_templates': {
          enabled: true,
          ttl: 7200, // 2 hours
          tags: ['templates'],
          invalidateOn: ['template:create', 'template:update', 'template:delete']
        },
        'get_template': {
          enabled: true,
          ttl: 14400, // 4 hours
          tags: ['templates'],
          invalidateOn: ['template:update', 'template:delete']
        },
        
        // Organization/team operations - medium TTL
        'list_organizations': {
          enabled: true,
          ttl: 3600, // 1 hour
          tags: ['organizations'],
          invalidateOn: ['org:update', 'team:update']
        },
        'list_teams': {
          enabled: true,
          ttl: 1800, // 30 minutes
          tags: ['teams'],
          invalidateOn: ['team:create', 'team:update', 'team:delete']
        }
      },
      defaultStrategy: {
        enabled: true,
        ttl: 1800, // 30 minutes default
        tags: ['default'],
        invalidateOn: []
      },
      enableConditionalCaching: true,
      enableEtagSupport: true,
      ...config
    };

    this.componentLogger = logger.child({ component: 'CachingMiddleware' });
    this.cache = new RedisCache(this.config.cache);
    this.initializeMetrics();
  }

  /**
   * Initialize cache metrics tracking
   */
  private initializeMetrics(): void {
    // Initialize metrics for each operation strategy
    Object.keys(this.config.strategies).forEach(operation => {
      this.operationMetrics.set(operation, { hits: 0, misses: 0, errors: 0 });
    });
  }

  /**
   * Apply caching middleware to FastMCP server
   */
  public apply(server: FastMCP): void {
    this.componentLogger.info('Applying caching middleware to FastMCP server');

    // Wrap tool execution with caching
    this.wrapServerTools(server);

    // Add cache management tools
    this.addCacheManagementTools(server);

    this.componentLogger.info('Caching middleware applied successfully');
  }

  /**
   * Wrap existing tools with caching logic
   */
  private wrapServerTools(server: FastMCP): void {
    // Get all registered tools
    const tools = server.listTools();
    
    tools.forEach(tool => {
      const originalHandler = tool.handler;
      if (!originalHandler) return;

      // Wrap the tool handler with caching
      tool.handler = async (params: Record<string, unknown>, context: Record<string, unknown>) => {
        return this.wrapWithCache(
          tool.name,
          params,
          async () => originalHandler(params, context),
          context
        );
      };
    });
  }

  /**
   * Add cache management tools to server
   */
  private addCacheManagementTools(server: FastMCP): void {
    // Cache status tool
    server.addTool({
      name: 'cache-status',
      description: 'Get cache system status and statistics',
      parameters: {},
      execute: async () => {
        try {
          const stats = await this.cache.getStats();
          const health = await this.cache.healthCheck();
          const operationStats = Object.fromEntries(this.operationMetrics);

          return {
            success: true,
            data: {
              health,
              stats,
              operationStats,
              strategies: Object.keys(this.config.strategies),
              config: {
                compression: this.config.cache.compression,
                ttl: this.config.cache.ttl
              }
            }
          };
        } catch (error) {
          return {
            success: false,
            error: {
              message: 'Failed to get cache status',
              details: error instanceof Error ? error.message : 'Unknown error'
            }
          };
        }
      }
    });

    // Cache invalidation tool
    server.addTool({
      name: 'cache-invalidate',
      description: 'Invalidate cache entries based on trigger patterns',
      parameters: {
        trigger: { type: 'string', description: 'Invalidation trigger (e.g., scenario:update)' },
        context: { type: 'object', description: 'Optional context for pattern expansion', required: false }
      },
      execute: async (params) => {
        try {
          const { trigger, context } = params;
          const deletedCount = await this.cache.invalidate(trigger as string, context as Record<string, string>);

          this.componentLogger.info('Cache invalidated via tool', { trigger, deletedCount });

          return {
            success: true,
            data: {
              trigger,
              deletedCount,
              timestamp: new Date().toISOString()
            }
          };
        } catch (error) {
          return {
            success: false,
            error: {
              message: 'Failed to invalidate cache',
              details: error instanceof Error ? error.message : 'Unknown error'
            }
          };
        }
      }
    });

    // Cache warm-up tool
    server.addTool({
      name: 'cache-warmup',
      description: 'Warm up cache with predefined data sets',
      parameters: {
        operations: { 
          type: 'array', 
          description: 'List of operations to warm up (e.g., ["list_scenarios", "list_users"])',
          required: false
        }
      },
      execute: async (params) => {
        try {
          const operations = (params.operations as string[]) || Object.keys(this.config.strategies);
          const warmupData = await this.generateWarmupData(operations);
          const successCount = await this.cache.warmUp(warmupData);

          return {
            success: true,
            data: {
              operations,
              totalItems: warmupData.length,
              successfulItems: successCount,
              timestamp: new Date().toISOString()
            }
          };
        } catch (error) {
          return {
            success: false,
            error: {
              message: 'Failed to warm up cache',
              details: error instanceof Error ? error.message : 'Unknown error'
            }
          };
        }
      }
    });
  }

  /**
   * Wrap operation with caching logic
   */
  public async wrapWithCache<T>(
    operation: string,
    params: Record<string, unknown>,
    executor: () => Promise<T>,
    context?: Record<string, unknown>
  ): Promise<T> {
    const strategy = this.config.strategies[operation] || this.config.defaultStrategy;
    
    if (!strategy.enabled) {
      return executor();
    }

    const startTime = Date.now();
    const cacheKey = this.generateCacheKey(operation, params, context, strategy);
    
    try {
      // Try to get from cache
      const cached = await this.cache.get<CachedResponse<T>>(cacheKey);
      
      if (cached && this.isCacheValid(cached, strategy)) {
        this.recordCacheHit(operation, Date.now() - startTime);
        
        this.componentLogger.debug('Cache hit', {
          operation,
          cacheKey,
          age: Date.now() - cached.timestamp
        });
        
        return cached.data;
      }

      // Cache miss - execute operation
      const result = await executor();
      
      // Check if response should be cached
      if (this.shouldCacheResponse(operation, params, result, strategy)) {
        const cachedResponse: CachedResponse<T> = {
          data: result,
          etag: this.generateEtag(result),
          timestamp: Date.now(),
          operation,
          params
        };
        
        // Store in cache with strategy TTL and tags
        await this.cache.set(
          cacheKey,
          cachedResponse,
          strategy.ttl,
          strategy.tags
        );
        
        this.componentLogger.debug('Cached response', {
          operation,
          cacheKey,
          ttl: strategy.ttl,
          tags: strategy.tags
        });
      }
      
      this.recordCacheMiss(operation, Date.now() - startTime);
      return result;

    } catch (error) {
      this.recordCacheError(operation);
      this.componentLogger.error('Cache operation error', {
        operation,
        cacheKey,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      
      // Execute operation without caching on cache error
      return executor();
    }
  }

  /**
   * Generate cache key for operation
   */
  private generateCacheKey(
    operation: string,
    params: Record<string, unknown>,
    context?: Record<string, unknown>,
    strategy?: CacheStrategy
  ): string {
    if (strategy?.keyGenerator) {
      return strategy.keyGenerator(operation, params, context);
    }

    // Default key generation
    const paramsHash = this.hashParams(params);
    const contextStr = context ? `:${this.hashParams(context)}` : '';
    
    return this.cache.generateKey('operation', `${operation}:${paramsHash}${contextStr}`);
  }

  /**
   * Generate hash for parameters
   */
  private hashParams(params: Record<string, unknown>): string {
    const sorted = Object.entries(params)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
      .join('&');
    
    return Buffer.from(sorted).toString('base64').slice(0, 16);
  }

  /**
   * Check if cached response is still valid
   */
  private isCacheValid<T>(cached: CachedResponse<T>, strategy: CacheStrategy): boolean {
    if (!this.config.enableConditionalCaching) {
      return true;
    }

    const age = Date.now() - cached.timestamp;
    const maxAge = strategy.ttl * 1000;
    
    return age < maxAge;
  }

  /**
   * Determine if response should be cached
   */
  private shouldCacheResponse<T>(
    operation: string,
    params: Record<string, unknown>,
    response: T,
    strategy: CacheStrategy
  ): boolean {
    if (strategy.shouldCache) {
      return strategy.shouldCache(operation, params, response as ApiResponse<unknown>);
    }

    // Default caching logic
    if (response && typeof response === 'object') {
      const apiResponse = response as ApiResponse<unknown>;
      
      // Don't cache error responses
      if ('success' in apiResponse && !apiResponse.success) {
        return false;
      }
      
      // Don't cache empty responses
      if ('data' in apiResponse && (!apiResponse.data || 
          (Array.isArray(apiResponse.data) && apiResponse.data.length === 0))) {
        return false;
      }
    }

    return true;
  }

  /**
   * Generate ETag for response
   */
  private generateEtag<T>(data: T): string {
    const content = JSON.stringify(data);
    const hash = Buffer.from(content).toString('base64');
    return `"${hash.slice(0, 16)}"`;
  }

  /**
   * Generate warm-up data for specified operations
   */
  private async generateWarmupData(operations: string[]): Promise<Array<{ key: string; data: unknown; ttl?: number }>> {
    const warmupData: Array<{ key: string; data: unknown; ttl?: number }> = [];
    
    // This would be expanded based on actual application needs
    // For now, we'll generate some common cache keys
    
    operations.forEach(operation => {
      const strategy = this.config.strategies[operation];
      if (strategy) {
        // Generate sample cache entries for common parameter combinations
        const sampleParams = this.getSampleParams(operation);
        sampleParams.forEach(params => {
          const key = this.generateCacheKey(operation, params, undefined, strategy);
          warmupData.push({
            key,
            data: { placeholder: true, operation, params }, // Placeholder data
            ttl: strategy.ttl
          });
        });
      }
    });
    
    return warmupData;
  }

  /**
   * Get sample parameters for operation warm-up
   */
  private getSampleParams(operation: string): Record<string, unknown>[] {
    const commonParams: Record<string, Record<string, unknown>[]> = {
      'list_scenarios': [
        { limit: 50 },
        { limit: 100 },
        { teamId: 'default' }
      ],
      'list_users': [
        { limit: 50 },
        { role: 'admin' },
        { teamId: 'default' }
      ],
      'list_connections': [
        { limit: 50 },
        { type: 'webhook' }
      ],
      'list_templates': [
        { category: 'automation' },
        { limit: 25 }
      ]
    };
    
    return commonParams[operation] || [{}];
  }

  /**
   * Record cache hit metrics
   */
  private recordCacheHit(operation: string, responseTime: number): void {
    const opMetrics = this.operationMetrics.get(operation);
    if (opMetrics) {
      opMetrics.hits++;
      this.operationMetrics.set(operation, opMetrics);
    }
    
    metrics.recordCacheHit('operation_cache', { operation });
    metrics.recordToolExecutionDuration(operation, responseTime / 1000);
  }

  /**
   * Record cache miss metrics
   */
  private recordCacheMiss(operation: string, responseTime: number): void {
    const opMetrics = this.operationMetrics.get(operation);
    if (opMetrics) {
      opMetrics.misses++;
      this.operationMetrics.set(operation, opMetrics);
    }
    
    metrics.recordCacheMiss('operation_cache', { operation });
    metrics.recordToolExecutionDuration(operation, responseTime / 1000);
  }

  /**
   * Record cache error metrics
   */
  private recordCacheError(operation: string): void {
    const opMetrics = this.operationMetrics.get(operation);
    if (opMetrics) {
      opMetrics.errors++;
      this.operationMetrics.set(operation, opMetrics);
    }
    
    metrics.recordError('cache', 'operation_cache_error', 'CachingMiddleware');
  }

  /**
   * Invalidate cache for specific operation patterns
   */
  public async invalidateOperationCache(operation: string, context?: Record<string, string>): Promise<number> {
    const strategy = this.config.strategies[operation];
    if (!strategy || !strategy.invalidateOn) {
      return 0;
    }

    let totalDeleted = 0;
    for (const trigger of strategy.invalidateOn) {
      const deleted = await this.cache.invalidate(trigger, context);
      totalDeleted += deleted;
    }

    this.componentLogger.info('Operation cache invalidated', {
      operation,
      totalDeleted,
      triggers: strategy.invalidateOn
    });

    return totalDeleted;
  }

  /**
   * Get cache statistics for specific operations
   */
  public getOperationStats(): Record<string, { hits: number; misses: number; errors: number; hitRate: number }> {
    const stats: Record<string, { hits: number; misses: number; errors: number; hitRate: number }> = {};
    
    this.operationMetrics.forEach((metrics, operation) => {
      const total = metrics.hits + metrics.misses;
      const hitRate = total > 0 ? metrics.hits / total : 0;
      
      stats[operation] = {
        ...metrics,
        hitRate: Math.round(hitRate * 10000) / 100 // Percentage with 2 decimal places
      };
    });
    
    return stats;
  }

  /**
   * Health check for caching middleware
   */
  public async healthCheck(): Promise<{ healthy: boolean; cache: boolean; middleware: boolean }> {
    try {
      const cacheHealth = await this.cache.healthCheck();
      
      return {
        healthy: cacheHealth.healthy,
        cache: cacheHealth.healthy,
        middleware: true
      };
    } catch (error) {
      this.componentLogger.error('Caching middleware health check failed', error);
      return {
        healthy: false,
        cache: false,
        middleware: false
      };
    }
  }

  /**
   * Shutdown caching middleware
   */
  public async shutdown(): Promise<void> {
    this.componentLogger.info('Shutting down caching middleware');
    await this.cache.shutdown();
    this.operationMetrics.clear();
  }
}

export default CachingMiddleware;