/**
 * Sophisticated multi-tier caching system with Redis integration
 * Features intelligent cache invalidation, response optimization, and comprehensive metrics
 */

import { Redis } from 'ioredis';
import logger from './logger.js';
import metrics from './metrics.js';
import { gzip, gunzip } from 'zlib';
import { promisify } from 'util';

const gzipAsync = promisify(gzip);
const gunzipAsync = promisify(gunzip);

export interface CacheConfig {
  redis: {
    host: string;
    port: number;
    password?: string;
    db?: number;
    maxRetriesPerRequest?: number;
    enableReadyCheck?: boolean;
  };
  compression: {
    enabled: boolean;
    threshold: number; // Bytes - compress if data exceeds this
    level: number; // 1-9, 6 is default
  };
  ttl: {
    default: number; // Default TTL in seconds
    scenarios: number;
    users: number;
    analytics: number;
    connections: number;
    short: number; // For frequently changing data
    long: number; // For rarely changing data
  };
  invalidation: {
    enabled: boolean;
    patterns: {
      [key: string]: string[]; // Invalidation patterns for different data types
    };
  };
}

export interface CacheEntry<T = unknown> {
  data: T;
  compressed: boolean;
  timestamp: number;
  ttl: number;
  version: string;
  tags: string[];
}

export interface CacheStats {
  hits: number;
  misses: number;
  sets: number;
  deletes: number;
  compressionRatio: number;
  averageResponseTime: number;
  keyCount: number;
  memoryUsage: number;
}

export interface InvalidationRule {
  pattern: string;
  triggers: string[];
  cascading: boolean;
}

export class RedisCache {
  private redis!: Redis;
  private readonly fallbackCache = new Map<string, CacheEntry>();
  private readonly config: CacheConfig;
  private readonly componentLogger: ReturnType<typeof logger.child>;
  private readonly stats: CacheStats;
  private readonly invalidationRules: Map<string, InvalidationRule>;
  private readonly maxFallbackSize = 1000;

  constructor(config: CacheConfig) {
    this.config = config;
    this.componentLogger = logger.child({ component: 'RedisCache' });
    this.stats = {
      hits: 0,
      misses: 0,
      sets: 0,
      deletes: 0,
      compressionRatio: 1.0,
      averageResponseTime: 0,
      keyCount: 0,
      memoryUsage: 0
    };
    this.invalidationRules = new Map();
    this.initializeRedis();
    this.setupInvalidationRules();
  }

  private initializeRedis(): void {
    this.redis = new Redis({
      host: this.config.redis.host,
      port: this.config.redis.port,
      password: this.config.redis.password,
      db: this.config.redis.db || 0,
      maxRetriesPerRequest: this.config.redis.maxRetriesPerRequest || 3,
      enableReadyCheck: this.config.redis.enableReadyCheck ?? true,
      lazyConnect: true,
      connectTimeout: 5000,
    });

    this.redis.on('connect', () => {
      this.componentLogger.info('Redis connected successfully', {
        host: this.config.redis.host,
        port: this.config.redis.port,
        db: this.config.redis.db
      });
    });

    this.redis.on('error', (error) => {
      this.componentLogger.error('Redis connection error', {
        error: error.message,
        fallbackMode: true
      });
      metrics.recordError('cache', 'redis_connection_error', 'RedisCache');
    });

    this.redis.on('ready', () => {
      this.componentLogger.info('Redis ready for operations');
    });
  }

  private setupInvalidationRules(): void {
    if (!this.config.invalidation.enabled) {
      return;
    }

    // Setup common invalidation patterns
    this.invalidationRules.set('scenario', {
      pattern: 'scenarios:*',
      triggers: ['scenario:create', 'scenario:update', 'scenario:delete'],
      cascading: true
    });

    this.invalidationRules.set('user', {
      pattern: 'users:*',
      triggers: ['user:update', 'user:permissions:update'],
      cascading: false
    });

    this.invalidationRules.set('analytics', {
      pattern: 'analytics:*',
      triggers: ['scenario:execute', 'data:update'],
      cascading: true
    });

    this.invalidationRules.set('connections', {
      pattern: 'connections:*',
      triggers: ['connection:create', 'connection:update', 'connection:delete'],
      cascading: true
    });
  }

  /**
   * Generate cache key with namespace and context
   */
  public generateKey(namespace: string, identifier: string, context?: Record<string, string>): string {
    let key = `make:${namespace}:${identifier}`;
    
    if (context) {
      const contextStr = Object.entries(context)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => `${k}=${v}`)
        .join('&');
      key += `:${Buffer.from(contextStr).toString('base64')}`;
    }
    
    return key;
  }

  /**
   * Get cached data with automatic decompression
   */
  public async get<T = unknown>(key: string, useMetrics = true): Promise<T | null> {
    const startTime = Date.now();
    
    try {
      // Try Redis first
      const cached = await this.getFromRedis<T>(key);
      if (cached !== null) {
        if (useMetrics) {
          this.recordHit(Date.now() - startTime);
        }
        return cached;
      }

      // Fallback to in-memory cache
      const fallback = this.getFromFallback<T>(key);
      if (fallback !== null) {
        if (useMetrics) {
          this.recordHit(Date.now() - startTime);
        }
        this.componentLogger.debug('Cache hit from fallback', { key });
        return fallback;
      }

      if (useMetrics) {
        this.recordMiss(Date.now() - startTime);
      }
      return null;

    } catch (error) {
      this.componentLogger.error('Cache get error', {
        key,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      if (useMetrics) {
        this.recordMiss(Date.now() - startTime);
      }
      metrics.recordError('cache', 'get_error', 'RedisCache');
      return null;
    }
  }

  /**
   * Set cached data with automatic compression and TTL
   */
  public async set<T = unknown>(
    key: string,
    data: T,
    ttl?: number,
    tags: string[] = [],
    useMetrics = true
  ): Promise<boolean> {
    const startTime = Date.now();
    
    try {
      const actualTtl = ttl || this.config.ttl.default;
      const entry: CacheEntry<T> = {
        data,
        compressed: false,
        timestamp: Date.now(),
        ttl: actualTtl,
        version: '1.0',
        tags
      };

      // Compress if data is large enough
      let serialized = JSON.stringify(entry);
      if (this.config.compression.enabled && Buffer.byteLength(serialized) > this.config.compression.threshold) {
        const compressed = await gzipAsync(Buffer.from(serialized), {
          level: this.config.compression.level
        });
        entry.compressed = true;
        serialized = compressed.toString('base64');
        
        const compressionRatio = Buffer.byteLength(serialized) / Buffer.byteLength(JSON.stringify(entry));
        this.updateCompressionRatio(compressionRatio);
      }

      // Set in Redis
      const redisSuccess = await this.setInRedis(key, serialized, actualTtl);
      
      // Also set in fallback cache
      this.setInFallback(key, entry);

      if (useMetrics) {
        this.recordSet(Date.now() - startTime);
      }

      // Store tags for invalidation
      if (tags.length > 0) {
        await this.storeTags(key, tags);
      }

      return redisSuccess;

    } catch (error) {
      this.componentLogger.error('Cache set error', {
        key,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      if (useMetrics) {
        metrics.recordError('cache', 'set_error', 'RedisCache');
      }
      return false;
    }
  }

  /**
   * Delete cached data
   */
  public async delete(key: string): Promise<boolean> {
    try {
      const results = await Promise.allSettled([
        this.redis.del(key),
        this.redis.del(`${key}:tags`)
      ]);

      this.fallbackCache.delete(key);
      this.recordDelete();

      return results[0].status === 'fulfilled' && results[0].value > 0;

    } catch (error) {
      this.componentLogger.error('Cache delete error', {
        key,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      metrics.recordError('cache', 'delete_error', 'RedisCache');
      return false;
    }
  }

  /**
   * Invalidate cache based on patterns and triggers
   */
  public async invalidate(trigger: string, context?: Record<string, string>): Promise<number> {
    if (!this.config.invalidation.enabled) {
      return 0;
    }

    let deletedCount = 0;
    
    try {
      for (const [ruleId, rule] of this.invalidationRules) {
        if (rule.triggers.includes(trigger)) {
          deletedCount += await this.processInvalidationRule(rule, ruleId, trigger, context);
        }
      }

      metrics.recordCacheInvalidation(trigger, deletedCount);
      return deletedCount;

    } catch (error) {
      this.componentLogger.error('Cache invalidation error', {
        trigger,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      metrics.recordError('cache', 'invalidation_error', 'RedisCache');
      return 0;
    }
  }

  private async processInvalidationRule(
    rule: InvalidationRule, 
    ruleId: string, 
    trigger: string, 
    context?: Record<string, string>
  ): Promise<number> {
    const pattern = this.expandPattern(rule.pattern, context);
    const keys = await this.redis.keys(pattern);
    let deletedCount = 0;
    
    if (keys.length > 0) {
      const deleted = await this.redis.del(...keys);
      deletedCount += deleted;
      
      // Remove from fallback cache
      keys.forEach(key => this.fallbackCache.delete(key));
      
      this.componentLogger.info('Cache invalidated', {
        trigger,
        pattern,
        keysDeleted: deleted,
        ruleId
      });
    }

    // Handle cascading invalidation
    if (rule.cascading) {
      deletedCount += await this.processCascadingInvalidation(keys);
    }

    return deletedCount;
  }

  private async processCascadingInvalidation(keys: string[]): Promise<number> {
    const cascadingKeys = await this.findCascadingKeys(keys);
    
    if (cascadingKeys.length === 0) {
      return 0;
    }
    
    const cascadingDeleted = await this.redis.del(...cascadingKeys);
    cascadingKeys.forEach(key => this.fallbackCache.delete(key));
    
    return cascadingDeleted;
  }

  /**
   * Get cache statistics
   */
  public async getStats(): Promise<CacheStats> {
    try {
      const info = await this.redis.info('memory');
      const keyspace = await this.redis.info('keyspace');
      
      // Parse Redis memory usage
      const memoryMatch = info.match(/used_memory:(\d+)/);
      const memoryUsage = memoryMatch ? parseInt(memoryMatch[1]) : 0;
      
      // Parse keyspace info for key count
      const keyspaceMatch = keyspace.match(/keys=(\d+)/);
      const keyCount = keyspaceMatch ? parseInt(keyspaceMatch[1]) : 0;

      return {
        ...this.stats,
        keyCount,
        memoryUsage
      };

    } catch (error) {
      this.componentLogger.error('Failed to get cache stats', error as Record<string, unknown>);
      return this.stats;
    }
  }

  /**
   * Warm up cache with predefined data
   */
  public async warmUp(warmupData: Array<{ key: string; data: unknown; ttl?: number }>): Promise<number> {
    let successCount = 0;
    
    this.componentLogger.info('Starting cache warm-up', { itemCount: warmupData.length });
    
    for (const item of warmupData) {
      try {
        const success = await this.set(item.key, item.data, item.ttl, [], false);
        if (success) {
          successCount++;
        }
      } catch (error) {
        this.componentLogger.warn('Failed to warm up cache item', {
          key: item.key,
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    }
    
    this.componentLogger.info('Cache warm-up completed', {
      total: warmupData.length,
      successful: successCount,
      failed: warmupData.length - successCount
    });
    
    return successCount;
  }

  /**
   * Health check for cache system
   */
  public async healthCheck(): Promise<{ healthy: boolean; redis: boolean; fallback: boolean; latency: number }> {
    const startTime = Date.now();
    
    try {
      // Test Redis connectivity
      await this.redis.ping();
      const latency = Date.now() - startTime;
      
      return {
        healthy: true,
        redis: true,
        fallback: this.fallbackCache.size < this.maxFallbackSize,
        latency
      };

    } catch {
      const latency = Date.now() - startTime;
      
      return {
        healthy: this.fallbackCache.size < this.maxFallbackSize,
        redis: false,
        fallback: this.fallbackCache.size < this.maxFallbackSize,
        latency
      };
    }
  }

  /**
   * Shutdown cache connections gracefully
   */
  public async shutdown(): Promise<void> {
    this.componentLogger.info('Shutting down cache system');
    
    try {
      await this.redis.quit();
      this.fallbackCache.clear();
      this.componentLogger.info('Cache system shutdown completed');
    } catch (error) {
      this.componentLogger.error('Error during cache shutdown', error as Record<string, unknown>);
    }
  }

  // Private helper methods

  private async getFromRedis<T>(key: string): Promise<T | null> {
    try {
      const cached = await this.redis.get(key);
      if (!cached) {
        return null;
      }

      return await this.deserializeEntry<T>(cached);

    } catch {
      this.componentLogger.debug('Redis get failed, trying fallback', { key });
      return null;
    }
  }

  private getFromFallback<T>(key: string): T | null {
    const entry = this.fallbackCache.get(key);
    if (!entry) {
      return null;
    }

    // Check if entry has expired
    if (Date.now() - entry.timestamp > entry.ttl * 1000) {
      this.fallbackCache.delete(key);
      return null;
    }

    return entry.data as T;
  }

  private async setInRedis(key: string, data: string, ttl: number): Promise<boolean> {
    try {
      const result = await this.redis.setex(key, ttl, data);
      return result === 'OK';
    } catch {
      this.componentLogger.debug('Redis set failed', { key });
      return false;
    }
  }

  private setInFallback<T>(key: string, entry: CacheEntry<T>): void {
    // Implement LRU eviction for fallback cache
    if (this.fallbackCache.size >= this.maxFallbackSize) {
      const firstKey = this.fallbackCache.keys().next().value;
      if (firstKey) {
        this.fallbackCache.delete(firstKey);
      }
    }
    
    this.fallbackCache.set(key, entry);
  }

  private async deserializeEntry<T>(cached: string): Promise<T | null> {
    try {
      // Check if data is compressed (base64 encoded)
      const isCompressed = /^[A-Za-z0-9+/=]+$/.test(cached) && cached.length % 4 === 0;
      
      let serialized: string;
      if (isCompressed) {
        try {
          const buffer = Buffer.from(cached, 'base64');
          const decompressed = await gunzipAsync(buffer);
          serialized = decompressed.toString();
        } catch {
          // If decompression fails, treat as uncompressed
          serialized = cached;
        }
      } else {
        serialized = cached;
      }

      const entry: CacheEntry<T> = JSON.parse(serialized);
      return entry.data;

    } catch (error) {
      this.componentLogger.error('Failed to deserialize cache entry', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return null;
    }
  }

  private async storeTags(key: string, tags: string[]): Promise<void> {
    try {
      await this.redis.setex(`${key}:tags`, this.config.ttl.default, JSON.stringify(tags));
    } catch {
      this.componentLogger.debug('Failed to store tags', { key, tags });
    }
  }

  private expandPattern(pattern: string, context?: Record<string, string>): string {
    if (!context) {
      return pattern;
    }

    let expandedPattern = pattern;
    for (const [key, value] of Object.entries(context)) {
      expandedPattern = expandedPattern.replace(`{${key}}`, value);
    }
    
    return expandedPattern;
  }

  private async findCascadingKeys(triggerKeys: string[]): Promise<string[]> {
    const cascadingKeys: string[] = [];
    
    for (const key of triggerKeys) {
      try {
        const tags = await this.redis.get(`${key}:tags`);
        if (tags) {
          const tagArray: string[] = JSON.parse(tags);
          // Find keys with related tags
          const relatedPattern = tagArray.map(tag => `*:${tag}:*`);
          for (const pattern of relatedPattern) {
            const keys = await this.redis.keys(pattern);
            cascadingKeys.push(...keys);
          }
        }
      } catch {
        this.componentLogger.debug('Failed to find cascading keys', { key });
      }
    }
    
    return [...new Set(cascadingKeys)]; // Remove duplicates
  }

  private recordHit(responseTime: number): void {
    this.stats.hits++;
    this.updateAverageResponseTime(responseTime);
    metrics.recordCacheHit('redis_cache');
  }

  private recordMiss(responseTime: number): void {
    this.stats.misses++;
    this.updateAverageResponseTime(responseTime);
    metrics.recordCacheMiss('redis_cache');
  }

  private recordSet(responseTime: number): void {
    this.stats.sets++;
    this.updateAverageResponseTime(responseTime);
  }

  private recordDelete(): void {
    this.stats.deletes++;
  }

  private updateAverageResponseTime(responseTime: number): void {
    const totalOps = this.stats.hits + this.stats.misses + this.stats.sets;
    this.stats.averageResponseTime = ((this.stats.averageResponseTime * (totalOps - 1)) + responseTime) / totalOps;
  }

  private updateCompressionRatio(ratio: number): void {
    this.stats.compressionRatio = (this.stats.compressionRatio + ratio) / 2;
  }
}

// Default cache configuration
export const defaultCacheConfig: CacheConfig = {
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379'),
    password: process.env.REDIS_PASSWORD,
    db: parseInt(process.env.REDIS_DB || '0'),
    maxRetriesPerRequest: 3,
    enableReadyCheck: true,
  },
  compression: {
    enabled: true,
    threshold: 1024, // 1KB
    level: 6
  },
  ttl: {
    default: 3600, // 1 hour
    scenarios: 1800, // 30 minutes
    users: 900, // 15 minutes
    analytics: 300, // 5 minutes
    connections: 1800, // 30 minutes
    short: 60, // 1 minute
    long: 86400 // 24 hours
  },
  invalidation: {
    enabled: true,
    patterns: {
      scenarios: ['scenarios:*', 'analytics:scenario:*'],
      users: ['users:*', 'sessions:*'],
      connections: ['connections:*', 'apps:*']
    }
  }
};

export default RedisCache;