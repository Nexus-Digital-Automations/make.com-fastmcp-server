/**
 * Core Functionality Test Suite for Caching Middleware
 * Tests cache operations, TTL management, memory limits, and statistics
 * Critical for ensuring caching system reliability and performance
 * Covers cache hit/miss scenarios, eviction policies, and memory management
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { CacheConfig, CacheEntry, CacheStatistics } from '../../../src/middleware/caching.js';

// Mock logger
const mockLogger = {
  child: jest.fn(() => ({
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn()
  })),
  info: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  debug: jest.fn()
};

jest.mock('../../../src/lib/logger.js', () => ({
  default: mockLogger
}));

describe('Caching Middleware - Core Functionality Tests', () => {
  let CacheManager: any;
  let cache: any;
  let componentLogger: any;

  beforeEach(async () => {
    jest.clearAllMocks();
    jest.resetModules();
    
    // Setup component logger mock
    componentLogger = {
      info: jest.fn(),
      error: jest.fn(),
      warn: jest.fn(),
      debug: jest.fn()
    };
    mockLogger.child.mockReturnValue(componentLogger);
    
    // Import the module after mocks are set up
    const cachingModule = await import('../../../src/middleware/caching.js');
    CacheManager = cachingModule.CacheManager;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Cache Manager Initialization', () => {
    it('should create cache manager with default configuration', () => {
      cache = new CacheManager();
      
      expect(cache).toBeDefined();
      expect(mockLogger.child).toHaveBeenCalledWith({ component: 'CacheManager' });
    });

    it('should create cache manager with custom configuration', () => {
      const config: CacheConfig = {
        maxSize: 500,
        defaultTTL: 120,
        maxMemoryMB: 256,
        enableStatistics: true
      };
      
      cache = new CacheManager(config);
      
      expect(cache).toBeDefined();
      expect(cache.getConfig()).toMatchObject(config);
    });

    it('should use default configuration when none provided', () => {
      cache = new CacheManager();
      
      const config = cache.getConfig();
      expect(config.maxSize).toBe(1000);
      expect(config.defaultTTL).toBe(300);
      expect(config.maxMemoryMB).toBe(100);
      expect(config.enableStatistics).toBe(true);
    });

    it('should validate configuration parameters', () => {
      const invalidConfigs = [
        { maxSize: -1 },
        { defaultTTL: -1 },
        { maxMemoryMB: -1 },
        { maxSize: 0 },
        { defaultTTL: 0 }
      ];
      
      invalidConfigs.forEach(config => {
        expect(() => new CacheManager(config as CacheConfig)).toThrow('Invalid cache configuration');
      });
    });
  });

  describe('Basic Cache Operations', () => {
    beforeEach(() => {
      cache = new CacheManager();
    });

    it('should set and get cache entries successfully', () => {
      const key = 'test_key';
      const value = { data: 'test_value', timestamp: Date.now() };
      
      cache.set(key, value);
      const retrieved = cache.get(key);
      
      expect(retrieved).toEqual(value);
      expect(componentLogger.debug).toHaveBeenCalledWith('Cache set', { key, size: expect.any(Number) });
      expect(componentLogger.debug).toHaveBeenCalledWith('Cache hit', { key });
    });

    it('should return undefined for non-existent keys', () => {
      const result = cache.get('non_existent_key');
      
      expect(result).toBeUndefined();
      expect(componentLogger.debug).toHaveBeenCalledWith('Cache miss', { key: 'non_existent_key' });
    });

    it('should check if keys exist in cache', () => {
      const key = 'test_key';
      const value = 'test_value';
      
      expect(cache.has(key)).toBe(false);
      
      cache.set(key, value);
      expect(cache.has(key)).toBe(true);
    });

    it('should delete cache entries successfully', () => {
      const key = 'test_key';
      const value = 'test_value';
      
      cache.set(key, value);
      expect(cache.has(key)).toBe(true);
      
      const deleted = cache.delete(key);
      expect(deleted).toBe(true);
      expect(cache.has(key)).toBe(false);
      expect(cache.get(key)).toBeUndefined();
      
      expect(componentLogger.debug).toHaveBeenCalledWith('Cache delete', { key });
    });

    it('should return false when deleting non-existent keys', () => {
      const deleted = cache.delete('non_existent_key');
      expect(deleted).toBe(false);
    });

    it('should clear all cache entries', () => {
      cache.set('key1', 'value1');
      cache.set('key2', 'value2');
      cache.set('key3', 'value3');
      
      expect(cache.size()).toBe(3);
      
      cache.clear();
      expect(cache.size()).toBe(0);
      expect(cache.get('key1')).toBeUndefined();
      expect(cache.get('key2')).toBeUndefined();
      expect(cache.get('key3')).toBeUndefined();
      
      expect(componentLogger.info).toHaveBeenCalledWith('Cache cleared');
    });

    it('should return correct cache size', () => {
      expect(cache.size()).toBe(0);
      
      cache.set('key1', 'value1');
      expect(cache.size()).toBe(1);
      
      cache.set('key2', 'value2');
      expect(cache.size()).toBe(2);
      
      cache.delete('key1');
      expect(cache.size()).toBe(1);
    });
  });

  describe('TTL (Time To Live) Management', () => {
    beforeEach(() => {
      cache = new CacheManager({ defaultTTL: 1 }); // 1 second TTL for testing
    });

    it('should set entries with default TTL', () => {
      const key = 'test_key';
      const value = 'test_value';
      
      cache.set(key, value);
      expect(cache.get(key)).toBe(value);
    });

    it('should set entries with custom TTL', () => {
      const key = 'test_key';
      const value = 'test_value';
      const customTTL = 2; // 2 seconds
      
      cache.set(key, value, customTTL);
      expect(cache.get(key)).toBe(value);
    });

    it('should expire entries after TTL', async () => {
      const key = 'test_key';
      const value = 'test_value';
      
      cache.set(key, value, 0.1); // 100ms TTL
      expect(cache.get(key)).toBe(value);
      
      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 150));
      
      expect(cache.get(key)).toBeUndefined();
      expect(componentLogger.debug).toHaveBeenCalledWith('Cache miss (expired)', { key });
    });

    it('should handle zero TTL (immediate expiration)', () => {
      const key = 'test_key';
      const value = 'test_value';
      
      cache.set(key, value, 0);
      expect(cache.get(key)).toBeUndefined();
    });

    it('should handle negative TTL (immediate expiration)', () => {
      const key = 'test_key';
      const value = 'test_value';
      
      cache.set(key, value, -1);
      expect(cache.get(key)).toBeUndefined();
    });

    it('should update TTL when entry is overwritten', () => {
      const key = 'test_key';
      
      cache.set(key, 'value1', 0.1); // Short TTL
      cache.set(key, 'value2', 10); // Long TTL
      
      expect(cache.get(key)).toBe('value2');
    });
  });

  describe('Memory Management and Size Limits', () => {
    it('should enforce maximum cache size through LRU eviction', () => {
      cache = new CacheManager({ maxSize: 3 });
      
      cache.set('key1', 'value1');
      cache.set('key2', 'value2');
      cache.set('key3', 'value3');
      expect(cache.size()).toBe(3);
      
      // Add fourth item, should evict oldest (key1)
      cache.set('key4', 'value4');
      expect(cache.size()).toBe(3);
      expect(cache.get('key1')).toBeUndefined(); // Evicted
      expect(cache.get('key2')).toBe('value2');
      expect(cache.get('key3')).toBe('value3');
      expect(cache.get('key4')).toBe('value4');
      
      expect(componentLogger.debug).toHaveBeenCalledWith('Cache eviction (size limit)', { evictedKey: 'key1' });
    });

    it('should update LRU order on access', () => {
      cache = new CacheManager({ maxSize: 3 });
      
      cache.set('key1', 'value1');
      cache.set('key2', 'value2');
      cache.set('key3', 'value3');
      
      // Access key1 to make it most recently used
      cache.get('key1');
      
      // Add fourth item, should evict key2 (oldest unused)
      cache.set('key4', 'value4');
      expect(cache.get('key1')).toBe('value1'); // Still exists
      expect(cache.get('key2')).toBeUndefined(); // Evicted
      expect(cache.get('key3')).toBe('value3');
      expect(cache.get('key4')).toBe('value4');
    });

    it('should calculate memory usage accurately', () => {
      cache = new CacheManager();
      
      const initialMemory = cache.getMemoryUsage();
      expect(initialMemory.totalMB).toBe(0);
      
      // Add entries and check memory usage
      cache.set('key1', 'a'.repeat(1000)); // ~1KB
      cache.set('key2', 'b'.repeat(2000)); // ~2KB
      
      const memoryAfter = cache.getMemoryUsage();
      expect(memoryAfter.totalMB).toBeGreaterThan(0);
      expect(memoryAfter.entryCount).toBe(2);
    });

    it('should enforce memory limits through eviction', () => {
      cache = new CacheManager({ maxMemoryMB: 0.001 }); // 1KB limit
      
      cache.set('key1', 'x'.repeat(500)); // ~500 bytes
      cache.set('key2', 'y'.repeat(600)); // ~600 bytes, should trigger eviction
      
      expect(cache.get('key1')).toBeUndefined(); // Evicted due to memory
      expect(cache.get('key2')).toBeDefined();
      
      expect(componentLogger.warn).toHaveBeenCalledWith('Cache eviction (memory limit)', expect.any(Object));
    });
  });

  describe('Cache Statistics', () => {
    beforeEach(() => {
      cache = new CacheManager({ enableStatistics: true });
    });

    it('should track basic statistics', () => {
      cache.set('key1', 'value1');
      cache.set('key2', 'value2');
      
      cache.get('key1'); // Hit
      cache.get('key1'); // Hit
      cache.get('key3'); // Miss
      
      const stats = cache.getStatistics();
      expect(stats.hits).toBe(2);
      expect(stats.misses).toBe(1);
      expect(stats.sets).toBe(2);
      expect(stats.hitRate).toBeCloseTo(0.67, 2); // 2/3
    });

    it('should track eviction statistics', () => {
      cache = new CacheManager({ maxSize: 2, enableStatistics: true });
      
      cache.set('key1', 'value1');
      cache.set('key2', 'value2');
      cache.set('key3', 'value3'); // Causes eviction
      
      const stats = cache.getStatistics();
      expect(stats.evictions).toBe(1);
    });

    it('should reset statistics when requested', () => {
      cache.set('key1', 'value1');
      cache.get('key1');
      cache.get('key2'); // Miss
      
      let stats = cache.getStatistics();
      expect(stats.hits).toBe(1);
      expect(stats.misses).toBe(1);
      
      cache.resetStatistics();
      stats = cache.getStatistics();
      expect(stats.hits).toBe(0);
      expect(stats.misses).toBe(0);
      expect(stats.sets).toBe(0);
      
      expect(componentLogger.info).toHaveBeenCalledWith('Cache statistics reset');
    });

    it('should handle statistics when disabled', () => {
      cache = new CacheManager({ enableStatistics: false });
      
      cache.set('key1', 'value1');
      cache.get('key1');
      
      const stats = cache.getStatistics();
      expect(stats.hits).toBe(0);
      expect(stats.misses).toBe(0);
      expect(stats.sets).toBe(0);
    });
  });

  describe('Error Handling and Edge Cases', () => {
    beforeEach(() => {
      cache = new CacheManager();
    });

    it('should handle undefined and null values', () => {
      cache.set('undefined_key', undefined);
      cache.set('null_key', null);
      
      expect(cache.get('undefined_key')).toBeUndefined();
      expect(cache.get('null_key')).toBeNull();
      expect(cache.has('undefined_key')).toBe(true);
      expect(cache.has('null_key')).toBe(true);
    });

    it('should handle complex object values', () => {
      const complexObject = {
        id: 123,
        name: 'Test Object',
        nested: {
          array: [1, 2, 3],
          date: new Date(),
          regex: /test/g
        },
        fn: () => 'test'
      };
      
      cache.set('complex_key', complexObject);
      const retrieved = cache.get('complex_key');
      
      expect(retrieved).toEqual(complexObject);
    });

    it('should handle very large keys and values', () => {
      const largeKey = 'x'.repeat(1000);
      const largeValue = 'y'.repeat(10000);
      
      cache.set(largeKey, largeValue);
      expect(cache.get(largeKey)).toBe(largeValue);
    });

    it('should handle special characters in keys', () => {
      const specialKeys = [
        'key with spaces',
        'key-with-dashes',
        'key_with_underscores',
        'key.with.dots',
        'key/with/slashes',
        'key:with:colons',
        'key@with@symbols',
        'key#with#hash',
        '中文键',
        'клавиша'
      ];
      
      specialKeys.forEach((key, index) => {
        const value = `value_${index}`;
        cache.set(key, value);
        expect(cache.get(key)).toBe(value);
      });
    });

    it('should handle concurrent operations safely', () => {
      const operations = [];
      
      // Simulate concurrent operations
      for (let i = 0; i < 100; i++) {
        operations.push(() => cache.set(`key_${i}`, `value_${i}`));
        operations.push(() => cache.get(`key_${i % 10}`));
        operations.push(() => cache.delete(`key_${i % 20}`));
      }
      
      // Execute all operations
      operations.forEach(op => op());
      
      // Cache should remain in consistent state
      expect(cache.size()).toBeLessThanOrEqual(100);
      expect(() => cache.getStatistics()).not.toThrow();
    });

    it('should handle memory calculation errors gracefully', () => {
      // Mock JSON.stringify to throw error
      const originalStringify = JSON.stringify;
      jest.spyOn(JSON, 'stringify').mockImplementation(() => {
        throw new Error('Circular reference');
      });
      
      const circularObj: any = { name: 'test' };
      circularObj.self = circularObj;
      
      cache.set('circular_key', circularObj);
      const memoryUsage = cache.getMemoryUsage();
      
      expect(memoryUsage.totalMB).toBe(0); // Should fallback to 0
      expect(componentLogger.error).toHaveBeenCalledWith(
        'Error calculating memory usage',
        expect.any(Object)
      );
      
      // Restore original function
      JSON.stringify = originalStringify;
    });
  });

  describe('Cache Entry Lifecycle', () => {
    beforeEach(() => {
      cache = new CacheManager({ defaultTTL: 10 });
    });

    it('should track entry creation and access times', () => {
      const key = 'test_key';
      const value = 'test_value';
      const startTime = Date.now();
      
      cache.set(key, value);
      const entry = cache.getEntry(key);
      
      expect(entry).toBeDefined();
      expect(entry!.createdAt).toBeGreaterThanOrEqual(startTime);
      expect(entry!.accessedAt).toBeGreaterThanOrEqual(startTime);
      expect(entry!.value).toBe(value);
    });

    it('should update access time on retrieval', async () => {
      const key = 'test_key';
      cache.set(key, 'value');
      
      const initialEntry = cache.getEntry(key);
      const initialAccessTime = initialEntry!.accessedAt;
      
      // Wait a bit and access again
      await new Promise(resolve => setTimeout(resolve, 10));
      cache.get(key);
      
      const updatedEntry = cache.getEntry(key);
      expect(updatedEntry!.accessedAt).toBeGreaterThan(initialAccessTime);
    });

    it('should return undefined for non-existent entry details', () => {
      const entry = cache.getEntry('non_existent_key');
      expect(entry).toBeUndefined();
    });
  });

  describe('Cache Configuration Management', () => {
    it('should allow runtime configuration updates', () => {
      cache = new CacheManager({ maxSize: 100 });
      
      const newConfig: CacheConfig = {
        maxSize: 200,
        defaultTTL: 600,
        maxMemoryMB: 50,
        enableStatistics: false
      };
      
      cache.updateConfig(newConfig);
      const currentConfig = cache.getConfig();
      
      expect(currentConfig).toMatchObject(newConfig);
      expect(componentLogger.info).toHaveBeenCalledWith('Cache configuration updated', newConfig);
    });

    it('should validate configuration during updates', () => {
      cache = new CacheManager();
      
      const invalidConfig = { maxSize: -5 };
      
      expect(() => cache.updateConfig(invalidConfig as CacheConfig))
        .toThrow('Invalid cache configuration');
    });

    it('should apply memory limits after configuration update', () => {
      cache = new CacheManager({ maxSize: 100 });
      
      // Add entries
      for (let i = 0; i < 50; i++) {
        cache.set(`key_${i}`, `value_${i}`);
      }
      
      expect(cache.size()).toBe(50);
      
      // Reduce max size
      cache.updateConfig({ maxSize: 10 });
      
      expect(cache.size()).toBeLessThanOrEqual(10);
    });
  });
});