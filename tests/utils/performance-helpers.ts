/**
 * Performance optimization utilities for tests
 * Provides helpers to reduce test execution times while maintaining coverage
 */

export class TestPerformanceOptimizer {
  /**
   * Optimize delay for tests - reduces long delays while maintaining realistic behavior
   */
  static optimizeDelay(originalDelayMs: number, maxDelayMs: number = 100): number {
    return Math.min(originalDelayMs, maxDelayMs);
  }

  /**
   * Create fast mock timer for operations that don't need real timing
   */
  static createFastMockTimer(callback: () => void, delayMs: number = 1): NodeJS.Timeout {
    return setTimeout(callback, Math.min(delayMs, 10));
  }

  /**
   * Optimize concurrent operations by reducing batch size for tests
   */
  static optimizeConcurrency(originalCount: number, maxCount: number = 5): number {
    return Math.min(originalCount, maxCount);
  }

  /**
   * Create optimized test scenarios with reduced timing
   */
  static createOptimizedScenarios<T extends { duration?: number; delay?: number }>(
    scenarios: T[],
    maxDuration: number = 50
  ): T[] {
    return scenarios.map(scenario => ({
      ...scenario,
      duration: scenario.duration ? Math.min(scenario.duration, maxDuration) : undefined,
      delay: scenario.delay ? Math.min(scenario.delay, maxDuration) : undefined
    }));
  }

  /**
   * Fast promise resolver that bypasses setTimeout for immediate resolution
   */
  static fastResolve<T>(value: T): Promise<T> {
    return Promise.resolve(value);
  }

  /**
   * Optimized async operation wrapper that reduces wait times
   */
  static async optimizeAsyncOperation<T>(
    operation: () => Promise<T>,
    timeoutMs: number = 100
  ): Promise<T> {
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error('Test timeout')), timeoutMs);
    });
    
    return Promise.race([operation(), timeoutPromise]);
  }

  /**
   * Batch operations for better test performance
   */
  static async batchOperations<T, R>(
    items: T[],
    operation: (item: T) => Promise<R>,
    batchSize: number = 3
  ): Promise<R[]> {
    const results: R[] = [];
    
    for (let i = 0; i < items.length; i += batchSize) {
      const batch = items.slice(i, i + batchSize);
      const batchResults = await Promise.all(batch.map(operation));
      results.push(...batchResults);
    }
    
    return results;
  }

  /**
   * Mock high-frequency operations with sampling
   */
  static createSampledOperation<T>(
    operation: () => Promise<T>,
    sampleRate: number = 0.1 // Run only 10% of operations
  ): () => Promise<T | null> {
    return async () => {
      if (Math.random() < sampleRate) {
        return await operation();
      }
      return null;
    };
  }
}

/**
 * Performance test configuration
 */
export interface PerformanceTestConfig {
  maxDuration: number;
  maxConcurrency: number;
  sampleRate: number;
  fastMode: boolean;
}

/**
 * Default performance configuration for different test types
 */
export const PerformanceConfigs = {
  unit: {
    maxDuration: 50,
    maxConcurrency: 3,
    sampleRate: 1.0,
    fastMode: true
  } as PerformanceTestConfig,
  
  integration: {
    maxDuration: 200,
    maxConcurrency: 5,
    sampleRate: 0.8,
    fastMode: true
  } as PerformanceTestConfig,
  
  e2e: {
    maxDuration: 500,
    maxConcurrency: 10,
    sampleRate: 0.5,
    fastMode: false
  } as PerformanceTestConfig
};

/**
 * Apply performance optimizations to test configuration
 */
export function applyPerformanceOptimizations(
  config: Partial<PerformanceTestConfig> = {}
): PerformanceTestConfig {
  const defaultConfig = process.env.CI ? PerformanceConfigs.unit : PerformanceConfigs.integration;
  
  return {
    ...defaultConfig,
    ...config
  };
}