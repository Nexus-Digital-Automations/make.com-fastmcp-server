/**
 * Comprehensive Unit Tests for Performance Monitor Utility
 * 
 * Tests performance tracking, baseline establishment, regression detection,
 * and statistical analysis functionality for the performance monitoring system.
 * Focuses on achieving 100% coverage for utils/performance-monitor.ts.
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { performance } from 'perf_hooks';
import {
  performanceMonitor,
  type PerformanceMetric,
  type PerformanceBaseline
} from '../../../src/utils/performance-monitor.js';

describe('Performance Monitor Utility', () => {

  beforeEach(() => {
    // Clear all metrics before each test for isolation
    performanceMonitor.clear();
    
    // Mock performance.now for consistent timing
    jest.spyOn(performance, 'now')
      .mockReturnValueOnce(1000) // First call (start time)
      .mockReturnValueOnce(1150); // Second call (end time = 150ms duration)
    
    // Mock Date.now for consistent IDs
    jest.spyOn(Date, 'now').mockReturnValue(1609459200000);
    
    // Mock Math.random for consistent ID generation
    jest.spyOn(Math, 'random').mockReturnValue(0.5);
  });

  afterEach(() => {
    performanceMonitor.clear();
    jest.restoreAllMocks();
  });

  describe('Singleton Pattern', () => {
    it('should return the same instance', () => {
      const instance1 = performanceMonitor;
      const instance2 = performanceMonitor;
      
      expect(instance1).toBe(instance2);
    });

    it('should maintain state across getInstance calls', () => {
      const metricId = performanceMonitor.startMetric('test-metric', 'api');
      
      // Get same instance and verify it has the active metric
      const instance2 = performanceMonitor;
      const metric = instance2.endMetric(metricId);
      
      expect(metric).toBeTruthy();
      expect(metric!.name).toBe('test-metric');
    });
  });

  describe('startMetric()', () => {
    it('should start tracking a performance metric', () => {
      const metricId = performanceMonitor.startMetric('api-call', 'api', { endpoint: '/users' });
      
      expect(typeof metricId).toBe('string');
      expect(metricId).toContain('api-call');
      expect(metricId).toContain('1609459200000'); // Mocked timestamp
    });

    it('should generate unique IDs for different metrics', () => {
      // Mock different random values
      jest.spyOn(Math, 'random')
        .mockReturnValueOnce(0.1)
        .mockReturnValueOnce(0.9);

      const id1 = performanceMonitor.startMetric('test-1', 'api');
      const id2 = performanceMonitor.startMetric('test-2', 'api');
      
      expect(id1).not.toBe(id2);
    });

    it('should handle all metric categories', () => {
      const categories: PerformanceMetric['category'][] = ['startup', 'api', 'tool', 'database', 'cache', 'custom'];
      
      categories.forEach(category => {
        const id = performanceMonitor.startMetric(`test-${category}`, category);
        expect(typeof id).toBe('string');
        expect(id).toContain(`test-${category}`);
      });
    });

    it('should store metric metadata', () => {
      const metadata = { userId: '123', endpoint: '/api/test' };
      const metricId = performanceMonitor.startMetric('api-test', 'api', metadata);
      const completedMetric = performanceMonitor.endMetric(metricId);
      
      expect(completedMetric!.metadata).toEqual(metadata);
    });
  });

  describe('endMetric()', () => {
    it('should end tracking and return completed metric', () => {
      const metricId = performanceMonitor.startMetric('test-operation', 'tool');
      const completedMetric = performanceMonitor.endMetric(metricId);
      
      expect(completedMetric).toBeTruthy();
      expect(completedMetric!.name).toBe('test-operation');
      expect(completedMetric!.category).toBe('tool');
      expect(completedMetric!.startTime).toBe(1000);
      expect(completedMetric!.endTime).toBe(1150);
      expect(completedMetric!.duration).toBe(150);
    });

    it('should return null for non-existent metric ID', () => {
      const result = performanceMonitor.endMetric('non-existent-id');
      
      expect(result).toBeNull();
    });

    it('should remove metric from active metrics after completion', () => {
      const metricId = performanceMonitor.startMetric('test-metric', 'api');
      performanceMonitor.endMetric(metricId);
      
      // Trying to end the same metric again should return null
      const secondAttempt = performanceMonitor.endMetric(metricId);
      expect(secondAttempt).toBeNull();
    });

    it('should add completed metric to completed metrics list', () => {
      const metricId = performanceMonitor.startMetric('completed-test', 'database');
      performanceMonitor.endMetric(metricId);
      
      const summary = performanceMonitor.getPerformanceSummary();
      expect(summary.totalMetrics).toBe(1);
    });
  });

  describe('trackSync()', () => {
    it('should track synchronous operation successfully', () => {
      const mockFn = jest.fn().mockReturnValue('test-result');
      const metadata = { operation: 'sync-test' };
      
      const result = performanceMonitor.trackSync('sync-operation', 'tool', mockFn, metadata);
      
      expect(result).toBe('test-result');
      expect(mockFn).toHaveBeenCalledTimes(1);
      
      const summary = performanceMonitor.getPerformanceSummary();
      expect(summary.totalMetrics).toBe(1);
    });

    it('should handle synchronous operation errors', () => {
      const mockFn = jest.fn().mockImplementation(() => {
        throw new Error('Sync operation failed');
      });

      expect(() => {
        performanceMonitor.trackSync('failing-sync', 'api', mockFn);
      }).toThrow('Sync operation failed');
      
      // Metric should still be recorded even if operation failed
      const summary = performanceMonitor.getPerformanceSummary();
      expect(summary.totalMetrics).toBe(1);
    });

    it('should track timing for successful sync operations', () => {
      const mockFn = jest.fn().mockReturnValue(42);
      
      performanceMonitor.trackSync('timed-sync', 'cache', mockFn);
      
      const summary = performanceMonitor.getPerformanceSummary();
      expect(summary.totalMetrics).toBe(1);
      expect(summary.categoryStats.cache).toBeDefined();
      expect(summary.categoryStats.cache.count).toBe(1);
    });
  });

  describe('trackAsync()', () => {
    it('should track asynchronous operation successfully', async () => {
      const mockAsyncFn = jest.fn().mockResolvedValue('async-result');
      const metadata = { operation: 'async-test' };
      
      const result = await performanceMonitor.trackAsync('async-operation', 'database', mockAsyncFn, metadata);
      
      expect(result).toBe('async-result');
      expect(mockAsyncFn).toHaveBeenCalledTimes(1);
      
      const summary = performanceMonitor.getPerformanceSummary();
      expect(summary.totalMetrics).toBe(1);
    });

    it('should handle asynchronous operation errors', async () => {
      const mockAsyncFn = jest.fn().mockRejectedValue(new Error('Async operation failed'));

      await expect(
        performanceMonitor.trackAsync('failing-async', 'api', mockAsyncFn)
      ).rejects.toThrow('Async operation failed');
      
      // Metric should still be recorded even if operation failed
      const summary = performanceMonitor.getPerformanceSummary();
      expect(summary.totalMetrics).toBe(1);
    });

    it('should track timing for async operations', async () => {
      const mockAsyncFn = jest.fn().mockResolvedValue('success');
      
      await performanceMonitor.trackAsync('timed-async', 'startup', mockAsyncFn);
      
      const summary = performanceMonitor.getPerformanceSummary();
      expect(summary.totalMetrics).toBe(1);
      expect(summary.categoryStats.startup).toBeDefined();
      expect(summary.categoryStats.startup.count).toBe(1);
    });
  });

  describe('Performance Baseline Calculations', () => {
    beforeEach(() => {
      // Clear previous mocks and set up consistent mock values for baseline calculations
      jest.restoreAllMocks();
      jest.spyOn(performance, 'now')
        .mockReturnValueOnce(1000).mockReturnValueOnce(1100) // 100ms
        .mockReturnValueOnce(2000).mockReturnValueOnce(2120) // 120ms
        .mockReturnValueOnce(3000).mockReturnValueOnce(3080) // 80ms
        .mockReturnValueOnce(4000).mockReturnValueOnce(4110) // 110ms
        .mockReturnValueOnce(5000).mockReturnValueOnce(5090); // 90ms
      
      // Mock other functions consistently
      jest.spyOn(Date, 'now').mockReturnValue(1609459200000);
      jest.spyOn(Math, 'random').mockReturnValue(0.5);
    });

    it('should calculate baseline after 5 samples', () => {
      // Create 5 metrics with consistent timing
      for (let i = 0; i < 5; i++) {
        const id = performanceMonitor.startMetric('baseline-test', 'api');
        performanceMonitor.endMetric(id);
      }
      
      const summary = performanceMonitor.getPerformanceSummary();
      expect(summary.baselines).toHaveLength(1);
      
      const baseline = summary.baselines[0];
      expect(baseline.name).toBe('baseline-test');
      expect(baseline.category).toBe('api');
      expect(baseline.samples).toBe(5);
      expect(baseline.averageDuration).toBeCloseTo(100); // Average of 100, 120, 80, 110, 90
      expect(baseline.minDuration).toBe(80);
      expect(baseline.maxDuration).toBe(120);
    });

    it('should not calculate baseline with fewer than 5 samples', () => {
      // Create only 3 metrics
      for (let i = 0; i < 3; i++) {
        const id = performanceMonitor.startMetric('insufficient-samples', 'tool');
        performanceMonitor.endMetric(id);
      }
      
      const summary = performanceMonitor.getPerformanceSummary();
      expect(summary.baselines).toHaveLength(0);
    });

    it('should calculate percentiles correctly', () => {
      // Create 5 metrics for baseline calculation
      for (let i = 0; i < 5; i++) {
        const id = performanceMonitor.startMetric('percentile-test', 'database');
        performanceMonitor.endMetric(id);
      }
      
      const summary = performanceMonitor.getPerformanceSummary();
      const baseline = summary.baselines[0];
      
      // For sorted array [80, 90, 100, 110, 120]:
      // P95 = 95th percentile = index 4 (120)
      // P99 = 99th percentile = index 4 (120)
      expect(baseline.p95).toBe(120);
      expect(baseline.p99).toBe(120);
    });

    it('should calculate standard deviation', () => {
      // Values: [100, 120, 80, 110, 90], average = 100
      for (let i = 0; i < 5; i++) {
        const id = performanceMonitor.startMetric('std-dev-test', 'cache');
        performanceMonitor.endMetric(id);
      }
      
      const summary = performanceMonitor.getPerformanceSummary();
      const baseline = summary.baselines[0];
      
      // Standard deviation calculation:
      // variance = ((100-100)² + (120-100)² + (80-100)² + (110-100)² + (90-100)²) / 5
      // variance = (0 + 400 + 400 + 100 + 100) / 5 = 200
      // std dev = √200 ≈ 14.14
      expect(baseline.standardDeviation).toBeCloseTo(14.14, 1);
    });
  });

  describe('isPerformanceRegression()', () => {
    beforeEach(() => {
      // Clear and set up baseline with known values
      performanceMonitor.clear();
      jest.restoreAllMocks();
      jest.spyOn(performance, 'now')
        .mockReturnValueOnce(1000).mockReturnValueOnce(1100) // 100ms
        .mockReturnValueOnce(2000).mockReturnValueOnce(2100) // 100ms
        .mockReturnValueOnce(3000).mockReturnValueOnce(3100) // 100ms
        .mockReturnValueOnce(4000).mockReturnValueOnce(4100) // 100ms
        .mockReturnValueOnce(5000).mockReturnValueOnce(5100); // 100ms
      
      jest.spyOn(Date, 'now').mockReturnValue(1609459200000);
      jest.spyOn(Math, 'random').mockReturnValue(0.5);

      // Create baseline (5 samples of 100ms each)
      for (let i = 0; i < 5; i++) {
        const id = performanceMonitor.startMetric('regression-test', 'api');
        performanceMonitor.endMetric(id);
      }
    });

    it('should detect regression when duration exceeds 2 standard deviations', () => {
      // With baseline average=100ms, std dev=0, threshold = 100 + (2 * 0) = 100ms
      // Any duration > 100ms should be a regression
      const testMetric: PerformanceMetric = {
        name: 'regression-test',
        category: 'api',
        startTime: 1000,
        endTime: 1201,
        duration: 201 // Well above threshold
      };
      
      const isRegression = performanceMonitor.isPerformanceRegression(testMetric);
      expect(isRegression).toBe(true);
    });

    it('should not detect regression for normal performance', () => {
      const testMetric: PerformanceMetric = {
        name: 'regression-test',
        category: 'api',
        startTime: 1000,
        endTime: 1095,
        duration: 95 // Below threshold
      };
      
      const isRegression = performanceMonitor.isPerformanceRegression(testMetric);
      expect(isRegression).toBe(false);
    });

    it('should return false for metrics without duration', () => {
      const testMetric: PerformanceMetric = {
        name: 'regression-test',
        category: 'api',
        startTime: 1000
        // No duration
      };
      
      const isRegression = performanceMonitor.isPerformanceRegression(testMetric);
      expect(isRegression).toBe(false);
    });

    it('should return false when no baseline exists', () => {
      const testMetric: PerformanceMetric = {
        name: 'no-baseline-test',
        category: 'tool',
        startTime: 1000,
        endTime: 1500,
        duration: 500
      };
      
      const isRegression = performanceMonitor.isPerformanceRegression(testMetric);
      expect(isRegression).toBe(false);
    });
  });

  describe('meetsPerformanceTarget()', () => {
    it('should return true when metric meets performance target', () => {
      const testMetric: PerformanceMetric = {
        name: 'fast-api',
        category: 'api',
        startTime: 1000,
        endTime: 1050,
        duration: 50 // Below 100ms target for API
      };
      
      const meetsTarget = performanceMonitor.meetsPerformanceTarget(testMetric);
      expect(meetsTarget).toBe(true);
    });

    it('should return false when metric exceeds performance target', () => {
      const testMetric: PerformanceMetric = {
        name: 'slow-api',
        category: 'api',
        startTime: 1000,
        endTime: 1200,
        duration: 200 // Above 100ms target for API
      };
      
      const meetsTarget = performanceMonitor.meetsPerformanceTarget(testMetric);
      expect(meetsTarget).toBe(false);
    });

    it('should handle all category targets correctly', () => {
      const targets = {
        startup: 2000,
        api: 100,
        tool: 500,
        database: 50,
        cache: 10,
        custom: 1000
      };

      Object.entries(targets).forEach(([category, target]) => {
        const goodMetric: PerformanceMetric = {
          name: `good-${category}`,
          category: category as PerformanceMetric['category'],
          startTime: 1000,
          endTime: 1000 + target - 10, // 10ms below target
          duration: target - 10
        };

        const badMetric: PerformanceMetric = {
          name: `bad-${category}`,
          category: category as PerformanceMetric['category'],
          startTime: 1000,
          endTime: 1000 + target + 10, // 10ms above target
          duration: target + 10
        };

        expect(performanceMonitor.meetsPerformanceTarget(goodMetric)).toBe(true);
        expect(performanceMonitor.meetsPerformanceTarget(badMetric)).toBe(false);
      });
    });

    it('should return false for metrics without duration', () => {
      const testMetric: PerformanceMetric = {
        name: 'no-duration',
        category: 'api',
        startTime: 1000
        // No duration
      };
      
      const meetsTarget = performanceMonitor.meetsPerformanceTarget(testMetric);
      expect(meetsTarget).toBe(false);
    });
  });

  describe('getPerformanceSummary()', () => {
    beforeEach(() => {
      // Create test data with varying performance
      jest.spyOn(performance, 'now')
        .mockReturnValueOnce(1000).mockReturnValueOnce(1080) // 80ms API
        .mockReturnValueOnce(2000).mockReturnValueOnce(2200) // 200ms API (regression)
        .mockReturnValueOnce(3000).mockReturnValueOnce(3040) // 40ms Database
        .mockReturnValueOnce(4000).mockReturnValueOnce(4005) // 5ms Cache
        .mockReturnValueOnce(5000).mockReturnValueOnce(5600); // 600ms Tool
    });

    it('should provide comprehensive performance summary', () => {
      // Create various metrics
      const apiId1 = performanceMonitor.startMetric('api-call-1', 'api');
      performanceMonitor.endMetric(apiId1);
      
      const apiId2 = performanceMonitor.startMetric('api-call-2', 'api');
      performanceMonitor.endMetric(apiId2);
      
      const dbId = performanceMonitor.startMetric('db-query', 'database');
      performanceMonitor.endMetric(dbId);
      
      const cacheId = performanceMonitor.startMetric('cache-get', 'cache');
      performanceMonitor.endMetric(cacheId);
      
      const toolId = performanceMonitor.startMetric('tool-exec', 'tool');
      performanceMonitor.endMetric(toolId);
      
      const summary = performanceMonitor.getPerformanceSummary();
      
      expect(summary.totalMetrics).toBe(5);
      expect(summary.activeMetrics).toBe(0);
      expect(summary.baselines).toHaveLength(0); // Not enough samples for baselines
      
      // Check category stats
      expect(summary.categoryStats.api).toEqual({
        count: 2,
        avgDuration: 140, // (80 + 200) / 2
        targetMet: 1 // Only first API call met 100ms target
      });
      
      expect(summary.categoryStats.database).toEqual({
        count: 1,
        avgDuration: 40,
        targetMet: 1 // 40ms < 50ms target
      });
    });

    it('should track recent regressions', () => {
      // Set up baseline first
      jest.spyOn(performance, 'now')
        .mockReturnValueOnce(1000).mockReturnValueOnce(1100) // 100ms
        .mockReturnValueOnce(2000).mockReturnValueOnce(2100) // 100ms
        .mockReturnValueOnce(3000).mockReturnValueOnce(3100) // 100ms
        .mockReturnValueOnce(4000).mockReturnValueOnce(4100) // 100ms
        .mockReturnValueOnce(5000).mockReturnValueOnce(5100) // 100ms
        .mockReturnValueOnce(6000).mockReturnValueOnce(6500); // 500ms (regression)

      // Create baseline
      for (let i = 0; i < 5; i++) {
        const id = performanceMonitor.startMetric('baseline-api', 'api');
        performanceMonitor.endMetric(id);
      }
      
      // Add regression
      const regressionId = performanceMonitor.startMetric('baseline-api', 'api');
      performanceMonitor.endMetric(regressionId);
      
      const summary = performanceMonitor.getPerformanceSummary();
      expect(summary.recentRegressions).toHaveLength(1);
      expect(summary.recentRegressions[0].duration).toBe(500);
    });
  });

  describe('exportData()', () => {
    it('should export comprehensive performance data', () => {
      // Create some test metrics
      const id1 = performanceMonitor.startMetric('export-test-1', 'api');
      performanceMonitor.endMetric(id1);
      
      const id2 = performanceMonitor.startMetric('export-test-2', 'database');
      performanceMonitor.endMetric(id2);
      
      const exportData = performanceMonitor.exportData();
      
      expect(exportData).toHaveProperty('metrics');
      expect(exportData).toHaveProperty('baselines');
      expect(exportData).toHaveProperty('summary');
      
      expect(exportData.metrics).toHaveLength(2);
      expect(exportData.baselines).toEqual([]);
      expect(exportData.summary.totalMetrics).toBe(2);
    });

    it('should export independent data copies', () => {
      const id = performanceMonitor.startMetric('copy-test', 'tool');
      performanceMonitor.endMetric(id);
      
      const exportData1 = performanceMonitor.exportData();
      const exportData2 = performanceMonitor.exportData();
      
      // Should be different array instances but same content
      expect(exportData1.metrics).not.toBe(exportData2.metrics);
      expect(exportData1.metrics).toEqual(exportData2.metrics);
    });
  });

  describe('clear()', () => {
    it('should clear all metrics and baselines', () => {
      // Create some data
      const id = performanceMonitor.startMetric('clear-test', 'api');
      performanceMonitor.endMetric(id);
      
      // Verify data exists
      let summary = performanceMonitor.getPerformanceSummary();
      expect(summary.totalMetrics).toBe(1);
      
      // Clear and verify
      performanceMonitor.clear();
      summary = performanceMonitor.getPerformanceSummary();
      
      expect(summary.totalMetrics).toBe(0);
      expect(summary.activeMetrics).toBe(0);
      expect(summary.baselines).toHaveLength(0);
      expect(Object.keys(summary.categoryStats)).toHaveLength(0);
    });

    it('should clear active metrics as well', () => {
      // Start a metric but don't end it
      performanceMonitor.startMetric('active-clear-test', 'cache');
      
      let summary = performanceMonitor.getPerformanceSummary();
      expect(summary.activeMetrics).toBe(1);
      
      performanceMonitor.clear();
      summary = performanceMonitor.getPerformanceSummary();
      
      expect(summary.activeMetrics).toBe(0);
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle empty metric name', () => {
      const id = performanceMonitor.startMetric('', 'custom');
      const metric = performanceMonitor.endMetric(id);
      
      expect(metric).toBeTruthy();
      expect(metric!.name).toBe('');
    });

    it('should handle very short durations', () => {
      jest.spyOn(performance, 'now')
        .mockReturnValueOnce(1000.0)
        .mockReturnValueOnce(1000.1); // 0.1ms duration

      const id = performanceMonitor.startMetric('short-duration', 'cache');
      const metric = performanceMonitor.endMetric(id);
      
      expect(metric!.duration).toBeCloseTo(0.1, 1);
      expect(performanceMonitor.meetsPerformanceTarget(metric!)).toBe(true);
    });

    it('should handle very long durations', () => {
      jest.spyOn(performance, 'now')
        .mockReturnValueOnce(1000)
        .mockReturnValueOnce(11000); // 10 seconds

      const id = performanceMonitor.startMetric('long-duration', 'startup');
      const metric = performanceMonitor.endMetric(id);
      
      expect(metric!.duration).toBe(10000);
      expect(performanceMonitor.meetsPerformanceTarget(metric!)).toBe(false);
    });

    it('should handle baseline calculation with identical values', () => {
      // Mock 5 identical durations
      jest.spyOn(performance, 'now')
        .mockReturnValueOnce(1000).mockReturnValueOnce(1100) // 100ms
        .mockReturnValueOnce(2000).mockReturnValueOnce(2100) // 100ms
        .mockReturnValueOnce(3000).mockReturnValueOnce(3100) // 100ms
        .mockReturnValueOnce(4000).mockReturnValueOnce(4100) // 100ms
        .mockReturnValueOnce(5000).mockReturnValueOnce(5100); // 100ms

      for (let i = 0; i < 5; i++) {
        const id = performanceMonitor.startMetric('identical-values', 'tool');
        performanceMonitor.endMetric(id);
      }
      
      const summary = performanceMonitor.getPerformanceSummary();
      const baseline = summary.baselines[0];
      
      expect(baseline.averageDuration).toBe(100);
      expect(baseline.minDuration).toBe(100);
      expect(baseline.maxDuration).toBe(100);
      expect(baseline.standardDeviation).toBe(0);
    });

    it('should handle metrics without metadata', () => {
      const id = performanceMonitor.startMetric('no-metadata', 'api');
      const metric = performanceMonitor.endMetric(id);
      
      expect(metric!.metadata).toBeUndefined();
    });

    it('should handle empty metadata object', () => {
      const id = performanceMonitor.startMetric('empty-metadata', 'database', {});
      const metric = performanceMonitor.endMetric(id);
      
      expect(metric!.metadata).toEqual({});
    });
  });

  describe('Statistical Accuracy', () => {
    it('should calculate percentiles correctly for larger datasets', () => {
      // Create 10 samples with known values: 10, 20, 30, ..., 100
      const mockTimes: number[] = [];
      for (let i = 1; i <= 10; i++) {
        mockTimes.push(1000 * i); // Start times
        mockTimes.push(1000 * i + (i * 10)); // End times (duration = i * 10)
      }
      jest.spyOn(performance, 'now').mockImplementation(() => mockTimes.shift() || 0);

      for (let i = 1; i <= 10; i++) {
        const id = performanceMonitor.startMetric('percentile-accuracy', 'custom');
        performanceMonitor.endMetric(id);
      }
      
      const summary = performanceMonitor.getPerformanceSummary();
      const baseline = summary.baselines[0];
      
      // For values [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]:
      // P95 (95% of 10 = 9.5, ceil = 10, index 9) = 100
      // P99 (99% of 10 = 9.9, ceil = 10, index 9) = 100
      expect(baseline.p95).toBe(100);
      expect(baseline.p99).toBe(100);
      expect(baseline.averageDuration).toBe(55); // (10+20+...+100)/10
    });
  });

  describe('Integration Tests', () => {
    it('should handle complete performance monitoring workflow', async () => {
      // Mock realistic timing values
      let currentTime = 1000;
      jest.spyOn(performance, 'now').mockImplementation(() => {
        const time = currentTime;
        currentTime += Math.random() * 100 + 50; // Random durations 50-150ms
        return time;
      });

      // Perform various operations
      const results: any[] = [];
      
      // Sync operations
      results.push(performanceMonitor.trackSync('sync-1', 'api', () => 'result1'));
      results.push(performanceMonitor.trackSync('sync-2', 'database', () => 'result2'));
      
      // Async operations
      results.push(await performanceMonitor.trackAsync('async-1', 'tool', async () => 'async-result1'));
      results.push(await performanceMonitor.trackAsync('async-2', 'cache', async () => 'async-result2'));
      
      // Manual tracking
      const manualId = performanceMonitor.startMetric('manual-operation', 'custom', { custom: true });
      // Simulate some work
      currentTime += 75;
      const manualMetric = performanceMonitor.endMetric(manualId);
      
      // Verify all operations completed
      expect(results).toEqual(['result1', 'result2', 'async-result1', 'async-result2']);
      expect(manualMetric).toBeTruthy();
      
      // Check comprehensive summary
      const summary = performanceMonitor.getPerformanceSummary();
      expect(summary.totalMetrics).toBe(5);
      expect(Object.keys(summary.categoryStats)).toHaveLength(5);
      
      // Verify export functionality
      const exportData = performanceMonitor.exportData();
      expect(exportData.metrics).toHaveLength(5);
      expect(exportData.summary.totalMetrics).toBe(5);
    });
  });
});