/**
 * Performance Monitoring Utility
 * 
 * Implements baseline performance monitoring as outlined in the research analysis.
 * Provides performance tracking, baseline establishment, and regression detection.
 * 
 * Research Priority: Phase 1 Foundation - Performance Monitoring Baseline
 */

import { performance } from 'perf_hooks';

export interface PerformanceMetric {
  name: string;
  startTime: number;
  endTime?: number;
  duration?: number;
  metadata?: Record<string, unknown>;
  category: 'startup' | 'api' | 'tool' | 'database' | 'cache' | 'custom';
}

export interface PerformanceBaseline {
  name: string;
  category: string;
  averageDuration: number;
  minDuration: number;
  maxDuration: number;
  samples: number;
  standardDeviation: number;
  p95: number;
  p99: number;
}

class PerformanceMonitor {
  private static instance: PerformanceMonitor;
  private readonly activeMetrics: Map<string, PerformanceMetric> = new Map();
  private readonly completedMetrics: PerformanceMetric[] = [];
  private readonly baselines: Map<string, PerformanceBaseline> = new Map();
  
  // Performance targets from research analysis
  private readonly targets: Record<PerformanceMetric['category'], number> = {
    startup: 2000, // 2 seconds
    api: 100,      // 100ms
    tool: 500,     // 500ms
    database: 50,  // 50ms
    cache: 10,     // 10ms
    custom: 1000,  // 1 second default for custom metrics
  };

  static getInstance(): PerformanceMonitor {
    if (!PerformanceMonitor.instance) {
      PerformanceMonitor.instance = new PerformanceMonitor();
    }
    return PerformanceMonitor.instance;
  }

  /**
   * Start tracking a performance metric
   */
  startMetric(name: string, category: PerformanceMetric['category'], metadata?: Record<string, unknown>): string {
    const id = `${name}_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
    const metric: PerformanceMetric = {
      name,
      startTime: performance.now(),
      category,
      metadata,
    };
    
    this.activeMetrics.set(id, metric);
    return id;
  }

  /**
   * End tracking a performance metric
   */
  endMetric(id: string): PerformanceMetric | null {
    const metric = this.activeMetrics.get(id);
    if (!metric) {
      return null;
    }

    metric.endTime = performance.now();
    metric.duration = metric.endTime - metric.startTime;

    this.activeMetrics.delete(id);
    this.completedMetrics.push(metric);

    // Update baseline if we have enough samples
    this.updateBaseline(metric);

    return metric;
  }

  /**
   * Track a synchronous operation
   */
  trackSync<T>(name: string, category: PerformanceMetric['category'], fn: () => T, metadata?: Record<string, unknown>): T {
    const id = this.startMetric(name, category, metadata);
    try {
      const result = fn();
      this.endMetric(id);
      return result;
    } catch (error) {
      this.endMetric(id);
      throw error;
    }
  }

  /**
   * Track an asynchronous operation
   */
  async trackAsync<T>(
    name: string, 
    category: PerformanceMetric['category'], 
    fn: () => Promise<T>, 
    metadata?: Record<string, unknown>
  ): Promise<T> {
    const id = this.startMetric(name, category, metadata);
    try {
      const result = await fn();
      this.endMetric(id);
      return result;
    } catch (error) {
      this.endMetric(id);
      throw error;
    }
  }

  /**
   * Update performance baseline for a metric
   */
  private updateBaseline(metric: PerformanceMetric): void {
    if (!metric.duration) {return;}

    const baselineKey = `${metric.category}_${metric.name}`;
    
    // Get all metrics for this name and category
    const relevantMetrics = this.completedMetrics
      .filter(m => m.name === metric.name && m.category === metric.category && m.duration)
      .map(m => m.duration);

    if (relevantMetrics.length >= 5) { // Need at least 5 samples for meaningful baseline
      const sorted = relevantMetrics.sort((a, b) => a - b);
      const sum = sorted.reduce((a, b) => a + b, 0);
      const average = sum / sorted.length;
      
      // Calculate standard deviation
      const variance = sorted.reduce((acc, val) => acc + Math.pow(val - average, 2), 0) / sorted.length;
      const standardDeviation = Math.sqrt(variance);
      
      // Calculate percentiles
      const p95Index = Math.ceil(sorted.length * 0.95) - 1;
      const p99Index = Math.ceil(sorted.length * 0.99) - 1;

      const baseline: PerformanceBaseline = {
        name: metric.name,
        category: metric.category,
        averageDuration: average,
        minDuration: sorted[0],
        maxDuration: sorted[sorted.length - 1],
        samples: sorted.length,
        standardDeviation,
        p95: sorted[p95Index],
        p99: sorted[p99Index],
      };

      this.baselines.set(baselineKey, baseline);
    }
  }

  /**
   * Check if a metric indicates performance regression
   */
  isPerformanceRegression(metric: PerformanceMetric): boolean {
    if (!metric.duration) {return false;}

    const baselineKey = `${metric.category}_${metric.name}`;
    const baseline = this.baselines.get(baselineKey);
    
    if (!baseline) {return false;}

    // Consider it a regression if it's > 2 standard deviations above average
    // or exceeds the P95 by more than 50%
    const regressionThreshold = Math.max(
      baseline.averageDuration + (2 * baseline.standardDeviation),
      baseline.p95 * 1.5
    );

    return metric.duration > regressionThreshold;
  }

  /**
   * Check if metric meets performance targets
   */
  meetsPerformanceTarget(metric: PerformanceMetric): boolean {
    if (!metric.duration) {return false;}

    const target = this.targets[metric.category];
    return metric.duration <= target;
  }

  /**
   * Get performance summary
   */
  getPerformanceSummary(): {
    totalMetrics: number;
    activeMetrics: number;
    baselines: PerformanceBaseline[];
    recentRegressions: PerformanceMetric[];
    categoryStats: Record<string, { count: number; avgDuration: number; targetMet: number }>;
  } {
    const recentMetrics = this.completedMetrics.slice(-50); // Last 50 metrics
    const recentRegressions = recentMetrics.filter(m => this.isPerformanceRegression(m));
    
    // Calculate category statistics
    const categoryStats: Record<string, { count: number; avgDuration: number; targetMet: number }> = {};
    
    Object.keys(this.targets).forEach(category => {
      const categoryMetrics = recentMetrics.filter(m => m.category === category && m.duration);
      if (categoryMetrics.length > 0) {
        const totalDuration = categoryMetrics.reduce((sum, m) => sum + (m.duration || 0), 0);
        const avgDuration = totalDuration / categoryMetrics.length;
        const targetMet = categoryMetrics.filter(m => this.meetsPerformanceTarget(m)).length;
        
        categoryStats[category] = {
          count: categoryMetrics.length,
          avgDuration,
          targetMet,
        };
      }
    });

    return {
      totalMetrics: this.completedMetrics.length,
      activeMetrics: this.activeMetrics.size,
      baselines: Array.from(this.baselines.values()),
      recentRegressions,
      categoryStats,
    };
  }

  /**
   * Export performance data for analysis
   */
  exportData(): {
    metrics: PerformanceMetric[];
    baselines: PerformanceBaseline[];
    summary: ReturnType<PerformanceMonitor['getPerformanceSummary']>;
  } {
    return {
      metrics: [...this.completedMetrics],
      baselines: Array.from(this.baselines.values()),
      summary: this.getPerformanceSummary(),
    };
  }

  /**
   * Clear all metrics (useful for testing)
   */
  clear(): void {
    this.activeMetrics.clear();
    this.completedMetrics.length = 0;
    this.baselines.clear();
  }
}

// Export singleton instance
export const performanceMonitor = PerformanceMonitor.getInstance();
export default performanceMonitor;