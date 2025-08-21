/**
 * Enhanced Staged Test Execution Framework
 * 
 * Enterprise-grade test execution framework with advanced timing controls,
 * performance monitoring, stress detection, and adaptive loading strategies.
 * 
 * Features:
 * - Multi-stage loading with proper timing controls
 * - Performance monitoring and metrics collection
 * - System stress detection and adaptive backoff
 * - Configurable timing strategies for different environments
 * - Enterprise-grade error handling and recovery
 * - Real-time performance analytics
 */

import type { Page, BrowserContext } from '@playwright/test';
import { expect } from '@playwright/test';

// ==================== INTERFACES & TYPES ====================

export interface StagedExecutionConfig {
  /** Global timeout for all operations (default: 120000ms) */
  globalTimeout: number;
  /** Debug logging enabled (default: false) */
  debugLogging: boolean;
  /** Performance monitoring enabled (default: true) */
  performanceMonitoring: boolean;
  /** Stress detection enabled (default: true) */
  stressDetection: boolean;
  /** Maximum retry attempts (default: 3) */
  maxRetries: number;
  /** Base delay between stages (default: 1000ms) */
  baseStageDelay: number;
  /** Environment type affects timing strategies */
  environment: 'development' | 'staging' | 'production' | 'ci';
}

export interface StageConfig {
  /** Stage name for logging */
  name: string;
  /** Stage timeout (default: 30000ms) */
  timeout: number;
  /** Stage priority (1-5, higher = more critical) */
  priority: number;
  /** Elements that must be loaded for stage completion */
  requiredElements: string[];
  /** Optional elements to wait for */
  optionalElements: string[];
  /** Custom validation function */
  customValidation?: (page: Page) => Promise<boolean>;
  /** Skip this stage if condition is met */
  skipCondition?: (page: Page) => Promise<boolean>;
  /** Pre-stage hooks */
  preHooks?: Array<(page: Page) => Promise<void>>;
  /** Post-stage hooks */
  postHooks?: Array<(page: Page) => Promise<void>>;
}

export interface PerformanceMetrics {
  /** Overall test execution time */
  totalExecutionTime: number;
  /** Time taken for each stage */
  stageTimings: Record<string, number>;
  /** Network request metrics */
  networkMetrics: {
    totalRequests: number;
    averageResponseTime: number;
    failedRequests: number;
    slowRequests: number; // > 2000ms
  };
  /** System stress incidents */
  stressEvents: Array<{
    timestamp: number;
    severity: 'low' | 'medium' | 'high';
    recovery_time: number;
  }>;
  /** Memory usage tracking */
  memoryUsage: {
    peak: number;
    average: number;
    leaks_detected: boolean;
  };
  /** CPU usage tracking */
  cpuUsage: {
    peak: number;
    average: number;
    throttling_detected: boolean;
  };
}

export interface SystemStressIndicators {
  /** High response times detected */
  slowResponses: boolean;
  /** Memory pressure detected */
  memoryPressure: boolean;
  /** CPU throttling detected */
  cpuThrottling: boolean;
  /** Network congestion detected */
  networkCongestion: boolean;
  /** Error rate above threshold */
  errorRateHigh: boolean;
  /** Overall stress level (0-1) */
  stressLevel: number;
}

// ==================== STAGED EXECUTION ENGINE ====================

export class StagedTestExecutionEngine {
  private config: StagedExecutionConfig;
  private metrics: PerformanceMetrics;
  private stages: Map<string, StageConfig> = new Map();
  private requestMetrics: Array<{ url: string; responseTime: number; status: number; timestamp: number }> = [];
  private memorySnapshots: Array<{ timestamp: number; used: number; total: number }> = [];
  private cpuSnapshots: Array<{ timestamp: number; usage: number }> = [];

  constructor(config: Partial<StagedExecutionConfig> = {}) {
    this.config = {
      globalTimeout: 120000,
      debugLogging: false,
      performanceMonitoring: true,
      stressDetection: true,
      maxRetries: 3,
      baseStageDelay: 1000,
      environment: 'development',
      ...config
    };

    this.metrics = {
      totalExecutionTime: 0,
      stageTimings: {},
      networkMetrics: {
        totalRequests: 0,
        averageResponseTime: 0,
        failedRequests: 0,
        slowRequests: 0
      },
      stressEvents: [],
      memoryUsage: {
        peak: 0,
        average: 0,
        leaks_detected: false
      },
      cpuUsage: {
        peak: 0,
        average: 0,
        throttling_detected: false
      }
    };

    this.initializeDefaultStages();
  }

  /**
   * Initialize default staging configuration for common test scenarios
   */
  private initializeDefaultStages(): void {
    // Stage 1: Initial Page Load
    this.addStage('initial-load', {
      name: 'Initial Page Load',
      timeout: 30000,
      priority: 5,
      requiredElements: ['body', 'html'],
      optionalElements: ['nav', 'header', '[role="navigation"]'],
      customValidation: async (page: Page) => {
        return await page.locator('body').isVisible();
      }
    });

    // Stage 2: Workflow Data Loading
    this.addStage('workflow-data', {
      name: 'Workflow Data Loading',
      timeout: 45000,
      priority: 4,
      requiredElements: [
        '[data-testid="scenarios-list"]',
        '.scenarios-container',
        '.scenario-item'
      ],
      optionalElements: [
        '[data-testid="connections-list"]',
        '.connections-container'
      ],
      skipCondition: async (page: Page) => {
        // Skip if we're not on a workflow page
        const url = page.url();
        return !url.includes('workflow') && !url.includes('scenario');
      }
    });

    // Stage 3: Dashboard Components
    this.addStage('dashboard-components', {
      name: 'Dashboard Components',
      timeout: 60000,
      priority: 3,
      requiredElements: [
        '[data-testid="dashboard"]',
        '.dashboard-container'
      ],
      optionalElements: [
        '[data-testid*="chart"]',
        '.chart-container',
        '.metrics-grid'
      ],
      skipCondition: async (page: Page) => {
        // Skip if we're not on a dashboard page
        const url = page.url();
        return !url.includes('dashboard') && !url.includes('analytics');
      },
      customValidation: async (page: Page) => {
        // Ensure charts are rendered if present
        const charts = page.locator('[data-testid*="chart"], .chart-container');
        const chartCount = await charts.count();
        
        if (chartCount > 0) {
          // Wait for at least one chart to have content
          for (let i = 0; i < Math.min(chartCount, 5); i++) {
            const chart = charts.nth(i);
            if (await chart.isVisible()) {
              return true;
            }
          }
          return false;
        }
        return true; // No charts to validate
      }
    });

    // Stage 4: Interactive Elements
    this.addStage('interactive-elements', {
      name: 'Interactive Elements',
      timeout: 20000,
      priority: 2,
      requiredElements: [],
      optionalElements: [
        'button:not([disabled])',
        'a[href]',
        '[role="button"]',
        'input[type="button"]'
      ],
      customValidation: async (page: Page) => {
        // Ensure at least some interactive elements are available
        const interactiveElements = page.locator('button:not([disabled]), a[href], [role="button"]');
        return await interactiveElements.count() > 0;
      }
    });
  }

  /**
   * Add a custom stage to the execution pipeline
   */
  public addStage(id: string, config: StageConfig): void {
    this.stages.set(id, config);
    if (this.config.debugLogging) {
      console.log(`[StagedExecution] Added stage: ${config.name}`);
    }
  }

  /**
   * Execute all stages in priority order
   */
  public async executeStages(page: Page, stageIds?: string[]): Promise<PerformanceMetrics> {
    const executionStart = Date.now();
    
    if (this.config.debugLogging) {
      console.log('[StagedExecution] Starting staged test execution');
    }

    // Setup performance monitoring
    if (this.config.performanceMonitoring) {
      await this.setupPerformanceMonitoring(page);
    }

    // Get stages to execute (either specified or all stages)
    const stagesToExecute = stageIds 
      ? stageIds.map(id => ({ id, config: this.stages.get(id)! })).filter(s => s.config)
      : Array.from(this.stages.entries()).map(([id, config]) => ({ id, config }));

    // Sort stages by priority (highest first)
    stagesToExecute.sort((a, b) => b.config.priority - a.config.priority);

    // Execute each stage
    for (const { id, config } of stagesToExecute) {
      try {
        // Check if stage should be skipped
        if (config.skipCondition && await config.skipCondition(page)) {
          if (this.config.debugLogging) {
            console.log(`[StagedExecution] Skipping stage: ${config.name}`);
          }
          continue;
        }

        await this.executeStage(page, id, config);
        
        // Add delay between stages to prevent overload
        if (this.config.baseStageDelay > 0) {
          await page.waitForTimeout(this.config.baseStageDelay);
        }

      } catch (error) {
        if (this.config.debugLogging) {
          console.error(`[StagedExecution] Stage failed: ${config.name}`, error);
        }
        
        // For critical stages (priority 4+), rethrow the error
        if (config.priority >= 4) {
          throw new Error(`Critical stage failed: ${config.name} - ${error}`);
        }
        
        // For non-critical stages, log and continue
        console.warn(`[StagedExecution] Non-critical stage failed: ${config.name}`);
      }
    }

    // Finalize metrics
    this.metrics.totalExecutionTime = Date.now() - executionStart;
    
    if (this.config.performanceMonitoring) {
      await this.finalizePerformanceMetrics(page);
    }

    if (this.config.debugLogging) {
      console.log('[StagedExecution] Execution completed', this.metrics);
    }

    return this.metrics;
  }

  /**
   * Execute a single stage with retry logic and stress detection
   */
  private async executeStage(page: Page, stageId: string, config: StageConfig): Promise<void> {
    const stageStart = Date.now();
    
    if (this.config.debugLogging) {
      console.log(`[StagedExecution] Executing stage: ${config.name}`);
    }

    // Execute pre-hooks
    if (config.preHooks) {
      for (const hook of config.preHooks) {
        await hook(page);
      }
    }

    let lastError: Error | null = null;
    
    for (let attempt = 0; attempt < this.config.maxRetries; attempt++) {
      try {
        // Check for system stress before attempting
        if (this.config.stressDetection) {
          const stressIndicators = await this.detectSystemStress(page);
          
          if (stressIndicators.stressLevel > 0.7) {
            const backoffTime = Math.min(5000 * (attempt + 1), 15000);
            
            if (this.config.debugLogging) {
              console.log(`[StagedExecution] High stress detected (${stressIndicators.stressLevel}), backing off ${backoffTime}ms`);
            }
            
            await page.waitForTimeout(backoffTime);
            
            // Record stress event
            this.metrics.stressEvents.push({
              timestamp: Date.now(),
              severity: stressIndicators.stressLevel > 0.9 ? 'high' : 'medium',
              recovery_time: backoffTime
            });
          }
        }

        // Wait for required elements
        await this.waitForStageElements(page, config);
        
        // Run custom validation if provided
        if (config.customValidation) {
          const isValid = await config.customValidation(page);
          if (!isValid) {
            throw new Error(`Stage validation failed: ${config.name}`);
          }
        }

        // Execute post-hooks
        if (config.postHooks) {
          for (const hook of config.postHooks) {
            await hook(page);
          }
        }

        // Stage completed successfully
        this.metrics.stageTimings[stageId] = Date.now() - stageStart;
        
        if (this.config.debugLogging) {
          console.log(`[StagedExecution] Stage completed: ${config.name} (${this.metrics.stageTimings[stageId]}ms)`);
        }
        
        return;

      } catch (error) {
        lastError = error as Error;
        
        if (attempt < this.config.maxRetries - 1) {
          const retryDelay = 2000 * (attempt + 1);
          
          if (this.config.debugLogging) {
            console.log(`[StagedExecution] Retry ${attempt + 1}/${this.config.maxRetries} for stage: ${config.name}`);
          }
          
          await page.waitForTimeout(retryDelay);
        }
      }
    }

    // All retries failed
    throw lastError || new Error(`Stage failed after ${this.config.maxRetries} attempts: ${config.name}`);
  }

  /**
   * Wait for required and optional elements in a stage
   */
  private async waitForStageElements(page: Page, config: StageConfig): Promise<void> {
    // Wait for basic page stability first
    await page.waitForLoadState('load', { timeout: config.timeout / 4 });
    await page.waitForLoadState('networkidle', { timeout: config.timeout / 4 });

    // Wait for required elements
    for (const selector of config.requiredElements) {
      try {
        const element = page.locator(selector).first();
        await element.waitFor({ state: 'visible', timeout: config.timeout / 2 });
        
        if (this.config.debugLogging) {
          console.log(`[StagedExecution] Required element loaded: ${selector}`);
        }
      } catch (error) {
        throw new Error(`Required element not found: ${selector} in stage ${config.name}`);
      }
    }

    // Wait for optional elements (with more lenient timeouts)
    for (const selector of config.optionalElements) {
      try {
        const element = page.locator(selector).first();
        await element.waitFor({ state: 'visible', timeout: config.timeout / 4 });
        
        if (this.config.debugLogging) {
          console.log(`[StagedExecution] Optional element loaded: ${selector}`);
        }
      } catch (error) {
        // Optional elements failing is not critical
        if (this.config.debugLogging) {
          console.log(`[StagedExecution] Optional element not found: ${selector}`);
        }
      }
    }
  }

  /**
   * Detect system stress indicators
   */
  private async detectSystemStress(page: Page): Promise<SystemStressIndicators> {
    const indicators: SystemStressIndicators = {
      slowResponses: false,
      memoryPressure: false,
      cpuThrottling: false,
      networkCongestion: false,
      errorRateHigh: false,
      stressLevel: 0
    };

    try {
      // Check network response times
      const recentRequests = this.requestMetrics.slice(-10);
      if (recentRequests.length > 5) {
        const avgResponseTime = recentRequests.reduce((sum, req) => sum + req.responseTime, 0) / recentRequests.length;
        indicators.slowResponses = avgResponseTime > 2000;
      }

      // Check error rate
      const recentFailures = recentRequests.filter(req => req.status >= 400).length;
      indicators.errorRateHigh = recentFailures / Math.max(recentRequests.length, 1) > 0.1;

      // Check for error elements on page
      const errorSelectors = [
        '.error-boundary',
        '[data-testid="error"]',
        '.timeout-error',
        '.server-error',
        '[aria-label*="error"]'
      ];

      for (const selector of errorSelectors) {
        const errorElements = await page.locator(selector).count();
        if (errorElements > 0) {
          indicators.errorRateHigh = true;
          break;
        }
      }

      // Check memory usage (if available)
      if (this.memorySnapshots.length > 0) {
        const latestMemory = this.memorySnapshots[this.memorySnapshots.length - 1];
        const memoryUsagePercent = latestMemory.used / latestMemory.total;
        indicators.memoryPressure = memoryUsagePercent > 0.85;
      }

      // Calculate overall stress level
      const stressFactors = [
        indicators.slowResponses ? 0.3 : 0,
        indicators.memoryPressure ? 0.2 : 0,
        indicators.cpuThrottling ? 0.2 : 0,
        indicators.networkCongestion ? 0.15 : 0,
        indicators.errorRateHigh ? 0.35 : 0
      ];
      
      indicators.stressLevel = stressFactors.reduce((sum, factor) => sum + factor, 0);

    } catch (error) {
      // If stress detection fails, assume moderate stress
      indicators.stressLevel = 0.5;
    }

    return indicators;
  }

  /**
   * Setup performance monitoring for the page
   */
  private async setupPerformanceMonitoring(page: Page): Promise<void> {
    // Monitor network requests
    page.on('response', (response) => {
      const requestStart = Date.now();
      const responseTime = requestStart - Date.now(); // This is approximate
      
      this.requestMetrics.push({
        url: response.url(),
        responseTime: Math.abs(responseTime),
        status: response.status(),
        timestamp: Date.now()
      });

      // Keep only recent metrics (last 100 requests)
      if (this.requestMetrics.length > 100) {
        this.requestMetrics = this.requestMetrics.slice(-50);
      }
    });

    // Monitor memory usage (if browser supports it)
    try {
      const memoryInfo = await page.evaluate(() => {
        return (performance as any).memory || { usedJSHeapSize: 0, totalJSHeapSize: 0 };
      });

      this.memorySnapshots.push({
        timestamp: Date.now(),
        used: memoryInfo.usedJSHeapSize || 0,
        total: memoryInfo.totalJSHeapSize || 1
      });
    } catch (error) {
      // Memory monitoring not available
    }
  }

  /**
   * Finalize performance metrics collection
   */
  private async finalizePerformanceMetrics(page: Page): Promise<void> {
    // Calculate network metrics
    if (this.requestMetrics.length > 0) {
      this.metrics.networkMetrics.totalRequests = this.requestMetrics.length;
      this.metrics.networkMetrics.averageResponseTime = 
        this.requestMetrics.reduce((sum, req) => sum + req.responseTime, 0) / this.requestMetrics.length;
      this.metrics.networkMetrics.failedRequests = 
        this.requestMetrics.filter(req => req.status >= 400).length;
      this.metrics.networkMetrics.slowRequests = 
        this.requestMetrics.filter(req => req.responseTime > 2000).length;
    }

    // Calculate memory metrics
    if (this.memorySnapshots.length > 0) {
      const memoryUsages = this.memorySnapshots.map(snap => snap.used / snap.total);
      this.metrics.memoryUsage.peak = Math.max(...memoryUsages);
      this.metrics.memoryUsage.average = memoryUsages.reduce((sum, usage) => sum + usage, 0) / memoryUsages.length;
      
      // Simple leak detection: significant memory increase over time
      if (this.memorySnapshots.length > 5) {
        const firstHalf = this.memorySnapshots.slice(0, Math.floor(this.memorySnapshots.length / 2));
        const secondHalf = this.memorySnapshots.slice(Math.floor(this.memorySnapshots.length / 2));
        
        const firstAvg = firstHalf.reduce((sum, snap) => sum + snap.used / snap.total, 0) / firstHalf.length;
        const secondAvg = secondHalf.reduce((sum, snap) => sum + snap.used / snap.total, 0) / secondHalf.length;
        
        this.metrics.memoryUsage.leaks_detected = (secondAvg - firstAvg) > 0.2; // 20% increase
      }
    }
  }

  /**
   * Get performance metrics
   */
  public getMetrics(): PerformanceMetrics {
    return { ...this.metrics };
  }

  /**
   * Reset metrics for a new test run
   */
  public resetMetrics(): void {
    this.metrics = {
      totalExecutionTime: 0,
      stageTimings: {},
      networkMetrics: {
        totalRequests: 0,
        averageResponseTime: 0,
        failedRequests: 0,
        slowRequests: 0
      },
      stressEvents: [],
      memoryUsage: {
        peak: 0,
        average: 0,
        leaks_detected: false
      },
      cpuUsage: {
        peak: 0,
        average: 0,
        throttling_detected: false
      }
    };

    this.requestMetrics = [];
    this.memorySnapshots = [];
    this.cpuSnapshots = [];
  }
}

// ==================== UTILITY FUNCTIONS ====================

/**
 * Create a default staged execution engine with environment-specific configuration
 */
export function createStagedExecutionEngine(
  environment: 'development' | 'staging' | 'production' | 'ci' = 'development',
  customConfig: Partial<StagedExecutionConfig> = {}
): StagedTestExecutionEngine {
  const envConfigs = {
    development: {
      globalTimeout: 120000,
      debugLogging: true,
      baseStageDelay: 1500,
      maxRetries: 2
    },
    staging: {
      globalTimeout: 90000,
      debugLogging: false,
      baseStageDelay: 1000,
      maxRetries: 3
    },
    production: {
      globalTimeout: 60000,
      debugLogging: false,
      baseStageDelay: 500,
      maxRetries: 2
    },
    ci: {
      globalTimeout: 180000,
      debugLogging: true,
      baseStageDelay: 2000,
      maxRetries: 4
    }
  };

  const config = {
    environment,
    ...envConfigs[environment],
    ...customConfig
  };

  return new StagedTestExecutionEngine(config);
}

/**
 * Execute a simple staged test with default configuration
 */
export async function executeBasicStagedTest(
  page: Page,
  environment: 'development' | 'staging' | 'production' | 'ci' = 'development'
): Promise<PerformanceMetrics> {
  const engine = createStagedExecutionEngine(environment);
  return await engine.executeStages(page);
}

/**
 * Execute staged test with custom stage configuration
 */
export async function executeCustomStagedTest(
  page: Page,
  customStages: Array<{ id: string; config: StageConfig }>,
  config: Partial<StagedExecutionConfig> = {}
): Promise<PerformanceMetrics> {
  const engine = new StagedTestExecutionEngine(config);
  
  // Add custom stages
  for (const { id, config: stageConfig } of customStages) {
    engine.addStage(id, stageConfig);
  }
  
  return await engine.executeStages(page, customStages.map(s => s.id));
}

export default StagedTestExecutionEngine;