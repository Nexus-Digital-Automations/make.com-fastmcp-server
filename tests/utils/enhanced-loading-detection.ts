/**
 * Enhanced Loading State Detection and Waiting Mechanisms
 * 
 * Provides comprehensive loading detection utilities that combine the best of
 * existing loading helpers with advanced detection capabilities, performance
 * monitoring, and intelligent waiting strategies.
 * 
 * Features:
 * - Unified loading detection API with intelligent selectors
 * - Advanced skeleton screen and dynamic content detection
 * - Performance-aware waiting with adaptive timeouts
 * - Integration with staged test execution framework
 * - Enhanced error handling and recovery mechanisms
 * - Real-time loading state monitoring and analytics
 */

import type { Page, Locator } from '@playwright/test';
import { 
  waitForElementsToLoad as baseWaitForElementsToLoad,
  waitForDashboardReady as baseWaitForDashboardReady, 
  waitForWorkflowsLoaded as baseWaitForWorkflowsLoaded,
  waitWithBackoff,
  type LoadingOptions,
  type DashboardLoadingOptions,
  type WorkflowLoadingOptions
} from '../browser/loading-sequence-helpers';
import { 
  StagedTestExecutionEngine,
  createStagedExecutionEngine,
  type PerformanceMetrics,
  type SystemStressIndicators
} from './staged-test-execution';

// ==================== ENHANCED INTERFACES ====================

export interface EnhancedLoadingOptions extends LoadingOptions {
  /** Use intelligent selector detection */
  intelligentSelectors?: boolean;
  /** Monitor performance during loading */
  performanceMonitoring?: boolean;
  /** Adaptive timeout based on detected content complexity */
  adaptiveTimeout?: boolean;
  /** Custom loading indicators beyond standard selectors */
  customLoadingSelectors?: string[];
  /** Custom content selectors that indicate loading completion */
  customContentSelectors?: string[];
  /** Minimum content threshold before considering load complete */
  minContentThreshold?: number;
  /** Enable stress-aware loading detection */
  stressAwareLoading?: boolean;
}

export interface LoadingDetectionResult {
  /** Whether loading completed successfully */
  success: boolean;
  /** Time taken for loading detection */
  duration: number;
  /** Performance metrics collected during loading */
  metrics?: PerformanceMetrics;
  /** System stress indicators detected */
  stressIndicators?: SystemStressIndicators;
  /** Loading stages completed */
  stagesCompleted: string[];
  /** Any warnings or issues encountered */
  warnings: string[];
  /** Content complexity detected */
  contentComplexity: 'low' | 'medium' | 'high';
}

export interface SkeletonDetectionConfig {
  /** Common skeleton screen selectors */
  skeletonSelectors: string[];
  /** Shimmer/pulse animation selectors */
  shimmerSelectors: string[];
  /** Placeholder content selectors */
  placeholderSelectors: string[];
  /** Maximum wait time for skeleton resolution */
  maxSkeletonWait: number;
}

export interface DynamicContentConfig {
  /** Selectors for elements that load dynamically */
  dynamicContentSelectors: string[];
  /** Minimum number of dynamic elements expected */
  minDynamicElements: number;
  /** Attributes that indicate content is loaded */
  loadedAttributes: string[];
  /** Text patterns that indicate loading completion */
  loadedTextPatterns: RegExp[];
}

// ==================== ENHANCED LOADING DETECTION ENGINE ====================

export class EnhancedLoadingDetectionEngine {
  private performanceEngine: StagedTestExecutionEngine;
  private skeletonConfig: SkeletonDetectionConfig;
  private dynamicContentConfig: DynamicContentConfig;

  constructor() {
    this.performanceEngine = createStagedExecutionEngine('development', {
      debugLogging: true,
      performanceMonitoring: true,
      stressDetection: true
    });

    this.skeletonConfig = {
      skeletonSelectors: [
        '.skeleton',
        '.skeleton-loader',
        '.skeleton-text',
        '.skeleton-avatar',
        '.skeleton-card',
        '[data-testid*="skeleton"]',
        '.animate-pulse',
        '.shimmer',
        '.loading-placeholder',
        '.content-placeholder'
      ],
      shimmerSelectors: [
        '.shimmer',
        '.shimmer-effect',
        '.animate-pulse',
        '.skeleton-shimmer',
        '[data-loading-shimmer]'
      ],
      placeholderSelectors: [
        '.placeholder',
        '.placeholder-text',
        '.placeholder-content',
        '[data-placeholder]',
        '.empty-state[data-loading="true"]'
      ],
      maxSkeletonWait: 10000
    };

    this.dynamicContentConfig = {
      dynamicContentSelectors: [
        '[data-testid*="dynamic"]',
        '[data-loaded]',
        '.content-loaded',
        '.data-populated',
        '[aria-busy="false"]',
        '.list-item:not(.placeholder)',
        '.chart:not(.loading)',
        '.table-row:not(.skeleton)'
      ],
      minDynamicElements: 1,
      loadedAttributes: [
        'data-loaded="true"',
        'aria-busy="false"',
        'data-state="loaded"',
        'data-content="populated"'
      ],
      loadedTextPatterns: [
        /\d+\s+(items?|results?|entries)/i,
        /loaded|ready|complete/i,
        /\$[\d,]+\.\d{2}/,  // currency patterns
        /\d{1,2}\/\d{1,2}\/\d{4}/,  // date patterns
      ]
    };
  }

  /**
   * Enhanced waitForElementsToLoad with intelligent detection
   */
  async waitForElementsToLoad(
    page: Page, 
    options: EnhancedLoadingOptions = {}
  ): Promise<LoadingDetectionResult> {
    const startTime = Date.now();
    const result: LoadingDetectionResult = {
      success: false,
      duration: 0,
      stagesCompleted: [],
      warnings: [],
      contentComplexity: 'medium'
    };

    try {
      // Stage 1: Basic loading detection using existing helpers
      result.stagesCompleted.push('basic-loading');
      await baseWaitForElementsToLoad(page, options);

      // Stage 2: Enhanced skeleton screen detection
      if (options.intelligentSelectors !== false) {
        result.stagesCompleted.push('skeleton-detection');
        await this.waitForSkeletonScreensToResolve(page, options);
      }

      // Stage 3: Dynamic content population detection
      result.stagesCompleted.push('dynamic-content');
      await this.waitForDynamicContentToLoad(page, options);

      // Stage 4: Content complexity analysis
      result.stagesCompleted.push('complexity-analysis');
      result.contentComplexity = await this.analyzeContentComplexity(page);

      // Stage 5: Performance monitoring (if enabled)
      if (options.performanceMonitoring) {
        result.stagesCompleted.push('performance-monitoring');
        result.metrics = await this.performanceEngine.executeStages(page, ['initial-load']);
      }

      // Stage 6: Stress detection (if enabled)
      if (options.stressAwareLoading) {
        result.stagesCompleted.push('stress-detection');
        result.stressIndicators = await this.detectLoadingStress(page);
      }

      result.success = true;
      
    } catch (error) {
      result.warnings.push(`Loading detection failed: ${error.message}`);
      
      // Attempt graceful degradation
      try {
        await baseWaitForElementsToLoad(page, { ...options, timeout: options.timeout ? options.timeout / 2 : 15000 });
        result.success = true;
        result.warnings.push('Fallback to basic loading detection succeeded');
      } catch (fallbackError) {
        result.warnings.push(`Fallback also failed: ${fallbackError.message}`);
      }
    }

    result.duration = Date.now() - startTime;
    return result;
  }

  /**
   * Enhanced dashboard loading with comprehensive content detection
   */
  async waitForDashboardReady(
    page: Page, 
    options: DashboardLoadingOptions & EnhancedLoadingOptions = {}
  ): Promise<LoadingDetectionResult> {
    const startTime = Date.now();
    const result: LoadingDetectionResult = {
      success: false,
      duration: 0,
      stagesCompleted: [],
      warnings: [],
      contentComplexity: 'high' // Dashboards are typically complex
    };

    try {
      // Stage 1: Basic dashboard loading
      result.stagesCompleted.push('basic-dashboard');
      await baseWaitForDashboardReady(page, options);

      // Stage 2: Enhanced chart and visualization detection
      result.stagesCompleted.push('chart-detection');
      await this.waitForChartsAndVisualizationsToLoad(page, options);

      // Stage 3: Data table and metrics detection
      result.stagesCompleted.push('data-detection');
      await this.waitForDataTablesAndMetricsToLoad(page, options);

      // Stage 4: Interactive elements validation
      result.stagesCompleted.push('interactive-validation');
      await this.validateInteractiveElements(page, options);

      // Stage 5: Performance monitoring for dashboard
      if (options.performanceMonitoring) {
        result.stagesCompleted.push('dashboard-performance');
        result.metrics = await this.performanceEngine.executeStages(page, ['dashboard-components']);
      }

      result.success = true;

    } catch (error) {
      result.warnings.push(`Dashboard loading failed: ${error.message}`);
      
      // Graceful degradation
      try {
        await baseWaitForDashboardReady(page, { ...options, timeout: options.timeout ? options.timeout / 2 : 30000 });
        result.success = true;
        result.warnings.push('Fallback to basic dashboard loading succeeded');
      } catch (fallbackError) {
        result.warnings.push(`Dashboard fallback failed: ${fallbackError.message}`);
      }
    }

    result.duration = Date.now() - startTime;
    return result;
  }

  /**
   * Enhanced workflow loading with comprehensive data detection
   */
  async waitForWorkflowsLoaded(
    page: Page, 
    options: WorkflowLoadingOptions & EnhancedLoadingOptions = {}
  ): Promise<LoadingDetectionResult> {
    const startTime = Date.now();
    const result: LoadingDetectionResult = {
      success: false,
      duration: 0,
      stagesCompleted: [],
      warnings: [],
      contentComplexity: 'medium'
    };

    try {
      // Stage 1: Basic workflow loading
      result.stagesCompleted.push('basic-workflows');
      await baseWaitForWorkflowsLoaded(page, options);

      // Stage 2: Enhanced scenario detection
      result.stagesCompleted.push('scenario-detection');
      await this.waitForScenariosToPopulate(page, options);

      // Stage 3: Connection validation
      result.stagesCompleted.push('connection-validation');
      await this.waitForConnectionsToValidate(page, options);

      // Stage 4: Template availability check
      if (options.waitForTemplates) {
        result.stagesCompleted.push('template-detection');
        await this.waitForTemplatesToLoad(page, options);
      }

      // Stage 5: Performance monitoring for workflows
      if (options.performanceMonitoring) {
        result.stagesCompleted.push('workflow-performance');
        result.metrics = await this.performanceEngine.executeStages(page, ['workflow-data']);
      }

      result.success = true;

    } catch (error) {
      result.warnings.push(`Workflow loading failed: ${error.message}`);
      
      // Graceful degradation
      try {
        await baseWaitForWorkflowsLoaded(page, { ...options, timeout: options.timeout ? options.timeout / 2 : 25000 });
        result.success = true;
        result.warnings.push('Fallback to basic workflow loading succeeded');
      } catch (fallbackError) {
        result.warnings.push(`Workflow fallback failed: ${fallbackError.message}`);
      }
    }

    result.duration = Date.now() - startTime;
    return result;
  }

  // ==================== PRIVATE HELPER METHODS ====================

  /**
   * Wait for skeleton screens to resolve into actual content
   */
  private async waitForSkeletonScreensToResolve(page: Page, options: EnhancedLoadingOptions): Promise<void> {
    const { timeout = 30000, debugLogging = false } = options;
    
    if (debugLogging) {
      console.log('[EnhancedLoading] Checking for skeleton screens...');
    }

    // Check for skeleton elements
    for (const selector of this.skeletonConfig.skeletonSelectors) {
      const skeletonElements = page.locator(selector);
      const count = await skeletonElements.count();
      
      if (count > 0) {
        if (debugLogging) {
          console.log(`[EnhancedLoading] Found ${count} skeleton elements: ${selector}`);
        }
        
        // Wait for skeleton elements to be replaced with actual content
        await skeletonElements.first().waitFor({ 
          state: 'hidden', 
          timeout: Math.min(this.skeletonConfig.maxSkeletonWait, timeout / 2) 
        });
        
        if (debugLogging) {
          console.log(`[EnhancedLoading] Skeleton elements resolved: ${selector}`);
        }
      }
    }

    // Check for shimmer effects
    for (const selector of this.skeletonConfig.shimmerSelectors) {
      const shimmerElements = page.locator(selector);
      const count = await shimmerElements.count();
      
      if (count > 0) {
        if (debugLogging) {
          console.log(`[EnhancedLoading] Found ${count} shimmer elements: ${selector}`);
        }
        
        // Wait for shimmer to stop (usually indicates content is loaded)
        await page.waitForTimeout(1000); // Give shimmer time to stop
        
        // Verify shimmer elements are gone or no longer animating
        const stillShimmering = await page.locator(`${selector}:not(.loaded):not([data-loaded="true"])`).count();
        if (stillShimmering === 0 && debugLogging) {
          console.log(`[EnhancedLoading] Shimmer effects resolved: ${selector}`);
        }
      }
    }
  }

  /**
   * Wait for dynamic content to populate
   */
  private async waitForDynamicContentToLoad(page: Page, options: EnhancedLoadingOptions): Promise<void> {
    const { timeout = 30000, debugLogging = false, minContentThreshold = 1 } = options;
    
    if (debugLogging) {
      console.log('[EnhancedLoading] Waiting for dynamic content to load...');
    }

    // Wait for dynamic content selectors
    let dynamicContentFound = 0;
    
    for (const selector of this.dynamicContentConfig.dynamicContentSelectors) {
      const elements = page.locator(selector);
      const count = await elements.count();
      
      if (count > 0) {
        dynamicContentFound += count;
        
        if (debugLogging) {
          console.log(`[EnhancedLoading] Found ${count} dynamic content elements: ${selector}`);
        }
        
        // Wait for at least one element to be visible
        await elements.first().waitFor({ state: 'visible', timeout: timeout / 3 });
      }
    }

    // Check for loaded attributes
    for (const attribute of this.dynamicContentConfig.loadedAttributes) {
      const elements = page.locator(`[${attribute}]`);
      const count = await elements.count();
      
      if (count > 0) {
        dynamicContentFound += count;
        
        if (debugLogging) {
          console.log(`[EnhancedLoading] Found ${count} elements with loaded attribute: ${attribute}`);
        }
      }
    }

    // Check for loaded text patterns
    for (const pattern of this.dynamicContentConfig.loadedTextPatterns) {
      const textContent = await page.textContent('body');
      if (textContent && pattern.test(textContent)) {
        dynamicContentFound += 1;
        
        if (debugLogging) {
          console.log(`[EnhancedLoading] Found loaded text pattern: ${pattern}`);
        }
      }
    }

    if (dynamicContentFound < minContentThreshold) {
      throw new Error(`Insufficient dynamic content loaded: ${dynamicContentFound} < ${minContentThreshold}`);
    }

    if (debugLogging) {
      console.log(`[EnhancedLoading] Dynamic content loading complete: ${dynamicContentFound} elements found`);
    }
  }

  /**
   * Analyze content complexity for adaptive timing
   */
  private async analyzeContentComplexity(page: Page): Promise<'low' | 'medium' | 'high'> {
    try {
      // Count various content types
      const [
        elementCount,
        imageCount,
        scriptCount,
        styleCount,
        svgCount,
        canvasCount,
        videoCount
      ] = await Promise.all([
        page.locator('*').count(),
        page.locator('img').count(),
        page.locator('script').count(),
        page.locator('style, link[rel="stylesheet"]').count(),
        page.locator('svg').count(),
        page.locator('canvas').count(),
        page.locator('video, audio').count()
      ]);

      const totalComplexity = 
        elementCount * 0.1 +
        imageCount * 2 +
        scriptCount * 3 +
        styleCount * 1 +
        svgCount * 1.5 +
        canvasCount * 5 +
        videoCount * 10;

      if (totalComplexity < 100) return 'low';
      if (totalComplexity < 500) return 'medium';
      return 'high';

    } catch (error) {
      return 'medium'; // Default fallback
    }
  }

  /**
   * Detect loading-specific system stress
   */
  private async detectLoadingStress(page: Page): Promise<SystemStressIndicators> {
    // Import the stress detection function directly to get proper typing
    const { detectSystemStress: baseDetectSystemStress } = await import('../browser/loading-sequence-helpers');
    
    // Create base stress indicators
    const isBasicStressed = await baseDetectSystemStress(page);
    
    const baseStress: SystemStressIndicators = {
      slowResponses: isBasicStressed,
      memoryPressure: false,
      cpuThrottling: false,
      networkCongestion: isBasicStressed,
      errorRateHigh: false,
      stressLevel: isBasicStressed ? 0.6 : 0.2
    };
    
    // Add loading-specific stress indicators
    try {
      const loadingElements = await page.locator('.loading, .spinner, .skeleton').count();
      const errorElements = await page.locator('.error, .failed, .timeout').count();
      const emptyElements = await page.locator('.empty, .no-data, .no-results').count();
      
      return {
        slowResponses: baseStress.slowResponses || loadingElements > 5,
        memoryPressure: baseStress.memoryPressure,
        cpuThrottling: baseStress.cpuThrottling,
        networkCongestion: baseStress.networkCongestion || emptyElements > 5,
        errorRateHigh: baseStress.errorRateHigh || errorElements > 3,
        // Override stress level if too many loading indicators persist
        stressLevel: loadingElements > 10 ? Math.max(baseStress.stressLevel, 0.8) : baseStress.stressLevel
      };
    } catch (error) {
      return baseStress;
    }
  }

  /**
   * Wait for charts and visualizations to load completely
   */
  private async waitForChartsAndVisualizationsToLoad(page: Page, options: EnhancedLoadingOptions): Promise<void> {
    const { timeout = 45000, debugLogging = false } = options;
    
    const chartSelectors = [
      '[data-testid*="chart"]',
      '.chart-container',
      '.recharts-surface',
      'canvas[width][height]',
      'svg[width][height]',
      '.visualization',
      '.graph-container',
      '.d3-chart',
      '.chartjs-chart'
    ];

    for (const selector of chartSelectors) {
      const charts = page.locator(selector);
      const count = await charts.count();
      
      if (count > 0) {
        if (debugLogging) {
          console.log(`[EnhancedLoading] Waiting for ${count} charts to load: ${selector}`);
        }
        
        // Wait for charts to be visible and rendered
        for (let i = 0; i < Math.min(count, 10); i++) {
          const chart = charts.nth(i);
          await chart.waitFor({ state: 'visible', timeout: timeout / 3 });
          
          // For canvas/SVG charts, wait a bit more for rendering
          if (selector.includes('canvas') || selector.includes('svg')) {
            await page.waitForTimeout(500);
          }
        }
      }
    }
  }

  /**
   * Wait for data tables and metrics to load
   */
  private async waitForDataTablesAndMetricsToLoad(page: Page, options: EnhancedLoadingOptions): Promise<void> {
    const { timeout = 30000, debugLogging = false } = options;
    
    const dataSelectors = [
      '[data-testid*="data-table"]',
      '.data-table',
      '.metrics-grid',
      '.stats-container',
      'table:not(.skeleton)',
      '.table-row:not(.placeholder)',
      '[data-loaded="true"]',
      '.metric-value:not(.loading)'
    ];

    for (const selector of dataSelectors) {
      const elements = page.locator(selector);
      const count = await elements.count();
      
      if (count > 0) {
        if (debugLogging) {
          console.log(`[EnhancedLoading] Waiting for ${count} data elements: ${selector}`);
        }
        
        await elements.first().waitFor({ state: 'visible', timeout: timeout / 2 });
      }
    }
  }

  /**
   * Validate that interactive elements are ready
   */
  private async validateInteractiveElements(page: Page, options: EnhancedLoadingOptions): Promise<void> {
    const { debugLogging = false } = options;
    
    const interactiveSelectors = [
      'button:not([disabled]):not(.loading)',
      'a[href]:not(.disabled)',
      'input:not([disabled]):not([readonly])',
      'select:not([disabled])',
      '[role="button"]:not([aria-disabled="true"])'
    ];

    let interactiveCount = 0;
    
    for (const selector of interactiveSelectors) {
      const elements = page.locator(selector);
      const count = await elements.count();
      interactiveCount += count;
    }

    if (debugLogging) {
      console.log(`[EnhancedLoading] Found ${interactiveCount} interactive elements ready`);
    }

    // Ensure at least some interactive elements are available
    if (interactiveCount === 0) {
      console.warn('[EnhancedLoading] Warning: No interactive elements detected');
    }
  }

  /**
   * Wait for scenarios to populate with actual data
   */
  private async waitForScenariosToPopulate(page: Page, options: EnhancedLoadingOptions): Promise<void> {
    const { timeout = 30000, debugLogging = false } = options;
    
    const scenarioSelectors = [
      '[data-testid="scenarios-list"] .scenario-item:not(.skeleton)',
      '.scenarios-container .scenario:not(.placeholder)',
      '.scenario-card:not(.loading)',
      '[data-scenario-id]:not([data-scenario-id=""])'
    ];

    for (const selector of scenarioSelectors) {
      const scenarios = page.locator(selector);
      const count = await scenarios.count();
      
      if (count > 0) {
        if (debugLogging) {
          console.log(`[EnhancedLoading] Found ${count} populated scenarios: ${selector}`);
        }
        
        // Verify scenarios have actual content
        const firstScenario = scenarios.first();
        await firstScenario.waitFor({ state: 'visible', timeout: timeout / 2 });
        
        // Check if scenario has meaningful content (not just placeholder text)
        const scenarioText = await firstScenario.textContent();
        if (scenarioText && scenarioText.trim().length > 10) {
          if (debugLogging) {
            console.log('[EnhancedLoading] Scenarios appear to have real content');
          }
          break;
        }
      }
    }
  }

  /**
   * Wait for connections to validate and show status
   */
  private async waitForConnectionsToValidate(page: Page, options: EnhancedLoadingOptions): Promise<void> {
    const { timeout = 20000, debugLogging = false } = options;
    
    const connectionSelectors = [
      '[data-testid="connections-list"] .connection-item:not(.skeleton)',
      '.connections-container .connection:not(.placeholder)',
      '.connection-card:not(.loading)',
      '[data-connection-status]:not([data-connection-status="loading"])'
    ];

    for (const selector of connectionSelectors) {
      const connections = page.locator(selector);
      const count = await connections.count();
      
      if (count > 0) {
        if (debugLogging) {
          console.log(`[EnhancedLoading] Found ${count} validated connections: ${selector}`);
        }
        
        await connections.first().waitFor({ state: 'visible', timeout: timeout / 2 });
        break;
      }
    }
  }

  /**
   * Wait for templates to load if applicable
   */
  private async waitForTemplatesToLoad(page: Page, options: EnhancedLoadingOptions): Promise<void> {
    const { timeout = 25000, debugLogging = false } = options;
    
    const templateSelectors = [
      '[data-testid="templates-list"] .template-item:not(.skeleton)',
      '.templates-container .template:not(.placeholder)',
      '.template-card:not(.loading)',
      '[data-template-id]:not([data-template-id=""])'
    ];

    for (const selector of templateSelectors) {
      const templates = page.locator(selector);
      const count = await templates.count();
      
      if (count > 0) {
        if (debugLogging) {
          console.log(`[EnhancedLoading] Found ${count} loaded templates: ${selector}`);
        }
        
        await templates.first().waitFor({ state: 'visible', timeout: timeout / 2 });
        break;
      }
    }
  }
}

// ==================== UTILITY FUNCTIONS ====================

/**
 * Create enhanced loading detection engine with default configuration
 */
export function createEnhancedLoadingEngine(): EnhancedLoadingDetectionEngine {
  return new EnhancedLoadingDetectionEngine();
}

/**
 * Enhanced wrapper for waitForElementsToLoad with intelligent detection
 */
export async function waitForElementsToLoadEnhanced(
  page: Page, 
  options: EnhancedLoadingOptions = {}
): Promise<LoadingDetectionResult> {
  const engine = createEnhancedLoadingEngine();
  return await engine.waitForElementsToLoad(page, {
    intelligentSelectors: true,
    performanceMonitoring: true,
    stressAwareLoading: true,
    ...options
  });
}

/**
 * Enhanced wrapper for waitForDashboardReady with comprehensive detection
 */
export async function waitForDashboardReadyEnhanced(
  page: Page, 
  options: DashboardLoadingOptions & EnhancedLoadingOptions = {}
): Promise<LoadingDetectionResult> {
  const engine = createEnhancedLoadingEngine();
  return await engine.waitForDashboardReady(page, {
    waitForCharts: true,
    waitForData: true,
    intelligentSelectors: true,
    performanceMonitoring: true,
    stressAwareLoading: true,
    ...options
  });
}

/**
 * Enhanced wrapper for waitForWorkflowsLoaded with comprehensive detection
 */
export async function waitForWorkflowsLoadedEnhanced(
  page: Page, 
  options: WorkflowLoadingOptions & EnhancedLoadingOptions = {}
): Promise<LoadingDetectionResult> {
  const engine = createEnhancedLoadingEngine();
  return await engine.waitForWorkflowsLoaded(page, {
    waitForScenarios: true,
    waitForConnections: true,
    intelligentSelectors: true,
    performanceMonitoring: true,
    stressAwareLoading: true,
    ...options
  });
}

/**
 * Run comprehensive loading detection across all page types
 */
export async function runComprehensiveLoadingDetection(
  page: Page, 
  options: EnhancedLoadingOptions = {}
): Promise<{
  elements: LoadingDetectionResult;
  dashboard?: LoadingDetectionResult;
  workflows?: LoadingDetectionResult;
  overall: {
    success: boolean;
    totalDuration: number;
    totalWarnings: string[];
    averageComplexity: string;
  };
}> {
  const engine = createEnhancedLoadingEngine();
  const startTime = Date.now();
  
  // Always run basic elements detection
  const elements = await engine.waitForElementsToLoad(page, options);
  
  const results: any = { elements };
  const allWarnings: string[] = [...elements.warnings];
  const complexities: string[] = [elements.contentComplexity];
  
  // Try dashboard detection if URL suggests dashboard
  const url = page.url().toLowerCase();
  if (url.includes('dashboard') || url.includes('analytics') || url.includes('performance')) {
    try {
      results.dashboard = await engine.waitForDashboardReady(page, options);
      allWarnings.push(...results.dashboard.warnings);
      complexities.push(results.dashboard.contentComplexity);
    } catch (error) {
      allWarnings.push(`Dashboard detection skipped: ${error.message}`);
    }
  }
  
  // Try workflow detection if URL suggests workflows
  if (url.includes('workflow') || url.includes('scenario') || url.includes('automation')) {
    try {
      results.workflows = await engine.waitForWorkflowsLoaded(page, options);
      allWarnings.push(...results.workflows.warnings);
      complexities.push(results.workflows.contentComplexity);
    } catch (error) {
      allWarnings.push(`Workflow detection skipped: ${error.message}`);
    }
  }
  
  // Calculate overall results
  const totalDuration = Date.now() - startTime;
  const successCount = Object.values(results).filter((r: any) => r.success).length;
  const totalChecks = Object.keys(results).length;
  
  const complexityMap = { low: 1, medium: 2, high: 3 };
  const avgComplexityValue = complexities.reduce((sum, c) => sum + complexityMap[c as keyof typeof complexityMap], 0) / complexities.length;
  const averageComplexity = avgComplexityValue < 1.5 ? 'low' : avgComplexityValue < 2.5 ? 'medium' : 'high';
  
  results.overall = {
    success: successCount === totalChecks,
    totalDuration,
    totalWarnings: allWarnings,
    averageComplexity
  };
  
  return results;
}

export default EnhancedLoadingDetectionEngine;