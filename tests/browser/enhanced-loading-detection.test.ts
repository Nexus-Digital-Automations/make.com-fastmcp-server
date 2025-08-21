/**
 * Enhanced Loading Detection System Tests
 * 
 * Comprehensive test suite for the enhanced loading detection utilities,
 * validating intelligent selector detection, performance monitoring,
 * adaptive timing, and stress-aware loading mechanisms.
 */

import { test, expect, Page } from '@playwright/test';
import {
  EnhancedLoadingDetectionEngine,
  createEnhancedLoadingEngine,
  waitForElementsToLoadEnhanced,
  waitForDashboardReadyEnhanced,
  waitForWorkflowsLoadedEnhanced,
  runComprehensiveLoadingDetection,
  type LoadingDetectionResult,
  type EnhancedLoadingOptions
} from '../utils/enhanced-loading-detection';

// Test configuration
const ENHANCED_LOADING_CONFIG: EnhancedLoadingOptions = {
  timeout: 60000,
  debugLogging: true,
  intelligentSelectors: true,
  performanceMonitoring: true,
  adaptiveTimeout: true,
  stressAwareLoading: true,
  minContentThreshold: 1
};

test.describe('Enhanced Loading Detection System', () => {
  
  test.beforeEach(async ({ page }) => {
    // Set reasonable timeouts for enhanced detection
    page.setDefaultTimeout(60000);
    page.setDefaultNavigationTimeout(45000);
  });

  test('Enhanced Elements Loading Detection - Basic Functionality', async ({ page }) => {
    console.log('[TEST] Testing enhanced elements loading detection...');
    
    await page.goto('/');
    
    const result = await waitForElementsToLoadEnhanced(page, ENHANCED_LOADING_CONFIG);
    
    // Validate result structure
    expect(result).toHaveProperty('success');
    expect(result).toHaveProperty('duration');
    expect(result).toHaveProperty('stagesCompleted');
    expect(result).toHaveProperty('warnings');
    expect(result).toHaveProperty('contentComplexity');
    
    // Validate success and performance
    expect(result.success).toBe(true);
    expect(result.duration).toBeGreaterThan(0);
    expect(result.stagesCompleted.length).toBeGreaterThanOrEqual(3);
    
    // Validate content complexity analysis
    expect(['low', 'medium', 'high']).toContain(result.contentComplexity);
    
    console.log('[TEST] Enhanced elements loading result:', {
      success: result.success,
      duration: result.duration,
      stages: result.stagesCompleted,
      complexity: result.contentComplexity,
      warnings: result.warnings.length
    });
    
    expect(result.success).toBe(true);
  });

  test('Enhanced Dashboard Loading Detection', async ({ page }) => {
    console.log('[TEST] Testing enhanced dashboard loading detection...');
    
    await page.goto('/');
    
    try {
      // Try to navigate to dashboard
      await page.goto('/dashboard');
      
      const result = await waitForDashboardReadyEnhanced(page, {
        ...ENHANCED_LOADING_CONFIG,
        waitForCharts: true,
        waitForData: true,
        waitForAnimations: false
      });
      
      // Validate dashboard-specific detection
      expect(result.success).toBe(true);
      expect(result.stagesCompleted).toContain('basic-dashboard');
      expect(result.contentComplexity).toBe('high'); // Dashboards should be high complexity
      
      // Validate performance monitoring was enabled
      if (result.metrics) {
        expect(result.metrics).toHaveProperty('totalExecutionTime');
        expect(result.metrics).toHaveProperty('networkMetrics');
      }
      
      console.log('[TEST] Enhanced dashboard loading result:', {
        success: result.success,
        duration: result.duration,
        stages: result.stagesCompleted,
        hasMetrics: !!result.metrics,
        warnings: result.warnings.length
      });
      
    } catch (error) {
      console.log('[TEST] Dashboard not available, testing on root page');
      
      // Fallback test on root page
      const result = await waitForDashboardReadyEnhanced(page, ENHANCED_LOADING_CONFIG);
      
      // Should still succeed with fallback mechanisms
      expect(result.success).toBe(true);
      expect(result.warnings.length).toBeGreaterThan(0); // Should have fallback warnings
    }
  });

  test('Enhanced Workflow Loading Detection', async ({ page }) => {
    console.log('[TEST] Testing enhanced workflow loading detection...');
    
    await page.goto('/');
    
    try {
      // Try to navigate to workflows
      await page.goto('/workflows');
      
      const result = await waitForWorkflowsLoadedEnhanced(page, {
        ...ENHANCED_LOADING_CONFIG,
        waitForScenarios: true,
        waitForConnections: true,
        waitForTemplates: false
      });
      
      // Validate workflow-specific detection
      expect(result.success).toBe(true);
      expect(result.stagesCompleted).toContain('basic-workflows');
      
      console.log('[TEST] Enhanced workflow loading result:', {
        success: result.success,
        duration: result.duration,
        stages: result.stagesCompleted,
        complexity: result.contentComplexity,
        warnings: result.warnings.length
      });
      
    } catch (error) {
      console.log('[TEST] Workflows not available, testing on root page');
      
      // Fallback test on root page
      const result = await waitForWorkflowsLoadedEnhanced(page, ENHANCED_LOADING_CONFIG);
      
      // Should still succeed with fallback mechanisms
      expect(result.success).toBe(true);
      expect(result.warnings.length).toBeGreaterThan(0); // Should have fallback warnings
    }
  });

  test('Comprehensive Loading Detection - All Page Types', async ({ page }) => {
    console.log('[TEST] Testing comprehensive loading detection across all page types...');
    
    await page.goto('/');
    
    const results = await runComprehensiveLoadingDetection(page, ENHANCED_LOADING_CONFIG);
    
    // Validate overall structure
    expect(results).toHaveProperty('elements');
    expect(results).toHaveProperty('overall');
    
    // Validate elements detection (always present)
    expect(results.elements.success).toBe(true);
    expect(results.elements.stagesCompleted.length).toBeGreaterThanOrEqual(3);
    
    // Validate overall summary
    expect(results.overall).toHaveProperty('success');
    expect(results.overall).toHaveProperty('totalDuration');
    expect(results.overall).toHaveProperty('totalWarnings');
    expect(results.overall).toHaveProperty('averageComplexity');
    
    expect(results.overall.totalDuration).toBeGreaterThan(0);
    expect(['low', 'medium', 'high']).toContain(results.overall.averageComplexity);
    
    console.log('[TEST] Comprehensive loading results:', {
      elementsSuccess: results.elements.success,
      dashboardTested: !!results.dashboard,
      workflowsTested: !!results.workflows,
      overallSuccess: results.overall.success,
      totalDuration: results.overall.totalDuration,
      totalWarnings: results.overall.totalWarnings.length,
      averageComplexity: results.overall.averageComplexity
    });
    
    expect(results.overall.success).toBe(true);
  });

  test('Intelligent Selector Detection', async ({ page }) => {
    console.log('[TEST] Testing intelligent selector detection...');
    
    await page.goto('/');
    
    const engine = createEnhancedLoadingEngine();
    
    // Test with intelligent selectors enabled
    const resultWithIntelligent = await engine.waitForElementsToLoad(page, {
      ...ENHANCED_LOADING_CONFIG,
      intelligentSelectors: true
    });
    
    // Test with intelligent selectors disabled
    const resultWithoutIntelligent = await engine.waitForElementsToLoad(page, {
      ...ENHANCED_LOADING_CONFIG,
      intelligentSelectors: false
    });
    
    // Both should succeed
    expect(resultWithIntelligent.success).toBe(true);
    expect(resultWithoutIntelligent.success).toBe(true);
    
    // Intelligent selectors should potentially complete more stages
    expect(resultWithIntelligent.stagesCompleted.length).toBeGreaterThanOrEqual(
      resultWithoutIntelligent.stagesCompleted.length
    );
    
    console.log('[TEST] Intelligent selector comparison:', {
      withIntelligent: {
        stages: resultWithIntelligent.stagesCompleted.length,
        duration: resultWithIntelligent.duration
      },
      withoutIntelligent: {
        stages: resultWithoutIntelligent.stagesCompleted.length,
        duration: resultWithoutIntelligent.duration
      }
    });
  });

  test('Performance Monitoring Integration', async ({ page }) => {
    console.log('[TEST] Testing performance monitoring integration...');
    
    await page.goto('/');
    
    const result = await waitForElementsToLoadEnhanced(page, {
      ...ENHANCED_LOADING_CONFIG,
      performanceMonitoring: true
    });
    
    expect(result.success).toBe(true);
    expect(result.stagesCompleted).toContain('performance-monitoring');
    
    // Validate performance metrics
    if (result.metrics) {
      expect(result.metrics).toHaveProperty('totalExecutionTime');
      expect(result.metrics).toHaveProperty('stageTimings');
      expect(result.metrics).toHaveProperty('networkMetrics');
      
      expect(result.metrics.totalExecutionTime).toBeGreaterThan(0);
      expect(typeof result.metrics.networkMetrics.totalRequests).toBe('number');
      
      console.log('[TEST] Performance metrics collected:', {
        totalTime: result.metrics.totalExecutionTime,
        stages: Object.keys(result.metrics.stageTimings).length,
        networkRequests: result.metrics.networkMetrics.totalRequests,
        stressEvents: result.metrics.stressEvents.length
      });
    }
  });

  test('Stress-Aware Loading Detection', async ({ page }) => {
    console.log('[TEST] Testing stress-aware loading detection...');
    
    await page.goto('/');
    
    const result = await waitForElementsToLoadEnhanced(page, {
      ...ENHANCED_LOADING_CONFIG,
      stressAwareLoading: true
    });
    
    expect(result.success).toBe(true);
    expect(result.stagesCompleted).toContain('stress-detection');
    
    // Validate stress indicators
    if (result.stressIndicators) {
      expect(result.stressIndicators).toHaveProperty('stressLevel');
      expect(result.stressIndicators).toHaveProperty('slowResponses');
      expect(result.stressIndicators).toHaveProperty('memoryPressure');
      expect(result.stressIndicators).toHaveProperty('errorRateHigh');
      
      expect(typeof result.stressIndicators.stressLevel).toBe('number');
      expect(result.stressIndicators.stressLevel).toBeGreaterThanOrEqual(0);
      expect(result.stressIndicators.stressLevel).toBeLessThanOrEqual(1);
      
      console.log('[TEST] Stress indicators detected:', {
        stressLevel: result.stressIndicators.stressLevel,
        slowResponses: result.stressIndicators.slowResponses,
        memoryPressure: result.stressIndicators.memoryPressure,
        errorRateHigh: result.stressIndicators.errorRateHigh
      });
    }
  });

  test('Content Complexity Analysis', async ({ page }) => {
    console.log('[TEST] Testing content complexity analysis...');
    
    await page.goto('/');
    
    const engine = createEnhancedLoadingEngine();
    const result = await engine.waitForElementsToLoad(page, ENHANCED_LOADING_CONFIG);
    
    expect(result.success).toBe(true);
    expect(['low', 'medium', 'high']).toContain(result.contentComplexity);
    expect(result.stagesCompleted).toContain('complexity-analysis');
    
    console.log('[TEST] Content complexity analysis:', {
      complexity: result.contentComplexity,
      stages: result.stagesCompleted.length,
      duration: result.duration
    });
    
    // Content complexity should influence loading strategy
    if (result.contentComplexity === 'high') {
      // High complexity pages might take longer
      expect(result.duration).toBeGreaterThan(1000); // At least 1 second
    }
  });

  test('Error Handling and Graceful Degradation', async ({ page }) => {
    console.log('[TEST] Testing error handling and graceful degradation...');
    
    await page.goto('/');
    
    // Test with very short timeout to trigger errors
    const result = await waitForElementsToLoadEnhanced(page, {
      ...ENHANCED_LOADING_CONFIG,
      timeout: 100, // Very short timeout
      maxRetries: 1
    });
    
    // Should either succeed or gracefully degrade
    if (!result.success) {
      expect(result.warnings.length).toBeGreaterThan(0);
      expect(result.warnings.some(w => w.includes('Fallback'))).toBe(true);
    }
    
    console.log('[TEST] Error handling result:', {
      success: result.success,
      warnings: result.warnings.length,
      stages: result.stagesCompleted.length,
      duration: result.duration
    });
    
    // Should complete some stages even with errors
    expect(result.stagesCompleted.length).toBeGreaterThan(0);
  });

  test('Custom Loading Selectors', async ({ page }) => {
    console.log('[TEST] Testing custom loading selectors...');
    
    await page.goto('/');
    
    const result = await waitForElementsToLoadEnhanced(page, {
      ...ENHANCED_LOADING_CONFIG,
      customLoadingSelectors: [
        '.custom-loader',
        '[data-custom-loading="true"]',
        '.my-spinner'
      ],
      customContentSelectors: [
        '.custom-content',
        '[data-content-loaded="true"]',
        '.my-data-container'
      ]
    });
    
    expect(result.success).toBe(true);
    
    console.log('[TEST] Custom selectors result:', {
      success: result.success,
      stages: result.stagesCompleted,
      warnings: result.warnings.length
    });
  });

  test('Adaptive Timeout Behavior', async ({ page }) => {
    console.log('[TEST] Testing adaptive timeout behavior...');
    
    await page.goto('/');
    
    const engine = createEnhancedLoadingEngine();
    
    // Test with adaptive timeout enabled
    const adaptiveResult = await engine.waitForElementsToLoad(page, {
      ...ENHANCED_LOADING_CONFIG,
      adaptiveTimeout: true,
      timeout: 30000
    });
    
    // Test with fixed timeout
    const fixedResult = await engine.waitForElementsToLoad(page, {
      ...ENHANCED_LOADING_CONFIG,
      adaptiveTimeout: false,
      timeout: 30000
    });
    
    expect(adaptiveResult.success).toBe(true);
    expect(fixedResult.success).toBe(true);
    
    console.log('[TEST] Adaptive timeout comparison:', {
      adaptive: {
        duration: adaptiveResult.duration,
        complexity: adaptiveResult.contentComplexity
      },
      fixed: {
        duration: fixedResult.duration,
        complexity: fixedResult.contentComplexity
      }
    });
  });

  test('Integration with Existing Loading Helpers', async ({ page }) => {
    console.log('[TEST] Testing integration with existing loading helpers...');
    
    await page.goto('/');
    
    // Import existing helpers for comparison
    const { 
      waitForElementsToLoad,
      waitForDashboardReady,
      waitForWorkflowsLoaded
    } = await import('../browser/loading-sequence-helpers');
    
    // Test enhanced vs original helpers
    const startTime = Date.now();
    
    // Original helper
    await waitForElementsToLoad(page, { timeout: 30000, debugLogging: false });
    const originalDuration = Date.now() - startTime;
    
    // Enhanced helper
    const enhancedStart = Date.now();
    const enhancedResult = await waitForElementsToLoadEnhanced(page, {
      timeout: 30000,
      debugLogging: false,
      performanceMonitoring: false // Disable for fair comparison
    });
    const enhancedDuration = Date.now() - enhancedStart;
    
    expect(enhancedResult.success).toBe(true);
    
    console.log('[TEST] Helper integration comparison:', {
      original: { duration: originalDuration },
      enhanced: { 
        duration: enhancedDuration,
        success: enhancedResult.success,
        stages: enhancedResult.stagesCompleted.length,
        complexity: enhancedResult.contentComplexity
      }
    });
    
    // Enhanced helper should provide additional insights
    expect(enhancedResult.stagesCompleted.length).toBeGreaterThan(0);
    expect(['low', 'medium', 'high']).toContain(enhancedResult.contentComplexity);
  });

});

test.describe('Enhanced Loading Detection - Edge Cases', () => {
  
  test('Handle Pages with No Loading Indicators', async ({ page }) => {
    console.log('[TEST] Testing pages with no loading indicators...');
    
    // Create a simple static page
    await page.goto('data:text/html,<html><body><h1>Static Page</h1><p>No loading indicators here</p></body></html>');
    
    const result = await waitForElementsToLoadEnhanced(page, ENHANCED_LOADING_CONFIG);
    
    expect(result.success).toBe(true);
    expect(result.contentComplexity).toBe('low');
    expect(result.duration).toBeLessThan(10000); // Should be fast for static content
    
    console.log('[TEST] Static page result:', {
      success: result.success,
      complexity: result.contentComplexity,
      duration: result.duration,
      stages: result.stagesCompleted
    });
  });

  test('Handle Network Timeouts Gracefully', async ({ page }) => {
    console.log('[TEST] Testing network timeout handling...');
    
    try {
      // Try to navigate to non-existent URL
      await page.goto('http://non-existent-domain-12345.com', { timeout: 5000 });
    } catch (error) {
      console.log('[TEST] Expected navigation failure for timeout test');
    }
    
    // Go to a valid page for the actual test
    await page.goto('/');
    
    const result = await waitForElementsToLoadEnhanced(page, {
      ...ENHANCED_LOADING_CONFIG,
      timeout: 5000 // Short timeout to test resilience
    });
    
    // Should handle timeouts gracefully
    expect(result.stagesCompleted.length).toBeGreaterThan(0);
    
    console.log('[TEST] Timeout handling result:', {
      success: result.success,
      warnings: result.warnings.length,
      stages: result.stagesCompleted
    });
  });

  test('Performance Under High Element Count', async ({ page }) => {
    console.log('[TEST] Testing performance under high element count...');
    
    // Create a page with many elements
    const highContentHtml = `
      <html><body>
        <div class="container">
          ${Array.from({ length: 1000 }, (_, i) => 
            `<div class="item-${i}">Content item ${i}</div>`
          ).join('')}
        </div>
      </body></html>
    `;
    
    await page.goto(`data:text/html,${encodeURIComponent(highContentHtml)}`);
    
    const result = await waitForElementsToLoadEnhanced(page, ENHANCED_LOADING_CONFIG);
    
    expect(result.success).toBe(true);
    expect(result.contentComplexity).toBe('high'); // Should detect high complexity
    
    console.log('[TEST] High element count result:', {
      success: result.success,
      complexity: result.contentComplexity,
      duration: result.duration,
      stages: result.stagesCompleted.length
    });
    
    // Should complete within reasonable time despite high element count
    expect(result.duration).toBeLessThan(60000); // Less than 1 minute
  });

});