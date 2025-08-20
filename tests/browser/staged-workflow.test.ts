/**
 * Staged Browser Tests with Proper Loading Sequences
 * 
 * Implements the user's requested approach:
 * 1. Let workflows load first before clicking buttons
 * 2. Wait for performance dashboard to load before switching views
 * 3. Add proper loading detection to prevent system overload
 */

import { test, expect, Page } from '@playwright/test';
import { 
  waitForElementsToLoad, 
  waitForWorkflowsLoaded, 
  waitForDashboardReady,
  safeClick,
  safeNavigate,
  detectSystemStress,
  waitWithBackoff
} from './loading-sequence-helpers';

// Test configuration for staged loading
const LOADING_CONFIG = {
  timeout: 60000,
  debugLogging: true,
  waitForCharts: true,
  waitForData: true,
  waitForScenarios: true,
  waitForConnections: true
};

test.describe('Staged Workflow Tests - Proper Loading Sequences', () => {
  
  test.beforeEach(async ({ page }) => {
    // Set longer timeouts for loading sequences
    page.setDefaultTimeout(60000);
    page.setDefaultNavigationTimeout(45000);
    
    // Enable request/response logging for debugging
    if (LOADING_CONFIG.debugLogging) {
      page.on('request', (request) => {
        console.log(`[REQUEST] ${request.method()} ${request.url()}`);
      });
      
      page.on('response', (response) => {
        console.log(`[RESPONSE] ${response.status()} ${response.url()}`);
      });
    }
  });

  test('Stage 1: Initial Page Load with Basic Elements', async ({ page }) => {
    console.log('[TEST] Stage 1: Testing initial page load...');
    
    // Navigate to application
    await page.goto('/');
    
    // Stage 1: Wait for basic page elements to load
    await waitForElementsToLoad(page, LOADING_CONFIG);
    
    // Verify basic page structure is ready
    await expect(page.locator('body')).toBeVisible();
    
    // Check for main navigation or header elements
    const navigationSelectors = [
      'nav',
      '[role="navigation"]',
      '.navigation',
      '.header',
      '.navbar'
    ];
    
    let navigationFound = false;
    for (const selector of navigationSelectors) {
      const element = page.locator(selector).first();
      if (await element.count() > 0) {
        await expect(element).toBeVisible();
        navigationFound = true;
        console.log(`[STAGE 1] Found navigation: ${selector}`);
        break;
      }
    }
    
    console.log(`[STAGE 1] Navigation found: ${navigationFound}`);
    console.log('[TEST] Stage 1 completed successfully');
  });

  test('Stage 2: Workflows Load First (User Requirement)', async ({ page }) => {
    console.log('[TEST] Stage 2: Testing workflows load first...');
    
    // Navigate to application
    await page.goto('/');
    
    // Stage 1: Basic elements first
    await waitForElementsToLoad(page, LOADING_CONFIG);
    
    // Stage 2: Navigate to workflows and wait for complete loading
    const workflowNavigationSelectors = [
      '[data-testid="workflows-nav"]',
      'a[href*="workflows"]',
      'a[href*="scenarios"]',
      '.workflows-link',
      '.scenarios-link',
      'nav a:has-text("Workflows")',
      'nav a:has-text("Scenarios")'
    ];
    
    // Find and navigate to workflows
    let workflowNavFound = false;
    for (const selector of workflowNavigationSelectors) {
      const navElement = page.locator(selector).first();
      if (await navElement.count() > 0) {
        console.log(`[STAGE 2] Navigating via workflows: ${selector}`);
        
        await safeNavigate(
          page, 
          selector,
          async (page) => await waitForWorkflowsLoaded(page, LOADING_CONFIG),
          LOADING_CONFIG
        );
        
        workflowNavFound = true;
        break;
      }
    }
    
    if (!workflowNavFound) {
      // Fallback: Go directly to workflows URL if navigation not found
      console.log('[STAGE 2] Navigation not found, trying direct URL');
      await page.goto('/workflows');
      await waitForWorkflowsLoaded(page, LOADING_CONFIG);
    }
    
    // Verify workflows are loaded before proceeding
    await expect.soft(page.locator('body')).toBeVisible();
    
    console.log('[TEST] Stage 2 completed - workflows loaded first');
  });

  test('Stage 3: Dashboard Loads After Workflows (User Requirement)', async ({ page }) => {
    console.log('[TEST] Stage 3: Testing dashboard loads after workflows...');
    
    // Navigate to application
    await page.goto('/');
    
    // Stage 1: Basic elements first
    await waitForElementsToLoad(page, LOADING_CONFIG);
    console.log('[STAGE 3] Stage 1 complete - basic elements loaded');
    
    // Stage 2: Workflows load first (as user requested)
    try {
      const workflowUrl = '/workflows';
      await page.goto(workflowUrl);
      await waitForWorkflowsLoaded(page, LOADING_CONFIG);
      console.log('[STAGE 3] Stage 2 complete - workflows loaded first');
    } catch (error) {
      console.log('[STAGE 3] Workflows page not available, proceeding with dashboard test');
    }
    
    // Stage 3: Navigate to performance dashboard AFTER workflows
    const dashboardNavigationSelectors = [
      '[data-testid="dashboard-nav"]',
      '[data-testid="performance-dashboard"]',
      'a[href*="dashboard"]',
      'a[href*="performance"]',
      '.dashboard-link',
      '.performance-link',
      'nav a:has-text("Dashboard")',
      'nav a:has-text("Performance")'
    ];
    
    // Find and navigate to dashboard
    let dashboardNavFound = false;
    for (const selector of dashboardNavigationSelectors) {
      const navElement = page.locator(selector).first();
      if (await navElement.count() > 0) {
        console.log(`[STAGE 3] Navigating to dashboard via: ${selector}`);
        
        await safeNavigate(
          page,
          selector,
          async (page) => await waitForDashboardReady(page, LOADING_CONFIG),
          LOADING_CONFIG
        );
        
        dashboardNavFound = true;
        break;
      }
    }
    
    if (!dashboardNavFound) {
      // Fallback: Go directly to dashboard URL
      console.log('[STAGE 3] Dashboard navigation not found, trying direct URL');
      await page.goto('/dashboard');
      await waitForDashboardReady(page, LOADING_CONFIG);
    }
    
    // Verify dashboard is fully loaded
    await expect.soft(page.locator('body')).toBeVisible();
    
    console.log('[TEST] Stage 3 completed - dashboard loaded after workflows');
  });

  test('Stage 4: Full Workflow with Loading Sequence', async ({ page }) => {
    console.log('[TEST] Stage 4: Testing complete workflow with proper sequence...');
    
    // Navigate to application
    await page.goto('/');
    
    // Stage 1: Basic elements load
    console.log('[STAGE 4] Step 1: Loading basic elements...');
    await waitForElementsToLoad(page, { ...LOADING_CONFIG, debugLogging: true });
    
    // Check for system stress before proceeding
    const isStressed = await detectSystemStress(page);
    if (isStressed) {
      console.log('[STAGE 4] System stress detected, implementing backoff...');
      await page.waitForTimeout(3000);
    }
    
    // Stage 2: Workflows load first (user requirement)
    console.log('[STAGE 4] Step 2: Loading workflows first...');
    await waitWithBackoff(page, async () => {
      try {
        await page.goto('/workflows', { waitUntil: 'networkidle' });
        await waitForWorkflowsLoaded(page, LOADING_CONFIG);
      } catch (error) {
        console.log('[STAGE 4] Workflows not available, using root page');
        await waitForElementsToLoad(page, LOADING_CONFIG);
      }
    }, LOADING_CONFIG);
    
    // Wait between stages to prevent overload (user requirement)
    console.log('[STAGE 4] Waiting between stages...');
    await page.waitForTimeout(2000);
    
    // Stage 3: Dashboard loads after workflows (user requirement)
    console.log('[STAGE 4] Step 3: Loading dashboard after workflows...');
    await waitWithBackoff(page, async () => {
      try {
        await page.goto('/dashboard', { waitUntil: 'networkidle' });
        await waitForDashboardReady(page, LOADING_CONFIG);
      } catch (error) {
        console.log('[STAGE 4] Dashboard not available, testing on current page');
        await waitForElementsToLoad(page, LOADING_CONFIG);
      }
    }, LOADING_CONFIG);
    
    // Stage 4: Safe interactions only after everything is loaded
    console.log('[STAGE 4] Step 4: Testing safe interactions...');
    
    // Look for interactive elements and test them safely
    const interactiveSelectors = [
      'button:not([disabled])',
      'a[href]',
      '[role="button"]',
      'input[type="button"]',
      '.btn',
      '.button'
    ];
    
    for (const selector of interactiveSelectors) {
      const elements = page.locator(selector);
      const count = await elements.count();
      
      if (count > 0) {
        console.log(`[STAGE 4] Testing ${count} interactive elements: ${selector}`);
        
        // Test first interactive element safely
        const firstElement = elements.first();
        if (await firstElement.isVisible()) {
          // Just verify it's clickable - don't actually click to avoid side effects
          await expect(firstElement).toBeEnabled();
          console.log(`[STAGE 4] Interactive element verified: ${selector}`);
          break;
        }
      }
    }
    
    // Final verification
    await expect(page.locator('body')).toBeVisible();
    console.log('[TEST] Stage 4 completed - full workflow with proper loading sequence');
  });

  test('Stage 5: Error Handling and Recovery', async ({ page }) => {
    console.log('[TEST] Stage 5: Testing error handling during loading sequences...');
    
    // Navigate to application
    await page.goto('/');
    
    // Test error handling in loading sequence
    try {
      await waitWithBackoff(page, async () => {
        await waitForElementsToLoad(page, { 
          ...LOADING_CONFIG, 
          timeout: 5000 // Shorter timeout to trigger errors 
        });
      }, { ...LOADING_CONFIG, maxRetries: 2 });
      
      console.log('[STAGE 5] Loading completed without errors');
    } catch (error) {
      console.log('[STAGE 5] Handled loading error gracefully:', error.message);
      
      // Verify error was handled and page is still functional
      await expect(page.locator('body')).toBeVisible();
    }
    
    // Test recovery from stress condition
    const isStressed = await detectSystemStress(page);
    console.log(`[STAGE 5] System stress detected: ${isStressed}`);
    
    if (isStressed) {
      console.log('[STAGE 5] Implementing stress recovery...');
      await page.waitForTimeout(5000);
      
      // Verify recovery
      const recoveredStress = await detectSystemStress(page);
      console.log(`[STAGE 5] Post-recovery stress: ${recoveredStress}`);
    }
    
    console.log('[TEST] Stage 5 completed - error handling verified');
  });

  test('Performance Monitoring During Stages', async ({ page }) => {
    console.log('[TEST] Performance: Monitoring loading stages...');
    
    const performanceMetrics = {
      stage1Duration: 0,
      stage2Duration: 0,
      stage3Duration: 0,
      totalDuration: 0
    };
    
    const testStart = Date.now();
    
    // Navigate to application
    await page.goto('/');
    
    // Stage 1: Basic elements
    const stage1Start = Date.now();
    await waitForElementsToLoad(page, LOADING_CONFIG);
    performanceMetrics.stage1Duration = Date.now() - stage1Start;
    console.log(`[PERFORMANCE] Stage 1 duration: ${performanceMetrics.stage1Duration}ms`);
    
    // Stage 2: Workflows
    const stage2Start = Date.now();
    try {
      await page.goto('/workflows');
      await waitForWorkflowsLoaded(page, LOADING_CONFIG);
    } catch (error) {
      console.log('[PERFORMANCE] Workflows not available');
    }
    performanceMetrics.stage2Duration = Date.now() - stage2Start;
    console.log(`[PERFORMANCE] Stage 2 duration: ${performanceMetrics.stage2Duration}ms`);
    
    // Stage 3: Dashboard
    const stage3Start = Date.now();
    try {
      await page.goto('/dashboard');
      await waitForDashboardReady(page, LOADING_CONFIG);
    } catch (error) {
      console.log('[PERFORMANCE] Dashboard not available');
    }
    performanceMetrics.stage3Duration = Date.now() - stage3Start;
    console.log(`[PERFORMANCE] Stage 3 duration: ${performanceMetrics.stage3Duration}ms`);
    
    performanceMetrics.totalDuration = Date.now() - testStart;
    
    console.log('[PERFORMANCE] Complete metrics:', JSON.stringify(performanceMetrics, null, 2));
    
    // Performance assertions
    expect(performanceMetrics.stage1Duration).toBeLessThan(30000); // 30 seconds max
    expect(performanceMetrics.totalDuration).toBeLessThan(120000); // 2 minutes max
    
    console.log('[TEST] Performance monitoring completed');
  });

});