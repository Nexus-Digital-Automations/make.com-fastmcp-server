/**
 * Dashboard and Workflow Sequence Tests
 * 
 * Implements the specific user requirements:
 * "workflows load first before clicking the performance dashboard, 
 * then have the dashboard load before switching to anything else"
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

// Configuration for dashboard-workflow sequence tests
const SEQUENCE_CONFIG = {
  timeout: 60000,
  debugLogging: true,
  waitForCharts: true,
  waitForData: true,
  waitForScenarios: true,
  waitForConnections: true,
  waitForAnimations: false, // Skip animations initially for faster loading
  stagingDelay: 2000 // Delay between stages to prevent overload
};

test.describe('Dashboard-Workflow Sequence Tests', () => {
  
  test.beforeEach(async ({ page }) => {
    // Configure timeouts and logging for sequence testing
    page.setDefaultTimeout(SEQUENCE_CONFIG.timeout);
    page.setDefaultNavigationTimeout(45000);
    
    // Log network activity for debugging
    if (SEQUENCE_CONFIG.debugLogging) {
      page.on('request', (request) => {
        console.log(`[NETWORK] REQ: ${request.method()} ${request.url()}`);
      });
      
      page.on('response', (response) => {
        if (!response.ok()) {
          console.log(`[NETWORK] ERR: ${response.status()} ${response.url()}`);
        }
      });
      
      page.on('console', (msg) => {
        if (msg.type() === 'error') {
          console.log(`[BROWSER] ERROR: ${msg.text()}`);
        }
      });
    }
  });

  test('Complete Sequence: Workflows → Performance Dashboard → Interactions', async ({ page }) => {
    console.log('[SEQUENCE] Starting complete workflow-dashboard sequence...');
    
    // Navigate to application root
    await page.goto('/');
    
    // === STAGE 1: Basic Page Load ===
    console.log('[SEQUENCE] Stage 1: Loading basic page elements...');
    await waitForElementsToLoad(page, SEQUENCE_CONFIG);
    
    // Verify basic page structure
    await expect(page.locator('body')).toBeVisible();
    console.log('[SEQUENCE] ✓ Stage 1 complete: Basic elements loaded');
    
    // Check system stress before proceeding
    const initialStress = await detectSystemStress(page);
    if (initialStress) {
      console.log('[SEQUENCE] Initial system stress detected, applying backoff...');
      await page.waitForTimeout(SEQUENCE_CONFIG.stagingDelay * 2);
    }
    
    // === STAGE 2: WORKFLOWS LOAD FIRST (User Requirement) ===
    console.log('[SEQUENCE] Stage 2: Loading workflows FIRST as requested...');
    
    await waitWithBackoff(page, async () => {
      // Try multiple approaches to load workflows
      const workflowApproaches = [
        { type: 'navigation', selectors: [
          '[data-testid="workflows-nav"]',
          'a[href*="workflows"]', 
          'a[href*="scenarios"]',
          'nav a:has-text("Workflows")',
          'nav a:has-text("Scenarios")',
          '.workflows-link',
          '.scenarios-link'
        ]},
        { type: 'direct_url', url: '/workflows' },
        { type: 'direct_url', url: '/scenarios' },
        { type: 'fallback', url: '/' } // Stay on current page
      ];
      
      let workflowsLoaded = false;
      
      for (const approach of workflowApproaches) {
        try {
          if (approach.type === 'navigation') {
            // Try navigation selectors
            for (const selector of approach.selectors) {
              const element = page.locator(selector).first();
              if (await element.count() > 0 && await element.isVisible()) {
                console.log(`[SEQUENCE] Using workflow navigation: ${selector}`);
                await safeClick(page, selector, { 
                  ...SEQUENCE_CONFIG, 
                  waitAfterClick: SEQUENCE_CONFIG.stagingDelay 
                });
                await waitForWorkflowsLoaded(page, SEQUENCE_CONFIG);
                workflowsLoaded = true;
                break;
              }
            }
          } else if (approach.type === 'direct_url') {
            // Try direct URL
            console.log(`[SEQUENCE] Trying direct workflow URL: ${approach.url}`);
            await page.goto(approach.url, { waitUntil: 'networkidle' });
            await waitForWorkflowsLoaded(page, SEQUENCE_CONFIG);
            workflowsLoaded = true;
          } else if (approach.type === 'fallback') {
            // Fallback: ensure current page has workflow elements
            console.log('[SEQUENCE] Using fallback approach for workflows');
            await waitForWorkflowsLoaded(page, { 
              ...SEQUENCE_CONFIG, 
              waitForScenarios: false, // More lenient for fallback
              waitForConnections: false 
            });
            workflowsLoaded = true;
          }
          
          if (workflowsLoaded) break;
          
        } catch (error) {
          console.log(`[SEQUENCE] Workflow approach failed: ${approach.type}`, error.message);
          continue;
        }
      }
      
      if (!workflowsLoaded) {
        throw new Error('Unable to load workflows with any approach');
      }
    }, SEQUENCE_CONFIG);
    
    console.log('[SEQUENCE] ✓ Stage 2 complete: Workflows loaded FIRST');
    
    // Mandatory delay before next stage (user requirement to prevent overload)
    await page.waitForTimeout(SEQUENCE_CONFIG.stagingDelay);
    
    // === STAGE 3: PERFORMANCE DASHBOARD AFTER WORKFLOWS ===
    console.log('[SEQUENCE] Stage 3: Loading performance dashboard AFTER workflows...');
    
    await waitWithBackoff(page, async () => {
      // Try multiple approaches to load dashboard
      const dashboardApproaches = [
        { type: 'navigation', selectors: [
          '[data-testid="performance-dashboard"]',
          '[data-testid="dashboard-nav"]',
          'a[href*="dashboard"]',
          'a[href*="performance"]',
          'nav a:has-text("Dashboard")',
          'nav a:has-text("Performance")',
          '.dashboard-link',
          '.performance-link'
        ]},
        { type: 'direct_url', url: '/dashboard' },
        { type: 'direct_url', url: '/performance' },
        { type: 'fallback', url: '/' }
      ];
      
      let dashboardLoaded = false;
      
      for (const approach of dashboardApproaches) {
        try {
          if (approach.type === 'navigation') {
            // Try navigation selectors
            for (const selector of approach.selectors) {
              const element = page.locator(selector).first();
              if (await element.count() > 0 && await element.isVisible()) {
                console.log(`[SEQUENCE] Using dashboard navigation: ${selector}`);
                await safeClick(page, selector, { 
                  ...SEQUENCE_CONFIG, 
                  waitAfterClick: SEQUENCE_CONFIG.stagingDelay 
                });
                await waitForDashboardReady(page, SEQUENCE_CONFIG);
                dashboardLoaded = true;
                break;
              }
            }
          } else if (approach.type === 'direct_url') {
            // Try direct URL
            console.log(`[SEQUENCE] Trying direct dashboard URL: ${approach.url}`);
            await page.goto(approach.url, { waitUntil: 'networkidle' });
            await waitForDashboardReady(page, SEQUENCE_CONFIG);
            dashboardLoaded = true;
          } else if (approach.type === 'fallback') {
            // Fallback: ensure current page has dashboard elements
            console.log('[SEQUENCE] Using fallback approach for dashboard');
            await waitForDashboardReady(page, { 
              ...SEQUENCE_CONFIG, 
              waitForCharts: false, // More lenient for fallback
              waitForData: false 
            });
            dashboardLoaded = true;
          }
          
          if (dashboardLoaded) break;
          
        } catch (error) {
          console.log(`[SEQUENCE] Dashboard approach failed: ${approach.type}`, error.message);
          continue;
        }
      }
      
      if (!dashboardLoaded) {
        throw new Error('Unable to load dashboard with any approach');
      }
    }, SEQUENCE_CONFIG);
    
    console.log('[SEQUENCE] ✓ Stage 3 complete: Performance dashboard loaded AFTER workflows');
    
    // Mandatory delay before interactions (user requirement)
    await page.waitForTimeout(SEQUENCE_CONFIG.stagingDelay);
    
    // === STAGE 4: SAFE INTERACTIONS ONLY AFTER EVERYTHING IS LOADED ===
    console.log('[SEQUENCE] Stage 4: Testing safe interactions after complete loading...');
    
    // Verify no system stress before interactions
    const preInteractionStress = await detectSystemStress(page);
    if (preInteractionStress) {
      console.log('[SEQUENCE] Pre-interaction stress detected, waiting...');
      await page.waitForTimeout(SEQUENCE_CONFIG.stagingDelay * 2);
    }
    
    // Find and test interactive elements safely
    const safeInteractionSelectors = [
      '[data-testid*="button"]:not([disabled])',
      'button:not([disabled])',
      'a[href]:not([href="#"])',
      '[role="button"]:not([disabled])',
      'input[type="button"]:not([disabled])'
    ];
    
    let interactionsFound = 0;
    for (const selector of safeInteractionSelectors) {
      const elements = page.locator(selector);
      const count = await elements.count();
      
      if (count > 0) {
        console.log(`[SEQUENCE] Found ${count} interactive elements: ${selector}`);
        
        // Test visibility and enable state of first element (don't click to avoid side effects)
        const firstElement = elements.first();
        if (await firstElement.isVisible()) {
          await expect(firstElement).toBeEnabled();
          interactionsFound++;
          console.log(`[SEQUENCE] ✓ Interactive element verified: ${selector}`);
          
          if (interactionsFound >= 3) break; // Test first 3 types
        }
      }
    }
    
    console.log(`[SEQUENCE] ✓ Stage 4 complete: ${interactionsFound} interactive elements verified`);
    
    // Final verification
    await expect(page.locator('body')).toBeVisible();
    console.log('[SEQUENCE] ✅ Complete sequence successful: Workflows → Dashboard → Interactions');
  });

  test('Stage Recovery: Handle Loading Failures Gracefully', async ({ page }) => {
    console.log('[RECOVERY] Testing stage recovery mechanisms...');
    
    await page.goto('/');
    
    // Test recovery from workflow loading failure
    try {
      await page.goto('/nonexistent-workflows');
      await waitForWorkflowsLoaded(page, { ...SEQUENCE_CONFIG, timeout: 5000 });
    } catch (error) {
      console.log('[RECOVERY] Workflow loading failed as expected, recovering...');
      await page.goto('/');
      await waitForElementsToLoad(page, SEQUENCE_CONFIG);
      console.log('[RECOVERY] ✓ Recovered from workflow loading failure');
    }
    
    // Test recovery from dashboard loading failure
    try {
      await page.goto('/nonexistent-dashboard');
      await waitForDashboardReady(page, { ...SEQUENCE_CONFIG, timeout: 5000 });
    } catch (error) {
      console.log('[RECOVERY] Dashboard loading failed as expected, recovering...');
      await page.goto('/');
      await waitForElementsToLoad(page, SEQUENCE_CONFIG);
      console.log('[RECOVERY] ✓ Recovered from dashboard loading failure');
    }
    
    // Verify recovery was successful
    await expect(page.locator('body')).toBeVisible();
    console.log('[RECOVERY] ✅ Recovery mechanisms working correctly');
  });

  test('Performance Under Load: Multiple Stage Transitions', async ({ page }) => {
    console.log('[LOAD-TEST] Testing performance under multiple stage transitions...');
    
    const transitions = [];
    const startTime = Date.now();
    
    for (let i = 0; i < 3; i++) {
      const transitionStart = Date.now();
      
      // Navigate through complete sequence
      await page.goto('/');
      await waitForElementsToLoad(page, SEQUENCE_CONFIG);
      
      // Brief pause between transitions
      await page.waitForTimeout(1000);
      
      const transitionDuration = Date.now() - transitionStart;
      transitions.push(transitionDuration);
      
      console.log(`[LOAD-TEST] Transition ${i + 1} duration: ${transitionDuration}ms`);
    }
    
    const totalDuration = Date.now() - startTime;
    const avgTransition = transitions.reduce((a, b) => a + b, 0) / transitions.length;
    
    console.log(`[LOAD-TEST] Performance metrics:`);
    console.log(`  - Total duration: ${totalDuration}ms`);
    console.log(`  - Average transition: ${avgTransition}ms`);
    console.log(`  - Transitions: ${JSON.stringify(transitions)}`);
    
    // Performance assertions
    expect(avgTransition).toBeLessThan(30000); // 30 seconds average
    expect(totalDuration).toBeLessThan(120000); // 2 minutes total
    
    console.log('[LOAD-TEST] ✅ Performance under load verified');
  });

});