/**
 * Browser Test Loading Sequence Helpers
 * 
 * Implements proper loading detection and waiting mechanisms for browser tests
 * to prevent race conditions and system overload during UI testing.
 */

import type { Page, Locator } from '@playwright/test';

export interface LoadingOptions {
  timeout?: number;
  checkInterval?: number;
  maxRetries?: number;
  debugLogging?: boolean;
}

export interface DashboardLoadingOptions extends LoadingOptions {
  waitForCharts?: boolean;
  waitForData?: boolean;
  waitForAnimations?: boolean;
}

export interface WorkflowLoadingOptions extends LoadingOptions {
  waitForScenarios?: boolean;
  waitForConnections?: boolean;
  waitForTemplates?: boolean;
}

/**
 * Wait for all basic page elements to load
 */
export async function waitForElementsToLoad(
  page: Page, 
  options: LoadingOptions = {}
): Promise<void> {
  const { 
    timeout = 30000, 
    checkInterval = 100, 
    maxRetries = 3,
    debugLogging = false 
  } = options;

  if (debugLogging) {
    console.log('[LoadingHelper] Starting waitForElementsToLoad...');
  }

  // Wait for basic page load
  await page.waitForLoadState('load', { timeout });
  
  // Wait for network to be idle (no requests for 500ms)
  await page.waitForLoadState('networkidle', { timeout });
  
  // Check for common loading indicators and wait for them to disappear
  const loadingSelectors = [
    '[data-testid="loading-spinner"]',
    '.loading-spinner',
    '.spinner',
    '.loader',
    '[data-loading="true"]',
    '.skeleton-loader',
    '.loading-overlay'
  ];

  for (let retry = 0; retry < maxRetries; retry++) {
    try {
      // Wait for all loading indicators to disappear
      for (const selector of loadingSelectors) {
        const loadingElements = page.locator(selector);
        const count = await loadingElements.count();
        
        if (count > 0) {
          if (debugLogging) {
            console.log(`[LoadingHelper] Waiting for ${count} loading elements: ${selector}`);
          }
          await loadingElements.first().waitFor({ state: 'hidden', timeout: timeout / 2 });
        }
      }

      // Wait for main content area to be visible
      const mainContentSelectors = [
        'main',
        '[data-testid="main-content"]', 
        '.main-content',
        '#app',
        '.app-container'
      ];

      for (const selector of mainContentSelectors) {
        const element = page.locator(selector).first();
        if (await element.count() > 0) {
          await element.waitFor({ state: 'visible', timeout: timeout / 2 });
          if (debugLogging) {
            console.log(`[LoadingHelper] Main content loaded: ${selector}`);
          }
          break;
        }
      }

      if (debugLogging) {
        console.log('[LoadingHelper] waitForElementsToLoad completed successfully');
      }
      return;

    } catch (error) {
      if (retry === maxRetries - 1) {
        throw new Error(`Elements failed to load after ${maxRetries} retries: ${error}`);
      }
      
      if (debugLogging) {
        console.log(`[LoadingHelper] Retry ${retry + 1}/${maxRetries} for elements loading`);
      }
      
      await page.waitForTimeout(checkInterval);
    }
  }
}

/**
 * Wait for workflows to load completely
 */
export async function waitForWorkflowsLoaded(
  page: Page, 
  options: WorkflowLoadingOptions = {}
): Promise<void> {
  const { 
    timeout = 45000,
    waitForScenarios = true,
    waitForConnections = true,
    waitForTemplates = false,
    debugLogging = false 
  } = options;

  if (debugLogging) {
    console.log('[LoadingHelper] Starting waitForWorkflowsLoaded...');
  }

  // First ensure basic elements are loaded
  await waitForElementsToLoad(page, { timeout: timeout / 3, debugLogging });

  // Wait for workflow-specific elements
  try {
    if (waitForScenarios) {
      // Wait for scenarios list to load
      const scenariosSelectors = [
        '[data-testid="scenarios-list"]',
        '.scenarios-container',
        '.scenario-item',
        '[data-scenario-id]'
      ];

      for (const selector of scenariosSelectors) {
        const elements = page.locator(selector);
        if (await elements.count() > 0) {
          await elements.first().waitFor({ state: 'visible', timeout: timeout / 2 });
          if (debugLogging) {
            console.log(`[LoadingHelper] Scenarios loaded: ${selector}`);
          }
          break;
        }
      }
    }

    if (waitForConnections) {
      // Wait for connections to load
      const connectionSelectors = [
        '[data-testid="connections-list"]',
        '.connections-container', 
        '.connection-item',
        '[data-connection-id]'
      ];

      for (const selector of connectionSelectors) {
        const elements = page.locator(selector);
        if (await elements.count() > 0) {
          await elements.first().waitFor({ state: 'visible', timeout: timeout / 2 });
          if (debugLogging) {
            console.log(`[LoadingHelper] Connections loaded: ${selector}`);
          }
          break;
        }
      }
    }

    if (waitForTemplates) {
      // Wait for templates to load
      const templateSelectors = [
        '[data-testid="templates-list"]',
        '.templates-container',
        '.template-item'
      ];

      for (const selector of templateSelectors) {
        const elements = page.locator(selector);
        if (await elements.count() > 0) {
          await elements.first().waitFor({ state: 'visible', timeout: timeout / 2 });
          if (debugLogging) {
            console.log(`[LoadingHelper] Templates loaded: ${selector}`);
          }
          break;
        }
      }
    }

    // Wait for any remaining network activity to complete
    await page.waitForLoadState('networkidle', { timeout: 5000 });

    if (debugLogging) {
      console.log('[LoadingHelper] waitForWorkflowsLoaded completed successfully');
    }

  } catch (error) {
    throw new Error(`Workflows failed to load: ${error}`);
  }
}

/**
 * Wait for dashboard to be fully ready
 */
export async function waitForDashboardReady(
  page: Page, 
  options: DashboardLoadingOptions = {}
): Promise<void> {
  const { 
    timeout = 60000,
    waitForCharts = true,
    waitForData = true,
    waitForAnimations = false,
    debugLogging = false 
  } = options;

  if (debugLogging) {
    console.log('[LoadingHelper] Starting waitForDashboardReady...');
  }

  // First ensure basic elements are loaded
  await waitForElementsToLoad(page, { timeout: timeout / 4, debugLogging });

  try {
    // Wait for dashboard container
    const dashboardSelectors = [
      '[data-testid="dashboard"]',
      '.dashboard-container',
      '.performance-dashboard',
      '#dashboard'
    ];

    for (const selector of dashboardSelectors) {
      const element = page.locator(selector);
      if (await element.count() > 0) {
        await element.waitFor({ state: 'visible', timeout: timeout / 2 });
        if (debugLogging) {
          console.log(`[LoadingHelper] Dashboard container loaded: ${selector}`);
        }
        break;
      }
    }

    if (waitForCharts) {
      // Wait for charts/visualizations to load
      const chartSelectors = [
        '[data-testid*="chart"]',
        '.chart-container',
        '.recharts-surface',
        'canvas',
        'svg[class*="chart"]',
        '.visualization'
      ];

      for (const selector of chartSelectors) {
        const charts = page.locator(selector);
        const count = await charts.count();
        
        if (count > 0) {
          if (debugLogging) {
            console.log(`[LoadingHelper] Waiting for ${count} charts: ${selector}`);
          }
          
          // Wait for each chart to be visible
          for (let i = 0; i < Math.min(count, 10); i++) { // Limit to 10 charts max
            await charts.nth(i).waitFor({ state: 'visible', timeout: timeout / 3 });
          }
        }
      }
    }

    if (waitForData) {
      // Wait for data tables/lists to load
      const dataSelectors = [
        '[data-testid*="data-table"]',
        '.data-table',
        '.metrics-grid',
        '.stats-container',
        '[data-loaded="true"]'
      ];

      for (const selector of dataSelectors) {
        const elements = page.locator(selector);
        if (await elements.count() > 0) {
          await elements.first().waitFor({ state: 'visible', timeout: timeout / 2 });
          if (debugLogging) {
            console.log(`[LoadingHelper] Data elements loaded: ${selector}`);
          }
        }
      }
    }

    if (waitForAnimations) {
      // Wait for animations to complete
      await page.waitForTimeout(1000);
      
      // Check if any elements are still animating
      const animatingElements = page.locator('.animate-pulse, .animate-spin, .animate-bounce');
      const animatingCount = await animatingElements.count();
      
      if (animatingCount > 0) {
        if (debugLogging) {
          console.log(`[LoadingHelper] Waiting for ${animatingCount} animations to complete`);
        }
        await page.waitForTimeout(2000); // Give animations time to complete
      }
    }

    // Final network idle check
    await page.waitForLoadState('networkidle', { timeout: 10000 });

    if (debugLogging) {
      console.log('[LoadingHelper] waitForDashboardReady completed successfully');
    }

  } catch (error) {
    throw new Error(`Dashboard failed to load: ${error}`);
  }
}

/**
 * Safe click with loading awareness
 */
export async function safeClick(
  page: Page,
  selector: string,
  options: LoadingOptions & { waitAfterClick?: number } = {}
): Promise<void> {
  const { 
    timeout = 30000,
    waitAfterClick = 1000,
    debugLogging = false 
  } = options;

  if (debugLogging) {
    console.log(`[LoadingHelper] Safe clicking: ${selector}`);
  }

  // Wait for element to be available and visible
  const element = page.locator(selector);
  await element.waitFor({ state: 'visible', timeout });
  
  // Ensure element is enabled and clickable
  await element.waitFor({ state: 'attached', timeout });
  await page.waitForTimeout(100); // Small delay to ensure element is ready

  // Scroll element into view if needed
  await element.scrollIntoViewIfNeeded();
  
  // Click the element
  await element.click();
  
  // Wait after click to allow for any loading to start
  if (waitAfterClick > 0) {
    await page.waitForTimeout(waitAfterClick);
  }

  if (debugLogging) {
    console.log(`[LoadingHelper] Clicked successfully: ${selector}`);
  }
}

/**
 * Safe navigation between views with proper loading
 */
export async function safeNavigate(
  page: Page,
  navigationSelector: string,
  waitForView: (page: Page) => Promise<void>,
  options: LoadingOptions = {}
): Promise<void> {
  const { debugLogging = false } = options;

  if (debugLogging) {
    console.log(`[LoadingHelper] Safe navigating via: ${navigationSelector}`);
  }

  // Perform the navigation click
  await safeClick(page, navigationSelector, { ...options, waitAfterClick: 2000 });
  
  // Wait for the new view to load
  await waitForView(page);
  
  if (debugLogging) {
    console.log(`[LoadingHelper] Navigation completed successfully`);
  }
}

/**
 * Detect if system is under stress/overloaded
 */
export async function detectSystemStress(page: Page): Promise<boolean> {
  try {
    // Check for performance indicators
    const stressIndicators = [
      '.error-boundary',
      '[data-testid="error"]',
      '.timeout-error',
      '.server-error',
      '[aria-label*="error"]'
    ];

    for (const selector of stressIndicators) {
      const elements = page.locator(selector);
      if (await elements.count() > 0) {
        return true;
      }
    }

    // Check network timing
    const startTime = Date.now();
    await page.waitForLoadState('networkidle', { timeout: 5000 });
    const networkTime = Date.now() - startTime;
    
    // If network idle takes too long, system might be stressed
    return networkTime > 4000;

  } catch (error) {
    // If we timeout waiting for network idle, system is likely stressed
    return true;
  }
}

/**
 * Wait with stress detection and backoff
 */
export async function waitWithBackoff(
  page: Page,
  waitFunction: () => Promise<void>,
  options: LoadingOptions = {}
): Promise<void> {
  const { maxRetries = 3, debugLogging = false } = options;
  
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      // Check if system is stressed
      const isStressed = await detectSystemStress(page);
      
      if (isStressed && attempt > 0) {
        const backoffTime = Math.min(5000 * attempt, 15000);
        if (debugLogging) {
          console.log(`[LoadingHelper] System stress detected, backing off ${backoffTime}ms`);
        }
        await page.waitForTimeout(backoffTime);
      }
      
      await waitFunction();
      return; // Success
      
    } catch (error) {
      if (attempt === maxRetries - 1) {
        throw error;
      }
      
      if (debugLogging) {
        console.log(`[LoadingHelper] Attempt ${attempt + 1} failed, retrying...`);
      }
      
      await page.waitForTimeout(2000 * (attempt + 1));
    }
  }
}