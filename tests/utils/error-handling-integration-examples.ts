/**
 * Error Handling Integration Examples
 * 
 * Practical examples showing how to integrate the comprehensive error handling
 * system with existing test suites, loading detection, and staged execution.
 * 
 * These examples demonstrate real-world usage patterns and best practices
 * for implementing robust test error handling in browser automation.
 */

import type { Page, TestInfo } from '@playwright/test';
import { expect } from '@playwright/test';
import {
  TestErrorHandlingEngine,
  createErrorHandlingEngine,
  withErrorHandling,
  expectWithRetry,
  type ErrorHandlingConfig
} from './test-error-handling';
import {
  waitForElementsToLoadEnhanced,
  waitForDashboardReadyEnhanced,
  waitForWorkflowsLoadedEnhanced
} from './enhanced-loading-detection';
import { StagedTestExecutionEngine } from './staged-test-execution';

// ==================== INTEGRATION CONFIGURATIONS ====================

// Development environment - more retries and detailed logging
export const DEVELOPMENT_ERROR_CONFIG: Partial<ErrorHandlingConfig> = {
  maxRetries: 5,
  baseRetryDelay: 1000,
  exponentialBackoff: true,
  screenshotOnFailure: true,
  videoOnFailure: true,
  detailedLogging: true,
  performanceMonitoring: true,
  gracefulDegradation: true,
  retryTimeout: 45000
};

// CI environment - faster execution with essential features
export const CI_ERROR_CONFIG: Partial<ErrorHandlingConfig> = {
  maxRetries: 3,
  baseRetryDelay: 500,
  exponentialBackoff: true,
  screenshotOnFailure: true,
  videoOnFailure: false, // Save space in CI
  detailedLogging: false,
  performanceMonitoring: false,
  gracefulDegradation: true,
  retryTimeout: 30000
};

// Production testing - minimal retries with comprehensive logging
export const PRODUCTION_ERROR_CONFIG: Partial<ErrorHandlingConfig> = {
  maxRetries: 2,
  baseRetryDelay: 2000,
  exponentialBackoff: true,
  screenshotOnFailure: true,
  videoOnFailure: true,
  detailedLogging: true,
  performanceMonitoring: true,
  gracefulDegradation: false, // Strict validation in production
  retryTimeout: 60000
};

// ==================== ENHANCED LOADING WITH ERROR HANDLING ====================

/**
 * Enhanced loading detection with comprehensive error handling
 */
export class LoadingWithErrorHandling {
  private errorEngine: TestErrorHandlingEngine;

  constructor(config: Partial<ErrorHandlingConfig> = {}) {
    this.errorEngine = createErrorHandlingEngine({
      ...DEVELOPMENT_ERROR_CONFIG,
      ...config
    });
  }

  /**
   * Wait for elements to load with automatic error recovery
   */
  async waitForElementsToLoadSafely(
    page: Page,
    options: {
      timeout?: number;
      intelligentSelectors?: boolean;
      performanceMonitoring?: boolean;
    } = {},
    testInfo?: TestInfo
  ) {
    return await this.errorEngine.executeWithErrorHandling(
      async () => {
        const result = await waitForElementsToLoadEnhanced(page, {
          timeout: options.timeout || 60000,
          intelligentSelectors: options.intelligentSelectors !== false,
          performanceMonitoring: options.performanceMonitoring !== false,
          stressAwareLoading: true
        });

        if (!result.success) {
          throw new Error(`Loading detection failed: ${result.warnings.join(', ')}`);
        }

        return result;
      },
      {
        operation: 'enhanced-elements-loading',
        additionalContext: { loadingOptions: options }
      },
      page,
      testInfo
    );
  }

  /**
   * Wait for dashboard to be ready with error recovery
   */
  async waitForDashboardSafely(
    page: Page,
    options: {
      timeout?: number;
      waitForCharts?: boolean;
      waitForData?: boolean;
    } = {},
    testInfo?: TestInfo
  ) {
    return await this.errorEngine.executeWithErrorHandling(
      async () => {
        const result = await waitForDashboardReadyEnhanced(page, {
          timeout: options.timeout || 90000,
          waitForCharts: options.waitForCharts !== false,
          waitForData: options.waitForData !== false,
          performanceMonitoring: true,
          intelligentSelectors: true
        });

        if (!result.success) {
          throw new Error(`Dashboard loading failed: ${result.warnings.join(', ')}`);
        }

        return result;
      },
      {
        operation: 'enhanced-dashboard-loading',
        additionalContext: { dashboardOptions: options }
      },
      page,
      testInfo
    );
  }

  /**
   * Wait for workflows to load with error recovery
   */
  async waitForWorkflowsSafely(
    page: Page,
    options: {
      timeout?: number;
      waitForScenarios?: boolean;
      waitForConnections?: boolean;
    } = {},
    testInfo?: TestInfo
  ) {
    return await this.errorEngine.executeWithErrorHandling(
      async () => {
        const result = await waitForWorkflowsLoadedEnhanced(page, {
          timeout: options.timeout || 75000,
          waitForScenarios: options.waitForScenarios !== false,
          waitForConnections: options.waitForConnections !== false,
          performanceMonitoring: true,
          intelligentSelectors: true
        });

        if (!result.success) {
          throw new Error(`Workflow loading failed: ${result.warnings.join(', ')}`);
        }

        return result;
      },
      {
        operation: 'enhanced-workflow-loading',
        additionalContext: { workflowOptions: options }
      },
      page,
      testInfo
    );
  }
}

// ==================== STAGED EXECUTION WITH ERROR HANDLING ====================

/**
 * Staged test execution with integrated error handling
 */
export class StagedExecutionWithErrorHandling {
  private stagedEngine: StagedTestExecutionEngine;
  private errorEngine: TestErrorHandlingEngine;
  private loadingHandler: LoadingWithErrorHandling;

  constructor(
    environment: 'development' | 'staging' | 'production' | 'ci' = 'development',
    errorConfig: Partial<ErrorHandlingConfig> = {}
  ) {
    this.stagedEngine = new StagedTestExecutionEngine({
      environment,
      debugLogging: true,
      performanceMonitoring: true,
      stressDetection: true
    });

    const envErrorConfigs = {
      development: DEVELOPMENT_ERROR_CONFIG,
      staging: DEVELOPMENT_ERROR_CONFIG,
      production: PRODUCTION_ERROR_CONFIG,
      ci: CI_ERROR_CONFIG
    };

    this.errorEngine = createErrorHandlingEngine({
      ...envErrorConfigs[environment],
      ...errorConfig
    });

    this.loadingHandler = new LoadingWithErrorHandling({
      ...envErrorConfigs[environment],
      ...errorConfig
    });
  }

  /**
   * Execute complete staged workflow with error handling
   */
  async executeFullWorkflowWithErrorHandling(
    page: Page,
    testInfo?: TestInfo
  ) {
    return await this.errorEngine.executeWithErrorHandling(
      async () => {
        // Stage 1: Enhanced elements loading
        console.log('[StagedExecution] Stage 1: Loading page elements...');
        const elementsResult = await this.loadingHandler.waitForElementsToLoadSafely(
          page,
          { timeout: 45000 },
          testInfo
        );

        if (!elementsResult.success) {
          throw new Error('Stage 1 failed: Elements loading unsuccessful');
        }

        // Stage 2: Enhanced workflow loading
        console.log('[StagedExecution] Stage 2: Loading workflows...');
        const workflowResult = await this.loadingHandler.waitForWorkflowsSafely(
          page,
          { timeout: 60000 },
          testInfo
        );

        if (!workflowResult.success) {
          console.warn('Stage 2 warning: Workflow loading had issues, continuing...');
        }

        // Stage 3: Enhanced dashboard loading
        console.log('[StagedExecution] Stage 3: Loading dashboard...');
        const dashboardResult = await this.loadingHandler.waitForDashboardSafely(
          page,
          { timeout: 75000 },
          testInfo
        );

        if (!dashboardResult.success) {
          console.warn('Stage 3 warning: Dashboard loading had issues, continuing...');
        }

        // Stage 4: Performance validation
        console.log('[StagedExecution] Stage 4: Performance validation...');
        const performanceMetrics = await this.stagedEngine.executeStages(page);

        return {
          elementsLoading: elementsResult.result,
          workflowLoading: workflowResult.result,
          dashboardLoading: dashboardResult.result,
          performanceMetrics
        };
      },
      {
        operation: 'full-staged-workflow-execution'
      },
      page,
      testInfo
    );
  }

  /**
   * Execute single stage with error handling
   */
  async executeSingleStage(
    page: Page,
    stageType: 'elements' | 'workflows' | 'dashboard',
    options: Record<string, unknown> = {},
    testInfo?: TestInfo
  ) {
    const stageHandlers = {
      elements: () => this.loadingHandler.waitForElementsToLoadSafely(page, options, testInfo),
      workflows: () => this.loadingHandler.waitForWorkflowsSafely(page, options, testInfo),
      dashboard: () => this.loadingHandler.waitForDashboardSafely(page, options, testInfo)
    };

    return await this.errorEngine.executeWithErrorHandling(
      stageHandlers[stageType],
      {
        operation: `single-stage-execution-${stageType}`,
        additionalContext: { stageType, stageOptions: options }
      },
      page,
      testInfo
    );
  }
}

// ==================== COMMON UI INTERACTIONS WITH ERROR HANDLING ====================

/**
 * Common UI interactions enhanced with error handling
 */
export class SafeUIInteractions {
  private errorEngine: TestErrorHandlingEngine;

  constructor(config: Partial<ErrorHandlingConfig> = {}) {
    this.errorEngine = createErrorHandlingEngine({
      ...DEVELOPMENT_ERROR_CONFIG,
      ...config
    });
  }

  /**
   * Safe form filling with validation
   */
  async safeFormFill(
    page: Page,
    formData: Record<string, string>,
    options: {
      formSelector?: string;
      submitSelector?: string;
      validateAfterFill?: boolean;
    } = {},
    testInfo?: TestInfo
  ) {
    return await this.errorEngine.executeWithErrorHandling(
      async () => {
        const {
          formSelector = 'form',
          submitSelector = 'button[type="submit"], input[type="submit"]',
          validateAfterFill = true
        } = options;

        // Wait for form to be ready
        const form = page.locator(formSelector);
        await form.waitFor({ state: 'visible', timeout: 30000 });

        // Fill each field with individual error handling
        for (const [fieldName, value] of Object.entries(formData)) {
          const fieldSelectors = [
            `[name="${fieldName}"]`,
            `[data-testid="${fieldName}"]`,
            `#${fieldName}`,
            `.${fieldName}`
          ];

          let fieldFilled = false;
          for (const selector of fieldSelectors) {
            try {
              const field = page.locator(selector);
              if (await field.count() > 0 && await field.isVisible()) {
                await field.clear();
                await field.fill(value);
                fieldFilled = true;
                break;
              }
            } catch (error) {
              continue; // Try next selector
            }
          }

          if (!fieldFilled) {
            throw new Error(`Could not fill field: ${fieldName}`);
          }
        }

        // Validate form data if requested
        if (validateAfterFill) {
          for (const [fieldName, expectedValue] of Object.entries(formData)) {
            const field = page.locator(`[name="${fieldName}"]`).first();
            if (await field.count() > 0) {
              const actualValue = await field.inputValue();
              if (actualValue !== expectedValue) {
                throw new Error(`Field validation failed: ${fieldName}. Expected: ${expectedValue}, Got: ${actualValue}`);
              }
            }
          }
        }

        return { formFilled: true, fieldsCount: Object.keys(formData).length };
      },
      {
        operation: 'safe-form-fill',
        additionalContext: { formData: Object.keys(formData) }
      },
      page,
      testInfo
    );
  }

  /**
   * Safe navigation with loading validation
   */
  async safeNavigateAndValidate(
    page: Page,
    url: string,
    validationSelectors: string[] = ['body'],
    options: {
      waitUntil?: 'load' | 'domcontentloaded' | 'networkidle';
      timeout?: number;
      validateContent?: boolean;
    } = {},
    testInfo?: TestInfo
  ) {
    return await this.errorEngine.executeWithErrorHandling(
      async () => {
        const {
          waitUntil = 'networkidle',
          timeout = 45000,
          validateContent = true
        } = options;

        // Navigate to URL
        await page.goto(url, { waitUntil, timeout });

        // Validate page loaded correctly
        if (validateContent) {
          for (const selector of validationSelectors) {
            const element = page.locator(selector);
            await element.waitFor({ state: 'visible', timeout: 30000 });
          }

          // Additional validation: check page is interactive
          await page.waitForLoadState('domcontentloaded');
          
          // Verify no error indicators
          const errorIndicators = [
            '.error-page',
            '.not-found',
            '[data-testid="error"]',
            '.server-error'
          ];

          for (const errorSelector of errorIndicators) {
            const errorElement = page.locator(errorSelector);
            const errorExists = await errorElement.count() > 0 && await errorElement.isVisible();
            if (errorExists) {
              throw new Error(`Error indicator found: ${errorSelector}`);
            }
          }
        }

        return {
          url: page.url(),
          title: await page.title(),
          validationsPassed: validationSelectors.length
        };
      },
      {
        operation: 'safe-navigate-and-validate',
        additionalContext: { targetUrl: url, validationSelectors }
      },
      page,
      testInfo
    );
  }

  /**
   * Safe element interaction with state validation
   */
  async safeInteractWithElement(
    page: Page,
    selector: string,
    action: 'click' | 'hover' | 'focus' | 'doubleClick',
    options: {
      waitForState?: 'visible' | 'enabled' | 'stable';
      timeout?: number;
      validateAfter?: boolean;
    } = {},
    testInfo?: TestInfo
  ) {
    return await this.errorEngine.executeWithErrorHandling(
      async () => {
        const {
          waitForState = 'visible',
          timeout = 30000,
          validateAfter = true
        } = options;

        const element = page.locator(selector);

        // Wait for element to be in desired state
        switch (waitForState) {
          case 'visible':
            await element.waitFor({ state: 'visible', timeout });
            break;
          case 'enabled':
            await element.waitFor({ state: 'visible', timeout });
            await expect(element).toBeEnabled({ timeout });
            break;
          case 'stable':
            await element.waitFor({ state: 'visible', timeout });
            // Wait for animations to complete
            await page.waitForTimeout(500);
            break;
        }

        // Scroll element into view
        await element.scrollIntoViewIfNeeded();

        // Perform the action
        switch (action) {
          case 'click':
            await element.click();
            break;
          case 'hover':
            await element.hover();
            break;
          case 'focus':
            await element.focus();
            break;
          case 'doubleClick':
            await element.dblclick();
            break;
        }

        // Validate action completed successfully
        if (validateAfter) {
          // Wait for any immediate effects
          await page.waitForTimeout(500);
          
          // Ensure element is still present and stable
          if (action !== 'hover') { // Hover might change element state
            await element.waitFor({ state: 'attached', timeout: 5000 });
          }
        }

        return {
          action,
          selector,
          elementState: await element.boundingBox() ? 'visible' : 'not-visible'
        };
      },
      {
        operation: `safe-${action}-interaction`,
        targetElements: [selector],
        additionalContext: { action, elementSelector: selector }
      },
      page,
      testInfo
    );
  }
}

// ==================== INTEGRATION UTILITIES ====================

/**
 * Create environment-specific error handling configuration
 */
export function createEnvironmentErrorConfig(
  environment: 'development' | 'staging' | 'production' | 'ci'
): Partial<ErrorHandlingConfig> {
  const configs = {
    development: DEVELOPMENT_ERROR_CONFIG,
    staging: DEVELOPMENT_ERROR_CONFIG,
    production: PRODUCTION_ERROR_CONFIG,
    ci: CI_ERROR_CONFIG
  };

  return configs[environment];
}

/**
 * Enhanced test wrapper with comprehensive error handling
 */
export function createSafeTest<T extends any[], R>(
  testFunction: (page: Page, ...args: T) => Promise<R>,
  options: {
    environment?: 'development' | 'staging' | 'production' | 'ci';
    customErrorConfig?: Partial<ErrorHandlingConfig>;
    enableStagedExecution?: boolean;
    enableLoadingDetection?: boolean;
  } = {}
) {
  const {
    environment = 'development',
    customErrorConfig = {},
    enableStagedExecution = false,
    enableLoadingDetection = true
  } = options;

  const errorConfig = {
    ...createEnvironmentErrorConfig(environment),
    ...customErrorConfig
  };

  const errorEngine = createErrorHandlingEngine(errorConfig);
  const loadingHandler = enableLoadingDetection ? new LoadingWithErrorHandling(errorConfig) : null;
  const stagedHandler = enableStagedExecution ? new StagedExecutionWithErrorHandling(environment, errorConfig) : null;

  return async (page: Page, testInfo: TestInfo, ...args: T): Promise<R> => {
    // Pre-test setup: ensure page is ready
    if (loadingHandler) {
      await loadingHandler.waitForElementsToLoadSafely(page, {}, testInfo);
    }

    // Execute test with error handling
    const result = await errorEngine.executeWithErrorHandling(
      () => testFunction(page, ...args),
      {
        operation: testFunction.name || 'safe-test-execution',
        testName: testInfo.title,
        additionalContext: {
          environment,
          stagingEnabled: enableStagedExecution,
          loadingDetectionEnabled: enableLoadingDetection
        }
      },
      page,
      testInfo
    );

    if (!result.success) {
      throw result.finalError || new Error('Test execution failed after all error handling attempts');
    }

    return result.result!;
  };
}

/**
 * Batch operation with error handling
 */
export async function executeBatchOperationsWithErrorHandling<T>(
  page: Page,
  operations: Array<{
    name: string;
    operation: () => Promise<T>;
    critical: boolean;
  }>,
  testInfo?: TestInfo
): Promise<{
  results: Array<{ name: string; success: boolean; result?: T; error?: Error }>;
  overallSuccess: boolean;
  criticalFailures: number;
}> {
  const errorEngine = createErrorHandlingEngine(DEVELOPMENT_ERROR_CONFIG);
  const results: Array<{ name: string; success: boolean; result?: T; error?: Error }> = [];
  let criticalFailures = 0;

  for (const { name, operation, critical } of operations) {
    const result = await errorEngine.executeWithErrorHandling(
      operation,
      {
        operation: `batch-operation-${name}`,
        additionalContext: { batchOperation: name, critical }
      },
      page,
      testInfo
    );

    const operationResult = {
      name,
      success: result.success,
      result: result.result,
      error: result.finalError
    };

    results.push(operationResult);

    if (!result.success && critical) {
      criticalFailures++;
    }
  }

  return {
    results,
    overallSuccess: criticalFailures === 0,
    criticalFailures
  };
}

export default {
  LoadingWithErrorHandling,
  StagedExecutionWithErrorHandling,
  SafeUIInteractions,
  createEnvironmentErrorConfig,
  createSafeTest,
  executeBatchOperationsWithErrorHandling,
  DEVELOPMENT_ERROR_CONFIG,
  CI_ERROR_CONFIG,
  PRODUCTION_ERROR_CONFIG
};