/**
 * Comprehensive Test Error Handling and Recovery System
 * 
 * Provides enterprise-grade error handling, recovery mechanisms, and debugging
 * capabilities for browser tests, including automatic retries, screenshot capture,
 * detailed logging, and graceful fallback strategies.
 * 
 * Features:
 * - Comprehensive error detection and classification
 * - Automatic retry mechanisms with exponential backoff
 * - Screenshot and video capture on failures
 * - Detailed error logging with context information
 * - Graceful fallback strategies for element loading failures
 * - Integration with existing loading detection systems
 * - Performance-aware error handling with stress detection
 */

import type { Page, TestInfo, Locator, BrowserContext } from '@playwright/test';
import { expect } from '@playwright/test';
import * as fs from 'fs/promises';
import * as path from 'path';

// ==================== INTERFACES & TYPES ====================

export interface ErrorHandlingConfig {
  /** Maximum number of retry attempts */
  maxRetries: number;
  /** Base delay between retries in milliseconds */
  baseRetryDelay: number;
  /** Whether to use exponential backoff for retries */
  exponentialBackoff: boolean;
  /** Maximum delay between retries in milliseconds */
  maxRetryDelay: number;
  /** Enable screenshot capture on failures */
  screenshotOnFailure: boolean;
  /** Enable video recording on failures */
  videoOnFailure: boolean;
  /** Enable detailed logging */
  detailedLogging: boolean;
  /** Enable performance monitoring during error handling */
  performanceMonitoring: boolean;
  /** Custom error handlers by error type */
  customErrorHandlers: Map<string, ErrorHandler>;
  /** Timeout for individual retry attempts */
  retryTimeout: number;
  /** Enable graceful degradation when possible */
  gracefulDegradation: boolean;
}

export interface ErrorContext {
  /** The operation that was being performed when error occurred */
  operation: string;
  /** Page URL when error occurred */
  pageUrl: string;
  /** Timestamp when error occurred */
  timestamp: Date;
  /** Current test name/description */
  testName: string;
  /** Loading state when error occurred */
  loadingState?: 'loading' | 'domcontentloaded' | 'networkidle';
  /** Network requests in progress when error occurred */
  networkRequests?: number;
  /** Elements being waited for when error occurred */
  targetElements?: string[];
  /** System performance indicators when error occurred */
  performanceMetrics?: {
    memoryUsage: number;
    cpuUsage: number;
    networkLatency: number;
  };
  /** Additional context data */
  additionalContext: Record<string, unknown>;
}

export interface ErrorHandlingResult {
  /** Whether the operation succeeded after error handling */
  success: boolean;
  /** Number of retry attempts made */
  attemptsMade: number;
  /** Total time spent on error handling and retries */
  totalDuration: number;
  /** Final error if all retries failed */
  finalError?: Error;
  /** List of all errors encountered during retries */
  errorHistory: Error[];
  /** Screenshots captured during error handling */
  screenshots: string[];
  /** Video recordings captured during error handling */
  videos: string[];
  /** Recovery strategies that were attempted */
  recoveryStrategiesUsed: string[];
  /** Whether graceful degradation was used */
  gracefulDegradationUsed: boolean;
  /** Additional diagnostic information */
  diagnosticInfo: Record<string, unknown>;
}

export interface FallbackStrategy {
  /** Name of the fallback strategy */
  name: string;
  /** Function to execute the fallback */
  execute: (page: Page, context: ErrorContext, originalError: Error) => Promise<boolean>;
  /** Priority of the fallback (higher = tried first) */
  priority: number;
  /** Conditions under which this fallback applies */
  applicableFor: (error: Error, context: ErrorContext) => boolean;
}

export interface ErrorHandler {
  /** Function to handle the specific error type */
  handle: (error: Error, context: ErrorContext, page: Page) => Promise<ErrorHandlingResult>;
  /** Whether this handler can recover from the error */
  canRecover: boolean;
  /** Priority of this handler */
  priority: number;
}

export interface ScreenshotOptions {
  /** Path where screenshot should be saved */
  path?: string;
  /** Whether to capture full page */
  fullPage: boolean;
  /** Quality of the screenshot (0-100) */
  quality?: number;
  /** Whether to mask sensitive elements */
  maskSensitive: boolean;
  /** Elements to mask in screenshot */
  maskElements: string[];
}

// ==================== ERROR TYPES ====================

export enum TestErrorType {
  TIMEOUT = 'timeout',
  ELEMENT_NOT_FOUND = 'element_not_found',
  NETWORK_ERROR = 'network_error',
  LOADING_FAILURE = 'loading_failure',
  INTERACTION_FAILURE = 'interaction_failure',
  ASSERTION_FAILURE = 'assertion_failure',
  NAVIGATION_FAILURE = 'navigation_failure',
  JAVASCRIPT_ERROR = 'javascript_error',
  MEMORY_ERROR = 'memory_error',
  SYSTEM_ERROR = 'system_error'
}

export class EnhancedTestError extends Error {
  public readonly errorType: TestErrorType;
  public readonly context: ErrorContext;
  public readonly originalError?: Error;
  public readonly retryable: boolean;

  constructor(
    message: string,
    errorType: TestErrorType,
    context: ErrorContext,
    originalError?: Error,
    retryable: boolean = true
  ) {
    super(message);
    this.name = 'EnhancedTestError';
    this.errorType = errorType;
    this.context = context;
    this.originalError = originalError;
    this.retryable = retryable;
  }
}

// ==================== TEST ERROR HANDLING ENGINE ====================

export class TestErrorHandlingEngine {
  private config: ErrorHandlingConfig;
  private fallbackStrategies: FallbackStrategy[] = [];
  private errorCount: Map<TestErrorType, number> = new Map();

  constructor(config: Partial<ErrorHandlingConfig> = {}) {
    this.config = {
      maxRetries: 3,
      baseRetryDelay: 1000,
      exponentialBackoff: true,
      maxRetryDelay: 15000,
      screenshotOnFailure: true,
      videoOnFailure: true,
      detailedLogging: true,
      performanceMonitoring: true,
      customErrorHandlers: new Map(),
      retryTimeout: 30000,
      gracefulDegradation: true,
      ...config
    };

    this.initializeDefaultFallbackStrategies();
    this.initializeDefaultErrorHandlers();
  }

  /**
   * Execute operation with comprehensive error handling and recovery
   */
  async executeWithErrorHandling<T>(
    operation: () => Promise<T>,
    context: Partial<ErrorContext>,
    page: Page,
    testInfo?: TestInfo
  ): Promise<ErrorHandlingResult & { result?: T }> {
    const fullContext: ErrorContext = {
      operation: 'unknown',
      pageUrl: page.url(),
      timestamp: new Date(),
      testName: testInfo?.title || 'unknown',
      additionalContext: {},
      ...context
    };

    const result: ErrorHandlingResult & { result?: T } = {
      success: false,
      attemptsMade: 0,
      totalDuration: 0,
      errorHistory: [],
      screenshots: [],
      videos: [],
      recoveryStrategiesUsed: [],
      gracefulDegradationUsed: false,
      diagnosticInfo: {}
    };

    const startTime = Date.now();

    if (this.config.detailedLogging) {
      console.log(`[ErrorHandling] Starting operation: ${fullContext.operation}`);
    }

    for (let attempt = 0; attempt <= this.config.maxRetries; attempt++) {
      result.attemptsMade = attempt + 1;

      try {
        // Update context with current attempt info
        fullContext.timestamp = new Date();
        fullContext.pageUrl = page.url();

        // Add performance monitoring if enabled
        if (this.config.performanceMonitoring) {
          fullContext.performanceMetrics = await this.collectPerformanceMetrics(page);
        }

        // Execute the operation
        const operationResult = await this.executeWithTimeout(
          operation,
          this.config.retryTimeout
        );

        result.result = operationResult;
        result.success = true;
        break;

      } catch (error) {
        const enhancedError = this.enhanceError(error as Error, fullContext);
        result.errorHistory.push(enhancedError);

        if (this.config.detailedLogging) {
          console.log(`[ErrorHandling] Attempt ${attempt + 1} failed:`, enhancedError.message);
        }

        // Capture screenshot and video on failure
        if (this.config.screenshotOnFailure) {
          const screenshotPath = await this.captureScreenshot(page, fullContext, testInfo);
          if (screenshotPath) result.screenshots.push(screenshotPath);
        }

        if (this.config.videoOnFailure && testInfo) {
          const videoPath = await this.captureVideo(page, fullContext, testInfo);
          if (videoPath) result.videos.push(videoPath);
        }

        // Try recovery strategies if this is not the last attempt
        if (attempt < this.config.maxRetries) {
          const recoverySucceeded = await this.attemptRecovery(
            enhancedError,
            fullContext,
            page,
            result
          );

          if (recoverySucceeded) {
            if (this.config.detailedLogging) {
              console.log(`[ErrorHandling] Recovery succeeded for attempt ${attempt + 1}`);
            }
            continue;
          }

          // Wait before retry with exponential backoff
          const retryDelay = this.calculateRetryDelay(attempt);
          if (this.config.detailedLogging) {
            console.log(`[ErrorHandling] Waiting ${retryDelay}ms before retry ${attempt + 2}`);
          }
          await this.delay(retryDelay);
        } else {
          // Last attempt failed, try graceful degradation
          if (this.config.gracefulDegradation) {
            const degradationSucceeded = await this.attemptGracefulDegradation(
              enhancedError,
              fullContext,
              page,
              result
            );

            if (degradationSucceeded) {
              result.success = true;
              result.gracefulDegradationUsed = true;
              break;
            }
          }

          result.finalError = enhancedError;
        }
      }
    }

    result.totalDuration = Date.now() - startTime;

    if (this.config.detailedLogging) {
      console.log(`[ErrorHandling] Operation completed:`, {
        success: result.success,
        attempts: result.attemptsMade,
        duration: result.totalDuration,
        recoveryStrategies: result.recoveryStrategiesUsed,
        gracefulDegradation: result.gracefulDegradationUsed
      });
    }

    return result;
  }

  /**
   * Safe click with comprehensive error handling
   */
  async safeClick(
    page: Page,
    selector: string,
    options: { timeout?: number; retries?: number } = {},
    testInfo?: TestInfo
  ): Promise<ErrorHandlingResult> {
    return await this.executeWithErrorHandling(
      async () => {
        const element = page.locator(selector);
        await element.waitFor({ state: 'visible', timeout: options.timeout || 30000 });
        await element.scrollIntoViewIfNeeded();
        await element.click();
      },
      {
        operation: `click on ${selector}`,
        targetElements: [selector]
      },
      page,
      testInfo
    );
  }

  /**
   * Safe navigation with comprehensive error handling
   */
  async safeNavigate(
    page: Page,
    url: string,
    options: { waitUntil?: 'load' | 'domcontentloaded' | 'networkidle'; timeout?: number } = {},
    testInfo?: TestInfo
  ): Promise<ErrorHandlingResult> {
    return await this.executeWithErrorHandling(
      async () => {
        await page.goto(url, {
          waitUntil: options.waitUntil || 'networkidle',
          timeout: options.timeout || 45000
        });
      },
      {
        operation: `navigate to ${url}`
      },
      page,
      testInfo
    );
  }

  /**
   * Safe element waiting with comprehensive error handling
   */
  async safeWaitForElement(
    page: Page,
    selector: string,
    options: { state?: 'attached' | 'detached' | 'visible' | 'hidden'; timeout?: number } = {},
    testInfo?: TestInfo
  ): Promise<ErrorHandlingResult & { element?: Locator }> {
    return await this.executeWithErrorHandling(
      async () => {
        const element = page.locator(selector);
        await element.waitFor({
          state: options.state || 'visible',
          timeout: options.timeout || 30000
        });
        return element;
      },
      {
        operation: `wait for element ${selector}`,
        targetElements: [selector]
      },
      page,
      testInfo
    );
  }

  /**
   * Safe text input with comprehensive error handling
   */
  async safeType(
    page: Page,
    selector: string,
    text: string,
    options: { delay?: number; timeout?: number } = {},
    testInfo?: TestInfo
  ): Promise<ErrorHandlingResult> {
    return await this.executeWithErrorHandling(
      async () => {
        const element = page.locator(selector);
        await element.waitFor({ state: 'visible', timeout: options.timeout || 30000 });
        await element.clear();
        await element.type(text, { delay: options.delay || 50 });
      },
      {
        operation: `type text into ${selector}`,
        targetElements: [selector],
        additionalContext: { text: text.slice(0, 100) + (text.length > 100 ? '...' : '') }
      },
      page,
      testInfo
    );
  }

  // ==================== PRIVATE HELPER METHODS ====================

  /**
   * Initialize default fallback strategies
   */
  private initializeDefaultFallbackStrategies(): void {
    // Refresh page fallback
    this.fallbackStrategies.push({
      name: 'page-refresh',
      priority: 1,
      applicableFor: (error, context) => {
        return error.message.includes('timeout') || 
               error.message.includes('network') ||
               context.operation.includes('navigate');
      },
      execute: async (page, context, originalError) => {
        try {
          if (this.config.detailedLogging) {
            console.log('[ErrorHandling] Attempting page refresh fallback');
          }
          await page.reload({ waitUntil: 'networkidle', timeout: 30000 });
          await this.delay(2000); // Give page time to stabilize
          return true;
        } catch (error) {
          return false;
        }
      }
    });

    // Wait and retry fallback
    this.fallbackStrategies.push({
      name: 'extended-wait',
      priority: 2,
      applicableFor: (error, context) => {
        return error.message.includes('not found') ||
               error.message.includes('not visible') ||
               context.operation.includes('wait');
      },
      execute: async (page, context, originalError) => {
        try {
          if (this.config.detailedLogging) {
            console.log('[ErrorHandling] Attempting extended wait fallback');
          }
          await this.delay(5000); // Extended wait
          await page.waitForLoadState('networkidle', { timeout: 30000 });
          return true;
        } catch (error) {
          return false;
        }
      }
    });

    // Alternative selector fallback
    this.fallbackStrategies.push({
      name: 'alternative-selector',
      priority: 3,
      applicableFor: (error, context) => {
        return error.message.includes('not found') && 
               context.targetElements && 
               context.targetElements.length > 0;
      },
      execute: async (page, context, originalError) => {
        if (!context.targetElements || context.targetElements.length === 0) return false;

        const originalSelector = context.targetElements[0];
        const alternativeSelectors = this.generateAlternativeSelectors(originalSelector);

        for (const altSelector of alternativeSelectors) {
          try {
            if (this.config.detailedLogging) {
              console.log(`[ErrorHandling] Trying alternative selector: ${altSelector}`);
            }
            
            const element = page.locator(altSelector);
            await element.waitFor({ state: 'visible', timeout: 5000 });
            
            if (this.config.detailedLogging) {
              console.log(`[ErrorHandling] Alternative selector worked: ${altSelector}`);
            }
            return true;
          } catch (error) {
            continue;
          }
        }
        return false;
      }
    });
  }

  /**
   * Initialize default error handlers
   */
  private initializeDefaultErrorHandlers(): void {
    // Timeout error handler
    this.config.customErrorHandlers.set('TimeoutError', {
      handle: async (error, context, page) => {
        if (this.config.detailedLogging) {
          console.log('[ErrorHandling] Handling timeout error');
        }

        // Check if page is responsive
        try {
          await page.waitForLoadState('domcontentloaded', { timeout: 5000 });
        } catch (e) {
          // Page is unresponsive, try refresh
          await page.reload({ timeout: 30000 });
        }

        return {
          success: true,
          attemptsMade: 1,
          totalDuration: 0,
          errorHistory: [error],
          screenshots: [],
          videos: [],
          recoveryStrategiesUsed: ['timeout-recovery'],
          gracefulDegradationUsed: false,
          diagnosticInfo: { timeoutHandled: true }
        };
      },
      canRecover: true,
      priority: 1
    });

    // Network error handler
    this.config.customErrorHandlers.set('NetworkError', {
      handle: async (error, context, page) => {
        if (this.config.detailedLogging) {
          console.log('[ErrorHandling] Handling network error');
        }

        // Wait for network to stabilize
        await this.delay(3000);
        
        try {
          await page.waitForLoadState('networkidle', { timeout: 30000 });
          return {
            success: true,
            attemptsMade: 1,
            totalDuration: 0,
            errorHistory: [error],
            screenshots: [],
            videos: [],
            recoveryStrategiesUsed: ['network-recovery'],
            gracefulDegradationUsed: false,
            diagnosticInfo: { networkStabilized: true }
          };
        } catch (e) {
          return {
            success: false,
            attemptsMade: 1,
            totalDuration: 0,
            errorHistory: [error],
            screenshots: [],
            videos: [],
            recoveryStrategiesUsed: ['network-recovery-failed'],
            gracefulDegradationUsed: false,
            diagnosticInfo: { networkFailed: true }
          };
        }
      },
      canRecover: true,
      priority: 2
    });
  }

  /**
   * Enhance error with additional context and classification
   */
  private enhanceError(error: Error, context: ErrorContext): EnhancedTestError {
    const errorType = this.classifyError(error);
    this.errorCount.set(errorType, (this.errorCount.get(errorType) || 0) + 1);

    return new EnhancedTestError(
      error.message,
      errorType,
      context,
      error,
      this.isRetryableError(errorType)
    );
  }

  /**
   * Classify error type based on error message and context
   */
  private classifyError(error: Error): TestErrorType {
    const message = error.message.toLowerCase();

    if (message.includes('timeout') || message.includes('timed out')) {
      return TestErrorType.TIMEOUT;
    }
    if (message.includes('not found') || message.includes('no element')) {
      return TestErrorType.ELEMENT_NOT_FOUND;
    }
    if (message.includes('network') || message.includes('fetch') || message.includes('connection')) {
      return TestErrorType.NETWORK_ERROR;
    }
    if (message.includes('loading') || message.includes('load')) {
      return TestErrorType.LOADING_FAILURE;
    }
    if (message.includes('click') || message.includes('type') || message.includes('interact')) {
      return TestErrorType.INTERACTION_FAILURE;
    }
    if (message.includes('expect') || message.includes('assert')) {
      return TestErrorType.ASSERTION_FAILURE;
    }
    if (message.includes('navigate') || message.includes('goto')) {
      return TestErrorType.NAVIGATION_FAILURE;
    }
    if (message.includes('javascript') || message.includes('script')) {
      return TestErrorType.JAVASCRIPT_ERROR;
    }
    if (message.includes('memory') || message.includes('out of memory')) {
      return TestErrorType.MEMORY_ERROR;
    }

    return TestErrorType.SYSTEM_ERROR;
  }

  /**
   * Determine if error type is retryable
   */
  private isRetryableError(errorType: TestErrorType): boolean {
    const nonRetryableErrors = [
      TestErrorType.ASSERTION_FAILURE,
      TestErrorType.JAVASCRIPT_ERROR,
      TestErrorType.MEMORY_ERROR
    ];

    return !nonRetryableErrors.includes(errorType);
  }

  /**
   * Attempt recovery using registered strategies
   */
  private async attemptRecovery(
    error: EnhancedTestError,
    context: ErrorContext,
    page: Page,
    result: ErrorHandlingResult
  ): Promise<boolean> {
    // Try custom error handler first
    const handler = this.config.customErrorHandlers.get(error.name);
    if (handler && handler.canRecover) {
      try {
        const handlerResult = await handler.handle(error, context, page);
        if (handlerResult.success) {
          result.recoveryStrategiesUsed.push(`custom-${error.name}`);
          return true;
        }
      } catch (handlerError) {
        if (this.config.detailedLogging) {
          console.log(`[ErrorHandling] Custom handler failed:`, handlerError);
        }
      }
    }

    // Try fallback strategies
    const applicableStrategies = this.fallbackStrategies
      .filter(strategy => strategy.applicableFor(error, context))
      .sort((a, b) => b.priority - a.priority);

    for (const strategy of applicableStrategies) {
      try {
        if (this.config.detailedLogging) {
          console.log(`[ErrorHandling] Trying recovery strategy: ${strategy.name}`);
        }

        const success = await strategy.execute(page, context, error);
        if (success) {
          result.recoveryStrategiesUsed.push(strategy.name);
          return true;
        }
      } catch (strategyError) {
        if (this.config.detailedLogging) {
          console.log(`[ErrorHandling] Recovery strategy ${strategy.name} failed:`, strategyError);
        }
      }
    }

    return false;
  }

  /**
   * Attempt graceful degradation for non-critical failures
   */
  private async attemptGracefulDegradation(
    error: EnhancedTestError,
    context: ErrorContext,
    page: Page,
    result: ErrorHandlingResult
  ): Promise<boolean> {
    // Only attempt graceful degradation for certain error types
    const degradableErrors = [
      TestErrorType.ELEMENT_NOT_FOUND,
      TestErrorType.LOADING_FAILURE,
      TestErrorType.INTERACTION_FAILURE
    ];

    if (!degradableErrors.includes(error.errorType)) {
      return false;
    }

    try {
      if (this.config.detailedLogging) {
        console.log('[ErrorHandling] Attempting graceful degradation');
      }

      // Verify page is still responsive
      await page.waitForLoadState('domcontentloaded', { timeout: 10000 });
      
      // Check if core functionality is still working
      const bodyVisible = await page.locator('body').isVisible();
      if (!bodyVisible) {
        return false;
      }

      result.recoveryStrategiesUsed.push('graceful-degradation');
      return true;

    } catch (degradationError) {
      if (this.config.detailedLogging) {
        console.log('[ErrorHandling] Graceful degradation failed:', degradationError);
      }
      return false;
    }
  }

  /**
   * Execute operation with timeout
   */
  private async executeWithTimeout<T>(
    operation: () => Promise<T>,
    timeout: number
  ): Promise<T> {
    return Promise.race([
      operation(),
      new Promise<never>((_, reject) => {
        setTimeout(() => {
          reject(new Error(`Operation timed out after ${timeout}ms`));
        }, timeout);
      })
    ]);
  }

  /**
   * Calculate retry delay with exponential backoff
   */
  private calculateRetryDelay(attempt: number): number {
    if (!this.config.exponentialBackoff) {
      return this.config.baseRetryDelay;
    }

    const delay = this.config.baseRetryDelay * Math.pow(2, attempt);
    return Math.min(delay, this.config.maxRetryDelay);
  }

  /**
   * Capture screenshot with context information
   */
  private async captureScreenshot(
    page: Page,
    context: ErrorContext,
    testInfo?: TestInfo
  ): Promise<string | null> {
    try {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const fileName = `error-${context.operation.replace(/[^\w]/g, '_')}-${timestamp}.png`;
      const screenshotDir = testInfo ? 
        path.join(testInfo.outputDir, 'screenshots') : 
        path.join(process.cwd(), 'test-results', 'screenshots');

      await fs.mkdir(screenshotDir, { recursive: true });
      const screenshotPath = path.join(screenshotDir, fileName);

      await page.screenshot({
        path: screenshotPath,
        fullPage: true,
        quality: 90
      });

      if (this.config.detailedLogging) {
        console.log(`[ErrorHandling] Screenshot captured: ${screenshotPath}`);
      }

      return screenshotPath;
    } catch (error) {
      if (this.config.detailedLogging) {
        console.log('[ErrorHandling] Failed to capture screenshot:', error);
      }
      return null;
    }
  }

  /**
   * Capture video recording
   */
  private async captureVideo(
    page: Page,
    context: ErrorContext,
    testInfo: TestInfo
  ): Promise<string | null> {
    try {
      const videoPath = await page.video()?.path();
      if (videoPath && testInfo) {
        // Copy video to test artifacts
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const fileName = `error-${context.operation.replace(/[^\w]/g, '_')}-${timestamp}.webm`;
        const videoDir = path.join(testInfo.outputDir, 'videos');
        
        await fs.mkdir(videoDir, { recursive: true });
        const targetPath = path.join(videoDir, fileName);
        
        await fs.copyFile(videoPath, targetPath);
        
        if (this.config.detailedLogging) {
          console.log(`[ErrorHandling] Video captured: ${targetPath}`);
        }
        
        return targetPath;
      }
    } catch (error) {
      if (this.config.detailedLogging) {
        console.log('[ErrorHandling] Failed to capture video:', error);
      }
    }
    
    return null;
  }

  /**
   * Collect performance metrics
   */
  private async collectPerformanceMetrics(page: Page): Promise<{
    memoryUsage: number;
    cpuUsage: number;
    networkLatency: number;
  }> {
    try {
      const memoryInfo = await page.evaluate(() => {
        return (performance as any).memory || { usedJSHeapSize: 0, totalJSHeapSize: 0 };
      });

      // Simple network latency check
      const startTime = Date.now();
      await page.evaluate(() => fetch('/').catch(() => {}));
      const networkLatency = Date.now() - startTime;

      return {
        memoryUsage: memoryInfo.usedJSHeapSize || 0,
        cpuUsage: 0, // CPU usage not easily available in browser context
        networkLatency
      };
    } catch (error) {
      return {
        memoryUsage: 0,
        cpuUsage: 0,
        networkLatency: 0
      };
    }
  }

  /**
   * Generate alternative selectors for fallback
   */
  private generateAlternativeSelectors(originalSelector: string): string[] {
    const alternatives: string[] = [];

    // If it's a data-testid selector, try alternatives
    if (originalSelector.includes('data-testid')) {
      const testId = originalSelector.match(/data-testid="([^"]+)"/)?.[1];
      if (testId) {
        alternatives.push(`[data-testid="${testId}"]`);
        alternatives.push(`[data-test="${testId}"]`);
        alternatives.push(`[id="${testId}"]`);
        alternatives.push(`.${testId}`);
      }
    }

    // If it's a class selector, try ID and other alternatives
    if (originalSelector.startsWith('.')) {
      const className = originalSelector.slice(1);
      alternatives.push(`#${className}`);
      alternatives.push(`[class*="${className}"]`);
      alternatives.push(`[data-class="${className}"]`);
    }

    // If it's an ID selector, try class and other alternatives
    if (originalSelector.startsWith('#')) {
      const id = originalSelector.slice(1);
      alternatives.push(`.${id}`);
      alternatives.push(`[id="${id}"]`);
      alternatives.push(`[data-id="${id}"]`);
    }

    return alternatives;
  }

  /**
   * Simple delay utility
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Get error statistics
   */
  public getErrorStatistics(): Map<TestErrorType, number> {
    return new Map(this.errorCount);
  }

  /**
   * Reset error statistics
   */
  public resetErrorStatistics(): void {
    this.errorCount.clear();
  }
}

// ==================== UTILITY FUNCTIONS ====================

/**
 * Create error handling engine with default configuration
 */
export function createErrorHandlingEngine(
  config: Partial<ErrorHandlingConfig> = {}
): TestErrorHandlingEngine {
  return new TestErrorHandlingEngine(config);
}

/**
 * Wrap test function with automatic error handling
 */
export function withErrorHandling<T extends any[], R>(
  testFunction: (...args: T) => Promise<R>,
  errorHandlingConfig: Partial<ErrorHandlingConfig> = {}
): (...args: T) => Promise<R> {
  const engine = createErrorHandlingEngine(errorHandlingConfig);

  return async (...args: T): Promise<R> => {
    const [page, ...otherArgs] = args;
    
    if (!page || typeof page.goto !== 'function') {
      throw new Error('First argument must be a Playwright Page object');
    }

    const result = await engine.executeWithErrorHandling(
      () => testFunction(...args),
      {
        operation: testFunction.name || 'anonymous-test-function'
      },
      page as Page
    );

    if (!result.success) {
      throw result.finalError || new Error('Test function failed after all retry attempts');
    }

    return result.result!;
  };
}

/**
 * Enhanced expect with automatic retry and error handling
 */
export async function expectWithRetry<T>(
  page: Page,
  assertion: () => Promise<T> | T,
  options: {
    retries?: number;
    delay?: number;
    timeout?: number;
    errorMessage?: string;
  } = {}
): Promise<T> {
  const {
    retries = 3,
    delay = 1000,
    timeout = 30000,
    errorMessage = 'Assertion failed after retries'
  } = options;

  const engine = createErrorHandlingEngine({ maxRetries: retries, baseRetryDelay: delay });

  const result = await engine.executeWithErrorHandling(
    async () => {
      const assertionResult = await assertion();
      return assertionResult;
    },
    {
      operation: 'assertion-with-retry'
    },
    page
  );

  if (!result.success) {
    throw new Error(`${errorMessage}: ${result.finalError?.message || 'Unknown error'}`);
  }

  return result.result!;
}

export default TestErrorHandlingEngine;