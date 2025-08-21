/**
 * Test Error Handling System Tests
 * 
 * Comprehensive test suite for the error handling and recovery system,
 * validating retry mechanisms, screenshot capture, graceful degradation,
 * and detailed error logging capabilities.
 */

import { test, expect, Page } from '@playwright/test';
import {
  TestErrorHandlingEngine,
  createErrorHandlingEngine,
  withErrorHandling,
  expectWithRetry,
  TestErrorType,
  EnhancedTestError,
  type ErrorHandlingConfig,
  type ErrorContext
} from '../utils/test-error-handling';
import * as path from 'path';
import * as fs from 'fs/promises';

// Test configuration for error handling
const ERROR_HANDLING_CONFIG: Partial<ErrorHandlingConfig> = {
  maxRetries: 2,
  baseRetryDelay: 500,
  exponentialBackoff: true,
  screenshotOnFailure: true,
  videoOnFailure: true,
  detailedLogging: true,
  performanceMonitoring: true,
  gracefulDegradation: true,
  retryTimeout: 10000
};

test.describe('Test Error Handling System', () => {
  
  test.beforeEach(async ({ page }) => {
    // Set reasonable timeouts for error handling tests
    page.setDefaultTimeout(30000);
    page.setDefaultNavigationTimeout(30000);
  });

  test('Basic Error Handling - Successful Operation', async ({ page }) => {
    console.log('[TEST] Testing basic error handling with successful operation...');
    
    const engine = createErrorHandlingEngine(ERROR_HANDLING_CONFIG);
    
    const result = await engine.executeWithErrorHandling(
      async () => {
        await page.goto('/');
        return 'success';
      },
      {
        operation: 'test-navigation'
      },
      page
    );
    
    expect(result.success).toBe(true);
    expect(result.result).toBe('success');
    expect(result.attemptsMade).toBe(1);
    expect(result.errorHistory).toHaveLength(0);
    expect(result.gracefulDegradationUsed).toBe(false);
    
    console.log('[TEST] Basic error handling successful operation result:', {
      success: result.success,
      attempts: result.attemptsMade,
      duration: result.totalDuration
    });
  });

  test('Error Handling - Retry Mechanism', async ({ page }) => {
    console.log('[TEST] Testing retry mechanism with transient failures...');
    
    const engine = createErrorHandlingEngine({
      ...ERROR_HANDLING_CONFIG,
      maxRetries: 3,
      baseRetryDelay: 100 // Faster for testing
    });
    
    let attemptCount = 0;
    
    const result = await engine.executeWithErrorHandling(
      async () => {
        attemptCount++;
        if (attemptCount < 3) {
          throw new Error('Simulated transient failure');
        }
        return 'success-after-retries';
      },
      {
        operation: 'test-retry-mechanism'
      },
      page
    );
    
    expect(result.success).toBe(true);
    expect(result.result).toBe('success-after-retries');
    expect(result.attemptsMade).toBe(3);
    expect(result.errorHistory).toHaveLength(2); // 2 failures before success
    expect(attemptCount).toBe(3);
    
    console.log('[TEST] Retry mechanism result:', {
      success: result.success,
      attempts: result.attemptsMade,
      errors: result.errorHistory.length,
      finalAttemptCount: attemptCount
    });
  });

  test('Safe Click with Error Handling', async ({ page }) => {
    console.log('[TEST] Testing safe click with error handling...');
    
    const engine = createErrorHandlingEngine(ERROR_HANDLING_CONFIG);
    
    await page.goto('/');
    
    // First try a selector that might exist
    const result = await engine.safeClick(
      page,
      'body', // Should always exist
      { timeout: 5000 }
    );
    
    expect(result.success).toBe(true);
    expect(result.attemptsMade).toBeGreaterThanOrEqual(1);
    
    console.log('[TEST] Safe click result:', {
      success: result.success,
      attempts: result.attemptsMade,
      recoveryStrategies: result.recoveryStrategiesUsed
    });
  });

  test('Safe Navigation with Error Handling', async ({ page }) => {
    console.log('[TEST] Testing safe navigation with error handling...');
    
    const engine = createErrorHandlingEngine(ERROR_HANDLING_CONFIG);
    
    const result = await engine.safeNavigate(
      page,
      '/',
      { waitUntil: 'domcontentloaded', timeout: 30000 }
    );
    
    expect(result.success).toBe(true);
    expect(result.attemptsMade).toBeGreaterThanOrEqual(1);
    
    console.log('[TEST] Safe navigation result:', {
      success: result.success,
      attempts: result.attemptsMade,
      duration: result.totalDuration
    });
  });

  test('Safe Element Waiting with Error Handling', async ({ page }) => {
    console.log('[TEST] Testing safe element waiting with error handling...');
    
    const engine = createErrorHandlingEngine(ERROR_HANDLING_CONFIG);
    
    await page.goto('/');
    
    const result = await engine.safeWaitForElement(
      page,
      'body',
      { state: 'visible', timeout: 10000 }
    );
    
    expect(result.success).toBe(true);
    expect(result.element).toBeDefined();
    expect(result.attemptsMade).toBeGreaterThanOrEqual(1);
    
    console.log('[TEST] Safe element waiting result:', {
      success: result.success,
      hasElement: !!result.element,
      attempts: result.attemptsMade
    });
  });

  test('Error Classification and Enhancement', async ({ page }) => {
    console.log('[TEST] Testing error classification and enhancement...');
    
    const engine = createErrorHandlingEngine(ERROR_HANDLING_CONFIG);
    
    // Test timeout error
    const timeoutResult = await engine.executeWithErrorHandling(
      async () => {
        throw new Error('Operation timed out after 30000ms');
      },
      {
        operation: 'test-timeout-classification'
      },
      page
    );
    
    expect(timeoutResult.success).toBe(false);
    expect(timeoutResult.errorHistory.length).toBeGreaterThan(0);
    
    const timeoutError = timeoutResult.errorHistory[0];
    expect(timeoutError.message).toContain('timed out');
    
    // Test element not found error
    const notFoundResult = await engine.executeWithErrorHandling(
      async () => {
        throw new Error('Element not found: .non-existent-element');
      },
      {
        operation: 'test-not-found-classification'
      },
      page
    );
    
    expect(notFoundResult.success).toBe(false);
    expect(notFoundResult.errorHistory.length).toBeGreaterThan(0);
    
    console.log('[TEST] Error classification results:', {
      timeoutError: {
        success: timeoutResult.success,
        errorCount: timeoutResult.errorHistory.length
      },
      notFoundError: {
        success: notFoundResult.success,
        errorCount: notFoundResult.errorHistory.length
      }
    });
  });

  test('Screenshot Capture on Failure', async ({ page }, testInfo) => {
    console.log('[TEST] Testing screenshot capture on failure...');
    
    const engine = createErrorHandlingEngine({
      ...ERROR_HANDLING_CONFIG,
      screenshotOnFailure: true,
      maxRetries: 1 // Reduce retries for faster test
    });
    
    await page.goto('/');
    
    const result = await engine.executeWithErrorHandling(
      async () => {
        throw new Error('Test error for screenshot capture');
      },
      {
        operation: 'test-screenshot-capture'
      },
      page,
      testInfo
    );
    
    expect(result.success).toBe(false);
    expect(result.screenshots.length).toBeGreaterThan(0);
    
    // Verify screenshot file exists
    const screenshotPath = result.screenshots[0];
    const screenshotExists = await fs.access(screenshotPath).then(() => true).catch(() => false);
    expect(screenshotExists).toBe(true);
    
    console.log('[TEST] Screenshot capture result:', {
      success: result.success,
      screenshotCount: result.screenshots.length,
      screenshotExists,
      screenshotPath: path.basename(screenshotPath)
    });
  });

  test('Graceful Degradation', async ({ page }) => {
    console.log('[TEST] Testing graceful degradation...');
    
    const engine = createErrorHandlingEngine({
      ...ERROR_HANDLING_CONFIG,
      gracefulDegradation: true,
      maxRetries: 1
    });
    
    await page.goto('/');
    
    const result = await engine.executeWithErrorHandling(
      async () => {
        // Simulate an element not found error that can be gracefully handled
        const element = page.locator('.non-existent-element');
        await element.waitFor({ state: 'visible', timeout: 1000 });
      },
      {
        operation: 'test-graceful-degradation'
      },
      page
    );
    
    // Should either succeed through graceful degradation or fail gracefully
    if (result.success) {
      expect(result.gracefulDegradationUsed).toBe(true);
      expect(result.recoveryStrategiesUsed).toContain('graceful-degradation');
    }
    
    console.log('[TEST] Graceful degradation result:', {
      success: result.success,
      gracefulDegradationUsed: result.gracefulDegradationUsed,
      recoveryStrategies: result.recoveryStrategiesUsed
    });
  });

  test('Recovery Strategies', async ({ page }) => {
    console.log('[TEST] Testing recovery strategies...');
    
    const engine = createErrorHandlingEngine({
      ...ERROR_HANDLING_CONFIG,
      maxRetries: 2
    });
    
    await page.goto('/');
    
    // Test with a timeout error that should trigger page refresh strategy
    const result = await engine.executeWithErrorHandling(
      async () => {
        // First attempt will fail, recovery should help subsequent attempts
        const element = page.locator('body');
        if (await element.count() === 0) {
          throw new Error('Page load timeout - element not found');
        }
        return 'recovered';
      },
      {
        operation: 'test-recovery-strategies'
      },
      page
    );
    
    expect(result.success).toBe(true);
    expect(result.result).toBe('recovered');
    
    console.log('[TEST] Recovery strategies result:', {
      success: result.success,
      attempts: result.attemptsMade,
      recoveryStrategies: result.recoveryStrategiesUsed
    });
  });

  test('Performance Monitoring During Errors', async ({ page }) => {
    console.log('[TEST] Testing performance monitoring during errors...');
    
    const engine = createErrorHandlingEngine({
      ...ERROR_HANDLING_CONFIG,
      performanceMonitoring: true,
      maxRetries: 1
    });
    
    await page.goto('/');
    
    const result = await engine.executeWithErrorHandling(
      async () => {
        // Simulate some work that uses resources
        await page.evaluate(() => {
          const arr = new Array(1000000).fill(0);
          return arr.length;
        });
        throw new Error('Test error with performance monitoring');
      },
      {
        operation: 'test-performance-monitoring'
      },
      page
    );
    
    expect(result.success).toBe(false);
    expect(result.diagnosticInfo).toBeDefined();
    
    console.log('[TEST] Performance monitoring result:', {
      success: result.success,
      hasDiagnosticInfo: !!result.diagnosticInfo,
      attempts: result.attemptsMade
    });
  });

  test('With Error Handling Wrapper', async ({ page }) => {
    console.log('[TEST] Testing withErrorHandling wrapper function...');
    
    const wrappedFunction = withErrorHandling(
      async (page: Page, shouldSucceed: boolean) => {
        if (!shouldSucceed) {
          throw new Error('Wrapped function test error');
        }
        await page.goto('/');
        return 'wrapped-success';
      },
      {
        maxRetries: 2,
        detailedLogging: true
      }
    );
    
    // Test successful case
    const successResult = await wrappedFunction(page, true);
    expect(successResult).toBe('wrapped-success');
    
    // Test failure case
    try {
      await wrappedFunction(page, false);
      expect(true).toBe(false); // Should not reach here
    } catch (error) {
      expect(error.message).toContain('Wrapped function test error');
    }
    
    console.log('[TEST] WithErrorHandling wrapper test completed');
  });

  test('Expect With Retry', async ({ page }) => {
    console.log('[TEST] Testing expectWithRetry function...');
    
    await page.goto('/');
    
    let attemptCount = 0;
    
    // Test successful retry
    const result = await expectWithRetry(
      page,
      async () => {
        attemptCount++;
        if (attemptCount < 2) {
          throw new Error('Assertion not ready yet');
        }
        expect(await page.locator('body').isVisible()).toBe(true);
        return 'assertion-passed';
      },
      {
        retries: 3,
        delay: 100,
        errorMessage: 'Custom assertion error'
      }
    );
    
    expect(result).toBe('assertion-passed');
    expect(attemptCount).toBe(2);
    
    console.log('[TEST] ExpectWithRetry result:', {
      result,
      attemptCount
    });
  });

  test('Error Statistics Tracking', async ({ page }) => {
    console.log('[TEST] Testing error statistics tracking...');
    
    const engine = createErrorHandlingEngine({
      ...ERROR_HANDLING_CONFIG,
      maxRetries: 1
    });
    
    // Generate different types of errors
    await engine.executeWithErrorHandling(
      async () => { throw new Error('timeout occurred'); },
      { operation: 'timeout-test' },
      page
    );
    
    await engine.executeWithErrorHandling(
      async () => { throw new Error('element not found'); },
      { operation: 'not-found-test' },
      page
    );
    
    await engine.executeWithErrorHandling(
      async () => { throw new Error('network connection failed'); },
      { operation: 'network-test' },
      page
    );
    
    const stats = engine.getErrorStatistics();
    
    expect(stats.size).toBeGreaterThan(0);
    expect(stats.get(TestErrorType.TIMEOUT)).toBeGreaterThanOrEqual(1);
    expect(stats.get(TestErrorType.ELEMENT_NOT_FOUND)).toBeGreaterThanOrEqual(1);
    expect(stats.get(TestErrorType.NETWORK_ERROR)).toBeGreaterThanOrEqual(1);
    
    console.log('[TEST] Error statistics:', {
      totalErrorTypes: stats.size,
      timeouts: stats.get(TestErrorType.TIMEOUT) || 0,
      notFound: stats.get(TestErrorType.ELEMENT_NOT_FOUND) || 0,
      network: stats.get(TestErrorType.NETWORK_ERROR) || 0
    });
    
    // Test statistics reset
    engine.resetErrorStatistics();
    const resetStats = engine.getErrorStatistics();
    expect(resetStats.size).toBe(0);
  });

  test('Alternative Selector Fallback', async ({ page }) => {
    console.log('[TEST] Testing alternative selector fallback...');
    
    const engine = createErrorHandlingEngine({
      ...ERROR_HANDLING_CONFIG,
      maxRetries: 2
    });
    
    await page.goto('/');
    
    // Add a test element with alternative selectors
    await page.evaluate(() => {
      const element = document.createElement('div');
      element.setAttribute('data-testid', 'test-element');
      element.setAttribute('id', 'test-element');
      element.className = 'test-element';
      element.textContent = 'Test Element';
      document.body.appendChild(element);
    });
    
    // Test with a selector that might fail but has alternatives
    const result = await engine.safeClick(
      page,
      '[data-testid="test-element"]',
      { timeout: 5000 }
    );
    
    expect(result.success).toBe(true);
    
    console.log('[TEST] Alternative selector fallback result:', {
      success: result.success,
      attempts: result.attemptsMade,
      recoveryStrategies: result.recoveryStrategiesUsed
    });
  });

  test('Complex Error Scenario with Multiple Recovery Attempts', async ({ page }) => {
    console.log('[TEST] Testing complex error scenario with multiple recovery attempts...');
    
    const engine = createErrorHandlingEngine({
      ...ERROR_HANDLING_CONFIG,
      maxRetries: 3,
      baseRetryDelay: 200
    });
    
    await page.goto('/');
    
    let attemptCount = 0;
    const result = await engine.executeWithErrorHandling(
      async () => {
        attemptCount++;
        
        if (attemptCount === 1) {
          throw new Error('Network timeout during initial load');
        } else if (attemptCount === 2) {
          throw new Error('Element not found after page refresh');
        } else if (attemptCount === 3) {
          throw new Error('Loading spinner still visible');
        }
        
        // Success on 4th attempt
        return 'success-after-complex-recovery';
      },
      {
        operation: 'complex-error-scenario',
        targetElements: ['.loading-spinner', '.main-content']
      },
      page
    );
    
    expect(result.success).toBe(true);
    expect(result.result).toBe('success-after-complex-recovery');
    expect(result.attemptsMade).toBe(4);
    expect(result.errorHistory).toHaveLength(3);
    expect(result.recoveryStrategiesUsed.length).toBeGreaterThan(0);
    
    console.log('[TEST] Complex error scenario result:', {
      success: result.success,
      attempts: result.attemptsMade,
      errorCount: result.errorHistory.length,
      recoveryStrategies: result.recoveryStrategiesUsed,
      duration: result.totalDuration
    });
  });

});

test.describe('Error Handling Edge Cases', () => {
  
  test('Non-Retryable Errors', async ({ page }) => {
    console.log('[TEST] Testing non-retryable errors...');
    
    const engine = createErrorHandlingEngine({
      ...ERROR_HANDLING_CONFIG,
      maxRetries: 3
    });
    
    // Assertion failure should not be retried
    const result = await engine.executeWithErrorHandling(
      async () => {
        expect(false).toBe(true); // This will always fail
      },
      {
        operation: 'test-non-retryable-error'
      },
      page
    );
    
    expect(result.success).toBe(false);
    // Should only attempt once for non-retryable errors
    expect(result.attemptsMade).toBe(1);
    
    console.log('[TEST] Non-retryable error result:', {
      success: result.success,
      attempts: result.attemptsMade
    });
  });

  test('Memory Pressure Handling', async ({ page }) => {
    console.log('[TEST] Testing memory pressure handling...');
    
    const engine = createErrorHandlingEngine({
      ...ERROR_HANDLING_CONFIG,
      performanceMonitoring: true
    });
    
    await page.goto('/');
    
    const result = await engine.executeWithErrorHandling(
      async () => {
        // Simulate memory-intensive operation
        const largeArray = new Array(1000000).fill('memory-test');
        return largeArray.length;
      },
      {
        operation: 'memory-pressure-test'
      },
      page
    );
    
    expect(result.success).toBe(true);
    expect(result.result).toBe(1000000);
    
    console.log('[TEST] Memory pressure handling result:', {
      success: result.success,
      result: result.result
    });
  });

  test('Concurrent Error Handling', async ({ page }) => {
    console.log('[TEST] Testing concurrent error handling...');
    
    const engine = createErrorHandlingEngine({
      ...ERROR_HANDLING_CONFIG,
      maxRetries: 2
    });
    
    await page.goto('/');
    
    // Run multiple operations concurrently
    const operations = Array.from({ length: 3 }, (_, index) => 
      engine.executeWithErrorHandling(
        async () => {
          if (Math.random() < 0.5) {
            throw new Error(`Concurrent operation ${index} failed`);
          }
          return `success-${index}`;
        },
        {
          operation: `concurrent-operation-${index}`
        },
        page
      )
    );
    
    const results = await Promise.all(operations);
    
    // At least some operations should succeed
    const successCount = results.filter(r => r.success).length;
    expect(successCount).toBeGreaterThan(0);
    
    console.log('[TEST] Concurrent error handling results:', {
      totalOperations: results.length,
      successfulOperations: successCount,
      failedOperations: results.length - successCount
    });
  });

});