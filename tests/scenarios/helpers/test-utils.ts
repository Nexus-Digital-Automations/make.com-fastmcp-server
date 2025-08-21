/**
 * Test utility functions for scenarios module testing
 * Provides common testing patterns and helper functions
 */

import { expect } from '@jest/globals';

/**
 * Assertion helpers for common testing patterns
 */
export const AssertionHelpers = {
  /**
   * Assert that a result contains success indicators
   */
  expectSuccessfulResult(result: string): void {
    expect(result.toLowerCase()).toContain('success');
    expect(result.toLowerCase()).not.toContain('error');
    expect(result.toLowerCase()).not.toContain('fail');
  },

  /**
   * Assert that a result contains error indicators
   */
  expectErrorResult(result: string, expectedErrorMessage?: string): void {
    expect(result.toLowerCase()).toContain('error');
    if (expectedErrorMessage) {
      expect(result.toLowerCase()).toContain(expectedErrorMessage.toLowerCase());
    }
  },

  /**
   * Assert tool result format
   */
  expectToolResultFormat(result: string): void {
    expect(typeof result).toBe('string');
    expect(result.length).toBeGreaterThan(0);
    
    // Try to parse as JSON to ensure it's well-formed
    try {
      const parsed = JSON.parse(result);
      expect(parsed).toHaveProperty('success');
    } catch {
      // If not JSON, should at least be meaningful text
      expect(result.trim().length).toBeGreaterThan(10);
    }
  },

  /**
   * Assert UUID format
   */
  expectValidUUID(value: string): void {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    expect(value).toMatch(uuidRegex);
  },

  /**
   * Assert API call was made with correct parameters
   */
  expectApiCall(mockFn: jest.MockedFunction<any>, method: string, endpoint: string, data?: any): void {
    expect(mockFn).toHaveBeenCalled();
    const lastCall = mockFn.mock.calls[mockFn.mock.calls.length - 1];
    
    if (method.toUpperCase() === 'GET') {
      expect(lastCall[0]).toBe(endpoint);
    } else {
      expect(lastCall[0]).toBe(endpoint);
      if (data) {
        expect(lastCall[1]).toEqual(expect.objectContaining(data));
      }
    }
  },

  /**
   * Assert logging was called with appropriate level
   */
  expectLogCall(mockLogger: any, level: 'info' | 'warn' | 'error' | 'debug', messageContains?: string): void {
    expect(mockLogger[level]).toHaveBeenCalled();
    if (messageContains) {
      const calls = mockLogger[level].mock.calls;
      const found = calls.some((call: any[]) => 
        call.some(arg => typeof arg === 'string' && arg.toLowerCase().includes(messageContains.toLowerCase()))
      );
      expect(found).toBe(true);
    }
  }
};

/**
 * Test workflow simulation utilities
 */
export class WorkflowSimulator {
  constructor(private server: any) {}

  async createScenario(data: any): Promise<any> {
    // Simulate scenario creation workflow
    return {
      id: `scenario-${Date.now()}`,
      ...data,
      isActive: false,
      createdAt: new Date().toISOString()
    };
  }

  async configureModules(scenarioId: string, modules: any[]): Promise<void> {
    // Simulate module configuration
    await new Promise(resolve => setTimeout(resolve, 10));
  }

  async testScenario(scenarioId: string): Promise<{ success: boolean }> {
    // Simulate scenario testing
    return { success: true };
  }

  async deployScenario(scenarioId: string): Promise<{ status: string }> {
    // Simulate scenario deployment
    return { status: 'active' };
  }

  async getScenarioStatus(scenarioId: string): Promise<{ isRunning: boolean }> {
    // Simulate status check
    return { isRunning: true };
  }
}

/**
 * Error testing utilities
 */
export const ErrorTestUtils = {
  /**
   * Test that a function throws with specific error message
   */
  async expectThrowsWithMessage(fn: () => Promise<any>, expectedMessage: string): Promise<void> {
    await expect(fn()).rejects.toThrow(expectedMessage);
  },

  /**
   * Test that a function handles errors gracefully
   */
  async expectGracefulErrorHandling(fn: () => Promise<string>, expectedErrorIndicator: string): Promise<void> {
    const result = await fn();
    expect(result.toLowerCase()).toContain(expectedErrorIndicator.toLowerCase());
    expect(result.toLowerCase()).not.toContain('uncaught');
    expect(result.toLowerCase()).not.toContain('undefined');
  },

  /**
   * Generate error scenarios for testing
   */
  generateErrorScenarios() {
    return [
      {
        name: 'Network timeout',
        error: new Error('Network timeout'),
        expectedMessage: 'timeout'
      },
      {
        name: 'Unauthorized access',
        error: new Error('Unauthorized'),
        expectedMessage: 'unauthorized'
      },
      {
        name: 'Resource not found',
        error: new Error('Not found'),
        expectedMessage: 'not found'
      },
      {
        name: 'Rate limit exceeded',
        error: new Error('Rate limit exceeded'),
        expectedMessage: 'rate limit'
      },
      {
        name: 'Server error',
        error: new Error('Internal server error'),
        expectedMessage: 'server error'
      }
    ];
  }
};

/**
 * Performance testing utilities
 */
export const PerformanceTestUtils = {
  /**
   * Run performance test with multiple iterations
   */
  async runPerformanceTest(
    testFn: () => Promise<any>, 
    iterations: number = 10
  ): Promise<{
    average: number;
    min: number;
    max: number;
    p95: number;
    results: any[];
  }> {
    const measurements: number[] = [];
    const results: any[] = [];

    for (let i = 0; i < iterations; i++) {
      const start = process.hrtime.bigint();
      const result = await testFn();
      const end = process.hrtime.bigint();
      
      const duration = Number(end - start) / 1_000_000; // Convert to ms
      measurements.push(duration);
      results.push(result);
    }

    const sorted = [...measurements].sort((a, b) => a - b);
    const average = measurements.reduce((sum, val) => sum + val, 0) / measurements.length;
    const min = sorted[0];
    const max = sorted[sorted.length - 1];
    const p95Index = Math.floor(0.95 * sorted.length);
    const p95 = sorted[p95Index];

    return { average, min, max, p95, results };
  },

  /**
   * Test concurrent operations
   */
  async testConcurrentOperations(
    testFn: () => Promise<any>,
    concurrency: number = 5
  ): Promise<{
    successful: number;
    failed: number;
    totalTime: number;
    results: Array<{ status: 'fulfilled' | 'rejected'; value?: any; reason?: any }>;
  }> {
    const start = process.hrtime.bigint();
    
    const promises = Array(concurrency).fill(0).map(() => testFn());
    const results = await Promise.allSettled(promises);
    
    const end = process.hrtime.bigint();
    const totalTime = Number(end - start) / 1_000_000;

    const successful = results.filter(r => r.status === 'fulfilled').length;
    const failed = results.filter(r => r.status === 'rejected').length;

    return {
      successful,
      failed,
      totalTime,
      results
    };
  }
};

/**
 * Schema testing utilities
 */
export const SchemaTestUtils = {
  /**
   * Test schema with valid and invalid data sets
   */
  testSchemaValidation(schema: any, testCases: {
    valid: any[];
    invalid: any[];
  }): void {
    // Test valid cases
    testCases.valid.forEach((validCase, index) => {
      expect(() => schema.parse(validCase)).not.toThrow(`Valid case ${index} should pass validation`);
    });

    // Test invalid cases
    testCases.invalid.forEach((invalidCase, index) => {
      expect(() => schema.parse(invalidCase)).toThrow(`Invalid case ${index} should fail validation`);
    });
  },

  /**
   * Generate comprehensive schema test cases
   */
  generateSchemaTestCases(baseValid: any): {
    valid: any[];
    invalid: any[];
  } {
    return {
      valid: [
        baseValid,
        { ...baseValid, additionalField: 'should be ignored' }
      ],
      invalid: [
        {},
        null,
        undefined,
        'not an object',
        123,
        [],
        { ...baseValid, name: '' }, // Empty required field
        { ...baseValid, name: null }, // Null required field
        { ...baseValid, name: 123 }, // Wrong type
      ]
    };
  }
};

/**
 * Integration testing utilities
 */
export const IntegrationTestUtils = {
  /**
   * Wait for async operations to complete
   */
  async waitForAsync(conditionFn: () => boolean, timeout: number = 5000): Promise<void> {
    const start = Date.now();
    while (!conditionFn()) {
      if (Date.now() - start > timeout) {
        throw new Error(`Condition not met within ${timeout}ms`);
      }
      await new Promise(resolve => setTimeout(resolve, 50));
    }
  },

  /**
   * Retry operation with exponential backoff
   */
  async retryWithBackoff<T>(
    operation: () => Promise<T>,
    maxAttempts: number = 3,
    baseDelay: number = 100
  ): Promise<T> {
    let lastError: Error;
    
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error as Error;
        
        if (attempt === maxAttempts) {
          throw lastError;
        }
        
        const delay = baseDelay * Math.pow(2, attempt - 1);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
    
    throw lastError!;
  }
};