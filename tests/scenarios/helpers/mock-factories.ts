/**
 * Enhanced mock factory functions for testing all modules
 * Provides reusable mock creation patterns for scenarios, log-streaming, and enterprise-secrets modules
 */

import { jest } from '@jest/globals';
import type MakeApiClient from '../../../src/lib/make-api-client.js';
import type { ToolContext } from '../../../src/tools/shared/types/tool-context.js';

/**
 * Create mock API client with jest spies
 */
export function createMockApiClient(): jest.Mocked<MakeApiClient> {
  return {
    get: jest.fn(),
    post: jest.fn(), 
    put: jest.fn(),
    delete: jest.fn(),
    patch: jest.fn()
  } as jest.Mocked<MakeApiClient>;
}

/**
 * Create mock logger with jest spies
 */
export function createMockLogger() {
  return {
    info: jest.fn(),
    warn: jest.fn(), 
    error: jest.fn(),
    debug: jest.fn(),
    child: jest.fn(() => createMockLogger())
  };
}

/**
 * Create tool context with optional overrides - supports all modules
 */
export function createToolContext(overrides: Partial<ToolContext> = {}): ToolContext {
  return {
    server: {} as never,
    apiClient: createMockApiClient(),
    logger: createMockLogger(),
    ...overrides
  };
}

/**
 * Create enhanced tool context for specific modules
 */
export function createModularToolContext(module: 'scenarios' | 'log-streaming' | 'enterprise-secrets', overrides: Partial<ToolContext> = {}): ToolContext {
  const baseContext = createToolContext(overrides);
  
  // Add module-specific enhancements
  switch (module) {
    case 'log-streaming':
      baseContext.apiClient.get.mockImplementation((endpoint: string) => {
        if (endpoint.includes('/executions') || endpoint.includes('/logs')) {
          return Promise.resolve({ success: true, data: [] });
        }
        return Promise.resolve({ success: true, data: {} });
      });
      break;
      
    case 'enterprise-secrets':
      baseContext.apiClient.get.mockImplementation((endpoint: string) => {
        if (endpoint.includes('/vault') || endpoint.includes('/hsm')) {
          return Promise.resolve({ success: true, data: { status: 'healthy' } });
        }
        return Promise.resolve({ success: true, data: {} });
      });
      baseContext.logger.audit = jest.fn();
      baseContext.logger.security = jest.fn();
      break;
      
    case 'scenarios':
    default:
      // Default scenarios module behavior
      baseContext.apiClient.get.mockImplementation((endpoint: string) => {
        if (endpoint.includes('/scenarios')) {
          return Promise.resolve({ success: true, data: [] });
        }
        return Promise.resolve({ success: true, data: {} });
      });
      break;
  }
  
  return baseContext;
}

/**
 * Create mock progress reporter
 */
export function createMockProgressReporter() {
  return jest.fn();
}

/**
 * Create mock execution context
 */
export function createMockExecutionContext() {
  return {
    log: createMockLogger(),
    reportProgress: createMockProgressReporter()
  };
}

/**
 * API Response builders for consistent mock responses
 */
export const ApiResponseBuilder = {
  success: <T>(data: T) => ({
    data,
    status: 200,
    statusText: 'OK',
    headers: {}
  }),
  
  error: (message: string, code: string = 'GENERIC_ERROR', status: number = 400) => ({
    response: {
      data: {
        error: { message, code }
      },
      status,
      statusText: 'Error'
    }
  }),
  
  notFound: (message: string = 'Resource not found') => ({
    response: {
      data: {
        error: { message, code: 'NOT_FOUND' }
      },
      status: 404,
      statusText: 'Not Found'
    }
  }),
  
  unauthorized: (message: string = 'Unauthorized') => ({
    response: {
      data: {
        error: { message, code: 'UNAUTHORIZED' }
      },
      status: 401,
      statusText: 'Unauthorized'
    }
  }),
  
  rateLimit: (message: string = 'Rate limit exceeded') => ({
    response: {
      data: {
        error: { message, code: 'RATE_LIMIT_EXCEEDED' }
      },
      status: 429,
      statusText: 'Too Many Requests'
    }
  })
};

/**
 * Mock server for integration testing
 */
export class MockApiServer {
  private routes: Map<string, any> = new Map();
  private delays: Map<string, number> = new Map();
  private failureRoutes: Set<string> = new Set();

  addRoute(method: string, path: string, response: any): void {
    const key = `${method.toUpperCase()} ${path}`;
    this.routes.set(key, response);
  }

  addDelay(path: string, delayMs: number): void {
    this.delays.set(path, delayMs);
  }

  addFailure(method: string, path: string): void {
    const key = `${method.toUpperCase()} ${path}`;
    this.failureRoutes.add(key);
  }

  async handleRequest(method: string, path: string): Promise<any> {
    const key = `${method.toUpperCase()} ${path}`;
    
    // Simulate delay if configured
    const delay = this.delays.get(path);
    if (delay) {
      await new Promise(resolve => setTimeout(resolve, delay));
    }
    
    // Simulate failure if configured
    if (this.failureRoutes.has(key)) {
      throw new Error('Mock server failure');
    }
    
    // Return mocked response
    const response = this.routes.get(key);
    if (!response) {
      throw ApiResponseBuilder.notFound(`Route not found: ${key}`);
    }
    
    return ApiResponseBuilder.success(response);
  }

  reset(): void {
    this.routes.clear();
    this.delays.clear();
    this.failureRoutes.clear();
  }
}

/**
 * Test utilities for performance measurement
 */
export const PerformanceTestUtils = {
  async measureExecutionTime<T>(fn: () => Promise<T>): Promise<{ result: T; executionTime: number }> {
    const start = process.hrtime.bigint();
    const result = await fn();
    const end = process.hrtime.bigint();
    const executionTime = Number(end - start) / 1_000_000; // Convert to milliseconds
    
    return { result, executionTime };
  },
  
  calculatePercentile(values: number[], percentile: number): number {
    const sorted = [...values].sort((a, b) => a - b);
    const index = Math.ceil((percentile / 100) * sorted.length) - 1;
    return sorted[Math.max(0, index)];
  },
  
  generateLoadTestData(count: number, baseData: any): any[] {
    return Array(count).fill(0).map((_, i) => ({
      ...baseData,
      name: `${baseData.name} ${i}`,
      id: `${baseData.id}-${i}`
    }));
  }
};

/**
 * Validation test utilities
 */
export const ValidationTestUtils = {
  testSchemaValidation: (schema: any, validData: any, invalidData: any[]) => {
    // Test valid data
    expect(() => schema.parse(validData)).not.toThrow();
    
    // Test invalid data
    invalidData.forEach(data => {
      expect(() => schema.parse(data)).toThrow();
    });
  },
  
  generateMaliciousInputs: () => [
    "'; DROP TABLE scenarios; --",
    '<script>alert("xss")</script>',
    '../../etc/passwd',
    '${process.env.SECRET_KEY}',
    'OR 1=1',
    '\u0000\u0001\u0002',
    'A'.repeat(10000) // Very long string
  ]
};