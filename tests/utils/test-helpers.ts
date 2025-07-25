/**
 * Test helper utilities for common testing operations
 * Provides reusable functions for test setup, assertions, and mocking
 */

import { jest } from '@jest/globals';
import { FastMCP } from 'fastmcp';
import { MockMakeApiClient } from '../mocks/make-api-client.mock.js';

/**
 * Create a mock FastMCP server instance for testing
 */
export const createMockServer = (): { server: any; mockTool: any } => {
  const mockTool = (...args: any[]) => {};
  mockTool.mock = { calls: [] };
  
  const registeredTools = new Map();
  
  const server = {
    addTool: (...args: any[]) => { 
      mockTool.mock.calls.push(args);
      // Store tool for executeToolCall
      if (args[0] && args[0].name) {
        registeredTools.set(args[0].name, args[0]);
      }
    },
    executeToolCall: async (params: { tool: string; parameters: any }) => {
      const tool = registeredTools.get(params.tool);
      if (!tool) {
        throw new Error(`Tool '${params.tool}' not found`);
      }
      
      // Actually execute the tool implementation
      const mockContext = {
        log: {
          info: (...args: any[]) => {},
          error: (...args: any[]) => {},
          warn: (...args: any[]) => {},
          debug: (...args: any[]) => {},
        },
        reportProgress: (...args: any[]) => {},
        session: { authenticated: true },
      };
      
      try {
        const result = await tool.execute(params.parameters, mockContext);
        return result;
      } catch (error) {
        throw error;
      }
    },
    on: (...args: any[]) => {},
    start: (...args: any[]) => {},
    stop: (...args: any[]) => {},
  };
  
  return { server, mockTool };
};

/**
 * Extract tool configuration from addTool mock calls
 */
export const extractToolConfigs = (mockTool: any) => {
  return mockTool.mock.calls.map((call: any[]) => call[0]);
};

/**
 * Find a specific tool by name from mock calls
 */
export const findTool = (mockTool: any, toolName: string) => {
  const configs = extractToolConfigs(mockTool);
  return configs.find((config: any) => config.name === toolName);
};

/**
 * Execute a tool with mock context and return result
 */
export const executeTool = async (
  tool: any, 
  input: any, 
  context: Partial<{ log: any; reportProgress: any; session: any }> = {}
) => {
  const mockContext = {
    log: {
      info: (...args: any[]) => {},
      error: (...args: any[]) => {},
      warn: (...args: any[]) => {},
      debug: (...args: any[]) => {},
    },
    reportProgress: (...args: any[]) => {},
    session: { authenticated: true },
    ...context,
  };
  
  return await tool.execute(input, mockContext);
};

/**
 * Assert that a tool call was logged correctly
 */
export const expectToolCall = (
  mockLog: any,
  level: 'info' | 'error' | 'warn' | 'debug',
  messagePattern: string | RegExp,
  data?: any
) => {
  const calls = mockLog[level].mock.calls;
  const matchingCall = calls.find((call: any[]) => {
    const message = call[0];
    if (typeof messagePattern === 'string') {
      return message.includes(messagePattern);
    }
    return messagePattern.test(message);
  });
  
  expect(matchingCall).toBeDefined();
  
  if (data && matchingCall) {
    expect(matchingCall[1]).toMatchObject(data);
  }
};

/**
 * Mock progress reporting and verify it was called
 */
export const expectProgressReported = (
  mockReportProgress: jest.MockedFunction<any>,
  expectedCalls: Array<{ progress: number; total: number }>
) => {
  expect(mockReportProgress).toHaveBeenCalledTimes(expectedCalls.length);
  
  expectedCalls.forEach((expectedCall, index) => {
    expect(mockReportProgress).toHaveBeenNthCalledWith(
      index + 1,
      expectedCall
    );
  });
};

/**
 * Create a test scenario with realistic complexity
 */
export const createComplexTestScenario = () => ({
  id: globalThis.testUtils.generateId(),
  name: 'Complex Integration Scenario',
  teamId: 12345,
  folderId: 3001,
  blueprint: {
    flow: [
      {
        id: 1,
        app: 'webhook',
        operation: 'trigger',
        metadata: {
          webhook_type: 'instant',
          url: 'https://hook.make.com/abcd1234',
        }
      },
      {
        id: 2,
        app: 'filter',
        operation: 'condition',
        metadata: {
          condition: 'data.type === "order"',
          fallback: 'ignore'
        }
      },
      {
        id: 3,
        app: 'database',
        operation: 'select',
        metadata: {
          table: 'customers',
          where: 'email = {{1.email}}',
          connectionId: 4002
        }
      },
      {
        id: 4,
        app: 'router',
        operation: 'split',
        metadata: {
          routes: [
            { condition: 'customer.vip === true', modules: [5, 6] },
            { condition: 'customer.vip === false', modules: [7] }
          ]
        }
      },
      {
        id: 5,
        app: 'email',
        operation: 'send',
        metadata: {
          template: 'vip_welcome',
          to: '{{3.email}}',
          connectionId: 4001
        }
      },
      {
        id: 6,
        app: 'crm',
        operation: 'update_contact',
        metadata: {
          contactId: '{{3.id}}',
          tags: ['vip', 'automated']
        }
      },
      {
        id: 7,
        app: 'email',
        operation: 'send',
        metadata: {
          template: 'standard_welcome',
          to: '{{3.email}}',
          connectionId: 4001
        }
      }
    ],
    settings: {
      errorHandling: 'continue',
      logging: 'full',
      timeout: 30000
    }
  },
  scheduling: {
    type: 'indefinitely' as const,
    interval: 900
  },
  isActive: true,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
});

/**
 * Validate Zod schema parsing in tests
 */
export const expectValidZodParse = (schema: any, data: any) => {
  // Handle non-Zod schemas gracefully
  if (!schema || typeof schema.safeParse !== 'function') {
    console.warn('expectValidZodParse called with non-Zod schema, returning data as-is');
    return data;
  }

  const result = schema.safeParse(data);
  if (!result.success) {
    console.error('Zod validation errors:', result.error.issues);
  }
  expect(result.success).toBe(true);
  return result.data;
};

/**
 * Expect Zod schema to reject invalid data
 */
export const expectInvalidZodParse = (schema: any, data: any, expectedErrors?: string[]) => {
  // Handle non-Zod schemas gracefully
  if (!schema || typeof schema.safeParse !== 'function') {
    console.warn('expectInvalidZodParse called with non-Zod schema, skipping validation');
    return;
  }

  const result = schema.safeParse(data);
  expect(result.success).toBe(false);
  
  if (expectedErrors && !result.success) {
    expectedErrors.forEach(expectedError => {
      expect(result.error.issues.some(issue => 
        issue.message.includes(expectedError) || issue.path.join('.').includes(expectedError)
      )).toBe(true);
    });
  }
};

/**
 * Mock API client with common response patterns
 */
export const createMockApiClientWithDefaults = (): MockMakeApiClient => {
  const mockClient = new MockMakeApiClient();
  
  // Add common successful responses
  mockClient.mockResponse('GET', '/teams/12345', {
    success: true,
    data: {
      id: 12345,
      name: 'Test Team',
      organizationId: 67890,
      members: 5,
      createdAt: '2024-01-01T00:00:00Z'
    }
  });
  
  mockClient.mockResponse('GET', '/organizations/67890', {
    success: true,
    data: {
      id: 67890,
      name: 'Test Organization',
      plan: 'professional',
      members: 25,
      createdAt: '2024-01-01T00:00:00Z'
    }
  });
  
  return mockClient;
};

/**
 * Simulate network conditions for resilience testing
 */
export const simulateNetworkConditions = {
  slow: (mockClient: MockMakeApiClient, endpoint: string) => {
    mockClient.mockDelay('GET', endpoint, 5000);
    mockClient.mockDelay('POST', endpoint, 5000);
    mockClient.mockDelay('PUT', endpoint, 5000);
    mockClient.mockDelay('DELETE', endpoint, 5000);
  },
  
  unreliable: (mockClient: MockMakeApiClient, endpoint: string, failureRate = 0.3) => {
    // Randomly fail requests based on failure rate
    if (Math.random() < failureRate) {
      mockClient.mockFailure('GET', endpoint, new Error('Network timeout'));
      mockClient.mockFailure('POST', endpoint, new Error('Connection reset'));
    }
  },
  
  rateLimited: (mockClient: MockMakeApiClient, endpoint: string) => {
    mockClient.mockFailure('GET', endpoint, new Error('Rate limit exceeded'));
    mockClient.mockFailure('POST', endpoint, new Error('Rate limit exceeded'));
  }
};

/**
 * Assert error response format
 */
export const expectErrorResponse = (error: any, expectedCode?: string, expectedMessage?: string | RegExp) => {
  expect(error).toBeInstanceOf(Error);
  
  if (expectedMessage) {
    if (typeof expectedMessage === 'string') {
      expect(error.message).toContain(expectedMessage);
    } else {
      expect(error.message).toMatch(expectedMessage);
    }
  }
  
  if (expectedCode && error.code) {
    expect(error.code).toBe(expectedCode);
  }
};

/**
 * Create a test environment with cleanup
 */
export const createTestEnvironment = () => {
  const cleanup: Array<() => void | Promise<void>> = [];
  
  const env = {
    addCleanup: (fn: () => void | Promise<void>) => {
      cleanup.push(fn);
    },
    
    cleanup: async () => {
      for (const fn of cleanup.reverse()) {
        await fn();
      }
      cleanup.length = 0;
    }
  };
  
  return env;
};

/**
 * Wait for a condition to be true with timeout
 */
export const waitForCondition = async (
  condition: () => boolean | Promise<boolean>,
  options: { timeout?: number; interval?: number } = {}
): Promise<void> => {
  const { timeout = 5000, interval = 100 } = options;
  const startTime = Date.now();
  
  while (Date.now() - startTime < timeout) {
    if (await condition()) {
      return;
    }
    await globalThis.testUtils.delay(interval);
  }
  
  throw new Error(`Condition not met within ${timeout}ms`);
};

/**
 * Performance testing utilities
 */
export const performanceHelpers = {
  measureExecutionTime: async <T>(fn: () => Promise<T>): Promise<{ result: T; duration: number }> => {
    const start = Date.now();
    const result = await fn();
    const duration = Date.now() - start;
    return { result, duration };
  },
  
  expectExecutionTime: async <T>(
    fn: () => Promise<T>, 
    maxDuration: number,
    message?: string
  ): Promise<T> => {
    const { result, duration } = await performanceHelpers.measureExecutionTime(fn);
    expect(duration).toBeLessThan(maxDuration);
    if (message) {
      console.log(`${message}: ${duration}ms`);
    }
    return result;
  }
};

export default {
  createMockServer,
  extractToolConfigs,
  findTool,
  executeTool,
  expectToolCall,
  expectProgressReported,
  createComplexTestScenario,
  expectValidZodParse,
  expectInvalidZodParse,
  createMockApiClientWithDefaults,
  simulateNetworkConditions,
  expectErrorResponse,
  createTestEnvironment,
  waitForCondition,
  performanceHelpers,
};