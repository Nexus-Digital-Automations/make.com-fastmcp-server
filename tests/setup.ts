/**
 * Global test setup and configuration
 * Initializes test environment for FastMCP server testing
 */

import { jest } from '@jest/globals';

// Setup test environment variables
process.env.NODE_ENV = 'test';
process.env.MAKE_API_KEY = 'test-api-key-12345';
process.env.MAKE_BASE_URL = 'https://test.make.com/api/v2';
process.env.LOG_LEVEL = 'error'; // Minimize logging during tests

// Global test utilities
declare global {
  var testTimeout: number;
}
global.testTimeout = 10000;

// Console overrides for cleaner test output
const originalConsoleError = console.error;
const originalConsoleWarn = console.warn;

beforeEach(() => {
  // Suppress console output during tests unless explicitly needed
  console.error = jest.fn();
  console.warn = jest.fn();
});

afterEach(() => {
  // Restore console methods
  console.error = originalConsoleError;
  console.warn = originalConsoleWarn;
  
  // Clear all mocks
  jest.clearAllMocks();
});

// Global error handler for unhandled test errors
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Performance monitoring utilities for tests
export const measurePerformance = async <T>(
  operation: () => Promise<T>,
  name: string = 'operation'
): Promise<{ result: T; duration: number; memoryDelta: number }> => {
  const startTime = performance.now();
  const startMemory = process.memoryUsage().heapUsed;
  
  const result = await operation();
  
  const endTime = performance.now();
  const endMemory = process.memoryUsage().heapUsed;
  
  return {
    result,
    duration: endTime - startTime,
    memoryDelta: endMemory - startMemory
  };
};