/**
 * Test setup and global configuration
 * Sets up test environment, mocks, and shared utilities
 */

import { jest } from '@jest/globals';

// Global test timeout - optimized for performance
jest.setTimeout(10000); // Reduced from 30s to 10s

// Mock console methods in test environment
global.console = {
  ...console,
  // Keep console.error and console.warn for debugging
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
};

// Setup environment variables for testing
process.env.NODE_ENV = 'test';
process.env.MAKE_API_KEY = 'test_api_key_12345';
process.env.MAKE_BASE_URL = 'https://api.make.com/api/v2';
process.env.MAKE_TEAM_ID = '12345';
process.env.MAKE_ORGANIZATION_ID = '67890';
process.env.LOG_LEVEL = 'error'; // Reduce log noise in tests

// Global test utilities
declare global {
  namespace globalThis {
    var testUtils: {
      generateId: () => number;
      createMockUser: () => any;
      createMockScenario: () => any;
      createMockConnection: () => any;
      delay: (ms: number) => Promise<void>;
    };
  }
}

// Test utilities
globalThis.testUtils = {
  generateId: () => Math.floor(Math.random() * 1000000),
  
  createMockUser: () => ({
    id: globalThis.testUtils.generateId(),
    name: 'Test User',
    email: 'test@example.com',
    role: 'admin' as const,
    teamId: 12345,
    organizationId: 67890,
    permissions: ['read', 'write', 'admin'],
    isActive: true,
  }),
  
  createMockScenario: () => ({
    id: globalThis.testUtils.generateId(),
    name: 'Test Scenario',
    teamId: 12345,
    folderId: null,
    blueprint: {},
    scheduling: {
      type: 'on-demand' as const,
    },
    isActive: true,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }),
  
  createMockConnection: () => ({
    id: globalThis.testUtils.generateId(),
    name: 'Test Connection',
    accountName: 'test-account',
    service: 'test-service',
    metadata: {},
    isValid: true,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }),
  
  delay: (ms: number) => new Promise(resolve => setTimeout(resolve, ms)),
};

// Setup global mocks for common dependencies
jest.mock('axios');
jest.mock('bottleneck');

// Global afterEach cleanup
afterEach(() => {
  jest.clearAllMocks();
});