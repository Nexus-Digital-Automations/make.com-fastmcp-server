/**
 * Basic infrastructure test to verify core setup is working
 * Tests the most fundamental components to ensure test environment is properly configured
 */

describe('Basic Infrastructure Tests', () => {
  describe('Environment Setup', () => {
    it('should have test environment configured', () => {
      expect(process.env.NODE_ENV).toBe('test');
      expect(process.env.MAKE_API_KEY).toBe('test_api_key_12345');
      expect(process.env.LOG_LEVEL).toBe('error');
    });

    it('should have test utilities available', () => {
      expect(globalThis.testUtils).toBeDefined();
      expect(typeof globalThis.testUtils.generateId).toBe('function');
      expect(typeof globalThis.testUtils.createMockUser).toBe('function');
      expect(typeof globalThis.testUtils.delay).toBe('function');
    });
  });

  describe('Mock System', () => {
    it('should successfully import config manager mock', async () => {
      const { default: configManager } = await import('../src/lib/config.js');
      
      expect(configManager).toBeDefined();
      expect(typeof configManager.getLogLevel).toBe('function');
      expect(configManager.getLogLevel()).toBe('error');
      expect(configManager.isTest()).toBe(true);
    });

    it('should successfully import logger mock', async () => {
      const { default: logger } = await import('../src/lib/logger.js');
      
      expect(logger).toBeDefined();
      expect(typeof logger.info).toBe('function');
      expect(typeof logger.error).toBe('function');
      expect(typeof logger.debug).toBe('function');
    });

    it('should have working test utilities', () => {
      const mockUser = globalThis.testUtils.createMockUser();
      expect(mockUser).toBeDefined();
      expect(mockUser.id).toBeDefined();
      expect(mockUser.name).toBe('Test User');
      expect(mockUser.email).toBe('test@example.com');

      const mockScenario = globalThis.testUtils.createMockScenario();
      expect(mockScenario).toBeDefined();
      expect(mockScenario.id).toBeDefined();
      expect(mockScenario.name).toBe('Test Scenario');
    });
  });

  describe('Basic Module Import', () => {
    it('should import types without errors', async () => {
      const types = await import('../src/types/index.js');
      expect(types).toBeDefined();
    });

    it('should import basic utils without errors', async () => {
      const { createApiResponse, createErrorResponse } = await import('../src/utils/error-response.js');
      expect(typeof createApiResponse).toBe('function');
      expect(typeof createErrorResponse).toBe('function');
    });
  });
});