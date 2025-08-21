/**
 * Basic Test Suite for Connection Management Tools
 * Tests core functionality of connection and webhook management tools
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { createMockServer } from '../../utils/test-helpers.js';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';

describe('Connection Management Tools - Basic Tests', () => {
  let mockServer: any;
  let mockTool: jest.MockedFunction<any>;
  let mockApiClient: MockMakeApiClient;

  beforeEach(async () => {
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockTool = serverSetup.mockTool;
    mockApiClient = new MockMakeApiClient();
    
    // Clear previous mock calls
    mockTool.mockClear();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Tool Registration', () => {
    it('should successfully import and register connection tools', async () => {
      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      
      // Should not throw an error
      expect(() => {
        addConnectionTools(mockServer, mockApiClient as any);
      }).not.toThrow();
      
      // Should call addTool for each tool
      expect(mockTool).toHaveBeenCalled();
      expect(mockTool.mock.calls.length).toBeGreaterThan(0);
    });

    it('should export connection management functions', async () => {
      const connectionsModule = await import('../../../src/tools/connections.js');
      
      // Check that expected exports exist
      expect(connectionsModule.addConnectionTools).toBeDefined();
      expect(typeof connectionsModule.addConnectionTools).toBe('function');
    });
  });

  describe('Module Structure', () => {
    it('should import without errors', async () => {
      // This test verifies the module can be imported without syntax errors
      await expect(import('../../../src/tools/connections.js')).resolves.toBeDefined();
    });

    it('should have proper TypeScript compilation', async () => {
      const connectionsModule = await import('../../../src/tools/connections.js');
      
      // Basic structural validation
      expect(connectionsModule).toBeDefined();
      expect(typeof connectionsModule).toBe('object');
    });
  });
});