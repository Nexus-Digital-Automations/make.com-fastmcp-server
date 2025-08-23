/**
 * Unit Tests for Connection Tools Orchestrator
 * Tests the main orchestrator that integrates connection CRUD, webhook, and diagnostics tools
 */

import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { FastMCP } from 'fastmcp';
import MakeApiClient from '../../../src/lib/make-api-client';
import { addConnectionTools } from '../../../src/tools/connections';

// Mock the specialized manager modules
jest.mock('../../../src/tools/connections/connection-manager.js', () => ({
  addConnectionCRUDTools: jest.fn()
}));

jest.mock('../../../src/tools/connections/webhook-manager.js', () => ({
  addWebhookTools: jest.fn()
}));

jest.mock('../../../src/tools/connections/diagnostics-manager.js', () => ({
  addConnectionDiagnosticsTools: jest.fn()
}));

jest.mock('../../../src/lib/logger.js', () => ({
  child: jest.fn(() => ({
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn()
  })),
  info: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  debug: jest.fn()
}));

// Import mocked modules
import { addConnectionCRUDTools } from '../../../src/tools/connections/connection-manager.js';
import { addWebhookTools } from '../../../src/tools/connections/webhook-manager.js';
import { addConnectionDiagnosticsTools } from '../../../src/tools/connections/diagnostics-manager.js';
import logger from '../../../src/lib/logger.js';

describe('Connection Tools Orchestrator', () => {
  let mockServer: FastMCP;
  let mockApiClient: MakeApiClient;
  let mockLogger: any;

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Create mock FastMCP server
    mockServer = {
      addTool: jest.fn(),
      addResource: jest.fn(),
      addPrompt: jest.fn()
    } as any;

    // Create mock API client
    mockApiClient = {
      get: jest.fn(),
      post: jest.fn(),
      patch: jest.fn(),
      delete: jest.fn(),
      baseURL: 'https://api.make.com',
      headers: { 'Authorization': 'Bearer test-token' }
    } as any;

    // Setup mock logger
    mockLogger = {
      info: jest.fn(),
      error: jest.fn(),
      warn: jest.fn(),
      debug: jest.fn()
    };

    (logger.child as jest.Mock).mockReturnValue(mockLogger);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('addConnectionTools', () => {
    test('should orchestrate all connection management modules', () => {
      addConnectionTools(mockServer, mockApiClient);

      // Verify all specialized managers are called
      expect(addConnectionCRUDTools).toHaveBeenCalledWith(mockServer, mockApiClient);
      expect(addWebhookTools).toHaveBeenCalledWith(mockServer, mockApiClient);
      expect(addConnectionDiagnosticsTools).toHaveBeenCalledWith(mockServer, mockApiClient);
    });

    test('should call each manager exactly once', () => {
      addConnectionTools(mockServer, mockApiClient);

      expect(addConnectionCRUDTools).toHaveBeenCalledTimes(1);
      expect(addWebhookTools).toHaveBeenCalledTimes(1);
      expect(addConnectionDiagnosticsTools).toHaveBeenCalledTimes(1);
    });

    test('should create component logger with correct component name', () => {
      addConnectionTools(mockServer, mockApiClient);

      expect(logger.child).toHaveBeenCalledWith({ component: 'ConnectionTools' });
    });

    test('should log initialization start', () => {
      addConnectionTools(mockServer, mockApiClient);

      expect(mockLogger.info).toHaveBeenCalledWith('Adding connection management tools');
    });

    test('should log successful completion with module list', () => {
      addConnectionTools(mockServer, mockApiClient);

      expect(mockLogger.info).toHaveBeenCalledWith(
        'Connection management tools added successfully',
        {
          modules: ['connection-manager', 'webhook-manager', 'diagnostics-manager']
        }
      );
    });

    test('should handle logger creation failure gracefully', () => {
      // Mock logger.child to throw an error
      (logger.child as jest.Mock).mockImplementation(() => {
        throw new Error('Logger creation failed');
      });

      // Should not throw and should use fallback logger
      expect(() => addConnectionTools(mockServer, mockApiClient)).not.toThrow();

      // Verify fallback behavior - should still call the managers
      expect(addConnectionCRUDTools).toHaveBeenCalledWith(mockServer, mockApiClient);
      expect(addWebhookTools).toHaveBeenCalledWith(mockServer, mockApiClient);
      expect(addConnectionDiagnosticsTools).toHaveBeenCalledWith(mockServer, mockApiClient);
    });

    test('should pass correct parameters to all managers', () => {
      const customServer = { addTool: jest.fn() } as any;
      const customApiClient = { 
        baseURL: 'https://custom.api.com',
        headers: { 'Authorization': 'Bearer custom-token' }
      } as any;

      addConnectionTools(customServer, customApiClient);

      expect(addConnectionCRUDTools).toHaveBeenCalledWith(customServer, customApiClient);
      expect(addWebhookTools).toHaveBeenCalledWith(customServer, customApiClient);
      expect(addConnectionDiagnosticsTools).toHaveBeenCalledWith(customServer, customApiClient);
    });

    test('should work with different FastMCP server instances', () => {
      const alternativeServer = {
        addTool: jest.fn(),
        addResource: jest.fn(),
        addPrompt: jest.fn(),
        customMethod: jest.fn()
      } as any;

      addConnectionTools(alternativeServer, mockApiClient);

      expect(addConnectionCRUDTools).toHaveBeenCalledWith(alternativeServer, mockApiClient);
      expect(addWebhookTools).toHaveBeenCalledWith(alternativeServer, mockApiClient);
      expect(addConnectionDiagnosticsTools).toHaveBeenCalledWith(alternativeServer, mockApiClient);
    });

    test('should work with different API client configurations', () => {
      const customApiClient = {
        get: jest.fn(),
        post: jest.fn(),
        patch: jest.fn(),
        delete: jest.fn(),
        baseURL: 'https://eu.make.com',
        headers: { 
          'Authorization': 'Bearer eu-token',
          'Content-Type': 'application/json'
        },
        timeout: 30000
      } as any;

      addConnectionTools(mockServer, customApiClient);

      expect(addConnectionCRUDTools).toHaveBeenCalledWith(mockServer, customApiClient);
      expect(addWebhookTools).toHaveBeenCalledWith(mockServer, customApiClient);
      expect(addConnectionDiagnosticsTools).toHaveBeenCalledWith(mockServer, customApiClient);
    });

    test('should maintain correct execution order', () => {
      const callOrder: string[] = [];

      (addConnectionCRUDTools as jest.Mock).mockImplementation(() => {
        callOrder.push('connection-crud');
      });

      (addWebhookTools as jest.Mock).mockImplementation(() => {
        callOrder.push('webhooks');
      });

      (addConnectionDiagnosticsTools as jest.Mock).mockImplementation(() => {
        callOrder.push('diagnostics');
      });

      addConnectionTools(mockServer, mockApiClient);

      expect(callOrder).toEqual(['connection-crud', 'webhooks', 'diagnostics']);
    });

    test('should handle manager errors gracefully', () => {
      // Mock one manager to throw an error
      (addConnectionCRUDTools as jest.Mock).mockImplementation(() => {
        throw new Error('Connection CRUD setup failed');
      });

      // Should propagate the error (orchestrator doesn't catch manager errors)
      expect(() => addConnectionTools(mockServer, mockApiClient)).toThrow('Connection CRUD setup failed');

      // Verify that the error occurred during the first manager call
      expect(addConnectionCRUDTools).toHaveBeenCalledWith(mockServer, mockApiClient);
      // Subsequent managers should not be called due to the error
      expect(addWebhookTools).not.toHaveBeenCalled();
      expect(addConnectionDiagnosticsTools).not.toHaveBeenCalled();
    });
  });

  describe('module integration', () => {
    test('should provide clean separation of concerns', () => {
      addConnectionTools(mockServer, mockApiClient);

      // Each manager should be called with the same parameters
      const expectedArgs = [mockServer, mockApiClient];
      
      expect(addConnectionCRUDTools).toHaveBeenCalledWith(...expectedArgs);
      expect(addWebhookTools).toHaveBeenCalledWith(...expectedArgs);
      expect(addConnectionDiagnosticsTools).toHaveBeenCalledWith(...expectedArgs);
    });

    test('should act as proper orchestrator without business logic', () => {
      // The orchestrator should not add any tools directly
      const serverSpy = jest.spyOn(mockServer, 'addTool');
      
      addConnectionTools(mockServer, mockApiClient);

      // Server.addTool should not be called directly by orchestrator
      expect(serverSpy).not.toHaveBeenCalled();
      
      // All tool addition should be delegated to specialized managers
      expect(addConnectionCRUDTools).toHaveBeenCalledTimes(1);
      expect(addWebhookTools).toHaveBeenCalledTimes(1);
      expect(addConnectionDiagnosticsTools).toHaveBeenCalledTimes(1);
    });

    test('should be idempotent - multiple calls should not cause issues', () => {
      // Call orchestrator multiple times
      addConnectionTools(mockServer, mockApiClient);
      addConnectionTools(mockServer, mockApiClient);
      addConnectionTools(mockServer, mockApiClient);

      // Each manager should be called once per orchestrator invocation
      expect(addConnectionCRUDTools).toHaveBeenCalledTimes(3);
      expect(addWebhookTools).toHaveBeenCalledTimes(3);
      expect(addConnectionDiagnosticsTools).toHaveBeenCalledTimes(3);
    });
  });

  describe('logging behavior', () => {
    test('should use structured logging with component context', () => {
      addConnectionTools(mockServer, mockApiClient);

      expect(logger.child).toHaveBeenCalledWith({ component: 'ConnectionTools' });
      expect(mockLogger.info).toHaveBeenCalledWith('Adding connection management tools');
      expect(mockLogger.info).toHaveBeenCalledWith(
        'Connection management tools added successfully',
        { modules: ['connection-manager', 'webhook-manager', 'diagnostics-manager'] }
      );
    });

    test('should handle missing logger gracefully', () => {
      // Test fallback when logger.child fails
      (logger.child as jest.Mock).mockImplementation(() => {
        throw new Error('Logger unavailable');
      });

      // Should still execute without errors
      expect(() => addConnectionTools(mockServer, mockApiClient)).not.toThrow();

      // All managers should still be called
      expect(addConnectionCRUDTools).toHaveBeenCalledTimes(1);
      expect(addWebhookTools).toHaveBeenCalledTimes(1);
      expect(addConnectionDiagnosticsTools).toHaveBeenCalledTimes(1);
    });
  });
});