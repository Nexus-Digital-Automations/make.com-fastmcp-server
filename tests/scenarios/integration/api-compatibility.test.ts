/**
 * @fileoverview API Compatibility Test Suite for Refactored Scenarios Module
 * 
 * Ensures that all existing APIs work exactly the same after refactoring.
 * This test suite focuses on maintaining 100% backward compatibility.
 * 
 * Test Categories:
 * - Input/Output schema validation
 * - API endpoint mapping verification
 * - Response format consistency
 * - Error handling compatibility
 * - Progress reporting compatibility
 */

import { jest } from '@jest/globals';
import { FastMCP, UserError } from 'fastmcp';
import { addScenarioTools } from '../../../src/tools/scenarios.js';
import type MakeApiClient from '../../../src/lib/make-api-client.js';

// Mock the logger
jest.mock('../../../src/lib/logger.js', () => {
  const mockChild = jest.fn(() => ({
    info: jest.fn(),
    debug: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  }));
  
  return {
    __esModule: true,
    default: {
      child: mockChild,
      info: jest.fn(),
      debug: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    },
  };
});

describe('Scenarios Module - API Compatibility', () => {
  let server: FastMCP;
  let mockApiClient: jest.Mocked<MakeApiClient>;
  let mockLog: any;
  let mockReportProgress: jest.Mock;

  beforeEach(() => {
    server = new FastMCP({
      name: 'compatibility-test-server',
      version: '1.0.0',
    });
    
    mockApiClient = {
      get: jest.fn(),
      post: jest.fn(),
      put: jest.fn(),
      patch: jest.fn(),
      delete: jest.fn(),
      healthCheck: jest.fn(),
      getRateLimiterStatus: jest.fn(),
      shutdown: jest.fn(),
    } as any;

    mockLog = {
      info: jest.fn(),
      debug: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    };
    mockReportProgress = jest.fn();

    addScenarioTools(server, mockApiClient);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Input Schema Compatibility', () => {
    test('list-scenarios should accept all original parameters', async () => {
      mockApiClient.get.mockResolvedValue({
        success: true,
        data: [],
        metadata: { total: 0 }
      });

      const tool = (server as any).tools.get('list-scenarios');

      // Test all parameter combinations that worked in original
      const validInputs = [
        {},
        { teamId: 'team_123' },
        { folderId: 'folder_456' },
        { limit: 50 },
        { offset: 100 },
        { search: 'test query' },
        { active: true },
        { active: false },
        {
          teamId: 'team_123',
          folderId: 'folder_456',
          limit: 25,
          offset: 10,
          search: 'complex query',
          active: true
        }
      ];

      for (const input of validInputs) {
        await expect(
          tool.execute(input, { log: mockLog, reportProgress: mockReportProgress })
        ).resolves.not.toThrow();
      }
    });

    test('get-scenario should maintain parameter compatibility', async () => {
      mockApiClient.get.mockResolvedValue({
        success: true,
        data: { id: 'scn_123', name: 'Test Scenario' }
      });

      const tool = (server as any).tools.get('get-scenario');

      const validInputs = [
        { scenarioId: 'scn_123' },
        { scenarioId: 'scn_123', includeBlueprint: false },
        { scenarioId: 'scn_123', includeBlueprint: true },
        { scenarioId: 'scn_123', includeExecutions: false },
        { scenarioId: 'scn_123', includeExecutions: true },
        {
          scenarioId: 'scn_123',
          includeBlueprint: true,
          includeExecutions: true
        }
      ];

      for (const input of validInputs) {
        await expect(
          tool.execute(input, { log: mockLog, reportProgress: mockReportProgress })
        ).resolves.not.toThrow();
      }
    });

    test('create-scenario should preserve original flexibility', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: { id: 'scn_new', name: 'New Scenario' }
      });

      const tool = (server as any).tools.get('create-scenario');

      const validInputs = [
        { name: 'Simple Scenario' },
        { name: 'Team Scenario', teamId: 'team_123' },
        { name: 'Folder Scenario', folderId: 'folder_456' },
        { name: 'Blueprint Scenario', blueprint: { modules: [] } },
        {
          name: 'Full Scenario',
          teamId: 'team_123',
          folderId: 'folder_456',
          blueprint: { modules: [], connections: [] },
          scheduling: {
            type: 'interval',
            interval: 30
          }
        },
        {
          name: 'Cron Scenario',
          scheduling: {
            type: 'cron',
            cron: '0 9 * * 1'
          }
        }
      ];

      for (const input of validInputs) {
        await expect(
          tool.execute(input, { log: mockLog, reportProgress: mockReportProgress })
        ).resolves.not.toThrow();
      }
    });

    test('update-scenario should maintain update flexibility', async () => {
      mockApiClient.patch.mockResolvedValue({
        success: true,
        data: { id: 'scn_123', name: 'Updated Scenario' }
      });

      const tool = (server as any).tools.get('update-scenario');

      const validInputs = [
        { scenarioId: 'scn_123', name: 'Updated Name' },
        { scenarioId: 'scn_123', active: true },
        { scenarioId: 'scn_123', active: false },
        { scenarioId: 'scn_123', blueprint: { modules: [] } },
        {
          scenarioId: 'scn_123',
          scheduling: {
            type: 'interval',
            interval: 60
          }
        },
        {
          scenarioId: 'scn_123',
          name: 'Complete Update',
          active: true,
          blueprint: { modules: [], connections: [] },
          scheduling: {
            type: 'cron',
            cron: '0 */6 * * *'
          }
        }
      ];

      for (const input of validInputs) {
        await expect(
          tool.execute(input, { log: mockLog, reportProgress: mockReportProgress })
        ).resolves.not.toThrow();
      }
    });

    test('should reject invalid inputs consistently', async () => {
      const testCases = [
        { 
          tool: 'list-scenarios',
          inputs: [
            { limit: 0 },
            { limit: 101 },
            { offset: -1 },
            { unknownField: 'invalid' }
          ]
        },
        {
          tool: 'get-scenario', 
          inputs: [
            {},
            { scenarioId: '' },
            { scenarioId: 'valid', unknownField: 'invalid' }
          ]
        },
        {
          tool: 'create-scenario',
          inputs: [
            {},
            { name: '' },
            { name: 'a'.repeat(101) },
            { name: 'Valid', scheduling: { type: 'invalid' } }
          ]
        }
      ];

      for (const testCase of testCases) {
        const tool = (server as any).tools.get(testCase.tool);
        
        for (const input of testCase.inputs) {
          await expect(
            tool.execute(input, { log: mockLog, reportProgress: mockReportProgress })
          ).rejects.toThrow();
        }
      }
    });
  });

  describe('API Endpoint Mapping Compatibility', () => {
    test('should map parameters to API endpoints exactly as original', async () => {
      mockApiClient.get.mockResolvedValue({
        success: true,
        data: [],
        metadata: { total: 0 }
      });

      const listTool = (server as any).tools.get('list-scenarios');
      
      // Test parameter mapping
      await listTool.execute({
        teamId: 'team_123',
        folderId: 'folder_456',
        limit: 20,
        offset: 10,
        search: 'test scenario',
        active: true
      }, { log: mockLog, reportProgress: mockReportProgress });

      expect(mockApiClient.get).toHaveBeenCalledWith('/scenarios', {
        params: {
          limit: 20,
          offset: 10,
          teamId: 'team_123',
          folderId: 'folder_456',
          q: 'test scenario',  // Note: search -> q mapping
          active: true
        }
      });
    });

    test('should maintain exact HTTP methods for each operation', async () => {
      const operations = [
        {
          tool: 'list-scenarios',
          method: 'get',
          args: {},
          expectedCall: ['/scenarios', { params: { limit: 10, offset: 0 } }]
        },
        {
          tool: 'get-scenario',
          method: 'get',
          args: { scenarioId: 'scn_123' },
          expectedCall: ['/scenarios/scn_123']
        },
        {
          tool: 'create-scenario',
          method: 'post',
          args: { name: 'Test' },
          expectedCall: ['/scenarios', { name: 'Test' }]
        },
        {
          tool: 'update-scenario',
          method: 'patch',
          args: { scenarioId: 'scn_123', name: 'Updated' },
          expectedCall: ['/scenarios/scn_123', { name: 'Updated' }]
        },
        {
          tool: 'delete-scenario',
          method: 'delete',
          args: { scenarioId: 'scn_123', force: true },
          expectedCall: ['/scenarios/scn_123']
        }
      ];

      // Mock successful responses
      mockApiClient.get.mockResolvedValue({ success: true, data: {} });
      mockApiClient.post.mockResolvedValue({ success: true, data: {} });
      mockApiClient.patch.mockResolvedValue({ success: true, data: {} });
      mockApiClient.delete.mockResolvedValue({ success: true, data: {} });

      for (const operation of operations) {
        const tool = (server as any).tools.get(operation.tool);
        await tool.execute(operation.args, { log: mockLog, reportProgress: mockReportProgress });
        
        expect(mockApiClient[operation.method]).toHaveBeenCalledWith(...operation.expectedCall);
        jest.clearAllMocks();
      }
    });

    test('should handle conditional API calls exactly as original', async () => {
      // Mock responses for get-scenario with optional data
      const mockScenario = { id: 'scn_123', name: 'Test Scenario' };
      const mockBlueprint = { modules: [], connections: [] };
      const mockExecutions = [{ id: 'exec_1', status: 'success' }];

      mockApiClient.get.mockImplementation((url: string) => {
        if (url === '/scenarios/scn_123') {
          return Promise.resolve({ success: true, data: mockScenario });
        } else if (url === '/scenarios/scn_123/blueprint') {
          return Promise.resolve({ success: true, data: mockBlueprint });
        } else if (url === '/scenarios/scn_123/executions') {
          return Promise.resolve({ success: true, data: mockExecutions });
        }
        return Promise.resolve({ success: false, error: { message: 'Not found' } });
      });

      const getTool = (server as any).tools.get('get-scenario');
      
      // Test without optional parameters
      await getTool.execute(
        { scenarioId: 'scn_123' },
        { log: mockLog, reportProgress: mockReportProgress }
      );
      expect(mockApiClient.get).toHaveBeenCalledTimes(1);
      expect(mockApiClient.get).toHaveBeenCalledWith('/scenarios/scn_123');

      jest.clearAllMocks();

      // Test with blueprint requested
      await getTool.execute(
        { scenarioId: 'scn_123', includeBlueprint: true },
        { log: mockLog, reportProgress: mockReportProgress }
      );
      expect(mockApiClient.get).toHaveBeenCalledTimes(2);
      expect(mockApiClient.get).toHaveBeenCalledWith('/scenarios/scn_123');
      expect(mockApiClient.get).toHaveBeenCalledWith('/scenarios/scn_123/blueprint');

      jest.clearAllMocks();

      // Test with executions requested
      await getTool.execute(
        { scenarioId: 'scn_123', includeExecutions: true },
        { log: mockLog, reportProgress: mockReportProgress }
      );
      expect(mockApiClient.get).toHaveBeenCalledTimes(2);
      expect(mockApiClient.get).toHaveBeenCalledWith('/scenarios/scn_123');
      expect(mockApiClient.get).toHaveBeenCalledWith('/scenarios/scn_123/executions', {
        params: { limit: 10 }
      });
    });
  });

  describe('Response Format Compatibility', () => {
    test('should maintain exact JSON response structure for list-scenarios', async () => {
      const mockScenarios = [
        { id: 'scn_1', name: 'Scenario 1', active: true },
        { id: 'scn_2', name: 'Scenario 2', active: false }
      ];

      mockApiClient.get.mockResolvedValue({
        success: true,
        data: mockScenarios,
        metadata: { total: 2 }
      });

      const tool = (server as any).tools.get('list-scenarios');
      const result = await tool.execute({}, { log: mockLog, reportProgress: mockReportProgress });
      
      const parsedResult = JSON.parse(result);
      
      // Verify exact structure
      expect(parsedResult).toHaveProperty('scenarios');
      expect(parsedResult).toHaveProperty('pagination');
      expect(parsedResult).toHaveProperty('filters');
      expect(parsedResult).toHaveProperty('timestamp');

      expect(parsedResult.scenarios).toEqual(mockScenarios);
      expect(parsedResult.pagination.total).toBe(2);
      expect(parsedResult.pagination.limit).toBe(10);
      expect(parsedResult.pagination.offset).toBe(0);
      expect(parsedResult.pagination.hasMore).toBe(false);
    });

    test('should preserve get-scenario response structure', async () => {
      const mockScenario = { id: 'scn_123', name: 'Test Scenario', active: true };
      const mockBlueprint = { modules: [], connections: [] };
      const mockExecutions = [{ id: 'exec_1', status: 'success' }];

      mockApiClient.get.mockImplementation((url: string) => {
        if (url === '/scenarios/scn_123') {
          return Promise.resolve({ success: true, data: mockScenario });
        } else if (url === '/scenarios/scn_123/blueprint') {
          return Promise.resolve({ success: true, data: mockBlueprint });
        } else if (url === '/scenarios/scn_123/executions') {
          return Promise.resolve({ success: true, data: mockExecutions });
        }
        return Promise.resolve({ success: false, error: { message: 'Not found' } });
      });

      const tool = (server as any).tools.get('get-scenario');
      const result = await tool.execute(
        { scenarioId: 'scn_123', includeBlueprint: true, includeExecutions: true },
        { log: mockLog, reportProgress: mockReportProgress }
      );
      
      const parsedResult = JSON.parse(result);
      
      // Verify structure matches original
      expect(parsedResult).toHaveProperty('scenario');
      expect(parsedResult).toHaveProperty('blueprint');
      expect(parsedResult).toHaveProperty('recentExecutions');
      expect(parsedResult).toHaveProperty('timestamp');
      
      expect(parsedResult.scenario).toEqual(mockScenario);
      expect(parsedResult.blueprint).toEqual(mockBlueprint);
      expect(parsedResult.recentExecutions).toEqual(mockExecutions);
    });

    test('should maintain create-scenario response format', async () => {
      const mockCreatedScenario = {
        id: 'scn_new',
        name: 'New Test Scenario',
        active: false,
        teamId: 'team_123'
      };

      mockApiClient.post.mockResolvedValue({
        success: true,
        data: mockCreatedScenario
      });

      const tool = (server as any).tools.get('create-scenario');
      const result = await tool.execute(
        { name: 'New Test Scenario', teamId: 'team_123' },
        { log: mockLog, reportProgress: mockReportProgress }
      );
      
      const parsedResult = JSON.parse(result);
      
      expect(parsedResult).toHaveProperty('scenario');
      expect(parsedResult).toHaveProperty('message');
      expect(parsedResult).toHaveProperty('timestamp');
      
      expect(parsedResult.scenario).toEqual(mockCreatedScenario);
      expect(parsedResult.message).toContain('created successfully');
    });
  });

  describe('Error Handling Compatibility', () => {
    test('should throw UserError with identical message format', async () => {
      const apiError = {
        success: false,
        error: { message: 'Scenario not found', code: 'NOT_FOUND' }
      };

      mockApiClient.get.mockResolvedValue(apiError);

      const tool = (server as any).tools.get('get-scenario');
      
      try {
        await tool.execute({ scenarioId: 'invalid' }, { log: mockLog, reportProgress: mockReportProgress });
        fail('Should have thrown an error');
      } catch (error) {
        expect(error).toBeInstanceOf(UserError);
        expect((error as Error).message).toBe('Failed to get scenario: Scenario not found');
      }
    });

    test('should handle network errors with consistent messaging', async () => {
      const networkError = new Error('Network timeout');
      
      mockApiClient.post.mockRejectedValue(networkError);

      const tool = (server as any).tools.get('create-scenario');
      
      try {
        await tool.execute({ name: 'Test' }, { log: mockLog, reportProgress: mockReportProgress });
        fail('Should have thrown an error');
      } catch (error) {
        expect(error).toBeInstanceOf(UserError);
        expect((error as Error).message).toBe('Network timeout');
      }
    });

    test('should preserve validation error messages', async () => {
      const validationTests = [
        {
          tool: 'list-scenarios',
          args: { limit: 101 },
          expectedPattern: /Number must be less than or equal to 100/
        },
        {
          tool: 'get-scenario',
          args: { scenarioId: '' },
          expectedPattern: /String must contain at least 1 character/
        },
        {
          tool: 'create-scenario',
          args: { name: '' },
          expectedPattern: /String must contain at least 1 character/
        }
      ];

      for (const test of validationTests) {
        const tool = (server as any).tools.get(test.tool);
        
        try {
          await tool.execute(test.args, { log: mockLog, reportProgress: mockReportProgress });
          fail(`Should have thrown validation error for ${test.tool}`);
        } catch (error) {
          expect((error as Error).message).toMatch(test.expectedPattern);
        }
      }
    });
  });

  describe('Progress Reporting Compatibility', () => {
    test('should maintain identical progress reporting behavior', async () => {
      mockApiClient.get.mockResolvedValue({
        success: true,
        data: [],
        metadata: { total: 0 }
      });

      const tool = (server as any).tools.get('list-scenarios');
      await tool.execute({}, { log: mockLog, reportProgress: mockReportProgress });

      // Verify exact progress calls match original implementation
      expect(mockReportProgress).toHaveBeenCalledWith({ progress: 0, total: 100 });
      expect(mockReportProgress).toHaveBeenCalledWith({ progress: 25, total: 100 });
      expect(mockReportProgress).toHaveBeenCalledWith({ progress: 75, total: 100 });
      expect(mockReportProgress).toHaveBeenCalledWith({ progress: 100, total: 100 });
      expect(mockReportProgress).toHaveBeenCalledTimes(4);
    });

    test('should report progress during multi-step operations', async () => {
      const mockScenario = { id: 'scn_123', name: 'Test' };
      const mockBlueprint = { modules: [] };

      mockApiClient.get.mockImplementation((url: string) => {
        if (url === '/scenarios/scn_123') {
          return Promise.resolve({ success: true, data: mockScenario });
        } else if (url === '/scenarios/scn_123/blueprint') {
          return Promise.resolve({ success: true, data: mockBlueprint });
        }
        return Promise.resolve({ success: false, error: { message: 'Not found' } });
      });

      const tool = (server as any).tools.get('get-scenario');
      await tool.execute(
        { scenarioId: 'scn_123', includeBlueprint: true },
        { log: mockLog, reportProgress: mockReportProgress }
      );

      // Should have progress calls for multi-step operation
      expect(mockReportProgress.mock.calls.length).toBeGreaterThan(2);
      
      // First call should be 0 progress
      expect(mockReportProgress.mock.calls[0]).toEqual([{ progress: 0, total: 100 }]);
      
      // Last call should be 100 progress
      const lastCall = mockReportProgress.mock.calls[mockReportProgress.mock.calls.length - 1];
      expect(lastCall).toEqual([{ progress: 100, total: 100 }]);
    });
  });

  describe('Default Value Compatibility', () => {
    test('should apply same default values as original implementation', async () => {
      mockApiClient.get.mockResolvedValue({
        success: true,
        data: [],
        metadata: { total: 0 }
      });

      const tool = (server as any).tools.get('list-scenarios');
      await tool.execute({}, { log: mockLog, reportProgress: mockReportProgress });

      // Verify default parameters are applied
      expect(mockApiClient.get).toHaveBeenCalledWith('/scenarios', {
        params: { limit: 10, offset: 0 }
      });
    });

    test('should maintain default scheduling type for create-scenario', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: { id: 'scn_new', name: 'Test' }
      });

      const tool = (server as any).tools.get('create-scenario');
      await tool.execute(
        { name: 'Test', scheduling: { type: 'immediately' } },
        { log: mockLog, reportProgress: mockReportProgress }
      );

      expect(mockApiClient.post).toHaveBeenCalledWith('/scenarios', {
        name: 'Test',
        scheduling: { type: 'immediately' }
      });
    });

    test('should preserve clone-scenario default active state', async () => {
      const mockBlueprint = { modules: [] };
      
      mockApiClient.get.mockResolvedValue({
        success: true,
        data: mockBlueprint
      });

      mockApiClient.post.mockResolvedValue({
        success: true,
        data: { id: 'scn_cloned', name: 'Cloned' }
      });

      const tool = (server as any).tools.get('clone-scenario');
      await tool.execute(
        { scenarioId: 'scn_123', name: 'Cloned Scenario' },
        { log: mockLog, reportProgress: mockReportProgress }
      );

      expect(mockApiClient.post).toHaveBeenCalledWith('/scenarios', {
        name: 'Cloned Scenario',
        blueprint: mockBlueprint,
        active: false // Default value
      });
    });
  });
});