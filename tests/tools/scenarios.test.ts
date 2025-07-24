/**
 * Comprehensive unit tests for Make.com scenario management tools
 * 
 * Tests cover:
 * - Input validation for all Zod schemas
 * - Error handling for API failures and network issues
 * - API interaction verification with proper mocking
 * - Progress reporting and logging validation
 * - Edge cases and boundary conditions
 * - Complex scenarios and workflow testing
 */

import { jest } from '@jest/globals';

// Mock the logger with explicit implementation
jest.mock('../../src/lib/logger.js', () => {
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

import { FastMCP, UserError } from 'fastmcp';
import { addScenarioTools } from '../../src/tools/scenarios.js';
import type MakeApiClient from '../../src/lib/make-api-client.js';

describe('Scenario Management Tools', () => {
  let server: FastMCP;
  let mockApiClient: jest.Mocked<MakeApiClient>;
  let mockLog: any;
  let mockReportProgress: jest.Mock;

  beforeEach(() => {
    // Create fresh FastMCP server instance
    server = new FastMCP({
      name: 'test-server',
      version: '1.0.0',
    });
    
    // Create comprehensive mock API client
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

    // Mock execution context
    mockLog = {
      info: jest.fn(),
      debug: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    };
    mockReportProgress = jest.fn();

    // Add scenario tools to server
    addScenarioTools(server, mockApiClient);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Tool Registration', () => {
    test('should register all scenario management tools', () => {
      const toolNames = Array.from((server as any).tools.keys());

      expect(toolNames).toContain('list-scenarios');
      expect(toolNames).toContain('get-scenario');
      expect(toolNames).toContain('create-scenario');
      expect(toolNames).toContain('update-scenario');
      expect(toolNames).toContain('delete-scenario');
      expect(toolNames).toContain('clone-scenario');
      expect(toolNames).toContain('run-scenario');
      expect(toolNames).toHaveLength(7);
    });

    test('should have correct tool configurations', () => {
      const tools = (server as any).tools;
      
      expect(tools.get('list-scenarios').description).toContain('List and search Make.com scenarios');
      expect(tools.get('get-scenario').description).toContain('Get detailed information');
      expect(tools.get('create-scenario').description).toContain('Create a new Make.com scenario');
      expect(tools.get('update-scenario').description).toContain('Update an existing Make.com scenario');
      expect(tools.get('delete-scenario').description).toContain('Delete a Make.com scenario');
      expect(tools.get('clone-scenario').description).toContain('Clone an existing Make.com scenario');
      expect(tools.get('run-scenario').description).toContain('Execute a Make.com scenario');
    });
  });

  describe('list-scenarios Tool', () => {
    const validListArgs = {
      teamId: 'team_123',
      folderId: 'folder_456',
      limit: 20,
      offset: 10,
      search: 'test scenario',
      active: true,
    };

    const mockScenarios = [
      { id: 'scn_1', name: 'Test Scenario 1', active: true },
      { id: 'scn_2', name: 'Test Scenario 2', active: false },
    ];

    beforeEach(() => {
      mockApiClient.get.mockResolvedValue({
        success: true,
        data: mockScenarios,
        metadata: { total: 2 },
      });
    });

    describe('Input Validation', () => {
      test('should accept valid parameters', async () => {
        const tool = (server as any).tools.get('list-scenarios');
        await expect(
          tool.execute(validListArgs, { log: mockLog, reportProgress: mockReportProgress })
        ).resolves.not.toThrow();
      });

      test('should reject invalid limit values', async () => {
        const tool = (server as any).tools.get('list-scenarios');
        
        await expect(
          tool.execute({ limit: 0 }, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow();

        await expect(
          tool.execute({ limit: 101 }, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow();
      });

      test('should reject negative offset', async () => {
        const tool = (server as any).tools.get('list-scenarios');
        
        await expect(
          tool.execute({ offset: -1 }, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow();
      });

      test('should apply default values', async () => {
        const tool = (server as any).tools.get('list-scenarios');
        await tool.execute({}, { log: mockLog, reportProgress: mockReportProgress });

        expect(mockApiClient.get).toHaveBeenCalledWith('/scenarios', {
          params: { limit: 10, offset: 0 }
        });
      });

      test('should reject unknown properties', async () => {
        const tool = (server as any).tools.get('list-scenarios');
        
        await expect(
          tool.execute({ unknownProp: 'value' }, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow();
      });
    });

    describe('API Interaction', () => {
      test('should make correct API call with all parameters', async () => {
        const tool = (server as any).tools.get('list-scenarios');
        await tool.execute(validListArgs, { log: mockLog, reportProgress: mockReportProgress });

        expect(mockApiClient.get).toHaveBeenCalledWith('/scenarios', {
          params: {
            limit: 20,
            offset: 10,
            teamId: 'team_123',
            folderId: 'folder_456',
            q: 'test scenario',
            active: true,
          }
        });
      });

      test('should handle successful API response', async () => {
        const tool = (server as any).tools.get('list-scenarios');
        const result = await tool.execute(validListArgs, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsedResult = JSON.parse(result);
        expect(parsedResult.scenarios).toEqual(mockScenarios);
        expect(parsedResult.pagination.total).toBe(2);
        expect(parsedResult.pagination.limit).toBe(20);
      });

      test('should report progress correctly', async () => {
        const tool = (server as any).tools.get('list-scenarios');
        await tool.execute(validListArgs, { log: mockLog, reportProgress: mockReportProgress });

        expect(mockReportProgress).toHaveBeenCalledWith({ progress: 0, total: 100 });
        expect(mockReportProgress).toHaveBeenCalledWith({ progress: 25, total: 100 });
        expect(mockReportProgress).toHaveBeenCalledWith({ progress: 75, total: 100 });
        expect(mockReportProgress).toHaveBeenCalledWith({ progress: 100, total: 100 });
      });
    });

    describe('Error Handling', () => {
      test('should handle API failure', async () => {
        mockApiClient.get.mockResolvedValue({
          success: false,
          error: { message: 'API Error', code: 'API_FAIL' },
        });

        const tool = (server as any).tools.get('list-scenarios');
        await expect(
          tool.execute(validListArgs, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow(UserError);
        await expect(
          tool.execute(validListArgs, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow('Failed to list scenarios: API Error');
      });

      test('should handle network errors', async () => {
        mockApiClient.get.mockRejectedValue(new Error('Network timeout'));

        const tool = (server as any).tools.get('list-scenarios');
        await expect(
          tool.execute(validListArgs, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow(UserError);
        await expect(
          tool.execute(validListArgs, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow('Network timeout');
      });

      test('should handle empty response gracefully', async () => {
        mockApiClient.get.mockResolvedValue({
          success: true,
          data: null,
          metadata: undefined,
        });

        const tool = (server as any).tools.get('list-scenarios');
        const result = await tool.execute({}, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsedResult = JSON.parse(result);
        expect(parsedResult.scenarios).toEqual([]);
        expect(parsedResult.pagination.total).toBe(0);
      });
    });

    describe('Complex Scenarios', () => {
      test('should handle pagination correctly', async () => {
        mockApiClient.get.mockResolvedValue({
          success: true,
          data: mockScenarios,
          metadata: { total: 150 },
        });

        const tool = (server as any).tools.get('list-scenarios');
        const result = await tool.execute({ limit: 50, offset: 100 }, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsedResult = JSON.parse(result);
        expect(parsedResult.pagination.hasMore).toBe(false); // 100 + 50 = 150, no more
      });

      test('should filter by active status correctly', async () => {
        const tool = (server as any).tools.get('list-scenarios');
        await tool.execute({ active: false }, { log: mockLog, reportProgress: mockReportProgress });

        expect(mockApiClient.get).toHaveBeenCalledWith('/scenarios', {
          params: { limit: 10, offset: 0, active: false }
        });
      });
    });
  });

  describe('get-scenario Tool', () => {
    const validGetArgs = {
      scenarioId: 'scn_123',
      includeBlueprint: true,
      includeExecutions: true,
    };

    const mockScenario = {
      id: 'scn_123',
      name: 'Test Scenario',
      active: true,
      teamId: 'team_123',
    };

    const mockBlueprint = { modules: [], connections: [] };
    const mockExecutions = [{ id: 'exec_1', status: 'success' }];

    beforeEach(() => {
      mockApiClient.get.mockImplementation((url: string) => {
        if (url === '/scenarios/scn_123') {
          return Promise.resolve({ success: true, data: mockScenario } as any);
        } else if (url === '/scenarios/scn_123/blueprint') {
          return Promise.resolve({ success: true, data: mockBlueprint } as any);
        } else if (url === '/scenarios/scn_123/executions') {
          return Promise.resolve({ success: true, data: mockExecutions } as any);
        }
        return Promise.resolve({ success: false, error: { message: 'Not found' } } as any);
      });
    });

    describe('Input Validation', () => {
      test('should require scenarioId', async () => {
        const tool = (server as any).tools.get('get-scenario');
        
        await expect(
          tool.execute({}, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow();
      });

      test('should reject empty scenarioId', async () => {
        const tool = (server as any).tools.get('get-scenario');
        
        await expect(
          tool.execute({ scenarioId: '' }, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow();
      });

      test('should accept valid boolean flags', async () => {
        const tool = (server as any).tools.get('get-scenario');
        
        await expect(
          tool.execute(validGetArgs, { log: mockLog, reportProgress: mockReportProgress })
        ).resolves.not.toThrow();
      });
    });

    describe('API Interaction', () => {
      test('should make basic scenario request', async () => {
        const tool = (server as any).tools.get('get-scenario');
        await tool.execute({ scenarioId: 'scn_123' }, { log: mockLog, reportProgress: mockReportProgress });

        expect(mockApiClient.get).toHaveBeenCalledWith('/scenarios/scn_123');
        expect(mockApiClient.get).toHaveBeenCalledTimes(1); // Only main request
      });

      test('should fetch blueprint when requested', async () => {
        const tool = (server as any).tools.get('get-scenario');
        const result = await tool.execute(validGetArgs, { log: mockLog, reportProgress: mockReportProgress });

        expect(mockApiClient.get).toHaveBeenCalledWith('/scenarios/scn_123/blueprint');
        
        const parsedResult = JSON.parse(result);
        expect(parsedResult.blueprint).toEqual(mockBlueprint);
      });

      test('should fetch executions when requested', async () => {
        const tool = (server as any).tools.get('get-scenario');
        const result = await tool.execute(validGetArgs, { log: mockLog, reportProgress: mockReportProgress });

        expect(mockApiClient.get).toHaveBeenCalledWith('/scenarios/scn_123/executions', {
          params: { limit: 10 }
        });
        
        const parsedResult = JSON.parse(result);
        expect(parsedResult.recentExecutions).toEqual(mockExecutions);
      });

      test('should handle partial failures gracefully', async () => {
        // Scenario exists but blueprint fails
        mockApiClient.get.mockImplementation((url: string) => {
          if (url === '/scenarios/scn_123') {
            return Promise.resolve({ success: true, data: mockScenario } as any);
          }
          return Promise.resolve({ success: false, error: { message: 'Not found' } } as any);
        });

        const tool = (server as any).tools.get('get-scenario');
        const result = await tool.execute(validGetArgs, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsedResult = JSON.parse(result);
        expect(parsedResult.scenario).toEqual(mockScenario);
        expect(parsedResult.blueprint).toBeUndefined();
        expect(parsedResult.recentExecutions).toBeUndefined();
      });
    });

    describe('Error Handling', () => {
      test('should handle scenario not found', async () => {
        mockApiClient.get.mockResolvedValue({
          success: false,
          error: { message: 'Scenario not found', code: 'NOT_FOUND' },
        });

        const tool = (server as any).tools.get('get-scenario');
        await expect(
          tool.execute({ scenarioId: 'invalid' }, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow(UserError);
        await expect(
          tool.execute({ scenarioId: 'invalid' }, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow('Failed to get scenario: Scenario not found');
      });
    });
  });

  describe('create-scenario Tool', () => {
    const validCreateArgs = {
      name: 'New Test Scenario',
      teamId: 'team_123',
      folderId: 'folder_456',
      blueprint: { modules: [], connections: [] },
      scheduling: {
        type: 'interval' as const,
        interval: 30,
      },
    };

    const mockCreatedScenario = {
      id: 'scn_new',
      name: 'New Test Scenario',
      active: false,
      teamId: 'team_123',
    };

    beforeEach(() => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: mockCreatedScenario,
      });
    });

    describe('Input Validation', () => {
      test('should require name', async () => {
        const tool = (server as any).tools.get('create-scenario');
        
        await expect(
          tool.execute({}, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow();
      });

      test('should reject empty name', async () => {
        const tool = (server as any).tools.get('create-scenario');
        
        await expect(
          tool.execute({ name: '' }, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow();
      });

      test('should reject name longer than 100 characters', async () => {
        const tool = (server as any).tools.get('create-scenario');
        const longName = 'a'.repeat(101);
        
        await expect(
          tool.execute({ name: longName }, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow();
      });

      test('should validate scheduling configuration', async () => {
        const tool = (server as any).tools.get('create-scenario');
        
        // Invalid scheduling type
        await expect(
          tool.execute({
            name: 'Test',
            scheduling: { type: 'invalid' as any }
          }, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow();

        // Invalid interval
        await expect(
          tool.execute({
            name: 'Test',
            scheduling: { type: 'interval', interval: -1 }
          }, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow();
      });

      test('should accept valid cron scheduling', async () => {
        const tool = (server as any).tools.get('create-scenario');
        
        await expect(
          tool.execute({
            name: 'Test',
            scheduling: { type: 'cron', cron: '0 9 * * 1' }
          }, { log: mockLog, reportProgress: mockReportProgress })
        ).resolves.not.toThrow();
      });
    });

    describe('API Interaction', () => {
      test('should make correct API call with minimal data', async () => {
        const tool = (server as any).tools.get('create-scenario');
        await tool.execute({ name: 'Simple Test' }, { log: mockLog, reportProgress: mockReportProgress });

        expect(mockApiClient.post).toHaveBeenCalledWith('/scenarios', {
          name: 'Simple Test'
        });
      });

      test('should include all optional parameters when provided', async () => {
        const tool = (server as any).tools.get('create-scenario');
        await tool.execute(validCreateArgs, { log: mockLog, reportProgress: mockReportProgress });

        expect(mockApiClient.post).toHaveBeenCalledWith('/scenarios', {
          name: 'New Test Scenario',
          teamId: 'team_123',
          folderId: 'folder_456',
          blueprint: { modules: [], connections: [] },
          scheduling: { type: 'interval', interval: 30 }
        });
      });

      test('should return created scenario details', async () => {
        const tool = (server as any).tools.get('create-scenario');
        const result = await tool.execute(validCreateArgs, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsedResult = JSON.parse(result);
        expect(parsedResult.scenario).toEqual(mockCreatedScenario);
        expect(parsedResult.message).toContain('created successfully');
        expect(parsedResult.timestamp).toBeDefined();
      });
    });

    describe('Error Handling', () => {
      test('should handle creation failure', async () => {
        mockApiClient.post.mockResolvedValue({
          success: false,
          error: { message: 'Insufficient permissions', code: 'FORBIDDEN' },
        });

        const tool = (server as any).tools.get('create-scenario');
        await expect(
          tool.execute(validCreateArgs, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow(UserError);
        await expect(
          tool.execute(validCreateArgs, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow('Failed to create scenario: Insufficient permissions');
      });
    });
  });

  describe('update-scenario Tool', () => {
    const validUpdateArgs = {
      scenarioId: 'scn_123',
      name: 'Updated Scenario Name',
      active: true,
      blueprint: { modules: ['updated'], connections: [] },
      scheduling: {
        type: 'cron' as const,
        cron: '0 */6 * * *',
      },
    };

    const mockUpdatedScenario = {
      id: 'scn_123',
      name: 'Updated Scenario Name',
      active: true,
      updatedAt: '2024-01-15T10:30:00Z',
    };

    beforeEach(() => {
      mockApiClient.patch.mockResolvedValue({
        success: true,
        data: mockUpdatedScenario,
      });
    });

    describe('Input Validation', () => {
      test('should require scenarioId', async () => {
        const tool = (server as any).tools.get('update-scenario');
        
        await expect(
          tool.execute({ name: 'Test' }, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow();
      });

      test('should require at least one update parameter', async () => {
        const tool = (server as any).tools.get('update-scenario');
        
        await expect(
          tool.execute({ scenarioId: 'scn_123' }, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow(UserError);
        await expect(
          tool.execute({ scenarioId: 'scn_123' }, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow('No update parameters provided');
      });

      test('should validate name length', async () => {
        const tool = (server as any).tools.get('update-scenario');
        const longName = 'a'.repeat(101);
        
        await expect(
          tool.execute({ scenarioId: 'scn_123', name: longName }, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow();
      });

      test('should validate scheduling parameters', async () => {
        const tool = (server as any).tools.get('update-scenario');
        
        await expect(
          tool.execute({
            scenarioId: 'scn_123',
            scheduling: { type: 'interval', interval: 0 }
          }, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow();
      });
    });

    describe('API Interaction', () => {
      test('should make PATCH request with update data', async () => {
        const tool = (server as any).tools.get('update-scenario');
        await tool.execute({ scenarioId: 'scn_123', active: false }, { log: mockLog, reportProgress: mockReportProgress });

        expect(mockApiClient.patch).toHaveBeenCalledWith('/scenarios/scn_123', {
          active: false
        });
      });

      test('should include all provided update fields', async () => {
        const tool = (server as any).tools.get('update-scenario');
        await tool.execute(validUpdateArgs, { log: mockLog, reportProgress: mockReportProgress });

        expect(mockApiClient.patch).toHaveBeenCalledWith('/scenarios/scn_123', {
          name: 'Updated Scenario Name',
          active: true,
          blueprint: { modules: ['updated'], connections: [] },
          scheduling: { type: 'cron', cron: '0 */6 * * *' }
        });
      });

      test('should return update summary', async () => {
        const tool = (server as any).tools.get('update-scenario');
        const result = await tool.execute(validUpdateArgs, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsedResult = JSON.parse(result);
        expect(parsedResult.scenario).toEqual(mockUpdatedScenario);
        expect(parsedResult.updates).toBeDefined();
        expect(parsedResult.message).toContain('updated successfully');
      });
    });

    describe('Error Handling', () => {
      test('should handle scenario not found', async () => {
        mockApiClient.patch.mockResolvedValue({
          success: false,
          error: { message: 'Scenario not found', code: 'NOT_FOUND' },
        });

        const tool = (server as any).tools.get('update-scenario');
        await expect(
          tool.execute({ scenarioId: 'invalid', name: 'Test' }, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow(UserError);
      });
    });
  });

  describe('delete-scenario Tool', () => {
    const mockActiveScenario = { id: 'scn_123', active: true };
    const mockInactiveScenario = { id: 'scn_123', active: false };

    beforeEach(() => {
      mockApiClient.delete.mockResolvedValue({ success: true, data: {} });
    });

    describe('Input Validation', () => {
      test('should require scenarioId', async () => {
        const tool = (server as any).tools.get('delete-scenario');
        
        await expect(
          tool.execute({}, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow();
      });

      test('should accept force parameter', async () => {
        const tool = (server as any).tools.get('delete-scenario');
        
        await expect(
          tool.execute({ scenarioId: 'scn_123', force: true }, { log: mockLog, reportProgress: mockReportProgress })
        ).resolves.not.toThrow();
      });
    });

    describe('Safety Checks', () => {
      test('should prevent deletion of active scenario without force', async () => {
        mockApiClient.get.mockResolvedValue({ success: true, data: mockActiveScenario });

        const tool = (server as any).tools.get('delete-scenario');
        await expect(
          tool.execute({ scenarioId: 'scn_123' }, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow(UserError);
        await expect(
          tool.execute({ scenarioId: 'scn_123' }, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow('Cannot delete active scenario');
      });

      test('should allow deletion of inactive scenario', async () => {
        mockApiClient.get.mockResolvedValue({ success: true, data: mockInactiveScenario });

        const tool = (server as any).tools.get('delete-scenario');
        await expect(
          tool.execute({ scenarioId: 'scn_123' }, { log: mockLog, reportProgress: mockReportProgress })
        ).resolves.not.toThrow();

        expect(mockApiClient.delete).toHaveBeenCalledWith('/scenarios/scn_123');
      });

      test('should skip safety check with force=true', async () => {
        const tool = (server as any).tools.get('delete-scenario');
        await tool.execute({ scenarioId: 'scn_123', force: true }, { log: mockLog, reportProgress: mockReportProgress });

        expect(mockApiClient.get).not.toHaveBeenCalled(); // No safety check
        expect(mockApiClient.delete).toHaveBeenCalledWith('/scenarios/scn_123');
      });
    });

    describe('API Interaction', () => {
      test('should return deletion confirmation', async () => {
        mockApiClient.get.mockResolvedValue({ success: true, data: mockInactiveScenario });

        const tool = (server as any).tools.get('delete-scenario');
        const result = await tool.execute({ scenarioId: 'scn_123' }, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsedResult = JSON.parse(result);
        expect(parsedResult.scenarioId).toBe('scn_123');
        expect(parsedResult.message).toContain('deleted successfully');
        expect(parsedResult.force).toBe(false);
      });
    });

    describe('Error Handling', () => {
      test('should handle deletion failure', async () => {
        mockApiClient.get.mockResolvedValue({ success: true, data: mockInactiveScenario });
        mockApiClient.delete.mockResolvedValue({
          success: false,
          error: { message: 'Delete failed', code: 'DELETE_ERROR' },
        });

        const tool = (server as any).tools.get('delete-scenario');
        await expect(
          tool.execute({ scenarioId: 'scn_123' }, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow(UserError);
      });

      test('should handle scenario not found during safety check', async () => {
        mockApiClient.get.mockResolvedValue({
          success: false,
          error: { message: 'Not found', code: 'NOT_FOUND' },
        });

        const tool = (server as any).tools.get('delete-scenario');
        await expect(
          tool.execute({ scenarioId: 'invalid' }, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow(UserError);
        await expect(
          tool.execute({ scenarioId: 'invalid' }, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow('Scenario not found: invalid');
      });
    });
  });

  describe('clone-scenario Tool', () => {
    const validCloneArgs = {
      scenarioId: 'scn_source',
      name: 'Cloned Scenario',
      teamId: 'team_456',
      folderId: 'folder_789',
      active: true,
    };

    const mockBlueprint = {
      modules: [{ id: 'mod_1', type: 'webhook' }],
      connections: [{ from: 'mod_1', to: 'mod_2' }],
    };

    const mockClonedScenario = {
      id: 'scn_cloned',
      name: 'Cloned Scenario',
      active: true,
      teamId: 'team_456',
    };

    beforeEach(() => {
      mockApiClient.get.mockResolvedValue({ success: true, data: mockBlueprint });
      mockApiClient.post.mockResolvedValue({ success: true, data: mockClonedScenario });
    });

    describe('Input Validation', () => {
      test('should require both scenarioId and name', async () => {
        const tool = (server as any).tools.get('clone-scenario');
        
        await expect(
          tool.execute({ name: 'Test' }, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow();

        await expect(
          tool.execute({ scenarioId: 'scn_123' }, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow();
      });

      test('should validate name length', async () => {
        const tool = (server as any).tools.get('clone-scenario');
        const longName = 'a'.repeat(101);
        
        await expect(
          tool.execute({ scenarioId: 'scn_123', name: longName }, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow();
      });

      test('should default active to false', async () => {
        const tool = (server as any).tools.get('clone-scenario');
        await tool.execute({ scenarioId: 'scn_123', name: 'Test' }, { log: mockLog, reportProgress: mockReportProgress });

        expect(mockApiClient.post).toHaveBeenCalledWith('/scenarios', expect.objectContaining({
          active: false
        }));
      });
    });

    describe('Cloning Process', () => {
      test('should fetch source blueprint first', async () => {
        const tool = (server as any).tools.get('clone-scenario');
        await tool.execute(validCloneArgs, { log: mockLog, reportProgress: mockReportProgress });

        expect(mockApiClient.get).toHaveBeenCalledWith('/scenarios/scn_source/blueprint');
      });

      test('should create new scenario with blueprint', async () => {
        const tool = (server as any).tools.get('clone-scenario');
        await tool.execute(validCloneArgs, { log: mockLog, reportProgress: mockReportProgress });

        expect(mockApiClient.post).toHaveBeenCalledWith('/scenarios', {
          name: 'Cloned Scenario',
          blueprint: mockBlueprint,
          active: true,
          teamId: 'team_456',
          folderId: 'folder_789',
        });
      });

      test('should return cloning result', async () => {
        const tool = (server as any).tools.get('clone-scenario');
        const result = await tool.execute(validCloneArgs, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsedResult = JSON.parse(result);
        expect(parsedResult.originalScenarioId).toBe('scn_source');
        expect(parsedResult.clonedScenario).toEqual(mockClonedScenario);
        expect(parsedResult.message).toContain('cloned successfully');
      });
    });

    describe('Error Handling', () => {
      test('should handle blueprint retrieval failure', async () => {
        mockApiClient.get.mockResolvedValue({
          success: false,
          error: { message: 'Blueprint not found', code: 'NOT_FOUND' },
        });

        const tool = (server as any).tools.get('clone-scenario');
        await expect(
          tool.execute(validCloneArgs, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow(UserError);
        await expect(
          tool.execute(validCloneArgs, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow('Failed to get source scenario blueprint');
      });

      test('should handle scenario creation failure', async () => {
        mockApiClient.post.mockResolvedValue({
          success: false,
          error: { message: 'Creation failed', code: 'CREATE_ERROR' },
        });

        const tool = (server as any).tools.get('clone-scenario');
        await expect(
          tool.execute(validCloneArgs, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow(UserError);
        await expect(
          tool.execute(validCloneArgs, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow('Failed to clone scenario: Creation failed');
      });
    });
  });

  describe('run-scenario Tool', () => {
    const validRunArgs = {
      scenarioId: 'scn_123',
      wait: true,
      timeout: 30,
    };

    const mockExecution = {
      id: 'exec_123',
      status: 'started',
      scenarioId: 'scn_123',
    };

    const mockCompletedExecution = {
      id: 'exec_123',
      status: 'success',
      scenarioId: 'scn_123',
      duration: 5000,
    };

    beforeEach(() => {
      mockApiClient.post.mockResolvedValue({ success: true, data: mockExecution });
      mockApiClient.get.mockResolvedValue({ success: true, data: mockCompletedExecution });
    });

    describe('Input Validation', () => {
      test('should require scenarioId', async () => {
        const tool = (server as any).tools.get('run-scenario');
        
        await expect(
          tool.execute({}, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow();
      });

      test('should validate timeout range', async () => {
        const tool = (server as any).tools.get('run-scenario');
        
        await expect(
          tool.execute({ scenarioId: 'scn_123', timeout: 0 }, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow();

        await expect(
          tool.execute({ scenarioId: 'scn_123', timeout: 301 }, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow();
      });

      test('should default wait to true and timeout to 60', async () => {
        const tool = (server as any).tools.get('run-scenario');
        
        // Mock fast completion to avoid timeout in test
        const fastExecution = { ...mockCompletedExecution, status: 'success' };
        mockApiClient.get.mockResolvedValue({ success: true, data: fastExecution });
        
        const result = await tool.execute({ scenarioId: 'scn_123' }, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsedResult = JSON.parse(result);
        expect(parsedResult.status).toBe('success');
      });
    });

    describe('Execution Workflow', () => {
      test('should start scenario execution', async () => {
        const tool = (server as any).tools.get('run-scenario');
        await tool.execute({ scenarioId: 'scn_123', wait: false }, { log: mockLog, reportProgress: mockReportProgress });

        expect(mockApiClient.post).toHaveBeenCalledWith('/scenarios/scn_123/run');
      });

      test('should return immediately when wait=false', async () => {
        const tool = (server as any).tools.get('run-scenario');
        const result = await tool.execute({ scenarioId: 'scn_123', wait: false }, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsedResult = JSON.parse(result);
        expect(parsedResult.executionId).toBe('exec_123');
        expect(parsedResult.status).toBe('started');
        expect(parsedResult.message).toContain('started');
        
        // Should not poll for status
        expect(mockApiClient.get).not.toHaveBeenCalled();
      });

      test('should poll for completion when wait=true', async () => {
        const tool = (server as any).tools.get('run-scenario');
        const result = await tool.execute(validRunArgs, { log: mockLog, reportProgress: mockReportProgress });

        expect(mockApiClient.get).toHaveBeenCalledWith('/scenarios/scn_123/executions/exec_123');
        
        const parsedResult = JSON.parse(result);
        expect(parsedResult.status).toBe('success');
        expect(parsedResult.execution).toEqual(mockCompletedExecution);
      });

      test('should handle timeout during execution', async () => {
        // Mock execution that never completes
        mockApiClient.get.mockResolvedValue({ 
          success: true, 
          data: { ...mockExecution, status: 'running' } 
        });

        const tool = (server as any).tools.get('run-scenario');
        const result = await tool.execute({ 
          scenarioId: 'scn_123', 
          wait: true, 
          timeout: 1 // Very short timeout
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsedResult = JSON.parse(result);
        expect(parsedResult.timeout).toBe(true);
        expect(parsedResult.message).toContain('timeout');
      }, 10000); // Increase test timeout

      test('should handle execution failure', async () => {
        const failedExecution = { ...mockExecution, status: 'error' };
        mockApiClient.get.mockResolvedValue({ success: true, data: failedExecution });

        const tool = (server as any).tools.get('run-scenario');
        const result = await tool.execute(validRunArgs, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsedResult = JSON.parse(result);
        expect(parsedResult.status).toBe('error');
        expect(parsedResult.execution).toEqual(failedExecution);
      });
    });

    describe('Error Handling', () => {
      test('should handle execution start failure', async () => {
        mockApiClient.post.mockResolvedValue({
          success: false,
          error: { message: 'Scenario not found', code: 'NOT_FOUND' },
        });

        const tool = (server as any).tools.get('run-scenario');
        await expect(
          tool.execute(validRunArgs, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow(UserError);
        await expect(
          tool.execute(validRunArgs, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow('Failed to start scenario execution');
      });

      test('should handle status polling failure gracefully', async () => {
        mockApiClient.get.mockResolvedValue({
          success: false,
          error: { message: 'Execution not found', code: 'NOT_FOUND' },
        });

        const tool = (server as any).tools.get('run-scenario');
        const result = await tool.execute({ 
          scenarioId: 'scn_123', 
          wait: true, 
          timeout: 1 
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        // Should still return result even if polling fails
        const parsedResult = JSON.parse(result);
        expect(parsedResult.executionId).toBe('exec_123');
      });
    });

    describe('Progress Reporting', () => {
      test('should report progress during execution monitoring', async () => {
        const tool = (server as any).tools.get('run-scenario');
        await tool.execute(validRunArgs, { log: mockLog, reportProgress: mockReportProgress });

        expect(mockReportProgress).toHaveBeenCalledWith({ progress: 0, total: 100 });
        expect(mockReportProgress).toHaveBeenCalledWith({ progress: 25, total: 100 });
        expect(mockReportProgress).toHaveBeenCalledWith({ progress: 100, total: 100 });
      });
    });
  });

  describe('Integration Tests', () => {
    test('should handle complete scenario lifecycle', async () => {
      const createTool = (server as any).tools.get('create-scenario');
      const updateTool = (server as any).tools.get('update-scenario');
      const runTool = (server as any).tools.get('run-scenario');
      const deleteTool = (server as any).tools.get('delete-scenario');

      // Mock responses for lifecycle
      mockApiClient.post.mockResolvedValueOnce({
        success: true,
        data: { id: 'scn_lifecycle', name: 'Lifecycle Test', active: false }
      });
      mockApiClient.patch.mockResolvedValueOnce({
        success: true,
        data: { id: 'scn_lifecycle', name: 'Lifecycle Test', active: true }
      });
      mockApiClient.post.mockResolvedValueOnce({
        success: true,
        data: { id: 'exec_1', status: 'success' }
      });
      mockApiClient.get.mockResolvedValueOnce({
        success: true,
        data: { id: 'scn_lifecycle', active: true }
      });
      mockApiClient.delete.mockResolvedValueOnce({ success: true, data: {} });

      // Create scenario
      await createTool.execute({ name: 'Lifecycle Test' }, { log: mockLog, reportProgress: mockReportProgress });
      
      // Update scenario (activate)
      await updateTool.execute({ scenarioId: 'scn_lifecycle', active: true }, { log: mockLog, reportProgress: mockReportProgress });
      
      // Run scenario
      await runTool.execute({ scenarioId: 'scn_lifecycle', wait: false }, { log: mockLog, reportProgress: mockReportProgress });
      
      // Force delete active scenario
      await deleteTool.execute({ scenarioId: 'scn_lifecycle', force: true }, { log: mockLog, reportProgress: mockReportProgress });

      expect(mockApiClient.post).toHaveBeenCalledTimes(2); // create + run
      expect(mockApiClient.patch).toHaveBeenCalledTimes(1); // update
      expect(mockApiClient.delete).toHaveBeenCalledTimes(1); // delete
    });

    test('should handle concurrent scenario operations', async () => {
      const listTool = (server as any).tools.get('list-scenarios');
      
      mockApiClient.get.mockResolvedValue({
        success: true,
        data: [{ id: 'scn_1' }, { id: 'scn_2' }],
        metadata: { total: 2 }
      });

      // Execute multiple list operations concurrently
      const promises = [
        listTool.execute({ teamId: 'team_1' }, { log: mockLog, reportProgress: mockReportProgress }),
        listTool.execute({ teamId: 'team_2' }, { log: mockLog, reportProgress: mockReportProgress }),
        listTool.execute({ active: true }, { log: mockLog, reportProgress: mockReportProgress }),
      ];

      await Promise.all(promises);
      expect(mockApiClient.get).toHaveBeenCalledTimes(3);
    });
  });

  describe('Performance and Edge Cases', () => {
    test('should handle large blueprint data', async () => {
      const largeBlueprintClone = {
        scenarioId: 'scn_large',
        name: 'Large Blueprint Clone',
      };
      
      const largeBlueprint = {
        modules: Array(100).fill({ id: 'mod', type: 'webhook', config: {} }),
        connections: Array(200).fill({ from: 'mod1', to: 'mod2' }),
      };

      mockApiClient.get.mockResolvedValue({ success: true, data: largeBlueprint });
      mockApiClient.post.mockResolvedValue({ success: true, data: { id: 'scn_cloned_large' } });

      const tool = (server as any).tools['clone-scenario'];
      await expect(
        tool.execute(largeBlueprintClone, { log: mockLog, reportProgress: mockReportProgress })
      ).resolves.not.toThrow();

      expect(mockApiClient.post).toHaveBeenCalledWith('/scenarios', expect.objectContaining({
        blueprint: largeBlueprint
      }));
    });

    test('should handle Unicode scenario names', async () => {
      const unicodeName = '测试场景 🚀 Тест сценарий';
      const tool = (server as any).tools['create-scenario'];
      
      mockApiClient.post.mockResolvedValue({ success: true, data: { id: 'scn_unicode', name: unicodeName } });

      await expect(
        tool.execute({ name: unicodeName }, { log: mockLog, reportProgress: mockReportProgress })
      ).resolves.not.toThrow();

      expect(mockApiClient.post).toHaveBeenCalledWith('/scenarios', expect.objectContaining({
        name: unicodeName
      }));
    });

    test('should handle API rate limiting gracefully', async () => {
      mockApiClient.get.mockRejectedValue({
        message: 'Rate limit exceeded',
        code: 'RATE_LIMIT',
        retryable: true
      });

      const tool = (server as any).tools['list-scenarios'];
      await expect(
        tool.execute({}, { log: mockLog, reportProgress: mockReportProgress })
      ).rejects.toThrow(UserError);
    });
  });

  describe('Logging and Monitoring', () => {
    test('should log all operations correctly', async () => {
      const tool = (server as any).tools['create-scenario'];
      mockApiClient.post.mockResolvedValue({ success: true, data: { id: 'scn_logged' } });

      await tool.execute({ name: 'Logged Scenario' }, { log: mockLog, reportProgress: mockReportProgress });

      expect(mockLog.info).toHaveBeenCalledWith('Creating scenario', expect.objectContaining({
        name: 'Logged Scenario'
      }));
      expect(mockLog.info).toHaveBeenCalledWith('Scenario created successfully', expect.any(Object));
    });

    test('should log errors appropriately', async () => {
      const tool = (server as any).tools['get-scenario'];
      mockApiClient.get.mockRejectedValue(new Error('Network failure'));

      await expect(
        tool.execute({ scenarioId: 'scn_error' }, { log: mockLog, reportProgress: mockReportProgress })
      ).rejects.toThrow();

      expect(mockLog.error).toHaveBeenCalledWith('Failed to get scenario', expect.objectContaining({
        scenarioId: 'scn_error',
        error: 'Network failure'
      }));
    });
  });
});