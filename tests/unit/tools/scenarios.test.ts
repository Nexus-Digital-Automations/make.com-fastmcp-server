/**
 * Comprehensive Unit Tests for Scenario Management Tools
 * 
 * Tests all scenario management operations including:
 * - Input validation for all Zod schemas
 * - Error handling for various failure modes
 * - API interaction testing with proper mocking
 * - Progress reporting and logging verification
 * - Edge cases and complex scenarios
 * 
 * @version 1.0.0
 * @author Make.com FastMCP Server Test Suite
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { UserError } from 'fastmcp';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';
import { 
  createMockServer, 
  findTool, 
  executeTool, 
  expectToolCall,
  expectProgressReported,
  expectValidZodParse,
  expectInvalidZodParse,
  createComplexTestScenario,
  simulateNetworkConditions,
  expectErrorResponse,
  performanceHelpers
} from '../../utils/test-helpers.js';
import { testScenarios, testErrors, generateTestData } from '../../fixtures/test-data.js';

describe('Scenario Management Tools - Comprehensive Test Suite', () => {
  let mockServer: any;
  let mockApiClient: MockMakeApiClient;
  let mockTool: jest.MockedFunction<any>;
  let mockLog: any;
  let mockReportProgress: jest.MockedFunction<any>;
  let addScenarioTools: any;

  beforeEach(async () => {
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockTool = serverSetup.mockTool;
    mockApiClient = new MockMakeApiClient();
    
    // Setup consistent mock logging and progress reporting
    mockLog = {
      info: jest.fn(),
      error: jest.fn(),
      warn: jest.fn(),
      debug: jest.fn()
    };
    mockReportProgress = jest.fn();
    
    // Mock logger before importing scenarios
    jest.doMock('../../../src/lib/logger.js', () => ({
      default: {
        child: jest.fn(() => mockLog),
        info: jest.fn(),
        error: jest.fn(),
        warn: jest.fn(),
        debug: jest.fn(),
      },
    }));
    
    // Dynamically import scenarios to ensure mocks are applied
    const scenariosModule = await import('../../../src/tools/scenarios.js');
    addScenarioTools = scenariosModule.addScenarioTools;
    
    // Initialize scenario tools
    addScenarioTools(mockServer, mockApiClient as any);
  });

  afterEach(() => {
    jest.clearAllMocks();
    mockApiClient.reset();
  });

  describe('Tool Registration and Configuration', () => {
    it('should register all scenario management tools with correct configuration', () => {
      const registeredTools = mockTool.mock.calls.map(call => call[0]);
      const expectedTools = [
        'list-scenarios',
        'get-scenario', 
        'create-scenario',
        'update-scenario',
        'delete-scenario',
        'clone-scenario',
        'run-scenario'
      ];
      
      expectedTools.forEach(toolName => {
        const tool = registeredTools.find(t => t.name === toolName);
        expect(tool).toBeDefined();
        expect(tool.description).toBeDefined();
        expect(tool.parameters).toBeDefined();
        expect(tool.execute).toBeInstanceOf(Function);
      });
    });

    it('should have correct tool annotations', () => {
      const tool = findTool(mockTool, 'list-scenarios');
      expect(tool.annotations).toBeDefined();
      expect(tool.annotations.title).toBe('List Scenarios');
      expect(tool.annotations.readOnlyHint).toBe(true);
      expect(tool.annotations.openWorldHint).toBe(true);
    });
  });

  describe('list-scenarios tool - Input Validation and Basic Operations', () => {
    const setupSuccessfulListResponse = (scenarios = [testScenarios.active, testScenarios.inactive]) => {
      mockApiClient.mockResponse('GET', '/scenarios', {
        success: true,
        data: scenarios,
        metadata: { total: scenarios.length, page: 1, limit: 10 }
      });
    };

    it('should validate schema and list scenarios with default parameters', async () => {
      setupSuccessfulListResponse();
      
      const tool = findTool(mockTool, 'list-scenarios');
      const result = await executeTool(tool, {}, { log: mockLog, reportProgress: mockReportProgress });
      
      // Verify response structure
      const parsedResult = JSON.parse(result);
      expect(parsedResult).toHaveProperty('scenarios');
      expect(parsedResult).toHaveProperty('pagination');
      expect(parsedResult).toHaveProperty('filters');
      expect(parsedResult).toHaveProperty('timestamp');
      
      // Verify progress reporting
      expectProgressReported(mockReportProgress, [
        { progress: 0, total: 100 },
        { progress: 25, total: 100 },
        { progress: 75, total: 100 },
        { progress: 100, total: 100 }
      ]);
      
      // Verify API call
      const calls = mockApiClient.getCallLog();
      expect(calls).toHaveLength(1);
      expect(calls[0]).toMatchObject({
        method: 'GET',
        endpoint: '/scenarios',
        data: { limit: 10, offset: 0 }
      });
    });

    it('should handle comprehensive filtering options', async () => {
      setupSuccessfulListResponse([testScenarios.active]);
      
      const tool = findTool(mockTool, 'list-scenarios');
      const filterArgs = {
        teamId: '12345',
        folderId: '3001', 
        limit: 25,
        offset: 50,
        search: 'test scenario',
        active: true
      };
      
      await executeTool(tool, filterArgs, { log: mockLog, reportProgress: mockReportProgress });
      
      const calls = mockApiClient.getCallLog();
      expect(calls[0].data).toMatchObject({
        limit: 25,
        offset: 50,
        teamId: '12345',
        folderId: '3001',
        q: 'test scenario',
        active: true
      });
    });

    it('should validate input parameters with Zod schema', async () => {
      const tool = findTool(mockTool, 'list-scenarios');
      setupSuccessfulListResponse();
      
      // Test valid parameters
      const validArgs = [
        { limit: 1, offset: 0 },
        { limit: 100, offset: 50 },
        { teamId: 'team123', folderId: 'folder456' },
        { search: 'test', active: true },
        { limit: 50, search: 'automation', active: false }
      ];
      
      for (const args of validArgs) {
        await expect(executeTool(tool, args, { log: mockLog })).resolves.toBeDefined();
      }
      
      // Test invalid parameters
      const invalidArgs = [
        { limit: 0 }, // Below minimum
        { limit: 101 }, // Above maximum
        { offset: -1 }, // Negative offset
        { teamId: 123 }, // Wrong type (should be string)
        { active: 'yes' }, // Wrong type (should be boolean)
        { unknownParam: 'value' } // Extra parameter (strict schema)
      ];
      
      for (const args of invalidArgs) {
        await expect(executeTool(tool, args, { log: mockLog })).rejects.toThrow();
      }
    });

    it('should handle various API error scenarios', async () => {
      const tool = findTool(mockTool, 'list-scenarios');
      
      // Test different error responses
      const errorScenarios = [
        { 
          response: testErrors.unauthorized,
          expectedMessage: 'Failed to list scenarios: Unauthorized access'
        },
        {
          response: testErrors.rateLimited, 
          expectedMessage: 'Failed to list scenarios: Rate limit exceeded'
        },
        {
          response: testErrors.serverError,
          expectedMessage: 'Failed to list scenarios: Internal server error'
        }
      ];
      
      for (const scenario of errorScenarios) {
        mockApiClient.mockResponse('GET', '/scenarios', scenario.response);
        
        await expect(
          executeTool(tool, {}, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow(UserError);
        
        // Verify error logging
        expect(mockLog.error).toHaveBeenCalledWith(
          'Failed to list scenarios',
          expect.objectContaining({ error: expect.any(String) })
        );
        
        mockApiClient.reset();
        mockLog.error.mockClear();
      }
    });
    
    it('should handle network failures and timeouts', async () => {
      const tool = findTool(mockTool, 'list-scenarios');
      mockApiClient.mockFailure('GET', '/scenarios', new Error('Network timeout'));
      
      await expect(
        executeTool(tool, {}, { log: mockLog, reportProgress: mockReportProgress })
      ).rejects.toThrow(UserError);
      
      expectToolCall(mockLog, 'error', 'Failed to list scenarios');
    });
    
    it('should handle empty results gracefully', async () => {
      mockApiClient.mockResponse('GET', '/scenarios', {
        success: true,
        data: [],
        metadata: { total: 0, page: 1, limit: 10 }
      });
      
      const tool = findTool(mockTool, 'list-scenarios');
      const result = await executeTool(tool, {}, { log: mockLog, reportProgress: mockReportProgress });
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.scenarios).toEqual([]);
      expect(parsedResult.pagination.total).toBe(0);
      expect(parsedResult.pagination.hasMore).toBe(false);
    });
  });

  describe('get-scenario tool - Detailed Retrieval and Data Expansion', () => {
    const setupScenarioResponse = (scenario = testScenarios.active) => {
      mockApiClient.mockResponse('GET', `/scenarios/${scenario.id}`, {
        success: true,
        data: scenario
      });
    };
    
    const setupBlueprintResponse = (scenarioId: number, blueprint: any = { flow: [], settings: {} }) => {
      mockApiClient.mockResponse('GET', `/scenarios/${scenarioId}/blueprint`, {
        success: true,
        data: blueprint
      });
    };
    
    const setupExecutionsResponse = (scenarioId: number, executions: any[] = []) => {
      mockApiClient.mockResponse('GET', `/scenarios/${scenarioId}/executions`, {
        success: true,
        data: executions
      });
    };

    it('should retrieve basic scenario details successfully', async () => {
      const scenario = testScenarios.active;
      setupScenarioResponse(scenario);
      
      const tool = findTool(mockTool, 'get-scenario');
      const result = await executeTool(tool, { 
        scenarioId: scenario.id.toString() 
      }, { log: mockLog, reportProgress: mockReportProgress });
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult).toHaveProperty('scenario');
      expect(parsedResult).toHaveProperty('timestamp');
      expect(parsedResult.scenario.id).toBe(scenario.id);
      expect(parsedResult.scenario.name).toBe(scenario.name);
      
      expectProgressReported(mockReportProgress, [
        { progress: 0, total: 100 },
        { progress: 50, total: 100 },
        { progress: 100, total: 100 }
      ]);
    });

    it('should include blueprint when requested', async () => {
      const scenario = testScenarios.active;
      const blueprint = {
        flow: [
          { id: 1, app: 'webhook', operation: 'trigger' },
          { id: 2, app: 'email', operation: 'send' }
        ],
        settings: { timeout: 30000, logging: 'full' }
      };
      
      setupScenarioResponse(scenario);
      setupBlueprintResponse(scenario.id, blueprint);
      
      const tool = findTool(mockTool, 'get-scenario');
      const result = await executeTool(tool, {
        scenarioId: scenario.id.toString(),
        includeBlueprint: true
      }, { log: mockLog, reportProgress: mockReportProgress });
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult).toHaveProperty('blueprint');
      expect(parsedResult.blueprint.flow).toHaveLength(2);
      expect(parsedResult.blueprint.settings.timeout).toBe(30000);
      
      const calls = mockApiClient.getCallLog();
      expect(calls).toHaveLength(2);
      expect(calls[1].endpoint).toBe(`/scenarios/${scenario.id}/blueprint`);
    });
    
    it('should include execution history when requested', async () => {
      const scenario = testScenarios.active;
      const executions = [
        { id: 1001, status: 'success', startedAt: '2024-01-15T10:00:00Z' },
        { id: 1002, status: 'error', startedAt: '2024-01-15T11:00:00Z' }
      ];
      
      setupScenarioResponse(scenario);
      setupExecutionsResponse(scenario.id, executions);
      
      const tool = findTool(mockTool, 'get-scenario');
      const result = await executeTool(tool, {
        scenarioId: scenario.id.toString(),
        includeExecutions: true
      }, { log: mockLog, reportProgress: mockReportProgress });
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult).toHaveProperty('recentExecutions');
      expect(parsedResult.recentExecutions).toHaveLength(2);
      
      const calls = mockApiClient.getCallLog();
      expect(calls).toHaveLength(2);
      expect(calls[1].endpoint).toBe(`/scenarios/${scenario.id}/executions`);
      expect(calls[1].data).toMatchObject({ limit: 10 });
    });
    
    it('should include both blueprint and executions when requested', async () => {
      const scenario = testScenarios.active;
      const blueprint = { flow: [], settings: {} };
      const executions = [{ id: 1001, status: 'success' }];
      
      setupScenarioResponse(scenario);
      setupBlueprintResponse(scenario.id, blueprint);
      setupExecutionsResponse(scenario.id, executions);
      
      const tool = findTool(mockTool, 'get-scenario');
      const result = await executeTool(tool, {
        scenarioId: scenario.id.toString(),
        includeBlueprint: true,
        includeExecutions: true
      }, { log: mockLog, reportProgress: mockReportProgress });
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult).toHaveProperty('blueprint');
      expect(parsedResult).toHaveProperty('recentExecutions');
      
      const calls = mockApiClient.getCallLog();
      expect(calls).toHaveLength(3); // scenario + blueprint + executions
    });
    
    it('should validate input parameters', async () => {
      const tool = findTool(mockTool, 'get-scenario');
      setupScenarioResponse();
      
      // Valid parameters
      await expect(executeTool(tool, { 
        scenarioId: '12345',
        includeBlueprint: false,
        includeExecutions: false
      }, { log: mockLog })).resolves.toBeDefined();
      
      // Invalid parameters
      const invalidArgs = [
        {}, // Missing scenarioId
        { scenarioId: '' }, // Empty scenarioId
        { scenarioId: '123', includeBlueprint: 'yes' }, // Wrong type
        { scenarioId: '123', includeExecutions: 1 }, // Wrong type
        { scenarioId: '123', extraParam: 'value' } // Extra parameter
      ];
      
      for (const args of invalidArgs) {
        await expect(executeTool(tool, args, { log: mockLog })).rejects.toThrow();
      }
    });

    it('should handle scenario not found and other API errors', async () => {
      const tool = findTool(mockTool, 'get-scenario');
      
      // Test scenario not found
      mockApiClient.mockResponse('GET', '/scenarios/99999', testErrors.notFound);
      await expect(
        executeTool(tool, { scenarioId: '99999' }, { log: mockLog })
      ).rejects.toThrow(UserError);
      
      // Test unauthorized access
      mockApiClient.mockResponse('GET', '/scenarios/12345', testErrors.unauthorized);
      await expect(
        executeTool(tool, { scenarioId: '12345' }, { log: mockLog })
      ).rejects.toThrow(UserError);
      
      // Verify error logging
      expect(mockLog.error).toHaveBeenCalledTimes(2);
    });
    
    it('should handle partial failures in data expansion', async () => {
      const scenario = testScenarios.active;
      setupScenarioResponse(scenario);
      
      // Blueprint request fails, executions succeeds
      mockApiClient.mockResponse('GET', `/scenarios/${scenario.id}/blueprint`, testErrors.serverError);
      setupExecutionsResponse(scenario.id, [{ id: 1001, status: 'success' }]);
      
      const tool = findTool(mockTool, 'get-scenario');
      const result = await executeTool(tool, {
        scenarioId: scenario.id.toString(),
        includeBlueprint: true,
        includeExecutions: true
      }, { log: mockLog, reportProgress: mockReportProgress });
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult).toHaveProperty('scenario');
      expect(parsedResult).not.toHaveProperty('blueprint'); // Failed to load
      expect(parsedResult).toHaveProperty('recentExecutions'); // Succeeded
    });
  });

  describe('create-scenario tool - Scenario Creation and Validation', () => {
    const setupCreateResponse = (scenario: any) => {
      mockApiClient.mockResponse('POST', '/scenarios', {
        success: true,
        data: scenario
      });
    };

    it('should create scenario with minimal required data', async () => {
      const newScenario = generateTestData.scenario({
        name: 'Minimal Test Scenario'
      });
      setupCreateResponse(newScenario);
      
      const tool = findTool(mockTool, 'create-scenario');
      const result = await executeTool(tool, {
        name: 'Minimal Test Scenario'
      }, { log: mockLog, reportProgress: mockReportProgress });
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult).toHaveProperty('scenario');
      expect(parsedResult).toHaveProperty('message');
      expect(parsedResult).toHaveProperty('timestamp');
      expect(parsedResult.scenario.name).toBe('Minimal Test Scenario');
      
      expectProgressReported(mockReportProgress, [
        { progress: 0, total: 100 },
        { progress: 25, total: 100 },
        { progress: 75, total: 100 },
        { progress: 100, total: 100 }
      ]);
      
      const calls = mockApiClient.getCallLog();
      expect(calls[0]).toMatchObject({
        method: 'POST',
        endpoint: '/scenarios',
        data: { name: 'Minimal Test Scenario' }
      });
    });
    
    it('should create scenario with complete configuration', async () => {
      const complexScenario = generateTestData.scenario({
        name: 'Complete Test Scenario',
        teamId: 12345
      });
      setupCreateResponse(complexScenario);
      
      const tool = findTool(mockTool, 'create-scenario');
      const createArgs = {
        name: 'Complete Test Scenario',
        teamId: '12345',
        folderId: '3001',
        blueprint: {
          flow: [
            { id: 1, app: 'webhook', operation: 'trigger' },
            { id: 2, app: 'email', operation: 'send' }
          ],
          settings: { timeout: 30000 }
        },
        scheduling: {
          type: 'interval' as const,
          interval: 900
        }
      };
      
      const result = await executeTool(tool, createArgs, { 
        log: mockLog, 
        reportProgress: mockReportProgress 
      });
      
      const calls = mockApiClient.getCallLog();
      expect(calls[0].data).toMatchObject({
        name: 'Complete Test Scenario',
        teamId: '12345',
        folderId: '3001',
        blueprint: expect.objectContaining({
          flow: expect.any(Array),
          settings: expect.any(Object)
        }),
        scheduling: {
          type: 'interval',
          interval: 900
        }
      });
    });

    it('should validate input parameters with Zod schema', async () => {
      const tool = findTool(mockTool, 'create-scenario');
      setupCreateResponse(generateTestData.scenario());
      
      // Test valid parameters
      const validArgs = [
        { name: 'Test Scenario' }, // Minimal valid
        { name: 'Test', teamId: '123', folderId: '456' }, // With IDs
        { 
          name: 'Complex Scenario',
          blueprint: { flow: [{ id: 1, app: 'webhook' }] },
          scheduling: { type: 'immediately' as const }
        },
        {
          name: 'Interval Scenario',
          scheduling: { type: 'interval' as const, interval: 900 }
        },
        {
          name: 'Cron Scenario', 
          scheduling: { type: 'cron' as const, cron: '0 9 * * 1' }
        }
      ];
      
      for (const args of validArgs) {
        await expect(executeTool(tool, args, { log: mockLog })).resolves.toBeDefined();
      }
      
      // Test invalid parameters
      const invalidArgs = [
        {}, // Missing name
        { name: '' }, // Empty name
        { name: 'A'.repeat(101) }, // Name too long
        { name: 'Test', teamId: 123 }, // Wrong type for teamId
        { name: 'Test', folderId: 456 }, // Wrong type for folderId
        { name: 'Test', scheduling: { type: 'invalid' } }, // Invalid scheduling type
        { name: 'Test', scheduling: { type: 'interval' } }, // Missing interval
        { name: 'Test', scheduling: { type: 'interval', interval: 0 } }, // Invalid interval
        { name: 'Test', scheduling: { type: 'cron' } }, // Missing cron expression
        { name: 'Test', extraParam: 'value' } // Extra parameter
      ];
      
      for (const args of invalidArgs) {
        await expect(executeTool(tool, args, { log: mockLog })).rejects.toThrow();
      }
    });

    it('should handle API creation errors', async () => {
      const tool = findTool(mockTool, 'create-scenario');
      
      const errorScenarios = [
        {
          response: testErrors.validation,
          expectedMessage: 'Failed to create scenario: Validation failed'
        },
        {
          response: testErrors.unauthorized,
          expectedMessage: 'Failed to create scenario: Unauthorized access'
        },
        {
          response: testErrors.rateLimited,
          expectedMessage: 'Failed to create scenario: Rate limit exceeded'
        }
      ];
      
      for (const scenario of errorScenarios) {
        mockApiClient.mockResponse('POST', '/scenarios', scenario.response);
        
        await expect(
          executeTool(tool, { name: 'Test Scenario' }, { log: mockLog })
        ).rejects.toThrow(UserError);
        
        expect(mockLog.error).toHaveBeenCalledWith(
          'Failed to create scenario',
          expect.objectContaining({ 
            name: 'Test Scenario',
            error: expect.any(String)
          })
        );
        
        mockApiClient.reset();
        mockLog.error.mockClear();
      }
    });
    
    it('should handle network failures', async () => {
      const tool = findTool(mockTool, 'create-scenario');
      mockApiClient.mockFailure('POST', '/scenarios', new Error('Connection timeout'));
      
      await expect(
        executeTool(tool, { name: 'Test Scenario' }, { log: mockLog })
      ).rejects.toThrow(UserError);
      
      expectToolCall(mockLog, 'error', 'Failed to create scenario');
    });

    it('should validate complex blueprint structures', async () => {
      const tool = findTool(mockTool, 'create-scenario');
      setupCreateResponse(generateTestData.scenario());
      
      const complexBlueprint = {
        flow: [
          {
            id: 1,
            app: 'webhook',
            operation: 'trigger',
            metadata: {
              url: 'https://hook.make.com/test',
              method: 'POST'
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
            app: 'email',
            operation: 'send',
            metadata: {
              to: '{{1.email}}',
              subject: 'Order Confirmation',
              template: 'order_confirmation'
            }
          }
        ],
        settings: {
          errorHandling: 'continue',
          logging: 'full',
          timeout: 30000,
          retries: 3
        },
        variables: {
          api_key: 'env.API_KEY',
          base_url: 'https://api.example.com'
        }
      };
      
      await expect(executeTool(tool, {
        name: 'Complex Blueprint Test',
        blueprint: complexBlueprint,
        scheduling: { type: 'immediately' }
      }, { log: mockLog })).resolves.toBeDefined();
      
      const calls = mockApiClient.getCallLog();
      expect(calls[0].data.blueprint).toEqual(complexBlueprint);
    });
  });

  describe('update-scenario tool - Partial Updates and Modifications', () => {
    const setupUpdateResponse = (scenarioId: number, updatedData: any) => {
      mockApiClient.mockResponse('PATCH', `/scenarios/${scenarioId}`, {
        success: true,
        data: { ...testScenarios.active, ...updatedData }
      });
    };

    it('should update scenario name successfully', async () => {
      const scenarioId = testScenarios.active.id;
      const updatedName = 'Updated Test Scenario';
      setupUpdateResponse(scenarioId, { name: updatedName });
      
      const tool = findTool(mockTool, 'update-scenario');
      const result = await executeTool(tool, {
        scenarioId: scenarioId.toString(),
        name: updatedName
      }, { log: mockLog, reportProgress: mockReportProgress });
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult).toHaveProperty('scenario');
      expect(parsedResult).toHaveProperty('updates');
      expect(parsedResult).toHaveProperty('message');
      expect(parsedResult).toHaveProperty('timestamp');
      expect(parsedResult.updates.name).toBe(updatedName);
      
      expectProgressReported(mockReportProgress, [
        { progress: 0, total: 100 },
        { progress: 25, total: 100 },
        { progress: 75, total: 100 },
        { progress: 100, total: 100 }
      ]);
    });
    
    it('should update scenario active status', async () => {
      const scenarioId = testScenarios.active.id;
      setupUpdateResponse(scenarioId, { active: false });
      
      const tool = findTool(mockTool, 'update-scenario');
      const result = await executeTool(tool, {
        scenarioId: scenarioId.toString(),
        active: false
      }, { log: mockLog, reportProgress: mockReportProgress });
      
      const calls = mockApiClient.getCallLog();
      expect(calls[0]).toMatchObject({
        method: 'PATCH',
        endpoint: `/scenarios/${scenarioId}`,
        data: { active: false }
      });
    });
    
    it('should update complex scenario configuration', async () => {
      const scenarioId = testScenarios.active.id;
      const updateData = {
        name: 'Complex Updated Scenario',
        active: true,
        blueprint: {
          flow: [
            { id: 1, app: 'webhook', operation: 'trigger', updated: true },
            { id: 2, app: 'database', operation: 'insert' }
          ],
          settings: { timeout: 45000, retries: 5 }
        },
        scheduling: {
          type: 'cron' as const,
          cron: '0 */2 * * *'
        }
      };
      
      setupUpdateResponse(scenarioId, updateData);
      
      const tool = findTool(mockTool, 'update-scenario');
      const result = await executeTool(tool, {
        scenarioId: scenarioId.toString(),
        ...updateData
      }, { log: mockLog, reportProgress: mockReportProgress });
      
      const calls = mockApiClient.getCallLog();
      expect(calls[0].data).toMatchObject(updateData);
    });

    it('should validate input parameters', async () => {
      const tool = findTool(mockTool, 'update-scenario');
      const scenarioId = testScenarios.active.id;
      setupUpdateResponse(scenarioId, {});
      
      // Test valid parameters
      const validArgs = [
        { scenarioId: scenarioId.toString(), name: 'New Name' },
        { scenarioId: scenarioId.toString(), active: true },
        { scenarioId: scenarioId.toString(), blueprint: { flow: [] } },
        { 
          scenarioId: scenarioId.toString(), 
          scheduling: { type: 'interval' as const, interval: 1800 }
        },
        {
          scenarioId: scenarioId.toString(),
          name: 'Complete Update',
          active: false,
          blueprint: { flow: [{ id: 1, app: 'test' }] },
          scheduling: { type: 'immediately' as const }
        }
      ];
      
      for (const args of validArgs) {
        await expect(executeTool(tool, args, { log: mockLog })).resolves.toBeDefined();
      }
      
      // Test invalid parameters
      const invalidArgs = [
        {}, // Missing scenarioId
        { scenarioId: '' }, // Empty scenarioId
        { scenarioId: '123' }, // No update parameters
        { scenarioId: '123', name: '' }, // Empty name
        { scenarioId: '123', name: 'A'.repeat(101) }, // Name too long
        { scenarioId: '123', active: 'yes' }, // Wrong type
        { 
          scenarioId: '123', 
          scheduling: { type: 'invalid' } 
        }, // Invalid scheduling type
        { 
          scenarioId: '123', 
          scheduling: { type: 'interval' } 
        }, // Missing interval
        { scenarioId: '123', extraParam: 'value' } // Extra parameter
      ];
      
      for (const args of invalidArgs) {
        await expect(executeTool(tool, args, { log: mockLog })).rejects.toThrow();
      }
    });
    
    it('should handle no update parameters error', async () => {
      const tool = findTool(mockTool, 'update-scenario');
      
      await expect(
        executeTool(tool, { scenarioId: '12345' }, { log: mockLog })
      ).rejects.toThrow(UserError);
      
      expectToolCall(mockLog, 'error', 'Failed to update scenario');
    });

    it('should handle API update errors', async () => {
      const tool = findTool(mockTool, 'update-scenario');
      const scenarioId = '12345';
      
      const errorScenarios = [
        {
          response: testErrors.notFound,
          expectedMessage: 'Failed to update scenario: Resource not found'
        },
        {
          response: testErrors.unauthorized,
          expectedMessage: 'Failed to update scenario: Unauthorized access'
        },
        {
          response: testErrors.validation,
          expectedMessage: 'Failed to update scenario: Validation failed'
        }
      ];
      
      for (const scenario of errorScenarios) {
        mockApiClient.mockResponse('PATCH', `/scenarios/${scenarioId}`, scenario.response);
        
        await expect(
          executeTool(tool, { 
            scenarioId, 
            name: 'Test Update'
          }, { log: mockLog })
        ).rejects.toThrow(UserError);
        
        expect(mockLog.error).toHaveBeenCalledWith(
          'Failed to update scenario',
          expect.objectContaining({ 
            scenarioId,
            error: expect.any(String)
          })
        );
        
        mockApiClient.reset();
        mockLog.error.mockClear();
      }
    });
  });

  describe('delete-scenario tool - Safe Deletion with Force Options', () => {
    const setupDeleteResponse = (scenarioId: number) => {
      mockApiClient.mockResponse('DELETE', `/scenarios/${scenarioId}`, {
        success: true,
        data: { message: 'Scenario deleted successfully' }
      });
    };
    
    const setupScenarioCheckResponse = (scenarioId: number, active = false) => {
      mockApiClient.mockResponse('GET', `/scenarios/${scenarioId}`, {
        success: true,
        data: { ...testScenarios.active, id: scenarioId, active }
      });
    };

    it('should delete inactive scenario successfully', async () => {
      const scenarioId = testScenarios.inactive.id;
      setupScenarioCheckResponse(scenarioId, false);
      setupDeleteResponse(scenarioId);
      
      const tool = findTool(mockTool, 'delete-scenario');
      const result = await executeTool(tool, {
        scenarioId: scenarioId.toString(),
        force: false
      }, { log: mockLog, reportProgress: mockReportProgress });
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult).toHaveProperty('scenarioId');
      expect(parsedResult).toHaveProperty('message');
      expect(parsedResult).toHaveProperty('force');
      expect(parsedResult).toHaveProperty('timestamp');
      expect(parsedResult.scenarioId).toBe(scenarioId.toString());
      expect(parsedResult.force).toBe(false);
      
      expectProgressReported(mockReportProgress, [
        { progress: 0, total: 100 },
        { progress: 50, total: 100 },
        { progress: 100, total: 100 }
      ]);
      
      const calls = mockApiClient.getCallLog();
      expect(calls).toHaveLength(2); // GET for check + DELETE
      expect(calls[1]).toMatchObject({
        method: 'DELETE',
        endpoint: `/scenarios/${scenarioId}`
      });
    });
    
    it('should prevent deletion of active scenario without force', async () => {
      const scenarioId = testScenarios.active.id;
      setupScenarioCheckResponse(scenarioId, true);
      
      const tool = findTool(mockTool, 'delete-scenario');
      
      await expect(
        executeTool(tool, {
          scenarioId: scenarioId.toString(),
          force: false
        }, { log: mockLog })
      ).rejects.toThrow(UserError);
      
      expectToolCall(mockLog, 'error', 'Failed to delete scenario');
      
      // Should not call DELETE endpoint
      const calls = mockApiClient.getCallLog();
      expect(calls).toHaveLength(1); // Only GET for check
    });

    it('should force delete active scenario', async () => {
      const scenarioId = testScenarios.active.id;
      setupDeleteResponse(scenarioId);
      
      const tool = findTool(mockTool, 'delete-scenario');
      const result = await executeTool(tool, {
        scenarioId: scenarioId.toString(),
        force: true
      }, { log: mockLog, reportProgress: mockReportProgress });
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.force).toBe(true);
      
      // Should skip scenario check and go directly to DELETE
      const calls = mockApiClient.getCallLog();
      expect(calls).toHaveLength(1); // Only DELETE
      expect(calls[0]).toMatchObject({
        method: 'DELETE',
        endpoint: `/scenarios/${scenarioId}`
      });
    });
    
    it('should validate input parameters', async () => {
      const tool = findTool(mockTool, 'delete-scenario');
      const scenarioId = '12345';
      setupScenarioCheckResponse(parseInt(scenarioId), false);
      setupDeleteResponse(parseInt(scenarioId));
      
      // Test valid parameters
      const validArgs = [
        { scenarioId },
        { scenarioId, force: false },
        { scenarioId, force: true }
      ];
      
      for (const args of validArgs) {
        await expect(executeTool(tool, args, { log: mockLog })).resolves.toBeDefined();
      }
      
      // Test invalid parameters
      const invalidArgs = [
        {}, // Missing scenarioId
        { scenarioId: '' }, // Empty scenarioId
        { scenarioId: '123', force: 'yes' }, // Wrong type for force
        { scenarioId: '123', extraParam: 'value' } // Extra parameter
      ];
      
      for (const args of invalidArgs) {
        await expect(executeTool(tool, args, { log: mockLog })).rejects.toThrow();
      }
    });

    it('should validate deletion parameters', async () => {
      const { addScenarioTools } = await import('../../../src/tools/scenarios.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'delete-scenario');
      
      // Missing scenario ID
      await expect(executeTool(tool, {})).rejects.toThrow();
      
      // Invalid scenario ID
      await expect(executeTool(tool, { scenarioId: 'invalid' })).rejects.toThrow();
    });
  });

  describe('clone-scenario tool - Blueprint Cloning and Team Assignment', () => {
    const setupBlueprintResponse = (scenarioId: number, blueprint: any = { flow: [], settings: {} }) => {
      mockApiClient.mockResponse('GET', `/scenarios/${scenarioId}/blueprint`, {
        success: true,
        data: blueprint
      });
    };
    
    const setupCloneResponse = (clonedScenario: any) => {
      mockApiClient.mockResponse('POST', '/scenarios', {
        success: true,
        data: clonedScenario
      });
    };

    it('should clone scenario with basic configuration', async () => {
      const sourceId = testScenarios.active.id;
      const cloneName = 'Cloned Test Scenario';
      const blueprint = {
        flow: [
          { id: 1, app: 'webhook', operation: 'trigger' },
          { id: 2, app: 'email', operation: 'send' }
        ],
        settings: { timeout: 30000 }
      };
      
      const clonedScenario = {
        ...testScenarios.active,
        id: 9999,
        name: cloneName,
        active: false
      };
      
      setupBlueprintResponse(sourceId, blueprint);
      setupCloneResponse(clonedScenario);
      
      const tool = findTool(mockTool, 'clone-scenario');
      const result = await executeTool(tool, {
        scenarioId: sourceId.toString(),
        name: cloneName
      }, { log: mockLog, reportProgress: mockReportProgress });
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult).toHaveProperty('originalScenarioId');
      expect(parsedResult).toHaveProperty('clonedScenario');
      expect(parsedResult).toHaveProperty('message');
      expect(parsedResult).toHaveProperty('timestamp');
      expect(parsedResult.originalScenarioId).toBe(sourceId.toString());
      expect(parsedResult.clonedScenario.name).toBe(cloneName);
      
      expectProgressReported(mockReportProgress, [
        { progress: 0, total: 100 },
        { progress: 25, total: 100 },
        { progress: 50, total: 100 },
        { progress: 100, total: 100 }
      ]);
      
      const calls = mockApiClient.getCallLog();
      expect(calls).toHaveLength(2);
      expect(calls[0]).toMatchObject({
        method: 'GET',
        endpoint: `/scenarios/${sourceId}/blueprint`
      });
      expect(calls[1]).toMatchObject({
        method: 'POST',
        endpoint: '/scenarios',
        data: {
          name: cloneName,
          blueprint,
          active: false
        }
      });
    });
    
    it('should clone scenario with team and folder assignment', async () => {
      const sourceId = testScenarios.active.id;
      const cloneName = 'Cross-team Clone';
      const targetTeamId = '54321';
      const targetFolderId = '6789';
      const blueprint = { flow: [], settings: {} };
      
      const clonedScenario = {
        ...testScenarios.active,
        id: 9999,
        name: cloneName,
        teamId: parseInt(targetTeamId),
        folderId: parseInt(targetFolderId),
        active: true
      };
      
      setupBlueprintResponse(sourceId, blueprint);
      setupCloneResponse(clonedScenario);
      
      const tool = findTool(mockTool, 'clone-scenario');
      const result = await executeTool(tool, {
        scenarioId: sourceId.toString(),
        name: cloneName,
        teamId: targetTeamId,
        folderId: targetFolderId,
        active: true
      }, { log: mockLog, reportProgress: mockReportProgress });
      
      const calls = mockApiClient.getCallLog();
      expect(calls[1].data).toMatchObject({
        name: cloneName,
        blueprint,
        active: true,
        teamId: targetTeamId,
        folderId: targetFolderId
      });
    });
    
    it('should validate input parameters', async () => {
      const tool = findTool(mockTool, 'clone-scenario');
      const sourceId = '12345';
      const blueprint = { flow: [] };
      
      setupBlueprintResponse(parseInt(sourceId), blueprint);
      setupCloneResponse(generateTestData.scenario());
      
      // Test valid parameters
      const validArgs = [
        { scenarioId: sourceId, name: 'Clone Test' },
        { scenarioId: sourceId, name: 'Clone', teamId: '123' },
        { scenarioId: sourceId, name: 'Clone', folderId: '456' },
        { scenarioId: sourceId, name: 'Clone', active: true },
        {
          scenarioId: sourceId,
          name: 'Complete Clone',
          teamId: '123',
          folderId: '456',
          active: false
        }
      ];
      
      for (const args of validArgs) {
        await expect(executeTool(tool, args, { log: mockLog })).resolves.toBeDefined();
      }
      
      // Test invalid parameters
      const invalidArgs = [
        {}, // Missing scenarioId and name
        { scenarioId: sourceId }, // Missing name
        { name: 'Clone' }, // Missing scenarioId
        { scenarioId: '', name: 'Clone' }, // Empty scenarioId
        { scenarioId: sourceId, name: '' }, // Empty name
        { scenarioId: sourceId, name: 'A'.repeat(101) }, // Name too long
        { scenarioId: sourceId, name: 'Clone', teamId: 123 }, // Wrong type
        { scenarioId: sourceId, name: 'Clone', active: 'yes' }, // Wrong type
        { scenarioId: sourceId, name: 'Clone', extraParam: 'value' } // Extra parameter
      ];
      
      for (const args of invalidArgs) {
        await expect(executeTool(tool, args, { log: mockLog })).rejects.toThrow();
      }
    });
    
    it('should handle blueprint retrieval failure', async () => {
      const tool = findTool(mockTool, 'clone-scenario');
      const sourceId = '12345';
      
      mockApiClient.mockResponse('GET', `/scenarios/${sourceId}/blueprint`, testErrors.notFound);
      
      await expect(
        executeTool(tool, {
          scenarioId: sourceId,
          name: 'Failed Clone'
        }, { log: mockLog })
      ).rejects.toThrow(UserError);
      
      expectToolCall(mockLog, 'error', 'Failed to clone scenario');
    });
    
    it('should handle clone creation failure', async () => {
      const tool = findTool(mockTool, 'clone-scenario');
      const sourceId = '12345';
      
      setupBlueprintResponse(parseInt(sourceId), { flow: [] });
      mockApiClient.mockResponse('POST', '/scenarios', testErrors.validation);
      
      await expect(
        executeTool(tool, {
          scenarioId: sourceId,
          name: 'Failed Clone'
        }, { log: mockLog })
      ).rejects.toThrow(UserError);
      
      expectToolCall(mockLog, 'error', 'Failed to clone scenario');
    });
  });

  describe('Error handling and logging', () => {
    it('should log all tool operations', async () => {
      mockApiClient.mockResponse('GET', '/scenarios', {
        success: true,
        data: [testScenarios.active]
      });

      const { addScenarioTools } = await import('../../../src/tools/scenarios.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-scenarios');
      const mockLog = {
        info: jest.fn(),
        error: jest.fn(),
        warn: jest.fn(),
        debug: jest.fn()
      };
      
      await executeTool(tool, {}, { log: mockLog });
      
      expectToolCall(mockLog, 'info', 'Listing scenarios');
      expectToolCall(mockLog, 'info', 'Successfully retrieved scenarios');
    });

    it('should handle rate limiting errors', async () => {
      mockApiClient.mockResponse('GET', '/scenarios', testErrors.rateLimited);

      const { addScenarioTools } = await import('../../../src/tools/scenarios.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-scenarios');
      
      await expect(executeTool(tool, {})).rejects.toThrow(UserError);
    });

    it('should handle unauthorized access', async () => {
      mockApiClient.mockResponse('GET', '/scenarios', testErrors.unauthorized);

      const { addScenarioTools } = await import('../../../src/tools/scenarios.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-scenarios');
      
      await expect(executeTool(tool, {})).rejects.toThrow(UserError);
    });
  });

  describe('Complex scenario operations', () => {
    it('should handle complex scenario blueprint', async () => {
      const complexScenario = createComplexTestScenario();
      mockApiClient.mockResponse('POST', '/scenarios', {
        success: true,
        data: complexScenario
      });

      const { addScenarioTools } = await import('../../../src/tools/scenarios.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-scenario');
      const result = await executeTool(tool, {
        name: complexScenario.name,
        blueprint: complexScenario.blueprint,
        scheduling: complexScenario.scheduling,
        teamId: complexScenario.teamId
      });
      
      expect(result).toContain(complexScenario.name);
      
      const calls = mockApiClient.getCallLog();
      expect(calls[0].data.blueprint.flow).toHaveLength(7);
      expect(calls[0].data.blueprint.settings).toBeDefined();
    });

    it('should handle stress conditions and bulk operations', async () => {
      // Test multiple rapid operations
      const listTool = findTool(mockTool, 'list-scenarios');
      
      // Setup responses for multiple pages
      for (let page = 0; page < 10; page++) {
        mockApiClient.mockResponse('GET', '/scenarios', {
          success: true,
          data: Array.from({ length: 10 }, () => generateTestData.scenario()),
          metadata: { total: 100, page: page + 1, limit: 10 }
        });
      }
      
      // Execute multiple list operations with different pagination
      const promises = Array.from({ length: 10 }, (_, index) =>
        executeTool(listTool, {
          limit: 10,
          offset: index * 10
        }, { log: mockLog })
      );
      
      const results = await Promise.all(promises);
      
      expect(results).toHaveLength(10);
      results.forEach((result, index) => {
        const parsed = JSON.parse(result);
        expect(parsed.scenarios).toHaveLength(10);
        expect(parsed.pagination.offset).toBe(index * 10);
      });
      
      // Verify API calls were made correctly
      const calls = mockApiClient.getCallLog();
      expect(calls).toHaveLength(10);
    });
    
    it('should handle data consistency and validation edge cases', async () => {
      const createTool = findTool(mockTool, 'create-scenario');
      
      // Test edge cases for name validation
      const edgeCaseNames = [
        'A', // Minimum length
        'A'.repeat(100), // Maximum length
        'Scenario with spaces and numbers 123',
        'Scenario-with-dashes_and_underscores',
        'Scénàrio wîth ñoñ-ASCII çhàrs' // Unicode characters
      ];
      
      for (const name of edgeCaseNames) {
        mockApiClient.mockResponse('POST', '/scenarios', {
          success: true,
          data: generateTestData.scenario({ name })
        });
        
        await expect(
          executeTool(createTool, { name }, { log: mockLog })
        ).resolves.toBeDefined();
        
        const calls = mockApiClient.getCallLog();
        expect(calls[calls.length - 1].data.name).toBe(name);
      }
    });
  });
  
  describe('Performance and Reliability Testing', () => {
    it('should maintain performance under load', async () => {
      const tool = findTool(mockTool, 'list-scenarios');
      mockApiClient.mockResponse('GET', '/scenarios', {
        success: true,
        data: Array.from({ length: 100 }, () => generateTestData.scenario())
      });
      
      const executionTime = await performanceHelpers.expectExecutionTime(
        () => executeTool(tool, { limit: 100 }, { log: mockLog }),
        2000, // Should complete within 2 seconds
        'Large scenario list'
      );
      
      expect(executionTime).toBeDefined();
      
      const result = JSON.parse(executionTime);
      expect(result.scenarios).toHaveLength(100);
    });
    
    it('should handle memory efficiently with large datasets', async () => {
      const tool = findTool(mockTool, 'get-scenario');
      
      // Create a large blueprint to test memory handling
      const largeBlueprint = {
        flow: Array.from({ length: 100 }, (_, i) => ({
          id: i + 1,
          app: `app_${i}`,
          operation: 'process',
          metadata: {
            config: Array.from({ length: 50 }, (_, j) => `config_${j}`),
            data: 'x'.repeat(1000) // 1KB of data per module
          }
        })),
        settings: {
          variables: Object.fromEntries(
            Array.from({ length: 200 }, (_, i) => [`var_${i}`, `value_${i}`])
          )
        }
      };
      
      const scenario = generateTestData.scenario({ blueprint: largeBlueprint });
      
      mockApiClient.mockResponse('GET', `/scenarios/${scenario.id}`, {
        success: true,
        data: scenario
      });
      mockApiClient.mockResponse('GET', `/scenarios/${scenario.id}/blueprint`, {
        success: true,
        data: largeBlueprint
      });
      
      const result = await executeTool(tool, {
        scenarioId: scenario.id.toString(),
        includeBlueprint: true
      }, { log: mockLog });
      
      const parsed = JSON.parse(result);
      expect(parsed.blueprint.flow).toHaveLength(100);
      expect(Object.keys(parsed.blueprint.settings.variables)).toHaveLength(200);
    });
    
    it('should gracefully degrade under adverse conditions', async () => {
      const tool = findTool(mockTool, 'list-scenarios');
      
      // Simulate unreliable network
      simulateNetworkConditions.unreliable(mockApiClient, '/scenarios', 0.7); // 70% failure rate
      
      // Should still handle requests that succeed
      mockApiClient.mockResponse('GET', '/scenarios', {
        success: true,
        data: [testScenarios.active]
      });
      
      // Some requests will fail, some will succeed
      const promises = Array.from({ length: 10 }, () =>
        executeTool(tool, {}, { log: mockLog }).catch(error => error)
      );
      
      const results = await Promise.all(promises);
      
      // Should have both successes and failures
      const successes = results.filter(r => typeof r === 'string');
      const failures = results.filter(r => r instanceof Error);
      
      expect(successes.length + failures.length).toBe(10);
      expect(failures.length).toBeGreaterThan(0); // Some should fail due to unreliable network
    });
  });
});