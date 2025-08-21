/**
 * @fileoverview Full Integration Test Suite for Refactored Scenarios Module
 * 
 * This test suite validates that the refactored scenarios module maintains
 * 100% functional equivalence with the original monolithic implementation.
 * 
 * Tests cover:
 * - Complete tool registration and FastMCP integration
 * - Full scenario management workflow
 * - API compatibility verification
 * - Integration between refactored components
 * - Error handling and validation chain
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

describe('Scenarios Module - Full Integration Suite', () => {
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

    // Add refactored scenario tools to server
    addScenarioTools(server, mockApiClient);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Tool Registration Validation', () => {
    test('should register all expected scenario management tools', () => {
      const toolNames = Array.from((server as any).tools.keys());

      // Verify core CRUD tools
      expect(toolNames).toContain('list-scenarios');
      expect(toolNames).toContain('get-scenario');
      expect(toolNames).toContain('create-scenario');
      expect(toolNames).toContain('update-scenario');
      expect(toolNames).toContain('delete-scenario');
      expect(toolNames).toContain('clone-scenario');
      expect(toolNames).toContain('run-scenario');
      
      // Verify blueprint management tools
      expect(toolNames).toContain('validate-blueprint');
      expect(toolNames).toContain('extract-blueprint-connections');
      expect(toolNames).toContain('optimize-blueprint');
      
      // Verify diagnostic tools  
      expect(toolNames).toContain('troubleshoot-scenario');
      expect(toolNames).toContain('generate-troubleshooting-report');

      // Verify tool count matches expected
      expect(toolNames.length).toBe(11);
    });

    test('should maintain identical tool configurations as original', () => {
      const tools = (server as any).tools;
      
      // Verify descriptions match original implementation
      expect(tools.get('list-scenarios').description).toContain('List and search Make.com scenarios');
      expect(tools.get('get-scenario').description).toContain('Get detailed information');
      expect(tools.get('create-scenario').description).toContain('Create a new Make.com scenario');
      expect(tools.get('update-scenario').description).toContain('Update an existing Make.com scenario');
      expect(tools.get('delete-scenario').description).toContain('Delete a Make.com scenario');
      expect(tools.get('clone-scenario').description).toContain('Clone an existing Make.com scenario');
      expect(tools.get('run-scenario').description).toContain('Execute a Make.com scenario');
      
      // Verify new blueprint tools have proper descriptions
      expect(tools.get('validate-blueprint').description).toContain('Validate Make.com scenario blueprint');
      expect(tools.get('extract-blueprint-connections').description).toContain('Extract connection requirements');
      expect(tools.get('optimize-blueprint').description).toContain('Analyze and optimize scenario blueprint');
      
      // Verify troubleshooting tools
      expect(tools.get('troubleshoot-scenario').description).toContain('Diagnose scenario issues');
      expect(tools.get('generate-troubleshooting-report').description).toContain('Generate comprehensive troubleshooting report');
    });

    test('should preserve FastMCP metadata and annotations', () => {
      const tools = (server as any).tools;
      
      // Verify tools have proper FastMCP metadata
      for (const [toolName, tool] of tools.entries()) {
        expect(tool.inputSchema).toBeDefined();
        expect(typeof tool.execute).toBe('function');
        
        // Verify tool is properly bound to server
        expect(tool.server).toBe(server);
      }
    });
  });

  describe('Complete Scenario Workflow Integration', () => {
    const mockScenario = {
      id: 'scn_integration_test',
      name: 'Integration Test Scenario',
      active: false,
      teamId: 'team_123',
      folderId: 'folder_456'
    };

    const mockBlueprint = {
      name: 'Test Blueprint',
      metadata: {
        version: 1,
        scenario: {
          roundtrips: 5,
          maxErrors: 3,
          autoCommit: true,
          sequential: false,
          confidential: true,
          dlq: true
        }
      },
      flow: [
        {
          id: 1,
          module: 'webhook',
          version: 1,
          parameters: { port: 8080 }
        },
        {
          id: 2,
          module: 'http',
          version: 1,
          connection: 1,
          parameters: { url: 'https://api.example.com' }
        }
      ]
    };

    beforeEach(() => {
      // Set up API responses for complete workflow
      mockApiClient.get.mockImplementation((url: string) => {
        if (url === '/scenarios') {
          return Promise.resolve({
            success: true,
            data: [mockScenario],
            metadata: { total: 1 }
          });
        } else if (url === `/scenarios/${mockScenario.id}`) {
          return Promise.resolve({
            success: true,
            data: mockScenario
          });
        } else if (url === `/scenarios/${mockScenario.id}/blueprint`) {
          return Promise.resolve({
            success: true,
            data: mockBlueprint
          });
        }
        return Promise.resolve({ success: false, error: { message: 'Not found' } });
      });

      mockApiClient.post.mockResolvedValue({
        success: true,
        data: { ...mockScenario, id: 'scn_created' }
      });

      mockApiClient.patch.mockResolvedValue({
        success: true,
        data: { ...mockScenario, active: true }
      });

      mockApiClient.delete.mockResolvedValue({
        success: true,
        data: {}
      });
    });

    test('should execute complete CRUD workflow successfully', async () => {
      // 1. List scenarios
      const listTool = (server as any).tools.get('list-scenarios');
      const listResult = await listTool.execute({}, { log: mockLog, reportProgress: mockReportProgress });
      const listData = JSON.parse(listResult);
      expect(listData.scenarios).toHaveLength(1);

      // 2. Get scenario details
      const getTool = (server as any).tools.get('get-scenario');
      const getResult = await getTool.execute(
        { scenarioId: mockScenario.id, includeBlueprint: true },
        { log: mockLog, reportProgress: mockReportProgress }
      );
      const getdata = JSON.parse(getResult);
      expect(getdata.scenario.id).toBe(mockScenario.id);
      expect(getdata.blueprint).toEqual(mockBlueprint);

      // 3. Create new scenario
      const createTool = (server as any).tools.get('create-scenario');
      const createResult = await createTool.execute(
        { name: 'New Scenario', blueprint: mockBlueprint },
        { log: mockLog, reportProgress: mockReportProgress }
      );
      const createData = JSON.parse(createResult);
      expect(createData.scenario.id).toBe('scn_created');

      // 4. Update scenario
      const updateTool = (server as any).tools.get('update-scenario');
      await updateTool.execute(
        { scenarioId: mockScenario.id, active: true },
        { log: mockLog, reportProgress: mockReportProgress }
      );

      // 5. Clone scenario
      const cloneTool = (server as any).tools.get('clone-scenario');
      await cloneTool.execute(
        { scenarioId: mockScenario.id, name: 'Cloned Scenario' },
        { log: mockLog, reportProgress: mockReportProgress }
      );

      // 6. Delete scenario
      const deleteTool = (server as any).tools.get('delete-scenario');
      await deleteTool.execute(
        { scenarioId: mockScenario.id, force: true },
        { log: mockLog, reportProgress: mockReportProgress }
      );

      // Verify all API calls were made
      expect(mockApiClient.get).toHaveBeenCalledTimes(4); // list, get, get blueprint, clone blueprint
      expect(mockApiClient.post).toHaveBeenCalledTimes(2); // create, clone
      expect(mockApiClient.patch).toHaveBeenCalledTimes(1); // update
      expect(mockApiClient.delete).toHaveBeenCalledTimes(1); // delete
    });

    test('should handle blueprint management workflow', async () => {
      // 1. Validate blueprint
      const validateTool = (server as any).tools.get('validate-blueprint');
      const validateResult = await validateTool.execute(
        { blueprint: mockBlueprint, strict: true, includeSecurityChecks: true },
        { log: mockLog, reportProgress: mockReportProgress }
      );
      const validateData = JSON.parse(validateResult);
      expect(validateData.isValid).toBe(true);
      expect(validateData.errors).toHaveLength(0);

      // 2. Extract connections
      const extractTool = (server as any).tools.get('extract-blueprint-connections');
      const extractResult = await extractTool.execute(
        { blueprint: mockBlueprint, includeOptional: true, groupByModule: true },
        { log: mockLog, reportProgress: mockReportProgress }
      );
      const extractData = JSON.parse(extractResult);
      expect(extractData.requiredConnections).toBeDefined();
      expect(extractData.connectionSummary).toBeDefined();

      // 3. Optimize blueprint
      const optimizeTool = (server as any).tools.get('optimize-blueprint');
      const optimizeResult = await optimizeTool.execute(
        { blueprint: mockBlueprint, optimizationType: 'all', includeImplementationSteps: true },
        { log: mockLog, reportProgress: mockReportProgress }
      );
      const optimizeData = JSON.parse(optimizeResult);
      expect(optimizeData.recommendations).toBeDefined();
      expect(optimizeData.summary).toBeDefined();
    });

    test('should execute troubleshooting workflow', async () => {
      // Mock troubleshooting data
      const mockExecutions = [
        { id: 'exec_1', status: 'success', duration: 1000 },
        { id: 'exec_2', status: 'error', duration: 500 }
      ];

      mockApiClient.get.mockImplementation((url: string) => {
        if (url.includes('/executions')) {
          return Promise.resolve({
            success: true,
            data: mockExecutions
          });
        }
        return mockApiClient.get.mock.results[0]?.value;
      });

      // 1. Troubleshoot individual scenario
      const troubleshootTool = (server as any).tools.get('troubleshoot-scenario');
      const troubleshootResult = await troubleshootTool.execute(
        {
          scenarioId: mockScenario.id,
          diagnosticTypes: ['all'],
          includeRecommendations: true,
          includePerformanceHistory: true
        },
        { log: mockLog, reportProgress: mockReportProgress }
      );
      const troubleshootData = JSON.parse(troubleshootResult);
      expect(troubleshootData.findings).toBeDefined();

      // 2. Generate comprehensive report
      const reportTool = (server as any).tools.get('generate-troubleshooting-report');
      const reportResult = await reportTool.execute(
        {
          scenarioIds: [mockScenario.id],
          reportOptions: {
            includeExecutiveSummary: true,
            includeDetailedAnalysis: true,
            includeActionPlan: true
          }
        },
        { log: mockLog, reportProgress: mockReportProgress }
      );
      const reportData = JSON.parse(reportResult);
      expect(reportData.metadata).toBeDefined();
      expect(reportData.executiveSummary).toBeDefined();
    });
  });

  describe('Error Handling and Validation Chain', () => {
    test('should handle validation errors consistently across all tools', async () => {
      const testCases = [
        { tool: 'list-scenarios', args: { limit: -1 } },
        { tool: 'get-scenario', args: { scenarioId: '' } },
        { tool: 'create-scenario', args: { name: '' } },
        { tool: 'update-scenario', args: { scenarioId: 'test' } }, // Missing update params
        { tool: 'delete-scenario', args: { scenarioId: '' } },
        { tool: 'clone-scenario', args: { scenarioId: 'test' } }, // Missing name
        { tool: 'run-scenario', args: { scenarioId: '', timeout: -1 } }
      ];

      for (const testCase of testCases) {
        const tool = (server as any).tools.get(testCase.tool);
        await expect(
          tool.execute(testCase.args, { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow();
      }
    });

    test('should handle API failures uniformly', async () => {
      const apiError = {
        success: false,
        error: { message: 'API Rate Limit Exceeded', code: 'RATE_LIMIT' }
      };

      mockApiClient.get.mockResolvedValue(apiError);
      mockApiClient.post.mockResolvedValue(apiError);
      mockApiClient.patch.mockResolvedValue(apiError);
      mockApiClient.delete.mockResolvedValue(apiError);

      const testTools = ['list-scenarios', 'get-scenario', 'create-scenario', 'update-scenario', 'delete-scenario'];
      const testArgs = [
        {},
        { scenarioId: 'test' },
        { name: 'Test' },
        { scenarioId: 'test', name: 'Test' },
        { scenarioId: 'test', force: true }
      ];

      for (let i = 0; i < testTools.length; i++) {
        const tool = (server as any).tools.get(testTools[i]);
        await expect(
          tool.execute(testArgs[i], { log: mockLog, reportProgress: mockReportProgress })
        ).rejects.toThrow(UserError);
      }
    });

    test('should propagate network errors correctly', async () => {
      const networkError = new Error('Network timeout');
      
      mockApiClient.get.mockRejectedValue(networkError);
      mockApiClient.post.mockRejectedValue(networkError);

      const listTool = (server as any).tools.get('list-scenarios');
      await expect(
        listTool.execute({}, { log: mockLog, reportProgress: mockReportProgress })
      ).rejects.toThrow(UserError);

      const createTool = (server as any).tools.get('create-scenario');
      await expect(
        createTool.execute({ name: 'Test' }, { log: mockLog, reportProgress: mockReportProgress })
      ).rejects.toThrow(UserError);
    });
  });

  describe('Performance and Compatibility', () => {
    test('should maintain response time benchmarks', async () => {
      const mockLargeScenarios = Array.from({ length: 100 }, (_, i) => ({
        id: `scn_${i}`,
        name: `Scenario ${i}`,
        active: i % 2 === 0
      }));

      mockApiClient.get.mockResolvedValue({
        success: true,
        data: mockLargeScenarios,
        metadata: { total: mockLargeScenarios.length }
      });

      const listTool = (server as any).tools.get('list-scenarios');
      const startTime = Date.now();
      
      const result = await listTool.execute(
        { limit: 100 },
        { log: mockLog, reportProgress: mockReportProgress }
      );
      
      const endTime = Date.now();
      const responseTime = endTime - startTime;
      
      // Should complete within reasonable time (< 1 second)
      expect(responseTime).toBeLessThan(1000);
      
      const data = JSON.parse(result);
      expect(data.scenarios).toHaveLength(100);
    });

    test('should handle large blueprint processing efficiently', async () => {
      const largeBlueprintModules = Array.from({ length: 1000 }, (_, i) => ({
        id: i + 1,
        module: `module_${i}`,
        version: 1,
        parameters: { config: `value_${i}` }
      }));

      const largeBlueprint = {
        name: 'Large Blueprint',
        metadata: {
          version: 1,
          scenario: {
            roundtrips: 1,
            maxErrors: 5,
            autoCommit: true,
            sequential: false,
            confidential: true,
            dlq: true
          }
        },
        flow: largeBlueprintModules
      };

      const validateTool = (server as any).tools.get('validate-blueprint');
      const startTime = Date.now();
      
      const result = await validateTool.execute(
        { blueprint: largeBlueprint, strict: true },
        { log: mockLog, reportProgress: mockReportProgress }
      );
      
      const endTime = Date.now();
      const processingTime = endTime - startTime;
      
      // Should handle large blueprints efficiently (< 2 seconds)
      expect(processingTime).toBeLessThan(2000);
      
      const data = JSON.parse(result);
      expect(data.isValid).toBe(true);
    });
  });

  describe('Regression Prevention', () => {
    test('should preserve exact API parameter mapping', async () => {
      const listTool = (server as any).tools.get('list-scenarios');
      
      await listTool.execute({
        teamId: 'team_123',
        folderId: 'folder_456',
        limit: 25,
        offset: 50,
        search: 'test query',
        active: true
      }, { log: mockLog, reportProgress: mockReportProgress });

      expect(mockApiClient.get).toHaveBeenCalledWith('/scenarios', {
        params: {
          teamId: 'team_123',
          folderId: 'folder_456', 
          limit: 25,
          offset: 50,
          q: 'test query',
          active: true
        }
      });
    });

    test('should maintain identical error message formats', async () => {
      mockApiClient.get.mockResolvedValue({
        success: false,
        error: { message: 'Custom API Error', code: 'CUSTOM_ERROR' }
      });

      const getTool = (server as any).tools.get('get-scenario');
      
      try {
        await getTool.execute({ scenarioId: 'test' }, { log: mockLog, reportProgress: mockReportProgress });
        fail('Should have thrown an error');
      } catch (error) {
        expect(error).toBeInstanceOf(UserError);
        expect((error as Error).message).toContain('Failed to get scenario: Custom API Error');
      }
    });

    test('should preserve progress reporting behavior', async () => {
      mockApiClient.get.mockResolvedValue({
        success: true,
        data: [],
        metadata: { total: 0 }
      });

      const listTool = (server as any).tools.get('list-scenarios');
      await listTool.execute({}, { log: mockLog, reportProgress: mockReportProgress });

      // Verify progress reporting calls match original behavior
      expect(mockReportProgress).toHaveBeenCalledWith({ progress: 0, total: 100 });
      expect(mockReportProgress).toHaveBeenCalledWith({ progress: 25, total: 100 });
      expect(mockReportProgress).toHaveBeenCalledWith({ progress: 75, total: 100 });
      expect(mockReportProgress).toHaveBeenCalledWith({ progress: 100, total: 100 });
    });
  });
});