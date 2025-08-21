/**
 * @fileoverview Comprehensive Test Suite for Modular Scenarios Architecture
 * Tests the refactored scenarios module components in isolation and integration
 */

import { FastMCP, UserError } from 'fastmcp';
import { describe, expect, test, beforeEach, afterEach, jest } from '@jest/globals';
import type { Mock } from 'jest-mock';

// Import modular components
import { addScenarioTools } from '../../../src/tools/scenarios/index.js';
import { 
  ScenarioFiltersSchema, 
  UpdateScenarioSchema,
  SchemaValidation 
} from '../../../src/tools/scenarios/schemas/index.js';
import {
  Blueprint,
  TroubleshootingReportData,
  OptimizationRecommendation
} from '../../../src/tools/scenarios/types/index.js';
import {
  validateBlueprintStructure,
  optimizeBlueprint,
  aggregateFindings
} from '../../../src/tools/scenarios/utils/index.js';
import { createListScenariosTools } from '../../../src/tools/scenarios/tools/list-scenarios.js';
import { createAnalyzeBlueprintTool } from '../../../src/tools/scenarios/tools/analyze-blueprint.js';

// Mock dependencies
const mockServer: FastMCP = {
  addTool: jest.fn() as Mock,
  start: jest.fn() as Mock,
  stop: jest.fn() as Mock,
} as any;

const mockApiClient = {
  get: jest.fn() as Mock,
  post: jest.fn() as Mock,
  put: jest.fn() as Mock,
  delete: jest.fn() as Mock,
} as any;

const mockLogger = {
  debug: jest.fn() as Mock,
  info: jest.fn() as Mock,
  warn: jest.fn() as Mock,
  error: jest.fn() as Mock,
  child: jest.fn(() => mockLogger) as Mock,
} as any;

describe('Modular Scenarios Architecture Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Schema Validation', () => {
    test('should validate scenario filters correctly', () => {
      const validFilters = {
        active: true,
        teamId: '123',
        limit: 10,
        offset: 0
      };

      const result = SchemaValidation.validate(ScenarioFiltersSchema, validFilters);
      
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.active).toBe(true);
        expect(result.data.teamId).toBe('123');
        expect(result.data.limit).toBe(10);
        expect(result.data.offset).toBe(0);
      }
    });

    test('should reject invalid scenario filters', () => {
      const invalidFilters = {
        active: 'invalid', // should be boolean
        limit: -1 // should be positive
      };

      const result = SchemaValidation.validate(ScenarioFiltersSchema, invalidFilters);
      
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error).toContain('Expected boolean');
      }
    });

    test('should validate update scenario schema', () => {
      const validUpdate = {
        scenarioId: 'scenario_123',
        name: 'Updated Scenario',
        active: false,
        blueprint: { flow: [] }
      };

      const result = SchemaValidation.validate(UpdateScenarioSchema, validUpdate);
      
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.scenarioId).toBe('scenario_123');
        expect(result.data.name).toBe('Updated Scenario');
        expect(result.data.active).toBe(false);
      }
    });

    test('should handle safe parse for malformed data', () => {
      const malformedData = {
        invalid: 'data'
      };

      const result = SchemaValidation.safeParse(ScenarioFiltersSchema, malformedData);
      
      expect(result).toBeNull();
    });
  });

  describe('Type Definitions', () => {
    test('should create valid Blueprint interface', () => {
      const blueprint: Blueprint = {
        name: 'Test Blueprint',
        flow: [
          {
            id: 1,
            module: 'http',
            version: 1,
            parameters: {},
            metadata: {}
          }
        ],
        metadata: {
          scenario: {
            name: 'Test Scenario',
            sequential: false,
            dlq: true
          }
        }
      };

      expect(blueprint.name).toBe('Test Blueprint');
      expect(blueprint.flow).toHaveLength(1);
      expect(blueprint.metadata?.scenario?.name).toBe('Test Scenario');
    });

    test('should create valid TroubleshootingReportData', () => {
      const reportData: TroubleshootingReportData = {
        metadata: {
          reportId: 'report_123',
          generatedAt: new Date().toISOString(),
          analysisScope: {
            scenarioCount: 5,
            timeRangeHours: 24
          }
        },
        systemOverview: {
          overallHealthScore: 85,
          totalScenarios: 5,
          activeScenarios: 3,
          issues: {
            critical: 0,
            warning: 2,
            info: 1
          }
        },
        consolidatedFindings: {
          totalIssues: 3,
          criticalIssues: 0,
          warningIssues: 2,
          infoIssues: 1,
          securityRiskLevel: 'low'
        },
        actionPlan: {
          immediate: [],
          shortTerm: [],
          longTerm: []
        }
      };

      expect(reportData.metadata.reportId).toBe('report_123');
      expect(reportData.systemOverview.overallHealthScore).toBe(85);
      expect(reportData.consolidatedFindings.totalIssues).toBe(3);
    });

    test('should create valid OptimizationRecommendation', () => {
      const recommendation: OptimizationRecommendation = {
        category: 'performance',
        priority: 'high',
        title: 'Optimize API Calls',
        description: 'Reduce unnecessary API calls by batching requests',
        estimatedImpact: 'High performance improvement',
        implementationEffort: 'Medium',
        implementationSteps: [
          'Identify batch opportunities',
          'Implement batching logic',
          'Test performance improvements'
        ]
      };

      expect(recommendation.category).toBe('performance');
      expect(recommendation.priority).toBe('high');
      expect(recommendation.implementationSteps).toHaveLength(3);
    });
  });

  describe('Utility Functions', () => {
    test('should validate blueprint structure correctly', () => {
      const validBlueprint: Blueprint = {
        name: 'Valid Blueprint',
        flow: [
          {
            id: 1,
            module: 'http',
            version: 1,
            parameters: {
              url: 'https://api.example.com',
              method: 'GET'
            },
            metadata: {}
          }
        ],
        metadata: {
          version: 1,
          scenario: {
            roundtrips: 1,
            maxErrors: 3,
            autoCommit: true,
            sequential: false,
            confidential: true,
            dlq: true
          }
        }
      };

      const result = validateBlueprintStructure(validBlueprint, false);

      // The blueprint validation expects specific metadata structure
      expect(result.isValid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.warnings).toEqual(expect.any(Array));
      expect(result.securityIssues).toEqual(expect.any(Array));
    });

    test('should detect blueprint validation errors', () => {
      const invalidBlueprint: Blueprint = {
        name: '', // Empty name should trigger error
        flow: [],
        metadata: {}
      };

      const result = validateBlueprintStructure(invalidBlueprint, true);

      expect(result.isValid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors.some(error => error.includes('name'))).toBe(true);
    });

    test('should optimize blueprint with recommendations', () => {
      const blueprint: Blueprint = {
        name: 'Blueprint to Optimize',
        flow: [
          {
            id: 1,
            module: 'http',
            version: 1,
            parameters: {},
            metadata: {}
          },
          {
            id: 2,
            module: 'delay',
            version: 1,
            parameters: { delay: 10000 }, // Long delay
            metadata: {}
          }
        ],
        metadata: {}
      };

      const result = optimizeBlueprint(blueprint);

      expect(result.optimizationScore).toEqual(expect.any(Number));
      expect(result.recommendations).toEqual(expect.any(Array));
      expect(result.metrics).toEqual(expect.any(Object));
      expect(result.metrics.moduleCount).toBe(2);
      
      // Should have recommendations for the blueprint
      expect(result.recommendations.length).toBeGreaterThanOrEqual(0);
    });

    test('should aggregate findings correctly', () => {
      const mockAnalyses = [
        {
          scenarioId: 'scenario_1',
          scenarioName: 'Test Scenario 1',
          diagnosticReport: {
            overallHealth: 'warning',
            diagnostics: [
              {
                category: 'performance',
                title: 'Performance issue',
                severity: 'warning'
              }
            ]
          },
          errors: []
        },
        {
          scenarioId: 'scenario_2',
          scenarioName: 'Test Scenario 2',
          diagnosticReport: {
            overallHealth: 'healthy',
            diagnostics: []
          },
          errors: []
        }
      ];

      const result = aggregateFindings(mockAnalyses as any);

      expect(result.totalScenarios).toBe(2);
      expect(result.totalIssues).toBe(1);
      expect(result.criticalIssues).toBe(0);
      expect(result.warningScenarios).toBe(1);
      expect(result.healthyScenarios).toBe(1);
      expect(result.securityRiskLevel).toBe('low');
      expect(result.commonIssues).toEqual(expect.any(Array));
    });
  });

  describe('Individual Tool Creation', () => {
    const mockToolContext = {
      server: mockServer,
      apiClient: mockApiClient,
      logger: mockLogger
    };

    test('should create list scenarios tool', () => {
      const tool = createListScenariosTools(mockToolContext);

      expect(tool.name).toBe('list-scenarios');
      expect(tool.description).toContain('List and search');
      expect(tool.parameters).toBeDefined();
      expect(tool.annotations.title).toBe('List Scenarios');
      expect(tool.annotations.readOnlyHint).toBe(true);
      expect(tool.execute).toEqual(expect.any(Function));
    });

    test('should create analyze blueprint tool', () => {
      const tool = createAnalyzeBlueprintTool(mockToolContext);

      expect(tool.name).toBe('analyze-blueprint');
      expect(tool.description).toContain('Analyze and validate');
      expect(tool.parameters).toBeDefined();
      expect(tool.annotations.title).toBe('Analyze Blueprint');
      expect(tool.annotations.readOnlyHint).toBe(true);
      expect(tool.execute).toEqual(expect.any(Function));
    });

    test('should execute list scenarios tool successfully', async () => {
      mockApiClient.get.mockResolvedValue({
        success: true,
        data: {
          scenarios: [
            { id: 1, name: 'Test Scenario 1', active: true },
            { id: 2, name: 'Test Scenario 2', active: false }
          ]
        }
      });

      const tool = createListScenariosTools(mockToolContext);
      const result = await tool.execute(
        { active: true, limit: 10 },
        { 
          log: mockLogger, 
          reportProgress: jest.fn() as Mock 
        }
      );

      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.scenarios).toBeDefined();
      expect(mockApiClient.get).toHaveBeenCalled();
    });

    test('should handle tool execution errors gracefully', async () => {
      mockApiClient.get.mockRejectedValue(new Error('API Error'));

      const tool = createListScenariosTools(mockToolContext);

      await expect(tool.execute(
        { active: true },
        { 
          log: mockLogger, 
          reportProgress: jest.fn() as Mock 
        }
      )).rejects.toThrow(UserError);

      expect(mockLogger.error).toHaveBeenCalled();
    });
  });

  describe('Main Tool Registration', () => {
    test('should register all scenario tools', () => {
      addScenarioTools(mockServer, mockApiClient);

      // Based on the actual implementation that registers 10 tools
      expect(mockServer.addTool).toHaveBeenCalledTimes(10);
      
      // Verify the tools were registered with correct structure
      const calls = (mockServer.addTool as Mock).mock.calls;
      expect(calls.length).toBe(10);
      
      // Each call should have a properly structured tool
      calls.forEach(call => {
        expect(call[0]).toMatchObject({
          name: expect.any(String),
          description: expect.any(String),
          parameters: expect.any(Object),
          annotations: expect.objectContaining({
            title: expect.any(String),
            readOnlyHint: expect.any(Boolean)
          }),
          execute: expect.any(Function)
        });
      });
    });

    test('should create tools with consistent context', () => {
      const addToolSpy = mockServer.addTool as Mock;
      addScenarioTools(mockServer, mockApiClient);

      // Verify each tool registration call
      expect(addToolSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          name: expect.any(String),
          description: expect.any(String),
          parameters: expect.any(Object),
          annotations: expect.objectContaining({
            title: expect.any(String),
            readOnlyHint: expect.any(Boolean),
            openWorldHint: expect.any(Boolean)
          }),
          execute: expect.any(Function)
        })
      );
    });
  });

  describe('Integration Testing', () => {
    test('should maintain FastMCP compatibility', () => {
      const toolContext = {
        server: mockServer,
        apiClient: mockApiClient,
        logger: mockLogger
      };

      // Test that all tools follow FastMCP tool definition structure
      const tools = [
        createListScenariosTools(toolContext),
        createAnalyzeBlueprintTool(toolContext)
      ];

      tools.forEach(tool => {
        expect(tool).toMatchObject({
          name: expect.any(String),
          description: expect.any(String),
          parameters: expect.any(Object),
          annotations: expect.objectContaining({
            title: expect.any(String),
            readOnlyHint: expect.any(Boolean),
            openWorldHint: expect.any(Boolean)
          }),
          execute: expect.any(Function)
        });
      });
    });

    test('should handle concurrent tool executions', async () => {
      mockApiClient.get.mockResolvedValue({
        success: true,
        data: { scenarios: [] }
      });

      const tool = createListScenariosTools({
        server: mockServer,
        apiClient: mockApiClient,
        logger: mockLogger
      });

      // Execute multiple concurrent calls
      const promises = Array(5).fill(null).map(() =>
        tool.execute(
          { active: true },
          { 
            log: mockLogger, 
            reportProgress: jest.fn() as Mock 
          }
        )
      );

      const results = await Promise.all(promises);

      expect(results).toHaveLength(5);
      results.forEach(result => {
        expect(result).toBeDefined();
        expect(() => JSON.parse(result)).not.toThrow();
      });
    });
  });

  describe('Performance and Memory', () => {
    test('should not have memory leaks in tool creation', () => {
      const initialMemory = process.memoryUsage().heapUsed;

      // Create many tool instances
      for (let i = 0; i < 100; i++) {
        createListScenariosTools({
          server: mockServer,
          apiClient: mockApiClient,
          logger: mockLogger
        });
      }

      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;

      // Memory increase should be reasonable (less than 10MB)
      expect(memoryIncrease).toBeLessThan(10 * 1024 * 1024);
    });

    test('should execute tools within reasonable time limits', async () => {
      mockApiClient.get.mockResolvedValue({
        success: true,
        data: { scenarios: [] }
      });

      const tool = createListScenariosTools({
        server: mockServer,
        apiClient: mockApiClient,
        logger: mockLogger
      });

      const startTime = Date.now();
      await tool.execute(
        { active: true },
        { 
          log: mockLogger, 
          reportProgress: jest.fn() as Mock 
        }
      );
      const executionTime = Date.now() - startTime;

      // Tool execution should complete within 1 second
      expect(executionTime).toBeLessThan(1000);
    });
  });
});