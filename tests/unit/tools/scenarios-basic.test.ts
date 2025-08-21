/**
 * Basic Test Suite for Scenario Management Tools
 * Tests core functionality of scenario management and workflow automation tools
 * Focuses on tool registration, configuration validation, and basic execution patterns
 * Covers comprehensive scenario lifecycle management and blueprint processing
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { UserError } from 'fastmcp';
import { createMockServer, findTool, executeTool, expectValidZodParse, expectInvalidZodParse, extractToolConfigs } from '../../utils/test-helpers.js';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';
import { testErrors, testScenarios } from '../../fixtures/test-data.js';

describe('Scenario Management Tools - Basic Tests', () => {
  let mockServer: any;
  let mockTool: jest.MockedFunction<any>;
  let mockApiClient: MockMakeApiClient;

  // Complete test scenario for testing
  const testScenario = {
    id: 2001,
    name: 'Test Automation Scenario',
    teamId: 12345,
    folderId: 3001,
    blueprint: {
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
    },
    scheduling: {
      type: 'interval' as const,
      interval: 900
    },
    isActive: true,
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-15T12:00:00Z',
    stats: {
      executions: 150,
      errors: 2,
      successRate: 98.7,
      avgExecutionTime: 2.5
    }
  };

  // Test blueprint for validation testing
  const testBlueprint = {
    name: 'Test Blueprint',
    flow: [
      {
        id: 1,
        app: 'webhook',
        operation: 'trigger',
        parameters: {
          url: 'https://hook.make.com/webhook',
          method: 'POST'
        }
      },
      {
        id: 2,
        app: 'email',
        operation: 'send',
        parameters: {
          to: '{{1.email}}',
          subject: 'Test Email',
          body: 'This is a test email'
        }
      }
    ],
    settings: {
      timeout: 30000,
      logging: 'full',
      errorHandling: 'continue'
    }
  };

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
    mockApiClient.reset();
  });

  describe('Tool Registration and Import', () => {
    it('should successfully import and register scenario tools', async () => {
      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      
      // Should not throw an error
      expect(() => {
        addScenarioTools(mockServer, mockApiClient as any);
      }).not.toThrow();
      
      // Should call addTool for each scenario tool
      expect(mockTool).toHaveBeenCalled();
      expect(mockTool.mock.calls.length).toBeGreaterThan(0);
    });

    it('should export the expected scenario tools and functions', async () => {
      const scenarioModule = await import('../../../src/tools/scenarios/index.js');
      
      // Check that expected exports exist
      expect(scenarioModule.addScenarioTools).toBeDefined();
      expect(typeof scenarioModule.addScenarioTools).toBe('function');
      
      // Note: scenarios.ts does not have a default export, which is expected behavior
    });

    it('should register all core scenario management tools', async () => {
      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const expectedTools = [
        'list-scenarios',
        'get-scenario',
        'create-scenario',
        'update-scenario',
        'delete-scenario',
        'clone-scenario',
        'run-scenario',
        'troubleshoot-scenario',
        'generate-troubleshooting-report',
        'analyze-blueprint',
        'validate-blueprint',
        'optimize-blueprint'
      ];
      
      expectedTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool).toBeDefined();
        expect(tool.name).toBe(toolName);
      });
    });

    it('should register scenario lifecycle management tools', async () => {
      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const lifecycleTools = [
        'create-scenario',
        'update-scenario', 
        'delete-scenario',
        'clone-scenario'
      ];
      
      lifecycleTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool).toBeDefined();
        expect(tool.description).toBeDefined();
        expect(tool.parameters).toBeDefined();
        expect(typeof tool.execute).toBe('function');
      });
    });

    it('should register workflow execution and monitoring tools', async () => {
      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const executionTools = [
        'run-scenario',
        'troubleshoot-scenario',
        'generate-troubleshooting-report'
      ];
      
      executionTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool).toBeDefined();
        expect(tool.description).toBeDefined();
        expect(tool.parameters).toBeDefined();
        expect(typeof tool.execute).toBe('function');
      });
    });

    it('should register blueprint management and validation tools', async () => {
      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const blueprintTools = [
        'analyze-blueprint',
        'validate-blueprint',
        'optimize-blueprint'
      ];
      
      blueprintTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool).toBeDefined();
        expect(tool.description).toBeDefined();
        expect(tool.parameters).toBeDefined();
        expect(typeof tool.execute).toBe('function');
      });
    });
  });

  describe('Tool Configuration Validation', () => {
    it('should have correct structure for list-scenarios tool', async () => {
      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-scenarios');
      
      expect(tool.name).toBe('list-scenarios');
      expect(tool.description).toContain('List and search Make.com scenarios');
      expect(tool.parameters).toBeDefined();
      expect(typeof tool.execute).toBe('function');
      expect(tool.annotations?.title).toBe('List Scenarios');
    });

    it('should have correct structure for scenario lifecycle tools', async () => {
      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      // Test create-scenario tool
      const createTool = findTool(mockTool, 'create-scenario');
      expect(createTool.name).toBe('create-scenario');
      expect(createTool.description).toContain('Create a new Make.com scenario');
      expect(createTool.parameters).toBeDefined();
      expect(createTool.annotations?.title).toBe('Create Scenario');

      // Test update-scenario tool
      const updateTool = findTool(mockTool, 'update-scenario');
      expect(updateTool.name).toBe('update-scenario');
      expect(updateTool.description).toContain('Update an existing Make.com scenario');
      expect(updateTool.parameters).toBeDefined();
      expect(updateTool.annotations?.title).toBe('Update Scenario');

      // Test delete-scenario tool
      const deleteTool = findTool(mockTool, 'delete-scenario');
      expect(deleteTool.name).toBe('delete-scenario');
      expect(deleteTool.description).toContain('Delete a Make.com scenario');
      expect(deleteTool.parameters).toBeDefined();
      expect(deleteTool.annotations?.title).toBe('Delete Scenario');
    });

    it('should have correct structure for workflow execution tools', async () => {
      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      // Test run-scenario tool
      const runTool = findTool(mockTool, 'run-scenario');
      expect(runTool.name).toBe('run-scenario');
      expect(runTool.description).toContain('Execute a Make.com scenario');
      expect(runTool.parameters).toBeDefined();
      expect(runTool.annotations?.title).toBe('Run Scenario');

      // Test troubleshoot-scenario tool
      const troubleshootTool = findTool(mockTool, 'troubleshoot-scenario');
      expect(troubleshootTool.name).toBe('troubleshoot-scenario');
      expect(troubleshootTool.description).toContain('Comprehensive Make.com scenario diagnostics');
      expect(troubleshootTool.parameters).toBeDefined();
      expect(troubleshootTool.annotations?.title).toBe('Troubleshoot Scenario');
    });

    it('should have correct structure for blueprint management tools', async () => {
      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      // Test validate-blueprint tool
      const validateTool = findTool(mockTool, 'validate-blueprint');
      expect(validateTool.name).toBe('validate-blueprint');
      expect(validateTool.description).toContain('Validate Make.com blueprint JSON');
      expect(validateTool.parameters).toBeDefined();
      expect(validateTool.annotations?.title).toBe('Validate Blueprint');

      // Test extract-blueprint-connections tool
      const extractTool = findTool(mockTool, 'extract-blueprint-connections');
      expect(extractTool.name).toBe('extract-blueprint-connections');
      expect(extractTool.description).toContain('Extract and analyze connection requirements');
      expect(extractTool.parameters).toBeDefined();
      expect(extractTool.annotations?.title).toBe('Extract Blueprint Connections');

      // Test optimize-blueprint tool
      const optimizeTool = findTool(mockTool, 'optimize-blueprint');
      expect(optimizeTool.name).toBe('optimize-blueprint');
      expect(optimizeTool.description).toContain('Analyze Make.com blueprint and provide optimization');
      expect(optimizeTool.parameters).toBeDefined();
      expect(optimizeTool.annotations?.title).toBe('Optimize Blueprint');
    });
  });

  describe('Schema Validation', () => {
    it('should validate list-scenarios schema with correct inputs', async () => {
      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-scenarios');
      
      // Valid inputs
      const validInputs = [
        {},
        { limit: 10, offset: 0 },
        { teamId: '12345', folderId: '3001' },
        { search: 'test scenario', active: true },
        { limit: 50, offset: 25, search: 'automation', active: false }
      ];
      
      validInputs.forEach(input => {
        expectValidZodParse(tool.parameters, input);
      });
    });

    it('should reject invalid list-scenarios schema inputs', async () => {
      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-scenarios');
      
      // Invalid inputs
      const invalidInputs = [
        { limit: 0 }, // limit must be >= 1
        { limit: 101 }, // limit must be <= 100
        { offset: -1 }, // offset must be >= 0
        { teamId: 123 }, // teamId must be string
        { active: 'yes' }, // active must be boolean
        { unknownField: 'value' } // unexpected field due to strict schema
      ];
      
      invalidInputs.forEach(input => {
        expectInvalidZodParse(tool.parameters, input);
      });
    });

    it('should validate create-scenario schema with different configurations', async () => {
      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-scenario');
      
      // Valid minimal input
      const validMinimal = {
        name: 'Test Scenario'
      };
      
      expectValidZodParse(tool.parameters, validMinimal);

      // Valid complete input
      const validComplete = {
        name: 'Complete Test Scenario',
        teamId: '12345',
        folderId: '3001',
        blueprint: testBlueprint,
        scheduling: {
          type: 'interval' as const,
          interval: 900
        }
      };
      
      expectValidZodParse(tool.parameters, validComplete);

      // Valid cron scheduling
      const validCron = {
        name: 'Cron Scenario',
        scheduling: {
          type: 'cron' as const,
          cron: '0 9 * * 1'
        }
      };
      
      expectValidZodParse(tool.parameters, validCron);
    });

    it('should validate update-scenario schema with partial updates', async () => {
      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'update-scenario');
      
      // Valid partial updates
      const validInputs = [
        { scenarioId: '2001', name: 'Updated Name' },
        { scenarioId: '2001', active: false },
        { scenarioId: '2001', blueprint: testBlueprint },
        { 
          scenarioId: '2001', 
          scheduling: { type: 'interval' as const, interval: 1800 }
        },
        {
          scenarioId: '2001',
          name: 'Complete Update',
          active: true,
          blueprint: testBlueprint
        }
      ];
      
      validInputs.forEach(input => {
        expectValidZodParse(tool.parameters, input);
      });
    });

    it('should validate blueprint schema with complex structures', async () => {
      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'validate-blueprint');
      
      const validBlueprint = {
        blueprint: {
          name: 'Complex Blueprint',
          flow: [
            {
              id: 1,
              app: 'webhook',
              operation: 'trigger',
              parameters: {
                url: 'https://hook.make.com/test',
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'Authorization': 'Bearer {{api_key}}'
                }
              }
            },
            {
              id: 2,
              app: 'filter',
              operation: 'condition',
              parameters: {
                condition: 'data.type === "order" && data.amount > 100',
                fallback: 'ignore'
              }
            },
            {
              id: 3,
              app: 'database',
              operation: 'insert',
              parameters: {
                table: 'orders',
                data: {
                  order_id: '{{1.order_id}}',
                  amount: '{{1.amount}}',
                  customer_email: '{{1.email}}'
                }
              }
            }
          ],
          settings: {
            errorHandling: 'continue',
            logging: 'full',
            timeout: 45000,
            retries: 3,
            maxExecutions: 1000
          },
          variables: {
            api_key: 'env.API_KEY',
            database_url: 'env.DATABASE_URL',
            notification_email: 'admin@company.com'
          }
        }
      };
      
      expectValidZodParse(tool.parameters, validBlueprint);
    });

    it('should validate troubleshooting schema with comprehensive options', async () => {
      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'troubleshoot-scenario');
      
      const validTroubleshooting = {
        scenarioId: '2001',
        diagnosticTypes: ['performance', 'connections', 'errors'],
        includeRecommendations: true,
        includePerformanceHistory: true,
        severityFilter: 'warning',
        autoFix: false,
        timeRange: {
          hours: 24
        }
      };
      
      expectValidZodParse(tool.parameters, validTroubleshooting);
    });

    it('should validate run scenario schema with execution parameters', async () => {
      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'run-scenario');
      
      // Valid run scenario with proper schema
      const validRun = {
        scenarioId: '2001',
        wait: true,
        timeout: 120
      };
      
      expectValidZodParse(tool.parameters, validRun);
    });
  });

  describe('Basic Tool Execution', () => {
    it('should execute list-scenarios successfully with mocked data', async () => {
      mockApiClient.mockResponse('GET', '/scenarios', {
        success: true,
        data: [testScenario],
        metadata: { total: 1, page: 1, limit: 10 }
      });

      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-scenarios');
      const result = await executeTool(tool, {});
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.scenarios).toBeDefined();
      expect(parsedResult.pagination).toBeDefined();
      expect(parsedResult.scenarios).toHaveLength(1);
      expect(parsedResult.scenarios[0].name).toBe(testScenario.name);
    });

    it('should execute get-scenario with detailed information', async () => {
      mockApiClient.mockResponse('GET', '/scenarios/2001', {
        success: true,
        data: testScenario
      });

      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-scenario');
      const result = await executeTool(tool, { 
        scenarioId: '2001',
        includeBlueprint: false,
        includeExecutions: false
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.scenario).toBeDefined();
      expect(parsedResult.scenario.id).toBe(2001);
      expect(parsedResult.scenario.name).toBe(testScenario.name);
    });

    it('should execute create-scenario with comprehensive configuration', async () => {
      const newScenario = {
        ...testScenario,
        id: 2003,
        name: 'New Test Scenario'
      };

      mockApiClient.mockResponse('POST', '/scenarios', {
        success: true,
        data: newScenario
      });

      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-scenario');
      const result = await executeTool(tool, {
        name: 'New Test Scenario',
        blueprint: testBlueprint,
        scheduling: {
          type: 'interval',
          interval: 900
        }
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.scenario).toBeDefined();
      expect(parsedResult.scenario.name).toBe('New Test Scenario');
    });

    it('should execute validate-blueprint with detailed validation', async () => {
      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'validate-blueprint');
      const result = await executeTool(tool, {
        blueprint: testBlueprint
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.validation).toBeDefined();
      expect(parsedResult.validation.isValid).toBeDefined();
      expect(parsedResult.summary).toBeDefined();
    });

    it('should execute run-scenario with execution monitoring', async () => {
      const executionResult = {
        id: 'exec_123',
        scenarioId: 2001,
        status: 'success',
        startedAt: '2024-01-20T10:00:00Z',
        completedAt: '2024-01-20T10:02:30Z',
        duration: 150,
        operations: 3,
        dataTransfer: 0.5,
        cost: 0.03
      };

      mockApiClient.mockResponse('POST', '/scenarios/2001/run', {
        success: true,
        data: executionResult
      });

      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'run-scenario');
      const result = await executeTool(tool, {
        scenarioId: '2001',
        wait: false,
        timeout: 60
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.execution).toBeDefined();
    });

    it('should execute troubleshoot-scenario with diagnostic analysis', async () => {
      const diagnosticResult = {
        scenarioId: '2001',
        healthScore: 85,
        status: 'warning',
        diagnostics: [
          {
            category: 'performance',
            severity: 'medium',
            issue: 'Slow response time detected',
            description: 'Average execution time exceeds threshold',
            recommendation: 'Consider optimizing data processing steps',
            fixable: true
          }
        ],
        recommendations: [
          'Optimize webhook response handling',
          'Review filter conditions for efficiency',
          'Consider caching frequently accessed data'
        ]
      };

      mockApiClient.mockResponse('GET', '/scenarios/2001', {
        success: true,
        data: testScenario
      });

      mockApiClient.mockResponse('GET', '/scenarios/2001/blueprint', {
        success: true,
        data: testBlueprint
      });

      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'troubleshoot-scenario');
      const result = await executeTool(tool, {
        scenarioId: '2001',
        diagnosticTypes: ['performance', 'connections'],
        includeRecommendations: true,
        autoFix: false
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.report).toBeDefined();
      expect(parsedResult.summary).toBeDefined();
    });
  });

  describe('Error Handling and Security', () => {
    it('should handle API failures gracefully', async () => {
      mockApiClient.mockFailure('GET', '/scenarios', new Error('Scenario service unavailable'));

      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-scenarios');
      
      await expect(executeTool(tool, {})).rejects.toThrow(UserError);
    });

    it('should handle unauthorized access errors', async () => {
      mockApiClient.mockResponse('GET', '/scenarios', testErrors.unauthorized);

      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-scenarios');
      
      await expect(executeTool(tool, {})).rejects.toThrow(UserError);
    });

    it('should validate required fields for scenario operations', async () => {
      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const createTool = findTool(mockTool, 'create-scenario');
      
      // Scenario without name should fail
      await expect(executeTool(createTool, {
        teamId: '12345' // Missing required name
      })).rejects.toThrow(UserError);
    });

    it('should validate blueprint security and compliance', async () => {
      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'validate-blueprint');
      
      // Blueprint with potential security issues
      const insecureBlueprint = {
        blueprint: {
          name: 'Insecure Blueprint',
          flow: [
            {
              id: 1,
              app: 'webhook',
              operation: 'trigger',
              parameters: {
                url: 'http://insecure-endpoint.com', // HTTP instead of HTTPS
                method: 'POST'
              }
            }
          ],
          settings: {
            timeout: 30000
          }
        }
      };
      
      const result = await executeTool(tool, insecureBlueprint);
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.validation.securityIssues).toBeDefined();
    });

    it('should enforce scenario lifecycle security controls', async () => {
      mockApiClient.mockResponse('DELETE', '/scenarios/2001', testErrors.unauthorized);

      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'delete-scenario');
      
      await expect(executeTool(tool, {
        scenarioId: '2001',
        force: false
      })).rejects.toThrow(UserError);
    });

    it('should validate execution permissions and rate limits', async () => {
      mockApiClient.mockResponse('POST', '/scenarios/2001/run', testErrors.rateLimited);

      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'run-scenario');
      
      await expect(executeTool(tool, {
        scenarioId: '2001'
      })).rejects.toThrow(UserError);
    });

    it('should handle blueprint optimization with performance analysis', async () => {
      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'optimize-blueprint');
      const result = await executeTool(tool, {
        blueprint: testBlueprint
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.optimization).toBeDefined();
      expect(parsedResult.recommendations).toBeDefined();
      expect(parsedResult.summary).toBeDefined();
    });
  });

  describe('Enterprise Workflow Automation Features', () => {
    it('should support advanced scenario cloning with team assignment', async () => {
      const sourceScenario = testScenario;
      const clonedScenario = {
        ...testScenario,
        id: 2004,
        name: 'Cloned Enterprise Scenario',
        teamId: 54321,
        isActive: false
      };

      mockApiClient.mockResponse('GET', '/scenarios/2001/blueprint', {
        success: true,
        data: testBlueprint
      });

      mockApiClient.mockResponse('POST', '/scenarios', {
        success: true,
        data: clonedScenario
      });

      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'clone-scenario');
      const result = await executeTool(tool, {
        scenarioId: '2001',
        name: 'Cloned Enterprise Scenario',
        teamId: '54321',
        folderId: '6789',
        active: false
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.clonedScenario).toBeDefined();
      expect(parsedResult.clonedScenario.name).toBe('Cloned Enterprise Scenario');
      expect(parsedResult.originalScenarioId).toBe('2001');
    });

    it('should support comprehensive troubleshooting report generation', async () => {
      const mockReport = {
        reportId: 'report_123',
        organizationId: 67890,
        generatedAt: '2024-01-20T10:00:00Z',
        executiveSummary: {
          totalScenarios: 25,
          healthyScenarios: 20,
          warningScenarios: 4,
          criticalScenarios: 1,
          systemHealthScore: 82
        },
        findings: {
          commonIssues: [
            {
              pattern: 'Slow API response times',
              frequency: 8,
              severity: 'medium',
              affectedScenarios: [2001, 2002, 2003]
            }
          ],
          recommendations: [
            'Implement connection pooling for database operations',
            'Add retry logic for external API calls',
            'Optimize webhook payload processing'
          ]
        },
        actionPlan: {
          immediate: ['Fix critical authentication errors'],
          shortTerm: ['Optimize performance bottlenecks'],
          longTerm: ['Implement comprehensive monitoring']
        }
      };

      mockApiClient.mockResponse('GET', '/scenarios', {
        success: true,
        data: [testScenario, { ...testScenario, id: 2002 }]
      });

      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'generate-troubleshooting-report');
      const result = await executeTool(tool, {
        scenarioIds: ['2001', '2002'],
        reportOptions: {
          includeExecutiveSummary: true,
          includeActionPlan: true,
          includeRecommendationTimeline: true,
          formatType: 'json'
        },
        analysisFilters: {
          timeRangeHours: 24,
          severityThreshold: 'warning',
          maxScenariosToAnalyze: 25
        },
        comparisonBaseline: {
          compareToHistorical: true,
          baselineTimeRangeHours: 168,
          includeBenchmarks: true
        }
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.report).toBeDefined();
      expect(parsedResult.summary).toBeDefined();
    });

    it('should support blueprint connection analysis for migration planning', async () => {
      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'extract-blueprint-connections');
      const result = await executeTool(tool, {
        blueprint: {
          ...testBlueprint,
          flow: [
            ...testBlueprint.flow,
            {
              id: 4,
              app: 'salesforce',
              operation: 'create_record',
              parameters: {
                connection: 'salesforce_prod',
                object: 'Account',
                data: {
                  Name: '{{1.company_name}}',
                  Email: '{{1.email}}'
                }
              }
            },
            {
              id: 5,
              app: 'slack',
              operation: 'send_message',
              parameters: {
                connection: 'slack_notifications',
                channel: '#alerts',
                message: 'New account created: {{4.Name}}'
              }
            }
          ]
        }
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.connections).toBeDefined();
      expect(parsedResult.analysis).toBeDefined();
      expect(parsedResult.migrationPlan).toBeDefined();
    });

    it('should support advanced scenario update with complex configuration', async () => {
      const updatedScenario = {
        ...testScenario,
        name: 'Updated Enterprise Scenario',
        blueprint: {
          ...testBlueprint,
          settings: {
            ...testBlueprint.settings,
            errorHandling: 'rollback',
            retries: 5,
            timeout: 60000
          }
        },
        scheduling: {
          type: 'cron',
          cron: '0 */2 * * *'
        }
      };

      mockApiClient.mockResponse('PATCH', '/scenarios/2001', {
        success: true,
        data: updatedScenario
      });

      const { addScenarioTools } = await import('../../../src/tools/scenarios/index.js');
      addScenarioTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'update-scenario');
      const result = await executeTool(tool, {
        scenarioId: '2001',
        name: 'Updated Enterprise Scenario',
        blueprint: {
          ...testBlueprint,
          settings: {
            ...testBlueprint.settings,
            errorHandling: 'rollback',
            retries: 5,
            timeout: 60000
          }
        },
        scheduling: {
          type: 'cron',
          cron: '0 */2 * * *'
        }
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.scenario).toBeDefined();
      expect(parsedResult.updates).toBeDefined();
      expect(parsedResult.scenario.name).toBe('Updated Enterprise Scenario');
    });
  });
});