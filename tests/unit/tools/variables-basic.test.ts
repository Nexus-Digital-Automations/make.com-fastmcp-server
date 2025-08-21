/**
 * Basic Test Suite for Variables Tools
 * Tests core functionality of variables management and execution recovery tools
 * Covers variable CRUD operations, bulk operations, export/import, variable resolution,
 * and incomplete execution recovery following established testing patterns
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { UserError } from 'fastmcp';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';
import { 
  createMockServer, 
  findTool, 
  executeTool, 
  expectProgressReported,
  expectValidZodParse,
  expectInvalidZodParse
} from '../../utils/test-helpers.js';

// Import types from variables.ts
type MakeCustomVariable = {
  id: number;
  name: string;
  value: any;
  type: 'string' | 'number' | 'boolean' | 'json';
  scope: 'organization' | 'team' | 'scenario';
  organizationId?: number;
  teamId?: number;
  scenarioId?: number;
  description?: string;
  tags?: string[];
  lastModified: string;
  modifiedBy: number;
  version: number;
  isEncrypted?: boolean;
};

type MakeIncompleteExecution = {
  id: number;
  scenarioId: number;
  status: 'waiting' | 'paused' | 'failed';
  stoppedAt: string;
  operations: number;
  dataTransfer: number;
  canResume: boolean;
};

describe('Variables Tools - Basic Tests', () => {
  let mockServer: any;
  let mockApiClient: MockMakeApiClient;
  let mockTool: jest.MockedFunction<any>;
  let mockLog: any;
  let mockReportProgress: jest.MockedFunction<any>;

  // Test data for variables
  const testVariable: MakeCustomVariable = {
    id: 1,
    name: 'API_BASE_URL',
    value: 'https://api.example.com/v1',
    type: 'string',
    scope: 'organization',
    organizationId: 123,
    teamId: 456,
    description: 'Base URL for external API integration',
    tags: ['production', 'api', 'external'],
    lastModified: '2024-01-01T12:00:00Z',
    modifiedBy: 1,
    version: 3,
    isEncrypted: false
  };

  const testJsonVariable: MakeCustomVariable = {
    id: 2,
    name: 'CONFIG_SETTINGS',
    value: {
      timeout: 30000,
      retries: 3,
      endpoints: ['api1.com', 'api2.com']
    },
    type: 'json',
    scope: 'team',
    organizationId: 123,
    teamId: 456,
    description: 'Configuration settings for API calls',
    tags: ['config', 'settings'],
    lastModified: '2024-01-02T10:30:00Z',
    modifiedBy: 2,
    version: 1,
    isEncrypted: false
  };

  const testEncryptedVariable: MakeCustomVariable = {
    id: 3,
    name: 'SECRET_KEY',
    value: '[ENCRYPTED]',
    type: 'string',
    scope: 'scenario',
    organizationId: 123,
    teamId: 456,
    scenarioId: 789,
    description: 'Encrypted secret key for authentication',
    tags: ['secret', 'encrypted'],
    lastModified: '2024-01-03T15:45:00Z',
    modifiedBy: 1,
    version: 2,
    isEncrypted: true
  };

  const testIncompleteExecution: MakeIncompleteExecution = {
    id: 1001,
    scenarioId: 789,
    status: 'paused',
    stoppedAt: '2024-01-15T14:30:00Z',
    operations: 1250,
    dataTransfer: 5.5,
    canResume: true
  };

  beforeEach(() => {
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockTool = serverSetup.mockTool;
    mockApiClient = new MockMakeApiClient();
    mockLog = {
      info: jest.fn(),
      error: jest.fn(),
      warn: jest.fn(),
      debug: jest.fn(),
    };
    mockReportProgress = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
    mockApiClient.reset();
  });

  describe('Tool Registration and Import Validation', () => {
    it('should import variables tools module without errors', async () => {
      const { addVariableTools } = await import('../../../src/tools/variables.js');
      expect(addVariableTools).toBeDefined();
      expect(typeof addVariableTools).toBe('function');
    });

    it('should register all 12 variables management tools', async () => {
      const { addVariableTools } = await import('../../../src/tools/variables.js');
      addVariableTools(mockServer, mockApiClient as any);
      
      const expectedTools = [
        'create-custom-variable',
        'list-custom-variables',
        'get-custom-variable',
        'update-custom-variable',
        'delete-custom-variable',
        'bulk-variable-operations',
        'export-custom-variables',
        'test-variable-resolution',
        'list-incomplete-executions-with-recovery',
        'bulk-resolve-incomplete-executions',
        'analyze-execution-failure-patterns',
        'create-recovery-automation-rule'
      ];

      expectedTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool).toBeDefined();
        expect(tool.name).toBe(toolName);
        expect(tool.description).toBeDefined();
        expect(tool.parameters).toBeDefined();
      });

      // Verify we have all 12 tools
      expect(mockTool.mock.calls).toHaveLength(12);
    });

    it('should have proper tool configuration for core variable tools', async () => {
      const { addVariableTools } = await import('../../../src/tools/variables.js');
      addVariableTools(mockServer, mockApiClient as any);
      
      const coreTools = [
        'create-custom-variable',
        'list-custom-variables', 
        'get-custom-variable',
        'update-custom-variable',
        'delete-custom-variable'
      ];
      
      coreTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool.description).toMatch(/variable/i);
        expect(tool.parameters).toBeDefined();
        expect(typeof tool.execute).toBe('function');
      });
    });

    it('should have proper tool configuration for execution recovery tools', async () => {
      const { addVariableTools } = await import('../../../src/tools/variables.js');
      addVariableTools(mockServer, mockApiClient as any);
      
      const recoveryTools = [
        'list-incomplete-executions-with-recovery',
        'bulk-resolve-incomplete-executions',
        'analyze-execution-failure-patterns',
        'create-recovery-automation-rule'
      ];
      
      recoveryTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool.description).toMatch(/(execution|recovery)/i);
        expect(tool.parameters).toBeDefined();
        expect(typeof tool.execute).toBe('function');
      });
    });
  });

  describe('Variable Creation and Validation', () => {
    describe('create-custom-variable tool', () => {
      it('should create organization-scoped string variable', async () => {
        mockApiClient.mockResponse('POST', '/organizations/123/variables', {
          success: true,
          data: testVariable
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-custom-variable');
        const result = await executeTool(tool, {
          name: 'API_BASE_URL',
          value: 'https://api.example.com/v1',
          type: 'string',
          scope: 'organization',
          organizationId: 123,
          description: 'Base URL for external API integration',
          tags: ['production', 'api', 'external']
        }, { log: mockLog });
        
        expect(result).toContain('API_BASE_URL');
        expect(result).toContain('created successfully');
        expect(result).toContain('"scope": "organization"');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/organizations/123/variables');
        expect(calls[0].method).toBe('POST');
        expect(calls[0].data.name).toBe('API_BASE_URL');
        expect(calls[0].data.type).toBe('string');
        expect(calls[0].data.scope).toBe('organization');
      });

      it('should create team-scoped JSON variable', async () => {
        mockApiClient.mockResponse('POST', '/teams/456/variables', {
          success: true,
          data: testJsonVariable
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-custom-variable');
        const result = await executeTool(tool, {
          name: 'CONFIG_SETTINGS',
          value: { timeout: 30000, retries: 3, endpoints: ['api1.com', 'api2.com'] },
          type: 'json',
          scope: 'team',
          organizationId: 123,
          teamId: 456,
          description: 'Configuration settings for API calls',
          tags: ['config', 'settings']
        }, { log: mockLog });
        
        expect(result).toContain('CONFIG_SETTINGS');
        expect(result).toContain('created successfully');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/teams/456/variables');
        expect(calls[0].data.type).toBe('json');
        expect(calls[0].data.scope).toBe('team');
        expect(typeof calls[0].data.value).toBe('object');
      });

      it('should create scenario-scoped encrypted variable', async () => {
        mockApiClient.mockResponse('POST', '/scenarios/789/variables', {
          success: true,
          data: testEncryptedVariable
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-custom-variable');
        const result = await executeTool(tool, {
          name: 'SECRET_KEY',
          value: 'super-secret-key-123',
          type: 'string',
          scope: 'scenario',
          organizationId: 123,
          teamId: 456,
          scenarioId: 789,
          description: 'Encrypted secret key for authentication',
          tags: ['secret', 'encrypted'],
          isEncrypted: true
        }, { log: mockLog });
        
        expect(result).toContain('SECRET_KEY');
        expect(result).toContain('created successfully');
        expect(result).toContain('Variable value is encrypted');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/scenarios/789/variables');
        expect(calls[0].data.isEncrypted).toBe(true);
        expect(calls[0].data.scope).toBe('scenario');
      });

      it('should validate variable type and format values correctly', async () => {
        mockApiClient.mockResponse('POST', '/organizations/123/variables', {
          success: true,
          data: { ...testVariable, type: 'number', value: 42 }
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-custom-variable');
        
        // Test number formatting
        await executeTool(tool, {
          name: 'MAX_RETRIES',
          value: '42',
          type: 'number',
          scope: 'organization',
          organizationId: 123
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.value).toBe(42);
      });

      it('should validate scope consistency requirements', async () => {
        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-custom-variable');
        
        // Should fail - organization scope without organizationId
        await expect(executeTool(tool, {
          name: 'TEST_VAR',
          value: 'test',
          type: 'string',
          scope: 'organization'
        }, { log: mockLog })).rejects.toThrow('Organization ID is required');
        
        // Should fail - team scope without teamId
        await expect(executeTool(tool, {
          name: 'TEST_VAR',
          value: 'test',
          type: 'string',
          scope: 'team',
          organizationId: 123
        }, { log: mockLog })).rejects.toThrow('Team ID are required');
        
        // Should fail - scenario scope without scenarioId
        await expect(executeTool(tool, {
          name: 'TEST_VAR',
          value: 'test',
          type: 'string',
          scope: 'scenario',
          organizationId: 123,
          teamId: 456
        }, { log: mockLog })).rejects.toThrow('Scenario ID are required');
      });

      it('should validate create variable parameters', async () => {
        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-custom-variable');
        
        // Test valid parameters
        expectValidZodParse(tool.parameters, {
          name: 'TEST_VAR',
          value: 'test',
          type: 'string',
          scope: 'organization',
          organizationId: 123
        });
        
        // Test invalid name (empty)
        expectInvalidZodParse(tool.parameters, {
          name: '',
          value: 'test',
          type: 'string',
          scope: 'organization',
          organizationId: 123
        });
        
        // Test invalid type
        expectInvalidZodParse(tool.parameters, {
          name: 'TEST_VAR',
          value: 'test',
          type: 'invalid-type',
          scope: 'organization',
          organizationId: 123
        });
        
        // Test invalid scope
        expectInvalidZodParse(tool.parameters, {
          name: 'TEST_VAR',
          value: 'test',
          type: 'string',
          scope: 'invalid-scope',
          organizationId: 123
        });
      });
    });
  });

  describe('Variable Listing and Search', () => {
    describe('list-custom-variables tool', () => {
      it('should list variables with default parameters', async () => {
        const variablesList = [testVariable, testJsonVariable, testEncryptedVariable];
        mockApiClient.mockResponse('GET', '/variables', {
          success: true,
          data: variablesList,
          metadata: { total: 3 }
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-custom-variables');
        const result = await executeTool(tool, {}, { log: mockLog });
        
        expect(result).toContain('API_BASE_URL');
        expect(result).toContain('CONFIG_SETTINGS');
        expect(result).toContain('SECRET_KEY');
        expect(result).toContain('"totalVariables": 3');
        expect(result).toContain('scopeBreakdown');
        expect(result).toContain('typeBreakdown');
        
        const parsedResult = JSON.parse(result);
        expect(parsedResult.variables).toHaveLength(3);
        expect(parsedResult.summary.encryptedCount).toBe(1);
        expect(parsedResult.variables.find((v: any) => v.name === 'SECRET_KEY').value).toBe('[ENCRYPTED]');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/variables');
        expect(calls[0].method).toBe('GET');
      });

      it('should filter variables by scope and type', async () => {
        const orgVariables = [testVariable];
        mockApiClient.mockResponse('GET', '/organizations/123/variables', {
          success: true,
          data: orgVariables,
          metadata: { total: 1 }
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-custom-variables');
        const result = await executeTool(tool, {
          scope: 'organization',
          organizationId: 123,
          type: 'string',
          namePattern: 'API*',
          tags: ['production'],
          limit: 50,
          sortBy: 'name',
          sortOrder: 'asc'
        }, { log: mockLog });
        
        expect(result).toContain('API_BASE_URL');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/organizations/123/variables');
        expect(calls[0].data.type).toBe('string');
        expect(calls[0].data.namePattern).toBe('API*');
        expect(calls[0].data.tags).toBe('production');
        expect(calls[0].data.limit).toBe(50);
        expect(calls[0].data.sortBy).toBe('name');
      });

      it('should list team-scoped variables', async () => {
        const teamVariables = [testJsonVariable];
        mockApiClient.mockResponse('GET', '/teams/456/variables', {
          success: true,
          data: teamVariables,
          metadata: { total: 1 }
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-custom-variables');
        await executeTool(tool, {
          scope: 'team',
          teamId: 456
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/teams/456/variables');
      });

      it('should list scenario-scoped variables', async () => {
        const scenarioVariables = [testEncryptedVariable];
        mockApiClient.mockResponse('GET', '/scenarios/789/variables', {
          success: true,
          data: scenarioVariables,
          metadata: { total: 1 }
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-custom-variables');
        await executeTool(tool, {
          scope: 'scenario',
          scenarioId: 789
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/scenarios/789/variables');
      });

      it('should validate list variables parameters', async () => {
        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-custom-variables');
        
        // Test valid parameters
        expectValidZodParse(tool.parameters, {});
        expectValidZodParse(tool.parameters, { scope: 'all', limit: 100 });
        
        // Test invalid scope
        expectInvalidZodParse(tool.parameters, { scope: 'invalid-scope' });
        
        // Test invalid limit
        expectInvalidZodParse(tool.parameters, { limit: 0 });
        expectInvalidZodParse(tool.parameters, { limit: 1001 });
        
        // Test invalid offset
        expectInvalidZodParse(tool.parameters, { offset: -1 });
      });
    });
  });

  describe('Variable Retrieval and Details', () => {
    describe('get-custom-variable tool', () => {
      it('should get variable with basic information', async () => {
        mockApiClient.mockResponse('GET', '/variables/1', {
          success: true,
          data: testVariable
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-custom-variable');
        const result = await executeTool(tool, {
          variableId: 1
        }, { log: mockLog });
        
        expect(result).toContain('API_BASE_URL');
        expect(result).toContain('"id": 1');
        expect(result).toContain('metadata');
        
        const parsedResult = JSON.parse(result);
        expect(parsedResult.variable.name).toBe('API_BASE_URL');
        expect(parsedResult.metadata.canEdit).toBe(true);
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/variables/1');
        expect(calls[0].method).toBe('GET');
      });

      it('should get variable with usage statistics', async () => {
        mockApiClient.mockResponse('GET', '/variables/1', {
          success: true,
          data: testVariable
        });
        
        mockApiClient.mockResponse('GET', '/variables/1/usage', {
          success: true,
          data: {
            usageCount: 15,
            lastAccessed: '2024-01-15T10:00:00Z',
            accessCount: 150
          }
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-custom-variable');
        const result = await executeTool(tool, {
          variableId: 1,
          includeUsage: true
        }, { log: mockLog });
        
        expect(result).toContain('usage');
        expect(result).toContain('accessCount');
        
        const calls = mockApiClient.getCallLog();
        expect(calls).toHaveLength(2);
        expect(calls[1].endpoint).toBe('/variables/1/usage');
      });

      it('should handle encrypted variable values', async () => {
        mockApiClient.mockResponse('GET', '/variables/3', {
          success: true,
          data: testEncryptedVariable
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-custom-variable');
        const result = await executeTool(tool, {
          variableId: 3
        }, { log: mockLog });
        
        const parsedResult = JSON.parse(result);
        expect(parsedResult.variable.value).toBe('[ENCRYPTED]');
        expect(parsedResult.variable.isEncrypted).toBe(true);
      });

      it('should handle variable not found', async () => {
        mockApiClient.mockResponse('GET', '/variables/999', {
          success: true,
          data: null
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-custom-variable');
        
        await expect(executeTool(tool, {
          variableId: 999
        }, { log: mockLog })).rejects.toThrow('Variable with ID 999 not found');
      });

      it('should validate get variable parameters', async () => {
        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-custom-variable');
        
        // Test valid parameters
        expectValidZodParse(tool.parameters, { variableId: 1 });
        expectValidZodParse(tool.parameters, { variableId: 1, includeUsage: true });
        
        // Test invalid variableId
        expectInvalidZodParse(tool.parameters, { variableId: 0 });
        expectInvalidZodParse(tool.parameters, { variableId: -1 });
      });
    });
  });

  describe('Variable Updates and Modifications', () => {
    describe('update-custom-variable tool', () => {
      it('should update variable name and description', async () => {
        const updatedVariable = {
          ...testVariable,
          name: 'UPDATED_API_BASE_URL',
          description: 'Updated base URL for external API integration',
          version: 4
        };

        mockApiClient.mockResponse('PUT', '/variables/1', {
          success: true,
          data: updatedVariable
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-custom-variable');
        const result = await executeTool(tool, {
          variableId: 1,
          name: 'UPDATED_API_BASE_URL',
          description: 'Updated base URL for external API integration'
        }, { log: mockLog });
        
        expect(result).toContain('UPDATED_API_BASE_URL');
        expect(result).toContain('updated successfully');
        expect(result).toContain('changes');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/variables/1');
        expect(calls[0].method).toBe('PUT');
        expect(calls[0].data.name).toBe('UPDATED_API_BASE_URL');
      });

      it('should update variable value with type validation', async () => {
        // First get current variable for type validation
        mockApiClient.mockResponse('GET', '/variables/1', {
          success: true,
          data: testVariable
        });
        
        const updatedVariable = {
          ...testVariable,
          value: 'https://api-v2.example.com/v1',
          version: 4
        };

        mockApiClient.mockResponse('PUT', '/variables/1', {
          success: true,
          data: updatedVariable
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-custom-variable');
        await executeTool(tool, {
          variableId: 1,
          value: 'https://api-v2.example.com/v1'
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls).toHaveLength(2); // GET for type validation, PUT for update
        expect(calls[1].data.value).toBe('https://api-v2.example.com/v1');
      });

      it('should update variable tags and encryption settings', async () => {
        const updatedVariable = {
          ...testVariable,
          tags: ['production', 'api', 'external', 'v2'],
          isEncrypted: true,
          version: 4
        };

        mockApiClient.mockResponse('PUT', '/variables/1', {
          success: true,
          data: updatedVariable
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-custom-variable');
        await executeTool(tool, {
          variableId: 1,
          tags: ['production', 'api', 'external', 'v2'],
          isEncrypted: true
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.tags).toEqual(['production', 'api', 'external', 'v2']);
        expect(calls[0].data.isEncrypted).toBe(true);
      });

      it('should validate update variable parameters', async () => {
        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-custom-variable');
        
        // Test valid parameters
        expectValidZodParse(tool.parameters, {
          variableId: 1,
          name: 'NEW_NAME'
        });
        
        // Test invalid variableId
        expectInvalidZodParse(tool.parameters, {
          variableId: 0,
          name: 'NEW_NAME'
        });
        
        // Test invalid type
        expectInvalidZodParse(tool.parameters, {
          variableId: 1,
          type: 'invalid-type'
        });
      });

      it('should require at least one update parameter', async () => {
        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-custom-variable');
        
        await expect(executeTool(tool, {
          variableId: 1
        }, { log: mockLog })).rejects.toThrow('No update data provided');
      });
    });
  });

  describe('Variable Deletion and Cleanup', () => {
    describe('delete-custom-variable tool', () => {
      it('should delete variable without usage check', async () => {
        mockApiClient.mockResponse('DELETE', '/variables/1', {
          success: true,
          data: { deleted: true }
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'delete-custom-variable');
        const result = await executeTool(tool, {
          variableId: 1,
          force: true
        }, { log: mockLog });
        
        expect(result).toContain('Variable 1 deleted successfully');
        expect(result).toContain('"forced": true');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/variables/1');
        expect(calls[0].method).toBe('DELETE');
      });

      it('should check usage before deletion when not forced', async () => {
        mockApiClient.mockResponse('GET', '/variables/1/usage', {
          success: true,
          data: { usageCount: 0 }
        });
        
        mockApiClient.mockResponse('DELETE', '/variables/1', {
          success: true,
          data: { deleted: true }
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'delete-custom-variable');
        await executeTool(tool, {
          variableId: 1,
          force: false
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls).toHaveLength(2); // Usage check then delete
        expect(calls[0].endpoint).toBe('/variables/1/usage');
        expect(calls[1].endpoint).toBe('/variables/1');
      });

      it('should prevent deletion when variable is in use', async () => {
        mockApiClient.mockResponse('GET', '/variables/1/usage', {
          success: true,
          data: { usageCount: 5 }
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'delete-custom-variable');
        
        await expect(executeTool(tool, {
          variableId: 1,
          force: false
        }, { log: mockLog })).rejects.toThrow('Variable is currently in use (5 references)');
      });

      it('should validate delete variable parameters', async () => {
        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'delete-custom-variable');
        
        // Test valid parameters
        expectValidZodParse(tool.parameters, { variableId: 1 });
        expectValidZodParse(tool.parameters, { variableId: 1, force: true });
        
        // Test invalid variableId
        expectInvalidZodParse(tool.parameters, { variableId: 0 });
      });
    });
  });

  describe('Bulk Variable Operations', () => {
    describe('bulk-variable-operations tool', () => {
      it('should perform bulk delete operation', async () => {
        const bulkResult = {
          affected: 3,
          failed: 0,
          errors: []
        };

        mockApiClient.mockResponse('POST', '/variables/bulk', {
          success: true,
          data: bulkResult
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'bulk-variable-operations');
        const result = await executeTool(tool, {
          operation: 'delete',
          variableIds: [1, 2, 3],
          operationData: {}
        }, { log: mockLog });
        
        expect(result).toContain('Bulk delete completed successfully');
        expect(result).toContain('"successful": 3');
        expect(result).toContain('"failed": 0');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/variables/bulk');
        expect(calls[0].method).toBe('POST');
        expect(calls[0].data.operation).toBe('delete');
        expect(calls[0].data.variableIds).toEqual([1, 2, 3]);
      });

      it('should perform bulk update tags operation', async () => {
        const bulkResult = {
          affected: 2,
          failed: 1,
          errors: ['Variable 3 not found']
        };

        mockApiClient.mockResponse('POST', '/variables/bulk', {
          success: true,
          data: bulkResult
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'bulk-variable-operations');
        await executeTool(tool, {
          operation: 'update_tags',
          variableIds: [1, 2, 3],
          operationData: {
            tags: ['updated', 'bulk-operation']
          }
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.operation).toBe('update_tags');
        expect(calls[0].data.operationData.tags).toEqual(['updated', 'bulk-operation']);
      });

      it('should validate bulk operations parameters', async () => {
        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'bulk-variable-operations');
        
        // Test valid parameters
        expectValidZodParse(tool.parameters, {
          operation: 'delete',
          variableIds: [1, 2, 3]
        });
        
        // Test invalid operation
        expectInvalidZodParse(tool.parameters, {
          operation: 'invalid-operation',
          variableIds: [1, 2, 3]
        });
        
        // Test empty variable IDs
        expectInvalidZodParse(tool.parameters, {
          operation: 'delete',
          variableIds: []
        });
        
        // Test too many variable IDs
        expectInvalidZodParse(tool.parameters, {
          operation: 'delete',
          variableIds: Array(101).fill(0).map((_, i) => i + 1)
        });
      });
    });
  });

  describe('Variable Export and Backup', () => {
    describe('export-custom-variables tool', () => {
      it('should export variables in JSON format', async () => {
        const exportResult = {
          count: 5,
          exportId: 'export_123',
          downloadUrl: 'https://api.make.com/exports/export_123.json',
          filename: 'variables_export_2024-01-15.json',
          expiresAt: '2024-01-16T15:00:00Z',
          encryptedCount: 1
        };

        mockApiClient.mockResponse('POST', '/variables/export', {
          success: true,
          data: exportResult
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'export-custom-variables');
        const result = await executeTool(tool, {
          scope: 'all',
          format: 'json',
          includeEncrypted: false,
          includeMetadata: true
        }, { log: mockLog });
        
        expect(result).toContain('Variables exported successfully in json format');
        expect(result).toContain('"totalVariables": 5');
        expect(result).toContain('downloadUrl');
        expect(result).toContain('export_123');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/variables/export');
        expect(calls[0].data.format).toBe('json');
        expect(calls[0].data.includeEncrypted).toBe(false);
      });

      it('should export organization-scoped variables in CSV format', async () => {
        const exportResult = {
          count: 3,
          exportId: 'export_456',
          downloadUrl: 'https://api.make.com/exports/export_456.csv',
          filename: 'org_123_variables.csv',
          expiresAt: '2024-01-16T15:00:00Z',
          encryptedCount: 0
        };

        mockApiClient.mockResponse('POST', '/variables/export', {
          success: true,
          data: exportResult
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'export-custom-variables');
        await executeTool(tool, {
          scope: 'organization',
          organizationId: 123,
          format: 'csv',
          includeEncrypted: false
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.scope).toBe('organization');
        expect(calls[0].data.organizationId).toBe(123);
        expect(calls[0].data.format).toBe('csv');
      });

      it('should export variables in ENV format', async () => {
        const exportResult = {
          count: 2,
          exportId: 'export_789',
          downloadUrl: 'https://api.make.com/exports/export_789.env',
          filename: 'variables.env',
          expiresAt: '2024-01-16T15:00:00Z',
          encryptedCount: 0
        };

        mockApiClient.mockResponse('POST', '/variables/export', {
          success: true,
          data: exportResult
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'export-custom-variables');
        await executeTool(tool, {
          format: 'env',
          includeMetadata: false
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.format).toBe('env');
        expect(calls[0].data.includeMetadata).toBe(false);
      });

      it('should validate export parameters', async () => {
        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'export-custom-variables');
        
        // Test valid parameters
        expectValidZodParse(tool.parameters, {});
        expectValidZodParse(tool.parameters, { format: 'json' });
        expectValidZodParse(tool.parameters, { scope: 'organization', organizationId: 123 });
        
        // Test invalid format
        expectInvalidZodParse(tool.parameters, { format: 'invalid-format' });
        
        // Test invalid scope
        expectInvalidZodParse(tool.parameters, { scope: 'invalid-scope' });
      });
    });
  });

  describe('Variable Resolution and Testing', () => {
    describe('test-variable-resolution tool', () => {
      it('should test variable resolution with context', async () => {
        const resolutionResult = {
          resolvedVariable: {
            id: 1,
            name: 'API_BASE_URL',
            value: 'https://api.example.com/v1',
            scope: 'organization',
            isEncrypted: false
          },
          inheritanceChain: [
            { scope: 'scenario', found: false },
            { scope: 'team', found: false },
            { scope: 'organization', found: true, variableId: 1 }
          ]
        };

        mockApiClient.mockResponse('POST', '/variables/test-resolution', {
          success: true,
          data: resolutionResult
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'test-variable-resolution');
        const result = await executeTool(tool, {
          variableName: 'API_BASE_URL',
          context: {
            organizationId: 123,
            teamId: 456,
            scenarioId: 789
          },
          includeInheritance: true
        }, { log: mockLog });
        
        expect(result).toContain('API_BASE_URL');
        expect(result).toContain('"resolved": true');
        expect(result).toContain('"resolvedScope": "organization"');
        expect(result).toContain('inheritanceChain');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/variables/test-resolution');
        expect(calls[0].data.variableName).toBe('API_BASE_URL');
        expect(calls[0].data.context.organizationId).toBe(123);
        expect(calls[0].data.includeInheritance).toBe(true);
      });

      it('should handle variable not resolved', async () => {
        const resolutionResult = {
          resolvedVariable: null,
          inheritanceChain: [
            { scope: 'scenario', found: false },
            { scope: 'team', found: false },
            { scope: 'organization', found: false }
          ]
        };

        mockApiClient.mockResponse('POST', '/variables/test-resolution', {
          success: true,
          data: resolutionResult
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'test-variable-resolution');
        const result = await executeTool(tool, {
          variableName: 'NON_EXISTENT_VAR',
          context: {
            organizationId: 123
          }
        }, { log: mockLog });
        
        const parsedResult = JSON.parse(result);
        expect(parsedResult.summary.resolved).toBe(false);
        expect(parsedResult.summary.value).toBeUndefined();
      });

      it('should validate resolution test parameters', async () => {
        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'test-variable-resolution');
        
        // Test valid parameters
        expectValidZodParse(tool.parameters, {
          variableName: 'TEST_VAR',
          context: { organizationId: 123 }
        });
        
        // Test invalid variable name (empty)
        expectInvalidZodParse(tool.parameters, {
          variableName: '',
          context: {}
        });
      });
    });
  });

  describe('Incomplete Execution Recovery', () => {
    describe('list-incomplete-executions-with-recovery tool', () => {
      it('should list incomplete executions with recovery plans', async () => {
        const incompleteExecutions = [testIncompleteExecution];
        const recoveryPlan = {
          canResume: true,
          recommendedAction: 'retry',
          estimatedRecoveryTime: 300,
          requiredSteps: ['validate_data', 'resume_execution']
        };

        mockApiClient.mockResponse('GET', '/incomplete-executions', {
          success: true,
          data: incompleteExecutions,
          metadata: { total: 1 }
        });

        mockApiClient.mockResponse('GET', '/incomplete-executions/1001/recovery-analysis', {
          success: true,
          data: recoveryPlan
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-incomplete-executions-with-recovery');
        const result = await executeTool(tool, {
          includeRecoveryPlan: true,
          limit: 20
        }, { log: mockLog });
        
        expect(result).toContain('"totalIncomplete": 1');
        expect(result).toContain('recoveryPlan');
        expect(result).toContain('statusBreakdown');
        expect(result).toContain('impactAnalysis');
        
        const parsedResult = JSON.parse(result);
        expect(parsedResult.incompleteExecutions).toHaveLength(1);
        expect(parsedResult.incompleteExecutions[0].recoveryPlan).toBeDefined();
        expect(parsedResult.summary.recoveryBreakdown.canResume).toBe(1);
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/incomplete-executions');
        expect(calls[1].endpoint).toBe('/incomplete-executions/1001/recovery-analysis');
      });

      it('should filter incomplete executions by scenario and status', async () => {
        const filteredExecutions = [{ ...testIncompleteExecution, status: 'failed' }];
        mockApiClient.mockResponse('GET', '/incomplete-executions', {
          success: true,
          data: filteredExecutions,
          metadata: { total: 1 }
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-incomplete-executions-with-recovery');
        await executeTool(tool, {
          scenarioId: 789,
          status: 'failed',
          ageHours: 24,
          canResume: false
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.scenarioId).toBe(789);
        expect(calls[0].data.status).toBe('failed');
        expect(calls[0].data.ageHours).toBe(24);
        expect(calls[0].data.canResume).toBe(false);
      });

      it('should validate list incomplete executions parameters', async () => {
        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-incomplete-executions-with-recovery');
        
        // Test valid parameters
        expectValidZodParse(tool.parameters, {});
        expectValidZodParse(tool.parameters, { status: 'failed', limit: 50 });
        
        // Test invalid status
        expectInvalidZodParse(tool.parameters, { status: 'invalid-status' });
        
        // Test invalid limit
        expectInvalidZodParse(tool.parameters, { limit: 0 });
        expectInvalidZodParse(tool.parameters, { limit: 101 });
      });
    });

    describe('bulk-resolve-incomplete-executions tool', () => {
      it('should bulk resolve executions with retry action', async () => {
        const bulkResult = {
          successful: 3,
          failed: 1,
          batchId: 'batch_123',
          estimatedCompletionTime: '2024-01-15T16:30:00Z',
          errors: ['Execution 1004 cannot be resumed']
        };

        mockApiClient.mockResponse('POST', '/incomplete-executions/bulk-resolve', {
          success: true,
          data: bulkResult
        });

        // Mock status updates for first few executions
        [1001, 1002, 1003].forEach(id => {
          mockApiClient.mockResponse('GET', `/executions/${id}/status`, {
            success: true,
            data: { status: 'resumed' }
          });
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'bulk-resolve-incomplete-executions');
        const result = await executeTool(tool, {
          executionIds: [1001, 1002, 1003, 1004],
          action: 'retry',
          options: {
            retryWithModifications: true,
            skipFailedModules: false,
            preserveState: true,
            notifyOnCompletion: true
          },
          reason: 'Bulk recovery after system maintenance'
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        expect(result).toContain('Bulk resolution initiated for 4 executions');
        expect(result).toContain('"successfulResolutions": 3');
        expect(result).toContain('"failedResolutions": 1');
        expect(result).toContain('batch_123');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/incomplete-executions/bulk-resolve');
        expect(calls[0].data.action).toBe('retry');
        expect(calls[0].data.executionIds).toEqual([1001, 1002, 1003, 1004]);
        expect(calls[0].data.options.retryWithModifications).toBe(true);
        
        expectProgressReported(mockReportProgress, [
          { progress: 0, total: 100 },
          { progress: 25, total: 100 },
          { progress: 75, total: 100 },
          { progress: 100, total: 100 }
        ]);
      });

      it('should validate bulk resolve parameters', async () => {
        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'bulk-resolve-incomplete-executions');
        
        // Test valid parameters
        expectValidZodParse(tool.parameters, {
          executionIds: [1001, 1002],
          action: 'retry'
        });
        
        // Test invalid action
        expectInvalidZodParse(tool.parameters, {
          executionIds: [1001],
          action: 'invalid-action'
        });
        
        // Test empty execution IDs
        expectInvalidZodParse(tool.parameters, {
          executionIds: [],
          action: 'retry'
        });
        
        // Test too many execution IDs
        expectInvalidZodParse(tool.parameters, {
          executionIds: Array(51).fill(0).map((_, i) => i + 1),
          action: 'retry'
        });
      });
    });

    describe('analyze-execution-failure-patterns tool', () => {
      it('should analyze failure patterns with recommendations', async () => {
        const analysisResult = {
          totalFailures: 25,
          failureRate: 0.12,
          topErrors: [
            { error: 'Connection timeout', count: 8, percentage: 32 },
            { error: 'Rate limit exceeded', count: 5, percentage: 20 }
          ],
          topScenarios: [
            { scenarioId: 789, name: 'Data Import', failures: 12 },
            { scenarioId: 456, name: 'Email Processing', failures: 8 }
          ],
          timePatterns: {
            hourly: { '14': 8, '15': 6, '16': 11 },
            daily: { 'Monday': 15, 'Tuesday': 10 }
          },
          recoveryStats: { successRate: 0.75 },
          operationsLost: 50000,
          dataTransferLost: 125.5,
          estimatedCost: 245.75,
          recommendations: [
            {
              priority: 'high',
              type: 'infrastructure',
              description: 'Implement connection pooling to reduce timeout errors'
            }
          ]
        };

        mockApiClient.mockResponse('POST', '/incomplete-executions/failure-analysis', {
          success: true,
          data: analysisResult
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'analyze-execution-failure-patterns');
        const result = await executeTool(tool, {
          organizationId: 123,
          timeRange: {
            startDate: '2024-01-01T00:00:00Z',
            endDate: '2024-01-31T23:59:59Z'
          },
          includeRecommendations: true,
          groupBy: 'scenario'
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        expect(result).toContain('"totalFailures": 25');
        expect(result).toContain('"failureRate": "12.00%"');
        expect(result).toContain('recommendations');
        expect(result).toContain('Connection timeout');
        
        const parsedResult = JSON.parse(result);
        expect(parsedResult.insights.totalFailures).toBe(25);
        expect(parsedResult.insights.mostCommonErrors).toHaveLength(2);
        expect(parsedResult.recommendations).toHaveLength(1);
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/incomplete-executions/failure-analysis');
        expect(calls[0].data.organizationId).toBe(123);
        expect(calls[0].data.groupBy).toBe('scenario');
        
        expectProgressReported(mockReportProgress, [
          { progress: 0, total: 100 },
          { progress: 25, total: 100 },
          { progress: 75, total: 100 },
          { progress: 100, total: 100 }
        ]);
      });

      it('should validate analysis parameters', async () => {
        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'analyze-execution-failure-patterns');
        
        // Test valid parameters
        expectValidZodParse(tool.parameters, {
          timeRange: {
            startDate: '2024-01-01T00:00:00Z',
            endDate: '2024-01-31T23:59:59Z'
          }
        });
        
        // Test invalid groupBy
        expectInvalidZodParse(tool.parameters, {
          timeRange: {
            startDate: '2024-01-01T00:00:00Z',
            endDate: '2024-01-31T23:59:59Z'
          },
          groupBy: 'invalid-group'
        });
      });
    });

    describe('create-recovery-automation-rule tool', () => {
      it('should create recovery automation rule', async () => {
        const automationRule = {
          id: 'rule_123',
          name: 'Auto Retry Connection Errors',
          conditions: {
            errorPatterns: ['Connection timeout', 'Network error'],
            maxAge: 24
          },
          actions: {
            primaryAction: 'retry',
            retryConfig: {
              maxRetries: 3,
              delayMinutes: 5,
              modifyOnRetry: false
            }
          },
          isActive: true,
          priority: 80,
          createdAt: '2024-01-15T10:00:00Z'
        };

        mockApiClient.mockResponse('POST', '/recovery-automation-rules', {
          success: true,
          data: automationRule
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-recovery-automation-rule');
        const result = await executeTool(tool, {
          name: 'Auto Retry Connection Errors',
          description: 'Automatically retry executions that failed due to connection issues',
          conditions: {
            errorPatterns: ['Connection timeout', 'Network error'],
            maxAge: 24,
            minOperations: 100
          },
          actions: {
            primaryAction: 'retry',
            retryConfig: {
              maxRetries: 3,
              delayMinutes: 5,
              modifyOnRetry: false
            }
          },
          isActive: true,
          priority: 80
        }, { log: mockLog });
        
        expect(result).toContain('Auto Retry Connection Errors');
        expect(result).toContain('created successfully');
        expect(result).toContain('rule_123');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/recovery-automation-rules');
        expect(calls[0].data.name).toBe('Auto Retry Connection Errors');
        expect(calls[0].data.actions.primaryAction).toBe('retry');
        expect(calls[0].data.conditions.errorPatterns).toEqual(['Connection timeout', 'Network error']);
      });

      it('should create rule with notification configuration', async () => {
        const notificationRule = {
          id: 'rule_456',
          name: 'Critical Failure Alerts',
          actions: {
            primaryAction: 'notify',
            notificationConfig: {
              recipients: ['admin@company.com'],
              severity: 'high',
              includeContext: true
            }
          }
        };

        mockApiClient.mockResponse('POST', '/recovery-automation-rules', {
          success: true,
          data: notificationRule
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-recovery-automation-rule');
        await executeTool(tool, {
          name: 'Critical Failure Alerts',
          conditions: {
            scenarioIds: [789],
            minOperations: 1000
          },
          actions: {
            primaryAction: 'notify',
            notificationConfig: {
              recipients: ['admin@company.com'],
              severity: 'high',
              includeContext: true
            }
          }
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.actions.notificationConfig.recipients).toEqual(['admin@company.com']);
        expect(calls[0].data.actions.notificationConfig.severity).toBe('high');
      });

      it('should validate automation rule parameters', async () => {
        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-recovery-automation-rule');
        
        // Test valid parameters
        expectValidZodParse(tool.parameters, {
          name: 'Test Rule',
          conditions: { errorPatterns: ['error'] },
          actions: { primaryAction: 'retry' }
        });
        
        // Test invalid name (empty)
        expectInvalidZodParse(tool.parameters, {
          name: '',
          conditions: { errorPatterns: ['error'] },
          actions: { primaryAction: 'retry' }
        });
        
        // Test invalid primary action
        expectInvalidZodParse(tool.parameters, {
          name: 'Test Rule',
          conditions: { errorPatterns: ['error'] },
          actions: { primaryAction: 'invalid-action' }
        });
        
        // Test invalid priority range
        expectInvalidZodParse(tool.parameters, {
          name: 'Test Rule',
          conditions: { errorPatterns: ['error'] },
          actions: { primaryAction: 'retry' },
          priority: 101
        });
      });
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle API errors gracefully', async () => {
      mockApiClient.mockResponse('POST', '/organizations/123/variables', {
        success: false,
        error: { message: 'Validation failed: Name already exists' }
      });

      const { addVariableTools } = await import('../../../src/tools/variables.js');
      addVariableTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-custom-variable');
      
      await expect(executeTool(tool, {
        name: 'DUPLICATE_NAME',
        value: 'test',
        type: 'string',
        scope: 'organization',
        organizationId: 123
      }, { log: mockLog })).rejects.toThrow('Validation failed: Name already exists');
    });

    it('should handle network errors', async () => {
      mockApiClient.mockError('GET', '/variables', new Error('Network timeout'));

      const { addVariableTools } = await import('../../../src/tools/variables.js');
      addVariableTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-custom-variables');
      
      await expect(executeTool(tool, {}, { log: mockLog }))
        .rejects.toThrow('Network timeout');
    });

    it('should handle type conversion errors', async () => {
      const { addVariableTools } = await import('../../../src/tools/variables.js');
      addVariableTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-custom-variable');
      
      // Should fail with invalid number
      await expect(executeTool(tool, {
        name: 'INVALID_NUMBER',
        value: 'not-a-number',
        type: 'number',
        scope: 'organization',
        organizationId: 123
      }, { log: mockLog })).rejects.toThrow('Invalid number value');
      
      // Should fail with invalid JSON
      await expect(executeTool(tool, {
        name: 'INVALID_JSON',
        value: 'invalid-json-string',
        type: 'json',
        scope: 'organization',
        organizationId: 123
      }, { log: mockLog })).rejects.toThrow('Invalid JSON value');
    });

    it('should handle empty responses', async () => {
      mockApiClient.mockResponse('GET', '/variables', {
        success: true,
        data: [],
        metadata: { total: 0 }
      });

      const { addVariableTools } = await import('../../../src/tools/variables.js');
      addVariableTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-custom-variables');
      const result = await executeTool(tool, {}, { log: mockLog });
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.variables).toHaveLength(0);
      expect(parsedResult.summary.totalVariables).toBe(0);
    });
  });

  describe('Integration and End-to-End Scenarios', () => {
    it('should handle complete variable lifecycle', async () => {
      const { addVariableTools } = await import('../../../src/tools/variables.js');
      addVariableTools(mockServer, mockApiClient as any);

      // 1. Create variable
      mockApiClient.mockResponse('POST', '/organizations/123/variables', {
        success: true,
        data: testVariable
      });

      const createTool = findTool(mockTool, 'create-custom-variable');
      await executeTool(createTool, {
        name: 'API_BASE_URL',
        value: 'https://api.example.com/v1',
        type: 'string',
        scope: 'organization',
        organizationId: 123
      }, { log: mockLog });

      // 2. Get variable
      mockApiClient.mockResponse('GET', '/variables/1', {
        success: true,
        data: testVariable
      });

      const getTool = findTool(mockTool, 'get-custom-variable');
      await executeTool(getTool, { variableId: 1 }, { log: mockLog });

      // 3. Update variable (with type validation call first)
      mockApiClient.mockResponse('GET', '/variables/1', {
        success: true,
        data: testVariable
      });
      
      mockApiClient.mockResponse('PUT', '/variables/1', {
        success: true,
        data: { ...testVariable, value: 'https://api-v2.example.com/v1' }
      });

      const updateTool = findTool(mockTool, 'update-custom-variable');
      await executeTool(updateTool, {
        variableId: 1,
        value: 'https://api-v2.example.com/v1'
      }, { log: mockLog });

      // 4. Delete variable
      mockApiClient.mockResponse('GET', '/variables/1/usage', {
        success: true,
        data: { usageCount: 0 }
      });
      
      mockApiClient.mockResponse('DELETE', '/variables/1', {
        success: true,
        data: { deleted: true }
      });

      const deleteTool = findTool(mockTool, 'delete-custom-variable');
      await executeTool(deleteTool, { variableId: 1 }, { log: mockLog });

      expect(mockApiClient.getCallLog()).toHaveLength(6); // CREATE, GET, GET (for type validation), UPDATE, GET (usage check), DELETE
    });

    it('should handle variable resolution in inheritance chain', async () => {
      // Test scenario: scenario-level variable overrides team-level which overrides org-level
      const resolutionChain = {
        resolvedVariable: {
          id: 3,
          name: 'DATABASE_URL',
          value: 'postgres://scenario-db:5432/app',
          scope: 'scenario'
        },
        inheritanceChain: [
          { scope: 'scenario', found: true, variableId: 3 },
          { scope: 'team', found: true, variableId: 2 },
          { scope: 'organization', found: true, variableId: 1 }
        ]
      };

      mockApiClient.mockResponse('POST', '/variables/test-resolution', {
        success: true,
        data: resolutionChain
      });

      const { addVariableTools } = await import('../../../src/tools/variables.js');
      addVariableTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'test-variable-resolution');
      const result = await executeTool(tool, {
        variableName: 'DATABASE_URL',
        context: {
          organizationId: 123,
          teamId: 456,
          scenarioId: 789
        }
      }, { log: mockLog });
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.summary.resolved).toBe(true);
      expect(parsedResult.summary.resolvedScope).toBe('scenario');
      expect(parsedResult.summary.inheritanceChain).toHaveLength(3);
    });
  });
});