/**
 * Unit tests for custom variable management and incomplete execution recovery tools
 * Tests variable CRUD operations, scope management, bulk operations, and execution recovery
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
  expectToolExecutionToFail
} from '../../utils/test-helpers.js';
import type { 
  MakeCustomVariable 
} from '../../../src/tools/variables.js';
import type { MakeIncompleteExecution } from '../../../src/types/index.js';

describe('Variable Management and Execution Recovery Tools - Comprehensive Test Suite', () => {
  let mockServer: any;
  let mockApiClient: MockMakeApiClient;
  let mockTool: jest.MockedFunction<any>;
  let mockLog: jest.MockedFunction<any>;
  let mockReportProgress: jest.MockedFunction<any>;

  const testCustomVariable: MakeCustomVariable = {
    id: 1,
    name: 'API_BASE_URL',
    value: 'https://api.example.com/v1',
    type: 'string',
    scope: 'organization',
    organizationId: 123,
    teamId: 456,
    scenarioId: undefined,
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
      endpoints: ['primary.api.com', 'backup.api.com'],
      features: { logging: true, monitoring: false }
    },
    type: 'json',
    scope: 'team',
    organizationId: 123,
    teamId: 456,
    description: 'Configuration settings for team operations',
    tags: ['config', 'team'],
    lastModified: '2024-01-01T10:30:00Z',
    modifiedBy: 2,
    version: 1,
    isEncrypted: false
  };

  const testEncryptedVariable: MakeCustomVariable = {
    id: 3,
    name: 'SECRET_API_KEY',
    value: '[ENCRYPTED]',
    type: 'string',
    scope: 'scenario',
    organizationId: 123,
    teamId: 456,
    scenarioId: 789,
    description: 'Secret API key for external service',
    tags: ['secret', 'production'],
    lastModified: '2024-01-01T11:15:00Z',
    modifiedBy: 1,
    version: 1,
    isEncrypted: true
  };

  const testIncompleteExecution: MakeIncompleteExecution = {
    id: 1,
    scenarioId: 789,
    name: 'Data Processing Workflow',
    stoppedAt: '2024-01-01T10:30:00Z',
    status: 'paused',
    operations: 150,
    dataTransfer: 2.5,
    canResume: true,
    reason: 'Manual pause for debugging',
    modules: [
      {
        id: 1,
        name: 'HTTP Request',
        status: 'completed',
        position: 1
      },
      {
        id: 2,
        name: 'Data Transformer',
        status: 'paused',
        position: 2
      },
      {
        id: 3,
        name: 'Database Insert',
        status: 'pending',
        position: 3
      }
    ]
  };

  beforeEach(() => {
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockTool = serverSetup.mockTool;
    mockApiClient = new MockMakeApiClient();
    mockLog = {
      info: (...args: any[]) => {},
      error: (...args: any[]) => {},
      warn: (...args: any[]) => {},
      debug: (...args: any[]) => {},
    };
    mockReportProgress = (...args: any[]) => {};
  });

  afterEach(() => {
    jest.clearAllMocks();
    mockApiClient.reset();
  });

  describe('Tool Registration and Configuration', () => {
    it('should register all variable management and execution recovery tools with correct configuration', async () => {
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
    });
  });

  describe('Variable Management', () => {
    describe('create-custom-variable tool', () => {
      it('should create organization-scoped variable successfully', async () => {
        mockApiClient.mockResponse('POST', '/organizations/123/variables', {
          success: true,
          data: testCustomVariable
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
          tags: ['production', 'api', 'external'],
          isEncrypted: false
        }, { log: mockLog });
        
        expect(result).toContain('API_BASE_URL');
        expect(result).toContain('created successfully');
        expect(result).toContain('https://api.example.com/v1');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/organizations/123/variables');
        expect(calls[0].method).toBe('POST');
        expect(calls[0].data.name).toBe('API_BASE_URL');
        expect(calls[0].data.scope).toBe('organization');
        expect(calls[0].data.tags).toEqual(['production', 'api', 'external']);
      });

      it('should create team-scoped JSON variable successfully', async () => {
        mockApiClient.mockResponse('POST', '/teams/456/variables', {
          success: true,
          data: testJsonVariable
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-custom-variable');
        const result = await executeTool(tool, {
          name: 'CONFIG_SETTINGS',
          value: {
            timeout: 30000,
            retries: 3,
            endpoints: ['primary.api.com', 'backup.api.com'],
            features: { logging: true, monitoring: false }
          },
          type: 'json',
          scope: 'team',
          organizationId: 123,
          teamId: 456,
          description: 'Configuration settings for team operations',
          tags: ['config', 'team']
        }, { log: mockLog });
        
        expect(result).toContain('CONFIG_SETTINGS');
        expect(result).toContain('created successfully');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/teams/456/variables');
        expect(calls[0].data.type).toBe('json');
        expect(calls[0].data.value.timeout).toBe(30000);
        expect(calls[0].data.value.features.logging).toBe(true);
      });

      it('should create scenario-scoped encrypted variable successfully', async () => {
        mockApiClient.mockResponse('POST', '/scenarios/789/variables', {
          success: true,
          data: testEncryptedVariable
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-custom-variable');
        const result = await executeTool(tool, {
          name: 'SECRET_API_KEY',
          value: 'sk-1234567890abcdef',
          type: 'string',
          scope: 'scenario',
          organizationId: 123,
          teamId: 456,
          scenarioId: 789,
          description: 'Secret API key for external service',
          tags: ['secret', 'production'],
          isEncrypted: true
        }, { log: mockLog });
        
        expect(result).toContain('SECRET_API_KEY');
        expect(result).toContain('Variable value is encrypted');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/scenarios/789/variables');
        expect(calls[0].data.isEncrypted).toBe(true);
      });

      it('should validate scope consistency requirements', async () => {
        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-custom-variable');
        
        // Test organization scope without organization ID
        await expect(executeTool(tool, {
          name: 'TEST_VAR',
          value: 'test',
          type: 'string',
          scope: 'organization'
        }, { log: mockLog })).rejects.toThrow('Organization ID is required for organization scope variables');
        
        // Test team scope without team ID
        await expect(executeTool(tool, {
          name: 'TEST_VAR',
          value: 'test',
          type: 'string',
          scope: 'team',
          organizationId: 123
        }, { log: mockLog })).rejects.toThrow('Organization ID and Team ID are required for team scope variables');
        
        // Test scenario scope without scenario ID
        await expect(executeTool(tool, {
          name: 'TEST_VAR',
          value: 'test',
          type: 'string',
          scope: 'scenario',
          organizationId: 123,
          teamId: 456
        }, { log: mockLog })).rejects.toThrow('Organization ID, Team ID, and Scenario ID are required for scenario scope variables');
      });

      it('should format variable values according to type', async () => {
        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-custom-variable');
        
        // Test number type conversion
        mockApiClient.mockResponse('POST', '/variables', {
          success: true,
          data: { ...testCustomVariable, type: 'number', value: 42 }
        });
        
        await executeTool(tool, {
          name: 'NUMBER_VAR',
          value: '42',
          type: 'number',
          scope: 'organization',
          organizationId: 123
        }, { log: mockLog });
        
        let calls = mockApiClient.getCallLog();
        expect(calls[0].data.value).toBe(42);
        
        mockApiClient.reset();
        
        // Test boolean type conversion
        mockApiClient.mockResponse('POST', '/variables', {
          success: true,
          data: { ...testCustomVariable, type: 'boolean', value: true }
        });
        
        await executeTool(tool, {
          name: 'BOOLEAN_VAR',
          value: 'true',
          type: 'boolean',
          scope: 'organization',
          organizationId: 123
        }, { log: mockLog });
        
        calls = mockApiClient.getCallLog();
        expect(calls[0].data.value).toBe(true);
      });

      it('should validate input parameters with Zod schema', async () => {
        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-custom-variable');
        
        // Test invalid variable type
        await expectToolExecutionToFail(() => 
          executeTool(tool, {
            name: 'TEST_VAR',
            value: 'test',
            type: 'invalid-type',
            scope: 'organization',
            organizationId: 123
          }, { log: mockLog })
        );
        
        // Test invalid scope
        await expectToolExecutionToFail(() => 
          executeTool(tool, {
            name: 'TEST_VAR',
            value: 'test',
            type: 'string',
            scope: 'invalid-scope',
            organizationId: 123
          }, { log: mockLog })
        );
        
        // Test empty name
        await expectToolExecutionToFail(() => 
          executeTool(tool, {
            name: '',
            value: 'test',
            type: 'string',
            scope: 'organization',
            organizationId: 123
          }, { log: mockLog })
        );
      });
    });

    describe('list-custom-variables tool', () => {
      it('should list variables with comprehensive filtering and analytics', async () => {
        const variablesList = [
          testCustomVariable,
          testJsonVariable,
          testEncryptedVariable,
          { ...testCustomVariable, id: 4, name: 'DEBUG_MODE', type: 'boolean', value: false, scope: 'team', tags: ['debug'] }
        ];

        mockApiClient.mockResponse('GET', '/variables', {
          success: true,
          data: variablesList,
          metadata: { total: 4 }
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-custom-variables');
        const result = await executeTool(tool, {}, { log: mockLog });
        
        const parsed = JSON.parse(result);
        expect(parsed.variables).toHaveLength(4);
        expect(parsed.summary.totalVariables).toBe(4);
        expect(parsed.summary.typeBreakdown.string).toBe(2);
        expect(parsed.summary.typeBreakdown.json).toBe(1);
        expect(parsed.summary.typeBreakdown.boolean).toBe(1);
        expect(parsed.summary.scopeBreakdown.organization).toBe(1);
        expect(parsed.summary.scopeBreakdown.team).toBe(2);
        expect(parsed.summary.scopeBreakdown.scenario).toBe(1);
        expect(parsed.summary.encryptedCount).toBe(1);
        expect(parsed.summary.uniqueTags).toContain('production');
        expect(parsed.summary.uniqueTags).toContain('api');
        expect(parsed.summary.uniqueTags).toContain('config');
        
        // Verify encrypted values are masked
        const encryptedVar = parsed.variables.find((v: any) => v.name === 'SECRET_API_KEY');
        expect(encryptedVar.value).toBe('[ENCRYPTED]');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/variables');
        expect(calls[0].params.limit).toBe(100);
        expect(calls[0].params.sortBy).toBe('name');
      });

      it('should filter variables by scope, type, and other criteria', async () => {
        mockApiClient.mockResponse('GET', '/teams/456/variables', {
          success: true,
          data: [testJsonVariable],
          metadata: { total: 1 }
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-custom-variables');
        await executeTool(tool, {
          scope: 'team',
          organizationId: 123,
          teamId: 456,
          type: 'json',
          tags: ['config'],
          namePattern: 'CONFIG_*',
          isEncrypted: false,
          sortBy: 'lastModified',
          sortOrder: 'desc'
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/teams/456/variables');
        expect(calls[0].params.scope).toBe('team');
        expect(calls[0].params.type).toBe('json');
        expect(calls[0].params.tags).toBe('config');
        expect(calls[0].params.namePattern).toBe('CONFIG_*');
        expect(calls[0].params.isEncrypted).toBe(false);
        expect(calls[0].params.sortBy).toBe('lastModified');
      });

      it('should handle organization and scenario scoped searches', async () => {
        // Test organization scope
        mockApiClient.mockResponse('GET', '/organizations/123/variables', {
          success: true,
          data: [testCustomVariable],
          metadata: { total: 1 }
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-custom-variables');
        await executeTool(tool, {
          scope: 'organization',
          organizationId: 123
        }, { log: mockLog });
        
        let calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/organizations/123/variables');
        
        mockApiClient.reset();
        
        // Test scenario scope
        mockApiClient.mockResponse('GET', '/scenarios/789/variables', {
          success: true,
          data: [testEncryptedVariable],
          metadata: { total: 1 }
        });
        
        addVariableTools(mockServer, mockApiClient as any);
        
        await executeTool(tool, {
          scope: 'scenario',
          scenarioId: 789
        }, { log: mockLog });
        
        calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/scenarios/789/variables');
      });
    });

    describe('get-custom-variable tool', () => {
      it('should get variable details with usage statistics', async () => {
        mockApiClient.mockResponse('GET', '/variables/1', {
          success: true,
          data: testCustomVariable
        });

        const usageStats = {
          lastAccessed: '2024-01-01T11:30:00Z',
          accessCount: 25,
          usedInScenarios: ['scenario-1', 'scenario-2'],
          referencedBy: [
            { type: 'module', id: 5, name: 'HTTP Request' },
            { type: 'condition', id: 2, name: 'Data Filter' }
          ]
        };

        mockApiClient.mockResponse('GET', '/variables/1/usage', {
          success: true,
          data: usageStats
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-custom-variable');
        const result = await executeTool(tool, {
          variableId: 1,
          includeUsage: true
        }, { log: mockLog });
        
        const parsed = JSON.parse(result);
        expect(parsed.variable.name).toBe('API_BASE_URL');
        expect(parsed.variable.value).toBe('https://api.example.com/v1');
        expect(parsed.usage.accessCount).toBe(25);
        expect(parsed.metadata.lastAccessed).toBe('2024-01-01T11:30:00Z');
        expect(parsed.metadata.canEdit).toBe(true);
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/variables/1');
        expect(calls[1].endpoint).toBe('/variables/1/usage');
      });

      it('should handle encrypted variable details', async () => {
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
        
        const parsed = JSON.parse(result);
        expect(parsed.variable.name).toBe('SECRET_API_KEY');
        expect(parsed.variable.value).toBe('[ENCRYPTED]');
        expect(parsed.variable.isEncrypted).toBe(true);
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
    });

    describe('update-custom-variable tool', () => {
      it('should update variable value and metadata successfully', async () => {
        // Mock getting current variable for type validation
        mockApiClient.mockResponse('GET', '/variables/1', {
          success: true,
          data: testCustomVariable
        });

        const updatedVariable = {
          ...testCustomVariable,
          value: 'https://api.example.com/v2',
          description: 'Updated base URL for external API integration',
          tags: ['production', 'api', 'external', 'v2'],
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
          value: 'https://api.example.com/v2',
          description: 'Updated base URL for external API integration',
          tags: ['production', 'api', 'external', 'v2']
        }, { log: mockLog });
        
        expect(result).toContain('updated successfully');
        expect(result).toContain('https://api.example.com/v2');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[1].endpoint).toBe('/variables/1');
        expect(calls[1].method).toBe('PUT');
        expect(calls[1].data.value).toBe('https://api.example.com/v2');
        expect(calls[1].data.tags).toEqual(['production', 'api', 'external', 'v2']);
      });

      it('should update variable type and value together', async () => {
        const updatedVariable = {
          ...testCustomVariable,
          type: 'json',
          value: { apiUrl: 'https://api.example.com/v1', timeout: 30000 }
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
          value: { apiUrl: 'https://api.example.com/v1', timeout: 30000 },
          type: 'json'
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.type).toBe('json');
        expect(calls[0].data.value.timeout).toBe(30000);
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

    describe('delete-custom-variable tool', () => {
      it('should delete variable successfully when not in use', async () => {
        mockApiClient.mockResponse('GET', '/variables/1/usage', {
          success: true,
          data: { usageCount: 0 }
        });

        mockApiClient.mockResponse('DELETE', '/variables/1', {
          success: true,
          data: {}
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'delete-custom-variable');
        const result = await executeTool(tool, {
          variableId: 1,
          force: false
        }, { log: mockLog });
        
        expect(result).toContain('deleted successfully');
        expect(result).toContain('"forced": false');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/variables/1/usage');
        expect(calls[1].endpoint).toBe('/variables/1');
        expect(calls[1].method).toBe('DELETE');
      });

      it('should prevent deletion when variable is in use unless forced', async () => {
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
        }, { log: mockLog })).rejects.toThrow('Variable is currently in use (5 references). Use force=true to delete anyway.');
      });

      it('should force delete variable when explicitly requested', async () => {
        mockApiClient.mockResponse('DELETE', '/variables/1', {
          success: true,
          data: {}
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'delete-custom-variable');
        const result = await executeTool(tool, {
          variableId: 1,
          force: true
        }, { log: mockLog });
        
        expect(result).toContain('deleted successfully');
        expect(result).toContain('"forced": true');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/variables/1');
        expect(calls[0].method).toBe('DELETE');
      });
    });

    describe('bulk-variable-operations tool', () => {
      it('should perform bulk delete operation successfully', async () => {
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
          variableIds: [1, 2, 3]
        }, { log: mockLog });
        
        const parsed = JSON.parse(result);
        expect(parsed.result.affected).toBe(3);
        expect(parsed.summary.successful).toBe(3);
        expect(parsed.summary.failed).toBe(0);
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/variables/bulk');
        expect(calls[0].data.operation).toBe('delete');
        expect(calls[0].data.variableIds).toEqual([1, 2, 3]);
      });

      it('should perform bulk tag update operation', async () => {
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
        const result = await executeTool(tool, {
          operation: 'update_tags',
          variableIds: [1, 2, 3],
          operationData: {
            tags: ['updated', 'bulk-operation']
          }
        }, { log: mockLog });
        
        const parsed = JSON.parse(result);
        expect(parsed.summary.successful).toBe(2);
        expect(parsed.summary.failed).toBe(1);
        expect(parsed.summary.errors).toContain('Variable 3 not found');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.operationData.tags).toEqual(['updated', 'bulk-operation']);
      });

      it('should validate bulk operation parameters', async () => {
        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'bulk-variable-operations');
        
        // Test invalid operation
        await expectToolExecutionToFail(() => 
          executeTool(tool, {
            operation: 'invalid-operation',
            variableIds: [1, 2, 3]
          }, { log: mockLog })
        );
        
        // Test empty variable IDs
        await expectToolExecutionToFail(() => 
          executeTool(tool, {
            operation: 'delete',
            variableIds: []
          }, { log: mockLog })
        );
        
        // Test too many variable IDs
        await expectToolExecutionToFail(() => 
          executeTool(tool, {
            operation: 'delete',
            variableIds: Array.from({ length: 101 }, (_, i) => i + 1)
          }, { log: mockLog })
        );
      });
    });

    describe('export-custom-variables tool', () => {
      it('should export variables in JSON format successfully', async () => {
        const exportResult = {
          exportId: 'export_123',
          count: 15,
          encryptedCount: 3,
          downloadUrl: 'https://downloads.example.com/variables_export_123.json',
          filename: 'variables_export_123.json',
          expiresAt: '2024-01-02T12:00:00Z'
        };

        mockApiClient.mockResponse('POST', '/variables/export', {
          success: true,
          data: exportResult
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'export-custom-variables');
        const result = await executeTool(tool, {
          scope: 'organization',
          organizationId: 123,
          format: 'json',
          includeEncrypted: false,
          includeMetadata: true
        }, { log: mockLog });
        
        const parsed = JSON.parse(result);
        expect(parsed.exportResult.count).toBe(15);
        expect(parsed.download.url).toBe('https://downloads.example.com/variables_export_123.json');
        expect(parsed.summary.totalVariables).toBe(15);
        expect(parsed.summary.encryptedVariables).toBe(3);
        expect(parsed.summary.format).toBe('json');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/variables/export');
        expect(calls[0].data.scope).toBe('organization');
        expect(calls[0].data.organizationId).toBe(123);
        expect(calls[0].data.format).toBe('json');
        expect(calls[0].data.includeEncrypted).toBe(false);
      });

      it('should export variables in different formats', async () => {
        const formats = ['csv', 'env'];

        for (const format of formats) {
          mockApiClient.mockResponse('POST', '/variables/export', {
            success: true,
            data: {
              exportId: `export_${format}`,
              count: 10,
              downloadUrl: `https://downloads.example.com/variables.${format}`,
              filename: `variables.${format}`
            }
          });

          const { addVariableTools } = await import('../../../src/tools/variables.js');
          addVariableTools(mockServer, mockApiClient as any);
          
          const tool = findTool(mockTool, 'export-custom-variables');
          await executeTool(tool, {
            scope: 'all',
            format: format as any
          }, { log: mockLog });
          
          const calls = mockApiClient.getCallLog();
          expect(calls[0].data.format).toBe(format);
          
          mockApiClient.reset();
        }
      });
    });

    describe('test-variable-resolution tool', () => {
      it('should test variable resolution with inheritance chain', async () => {
        const resolutionResult = {
          resolvedVariable: {
            ...testCustomVariable,
            scope: 'organization'
          },
          inheritanceChain: [
            { scope: 'scenario', found: false, reason: 'Variable not defined at scenario level' },
            { scope: 'team', found: false, reason: 'Variable not defined at team level' },
            { scope: 'organization', found: true, variable: testCustomVariable }
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
        
        const parsed = JSON.parse(result);
        expect(parsed.summary.resolved).toBe(true);
        expect(parsed.summary.resolvedScope).toBe('organization');
        expect(parsed.summary.value).toBe('https://api.example.com/v1');
        expect(parsed.summary.inheritanceChain).toHaveLength(3);
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/variables/test-resolution');
        expect(calls[0].data.variableName).toBe('API_BASE_URL');
        expect(calls[0].data.context.scenarioId).toBe(789);
        expect(calls[0].data.includeInheritance).toBe(true);
      });

      it('should handle unresolved variable names', async () => {
        const resolutionResult = {
          resolvedVariable: null,
          inheritanceChain: [
            { scope: 'scenario', found: false, reason: 'Variable not defined' },
            { scope: 'team', found: false, reason: 'Variable not defined' },
            { scope: 'organization', found: false, reason: 'Variable not defined' }
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
          variableName: 'NONEXISTENT_VAR',
          context: { organizationId: 123 }
        }, { log: mockLog });
        
        const parsed = JSON.parse(result);
        expect(parsed.summary.resolved).toBe(false);
        expect(parsed.summary.resolvedScope).toBeUndefined();
      });
    });
  });

  describe('Incomplete Execution Recovery', () => {
    describe('list-incomplete-executions-with-recovery tool', () => {
      it('should list incomplete executions with comprehensive recovery analysis', async () => {
        const incompleteExecutions = [
          testIncompleteExecution,
          { ...testIncompleteExecution, id: 2, status: 'failed', canResume: false, operations: 75, reason: 'API timeout error' },
          { ...testIncompleteExecution, id: 3, status: 'waiting', operations: 300, reason: 'Dependency module update' }
        ];

        mockApiClient.mockResponse('GET', '/incomplete-executions', {
          success: true,
          data: incompleteExecutions,
          metadata: { total: 3 }
        });

        // Mock recovery analysis for each execution
        for (let i = 1; i <= 3; i++) {
          mockApiClient.mockResponse('GET', `/incomplete-executions/${i}/recovery-analysis`, {
            success: true,
            data: {
              canResume: i !== 2,
              recommendedAction: i === 1 ? 'resume' : i === 2 ? 'retry' : 'wait',
              riskLevel: i === 2 ? 'high' : 'low',
              estimatedRecoveryTime: i * 5,
              prerequisites: []
            }
          });
        }

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-incomplete-executions-with-recovery');
        const result = await executeTool(tool, {
          includeRecoveryPlan: true,
          status: 'all'
        }, { log: mockLog });
        
        const parsed = JSON.parse(result);
        expect(parsed.incompleteExecutions).toHaveLength(3);
        expect(parsed.summary.totalIncomplete).toBe(3);
        expect(parsed.summary.statusBreakdown.paused).toBe(1);
        expect(parsed.summary.statusBreakdown.failed).toBe(1);
        expect(parsed.summary.statusBreakdown.waiting).toBe(1);
        expect(parsed.summary.recoveryBreakdown.canResume).toBe(2);
        expect(parsed.summary.recoveryBreakdown.requiresIntervention).toBe(1);
        expect(parsed.summary.impactAnalysis.totalOperationsAffected).toBe(525);
        expect(parsed.summary.impactAnalysis.uniqueScenarios).toBe(1);
        
        // Verify recovery plans are included
        expect(parsed.incompleteExecutions[0].recoveryPlan.recommendedAction).toBe('resume');
        expect(parsed.incompleteExecutions[1].recoveryPlan.recommendedAction).toBe('retry');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/incomplete-executions');
        expect(calls[0].params.includeRecoveryPlan).toBe(true);
      });

      it('should filter executions by scenario, organization, and status', async () => {
        mockApiClient.mockResponse('GET', '/incomplete-executions', {
          success: true,
          data: [testIncompleteExecution],
          metadata: { total: 1 }
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-incomplete-executions-with-recovery');
        await executeTool(tool, {
          scenarioId: 789,
          organizationId: 123,
          teamId: 456,
          status: 'paused',
          ageHours: 24,
          canResume: true
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].params.scenarioId).toBe(789);
        expect(calls[0].params.organizationId).toBe(123);
        expect(calls[0].params.teamId).toBe(456);
        expect(calls[0].params.status).toBe('paused');
        expect(calls[0].params.ageHours).toBe(24);
        expect(calls[0].params.canResume).toBe(true);
      });
    });

    describe('bulk-resolve-incomplete-executions tool', () => {
      it('should resolve multiple executions with batch operations', async () => {
        const bulkResult = {
          successful: 4,
          failed: 1,
          batchId: 'batch_123',
          estimatedCompletionTime: '2024-01-01T12:10:00Z',
          errors: ['Execution 5 cannot be resumed due to missing dependencies']
        };

        mockApiClient.mockResponse('POST', '/incomplete-executions/bulk-resolve', {
          success: true,
          data: bulkResult
        });

        // Mock status updates for resolved executions
        for (let i = 1; i <= 5; i++) {
          mockApiClient.mockResponse('GET', `/executions/${i}/status`, {
            success: true,
            data: { status: i === 5 ? 'error' : 'running' }
          });
        }

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'bulk-resolve-incomplete-executions');
        const result = await executeTool(tool, {
          executionIds: [1, 2, 3, 4, 5],
          action: 'retry',
          options: {
            retryWithModifications: true,
            skipFailedModules: false,
            preserveState: true,
            notifyOnCompletion: true
          },
          reason: 'Batch recovery after system maintenance'
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsed = JSON.parse(result);
        expect(parsed.summary.requestedCount).toBe(5);
        expect(parsed.summary.successfulResolutions).toBe(4);
        expect(parsed.summary.failedResolutions).toBe(1);
        expect(parsed.summary.action).toBe('retry');
        expect(parsed.summary.batchId).toBe('batch_123');
        expect(parsed.statusUpdates).toHaveLength(5);
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/incomplete-executions/bulk-resolve');
        expect(calls[0].data.executionIds).toEqual([1, 2, 3, 4, 5]);
        expect(calls[0].data.action).toBe('retry');
        expect(calls[0].data.options.retryWithModifications).toBe(true);
        expect(calls[0].data.reason).toBe('Batch recovery after system maintenance');
        
        expectProgressReported(mockReportProgress, [
          { progress: 0, total: 100 },
          { progress: 25, total: 100 },
          { progress: 75, total: 100 },
          { progress: 100, total: 100 }
        ]);
      });

      it('should handle different bulk resolution actions', async () => {
        const actions = ['skip', 'cancel', 'auto'];

        for (const action of actions) {
          mockApiClient.mockResponse('POST', '/incomplete-executions/bulk-resolve', {
            success: true,
            data: {
              successful: 2,
              failed: 0,
              batchId: `batch_${action}`
            }
          });

          const { addVariableTools } = await import('../../../src/tools/variables.js');
          addVariableTools(mockServer, mockApiClient as any);
          
          const tool = findTool(mockTool, 'bulk-resolve-incomplete-executions');
          await executeTool(tool, {
            executionIds: [1, 2],
            action: action as any
          }, { log: mockLog, reportProgress: mockReportProgress });
          
          const calls = mockApiClient.getCallLog();
          expect(calls[0].data.action).toBe(action);
          
          mockApiClient.reset();
        }
      });

      it('should validate bulk resolution parameters', async () => {
        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'bulk-resolve-incomplete-executions');
        
        // Test empty execution IDs
        await expectToolExecutionToFail(() => 
          executeTool(tool, {
            executionIds: [],
            action: 'retry'
          }, { log: mockLog })
        );
        
        // Test too many execution IDs
        await expectToolExecutionToFail(() => 
          executeTool(tool, {
            executionIds: Array.from({ length: 51 }, (_, i) => i + 1),
            action: 'retry'
          }, { log: mockLog })
        );
        
        // Test invalid action
        await expectToolExecutionToFail(() => 
          executeTool(tool, {
            executionIds: [1, 2],
            action: 'invalid-action'
          }, { log: mockLog })
        );
      });
    });

    describe('analyze-execution-failure-patterns tool', () => {
      it('should analyze failure patterns with comprehensive insights', async () => {
        const analysisResult = {
          totalFailures: 45,
          failureRate: 0.15,
          topErrors: [
            { error: 'API timeout', count: 20, percentage: 44.4 },
            { error: 'Authentication failed', count: 12, percentage: 26.7 },
            { error: 'Rate limit exceeded', count: 8, percentage: 17.8 }
          ],
          topScenarios: [
            { scenarioId: 789, name: 'Data Processing', failures: 25 },
            { scenarioId: 456, name: 'Email Automation', failures: 15 },
            { scenarioId: 123, name: 'CRM Sync', failures: 5 }
          ],
          timePatterns: {
            hourlyDistribution: { '09': 8, '14': 12, '18': 15 },
            dailyTrends: { monday: 10, tuesday: 8, wednesday: 12 }
          },
          recoveryStats: {
            successRate: 0.82,
            averageRecoveryTime: 45,
            manualInterventions: 8
          },
          operationsLost: 3500,
          dataTransferLost: 15.2,
          estimatedCost: 850.75,
          recommendations: [
            {
              type: 'timeout_adjustment',
              priority: 'high',
              description: 'Increase API timeout values for external services',
              impact: 'Could reduce failures by 40%'
            },
            {
              type: 'retry_strategy',
              priority: 'medium',
              description: 'Implement exponential backoff for rate limit handling',
              impact: 'Could reduce failures by 15%'
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
        
        const parsed = JSON.parse(result);
        expect(parsed.analysis.totalFailures).toBe(45);
        expect(parsed.insights.failureRate).toBe(0.15);
        expect(parsed.insights.mostCommonErrors).toHaveLength(3);
        expect(parsed.insights.mostAffectedScenarios).toHaveLength(3);
        expect(parsed.insights.operationalImpact.operationsLost).toBe(3500);
        expect(parsed.recommendations).toHaveLength(2);
        expect(parsed.summary.actionableRecommendations).toBe(1);
        expect(parsed.summary.failureRate).toBe('15.00%');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/incomplete-executions/failure-analysis');
        expect(calls[0].data.organizationId).toBe(123);
        expect(calls[0].data.groupBy).toBe('scenario');
        expect(calls[0].data.includeRecommendations).toBe(true);
        
        expectProgressReported(mockReportProgress, [
          { progress: 0, total: 100 },
          { progress: 25, total: 100 },
          { progress: 75, total: 100 },
          { progress: 100, total: 100 }
        ]);
      });

      it('should analyze patterns by different grouping methods', async () => {
        const groupings = ['module', 'error_type', 'time'];

        for (const groupBy of groupings) {
          mockApiClient.mockResponse('POST', '/incomplete-executions/failure-analysis', {
            success: true,
            data: {
              totalFailures: 20,
              failureRate: 0.1,
              groupBy: groupBy
            }
          });

          const { addVariableTools } = await import('../../../src/tools/variables.js');
          addVariableTools(mockServer, mockApiClient as any);
          
          const tool = findTool(mockTool, 'analyze-execution-failure-patterns');
          await executeTool(tool, {
            timeRange: {
              startDate: '2024-01-01T00:00:00Z',
              endDate: '2024-01-31T23:59:59Z'
            },
            groupBy: groupBy as any
          }, { log: mockLog, reportProgress: mockReportProgress });
          
          const calls = mockApiClient.getCallLog();
          expect(calls[0].data.groupBy).toBe(groupBy);
          
          mockApiClient.reset();
        }
      });
    });

    describe('create-recovery-automation-rule tool', () => {
      it('should create comprehensive recovery automation rule', async () => {
        const automationRule = {
          id: 1,
          name: 'API Timeout Auto-Recovery',
          description: 'Automatically retry executions that fail due to API timeouts',
          conditions: {
            errorPatterns: ['timeout', 'connection refused'],
            maxAge: 24
          },
          actions: {
            primaryAction: 'retry',
            retryConfig: {
              maxRetries: 3,
              delayMinutes: 5,
              modifyOnRetry: true
            }
          },
          isActive: true,
          priority: 75
        };

        mockApiClient.mockResponse('POST', '/recovery-automation-rules', {
          success: true,
          data: automationRule
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-recovery-automation-rule');
        const result = await executeTool(tool, {
          name: 'API Timeout Auto-Recovery',
          description: 'Automatically retry executions that fail due to API timeouts',
          conditions: {
            errorPatterns: ['timeout', 'connection refused'],
            scenarioIds: [789, 456],
            moduleTypes: ['http'],
            maxAge: 24,
            minOperations: 10
          },
          actions: {
            primaryAction: 'retry',
            retryConfig: {
              maxRetries: 3,
              delayMinutes: 5,
              modifyOnRetry: true
            },
            notificationConfig: {
              recipients: ['admin@example.com'],
              severity: 'medium',
              includeContext: true
            }
          },
          isActive: true,
          priority: 75
        }, { log: mockLog });
        
        const parsed = JSON.parse(result);
        expect(parsed.rule.name).toBe('API Timeout Auto-Recovery');
        expect(parsed.summary.primaryAction).toBe('retry');
        expect(parsed.summary.isActive).toBe(true);
        expect(parsed.summary.priority).toBe(75);
        expect(parsed.summary.conditionCount).toBe(4);
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/recovery-automation-rules');
        expect(calls[0].data.name).toBe('API Timeout Auto-Recovery');
        expect(calls[0].data.conditions.errorPatterns).toEqual(['timeout', 'connection refused']);
        expect(calls[0].data.actions.primaryAction).toBe('retry');
        expect(calls[0].data.actions.retryConfig.maxRetries).toBe(3);
      });

      it('should create different types of automation rules', async () => {
        const ruleConfigs = [
          {
            name: 'Notification Rule',
            primaryAction: 'notify',
            notificationConfig: {
              recipients: ['team@example.com'],
              severity: 'high'
            }
          },
          {
            name: 'Skip Rule',
            primaryAction: 'skip',
            conditions: { moduleTypes: ['email'] }
          },
          {
            name: 'Cancel Rule',
            primaryAction: 'cancel',
            conditions: { errorPatterns: ['critical error'] }
          }
        ];

        for (const config of ruleConfigs) {
          mockApiClient.mockResponse('POST', '/recovery-automation-rules', {
            success: true,
            data: { id: 1, ...config, isActive: true, priority: 50 }
          });

          const { addVariableTools } = await import('../../../src/tools/variables.js');
          addVariableTools(mockServer, mockApiClient as any);
          
          const tool = findTool(mockTool, 'create-recovery-automation-rule');
          await executeTool(tool, {
            name: config.name,
            conditions: config.conditions || {},
            actions: {
              primaryAction: config.primaryAction as any,
              ...config.notificationConfig && { notificationConfig: config.notificationConfig }
            }
          }, { log: mockLog });
          
          const calls = mockApiClient.getCallLog();
          expect(calls[0].data.actions.primaryAction).toBe(config.primaryAction);
          
          mockApiClient.reset();
        }
      });

      it('should validate automation rule parameters', async () => {
        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-recovery-automation-rule');
        
        // Test empty name
        await expectToolExecutionToFail(() => 
          executeTool(tool, {
            name: '',
            conditions: {},
            actions: { primaryAction: 'retry' }
          }, { log: mockLog })
        );
        
        // Test invalid primary action
        await expectToolExecutionToFail(() => 
          executeTool(tool, {
            name: 'Test Rule',
            conditions: {},
            actions: { primaryAction: 'invalid-action' }
          }, { log: mockLog })
        );
        
        // Test invalid priority
        await expectToolExecutionToFail(() => 
          executeTool(tool, {
            name: 'Test Rule',
            conditions: {},
            actions: { primaryAction: 'retry' },
            priority: 0
          }, { log: mockLog })
        );
      });
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle API errors gracefully across all tools', async () => {
      const tools = [
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

      for (const toolName of tools) {
        mockApiClient.mockResponse('*', '*', {
          success: false,
          error: { message: 'Service temporarily unavailable' }
        });

        const { addVariableTools } = await import('../../../src/tools/variables.js');
        addVariableTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, toolName);
        
        let testInput: any = {};
        if (toolName === 'create-custom-variable') {
          testInput = {
            name: 'TEST_VAR',
            value: 'test',
            type: 'string',
            scope: 'organization',
            organizationId: 123
          };
        } else if (toolName === 'get-custom-variable') {
          testInput = { variableId: 1 };
        } else if (toolName === 'update-custom-variable') {
          testInput = { variableId: 1, value: 'new value' };
        } else if (toolName === 'delete-custom-variable') {
          testInput = { variableId: 1 };
        } else if (toolName === 'bulk-variable-operations') {
          testInput = { operation: 'delete', variableIds: [1, 2, 3] };
        } else if (toolName === 'export-custom-variables') {
          testInput = { scope: 'all', format: 'json' };
        } else if (toolName === 'test-variable-resolution') {
          testInput = { variableName: 'TEST_VAR', context: {} };
        } else if (toolName === 'bulk-resolve-incomplete-executions') {
          testInput = { executionIds: [1, 2], action: 'retry' };
        } else if (toolName === 'analyze-execution-failure-patterns') {
          testInput = {
            timeRange: {
              startDate: '2024-01-01T00:00:00Z',
              endDate: '2024-01-31T23:59:59Z'
            }
          };
        } else if (toolName === 'create-recovery-automation-rule') {
          testInput = {
            name: 'Test Rule',
            conditions: {},
            actions: { primaryAction: 'retry' }
          };
        }
        
        await expect(executeTool(tool, testInput, { log: mockLog, reportProgress: mockReportProgress }))
          .rejects.toThrow(UserError);
        
        mockApiClient.reset();
      }
    });

    it('should handle network errors', async () => {
      mockApiClient.mockError('POST', '/organizations/123/variables', new Error('Network timeout'));

      const { addVariableTools } = await import('../../../src/tools/variables.js');
      addVariableTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-custom-variable');
      
      await expect(executeTool(tool, {
        name: 'TEST_VAR',
        value: 'test',
        type: 'string',
        scope: 'organization',
        organizationId: 123
      }, { log: mockLog })).rejects.toThrow('Failed to create custom variable: Network timeout');
    });

    it('should log operations correctly', async () => {
      mockApiClient.mockResponse('POST', '/organizations/123/variables', {
        success: true,
        data: testCustomVariable
      });

      const { addVariableTools } = await import('../../../src/tools/variables.js');
      addVariableTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-custom-variable');
      await executeTool(tool, {
        name: 'API_BASE_URL',
        value: 'https://api.example.com/v1',
        type: 'string',
        scope: 'organization',
        organizationId: 123
      }, { log: mockLog });
      
      expect(mockLog).toHaveBeenCalledWith(
        'info',
        'Creating custom variable',
        expect.objectContaining({
          name: 'API_BASE_URL',
          type: 'string',
          scope: 'organization'
        })
      );
      expect(mockLog).toHaveBeenCalledWith(
        'info',
        'Successfully created custom variable',
        expect.objectContaining({
          variableId: 1,
          name: 'API_BASE_URL'
        })
      );
    });
  });

  describe('Security and Data Protection', () => {
    it('should mask encrypted variable values in responses', async () => {
      mockApiClient.mockResponse('GET', '/variables', {
        success: true,
        data: [testCustomVariable, testEncryptedVariable],
        metadata: { total: 2 }
      });

      const { addVariableTools } = await import('../../../src/tools/variables.js');
      addVariableTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-custom-variables');
      const result = await executeTool(tool, {}, { log: mockLog });
      
      const parsed = JSON.parse(result);
      const regularVar = parsed.variables.find((v: any) => v.name === 'API_BASE_URL');
      const encryptedVar = parsed.variables.find((v: any) => v.name === 'SECRET_API_KEY');
      
      expect(regularVar.value).toBe('https://api.example.com/v1');
      expect(encryptedVar.value).toBe('[ENCRYPTED]');
    });

    it('should handle variable formatting validation errors', async () => {
      const { addVariableTools } = await import('../../../src/tools/variables.js');
      addVariableTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-custom-variable');
      
      // Test invalid number format
      await expect(executeTool(tool, {
        name: 'INVALID_NUMBER',
        value: 'not-a-number',
        type: 'number',
        scope: 'organization',
        organizationId: 123
      }, { log: mockLog })).rejects.toThrow('Invalid number value: not-a-number');
      
      // Test invalid boolean format
      await expect(executeTool(tool, {
        name: 'INVALID_BOOLEAN',
        value: 'maybe',
        type: 'boolean',
        scope: 'organization',
        organizationId: 123
      }, { log: mockLog })).rejects.toThrow('Invalid boolean value: maybe');
      
      // Test invalid JSON format
      await expect(executeTool(tool, {
        name: 'INVALID_JSON',
        value: '{ invalid json',
        type: 'json',
        scope: 'organization',
        organizationId: 123
      }, { log: mockLog })).rejects.toThrow('Invalid JSON value: { invalid json');
    });
  });
});