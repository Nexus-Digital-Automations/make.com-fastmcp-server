/**
 * Basic unit tests for notification management tools
 * Tests the missing data structure management tools and provides additional coverage
 * for notification delivery, channel routing, and template validation
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
import type { 
  MakeCustomDataStructure,
  DataStructureListResponse,
  DataStructureWithStats,
  DataStructureDependency,
  DataStructureDependencyResponse,
  DataStructureArchiveResponse
} from '../../../src/tools/notifications.js';

describe('Notification Management Tools - Additional Coverage', () => {
  let mockServer: any;
  let mockApiClient: MockMakeApiClient;
  let mockTool: jest.MockedFunction<any>;
  let mockLog: any;
  let mockReportProgress: jest.MockedFunction<any>;

  const testDataStructure: MakeCustomDataStructure = {
    id: 1,
    name: 'Product Schema',
    description: 'Schema for product data validation',
    type: 'schema',
    organizationId: 123,
    teamId: 1,
    scope: 'organization',
    structure: {
      schema: {
        type: 'object',
        properties: {
          name: { type: 'string', minLength: 1, maxLength: 100 },
          price: { type: 'number', minimum: 0 },
          category: { type: 'string', enum: ['electronics', 'clothing', 'books'] },
          tags: { type: 'array', items: { type: 'string' } }
        },
        required: ['name', 'price', 'category']
      },
      version: '2.1.0',
      format: 'json'
    },
    validation: {
      enabled: true,
      strict: true,
      rules: [
        {
          field: 'price',
          type: 'range',
          parameters: { min: 0, max: 10000 },
          message: 'Price must be between $0 and $10,000'
        },
        {
          field: 'name',
          type: 'required',
          parameters: {},
          message: 'Product name is required'
        }
      ]
    },
    transformation: {
      enabled: true,
      mappings: [
        {
          source: 'product_name',
          target: 'name',
          function: 'trim'
        },
        {
          source: 'cost',
          target: 'price',
          function: 'parseFloat'
        }
      ],
      filters: [
        {
          field: 'price',
          operator: 'gt',
          value: 0
        },
        {
          field: 'category',
          operator: 'in',
          value: ['electronics', 'clothing', 'books']
        }
      ]
    },
    usage: {
      scenariosUsing: 8,
      lastUsed: '2024-01-15T14:30:00Z',
      validationCount: 2500,
      errorRate: 1.2
    },
    versions: [
      {
        version: '2.1.0',
        changes: 'Added tags array, updated price validation',
        createdAt: '2024-01-10T09:00:00Z',
        createdBy: 1
      },
      {
        version: '2.0.0',
        changes: 'Major schema update with new structure',
        createdAt: '2023-12-15T10:00:00Z',
        createdBy: 1
      }
    ],
    createdAt: '2023-12-01T10:00:00Z',
    updatedAt: '2024-01-10T09:00:00Z',
    createdBy: 1
  };

  const testDataStructureStats: DataStructureWithStats = {
    ...testDataStructure,
    usage: {
      scenariosUsing: 8,
      lastUsed: '2024-01-15T14:30:00Z',
      validationCount: 2500,
      errorRate: 1.2,
      transformationCount: 1800,
      averageValidationTime: 125.5,
      successRate: 98.8
    },
    validationHistory: [
      {
        timestamp: '2024-01-15T14:30:00Z',
        result: 'success',
        errors: [],
        processingTime: 120
      },
      {
        timestamp: '2024-01-15T14:25:00Z',
        result: 'failure',
        errors: ['Invalid price format'],
        processingTime: 95
      }
    ],
    transformationHistory: [
      {
        timestamp: '2024-01-15T14:30:00Z',
        result: 'success',
        inputRecords: 50,
        outputRecords: 48,
        processingTime: 340
      }
    ]
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
    it('should import notification tools module without errors', async () => {
      const { addNotificationTools } = await import('../../../src/tools/notifications.js');
      expect(addNotificationTools).toBeDefined();
      expect(typeof addNotificationTools).toBe('function');
    });

    it('should register all notification management tools', async () => {
      const { addNotificationTools } = await import('../../../src/tools/notifications.js');
      addNotificationTools(mockServer, mockApiClient as any);
      
      const allExpectedTools = [
        'create-notification',
        'get-email-preferences', 
        'update-email-preferences',
        'create-notification-template',
        'create-data-structure',
        'list-data-structures',
        'get-data-structure',
        'update-data-structure',
        'delete-data-structure',
        'list-notifications'
      ];

      allExpectedTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool).toBeDefined();
        expect(tool.name).toBe(toolName);
        expect(tool.description).toBeDefined();
        expect(tool.parameters).toBeDefined();
      });

      // Verify we have all 10 tools
      expect(mockTool.mock.calls).toHaveLength(10);
    });

    it('should have proper tool configuration for all tools', async () => {
      const { addNotificationTools } = await import('../../../src/tools/notifications.js');
      addNotificationTools(mockServer, mockApiClient as any);
      
      const tools = ['list-data-structures', 'get-data-structure', 'update-data-structure', 'delete-data-structure'];
      
      tools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool.description).toMatch(/data structure/i);
        expect(tool.parameters).toBeDefined();
        expect(typeof tool.execute).toBe('function');
      });
    });
  });

  describe('Data Structure Listing and Search', () => {
    describe('list-data-structures tool', () => {
      it('should list data structures with default parameters', async () => {
        const listResponse: DataStructureListResponse = {
          dataStructures: [testDataStructure],
          pagination: {
            total: 1,
            offset: 0,
            limit: 20,
            hasMore: false
          },
          filters: {
            type: 'all',
            scope: 'all',
            format: 'all'
          }
        };

        mockApiClient.mockResponse('GET', '/data-structures', {
          success: true,
          data: listResponse
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-data-structures');
        const result = await executeTool(tool, {}, { log: mockLog });
        
        expect(result).toContain('Product Schema');
        expect(result).toContain('"totalFound": 1');
        expect(result).toContain('statistics');
        expect(result).toContain('byType');
        expect(result).toContain('byScope');
        expect(result).toContain('byFormat');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/data-structures');
        expect(calls[0].method).toBe('GET');
        expect(calls[0].data.limit).toBe(20);
        expect(calls[0].data.offset).toBe(0);
      });

      it('should filter data structures by type and scope', async () => {
        const filteredResponse: DataStructureListResponse = {
          dataStructures: [{ ...testDataStructure, type: 'validation', scope: 'team' }],
          pagination: {
            total: 1,
            offset: 0,
            limit: 10,
            hasMore: false
          },
          filters: {
            type: 'validation',
            scope: 'team',
            format: 'json'
          }
        };

        mockApiClient.mockResponse('GET', '/data-structures', {
          success: true,
          data: filteredResponse
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-data-structures');
        await executeTool(tool, {
          type: 'validation',
          scope: 'team',
          format: 'json',
          search: 'product',
          limit: 10,
          sortBy: 'name',
          sortOrder: 'asc'
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.type).toBe('validation');
        expect(calls[0].data.scope).toBe('team');
        expect(calls[0].data.format).toBe('json');
        expect(calls[0].data.search).toBe('product');
        expect(calls[0].data.limit).toBe(10);
        expect(calls[0].data.sortBy).toBe('name');
        expect(calls[0].data.sortOrder).toBe('asc');
      });

      it('should list organization-scoped data structures', async () => {
        const orgId = 456;
        mockApiClient.mockResponse('GET', `/organizations/${orgId}/data-structures`, {
          success: true,
          data: {
            dataStructures: [{ ...testDataStructure, organizationId: orgId }],
            pagination: { total: 1, offset: 0, limit: 20, hasMore: false },
            filters: { type: 'all', scope: 'organization', format: 'all' }
          }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-data-structures');
        await executeTool(tool, { organizationId: orgId }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe(`/organizations/${orgId}/data-structures`);
      });

      it('should list team-scoped data structures', async () => {
        const teamId = 789;
        mockApiClient.mockResponse('GET', `/teams/${teamId}/data-structures`, {
          success: true,
          data: {
            dataStructures: [{ ...testDataStructure, teamId }],
            pagination: { total: 1, offset: 0, limit: 20, hasMore: false },
            filters: { type: 'all', scope: 'team', format: 'all' }
          }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-data-structures');
        await executeTool(tool, { teamId }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe(`/teams/${teamId}/data-structures`);
      });

      it('should handle empty results', async () => {
        mockApiClient.mockResponse('GET', '/data-structures', {
          success: true,
          data: {
            dataStructures: [],
            pagination: { total: 0, offset: 0, limit: 20, hasMore: false },
            filters: { type: 'all', scope: 'all', format: 'all' }
          }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-data-structures');
        const result = await executeTool(tool, {}, { log: mockLog });
        
        expect(result).toContain('"totalFound": 0');
        expect(result).toContain('"dataStructures": []');
      });

      it('should validate list parameters', async () => {
        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-data-structures');
        
        // Test invalid type
        expectInvalidZodParse(tool.parameters, { type: 'invalid-type' });
        
        // Test invalid scope
        expectInvalidZodParse(tool.parameters, { scope: 'invalid-scope' });
        
        // Test invalid limit
        expectInvalidZodParse(tool.parameters, { limit: 0 });
        expectInvalidZodParse(tool.parameters, { limit: 101 });
        
        // Test invalid offset
        expectInvalidZodParse(tool.parameters, { offset: -1 });
      });
    });
  });

  describe('Data Structure Retrieval', () => {
    describe('get-data-structure tool', () => {
      it('should get data structure with basic information', async () => {
        mockApiClient.mockResponse('GET', '/data-structures/1', {
          success: true,
          data: testDataStructureStats
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-data-structure');
        const result = await executeTool(tool, {
          dataStructureId: 1
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        expect(result).toContain('Product Schema');
        expect(result).toContain('"id": 1');
        expect(result).toContain('validateUrl');
        expect(result).toContain('transformUrl');
        expect(result).toContain('configuration');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/data-structures/1');
        expect(calls[0].data.includeUsageStats).toBe(true);
        expect(calls[0].data.includeValidationHistory).toBe(false);
        expect(calls[0].data.includeTransformationHistory).toBe(false);
        
        expectProgressReported(mockReportProgress, [
          { progress: 0, total: 100 },
          { progress: 50, total: 100 },
          { progress: 100, total: 100 }
        ]);
      });

      it('should get data structure with usage history', async () => {
        mockApiClient.mockResponse('GET', '/data-structures/1', {
          success: true,
          data: testDataStructureStats
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-data-structure');
        await executeTool(tool, {
          dataStructureId: 1,
          includeValidationHistory: true,
          includeTransformationHistory: true
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.includeValidationHistory).toBe(true);
        expect(calls[0].data.includeTransformationHistory).toBe(true);
      });

      it('should get organization-scoped data structure', async () => {
        const orgId = 123;
        mockApiClient.mockResponse('GET', `/organizations/${orgId}/data-structures/1`, {
          success: true,
          data: { ...testDataStructureStats, organizationId: orgId }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-data-structure');
        await executeTool(tool, {
          dataStructureId: 1,
          organizationId: orgId
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe(`/organizations/${orgId}/data-structures/1`);
      });

      it('should get team-scoped data structure', async () => {
        const teamId = 456;
        mockApiClient.mockResponse('GET', `/teams/${teamId}/data-structures/1`, {
          success: true,
          data: { ...testDataStructureStats, teamId }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-data-structure');
        await executeTool(tool, {
          dataStructureId: 1,
          teamId
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe(`/teams/${teamId}/data-structures/1`);
      });

      it('should handle data structure not found', async () => {
        mockApiClient.mockResponse('GET', '/data-structures/999', {
          success: true,
          data: null
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-data-structure');
        
        await expect(executeTool(tool, {
          dataStructureId: 999
        }, { log: mockLog })).rejects.toThrow('Data structure not found or access denied');
      });

      it('should validate get parameters', async () => {
        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-data-structure');
        
        // Test invalid data structure ID
        expectInvalidZodParse(tool.parameters, { dataStructureId: 0 });
        
        // Test invalid organization ID
        expectInvalidZodParse(tool.parameters, { 
          dataStructureId: 1,
          organizationId: 0 
        });
        
        // Test invalid team ID
        expectInvalidZodParse(tool.parameters, { 
          dataStructureId: 1,
          teamId: 0 
        });
      });
    });
  });

  describe('Data Structure Updates', () => {
    describe('update-data-structure tool', () => {
      it('should update data structure name and description', async () => {
        const updatedStructure = {
          ...testDataStructure,
          name: 'Updated Product Schema',
          description: 'Updated schema for product validation',
          updatedAt: '2024-01-16T10:00:00Z'
        };

        mockApiClient.mockResponse('PATCH', '/data-structures/1', {
          success: true,
          data: updatedStructure
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-data-structure');
        const result = await executeTool(tool, {
          dataStructureId: 1,
          name: 'Updated Product Schema',
          description: 'Updated schema for product validation'
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        expect(result).toContain('Updated Product Schema');
        expect(result).toContain('updated successfully');
        expect(result).toContain('fieldsUpdated');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/data-structures/1');
        expect(calls[0].method).toBe('PATCH');
        expect(calls[0].data.name).toBe('Updated Product Schema');
        expect(calls[0].data.description).toBe('Updated schema for product validation');
        
        expectProgressReported(mockReportProgress, [
          { progress: 0, total: 100 },
          { progress: 30, total: 100 },
          { progress: 80, total: 100 },
          { progress: 100, total: 100 }
        ]);
      });

      it('should update structure schema and version', async () => {
        const updatedSchema = {
          type: 'object',
          properties: {
            name: { type: 'string', minLength: 2, maxLength: 150 },
            price: { type: 'number', minimum: 0.01 },
            category: { type: 'string' },
            inStock: { type: 'boolean' }
          },
          required: ['name', 'price', 'category', 'inStock']
        };

        mockApiClient.mockResponse('PATCH', '/data-structures/1', {
          success: true,
          data: {
            ...testDataStructure,
            structure: {
              ...testDataStructure.structure,
              schema: updatedSchema,
              version: '3.0.0'
            }
          }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-data-structure');
        await executeTool(tool, {
          dataStructureId: 1,
          structure: {
            schema: updatedSchema,
            version: '3.0.0',
            format: 'json'
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.structure.schema.properties.inStock).toBeDefined();
        expect(calls[0].data.structure.version).toBe('3.0.0');
        expect(calls[0].data.structure.format).toBe('json');
      });

      it('should update validation rules', async () => {
        const newValidationRules = [
          {
            field: 'name',
            type: 'required',
            message: 'Product name is mandatory'
          },
          {
            field: 'price',
            type: 'range',
            parameters: { min: 0.01, max: 50000 },
            message: 'Price must be between $0.01 and $50,000'
          },
          {
            field: 'category',
            type: 'custom',
            parameters: { allowedValues: ['electronics', 'clothing', 'books', 'home'] },
            message: 'Invalid product category'
          }
        ];

        mockApiClient.mockResponse('PATCH', '/data-structures/1', {
          success: true,
          data: {
            ...testDataStructure,
            validation: {
              enabled: true,
              strict: true,
              rules: newValidationRules
            }
          }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-data-structure');
        await executeTool(tool, {
          dataStructureId: 1,
          validation: {
            enabled: true,
            strict: true,
            rules: newValidationRules
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.validation.rules).toHaveLength(3);
        expect(calls[0].data.validation.strict).toBe(true);
      });

      it('should update transformation mappings and filters', async () => {
        const newMappings = [
          {
            source: 'item_name',
            target: 'name',
            type: 'direct'
          },
          {
            source: 'unit_price',
            target: 'price',
            type: 'computed',
            parameters: { function: 'parseFloat' }
          }
        ];

        const newFilters = [
          {
            field: 'price',
            operator: 'gte',
            value: 0.01,
            caseSensitive: false
          },
          {
            field: 'name',
            operator: 'contains',
            value: '',
            caseSensitive: false
          }
        ];

        mockApiClient.mockResponse('PATCH', '/data-structures/1', {
          success: true,
          data: {
            ...testDataStructure,
            transformation: {
              enabled: true,
              mappings: newMappings,
              filters: newFilters
            }
          }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-data-structure');
        await executeTool(tool, {
          dataStructureId: 1,
          transformation: {
            enabled: true,
            mappings: newMappings,
            filters: newFilters
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.transformation.mappings).toHaveLength(2);
        expect(calls[0].data.transformation.filters).toHaveLength(2);
        expect(calls[0].data.transformation.enabled).toBe(true);
      });

      it('should update organization-scoped data structure', async () => {
        const orgId = 789;
        mockApiClient.mockResponse('PATCH', `/organizations/${orgId}/data-structures/1`, {
          success: true,
          data: { ...testDataStructure, organizationId: orgId }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-data-structure');
        await executeTool(tool, {
          dataStructureId: 1,
          organizationId: orgId,
          name: 'Updated Org Schema'
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe(`/organizations/${orgId}/data-structures/1`);
      });

      it('should validate JSON schema in updates', async () => {
        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-data-structure');
        
        // This should work with valid JSON schema
        mockApiClient.mockResponse('PATCH', '/data-structures/1', {
          success: true,
          data: testDataStructure
        });
        
        await executeTool(tool, {
          dataStructureId: 1,
          structure: {
            schema: { type: 'object', properties: { test: { type: 'string' } } }
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        expect(mockApiClient.getCallLog()).toHaveLength(1);
      });

      it('should validate update parameters', async () => {
        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-data-structure');
        
        // Test invalid data structure ID
        expectInvalidZodParse(tool.parameters, {
          dataStructureId: 0,
          name: 'Test'
        });
        
        // Test invalid validation rule type
        expectInvalidZodParse(tool.parameters, {
          dataStructureId: 1,
          validation: {
            rules: [{
              field: 'test',
              type: 'invalid-type',
              message: 'Error'
            }]
          }
        });
        
        // Test invalid transformation filter operator
        expectInvalidZodParse(tool.parameters, {
          dataStructureId: 1,
          transformation: {
            filters: [{
              field: 'test',
              operator: 'invalid-operator',
              value: 'test'
            }]
          }
        });
      });
    });
  });

  describe('Data Structure Deletion', () => {
    describe('delete-data-structure tool', () => {
      it('should delete data structure with dependency check', async () => {
        // Mock getting the data structure first
        mockApiClient.mockResponse('GET', '/data-structures/1', {
          success: true,
          data: testDataStructure
        });

        // Mock dependency check (no dependencies)
        mockApiClient.mockResponse('GET', '/data-structures/1/dependencies', {
          success: true,
          data: { dependencies: [] }
        });

        // Mock archive creation
        const archiveResponse: DataStructureArchiveResponse = {
          archiveId: 'arch_123',
          downloadUrl: 'https://archive.example.com/arch_123.zip'
        };
        mockApiClient.mockResponse('POST', '/data-structures/1/archive', {
          success: true,
          data: archiveResponse
        });

        // Mock deletion
        mockApiClient.mockResponse('DELETE', '/data-structures/1', {
          success: true,
          data: { deleted: true }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'delete-data-structure');
        const result = await executeTool(tool, {
          dataStructureId: 1
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        expect(result).toContain('Product Schema');
        expect(result).toContain('deleted successfully');
        expect(result).toContain('archive');
        expect(result).toContain('arch_123');
        expect(result).toContain('recovery');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/data-structures/1'); // GET
        expect(calls[1].endpoint).toBe('/data-structures/1/dependencies'); // GET dependencies
        expect(calls[2].endpoint).toBe('/data-structures/1/archive'); // POST archive
        expect(calls[3].endpoint).toBe('/data-structures/1'); // DELETE
        
        expectProgressReported(mockReportProgress, [
          { progress: 0, total: 100 },
          { progress: 20, total: 100 },
          { progress: 40, total: 100 },
          { progress: 60, total: 100 },
          { progress: 100, total: 100 }
        ]);
      });

      it('should prevent deletion when dependencies exist', async () => {
        const dependencies: DataStructureDependency[] = [
          {
            type: 'scenario',
            id: 'scen_123',
            name: 'Product Import Scenario',
            usage: 'Used for data validation'
          },
          {
            type: 'template',
            id: 'tmpl_456',
            name: 'Product Template',
            usage: 'Schema reference'
          }
        ];

        // Mock getting the data structure
        mockApiClient.mockResponse('GET', '/data-structures/1', {
          success: true,
          data: testDataStructure
        });

        // Mock dependency check (has dependencies)
        mockApiClient.mockResponse('GET', '/data-structures/1/dependencies', {
          success: true,
          data: { dependencies }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'delete-data-structure');
        
        await expect(executeTool(tool, {
          dataStructureId: 1,
          checkDependencies: true,
          force: false
        }, { log: mockLog })).rejects.toThrow(/Cannot delete.*dependencies/);
      });

      it('should force delete when dependencies exist', async () => {
        const dependencies: DataStructureDependency[] = [
          {
            type: 'scenario',
            id: 'scen_123',
            name: 'Product Import Scenario',
            usage: 'Used for data validation'
          }
        ];

        // Mock getting the data structure
        mockApiClient.mockResponse('GET', '/data-structures/1', {
          success: true,
          data: testDataStructure
        });

        // Mock dependency check (has dependencies)
        mockApiClient.mockResponse('GET', '/data-structures/1/dependencies', {
          success: true,
          data: { dependencies }
        });

        // Mock deletion (forced)
        mockApiClient.mockResponse('DELETE', '/data-structures/1', {
          success: true,
          data: { deleted: true, forced: true }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'delete-data-structure');
        const result = await executeTool(tool, {
          dataStructureId: 1,
          force: true,
          archiveBeforeDelete: false
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        expect(result).toContain('deleted successfully');
        expect(result).toContain('dependencies');
        expect(result).toContain('forcedDeletion');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[2].data.force).toBe(true);
      });

      it('should delete organization-scoped data structure', async () => {
        const orgId = 456;
        
        mockApiClient.mockResponse('GET', `/organizations/${orgId}/data-structures/1`, {
          success: true,
          data: { ...testDataStructure, organizationId: orgId }
        });

        mockApiClient.mockResponse('GET', `/organizations/${orgId}/data-structures/1/dependencies`, {
          success: true,
          data: { dependencies: [] }
        });

        mockApiClient.mockResponse('DELETE', `/organizations/${orgId}/data-structures/1`, {
          success: true,
          data: { deleted: true }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'delete-data-structure');
        await executeTool(tool, {
          dataStructureId: 1,
          organizationId: orgId,
          archiveBeforeDelete: false
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe(`/organizations/${orgId}/data-structures/1`);
        expect(calls[2].endpoint).toBe(`/organizations/${orgId}/data-structures/1`);
      });

      it('should handle archive creation failure gracefully', async () => {
        // Mock getting the data structure
        mockApiClient.mockResponse('GET', '/data-structures/1', {
          success: true,
          data: testDataStructure
        });

        // Mock dependency check
        mockApiClient.mockResponse('GET', '/data-structures/1/dependencies', {
          success: true,
          data: { dependencies: [] }
        });

        // Mock archive creation failure
        mockApiClient.mockError('POST', '/data-structures/1/archive', new Error('Archive service unavailable'));

        // Mock successful deletion
        mockApiClient.mockResponse('DELETE', '/data-structures/1', {
          success: true,
          data: { deleted: true }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'delete-data-structure');
        const result = await executeTool(tool, {
          dataStructureId: 1
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        expect(result).toContain('deleted successfully');
        expect(result).toContain('"canRestore": false');
        expect(result).toContain('No archive was created');
      });

      it('should validate delete parameters', async () => {
        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'delete-data-structure');
        
        // Test invalid data structure ID
        expectInvalidZodParse(tool.parameters, { dataStructureId: 0 });
        
        // Test invalid organization ID
        expectInvalidZodParse(tool.parameters, {
          dataStructureId: 1,
          organizationId: 0
        });
        
        // Test invalid team ID
        expectInvalidZodParse(tool.parameters, {
          dataStructureId: 1,
          teamId: 0
        });
      });
    });
  });

  describe('Channel Management and Routing', () => {
    it('should handle multi-channel notification delivery validation', async () => {
      const multiChannelNotification = {
        id: 2,
        type: 'security',
        category: 'alert',
        priority: 'critical',
        title: 'Security Breach Detected',
        message: 'Unauthorized access attempt detected',
        recipients: {
          users: [1, 2, 3],
          teams: [1, 2],
          organizations: [1],
          emails: ['admin@company.com', 'security@company.com']
        },
        channels: {
          email: true,
          inApp: true,
          sms: true,
          webhook: true,
          slack: true,
          teams: false
        },
        status: 'sent',
        delivery: {
          sentAt: '2024-01-15T15:00:00Z',
          totalRecipients: 8,
          successfulDeliveries: 7,
          failedDeliveries: 1,
          errors: [{
            recipient: 'sms:+1234567890',
            channel: 'sms',
            error: 'Invalid phone number',
            timestamp: '2024-01-15T15:00:30Z'
          }]
        }
      };

      mockApiClient.mockResponse('POST', '/notifications', {
        success: true,
        data: multiChannelNotification
      });

      const { addNotificationTools } = await import('../../../src/tools/notifications.js');
      addNotificationTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-notification');
      const result = await executeTool(tool, {
        type: 'security',
        category: 'alert',
        priority: 'critical',
        title: 'Security Breach Detected',
        message: 'Unauthorized access attempt detected',
        recipients: {
          users: [1, 2, 3],
          teams: [1, 2],
          organizations: [1],
          emails: ['admin@company.com', 'security@company.com']
        },
        channels: {
          email: true,
          inApp: true,
          sms: true,
          webhook: true,
          slack: true,
          teams: false
        }
      }, { log: mockLog, reportProgress: mockReportProgress });
      
      expect(result).toContain('Security Breach Detected');
      expect(result).toContain('"priority": "critical"');
      expect(result).toContain('"totalRecipients": 8');
      expect(result).toContain('email');
      expect(result).toContain('slack');
      expect(result).toContain('webhook');
      
      const parsed = JSON.parse(result);
      expect(parsed.summary.channels).toContain('email');
      expect(parsed.summary.channels).toContain('inApp');
      expect(parsed.summary.channels).toContain('sms');
      expect(parsed.summary.channels).toContain('webhook');
      expect(parsed.summary.channels).toContain('slack');
      expect(parsed.summary.channels).not.toContain('teams');
    });
  });

  describe('Template and Personalization Testing', () => {
    it('should validate template variable substitution', async () => {
      const templateWithVariables = {
        id: 10,
        name: 'User Welcome Template',
        type: 'email',
        category: 'marketing',
        template: {
          subject: 'Welcome {{firstName}}! Your {{planType}} account is ready',
          body: `
            <h1>Welcome {{firstName}} {{lastName}}!</h1>
            <p>Thank you for signing up for our {{planType}} plan.</p>
            <p>Your account balance is {{currency}}{{balance}}</p>
            <p>Login at: {{loginUrl}}</p>
            {{#if isPremium}}
            <p>As a premium member, you get access to exclusive features!</p>
            {{/if}}
          `,
          format: 'html',
          variables: [
            { name: 'firstName', type: 'string', required: true, description: 'User first name' },
            { name: 'lastName', type: 'string', required: true, description: 'User last name' },
            { name: 'planType', type: 'string', required: true, description: 'Subscription plan' },
            { name: 'balance', type: 'number', required: true, description: 'Account balance' },
            { name: 'currency', type: 'string', required: false, defaultValue: '$', description: 'Currency symbol' },
            { name: 'loginUrl', type: 'string', required: true, description: 'Login URL' },
            { name: 'isPremium', type: 'boolean', required: false, defaultValue: false, description: 'Premium status' }
          ]
        }
      };

      mockApiClient.mockResponse('POST', '/notifications/templates', {
        success: true,
        data: templateWithVariables
      });

      const { addNotificationTools } = await import('../../../src/tools/notifications.js');
      addNotificationTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-notification-template');
      const result = await executeTool(tool, {
        name: 'User Welcome Template',
        type: 'email',
        category: 'marketing',
        template: {
          subject: 'Welcome {{firstName}}! Your {{planType}} account is ready',
          body: templateWithVariables.template.body,
          format: 'html',
          variables: templateWithVariables.template.variables
        }
      }, { log: mockLog, reportProgress: mockReportProgress });
      
      expect(result).toContain('User Welcome Template');
      expect(result).toContain('"variables": 7');
      expect(result).toContain('testUrl');
      expect(result).toContain('previewUrl');
      
      const calls = mockApiClient.getCallLog();
      expect(calls[0].data.template.variables).toHaveLength(7);
      expect(calls[0].data.template.variables.find((v: any) => v.name === 'firstName')?.required).toBe(true);
      expect(calls[0].data.template.variables.find((v: any) => v.name === 'currency')?.defaultValue).toBe('$');
    });
  });

  describe('Subscription and Preference Validation', () => {
    it('should validate complex email preference scenarios', async () => {
      const complexPreferences = {
        userId: 1,
        organizationId: 123,
        preferences: {
          system: {
            enabled: true,
            frequency: 'hourly',
            categories: {
              updates: true,
              maintenance: false,
              security: true,
              announcements: true
            }
          },
          billing: {
            enabled: true,
            categories: {
              invoices: true,
              paymentReminders: true,
              usageAlerts: true,
              planChanges: true
            }
          },
          scenarios: {
            enabled: true,
            frequency: 'immediate',
            categories: {
              failures: true,
              completions: false,
              warnings: true,
              scheduleChanges: true
            },
            filters: {
              onlyMyScenarios: false,
              onlyImportantScenarios: true,
              scenarioIds: [10, 20, 30, 40, 50],
              teamIds: [5, 8]
            }
          },
          team: {
            enabled: true,
            categories: {
              invitations: true,
              roleChanges: true,
              memberChanges: false,
              teamUpdates: true
            }
          },
          marketing: {
            enabled: true,
            categories: {
              productUpdates: true,
              newsletters: true,
              webinars: false,
              surveys: false
            }
          },
          customChannels: [
            {
              name: 'Critical Alerts Slack',
              type: 'slack',
              enabled: true,
              configuration: {
                webhook: 'https://hooks.slack.com/services/T123/B456/xyz789',
                channel: '#critical-alerts',
                username: 'AlertBot'
              },
              filters: {
                priority: ['high', 'critical'],
                types: ['system', 'security', 'scenario']
              }
            },
            {
              name: 'Teams Integration',
              type: 'teams',
              enabled: true,
              configuration: {
                webhook: 'https://outlook.office.com/webhook/abc123',
                threadId: 'thread_456'
              },
              filters: {
                businessHours: true,
                categories: ['billing', 'team']
              }
            }
          ]
        },
        timezone: 'Europe/London',
        language: 'en-GB',
        unsubscribeAll: false,
        lastUpdated: '2024-01-15T10:00:00Z'
      };

      mockApiClient.mockResponse('PUT', '/notifications/email-preferences', {
        success: true,
        data: complexPreferences
      });

      const { addNotificationTools } = await import('../../../src/tools/notifications.js');
      addNotificationTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'update-email-preferences');
      const result = await executeTool(tool, {
        preferences: complexPreferences.preferences,
        timezone: 'Europe/London',
        language: 'en-GB'
      }, { log: mockLog, reportProgress: mockReportProgress });
      
      expect(result).toContain('updated successfully');
      expect(result).toContain('Europe/London');
      expect(result).toContain('en-GB');
      
      const calls = mockApiClient.getCallLog();
      expect(calls[0].endpoint).toBe('/notifications/email-preferences');
      expect(calls[0].method).toBe('PUT');
      expect(calls[0].data.preferences).toBeDefined();
      expect(calls[0].data.timezone).toBe('Europe/London');
      expect(calls[0].data.language).toBe('en-GB');
    });
  });

  describe('Error Handling and Network Resilience', () => {
    it('should handle network timeouts gracefully', async () => {
      mockApiClient.mockError('GET', '/data-structures', new Error('Request timeout'));

      const { addNotificationTools } = await import('../../../src/tools/notifications.js');
      addNotificationTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-data-structures');
      
      await expect(executeTool(tool, {}, { log: mockLog }))
        .rejects.toThrow('Failed to list data structures: Request timeout');
    });

    it('should handle API rate limiting', async () => {
      mockApiClient.mockResponse('POST', '/data-structures', {
        success: false,
        error: { 
          message: 'Rate limit exceeded. Try again in 60 seconds.',
          code: 'RATE_LIMIT_EXCEEDED',
          retryAfter: 60
        }
      });

      const { addNotificationTools } = await import('../../../src/tools/notifications.js');
      addNotificationTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-data-structure');
      
      await expect(executeTool(tool, {
        name: 'Test Schema',
        type: 'schema',
        structure: { schema: {}, format: 'json' }
      }, { log: mockLog })).rejects.toThrow('Rate limit exceeded');
    });

    it('should handle invalid API responses', async () => {
      mockApiClient.mockResponse('GET', '/data-structures', {
        success: true,
        data: null
      });

      const { addNotificationTools } = await import('../../../src/tools/notifications.js');
      addNotificationTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-data-structures');
      
      await expect(executeTool(tool, {}, { log: mockLog }))
        .rejects.toThrow('Invalid response format');
    });
  });

  describe('Comprehensive Integration Scenarios', () => {
    it('should handle complete data structure lifecycle', async () => {
      const { addNotificationTools } = await import('../../../src/tools/notifications.js');
      addNotificationTools(mockServer, mockApiClient as any);

      // 1. Create data structure
      mockApiClient.mockResponse('POST', '/data-structures', {
        success: true,
        data: testDataStructure
      });

      const createTool = findTool(mockTool, 'create-data-structure');
      await executeTool(createTool, {
        name: 'Product Schema',
        type: 'schema',
        structure: { schema: { type: 'object' }, format: 'json' }
      }, { log: mockLog, reportProgress: mockReportProgress });

      // 2. Get the created structure
      mockApiClient.mockResponse('GET', '/data-structures/1', {
        success: true,
        data: testDataStructureStats
      });

      const getTool = findTool(mockTool, 'get-data-structure');
      await executeTool(getTool, { dataStructureId: 1 }, { log: mockLog, reportProgress: mockReportProgress });

      // 3. Update the structure
      mockApiClient.mockResponse('PATCH', '/data-structures/1', {
        success: true,
        data: { ...testDataStructure, name: 'Updated Product Schema' }
      });

      const updateTool = findTool(mockTool, 'update-data-structure');
      await executeTool(updateTool, {
        dataStructureId: 1,
        name: 'Updated Product Schema'
      }, { log: mockLog, reportProgress: mockReportProgress });

      // 4. List structures to verify update
      mockApiClient.mockResponse('GET', '/data-structures', {
        success: true,
        data: {
          dataStructures: [{ ...testDataStructure, name: 'Updated Product Schema' }],
          pagination: { total: 1, offset: 0, limit: 20, hasMore: false },
          filters: { type: 'all', scope: 'all', format: 'all' }
        }
      });

      const listTool = findTool(mockTool, 'list-data-structures');
      await executeTool(listTool, {}, { log: mockLog });

      expect(mockApiClient.getCallLog()).toHaveLength(4);
      expect(mockApiClient.getCallLog()[0].method).toBe('POST');
      expect(mockApiClient.getCallLog()[1].method).toBe('GET');
      expect(mockApiClient.getCallLog()[2].method).toBe('PATCH');
      expect(mockApiClient.getCallLog()[3].method).toBe('GET');
    });
  });

  describe('Comprehensive Notification Management Tests', () => {
    // Test data for notification tools
    const testNotification = {
      id: 1,
      type: 'system',
      category: 'info',
      priority: 'medium',
      title: 'Test Notification',
      message: 'This is a test notification',
      data: { userId: 123 },
      recipients: {
        users: [1, 2, 3],
        teams: [1],
        organizations: [1],
        emails: ['test@example.com']
      },
      channels: {
        email: true,
        inApp: true,
        sms: false,
        webhook: false,
        slack: false,
        teams: false
      },
      status: 'sent',
      delivery: {
        sentAt: '2024-01-15T10:00:00Z',
        deliveredAt: '2024-01-15T10:00:30Z',
        totalRecipients: 5,
        successfulDeliveries: 5,
        failedDeliveries: 0,
        errors: []
      },
      schedule: {},
      template: {
        id: 1,
        variables: {}
      },
      tracking: {
        opens: 0,
        clicks: 0,
        unsubscribes: 0,
        complaints: 0
      },
      createdAt: '2024-01-15T10:00:00Z',
      updatedAt: '2024-01-15T10:00:00Z',
      createdBy: 1,
      createdByName: 'Test User'
    };

    const testEmailPreferences = {
      userId: 1,
      organizationId: 123,
      preferences: {
        system: {
          enabled: true,
          frequency: 'immediate',
          categories: {
            updates: true,
            maintenance: true,
            security: true,
            announcements: false
          }
        },
        billing: {
          enabled: true,
          categories: {
            invoices: true,
            paymentReminders: true,
            usageAlerts: true,
            planChanges: true
          }
        },
        scenarios: {
          enabled: true,
          frequency: 'hourly',
          categories: {
            failures: true,
            completions: false,
            warnings: true,
            scheduleChanges: true
          },
          filters: {
            onlyMyScenarios: false,
            onlyImportantScenarios: true,
            scenarioIds: [10, 20],
            teamIds: [5]
          }
        },
        team: {
          enabled: true,
          categories: {
            invitations: true,
            roleChanges: true,
            memberChanges: false,
            teamUpdates: true
          }
        },
        marketing: {
          enabled: false,
          categories: {
            productUpdates: false,
            newsletters: false,
            webinars: false,
            surveys: false
          }
        },
        customChannels: []
      },
      timezone: 'America/New_York',
      language: 'en-US',
      unsubscribeAll: false,
      lastUpdated: '2024-01-15T10:00:00Z'
    };

    const testNotificationTemplate = {
      id: 1,
      name: 'System Alert Template',
      description: 'Template for system alerts',
      type: 'email',
      category: 'system',
      organizationId: 123,
      isGlobal: false,
      template: {
        subject: 'System Alert: {{alertType}}',
        body: '<h1>{{alertType}}</h1><p>{{alertMessage}}</p>',
        format: 'html',
        variables: [
          {
            name: 'alertType',
            type: 'string',
            required: true,
            description: 'Type of alert'
          },
          {
            name: 'alertMessage',
            type: 'string',
            required: true,
            description: 'Alert message content'
          }
        ]
      },
      design: {
        theme: 'default',
        colors: { primary: '#007bff', secondary: '#6c757d' },
        fonts: { body: 'Arial, sans-serif' },
        layout: 'single-column'
      },
      testing: {
        lastTested: '2024-01-15T09:00:00Z',
        testResults: {
          renderingTime: 250,
          size: 1024,
          errors: [],
          warnings: []
        }
      },
      usage: {
        totalSent: 150,
        lastUsed: '2024-01-15T08:00:00Z',
        averageDeliveryTime: 2.5,
        deliveryRate: 98.7
      },
      createdAt: '2024-01-01T10:00:00Z',
      updatedAt: '2024-01-15T10:00:00Z',
      createdBy: 1
    };

    describe('create-notification tool', () => {
      it('should create notification with basic configuration', async () => {
        mockApiClient.mockResponse('POST', '/notifications', {
          success: true,
          data: testNotification
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-notification');
        const result = await executeTool(tool, {
          type: 'system',
          category: 'info',
          priority: 'medium',
          title: 'Test Notification',
          message: 'This is a test notification',
          recipients: {
            users: [1, 2, 3],
            teams: [1],
            organizations: [1],
            emails: ['test@example.com']
          },
          channels: {
            email: true,
            inApp: true
          }
        }, { log: mockLog, reportProgress: mockReportProgress });

        expect(result).toContain('Test Notification');
        expect(result).toContain('"status": "sent"');
        expect(result).toContain('"totalRecipients": 5');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/notifications');
        expect(calls[0].method).toBe('POST');
        expect(calls[0].data.type).toBe('system');
        expect(calls[0].data.title).toBe('Test Notification');

        expectProgressReported(mockReportProgress, [
          { progress: 0, total: 100 },
          { progress: 50, total: 100 },
          { progress: 100, total: 100 }
        ]);
      });

      it('should create notification with scheduling', async () => {
        const scheduledNotification = {
          ...testNotification,
          status: 'scheduled',
          schedule: {
            sendAt: '2024-01-16T10:00:00Z',
            timezone: 'UTC'
          }
        };

        mockApiClient.mockResponse('POST', '/notifications', {
          success: true,
          data: scheduledNotification
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-notification');
        await executeTool(tool, {
          type: 'marketing',
          category: 'reminder',
          priority: 'low',
          title: 'Scheduled Marketing Email',
          message: 'Don\'t forget about our sale!',
          recipients: {
            users: [1, 2, 3]
          },
          channels: {
            email: true
          },
          schedule: {
            sendAt: '2024-01-16T10:00:00Z',
            timezone: 'UTC'
          }
        }, { log: mockLog, reportProgress: mockReportProgress });

        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.schedule.sendAt).toBe('2024-01-16T10:00:00Z');
        expect(calls[0].data.status).toBe('scheduled');
      });

      it('should create notification with template variables', async () => {
        const templateNotification = {
          ...testNotification,
          template: {
            id: 5,
            variables: {
              userName: 'John Doe',
              planType: 'Premium',
              expiryDate: '2024-02-15'
            }
          }
        };

        mockApiClient.mockResponse('POST', '/notifications', {
          success: true,
          data: templateNotification
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-notification');
        await executeTool(tool, {
          type: 'billing',
          category: 'reminder',
          title: 'Subscription Expiry Reminder',
          message: 'Your subscription will expire soon',
          recipients: {
            users: [123]
          },
          channels: {
            email: true,
            inApp: true
          },
          templateId: 5,
          templateVariables: {
            userName: 'John Doe',
            planType: 'Premium',
            expiryDate: '2024-02-15'
          }
        }, { log: mockLog });

        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.template.id).toBe(5);
        expect(calls[0].data.template.variables.userName).toBe('John Doe');
      });

      it('should validate notification parameters', async () => {
        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-notification');
        
        // Test invalid type
        expectInvalidZodParse(tool.parameters, {
          type: 'invalid-type',
          category: 'info',
          title: 'Test',
          message: 'Test message',
          recipients: { users: [1] },
          channels: { email: true }
        });
        
        // Test invalid category
        expectInvalidZodParse(tool.parameters, {
          type: 'system',
          category: 'invalid-category',
          title: 'Test',
          message: 'Test message',
          recipients: { users: [1] },
          channels: { email: true }
        });
        
        // Test empty title
        expectInvalidZodParse(tool.parameters, {
          type: 'system',
          category: 'info',
          title: '',
          message: 'Test message',
          recipients: { users: [1] },
          channels: { email: true }
        });
        
        // Test invalid email in recipients
        expectInvalidZodParse(tool.parameters, {
          type: 'system',
          category: 'info',
          title: 'Test',
          message: 'Test message',
          recipients: { emails: ['invalid-email'] },
          channels: { email: true }
        });
      });

      it('should handle notification creation errors', async () => {
        mockApiClient.mockResponse('POST', '/notifications', {
          success: false,
          error: { message: 'Invalid recipient configuration' }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-notification');
        
        await expect(executeTool(tool, {
          type: 'system',
          category: 'info',
          title: 'Test Notification',
          message: 'Test message',
          recipients: { users: [1] },
          channels: { email: true }
        }, { log: mockLog })).rejects.toThrow('Invalid recipient configuration');
      });

      it('should require at least one recipient', async () => {
        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-notification');
        
        await expect(executeTool(tool, {
          type: 'system',
          category: 'info',
          title: 'Test Notification',
          message: 'Test message',
          recipients: {
            users: [],
            teams: [],
            organizations: [],
            emails: []
          },
          channels: { email: true }
        }, { log: mockLog })).rejects.toThrow('At least one recipient must be specified');
      });

      it('should require at least one enabled channel', async () => {
        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-notification');
        
        await expect(executeTool(tool, {
          type: 'system',
          category: 'info',
          title: 'Test Notification',
          message: 'Test message',
          recipients: { users: [1] },
          channels: {
            email: false,
            inApp: false,
            sms: false,
            webhook: false,
            slack: false,
            teams: false
          }
        }, { log: mockLog })).rejects.toThrow('At least one delivery channel must be enabled');
      });
    });

    describe('get-email-preferences tool', () => {
      it('should get current user email preferences', async () => {
        mockApiClient.mockResponse('GET', '/notifications/email-preferences', {
          success: true,
          data: testEmailPreferences
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-email-preferences');
        const result = await executeTool(tool, {}, { log: mockLog });

        expect(result).toContain('"userId": 1');
        expect(result).toContain('"organizationId": 123');
        expect(result).toContain('America/New_York');
        expect(result).toContain('en-US');
        
        const parsed = JSON.parse(result);
        expect(parsed.summary.categories.system).toBe(true);
        expect(parsed.summary.categories.marketing).toBe(false);
        expect(parsed.settings.systemFrequency).toBe('immediate');

        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/notifications/email-preferences');
        expect(calls[0].method).toBe('GET');
      });

      it('should get specific user email preferences', async () => {
        const userId = 456;
        mockApiClient.mockResponse('GET', `/users/${userId}/email-preferences`, {
          success: true,
          data: { ...testEmailPreferences, userId }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-email-preferences');
        await executeTool(tool, { userId }, { log: mockLog });

        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe(`/users/${userId}/email-preferences`);
      });

      it('should get email preferences with statistics', async () => {
        mockApiClient.mockResponse('GET', '/notifications/email-preferences', {
          success: true,
          data: testEmailPreferences
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-email-preferences');
        await executeTool(tool, { includeStats: true }, { log: mockLog });

        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.includeStats).toBe(true);
      });

      it('should validate get email preferences parameters', async () => {
        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-email-preferences');
        
        // Test valid parameters
        expectValidZodParse(tool.parameters, {});
        expectValidZodParse(tool.parameters, { userId: 1 });
        expectValidZodParse(tool.parameters, { includeStats: true });
        
        // Test invalid userId
        expectInvalidZodParse(tool.parameters, { userId: 0 });
        expectInvalidZodParse(tool.parameters, { userId: -1 });
      });

      it('should handle email preferences not found error', async () => {
        mockApiClient.mockResponse('GET', '/notifications/email-preferences', {
          success: false,
          error: { message: 'User preferences not found' }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-email-preferences');
        
        await expect(executeTool(tool, {}, { log: mockLog }))
          .rejects.toThrow('User preferences not found');
      });
    });

    describe('create-notification-template tool', () => {
      it('should create basic email template', async () => {
        mockApiClient.mockResponse('POST', '/notifications/templates', {
          success: true,
          data: testNotificationTemplate
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-notification-template');
        const result = await executeTool(tool, {
          name: 'System Alert Template',
          type: 'email',
          category: 'system',
          template: {
            subject: 'System Alert: {{alertType}}',
            body: '<h1>{{alertType}}</h1><p>{{alertMessage}}</p>',
            format: 'html',
            variables: [
              {
                name: 'alertType',
                type: 'string',
                required: true,
                description: 'Type of alert'
              },
              {
                name: 'alertMessage',
                type: 'string',
                required: true,
                description: 'Alert message content'
              }
            ]
          }
        }, { log: mockLog, reportProgress: mockReportProgress });

        expect(result).toContain('System Alert Template');
        expect(result).toContain('"variables": 2');
        expect(result).toContain('testUrl');
        expect(result).toContain('previewUrl');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/notifications/templates');
        expect(calls[0].method).toBe('POST');
        expect(calls[0].data.name).toBe('System Alert Template');
        expect(calls[0].data.template.variables).toHaveLength(2);

        expectProgressReported(mockReportProgress, [
          { progress: 0, total: 100 },
          { progress: 50, total: 100 },
          { progress: 100, total: 100 }
        ]);
      });

      it('should create organization-scoped template', async () => {
        const orgTemplate = {
          ...testNotificationTemplate,
          organizationId: 456,
          isGlobal: false
        };

        mockApiClient.mockResponse('POST', '/organizations/456/notifications/templates', {
          success: true,
          data: orgTemplate
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-notification-template');
        await executeTool(tool, {
          name: 'Org Template',
          type: 'email',
          category: 'team',
          organizationId: 456,
          template: {
            body: 'Test template body'
          }
        }, { log: mockLog, reportProgress: mockReportProgress });

        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/organizations/456/notifications/templates');
        expect(calls[0].data.organizationId).toBe(456);
        expect(calls[0].data.isGlobal).toBe(false);
      });

      it('should create template with design configuration', async () => {
        const designTemplate = {
          ...testNotificationTemplate,
          design: {
            theme: 'modern',
            colors: { primary: '#ff0000', secondary: '#00ff00' },
            fonts: { heading: 'Roboto, sans-serif', body: 'Open Sans, sans-serif' },
            layout: 'two-column',
            customCss: '.custom { color: blue; }'
          }
        };

        mockApiClient.mockResponse('POST', '/notifications/templates', {
          success: true,
          data: designTemplate
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-notification-template');
        await executeTool(tool, {
          name: 'Styled Template',
          type: 'email',
          category: 'marketing',
          template: {
            body: 'Styled template body'
          },
          design: {
            theme: 'modern',
            colors: { primary: '#ff0000', secondary: '#00ff00' },
            fonts: { heading: 'Roboto, sans-serif', body: 'Open Sans, sans-serif' },
            layout: 'two-column',
            customCss: '.custom { color: blue; }'
          }
        }, { log: mockLog, reportProgress: mockReportProgress });

        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.design.theme).toBe('modern');
        expect(calls[0].data.design.colors.primary).toBe('#ff0000');
        expect(calls[0].data.design.customCss).toBe('.custom { color: blue; }');
      });

      it('should validate template parameters', async () => {
        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-notification-template');
        
        // Test valid template
        expectValidZodParse(tool.parameters, {
          name: 'Test Template',
          type: 'email',
          category: 'system',
          template: {
            body: 'Template body'
          }
        });
        
        // Test invalid name (empty)
        expectInvalidZodParse(tool.parameters, {
          name: '',
          type: 'email',
          category: 'system',
          template: { body: 'Body' }
        });
        
        // Test invalid type
        expectInvalidZodParse(tool.parameters, {
          name: 'Test Template',
          type: 'invalid-type',
          category: 'system',
          template: { body: 'Body' }
        });
        
        // Test invalid category
        expectInvalidZodParse(tool.parameters, {
          name: 'Test Template',
          type: 'email',
          category: 'invalid-category',
          template: { body: 'Body' }
        });
        
        // Test missing body
        expectInvalidZodParse(tool.parameters, {
          name: 'Test Template',
          type: 'email',
          category: 'system',
          template: {}
        });
      });

      it('should handle template creation errors', async () => {
        mockApiClient.mockResponse('POST', '/notifications/templates', {
          success: false,
          error: { message: 'Template name already exists' }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-notification-template');
        
        await expect(executeTool(tool, {
          name: 'Duplicate Template',
          type: 'email',
          category: 'system',
          template: {
            body: 'Template body'
          }
        }, { log: mockLog })).rejects.toThrow('Template name already exists');
      });
    });

    describe('list-notifications tool', () => {
      const testNotificationsList = [
        testNotification,
        {
          ...testNotification,
          id: 2,
          type: 'billing',
          category: 'warning',
          priority: 'high',
          title: 'Payment Failed',
          status: 'delivered'
        },
        {
          ...testNotification,
          id: 3,
          type: 'security',
          category: 'alert',
          priority: 'critical',
          title: 'Security Alert',
          status: 'failed'
        }
      ];

      it('should list notifications with default parameters', async () => {
        mockApiClient.mockResponse('GET', '/notifications', {
          success: true,
          data: testNotificationsList,
          metadata: { total: 3 }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-notifications');
        const result = await executeTool(tool, {}, { log: mockLog });

        expect(result).toContain('"total": 3');
        expect(result).toContain('analytics');
        expect(result).toContain('typeBreakdown');
        expect(result).toContain('statusBreakdown');
        expect(result).toContain('priorityBreakdown');
        
        const parsed = JSON.parse(result);
        expect(parsed.notifications).toHaveLength(3);
        expect(parsed.analytics.totalNotifications).toBe(3);
        expect(parsed.analytics.typeBreakdown).toHaveProperty('system');
        expect(parsed.analytics.typeBreakdown).toHaveProperty('billing');
        expect(parsed.analytics.typeBreakdown).toHaveProperty('security');

        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/notifications');
        expect(calls[0].method).toBe('GET');
        expect(calls[0].data.limit).toBe(20);
        expect(calls[0].data.offset).toBe(0);
      });

      it('should list notifications with filtering', async () => {
        const filteredNotifications = [testNotificationsList[2]]; // Only security alerts

        mockApiClient.mockResponse('GET', '/notifications', {
          success: true,
          data: filteredNotifications,
          metadata: { total: 1 }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-notifications');
        await executeTool(tool, {
          type: 'security',
          priority: 'critical',
          status: 'failed',
          dateRange: {
            startDate: '2024-01-01',
            endDate: '2024-01-31'
          },
          limit: 10,
          sortBy: 'priority',
          sortOrder: 'desc'
        }, { log: mockLog });

        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.type).toBe('security');
        expect(calls[0].data.priority).toBe('critical');
        expect(calls[0].data.status).toBe('failed');
        expect(calls[0].data.startDate).toBe('2024-01-01');
        expect(calls[0].data.endDate).toBe('2024-01-31');
        expect(calls[0].data.limit).toBe(10);
        expect(calls[0].data.sortBy).toBe('priority');
        expect(calls[0].data.sortOrder).toBe('desc');
      });

      it('should list notifications with delivery analytics', async () => {
        const notificationsWithDelivery = testNotificationsList.map(n => ({
          ...n,
          delivery: {
            ...n.delivery,
            totalRecipients: 10,
            successfulDeliveries: 8,
            failedDeliveries: 2
          }
        }));

        mockApiClient.mockResponse('GET', '/notifications', {
          success: true,
          data: notificationsWithDelivery,
          metadata: { total: 3 }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-notifications');
        const result = await executeTool(tool, {
          includeDelivery: true,
          includeTracking: true
        }, { log: mockLog });

        const parsed = JSON.parse(result);
        expect(parsed.analytics.deliveryAnalytics).toBeDefined();
        expect(parsed.analytics.deliveryAnalytics.totalRecipients).toBe(30);
        expect(parsed.analytics.deliveryAnalytics.successfulDeliveries).toBe(24);
        expect(parsed.analytics.deliveryAnalytics.failedDeliveries).toBe(6);
        expect(parsed.analytics.deliveryAnalytics.averageDeliveryRate).toBeCloseTo(80);

        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.includeDelivery).toBe(true);
        expect(calls[0].data.includeTracking).toBe(true);
      });

      it('should validate list notifications parameters', async () => {
        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-notifications');
        
        // Test valid parameters
        expectValidZodParse(tool.parameters, {});
        expectValidZodParse(tool.parameters, { type: 'system', limit: 50 });
        expectValidZodParse(tool.parameters, {
          dateRange: {
            startDate: '2024-01-01',
            endDate: '2024-01-31'
          }
        });
        
        // Test invalid type
        expectInvalidZodParse(tool.parameters, { type: 'invalid-type' });
        
        // Test invalid status
        expectInvalidZodParse(tool.parameters, { status: 'invalid-status' });
        
        // Test invalid priority
        expectInvalidZodParse(tool.parameters, { priority: 'invalid-priority' });
        
        // Test invalid limit
        expectInvalidZodParse(tool.parameters, { limit: 0 });
        expectInvalidZodParse(tool.parameters, { limit: 101 });
        
        // Test invalid offset
        expectInvalidZodParse(tool.parameters, { offset: -1 });
        
        // Test invalid sortBy
        expectInvalidZodParse(tool.parameters, { sortBy: 'invalid-field' });
      });

      it('should handle empty notification list', async () => {
        mockApiClient.mockResponse('GET', '/notifications', {
          success: true,
          data: [],
          metadata: { total: 0 }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-notifications');
        const result = await executeTool(tool, {}, { log: mockLog });

        const parsed = JSON.parse(result);
        expect(parsed.notifications).toHaveLength(0);
        expect(parsed.analytics.totalNotifications).toBe(0);
        expect(parsed.pagination.total).toBe(0);
      });

      it('should handle list notifications API errors', async () => {
        mockApiClient.mockResponse('GET', '/notifications', {
          success: false,
          error: { message: 'Access denied' }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-notifications');
        
        await expect(executeTool(tool, {}, { log: mockLog }))
          .rejects.toThrow('Access denied');
      });
    });

    describe('update-email-preferences tool', () => {
      it('should update email preferences with comprehensive settings', async () => {
        const updatedPreferences = {
          ...testEmailPreferences,
          preferences: {
            ...testEmailPreferences.preferences,
            system: {
              enabled: false,
              frequency: 'daily',
              categories: {
                updates: false,
                maintenance: true,
                security: true,
                announcements: true
              }
            },
            marketing: {
              enabled: true,
              categories: {
                productUpdates: true,
                newsletters: true,
                webinars: false,
                surveys: false
              }
            }
          },
          timezone: 'Europe/London',
          language: 'en-GB',
          lastUpdated: '2024-01-16T10:00:00Z'
        };

        mockApiClient.mockResponse('PUT', '/notifications/email-preferences', {
          success: true,
          data: updatedPreferences
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-email-preferences');
        const result = await executeTool(tool, {
          preferences: {
            system: {
              enabled: false,
              frequency: 'daily',
              categories: {
                updates: false,
                maintenance: true,
                security: true,
                announcements: true
              }
            },
            marketing: {
              enabled: true,
              categories: {
                productUpdates: true,
                newsletters: true,
                webinars: false,
                surveys: false
              }
            }
          },
          timezone: 'Europe/London',
          language: 'en-GB'
        }, { log: mockLog, reportProgress: mockReportProgress });

        expect(result).toContain('Email preferences updated successfully');
        expect(result).toContain('Europe/London');
        expect(result).toContain('en-GB');
        
        const parsed = JSON.parse(result);
        expect(parsed.changes.preferences).toBe(true);
        expect(parsed.changes.timezone).toBe(true);
        expect(parsed.changes.language).toBe(true);
        expect(parsed.summary.enabledCategories).toContain('billing');
        expect(parsed.summary.enabledCategories).toContain('scenarios');
        expect(parsed.summary.enabledCategories).toContain('marketing');

        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/notifications/email-preferences');
        expect(calls[0].method).toBe('PUT');
        expect(calls[0].data.preferences.system.enabled).toBe(false);
        expect(calls[0].data.preferences.marketing.enabled).toBe(true);
        expect(calls[0].data.timezone).toBe('Europe/London');

        expectProgressReported(mockReportProgress, [
          { progress: 0, total: 100 },
          { progress: 50, total: 100 },
          { progress: 100, total: 100 }
        ]);
      });

      it('should update specific user email preferences', async () => {
        const userId = 789;
        const updatedPreferences = {
          ...testEmailPreferences,
          userId,
          unsubscribeAll: true
        };

        mockApiClient.mockResponse('PUT', `/users/${userId}/email-preferences`, {
          success: true,
          data: updatedPreferences
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-email-preferences');
        await executeTool(tool, {
          userId,
          unsubscribeAll: true
        }, { log: mockLog, reportProgress: mockReportProgress });

        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe(`/users/${userId}/email-preferences`);
        expect(calls[0].data.unsubscribeAll).toBe(true);
      });

      it('should update custom channels configuration', async () => {
        const customChannelsConfig = {
          ...testEmailPreferences,
          preferences: {
            ...testEmailPreferences.preferences,
            customChannels: [
              {
                name: 'Development Alerts',
                type: 'slack',
                enabled: true,
                configuration: {
                  webhook: 'https://hooks.slack.com/services/T123/B456/xyz789',
                  channel: '#dev-alerts'
                },
                filters: {
                  priority: ['high', 'critical'],
                  types: ['system', 'security']
                }
              },
              {
                name: 'Management Reports',
                type: 'webhook',
                enabled: true,
                configuration: {
                  url: 'https://api.company.com/notifications',
                  headers: { 'Authorization': 'Bearer token123' }
                },
                filters: {
                  categories: ['billing', 'team']
                }
              }
            ]
          }
        };

        mockApiClient.mockResponse('PUT', '/notifications/email-preferences', {
          success: true,
          data: customChannelsConfig
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-email-preferences');
        const result = await executeTool(tool, {
          preferences: {
            customChannels: customChannelsConfig.preferences.customChannels
          }
        }, { log: mockLog, reportProgress: mockReportProgress });

        expect(result).toContain('Email preferences updated successfully');
        
        const calls = mockApiClient.getCallLog();
        expect(calls).toHaveLength(1);
        expect(calls[0].endpoint).toBe('/notifications/email-preferences');
        expect(calls[0].method).toBe('PUT');
        expect(calls[0].data).toBeDefined();
        expect(calls[0].data.preferences).toBeDefined();
      });

      it('should validate update email preferences parameters', async () => {
        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-email-preferences');
        
        // Test valid parameters
        expectValidZodParse(tool.parameters, {
          preferences: {
            system: {
              enabled: true,
              frequency: 'immediate'
            }
          }
        });
        
        expectValidZodParse(tool.parameters, {
          userId: 1,
          timezone: 'UTC',
          language: 'en-US',
          unsubscribeAll: false
        });
        
        // Test invalid userId
        expectInvalidZodParse(tool.parameters, { userId: 0 });
        expectInvalidZodParse(tool.parameters, { userId: -1 });
        
        // Test invalid frequency
        expectInvalidZodParse(tool.parameters, {
          preferences: {
            system: {
              frequency: 'invalid-frequency'
            }
          }
        });
      });

      it('should handle update email preferences errors', async () => {
        mockApiClient.mockResponse('PUT', '/notifications/email-preferences', {
          success: false,
          error: { message: 'Invalid preference configuration' }
        });

        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-email-preferences');
        
        await expect(executeTool(tool, {
          preferences: {
            system: {
              enabled: false
            }
          }
        }, { log: mockLog })).rejects.toThrow('Invalid preference configuration');
      });

      it('should require at least one update parameter', async () => {
        const { addNotificationTools } = await import('../../../src/tools/notifications.js');
        addNotificationTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-email-preferences');
        
        await expect(executeTool(tool, {}, { log: mockLog }))
          .rejects.toThrow('At least one field must be provided for update');
      });
    });
  });
});