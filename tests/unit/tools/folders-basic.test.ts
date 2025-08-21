/**
 * Basic Test Suite for Folder Organization Tools
 * Tests core functionality of folder management, data stores, and data structures tools
 * Focuses on tool registration, configuration validation, and basic execution patterns
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { UserError } from 'fastmcp';
import { createMockServer, findTool, executeTool, expectValidZodParse, expectInvalidZodParse } from '../../utils/test-helpers.js';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';
import { testErrors } from '../../fixtures/test-data.js';

// Type imports for testing
import type { 
  MakeFolder, 
  MakeDataStore, 
  MakeDataStructure 
} from '../../../src/tools/folders.js';

describe('Folder Organization Tools - Basic Tests', () => {
  let mockServer: any;
  let mockTool: jest.MockedFunction<any>;
  let mockApiClient: MockMakeApiClient;

  // Mock folder hierarchy for testing
  const testFolder: MakeFolder = {
    id: 5001,
    name: 'CRM Integration Templates',
    description: 'Collection of templates for CRM system integrations',
    parentId: null,
    path: '/crm-integration-templates',
    organizationId: 1001,
    teamId: 2001,
    type: 'template',
    permissions: {
      read: ['user_12345', 'team_2001'],
      write: ['user_12345', 'user_67890'],
      admin: ['user_12345'],
    },
    itemCount: {
      templates: 15,
      scenarios: 8,
      connections: 5,
      subfolders: 3,
      total: 31,
    },
    metadata: {
      size: 2048576, // 2MB in bytes
      lastActivity: '2024-01-20T10:30:00Z',
      mostActiveItem: {
        type: 'template',
        id: 12345,
        name: 'Salesforce Lead Sync',
        activity: 25,
      },
    },
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-15T00:00:00Z',
    createdBy: 12345,
    createdByName: 'Organization Admin',
  };

  // Mock data store for testing
  const testDataStore: MakeDataStore = {
    id: 8001,
    name: 'Customer Records',
    description: 'Structured storage for customer information and preferences',
    type: 'data_structure',
    organizationId: 1001,
    teamId: 2001,
    structure: {
      fields: [
        {
          name: 'customerId',
          type: 'string',
          required: true,
          validation: {
            min: 1,
            max: 50,
            pattern: '^CUST[0-9]{6}$',
          },
        },
        {
          name: 'email',
          type: 'string',
          required: true,
          validation: {
            pattern: '^[^@]+@[^@]+\\.[^@]+$',
          },
        },
        {
          name: 'firstName',
          type: 'string',
          required: true,
          validation: {
            min: 1,
            max: 100,
          },
        },
      ],
      indexes: [
        {
          fields: ['customerId'],
          unique: true,
          name: 'idx_customer_id',
        },
        {
          fields: ['email'],
          unique: true,
          name: 'idx_customer_email',
        },
      ],
    },
    settings: {
      maxSize: 500, // 500MB
      autoCleanup: true,
      encryption: true,
      compression: false,
    },
    usage: {
      recordCount: 15432,
      sizeUsed: 125829120, // ~120MB in bytes
      operationsToday: 1250,
      lastOperation: '2024-01-20T10:00:00Z',
    },
    permissions: {
      read: ['user_12345', 'team_2001'],
      write: ['user_12345', 'user_67890'],
      admin: ['user_12345'],
    },
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-15T00:00:00Z',
    createdBy: 12345,
  };

  // Mock data structure for testing
  const testDataStructure: MakeDataStructure = {
    id: 9001,
    name: 'Product Catalog Structure',
    description: 'Data structure for product information management',
    organizationId: 1001,
    teamId: 2001,
    specification: [
      {
        name: 'productId',
        type: 'text',
        required: true,
        constraints: {
          minLength: 5,
          maxLength: 20,
          pattern: '^PROD[0-9]+$',
        },
      },
      {
        name: 'name',
        type: 'text',
        required: true,
        constraints: {
          minLength: 1,
          maxLength: 255,
        },
      },
      {
        name: 'price',
        type: 'number',
        required: true,
        constraints: {
          minimum: 0,
          maximum: 10000,
        },
      },
      {
        name: 'tags',
        type: 'array',
        required: false,
        spec: [
          {
            name: 'tag',
            type: 'text',
            required: true,
            constraints: {
              maxLength: 50,
            },
          },
        ],
      },
    ],
    strict: true,
    usage: {
      dataStoresCount: 3,
      totalRecords: 25000,
      lastUsed: '2024-01-20T09:00:00Z',
    },
    validation: {
      enabled: true,
      rules: ['required_fields', 'data_types', 'constraints'],
      lastValidation: '2024-01-20T08:00:00Z',
      validationErrors: 0,
    },
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-10T00:00:00Z',
    createdBy: 12345,
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
    it('should successfully import and register folder tools', async () => {
      const { addFolderTools } = await import('../../../src/tools/folders.js');
      
      // Should not throw an error
      expect(() => {
        addFolderTools(mockServer, mockApiClient as any);
      }).not.toThrow();
      
      // Should call addTool for each folder tool
      expect(mockTool).toHaveBeenCalled();
      expect(mockTool.mock.calls.length).toBeGreaterThan(0);
    });

    it('should export the expected folder tools and types', async () => {
      const foldersModule = await import('../../../src/tools/folders.js');
      
      // Check that expected exports exist
      expect(foldersModule.addFolderTools).toBeDefined();
      expect(typeof foldersModule.addFolderTools).toBe('function');
      expect(foldersModule.default).toBeDefined();
      expect(typeof foldersModule.default).toBe('function');
      
      // Note: TypeScript interfaces are not available at runtime, so we can't test for them
      // This is expected behavior - interfaces exist only during compilation
    });

    it('should register all core folder management tools', async () => {
      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const expectedTools = [
        'create-folder',
        'list-folders',
        'get-folder-contents',
        'move-items',
        'create-data-store',
        'list-data-stores',
        'list-data-structures',
        'get-data-structure',
        'create-data-structure',
        'update-data-structure',
        'delete-data-structure',
        'get-data-store',
        'update-data-store',
        'delete-data-store'
      ];
      
      expectedTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool).toBeDefined();
        expect(tool.name).toBe(toolName);
      });
    });
  });

  describe('Tool Configuration Validation', () => {
    it('should have correct structure for create-folder tool', async () => {
      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-folder');
      
      expect(tool.name).toBe('create-folder');
      expect(tool.description).toContain('Create a new folder');
      expect(tool.parameters).toBeDefined();
      expect(typeof tool.execute).toBe('function');
      expect(tool.annotations).toBeDefined();
      expect(tool.annotations.title).toBe('Create Folder');
      expect(tool.annotations.idempotentHint).toBe(true);
    });

    it('should have correct structure for folder listing and content tools', async () => {
      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const listTool = findTool(mockTool, 'list-folders');
      expect(listTool.name).toBe('list-folders');
      expect(listTool.description).toContain('List and filter folders');
      expect(listTool.annotations.readOnlyHint).toBe(true);

      const contentsTool = findTool(mockTool, 'get-folder-contents');
      expect(contentsTool.name).toBe('get-folder-contents');
      expect(contentsTool.description).toContain('detailed contents');
      expect(contentsTool.annotations.readOnlyHint).toBe(true);

      const moveTool = findTool(mockTool, 'move-items');
      expect(moveTool.name).toBe('move-items');
      expect(moveTool.description).toContain('Move or copy items');
    });

    it('should have correct structure for data store management tools', async () => {
      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const createDataStoreTool = findTool(mockTool, 'create-data-store');
      expect(createDataStoreTool.name).toBe('create-data-store');
      expect(createDataStoreTool.description).toContain('Create a new data store');

      const listDataStoresTool = findTool(mockTool, 'list-data-stores');
      expect(listDataStoresTool.name).toBe('list-data-stores');
      expect(listDataStoresTool.description).toContain('List and filter data stores');

      const getDataStoreTool = findTool(mockTool, 'get-data-store');
      expect(getDataStoreTool.name).toBe('get-data-store');
      expect(getDataStoreTool.description).toContain('Get detailed information');
    });

    it('should have correct structure for data structure lifecycle tools', async () => {
      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const createStructureTool = findTool(mockTool, 'create-data-structure');
      expect(createStructureTool.name).toBe('create-data-structure');
      expect(createStructureTool.description).toContain('Create a new data structure');

      const updateStructureTool = findTool(mockTool, 'update-data-structure');
      expect(updateStructureTool.name).toBe('update-data-structure');
      expect(updateStructureTool.description).toContain('Update an existing data structure');

      const deleteStructureTool = findTool(mockTool, 'delete-data-structure');
      expect(deleteStructureTool.name).toBe('delete-data-structure');
      expect(deleteStructureTool.description).toContain('Delete a data structure');
    });
  });

  describe('Schema Validation', () => {
    it('should validate create-folder schema with correct inputs', async () => {
      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-folder');
      
      // Valid inputs
      const validInputs = [
        {
          name: 'Test Folder',
          type: 'mixed'
        },
        {
          name: 'Marketing Templates',
          description: 'Collection of marketing automation templates',
          type: 'template',
          organizationId: 1001,
          teamId: 2001,
        },
        {
          name: 'Nested Folder',
          parentId: 5001,
          type: 'scenario',
          permissions: {
            read: ['user_123'],
            write: ['user_123'],
            admin: ['user_123']
          }
        }
      ];
      
      validInputs.forEach(input => {
        expectValidZodParse(tool.parameters, input);
      });
    });

    it('should reject invalid create-folder schema inputs', async () => {
      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-folder');
      
      // Invalid inputs
      const invalidInputs = [
        {}, // Missing required name
        { name: '', type: 'template' }, // Empty name
        { name: 'Test', type: 'invalid_type' }, // Invalid type
        { name: 'Test', parentId: 0 }, // parentId must be >= 1
        { name: 'Test', organizationId: -1 }, // negative organizationId
        { name: 'a'.repeat(101), type: 'mixed' }, // name too long
      ];
      
      invalidInputs.forEach(input => {
        expectInvalidZodParse(tool.parameters, input);
      });
    });

    it('should validate list-folders schema with filtering options', async () => {
      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-folders');
      
      const validListInputs = [
        {}, // Default parameters
        { parentId: 5001, type: 'template', limit: 50 },
        { searchQuery: 'CRM', includeContents: true, sortBy: 'name', sortOrder: 'desc' },
        { organizationId: 1001, teamId: 2001, includeEmpty: false, offset: 100 }
      ];
      
      validListInputs.forEach(input => {
        expectValidZodParse(tool.parameters, input);
      });
    });

    it('should validate data store creation schema with different types', async () => {
      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-data-store');
      
      // Valid data_structure store
      const validDataStructure = {
        name: 'Customer Database',
        description: 'Structured storage for customers',
        type: 'data_structure',
        structure: {
          fields: [
            {
              name: 'customerId',
              type: 'string',
              required: true,
              validation: { min: 1, max: 50 }
            }
          ],
          indexes: [
            {
              fields: ['customerId'],
              unique: true,
              name: 'idx_customer_id'
            }
          ]
        },
        settings: {
          maxSize: 500,
          encryption: true
        }
      };
      
      expectValidZodParse(tool.parameters, validDataStructure);

      // Valid key-value store
      const validKeyValue = {
        name: 'Session Cache',
        type: 'key_value',
        settings: {
          maxSize: 100,
          ttl: 3600,
          autoCleanup: true
        }
      };
      
      expectValidZodParse(tool.parameters, validKeyValue);

      // Valid queue store
      const validQueue = {
        name: 'Task Queue',
        type: 'queue',
        settings: {
          maxSize: 50
        },
        permissions: {
          read: ['worker_service'],
          write: ['task_scheduler'],
          admin: ['admin_user']
        }
      };
      
      expectValidZodParse(tool.parameters, validQueue);
    });

    it('should validate data structure schema with complex field specifications', async () => {
      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-data-structure');
      
      const validDataStructure = {
        name: 'Product Catalog',
        description: 'Structure for product data',
        organizationId: 1001,
        specification: [
          {
            name: 'productId',
            type: 'text',
            required: true,
            constraints: {
              minLength: 5,
              maxLength: 20,
              pattern: '^PROD[0-9]+$'
            }
          },
          {
            name: 'price',
            type: 'number',
            required: true,
            constraints: {
              minimum: 0,
              maximum: 10000
            }
          },
          {
            name: 'tags',
            type: 'array',
            required: false,
            spec: [
              {
                name: 'tag',
                type: 'text',
                required: true,
                constraints: { maxLength: 50 }
              }
            ]
          },
          {
            name: 'metadata',
            type: 'collection',
            required: false,
            spec: [
              {
                name: 'key',
                type: 'text',
                required: true
              },
              {
                name: 'value',
                type: 'text',
                required: true
              }
            ]
          }
        ],
        strict: true
      };
      
      expectValidZodParse(tool.parameters, validDataStructure);
    });

    it('should validate move-items schema with bulk operations', async () => {
      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'move-items');
      
      const validMoveOperation = {
        items: [
          { type: 'template', id: 1001 },
          { type: 'scenario', id: 2001 },
          { type: 'connection', id: 3001 }
        ],
        targetFolderId: 5001,
        copyInsteadOfMove: false
      };
      
      expectValidZodParse(tool.parameters, validMoveOperation);
      
      // Move to root (no target folder)
      const moveToRoot = {
        items: [{ type: 'folder', id: 4001 }],
        copyInsteadOfMove: false
      };
      
      expectValidZodParse(tool.parameters, moveToRoot);
      
      // Copy operation
      const copyOperation = {
        items: [{ type: 'template', id: 1001 }],
        targetFolderId: 6001,
        copyInsteadOfMove: true
      };
      
      expectValidZodParse(tool.parameters, copyOperation);
    });
  });

  describe('Basic Tool Execution', () => {
    it('should execute create-folder successfully with mocked data', async () => {
      mockApiClient.mockResponse('POST', '/organizations/1001/folders', {
        success: true,
        data: testFolder
      });

      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-folder');
      const result = await executeTool(tool, {
        name: 'CRM Integration Templates',
        description: 'Collection of templates for CRM system integrations',
        type: 'template',
        organizationId: 1001,
        teamId: 2001
      });
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.folder).toBeDefined();
      expect(parsedResult.folder.id).toBe(testFolder.id);
      expect(parsedResult.folder.name).toBe(testFolder.name);
      expect(parsedResult.message).toContain('created successfully');
      expect(parsedResult.organization.path).toBe(testFolder.path);
      expect(parsedResult.organization.type).toBe(testFolder.type);
    });

    it('should execute list-folders with hierarchy and filtering', async () => {
      const mockFolders = [testFolder];
      
      mockApiClient.mockResponse('GET', '/folders', {
        success: true,
        data: mockFolders,
        metadata: { total: 1, hasMore: false }
      });

      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-folders');
      const result = await executeTool(tool, {
        type: 'template',
        organizationId: 1001,
        includeContents: true,
        sortBy: 'name',
        sortOrder: 'asc'
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.folders).toHaveLength(1);
      expect(parsedResult.summary).toBeDefined();
      expect(parsedResult.summary.typeBreakdown.template).toBe(1);
      expect(parsedResult.summary.contentSummary.totalItems).toBe(31);
      expect(parsedResult.hierarchy).toBeDefined();
      expect(parsedResult.pagination.total).toBe(1);
    });

    it('should execute get-folder-contents with detailed metadata', async () => {
      const folderContents = {
        folder: testFolder,
        items: [
          { id: 1, type: 'template', name: 'Lead Generation Template', lastModified: '2024-01-20T10:00:00Z' },
          { id: 2, type: 'scenario', name: 'Data Sync Scenario', lastModified: '2024-01-20T09:00:00Z' },
          { id: 3, type: 'connection', name: 'Salesforce Production', lastModified: '2024-01-19T15:00:00Z' }
        ],
        breakdown: { templates: 1, scenarios: 1, connections: 1, subfolders: 0 }
      };

      mockApiClient.mockResponse('GET', '/folders/5001/contents', {
        success: true,
        data: folderContents,
        metadata: { total: 3, hasMore: false }
      });

      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-folder-contents');
      const result = await executeTool(tool, {
        folderId: 5001,
        contentType: 'all',
        includeMetadata: true,
        limit: 100
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.contents).toHaveLength(3);
      expect(parsedResult.summary.itemBreakdown.templates).toBe(1);
      expect(parsedResult.summary.folderInfo.name).toBe(testFolder.name);
      expect(parsedResult.pagination.total).toBe(3);
    });

    it('should execute create-data-store with structured configuration', async () => {
      mockApiClient.mockResponse('POST', '/organizations/1001/data-stores', {
        success: true,
        data: testDataStore
      });

      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-data-store');
      const result = await executeTool(tool, {
        name: 'Customer Records',
        description: 'Structured storage for customer information',
        type: 'data_structure',
        organizationId: 1001,
        teamId: 2001,
        structure: {
          fields: [
            {
              name: 'customerId',
              type: 'string',
              required: true,
              validation: { min: 1, max: 50, pattern: '^CUST[0-9]{6}$' }
            },
            {
              name: 'email',
              type: 'string',
              required: true,
              validation: { pattern: '^[^@]+@[^@]+\\.[^@]+$' }
            }
          ],
          indexes: [
            {
              fields: ['customerId'],
              unique: true,
              name: 'idx_customer_id'
            }
          ]
        },
        settings: {
          maxSize: 500,
          encryption: true,
          autoCleanup: true
        }
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.dataStore).toBeDefined();
      expect(parsedResult.dataStore.id).toBe(testDataStore.id);
      expect(parsedResult.configuration.type).toBe('data_structure');
      expect(parsedResult.configuration.fieldCount).toBe(3);
      expect(parsedResult.configuration.indexCount).toBe(2);
      expect(parsedResult.configuration.encryption).toBe(true);
    });

    it('should execute create-data-structure with complex field specifications', async () => {
      mockApiClient.mockResponse('POST', '/organizations/1001/data-structures', {
        success: true,
        data: testDataStructure
      });

      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-data-structure');
      const result = await executeTool(tool, {
        name: 'Product Catalog Structure',
        description: 'Data structure for product information management',
        organizationId: 1001,
        teamId: 2001,
        specification: [
          {
            name: 'productId',
            type: 'text',
            required: true,
            constraints: {
              minLength: 5,
              maxLength: 20,
              pattern: '^PROD[0-9]+$'
            }
          },
          {
            name: 'price',
            type: 'number',
            required: true,
            constraints: {
              minimum: 0,
              maximum: 10000
            }
          },
          {
            name: 'tags',
            type: 'array',
            required: false,
            spec: [
              {
                name: 'tag',
                type: 'text',
                required: true,
                constraints: { maxLength: 50 }
              }
            ]
          }
        ],
        strict: true
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.dataStructure).toBeDefined();
      expect(parsedResult.dataStructure.id).toBe(testDataStructure.id);
      expect(parsedResult.configuration.fieldCount).toBe(4);
      expect(parsedResult.configuration.strictMode).toBe(true);
      expect(parsedResult.configuration.complexFields).toBe(1);
    });

    it('should execute move-items with progress reporting', async () => {
      // Mock target folder validation
      mockApiClient.mockResponse('GET', '/folders/6001', {
        success: true,
        data: { ...testFolder, id: 6001, name: 'Target Folder' }
      });

      // Mock move operation result
      const moveResult = {
        successful: 3,
        failed: 0,
        targetFolderName: 'Target Folder',
        errors: []
      };

      mockApiClient.mockResponse('POST', '/folders/move-items', {
        success: true,
        data: moveResult
      });

      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'move-items');
      const mockReportProgress = jest.fn();
      
      const result = await executeTool(tool, {
        items: [
          { type: 'template', id: 1001 },
          { type: 'scenario', id: 2001 },
          { type: 'connection', id: 3001 }
        ],
        targetFolderId: 6001,
        copyInsteadOfMove: false
      }, {
        reportProgress: mockReportProgress
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.summary.operation).toBe('move');
      expect(parsedResult.summary.successfulOperations).toBe(3);
      expect(parsedResult.summary.failedOperations).toBe(0);
      expect(parsedResult.summary.targetFolder).toBe('Target Folder');
      
      // Verify progress reporting was called
      expect(mockReportProgress).toHaveBeenCalledWith({ progress: 0, total: 100 });
      expect(mockReportProgress).toHaveBeenCalledWith({ progress: 25, total: 100 });
      expect(mockReportProgress).toHaveBeenCalledWith({ progress: 100, total: 100 });
    });
  });

  describe('Error Handling and Security', () => {
    it('should handle API failures gracefully', async () => {
      mockApiClient.mockFailure('GET', '/folders', new Error('Folder service unavailable'));

      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-folders');
      
      await expect(executeTool(tool, {})).rejects.toThrow(UserError);
    });

    it('should handle unauthorized access errors', async () => {
      mockApiClient.mockResponse('GET', '/folders', testErrors.unauthorized);

      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-folders');
      
      await expect(executeTool(tool, {})).rejects.toThrow(UserError);
    });

    it('should validate parent folder existence for nested folders', async () => {
      mockApiClient.mockResponse('GET', '/folders/99999', {
        success: false,
        error: { message: 'Folder not found', status: 404 }
      });

      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-folder');
      
      await expect(executeTool(tool, {
        name: 'Invalid Parent Test',
        description: 'Testing invalid parent folder',
        parentId: 99999,
        type: 'template'
      })).rejects.toThrow('Parent folder with ID 99999 not found');
    });

    it('should validate data structure field uniqueness', async () => {
      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-data-structure');
      
      // Test duplicate field names
      await expect(executeTool(tool, {
        name: 'Invalid Structure',
        description: 'Testing duplicate fields',
        specification: [
          { name: 'duplicateField', type: 'text', required: true },
          { name: 'duplicateField', type: 'number', required: false } // Duplicate name
        ],
        strict: true
      })).rejects.toThrow('Field names must be unique within the data structure');
    });

    it('should validate data store structure requirements', async () => {
      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-data-store');
      
      // Data structure type without fields should fail
      await expect(executeTool(tool, {
        name: 'Invalid Structure Store',
        description: 'Testing missing structure',
        type: 'data_structure',
        // Missing structure.fields for data_structure type
      })).rejects.toThrow('Data structure type requires field definitions');
    });

    it('should validate constraint logic in data structure fields', async () => {
      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-data-structure');
      
      // Invalid constraints (minLength > maxLength)
      await expect(executeTool(tool, {
        name: 'Invalid Constraints Structure',
        description: 'Testing invalid constraints',
        specification: [
          {
            name: 'invalidField',
            type: 'text',
            required: true,
            constraints: {
              minLength: 100,
              maxLength: 50 // maxLength < minLength
            }
          }
        ],
        strict: true
      })).rejects.toThrow('minLength cannot be greater than maxLength');
    });

    it('should handle folder hierarchy access control', async () => {
      mockApiClient.mockResponse('POST', '/folders', {
        success: true,
        data: { ...testFolder, permissions: { read: [], write: [], admin: ['user_12345'] } }
      });

      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-folder');
      const result = await executeTool(tool, {
        name: 'Restricted Folder',
        description: 'Folder with admin-only access',
        type: 'mixed',
        permissions: {
          read: [],
          write: [],
          admin: ['user_12345']
        }
      });
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.organization.permissions.readAccess).toBe(0);
      expect(parsedResult.organization.permissions.writeAccess).toBe(0);
      expect(parsedResult.organization.permissions.adminAccess).toBe(1);
    });

    it('should enforce audit trails for data structure modifications', async () => {
      mockApiClient.mockResponse('GET', '/data-structures/9001', {
        success: true,
        data: testDataStructure
      });

      mockApiClient.mockResponse('PATCH', '/data-structures/9001', {
        success: true,
        data: { ...testDataStructure, name: 'Updated Structure' }
      });

      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'update-data-structure');
      const mockLog = {
        info: jest.fn(),
        error: jest.fn(),
        warn: jest.fn(),
        debug: jest.fn()
      };
      
      await executeTool(tool, {
        id: 9001,
        name: 'Updated Structure'
      }, { log: mockLog });
      
      // Verify audit logging
      expect(mockLog.info).toHaveBeenCalledWith(
        'Updating data structure',
        expect.any(Object)
      );
      expect(mockLog.info).toHaveBeenCalledWith(
        'Successfully updated data structure',
        expect.any(Object)
      );
    });
  });

  describe('Organizational Hierarchy and Permission Management', () => {
    it('should support complex organizational folder structures', async () => {
      // Test creating organization-level folder
      mockApiClient.mockResponse('POST', '/organizations/1001/folders', {
        success: true,
        data: { ...testFolder, organizationId: 1001, teamId: null }
      });

      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-folder');
      const result = await executeTool(tool, {
        name: 'Organization Templates',
        description: 'Organization-wide template collection',
        type: 'template',
        organizationId: 1001
      });
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.folder.organizationId).toBe(1001);
      expect(parsedResult.folder.teamId).toBeNull();
    });

    it('should support team-specific folder isolation', async () => {
      // Test creating team-level folder with proper permissions structure
      const teamFolder = {
        ...testFolder,
        organizationId: 1001,
        teamId: 2001,
        permissions: {
          read: ['user_12345', 'team_2001'],
          write: ['user_12345', 'user_67890'],
          admin: ['user_12345']
        }
      };

      mockApiClient.mockResponse('POST', '/teams/2001/folders', {
        success: true,
        data: teamFolder
      });

      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-folder');
      const result = await executeTool(tool, {
        name: 'Team Marketing Assets',
        description: 'Marketing team specific resources',
        type: 'mixed',
        organizationId: 1001,
        teamId: 2001
      });
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.folder.organizationId).toBe(1001);
      expect(parsedResult.folder.teamId).toBe(2001);
    });

    it('should validate folder permission inheritance', async () => {
      const parentFolder = { ...testFolder, id: 7001 };
      const childFolder = { 
        ...testFolder, 
        id: 7002, 
        parentId: 7001, 
        permissions: { read: ['inherited'], write: ['inherited'], admin: ['inherited'] }
      };

      // Mock parent folder validation
      mockApiClient.mockResponse('GET', '/folders/7001', {
        success: true,
        data: parentFolder
      });

      mockApiClient.mockResponse('POST', '/folders', {
        success: true,
        data: childFolder
      });

      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-folder');
      const result = await executeTool(tool, {
        name: 'Child Folder',
        description: 'Child folder with inherited permissions',
        parentId: 7001,
        type: 'scenario'
      });
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.folder.parentId).toBe(7001);
      expect(parsedResult.folder.permissions.read).toContain('inherited');
    });
  });

  describe('Data Store and Structure Integration', () => {
    it('should support comprehensive data store lifecycle management', async () => {
      const cacheStore = {
        ...testDataStore,
        id: 8002,
        type: 'cache' as const,
        name: 'Session Cache',
        structure: {},
        settings: { ...testDataStore.settings, ttl: 3600, maxSize: 100 }
      };

      mockApiClient.mockResponse('POST', '/data-stores', {
        success: true,
        data: cacheStore
      });

      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-data-store');
      const result = await executeTool(tool, {
        name: 'Session Cache',
        description: 'Cache for session data',
        type: 'cache',
        settings: {
          maxSize: 100,
          ttl: 3600,
          autoCleanup: true,
          encryption: false,
          compression: true
        }
      });
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.dataStore.type).toBe('cache');
      expect(parsedResult.configuration.maxSize).toBe('100 MB');
      expect(parsedResult.configuration.fieldCount).toBe(0);
    });

    it('should validate data structure usage analytics', async () => {
      const structuresWithUsage = [
        {
          ...testDataStructure,
          usage: {
            dataStoresCount: 5,
            totalRecords: 50000,
            lastUsed: '2024-01-20T10:00:00Z'
          }
        }
      ];

      mockApiClient.mockResponse('GET', '/data-structures', {
        success: true,
        data: structuresWithUsage,
        metadata: { total: 1, hasMore: false }
      });

      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-data-structures');
      const result = await executeTool(tool, {
        includeUsage: true,
        includeValidation: true,
        sortBy: 'usageCount',
        sortOrder: 'desc'
      });
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.dataStructures).toHaveLength(1);
      expect(parsedResult.summary.usageSummary).toBeDefined();
      expect(parsedResult.summary.usageSummary.totalDataStores).toBe(5);
      expect(parsedResult.summary.usageSummary.totalRecords).toBe(50000);
      expect(parsedResult.summary.validationSummary).toBeDefined();
    });

    it('should support data structure dependency validation', async () => {
      const structureWithDependencies = {
        ...testDataStructure,
        usage: { dataStoresCount: 3, totalRecords: 10000, lastUsed: '2024-01-20T10:00:00Z' }
      };

      const associatedStores = [
        { id: 1, name: 'Store 1', usage: { recordCount: 5000 } },
        { id: 2, name: 'Store 2', usage: { recordCount: 3000 } },
        { id: 3, name: 'Store 3', usage: { recordCount: 2000 } }
      ];

      // First mock the structure fetch with associated stores
      mockApiClient.mockResponse('GET', '/data-structures/9001', {
        success: true,
        data: structureWithDependencies,
        dataStores: associatedStores
      });

      const { addFolderTools } = await import('../../../src/tools/folders.js');
      addFolderTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'delete-data-structure');
      
      // The tool throws an error when there are dependencies and no force flag
      // This tests the dependency validation logic
      await expect(executeTool(tool, {
        id: 9001,
        confirmDeletion: false,
        force: false
      })).rejects.toThrow('Cannot delete data structure "Product Catalog Structure" - it has 3 associated data stores');
      
      // Also test the case where there are no dependencies - should return confirmation
      const structureWithoutDependencies = {
        ...testDataStructure,
        usage: { dataStoresCount: 0, totalRecords: 0, lastUsed: '2024-01-20T10:00:00Z' }
      };

      mockApiClient.mockResponse('GET', '/data-structures/9002', {
        success: true,
        data: structureWithoutDependencies,
        dataStores: []
      });

      const result = await executeTool(tool, {
        id: 9002,
        confirmDeletion: false
      });
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.action).toBe('confirmation_required');
      expect(parsedResult.dependencies.dataStoresCount).toBe(0);
    });
  });
});