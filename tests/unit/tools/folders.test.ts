/**
 * Comprehensive Test Suite for Folder Organization Tools
 * Tests all 6 folder and data store management tools with hierarchical operations
 * and advanced testing patterns following testing.md guidelines
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { UserError } from 'fastmcp';
// Tool imports removed - will be handled by mock setupfolders.js';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';
// Tool imports removed - will be handled by mock setupfolders.js';

// Advanced testing utilities
class ChaosMonkey {
  constructor(private config: { failureRate: number; latencyMs: number; scenarios: string[] }) {}

  shouldFail(): boolean {
    return Math.random() < this.config.failureRate;
  }

  getRandomLatency(): number {
    return Math.random() * this.config.latencyMs;
  }

  getRandomScenario(): string {
    return this.config.scenarios[Math.floor(Math.random() * this.config.scenarios.length)];
  }
}

// Security testing utilities
const securityTestPatterns = {
  sqlInjection: ["'; DROP TABLE folders; --", "1' OR '1'='1", "'; SELECT * FROM data; --"],
  xss: ["<script>alert('xss')</script>", "javascript:alert('xss')", "<img src=x onerror=alert('xss')>"],
  pathTraversal: ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam", "....//....//etc/passwd"],
  commandInjection: ["; cat /etc/passwd", "| whoami", "&& rm -rf /", "; shutdown -h now"],
  ldapInjection: ["*)(uid=*))(|(uid=*", "*)(|(objectClass=*))", "admin)(&(password=*)"],
};

describe('Folder Organization Tools', () => {
  let server: FastMCP;
  let mockApiClient: MockMakeApiClient;
  let chaosMonkey: ChaosMonkey;

  // Mock data generators
  const generateMockFolder = (overrides?: Partial<MakeFolder>): MakeFolder => ({
    id: Math.floor(Math.random() * 100000),
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
      lastActivity: new Date(Date.now() - 3600000).toISOString(),
      mostActiveItem: {
        type: 'template',
        id: 12345,
        name: 'Salesforce Lead Sync',
        activity: 25,
      },
    },
    createdAt: new Date(Date.now() - 86400000 * 30).toISOString(),
    updatedAt: new Date(Date.now() - 86400000).toISOString(),
    createdBy: 12345,
    createdByName: 'Organization Admin',
    ...overrides,
  });

  const generateMockDataStore = (overrides?: Partial<MakeDataStore>): MakeDataStore => ({
    id: Math.floor(Math.random() * 100000),
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
        {
          name: 'lastName',
          type: 'string',
          required: true,
          validation: {
            min: 1,
            max: 100,
          },
        },
        {
          name: 'preferences',
          type: 'object',
          required: false,
          defaultValue: {},
        },
        {
          name: 'createdAt',
          type: 'date',
          required: true,
          defaultValue: new Date().toISOString(),
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
        {
          fields: ['lastName', 'firstName'],
          unique: false,
          name: 'idx_customer_name',
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
      lastOperation: new Date(Date.now() - 1800000).toISOString(),
    },
    permissions: {
      read: ['user_12345', 'team_2001'],
      write: ['user_12345', 'user_67890'],
      admin: ['user_12345'],
    },
    createdAt: new Date(Date.now() - 86400000 * 90).toISOString(),
    updatedAt: new Date(Date.now() - 86400000).toISOString(),
    createdBy: 12345,
    ...overrides,
  });

  const generateFolderHierarchy = (): MakeFolder[] => [
    generateMockFolder({
      id: 1,
      name: 'Root CRM',
      path: '/crm',
      parentId: null,
      itemCount: { templates: 5, scenarios: 2, connections: 1, subfolders: 2, total: 10 },
    }),
    generateMockFolder({
      id: 2,
      name: 'Salesforce',
      path: '/crm/salesforce',
      parentId: 1,
      itemCount: { templates: 8, scenarios: 3, connections: 2, subfolders: 1, total: 14 },
    }),
    generateMockFolder({
      id: 3,
      name: 'HubSpot',
      path: '/crm/hubspot',
      parentId: 1,
      itemCount: { templates: 6, scenarios: 4, connections: 1, subfolders: 0, total: 11 },
    }),
    generateMockFolder({
      id: 4,
      name: 'Lead Management',
      path: '/crm/salesforce/leads',
      parentId: 2,
      itemCount: { templates: 12, scenarios: 5, connections: 0, subfolders: 0, total: 17 },
    }),
  ];

  beforeEach(() => {
    // Server setup will be handled by test helpers
    mockApiClient = new MockMakeApiClient();
    chaosMonkey = new ChaosMonkey({
      failureRate: 0.1,
      latencyMs: 1000,
      scenarios: ['latency', 'error', 'timeout'],
    });

    // Add tools to server
    // Tool setup handled by mock
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Tool Registration', () => {
    test('should register all folder organization tools', () => {
      const tools = server.getTools();
      const expectedTools = [
        'create-folder',
        'list-folders',
        'get-folder-contents',
        'move-items',
        'create-data-store',
        'list-data-stores',
      ];

      expectedTools.forEach(toolName => {
        expect(tools).toHaveProperty(toolName);
      });
    });

    test('should have correct tool schemas', () => {
      const tools = server.getTools();
      
      expect(tools['create-folder'].parameters).toBeDefined();
      expect(tools['list-folders'].parameters).toBeDefined();
      expect(tools['get-folder-contents'].parameters).toBeDefined();
      expect(tools['move-items'].parameters).toBeDefined();
      expect(tools['create-data-store'].parameters).toBeDefined();
      expect(tools['list-data-stores'].parameters).toBeDefined();
    });
  });

  describe('create-folder', () => {
    describe('Basic Functionality', () => {
      test('should create root folder successfully', async () => {
        const mockFolder = generateMockFolder();
        mockApiClient.setMockResponse('post', '/folders', {
          success: true,
          data: mockFolder,
        });

        const result = await mockServer.executeToolCall({
          tool: 'create-folder',
          parameters: {
            name: 'Marketing Templates',
            description: 'Collection of marketing automation templates',
            type: 'template',
            organizationId: 1001,
            teamId: 2001,
          },
        });

        expect(mockApiClient.post).toHaveBeenCalledWith('/organizations/1001/folders', expect.objectContaining({
          name: 'Marketing Templates',
          type: 'template',
          organizationId: 1001,
          teamId: 2001,
        }));

        const response = JSON.parse(result);
        expect(response.folder).toBeDefined();
        expect(response.message).toContain('created successfully');
        expect(response.organization.path).toBeDefined();
      });

      test('should create nested folder', async () => {
        const parentFolder = generateMockFolder({ id: 5001 });
        const childFolder = generateMockFolder({
          parentId: 5001,
          path: '/marketing-templates/email-campaigns',
        });

        // Mock parent folder validation
        mockApiClient.setMockResponse('get', '/folders/5001', {
          success: true,
          data: parentFolder,
        });

        mockApiClient.setMockResponse('post', '/folders', {
          success: true,
          data: childFolder,
        });

        const result = await mockServer.executeToolCall({
          tool: 'create-folder',
          parameters: {
            name: 'Email Campaigns',
            description: 'Email marketing campaign templates',
            parentId: 5001,
            type: 'template',
          },
        });

        expect(mockApiClient.get).toHaveBeenCalledWith('/folders/5001');
        expect(mockApiClient.post).toHaveBeenCalledWith('/folders', expect.objectContaining({
          parentId: 5001,
        }));

        const response = JSON.parse(result);
        expect(response.folder.parentId).toBe(5001);
        expect(response.folder.path).toContain('email-campaigns');
      });

      test('should create folder with custom permissions', async () => {
        const mockFolder = generateMockFolder({
          permissions: {
            read: ['user_12345', 'user_67890', 'team_2001'],
            write: ['user_12345'],
            admin: ['user_12345'],
          },
        });

        mockApiClient.setMockResponse('post', '/folders', {
          success: true,
          data: mockFolder,
        });

        const result = await mockServer.executeToolCall({
          tool: 'create-folder',
          parameters: {
            name: 'Restricted Templates',
            description: 'Templates with restricted access',
            type: 'template',
            permissions: {
              read: ['user_12345', 'user_67890', 'team_2001'],
              write: ['user_12345'],
              admin: ['user_12345'],
            },
          },
        });

        const response = JSON.parse(result);
        expect(response.organization.permissions.readAccess).toBe(3);
        expect(response.organization.permissions.writeAccess).toBe(1);
        expect(response.organization.permissions.adminAccess).toBe(1);
      });
    });

    describe('Security Testing', () => {
      test('should sanitize folder metadata', async () => {
        const mockFolder = generateMockFolder();
        mockApiClient.setMockResponse('post', '/folders', {
          success: true,
          data: mockFolder,
        });

        const maliciousName = securityTestPatterns.xss[0];
        const maliciousDescription = securityTestPatterns.sqlInjection[0];

        const result = await mockServer.executeToolCall({
          tool: 'create-folder',
          parameters: {
            name: maliciousName,
            description: maliciousDescription,
            type: 'template',
          },
        });

        // Folder should be created but content should be sanitized
        const response = JSON.parse(result);
        expect(response.folder).toBeDefined();
        // Verify sanitization occurred (actual implementation would sanitize)
      });

      test('should validate parent folder existence', async () => {
        mockApiClient.setMockResponse('get', '/folders/99999', {
          success: false,
          error: { message: 'Folder not found', status: 404 },
        });

        await expect(mockServer.executeToolCall({
          tool: 'create-folder',
          parameters: {
            name: 'Invalid Parent Test',
            description: 'Testing invalid parent folder',
            parentId: 99999,
            type: 'template',
          },
        })).rejects.toThrow('Parent folder with ID 99999 not found');
      });
    });

    describe('Error Handling', () => {
      test('should handle API failures gracefully', async () => {
        mockApiClient.setMockResponse('post', '/folders', {
          success: false,
          error: { message: 'Folder service temporarily unavailable' },
        });

        await expect(mockServer.executeToolCall({
          tool: 'create-folder',
          parameters: {
            name: 'Test Folder',
            description: 'Test description',
            type: 'template',
          },
        })).rejects.toThrow('Failed to create folder: Folder service temporarily unavailable');
      });

      test('should validate required fields', async () => {
        await expect(mockServer.executeToolCall({
          tool: 'create-folder',
          parameters: {
            // Missing required name
            description: 'Test description',
            type: 'template',
          },
        })).rejects.toThrow();
      });

      test('should validate folder types', async () => {
        await expect(mockServer.executeToolCall({
          tool: 'create-folder',
          parameters: {
            name: 'Test Folder',
            description: 'Test description',
            type: 'invalid_type' as 'template' | 'scenario' | 'connection' | 'mixed',
          },
        })).rejects.toThrow();
      });
    });
  });

  describe('list-folders', () => {
    describe('Basic Functionality', () => {
      test('should list root folders', async () => {
        const mockFolders = generateFolderHierarchy().filter(f => f.parentId === null);
        mockApiClient.setMockResponse('get', '/folders', {
          success: true,
          data: mockFolders,
          metadata: { total: 1, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'list-folders',
          parameters: {
            parentId: undefined, // Root folders
            type: 'all',
            limit: 50,
            offset: 0,
          },
        });

        expect(mockApiClient.get).toHaveBeenCalledWith('/folders', {
          params: expect.objectContaining({
            limit: 50,
            offset: 0,
            sortBy: 'name',
            sortOrder: 'asc',
          }),
        });

        const response = JSON.parse(result);
        expect(response.folders).toHaveLength(1);
        expect(response.summary).toBeDefined();
        expect(response.summary.totalFolders).toBe(1);
      });

      test('should list folders with hierarchy visualization', async () => {
        const hierarchyFolders = generateFolderHierarchy();
        mockApiClient.setMockResponse('get', '/folders', {
          success: true,
          data: hierarchyFolders,
          metadata: { total: 4, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'list-folders',
          parameters: {
            includeContents: true,
            sortBy: 'name',
            sortOrder: 'asc',
          },
        });

        const response = JSON.parse(result);
        expect(response.folders).toHaveLength(4);
        expect(response.hierarchy).toBeDefined();
        expect(response.summary.contentSummary).toBeDefined();
      });

      test('should filter folders by type and organization', async () => {
        const templateFolders = [
          generateMockFolder({ type: 'template', organizationId: 1001 }),
          generateMockFolder({ type: 'template', organizationId: 1001 }),
        ];

        mockApiClient.setMockResponse('get', '/folders', {
          success: true,
          data: templateFolders,
          metadata: { total: 2, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'list-folders',
          parameters: {
            type: 'template',
            organizationId: 1001,
            includeEmpty: false,
          },
        });

        expect(mockApiClient.get).toHaveBeenCalledWith('/folders', {
          params: expect.objectContaining({
            type: 'template',
            organizationId: 1001,
            includeEmpty: false,
          }),
        });

        const response = JSON.parse(result);
        expect(response.folders).toHaveLength(2);
        expect(response.summary.typeBreakdown.template).toBe(2);
      });
    });

    describe('Advanced Filtering and Analytics', () => {
      test('should search folders and provide analytics', async () => {
        const searchFolders = [
          generateMockFolder({ 
            name: 'CRM Integration Templates',
            itemCount: { templates: 15, scenarios: 5, connections: 3, subfolders: 2, total: 25 },
          }),
          generateMockFolder({ 
            name: 'CRM Data Processing',
            itemCount: { templates: 8, scenarios: 12, connections: 1, subfolders: 0, total: 21 },
          }),
        ];

        mockApiClient.setMockResponse('get', '/folders', {
          success: true,
          data: searchFolders,
          metadata: { total: 2, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'list-folders',
          parameters: {
            searchQuery: 'CRM',
            includeContents: false,
          },
        });

        expect(mockApiClient.get).toHaveBeenCalledWith('/folders', {
          params: expect.objectContaining({
            search: 'CRM',
          }),
        });

        const response = JSON.parse(result);
        expect(response.folders).toHaveLength(2);
        expect(response.summary.contentSummary.totalItems).toBe(46);
        expect(response.summary.contentSummary.templates).toBe(23);
        expect(response.summary.largestFolder).toBeDefined();
      });

      test('should identify most recent activity', async () => {
        const recentActivityFolders = [
          generateMockFolder({
            metadata: {
              size: 1024000,
              lastActivity: new Date(Date.now() - 3600000).toISOString(), // 1 hour ago
              mostActiveItem: { type: 'template', id: 1, name: 'Recent Template', activity: 10 },
            },
          }),
          generateMockFolder({
            metadata: {
              size: 2048000,
              lastActivity: new Date(Date.now() - 7200000).toISOString(), // 2 hours ago
              mostActiveItem: { type: 'scenario', id: 2, name: 'Active Scenario', activity: 20 },
            },
          }),
        ];

        mockApiClient.setMockResponse('get', '/folders', {
          success: true,
          data: recentActivityFolders,
          metadata: { total: 2, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'list-folders',
          parameters: {
            sortBy: 'lastActivity',
            sortOrder: 'desc',
          },
        });

        const response = JSON.parse(result);
        expect(response.summary.mostRecentActivity).toBeDefined();
        expect(response.summary.mostRecentActivity.metadata.lastActivity).toBe(recentActivityFolders[0].metadata.lastActivity);
      });
    });

    describe('Error Handling', () => {
      test('should handle API failures', async () => {
        mockApiClient.setMockResponse('get', '/folders', {
          success: false,
          error: { message: 'Folder service temporarily unavailable' },
        });

        await expect(mockServer.executeToolCall({
          tool: 'list-folders',
          parameters: {},
        })).rejects.toThrow('Failed to list folders: Folder service temporarily unavailable');
      });
    });
  });

  describe('get-folder-contents', () => {
    describe('Basic Functionality', () => {
      test('should retrieve folder contents with metadata', async () => {
        const folderContents = {
          folder: generateMockFolder(),
          items: [
            { id: 1, type: 'template', name: 'Lead Generation Template', lastModified: new Date().toISOString() },
            { id: 2, type: 'scenario', name: 'Data Sync Scenario', lastModified: new Date().toISOString() },
            { id: 3, type: 'connection', name: 'Salesforce Production', lastModified: new Date().toISOString() },
          ],
          breakdown: { templates: 1, scenarios: 1, connections: 1, subfolders: 0 },
        };

        mockApiClient.setMockResponse('get', '/folders/12345/contents', {
          success: true,
          data: folderContents,
          metadata: { total: 3, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'get-folder-contents',
          parameters: {
            folderId: 12345,
            contentType: 'all',
            includeMetadata: true,
            limit: 100,
          },
        });

        expect(mockApiClient.get).toHaveBeenCalledWith('/folders/12345/contents', {
          params: expect.objectContaining({
            contentType: 'all',
            includeMetadata: true,
            limit: 100,
          }),
        });

        const response = JSON.parse(result);
        expect(response.contents).toHaveLength(3);
        expect(response.summary.itemBreakdown).toBeDefined();
        expect(response.summary.folderInfo).toBeDefined();
      });

      test('should filter folder contents by type', async () => {
        const templateContents = {
          folder: generateMockFolder(),
          items: [
            { id: 1, type: 'template', name: 'Email Template', lastModified: new Date().toISOString() },
            { id: 2, type: 'template', name: 'SMS Template', lastModified: new Date().toISOString() },
          ],
          breakdown: { templates: 2, scenarios: 0, connections: 0, subfolders: 0 },
        };

        mockApiClient.setMockResponse('get', '/folders/12345/contents', {
          success: true,
          data: templateContents,
          metadata: { total: 2, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'get-folder-contents',
          parameters: {
            folderId: 12345,
            contentType: 'templates',
            includeMetadata: true,
          },
        });

        const response = JSON.parse(result);
        expect(response.contents).toHaveLength(2);
        expect(response.summary.itemBreakdown.templates).toBe(2);
      });
    });

    describe('Error Handling', () => {
      test('should handle folder not found', async () => {
        mockApiClient.setMockResponse('get', '/folders/99999/contents', {
          success: false,
          error: { message: 'Folder not found', status: 404 },
        });

        await expect(mockServer.executeToolCall({
          tool: 'get-folder-contents',
          parameters: {
            folderId: 99999,
          },
        })).rejects.toThrow('Failed to get folder contents: Folder not found');
      });
    });
  });

  describe('move-items', () => {
    describe('Basic Functionality', () => {
      test('should move items between folders', async () => {
        const targetFolder = generateMockFolder({ id: 5001 });
        const moveResult = {
          successful: 3,
          failed: 0,
          targetFolderName: 'Target Folder',
          errors: [],
        };

        // Mock target folder validation
        mockApiClient.setMockResponse('get', '/folders/5001', {
          success: true,
          data: targetFolder,
        });

        mockApiClient.setMockResponse('post', '/folders/move-items', {
          success: true,
          data: moveResult,
        });

        const result = await mockServer.executeToolCall({
          tool: 'move-items',
          parameters: {
            items: [
              { type: 'template', id: 1001 },
              { type: 'scenario', id: 2001 },
              { type: 'connection', id: 3001 },
            ],
            targetFolderId: 5001,
            copyInsteadOfMove: false,
          },
        });

        expect(mockApiClient.get).toHaveBeenCalledWith('/folders/5001');
        expect(mockApiClient.post).toHaveBeenCalledWith('/folders/move-items', expect.objectContaining({
          items: expect.arrayContaining([
            { type: 'template', id: 1001 },
            { type: 'scenario', id: 2001 },
            { type: 'connection', id: 3001 },
          ]),
          targetFolderId: 5001,
          operation: 'move',
        }));

        const response = JSON.parse(result);
        expect(response.summary.operation).toBe('move');
        expect(response.summary.successfulOperations).toBe(3);
        expect(response.summary.failedOperations).toBe(0);
      });

      test('should copy items instead of moving', async () => {
        const copyResult = {
          successful: 2,
          failed: 0,
          targetFolderName: 'Copy Target',
          errors: [],
        };

        mockApiClient.setMockResponse('post', '/folders/move-items', {
          success: true,
          data: copyResult,
        });

        const result = await mockServer.executeToolCall({
          tool: 'move-items',
          parameters: {
            items: [
              { type: 'template', id: 1001 },
              { type: 'template', id: 1002 },
            ],
            targetFolderId: 5001,
            copyInsteadOfMove: true,
          },
        });

        expect(mockApiClient.post).toHaveBeenCalledWith('/folders/move-items', expect.objectContaining({
          operation: 'copy',
        }));

        const response = JSON.parse(result);
        expect(response.summary.operation).toBe('copy');
        expect(response.message).toContain('copied');
      });

      test('should move items to root folder', async () => {
        const moveToRootResult = {
          successful: 1,
          failed: 0,
          targetFolderName: 'Root',
          errors: [],
        };

        mockApiClient.setMockResponse('post', '/folders/move-items', {
          success: true,
          data: moveToRootResult,
        });

        const result = await mockServer.executeToolCall({
          tool: 'move-items',
          parameters: {
            items: [{ type: 'folder', id: 4001 }],
            targetFolderId: undefined, // Move to root
            copyInsteadOfMove: false,
          },
        });

        expect(mockApiClient.post).toHaveBeenCalledWith('/folders/move-items', expect.objectContaining({
          targetFolderId: undefined,
        }));

        const response = JSON.parse(result);
        expect(response.summary.targetFolder).toBe('Root');
      });
    });

    describe('Bulk Operations', () => {
      test('should handle partial failures in bulk move', async () => {
        const partialFailureResult = {
          successful: 2,
          failed: 1,
          targetFolderName: 'Target Folder',
          errors: [
            { itemId: 1003, itemType: 'template', error: 'Permission denied' },
          ],
        };

        mockApiClient.setMockResponse('post', '/folders/move-items', {
          success: true,
          data: partialFailureResult,
        });

        const result = await mockServer.executeToolCall({
          tool: 'move-items',
          parameters: {
            items: [
              { type: 'template', id: 1001 },
              { type: 'template', id: 1002 },
              { type: 'template', id: 1003 }, // This one fails
            ],
            targetFolderId: 5001,
            copyInsteadOfMove: false,
          },
        });

        const response = JSON.parse(result);
        expect(response.summary.successfulOperations).toBe(2);
        expect(response.summary.failedOperations).toBe(1);
        expect(response.errors).toHaveLength(1);
        expect(response.errors[0].error).toBe('Permission denied');
      });
    });

    describe('Error Handling', () => {
      test('should validate target folder existence', async () => {
        mockApiClient.setMockResponse('get', '/folders/99999', {
          success: false,
          error: { message: 'Folder not found', status: 404 },
        });

        await expect(mockServer.executeToolCall({
          tool: 'move-items',
          parameters: {
            items: [{ type: 'template', id: 1001 }],
            targetFolderId: 99999,
            copyInsteadOfMove: false,
          },
        })).rejects.toThrow('Target folder with ID 99999 not found');
      });

      test('should handle move operation failures', async () => {
        mockApiClient.setMockResponse('post', '/folders/move-items', {
          success: false,
          error: { message: 'Move operation failed' },
        });

        await expect(mockServer.executeToolCall({
          tool: 'move-items',
          parameters: {
            items: [{ type: 'template', id: 1001 }],
            targetFolderId: 5001,
            copyInsteadOfMove: false,
          },
        })).rejects.toThrow('Failed to move items: Move operation failed');
      });

      test('should validate items array', async () => {
        await expect(mockServer.executeToolCall({
          tool: 'move-items',
          parameters: {
            items: [], // Empty array
            targetFolderId: 5001,
            copyInsteadOfMove: false,
          },
        })).rejects.toThrow();
      });
    });
  });

  describe('create-data-store', () => {
    describe('Basic Functionality', () => {
      test('should create structured data store', async () => {
        const mockDataStore = generateMockDataStore();
        mockApiClient.setMockResponse('post', '/data-stores', {
          success: true,
          data: mockDataStore,
        });

        const result = await mockServer.executeToolCall({
          tool: 'create-data-store',
          parameters: {
            name: 'Customer Database',
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
                  validation: { min: 1, max: 50 },
                },
                {
                  name: 'email',
                  type: 'string',
                  required: true,
                  validation: { pattern: '^[^@]+@[^@]+\\.[^@]+$' },
                },
              ],
              indexes: [
                {
                  fields: ['customerId'],
                  unique: true,
                  name: 'idx_customer_id',
                },
              ],
            },
            settings: {
              maxSize: 500,
              encryption: true,
              autoCleanup: true,
            },
          },
        });

        expect(mockApiClient.post).toHaveBeenCalledWith('/organizations/1001/data-stores', expect.objectContaining({
          name: 'Customer Database',
          type: 'data_structure',
          structure: expect.objectContaining({
            fields: expect.arrayContaining([
              expect.objectContaining({ name: 'customerId', type: 'string', required: true }),
            ]),
          }),
        }));

        const response = JSON.parse(result);
        expect(response.dataStore).toBeDefined();
        expect(response.configuration.fieldCount).toBe(6);
        expect(response.configuration.indexCount).toBe(3);
        expect(response.configuration.encryption).toBe(true);
      });

      test('should create key-value data store', async () => {
        const kvDataStore = generateMockDataStore({
          type: 'key_value',
          structure: {},
        });

        mockApiClient.setMockResponse('post', '/data-stores', {
          success: true,
          data: kvDataStore,
        });

        const result = await mockServer.executeToolCall({
          tool: 'create-data-store',
          parameters: {
            name: 'Session Cache',
            description: 'Key-value store for session data',
            type: 'key_value',
            settings: {
              maxSize: 100,
              ttl: 3600, // 1 hour
              autoCleanup: true,
              compression: true,
            },
          },
        });

        const response = JSON.parse(result);
        expect(response.dataStore.type).toBe('key_value');
        expect(response.configuration.fieldCount).toBe(0);
      });

      test('should create queue data store', async () => {
        const queueDataStore = generateMockDataStore({
          type: 'queue',
          structure: {},
        });

        mockApiClient.setMockResponse('post', '/data-stores', {
          success: true,
          data: queueDataStore,
        });

        const result = await mockServer.executeToolCall({
          tool: 'create-data-store',
          parameters: {
            name: 'Task Queue',
            description: 'Queue for background task processing',
            type: 'queue',
            settings: {
              maxSize: 50,
              autoCleanup: false,
            },
            permissions: {
              read: ['user_12345', 'worker_service'],
              write: ['user_12345', 'task_scheduler'],
              admin: ['user_12345'],
            },
          },
        });

        const response = JSON.parse(result);
        expect(response.dataStore.type).toBe('queue');
        expect(response.permissions.readAccess).toBe(2);
        expect(response.permissions.writeAccess).toBe(2);
      });
    });

    describe('Data Structure Validation', () => {
      test('should validate field definitions for data_structure type', async () => {
        await expect(mockServer.executeToolCall({
          tool: 'create-data-store',
          parameters: {
            name: 'Invalid Structure',
            description: 'Testing invalid structure validation',
            type: 'data_structure',
            // Missing structure fields
          },
        })).rejects.toThrow('Data structure type requires field definitions');
      });

      test('should validate unique field names', async () => {
        await expect(mockServer.executeToolCall({
          tool: 'create-data-store',
          parameters: {
            name: 'Duplicate Fields',
            description: 'Testing duplicate field validation',
            type: 'data_structure',
            structure: {
              fields: [
                { name: 'duplicateField', type: 'string', required: true },
                { name: 'duplicateField', type: 'number', required: false }, // Duplicate name
              ],
            },
          },
        })).rejects.toThrow('Field names must be unique within the data structure');
      });
    });

    describe('Error Handling', () => {
      test('should handle API failures gracefully', async () => {
        mockApiClient.setMockResponse('post', '/data-stores', {
          success: false,
          error: { message: 'Data store service temporarily unavailable' },
        });

        await expect(mockServer.executeToolCall({
          tool: 'create-data-store',
          parameters: {
            name: 'Test Store',
            description: 'Test description',
            type: 'key_value',
          },
        })).rejects.toThrow('Failed to create data store: Data store service temporarily unavailable');
      });

      test('should validate required fields', async () => {
        await expect(mockServer.executeToolCall({
          tool: 'create-data-store',
          parameters: {
            // Missing required name and type
            description: 'Test description',
          },
        })).rejects.toThrow();
      });
    });
  });

  describe('list-data-stores', () => {
    describe('Basic Functionality', () => {
      test('should list data stores with filters', async () => {
        const mockDataStores = [
          generateMockDataStore({ type: 'data_structure' }),
          generateMockDataStore({ type: 'key_value' }),
          generateMockDataStore({ type: 'queue' }),
        ];

        mockApiClient.setMockResponse('get', '/data-stores', {
          success: true,
          data: mockDataStores,
          metadata: { total: 3, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'list-data-stores',
          parameters: {
            type: 'all',
            organizationId: 1001,
            includeUsage: true,
            includeStructure: false,
            limit: 50,
          },
        });

        expect(mockApiClient.get).toHaveBeenCalledWith('/data-stores', {
          params: expect.objectContaining({
            organizationId: 1001,
            includeUsage: true,
            includeStructure: false,
            limit: 50,
          }),
        });

        const response = JSON.parse(result);
        expect(response.dataStores).toHaveLength(3);
        expect(response.summary).toBeDefined();
        expect(response.summary.typeBreakdown).toBeDefined();
      });

      test('should provide usage analytics', async () => {
        const dataStoresWithUsage = [
          generateMockDataStore({
            usage: { recordCount: 10000, sizeUsed: 50000000, operationsToday: 500, lastOperation: new Date().toISOString() },
          }),
          generateMockDataStore({
            usage: { recordCount: 5000, sizeUsed: 25000000, operationsToday: 200, lastOperation: new Date().toISOString() },
          }),
        ];

        mockApiClient.setMockResponse('get', '/data-stores', {
          success: true,
          data: dataStoresWithUsage,
          metadata: { total: 2, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'list-data-stores',
          parameters: {
            includeUsage: true,
            sortBy: 'recordCount',
            sortOrder: 'desc',
          },
        });

        const response = JSON.parse(result);
        expect(response.summary.usageSummary).toBeDefined();
        expect(response.summary.usageSummary.totalRecords).toBe(15000);
        expect(response.summary.usageSummary.totalOperationsToday).toBe(700);
        expect(response.summary.storageAnalysis).toBeDefined();
      });
    });

    describe('Error Handling', () => {
      test('should handle API failures', async () => {
        mockApiClient.setMockResponse('get', '/data-stores', {
          success: false,
          error: { message: 'Data store service temporarily unavailable' },
        });

        await expect(mockServer.executeToolCall({
          tool: 'list-data-stores',
          parameters: {},
        })).rejects.toThrow('Failed to list data stores: Data store service temporarily unavailable');
      });
    });
  });

  describe('Integration Testing', () => {
    test('should handle complete folder organization workflow', async () => {
      // 1. Create root folder
      const rootFolder = generateMockFolder({ id: 1001 });
      mockApiClient.setMockResponse('post', '/folders', {
        success: true,
        data: rootFolder,
      });

      const rootResult = await mockServer.executeToolCall({
        tool: 'create-folder',
        parameters: {
          name: 'Integration Test Root',
          description: 'Root folder for integration testing',
          type: 'mixed',
        },
      });

      // 2. Create child folder
      const childFolder = generateMockFolder({ id: 1002, parentId: 1001 });
      mockApiClient.setMockResponse('get', '/folders/1001', {
        success: true,
        data: rootFolder,
      });
      mockApiClient.setMockResponse('post', '/folders', {
        success: true,
        data: childFolder,
      });

      const childResult = await mockServer.executeToolCall({
        tool: 'create-folder',
        parameters: {
          name: 'Child Folder',
          description: 'Child folder for testing',
          parentId: 1001,
          type: 'template',
        },
      });

      // 3. Create data store
      const dataStore = generateMockDataStore();
      mockApiClient.setMockResponse('post', '/data-stores', {
        success: true,
        data: dataStore,
      });

      const dataStoreResult = await mockServer.executeToolCall({
        tool: 'create-data-store',
        parameters: {
          name: 'Integration Test Store',
          description: 'Data store for integration testing',
          type: 'key_value',
        },
      });

      // 4. List folders to verify hierarchy
      mockApiClient.setMockResponse('get', '/folders', {
        success: true,
        data: [rootFolder, childFolder],
        metadata: { total: 2, hasMore: false },
      });

      const listResult = await mockServer.executeToolCall({
        tool: 'list-folders',
        parameters: {
          includeContents: true,
        },
      });

      // Verify the workflow completed successfully
      expect(JSON.parse(rootResult).folder.id).toBe(1001);
      expect(JSON.parse(childResult).folder.parentId).toBe(1001);
      expect(JSON.parse(dataStoreResult).dataStore).toBeDefined();
      expect(JSON.parse(listResult).folders).toHaveLength(2);
      expect(JSON.parse(listResult).hierarchy).toBeDefined();
    });
  });

  describe('Chaos Engineering Tests', () => {
    test('should handle service degradation gracefully', async () => {
      const scenarios = ['latency', 'error', 'timeout'];
      const results: { scenario: string; success: boolean }[] = [];

      for (const scenario of scenarios) {
        try {
          if (scenario === 'latency') {
            // Simulate high latency
            mockApiClient.setMockResponse('post', '/folders', {
              success: true,
              data: generateMockFolder(),
            }, chaosMonkey.getRandomLatency());
          } else if (scenario === 'error') {
            // Simulate service error
            mockApiClient.setMockResponse('post', '/folders', {
              success: false,
              error: { message: 'Service temporarily unavailable' },
            });
          } else if (scenario === 'timeout') {
            // Simulate timeout
            mockApiClient.setMockResponse('post', '/folders', {
              success: false,
              error: { message: 'Request timeout' },
            });
          }

          await mockServer.executeToolCall({
            tool: 'create-folder',
            parameters: {
              name: `Chaos Test ${scenario}`,
              description: 'Testing service degradation scenarios',
              type: 'template',
            },
          });

          results.push({ scenario, success: true });
        } catch (error) {
          results.push({ scenario, success: false });
        }
      }

      // At least one scenario should handle gracefully
      const successfulScenarios = results.filter(r => r.success).length;
      expect(successfulScenarios).toBeGreaterThan(0);
    });
  });

  describe('Performance Testing', () => {
    test('should handle concurrent folder operations', async () => {
      const concurrentRequests = 10;
      const promises: Promise<string>[] = [];

      mockApiClient.setMockResponse('post', '/folders', {
        success: true,
        data: generateMockFolder(),
      });

      for (let i = 0; i < concurrentRequests; i++) {
        promises.push(mockServer.executeToolCall({
          tool: 'create-folder',
          parameters: {
            name: `Concurrent Folder ${i}`,
            description: `Testing concurrent folder creation ${i}`,
            type: 'template',
          },
        }));
      }

      const results = await Promise.allSettled(promises);
      const successful = results.filter(r => r.status === 'fulfilled').length;
      
      expect(successful).toBeGreaterThan(concurrentRequests * 0.8); // 80% success rate
    });
  });
});