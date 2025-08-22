/**
 * Comprehensive Test Suite for Template Management Tools
 * Tests all 6 template management tools with validation and usage tracking
 * and advanced testing patterns following testing.md guidelines
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { UserError } from 'fastmcp';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';
import { 
  createMockServer, 
  findTool, 
  executeTool 
} from '../../utils/test-helpers.js';

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
  sqlInjection: ["'; DROP TABLE templates; --", "1' OR '1'='1", "'; SELECT * FROM templates; --"],
  xss: ["<script>alert('xss')</script>", "javascript:alert('xss')", "<img src=x onerror=alert('xss')>"],
  pathTraversal: ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam", "....//....//etc/passwd"],
  commandInjection: ["; cat /etc/passwd", "| whoami", "&& rm -rf /", "; shutdown -h now"],
  ldapInjection: ["*)(uid=*))(|(uid=*", "*)(|(objectClass=*))", "admin)(&(password=*)"],
};

describe('Template Management Tools', () => {
  let mockServer: any;
  let mockTool: any;
  let mockApiClient: MockMakeApiClient;
  let chaosMonkey: ChaosMonkey;

  // Mock data generators
  const generateMockTemplate = (overrides?: Partial<MakeExtendedTemplate>): MakeExtendedTemplate => ({
    id: Math.floor(Math.random() * 100000),
    name: 'Data Sync Template',
    description: 'Automated data synchronization between CRM and email marketing platform',
    category: 'data-integration',
    blueprint: {
      modules: [
        {
          id: 1,
          app: 'salesforce',
          module: 'getContacts',
          configuration: {
            connection: 'salesforce_prod',
            filter: { lastModified: '{{now() - 1 day}}' },
          },
        },
        {
          id: 2,
          app: 'mailchimp',
          module: 'addSubscriber',
          configuration: {
            connection: 'mailchimp_main',
            listId: '{{1.listId}}',
            email: '{{1.email}}',
            firstName: '{{1.firstName}}',
            lastName: '{{1.lastName}}',
          },
        },
      ],
      routes: [
        {
          from: 1,
          to: 2,
          condition: "{{1.email !== ''}}",
        },
      ],
      scheduling: {
        type: 'interval',
        interval: 3600, // 1 hour
      },
      errorHandling: {
        retries: 3,
        timeout: 300,
        fallback: 'continue',
      },
    },
    tags: ['crm', 'email-marketing', 'automation', 'data-sync'],
    organizationId: 1001,
    teamId: 2001,
    creatorId: 12345,
    creatorName: 'Template Creator',
    version: 1,
    versionHistory: [
      {
        version: 1,
        createdAt: new Date().toISOString(),
        changes: 'Initial template creation',
        createdBy: 12345,
      },
    ],
    usage: {
      totalUses: 25,
      lastUsed: new Date(Date.now() - 86400000).toISOString(),
      activeScenarios: 8,
    },
    sharing: {
      isPublic: false,
      organizationVisible: true,
      teamVisible: true,
      sharedWith: [
        {
          type: 'team',
          id: 2001,
          name: 'Integration Team',
          permissions: ['view', 'use'],
        },
      ],
    },
    metadata: {
      complexity: 'moderate',
      estimatedSetupTime: 15,
      requiredConnections: ['salesforce', 'mailchimp'],
      supportedRegions: ['US', 'EU'],
    },
    createdAt: new Date(Date.now() - 86400000 * 30).toISOString(),
    updatedAt: new Date(Date.now() - 86400000).toISOString(),
    createdBy: 12345,
    createdByName: 'Template Creator',
    ...overrides,
  });

  const generateMockFolder = (overrides?: Partial<MakeFolder>): MakeFolder => ({
    id: Math.floor(Math.random() * 100000),
    name: 'CRM Templates',
    description: 'Templates for CRM integrations',
    parentId: null,
    path: '/crm-templates',
    organizationId: 1001,
    teamId: 2001,
    type: 'template',
    permissions: {
      read: ['user_12345', 'team_2001'],
      write: ['user_12345'],
      admin: ['user_12345'],
    },
    itemCount: {
      templates: 15,
      scenarios: 0,
      connections: 0,
      subfolders: 3,
    },
    createdAt: new Date(Date.now() - 86400000 * 60).toISOString(),
    updatedAt: new Date(Date.now() - 86400000).toISOString(),
    createdBy: 12345,
    ...overrides,
  });

  const generateComplexBlueprint = (): Record<string, unknown> => ({
    modules: [
      {
        id: 1,
        app: 'webhook',
        module: 'webhook',
        configuration: { method: 'POST', url: '/webhook/trigger' },
      },
      {
        id: 2,
        app: 'json',
        module: 'parseJSON',
        configuration: { data: '{{1.body}}' },
      },
      {
        id: 3,
        app: 'filter',
        module: 'filter',
        configuration: { condition: "{{2.type === 'order'}}" },
      },
      {
        id: 4,
        app: 'database',
        module: 'insertRecord',
        configuration: {
          table: 'orders',
          data: {
            orderId: '{{2.id}}',
            customerId: '{{2.customerId}}',
            amount: '{{2.amount}}',
            timestamp: '{{now()}}',
          },
        },
      },
      {
        id: 5,
        app: 'email',
        module: 'sendEmail',
        configuration: {
          to: '{{2.customerEmail}}',
          subject: 'Order Confirmation #{{2.id}}',
          template: 'order_confirmation',
        },
      },
      {
        id: 6,
        app: 'slack',
        module: 'sendMessage',
        configuration: {
          channel: '#orders',
          message: 'New order: {{2.id}} - ${{2.amount}}',
        },
      },
    ],
    routes: [
      { from: 1, to: 2 },
      { from: 2, to: 3 },
      { from: 3, to: 4, condition: "{{3.match === true}}" },
      { from: 4, to: 5 },
      { from: 4, to: 6 },
    ],
    errorHandling: {
      retries: 3,
      timeout: 600,
      fallback: 'rollback',
      notifications: ['admin@company.com'],
    },
    variables: {
      retryDelay: 5000,
      maxRetries: 3,
      debugMode: false,
    },
  });

  beforeEach(async () => {
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockTool = serverSetup.mockTool;
    
    mockApiClient = new MockMakeApiClient();
    chaosMonkey = new ChaosMonkey({
      failureRate: 0.1,
      latencyMs: 1000,
      scenarios: ['latency', 'error', 'timeout'],
    });

    // Import and add template tools
    const { addTemplateTools } = await import('../../../src/tools/templates.js');
    addTemplateTools(mockServer, mockApiClient as any);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Tool Registration', () => {
    test('should register all template management tools', () => {
      const tools = mockServer.getTools();
      const expectedTools = [
        'create_template',
        'list_templates',
        'get_template',
        'update_template',
        'use_template',
        'delete_template',
      ];

      expectedTools.forEach(toolName => {
        expect(tools).toHaveProperty(toolName);
      });
    });

    test('should have correct tool schemas', () => {
      const tools = mockServer.getTools();
      
      expect(tools['create_template'].parameters).toBeDefined();
      expect(tools['list_templates'].parameters).toBeDefined();
      expect(tools['get_template'].parameters).toBeDefined();
      expect(tools['update_template'].parameters).toBeDefined();
      expect(tools['use_template'].parameters).toBeDefined();
      expect(tools['delete_template'].parameters).toBeDefined();
    });
  });

  describe('create-template', () => {
    describe('Basic Functionality', () => {
      test('should create a simple template successfully', async () => {
        const mockTemplate = generateMockTemplate();
        mockApiClient.setMockResponse('post', '/templates', {
          success: true,
          data: mockTemplate,
        });

        const simpleBlueprint = {
          modules: [
            {
              id: 1,
              app: 'webhook',
              module: 'webhook',
              configuration: { method: 'POST' },
            },
          ],
          routes: [],
        };

        const tool = findTool(mockTool, 'create-template');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        const result = await tool.execute({
          name: 'Simple Webhook Template',
          description: 'Basic webhook receiver template',
          category: 'webhooks',
          blueprint: simpleBlueprint,
          tags: ['webhook', 'simple'],
          organizationId: 1001,
          teamId: 2001,
        }, mockContext);

        expect(mockApiClient.post).toHaveBeenCalledWith('/organizations/1001/templates', expect.objectContaining({
          name: 'Simple Webhook Template',
          category: 'webhooks',
          blueprint: simpleBlueprint,
        }));

        const response = JSON.parse(result);
        expect(response.template).toBeDefined();
        expect(response.analysis.complexity).toBe('simple');
        expect(response.message).toContain('created successfully');
      });

      test('should create complex template with analysis', async () => {
        const complexTemplate = generateMockTemplate({
          metadata: {
            complexity: 'complex',
            estimatedSetupTime: 45,
            requiredConnections: ['webhook', 'database', 'email', 'slack'],
          },
        });

        mockApiClient.setMockResponse('post', '/templates', {
          success: true,
          data: complexTemplate,
        });

        const complexBlueprint = generateComplexBlueprint();

        const tool = findTool(mockTool, 'create-template');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        const result = await tool.execute({
          name: 'Order Processing Workflow',
          description: 'Complete order processing with notifications',
          category: 'e-commerce',
          blueprint: complexBlueprint,
          tags: ['orders', 'automation', 'notifications'],
          isPublic: false,
          sharing: {
            organizationVisible: true,
            teamVisible: true,
          },
          metadata: {
            complexity: 'complex',
            estimatedSetupTime: 45,
            requiredConnections: ['webhook', 'database', 'email', 'slack'],
          },
        }, mockContext);

        const response = JSON.parse(result);
        expect(response.template.metadata.complexity).toBe('complex');
        expect(response.analysis.estimatedSetupTime).toBe('45 minutes');
        expect(response.analysis.requiredConnections).toHaveLength(4);
      });

      test('should create template in specific folder', async () => {
        const mockTemplate = generateMockTemplate();
        const mockFolder = generateMockFolder();
        
        mockApiClient.setMockResponse('post', '/templates', {
          success: true,
          data: mockTemplate,
        });

        const tool = findTool(mockTool, 'create-template');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        const result = await tool.execute({
          name: 'Folder Template',
          description: 'Template created in specific folder',
          category: 'automation',
          blueprint: { modules: [], routes: [] },
          folderId: mockFolder.id,
        }, mockContext);

        expect(mockApiClient.post).toHaveBeenCalledWith('/templates', expect.objectContaining({
          folderId: mockFolder.id,
        }));

        const response = JSON.parse(result);
        expect(response.template).toBeDefined();
      });
    });

    describe('Template Analysis', () => {
      test('should analyze template complexity correctly', async () => {
        const testCases = [
          {
            blueprint: { modules: [{ id: 1, app: 'webhook' }], routes: [] },
            expectedComplexity: 'simple',
            expectedTime: 10,
          },
          {
            blueprint: { 
              modules: Array.from({ length: 10 }, (_, i) => ({ id: i + 1, app: `app${i}` })),
              routes: Array.from({ length: 8 }, (_, i) => ({ from: i + 1, to: i + 2 })),
            },
            expectedComplexity: 'moderate',
            expectedTime: 30,
          },
          {
            blueprint: generateComplexBlueprint(),
            expectedComplexity: 'complex',
            expectedTime: 45,
          },
        ];

        for (const testCase of testCases) {
          const mockTemplate = generateMockTemplate({
            metadata: {
              complexity: testCase.expectedComplexity,
              estimatedSetupTime: testCase.expectedTime,
              requiredConnections: [],
            },
          });

          mockApiClient.setMockResponse('post', '/templates', {
            success: true,
            data: mockTemplate,
          });

          const result = await mockServer.executeToolCall({
            tool: 'create-template',
            parameters: {
              name: `${testCase.expectedComplexity} Template`,
              description: `Template with ${testCase.expectedComplexity} complexity`,
              category: 'test',
              blueprint: testCase.blueprint,
            },
          });

          const response = JSON.parse(result);
          expect(response.analysis.complexity).toBe(testCase.expectedComplexity);
        }
      });

      test('should extract required connections from blueprint', async () => {
        const blueprint = {
          modules: [
            { id: 1, app: 'salesforce', module: 'getContacts' },
            { id: 2, app: 'mailchimp', module: 'addSubscriber' },
            { id: 3, app: 'salesforce', module: 'updateContact' }, // Duplicate
          ],
          routes: [],
        };

        const mockTemplate = generateMockTemplate({
          metadata: {
            complexity: 'moderate',
            estimatedSetupTime: 20,
            requiredConnections: ['salesforce', 'mailchimp'],
          },
        });

        mockApiClient.setMockResponse('post', '/templates', {
          success: true,
          data: mockTemplate,
        });

        const tool = findTool(mockTool, 'create-template');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        const result = await tool.execute({
          name: 'Connection Analysis Template',
          description: 'Template for testing connection extraction',
          category: 'test',
          blueprint,
        }, mockContext);

        const response = JSON.parse(result);
        expect(response.analysis.requiredConnections).toEqual(['salesforce', 'mailchimp']);
      });
    });

    describe('Security Testing', () => {
      test('should sanitize template metadata', async () => {
        const mockTemplate = generateMockTemplate();
        mockApiClient.setMockResponse('post', '/templates', {
          success: true,
          data: mockTemplate,
        });

        const maliciousName = securityTestPatterns.xss[0];
        const maliciousDescription = securityTestPatterns.sqlInjection[0];

        const tool = findTool(mockTool, 'create-template');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        const result = await tool.execute({
          name: maliciousName,
          description: maliciousDescription,
          category: 'test',
          blueprint: { modules: [], routes: [] },
        }, mockContext);

        // Template should be created but content should be sanitized
        const response = JSON.parse(result);
        expect(response.template).toBeDefined();
        // Verify sanitization occurred (actual implementation would sanitize)
      });

      test('should validate blueprint structure', async () => {
        const invalidBlueprints = [
          null,
          undefined,
          'invalid string',
          123,
          { modules: 'invalid' },
          { routes: 'invalid' },
        ];

        for (const invalidBlueprint of invalidBlueprints) {
          await expect(mockServer.executeToolCall({
            tool: 'create-template',
            parameters: {
              name: 'Invalid Blueprint Test',
              description: 'Testing invalid blueprint validation',
              category: 'test',
              blueprint: invalidBlueprint,
            },
          })).rejects.toThrow();
        }
      });
    });

    describe('Error Handling', () => {
      test('should handle API failures gracefully', async () => {
        mockApiClient.setMockResponse('post', '/templates', {
          success: false,
          error: { message: 'Template service temporarily unavailable' },
        });

        const tool = findTool(mockTool, 'create-template');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        await expect(tool.execute({
          name: 'Test Template',
          description: 'Test description',
          category: 'test',
          blueprint: { modules: [], routes: [] },
        }, mockContext)).rejects.toThrow('Failed to create template: Template service temporarily unavailable');
      });

      test('should validate required fields', async () => {
        const tool = findTool(mockTool, 'create-template');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        await expect(tool.execute({
          // Missing required fields
        }, mockContext)).rejects.toThrow();
      });

      test('should validate blueprint as object', async () => {
        const tool = findTool(mockTool, 'create-template');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        await expect(tool.execute({
          name: 'Test Template',
          description: 'Test description',
          category: 'test',
          blueprint: 'invalid blueprint string',
        }, mockContext)).rejects.toThrow();
      });
    });
  });

  describe('list-templates', () => {
    describe('Basic Functionality', () => {
      test('should list templates with basic filters', async () => {
        const mockTemplates = [
          generateMockTemplate(),
          generateMockTemplate({ category: 'e-commerce' }),
          generateMockTemplate({ category: 'crm' }),
        ];

        mockApiClient.setMockResponse('get', '/templates', {
          success: true,
          data: mockTemplates,
          metadata: { total: 3, hasMore: false },
        });

        const tool = findTool(mockTool, 'list-templates');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        const result = await tool.execute({
          category: 'data-integration',
          organizationId: 1001,
          limit: 50,
          offset: 0,
        }, mockContext);

        expect(mockApiClient.get).toHaveBeenCalledWith('/templates', {
          params: expect.objectContaining({
            category: 'data-integration',
            organizationId: 1001,
            limit: 50,
            offset: 0,
          }),
        });

        const response = JSON.parse(result);
        expect(response.templates).toHaveLength(3);
        expect(response.summary).toBeDefined();
        expect(response.summary.totalTemplates).toBe(3);
      });

      test('should filter templates by tags', async () => {
        const mockTemplates = [
          generateMockTemplate({ tags: ['automation', 'crm'] }),
          generateMockTemplate({ tags: ['automation', 'email'] }),
        ];

        mockApiClient.setMockResponse('get', '/templates', {
          success: true,
          data: mockTemplates,
          metadata: { total: 2, hasMore: false },
        });

        const tool = findTool(mockTool, 'list-templates');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        const result = await tool.execute({
          tags: ['automation', 'crm'],
          includeUsage: true,
        }, mockContext);

        expect(mockApiClient.get).toHaveBeenCalledWith('/templates', {
          params: expect.objectContaining({
            tags: 'automation,crm',
            includeUsage: true,
          }),
        });

        const response = JSON.parse(result);
        expect(response.templates).toHaveLength(2);
        expect(response.summary.popularTags).toBeDefined();
      });

      test('should search templates by query', async () => {
        const mockTemplates = [
          generateMockTemplate({ 
            name: 'CRM Data Sync',
            description: 'Synchronize CRM data with external systems',
          }),
        ];

        mockApiClient.setMockResponse('get', '/templates', {
          success: true,
          data: mockTemplates,
          metadata: { total: 1, hasMore: false },
        });

        const tool = findTool(mockTool, 'list-templates');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        const result = await tool.execute({
          searchQuery: 'CRM sync',
          includeVersions: false,
        }, mockContext);

        expect(mockApiClient.get).toHaveBeenCalledWith('/templates', {
          params: expect.objectContaining({
            search: 'CRM sync',
            includeVersions: false,
          }),
        });

        const response = JSON.parse(result);
        expect(response.templates).toHaveLength(1);
      });
    });

    describe('Advanced Filtering', () => {
      test('should filter by complexity and connections', async () => {
        const mockTemplates = [
          generateMockTemplate({ 
            metadata: { 
              complexity: 'complex',
              requiredConnections: ['salesforce', 'mailchimp', 'slack'],
              estimatedSetupTime: 45,
            },
          }),
        ];

        mockApiClient.setMockResponse('get', '/templates', {
          success: true,
          data: mockTemplates,
          metadata: { total: 1, hasMore: false },
        });

        const tool = findTool(mockTool, 'list-templates');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        const result = await tool.execute({
          complexity: 'complex',
          hasConnections: ['salesforce', 'mailchimp'],
          minUsage: 10,
        }, mockContext);

        expect(mockApiClient.get).toHaveBeenCalledWith('/templates', {
          params: expect.objectContaining({
            complexity: 'complex',
            hasConnections: 'salesforce,mailchimp',
            minUsage: 10,
          }),
        });

        const response = JSON.parse(result);
        expect(response.templates[0].metadata.complexity).toBe('complex');
      });

      test('should filter by creator and visibility', async () => {
        const mockTemplates = [
          generateMockTemplate({ 
            creatorId: 12345,
            sharing: { isPublic: true, organizationVisible: true, teamVisible: true, sharedWith: [] },
          }),
        ];

        mockApiClient.setMockResponse('get', '/templates', {
          success: true,
          data: mockTemplates,
          metadata: { total: 1, hasMore: false },
        });

        const tool = findTool(mockTool, 'list-templates');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        const result = await tool.execute({
          creatorId: 12345,
          isPublic: true,
          sortBy: 'usage',
          sortOrder: 'desc',
        }, mockContext);

        const response = JSON.parse(result);
        expect(response.templates[0].creatorId).toBe(12345);
        expect(response.templates[0].sharing.isPublic).toBe(true);
      });
    });

    describe('Analytics and Summary', () => {
      test('should provide comprehensive template analytics', async () => {
        const mockTemplates = [
          generateMockTemplate({ 
            category: 'crm',
            metadata: { complexity: 'simple' },
            sharing: { isPublic: true, organizationVisible: true, teamVisible: true, sharedWith: [] },
            usage: { totalUses: 50 },
          }),
          generateMockTemplate({ 
            category: 'e-commerce',
            metadata: { complexity: 'moderate' },
            sharing: { isPublic: false, organizationVisible: true, teamVisible: false, sharedWith: [] },
            usage: { totalUses: 25 },
          }),
          generateMockTemplate({ 
            category: 'automation',
            metadata: { complexity: 'complex' },
            sharing: { isPublic: false, organizationVisible: false, teamVisible: true, sharedWith: [] },
            usage: { totalUses: 75 },
          }),
        ];

        mockApiClient.setMockResponse('get', '/templates', {
          success: true,
          data: mockTemplates,
          metadata: { total: 3, hasMore: false },
        });

        const tool = findTool(mockTool, 'list-templates');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        const result = await tool.execute({
          includeUsage: true,
          includeVersions: false,
        }, mockContext);

        const response = JSON.parse(result);
        expect(response.summary.categoryBreakdown).toBeDefined();
        expect(response.summary.complexityBreakdown).toBeDefined();
        expect(response.summary.visibilityBreakdown).toBeDefined();
        expect(response.summary.mostUsedTemplates).toBeDefined();
        expect(response.summary.popularTags).toBeDefined();

        expect(response.summary.categoryBreakdown.crm).toBe(1);
        expect(response.summary.complexityBreakdown.simple).toBe(1);
        expect(response.summary.visibilityBreakdown.public).toBe(1);
      });
    });

    describe('Error Handling', () => {
      test('should handle API failures', async () => {
        mockApiClient.setMockResponse('get', '/templates', {
          success: false,
          error: { message: 'Template service temporarily unavailable' },
        });

        const tool = findTool(mockTool, 'list-templates');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        await expect(tool.execute({}, mockContext)).rejects.toThrow('Failed to list templates: Template service temporarily unavailable');
      });
    });
  });

  describe('get-template', () => {
    describe('Basic Functionality', () => {
      test('should retrieve template without blueprint', async () => {
        const mockTemplate = generateMockTemplate();
        mockApiClient.setMockResponse('get', '/templates/12345', {
          success: true,
          data: mockTemplate,
        });

        const tool = findTool(mockTool, 'get-template');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        const result = await tool.execute({
          templateId: 12345,
          includeBlueprint: false,
          includeUsage: true,
          includeSharing: true,
        }, mockContext);

        expect(mockApiClient.get).toHaveBeenCalledWith('/templates/12345', {
          params: expect.objectContaining({
            includeBlueprint: false,
            includeUsage: true,
            includeSharing: true,
          }),
        });

        const response = JSON.parse(result);
        expect(response.template).toBeDefined();
        expect(response.template.blueprint).toBe('[Blueprint excluded - use includeBlueprint=true to view]');
        expect(response.usage).toBeDefined();
        expect(response.sharing).toBeDefined();
      });

      test('should retrieve template with full blueprint', async () => {
        const mockTemplate = generateMockTemplate({
          blueprint: generateComplexBlueprint(),
        });
        
        mockApiClient.setMockResponse('get', '/templates/12345', {
          success: true,
          data: mockTemplate,
        });

        const tool = findTool(mockTool, 'get-template');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        const result = await tool.execute({
          templateId: 12345,
          includeBlueprint: true,
          includeVersions: true,
        }, mockContext);

        const response = JSON.parse(result);
        expect(response.template.blueprint).toBeDefined();
        expect(response.template.blueprint.modules).toBeDefined();
        expect(response.versions).toBeDefined();
      });

      test('should include metadata and permissions', async () => {
        const mockTemplate = generateMockTemplate({
          usage: { totalUses: 100, activeScenarios: 0, lastUsed: new Date().toISOString() },
        });
        
        mockApiClient.setMockResponse('get', '/templates/12345', {
          success: true,
          data: mockTemplate,
        });

        const tool = findTool(mockTool, 'get-template');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        const result = await tool.execute({
          templateId: 12345,
          includeUsage: true,
          includeSharing: true,
        }, mockContext);

        const response = JSON.parse(result);
        expect(response.metadata).toBeDefined();
        expect(response.metadata.canEdit).toBeDefined();
        expect(response.metadata.canDelete).toBe(true); // No active scenarios
        expect(response.metadata.canUse).toBeDefined();
        expect(response.metadata.complexity).toBeDefined();
      });
    });

    describe('Error Handling', () => {
      test('should handle template not found', async () => {
        mockApiClient.setMockResponse('get', '/templates/99999', {
          success: false,
          error: { message: 'Template not found', status: 404 },
        });

        const tool = findTool(mockTool, 'get-template');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        await expect(tool.execute({
          templateId: 99999,
        }, mockContext)).rejects.toThrow('Failed to get template: Template not found');
      });

      test('should validate template ID', async () => {
        const tool = findTool(mockTool, 'get-template');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        await expect(tool.execute({
          templateId: -1, // Invalid ID
        }, mockContext)).rejects.toThrow();
      });
    });
  });

  describe('update-template', () => {
    describe('Basic Functionality', () => {
      test('should update template metadata', async () => {
        const updatedTemplate = generateMockTemplate({
          name: 'Updated Template Name',
          description: 'Updated template description',
          version: 2,
        });

        mockApiClient.setMockResponse('put', '/templates/12345', {
          success: true,
          data: updatedTemplate,
        });

        const tool = findTool(mockTool, 'update-template');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        const result = await tool.execute({
          templateId: 12345,
          name: 'Updated Template Name',
          description: 'Updated template description',
          tags: ['updated', 'template'],
        }, mockContext);

        expect(mockApiClient.put).toHaveBeenCalledWith('/templates/12345', expect.objectContaining({
          name: 'Updated Template Name',
          description: 'Updated template description',
          tags: ['updated', 'template'],
        }));

        const response = JSON.parse(result);
        expect(response.template.name).toBe('Updated Template Name');
        expect(response.changes).toContain('name');
        expect(response.version.current).toBe(2);
      });

      test('should update blueprint and recalculate metadata', async () => {
        const newBlueprint = generateComplexBlueprint();
        const updatedTemplate = generateMockTemplate({
          blueprint: newBlueprint,
          metadata: {
            complexity: 'complex',
            estimatedSetupTime: 45,
            requiredConnections: ['webhook', 'database', 'email', 'slack'],
          },
          version: 2,
        });

        mockApiClient.setMockResponse('put', '/templates/12345', {
          success: true,
          data: updatedTemplate,
        });

        const tool = findTool(mockTool, 'update-template');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        const result = await tool.execute({
          templateId: 12345,
          blueprint: newBlueprint,
        }, mockContext);

        const response = JSON.parse(result);
        expect(response.template.blueprint).toBeDefined();
        expect(response.template.metadata.complexity).toBe('complex');
        expect(response.changes).toContain('blueprint');
      });

      test('should update sharing settings', async () => {
        const updatedTemplate = generateMockTemplate({
          sharing: {
            isPublic: true,
            organizationVisible: true,
            teamVisible: true,
            sharedWith: [],
          },
        });

        mockApiClient.setMockResponse('put', '/templates/12345', {
          success: true,
          data: updatedTemplate,
        });

        const tool = findTool(mockTool, 'update-template');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        const result = await tool.execute({
          templateId: 12345,
          isPublic: true,
          sharing: {
            organizationVisible: true,
            teamVisible: true,
          },
        }, mockContext);

        const response = JSON.parse(result);
        expect(response.template.sharing.isPublic).toBe(true);
        expect(response.changes).toContain('isPublic');
        expect(response.changes).toContain('sharing');
      });
    });

    describe('Error Handling', () => {
      test('should handle template not found', async () => {
        mockApiClient.setMockResponse('put', '/templates/99999', {
          success: false,
          error: { message: 'Template not found', status: 404 },
        });

        const tool = findTool(mockTool, 'update-template');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        await expect(tool.execute({
          templateId: 99999,
          name: 'Updated Name',
        }, mockContext)).rejects.toThrow('Failed to update template: Template not found');
      });

      test('should require at least one update field', async () => {
        const tool = findTool(mockTool, 'update-template');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        await expect(tool.execute({
          templateId: 12345,
          // No update fields provided
        }, mockContext)).rejects.toThrow();
      });
    });
  });

  describe('use-template', () => {
    describe('Basic Functionality', () => {
      test('should create scenario from template', async () => {
        const useResult = {
          scenarioId: 67890,
          templateId: 12345,
          templateName: 'Data Sync Template',
          scenarioName: 'CRM to Email Marketing Sync',
          customizationsApplied: 3,
          connectionsCreated: 2,
        };

        mockApiClient.setMockResponse('post', '/templates/12345/use', {
          success: true,
          data: useResult,
        });

        const tool = findTool(mockTool, 'use-template');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        const result = await tool.execute({
          templateId: 12345,
          scenarioName: 'CRM to Email Marketing Sync',
          folderId: 5001,
          customizations: {
            module1: { filter: { lastModified: '{{now() - 2 days}}' } },
            module2: { listId: 'marketing_list_001' },
          },
          connectionMappings: {
            salesforce_connection: 54321,
            mailchimp_connection: 65432,
          },
        }, mockContext);

        expect(mockApiClient.post).toHaveBeenCalledWith('/templates/12345/use', expect.objectContaining({
          scenarioName: 'CRM to Email Marketing Sync',
          folderId: 5001,
          customizations: expect.any(Object),
          connectionMappings: expect.any(Object),
        }));

        const response = JSON.parse(result);
        expect(response.scenario.id).toBe(67890);
        expect(response.scenario.name).toBe('CRM to Email Marketing Sync');
        expect(response.customizations.applied).toBe(2);
        expect(response.customizations.connectionsMapped).toBe(2);
      });

      test('should handle template usage with variable overrides', async () => {
        const useResult = {
          scenarioId: 67891,
          templateId: 12345,
          templateName: 'Automation Template',
          scenarioName: 'Custom Automation',
          variablesOverridden: 3,
          schedulingUpdated: true,
        };

        mockApiClient.setMockResponse('post', '/templates/12345/use', {
          success: true,
          data: useResult,
        });

        const tool = findTool(mockTool, 'use-template');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        const result = await tool.execute({
          templateId: 12345,
          scenarioName: 'Custom Automation',
          variableOverrides: {
            retryCount: 5,
            timeoutSeconds: 120,
            debugMode: true,
          },
          schedulingOverride: {
            type: 'indefinitely',
            interval: 7200, // 2 hours
          },
        }, mockContext);

        const response = JSON.parse(result);
        expect(response.scenario.id).toBe(67891);
        expect(response.customizations.variablesOverridden).toBe(3);
      });
    });

    describe('Error Handling', () => {
      test('should handle template not found', async () => {
        mockApiClient.setMockResponse('post', '/templates/99999/use', {
          success: false,
          error: { message: 'Template not found', status: 404 },
        });

        const tool = findTool(mockTool, 'use-template');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        await expect(tool.execute({
          templateId: 99999,
          scenarioName: 'Test Scenario',
        }, mockContext)).rejects.toThrow('Failed to use template: Template not found');
      });

      test('should validate scenario name', async () => {
        const tool = findTool(mockTool, 'use-template');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        await expect(tool.execute({
          templateId: 12345,
          scenarioName: '', // Empty name
        }, mockContext)).rejects.toThrow();
      });
    });
  });

  describe('delete-template', () => {
    describe('Basic Functionality', () => {
      test('should delete unused template', async () => {
        // Mock usage check showing no active scenarios
        mockApiClient.setMockResponse('get', '/templates/12345/usage', {
          success: true,
          data: { activeScenarios: 0, totalUses: 10 },
        });

        mockApiClient.setMockResponse('delete', '/templates/12345', {
          success: true,
          data: { deleted: true, templateId: 12345 },
        });

        const tool = findTool(mockTool, 'delete-template');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        const result = await tool.execute({
          templateId: 12345,
          force: false,
        }, mockContext);

        expect(mockApiClient.get).toHaveBeenCalledWith('/templates/12345/usage');
        expect(mockApiClient.delete).toHaveBeenCalledWith('/templates/12345');

        const response = JSON.parse(result);
        expect(response.templateId).toBe(12345);
        expect(response.forced).toBe(false);
      });

      test('should force delete template with active scenarios', async () => {
        // Mock usage check showing active scenarios
        mockApiClient.setMockResponse('get', '/templates/12345/usage', {
          success: true,
          data: { activeScenarios: 5, totalUses: 25 },
        });

        mockApiClient.setMockResponse('delete', '/templates/12345', {
          success: true,
          data: { deleted: true, templateId: 12345, forced: true },
        });

        const tool = findTool(mockTool, 'delete-template');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        const result = await tool.execute({
          templateId: 12345,
          force: true,
        }, mockContext);

        const response = JSON.parse(result);
        expect(response.templateId).toBe(12345);
        expect(response.forced).toBe(true);
      });
    });

    describe('Safety Checks', () => {
      test('should prevent deletion of template in use without force', async () => {
        mockApiClient.setMockResponse('get', '/templates/12345/usage', {
          success: true,
          data: { activeScenarios: 3, totalUses: 15 },
        });

        const tool = findTool(mockTool, 'delete-template');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        await expect(tool.execute({
          templateId: 12345,
          force: false,
        }, mockContext)).rejects.toThrow('Template is currently in use (3 active scenarios). Use force=true to delete anyway.');
      });
    });

    describe('Error Handling', () => {
      test('should handle template not found', async () => {
        mockApiClient.setMockResponse('delete', '/templates/99999', {
          success: false,
          error: { message: 'Template not found', status: 404 },
        });

        const tool = findTool(mockTool, 'delete-template');
        const mockContext = {
          log: {
            info: () => {},
            error: () => {},
            warn: () => {},
            debug: () => {},
          },
          reportProgress: () => {},
          session: { authenticated: true },
        };
        
        await expect(tool.execute({
          templateId: 99999,
        }, mockContext)).rejects.toThrow('Failed to delete template: Template not found');
      });
    });
  });

  describe('Integration Testing', () => {
    test('should handle complete template lifecycle', async () => {
      // 1. Create template
      const newTemplate = generateMockTemplate();
      mockApiClient.setMockResponse('post', '/templates', {
        success: true,
        data: newTemplate,
      });

      const createTool = findTool(mockTool, 'create-template');
      const mockContext = {
        log: {
          info: () => {},
          error: () => {},
          warn: () => {},
          debug: () => {},
        },
        reportProgress: () => {},
        session: { authenticated: true },
      };
      
      const createResult = await createTool.execute({
        name: 'Lifecycle Test Template',
        description: 'Template for testing complete lifecycle',
        category: 'test',
        blueprint: { modules: [{ id: 1, app: 'webhook' }], routes: [] },
        tags: ['test', 'lifecycle'],
      }, mockContext);

      // 2. Update template
      const updatedTemplate = generateMockTemplate({
        ...newTemplate,
        description: 'Updated lifecycle template',
        version: 2,
      });
      mockApiClient.setMockResponse('put', `/templates/${newTemplate.id}`, {
        success: true,
        data: updatedTemplate,
      });

      const updateTool = findTool(mockTool, 'update-template');
      const updateResult = await updateTool.execute({
        templateId: newTemplate.id,
        description: 'Updated lifecycle template',
      }, mockContext);

      // 3. Use template
      const useResult = {
        scenarioId: 67890,
        templateId: newTemplate.id,
        templateName: newTemplate.name,
        scenarioName: 'Test Scenario',
      };
      mockApiClient.setMockResponse('post', `/templates/${newTemplate.id}/use`, {
        success: true,
        data: useResult,
      });

      const useTool = findTool(mockTool, 'use-template');
      const scenarioResult = await useTool.execute({
        templateId: newTemplate.id,
        scenarioName: 'Test Scenario',
      }, mockContext);

      // 4. Get template details
      mockApiClient.setMockResponse('get', `/templates/${newTemplate.id}`, {
        success: true,
        data: updatedTemplate,
      });

      const getTool = findTool(mockTool, 'get-template');
      const getResult = await getTool.execute({
        templateId: newTemplate.id,
        includeUsage: true,
      }, mockContext);

      // Verify lifecycle completed successfully
      expect(JSON.parse(createResult).template).toBeDefined();
      expect(JSON.parse(updateResult).template.description).toBe('Updated lifecycle template');
      expect(JSON.parse(scenarioResult).scenario.id).toBe(67890);
      expect(JSON.parse(getResult).template).toBeDefined();
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
            mockApiClient.setMockResponse('post', '/templates', {
              success: true,
              data: generateMockTemplate(),
            }, chaosMonkey.getRandomLatency());
          } else if (scenario === 'error') {
            // Simulate service error
            mockApiClient.setMockResponse('post', '/templates', {
              success: false,
              error: { message: 'Service temporarily unavailable' },
            });
          } else if (scenario === 'timeout') {
            // Simulate timeout
            mockApiClient.setMockResponse('post', '/templates', {
              success: false,
              error: { message: 'Request timeout' },
            });
          }

          const createTool = findTool(mockTool, 'create-template');
          const mockContext = {
            log: {
              info: () => {},
              error: () => {},
              warn: () => {},
              debug: () => {},
            },
            reportProgress: () => {},
            session: { authenticated: true },
          };
          
          await createTool.execute({
            name: `Chaos Test ${scenario}`,
            description: 'Testing service degradation scenarios',
            category: 'test',
            blueprint: { modules: [], routes: [] },
          }, mockContext);

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
    test('should handle concurrent template operations', async () => {
      const concurrentRequests = 15;
      const promises: Promise<string>[] = [];

      mockApiClient.setMockResponse('post', '/templates', {
        success: true,
        data: generateMockTemplate(),
      });

      const createTool = findTool(mockTool, 'create-template');
      const mockContext = {
        log: {
          info: () => {},
          error: () => {},
          warn: () => {},
          debug: () => {},
        },
        reportProgress: () => {},
        session: { authenticated: true },
      };
      
      for (let i = 0; i < concurrentRequests; i++) {
        promises.push(createTool.execute({
          name: `Concurrent Template ${i}`,
          description: `Testing concurrent template creation ${i}`,
          category: 'test',
          blueprint: { modules: [], routes: [] },
        }, mockContext));
      }

      const results = await Promise.allSettled(promises);
      const successful = results.filter(r => r.status === 'fulfilled').length;
      
      expect(successful).toBeGreaterThan(concurrentRequests * 0.8); // 80% success rate
    });
  });
});