/**
 * Basic Test Suite for Compliance Policy Tools
 * Tests core functionality of enterprise compliance policy management tools
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { createMockServer } from '../../utils/test-helpers.js';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';

// Mock all dependencies first
jest.mock('fs/promises', () => ({
  mkdir: jest.fn().mockResolvedValue(undefined),
  readFile: jest.fn().mockResolvedValue(JSON.stringify({
    policies: {},
    metadata: { created: new Date().toISOString(), version: '1.0.0' }
  })),
  writeFile: jest.fn().mockResolvedValue(undefined),
}));

jest.mock('path', () => ({
  join: jest.fn((...args) => args.join('/')),
  dirname: jest.fn((p) => p.split('/').slice(0, -1).join('/')),
}));

jest.mock('../../../src/lib/logger.js', () => ({
  default: {
    child: jest.fn(() => ({
      info: jest.fn(),
      error: jest.fn(),
      warn: jest.fn(),
      debug: jest.fn(),
    })),
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
  },
}));

jest.mock('../../../src/lib/audit-logger.js', () => ({
  auditLogger: {
    logEvent: jest.fn().mockResolvedValue(undefined),
  },
}));

jest.mock('../../../src/tools/compliance-templates.js', () => ({
  getComplianceTemplate: jest.fn(),
  listComplianceTemplates: jest.fn(),
  getTemplateMetadata: jest.fn(),
}));

describe('Compliance Policy Tools - Basic Tests', () => {
  let mockServer: any;
  let mockTool: jest.MockedFunction<any>;
  let mockApiClient: MockMakeApiClient;
  let addCompliancePolicyTools: any;

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
  });

  describe('Tool Registration and Import', () => {
    it('should successfully import and register compliance policy tools', async () => {
      const { addCompliancePolicyTools: importedFunction } = await import('../../../src/tools/compliance-policy.js');
      addCompliancePolicyTools = importedFunction;
      
      // Should not throw an error
      expect(() => {
        addCompliancePolicyTools(mockServer, mockApiClient as any);
      }).not.toThrow();
      
      // Should call addTool for each tool
      expect(mockTool).toHaveBeenCalled();
      expect(mockTool.mock.calls.length).toBeGreaterThan(0);
    });

    it('should export the expected functions and types', async () => {
      const compliancePolicyModule = await import('../../../src/tools/compliance-policy.js');
      
      // Check that expected exports exist
      expect(compliancePolicyModule.addCompliancePolicyTools).toBeDefined();
      expect(typeof compliancePolicyModule.addCompliancePolicyTools).toBe('function');
      expect(compliancePolicyModule.default).toBeDefined();
    });

    it('should register all expected compliance policy tools', async () => {
      const { addCompliancePolicyTools: importedFunction } = await import('../../../src/tools/compliance-policy.js');
      addCompliancePolicyTools = importedFunction;
      
      addCompliancePolicyTools(mockServer, mockApiClient as any);
      
      const toolNames = mockTool.mock.calls.map(call => call[0].name);
      
      // Verify all expected tools are registered
      expect(toolNames).toContain('create-compliance-policy');
      expect(toolNames).toContain('validate-compliance');
      expect(toolNames).toContain('generate-compliance-report');
      expect(toolNames).toContain('list-compliance-policies');
      expect(toolNames).toContain('update-compliance-policy');
      expect(toolNames).toContain('get-compliance-templates');
      expect(toolNames).toContain('create-policy-from-template');
      
      // Should register exactly 7 tools
      expect(toolNames.length).toBe(7);
    });
  });

  describe('Tool Configuration Validation', () => {
    beforeEach(async () => {
      const { addCompliancePolicyTools: importedFunction } = await import('../../../src/tools/compliance-policy.js');
      addCompliancePolicyTools = importedFunction;
      addCompliancePolicyTools(mockServer, mockApiClient as any);
    });

    it('should have correctly structured create-compliance-policy tool', () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'create-compliance-policy')[0];
      
      expect(toolConfig.name).toBe('create-compliance-policy');
      expect(toolConfig.description).toBeDefined();
      expect(toolConfig.description).toContain('compliance policy');
      expect(toolConfig.parameters).toBeDefined();
      expect(typeof toolConfig.execute).toBe('function');
      expect(toolConfig.annotations).toBeDefined();
      expect(toolConfig.annotations.title).toBe('Compliance Policy Creation');
    });

    it('should have correctly structured validate-compliance tool', () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-compliance')[0];
      
      expect(toolConfig.name).toBe('validate-compliance');
      expect(toolConfig.description).toBeDefined();
      expect(toolConfig.description).toContain('validate compliance');
      expect(toolConfig.parameters).toBeDefined();
      expect(typeof toolConfig.execute).toBe('function');
    });

    it('should have correctly structured generate-compliance-report tool', () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'generate-compliance-report')[0];
      
      expect(toolConfig.name).toBe('generate-compliance-report');
      expect(toolConfig.description).toBeDefined();
      expect(toolConfig.description).toContain('compliance report');
      expect(toolConfig.parameters).toBeDefined();
      expect(typeof toolConfig.execute).toBe('function');
    });

    it('should have correctly structured template-related tools', () => {
      const templateTool = mockTool.mock.calls.find(call => call[0].name === 'get-compliance-templates')[0];
      const createFromTemplateTool = mockTool.mock.calls.find(call => call[0].name === 'create-policy-from-template')[0];
      
      expect(templateTool.name).toBe('get-compliance-templates');
      expect(templateTool.description).toContain('template');
      expect(createFromTemplateTool.name).toBe('create-policy-from-template');
      expect(createFromTemplateTool.description).toContain('template');
    });
  });

  describe('Schema Validation', () => {
    beforeEach(async () => {
      const { addCompliancePolicyTools: importedFunction } = await import('../../../src/tools/compliance-policy.js');
      addCompliancePolicyTools = importedFunction;
      addCompliancePolicyTools(mockServer, mockApiClient as any);
    });

    it('should validate create-compliance-policy schema with valid data', () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'create-compliance-policy')[0];
      
      const validInput = {
        policyName: 'SOX Financial Controls',
        description: 'Comprehensive SOX compliance policy for financial reporting controls',
        framework: ['sox'],
        version: '1.0.0',
        effectiveDate: new Date().toISOString(),
        scope: {
          organizationScope: 'global' as const,
        },
        controls: {
          preventive: [{
            controlId: 'SOX-001',
            name: 'Segregation of Duties',
            description: 'Implement segregation of duties for financial processes',
            framework: ['sox'],
            category: 'preventive' as const,
            automationLevel: 'semi-automated' as const,
            frequency: 'monthly' as const,
          }],
          detective: [{
            controlId: 'SOX-002',
            name: 'Financial Review Controls',
            description: 'Regular review of financial transactions',
            framework: ['sox'],
            category: 'detective' as const,
            automationLevel: 'manual' as const,
            frequency: 'weekly' as const,
          }],
          corrective: [{
            controlId: 'SOX-003',
            name: 'Issue Remediation',
            description: 'Process for correcting identified issues',
            framework: ['sox'],
            category: 'corrective' as const,
            automationLevel: 'manual' as const,
            frequency: 'quarterly' as const,
          }],
        },
        enforcement: {
          automatedChecks: [{
            checkId: 'CHECK-001',
            name: 'Audit Trail Validation',
            description: 'Automated audit trail completeness check',
            checkType: 'scenario_validation' as const,
            schedule: 'daily' as const,
            criteria: { auditEnabled: true },
            actions: ['alert', 'escalate'],
            enabled: true,
          }],
          violations: {
            severity: 'high' as const,
            actions: [{
              actionId: 'ACTION-001',
              name: 'Compliance Alert',
              type: 'alert' as const,
              description: 'Send compliance violation alert',
              automated: true,
            }],
          },
          reporting: {
            frequency: 'monthly' as const,
            recipients: ['compliance@company.com'],
            format: ['json'],
          },
        },
      };

      expect(() => {
        expectValidZodParse(toolConfig.parameters, validInput);
      }).not.toThrow();
    });

    it('should reject invalid create-compliance-policy data', () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'create-compliance-policy')[0];
      
      const invalidInputs = [
        // Missing required fields
        {},
        // Invalid framework
        {
          policyName: 'Test',
          framework: ['invalid-framework'],
          controls: { preventive: [], detective: [], corrective: [] },
          enforcement: { 
            automatedChecks: [],
            violations: { severity: 'high', actions: [] },
            reporting: { frequency: 'monthly', recipients: [], format: [] }
          }
        },
        // Invalid scope
        {
          policyName: 'Test',
          framework: ['sox'],
          scope: { organizationScope: 'invalid-scope' },
          controls: { preventive: [], detective: [], corrective: [] },
          enforcement: { 
            automatedChecks: [],
            violations: { severity: 'high', actions: [] },
            reporting: { frequency: 'monthly', recipients: [], format: [] }
          }
        },
      ];

      invalidInputs.forEach((invalidInput, index) => {
        expect(() => {
          expectValidZodParse(toolConfig.parameters, invalidInput);
        }).toThrow();
      });
    });

    it('should validate compliance report schema with valid data', () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'generate-compliance-report')[0];
      
      const validInput = {
        startDate: '2024-01-01T00:00:00Z',
        endDate: '2024-01-31T23:59:59Z',
        format: 'json' as const,
        includeViolations: true,
        includeMetrics: true,
        includeRecommendations: true,
      };

      expect(() => {
        expectValidZodParse(toolConfig.parameters, validInput);
      }).not.toThrow();
    });

    it('should validate compliance validation schema', () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-compliance')[0];
      
      const validInput = {
        policyId: 'policy_123',
        targetType: 'scenario' as const,
        targetId: 'scenario_456',
        includeRecommendations: true,
      };

      expect(() => {
        expectValidZodParse(toolConfig.parameters, validInput);
      }).not.toThrow();
    });
  });

  describe('Basic Tool Execution', () => {
    beforeEach(async () => {
      const { addCompliancePolicyTools: importedFunction } = await import('../../../src/tools/compliance-policy.js');
      addCompliancePolicyTools = importedFunction;
      addCompliancePolicyTools(mockServer, mockApiClient as any);
    });

    it('should execute create-compliance-policy successfully', async () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'create-compliance-policy')[0];
      
      const input = {
        policyName: 'Test SOX Policy',
        description: 'Test SOX compliance policy',
        framework: ['sox'],
        version: '1.0.0',
        effectiveDate: new Date().toISOString(),
        scope: {
          organizationScope: 'global' as const,
        },
        controls: {
          preventive: [{
            controlId: 'SOX-001',
            name: 'Segregation of Duties',
            description: 'Implement segregation of duties',
            framework: ['sox'],
            category: 'preventive' as const,
            automationLevel: 'manual' as const,
            frequency: 'monthly' as const,
          }],
          detective: [{
            controlId: 'SOX-002',
            name: 'Review Controls',
            description: 'Regular review processes',
            framework: ['sox'],
            category: 'detective' as const,
            automationLevel: 'manual' as const,
            frequency: 'weekly' as const,
          }],
          corrective: [{
            controlId: 'SOX-003',
            name: 'Issue Remediation',
            description: 'Corrective actions',
            framework: ['sox'],
            category: 'corrective' as const,
            automationLevel: 'manual' as const,
            frequency: 'quarterly' as const,
          }],
        },
        enforcement: {
          automatedChecks: [{
            checkId: 'CHECK-001',
            name: 'Audit Check',
            description: 'Automated audit check',
            checkType: 'scenario_validation' as const,
            schedule: 'daily' as const,
            criteria: {},
            actions: ['alert'],
            enabled: true,
          }],
          violations: {
            severity: 'high' as const,
            actions: [{
              actionId: 'ACTION-001',
              name: 'Alert Action',
              type: 'alert' as const,
              description: 'Send alert',
              automated: true,
            }],
          },
          reporting: {
            frequency: 'monthly' as const,
            recipients: ['test@example.com'],
            format: ['json'],
          },
        },
      };

      const mockContext = {
        log: { info: jest.fn(), error: jest.fn(), warn: jest.fn(), debug: jest.fn() },
        reportProgress: jest.fn(),
        session: { authenticated: true },
      };

      const result = await toolConfig.execute(input, mockContext);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.policyId).toBeDefined();
      expect(parsedResult.policy.name).toBe('Test SOX Policy');
      expect(parsedResult.policy.frameworks).toEqual(['sox']);
    });

    it('should execute list-compliance-policies successfully', async () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'list-compliance-policies')[0];
      
      const result = await executeTool(toolConfig, {});
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.totalPolicies).toBeDefined();
      expect(Array.isArray(parsedResult.policies)).toBe(true);
    });

    it('should execute generate-compliance-report successfully', async () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'generate-compliance-report')[0];
      
      const input = {
        startDate: '2024-01-01T00:00:00Z',
        endDate: '2024-01-31T23:59:59Z',
        format: 'json' as const,
        includeViolations: true,
        includeMetrics: true,
        includeRecommendations: true,
      };

      const result = await executeTool(toolConfig, input);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.reportId).toBeDefined();
      expect(parsedResult.metadata).toBeDefined();
      expect(parsedResult.summary).toBeDefined();
    });

    it('should execute get-compliance-templates successfully', async () => {
      const { getTemplateMetadata } = await import('../../../src/tools/compliance-templates.js');
      const mockGetTemplateMetadata = getTemplateMetadata as jest.MockedFunction<typeof getTemplateMetadata>;
      
      mockGetTemplateMetadata.mockReturnValue([
        {
          templateId: 'sox-template',
          templateName: 'SOX Compliance Template',
          description: 'Template for SOX compliance',
          framework: ['sox'],
          version: '1.0.0',
          lastUpdated: new Date().toISOString(),
        }
      ]);

      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'get-compliance-templates')[0];
      
      const mockContext = {
        log: { info: jest.fn(), error: jest.fn(), warn: jest.fn(), debug: jest.fn() },
        reportProgress: jest.fn(),
        session: { authenticated: true },
      };
      
      const result = await toolConfig.execute({}, mockContext);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.totalTemplates).toBeDefined();
      expect(Array.isArray(parsedResult.templates)).toBe(true);
    });
  });

  describe('Error Handling and Edge Cases', () => {
    beforeEach(async () => {
      const { addCompliancePolicyTools: importedFunction } = await import('../../../src/tools/compliance-policy.js');
      addCompliancePolicyTools = importedFunction;
      addCompliancePolicyTools(mockServer, mockApiClient as any);
    });

    it('should handle file system errors gracefully', async () => {
      // Mock fs.readFile to throw an error
      mockFs.readFile.mockRejectedValueOnce(new Error('File system error'));
      
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'list-compliance-policies')[0];
      
      // Should handle the error gracefully and not crash
      await expect(executeTool(toolConfig, {})).rejects.toThrow();
    });

    it('should handle API client errors in validation', async () => {
      // Mock API client to fail
      mockApiClient.mockFailure('GET', '/scenarios/test-scenario', new Error('API Error'));
      
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-compliance')[0];
      
      // Mock that a policy exists
      mockFs.readFile.mockResolvedValueOnce(JSON.stringify({
        policies: {
          'policy-123': {
            policyId: 'policy-123',
            policyName: 'Test Policy',
            framework: ['sox'],
            controls: { preventive: [], detective: [], corrective: [] }
          }
        }
      }));

      const input = {
        policyId: 'policy-123',
        targetType: 'scenario' as const,
        targetId: 'test-scenario',
      };

      const result = await executeTool(toolConfig, input);
      const parsedResult = JSON.parse(result);
      
      // Should handle API error gracefully
      expect(parsedResult.compliant).toBe(false);
      expect(parsedResult.validation.violations).toBeDefined();
    });

    it('should handle invalid date ranges in reports', async () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'generate-compliance-report')[0];
      
      const input = {
        startDate: '2024-12-31T23:59:59Z',
        endDate: '2024-01-01T00:00:00Z', // End before start
        format: 'json' as const,
      };

      // Should handle gracefully
      const result = await executeTool(toolConfig, input);
      expect(result).toBeDefined();
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBe(true);
    });

    it('should handle missing policy in validation', async () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-compliance')[0];
      
      const input = {
        policyId: 'non-existent-policy',
        targetType: 'scenario' as const,
        targetId: 'test-scenario',
      };

      await expect(executeTool(toolConfig, input)).rejects.toThrow('not found');
    });
  });

  describe('Compliance Framework Testing', () => {
    beforeEach(async () => {
      const { addCompliancePolicyTools: importedFunction } = await import('../../../src/tools/compliance-policy.js');
      addCompliancePolicyTools = importedFunction;
      addCompliancePolicyTools(mockServer, mockApiClient as any);
    });

    it('should support all major compliance frameworks', () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'create-compliance-policy')[0];
      
      const frameworks = ['sox', 'gdpr', 'hipaa', 'pci_dss', 'iso27001', 'custom'];
      
      frameworks.forEach(framework => {
        const input = {
          policyName: `${framework.toUpperCase()} Policy`,
          description: `Test policy for ${framework}`,
          framework: [framework],
          scope: { organizationScope: 'global' as const },
          controls: {
            preventive: [],
            detective: [],
            corrective: [],
          },
          enforcement: {
            automatedChecks: [],
            violations: { severity: 'medium' as const, actions: [] },
            reporting: { frequency: 'monthly' as const, recipients: [], format: ['json'] },
          },
        };

        expect(() => {
          expectValidZodParse(toolConfig.parameters, input);
        }).not.toThrow();
      });
    });

    it('should support multiple frameworks in single policy', () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'create-compliance-policy')[0];
      
      const input = {
        policyName: 'Multi-Framework Policy',
        description: 'Policy covering multiple frameworks',
        framework: ['sox', 'gdpr', 'iso27001'],
        scope: { organizationScope: 'global' as const },
        controls: {
          preventive: [{
            controlId: 'MULTI-001',
            name: 'Multi-Framework Control',
            description: 'Control applicable to multiple frameworks',
            framework: ['sox', 'gdpr', 'iso27001'],
            category: 'preventive' as const,
            automationLevel: 'manual' as const,
            frequency: 'monthly' as const,
          }],
          detective: [],
          corrective: [],
        },
        enforcement: {
          automatedChecks: [],
          violations: { severity: 'high' as const, actions: [] },
          reporting: { frequency: 'quarterly' as const, recipients: [], format: ['json'] },
        },
      };

      expect(() => {
        expectValidZodParse(toolConfig.parameters, input);
      }).not.toThrow();
    });

    it('should validate framework-specific control requirements', async () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'create-compliance-policy')[0];
      
      // Test SOX framework with appropriate controls
      const soxInput = {
        policyName: 'SOX Comprehensive Policy',
        description: 'Comprehensive SOX compliance policy',
        framework: ['sox'],
        scope: { organizationScope: 'global' as const },
        controls: {
          preventive: [{
            controlId: 'SOX-SEGREGATION',
            name: 'Segregation of Duties Control',
            description: 'Implements segregation of duties for financial processes',
            framework: ['sox'],
            category: 'preventive' as const,
            automationLevel: 'manual' as const,
            frequency: 'continuous' as const,
          }],
          detective: [{
            controlId: 'SOX-AUDIT',
            name: 'Audit Trail Integrity Check',
            description: 'Ensures audit trail completeness and integrity',
            framework: ['sox'],
            category: 'detective' as const,
            automationLevel: 'semi-automated' as const,
            frequency: 'daily' as const,
          }],
          corrective: [{
            controlId: 'SOX-CHANGE',
            name: 'Change Management Process',
            description: 'Controlled change management for financial systems',
            framework: ['sox'],
            category: 'corrective' as const,
            automationLevel: 'manual' as const,
            frequency: 'monthly' as const,
          }],
        },
        enforcement: {
          automatedChecks: [],
          violations: { severity: 'critical' as const, actions: [] },
          reporting: { frequency: 'monthly' as const, recipients: [], format: ['json'] },
        },
      };

      const result = await executeTool(toolConfig, soxInput);
      const parsedResult = JSON.parse(result);
      
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.controls.total).toBe(3);
    });
  });

  describe('Policy Validation and Enforcement Testing', () => {
    beforeEach(async () => {
      const { addCompliancePolicyTools: importedFunction } = await import('../../../src/tools/compliance-policy.js');
      addCompliancePolicyTools = importedFunction;
      addCompliancePolicyTools(mockServer, mockApiClient as any);
    });

    it('should validate different target types', () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-compliance')[0];
      
      const targetTypes = ['scenario', 'connection', 'user', 'data_flow'];
      
      targetTypes.forEach(targetType => {
        const input = {
          policyId: 'test-policy',
          targetType: targetType as any,
          targetId: `test-${targetType}`,
          includeRecommendations: true,
        };

        expect(() => {
          expectValidZodParse(toolConfig.parameters, input);
        }).not.toThrow();
      });
    });

    it('should support different violation severity levels', () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'create-compliance-policy')[0];
      
      const severityLevels = ['low', 'medium', 'high', 'critical'];
      
      severityLevels.forEach(severity => {
        const input = {
          policyName: `${severity} Severity Policy`,
          description: `Policy with ${severity} severity`,
          framework: ['custom'],
          scope: { organizationScope: 'team' as const },
          controls: { preventive: [], detective: [], corrective: [] },
          enforcement: {
            automatedChecks: [],
            violations: { severity: severity as any, actions: [] },
            reporting: { frequency: 'weekly' as const, recipients: [], format: ['json'] },
          },
        };

        expect(() => {
          expectValidZodParse(toolConfig.parameters, input);
        }).not.toThrow();
      });
    });

    it('should support different enforcement action types', () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'create-compliance-policy')[0];
      
      const actionTypes = ['block', 'alert', 'quarantine', 'escalate', 'remediate'];
      
      actionTypes.forEach(actionType => {
        const action = {
          actionId: `ACTION-${actionType.toUpperCase()}`,
          name: `${actionType} Action`,
          type: actionType as any,
          description: `Performs ${actionType} action`,
          automated: true,
        };

        const input = {
          policyName: `${actionType} Action Policy`,
          description: `Policy with ${actionType} action`,
          framework: ['custom'],
          scope: { organizationScope: 'project' as const },
          controls: { preventive: [], detective: [], corrective: [] },
          enforcement: {
            automatedChecks: [],
            violations: { severity: 'medium' as const, actions: [action] },
            reporting: { frequency: 'daily' as const, recipients: [], format: ['json'] },
          },
        };

        expect(() => {
          expectValidZodParse(toolConfig.parameters, input);
        }).not.toThrow();
      });
    });
  });

  describe('Reporting and Template Testing', () => {
    beforeEach(async () => {
      const { addCompliancePolicyTools: importedFunction } = await import('../../../src/tools/compliance-policy.js');
      addCompliancePolicyTools = importedFunction;
      addCompliancePolicyTools(mockServer, mockApiClient as any);
    });

    it('should support different report formats', () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'generate-compliance-report')[0];
      
      const formats = ['json', 'pdf', 'excel', 'dashboard'];
      
      formats.forEach(format => {
        const input = {
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z',
          format: format as any,
        };

        expect(() => {
          expectValidZodParse(toolConfig.parameters, input);
        }).not.toThrow();
      });
    });

    it('should support different reporting frequencies', () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'create-compliance-policy')[0];
      
      const frequencies = ['real-time', 'daily', 'weekly', 'monthly', 'quarterly'];
      
      frequencies.forEach(frequency => {
        const input = {
          policyName: `${frequency} Reporting Policy`,
          description: `Policy with ${frequency} reporting`,
          framework: ['custom'],
          scope: { organizationScope: 'global' as const },
          controls: { preventive: [], detective: [], corrective: [] },
          enforcement: {
            automatedChecks: [],
            violations: { severity: 'medium' as const, actions: [] },
            reporting: { frequency: frequency as any, recipients: [], format: ['json'] },
          },
        };

        expect(() => {
          expectValidZodParse(toolConfig.parameters, input);
        }).not.toThrow();
      });
    });

    it('should handle template operations correctly', async () => {
      const mockTemplate = {
        templateId: 'sox-template',
        templateName: 'SOX Compliance Template',
        description: 'Comprehensive SOX compliance template',
        framework: ['sox'],
        version: '1.0.0',
        lastUpdated: new Date().toISOString(),
        template: {
          policyName: 'SOX Compliance Policy',
          description: 'SOX compliance policy from template',
          framework: ['sox'],
          version: '1.0.0',
          effectiveDate: new Date().toISOString(),
          scope: { organizationScope: 'global' as const },
          controls: { preventive: [], detective: [], corrective: [] },
          enforcement: {
            automatedChecks: [],
            violations: { severity: 'high' as const, actions: [] },
            reporting: { frequency: 'monthly' as const, recipients: [], format: ['json'] },
          },
        },
      };

      mockComplianceTemplates.getComplianceTemplate.mockReturnValue(mockTemplate);

      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'create-policy-from-template')[0];
      
      const input = {
        framework: 'sox' as const,
        policyName: 'My SOX Policy',
        customizations: {
          organizationScope: 'team' as const,
          reportingFrequency: 'weekly' as const,
        },
      };

      const result = await executeTool(toolConfig, input);
      const parsedResult = JSON.parse(result);
      
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.policyId).toBeDefined();
      expect(parsedResult.template.framework).toBe('sox');
    });
  });
});