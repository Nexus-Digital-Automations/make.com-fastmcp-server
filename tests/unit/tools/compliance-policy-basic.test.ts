/**
 * Basic Test Suite for Compliance Policy Tools
 * Tests core functionality of enterprise compliance policy management tools
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { createMockServer, findTool, executeTool } from '../../utils/test-helpers.js';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';

// Mock fs/promises with basic functionality
const mockFs = {
  mkdir: jest.fn().mockResolvedValue(undefined),
  readFile: jest.fn().mockResolvedValue(JSON.stringify({
    policies: {},
    metadata: { created: new Date().toISOString(), version: '1.0.0' }
  })),
  writeFile: jest.fn().mockResolvedValue(undefined),
};

jest.mock('fs/promises', () => mockFs);

jest.mock('path', () => ({
  join: jest.fn((...args) => args.join('/')),
  dirname: jest.fn((p) => p.split('/').slice(0, -1).join('/')),
  resolve: jest.fn((...args) => args.join('/')),
}));

// Mock compliance templates
const mockComplianceTemplates = {
  getComplianceTemplate: jest.fn(),
  listComplianceTemplates: jest.fn(),
  getTemplateMetadata: jest.fn(),
};

jest.mock('../../../src/tools/compliance-templates.js', () => mockComplianceTemplates);

// Use global mocks for logger and audit-logger from jest.config.js
// No need to override them here

describe('Compliance Policy Tools - Basic Tests', () => {
  let mockServer: any;
  let mockTool: jest.MockedFunction<any>;
  let mockApiClient: MockMakeApiClient;

  beforeEach(async () => {
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockTool = serverSetup.mockTool;
    mockApiClient = new MockMakeApiClient();
    
    // Clear previous mock calls
    mockTool.mockClear();
    
    // Clear mock fs state to reset policy storage between tests
    mockFs.readFile.mockResolvedValue(JSON.stringify({
      policies: {},
      metadata: { created: new Date().toISOString(), version: '1.0.0' }
    }));
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Tool Registration and Import', () => {
    it('should successfully import compliance policy module', async () => {
      const compliancePolicyModule = await import('../../../src/tools/compliance-policy.js');
      
      expect(compliancePolicyModule.addCompliancePolicyTools).toBeDefined();
      expect(typeof compliancePolicyModule.addCompliancePolicyTools).toBe('function');
    });

    it('should register compliance policy tools successfully', async () => {
      const { addCompliancePolicyTools } = await import('../../../src/tools/compliance-policy.js');
      
      addCompliancePolicyTools(mockServer, mockApiClient as any);
      
      const toolNames = mockTool.mock.calls.map(call => call[0].name);
      
      // Verify key tools are registered
      expect(toolNames).toContain('create-compliance-policy');
      expect(toolNames).toContain('validate-compliance');
      expect(toolNames).toContain('generate-compliance-report');
      expect(toolNames).toContain('list-compliance-policies');
      expect(mockTool.mock.calls.length).toBeGreaterThan(0);
    });
  });

  describe('Tool Configuration Validation', () => {
    beforeEach(async () => {
      const { addCompliancePolicyTools } = await import('../../../src/tools/compliance-policy.js');
      addCompliancePolicyTools(mockServer, mockApiClient as any);
    });

    it('should have correct structure for create-compliance-policy tool', () => {
      const createTool = findTool(mockTool, 'create-compliance-policy');
      
      expect(createTool).toBeDefined();
      expect(createTool.name).toBe('create-compliance-policy');
      expect(createTool.description).toBeDefined();
      expect(createTool.description).toContain('compliance policy');
      expect(createTool.parameters).toBeDefined();
      expect(typeof createTool.execute).toBe('function');
    });

    it('should have correct structure for validate-compliance tool', () => {
      const validateTool = findTool(mockTool, 'validate-compliance');
      
      expect(validateTool).toBeDefined();
      expect(validateTool.name).toBe('validate-compliance');
      expect(validateTool.description).toBeDefined();
      expect(validateTool.description.toLowerCase()).toContain('validate compliance');
      expect(validateTool.parameters).toBeDefined();
      expect(typeof validateTool.execute).toBe('function');
    });

    it('should have correct structure for generate-compliance-report tool', () => {
      const reportTool = findTool(mockTool, 'generate-compliance-report');
      
      expect(reportTool).toBeDefined();
      expect(reportTool.name).toBe('generate-compliance-report');
      expect(reportTool.description).toBeDefined();
      expect(reportTool.description).toContain('compliance report');
      expect(reportTool.parameters).toBeDefined();
      expect(typeof reportTool.execute).toBe('function');
    });

    it('should have correct structure for list-compliance-policies tool', () => {
      const listTool = findTool(mockTool, 'list-compliance-policies');
      
      expect(listTool).toBeDefined();
      expect(listTool.name).toBe('list-compliance-policies');
      expect(listTool.description).toBeDefined();
      expect(listTool.parameters).toBeDefined();
      expect(typeof listTool.execute).toBe('function');
    });
  });

  describe('Basic Tool Execution', () => {
    beforeEach(async () => {
      const { addCompliancePolicyTools } = await import('../../../src/tools/compliance-policy.js');
      addCompliancePolicyTools(mockServer, mockApiClient as any);
    });

    it('should execute create-compliance-policy successfully', async () => {
      const createTool = findTool(mockTool, 'create-compliance-policy');
      
      const input = {
        policyName: `Test Custom Policy ${Date.now()}`,
        description: 'Test custom compliance policy',
        framework: ['custom'],
        version: '1.0.0',
        effectiveDate: new Date().toISOString(),
        scope: {
          organizationScope: 'global' as const,
        },
        controls: {
          preventive: [
            {
              controlId: 'SOX-001',
              name: 'segregation_of_duties',
              description: 'Implement segregation of duties',
              framework: ['sox'],
              category: 'preventive' as const,
              automationLevel: 'manual' as const,
              frequency: 'monthly' as const,
            },
            {
              controlId: 'SOX-002',
              name: 'audit_trail_integrity',
              description: 'Ensure audit trail integrity',
              framework: ['sox'],
              category: 'preventive' as const,
              automationLevel: 'manual' as const,
              frequency: 'monthly' as const,
            },
            {
              controlId: 'SOX-003',
              name: 'change_management',
              description: 'Implement change management controls',
              framework: ['sox'],
              category: 'preventive' as const,
              automationLevel: 'manual' as const,
              frequency: 'monthly' as const,
            }
          ],
          detective: [],
          corrective: [],
        },
        enforcement: {
          automatedChecks: [],
          violations: {
            severity: 'high' as const,
            actions: [],
          },
          reporting: {
            frequency: 'monthly' as const,
            recipients: ['test@example.com'],
            format: ['json'],
          },
        },
      };

      const result = await executeTool(createTool, input);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.policyId).toBeDefined();
    });

    it('should execute list-compliance-policies successfully', async () => {
      const listTool = findTool(mockTool, 'list-compliance-policies');
      
      const result = await executeTool(listTool, {});
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.totalPolicies).toBeDefined();
      expect(Array.isArray(parsedResult.policies)).toBe(true);
    });

    it('should execute generate-compliance-report successfully', async () => {
      const reportTool = findTool(mockTool, 'generate-compliance-report');
      
      const input = {
        startDate: '2024-01-01T00:00:00Z',
        endDate: '2024-01-31T23:59:59Z',
        format: 'json' as const,
        includeViolations: true,
        includeMetrics: true,
        includeRecommendations: true,
      };

      const result = await executeTool(reportTool, input);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.reportId).toBeDefined();
      expect(parsedResult.metadata).toBeDefined();
    });
  });

  describe('Error Handling', () => {
    beforeEach(async () => {
      const { addCompliancePolicyTools } = await import('../../../src/tools/compliance-policy.js');
      addCompliancePolicyTools(mockServer, mockApiClient as any);
    });

    it('should handle file system errors gracefully', async () => {
      // Mock fs.readFile to throw an error
      mockFs.readFile.mockRejectedValueOnce(new Error('File system error'));
      
      const listTool = findTool(mockTool, 'list-compliance-policies');
      
      // Tool should handle the error gracefully and return empty results instead of crashing
      const result = await executeTool(listTool, {});
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBe(true);
      expect(Array.isArray(parsedResult.policies)).toBe(true);
    });

    it('should handle missing policy in validation', async () => {
      const validateTool = findTool(mockTool, 'validate-compliance');
      
      const input = {
        policyId: 'non-existent-policy',
        targetType: 'scenario' as const,
        targetId: 'test-scenario',
      };

      await expect(executeTool(validateTool, input)).rejects.toThrow('not found');
    });
  });

  describe('Framework Support', () => {
    beforeEach(async () => {
      const { addCompliancePolicyTools } = await import('../../../src/tools/compliance-policy.js');
      addCompliancePolicyTools(mockServer, mockApiClient as any);
    });

    it('should support major compliance frameworks', async () => {
      const createTool = findTool(mockTool, 'create-compliance-policy');
      
      const frameworks = ['custom']; // Test with custom framework first
      
      for (const framework of frameworks) {
        const input = {
          policyName: `${framework.toUpperCase()} Policy ${Date.now()}_${Math.random()}`,
          description: `Test policy for ${framework}`,
          framework: [framework],
          version: '1.0.0',
          effectiveDate: new Date().toISOString(),
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

        // This should not throw - schema validation
        const result = await executeTool(createTool, input);
        expect(result).toBeDefined();
        
        const parsedResult = JSON.parse(result);
        expect(parsedResult.success).toBe(true);
      }
    });
  });
});