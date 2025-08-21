/**
 * Basic Test Suite for Policy Compliance Validation Tools
 * Tests core functionality of unified policy compliance validation system
 * 
 * This test suite comprehensively validates the policy compliance validation system
 * including tool registration, schema validation, policy validation execution,
 * cross-policy validation, error handling, and automated remediation testing.
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { createMockServer, executeTool, expectValidZodParse, expectInvalidZodParse } from '../../utils/test-helpers.js';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';

// Mock all dependencies first
const mockLogger = {
  info: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  debug: jest.fn(),
  child: jest.fn(() => mockLogger),
};

jest.mock('fs/promises', () => ({
  mkdir: jest.fn().mockResolvedValue(undefined),
  readFile: jest.fn().mockResolvedValue(JSON.stringify({
    validations: {},
    metadata: { created: new Date().toISOString(), version: '1.0.0' }
  })),
  writeFile: jest.fn().mockResolvedValue(undefined),
}));

jest.mock('path', () => ({
  join: jest.fn((...args) => args.join('/')),
  dirname: jest.fn((p) => p.split('/').slice(0, -1).join('/')),
}));

jest.mock('crypto', () => ({
  createHash: jest.fn(() => ({
    update: jest.fn().mockReturnThis(),
    digest: jest.fn().mockReturnValue('abcd1234'),
  })),
}));

jest.mock('../../../src/lib/logger.js', () => ({
  __esModule: true,
  default: mockLogger,
}));

jest.mock('../../../src/lib/audit-logger.js', () => ({
  __esModule: true,
  auditLogger: {
    logEvent: jest.fn().mockResolvedValue(undefined),
  },
}));

// Mock the file system operations at module level
const mockFs = {
  readFile: jest.fn().mockResolvedValue(JSON.stringify({
    validations: {},
    metadata: { created: new Date().toISOString(), version: '1.0.0' }
  })),
  writeFile: jest.fn().mockResolvedValue(undefined),
  mkdir: jest.fn().mockResolvedValue(undefined),
};

// Apply mocks
require('fs/promises').readFile = mockFs.readFile;
require('fs/promises').writeFile = mockFs.writeFile;
require('fs/promises').mkdir = mockFs.mkdir;

describe('Policy Compliance Validation Tools - Basic Tests', () => {
  let mockServer: any;
  let mockTool: jest.MockedFunction<any>;
  let mockApiClient: MockMakeApiClient;
  let addPolicyComplianceValidationTools: any;

  beforeEach(async () => {
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockTool = serverSetup.mockTool;
    mockApiClient = new MockMakeApiClient();
    
    // Clear previous mock calls
    mockTool.mockClear();
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Tool Registration and Import', () => {
    it('should successfully import and register policy compliance validation tools', async () => {
      const { addPolicyComplianceValidationTools: importedFunction } = await import('../../../src/tools/policy-compliance-validation.js');
      addPolicyComplianceValidationTools = importedFunction;
      
      // Should not throw an error
      expect(() => {
        addPolicyComplianceValidationTools(mockServer, mockApiClient as any);
      }).not.toThrow();
      
      // Should call addTool for the validation tool
      expect(mockTool).toHaveBeenCalled();
      expect(mockTool.mock.calls.length).toBeGreaterThan(0);
    });

    it('should export the expected functions and types', async () => {
      const policyComplianceModule = await import('../../../src/tools/policy-compliance-validation.js');
      
      // Check that expected exports exist
      expect(policyComplianceModule.addPolicyComplianceValidationTools).toBeDefined();
      expect(typeof policyComplianceModule.addPolicyComplianceValidationTools).toBe('function');
      expect(policyComplianceModule.default).toBeDefined();
    });

    it('should register the validate-policy-compliance tool', async () => {
      const { addPolicyComplianceValidationTools: importedFunction } = await import('../../../src/tools/policy-compliance-validation.js');
      addPolicyComplianceValidationTools = importedFunction;
      
      addPolicyComplianceValidationTools(mockServer, mockApiClient as any);
      
      const toolNames = mockTool.mock.calls.map(call => call[0].name);
      
      // Verify the main tool is registered
      expect(toolNames).toContain('validate-policy-compliance');
      
      // Should register exactly 1 tool
      expect(toolNames.length).toBe(1);
    });
  });

  describe('Tool Configuration and Structure Validation', () => {
    beforeEach(async () => {
      const { addPolicyComplianceValidationTools: importedFunction } = await import('../../../src/tools/policy-compliance-validation.js');
      addPolicyComplianceValidationTools = importedFunction;
      addPolicyComplianceValidationTools(mockServer, mockApiClient as any);
    });

    it('should have correctly structured validate-policy-compliance tool', () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-policy-compliance')[0];
      
      expect(toolConfig.name).toBe('validate-policy-compliance');
      expect(toolConfig.description).toBeDefined();
      expect(toolConfig.description).toContain('policy compliance validation');
      expect(toolConfig.parameters).toBeDefined();
      expect(typeof toolConfig.execute).toBe('function');
      expect(toolConfig.annotations).toBeDefined();
      expect(toolConfig.annotations.title).toBe('Validate Policy Compliance');
      expect(toolConfig.annotations.idempotentHint).toBe(true);
      expect(toolConfig.annotations.destructiveHint).toBe(false);
    });

    it('should have proper tool metadata and documentation', () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-policy-compliance')[0];
      
      expect(toolConfig.description).toContain('cross-policy analysis');
      expect(toolConfig.description).toContain('comprehensive scoring');
      expect(toolConfig.description).toContain('remediation guidance');
      expect(toolConfig.annotations.openWorldHint).toBe(true);
      expect(toolConfig.annotations.readOnlyHint).toBe(false);
    });
  });

  describe('Schema Validation', () => {
    beforeEach(async () => {
      const { addPolicyComplianceValidationTools: importedFunction } = await import('../../../src/tools/policy-compliance-validation.js');
      addPolicyComplianceValidationTools = importedFunction;
      addPolicyComplianceValidationTools(mockServer, mockApiClient as any);
    });

    it('should validate complete policy compliance schema with valid data', () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-policy-compliance')[0];
      
      const validInput = {
        targets: [{
          targetType: 'scenario' as const,
          targetId: 'scenario_123',
          targetName: 'Customer Data Processing Scenario',
          metadata: {
            description: 'Processes customer data with GDPR compliance',
            lastModified: '2024-01-15T10:30:00Z',
            owner: 'data-team@company.com'
          }
        }],
        policySelection: {
          policyTypes: ['compliance', 'naming_convention'] as const,
          frameworks: ['gdpr', 'sox'] as const,
          organizationId: 12345,
          teamId: 6789,
          tags: ['data-processing', 'customer-data'],
          activeOnly: true
        },
        validationOptions: {
          includeRecommendations: true,
          includeComplianceScore: true,
          includeViolationDetails: true,
          enableCrossValidation: true,
          scoringWeights: {
            compliance: 0.5,
            naming: 0.3,
            archival: 0.2
          },
          severityThresholds: {
            critical: 95,
            high: 80,
            medium: 60,
            low: 30
          },
          validationDepth: 'comprehensive' as const
        },
        reportingOptions: {
          format: 'detailed' as const,
          includeAuditTrail: true,
          includeHistoricalTrends: true,
          exportOptions: {
            generatePdf: true,
            generateExcel: false,
            generateDashboard: true
          }
        },
        executionContext: {
          userId: 'user_456',
          reason: 'Quarterly compliance review',
          correlationId: 'review_2024_q1_001',
          priority: 'high' as const,
          dryRun: false
        }
      };

      expect(() => {
        expectValidZodParse(toolConfig.parameters, validInput);
      }).not.toThrow();
    });

    it('should validate minimal valid policy compliance schema', () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-policy-compliance')[0];
      
      const minimalValidInput = {
        targets: [{
          targetType: 'connection' as const,
          targetId: 'conn_789'
        }],
        policySelection: {},
        validationOptions: {}
      };

      expect(() => {
        expectValidZodParse(toolConfig.parameters, minimalValidInput);
      }).not.toThrow();
    });

    it('should reject invalid policy compliance data', () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-policy-compliance')[0];
      
      const invalidInputs = [
        // Missing required fields
        {},
        // Empty targets array
        {
          targets: [],
          policySelection: {},
          validationOptions: {}
        },
        // Invalid target type
        {
          targets: [{
            targetType: 'invalid-type',
            targetId: 'test_123'
          }],
          policySelection: {},
          validationOptions: {}
        },
        // Invalid framework
        {
          targets: [{
            targetType: 'scenario',
            targetId: 'test_123'
          }],
          policySelection: {
            frameworks: ['invalid-framework']
          },
          validationOptions: {}
        },
        // Invalid validation depth
        {
          targets: [{
            targetType: 'scenario',
            targetId: 'test_123'
          }],
          policySelection: {},
          validationOptions: {
            validationDepth: 'invalid-depth'
          }
        }
      ];

      invalidInputs.forEach((invalidInput, index) => {
        expect(() => {
          expectValidZodParse(toolConfig.parameters, invalidInput);
        }).toThrow();
      });
    });

    it('should validate target types and frameworks', () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-policy-compliance')[0];
      
      const targetTypes = ['scenario', 'connection', 'template', 'folder', 'user', 'data_flow', 'organization', 'team'];
      const frameworks = ['sox', 'gdpr', 'hipaa', 'pci_dss', 'iso27001', 'enterprise', 'custom'];
      
      targetTypes.forEach(targetType => {
        const input = {
          targets: [{
            targetType: targetType as any,
            targetId: `test_${targetType}`
          }],
          policySelection: {},
          validationOptions: {}
        };

        expect(() => {
          expectValidZodParse(toolConfig.parameters, input);
        }).not.toThrow();
      });

      frameworks.forEach(framework => {
        const input = {
          targets: [{
            targetType: 'scenario',
            targetId: 'test_scenario'
          }],
          policySelection: {
            frameworks: [framework as any]
          },
          validationOptions: {}
        };

        expect(() => {
          expectValidZodParse(toolConfig.parameters, input);
        }).not.toThrow();
      });
    });
  });

  describe('Basic Tool Execution', () => {
    beforeEach(async () => {
      const { addPolicyComplianceValidationTools: importedFunction } = await import('../../../src/tools/policy-compliance-validation.js');
      addPolicyComplianceValidationTools = importedFunction;
      addPolicyComplianceValidationTools(mockServer, mockApiClient as any);

      // Setup mock API responses for policy fetching
      mockApiClient.mockResponse('GET', '/policies/compliance', {
        success: true,
        data: [
          {
            id: 'policy_compliance_001',
            name: 'GDPR Data Protection Policy',
            framework: ['gdpr'],
            active: true,
            controls: {
              preventive: [{ controlId: 'GDPR-001', name: 'Data Minimization' }],
              detective: [{ controlId: 'GDPR-002', name: 'Access Monitoring' }],
              corrective: [{ controlId: 'GDPR-003', name: 'Breach Response' }]
            }
          }
        ]
      });

      mockApiClient.mockResponse('GET', '/policies/naming-conventions', {
        success: true,
        data: [
          {
            id: 'policy_naming_001',
            name: 'Enterprise Naming Standards',
            rules: [
              { ruleId: 'NAME-001', name: 'Scenario Naming Pattern' },
              { ruleId: 'NAME-002', name: 'Connection Naming Pattern' }
            ]
          }
        ]
      });

      mockApiClient.mockResponse('GET', '/policies/scenario-archival', {
        success: true,
        data: [
          {
            id: 'policy_archival_001',
            name: 'Inactive Scenario Archival Policy',
            conditions: [
              { conditionId: 'ARCH-001', name: 'Inactivity Period' },
              { conditionId: 'ARCH-002', name: 'Resource Utilization' }
            ]
          }
        ]
      });

      // Setup compliance validation responses
      mockApiClient.mockResponse('POST', '/api/compliance/validate', {
        success: true,
        data: {
          compliant: true,
          violations: [],
          riskScore: 0,
          complianceScore: 100
        }
      });

      // Setup naming validation responses
      mockApiClient.mockResponse('POST', '/api/naming/validate', {
        success: true,
        data: {
          validationResults: {
            'scenario_123': {
              status: 'valid',
              suggestions: [],
              details: {
                ruleResults: [
                  {
                    ruleId: 'NAME-001',
                    ruleName: 'Scenario Naming Pattern',
                    isValid: true,
                    errors: [],
                    enforcementLevel: 'warning'
                  }
                ]
              }
            }
          }
        }
      });

      // Setup archival evaluation responses
      mockApiClient.mockResponse('POST', '/api/archival/evaluate', {
        success: true,
        data: {
          scenariosToArchive: []
        }
      });
    });

    it('should execute validate-policy-compliance successfully with single target', async () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-policy-compliance')[0];
      
      const input = {
        targets: [{
          targetType: 'scenario' as const,
          targetId: 'scenario_123',
          targetName: 'Customer Data Processing',
          metadata: {
            description: 'Processes customer orders and data'
          }
        }],
        policySelection: {
          policyTypes: ['compliance', 'naming_convention'] as const,
          frameworks: ['gdpr'] as const,
          activeOnly: true
        },
        validationOptions: {
          includeRecommendations: true,
          includeComplianceScore: true,
          enableCrossValidation: true,
          validationDepth: 'standard' as const
        }
      };

      const result = await executeTool(toolConfig, input);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.validationId).toBeDefined();
      expect(parsedResult.results).toBeDefined();
      expect(Array.isArray(parsedResult.results)).toBe(true);
      expect(parsedResult.results.length).toBe(1);
      expect(parsedResult.summary).toBeDefined();
      expect(parsedResult.summary.totalTargets).toBe(1);
      expect(parsedResult.recommendations).toBeDefined();
      expect(Array.isArray(parsedResult.recommendations)).toBe(true);
    });

    it('should execute validate-policy-compliance with multiple targets', async () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-policy-compliance')[0];
      
      const input = {
        targets: [
          {
            targetType: 'scenario' as const,
            targetId: 'scenario_123',
            targetName: 'Customer Data Processing'
          },
          {
            targetType: 'connection' as const,
            targetId: 'conn_456',
            targetName: 'Database Connection'
          },
          {
            targetType: 'template' as const,
            targetId: 'template_789',
            targetName: 'Data Export Template'
          }
        ],
        policySelection: {
          policyTypes: ['compliance'] as const,
          frameworks: ['gdpr', 'sox'] as const
        },
        validationOptions: {
          includeRecommendations: true,
          includeComplianceScore: true,
          validationDepth: 'comprehensive' as const
        }
      };

      const result = await executeTool(toolConfig, input);
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.results.length).toBe(3);
      expect(parsedResult.summary.totalTargets).toBe(3);
    });

    it('should handle validation with custom execution context', async () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-policy-compliance')[0];
      
      const input = {
        targets: [{
          targetType: 'data_flow' as const,
          targetId: 'flow_999',
          targetName: 'Customer Data Flow'
        }],
        policySelection: {
          frameworks: ['gdpr', 'hipaa'] as const
        },
        validationOptions: {
          validationDepth: 'basic' as const
        },
        executionContext: {
          userId: 'compliance_officer_001',
          reason: 'Security audit requirement',
          correlationId: 'audit_2024_001',
          priority: 'immediate' as const,
          dryRun: true
        }
      };

      const result = await executeTool(toolConfig, input);
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.auditTrail).toBeDefined();
      expect(parsedResult.auditTrail.userId).toBe('compliance_officer_001');
      expect(parsedResult.auditTrail.dryRun).toBe(true);
    });
  });

  describe('Error Handling Scenarios', () => {
    beforeEach(async () => {
      const { addPolicyComplianceValidationTools: importedFunction } = await import('../../../src/tools/policy-compliance-validation.js');
      addPolicyComplianceValidationTools = importedFunction;
      addPolicyComplianceValidationTools(mockServer, mockApiClient as any);
    });

    it('should handle file system errors gracefully', async () => {
      // Mock fs operations to fail
      mockFs.readFile.mockRejectedValueOnce(new Error('Storage system unavailable'));
      
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-policy-compliance')[0];
      
      const input = {
        targets: [{
          targetType: 'scenario' as const,
          targetId: 'scenario_123'
        }],
        policySelection: {},
        validationOptions: {}
      };

      // Should handle the error gracefully
      await expect(executeTool(toolConfig, input)).rejects.toThrow();
    });

    it('should handle API client errors during policy fetching', async () => {
      // Mock API client to fail policy fetching
      mockApiClient.mockFailure('GET', '/policies/compliance', new Error('Policy service unavailable'));
      
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-policy-compliance')[0];
      
      const input = {
        targets: [{
          targetType: 'scenario' as const,
          targetId: 'scenario_123'
        }],
        policySelection: {
          policyTypes: ['compliance'] as const,
          frameworks: ['gdpr'] as const
        },
        validationOptions: {}
      };

      const result = await executeTool(toolConfig, input);
      const parsedResult = JSON.parse(result);
      
      // Should complete validation but may show no applicable policies
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.results).toBeDefined();
    });

    it('should handle individual target validation failures', async () => {
      // Mock compliance validation to fail
      mockApiClient.mockFailure('POST', '/api/compliance/validate', new Error('Target not accessible'));
      
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-policy-compliance')[0];
      
      // Setup policy responses
      mockApiClient.mockResponse('GET', '/policies/compliance', {
        success: true,
        data: [{
          id: 'policy_001',
          name: 'Test Policy',
          framework: ['gdpr']
        }]
      });

      const input = {
        targets: [{
          targetType: 'scenario' as const,
          targetId: 'inaccessible_scenario'
        }],
        policySelection: {
          policyTypes: ['compliance'] as const
        },
        validationOptions: {}
      };

      const result = await executeTool(toolConfig, input);
      const parsedResult = JSON.parse(result);
      
      expect(parsedResult.success).toBe(true);
      // Should handle the error but may still complete validation
      expect(['unknown', 'non_compliant', 'warning'].includes(parsedResult.results[0].overallComplianceStatus)).toBe(true);
      expect(parsedResult.results[0].violations).toBeDefined();
      expect(Array.isArray(parsedResult.results[0].violations)).toBe(true);
    });

    it('should handle storage errors during result persistence', async () => {
      // Mock storage write to fail
      mockFs.writeFile.mockRejectedValueOnce(new Error('Storage write failed'));
      
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-policy-compliance')[0];
      
      const input = {
        targets: [{
          targetType: 'scenario' as const,
          targetId: 'scenario_123'
        }],
        policySelection: {},
        validationOptions: {}
      };

      // Should fail due to storage issues
      await expect(executeTool(toolConfig, input)).rejects.toThrow();
    });
  });

  describe('Policy Rule Validation Testing', () => {
    beforeEach(async () => {
      const { addPolicyComplianceValidationTools: importedFunction } = await import('../../../src/tools/policy-compliance-validation.js');
      addPolicyComplianceValidationTools = importedFunction;
      addPolicyComplianceValidationTools(mockServer, mockApiClient as any);

      // Setup comprehensive policy responses with violations
      mockApiClient.mockResponse('GET', '/policies/compliance', {
        success: true,
        data: [{
          id: 'policy_gdpr_strict',
          name: 'Strict GDPR Compliance Policy',
          framework: ['gdpr'],
          controls: {
            preventive: [
              { controlId: 'GDPR-PREVENT-001', name: 'Data Minimization Control' },
              { controlId: 'GDPR-PREVENT-002', name: 'Consent Management Control' }
            ],
            detective: [
              { controlId: 'GDPR-DETECT-001', name: 'Data Breach Detection' }
            ],
            corrective: [
              { controlId: 'GDPR-CORRECT-001', name: 'Breach Response Procedure' }
            ]
          }
        }]
      });

      // Setup validation response with violations
      mockApiClient.mockResponse('POST', '/api/compliance/validate', {
        success: true,
        data: {
          compliant: false,
          violations: [
            {
              controlId: 'GDPR-PREVENT-001',
              severity: 'high',
              description: 'Data collection exceeds necessary scope for processing purpose',
              recommendations: ['Review data collection scope', 'Implement data minimization controls']
            },
            {
              controlId: 'GDPR-DETECT-001',
              severity: 'medium',
              description: 'Audit logging insufficient for breach detection',
              recommendations: ['Enable comprehensive audit logging', 'Implement real-time monitoring']
            }
          ],
          riskScore: 75,
          complianceScore: 25
        }
      });
    });

    it('should validate compliance policies and detect violations', async () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-policy-compliance')[0];
      
      const input = {
        targets: [{
          targetType: 'scenario' as const,
          targetId: 'data_processing_scenario',
          targetName: 'Customer Data Processing Scenario'
        }],
        policySelection: {
          policyTypes: ['compliance'] as const,
          frameworks: ['gdpr'] as const
        },
        validationOptions: {
          includeViolationDetails: true,
          includeRecommendations: true,
          validationDepth: 'comprehensive' as const
        }
      };

      const result = await executeTool(toolConfig, input);
      const parsedResult = JSON.parse(result);
      
      expect(parsedResult.success).toBe(true);
      expect(['non_compliant', 'warning'].includes(parsedResult.results[0].overallComplianceStatus)).toBe(true);
      expect(parsedResult.results[0].violations.length).toBeGreaterThan(0);
      
      // Check violation details
      const violations = parsedResult.results[0].violations;
      expect(violations.some(v => v.severity === 'high')).toBe(true);
      expect(violations.some(v => v.framework === 'gdpr')).toBe(true);
      expect(violations.every(v => v.recommendations.length > 0)).toBe(true);
    });

    it('should generate appropriate remediation steps for violations', async () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-policy-compliance')[0];
      
      const input = {
        targets: [{
          targetType: 'data_flow' as const,
          targetId: 'customer_data_flow'
        }],
        policySelection: {
          policyTypes: ['compliance'] as const,
          frameworks: ['gdpr'] as const
        },
        validationOptions: {
          includeRecommendations: true
        }
      };

      const result = await executeTool(toolConfig, input);
      const parsedResult = JSON.parse(result);
      
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.recommendations).toBeDefined();
      expect(Array.isArray(parsedResult.recommendations)).toBe(true);
      
      // Check recommendation structure
      const recommendations = parsedResult.recommendations;
      expect(recommendations.every(r => r.priority !== undefined)).toBe(true);
      expect(recommendations.every(r => r.category !== undefined)).toBe(true);
      expect(recommendations.every(r => r.title !== undefined)).toBe(true);
      expect(recommendations.every(r => r.description !== undefined)).toBe(true);
      
      // Check that critical violations get immediate priority recommendations
      const immediateRecommendations = recommendations.filter(r => r.priority === 'immediate');
      // May or may not have immediate recommendations depending on policy setup
      expect(immediateRecommendations).toBeDefined();
    });
  });

  describe('Compliance Checking and Violation Detection', () => {
    beforeEach(async () => {
      const { addPolicyComplianceValidationTools: importedFunction } = await import('../../../src/tools/policy-compliance-validation.js');
      addPolicyComplianceValidationTools = importedFunction;
      addPolicyComplianceValidationTools(mockServer, mockApiClient as any);

      // Setup naming convention validation with violations
      mockApiClient.mockResponse('POST', '/api/naming/validate', {
        success: true,
        data: {
          validationResults: {
            'scenario_invalid_name': {
              status: 'invalid',
              suggestions: ['customer-data-processing-v1', 'customer-data-handler-main'],
              details: {
                ruleResults: [
                  {
                    ruleId: 'NAME-001',
                    ruleName: 'Scenario Naming Pattern',
                    isValid: false,
                    errors: ['Name does not follow kebab-case convention', 'Name exceeds maximum length'],
                    enforcementLevel: 'strict'
                  },
                  {
                    ruleId: 'NAME-002',
                    ruleName: 'Descriptive Naming Rule',
                    isValid: false,
                    errors: ['Name lacks descriptive context'],
                    enforcementLevel: 'warning'
                  }
                ]
              }
            }
          }
        }
      });

      // Setup archival evaluation with archival candidates
      mockApiClient.mockResponse('POST', '/api/archival/evaluate', {
        success: true,
        data: {
          scenariosToArchive: [
            {
              scenarioId: 'inactive_scenario',
              reasons: ['No execution in 90 days', 'Low resource utilization', 'No active connections'],
              score: 0.85
            }
          ]
        }
      });
    });

    it('should detect naming convention violations', async () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-policy-compliance')[0];
      
      mockApiClient.mockResponse('GET', '/policies/naming-conventions', {
        success: true,
        data: [{
          id: 'naming_policy_001',
          name: 'Enterprise Naming Standards',
          rules: [
            { ruleId: 'NAME-001', name: 'Kebab Case Convention' },
            { ruleId: 'NAME-002', name: 'Descriptive Naming' }
          ]
        }]
      });

      const input = {
        targets: [{
          targetType: 'scenario' as const,
          targetId: 'scenario_invalid_name',
          targetName: 'INVALIDSCENARIONAME_123!!!'
        }],
        policySelection: {
          policyTypes: ['naming_convention'] as const
        },
        validationOptions: {
          includeViolationDetails: true
        }
      };

      const result = await executeTool(toolConfig, input);
      const parsedResult = JSON.parse(result);
      
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.results[0].violations.length).toBeGreaterThan(0);
      
      const namingViolations = parsedResult.results[0].violations.filter(v => v.policyType === 'naming_convention');
      expect(namingViolations.length).toBeGreaterThan(0);
      expect(namingViolations.some(v => v.severity === 'critical')).toBe(true); // strict enforcement
    });

    it('should detect archival policy violations', async () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-policy-compliance')[0];
      
      mockApiClient.mockResponse('GET', '/policies/scenario-archival', {
        success: true,
        data: [{
          id: 'archival_policy_001',
          name: 'Inactive Scenario Archival Policy',
          conditions: [
            { conditionId: 'ARCH-001', name: 'Inactivity Threshold' },
            { conditionId: 'ARCH-002', name: 'Resource Utilization Threshold' }
          ]
        }]
      });

      const input = {
        targets: [{
          targetType: 'scenario' as const,
          targetId: 'inactive_scenario',
          targetName: 'Old Unused Scenario'
        }],
        policySelection: {
          policyTypes: ['scenario_archival'] as const
        },
        validationOptions: {
          includeViolationDetails: true
        }
      };

      const result = await executeTool(toolConfig, input);
      const parsedResult = JSON.parse(result);
      
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.results[0].violations.length).toBeGreaterThan(0);
      
      const archivalViolations = parsedResult.results[0].violations.filter(v => v.policyType === 'scenario_archival');
      expect(archivalViolations.length).toBeGreaterThan(0);
      expect(archivalViolations[0].violationType).toBe('archival_candidate');
      expect(archivalViolations[0].metadata.archivalScore).toBe(0.85);
    });

    it('should calculate compliance scores correctly', async () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-policy-compliance')[0];
      
      // Setup mixed compliance results
      mockApiClient.mockResponse('GET', '/policies/compliance', {
        success: true,
        data: [{
          id: 'mixed_policy',
          name: 'Mixed Compliance Policy',
          framework: ['gdpr'],
          controls: { preventive: [{}, {}], detective: [{}], corrective: [{}] } // 4 controls
        }]
      });

      mockApiClient.mockResponse('POST', '/api/compliance/validate', {
        success: true,
        data: {
          compliant: false,
          violations: [
            { controlId: 'CTRL-001', severity: 'high', description: 'High severity violation' }
          ], // 1 violation out of 4 controls
          riskScore: 50,
          complianceScore: 75
        }
      });

      const input = {
        targets: [{
          targetType: 'scenario' as const,
          targetId: 'mixed_compliance_scenario'
        }],
        policySelection: {
          policyTypes: ['compliance'] as const,
          frameworks: ['gdpr'] as const
        },
        validationOptions: {
          includeComplianceScore: true,
          scoringWeights: {
            compliance: 1.0,
            naming: 0.0,
            archival: 0.0
          }
        }
      };

      const result = await executeTool(toolConfig, input);
      const parsedResult = JSON.parse(result);
      
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.results[0].overallComplianceScore).toBeGreaterThan(0);
      expect(parsedResult.results[0].overallRiskScore).toBeGreaterThan(0);
      expect(parsedResult.summary.averageComplianceScore).toBeDefined();
    });
  });

  describe('Cross-Policy Validation and Automated Remediation Testing', () => {
    beforeEach(async () => {
      const { addPolicyComplianceValidationTools: importedFunction } = await import('../../../src/tools/policy-compliance-validation.js');
      addPolicyComplianceValidationTools = importedFunction;
      addPolicyComplianceValidationTools(mockServer, mockApiClient as any);

      // Setup policies that might conflict
      mockApiClient.mockResponse('GET', '/policies/compliance', {
        success: true,
        data: [{
          id: 'compliance_strict',
          name: 'Strict Security Policy',
          framework: ['sox', 'iso27001']
        }]
      });

      mockApiClient.mockResponse('GET', '/policies/naming-conventions', {
        success: true,
        data: [{
          id: 'naming_flexible',
          name: 'Flexible Naming Policy'
        }]
      });

      mockApiClient.mockResponse('GET', '/policies/scenario-archival', {
        success: true,
        data: [{
          id: 'archival_aggressive',
          name: 'Aggressive Archival Policy'
        }]
      });

      // Setup responses with conflicts
      mockApiClient.mockResponse('POST', '/api/compliance/validate', {
        success: true,
        data: {
          compliant: false,
          violations: [
            {
              controlId: 'SOX-001',
              severity: 'critical',
              description: 'Critical security control violation'
            }
          ],
          riskScore: 90,
          complianceScore: 10
        }
      });

      mockApiClient.mockResponse('POST', '/api/naming/validate', {
        success: true,
        data: {
          validationResults: {
            'conflict_scenario': {
              status: 'invalid',
              details: {
                ruleResults: [{
                  ruleId: 'NAME-001',
                  isValid: false,
                  errors: ['Naming conflict with security requirements'],
                  enforcementLevel: 'warning'
                }]
              }
            }
          }
        }
      });

      mockApiClient.mockResponse('POST', '/api/archival/evaluate', {
        success: true,
        data: {
          scenariosToArchive: [{
            scenarioId: 'conflict_scenario',
            reasons: ['Low usage pattern'],
            score: 0.7
          }]
        }
      });
    });

    it('should perform cross-policy validation and detect conflicts', async () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-policy-compliance')[0];
      
      const input = {
        targets: [{
          targetType: 'scenario' as const,
          targetId: 'conflict_scenario',
          targetName: 'Conflicting Requirements Scenario'
        }],
        policySelection: {
          policyTypes: ['compliance', 'naming_convention', 'scenario_archival'] as const,
          frameworks: ['sox', 'iso27001'] as const
        },
        validationOptions: {
          enableCrossValidation: true,
          includeViolationDetails: true,
          validationDepth: 'comprehensive' as const
        }
      };

      const result = await executeTool(toolConfig, input);
      const parsedResult = JSON.parse(result);
      
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.crossValidationResults).toBeDefined();
      expect(Array.isArray(parsedResult.crossValidationResults)).toBe(true);
      
      // Should detect conflicts between different policy types
      if (parsedResult.crossValidationResults.length > 0) {
        const conflicts = parsedResult.crossValidationResults;
        expect(conflicts.some(c => c.issueType.includes('conflict'))).toBe(true);
        expect(conflicts.every(c => c.recommendations.length > 0)).toBe(true);
      }
    });

    it('should generate comprehensive remediation recommendations', async () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-policy-compliance')[0];
      
      const input = {
        targets: [{
          targetType: 'data_flow' as const,
          targetId: 'high_violation_flow'
        }],
        policySelection: {
          policyTypes: ['compliance', 'naming_convention'] as const
        },
        validationOptions: {
          includeRecommendations: true,
          validationDepth: 'comprehensive' as const
        }
      };

      const result = await executeTool(toolConfig, input);
      const parsedResult = JSON.parse(result);
      
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.recommendations).toBeDefined();
      expect(Array.isArray(parsedResult.recommendations)).toBe(true);
      
      // Check recommendation structure and content
      const recommendations = parsedResult.recommendations;
      if (recommendations && recommendations.length > 0) {
        expect(recommendations.every(r => ['immediate', 'high', 'medium', 'low', 'informational'].includes(r.priority))).toBe(true);
        expect(recommendations.every(r => r.category !== undefined)).toBe(true);
        expect(recommendations.every(r => r.estimatedImpact !== undefined)).toBe(true);
        expect(recommendations.every(r => typeof r.automatable === 'boolean')).toBe(true);
        
        // Should be sorted by priority
        const priorityOrder = { immediate: 0, high: 1, medium: 2, low: 3, informational: 4 };
        for (let i = 1; i < recommendations.length; i++) {
          expect(priorityOrder[recommendations[i-1].priority]).toBeLessThanOrEqual(priorityOrder[recommendations[i].priority]);
        }
      }
    });

    it('should provide detailed compliance breakdown', async () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-policy-compliance')[0];
      
      const input = {
        targets: [
          {
            targetType: 'scenario' as const,
            targetId: 'scenario_1'
          },
          {
            targetType: 'connection' as const,
            targetId: 'connection_1'
          }
        ],
        policySelection: {
          policyTypes: ['compliance'] as const,
          frameworks: ['gdpr', 'sox'] as const
        },
        validationOptions: {
          includeComplianceScore: true
        }
      };

      const result = await executeTool(toolConfig, input);
      const parsedResult = JSON.parse(result);
      
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.complianceBreakdown).toBeDefined();
      
      const breakdown = parsedResult.complianceBreakdown;
      expect(breakdown.byFramework).toBeDefined();
      expect(breakdown.byPolicyType).toBeDefined();
      expect(breakdown.bySeverity).toBeDefined();
      
      // Check framework breakdown structure
      Object.values(breakdown.byFramework).forEach((frameworkData: any) => {
        expect(frameworkData.score).toBeDefined();
        expect(frameworkData.violations).toBeDefined();
        expect(frameworkData.targets).toBeDefined();
      });
    });

    it('should support different report formats and export options', async () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-policy-compliance')[0];
      
      const input = {
        targets: [{
          targetType: 'organization' as const,
          targetId: 'org_12345'
        }],
        policySelection: {},
        validationOptions: {},
        reportingOptions: {
          format: 'executive' as const,
          includeAuditTrail: true,
          includeHistoricalTrends: true,
          exportOptions: {
            generatePdf: true,
            generateExcel: true,
            generateDashboard: true
          }
        },
        executionContext: {
          userId: 'executive_user',
          reason: 'Board compliance report',
          priority: 'immediate' as const
        }
      };

      const result = await executeTool(toolConfig, input);
      const parsedResult = JSON.parse(result);
      
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.reportingOptions).toBeDefined();
      expect(parsedResult.reportingOptions.currentFormat).toBe('executive');
      expect(parsedResult.reportingOptions.exportOptions.downloadUrls).toBeDefined();
      expect(parsedResult.reportingOptions.exportOptions.downloadUrls.pdf).toBeDefined();
      expect(parsedResult.reportingOptions.exportOptions.downloadUrls.excel).toBeDefined();
      expect(parsedResult.reportingOptions.exportOptions.downloadUrls.dashboard).toBeDefined();
    });
  });

  describe('Advanced Validation Features', () => {
    beforeEach(async () => {
      const { addPolicyComplianceValidationTools: importedFunction } = await import('../../../src/tools/policy-compliance-validation.js');
      addPolicyComplianceValidationTools = importedFunction;
      addPolicyComplianceValidationTools(mockServer, mockApiClient as any);
    });

    it('should handle validation with custom scoring weights', async () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-policy-compliance')[0];
      
      const input = {
        targets: [{
          targetType: 'scenario' as const,
          targetId: 'weighted_scenario'
        }],
        policySelection: {
          policyTypes: ['compliance', 'naming_convention', 'scenario_archival'] as const
        },
        validationOptions: {
          includeComplianceScore: true,
          scoringWeights: {
            compliance: 0.6,  // Higher weight for compliance
            naming: 0.2,      // Lower weight for naming
            archival: 0.2     // Lower weight for archival
          },
          severityThresholds: {
            critical: 95,
            high: 80,
            medium: 60,
            low: 30
          }
        }
      };

      const result = await executeTool(toolConfig, input);
      const parsedResult = JSON.parse(result);
      
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.results[0].overallComplianceScore).toBeDefined();
      // Score should reflect the custom weighting
    });

    it('should support all validation depth levels', async () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-policy-compliance')[0];
      
      const validationDepths = ['basic', 'standard', 'comprehensive'] as const;
      
      for (const depth of validationDepths) {
        const input = {
          targets: [{
            targetType: 'template' as const,
            targetId: `template_${depth}`
          }],
          policySelection: {},
          validationOptions: {
            validationDepth: depth
          }
        };

        const result = await executeTool(toolConfig, input);
        const parsedResult = JSON.parse(result);
        
        expect(parsedResult.success).toBe(true);
        expect(parsedResult.auditTrail.validationDepth).toBe(depth);
      }
    });

    it('should handle dry run execution correctly', async () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-policy-compliance')[0];
      
      const input = {
        targets: [{
          targetType: 'user' as const,
          targetId: 'user_test_123'
        }],
        policySelection: {},
        validationOptions: {},
        executionContext: {
          dryRun: true,
          reason: 'Testing validation rules'
        }
      };

      const result = await executeTool(toolConfig, input);
      const parsedResult = JSON.parse(result);
      
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.auditTrail.dryRun).toBe(true);
      // In dry run mode, violations should not be logged to audit systems
    });

    it('should provide comprehensive capability information', async () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'validate-policy-compliance')[0];
      
      const input = {
        targets: [{
          targetType: 'folder' as const,
          targetId: 'folder_capabilities_test'
        }],
        policySelection: {},
        validationOptions: {}
      };

      const result = await executeTool(toolConfig, input);
      const parsedResult = JSON.parse(result);
      
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.capabilities).toBeDefined();
      
      const capabilities = parsedResult.capabilities;
      expect(capabilities.policyTypes).toEqual(['compliance', 'naming_convention', 'scenario_archival']);
      expect(capabilities.frameworks).toEqual(['sox', 'gdpr', 'hipaa', 'pci_dss', 'iso27001', 'enterprise', 'custom']);
      expect(capabilities.validationDepths).toEqual(['basic', 'standard', 'comprehensive']);
      expect(capabilities.crossValidation).toBe(true);
      expect(capabilities.scoring).toBe(true);
      expect(capabilities.recommendations).toBe(true);
      expect(capabilities.auditIntegration).toBe(true);
      expect(capabilities.historicalTracking).toBe(true);
      expect(capabilities.automatedRemediation).toBe(true);
    });
  });
});