/**
 * @fileoverview Comprehensive integration tests for Make.com FastMCP tool endpoints
 * 
 * Tests end-to-end functionality of all major tool categories including:
 * - AI/ML tools (ai-agents, ai-governance)
 * - Security tools (zero-trust-auth, multi-tenant-security) 
 * - Infrastructure tools (log-streaming, monitoring, performance)
 * - Business logic tools (marketplace, budget-control)
 * - Policy/compliance tools
 * 
 * @version 1.0.0
 */

import { describe, test, expect, beforeAll, afterAll, beforeEach, afterEach } from '@jest/globals';
import type { FastMCP } from 'fastmcp';
import type MakeApiClient from '../../src/lib/make-api-client.js';

// Tool imports
import { addAIAgentTools } from '../../src/tools/ai-agents.js';
import { addAIGovernanceEngineTools } from '../../src/tools/ai-governance-engine.js';
import { addZeroTrustAuthTools } from '../../src/tools/zero-trust-auth.js';
import { addMultiTenantSecurityTools } from '../../src/tools/multi-tenant-security.js';
import { addLogStreamingTools } from '../../src/tools/log-streaming.js';
import { addRealTimeMonitoringTools } from '../../src/tools/real-time-monitoring.js';
import { addPerformanceAnalysisTools } from '../../src/tools/performance-analysis.js';
import { addMarketplaceTools } from '../../src/tools/marketplace.js';
import { addBudgetControlTools } from '../../src/tools/budget-control.js';
import { addPolicyComplianceValidationTools } from '../../src/tools/policy-compliance-validation.js';
import { addEnterpriseSecretsTools } from '../../src/tools/enterprise-secrets.js';
import { addBlueprintCollaborationTools } from '../../src/tools/blueprint-collaboration.js';

// Mock implementations
const mockServer: FastMCP = {
  addTool: jest.fn(),
  addResource: jest.fn(),
  addPrompt: jest.fn(),
} as unknown as FastMCP;

const mockApiClient: MakeApiClient = {
  get: jest.fn(),
  post: jest.fn(), 
  put: jest.fn(),
  delete: jest.fn(),
  getTeams: jest.fn(),
  getScenarios: jest.fn(),
  getConnections: jest.fn(),
  testConnection: jest.fn(),
} as unknown as MakeApiClient;

// Test data
const testScenarioId = 'test-scenario-123';
const testTeamId = 123;
const testUserId = 'test-user-456';
const testOrgId = 'test-org-789';

describe('Tool Endpoints Integration Tests', () => {
  beforeAll(async () => {
    // Global setup
    process.env.NODE_ENV = 'test';
  });

  afterAll(async () => {
    // Global cleanup
    jest.clearAllMocks();
  });

  beforeEach(() => {
    // Reset mocks before each test
    jest.clearAllMocks();
    
    // Setup default mock responses
    (mockApiClient.get as jest.Mock).mockResolvedValue({ data: {} });
    (mockApiClient.post as jest.Mock).mockResolvedValue({ data: {} });
    (mockApiClient.put as jest.Mock).mockResolvedValue({ data: {} });
    (mockApiClient.delete as jest.Mock).mockResolvedValue({ data: {} });
  });

  afterEach(() => {
    // Cleanup after each test
    jest.clearAllMocks();
  });

  describe('AI/ML Tools Integration', () => {
    describe('AI Agents Tool', () => {
      test('should register AI agent tools successfully', () => {
        expect(() => {
          addAIAgentTools(mockServer, mockApiClient);
        }).not.toThrow();
        
        expect(mockServer.addTool).toHaveBeenCalledTimes(4);
      });

      test('should handle AI agent operations', async () => {
        addAIAgentTools(mockServer, mockApiClient);
        
        // Verify tool registration calls
        const toolCalls = (mockServer.addTool as jest.Mock).mock.calls;
        expect(toolCalls).toHaveLength(4);
        
        // Check for key AI agent tools
        const toolNames = toolCalls.map(call => call[0].name);
        expect(toolNames).toContain('create_ai_agent');
        expect(toolNames).toContain('manage_ai_agent');
        expect(toolNames).toContain('monitor_ai_agent');
      });
    });

    describe('AI Governance Engine Tool', () => {
      test('should register AI governance tools successfully', () => {
        expect(() => {
          addAIGovernanceEngineTools(mockServer, mockApiClient);
        }).not.toThrow();
        
        expect(mockServer.addTool).toHaveBeenCalledTimes(6);
      });

      test('should handle governance policy operations', async () => {
        addAIGovernanceEngineTools(mockServer, mockApiClient);
        
        const toolCalls = (mockServer.addTool as jest.Mock).mock.calls;
        const toolNames = toolCalls.map(call => call[0].name);
        
        expect(toolNames).toContain('create_governance_policy');
        expect(toolNames).toContain('validate_ai_compliance');
        expect(toolNames).toContain('generate_governance_report');
      });
    });
  });

  describe('Security Tools Integration', () => {
    describe('Zero Trust Auth Tool', () => {
      test('should register zero trust auth tools successfully', () => {
        expect(() => {
          addZeroTrustAuthTools(mockServer, mockApiClient);
        }).not.toThrow();
        
        expect(mockServer.addTool).toHaveBeenCalledTimes(12);
      });

      test('should handle authentication and authorization', async () => {
        addZeroTrustAuthTools(mockServer, mockApiClient);
        
        const toolCalls = (mockServer.addTool as jest.Mock).mock.calls;
        const toolNames = toolCalls.map(call => call[0].name);
        
        expect(toolNames).toContain('configure_zero_trust_policy');
        expect(toolNames).toContain('validate_access_request');
        expect(toolNames).toContain('audit_security_events');
      });
    });

    describe('Multi-Tenant Security Tool', () => {
      test('should register multi-tenant security tools successfully', () => {
        expect(() => {
          addMultiTenantSecurityTools(mockServer, mockApiClient);
        }).not.toThrow();
        
        expect(mockServer.addTool).toHaveBeenCalledTimes(13);
      });

      test('should handle tenant isolation and security', async () => {
        addMultiTenantSecurityTools(mockServer, mockApiClient);
        
        const toolCalls = (mockServer.addTool as jest.Mock).mock.calls;
        const toolNames = toolCalls.map(call => call[0].name);
        
        expect(toolNames).toContain('create_tenant_security_profile');
        expect(toolNames).toContain('audit_tenant_access');
        expect(toolNames).toContain('validate_tenant_isolation');
      });
    });

    describe('Enterprise Secrets Tool', () => {
      test('should register enterprise secrets tools successfully', () => {
        expect(() => {
          addEnterpriseSecretsTools(mockServer, mockApiClient);
        }).not.toThrow();
        
        expect(mockServer.addTool).toHaveBeenCalledTimes(16);
      });

      test('should handle secrets management operations', async () => {
        addEnterpriseSecretsTools(mockServer, mockApiClient);
        
        const toolCalls = (mockServer.addTool as jest.Mock).mock.calls;
        const toolNames = toolCalls.map(call => call[0].name);
        
        expect(toolNames).toContain('create_secret');
        expect(toolNames).toContain('rotate_secret');
        expect(toolNames).toContain('audit_secret_access');
      });
    });
  });

  describe('Infrastructure Tools Integration', () => {
    describe('Log Streaming Tool', () => {
      test('should register log streaming tools successfully', () => {
        expect(() => {
          addLogStreamingTools(mockServer, mockApiClient);
        }).not.toThrow();
        
        expect(mockServer.addTool).toHaveBeenCalledTimes(19);
      });

      test('should handle real-time log streaming operations', async () => {
        addLogStreamingTools(mockServer, mockApiClient);
        
        const toolCalls = (mockServer.addTool as jest.Mock).mock.calls;
        const toolNames = toolCalls.map(call => call[0].name);
        
        expect(toolNames).toContain('start_log_stream');
        expect(toolNames).toContain('configure_log_filters');
        expect(toolNames).toContain('export_log_data');
      });
    });

    describe('Real-Time Monitoring Tool', () => {
      test('should register monitoring tools successfully', () => {
        expect(() => {
          addRealTimeMonitoringTools(mockServer, mockApiClient);
        }).not.toThrow();
        
        expect(mockServer.addTool).toHaveBeenCalledTimes(8);
      });

      test('should handle monitoring and alerting', async () => {
        addRealTimeMonitoringTools(mockServer, mockApiClient);
        
        const toolCalls = (mockServer.addTool as jest.Mock).mock.calls;
        const toolNames = toolCalls.map(call => call[0].name);
        
        expect(toolNames).toContain('start_real_time_monitoring');
        expect(toolNames).toContain('configure_monitoring_alerts');
        expect(toolNames).toContain('get_system_health');
      });
    });

    describe('Performance Analysis Tool', () => {
      test('should register performance analysis tools successfully', () => {
        expect(() => {
          addPerformanceAnalysisTools(mockServer, mockApiClient);
        }).not.toThrow();
        
        expect(mockServer.addTool).toHaveBeenCalledTimes(6);
      });

      test('should handle performance analysis operations', async () => {
        addPerformanceAnalysisTools(mockServer, mockApiClient);
        
        const toolCalls = (mockServer.addTool as jest.Mock).mock.calls;
        const toolNames = toolCalls.map(call => call[0].name);
        
        expect(toolNames).toContain('analyze_scenario_performance');
        expect(toolNames).toContain('generate_performance_report');
        expect(toolNames).toContain('optimize_performance');
      });
    });
  });

  describe('Business Logic Tools Integration', () => {
    describe('Marketplace Tool', () => {
      test('should register marketplace tools successfully', () => {
        expect(() => {
          addMarketplaceTools(mockServer, mockApiClient);
        }).not.toThrow();
        
        expect(mockServer.addTool).toHaveBeenCalledTimes(7);
      });

      test('should handle marketplace operations', async () => {
        addMarketplaceTools(mockServer, mockApiClient);
        
        const toolCalls = (mockServer.addTool as jest.Mock).mock.calls;
        const toolNames = toolCalls.map(call => call[0].name);
        
        expect(toolNames).toContain('browse_marketplace');
        expect(toolNames).toContain('install_marketplace_app');
        expect(toolNames).toContain('manage_app_subscriptions');
      });
    });

    describe('Budget Control Tool', () => {
      test('should register budget control tools successfully', () => {
        expect(() => {
          addBudgetControlTools(mockServer, mockApiClient);
        }).not.toThrow();
        
        expect(mockServer.addTool).toHaveBeenCalledTimes(8);
      });

      test('should handle budget management operations', async () => {
        addBudgetControlTools(mockServer, mockApiClient);
        
        const toolCalls = (mockServer.addTool as jest.Mock).mock.calls;
        const toolNames = toolCalls.map(call => call[0].name);
        
        expect(toolNames).toContain('set_budget_limits');
        expect(toolNames).toContain('monitor_budget_usage');
        expect(toolNames).toContain('generate_budget_alerts');
      });
    });
  });

  describe('Policy and Compliance Tools Integration', () => {
    describe('Policy Compliance Validation Tool', () => {
      test('should register policy compliance tools successfully', () => {
        expect(() => {
          addPolicyComplianceValidationTools(mockServer, mockApiClient);
        }).not.toThrow();
        
        expect(mockServer.addTool).toHaveBeenCalledTimes(8);
      });

      test('should handle compliance validation operations', async () => {
        addPolicyComplianceValidationTools(mockServer, mockApiClient);
        
        const toolCalls = (mockServer.addTool as jest.Mock).mock.calls;
        const toolNames = toolCalls.map(call => call[0].name);
        
        expect(toolNames).toContain('validate_policy_compliance');
        expect(toolNames).toContain('generate_compliance_report');
        expect(toolNames).toContain('remediate_compliance_violations');
      });
    });

    describe('Blueprint Collaboration Tool', () => {
      test('should register blueprint collaboration tools successfully', () => {
        expect(() => {
          addBlueprintCollaborationTools(mockServer, mockApiClient);
        }).not.toThrow();
        
        expect(mockServer.addTool).toHaveBeenCalledTimes(9);
      });

      test('should handle collaborative blueprint operations', async () => {
        addBlueprintCollaborationTools(mockServer, mockApiClient);
        
        const toolCalls = (mockServer.addTool as jest.Mock).mock.calls;
        const toolNames = toolCalls.map(call => call[0].name);
        
        expect(toolNames).toContain('create_collaboration_session');
        expect(toolNames).toContain('share_blueprint');
        expect(toolNames).toContain('manage_blueprint_permissions');
      });
    });
  });

  describe('Cross-Tool Integration Scenarios', () => {
    test('should support multi-tool workflow integration', async () => {
      // Register multiple tool sets
      addAIAgentTools(mockServer, mockApiClient);
      addZeroTrustAuthTools(mockServer, mockApiClient);
      addLogStreamingTools(mockServer, mockApiClient);
      addPerformanceAnalysisTools(mockServer, mockApiClient);
      
      // Verify all tools are registered
      expect(mockServer.addTool).toHaveBeenCalledTimes(43); // Sum of all tool counts
    });

    test('should handle error scenarios across tool integrations', async () => {
      // Setup error conditions
      (mockApiClient.get as jest.Mock).mockRejectedValue(new Error('API Error'));
      
      // Test tool registration still works even with API errors
      expect(() => {
        addAIAgentTools(mockServer, mockApiClient);
        addZeroTrustAuthTools(mockServer, mockApiClient);
      }).not.toThrow();
      
      expect(mockServer.addTool).toHaveBeenCalledTimes(16);
    });

    test('should support concurrent tool operations', async () => {
      // Register tools concurrently
      const toolRegistrations = Promise.all([
        Promise.resolve(addAIAgentTools(mockServer, mockApiClient)),
        Promise.resolve(addZeroTrustAuthTools(mockServer, mockApiClient)),
        Promise.resolve(addLogStreamingTools(mockServer, mockApiClient)),
        Promise.resolve(addPerformanceAnalysisTools(mockServer, mockApiClient)),
      ]);
      
      await expect(toolRegistrations).resolves.toBeDefined();
      expect(mockServer.addTool).toHaveBeenCalledTimes(37);
    });

    test('should validate tool parameter schemas', async () => {
      addAIAgentTools(mockServer, mockApiClient);
      
      const toolCalls = (mockServer.addTool as jest.Mock).mock.calls;
      
      // Verify all tools have proper schema definitions
      toolCalls.forEach(([tool]) => {
        expect(tool).toHaveProperty('name');
        expect(tool).toHaveProperty('description');
        expect(tool).toHaveProperty('inputSchema');
        expect(tool.inputSchema).toHaveProperty('type', 'object');
      });
    });

    test('should handle authentication flow integration', async () => {
      // Test integration between auth tools and other tools
      addZeroTrustAuthTools(mockServer, mockApiClient);
      addMultiTenantSecurityTools(mockServer, mockApiClient);
      addEnterpriseSecretsTools(mockServer, mockApiClient);
      
      // Verify security-focused tools are properly registered
      expect(mockServer.addTool).toHaveBeenCalledTimes(41);
      
      // Verify auth-related tools are present
      const toolCalls = (mockServer.addTool as jest.Mock).mock.calls;
      const toolNames = toolCalls.map(call => call[0].name);
      
      expect(toolNames).toContain('configure_zero_trust_policy');
      expect(toolNames).toContain('create_tenant_security_profile');
      expect(toolNames).toContain('create_secret');
    });

    test('should support comprehensive monitoring integration', async () => {
      // Test integration of all monitoring and analysis tools
      addRealTimeMonitoringTools(mockServer, mockApiClient);
      addPerformanceAnalysisTools(mockServer, mockApiClient);
      addLogStreamingTools(mockServer, mockApiClient);
      
      expect(mockServer.addTool).toHaveBeenCalledTimes(33);
      
      const toolCalls = (mockServer.addTool as jest.Mock).mock.calls;
      const toolNames = toolCalls.map(call => call[0].name);
      
      // Verify comprehensive monitoring capabilities
      expect(toolNames).toContain('start_real_time_monitoring');
      expect(toolNames).toContain('analyze_scenario_performance');
      expect(toolNames).toContain('start_log_stream');
    });
  });

  describe('Tool Configuration and Validation', () => {
    test('should validate tool input schemas', async () => {
      addAIAgentTools(mockServer, mockApiClient);
      
      const toolCalls = (mockServer.addTool as jest.Mock).mock.calls;
      
      toolCalls.forEach(([tool]) => {
        const schema = tool.inputSchema;
        expect(schema).toHaveProperty('type');
        expect(schema).toHaveProperty('properties');
        
        if (schema.required) {
          expect(Array.isArray(schema.required)).toBe(true);
        }
      });
    });

    test('should handle tool configuration errors gracefully', async () => {
      // Test with invalid server configuration
      const invalidServer = {} as FastMCP;
      
      expect(() => {
        addAIAgentTools(invalidServer, mockApiClient);
      }).toThrow();
    });

    test('should support tool capability discovery', async () => {
      // Register multiple tool categories
      addAIAgentTools(mockServer, mockApiClient);
      addZeroTrustAuthTools(mockServer, mockApiClient);
      addLogStreamingTools(mockServer, mockApiClient);
      
      const toolCalls = (mockServer.addTool as jest.Mock).mock.calls;
      
      // Verify tools cover different capability areas
      const categories = new Set();
      toolCalls.forEach(([tool]) => {
        const description = tool.description.toLowerCase();
        if (description.includes('ai') || description.includes('agent')) {
          categories.add('ai');
        }
        if (description.includes('security') || description.includes('auth')) {
          categories.add('security');
        }
        if (description.includes('log') || description.includes('monitoring')) {
          categories.add('monitoring');
        }
      });
      
      expect(categories.size).toBeGreaterThan(1);
    });
  });
});