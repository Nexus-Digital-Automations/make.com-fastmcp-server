/**
 * Basic Test Suite for Audit and Compliance Tools
 * Tests core functionality of audit and compliance management tools
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { createMockServer } from '../../utils/test-helpers.js';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';

describe('Audit and Compliance Tools - Basic Tests', () => {
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
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Tool Registration', () => {
    it('should successfully import and register audit compliance tools', async () => {
      const { addAuditComplianceTools } = await import('../../../src/tools/audit-compliance.js');
      
      // Should not throw an error
      expect(() => {
        addAuditComplianceTools(mockServer, mockApiClient as any);
      }).not.toThrow();
      
      // Should call addTool for each tool
      expect(mockTool).toHaveBeenCalled();
      expect(mockTool.mock.calls.length).toBeGreaterThan(0);
    });

    it('should export the expected tools', async () => {
      const auditComplianceModule = await import('../../../src/tools/audit-compliance.js');
      
      // Check that expected exports exist
      expect(auditComplianceModule.addAuditComplianceTools).toBeDefined();
      expect(typeof auditComplianceModule.addAuditComplianceTools).toBe('function');
      
      expect(auditComplianceModule.generateComplianceReportTool).toBeDefined();
      expect(auditComplianceModule.performAuditMaintenanceTool).toBeDefined();
      expect(auditComplianceModule.getAuditConfigurationTool).toBeDefined();
      expect(auditComplianceModule.securityHealthCheckTool).toBeDefined();
      expect(auditComplianceModule.createSecurityIncidentTool).toBeDefined();
    });
  });

  describe('Tool Configuration', () => {
    it('should have correct tool structure', async () => {
      const { generateComplianceReportTool } = await import('../../../src/tools/audit-compliance.js');
      
      expect(generateComplianceReportTool.name).toBe('generate_compliance_report');
      expect(generateComplianceReportTool.description).toBeDefined();
      expect(generateComplianceReportTool.inputSchema).toBeDefined();
      expect(typeof generateComplianceReportTool.handler).toBe('function');
    });

    it('should have security health check tool with correct structure', async () => {
      const { securityHealthCheckTool } = await import('../../../src/tools/audit-compliance.js');
      
      expect(securityHealthCheckTool.name).toBe('security_health_check');
      expect(securityHealthCheckTool.description).toBeDefined();
      expect(securityHealthCheckTool.inputSchema).toBeDefined();
      expect(typeof securityHealthCheckTool.handler).toBe('function');
    });
  });

  describe('Tool Execution', () => {
    it('should execute security health check successfully', async () => {
      const { securityHealthCheckTool } = await import('../../../src/tools/audit-compliance.js');
      
      // Mock execution should not throw
      const result = await securityHealthCheckTool.handler({});
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      // Parse the JSON result
      const parsedResult = JSON.parse(result);
      expect(parsedResult.stats).toBeDefined();
      expect(parsedResult.stats.totalEvents).toBeDefined();
    });

    it('should execute generate compliance report with valid input', async () => {
      const { generateComplianceReportTool } = await import('../../../src/tools/audit-compliance.js');
      
      const input = {
        startDate: '2024-01-01T00:00:00Z',
        endDate: '2024-01-31T23:59:59Z',
        format: 'json' as const,
      };
      
      const result = await generateComplianceReportTool.handler(input);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      // Parse the JSON result
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.report).toBeDefined();
    });

    it('should execute audit maintenance successfully', async () => {
      const { performAuditMaintenanceTool } = await import('../../../src/tools/audit-compliance.js');
      
      const result = await performAuditMaintenanceTool.handler({});
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      // Parse the JSON result
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.deletedFiles).toBeDefined();
      expect(parsedResult.rotatedFiles).toBeDefined();
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid date ranges in compliance report', async () => {
      const { generateComplianceReportTool } = await import('../../../src/tools/audit-compliance.js');
      
      const input = {
        startDate: '2024-12-31T23:59:59Z',
        endDate: '2024-01-01T00:00:00Z', // End before start
        format: 'json' as const,
      };
      
      // Should handle gracefully and not throw
      const result = await generateComplianceReportTool.handler(input);
      expect(result).toBeDefined();
      
      const parsedResult = JSON.parse(result);
      // Should either succeed with warnings or fail gracefully
      expect(parsedResult).toBeDefined();
    });
  });
});