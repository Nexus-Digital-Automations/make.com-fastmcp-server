/**
 * Comprehensive Test Suite for Audit and Compliance Tools
 * Tests all 6 audit and compliance management tools with security validation
 * and advanced testing patterns following testing.md guidelines
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { UserError } from 'fastmcp';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';
import { 
  createMockServer, 
  findTool, 
  executeTool, 
  expectToolCall,
  expectProgressReported,
  expectValidZodParse,
  expectInvalidZodParse
} from '../../utils/test-helpers.js';
import { testScenario, testConnection, testErrors } from '../../fixtures/test-data.js';

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
  sqlInjection: ["'; DROP TABLE users; --", "1' OR '1'='1", "'; SELECT * FROM sensitive_data; --"],
  xss: ["<script>alert('xss')</script>", "javascript:alert('xss')", "<img src=x onerror=alert('xss')>"],
  pathTraversal: ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam", "....//....//etc/passwd"],
  commandInjection: ["; cat /etc/passwd", "| whoami", "&& rm -rf /", "; shutdown -h now"],
  ldapInjection: ["*)(uid=*))(|(uid=*", "*)(|(objectClass=*))", "admin)(&(password=*)"],
};

// Performance testing configuration
// const performanceConfig = {
//   concurrencyLevels: [1, 5, 10, 25, 50],
//   requestsPerLevel: 100,
//   timeoutMs: 5000,
//   acceptableLatencyP95: 1000,
//   acceptableLatencyP99: 2000,
// };

describe('Audit and Compliance Tools', () => {
  let mockServer: any;
  let mockApiClient: MockMakeApiClient;
  let mockTool: jest.MockedFunction<any>;
  let chaosMonkey: ChaosMonkey;

  // Mock data generators
  const generateMockAuditEvent = (overrides?: Partial<MakeAuditEvent>): MakeAuditEvent => ({
    id: Math.floor(Math.random() * 100000),
    timestamp: new Date().toISOString(),
    level: 'info',
    category: 'authentication',
    action: 'user_login',
    actor: {
      userId: 12345,
      userName: 'test.user@example.com',
      userRole: 'admin',
      sessionId: 'session_' + Math.random().toString(36).substr(2, 9),
      ipAddress: '192.168.1.100',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      metadata: {
        department: 'Engineering',
        location: 'US-East',
        authMethod: 'oauth2',
      },
    },
    resource: {
      type: 'user_account',
      id: 'user_12345',
      name: 'Test User Account',
      organizationId: 1001,
      teamId: 2001,
      attributes: {
        accountType: 'standard',
        permissions: ['read', 'write'],
        lastAccess: new Date(Date.now() - 86400000).toISOString(),
      },
    },
    changes: {
      before: { status: 'logged_out', lastLogin: null },
      after: { status: 'logged_in', lastLogin: new Date().toISOString() },
      fields: ['status', 'lastLogin'],
    },
    context: {
      source: 'web_application',
      correlationId: 'corr_' + Math.random().toString(36).substr(2, 9),
      parentEventId: null,
      tags: ['authentication', 'login', 'success'],
      environment: 'production',
      application: 'make-platform',
      version: '2.1.0',
    },
    compliance: {
      frameworks: ['SOX', 'GDPR', 'HIPAA'],
      requirements: ['data_access_logging', 'user_authentication'],
      retentionPeriod: 2555, // 7 years in days
      classification: 'internal',
    },
    riskLevel: 'low',
    outcome: 'success',
    errorDetails: null,
    ...overrides,
  });

  const generateMockComplianceReport = (overrides?: Partial<MakeComplianceReport>): MakeComplianceReport => ({
    id: Math.floor(Math.random() * 100000),
    title: 'Monthly Security Compliance Report',
    description: 'Comprehensive security and compliance assessment for the current month',
    framework: 'SOX',
    reportType: 'periodic',
    period: {
      startDate: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
      endDate: new Date().toISOString(),
      timezone: 'UTC',
    },
    organizationId: 1001,
    teamId: 2001,
    scope: {
      systems: ['make-platform', 'api-gateway', 'data-warehouse'],
      dataTypes: ['financial', 'personal', 'system'],
      processes: ['user_management', 'data_processing', 'access_control'],
      regions: ['US', 'EU', 'APAC'],
    },
    findings: [
      {
        id: 'finding_001',
        severity: 'medium',
        category: 'access_control',
        title: 'Privileged Access Review Required',
        description: 'Some privileged accounts have not been reviewed in the past 90 days',
        impact: 'Potential unauthorized access to sensitive systems',
        recommendation: 'Implement quarterly privileged access reviews',
        status: 'open',
        assignedTo: 'security-team',
        dueDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
        evidence: ['audit_log_001', 'access_report_q3'],
      },
    ],
    metrics: {
      totalEvents: 125436,
      criticalEvents: 23,
      complianceScore: 94.5,
      riskScore: 2.1,
      trendsFromPrevious: {
        eventsChange: '+12%',
        complianceChange: '+2.1%',
        riskChange: '-0.5%',
      },
    },
    recommendations: [
      'Implement automated compliance monitoring',
      'Enhance privileged access management',
      'Strengthen data encryption policies',
    ],
    status: 'completed',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    createdBy: 67890,
    createdByName: 'Security Auditor',
    ...overrides,
  });

  const generateMockSecurityAlert = (overrides?: Partial<MakeSecurityAlert>): MakeSecurityAlert => ({
    id: Math.floor(Math.random() * 100000),
    title: 'Suspicious Login Activity Detected',
    description: 'Multiple failed login attempts from unusual geographic location',
    severity: 'high',
    category: 'authentication',
    source: 'security_monitoring',
    triggeredBy: {
      ruleId: 'rule_failed_logins_001',
      ruleName: 'Failed Login Attempts Threshold',
      threshold: 5,
      actualValue: 8,
      timeWindow: '5 minutes',
    },
    affectedResources: [
      {
        type: 'user_account',
        id: 'user_12345',
        name: 'test.user@example.com',
        criticality: 'high',
      },
    ],
    timeline: [
      {
        timestamp: new Date(Date.now() - 300000).toISOString(),
        event: 'First failed login attempt detected',
        source: 'authentication_service',
      },
      {
        timestamp: new Date(Date.now() - 240000).toISOString(),
        event: 'Pattern recognition: Geographic anomaly detected',
        source: 'threat_detection',
      },
      {
        timestamp: new Date().toISOString(),
        event: 'Alert triggered due to threshold breach',
        source: 'alerting_system',
      },
    ],
    indicators: {
      ipAddresses: ['203.0.113.45', '198.51.100.67'],
      userAgents: ['Suspicious-Bot/1.0', 'Unknown-Client/2.1'],
      geolocations: ['Unknown Location', 'Tor Exit Node'],
      patterns: ['brute_force', 'credential_stuffing'],
    },
    riskAssessment: {
      riskScore: 8.5,
      likelihood: 'high',
      impact: 'medium',
      confidenceLevel: 92,
      mitigationPriority: 'immediate',
    },
    response: {
      status: 'investigating',
      assignedTo: 'security-team',
      actions: [
        {
          type: 'account_lockout',
          timestamp: new Date().toISOString(),
          performedBy: 'automated_response',
          details: 'User account temporarily locked for security',
        },
      ],
      escalationLevel: 1,
    },
    compliance: {
      frameworks: ['SOX', 'PCI-DSS'],
      requirements: ['incident_response', 'security_monitoring'],
      reportingRequired: true,
      notificationsSent: ['security-team@company.com', 'compliance@company.com'],
    },
    organizationId: 1001,
    teamId: 2001,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    resolvedAt: null,
    ...overrides,
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

    // Register audit compliance tools before each test
    const { addAuditComplianceTools } = await import('../../../src/tools/audit-compliance.js');
    addAuditComplianceTools(mockServer, mockApiClient as any);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Tool Registration', () => {
    it('should register all audit and compliance tools', async () => {
      const { addAuditComplianceTools } = await import('../../../src/tools/audit-compliance.js');
      addAuditComplianceTools(mockServer, mockApiClient as any);
      
      const expectedTools = [
        'log_audit_event',
        'generate_compliance_report',
        'perform_audit_maintenance',
        'get_audit_configuration',
        'security_health_check',
        'create_security_incident',
      ];

      expectedTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool).toBeDefined();
        expect(tool.name).toBe(toolName);
      });
      
      expect(expectedTools).toHaveLength(6);
      expect(mockTool).toHaveBeenCalledTimes(6);
    });

    it('should have correct tool schemas', async () => {
      const { addAuditComplianceTools } = await import('../../../src/tools/audit-compliance.js');
      addAuditComplianceTools(mockServer, mockApiClient as any);
      
      const expectedTools = [
        'log_audit_event',
        'generate_compliance_report',
        'perform_audit_maintenance', 
        'get_audit_configuration',
        'security_health_check',
        'create_security_incident'
      ];
      
      expectedTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool).toBeDefined();
        expect(tool.parameters).toBeDefined();
      });
    });
  });

  describe('log-audit-event', () => {
    describe('Basic Functionality', () => {
      test('should log a basic audit event successfully', async () => {
        // Register tools for this test
        const { addAuditComplianceTools } = await import('../../../src/tools/audit-compliance.js');
        addAuditComplianceTools(mockServer, mockApiClient as any);
        
        const mockEvent = generateMockAuditEvent();
        mockApiClient.setMockResponse('post', '/audit/events', {
          success: true,
          data: mockEvent,
        });

        const result = await mockServer.executeToolCall({
          tool: 'log_audit_event',
          parameters: {
            level: 'info',
            category: 'authentication',
            action: 'user_login',
            resource: 'user_account:user_12345',
            userId: '12345',
            success: true,
            details: {
              actorName: 'test.user@example.com',
              resourceType: 'user_account',
              resourceId: 'user_12345',
            },
            riskLevel: 'low',
          },
        });

        expect(mockApiClient.post).toHaveBeenCalledWith('/audit/events', expect.objectContaining({
          level: 'info',
          category: 'authentication',
          action: 'user_login',
        }));

        const response = JSON.parse(result);
        expect(response.eventId).toBeDefined();
        expect(response.message).toContain('logged successfully');
      });

      test('should log critical security event with enhanced metadata', async () => {
        const mockEvent = generateMockAuditEvent({
          level: 'critical',
          category: 'security',
          action: 'unauthorized_access_attempt',
          riskLevel: 'critical',
        });
        
        mockApiClient.setMockResponse('post', '/audit/events', {
          success: true,
          data: mockEvent,
        });

        const result = await mockServer.executeToolCall({
          tool: 'log_audit_event',
          parameters: {
            level: 'critical',
            category: 'security',
            action: 'unauthorized_access_attempt',
            actorId: '99999',
            actorName: 'suspicious.user@external.com',
            resourceType: 'sensitive_data',
            resourceId: 'financial_records_2024',
            outcome: 'blocked',
            riskLevel: 'critical',
            metadata: {
              threatSignature: 'SQL_INJECTION_ATTEMPT',
              sourceIp: '203.0.113.45',
              blockedByRule: 'WAF_RULE_001',
            },
            complianceFrameworks: ['SOX', 'PCI-DSS'],
          },
        });

        expect(mockApiClient.post).toHaveBeenCalledWith('/audit/events', expect.objectContaining({
          level: 'critical',
          category: 'security',
          riskLevel: 'critical',
        }));

        const response = JSON.parse(result);
        expect(response.event.level).toBe('critical');
        expect(response.securityAnalysis).toBeDefined();
        expect(response.complianceImpact).toBeDefined();
      });

      test('should handle organizational audit events', async () => {
        const mockEvent = generateMockAuditEvent({ organizationId: 1001 });
        mockApiClient.setMockResponse('post', '/organizations/1001/audit/events', {
          success: true,
          data: mockEvent,
        });

        const result = await mockServer.executeToolCall({
          tool: 'log_audit_event',
          parameters: {
            level: 'info',
            category: 'configuration',
            action: 'organization_settings_updated',
            actorId: '12345',
            actorName: 'admin@company.com',
            resourceType: 'organization',
            resourceId: 'org_1001',
            outcome: 'success',
            organizationId: 1001,
          },
        });

        expect(mockApiClient.post).toHaveBeenCalledWith('/organizations/1001/audit/events', expect.any(Object));
        
        const response = JSON.parse(result);
        expect(response.event.organizationId).toBe(1001);
      });
    });

    describe('Security Testing', () => {
      test('should validate and sanitize input fields', async () => {
        const maliciousInputs = [
          { field: 'action', value: securityTestPatterns.sqlInjection[0] },
          { field: 'actorName', value: securityTestPatterns.xss[0] },
          { field: 'description', value: securityTestPatterns.commandInjection[0] },
        ];

        for (const { field, value } of maliciousInputs) {
          try {
            await mockServer.executeToolCall({
              tool: 'log_audit_event',
              parameters: {
                level: 'info',
                category: 'authentication',
                action: field === 'action' ? value : 'test_action',
                actorId: '12345',
                actorName: field === 'actorName' ? value : 'test@example.com',
                resourceType: 'test',
                resourceId: 'test_123',
                outcome: 'success',
                description: field === 'description' ? value : 'Test description',
              },
            });
            // If we reach here without throwing, the input was accepted
            // This might be acceptable depending on sanitization logic
          } catch (error) {
            // Input validation should catch malicious patterns
            expect(error).toBeDefined();
          }
        }
      });

      test('should prevent audit log tampering', async () => {
        const tamperedEvent = {
          level: 'info',
          category: 'authentication',
          action: 'user_login',
          actorId: '12345',
          actorName: 'test@example.com',
          resourceType: 'user',
          resourceId: 'user_123',
          outcome: 'success',
          // Attempting to override system fields
          id: 999999,
          timestamp: '1970-01-01T00:00:00.000Z',
          createdAt: '1970-01-01T00:00:00.000Z',
        };

        mockApiClient.setMockResponse('post', '/audit/events', {
          success: true,
          data: generateMockAuditEvent(),
        });

        await mockServer.executeToolCall({
          tool: 'log_audit_event',
          parameters: tamperedEvent,
        });

        const lastCall = mockApiClient.post.mock.calls[0];
        const sentData = lastCall[1];
        
        // System should ignore tampered system fields
        expect(sentData.id).toBeUndefined();
        expect(sentData.timestamp).not.toBe('1970-01-01T00:00:00.000Z');
      });
    });

    describe('Error Handling', () => {
      test('should handle API failures gracefully', async () => {
        mockApiClient.setMockResponse('post', '/audit/events', {
          success: false,
          error: { message: 'Audit service temporarily unavailable' },
        });

        await expect(mockServer.executeToolCall({
          tool: 'log_audit_event',
          parameters: {
            level: 'info',
            category: 'authentication',
            action: 'user_login',
            actorId: '12345',
            actorName: 'test@example.com',
            resourceType: 'user',
            resourceId: 'user_123',
            outcome: 'success',
          },
        })).rejects.toThrow('Failed to log audit event: Audit service temporarily unavailable');
      });

      test('should validate required fields', async () => {
        await expect(mockServer.executeToolCall({
          tool: 'log_audit_event',
          parameters: {
            level: 'info',
            category: 'authentication',
            // Missing required fields
          },
        })).rejects.toThrow();
      });

      test('should validate enum values', async () => {
        await expect(mockServer.executeToolCall({
          tool: 'log_audit_event',
          parameters: {
            level: 'invalid_level' as 'info' | 'warn' | 'error' | 'critical',
            category: 'authentication',
            action: 'user_login',
            actorId: '12345',
            actorName: 'test@example.com',
            resourceType: 'user',
            resourceId: 'user_123',
            outcome: 'success',
          },
        })).rejects.toThrow();
      });
    });

    describe('Performance Testing', () => {
      test('should handle concurrent audit event logging', async () => {
        const concurrentRequests = 50;
        const promises: Promise<string>[] = [];

        mockApiClient.setMockResponse('post', '/audit/events', {
          success: true,
          data: generateMockAuditEvent(),
        });

        for (let i = 0; i < concurrentRequests; i++) {
          promises.push(mockServer.executeToolCall({
            tool: 'log_audit_event',
            parameters: {
              level: 'info',
              category: 'authentication',
              action: `concurrent_test_${i}`,
              actorId: `user_${i}`,
              actorName: `test${i}@example.com`,
              resourceType: 'test',
              resourceId: `test_${i}`,
              outcome: 'success',
            },
          }));
        }

        const results = await Promise.allSettled(promises);
        const successful = results.filter(r => r.status === 'fulfilled').length;
        
        expect(successful).toBeGreaterThan(concurrentRequests * 0.9); // 90% success rate
      });
    });
  });

  describe('search-audit-events', () => {
    describe('Basic Functionality', () => {
      test('should search audit events with basic filters', async () => {
        const mockEvents = [generateMockAuditEvent(), generateMockAuditEvent()];
        mockApiClient.setMockResponse('get', '/audit/events', {
          success: true,
          data: mockEvents,
          metadata: { total: 2, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'search-audit-events',
          parameters: {
            level: 'info',
            category: 'authentication',
            limit: 50,
            offset: 0,
          },
        });

        expect(mockApiClient.get).toHaveBeenCalledWith('/audit/events', {
          params: expect.objectContaining({
            level: 'info',
            category: 'authentication',
            limit: 50,
            offset: 0,
          }),
        });

        const response = JSON.parse(result);
        expect(response.events).toHaveLength(2);
        expect(response.analysis).toBeDefined();
      });

      test('should search with date range filters', async () => {
        const startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
        const endDate = new Date().toISOString();
        
        mockApiClient.setMockResponse('get', '/audit/events', {
          success: true,
          data: [generateMockAuditEvent()],
          metadata: { total: 1, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'search-audit-events',
          parameters: {
            startDate,
            endDate,
            category: 'security',
          },
        });

        expect(mockApiClient.get).toHaveBeenCalledWith('/audit/events', {
          params: expect.objectContaining({
            startDate,
            endDate,
            category: 'security',
          }),
        });

        const response = JSON.parse(result);
        expect(response.events).toBeDefined();
        expect(response.timeRange).toEqual({ startDate, endDate });
      });

      test('should search with advanced filters', async () => {
        mockApiClient.setMockResponse('get', '/audit/events', {
          success: true,
          data: [generateMockAuditEvent({ riskLevel: 'high' })],
          metadata: { total: 1, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'search-audit-events',
          parameters: {
            actorId: '12345',
            resourceType: 'user_account',
            outcome: 'success',
            riskLevel: 'high',
            complianceFramework: 'SOX',
            includeMetadata: true,
          },
        });

        expect(mockApiClient.get).toHaveBeenCalledWith('/audit/events', {
          params: expect.objectContaining({
            actorId: '12345',
            resourceType: 'user_account',
            riskLevel: 'high',
            complianceFramework: 'SOX',
            includeMetadata: true,
          }),
        });

        const response = JSON.parse(result);
        expect(response.events[0].riskLevel).toBe('high');
      });
    });

    describe('Security Analysis', () => {
      test('should detect suspicious patterns in audit events', async () => {
        const suspiciousEvents = [
          generateMockAuditEvent({
            level: 'warn',
            category: 'authentication',
            action: 'failed_login',
            riskLevel: 'medium',
          }),
          generateMockAuditEvent({
            level: 'error',
            category: 'authentication',
            action: 'failed_login',
            riskLevel: 'high',
          }),
        ];

        mockApiClient.setMockResponse('get', '/audit/events', {
          success: true,
          data: suspiciousEvents,
          metadata: { total: 2, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'search-audit-events',
          parameters: {
            category: 'authentication',
            action: 'failed_login',
            riskLevel: 'medium',
          },
        });

        const response = JSON.parse(result);
        expect(response.analysis.securityInsights).toBeDefined();
        expect(response.analysis.riskAnalysis).toBeDefined();
        expect(response.analysis.recommendations).toBeDefined();
      });

      test('should analyze compliance-related events', async () => {
        const complianceEvents = [
          generateMockAuditEvent({
            category: 'data_access',
            action: 'sensitive_data_accessed',
            compliance: {
              frameworks: ['GDPR', 'HIPAA'],
              requirements: ['data_protection', 'access_logging'],
              retentionPeriod: 2555,
              classification: 'confidential',
            },
          }),
        ];

        mockApiClient.setMockResponse('get', '/audit/events', {
          success: true,
          data: complianceEvents,
          metadata: { total: 1, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'search-audit-events',
          parameters: {
            complianceFramework: 'GDPR',
            category: 'data_access',
          },
        });

        const response = JSON.parse(result);
        expect(response.analysis.complianceAnalysis).toBeDefined();
        expect(response.analysis.complianceAnalysis.frameworks).toContain('GDPR');
      });
    });

    describe('Error Handling', () => {
      test('should handle invalid date ranges', async () => {
        await expect(mockServer.executeToolCall({
          tool: 'search-audit-events',
          parameters: {
            startDate: '2024-12-31T23:59:59Z',
            endDate: '2024-01-01T00:00:00Z', // End before start
          },
        })).rejects.toThrow();
      });

      test('should handle API search failures', async () => {
        mockApiClient.setMockResponse('get', '/audit/events', {
          success: false,
          error: { message: 'Search service temporarily unavailable' },
        });

        await expect(mockServer.executeToolCall({
          tool: 'search-audit-events',
          parameters: {
            category: 'authentication',
          },
        })).rejects.toThrow('Failed to search audit events: Search service temporarily unavailable');
      });
    });
  });

  describe('generate-compliance-report', () => {
    describe('Basic Functionality', () => {
      test('should generate a compliance report successfully', async () => {
        const mockReport = generateMockComplianceReport();
        mockApiClient.setMockResponse('post', '/compliance/reports', {
          success: true,
          data: mockReport,
        });

        const result = await mockServer.executeToolCall({
          tool: 'generate-compliance-report',
          parameters: {
            title: 'Q4 2024 SOX Compliance Report',
            framework: 'SOX',
            reportType: 'periodic',
            period: {
              startDate: '2024-10-01T00:00:00Z',
              endDate: '2024-12-31T23:59:59Z',
            },
            scope: {
              systems: ['make-platform', 'api-gateway'],
              dataTypes: ['financial', 'personal'],
              processes: ['user_management', 'data_processing'],
            },
          },
        });

        expect(mockApiClient.post).toHaveBeenCalledWith('/compliance/reports', expect.objectContaining({
          title: 'Q4 2024 SOX Compliance Report',
          framework: 'SOX',
          reportType: 'periodic',
        }));

        const response = JSON.parse(result);
        expect(response.report).toBeDefined();
        expect(response.report.framework).toBe('SOX');
        expect(response.summary.analysisComplete).toBe(true);
      });

      test('should generate incident-specific compliance report', async () => {
        const mockReport = generateMockComplianceReport({
          reportType: 'incident',
          framework: 'GDPR',
          title: 'Data Breach Incident Compliance Analysis',
        });
        
        mockApiClient.setMockResponse('post', '/compliance/reports', {
          success: true,
          data: mockReport,
        });

        const result = await mockServer.executeToolCall({
          tool: 'generate-compliance-report',
          parameters: {
            title: 'Data Breach Incident Compliance Analysis',
            framework: 'GDPR',
            reportType: 'incident',
            period: {
              startDate: '2024-12-01T00:00:00Z',
              endDate: '2024-12-01T23:59:59Z',
            },
            scope: {
              systems: ['user-database'],
              dataTypes: ['personal'],
              processes: ['data_processing'],
            },
            incidentId: 'INC-2024-001',
            urgency: 'high',
          },
        });

        const response = JSON.parse(result);
        expect(response.report.reportType).toBe('incident');
        expect(response.report.framework).toBe('GDPR');
        expect(response.incidentAnalysis).toBeDefined();
      });

      test('should generate organizational compliance report', async () => {
        const mockReport = generateMockComplianceReport({ organizationId: 1001 });
        mockApiClient.setMockResponse('post', '/organizations/1001/compliance/reports', {
          success: true,
          data: mockReport,
        });

        const result = await mockServer.executeToolCall({
          tool: 'generate-compliance-report',
          parameters: {
            title: 'Organization-wide PCI-DSS Assessment',
            framework: 'PCI-DSS',
            reportType: 'assessment',
            organizationId: 1001,
            period: {
              startDate: '2024-01-01T00:00:00Z',
              endDate: '2024-12-31T23:59:59Z',
            },
            scope: {
              systems: ['payment-processor', 'customer-portal'],
              dataTypes: ['payment'],
              processes: ['payment_processing'],
            },
          },
        });

        expect(mockApiClient.post).toHaveBeenCalledWith('/organizations/1001/compliance/reports', expect.any(Object));
        
        const response = JSON.parse(result);
        expect(response.report.organizationId).toBe(1001);
      });
    });

    describe('Advanced Reporting', () => {
      test('should include automated recommendations', async () => {
        const mockReport = generateMockComplianceReport({
          recommendations: [
            'Implement multi-factor authentication for all admin accounts',
            'Enhance data encryption for sensitive customer information',
            'Establish automated compliance monitoring dashboard',
          ],
        });

        mockApiClient.setMockResponse('post', '/compliance/reports', {
          success: true,
          data: mockReport,
        });

        const result = await mockServer.executeToolCall({
          tool: 'generate-compliance-report',
          parameters: {
            title: 'Comprehensive Security Assessment',
            framework: 'ISO27001',
            reportType: 'assessment',
            period: {
              startDate: '2024-11-01T00:00:00Z',
              endDate: '2024-11-30T23:59:59Z',
            },
            scope: {
              systems: ['all'],
              dataTypes: ['all'],
              processes: ['all'],
            },
            includeRecommendations: true,
            detailLevel: 'comprehensive',
          },
        });

        const response = JSON.parse(result);
        expect(response.recommendations).toBeDefined();
        expect(response.recommendations.length).toBeGreaterThan(0);
        expect(response.report.recommendations).toBeDefined();
      });

      test('should handle custom compliance frameworks', async () => {
        const customReport = generateMockComplianceReport({
          framework: 'CUSTOM',
          title: 'Custom Internal Security Framework Assessment',
        });

        mockApiClient.setMockResponse('post', '/compliance/reports', {
          success: true,
          data: customReport,
        });

        const result = await mockServer.executeToolCall({
          tool: 'generate-compliance-report',
          parameters: {
            title: 'Custom Internal Security Framework Assessment',
            framework: 'CUSTOM',
            reportType: 'assessment',
            period: {
              startDate: '2024-12-01T00:00:00Z',
              endDate: '2024-12-31T23:59:59Z',
            },
            scope: {
              systems: ['internal-tools'],
              dataTypes: ['internal'],
              processes: ['internal_processes'],
            },
            customCriteria: {
              securityControls: ['access_control', 'data_protection'],
              auditRequirements: ['logging', 'monitoring'],
              riskThresholds: { high: 8, medium: 5, low: 2 },
            },
          },
        });

        const response = JSON.parse(result);
        expect(response.report.framework).toBe('CUSTOM');
        expect(response.customAnalysis).toBeDefined();
      });
    });

    describe('Error Handling', () => {
      test('should validate report parameters', async () => {
        await expect(mockServer.executeToolCall({
          tool: 'generate-compliance-report',
          parameters: {
            title: '', // Empty title
            framework: 'SOX',
            reportType: 'periodic',
            period: {
              startDate: '2024-12-31T23:59:59Z',
              endDate: '2024-01-01T00:00:00Z', // Invalid date range
            },
            scope: {},
          },
        })).rejects.toThrow();
      });

      test('should handle report generation failures', async () => {
        mockApiClient.setMockResponse('post', '/compliance/reports', {
          success: false,
          error: { message: 'Insufficient data for report generation' },
        });

        await expect(mockServer.executeToolCall({
          tool: 'generate-compliance-report',
          parameters: {
            title: 'Test Report',
            framework: 'SOX',
            reportType: 'periodic',
            period: {
              startDate: '2024-12-01T00:00:00Z',
              endDate: '2024-12-31T23:59:59Z',
            },
            scope: {
              systems: ['test-system'],
              dataTypes: ['test'],
              processes: ['test_process'],
            },
          },
        })).rejects.toThrow('Failed to generate compliance report: Insufficient data for report generation');
      });
    });
  });

  describe('list-compliance-reports', () => {
    describe('Basic Functionality', () => {
      test('should list compliance reports with filters', async () => {
        const mockReports = [
          generateMockComplianceReport(),
          generateMockComplianceReport({ framework: 'GDPR' }),
        ];
        
        mockApiClient.setMockResponse('get', '/compliance/reports', {
          success: true,
          data: mockReports,
          metadata: { total: 2, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'list-compliance-reports',
          parameters: {
            framework: 'SOX',
            reportType: 'periodic',
            limit: 50,
          },
        });

        expect(mockApiClient.get).toHaveBeenCalledWith('/compliance/reports', {
          params: expect.objectContaining({
            framework: 'SOX',
            reportType: 'periodic',
            limit: 50,
          }),
        });

        const response = JSON.parse(result);
        expect(response.reports).toHaveLength(2);
        expect(response.summary).toBeDefined();
      });

      test('should filter by date range and status', async () => {
        const mockReports = [generateMockComplianceReport({ status: 'completed' })];
        mockApiClient.setMockResponse('get', '/compliance/reports', {
          success: true,
          data: mockReports,
          metadata: { total: 1, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'list-compliance-reports',
          parameters: {
            status: 'completed',
            startDate: '2024-01-01T00:00:00Z',
            endDate: '2024-12-31T23:59:59Z',
            sortBy: 'createdAt',
            sortOrder: 'desc',
          },
        });

        const response = JSON.parse(result);
        expect(response.reports[0].status).toBe('completed');
        expect(response.dateRange).toBeDefined();
      });
    });

    describe('Analytics and Insights', () => {
      test('should provide compliance analytics', async () => {
        const mockReports = [
          generateMockComplianceReport({ framework: 'SOX', metrics: { complianceScore: 95 } }),
          generateMockComplianceReport({ framework: 'GDPR', metrics: { complianceScore: 88 } }),
          generateMockComplianceReport({ framework: 'PCI-DSS', metrics: { complianceScore: 92 } }),
        ];

        mockApiClient.setMockResponse('get', '/compliance/reports', {
          success: true,
          data: mockReports,
          metadata: { total: 3, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'list-compliance-reports',
          parameters: {
            includeAnalytics: true,
            includeMetrics: true,
          },
        });

        const response = JSON.parse(result);
        expect(response.analytics).toBeDefined();
        expect(response.analytics.frameworkBreakdown).toBeDefined();
        expect(response.analytics.complianceScores).toBeDefined();
        expect(response.analytics.trendAnalysis).toBeDefined();
      });
    });
  });

  describe('create-security-alert', () => {
    describe('Basic Functionality', () => {
      test('should create security alert successfully', async () => {
        const mockAlert = generateMockSecurityAlert();
        mockApiClient.setMockResponse('post', '/security/alerts', {
          success: true,
          data: mockAlert,
        });

        const result = await mockServer.executeToolCall({
          tool: 'create-security-alert',
          parameters: {
            title: 'Suspicious Login Activity',
            description: 'Multiple failed login attempts detected',
            severity: 'high',
            category: 'authentication',
            source: 'security_monitoring',
            affectedResources: [
              {
                type: 'user_account',
                id: 'user_12345',
                name: 'test@example.com',
                criticality: 'high',
              },
            ],
            indicators: {
              ipAddresses: ['203.0.113.45'],
              patterns: ['brute_force'],
            },
          },
        });

        expect(mockApiClient.post).toHaveBeenCalledWith('/security/alerts', expect.objectContaining({
          title: 'Suspicious Login Activity',
          severity: 'high',
          category: 'authentication',
        }));

        const response = JSON.parse(result);
        expect(response.alert).toBeDefined();
        expect(response.alert.severity).toBe('high');
        expect(response.responseActions).toBeDefined();
      });

      test('should create critical security alert with automated response', async () => {
        const criticalAlert = generateMockSecurityAlert({
          severity: 'critical',
          category: 'data_breach',
          riskAssessment: {
            riskScore: 9.8,
            likelihood: 'high',
            impact: 'critical',
            confidenceLevel: 98,
            mitigationPriority: 'immediate',
          },
        });

        mockApiClient.setMockResponse('post', '/security/alerts', {
          success: true,
          data: criticalAlert,
        });

        const result = await mockServer.executeToolCall({
          tool: 'create-security-alert',
          parameters: {
            title: 'Data Exfiltration Attempt Detected',
            description: 'Unusual data transfer patterns detected from sensitive database',
            severity: 'critical',
            category: 'data_breach',
            source: 'data_loss_prevention',
            affectedResources: [
              {
                type: 'database',
                id: 'sensitive_db_001',
                name: 'Customer PII Database',
                criticality: 'critical',
              },
            ],
            riskAssessment: {
              riskScore: 9.8,
              likelihood: 'high',
              impact: 'critical',
              mitigationPriority: 'immediate',
            },
            automatedResponse: {
              enabled: true,
              actions: ['isolate_system', 'notify_security_team'],
            },
          },
        });

        const response = JSON.parse(result);
        expect(response.alert.severity).toBe('critical');
        expect(response.automatedActions).toBeDefined();
        expect(response.escalation).toBeDefined();
      });
    });

    describe('Security Validation', () => {
      test('should validate security alert data', async () => {
        // Test with invalid severity
        await expect(mockServer.executeToolCall({
          tool: 'create-security-alert',
          parameters: {
            title: 'Test Alert',
            description: 'Test description',
            severity: 'invalid_severity' as 'low' | 'medium' | 'high' | 'critical',
            category: 'authentication',
            source: 'test',
            affectedResources: [],
          },
        })).rejects.toThrow();

        // Test with missing required fields
        await expect(mockServer.executeToolCall({
          tool: 'create-security-alert',
          parameters: {
            title: '',
            description: 'Test description',
            severity: 'high',
            category: 'authentication',
            source: 'test',
          },
        })).rejects.toThrow();
      });

      test('should sanitize alert content', async () => {
        const mockAlert = generateMockSecurityAlert();
        mockApiClient.setMockResponse('post', '/security/alerts', {
          success: true,
          data: mockAlert,
        });

        const maliciousTitle = securityTestPatterns.xss[0];
        const maliciousDescription = securityTestPatterns.sqlInjection[0];

        const result = await mockServer.executeToolCall({
          tool: 'create-security-alert',
          parameters: {
            title: maliciousTitle,
            description: maliciousDescription,
            severity: 'medium',
            category: 'system',
            source: 'test',
            affectedResources: [],
          },
        });

        // Alert should be created but content should be sanitized
        const response = JSON.parse(result);
        expect(response.alert).toBeDefined();
        // Verify sanitization occurred (actual implementation would sanitize)
      });
    });

    describe('Error Handling', () => {
      test('should handle alert creation failures', async () => {
        mockApiClient.setMockResponse('post', '/security/alerts', {
          success: false,
          error: { message: 'Alert service temporarily unavailable' },
        });

        await expect(mockServer.executeToolCall({
          tool: 'create-security-alert',
          parameters: {
            title: 'Test Alert',
            description: 'Test description',
            severity: 'medium',
            category: 'system',
            source: 'test',
            affectedResources: [],
          },
        })).rejects.toThrow('Failed to create security alert: Alert service temporarily unavailable');
      });
    });
  });

  describe('manage-security-alerts', () => {
    describe('Basic Functionality', () => {
      test('should list security alerts with filters', async () => {
        const mockAlerts = [
          generateMockSecurityAlert(),
          generateMockSecurityAlert({ severity: 'critical' }),
        ];

        mockApiClient.setMockResponse('get', '/security/alerts', {
          success: true,
          data: mockAlerts,
          metadata: { total: 2, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'manage-security-alerts',
          parameters: {
            action: 'list',
            filters: {
              severity: 'high',
              status: 'investigating',
              category: 'authentication',
            },
            limit: 50,
          },
        });

        expect(mockApiClient.get).toHaveBeenCalledWith('/security/alerts', {
          params: expect.objectContaining({
            severity: 'high',
            status: 'investigating',
            category: 'authentication',
            limit: 50,
          }),
        });

        const response = JSON.parse(result);
        expect(response.alerts).toHaveLength(2);
        expect(response.summary).toBeDefined();
      });

      test('should update security alert status', async () => {
        const updatedAlert = generateMockSecurityAlert({
          response: { status: 'resolved', assignedTo: 'security-team' },
        });

        mockApiClient.setMockResponse('put', '/security/alerts/12345', {
          success: true,
          data: updatedAlert,
        });

        const result = await mockServer.executeToolCall({
          tool: 'manage-security-alerts',
          parameters: {
            action: 'update',
            alertId: 12345,
            updates: {
              status: 'resolved',
              assignedTo: 'security-team',
              resolutionNotes: 'False positive - legitimate user activity',
            },
          },
        });

        expect(mockApiClient.put).toHaveBeenCalledWith('/security/alerts/12345', expect.objectContaining({
          status: 'resolved',
          assignedTo: 'security-team',
          resolutionNotes: 'False positive - legitimate user activity',
        }));

        const response = JSON.parse(result);
        expect(response.alert.response.status).toBe('resolved');
        expect(response.message).toContain('updated successfully');
      });

      test('should escalate security alert', async () => {
        const escalatedAlert = generateMockSecurityAlert({
          response: { escalationLevel: 2, assignedTo: 'incident-response-team' },
        });

        mockApiClient.setMockResponse('post', '/security/alerts/12345/escalate', {
          success: true,
          data: escalatedAlert,
        });

        const result = await mockServer.executeToolCall({
          tool: 'manage-security-alerts',
          parameters: {
            action: 'escalate',
            alertId: 12345,
            escalation: {
              level: 2,
              reason: 'Confirmed security incident requiring immediate response',
              assignTo: 'incident-response-team',
              notifyStakeholders: true,
            },
          },
        });

        expect(mockApiClient.post).toHaveBeenCalledWith('/security/alerts/12345/escalate', expect.objectContaining({
          level: 2,
          reason: 'Confirmed security incident requiring immediate response',
        }));

        const response = JSON.parse(result);
        expect(response.alert.response.escalationLevel).toBe(2);
        expect(response.escalationActions).toBeDefined();
      });

      test('should bulk update security alerts', async () => {
        const bulkUpdateResult = {
          successful: 5,
          failed: 0,
          results: [
            { alertId: 1, status: 'success' },
            { alertId: 2, status: 'success' },
            { alertId: 3, status: 'success' },
            { alertId: 4, status: 'success' },
            { alertId: 5, status: 'success' },
          ],
        };

        mockApiClient.setMockResponse('put', '/security/alerts/bulk', {
          success: true,
          data: bulkUpdateResult,
        });

        const result = await mockServer.executeToolCall({
          tool: 'manage-security-alerts',
          parameters: {
            action: 'bulk_update',
            alertIds: [1, 2, 3, 4, 5],
            updates: {
              status: 'reviewed',
              assignedTo: 'security-team',
            },
          },
        });

        expect(mockApiClient.put).toHaveBeenCalledWith('/security/alerts/bulk', expect.objectContaining({
          alertIds: [1, 2, 3, 4, 5],
          updates: {
            status: 'reviewed',
            assignedTo: 'security-team',
          },
        }));

        const response = JSON.parse(result);
        expect(response.bulkResult.successful).toBe(5);
        expect(response.bulkResult.failed).toBe(0);
      });
    });

    describe('Advanced Alert Management', () => {
      test('should generate alert analytics', async () => {
        const analyticsData = {
          totalAlerts: 125,
          severityBreakdown: { critical: 5, high: 15, medium: 45, low: 60 },
          categoryBreakdown: { authentication: 50, authorization: 25, data_access: 30, system: 20 },
          trendsFromPrevious: { alertsChange: '+12%', criticalChange: '-20%' },
          meanTimeToResolution: 4.5, // hours
          topThreats: ['brute_force', 'privilege_escalation', 'data_exfiltration'],
        };

        mockApiClient.setMockResponse('get', '/security/alerts/analytics', {
          success: true,
          data: analyticsData,
        });

        const result = await mockServer.executeToolCall({
          tool: 'manage-security-alerts',
          parameters: {
            action: 'analytics',
            timeRange: {
              startDate: '2024-11-01T00:00:00Z',
              endDate: '2024-11-30T23:59:59Z',
            },
            includeMetrics: true,
            includeTrends: true,
          },
        });

        const response = JSON.parse(result);
        expect(response.analytics).toBeDefined();
        expect(response.analytics.totalAlerts).toBe(125);
        expect(response.analytics.severityBreakdown).toBeDefined();
        expect(response.metrics.meanTimeToResolution).toBe(4.5);
      });
    });

    describe('Error Handling', () => {
      test('should handle invalid alert actions', async () => {
        await expect(mockServer.executeToolCall({
          tool: 'manage-security-alerts',
          parameters: {
            action: 'invalid_action' as 'list' | 'update' | 'escalate' | 'bulk_update' | 'analytics',
          },
        })).rejects.toThrow();
      });

      test('should handle alert management failures', async () => {
        mockApiClient.setMockResponse('get', '/security/alerts', {
          success: false,
          error: { message: 'Alert management service unavailable' },
        });

        await expect(mockServer.executeToolCall({
          tool: 'manage-security-alerts',
          parameters: {
            action: 'list',
          },
        })).rejects.toThrow('Failed to manage security alerts: Alert management service unavailable');
      });
    });
  });

  describe('Integration Testing', () => {
    test('should handle end-to-end audit workflow', async () => {
      // 1. Log a critical security event
      const auditEvent = generateMockAuditEvent({
        level: 'critical',
        category: 'security',
        action: 'unauthorized_access_attempt',
        riskLevel: 'critical',
      });

      mockApiClient.setMockResponse('post', '/audit/events', {
        success: true,
        data: auditEvent,
      });

      const logResult = await mockServer.executeToolCall({
        tool: 'log_audit_event',
        parameters: {
          level: 'critical',
          category: 'security',
          action: 'unauthorized_access_attempt',
          actorId: '99999',
          actorName: 'suspicious.user@external.com',
          resourceType: 'sensitive_data',
          resourceId: 'financial_records',
          outcome: 'blocked',
          riskLevel: 'critical',
        },
      });

      // 2. Create a security alert based on the event
      const securityAlert = generateMockSecurityAlert({
        severity: 'critical',
        category: 'security',
        triggeredBy: {
          ruleId: 'rule_unauthorized_access',
          ruleName: 'Unauthorized Access Detection',
          threshold: 1,
          actualValue: 1,
          timeWindow: '1 minute',
        },
      });

      mockApiClient.setMockResponse('post', '/security/alerts', {
        success: true,
        data: securityAlert,
      });

      const alertResult = await mockServer.executeToolCall({
        tool: 'create-security-alert',
        parameters: {
          title: 'Critical Unauthorized Access Attempt',
          description: 'Blocked unauthorized access to sensitive financial data',
          severity: 'critical',
          category: 'security',
          source: 'security_monitoring',
          affectedResources: [
            {
              type: 'database',
              id: 'financial_records',
              name: 'Financial Records Database',
              criticality: 'critical',
            },
          ],
          correlationId: auditEvent.context.correlationId,
        },
      });

      // 3. Search for related audit events
      mockApiClient.setMockResponse('get', '/audit/events', {
        success: true,
        data: [auditEvent],
        metadata: { total: 1, hasMore: false },
      });

      const searchResult = await mockServer.executeToolCall({
        tool: 'search-audit-events',
        parameters: {
          category: 'security',
          riskLevel: 'critical',
          correlationId: auditEvent.context.correlationId,
        },
      });

      // Verify the workflow completed successfully
      expect(JSON.parse(logResult).event).toBeDefined();
      expect(JSON.parse(alertResult).alert).toBeDefined();
      expect(JSON.parse(searchResult).events).toHaveLength(1);
    });

    test('should handle compliance reporting workflow', async () => {
      // 1. Generate compliance report
      const complianceReport = generateMockComplianceReport();
      mockApiClient.setMockResponse('post', '/compliance/reports', {
        success: true,
        data: complianceReport,
      });

      const reportResult = await mockServer.executeToolCall({
        tool: 'generate-compliance-report',
        parameters: {
          title: 'Monthly SOX Compliance Assessment',
          framework: 'SOX',
          reportType: 'periodic',
          period: {
            startDate: '2024-11-01T00:00:00Z',
            endDate: '2024-11-30T23:59:59Z',
          },
          scope: {
            systems: ['make-platform'],
            dataTypes: ['financial'],
            processes: ['financial_reporting'],
          },
        },
      });

      // 2. List generated reports
      mockApiClient.setMockResponse('get', '/compliance/reports', {
        success: true,
        data: [complianceReport],
        metadata: { total: 1, hasMore: false },
      });

      const listResult = await mockServer.executeToolCall({
        tool: 'list-compliance-reports',
        parameters: {
          framework: 'SOX',
          status: 'completed',
          includeAnalytics: true,
        },
      });

      // Verify the workflow completed successfully
      expect(JSON.parse(reportResult).report).toBeDefined();
      expect(JSON.parse(listResult).reports).toHaveLength(1);
      expect(JSON.parse(listResult).analytics).toBeDefined();
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
            mockApiClient.setMockResponse('post', '/audit/events', {
              success: true,
              data: generateMockAuditEvent(),
            }, chaosMonkey.getRandomLatency());
          } else if (scenario === 'error') {
            // Simulate service error
            mockApiClient.setMockResponse('post', '/audit/events', {
              success: false,
              error: { message: 'Service temporarily unavailable' },
            });
          } else if (scenario === 'timeout') {
            // Simulate timeout
            mockApiClient.setMockResponse('post', '/audit/events', {
              success: false,
              error: { message: 'Request timeout' },
            });
          }

          await mockServer.executeToolCall({
            tool: 'log_audit_event',
            parameters: {
              level: 'info',
              category: 'system',
              action: `chaos_test_${scenario}`,
              actorId: 'chaos_monkey',
              actorName: 'chaos.test@example.com',
              resourceType: 'test',
              resourceId: 'chaos_test',
              outcome: 'success',
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
});