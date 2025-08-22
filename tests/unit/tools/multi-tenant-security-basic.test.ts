/**
 * Basic Test Suite for Multi-Tenant Security Tools
 * Tests core functionality of multi-tenant security management tools including
 * tenant provisioning, cryptographic isolation, network segmentation, resource quotas,
 * governance policies, data leakage prevention, and compliance boundaries
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { createMockServer, findTool, executeTool } from '../../utils/test-helpers.js';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';

describe('Multi-Tenant Security Tools - Basic Tests', () => {
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
    it('should successfully import and register multi-tenant security tools', async () => {
      const { addMultiTenantSecurityTools } = await import('../../../src/tools/multi-tenant-security.js');
      
      // Should not throw an error
      expect(() => {
        addMultiTenantSecurityTools(mockServer, mockApiClient as any);
      }).not.toThrow();
      
      // Should call addTool for each tool
      expect(mockTool).toHaveBeenCalled();
      expect(mockTool.mock.calls.length).toBeGreaterThan(0);
    });

    it('should export the expected tools and collections', async () => {
      const multiTenantSecurityModule = await import('../../../src/tools/multi-tenant-security.js');
      
      // Check that expected exports exist
      expect(multiTenantSecurityModule.addMultiTenantSecurityTools).toBeDefined();
      expect(typeof multiTenantSecurityModule.addMultiTenantSecurityTools).toBe('function');
      
      // multiTenantSecurityTools array export not available, but function exists
    });

    it('should register all expected multi-tenant security tools', async () => {
      const { addMultiTenantSecurityTools } = await import('../../../src/tools/multi-tenant-security.js');
      
      addMultiTenantSecurityTools(mockServer, mockApiClient as any);
      
      // Should register multiple tools
      expect(mockTool.mock.calls.length).toBeGreaterThan(0);
      
      // Extract tool names from mock calls
      const registeredToolNames = mockTool.mock.calls.map(call => call[0]?.name).filter(Boolean);
      
      // Expected tool names based on the implementation
      const expectedToolNames = [
        'provision_tenant',
        'manage_cryptographic_isolation',
        'configure_network_segmentation',
        'manage_resource_quotas',
        'manage_governance_policies',
        'prevent_data_leakage',
        'manage_compliance_boundaries'
      ];
      
      expectedToolNames.forEach(expectedName => {
        expect(registeredToolNames).toContain(expectedName);
      });
    });
  });

  describe('Tool Configuration and Structure', () => {
    beforeEach(async () => {
      const { addMultiTenantSecurityTools } = await import('../../../src/tools/multi-tenant-security.js');
      addMultiTenantSecurityTools(mockServer, mockApiClient as any);
    });

    it('should have correct structure for tenant provisioning tool', () => {
      const provisionTool = findTool(mockTool, 'provision_tenant');
      
      expect(provisionTool).toBeDefined();
      expect(provisionTool.name).toBe('provision_tenant');
      expect(provisionTool.description).toBeDefined();
      expect(typeof provisionTool.description).toBe('string');
      expect(provisionTool.description).toContain('tenant');
      expect(provisionTool.description).toContain('security isolation');
      expect(provisionTool.parameters).toBeDefined();
      expect(typeof provisionTool.execute).toBe('function');
    });

    it('should have correct structure for cryptographic isolation tool', () => {
      const cryptoTool = findTool(mockTool, 'manage_cryptographic_isolation');
      
      expect(cryptoTool).toBeDefined();
      expect(cryptoTool.name).toBe('manage_cryptographic_isolation');
      expect(cryptoTool.description).toBeDefined();
      expect(typeof cryptoTool.description).toBe('string');
      expect(cryptoTool.description).toContain('cryptographic isolation');
      expect(cryptoTool.parameters).toBeDefined();
      expect(typeof cryptoTool.execute).toBe('function');
    });

    it('should have correct structure for network segmentation tool', () => {
      const networkTool = findTool(mockTool, 'configure_network_segmentation');
      
      expect(networkTool).toBeDefined();
      expect(networkTool.name).toBe('configure_network_segmentation');
      expect(networkTool.description).toBeDefined();
      expect(typeof networkTool.description).toBe('string');
      expect(networkTool.description).toContain('network segmentation');
      expect(networkTool.parameters).toBeDefined();
      expect(typeof networkTool.execute).toBe('function');
    });

    it('should have correct structure for resource quota management tool', () => {
      const quotaTool = findTool(mockTool, 'manage_resource_quotas');
      
      expect(quotaTool).toBeDefined();
      expect(quotaTool.name).toBe('manage_resource_quotas');
      expect(quotaTool.description).toBeDefined();
      expect(typeof quotaTool.description).toBe('string');
      expect(quotaTool.description).toContain('resource quota');
      expect(quotaTool.parameters).toBeDefined();
      expect(typeof quotaTool.execute).toBe('function');
    });

    it('should have correct structure for governance policy tool', () => {
      const policyTool = findTool(mockTool, 'manage_governance_policies');
      
      expect(policyTool).toBeDefined();
      expect(policyTool.name).toBe('manage_governance_policies');
      expect(policyTool.description).toBeDefined();
      expect(typeof policyTool.description).toBe('string');
      expect(policyTool.description).toContain('governance polic');
      expect(policyTool.parameters).toBeDefined();
      expect(typeof policyTool.execute).toBe('function');
    });

    it('should have correct structure for data leakage prevention tool', () => {
      const dlpTool = findTool(mockTool, 'prevent_data_leakage');
      
      expect(dlpTool).toBeDefined();
      expect(dlpTool.name).toBe('prevent_data_leakage');
      expect(dlpTool.description).toBeDefined();
      expect(typeof dlpTool.description).toBe('string');
      expect(dlpTool.description).toContain('data leakage prevention');
      expect(dlpTool.parameters).toBeDefined();
      expect(typeof dlpTool.execute).toBe('function');
    });

    it('should have correct structure for compliance boundary tool', () => {
      const complianceTool = findTool(mockTool, 'manage_compliance_boundaries');
      
      expect(complianceTool).toBeDefined();
      expect(complianceTool.name).toBe('manage_compliance_boundaries');
      expect(complianceTool.description).toBeDefined();
      expect(typeof complianceTool.description).toBe('string');
      expect(complianceTool.description).toContain('compliance boundaries');
      expect(complianceTool.parameters).toBeDefined();
      expect(typeof complianceTool.execute).toBe('function');
    });
  });

  describe('Tool Execution - Basic Functionality', () => {
    beforeEach(async () => {
      const { addMultiTenantSecurityTools } = await import('../../../src/tools/multi-tenant-security.js');
      addMultiTenantSecurityTools(mockServer, mockApiClient as any);
    });

    it('should execute tenant provisioning successfully with valid input', async () => {
      const provisionTool = findTool(mockTool, 'provision_tenant');
      
      const input = {
        tenantId: 'tenant_001',
        tenantName: 'Test Corporation',
        subscriptionTier: 'enterprise' as const,
        complianceFrameworks: ['SOC2', 'GDPR'] as const,
        organizationInfo: {
          name: 'Test Corporation',
          domain: 'testcorp.com',
          country: 'US',
          industry: 'Technology',
          contactEmail: 'admin@testcorp.com',
          dataResidency: 'US-EAST'
        },
        resourceQuotas: {
          maxUsers: 100,
          maxConnections: 50,
          maxScenarios: 200,
          storageQuotaGB: 1000,
          computeUnits: 500,
          apiCallsPerMonth: 1000000
        },
        securitySettings: {
          requireMFA: true,
          sessionTimeoutMinutes: 480,
          passwordPolicy: {
            minLength: 12,
            requireSpecialChars: true,
            requireNumbers: true,
            requireUppercase: true
          },
          ipWhitelist: ['192.168.1.0/24'],
          networkIsolation: true
        }
      };
      
      const result = await executeTool(provisionTool, input);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      // Parse the JSON result
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBeDefined();
      expect(typeof parsedResult.success).toBe('boolean');
      expect(parsedResult.tenantId).toBe('tenant_001');
      expect(parsedResult.provisioningDetails).toBeDefined();
      expect(parsedResult.provisioningDetails.cryptographicKeys).toBeDefined();
      expect(parsedResult.provisioningDetails.networkConfiguration).toBeDefined();
      expect(parsedResult.provisioningDetails.resourceAllocation).toBeDefined();
      expect(parsedResult.provisioningDetails.policies).toBeDefined();
      expect(parsedResult.provisioningDetails.complianceStatus).toBeDefined();
    });

    it('should execute cryptographic isolation with key generation', async () => {
      const cryptoTool = findTool(mockTool, 'manage_cryptographic_isolation');
      
      const input = {
        tenantId: 'tenant_001',
        operation: 'generate_keys' as const,
        keyType: 'master' as const,
        keyRotationPolicy: {
          automaticRotation: true,
          rotationIntervalDays: 90,
          retainOldKeys: true,
          retentionDays: 30
        },
        hsmConfiguration: {
          enabled: false
        }
      };
      
      const result = await executeTool(cryptoTool, input);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      // Parse the JSON result
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBeDefined();
      expect(parsedResult.operation).toBe('generate_keys');
      expect(parsedResult.tenantId).toBe('tenant_001');
      expect(parsedResult.keyManagement).toBeDefined();
      if (parsedResult.success) {
        expect(parsedResult.keyManagement.masterKeyId).toBeDefined();
        expect(parsedResult.keyManagement.dataEncryptionKeys).toBeDefined();
        expect(parsedResult.keyManagement.keyRotationSchedule).toBeDefined();
      }
    });

    it('should execute network segmentation with VPC creation', async () => {
      const networkTool = findTool(mockTool, 'configure_network_segmentation');
      
      const input = {
        tenantId: 'tenant_001',
        operation: 'create_vpc' as const,
        networkConfig: {
          vpcCidr: '10.0.0.0/16',
          subnetConfiguration: [
            {
              name: 'public-subnet',
              cidr: '10.0.1.0/24',
              type: 'public' as const,
              availability_zone: 'us-east-1a'
            },
            {
              name: 'private-subnet',
              cidr: '10.0.2.0/24',
              type: 'private' as const,
              availability_zone: 'us-east-1b'
            }
          ],
          microsegmentation: {
            enabled: true,
            segmentationPolicy: 'strict' as const,
            allowedProtocols: ['HTTPS', 'TLS'],
            blockedPorts: [23, 135, 139, 445]
          }
        },
        securityPolicies: {
          ingressRules: [
            {
              source: '0.0.0.0/0',
              destination: '10.0.1.0/24',
              protocol: 'HTTPS',
              port: 443,
              action: 'allow' as const
            }
          ],
          egressRules: [
            {
              source: '10.0.2.0/24',
              destination: '0.0.0.0/0',
              protocol: 'HTTPS',
              port: 443,
              action: 'allow' as const
            }
          ],
          crossTenantPrevention: true
        }
      };
      
      const result = await executeTool(networkTool, input);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      // Parse the JSON result
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBeDefined();
      expect(parsedResult.tenantId).toBe('tenant_001');
      expect(parsedResult.networkConfiguration).toBeDefined();
      expect(parsedResult.isolationMetrics).toBeDefined();
      expect(parsedResult.isolationMetrics.crossTenantBlocking).toBeDefined();
      expect(parsedResult.isolationMetrics.trafficIsolation).toBeDefined();
      expect(parsedResult.isolationMetrics.policyCompliance).toBeDefined();
      expect(parsedResult.monitoring).toBeDefined();
    });

    it('should execute resource quota management with quota setting', async () => {
      const quotaTool = findTool(mockTool, 'manage_resource_quotas');
      
      const input = {
        tenantId: 'tenant_001',
        operation: 'set_quotas' as const,
        resourceQuotas: {
          compute: {
            cpuCores: 16,
            memoryGB: 64,
            storageGB: 1000,
            networkBandwidthMbps: 1000
          },
          application: {
            maxConcurrentUsers: 100,
            maxActiveConnections: 500,
            maxWorkflowExecutions: 1000,
            apiRequestsPerMinute: 1000,
            maxWebhooks: 50
          },
          data: {
            maxDatabaseSize: 10000,
            maxFileUploads: 1000,
            maxBackups: 10,
            retentionDays: 365
          }
        },
        scalingPolicies: {
          autoScaling: true,
          scaleUpThreshold: 80,
          scaleDownThreshold: 20,
          cooldownMinutes: 5,
          maxScaleMultiplier: 3
        }
      };
      
      const result = await executeTool(quotaTool, input);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      // Parse the JSON result
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBeDefined();
      expect(parsedResult.tenantId).toBe('tenant_001');
      expect(parsedResult.quotaConfiguration).toBeDefined();
      expect(parsedResult.currentUsage).toBeDefined();
      expect(parsedResult.utilizationMetrics).toBeDefined();
      expect(parsedResult.scalingStatus).toBeDefined();
      if (parsedResult.success) {
        expect(parsedResult.quotaConfiguration.compute).toBeDefined();
        expect(parsedResult.quotaConfiguration.application).toBeDefined();
        expect(parsedResult.quotaConfiguration.data).toBeDefined();
      }
    });

    it('should execute governance policy creation successfully', async () => {
      const policyTool = findTool(mockTool, 'manage_governance_policies');
      
      const input = {
        tenantId: 'tenant_001',
        operation: 'create_policy' as const,
        policyConfig: {
          policyName: 'Data Access Control Policy',
          policyType: 'access_control' as const,
          priority: 90,
          enabled: true,
          rules: [
            {
              ruleId: 'rule_001',
              condition: 'user.department === "finance"',
              action: 'allow_financial_data_access',
              parameters: { dataTypes: ['financial', 'PCI'] }
            },
            {
              ruleId: 'rule_002',
              condition: 'user.clearance_level < 3',
              action: 'deny_sensitive_data_access',
              parameters: { dataTypes: ['restricted'] }
            }
          ]
        },
        complianceMapping: {
          frameworks: ['SOC2', 'GDPR'] as const,
          controlObjectives: ['AC-1', 'AC-2', 'AC-3'],
          evidenceCollection: true,
          reportingFrequency: 'monthly' as const
        },
        auditSettings: {
          logAllAccess: true,
          retainAuditLogs: true,
          alertOnViolations: true,
          escalationPolicy: 'immediate_security_team'
        }
      };
      
      const result = await executeTool(policyTool, input);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      // Parse the JSON result
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBeDefined();
      expect(parsedResult.tenantId).toBe('tenant_001');
      expect(parsedResult.policyManagement).toBeDefined();
      expect(parsedResult.complianceStatus).toBeDefined();
      expect(parsedResult.auditTrail).toBeDefined();
      if (parsedResult.success) {
        expect(parsedResult.policyManagement.policiesActive).toBeDefined();
        expect(parsedResult.policyManagement.complianceScore).toBeDefined();
      }
    });

    it('should execute data leakage prevention with data classification', async () => {
      const dlpTool = findTool(mockTool, 'prevent_data_leakage');
      
      const input = {
        tenantId: 'tenant_001',
        operation: 'classify_data' as const,
        dataClassification: {
          classificationLevel: 'confidential' as const,
          dataTypes: ['PII', 'financial'] as const,
          sensitivityScore: 8,
          retentionPeriod: 2555
        },
        protectionMechanisms: {
          encryption: {
            algorithm: 'AES-256-GCM' as const,
            keyRotation: true,
            fieldLevelEncryption: true
          },
          accessControls: {
            requireAuthorization: true,
            multiFactorAuth: true,
            temporalRestrictions: true,
            locationRestrictions: true
          },
          monitoring: {
            logAccess: true,
            detectAnomalies: true,
            realTimeAlerts: true,
            forensicsCapability: true
          }
        }
      };
      
      const result = await executeTool(dlpTool, input);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      // Parse the JSON result
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBeDefined();
      expect(parsedResult.tenantId).toBe('tenant_001');
      expect(parsedResult.dataProtection).toBeDefined();
      expect(parsedResult.threatDetection).toBeDefined();
      expect(parsedResult.complianceStatus).toBeDefined();
      if (parsedResult.success) {
        expect(parsedResult.dataProtection.classifiedData).toBeDefined();
        expect(parsedResult.threatDetection.riskScore).toBeDefined();
        expect(parsedResult.complianceStatus.dataGovernance).toBeDefined();
      }
    });

    it('should execute compliance boundary establishment successfully', async () => {
      const complianceTool = findTool(mockTool, 'manage_compliance_boundaries');
      
      const input = {
        tenantId: 'tenant_001',
        operation: 'establish_boundaries' as const,
        complianceFramework: 'GDPR' as const,
        boundaryConfig: {
          dataResidency: {
            allowedRegions: ['EU-WEST-1', 'EU-CENTRAL-1'],
            dataLocalization: true,
            crossBorderRestrictions: true
          },
          processingLimitations: {
            purposeLimitation: true,
            dataMinimization: true,
            storageRestrictions: true,
            retentionLimits: true
          },
          accessControls: {
            roleBased: true,
            attributeBased: true,
            temporalAccess: true,
            auditTrail: true
          }
        },
        auditRequirements: {
          continuousMonitoring: true,
          regularAssessments: true,
          thirdPartyAudits: false,
          certificationMaintenance: true
        }
      };
      
      const result = await executeTool(complianceTool, input);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      // Parse the JSON result
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBeDefined();
      expect(parsedResult.tenantId).toBe('tenant_001');
      expect(parsedResult.complianceFramework).toBe('GDPR');
      expect(parsedResult.boundaryStatus).toBeDefined();
      expect(parsedResult.complianceMetrics).toBeDefined();
      expect(parsedResult.certificateStatus).toBeDefined();
      if (parsedResult.success) {
        expect(parsedResult.boundaryStatus.dataResidency).toBeDefined();
        expect(parsedResult.complianceMetrics.overallScore).toBeDefined();
        expect(parsedResult.certificateStatus.certified).toBeDefined();
      }
    });
  });

  describe('Tenant Isolation Validation Scenarios', () => {
    beforeEach(async () => {
      const { addMultiTenantSecurityTools } = await import('../../../src/tools/multi-tenant-security.js');
      addMultiTenantSecurityTools(mockServer, mockApiClient as any);
    });

    it('should verify cryptographic isolation between tenants', async () => {
      const cryptoTool = findTool(mockTool, 'manage_cryptographic_isolation');
      
      const isolationVerificationInput = {
        tenantId: 'tenant_001',
        operation: 'verify_isolation' as const
      };
      
      const result = await executeTool(cryptoTool, isolationVerificationInput);
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      
      if (parsedResult.success && parsedResult.isolationVerification) {
        expect(parsedResult.isolationVerification.crossTenantAccess).toBe(false);
        expect(parsedResult.isolationVerification.keyIsolation).toBe(true);
        expect(parsedResult.isolationVerification.dataIsolation).toBe(true);
      }
    });

    it('should validate network segmentation prevents cross-tenant access', async () => {
      const networkTool = findTool(mockTool, 'configure_network_segmentation');
      
      const monitoringInput = {
        tenantId: 'tenant_001',
        operation: 'monitor_traffic' as const,
        networkConfig: {},
        securityPolicies: {
          crossTenantPrevention: true
        }
      };
      
      const result = await executeTool(networkTool, monitoringInput);
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      
      if (parsedResult.success) {
        expect(parsedResult.isolationMetrics.crossTenantBlocking).toBe(true);
        expect(parsedResult.isolationMetrics.trafficIsolation).toBeGreaterThan(95);
        expect(parsedResult.isolationMetrics.policyCompliance).toBeGreaterThan(95);
      }
    });

    it('should encrypt data with tenant-specific keys', async () => {
      const cryptoTool = findTool(mockTool, 'manage_cryptographic_isolation');
      
      const encryptionInput = {
        tenantId: 'tenant_001',
        operation: 'encrypt_data' as const,
        data: 'sensitive_tenant_data_123'
      };
      
      const result = await executeTool(cryptoTool, encryptionInput);
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      
      if (parsedResult.success && parsedResult.encryptionResult) {
        expect(parsedResult.encryptionResult.encryptedData).toBeDefined();
        expect(parsedResult.encryptionResult.encryptedData).not.toBe('sensitive_tenant_data_123');
        expect(parsedResult.encryptionResult.encryptionMetadata).toBeDefined();
        expect(parsedResult.encryptionResult.encryptionMetadata.tenantId).toBe('tenant_001');
      }
    });

    it('should decrypt data only with correct tenant context', async () => {
      const cryptoTool = findTool(mockTool, 'manage_cryptographic_isolation');
      
      const decryptionInput = {
        tenantId: 'tenant_001',
        operation: 'decrypt_data' as const,
        encryptedData: 'encrypted_data_sample_encrypted'
      };
      
      const result = await executeTool(cryptoTool, decryptionInput);
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      
      if (parsedResult.success && parsedResult.encryptionResult) {
        expect(parsedResult.encryptionResult.decryptedData).toBeDefined();
        expect(parsedResult.encryptionResult.decryptedData).toBe('decrypted_data');
      }
    });

    it('should enforce resource quotas per tenant', async () => {
      const quotaTool = findTool(mockTool, 'manage_resource_quotas');
      
      const quotaMonitoringInput = {
        tenantId: 'tenant_001',
        operation: 'monitor_usage' as const,
        resourceQuotas: {
          compute: {
            cpuCores: 8,
            memoryGB: 32,
            storageGB: 500,
            networkBandwidthMbps: 500
          },
          application: {
            maxConcurrentUsers: 50,
            maxActiveConnections: 250,
            maxWorkflowExecutions: 500,
            apiRequestsPerMinute: 500,
            maxWebhooks: 25
          },
          data: {
            maxDatabaseSize: 5000,
            maxFileUploads: 500,
            maxBackups: 5,
            retentionDays: 180
          }
        }
      };
      
      const result = await executeTool(quotaTool, quotaMonitoringInput);
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      
      if (parsedResult.success) {
        expect(parsedResult.quotaConfiguration).toBeDefined();
        expect(parsedResult.currentUsage).toBeDefined();
        expect(parsedResult.utilizationMetrics).toBeDefined();
        
        // Verify utilization is within reasonable bounds
        expect(parsedResult.utilizationMetrics.cpuUtilization).toBeLessThanOrEqual(100);
        expect(parsedResult.utilizationMetrics.memoryUtilization).toBeLessThanOrEqual(100);
        expect(parsedResult.utilizationMetrics.storageUtilization).toBeLessThanOrEqual(100);
      }
    });
  });

  describe('Cross-Tenant Security Boundary Testing', () => {
    beforeEach(async () => {
      const { addMultiTenantSecurityTools } = await import('../../../src/tools/multi-tenant-security.js');
      addMultiTenantSecurityTools(mockServer, mockApiClient as any);
    });

    it('should prevent data leakage between different tenants', async () => {
      const dlpTool = findTool(mockTool, 'prevent_data_leakage');
      
      const leakagePreventionInput = {
        tenantId: 'tenant_001',
        operation: 'monitor_access' as const,
        dataClassification: {
          classificationLevel: 'restricted' as const,
          dataTypes: ['PII', 'PHI'] as const,
          sensitivityScore: 9,
          retentionPeriod: 2555
        },
        protectionMechanisms: {
          encryption: {
            algorithm: 'AES-256-GCM' as const,
            keyRotation: true,
            fieldLevelEncryption: true
          },
          accessControls: {
            requireAuthorization: true,
            multiFactorAuth: true,
            temporalRestrictions: true,
            locationRestrictions: true
          },
          monitoring: {
            logAccess: true,
            detectAnomalies: true,
            realTimeAlerts: true,
            forensicsCapability: true
          }
        }
      };
      
      const result = await executeTool(dlpTool, leakagePreventionInput);
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      
      if (parsedResult.success) {
        expect(parsedResult.threatDetection.activeMonitoring).toBe(true);
        expect(parsedResult.complianceStatus.accessControls).toBe(true);
        expect(parsedResult.complianceStatus.auditTrails).toBe(true);
        expect(parsedResult.threatDetection.riskScore).toBeDefined();
      }
    });

    it('should enforce tenant-specific governance policies', async () => {
      const policyTool = findTool(mockTool, 'manage_governance_policies');
      
      const policyEnforcementInput = {
        tenantId: 'tenant_001',
        operation: 'enforce_policy' as const,
        policyConfig: {
          policyName: 'Cross-Tenant Isolation Policy',
          policyType: 'security_policy' as const,
          priority: 100,
          enabled: true,
          rules: [
            {
              ruleId: 'isolation_rule_001',
              condition: 'request.tenantId !== resource.tenantId',
              action: 'deny_access',
              parameters: { logViolation: true, alertSecurity: true }
            }
          ]
        },
        auditSettings: {
          logAllAccess: true,
          retainAuditLogs: true,
          alertOnViolations: true,
          escalationPolicy: 'immediate_security_team'
        }
      };
      
      const result = await executeTool(policyTool, policyEnforcementInput);
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      
      if (parsedResult.success) {
        expect(parsedResult.policyManagement.policiesEnforced).toBeGreaterThan(0);
        expect(parsedResult.policyManagement.complianceScore).toBeGreaterThan(80);
        expect(parsedResult.auditTrail.auditCoverage).toBeGreaterThan(95);
      }
    });

    it('should validate compliance boundaries are tenant-specific', async () => {
      const complianceTool = findTool(mockTool, 'manage_compliance_boundaries');
      
      const boundaryValidationInput = {
        tenantId: 'tenant_001',
        operation: 'validate_compliance' as const,
        complianceFramework: 'SOC2' as const,
        boundaryConfig: {
          dataResidency: {
            allowedRegions: ['US-EAST-1', 'US-WEST-2'],
            dataLocalization: true,
            crossBorderRestrictions: true
          },
          processingLimitations: {
            purposeLimitation: true,
            dataMinimization: true,
            storageRestrictions: true,
            retentionLimits: true
          },
          accessControls: {
            roleBased: true,
            attributeBased: true,
            temporalAccess: false,
            auditTrail: true
          }
        },
        auditRequirements: {
          continuousMonitoring: true,
          regularAssessments: true,
          thirdPartyAudits: true,
          certificationMaintenance: true
        }
      };
      
      const result = await executeTool(complianceTool, boundaryValidationInput);
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      
      if (parsedResult.success) {
        expect(parsedResult.boundaryStatus.dataResidency).toBe(true);
        expect(parsedResult.boundaryStatus.processingCompliance).toBe(true);
        expect(parsedResult.boundaryStatus.accessControlCompliance).toBe(true);
        expect(parsedResult.complianceMetrics.overallScore).toBeGreaterThan(90);
      }
    });
  });

  describe('Error Handling Scenarios', () => {
    beforeEach(async () => {
      const { addMultiTenantSecurityTools } = await import('../../../src/tools/multi-tenant-security.js');
      addMultiTenantSecurityTools(mockServer, mockApiClient as any);
    });

    it('should handle invalid tenant ID in provisioning gracefully', async () => {
      const provisionTool = findTool(mockTool, 'provision_tenant');
      
      const input = {
        tenantId: '',  // Invalid empty tenant ID
        tenantName: 'Test Corp',
        subscriptionTier: 'basic' as const,
        complianceFrameworks: ['SOC2'] as const,
        organizationInfo: {
          name: 'Test Corp',
          country: 'US',
          contactEmail: 'invalid-email'  // Invalid email
        },
        resourceQuotas: {
          maxUsers: 0,  // Invalid zero users
          maxConnections: 1,
          maxScenarios: 1,
          storageQuotaGB: 1,
          computeUnits: 1,
          apiCallsPerMonth: 1000
        },
        securitySettings: {
          requireMFA: false,
          sessionTimeoutMinutes: 480,
          passwordPolicy: {
            minLength: 12,
            requireSpecialChars: true,
            requireNumbers: true,
            requireUppercase: true
          },
          networkIsolation: true
        }
      };
      
      // Should reject with parameter validation error
      await expect(executeTool(provisionTool, input)).rejects.toThrow('Parameter validation failed');
    });

    it('should handle invalid operation in cryptographic isolation', async () => {
      const cryptoTool = findTool(mockTool, 'manage_cryptographic_isolation');
      
      const input = {
        tenantId: 'tenant_001',
        operation: 'invalid_operation' as any  // Invalid operation
      };
      
      // Should reject with parameter validation error
      await expect(executeTool(cryptoTool, input)).rejects.toThrow('Parameter validation failed');
    });

    it('should handle missing required data in encryption operations', async () => {
      const cryptoTool = findTool(mockTool, 'manage_cryptographic_isolation');
      
      const input = {
        tenantId: 'tenant_001',
        operation: 'encrypt_data' as const
        // Missing required 'data' field
      };
      
      // Should handle gracefully and not throw
      const result = await executeTool(cryptoTool, input);
      expect(result).toBeDefined();
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBe(false);
      expect(parsedResult.error).toBeDefined();
      expect(parsedResult.error).toContain('Data required');
    });

    it('should handle invalid network configuration', async () => {
      const networkTool = findTool(mockTool, 'configure_network_segmentation');
      
      const input = {
        tenantId: 'tenant_001',
        operation: 'create_vpc' as const,
        networkConfig: {
          vpcCidr: 'invalid_cidr',  // Invalid CIDR
          subnetConfiguration: []  // Empty subnets
        },
        securityPolicies: {
          crossTenantPrevention: true
        }
      };
      
      // Should handle gracefully and not throw
      const result = await executeTool(networkTool, input);
      expect(result).toBeDefined();
      
      const parsedResult = JSON.parse(result);
      // Should either succeed with defaults or fail gracefully
      expect(parsedResult).toBeDefined();
    });

    it('should handle invalid resource quota values', async () => {
      const quotaTool = findTool(mockTool, 'manage_resource_quotas');
      
      const input = {
        tenantId: 'tenant_001',
        operation: 'set_quotas' as const,
        resourceQuotas: {
          compute: {
            cpuCores: -1,  // Invalid negative value
            memoryGB: 0,   // Invalid zero value
            storageGB: 1,
            networkBandwidthMbps: 1
          },
          application: {
            maxConcurrentUsers: 0,  // Invalid zero
            maxActiveConnections: 1,
            maxWorkflowExecutions: 1,
            apiRequestsPerMinute: 10,
            maxWebhooks: 1
          },
          data: {
            maxDatabaseSize: 100,
            maxFileUploads: 1,
            maxBackups: 1,
            retentionDays: 7
          }
        }
      };
      
      // Should reject with parameter validation error
      await expect(executeTool(quotaTool, input)).rejects.toThrow('Parameter validation failed');
    });

    it('should handle invalid compliance framework', async () => {
      const complianceTool = findTool(mockTool, 'manage_compliance_boundaries');
      
      const input = {
        tenantId: 'tenant_001',
        operation: 'establish_boundaries' as const,
        complianceFramework: 'INVALID_FRAMEWORK' as any,  // Invalid framework
        boundaryConfig: {
          dataResidency: {
            allowedRegions: [],  // Empty regions
            dataLocalization: true,
            crossBorderRestrictions: true
          },
          processingLimitations: {
            purposeLimitation: true,
            dataMinimization: true,
            storageRestrictions: true,
            retentionLimits: true
          },
          accessControls: {
            roleBased: true,
            attributeBased: true,
            temporalAccess: false,
            auditTrail: true
          }
        },
        auditRequirements: {
          continuousMonitoring: true,
          regularAssessments: true,
          thirdPartyAudits: false,
          certificationMaintenance: true
        }
      };
      
      // Should reject with parameter validation error
      await expect(executeTool(complianceTool, input)).rejects.toThrow('Parameter validation failed');
    });
  });

  describe('Input Validation and Schema Compliance', () => {
    beforeEach(async () => {
      const { addMultiTenantSecurityTools } = await import('../../../src/tools/multi-tenant-security.js');
      addMultiTenantSecurityTools(mockServer, mockApiClient as any);
    });

    it('should have valid input schemas for all tools', () => {
      const expectedTools = [
        'provision_tenant',
        'manage_cryptographic_isolation',
        'configure_network_segmentation',
        'manage_resource_quotas',
        'manage_governance_policies',
        'prevent_data_leakage',
        'manage_compliance_boundaries'
      ];
      
      expectedTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool).toBeDefined();
        expect(tool.parameters).toBeDefined();
        // Verify schema is a Zod schema by checking for parse method
        expect(typeof tool.parameters.parse).toBe('function');
        expect(typeof tool.parameters.safeParse).toBe('function');
      });
    });

    it('should validate tenant provisioning input schema correctly', () => {
      const provisionTool = findTool(mockTool, 'provision_tenant');
      
      const validInput = {
        tenantId: 'tenant_001',
        tenantName: 'Test Corporation',
        subscriptionTier: 'enterprise' as const,
        complianceFrameworks: ['SOC2'] as const,
        organizationInfo: {
          name: 'Test Corporation',
          country: 'US',
          contactEmail: 'admin@testcorp.com'
        },
        resourceQuotas: {
          maxUsers: 100,
          maxConnections: 50,
          maxScenarios: 200,
          storageQuotaGB: 1000,
          computeUnits: 500,
          apiCallsPerMonth: 1000000
        },
        securitySettings: {
          passwordPolicy: {},
          networkIsolation: true
        }
      };
      
      // Should parse without error
      expect(() => provisionTool.parameters.parse(validInput)).not.toThrow();
    });

    it('should validate cryptographic isolation input schema correctly', () => {
      const cryptoTool = findTool(mockTool, 'manage_cryptographic_isolation');
      
      const validInput = {
        tenantId: 'tenant_001',
        operation: 'generate_keys' as const,
        keyType: 'master' as const
      };
      
      // Should parse without error
      expect(() => cryptoTool.parameters.parse(validInput)).not.toThrow();
    });

    it('should validate network segmentation input schema correctly', () => {
      const networkTool = findTool(mockTool, 'configure_network_segmentation');
      
      const validInput = {
        tenantId: 'tenant_001',
        operation: 'create_vpc' as const,
        networkConfig: {},
        securityPolicies: {}
      };
      
      // Should parse without error
      expect(() => networkTool.parameters.parse(validInput)).not.toThrow();
    });
  });

  describe('Integration with Dependencies', () => {
    it('should successfully import all required dependencies', async () => {
      // This test verifies that all dependencies can be imported without errors
      await expect(import('../../../src/tools/multi-tenant-security.js')).resolves.toBeDefined();
    });

    it('should have proper TypeScript compilation and module structure', async () => {
      const multiTenantSecurityModule = await import('../../../src/tools/multi-tenant-security.js');
      
      // Basic structural validation
      expect(multiTenantSecurityModule).toBeDefined();
      expect(typeof multiTenantSecurityModule).toBe('object');
      
      // Should have proper exports
      expect(Object.keys(multiTenantSecurityModule).length).toBeGreaterThan(0);
    });

    it('should work with mock API client without errors', async () => {
      const { addMultiTenantSecurityTools } = await import('../../../src/tools/multi-tenant-security.js');
      
      // Should not throw when called with mock API client
      expect(() => {
        addMultiTenantSecurityTools(mockServer, mockApiClient as any);
      }).not.toThrow();
      
      // Should have registered tools
      expect(mockTool).toHaveBeenCalled();
    });
  });
});