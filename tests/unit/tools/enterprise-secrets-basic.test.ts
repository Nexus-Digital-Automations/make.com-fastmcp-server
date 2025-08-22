/**
 * Basic Test Suite for Enterprise Secrets Management Tools
 * Tests core functionality of enterprise-grade secrets management tools with security focus
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { createMockServer, expectValidZodParse, expectInvalidZodParse } from '../../utils/test-helpers.js';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';

describe('Enterprise Secrets Management Tools - Basic Tests', () => {
  let mockServer: any;
  let mockTool: jest.MockedFunction<any>;
  let mockApiClient: MockMakeApiClient;
  let mockContext: any;

  beforeEach(async () => {
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockTool = serverSetup.mockTool;
    mockApiClient = new MockMakeApiClient();
    
    // Create mock context for tool execution
    mockContext = {
      log: {
        info: jest.fn(),
        error: jest.fn(),
        warn: jest.fn(),
        debug: jest.fn(),
      },
      reportProgress: jest.fn(),
      session: { authenticated: true },
    };
    
    // Clear previous mock calls
    mockTool.mockClear();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Tool Registration', () => {
    it('should successfully import and register all enterprise secrets tools', async () => {
      const { addEnterpriseSecretsTools } = await import('../../../src/tools/enterprise-secrets.js');
      
      // Should not throw an error
      expect(() => {
        addEnterpriseSecretsTools(mockServer, mockApiClient as any);
      }).not.toThrow();
      
      // Should call addTool for each tool (10 tools expected)
      expect(mockTool).toHaveBeenCalled();
      expect(mockTool.mock.calls.length).toBe(10);
    });

    it('should export the expected tools array', async () => {
      const enterpriseSecretsModule = await import('../../../src/tools/enterprise-secrets.js');
      
      // Check that expected exports exist
      expect(enterpriseSecretsModule.addEnterpriseSecretsTools).toBeDefined();
      expect(typeof enterpriseSecretsModule.addEnterpriseSecretsTools).toBe('function');
      
      expect(enterpriseSecretsModule.enterpriseSecretsTools).toBeDefined();
      expect(Array.isArray(enterpriseSecretsModule.enterpriseSecretsTools)).toBe(true);
      expect(enterpriseSecretsModule.enterpriseSecretsTools.length).toBe(10);
    });

    it('should register tools with correct names', async () => {
      const { addEnterpriseSecretsTools } = await import('../../../src/tools/enterprise-secrets.js');
      
      addEnterpriseSecretsTools(mockServer, mockApiClient as any);
      
      const registeredTools = mockTool.mock.calls.map(call => call[0].name);
      const expectedToolNames = [
        'configure-vault-server',
        'configure-hsm-integration',
        'manage-secret-engines',
        'configure-key-rotation',
        'generate-dynamic-secrets',
        'manage-rbac-policies',
        'scan-secret-leakage',
        'configure-breach-detection',
        'configure-audit-system',
        'generate-compliance-report'
      ];
      
      expectedToolNames.forEach(toolName => {
        expect(registeredTools).toContain(toolName);
      });
    });
  });

  describe('Tool Configuration Validation', () => {
    it('should have correct tool structure for vault server configuration', async () => {
      const { addEnterpriseSecretsTools } = await import('../../../src/tools/enterprise-secrets.js');
      
      addEnterpriseSecretsTools(mockServer, mockApiClient as any);
      
      const vaultTool = mockTool.mock.calls.find(call => call[0].name === 'configure-vault-server')?.[0];
      expect(vaultTool).toBeDefined();
      expect(vaultTool.name).toBe('configure-vault-server');
      expect(vaultTool.description).toBeDefined();
      expect(vaultTool.description).toContain('HashiCorp Vault server cluster');
      expect(vaultTool.parameters).toBeDefined();
      expect(typeof vaultTool.execute).toBe('function');
    });

    it('should have correct tool structure for HSM integration', async () => {
      const { addEnterpriseSecretsTools } = await import('../../../src/tools/enterprise-secrets.js');
      
      addEnterpriseSecretsTools(mockServer, mockApiClient as any);
      
      const hsmTool = mockTool.mock.calls.find(call => call[0].name === 'configure-hsm-integration')?.[0];
      expect(hsmTool).toBeDefined();
      expect(hsmTool.name).toBe('configure-hsm-integration');
      expect(hsmTool.description).toBeDefined();
      expect(hsmTool.description).toContain('Hardware Security Module');
      expect(hsmTool.parameters).toBeDefined();
      expect(typeof hsmTool.execute).toBe('function');
    });

    it('should have correct tool structure for dynamic secret generation', async () => {
      const { addEnterpriseSecretsTools } = await import('../../../src/tools/enterprise-secrets.js');
      
      addEnterpriseSecretsTools(mockServer, mockApiClient as any);
      
      const dynamicSecretTool = mockTool.mock.calls.find(call => call[0].name === 'generate-dynamic-secrets')?.[0];
      expect(dynamicSecretTool).toBeDefined();
      expect(dynamicSecretTool.name).toBe('generate-dynamic-secrets');
      expect(dynamicSecretTool.description).toBeDefined();
      expect(dynamicSecretTool.description).toContain('just-in-time dynamic secrets');
      expect(dynamicSecretTool.parameters).toBeDefined();
      expect(typeof dynamicSecretTool.execute).toBe('function');
    });

    it('should have correct tool structure for secret scanning', async () => {
      const { addEnterpriseSecretsTools } = await import('../../../src/tools/enterprise-secrets.js');
      
      addEnterpriseSecretsTools(mockServer, mockApiClient as any);
      
      const scanningTool = mockTool.mock.calls.find(call => call[0].name === 'scan-secret-leakage')?.[0];
      expect(scanningTool).toBeDefined();
      expect(scanningTool.name).toBe('scan-secret-leakage');
      expect(scanningTool.description).toBeDefined();
      expect(scanningTool.description).toContain('secret scanning');
      expect(scanningTool.parameters).toBeDefined();
      expect(typeof scanningTool.execute).toBe('function');
    });

    it('should have correct tool structure for compliance reporting', async () => {
      const { addEnterpriseSecretsTools } = await import('../../../src/tools/enterprise-secrets.js');
      
      addEnterpriseSecretsTools(mockServer, mockApiClient as any);
      
      const complianceTool = mockTool.mock.calls.find(call => call[0].name === 'generate-compliance-report')?.[0];
      expect(complianceTool).toBeDefined();
      expect(complianceTool.name).toBe('generate-compliance-report');
      expect(complianceTool.description).toBeDefined();
      expect(complianceTool.description).toContain('compliance reports');
      expect(complianceTool.parameters).toBeDefined();
      expect(typeof complianceTool.execute).toBe('function');
    });
  });

  describe('Schema Validation', () => {
    it('should validate vault server configuration schema correctly', async () => {
      const { addEnterpriseSecretsTools } = await import('../../../src/tools/enterprise-secrets.js');
      
      addEnterpriseSecretsTools(mockServer, mockApiClient as any);
      
      const vaultTool = mockTool.mock.calls.find(call => call[0].name === 'configure-vault-server')?.[0];
      const validConfig = {
        clusterId: 'test-cluster-001',
        nodeId: 'vault-node-1',
        config: {
          storage: {
            type: 'consul',
            config: {
              address: '127.0.0.1:8500',
              path: 'vault/'
            }
          },
          listener: {
            type: 'tcp',
            address: '0.0.0.0:8200',
            tlsConfig: {
              certFile: '/etc/vault/tls/cert.pem',
              keyFile: '/etc/vault/tls/key.pem',
              minVersion: 'tls12'
            }
          },
          seal: {
            type: 'shamir',
            config: {
              shares: 5,
              threshold: 3
            }
          },
          telemetry: {
            prometheusEnabled: true
          }
        },
        highAvailability: {
          enabled: true,
          redirectAddress: 'https://vault.example.com:8200',
          clusterAddress: 'https://vault.example.com:8201'
        }
      };

      expectValidZodParse(vaultTool.parameters, validConfig);
    });

    it('should reject invalid vault server configuration', async () => {
      const { addEnterpriseSecretsTools } = await import('../../../src/tools/enterprise-secrets.js');
      
      addEnterpriseSecretsTools(mockServer, mockApiClient as any);
      
      const vaultTool = mockTool.mock.calls.find(call => call[0].name === 'configure-vault-server')?.[0];
      const invalidConfig = {
        clusterId: '', // Invalid: empty string
        nodeId: 'vault-node-1',
        config: {
          storage: {
            type: 'invalid-storage', // Invalid: not in enum
            config: {}
          },
          listener: {
            type: 'tcp',
            address: '0.0.0.0:8200',
            tlsConfig: {
              // Missing required certFile and keyFile
            }
          },
          seal: {
            type: 'shamir',
            config: {}
          },
          telemetry: {}
        },
        highAvailability: {
          enabled: true,
          redirectAddress: 'https://vault.example.com:8200',
          clusterAddress: 'https://vault.example.com:8201'
        }
      };

      expectInvalidZodParse(vaultTool.parameters, invalidConfig, ['Cluster ID is required']);
    });

    it('should validate HSM configuration schema correctly', async () => {
      const { addEnterpriseSecretsTools } = await import('../../../src/tools/enterprise-secrets.js');
      
      addEnterpriseSecretsTools(mockServer, mockApiClient as any);
      
      const hsmTool = mockTool.mock.calls.find(call => call[0].name === 'configure-hsm-integration')?.[0];
      const validConfig = {
        provider: 'aws_cloudhsm',
        config: {
          region: 'us-west-2',
          endpoint: 'https://cloudhsmv2.us-west-2.amazonaws.com',
          accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
          secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
          encryptionAlgorithm: 'aes256-gcm'
        },
        compliance: {
          fipsLevel: 'level3',
          certifications: ['FIPS 140-2 Level 3', 'Common Criteria EAL4+']
        }
      };

      expectValidZodParse(hsmTool.parameters, validConfig);
    });

    it('should validate dynamic secret configuration schema correctly', async () => {
      const { addEnterpriseSecretsTools } = await import('../../../src/tools/enterprise-secrets.js');
      
      addEnterpriseSecretsTools(mockServer, mockApiClient as any);
      
      const dynamicSecretTool = mockTool.mock.calls.find(call => call[0].name === 'generate-dynamic-secrets')?.[0];
      const validConfig = {
        secretType: 'database',
        name: 'postgres-dynamic-creds',
        config: {
          connectionName: 'postgres-main',
          creationStatements: [
            'CREATE ROLE "{{name}}" WITH LOGIN PASSWORD \'{{password}}\' VALID UNTIL \'{{expiration}}\';',
            'GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{name}}";'
          ],
          revocationStatements: [
            'DROP ROLE IF EXISTS "{{name}}";'
          ]
        },
        leaseConfig: {
          defaultTtl: '1h',
          maxTtl: '24h',
          renewable: true
        }
      };

      expectValidZodParse(dynamicSecretTool.parameters, validConfig);
    });

    it('should validate secret scanning configuration schema correctly', async () => {
      const { addEnterpriseSecretsTools } = await import('../../../src/tools/enterprise-secrets.js');
      
      addEnterpriseSecretsTools(mockServer, mockApiClient as any);
      
      const scanningTool = mockTool.mock.calls.find(call => call[0].name === 'scan-secret-leakage')?.[0];
      const validConfig = {
        scanType: 'repository',
        targets: [
          '/app/src',
          '/app/config',
          '/app/scripts'
        ],
        detectionRules: {
          entropyThreshold: 4.5,
          patternMatching: true,
          customPatterns: [
            {
              name: 'aws_access_key',
              pattern: 'AKIA[0-9A-Z]{16}',
              confidence: 0.9
            }
          ]
        },
        responseActions: {
          alertSeverity: 'high',
          automaticRevocation: false,
          quarantineEnabled: true,
          notificationChannels: ['security-team', 'dev-ops']
        }
      };

      expectValidZodParse(scanningTool.parameters, validConfig);
    });
  });

  describe('Tool Execution', () => {
    it('should execute vault server configuration successfully', async () => {
      const { createConfigureVaultServerTool } = await import('../../../src/tools/enterprise-secrets/tools/configure-vault-server.js');
      
      const toolContext = {
        server: mockServer,
        apiClient: mockApiClient,
        logger: {
          info: jest.fn(),
          error: jest.fn(),
          warn: jest.fn(),
          debug: jest.fn(),
        }
      };
      
      const tool = createConfigureVaultServerTool(toolContext);
      const input = {
        clusterId: 'test-cluster-001',
        nodeId: 'vault-node-1',
        config: {
          storage: {
            type: 'consul',
            config: {
              address: '127.0.0.1:8500',
              path: 'vault/'
            }
          },
          listener: {
            type: 'tcp',
            address: '0.0.0.0:8200',
            tlsConfig: {
              certFile: '/etc/vault/tls/cert.pem',
              keyFile: '/etc/vault/tls/key.pem'
            }
          },
          seal: {
            type: 'shamir',
            config: {}
          },
          telemetry: {}
        },
        highAvailability: {
          enabled: true,
          redirectAddress: 'https://vault.example.com:8200',
          clusterAddress: 'https://vault.example.com:8201'
        }
      };

      const result = await tool.execute(input, mockContext);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.clusterInfo).toBeDefined();
      expect(parsedResult.clusterInfo.clusterId).toBe('test-cluster-001');
      expect(parsedResult.message).toContain('configured successfully');
    });

    it('should execute HSM integration successfully', async () => {
      const { createConfigureHSMIntegrationTool } = await import('../../../src/tools/enterprise-secrets/tools/configure-hsm-integration.js');
      
      const toolContext = {
        server: mockServer,
        apiClient: mockApiClient,
        logger: {
          info: jest.fn(),
          error: jest.fn(),
          warn: jest.fn(),
          debug: jest.fn(),
        }
      };
      
      const tool = createConfigureHSMIntegrationTool(toolContext);
      const input = {
        provider: 'pkcs11',
        config: {
          library: '/usr/lib/pkcs11/libpkcs11.so',
          slot: 0,
          pin: 'test-pin',
          keyLabel: 'vault-key',
          encryptionAlgorithm: 'aes256-gcm'
        },
        compliance: {
          fipsLevel: 'level2'
        }
      };

      const result = await tool.execute(input, mockContext);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.hsmStatus).toBeDefined();
      expect(parsedResult.hsmStatus.provider).toBe('pkcs11');
      expect(parsedResult.message).toContain('configured successfully');
    });

    it('should execute dynamic secret generation successfully', async () => {
      const { createGenerateDynamicSecretsTool } = await import('../../../src/tools/enterprise-secrets/tools/generate-dynamic-secrets.js');
      
      const toolContext = {
        server: mockServer,
        apiClient: mockApiClient,
        logger: {
          info: jest.fn(),
          error: jest.fn(),
          warn: jest.fn(),
          debug: jest.fn(),
        }
      };
      
      const tool = createGenerateDynamicSecretsTool(toolContext);
      const input = {
        secretType: 'aws',
        name: 'aws-temp-access',
        config: {
          roleArn: 'arn:aws:iam::123456789012:role/DynamicRole',
          credentialType: 'assumed_role',
          policyArns: ['arn:aws:iam::aws:policy/ReadOnlyAccess']
        },
        leaseConfig: {
          defaultTtl: '2h',
          maxTtl: '12h',
          renewable: true
        }
      };

      const result = await tool.execute(input, mockContext);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.secret).toBeDefined();
      expect(parsedResult.secret.leaseId).toBeDefined();
      expect(parsedResult.secret.accessKeyId).toBeDefined();
      expect(parsedResult.secret.secretAccessKey).toBeDefined();
      expect(parsedResult.secret.renewable).toBe(true);
    });

    it('should execute secret scanning successfully', async () => {
      const { createScanSecretLeakageTool } = await import('../../../src/tools/enterprise-secrets/tools/scan-secret-leakage.js');
      
      const toolContext = {
        server: mockServer,
        apiClient: mockApiClient,
        logger: {
          info: jest.fn(),
          error: jest.fn(),
          warn: jest.fn(),
          debug: jest.fn(),
        }
      };
      
      const tool = createScanSecretLeakageTool(toolContext);
      const input = {
        scanType: 'configuration',
        targets: ['/app/config', '/app/.env'],
        detectionRules: {
          entropyThreshold: 4.0,
          patternMatching: true,
          customPatterns: [
            {
              name: 'api_key',
              pattern: 'api_key_[a-zA-Z0-9]{32}',
              confidence: 0.8
            }
          ]
        },
        responseActions: {
          alertSeverity: 'medium',
          automaticRevocation: false,
          quarantineEnabled: true
        }
      };

      const result = await tool.execute(input, mockContext);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.scanResults).toBeDefined();
      expect(parsedResult.scanResults.alertsGenerated).toBeDefined();
      expect(typeof parsedResult.scanResults.alertsGenerated).toBe('number');
    });

    it('should execute compliance report generation successfully', async () => {
      const { createGenerateComplianceReportTool } = await import('../../../src/tools/enterprise-secrets/tools/generate-compliance-report.js');
      
      const toolContext = {
        server: mockServer,
        apiClient: mockApiClient,
        logger: {
          info: jest.fn(),
          error: jest.fn(),
          warn: jest.fn(),
          debug: jest.fn(),
        }
      };
      
      const tool = createGenerateComplianceReportTool(toolContext);
      const input = {
        framework: 'soc2'
      };

      const result = await tool.execute(input, mockContext);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.report).toBeDefined();
      expect(parsedResult.report.framework).toBe('soc2');
      expect(parsedResult.report.overallCompliance).toBeDefined();
      expect(parsedResult.report.controlStatus).toBeDefined();
      expect(Array.isArray(parsedResult.report.controlStatus)).toBe(true);
    });

    it('should execute RBAC policy management successfully', async () => {
      const { createManageRBACPoliciesTool } = await import('../../../src/tools/enterprise-secrets/tools/manage-rbac-policies.js');
      
      const toolContext = {
        server: mockServer,
        apiClient: mockApiClient,
        logger: {
          info: jest.fn(),
          error: jest.fn(),
          warn: jest.fn(),
          debug: jest.fn(),
        }
      };
      
      const tool = createManageRBACPoliciesTool(toolContext);
      const input = {
        policyName: 'dev-team-policy',
        description: 'Policy for development team access',
        rules: [
          {
            path: 'secret/dev/*',
            capabilities: ['create', 'read', 'update', 'delete', 'list'],
            requiredParameters: ['environment'],
            allowedParameters: {
              'environment': ['development', 'staging']
            }
          },
          {
            path: 'secret/prod/*',
            capabilities: ['read'],
            deniedParameters: ['admin_access']
          }
        ],
        metadata: {
          tenant: 'acme-corp',
          environment: 'development',
          department: 'engineering',
          owner: 'dev-team-lead@acme.com'
        }
      };

      const result = await tool.execute(input, mockContext);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.policyName).toBe('dev-team-policy');
      expect(parsedResult.policyContent).toBeDefined();
      expect(parsedResult.policyContent).toContain('secret/dev/*');
    });

    it('should execute key rotation configuration successfully', async () => {
      const { createConfigureKeyRotationTool } = await import('../../../src/tools/enterprise-secrets/tools/configure-key-rotation.js');
      
      const toolContext = {
        server: mockServer,
        apiClient: mockApiClient,
        logger: {
          info: jest.fn(),
          error: jest.fn(),
          warn: jest.fn(),
          debug: jest.fn(),
        }
      };
      
      const tool = createConfigureKeyRotationTool(toolContext);
      const input = {
        policyName: 'monthly-key-rotation',
        targetPaths: ['secret/database/*', 'secret/api-keys/*'],
        rotationType: 'scheduled',
        schedule: {
          intervalHours: 720, // 30 days
          rotationWindow: {
            start: '02:00',
            end: '04:00'
          }
        },
        rotationCriteria: {
          maxAgeHours: 720,
          complianceRequirement: 'SOC2'
        },
        rotationStrategy: {
          strategy: 'graceful',
          gracePeriodHours: 24,
          rollbackEnabled: true,
          notificationEnabled: true
        }
      };

      const result = await tool.execute(input, mockContext);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.rotationStatus).toBeDefined();
      expect(parsedResult.rotationStatus.policyName).toBe('monthly-key-rotation');
      expect(parsedResult.rotationStatus.status).toBe('active');
    });
  });

  describe('Error Handling and Security', () => {
    it('should handle invalid vault configuration gracefully', async () => {
      const { createConfigureVaultServerTool } = await import('../../../src/tools/enterprise-secrets/tools/configure-vault-server.js');
      
      const toolContext = {
        server: mockServer,
        apiClient: mockApiClient,
        logger: {
          info: jest.fn(),
          error: jest.fn(),
          warn: jest.fn(),
          debug: jest.fn(),
        }
      };
      
      const tool = createConfigureVaultServerTool(toolContext);
      const invalidInput = {
        clusterId: '',
        nodeId: '',
        config: {}
      };

      // Should throw validation error
      await expect(tool.execute(invalidInput, mockContext)).rejects.toThrow();
    });

    it('should handle invalid HSM provider gracefully', async () => {
      const { createConfigureHSMIntegrationTool } = await import('../../../src/tools/enterprise-secrets/tools/configure-hsm-integration.js');
      
      const toolContext = {
        server: mockServer,
        apiClient: mockApiClient,
        logger: {
          info: jest.fn(),
          error: jest.fn(),
          warn: jest.fn(),
          debug: jest.fn(),
        }
      };
      
      const tool = createConfigureHSMIntegrationTool(toolContext);
      const invalidInput = {
        provider: 'invalid_provider',
        config: {},
        compliance: {}
      };

      // Should throw validation error
      await expect(tool.execute(invalidInput, mockContext)).rejects.toThrow();
    });

    it('should handle invalid secret type for dynamic secrets', async () => {
      const { createGenerateDynamicSecretsTool } = await import('../../../src/tools/enterprise-secrets/tools/generate-dynamic-secrets.js');
      
      const toolContext = {
        server: mockServer,
        apiClient: mockApiClient,
        logger: {
          info: jest.fn(),
          error: jest.fn(),
          warn: jest.fn(),
          debug: jest.fn(),
        }
      };
      
      const tool = createGenerateDynamicSecretsTool(toolContext);
      const invalidInput = {
        secretType: 'invalid_type',
        name: 'test',
        config: {},
        leaseConfig: {
          defaultTtl: '1h',
          maxTtl: '24h',
          renewable: true
        }
      };

      // Should throw validation error
      await expect(tool.execute(invalidInput, mockContext)).rejects.toThrow();
    });

    it('should handle empty scan targets gracefully', async () => {
      const { createScanSecretLeakageTool } = await import('../../../src/tools/enterprise-secrets/tools/scan-secret-leakage.js');
      
      const toolContext = {
        server: mockServer,
        apiClient: mockApiClient,
        logger: {
          info: jest.fn(),
          error: jest.fn(),
          warn: jest.fn(),
          debug: jest.fn(),
        }
      };
      
      const tool = createScanSecretLeakageTool(toolContext);
      const invalidInput = {
        scanType: 'repository',
        targets: [], // Empty targets array
        detectionRules: {},
        responseActions: {}
      };

      // Should throw validation error
      await expect(tool.execute(invalidInput, mockContext)).rejects.toThrow();
    });

    it('should handle invalid compliance framework gracefully', async () => {
      const { createGenerateComplianceReportTool } = await import('../../../src/tools/enterprise-secrets/tools/generate-compliance-report.js');
      
      const toolContext = {
        server: mockServer,
        apiClient: mockApiClient,
        logger: {
          info: jest.fn(),
          error: jest.fn(),
          warn: jest.fn(),
          debug: jest.fn(),
        }
      };
      
      const tool = createGenerateComplianceReportTool(toolContext);
      const invalidInput = {
        framework: 'invalid_framework'
      };

      // Should throw validation error
      await expect(tool.execute(invalidInput, mockContext)).rejects.toThrow();
    });

    it('should validate encryption algorithms in HSM configuration', async () => {
      const { addEnterpriseSecretsTools } = await import('../../../src/tools/enterprise-secrets.js');
      
      addEnterpriseSecretsTools(mockServer, mockApiClient as any);
      
      const hsmTool = mockTool.mock.calls.find(call => call[0].name === 'configure-hsm-integration')?.[0];
      
      // Valid encryption algorithms should work
      const validConfig = {
        provider: 'pkcs11',
        config: {
          encryptionAlgorithm: 'aes256-gcm'
        },
        compliance: {}
      };

      expectValidZodParse(hsmTool.parameters, validConfig);

      // Invalid encryption algorithm should fail
      const invalidConfig = {
        provider: 'pkcs11',
        config: {
          encryptionAlgorithm: 'weak-des'
        },
        compliance: {}
      };

      expectInvalidZodParse(hsmTool.parameters, invalidConfig);
    });

    it('should validate FIPS compliance levels', async () => {
      const { addEnterpriseSecretsTools } = await import('../../../src/tools/enterprise-secrets.js');
      
      addEnterpriseSecretsTools(mockServer, mockApiClient as any);
      
      const hsmTool = mockTool.mock.calls.find(call => call[0].name === 'configure-hsm-integration')?.[0];
      
      // Valid FIPS levels
      const validFipsLevels = ['level1', 'level2', 'level3', 'level4'];
      
      validFipsLevels.forEach(level => {
        const config = {
          provider: 'aws_cloudhsm',
          config: {},
          compliance: {
            fipsLevel: level
          }
        };
        expectValidZodParse(hsmTool.parameters, config);
      });
    });
  });

  describe('Security-Focused Testing', () => {
    it('should ensure sensitive data is not logged in vault configuration', async () => {
      const { createConfigureVaultServerTool } = await import('../../../src/tools/enterprise-secrets/tools/configure-vault-server.js');
      
      const toolContext = {
        server: mockServer,
        apiClient: mockApiClient,
        logger: {
          info: jest.fn(),
          error: jest.fn(),
          warn: jest.fn(),
          debug: jest.fn(),
        }
      };
      
      const tool = createConfigureVaultServerTool(toolContext);
      const input = {
        clusterId: 'test-cluster',
        nodeId: 'vault-node-1',
        config: {
          storage: { type: 'consul', config: {} },
          listener: {
            type: 'tcp',
            address: '0.0.0.0:8200',
            tlsConfig: {
              certFile: '/etc/vault/tls/cert.pem',
              keyFile: '/etc/vault/tls/key.pem'
            }
          },
          seal: { type: 'shamir', config: {} },
          telemetry: {}
        },
        highAvailability: {
          enabled: true,
          redirectAddress: 'https://vault.example.com:8200',
          clusterAddress: 'https://vault.example.com:8201'
        }
      };

      const result = await tool.execute(input, mockContext);
      const parsedResult = JSON.parse(result);
      
      // Ensure sensitive paths are not exposed in logs
      expect(JSON.stringify(parsedResult)).not.toContain('/etc/vault/tls/key.pem');
      expect(parsedResult.success).toBe(true);
    });

    it('should validate secure password generation in dynamic secrets', async () => {
      const { createGenerateDynamicSecretsTool } = await import('../../../src/tools/enterprise-secrets/tools/generate-dynamic-secrets.js');
      
      const toolContext = {
        server: mockServer,
        apiClient: mockApiClient,
        logger: {
          info: jest.fn(),
          error: jest.fn(),
          warn: jest.fn(),
          debug: jest.fn(),
        }
      };
      
      const tool = createGenerateDynamicSecretsTool(toolContext);
      const input = {
        secretType: 'database',
        name: 'postgres-creds',
        config: {
          connectionName: 'postgres-main',
          creationStatements: ['CREATE ROLE "{{name}}" WITH LOGIN PASSWORD \'{{password}}\';']
        },
        leaseConfig: {
          defaultTtl: '1h',
          maxTtl: '24h',
          renewable: true
        }
      };

      const result = await tool.execute(input, mockContext);
      const parsedResult = JSON.parse(result);
      
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.secret.password).toBeDefined();
      expect(parsedResult.secret.password.length).toBeGreaterThan(20); // Ensure strong password
      expect(parsedResult.secret.leaseId).toMatch(/^dynamic-secret\/database\/[0-9a-f-]+$/);
    });

    it('should validate audit trail integrity requirements', async () => {
      const { createConfigureAuditSystemTool } = await import('../../../src/tools/enterprise-secrets/tools/configure-audit-system.js');
      
      const toolContext = {
        server: mockServer,
        apiClient: mockApiClient,
        logger: {
          info: jest.fn(),
          error: jest.fn(),
          warn: jest.fn(),
          debug: jest.fn(),
        }
      };
      
      const tool = createConfigureAuditSystemTool(toolContext);
      const secureConfig = {
        auditDevices: [
          {
            type: 'file',
            path: '/var/log/vault/audit.log',
            config: {},
            format: 'json'
          }
        ],
        auditFilters: {
          excludeUnauthentic: true,
          sensitiveDataRedaction: true
        },
        retention: {
          retentionPeriodDays: 2555, // 7 years
          compressionEnabled: true,
          encryptionEnabled: true,
          immutableStorage: true
        },
        compliance: {
          frameworks: ['soc2', 'pci_dss'],
          evidenceCollection: true,
          reportGeneration: true
        }
      };

      const result = await tool.execute(secureConfig, mockContext);
      const parsedResult = JSON.parse(result);
      
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.auditConfiguration.encryptionEnabled).toBe(true);
      expect(parsedResult.auditConfiguration.immutableStorage).toBe(true);
      expect(parsedResult.auditConfiguration.retentionPeriod).toBe(2555);
    });

    it('should ensure high-entropy detection in secret scanning', async () => {
      const { createScanSecretLeakageTool } = await import('../../../src/tools/enterprise-secrets/tools/scan-secret-leakage.js');
      
      const toolContext = {
        server: mockServer,
        apiClient: mockApiClient,
        logger: {
          info: jest.fn(),
          error: jest.fn(),
          warn: jest.fn(),
          debug: jest.fn(),
        }
      };
      
      const tool = createScanSecretLeakageTool(toolContext);
      const highSecurityConfig = {
        scanType: 'memory',
        targets: ['/proc/self/mem'],
        detectionRules: {
          entropyThreshold: 7.0, // Very high entropy threshold
          patternMatching: true,
          customPatterns: [
            {
              name: 'high_entropy_string',
              pattern: '[A-Za-z0-9+/]{40,}={0,2}', // Base64-like patterns
              confidence: 0.95
            }
          ]
        },
        responseActions: {
          alertSeverity: 'critical',
          automaticRevocation: true,
          quarantineEnabled: true,
          notificationChannels: ['security-soc', 'incident-response']
        }
      };

      const result = await tool.execute(highSecurityConfig, mockContext);
      const parsedResult = JSON.parse(result);
      
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.scanResults).toBeDefined();
      // Validate that high-severity alerts are properly categorized
      expect(parsedResult.scanResults.criticalAlerts).toBeDefined();
      expect(typeof parsedResult.scanResults.criticalAlerts).toBe('number');
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle multiple secret engines configuration', async () => {
      const { createManageSecretEnginesTool } = await import('../../../src/tools/enterprise-secrets/tools/manage-secret-engines.js');
      
      const toolContext = {
        server: mockServer,
        apiClient: mockApiClient,
        logger: {
          info: jest.fn(),
          error: jest.fn(),
          warn: jest.fn(),
          debug: jest.fn(),
        }
      };
      
      const tool = createManageSecretEnginesTool(toolContext);
      
      // Test different engine types
      const engineTypes = ['kv', 'database', 'pki', 'transit', 'aws'];
      
      for (const engineType of engineTypes) {
        const input = {
          engineType,
          path: `${engineType}-engine`,
          description: `${engineType} secret engine for testing`,
          config: {}
        };

        const result = await tool.execute(input, mockContext);
        const parsedResult = JSON.parse(result);
        
        expect(parsedResult.success).toBe(true);
        expect(parsedResult.engineStatus.type).toBe(engineType);
        expect(parsedResult.engineStatus.path).toBe(`${engineType}-engine`);
      }
    });

    it('should validate breach detection thresholds', async () => {
      const { createConfigureBreachDetectionTool } = await import('../../../src/tools/enterprise-secrets/tools/configure-breach-detection.js');
      
      const toolContext = {
        server: mockServer,
        apiClient: mockApiClient,
        logger: {
          info: jest.fn(),
          error: jest.fn(),
          warn: jest.fn(),
          debug: jest.fn(),
        }
      };
      
      const tool = createConfigureBreachDetectionTool(toolContext);
      const performanceConfig = {
        detectionMethods: {
          anomalyDetection: true,
          patternAnalysis: true,
          threatIntelligence: true,
          behavioralAnalysis: true
        },
        monitoringTargets: [
          'secret_access_patterns',
          'authentication_events',
          'authorization_failures',
          'unusual_api_usage'
        ],
        responseConfig: {
          automaticContainment: true,
          alertEscalation: true,
          forensicCollection: true,
          stakeholderNotification: true
        },
        thresholds: {
          accessFrequencyThreshold: 1000, // High-volume threshold
          geographicVelocityKmh: 500,
          failureRateThreshold: 0.05,
          anomalyScoreThreshold: 0.9
        }
      };

      const result = await tool.execute(performanceConfig, mockContext);
      const parsedResult = JSON.parse(result);
      
      expect(parsedResult.success).toBe(true);
      expect(parsedResult.configuration.thresholds.accessFrequencyThreshold).toBe(1000);
      expect(parsedResult.configuration.detectionMethods.anomalyDetection).toBe(true);
    });
  });
});