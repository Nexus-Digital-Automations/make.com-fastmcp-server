/**
 * @fileoverview Comprehensive test suite for HSM Integration
 * Tests Hardware Security Module configuration, key management, and security operations
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { configureHsmIntegrationTool } from '../../../../src/tools/enterprise-secrets/tools/configure-hsm-integration.js';
import { ToolContext } from '../../../../src/tools/shared/types/tool-context.js';
import { UserError } from 'fastmcp';

// Mock dependencies
const mockApiClient = {
  post: jest.fn(),
  get: jest.fn(),
  put: jest.fn(),
  delete: jest.fn(),
};

const mockLogger = {
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
};

const mockServer = {
  addTool: jest.fn(),
};

describe('HSM Integration - Comprehensive Tests', () => {
  let toolContext: ToolContext;

  beforeEach(() => {
    toolContext = {
      server: mockServer as any,
      apiClient: mockApiClient as any,
      logger: mockLogger,
    };
    
    // Reset all mocks
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('Tool Registration and Structure', () => {
    it('should create tool with correct configuration', () => {
      const tool = configureHsmIntegrationTool(toolContext);
      
      expect(tool.name).toBe('configure-hsm-integration');
      expect(tool.description).toContain('HSM integration');
      expect(tool.parameters).toBeDefined();
      expect(tool.annotations).toBeDefined();
      expect(typeof tool.execute).toBe('function');
    });

    it('should have proper security annotations', () => {
      const tool = configureHsmIntegrationTool(toolContext);
      
      expect(tool.annotations.title).toBeDefined();
      expect(tool.annotations.readOnlyHint).toBe(false);
      expect(tool.annotations.destructiveHint).toBe(true);
      expect(tool.annotations.openWorldHint).toBe(false);
    });
  });

  describe('Parameter Validation', () => {
    it('should validate required HSM provider', async () => {
      const tool = configureHsmIntegrationTool(toolContext);
      
      await expect(tool.execute({
        hsmName: 'test-hsm'
        // Missing provider
      }, { log: mockLogger })).rejects.toThrow();
    });

    it('should validate HSM provider options', async () => {
      const tool = configureHsmIntegrationTool(toolContext);
      
      await expect(tool.execute({
        hsmName: 'test-hsm',
        provider: 'invalid-provider' as any
      }, { log: mockLogger })).rejects.toThrow();
    });

    it('should validate connection endpoint format', async () => {
      const tool = configureHsmIntegrationTool(toolContext);
      
      await expect(tool.execute({
        hsmName: 'test-hsm',
        provider: 'aws-cloudhsm',
        connectionEndpoint: 'invalid-endpoint'
      }, { log: mockLogger })).rejects.toThrow();
    });

    it('should accept valid HSM configuration', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          hsmId: 'hsm-123',
          status: 'configured',
          provider: 'aws-cloudhsm'
        }
      });

      const tool = configureHsmIntegrationTool(toolContext);
      
      const result = await tool.execute({
        hsmName: 'production-hsm',
        provider: 'aws-cloudhsm',
        connectionEndpoint: 'hsm-cluster.us-east-1.cloudhsm.amazonaws.com',
        enableHighAvailability: true,
        keyRotationPolicy: 'automatic'
      }, { log: mockLogger });

      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
    });
  });

  describe('HSM Provider Configuration', () => {
    beforeEach(() => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          hsmId: 'hsm-test-123',
          status: 'configured',
          provider: 'aws-cloudhsm',
          cluster: {
            clusterId: 'cluster-abc123',
            state: 'ACTIVE',
            nodes: 3
          }
        }
      });
    });

    it('should configure AWS CloudHSM integration', async () => {
      const tool = configureHsmIntegrationTool(toolContext);
      
      const result = await tool.execute({
        hsmName: 'aws-production-hsm',
        provider: 'aws-cloudhsm',
        connectionEndpoint: 'hsm-cluster.us-east-1.cloudhsm.amazonaws.com',
        enableHighAvailability: true,
        keyRotationPolicy: 'automatic',
        encryptionAlgorithm: 'AES-256-GCM'
      }, { log: mockLogger });

      expect(mockApiClient.post).toHaveBeenCalledWith(
        '/enterprise-secrets/hsm/configure',
        expect.objectContaining({
          hsmName: 'aws-production-hsm',
          provider: 'aws-cloudhsm',
          connectionEndpoint: 'hsm-cluster.us-east-1.cloudhsm.amazonaws.com',
          enableHighAvailability: true
        })
      );

      const parsed = JSON.parse(result);
      expect(parsed.hsm).toBeDefined();
      expect(parsed.hsm.hsmId).toBe('hsm-test-123');
      expect(parsed.message).toContain('successfully configured');
    });

    it('should configure Azure Dedicated HSM', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          hsmId: 'azure-hsm-456',
          status: 'configured',
          provider: 'azure-dedicated-hsm'
        }
      });

      const tool = configureHsmIntegrationTool(toolContext);
      
      await tool.execute({
        hsmName: 'azure-hsm',
        provider: 'azure-dedicated-hsm',
        connectionEndpoint: 'hsm.vault.azure.net',
        enableHighAvailability: true,
        keyRotationPolicy: 'manual'
      }, { log: mockLogger });

      expect(mockApiClient.post).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          provider: 'azure-dedicated-hsm',
          connectionEndpoint: 'hsm.vault.azure.net'
        })
      );
    });

    it('should configure Google Cloud HSM', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          hsmId: 'gcp-hsm-789',
          status: 'configured',
          provider: 'google-cloud-hsm'
        }
      });

      const tool = configureHsmIntegrationTool(toolContext);
      
      await tool.execute({
        hsmName: 'gcp-hsm',
        provider: 'google-cloud-hsm',
        connectionEndpoint: 'projects/my-project/locations/us-central1/keyRings/hsm-ring',
        enableHighAvailability: false,
        keyRotationPolicy: 'scheduled',
        encryptionAlgorithm: 'RSA-4096'
      }, { log: mockLogger });

      expect(mockApiClient.post).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          provider: 'google-cloud-hsm',
          encryptionAlgorithm: 'RSA-4096'
        })
      );
    });

    it('should configure Thales nShield HSM', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          hsmId: 'thales-hsm-101',
          status: 'configured',
          provider: 'thales-nshield'
        }
      });

      const tool = configureHsmIntegrationTool(toolContext);
      
      await tool.execute({
        hsmName: 'thales-hsm',
        provider: 'thales-nshield',
        connectionEndpoint: '192.168.1.100:9000',
        enableHighAvailability: true,
        keyRotationPolicy: 'automatic',
        encryptionAlgorithm: 'AES-256-GCM'
      }, { log: mockLogger });

      expect(mockApiClient.post).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          provider: 'thales-nshield',
          connectionEndpoint: '192.168.1.100:9000'
        })
      );
    });
  });

  describe('Key Management Operations', () => {
    it('should configure automatic key rotation', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          hsmId: 'hsm-123',
          status: 'configured',
          keyRotation: {
            policy: 'automatic',
            interval: '30d',
            nextRotation: '2024-02-15T00:00:00Z'
          }
        }
      });

      const tool = configureHsmIntegrationTool(toolContext);
      
      const result = await tool.execute({
        hsmName: 'auto-rotate-hsm',
        provider: 'aws-cloudhsm',
        connectionEndpoint: 'hsm-cluster.amazonaws.com',
        keyRotationPolicy: 'automatic',
        rotationInterval: '30d'
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.keyManagement).toBeDefined();
      expect(parsed.keyManagement.rotationPolicy).toBe('automatic');
      expect(parsed.keyManagement.nextRotation).toBeDefined();
    });

    it('should validate encryption algorithm support', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          hsmId: 'hsm-123',
          status: 'configured',
          supportedAlgorithms: ['AES-256-GCM', 'RSA-2048', 'RSA-4096', 'ECDSA-P256']
        }
      });

      const tool = configureHsmIntegrationTool(toolContext);
      
      const algorithms = ['AES-256-GCM', 'RSA-2048', 'RSA-4096', 'ECDSA-P256'];
      
      for (const algorithm of algorithms) {
        await expect(tool.execute({
          hsmName: `hsm-${algorithm}`,
          provider: 'aws-cloudhsm',
          connectionEndpoint: 'hsm-cluster.amazonaws.com',
          encryptionAlgorithm: algorithm as any
        }, { log: mockLogger })).resolves.toBeDefined();
      }
    });

    it('should handle key backup and recovery configuration', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          hsmId: 'hsm-123',
          status: 'configured',
          backup: {
            enabled: true,
            schedule: 'daily',
            retention: '30d',
            location: 's3://hsm-backups/keys'
          }
        }
      });

      const tool = configureHsmIntegrationTool(toolContext);
      
      const result = await tool.execute({
        hsmName: 'backup-hsm',
        provider: 'aws-cloudhsm',
        connectionEndpoint: 'hsm-cluster.amazonaws.com',
        enableBackup: true,
        backupSchedule: 'daily',
        backupRetention: '30d'
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.backup).toBeDefined();
      expect(parsed.backup.enabled).toBe(true);
      expect(parsed.backup.schedule).toBe('daily');
    });
  });

  describe('Security and Compliance', () => {
    it('should enforce FIPS compliance for HSM operations', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          hsmId: 'fips-hsm-123',
          status: 'configured',
          compliance: {
            fips140Level: 'Level 3',
            commonCriteria: 'EAL4+',
            certifications: ['FIPS 140-2', 'Common Criteria']
          }
        }
      });

      const tool = configureHsmIntegrationTool(toolContext);
      
      const result = await tool.execute({
        hsmName: 'fips-compliant-hsm',
        provider: 'thales-nshield',
        connectionEndpoint: '192.168.1.100:9000',
        enableFipsCompliance: true,
        securityLevel: 'high'
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.compliance).toBeDefined();
      expect(parsed.compliance.fips140Level).toBeDefined();
      expect(parsed.security.level).toBe('high');
    });

    it('should validate authentication credentials', async () => {
      const tool = configureHsmIntegrationTool(toolContext);
      
      await expect(tool.execute({
        hsmName: 'auth-hsm',
        provider: 'aws-cloudhsm',
        connectionEndpoint: 'hsm-cluster.amazonaws.com',
        authenticationMethod: 'client-certificate'
      }, { log: mockLogger })).rejects.toThrow(/authentication/i);
    });

    it('should handle HSM tamper detection', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          hsmId: 'tamper-hsm-123',
          status: 'configured',
          tamperDetection: {
            enabled: true,
            sensitivity: 'high',
            alertEndpoint: 'https://security.example.com/alerts'
          }
        }
      });

      const tool = configureHsmIntegrationTool(toolContext);
      
      const result = await tool.execute({
        hsmName: 'tamper-detect-hsm',
        provider: 'thales-nshield',
        connectionEndpoint: '192.168.1.100:9000',
        enableTamperDetection: true,
        tamperSensitivity: 'high'
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.security.tamperDetection.enabled).toBe(true);
      expect(parsed.security.tamperDetection.sensitivity).toBe('high');
    });
  });

  describe('Error Handling', () => {
    it('should handle HSM unavailable errors', async () => {
      mockApiClient.post.mockRejectedValue(new Error('HSM cluster unavailable'));

      const tool = configureHsmIntegrationTool(toolContext);
      
      await expect(tool.execute({
        hsmName: 'unavailable-hsm',
        provider: 'aws-cloudhsm',
        connectionEndpoint: 'offline-hsm.amazonaws.com'
      }, { log: mockLogger })).rejects.toThrow(UserError);

      expect(mockLogger.error).toHaveBeenCalledWith(
        expect.stringContaining('Failed to configure HSM integration'),
        expect.any(Object)
      );
    });

    it('should handle authentication failures', async () => {
      mockApiClient.post.mockResolvedValue({
        success: false,
        error: { message: 'HSM authentication failed', code: 'HSM_AUTH_ERROR' }
      });

      const tool = configureHsmIntegrationTool(toolContext);
      
      await expect(tool.execute({
        hsmName: 'auth-fail-hsm',
        provider: 'azure-dedicated-hsm',
        connectionEndpoint: 'hsm.vault.azure.net'
      }, { log: mockLogger })).rejects.toThrow(UserError);
    });

    it('should handle unsupported HSM features', async () => {
      mockApiClient.post.mockResolvedValue({
        success: false,
        error: { message: 'Feature not supported by HSM', code: 'FEATURE_NOT_SUPPORTED' }
      });

      const tool = configureHsmIntegrationTool(toolContext);
      
      await expect(tool.execute({
        hsmName: 'unsupported-hsm',
        provider: 'basic-hsm',
        connectionEndpoint: 'hsm.example.com',
        encryptionAlgorithm: 'QUANTUM-RESISTANT' as any
      }, { log: mockLogger })).rejects.toThrow(UserError);
    });

    it('should handle HSM capacity limitations', async () => {
      mockApiClient.post.mockResolvedValue({
        success: false,
        error: { message: 'HSM at capacity', code: 'HSM_CAPACITY_EXCEEDED' }
      });

      const tool = configureHsmIntegrationTool(toolContext);
      
      await expect(tool.execute({
        hsmName: 'capacity-hsm',
        provider: 'aws-cloudhsm',
        connectionEndpoint: 'full-hsm.amazonaws.com'
      }, { log: mockLogger })).rejects.toThrow(UserError);
    });
  });

  describe('Performance and Monitoring', () => {
    it('should handle concurrent HSM operations', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: { hsmId: 'hsm-123', status: 'configured' }
      });

      const tool = configureHsmIntegrationTool(toolContext);
      
      const operations = Array(3).fill(0).map(async (_, i) => {
        return tool.execute({
          hsmName: `concurrent-hsm-${i}`,
          provider: 'aws-cloudhsm',
          connectionEndpoint: `hsm-${i}.amazonaws.com`
        }, { log: mockLogger });
      });

      const results = await Promise.allSettled(operations);
      const successful = results.filter(r => r.status === 'fulfilled');
      
      expect(successful).toHaveLength(3);
    });

    it('should configure HSM performance monitoring', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          hsmId: 'monitor-hsm-123',
          status: 'configured',
          monitoring: {
            enabled: true,
            metrics: ['throughput', 'latency', 'errors', 'capacity'],
            alertThresholds: {
              latency: '500ms',
              errorRate: '1%',
              capacity: '90%'
            }
          }
        }
      });

      const tool = configureHsmIntegrationTool(toolContext);
      
      const result = await tool.execute({
        hsmName: 'monitored-hsm',
        provider: 'thales-nshield',
        connectionEndpoint: '192.168.1.100:9000',
        enableMonitoring: true,
        monitoringLevel: 'detailed'
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.monitoring).toBeDefined();
      expect(parsed.monitoring.enabled).toBe(true);
      expect(parsed.monitoring.metrics).toContain('throughput');
    });

    it('should validate HSM connection health', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          hsmId: 'health-hsm-123',
          status: 'configured',
          health: {
            status: 'healthy',
            latency: 45,
            throughput: 1000,
            lastHealthCheck: '2024-01-15T10:00:00Z'
          }
        }
      });

      const tool = configureHsmIntegrationTool(toolContext);
      
      const result = await tool.execute({
        hsmName: 'health-check-hsm',
        provider: 'aws-cloudhsm',
        connectionEndpoint: 'hsm-cluster.amazonaws.com',
        enableHealthChecks: true
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.health).toBeDefined();
      expect(parsed.health.status).toBe('healthy');
      expect(parsed.health.latency).toBeLessThan(100);
    });
  });

  describe('Integration and Compatibility', () => {
    it('should integrate with existing vault configurations', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          hsmId: 'vault-hsm-123',
          status: 'configured',
          vaultIntegration: {
            vaultUrl: 'https://vault.example.com',
            sealType: 'hsm',
            keyShares: 0
          }
        }
      });

      const tool = configureHsmIntegrationTool(toolContext);
      
      const result = await tool.execute({
        hsmName: 'vault-integrated-hsm',
        provider: 'aws-cloudhsm',
        connectionEndpoint: 'hsm-cluster.amazonaws.com',
        integrateWithVault: true,
        vaultUrl: 'https://vault.example.com'
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.integration).toBeDefined();
      expect(parsed.integration.vault).toBeDefined();
      expect(parsed.integration.vault.sealType).toBe('hsm');
    });

    it('should validate HSM provider compatibility', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          hsmId: 'compat-hsm-123',
          status: 'configured',
          compatibility: {
            vault: true,
            pkcs11: true,
            jce: true,
            openssl: true
          }
        }
      });

      const tool = configureHsmIntegrationTool(toolContext);
      
      const result = await tool.execute({
        hsmName: 'compatibility-hsm',
        provider: 'thales-nshield',
        connectionEndpoint: '192.168.1.100:9000',
        validateCompatibility: true
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.compatibility).toBeDefined();
      expect(parsed.compatibility.vault).toBe(true);
      expect(parsed.compatibility.pkcs11).toBe(true);
    });
  });
});