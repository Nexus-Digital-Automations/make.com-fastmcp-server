/**
 * @fileoverview Comprehensive test suite for Vault Configuration management
 * Tests vault server setup, configuration validation, and integration scenarios
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { configureVaultServerTool } from '../../../../src/tools/enterprise-secrets/tools/configure-vault-server.js';
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

describe('Vault Configuration Management - Comprehensive Tests', () => {
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
      const tool = configureVaultServerTool(toolContext);
      
      expect(tool.name).toBe('configure-vault-server');
      expect(tool.description).toContain('vault server');
      expect(tool.parameters).toBeDefined();
      expect(tool.annotations).toBeDefined();
      expect(typeof tool.execute).toBe('function');
    });

    it('should have proper tool annotations', () => {
      const tool = configureVaultServerTool(toolContext);
      
      expect(tool.annotations.title).toBeDefined();
      expect(tool.annotations.readOnlyHint).toBe(false);
      expect(tool.annotations.destructiveHint).toBe(true);
      expect(tool.annotations.openWorldHint).toBe(false);
    });
  });

  describe('Parameter Validation', () => {
    it('should validate required vault URL', async () => {
      const tool = configureVaultServerTool(toolContext);
      
      await expect(tool.execute({
        serverName: 'test-vault'
        // Missing vaultUrl
      }, { log: mockLogger })).rejects.toThrow();
    });

    it('should validate vault URL format', async () => {
      const tool = configureVaultServerTool(toolContext);
      
      await expect(tool.execute({
        serverName: 'test-vault',
        vaultUrl: 'invalid-url'
      }, { log: mockLogger })).rejects.toThrow();
    });

    it('should accept valid configuration parameters', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          serverId: 'vault-123',
          status: 'configured',
          endpoint: 'https://vault.example.com'
        }
      });

      const tool = configureVaultServerTool(toolContext);
      
      const result = await tool.execute({
        serverName: 'test-vault',
        vaultUrl: 'https://vault.example.com',
        authMethod: 'token',
        sealType: 'shamir',
        enableAudit: true,
        highAvailability: false
      }, { log: mockLogger });

      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
    });

    it('should validate authentication method options', async () => {
      const tool = configureVaultServerTool(toolContext);
      
      await expect(tool.execute({
        serverName: 'test-vault',
        vaultUrl: 'https://vault.example.com',
        authMethod: 'invalid-method' as any
      }, { log: mockLogger })).rejects.toThrow();
    });

    it('should validate seal type options', async () => {
      const tool = configureVaultServerTool(toolContext);
      
      await expect(tool.execute({
        serverName: 'test-vault',
        vaultUrl: 'https://vault.example.com',
        authMethod: 'token',
        sealType: 'invalid-seal' as any
      }, { log: mockLogger })).rejects.toThrow();
    });
  });

  describe('Vault Server Configuration', () => {
    beforeEach(() => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          serverId: 'vault-server-123',
          status: 'configured',
          endpoint: 'https://vault.example.com',
          version: '1.15.2',
          sealed: false
        }
      });
    });

    it('should configure basic vault server', async () => {
      const tool = configureVaultServerTool(toolContext);
      
      const result = await tool.execute({
        serverName: 'production-vault',
        vaultUrl: 'https://vault.example.com',
        authMethod: 'token',
        sealType: 'shamir'
      }, { log: mockLogger });

      expect(mockApiClient.post).toHaveBeenCalledWith(
        '/enterprise-secrets/vault/configure',
        expect.objectContaining({
          serverName: 'production-vault',
          vaultUrl: 'https://vault.example.com',
          authMethod: 'token',
          sealType: 'shamir'
        })
      );

      const parsed = JSON.parse(result);
      expect(parsed.server).toBeDefined();
      expect(parsed.server.serverId).toBe('vault-server-123');
      expect(parsed.message).toContain('successfully configured');
    });

    it('should configure vault with high availability', async () => {
      const tool = configureVaultServerTool(toolContext);
      
      await tool.execute({
        serverName: 'ha-vault',
        vaultUrl: 'https://vault-cluster.example.com',
        authMethod: 'ldap',
        sealType: 'awskms',
        highAvailability: true,
        enableAudit: true
      }, { log: mockLogger });

      expect(mockApiClient.post).toHaveBeenCalledWith(
        '/enterprise-secrets/vault/configure',
        expect.objectContaining({
          highAvailability: true,
          enableAudit: true,
          sealType: 'awskms'
        })
      );
    });

    it('should configure vault with custom storage backend', async () => {
      const tool = configureVaultServerTool(toolContext);
      
      await tool.execute({
        serverName: 'custom-vault',
        vaultUrl: 'https://vault.example.com',
        authMethod: 'token',
        sealType: 'transit',
        storageBackend: 'consul',
        enableAudit: true
      }, { log: mockLogger });

      expect(mockApiClient.post).toHaveBeenCalledWith(
        '/enterprise-secrets/vault/configure',
        expect.objectContaining({
          storageBackend: 'consul'
        })
      );
    });
  });

  describe('Error Handling', () => {
    it('should handle vault server unreachable error', async () => {
      mockApiClient.post.mockRejectedValue(new Error('Connection refused'));

      const tool = configureVaultServerTool(toolContext);
      
      await expect(tool.execute({
        serverName: 'unreachable-vault',
        vaultUrl: 'https://unreachable.example.com',
        authMethod: 'token',
        sealType: 'shamir'
      }, { log: mockLogger })).rejects.toThrow(UserError);

      expect(mockLogger.error).toHaveBeenCalledWith(
        expect.stringContaining('Failed to configure vault server'),
        expect.any(Object)
      );
    });

    it('should handle authentication failures', async () => {
      mockApiClient.post.mockResolvedValue({
        success: false,
        error: { message: 'Authentication failed', code: 'AUTH_ERROR' }
      });

      const tool = configureVaultServerTool(toolContext);
      
      await expect(tool.execute({
        serverName: 'auth-fail-vault',
        vaultUrl: 'https://vault.example.com',
        authMethod: 'token',
        sealType: 'shamir'
      }, { log: mockLogger })).rejects.toThrow(UserError);
    });

    it('should handle vault already configured scenarios', async () => {
      mockApiClient.post.mockResolvedValue({
        success: false,
        error: { message: 'Vault server already configured', code: 'ALREADY_CONFIGURED' }
      });

      const tool = configureVaultServerTool(toolContext);
      
      await expect(tool.execute({
        serverName: 'existing-vault',
        vaultUrl: 'https://vault.example.com',
        authMethod: 'token',
        sealType: 'shamir'
      }, { log: mockLogger })).rejects.toThrow(UserError);
    });

    it('should handle invalid seal configuration', async () => {
      mockApiClient.post.mockResolvedValue({
        success: false,
        error: { message: 'Invalid seal configuration', code: 'SEAL_CONFIG_ERROR' }
      });

      const tool = configureVaultServerTool(toolContext);
      
      await expect(tool.execute({
        serverName: 'bad-seal-vault',
        vaultUrl: 'https://vault.example.com',
        authMethod: 'token',
        sealType: 'shamir'
      }, { log: mockLogger })).rejects.toThrow(UserError);
    });
  });

  describe('Security Validation', () => {
    it('should enforce HTTPS for vault URLs', async () => {
      const tool = configureVaultServerTool(toolContext);
      
      await expect(tool.execute({
        serverName: 'insecure-vault',
        vaultUrl: 'http://vault.example.com', // HTTP not HTTPS
        authMethod: 'token',
        sealType: 'shamir'
      }, { log: mockLogger })).rejects.toThrow();
    });

    it('should validate secure authentication methods', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: { serverId: 'vault-123', status: 'configured' }
      });

      const tool = configureVaultServerTool(toolContext);
      
      // Test each secure auth method
      const secureMethods = ['token', 'ldap', 'okta', 'aws', 'gcp', 'azure'];
      
      for (const method of secureMethods) {
        await expect(tool.execute({
          serverName: `vault-${method}`,
          vaultUrl: 'https://vault.example.com',
          authMethod: method as any,
          sealType: 'shamir'
        }, { log: mockLogger })).resolves.toBeDefined();
      }
    });

    it('should enforce audit logging for production configurations', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: { serverId: 'vault-123', status: 'configured' }
      });

      const tool = configureVaultServerTool(toolContext);
      
      const result = await tool.execute({
        serverName: 'production-vault',
        vaultUrl: 'https://vault.example.com',
        authMethod: 'ldap',
        sealType: 'awskms',
        enableAudit: true,
        highAvailability: true
      }, { log: mockLogger });

      expect(mockApiClient.post).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          enableAudit: true
        })
      );

      const parsed = JSON.parse(result);
      expect(parsed.security).toBeDefined();
      expect(parsed.security.auditEnabled).toBe(true);
    });
  });

  describe('Integration Scenarios', () => {
    it('should handle vault configuration with existing policies', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          serverId: 'vault-123',
          status: 'configured',
          policies: ['default', 'admin', 'read-only']
        }
      });

      const tool = configureVaultServerTool(toolContext);
      
      const result = await tool.execute({
        serverName: 'policy-vault',
        vaultUrl: 'https://vault.example.com',
        authMethod: 'token',
        sealType: 'shamir',
        enableAudit: true
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.server.policies).toEqual(['default', 'admin', 'read-only']);
    });

    it('should configure vault for development environment', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          serverId: 'dev-vault-123',
          status: 'configured',
          environment: 'development'
        }
      });

      const tool = configureVaultServerTool(toolContext);
      
      await tool.execute({
        serverName: 'dev-vault',
        vaultUrl: 'https://vault-dev.example.com',
        authMethod: 'token',
        sealType: 'shamir',
        enableAudit: false, // Less strict for dev
        highAvailability: false
      }, { log: mockLogger });

      expect(mockApiClient.post).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          serverName: 'dev-vault',
          enableAudit: false,
          highAvailability: false
        })
      );
    });

    it('should validate vault health after configuration', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          serverId: 'vault-123',
          status: 'configured',
          health: {
            sealed: false,
            standby: false,
            initialized: true,
            version: '1.15.2'
          }
        }
      });

      const tool = configureVaultServerTool(toolContext);
      
      const result = await tool.execute({
        serverName: 'health-vault',
        vaultUrl: 'https://vault.example.com',
        authMethod: 'token',
        sealType: 'shamir'
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.health).toBeDefined();
      expect(parsed.health.sealed).toBe(false);
      expect(parsed.health.initialized).toBe(true);
    });
  });

  describe('Performance and Reliability', () => {
    it('should handle concurrent vault configurations', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: { serverId: 'vault-123', status: 'configured' }
      });

      const tool = configureVaultServerTool(toolContext);
      
      const configurations = Array(5).fill(0).map(async (_, i) => {
        return tool.execute({
          serverName: `concurrent-vault-${i}`,
          vaultUrl: `https://vault-${i}.example.com`,
          authMethod: 'token',
          sealType: 'shamir'
        }, { log: mockLogger });
      });

      const results = await Promise.allSettled(configurations);
      const successful = results.filter(r => r.status === 'fulfilled');
      
      expect(successful).toHaveLength(5);
    });

    it('should handle timeout scenarios gracefully', async () => {
      mockApiClient.post.mockImplementation(() => 
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Request timeout')), 100)
        )
      );

      const tool = configureVaultServerTool(toolContext);
      
      await expect(tool.execute({
        serverName: 'timeout-vault',
        vaultUrl: 'https://slow-vault.example.com',
        authMethod: 'token',
        sealType: 'shamir'
      }, { log: mockLogger })).rejects.toThrow();

      expect(mockLogger.error).toHaveBeenCalled();
    });
  });

  describe('Configuration Validation', () => {
    it('should validate storage backend compatibility', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: { serverId: 'vault-123', status: 'configured' }
      });

      const tool = configureVaultServerTool(toolContext);
      
      // Valid combinations
      const validCombinations = [
        { sealType: 'shamir', storageBackend: 'file' },
        { sealType: 'awskms', storageBackend: 's3' },
        { sealType: 'gcpkms', storageBackend: 'gcs' },
        { sealType: 'azurekeyvault', storageBackend: 'azure' }
      ];

      for (const combo of validCombinations) {
        await expect(tool.execute({
          serverName: 'compat-vault',
          vaultUrl: 'https://vault.example.com',
          authMethod: 'token',
          ...combo
        }, { log: mockLogger })).resolves.toBeDefined();
      }
    });

    it('should validate high availability configuration requirements', async () => {
      const tool = configureVaultServerTool(toolContext);
      
      // HA requires specific storage backends
      await expect(tool.execute({
        serverName: 'ha-vault',
        vaultUrl: 'https://vault.example.com',
        authMethod: 'token',
        sealType: 'shamir',
        highAvailability: true,
        storageBackend: 'file' // Invalid for HA
      }, { log: mockLogger })).rejects.toThrow();
    });
  });
});