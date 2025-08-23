/**
 * Basic Test Suite for Credential Management Tools
 * Tests core functionality of secure credential storage, rotation, and management tools
 * Covers encryption, auto-rotation, audit logging, migration, generation, and cleanup
 * Security-focused testing with comprehensive validation following established patterns
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { UserError } from 'fastmcp';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';
import { 
  createMockServer, 
  findTool, 
  executeTool, 
  expectProgressReported,
  expectValidZodParse,
  expectInvalidZodParse
} from '../../utils/test-helpers.js';

// Import types and schemas from credential-management.ts
type CredentialType = 'api_key' | 'secret' | 'token' | 'certificate';
type CredentialStatus = 'active' | 'rotating' | 'deprecated' | 'revoked';
type AuditEvent = 'credential_accessed' | 'credential_rotated' | 'credential_expired' | 'unauthorized_access';

// Create mock objects
const mockSecureConfigManager = {
  storeCredential: jest.fn(),
  getCredentialStatus: jest.fn(),
  rotateCredential: jest.fn(),
  getSecurityEvents: jest.fn(),
  migrateToSecureStorage: jest.fn(),
  cleanup: jest.fn(),
};

const mockCredentialManager = {
  listCredentials: jest.fn(),
};

const mockEncryptionService = {
  generateApiKey: jest.fn(),
  generateSecureSecret: jest.fn(),
};

// Mock the actual modules used by credential-management.ts
jest.mock('../../../src/lib/secure-config.js', () => ({
  secureConfigManager: mockSecureConfigManager,
}));

jest.mock('../../../src/utils/encryption.js', () => ({
  credentialManager: mockCredentialManager,
  encryptionService: mockEncryptionService,
}));

describe('Credential Management Tools - Basic Tests', () => {
  let mockServer: any;
  let mockApiClient: MockMakeApiClient;
  let mockTool: jest.MockedFunction<any>;
  let mockLog: any;
  let mockReportProgress: jest.MockedFunction<any>;

  // Test data for credentials
  const testCredential = {
    id: 'cred_123',
    type: 'api_key' as CredentialType,
    service: 'payment-gateway',
    value: 'ak_test_123456789abcdef',
    encrypted: true,
    createdAt: new Date('2024-01-01T10:00:00Z'),
    lastUsed: new Date('2024-01-15T14:30:00Z'),
    userId: 'user_456',
    rotationInfo: {
      status: 'active' as CredentialStatus,
      autoRotate: true,
      interval: 90 * 24 * 60 * 60 * 1000, // 90 days in milliseconds
      expiresAt: new Date('2024-04-01T10:00:00Z'),
    },
  };

  const testSecretCredential = {
    id: 'cred_456',
    type: 'secret' as CredentialType,
    service: 'database',
    value: '[ENCRYPTED]',
    encrypted: true,
    createdAt: new Date('2024-01-05T12:00:00Z'),
    lastUsed: new Date('2024-01-15T16:00:00Z'),
    userId: 'user_789',
    rotationInfo: {
      status: 'rotating' as CredentialStatus,
      autoRotate: true,
      interval: 30 * 24 * 60 * 60 * 1000, // 30 days in milliseconds
      expiresAt: new Date('2024-02-05T12:00:00Z'),
    },
  };

  const testCertificateCredential = {
    id: 'cred_789',
    type: 'certificate' as CredentialType,
    service: 'ssl-provider',
    value: '[ENCRYPTED_CERTIFICATE]',
    encrypted: true,
    createdAt: new Date('2024-01-10T09:00:00Z'),
    lastUsed: new Date('2024-01-14T11:30:00Z'),
    userId: 'user_456',
    rotationInfo: {
      status: 'deprecated' as CredentialStatus,
      autoRotate: false,
      interval: null,
      expiresAt: new Date('2024-12-31T23:59:59Z'),
    },
  };

  const testAuditEvents = [
    {
      id: 'audit_001',
      timestamp: new Date('2024-01-15T14:30:00Z'),
      event: 'credential_accessed' as AuditEvent,
      credentialId: 'cred_123',
      userId: 'user_456',
      success: true,
      metadata: {
        source: 'api',
        userAgent: 'FastMCP/1.0',
        ipAddress: '192.168.1.100',
      },
    },
    {
      id: 'audit_002',
      timestamp: new Date('2024-01-15T16:00:00Z'),
      event: 'credential_rotated' as AuditEvent,
      credentialId: 'cred_456',
      userId: 'user_789',
      success: true,
      metadata: {
        rotationType: 'automatic',
        gracePeriod: 24 * 60 * 60 * 1000, // 24 hours
      },
    },
    {
      id: 'audit_003',
      timestamp: new Date('2024-01-15T17:15:00Z'),
      event: 'unauthorized_access' as AuditEvent,
      credentialId: 'cred_123',
      userId: 'unknown',
      success: false,
      metadata: {
        source: 'api',
        reason: 'invalid_token',
        ipAddress: '10.0.0.1',
      },
    },
  ];

  beforeEach(() => {
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockTool = serverSetup.mockTool;
    mockApiClient = new MockMakeApiClient();
    mockLog = {
      info: jest.fn(),
      error: jest.fn(),
      warn: jest.fn(),
      debug: jest.fn(),
    };
    mockReportProgress = jest.fn();

    // Reset all mocks
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.clearAllMocks();
    mockApiClient.reset();
  });

  describe('Tool Registration and Import Validation', () => {
    it('should import credential management tools module without errors', async () => {
      const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
      expect(addCredentialManagementTools).toBeDefined();
      expect(typeof addCredentialManagementTools).toBe('function');
    });

    it('should register all 8 credential management tools', async () => {
      const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
      addCredentialManagementTools(mockServer, mockApiClient as any);
      
      const expectedTools = [
        'store-credential',
        'get-credential-status',
        'rotate-credential',
        'list-credentials',
        'get-audit-events',
        'migrate-credentials',
        'generate-credential',
        'cleanup-credentials',
      ];

      expectedTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool).toBeDefined();
        expect(tool.name).toBe(toolName);
        expect(tool.description).toBeDefined();
        expect(tool.parameters).toBeDefined();
        expect(tool.execute).toBeDefined();
        expect(typeof tool.execute).toBe('function');
      });

      // Verify we have all 8 tools
      expect(mockTool.mock.calls).toHaveLength(8);
    });

    it('should have proper tool configuration for core credential tools', async () => {
      const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
      addCredentialManagementTools(mockServer, mockApiClient as any);
      
      const coreTools = [
        'store-credential',
        'get-credential-status',
        'rotate-credential',
        'list-credentials',
        'get-audit-events',
      ];
      
      coreTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool.description).toMatch(/(credential|audit|security)/i);
        expect(tool.parameters).toBeDefined();
        expect(typeof tool.execute).toBe('function');
      });
    });

    it('should have proper tool configuration for security and utility tools', async () => {
      const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
      addCredentialManagementTools(mockServer, mockApiClient as any);
      
      const securityTools = [
        'migrate-credentials',
        'generate-credential', 
        'cleanup-credentials',
      ];
      
      securityTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool.description).toMatch(/(migrate|generate|cleanup|clean|credential)/i);
        expect(tool.parameters).toBeDefined();
        expect(typeof tool.execute).toBe('function');
      });
    });
  });

  describe('Credential Storage and Encryption', () => {
    describe('store-credential tool', () => {
      it('should store API key credential with auto-rotation', async () => {
        mockSecureConfigManager.storeCredential.mockResolvedValue('cred_123');

        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'store-credential');
        const result = await tool.execute({
          type: 'api_key',
          service: 'payment-gateway',
          value: 'ak_test_123456789abcdef',
          autoRotate: true,
          rotationIntervalDays: 90,
          userId: 'user_456',
        });
        
        expect(result.credentialId).toBe('cred_123');
        expect(result.message).toContain('stored successfully');
        expect(result.message).toContain('cred_123');
        
        expect(mockSecureConfigManager.storeCredential).toHaveBeenCalledWith(
          'api_key',
          'payment-gateway',
          'ak_test_123456789abcdef',
          {
            autoRotate: true,
            rotationInterval: 90 * 24 * 60 * 60 * 1000, // 90 days in milliseconds
            userId: 'user_456',
          }
        );
      });

      it('should store secret credential without auto-rotation', async () => {
        mockSecureConfigManager.storeCredential.mockResolvedValue('cred_456');

        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'store-credential');
        const result = await tool.execute({
          type: 'secret',
          service: 'database',
          value: 'super_secret_password_123',
          autoRotate: false,
          userId: 'user_789',
        });
        
        expect(result.credentialId).toBe('cred_456');
        expect(result.message).toContain('stored successfully');
        
        expect(mockSecureConfigManager.storeCredential).toHaveBeenCalledWith(
          'secret',
          'database',
          'super_secret_password_123',
          {
            autoRotate: false,
            rotationInterval: undefined,
            userId: 'user_789',
          }
        );
      });

      it('should store certificate credential with custom rotation interval', async () => {
        mockSecureConfigManager.storeCredential.mockResolvedValue('cred_789');

        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'store-credential');
        const result = await tool.execute({
          type: 'certificate',
          service: 'ssl-provider',
          value: '-----BEGIN CERTIFICATE-----\nMIIDXTCCAkW...\n-----END CERTIFICATE-----',
          autoRotate: true,
          rotationIntervalDays: 365,
          userId: 'user_456',
        });
        
        expect(result.credentialId).toBe('cred_789');
        expect(mockSecureConfigManager.storeCredential).toHaveBeenCalledWith(
          'certificate',
          'ssl-provider',
          expect.any(String),
          {
            autoRotate: true,
            rotationInterval: 365 * 24 * 60 * 60 * 1000, // 1 year in milliseconds
            userId: 'user_456',
          }
        );
      });

      it('should handle storage errors gracefully', async () => {
        mockSecureConfigManager.storeCredential.mockRejectedValue(new Error('Encryption service unavailable'));

        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'store-credential');
        const result = await tool.execute({
          type: 'api_key',
          service: 'test-service',
          value: 'test_key',
          userId: 'user_123',
        });
        
        expect(result.credentialId).toBe('');
        expect(result.message).toBe('Encryption service unavailable');
      });

      it('should validate store credential input schema', async () => {
        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'store-credential');
        
        // Test valid inputs
        expectValidZodParse(tool.parameters, {
          type: 'api_key',
          service: 'test-service',
          value: 'test_value',
          autoRotate: true,
          rotationIntervalDays: 30,
          userId: 'user_123',
        });

        expectValidZodParse(tool.parameters, {
          type: 'secret',
          service: 'database',
          value: 'password123',
        });

        // Test invalid inputs
        expectInvalidZodParse(tool.parameters, {
          type: 'invalid_type',
          service: 'test-service',
          value: 'test_value',
        });

        expectInvalidZodParse(tool.parameters, {
          type: 'api_key',
          service: '',
          value: 'test_value',
        });

        expectInvalidZodParse(tool.parameters, {
          type: 'api_key',
          service: 'test-service',
          value: '',
        });

        expectInvalidZodParse(tool.parameters, {
          type: 'api_key',
          service: 'test-service',
          value: 'test_value',
          rotationIntervalDays: 0,
        });

        expectInvalidZodParse(tool.parameters, {
          type: 'api_key',
          service: 'test-service',
          value: 'test_value',
          rotationIntervalDays: 366,
        });
      });
    });
  });

  describe('Credential Status and Metadata', () => {
    describe('get-credential-status tool', () => {
      it('should get credential status with metadata', async () => {
        mockSecureConfigManager.getCredentialStatus.mockReturnValue({
          status: 'active',
          rotationPolicy: {
            enabled: true,
            interval: 90 * 24 * 60 * 60 * 1000, // 90 days in milliseconds
          },
          metadata: {
            lastUsed: new Date('2024-01-15T14:30:00Z'),
          },
          nextRotation: new Date('2024-04-01T10:00:00Z'),
        });

        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-credential-status');
        const result = await tool.execute({
          credentialId: 'cred_123',
          userId: 'user_456',
        });
        
        expect(result.success).toBe(true);
        expect(result.credentialId).toBe('cred_123');
        expect(result.status).toBe('active');
        expect(result.autoRotate).toBe(true);
        expect(result.rotationInterval).toBe(90);
        expect(result.lastRotation).toBe('2024-01-15T14:30:00.000Z');
        expect(result.nextRotation).toBe('2024-04-01T10:00:00.000Z');
        
        expect(mockSecureConfigManager.getCredentialStatus).toHaveBeenCalledWith('cred_123');
      });

      it('should handle credential not found', async () => {
        mockSecureConfigManager.getCredentialStatus.mockReturnValue({
          status: 'not_found',
        });

        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-credential-status');
        const result = await tool.execute({
          credentialId: 'cred_nonexistent',
          userId: 'user_456',
        });
        
        expect(result.success).toBe(false);
        expect(result.error).toBe('Credential cred_nonexistent not found');
      });

      it('should handle status check errors', async () => {
        mockSecureConfigManager.getCredentialStatus.mockImplementation(() => {
          throw new Error('Database connection failed');
        });

        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-credential-status');
        const result = await tool.execute({
          credentialId: 'cred_123',
          userId: 'user_456',
        });
        
        expect(result.success).toBe(false);
        expect(result.error).toBe('Database connection failed');
      });

      it('should validate get credential status input schema', async () => {
        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-credential-status');
        
        // Test valid inputs
        expectValidZodParse(tool.parameters, {
          credentialId: 'cred_123',
          userId: 'user_456',
        });

        expectValidZodParse(tool.parameters, {
          credentialId: 'cred_123',
        });

        // Test invalid inputs
        expectInvalidZodParse(tool.parameters, {
          credentialId: '',
        });
      });
    });
  });

  describe('Credential Rotation and Security', () => {
    describe('rotate-credential tool', () => {
      it('should rotate credential with new value and grace period', async () => {
        mockSecureConfigManager.rotateCredential.mockResolvedValue('cred_123_new');

        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'rotate-credential');
        const result = await tool.execute({
          credentialId: 'cred_123',
          newValue: 'ak_test_new_987654321fedcba',
          gracePeriodHours: 48,
          userId: 'user_456',
        });
        
        expect(result.success).toBe(true);
        expect(result.credentialId).toBe('cred_123_new');
        expect(result.rotationTimestamp).toBeDefined();
        expect(result.message).toContain('rotated successfully');
        expect(result.message).toContain('cred_123_new');
        
        expect(mockSecureConfigManager.rotateCredential).toHaveBeenCalledWith(
          'cred_123',
          {
            newValue: 'ak_test_new_987654321fedcba',
            gracePeriod: 48 * 60 * 60 * 1000, // 48 hours in milliseconds
            userId: 'user_456',
          }
        );
      });

      it('should rotate credential without providing new value (auto-generated)', async () => {
        mockSecureConfigManager.rotateCredential.mockResolvedValue('cred_456_rotated');

        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'rotate-credential');
        const result = await tool.execute({
          credentialId: 'cred_456',
          gracePeriodHours: 24,
          userId: 'user_789',
        });
        
        expect(result.success).toBe(true);
        expect(result.credentialId).toBe('cred_456_rotated');
        
        expect(mockSecureConfigManager.rotateCredential).toHaveBeenCalledWith(
          'cred_456',
          {
            newValue: undefined,
            gracePeriod: 24 * 60 * 60 * 1000, // 24 hours in milliseconds
            userId: 'user_789',
          }
        );
      });

      it('should handle rotation errors gracefully', async () => {
        mockSecureConfigManager.rotateCredential.mockRejectedValue(new Error('Credential is already being rotated'));

        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'rotate-credential');
        const result = await tool.execute({
          credentialId: 'cred_123',
          userId: 'user_456',
        });
        
        expect(result.success).toBe(false);
        expect(result.error).toBe('Credential is already being rotated');
      });

      it('should validate rotate credential input schema', async () => {
        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'rotate-credential');
        
        // Test valid inputs
        expectValidZodParse(tool.parameters, {
          credentialId: 'cred_123',
          newValue: 'new_secret_value',
          gracePeriodHours: 48,
          userId: 'user_456',
        });

        expectValidZodParse(tool.parameters, {
          credentialId: 'cred_123',
        });

        // Test invalid inputs
        expectInvalidZodParse(tool.parameters, {
          credentialId: '',
        });

        expectInvalidZodParse(tool.parameters, {
          credentialId: 'cred_123',
          gracePeriodHours: 0,
        });

        expectInvalidZodParse(tool.parameters, {
          credentialId: 'cred_123',
          gracePeriodHours: 169, // > 168 hours (1 week)
        });
      });
    });
  });

  describe('Credential Listing and Filtering', () => {
    describe('list-credentials tool', () => {
      it('should list all credentials with default filters', async () => {
        mockCredentialManager.listCredentials.mockReturnValue([
          testCredential,
          testSecretCredential,
          testCertificateCredential,
        ]);

        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-credentials');
        const result = await tool.execute({});
        
        expect(result.credentials).toHaveLength(3);
        expect(result.credentials[0].credentialId).toBe('cred_123');
        expect(result.credentials[0].type).toBe('api_key');
        expect(result.credentials[0].service).toBe('payment-gateway');
        expect(result.credentials[0].status).toBe('active');
        expect(result.credentials[0].autoRotate).toBe(true);
        expect(result.credentials[0].lastRotation).toBe('2024-01-15T14:30:00.000Z');
        expect(result.credentials[0].nextRotation).toBe('2024-04-01T10:00:00.000Z');
        
        expect(mockCredentialManager.listCredentials).toHaveBeenCalledWith({
          service: undefined,
          type: undefined,
          status: undefined,
        });
      });

      it('should filter credentials by service', async () => {
        mockCredentialManager.listCredentials.mockReturnValue([testCredential]);

        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-credentials');
        const result = await tool.execute({
          service: 'payment-gateway',
        });
        
        expect(result.credentials).toHaveLength(1);
        expect(result.credentials[0].service).toBe('payment-gateway');
        
        expect(mockCredentialManager.listCredentials).toHaveBeenCalledWith({
          service: 'payment-gateway',
          type: undefined,
          status: undefined,
        });
      });

      it('should filter credentials by type and status', async () => {
        mockCredentialManager.listCredentials.mockReturnValue([testSecretCredential]);

        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-credentials');
        const result = await tool.execute({
          type: 'secret',
          status: 'rotating',
        });
        
        expect(result.credentials).toHaveLength(1);
        expect(result.credentials[0].type).toBe('secret');
        expect(result.credentials[0].status).toBe('rotating');
        
        expect(mockCredentialManager.listCredentials).toHaveBeenCalledWith({
          service: undefined,
          type: 'secret',
          status: 'rotating',
        });
      });

      it('should handle empty credential list', async () => {
        mockCredentialManager.listCredentials.mockReturnValue([]);

        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-credentials');
        const result = await tool.execute({});
        
        expect(result.credentials).toHaveLength(0);
      });

      it('should handle listing errors gracefully', async () => {
        mockCredentialManager.listCredentials.mockImplementation(() => {
          throw new Error('Database query failed');
        });

        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-credentials');
        const result = await tool.execute({});
        
        expect(result.credentials).toHaveLength(0);
      });

      it('should validate list credentials input schema', async () => {
        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-credentials');
        
        // Test valid inputs
        expectValidZodParse(tool.parameters, {});
        expectValidZodParse(tool.parameters, {
          service: 'test-service',
          type: 'api_key',
          status: 'active',
        });

        // Test invalid inputs
        expectInvalidZodParse(tool.parameters, {
          type: 'invalid_type',
        });

        expectInvalidZodParse(tool.parameters, {
          status: 'invalid_status',
        });
      });
    });
  });

  describe('Security Audit and Events', () => {
    describe('get-audit-events tool', () => {
      it('should retrieve audit events with filtering', async () => {
        mockSecureConfigManager.getSecurityEvents.mockReturnValue(testAuditEvents);

        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-audit-events');
        const result = await tool.execute({
          credentialId: 'cred_123',
          userId: 'user_456',
          event: 'credential_accessed',
          startDate: '2024-01-15T00:00:00Z',
          endDate: '2024-01-15T23:59:59Z',
          limit: 50,
        });
        
        expect(result.events).toHaveLength(3);
        expect(result.events[0].timestamp).toBe('2024-01-15T14:30:00.000Z');
        expect(result.events[0].action).toBe('credential_accessed');
        expect(result.events[0].credentialId).toBe('cred_123');
        expect(result.events[0].userId).toBe('user_456');
        expect(result.events[0].success).toBe(true);
        expect(result.events[0].details).toEqual({
          source: 'api',
          userAgent: 'FastMCP/1.0',
          ipAddress: '192.168.1.100',
        });
        
        expect(mockSecureConfigManager.getSecurityEvents).toHaveBeenCalledWith({
          credentialId: 'cred_123',
          userId: 'user_456',
          event: 'credential_accessed',
          startDate: new Date('2024-01-15T00:00:00Z'),
          endDate: new Date('2024-01-15T23:59:59Z'),
          limit: 50,
        });
      });

      it('should retrieve all audit events without filtering', async () => {
        mockSecureConfigManager.getSecurityEvents.mockReturnValue(testAuditEvents);

        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-audit-events');
        const result = await tool.execute({
          limit: 100,
        });
        
        expect(result.events).toHaveLength(3);
        
        expect(mockSecureConfigManager.getSecurityEvents).toHaveBeenCalledWith({
          credentialId: undefined,
          userId: undefined,
          event: undefined,
          startDate: undefined,
          endDate: undefined,
          limit: 100,
        });
      });

      it('should handle unauthorized access events specifically', async () => {
        const unauthorizedEvents = testAuditEvents.filter(event => 
          event.event === 'unauthorized_access'
        );
        mockSecureConfigManager.getSecurityEvents.mockReturnValue(unauthorizedEvents);

        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-audit-events');
        const result = await tool.execute({
          event: 'unauthorized_access',
        });
        
        expect(result.events).toHaveLength(1);
        expect(result.events[0].action).toBe('unauthorized_access');
        expect(result.events[0].success).toBe(false);
        expect(result.events[0].details.reason).toBe('invalid_token');
      });

      it('should handle audit query errors gracefully', async () => {
        mockSecureConfigManager.getSecurityEvents.mockImplementation(() => {
          throw new Error('Audit log database unavailable');
        });

        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-audit-events');
        const result = await tool.execute({});
        
        expect(result.events).toHaveLength(0);
      });

      it('should validate audit query input schema', async () => {
        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-audit-events');
        
        // Test valid inputs
        expectValidZodParse(tool.parameters, {});
        expectValidZodParse(tool.parameters, {
          credentialId: 'cred_123',
          userId: 'user_456',
          event: 'credential_accessed',
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z',
          limit: 50,
        });

        // Test invalid inputs
        expectInvalidZodParse(tool.parameters, {
          event: 'invalid_event',
        });

        expectInvalidZodParse(tool.parameters, {
          limit: 0,
        });

        expectInvalidZodParse(tool.parameters, {
          limit: 1001,
        });
      });
    });
  });

  describe('Credential Migration and Utilities', () => {
    describe('migrate-credentials tool', () => {
      it('should migrate credentials to secure storage successfully', async () => {
        mockSecureConfigManager.migrateToSecureStorage.mockResolvedValue({
          migrated: ['cred_001', 'cred_002', 'cred_003'],
          errors: [],
        });

        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'migrate-credentials');
        const result = await tool.execute({
          userId: 'user_456',
        });
        
        expect(result.success).toBe(true);
        expect(result.migratedCount).toBe(3);
        expect(result.failedCount).toBe(0);
        expect(result.errors).toHaveLength(0);
        expect(result.message).toContain('3 credentials migrated successfully');
        
        expect(mockSecureConfigManager.migrateToSecureStorage).toHaveBeenCalledWith('user_456');
      });

      it('should handle partial migration with errors', async () => {
        mockSecureConfigManager.migrateToSecureStorage.mockResolvedValue({
          migrated: ['cred_001', 'cred_002'],
          errors: [
            { credential: 'cred_003', error: 'Invalid format' },
            { credential: 'cred_004', error: 'Encryption failed' },
          ],
        });

        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'migrate-credentials');
        const result = await tool.execute({
          userId: 'user_456',
        });
        
        expect(result.success).toBe(true);
        expect(result.migratedCount).toBe(2);
        expect(result.failedCount).toBe(2);
        expect(result.errors).toHaveLength(2);
        expect(result.errors[0]).toBe('cred_003: Invalid format');
        expect(result.errors[1]).toBe('cred_004: Encryption failed');
        expect(result.message).toContain('2 credentials migrated successfully');
      });

      it('should handle migration system failure', async () => {
        mockSecureConfigManager.migrateToSecureStorage.mockRejectedValue(new Error('Migration service temporarily unavailable'));

        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'migrate-credentials');
        const result = await tool.execute({
          userId: 'user_456',
        });
        
        expect(result.success).toBe(false);
        expect(result.migratedCount).toBe(0);
        expect(result.failedCount).toBe(0);
        expect(result.errors).toContain('Migration service temporarily unavailable');
        expect(result.message).toBe('Migration failed');
      });

      it('should validate migrate credentials input schema', async () => {
        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'migrate-credentials');
        
        // Test valid inputs
        expectValidZodParse(tool.parameters, {});
        expectValidZodParse(tool.parameters, {
          userId: 'user_456',
        });
      });
    });

    describe('generate-credential tool', () => {
      it('should generate API key with prefix and custom length', async () => {
        // Reset and setup mocks
        jest.clearAllMocks();
        mockEncryptionService.generateApiKey.mockReturnValue('sk_test_1234567890abcdef1234567890abcdef');

        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'generate-credential');
        const result = await tool.execute({
          type: 'api_key',
          prefix: 'sk_test',
          length: 32,
        });
        
        expect(result.success).toBe(true);
        expect(result.type).toBe('api_key');
        expect(result.value).toBe('sk_test_1234567890abcdef1234567890abcdef');
        expect(result.length).toBe(result.value.length); // actual length of generated value
        
        expect(mockEncryptionService.generateApiKey).toHaveBeenCalledWith('sk_test', 32);
      });

      it('should generate secret with default parameters', async () => {
        // Reset and setup mocks
        jest.clearAllMocks();
        mockEncryptionService.generateSecureSecret.mockReturnValue('abcd1234567890efghijklmnopqrstuvwx');

        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'generate-credential');
        const result = await tool.execute({
          type: 'secret',
        });
        
        expect(result.success).toBe(true);
        expect(result.type).toBe('secret');
        expect(result.value).toBe('abcd1234567890efghijklmnopqrstuvwx');
        expect(result.length).toBe(result.value.length); // actual length of generated value
        
        expect(mockEncryptionService.generateSecureSecret).toHaveBeenCalledWith(32);
      });

      it('should handle generation errors gracefully', async () => {
        mockEncryptionService.generateApiKey.mockImplementation(() => {
          throw new Error('Random number generator failed');
        });

        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'generate-credential');
        const result = await tool.execute({
          type: 'api_key',
        });
        
        expect(result.success).toBe(false);
        expect(result.type).toBe('api_key');
        expect(result.length).toBe(0);
        expect(result.error).toBe('Random number generator failed');
      });

      it('should validate generate credential input schema', async () => {
        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'generate-credential');
        
        // Test valid inputs - Note: we need to test the actual schema from the tool
        expectValidZodParse(tool.parameters, {
          type: 'api_key',
          prefix: 'test',
          length: 32,
        });

        expectValidZodParse(tool.parameters, {
          type: 'secret',
        });

        // Test invalid inputs
        expectInvalidZodParse(tool.parameters, {
          type: 'invalid_type',
        });

        expectInvalidZodParse(tool.parameters, {
          type: 'api_key',
          length: 15, // < 16
        });

        expectInvalidZodParse(tool.parameters, {
          type: 'api_key',
          length: 129, // > 128
        });
      });
    });

    describe('cleanup-credentials tool', () => {
      it('should perform cleanup and return health status', async () => {
        mockSecureConfigManager.cleanup.mockReturnValue({
          expiredCredentials: 5,
          oldEvents: 1000,
        });

        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'cleanup-credentials');
        const result = await tool.execute({});
        
        expect(result.status).toBe('healthy');
        expect(result.totalCredentials).toBe(100);
        expect(result.activeCredentials).toBe(95);
        expect(result.rotationsPending).toBe(5);
        expect(result.encryptionStrength).toBe('AES-256');
        expect(result.storageType).toBe('secure');
        expect(result.lastAudit).toBeDefined();
        
        expect(mockSecureConfigManager.cleanup).toHaveBeenCalled();
      });

      it('should handle cleanup errors gracefully', async () => {
        mockSecureConfigManager.cleanup.mockImplementation(() => {
          throw new Error('Cleanup process failed');
        });

        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'cleanup-credentials');
        const result = await tool.execute({});
        
        expect(result.status).toBe('error');
        expect(result.totalCredentials).toBe(0);
        expect(result.activeCredentials).toBe(0);
        expect(result.rotationsPending).toBe(0);
        expect(result.encryptionStrength).toBe('unknown');
        expect(result.storageType).toBe('unknown');
      });

      it('should validate cleanup input schema (empty object)', async () => {
        const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
        addCredentialManagementTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'cleanup-credentials');
        
        // Test valid input (empty object)
        expectValidZodParse(tool.parameters, {});
      });
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle concurrent rotation conflicts', async () => {
      mockSecureConfigManager.rotateCredential.mockRejectedValue(new Error('Credential rotation already in progress'));

      const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
      addCredentialManagementTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'rotate-credential');
      const result = await tool.execute({
        credentialId: 'cred_123',
        userId: 'user_456',
      });
      
      expect(result.success).toBe(false);
      expect(result.error).toBe('Credential rotation already in progress');
    });

    it('should handle encryption service failures', async () => {
      mockSecureConfigManager.storeCredential.mockRejectedValue(new Error('Encryption key not available'));

      const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
      addCredentialManagementTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'store-credential');
      const result = await tool.execute({
        type: 'api_key',
        service: 'test-service',
        value: 'test_key',
      });
      
      expect(result.credentialId).toBe('');
      expect(result.message).toBe('Encryption key not available');
    });

    it('should handle invalid credential access attempts', async () => {
      mockSecureConfigManager.getCredentialStatus.mockReturnValue({
        status: 'revoked',
      });

      const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
      addCredentialManagementTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-credential-status');
      const result = await tool.execute({
        credentialId: 'cred_revoked',
        userId: 'user_456',
      });
      
      expect(result.success).toBe(true);
      expect(result.status).toBe('revoked');
    });

    it('should handle storage corruption scenarios', async () => {
      mockCredentialManager.listCredentials.mockImplementation(() => {
        throw new Error('Storage integrity check failed');
      });

      const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
      addCredentialManagementTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-credentials');
      const result = await tool.execute({});
      
      expect(result.credentials).toHaveLength(0);
    });

    it('should handle audit log overflow scenarios', async () => {
      const largeAuditEvents = Array(1000).fill(0).map((_, i) => ({
        ...testAuditEvents[0],
        id: `audit_${i.toString().padStart(3, '0')}`,
        timestamp: new Date(Date.now() - i * 1000),
      }));
      
      mockSecureConfigManager.getSecurityEvents.mockReturnValue(largeAuditEvents.slice(0, 100)); // Limited by tool

      const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
      addCredentialManagementTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-audit-events');
      const result = await tool.execute({
        limit: 100,
      });
      
      expect(result.events).toHaveLength(100);
    });
  });

  describe('Integration and Security Workflows', () => {
    it('should handle complete credential lifecycle', async () => {
      const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
      addCredentialManagementTools(mockServer, mockApiClient as any);

      // 1. Store credential
      mockSecureConfigManager.storeCredential.mockResolvedValue('cred_lifecycle');
      const storeTool = findTool(mockTool, 'store-credential');
      await storeTool.handler({
        type: 'api_key',
        service: 'integration-test',
        value: 'test_key_lifecycle',
        autoRotate: true,
        rotationIntervalDays: 30,
        userId: 'user_lifecycle',
      });

      // 2. Get status
      mockSecureConfigManager.getCredentialStatus.mockReturnValue({
        status: 'active',
        rotationPolicy: { enabled: true, interval: 30 * 24 * 60 * 60 * 1000 },
        metadata: { lastUsed: new Date() },
        nextRotation: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      });
      const statusTool = findTool(mockTool, 'get-credential-status');
      await statusTool.handler({ credentialId: 'cred_lifecycle' });

      // 3. Rotate credential
      mockSecureConfigManager.rotateCredential.mockResolvedValue('cred_lifecycle_rotated');
      const rotateTool = findTool(mockTool, 'rotate-credential');
      await rotateTool.handler({
        credentialId: 'cred_lifecycle',
        gracePeriodHours: 24,
        userId: 'user_lifecycle',
      });

      // 4. Check audit events
      mockSecureConfigManager.getSecurityEvents.mockReturnValue([
        {
          timestamp: new Date(),
          event: 'credential_rotated',
          credentialId: 'cred_lifecycle',
          userId: 'user_lifecycle',
          success: true,
          metadata: {},
        },
      ]);
      const auditTool = findTool(mockTool, 'get-audit-events');
      await auditTool.handler({ credentialId: 'cred_lifecycle' });

      // Verify all operations were called
      expect(mockSecureConfigManager.storeCredential).toHaveBeenCalledTimes(1);
      expect(mockSecureConfigManager.getCredentialStatus).toHaveBeenCalledTimes(1);
      expect(mockSecureConfigManager.rotateCredential).toHaveBeenCalledTimes(1);
      expect(mockSecureConfigManager.getSecurityEvents).toHaveBeenCalledTimes(1);
    });

    it('should handle security incident response workflow', async () => {
      const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
      addCredentialManagementTools(mockServer, mockApiClient as any);

      // 1. Detect unauthorized access in audit events
      mockSecureConfigManager.getSecurityEvents.mockReturnValue([
        {
          timestamp: new Date(),
          event: 'unauthorized_access',
          credentialId: 'cred_compromised',
          userId: 'unknown',
          success: false,
          metadata: { reason: 'invalid_token', ipAddress: '10.0.0.1' },
        },
      ]);
      
      const auditTool = findTool(mockTool, 'get-audit-events');
      const auditResult = await auditTool.handler({
        event: 'unauthorized_access',
        credentialId: 'cred_compromised',
      });
      
      expect(auditResult.events[0].success).toBe(false);
      expect(auditResult.events[0].details.reason).toBe('invalid_token');

      // 2. Immediately rotate compromised credential
      mockSecureConfigManager.rotateCredential.mockResolvedValue('cred_compromised_secure');
      const rotateTool = findTool(mockTool, 'rotate-credential');
      const rotateResult = await rotateTool.handler({
        credentialId: 'cred_compromised',
        gracePeriodHours: 1, // Minimal grace period for security
        userId: 'security_admin',
      });
      
      expect(rotateResult.success).toBe(true);
      expect(rotateResult.credentialId).toBe('cred_compromised_secure');
    });

    it('should handle bulk credential migration scenario', async () => {
      const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
      addCredentialManagementTools(mockServer, mockApiClient as any);

      // 1. List current credentials to see what needs migration
      mockCredentialManager.listCredentials.mockReturnValue([
        { ...testCredential, encrypted: false },
        { ...testSecretCredential, encrypted: false },
      ]);
      
      const listTool = findTool(mockTool, 'list-credentials');
      const listResult = await listTool.handler({});
      expect(listResult.credentials).toHaveLength(2);

      // 2. Migrate unencrypted credentials
      mockSecureConfigManager.migrateToSecureStorage.mockResolvedValue({
        migrated: ['cred_123', 'cred_456'],
        errors: [],
      });
      
      const migrateTool = findTool(mockTool, 'migrate-credentials');
      const migrateResult = await migrateTool.handler({
        userId: 'migration_admin',
      });
      
      expect(migrateResult.success).toBe(true);
      expect(migrateResult.migratedCount).toBe(2);
      expect(migrateResult.failedCount).toBe(0);

      // 3. Clean up after migration
      mockSecureConfigManager.cleanup.mockReturnValue({
        expiredCredentials: 0,
        oldEvents: 500,
      });
      
      const cleanupTool = findTool(mockTool, 'cleanup-credentials');
      const cleanupResult = await cleanupTool.handler({});
      expect(cleanupResult.status).toBe('healthy');
    });
  });
});