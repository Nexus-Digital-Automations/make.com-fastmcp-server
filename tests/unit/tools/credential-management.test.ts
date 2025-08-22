/**
 * Comprehensive Test Suite for Credential Management Tools - CORRECTED VERSION
 * Tests core functionality of credential management tools using proven patterns
 * Based on successful patterns from enterprise-secrets-basic.test.ts
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { createMockServer, expectValidZodParse, expectInvalidZodParse } from '../../utils/test-helpers.js';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';

// ✅ CORRECTED: Mock the encryption service directly to prevent logger issues
jest.mock('../../../src/utils/encryption.js', () => ({
  EncryptionService: jest.fn().mockImplementation(() => ({
    encrypt: jest.fn().mockResolvedValue({
      data: 'encrypted_data',
      iv: 'mock_iv',
      salt: 'mock_salt',
      algorithm: 'aes-256-gcm',
      keyLength: 32
    }),
    decrypt: jest.fn().mockResolvedValue('decrypted_data'),
    generateSecureSecret: jest.fn().mockReturnValue('mock_secret'),
    generateApiKey: jest.fn().mockReturnValue('mcp_123_mock_key'),
    hash: jest.fn().mockReturnValue('mock_hash'),
    verifyHash: jest.fn().mockReturnValue(true),
    generateToken: jest.fn().mockReturnValue('mock_token'),
  })),
  CredentialManager: jest.fn().mockImplementation(() => ({
    storeCredential: jest.fn().mockResolvedValue('credential_123'),
    retrieveCredential: jest.fn().mockResolvedValue('stored_credential'),
    rotateCredential: jest.fn().mockResolvedValue('new_credential_456'),
    revokeCredential: jest.fn().mockResolvedValue(undefined),
    getCredentialMetadata: jest.fn().mockReturnValue({
      id: 'credential_123',
      type: 'api_key',
      service: 'test-service',
      createdAt: new Date(),
      encrypted: true,
      rotationInfo: {
        keyId: 'key_123',
        createdAt: new Date(),
        status: 'active'
      }
    }),
    listCredentials: jest.fn().mockReturnValue([]),
    getAuditLog: jest.fn().mockReturnValue([]),
    cleanupExpiredCredentials: jest.fn().mockReturnValue(0),
  })),
  encryptionService: {
    encrypt: jest.fn().mockResolvedValue({
      data: 'encrypted_data',
      iv: 'mock_iv',
      salt: 'mock_salt',
      algorithm: 'aes-256-gcm',
      keyLength: 32
    }),
    decrypt: jest.fn().mockResolvedValue('decrypted_data'),
    generateSecureSecret: jest.fn().mockReturnValue('mock_secret'),
    generateApiKey: jest.fn().mockReturnValue('mcp_123_mock_key'),
    hash: jest.fn().mockReturnValue('mock_hash'),
    verifyHash: jest.fn().mockReturnValue(true),
    generateToken: jest.fn().mockReturnValue('mock_token'),
  },
  credentialManager: {
    storeCredential: jest.fn().mockResolvedValue('credential_123'),
    retrieveCredential: jest.fn().mockResolvedValue('stored_credential'),
    rotateCredential: jest.fn().mockResolvedValue('new_credential_456'),
    revokeCredential: jest.fn().mockResolvedValue(undefined),
    getCredentialMetadata: jest.fn().mockReturnValue({
      id: 'credential_123',
      type: 'api_key',
      service: 'test-service',
      createdAt: new Date(),
      encrypted: true,
      rotationInfo: {
        keyId: 'key_123',
        createdAt: new Date(),
        status: 'active'
      }
    }),
    listCredentials: jest.fn().mockReturnValue([]),
    getAuditLog: jest.fn().mockReturnValue([]),
    cleanupExpiredCredentials: jest.fn().mockReturnValue(0),
  },
  CryptographicError: class CryptographicError extends Error {
    constructor(message: string, public operation: string) {
      super(message);
      this.name = 'CryptographicError';
    }
  }
}));

// ✅ Also mock secure-config to prevent logger issues there
jest.mock('../../../src/lib/secure-config.js', () => ({
  SecureConfigManager: jest.fn().mockImplementation(() => ({
    storeCredential: jest.fn().mockResolvedValue('credential_123'),
    getCredential: jest.fn().mockResolvedValue('stored_credential'),
    getSecureMakeConfig: jest.fn().mockResolvedValue({
      baseUrl: 'https://api.make.com',
      apiKey: 'mock_api_key'
    }),
    rotateCredential: jest.fn().mockResolvedValue('new_credential_456'),
    getCredentialStatus: jest.fn().mockReturnValue({
      status: 'healthy',
      metadata: { id: 'credential_123', type: 'api_key' }
    }),
    getSecurityEvents: jest.fn().mockReturnValue([]),
    cleanup: jest.fn().mockReturnValue({ expiredCredentials: 0, oldEvents: 0 }),
    shutdown: jest.fn(),
  })),
  secureConfigManager: {
    getInstance: jest.fn().mockReturnValue({
      storeCredential: jest.fn().mockResolvedValue('credential_123'),
      getCredential: jest.fn().mockResolvedValue('stored_credential'),
      getSecureMakeConfig: jest.fn().mockResolvedValue({
        baseUrl: 'https://api.make.com',
        apiKey: 'mock_api_key'
      }),
      rotateCredential: jest.fn().mockResolvedValue('new_credential_456'),
      getCredentialStatus: jest.fn().mockReturnValue({
        status: 'healthy',
        metadata: { id: 'credential_123', type: 'api_key' }
      }),
      getSecurityEvents: jest.fn().mockReturnValue([]),
      cleanup: jest.fn().mockReturnValue({ expiredCredentials: 0, oldEvents: 0 }),
      shutdown: jest.fn(),
    }),
    storeCredential: jest.fn().mockResolvedValue('credential_123'),
    getCredential: jest.fn().mockResolvedValue('stored_credential'),
    getSecureMakeConfig: jest.fn().mockResolvedValue({
      baseUrl: 'https://api.make.com',
      apiKey: 'mock_api_key'
    }),
    rotateCredential: jest.fn().mockResolvedValue('new_credential_456'),
    getCredentialStatus: jest.fn().mockReturnValue({
      status: 'healthy',
      metadata: { id: 'credential_123', type: 'api_key' }
    }),
    getSecurityEvents: jest.fn().mockReturnValue([]),
    cleanup: jest.fn().mockReturnValue({ expiredCredentials: 0, oldEvents: 0 }),
    shutdown: jest.fn(),
  },
  default: {
    getInstance: jest.fn().mockReturnValue({
      storeCredential: jest.fn().mockResolvedValue('credential_123'),
      getCredential: jest.fn().mockResolvedValue('stored_credential'),
    }),
    storeCredential: jest.fn().mockResolvedValue('credential_123'),
    getCredential: jest.fn().mockResolvedValue('stored_credential'),
  }
}));

// Advanced testing utilities
class ChaosMonkey {
  constructor(private config: { failureRate: number; latencyMs: number; scenarios: string[] }) {}

  async introduce(scenario: string): Promise<void> {
    if (Math.random() < this.config.failureRate && this.config.scenarios.includes(scenario)) {
      switch (scenario) {
        case 'latency':
          await new Promise((resolve) => setTimeout(resolve, this.config.latencyMs));
          break;
        case 'error':
          throw new Error(`Chaos Monkey induced ${scenario} failure`);
        case 'timeout':
          await new Promise((resolve) => setTimeout(resolve, this.config.latencyMs * 2));
          break;
      }
    }
  }
}

// Testing data generators
const testPasswords = {
  weak: ['123456', 'password', 'qwerty', 'abc123'],
  medium: ['Password123!', 'MySecure456$', 'Tr@il2023'],
  strong: ['8N$kL9#mP2@vQ4^wR7&tY1!uI3%eO6*sA5+gH', 'Zx9!Cv8@Bn7#Mm6$Kl5%Jh4&Ng3*Df2+Se1'],
  specialCharacters: ['!@#$%^&*()', '+={}[]|\\:";\'<>?,./', '™£¢∞§¶•ªº'],
  unicodeChars: ['测试密码', 'пароль', 'كلمة مرور', '🔐🗝️🔑'],
};

describe('Credential Management Tools - Basic Tests', () => {
  let mockServer: any;
  let mockTool: jest.MockedFunction<any>;
  let mockApiClient: MockMakeApiClient;
  let mockContext: any;
  let chaosMonkey: ChaosMonkey;

  // Mock data generators
  const generateMockCredential = (overrides?: Partial<any>): any => ({
    id: Math.floor(Math.random() * 100000),
    type: 'api_key',
    name: 'Test Credential',
    service: 'test-service',
    createdAt: new Date().toISOString(),
    lastUsed: null,
    expiresAt: null,
    isActive: true,
    security: {
      isEncrypted: true,
      encryptionAlgorithm: 'AES-256-GCM',
      keyDerivation: 'PBKDF2',
      accessCount: 0,
      lastAccessed: null,
      lastRotated: new Date().toISOString(),
      compromiseIndicators: [],
      securityScore: 8.5,
    },
    metadata: {
      version: '1.0',
      tags: ['production', 'api'],
      environments: ['prod'],
      complianceLevel: 'high',
      dataClassification: 'confidential',
    },
    rotation: {
      autoRotate: false,
      rotationDays: 90,
      lastRotation: new Date().toISOString(),
      nextRotation: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(),
      rotationHistory: [],
    },
    usage: {
      accessCount: 0,
      lastAccessed: null,
      accessPatterns: [],
      restrictions: {
        ipWhitelist: [],
        timeRestrictions: null,
        usageQuota: null,
      },
    },
    compliance: {
      frameworks: ['SOC2', 'GDPR', 'HIPAA'],
      auditTrail: [],
      retentionPolicy: '7_years',
      dataResidency: 'us-east-1',
    },
    organizationId: 1001,
    teamId: 2001,
    ...overrides,
  });

  beforeEach(async () => {
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockTool = serverSetup.mockTool;
    mockApiClient = new MockMakeApiClient();
    
    // ✅ CORRECTED: Create standardized mock context for tool execution
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
    
    chaosMonkey = new ChaosMonkey({
      failureRate: 0.1,
      latencyMs: 1000,
      scenarios: ['latency', 'error', 'timeout'],
    });

    mockTool.mockClear();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Tool Registration', () => {
    it('should successfully import and register all credential management tools', async () => {
      const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
      
      expect(() => {
        addCredentialManagementTools(mockServer, mockApiClient as any);
      }).not.toThrow();
      
      expect(mockTool).toHaveBeenCalled();
      expect(mockTool.mock.calls.length).toBeGreaterThan(0);
    });

    it('should register all expected credential management tools', async () => {
      const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
      addCredentialManagementTools(mockServer, mockApiClient as any);
      
      const toolNames = mockTool.mock.calls.map(call => call[0].name);
      
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
        expect(toolNames).toContain(toolName);
      });
      
      expect(toolNames.length).toBeGreaterThan(0);
    });
  });

  describe('Tool Execution', () => {
    beforeEach(async () => {
      const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
      addCredentialManagementTools(mockServer, mockApiClient as any);
    });

    it('should execute store-credential successfully', async () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'store-credential')[0];
      
      const input = {
        type: 'api_key',
        service: 'external-api-service',
        value: 'sk-test-1234567890abcdef',
        name: 'Test API Key',
        description: 'API key for external service integration',
        organizationId: 1001,
        teamId: 2001,
      };

      // ✅ CORRECTED: Direct tool execution with context
      const result = await toolConfig.execute(input, mockContext);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.credentialId).toBeDefined();
      expect(parsedResult.message).toBeDefined();
      expect(parsedResult.message).toContain('stored successfully');
    });

    it('should execute list-credentials successfully', async () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'list-credentials')[0];
      
      const input = {
        type: 'api_key',
        service: 'external-api-service',
        limit: 10,
      };

      // ✅ CORRECTED: Direct tool execution with context
      const result = await toolConfig.execute(input, mockContext);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.credentials).toBeDefined();
      expect(Array.isArray(parsedResult.credentials)).toBe(true);
    });
  });

  describe('Schema Validation', () => {
    beforeEach(async () => {
      const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
      addCredentialManagementTools(mockServer, mockApiClient as any);
    });

    it('should validate store-credential schema with valid data', () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'store-credential')[0];
      
      const validInput = {
        type: 'api_key',
        service: 'external-api-service',
        value: 'sk-test-1234567890abcdef',
        name: 'Test API Key',
        description: 'API key for external service integration',
        organizationId: 1001,
        teamId: 2001,
      };

      expectValidZodParse(toolConfig.parameters, validInput);
    });

    it('should reject invalid store-credential data', () => {
      const toolConfig = mockTool.mock.calls.find(call => call[0].name === 'store-credential')[0];
      
      const invalidInputs = [
        {}, // Missing required fields
        {
          type: 'invalid_type',
          service: 'test-service',
          value: 'test-value',
          name: 'Test Credential',
        },
      ];

      invalidInputs.forEach(invalidInput => {
        expectInvalidZodParse(toolConfig.parameters, invalidInput);
      });
    });
  });
});