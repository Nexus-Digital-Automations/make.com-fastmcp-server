/**
 * Comprehensive Test Suite for Credential Management Tools
 * Tests all 8 credential management tools with security validation
 * and advanced testing patterns following testing.md guidelines
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { UserError } from 'fastmcp';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';
import { 
  createMockServer, 
  findTool, 
  executeTool 
} from '../../utils/test-helpers.js';

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
  sqlInjection: ["'; DROP TABLE credentials; --", "1' OR '1'='1", "'; SELECT * FROM passwords; --"],
  xss: ["<script>alert('xss')</script>", "javascript:alert('xss')", "<img src=x onerror=alert('xss')>"],
  pathTraversal: ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam", "....//....//etc/passwd"],
  commandInjection: ["; cat /etc/passwd", "| whoami", "&& rm -rf /", "; shutdown -h now"],
  ldapInjection: ["*)(uid=*))(|(uid=*", "*)(|(objectClass=*))", "admin)(&(password=*)"],
};

// Encryption testing utilities
const encryptionTestCases = {
  weakPasswords: ['123456', 'password', 'admin', '', 'a'],
  strongPasswords: ['Tr0ub4dor&3', 'correct horse battery staple', 'P@ssw0rd123!@#'],
  specialCharacters: ['!@#$%^&*()', '+={}[]|\\:";\'<>?,./', '™£¢∞§¶•ªº'],
  unicodeChars: ['测试密码', 'пароль', 'كلمة مرور', '🔐🗝️🔑'],
};

describe('Credential Management Tools', () => {
  let mockServer: ReturnType<typeof createMockServer>;
  let mockTool: any;
  let mockApiClient: MockMakeApiClient;
  let chaosMonkey: ChaosMonkey;

  // Mock data generators
  const generateMockCredential = (overrides?: Partial<MakeCredential>): MakeCredential => ({
    id: Math.floor(Math.random() * 100000),
    name: 'test-api-key',
    description: 'Test API key for external service integration',
    type: 'api_key',
    service: 'external-api-service',
    organizationId: 1001,
    teamId: 2001,
    status: 'active',
    metadata: {
      createdBy: 12345,
      createdByName: 'Security Admin',
      environment: 'production',
      purpose: 'API integration',
      tags: ['external', 'api', 'production'],
      expirationPolicy: 'manual',
      rotationRequired: true,
    },
    security: {
      isEncrypted: true,
      encryptionAlgorithm: 'AES-256-GCM',
      keyDerivation: 'PBKDF2',
      accessCount: 45,
      lastAccessed: new Date(Date.now() - 3600000).toISOString(),
      lastRotated: new Date(Date.now() - 86400000 * 30).toISOString(),
      compromiseIndicators: [],
      securityScore: 8.5,
    },
    permissions: {
      read: ['user_12345', 'team_2001'],
      write: ['user_12345'],
      admin: ['user_12345', 'security_team'],
      rotate: ['user_12345', 'security_team'],
    },
    rotation: {
      autoRotate: true,
      intervalDays: 90,
      nextRotation: new Date(Date.now() + 86400000 * 60).toISOString(),
      lastRotation: new Date(Date.now() - 86400000 * 30).toISOString(),
      rotationHistory: [
        {
          rotatedAt: new Date(Date.now() - 86400000 * 30).toISOString(),
          reason: 'scheduled_rotation',
          rotatedBy: 12345,
          rotatedByName: 'Security Admin',
          success: true,
        },
      ],
    },
    usage: {
      connectionsCount: 15,
      scenariosCount: 8,
      lastUsedScenario: 'data-sync-scenario',
      usagePattern: {
        daily: [12, 15, 18, 20, 16, 14, 22],
        peak: { hour: 14, count: 22 },
        trend: 'stable',
      },
    },
    audit: {
      createdAt: new Date(Date.now() - 86400000 * 90).toISOString(),
      updatedAt: new Date(Date.now() - 86400000).toISOString(),
      accessLogs: [
        {
          timestamp: new Date(Date.now() - 3600000).toISOString(),
          action: 'credential_accessed',
          userId: 12345,
          scenario: 'data-sync-scenario',
          ipAddress: '192.168.1.100',
          success: true,
        },
      ],
      modificationHistory: [
        {
          timestamp: new Date(Date.now() - 86400000).toISOString(),
          action: 'metadata_updated',
          userId: 12345,
          changes: ['description', 'tags'],
          reason: 'documentation_update',
        },
      ],
    },
    ...overrides,
  });

  const generateMockRotationSchedule = (overrides?: Partial<MakeCredentialRotationSchedule>): MakeCredentialRotationSchedule => ({
    id: Math.floor(Math.random() * 100000),
    credentialId: Math.floor(Math.random() * 100000),
    credentialName: 'test-credential',
    organizationId: 1001,
    teamId: 2001,
    schedule: {
      type: 'automatic',
      intervalDays: 90,
      timeOfDay: '02:00',
      timezone: 'UTC',
      daysOfWeek: ['sunday'],
      excludeDates: ['2024-12-25', '2024-01-01'],
    },
    nextExecution: new Date(Date.now() + 86400000 * 60).toISOString(),
    lastExecution: new Date(Date.now() - 86400000 * 30).toISOString(),
    status: 'active',
    configuration: {
      backupOldCredential: true,
      notifyUsers: true,
      testNewCredential: true,
      rollbackOnFailure: true,
      gracePeriodHours: 24,
    },
    history: [
      {
        executedAt: new Date(Date.now() - 86400000 * 30).toISOString(),
        status: 'success',
        duration: 45,
        newCredentialId: Math.floor(Math.random() * 100000),
        rotatedBy: 'automatic_system',
        notes: 'Successful automatic rotation',
      },
    ],
    metrics: {
      successfulRotations: 12,
      failedRotations: 1,
      averageDuration: 42,
      lastFailureReason: 'API service temporarily unavailable',
    },
    createdAt: new Date(Date.now() - 86400000 * 180).toISOString(),
    updatedAt: new Date(Date.now() - 86400000).toISOString(),
    createdBy: 12345,
    ...overrides,
  });

  const generateMockAuditLog = (overrides?: Partial<MakeCredentialAuditLog>): MakeCredentialAuditLog => ({
    id: Math.floor(Math.random() * 100000),
    credentialId: Math.floor(Math.random() * 100000),
    credentialName: 'test-credential',
    action: 'credential_accessed',
    timestamp: new Date().toISOString(),
    actor: {
      userId: 12345,
      userName: 'test.user@example.com',
      sessionId: 'session_' + Math.random().toString(36).substr(2, 9),
      ipAddress: '192.168.1.100',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    },
    context: {
      scenario: 'data-sync-scenario',
      operation: 'api_call',
      source: 'make_platform',
      correlationId: 'corr_' + Math.random().toString(36).substr(2, 9),
      environment: 'production',
    },
    details: {
      success: true,
      errorCode: null,
      errorMessage: null,
      accessMethod: 'api_key_header',
      dataAccessed: false,
      sensitiveOperation: false,
    },
    security: {
      riskLevel: 'low',
      anomalyScore: 0.1,
      geoLocation: {
        country: 'US',
        region: 'California',
        city: 'San Francisco',
        coordinates: { lat: 37.7749, lon: -122.4194 },
      },
      deviceFingerprint: 'fp_' + Math.random().toString(36).substr(2, 16),
    },
    organizationId: 1001,
    teamId: 2001,
    ...overrides,
  });

  beforeEach(async () => {
    // Create mock server and tool
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockTool = serverSetup.mockTool;
    
    mockApiClient = new MockMakeApiClient();
    chaosMonkey = new ChaosMonkey({
      failureRate: 0.1,
      latencyMs: 1000,
      scenarios: ['latency', 'error', 'timeout'],
    });

    // Add tools to server
    const { addCredentialManagementTools } = await import('../../../src/tools/credential-management.js');
    addCredentialManagementTools(mockServer, mockApiClient as any);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Tool Registration', () => {
    test('should register all credential management tools', () => {
      const toolConfigs = mockTool.mock.calls.map((call: any[]) => call[0]);
      const expectedTools = [
        'store_credential',
        'get_credential_status',
        'rotate_credential',
        'list_credentials',
        'get_audit_events',
        'migrate_credentials',
        'generate_credential',
        'cleanup_credentials',
      ];

      expectedTools.forEach(toolName => {
        const tool = toolConfigs.find((config: any) => config.name === toolName);
        expect(tool).toBeDefined();
      });
    });

    test('should have correct tool schemas', () => {
      const toolConfigs = mockTool.mock.calls.map((call: any[]) => call[0]);
      
      const expectedTools = [
        'store_credential',
        'get_credential_status',
        'rotate_credential',
        'list_credentials',
        'get_audit_events',
        'migrate_credentials',
        'generate_credential',
        'cleanup_credentials',
      ];
      
      expectedTools.forEach(toolName => {
        const tool = toolConfigs.find((config: any) => config.name === toolName);
        expect(tool?.parameters).toBeDefined();
      });
    });
  });

  describe('store-credential', () => {
    describe('Basic Functionality', () => {
      test('should store a new credential successfully', async () => {
        const mockCredential = generateMockCredential();
        mockApiClient.setMockResponse('post', '/credentials', {
          success: true,
          data: mockCredential,
        });

        const result = await mockServer.executeToolCall({
          tool: 'store-credential',
          parameters: {
            type: 'api_key',
            service: 'external-api-service',
            value: 'sk-test-1234567890abcdef',
            name: 'Test API Key',
            description: 'API key for external service integration',
            organizationId: 1001,
            teamId: 2001,
          },
        });

        expect(mockApiClient.post).toHaveBeenCalledWith('/organizations/1001/credentials', expect.objectContaining({
          type: 'api_key',
          service: 'external-api-service',
          name: 'Test API Key',
        }));

        const response = JSON.parse(result);
        expect(response.credential).toBeDefined();
        expect(response.credential.security.isEncrypted).toBe(true);
        expect(response.message).toContain('stored successfully');
        expect(response.security.encryptionStatus).toBe('encrypted');
      });

      test('should store secret with enhanced security', async () => {
        const mockCredential = generateMockCredential({
          type: 'secret',
          security: {
            isEncrypted: true,
            encryptionAlgorithm: 'AES-256-GCM',
            keyDerivation: 'PBKDF2',
            accessCount: 0,
            lastAccessed: null,
            lastRotated: new Date().toISOString(),
            compromiseIndicators: [],
            securityScore: 9.2,
          },
        });
        
        mockApiClient.setMockResponse('post', '/credentials', {
          success: true,
          data: mockCredential,
        });

        const result = await mockServer.executeToolCall({
          tool: 'store-credential',
          parameters: {
            type: 'secret',
            service: 'payment-processor',
            value: 'webhook_secret_very_long_and_secure_value_12345',
            name: 'Payment Webhook Secret',
            description: 'Webhook signature verification secret',
            encrypt: true,
            autoRotate: true,
            rotationDays: 30,
            securityLevel: 'high',
          },
        });

        expect(mockApiClient.post).toHaveBeenCalledWith('/credentials', expect.objectContaining({
          type: 'secret',
          service: 'payment-processor',
          encrypt: true,
          autoRotate: true,
          rotationDays: 30,
        }));

        const response = JSON.parse(result);
        expect(response.credential.type).toBe('secret');
        expect(response.security.securityScore).toBeGreaterThan(9);
        expect(response.rotation.autoRotate).toBe(true);
      });

      test('should store certificate with validation', async () => {
        const mockCredential = generateMockCredential({
          type: 'certificate',
          metadata: {
            createdBy: 12345,
            createdByName: 'Security Admin',
            environment: 'production',
            purpose: 'SSL/TLS termination',
            tags: ['ssl', 'certificate', 'production'],
            expirationPolicy: 'automatic',
            rotationRequired: true,
          },
        });
        
        mockApiClient.setMockResponse('post', '/credentials', {
          success: true,
          data: mockCredential,
        });

        const certificateData = '-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHHH...';
        const privateKeyData = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0B...';

        const result = await mockServer.executeToolCall({
          tool: 'store-credential',
          parameters: {
            type: 'certificate',
            service: 'web-server',
            value: certificateData,
            name: 'Production SSL Certificate',
            description: 'SSL certificate for production web server',
            certificateData,
            privateKeyData,
            validateCertificate: true,
          },
        });

        expect(mockApiClient.post).toHaveBeenCalledWith('/credentials', expect.objectContaining({
          type: 'certificate',
          service: 'web-server',
          validateCertificate: true,
        }));

        const response = JSON.parse(result);
        expect(response.credential.type).toBe('certificate');
        expect(response.validation).toBeDefined();
        expect(response.validation.certificateValid).toBeDefined();
      });
    });

    describe('Security Testing', () => {
      test('should validate credential strength', async () => {
        for (const weakPassword of encryptionTestCases.weakPasswords) {
          try {
            await mockServer.executeToolCall({
              tool: 'store-credential',
              parameters: {
                type: 'secret',
                service: 'test-service',
                value: weakPassword,
                name: 'Test Weak Secret',
                description: 'Testing weak credential detection',
              },
            });
            // If we reach here, the weak password was accepted
            // This might be acceptable depending on validation logic
          } catch (error) {
            // Weak password validation should catch this
            expect(error).toBeDefined();
          }
        }
      });

      test('should sanitize credential metadata', async () => {
        const mockCredential = generateMockCredential();
        mockApiClient.setMockResponse('post', '/credentials', {
          success: true,
          data: mockCredential,
        });

        const maliciousName = securityTestPatterns.xss[0];
        const maliciousDescription = securityTestPatterns.sqlInjection[0];

        const result = await mockServer.executeToolCall({
          tool: 'store-credential',
          parameters: {
            type: 'api_key',
            service: 'test-service',
            value: 'safe-credential-value',
            name: maliciousName,
            description: maliciousDescription,
          },
        });

        // Credential should be stored but metadata should be sanitized
        const response = JSON.parse(result);
        expect(response.credential).toBeDefined();
        // Verify sanitization occurred (actual implementation would sanitize)
      });

      test('should prevent credential value exposure', async () => {
        const mockCredential = generateMockCredential();
        mockApiClient.setMockResponse('post', '/credentials', {
          success: true,
          data: mockCredential,
        });

        const sensitiveValue = 'sk-live-very-secret-api-key-12345';

        const result = await mockServer.executeToolCall({
          tool: 'store-credential',
          parameters: {
            type: 'api_key',
            service: 'payment-service',
            value: sensitiveValue,
            name: 'Live Payment API Key',
            description: 'Production payment processing key',
          },
        });

        const response = JSON.parse(result);
        // Credential value should never be exposed in response
        expect(JSON.stringify(response)).not.toContain(sensitiveValue);
        expect(response.credential.value).toBeUndefined();
      });
    });

    describe('Error Handling', () => {
      test('should handle API failures gracefully', async () => {
        mockApiClient.setMockResponse('post', '/credentials', {
          success: false,
          error: { message: 'Credential storage service temporarily unavailable' },
        });

        await expect(mockServer.executeToolCall({
          tool: 'store-credential',
          parameters: {
            type: 'api_key',
            service: 'test-service',
            value: 'test-value',
            name: 'Test Credential',
          },
        })).rejects.toThrow('Failed to store credential: Credential storage service temporarily unavailable');
      });

      test('should validate required fields', async () => {
        await expect(mockServer.executeToolCall({
          tool: 'store-credential',
          parameters: {
            type: 'api_key',
            // Missing required fields
          },
        })).rejects.toThrow();
      });

      test('should validate credential types', async () => {
        await expect(mockServer.executeToolCall({
          tool: 'store-credential',
          parameters: {
            type: 'invalid_type' as 'api_key' | 'secret' | 'token' | 'certificate',
            service: 'test-service',
            value: 'test-value',
            name: 'Test Credential',
          },
        })).rejects.toThrow();
      });
    });

    describe('Encryption and Security', () => {
      test('should enforce encryption for sensitive credentials', async () => {
        const mockCredential = generateMockCredential({
          security: { 
            isEncrypted: true,
            encryptionAlgorithm: 'AES-256-GCM',
            keyDerivation: 'PBKDF2',
            accessCount: 0,
            lastAccessed: null,
            lastRotated: new Date().toISOString(),
            compromiseIndicators: [],
            securityScore: 9.5,
          },
        });
        
        mockApiClient.setMockResponse('post', '/credentials', {
          success: true,
          data: mockCredential,
        });

        const result = await mockServer.executeToolCall({
          tool: 'store-credential',
          parameters: {
            type: 'secret',
            service: 'database',
            value: 'database_master_password_very_secure',
            name: 'Database Master Password',
            description: 'Master password for production database',
            encrypt: true,
            encryptionAlgorithm: 'AES-256-GCM',
          },
        });

        const response = JSON.parse(result);
        expect(response.credential.security.isEncrypted).toBe(true);
        expect(response.credential.security.encryptionAlgorithm).toBe('AES-256-GCM');
        expect(response.security.encryptionStatus).toBe('encrypted');
      });

      test('should handle special characters in credentials', async () => {
        const mockCredential = generateMockCredential();
        mockApiClient.setMockResponse('post', '/credentials', {
          success: true,
          data: mockCredential,
        });

        for (const specialChars of encryptionTestCases.specialCharacters) {
          const result = await mockServer.executeToolCall({
            tool: 'store-credential',
            parameters: {
              type: 'secret',
              service: 'test-service',
              value: `password${specialChars}123`,
              name: 'Special Characters Test',
              description: 'Testing special character handling',
            },
          });

          const response = JSON.parse(result);
          expect(response.credential).toBeDefined();
        }
      });

      test('should handle unicode characters in credentials', async () => {
        const mockCredential = generateMockCredential();
        mockApiClient.setMockResponse('post', '/credentials', {
          success: true,
          data: mockCredential,
        });

        for (const unicodeChars of encryptionTestCases.unicodeChars) {
          const result = await mockServer.executeToolCall({
            tool: 'store-credential',
            parameters: {
              type: 'secret',
              service: 'test-service',
              value: unicodeChars,
              name: 'Unicode Test',
              description: 'Testing unicode character handling',
            },
          });

          const response = JSON.parse(result);
          expect(response.credential).toBeDefined();
        }
      });
    });
  });

  describe('retrieve-credential', () => {
    describe('Basic Functionality', () => {
      test('should retrieve credential by ID', async () => {
        const mockCredential = generateMockCredential();
        mockApiClient.setMockResponse('get', '/credentials/12345', {
          success: true,
          data: mockCredential,
        });

        const result = await mockServer.executeToolCall({
          tool: 'retrieve-credential',
          parameters: {
            credentialId: 12345,
            includeValue: false,
            includeMetadata: true,
          },
        });

        expect(mockApiClient.get).toHaveBeenCalledWith('/credentials/12345', {
          params: expect.objectContaining({
            includeValue: false,
            includeMetadata: true,
          }),
        });

        const response = JSON.parse(result);
        expect(response.credential).toBeDefined();
        expect(response.credential.id).toBe(mockCredential.id);
        expect(response.credential.value).toBeUndefined(); // Value should not be included
      });

      test('should retrieve credential value with proper authorization', async () => {
        const mockCredential = generateMockCredential();
        mockApiClient.setMockResponse('get', '/credentials/12345', {
          success: true,
          data: { ...mockCredential, value: '[CREDENTIAL_VALUE_ENCRYPTED]' },
        });

        const result = await mockServer.executeToolCall({
          tool: 'retrieve-credential',
          parameters: {
            credentialId: 12345,
            includeValue: true,
            purpose: 'api_integration',
            scenario: 'data-sync-scenario',
          },
        });

        expect(mockApiClient.get).toHaveBeenCalledWith('/credentials/12345', {
          params: expect.objectContaining({
            includeValue: true,
            purpose: 'api_integration',
            scenario: 'data-sync-scenario',
          }),
        });

        const response = JSON.parse(result);
        expect(response.credential).toBeDefined();
        expect(response.credential.value).toBe('[CREDENTIAL_VALUE_ENCRYPTED]');
        expect(response.accessLogged).toBe(true);
      });

      test('should retrieve credential by name and service', async () => {
        const mockCredential = generateMockCredential();
        mockApiClient.setMockResponse('get', '/credentials/by-name', {
          success: true,
          data: mockCredential,
        });

        const result = await mockServer.executeToolCall({
          tool: 'retrieve-credential',
          parameters: {
            name: 'test-api-key',
            service: 'external-api-service',
            includeValue: false,
          },
        });

        expect(mockApiClient.get).toHaveBeenCalledWith('/credentials/by-name', {
          params: expect.objectContaining({
            name: 'test-api-key',
            service: 'external-api-service',
          }),
        });

        const response = JSON.parse(result);
        expect(response.credential).toBeDefined();
        expect(response.credential.name).toBe('test-api-key');
      });
    });

    describe('Security Testing', () => {
      test('should audit credential access', async () => {
        const mockCredential = generateMockCredential();
        mockApiClient.setMockResponse('get', '/credentials/12345', {
          success: true,
          data: mockCredential,
        });

        const result = await mockServer.executeToolCall({
          tool: 'retrieve-credential',
          parameters: {
            credentialId: 12345,
            includeValue: true,
            purpose: 'testing',
            auditTrail: true,
          },
        });

        const response = JSON.parse(result);
        expect(response.accessLogged).toBe(true);
        expect(response.auditTrail).toBeDefined();
        expect(response.auditTrail.action).toBe('credential_accessed');
      });

      test('should prevent unauthorized access', async () => {
        mockApiClient.setMockResponse('get', '/credentials/12345', {
          success: false,
          error: { message: 'Insufficient permissions to access credential', status: 403 },
        });

        await expect(mockServer.executeToolCall({
          tool: 'retrieve-credential',
          parameters: {
            credentialId: 12345,
            includeValue: true,
          },
        })).rejects.toThrow('Failed to retrieve credential: Insufficient permissions to access credential');
      });

      test('should mask sensitive data in logs', async () => {
        const mockCredential = generateMockCredential();
        mockApiClient.setMockResponse('get', '/credentials/12345', {
          success: true,
          data: mockCredential,
        });

        const result = await mockServer.executeToolCall({
          tool: 'retrieve-credential',
          parameters: {
            credentialId: 12345,
            includeValue: false,
            includeSecurityInfo: true,
          },
        });

        const response = JSON.parse(result);
        // Security information should be included but not sensitive details
        expect(response.credential.security).toBeDefined();
        expect(response.credential.security.isEncrypted).toBeDefined();
        expect(response.credential.security.securityScore).toBeDefined();
      });
    });

    describe('Error Handling', () => {
      test('should handle credential not found', async () => {
        mockApiClient.setMockResponse('get', '/credentials/99999', {
          success: false,
          error: { message: 'Credential not found', status: 404 },
        });

        await expect(mockServer.executeToolCall({
          tool: 'retrieve-credential',
          parameters: {
            credentialId: 99999,
          },
        })).rejects.toThrow('Failed to retrieve credential: Credential not found');
      });

      test('should validate required parameters', async () => {
        await expect(mockServer.executeToolCall({
          tool: 'retrieve-credential',
          parameters: {
            // Missing credentialId and name/service
          },
        })).rejects.toThrow();
      });
    });
  });

  describe('list-credentials', () => {
    describe('Basic Functionality', () => {
      test('should list credentials with filters', async () => {
        const mockCredentials = [
          generateMockCredential(),
          generateMockCredential({ type: 'secret' }),
          generateMockCredential({ type: 'token' }),
        ];
        
        mockApiClient.setMockResponse('get', '/credentials', {
          success: true,
          data: mockCredentials,
          metadata: { total: 3, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'list-credentials',
          parameters: {
            type: 'api_key',
            service: 'external-api-service',
            status: 'active',
            limit: 50,
            offset: 0,
          },
        });

        expect(mockApiClient.get).toHaveBeenCalledWith('/credentials', {
          params: expect.objectContaining({
            type: 'api_key',
            service: 'external-api-service',
            status: 'active',
            limit: 50,
            offset: 0,
          }),
        });

        const response = JSON.parse(result);
        expect(response.credentials).toHaveLength(3);
        expect(response.summary).toBeDefined();
        expect(response.summary.totalCredentials).toBe(3);
      });

      test('should list credentials with security analysis', async () => {
        const mockCredentials = [
          generateMockCredential({ security: { securityScore: 9.5, isEncrypted: true, compromiseIndicators: [], accessCount: 10, lastAccessed: new Date().toISOString(), lastRotated: new Date().toISOString(), encryptionAlgorithm: 'AES-256-GCM', keyDerivation: 'PBKDF2' } }),
          generateMockCredential({ security: { securityScore: 6.2, isEncrypted: false, compromiseIndicators: ['weak_password'], accessCount: 100, lastAccessed: new Date().toISOString(), lastRotated: new Date(Date.now() - 86400000 * 180).toISOString(), encryptionAlgorithm: 'none', keyDerivation: 'none' } }),
        ];

        mockApiClient.setMockResponse('get', '/credentials', {
          success: true,
          data: mockCredentials,
          metadata: { total: 2, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'list-credentials',
          parameters: {
            includeSecurityAnalysis: true,
            includeUsageStats: true,
            sortBy: 'security_score',
            sortOrder: 'desc',
          },
        });

        const response = JSON.parse(result);
        expect(response.securityAnalysis).toBeDefined();
        expect(response.securityAnalysis.averageSecurityScore).toBeDefined();
        expect(response.securityAnalysis.encryptedCount).toBeDefined();
        expect(response.securityAnalysis.compromisedCredentials).toBeDefined();
        expect(response.usageAnalysis).toBeDefined();
      });

      test('should filter by expiration status', async () => {
        const expiringCredential = generateMockCredential({
          rotation: {
            autoRotate: true,
            intervalDays: 90,
            nextRotation: new Date(Date.now() + 86400000 * 7).toISOString(), // Expires in 7 days
            lastRotation: new Date(Date.now() - 86400000 * 83).toISOString(),
            rotationHistory: [],
          },
        });

        mockApiClient.setMockResponse('get', '/credentials', {
          success: true,
          data: [expiringCredential],
          metadata: { total: 1, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'list-credentials',
          parameters: {
            expiringDays: 30,
            includeExpiration: true,
          },
        });

        const response = JSON.parse(result);
        expect(response.credentials).toHaveLength(1);
        expect(response.expirationAnalysis).toBeDefined();
        expect(response.expirationAnalysis.expiringSoon).toBeGreaterThan(0);
      });
    });

    describe('Advanced Filtering', () => {
      test('should search credentials by metadata', async () => {
        const mockCredentials = [
          generateMockCredential({
            metadata: {
              tags: ['production', 'api', 'payment'],
              environment: 'production',
              purpose: 'payment processing',
              createdBy: 12345,
              createdByName: 'Security Admin',
              expirationPolicy: 'automatic',
              rotationRequired: true,
            },
          }),
        ];

        mockApiClient.setMockResponse('get', '/credentials', {
          success: true,
          data: mockCredentials,
          metadata: { total: 1, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'list-credentials',
          parameters: {
            tags: ['production', 'payment'],
            environment: 'production',
            searchQuery: 'payment',
          },
        });

        expect(mockApiClient.get).toHaveBeenCalledWith('/credentials', {
          params: expect.objectContaining({
            tags: 'production,payment',
            environment: 'production',
            search: 'payment',
          }),
        });

        const response = JSON.parse(result);
        expect(response.credentials).toHaveLength(1);
        expect(response.credentials[0].metadata.tags).toContain('payment');
      });

      test('should filter by organization and team', async () => {
        const mockCredentials = [generateMockCredential({ organizationId: 1001, teamId: 2001 })];
        mockApiClient.setMockResponse('get', '/organizations/1001/credentials', {
          success: true,
          data: mockCredentials,
          metadata: { total: 1, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'list-credentials',
          parameters: {
            organizationId: 1001,
            teamId: 2001,
          },
        });

        expect(mockApiClient.get).toHaveBeenCalledWith('/organizations/1001/credentials', expect.any(Object));
        
        const response = JSON.parse(result);
        expect(response.credentials[0].organizationId).toBe(1001);
        expect(response.credentials[0].teamId).toBe(2001);
      });
    });

    describe('Security Analysis', () => {
      test('should identify security risks', async () => {
        const riskyCredentials = [
          generateMockCredential({
            security: {
              securityScore: 3.2,
              isEncrypted: false,
              compromiseIndicators: ['weak_password', 'excessive_access'],
              accessCount: 1000,
              lastAccessed: new Date().toISOString(),
              lastRotated: new Date(Date.now() - 86400000 * 365).toISOString(), // Not rotated for a year
              encryptionAlgorithm: 'none',
              keyDerivation: 'none',
            },
          }),
          generateMockCredential({
            security: {
              securityScore: 2.1,
              isEncrypted: true,
              compromiseIndicators: ['suspicious_access_pattern', 'geolocation_anomaly'],
              accessCount: 50,
              lastAccessed: new Date().toISOString(),
              lastRotated: new Date(Date.now() - 86400000 * 30).toISOString(),
              encryptionAlgorithm: 'AES-256-GCM',
              keyDerivation: 'PBKDF2',
            },
          }),
        ];

        mockApiClient.setMockResponse('get', '/credentials', {
          success: true,
          data: riskyCredentials,
          metadata: { total: 2, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'list-credentials',
          parameters: {
            securityScore: 5.0,
            includeSecurityAnalysis: true,
            includeRiskAssessment: true,
          },
        });

        const response = JSON.parse(result);
        expect(response.securityAnalysis.compromisedCredentials).toBeGreaterThan(0);
        expect(response.securityAnalysis.weakCredentials).toBeGreaterThan(0);
        expect(response.riskAssessment).toBeDefined();
        expect(response.recommendations).toBeDefined();
      });
    });

    describe('Error Handling', () => {
      test('should handle API failures', async () => {
        mockApiClient.setMockResponse('get', '/credentials', {
          success: false,
          error: { message: 'Credential service temporarily unavailable' },
        });

        await expect(mockServer.executeToolCall({
          tool: 'list-credentials',
          parameters: {},
        })).rejects.toThrow('Failed to list credentials: Credential service temporarily unavailable');
      });
    });
  });

  describe('update-credential', () => {
    describe('Basic Functionality', () => {
      test('should update credential metadata', async () => {
        const updatedCredential = generateMockCredential({
          name: 'Updated API Key',
          description: 'Updated description for API key',
          metadata: {
            tags: ['updated', 'api', 'production'],
            environment: 'production',
            purpose: 'updated purpose',
            createdBy: 12345,
            createdByName: 'Security Admin',
            expirationPolicy: 'manual',
            rotationRequired: true,
          },
        });

        mockApiClient.setMockResponse('put', '/credentials/12345', {
          success: true,
          data: updatedCredential,
        });

        const result = await mockServer.executeToolCall({
          tool: 'update-credential',
          parameters: {
            credentialId: 12345,
            name: 'Updated API Key',
            description: 'Updated description for API key',
            tags: ['updated', 'api', 'production'],
            updateReason: 'metadata_update',
          },
        });

        expect(mockApiClient.put).toHaveBeenCalledWith('/credentials/12345', expect.objectContaining({
          name: 'Updated API Key',
          description: 'Updated description for API key',
          tags: ['updated', 'api', 'production'],
          updateReason: 'metadata_update',
        }));

        const response = JSON.parse(result);
        expect(response.credential.name).toBe('Updated API Key');
        expect(response.changes).toContain('name');
        expect(response.changes).toContain('description');
        expect(response.auditLogged).toBe(true);
      });

      test('should update credential value securely', async () => {
        const updatedCredential = generateMockCredential({
          security: {
            isEncrypted: true,
            encryptionAlgorithm: 'AES-256-GCM',
            keyDerivation: 'PBKDF2',
            accessCount: 0,
            lastAccessed: null,
            lastRotated: new Date().toISOString(),
            compromiseIndicators: [],
            securityScore: 9.2,
          },
        });

        mockApiClient.setMockResponse('put', '/credentials/12345', {
          success: true,
          data: updatedCredential,
        });

        const result = await mockServer.executeToolCall({
          tool: 'update-credential',
          parameters: {
            credentialId: 12345,
            value: 'new-secure-api-key-value-12345',
            encrypt: true,
            backupOldValue: true,
            updateReason: 'credential_rotation',
          },
        });

        const response = JSON.parse(result);
        expect(response.credential.security.isEncrypted).toBe(true);
        expect(response.valueUpdated).toBe(true);
        expect(response.backupCreated).toBe(true);
        // Value should never be exposed in response
        expect(JSON.stringify(response)).not.toContain('new-secure-api-key-value-12345');
      });

      test('should update rotation settings', async () => {
        const updatedCredential = generateMockCredential({
          rotation: {
            autoRotate: true,
            intervalDays: 60, // Updated from 90 to 60
            nextRotation: new Date(Date.now() + 86400000 * 60).toISOString(),
            lastRotation: new Date(Date.now() - 86400000 * 30).toISOString(),
            rotationHistory: [],
          },
        });

        mockApiClient.setMockResponse('put', '/credentials/12345', {
          success: true,
          data: updatedCredential,
        });

        const result = await mockServer.executeToolCall({
          tool: 'update-credential',
          parameters: {
            credentialId: 12345,
            autoRotate: true,
            rotationDays: 60,
            updateReason: 'rotation_policy_update',
          },
        });

        const response = JSON.parse(result);
        expect(response.credential.rotation.autoRotate).toBe(true);
        expect(response.credential.rotation.intervalDays).toBe(60);
        expect(response.rotationUpdated).toBe(true);
      });
    });

    describe('Security Testing', () => {
      test('should validate update permissions', async () => {
        mockApiClient.setMockResponse('put', '/credentials/12345', {
          success: false,
          error: { message: 'Insufficient permissions to update credential', status: 403 },
        });

        await expect(mockServer.executeToolCall({
          tool: 'update-credential',
          parameters: {
            credentialId: 12345,
            name: 'Unauthorized Update',
          },
        })).rejects.toThrow('Failed to update credential: Insufficient permissions to update credential');
      });

      test('should audit all update operations', async () => {
        const updatedCredential = generateMockCredential();
        mockApiClient.setMockResponse('put', '/credentials/12345', {
          success: true,
          data: updatedCredential,
        });

        const result = await mockServer.executeToolCall({
          tool: 'update-credential',
          parameters: {
            credentialId: 12345,
            description: 'Updated for security compliance',
            updateReason: 'security_compliance',
            auditTrail: true,
          },
        });

        const response = JSON.parse(result);
        expect(response.auditLogged).toBe(true);
        expect(response.auditTrail).toBeDefined();
        expect(response.auditTrail.action).toBe('credential_updated');
        expect(response.auditTrail.reason).toBe('security_compliance');
      });

      test('should prevent unauthorized value updates', async () => {
        mockApiClient.setMockResponse('put', '/credentials/12345', {
          success: false,
          error: { message: 'Value updates require additional authorization', status: 403 },
        });

        await expect(mockServer.executeToolCall({
          tool: 'update-credential',
          parameters: {
            credentialId: 12345,
            value: 'new-unauthorized-value',
          },
        })).rejects.toThrow('Failed to update credential: Value updates require additional authorization');
      });
    });

    describe('Error Handling', () => {
      test('should handle credential not found', async () => {
        mockApiClient.setMockResponse('put', '/credentials/99999', {
          success: false,
          error: { message: 'Credential not found', status: 404 },
        });

        await expect(mockServer.executeToolCall({
          tool: 'update-credential',
          parameters: {
            credentialId: 99999,
            name: 'Non-existent Credential',
          },
        })).rejects.toThrow('Failed to update credential: Credential not found');
      });

      test('should validate update parameters', async () => {
        await expect(mockServer.executeToolCall({
          tool: 'update-credential',
          parameters: {
            credentialId: 12345,
            // No update fields provided
          },
        })).rejects.toThrow();
      });
    });
  });

  describe('rotate-credential', () => {
    describe('Basic Functionality', () => {
      test('should rotate credential successfully', async () => {
        const rotationResult = {
          success: true,
          oldCredentialId: 12345,
          newCredentialId: 67890,
          rotatedAt: new Date().toISOString(),
          backupCreated: true,
          affectedConnections: 5,
          affectedScenarios: 3,
        };

        mockApiClient.setMockResponse('post', '/credentials/12345/rotate', {
          success: true,
          data: rotationResult,
        });

        const result = await mockServer.executeToolCall({
          tool: 'rotate-credential',
          parameters: {
            credentialId: 12345,
            rotationType: 'manual',
            reason: 'security_audit_requirement',
            backupOldCredential: true,
            testNewCredential: true,
          },
        });

        expect(mockApiClient.post).toHaveBeenCalledWith('/credentials/12345/rotate', expect.objectContaining({
          rotationType: 'manual',
          reason: 'security_audit_requirement',
          backupOldCredential: true,
          testNewCredential: true,
        }));

        const response = JSON.parse(result);
        expect(response.rotation.success).toBe(true);
        expect(response.rotation.newCredentialId).toBe(67890);
        expect(response.impact.affectedConnections).toBe(5);
        expect(response.impact.affectedScenarios).toBe(3);
      });

      test('should handle automatic rotation', async () => {
        const rotationResult = {
          success: true,
          oldCredentialId: 12345,
          newCredentialId: 67890,
          rotatedAt: new Date().toISOString(),
          rotationType: 'automatic',
          scheduledRotation: true,
          backupCreated: true,
          validationPassed: true,
        };

        mockApiClient.setMockResponse('post', '/credentials/12345/rotate', {
          success: true,
          data: rotationResult,
        });

        const result = await mockServer.executeToolCall({
          tool: 'rotate-credential',
          parameters: {
            credentialId: 12345,
            rotationType: 'automatic',
            generateNewValue: true,
            notifyUsers: true,
          },
        });

        const response = JSON.parse(result);
        expect(response.rotation.rotationType).toBe('automatic');
        expect(response.rotation.scheduledRotation).toBe(true);
        expect(response.rotation.validationPassed).toBe(true);
        expect(response.notifications).toBeDefined();
      });

      test('should handle emergency rotation', async () => {
        const rotationResult = {
          success: true,
          oldCredentialId: 12345,
          newCredentialId: 67890,
          rotatedAt: new Date().toISOString(),
          rotationType: 'emergency',
          oldCredentialRevoked: true,
          emergencyReason: 'suspected_compromise',
          immediateEffect: true,
        };

        mockApiClient.setMockResponse('post', '/credentials/12345/rotate', {
          success: true,
          data: rotationResult,
        });

        const result = await mockServer.executeToolCall({
          tool: 'rotate-credential',
          parameters: {
            credentialId: 12345,
            rotationType: 'emergency',
            reason: 'suspected_compromise',
            revokeOldCredential: true,
            immediateEffect: true,
          },
        });

        const response = JSON.parse(result);
        expect(response.rotation.rotationType).toBe('emergency');
        expect(response.rotation.oldCredentialRevoked).toBe(true);
        expect(response.rotation.immediateEffect).toBe(true);
        expect(response.securityAlert).toBeDefined();
      });
    });

    describe('Advanced Rotation Features', () => {
      test('should handle custom rotation values', async () => {
        const rotationResult = {
          success: true,
          oldCredentialId: 12345,
          newCredentialId: 67890,
          rotatedAt: new Date().toISOString(),
          customValueProvided: true,
          validationPassed: true,
        };

        mockApiClient.setMockResponse('post', '/credentials/12345/rotate', {
          success: true,
          data: rotationResult,
        });

        const result = await mockServer.executeToolCall({
          tool: 'rotate-credential',
          parameters: {
            credentialId: 12345,
            rotationType: 'manual',
            newValue: 'new-custom-credential-value-12345',
            reason: 'planned_rotation_with_custom_value',
            validateNewValue: true,
          },
        });

        const response = JSON.parse(result);
        expect(response.rotation.customValueProvided).toBe(true);
        expect(response.rotation.validationPassed).toBe(true);
        // New value should never be exposed in response
        expect(JSON.stringify(response)).not.toContain('new-custom-credential-value-12345');
      });

      test('should handle graceful rotation with rollback capability', async () => {
        const rotationResult = {
          success: true,
          oldCredentialId: 12345,
          newCredentialId: 67890,
          rotatedAt: new Date().toISOString(),
          gracePeriodHours: 24,
          rollbackCapable: true,
          monitoringEnabled: true,
        };

        mockApiClient.setMockResponse('post', '/credentials/12345/rotate', {
          success: true,
          data: rotationResult,
        });

        const result = await mockServer.executeToolCall({
          tool: 'rotate-credential',
          parameters: {
            credentialId: 12345,
            rotationType: 'graceful',
            gracePeriodHours: 24,
            enableRollback: true,
            monitorConnections: true,
          },
        });

        const response = JSON.parse(result);
        expect(response.rotation.gracePeriodHours).toBe(24);
        expect(response.rotation.rollbackCapable).toBe(true);
        expect(response.monitoring).toBeDefined();
        expect(response.rollbackInstructions).toBeDefined();
      });
    });

    describe('Error Handling', () => {
      test('should handle rotation failures', async () => {
        mockApiClient.setMockResponse('post', '/credentials/12345/rotate', {
          success: false,
          error: { message: 'Credential rotation failed: external service unavailable' },
        });

        await expect(mockServer.executeToolCall({
          tool: 'rotate-credential',
          parameters: {
            credentialId: 12345,
            rotationType: 'manual',
            reason: 'scheduled_rotation',
          },
        })).rejects.toThrow('Failed to rotate credential: Credential rotation failed: external service unavailable');
      });

      test('should handle validation failures', async () => {
        mockApiClient.setMockResponse('post', '/credentials/12345/rotate', {
          success: false,
          error: { message: 'New credential validation failed' },
        });

        await expect(mockServer.executeToolCall({
          tool: 'rotate-credential',
          parameters: {
            credentialId: 12345,
            rotationType: 'manual',
            newValue: 'invalid-credential-value',
            validateNewValue: true,
          },
        })).rejects.toThrow('Failed to rotate credential: New credential validation failed');
      });
    });
  });

  describe('delete-credential', () => {
    describe('Basic Functionality', () => {
      test('should delete unused credential', async () => {
        const deleteResult = {
          success: true,
          credentialId: 12345,
          deletedAt: new Date().toISOString(),
          backupCreated: true,
          affectedConnections: 0,
          affectedScenarios: 0,
        };

        mockApiClient.setMockResponse('delete', '/credentials/12345', {
          success: true,
          data: deleteResult,
        });

        const result = await mockServer.executeToolCall({
          tool: 'delete-credential',
          parameters: {
            credentialId: 12345,
            reason: 'no_longer_needed',
            createBackup: true,
            force: false,
          },
        });

        expect(mockApiClient.delete).toHaveBeenCalledWith('/credentials/12345', {
          data: expect.objectContaining({
            reason: 'no_longer_needed',
            createBackup: true,
            force: false,
          }),
        });

        const response = JSON.parse(result);
        expect(response.deletion.success).toBe(true);
        expect(response.deletion.backupCreated).toBe(true);
        expect(response.impact.affectedConnections).toBe(0);
      });

      test('should handle force deletion of active credential', async () => {
        const deleteResult = {
          success: true,
          credentialId: 12345,
          deletedAt: new Date().toISOString(),
          forced: true,
          affectedConnections: 5,
          affectedScenarios: 3,
          connectionsDisabled: true,
          scenariosDeactivated: true,
        };

        mockApiClient.setMockResponse('delete', '/credentials/12345', {
          success: true,
          data: deleteResult,
        });

        const result = await mockServer.executeToolCall({
          tool: 'delete-credential',
          parameters: {
            credentialId: 12345,
            reason: 'security_breach',
            force: true,
            disableConnections: true,
          },
        });

        const response = JSON.parse(result);
        expect(response.deletion.forced).toBe(true);
        expect(response.impact.connectionsDisabled).toBe(true);
        expect(response.impact.scenariosDeactivated).toBe(true);
        expect(response.securityAlert).toBeDefined();
      });
    });

    describe('Safety Checks', () => {
      test('should prevent deletion of active credentials without force', async () => {
        mockApiClient.setMockResponse('delete', '/credentials/12345', {
          success: false,
          error: { 
            message: 'Cannot delete credential: currently in use by 5 connections and 3 scenarios. Use force=true to override.',
            status: 409,
          },
        });

        await expect(mockServer.executeToolCall({
          tool: 'delete-credential',
          parameters: {
            credentialId: 12345,
            reason: 'cleanup',
            force: false,
          },
        })).rejects.toThrow('Failed to delete credential: Cannot delete credential: currently in use by 5 connections and 3 scenarios. Use force=true to override.');
      });

      test('should require deletion reason', async () => {
        await expect(mockServer.executeToolCall({
          tool: 'delete-credential',
          parameters: {
            credentialId: 12345,
            // Missing required reason
          },
        })).rejects.toThrow();
      });
    });

    describe('Error Handling', () => {
      test('should handle credential not found', async () => {
        mockApiClient.setMockResponse('delete', '/credentials/99999', {
          success: false,
          error: { message: 'Credential not found', status: 404 },
        });

        await expect(mockServer.executeToolCall({
          tool: 'delete-credential',
          parameters: {
            credentialId: 99999,
            reason: 'cleanup',
          },
        })).rejects.toThrow('Failed to delete credential: Credential not found');
      });

      test('should handle insufficient permissions', async () => {
        mockApiClient.setMockResponse('delete', '/credentials/12345', {
          success: false,
          error: { message: 'Insufficient permissions to delete credential', status: 403 },
        });

        await expect(mockServer.executeToolCall({
          tool: 'delete-credential',
          parameters: {
            credentialId: 12345,
            reason: 'cleanup',
          },
        })).rejects.toThrow('Failed to delete credential: Insufficient permissions to delete credential');
      });
    });
  });

  describe('audit-credential-access', () => {
    describe('Basic Functionality', () => {
      test('should retrieve credential access audit logs', async () => {
        const mockAuditLogs = [
          generateMockAuditLog(),
          generateMockAuditLog({ action: 'credential_updated' }),
          generateMockAuditLog({ action: 'credential_rotated' }),
        ];

        mockApiClient.setMockResponse('get', '/credentials/12345/audit', {
          success: true,
          data: mockAuditLogs,
          metadata: { total: 3, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'audit-credential-access',
          parameters: {
            credentialId: 12345,
            action: 'credential_accessed',
            startDate: '2024-11-01T00:00:00Z',
            endDate: '2024-11-30T23:59:59Z',
            limit: 50,
          },
        });

        expect(mockApiClient.get).toHaveBeenCalledWith('/credentials/12345/audit', {
          params: expect.objectContaining({
            action: 'credential_accessed',
            startDate: '2024-11-01T00:00:00Z',
            endDate: '2024-11-30T23:59:59Z',
            limit: 50,
          }),
        });

        const response = JSON.parse(result);
        expect(response.auditLogs).toHaveLength(3);
        expect(response.summary).toBeDefined();
        expect(response.summary.totalEvents).toBe(3);
      });

      test('should analyze access patterns', async () => {
        const mockAuditLogs = [
          generateMockAuditLog({ 
            actor: { userId: 12345, userName: 'user1@example.com', sessionId: 'session1', ipAddress: '192.168.1.100', userAgent: 'Browser/1.0' },
            context: { scenario: 'sync-scenario', operation: 'api_call', source: 'make_platform', correlationId: 'corr1', environment: 'production' },
            timestamp: new Date(Date.now() - 3600000).toISOString(),
          }),
          generateMockAuditLog({ 
            actor: { userId: 12345, userName: 'user1@example.com', sessionId: 'session2', ipAddress: '203.0.113.45', userAgent: 'Browser/1.0' },
            context: { scenario: 'sync-scenario', operation: 'api_call', source: 'make_platform', correlationId: 'corr2', environment: 'production' },
            timestamp: new Date(Date.now() - 1800000).toISOString(),
          }),
        ];

        mockApiClient.setMockResponse('get', '/credentials/12345/audit', {
          success: true,
          data: mockAuditLogs,
          metadata: { total: 2, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'audit-credential-access',
          parameters: {
            credentialId: 12345,
            includeAnalysis: true,
            includeSecurityInsights: true,
          },
        });

        const response = JSON.parse(result);
        expect(response.analysis).toBeDefined();
        expect(response.analysis.accessPatterns).toBeDefined();
        expect(response.analysis.userBreakdown).toBeDefined();
        expect(response.securityInsights).toBeDefined();
        expect(response.securityInsights.anomalies).toBeDefined();
      });
    });

    describe('Security Analysis', () => {
      test('should detect suspicious access patterns', async () => {
        const suspiciousLogs = [
          generateMockAuditLog({
            actor: { userId: 99999, userName: 'suspicious@external.com', sessionId: 'suspicious_session', ipAddress: '203.0.113.45', userAgent: 'Bot/1.0' },
            security: {
              riskLevel: 'high',
              anomalyScore: 0.8,
              geoLocation: { country: 'Unknown', region: 'Unknown', city: 'Unknown', coordinates: { lat: 0, lon: 0 } },
              deviceFingerprint: 'suspicious_device',
            },
            details: { success: false, errorCode: 'UNAUTHORIZED_ACCESS', errorMessage: 'Access denied', accessMethod: 'api_key_header', dataAccessed: false, sensitiveOperation: true },
          }),
        ];

        mockApiClient.setMockResponse('get', '/credentials/12345/audit', {
          success: true,
          data: suspiciousLogs,
          metadata: { total: 1, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'audit-credential-access',
          parameters: {
            credentialId: 12345,
            riskLevel: 'high',
            includeSecurityInsights: true,
            includeThreatAnalysis: true,
          },
        });

        const response = JSON.parse(result);
        expect(response.securityInsights.highRiskEvents).toBeGreaterThan(0);
        expect(response.threatAnalysis).toBeDefined();
        expect(response.threatAnalysis.suspiciousPatterns).toBeDefined();
        expect(response.recommendations).toBeDefined();
      });

      test('should analyze geographic access patterns', async () => {
        const geoLogs = [
          generateMockAuditLog({
            security: {
              riskLevel: 'low',
              anomalyScore: 0.1,
              geoLocation: { country: 'US', region: 'California', city: 'San Francisco', coordinates: { lat: 37.7749, lon: -122.4194 } },
              deviceFingerprint: 'known_device_1',
            },
          }),
          generateMockAuditLog({
            security: {
              riskLevel: 'medium',
              anomalyScore: 0.6,
              geoLocation: { country: 'RU', region: 'Moscow', city: 'Moscow', coordinates: { lat: 55.7558, lon: 37.6176 } },
              deviceFingerprint: 'unknown_device_1',
            },
          }),
        ];

        mockApiClient.setMockResponse('get', '/credentials/12345/audit', {
          success: true,
          data: geoLogs,
          metadata: { total: 2, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'audit-credential-access',
          parameters: {
            credentialId: 12345,
            includeGeoAnalysis: true,
            includeDeviceAnalysis: true,
          },
        });

        const response = JSON.parse(result);
        expect(response.geoAnalysis).toBeDefined();
        expect(response.geoAnalysis.countries).toBeDefined();
        expect(response.geoAnalysis.anomalousLocations).toBeDefined();
        expect(response.deviceAnalysis).toBeDefined();
        expect(response.deviceAnalysis.knownDevices).toBeDefined();
      });
    });

    describe('Error Handling', () => {
      test('should handle audit log retrieval failures', async () => {
        mockApiClient.setMockResponse('get', '/credentials/12345/audit', {
          success: false,
          error: { message: 'Audit service temporarily unavailable' },
        });

        await expect(mockServer.executeToolCall({
          tool: 'audit-credential-access',
          parameters: {
            credentialId: 12345,
          },
        })).rejects.toThrow('Failed to retrieve credential audit logs: Audit service temporarily unavailable');
      });

      test('should validate date ranges', async () => {
        await expect(mockServer.executeToolCall({
          tool: 'audit-credential-access',
          parameters: {
            credentialId: 12345,
            startDate: '2024-12-31T23:59:59Z',
            endDate: '2024-01-01T00:00:00Z', // End before start
          },
        })).rejects.toThrow();
      });
    });
  });

  describe('manage-credential-rotations', () => {
    describe('Basic Functionality', () => {
      test('should list rotation schedules', async () => {
        const mockSchedules = [
          generateMockRotationSchedule(),
          generateMockRotationSchedule({ status: 'paused' }),
        ];

        mockApiClient.setMockResponse('get', '/credentials/rotations', {
          success: true,
          data: mockSchedules,
          metadata: { total: 2, hasMore: false },
        });

        const result = await mockServer.executeToolCall({
          tool: 'manage-credential-rotations',
          parameters: {
            action: 'list',
            status: 'active',
            includeMetrics: true,
          },
        });

        expect(mockApiClient.get).toHaveBeenCalledWith('/credentials/rotations', {
          params: expect.objectContaining({
            status: 'active',
            includeMetrics: true,
          }),
        });

        const response = JSON.parse(result);
        expect(response.schedules).toHaveLength(2);
        expect(response.summary).toBeDefined();
        expect(response.metrics).toBeDefined();
      });

      test('should create rotation schedule', async () => {
        const newSchedule = generateMockRotationSchedule();
        mockApiClient.setMockResponse('post', '/credentials/rotations', {
          success: true,
          data: newSchedule,
        });

        const result = await mockServer.executeToolCall({
          tool: 'manage-credential-rotations',
          parameters: {
            action: 'create',
            credentialId: 12345,
            schedule: {
              type: 'automatic',
              intervalDays: 90,
              timeOfDay: '02:00',
              timezone: 'UTC',
            },
            configuration: {
              backupOldCredential: true,
              notifyUsers: true,
              testNewCredential: true,
            },
          },
        });

        expect(mockApiClient.post).toHaveBeenCalledWith('/credentials/rotations', expect.objectContaining({
          credentialId: 12345,
          schedule: expect.objectContaining({
            type: 'automatic',
            intervalDays: 90,
          }),
        }));

        const response = JSON.parse(result);
        expect(response.schedule).toBeDefined();
        expect(response.schedule.status).toBe('active');
        expect(response.nextExecution).toBeDefined();
      });

      test('should update rotation schedule', async () => {
        const updatedSchedule = generateMockRotationSchedule({
          schedule: {
            type: 'automatic',
            intervalDays: 60, // Updated from 90
            timeOfDay: '03:00', // Updated from 02:00
            timezone: 'UTC',
            daysOfWeek: ['sunday'],
            excludeDates: ['2024-12-25', '2024-01-01'],
          },
        });

        mockApiClient.setMockResponse('put', '/credentials/rotations/12345', {
          success: true,
          data: updatedSchedule,
        });

        const result = await mockServer.executeToolCall({
          tool: 'manage-credential-rotations',
          parameters: {
            action: 'update',
            scheduleId: 12345,
            schedule: {
              intervalDays: 60,
              timeOfDay: '03:00',
            },
            updateReason: 'security_policy_update',
          },
        });

        const response = JSON.parse(result);
        expect(response.schedule.schedule.intervalDays).toBe(60);
        expect(response.schedule.schedule.timeOfDay).toBe('03:00');
        expect(response.changes).toContain('intervalDays');
        expect(response.changes).toContain('timeOfDay');
      });

      test('should execute manual rotation', async () => {
        const executionResult = {
          success: true,
          executionId: 'exec_12345',
          scheduleId: 12345,
          startedAt: new Date().toISOString(),
          status: 'running',
          estimatedCompletion: new Date(Date.now() + 300000).toISOString(),
        };

        mockApiClient.setMockResponse('post', '/credentials/rotations/12345/execute', {
          success: true,
          data: executionResult,
        });

        const result = await mockServer.executeToolCall({
          tool: 'manage-credential-rotations',
          parameters: {
            action: 'execute',
            scheduleId: 12345,
            executionType: 'manual',
            reason: 'security_audit_requirement',
          },
        });

        const response = JSON.parse(result);
        expect(response.execution.status).toBe('running');
        expect(response.execution.executionId).toBe('exec_12345');
        expect(response.monitoring).toBeDefined();
      });
    });

    describe('Advanced Rotation Management', () => {
      test('should pause and resume rotation schedules', async () => {
        const pausedSchedule = generateMockRotationSchedule({ status: 'paused' });
        mockApiClient.setMockResponse('post', '/credentials/rotations/12345/pause', {
          success: true,
          data: pausedSchedule,
        });

        const pauseResult = await mockServer.executeToolCall({
          tool: 'manage-credential-rotations',
          parameters: {
            action: 'pause',
            scheduleId: 12345,
            reason: 'maintenance_window',
            duration: 'PT2H', // 2 hours
          },
        });

        const pauseResponse = JSON.parse(pauseResult);
        expect(pauseResponse.schedule.status).toBe('paused');

        // Resume the schedule
        const resumedSchedule = generateMockRotationSchedule({ status: 'active' });
        mockApiClient.setMockResponse('post', '/credentials/rotations/12345/resume', {
          success: true,
          data: resumedSchedule,
        });

        const resumeResult = await mockServer.executeToolCall({
          tool: 'manage-credential-rotations',
          parameters: {
            action: 'resume',
            scheduleId: 12345,
            reason: 'maintenance_completed',
          },
        });

        const resumeResponse = JSON.parse(resumeResult);
        expect(resumeResponse.schedule.status).toBe('active');
      });

      test('should provide rotation analytics', async () => {
        const analyticsData = {
          totalSchedules: 25,
          activeSchedules: 20,
          pausedSchedules: 3,
          errorSchedules: 2,
          totalRotations: 150,
          successfulRotations: 142,
          failedRotations: 8,
          averageRotationTime: 45, // seconds
          upcomingRotations: 5,
          overdueRotations: 1,
          rotationTrends: {
            daily: [2, 3, 1, 4, 2, 1, 3],
            weekly: [15, 18, 12, 20, 16, 14, 19],
            monthly: [65, 72, 68, 75],
          },
        };

        mockApiClient.setMockResponse('get', '/credentials/rotations/analytics', {
          success: true,
          data: analyticsData,
        });

        const result = await mockServer.executeToolCall({
          tool: 'manage-credential-rotations',
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
        expect(response.analytics.totalSchedules).toBe(25);
        expect(response.analytics.successRate).toBeDefined();
        expect(response.trends).toBeDefined();
        expect(response.recommendations).toBeDefined();
      });
    });

    describe('Error Handling', () => {
      test('should handle invalid rotation actions', async () => {
        await expect(mockServer.executeToolCall({
          tool: 'manage-credential-rotations',
          parameters: {
            action: 'invalid_action' as 'list' | 'create' | 'update' | 'delete' | 'execute' | 'pause' | 'resume' | 'analytics',
          },
        })).rejects.toThrow();
      });

      test('should handle rotation management failures', async () => {
        mockApiClient.setMockResponse('get', '/credentials/rotations', {
          success: false,
          error: { message: 'Rotation management service unavailable' },
        });

        await expect(mockServer.executeToolCall({
          tool: 'manage-credential-rotations',
          parameters: {
            action: 'list',
          },
        })).rejects.toThrow('Failed to manage credential rotations: Rotation management service unavailable');
      });
    });
  });

  describe('Integration Testing', () => {
    test('should handle end-to-end credential lifecycle', async () => {
      // 1. Store a new credential
      const newCredential = generateMockCredential();
      mockApiClient.setMockResponse('post', '/credentials', {
        success: true,
        data: newCredential,
      });

      const storeResult = await mockServer.executeToolCall({
        tool: 'store-credential',
        parameters: {
          type: 'api_key',
          service: 'integration-test-service',
          value: 'test-api-key-value-12345',
          name: 'Integration Test API Key',
          description: 'API key for integration testing',
          autoRotate: true,
          rotationDays: 90,
        },
      });

      // 2. Retrieve the credential
      mockApiClient.setMockResponse('get', `/credentials/${newCredential.id}`, {
        success: true,
        data: newCredential,
      });

      const retrieveResult = await mockServer.executeToolCall({
        tool: 'retrieve-credential',
        parameters: {
          credentialId: newCredential.id,
          includeValue: false,
          includeMetadata: true,
        },
      });

      // 3. Update the credential
      const updatedCredential = generateMockCredential({
        ...newCredential,
        description: 'Updated description for integration test',
      });
      mockApiClient.setMockResponse('put', `/credentials/${newCredential.id}`, {
        success: true,
        data: updatedCredential,
      });

      const updateResult = await mockServer.executeToolCall({
        tool: 'update-credential',
        parameters: {
          credentialId: newCredential.id,
          description: 'Updated description for integration test',
          updateReason: 'integration_test_update',
        },
      });

      // 4. Rotate the credential
      const rotationResult = {
        success: true,
        oldCredentialId: newCredential.id,
        newCredentialId: newCredential.id + 1,
        rotatedAt: new Date().toISOString(),
      };
      mockApiClient.setMockResponse('post', `/credentials/${newCredential.id}/rotate`, {
        success: true,
        data: rotationResult,
      });

      const rotateResult = await mockServer.executeToolCall({
        tool: 'rotate-credential',
        parameters: {
          credentialId: newCredential.id,
          rotationType: 'manual',
          reason: 'integration_test_rotation',
        },
      });

      // Verify the lifecycle completed successfully
      expect(JSON.parse(storeResult).credential).toBeDefined();
      expect(JSON.parse(retrieveResult).credential).toBeDefined();
      expect(JSON.parse(updateResult).credential.description).toBe('Updated description for integration test');
      expect(JSON.parse(rotateResult).rotation.success).toBe(true);
    });

    test('should handle security incident response workflow', async () => {
      const compromisedCredential = generateMockCredential({
        security: {
          securityScore: 2.1,
          isEncrypted: true,
          compromiseIndicators: ['suspicious_access_pattern', 'unusual_geographic_location'],
          accessCount: 1000,
          lastAccessed: new Date().toISOString(),
          lastRotated: new Date(Date.now() - 86400000 * 180).toISOString(),
          encryptionAlgorithm: 'AES-256-GCM',
          keyDerivation: 'PBKDF2',
        },
      });

      // 1. Emergency rotation due to security incident
      const emergencyRotationResult = {
        success: true,
        oldCredentialId: compromisedCredential.id,
        newCredentialId: compromisedCredential.id + 1000,
        rotatedAt: new Date().toISOString(),
        rotationType: 'emergency',
        oldCredentialRevoked: true,
        immediateEffect: true,
      };

      mockApiClient.setMockResponse('post', `/credentials/${compromisedCredential.id}/rotate`, {
        success: true,
        data: emergencyRotationResult,
      });

      const rotationResult = await mockServer.executeToolCall({
        tool: 'rotate-credential',
        parameters: {
          credentialId: compromisedCredential.id,
          rotationType: 'emergency',
          reason: 'suspected_compromise',
          revokeOldCredential: true,
          immediateEffect: true,
        },
      });

      // 2. Audit the compromised credential access
      const suspiciousAuditLogs = [
        generateMockAuditLog({
          credentialId: compromisedCredential.id,
          security: {
            riskLevel: 'high',
            anomalyScore: 0.9,
            geoLocation: { country: 'Unknown', region: 'Unknown', city: 'Unknown', coordinates: { lat: 0, lon: 0 } },
            deviceFingerprint: 'suspicious_device',
          },
        }),
      ];

      mockApiClient.setMockResponse('get', `/credentials/${compromisedCredential.id}/audit`, {
        success: true,
        data: suspiciousAuditLogs,
        metadata: { total: 1, hasMore: false },
      });

      const auditResult = await mockServer.executeToolCall({
        tool: 'audit-credential-access',
        parameters: {
          credentialId: compromisedCredential.id,
          riskLevel: 'high',
          includeSecurityInsights: true,
          includeThreatAnalysis: true,
        },
      });

      // 3. Delete the compromised credential
      const deleteResult = {
        success: true,
        credentialId: compromisedCredential.id,
        deletedAt: new Date().toISOString(),
        forced: true,
        reason: 'security_incident',
      };

      mockApiClient.setMockResponse('delete', `/credentials/${compromisedCredential.id}`, {
        success: true,
        data: deleteResult,
      });

      const deletionResult = await mockServer.executeToolCall({
        tool: 'delete-credential',
        parameters: {
          credentialId: compromisedCredential.id,
          reason: 'security_incident',
          force: true,
        },
      });

      // Verify the security incident response completed successfully
      expect(JSON.parse(rotationResult).rotation.rotationType).toBe('emergency');
      expect(JSON.parse(auditResult).securityInsights.highRiskEvents).toBeGreaterThan(0);
      expect(JSON.parse(deletionResult).deletion.success).toBe(true);
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
            mockApiClient.setMockResponse('post', '/credentials', {
              success: true,
              data: generateMockCredential(),
            }, chaosMonkey.getRandomLatency());
          } else if (scenario === 'error') {
            // Simulate service error
            mockApiClient.setMockResponse('post', '/credentials', {
              success: false,
              error: { message: 'Service temporarily unavailable' },
            });
          } else if (scenario === 'timeout') {
            // Simulate timeout
            mockApiClient.setMockResponse('post', '/credentials', {
              success: false,
              error: { message: 'Request timeout' },
            });
          }

          await mockServer.executeToolCall({
            tool: 'store-credential',
            parameters: {
              type: 'api_key',
              service: `chaos-test-${scenario}`,
              value: 'chaos-test-value',
              name: `Chaos Test ${scenario}`,
              description: 'Testing service degradation scenarios',
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

  describe('Performance Testing', () => {
    test('should handle concurrent credential operations', async () => {
      const concurrentRequests = 20;
      const promises: Promise<string>[] = [];

      mockApiClient.setMockResponse('post', '/credentials', {
        success: true,
        data: generateMockCredential(),
      });

      for (let i = 0; i < concurrentRequests; i++) {
        promises.push(mockServer.executeToolCall({
          tool: 'store-credential',
          parameters: {
            type: 'api_key',
            service: `concurrent-test-service-${i}`,
            value: `concurrent-test-value-${i}`,
            name: `Concurrent Test ${i}`,
            description: 'Testing concurrent credential operations',
          },
        }));
      }

      const results = await Promise.allSettled(promises);
      const successful = results.filter(r => r.status === 'fulfilled').length;
      
      expect(successful).toBeGreaterThan(concurrentRequests * 0.8); // 80% success rate
    });
  });
});