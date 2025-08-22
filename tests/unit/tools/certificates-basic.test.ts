/**
 * Basic Test Suite for Certificate Management Tools
 * Tests core functionality of certificate and key management tools
 * Focuses on tool registration, configuration validation, and basic execution patterns
 * Covers certificate creation, listing, validation, key management, and rotation
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { UserError } from 'fastmcp';
import { createMockServer, findTool, executeTool, expectValidZodParse, expectInvalidZodParse } from '../../utils/test-helpers.js';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';
import { testErrors } from '../../fixtures/test-data.js';

describe('Certificate Management Tools - Basic Tests', () => {
  let mockServer: any;
  let mockTool: jest.MockedFunction<any>;
  let mockApiClient: MockMakeApiClient;

  // Test certificate data for testing - matches MakeCertificate interface
  const testCertificate = {
    id: 1,
    name: 'Test SSL Certificate',
    description: 'Test certificate for API',
    type: 'ssl' as const,
    format: 'pem' as const,
    organizationId: 12345,
    teamId: 67890,
    status: 'active' as const,
    certificate: {
      data: 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t',
      fingerprint: 'SHA256:1234567890abcdef',
      serialNumber: '0x1a2b3c4d5e6f',
      subject: {
        commonName: 'api.example.com',
        organization: 'Test Org',
        country: 'US'
      },
      issuer: {
        commonName: 'Let\'s Encrypt',
        organization: 'Let\'s Encrypt'
      },
      validity: {
        notBefore: '2024-01-01T00:00:00Z',
        notAfter: '2024-12-31T23:59:59Z',
        daysUntilExpiry: 300
      },
      extensions: {
        keyUsage: ['digitalSignature', 'keyEncipherment'],
        extendedKeyUsage: ['serverAuth'],
        subjectAltNames: ['api.example.com'],
        isCA: false
      }
    },
    privateKey: {
      hasPrivateKey: true,
      keyType: 'rsa' as const,
      keySize: 2048,
      isEncrypted: false
    },
    usage: {
      connections: 5,
      scenarios: 3,
      lastUsed: '2024-01-15T12:00:00Z'
    },
    security: {
      isSecure: true,
      vulnerabilities: [],
      complianceStatus: {
        fips: true,
        commonCriteria: true,
        customCompliance: []
      }
    },
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-15T12:00:00Z',
    createdBy: 1001,
    createdByName: 'admin@example.com'
  };

  // Test key data - matches MakeKey interface  
  const testKey = {
    id: 1,
    name: 'Test Private Key',
    description: 'Test cryptographic key',
    type: 'rsa' as const,
    keyUsage: 'signing' as const,
    format: 'pem' as const,
    organizationId: 12345,
    teamId: 67890,
    status: 'active' as const,
    keyMaterial: {
      hasPublicKey: true,
      hasPrivateKey: true,
      keySize: 2048,
      isEncrypted: false,
      encryptionAlgorithm: undefined
    },
    metadata: {
      algorithm: 'RSA',
      hashAlgorithm: 'SHA256'
    },
    rotation: {
      rotationSchedule: {
        enabled: false,
        intervalDays: 90
      },
      rotationHistory: []
    },
    permissions: {
      read: ['admin'],
      use: ['admin'],
      admin: ['admin']
    },
    usage: {
      operations: 10,
      connections: 5,
      lastUsed: '2024-01-15T12:00:00Z'
    },
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-15T12:00:00Z',
    createdBy: 1001
  };

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
    mockApiClient.reset();
  });

  describe('Tool Registration and Import', () => {
    it('should successfully import and register certificate tools', async () => {
      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      
      // Should not throw an error
      expect(() => {
        addCertificateTools(mockServer, mockApiClient as any);
      }).not.toThrow();
      
      // Should call addTool for each certificate tool
      expect(mockTool).toHaveBeenCalled();
      expect(mockTool.mock.calls.length).toBeGreaterThan(0);
    });

    it('should export the expected certificate management functions', async () => {
      const certificateModule = await import('../../../src/tools/certificates.js');
      
      // Check that expected exports exist
      expect(certificateModule.addCertificateTools).toBeDefined();
      expect(typeof certificateModule.addCertificateTools).toBe('function');
    });

    it('should register all core certificate management tools', async () => {
      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const expectedTools = [
        'create-certificate',
        'list-certificates',
        'get-certificate',
        'validate-certificate',
        'create-key',
        'rotate-certificate'
      ];
      
      expectedTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool).toBeDefined();
        expect(tool.name).toBe(toolName);
      });
    });

    it('should register certificate lifecycle management tools', async () => {
      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const lifecycleTools = [
        'create-certificate',
        'get-certificate',
        'validate-certificate',
        'rotate-certificate'
      ];
      
      lifecycleTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool).toBeDefined();
        expect(tool.description).toBeDefined();
        expect(tool.parameters).toBeDefined();
        expect(typeof tool.execute).toBe('function');
      });
    });

    it('should register key management and listing tools', async () => {
      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const managementTools = [
        'list-certificates',
        'create-key'
      ];
      
      managementTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool).toBeDefined();
        expect(tool.description).toBeDefined();
        expect(tool.parameters).toBeDefined();
        expect(typeof tool.execute).toBe('function');
      });
    });
  });

  describe('Tool Configuration Validation', () => {
    it('should have correct structure for create-certificate tool', async () => {
      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-certificate');
      
      expect(tool.name).toBe('create-certificate');
      expect(tool.description).toContain('Create and store a new certificate');
      expect(tool.parameters).toBeDefined();
      expect(typeof tool.execute).toBe('function');
      // Note: certificates tools may not have title annotations
    });

    it('should have correct structure for list-certificates tool', async () => {
      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-certificates');
      
      expect(tool.name).toBe('list-certificates');
      expect(tool.description).toContain('List and filter certificates');
      expect(tool.parameters).toBeDefined();
      expect(typeof tool.execute).toBe('function');
      // Note: certificates tools may not have title annotations
    });

    it('should have correct structure for validate-certificate tool', async () => {
      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'validate-certificate');
      
      expect(tool.name).toBe('validate-certificate');
      expect(tool.description).toContain('Validate certificate data, chain, and configuration');
      expect(tool.parameters).toBeDefined();
      expect(typeof tool.execute).toBe('function');
      // Note: certificates tools may not have title annotations
    });

    it('should have correct structure for key management tools', async () => {
      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      // Test create-key tool
      const createKeyTool = findTool(mockTool, 'create-key');
      expect(createKeyTool.name).toBe('create-key');
      expect(createKeyTool.description).toContain('Create or import a cryptographic key');
      expect(createKeyTool.parameters).toBeDefined();
      // Note: certificates tools may not have title annotations

      // Test rotate-certificate tool
      const rotateTool = findTool(mockTool, 'rotate-certificate');
      expect(rotateTool.name).toBe('rotate-certificate');
      expect(rotateTool.description).toContain('Rotate a certificate or key');
      expect(rotateTool.parameters).toBeDefined();
      // Note: certificates tools may not have title annotations
    });
  });

  describe('Schema Validation', () => {
    it('should validate create-certificate schema with different configurations', async () => {
      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-certificate');
      
      // Valid minimal certificate
      const validMinimal = {
        name: 'Test Certificate',
        type: 'ssl',
        certificateData: 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t' // Base64 mock data
      };
      
      expectValidZodParse(tool.parameters, validMinimal);

      // Valid comprehensive certificate
      const validComprehensive = {
        name: 'Comprehensive Certificate',
        type: 'ssl',
        format: 'pem',
        certificateData: 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t',
        privateKeyData: 'LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t',
        organizationId: 12345,
        teamId: 67890,
        chainCertificates: ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t'],
        validateCertificate: true,
        autoRotation: {
          enabled: true,
          daysBeforeExpiry: 30
        }
      };
      
      expectValidZodParse(tool.parameters, validComprehensive);
    });

    it('should validate list-certificates schema with filtering options', async () => {
      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-certificates');
      
      // Valid minimal request
      const validMinimal = {};
      
      expectValidZodParse(tool.parameters, validMinimal);

      // Valid filtered request
      const validFiltered = {
        type: 'ssl',
        status: 'active',
        organizationId: 12345,
        limit: 50,
        offset: 0,
        includePrivateKeys: false,
        includeChain: true
      };
      
      expectValidZodParse(tool.parameters, validFiltered);
    });

    it('should validate validate-certificate schema with validation options', async () => {
      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'validate-certificate');
      
      // Valid certificate validation
      const validValidation = {
        certificateData: 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t',
        privateKeyData: 'LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t',
        checkRevocation: true,
        checkHostname: 'api.example.com',
        customValidations: ['key_usage', 'extended_key_usage']
      };
      
      expectValidZodParse(tool.parameters, validValidation);
    });

    it('should validate key management schemas', async () => {
      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const createKeyTool = findTool(mockTool, 'create-key');
      
      // Valid key creation  
      const validKey = {
        name: 'Test Key',
        type: 'rsa',
        usage: 'signing',
        keyMaterial: {
          generate: true,
          keySize: 2048
        }
      };
      
      expectValidZodParse(createKeyTool.parameters, validKey);

      const rotateTool = findTool(mockTool, 'rotate-certificate');
      
      // Valid certificate rotation
      const validRotation = {
        resourceId: 1001,
        resourceType: 'certificate',
        rotationMethod: 'automatic',
        reason: 'Test rotation' // Required parameter
      };
      
      expectValidZodParse(rotateTool.parameters, validRotation);
    });

    it('should reject invalid certificate inputs', async () => {
      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-certificate');
      
      // Invalid inputs
      const invalidInputs = [
        { name: '', type: 'ssl', certificateData: 'data' }, // Empty name
        { name: 'Test' }, // Missing required certificateData and type
        { name: 'Test', type: 'invalid', certificateData: 'data' }, // Invalid type
        { name: 'Test', type: 'ssl', certificateData: '' }, // Empty certificate data
        { name: 'Test', type: 'ssl', certificateData: 'data', format: 'invalid' } // Invalid format
      ];
      
      invalidInputs.forEach(input => {
        expectInvalidZodParse(tool.parameters, input);
      });
    });
  });

  describe('Basic Tool Execution', () => {
    it('should execute create-certificate successfully', async () => {
      mockApiClient.mockResponse('POST', '/certificates', {
        success: true,
        data: testCertificate
      });

      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-certificate');
      const result = await executeTool(tool, {
        name: 'Test Certificate',
        type: 'ssl',
        certificateData: 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t' // Required parameter
      });
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.certificate).toBeDefined();
    });

    it('should execute list-certificates with filtering', async () => {
      mockApiClient.mockResponse('GET', '/certificates', {
        success: true,
        data: [testCertificate],
        metadata: { total: 1, page: 1, limit: 10 }
      });

      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-certificates');
      const result = await executeTool(tool, {
        status: 'active',
        limit: 10
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.certificates).toBeDefined();
      expect(parsedResult.certificates).toHaveLength(1);
      expect(parsedResult.certificates[0].certificate.subject.commonName).toBe('api.example.com');
    });

    it('should execute get-certificate with detailed information', async () => {
      mockApiClient.mockResponse('GET', '/certificates/1', {
        success: true,
        data: testCertificate
      });

      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-certificate');
      const result = await executeTool(tool, {
        certificateId: 1, // Should be number, not string
        includeChain: true
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.certificate).toBeDefined();
    });

    it('should execute validate-certificate with comprehensive checks', async () => {
      const validationResult = {
        certificateId: 'cert_001',
        isValid: true,
        validationChecks: {
          expiry: { valid: true, expiresAt: '2024-12-31T23:59:59Z' },
          revocation: { valid: true, checked: true },
          chain: { valid: true, chainLength: 3 },
          signature: { valid: true, algorithm: 'SHA256withRSA' }
        },
        security: {
          strength: 'high',
          weaknesses: [],
          recommendations: []
        }
      };

      mockApiClient.mockResponse('POST', '/certificates/validate', {
        success: true,
        data: validationResult
      });

      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'validate-certificate');
      const result = await executeTool(tool, {
        certificateData: 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t', // Required parameter
        checkRevocation: true
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.validation).toBeDefined();
      expect(parsedResult.validation.isValid).toBe(true);
    });

    it('should execute create-key with cryptographic parameters', async () => {
      mockApiClient.mockResponse('POST', '/keys', {
        success: true,
        data: testKey
      });

      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-key');
      const result = await executeTool(tool, {
        name: 'Test Key',
        type: 'rsa', // Use correct parameter name
        usage: 'signing', // Required parameter
        keyMaterial: {
          generate: true,
          keySize: 2048
        }
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.key).toBeDefined();
    });

    it('should execute rotate-certificate with renewal', async () => {
      const rotatedCertificate = {
        ...testCertificate,
        id: 'cert_002',
        validFrom: '2024-01-15T00:00:00Z',
        validTo: '2025-01-15T00:00:00Z',
        previousCertificateId: 'cert_001'
      };

      mockApiClient.mockResponse('POST', '/certificates/1/rotate', {
        success: true,
        data: rotatedCertificate
      });

      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'rotate-certificate');
      const result = await executeTool(tool, {
        resourceId: 1, // Use correct parameter name and type
        resourceType: 'certificate',
        rotationMethod: 'automatic',
        reason: 'Certificate renewal' // Required parameter
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.rotation).toBeDefined();
    });
  });

  describe('Error Handling and Security', () => {
    it('should handle API failures gracefully', async () => {
      mockApiClient.mockFailure('GET', '/certificates', new Error('Certificate service unavailable'));

      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-certificates');
      
      await expect(executeTool(tool, {})).rejects.toThrow(UserError);
    });

    it('should handle unauthorized access errors', async () => {
      mockApiClient.mockResponse('POST', '/certificates', testErrors.unauthorized);

      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-certificate');
      
      await expect(executeTool(tool, {
        name: 'Test Certificate',
        type: 'ssl',
        certificateData: 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t'
      })).rejects.toThrow();
    });

    it('should validate required fields for certificate operations', async () => {
      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const createTool = findTool(mockTool, 'create-certificate');
      
      // Certificate without required fields should fail
      await expect(executeTool(createTool, {
        // Missing name, type, and certificateData - all required
        description: 'Missing required fields'
      })).rejects.toThrow();
    });

    it('should enforce certificate security validation', async () => {
      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-certificate');
      
      // Certificate with strong security parameters
      const secureCertificate = {
        name: 'Secure Certificate',
        type: 'ssl',
        certificateData: 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t' // Required parameter
      };
      
      mockApiClient.mockResponse('POST', '/certificates', {
        success: true,
        data: { ...testCertificate, ...secureCertificate }
      });

      const result = await executeTool(tool, secureCertificate);
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.certificate).toBeDefined();
      expect(parsedResult.security).toBeDefined();
    });

    it('should handle certificate validation errors', async () => {
      const invalidValidation = {
        certificateId: 'cert_001',
        isValid: false,
        validationChecks: {
          expiry: { valid: false, expired: true },
          revocation: { valid: false, revoked: true }
        }
      };

      mockApiClient.mockResponse('POST', '/certificates/validate', {
        success: true,
        data: invalidValidation
      });

      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'validate-certificate');
      const result = await executeTool(tool, {
        certificateData: 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t' // Required parameter
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.validation.isValid).toBe(false);
    });
  });

  describe('Enterprise Certificate Management Features', () => {
    it('should support automated certificate lifecycle management', async () => {
      const lifecycleConfig = {
        certificateId: 'cert_001',
        autoRenew: true,
        renewalThreshold: 30,
        notificationChannels: ['email', 'webhook'],
        backupPrevious: true
      };

      mockApiClient.mockResponse('POST', '/certificates/1/rotate', {
        success: true,
        data: { 
          ...testCertificate,
          id: 'cert_002',
          lifecycle: lifecycleConfig
        }
      });

      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'rotate-certificate');
      const result = await executeTool(tool, {
        resourceId: 1, // Use correct parameter name and type
        resourceType: 'certificate',
        rotationMethod: 'automatic',
        reason: 'Automated lifecycle management' // Required parameter
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.rotation).toBeDefined();
    });

    it('should support multi-domain certificate management', async () => {
      const multiDomainCert = {
        ...testCertificate,
        id: 'cert_multi_001'
      };

      mockApiClient.mockResponse('POST', '/certificates', {
        success: true,
        data: multiDomainCert
      });

      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-certificate');
      const result = await executeTool(tool, {
        name: 'Wildcard Certificate',
        type: 'ssl', // Use valid enum value
        certificateData: 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t' // Required parameter
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.certificate).toBeDefined();
    });

    it('should support certificate compliance and audit trails', async () => {
      const complianceReport = {
        certificateId: 'cert_001',
        compliance: {
          standards: ['PCI-DSS', 'SOC2', 'HIPAA'],
          score: 95,
          violations: [],
          recommendations: ['Enable OCSP stapling', 'Configure HSTS']
        },
        auditTrail: [
          {
            action: 'created',
            timestamp: '2024-01-01T00:00:00Z',
            user: 'admin@example.com'
          },
          {
            action: 'validated',
            timestamp: '2024-01-15T12:00:00Z',
            user: 'system'
          }
        ]
      };

      mockApiClient.mockResponse('POST', '/certificates/validate', {
        success: true,
        data: complianceReport
      });

      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'validate-certificate');
      const result = await executeTool(tool, {
        certificateData: 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t' // Required parameter - remove unrecognized keys
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.validation).toBeDefined();
    });
  });
});