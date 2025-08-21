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

  // Test certificate data for testing
  const testCertificate = {
    id: 'cert_001',
    name: 'Test SSL Certificate',
    domain: 'api.example.com',
    type: 'ssl',
    status: 'active',
    algorithm: 'RSA',
    keySize: 2048,
    issuer: 'Let\'s Encrypt',
    subject: 'CN=api.example.com',
    validFrom: '2024-01-01T00:00:00Z',
    validTo: '2024-12-31T23:59:59Z',
    fingerprint: 'SHA256:1234567890abcdef',
    serialNumber: '0x1a2b3c4d5e6f',
    purposes: ['server_auth', 'client_auth'],
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-15T12:00:00Z'
  };

  // Test key data
  const testKey = {
    id: 'key_001',
    name: 'Test Private Key',
    algorithm: 'RSA',
    keySize: 2048,
    usage: 'signing',
    status: 'active',
    createdAt: '2024-01-01T00:00:00Z',
    expiresAt: '2025-01-01T00:00:00Z'
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
        rotationMethod: 'automatic'
      };
      
      expectValidZodParse(rotateTool.parameters, validRotation);
    });

    it('should reject invalid certificate inputs', async () => {
      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-certificate');
      
      // Invalid inputs
      const invalidInputs = [
        { name: '' }, // Empty name
        { name: 'Test' }, // Missing required certificateData
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
        domain: 'api.example.com',
        type: 'ssl'
      });
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.certificate).toBeDefined();
      expect(parsedResult.certificate.domain).toBe('api.example.com');
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
      expect(parsedResult.certificates[0].domain).toBe('api.example.com');
    });

    it('should execute get-certificate with detailed information', async () => {
      mockApiClient.mockResponse('GET', '/certificates/cert_001', {
        success: true,
        data: testCertificate
      });

      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-certificate');
      const result = await executeTool(tool, {
        certificateId: 'cert_001',
        includeChain: true
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.certificate).toBeDefined();
      expect(parsedResult.certificate.id).toBe('cert_001');
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

      mockApiClient.mockResponse('POST', '/certificates/cert_001/validate', {
        success: true,
        data: validationResult
      });

      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'validate-certificate');
      const result = await executeTool(tool, {
        certificateId: 'cert_001',
        checkRevocation: true,
        checkChain: true
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
        algorithm: 'RSA',
        keySize: 2048
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.key).toBeDefined();
      expect(parsedResult.key.algorithm).toBe('RSA');
    });

    it('should execute rotate-certificate with renewal', async () => {
      const rotatedCertificate = {
        ...testCertificate,
        id: 'cert_002',
        validFrom: '2024-01-15T00:00:00Z',
        validTo: '2025-01-15T00:00:00Z',
        previousCertificateId: 'cert_001'
      };

      mockApiClient.mockResponse('POST', '/certificates/cert_001/rotate', {
        success: true,
        data: rotatedCertificate
      });

      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'rotate-certificate');
      const result = await executeTool(tool, {
        certificateId: 'cert_001',
        newValidityPeriod: 365
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.newCertificate).toBeDefined();
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
        domain: 'example.com',
        type: 'ssl'
      })).rejects.toThrow(UserError);
    });

    it('should validate required fields for certificate operations', async () => {
      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const createTool = findTool(mockTool, 'create-certificate');
      
      // Certificate without required fields should fail
      await expect(executeTool(createTool, {
        description: 'Missing required fields'
      })).rejects.toThrow(UserError);
    });

    it('should enforce certificate security validation', async () => {
      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-certificate');
      
      // Certificate with strong security parameters
      const secureCertificate = {
        name: 'Secure Certificate',
        domain: 'secure.example.com',
        type: 'ssl',
        algorithm: 'RSA',
        keySize: 4096,
        purposes: ['server_auth']
      };
      
      mockApiClient.mockResponse('POST', '/certificates', {
        success: true,
        data: { ...testCertificate, ...secureCertificate }
      });

      const result = await executeTool(tool, secureCertificate);
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.certificate).toBeDefined();
      expect(parsedResult.securityValidation).toBeDefined();
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

      mockApiClient.mockResponse('POST', '/certificates/cert_001/validate', {
        success: true,
        data: invalidValidation
      });

      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'validate-certificate');
      const result = await executeTool(tool, {
        certificateId: 'cert_001'
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

      mockApiClient.mockResponse('POST', '/certificates/cert_001/rotate', {
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
        certificateId: 'cert_001',
        autoRenew: true,
        renewalThreshold: 30
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.newCertificate).toBeDefined();
      expect(parsedResult.lifecycle).toBeDefined();
    });

    it('should support multi-domain certificate management', async () => {
      const multiDomainCert = {
        ...testCertificate,
        id: 'cert_multi_001',
        domain: '*.example.com',
        subjectAltNames: [
          'www.example.com',
          'api.example.com', 
          'mail.example.com',
          'app.example.com'
        ],
        type: 'wildcard'
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
        domain: '*.example.com',
        type: 'wildcard',
        subjectAltNames: ['www.example.com', 'api.example.com']
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.certificate.domain).toBe('*.example.com');
      expect(parsedResult.certificate.subjectAltNames).toBeDefined();
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

      mockApiClient.mockResponse('POST', '/certificates/cert_001/validate', {
        success: true,
        data: complianceReport
      });

      const { addCertificateTools } = await import('../../../src/tools/certificates.js');
      addCertificateTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'validate-certificate');
      const result = await executeTool(tool, {
        certificateId: 'cert_001',
        includeCompliance: true,
        includeAuditTrail: true
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.compliance).toBeDefined();
      expect(parsedResult.auditTrail).toBeDefined();
    });
  });
});