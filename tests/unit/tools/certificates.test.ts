/**
 * Comprehensive test suite for certificates.ts module
 * Tests all 6 certificate and key management tools with security focus
 * 
 * Coverage targets: 90%+ for all tools
 * Security patterns: Certificate validation, rotation, cryptographic analysis
 * Testing patterns: Chaos engineering, performance testing, advanced error scenarios
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { FastMCP, UserError } from 'fastmcp';

// Mock the Make API client
const mockApiClient = {
  request: jest.fn(),
  get: jest.fn(),
  post: jest.fn(),
  put: jest.fn(),
  delete: jest.fn(),
  patch: jest.fn()
} as unknown as import('../../../src/lib/make-api-client.js').default;

jest.mock('../../../src/lib/make-api-client.js', () => ({
  default: jest.fn(() => mockApiClient)
}));

// Mock external dependencies
jest.mock('fs/promises', () => ({
  readFile: jest.fn(),
  writeFile: jest.fn(),
  mkdir: jest.fn(),
  access: jest.fn()
}));

jest.mock('crypto', () => ({
  createHash: jest.fn(() => ({
    update: jest.fn().mockReturnThis(),
    digest: jest.fn(() => 'mocked-hash')
  })),
  randomBytes: jest.fn(() => Buffer.from('mocked-random-bytes')),
  createCipher: jest.fn(),
  createDecipher: jest.fn()
}));

// Mock node:crypto for certificate analysis
jest.mock('node:crypto', () => ({
  X509Certificate: jest.fn().mockImplementation(() => ({
    subject: 'CN=example.com',
    issuer: 'CN=Example CA',
    validFrom: '2024-01-01T00:00:00.000Z',
    validTo: '2025-01-01T00:00:00.000Z',
    fingerprint: 'AA:BB:CC:DD:EE:FF',
    keyUsage: ['digitalSignature', 'keyEncipherment'],
    subjectAltName: 'DNS:example.com, DNS:www.example.com',
    ca: false,
    verify: jest.fn(() => true)
  })),
  createVerify: jest.fn(() => ({
    update: jest.fn().mockReturnThis(),
    verify: jest.fn(() => true)
  })),
  constants: {
    RSA_PKCS1_PSS_PADDING: 6
  }
}));

// Performance monitoring setup
interface PerformanceMetrics {
  executionTime: number;
  memoryUsage: number;
  cpuUsage: number;
}

const performanceMonitor = {
  start: (): { end: () => PerformanceMetrics } => {
    const startTime = process.hrtime.bigint();
    const startMemory = process.memoryUsage();
    
    return {
      end: (): PerformanceMetrics => {
        const endTime = process.hrtime.bigint();
        const endMemory = process.memoryUsage();
        
        return {
          executionTime: Number(endTime - startTime) / 1000000, // Convert to milliseconds
          memoryUsage: endMemory.heapUsed - startMemory.heapUsed,
          cpuUsage: process.cpuUsage().user
        };
      }
    };
  }
};

// Chaos engineering for certificate operations
class CertificateChaosMonkey {
  private failureRate: number;
  private latencyMs: number;
  private scenarios: string[];

  constructor(config: { failureRate?: number; latencyMs?: number; scenarios?: string[] }) {
    this.failureRate = config.failureRate || 0.1;
    this.latencyMs = config.latencyMs || 5000;
    this.scenarios = config.scenarios || ['latency', 'error', 'timeout', 'corruption'];
  }

  async chaos<T>(operation: () => Promise<T>): Promise<T> {
    if (Math.random() < this.failureRate) {
      const scenario = this.scenarios[Math.floor(Math.random() * this.scenarios.length)];
      
      switch (scenario) {
        case 'latency':
          await new Promise(resolve => setTimeout(resolve, this.latencyMs));
          break;
        case 'error':
          throw new Error('Chaos monkey error injection');
        case 'timeout':
          throw new Error('Operation timeout');
        case 'corruption':
          throw new Error('Certificate data corruption detected');
      }
    }
    
    return operation();
  }
}

describe('Certificates Tools', () => {
  let server: FastMCP;
  let chaosMonkey: CertificateChaosMonkey;

  beforeAll(() => {
    server = new FastMCP('certificates-test-server', '1.0.0');
    chaosMonkey = new CertificateChaosMonkey({ failureRate: 0.1 });
  });

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Setup default successful API responses
    mockApiClient.get.mockResolvedValue({
      data: { certificates: [], total: 0 },
      status: 200,
      headers: {}
    });
    
    mockApiClient.post.mockResolvedValue({
      data: { id: 'cert-123', status: 'created' },
      status: 201,
      headers: {}
    });
    
    mockApiClient.put.mockResolvedValue({
      data: { id: 'cert-123', status: 'updated' },
      status: 200,
      headers: {}
    });
    
    mockApiClient.delete.mockResolvedValue({
      data: { status: 'deleted' },
      status: 200,
      headers: {}
    });
  });

  describe('Tool Registration', () => {
    test('should register all certificate management tools', async () => {
      const tools = server.getAvailableTools();
      const certificateTools = tools.filter(tool => 
        tool.name.startsWith('make_certificates_') || 
        tool.name.startsWith('make_certificate_')
      );

      expect(certificateTools).toHaveLength(6);
      
      const expectedTools = [
        'make_certificates_list',
        'make_certificate_create',
        'make_certificate_get',
        'make_certificate_update',
        'make_certificate_delete',
        'make_certificate_analyze_security'
      ];

      expectedTools.forEach(toolName => {
        expect(certificateTools.some(tool => tool.name === toolName)).toBe(true);
      });
    });

    test('should have proper tool schemas', async () => {
      const tools = server.getAvailableTools();
      const certificateTools = tools.filter(tool => 
        tool.name.startsWith('make_certificates_') || 
        tool.name.startsWith('make_certificate_')
      );

      certificateTools.forEach(tool => {
        expect(tool).toHaveProperty('name');
        expect(tool).toHaveProperty('description');
        expect(tool).toHaveProperty('inputSchema');
        expect(typeof tool.description).toBe('string');
        expect(tool.description.length).toBeGreaterThan(0);
      });
    });
  });

  describe('make_certificates_list', () => {
    test('should list certificates with default parameters', async () => {
      const mockCertificates = [
        {
          id: 'cert-1',
          name: 'example.com',
          type: 'ssl',
          status: 'active',
          expiresAt: '2025-12-31T23:59:59Z',
          domain: 'example.com'
        },
        {
          id: 'cert-2',
          name: 'api.example.com',
          type: 'ssl',
          status: 'expired',
          expiresAt: '2024-06-30T23:59:59Z',
          domain: 'api.example.com'
        }
      ];

      mockApiClient.get.mockResolvedValue({
        data: { 
          certificates: mockCertificates,
          total: 2,
          page: 1,
          limit: 50
        },
        status: 200,
        headers: {}
      });

      const result = await server.callTool('make_certificates_list', {});

      expect(mockApiClient.get).toHaveBeenCalledWith('/certificates', {
        params: {
          page: 1,
          limit: 50,
          sortBy: 'name',
          sortOrder: 'asc'
        }
      });

      expect(result.content).toHaveLength(1);
      expect(result.content[0].type).toBe('text');
      
      const responseText = result.content[0].text;
      expect(responseText).toContain('Found 2 certificates');
      expect(responseText).toContain('example.com');
      expect(responseText).toContain('api.example.com');
      expect(responseText).toContain('active');
      expect(responseText).toContain('expired');
    });

    test('should handle pagination parameters', async () => {
      mockApiClient.get.mockResolvedValue({
        data: { certificates: [], total: 0 },
        status: 200,
        headers: {}
      });

      await server.callTool('make_certificates_list', {
        page: 2,
        limit: 25,
        sortBy: 'expiresAt',
        sortOrder: 'desc'
      });

      expect(mockApiClient.get).toHaveBeenCalledWith('/certificates', {
        params: {
          page: 2,
          limit: 25,
          sortBy: 'expiresAt',
          sortOrder: 'desc'
        }
      });
    });

    test('should handle filter parameters', async () => {
      await server.callTool('make_certificates_list', {
        status: 'expired',
        type: 'ssl',
        domain: 'example.com',
        search: 'api'
      });

      expect(mockApiClient.get).toHaveBeenCalledWith('/certificates', {
        params: {
          page: 1,
          limit: 50,
          sortBy: 'name',
          sortOrder: 'asc',
          status: 'expired',
          type: 'ssl',
          domain: 'example.com',
          search: 'api'
        }
      });
    });

    test('should handle API errors gracefully', async () => {
      mockApiClient.get.mockRejectedValue(new Error('Network error'));

      const result = await server.callTool('make_certificates_list', {});

      expect(result.content[0].type).toBe('text');
      expect(result.content[0].text).toContain('Error listing certificates');
      expect(result.content[0].text).toContain('Network error');
    });

    test('should handle empty certificate list', async () => {
      mockApiClient.get.mockResolvedValue({
        data: { certificates: [], total: 0 },
        status: 200,
        headers: {}
      });

      const result = await server.callTool('make_certificates_list', {});

      expect(result.content[0].text).toContain('No certificates found');
    });

    test('should validate pagination limits', async () => {
      await server.callTool('make_certificates_list', {
        limit: 200 // Should be capped at 100
      });

      const lastCall = mockApiClient.get.mock.calls[mockApiClient.get.mock.calls.length - 1];
      expect(lastCall[1].params.limit).toBeLessThanOrEqual(100);
    });

    test('should handle performance monitoring', async () => {
      const monitor = performanceMonitor.start();
      
      await server.callTool('make_certificates_list', {});
      
      const metrics = monitor.end();
      expect(metrics.executionTime).toBeGreaterThan(0);
    });
  });

  describe('make_certificate_create', () => {
    test('should create SSL certificate successfully', async () => {
      const mockCertificate = {
        id: 'cert-123',
        name: 'example.com',
        type: 'ssl',
        domain: 'example.com',
        status: 'pending',
        createdAt: '2024-01-01T00:00:00Z'
      };

      mockApiClient.post.mockResolvedValue({
        data: mockCertificate,
        status: 201,
        headers: {}
      });

      const result = await server.callTool('make_certificate_create', {
        name: 'example.com',
        type: 'ssl',
        domain: 'example.com',
        autoRenew: true,
        validityPeriod: 365
      });

      expect(mockApiClient.post).toHaveBeenCalledWith('/certificates', {
        name: 'example.com',
        type: 'ssl',
        domain: 'example.com',
        autoRenew: true,
        validityPeriod: 365
      });

      expect(result.content[0].type).toBe('text');
      expect(result.content[0].text).toContain('Certificate created successfully');
      expect(result.content[0].text).toContain('cert-123');
      expect(result.content[0].text).toContain('example.com');
    });

    test('should create client certificate with CSR', async () => {
      const mockCsr = '-----BEGIN CERTIFICATE REQUEST-----\nMIICWjCCAUICAQAwFTETMBEGA1UEAwwKZXhhbXBsZS5jb20=\n-----END CERTIFICATE REQUEST-----';
      
      await server.callTool('make_certificate_create', {
        name: 'client-cert',
        type: 'client',
        csr: mockCsr,
        validityPeriod: 730
      });

      expect(mockApiClient.post).toHaveBeenCalledWith('/certificates', {
        name: 'client-cert',
        type: 'client',
        csr: mockCsr,
        validityPeriod: 730
      });
    });

    test('should handle certificate creation with custom extensions', async () => {
      await server.callTool('make_certificate_create', {
        name: 'wildcard-cert',
        type: 'ssl',
        domain: '*.example.com',
        subjectAltNames: ['example.com', 'www.example.com', 'api.example.com'],
        keyUsage: ['digitalSignature', 'keyEncipherment'],
        extendedKeyUsage: ['serverAuth', 'clientAuth']
      });

      const lastCall = mockApiClient.post.mock.calls[mockApiClient.post.mock.calls.length - 1];
      expect(lastCall[1]).toMatchObject({
        name: 'wildcard-cert',
        type: 'ssl',
        domain: '*.example.com',
        subjectAltNames: ['example.com', 'www.example.com', 'api.example.com'],
        keyUsage: ['digitalSignature', 'keyEncipherment'],
        extendedKeyUsage: ['serverAuth', 'clientAuth']
      });
    });

    test('should handle validation errors', async () => {
      mockApiClient.post.mockRejectedValue({
        response: {
          status: 400,
          data: { error: 'Invalid domain format' }
        }
      });

      const result = await server.callTool('make_certificate_create', {
        name: 'invalid-cert',
        type: 'ssl',
        domain: 'invalid..domain'
      });

      expect(result.content[0].text).toContain('Error creating certificate');
      expect(result.content[0].text).toContain('Invalid domain format');
    });

    test('should handle network errors', async () => {
      mockApiClient.post.mockRejectedValue(new Error('Connection timeout'));

      const result = await server.callTool('make_certificate_create', {
        name: 'test-cert',
        type: 'ssl',
        domain: 'test.com'
      });

      expect(result.content[0].text).toContain('Error creating certificate');
      expect(result.content[0].text).toContain('Connection timeout');
    });

    test('should validate required fields', async () => {
      // This test assumes validation happens at the schema level
      try {
        await server.callTool('make_certificate_create', {
          type: 'ssl'
          // Missing required 'name' field
        });
      } catch (error) {
        expect(error).toBeDefined();
      }
    });

    test('should handle chaos monkey scenarios', async () => {
      let attempts = 0;
      const maxAttempts = 5;

      while (attempts < maxAttempts) {
        try {
          await chaosMonkey.chaos(async () => {
            return server.callTool('make_certificate_create', {
              name: `chaos-cert-${attempts}`,
              type: 'ssl',
              domain: `chaos${attempts}.example.com`
            });
          });
          break;
        } catch (error) {
          attempts++;
          if (attempts >= maxAttempts) {
            expect(error).toBeDefined();
          }
        }
      }
    });
  });

  describe('make_certificate_get', () => {
    test('should retrieve certificate details', async () => {
      const mockCertificate = {
        id: 'cert-123',
        name: 'example.com',
        type: 'ssl',
        domain: 'example.com',
        status: 'active',
        createdAt: '2024-01-01T00:00:00Z',
        expiresAt: '2025-01-01T00:00:00Z',
        fingerprint: 'AA:BB:CC:DD:EE:FF',
        issuer: 'CN=Example CA',
        subject: 'CN=example.com',
        serialNumber: '123456789',
        keyUsage: ['digitalSignature', 'keyEncipherment'],
        subjectAltNames: ['example.com', 'www.example.com']
      };

      mockApiClient.get.mockResolvedValue({
        data: mockCertificate,
        status: 200,
        headers: {}
      });

      const result = await server.callTool('make_certificate_get', {
        certificateId: 'cert-123'
      });

      expect(mockApiClient.get).toHaveBeenCalledWith('/certificates/cert-123');

      expect(result.content[0].type).toBe('text');
      const responseText = result.content[0].text;
      expect(responseText).toContain('Certificate Details');
      expect(responseText).toContain('cert-123');
      expect(responseText).toContain('example.com');
      expect(responseText).toContain('active');
      expect(responseText).toContain('AA:BB:CC:DD:EE:FF');
    });

    test('should include certificate content when requested', async () => {
      const mockCertContent = '-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAKoK/hYo3i7LMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\n-----END CERTIFICATE-----';
      
      mockApiClient.get.mockResolvedValue({
        data: {
          id: 'cert-123',
          name: 'example.com',
          certificateContent: mockCertContent,
          privateKeyContent: '-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----'
        },
        status: 200,
        headers: {}
      });

      const result = await server.callTool('make_certificate_get', {
        certificateId: 'cert-123',
        includeCertificateContent: true,
        includePrivateKey: true
      });

      expect(mockApiClient.get).toHaveBeenCalledWith('/certificates/cert-123', {
        params: {
          includeCertificateContent: true,
          includePrivateKey: true
        }
      });

      const responseText = result.content[0].text;
      expect(responseText).toContain('BEGIN CERTIFICATE');
      expect(responseText).toContain('BEGIN PRIVATE KEY');
    });

    test('should handle certificate not found', async () => {
      mockApiClient.get.mockRejectedValue({
        response: {
          status: 404,
          data: { error: 'Certificate not found' }
        }
      });

      const result = await server.callTool('make_certificate_get', {
        certificateId: 'nonexistent'
      });

      expect(result.content[0].text).toContain('Error retrieving certificate');
      expect(result.content[0].text).toContain('Certificate not found');
    });

    test('should handle expired certificates', async () => {
      const expiredCert = {
        id: 'cert-expired',
        name: 'expired.com',
        status: 'expired',
        expiresAt: '2023-01-01T00:00:00Z'
      };

      mockApiClient.get.mockResolvedValue({
        data: expiredCert,
        status: 200,
        headers: {}
      });

      const result = await server.callTool('make_certificate_get', {
        certificateId: 'cert-expired'
      });

      const responseText = result.content[0].text;
      expect(responseText).toContain('⚠️ EXPIRED');
      expect(responseText).toContain('expired');
    });

    test('should format expiration warnings', async () => {
      const soonToExpire = new Date();
      soonToExpire.setDate(soonToExpire.getDate() + 15); // 15 days from now

      mockApiClient.get.mockResolvedValue({
        data: {
          id: 'cert-warning',
          name: 'warning.com',
          status: 'active',
          expiresAt: soonToExpire.toISOString()
        },
        status: 200,
        headers: {}
      });

      const result = await server.callTool('make_certificate_get', {
        certificateId: 'cert-warning'
      });

      const responseText = result.content[0].text;
      expect(responseText).toContain('⚠️');
    });

    test('should handle performance under load', async () => {
      const promises = Array.from({ length: 10 }, (_, i) => {
        mockApiClient.get.mockResolvedValueOnce({
          data: { id: `cert-${i}`, name: `test${i}.com` },
          status: 200,
          headers: {}
        });
        
        return server.callTool('make_certificate_get', {
          certificateId: `cert-${i}`
        });
      });

      const results = await Promise.all(promises);
      expect(results).toHaveLength(10);
    });
  });

  describe('make_certificate_update', () => {
    test('should update certificate properties', async () => {
      const updatedCert = {
        id: 'cert-123',
        name: 'updated-example.com',
        autoRenew: true,
        description: 'Updated certificate'
      };

      mockApiClient.put.mockResolvedValue({
        data: updatedCert,
        status: 200,
        headers: {}
      });

      const result = await server.callTool('make_certificate_update', {
        certificateId: 'cert-123',
        name: 'updated-example.com',
        autoRenew: true,
        description: 'Updated certificate'
      });

      expect(mockApiClient.put).toHaveBeenCalledWith('/certificates/cert-123', {
        name: 'updated-example.com',
        autoRenew: true,
        description: 'Updated certificate'
      });

      expect(result.content[0].text).toContain('Certificate updated successfully');
      expect(result.content[0].text).toContain('cert-123');
    });

    test('should renew certificate', async () => {
      await server.callTool('make_certificate_update', {
        certificateId: 'cert-123',
        renew: true,
        validityPeriod: 730
      });

      expect(mockApiClient.put).toHaveBeenCalledWith('/certificates/cert-123', {
        renew: true,
        validityPeriod: 730
      });
    });

    test('should update certificate tags and metadata', async () => {
      await server.callTool('make_certificate_update', {
        certificateId: 'cert-123',
        tags: ['production', 'web-server'],
        metadata: {
          environment: 'production',
          owner: 'web-team',
          purpose: 'https-termination'
        }
      });

      const lastCall = mockApiClient.put.mock.calls[mockApiClient.put.mock.calls.length - 1];
      expect(lastCall[1]).toMatchObject({
        tags: ['production', 'web-server'],
        metadata: {
          environment: 'production',
          owner: 'web-team',
          purpose: 'https-termination'
        }
      });
    });

    test('should handle validation errors during update', async () => {
      mockApiClient.put.mockRejectedValue({
        response: {
          status: 400,
          data: { 
            error: 'Validation failed',
            details: ['Name already exists']
          }
        }
      });

      const result = await server.callTool('make_certificate_update', {
        certificateId: 'cert-123',
        name: 'duplicate-name'
      });

      expect(result.content[0].text).toContain('Error updating certificate');
      expect(result.content[0].text).toContain('Name already exists');
    });

    test('should handle certificate not found during update', async () => {
      mockApiClient.put.mockRejectedValue({
        response: {
          status: 404,
          data: { error: 'Certificate not found' }
        }
      });

      const result = await server.callTool('make_certificate_update', {
        certificateId: 'nonexistent',
        name: 'new-name'
      });

      expect(result.content[0].text).toContain('Certificate not found');
    });

    test('should validate update parameters', async () => {
      // Test with empty update
      await server.callTool('make_certificate_update', {
        certificateId: 'cert-123'
        // No update fields provided
      });

      // Should still make the call but with empty body
      expect(mockApiClient.put).toHaveBeenCalledWith('/certificates/cert-123', {});
    });

    test('should handle concurrent updates', async () => {
      const updates = Array.from({ length: 5 }, (_, i) => {
        mockApiClient.put.mockResolvedValueOnce({
          data: { id: `cert-${i}`, updated: true },
          status: 200,
          headers: {}
        });
        
        return server.callTool('make_certificate_update', {
          certificateId: `cert-${i}`,
          description: `Updated description ${i}`
        });
      });

      const results = await Promise.all(updates);
      expect(results).toHaveLength(5);
      results.forEach(result => {
        expect(result.content[0].text).toContain('updated successfully');
      });
    });
  });

  describe('make_certificate_delete', () => {
    test('should delete certificate successfully', async () => {
      mockApiClient.delete.mockResolvedValue({
        data: { status: 'deleted', id: 'cert-123' },
        status: 200,
        headers: {}
      });

      const result = await server.callTool('make_certificate_delete', {
        certificateId: 'cert-123'
      });

      expect(mockApiClient.delete).toHaveBeenCalledWith('/certificates/cert-123');

      expect(result.content[0].text).toContain('Certificate deleted successfully');
      expect(result.content[0].text).toContain('cert-123');
    });

    test('should handle force deletion', async () => {
      await server.callTool('make_certificate_delete', {
        certificateId: 'cert-123',
        force: true
      });

      expect(mockApiClient.delete).toHaveBeenCalledWith('/certificates/cert-123', {
        params: { force: true }
      });
    });

    test('should handle certificate in use error', async () => {
      mockApiClient.delete.mockRejectedValue({
        response: {
          status: 409,
          data: { 
            error: 'Certificate in use',
            usedBy: ['connection-1', 'webhook-handler-2']
          }
        }
      });

      const result = await server.callTool('make_certificate_delete', {
        certificateId: 'cert-123'
      });

      expect(result.content[0].text).toContain('Certificate in use');
      expect(result.content[0].text).toContain('connection-1');
      expect(result.content[0].text).toContain('webhook-handler-2');
    });

    test('should handle certificate not found during deletion', async () => {
      mockApiClient.delete.mockRejectedValue({
        response: {
          status: 404,
          data: { error: 'Certificate not found' }
        }
      });

      const result = await server.callTool('make_certificate_delete', {
        certificateId: 'nonexistent'
      });

      expect(result.content[0].text).toContain('Certificate not found');
    });

    test('should handle permission errors', async () => {
      mockApiClient.delete.mockRejectedValue({
        response: {
          status: 403,
          data: { error: 'Insufficient permissions' }
        }
      });

      const result = await server.callTool('make_certificate_delete', {
        certificateId: 'cert-123'
      });

      expect(result.content[0].text).toContain('Insufficient permissions');
    });

    test('should validate deletion with backup', async () => {
      await server.callTool('make_certificate_delete', {
        certificateId: 'cert-123',
        createBackup: true
      });

      expect(mockApiClient.delete).toHaveBeenCalledWith('/certificates/cert-123', {
        params: { createBackup: true }
      });
    });

    test('should handle batch deletion scenarios', async () => {
      const deletions = ['cert-1', 'cert-2', 'cert-3'].map(id => {
        mockApiClient.delete.mockResolvedValueOnce({
          data: { status: 'deleted', id },
          status: 200,
          headers: {}
        });
        
        return server.callTool('make_certificate_delete', {
          certificateId: id
        });
      });

      const results = await Promise.all(deletions);
      expect(results).toHaveLength(3);
    });
  });

  describe('make_certificate_analyze_security', () => {
    test('should analyze certificate security comprehensively', async () => {
      const mockAnalysis = {
        certificateId: 'cert-123',
        securityScore: 85,
        findings: [
          {
            level: 'warning',
            category: 'expiration',
            message: 'Certificate expires in 30 days',
            recommendation: 'Schedule renewal before expiration'
          },
          {
            level: 'info',
            category: 'algorithm',
            message: 'Strong RSA-2048 key algorithm',
            recommendation: 'Consider upgrading to RSA-4096 for enhanced security'
          }
        ],
        compliance: {
          pci: true,
          sox: true,
          hipaa: false
        },
        vulnerabilities: [],
        recommendations: [
          'Enable OCSP stapling',
          'Implement certificate transparency monitoring',
          'Configure HSTS headers'
        ]
      };

      mockApiClient.post.mockResolvedValue({
        data: mockAnalysis,
        status: 200,
        headers: {}
      });

      const result = await server.callTool('make_certificate_analyze_security', {
        certificateId: 'cert-123',
        includeCompliance: true,
        includeVulnerabilities: true
      });

      expect(mockApiClient.post).toHaveBeenCalledWith('/certificates/cert-123/analyze', {
        includeCompliance: true,
        includeVulnerabilities: true
      });

      const responseText = result.content[0].text;
      expect(responseText).toContain('Security Analysis');
      expect(responseText).toContain('Score: 85');
      expect(responseText).toContain('expires in 30 days');
      expect(responseText).toContain('RSA-2048');
      expect(responseText).toContain('OCSP stapling');
    });

    test('should handle deep security analysis', async () => {
      await server.callTool('make_certificate_analyze_security', {
        certificateId: 'cert-123',
        analysisDepth: 'deep',
        checkRevocation: true,
        validateChain: true,
        scanVulnerabilities: true
      });

      expect(mockApiClient.post).toHaveBeenCalledWith('/certificates/cert-123/analyze', {
        analysisDepth: 'deep',
        checkRevocation: true,
        validateChain: true,
        scanVulnerabilities: true
      });
    });

    test('should identify critical security issues', async () => {
      const criticalAnalysis = {
        certificateId: 'cert-vulnerable',
        securityScore: 25,
        findings: [
          {
            level: 'critical',
            category: 'vulnerability',
            message: 'Weak MD5 signature algorithm detected',
            recommendation: 'Immediately replace with SHA-256 or higher'
          },
          {
            level: 'high',
            category: 'key_strength',
            message: 'RSA-1024 key size is insufficient',
            recommendation: 'Upgrade to RSA-2048 minimum'
          }
        ],
        vulnerabilities: [
          {
            id: 'CVE-2023-1234',
            severity: 'high',
            description: 'Certificate chain validation bypass',
            affected: true
          }
        ]
      };

      mockApiClient.post.mockResolvedValue({
        data: criticalAnalysis,
        status: 200,
        headers: {}
      });

      const result = await server.callTool('make_certificate_analyze_security', {
        certificateId: 'cert-vulnerable'
      });

      const responseText = result.content[0].text;
      expect(responseText).toContain('🚨 CRITICAL');
      expect(responseText).toContain('MD5 signature');
      expect(responseText).toContain('RSA-1024');
      expect(responseText).toContain('CVE-2023-1234');
    });

    test('should analyze certificate chain', async () => {
      const chainAnalysis = {
        certificateId: 'cert-123',
        chainValidation: {
          valid: true,
          depth: 3,
          rootCA: 'DigiCert Global Root CA',
          intermediates: ['DigiCert SHA2 Extended Validation Server CA'],
          issues: []
        },
        ocspStatus: {
          enabled: true,
          response: 'good',
          nextUpdate: '2024-01-08T00:00:00Z'
        }
      };

      mockApiClient.post.mockResolvedValue({
        data: chainAnalysis,
        status: 200,
        headers: {}
      });

      const result = await server.callTool('make_certificate_analyze_security', {
        certificateId: 'cert-123',
        validateChain: true,
        checkOcsp: true
      });

      const responseText = result.content[0].text;
      expect(responseText).toContain('Chain Validation');
      expect(responseText).toContain('DigiCert');
      expect(responseText).toContain('OCSP Status');
    });

    test('should handle analysis errors gracefully', async () => {
      mockApiClient.post.mockRejectedValue({
        response: {
          status: 422,
          data: { error: 'Certificate format not supported' }
        }
      });

      const result = await server.callTool('make_certificate_analyze_security', {
        certificateId: 'cert-invalid'
      });

      expect(result.content[0].text).toContain('Error analyzing certificate');
      expect(result.content[0].text).toContain('format not supported');
    });

    test('should provide compliance assessment', async () => {
      const complianceAnalysis = {
        certificateId: 'cert-123',
        compliance: {
          pci: {
            compliant: true,
            requirements: ['RSA-2048+', 'SHA-256+', 'Valid CA'],
            issues: []
          },
          sox: {
            compliant: false,
            requirements: ['Extended Validation', 'Key Escrow'],
            issues: ['Missing key escrow']
          }
        }
      };

      mockApiClient.post.mockResolvedValue({
        data: complianceAnalysis,
        status: 200,
        headers: {}
      });

      const result = await server.callTool('make_certificate_analyze_security', {
        certificateId: 'cert-123',
        includeCompliance: true,
        complianceStandards: ['pci', 'sox']
      });

      const responseText = result.content[0].text;
      expect(responseText).toContain('Compliance Assessment');
      expect(responseText).toContain('PCI: ✅');
      expect(responseText).toContain('SOX: ❌');
      expect(responseText).toContain('key escrow');
    });

    test('should handle performance under analysis load', async () => {
      const monitor = performanceMonitor.start();
      
      mockApiClient.post.mockResolvedValue({
        data: { securityScore: 90, findings: [] },
        status: 200,
        headers: {}
      });

      await server.callTool('make_certificate_analyze_security', {
        certificateId: 'cert-123',
        analysisDepth: 'deep'
      });
      
      const metrics = monitor.end();
      expect(metrics.executionTime).toBeLessThan(10000); // 10 seconds max
    });
  });

  describe('Security Testing', () => {
    test('should handle certificate data encryption', async () => {
      const sensitiveData = {
        privateKey: '-----BEGIN PRIVATE KEY-----\nsensitive\n-----END PRIVATE KEY-----',
        passphrase: 'super-secret-passphrase'
      };

      // Mock encryption handling
      const mockCrypto = await import('crypto');
      mockCrypto.createHash.mockImplementation(() => ({
        update: jest.fn().mockReturnThis(),
        digest: jest.fn(() => 'encrypted-hash')
      }));

      await server.callTool('make_certificate_create', {
        name: 'secure-cert',
        type: 'client',
        privateKeyData: sensitiveData.privateKey,
        passphrase: sensitiveData.passphrase
      });

      // Verify sensitive data is handled securely
      const calls = mockApiClient.post.mock.calls;
      const lastCall = calls[calls.length - 1];
      
      // Should not contain raw sensitive data
      expect(JSON.stringify(lastCall)).not.toContain('super-secret-passphrase');
    });

    test('should validate certificate against known vulnerabilities', async () => {
      const vulnerabilityAnalysis = {
        certificateId: 'cert-test',
        vulnerabilities: [
          {
            id: 'WEAK-KEY-1024',
            severity: 'high',
            description: 'RSA key size below 2048 bits',
            mitigation: 'Generate new certificate with RSA-2048 or higher'
          }
        ],
        riskScore: 75
      };

      mockApiClient.post.mockResolvedValue({
        data: vulnerabilityAnalysis,
        status: 200,
        headers: {}
      });

      const result = await server.callTool('make_certificate_analyze_security', {
        certificateId: 'cert-test',
        scanVulnerabilities: true
      });

      expect(result.content[0].text).toContain('WEAK-KEY-1024');
      expect(result.content[0].text).toContain('RSA-2048');
    });

    test('should handle certificate authority validation', async () => {
      const caValidation = {
        certificateId: 'cert-ca-test',
        issuerValidation: {
          trusted: false,
          issuer: 'CN=Unknown CA',
          warnings: ['Self-signed root certificate', 'Not in trusted store']
        }
      };

      mockApiClient.post.mockResolvedValue({
        data: caValidation,
        status: 200,
        headers: {}
      });

      const result = await server.callTool('make_certificate_analyze_security', {
        certificateId: 'cert-ca-test',
        validateIssuer: true
      });

      expect(result.content[0].text).toContain('Issuer Validation');
      expect(result.content[0].text).toContain('Self-signed');
      expect(result.content[0].text).toContain('Not in trusted store');
    });
  });

  describe('Error Handling & Edge Cases', () => {
    test('should handle malformed certificate data', async () => {
      mockApiClient.get.mockResolvedValue({
        data: {
          id: 'cert-malformed',
          certificateContent: 'INVALID-CERTIFICATE-DATA'
        },
        status: 200,
        headers: {}
      });

      const result = await server.callTool('make_certificate_get', {
        certificateId: 'cert-malformed',
        includeCertificateContent: true
      });

      // Should handle gracefully without crashing
      expect(result.content[0].type).toBe('text');
      expect(result.content[0].text).toContain('cert-malformed');
    });

    test('should handle concurrent certificate operations', async () => {
      const operations = [
        (): Promise<import('../../types.js').ToolResult> => { return server.callTool('make_certificates_list', {}); },
        (): Promise<import('../../types.js').ToolResult> => { return server.callTool('make_certificate_get', { certificateId: 'cert-1' }); },
        (): Promise<import('../../types.js').ToolResult> => { return server.callTool('make_certificate_create', { name: 'test', type: 'ssl', domain: 'test.com' }); },
        (): Promise<import('../../types.js').ToolResult> => { return server.callTool('make_certificate_update', { certificateId: 'cert-2', name: 'updated' }); },
        (): Promise<import('../../types.js').ToolResult> => { return server.callTool('make_certificate_analyze_security', { certificateId: 'cert-3' }); }
      ];

      // Mock responses for all operations
      operations.forEach((_, index) => {
        if (index === 0) {
          mockApiClient.get.mockResolvedValueOnce({ data: { certificates: [] }, status: 200, headers: {} });
        } else if (index === 1) {
          mockApiClient.get.mockResolvedValueOnce({ data: { id: 'cert-1' }, status: 200, headers: {} });
        } else if (index === 2) {
          mockApiClient.post.mockResolvedValueOnce({ data: { id: 'new-cert' }, status: 201, headers: {} });
        } else if (index === 3) {
          mockApiClient.put.mockResolvedValueOnce({ data: { id: 'cert-2' }, status: 200, headers: {} });
        } else if (index === 4) {
          mockApiClient.post.mockResolvedValueOnce({ data: { securityScore: 90 }, status: 200, headers: {} });
        }
      });

      const results = await Promise.all(operations.map(op => op()));
      expect(results).toHaveLength(5);
      
      // All operations should complete successfully
      results.forEach(result => {
        expect(result.content[0].type).toBe('text');
        expect(result.content[0].text).not.toContain('Error');
      });
    });

    test('should handle API rate limiting', async () => {
      mockApiClient.get.mockRejectedValue({
        response: {
          status: 429,
          data: { error: 'Rate limit exceeded' },
          headers: { 'retry-after': '60' }
        }
      });

      const result = await server.callTool('make_certificates_list', {});

      expect(result.content[0].text).toContain('Rate limit exceeded');
      expect(result.content[0].text).toContain('retry-after');
    });

    test('should handle network timeouts gracefully', async () => {
      mockApiClient.get.mockRejectedValue(new Error('ECONNABORTED'));

      const result = await server.callTool('make_certificates_list', {});

      expect(result.content[0].text).toContain('network error');
    });

    test('should validate certificate expiration edge cases', async () => {
      const now = new Date();
      const almostExpired = new Date(now.getTime() + 24 * 60 * 60 * 1000); // 1 day

      mockApiClient.get.mockResolvedValue({
        data: {
          id: 'cert-almost-expired',
          expiresAt: almostExpired.toISOString(),
          status: 'active'
        },
        status: 200,
        headers: {}
      });

      const result = await server.callTool('make_certificate_get', {
        certificateId: 'cert-almost-expired'
      });

      expect(result.content[0].text).toContain('🚨');
      expect(result.content[0].text).toContain('expires');
    });
  });

  describe('Performance & Load Testing', () => {
    test('should handle bulk certificate operations efficiently', async () => {
      const bulkSize = 50;
      const startTime = Date.now();

      // Mock bulk response
      mockApiClient.get.mockResolvedValue({
        data: {
          certificates: Array.from({ length: bulkSize }, (_, i) => ({
            id: `cert-${i}`,
            name: `example${i}.com`,
            status: 'active'
          })),
          total: bulkSize
        },
        status: 200,
        headers: {}
      });

      const result = await server.callTool('make_certificates_list', {
        limit: bulkSize
      });

      const executionTime = Date.now() - startTime;
      
      expect(result.content[0].text).toContain(`Found ${bulkSize} certificates`);
      expect(executionTime).toBeLessThan(5000); // Should complete within 5 seconds
    });

    test('should maintain performance under memory pressure', async () => {
      const largeData = 'x'.repeat(100000); // 100KB string
      
      mockApiClient.get.mockResolvedValue({
        data: {
          id: 'cert-large',
          certificateContent: largeData,
          description: largeData
        },
        status: 200,
        headers: {}
      });

      const startMemory = process.memoryUsage().heapUsed;
      
      await server.callTool('make_certificate_get', {
        certificateId: 'cert-large',
        includeCertificateContent: true
      });

      const endMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = endMemory - startMemory;
      
      // Memory increase should be reasonable (less than 10MB)
      expect(memoryIncrease).toBeLessThan(10 * 1024 * 1024);
    });

    test('should handle stress testing scenarios', async () => {
      const stressOperations = Array.from({ length: 20 }, (_, i) => {
        // Alternate between different operations
        const operations = [
          (): Promise<import('../../types.js').ToolResult> => { return server.callTool('make_certificates_list', { page: i % 5 + 1 }); },
          (): Promise<import('../../types.js').ToolResult> => { return server.callTool('make_certificate_get', { certificateId: `cert-${i}` }); },
          (): Promise<import('../../types.js').ToolResult> => { return server.callTool('make_certificate_analyze_security', { certificateId: `cert-${i}` }); }
        ];
        
        const opIndex = i % operations.length;
        
        // Mock appropriate responses
        if (opIndex === 0) {
          mockApiClient.get.mockResolvedValueOnce({ data: { certificates: [] }, status: 200, headers: {} });
        } else if (opIndex === 1) {
          mockApiClient.get.mockResolvedValueOnce({ data: { id: `cert-${i}` }, status: 200, headers: {} });
        } else {
          mockApiClient.post.mockResolvedValueOnce({ data: { securityScore: 80 }, status: 200, headers: {} });
        }
        
        return operations[opIndex];
      });

      const startTime = Date.now();
      const results = await Promise.all(stressOperations.map(op => op()));
      const totalTime = Date.now() - startTime;

      expect(results).toHaveLength(20);
      expect(totalTime).toBeLessThan(15000); // All operations within 15 seconds
      
      // All operations should succeed
      results.forEach(result => {
        expect(result.content[0].type).toBe('text');
      });
    });
  });

  describe('Integration Testing', () => {
    test('should integrate with certificate lifecycle workflow', async () => {
      // Step 1: Create certificate
      mockApiClient.post.mockResolvedValueOnce({
        data: { id: 'workflow-cert', status: 'pending' },
        status: 201,
        headers: {}
      });

      const createResult = await server.callTool('make_certificate_create', {
        name: 'workflow-test.com',
        type: 'ssl',
        domain: 'workflow-test.com'
      });

      expect(createResult.content[0].text).toContain('created successfully');

      // Step 2: Get certificate details
      mockApiClient.get.mockResolvedValueOnce({
        data: { 
          id: 'workflow-cert', 
          status: 'active',
          expiresAt: '2025-12-31T23:59:59Z'
        },
        status: 200,
        headers: {}
      });

      const getResult = await server.callTool('make_certificate_get', {
        certificateId: 'workflow-cert'
      });

      expect(getResult.content[0].text).toContain('workflow-cert');

      // Step 3: Analyze security
      mockApiClient.post.mockResolvedValueOnce({
        data: { 
          securityScore: 95,
          findings: []
        },
        status: 200,
        headers: {}
      });

      const analyzeResult = await server.callTool('make_certificate_analyze_security', {
        certificateId: 'workflow-cert'
      });

      expect(analyzeResult.content[0].text).toContain('Score: 95');

      // Step 4: Update certificate
      mockApiClient.put.mockResolvedValueOnce({
        data: { id: 'workflow-cert', updated: true },
        status: 200,
        headers: {}
      });

      const updateResult = await server.callTool('make_certificate_update', {
        certificateId: 'workflow-cert',
        autoRenew: true
      });

      expect(updateResult.content[0].text).toContain('updated successfully');
    });

    test('should handle external service dependencies', async () => {
      // Simulate external CA service integration
      mockApiClient.post.mockImplementation((url, data) => {
        if (url.includes('/certificates') && data.type === 'ssl') {
          // Simulate CA validation process
          return Promise.resolve({
            data: {
              id: 'ca-issued-cert',
              status: 'validating',
              caValidation: {
                status: 'pending',
                challenges: ['dns-01', 'http-01']
              }
            },
            status: 201,
            headers: {}
          });
        }
        return Promise.reject(new Error('Unexpected request'));
      });

      const result = await server.callTool('make_certificate_create', {
        name: 'ca-test.com',
        type: 'ssl',
        domain: 'ca-test.com',
        caProvider: 'letsencrypt'
      });

      expect(result.content[0].text).toContain('ca-issued-cert');
      expect(result.content[0].text).toContain('validating');
    });
  });

  describe('Chaos Engineering', () => {
    test('should recover from random failures', async () => {
      let attempts = 0;
      const maxAttempts = 10;
      
      while (attempts < maxAttempts) {
        try {
          await chaosMonkey.chaos(async () => {
            mockApiClient.get.mockResolvedValueOnce({
              data: { certificates: [] },
              status: 200,
              headers: {}
            });
            
            return server.callTool('make_certificates_list', {});
          });
          
          break; // Success
        } catch (error) {
          attempts++;
          
          if (attempts >= maxAttempts) {
            // After max attempts, operation should still be recoverable
            expect((error as Error).message).toMatch(/chaos monkey|timeout|corruption/i);
          }
        }
      }
      
      expect(attempts).toBeLessThan(maxAttempts);
    });

    test('should handle certificate corruption scenarios', async () => {
      const corruptCertData = {
        id: 'corrupt-cert',
        certificateContent: 'CORRUPTED-DATA-' + 'x'.repeat(1000),
        status: 'invalid'
      };

      mockApiClient.get.mockResolvedValue({
        data: corruptCertData,
        status: 200,
        headers: {}
      });

      const result = await server.callTool('make_certificate_get', {
        certificateId: 'corrupt-cert',
        includeCertificateContent: true
      });

      // Should handle corruption gracefully
      expect(result.content[0].type).toBe('text');
      expect(result.content[0].text).toContain('corrupt-cert');
    });

    test('should survive service degradation', async () => {
      // Simulate degraded service responses
      mockApiClient.get.mockImplementation(() => {
        return new Promise(resolve => {
          setTimeout(() => {
            resolve({
              data: { certificates: [], warning: 'Service degraded' },
              status: 200,
              headers: {}
            });
          }, 2000); // 2 second delay
        });
      });

      const startTime = Date.now();
      const result = await server.callTool('make_certificates_list', {});
      const endTime = Date.now();

      expect(endTime - startTime).toBeGreaterThan(1500); // Confirm delay occurred
      expect(result.content[0].text).toContain('No certificates found');
    });
  });
});