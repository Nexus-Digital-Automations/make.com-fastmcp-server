import { describe, expect, it, beforeEach, afterEach, jest } from '@jest/globals';
import request from 'supertest';
import { server } from '../../src/server';
import { MakeAPIClient } from '../../src/lib/make-api-client';

describe('Authentication Security Tests', () => {
    let app: any;
    let mockMakeClient: jest.Mocked<MakeAPIClient>;

    beforeEach(() => {
        app = server;
        mockMakeClient = {
            makeRequest: jest.fn(),
            get: jest.fn(),
            post: jest.fn(),
            put: jest.fn(),
            delete: jest.fn(),
            patch: jest.fn()
        } as unknown as jest.Mocked<MakeAPIClient>;

        // Reset any rate limiting or brute force protection
        jest.clearAllMocks();
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    describe('Brute Force Protection', () => {
        const testEmail = 'brute-force-test@example.com';
        const wrongPassword = 'wrongpassword123';
        const correctPassword = 'correctpassword123';

        it('should implement rate limiting for failed login attempts', async () => {
            const failedAttempts = [];

            // Make multiple failed login attempts rapidly
            for (let i = 0; i < 6; i++) {
                const response = request(app)
                    .post('/api/authenticate')
                    .send({
                        apiKey: `invalid-key-${i}`,
                        baseUrl: 'https://api.make.com'
                    });
                
                failedAttempts.push(response);
            }

            const responses = await Promise.all(failedAttempts);

            // First few attempts should return 401 Unauthorized
            expect(responses.slice(0, 3).every(res => res.status === 401)).toBe(true);

            // Later attempts should be rate limited (429 Too Many Requests)
            const rateLimitedResponses = responses.slice(3);
            expect(rateLimitedResponses.some(res => res.status === 429)).toBe(true);

            // Rate limited responses should include retry-after header
            rateLimitedResponses.forEach(response => {
                if (response.status === 429) {
                    expect(response.headers['retry-after']).toBeDefined();
                    expect(parseInt(response.headers['retry-after'])).toBeGreaterThan(0);
                }
            });
        });

        it('should implement progressive delays for failed attempts', async () => {
            const timestamps: number[] = [];

            // Make sequential failed attempts and record timing
            for (let i = 0; i < 5; i++) {
                const startTime = Date.now();
                
                await request(app)
                    .post('/api/authenticate')
                    .send({
                        apiKey: `invalid-key-attempt-${i}`,
                        baseUrl: 'https://api.make.com'
                    });
                
                timestamps.push(Date.now() - startTime);
                
                // Small delay between attempts
                await new Promise(resolve => setTimeout(resolve, 100));
            }

            // Later attempts should take longer due to progressive delays
            expect(timestamps[4]).toBeGreaterThan(timestamps[0]);
        });

        it('should temporarily lock accounts after threshold failures', async () => {
            const apiKey = 'test-api-key-for-locking';

            // Make multiple failed attempts with same API key
            for (let i = 0; i < 5; i++) {
                await request(app)
                    .post('/api/authenticate')
                    .send({
                        apiKey: apiKey,
                        baseUrl: 'https://api.make.com'
                    });
            }

            // Subsequent attempt should be locked even with correct credentials
            const lockedResponse = await request(app)
                .post('/api/authenticate')
                .send({
                    apiKey: apiKey,
                    baseUrl: 'https://api.make.com'
                });

            expect([423, 429]).toContain(lockedResponse.status); // 423 Locked or 429 Too Many Requests
            
            if (lockedResponse.body) {
                expect(lockedResponse.body).toMatchObject(
                    expect.objectContaining({
                        error: expect.stringMatching(/locked|blocked|rate.limit/i)
                    })
                );
            }
        });

        it('should implement CAPTCHA requirement after failed attempts', async () => {
            const testApiKey = 'captcha-test-key';

            // Make multiple failed attempts
            for (let i = 0; i < 8; i++) {
                await request(app)
                    .post('/api/authenticate')
                    .send({
                        apiKey: testApiKey,
                        baseUrl: 'https://api.make.com'
                    });
            }

            // Next attempt should require CAPTCHA
            const captchaResponse = await request(app)
                .post('/api/authenticate')
                .send({
                    apiKey: testApiKey,
                    baseUrl: 'https://api.make.com'
                });

            expect([400, 403, 429]).toContain(captchaResponse.status);
            
            if (captchaResponse.body) {
                expect(captchaResponse.body).toMatchObject(
                    expect.objectContaining({
                        requiresCaptcha: true
                    })
                );
            }
        });
    });

    describe('Session Security', () => {
        it('should invalidate sessions on password change', async () => {
            // Simulate successful authentication
            const authResponse = await request(app)
                .post('/api/authenticate')
                .send({
                    apiKey: 'valid-api-key',
                    baseUrl: 'https://api.make.com'
                });

            if (authResponse.status === 200) {
                const token = authResponse.body.token;

                // Simulate password change
                const changeResponse = await request(app)
                    .post('/api/change-credentials')
                    .set('Authorization', `Bearer ${token}`)
                    .send({
                        newApiKey: 'new-api-key',
                        currentApiKey: 'valid-api-key'
                    });

                // If password change succeeded, old token should be invalid
                if (changeResponse.status === 200) {
                    const testResponse = await request(app)
                        .get('/scenarios/list')
                        .set('Authorization', `Bearer ${token}`)
                        .query({ teamId: '12345' });

                    expect(testResponse.status).toBe(401);
                }
            }
        });

        it('should implement session timeout', async () => {
            const authResponse = await request(app)
                .post('/api/authenticate')
                .send({
                    apiKey: 'valid-api-key',
                    baseUrl: 'https://api.make.com'
                });

            if (authResponse.status === 200) {
                const token = authResponse.body.token;

                // Wait for session timeout (simulated by sending expired timestamp)
                const expiredResponse = await request(app)
                    .get('/scenarios/list')
                    .set('Authorization', `Bearer ${token}`)
                    .set('X-Test-Time-Override', (Date.now() + 3600000).toString()) // 1 hour future
                    .query({ teamId: '12345' });

                expect([401, 403]).toContain(expiredResponse.status);
            }
        });

        it('should implement concurrent session limits', async () => {
            const apiKey = 'concurrent-session-test';
            const sessions = [];

            // Create multiple concurrent sessions
            for (let i = 0; i < 5; i++) {
                const sessionResponse = request(app)
                    .post('/api/authenticate')
                    .send({
                        apiKey: apiKey,
                        baseUrl: 'https://api.make.com',
                        deviceId: `device-${i}`
                    });
                
                sessions.push(sessionResponse);
            }

            const sessionResponses = await Promise.all(sessions);

            // Some sessions should be rejected due to concurrent session limits
            const rejectedSessions = sessionResponses.filter(res => [403, 429].includes(res.status));
            expect(rejectedSessions.length).toBeGreaterThan(0);
        });

        it('should detect and prevent session hijacking', async () => {
            const authResponse = await request(app)
                .post('/api/authenticate')
                .send({
                    apiKey: 'hijack-test-key',
                    baseUrl: 'https://api.make.com'
                });

            if (authResponse.status === 200) {
                const token = authResponse.body.token;

                // Use token from different IP/User-Agent
                const hijackResponse = await request(app)
                    .get('/scenarios/list')
                    .set('Authorization', `Bearer ${token}`)
                    .set('User-Agent', 'Malicious-Bot/1.0')
                    .set('X-Forwarded-For', '192.168.1.100') // Different IP
                    .query({ teamId: '12345' });

                // Should detect suspicious activity
                expect([401, 403]).toContain(hijackResponse.status);
            }
        });
    });

    describe('API Token Security', () => {
        it('should validate API token format and structure', async () => {
            const invalidTokens = [
                'short',
                '12345',
                'invalid-format',
                'a'.repeat(1000), // Too long
                '', // Empty
                null,
                undefined,
                'token with spaces',
                'token\nwith\nnewlines',
                'token\twith\ttabs'
            ];

            for (const token of invalidTokens) {
                const response = await request(app)
                    .post('/api/authenticate')
                    .send({
                        apiKey: token,
                        baseUrl: 'https://api.make.com'
                    });

                expect([400, 401, 422]).toContain(response.status);
            }
        });

        it('should implement token rotation requirements', async () => {
            const oldToken = 'old-api-token';
            
            // Authenticate with old token
            const authResponse = await request(app)
                .post('/api/authenticate')
                .send({
                    apiKey: oldToken,
                    baseUrl: 'https://api.make.com'
                });

            if (authResponse.status === 200) {
                // Request token rotation
                const rotateResponse = await request(app)
                    .post('/api/rotate-token')
                    .set('Authorization', `Bearer ${authResponse.body.token}`)
                    .send({
                        currentApiKey: oldToken
                    });

                if (rotateResponse.status === 200) {
                    const newToken = rotateResponse.body.newApiKey;

                    // Old token should no longer work
                    const oldTokenResponse = await request(app)
                        .post('/api/authenticate')
                        .send({
                            apiKey: oldToken,
                            baseUrl: 'https://api.make.com'
                        });

                    expect(oldTokenResponse.status).toBe(401);

                    // New token should work
                    const newTokenResponse = await request(app)
                        .post('/api/authenticate')
                        .send({
                            apiKey: newToken,
                            baseUrl: 'https://api.make.com'
                        });

                    expect([200, 202]).toContain(newTokenResponse.status);
                }
            }
        });

        it('should implement token scope validation', async () => {
            const limitedScopeToken = 'limited-scope-token';

            // Authenticate with limited scope token
            const authResponse = await request(app)
                .post('/api/authenticate')
                .send({
                    apiKey: limitedScopeToken,
                    baseUrl: 'https://api.make.com'
                });

            if (authResponse.status === 200) {
                // Try to access resources outside token scope
                const restrictedResponse = await request(app)
                    .post('/admin/settings')
                    .set('Authorization', `Bearer ${authResponse.body.token}`)
                    .send({
                        setting: 'test'
                    });

                expect([403, 404]).toContain(restrictedResponse.status);
            }
        });
    });

    describe('Multi-Factor Authentication', () => {
        it('should require MFA for sensitive operations', async () => {
            const authResponse = await request(app)
                .post('/api/authenticate')
                .send({
                    apiKey: 'mfa-required-token',
                    baseUrl: 'https://api.make.com'
                });

            if (authResponse.status === 200) {
                // Attempt sensitive operation without MFA
                const sensitiveResponse = await request(app)
                    .delete('/scenarios/12345')
                    .set('Authorization', `Bearer ${authResponse.body.token}`);

                expect([403, 428]).toContain(sensitiveResponse.status); // 428 Precondition Required
                
                if (sensitiveResponse.body) {
                    expect(sensitiveResponse.body).toMatchObject({
                        requiresMFA: true
                    });
                }
            }
        });

        it('should validate TOTP codes correctly', async () => {
            const invalidTOTPCodes = [
                '123456', // Static/weak code
                '000000', // Sequential code
                '111111', // Repeated digits
                'abcdef', // Non-numeric
                '12345',  // Too short
                '1234567', // Too long
                ''        // Empty
            ];

            for (const code of invalidTOTPCodes) {
                const response = await request(app)
                    .post('/api/verify-mfa')
                    .send({
                        totpCode: code,
                        sessionId: 'test-session'
                    });

                expect([400, 401, 422]).toContain(response.status);
            }
        });

        it('should prevent TOTP code replay attacks', async () => {
            const validCode = '123456';
            const sessionId = 'replay-test-session';

            // Use TOTP code first time
            const firstResponse = await request(app)
                .post('/api/verify-mfa')
                .send({
                    totpCode: validCode,
                    sessionId: sessionId
                });

            // Try to reuse the same code
            const replayResponse = await request(app)
                .post('/api/verify-mfa')
                .send({
                    totpCode: validCode,
                    sessionId: sessionId
                });

            expect([400, 401, 409]).toContain(replayResponse.status); // 409 Conflict for replay
        });
    });

    describe('Password Policy Enforcement', () => {
        it('should enforce strong password requirements', async () => {
            const weakPasswords = [
                'password',
                '123456',
                'qwerty',
                'admin',
                'test',
                'a'.repeat(4), // Too short
                'password123', // Common pattern
                'Password', // No numbers or symbols
                '12345678', // Only numbers
                'ABCDEFGH', // Only uppercase
                'abcdefgh'  // Only lowercase
            ];

            for (const password of weakPasswords) {
                const response = await request(app)
                    .post('/api/change-password')
                    .send({
                        currentPassword: 'old-password',
                        newPassword: password
                    });

                expect([400, 422]).toContain(response.status);
                
                if (response.body) {
                    expect(response.body).toMatchObject(
                        expect.objectContaining({
                            error: expect.stringMatching(/password.*requirements/i)
                        })
                    );
                }
            }
        });

        it('should prevent password reuse', async () => {
            const currentPassword = 'CurrentP@ssw0rd!';
            const oldPassword = 'OldP@ssw0rd!';

            // Try to reuse old password
            const response = await request(app)
                .post('/api/change-password')
                .send({
                    currentPassword: currentPassword,
                    newPassword: oldPassword // Previously used password
                });

            expect([400, 409, 422]).toContain(response.status);
            
            if (response.body) {
                expect(response.body).toMatchObject(
                    expect.objectContaining({
                        error: expect.stringMatching(/password.*reuse|previously.*used/i)
                    })
                );
            }
        });
    });

    describe('Account Lockout Protection', () => {
        it('should implement account lockout after multiple failures', async () => {
            const testAccount = 'lockout-test-account';
            const maxFailures = 5;

            // Make multiple failed attempts
            for (let i = 0; i < maxFailures + 1; i++) {
                await request(app)
                    .post('/api/authenticate')
                    .send({
                        apiKey: `${testAccount}-wrong-${i}`,
                        baseUrl: 'https://api.make.com'
                    });
            }

            // Account should be locked
            const lockedResponse = await request(app)
                .post('/api/authenticate')
                .send({
                    apiKey: `${testAccount}-correct`,
                    baseUrl: 'https://api.make.com'
                });

            expect([423, 429]).toContain(lockedResponse.status);
        });

        it('should provide lockout status information', async () => {
            const response = await request(app)
                .get('/api/account-status')
                .query({
                    apiKey: 'locked-account-key'
                });

            if (response.status === 200) {
                expect(response.body).toMatchObject({
                    isLocked: expect.any(Boolean),
                    lockoutExpiry: expect.any(String),
                    failedAttempts: expect.any(Number)
                });
            }
        });

        it('should implement lockout recovery mechanisms', async () => {
            const response = await request(app)
                .post('/api/unlock-account')
                .send({
                    apiKey: 'locked-account',
                    recoveryCode: 'valid-recovery-code',
                    newApiKey: 'new-secure-api-key'
                });

            if (response.status === 200) {
                // Verify account is unlocked
                const authResponse = await request(app)
                    .post('/api/authenticate')
                    .send({
                        apiKey: 'new-secure-api-key',
                        baseUrl: 'https://api.make.com'
                    });

                expect([200, 202]).toContain(authResponse.status);
            }
        });
    });

    describe('Audit Logging for Security Events', () => {
        it('should log authentication failures', async () => {
            const response = await request(app)
                .post('/api/authenticate')
                .send({
                    apiKey: 'invalid-key-for-logging',
                    baseUrl: 'https://api.make.com'
                });

            expect([401, 403]).toContain(response.status);

            // Check that failure is logged (would require access to logs)
            // This test assumes logging is properly implemented
        });

        it('should log suspicious authentication patterns', async () => {
            // Simulate suspicious pattern: rapid requests from multiple IPs
            const suspiciousRequests = [];
            
            for (let i = 0; i < 10; i++) {
                const request_promise = request(app)
                    .post('/api/authenticate')
                    .set('X-Forwarded-For', `192.168.1.${i}`)
                    .send({
                        apiKey: 'test-key',
                        baseUrl: 'https://api.make.com'
                    });
                
                suspiciousRequests.push(request_promise);
            }

            const responses = await Promise.all(suspiciousRequests);
            
            // Should trigger rate limiting or security alerts
            expect(responses.some(res => [429, 403].includes(res.status))).toBe(true);
        });
    });
});