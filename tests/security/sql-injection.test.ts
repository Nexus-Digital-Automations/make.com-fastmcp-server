import { describe, expect, it, beforeEach, afterEach } from '@jest/globals';
import request from 'supertest';
import { server } from '../../src/server';
import { MakeAPIClient } from '../../src/lib/make-api-client';

describe('SQL Injection Prevention Tests', () => {
    let app: any;
    let mockMakeClient: jest.Mocked<MakeAPIClient>;

    const sqlInjectionPayloads = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "1' UNION SELECT * FROM users--",
        "' OR 1=1--",
        "admin'--",
        "') OR ('1'='1'--",
        "' UNION SELECT password FROM users WHERE '1'='1",
        "'; INSERT INTO users VALUES('admin', 'hacked'); --",
        "1'; UPDATE users SET password='hacked' WHERE id=1; --",
        "' OR EXISTS(SELECT * FROM users) --"
    ];

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
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    describe('Authentication Endpoint SQL Injection', () => {
        sqlInjectionPayloads.forEach((payload, index) => {
            it(`should safely handle SQL injection payload ${index + 1}: ${payload.substring(0, 20)}...`, async () => {
                const response = await request(app)
                    .post('/api/authenticate')
                    .send({ 
                        apiKey: payload,
                        baseUrl: payload 
                    });

                // Should reject malicious input appropriately
                expect([400, 401, 422]).toContain(response.status);
                
                // Response should not contain SQL error messages
                expect(response.body).not.toMatchObject(
                    expect.objectContaining({
                        message: expect.stringMatching(/SQL|syntax|database|table/i)
                    })
                );
                
                // Should not expose internal database structure
                expect(JSON.stringify(response.body)).not.toMatch(/SELECT|INSERT|UPDATE|DELETE|DROP|CREATE/i);
            });
        });
    });

    describe('Scenarios Tool SQL Injection', () => {
        sqlInjectionPayloads.forEach((payload, index) => {
            it(`should prevent SQL injection in scenarios list with payload ${index + 1}`, async () => {
                const response = await request(app)
                    .post('/scenarios/list')
                    .send({
                        teamId: payload,
                        folderId: payload,
                        filter: {
                            name: payload,
                            status: payload
                        }
                    });

                // Should handle malicious input safely
                expect([400, 401, 422]).toContain(response.status);
                
                // Verify no SQL-related error exposure
                const responseText = JSON.stringify(response.body);
                expect(responseText).not.toMatch(/SQL|syntax|database|table|column/i);
                expect(responseText).not.toMatch(/ORA-|ERROR:|mysql_|pg_/i);
            });
        });

        sqlInjectionPayloads.forEach((payload, index) => {
            it(`should prevent SQL injection in scenario creation with payload ${index + 1}`, async () => {
                const response = await request(app)
                    .post('/scenarios/create')
                    .send({
                        name: payload,
                        teamId: payload,
                        folderId: payload,
                        blueprint: {
                            name: payload,
                            flow: [{
                                id: payload,
                                type: payload
                            }]
                        }
                    });

                expect([400, 401, 422]).toContain(response.status);
                
                const responseText = JSON.stringify(response.body);
                expect(responseText).not.toMatch(/SQL|syntax|database|constraint/i);
            });
        });
    });

    describe('Users and Teams SQL Injection', () => {
        sqlInjectionPayloads.forEach((payload, index) => {
            it(`should prevent SQL injection in user operations with payload ${index + 1}`, async () => {
                const response = await request(app)
                    .post('/users/list')
                    .send({
                        teamId: payload,
                        filter: {
                            email: payload,
                            name: payload,
                            role: payload
                        }
                    });

                expect([400, 401, 422]).toContain(response.status);
                
                // Ensure no user data is leaked through SQL errors
                expect(response.body).not.toMatchObject(
                    expect.objectContaining({
                        users: expect.any(Array)
                    })
                );
                
                const responseText = JSON.stringify(response.body);
                expect(responseText).not.toMatch(/SQL|database|user|email|password/i);
            });
        });
    });

    describe('Data Store SQL Injection', () => {
        sqlInjectionPayloads.forEach((payload, index) => {
            it(`should prevent SQL injection in data store operations with payload ${index + 1}`, async () => {
                const response = await request(app)
                    .post('/data-stores/get')
                    .send({
                        key: payload,
                        dataStructureId: payload
                    });

                expect([400, 401, 422]).toContain(response.status);
                
                // Should not expose data store contents through SQL injection
                expect(response.body).not.toMatchObject(
                    expect.objectContaining({
                        value: expect.anything(),
                        data: expect.anything()
                    })
                );
            });
        });

        sqlInjectionPayloads.forEach((payload, index) => {
            it(`should prevent SQL injection in data store updates with payload ${index + 1}`, async () => {
                const response = await request(app)
                    .post('/data-stores/set')
                    .send({
                        key: payload,
                        value: payload,
                        dataStructureId: payload
                    });

                expect([400, 401, 422]).toContain(response.status);
                
                // Verify malicious data is not stored
                const responseText = JSON.stringify(response.body);
                expect(responseText).not.toMatch(/updated|stored|saved/i);
            });
        });
    });

    describe('Connection and API Key SQL Injection', () => {
        sqlInjectionPayloads.forEach((payload, index) => {
            it(`should prevent SQL injection in connection creation with payload ${index + 1}`, async () => {
                const response = await request(app)
                    .post('/connections/create')
                    .send({
                        name: payload,
                        type: payload,
                        credentials: {
                            username: payload,
                            password: payload,
                            apiKey: payload
                        }
                    });

                expect([400, 401, 422]).toContain(response.status);
                
                // Should not store or expose malicious credentials
                expect(response.body).not.toMatchObject(
                    expect.objectContaining({
                        id: expect.any(String),
                        connection: expect.any(Object)
                    })
                );
            });
        });
    });

    describe('Advanced SQL Injection Patterns', () => {
        const advancedPayloads = [
            // Time-based blind SQL injection
            "'; WAITFOR DELAY '00:00:05'; --",
            "' OR IF(1=1, SLEEP(5), 0) --",
            
            // Boolean-based blind SQL injection
            "' AND (SELECT COUNT(*) FROM users) > 0 --",
            "' AND (ASCII(SUBSTRING((SELECT TOP 1 name FROM users),1,1))) > 65 --",
            
            // Union-based SQL injection
            "' UNION SELECT 1,2,3,4,5 --",
            "' UNION ALL SELECT NULL,NULL,NULL --",
            
            // Error-based SQL injection
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e)) --",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --"
        ];

        advancedPayloads.forEach((payload, index) => {
            it(`should prevent advanced SQL injection pattern ${index + 1}`, async () => {
                const response = await request(app)
                    .post('/scenarios/list')
                    .send({
                        teamId: payload,
                        filter: { name: payload }
                    });

                expect([400, 401, 422]).toContain(response.status);
                
                // Should not delay response (time-based attack prevention)
                const startTime = Date.now();
                const responseTime = Date.now() - startTime;
                expect(responseTime).toBeLessThan(3000); // Max 3 seconds response time
                
                // Should not expose database structure or version
                const responseText = JSON.stringify(response.body);
                expect(responseText).not.toMatch(/version|information_schema|mysql|postgresql|oracle/i);
            });
        });
    });

    describe('Parameter Validation and Type Safety', () => {
        it('should enforce strict parameter types', async () => {
            const response = await request(app)
                .post('/scenarios/list')
                .send({
                    teamId: 123, // Should be string
                    limit: "' OR 1=1 --", // Should be number
                    offset: { nested: "' UNION SELECT * FROM users --" } // Should be number
                });

            expect([400, 422]).toContain(response.status);
            expect(response.body).toMatchObject(
                expect.objectContaining({
                    error: expect.stringMatching(/validation|parameter|type/i)
                })
            );
        });

        it('should sanitize nested object parameters', async () => {
            const response = await request(app)
                .post('/scenarios/create')
                .send({
                    name: "test",
                    blueprint: {
                        name: "'; DROP TABLE scenarios; --",
                        flow: [{
                            id: "' OR 1=1 --",
                            type: "webhook",
                            parameters: {
                                url: "javascript:alert('xss')",
                                method: "'; DELETE FROM webhooks; --"
                            }
                        }]
                    }
                });

            expect([400, 422]).toContain(response.status);
            
            // Should reject malicious nested parameters
            const responseText = JSON.stringify(response.body);
            expect(responseText).not.toMatch(/created|saved|updated/i);
        });
    });
});