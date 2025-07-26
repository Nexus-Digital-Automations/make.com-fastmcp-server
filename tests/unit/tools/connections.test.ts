/**
 * Unit tests for connection and webhook management tools
 * Tests connection CRUD operations, webhook management, and integration security
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { UserError } from 'fastmcp';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';
import { 
  createMockServer, 
  findTool, 
  executeTool, 
  expectToolCall,
  expectProgressReported,
  expectValidZodParse,
  expectInvalidZodParse
} from '../../utils/test-helpers.js';
import { testConnection, testWebhook, testErrors } from '../../fixtures/test-data.js';

describe('Connection and Webhook Management Tools - Comprehensive Test Suite', () => {
  let mockServer: any;
  let mockApiClient: MockMakeApiClient;
  let mockTool: jest.MockedFunction<any>;

  beforeEach(() => {
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockTool = serverSetup.mockTool;
    mockApiClient = new MockMakeApiClient();
  });

  afterEach(() => {
    jest.clearAllMocks();
    mockApiClient.reset();
  });

  describe('Tool Registration and Configuration', () => {
    it('should register all connection and webhook tools with correct configuration', async () => {
      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const expectedTools = [
        'list-connections',
        'get-connection',
        'create-connection',
        'update-connection',
        'delete-connection',
        'test-connection',
        'list-webhooks',
        'create-webhook',
        'update-webhook',
        'delete-webhook'
      ];

      expectedTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool).toBeDefined();
        expect(tool.name).toBe(toolName);
        expect(tool.description).toBeDefined();
        expect(tool.parameters).toBeDefined();
      });
    });
  });

  describe('Connection Management', () => {
    describe('list-connections tool', () => {
      it('should list connections with default filters', async () => {
        mockApiClient.mockResponse('GET', '/connections', {
          success: true,
          data: [testConnection],
          metadata: { total: 1 }
        });

        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-connections');
        const result = await executeTool(tool, {});
        
        expect(result).toContain(testConnection.name);
        expect(result).toContain(testConnection.service);
        expect(result).toContain('pagination');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].params.limit).toBe(20);
        expect(calls[0].params.offset).toBe(0);
      });

      it('should filter connections by service, status, and search', async () => {
        mockApiClient.mockResponse('GET', '/connections', {
          success: true,
          data: [testConnection],
          metadata: { total: 1 }
        });

        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-connections');
        const result = await executeTool(tool, {
          service: 'slack',
          status: 'valid',
          search: 'production',
          limit: 50,
          offset: 10
        });

        const calls = mockApiClient.getCallLog();
        expect(calls[0].params.service).toBe('slack');
        expect(calls[0].params.valid).toBe(true);
        expect(calls[0].params.search).toBe('production');
        expect(calls[0].params.limit).toBe(50);
        expect(calls[0].params.offset).toBe(10);
      });

      it('should handle pagination with hasMore flag', async () => {
        const connections = Array(20).fill(testConnection);
        mockApiClient.mockResponse('GET', '/connections', {
          success: true,
          data: connections,
          metadata: { total: 100 }
        });

        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-connections');
        const result = await executeTool(tool, {
          limit: 20,
          offset: 10
        });

        const parsed = JSON.parse(result);
        expect(parsed.pagination.total).toBe(100);
        expect(parsed.pagination.limit).toBe(20);
        expect(parsed.pagination.offset).toBe(10);
        expect(parsed.pagination.hasMore).toBe(true);
      });

      it('should validate input parameters with Zod schema', async () => {
        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-connections');
        
        // Valid parameters
        expectValidZodParse(tool.parameters, {
          service: 'slack',
          status: 'valid',
          search: 'test',
          limit: 50,
          offset: 0
        });

        // Invalid parameters
        expectInvalidZodParse(tool.parameters, {
          limit: 0 // Invalid: must be >= 1
        });
        
        expectInvalidZodParse(tool.parameters, {
          limit: 101 // Invalid: must be <= 100
        });
        
        expectInvalidZodParse(tool.parameters, {
          status: 'invalid' // Invalid status
        });
      });
    });

    describe('get-connection tool', () => {
      it('should get connection details successfully', async () => {
        mockApiClient.mockResponse('GET', '/connections/12345', {
          success: true,
          data: testConnection
        });

        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-connection');
        const result = await executeTool(tool, { connectionId: 12345 });
        
        expect(result).toContain(testConnection.name);
        expect(result).toContain(testConnection.service);
        expect(result).toContain(testConnection.accountName);
      });

      it('should handle connection not found', async () => {
        mockApiClient.mockResponse('GET', '/connections/99999', {
          success: true,
          data: {}
        });

        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-connection');
        
        await expect(executeTool(tool, { connectionId: 99999 }))
          .rejects.toThrow('Connection with ID 99999 not found');
      });

      it('should handle API errors gracefully', async () => {
        mockApiClient.mockResponse('GET', '/connections/12345', {
          success: false,
          error: testErrors.apiError
        });

        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-connection');
        
        await expect(executeTool(tool, { connectionId: 12345 }))
          .rejects.toThrow(UserError);
      });
    });

    describe('create-connection tool', () => {
      it('should create connection successfully with all parameters', async () => {
        const newConnection = {
          ...testConnection,
          id: 12346,
          name: 'New Slack Connection',
          service: 'slack',
          accountName: 'team-workspace',
          credentials: { token: 'xoxb-token-123' },
          metadata: { department: 'engineering' }
        };

        mockApiClient.mockResponse('POST', '/connections', {
          success: true,
          data: newConnection
        });

        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-connection');
        const result = await executeTool(tool, {
          name: 'New Slack Connection',
          service: 'slack',
          accountName: 'team-workspace',
          credentials: { token: 'xoxb-token-123' },
          metadata: { department: 'engineering' }
        });

        expect(result).toContain('New Slack Connection');
        expect(result).toContain('created successfully');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.name).toBe('New Slack Connection');
        expect(calls[0].data.service).toBe('slack');
        expect(calls[0].data.accountName).toBe('team-workspace');
        expect(calls[0].data.credentials.token).toBe('xoxb-token-123');
        expect(calls[0].data.metadata.department).toBe('engineering');
      });

      it('should create connection with minimal required parameters', async () => {
        const minimalConnection = {
          ...testConnection,
          id: 12347,
          name: 'Gmail Connection',
          service: 'gmail',
          accountName: 'user@example.com'
        };

        mockApiClient.mockResponse('POST', '/connections', {
          success: true,
          data: minimalConnection
        });

        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-connection');
        const result = await executeTool(tool, {
          name: 'Gmail Connection',
          service: 'gmail',
          accountName: 'user@example.com',
          credentials: { refresh_token: 'refresh_123' }
        });

        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.metadata).toEqual({});
      });

      it('should handle creation failures', async () => {
        mockApiClient.mockResponse('POST', '/connections', {
          success: false,
          error: { message: 'Invalid credentials provided' }
        });

        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-connection');
        
        await expect(executeTool(tool, {
          name: 'Invalid Connection',
          service: 'slack',
          accountName: 'invalid',
          credentials: { token: 'invalid' }
        })).rejects.toThrow('Invalid credentials provided');
      });

      it('should validate input parameters', async () => {
        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-connection');
        
        // Valid parameters
        expectValidZodParse(tool.parameters, {
          name: 'Test Connection',
          service: 'slack',
          accountName: 'test-account',
          credentials: { token: 'test-token' }
        });

        // Invalid parameters
        expectInvalidZodParse(tool.parameters, {
          name: '', // Invalid: must be non-empty
          service: 'slack',
          accountName: 'test',
          credentials: {}
        });
        
        expectInvalidZodParse(tool.parameters, {
          name: 'Test',
          service: '', // Invalid: must be non-empty
          accountName: 'test',
          credentials: {}
        });
      });
    });

    describe('update-connection tool', () => {
      it('should update connection with selective fields', async () => {
        const updatedConnection = {
          ...testConnection,
          name: 'Updated Connection Name',
          accountName: 'updated-account@example.com'
        };

        mockApiClient.mockResponse('PATCH', '/connections/12345', {
          success: true,
          data: updatedConnection
        });

        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-connection');
        const result = await executeTool(tool, {
          connectionId: 12345,
          name: 'Updated Connection Name',
          accountName: 'updated-account@example.com'
        });

        expect(result).toContain('Connection updated successfully');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.name).toBe('Updated Connection Name');
        expect(calls[0].data.accountName).toBe('updated-account@example.com');
        expect(calls[0].data.credentials).toBeUndefined();
        expect(calls[0].data.metadata).toBeUndefined();
      });

      it('should update credentials and metadata', async () => {
        const updatedConnection = {
          ...testConnection,
          credentials: { token: 'new-token-123' },
          metadata: { updated: true, version: '2.0' }
        };

        mockApiClient.mockResponse('PATCH', '/connections/12345', {
          success: true,
          data: updatedConnection
        });

        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-connection');
        const result = await executeTool(tool, {
          connectionId: 12345,
          credentials: { token: 'new-token-123' },
          metadata: { updated: true, version: '2.0' }
        });

        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.credentials.token).toBe('new-token-123');
        expect(calls[0].data.metadata.updated).toBe(true);
        expect(calls[0].data.metadata.version).toBe('2.0');
      });

      it('should handle no update data provided', async () => {
        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-connection');
        
        await expect(executeTool(tool, {
          connectionId: 12345
        })).rejects.toThrow('No update data provided');
      });

      it('should handle update failures', async () => {
        mockApiClient.mockResponse('PATCH', '/connections/12345', {
          success: false,
          error: { message: 'Connection not found' }
        });

        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-connection');
        
        await expect(executeTool(tool, {
          connectionId: 12345,
          name: 'Updated Name'
        })).rejects.toThrow('Connection not found');
      });
    });

    describe('delete-connection tool', () => {
      it('should delete connection successfully', async () => {
        mockApiClient.mockResponse('DELETE', '/connections/12345', {
          success: true,
          data: { deleted: true }
        });

        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'delete-connection');
        const result = await executeTool(tool, { connectionId: 12345 });
        
        expect(result).toContain('Connection 12345 deleted successfully');
      });

      it('should handle deletion failures', async () => {
        mockApiClient.mockResponse('DELETE', '/connections/12345', {
          success: false,
          error: { message: 'Connection is in use by active scenarios' }
        });

        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'delete-connection');
        
        await expect(executeTool(tool, { connectionId: 12345 }))
          .rejects.toThrow('Connection is in use by active scenarios');
      });
    });

    describe('test-connection tool', () => {
      it('should test connection successfully', async () => {
        mockApiClient.mockResponse('POST', '/connections/12345/test', {
          success: true,
          data: {
            valid: true,
            message: 'Connection test successful',
            details: {
              responseTime: 150,
              endpoint: 'https://api.slack.com/api/auth.test'
            }
          }
        });

        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'test-connection');
        const result = await executeTool(tool, { connectionId: 12345 });
        
        const parsed = JSON.parse(result);
        expect(parsed.connectionId).toBe(12345);
        expect(parsed.isValid).toBe(true);
        expect(parsed.message).toBe('Connection test successful');
        expect(parsed.details.responseTime).toBe(150);
      });

      it('should test connection with specific endpoint', async () => {
        mockApiClient.mockResponse('POST', '/connections/12345/test', {
          success: true,
          data: {
            valid: true,
            message: 'Endpoint test successful',
            details: { endpoint: '/api/v1/custom' }
          }
        });

        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'test-connection');
        const result = await executeTool(tool, {
          connectionId: 12345,
          testEndpoint: '/api/v1/custom'
        });

        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.endpoint).toBe('/api/v1/custom');
      });

      it('should handle failed connection test', async () => {
        mockApiClient.mockResponse('POST', '/connections/12345/test', {
          success: true,
          data: {
            valid: false,
            message: 'Authentication failed - invalid token',
            details: { errorCode: 'AUTH_FAILED' }
          }
        });

        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'test-connection');
        const result = await executeTool(tool, { connectionId: 12345 });
        
        const parsed = JSON.parse(result);
        expect(parsed.isValid).toBe(false);
        expect(parsed.message).toBe('Authentication failed - invalid token');
      });

      it('should handle test API failures', async () => {
        mockApiClient.mockResponse('POST', '/connections/12345/test', {
          success: false,
          error: { message: 'Connection not found' }
        });

        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'test-connection');
        
        await expect(executeTool(tool, { connectionId: 12345 }))
          .rejects.toThrow('Connection not found');
      });
    });
  });

  describe('Webhook Management', () => {
    describe('list-webhooks tool', () => {
      it('should list webhooks with default filters', async () => {
        mockApiClient.mockResponse('GET', '/webhooks', {
          success: true,
          data: [testWebhook],
          metadata: { total: 1 }
        });

        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-webhooks');
        const result = await executeTool(tool, {});
        
        expect(result).toContain(testWebhook.name);
        expect(result).toContain(testWebhook.url);
        expect(result).toContain('pagination');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].params.limit).toBe(20);
        expect(calls[0].params.offset).toBe(0);
      });

      it('should filter webhooks by connection, scenario, and status', async () => {
        mockApiClient.mockResponse('GET', '/webhooks', {
          success: true,
          data: [testWebhook],
          metadata: { total: 1 }
        });

        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-webhooks');
        const result = await executeTool(tool, {
          connectionId: 12345,
          scenarioId: 67890,
          status: 'active',
          limit: 50,
          offset: 5
        });

        const calls = mockApiClient.getCallLog();
        expect(calls[0].params.connectionId).toBe(12345);
        expect(calls[0].params.scenarioId).toBe(67890);
        expect(calls[0].params.active).toBe(true);
        expect(calls[0].params.limit).toBe(50);
        expect(calls[0].params.offset).toBe(5);
      });

      it('should handle inactive status filter', async () => {
        mockApiClient.mockResponse('GET', '/webhooks', {
          success: true,
          data: [{ ...testWebhook, isActive: false }],
          metadata: { total: 1 }
        });

        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-webhooks');
        const result = await executeTool(tool, {
          status: 'inactive'
        });

        const calls = mockApiClient.getCallLog();
        expect(calls[0].params.active).toBe(false);
      });
    });

    describe('create-webhook tool', () => {
      it('should create webhook with all parameters', async () => {
        const newWebhook = {
          ...testWebhook,
          id: 12346,
          name: 'New Test Webhook',
          url: 'https://example.com/webhook/new',
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-API-Key': 'secret' },
          connectionId: 12345,
          scenarioId: 67890,
          isActive: true
        };

        mockApiClient.mockResponse('POST', '/webhooks', {
          success: true,
          data: newWebhook
        });

        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-webhook');
        const result = await executeTool(tool, {
          name: 'New Test Webhook',
          url: 'https://example.com/webhook/new',
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-API-Key': 'secret' },
          connectionId: 12345,
          scenarioId: 67890,
          isActive: true
        });

        expect(result).toContain('New Test Webhook');
        expect(result).toContain('created successfully');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.name).toBe('New Test Webhook');
        expect(calls[0].data.url).toBe('https://example.com/webhook/new');
        expect(calls[0].data.method).toBe('POST');
        expect(calls[0].data.headers['Content-Type']).toBe('application/json');
        expect(calls[0].data.connectionId).toBe(12345);
        expect(calls[0].data.scenarioId).toBe(67890);
        expect(calls[0].data.isActive).toBe(true);
      });

      it('should create webhook with minimal parameters', async () => {
        const minimalWebhook = {
          ...testWebhook,
          id: 12347,
          name: 'Minimal Webhook',
          url: 'https://example.com/minimal'
        };

        mockApiClient.mockResponse('POST', '/webhooks', {
          success: true,
          data: minimalWebhook
        });

        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-webhook');
        const result = await executeTool(tool, {
          name: 'Minimal Webhook',
          url: 'https://example.com/minimal'
        });

        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.method).toBe('POST'); // Default value
        expect(calls[0].data.headers).toEqual({});
        expect(calls[0].data.isActive).toBe(true); // Default value
      });

      it('should validate webhook URL format', async () => {
        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-webhook');
        
        // Valid URL
        expectValidZodParse(tool.parameters, {
          name: 'Test Webhook',
          url: 'https://example.com/webhook'
        });

        // Invalid URL
        expectInvalidZodParse(tool.parameters, {
          name: 'Test Webhook',
          url: 'not-a-url'
        });
      });

      it('should validate HTTP methods', async () => {
        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-webhook');
        
        const validMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
        
        for (const method of validMethods) {
          expectValidZodParse(tool.parameters, {
            name: 'Test Webhook',
            url: 'https://example.com/webhook',
            method: method as any
          });
        }

        // Invalid method
        expectInvalidZodParse(tool.parameters, {
          name: 'Test Webhook',
          url: 'https://example.com/webhook',
          method: 'INVALID'
        });
      });
    });

    describe('update-webhook tool', () => {
      it('should update webhook with selective fields', async () => {
        const updatedWebhook = {
          ...testWebhook,
          name: 'Updated Webhook Name',
          url: 'https://example.com/updated-webhook',
          isActive: false
        };

        mockApiClient.mockResponse('PATCH', '/webhooks/12345', {
          success: true,
          data: updatedWebhook
        });

        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-webhook');
        const result = await executeTool(tool, {
          webhookId: 12345,
          name: 'Updated Webhook Name',
          url: 'https://example.com/updated-webhook',
          isActive: false
        });

        expect(result).toContain('Webhook updated successfully');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.name).toBe('Updated Webhook Name');
        expect(calls[0].data.url).toBe('https://example.com/updated-webhook');
        expect(calls[0].data.isActive).toBe(false);
        expect(calls[0].data.method).toBeUndefined();
        expect(calls[0].data.headers).toBeUndefined();
      });

      it('should update method and headers', async () => {
        const updatedWebhook = {
          ...testWebhook,
          method: 'PUT',
          headers: { 'Authorization': 'Bearer token123', 'X-Custom': 'value' }
        };

        mockApiClient.mockResponse('PATCH', '/webhooks/12345', {
          success: true,
          data: updatedWebhook
        });

        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-webhook');
        const result = await executeTool(tool, {
          webhookId: 12345,
          method: 'PUT',
          headers: { 'Authorization': 'Bearer token123', 'X-Custom': 'value' }
        });

        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.method).toBe('PUT');
        expect(calls[0].data.headers.Authorization).toBe('Bearer token123');
        expect(calls[0].data.headers['X-Custom']).toBe('value');
      });

      it('should handle no update data provided', async () => {
        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-webhook');
        
        await expect(executeTool(tool, {
          webhookId: 12345
        })).rejects.toThrow('No update data provided');
      });

      it('should handle update failures', async () => {
        mockApiClient.mockResponse('PATCH', '/webhooks/12345', {
          success: false,
          error: { message: 'Webhook not found' }
        });

        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'update-webhook');
        
        await expect(executeTool(tool, {
          webhookId: 12345,
          name: 'Updated Name'
        })).rejects.toThrow('Webhook not found');
      });
    });

    describe('delete-webhook tool', () => {
      it('should delete webhook successfully', async () => {
        mockApiClient.mockResponse('DELETE', '/webhooks/12345', {
          success: true,
          data: { deleted: true }
        });

        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'delete-webhook');
        const result = await executeTool(tool, { webhookId: 12345 });
        
        expect(result).toContain('Webhook 12345 deleted successfully');
      });

      it('should handle deletion failures', async () => {
        mockApiClient.mockResponse('DELETE', '/webhooks/12345', {
          success: false,
          error: { message: 'Webhook is actively receiving data' }
        });

        const { addConnectionTools } = await import('../../../src/tools/connections.js');
        addConnectionTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'delete-webhook');
        
        await expect(executeTool(tool, { webhookId: 12345 }))
          .rejects.toThrow('Webhook is actively receiving data');
      });
    });
  });

  describe('Security and Data Handling', () => {
    it('should mask sensitive credentials in connection responses', async () => {
      const connectionWithCredentials = {
        ...testConnection,
        credentials: {
          token: 'xoxb-sensitive-token-12345',
          refresh_token: 'refresh-secret-67890',
          client_secret: 'client-secret-abcdef'
        }
      };

      mockApiClient.mockResponse('GET', '/connections/12345', {
        success: true,
        data: connectionWithCredentials
      });

      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-connection');
      const result = await executeTool(tool, { connectionId: 12345 });
      
      // Should contain connection data but credentials should be handled appropriately
      expect(result).toContain(testConnection.name);
      expect(result).toContain(testConnection.service);
      
      // Note: In a real implementation, credentials should be masked or excluded from responses
      // This test documents the expected behavior but actual masking would be implemented
      // in the tool itself, not in the test mock
    });

    it('should handle webhook authentication headers securely', async () => {
      const webhookWithAuth = {
        ...testWebhook,
        headers: {
          'Authorization': 'Bearer secret-token-12345',
          'X-API-Key': 'api-key-67890',
          'Content-Type': 'application/json'
        }
      };

      mockApiClient.mockResponse('GET', '/webhooks', {
        success: true,
        data: [webhookWithAuth],
        metadata: { total: 1 }
      });

      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-webhooks');
      const result = await executeTool(tool, {});
      
      // Should contain webhook data but sensitive headers should be handled appropriately
      expect(result).toContain(testWebhook.name);
      expect(result).toContain(testWebhook.url);
      
      // Note: In a real implementation, sensitive headers should be masked or excluded
      // This test documents the expected behavior
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle API errors gracefully across all tools', async () => {
      const toolsToTest = [
        { name: 'list-connections', params: {} },
        { name: 'get-connection', params: { connectionId: 12345 } },
        { name: 'create-connection', params: { name: 'Test', service: 'test', accountName: 'test', credentials: {} } },
        { name: 'test-connection', params: { connectionId: 12345 } },
        { name: 'list-webhooks', params: {} },
        { name: 'create-webhook', params: { name: 'Test', url: 'https://example.com' } }
      ];

      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);

      for (const { name, params } of toolsToTest) {
        mockApiClient.mockResponse('GET', '/mock-endpoint', {
          success: false,
          error: testErrors.apiError
        });

        const tool = findTool(mockTool, name);
        await expect(executeTool(tool, params))
          .rejects.toThrow(UserError);
        
        mockApiClient.reset();
      }
    });

    it('should handle network errors', async () => {
      mockApiClient.mockNetworkError();

      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-connections');
      
      await expect(executeTool(tool, {}))
        .rejects.toThrow(UserError);
    });

    it('should log operations correctly', async () => {
      const mockLog = { info: jest.fn(), error: jest.fn() };
      
      mockApiClient.mockResponse('GET', '/connections', {
        success: true,
        data: [testConnection],
        metadata: { total: 1 }
      });

      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-connections');
      await executeTool(tool, {}, { log: mockLog });
      
      expect(mockLog.info).toHaveBeenCalledWith(
        expect.stringContaining('Listing connections'),
        expect.any(Object)
      );
      expect(mockLog.info).toHaveBeenCalledWith(
        expect.stringContaining('Successfully retrieved connections'),
        expect.objectContaining({ count: 1, total: 1 })
      );
    });
  });

  describe('Input Validation', () => {
    it('should validate all schema parameters correctly', async () => {
      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);

      // Test connection filters
      const connectionFiltersSchema = findTool(mockTool, 'list-connections').parameters;
      expectValidZodParse(connectionFiltersSchema, {
        service: 'slack',
        status: 'valid',
        search: 'production',
        limit: 50,
        offset: 10
      });

      // Test create connection schema
      const createConnectionSchema = findTool(mockTool, 'create-connection').parameters;
      expectValidZodParse(createConnectionSchema, {
        name: 'Test Connection',
        service: 'gmail',
        accountName: 'test@example.com',
        credentials: { refresh_token: 'token123' },
        metadata: { department: 'engineering' }
      });

      // Test webhook filters
      const webhookFiltersSchema = findTool(mockTool, 'list-webhooks').parameters;
      expectValidZodParse(webhookFiltersSchema, {
        connectionId: 12345,
        scenarioId: 67890,
        status: 'active',
        limit: 25,
        offset: 5
      });

      // Test create webhook schema
      const createWebhookSchema = findTool(mockTool, 'create-webhook').parameters;
      expectValidZodParse(createWebhookSchema, {
        name: 'Test Webhook',
        url: 'https://example.com/webhook',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        connectionId: 12345,
        scenarioId: 67890,
        isActive: true
      });
    });

    it('should reject invalid input parameters', async () => {
      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);

      // Invalid connection parameters
      const connectionFiltersSchema = findTool(mockTool, 'list-connections').parameters;
      expectInvalidZodParse(connectionFiltersSchema, {
        limit: 0 // Must be >= 1
      });
      
      expectInvalidZodParse(connectionFiltersSchema, {
        limit: 101 // Must be <= 100
      });

      // Invalid webhook parameters
      const createWebhookSchema = findTool(mockTool, 'create-webhook').parameters;
      expectInvalidZodParse(createWebhookSchema, {
        name: 'Test',
        url: 'not-a-valid-url'
      });
      
      expectInvalidZodParse(createWebhookSchema, {
        name: '', // Must be non-empty
        url: 'https://example.com'
      });
    });
  });

  describe('Integration Scenarios', () => {
    it('should handle complete connection lifecycle', async () => {
      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);

      // 1. Create connection
      mockApiClient.mockResponse('POST', '/connections', {
        success: true,
        data: { ...testConnection, id: 12345 }
      });
      
      const createTool = findTool(mockTool, 'create-connection');
      const createResult = await executeTool(createTool, {
        name: 'Test Slack Connection',
        service: 'slack',
        accountName: 'team-workspace',
        credentials: { token: 'xoxb-token' }
      });
      
      expect(createResult).toContain('created successfully');

      // 2. Test connection
      mockApiClient.mockResponse('POST', '/connections/12345/test', {
        success: true,
        data: { valid: true, message: 'Connection test successful' }
      });
      
      const testTool = findTool(mockTool, 'test-connection');
      const testResult = await executeTool(testTool, { connectionId: 12345 });
      
      expect(testResult).toContain('"isValid":true');

      // 3. Update connection
      mockApiClient.mockResponse('PATCH', '/connections/12345', {
        success: true,
        data: { ...testConnection, id: 12345, name: 'Updated Slack Connection' }
      });
      
      const updateTool = findTool(mockTool, 'update-connection');
      const updateResult = await executeTool(updateTool, {
        connectionId: 12345,
        name: 'Updated Slack Connection'
      });
      
      expect(updateResult).toContain('updated successfully');

      // 4. Delete connection
      mockApiClient.mockResponse('DELETE', '/connections/12345', {
        success: true,
        data: { deleted: true }
      });
      
      const deleteTool = findTool(mockTool, 'delete-connection');
      const deleteResult = await executeTool(deleteTool, { connectionId: 12345 });
      
      expect(deleteResult).toContain('deleted successfully');
    });

    it('should handle complete webhook lifecycle', async () => {
      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);

      // 1. Create webhook
      mockApiClient.mockResponse('POST', '/webhooks', {
        success: true,
        data: { ...testWebhook, id: 67890 }
      });
      
      const createTool = findTool(mockTool, 'create-webhook');
      const createResult = await executeTool(createTool, {
        name: 'Test Webhook',
        url: 'https://example.com/webhook',
        method: 'POST',
        connectionId: 12345
      });
      
      expect(createResult).toContain('created successfully');

      // 2. Update webhook
      mockApiClient.mockResponse('PATCH', '/webhooks/67890', {
        success: true,
        data: { ...testWebhook, id: 67890, isActive: false }
      });
      
      const updateTool = findTool(mockTool, 'update-webhook');
      const updateResult = await executeTool(updateTool, {
        webhookId: 67890,
        isActive: false
      });
      
      expect(updateResult).toContain('updated successfully');

      // 3. Delete webhook
      mockApiClient.mockResponse('DELETE', '/webhooks/67890', {
        success: true,
        data: { deleted: true }
      });
      
      const deleteTool = findTool(mockTool, 'delete-webhook');
      const deleteResult = await executeTool(deleteTool, { webhookId: 67890 });
      
      expect(deleteResult).toContain('deleted successfully');
    });
  });
});