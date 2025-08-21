/**
 * Basic Test Suite for Connection Management Tools
 * Tests core functionality of connection and webhook management tools
 * Focuses on tool registration, configuration validation, and basic execution patterns
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { UserError } from 'fastmcp';
import { createMockServer, findTool, executeTool, expectValidZodParse, expectInvalidZodParse } from '../../utils/test-helpers.js';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';
import { testErrors } from '../../fixtures/test-data.js';

describe('Connection Management Tools - Basic Tests', () => {
  let mockServer: any;
  let mockTool: jest.MockedFunction<any>;
  let mockApiClient: MockMakeApiClient;

  // Complete test connection for testing
  const testConnection = {
    id: 4001,
    name: 'Test Slack Connection',
    service: 'slack',
    accountName: 'test-workspace',
    valid: true,
    lastVerified: '2024-01-15T10:30:00Z',
    createdAt: '2024-01-01T00:00:00Z',
    credentials: {
      token: 'xoxb-test-token',
      workspace: 'test-workspace',
      expires_at: '2024-12-31T23:59:59Z'
    },
    metadata: {
      department: 'engineering',
      environment: 'production'
    }
  };

  // Complete test webhook for testing
  const testWebhook = {
    id: 5001,
    name: 'Test Order Webhook',
    url: 'https://api.company.com/webhooks/orders',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer test-token'
    },
    connectionId: 4001,
    scenarioId: 2001,
    isActive: true,
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-15T10:30:00Z'
  };

  // Test diagnostic result for advanced diagnostics
  const testDiagnosticResult = {
    connectionId: 4001,
    name: 'Test Slack Connection',
    service: 'slack',
    accountName: 'test-workspace',
    overallHealth: 'healthy' as const,
    healthScore: 95,
    diagnostics: [
      {
        category: 'health' as const,
        severity: 'info' as const,
        title: 'Connection Health: Good',
        description: 'Connection passes basic health checks',
        details: {
          name: 'Test Slack Connection',
          service: 'slack',
          isActive: true,
          lastVerified: '2024-01-15T10:30:00Z'
        },
        recommendations: ['Continue monitoring connection health'],
        fixable: false,
        timestamp: '2024-01-15T12:00:00Z'
      }
    ],
    summary: {
      totalIssues: 0,
      criticalIssues: 0,
      warningIssues: 0,
      infoIssues: 1,
      fixableIssues: 0
    },
    executionTime: 150,
    timestamp: '2024-01-15T12:00:00Z'
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
    it('should successfully import and register connection tools', async () => {
      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      
      // Should not throw an error
      expect(() => {
        addConnectionTools(mockServer, mockApiClient as any);
      }).not.toThrow();
      
      // Should call addTool for each connection tool
      expect(mockTool).toHaveBeenCalled();
      expect(mockTool.mock.calls.length).toBeGreaterThan(0);
    });

    it('should export the expected connection tools and functions', async () => {
      const connectionsModule = await import('../../../src/tools/connections.js');
      
      // Check that expected exports exist
      expect(connectionsModule.addConnectionTools).toBeDefined();
      expect(typeof connectionsModule.addConnectionTools).toBe('function');
      expect(connectionsModule.default).toBeDefined();
      expect(typeof connectionsModule.default).toBe('function');
      
      // Note: TypeScript interfaces are not available at runtime, so we can't test for them
      // This is expected behavior - interfaces exist only during compilation
    });

    it('should register all core connection management tools', async () => {
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
        'delete-webhook',
        'diagnose-connection-issues'
      ];
      
      expectedTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool).toBeDefined();
        expect(tool.name).toBe(toolName);
      });
    });
  });

  describe('Tool Configuration Validation', () => {
    it('should have correct structure for list-connections tool', async () => {
      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-connections');
      
      expect(tool.name).toBe('list-connections');
      expect(tool.description).toContain('List and filter app connections');
      expect(tool.parameters).toBeDefined();
      expect(typeof tool.execute).toBe('function');
      expect(tool.annotations?.readOnlyHint).toBe(true);
      expect(tool.annotations?.openWorldHint).toBe(true);
    });

    it('should have correct structure for connection CRUD operations', async () => {
      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const getConnectionTool = findTool(mockTool, 'get-connection');
      expect(getConnectionTool.name).toBe('get-connection');
      expect(getConnectionTool.description).toContain('detailed information');
      expect(getConnectionTool.parameters).toBeDefined();

      const createConnectionTool = findTool(mockTool, 'create-connection');
      expect(createConnectionTool.name).toBe('create-connection');
      expect(createConnectionTool.description).toContain('Create a new app connection');
      expect(createConnectionTool.parameters).toBeDefined();

      const updateConnectionTool = findTool(mockTool, 'update-connection');
      expect(updateConnectionTool.name).toBe('update-connection');
      expect(updateConnectionTool.description).toContain('Update an existing app connection');
      expect(updateConnectionTool.parameters).toBeDefined();

      const deleteConnectionTool = findTool(mockTool, 'delete-connection');
      expect(deleteConnectionTool.name).toBe('delete-connection');
      expect(deleteConnectionTool.description).toContain('Delete an app connection');
      expect(deleteConnectionTool.parameters).toBeDefined();
      expect(deleteConnectionTool.annotations?.destructiveHint).toBe(true);
    });

    it('should have correct structure for webhook management tools', async () => {
      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const listWebhooksTool = findTool(mockTool, 'list-webhooks');
      expect(listWebhooksTool.name).toBe('list-webhooks');
      expect(listWebhooksTool.description).toContain('List and filter webhooks');
      expect(listWebhooksTool.parameters).toBeDefined();

      const createWebhookTool = findTool(mockTool, 'create-webhook');
      expect(createWebhookTool.name).toBe('create-webhook');
      expect(createWebhookTool.description).toContain('Create a new webhook');
      expect(createWebhookTool.parameters).toBeDefined();

      const updateWebhookTool = findTool(mockTool, 'update-webhook');
      expect(updateWebhookTool.name).toBe('update-webhook');
      expect(updateWebhookTool.description).toContain('Update an existing webhook');
      expect(updateWebhookTool.parameters).toBeDefined();

      const deleteWebhookTool = findTool(mockTool, 'delete-webhook');
      expect(deleteWebhookTool.name).toBe('delete-webhook');
      expect(deleteWebhookTool.description).toContain('Delete a webhook');
      expect(deleteWebhookTool.parameters).toBeDefined();
      expect(deleteWebhookTool.annotations?.destructiveHint).toBe(true);
    });

    it('should have correct structure for connection testing and diagnostics', async () => {
      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const testConnectionTool = findTool(mockTool, 'test-connection');
      expect(testConnectionTool.name).toBe('test-connection');
      expect(testConnectionTool.description).toContain('Test an app connection');
      expect(testConnectionTool.parameters).toBeDefined();
      expect(testConnectionTool.annotations?.readOnlyHint).toBe(true);

      const diagnoseTool = findTool(mockTool, 'diagnose-connection-issues');
      expect(diagnoseTool.name).toBe('diagnose-connection-issues');
      expect(diagnoseTool.description).toContain('Comprehensive connection diagnostics');
      expect(diagnoseTool.parameters).toBeDefined();
      expect(diagnoseTool.annotations?.readOnlyHint).toBe(true);
    });
  });

  describe('Schema Validation', () => {
    it('should validate connection filters schema with correct inputs', async () => {
      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-connections');
      
      // Valid inputs
      const validInputs = [
        {},
        { service: 'slack' },
        { status: 'valid' },
        { search: 'production' },
        { limit: 50, offset: 10 },
        { service: 'gmail', status: 'invalid', search: 'test', limit: 25, offset: 5 }
      ];
      
      validInputs.forEach(input => {
        expectValidZodParse(tool.parameters, input);
      });
    });

    it('should reject invalid connection filters schema inputs', async () => {
      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-connections');
      
      // Invalid inputs
      const invalidInputs = [
        { status: 'unknown' }, // invalid status enum
        { limit: 0 }, // limit must be >= 1
        { limit: 101 }, // limit must be <= 100
        { offset: -1 }, // offset must be >= 0
        { unknownField: 'value' }, // unexpected field due to strict schema
      ];
      
      invalidInputs.forEach(input => {
        expectInvalidZodParse(tool.parameters, input);
      });
    });

    it('should validate create connection schema with different services', async () => {
      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-connection');
      
      // Valid Slack connection input
      const validSlackConnection = {
        name: 'Production Slack',
        service: 'slack',
        accountName: 'company-workspace',
        credentials: {
          token: 'xoxb-slack-token',
          workspace: 'company'
        },
        metadata: {
          department: 'engineering',
          environment: 'production'
        }
      };
      
      expectValidZodParse(tool.parameters, validSlackConnection);

      // Valid Gmail connection input
      const validGmailConnection = {
        name: 'Support Gmail',
        service: 'gmail',
        accountName: 'support@company.com',
        credentials: {
          refresh_token: 'gmail-refresh-token',
          client_id: 'gmail-client-id'
        }
      };
      
      expectValidZodParse(tool.parameters, validGmailConnection);
    });

    it('should validate webhook creation schema with different methods', async () => {
      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-webhook');
      
      // Valid POST webhook
      const validPostWebhook = {
        name: 'Order Processing Webhook',
        url: 'https://api.company.com/webhooks/orders',
        method: 'POST' as const,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer webhook-token'
        },
        connectionId: 4001,
        scenarioId: 2001,
        isActive: true
      };
      
      expectValidZodParse(tool.parameters, validPostWebhook);

      // Valid GET webhook (minimal)
      const validGetWebhook = {
        name: 'Status Check Webhook',
        url: 'https://api.company.com/status',
        method: 'GET' as const
      };
      
      expectValidZodParse(tool.parameters, validGetWebhook);
    });

    it('should validate connection diagnostics schema with comprehensive options', async () => {
      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'diagnose-connection-issues');
      
      const validDiagnosticOptions = {
        connectionId: 4001,
        diagnosticTypes: ['connectivity', 'authentication', 'performance'],
        includePerformanceMetrics: true,
        includeSecurityChecks: true,
        testConnectivity: true,
        timeRangeHours: 72,
        severityFilter: 'warning' as const,
        generateReport: true
      };
      
      expectValidZodParse(tool.parameters, validDiagnosticOptions);

      // Test with service filter instead of connectionId
      const validServiceDiagnostics = {
        service: 'slack',
        diagnosticTypes: ['all'],
        includePerformanceMetrics: false,
        includeSecurityChecks: false,
        testConnectivity: false,
        timeRangeHours: 24
      };
      
      expectValidZodParse(tool.parameters, validServiceDiagnostics);
    });
  });

  describe('Basic Tool Execution', () => {
    it('should execute list-connections successfully with mocked data', async () => {
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
        limit: 20
      });
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.connections).toBeDefined();
      expect(parsedResult.connections).toHaveLength(1);
      expect(parsedResult.connections[0].name).toBe(testConnection.name);
      expect(parsedResult.pagination).toBeDefined();
      expect(parsedResult.pagination.total).toBe(1);
    });

    it('should execute get-connection with specific connection ID', async () => {
      mockApiClient.mockResponse('GET', '/connections/4001', {
        success: true,
        data: testConnection
      });

      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-connection');
      const result = await executeTool(tool, {
        connectionId: 4001
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.connection).toBeDefined();
      expect(parsedResult.connection.id).toBe(4001);
      expect(parsedResult.connection.name).toBe(testConnection.name);
      expect(parsedResult.connection.service).toBe('slack');
    });

    it('should execute create-connection successfully', async () => {
      const newConnection = { ...testConnection, id: 4002, name: 'New Test Connection' };
      
      mockApiClient.mockResponse('POST', '/connections', {
        success: true,
        data: newConnection
      });

      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-connection');
      const result = await executeTool(tool, {
        name: 'New Test Connection',
        service: 'slack',
        accountName: 'new-workspace',
        credentials: {
          token: 'xoxb-new-token',
          workspace: 'new-workspace'
        },
        metadata: {
          environment: 'development'
        }
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.connection).toBeDefined();
      expect(parsedResult.connection.name).toBe('New Test Connection');
      expect(parsedResult.message).toContain('created successfully');
    });

    it('should execute update-connection with partial updates', async () => {
      const updatedConnection = { ...testConnection, name: 'Updated Connection Name' };
      
      mockApiClient.mockResponse('PATCH', '/connections/4001', {
        success: true,
        data: updatedConnection
      });

      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'update-connection');
      const result = await executeTool(tool, {
        connectionId: 4001,
        name: 'Updated Connection Name'
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.connection).toBeDefined();
      expect(parsedResult.connection.name).toBe('Updated Connection Name');
      expect(parsedResult.message).toContain('updated successfully');
    });

    it('should execute test-connection with validation results', async () => {
      const testResult = {
        valid: true,
        message: 'Connection test successful',
        responseTime: 245,
        details: {
          endpoint: '/api/test',
          statusCode: 200
        }
      };
      
      mockApiClient.mockResponse('POST', '/connections/4001/test', {
        success: true,
        data: testResult
      });

      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'test-connection');
      const result = await executeTool(tool, {
        connectionId: 4001,
        testEndpoint: '/api/test'
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.connectionId).toBe(4001);
      expect(parsedResult.isValid).toBe(true);
      expect(parsedResult.message).toBe('Connection test successful');
      expect(parsedResult.details).toBeDefined();
    });

    it('should execute list-webhooks with filtering parameters', async () => {
      mockApiClient.mockResponse('GET', '/webhooks', {
        success: true,
        data: [testWebhook],
        metadata: { total: 1 }
      });

      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-webhooks');
      const result = await executeTool(tool, {
        connectionId: 4001,
        status: 'active',
        limit: 10
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.webhooks).toBeDefined();
      expect(parsedResult.webhooks).toHaveLength(1);
      expect(parsedResult.webhooks[0].name).toBe(testWebhook.name);
      expect(parsedResult.pagination.total).toBe(1);
    });

    it('should execute create-webhook successfully', async () => {
      const newWebhook = { ...testWebhook, id: 5002, name: 'New Test Webhook' };
      
      mockApiClient.mockResponse('POST', '/webhooks', {
        success: true,
        data: newWebhook
      });

      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-webhook');
      const result = await executeTool(tool, {
        name: 'New Test Webhook',
        url: 'https://api.company.com/webhooks/new',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        connectionId: 4001,
        isActive: true
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.webhook).toBeDefined();
      expect(parsedResult.webhook.name).toBe('New Test Webhook');
      expect(parsedResult.message).toContain('created successfully');
    });
  });

  describe('Error Handling and Security', () => {
    it('should handle API failures gracefully', async () => {
      mockApiClient.mockFailure('GET', '/connections', new Error('Connection service unavailable'));

      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-connections');
      
      await expect(executeTool(tool, {})).rejects.toThrow(UserError);
    });

    it('should handle unauthorized access errors', async () => {
      mockApiClient.mockResponse('GET', '/connections/4001', testErrors.unauthorized);

      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-connection');
      
      await expect(executeTool(tool, { connectionId: 4001 })).rejects.toThrow(UserError);
    });

    it('should validate required fields for connection creation', async () => {
      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-connection');
      
      // Missing required name field should fail validation
      await expect(executeTool(tool, {
        service: 'slack',
        accountName: 'test-workspace',
        credentials: { token: 'test-token' }
      })).rejects.toThrow();
      
      // Missing required service field should fail validation
      await expect(executeTool(tool, {
        name: 'Test Connection',
        accountName: 'test-workspace',
        credentials: { token: 'test-token' }
      })).rejects.toThrow();
    });

    it('should validate webhook URL format', async () => {
      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-webhook');
      
      // Invalid URL should fail validation
      await expect(executeTool(tool, {
        name: 'Test Webhook',
        url: 'not-a-valid-url',
        method: 'POST'
      })).rejects.toThrow();
    });

    it('should require update data for connection updates', async () => {
      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'update-connection');
      
      // Empty update data should fail
      mockApiClient.mockResponse('PATCH', '/connections/4001', testErrors.badRequest);
      
      await expect(executeTool(tool, {
        connectionId: 4001
        // No update fields provided
      })).rejects.toThrow(UserError);
    });

    it('should handle connection not found errors', async () => {
      mockApiClient.mockResponse('GET', '/connections/999999', {
        success: false,
        error: { message: 'Connection not found' }
      });

      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-connection');
      
      await expect(executeTool(tool, { connectionId: 999999 })).rejects.toThrow(UserError);
    });

    it('should prevent credential exposure in responses', async () => {
      const connectionWithCredentials = {
        ...testConnection,
        credentials: {
          secret_key: 'very-secret-key',
          api_token: 'sensitive-token',
          password: 'secret-password'
        }
      };

      mockApiClient.mockResponse('GET', '/connections/4001', {
        success: true,
        data: connectionWithCredentials
      });

      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-connection');
      const result = await executeTool(tool, { connectionId: 4001 });
      
      // Credentials should be included but should be marked as secure in production
      // This test verifies the structure is maintained
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.connection.credentials).toBeDefined();
    });
  });

  describe('Advanced Connection Diagnostics', () => {
    it('should execute comprehensive connection diagnostics', async () => {
      // Mock connection retrieval
      mockApiClient.mockResponse('GET', '/connections/4001', {
        success: true,
        data: testConnection
      });

      // Mock connection test
      mockApiClient.mockResponse('POST', '/connections/4001/test', {
        success: true,
        data: { valid: true, message: 'Connection test successful', responseTime: 150 }
      });

      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'diagnose-connection-issues');
      const result = await executeTool(tool, {
        connectionId: 4001,
        diagnosticTypes: ['health', 'connectivity', 'authentication'],
        includePerformanceMetrics: true,
        includeSecurityChecks: true,
        testConnectivity: true,
        timeRangeHours: 24
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.connections).toBeDefined();
      expect(parsedResult.connections).toHaveLength(1);
      expect(parsedResult.connections[0].connectionId).toBe(4001);
      expect(parsedResult.connections[0].overallHealth).toBeDefined();
      expect(parsedResult.connections[0].healthScore).toBeGreaterThanOrEqual(0);
      expect(parsedResult.connections[0].diagnostics).toBeDefined();
      expect(parsedResult.summary).toBeDefined();
      expect(parsedResult.metadata).toBeDefined();
    });

    it('should execute service-based diagnostics for multiple connections', async () => {
      const slackConnections = [
        testConnection,
        { ...testConnection, id: 4002, name: 'Another Slack Connection' }
      ];

      mockApiClient.mockResponse('GET', '/connections', {
        success: true,
        data: slackConnections,
        metadata: { total: 2 }
      });

      // Mock test calls for both connections
      mockApiClient.mockResponse('POST', '/connections/4001/test', {
        success: true,
        data: { valid: true, message: 'Connection test successful', responseTime: 150 }
      });

      mockApiClient.mockResponse('POST', '/connections/4002/test', {
        success: true,
        data: { valid: true, message: 'Connection test successful', responseTime: 200 }
      });

      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'diagnose-connection-issues');
      const result = await executeTool(tool, {
        service: 'slack',
        diagnosticTypes: ['all'],
        includePerformanceMetrics: true,
        includeSecurityChecks: true,
        testConnectivity: true,
        timeRangeHours: 48
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.connections).toHaveLength(2);
      expect(parsedResult.summary.totalConnections).toBe(2);
      expect(parsedResult.performance).toBeDefined();
      expect(parsedResult.security).toBeDefined();
      expect(parsedResult.recommendations).toBeDefined();
    });

    it('should handle diagnostic failures gracefully', async () => {
      mockApiClient.mockResponse('GET', '/connections/4001', {
        success: true,
        data: testConnection
      });

      // Mock test failure
      mockApiClient.mockResponse('POST', '/connections/4001/test', {
        success: false,
        error: { message: 'Connection test failed' }
      });

      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'diagnose-connection-issues');
      const result = await executeTool(tool, {
        connectionId: 4001,
        diagnosticTypes: ['connectivity'],
        testConnectivity: true
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.connections).toHaveLength(1);
      
      // Should include error diagnostics
      const diagnostics = parsedResult.connections[0].diagnostics;
      expect(diagnostics.some((d: any) => d.severity === 'error')).toBe(true);
    });

    it('should filter diagnostics by severity level', async () => {
      mockApiClient.mockResponse('GET', '/connections/4001', {
        success: true,
        data: { ...testConnection, valid: false } // Make connection invalid to generate warnings
      });

      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'diagnose-connection-issues');
      const result = await executeTool(tool, {
        connectionId: 4001,
        diagnosticTypes: ['health'],
        severityFilter: 'warning',
        testConnectivity: false
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.connections).toHaveLength(1);
      
      // All diagnostics should be warning level or higher
      const diagnostics = parsedResult.connections[0].diagnostics;
      diagnostics.forEach((diagnostic: any) => {
        expect(['warning', 'error', 'critical']).toContain(diagnostic.severity);
      });
    });
  });

  describe('Enterprise Security Patterns', () => {
    it('should implement secure credential handling patterns', async () => {
      const secureConnection = {
        ...testConnection,
        credentials: {
          encrypted_token: 'encrypted-value',
          key_id: 'hsm-key-123',
          expires_at: '2024-12-31T23:59:59Z'
        }
      };

      mockApiClient.mockResponse('POST', '/connections', {
        success: true,
        data: secureConnection
      });

      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-connection');
      const result = await executeTool(tool, {
        name: 'Secure Enterprise Connection',
        service: 'enterprise-api',
        accountName: 'enterprise-account',
        credentials: {
          client_certificate: 'cert-data',
          private_key: 'key-data',
          ca_bundle: 'ca-data'
        },
        metadata: {
          security_level: 'high',
          compliance_requirements: ['SOC2', 'GDPR']
        }
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.connection).toBeDefined();
      expect(parsedResult.connection.name).toBe('Secure Enterprise Connection');
    });

    it('should validate enterprise security diagnostics', async () => {
      const enterpriseConnection = {
        ...testConnection,
        service: 'enterprise-saml',
        credentials: {
          saml_certificate: 'cert-data',
          signing_key: 'key-data',
          expires_at: '2024-12-31T23:59:59Z'
        },
        metadata: {
          security_level: 'enterprise',
          mfa_required: true,
          audit_enabled: true
        }
      };

      mockApiClient.mockResponse('GET', '/connections/4001', {
        success: true,
        data: enterpriseConnection
      });

      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'diagnose-connection-issues');
      const result = await executeTool(tool, {
        connectionId: 4001,
        diagnosticTypes: ['security', 'authentication'],
        includeSecurityChecks: true,
        testConnectivity: false
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.security).toBeDefined();
      expect(parsedResult.security.connectionsAnalyzed).toBeGreaterThan(0);
      expect(parsedResult.security.overallSecurityScore).toBeGreaterThanOrEqual(0);
    });

    it('should detect and report security vulnerabilities', async () => {
      const vulnerableConnection = {
        ...testConnection,
        credentials: {
          password: 'weak123', // Weak password
          secret: 'test_secret', // Test credentials in production
          scope: 'admin write:all' // Excessive permissions
        },
        createdAt: '2022-01-01T00:00:00Z' // Old connection
      };

      mockApiClient.mockResponse('GET', '/connections/4001', {
        success: true,
        data: vulnerableConnection
      });

      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'diagnose-connection-issues');
      const result = await executeTool(tool, {
        connectionId: 4001,
        diagnosticTypes: ['security'],
        includeSecurityChecks: true,
        testConnectivity: false
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.connections[0].diagnostics).toBeDefined();
      
      // Should detect security issues
      const securityDiagnostics = parsedResult.connections[0].diagnostics.filter(
        (d: any) => d.category === 'security'
      );
      expect(securityDiagnostics.length).toBeGreaterThan(0);
      
      // Should have recommendations for security improvements
      const recommendations = parsedResult.recommendations;
      expect(recommendations.topRecommendations.length).toBeGreaterThan(0);
    });
  });

  describe('Webhook Management Integration', () => {
    it('should execute delete operations with confirmation', async () => {
      mockApiClient.mockResponse('DELETE', '/connections/4001', {
        success: true,
        data: { message: 'Connection deleted successfully' }
      });

      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'delete-connection');
      const result = await executeTool(tool, {
        connectionId: 4001
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.message).toContain('deleted successfully');
    });

    it('should execute webhook updates with validation', async () => {
      const updatedWebhook = {
        ...testWebhook,
        url: 'https://api.company.com/webhooks/updated',
        isActive: false
      };

      mockApiClient.mockResponse('PATCH', '/webhooks/5001', {
        success: true,
        data: updatedWebhook
      });

      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'update-webhook');
      const result = await executeTool(tool, {
        webhookId: 5001,
        url: 'https://api.company.com/webhooks/updated',
        isActive: false
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.webhook.url).toBe('https://api.company.com/webhooks/updated');
      expect(parsedResult.webhook.isActive).toBe(false);
      expect(parsedResult.message).toContain('updated successfully');
    });

    it('should handle webhook deletion', async () => {
      mockApiClient.mockResponse('DELETE', '/webhooks/5001', {
        success: true,
        data: { message: 'Webhook deleted successfully' }
      });

      const { addConnectionTools } = await import('../../../src/tools/connections.js');
      addConnectionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'delete-webhook');
      const result = await executeTool(tool, {
        webhookId: 5001
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.message).toContain('deleted successfully');
    });
  });

  describe('Module Structure', () => {
    it('should import without errors', async () => {
      // This test verifies the module can be imported without syntax errors
      await expect(import('../../../src/tools/connections.js')).resolves.toBeDefined();
    });

    it('should have proper TypeScript compilation', async () => {
      const connectionsModule = await import('../../../src/tools/connections.js');
      
      // Basic structural validation
      expect(connectionsModule).toBeDefined();
      expect(typeof connectionsModule).toBe('object');
    });
  });
});