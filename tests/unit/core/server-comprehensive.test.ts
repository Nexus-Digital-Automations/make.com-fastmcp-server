/**
 * Comprehensive Test Suite for Core FastMCP Server
 * Tests main server initialization, authentication, tool registration, and lifecycle management
 * Critical for ensuring core server infrastructure reliability and security
 * Covers server instance creation, configuration validation, tool loading, and error handling
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { MakeServerInstance } from '../../../src/server.js';
import { FastMCP } from 'fastmcp';

// Mock all external dependencies
// Note: config.js is already globally mocked via jest.config.js moduleNameMapper

// Note: logger.js is already globally mocked via jest.config.js moduleNameMapper

// Note: make-api-client.js is already globally mocked via jest.config.js moduleNameMapper

jest.mock('../../../src/utils/errors.js', () => ({
  setupGlobalErrorHandlers: jest.fn(),
  MakeServerError: class MakeServerError extends Error {
    constructor(message: string, code?: string, status?: number, isRetryable?: boolean, context?: any, metadata?: any) {
      super(message);
      this.name = 'MakeServerError';
      this.code = code || 'UNKNOWN_ERROR';
      this.correlationId = metadata?.correlationId || 'test_correlation_id';
    }
    code: string;
    correlationId: string;
  },
  createAuthenticationError: jest.fn((message, context, metadata) => ({
    message,
    correlationId: metadata?.correlationId || 'test_correlation_id'
  }))
}));

jest.mock('../../../src/utils/error-response.js', () => ({
  extractCorrelationId: jest.fn(() => 'test_correlation_id')
}));

// Mock all tool modules
const mockToolModules = [
  'scenarios', 'connections', 'permissions', 'analytics', 'variables',
  'ai-agents', 'templates', 'folders', 'certificates', 'procedures',
  'custom-apps', 'sdk', 'billing', 'notifications', 'performance-analysis',
  'log-streaming', 'real-time-monitoring', 'naming-convention-policy',
  'scenario-archival-policy', 'audit-compliance', 'compliance-policy',
  'policy-compliance-validation', 'marketplace', 'budget-control',
  'cicd-integration', 'ai-governance-engine', 'zero-trust-auth',
  'multi-tenant-security', 'enterprise-secrets', 'blueprint-collaboration'
];

mockToolModules.forEach(module => {
  jest.mock(`../../../src/tools/${module}.js`, () => ({
    [`add${module.split('-').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join('')}Tools`]: jest.fn()
  }));
});

jest.mock('fastmcp', () => ({
  FastMCP: jest.fn().mockImplementation(() => ({
    addTool: jest.fn(),
    start: jest.fn().mockResolvedValue(undefined),
    on: jest.fn(),
    shutdown: jest.fn().mockResolvedValue(undefined)
  })),
  UserError: class UserError extends Error {
    constructor(message: string) {
      super(message);
      this.name = 'UserError';
    }
  }
}));

describe('Core FastMCP Server - Comprehensive Tests', () => {
  let serverInstance: MakeServerInstance;
  let mockFastMCP: any;

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Reset the FastMCP mock
    mockFastMCP = {
      addTool: jest.fn(),
      start: jest.fn().mockResolvedValue(undefined),
      on: jest.fn(),
      shutdown: jest.fn().mockResolvedValue(undefined)
    };
    
    (FastMCP as jest.MockedClass<any>).mockImplementation(() => mockFastMCP);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Server Instance Creation and Initialization', () => {
    it('should create server instance successfully', () => {
      expect(() => {
        serverInstance = new MakeServerInstance();
      }).not.toThrow();
      
      expect(FastMCP).toHaveBeenCalledWith(expect.objectContaining({
        name: 'Test Make.com FastMCP Server',
        version: '1.0.0',
        instructions: expect.stringContaining('Make.com FastMCP Server')
      }));
    });

    it('should initialize with proper server configuration', () => {
      serverInstance = new MakeServerInstance();
      
      const fastMCPCall = (FastMCP as jest.MockedClass<any>).mock.calls[0][0];
      expect(fastMCPCall.name).toBe('Test Make.com FastMCP Server');
      expect(fastMCPCall.version).toBe('1.0.0');
      expect(fastMCPCall.instructions).toContain('comprehensive Make.com API access');
      expect(fastMCPCall.authenticate).toBeUndefined(); // Auth disabled in test
    });

    it('should setup server event handlers during initialization', () => {
      serverInstance = new MakeServerInstance();
      
      expect(mockFastMCP.on).toHaveBeenCalledWith('connect', expect.any(Function));
      expect(mockFastMCP.on).toHaveBeenCalledWith('disconnect', expect.any(Function));
    });

    it('should throw error if FastMCP server fails to initialize properly', () => {
      (FastMCP as jest.MockedClass<any>).mockImplementation(() => ({})); // Missing addTool method
      
      expect(() => {
        new MakeServerInstance();
      }).toThrow('FastMCP server instance not properly initialized');
    });

    it('should expose server instance via getServer method', () => {
      serverInstance = new MakeServerInstance();
      const server = serverInstance.getServer();
      
      expect(server).toBe(mockFastMCP);
    });
  });

  describe('Server Instructions and Configuration', () => {
    it('should generate comprehensive server instructions', () => {
      serverInstance = new MakeServerInstance();
      
      const fastMCPCall = (FastMCP as jest.MockedClass<any>).mock.calls[0][0];
      const instructions = fastMCPCall.instructions;
      
      expect(instructions).toContain('Make.com FastMCP Server');
      expect(instructions).toContain('Platform Management');
      expect(instructions).toContain('Security & Certificates');
      expect(instructions).toContain('Enterprise Budget Control');
      expect(instructions).toContain('AI-Driven Governance');
      expect(instructions).toContain('Rate Limiting');
      expect(instructions).toContain('Authentication');
    });

    it('should include authentication status in instructions', () => {
      serverInstance = new MakeServerInstance();
      
      const fastMCPCall = (FastMCP as jest.MockedClass<any>).mock.calls[0][0];
      const instructions = fastMCPCall.instructions;
      
      expect(instructions).toContain('Server runs in open mode (no authentication required)');
    });

    it('should include rate limiting configuration in instructions', () => {
      serverInstance = new MakeServerInstance();
      
      const fastMCPCall = (FastMCP as jest.MockedClass<any>).mock.calls[0][0];
      const instructions = fastMCPCall.instructions;
      
      expect(instructions).toContain('100 requests per 60 seconds');
    });
  });

  describe('Basic Tools Registration', () => {
    beforeEach(() => {
      serverInstance = new MakeServerInstance();
    });

    it('should register health-check tool with correct configuration', () => {
      const addToolCalls = mockFastMCP.addTool.mock.calls;
      const healthCheckTool = addToolCalls.find(call => call[0].name === 'health-check');
      
      expect(healthCheckTool).toBeDefined();
      expect(healthCheckTool[0]).toMatchObject({
        name: 'health-check',
        description: 'Check server and Make.com API connectivity status',
        annotations: {
          title: 'Health Check',
          readOnlyHint: true,
          openWorldHint: true
        }
      });
      expect(typeof healthCheckTool[0].execute).toBe('function');
    });

    it('should register server-info tool with correct configuration', () => {
      const addToolCalls = mockFastMCP.addTool.mock.calls;
      const serverInfoTool = addToolCalls.find(call => call[0].name === 'server-info');
      
      expect(serverInfoTool).toBeDefined();
      expect(serverInfoTool[0]).toMatchObject({
        name: 'server-info',
        description: 'Get detailed server configuration and capabilities',
        annotations: {
          title: 'Server Information',
          readOnlyHint: true
        }
      });
      expect(typeof serverInfoTool[0].execute).toBe('function');
    });

    it('should register test-configuration tool with correct configuration', () => {
      const addToolCalls = mockFastMCP.addTool.mock.calls;
      const configTestTool = addToolCalls.find(call => call[0].name === 'test-configuration');
      
      expect(configTestTool).toBeDefined();
      expect(configTestTool[0]).toMatchObject({
        name: 'test-configuration',
        description: 'Test Make.com API configuration and permissions',
        annotations: {
          title: 'Configuration Test',
          readOnlyHint: true,
          openWorldHint: true
        }
      });
      expect(typeof configTestTool[0].execute).toBe('function');
    });
  });

  describe('Advanced Tools Loading', () => {
    it('should attempt to load all advanced tool modules', () => {
      serverInstance = new MakeServerInstance();
      
      // Verify that tool loading functions were called
      // Note: We can't easily verify all modules were loaded due to mocking,
      // but we can verify the server was created successfully which indicates
      // the tool loading process completed without fatal errors
      expect(mockFastMCP.addTool).toHaveBeenCalled();
      expect(mockFastMCP.addTool.mock.calls.length).toBeGreaterThan(0);
    });
  });

  describe('Tool Execution - Health Check', () => {
    beforeEach(() => {
      serverInstance = new MakeServerInstance();
    });

    it('should execute health-check tool successfully', async () => {
      const addToolCalls = mockFastMCP.addTool.mock.calls;
      const healthCheckTool = addToolCalls.find(call => call[0].name === 'health-check');
      
      const mockContext = {
        log: { info: jest.fn(), error: jest.fn() },
        session: null
      };
      
      const result = await healthCheckTool[0].execute({}, mockContext);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult).toMatchObject({
        server: 'healthy',
        makeApi: {
          healthy: true,
          responseTime: expect.stringContaining('ms')
        },
        overall: 'healthy'
      });
    });

    it('should handle API health check failures gracefully', async () => {
      // Mock API client to return unhealthy status
      const mockApiClient = require('../../../src/lib/make-api-client.js').default;
      const mockInstance = new mockApiClient();
      mockInstance.healthCheck.mockResolvedValue(false);
      
      const addToolCalls = mockFastMCP.addTool.mock.calls;
      const healthCheckTool = addToolCalls.find(call => call[0].name === 'health-check');
      
      const mockContext = {
        log: { info: jest.fn(), error: jest.fn() },
        session: null
      };
      
      const result = await healthCheckTool[0].execute({}, mockContext);
      const parsedResult = JSON.parse(result);
      
      expect(parsedResult.overall).toBe('degraded');
      expect(parsedResult.makeApi.healthy).toBe(false);
    });
  });

  describe('Tool Execution - Server Info', () => {
    beforeEach(() => {
      serverInstance = new MakeServerInstance();
    });

    it('should execute server-info tool successfully', async () => {
      const addToolCalls = mockFastMCP.addTool.mock.calls;
      const serverInfoTool = addToolCalls.find(call => call[0].name === 'server-info');
      
      const mockContext = {
        log: { info: jest.fn(), error: jest.fn() },
        session: null
      };
      
      const result = await serverInfoTool[0].execute({}, mockContext);
      
      expect(result).toBeDefined();
      expect(result.content).toBeDefined();
      expect(result.content[0].type).toBe('text');
      
      const parsedInfo = JSON.parse(result.content[0].text);
      expect(parsedInfo).toMatchObject({
        name: 'Test Make.com FastMCP Server',
        version: '1.0.0',
        configuration: {
          logLevel: 'info',
          authentication: { enabled: false },
          makeApi: {
            baseUrl: 'https://api.make.com',
            timeout: 30000,
            retries: 3,
            teamId: 'test_team',
            organizationId: 'test_org'
          }
        },
        capabilities: expect.arrayContaining([
          'scenario-management',
          'connection-management',
          'analytics-reporting',
          'enterprise-budget-control',
          'ai-driven-governance'
        ])
      });
    });
  });

  describe('Tool Execution - Configuration Test', () => {
    beforeEach(() => {
      serverInstance = new MakeServerInstance();
    });

    it('should execute test-configuration tool successfully', async () => {
      const addToolCalls = mockFastMCP.addTool.mock.calls;
      const configTestTool = addToolCalls.find(call => call[0].name === 'test-configuration');
      
      const mockContext = {
        log: { info: jest.fn(), error: jest.fn() },
        reportProgress: jest.fn(),
        session: null
      };
      
      const result = await configTestTool[0].execute({ includePermissions: false }, mockContext);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult).toMatchObject({
        apiConnectivity: true,
        userInfo: { id: 'test_user', name: 'Test User' },
        scenarioAccess: true,
        configuration: {
          baseUrl: 'https://api.make.com',
          hasTeamId: true,
          hasOrgId: true
        }
      });
      
      expect(mockContext.reportProgress).toHaveBeenCalledWith({ progress: 100, total: 100 });
    });

    it('should include permissions analysis when requested', async () => {
      const addToolCalls = mockFastMCP.addTool.mock.calls;
      const configTestTool = addToolCalls.find(call => call[0].name === 'test-configuration');
      
      const mockContext = {
        log: { info: jest.fn(), error: jest.fn() },
        reportProgress: jest.fn(),
        session: null
      };
      
      const result = await configTestTool[0].execute({ includePermissions: true }, mockContext);
      const parsedResult = JSON.parse(result);
      
      expect(parsedResult.permissions).toBeDefined();
      expect(parsedResult.permissions.analyzed).toBe(true);
    });

    it('should handle configuration test failures', async () => {
      // Mock API client to throw error
      const mockApiClient = require('../../../src/lib/make-api-client.js').default;
      const mockInstance = new mockApiClient();
      mockInstance.get.mockRejectedValue(new Error('API connection failed'));
      
      const addToolCalls = mockFastMCP.addTool.mock.calls;
      const configTestTool = addToolCalls.find(call => call[0].name === 'test-configuration');
      
      const mockContext = {
        log: { info: jest.fn(), error: jest.fn() },
        reportProgress: jest.fn(),
        session: null
      };
      
      await expect(configTestTool[0].execute({ includePermissions: false }, mockContext))
        .rejects.toThrow('Configuration test failed');
    });
  });

  describe('Server Lifecycle Management', () => {
    beforeEach(() => {
      serverInstance = new MakeServerInstance();
    });

    it('should start server successfully with default options', async () => {
      await expect(serverInstance.start()).resolves.not.toThrow();
      
      expect(mockFastMCP.start).toHaveBeenCalledWith({
        transportType: 'stdio'
      });
    });

    it('should start server with custom options', async () => {
      const customOptions = {
        transportType: 'httpStream',
        httpStream: { port: 3001, endpoint: '/api' }
      };
      
      await expect(serverInstance.start(customOptions)).resolves.not.toThrow();
      
      expect(mockFastMCP.start).toHaveBeenCalledWith(customOptions);
    });

    it('should skip API health check in development mode', async () => {
      const mockConfig = require('../../../src/lib/config.js').default;
      mockConfig.getMakeConfig.mockReturnValue({
        ...mockConfig.getMakeConfig(),
        apiKey: 'test_key_for_development'
      });
      
      await expect(serverInstance.start()).resolves.not.toThrow();
    });

    it('should shutdown server gracefully', async () => {
      await expect(serverInstance.shutdown()).resolves.not.toThrow();
      
      const mockApiClient = require('../../../src/lib/make-api-client.js').default;
      const mockInstance = new mockApiClient();
      expect(mockInstance.shutdown).toHaveBeenCalled();
    });

    it('should handle API client shutdown errors gracefully', async () => {
      const mockApiClient = require('../../../src/lib/make-api-client.js').default;
      const mockInstance = new mockApiClient();
      mockInstance.shutdown.mockRejectedValue(new Error('Shutdown failed'));
      
      await expect(serverInstance.shutdown()).resolves.not.toThrow();
    });
  });

  describe('Authentication System', () => {
    it('should create server with authentication when enabled', () => {
      const mockConfig = require('../../../src/lib/config.js').default;
      mockConfig.isAuthEnabled.mockReturnValue(true);
      
      serverInstance = new MakeServerInstance();
      
      const fastMCPCall = (FastMCP as jest.MockedClass<any>).mock.calls[0][0];
      expect(fastMCPCall.authenticate).toBeDefined();
      expect(typeof fastMCPCall.authenticate).toBe('function');
    });

    it('should create server without authentication when disabled', () => {
      const mockConfig = require('../../../src/lib/config.js').default;
      mockConfig.isAuthEnabled.mockReturnValue(false);
      
      serverInstance = new MakeServerInstance();
      
      const fastMCPCall = (FastMCP as jest.MockedClass<any>).mock.calls[0][0];
      expect(fastMCPCall.authenticate).toBeUndefined();
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle missing API key configuration', async () => {
      const mockConfig = require('../../../src/lib/config.js').default;
      mockConfig.getMakeConfig.mockReturnValue({
        ...mockConfig.getMakeConfig(),
        apiKey: ''
      });
      
      serverInstance = new MakeServerInstance();
      
      await expect(serverInstance.start()).rejects.toThrow('Make.com API is not accessible');
    });

    it('should handle API health check failure during startup', async () => {
      const mockApiClient = require('../../../src/lib/make-api-client.js').default;
      const mockInstance = new mockApiClient();
      mockInstance.healthCheck.mockResolvedValue(false);
      
      const mockConfig = require('../../../src/lib/config.js').default;
      mockConfig.getMakeConfig.mockReturnValue({
        ...mockConfig.getMakeConfig(),
        apiKey: 'real_api_key'
      });
      
      serverInstance = new MakeServerInstance();
      
      await expect(serverInstance.start()).rejects.toThrow('Make.com API is not accessible');
    });

    it('should handle server start failures gracefully', async () => {
      mockFastMCP.start.mockRejectedValue(new Error('Server start failed'));
      
      serverInstance = new MakeServerInstance();
      
      await expect(serverInstance.start()).rejects.toThrow('Server start failed');
    });
  });

  describe('Event Handler Registration', () => {
    beforeEach(() => {
      serverInstance = new MakeServerInstance();
    });

    it('should register connect event handler', () => {
      expect(mockFastMCP.on).toHaveBeenCalledWith('connect', expect.any(Function));
    });

    it('should register disconnect event handler', () => {
      expect(mockFastMCP.on).toHaveBeenCalledWith('disconnect', expect.any(Function));
    });

    it('should handle connect events properly', () => {
      const connectHandler = mockFastMCP.on.mock.calls.find(call => call[0] === 'connect')[1];
      
      expect(() => {
        connectHandler({
          session: {
            clientCapabilities: { tools: true, resources: true }
          }
        });
      }).not.toThrow();
    });

    it('should handle disconnect events properly', () => {
      const disconnectHandler = mockFastMCP.on.mock.calls.find(call => call[0] === 'disconnect')[1];
      
      expect(() => {
        disconnectHandler({
          session: { id: 'test_session' }
        });
      }).not.toThrow();
    });
  });

  describe('Server Integration and Dependencies', () => {
    it('should properly initialize all dependencies', () => {
      serverInstance = new MakeServerInstance();
      
      // Verify that critical dependencies were initialized
      const mockConfig = require('../../../src/lib/config.js').default;
      expect(mockConfig.getMakeConfig).toHaveBeenCalled();
      
      const mockApiClient = require('../../../src/lib/make-api-client.js').default;
      expect(mockApiClient).toHaveBeenCalledWith(expect.any(Object));
      
      const mockErrorUtils = require('../../../src/utils/errors.js');
      expect(mockErrorUtils.setupGlobalErrorHandlers).toHaveBeenCalled();
    });

    it('should handle dependency initialization failures gracefully', () => {
      const mockApiClient = require('../../../src/lib/make-api-client.js').default;
      mockApiClient.mockImplementation(() => {
        throw new Error('API client initialization failed');
      });
      
      expect(() => {
        new MakeServerInstance();
      }).toThrow('API client initialization failed');
    });
  });
});