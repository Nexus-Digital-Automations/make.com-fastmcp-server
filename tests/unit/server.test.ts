/**
 * Comprehensive test suite for src/server.ts - Main FastMCP Server Implementation
 *
 * Tests critical server functionality including:
 * - Server initialization and configuration
 * - FastMCP protocol handling and compliance
 * - Tool registration and execution
 * - Authentication and session management
 * - Error handling and recovery
 * - Health check and monitoring
 * - Graceful shutdown and lifecycle management
 *
 * Target: 85%+ coverage of main server implementation
 * Critical for production - server failures affect entire system availability
 */

import {
  jest,
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
} from "@jest/globals";
import { MakeServerInstance } from "../../src/server.js";
import { UserError } from "fastmcp";

// Mock external dependencies with comprehensive functionality
jest.mock("../../src/lib/config.js", () => {
  const mockConfig = {
    name: "Test Make.com FastMCP Server",
    version: "1.0.0",
    logLevel: "error",
    authentication: {
      enabled: false,
      secret: "test-secret-12345678901234567890123456",
    },
    rateLimit: {
      maxRequests: 100,
      windowMs: 60000,
    },
    make: {
      apiKey: "test_api_key_12345",
      baseUrl: "https://api.make.com/api/v2",
      teamId: "test_team",
      organizationId: "test_org",
      timeout: 30000,
      retries: 3,
    },
  };

  return {
    __esModule: true,
    default: {
      getConfig: jest.fn(() => mockConfig),
      getMakeConfig: jest.fn(() => mockConfig.make),
      getLogLevel: jest.fn(() => "error"),
      isAuthEnabled: jest.fn(() => false),
      getAuthSecret: jest.fn(() => mockConfig.authentication.secret),
      getRateLimitConfig: jest.fn(() => mockConfig.rateLimit),
    },
  };
});

jest.mock("../../src/lib/logger.js", () => {
  const mockLogger = {
    child: jest.fn(() => ({
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
      debug: jest.fn(),
    })),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  };
  return { __esModule: true, default: mockLogger };
});

jest.mock("../../src/lib/make-api-client.js", () => {
  class MockMakeApiClient {
    constructor(config: any) {}

    async get(url: string, options?: any) {
      if (url === "/users/me") {
        return {
          success: true,
          data: {
            id: "test_user_123",
            name: "Test User",
            email: "test@example.com",
            role: "admin",
          },
        };
      }
      if (url.includes("/teams/")) {
        return { success: true, data: { id: "test_team", name: "Test Team" } };
      }
      if (url === "/scenarios") {
        return { success: true, data: [] };
      }
      return { success: true, data: {} };
    }

    async healthCheck() {
      return true;
    }

    getRateLimiterStatus() {
      return { running: 0, queued: 0 };
    }

    async shutdown() {}
  }

  return { __esModule: true, default: MockMakeApiClient };
});

jest.mock("../../src/utils/errors.js", () => ({
  setupGlobalErrorHandlers: jest.fn(),
  MakeServerError: class MakeServerError extends Error {
    constructor(
      message: string,
      code?: string,
      status?: number,
      isRetryable?: boolean,
      context?: any,
      metadata?: any,
    ) {
      super(message);
      this.name = "MakeServerError";
      this.code = code || "UNKNOWN_ERROR";
      this.correlationId = metadata?.correlationId || "test_correlation_id";
    }
    code: string;
    correlationId: string;
  },
  createAuthenticationError: jest.fn((message, context, metadata) => ({
    message,
    correlationId: metadata?.correlationId || "test_correlation_id",
  })),
}));

jest.mock("../../src/utils/error-response.js", () => ({
  extractCorrelationId: jest.fn(() => "test_correlation_id"),
}));

// Mock all tool modules
const mockToolModules = [
  "scenarios",
  "connections",
  "permissions",
  "analytics",
  "variables",
  "ai-agents",
  "templates",
  "folders",
  "certificates",
  "procedures",
  "custom-apps",
  "sdk",
  "billing",
  "notifications",
  "performance-analysis",
  "log-streaming",
  "real-time-monitoring",
  "naming-convention-policy",
  "scenario-archival-policy",
  "audit-compliance",
  "compliance-policy",
  "policy-compliance-validation",
  "marketplace",
  "budget-control",
  "cicd-integration",
  "ai-governance-engine",
  "zero-trust-auth",
  "multi-tenant-security",
  "enterprise-secrets",
  "blueprint-collaboration",
];

mockToolModules.forEach((module) => {
  const functionName = `add${module
    .split("-")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join("")}Tools`;

  jest.mock(`../../src/tools/${module}.js`, () => ({
    [functionName]: jest.fn(),
  }));
});

jest.mock("fastmcp", () => ({
  FastMCP: jest.fn().mockImplementation(() => ({
    addTool: jest.fn(),
    start: jest.fn().mockResolvedValue(undefined),
    on: jest.fn(),
    shutdown: jest.fn().mockResolvedValue(undefined),
  })),
  UserError: class UserError extends Error {
    constructor(message: string) {
      super(message);
      this.name = "UserError";
    }
  },
}));

describe("FastMCP Server Implementation - Comprehensive Test Suite", () => {
  let serverInstance: MakeServerInstance;
  let mockFastMCP: any;
  const { FastMCP } = require("fastmcp");

  beforeEach(() => {
    jest.clearAllMocks();

    // Reset FastMCP mock
    mockFastMCP = {
      addTool: jest.fn(),
      start: jest.fn().mockResolvedValue(undefined),
      on: jest.fn(),
      shutdown: jest.fn().mockResolvedValue(undefined),
    };

    (FastMCP as jest.MockedClass<any>).mockImplementation(() => mockFastMCP);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("Server Instance Creation and Initialization", () => {
    it("should create server instance successfully with proper configuration", () => {
      expect(() => {
        serverInstance = new MakeServerInstance();
      }).not.toThrow();

      expect(FastMCP).toHaveBeenCalledWith(
        expect.objectContaining({
          name: "Test Make.com FastMCP Server",
          version: "1.0.0",
          instructions: expect.stringContaining("Make.com FastMCP Server"),
        }),
      );
    });

    it("should initialize with comprehensive server instructions", () => {
      serverInstance = new MakeServerInstance();

      const fastMCPCall = (FastMCP as jest.MockedClass<any>).mock.calls[0][0];
      const instructions = fastMCPCall.instructions;

      // Verify key capabilities are documented
      expect(instructions).toContain("Platform Management");
      expect(instructions).toContain("Security & Certificates");
      expect(instructions).toContain("Enterprise Budget Control");
      expect(instructions).toContain("AI-Driven Governance");
      expect(instructions).toContain("Zero Trust Authentication");
      expect(instructions).toContain("Multi-Tenant Security");
      expect(instructions).toContain("Blueprint Versioning");
    });

    it("should setup global error handlers during initialization", () => {
      const mockSetupGlobalErrorHandlers =
        require("../../src/utils/errors.js").setupGlobalErrorHandlers;

      serverInstance = new MakeServerInstance();

      expect(mockSetupGlobalErrorHandlers).toHaveBeenCalled();
    });

    it("should initialize Make.com API client with proper configuration", () => {
      const MockMakeApiClient =
        require("../../src/lib/make-api-client.js").default;

      serverInstance = new MakeServerInstance();

      expect(MockMakeApiClient).toHaveBeenCalledWith(
        expect.objectContaining({
          apiKey: "test_api_key_12345",
          baseUrl: "https://api.make.com/api/v2",
          teamId: "test_team",
          organizationId: "test_org",
        }),
      );
    });

    it("should throw error if FastMCP server fails to initialize properly", () => {
      (FastMCP as jest.MockedClass<any>).mockImplementation(() => ({})); // Missing addTool method

      expect(() => {
        new MakeServerInstance();
      }).toThrow("FastMCP server instance not properly initialized");
    });

    it("should setup process-level error handlers for uncaught exceptions", () => {
      const originalProcessOn = process.on;
      const processOnSpy = jest.spyOn(process, "on");

      serverInstance = new MakeServerInstance();

      expect(processOnSpy).toHaveBeenCalledWith(
        "uncaughtException",
        expect.any(Function),
      );
      expect(processOnSpy).toHaveBeenCalledWith(
        "unhandledRejection",
        expect.any(Function),
      );

      processOnSpy.mockRestore();
    });
  });

  describe("Authentication and Session Management", () => {
    it("should create server without authentication when disabled", () => {
      const mockConfig = require("../../src/lib/config.js").default;
      mockConfig.isAuthEnabled.mockReturnValue(false);

      serverInstance = new MakeServerInstance();

      const fastMCPCall = (FastMCP as jest.MockedClass<any>).mock.calls[0][0];
      expect(fastMCPCall.authenticate).toBeUndefined();
    });

    it("should create server with authentication when enabled", () => {
      const mockConfig = require("../../src/lib/config.js").default;
      mockConfig.isAuthEnabled.mockReturnValue(true);

      serverInstance = new MakeServerInstance();

      const fastMCPCall = (FastMCP as jest.MockedClass<any>).mock.calls[0][0];
      expect(fastMCPCall.authenticate).toBeDefined();
      expect(typeof fastMCPCall.authenticate).toBe("function");
    });

    it("should handle authentication with valid API key", async () => {
      const mockConfig = require("../../src/lib/config.js").default;
      mockConfig.isAuthEnabled.mockReturnValue(true);
      mockConfig.getAuthSecret.mockReturnValue("valid-secret");

      serverInstance = new MakeServerInstance();
      const fastMCPCall = (FastMCP as jest.MockedClass<any>).mock.calls[0][0];

      const mockRequest = {
        headers: { "x-api-key": "valid-secret" },
      };

      const result = await fastMCPCall.authenticate(mockRequest);

      expect(result).toEqual({
        authenticated: true,
        timestamp: expect.any(String),
        correlationId: "test_correlation_id",
      });
    });

    it("should reject authentication with invalid API key", async () => {
      const mockConfig = require("../../src/lib/config.js").default;
      mockConfig.isAuthEnabled.mockReturnValue(true);
      mockConfig.getAuthSecret.mockReturnValue("valid-secret");

      serverInstance = new MakeServerInstance();
      const fastMCPCall = (FastMCP as jest.MockedClass<any>).mock.calls[0][0];

      const mockRequest = {
        headers: { "x-api-key": "invalid-secret" },
      };

      await expect(
        fastMCPCall.authenticate(mockRequest),
      ).rejects.toBeInstanceOf(Response);
    });

    it("should reject authentication with missing API key", async () => {
      const mockConfig = require("../../src/lib/config.js").default;
      mockConfig.isAuthEnabled.mockReturnValue(true);
      mockConfig.getAuthSecret.mockReturnValue("valid-secret");

      serverInstance = new MakeServerInstance();
      const fastMCPCall = (FastMCP as jest.MockedClass<any>).mock.calls[0][0];

      const mockRequest = { headers: {} };

      await expect(
        fastMCPCall.authenticate(mockRequest),
      ).rejects.toBeInstanceOf(Response);
    });
  });

  describe("FastMCP Protocol and Tool Registration", () => {
    beforeEach(() => {
      serverInstance = new MakeServerInstance();
    });

    it("should register health-check tool with proper configuration", () => {
      const addToolCalls = mockFastMCP.addTool.mock.calls;
      const healthCheckTool = addToolCalls.find(
        (call) => call[0].name === "health-check",
      );

      expect(healthCheckTool).toBeDefined();
      expect(healthCheckTool[0]).toMatchObject({
        name: "health-check",
        description: "Check server and Make.com API connectivity status",
        annotations: {
          title: "Health Check",
          readOnlyHint: true,
          openWorldHint: true,
        },
      });
      expect(typeof healthCheckTool[0].execute).toBe("function");
    });

    it("should register security-status tool with proper configuration", () => {
      const addToolCalls = mockFastMCP.addTool.mock.calls;
      const securityTool = addToolCalls.find(
        (call) => call[0].name === "security-status",
      );

      expect(securityTool).toBeDefined();
      expect(securityTool[0]).toMatchObject({
        name: "security-status",
        description: "Get detailed security system status and metrics",
        annotations: {
          title: "Security Status",
          readOnlyHint: true,
        },
      });
    });

    it("should register server-info tool with proper configuration", () => {
      const addToolCalls = mockFastMCP.addTool.mock.calls;
      const serverInfoTool = addToolCalls.find(
        (call) => call[0].name === "server-info",
      );

      expect(serverInfoTool).toBeDefined();
      expect(serverInfoTool[0]).toMatchObject({
        name: "server-info",
        description: "Get detailed server configuration and capabilities",
        annotations: {
          title: "Server Information",
          readOnlyHint: true,
        },
      });
    });

    it("should register test-configuration tool with proper configuration", () => {
      const addToolCalls = mockFastMCP.addTool.mock.calls;
      const configTestTool = addToolCalls.find(
        (call) => call[0].name === "test-configuration",
      );

      expect(configTestTool).toBeDefined();
      expect(configTestTool[0]).toMatchObject({
        name: "test-configuration",
        description: "Test Make.com API configuration and permissions",
        annotations: {
          title: "Configuration Test",
          readOnlyHint: true,
          openWorldHint: true,
        },
      });
    });

    it("should register all basic tools during initialization", () => {
      const addToolCalls = mockFastMCP.addTool.mock.calls;
      const toolNames = addToolCalls.map((call) => call[0].name);

      expect(toolNames).toContain("health-check");
      expect(toolNames).toContain("security-status");
      expect(toolNames).toContain("server-info");
      expect(toolNames).toContain("test-configuration");
    });
  });

  describe("Tool Execution and FastMCP Protocol Compliance", () => {
    beforeEach(() => {
      serverInstance = new MakeServerInstance();
    });

    it("should execute health-check tool successfully", async () => {
      const addToolCalls = mockFastMCP.addTool.mock.calls;
      const healthCheckTool = addToolCalls.find(
        (call) => call[0].name === "health-check",
      );

      const mockContext = {
        log: { info: jest.fn(), error: jest.fn() },
        session: null,
      };

      const result = await healthCheckTool[0].execute(
        { includeSecurity: true },
        mockContext,
      );

      expect(result).toBeDefined();
      expect(typeof result).toBe("string");

      const parsedResult = JSON.parse(result);
      expect(parsedResult).toMatchObject({
        server: "healthy",
        makeApi: {
          healthy: true,
          responseTime: expect.stringContaining("ms"),
        },
        overall: "healthy",
      });
    });

    it("should execute server-info tool and return comprehensive information", async () => {
      const addToolCalls = mockFastMCP.addTool.mock.calls;
      const serverInfoTool = addToolCalls.find(
        (call) => call[0].name === "server-info",
      );

      const mockContext = {
        log: { info: jest.fn(), error: jest.fn() },
        session: null,
      };

      const result = await serverInfoTool[0].execute({}, mockContext);

      expect(result).toBeDefined();
      expect(result.content).toBeDefined();
      expect(result.content[0].type).toBe("text");

      const parsedInfo = JSON.parse(result.content[0].text);
      expect(parsedInfo).toMatchObject({
        name: "Test Make.com FastMCP Server",
        version: "1.0.0",
        capabilities: expect.arrayContaining([
          "scenario-management",
          "enterprise-budget-control",
          "ai-driven-governance",
        ]),
      });
    });

    it("should execute test-configuration tool with API connectivity tests", async () => {
      const addToolCalls = mockFastMCP.addTool.mock.calls;
      const configTestTool = addToolCalls.find(
        (call) => call[0].name === "test-configuration",
      );

      const mockContext = {
        log: { info: jest.fn(), error: jest.fn() },
        reportProgress: jest.fn(),
        session: null,
      };

      const result = await configTestTool[0].execute(
        { includePermissions: false },
        mockContext,
      );

      expect(result).toBeDefined();
      expect(typeof result).toBe("string");

      const parsedResult = JSON.parse(result);
      expect(parsedResult).toMatchObject({
        apiConnectivity: true,
        userInfo: expect.objectContaining({
          id: "test_user_123",
          name: "Test User",
        }),
        scenarioAccess: true,
      });

      expect(mockContext.reportProgress).toHaveBeenCalledWith({
        progress: 100,
        total: 100,
      });
    });

    it("should handle tool execution errors gracefully", async () => {
      const addToolCalls = mockFastMCP.addTool.mock.calls;
      const configTestTool = addToolCalls.find(
        (call) => call[0].name === "test-configuration",
      );

      // Mock API client to throw error
      const mockApiClient = require("../../src/lib/make-api-client.js").default;
      const mockInstance = new mockApiClient();
      mockInstance.get.mockRejectedValue(new Error("API connection failed"));

      const mockContext = {
        log: { info: jest.fn(), error: jest.fn() },
        reportProgress: jest.fn(),
        session: null,
      };

      await expect(
        configTestTool[0].execute({ includePermissions: false }, mockContext),
      ).rejects.toThrow(UserError);
    });
  });

  describe("Server Lifecycle Management", () => {
    beforeEach(() => {
      serverInstance = new MakeServerInstance();
    });

    it("should start server successfully with default options", async () => {
      await expect(serverInstance.start()).resolves.not.toThrow();

      expect(mockFastMCP.start).toHaveBeenCalledWith({
        transportType: "stdio",
      });
    });

    it("should start server with custom options", async () => {
      const customOptions = {
        transportType: "httpStream",
        httpStream: { port: 3001, endpoint: "/api" },
      };

      await expect(serverInstance.start(customOptions)).resolves.not.toThrow();

      expect(mockFastMCP.start).toHaveBeenCalledWith(customOptions);
    });

    it("should validate Make.com API connectivity before starting", async () => {
      const mockApiClient = require("../../src/lib/make-api-client.js").default;
      const mockInstance = new mockApiClient();
      const healthCheckSpy = jest.spyOn(mockInstance, "healthCheck");

      const mockConfig = require("../../src/lib/config.js").default;
      mockConfig.getMakeConfig.mockReturnValue({
        ...mockConfig.getMakeConfig(),
        apiKey: "real_api_key", // Not a test key
      });

      await serverInstance.start();

      expect(healthCheckSpy).toHaveBeenCalled();
    });

    it("should skip API validation in development mode", async () => {
      const mockConfig = require("../../src/lib/config.js").default;
      mockConfig.getMakeConfig.mockReturnValue({
        ...mockConfig.getMakeConfig(),
        apiKey: "test_key_development", // Contains 'test_key'
      });

      await expect(serverInstance.start()).resolves.not.toThrow();
    });

    it("should handle API health check failure during startup", async () => {
      const mockApiClient = require("../../src/lib/make-api-client.js").default;
      const mockInstance = new mockApiClient();
      mockInstance.healthCheck.mockResolvedValue(false);

      const mockConfig = require("../../src/lib/config.js").default;
      mockConfig.getMakeConfig.mockReturnValue({
        ...mockConfig.getMakeConfig(),
        apiKey: "real_api_key",
      });

      await expect(serverInstance.start()).rejects.toThrow(
        "Make.com API is not accessible",
      );
    });

    it("should shutdown server gracefully", async () => {
      await expect(serverInstance.shutdown()).resolves.not.toThrow();

      const mockApiClient = require("../../src/lib/make-api-client.js").default;
      const mockInstance = new mockApiClient();
      expect(mockInstance.shutdown).toHaveBeenCalled();
    });

    it("should handle shutdown errors gracefully", async () => {
      const mockApiClient = require("../../src/lib/make-api-client.js").default;
      const mockInstance = new mockApiClient();
      mockInstance.shutdown.mockRejectedValue(new Error("Shutdown failed"));

      await expect(serverInstance.shutdown()).resolves.not.toThrow();
    });
  });

  describe("Event Handling and Protocol Compliance", () => {
    beforeEach(() => {
      serverInstance = new MakeServerInstance();
    });

    it("should register connect and disconnect event handlers", () => {
      expect(mockFastMCP.on).toHaveBeenCalledWith(
        "connect",
        expect.any(Function),
      );
      expect(mockFastMCP.on).toHaveBeenCalledWith(
        "disconnect",
        expect.any(Function),
      );
    });

    it("should handle connect events properly", () => {
      const connectHandler = mockFastMCP.on.mock.calls.find(
        (call) => call[0] === "connect",
      )[1];

      expect(() => {
        connectHandler({
          session: {
            clientCapabilities: { tools: true, resources: true },
          },
        });
      }).not.toThrow();
    });

    it("should handle disconnect events properly", () => {
      const disconnectHandler = mockFastMCP.on.mock.calls.find(
        (call) => call[0] === "disconnect",
      )[1];

      expect(() => {
        disconnectHandler({
          session: { id: "test_session" },
        });
      }).not.toThrow();
    });
  });

  describe("Error Handling and Recovery", () => {
    it("should handle server initialization failures", () => {
      const mockApiClient = require("../../src/lib/make-api-client.js").default;
      mockApiClient.mockImplementation(() => {
        throw new Error("API client initialization failed");
      });

      expect(() => {
        new MakeServerInstance();
      }).toThrow("API client initialization failed");
    });

    it("should handle server start failures gracefully", async () => {
      serverInstance = new MakeServerInstance();
      mockFastMCP.start.mockRejectedValue(new Error("Server start failed"));

      await expect(serverInstance.start()).rejects.toThrow(
        "Server start failed",
      );
    });

    it("should determine overall health based on API and security status", () => {
      serverInstance = new MakeServerInstance();

      // Test healthy state
      let health = (serverInstance as any).determineOverallHealth(true, {
        overall: "healthy",
      });
      expect(health).toBe("healthy");

      // Test degraded state due to API
      health = (serverInstance as any).determineOverallHealth(false, {
        overall: "healthy",
      });
      expect(health).toBe("degraded");

      // Test degraded state due to security
      health = (serverInstance as any).determineOverallHealth(true, {
        overall: "degraded",
      });
      expect(health).toBe("degraded");
    });
  });

  describe("Advanced Tool Loading and Integration", () => {
    beforeEach(() => {
      serverInstance = new MakeServerInstance();
    });

    it("should provide access to underlying FastMCP server instance", () => {
      const server = serverInstance.getServer();
      expect(server).toBe(mockFastMCP);
    });

    it("should defer advanced tools loading to avoid initialization timeout", () => {
      // Advanced tools should be loaded asynchronously after server initialization
      // This is tested by verifying server initializes successfully
      expect(serverInstance).toBeDefined();
      expect(mockFastMCP.addTool).toHaveBeenCalledTimes(4); // Only basic tools initially
    });
  });

  describe("Security and Monitoring Integration", () => {
    beforeEach(() => {
      serverInstance = new MakeServerInstance();
    });

    it("should execute security-status tool with comprehensive status", async () => {
      const addToolCalls = mockFastMCP.addTool.mock.calls;
      const securityTool = addToolCalls.find(
        (call) => call[0].name === "security-status",
      );

      const mockContext = {
        log: { info: jest.fn(), error: jest.fn() },
        session: null,
      };

      const result = await securityTool[0].execute(
        { includeMetrics: true, includeEvents: true },
        mockContext,
      );

      expect(result).toBeDefined();
      expect(typeof result).toBe("string");

      const parsedResult = JSON.parse(result);
      expect(parsedResult).toMatchObject({
        status: "disabled",
        message: "Security middleware temporarily disabled",
        configuration: expect.any(Object),
        metrics: { disabled: true },
        recentEvents: [],
      });
    });

    it("should include correlation IDs in all tool executions", async () => {
      const addToolCalls = mockFastMCP.addTool.mock.calls;
      const healthCheckTool = addToolCalls.find(
        (call) => call[0].name === "health-check",
      );

      const mockContext = {
        log: { info: jest.fn(), error: jest.fn() },
        session: { correlationId: "test_correlation_id" },
      };

      await healthCheckTool[0].execute({}, mockContext);

      expect(mockContext.log.info).toHaveBeenCalledWith(
        expect.stringContaining("Health check"),
        expect.objectContaining({ correlationId: "test_correlation_id" }),
      );
    });
  });

  describe("Configuration and Environment Integration", () => {
    it("should include rate limiting information in server instructions", () => {
      serverInstance = new MakeServerInstance();

      const fastMCPCall = (FastMCP as jest.MockedClass<any>).mock.calls[0][0];
      const instructions = fastMCPCall.instructions;

      expect(instructions).toContain("100 requests per 60 seconds");
    });

    it("should indicate authentication status in server instructions", () => {
      const mockConfig = require("../../src/lib/config.js").default;
      mockConfig.isAuthEnabled.mockReturnValue(false);

      serverInstance = new MakeServerInstance();

      const fastMCPCall = (FastMCP as jest.MockedClass<any>).mock.calls[0][0];
      const instructions = fastMCPCall.instructions;

      expect(instructions).toContain(
        "Server runs in open mode (no authentication required)",
      );
    });
  });

  describe("Integration and Dependency Management", () => {
    it("should properly initialize all critical dependencies", () => {
      serverInstance = new MakeServerInstance();

      // Verify config manager usage
      const mockConfig = require("../../src/lib/config.js").default;
      expect(mockConfig.getMakeConfig).toHaveBeenCalled();

      // Verify API client initialization
      const MockMakeApiClient =
        require("../../src/lib/make-api-client.js").default;
      expect(MockMakeApiClient).toHaveBeenCalled();

      // Verify error handler setup
      const mockErrorUtils = require("../../src/utils/errors.js");
      expect(mockErrorUtils.setupGlobalErrorHandlers).toHaveBeenCalled();
    });

    it("should handle logger child creation failures gracefully", () => {
      const mockLogger = require("../../src/lib/logger.js").default;
      mockLogger.child.mockImplementation(() => {
        throw new Error("Logger child creation failed");
      });

      // Should still create server instance with fallback logger
      expect(() => {
        serverInstance = new MakeServerInstance();
      }).not.toThrow();
    });
  });
});
