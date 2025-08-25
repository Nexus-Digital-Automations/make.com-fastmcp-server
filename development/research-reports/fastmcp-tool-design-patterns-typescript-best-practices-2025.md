# FastMCP Tool Design Patterns and TypeScript Best Practices Research Report

**Research Task ID:** task_1756146296963_iy2nftsak  
**Created:** August 25, 2025  
**Research Focus:** FastMCP tool architecture patterns, TypeScript integration, API client best practices, development workflow support, and performance/scalability considerations

## Executive Summary

This comprehensive research investigates FastMCP tool design patterns and TypeScript best practices for creating enterprise-grade MCP server tools. The research covers architectural patterns, type safety approaches, API integration strategies, development workflows, and performance optimization techniques essential for building comprehensive Make.com FastMCP tool suites.

## Table of Contents

1. [FastMCP Tool Architecture Patterns](#fastmcp-tool-architecture-patterns)
2. [TypeScript Integration Patterns](#typescript-integration-patterns)
3. [API Client Integration Best Practices](#api-client-integration-best-practices)
4. [Development Workflow Support](#development-workflow-support)
5. [Performance and Scalability Considerations](#performance-and-scalability-considerations)
6. [Recommendations for Make.com Tool Suite](#recommendations-for-makecom-tool-suite)

## 1. FastMCP Tool Architecture Patterns

### Core Framework Philosophy

FastMCP follows an **opinionated framework approach** that:

- Eliminates complexity by providing automatic boilerplate handling
- Provides simple, intuitive APIs for common tasks
- Maintains flexibility while abstracting implementation details
- Supports both stateful and stateless operation modes

### Tool Organization Patterns

#### 1.1 Single Responsibility Principle

```typescript
// ✅ Good: Focused tool with single purpose
server.addTool({
  name: "create-agent",
  description: "Create a new AI agent with specified configuration",
  parameters: z.object({
    name: z.string().min(1).max(100),
    teamId: z.number().int().positive(),
    llmProvider: z.enum(["openai", "claude", "custom"]),
  }),
  execute: async (args) => {
    // Single responsibility: create agent only
    return await createAgent(args);
  },
});

// ❌ Avoid: Monolithic tools handling multiple concerns
server.addTool({
  name: "agent-manager", // Too broad
  description: "Manage all agent operations",
  // Multiple responsibilities mixed together
});
```

#### 1.2 Tool Suite Organization Pattern

```typescript
// Organize tools by functional domains
const AI_AGENT_TOOLS = {
  lifecycle: "ai-agent-lifecycle-manager",
  context: "ai-agent-context-engine",
  providers: "llm-provider-gateway",
  monitoring: "agent-monitoring-dashboard",
  security: "security-auth-controller",
  recovery: "error-recovery-system",
  performance: "caching-performance-optimizer",
  testing: "testing-validation-framework",
} as const;

// Each tool focuses on its domain
server.addTool({
  name: AI_AGENT_TOOLS.lifecycle,
  description: "Complete agent lifecycle management",
  // Focused on lifecycle operations only
});
```

#### 1.3 Tool Annotation Patterns (2025 MCP Specification)

```typescript
server.addTool({
  name: "fetch-agent-data",
  description: "Retrieve agent information",
  parameters: z.object({
    agentId: z.string().uuid(),
  }),
  annotations: {
    title: "Agent Data Fetcher", // Human-readable title
    readOnlyHint: true, // Doesn't modify environment
    destructiveHint: false, // Safe operation
    idempotentHint: true, // Can be called repeatedly
    openWorldHint: true, // Interacts with external entities
  },
  execute: async (args) => {
    return await fetchAgentData(args.agentId);
  },
});
```

### Parameter Validation Patterns

#### 1.4 Standard Schema Support

```typescript
// Supports multiple validation libraries via Standard Schema
import { z } from "zod";
import { type } from "arktype";
import * as v from "valibot";

// Zod pattern (recommended)
const zodTool = {
  parameters: z.object({
    id: z.string().uuid(),
    config: z.object({
      temperature: z.number().min(0).max(2),
      maxTokens: z.number().int().positive().max(4000),
    }),
  }),
};

// ArkType pattern
const arkTypeTool = {
  parameters: type({
    id: "string",
    config: {
      temperature: "number",
      maxTokens: "integer",
    },
  }),
};

// Valibot pattern (requires @valibot/to-json-schema)
const valibotTool = {
  parameters: v.object({
    id: v.string(),
    config: v.object({
      temperature: v.number(),
      maxTokens: v.number(),
    }),
  }),
};
```

#### 1.5 Comprehensive Input Validation Pattern

```typescript
server.addTool({
  name: "update-agent",
  parameters: z.object({
    agentId: z.string().uuid(),
    updates: z.object({
      name: z.string().min(1).max(100).optional(),
      systemPrompt: z.string().min(10).max(4000).optional(),
      temperature: z.number().min(0).max(2).optional(),
      tools: z.array(z.string()).max(20).optional(),
    }),
  }),
  execute: async (args, { log, session }) => {
    // Parameter presence validation (handled by schema)
    // Type checking (handled by TypeScript + schema)
    // Value validation (handled by schema constraints)

    // Security checks
    await validateAgentAccess(session, args.agentId);

    // Business logic validation
    if (args.updates.tools?.some((tool) => !isValidTool(tool))) {
      throw new UserError("Invalid tool specified");
    }

    return await updateAgent(args.agentId, args.updates);
  },
});
```

### Content Response Patterns

#### 1.6 Multi-Content Type Support

```typescript
import { imageContent, audioContent } from "fastmcp";

server.addTool({
  name: "generate-agent-report",
  execute: async (args) => {
    // Return combination of content types
    return {
      content: [
        {
          type: "text",
          text: "# Agent Performance Report\n\nGenerated analysis...",
        },
        await imageContent({
          url: "https://api.example.com/charts/performance.png",
        }),
        await audioContent({
          path: "/tmp/voice-summary.mp3",
        }),
      ],
    };
  },
});
```

## 2. TypeScript Integration Patterns

### Type Safety Approaches

#### 2.1 Strict Configuration (2025 Best Practices)

```typescript
// tsconfig.json - Strict mode configuration
{
  "compilerOptions": {
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "noImplicitReturns": true,
    "noImplicitOverride": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "strictFunctionTypes": true
  }
}
```

#### 2.2 Interface Definitions for Tool Parameters

```typescript
// Core interfaces with comprehensive typing
interface AgentConfiguration {
  name: string;
  description: string;
  teamId: number;
  llmProvider: LLMProvider;
  modelName: string;
  systemPrompt: string;
  temperature: number;
  maxTokens: number;
  tools: string[];
  securityPolicy: SecurityPolicy;
  contextSettings: ContextSettings;
  performanceSettings: PerformanceSettings;
}

interface SecurityPolicy {
  accessLevel: "public" | "team" | "private";
  allowedUsers: string[];
  allowedTeams: number[];
  rateLimits: SecurityRateLimits;
  dataRetention: DataRetentionPolicy;
  encryption: EncryptionSettings;
  auditLogging: boolean;
  complianceLevel: ComplianceLevel;
}

// Template literal types for dynamic patterns
type APIEndpoint = `/api/v${number}/${string}`;
type EventName = `agent:${string}:${string}`;
type CacheKey = `cache:${string}:${string}`;
```

#### 2.3 Generic Patterns for API Integration

```typescript
// Generic API response handler
interface APIResponse<T> {
  data: T;
  status: number;
  message: string;
  timestamp: Date;
  requestId: string;
}

// Generic tool execution context
interface ToolContext<TSession = any, TParams = any> {
  session: TSession;
  log: Logger;
  reportProgress: (progress: { progress: number; total: number }) => void;
  parameters: TParams;
}

// Generic tool definition
interface ToolDefinition<TParams, TResult, TSession = any> {
  name: string;
  description: string;
  parameters: Schema<TParams>;
  annotations?: ToolAnnotations;
  execute: (
    params: TParams,
    context: ToolContext<TSession, TParams>,
  ) => Promise<TResult>;
}

// Usage example
const createAgentTool: ToolDefinition<
  AgentConfiguration,
  APIResponse<AIAgent>,
  AuthenticatedSession
> = {
  name: "create-agent",
  description: "Create a new AI agent",
  parameters: AgentConfigurationSchema,
  execute: async (params, { session, log }) => {
    // Fully typed implementation
    return await apiClient.createAgent(params);
  },
};
```

#### 2.4 Satisfies Operator Pattern (2025)

```typescript
// Use satisfies for type constraints with flexibility
const toolConfig = {
  development: {
    timeout: 30000,
    retries: 3,
    logLevel: "debug",
  },
  production: {
    timeout: 10000,
    retries: 5,
    logLevel: "error",
  },
} satisfies Record<string, ToolEnvironmentConfig>;

// Maintains type inference while enforcing constraints
type LogLevel = "debug" | "info" | "warn" | "error";
interface ToolEnvironmentConfig {
  timeout: number;
  retries: number;
  logLevel: LogLevel;
}
```

### Async/Await Patterns and Error Handling

#### 2.5 Advanced Error Handling Patterns (2025)

```typescript
// Custom error hierarchy for MCP tools
abstract class MCPError extends Error {
  abstract readonly code: string;
  abstract readonly statusCode: number;
  readonly timestamp: Date = new Date();

  constructor(
    message: string,
    public readonly context: Record<string, any> = {},
  ) {
    super(message);
    this.name = this.constructor.name;
  }
}

class APIError extends MCPError {
  readonly code = "API_ERROR";
  constructor(
    public readonly statusCode: number,
    message: string,
    context?: Record<string, any>,
  ) {
    super(message, context);
  }
}

class ValidationError extends MCPError {
  readonly code = "VALIDATION_ERROR";
  readonly statusCode = 400;

  constructor(
    message: string,
    public readonly validationErrors: ValidationDetail[],
  ) {
    super(message, { validationErrors });
  }
}

// Type-safe error handling pattern
async function executeWithErrorHandling<T>(
  operation: () => Promise<T>,
  context: OperationContext,
): Promise<Result<T, MCPError>> {
  try {
    const result = await operation();
    return { success: true, data: result };
  } catch (error) {
    const mcpError = transformError(error, context);

    // Log with full context
    context.log.error("Operation failed", {
      error: mcpError.message,
      code: mcpError.code,
      context: mcpError.context,
      stack: mcpError.stack,
    });

    return { success: false, error: mcpError };
  }
}
```

#### 2.6 Concurrent Operations Pattern

```typescript
// Handle multiple async operations with proper error handling
async function processMultipleAgents(
  agentIds: string[],
  operation: (agentId: string) => Promise<AgentResult>,
): Promise<BatchResult<AgentResult>> {
  const results = await Promise.allSettled(
    agentIds.map(async (agentId) => {
      try {
        const result = await operation(agentId);
        return { agentId, success: true, data: result };
      } catch (error) {
        return {
          agentId,
          success: false,
          error: transformError(error, { agentId }),
        };
      }
    }),
  );

  const successful = results
    .filter(
      (r): r is PromiseFulfilledResult<AgentOperationResult> =>
        r.status === "fulfilled" && r.value.success,
    )
    .map((r) => r.value);

  const failed = results
    .filter(
      (r): r is PromiseFulfilledResult<AgentOperationResult> =>
        r.status === "fulfilled" && !r.value.success,
    )
    .map((r) => r.value);

  return {
    successful,
    failed,
    total: agentIds.length,
    successRate: (successful.length / agentIds.length) * 100,
  };
}
```

## 3. API Client Integration Best Practices

### HTTP Client Configuration and Management

#### 3.1 Enterprise HTTP Client Pattern

```typescript
export class EnterpriseAPIClient {
  private readonly httpClient: AxiosInstance;
  private readonly logger: Logger;
  private readonly cache: CacheManager;
  private readonly rateLimiter: RateLimiter;
  private readonly circuitBreaker: CircuitBreaker;

  constructor(config: APIClientConfig) {
    this.httpClient = axios.create({
      baseURL: config.baseUrl,
      timeout: config.timeout || 30000,
      headers: {
        "User-Agent": "FastMCP-Tools/1.0.0",
        "Content-Type": "application/json",
      },
    });

    this.setupInterceptors();
    this.setupRetryLogic();
  }

  private setupInterceptors(): void {
    // Request interceptor for authentication and logging
    this.httpClient.interceptors.request.use(
      (config) => {
        const operationId = generateOperationId();
        config.headers["X-Operation-ID"] = operationId;

        this.logger.debug("API Request", {
          method: config.method?.toUpperCase(),
          url: config.url,
          operationId,
        });

        return config;
      },
      (error) => {
        this.logger.error("Request setup failed", { error: error.message });
        return Promise.reject(error);
      },
    );

    // Response interceptor for error handling and caching
    this.httpClient.interceptors.response.use(
      (response) => {
        this.logger.debug("API Response", {
          status: response.status,
          operationId: response.config.headers["X-Operation-ID"],
          responseTime: response.headers["x-response-time"],
        });

        return response;
      },
      async (error) => {
        const shouldRetry = await this.handleResponseError(error);

        if (shouldRetry) {
          return this.retryRequest(error.config);
        }

        return Promise.reject(this.transformAPIError(error));
      },
    );
  }
}
```

### Authentication Token Handling and Refresh

#### 3.2 Token Management Pattern (2025)

```typescript
class TokenManager {
  private accessToken?: string;
  private refreshToken?: string;
  private tokenExpiry?: Date;
  private refreshPromise?: Promise<TokenResponse>;

  constructor(private readonly config: AuthConfig) {}

  async getValidToken(): Promise<string> {
    if (this.isTokenValid()) {
      return this.accessToken!;
    }

    // Prevent concurrent refresh requests
    if (this.refreshPromise) {
      const tokens = await this.refreshPromise;
      return tokens.accessToken;
    }

    this.refreshPromise = this.refreshTokens();

    try {
      const tokens = await this.refreshPromise;
      this.updateTokens(tokens);
      return tokens.accessToken;
    } finally {
      this.refreshPromise = undefined;
    }
  }

  private isTokenValid(): boolean {
    if (!this.accessToken || !this.tokenExpiry) {
      return false;
    }

    // Check if token expires within next 5 minutes
    const fiveMinutes = 5 * 60 * 1000;
    return this.tokenExpiry.getTime() > Date.now() + fiveMinutes;
  }

  private async refreshTokens(): Promise<TokenResponse> {
    if (!this.refreshToken) {
      throw new AuthenticationError("No refresh token available");
    }

    try {
      const response = await axios.post("/auth/refresh", {
        refreshToken: this.refreshToken,
      });

      return response.data;
    } catch (error) {
      // Clear invalid tokens
      this.clearTokens();
      throw new AuthenticationError("Token refresh failed");
    }
  }
}
```

### Rate Limiting Implementation Strategies

#### 3.3 Advanced Rate Limiting Patterns (2025)

```typescript
// Multi-algorithm rate limiter
export class AdaptiveRateLimiter {
  private readonly algorithms: Map<string, RateLimitAlgorithm>;
  private readonly storage: RateLimitStorage;

  constructor(config: RateLimitConfig) {
    this.algorithms = new Map([
      ["token-bucket", new TokenBucketAlgorithm(config.tokenBucket)],
      ["sliding-window", new SlidingWindowAlgorithm(config.slidingWindow)],
      ["leaky-bucket", new LeakyBucketAlgorithm(config.leakyBucket)],
    ]);

    this.storage =
      config.storage === "redis"
        ? new RedisStorage(config.redis)
        : new InMemoryStorage();
  }

  async checkLimit(
    key: string,
    algorithm: string = "token-bucket",
  ): Promise<RateLimitResult> {
    const limiter = this.algorithms.get(algorithm);
    if (!limiter) {
      throw new Error(`Unknown rate limiting algorithm: ${algorithm}`);
    }

    const result = await limiter.checkLimit(key, this.storage);

    // Dynamic adjustment based on system load
    if (this.shouldAdjustLimits()) {
      result.remainingRequests = Math.floor(result.remainingRequests * 0.8);
    }

    return result;
  }

  private shouldAdjustLimits(): boolean {
    const cpuUsage = process.cpuUsage();
    const memoryUsage = process.memoryUsage();

    // Reduce limits if system is under stress
    return (
      cpuUsage.user / 1000000 > 800 || // 80% CPU
      memoryUsage.heapUsed / memoryUsage.heapTotal > 0.8 // 80% memory
    );
  }
}

// Dynamic rate limiting based on API response headers
class HeaderBasedRateLimiter {
  async extractLimitsFromHeaders(
    headers: Record<string, string>,
  ): Promise<RateLimitInfo> {
    return {
      limit: parseInt(headers["x-ratelimit-limit"] || "100"),
      remaining: parseInt(headers["x-ratelimit-remaining"] || "100"),
      resetTime: new Date(headers["x-ratelimit-reset"] || Date.now() + 60000),
      retryAfter: parseInt(headers["retry-after"] || "60"),
    };
  }

  async waitForRateLimit(rateLimitInfo: RateLimitInfo): Promise<void> {
    if (rateLimitInfo.remaining > 0) {
      return;
    }

    const waitTime = rateLimitInfo.resetTime.getTime() - Date.now();
    if (waitTime > 0) {
      await new Promise((resolve) => setTimeout(resolve, waitTime));
    }
  }
}
```

### Request/Response Transformation Patterns

#### 3.4 Transformation Pipeline Pattern

```typescript
interface RequestTransformer {
  transform(request: APIRequest): Promise<APIRequest>;
}

interface ResponseTransformer<T> {
  transform(response: APIResponse, request: APIRequest): Promise<T>;
}

class APITransformationPipeline {
  private requestTransformers: RequestTransformer[] = [];
  private responseTransformers: Map<string, ResponseTransformer<any>> =
    new Map();

  addRequestTransformer(transformer: RequestTransformer): void {
    this.requestTransformers.push(transformer);
  }

  addResponseTransformer<T>(
    endpoint: string,
    transformer: ResponseTransformer<T>,
  ): void {
    this.responseTransformers.set(endpoint, transformer);
  }

  async executeRequest<T>(endpoint: string, request: APIRequest): Promise<T> {
    // Apply request transformations
    let transformedRequest = request;
    for (const transformer of this.requestTransformers) {
      transformedRequest = await transformer.transform(transformedRequest);
    }

    // Execute request
    const response = await this.httpClient.request(transformedRequest);

    // Apply response transformation
    const responseTransformer = this.responseTransformers.get(endpoint);
    if (responseTransformer) {
      return await responseTransformer.transform(response, transformedRequest);
    }

    return response.data;
  }
}

// Example transformers
class AuthenticationTransformer implements RequestTransformer {
  constructor(private tokenManager: TokenManager) {}

  async transform(request: APIRequest): Promise<APIRequest> {
    const token = await this.tokenManager.getValidToken();
    return {
      ...request,
      headers: {
        ...request.headers,
        Authorization: `Bearer ${token}`,
      },
    };
  }
}

class AgentResponseTransformer implements ResponseTransformer<AIAgent> {
  async transform(response: APIResponse): Promise<AIAgent> {
    const data = response.data;

    // Transform API response to internal model
    return {
      id: data.id,
      name: data.name,
      description: data.description,
      teamId: data.teamId,
      llmProvider: data.llmProvider,
      modelName: data.modelName,
      systemPrompt: data.systemPrompt,
      temperature: data.temperature,
      maxTokens: data.maxTokens,
      tools: data.tools || [],
      securityPolicy: data.securityPolicy || getDefaultSecurityPolicy(),
      status: data.status || "active",
      metrics: data.metrics || getDefaultMetrics(),
      createdAt: new Date(data.createdAt),
      updatedAt: new Date(data.updatedAt),
      createdBy: data.createdBy,
      lastActiveAt: data.lastActiveAt ? new Date(data.lastActiveAt) : undefined,
    };
  }
}
```

## 4. Development Workflow Support

### Tool Testing and Validation Approaches

#### 4.1 Comprehensive Testing Strategy

```typescript
// Test helper for MCP tools
export class MCPToolTester {
  private server: FastMCP;
  private testSession: MockSession;

  constructor(private config: TestConfig) {
    this.server = new FastMCP({
      name: "test-server",
      version: "1.0.0",
    });

    this.testSession = new MockSession({
      userId: "test-user",
      permissions: ["admin"],
    });
  }

  async testTool<TParams, TResult>(
    toolName: string,
    parameters: TParams,
    expectedResult?: TResult,
  ): Promise<TestResult<TResult>> {
    const startTime = Date.now();

    try {
      const result = await this.server.callTool(
        toolName,
        parameters,
        this.testSession,
      );

      const duration = Date.now() - startTime;

      // Validate result structure
      this.validateResult(result, expectedResult);

      return {
        success: true,
        result,
        duration,
        logs: this.testSession.getLogs(),
      };
    } catch (error) {
      return {
        success: false,
        error: error as Error,
        duration: Date.now() - startTime,
        logs: this.testSession.getLogs(),
      };
    }
  }

  async runIntegrationTests(testSuite: TestSuite): Promise<TestSuiteResult> {
    const results: TestResult<any>[] = [];

    for (const test of testSuite.tests) {
      const result = await this.testTool(
        test.toolName,
        test.parameters,
        test.expectedResult,
      );

      results.push(result);

      // Stop on first failure if configured
      if (!result.success && testSuite.stopOnFailure) {
        break;
      }
    }

    return {
      totalTests: testSuite.tests.length,
      passed: results.filter((r) => r.success).length,
      failed: results.filter((r) => !r.success).length,
      results,
      duration: results.reduce((sum, r) => sum + r.duration, 0),
    };
  }
}

// Usage example
describe("AI Agent Tools", () => {
  const tester = new MCPToolTester({ timeout: 30000 });

  test("create agent with valid parameters", async () => {
    const parameters = {
      name: "Test Agent",
      teamId: 123,
      llmProvider: "openai",
      modelName: "gpt-4",
      systemPrompt: "You are a helpful assistant",
      temperature: 0.7,
      maxTokens: 1000,
    };

    const result = await tester.testTool("create-agent", parameters);

    expect(result.success).toBe(true);
    expect(result.result.content[0].text).toContain(
      "Agent created successfully",
    );
  });
});
```

#### 4.2 FastMCP CLI Development Pattern

```bash
# Development workflow using FastMCP CLI
npx fastmcp dev server.ts          # Interactive development mode
npx fastmcp inspect server.ts      # Web UI inspection
npx fastmcp test server.ts         # Run test suite
npx fastmcp validate server.ts     # Validate tool definitions
npx fastmcp benchmark server.ts    # Performance benchmarking
```

### Development vs Production Configurations

#### 4.3 Environment-Specific Configuration Pattern

```typescript
interface EnvironmentConfig {
  development: ServerConfig;
  staging: ServerConfig;
  production: ServerConfig;
}

const config: EnvironmentConfig = {
  development: {
    logLevel: "debug",
    timeout: 60000,
    retries: 1,
    rateLimiting: {
      enabled: false,
    },
    caching: {
      enabled: false,
    },
    authentication: {
      required: false,
    },
  },
  staging: {
    logLevel: "info",
    timeout: 30000,
    retries: 3,
    rateLimiting: {
      enabled: true,
      requestsPerMinute: 1000,
    },
    caching: {
      enabled: true,
      ttl: 300, // 5 minutes
    },
    authentication: {
      required: true,
    },
  },
  production: {
    logLevel: "error",
    timeout: 15000,
    retries: 5,
    rateLimiting: {
      enabled: true,
      requestsPerMinute: 100,
    },
    caching: {
      enabled: true,
      ttl: 3600, // 1 hour
    },
    authentication: {
      required: true,
      mfa: true,
    },
  },
};

// Environment detection and configuration loading
function getEnvironmentConfig(): ServerConfig {
  const environment = process.env.NODE_ENV as keyof EnvironmentConfig;
  return config[environment] || config.development;
}
```

### Logging and Debugging Capabilities

#### 4.4 Structured Logging Pattern

```typescript
// Comprehensive logging system for MCP tools
export class MCPLogger {
  private logger: Winston.Logger;

  constructor(config: LoggingConfig) {
    this.logger = winston.createLogger({
      level: config.level,
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json(),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
          return JSON.stringify({
            timestamp,
            level,
            message,
            operationId: meta.operationId,
            toolName: meta.toolName,
            userId: meta.userId,
            sessionId: meta.sessionId,
            duration: meta.duration,
            ...meta,
          });
        }),
      ),
      transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: "mcp-tools.log" }),
        new winston.transports.File({
          filename: "mcp-errors.log",
          level: "error",
        }),
      ],
    });
  }

  logToolExecution<T>(
    toolName: string,
    parameters: T,
    context: ToolExecutionContext,
  ): ToolLogger {
    const operationId = generateOperationId();
    const startTime = Date.now();

    this.logger.info("Tool execution started", {
      operationId,
      toolName,
      parameters: this.sanitizeParameters(parameters),
      userId: context.session.userId,
      sessionId: context.session.id,
    });

    return {
      success: (result: any) => {
        this.logger.info("Tool execution completed", {
          operationId,
          toolName,
          duration: Date.now() - startTime,
          resultSize: JSON.stringify(result).length,
        });
      },
      error: (error: Error) => {
        this.logger.error("Tool execution failed", {
          operationId,
          toolName,
          duration: Date.now() - startTime,
          error: error.message,
          stack: error.stack,
        });
      },
      progress: (progress: {
        current: number;
        total: number;
        message?: string;
      }) => {
        this.logger.debug("Tool execution progress", {
          operationId,
          toolName,
          progress: (progress.current / progress.total) * 100,
          message: progress.message,
        });
      },
    };
  }
}
```

### Progress Reporting for Long-running Operations

#### 4.5 Progress Tracking Pattern

```typescript
server.addTool({
  name: "bulk-agent-update",
  description: "Update multiple agents simultaneously",
  parameters: z.object({
    agentIds: z.array(z.string().uuid()),
    updates: z.record(z.any()),
  }),
  execute: async (args, { reportProgress, log }) => {
    const { agentIds, updates } = args;
    const total = agentIds.length;
    const results = [];

    reportProgress({ progress: 0, total });

    for (let i = 0; i < agentIds.length; i++) {
      const agentId = agentIds[i];

      try {
        log.info(`Updating agent ${i + 1}/${total}`, { agentId });

        const result = await updateAgent(agentId, updates);
        results.push({ agentId, success: true, result });

        reportProgress({
          progress: i + 1,
          total,
          message: `Updated agent ${agentId}`,
        });
      } catch (error) {
        log.error(`Failed to update agent ${agentId}`, {
          error: error.message,
        });
        results.push({ agentId, success: false, error: error.message });

        reportProgress({
          progress: i + 1,
          total,
          message: `Failed to update agent ${agentId}`,
        });
      }
    }

    const successful = results.filter((r) => r.success).length;
    const failed = results.filter((r) => !r.success).length;

    return {
      content: [
        {
          type: "text",
          text: `✅ Bulk update completed!\n\n**Results:**\n- Successful: ${successful}/${total}\n- Failed: ${failed}/${total}\n- Success Rate: ${((successful / total) * 100).toFixed(1)}%`,
        },
      ],
    };
  },
});
```

## 5. Performance and Scalability Considerations

### Caching Strategies for API Responses

#### 5.1 Multi-Layer Caching Pattern

```typescript
// Comprehensive caching system for MCP tools
export class MCPCacheManager {
  private memoryCache: Map<string, CacheEntry>;
  private redisClient?: RedisClient;
  private diskCache?: DiskCache;

  constructor(private config: CacheConfig) {
    this.memoryCache = new Map();

    if (config.redis.enabled) {
      this.redisClient = new RedisClient(config.redis);
    }

    if (config.disk.enabled) {
      this.diskCache = new DiskCache(config.disk);
    }

    // Setup cache cleanup
    setInterval(() => this.cleanup(), config.cleanupInterval || 300000);
  }

  async get<T>(key: string): Promise<T | null> {
    // L1: Memory cache (fastest)
    const memoryResult = this.memoryCache.get(key);
    if (memoryResult && !this.isExpired(memoryResult)) {
      return memoryResult.data as T;
    }

    // L2: Redis cache (fast)
    if (this.redisClient) {
      const redisResult = await this.redisClient.get(key);
      if (redisResult) {
        const data = JSON.parse(redisResult);
        // Promote to memory cache
        this.memoryCache.set(key, {
          data,
          timestamp: Date.now(),
          ttl: this.config.memory.ttl,
        });
        return data as T;
      }
    }

    // L3: Disk cache (slower but persistent)
    if (this.diskCache) {
      const diskResult = await this.diskCache.get(key);
      if (diskResult) {
        // Promote to higher cache levels
        if (this.redisClient) {
          await this.redisClient.setex(
            key,
            this.config.redis.ttl,
            JSON.stringify(diskResult),
          );
        }

        this.memoryCache.set(key, {
          data: diskResult,
          timestamp: Date.now(),
          ttl: this.config.memory.ttl,
        });

        return diskResult as T;
      }
    }

    return null;
  }

  async set<T>(key: string, data: T, options?: CacheOptions): Promise<void> {
    const ttl = options?.ttl || this.config.defaultTtl;

    // Store in all available cache layers
    this.memoryCache.set(key, {
      data,
      timestamp: Date.now(),
      ttl,
    });

    if (this.redisClient) {
      await this.redisClient.setex(key, ttl, JSON.stringify(data));
    }

    if (this.diskCache) {
      await this.diskCache.set(key, data, ttl);
    }
  }

  // Smart cache invalidation
  async invalidatePattern(pattern: string): Promise<void> {
    // Memory cache
    for (const key of this.memoryCache.keys()) {
      if (this.matchesPattern(key, pattern)) {
        this.memoryCache.delete(key);
      }
    }

    // Redis cache
    if (this.redisClient) {
      const keys = await this.redisClient.keys(pattern);
      if (keys.length > 0) {
        await this.redisClient.del(...keys);
      }
    }

    // Disk cache
    if (this.diskCache) {
      await this.diskCache.invalidatePattern(pattern);
    }
  }
}

// Usage in tools
server.addTool({
  name: "get-agent",
  execute: async (args, { log }) => {
    const cacheKey = `agent:${args.agentId}`;

    // Try cache first
    const cached = await cacheManager.get<AIAgent>(cacheKey);
    if (cached) {
      log.debug("Cache hit", { cacheKey });
      return formatAgentResponse(cached);
    }

    // Fetch from API
    log.debug("Cache miss, fetching from API", { cacheKey });
    const agent = await apiClient.getAgent(args.agentId);

    // Cache the result
    await cacheManager.set(cacheKey, agent, { ttl: 300 }); // 5 minutes

    return formatAgentResponse(agent);
  },
});
```

### Connection Pooling and Resource Management

#### 5.2 Resource Pool Pattern

```typescript
// Connection pool manager for external resources
export class ResourcePoolManager {
  private pools: Map<string, ConnectionPool>;
  private healthCheckers: Map<string, HealthChecker>;

  constructor(private config: PoolConfig) {
    this.pools = new Map();
    this.healthCheckers = new Map();
  }

  createPool(name: string, factory: ConnectionFactory): void {
    const poolConfig = this.config.pools[name] || this.config.default;

    const pool = new ConnectionPool({
      ...poolConfig,
      factory,
      validate: (connection) => this.validateConnection(connection),
      destroy: (connection) => this.destroyConnection(connection),
    });

    this.pools.set(name, pool);

    // Setup health checking
    const healthChecker = new HealthChecker(pool, {
      interval: poolConfig.healthCheckInterval,
      timeout: poolConfig.healthCheckTimeout,
    });

    this.healthCheckers.set(name, healthChecker);
    healthChecker.start();
  }

  async acquire<T>(poolName: string): Promise<PooledConnection<T>> {
    const pool = this.pools.get(poolName);
    if (!pool) {
      throw new Error(`Pool '${poolName}' not found`);
    }

    try {
      const connection = await pool.acquire();

      return {
        connection: connection as T,
        release: () => pool.release(connection),
        destroy: () => pool.destroy(connection),
      };
    } catch (error) {
      throw new Error(
        `Failed to acquire connection from pool '${poolName}': ${error.message}`,
      );
    }
  }

  async shutdown(): Promise<void> {
    // Stop health checkers
    for (const healthChecker of this.healthCheckers.values()) {
      await healthChecker.stop();
    }

    // Drain and close all pools
    const shutdownPromises = Array.from(this.pools.values()).map((pool) =>
      pool.drain().then(() => pool.clear()),
    );

    await Promise.all(shutdownPromises);
  }
}

// Database connection pool example
const dbPool = new ResourcePoolManager({
  default: {
    min: 2,
    max: 10,
    acquireTimeoutMillis: 30000,
    idleTimeoutMillis: 300000,
    healthCheckInterval: 60000,
    healthCheckTimeout: 5000,
  },
  pools: {
    postgres: {
      min: 5,
      max: 20,
    },
    redis: {
      min: 2,
      max: 10,
    },
  },
});

// HTTP client pool for API calls
class HTTPConnectionFactory implements ConnectionFactory {
  constructor(private config: HTTPConfig) {}

  async create(): Promise<AxiosInstance> {
    return axios.create({
      baseURL: this.config.baseUrl,
      timeout: this.config.timeout,
      maxRedirects: this.config.maxRedirects,
      headers: this.config.defaultHeaders,
    });
  }
}
```

### Concurrent Request Handling

#### 5.3 Advanced Concurrency Patterns

```typescript
// Semaphore for controlling concurrent operations
export class Semaphore {
  private permits: number;
  private waiting: Array<() => void> = [];

  constructor(permits: number) {
    this.permits = permits;
  }

  async acquire(): Promise<() => void> {
    if (this.permits > 0) {
      this.permits--;
      return () => this.release();
    }

    return new Promise((resolve) => {
      this.waiting.push(() => {
        resolve(() => this.release());
      });
    });
  }

  private release(): void {
    this.permits++;

    if (this.waiting.length > 0) {
      const next = this.waiting.shift()!;
      this.permits--;
      next();
    }
  }
}

// Concurrent request manager
export class ConcurrentRequestManager {
  private semaphore: Semaphore;
  private activeRequests: Map<string, Promise<any>>;
  private requestQueue: RequestQueue;

  constructor(maxConcurrentRequests: number = 10, queueConfig?: QueueConfig) {
    this.semaphore = new Semaphore(maxConcurrentRequests);
    this.activeRequests = new Map();
    this.requestQueue = new RequestQueue(queueConfig);
  }

  async execute<T>(
    key: string,
    operation: () => Promise<T>,
    options?: RequestOptions,
  ): Promise<T> {
    // Deduplicate identical concurrent requests
    if (this.activeRequests.has(key)) {
      return (await this.activeRequests.get(key)) as T;
    }

    const requestPromise = this.executeWithSemaphore(operation, options);
    this.activeRequests.set(key, requestPromise);

    try {
      return await requestPromise;
    } finally {
      this.activeRequests.delete(key);
    }
  }

  private async executeWithSemaphore<T>(
    operation: () => Promise<T>,
    options?: RequestOptions,
  ): Promise<T> {
    if (options?.priority) {
      await this.requestQueue.enqueue(operation, options.priority);
      return await this.requestQueue.dequeue();
    }

    const release = await this.semaphore.acquire();

    try {
      return await operation();
    } finally {
      release();
    }
  }

  async executeBatch<T>(
    operations: Array<{ key: string; operation: () => Promise<T> }>,
    batchOptions?: BatchOptions,
  ): Promise<Array<{ key: string; result?: T; error?: Error }>> {
    const batchSize = batchOptions?.batchSize || 5;
    const results: Array<{ key: string; result?: T; error?: Error }> = [];

    // Process operations in batches
    for (let i = 0; i < operations.length; i += batchSize) {
      const batch = operations.slice(i, i + batchSize);

      const batchResults = await Promise.allSettled(
        batch.map(async ({ key, operation }) => {
          try {
            const result = await this.execute(key, operation);
            return { key, result };
          } catch (error) {
            return { key, error: error as Error };
          }
        }),
      );

      results.push(
        ...batchResults.map((r) =>
          r.status === "fulfilled" ? r.value : r.reason,
        ),
      );
    }

    return results;
  }
}

// Usage in tools
const concurrentManager = new ConcurrentRequestManager(10);

server.addTool({
  name: "batch-agent-status",
  execute: async (args, { reportProgress }) => {
    const operations = args.agentIds.map((agentId) => ({
      key: `status:${agentId}`,
      operation: () => apiClient.getAgentStatus(agentId),
    }));

    const results = await concurrentManager.executeBatch(operations, {
      batchSize: 5,
    });

    reportProgress({ progress: results.length, total: operations.length });

    return formatBatchResults(results);
  },
});
```

### Memory Management Patterns

#### 5.4 Memory Optimization Strategies

```typescript
// Memory-aware data structures
export class MemoryAwareCache<T> {
  private cache: Map<string, CacheEntry<T>>;
  private memoryUsage: number = 0;
  private readonly maxMemoryMB: number;
  private readonly cleanupThreshold: number;

  constructor(maxMemoryMB: number = 100) {
    this.cache = new Map();
    this.maxMemoryMB = maxMemoryMB;
    this.cleanupThreshold = maxMemoryMB * 0.8; // Start cleanup at 80%

    // Monitor memory usage
    setInterval(() => this.monitorMemory(), 30000);
  }

  set(key: string, value: T, ttl: number = 300000): void {
    const size = this.estimateSize(value);

    // Check if adding this entry would exceed memory limit
    if ((this.memoryUsage + size) / (1024 * 1024) > this.maxMemoryMB) {
      this.performCleanup();

      // If still not enough space, reject the entry
      if ((this.memoryUsage + size) / (1024 * 1024) > this.maxMemoryMB) {
        throw new Error("Cache memory limit exceeded");
      }
    }

    const entry: CacheEntry<T> = {
      value,
      timestamp: Date.now(),
      ttl,
      size,
      accessCount: 0,
      lastAccessed: Date.now(),
    };

    this.cache.set(key, entry);
    this.memoryUsage += size;
  }

  get(key: string): T | null {
    const entry = this.cache.get(key);

    if (!entry) {
      return null;
    }

    // Check expiration
    if (Date.now() - entry.timestamp > entry.ttl) {
      this.delete(key);
      return null;
    }

    // Update access statistics
    entry.accessCount++;
    entry.lastAccessed = Date.now();

    return entry.value;
  }

  private performCleanup(): void {
    const entries = Array.from(this.cache.entries());

    // Sort by priority (LRU + access frequency)
    entries.sort(([, a], [, b]) => {
      const aPriority = this.calculatePriority(a);
      const bPriority = this.calculatePriority(b);
      return aPriority - bPriority;
    });

    // Remove entries until memory usage is below threshold
    let removedEntries = 0;
    const targetMemory = this.cleanupThreshold * 1024 * 1024;

    for (const [key, entry] of entries) {
      if (this.memoryUsage <= targetMemory) {
        break;
      }

      this.delete(key);
      removedEntries++;
    }

    console.log(
      `Cache cleanup: removed ${removedEntries} entries, memory usage: ${(this.memoryUsage / (1024 * 1024)).toFixed(2)}MB`,
    );
  }

  private calculatePriority(entry: CacheEntry<T>): number {
    const now = Date.now();
    const age = now - entry.timestamp;
    const timeSinceAccess = now - entry.lastAccessed;
    const accessFrequency = entry.accessCount / (age / 1000); // accesses per second

    // Lower priority means more likely to be evicted
    return accessFrequency / (timeSinceAccess / 1000);
  }

  private estimateSize(obj: any): number {
    return JSON.stringify(obj).length * 2; // Rough estimate
  }

  private monitorMemory(): void {
    const usage = process.memoryUsage();
    const heapUsedMB = usage.heapUsed / (1024 * 1024);
    const cacheUsedMB = this.memoryUsage / (1024 * 1024);

    console.log(
      `Memory usage - Heap: ${heapUsedMB.toFixed(2)}MB, Cache: ${cacheUsedMB.toFixed(2)}MB`,
    );

    // Force cleanup if system memory is high
    if (heapUsedMB > 500) {
      // 500MB threshold
      this.performCleanup();
    }
  }
}

// Streaming data processing for large responses
export class StreamingProcessor {
  async processLargeDataset<T>(
    dataSource: AsyncIterable<T>,
    processor: (chunk: T[]) => Promise<void>,
    chunkSize: number = 100,
  ): Promise<void> {
    let chunk: T[] = [];

    for await (const item of dataSource) {
      chunk.push(item);

      if (chunk.length >= chunkSize) {
        await processor(chunk);
        chunk = []; // Clear chunk to free memory
      }
    }

    // Process remaining items
    if (chunk.length > 0) {
      await processor(chunk);
    }
  }
}

// Usage in tools for handling large datasets
server.addTool({
  name: "process-large-agent-dataset",
  execute: async (args, { reportProgress }) => {
    const processor = new StreamingProcessor();
    let processedCount = 0;

    await processor.processLargeDataset(
      getAgentDataStream(args.teamId),
      async (chunk) => {
        // Process chunk without loading entire dataset into memory
        const results = await Promise.all(
          chunk.map((agent) => processAgent(agent)),
        );

        processedCount += results.length;
        reportProgress({
          progress: processedCount,
          total: args.estimatedTotal,
        });

        // Chunk processing complete, memory automatically freed
      },
      50, // Process 50 agents at a time
    );

    return "Large dataset processed successfully";
  },
});
```

## 6. Recommendations for Make.com Tool Suite

### Tool Structure and Organization

Based on the research findings, here are specific recommendations for designing a comprehensive Make.com FastMCP tool suite:

#### 6.1 Recommended Tool Architecture

```typescript
// Make.com FastMCP Tool Suite Architecture
export const MAKECOM_TOOLS = {
  // Core Management Tools
  lifecycle: "makecom-agent-lifecycle-manager", // Create, update, delete agents
  context: "makecom-context-manager", // Manage agent memory and context
  execution: "makecom-execution-engine", // Execute agents and scenarios

  // API Integration Tools
  customApps: "makecom-custom-apps-manager", // Custom Apps API integration
  templates: "makecom-templates-manager", // Templates API management
  scenarios: "makecom-scenarios-manager", // Scenario management

  // Administration Tools
  teams: "makecom-teams-admin", // Team and organization management
  billing: "makecom-billing-monitor", // Billing and usage monitoring

  // Development Tools
  debugging: "makecom-debug-assistant", // Debugging and troubleshooting
  testing: "makecom-test-runner", // Testing and validation
} as const;
```

#### 6.2 Tool Naming Conventions

```typescript
// Follow consistent naming patterns
const TOOL_NAMING_PATTERNS = {
  // Action + Entity pattern
  "create-agent": "Create a new AI agent",
  "update-scenario": "Update existing scenario",
  "delete-template": "Delete a template",

  // Entity + Action pattern for queries
  "agent-status": "Get agent status information",
  "scenario-history": "Get scenario execution history",
  "team-usage": "Get team usage statistics",

  // Batch operations
  "batch-agent-update": "Update multiple agents",
  "bulk-scenario-export": "Export multiple scenarios",

  // Management operations
  "manage-custom-apps": "Manage custom applications",
  "monitor-billing": "Monitor billing and usage",
};
```

### Parameter Schema Design

#### 6.3 Standardized Parameter Patterns

```typescript
// Common parameter schemas for Make.com tools
const MakeComSchemas = {
  // Agent identification
  agentId: z.string().uuid(),
  teamId: z.number().int().positive(),
  organizationId: z.number().int().positive(),

  // Pagination
  pagination: z.object({
    page: z.number().int().positive().default(1),
    limit: z.number().int().min(1).max(100).default(20),
    sortBy: z.string().optional(),
    sortOrder: z.enum(["asc", "desc"]).default("desc"),
  }),

  // Date ranges
  dateRange: z.object({
    startDate: z.string().datetime(),
    endDate: z.string().datetime(),
  }),

  // Filtering
  filter: z.object({
    status: z.array(z.string()).optional(),
    tags: z.array(z.string()).optional(),
    createdBy: z.string().optional(),
    search: z.string().optional(),
  }),

  // Agent configuration
  agentConfig: z.object({
    name: z.string().min(1).max(100),
    description: z.string().max(500),
    systemPrompt: z.string().min(10).max(4000),
    temperature: z.number().min(0).max(2).default(0.7),
    maxTokens: z.number().int().positive().max(4000).default(1000),
    tools: z.array(z.string()).max(20).optional(),
    contextSettings: z.object({
      memoryEnabled: z.boolean().default(true),
      learningEnabled: z.boolean().default(true),
      maxContextLength: z.number().int().positive().default(8000),
    }),
  }),
};
```

### Error Handling Strategy

#### 6.4 Make.com-Specific Error Handling

```typescript
// Custom error types for Make.com integration
export class MakeComError extends MCPError {
  constructor(
    message: string,
    public readonly makeComCode: string,
    public readonly statusCode: number = 500,
    context?: Record<string, any>,
  ) {
    super(message, `MAKECOM_${makeComCode}`, statusCode, context);
  }
}

export class MakeComAPIError extends MakeComError {
  constructor(statusCode: number, message: string, apiResponse?: any) {
    super(message, "API_ERROR", statusCode, { apiResponse });
  }
}

export class MakeComRateLimitError extends MakeComError {
  constructor(resetTime: Date, requestsRemaining: number = 0) {
    super("Make.com API rate limit exceeded", "RATE_LIMIT", 429, {
      resetTime,
      requestsRemaining,
    });
  }
}

// Error recovery strategies for Make.com
const makeComErrorRecovery = {
  rateLimitRecovery: async (error: MakeComRateLimitError) => {
    const waitTime = error.context.resetTime.getTime() - Date.now();
    if (waitTime > 0) {
      await new Promise((resolve) => setTimeout(resolve, waitTime));
      return { recovered: true, strategy: "wait-for-reset" };
    }
    return { recovered: false };
  },

  authTokenRecovery: async (error: MakeComAPIError) => {
    if (error.statusCode === 401) {
      const newToken = await refreshMakeComToken();
      if (newToken) {
        return { recovered: true, strategy: "token-refresh", data: newToken };
      }
    }
    return { recovered: false };
  },
};
```

### Development Workflow Integration

#### 6.5 Make.com Development Workflow

```typescript
// Development workflow configuration for Make.com tools
export const makeComWorkflow = {
  development: {
    apiBaseUrl: "https://eu1.make.com/api/v2",
    rateLimits: {
      enabled: false, // Disable for development
    },
    caching: {
      enabled: false, // Fresh data for development
    },
    logging: {
      level: "debug",
      includeRequestBodies: true,
      includeResponseBodies: true,
    },
    validation: {
      strictMode: true,
      validateResponses: true,
    },
  },

  production: {
    apiBaseUrl: "https://eu1.make.com/api/v2",
    rateLimits: {
      enabled: true,
      requestsPerMinute: 60,
      burstLimit: 10,
    },
    caching: {
      enabled: true,
      defaultTTL: 300, // 5 minutes
      patterns: {
        "agent:*": 600, // 10 minutes for agent data
        "team:*": 1800, // 30 minutes for team data
        "template:*": 3600, // 1 hour for templates
      },
    },
    logging: {
      level: "info",
      includeRequestBodies: false,
      includeResponseBodies: false,
      sanitizeSecrets: true,
    },
    validation: {
      strictMode: true,
      validateResponses: false, // Performance optimization
    },
  },
};
```

## Conclusion

This research provides comprehensive patterns and best practices for building FastMCP TypeScript tools, specifically tailored for Make.com integration. The key findings emphasize:

1. **Architectural Clarity**: Use single-responsibility tools organized by functional domains
2. **Type Safety**: Leverage TypeScript's strict mode with comprehensive interfaces
3. **Robust Error Handling**: Implement multi-layer error recovery with specific Make.com considerations
4. **Performance Optimization**: Use multi-layer caching, connection pooling, and concurrent request handling
5. **Development Support**: Provide comprehensive logging, testing, and debugging capabilities

These patterns enable the creation of enterprise-grade MCP tools that are maintainable, scalable, and production-ready for Make.com integration scenarios.

## Research Sources

- FastMCP TypeScript Framework Documentation
- Microsoft MCP Best Practices Guide
- TypeScript Best Practices 2025
- API Rate Limiting Patterns 2025
- Modern JavaScript/TypeScript Async Patterns
- Existing Make.com FastMCP Implementation Research

**Research Completed:** August 25, 2025
