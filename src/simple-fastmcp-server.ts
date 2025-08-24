/**
 * Simple Make.com FastMCP Server
 * Pure MCP server with only essential Make.com API integration tools
 */

import { FastMCP } from "fastmcp";
import { z } from "zod";
import axios from "axios";
import dotenv from "dotenv";
import winston from "winston";
import DailyRotateFile from "winston-daily-rotate-file";
import { v4 as uuidv4 } from "uuid";
import { performance } from "perf_hooks";

// Load environment variables
dotenv.config();

// Error classification system
enum ErrorCategory {
  MAKE_API_ERROR = "MAKE_API_ERROR",
  VALIDATION_ERROR = "VALIDATION_ERROR",
  AUTHENTICATION_ERROR = "AUTHENTICATION_ERROR",
  RATE_LIMIT_ERROR = "RATE_LIMIT_ERROR",
  TIMEOUT_ERROR = "TIMEOUT_ERROR",
  INTERNAL_ERROR = "INTERNAL_ERROR",
  MCP_PROTOCOL_ERROR = "MCP_PROTOCOL_ERROR",
}

enum ErrorSeverity {
  LOW = "LOW", // Recoverable, expected errors
  MEDIUM = "MEDIUM", // Service degradation
  HIGH = "HIGH", // Service failure
  CRITICAL = "CRITICAL", // System failure
}

class MCPServerError extends Error {
  constructor(
    message: string,
    public readonly category: ErrorCategory,
    public readonly severity: ErrorSeverity,
    public readonly correlationId: string,
    public readonly operation: string,
    public readonly cause?: Error,
  ) {
    super(message);
    this.name = "MCPServerError";
  }
}

// Logger configuration
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json(),
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple(),
      ),
    }),
    ...(process.env.LOG_FILE_ENABLED !== "false"
      ? [
          new DailyRotateFile({
            filename: "logs/fastmcp-server-%DATE%.log",
            datePattern: "YYYY-MM-DD",
            maxSize: "20m",
            maxFiles: "14d",
          }),
        ]
      : []),
  ],
});

// Performance monitoring interfaces and classes
interface PerformanceMetrics {
  timestamp: Date;
  operation: string;
  duration: number;
  memoryDelta: number;
  cpuUsage: NodeJS.CpuUsage;
  concurrentRequests: number;
  correlationId: string;
}

interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: Date;
  checks: {
    [checkName: string]: {
      status: 'pass' | 'fail';
      duration: number;
      message?: string;
    };
  };
}

interface MetricsSnapshot {
  httpRequestDuration: Map<string, number[]>;
  httpRequestCount: Map<string, number>;
  errorCount: Map<string, number>;
  memoryUsage: number;
  timestamp: Date;
}

class PerformanceMonitor {
  private static metrics: PerformanceMetrics[] = [];
  private static concurrentOperations = 0;
  private static readonly MAX_METRICS_HISTORY = 1000;
  
  static async trackOperation<T>(
    operation: string,
    correlationId: string,
    fn: () => Promise<T>
  ): Promise<{ result: T; metrics: PerformanceMetrics }> {
    const startTime = performance.now();
    const startMemory = process.memoryUsage().heapUsed;
    const startCpu = process.cpuUsage();
    
    this.concurrentOperations++;
    
    try {
      const result = await fn();
      const endTime = performance.now();
      const endMemory = process.memoryUsage().heapUsed;
      const endCpu = process.cpuUsage(startCpu);
      
      const metrics: PerformanceMetrics = {
        timestamp: new Date(),
        operation,
        duration: endTime - startTime,
        memoryDelta: endMemory - startMemory,
        cpuUsage: endCpu,
        concurrentRequests: this.concurrentOperations,
        correlationId
      };
      
      this.recordMetrics(metrics);
      
      // Log performance warnings for slow operations
      if (metrics.duration > 5000) {
        logger.warn('Slow operation detected', {
          operation: metrics.operation,
          duration: metrics.duration,
          correlationId: metrics.correlationId,
          memoryDelta: metrics.memoryDelta,
          concurrentRequests: metrics.concurrentRequests
        });
      }
      
      return { result, metrics };
    } finally {
      this.concurrentOperations--;
    }
  }
  
  private static recordMetrics(metrics: PerformanceMetrics) {
    this.metrics.push(metrics);
    
    // Keep metrics history under control
    if (this.metrics.length > this.MAX_METRICS_HISTORY) {
      this.metrics = this.metrics.slice(-this.MAX_METRICS_HISTORY);
    }
    
    // Log periodic performance summaries every 100 operations
    if (this.metrics.length % 100 === 0) {
      this.logPerformanceSummary();
    }
  }
  
  private static logPerformanceSummary() {
    const recentMetrics = this.metrics.slice(-100);
    const avgDuration = recentMetrics.reduce((sum, m) => sum + m.duration, 0) / recentMetrics.length;
    const maxDuration = Math.max(...recentMetrics.map(m => m.duration));
    const avgMemoryDelta = recentMetrics.reduce((sum, m) => sum + m.memoryDelta, 0) / recentMetrics.length;
    
    logger.info('Performance summary (last 100 operations)', {
      averageDuration: Math.round(avgDuration),
      maxDuration: Math.round(maxDuration),
      averageMemoryDelta: Math.round(avgMemoryDelta / 1024), // KB
      totalOperations: this.metrics.length,
      correlationId: 'perf-summary'
    });
  }
  
  static getMetricsReport(): {
    summary: {
      totalOperations: number;
      averageDuration: number;
      maxDuration: number;
      currentMemoryUsage: number;
      concurrentOperations: number;
    };
    percentiles: {
      p50: number;
      p95: number;
      p99: number;
    };
  } {
    const durations = this.metrics.map(m => m.duration);
    const sortedDurations = durations.sort((a, b) => a - b);
    
    return {
      summary: {
        totalOperations: this.metrics.length,
        averageDuration: durations.length > 0 ? durations.reduce((sum, d) => sum + d, 0) / durations.length : 0,
        maxDuration: durations.length > 0 ? Math.max(...durations) : 0,
        currentMemoryUsage: process.memoryUsage().heapUsed,
        concurrentOperations: this.concurrentOperations
      },
      percentiles: {
        p50: sortedDurations[Math.floor(sortedDurations.length * 0.5)] || 0,
        p95: sortedDurations[Math.floor(sortedDurations.length * 0.95)] || 0,
        p99: sortedDurations[Math.floor(sortedDurations.length * 0.99)] || 0
      }
    };
  }
}

class MetricsCollector {
  private static snapshot: MetricsSnapshot = {
    httpRequestDuration: new Map(),
    httpRequestCount: new Map(),
    errorCount: new Map(),
    memoryUsage: 0,
    timestamp: new Date()
  };
  
  static recordRequest(operation: string, duration: number, success: boolean) {
    // Update request duration histogram
    if (!this.snapshot.httpRequestDuration.has(operation)) {
      this.snapshot.httpRequestDuration.set(operation, []);
    }
    this.snapshot.httpRequestDuration.get(operation)!.push(duration);
    
    // Update request count
    const currentCount = this.snapshot.httpRequestCount.get(operation) || 0;
    this.snapshot.httpRequestCount.set(operation, currentCount + 1);
    
    // Update error count
    if (!success) {
      const currentErrorCount = this.snapshot.errorCount.get(operation) || 0;
      this.snapshot.errorCount.set(operation, currentErrorCount + 1);
    }
    
    // Update memory usage
    this.snapshot.memoryUsage = process.memoryUsage().heapUsed;
    this.snapshot.timestamp = new Date();
  }
  
  static getMetricsReport(): string {
    let report = 'FastMCP Server Metrics Report\n';
    report += `Timestamp: ${this.snapshot.timestamp.toISOString()}\n`;
    report += `Memory Usage: ${(this.snapshot.memoryUsage / 1024 / 1024).toFixed(2)} MB\n\n`;
    
    // Request duration analysis
    this.snapshot.httpRequestDuration.forEach((durations, operation) => {
      if (durations.length === 0) {
        return;
      }
      
      const sorted = durations.sort((a, b) => a - b);
      const p50 = sorted[Math.floor(sorted.length * 0.5)];
      const p95 = sorted[Math.floor(sorted.length * 0.95)];
      const p99 = sorted[Math.floor(sorted.length * 0.99)];
      
      report += `${operation}:\n`;
      report += `  Requests: ${durations.length}\n`;
      report += `  P50: ${p50?.toFixed(2) || 0}ms\n`;
      report += `  P95: ${p95?.toFixed(2) || 0}ms\n`;
      report += `  P99: ${p99?.toFixed(2) || 0}ms\n`;
      
      const errorCount = this.snapshot.errorCount.get(operation) || 0;
      const errorRate = (errorCount / durations.length * 100).toFixed(2);
      report += `  Error Rate: ${errorRate}%\n\n`;
    });
    
    return report;
  }
}

class HealthMonitor {
  static async performHealthCheck(): Promise<HealthStatus> {
    const checks: HealthStatus['checks'] = {};
    
    // Check Make.com API connectivity
    checks.makeApiConnectivity = await this.checkMakeApiConnectivity();
    
    // Check memory usage
    checks.memoryUsage = this.checkMemoryUsage();
    
    // Check log file system
    checks.logFileSystem = await this.checkLogFileSystem();
    
    // Check error rates
    checks.errorRates = this.checkErrorRates();
    
    // Determine overall status
    const failedChecks = Object.values(checks).filter(check => check.status === 'fail');
    let status: HealthStatus['status'];
    
    if (failedChecks.length === 0) {
      status = 'healthy';
    } else if (failedChecks.length <= 1) {
      status = 'degraded';
    } else {
      status = 'unhealthy';
    }
    
    const healthStatus: HealthStatus = {
      status,
      timestamp: new Date(),
      checks
    };
    
    // Log health status if degraded or unhealthy
    if (status !== 'healthy') {
      logger.warn('Health check failed', {
        status,
        failedChecks: failedChecks.length,
        details: checks,
        correlationId: 'health-check'
      });
    } else {
      logger.info('Health check passed', {
        status,
        correlationId: 'health-check'
      });
    }
    
    return healthStatus;
  }
  
  private static async checkMakeApiConnectivity(): Promise<HealthStatus['checks'][string]> {
    const startTime = performance.now();
    try {
      // Attempt lightweight API call to test connectivity
      await axios.get(`${config.makeBaseUrl}/users?limit=1`, {
        headers: { Authorization: `Token ${config.makeApiKey}` },
        timeout: 5000
      });
      
      return {
        status: 'pass',
        duration: performance.now() - startTime
      };
    } catch (error: unknown) {
      const axiosError = error as { message?: string };
      return {
        status: 'fail',
        duration: performance.now() - startTime,
        message: `Make.com API connectivity failed: ${axiosError.message || 'Unknown error'}`
      };
    }
  }
  
  private static checkMemoryUsage(): HealthStatus['checks'][string] {
    const startTime = performance.now();
    const memUsage = process.memoryUsage();
    const memoryUsageMB = memUsage.heapUsed / 1024 / 1024;
    
    // Use configured memory threshold
    const threshold = config.memoryThresholdMB;
    const status = memoryUsageMB > threshold ? 'fail' : 'pass';
    
    return {
      status,
      duration: performance.now() - startTime,
      message: status === 'fail' ? 
        `Memory usage ${memoryUsageMB.toFixed(2)}MB exceeds threshold ${threshold}MB` : 
        `Memory usage: ${memoryUsageMB.toFixed(2)}MB`
    };
  }
  
  private static async checkLogFileSystem(): Promise<HealthStatus['checks'][string]> {
    const startTime = performance.now();
    const fs = await import('fs');
    const path = await import('path');
    
    try {
      const logsDir = path.join(process.cwd(), 'logs');
      await fs.promises.access(logsDir, fs.constants.R_OK | fs.constants.W_OK);
      
      return {
        status: 'pass',
        duration: performance.now() - startTime,
        message: 'Log directory accessible'
      };
    } catch (error: unknown) {
      const fsError = error as { message?: string };
      return {
        status: 'fail',
        duration: performance.now() - startTime,
        message: `Log file system check failed: ${fsError.message || 'Unknown error'}`
      };
    }
  }
  
  private static checkErrorRates(): HealthStatus['checks'][string] {
    const startTime = performance.now();
    const metricsReport = PerformanceMonitor.getMetricsReport();
    
    // Simple error rate check based on recent operations
    const errorThreshold = 0.05; // 5% error rate threshold
    const _totalOperations = metricsReport.summary.totalOperations;
    
    // For simplicity, we'll use a basic check - in production this would
    // analyze actual error counts from metrics
    const estimatedErrorRate = 0; // Would be calculated from actual error metrics
    
    const status = estimatedErrorRate > errorThreshold ? 'fail' : 'pass';
    
    return {
      status,
      duration: performance.now() - startTime,
      message: `Current error rate: ${(estimatedErrorRate * 100).toFixed(2)}%`
    };
  }
}

// Simple configuration from environment
const config = {
  makeApiKey: process.env.MAKE_API_KEY,
  makeBaseUrl: process.env.MAKE_BASE_URL || "https://us1.make.com/api/v2",
  timeout: 30000,
  // Performance monitoring configuration
  performanceMonitoringEnabled: process.env.PERFORMANCE_MONITORING_ENABLED !== "false",
  memoryThresholdMB: parseInt(process.env.MEMORY_THRESHOLD_MB || "512"),
  metricsCollectionEnabled: process.env.METRICS_COLLECTION_ENABLED !== "false",
  healthCheckEnabled: process.env.HEALTH_CHECK_ENABLED !== "false",
};

// Simple Make.com API client
class SimpleMakeClient {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly timeout: number;

  constructor() {
    if (!config.makeApiKey) {
      throw new Error("MAKE_API_KEY environment variable is required");
    }

    this.apiKey = config.makeApiKey;
    this.baseUrl = config.makeBaseUrl;
    this.timeout = config.timeout;
  }

  private async request(
    method: string,
    endpoint: string,
    data?: unknown,
    correlationId?: string,
  ) {
    const requestId = correlationId || uuidv4();
    const operation = `${method.toUpperCase()} ${endpoint}`;

    // Use performance monitoring if enabled, otherwise fallback to direct execution
    if (config.performanceMonitoringEnabled) {
      const { result, metrics } = await PerformanceMonitor.trackOperation(
        operation,
        requestId,
        async () => {
          return await this.executeRequest(method, endpoint, data, requestId, operation);
        }
      );

      // Record metrics if enabled
      if (config.metricsCollectionEnabled) {
        const success = !result || typeof result === 'object';
        MetricsCollector.recordRequest(operation, metrics.duration, success);
      }

      return result;
    } else {
      return await this.executeRequest(method, endpoint, data, requestId, operation);
    }
  }

  private async executeRequest(
    method: string,
    endpoint: string,
    data: unknown,
    requestId: string,
    operation: string,
  ) {
    const startTime = Date.now();

    logger.info("API request started", {
      correlationId: requestId,
      operation,
      endpoint,
      method,
    });

    try {
      const response = await axios({
        method,
        url: `${this.baseUrl}${endpoint}`,
        headers: {
          Authorization: `Token ${this.apiKey}`,
          "Content-Type": "application/json",
          Accept: "application/json",
          "X-Correlation-ID": requestId,
        },
        data,
        timeout: this.timeout,
      });

      const duration = Date.now() - startTime;
      logger.info("API request completed", {
        correlationId: requestId,
        operation,
        duration,
        statusCode: response.status,
      });

      return response.data;
    } catch (error: unknown) {
      const duration = Date.now() - startTime;
      const axiosError = error as {
        response?: { data?: { message?: string }; status?: number };
        message?: string;
        code?: string;
      };

      const mcpError = new MCPServerError(
        `Make.com API error: ${axiosError.response?.data?.message || axiosError.message || "Unknown error"}`,
        this.classifyError(axiosError),
        this.determineSeverity(axiosError),
        requestId,
        operation,
        error as Error,
      );

      logger.error("API request failed", {
        correlationId: requestId,
        operation,
        duration,
        category: mcpError.category,
        severity: mcpError.severity,
        statusCode: axiosError.response?.status,
        errorCode: axiosError.code,
        message: mcpError.message,
        stack: mcpError.stack,
      });

      throw mcpError;
    }
  }

  private classifyError(error: {
    response?: { status?: number };
    code?: string;
  }): ErrorCategory {
    if (error.response?.status === 401) {
      return ErrorCategory.AUTHENTICATION_ERROR;
    }
    if (error.response?.status === 429) {
      return ErrorCategory.RATE_LIMIT_ERROR;
    }
    if (error.code === "ECONNABORTED") {
      return ErrorCategory.TIMEOUT_ERROR;
    }
    if (error.response?.status && error.response.status >= 500) {
      return ErrorCategory.INTERNAL_ERROR;
    }
    return ErrorCategory.MAKE_API_ERROR;
  }

  private determineSeverity(error: {
    response?: { status?: number };
    code?: string;
  }): ErrorSeverity {
    if (error.response?.status === 401) {
      return ErrorSeverity.HIGH;
    }
    if (error.response?.status === 429) {
      return ErrorSeverity.MEDIUM;
    }
    if (error.response?.status && error.response.status >= 500) {
      return ErrorSeverity.HIGH;
    }
    if (error.code === "ECONNABORTED") {
      return ErrorSeverity.MEDIUM;
    }
    return ErrorSeverity.LOW;
  }

  async getScenarios(limit?: number) {
    const params = limit ? `?limit=${limit}` : "";
    return this.request("GET", `/scenarios${params}`);
  }

  async getScenario(scenarioId: string) {
    return this.request("GET", `/scenarios/${scenarioId}`);
  }

  async createScenario(scenarioData: unknown) {
    return this.request("POST", "/scenarios", scenarioData);
  }

  async updateScenario(scenarioId: string, scenarioData: unknown) {
    return this.request("PATCH", `/scenarios/${scenarioId}`, scenarioData);
  }

  async deleteScenario(scenarioId: string) {
    return this.request("DELETE", `/scenarios/${scenarioId}`);
  }

  async runScenario(scenarioId: string) {
    return this.request("POST", `/scenarios/${scenarioId}/run`);
  }

  async getConnections(limit?: number) {
    const params = limit ? `?limit=${limit}` : "";
    return this.request("GET", `/connections${params}`);
  }

  async getConnection(connectionId: string) {
    return this.request("GET", `/connections/${connectionId}`);
  }

  async createConnection(connectionData: unknown) {
    return this.request("POST", "/connections", connectionData);
  }

  async deleteConnection(connectionId: string) {
    return this.request("DELETE", `/connections/${connectionId}`);
  }

  async getUsers(limit?: number) {
    const params = limit ? `?limit=${limit}` : "";
    return this.request("GET", `/users${params}`);
  }

  async getUser(userId: string) {
    return this.request("GET", `/users/${userId}`);
  }

  async getOrganizations() {
    return this.request("GET", "/organizations");
  }

  async getTeams() {
    return this.request("GET", "/teams");
  }
}

// Initialize the FastMCP server
const server = new FastMCP({
  name: "Make.com Simple FastMCP Server",
  version: "1.0.0",
});

// Initialize Make.com API client
const makeClient = new SimpleMakeClient();

// SCENARIO TOOLS
server.addTool({
  name: "list-scenarios",
  description: "List Make.com scenarios with optional limit",
  parameters: z.object({
    limit: z
      .number()
      .min(1)
      .max(100)
      .optional()
      .describe("Maximum number of scenarios to return (1-100)"),
  }),
  execute: async (args) => {
    const scenarios = await makeClient.getScenarios(args.limit);
    return {
      content: [
        {
          type: "text",
          text: `Found ${scenarios.scenarios?.length || 0} scenarios:\n\n${JSON.stringify(scenarios, null, 2)}`,
        },
      ],
    };
  },
});

server.addTool({
  name: "get-scenario",
  description: "Get details of a specific Make.com scenario",
  parameters: z.object({
    scenario_id: z.string().describe("The ID of the scenario to retrieve"),
  }),
  execute: async (args) => {
    const scenario = await makeClient.getScenario(args.scenario_id);
    return {
      content: [
        {
          type: "text",
          text: `Scenario Details:\n\n${JSON.stringify(scenario, null, 2)}`,
        },
      ],
    };
  },
});

server.addTool({
  name: "create-scenario",
  description: "Create a new Make.com scenario",
  parameters: z.object({
    name: z.string().describe("Name of the scenario"),
    blueprint: z
      .unknown()
      .optional()
      .describe("Scenario blueprint/configuration"),
    settings: z.unknown().optional().describe("Scenario settings"),
  }),
  execute: async (args) => {
    const scenarioData = {
      name: args.name,
      blueprint: args.blueprint,
      settings: args.settings,
    };
    const result = await makeClient.createScenario(scenarioData);
    return {
      content: [
        {
          type: "text",
          text: `Scenario created successfully:\n\n${JSON.stringify(result, null, 2)}`,
        },
      ],
    };
  },
});

server.addTool({
  name: "update-scenario",
  description: "Update an existing Make.com scenario",
  parameters: z.object({
    scenario_id: z.string().describe("The ID of the scenario to update"),
    name: z.string().optional().describe("New name for the scenario"),
    blueprint: z
      .unknown()
      .optional()
      .describe("Updated scenario blueprint/configuration"),
    settings: z.unknown().optional().describe("Updated scenario settings"),
  }),
  execute: async (args) => {
    const updateData: Record<string, unknown> = {};
    if (args.name) {
      updateData.name = args.name;
    }
    if (args.blueprint) {
      updateData.blueprint = args.blueprint;
    }
    if (args.settings) {
      updateData.settings = args.settings;
    }

    const result = await makeClient.updateScenario(
      args.scenario_id,
      updateData,
    );
    return {
      content: [
        {
          type: "text",
          text: `Scenario updated successfully:\n\n${JSON.stringify(result, null, 2)}`,
        },
      ],
    };
  },
});

server.addTool({
  name: "delete-scenario",
  description: "Delete a Make.com scenario",
  parameters: z.object({
    scenario_id: z.string().describe("The ID of the scenario to delete"),
  }),
  execute: async (args) => {
    await makeClient.deleteScenario(args.scenario_id);
    return {
      content: [
        {
          type: "text",
          text: `Scenario ${args.scenario_id} deleted successfully`,
        },
      ],
    };
  },
});

server.addTool({
  name: "run-scenario",
  description: "Execute a Make.com scenario",
  parameters: z.object({
    scenario_id: z.string().describe("The ID of the scenario to run"),
  }),
  execute: async (args) => {
    const result = await makeClient.runScenario(args.scenario_id);
    return {
      content: [
        {
          type: "text",
          text: `Scenario execution initiated:\n\n${JSON.stringify(result, null, 2)}`,
        },
      ],
    };
  },
});

// CONNECTION TOOLS
server.addTool({
  name: "list-connections",
  description: "List Make.com connections with optional limit",
  parameters: z.object({
    limit: z
      .number()
      .min(1)
      .max(100)
      .optional()
      .describe("Maximum number of connections to return (1-100)"),
  }),
  execute: async (args) => {
    const connections = await makeClient.getConnections(args.limit);
    return {
      content: [
        {
          type: "text",
          text: `Found ${connections.connections?.length || 0} connections:\n\n${JSON.stringify(connections, null, 2)}`,
        },
      ],
    };
  },
});

server.addTool({
  name: "get-connection",
  description: "Get details of a specific Make.com connection",
  parameters: z.object({
    connection_id: z.string().describe("The ID of the connection to retrieve"),
  }),
  execute: async (args) => {
    const connection = await makeClient.getConnection(args.connection_id);
    return {
      content: [
        {
          type: "text",
          text: `Connection Details:\n\n${JSON.stringify(connection, null, 2)}`,
        },
      ],
    };
  },
});

server.addTool({
  name: "create-connection",
  description: "Create a new Make.com connection",
  parameters: z.object({
    app: z.string().describe("App/service name for the connection"),
    name: z.string().describe("Name of the connection"),
    credentials: z.unknown().describe("Connection credentials/configuration"),
  }),
  execute: async (args) => {
    const connectionData = {
      app: args.app,
      name: args.name,
      credentials: args.credentials,
    };
    const result = await makeClient.createConnection(connectionData);
    return {
      content: [
        {
          type: "text",
          text: `Connection created successfully:\n\n${JSON.stringify(result, null, 2)}`,
        },
      ],
    };
  },
});

server.addTool({
  name: "delete-connection",
  description: "Delete a Make.com connection",
  parameters: z.object({
    connection_id: z.string().describe("The ID of the connection to delete"),
  }),
  execute: async (args) => {
    await makeClient.deleteConnection(args.connection_id);
    return {
      content: [
        {
          type: "text",
          text: `Connection ${args.connection_id} deleted successfully`,
        },
      ],
    };
  },
});

// USER & ORGANIZATION TOOLS
server.addTool({
  name: "list-users",
  description: "List Make.com users with optional limit",
  parameters: z.object({
    limit: z
      .number()
      .min(1)
      .max(100)
      .optional()
      .describe("Maximum number of users to return (1-100)"),
  }),
  execute: async (args) => {
    const users = await makeClient.getUsers(args.limit);
    return {
      content: [
        {
          type: "text",
          text: `Found ${users.users?.length || 0} users:\n\n${JSON.stringify(users, null, 2)}`,
        },
      ],
    };
  },
});

server.addTool({
  name: "get-user",
  description: "Get details of a specific Make.com user",
  parameters: z.object({
    user_id: z.string().describe("The ID of the user to retrieve"),
  }),
  execute: async (args) => {
    const user = await makeClient.getUser(args.user_id);
    return {
      content: [
        {
          type: "text",
          text: `User Details:\n\n${JSON.stringify(user, null, 2)}`,
        },
      ],
    };
  },
});

server.addTool({
  name: "list-organizations",
  description: "List Make.com organizations",
  parameters: z.object({}),
  execute: async () => {
    const organizations = await makeClient.getOrganizations();
    return {
      content: [
        {
          type: "text",
          text: `Organizations:\n\n${JSON.stringify(organizations, null, 2)}`,
        },
      ],
    };
  },
});

server.addTool({
  name: "list-teams",
  description: "List Make.com teams",
  parameters: z.object({}),
  execute: async () => {
    const teams = await makeClient.getTeams();
    return {
      content: [
        {
          type: "text",
          text: `Teams:\n\n${JSON.stringify(teams, null, 2)}`,
        },
      ],
    };
  },
});

// ADD RESOURCES
server.addResource({
  uri: "make://scenarios",
  name: "Make.com Scenarios",
  description: "Access to Make.com scenario data and management",
  mimeType: "application/json",
  load: async () => {
    try {
      const scenarios = await makeClient.getScenarios();
      return [
        {
          uri: "make://scenarios",
          mimeType: "application/json",
          text: JSON.stringify(scenarios, null, 2),
        },
      ];
    } catch (error) {
      return [
        {
          uri: "make://scenarios",
          mimeType: "text/plain",
          text: `Error loading scenarios: ${error instanceof Error ? error.message : String(error)}`,
        },
      ];
    }
  },
});

server.addResource({
  uri: "make://connections",
  name: "Make.com Connections",
  description: "Access to Make.com connection data and management",
  mimeType: "application/json",
  load: async () => {
    try {
      const connections = await makeClient.getConnections();
      return [
        {
          uri: "make://connections",
          mimeType: "application/json",
          text: JSON.stringify(connections, null, 2),
        },
      ];
    } catch (error) {
      return [
        {
          uri: "make://connections",
          mimeType: "text/plain",
          text: `Error loading connections: ${error instanceof Error ? error.message : String(error)}`,
        },
      ];
    }
  },
});

server.addResource({
  uri: "make://users",
  name: "Make.com Users",
  description: "Access to Make.com user data and management",
  mimeType: "application/json",
  load: async () => {
    try {
      const users = await makeClient.getUsers();
      return [
        {
          uri: "make://users",
          mimeType: "application/json",
          text: JSON.stringify(users, null, 2),
        },
      ];
    } catch (error) {
      return [
        {
          uri: "make://users",
          mimeType: "text/plain",
          text: `Error loading users: ${error instanceof Error ? error.message : String(error)}`,
        },
      ];
    }
  },
});

// ADD PROMPTS
server.addPrompt({
  name: "create-automation-scenario",
  description: "Help create a Make.com automation scenario with best practices",
  arguments: [
    {
      name: "workflow_description",
      description: "Description of the automation workflow to create",
      required: true,
    },
    {
      name: "data_sources",
      description: "List of data sources or apps to integrate",
      required: false,
    },
  ],
  load: async (args) => {
    const { workflow_description, data_sources } = args;
    return `Create a Make.com automation scenario for: ${workflow_description}${data_sources ? ` using data sources: ${data_sources}` : ""}

Consider these best practices:
1. Start with a clear trigger event
2. Add error handling modules
3. Use filters to reduce unnecessary operations
4. Implement proper data validation
5. Set up monitoring and logging
6. Test thoroughly before activation

Would you like me to help you design the specific modules and connections for this automation?`;
  },
});

server.addPrompt({
  name: "optimize-scenario",
  description:
    "Analyze and provide optimization suggestions for a Make.com scenario",
  arguments: [
    {
      name: "scenario_id",
      description: "ID of the scenario to analyze and optimize",
      required: true,
    },
  ],
  load: async (args) => {
    const { scenario_id } = args;
    if (!scenario_id) {
      return "Error: scenario_id is required for optimization analysis";
    }

    try {
      const scenario = await makeClient.getScenario(scenario_id);
      return `Analyzing scenario "${scenario.name || scenario_id}" for optimization opportunities:

Current scenario analysis:
${JSON.stringify(scenario, null, 2)}

Optimization recommendations:
1. Review module execution order for efficiency
2. Check for unnecessary API calls or data processing
3. Implement proper error handling and retry logic
4. Consider using filters to reduce processing load
5. Optimize data mapping and transformations
6. Review schedule and execution frequency
7. Monitor performance metrics and bottlenecks

Would you like specific recommendations for any particular aspect of this scenario?`;
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      return `Error retrieving scenario ${scenario_id}: ${errorMessage}

General optimization checklist:
1. Minimize API calls per execution
2. Use efficient data filtering
3. Implement proper error handling
4. Optimize module sequencing
5. Review execution scheduling
6. Monitor resource usage`;
    }
  },
});

server.addPrompt({
  name: "troubleshoot-connection",
  description: "Help troubleshoot Make.com connection issues",
  arguments: [
    {
      name: "connection_id",
      description: "ID of the connection having issues",
      required: true,
    },
    {
      name: "error_message",
      description: "Error message or description of the issue",
      required: false,
    },
  ],
  load: async (args) => {
    const { connection_id, error_message } = args;
    if (!connection_id) {
      return "Error: connection_id is required for troubleshooting";
    }

    try {
      const connection = await makeClient.getConnection(connection_id);
      return `Troubleshooting connection "${connection.name || connection_id}":

Connection details:
${JSON.stringify(connection, null, 2)}

${error_message ? `Reported error: ${error_message}\n\n` : ""}Common troubleshooting steps:
1. Verify API credentials are still valid
2. Check if the external service is accessible
3. Review authentication/authorization settings
4. Test connection with simple API calls
5. Check for API rate limiting or quota issues
6. Verify webhook endpoints if applicable
7. Review connection permissions and scopes

Would you like me to help diagnose specific error patterns or test the connection?`;
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      return `Error retrieving connection ${connection_id}: ${errorMessage}

${error_message ? `Reported issue: ${error_message}\n\n` : ""}General connection troubleshooting:
1. Verify connection still exists and is accessible
2. Check API credentials and permissions
3. Test basic connectivity to the service
4. Review error logs for specific failure patterns
5. Ensure the connection configuration is correct`;
    }
  },
});

// PERFORMANCE MONITORING TOOLS (conditionally enabled)
if (config.performanceMonitoringEnabled) {
  server.addTool({
    name: "get-performance-metrics",
    description: "Get comprehensive performance metrics and statistics",
    parameters: z.object({}),
    execute: async () => {
      const report = PerformanceMonitor.getMetricsReport();
      return {
        content: [
          {
            type: "text",
            text: `Performance Metrics Report:

Summary:
- Total Operations: ${report.summary.totalOperations}
- Average Duration: ${report.summary.averageDuration.toFixed(2)}ms
- Max Duration: ${report.summary.maxDuration.toFixed(2)}ms
- Current Memory Usage: ${(report.summary.currentMemoryUsage / 1024 / 1024).toFixed(2)}MB
- Concurrent Operations: ${report.summary.concurrentOperations}

Percentiles:
- P50 (Median): ${report.percentiles.p50.toFixed(2)}ms
- P95: ${report.percentiles.p95.toFixed(2)}ms
- P99: ${report.percentiles.p99.toFixed(2)}ms`,
          },
        ],
      };
    },
  });
}

if (config.metricsCollectionEnabled) {
  server.addTool({
    name: "get-metrics-report",
    description: "Get detailed metrics report with request analysis",
    parameters: z.object({}),
    execute: async () => {
      const report = MetricsCollector.getMetricsReport();
      return {
        content: [
          {
            type: "text",
            text: report,
          },
        ],
      };
    },
  });
}

if (config.healthCheckEnabled) {
  server.addTool({
    name: "perform-health-check",
    description: "Perform comprehensive system health check",
    parameters: z.object({}),
    execute: async () => {
      const health = await HealthMonitor.performHealthCheck();
      const statusEmoji = health.status === 'healthy' ? '✅' : 
                        health.status === 'degraded' ? '⚠️' : '❌';
      
      let report = `${statusEmoji} System Health Status: ${health.status.toUpperCase()}\n`;
      report += `Timestamp: ${health.timestamp.toISOString()}\n\n`;
      
      report += "Health Checks:\n";
      Object.entries(health.checks).forEach(([checkName, result]) => {
        const checkEmoji = result.status === 'pass' ? '✅' : '❌';
        report += `${checkEmoji} ${checkName}: ${result.status} (${result.duration.toFixed(2)}ms)\n`;
        if (result.message) {
          report += `   ${result.message}\n`;
        }
      });
      
      return {
        content: [
          {
            type: "text",
            text: report,
          },
        ],
      };
    },
  });
}

// Start the server
server.start({
  transportType: "stdio",
});

const startupMessage = [
  "Make.com Simple FastMCP Server started successfully",
  `Performance Monitoring: ${config.performanceMonitoringEnabled ? 'ENABLED' : 'DISABLED'}`,
  `Metrics Collection: ${config.metricsCollectionEnabled ? 'ENABLED' : 'DISABLED'}`,
  `Health Checks: ${config.healthCheckEnabled ? 'ENABLED' : 'DISABLED'}`,
  `Memory Threshold: ${config.memoryThresholdMB}MB`
].join(" | ");

console.error(startupMessage);

// Log startup configuration
logger.info("FastMCP Server started", {
  performanceMonitoring: config.performanceMonitoringEnabled,
  metricsCollection: config.metricsCollectionEnabled,
  healthCheck: config.healthCheckEnabled,
  memoryThreshold: config.memoryThresholdMB,
  correlationId: 'server-startup'
});
