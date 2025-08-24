/**
 * Comprehensive MCP Server Stdio Communication Tests
 * Tests server initialization, stdio communication, and JSON-RPC message handling
 * Similar to how Claude Desktop would communicate with the MCP server
 */

import {
  describe,
  test,
  expect,
  beforeAll,
  afterAll,
} from "@jest/jest-globals";
import { spawn, ChildProcess } from "child_process";
import * as path from "path";
import { fileURLToPath } from "url";
import { EventEmitter } from "events";
import logger from "../../src/lib/logger.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

interface TestResult {
  success: boolean;
  message: string;
  output?: string;
  error?: string;
  duration?: number;
}

class MCPServerTester extends EventEmitter {
  private server: ChildProcess | null = null;
  private serverOutput: string = "";
  private serverError: string = "";
  private messageId = 0;
  private pendingRequests = new Map<
    number,
    { resolve: Function; reject: Function; timeout: NodeJS.Timeout }
  >();
  private initializationComplete = false;

  constructor(
    private serverPath: string,
    private timeout: number = 30000,
  ) {
    super();
  }

  async startServer(): Promise<TestResult> {
    const startTime = Date.now();

    return new Promise((resolve) => {
      logger.info("Starting MCP server for stdio testing", {
        serverPath: this.serverPath,
      });

      // Check if server file exists
      if (!this.serverPath) {
        resolve({
          success: false,
          message: "Server path not provided",
          duration: Date.now() - startTime,
        });
        return;
      }

      this.server = spawn("node", [this.serverPath], {
        stdio: ["pipe", "pipe", "pipe"],
        cwd: path.dirname(this.serverPath),
        env: { ...process.env, NODE_ENV: "test" },
      });

      let initializationTimer: NodeJS.Timeout;
      let serverStarted = false;

      // Handle server output
      this.server.stdout?.on("data", (data: Buffer) => {
        const output = data.toString();
        this.serverOutput += output;

        // Parse JSON-RPC messages
        this.parseJsonRpcMessages(output);

        // Check for server readiness indicators
        if (
          !serverStarted &&
          (output.includes("listening") ||
            output.includes("ready") ||
            output.includes("initialized"))
        ) {
          serverStarted = true;
          clearTimeout(initializationTimer);
          resolve({
            success: true,
            message: "Server started successfully",
            output: this.serverOutput,
            duration: Date.now() - startTime,
          });
        }
      });

      // Handle server errors
      this.server.stderr?.on("data", (data: Buffer) => {
        const error = data.toString();
        this.serverError += error;
        logger.warn("MCP Server error output", { error });
      });

      // Handle server exit
      this.server.on("exit", (code, signal) => {
        if (!serverStarted) {
          clearTimeout(initializationTimer);
          resolve({
            success: false,
            message: `Server exited prematurely with code ${code} and signal ${signal}`,
            output: this.serverOutput,
            error: this.serverError,
            duration: Date.now() - startTime,
          });
        }
      });

      // Handle spawn errors
      this.server.on("error", (error) => {
        clearTimeout(initializationTimer);
        resolve({
          success: false,
          message: `Failed to spawn server: ${error.message}`,
          error: error.message,
          duration: Date.now() - startTime,
        });
      });

      // Set initialization timeout
      initializationTimer = setTimeout(() => {
        if (!serverStarted) {
          resolve({
            success: false,
            message: `Server failed to initialize within ${this.timeout}ms`,
            output: this.serverOutput,
            error: this.serverError,
            duration: Date.now() - startTime,
          });
        }
      }, this.timeout);

      // Give the server a moment to start producing output
      setTimeout(() => {
        if (!serverStarted && this.serverOutput.length > 0) {
          // Server has output but no ready indicator, consider it started
          serverStarted = true;
          clearTimeout(initializationTimer);
          resolve({
            success: true,
            message: "Server started (detected via output)",
            output: this.serverOutput,
            duration: Date.now() - startTime,
          });
        }
      }, 2000);
    });
  }

  async sendJsonRpcRequest(method: string, params?: any): Promise<TestResult> {
    const startTime = Date.now();

    if (!this.server || !this.server.stdin) {
      return {
        success: false,
        message: "Server not started or stdin not available",
      };
    }

    const id = ++this.messageId;
    const request = {
      jsonrpc: "2.0",
      id,
      method,
      ...(params && { params }),
    };

    return new Promise((resolve) => {
      const timeout = setTimeout(() => {
        this.pendingRequests.delete(id);
        resolve({
          success: false,
          message: `Request timed out after 10 seconds`,
          duration: Date.now() - startTime,
        });
      }, 10000);

      this.pendingRequests.set(id, {
        resolve: (result: any) => {
          clearTimeout(timeout);
          this.pendingRequests.delete(id);
          resolve({
            success: true,
            message: "Request completed successfully",
            output: JSON.stringify(result, null, 2),
            duration: Date.now() - startTime,
          });
        },
        reject: (error: any) => {
          clearTimeout(timeout);
          this.pendingRequests.delete(id);
          resolve({
            success: false,
            message: `Request failed: ${error.message || "Unknown error"}`,
            error: JSON.stringify(error, null, 2),
            duration: Date.now() - startTime,
          });
        },
        timeout,
      });

      try {
        const requestString = JSON.stringify(request) + "\n";
        this.server!.stdin!.write(requestString);
        logger.info("Sent JSON-RPC request", { method, id });
      } catch (error) {
        clearTimeout(timeout);
        this.pendingRequests.delete(id);
        resolve({
          success: false,
          message: `Failed to send request: ${error instanceof Error ? error.message : "Unknown error"}`,
          duration: Date.now() - startTime,
        });
      }
    });
  }

  private parseJsonRpcMessages(output: string): void {
    const lines = output.split("\n").filter((line) => line.trim());

    for (const line of lines) {
      try {
        const message = JSON.parse(line);

        if (message.jsonrpc === "2.0" && message.id !== undefined) {
          const pendingRequest = this.pendingRequests.get(message.id);

          if (pendingRequest) {
            if (message.error) {
              pendingRequest.reject(message.error);
            } else {
              pendingRequest.resolve(message.result || message);
            }
          }
        }
      } catch (error) {
        // Not a JSON message, ignore
      }
    }
  }

  async initialize(): Promise<TestResult> {
    return this.sendJsonRpcRequest("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: {
        name: "test-client",
        version: "1.0.0",
      },
    });
  }

  async listTools(): Promise<TestResult> {
    return this.sendJsonRpcRequest("tools/list");
  }

  async callTool(name: string, args: any = {}): Promise<TestResult> {
    return this.sendJsonRpcRequest("tools/call", {
      name,
      arguments: args,
    });
  }

  async shutdown(): Promise<void> {
    // Clean up pending requests
    for (const [id, request] of this.pendingRequests.entries()) {
      clearTimeout(request.timeout);
      request.reject(new Error("Test cleanup - server shutdown"));
    }
    this.pendingRequests.clear();

    if (this.server) {
      // Try graceful shutdown first
      try {
        this.server.kill("SIGTERM");

        // Wait a moment for graceful shutdown
        await new Promise((resolve) => setTimeout(resolve, 1000));

        // Force kill if still running
        if (!this.server.killed) {
          this.server.kill("SIGKILL");
        }
      } catch (error) {
        logger.warn("Error during server shutdown", { error });
      }

      this.server = null;
    }
  }

  getServerOutput(): { stdout: string; stderr: string } {
    return {
      stdout: this.serverOutput,
      stderr: this.serverError,
    };
  }
}

describe("MCP Server Stdio Communication Tests", () => {
  let tester: MCPServerTester;
  const serverPath = path.resolve(__dirname, "../../dist/index.js");

  beforeAll(() => {
    logger.info("Starting MCP Server stdio communication test suite");
  });

  afterAll(() => {
    logger.info("Completed MCP Server stdio communication test suite");
  });

  describe("Server Initialization", () => {
    test("should start server without hanging", async () => {
      tester = new MCPServerTester(serverPath, 15000); // 15 second timeout

      const result = await tester.startServer();

      expect(result.success).toBe(true);
      expect(result.message).toContain("Server started");
      expect(result.duration).toBeLessThan(15000);

      logger.info("Server initialization test result", result);
    }, 20000);

    test("should respond to JSON-RPC initialize request", async () => {
      if (!tester) {
        tester = new MCPServerTester(serverPath);
        await tester.startServer();
      }

      const result = await tester.initialize();

      expect(result.success).toBe(true);
      expect(result.message).toContain("completed successfully");

      logger.info("Initialize request test result", result);
    }, 15000);

    test("should handle tools/list request", async () => {
      if (!tester) {
        tester = new MCPServerTester(serverPath);
        await tester.startServer();
        await tester.initialize();
      }

      const result = await tester.listTools();

      expect(result.success).toBe(true);

      logger.info("Tools list request test result", result);
    }, 15000);
  });

  describe("Stdio Communication", () => {
    test("should maintain stable stdio connection", async () => {
      if (!tester) {
        tester = new MCPServerTester(serverPath);
        await tester.startServer();
        await tester.initialize();
      }

      // Send multiple requests to test connection stability
      const requests = [];
      for (let i = 0; i < 3; i++) {
        requests.push(tester.listTools());
      }

      const results = await Promise.all(requests);

      for (const result of results) {
        expect(result.success).toBe(true);
      }

      logger.info("Multiple request test completed", {
        totalRequests: results.length,
        successCount: results.filter((r) => r.success).length,
      });
    }, 20000);

    test("should handle concurrent requests", async () => {
      if (!tester) {
        tester = new MCPServerTester(serverPath);
        await tester.startServer();
        await tester.initialize();
      }

      // Send concurrent initialize and tools/list requests
      const [initResult, toolsResult] = await Promise.all([
        tester.sendJsonRpcRequest("initialize", {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "concurrent-test", version: "1.0.0" },
        }),
        tester.listTools(),
      ]);

      expect(initResult.success || toolsResult.success).toBe(true);

      logger.info("Concurrent request test results", {
        initResult,
        toolsResult,
      });
    }, 15000);
  });

  describe("Error Handling", () => {
    test("should handle invalid JSON-RPC requests gracefully", async () => {
      if (!tester) {
        tester = new MCPServerTester(serverPath);
        await tester.startServer();
      }

      const result = await tester.sendJsonRpcRequest("invalid_method", {});

      // Should either succeed with error response or fail gracefully
      expect(result.success || result.message.includes("error")).toBe(true);

      logger.info("Invalid method test result", result);
    }, 15000);

    test("should maintain server stability after errors", async () => {
      if (!tester) {
        tester = new MCPServerTester(serverPath);
        await tester.startServer();
      }

      // Send invalid request
      await tester.sendJsonRpcRequest("invalid_method", {});

      // Server should still respond to valid requests
      const result = await tester.listTools();

      expect(result.success).toBe(true);

      logger.info("Server stability after error test result", result);
    }, 20000);
  });

  describe("Performance", () => {
    test("should respond to requests within reasonable time", async () => {
      if (!tester) {
        tester = new MCPServerTester(serverPath);
        await tester.startServer();
        await tester.initialize();
      }

      const result = await tester.listTools();

      expect(result.success).toBe(true);
      expect(result.duration).toBeLessThan(5000); // Should respond within 5 seconds

      logger.info("Response time test result", result);
    }, 10000);
  });

  // Cleanup after all tests
  afterAll(async () => {
    if (tester) {
      await tester.shutdown();

      const output = tester.getServerOutput();
      logger.info("Final server output", {
        stdoutLength: output.stdout.length,
        stderrLength: output.stderr.length,
      });
    }
  });
});

// Additional test for direct server testing without Jest framework
export async function runDirectStdioTest(): Promise<TestResult[]> {
  const results: TestResult[] = [];
  const serverPath = path.resolve(process.cwd(), "dist/index.js");

  logger.info("Running direct stdio test");

  const tester = new MCPServerTester(serverPath);

  try {
    // Test 1: Server startup
    const startupResult = await tester.startServer();
    results.push(startupResult);

    if (startupResult.success) {
      // Test 2: Initialize
      const initResult = await tester.initialize();
      results.push(initResult);

      // Test 3: List tools
      const toolsResult = await tester.listTools();
      results.push(toolsResult);
    }
  } catch (error) {
    results.push({
      success: false,
      message: `Direct test failed: ${error instanceof Error ? error.message : "Unknown error"}`,
    });
  } finally {
    await tester.shutdown();
  }

  return results;
}

export { MCPServerTester };
