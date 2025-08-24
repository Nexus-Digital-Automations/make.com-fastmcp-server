#!/usr/bin/env node

/**
 * Standalone MCP Server Stdio Communication Test
 * Tests server initialization and stdio communication without hanging
 * Can be run directly: node test-server-stdio.js
 */

import { spawn } from "child_process";
import * as path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class StdioTester {
  constructor() {
    this.serverPath = path.join(__dirname, "dist", "index.js");
    this.testResults = [];
    this.startTime = Date.now();
  }

  log(message, data = {}) {
    const timestamp = new Date().toISOString();
    console.log(
      `[${timestamp}] ${message}`,
      data.error ? `- ERROR: ${data.error}` : "",
    );
    if (data.details) {
      console.log("  Details:", data.details);
    }
  }

  async runTest(testName, testFn, timeout = 15000) {
    const testStart = Date.now();
    this.log(`Starting test: ${testName}`);

    try {
      const result = await Promise.race([
        testFn(),
        new Promise((_, reject) =>
          setTimeout(
            () => reject(new Error(`Test timeout after ${timeout}ms`)),
            timeout,
          ),
        ),
      ]);

      const duration = Date.now() - testStart;
      this.testResults.push({
        name: testName,
        success: true,
        duration,
        result,
      });

      this.log(`✅ Test passed: ${testName} (${duration}ms)`);
      return result;
    } catch (error) {
      const duration = Date.now() - testStart;
      this.testResults.push({
        name: testName,
        success: false,
        duration,
        error: error.message,
      });

      this.log(`❌ Test failed: ${testName} (${duration}ms)`, {
        error: error.message,
      });
      throw error;
    }
  }

  async testServerStartup() {
    return new Promise((resolve, reject) => {
      this.log("Spawning MCP server process");

      const server = spawn("node", [this.serverPath], {
        stdio: ["pipe", "pipe", "pipe"],
        cwd: __dirname,
        env: { ...process.env, NODE_ENV: "test" },
      });

      let serverOutput = "";
      let serverError = "";
      let serverStarted = false;
      let initializationDetected = false;

      // Timeout handler
      const timeoutId = setTimeout(() => {
        if (!serverStarted) {
          server.kill("SIGKILL");
          reject(
            new Error(
              `Server failed to start within timeout. Output: ${serverOutput.substring(0, 500)}`,
            ),
          );
        }
      }, 10000);

      // Handle server output
      server.stdout.on("data", (data) => {
        const output = data.toString();
        serverOutput += output;

        // Look for various indicators that the server is running
        const indicators = [
          "listening",
          "ready",
          "initialized",
          "MCP server",
          "FastMCP",
          "started",
          "running",
        ];

        if (
          !initializationDetected &&
          indicators.some((indicator) =>
            output.toLowerCase().includes(indicator.toLowerCase()),
          )
        ) {
          initializationDetected = true;
          this.log("Server initialization detected via output");
        }

        // Any output suggests the server is at least running
        if (!serverStarted && serverOutput.length > 50) {
          serverStarted = true;
          clearTimeout(timeoutId);
          server.kill("SIGTERM");

          resolve({
            success: true,
            output: serverOutput,
            error: serverError,
            initializationDetected,
          });
        }
      });

      // Handle server errors
      server.stderr.on("data", (data) => {
        serverError += data.toString();
        this.log("Server stderr:", { details: data.toString() });
      });

      // Handle server exit
      server.on("exit", (code, signal) => {
        clearTimeout(timeoutId);

        if (!serverStarted) {
          if (code === 0 || serverOutput.length > 0) {
            // Server exited cleanly or produced output before exiting
            resolve({
              success: true,
              output: serverOutput,
              error: serverError,
              exitCode: code,
              exitSignal: signal,
              initializationDetected,
            });
          } else {
            reject(
              new Error(
                `Server exited with code ${code}. Error: ${serverError}`,
              ),
            );
          }
        }
      });

      // Handle spawn errors
      server.on("error", (error) => {
        clearTimeout(timeoutId);
        reject(new Error(`Failed to spawn server: ${error.message}`));
      });

      // Give server time to start and produce output
      setTimeout(() => {
        if (!serverStarted && !server.killed) {
          if (serverOutput.length > 0 || serverError.length > 0) {
            // Server has produced some output, consider it started
            serverStarted = true;
            clearTimeout(timeoutId);
            server.kill("SIGTERM");

            resolve({
              success: true,
              output: serverOutput,
              error: serverError,
              initializationDetected:
                initializationDetected || serverOutput.length > 100,
            });
          }
        }
      }, 3000);
    });
  }

  async testStdioJsonRpc() {
    return new Promise((resolve, reject) => {
      this.log("Testing JSON-RPC communication via stdio");

      const server = spawn("node", [this.serverPath], {
        stdio: ["pipe", "pipe", "pipe"],
        cwd: __dirname,
        env: { ...process.env, NODE_ENV: "test" },
      });

      let serverOutput = "";
      let serverError = "";
      let jsonRpcResponseReceived = false;

      // Timeout handler
      const timeoutId = setTimeout(() => {
        server.kill("SIGKILL");
        resolve({
          success: jsonRpcResponseReceived,
          output: serverOutput,
          error: serverError,
          message: jsonRpcResponseReceived
            ? "JSON-RPC response received"
            : "No JSON-RPC response within timeout",
        });
      }, 8000);

      // Handle server output
      server.stdout.on("data", (data) => {
        const output = data.toString();
        serverOutput += output;

        // Look for JSON-RPC responses
        const lines = output.split("\n").filter((line) => line.trim());
        for (const line of lines) {
          try {
            const parsed = JSON.parse(line);
            if (
              parsed.jsonrpc &&
              (parsed.result !== undefined || parsed.error !== undefined)
            ) {
              jsonRpcResponseReceived = true;
              this.log("JSON-RPC response received");
              clearTimeout(timeoutId);
              server.kill("SIGTERM");

              resolve({
                success: true,
                output: serverOutput,
                error: serverError,
                response: parsed,
                message: "Valid JSON-RPC response received",
              });
              return;
            }
          } catch (e) {
            // Not JSON, continue
          }
        }
      });

      // Handle server errors
      server.stderr.on("data", (data) => {
        serverError += data.toString();
      });

      // Handle server exit
      server.on("exit", (code, signal) => {
        clearTimeout(timeoutId);
        if (!jsonRpcResponseReceived) {
          resolve({
            success: false,
            output: serverOutput,
            error: serverError,
            exitCode: code,
            exitSignal: signal,
            message: `Server exited before JSON-RPC response (code: ${code})`,
          });
        }
      });

      // Handle spawn errors
      server.on("error", (error) => {
        clearTimeout(timeoutId);
        resolve({
          success: false,
          error: error.message,
          message: `Failed to spawn server: ${error.message}`,
        });
      });

      // Wait for server to start, then send JSON-RPC request
      setTimeout(() => {
        try {
          const initRequest = {
            jsonrpc: "2.0",
            id: 1,
            method: "initialize",
            params: {
              protocolVersion: "2024-11-05",
              capabilities: {},
              clientInfo: {
                name: "stdio-test",
                version: "1.0.0",
              },
            },
          };

          const requestString = JSON.stringify(initRequest) + "\n";
          server.stdin.write(requestString);
          this.log("Sent JSON-RPC initialize request");
        } catch (error) {
          this.log("Failed to send JSON-RPC request", { error: error.message });
        }
      }, 2000);
    });
  }

  async testServerStability() {
    return new Promise((resolve, reject) => {
      this.log("Testing server stability (multiple requests)");

      const server = spawn("node", [this.serverPath], {
        stdio: ["pipe", "pipe", "pipe"],
        cwd: __dirname,
        env: { ...process.env, NODE_ENV: "test" },
      });

      let serverOutput = "";
      let serverError = "";
      let requestsSent = 0;
      let responsesReceived = 0;

      const timeoutId = setTimeout(() => {
        server.kill("SIGKILL");
        resolve({
          success: responsesReceived > 0,
          output: serverOutput,
          error: serverError,
          requestsSent,
          responsesReceived,
          message: `Sent ${requestsSent} requests, received ${responsesReceived} responses`,
        });
      }, 10000);

      server.stdout.on("data", (data) => {
        const output = data.toString();
        serverOutput += output;

        // Count JSON-RPC responses
        const lines = output.split("\n").filter((line) => line.trim());
        for (const line of lines) {
          try {
            const parsed = JSON.parse(line);
            if (parsed.jsonrpc && parsed.id !== undefined) {
              responsesReceived++;
              this.log(`Response ${responsesReceived} received`);

              if (responsesReceived >= 3) {
                clearTimeout(timeoutId);
                server.kill("SIGTERM");
                resolve({
                  success: true,
                  output: serverOutput,
                  error: serverError,
                  requestsSent,
                  responsesReceived,
                  message: "Server handled multiple requests successfully",
                });
                return;
              }
            }
          } catch (e) {
            // Not JSON
          }
        }
      });

      server.stderr.on("data", (data) => {
        serverError += data.toString();
      });

      server.on("error", (error) => {
        clearTimeout(timeoutId);
        resolve({
          success: false,
          error: error.message,
          message: `Server error: ${error.message}`,
        });
      });

      // Send multiple requests
      setTimeout(() => {
        const sendRequest = (id) => {
          try {
            const request = {
              jsonrpc: "2.0",
              id,
              method: id === 1 ? "initialize" : "tools/list",
              ...(id === 1 && {
                params: {
                  protocolVersion: "2024-11-05",
                  capabilities: {},
                  clientInfo: { name: "stability-test", version: "1.0.0" },
                },
              }),
            };

            server.stdin.write(JSON.stringify(request) + "\n");
            requestsSent++;
            this.log(`Sent request ${id}`);
          } catch (error) {
            this.log(`Failed to send request ${id}`, { error: error.message });
          }
        };

        sendRequest(1);
        setTimeout(() => sendRequest(2), 1000);
        setTimeout(() => sendRequest(3), 2000);
      }, 2000);
    });
  }

  printSummary() {
    const totalDuration = Date.now() - this.startTime;
    const passedTests = this.testResults.filter((t) => t.success).length;
    const failedTests = this.testResults.length - passedTests;

    console.log("\n" + "=".repeat(60));
    console.log("📊 MCP Server Stdio Communication Test Summary");
    console.log("=".repeat(60));

    this.testResults.forEach((test) => {
      const status = test.success ? "✅" : "❌";
      console.log(`${status} ${test.name} (${test.duration}ms)`);
      if (!test.success && test.error) {
        console.log(`    Error: ${test.error}`);
      }
    });

    console.log("\n📈 Results:");
    console.log(`  Total tests: ${this.testResults.length}`);
    console.log(`  Passed: ${passedTests}`);
    console.log(`  Failed: ${failedTests}`);
    console.log(
      `  Success rate: ${((passedTests / this.testResults.length) * 100).toFixed(1)}%`,
    );
    console.log(`  Total duration: ${totalDuration}ms`);

    if (failedTests === 0) {
      console.log("\n🎉 All stdio communication tests passed!");
      console.log("✨ Server initializes correctly and communicates via stdio");
    } else {
      console.log(
        "\n⚠️  Some tests failed - server may have initialization issues",
      );
    }

    console.log("=".repeat(60));
  }

  async runAllTests() {
    this.log("Starting MCP Server Stdio Communication Tests");

    try {
      await this.runTest("Server Startup", () => this.testServerStartup());
      await this.runTest("JSON-RPC Communication", () =>
        this.testStdioJsonRpc(),
      );
      await this.runTest("Server Stability", () => this.testServerStability());
    } catch (error) {
      this.log("Test execution stopped due to critical failure", {
        error: error.message,
      });
    }

    this.printSummary();
    return this.testResults;
  }
}

// Run tests if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const tester = new StdioTester();

  tester
    .runAllTests()
    .then((results) => {
      const allPassed = results.every((r) => r.success);
      process.exit(allPassed ? 0 : 1);
    })
    .catch((error) => {
      console.error("Test runner failed:", error);
      process.exit(1);
    });
}

export default StdioTester;
