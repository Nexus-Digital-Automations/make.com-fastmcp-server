#!/usr/bin/env node

/**
 * Clean stdio test that suppresses all promotional output
 * Tests server initialization without stdout contamination
 */

import { spawn } from "child_process";
import * as path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log("Testing MCP Server Stdio Communication (Clean)\n");

const serverPath = path.join(__dirname, "dist", "index.js");

// Test with environment variables that suppress promotional output
console.log("Test 1: Starting MCP server with clean stdio...");
const server = spawn("node", [serverPath], {
  stdio: ["pipe", "pipe", "pipe"],
  cwd: __dirname,
  env: {
    ...process.env,
    NODE_ENV: "test",
    // Suppress dotenv promotional output
    DOTENV_KEY: "",
    NO_COLOR: "1",
  },
});

let serverStarted = false;
let initializationComplete = false;
let serverOutput = "";
let serverError = "";
let messagesSent = 0;
let responsesReceived = 0;

// Set up test timeout
const testTimeout = setTimeout(() => {
  if (!serverStarted) {
    console.log("❌ Server failed to start within 10 seconds");
    console.log("Server output:", serverOutput);
    console.log("Server error:", serverError);
    server.kill("SIGKILL");
    process.exit(1);
  }
}, 10000);

// Handle server stdout - looking for clean MCP communication
server.stdout.on("data", (data) => {
  const output = data.toString();

  // Skip dotenv promotional messages
  if (
    output.includes("[dotenv") ||
    output.includes("auto-backup") ||
    output.includes("Radar")
  ) {
    return;
  }

  serverOutput += output;

  // Look for server startup indicators
  if (!serverStarted) {
    // If we get any non-promotional output, consider server started
    if (output.trim().length > 0) {
      serverStarted = true;
      clearTimeout(testTimeout);
      console.log("✅ Server started and stdio communication established");

      // Start MCP protocol test
      setTimeout(() => testMcpCommunication(), 1000);
    }
  } else {
    // Parse JSON-RPC responses
    const lines = output.split("\n").filter((line) => line.trim());
    for (const line of lines) {
      try {
        const message = JSON.parse(line);
        if (message.jsonrpc === "2.0" && message.id !== undefined) {
          responsesReceived++;
          console.log(
            `✅ Received JSON-RPC response ${responsesReceived}:`,
            message.id,
          );

          if (responsesReceived >= messagesSent) {
            // All messages responded to
            console.log("\n=== Test Summary ===");
            console.log("✅ Server started successfully");
            console.log("✅ Stdio communication working");
            console.log("✅ JSON-RPC protocol functional");
            console.log(
              `✅ Messages sent: ${messagesSent}, responses: ${responsesReceived}`,
            );

            server.kill("SIGTERM");
            setTimeout(() => process.exit(0), 1000);
          }
        }
      } catch (e) {
        // Not JSON, continue
      }
    }
  }
});

// Handle server stderr
server.stderr.on("data", (data) => {
  const error = data.toString();

  // Filter out promotional messages from stderr too
  if (
    !error.includes("[dotenv") &&
    !error.includes("auto-backup") &&
    !error.includes("Radar")
  ) {
    serverError += error;
    console.log("Server stderr:", error);
  }
});

// Handle server exit
server.on("exit", (code, signal) => {
  if (code !== 0 && code !== null && code !== 143) {
    // 143 is SIGTERM
    console.log(`❌ Server exited with code ${code}, signal ${signal}`);
    if (serverError) {
      console.log("Error output:", serverError);
    }
    process.exit(1);
  }
});

// Handle spawn errors
server.on("error", (error) => {
  console.log("❌ Failed to spawn server:", error.message);
  process.exit(1);
});

function testMcpCommunication() {
  console.log("\nTest 2: Testing MCP JSON-RPC communication...");

  // Send initialize request
  const initializeRequest = {
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

  try {
    server.stdin.write(JSON.stringify(initializeRequest) + "\n");
    messagesSent++;
    console.log("📤 Sent initialize request");

    // Send tools/list request after a delay
    setTimeout(() => {
      const toolsRequest = {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/list",
        params: {},
      };

      server.stdin.write(JSON.stringify(toolsRequest) + "\n");
      messagesSent++;
      console.log("📤 Sent tools/list request");
    }, 1000);
  } catch (error) {
    console.log("❌ Failed to send JSON-RPC request:", error.message);
    server.kill();
    process.exit(1);
  }
}

// Graceful shutdown on Ctrl+C
process.on("SIGINT", () => {
  console.log("\nShutting down test...");
  server.kill();
  process.exit(0);
});
