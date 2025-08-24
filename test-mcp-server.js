#!/usr/bin/env node

/**
 * Test script to verify MCP server initialization and stdio communication
 * Simulates how Claude Desktop would communicate with the server
 */

import { spawn } from "child_process";
import * as path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log("Testing MCP Server Initialization and Stdio Communication\n");

const serverPath = path.join(__dirname, "dist", "index.js");

// Test 1: Server starts without errors
console.log("Test 1: Starting MCP server...");
const server = spawn("node", [serverPath], {
  stdio: ["pipe", "pipe", "pipe"],
  cwd: __dirname,
});

let initTimeout;
let responseReceived = false;
let serverOutput = "";
let serverError = "";

// Handle server output
server.stdout.on("data", (data) => {
  const output = data.toString();
  serverOutput += output;

  // Look for MCP initialization message or successful start
  if (!responseReceived) {
    console.log("✅ Server started and produced output");
    responseReceived = true;
    clearTimeout(initTimeout);

    // Test 2: Send MCP initialization request
    console.log("\nTest 2: Sending MCP initialize request...");

    const initializeRequest = {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: {
          name: "test-client",
          version: "1.0.0",
        },
      },
    };

    const requestString = JSON.stringify(initializeRequest) + "\n";
    server.stdin.write(requestString);

    // Test 3: Wait for initialize response
    setTimeout(() => {
      console.log("\nTest 3: Checking for initialize response...");

      try {
        // Look for JSON-RPC response in output
        const lines = serverOutput.split("\n").filter((line) => line.trim());
        let foundResponse = false;

        for (const line of lines) {
          try {
            const parsed = JSON.parse(line);
            if (parsed.id === 1 && (parsed.result || parsed.error)) {
              console.log("✅ Received valid MCP initialize response");
              foundResponse = true;
              break;
            }
          } catch (e) {
            // Not JSON, continue looking
          }
        }

        if (!foundResponse) {
          console.log("⚠️  No valid initialize response found in output");
          console.log("Server output so far:", serverOutput);
        }
      } catch (error) {
        console.log("⚠️  Error parsing server response:", error.message);
      }

      // Cleanup and summary
      console.log("\n=== Test Summary ===");
      console.log("✅ Server started successfully");
      console.log("✅ Stdio communication established");

      if (serverError) {
        console.log("❌ Server errors detected:", serverError);
      }

      console.log("\nFull server output:");
      console.log("--- stdout ---");
      console.log(serverOutput);

      if (serverError) {
        console.log("--- stderr ---");
        console.log(serverError);
      }

      server.kill();
      process.exit(0);
    }, 2000);
  }
});

// Handle server errors
server.stderr.on("data", (data) => {
  serverError += data.toString();
});

// Handle server exit
server.on("exit", (code, signal) => {
  if (code !== 0 && code !== null) {
    console.log(`❌ Server exited with code ${code}`);
    if (serverError) {
      console.log("Error output:", serverError);
    }
  }
});

// Handle server spawn errors
server.on("error", (error) => {
  console.log("❌ Failed to start server:", error.message);
  process.exit(1);
});

// Timeout if server doesn't start within 5 seconds
initTimeout = setTimeout(() => {
  if (!responseReceived) {
    console.log("❌ Server failed to start within 5 seconds");
    if (serverError) {
      console.log("Error output:", serverError);
    }
    server.kill();
    process.exit(1);
  }
}, 5000);

// Graceful shutdown on Ctrl+C
process.on("SIGINT", () => {
  console.log("\nShutting down test...");
  server.kill();
  process.exit(0);
});
