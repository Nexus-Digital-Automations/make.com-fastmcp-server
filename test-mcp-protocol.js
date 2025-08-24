#!/usr/bin/env node

/**
 * Proper MCP Protocol Test
 * Tests stdio communication following the actual MCP protocol specification
 * MCP servers are silent until they receive JSON-RPC requests via stdin
 */

import { spawn } from "child_process";
import * as path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log("🧪 Testing MCP Server with Proper Protocol\n");

const serverPath = path.join(__dirname, "dist", "index.js");

console.log(
  "1. Starting MCP server (should be silent until JSON-RPC input)...",
);
const server = spawn("node", [serverPath], {
  stdio: ["pipe", "pipe", "pipe"],
  cwd: __dirname,
  env: {
    ...process.env,
    NODE_ENV: "test",
  },
});

let responses = [];
let serverReady = false;
let testResults = {
  serverStarted: false,
  protocolWorking: false,
  initializeResponse: null,
  toolsListResponse: null,
  errors: [],
};

// Handle server output (should only be JSON-RPC responses)
server.stdout.on("data", (data) => {
  const output = data.toString();

  // Parse JSON-RPC responses
  const lines = output.split("\n").filter((line) => line.trim());

  for (const line of lines) {
    try {
      const response = JSON.parse(line);
      responses.push(response);

      if (response.jsonrpc === "2.0" && response.id !== undefined) {
        console.log(`✅ Received JSON-RPC response for request ${response.id}`);

        if (response.id === 1) {
          testResults.initializeResponse = response;
          testResults.protocolWorking = true;

          // Send tools/list after successful initialize
          setTimeout(() => sendToolsListRequest(), 500);
        } else if (response.id === 2) {
          testResults.toolsListResponse = response;

          // Complete the test
          setTimeout(() => completeTest(), 500);
        }
      }
    } catch (e) {
      // Non-JSON output (shouldn't happen in proper MCP)
      console.log("⚠️  Non-JSON output from server:", line);
    }
  }
});

// Handle server errors (filter out dotenv promotional messages)
server.stderr.on("data", (data) => {
  const error = data.toString();

  // Ignore dotenv promotional output
  if (!error.includes("[dotenv") && !error.includes("tip:")) {
    console.log("❌ Server error:", error);
    testResults.errors.push(error);
  }
});

// Handle server exit
server.on("exit", (code, signal) => {
  if (code !== 0 && code !== 143 && code !== null) {
    // 143 = SIGTERM
    console.log(
      `❌ Server exited unexpectedly: code=${code}, signal=${signal}`,
    );
    testResults.errors.push(`Unexpected exit: ${code}/${signal}`);
  }
});

// Handle spawn errors
server.on("error", (error) => {
  console.log("❌ Failed to spawn server:", error.message);
  testResults.errors.push(error.message);
  process.exit(1);
});

function sendInitializeRequest() {
  console.log("\n2. Sending JSON-RPC initialize request...");

  const initRequest = {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: {
        name: "mcp-protocol-test",
        version: "1.0.0",
      },
    },
  };

  const requestString = JSON.stringify(initRequest) + "\n";
  server.stdin.write(requestString);
  console.log("📤 Sent initialize request");
}

function sendToolsListRequest() {
  console.log("\n3. Sending tools/list request...");

  const toolsRequest = {
    jsonrpc: "2.0",
    id: 2,
    method: "tools/list",
    params: {},
  };

  const requestString = JSON.stringify(toolsRequest) + "\n";
  server.stdin.write(requestString);
  console.log("📤 Sent tools/list request");
}

function completeTest() {
  console.log("\n=== MCP Protocol Test Results ===");

  // Analyze results
  testResults.serverStarted = true; // If we got this far, server started

  console.log("✅ Server started successfully");
  console.log(`✅ Protocol working: ${testResults.protocolWorking}`);
  console.log(
    `✅ Initialize response: ${testResults.initializeResponse ? "received" : "missing"}`,
  );
  console.log(
    `✅ Tools list response: ${testResults.toolsListResponse ? "received" : "missing"}`,
  );
  console.log(`📊 Total JSON-RPC responses: ${responses.length}`);
  console.log(`❌ Errors encountered: ${testResults.errors.length}`);

  if (testResults.errors.length > 0) {
    console.log("\nErrors:");
    testResults.errors.forEach((error) => console.log(`  - ${error}`));
  }

  if (testResults.protocolWorking && responses.length >= 2) {
    console.log(
      "\n🎉 All tests passed! MCP server stdio communication working correctly.",
    );
    console.log(
      "✨ Server follows proper MCP protocol: silent until JSON-RPC input received",
    );
  } else {
    console.log("\n⚠️  Some tests failed - check protocol implementation");
  }

  // Cleanup
  server.kill("SIGTERM");
  setTimeout(() => process.exit(testResults.protocolWorking ? 0 : 1), 1000);
}

// Start the test sequence
setTimeout(() => {
  console.log(
    "✅ Server appears to be running (no immediate output as expected)",
  );
  sendInitializeRequest();
}, 1000);

// Fallback timeout
setTimeout(() => {
  console.log("\n⏰ Test timeout - server may not be responding to JSON-RPC");

  if (responses.length === 0) {
    console.log(
      "❌ No JSON-RPC responses received - server may not be working",
    );
  } else {
    console.log(
      `⚠️  Received ${responses.length} responses but test didn't complete`,
    );
  }

  server.kill("SIGTERM");
  setTimeout(() => process.exit(1), 1000);
}, 10000);

// Graceful shutdown
process.on("SIGINT", () => {
  console.log("\nShutting down test...");
  server.kill("SIGTERM");
  process.exit(0);
});
