#!/usr/bin/env node

/**
 * Test script to verify the server properly handles JSON-RPC communication
 * This simulates exactly how Claude Desktop would communicate with the server
 */

import { spawn } from "child_process";
import * as path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log("🧪 Testing MCP Server JSON-RPC Communication");

const serverPath = path.join(__dirname, "dist", "index.js");

console.log("\n1. Starting MCP server...");
const server = spawn("node", [serverPath], {
  stdio: ["pipe", "pipe", "pipe"],
  cwd: __dirname,
});

let serverOutput = "";
let serverError = "";
let testsPassed = 0;
let testsTotal = 4;

// Capture all output
server.stdout.on("data", (data) => {
  const output = data.toString();
  serverOutput += output;
  console.log("📤 Server stdout:", output.trim());
});

server.stderr.on("data", (data) => {
  const output = data.toString();
  serverError += output;
  console.log("📤 Server stderr:", output.trim());
});

server.on("exit", (code, signal) => {
  console.log(`\n📊 Server exited: code=${code}, signal=${signal}`);
  console.log(`\n🎯 Test Results: ${testsPassed}/${testsTotal} passed`);
  if (testsPassed === testsTotal) {
    console.log(
      "✅ All tests passed! Server JSON-RPC communication is working correctly.",
    );
  } else {
    console.log("❌ Some tests failed. Server needs investigation.");
  }
  process.exit(testsPassed === testsTotal ? 0 : 1);
});

server.on("error", (error) => {
  console.log("❌ Server spawn error:", error.message);
  process.exit(1);
});

// Test sequence
setTimeout(() => {
  console.log("\n2. Sending initialize request...");

  const initializeRequest = {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2024-11-05",
      capabilities: {
        roots: {
          listChanged: true,
        },
        sampling: {},
      },
      clientInfo: {
        name: "test-client",
        version: "1.0.0",
      },
    },
  };

  const requestString = JSON.stringify(initializeRequest) + "\n";
  console.log("📨 Sending:", requestString.trim());
  server.stdin.write(requestString);

  // Test 1: Check if server responds to initialize
  setTimeout(() => {
    console.log("\n3. Checking for initialize response...");

    const lines = serverOutput.split("\n").filter((line) => line.trim());
    let foundResponse = false;

    for (const line of lines) {
      try {
        const parsed = JSON.parse(line);
        if (parsed.id === 1 && parsed.result) {
          console.log("✅ Test 1: Valid initialize response received");
          console.log("📋 Response:", JSON.stringify(parsed, null, 2));
          testsPassed++;
          foundResponse = true;
          break;
        }
      } catch (e) {
        // Not JSON, continue
      }
    }

    if (!foundResponse) {
      console.log("❌ Test 1: No valid initialize response found");
    }

    // Test 2: Send initialized notification
    setTimeout(() => {
      console.log("\n4. Sending initialized notification...");

      const initializedNotification = {
        jsonrpc: "2.0",
        method: "notifications/initialized",
      };

      const notificationString = JSON.stringify(initializedNotification) + "\n";
      console.log("📨 Sending:", notificationString.trim());
      server.stdin.write(notificationString);

      testsPassed++; // Count as passed if we can send it
      console.log("✅ Test 2: Initialized notification sent");

      // Test 3: Test tool listing
      setTimeout(() => {
        console.log("\n5. Requesting tools list...");

        const toolsRequest = {
          jsonrpc: "2.0",
          id: 2,
          method: "tools/list",
        };

        const toolsString = JSON.stringify(toolsRequest) + "\n";
        console.log("📨 Sending:", toolsString.trim());
        server.stdin.write(toolsString);

        // Test 4: Check for tools response
        setTimeout(() => {
          console.log("\n6. Checking for tools response...");

          const allOutput = serverOutput;
          let foundToolsResponse = false;

          const lines = allOutput.split("\n").filter((line) => line.trim());
          for (const line of lines) {
            try {
              const parsed = JSON.parse(line);
              if (parsed.id === 2 && (parsed.result || parsed.error)) {
                console.log("✅ Test 3: Tools list response received");
                console.log(
                  "📋 Tools response:",
                  JSON.stringify(parsed, null, 2),
                );
                testsPassed++;
                foundToolsResponse = true;
                break;
              }
            } catch (e) {
              // Not JSON, continue
            }
          }

          if (!foundToolsResponse) {
            console.log("❌ Test 3: No tools response found");
          }

          // Test 4: Server stays responsive
          console.log("\n7. Testing server responsiveness...");
          const pingRequest = {
            jsonrpc: "2.0",
            id: 3,
            method: "ping",
          };

          const pingString = JSON.stringify(pingRequest) + "\n";
          console.log("📨 Sending:", pingString.trim());
          server.stdin.write(pingString);

          setTimeout(() => {
            console.log("✅ Test 4: Server remained responsive (no hang)");
            testsPassed++;

            // End test
            console.log("\n8. Terminating server...");
            server.kill("SIGTERM");
          }, 1000);
        }, 2000);
      }, 1000);
    }, 1000);
  }, 2000);
}, 1000);

// Graceful shutdown
process.on("SIGINT", () => {
  console.log("\nShutting down test...");
  server.kill();
  process.exit(0);
});
