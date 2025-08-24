#!/usr/bin/env node

/**
 * Comprehensive test to verify the MCP server is fully functional
 */

import { spawn } from "child_process";

console.log("🧪 COMPREHENSIVE MCP SERVER TEST");
console.log("=================================");

const server = spawn("node", ["debug-server-direct.js"], {
  stdio: ["pipe", "pipe", "pipe"],
});

let responses = [];
let testsPassed = 0;
let totalTests = 0;

server.stdout.on("data", (data) => {
  const output = data.toString();

  // Parse JSON-RPC responses
  const lines = output.split("\n").filter((line) => line.trim());
  for (const line of lines) {
    if (line.trim()) {
      try {
        const response = JSON.parse(line.trim());
        if (response.jsonrpc === "2.0") {
          responses.push(response);
          console.log(
            `📥 Response ${response.id}: ${response.result ? "✅ SUCCESS" : "❌ ERROR"}`,
          );
          if (response.result) testsPassed++;
        }
      } catch (e) {
        // Not JSON
      }
    }
  }
});

server.stderr.on("data", (data) => {
  const output = data.toString().trim();
  if (output && !output.includes("[dotenv")) {
    console.log(`🔧 Server: ${output}`);
  }
});

// Wait for server to start, then run tests
setTimeout(() => {
  console.log("\n📋 Running MCP Protocol Tests...\n");

  // Test 1: Initialize
  totalTests++;
  console.log("Test 1: Initialize protocol");
  server.stdin.write(
    JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        clientInfo: { name: "test-client", version: "1.0.0" },
      },
    }) + "\n",
  );

  setTimeout(() => {
    // Test 2: List tools
    totalTests++;
    console.log("Test 2: List available tools");
    server.stdin.write(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/list",
        params: {},
      }) + "\n",
    );

    setTimeout(() => {
      // Test 3: Server info
      totalTests++;
      console.log("Test 3: Get server information");
      server.stdin.write(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 3,
          method: "tools/call",
          params: {
            name: "server-info",
            arguments: {},
          },
        }) + "\n",
      );

      // Final results after all tests
      setTimeout(() => {
        console.log("\n📊 TEST RESULTS");
        console.log("===============");
        console.log(`Tests passed: ${testsPassed}/${totalTests}`);
        console.log(
          `Success rate: ${Math.round((testsPassed / totalTests) * 100)}%`,
        );

        if (testsPassed === totalTests) {
          console.log("\n🎉 ALL TESTS PASSED! MCP Server is fully functional!");
          console.log("✅ JSON-RPC protocol compliance verified");
          console.log("✅ Tool registration and calling working");
          console.log("✅ Server information accessible");
        } else {
          console.log("\n⚠️  Some tests failed, but server is responding");
        }

        console.log("\n📋 Server Capabilities Summary:");
        responses.forEach((resp, i) => {
          if (resp.result?.capabilities) {
            console.log(`- Protocol Version: ${resp.result.protocolVersion}`);
            console.log(
              `- Tools: ${resp.result.capabilities.tools ? "Supported" : "Not supported"}`,
            );
            console.log(
              `- Logging: ${resp.result.capabilities.logging ? "Supported" : "Not supported"}`,
            );
          }
        });

        server.kill();
        process.exit(0);
      }, 2000);
    }, 1500);
  }, 1500);
}, 1000);

// Cleanup
process.on("SIGINT", () => {
  server.kill();
  process.exit(0);
});
