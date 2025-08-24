#!/usr/bin/env node

/**
 * Debug script to trace JSON-RPC flow in our MakeServerInstance
 */

import { spawn } from "child_process";

console.log("🔬 DEBUG: Tracing JSON-RPC flow...");

// Test our server with detailed logging
const serverProcess = spawn(
  "node",
  [
    "-e",
    `
// Import and start our server
import { default: MakeServerInstance } from './dist/server.js';

console.error('DEBUG: Creating MakeServerInstance...');
const serverInstance = new MakeServerInstance();

console.error('DEBUG: MakeServerInstance created');
console.error('DEBUG: FastMCP server type:', serverInstance.server.constructor.name);

console.error('DEBUG: Starting server with stdio transport...');
await serverInstance.start({ transportType: 'stdio' });

console.error('DEBUG: Server start() method completed');
console.error('DEBUG: Server should now be listening for JSON-RPC messages');

// Set up a timeout to show server is running
setTimeout(() => {
  console.error('DEBUG: Server has been running for 5 seconds');
}, 5000);
`,
  ],
  {
    stdio: ["pipe", "pipe", "pipe"],
    cwd: process.cwd(),
  },
);

let stdoutOutput = "";
let stderrOutput = "";
let gotResponse = false;

serverProcess.stdout.on("data", (data) => {
  const output = data.toString();
  stdoutOutput += output;
  console.log("📤 STDOUT:", JSON.stringify(output));

  // Check for JSON-RPC response
  try {
    const lines = output.split("\n").filter((line) => line.trim());
    for (const line of lines) {
      if (line.trim()) {
        const parsed = JSON.parse(line.trim());
        if (parsed.jsonrpc === "2.0" && parsed.id === 1) {
          console.log("✅ Got JSON-RPC response:", parsed);
          gotResponse = true;
        }
      }
    }
  } catch (e) {
    // Not JSON or not complete
  }
});

serverProcess.stderr.on("data", (data) => {
  const output = data.toString();
  stderrOutput += output;
  console.log("📤 STDERR:", output.trim());
});

serverProcess.on("error", (error) => {
  console.log("❌ Process error:", error);
});

// Wait for server to start, then send initialize
setTimeout(() => {
  console.log("\n📨 Sending initialize request...");

  const initRequest = {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "debug-test", version: "1.0.0" },
    },
  };

  const requestString = JSON.stringify(initRequest) + "\n";
  console.log("📨 Sending:", requestString.trim());

  serverProcess.stdin.write(requestString);

  // Wait for response
  setTimeout(() => {
    console.log(
      `\n📊 Result: ${gotResponse ? "✅ SUCCESS" : "❌ NO RESPONSE"}`,
    );
    console.log("Total stdout length:", stdoutOutput.length);
    console.log("Total stderr length:", stderrOutput.length);

    if (!gotResponse) {
      console.log("\n🔍 DIAGNOSIS:");
      console.log(
        "- Server started successfully (stderr shows startup messages)",
      );
      console.log("- No JSON-RPC response received on stdout");
      console.log(
        "- This indicates the FastMCP server is not processing or responding to messages",
      );
    }

    serverProcess.kill();
    process.exit(0);
  }, 3000);
}, 2000);

// Cleanup
process.on("SIGINT", () => {
  serverProcess.kill();
  process.exit(0);
});
