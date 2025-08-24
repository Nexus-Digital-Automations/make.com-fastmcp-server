#!/usr/bin/env node

/**
 * Debug script to investigate if logger or other components are interfering with stdout
 */

console.log(
  "🔬 DEBUG: Investigating stdout interference in MakeServerInstance...",
);

// First, let's check what happens when we create a MakeServerInstance without starting it
console.log("\n=== Step 1: Creating MakeServerInstance (no start) ===");

try {
  const { default: MakeServerInstance } = await import("./dist/server.js");
  console.log("✅ MakeServerInstance imported successfully");

  const serverInstance = new MakeServerInstance();
  console.log("✅ MakeServerInstance created successfully");

  // Check if the server instance has the FastMCP server
  const fastmcpServer = serverInstance.server;
  console.log(
    "✅ FastMCP server instance accessed:",
    fastmcpServer.constructor.name,
  );

  console.log("\n=== Step 2: Checking stdout/stderr streams ===");
  console.log("process.stdout.isTTY:", process.stdout.isTTY);
  console.log("process.stderr.isTTY:", process.stderr.isTTY);
  console.log("process.stdin.isTTY:", process.stdin.isTTY);

  console.log("\n=== Step 3: Testing basic stdout output ===");
  process.stdout.write("TEST: Direct stdout.write\n");
  console.log("TEST: Console.log output");

  console.log("\n=== Step 4: Checking if logger is interfering ===");
  const logger = serverInstance.componentLogger;
  logger.info("Test logger message");

  console.log("\n=== Step 5: Checking FastMCP server directly ===");

  // Try starting just the FastMCP server from our instance
  console.log("🚀 Starting FastMCP server directly from instance...");

  // Create a simple test without external stdio interference
  const testMessage =
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0.0"}}}';

  console.log("📨 Test message ready:", testMessage);

  // Don't actually start the server in this test - just verify the setup
  console.log("✅ Investigation completed - server instance is ready");
} catch (error) {
  console.log("❌ Error during investigation:", error.message);
  console.log("Stack:", error.stack);
}

console.log("\n=== Step 6: Checking what FastMCP server expects ===");

// Test the FastMCP server in the most minimal way
try {
  console.log("📋 Creating minimal FastMCP server for comparison...");

  const { FastMCP } = await import("fastmcp");
  const minimalServer = new FastMCP({
    name: "Debug Test",
    version: "1.0.0",
  });

  console.log("✅ Minimal FastMCP server created");
  console.log(
    "Server methods available:",
    Object.getOwnPropertyNames(minimalServer.constructor.prototype),
  );
} catch (error) {
  console.log("❌ Error creating minimal FastMCP:", error.message);
}

process.exit(0);
