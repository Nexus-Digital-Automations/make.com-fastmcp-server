#!/usr/bin/env node

/**
 * Direct test of our server with proper ES module syntax
 */

import MakeServerInstance from "./dist/server.js";

console.error("🔬 DEBUG: Starting direct server test...");

async function testServer() {
  try {
    console.error("DEBUG: Creating MakeServerInstance...");
    const serverInstance = new MakeServerInstance();

    console.error("DEBUG: MakeServerInstance created successfully");
    console.error(
      "DEBUG: FastMCP server type:",
      serverInstance.server.constructor.name,
    );

    console.error("DEBUG: About to start server with stdio transport...");

    // Start the server
    await serverInstance.start({ transportType: "stdio" });

    console.error(
      "DEBUG: Server start() completed - server should be listening",
    );
    console.error("DEBUG: Waiting for JSON-RPC messages on stdin...");

    // The server is now running and should be handling JSON-RPC via stdio
    // At this point, any JSON-RPC messages sent to stdin should produce responses on stdout
  } catch (error) {
    console.error("❌ Error starting server:", error.message);
    console.error("Stack:", error.stack);
    process.exit(1);
  }
}

testServer();
