#!/usr/bin/env node

/**
 * Minimal FastMCP test to see if the library works
 */

import { FastMCP } from "fastmcp";

console.log("Creating minimal FastMCP server...");

try {
  const server = new FastMCP({
    name: "test-server",
    version: "1.0.0",
  });

  console.log("✅ FastMCP server created");

  // Add a simple tool
  server.addTool(
    {
      name: "test_tool",
      description: "A test tool",
      schema: {
        type: "object",
        properties: {},
      },
    },
    async () => {
      return "Hello from test tool!";
    },
  );

  console.log("✅ Test tool added");

  // Start the server
  console.log("Starting server with stdio transport...");

  await server.start({
    transportType: "stdio",
  });

  console.log("✅ Server started successfully and listening on stdio");
} catch (error) {
  console.error("❌ Error:", error);
  console.error("Stack:", error.stack);
  process.exit(1);
}
