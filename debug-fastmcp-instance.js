#!/usr/bin/env node

/**
 * Debug script to test if our FastMCP server instance is working correctly
 */

console.log("🔍 DEBUG: Testing FastMCP server instance in isolation...");

try {
  // Import our server
  const { default: MakeServerInstance } = await import("./dist/server.js");

  console.log("✅ DEBUG: Server module imported successfully");

  // Create server instance
  const serverInstance = new MakeServerInstance();
  console.log("✅ DEBUG: Server instance created");

  // Access the FastMCP server directly
  const fastmcpServer = serverInstance.server;
  console.log(
    "✅ DEBUG: FastMCP server instance accessed:",
    fastmcpServer.constructor.name,
  );

  // Check if it has the necessary methods
  console.log(
    "🔍 DEBUG: FastMCP server methods:",
    Object.getOwnPropertyNames(fastmcpServer.constructor.prototype),
  );

  // Try to start just the FastMCP server
  console.log("🚀 DEBUG: Starting FastMCP server directly...");

  await fastmcpServer.start({
    transportType: "stdio",
  });

  console.log("✅ DEBUG: FastMCP server started directly");

  // Now test if it responds
  setTimeout(() => {
    console.log("⏰ DEBUG: FastMCP server has been running for 2 seconds");
    process.exit(0);
  }, 2000);
} catch (error) {
  console.log("❌ DEBUG: Error testing FastMCP instance:", error.message);
  console.log("Stack:", error.stack);
  process.exit(1);
}
