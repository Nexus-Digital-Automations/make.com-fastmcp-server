/**
 * Minimal MCP server to test JSON parsing issues
 */

import { FastMCP } from "fastmcp";
import { z } from "zod";

console.log("🧪 Creating minimal MCP server for testing...");

const server = new FastMCP({
  name: "Minimal Test Server",
  version: "1.0.0",
  instructions: "Minimal server to debug JSON issues",
});

// Add only essential tools to isolate the issue
server.addTool({
  name: "simple-test",
  description: "Simple test tool with safe response",
  parameters: z.object({}),
  execute: async () => {
    // Return simple content array format (safest)
    return {
      content: [
        {
          type: "text",
          text: "Simple test response",
        },
      ],
    };
  },
});

server.addTool({
  name: "json-array-test",
  description: "Test JSON array handling",
  parameters: z.object({}),
  execute: async () => {
    // Test if returning arrays directly causes issues
    const testData = {
      simpleArray: ["item1", "item2", "item3"],
      objectArray: [
        { id: 1, name: "test1" },
        { id: 2, name: "test2" },
      ],
    };

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(testData, null, 2),
        },
      ],
    };
  },
});

// Start server
async function startMinimalServer() {
  try {
    console.log("🚀 Starting minimal MCP server...");
    await server.start({
      transportType: "stdio",
    });
    console.log("✅ Minimal server started successfully");
  } catch (error) {
    console.error("❌ Minimal server failed:", error);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  startMinimalServer().catch(console.error);
}
