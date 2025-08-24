#!/usr/bin/env node

/**
 * Minimal test to check what's happening during server startup
 */

// Let's test if we can import the server components without errors
console.log("Testing basic imports...");

try {
  console.log("1. Testing logger import...");
  const { default: logger } = await import("./dist/lib/logger.js");
  console.log("✅ Logger imported successfully");

  console.log("2. Testing logger functionality...");
  logger.info("Test log message");
  console.log("✅ Logger works");

  console.log("3. Testing config manager import...");
  const { default: configManager } = await import("./dist/lib/config.js");
  console.log("✅ Config manager imported successfully");

  console.log("4. Testing config manager functionality...");
  const config = configManager();
  console.log("✅ Config manager function works");

  console.log("5. Testing config access...");
  const configData = config.getConfig();
  console.log("✅ Config access works:", configData.name);

  console.log("6. Testing server import...");
  const { default: MakeServerInstance } = await import("./dist/server.js");
  console.log("✅ Server imported successfully");

  console.log("7. Testing server instantiation...");
  const serverInstance = new MakeServerInstance();
  console.log("✅ Server instance created");

  console.log(
    "\nAll basic components work! Issue might be in server.start() method.",
  );
} catch (error) {
  console.error("❌ Error during testing:", error);
  console.error("Stack:", error.stack);
}
