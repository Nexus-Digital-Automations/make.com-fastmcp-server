#!/usr/bin/env node

/**
 * Debug configuration loading to identify the exact issue
 */

// Simulate the server environment
process.env.NODE_ENV = "test";

// Manually load .env file since we're in test mode
import { config as loadEnv } from "dotenv";
loadEnv();

console.log("🔍 Debugging Configuration Loading\n");

console.log("Environment variables:");
console.log("MAKE_API_KEY:", process.env.MAKE_API_KEY);
console.log("NODE_ENV:", process.env.NODE_ENV);

try {
  // Import the config manager directly
  console.log("\n1. Testing config manager import...");
  const configModule = await import("./dist/lib/config.js");
  const configManager = configModule.default;

  console.log("✅ Config manager imported successfully");

  console.log("\n2. Testing config retrieval...");
  const configInstance = configManager(); // configManager is a function
  const makeConfig = configInstance.getMakeConfig();

  console.log("Make API Config:");
  console.log("  apiKey length:", makeConfig.apiKey.length);
  console.log(
    "  apiKey starts with test_key:",
    makeConfig.apiKey.includes("test_key"),
  );
  console.log("  baseUrl:", makeConfig.baseUrl);

  console.log("\n3. Testing server instance creation...");
  const serverModule = await import("./dist/server.js");
  const MakeServerInstance = serverModule.default;

  console.log("✅ Server class imported successfully");

  const server = new MakeServerInstance();
  console.log("✅ Server instance created successfully");

  console.log("\n4. Testing server start (this is where it likely hangs)...");

  // Set a timeout to catch if start() hangs
  const startTimeout = setTimeout(() => {
    console.log("❌ Server start() method is hanging");
    console.log("This confirms the issue is in the server.start() method");
    process.exit(1);
  }, 5000);

  try {
    await server.start();
    clearTimeout(startTimeout);
    console.log("✅ Server started successfully!");

    // Cleanup
    await server.shutdown();
    console.log("✅ Server shutdown completed");
  } catch (error) {
    clearTimeout(startTimeout);
    console.log("❌ Server start failed:", error.message);
    console.log("Full error:", error);
  }
} catch (error) {
  console.log("❌ Configuration or import error:", error.message);
  console.log("Full error:", error);
  process.exit(1);
}
