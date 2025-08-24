#!/usr/bin/env node

/**
 * Debug script to identify exactly where server initialization hangs
 */

import { performance } from "perf_hooks";

console.log("🔍 DEBUG: Starting server initialization analysis...");

// Track each step with timestamps
function debugStep(step, fn) {
  const start = performance.now();
  console.log(`🚀 DEBUG: Starting ${step}...`);

  try {
    const result = fn();
    const end = performance.now();
    console.log(`✅ DEBUG: ${step} completed in ${(end - start).toFixed(2)}ms`);
    return result;
  } catch (error) {
    const end = performance.now();
    console.log(
      `❌ DEBUG: ${step} failed after ${(end - start).toFixed(2)}ms:`,
      error.message,
    );
    throw error;
  }
}

async function debugAsyncStep(step, fn) {
  const start = performance.now();
  console.log(`🚀 DEBUG: Starting ${step}...`);

  try {
    const result = await fn();
    const end = performance.now();
    console.log(`✅ DEBUG: ${step} completed in ${(end - start).toFixed(2)}ms`);
    return result;
  } catch (error) {
    const end = performance.now();
    console.log(
      `❌ DEBUG: ${step} failed after ${(end - start).toFixed(2)}ms:`,
      error.message,
    );
    throw error;
  }
}

async function debugServerInitialization() {
  try {
    // Step 1: Basic imports
    console.log("\n=== STEP 1: BASIC IMPORTS ===");
    const logger = debugStep("logger import", () => {
      return import("./dist/lib/logger.js");
    });

    const configManager = debugStep("config manager import", () => {
      return import("./dist/lib/config.js");
    });

    console.log("\n=== STEP 2: IMPORT RESOLUTION ===");
    const loggerModule = await debugAsyncStep(
      "logger module resolution",
      () => logger,
    );
    const configModule = await debugAsyncStep(
      "config module resolution",
      () => configManager,
    );

    console.log("\n=== STEP 3: MODULE INITIALIZATION ===");
    const config = debugStep("config manager instantiation", () => {
      return configModule.default();
    });

    console.log("\n=== STEP 4: CONFIG ACCESS ===");
    const serverConfig = debugStep("config access", () => {
      return config.getConfig();
    });

    console.log(`📊 DEBUG: Config loaded: ${serverConfig.name}`);

    console.log("\n=== STEP 5: SERVER MODULE IMPORT ===");
    const serverModule = await debugAsyncStep("server module import", () => {
      return import("./dist/server.js");
    });

    console.log("\n=== STEP 6: SERVER INSTANTIATION ===");
    const serverInstance = debugStep("server instantiation", () => {
      return new serverModule.default();
    });

    console.log("✅ DEBUG: Server instance created successfully");

    console.log("\n=== STEP 7: SERVER START (CRITICAL POINT) ===");

    // This is where it likely hangs - let's add a timeout
    const startPromise = serverInstance.start({
      transportType: "stdio",
    });

    // Add timeout to detect hanging
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(
        () => reject(new Error("Server start timeout after 10 seconds")),
        10000,
      );
    });

    await debugAsyncStep("server start with timeout", () => {
      return Promise.race([startPromise, timeoutPromise]);
    });

    console.log("🎉 DEBUG: Server started successfully!");

    // Test basic functionality
    console.log("\n=== STEP 8: BASIC FUNCTIONALITY TEST ===");
    setTimeout(() => {
      console.log(
        "⏰ DEBUG: Server has been running for 2 seconds - appears functional",
      );
      process.exit(0);
    }, 2000);
  } catch (error) {
    console.log("\n💥 DEBUG: Server initialization failed:", error.message);
    console.log("Stack trace:", error.stack);
    process.exit(1);
  }
}

// Handle process signals
process.on("SIGINT", () => {
  console.log("\n🛑 DEBUG: Received SIGINT, shutting down...");
  process.exit(0);
});

process.on("SIGTERM", () => {
  console.log("\n🛑 DEBUG: Received SIGTERM, shutting down...");
  process.exit(0);
});

// Start debugging
debugServerInitialization().catch((error) => {
  console.log("\n💥 FATAL ERROR:", error);
  process.exit(1);
});
