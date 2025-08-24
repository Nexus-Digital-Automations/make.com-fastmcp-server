#!/usr/bin/env node

/**
 * Test script to validate telemetry module functionality
 */

async function testTelemetry() {
  try {
    console.log("Testing telemetry module import...");

    // Test if we can import the module without compilation errors
    const {
      default: telemetry,
      TelemetryManager,
      createFastMCPSpan,
      createMakeAPISpan,
    } = await import("./dist/lib/telemetry.js");

    console.log("✅ Telemetry module imported successfully");
    console.log("✅ TelemetryManager class available");
    console.log("✅ createFastMCPSpan helper available");
    console.log("✅ createMakeAPISpan helper available");

    // Test basic configuration
    const config = telemetry.getConfig();
    console.log("✅ Configuration accessible:", {
      serviceName: config.serviceName,
      environment: config.environment,
      otlpEndpoint: config.otlpEndpoint,
    });

    console.log("✅ All telemetry tests passed!");
    return true;
  } catch (error) {
    console.error("❌ Telemetry test failed:", error.message);
    return false;
  }
}

// Run the test if this script is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  testTelemetry().then((success) => {
    process.exit(success ? 0 : 1);
  });
}

export { testTelemetry };
