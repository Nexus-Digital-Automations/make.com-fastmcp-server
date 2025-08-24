#!/usr/bin/env node

/**
 * Test with the known-working minimal FastMCP server for comparison
 */

import { spawn } from "child_process";

console.log("🔬 Comparing with known-working minimal FastMCP server");

console.log("\n=== Testing our minimal FastMCP server ===");
const minimalServer = spawn("node", ["test-fastmcp.js"], {
  stdio: ["pipe", "pipe", "pipe"],
});

let minimalOutput = "";
let minimalResponded = false;

minimalServer.stdout.on("data", (data) => {
  const output = data.toString();
  minimalOutput += output;
  console.log("📤 Minimal server:", output.trim());

  // Check for JSON response
  try {
    const parsed = JSON.parse(output.trim());
    if (parsed.id === 1) {
      console.log("✅ Minimal server responded correctly!");
      minimalResponded = true;
    }
  } catch (e) {
    // Not JSON or not complete
  }
});

minimalServer.stderr.on("data", (data) => {
  console.log("📤 Minimal stderr:", data.toString().trim());
});

setTimeout(() => {
  console.log("\n📨 Sending initialize to minimal server...");
  const initRequest =
    JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "test", version: "1.0.0" },
      },
    }) + "\n";

  minimalServer.stdin.write(initRequest);

  setTimeout(() => {
    console.log(
      `\n📊 Minimal server test: ${minimalResponded ? "✅ SUCCESS" : "❌ FAILED"}`,
    );

    console.log("\n=== Now testing our main server ===");

    const mainServer = spawn("node", ["dist/index.js"], {
      stdio: ["pipe", "pipe", "pipe"],
    });

    let mainOutput = "";
    let mainResponded = false;

    mainServer.stdout.on("data", (data) => {
      const output = data.toString();
      mainOutput += output;
      console.log("📤 Main server:", output.trim());

      // Check for JSON response
      try {
        const parsed = JSON.parse(output.trim());
        if (parsed.id === 1) {
          console.log("✅ Main server responded correctly!");
          mainResponded = true;
        }
      } catch (e) {
        // Not JSON or not complete
      }
    });

    mainServer.stderr.on("data", (data) => {
      console.log("📤 Main stderr:", data.toString().trim());
    });

    setTimeout(() => {
      console.log("\n📨 Sending initialize to main server...");
      mainServer.stdin.write(initRequest);

      setTimeout(() => {
        console.log(
          `\n📊 Main server test: ${mainResponded ? "✅ SUCCESS" : "❌ FAILED"}`,
        );

        console.log("\n=== COMPARISON RESULTS ===");
        console.log(
          `Minimal server: ${minimalResponded ? "✅ Working" : "❌ Broken"}`,
        );
        console.log(
          `Main server: ${mainResponded ? "✅ Working" : "❌ Broken"}`,
        );

        if (minimalResponded && !mainResponded) {
          console.log(
            "\n🔍 DIAGNOSIS: Main server has issues with JSON-RPC processing",
          );
          console.log(
            "The server starts but doesn't output JSON-RPC responses properly",
          );
        } else if (!minimalResponded && !mainResponded) {
          console.log(
            "\n🔍 DIAGNOSIS: Both servers have issues - may be test environment problem",
          );
        } else if (minimalResponded && mainResponded) {
          console.log(
            "\n🔍 DIAGNOSIS: Both servers working - issue may be elsewhere",
          );
        }

        // Cleanup
        minimalServer.kill();
        mainServer.kill();
        process.exit(0);
      }, 3000);
    }, 1000);
  }, 3000);
}, 1000);

// Graceful cleanup
process.on("SIGINT", () => {
  console.log("\nCleaning up...");
  try {
    minimalServer.kill();
    mainServer.kill();
  } catch (e) {
    // Already dead
  }
  process.exit(0);
});
