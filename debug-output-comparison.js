#!/usr/bin/env node

/**
 * Debug script to compare output between direct FastMCP server and wrapped MakeServerInstance
 */

import { spawn } from "child_process";
import { FastMCP } from "fastmcp";

console.log(
  "🔬 DEBUG: Comparing FastMCP direct vs MakeServerInstance wrapper output...",
);

// Test 1: Direct FastMCP server (we know this works from previous tests)
console.log("\n=== Test 1: Direct FastMCP Server ===");

async function testDirectFastMCP() {
  const server = new FastMCP({
    name: "Direct Test Server",
    version: "1.0.0",
  });

  console.log("🚀 Starting direct FastMCP server...");

  // Create a child process to test JSON-RPC communication
  const directTest = spawn(
    "node",
    [
      "-e",
      `
    import { FastMCP } from 'fastmcp';
    const server = new FastMCP({
      name: 'Direct Test',
      version: '1.0.0'
    });
    await server.start({ transportType: 'stdio' });
  `,
    ],
    {
      stdio: ["pipe", "pipe", "inherit"],
    },
  );

  let directOutput = "";
  let directResponded = false;

  directTest.stdout.on("data", (data) => {
    const output = data.toString();
    directOutput += output;
    console.log("📤 Direct FastMCP output:", output.trim());

    try {
      const parsed = JSON.parse(output.trim());
      if (parsed.id === 1) {
        console.log("✅ Direct FastMCP responded correctly!");
        directResponded = true;
      }
    } catch (e) {
      // Not complete JSON yet
    }
  });

  // Send initialize request after server starts
  setTimeout(() => {
    console.log("📨 Sending initialize to direct FastMCP...");
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
      }) + "\\n";

    directTest.stdin.write(initRequest);

    setTimeout(() => {
      console.log(
        `📊 Direct FastMCP result: ${directResponded ? "✅ SUCCESS" : "❌ FAILED"}`,
      );
      directTest.kill();

      // Now test MakeServerInstance
      testMakeServerInstance();
    }, 2000);
  }, 1000);
}

async function testMakeServerInstance() {
  console.log("\n=== Test 2: MakeServerInstance Wrapper ===");

  const wrapperTest = spawn(
    "node",
    [
      "-e",
      `
    import MakeServerInstance from './dist/server.js';
    const serverInstance = new MakeServerInstance();
    console.log('🚀 Starting MakeServerInstance...');
    await serverInstance.start({ transportType: 'stdio' });
  `,
    ],
    {
      stdio: ["pipe", "pipe", "inherit"],
      cwd: process.cwd(),
    },
  );

  let wrapperOutput = "";
  let wrapperResponded = false;

  wrapperTest.stdout.on("data", (data) => {
    const output = data.toString();
    wrapperOutput += output;
    console.log("📤 MakeServerInstance output:", output.trim());

    try {
      const parsed = JSON.parse(output.trim());
      if (parsed.id === 1) {
        console.log("✅ MakeServerInstance responded correctly!");
        wrapperResponded = true;
      }
    } catch (e) {
      // Not complete JSON yet
    }
  });

  // Send initialize request after server starts
  setTimeout(() => {
    console.log("📨 Sending initialize to MakeServerInstance...");
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
      }) + "\\n";

    wrapperTest.stdin.write(initRequest);

    setTimeout(() => {
      console.log(
        `📊 MakeServerInstance result: ${wrapperResponded ? "✅ SUCCESS" : "❌ FAILED"}`,
      );
      wrapperTest.kill();

      // Show comparison
      console.log("\n=== COMPARISON RESULTS ===");
      console.log(
        `Direct FastMCP: ${directResponded ? "✅ Working" : "❌ Broken"}`,
      );
      console.log(
        `MakeServerInstance: ${wrapperResponded ? "✅ Working" : "❌ Broken"}`,
      );

      if (directResponded && !wrapperResponded) {
        console.log(
          "\n🔍 DIAGNOSIS: MakeServerInstance wrapper is interfering with JSON-RPC output",
        );
        console.log(
          "Need to investigate what in the wrapper is preventing stdout communication",
        );
      }

      process.exit(0);
    }, 3000);
  }, 2000);
}

// Start the test
testDirectFastMCP();

// Cleanup on exit
process.on("SIGINT", () => {
  console.log("\\nCleaning up...");
  process.exit(0);
});
