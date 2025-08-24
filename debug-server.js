#!/usr/bin/env node

/**
 * Debug script to test basic server functionality
 */

import { spawn } from "child_process";
import * as path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log("Debug: Testing basic server startup\n");

const serverPath = path.join(__dirname, "dist", "index.js");

console.log("1. Testing if server starts without error...");
const server = spawn("node", [serverPath], {
  stdio: ["pipe", "pipe", "pipe"],
  cwd: __dirname,
});

let hasOutput = false;
let errorOutput = "";
let stdOutput = "";

// Capture all output
server.stdout.on("data", (data) => {
  hasOutput = true;
  stdOutput += data.toString();
  console.log("📤 Server stdout:", data.toString().trim());
});

server.stderr.on("data", (data) => {
  hasOutput = true;
  errorOutput += data.toString();
  console.log("📤 Server stderr:", data.toString().trim());
});

server.on("exit", (code, signal) => {
  console.log(`\n📊 Server exited: code=${code}, signal=${signal}`);
  console.log(`📈 Had output: ${hasOutput}`);

  if (stdOutput) {
    console.log("\n--- Full stdout ---");
    console.log(stdOutput);
  }

  if (errorOutput) {
    console.log("\n--- Full stderr ---");
    console.log(errorOutput);
  }

  process.exit(0);
});

server.on("error", (error) => {
  console.log("❌ Server spawn error:", error.message);
  process.exit(1);
});

// Send a test message after 2 seconds
setTimeout(() => {
  console.log("\n2. Sending JSON-RPC test message...");
  const testMsg =
    JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "debug-test", version: "1.0.0" },
      },
    }) + "\n";

  console.log("📨 Sending:", testMsg.trim());
  server.stdin.write(testMsg);
}, 2000);

// Kill after 8 seconds
setTimeout(() => {
  console.log("\n3. Killing server after timeout...");
  server.kill("SIGTERM");
}, 8000);

// Graceful shutdown
process.on("SIGINT", () => {
  console.log("\nShutting down debug script...");
  server.kill();
  process.exit(0);
});
