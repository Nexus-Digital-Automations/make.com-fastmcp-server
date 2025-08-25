#!/usr/bin/env node

// Test script to verify monitoring logging doesn't interfere with stdout
// This simulates the MCP protocol requirement that stdout be reserved for JSON-RPC

const path = require("path");
const fs = require("fs");

// Test the logger utility functions
const {
  logPatternRegistration,
  logMultiplePatternRegistration,
} = require("./dist/utils/logger.js");

console.log("Testing monitoring logging...");

// Simulate pattern registration - this should go to log files, not stdout
logPatternRegistration("TEST_PATTERN", "critical");
logMultiplePatternRegistration(5);

// Simulate MCP JSON-RPC response - this MUST go to stdout
const mcpResponse = {
  jsonrpc: "2.0",
  id: 1,
  result: {
    status: "success",
    message: "Monitoring logging test completed",
  },
};

// This is what should be sent to stdout for MCP protocol
console.log(JSON.stringify(mcpResponse));

// Verify log files were created
const logDir = "./logs/monitoring";
if (fs.existsSync(logDir)) {
  const files = fs.readdirSync(logDir);
  console.error(`✅ Log files created: ${files.join(", ")}`); // Use console.error so it goes to stderr, not stdout
} else {
  console.error("❌ Log directory was not created");
}

console.error("Test completed - check that only JSON was sent to stdout");
