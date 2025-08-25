#!/usr/bin/env node

/**
 * Make.com FastMCP Server - Entry Point
 * Handles command-line arguments and starts appropriate server configuration
 */

import "./simple-fastmcp-server.js";

// The simple-fastmcp-server.ts file already starts the server with server.start()
// This index.ts file simply imports it to trigger the server startup
// Command-line arguments (like --development, --essential, etc.) can be processed
// by the simple-fastmcp-server.ts if needed in the future
