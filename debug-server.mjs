#!/usr/bin/env node

import { FastMCP } from 'fastmcp';

console.log('Creating FastMCP server...');

const server = new FastMCP({
  name: 'Debug Server',
  version: '1.0.0',
  instructions: 'Debug server to test initialization'
});

console.log('Server created, starting...');

try {
  // Start with minimal options
  await server.start({
    transportType: 'stdio'
  });
  
  console.log('Server started successfully!');
} catch (error) {
  console.error('Error starting server:', error);
  process.exit(1);
}