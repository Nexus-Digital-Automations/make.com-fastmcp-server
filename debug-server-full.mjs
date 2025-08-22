#!/usr/bin/env node

import { MakeServerInstance } from './dist/index.js';

console.log('Creating MakeServerInstance...');

try {
  const serverInstance = new MakeServerInstance();
  console.log('Server instance created successfully');
  
  console.log('Starting server...');
  
  // Add timeout to the start operation
  const startPromise = serverInstance.start({
    transportType: 'stdio'
  });
  
  const timeoutPromise = new Promise((_, reject) => {
    setTimeout(() => reject(new Error('Start timeout after 30 seconds')), 30000);
  });
  
  await Promise.race([startPromise, timeoutPromise]);
  
  console.log('Server started successfully!');
} catch (error) {
  console.error('Error:', error.message);
  process.exit(1);
}