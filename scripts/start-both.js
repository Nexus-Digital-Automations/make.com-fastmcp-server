#!/usr/bin/env node

/**
 * Start Both Servers in Development Mode
 * Starts Core Operations and Analytics & Governance servers concurrently
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = resolve(__dirname, '..');

console.log('🚀 Starting Make.com FastMCP Server - Dual Mode');
console.log(`📁 Project root: ${projectRoot}`);
console.log('');
console.log('🔧 Starting both servers:');
console.log('  📱 Core Operations Server (Port 3000)');
console.log('  📊 Analytics & Governance Server (Port 3001)');
console.log('');

try {
  // Change to project directory
  process.chdir(projectRoot);
  
  const servers = [];
  
  // Start Core Server
  console.log('▶️  Starting Core Operations Server...');
  const coreServer = spawn('tsx', ['src/index.ts', '--core'], {
    stdio: ['inherit', 'pipe', 'pipe'],
    env: {
      ...process.env,
      NODE_ENV: process.env.NODE_ENV || 'development'
    }
  });
  
  coreServer.stdout.on('data', (data) => {
    console.log(`[CORE] ${data.toString().trim()}`);
  });
  
  coreServer.stderr.on('data', (data) => {
    console.error(`[CORE ERROR] ${data.toString().trim()}`);
  });
  
  servers.push(coreServer);
  
  // Start Analytics Server  
  console.log('▶️  Starting Analytics & Governance Server...');
  const analyticsServer = spawn('tsx', ['src/index.ts', '--analytics'], {
    stdio: ['inherit', 'pipe', 'pipe'], 
    env: {
      ...process.env,
      NODE_ENV: process.env.NODE_ENV || 'development'
    }
  });
  
  analyticsServer.stdout.on('data', (data) => {
    console.log(`[ANALYTICS] ${data.toString().trim()}`);
  });
  
  analyticsServer.stderr.on('data', (data) => {
    console.error(`[ANALYTICS ERROR] ${data.toString().trim()}`);
  });
  
  servers.push(analyticsServer);
  
  // Handle server exits
  coreServer.on('exit', (code) => {
    console.log(`🔴 Core Operations Server exited with code ${code}`);
    if (code !== 0) {
      console.log('🛑 Shutting down Analytics Server...');
      analyticsServer.kill();
    }
  });
  
  analyticsServer.on('exit', (code) => {
    console.log(`🔴 Analytics & Governance Server exited with code ${code}`);
    if (code !== 0) {
      console.log('🛑 Shutting down Core Server...');
      coreServer.kill();
    }
  });
  
  // Handle process termination
  process.on('SIGINT', () => {
    console.log('\\n🛑 Received SIGINT, shutting down both servers...');
    servers.forEach(server => server.kill());
    process.exit(0);
  });
  
  process.on('SIGTERM', () => {
    console.log('\\n🛑 Received SIGTERM, shutting down both servers...');
    servers.forEach(server => server.kill());
    process.exit(0);
  });
  
  console.log('');
  console.log('✅ Both servers started successfully!');
  console.log('📱 Core Operations Server: http://localhost:3000');
  console.log('📊 Analytics & Governance Server: http://localhost:3001');
  console.log('');
  console.log('Press Ctrl+C to stop both servers');
  
} catch (error) {
  console.error('❌ Failed to start servers:', error.message);
  process.exit(1);
}