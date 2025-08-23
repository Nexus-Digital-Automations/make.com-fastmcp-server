#!/usr/bin/env node

/**
 * Start Core Operations Server
 * Handles user-facing operations: scenarios, connections, permissions, etc.
 */

import { execSync } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = resolve(__dirname, '..');

console.log('🚀 Starting Make.com Core Operations Server...');
console.log(`📁 Project root: ${projectRoot}`);
console.log('🔧 Server type: Core Operations');
console.log('🌐 Port: 3000');
console.log('🛠️  Tools: Scenarios, Connections, Permissions, Variables, Templates, Folders, Custom Apps, SDK, Marketplace, Billing, AI Agents, Enterprise Secrets, Blueprint Collaboration');
console.log('');

try {
  // Change to project directory and start core server
  process.chdir(projectRoot);
  
  const command = `tsx src/index.ts --core`;
  console.log(`▶️  Executing: ${command}`);
  console.log('');
  
  execSync(command, { 
    stdio: 'inherit',
    env: {
      ...process.env,
      NODE_ENV: process.env.NODE_ENV || 'development'
    }
  });
  
} catch (error) {
  console.error('❌ Failed to start Core Operations Server:', error.message);
  process.exit(1);
}