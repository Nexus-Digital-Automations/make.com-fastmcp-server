#!/usr/bin/env node

/**
 * Start Analytics & Governance Server
 * Handles monitoring, analytics, compliance, and policy enforcement
 */

import { execSync } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = resolve(__dirname, '..');

console.log('📊 Starting Make.com Analytics & Governance Server...');
console.log(`📁 Project root: ${projectRoot}`);
console.log('🔧 Server type: Analytics & Governance');
console.log('🌐 Port: 3001');
console.log('🛠️  Tools: Analytics, Performance Analysis, Real-time Monitoring, Log Streaming, Audit Compliance, Policy Validation, Zero Trust Auth, Multi-tenant Security, CI/CD Integration, Procedures, Naming Policies, Archival Policies, Notifications, Budget Control, Certificates, AI Governance');
console.log('');

try {
  // Change to project directory and start analytics server
  process.chdir(projectRoot);
  
  const command = `tsx src/index.ts --analytics`;
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
  console.error('❌ Failed to start Analytics & Governance Server:', error.message);
  process.exit(1);
}