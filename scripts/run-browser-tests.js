#!/usr/bin/env node

/**
 * Browser Test Runner Script
 * 
 * Runs Playwright browser tests with proper configuration for staged loading sequences.
 * Supports the user's requirement for workflows → dashboard → interactions testing.
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PROJECT_ROOT = join(__dirname, '..');

// Parse command line arguments
const args = process.argv.slice(2);
const testType = args[0] || 'all';
const options = args.slice(1);

// Test configurations
const TEST_CONFIGS = {
  staging: {
    description: 'Run staged loading sequence tests',
    command: 'playwright',
    args: ['test', 'tests/browser/staged-workflow.test.ts'],
    timeout: 180000 // 3 minutes
  },
  dashboard: {
    description: 'Run dashboard-workflow sequence tests',
    command: 'playwright',
    args: ['test', 'tests/browser/dashboard-workflow-sequence.test.ts'],
    timeout: 180000
  },
  all: {
    description: 'Run all browser tests',
    command: 'playwright',
    args: ['test', 'tests/browser/'],
    timeout: 300000 // 5 minutes
  },
  debug: {
    description: 'Run browser tests in debug mode',
    command: 'playwright',
    args: ['test', 'tests/browser/', '--debug'],
    timeout: 600000 // 10 minutes for debugging
  },
  headed: {
    description: 'Run browser tests in headed mode (visible browser)',
    command: 'playwright',
    args: ['test', 'tests/browser/'],
    timeout: 300000,
    env: { HEADED: 'true' }
  },
  report: {
    description: 'Show last test report',
    command: 'playwright',
    args: ['show-report'],
    timeout: 30000
  }
};

function showUsage() {
  console.log('Browser Test Runner');
  console.log('');
  console.log('Usage: node scripts/run-browser-tests.js [testType] [options]');
  console.log('');
  console.log('Test Types:');
  Object.entries(TEST_CONFIGS).forEach(([key, config]) => {
    console.log(`  ${key.padEnd(12)} - ${config.description}`);
  });
  console.log('');
  console.log('Examples:');
  console.log('  node scripts/run-browser-tests.js staging');
  console.log('  node scripts/run-browser-tests.js dashboard');
  console.log('  node scripts/run-browser-tests.js all');
  console.log('  node scripts/run-browser-tests.js debug');
  console.log('  node scripts/run-browser-tests.js headed');
  console.log('  node scripts/run-browser-tests.js report');
}

function runCommand(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    console.log(`[BROWSER-TESTS] Running: ${command} ${args.join(' ')}`);
    
    const child = spawn(command, args, {
      cwd: PROJECT_ROOT,
      stdio: 'inherit',
      env: { 
        ...process.env, 
        ...options.env,
        // Set environment variables for browser testing
        PLAYWRIGHT_BROWSERS_PATH: process.env.PLAYWRIGHT_BROWSERS_PATH || 'undefined'
      }
    });
    
    // Set timeout if specified
    let timeoutHandle;
    if (options.timeout) {
      timeoutHandle = setTimeout(() => {
        console.log(`[BROWSER-TESTS] Test timeout after ${options.timeout}ms`);
        child.kill('SIGTERM');
        reject(new Error(`Test timeout after ${options.timeout}ms`));
      }, options.timeout);
    }
    
    child.on('close', (code) => {
      if (timeoutHandle) {
        clearTimeout(timeoutHandle);
      }
      
      if (code === 0) {
        console.log(`[BROWSER-TESTS] ✅ Tests completed successfully`);
        resolve();
      } else {
        console.log(`[BROWSER-TESTS] ❌ Tests failed with exit code ${code}`);
        reject(new Error(`Tests failed with exit code ${code}`));
      }
    });
    
    child.on('error', (error) => {
      if (timeoutHandle) {
        clearTimeout(timeoutHandle);
      }
      
      console.error(`[BROWSER-TESTS] ❌ Failed to start tests:`, error.message);
      reject(error);
    });
  });
}

async function main() {
  // Show usage if help requested
  if (args.includes('--help') || args.includes('-h')) {
    showUsage();
    return;
  }
  
  // Validate test type
  const config = TEST_CONFIGS[testType];
  if (!config) {
    console.error(`❌ Unknown test type: ${testType}`);
    console.error('');
    showUsage();
    process.exit(1);
  }
  
  console.log(`[BROWSER-TESTS] ${config.description}`);
  console.log(`[BROWSER-TESTS] Working directory: ${PROJECT_ROOT}`);
  
  // Check if Playwright is installed
  try {
    await runCommand('npx', ['playwright', '--version'], { timeout: 10000 });
  } catch (error) {
    console.error('❌ Playwright not found. Please install it first:');
    console.error('   npm install --save-dev @playwright/test playwright');
    console.error('   npx playwright install chromium');
    process.exit(1);
  }
  
  // Run the tests
  try {
    const commandArgs = [...config.args, ...options];
    await runCommand('npx', [config.command, ...commandArgs], {
      timeout: config.timeout,
      env: config.env || {}
    });
    
    console.log('');
    console.log('[BROWSER-TESTS] 🎉 Browser tests completed successfully!');
    
    if (testType !== 'report') {
      console.log('');
      console.log('View detailed results:');
      console.log('  node scripts/run-browser-tests.js report');
    }
    
  } catch (error) {
    console.error('');
    console.error('[BROWSER-TESTS] ❌ Browser tests failed:', error.message);
    
    console.error('');
    console.error('Debugging suggestions:');
    console.error('  1. Run in debug mode: node scripts/run-browser-tests.js debug');
    console.error('  2. Run in headed mode: node scripts/run-browser-tests.js headed');
    console.error('  3. Check the test report: node scripts/run-browser-tests.js report');
    console.error('  4. Verify application is running on http://localhost:3000');
    
    process.exit(1);
  }
}

main().catch(console.error);