#!/usr/bin/env node

/**
 * @fileoverview Performance Test Runner for Make.com FastMCP Server
 * 
 * This script runs performance tests specifically and generates performance reports.
 * It's used by the main test runner and validation scripts.
 */

import { spawn } from 'child_process';
import { performance } from 'perf_hooks';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Configuration
const config = {
  verbose: process.argv.includes('--verbose'),
  watch: process.argv.includes('--watch'),
  coverage: process.argv.includes('--coverage'),
  scenarios: process.argv.includes('--scenarios'),
  timeout: 300000 // 5 minutes
};

// Console colors
const colors = {
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  reset: '\x1b[0m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

async function runJestTests(pattern, options = {}) {
  return new Promise((resolve, reject) => {
    const jestArgs = [
      'node_modules/.bin/jest',
      pattern,
      '--testTimeout=60000',
      '--maxWorkers=1', // Single worker for consistent performance measurements
      '--no-cache',
      '--forceExit'
    ];
    
    if (config.verbose) {
      jestArgs.push('--verbose');
    }
    
    if (config.coverage) {
      jestArgs.push('--coverage');
      jestArgs.push('--coverageDirectory=coverage/performance');
    }
    
    if (config.watch) {
      jestArgs.push('--watch');
    }
    
    // Add any additional options
    Object.entries(options).forEach(([key, value]) => {
      if (value === true) {
        jestArgs.push(`--${key}`);
      } else if (value !== false) {
        jestArgs.push(`--${key}=${value}`);
      }
    });
    
    log(`Running: ${jestArgs.join(' ')}`, 'blue');
    
    const child = spawn('node', jestArgs, {
      stdio: 'inherit',
      cwd: path.join(__dirname, '..')
    });
    
    child.on('close', (code) => {
      resolve({
        code,
        success: code === 0
      });
    });
    
    child.on('error', (error) => {
      reject(error);
    });
  });
}

async function runPerformanceTests() {
  log('🚀 Starting Performance Test Suite', 'cyan');
  
  const startTime = performance.now();
  const testPatterns = [];
  
  // Add scenarios performance tests if requested or no specific pattern
  if (config.scenarios || process.argv.length <= 2) {
    testPatterns.push('tests/scenarios/performance/');
  }
  
  // If no specific patterns, run all performance tests
  if (testPatterns.length === 0) {
    testPatterns.push('tests/**/performance/');
  }
  
  const results = [];
  
  for (const pattern of testPatterns) {
    log(`\n📊 Running performance tests: ${pattern}`, 'yellow');
    
    try {
      const result = await runJestTests(pattern, {
        testPathPattern: pattern,
        testNamePattern: config.scenarios ? 'scenarios' : undefined
      });
      
      results.push({
        pattern,
        success: result.success,
        code: result.code
      });
      
      if (result.success) {
        log(`✅ Performance tests passed: ${pattern}`, 'green');
      } else {
        log(`❌ Performance tests failed: ${pattern}`, 'red');
      }
      
    } catch (error) {
      log(`💥 Performance tests crashed: ${pattern}`, 'red');
      log(`Error: ${error.message}`, 'red');
      
      results.push({
        pattern,
        success: false,
        error: error.message
      });
    }
  }
  
  const endTime = performance.now();
  const totalTime = endTime - startTime;
  
  // Summary
  log(`\n${'='.repeat(50)}`, 'cyan');
  log('PERFORMANCE TEST SUMMARY', 'cyan');
  log(`${'='.repeat(50)}`, 'cyan');
  
  const successCount = results.filter(r => r.success).length;
  const totalCount = results.length;
  
  log(`\nResults:`, 'white');
  log(`  Total Test Suites: ${totalCount}`, 'white');
  log(`  Passed: ${successCount}`, successCount === totalCount ? 'green' : 'white');
  log(`  Failed: ${totalCount - successCount}`, successCount === totalCount ? 'green' : 'red');
  log(`  Total Time: ${(totalTime / 1000).toFixed(2)}s`, 'blue');
  
  if (results.some(r => !r.success)) {
    log(`\nFailed Test Suites:`, 'red');
    results.filter(r => !r.success).forEach(result => {
      log(`  ❌ ${result.pattern}`, 'red');
      if (result.error) {
        log(`     Error: ${result.error}`, 'red');
      }
    });
  }
  
  const allPassed = results.every(r => r.success);
  
  log(`\n${'='.repeat(50)}`, allPassed ? 'green' : 'red');
  log(`PERFORMANCE TESTS ${allPassed ? 'PASSED' : 'FAILED'}`, allPassed ? 'green' : 'red');
  log(`${'='.repeat(50)}`, allPassed ? 'green' : 'red');
  
  if (allPassed) {
    log('\n🎉 All performance tests passed!', 'green');
  } else {
    log('\n⚠️  Some performance tests failed. Please review the results.', 'red');
  }
  
  return allPassed;
}

// Main execution
async function main() {
  try {
    const success = await runPerformanceTests();
    process.exit(success ? 0 : 1);
  } catch (error) {
    log(`\n💥 PERFORMANCE TEST RUNNER CRASHED:`, 'red');
    log(`${error.message}`, 'red');
    if (config.verbose && error.stack) {
      log(`${error.stack}`, 'red');
    }
    process.exit(2);
  }
}

// Run if this script is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}