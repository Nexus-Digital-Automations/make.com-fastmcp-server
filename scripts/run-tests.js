#!/usr/bin/env node

/**
 * Test runner script with different test suite options
 * Provides easy ways to run unit, integration, e2e, or all tests
 */

import { spawn } from 'child_process';
import { existsSync } from 'fs';
import { join as _join } from 'path';

const testTypes = {
  unit: 'tests/unit',
  integration: 'tests/integration', 
  e2e: 'tests/e2e',
  all: 'tests'
};

const coverageTypes = {
  unit: ['src/tools/**', 'src/lib/**'],
  integration: ['src/lib/**', 'src/utils/**'],
  e2e: ['src/**'],
  all: ['src/**']
};

function runCommand(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    console.log(`Running: ${command} ${args.join(' ')}`);
    
    const child = spawn(command, args, {
      stdio: 'inherit',
      shell: true,
      ...options
    });
    
    child.on('close', (code) => {
      if (code === 0) {
        resolve(code);
      } else {
        reject(new Error(`Command failed with exit code ${code}`));
      }
    });
    
    child.on('error', (error) => {
      reject(error);
    });
  });
}

async function runTests(type = 'all', options = {}) {
  const {
    watch = false,
    coverage = true,
    verbose = false,
    updateSnapshots = false,
    bail = false,
    maxWorkers = undefined
  } = options;
  
  if (!testTypes[type]) {
    console.error(`Invalid test type: ${type}`);
    console.error(`Available types: ${Object.keys(testTypes).join(', ')}`);
    process.exit(1);
  }
  
  const testPath = testTypes[type];
  
  // Check if test directory exists
  if (!existsSync(testPath)) {
    console.error(`Test directory does not exist: ${testPath}`);
    process.exit(1);
  }
  
  const jestArgs = [
    testPath,
    '--config=jest.config.js'
  ];
  
  if (watch) {
    jestArgs.push('--watch');
  }
  
  if (coverage && !watch) {
    jestArgs.push('--coverage');
    
    // Add coverage-specific collections for different test types
    const coveragePaths = coverageTypes[type];
    if (coveragePaths) {
      coveragePaths.forEach(path => {
        jestArgs.push(`--collectCoverageFrom=${path}/*.{ts,js}`);
      });
    }
  }
  
  if (verbose) {
    jestArgs.push('--verbose');
  }
  
  if (updateSnapshots) {
    jestArgs.push('--updateSnapshot');
  }
  
  if (bail) {
    jestArgs.push('--bail');
  }
  
  if (maxWorkers) {
    jestArgs.push(`--maxWorkers=${maxWorkers}`);
  }
  
  try {
    await runCommand('npx', ['jest', ...jestArgs]);
    console.log(`\n✅ ${type} tests completed successfully`);
  } catch (error) {
    console.error(`\n❌ ${type} tests failed:`, error.message);
    process.exit(1);
  }
}

async function runLinting() {
  console.log('\n🔍 Running linting...');
  try {
    await runCommand('npm', ['run', 'lint']);
    console.log('✅ Linting passed');
  } catch (error) {
    console.error('❌ Linting failed:', error.message);
    throw error;
  }
}

async function runTypeChecking() {
  console.log('\n🔍 Running type checking...');
  try {
    await runCommand('npm', ['run', 'typecheck']);
    console.log('✅ Type checking passed');
  } catch (error) {
    console.error('❌ Type checking failed:', error.message);
    throw error;
  }
}

async function buildProject() {
  console.log('\n🔨 Building project...');
  try {
    await runCommand('npm', ['run', 'build']);
    console.log('✅ Build completed');
  } catch (error) {
    console.error('❌ Build failed:', error.message);
    throw error;
  }
}

async function runFullValidation() {
  console.log('🚀 Running full project validation...\n');
  
  try {
    // Step 1: Linting
    await runLinting();
    
    // Step 2: Type checking
    await runTypeChecking();
    
    // Step 3: Build
    await buildProject();
    
    // Step 4: All tests with coverage
    await runTests('all', { coverage: true, bail: true });
    
    console.log('\n🎉 All validation steps passed!');
    console.log('Your project is ready for production.');
    
  } catch (error) {
    console.error('\n💥 Validation failed. Please fix the issues above.');
    process.exit(1);
  }
}

function printUsage() {
  console.log(`
Usage: node scripts/run-tests.js [command] [options]

Commands:
  unit         Run unit tests only
  integration  Run integration tests only  
  e2e          Run end-to-end tests only
  all          Run all tests (default)
  validate     Run full validation (lint + typecheck + build + tests)

Options:
  --watch      Run tests in watch mode
  --no-coverage   Skip coverage collection
  --verbose    Show verbose output
  --update-snapshots   Update Jest snapshots
  --bail       Stop on first test failure
  --max-workers=N   Limit number of worker processes

Examples:
  node scripts/run-tests.js unit --watch
  node scripts/run-tests.js integration --verbose
  node scripts/run-tests.js all --no-coverage
  node scripts/run-tests.js validate
`);
}

// Parse command line arguments
const args = process.argv.slice(2);
const command = args[0] || 'all';

if (command === 'help' || command === '--help' || command === '-h') {
  printUsage();
  process.exit(0);
}

const options = {
  watch: args.includes('--watch'),
  coverage: !args.includes('--no-coverage'),
  verbose: args.includes('--verbose'),
  updateSnapshots: args.includes('--update-snapshots'),
  bail: args.includes('--bail'),
  maxWorkers: args.find(arg => arg.startsWith('--max-workers='))?.split('=')[1]
};

// Run the appropriate command
(async () => {
  try {
    if (command === 'validate') {
      await runFullValidation();
    } else {
      await runTests(command, options);
    }
  } catch (error) {
    console.error('Test execution failed:', error.message);
    process.exit(1);
  }
})();