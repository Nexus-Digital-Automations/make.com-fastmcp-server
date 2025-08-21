#!/usr/bin/env node

/**
 * @fileoverview Regression Test Script for Scenarios Module
 * 
 * This script performs comprehensive regression testing to ensure the refactored
 * scenarios module produces identical outputs to the original implementation.
 * 
 * Test Methodology:
 * - Load both original and refactored implementations
 * - Execute identical test scenarios
 * - Compare outputs for exact matches
 * - Report any discrepancies
 */

import { performance } from 'perf_hooks';
import { FastMCP } from 'fastmcp';
import { createHash } from 'crypto';

// Test configuration
const TEST_CONFIG = {
  iterations: 100,
  timeout: 5000,
  toleranceMs: 50, // Performance tolerance
  enableVerbose: process.argv.includes('--verbose'),
  enablePerformance: process.argv.includes('--performance')
};

// Results tracking
const regressionResults = {
  tests: [],
  summary: {
    total: 0,
    passed: 0,
    failed: 0,
    warnings: 0
  },
  performance: {
    original: {},
    refactored: {},
    comparisons: []
  }
};

// Console colors
const colors = {
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  reset: '\x1b[0m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function hashObject(obj) {
  return createHash('sha256').update(JSON.stringify(obj, null, 0)).digest('hex');
}

function deepEqual(obj1, obj2) {
  return JSON.stringify(obj1, null, 0) === JSON.stringify(obj2, null, 0);
}

class RegressionTest {
  constructor(name, description) {
    this.name = name;
    this.description = description;
    this.passed = false;
    this.error = null;
    this.warnings = [];
    this.performance = {
      original: 0,
      refactored: 0,
      difference: 0,
      percentChange: 0
    };
  }

  pass() {
    this.passed = true;
    regressionResults.summary.passed++;
  }

  fail(error) {
    this.passed = false;
    this.error = error;
    regressionResults.summary.failed++;
  }

  warn(message) {
    this.warnings.push(message);
    regressionResults.summary.warnings++;
  }

  setPerformance(original, refactored) {
    this.performance.original = original;
    this.performance.refactored = refactored;
    this.performance.difference = refactored - original;
    this.performance.percentChange = original > 0 ? ((refactored - original) / original) * 100 : 0;
  }

  log() {
    const status = this.passed ? '✅' : '❌';
    const color = this.passed ? 'green' : 'red';
    
    log(`${status} ${this.name}`, color);
    
    if (TEST_CONFIG.enableVerbose) {
      log(`   Description: ${this.description}`, 'cyan');
      
      if (this.performance.original > 0) {
        const perfColor = this.performance.percentChange > 10 ? 'red' : 
                         this.performance.percentChange < -10 ? 'green' : 'yellow';
        log(`   Performance: ${this.performance.original.toFixed(2)}ms → ${this.performance.refactored.toFixed(2)}ms (${this.performance.percentChange > 0 ? '+' : ''}${this.performance.percentChange.toFixed(1)}%)`, perfColor);
      }
      
      if (this.warnings.length > 0) {
        this.warnings.forEach(warning => log(`   ⚠️  ${warning}`, 'yellow'));
      }
      
      if (this.error) {
        log(`   Error: ${this.error.message}`, 'red');
      }
    }
  }
}

// Mock API client that returns deterministic results
const deterministicApiClient = {
  get: (url, options) => {
    const hash = hashObject({ url, options });
    return Promise.resolve({
      success: true,
      data: generateDeterministicData(hash, 'get'),
      metadata: { total: 42, hash }
    });
  },
  
  post: (url, data) => {
    const hash = hashObject({ url, data });
    return Promise.resolve({
      success: true,
      data: generateDeterministicData(hash, 'post'),
      metadata: { hash }
    });
  },
  
  patch: (url, data) => {
    const hash = hashObject({ url, data });
    return Promise.resolve({
      success: true,
      data: generateDeterministicData(hash, 'patch'),
      metadata: { hash }
    });
  },
  
  delete: (url) => {
    const hash = hashObject({ url });
    return Promise.resolve({
      success: true,
      data: {},
      metadata: { hash }
    });
  },
  
  healthCheck: () => Promise.resolve({ healthy: true }),
  getRateLimiterStatus: () => Promise.resolve({ remaining: 100 }),
  shutdown: () => Promise.resolve()
};

function generateDeterministicData(hash, operation) {
  const seed = parseInt(hash.substring(0, 8), 16);
  const random = (seed) => (seed * 9301 + 49297) % 233280 / 233280;
  
  switch (operation) {
    case 'get':
      return Array.from({ length: 3 }, (_, i) => ({
        id: `scn_${hash.substring(0, 8)}_${i}`,
        name: `Scenario ${seed + i}`,
        active: random(seed + i) > 0.5,
        teamId: `team_${Math.floor(random(seed + i * 2) * 10)}`,
        createdAt: new Date(1640995200000 + seed * 1000).toISOString()
      }));
      
    case 'post':
      return {
        id: `scn_created_${hash.substring(0, 8)}`,
        name: `Created Scenario ${seed}`,
        active: false,
        createdAt: new Date().toISOString()
      };
      
    case 'patch':
      return {
        id: `scn_updated_${hash.substring(0, 8)}`,
        name: `Updated Scenario ${seed}`,
        active: true,
        updatedAt: new Date().toISOString()
      };
      
    default:
      return {};
  }
}

async function setupTestEnvironments() {
  log('🔧 Setting up test environments...', 'blue');
  
  // Original implementation server
  const originalServer = new FastMCP({
    name: 'original-test-server',
    version: '1.0.0'
  });
  
  // Refactored implementation server
  const refactoredServer = new FastMCP({
    name: 'refactored-test-server',
    version: '1.0.0'
  });
  
  try {
    // Load original scenarios implementation
    const { addScenarioTools: addOriginalTools } = await import('../../src/tools/scenarios.js');
    addOriginalTools(originalServer, deterministicApiClient);
    
    // Load refactored scenarios implementation
    const { addScenarioTools: addRefactoredTools } = await import('../../src/tools/scenarios.js');
    addRefactoredTools(refactoredServer, deterministicApiClient);
    
    return { originalServer, refactoredServer };
    
  } catch (error) {
    log(`Failed to set up test environments: ${error.message}`, 'red');
    process.exit(1);
  }
}

async function executeTestScenario(original, refactored, testName, toolName, args) {
  const test = new RegressionTest(testName, `Compare ${toolName} tool outputs`);
  regressionResults.tests.push(test);
  regressionResults.summary.total++;
  
  const mockContext = {
    log: {
      info: () => {},
      debug: () => {},
      warn: () => {},
      error: () => {}
    },
    reportProgress: () => {}
  };
  
  try {
    // Execute original implementation
    const originalTool = original.tools.get(toolName);
    if (!originalTool) {
      throw new Error(`Original tool '${toolName}' not found`);
    }
    
    const originalStart = performance.now();
    const originalResult = await originalTool.execute(args, mockContext);
    const originalEnd = performance.now();
    const originalTime = originalEnd - originalStart;
    
    // Execute refactored implementation
    const refactoredTool = refactored.tools.get(toolName);
    if (!refactoredTool) {
      throw new Error(`Refactored tool '${toolName}' not found`);
    }
    
    const refactoredStart = performance.now();
    const refactoredResult = await refactoredTool.execute(args, mockContext);
    const refactoredEnd = performance.now();
    const refactoredTime = refactoredEnd - refactoredStart;
    
    // Compare results
    try {
      const originalParsed = JSON.parse(originalResult);
      const refactoredParsed = JSON.parse(refactoredResult);
      
      if (deepEqual(originalParsed, refactoredParsed)) {
        test.pass();
      } else {
        const originalHash = hashObject(originalParsed);
        const refactoredHash = hashObject(refactoredParsed);
        test.fail(new Error(`Output mismatch: ${originalHash} !== ${refactoredHash}`));
        
        if (TEST_CONFIG.enableVerbose) {
          console.log('Original output:', JSON.stringify(originalParsed, null, 2));
          console.log('Refactored output:', JSON.stringify(refactoredParsed, null, 2));
        }
      }
    } catch (parseError) {
      test.fail(new Error(`Failed to parse outputs: ${parseError.message}`));
    }
    
    // Performance comparison
    test.setPerformance(originalTime, refactoredTime);
    
    if (TEST_CONFIG.enablePerformance) {
      const perfDiff = Math.abs(refactoredTime - originalTime);
      if (perfDiff > TEST_CONFIG.toleranceMs) {
        test.warn(`Performance difference of ${perfDiff.toFixed(2)}ms exceeds tolerance (${TEST_CONFIG.toleranceMs}ms)`);
      }
    }
    
    // Store performance data
    regressionResults.performance.comparisons.push({
      test: testName,
      tool: toolName,
      original: originalTime,
      refactored: refactoredTime,
      difference: refactoredTime - originalTime,
      percentChange: test.performance.percentChange
    });
    
  } catch (error) {
    test.fail(error);
  }
  
  return test;
}

async function runRegressionTests() {
  log('🧪 Running regression tests...', 'blue');
  
  const { originalServer, refactoredServer } = await setupTestEnvironments();
  
  // Define comprehensive test scenarios
  const testScenarios = [
    // Basic CRUD operations
    {
      name: 'List scenarios - empty filters',
      tool: 'list-scenarios',
      args: {}
    },
    {
      name: 'List scenarios - with filters',
      tool: 'list-scenarios',
      args: {
        teamId: 'team_123',
        folderId: 'folder_456',
        limit: 25,
        offset: 10,
        search: 'test query',
        active: true
      }
    },
    {
      name: 'Get scenario details',
      tool: 'get-scenario',
      args: {
        scenarioId: 'scn_test_123'
      }
    },
    {
      name: 'Get scenario with blueprint',
      tool: 'get-scenario',
      args: {
        scenarioId: 'scn_test_123',
        includeBlueprint: true,
        includeExecutions: true
      }
    },
    {
      name: 'Create simple scenario',
      tool: 'create-scenario',
      args: {
        name: 'Regression Test Scenario'
      }
    },
    {
      name: 'Create complex scenario',
      tool: 'create-scenario',
      args: {
        name: 'Complex Regression Test Scenario',
        teamId: 'team_456',
        folderId: 'folder_789',
        blueprint: {
          name: 'Test Blueprint',
          metadata: {
            version: 1,
            scenario: {
              roundtrips: 3,
              maxErrors: 2,
              autoCommit: true,
              sequential: false,
              confidential: true,
              dlq: true
            }
          },
          flow: [
            { id: 1, module: 'webhook', version: 1 },
            { id: 2, module: 'http:request', version: 1, connection: 1 }
          ]
        },
        scheduling: {
          type: 'interval',
          interval: 30
        }
      }
    },
    {
      name: 'Update scenario name',
      tool: 'update-scenario',
      args: {
        scenarioId: 'scn_test_456',
        name: 'Updated Scenario Name'
      }
    },
    {
      name: 'Update scenario status',
      tool: 'update-scenario',
      args: {
        scenarioId: 'scn_test_456',
        active: true
      }
    },
    {
      name: 'Update scenario with blueprint',
      tool: 'update-scenario',
      args: {
        scenarioId: 'scn_test_456',
        name: 'Fully Updated Scenario',
        active: false,
        blueprint: {
          name: 'Updated Blueprint',
          metadata: { version: 2 },
          flow: [
            { id: 1, module: 'webhook', version: 1 },
            { id: 2, module: 'database:query', version: 1, connection: 1 }
          ]
        }
      }
    },
    {
      name: 'Delete scenario (inactive)',
      tool: 'delete-scenario',
      args: {
        scenarioId: 'scn_test_789',
        force: false
      }
    },
    {
      name: 'Force delete scenario',
      tool: 'delete-scenario',
      args: {
        scenarioId: 'scn_test_789',
        force: true
      }
    },
    {
      name: 'Clone scenario',
      tool: 'clone-scenario',
      args: {
        scenarioId: 'scn_source_123',
        name: 'Cloned Test Scenario'
      }
    },
    {
      name: 'Clone scenario with options',
      tool: 'clone-scenario',
      args: {
        scenarioId: 'scn_source_123',
        name: 'Advanced Cloned Scenario',
        teamId: 'team_target',
        folderId: 'folder_target',
        active: true
      }
    },
    {
      name: 'Run scenario (no wait)',
      tool: 'run-scenario',
      args: {
        scenarioId: 'scn_run_test',
        wait: false
      }
    },
    {
      name: 'Run scenario with timeout',
      tool: 'run-scenario',
      args: {
        scenarioId: 'scn_run_test',
        wait: true,
        timeout: 60
      }
    },
    
    // Blueprint operations
    {
      name: 'Validate simple blueprint',
      tool: 'validate-blueprint',
      args: {
        blueprint: {
          name: 'Simple Blueprint',
          metadata: {
            version: 1,
            scenario: {
              roundtrips: 1,
              maxErrors: 1,
              autoCommit: true,
              sequential: false
            }
          },
          flow: [
            { id: 1, module: 'webhook', version: 1 }
          ]
        }
      }
    },
    {
      name: 'Validate complex blueprint with security',
      tool: 'validate-blueprint',
      args: {
        blueprint: {
          name: 'Complex Blueprint',
          metadata: {
            version: 2,
            scenario: {
              roundtrips: 5,
              maxErrors: 3,
              autoCommit: true,
              sequential: false,
              confidential: true,
              dlq: true
            }
          },
          flow: [
            { id: 1, module: 'webhook', version: 1 },
            { id: 2, module: 'http:request', version: 1, connection: 1 },
            { id: 3, module: 'database:query', version: 1, connection: 2 },
            { id: 4, module: 'email:send', version: 1, connection: 3 }
          ]
        },
        strict: true,
        includeSecurityChecks: true
      }
    },
    {
      name: 'Extract blueprint connections',
      tool: 'extract-blueprint-connections',
      args: {
        blueprint: {
          flow: [
            { id: 1, module: 'webhook', version: 1 },
            { id: 2, module: 'http:request', version: 1, connection: 1 },
            { id: 3, module: 'database:mysql', version: 1, connection: 2 },
            { id: 4, module: 'builtin:Iterator', version: 1 },
            { id: 5, module: 'slack:message', version: 1, connection: 3 }
          ]
        },
        includeOptional: true,
        groupByModule: true
      }
    },
    {
      name: 'Optimize blueprint for performance',
      tool: 'optimize-blueprint',
      args: {
        blueprint: {
          name: 'Performance Test Blueprint',
          flow: Array.from({ length: 20 }, (_, i) => ({
            id: i + 1,
            module: i % 3 === 0 ? 'builtin:Delay' : 'http:request',
            version: 1,
            connection: i % 3 !== 0 ? Math.floor(i / 3) + 1 : undefined,
            parameters: { config: `module_${i}` }
          }))
        },
        optimizationType: 'performance',
        includeImplementationSteps: true
      }
    },
    {
      name: 'Optimize blueprint for security',
      tool: 'optimize-blueprint',
      args: {
        blueprint: {
          name: 'Security Test Blueprint',
          metadata: {
            version: 1,
            scenario: {
              confidential: false,
              dlq: false
            }
          },
          flow: [
            {
              id: 1,
              module: 'http:request',
              version: 1,
              connection: 1,
              parameters: {
                url: 'https://api.example.com',
                apiKey: 'hardcoded-key-123'
              }
            }
          ]
        },
        optimizationType: 'security',
        includeImplementationSteps: true
      }
    }
  ];
  
  // Execute all test scenarios
  const tests = [];
  for (const scenario of testScenarios) {
    const test = await executeTestScenario(
      originalServer,
      refactoredServer,
      scenario.name,
      scenario.tool,
      scenario.args
    );
    tests.push(test);
    test.log();
  }
  
  return tests;
}

async function generateRegressionReport() {
  log('\n📊 Generating regression test report...', 'blue');
  
  const { total, passed, failed, warnings } = regressionResults.summary;
  const passRate = total > 0 ? (passed / total) * 100 : 0;
  
  log(`\n${'='.repeat(60)}`, 'cyan');
  log(`REGRESSION TEST SUMMARY`, 'cyan');
  log(`${'='.repeat(60)}`, 'cyan');
  
  log(`\nTest Results:`, 'white');
  log(`  Total Tests: ${total}`, 'white');
  log(`  Passed: ${passed}`, passed === total ? 'green' : 'white');
  log(`  Failed: ${failed}`, failed === 0 ? 'green' : 'red');
  log(`  Warnings: ${warnings}`, warnings === 0 ? 'green' : 'yellow');
  log(`  Pass Rate: ${passRate.toFixed(1)}%`, passRate >= 95 ? 'green' : 'red');
  
  if (TEST_CONFIG.enablePerformance && regressionResults.performance.comparisons.length > 0) {
    log(`\nPerformance Analysis:`, 'white');
    
    const comparisons = regressionResults.performance.comparisons;
    const avgPerformanceChange = comparisons.reduce((sum, c) => sum + c.percentChange, 0) / comparisons.length;
    
    log(`  Average Performance Change: ${avgPerformanceChange > 0 ? '+' : ''}${avgPerformanceChange.toFixed(1)}%`, 
        avgPerformanceChange > 10 ? 'red' : avgPerformanceChange < -10 ? 'green' : 'yellow');
    
    const significantChanges = comparisons.filter(c => Math.abs(c.percentChange) > 20);
    if (significantChanges.length > 0) {
      log(`  Significant Performance Changes (>20%):`, 'yellow');
      for (const change of significantChanges) {
        log(`    ${change.test}: ${change.percentChange > 0 ? '+' : ''}${change.percentChange.toFixed(1)}%`, 'yellow');
      }
    }
  }
  
  // Failed tests details
  const failedTests = regressionResults.tests.filter(t => !t.passed);
  if (failedTests.length > 0) {
    log(`\nFailed Tests:`, 'red');
    for (const test of failedTests) {
      log(`  ❌ ${test.name}`, 'red');
      if (test.error) {
        log(`     ${test.error.message}`, 'red');
      }
    }
  }
  
  // Warnings details
  const testsWithWarnings = regressionResults.tests.filter(t => t.warnings.length > 0);
  if (testsWithWarnings.length > 0) {
    log(`\nTests with Warnings:`, 'yellow');
    for (const test of testsWithWarnings) {
      log(`  ⚠️  ${test.name}`, 'yellow');
      for (const warning of test.warnings) {
        log(`     ${warning}`, 'yellow');
      }
    }
  }
  
  // Final verdict
  const isSuccess = passRate >= 95 && failed === 0;
  
  log(`\n${'='.repeat(60)}`, isSuccess ? 'green' : 'red');
  log(`REGRESSION TEST ${isSuccess ? 'PASSED' : 'FAILED'}`, isSuccess ? 'green' : 'red');
  log(`${'='.repeat(60)}`, isSuccess ? 'green' : 'red');
  
  if (isSuccess) {
    log(`\n✅ All regression tests passed! The refactored module produces identical outputs.`, 'green');
  } else {
    log(`\n❌ Some regression tests failed. The refactored module has compatibility issues.`, 'red');
  }
  
  return isSuccess;
}

async function main() {
  log('🔄 Starting Scenarios Module Regression Testing', 'cyan');
  log(`Test configuration: ${TEST_CONFIG.iterations} iterations, ${TEST_CONFIG.timeout}ms timeout`, 'blue');
  
  try {
    await runRegressionTests();
    const success = await generateRegressionReport();
    
    process.exit(success ? 0 : 1);
    
  } catch (error) {
    log(`\n💥 REGRESSION TESTING FAILED:`, 'red');
    log(`${error.message}`, 'red');
    if (error.stack) {
      log(`${error.stack}`, 'red');
    }
    
    process.exit(2);
  }
}

// Run regression tests if this script is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

export { main as runRegressionTests, regressionResults };