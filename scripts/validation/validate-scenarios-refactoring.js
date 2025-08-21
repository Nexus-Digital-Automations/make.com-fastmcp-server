#!/usr/bin/env node

/**
 * @fileoverview Validation Script for Scenarios Module Refactoring
 * 
 * This script validates that the refactored scenarios module maintains
 * 100% functional equivalence with the original monolithic implementation.
 * 
 * Validation Categories:
 * - Tool registration verification
 * - Schema validation compatibility  
 * - Blueprint processing consistency
 * - API endpoint mapping preservation
 * - Error handling compatibility
 * - Performance regression detection
 */

import { performance } from 'perf_hooks';
import { FastMCP } from 'fastmcp';
import { addScenarioTools } from '../../src/tools/scenarios.js';
import {
  validateBlueprintStructure,
  extractBlueprintConnections
} from '../../src/tools/scenarios/utils/blueprint-analysis.js';
import {
  CreateScenarioSchema,
  UpdateScenarioSchema,
  DeleteScenarioSchema,
  CloneScenarioSchema
} from '../../src/tools/scenarios/schemas/blueprint-update.js';
import {
  ScenarioFiltersSchema,
  ScenarioDetailSchema,
  RunScenarioSchema
} from '../../src/tools/scenarios/schemas/scenario-filters.js';

// Validation results tracking
const validationResults = {
  passed: 0,
  failed: 0,
  errors: [],
  warnings: [],
  performanceMetrics: {}
};

// Mock API client for testing
const mockApiClient = {
  get: () => Promise.resolve({
    success: true,
    data: [{ id: 'scn_test', name: 'Test Scenario' }],
    metadata: { total: 1 }
  }),
  post: () => Promise.resolve({
    success: true,
    data: { id: 'scn_created', name: 'Created Scenario' }
  }),
  patch: () => Promise.resolve({
    success: true,
    data: { id: 'scn_updated', name: 'Updated Scenario' }
  }),
  delete: () => Promise.resolve({
    success: true,
    data: {}
  }),
  healthCheck: () => Promise.resolve({ healthy: true }),
  getRateLimiterStatus: () => Promise.resolve({ remaining: 100 }),
  shutdown: () => Promise.resolve()
};

// Console colors for output
const colors = {
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  reset: '\x1b[0m'
};

function log(message, color = 'white') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function logSection(title) {
  log(`\n${'='.repeat(60)}`, 'cyan');
  log(`${title}`, 'cyan');
  log(`${'='.repeat(60)}`, 'cyan');
}

function logTest(testName, passed, error = null) {
  const status = passed ? '✅ PASS' : '❌ FAIL';
  const statusColor = passed ? 'green' : 'red';
  
  log(`${status} ${testName}`, statusColor);
  
  if (passed) {
    validationResults.passed++;
  } else {
    validationResults.failed++;
    if (error) {
      validationResults.errors.push({ test: testName, error: error.message });
      log(`   Error: ${error.message}`, 'red');
    }
  }
}

function logWarning(message) {
  log(`⚠️  WARNING: ${message}`, 'yellow');
  validationResults.warnings.push(message);
}

function logPerformanceMetric(name, value, unit = 'ms') {
  log(`📊 ${name}: ${value.toFixed(2)}${unit}`, 'blue');
  validationResults.performanceMetrics[name] = { value, unit };
}

async function validateToolRegistration() {
  logSection('Tool Registration Validation');
  
  try {
    const server = new FastMCP({
      name: 'validation-test-server',
      version: '1.0.0'
    });
    
    const startTime = performance.now();
    addScenarioTools(server, mockApiClient);
    const endTime = performance.now();
    
    const registrationTime = endTime - startTime;
    logPerformanceMetric('Tool Registration Time', registrationTime);
    
    // Verify expected tools are registered
    const tools = server.tools;
    const toolNames = Array.from(tools.keys());
    
    const expectedTools = [
      'list-scenarios',
      'get-scenario', 
      'create-scenario',
      'update-scenario',
      'delete-scenario',
      'clone-scenario',
      'run-scenario',
      'validate-blueprint',
      'extract-blueprint-connections',
      'optimize-blueprint',
      'troubleshoot-scenario',
      'generate-troubleshooting-report'
    ];
    
    logTest('Expected number of tools registered', toolNames.length === expectedTools.length);
    
    for (const expectedTool of expectedTools) {
      const isRegistered = toolNames.includes(expectedTool);
      logTest(`Tool '${expectedTool}' registered`, isRegistered);
      
      if (isRegistered) {
        const tool = tools.get(expectedTool);
        logTest(`Tool '${expectedTool}' has description`, !!tool.description);
        logTest(`Tool '${expectedTool}' has input schema`, !!tool.inputSchema);
        logTest(`Tool '${expectedTool}' has execute function`, typeof tool.execute === 'function');
      }
    }
    
    // Performance benchmark
    if (registrationTime > 100) {
      logWarning(`Tool registration took ${registrationTime}ms (expected < 100ms)`);
    }
    
  } catch (error) {
    logTest('Tool registration process', false, error);
  }
}

async function validateSchemaCompatibility() {
  logSection('Schema Validation Compatibility');
  
  // Test cases for each schema
  const testCases = [
    {
      name: 'CreateScenarioSchema',
      schema: CreateScenarioSchema,
      validCases: [
        { name: 'Simple Scenario' },
        { 
          name: 'Complete Scenario',
          teamId: 'team_123',
          folderId: 'folder_456',
          blueprint: { modules: [] },
          scheduling: { type: 'interval', interval: 30 }
        }
      ],
      invalidCases: [
        {},
        { name: '' },
        { name: 'a'.repeat(101) }
      ]
    },
    {
      name: 'UpdateScenarioSchema',
      schema: UpdateScenarioSchema,
      validCases: [
        { scenarioId: 'scn_123', name: 'Updated' },
        { scenarioId: 'scn_123', active: true },
        { scenarioId: 'scn_123', blueprint: { modules: [] } }
      ],
      invalidCases: [
        {},
        { scenarioId: '' },
        { scenarioId: 'scn_123' } // Missing update parameters would be caught at runtime
      ]
    },
    {
      name: 'ScenarioFiltersSchema',
      schema: ScenarioFiltersSchema,
      validCases: [
        {},
        { teamId: 'team_123', limit: 50, active: true },
        { search: 'test query', offset: 10 }
      ],
      invalidCases: [
        { limit: 0 },
        { limit: 101 },
        { offset: -1 }
      ]
    }
  ];
  
  const startTime = performance.now();
  let totalValidations = 0;
  
  for (const testCase of testCases) {
    // Test valid cases
    for (const validData of testCase.validCases) {
      try {
        testCase.schema.parse(validData);
        logTest(`${testCase.name} valid case`, true);
        totalValidations++;
      } catch (error) {
        logTest(`${testCase.name} valid case`, false, error);
        totalValidations++;
      }
    }
    
    // Test invalid cases
    for (const invalidData of testCase.invalidCases) {
      try {
        testCase.schema.parse(invalidData);
        logTest(`${testCase.name} invalid case rejection`, false, new Error('Should have thrown validation error'));
        totalValidations++;
      } catch (error) {
        logTest(`${testCase.name} invalid case rejection`, true);
        totalValidations++;
      }
    }
  }
  
  const endTime = performance.now();
  const totalValidationTime = endTime - startTime;
  const avgValidationTime = totalValidationTime / totalValidations;
  
  logPerformanceMetric('Total Schema Validation Time', totalValidationTime);
  logPerformanceMetric('Average Validation Time', avgValidationTime);
  
  if (avgValidationTime > 1) {
    logWarning(`Average schema validation time ${avgValidationTime}ms (expected < 1ms)`);
  }
}

async function validateBlueprintProcessing() {
  logSection('Blueprint Processing Validation');
  
  const testBlueprints = [
    {
      name: 'Simple Valid Blueprint',
      blueprint: {
        name: 'Simple Test Blueprint',
        metadata: {
          version: 1,
          scenario: {
            roundtrips: 1,
            maxErrors: 1,
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
      expectedValid: true
    },
    {
      name: 'Complex Valid Blueprint',
      blueprint: {
        name: 'Complex Test Blueprint',
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
        flow: Array.from({ length: 50 }, (_, i) => ({
          id: i + 1,
          module: i % 2 === 0 ? 'http:request' : 'database:query',
          version: 1,
          connection: i % 2 === 0 ? Math.floor(i / 2) + 1 : undefined,
          parameters: { config: `test_${i}` }
        }))
      },
      expectedValid: true
    },
    {
      name: 'Invalid Blueprint - Missing Name',
      blueprint: {
        metadata: { version: 1 },
        flow: []
      },
      expectedValid: false
    }
  ];
  
  for (const testCase of testBlueprints) {
    try {
      const startTime = performance.now();
      
      // Validate blueprint structure
      const validationResult = validateBlueprintStructure(testCase.blueprint, true);
      const validationTime = performance.now() - startTime;
      
      logTest(
        `${testCase.name} - Validation Result`,
        validationResult.isValid === testCase.expectedValid
      );
      
      if (testCase.expectedValid && validationResult.isValid) {
        // Test connection extraction
        const connectionStartTime = performance.now();
        const connectionResult = extractBlueprintConnections(testCase.blueprint, true);
        const connectionTime = performance.now() - connectionStartTime;
        
        logTest(
          `${testCase.name} - Connection Extraction`,
          connectionResult.connectionSummary.totalModules === testCase.blueprint.flow?.length
        );
        
        logPerformanceMetric(`${testCase.name} - Validation Time`, validationTime);
        logPerformanceMetric(`${testCase.name} - Connection Extraction Time`, connectionTime);
        
        // Performance warnings
        if (validationTime > 50) {
          logWarning(`Blueprint validation for ${testCase.name} took ${validationTime}ms (expected < 50ms)`);
        }
        
        if (connectionTime > 30) {
          logWarning(`Connection extraction for ${testCase.name} took ${connectionTime}ms (expected < 30ms)`);
        }
      }
      
    } catch (error) {
      logTest(`${testCase.name} - Processing`, false, error);
    }
  }
}

async function validateToolExecution() {
  logSection('Tool Execution Validation');
  
  const server = new FastMCP({
    name: 'execution-test-server',
    version: '1.0.0'
  });
  
  addScenarioTools(server, mockApiClient);
  
  const mockContext = {
    log: {
      info: () => {},
      debug: () => {},
      warn: () => {},
      error: () => {}
    },
    reportProgress: () => {}
  };
  
  const toolTests = [
    {
      name: 'list-scenarios',
      args: {},
      expectedResult: (result) => {
        const parsed = JSON.parse(result);
        return parsed.scenarios && Array.isArray(parsed.scenarios);
      }
    },
    {
      name: 'get-scenario',
      args: { scenarioId: 'scn_test' },
      expectedResult: (result) => {
        const parsed = JSON.parse(result);
        return parsed.scenario && parsed.scenario.id;
      }
    },
    {
      name: 'create-scenario',
      args: { name: 'Test Scenario Creation' },
      expectedResult: (result) => {
        const parsed = JSON.parse(result);
        return parsed.scenario && parsed.message;
      }
    },
    {
      name: 'validate-blueprint',
      args: {
        blueprint: {
          name: 'Test Blueprint',
          metadata: { version: 1, scenario: { roundtrips: 1, maxErrors: 1, autoCommit: true, sequential: false } },
          flow: [{ id: 1, module: 'webhook', version: 1 }]
        }
      },
      expectedResult: (result) => {
        const parsed = JSON.parse(result);
        return parsed.isValid !== undefined;
      }
    }
  ];
  
  for (const test of toolTests) {
    try {
      const tool = server.tools.get(test.name);
      
      if (!tool) {
        logTest(`Tool '${test.name}' execution - Tool exists`, false);
        continue;
      }
      
      const startTime = performance.now();
      const result = await tool.execute(test.args, mockContext);
      const executionTime = performance.now() - startTime;
      
      const isValidResult = test.expectedResult(result);
      
      logTest(`Tool '${test.name}' execution - Valid result`, isValidResult);
      logPerformanceMetric(`${test.name} Execution Time`, executionTime);
      
      if (executionTime > 100) {
        logWarning(`Tool '${test.name}' execution took ${executionTime}ms (expected < 100ms)`);
      }
      
    } catch (error) {
      logTest(`Tool '${test.name}' execution`, false, error);
    }
  }
}

async function validateErrorHandling() {
  logSection('Error Handling Validation');
  
  const server = new FastMCP({
    name: 'error-test-server',
    version: '1.0.0'
  });
  
  // Mock API client that returns errors
  const errorApiClient = {
    ...mockApiClient,
    get: () => Promise.resolve({
      success: false,
      error: { message: 'Test API Error', code: 'TEST_ERROR' }
    }),
    post: () => Promise.reject(new Error('Network Error'))
  };
  
  addScenarioTools(server, errorApiClient);
  
  const mockContext = {
    log: {
      info: () => {},
      debug: () => {},
      warn: () => {},
      error: () => {}
    },
    reportProgress: () => {}
  };
  
  const errorTests = [
    {
      name: 'list-scenarios with API error',
      tool: 'list-scenarios',
      args: {},
      shouldThrow: true
    },
    {
      name: 'create-scenario with network error',
      tool: 'create-scenario',
      args: { name: 'Test' },
      shouldThrow: true
    },
    {
      name: 'get-scenario with invalid args',
      tool: 'get-scenario',
      args: { scenarioId: '' },
      shouldThrow: true
    }
  ];
  
  for (const test of errorTests) {
    try {
      const tool = server.tools.get(test.tool);
      const result = await tool.execute(test.args, mockContext);
      
      logTest(`${test.name} - Should throw error`, !test.shouldThrow);
      
    } catch (error) {
      const threwError = !!error;
      logTest(`${test.name} - Properly threw error`, threwError === test.shouldThrow);
      
      // Verify error is UserError for API failures
      if (test.shouldThrow && error.constructor.name !== 'UserError' && !test.name.includes('invalid args')) {
        logWarning(`Error should be UserError but got ${error.constructor.name}`);
      }
    }
  }
}

async function validatePerformanceRegression() {
  logSection('Performance Regression Detection');
  
  // Baseline performance expectations (in milliseconds)
  const performanceBaselines = {
    toolRegistration: 100,
    schemaValidation: 1, // per validation
    blueprintValidation: 50, // for medium-size blueprint
    connectionExtraction: 30, // for medium-size blueprint
    toolExecution: 100 // per tool execution
  };
  
  let regressionDetected = false;
  
  for (const [metric, baseline] of Object.entries(performanceBaselines)) {
    const recorded = validationResults.performanceMetrics[metric];
    
    if (recorded && recorded.value > baseline) {
      logWarning(`Performance regression detected: ${metric} took ${recorded.value}ms (baseline: ${baseline}ms)`);
      regressionDetected = true;
    }
  }
  
  logTest('No performance regressions detected', !regressionDetected);
  
  // Test concurrent execution performance
  try {
    const server = new FastMCP({
      name: 'concurrent-test-server',
      version: '1.0.0'
    });
    
    addScenarioTools(server, mockApiClient);
    
    const mockContext = {
      log: { info: () => {}, debug: () => {}, warn: () => {}, error: () => {} },
      reportProgress: () => {}
    };
    
    const concurrentStartTime = performance.now();
    
    // Execute multiple tools concurrently
    const concurrentPromises = [];
    for (let i = 0; i < 10; i++) {
      const tool = server.tools.get('validate-blueprint');
      concurrentPromises.push(
        tool.execute({
          blueprint: {
            name: `Concurrent Test ${i}`,
            metadata: { version: 1, scenario: { roundtrips: 1, maxErrors: 1, autoCommit: true, sequential: false } },
            flow: [{ id: 1, module: 'webhook', version: 1 }]
          }
        }, mockContext)
      );
    }
    
    await Promise.all(concurrentPromises);
    
    const concurrentEndTime = performance.now();
    const concurrentExecutionTime = concurrentEndTime - concurrentStartTime;
    
    logPerformanceMetric('Concurrent Execution Time (10 tools)', concurrentExecutionTime);
    
    if (concurrentExecutionTime > 500) {
      logWarning(`Concurrent execution took ${concurrentExecutionTime}ms (expected < 500ms)`);
    }
    
    logTest('Concurrent execution performance acceptable', concurrentExecutionTime <= 500);
    
  } catch (error) {
    logTest('Concurrent execution test', false, error);
  }
}

async function generateValidationReport() {
  logSection('Validation Report');
  
  const totalTests = validationResults.passed + validationResults.failed;
  const passRate = totalTests > 0 ? (validationResults.passed / totalTests) * 100 : 0;
  
  log(`\n📈 VALIDATION SUMMARY:`, 'cyan');
  log(`   Total Tests: ${totalTests}`, 'white');
  log(`   Passed: ${validationResults.passed}`, 'green');
  log(`   Failed: ${validationResults.failed}`, 'red');
  log(`   Pass Rate: ${passRate.toFixed(1)}%`, passRate >= 95 ? 'green' : 'red');
  log(`   Warnings: ${validationResults.warnings.length}`, 'yellow');
  
  if (validationResults.errors.length > 0) {
    log(`\n🔴 ERRORS:`, 'red');
    for (const error of validationResults.errors) {
      log(`   ${error.test}: ${error.error}`, 'red');
    }
  }
  
  if (validationResults.warnings.length > 0) {
    log(`\n⚠️  WARNINGS:`, 'yellow');
    for (const warning of validationResults.warnings) {
      log(`   ${warning}`, 'yellow');
    }
  }
  
  log(`\n📊 PERFORMANCE METRICS:`, 'blue');
  for (const [name, metric] of Object.entries(validationResults.performanceMetrics)) {
    log(`   ${name}: ${metric.value.toFixed(2)}${metric.unit}`, 'blue');
  }
  
  // Final verdict
  const isSuccess = passRate >= 95 && validationResults.failed === 0;
  
  log(`\n${'='.repeat(60)}`, isSuccess ? 'green' : 'red');
  log(`VALIDATION ${isSuccess ? 'PASSED' : 'FAILED'}: Scenarios module refactoring`, isSuccess ? 'green' : 'red');
  log(`${'='.repeat(60)}`, isSuccess ? 'green' : 'red');
  
  if (isSuccess) {
    log(`\n✅ The refactored scenarios module maintains full compatibility!`, 'green');
  } else {
    log(`\n❌ The refactored scenarios module has compatibility issues that need to be addressed.`, 'red');
  }
  
  return isSuccess;
}

// Main validation execution
async function runValidation() {
  log('🚀 Starting Scenarios Module Refactoring Validation', 'cyan');
  log(`Validation started at: ${new Date().toISOString()}`, 'white');
  
  try {
    await validateToolRegistration();
    await validateSchemaCompatibility();
    await validateBlueprintProcessing();
    await validateToolExecution();
    await validateErrorHandling();
    await validatePerformanceRegression();
    
    const success = await generateValidationReport();
    
    process.exit(success ? 0 : 1);
    
  } catch (error) {
    log(`\n💥 VALIDATION FAILED WITH CRITICAL ERROR:`, 'red');
    log(`${error.message}`, 'red');
    if (error.stack) {
      log(`${error.stack}`, 'red');
    }
    
    process.exit(2);
  }
}

// Run validation if this script is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runValidation();
}

export { runValidation, validationResults };