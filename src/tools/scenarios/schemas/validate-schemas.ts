/**
 * @fileoverview Schema validation test script
 * @description Validates that all extracted schemas work correctly and maintain compatibility
 */

import { 
  // Filter schemas
  ScenarioFiltersSchema,
  ScenarioDetailSchema,
  RunScenarioSchema,
  TroubleshootScenarioSchema,
  GenerateTroubleshootingReportSchema,
  
  // Update schemas
  CreateScenarioSchema,
  UpdateScenarioSchema,
  DeleteScenarioSchema,
  CloneScenarioSchema,
  
  // Blueprint schemas
  ValidateBlueprintSchema,
  ExtractBlueprintConnectionsSchema,
  OptimizeBlueprintSchema,
  
  // Utilities
  ScenariosSchemas,
  SchemaValidation,
} from './index';

/**
 * Test data for schema validation
 */
const testData = {
  scenarioFilters: {
    teamId: 'team_123',
    folderId: 'folder_456',
    limit: 20,
    offset: 0,
    search: 'test scenario',
    active: true,
  },
  
  scenarioDetail: {
    scenarioId: 'scenario_123',
    includeBlueprint: true,
    includeExecutions: false,
  },
  
  runScenario: {
    scenarioId: 'scenario_123',
    wait: true,
    timeout: 120,
  },
  
  troubleshootScenario: {
    scenarioId: 'scenario_123',
    diagnosticTypes: ['health', 'performance'],
    includeRecommendations: true,
    severityFilter: 'warning' as const,
    timeRange: { hours: 48 },
  },
  
  generateReport: {
    scenarioIds: ['scenario_1', 'scenario_2'],
    reportOptions: {
      includeExecutiveSummary: true,
      formatType: 'json' as const,
    },
    analysisFilters: {
      timeRangeHours: 24,
      severityThreshold: 'warning' as const,
    },
  },
  
  createScenario: {
    name: 'Test Scenario',
    teamId: 'team_123',
    blueprint: { modules: [] },
    scheduling: {
      type: 'interval' as const,
      interval: 30,
    },
  },
  
  updateScenario: {
    scenarioId: 'scenario_123',
    name: 'Updated Scenario',
    active: false,
    blueprint: { modules: [], connections: [] },
  },
  
  deleteScenario: {
    scenarioId: 'scenario_123',
    force: true,
  },
  
  cloneScenario: {
    scenarioId: 'scenario_123',
    name: 'Cloned Scenario',
    active: false,
  },
  
  validateBlueprint: {
    blueprint: { modules: [], connections: [] },
    strict: true,
    includeSecurityChecks: true,
  },
  
  extractConnections: {
    blueprint: { modules: [], connections: [] },
    includeOptional: false,
    groupByModule: true,
  },
  
  optimizeBlueprint: {
    blueprint: { modules: [], connections: [] },
    optimizationType: 'performance' as const,
    includeImplementationSteps: true,
  },
};

/**
 * Schema validation test results
 */
interface ValidationResult {
  schema: string;
  success: boolean;
  error?: string;
  data?: unknown;
}

/**
 * Run validation tests for all schemas
 */
function runValidationTests(): ValidationResult[] {
  const results: ValidationResult[] = [];

  const tests = [
    { schema: 'ScenarioFiltersSchema', validator: ScenarioFiltersSchema, data: testData.scenarioFilters },
    { schema: 'ScenarioDetailSchema', validator: ScenarioDetailSchema, data: testData.scenarioDetail },
    { schema: 'RunScenarioSchema', validator: RunScenarioSchema, data: testData.runScenario },
    { schema: 'TroubleshootScenarioSchema', validator: TroubleshootScenarioSchema, data: testData.troubleshootScenario },
    { schema: 'GenerateTroubleshootingReportSchema', validator: GenerateTroubleshootingReportSchema, data: testData.generateReport },
    { schema: 'CreateScenarioSchema', validator: CreateScenarioSchema, data: testData.createScenario },
    { schema: 'UpdateScenarioSchema', validator: UpdateScenarioSchema, data: testData.updateScenario },
    { schema: 'DeleteScenarioSchema', validator: DeleteScenarioSchema, data: testData.deleteScenario },
    { schema: 'CloneScenarioSchema', validator: CloneScenarioSchema, data: testData.cloneScenario },
    { schema: 'ValidateBlueprintSchema', validator: ValidateBlueprintSchema, data: testData.validateBlueprint },
    { schema: 'ExtractBlueprintConnectionsSchema', validator: ExtractBlueprintConnectionsSchema, data: testData.extractConnections },
    { schema: 'OptimizeBlueprintSchema', validator: OptimizeBlueprintSchema, data: testData.optimizeBlueprint },
  ];

  for (const test of tests) {
    try {
      const result = test.validator.parse(test.data);
      results.push({
        schema: test.schema,
        success: true,
        data: result,
      });
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      results.push({
        schema: test.schema,
        success: false,
        error: errorMessage,
      });
    }
  }

  return results;
}

/**
 * Test schema utilities
 */
function testSchemaUtilities(): void {
  process.stderr.write('\n=== Testing Schema Utilities ===\n');
  
  // Test SchemaValidation.validate
  const validateResult = SchemaValidation.validate(ScenarioFiltersSchema, testData.scenarioFilters);
  process.stderr.write(`SchemaValidation.validate result: ${validateResult.success ? 'SUCCESS' : 'FAILED'}\n`);
  
  // Test SchemaValidation.safeParse
  const safeParseResult = SchemaValidation.safeParse(CreateScenarioSchema, testData.createScenario);
  process.stderr.write(`SchemaValidation.safeParse result: ${safeParseResult ? 'SUCCESS' : 'FAILED'}\n`);
  
  // Test ScenariosSchemas structure
  process.stderr.write(`ScenariosSchemas.filters keys: ${Object.keys(ScenariosSchemas.filters)}\n`);
  process.stderr.write(`ScenariosSchemas.updates keys: ${Object.keys(ScenariosSchemas.updates)}\n`);
  process.stderr.write(`ScenariosSchemas.blueprints keys: ${Object.keys(ScenariosSchemas.blueprints)}\n`);
}

/**
 * Main validation function
 */
export function validateExtractedSchemas(): boolean {
  process.stderr.write('=== Schema Extraction Validation ===\n');
  
  const results = runValidationTests();
  let allPassed = true;
  
  process.stderr.write('\n=== Validation Results ===\n');
  for (const result of results) {
    const status = result.success ? '✅ PASS' : '❌ FAIL';
    process.stderr.write(`${status} ${result.schema}\n`);
    if (!result.success) {
      process.stderr.write(`   Error: ${result.error}\n`);
      allPassed = false;
    }
  }
  
  testSchemaUtilities();
  
  process.stderr.write('\n=== Summary ===\n');
  process.stderr.write(`Total schemas tested: ${results.length}\n`);
  process.stderr.write(`Passed: ${results.filter(r => r.success).length}\n`);
  process.stderr.write(`Failed: ${results.filter(r => !r.success).length}\n`);
  process.stderr.write(`Overall result: ${allPassed ? '✅ ALL SCHEMAS VALID' : '❌ SOME SCHEMAS FAILED'}\n`);
  
  return allPassed;
}

// Run validation if called directly (ES module version)
if (import.meta.url === `file://${process.argv[1]}`) {
  const success = validateExtractedSchemas();
  process.exit(success ? 0 : 1);
}