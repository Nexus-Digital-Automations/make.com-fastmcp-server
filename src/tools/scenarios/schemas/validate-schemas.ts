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
  console.log('\n=== Testing Schema Utilities ===');
  
  // Test SchemaValidation.validate
  const validateResult = SchemaValidation.validate(ScenarioFiltersSchema, testData.scenarioFilters);
  console.log('SchemaValidation.validate result:', validateResult.success ? 'SUCCESS' : 'FAILED');
  
  // Test SchemaValidation.safeParse
  const safeParseResult = SchemaValidation.safeParse(CreateScenarioSchema, testData.createScenario);
  console.log('SchemaValidation.safeParse result:', safeParseResult ? 'SUCCESS' : 'FAILED');
  
  // Test ScenariosSchemas structure
  console.log('ScenariosSchemas.filters keys:', Object.keys(ScenariosSchemas.filters));
  console.log('ScenariosSchemas.updates keys:', Object.keys(ScenariosSchemas.updates));
  console.log('ScenariosSchemas.blueprints keys:', Object.keys(ScenariosSchemas.blueprints));
}

/**
 * Main validation function
 */
export function validateExtractedSchemas(): boolean {
  console.log('=== Schema Extraction Validation ===');
  
  const results = runValidationTests();
  let allPassed = true;
  
  console.log('\n=== Validation Results ===');
  for (const result of results) {
    const status = result.success ? '✅ PASS' : '❌ FAIL';
    console.log(`${status} ${result.schema}`);
    if (!result.success) {
      console.log(`   Error: ${result.error}`);
      allPassed = false;
    }
  }
  
  testSchemaUtilities();
  
  console.log('\n=== Summary ===');
  console.log(`Total schemas tested: ${results.length}`);
  console.log(`Passed: ${results.filter(r => r.success).length}`);
  console.log(`Failed: ${results.filter(r => !r.success).length}`);
  console.log(`Overall result: ${allPassed ? '✅ ALL SCHEMAS VALID' : '❌ SOME SCHEMAS FAILED'}`);
  
  return allPassed;
}

// Run validation if called directly (ES module version)
if (import.meta.url === `file://${process.argv[1]}`) {
  const success = validateExtractedSchemas();
  process.exit(success ? 0 : 1);
}