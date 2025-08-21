/**
 * @fileoverview Scenarios tool implementations aggregation
 * Central export for all scenario-related tool creators
 */

// Re-export all tool creators that have been implemented
export { createListScenariosTools } from './list-scenarios.js';
export { createGetScenarioTool } from './get-scenario.js';
export { createCreateScenarioTool } from './create-scenario.js';
export { createUpdateScenarioTool } from './update-scenario.js';
export { createDeleteScenarioTool } from './delete-scenario.js';
export { createCloneScenarioTool } from './clone-scenario.js';

// Placeholder exports for tools that are still being implemented
// These will be uncommented as the tools are completed by other subagents
// export { createRunScenarioTool } from './run-scenario.js';
// export { createTroubleshootScenarioTool } from './troubleshoot-scenario.js';
// export { createGenerateTroubleshootingReportTool } from './generate-troubleshooting-report.js';
// export { createValidateBlueprintTool } from './validate-blueprint.js';
// export { createExtractBlueprintConnectionsTool } from './extract-blueprint-connections.js';
// export { createOptimizeBlueprintTool } from './optimize-blueprint.js';

/**
 * Collection of all tool creator functions for easy access
 */
export const ScenarioToolCreators = {
  // CRUD operations
  list: 'createListScenariosTools',
  get: 'createGetScenarioTool', 
  create: 'createCreateScenarioTool',
  update: 'createUpdateScenarioTool',
  delete: 'createDeleteScenarioTool',
  clone: 'createCloneScenarioTool',
  
  // Execution and analysis (being implemented)
  run: 'createRunScenarioTool',
  troubleshoot: 'createTroubleshootScenarioTool',
  report: 'createGenerateTroubleshootingReportTool',
  
  // Blueprint operations (being implemented)
  validate: 'createValidateBlueprintTool',
  extractConnections: 'createExtractBlueprintConnectionsTool',
  optimize: 'createOptimizeBlueprintTool'
} as const;