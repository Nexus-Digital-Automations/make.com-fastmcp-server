/**
 * @fileoverview Make.com Scenario Management Tools - Modular Entry Point
 * 
 * This is the main export file for the refactored scenarios module.
 * It provides comprehensive scenario management functionality through
 * a modular architecture with dependency injection.
 * 
 * Key Features:
 * - CRUD operations for scenarios
 * - Advanced filtering and search
 * - Blueprint analysis and validation
 * - Optimization recommendations
 * - Comprehensive troubleshooting
 * - Performance analysis
 * 
 * @version 2.0.0 - Refactored modular architecture
 * @author Make.com FastMCP Server
 * @see {@link https://docs.make.com/api} Make.com API Documentation
 */

import { FastMCP } from 'fastmcp';
import MakeApiClient from '../../lib/make-api-client.js';
import logger from '../../lib/logger.js';
import { ToolContext } from '../shared/types/tool-context.js';

// Import all available tool creators - CRUD operations
import { createListScenariosTools } from './tools/list-scenarios.js';
import { createGetScenarioTool } from './tools/get-scenario.js';
import { createScenarioTool } from './tools/create-scenario.js';
import { createUpdateScenarioTool } from './tools/update-scenario.js';
import { createDeleteScenarioTool } from './tools/delete-scenario.js';
import { createCloneScenarioTool } from './tools/clone-scenario.js';

// Import execution and analysis tools
import { createRunScenarioTool } from './tools/run-scenario.js';
import { createTroubleshootScenarioTool } from './tools/troubleshoot-scenario.js';
import { createGenerateTroubleshootingReportTool } from './tools/generate-troubleshooting-report.js';

// Import blueprint tools
import { createValidateBlueprintTool } from './tools/validate-blueprint.js';
import { createExtractBlueprintConnectionsTool } from './tools/extract-blueprint-connections.js';
import { createOptimizeBlueprintTool } from './tools/optimize-blueprint.js';

// Import version information
import { VERSION_INFO } from './constants.js';

/**
 * Add all scenario management tools to FastMCP server
 * 
 * This function implements the modular tool registration pattern with
 * dependency injection, replacing the previous monolithic approach.
 * 
 * @param server - FastMCP server instance
 * @param apiClient - Make.com API client
 */
export function addScenarioTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ 
    component: 'ScenariosModule',
    version: VERSION_INFO.SCENARIOS_MODULE_VERSION 
  });
  
  componentLogger.info('Initializing modular scenario management tools', {
    moduleVersion: VERSION_INFO.SCENARIOS_MODULE_VERSION,
    apiVersion: VERSION_INFO.API_VERSION
  });

  // Create shared tool context for dependency injection
  const toolContext: ToolContext = { 
    server, 
    apiClient, 
    logger: componentLogger 
  };

  try {
    // Register CRUD operation tools
    componentLogger.debug('Registering CRUD operation tools');
    server.addTool(createListScenariosTools(toolContext));
    server.addTool(createGetScenarioTool(toolContext));
    server.addTool(createScenarioTool(toolContext));
    server.addTool(createUpdateScenarioTool(toolContext));
    server.addTool(createDeleteScenarioTool(toolContext));
    server.addTool(createCloneScenarioTool(toolContext));

    // Register execution and analysis tools
    componentLogger.debug('Registering execution and analysis tools');
    server.addTool(createRunScenarioTool(toolContext));
    server.addTool(createTroubleshootScenarioTool(toolContext));
    server.addTool(createGenerateTroubleshootingReportTool(toolContext));

    // Register blueprint tools
    componentLogger.debug('Registering blueprint manipulation tools');
    server.addTool(createValidateBlueprintTool(toolContext));
    server.addTool(createExtractBlueprintConnectionsTool(toolContext));
    server.addTool(createOptimizeBlueprintTool(toolContext));

    componentLogger.info('Scenario management tools registered successfully', {
      toolsRegistered: [
        'list-scenarios', 'get-scenario', 'create-scenario',
        'update-scenario', 'delete-scenario', 'clone-scenario',
        'run-scenario', 'troubleshoot-scenario', 'generate-troubleshooting-report',
        'validate-blueprint', 'extract-blueprint-connections', 'optimize-blueprint'
      ],
      totalTools: 12,
      totalExpected: 12,
      completionPercentage: 100,
      categories: [
        'CRUD operations', 'execution', 'analysis', 'troubleshooting', 'optimization'
      ],
      architecture: 'modular-with-dependency-injection',
      status: 'complete-implementation'
    });

  } catch (error) {
    componentLogger.error('Failed to register scenario management tools', {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined
    });
    throw error;
  }
}

/**
 * Export the main registration function as default for backward compatibility
 */
export default addScenarioTools;

/**
 * Re-export types and utilities for external use
 * Note: Selective exports to avoid duplicate naming conflicts
 */
export type * from './types/index.js';
export type * from './schemas/index.js';
export { ScenariosSchemas } from './schemas/index.js';
export { validateBlueprintStructure } from './utils/index.js';
export type { OptimizationMetrics } from './utils/index.js';

/**
 * Module metadata for introspection
 */
export const ScenariosModuleInfo = {
  name: 'scenarios',
  version: VERSION_INFO.SCENARIOS_MODULE_VERSION,
  description: 'Comprehensive Make.com scenario management with modular architecture',
  architecture: 'modular-dependency-injection',
  features: [
    'CRUD operations',
    'Advanced filtering',
    'Blueprint validation',
    'Performance optimization',
    'Comprehensive troubleshooting',
    'Executive reporting'
  ],
  toolCount: 10,
  migrationStatus: 'phase-1-complete',
  compatibility: {
    fastMCP: VERSION_INFO.COMPATIBILITY_VERSION,
    makeAPI: VERSION_INFO.API_VERSION
  }
} as const;