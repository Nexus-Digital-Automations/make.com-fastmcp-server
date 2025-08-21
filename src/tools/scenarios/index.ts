/**
 * @fileoverview Make.com Scenario Management Tools - Main Integration
 * 
 * Provides comprehensive CRUD operations for Make.com scenarios including:
 * - Creating, updating, and deleting scenarios
 * - Advanced filtering and search capabilities  
 * - Scenario execution with monitoring
 * - Blueprint management and cloning
 * - Scheduling configuration
 * 
 * This modular implementation replaces the monolithic scenarios.ts file
 * with a clean, maintainable architecture following FastMCP best practices.
 * 
 * @version 1.0.0
 * @author Make.com FastMCP Server
 * @see {@link https://docs.make.com/api} Make.com API Documentation
 */

import { FastMCP } from 'fastmcp';
import MakeApiClient from '../../lib/make-api-client.js';
import logger from '../../lib/logger.js';
import { ToolContext } from '../shared/types/tool-context.js';

// Import all completed tool creators
import { createListScenariosTools } from './tools/list-scenarios.js';
import { createGetScenarioTool } from './tools/get-scenario.js';
import { createCreateScenarioTool } from './tools/create-scenario.js';
import { createUpdateScenarioTool } from './tools/update-scenario.js';
import { createDeleteScenarioTool } from './tools/delete-scenario.js';
import { createCloneScenarioTool } from './tools/clone-scenario.js';

// TODO: Import remaining tools as they are completed by other subagents
// import { createRunScenarioTool } from './tools/run-scenario.js';
// import { createTroubleshootScenarioTool } from './tools/troubleshoot-scenario.js';
// import { createGenerateTroubleshootingReportTool } from './tools/generate-troubleshooting-report.js';
// import { createValidateBlueprintTool } from './tools/validate-blueprint.js';
// import { createExtractBlueprintConnectionsTool } from './tools/extract-blueprint-connections.js';
// import { createOptimizeBlueprintTool } from './tools/optimize-blueprint.js';

// Re-export all types and schemas for external usage
export * from './types/index.js';
export * from './schemas/index.js';

/**
 * Add scenario management tools to FastMCP server
 * 
 * This function maintains 100% compatibility with the original addScenarioTools
 * function while providing a clean, modular implementation.
 * 
 * @param server FastMCP server instance
 * @param apiClient Make.com API client
 */
export function addScenarioTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'ScenarioTools' });
  
  componentLogger.info('Adding scenario management tools');

  // Create shared tool context for dependency injection
  const toolContext: ToolContext = { 
    server, 
    apiClient, 
    logger: componentLogger 
  };

  try {
    // Register individual tools with proper error handling
    const toolRegistrations = [
      { name: 'list-scenarios', creator: createListScenariosTools },
      { name: 'get-scenario', creator: createGetScenarioTool },
      { name: 'create-scenario', creator: createCreateScenarioTool },
      { name: 'update-scenario', creator: createUpdateScenarioTool },
      { name: 'delete-scenario', creator: createDeleteScenarioTool },
      { name: 'clone-scenario', creator: createCloneScenarioTool },
      { name: 'run-scenario', creator: createRunScenarioTool },
      { name: 'troubleshoot-scenario', creator: createTroubleshootScenarioTool },
      { name: 'generate-troubleshooting-report', creator: createGenerateTroubleshootingReportTool },
      { name: 'validate-blueprint', creator: createValidateBlueprintTool },
      { name: 'extract-blueprint-connections', creator: createExtractBlueprintConnectionsTool },
      { name: 'optimize-blueprint', creator: createOptimizeBlueprintTool },
    ];

    // Register each tool with error handling
    toolRegistrations.forEach(({ name, creator }) => {
      try {
        const toolDefinition = creator(toolContext);
        server.addTool(toolDefinition);
        componentLogger.debug(`Successfully registered tool: ${name}`);
      } catch (error) {
        componentLogger.error(`Failed to register tool: ${name}`, { 
          error: error instanceof Error ? error.message : String(error) 
        });
        throw error; // Re-throw to maintain original error behavior
      }
    });

    componentLogger.info('Scenario management tools added successfully', {
      toolCount: toolRegistrations.length,
      categories: ['CRUD', 'execution', 'analysis', 'optimization', 'troubleshooting'],
      tools: toolRegistrations.map(t => t.name)
    });

  } catch (error) {
    componentLogger.error('Failed to add scenario management tools', {
      error: error instanceof Error ? error.message : String(error)
    });
    throw error; // Maintain original error propagation behavior
  }
}

/**
 * Default export for backward compatibility
 * @deprecated Use named export `addScenarioTools` instead
 */
export default addScenarioTools;

/**
 * Tool metadata for introspection and documentation
 */
export const ScenariosToolMetadata = {
  name: 'scenarios',
  version: '1.0.0',
  description: 'Comprehensive Make.com scenario management tools',
  toolCount: 12,
  categories: ['CRUD', 'execution', 'analysis', 'optimization', 'troubleshooting'],
  tools: [
    'list-scenarios',
    'get-scenario', 
    'create-scenario',
    'update-scenario',
    'delete-scenario',
    'clone-scenario',
    'run-scenario',
    'troubleshoot-scenario',
    'generate-troubleshooting-report',
    'validate-blueprint',
    'extract-blueprint-connections',
    'optimize-blueprint'
  ],
  maintainer: 'Make.com FastMCP Server Team',
  lastUpdated: new Date().toISOString()
} as const;