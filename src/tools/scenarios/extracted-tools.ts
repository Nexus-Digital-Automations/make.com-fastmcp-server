/**
 * @fileoverview Extracted First 7 Scenario Tools - Modular Architecture
 * 
 * This file provides the first 7 tools extracted from scenarios.ts monolith
 * following the modular architecture pattern from the TypeScript refactoring research.
 * 
 * Extracted Tools:
 * 1. list-scenarios - List and search scenarios with advanced filtering
 * 2. get-scenario - Get detailed scenario information with optional data expansion
 * 3. create-scenario - Create new scenarios with configuration options
 * 4. update-scenario - Update existing scenario configurations
 * 5. delete-scenario - Delete scenarios with safety checks
 * 6. clone-scenario - Clone scenarios with customizable options
 * 7. run-scenario - Execute scenarios with monitoring and timeout
 * 
 * @version 1.0.0 (Extracted from scenarios.ts)
 */

import { FastMCP } from 'fastmcp';
import MakeApiClient from '../../lib/make-api-client.js';
import logger from '../../lib/logger.js';
import { ToolContext } from '../shared/types/tool-context.js';

// Import individual extracted tools
import {
  createListScenariosTools,
  createGetScenarioTool,
  createScenarioTool,
  createUpdateScenarioTool,
  createDeleteScenarioTool,
  createCloneScenarioTool,
  createRunScenarioTool,
} from './tools/index.js';

/**
 * Add extracted scenario management tools to FastMCP server
 * 
 * This function registers only the first 7 tools extracted from the scenarios.ts
 * monolith, implementing the modular architecture pattern with dependency injection.
 * 
 * @param server - FastMCP server instance
 * @param apiClient - Make.com API client instance
 */
export function addExtractedScenarioTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'ExtractedScenarioTools' });
  
  componentLogger.info('Adding extracted scenario management tools (modular architecture)');

  // Create tool context with dependency injection
  const toolContext: ToolContext = { 
    server, 
    apiClient, 
    logger: componentLogger 
  };

  // Register extracted tools
  try {
    server.addTool(createListScenariosTools(toolContext));
    server.addTool(createGetScenarioTool(toolContext));
    server.addTool(createScenarioTool(toolContext));
    server.addTool(createUpdateScenarioTool(toolContext));
    server.addTool(createDeleteScenarioTool(toolContext));
    server.addTool(createCloneScenarioTool(toolContext));
    server.addTool(createRunScenarioTool(toolContext));

    componentLogger.info('Extracted scenario tools added successfully', {
      toolCount: 7,
      tools: [
        'list-scenarios',
        'get-scenario', 
        'create-scenario',
        'update-scenario',
        'delete-scenario',
        'clone-scenario',
        'run-scenario'
      ],
      categories: ['CRUD', 'execution'],
      architecture: 'modular',
      extractionSource: 'scenarios.ts monolith'
    });
  } catch (error) {
    componentLogger.error('Failed to add extracted scenario tools', { 
      error: error instanceof Error ? error.message : String(error)
    });
    throw error;
  }
}

export default addExtractedScenarioTools;