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

// Import all tool creators
import {
  createListScenariosTools,
  createScenarioTool,
  createCreateScenarioTool,
  createUpdateScenarioTool,
  createDeleteScenarioTool,
  createCloneScenarioTool,
  createAnalyzeBlueprintTool,
  createOptimizeBlueprintTool,
  createTroubleshootScenarioTool,
  createGenerateTroubleshootingReportTool
} from './tools/index.js';

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
    server.addTool(createScenarioTool(toolContext));
    server.addTool(createCreateScenarioTool(toolContext));
    server.addTool(createUpdateScenarioTool(toolContext));
    server.addTool(createDeleteScenarioTool(toolContext));
    server.addTool(createCloneScenarioTool(toolContext));

    // Register analysis and optimization tools
    componentLogger.debug('Registering analysis and optimization tools');
    server.addTool(createAnalyzeBlueprintTool(toolContext));
    server.addTool(createOptimizeBlueprintTool(toolContext));

    // Register troubleshooting and diagnostic tools
    componentLogger.debug('Registering troubleshooting tools');
    server.addTool(createTroubleshootScenarioTool(toolContext));
    server.addTool(createGenerateTroubleshootingReportTool(toolContext));

    componentLogger.info('Scenario management tools registered successfully', {
      toolsRegistered: [
        'list-scenarios',
        'get-scenario',
        'create-scenario',
        'update-scenario',
        'delete-scenario',
        'clone-scenario',
        'analyze-blueprint',
        'optimize-blueprint',
        'troubleshoot-scenario',
        'generate-troubleshooting-report'
      ],
      totalTools: 10,
      categories: [
        'CRUD operations',
        'blueprint analysis', 
        'optimization',
        'troubleshooting',
        'diagnostics'
      ],
      architecture: 'modular-with-dependency-injection'
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
 */
export * from './types/index.js';
export * from './schemas/index.js';
export * from './utils/index.js';
export * from './constants.js';

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