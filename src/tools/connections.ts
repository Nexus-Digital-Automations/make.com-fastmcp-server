/**
 * @fileoverview Make.com Connection Management Tools Orchestrator
 * 
 * Main orchestrator for connection management tools that integrates:
 * - Connection CRUD operations (via connection-manager module)
 * - Webhook management (via webhook-manager module)
 * - Connection diagnostics and health monitoring (via diagnostics-manager module)
 * 
 * This module serves as the central entry point for all connection-related
 * functionality, providing a clean separation of concerns across specialized managers.
 * 
 * @version 1.0.0
 * @author Make.com FastMCP Server
 * @see {@link https://docs.make.com/api/connections} Make.com Connections API Documentation
 */

import { FastMCP } from 'fastmcp';
import MakeApiClient from '../lib/make-api-client.js';
import logger from '../lib/logger.js';
import { addConnectionCRUDTools } from './connections/connection-manager.js';
import { addWebhookTools } from './connections/webhook-manager.js';
import { addConnectionDiagnosticsTools } from './connections/diagnostics-manager.js';


/**
 * Adds comprehensive connection management tools to the FastMCP server
 * 
 * Orchestrates and integrates all connection-related functionality by delegating
 * to specialized managers for different aspects of connection management:
 * - Connection CRUD operations (connection-manager)
 * - Webhook management (webhook-manager)
 * - Connection diagnostics and monitoring (diagnostics-manager)
 * 
 * @param {FastMCP} server - The FastMCP server instance
 * @param {MakeApiClient} apiClient - Make.com API client with rate limiting and error handling
 * @returns {void}
 * 
 * @example
 * ```typescript
 * import { addConnectionTools } from './tools/connections.js';
 * 
 * const server = new FastMCP();
 * const apiClient = new MakeApiClient(config);
 * addConnectionTools(server, apiClient);
 * ```
 */
export function addConnectionTools(server: FastMCP, apiClient: MakeApiClient): void {
  const getComponentLogger = () => {
    try {
      return logger.child({ component: 'ConnectionTools' });
    } catch (error) {
      // Fallback for test environments
      return logger as any;
    }
  };
  const componentLogger = getComponentLogger();
  
  componentLogger.info('Adding connection management tools');

  // Add connection CRUD tools from the connection-manager module
  addConnectionCRUDTools(server, apiClient);

  // Add webhook management tools from the webhook-manager module
  addWebhookTools(server, apiClient);

  // Add connection diagnostics tools from the diagnostics-manager module
  addConnectionDiagnosticsTools(server, apiClient);


  componentLogger.info('Connection management tools added successfully', {
    modules: ['connection-manager', 'webhook-manager', 'diagnostics-manager']
  });
}


export default addConnectionTools;