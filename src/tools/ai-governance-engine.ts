/**
 * AI-Driven Governance Engine for Make.com FastMCP Server
 * Updated to use modular architecture from ai-governance-engine module refactoring
 */

import { FastMCP } from 'fastmcp';
import { MakeApiClient } from '../lib/make-api-client.js';
import logger from '../lib/logger.js';

// Import the modular implementation from the refactored ai-governance-engine module
import { addAIGovernanceEngineTools as addModularGovernanceTools } from './ai-governance-engine/index.js';

/**
 * Add AI governance engine tools to FastMCP server
 * Uses the new modular architecture with AIGovernanceManager core business logic
 */
export function addAIGovernanceEngineTools(server: FastMCP, apiClient: MakeApiClient): void {
  const getComponentLogger = (): ReturnType<typeof logger.child> => {
    try {
      return logger.child({ component: 'AIGovernanceEngine' });
    } catch {
      // Fallback for test environments
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return logger as any;
    }
  };
  const componentLogger = getComponentLogger();
  
  componentLogger.info('Adding modular AI governance engine tools');
  
  // Use the new modular implementation
  addModularGovernanceTools(server, apiClient);
  
  componentLogger.info('Modular AI governance engine tools added successfully');
}

export default addAIGovernanceEngineTools;