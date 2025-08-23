/**
 * AI Governance Engine Module
 * Updated to use modular architecture from ai-governance-engine refactoring
 */

import { FastMCP } from 'fastmcp';
import { MakeApiClient } from '../../lib/make-api-client.js';
import logger from '../../lib/logger.js';

// Import the modular tools from the refactored governance engine
import { governanceTools } from './tools/index.js';

interface GovernanceToolContext {
  server: FastMCP;
  apiClient: MakeApiClient;
  logger: typeof logger;
  log: {
    debug: (message: string, data?: unknown) => void;
    info: (message: string, data?: unknown) => void;
    warn: (message: string, data?: unknown) => void;
    error: (message: string, data?: unknown) => void;
  };
  reportProgress: (progress: { progress: number; total: number }) => void;
  config: {
    enabled: boolean;
    maxRetries: number;
    timeout: number;
  };
}

// ==================== HELPER FUNCTIONS ====================

/**
 * Create tool context for governance operations
 */
function createToolContext(
  componentLogger: ReturnType<typeof logger.child>,
  server: FastMCP,
  apiClient: MakeApiClient,
  executionContext: { 
    log: { 
      debug: (message: string, data?: unknown) => void; 
      info: (message: string, data?: unknown) => void; 
      warn: (message: string, data?: unknown) => void; 
      error: (message: string, data?: unknown) => void; 
    }; 
    reportProgress: (progress: { progress: number; total: number }) => void 
  }
): GovernanceToolContext {
  return {
    server,
    apiClient,
    logger: componentLogger,
    log: executionContext.log,
    reportProgress: executionContext.reportProgress,
    config: {
      enabled: true,
      maxRetries: 3,
      timeout: 60000
    }
  };
}

/**
 * Add monitor compliance tool
 */
function addMonitorComplianceTool(server: FastMCP, apiClient: MakeApiClient, componentLogger: ReturnType<typeof logger.child>): void {
  server.addTool({
    name: 'monitor-compliance',
    description: 'Monitor compliance across multiple frameworks with real-time alerts and predictive analytics',
    parameters: governanceTools.monitorCompliance.metadata.parameters,
    annotations: {
      title: 'AI-Powered Compliance Monitoring',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(componentLogger, server, apiClient, context);
      context.reportProgress({ progress: 20, total: 100 });
      
      const result = await governanceTools.monitorCompliance(toolContext, args);
      
      context.reportProgress({ progress: 100, total: 100 });
      
      if (result.error) {
        throw new Error(result.error);
      }
      
      return result.message || 'Compliance monitoring completed successfully';
    }
  });
}

/**
 * Add analyze policy conflicts tool
 */
function addAnalyzePolicyConflictsTool(server: FastMCP, apiClient: MakeApiClient, componentLogger: ReturnType<typeof logger.child>): void {
  server.addTool({
    name: 'analyze-policy-conflicts',
    description: 'Analyze policy conflicts and recommend resolution strategies using AI-powered conflict detection',
    parameters: governanceTools.analyzePolicyConflicts.metadata.parameters,
    annotations: {
      title: 'AI Policy Conflict Analysis',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(componentLogger, server, apiClient, context);
      context.reportProgress({ progress: 30, total: 100 });
      
      const result = await governanceTools.analyzePolicyConflicts(toolContext, args);
      
      context.reportProgress({ progress: 100, total: 100 });
      
      if (result.error) {
        throw new Error(result.error);
      }
      
      return result.message || 'Policy conflict analysis completed successfully';
    }
  });
}

/**
 * Add remaining governance tool helper functions
 */
function addAssessRiskTool(_server: FastMCP, _apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  // TODO: Implement this helper function
}

function addConfigureAutomatedRemediationTool(_server: FastMCP, _apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  // TODO: Implement this helper function
}

function addGenerateGovernanceInsightsTool(_server: FastMCP, _apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  // TODO: Implement this helper function
}

function addGenerateGovernanceDashboardTool(_server: FastMCP, _apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  // TODO: Implement this helper function
}

function addOptimizePoliciesTool(_server: FastMCP, _apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  // TODO: Implement this helper function
}

/**
 * Add AI governance engine tools to FastMCP server
 * Uses the new modular architecture with AIGovernanceManager core business logic
 */
export function addAIGovernanceEngineTools(server: FastMCP, apiClient: MakeApiClient): void {
  const getComponentLogger = () => {
    try {
      return logger.child({ component: 'AIGovernanceEngineTools' });
    } catch (error) {
      // Fallback for test environments
      return logger as any;
    }
  };
  const componentLogger = getComponentLogger();
  
  componentLogger.info('Adding modular AI governance engine tools');

  // Register all governance tools using helper functions
  addMonitorComplianceTool(server, apiClient, componentLogger);
  addAnalyzePolicyConflictsTool(server, apiClient, componentLogger);
  addAssessRiskTool(server, apiClient, componentLogger);
  addConfigureAutomatedRemediationTool(server, apiClient, componentLogger);
  addGenerateGovernanceInsightsTool(server, apiClient, componentLogger);
  addGenerateGovernanceDashboardTool(server, apiClient, componentLogger);
  addOptimizePoliciesTool(server, apiClient, componentLogger);

  componentLogger.info('Modular AI governance engine tools added successfully');
}

export default addAIGovernanceEngineTools;
