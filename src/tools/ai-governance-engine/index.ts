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
function addAssessRiskTool(server: FastMCP, apiClient: MakeApiClient, componentLogger: ReturnType<typeof logger.child>): void {
  server.addTool({
    name: 'assess-risk',
    description: 'Conduct comprehensive AI-powered risk assessment with predictive analytics',
    parameters: governanceTools.assessRisk.metadata.parameters,
    annotations: {
      title: 'AI Risk Assessment',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(componentLogger, server, apiClient, context);
      context.reportProgress({ progress: 25, total: 100 });
      
      const result = await governanceTools.assessRisk(toolContext, args);
      
      context.reportProgress({ progress: 100, total: 100 });
      
      if (result.error) {
        throw new Error(result.error);
      }
      
      return result.message || 'Risk assessment completed successfully';
    }
  });
}

function addConfigureAutomatedRemediationTool(server: FastMCP, apiClient: MakeApiClient, componentLogger: ReturnType<typeof logger.child>): void {
  server.addTool({
    name: 'configure-automated-remediation',
    description: 'Configure intelligent automated remediation workflows with escalation paths',
    parameters: governanceTools.configureAutomatedRemediation.metadata.parameters,
    annotations: {
      title: 'Automated Remediation Configuration',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(componentLogger, server, apiClient, context);
      context.reportProgress({ progress: 35, total: 100 });
      
      const result = await governanceTools.configureAutomatedRemediation(toolContext, args);
      
      context.reportProgress({ progress: 100, total: 100 });
      
      if (result.error) {
        throw new Error(result.error);
      }
      
      return result.message || 'Automated remediation configured successfully';
    }
  });
}

function addGenerateGovernanceInsightsTool(server: FastMCP, apiClient: MakeApiClient, componentLogger: ReturnType<typeof logger.child>): void {
  server.addTool({
    name: 'generate-governance-insights',
    description: 'Generate AI-powered governance insights with predictive analytics and recommendations',
    parameters: governanceTools.generateGovernanceInsights.metadata.parameters,
    annotations: {
      title: 'Governance Intelligence Dashboard',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(componentLogger, server, apiClient, context);
      context.reportProgress({ progress: 40, total: 100 });
      
      const result = await governanceTools.generateGovernanceInsights(toolContext, args);
      
      context.reportProgress({ progress: 100, total: 100 });
      
      if (result.error) {
        throw new Error(result.error);
      }
      
      return result.message || 'Governance insights generated successfully';
    }
  });
}

function addGenerateGovernanceDashboardTool(server: FastMCP, apiClient: MakeApiClient, componentLogger: ReturnType<typeof logger.child>): void {
  server.addTool({
    name: 'generate-governance-dashboard',
    description: 'Generate real-time governance intelligence dashboard with predictive analytics',
    parameters: governanceTools.generateGovernanceDashboard.metadata.parameters,
    annotations: {
      title: 'Governance Intelligence Dashboard',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(componentLogger, server, apiClient, context);
      context.reportProgress({ progress: 45, total: 100 });
      
      const result = await governanceTools.generateGovernanceDashboard(toolContext, args);
      
      context.reportProgress({ progress: 100, total: 100 });
      
      if (result.error) {
        throw new Error(result.error);
      }
      
      return result.message || 'Governance dashboard generated successfully';
    }
  });
}

function addOptimizePoliciesTool(server: FastMCP, apiClient: MakeApiClient, componentLogger: ReturnType<typeof logger.child>): void {
  server.addTool({
    name: 'optimize-policies',
    description: 'AI-powered policy optimization with simulation and impact analysis',
    parameters: governanceTools.optimizePolicies.metadata.parameters,
    annotations: {
      title: 'Policy Optimization Engine',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(componentLogger, server, apiClient, context);
      context.reportProgress({ progress: 50, total: 100 });
      
      const result = await governanceTools.optimizePolicies(toolContext, args);
      
      context.reportProgress({ progress: 100, total: 100 });
      
      if (result.error) {
        throw new Error(result.error);
      }
      
      return result.message || 'Policy optimization completed successfully';
    }
  });
}

/**
 * Add AI governance engine tools to FastMCP server
 * Uses the new modular architecture with AIGovernanceManager core business logic
 */
export function addAIGovernanceEngineTools(server: FastMCP, apiClient: MakeApiClient): void {
  const getComponentLogger = (): ReturnType<typeof logger.child> => {
    try {
      return logger.child({ component: 'AIGovernanceEngineTools' });
    } catch {
      // Fallback for test environments
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
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
