/**
 * AI Governance Engine Module
 * Updated to use modular architecture from ai-governance-engine refactoring
 */

import { FastMCP } from 'fastmcp';
import { MakeApiClient } from '../../lib/make-api-client.js';
import logger from '../../lib/logger.js';

// Import the modular tools from the refactored governance engine
import { governanceTools } from './tools/index.js';

/**
 * Add AI governance engine tools to FastMCP server
 * Uses the new modular architecture with AIGovernanceManager core business logic
 */
export function addAIGovernanceEngineTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'AIGovernanceEngineTools' });
  
  componentLogger.info('Adding modular AI governance engine tools');

  // Create context for tools
  const createToolContext = (executionContext: { log: any; reportProgress: any }): any => ({
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
  });

  /**
   * Monitor Compliance Tool
   * Real-time compliance monitoring with predictive analytics and automated remediation
   */
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
      const toolContext = createToolContext(context);
      context.reportProgress({ progress: 20, total: 100 });
      
      const result = await governanceTools.monitorCompliance(toolContext, args);
      
      context.reportProgress({ progress: 100, total: 100 });
      
      if (result.error) {
        throw new Error(result.error);
      }
      
      // Handle content array properly for FastMCP compatibility
      if (result.content && Array.isArray(result.content)) {
        const textContent = result.content
          .filter(item => item.type === 'text' && item.text)
          .map(item => item.text)
          .join('\n\n');
        return textContent || result.message || 'Compliance monitoring completed successfully';
      }
      
      return result.message || 'Compliance monitoring completed successfully';
    }
  });

  /**
   * Analyze Policy Conflicts Tool
   * AI-powered policy conflict detection with automated resolution suggestions
   */
  server.addTool({
    name: 'analyze-policy-conflicts',
    description: 'Detect and analyze policy conflicts with AI-powered resolution suggestions',
    parameters: governanceTools.analyzePolicyConflicts.metadata.parameters,
    annotations: {
      title: 'Policy Conflict Analysis',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      context.reportProgress({ progress: 30, total: 100 });
      
      const result = await governanceTools.analyzePolicyConflicts(toolContext, args);
      
      context.reportProgress({ progress: 100, total: 100 });
      
      if (result.error) {
        throw new Error(result.error);
      }
      
      // Handle content array properly for FastMCP compatibility
      if (result.content && Array.isArray(result.content)) {
        const textContent = result.content
          .filter(item => item.type === 'text' && item.text)
          .map(item => item.text)
          .join('\n\n');
        return textContent || result.message || 'Policy conflict analysis completed successfully';
      }
      
      return result.message || 'Policy conflict analysis completed successfully';
    }
  });

  /**
   * Assess Risk Tool
   * Comprehensive AI-powered risk assessment with predictive analytics
   */
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
      const toolContext = createToolContext(context);
      context.reportProgress({ progress: 25, total: 100 });
      
      const result = await governanceTools.assessRisk(toolContext, args);
      
      context.reportProgress({ progress: 100, total: 100 });
      
      if (result.error) {
        throw new Error(result.error);
      }
      
      // Handle content array properly for FastMCP compatibility
      if (result.content && Array.isArray(result.content)) {
        const textContent = result.content
          .filter(item => item.type === 'text' && item.text)
          .map(item => item.text)
          .join('\n\n');
        return textContent || result.message || 'Risk assessment completed successfully';
      }
      
      return result.message || 'Risk assessment completed successfully';
    }
  });

  /**
   * Configure Automated Remediation Tool
   * Configure intelligent automated remediation workflows with escalation paths
   */
  server.addTool({
    name: 'configure-automated-remediation',
    description: 'Configure intelligent automated remediation workflows with escalation paths',
    parameters: governanceTools.configureAutomatedRemediation.metadata.parameters,
    annotations: {
      title: 'Automated Remediation Configuration',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      context.reportProgress({ progress: 40, total: 100 });
      
      const result = await governanceTools.configureAutomatedRemediation(toolContext, args);
      
      context.reportProgress({ progress: 100, total: 100 });
      
      if (result.error) {
        throw new Error(result.error);
      }
      
      // Handle content array properly for FastMCP compatibility
      if (result.content && Array.isArray(result.content)) {
        const textContent = result.content
          .filter(item => item.type === 'text' && item.text)
          .map(item => item.text)
          .join('\n\n');
        return textContent || result.message || 'Automated remediation configured successfully';
      }
      
      return result.message || 'Automated remediation configured successfully';
    }
  });

  /**
   * Generate Governance Insights Tool
   * Generate AI-powered governance insights with predictive analytics and recommendations
   */
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
      const toolContext = createToolContext(context);
      context.reportProgress({ progress: 35, total: 100 });
      
      const result = await governanceTools.generateGovernanceInsights(toolContext, args);
      
      context.reportProgress({ progress: 100, total: 100 });
      
      if (result.error) {
        throw new Error(result.error);
      }
      
      // Handle content array properly for FastMCP compatibility
      if (result.content && Array.isArray(result.content)) {
        const textContent = result.content
          .filter(item => item.type === 'text' && item.text)
          .map(item => item.text)
          .join('\n\n');
        return textContent || result.message || 'Governance insights generated successfully';
      }
      
      return result.message || 'Governance insights generated successfully';
    }
  });

  /**
   * Generate Governance Dashboard Tool
   * Generate real-time governance intelligence dashboard with predictive analytics
   */
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
      const toolContext = createToolContext(context);
      context.reportProgress({ progress: 30, total: 100 });
      
      const result = await governanceTools.generateGovernanceDashboard(toolContext, args);
      
      context.reportProgress({ progress: 100, total: 100 });
      
      if (result.error) {
        throw new Error(result.error);
      }
      
      // Handle content array properly for FastMCP compatibility
      if (result.content && Array.isArray(result.content)) {
        const textContent = result.content
          .filter(item => item.type === 'text' && item.text)
          .map(item => item.text)
          .join('\n\n');
        return textContent || result.message || 'Governance dashboard generated successfully';
      }
      
      return result.message || 'Governance dashboard generated successfully';
    }
  });

  /**
   * Optimize Policies Tool
   * AI-powered policy optimization with simulation and impact analysis
   */
  server.addTool({
    name: 'optimize-policies',
    description: 'AI-powered policy optimization with simulation and impact analysis',
    parameters: governanceTools.optimizePolicies.metadata.parameters,
    annotations: {
      title: 'Policy Optimization Engine',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      context.reportProgress({ progress: 45, total: 100 });
      
      const result = await governanceTools.optimizePolicies(toolContext, args);
      
      context.reportProgress({ progress: 100, total: 100 });
      
      if (result.error) {
        throw new Error(result.error);
      }
      
      // Handle content array properly for FastMCP compatibility
      if (result.content && Array.isArray(result.content)) {
        const textContent = result.content
          .filter(item => item.type === 'text' && item.text)
          .map(item => item.text)
          .join('\n\n');
        return textContent || result.message || 'Policy optimization completed successfully';
      }
      
      return result.message || 'Policy optimization completed successfully';
    }
  });

  componentLogger.info('Modular AI governance engine tools added successfully - 7 tools registered');
}

export default addAIGovernanceEngineTools;