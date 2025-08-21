/**
 * @fileoverview Log Streaming Module Index
 * Main entry point for log streaming tools - modular architecture implementation
 */

import { FastMCP } from 'fastmcp';
import MakeApiClient from '../../lib/make-api-client.js';
import logger from '../../lib/logger.js';
import { ToolContext, createToolContextLogger } from '../shared/types/tool-context.js';

// Import individual tool creators
import { createGetScenarioRunLogsTool } from './tools/get-scenario-run-logs.js';
import { createQueryLogsByTimeRangeTool } from './tools/query-logs-by-timerange.js';
import { createStreamLiveExecutionTool } from './tools/stream-live-execution.js';
import { createExportLogsForAnalysisTool } from './tools/export-logs-for-analysis.js';

/**
 * Add all log streaming tools to the FastMCP server
 */
export function addLogStreamingTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'LogStreamingTools' });
  
  componentLogger.info('Initializing log streaming tools with modular architecture');

  // Create shared context for all tools
  const context: ToolContext = {
    server,
    apiClient,
    logger: createToolContextLogger(componentLogger),
  };

  try {
    // 1. Get Scenario Run Logs with Real-Time Streaming
    const getScenarioRunLogsTool = createGetScenarioRunLogsTool(context);
    server.addTool(getScenarioRunLogsTool);
    componentLogger.debug('Added get_scenario_run_logs tool');

    // 2. Query Logs by Time Range - Enhanced Historical Log Analysis
    const queryLogsByTimeRangeTool = createQueryLogsByTimeRangeTool(context);
    server.addTool(queryLogsByTimeRangeTool);
    componentLogger.debug('Added query_logs_by_timerange tool');

    // 3. Stream Live Execution
    const streamLiveExecutionTool = createStreamLiveExecutionTool(context);
    server.addTool(streamLiveExecutionTool);
    componentLogger.debug('Added stream_live_execution tool');

    // 4. Export Logs for Analysis with External System Integration
    const exportLogsForAnalysisTool = createExportLogsForAnalysisTool(context);
    server.addTool(exportLogsForAnalysisTool);
    componentLogger.debug('Added export_logs_for_analysis tool');

    componentLogger.info('Log streaming tools initialized successfully', {
      toolsAdded: 4,
      architecture: 'modular',
      version: '2.0.0',
    });

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    componentLogger.error('Failed to initialize log streaming tools', { error: errorMessage });
    throw new Error(`Log streaming tools initialization failed: ${errorMessage}`);
  }
}

// Default export for compatibility
export default addLogStreamingTools;

// Re-export types and schemas for external use
export * from './types/index.js';
export * from './schemas/index.js';
export * from './utils/stream-processor.js';