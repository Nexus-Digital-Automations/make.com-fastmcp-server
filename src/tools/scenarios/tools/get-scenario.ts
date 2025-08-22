/**
 * @fileoverview Get Scenario Tool Implementation
 * Retrieves detailed information about a specific Make.com scenario
 */

import { UserError } from 'fastmcp';
import { ScenarioDetailSchema } from '../schemas/scenario-filters.js';
import { ToolContext, ToolDefinition } from '../../shared/types/tool-context.js';
import { formatSuccessResponse } from '../../../utils/response-formatter.js';

/**
 * Create get scenario tool configuration
 */
export function createGetScenarioTool(context: ToolContext): ToolDefinition {
  const { apiClient } = context;
  
  return {
    name: 'get-scenario',
    description: 'Get detailed information about a specific Make.com scenario',
    parameters: ScenarioDetailSchema,
    annotations: {
      title: 'Get Scenario Details',
      readOnlyHint: true,
      openWorldHint: false,
    },
    execute: async (args: unknown, context): Promise<string> => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} }, reportProgress = (): void => {} } = context || {};
      const typedArgs = args as { scenarioId: string; includeBlueprint?: boolean; includeExecutions?: boolean };
      log?.info?.('Getting scenario details', { scenarioId: typedArgs.scenarioId });
      reportProgress?.({ progress: 0, total: 100 });

      try {
        const response = await apiClient.get(`/scenarios/${typedArgs.scenarioId}`);
        reportProgress?.({ progress: 50, total: 100 });

        if (!response.success) {
          throw new UserError(`Failed to get scenario: ${response.error?.message}`);
        }

        const scenario = response.data;
        const result: Record<string, unknown> = {
          scenario,
          timestamp: new Date().toISOString(),
        };

        // Get blueprint if requested
        if (typedArgs.includeBlueprint) {
          const blueprintResponse = await apiClient.get(`/scenarios/${typedArgs.scenarioId}/blueprint`);
          if (blueprintResponse.success) {
            result.blueprint = blueprintResponse.data;
          }
        }

        // Get execution history if requested
        if (typedArgs.includeExecutions) {
          const executionsResponse = await apiClient.get(`/scenarios/${typedArgs.scenarioId}/executions`, {
            params: { limit: 10 }
          });
          if (executionsResponse.success) {
            result.recentExecutions = executionsResponse.data;
          }
        }

        reportProgress?.({ progress: 100, total: 100 });

        log?.info?.('Scenario details retrieved successfully', { 
          scenarioId: typedArgs.scenarioId,
          includeBlueprint: typedArgs.includeBlueprint,
          includeExecutions: typedArgs.includeExecutions 
        });

        return formatSuccessResponse(result).content[0].text;
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log?.error?.('Failed to get scenario details', { 
          scenarioId: typedArgs.scenarioId, 
          error: errorMessage 
        });
        throw new UserError(`Failed to get scenario: ${errorMessage}`);
      }
    },
  };
}