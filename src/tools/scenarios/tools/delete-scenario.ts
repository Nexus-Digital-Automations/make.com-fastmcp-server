/**
 * @fileoverview Delete Scenario Tool Implementation
 * Deletes a Make.com scenario with safety checks and force options
 */

import { UserError } from 'fastmcp';
import { DeleteScenarioSchema } from '../schemas/blueprint-update.js';
import { ToolContext, ToolDefinition } from '../../shared/types/tool-context.js';
import { formatSuccessResponse } from '../../../utils/response-formatter.js';

/**
 * Create delete scenario tool configuration
 */
export function createDeleteScenarioTool(context: ToolContext): ToolDefinition {
  const { apiClient } = context;
  
  return {
    name: 'delete-scenario',
    description: 'Delete a Make.com scenario with safety checks and force options',
    parameters: DeleteScenarioSchema,
    annotations: {
      title: 'Delete Scenario',
      readOnlyHint: false,
      destructiveHint: true,
      openWorldHint: false,
    },
    execute: async (args: unknown, context): Promise<string> => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} }, reportProgress = (): void => {} } = context || {};
      const typedArgs = args as { scenarioId: string; force?: boolean };
      
      if (log && log.info) { log.info('Deleting scenario', { scenarioId: typedArgs.scenarioId, force: typedArgs.force }); }
      reportProgress?.({ progress: 0, total: 100 });

      try {
        // Check scenario status first if not forcing
        if (!typedArgs.force) {
          reportProgress?.({ progress: 10, total: 100 });
          const statusResponse = await apiClient.get(`/scenarios/${typedArgs.scenarioId}`);
          
          if (statusResponse.success && statusResponse.data) {
            const scenario = statusResponse.data as { active?: boolean };
            if (scenario.active) {
              throw new UserError(
                'Cannot delete active scenario. Use --force true to override, or deactivate scenario first.'
              );
            }
          }
        }

        reportProgress?.({ progress: 50, total: 100 });

        const response = await apiClient.delete(`/scenarios/${typedArgs.scenarioId}`);
        reportProgress?.({ progress: 90, total: 100 });

        if (!response.success) {
          throw new UserError(`Failed to delete scenario: ${response.error?.message}`);
        }

        reportProgress?.({ progress: 100, total: 100 });

        const result = {
          scenarioId: typedArgs.scenarioId,
          message: `Scenario deleted successfully`,
          force: Boolean(typedArgs.force),
          timestamp: new Date().toISOString(),
        };

        if (log && log.info) { log.info('Scenario deleted successfully', { 
          scenarioId: typedArgs.scenarioId,
          force: typedArgs.force 
        }); }

        return formatSuccessResponse(result).content[0].text;
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (log && log.error) { log.error('Failed to delete scenario', { 
          scenarioId: typedArgs.scenarioId, 
          error: errorMessage 
        }); }
        throw new UserError(`Failed to delete scenario: ${errorMessage}`);
      }
    },
  };
}