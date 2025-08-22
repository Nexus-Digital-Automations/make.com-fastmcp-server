/**
 * @fileoverview Update Scenario Tool Implementation
 * Updates an existing Make.com scenario configuration
 */

import { UserError } from 'fastmcp';
import { UpdateScenarioSchema } from '../schemas/blueprint-update.js';
import { ToolContext, ToolDefinition } from '../../shared/types/tool-context.js';
import { formatSuccessResponse } from '../../../utils/response-formatter.js';

/**
 * Create update scenario tool configuration
 */
export function createUpdateScenarioTool(context: ToolContext): ToolDefinition {
  const { apiClient } = context;
  
  return {
    name: 'update-scenario',
    description: 'Update an existing Make.com scenario configuration',
    parameters: UpdateScenarioSchema,
    annotations: {
      title: 'Update Scenario',
      readOnlyHint: false,
      openWorldHint: false,
    },
    execute: async (args: unknown, context): Promise<string> => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} }, reportProgress = (): void => {} } = context || {};
      const typedArgs = args as {
        scenarioId: string;
        name?: string;
        active?: boolean;
        blueprint?: unknown;
        scheduling?: { type: string; interval?: number; cron?: string };
      };
      
      if (log && log.info) { log.info('Updating scenario', { scenarioId: typedArgs.scenarioId }); }
      reportProgress?.({ progress: 0, total: 100 });

      try {
        const updateData: Record<string, unknown> = {};
        
        if (typedArgs.name !== undefined) {updateData.name = typedArgs.name;}
        if (typedArgs.active !== undefined) {updateData.active = typedArgs.active;}
        if (typedArgs.blueprint !== undefined) {updateData.blueprint = typedArgs.blueprint;}
        if (typedArgs.scheduling !== undefined) {updateData.scheduling = typedArgs.scheduling;}

        if (Object.keys(updateData).length === 0) {
          throw new UserError('No update parameters provided');
        }

        reportProgress?.({ progress: 25, total: 100 });

        const response = await apiClient.patch(`/scenarios/${typedArgs.scenarioId}`, updateData);
        reportProgress?.({ progress: 75, total: 100 });

        if (!response.success) {
          throw new UserError(`Failed to update scenario: ${response.error?.message}`);
        }

        const updatedScenario = response.data;
        reportProgress?.({ progress: 100, total: 100 });

        const result = {
          scenario: updatedScenario,
          updates: updateData,
          message: `Scenario updated successfully`,
          timestamp: new Date().toISOString(),
        };

        if (log && log.info) { log.info('Scenario updated successfully', { scenarioId: typedArgs.scenarioId }); }
        return formatSuccessResponse(result).content[0].text;
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (log && log.error) { log.error('Failed to update scenario', { 
          scenarioId: typedArgs.scenarioId, 
          error: errorMessage 
        }); }
        throw new UserError(`Failed to update scenario: ${errorMessage}`);
      }
    },
  };
}