/**
 * @fileoverview Clone Scenario Tool Implementation
 * Clones an existing Make.com scenario with customizable options
 */

import { UserError } from 'fastmcp';
import { CloneScenarioSchema } from '../schemas/blueprint-update.js';
import { ToolContext, ToolDefinition } from '../../shared/types/tool-context.js';
import { formatSuccessResponse } from '../../../utils/response-formatter.js';

/**
 * Create clone scenario tool configuration
 */
export function createCloneScenarioTool(context: ToolContext): ToolDefinition {
  const { apiClient } = context;
  
  return {
    name: 'clone-scenario',
    description: 'Clone an existing Make.com scenario with a new name',
    parameters: CloneScenarioSchema,
    annotations: {
      title: 'Clone Scenario',
      readOnlyHint: false,
      openWorldHint: false,
    },
    execute: async (args: unknown, context): Promise<string> => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} }, reportProgress = (): void => {} } = context || {};
      const typedArgs = args as {
        scenarioId: string;
        name: string;
        teamId?: string;
        folderId?: string;
        active?: boolean;
      };
      
      if (log && log.info) { log.info('Cloning scenario', { 
        sourceId: typedArgs.scenarioId, 
        newName: typedArgs.name 
      }); }
      reportProgress?.({ progress: 0, total: 100 });

      try {
        // Get source scenario blueprint
        const blueprintResponse = await apiClient.get(`/scenarios/${typedArgs.scenarioId}/blueprint`);
        if (!blueprintResponse.success) {
          throw new UserError(`Failed to get source scenario blueprint: ${blueprintResponse.error?.message}`);
        }

        reportProgress?.({ progress: 25, total: 100 });

        // Create clone data
        const cloneData: Record<string, unknown> = {
          name: typedArgs.name,
          blueprint: blueprintResponse.data,
          active: typedArgs.active,
        };

        if (typedArgs.teamId) {cloneData.teamId = typedArgs.teamId;}
        if (typedArgs.folderId) {cloneData.folderId = typedArgs.folderId;}

        reportProgress?.({ progress: 50, total: 100 });

        // Create the cloned scenario
        const response = await apiClient.post('/scenarios', cloneData);
        reportProgress?.({ progress: 100, total: 100 });

        if (!response.success) {
          throw new UserError(`Failed to clone scenario: ${response.error?.message}`);
        }

        const clonedScenario = response.data;

        const result = {
          originalScenarioId: typedArgs.scenarioId,
          clonedScenario,
          message: `Scenario cloned successfully as "${typedArgs.name}"`,
          timestamp: new Date().toISOString(),
        };

        // Type guard for cloned scenario
        const clonedScenarioObj = clonedScenario as { id?: unknown } | null | undefined;
        
        if (log && log.info) { log.info('Scenario cloned successfully', { 
          sourceId: typedArgs.scenarioId,
          cloneId: String(clonedScenarioObj?.id ?? 'unknown'),
          name: typedArgs.name 
        }); }

        return formatSuccessResponse(result).content[0].text;
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (log && log.error) { log.error('Failed to clone scenario', { 
          scenarioId: typedArgs.scenarioId, 
          error: errorMessage 
        }); }
        throw new UserError(`Failed to clone scenario: ${errorMessage}`);
      }
    },
  };
}