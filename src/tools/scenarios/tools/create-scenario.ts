/**
 * @fileoverview Create Scenario Tool Implementation
 * Creates a new Make.com scenario with optional configuration
 */

import { UserError } from 'fastmcp';
import { CreateScenarioSchema } from '../schemas/blueprint-update.js';
import { ToolContext, ToolDefinition } from '../../shared/types/tool-context.js';
import { formatSuccessResponse } from '../../../utils/response-formatter.js';

/**
 * Create scenario tool configuration
 */
export function createScenarioTool(context: ToolContext): ToolDefinition {
  const { apiClient } = context;
  
  return {
    name: 'create-scenario',
    description: 'Create a new Make.com scenario with optional configuration',
    parameters: CreateScenarioSchema,
    annotations: {
      title: 'Create Scenario',
      readOnlyHint: false,
      openWorldHint: false,
    },
    execute: async (args: unknown, context): Promise<string> => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} }, reportProgress = (): void => {} } = context || {};
      const typedArgs = args as { 
        name: string; 
        teamId?: string; 
        folderId?: string; 
        blueprint?: unknown; 
        scheduling?: { type: string; interval?: number; cron?: string } 
      };
      
      if (log && log.info) { log.info('Creating scenario', { name: typedArgs.name, teamId: typedArgs.teamId }); }
      reportProgress?.({ progress: 0, total: 100 });

      try {
        const scenarioData: Record<string, unknown> = {
          name: typedArgs.name,
        };

        if (typedArgs.teamId) scenarioData.teamId = typedArgs.teamId;
        if (typedArgs.folderId) scenarioData.folderId = typedArgs.folderId;
        if (typedArgs.blueprint) scenarioData.blueprint = typedArgs.blueprint;
        if (typedArgs.scheduling) scenarioData.scheduling = typedArgs.scheduling;

        reportProgress?.({ progress: 25, total: 100 });

        const response = await apiClient.post('/scenarios', scenarioData);
        reportProgress?.({ progress: 75, total: 100 });

        if (!response.success) {
          throw new UserError(`Failed to create scenario: ${response.error?.message}`);
        }

        const createdScenario = response.data;
        reportProgress?.({ progress: 100, total: 100 });

        const result = {
          scenario: createdScenario,
          message: `Scenario "${typedArgs.name}" created successfully`,
          timestamp: new Date().toISOString(),
        };

        // Type guard for created scenario
        const scenarioObj = createdScenario as { id?: unknown } | null | undefined;
        
        if (log && log.info) { log.info('Scenario created successfully', { 
          scenarioId: String(scenarioObj?.id ?? 'unknown'),
          name: typedArgs.name 
        }); }

        return formatSuccessResponse(result).content[0].text;
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (log && log.error) { log.error('Failed to create scenario', { name: typedArgs.name, error: errorMessage }); }
        throw new UserError(`Failed to create scenario: ${errorMessage}`);
      }
    },
  };
}