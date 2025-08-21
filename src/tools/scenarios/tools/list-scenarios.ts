/**
 * @fileoverview List Scenarios Tool Implementation
 * Single-responsibility tool with focused functionality for listing and searching scenarios
 */

import { UserError } from 'fastmcp';
import { ScenarioFiltersSchema } from '../schemas/scenario-filters.js';
import { ToolContext, ToolDefinition } from '../../shared/types/tool-context.js';

/**
 * Create list scenarios tool configuration
 */
export function createListScenariosTools(context: ToolContext): ToolDefinition {
  const { apiClient, logger } = context;
  
  return {
    name: 'list-scenarios',
    description: 'List and search Make.com scenarios with advanced filtering options',
    parameters: ScenarioFiltersSchema,
    annotations: {
      title: 'List Scenarios',
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (args: unknown, { log, reportProgress }) => {
      log?.info?.('Listing scenarios', { filters: args });
      reportProgress?.({ progress: 0, total: 100 });

      try {
        // Build query parameters
        const params: Record<string, unknown> = {
          limit: (args as any).limit,
          offset: (args as any).offset,
        };

        if ((args as any).teamId) params.teamId = (args as any).teamId;
        if ((args as any).folderId) params.folderId = (args as any).folderId;
        if ((args as any).search) params.q = (args as any).search;
        if ((args as any).active !== undefined) params.active = (args as any).active;

        reportProgress?.({ progress: 25, total: 100 });

        const response = await apiClient.get('/scenarios', { params });
        reportProgress?.({ progress: 75, total: 100 });

        if (!response.success) {
          throw new UserError(`Failed to list scenarios: ${response.error?.message}`);
        }

        const scenarios = response.data;
        const metadata = response.metadata;

        reportProgress?.({ progress: 100, total: 100 });

        // Type guard for scenarios array
        const scenariosArray = Array.isArray(scenarios) ? scenarios : [];

        const result = {
          scenarios: scenariosArray,
          pagination: {
            total: metadata?.total || scenariosArray.length,
            limit: (args as any).limit,
            offset: (args as any).offset,
            hasMore: (metadata?.total || 0) > ((args as any).offset + (args as any).limit),
          },
          filters: args,
          timestamp: new Date().toISOString(),
        };

        log?.info?.('Scenarios listed successfully', { 
          count: result.scenarios.length,
          total: result.pagination.total 
        });

        return JSON.stringify(result, null, 2);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.error?.('Failed to list scenarios', { error: errorMessage });
        throw new UserError(`Failed to list scenarios: ${errorMessage}`);
      }
    },
  };
}