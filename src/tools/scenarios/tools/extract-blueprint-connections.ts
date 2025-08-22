/**
 * @fileoverview Extract Blueprint Connections Tool Implementation
 * Extract and analyze connection requirements from Make.com blueprints
 */

import { UserError } from 'fastmcp';
import { ExtractBlueprintConnectionsSchema } from '../utils/blueprint-analysis.js';
import { ToolContext, ToolDefinition } from '../../shared/types/tool-context.js';
import { extractBlueprintConnections } from '../utils/blueprint-analysis.js';
import { formatSuccessResponse } from '../../../utils/response-formatter.js';

/**
 * Create extract blueprint connections tool configuration
 */
export function createExtractBlueprintConnectionsTool(context: ToolContext): ToolDefinition {
  const { logger: _logger } = context;
  
  return {
    name: 'extract-blueprint-connections',
    description: 'Extract and analyze connection requirements from Make.com blueprints for migration planning',
    parameters: ExtractBlueprintConnectionsSchema,
    annotations: {
      title: 'Extract Blueprint Connections',
      readOnlyHint: true,
      openWorldHint: false,
    },
    execute: async (args: unknown, context): Promise<string> => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} }, reportProgress = (): void => {} } = context || {};
      log?.info?.('Extracting blueprint connections', { hasBlueprint: !!(args as { blueprint?: unknown }).blueprint });
      reportProgress?.({ progress: 0, total: 100 });

      try {
        const { blueprint, includeOptional = false, groupByModule = true } = args as {
          blueprint?: unknown;
          includeOptional?: boolean;
          groupByModule?: boolean;
        };
        
        if (!blueprint) {
          throw new UserError('Blueprint is required for connection extraction');
        }

        reportProgress?.({ progress: 50, total: 100 });

        // Extract connection requirements
        const connectionResult = extractBlueprintConnections(blueprint, includeOptional);
        
        reportProgress?.({ progress: 100, total: 100 });

        // Prepare detailed result
        const result = {
          connectionAnalysis: {
            totalConnections: connectionResult.requiredConnections.length,
            requiredConnections: connectionResult.requiredConnections,
            connectionSummary: connectionResult.connectionSummary,
            dependencyMap: groupByModule ? connectionResult.dependencyMap : undefined,
          },
          migrationPlanning: {
            uniqueServices: connectionResult.connectionSummary.uniqueServices,
            connectionCount: connectionResult.connectionSummary.modulesRequiringConnections,
            estimatedSetupTime: connectionResult.connectionSummary.uniqueServices.length * 15, // 15 min per service
            complexity: connectionResult.connectionSummary.uniqueServices.length > 5 ? 'high' : 
                       connectionResult.connectionSummary.uniqueServices.length > 2 ? 'medium' : 'low'
          },
          recommendations: [
            connectionResult.connectionSummary.modulesRequiringConnections === 0 ?
              'No external connections required - blueprint can be deployed immediately' :
              `Set up ${connectionResult.connectionSummary.uniqueServices.length} connection(s) before deployment`,
            connectionResult.connectionSummary.uniqueServices.length > 0 ?
              `Required services: ${connectionResult.connectionSummary.uniqueServices.join(', ')}` :
              'No external service integrations needed'
          ]
        };

        log?.info?.('Blueprint connection extraction completed', {
          totalConnections: result.connectionAnalysis.totalConnections,
          uniqueServices: result.migrationPlanning.uniqueServices.length
        });

        return formatSuccessResponse(result).content[0].text;

      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error during connection extraction';
        log?.error?.('Blueprint connection extraction failed', { error: errorMessage });
        throw new UserError(`Failed to extract blueprint connections: ${errorMessage}`);
      }
    }
  };
}