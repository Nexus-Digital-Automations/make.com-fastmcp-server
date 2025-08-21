/**
 * @fileoverview Extract Blueprint Connections Tool Implementation
 * Connection analysis and dependency mapping for blueprints
 */

import { UserError } from 'fastmcp';
import { ExtractBlueprintConnectionsSchema } from '../schemas/blueprint-update.js';
import { ToolContext, ToolDefinition } from '../types/tool-context.js';
import { extractBlueprintConnections } from '../utils/blueprint-analysis.js';

/**
 * Create extract blueprint connections tool configuration
 */
export function createExtractBlueprintConnectionsTool(context: ToolContext): ToolDefinition {
  const { apiClient, logger } = context;
  
  return {
    name: 'extract-blueprint-connections',
    description: 'Analyze and extract connection requirements from Make.com blueprints with dependency mapping',
    parameters: ExtractBlueprintConnectionsSchema,
    annotations: {
      title: 'Extract Blueprint Connections',
      readOnlyHint: true,
    },
    execute: async (args, { log }) => {
      log?.info('Extracting blueprint connections', { 
        hasBlueprint: !!args.blueprint,
        includeOptional: args.includeOptional,
        groupByModule: args.groupByModule
      });

      try {
        const connectionData = extractBlueprintConnections(
          args.blueprint, 
          args.includeOptional
        );

        // Build the response based on groupByModule preference
        const response = {
          summary: connectionData.connectionSummary,
          connections: args.groupByModule 
            ? groupConnectionsByModule(connectionData.requiredConnections)
            : connectionData.requiredConnections,
          dependencyMap: connectionData.dependencyMap,
          migration: {
            setupOrder: generateSetupOrder(connectionData.dependencyMap),
            criticalConnections: connectionData.requiredConnections
              .filter(conn => conn.required)
              .map(conn => ({
                service: conn.service,
                moduleCount: connectionData.dependencyMap[conn.service || 'unknown']?.length || 0
              }))
              .sort((a, b) => b.moduleCount - a.moduleCount)
          },
          analysis: {
            mostUsedServices: Object.entries(connectionData.dependencyMap)
              .map(([service, modules]) => ({ service, moduleCount: modules.length }))
              .sort((a, b) => b.moduleCount - a.moduleCount),
            connectionComplexity: calculateConnectionComplexity(connectionData),
            recommendations: generateConnectionRecommendations(connectionData)
          }
        };

        log?.info('Blueprint connection extraction completed', {
          totalConnections: connectionData.requiredConnections.length,
          uniqueServices: connectionData.connectionSummary.uniqueServices.length,
          optionalIncluded: args.includeOptional
        });

        return JSON.stringify(response, null, 2);

      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log?.error('Blueprint connection extraction failed', { error: errorMessage });
        throw new UserError(`Blueprint connection extraction failed: ${errorMessage}`);
      }
    }
  };
}

/**
 * Group connections by module type
 */
function groupConnectionsByModule(connections: Array<{ moduleId: number; moduleType: string; connectionId?: number; service?: string; required: boolean }>): Record<string, Array<{ moduleId: number; connectionId?: number; required: boolean }>> {
  const grouped: Record<string, Array<{ moduleId: number; connectionId?: number; required: boolean }>> = {};
  
  connections.forEach(conn => {
    const service = conn.service || 'unknown';
    if (!grouped[service]) {
      grouped[service] = [];
    }
    grouped[service].push({
      moduleId: conn.moduleId,
      connectionId: conn.connectionId,
      required: conn.required
    });
  });

  return grouped;
}

/**
 * Generate recommended setup order based on dependencies
 */
function generateSetupOrder(dependencyMap: Record<string, number[]>): string[] {
  // Simple ordering: most-used services first
  return Object.entries(dependencyMap)
    .sort(([, aModules], [, bModules]) => bModules.length - aModules.length)
    .map(([service]) => service);
}

/**
 * Calculate connection complexity score
 */
function calculateConnectionComplexity(connectionData: {
  requiredConnections: any[];
  connectionSummary: { uniqueServices: string[]; totalModules: number };
  dependencyMap: Record<string, number[]>;
}): { score: number; level: string; factors: string[] } {
  const uniqueServices = connectionData.connectionSummary.uniqueServices.length;
  const totalConnections = connectionData.requiredConnections.length;
  const averageModulesPerService = totalConnections / Math.max(uniqueServices, 1);
  
  // Simple complexity scoring
  let score = 0;
  const factors: string[] = [];

  if (uniqueServices > 10) {
    score += 30;
    factors.push('High number of unique services');
  }
  
  if (totalConnections > 50) {
    score += 25;
    factors.push('Large number of total connections');
  }
  
  if (averageModulesPerService > 5) {
    score += 20;
    factors.push('High coupling between services');
  }

  const level = score > 50 ? 'high' : score > 25 ? 'medium' : 'low';
  
  return { score, level, factors };
}

/**
 * Generate connection recommendations
 */
function generateConnectionRecommendations(connectionData: {
  requiredConnections: any[];
  connectionSummary: { uniqueServices: string[]; totalModules: number };
  dependencyMap: Record<string, number[]>;
}): string[] {
  const recommendations: string[] = [];
  const complexity = calculateConnectionComplexity(connectionData);
  
  if (complexity.level === 'high') {
    recommendations.push('Consider breaking down workflow into smaller, more focused scenarios');
    recommendations.push('Implement connection pooling to optimize resource usage');
  }
  
  if (connectionData.connectionSummary.uniqueServices.length > 5) {
    recommendations.push('Document all service dependencies for easier maintenance');
    recommendations.push('Consider consolidating similar service operations');
  }
  
  // Check for services with many connections
  Object.entries(connectionData.dependencyMap).forEach(([service, modules]) => {
    if (modules.length > 10) {
      recommendations.push(`Consider optimizing ${service} usage - used in ${modules.length} modules`);
    }
  });
  
  if (recommendations.length === 0) {
    recommendations.push('Connection structure appears well-organized');
    recommendations.push('Consider periodic review of connection usage patterns');
  }
  
  return recommendations.slice(0, 8); // Limit to 8 recommendations
}