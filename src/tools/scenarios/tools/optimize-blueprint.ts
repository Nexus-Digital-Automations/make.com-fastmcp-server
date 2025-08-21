/**
 * @fileoverview Optimize Blueprint Tool Implementation
 * Blueprint optimization analysis with performance and cost recommendations
 */

import { UserError } from 'fastmcp';
import { OptimizeBlueprintSchema } from '../schemas/blueprint-update.js';
import { ToolContext, ToolDefinition } from '../types/tool-context.js';
import { optimizeBlueprint } from '../utils/optimization.js';
import { Blueprint } from '../types/blueprint.js';

/**
 * Create optimize blueprint tool configuration
 */
export function createOptimizeBlueprintTool(context: ToolContext): ToolDefinition {
  const { apiClient, logger } = context;
  
  return {
    name: 'optimize-blueprint',
    description: 'Analyze and optimize Make.com blueprints for performance, cost, and security improvements',
    parameters: OptimizeBlueprintSchema,
    annotations: {
      title: 'Optimize Blueprint',
      readOnlyHint: true,
    },
    execute: async (args, { log }) => {
      log?.info('Starting blueprint optimization analysis', { 
        hasBlueprint: !!args.blueprint,
        optimizationType: args.optimizationType,
        includeImplementationSteps: args.includeImplementationSteps
      });

      try {
        // Validate blueprint structure first
        if (!args.blueprint || typeof args.blueprint !== 'object') {
          throw new UserError('Invalid blueprint provided - must be a valid JSON object');
        }

        const blueprint = args.blueprint as Blueprint;
        
        // Run optimization analysis
        const optimizationResult = optimizeBlueprint(blueprint);

        // Filter recommendations by optimization type
        let filteredRecommendations = optimizationResult.recommendations;
        if (args.optimizationType !== 'all') {
          filteredRecommendations = optimizationResult.recommendations.filter(
            rec => rec.category === args.optimizationType
          );
        }

        // Generate detailed implementation guidance if requested
        let implementationGuidance: Record<string, any> | undefined;
        if (args.includeImplementationSteps && filteredRecommendations.length > 0) {
          implementationGuidance = generateImplementationGuidance(
            filteredRecommendations,
            args.optimizationType
          );
        }

        // Generate optimization summary
        const optimizationSummary = {
          currentScore: optimizationResult.optimizationScore,
          potentialImprovement: Math.max(0, 100 - optimizationResult.optimizationScore),
          priorityLevel: optimizationResult.optimizationScore < 70 ? 'high' : 
                       optimizationResult.optimizationScore < 85 ? 'medium' : 'low',
          focusAreas: getFocusAreas(filteredRecommendations),
          estimatedImpact: calculateEstimatedImpact(filteredRecommendations)
        };

        // Build comprehensive response
        const response = {
          optimizationSummary,
          analysis: {
            blueprintMetrics: optimizationResult.metrics,
            optimizationScore: optimizationResult.optimizationScore,
            recommendationCount: filteredRecommendations.length,
            categories: getCategoryBreakdown(filteredRecommendations)
          },
          recommendations: filteredRecommendations.map(rec => ({
            ...rec,
            implementationSteps: args.includeImplementationSteps ? rec.implementationSteps : undefined
          })),
          ...(implementationGuidance && { implementationGuidance }),
          metadata: {
            analysisType: args.optimizationType,
            blueprintName: blueprint.name || 'Unnamed Blueprint',
            moduleCount: blueprint.flow?.length || 0,
            analysisTimestamp: new Date().toISOString()
          }
        };

        log?.info('Blueprint optimization analysis completed', {
          optimizationScore: optimizationResult.optimizationScore,
          recommendationCount: filteredRecommendations.length,
          priorityLevel: optimizationSummary.priorityLevel,
          moduleCount: optimizationResult.metrics.moduleCount
        });

        return JSON.stringify(response, null, 2);

      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log?.error('Blueprint optimization failed', { error: errorMessage });
        throw new UserError(`Blueprint optimization failed: ${errorMessage}`);
      }
    }
  };
}

/**
 * Generate detailed implementation guidance
 */
function generateImplementationGuidance(
  recommendations: Array<{ category: string; priority: string; title: string; implementationSteps?: string[] }>,
  optimizationType: string
): Record<string, any> {
  const highPriorityRecs = recommendations.filter(rec => rec.priority === 'high');
  const mediumPriorityRecs = recommendations.filter(rec => rec.priority === 'medium');
  
  return {
    quickWins: highPriorityRecs.slice(0, 3).map(rec => ({
      title: rec.title,
      category: rec.category,
      timeEstimate: getTimeEstimate(rec.category),
      difficulty: getDifficulty(rec.category),
      steps: rec.implementationSteps?.slice(0, 3) || []
    })),
    mediumTermActions: mediumPriorityRecs.slice(0, 3).map(rec => ({
      title: rec.title,
      category: rec.category,
      timeEstimate: getTimeEstimate(rec.category, 'medium'),
      difficulty: getDifficulty(rec.category, 'medium'),
      steps: rec.implementationSteps || []
    })),
    implementationOrder: generateImplementationOrder(recommendations),
    resourceRequirements: {
      technicalSkills: getTechnicalSkills(optimizationType),
      estimatedTime: calculateTotalTime(recommendations),
      tools: getRequiredTools(optimizationType)
    }
  };
}

/**
 * Get focus areas from recommendations
 */
function getFocusAreas(recommendations: Array<{ category: string; priority: string }>): string[] {
  const categoryCount: Record<string, number> = {};
  
  recommendations.forEach(rec => {
    categoryCount[rec.category] = (categoryCount[rec.category] || 0) + 1;
  });
  
  return Object.entries(categoryCount)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 3)
    .map(([category]) => category);
}

/**
 * Calculate estimated impact from recommendations
 */
function calculateEstimatedImpact(recommendations: Array<{ priority: string; estimatedImpact?: string }>): {
  performance: number;
  cost: number;
  security: number;
  overall: number;
} {
  const impact = { performance: 0, cost: 0, security: 0, overall: 0 };
  
  recommendations.forEach(rec => {
    const weight = rec.priority === 'high' ? 3 : rec.priority === 'medium' ? 2 : 1;
    
    // Parse estimated impact if available
    if (rec.estimatedImpact?.includes('%')) {
      const percentage = parseInt(rec.estimatedImpact.match(/(\d+)%/)?.[1] || '0');
      impact.performance += percentage * weight;
      impact.cost += percentage * weight;
      impact.security += percentage * weight;
    } else {
      // Default impact values based on priority
      impact.performance += weight * 5;
      impact.cost += weight * 3;
      impact.security += weight * 4;
    }
  });
  
  // Normalize and calculate overall
  const maxImpact = recommendations.length * 3 * 15; // max possible impact
  impact.performance = Math.min(100, Math.round((impact.performance / maxImpact) * 100));
  impact.cost = Math.min(100, Math.round((impact.cost / maxImpact) * 100));
  impact.security = Math.min(100, Math.round((impact.security / maxImpact) * 100));
  impact.overall = Math.round((impact.performance + impact.cost + impact.security) / 3);
  
  return impact;
}

/**
 * Get category breakdown of recommendations
 */
function getCategoryBreakdown(recommendations: Array<{ category: string; priority: string }>): Record<string, { total: number; high: number; medium: number; low: number }> {
  const breakdown: Record<string, { total: number; high: number; medium: number; low: number }> = {};
  
  recommendations.forEach(rec => {
    if (!breakdown[rec.category]) {
      breakdown[rec.category] = { total: 0, high: 0, medium: 0, low: 0 };
    }
    
    breakdown[rec.category].total++;
    breakdown[rec.category][rec.priority as 'high' | 'medium' | 'low']++;
  });
  
  return breakdown;
}

/**
 * Helper functions for implementation guidance
 */
function getTimeEstimate(category: string, term: 'quick' | 'medium' = 'quick'): string {
  const times: Record<string, Record<string, string>> = {
    performance: { quick: '1-2 hours', medium: '1-2 days' },
    cost: { quick: '30 minutes', medium: '4-8 hours' },
    security: { quick: '1-3 hours', medium: '1-3 days' },
    reliability: { quick: '2-4 hours', medium: '2-5 days' }
  };
  
  return times[category]?.[term] || '1-4 hours';
}

function getDifficulty(category: string, term: 'quick' | 'medium' = 'quick'): string {
  const difficulties: Record<string, Record<string, string>> = {
    performance: { quick: 'easy', medium: 'moderate' },
    cost: { quick: 'easy', medium: 'easy' },
    security: { quick: 'moderate', medium: 'moderate' },
    reliability: { quick: 'moderate', medium: 'challenging' }
  };
  
  return difficulties[category]?.[term] || 'moderate';
}

function generateImplementationOrder(recommendations: Array<{ category: string; priority: string; title: string }>): string[] {
  // Sort by priority first, then by category importance
  const priorityOrder = ['high', 'medium', 'low'];
  const categoryOrder = ['security', 'performance', 'reliability', 'cost'];
  
  return recommendations
    .sort((a, b) => {
      const priorityDiff = priorityOrder.indexOf(a.priority) - priorityOrder.indexOf(b.priority);
      if (priorityDiff !== 0) return priorityDiff;
      
      return categoryOrder.indexOf(a.category) - categoryOrder.indexOf(b.category);
    })
    .map(rec => rec.title);
}

function getTechnicalSkills(optimizationType: string): string[] {
  const skillMap: Record<string, string[]> = {
    performance: ['Performance analysis', 'Blueprint optimization', 'Make.com advanced features'],
    cost: ['Resource optimization', 'Usage analysis', 'Connection management'],
    security: ['Security best practices', 'Data protection', 'Access control'],
    all: ['Blueprint design', 'Make.com platform expertise', 'System optimization']
  };
  
  return skillMap[optimizationType] || skillMap.all;
}

function calculateTotalTime(recommendations: Array<{ priority: string }>): string {
  const timeWeights = { high: 3, medium: 2, low: 1 };
  const totalWeight = recommendations.reduce((sum, rec) => 
    sum + (timeWeights[rec.priority as keyof typeof timeWeights] || 1), 0
  );
  
  if (totalWeight < 5) return '1-2 days';
  if (totalWeight < 10) return '3-5 days';
  return '1-2 weeks';
}

function getRequiredTools(optimizationType: string): string[] {
  const toolMap: Record<string, string[]> = {
    performance: ['Make.com scenario logs', 'Performance monitoring tools', 'Blueprint analyzer'],
    cost: ['Make.com usage dashboard', 'Cost analysis tools', 'Resource optimizer'],
    security: ['Security scanner', 'Compliance checker', 'Access audit tools'],
    all: ['Make.com platform', 'Development environment', 'Monitoring tools']
  };
  
  return toolMap[optimizationType] || toolMap.all;
}