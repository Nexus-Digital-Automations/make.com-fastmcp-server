/**
 * @fileoverview Optimize Blueprint Tool Implementation
 * Single-responsibility tool for blueprint optimization analysis
 */

import { UserError } from 'fastmcp';
import { OptimizeBlueprintSchema } from '../schemas/blueprint-update.js';
import { ToolContext, ToolDefinition } from '../../shared/types/tool-context.js';
import { optimizeBlueprint } from '../utils/optimization.js';
import { Blueprint } from '../types/blueprint.js';

/**
 * Create optimize blueprint tool configuration
 */
export function createOptimizeBlueprintTool(context: ToolContext): ToolDefinition {
  const { apiClient, logger } = context;
  
  return {
    name: 'optimize-blueprint',
    description: 'Analyze blueprint for optimization opportunities and provide performance recommendations',
    parameters: OptimizeBlueprintSchema,
    annotations: {
      title: 'Optimize Blueprint',
      readOnlyHint: true,
      openWorldHint: false,
    },
    execute: async (args: unknown, { log, reportProgress }) => {
      log?.info?.('Optimizing blueprint', { hasBlueprint: !!(args as any).blueprint });
      reportProgress?.({ progress: 0, total: 100 });

      try {
        const { blueprint } = args as any;
        
        if (!blueprint) {
          throw new UserError('Blueprint is required for optimization analysis');
        }

        reportProgress?.({ progress: 25, total: 100 });

        // Perform optimization analysis
        const optimizationResult = optimizeBlueprint(blueprint as Blueprint);
        
        reportProgress?.({ progress: 75, total: 100 });

        // Prepare comprehensive optimization report
        const optimizationReport = {
          analysis: {
            optimizationScore: optimizationResult.optimizationScore,
            grade: getOptimizationGrade(optimizationResult.optimizationScore),
            status: optimizationResult.optimizationScore >= 80 ? 'well-optimized' : 
                    optimizationResult.optimizationScore >= 60 ? 'needs-improvement' : 'requires-optimization'
          },
          metrics: {
            ...optimizationResult.metrics,
            efficiency: {
              moduleEfficiency: calculateModuleEfficiency(optimizationResult.metrics),
              connectionEfficiency: calculateConnectionEfficiency(optimizationResult.metrics),
              performanceRating: getPerformanceRating(optimizationResult.metrics)
            }
          },
          recommendations: {
            total: optimizationResult.recommendations.length,
            byPriority: {
              high: optimizationResult.recommendations.filter(r => r.priority === 'high').length,
              medium: optimizationResult.recommendations.filter(r => r.priority === 'medium').length,
              low: optimizationResult.recommendations.filter(r => r.priority === 'low').length
            },
            items: optimizationResult.recommendations.map(rec => ({
              ...rec,
              estimatedImplementationTime: getImplementationTime(rec),
              potentialImpactScore: getImpactScore(rec)
            }))
          },
          costAnalysis: {
            estimatedMonthlyCost: estimateMonthlyCost(optimizationResult.metrics),
            optimizationPotential: estimateOptimizationSavings(optimizationResult),
            costEfficiencyRating: getCostEfficiencyRating(optimizationResult.metrics)
          },
          performanceProjections: {
            currentPerformance: {
              estimatedExecutionTime: `${optimizationResult.metrics.estimatedExecutionTime}ms`,
              resourceUsage: `${optimizationResult.metrics.memoryUsage}KB`,
              networkCalls: optimizationResult.metrics.networkCalls
            },
            optimizedPerformance: calculateOptimizedPerformance(optimizationResult)
          },
          implementationPlan: generateImplementationPlan(optimizationResult.recommendations),
          analysisTimestamp: new Date().toISOString(),
          blueprintInfo: {
            moduleCount: optimizationResult.metrics.moduleCount,
            complexityScore: optimizationResult.metrics.complexityScore,
            connectionCount: optimizationResult.metrics.connectionCount
          }
        };

        reportProgress?.({ progress: 100, total: 100 });

        log?.info?.('Blueprint optimization analysis completed', {
          optimizationScore: optimizationReport.analysis.optimizationScore,
          grade: optimizationReport.analysis.grade,
          recommendationCount: optimizationReport.recommendations.total,
          highPriorityRecommendations: optimizationReport.recommendations.byPriority.high
        });

        return JSON.stringify(optimizationReport, null, 2);
        
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.error?.('Blueprint optimization failed', { error: errorMessage });
        throw new UserError(`Blueprint optimization failed: ${errorMessage}`);
      }
    },
  };
}

/**
 * Get optimization grade based on score
 */
function getOptimizationGrade(score: number): string {
  if (score >= 90) return 'A+';
  if (score >= 85) return 'A';
  if (score >= 80) return 'B+';
  if (score >= 75) return 'B';
  if (score >= 70) return 'C+';
  if (score >= 65) return 'C';
  if (score >= 60) return 'D+';
  if (score >= 55) return 'D';
  return 'F';
}

/**
 * Calculate module efficiency ratio
 */
function calculateModuleEfficiency(metrics: any): number {
  // Higher efficiency means fewer modules achieving the same functionality
  const baselineModules = 10; // Typical workflow size
  const efficiency = Math.min(100, (baselineModules / Math.max(1, metrics.moduleCount)) * 100);
  return Math.round(efficiency);
}

/**
 * Calculate connection efficiency ratio
 */
function calculateConnectionEfficiency(metrics: any): number {
  if (metrics.moduleCount === 0) return 100;
  
  const connectionRatio = metrics.connectionCount / metrics.moduleCount;
  // Lower ratio generally means better efficiency (fewer external dependencies)
  const efficiency = Math.max(0, 100 - (connectionRatio * 25));
  return Math.round(efficiency);
}

/**
 * Get performance rating based on metrics
 */
function getPerformanceRating(metrics: any): string {
  if (metrics.estimatedExecutionTime < 1000 && metrics.memoryUsage < 500) return 'Excellent';
  if (metrics.estimatedExecutionTime < 3000 && metrics.memoryUsage < 1000) return 'Good';
  if (metrics.estimatedExecutionTime < 5000 && metrics.memoryUsage < 2000) return 'Fair';
  return 'Needs Improvement';
}

/**
 * Get estimated implementation time for recommendation
 */
function getImplementationTime(recommendation: any): string {
  switch (recommendation.priority) {
    case 'high':
      return '2-4 hours';
    case 'medium':
      return '4-8 hours';
    case 'low':
      return '1-2 days';
    default:
      return '4-8 hours';
  }
}

/**
 * Get impact score for recommendation
 */
function getImpactScore(recommendation: any): number {
  const categoryScores = {
    performance: 85,
    cost: 70,
    reliability: 90,
    security: 95,
    maintainability: 60
  };
  
  const priorityMultipliers = {
    high: 1.0,
    medium: 0.8,
    low: 0.6
  };
  
  const baseScore = categoryScores[recommendation.category] || 70;
  const multiplier = priorityMultipliers[recommendation.priority] || 0.8;
  
  return Math.round(baseScore * multiplier);
}

/**
 * Estimate monthly cost based on metrics
 */
function estimateMonthlyCost(metrics: any): number {
  // Simplified cost estimation based on complexity and usage
  const baseCost = 10; // Base monthly cost
  const moduleCost = metrics.moduleCount * 0.5;
  const connectionCost = metrics.connectionCount * 2;
  const complexityCost = (metrics.complexityScore / 100) * 50;
  
  return Math.round(baseCost + moduleCost + connectionCost + complexityCost);
}

/**
 * Estimate optimization savings
 */
function estimateOptimizationSavings(optimizationResult: any): number {
  const currentCost = estimateMonthlyCost(optimizationResult.metrics);
  const savingsPercentage = Math.min(50, (100 - optimizationResult.optimizationScore) * 0.5);
  
  return Math.round(currentCost * (savingsPercentage / 100));
}

/**
 * Get cost efficiency rating
 */
function getCostEfficiencyRating(metrics: any): string {
  const costPerModule = estimateMonthlyCost(metrics) / Math.max(1, metrics.moduleCount);
  
  if (costPerModule < 1) return 'Excellent';
  if (costPerModule < 2) return 'Good';
  if (costPerModule < 4) return 'Fair';
  return 'Poor';
}

/**
 * Calculate optimized performance projections
 */
function calculateOptimizedPerformance(optimizationResult: any) {
  const currentMetrics = optimizationResult.metrics;
  const improvementFactor = optimizationResult.optimizationScore / 100;
  
  return {
    estimatedExecutionTime: `${Math.round(currentMetrics.estimatedExecutionTime * improvementFactor)}ms`,
    resourceUsage: `${Math.round(currentMetrics.memoryUsage * improvementFactor)}KB`,
    networkCalls: Math.max(1, Math.round(currentMetrics.networkCalls * improvementFactor)),
    improvementPercentage: Math.round((1 - improvementFactor) * 100)
  };
}

/**
 * Generate implementation plan
 */
function generateImplementationPlan(recommendations: any[]) {
  const highPriorityItems = recommendations.filter(r => r.priority === 'high');
  const mediumPriorityItems = recommendations.filter(r => r.priority === 'medium');
  const lowPriorityItems = recommendations.filter(r => r.priority === 'low');
  
  return {
    phase1: {
      name: 'Critical Optimizations',
      duration: '1-2 weeks',
      items: highPriorityItems.slice(0, 3).map(item => item.title),
      expectedImpact: 'Major performance and cost improvements'
    },
    phase2: {
      name: 'Performance Enhancements',
      duration: '2-3 weeks',
      items: mediumPriorityItems.slice(0, 5).map(item => item.title),
      expectedImpact: 'Moderate performance improvements'
    },
    phase3: {
      name: 'Fine-tuning',
      duration: '2-4 weeks',
      items: lowPriorityItems.slice(0, 5).map(item => item.title),
      expectedImpact: 'Incremental optimizations'
    },
    totalEstimatedDuration: '5-9 weeks'
  };
}