/**
 * @fileoverview Blueprint Optimization Utilities
 * 
 * Provides optimization analysis and recommendations for Make.com blueprints.
 * Analyzes performance, cost, and architecture patterns to suggest improvements.
 * 
 * @version 1.0.0
 */

import { z } from 'zod';
import { Blueprint, BlueprintModule } from '../types/blueprint.js';
import { OptimizationRecommendation } from '../types/optimization.js';

// Additional interfaces for our specific optimization function
export interface OptimizationMetrics {
  moduleCount: number;
  connectionCount: number;
  complexityScore: number;
  securityScore: number;
}

export interface OptimizationResult {
  optimizationScore: number;
  recommendations: OptimizationRecommendation[];
  metrics: OptimizationMetrics;
}

// Zod schema for optimization
export const OptimizeBlueprintSchema = z.object({
  blueprint: z.any().describe('Blueprint JSON to analyze and optimize'),
  optimizationType: z.enum(['performance', 'cost', 'security', 'all']).default('performance').describe('Type of optimization to focus on'),
  includeImplementationSteps: z.boolean().default(true).describe('Include step-by-step implementation guidance'),
});

// Blueprint optimization function extracted from scenarios.ts
export function optimizeBlueprint(blueprint: unknown, optimizationType: 'performance' | 'cost' | 'security' | 'all' = 'performance'): OptimizationResult {
  const recommendations: OptimizationRecommendation[] = [];

  let optimizationScore = 100;
  const metrics: OptimizationMetrics = { moduleCount: 0, connectionCount: 0, complexityScore: 0, securityScore: 100 };

  try {
    if (!blueprint || typeof blueprint !== 'object') {
      throw new Error('Invalid blueprint structure');
    }

    const bp = blueprint as Blueprint;

    if (!bp.flow || !Array.isArray(bp.flow)) {
      throw new Error('Blueprint must contain a flow array');
    }

    metrics.moduleCount = bp.flow.length;

    // Analyze modules for optimization opportunities
    const connectionMap = new Map<number, number>();
    const moduleTypes = new Set<string>();

    bp.flow.forEach((module: BlueprintModule) => {
      if (!module || typeof module.id !== 'number') {return;}

      moduleTypes.add(module.module || 'unknown');

      if (module.connection) {
        metrics.connectionCount++;
        connectionMap.set(module.id, module.connection);
      }

      // Performance optimizations
      if (optimizationType === 'performance' || optimizationType === 'all') {
        if (module.module === 'builtin:Iterator' && bp.flow?.length && bp.flow.length > 50) {
          recommendations.push({
            category: 'performance',
            priority: 'high',
            title: 'Optimize Iterator Module for Large Workflows',
            description: `Iterator module (ID: ${module.id}) in a workflow with ${bp.flow.length} modules may cause performance bottlenecks`,
            estimatedImpact: '30-50% execution time reduction',
            implementationSteps: [
              'Consider batching iterator operations',
              'Implement parallel processing where possible',
              'Add progress monitoring for long iterations'
            ]
          });
          optimizationScore -= 15;
        }

        if (module.module?.includes('Database') && !module.parameters?.batchSize) {
          recommendations.push({
            category: 'performance',
            priority: 'medium',
            title: 'Enable Database Batch Operations',
            description: `Database module (ID: ${module.id}) should use batch operations for better performance`,
            estimatedImpact: '20-40% faster database operations',
            implementationSteps: [
              'Configure appropriate batch size parameter',
              'Test batch operations with representative data',
              'Monitor database connection limits'
            ]
          });
          optimizationScore -= 10;
        }
      }

      // Cost optimizations
      if (optimizationType === 'cost' || optimizationType === 'all') {
        if (module.module?.includes('AI') || module.module?.includes('GPT')) {
          recommendations.push({
            category: 'cost',
            priority: 'high',
            title: 'Optimize AI Service Usage',
            description: `AI module (ID: ${module.id}) can be expensive - consider optimization strategies`,
            estimatedImpact: '25-60% cost reduction',
            implementationSteps: [
              'Implement request caching for repeated queries',
              'Use prompt optimization techniques',
              'Consider using smaller models for simple tasks',
              'Add usage monitoring and alerts'
            ]
          });
          optimizationScore -= 20;
        }
      }

      // Security optimizations
      if (optimizationType === 'security' || optimizationType === 'all') {
        if (module.parameters) {
          const paramStr = JSON.stringify(module.parameters);
          if (paramStr.includes('password') || paramStr.includes('secret') || paramStr.includes('token')) {
            recommendations.push({
              category: 'security',
              priority: 'high',
              title: 'Secure Credential Management',
              description: `Module (ID: ${module.id}) may contain hardcoded credentials`,
              estimatedImpact: 'Critical security improvement',
              implementationSteps: [
                'Move credentials to secure variable storage',
                'Use Make.com connection system instead of hardcoded values',
                'Enable scenario confidential mode',
                'Regularly rotate credentials'
              ]
            });
            optimizationScore -= 25;
            metrics.securityScore -= 30;
          }
        }

        if (!bp.metadata?.scenario?.confidential) {
          recommendations.push({
            category: 'security',
            priority: 'medium',
            title: 'Enable Confidential Mode',
            description: 'Scenario is not marked as confidential, which may expose sensitive data',
            estimatedImpact: 'Enhanced data privacy and security',
            implementationSteps: [
              'Enable confidential mode in scenario metadata',
              'Review data handling and logging practices',
              'Ensure compliance with privacy regulations'
            ]
          });
          optimizationScore -= 10;
          metrics.securityScore -= 15;
        }
      }
    });

    // Calculate complexity score
    metrics.complexityScore = Math.min(100, (metrics.moduleCount * 2) + (metrics.connectionCount * 3) + (moduleTypes.size * 1.5));

    // Workflow-level optimizations
    if (metrics.moduleCount > 100) {
      recommendations.push({
        category: 'performance',
        priority: 'high',
        title: 'Consider Workflow Decomposition',
        description: `Large workflow with ${metrics.moduleCount} modules may benefit from decomposition`,
        estimatedImpact: 'Improved maintainability and performance',
        implementationSteps: [
          'Identify logical workflow boundaries',
          'Split into smaller, focused workflows',
          'Use webhooks or API calls to connect workflows',
          'Implement proper error handling between workflows'
        ]
      });
      optimizationScore -= 15;
    }

    if (metrics.connectionCount > 10) {
      recommendations.push({
        category: 'cost',
        priority: 'medium',
        title: 'Optimize Connection Usage',
        description: `High number of connections (${metrics.connectionCount}) may increase costs`,
        estimatedImpact: '10-30% cost reduction',
        implementationSteps: [
          'Consolidate similar service connections',
          'Use connection pooling where available',
          'Monitor connection usage and quotas',
          'Consider caching strategies for repeated API calls'
        ]
      });
      optimizationScore -= 8;
    }

    // Reliability recommendations
    if (!bp.metadata?.scenario?.dlq) {
      recommendations.push({
        category: 'reliability',
        priority: 'medium',
        title: 'Enable Dead Letter Queue',
        description: 'Enable DLQ to handle failed executions gracefully',
        estimatedImpact: 'Improved error recovery and debugging',
        implementationSteps: [
          'Enable DLQ in scenario metadata',
          'Configure appropriate retry policies',
          'Set up monitoring for failed executions',
          'Implement error handling workflows'
        ]
      });
      optimizationScore -= 5;
    }

  } catch (error) {
    throw new Error(`Blueprint optimization failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }

  return {
    optimizationScore: Math.max(0, Math.round(optimizationScore)),
    recommendations: recommendations.sort((a, b) => {
      const priorityOrder: Record<string, number> = { high: 3, medium: 2, low: 1 };
      return (priorityOrder[b.priority] || 0) - (priorityOrder[a.priority] || 0);
    }),
    metrics
  };
}