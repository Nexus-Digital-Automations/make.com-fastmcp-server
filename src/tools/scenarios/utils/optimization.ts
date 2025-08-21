/**
 * @fileoverview Blueprint Optimization Utilities
 * 
 * Provides optimization analysis and recommendations for Make.com blueprints.
 * Analyzes performance, cost, and architecture patterns to suggest improvements.
 * 
 * @version 1.0.0
 */

import { Blueprint, BlueprintModule } from '../types/blueprint.js';
import { OptimizationRecommendation, OptimizationMetrics, OptimizationResult } from '../types/optimization.js';

/**
 * Analyze blueprint and provide optimization recommendations
 */
export function optimizeBlueprint(blueprint: Blueprint): OptimizationResult {
  const metrics: OptimizationMetrics = {
    moduleCount: 0,
    connectionCount: 0,
    complexityScore: 0,
    estimatedExecutionTime: 0,
    memoryUsage: 0,
    networkCalls: 0
  };

  const recommendations: OptimizationRecommendation[] = [];
  let optimizationScore = 100;

  try {
    if (!blueprint?.flow || !Array.isArray(blueprint.flow)) {
      throw new Error('Invalid blueprint structure - missing or invalid flow');
    }

    const bp = blueprint;
    metrics.moduleCount = bp.flow.length;

    // Analyze modules and connections
    const connectionIds = new Set<number>();
    const moduleTypes = new Set<string>();

    bp.flow.forEach((module: BlueprintModule) => {
      if (module.connection) {
        connectionIds.add(module.connection);
        metrics.connectionCount++;
      }
      
      if (module.module) {
        moduleTypes.add(module.module);
        
        // Estimate network calls based on module type
        if (!module.module.startsWith('builtin:')) {
          metrics.networkCalls++;
        }
      }

      // Estimate execution time (simplified heuristic)
      metrics.estimatedExecutionTime += getModuleExecutionTime(module.module || '');
      
      // Estimate memory usage
      metrics.memoryUsage += getModuleMemoryUsage(module.module || '', module.parameters);
    });

    // Calculate complexity score
    metrics.complexityScore = Math.min(100, 
      (metrics.moduleCount * 2) + 
      (metrics.connectionCount * 3) + 
      (moduleTypes.size * 1.5)
    );

    // Generate recommendations based on analysis
    generateOptimizationRecommendations(bp, metrics, recommendations, optimizationScore);

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

/**
 * Generate optimization recommendations based on blueprint analysis
 */
function generateOptimizationRecommendations(
  blueprint: Blueprint,
  metrics: OptimizationMetrics,
  recommendations: OptimizationRecommendation[],
  optimizationScore: number
): void {
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
  if (!blueprint.metadata?.scenario?.dlq) {
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

  // Performance recommendations
  if (metrics.networkCalls > 50) {
    recommendations.push({
      category: 'performance',
      priority: 'high',
      title: 'Reduce Network Calls',
      description: `High number of network calls (${metrics.networkCalls}) may impact performance`,
      estimatedImpact: '20-40% performance improvement',
      implementationSteps: [
        'Implement request batching where possible',
        'Use bulk operations instead of individual calls',
        'Cache frequently accessed data',
        'Consider asynchronous processing patterns'
      ]
    });
    optimizationScore -= 12;
  }

  // Security recommendations
  if (blueprint.metadata?.scenario?.confidential === false) {
    recommendations.push({
      category: 'security',
      priority: 'low',
      title: 'Enable Confidential Mode',
      description: 'Consider marking scenario as confidential for better security',
      estimatedImpact: 'Improved data security and compliance',
      implementationSteps: [
        'Enable confidential flag in scenario metadata',
        'Review data handling practices',
        'Implement additional access controls',
        'Document security considerations'
      ]
    });
    optimizationScore -= 3;
  }
}

/**
 * Estimate execution time for a module type (in milliseconds)
 */
function getModuleExecutionTime(moduleType: string): number {
  const executionTimes: Record<string, number> = {
    'builtin:BasicRouter': 10,
    'builtin:Delay': 1000,
    'builtin:JSONTransformer': 50,
    'builtin:Iterator': 20,
    'http:ActionSendData': 200,
    'google-sheets': 300,
    'slack': 150,
    'email': 500,
    'database': 100,
    'webhook': 100
  };

  // Extract service from module type
  const service = moduleType.split(':')[0];
  return executionTimes[moduleType] || executionTimes[service] || 250;
}

/**
 * Estimate memory usage for a module (in KB)
 */
function getModuleMemoryUsage(moduleType: string, parameters?: Record<string, unknown>): number {
  const baseMemory = 50; // Base memory per module
  
  // Add memory based on parameter complexity
  let parameterMemory = 0;
  if (parameters) {
    const paramString = JSON.stringify(parameters);
    parameterMemory = Math.min(100, paramString.length / 10);
  }

  // Add memory based on module type
  const moduleMemory = moduleType.startsWith('builtin:') ? 25 : 75;

  return baseMemory + parameterMemory + moduleMemory;
}