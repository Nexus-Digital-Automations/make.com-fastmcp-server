/**
 * @fileoverview Scenarios Utility Index
 * 
 * Centralized exports for all scenario utility functions and types.
 * This file aggregates all utility modules for easy importing.
 * 
 * @version 1.0.0
 */

import { OptimizationRecommendation } from '../types/optimization.js';

// Blueprint Analysis exports
export type {
  Blueprint,
  BlueprintModule,
  ValidateBlueprintSchema,
  ExtractBlueprintConnectionsSchema,
} from './blueprint-analysis.js';

export {
  validateBlueprintStructure,
  extractBlueprintConnections
} from './blueprint-analysis.js';

// Optimization exports
export type {
  OptimizationMetrics,
  OptimizationResult,
  OptimizeBlueprintSchema,
} from './optimization.js';

export {
  optimizeBlueprint
} from './optimization.js';

// Re-export OptimizationRecommendation from types
export type { OptimizationRecommendation } from '../types/optimization.js';

// Troubleshooting exports
export type {
  ScenarioAnalysis,
  ConsolidatedFindings,
  ActionPlan,
  SystemOverview,
  CostAnalysisReport,
} from './troubleshooting.js';

export {
  aggregateFindings,
  generateSystemOverview,
  generateActionPlan,
  generateCostAnalysis,
  generateExecutiveSummary,
  generateTroubleshootingReport
} from './troubleshooting.js';

// Report Formatting exports
export {
  formatAsMarkdown,
  formatAsPdfReady
} from './report-formatting.js';

// Utility type definitions for common use cases
export type BlueprintValidationResult = {
  isValid: boolean;
  errors: string[];
  warnings: string[];
  securityIssues: Array<{ 
    type: string; 
    description: string; 
    severity: 'low' | 'medium' | 'high' | 'critical' 
  }>;
};

export type ConnectionExtractionResult = {
  requiredConnections: Array<{ 
    moduleId: number; 
    moduleType: string; 
    connectionId?: number; 
    service?: string; 
    required: boolean 
  }>;
  connectionSummary: { 
    totalModules: number; 
    modulesRequiringConnections: number; 
    uniqueServices: string[] 
  };
  dependencyMap: Record<string, number[]>;
};

export type OptimizationResultType = {
  optimizationScore: number;
  recommendations: OptimizationRecommendation[];
  metrics: {
    moduleCount: number;
    connectionCount: number;
    complexityScore: number;
    securityScore: number;
  };
};

// Utility constants for common operations
export const BUILTIN_MODULES = [
  'builtin:BasicRouter',
  'builtin:Delay',
  'builtin:JSONTransformer',
  'builtin:Iterator'
] as const;

export const SECURITY_PATTERNS = [
  'password',
  'secret', 
  'token',
  'apikey',
  'api_key',
  'key'
] as const;

export const OPTIMIZATION_CATEGORIES = [
  'performance',
  'cost',
  'security',
  'reliability'
] as const;

export const PRIORITY_LEVELS = [
  'low',
  'medium',
  'high',
  'critical'
] as const;

export const HEALTH_THRESHOLDS = {
  HEALTHY: 80,
  WARNING: 60,
  CRITICAL: 0
} as const;

// Helper functions for common operations
export function isBuiltinModule(moduleType: string): boolean {
  return BUILTIN_MODULES.some(builtin => moduleType.startsWith(builtin));
}

export function getHealthCategory(score: number): 'healthy' | 'warning' | 'critical' {
  if (score >= HEALTH_THRESHOLDS.HEALTHY) {return 'healthy';}
  if (score >= HEALTH_THRESHOLDS.WARNING) {return 'warning';}
  return 'critical';
}

export function prioritizeRecommendations(
  recommendations: OptimizationRecommendation[]
): OptimizationRecommendation[] {
  const priorityOrder: Record<string, number> = { 
    critical: 4, 
    high: 3, 
    medium: 2, 
    low: 1 
  };
  
  return recommendations.sort((a, b) => 
    (priorityOrder[b.priority] || 0) - (priorityOrder[a.priority] || 0)
  );
}

export function calculateComplexityScore(
  moduleCount: number, 
  connectionCount: number, 
  uniqueServices: number
): number {
  return Math.min(100, (moduleCount * 2) + (connectionCount * 3) + (uniqueServices * 1.5));
}

export function estimateExecutionCost(
  moduleCount: number, 
  complexityScore: number,
  hasAI: boolean = false
): number {
  const baseCost = moduleCount * 0.01; // $0.01 per module execution
  const complexityMultiplier = 1 + (complexityScore / 200); // Up to 1.5x for high complexity
  const aiMultiplier = hasAI ? 5 : 1; // AI modules cost 5x more
  
  return baseCost * complexityMultiplier * aiMultiplier;
}