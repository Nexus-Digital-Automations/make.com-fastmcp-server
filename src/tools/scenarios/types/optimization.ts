/**
 * @fileoverview Optimization algorithm types for Make.com scenarios
 * Type definitions for performance optimization, algorithm recommendations, and enhancement suggestions
 */

import { PerformanceAnalysisResult } from './report.js';

export interface OptimizationRecommendation {
  category: string;
  priority: 'high' | 'medium' | 'low';
  title: string;
  description: string;
  estimatedImpact?: string;
  implementationSteps?: string[];
}

export interface OptimizationAnalysis {
  scenarioId: string;
  scenarioName: string;
  currentPerformance: PerformanceAnalysisResult;
  optimizationOpportunities: OptimizationRecommendation[];
  estimatedImprovements: {
    responseTimeReduction: number;
    throughputIncrease: number;
    errorReduction: number;
    costSavings: number;
  };
  implementationComplexity: 'low' | 'medium' | 'high' | 'critical';
  recommendedActions: {
    immediate: string[];
    shortTerm: string[];
    longTerm: string[];
  };
}

export interface BlueprintOptimizationResult {
  originalBlueprint: unknown;
  optimizedBlueprint: unknown;
  optimizations: Array<{
    type: 'performance' | 'reliability' | 'cost' | 'maintainability';
    description: string;
    impact: 'high' | 'medium' | 'low';
    changes: Array<{
      moduleId: number;
      changetype: 'parameter' | 'connection' | 'flow' | 'metadata';
      before: unknown;
      after: unknown;
      reason: string;
    }>;
  }>;
  estimatedImprovements: {
    performanceGain: number;
    reliabilityIncrease: number;
    costReduction: number;
    maintainabilityScore: number;
  };
  validationResults: {
    isValid: boolean;
    errors: string[];
    warnings: string[];
  };
}

export interface PerformanceOptimizationMetrics {
  baseline: {
    responseTime: number;
    throughput: number;
    errorRate: number;
    resourceUtilization: number;
  };
  optimized: {
    responseTime: number;
    throughput: number;
    errorRate: number;
    resourceUtilization: number;
  };
  improvements: {
    responseTimeImprovement: number;
    throughputImprovement: number;
    errorRateReduction: number;
    resourceEfficiencyGain: number;
  };
  confidence: number;
}

export interface OptimizationStrategy {
  strategyId: string;
  name: string;
  description: string;
  applicableScenarios: string[];
  prerequisites: string[];
  steps: Array<{
    stepNumber: number;
    description: string;
    estimatedTime: string;
    risk: 'low' | 'medium' | 'high';
    rollbackPlan?: string;
  }>;
  expectedOutcome: PerformanceOptimizationMetrics;
  monitoring: {
    keyMetrics: string[];
    alertThresholds: Record<string, number>;
    rollbackCriteria: string[];
  };
}

export interface AutoOptimizationConfig {
  enabled: boolean;
  aggressiveness: 'conservative' | 'moderate' | 'aggressive';
  allowedOptimizations: Array<'performance' | 'cost' | 'reliability' | 'maintainability'>;
  safeguards: {
    requireApproval: boolean;
    maxChangesPerRun: number;
    testInStaging: boolean;
    rollbackOnFailure: boolean;
  };
  schedule: {
    frequency: 'daily' | 'weekly' | 'monthly';
    timeWindow: {
      startHour: number;
      endHour: number;
    };
  };
}