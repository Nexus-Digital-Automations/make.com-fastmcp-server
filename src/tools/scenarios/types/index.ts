/**
 * @fileoverview Type aggregation and re-exports for scenarios types
 * Centralized export of all scenario-related TypeScript types
 */

// Re-export blueprint types
export {
  BlueprintModule,
  Blueprint,
} from './blueprint.js';

// Re-export report and analysis types
export {
  ReportMetadata,
  TroubleshootingReportData,
  PerformanceAnalysisResult,
  ScenarioAnalysis,
  ConsolidatedFindings,
  ActionPlan,
  SystemOverview,
  CostAnalysisReport,
  _TroubleshootingReportFormatted,
} from './report.js';

// Re-export optimization types
export {
  OptimizationRecommendation,
  OptimizationAnalysis,
  BlueprintOptimizationResult,
  PerformanceOptimizationMetrics,
  OptimizationStrategy,
  AutoOptimizationConfig,
} from './optimization.js';

/**
 * Collections of related types for easy access
 */
export const ScenarioTypes = {
  // Blueprint-related types
  blueprint: {
    BlueprintModule: {} as BlueprintModule,
    Blueprint: {} as Blueprint,
  },
  
  // Report and analysis types
  report: {
    ReportMetadata: {} as ReportMetadata,
    TroubleshootingReportData: {} as TroubleshootingReportData,
    PerformanceAnalysisResult: {} as PerformanceAnalysisResult,
    ScenarioAnalysis: {} as ScenarioAnalysis,
    ConsolidatedFindings: {} as ConsolidatedFindings,
    ActionPlan: {} as ActionPlan,
    SystemOverview: {} as SystemOverview,
    CostAnalysisReport: {} as CostAnalysisReport,
  },
  
  // Optimization types
  optimization: {
    OptimizationRecommendation: {} as OptimizationRecommendation,
    OptimizationAnalysis: {} as OptimizationAnalysis,
    BlueprintOptimizationResult: {} as BlueprintOptimizationResult,
    PerformanceOptimizationMetrics: {} as PerformanceOptimizationMetrics,
    OptimizationStrategy: {} as OptimizationStrategy,
    AutoOptimizationConfig: {} as AutoOptimizationConfig,
  },
} as const;

/**
 * Type guards for runtime type checking
 */
export const TypeGuards = {
  isBlueprintModule(obj: unknown): obj is BlueprintModule {
    return typeof obj === 'object' && obj !== null && 
           'id' in obj && 'module' in obj && 'version' in obj;
  },

  isBlueprint(obj: unknown): obj is Blueprint {
    return typeof obj === 'object' && obj !== null;
  },

  isPerformanceAnalysisResult(obj: unknown): obj is PerformanceAnalysisResult {
    return typeof obj === 'object' && obj !== null &&
           'analysisTimestamp' in obj && 'targetType' in obj && 'overallHealthScore' in obj;
  },

  isOptimizationRecommendation(obj: unknown): obj is OptimizationRecommendation {
    return typeof obj === 'object' && obj !== null &&
           'category' in obj && 'priority' in obj && 'title' in obj && 'description' in obj;
  }
} as const;

// Re-export imports for convenience
export type {
  BlueprintModule,
  Blueprint,
  ReportMetadata,
  TroubleshootingReportData,
  PerformanceAnalysisResult,
  ScenarioAnalysis,
  ConsolidatedFindings,
  ActionPlan,
  SystemOverview,
  CostAnalysisReport,
  _TroubleshootingReportFormatted,
  OptimizationRecommendation,
  OptimizationAnalysis,
  BlueprintOptimizationResult,
  PerformanceOptimizationMetrics,
  OptimizationStrategy,
  AutoOptimizationConfig,
};