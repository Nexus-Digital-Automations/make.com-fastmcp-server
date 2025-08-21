/**
 * @fileoverview Scenario filtering and query validation schemas
 * @description Input validation schemas for filtering operations, querying, and diagnostics
 */

import { z } from 'zod';

/**
 * Schema for filtering scenarios in list operations
 */
export const ScenarioFiltersSchema = z.object({
  teamId: z.string().optional().describe('Filter by team ID'),
  folderId: z.string().optional().describe('Filter by folder ID'),
  limit: z.number().min(1).max(100).default(10).describe('Number of scenarios to retrieve (1-100)'),
  offset: z.number().min(0).default(0).describe('Number of scenarios to skip'),
  search: z.string().optional().describe('Search term to filter scenarios'),
  active: z.boolean().optional().describe('Filter by active/inactive status'),
}).strict();

/**
 * Schema for retrieving detailed scenario information
 */
export const ScenarioDetailSchema = z.object({
  scenarioId: z.string().min(1).describe('Scenario ID to retrieve details for (required)'),
  includeBlueprint: z.boolean().default(false).describe('Include full scenario blueprint in response'),
  includeExecutions: z.boolean().default(false).describe('Include recent execution history'),
}).strict();

/**
 * Schema for running/executing scenarios
 */
export const RunScenarioSchema = z.object({
  scenarioId: z.string().min(1).describe('Scenario ID to execute (required)'),
  wait: z.boolean().default(true).describe('Wait for execution to complete'),
  timeout: z.number().min(1).max(300).default(60).describe('Timeout in seconds for execution'),
}).strict();

/**
 * Schema for troubleshooting individual scenarios
 */
export const TroubleshootScenarioSchema = z.object({
  scenarioId: z.string().min(1).describe('Scenario ID to troubleshoot (required)'),
  diagnosticTypes: z.array(z.enum([
    'health', 'performance', 'connections', 'errors', 'security', 'all'
  ])).default(['all']).describe('Types of diagnostics to run'),
  includeRecommendations: z.boolean().default(true).describe('Include fix recommendations'),
  includePerformanceHistory: z.boolean().default(true).describe('Include performance trend analysis'),
  severityFilter: z.enum(['info', 'warning', 'error', 'critical']).optional().describe('Minimum severity level to report'),
  autoFix: z.boolean().default(false).describe('Attempt automatic fixes for fixable issues'),
  timeRange: z.object({
    hours: z.number().min(1).max(720).default(24).describe('Hours of execution history to analyze')
  }).optional().describe('Time range for historical analysis')
}).strict();

/**
 * Schema for generating comprehensive troubleshooting reports
 */
export const GenerateTroubleshootingReportSchema = z.object({
  scenarioIds: z.array(z.string().min(1)).optional().describe('Specific scenario IDs to analyze (optional - if not provided, analyzes all scenarios)'),
  reportOptions: z.object({
    includeExecutiveSummary: z.boolean().default(true).describe('Include executive summary with key findings'),
    includeDetailedAnalysis: z.boolean().default(true).describe('Include detailed diagnostic analysis'),
    includeActionPlan: z.boolean().default(true).describe('Include prioritized action plan'),
    includePerformanceMetrics: z.boolean().default(true).describe('Include performance benchmarks and metrics'),
    includeSecurityAssessment: z.boolean().default(true).describe('Include security and compliance assessment'),
    includeCostAnalysis: z.boolean().default(false).describe('Include cost impact analysis'),
    includeRecommendationTimeline: z.boolean().default(true).describe('Include timeline for implementing recommendations'),
    formatType: z.enum(['json', 'markdown', 'pdf-ready']).default('json').describe('Output format for the report')
  }).optional().describe('Report generation options'),
  analysisFilters: z.object({
    timeRangeHours: z.number().min(1).max(720).default(24).describe('Time range for analysis (hours)'),
    severityThreshold: z.enum(['info', 'warning', 'error', 'critical']).default('info').describe('Minimum severity threshold'),
    includeInactiveScenarios: z.boolean().default(false).describe('Include inactive scenarios in analysis'),
    maxScenariosToAnalyze: z.number().min(1).max(100).default(25).describe('Maximum number of scenarios to analyze'),
    prioritizeByUsage: z.boolean().default(true).describe('Prioritize scenarios by usage/execution frequency')
  }).optional().describe('Analysis filtering and prioritization options'),
  comparisonBaseline: z.object({
    compareToHistorical: z.boolean().default(true).describe('Compare against historical performance'),
    baselineTimeRangeHours: z.number().min(24).max(2160).default(168).describe('Baseline period for comparison (hours)'),
    includeBenchmarks: z.boolean().default(true).describe('Include industry benchmarks')
  }).optional().describe('Baseline comparison settings')
}).strict();

// Type exports for better TypeScript integration
export type ScenarioFilters = z.infer<typeof ScenarioFiltersSchema>;
export type ScenarioDetail = z.infer<typeof ScenarioDetailSchema>;
export type RunScenario = z.infer<typeof RunScenarioSchema>;
export type TroubleshootScenario = z.infer<typeof TroubleshootScenarioSchema>;
export type GenerateTroubleshootingReport = z.infer<typeof GenerateTroubleshootingReportSchema>;