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

// Troubleshooting schemas moved to troubleshooting.ts to avoid duplication

// Type exports for better TypeScript integration
export type ScenarioFilters = z.infer<typeof ScenarioFiltersSchema>;
export type ScenarioDetail = z.infer<typeof ScenarioDetailSchema>;
export type RunScenario = z.infer<typeof RunScenarioSchema>;
// TroubleshootScenario and GenerateTroubleshootingReport types moved to troubleshooting.ts