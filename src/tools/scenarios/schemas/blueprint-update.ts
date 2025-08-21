/**
 * @fileoverview Blueprint and scenario modification schemas
 * @description Update and modification schemas for scenario creation, updates, and blueprint operations
 */

import { z } from 'zod';

/**
 * Common scheduling configuration schema used across multiple operations
 */
const SchedulingSchema = z.object({
  type: z.enum(['immediately', 'interval', 'cron']),
  interval: z.number().positive().optional().describe('Interval in minutes for interval scheduling'),
  cron: z.string().optional().describe('Cron expression for cron scheduling'),
}).describe('Scheduling configuration');

/**
 * Schema for creating new scenarios
 */
export const CreateScenarioSchema = z.object({
  name: z.string().min(1).max(100).describe('Scenario name (required)'),
  teamId: z.string().optional().describe('Team ID to create scenario in'),
  folderId: z.string().optional().describe('Folder ID to organize scenario'),
  blueprint: z.any().optional().describe('Scenario blueprint/configuration JSON'),
  scheduling: SchedulingSchema.extend({
    type: z.enum(['immediately', 'interval', 'cron']).default('immediately'),
  }).optional().describe('Scheduling configuration'),
}).strict();

/**
 * Schema for updating existing scenarios
 */
export const UpdateScenarioSchema = z.object({
  scenarioId: z.string().min(1).describe('Scenario ID to update (required)'),
  name: z.string().min(1).max(100).optional().describe('New scenario name'),
  active: z.boolean().optional().describe('Set scenario active/inactive status'),
  blueprint: z.any().optional().describe('Updated scenario blueprint/configuration'),
  scheduling: SchedulingSchema.optional().describe('Updated scheduling configuration'),
}).strict();

/**
 * Schema for deleting scenarios
 */
export const DeleteScenarioSchema = z.object({
  scenarioId: z.string().min(1).describe('Scenario ID to delete (required)'),
  force: z.boolean().default(false).describe('Force delete even if scenario is active'),
}).strict();

/**
 * Schema for cloning scenarios
 */
export const CloneScenarioSchema = z.object({
  scenarioId: z.string().min(1).describe('Source scenario ID to clone (required)'),
  name: z.string().min(1).max(100).describe('Name for the cloned scenario (required)'),
  teamId: z.string().optional().describe('Target team ID (defaults to source scenario team)'),
  folderId: z.string().optional().describe('Target folder ID'),
  active: z.boolean().default(false).describe('Whether to activate the cloned scenario'),
}).strict();

/**
 * Schema for validating blueprints
 */
export const ValidateBlueprintSchema = z.object({
  blueprint: z.any().describe('Blueprint JSON to validate against Make.com schema'),
  strict: z.boolean().default(false).describe('Whether to apply strict validation mode'),
  includeSecurityChecks: z.boolean().default(true).describe('Include security validation checks'),
});

/**
 * Schema for extracting connections from blueprints
 */
export const ExtractBlueprintConnectionsSchema = z.object({
  blueprint: z.any().describe('Blueprint JSON to extract connections from'),
  includeOptional: z.boolean().default(false).describe('Include optional connections in results'),
  groupByModule: z.boolean().default(true).describe('Group connections by module type'),
});

/**
 * Schema for optimizing blueprints
 */
export const OptimizeBlueprintSchema = z.object({
  blueprint: z.any().describe('Blueprint JSON to analyze and optimize'),
  optimizationType: z.enum(['performance', 'cost', 'security', 'all']).default('performance').describe('Type of optimization to focus on'),
  includeImplementationSteps: z.boolean().default(true).describe('Include step-by-step implementation guidance'),
});

// Type exports for better TypeScript integration
export type CreateScenario = z.infer<typeof CreateScenarioSchema>;
export type UpdateScenario = z.infer<typeof UpdateScenarioSchema>;
export type DeleteScenario = z.infer<typeof DeleteScenarioSchema>;
export type CloneScenario = z.infer<typeof CloneScenarioSchema>;
export type ValidateBlueprint = z.infer<typeof ValidateBlueprintSchema>;
export type ExtractBlueprintConnections = z.infer<typeof ExtractBlueprintConnectionsSchema>;
export type OptimizeBlueprint = z.infer<typeof OptimizeBlueprintSchema>;