/**
 * @fileoverview Schema definitions for scenario CRUD operations
 */

import { z } from 'zod';

export const CreateScenarioSchema = z.object({
  name: z.string().min(1).max(100).describe('Scenario name (required)'),
  teamId: z.string().optional().describe('Team ID to create scenario in'),
  folderId: z.string().optional().describe('Folder ID to organize scenario'),
  blueprint: z.any().optional().describe('Scenario blueprint/configuration JSON'),
  scheduling: z.object({
    type: z.enum(['immediately', 'interval', 'cron']).default('immediately'),
    interval: z.number().positive().optional().describe('Interval in minutes for interval scheduling'),
    cron: z.string().optional().describe('Cron expression for cron scheduling'),
  }).optional().describe('Scheduling configuration'),
}).strict();

export const UpdateScenarioSchema = z.object({
  scenarioId: z.string().min(1).describe('Scenario ID to update (required)'),
  name: z.string().min(1).max(100).optional().describe('New scenario name'),
  active: z.boolean().optional().describe('Set scenario active/inactive status'),
  blueprint: z.any().optional().describe('Updated scenario blueprint/configuration'),
  scheduling: z.object({
    type: z.enum(['immediately', 'interval', 'cron']),
    interval: z.number().positive().optional(),
    cron: z.string().optional(),
  }).optional().describe('Updated scheduling configuration'),
}).strict();

export const DeleteScenarioSchema = z.object({
  scenarioId: z.string().min(1).describe('Scenario ID to delete (required)'),
  force: z.boolean().default(false).describe('Force delete even if scenario is active'),
}).strict();

export const ScenarioDetailSchema = z.object({
  scenarioId: z.string().min(1).describe('Scenario ID to retrieve details for (required)'),
  includeBlueprint: z.boolean().default(false).describe('Include full scenario blueprint in response'),
  includeExecutions: z.boolean().default(false).describe('Include recent execution history'),
}).strict();

export const CloneScenarioSchema = z.object({
  scenarioId: z.string().min(1).describe('Source scenario ID to clone (required)'),
  name: z.string().min(1).max(100).describe('Name for the cloned scenario (required)'),
  teamId: z.string().optional().describe('Target team ID (defaults to source scenario team)'),
  folderId: z.string().optional().describe('Target folder ID'),
  active: z.boolean().default(false).describe('Whether to activate the cloned scenario'),
}).strict();

export const RunScenarioSchema = z.object({
  scenarioId: z.string().min(1).describe('Scenario ID to execute (required)'),
  wait: z.boolean().default(true).describe('Wait for execution to complete'),
  timeout: z.number().min(1).max(300).default(60).describe('Timeout in seconds for execution'),
}).strict();