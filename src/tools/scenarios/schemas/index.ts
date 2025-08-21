/**
 * @fileoverview Centralized schema exports for scenarios tool
 * @description Aggregates and re-exports all Zod schemas and types used in scenarios operations
 */

import { z } from 'zod';

// Import schemas for local use
import {
  ScenarioFiltersSchema as _ScenarioFiltersSchema,
  ScenarioDetailSchema as _ScenarioDetailSchema,
  RunScenarioSchema as _RunScenarioSchema,
} from './scenario-filters.js';

import {
  TroubleshootScenarioSchema as _TroubleshootScenarioSchema,
  GenerateTroubleshootingReportSchema as _GenerateTroubleshootingReportSchema,
} from './troubleshooting.js';

import {
  CreateScenarioSchema as _CreateScenarioSchema,
  UpdateScenarioSchema as _UpdateScenarioSchema,
  DeleteScenarioSchema as _DeleteScenarioSchema,
  CloneScenarioSchema as _CloneScenarioSchema,
  ValidateBlueprintSchema as _ValidateBlueprintSchema,
  ExtractBlueprintConnectionsSchema as _ExtractBlueprintConnectionsSchema,
  OptimizeBlueprintSchema as _OptimizeBlueprintSchema,
} from './blueprint-update.js';

// Re-export schemas from scenario-filters
export {
  ScenarioFiltersSchema,
  ScenarioDetailSchema,
  RunScenarioSchema,
  type ScenarioFilters,
  type ScenarioDetail,
  type RunScenario,
} from './scenario-filters.js';

// Re-export troubleshooting schemas
export {
  TroubleshootScenarioSchema,
  GenerateTroubleshootingReportSchema,
  type TroubleshootScenario,
  type GenerateTroubleshootingReport,
} from './troubleshooting.js';

// Re-export all schemas from blueprint-update
export {
  CreateScenarioSchema,
  UpdateScenarioSchema,
  DeleteScenarioSchema,
  CloneScenarioSchema,
  ValidateBlueprintSchema,
  ExtractBlueprintConnectionsSchema,
  OptimizeBlueprintSchema,
  type CreateScenario,
  type UpdateScenario,
  type DeleteScenario,
  type CloneScenario,
  type ValidateBlueprint,
  type ExtractBlueprintConnections,
  type OptimizeBlueprint,
} from './blueprint-update.js';

/**
 * Collection of all scenario-related schemas for easy access
 */
export const ScenariosSchemas = {
  // Filter and query schemas
  filters: {
    ScenarioFiltersSchema: _ScenarioFiltersSchema,
    ScenarioDetailSchema: _ScenarioDetailSchema,
    RunScenarioSchema: _RunScenarioSchema,
    TroubleshootScenarioSchema: _TroubleshootScenarioSchema,
    GenerateTroubleshootingReportSchema: _GenerateTroubleshootingReportSchema,
  },
  
  // Update and modification schemas
  updates: {
    CreateScenarioSchema: _CreateScenarioSchema,
    UpdateScenarioSchema: _UpdateScenarioSchema,
    DeleteScenarioSchema: _DeleteScenarioSchema,
    CloneScenarioSchema: _CloneScenarioSchema,
  },
  
  // Blueprint manipulation schemas
  blueprints: {
    ValidateBlueprintSchema: _ValidateBlueprintSchema,
    ExtractBlueprintConnectionsSchema: _ExtractBlueprintConnectionsSchema,
    OptimizeBlueprintSchema: _OptimizeBlueprintSchema,
  },
} as const;

/**
 * Union of all scenario operation input types
 */
export type ScenarioOperationInput = 
  | z.infer<typeof _ScenarioFiltersSchema>
  | z.infer<typeof _ScenarioDetailSchema>
  | z.infer<typeof _RunScenarioSchema>
  | z.infer<typeof _TroubleshootScenarioSchema>
  | z.infer<typeof _GenerateTroubleshootingReportSchema>
  | z.infer<typeof _CreateScenarioSchema>
  | z.infer<typeof _UpdateScenarioSchema>
  | z.infer<typeof _DeleteScenarioSchema>
  | z.infer<typeof _CloneScenarioSchema>
  | z.infer<typeof _ValidateBlueprintSchema>
  | z.infer<typeof _ExtractBlueprintConnectionsSchema>
  | z.infer<typeof _OptimizeBlueprintSchema>;

/**
 * Schema validation utilities
 */
export const SchemaValidation = {
  /**
   * Validate input against a specific schema
   */
  validate<T>(schema: z.ZodSchema<T>, input: unknown): { success: true; data: T } | { success: false; error: string } {
    try {
      const result = schema.parse(input);
      return { success: true, data: result };
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Validation failed';
      return { 
        success: false, 
        error: errorMessage
      };
    }
  },

  /**
   * Safe parse that returns parsed result or null
   */
  safeParse<T>(schema: z.ZodSchema<T>, input: unknown): T | null {
    try {
      return schema.parse(input);
    } catch {
      return null;
    }
  }
} as const;