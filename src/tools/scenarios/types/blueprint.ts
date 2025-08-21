/**
 * @fileoverview Blueprint-related types for Make.com scenarios
 * Type definitions for scenario blueprints and their components
 */

export interface BlueprintModule {
  id: number;
  module: string;
  version: number;
  parameters?: Record<string, unknown>;
  connection?: number;
  metadata?: Record<string, unknown>;
}

export interface Blueprint {
  name?: string;
  metadata?: {
    version?: number;
    scenario?: {
      roundtrips?: number;
      maxErrors?: number;
      autoCommit?: boolean;
      sequential?: boolean;
      confidential?: boolean;
      dlq?: boolean;
    };
  };
  flow?: BlueprintModule[];
  [key: string]: unknown;
}

// OptimizationRecommendation moved to optimization.ts