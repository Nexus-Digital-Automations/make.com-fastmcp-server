/**
 * @fileoverview Blueprint Analysis Utilities
 * 
 * Provides comprehensive blueprint validation, structure analysis, and security checks
 * for Make.com blueprint files. Includes utilities for connection extraction and
 * dependency mapping.
 * 
 * @version 1.0.0
 */

import { z } from 'zod';

// Blueprint type definitions
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

// Zod schemas for validation
export const ValidateBlueprintSchema = z.object({
  blueprint: z.any().describe('Blueprint JSON to validate against Make.com schema'),
  strict: z.boolean().default(false).describe('Whether to apply strict validation mode'),
  includeSecurityChecks: z.boolean().default(true).describe('Include security validation checks'),
});

export const ExtractBlueprintConnectionsSchema = z.object({
  blueprint: z.any().describe('Blueprint JSON to extract connections from'),
  includeOptional: z.boolean().default(false).describe('Include optional connections in results'),
  groupByModule: z.boolean().default(true).describe('Group connections by module type'),
});

// Blueprint validation function
export function validateBlueprintStructure(blueprint: unknown, strict: boolean = false): { 
  isValid: boolean; 
  errors: string[]; 
  warnings: string[]; 
  securityIssues: Array<{ type: string; description: string; severity: 'low' | 'medium' | 'high' | 'critical' }>; 
} {
  const errors: string[] = [];
  const warnings: string[] = [];
  const securityIssues: Array<{ type: string; description: string; severity: 'low' | 'medium' | 'high' | 'critical' }> = [];

  try {
    // Check if blueprint is an object
    if (!blueprint || typeof blueprint !== 'object') {
      errors.push('Blueprint must be a valid JSON object');
      return { isValid: false, errors, warnings, securityIssues };
    }

    const bp = blueprint as Blueprint;

    // Validate required top-level properties
    if (!bp.name || typeof bp.name !== 'string') {
      errors.push('Blueprint must have a name property of type string');
    }

    if (!bp.flow || !Array.isArray(bp.flow)) {
      errors.push('Blueprint must have a flow property containing an array of modules');
    }

    if (!bp.metadata || typeof bp.metadata !== 'object') {
      errors.push('Blueprint must have metadata property');
    } else {
      // Validate metadata structure
      if (typeof bp.metadata.version !== 'number') {
        errors.push('Blueprint metadata must include version number');
      }

      if (!bp.metadata.scenario || typeof bp.metadata.scenario !== 'object') {
        errors.push('Blueprint metadata must include scenario configuration');
      } else {
        const scenario = bp.metadata.scenario;
        
        // Check critical scenario settings
        if (typeof scenario.roundtrips !== 'number' || scenario.roundtrips < 1) {
          warnings.push('Scenario roundtrips should be a positive number');
        }
        
        if (typeof scenario.maxErrors !== 'number' || scenario.maxErrors < 0) {
          warnings.push('Scenario maxErrors should be a non-negative number');
        }

        if (typeof scenario.autoCommit !== 'boolean') {
          warnings.push('Scenario autoCommit should be a boolean value');
        }

        if (typeof scenario.sequential !== 'boolean') {
          warnings.push('Scenario sequential should be a boolean value');
        }

        if (typeof scenario.confidential !== 'boolean') {
          warnings.push('Scenario confidential should be a boolean value');
        }
      }
    }

    // Validate flow modules
    if (bp.flow && Array.isArray(bp.flow)) {
      bp.flow.forEach((module: BlueprintModule, index: number) => {
        if (!module || typeof module !== 'object') {
          errors.push(`Module at index ${index} must be an object`);
          return;
        }

        if (typeof module.id !== 'number' || module.id < 1) {
          errors.push(`Module at index ${index} must have a positive numeric id`);
        }

        if (!module.module || typeof module.module !== 'string') {
          errors.push(`Module at index ${index} must have a module type string`);
        }

        if (typeof module.version !== 'number' || module.version < 1) {
          errors.push(`Module at index ${index} must have a positive version number`);
        }

        // Security checks
        if (module.parameters) {
          const paramStr = JSON.stringify(module.parameters).toLowerCase();
          
          // Check for potential hardcoded secrets
          const secretPatterns = ['password', 'secret', 'token', 'apikey', 'api_key', 'key'];
          secretPatterns.forEach(pattern => {
            if (paramStr.includes(pattern) && paramStr.includes('=')) {
              securityIssues.push({
                type: 'potential_hardcoded_secret',
                description: `Module ${module.id} may contain hardcoded secrets in parameters`,
                severity: 'high'
              });
            }
          });

          // Check for URLs with credentials
          const urlWithCredentialsPattern = /https?:\/\/[^:/\s]+:[^@/\s]+@/;
          if (urlWithCredentialsPattern.test(paramStr)) {
            securityIssues.push({
              type: 'credentials_in_url',
              description: `Module ${module.id} contains credentials in URL parameters`,
              severity: 'critical'
            });
          }
        }

        // Performance warnings
        if (strict) {
          if (!module.metadata) {
            warnings.push(`Module ${module.id} is missing metadata (recommended for better performance)`);
          }

          if (module.connection && typeof module.connection !== 'number') {
            warnings.push(`Module ${module.id} has invalid connection reference`);
          }
        }
      });

      // Check for duplicate module IDs
      const moduleIds = bp.flow.map((m: BlueprintModule) => m.id).filter((id: number | undefined): id is number => typeof id === 'number');
      const duplicateIds = moduleIds.filter((id: number, index: number) => moduleIds.indexOf(id) !== index);
      if (duplicateIds.length > 0) {
        errors.push(`Duplicate module IDs found: ${duplicateIds.join(', ')}`);
      }

      // Check for sequential module ID gaps (warning only)
      const sortedIds = [...new Set(moduleIds as number[])].sort((a: number, b: number) => a - b);
      for (let i = 1; i < sortedIds.length; i++) {
        if (sortedIds[i] - sortedIds[i - 1] > 1) {
          warnings.push(`Non-sequential module IDs detected (gap between ${sortedIds[i - 1]} and ${sortedIds[i]})`);
          break;
        }
      }
    }

    // Additional security checks
    if (bp.metadata?.scenario?.confidential === false) {
      securityIssues.push({
        type: 'non_confidential_scenario',
        description: 'Scenario is not marked as confidential - consider security implications',
        severity: 'low'
      });
    }

    if (bp.metadata?.scenario?.dlq === false) {
      warnings.push('Dead Letter Queue is disabled - failed executions may be lost');
    }

  } catch (error) {
    errors.push(`Blueprint validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }

  return {
    isValid: errors.length === 0,
    errors,
    warnings,
    securityIssues
  };
}

// Connection extraction function
export function extractBlueprintConnections(blueprint: unknown, includeOptional: boolean = false): {
  requiredConnections: Array<{ moduleId: number; moduleType: string; connectionId?: number; service?: string; required: boolean }>;
  connectionSummary: { totalModules: number; modulesRequiringConnections: number; uniqueServices: string[] };
  dependencyMap: Record<string, number[]>;
} {
  const connections: Array<{ moduleId: number; moduleType: string; connectionId?: number; service?: string; required: boolean }> = [];
  const serviceMap = new Map<string, number[]>();

  try {
    if (!blueprint || typeof blueprint !== 'object') {
      throw new Error('Invalid blueprint structure');
    }

    const bp = blueprint as Blueprint;

    if (!bp.flow || !Array.isArray(bp.flow)) {
      throw new Error('Blueprint must contain a flow array');
    }

    bp.flow.forEach((module: BlueprintModule) => {
      if (!module || typeof module.id !== 'number' || !module.module) {
        return; // Skip invalid modules
      }

      const moduleType = module.module;
      
      // Determine if this module type typically requires connections
      const requiresConnection = moduleType !== 'builtin:BasicRouter' && 
                               moduleType !== 'builtin:Delay' &&
                               moduleType !== 'builtin:JSONTransformer' &&
                               moduleType !== 'builtin:Iterator' &&
                               !moduleType.startsWith('builtin:');

      if (requiresConnection || module.connection) {
        const connection = {
          moduleId: module.id,
          moduleType: moduleType,
          connectionId: module.connection,
          service: moduleType.split(':')[0] || 'unknown',
          required: requiresConnection
        };

        // Include all required connections, and optional ones if specified
        if (connection.required || (includeOptional && module.connection)) {
          connections.push(connection);
        }

        // Build service dependency map
        if (connection.service) {
          if (!serviceMap.has(connection.service)) {
            serviceMap.set(connection.service, []);
          }
          serviceMap.get(connection.service)!.push(module.id);
        }
      }
    });

    // Build dependency map from service map
    const dependencyMap: Record<string, number[]> = {};
    serviceMap.forEach((moduleIds, service) => {
      dependencyMap[service] = moduleIds;
    });

    return {
      requiredConnections: connections,
      connectionSummary: {
        totalModules: bp.flow.length,
        modulesRequiringConnections: connections.length,
        uniqueServices: Array.from(serviceMap.keys())
      },
      dependencyMap
    };

  } catch (error) {
    throw new Error(`Connection extraction failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}