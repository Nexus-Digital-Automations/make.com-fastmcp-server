/**
 * @fileoverview Blueprint Analysis Utilities - Refactored
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

// Type for validation results
type ValidationResult = {
  errors: string[];
  warnings: string[];
  securityIssues: Array<{ type: string; description: string; severity: 'low' | 'medium' | 'high' | 'critical' }>;
};

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
  const result: ValidationResult = {
    errors: [],
    warnings: [],
    securityIssues: []
  };

  try {
    if (!validateBlueprintObject(blueprint, result)) {
      return { isValid: false, ...result };
    }

    const bp = blueprint as Blueprint;
    
    validateBlueprintTopLevel(bp, result);
    validateBlueprintMetadata(bp, result);
    validateBlueprintFlow(bp, result, strict);
    performAdditionalSecurityChecks(bp, result);

  } catch (error) {
    result.errors.push(`Blueprint validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }

  return {
    isValid: result.errors.length === 0,
    ...result
  };
}

/**
 * Validate that blueprint is a valid object
 */
function validateBlueprintObject(blueprint: unknown, result: ValidationResult): boolean {
  if (!blueprint || typeof blueprint !== 'object') {
    result.errors.push('Blueprint must be a valid JSON object');
    return false;
  }
  return true;
}

/**
 * Validate top-level blueprint properties
 */
function validateBlueprintTopLevel(bp: Blueprint, result: ValidationResult): void {
  if (!bp.name || typeof bp.name !== 'string') {
    result.errors.push('Blueprint must have a name property of type string');
  }

  if (!bp.flow || !Array.isArray(bp.flow)) {
    result.errors.push('Blueprint must have a flow property containing an array of modules');
  }

  if (!bp.metadata || typeof bp.metadata !== 'object') {
    result.errors.push('Blueprint must have metadata property');
  }
}

/**
 * Validate blueprint metadata structure
 */
function validateBlueprintMetadata(bp: Blueprint, result: ValidationResult): void {
  if (!bp.metadata || typeof bp.metadata !== 'object') {
    return; // Already validated in top-level
  }

  validateMetadataVersion(bp.metadata, result);
  validateScenarioConfiguration(bp.metadata, result);
}

/**
 * Validate metadata version
 */
function validateMetadataVersion(metadata: NonNullable<Blueprint['metadata']>, result: ValidationResult): void {
  if (typeof metadata.version !== 'number') {
    result.errors.push('Blueprint metadata must include version number');
  }
}

/**
 * Validate scenario configuration in metadata
 */
function validateScenarioConfiguration(metadata: NonNullable<Blueprint['metadata']>, result: ValidationResult): void {
  if (!metadata.scenario || typeof metadata.scenario !== 'object') {
    result.errors.push('Blueprint metadata must include scenario configuration');
    return;
  }

  const scenario = metadata.scenario;
  validateScenarioSettings(scenario, result);
}

/**
 * Validate individual scenario settings
 */
function validateScenarioSettings(scenario: NonNullable<Blueprint['metadata']>['scenario'], result: ValidationResult): void {
  if (!scenario) {return;}

  if (typeof scenario.roundtrips !== 'number' || scenario.roundtrips < 1) {
    result.warnings.push('Scenario roundtrips should be a positive number');
  }
  
  if (typeof scenario.maxErrors !== 'number' || scenario.maxErrors < 0) {
    result.warnings.push('Scenario maxErrors should be a non-negative number');
  }

  if (typeof scenario.autoCommit !== 'boolean') {
    result.warnings.push('Scenario autoCommit should be a boolean value');
  }

  if (typeof scenario.sequential !== 'boolean') {
    result.warnings.push('Scenario sequential should be a boolean value');
  }

  if (typeof scenario.confidential !== 'boolean') {
    result.warnings.push('Scenario confidential should be a boolean value');
  }
}

/**
 * Validate blueprint flow modules
 */
function validateBlueprintFlow(bp: Blueprint, result: ValidationResult, strict: boolean): void {
  if (!bp.flow || !Array.isArray(bp.flow)) {
    return; // Already validated in top-level
  }

  bp.flow.forEach((module, index) => {
    validateIndividualModule(module, index, result, strict);
  });

  validateModuleIds(bp.flow, result);
}

/**
 * Validate individual module structure
 */
function validateIndividualModule(module: BlueprintModule, index: number, result: ValidationResult, strict: boolean): void {
  if (!module || typeof module !== 'object') {
    result.errors.push(`Module at index ${index} must be an object`);
    return;
  }

  validateModuleBasicProperties(module, index, result);
  validateModuleParameters(module, result);
  validateModulePerformance(module, result, strict);
}

/**
 * Validate basic module properties
 */
function validateModuleBasicProperties(module: BlueprintModule, index: number, result: ValidationResult): void {
  if (typeof module.id !== 'number' || module.id < 1) {
    result.errors.push(`Module at index ${index} must have a positive numeric id`);
  }

  if (!module.module || typeof module.module !== 'string') {
    result.errors.push(`Module at index ${index} must have a module type string`);
  }

  if (typeof module.version !== 'number' || module.version < 1) {
    result.errors.push(`Module at index ${index} must have a positive version number`);
  }
}

/**
 * Validate module parameters for security issues
 */
function validateModuleParameters(module: BlueprintModule, result: ValidationResult): void {
  if (!module.parameters) {return;}

  const paramStr = JSON.stringify(module.parameters).toLowerCase();
  
  checkForHardcodedSecrets(paramStr, module.id, result);
  checkForCredentialsInUrls(paramStr, module.id, result);
}

/**
 * Check for potential hardcoded secrets
 */
function checkForHardcodedSecrets(paramStr: string, moduleId: number, result: ValidationResult): void {
  const secretPatterns = ['password', 'secret', 'token', 'apikey', 'api_key', 'key'];
  
  secretPatterns.forEach(pattern => {
    if (paramStr.includes(pattern) && paramStr.includes('=')) {
      result.securityIssues.push({
        type: 'potential_hardcoded_secret',
        description: `Module ${moduleId} may contain hardcoded secrets in parameters`,
        severity: 'high'
      });
    }
  });
}

/**
 * Check for credentials in URLs
 */
function checkForCredentialsInUrls(paramStr: string, moduleId: number, result: ValidationResult): void {
  const urlWithCredentialsPattern = /https?:\/\/[^:/\s]+:[^@/\s]+@/;
  
  if (urlWithCredentialsPattern.test(paramStr)) {
    result.securityIssues.push({
      type: 'credentials_in_url',
      description: `Module ${moduleId} contains credentials in URL parameters`,
      severity: 'critical'
    });
  }
}

/**
 * Validate module performance-related properties
 */
function validateModulePerformance(module: BlueprintModule, result: ValidationResult, strict: boolean): void {
  if (!strict) {return;}

  if (!module.metadata) {
    result.warnings.push(`Module ${module.id} is missing metadata (recommended for better performance)`);
  }

  if (module.connection && typeof module.connection !== 'number') {
    result.warnings.push(`Module ${module.id} has invalid connection reference`);
  }
}

/**
 * Validate module IDs for duplicates and sequential gaps
 */
function validateModuleIds(flow: BlueprintModule[], result: ValidationResult): void {
  const moduleIds = flow.map(m => m.id).filter((id): id is number => typeof id === 'number');
  
  checkForDuplicateIds(moduleIds, result);
  checkForSequentialGaps(moduleIds, result);
}

/**
 * Check for duplicate module IDs
 */
function checkForDuplicateIds(moduleIds: number[], result: ValidationResult): void {
  const duplicateIds = moduleIds.filter((id, index) => moduleIds.indexOf(id) !== index);
  
  if (duplicateIds.length > 0) {
    result.errors.push(`Duplicate module IDs found: ${duplicateIds.join(', ')}`);
  }
}

/**
 * Check for sequential module ID gaps
 */
function checkForSequentialGaps(moduleIds: number[], result: ValidationResult): void {
  const sortedIds = Array.from(new Set(moduleIds)).sort((a, b) => a - b);
  
  for (let i = 1; i < sortedIds.length; i++) {
    if (sortedIds[i] - sortedIds[i - 1] > 1) {
      result.warnings.push(`Non-sequential module IDs detected (gap between ${sortedIds[i - 1]} and ${sortedIds[i]})`);
      break;
    }
  }
}

/**
 * Perform additional security checks
 */
function performAdditionalSecurityChecks(bp: Blueprint, result: ValidationResult): void {
  checkConfidentialMode(bp, result);
  checkDeadLetterQueue(bp, result);
}

/**
 * Check confidential mode setting
 */
function checkConfidentialMode(bp: Blueprint, result: ValidationResult): void {
  if (bp.metadata?.scenario?.confidential === false) {
    result.securityIssues.push({
      type: 'non_confidential_scenario',
      description: 'Scenario is not marked as confidential - consider security implications',
      severity: 'low'
    });
  }
}

/**
 * Check Dead Letter Queue setting
 */
function checkDeadLetterQueue(bp: Blueprint, result: ValidationResult): void {
  if (bp.metadata?.scenario?.dlq === false) {
    result.warnings.push('Dead Letter Queue is disabled - failed executions may be lost');
  }
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
          const serviceModules = serviceMap.get(connection.service);
          if (serviceModules) {
            serviceModules.push(module.id);
          }
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