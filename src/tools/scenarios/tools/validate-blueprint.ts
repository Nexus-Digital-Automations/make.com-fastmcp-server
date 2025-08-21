/**
 * @fileoverview Validate Blueprint Tool Implementation
 * Blueprint validation with security and compliance checks
 */

import { UserError } from 'fastmcp';
import { ValidateBlueprintSchema } from '../schemas/blueprint-update.js';
import { ToolContext, ToolDefinition } from '../types/tool-context.js';
import { validateBlueprintStructure } from '../utils/blueprint-analysis.js';

/**
 * Create validate blueprint tool configuration
 */
export function createValidateBlueprintTool(context: ToolContext): ToolDefinition {
  const { apiClient, logger } = context;
  
  return {
    name: 'validate-blueprint',
    description: 'Validate Make.com blueprint JSON against schema with security and compliance checks',
    parameters: ValidateBlueprintSchema,
    annotations: {
      title: 'Validate Blueprint',
      readOnlyHint: true,
    },
    execute: async (args, { log }) => {
      log?.info?.('Validating blueprint', { 
        hasBlueprint: !!args.blueprint,
        strict: args.strict,
        includeSecurityChecks: args.includeSecurityChecks
      });

      try {
        const validationResult = validateBlueprintStructure(
          args.blueprint, 
          args.strict
        );

        log?.info('Blueprint validation completed', {
          isValid: validationResult.isValid,
          errorCount: validationResult.errors.length,
          warningCount: validationResult.warnings.length,
          securityIssueCount: validationResult.securityIssues.length
        });

        return JSON.stringify({
          isValid: validationResult.isValid,
          summary: {
            totalErrors: validationResult.errors.length,
            totalWarnings: validationResult.warnings.length,
            totalSecurityIssues: validationResult.securityIssues.length,
            validationPassed: validationResult.isValid,
            securityChecksPassed: args.includeSecurityChecks ? validationResult.securityIssues.length === 0 : true
          },
          validation: {
            errors: validationResult.errors,
            warnings: validationResult.warnings,
            securityIssues: args.includeSecurityChecks ? validationResult.securityIssues : []
          },
          recommendations: [
            ...validationResult.errors.map(error => `Fix error: ${error}`),
            ...validationResult.warnings.map(warning => `Consider: ${warning}`),
            ...(args.includeSecurityChecks ? validationResult.securityIssues
              .filter(issue => issue.severity === 'critical' || issue.severity === 'high')
              .map(issue => `Security: ${issue.description}`) : [])
          ].slice(0, 10)
        }, null, 2);

      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log?.error('Blueprint validation failed', { error: errorMessage });
        throw new UserError(`Blueprint validation failed: ${errorMessage}`);
      }
    }
  };
}