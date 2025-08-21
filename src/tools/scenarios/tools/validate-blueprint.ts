/**
 * @fileoverview Validate Blueprint Tool Implementation
 * Blueprint validation with security and compliance checks
 */

import { UserError } from 'fastmcp';
import { ValidateBlueprintSchema } from '../schemas/blueprint-update.js';
import { ToolContext, ToolDefinition } from '../../shared/types/tool-context.js';
import { validateBlueprintStructure } from '../utils/blueprint-analysis.js';

/**
 * Create validate blueprint tool configuration
 */
export function createValidateBlueprintTool(context: ToolContext): ToolDefinition {
  const { apiClient: _apiClient, logger: _logger } = context;
  
  return {
    name: 'validate-blueprint',
    description: 'Validate Make.com blueprint JSON against schema with security and compliance checks',
    parameters: ValidateBlueprintSchema,
    annotations: {
      title: 'Validate Blueprint',
      readOnlyHint: true,
      openWorldHint: false,
    },
    execute: async (args: unknown, { log }): Promise<string> => {
      const typedArgs = args as any;
      log?.info?.('Validating blueprint', { 
        hasBlueprint: !!typedArgs.blueprint,
        strict: typedArgs.strict,
        includeSecurityChecks: typedArgs.includeSecurityChecks
      });

      try {
        const validationResult = validateBlueprintStructure(
          typedArgs.blueprint, 
          typedArgs.strict
        );

        log?.info?.('Blueprint validation completed', {
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
            securityChecksPassed: typedArgs.includeSecurityChecks ? validationResult.securityIssues.length === 0 : true
          },
          validation: {
            errors: validationResult.errors,
            warnings: validationResult.warnings,
            securityIssues: typedArgs.includeSecurityChecks ? validationResult.securityIssues : []
          },
          recommendations: [
            ...validationResult.errors.map((error: string) => `Fix error: ${error}`),
            ...validationResult.warnings.map((warning: string) => `Consider: ${warning}`),
            ...(typedArgs.includeSecurityChecks ? validationResult.securityIssues
              .filter((issue: any) => issue.severity === 'critical' || issue.severity === 'high')
              .map((issue: any) => `Security: ${issue.description}`) : [])
          ].slice(0, 10)
        }, null, 2);

      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log?.error?.('Blueprint validation failed', { error: errorMessage });
        throw new UserError(`Blueprint validation failed: ${errorMessage}`);
      }
    }
  };
}