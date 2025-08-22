/**
 * @fileoverview Validate Blueprint Tool Implementation
 * Blueprint validation with security and compliance checks
 */

import { UserError } from 'fastmcp';
import { ValidateBlueprintSchema } from '../schemas/blueprint-update.js';
import { ToolContext, ToolDefinition } from '../../shared/types/tool-context.js';
import { validateBlueprintStructure } from '../utils/blueprint-analysis.js';
import { formatSuccessResponse } from '../../../utils/response-formatter.js';

interface ValidateBlueprintArgs {
  blueprint?: unknown;
  strict?: boolean;
  includeSecurityChecks?: boolean;
}

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
    execute: async (args: unknown, context): Promise<string> => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} }, reportProgress: _reportProgress = (): void => {} } = context || {};
      const typedArgs = args as ValidateBlueprintArgs;
      if (log?.info) { log.info('Validating blueprint', { 
        hasBlueprint: !!typedArgs.blueprint,
        strict: typedArgs.strict,
        includeSecurityChecks: typedArgs.includeSecurityChecks
      }); }

      try {
        const validationResult = validateBlueprintStructure(
          typedArgs.blueprint, 
          typedArgs.strict
        );

        if (log?.info) { log.info('Blueprint validation completed', {
          isValid: validationResult.isValid,
          errorCount: validationResult.errors.length,
          warningCount: validationResult.warnings.length,
          securityIssueCount: validationResult.securityIssues.length
        }); }

        return formatSuccessResponse({
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
              .filter((issue: { severity: string }) => issue.severity === 'critical' || issue.severity === 'high')
              .map((issue: { description: string }) => `Security: ${issue.description}`) : [])
          ].slice(0, 10)
        }).content[0].text;

      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (log?.error) { log.error('Blueprint validation failed', { error: errorMessage }); }
        throw new UserError(`Blueprint validation failed: ${errorMessage}`);
      }
    }
  };
}