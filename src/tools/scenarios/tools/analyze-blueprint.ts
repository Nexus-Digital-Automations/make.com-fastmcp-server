/**
 * @fileoverview Analyze Blueprint Tool Implementation
 * Single-responsibility tool for blueprint analysis and validation
 */

import { UserError } from 'fastmcp';
import { ValidateBlueprintSchema } from '../schemas/blueprint-update.js';
import { ToolContext, ToolDefinition } from '../../shared/types/tool-context.js';
import { validateBlueprintStructure } from '../utils/blueprint-analysis.js';
import { Blueprint } from '../types/blueprint.js';

/**
 * Create analyze blueprint tool configuration
 */
export function createAnalyzeBlueprintTool(context: ToolContext): ToolDefinition {
  const { logger } = context;
  
  return {
    name: 'analyze-blueprint',
    description: 'Analyze and validate Make.com blueprint structure with security and performance checks',
    parameters: ValidateBlueprintSchema,
    annotations: {
      title: 'Analyze Blueprint',
      readOnlyHint: true,
      openWorldHint: false,
    },
    execute: async (args: unknown, { log, reportProgress }): Promise<string> => {
      log?.info?.('Analyzing blueprint', { hasBlueprint: !!(args as any).blueprint });
      reportProgress?.({ progress: 0, total: 100 });

      try {
        const { blueprint, strict = false, includeSecurityChecks = true } = args as {
          blueprint?: Blueprint;
          strict?: boolean;
          includeSecurityChecks?: boolean;
        };
        
        if (!blueprint) {
          throw new UserError('Blueprint is required for analysis');
        }

        reportProgress?.({ progress: 25, total: 100 });

        // Perform blueprint validation
        const validationResult = validateBlueprintStructure(blueprint, strict);
        
        reportProgress?.({ progress: 75, total: 100 });

        // Prepare comprehensive analysis result
        const analysisResult = {
          validationSummary: {
            isValid: validationResult.isValid,
            score: calculateValidationScore(validationResult),
            status: validationResult.isValid ? 'valid' : 'invalid'
          },
          issues: {
            errors: validationResult.errors,
            warnings: validationResult.warnings,
            securityIssues: includeSecurityChecks ? validationResult.securityIssues : []
          },
          blueprintMetrics: {
            moduleCount: blueprint.flow?.length ?? 0,
            hasMetadata: !!blueprint.metadata,
            hasName: !!blueprint.name,
            securityLevel: getSecurityLevel(validationResult.securityIssues)
          },
          recommendations: generateBlueprintRecommendations(validationResult, blueprint),
          analysisTimestamp: new Date().toISOString(),
          strict: strict,
          securityChecksEnabled: includeSecurityChecks
        };

        reportProgress?.({ progress: 100, total: 100 });

        log?.info?.('Blueprint analysis completed', {
          isValid: analysisResult.validationSummary.isValid,
          score: analysisResult.validationSummary.score,
          errorCount: analysisResult.issues.errors.length,
          warningCount: analysisResult.issues.warnings.length,
          securityIssueCount: analysisResult.issues.securityIssues.length
        });

        return JSON.stringify(analysisResult, null, 2);
        
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.error?.('Blueprint analysis failed', { error: errorMessage });
        throw new UserError(`Blueprint analysis failed: ${errorMessage}`);
      }
    },
  };
}

/**
 * Calculate overall validation score (0-100)
 */
function calculateValidationScore(validationResult: {
  errors: string[];
  warnings: string[];
  securityIssues: Array<{ severity: string }>;
}): number {
  let score = 100;
  
  // Deduct points for errors
  score -= validationResult.errors.length * 20;
  
  // Deduct points for warnings
  score -= validationResult.warnings.length * 5;
  
  // Deduct points for security issues
  validationResult.securityIssues.forEach((issue: any) => {
    switch (issue.severity) {
      case 'critical':
        score -= 25;
        break;
      case 'high':
        score -= 15;
        break;
      case 'medium':
        score -= 10;
        break;
      case 'low':
        score -= 5;
        break;
    }
  });
  
  return Math.max(0, score);
}

/**
 * Determine security level based on issues
 */
function getSecurityLevel(securityIssues: Array<{ severity: string }>): string {
  if (securityIssues.some(issue => issue.severity === 'critical')) {
    return 'critical';
  }
  if (securityIssues.some(issue => issue.severity === 'high')) {
    return 'high';
  }
  if (securityIssues.some(issue => issue.severity === 'medium')) {
    return 'medium';
  }
  if (securityIssues.length > 0) {
    return 'low';
  }
  return 'secure';
}

/**
 * Generate blueprint-specific recommendations
 */
function generateBlueprintRecommendations(validationResult: {
  errors: string[];
  warnings: string[];
  securityIssues: Array<{ severity: string }>;
}, blueprint: Blueprint): string[] {
  const recommendations: string[] = [];
  
  // Error-based recommendations
  if (validationResult.errors.length > 0) {
    recommendations.push('Fix all validation errors before deploying blueprint');
  }
  
  // Warning-based recommendations
  if (validationResult.warnings.length > 5) {
    recommendations.push('Address warnings to improve blueprint reliability');
  }
  
  // Security recommendations
  if (validationResult.securityIssues.length > 0) {
    recommendations.push('Review and resolve security issues');
    if (validationResult.securityIssues.some((issue) => issue.severity === 'critical')) {
      recommendations.push('URGENT: Address critical security vulnerabilities immediately');
    }
  }
  
  // Structure recommendations
  if (!blueprint.metadata?.scenario?.dlq) {
    recommendations.push('Consider enabling Dead Letter Queue for better error handling');
  }
  
  if (blueprint.flow && blueprint.flow.length > 50) {
    recommendations.push('Large blueprint detected - consider breaking into smaller workflows');
  }
  
  // Performance recommendations
  if (!blueprint.metadata?.scenario?.sequential) {
    recommendations.push('Review parallel execution settings for optimal performance');
  }
  
  return recommendations;
}