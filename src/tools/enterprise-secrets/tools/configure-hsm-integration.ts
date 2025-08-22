/**
 * @fileoverview Configure HSM Integration Tool Implementation
 * Configure Hardware Security Module integration for enterprise-grade key protection
 */

import { UserError } from 'fastmcp';
import { HSMConfigSchema } from '../schemas/index.js';
import { ToolContext, ToolDefinition, ToolExecutionContext } from '../../shared/types/tool-context.js';
import { HSMIntegrationManager } from '../utils/index.js';
import { formatSuccessResponse } from '../../../utils/response-formatter.js';

/**
 * Configure HSM integration tool configuration
 */
export function createConfigureHSMIntegrationTool(context: ToolContext): ToolDefinition {
  const { logger } = context;
  
  return {
    name: 'configure-hsm-integration',
    description: 'Configure Hardware Security Module integration for enterprise-grade key protection',
    parameters: HSMConfigSchema,
    annotations: {
      title: 'Configure Hardware Security Module Integration',
      readOnlyHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (args: unknown, execContext: ToolExecutionContext): Promise<string> => {
      const { log, reportProgress } = execContext;
      
      log?.info?.('Configuring HSM integration', JSON.stringify(args));
      reportProgress?.({ progress: 0, total: 100 });

      try {
        const validatedInput = HSMConfigSchema.parse(args);
        const hsmManager = HSMIntegrationManager.getInstance();
        
        reportProgress?.({ progress: 25, total: 100 });
        
        const hsmStatus = await hsmManager.configureHSM(validatedInput);
        
        reportProgress?.({ progress: 75, total: 100 });

        const result = {
          success: true,
          hsmStatus,
          message: `HSM integration with ${validatedInput.provider} configured successfully`,
        };

        logger.info?.('HSM integration configured successfully', {
          provider: validatedInput.provider,
          fipsLevel: validatedInput.compliance?.fipsLevel,
        });

        reportProgress?.({ progress: 100, total: 100 });
        return formatSuccessResponse(result).content[0].text;
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.error?.('HSM integration failed', { error: errorMessage });
        throw new UserError(`Failed to configure HSM integration: ${errorMessage}`);
      }
    },
  };
}