/**
 * @fileoverview Configure Vault Server Tool Implementation
 * Configure and provision HashiCorp Vault server cluster with high availability and enterprise features
 */

import { UserError } from 'fastmcp';
import { VaultServerConfigSchema } from '../schemas/index.js';
import { ToolContext, ToolDefinition, ToolExecutionContext } from '../../shared/types/tool-context.js';
import { VaultServerManager } from '../utils/index.js';
import { formatSuccessResponse } from '../../../utils/response-formatter.js';

/**
 * Configure Vault server tool configuration
 */
export function createConfigureVaultServerTool(context: ToolContext): ToolDefinition {
  const { logger } = context;
  
  return {
    name: 'configure-vault-server',
    description: 'Configure and provision HashiCorp Vault server cluster with high availability and enterprise features',
    parameters: VaultServerConfigSchema,
    annotations: {
      title: 'Configure Vault Server Cluster with Enterprise Features',
      readOnlyHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (args: unknown, execContext: ToolExecutionContext): Promise<string> => {
      const { log, reportProgress } = execContext;
      
      log?.info?.('Configuring Vault server cluster', JSON.stringify(args));
      reportProgress?.({ progress: 0, total: 100 });

      try {
        const validatedInput = VaultServerConfigSchema.parse(args);
        const vaultManager = VaultServerManager.getInstance();
        
        reportProgress?.({ progress: 25, total: 100 });
        
        const clusterInfo = await vaultManager.configureVaultCluster(validatedInput);
        
        reportProgress?.({ progress: 75, total: 100 });

        const result = {
          success: true,
          clusterInfo,
          message: `Vault cluster ${validatedInput.clusterId} configured successfully`,
        };

        logger.info?.('Vault cluster configured successfully', {
          clusterId: validatedInput.clusterId,
          nodeId: validatedInput.nodeId,
          storageType: validatedInput.config.storage.type,
        });

        reportProgress?.({ progress: 100, total: 100 });
        return formatSuccessResponse(result).content[0].text;
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.error?.('Vault server configuration failed', { error: errorMessage });
        throw new UserError(`Failed to configure Vault server: ${errorMessage}`);
      }
    },
  };
}