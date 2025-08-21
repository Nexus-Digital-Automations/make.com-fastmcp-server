/**
 * @fileoverview Manage RBAC Policies Tool Implementation
 * Create and manage fine-grained role-based access control policies for secret access
 */

import { UserError } from 'fastmcp';
import { RBACPolicySchema } from '../schemas/index.js';
import { ToolContext, ToolDefinition, ToolExecutionContext } from '../../shared/types/tool-context.js';
import { auditLogger } from '../../../lib/audit-logger.js';

/**
 * RBAC Policy Manager class
 */
class RBACPolicyManager {
  private static instance: RBACPolicyManager | null = null;
  private policies: Map<string, unknown> = new Map();

  public static getInstance(): RBACPolicyManager {
    if (!RBACPolicyManager.instance) {
      RBACPolicyManager.instance = new RBACPolicyManager();
    }
    return RBACPolicyManager.instance;
  }

  /**
   * Create and manage RBAC policy
   */
  public async manageRBACPolicy(policy: Parameters<typeof RBACPolicySchema.parse>[0]): Promise<{
    policyName: string;
    policyContent: string;
    success: boolean;
  }> {
    const validatedInput = RBACPolicySchema.parse(policy);

    // Create HCL policy content
    const policyContent = validatedInput.rules.map(rule => `
path "${rule.path}" {
  capabilities = [${rule.capabilities.map(c => `"${c}"`).join(', ')}]
  ${rule.requiredParameters ? `required_parameters = [${rule.requiredParameters.map(p => `"${p}"`).join(', ')}]` : ''}
  ${rule.allowedParameters ? `allowed_parameters = ${JSON.stringify(rule.allowedParameters)}` : ''}
  ${rule.deniedParameters ? `denied_parameters = [${rule.deniedParameters.map(p => `"${p}"`).join(', ')}]` : ''}
  ${rule.minWrappingTtl ? `min_wrapping_ttl = "${rule.minWrappingTtl}"` : ''}
  ${rule.maxWrappingTtl ? `max_wrapping_ttl = "${rule.maxWrappingTtl}"` : ''}
}
      `).join('\n');

    // Store policy
    this.policies.set(validatedInput.policyName, {
      name: validatedInput.policyName,
      content: policyContent,
      metadata: validatedInput.metadata,
      createdAt: new Date(),
    });

    // Log policy creation
    await auditLogger.logEvent({
      level: 'info',
      category: 'security',
      action: 'rbac_policy_created',
      success: true,
      details: {
        policyName: validatedInput.policyName,
        ruleCount: validatedInput.rules.length,
        metadata: validatedInput.metadata,
      },
      riskLevel: 'low',
    });

    return {
      success: true,
      policyName: validatedInput.policyName,
      policyContent,
    };
  }

  /**
   * Get policy by name
   */
  public getPolicy(policyName: string): unknown {
    return this.policies.get(policyName);
  }

  /**
   * List all policies
   */
  public listPolicies(): Array<{ name: string; metadata?: unknown }> {
    return Array.from(this.policies.entries()).map(([name, policy]) => ({
      name,
      metadata: (policy as { metadata?: unknown }).metadata,
    }));
  }

  /**
   * Delete policy
   */
  public async deletePolicy(policyName: string): Promise<void> {
    if (!this.policies.has(policyName)) {
      throw new Error(`Policy not found: ${policyName}`);
    }

    this.policies.delete(policyName);

    // Log policy deletion
    await auditLogger.logEvent({
      level: 'info',
      category: 'security',
      action: 'rbac_policy_deleted',
      success: true,
      details: { policyName },
      riskLevel: 'low',
    });
  }
}

/**
 * Manage RBAC policies tool configuration
 */
export function createManageRBACPoliciesTool(context: ToolContext): ToolDefinition {
  const { logger } = context;
  
  return {
    name: 'manage-rbac-policies',
    description: 'Create and manage fine-grained role-based access control policies for secret access',
    parameters: RBACPolicySchema,
    annotations: {
      title: 'Create and Manage RBAC Access Control Policies',
      readOnlyHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    execute: async (args: unknown, execContext: ToolExecutionContext): Promise<string> => {
      const { log, reportProgress } = execContext;
      
      log?.info?.('Managing RBAC policies', JSON.stringify(args));
      reportProgress?.({ progress: 0, total: 100 });

      try {
        const validatedInput = RBACPolicySchema.parse(args);
        const policyManager = RBACPolicyManager.getInstance();
        
        reportProgress?.({ progress: 25, total: 100 });
        
        const result = await policyManager.manageRBACPolicy(validatedInput);
        
        reportProgress?.({ progress: 75, total: 100 });

        const response = {
          ...result,
          message: `RBAC policy ${validatedInput.policyName} created successfully`,
        };

        logger.info?.('RBAC policy created successfully', {
          policyName: validatedInput.policyName,
          ruleCount: validatedInput.rules.length,
        });

        reportProgress?.({ progress: 100, total: 100 });
        return JSON.stringify(response, null, 2);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.error?.('RBAC policy management failed', { error: errorMessage });
        throw new UserError(`Failed to manage RBAC policy: ${errorMessage}`);
      }
    },
  };
}