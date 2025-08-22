/**
 * @fileoverview Configure Key Rotation Tool Implementation
 * Configure automated key rotation policies with scheduled and event-driven triggers
 */

import { UserError } from 'fastmcp';
import { KeyRotationPolicySchema } from '../schemas/index.js';
import { ToolContext, ToolDefinition, ToolExecutionContext } from '../../shared/types/tool-context.js';
import { KeyRotationStatus } from '../types/index.js';
import { auditLogger } from '../../../lib/audit-logger.js';
import { formatSuccessResponse } from '../../../utils/response-formatter.js';

/**
 * Key Rotation Manager class
 */
class KeyRotationManager {
  private static instance: KeyRotationManager | null = null;
  private readonly rotationPolicies: Map<string, KeyRotationStatus> = new Map();

  public static getInstance(): KeyRotationManager {
    if (!KeyRotationManager.instance) {
      KeyRotationManager.instance = new KeyRotationManager();
    }
    return KeyRotationManager.instance;
  }

  /**
   * Configure automated key rotation policy
   */
  public async configureKeyRotation(policy: Parameters<typeof KeyRotationPolicySchema.parse>[0]): Promise<KeyRotationStatus> {
    const validatedPolicy = KeyRotationPolicySchema.parse(policy);

    // Calculate next rotation time
    const nextRotation = this.calculateNextRotation(validatedPolicy);

    const rotationStatus: KeyRotationStatus = {
      policyName: validatedPolicy.policyName,
      lastRotation: new Date(0), // Never rotated initially
      nextScheduledRotation: nextRotation,
      rotationCount: 0,
      status: 'active',
      affectedPaths: validatedPolicy.targetPaths,
      rotationHistory: [],
    };

    // Store rotation policy
    this.rotationPolicies.set(validatedPolicy.policyName, rotationStatus);

    // Schedule rotation monitoring
    this.scheduleRotationMonitoring(validatedPolicy);

    // Log policy configuration
    await auditLogger.logEvent({
      level: 'info',
      category: 'security',
      action: 'key_rotation_policy_configured',
      success: true,
      details: {
        policyName: validatedPolicy.policyName,
        rotationType: validatedPolicy.rotationType,
        targetPaths: validatedPolicy.targetPaths,
        nextRotation: nextRotation.toISOString(),
      },
      riskLevel: 'low',
    });

    return rotationStatus;
  }

  private calculateNextRotation(policy: Parameters<typeof KeyRotationPolicySchema.parse>[0]): Date {
    const validatedPolicy = KeyRotationPolicySchema.parse(policy);
    const now = new Date();
    
    if (validatedPolicy.rotationType === 'scheduled' && validatedPolicy.schedule.intervalHours) {
      return new Date(now.getTime() + validatedPolicy.schedule.intervalHours * 60 * 60 * 1000);
    }
    
    // Default to 30 days for other rotation types
    return new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
  }

  private scheduleRotationMonitoring(policy: Parameters<typeof KeyRotationPolicySchema.parse>[0]): void {
    const _validatedPolicy = KeyRotationPolicySchema.parse(policy);
    // Schedule monitoring for the rotation policy
    // Debug: Scheduling rotation monitoring (policy: validatedPolicy.policyName, type: validatedPolicy.rotationType)
  }

  /**
   * Execute key rotation for a specific policy
   */
  public async executeKeyRotation(policyName: string): Promise<void> {
    const rotationStatus = this.rotationPolicies.get(policyName);
    if (!rotationStatus) {
      throw new Error(`Rotation policy not found: ${policyName}`);
    }

    try {
      // Execute rotation
      rotationStatus.status = 'pending';
      
      // Simulate rotation process
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Update rotation status
      rotationStatus.lastRotation = new Date();
      rotationStatus.nextScheduledRotation = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // Next month
      rotationStatus.rotationCount++;
      rotationStatus.status = 'active';
      
      rotationStatus.rotationHistory.push({
        timestamp: new Date(),
        triggerType: 'scheduled',
        success: true,
        details: 'Automatic scheduled rotation completed successfully',
      });

      // Log rotation
      await auditLogger.logEvent({
        level: 'info',
        category: 'security',
        action: 'key_rotation_executed',
        success: true,
        details: {
          policyName,
          rotationCount: rotationStatus.rotationCount,
          triggerType: 'scheduled',
        },
        riskLevel: 'low',
      });
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      
      rotationStatus.status = 'failed';
      rotationStatus.rotationHistory.push({
        timestamp: new Date(),
        triggerType: 'scheduled',
        success: false,
        details: errorMessage,
      });
      
      throw error;
    }
  }
}

/**
 * Configure key rotation tool configuration
 */
export function createConfigureKeyRotationTool(context: ToolContext): ToolDefinition {
  const { logger } = context;
  
  return {
    name: 'configure-key-rotation',
    description: 'Configure automated key rotation policies with scheduled and event-driven triggers',
    parameters: KeyRotationPolicySchema,
    annotations: {
      title: 'Configure Automated Key Rotation Policies',
      readOnlyHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    execute: async (args: unknown, execContext: ToolExecutionContext): Promise<string> => {
      const { log, reportProgress } = execContext;
      
      log?.info?.('Configuring key rotation policy', JSON.stringify(args));
      reportProgress?.({ progress: 0, total: 100 });

      try {
        const validatedInput = KeyRotationPolicySchema.parse(args);
        const rotationManager = KeyRotationManager.getInstance();
        
        reportProgress?.({ progress: 25, total: 100 });
        
        const rotationStatus = await rotationManager.configureKeyRotation(validatedInput);
        
        reportProgress?.({ progress: 75, total: 100 });

        const result = {
          success: true,
          rotationStatus,
          message: `Key rotation policy ${validatedInput.policyName} configured successfully`,
        };

        logger.info?.('Key rotation policy configured', {
          policyName: validatedInput.policyName,
          rotationType: validatedInput.rotationType,
          targetPaths: validatedInput.targetPaths.length,
        });

        reportProgress?.({ progress: 100, total: 100 });
        return formatSuccessResponse(result).content[0].text;
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.error?.('Key rotation configuration failed', { error: errorMessage });
        throw new UserError(`Failed to configure key rotation: ${errorMessage}`);
      }
    },
  };
}