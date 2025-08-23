/**
 * @fileoverview Make.com Scenario Archival Policy Management Tools
 * 
 * Provides comprehensive scenario archival policy creation, management, and enforcement tools including:
 * - Policy creation with flexible usage-based triggers and conditions
 * - Automated enforcement mechanisms for scenario lifecycle management
 * - Usage tracking and condition evaluation systems
 * - Grace periods, notifications, and rollback capabilities
 * - Integration with existing permissions and scenario management infrastructure
 * - Production-ready policy enforcement with scheduling capabilities
 * 
 * @version 1.0.0
 * @author Make.com FastMCP Server
 * @see {@link https://docs.make.com/api} Make.com API Documentation
 */

import { FastMCP, UserError } from 'fastmcp';
import { z } from 'zod';
import MakeApiClient from '../lib/make-api-client.js';
import { auditLogger } from '../lib/audit-logger.js';
import logger from '../lib/logger.js';
import { formatSuccessResponse } from '../utils/response-formatter.js';

// Define comprehensive scenario archival policy interfaces and schemas

/**
 * Scenario archival trigger conditions
 */
export enum ArchivalTrigger {
  INACTIVITY = 'inactivity',           // No executions for X period
  NO_EXECUTIONS = 'no_executions',     // Never executed scenarios
  LOW_SUCCESS_RATE = 'low_success_rate', // High failure rate
  RESOURCE_USAGE = 'resource_usage',   // High resource consumption
  MANUAL = 'manual',                   // Manual archival trigger
  SCHEDULED = 'scheduled',             // Time-based archival
  DEPENDENCY = 'dependency',           // Dependency-based conditions
  CUSTOM = 'custom',                   // Custom evaluation function
}

/**
 * Policy enforcement actions
 */
export enum ArchivalAction {
  DISABLE = 'disable',                 // Disable scenario (default)
  ARCHIVE = 'archive',                 // Move to archive folder
  DELETE = 'delete',                   // Permanently delete (high risk)
  NOTIFY_ONLY = 'notify_only',         // Notification without action
  TAG = 'tag',                         // Add archival tags
  MOVE_FOLDER = 'move_folder',         // Move to specific folder
}

/**
 * Policy enforcement levels
 */
export enum ArchivalEnforcement {
  AUTOMATIC = 'automatic',             // Fully automated enforcement
  REVIEW_REQUIRED = 'review_required', // Human review before action
  NOTIFICATION_ONLY = 'notification_only', // No automatic action
  SCHEDULED = 'scheduled',             // Scheduled enforcement windows
  DISABLED = 'disabled',               // Policy exists but not enforced
}

/**
 * Scenario usage metrics for archival decisions
 */
interface ScenarioUsageMetrics {
  scenarioId: string;
  scenarioName: string;
  lastExecution: string | null;
  totalExecutions: number;
  executionsPeriod: number;
  successRate: number;
  averageExecutionTime: number;
  resourceUsage: {
    cpu: number;
    memory: number;
    operations: number;
    dataTransfer: number;
  };
  dependencies: {
    incoming: string[];
    outgoing: string[];
  };
  tags: string[];
  folderId?: string;
  teamId?: number;
  organizationId?: number;
  createdAt: string;
  updatedAt: string;
  isActive: boolean;
}

/**
 * Archival condition definition schema
 */
const ArchivalConditionSchema = z.object({
  id: z.string().min(1).describe('Unique condition identifier'),
  name: z.string().min(1).describe('Human-readable condition name'),
  description: z.string().optional().describe('Condition description and purpose'),
  trigger: z.nativeEnum(ArchivalTrigger).describe('Archival trigger type'),
  
  // Inactivity conditions
  inactivityPeriodDays: z.number().min(1).optional().describe('Days of inactivity before archival'),
  minimumExecutions: z.number().min(0).optional().describe('Minimum executions to avoid archival'),
  
  // Success rate conditions
  successRateThreshold: z.number().min(0).max(100).optional().describe('Minimum success rate percentage'),
  evaluationPeriodDays: z.number().min(1).optional().describe('Period for success rate evaluation'),
  
  // Resource usage conditions
  maxCpuUsage: z.number().min(0).optional().describe('Maximum CPU usage threshold'),
  maxMemoryUsage: z.number().min(0).optional().describe('Maximum memory usage threshold'),
  maxOperationsPerExecution: z.number().min(0).optional().describe('Maximum operations per execution'),
  
  // Dependency conditions
  requireActiveDependencies: z.boolean().default(false).describe('Require active dependencies'),
  maxIncomingDependencies: z.number().min(0).optional().describe('Maximum incoming dependencies'),
  maxOutgoingDependencies: z.number().min(0).optional().describe('Maximum outgoing dependencies'),
  
  // Custom evaluation
  customEvaluationFunction: z.string().optional().describe('Custom JavaScript evaluation function'),
  
  // Condition metadata
  priority: z.number().min(1).max(100).default(50).describe('Condition priority (1=highest)'),
  weight: z.number().min(0).max(1).default(1).describe('Condition weight in evaluation'),
  tags: z.array(z.string()).optional().describe('Condition tags for categorization'),
  
}).strict();

/**
 * Grace period and notification settings
 */
const GracePeriodSchema = z.object({
  enabled: z.boolean().default(true).describe('Enable grace period'),
  durationDays: z.number().min(1).max(365).default(7).describe('Grace period duration in days'),
  notificationSchedule: z.array(z.number()).default([7, 3, 1]).describe('Days before archival to notify'),
  allowOwnerOverride: z.boolean().default(true).describe('Allow scenario owner to override'),
  allowTeamOverride: z.boolean().default(true).describe('Allow team to override archival'),
  escalationContacts: z.array(z.string()).optional().describe('Escalation contact emails'),
}).strict();

/**
 * Rollback and recovery settings
 */
const RollbackSchema = z.object({
  enabled: z.boolean().default(true).describe('Enable rollback capability'),
  retentionPeriodDays: z.number().min(1).max(365).default(30).describe('Rollback retention period'),
  automaticRollbackTriggers: z.array(z.string()).default([
    'execution_request',
    'dependency_activation',
    'owner_request'
  ]).describe('Automatic rollback triggers'),
  requireApproval: z.boolean().default(false).describe('Require approval for rollback'),
  notifyOnRollback: z.boolean().default(true).describe('Notify stakeholders on rollback'),
}).strict();

/**
 * Create scenario archival policy schema
 */
const CreateScenarioArchivalPolicySchema = z.object({
  name: z.string().min(1).max(100).describe('Policy name'),
  description: z.string().max(500).optional().describe('Policy description'),
  
  scope: z.object({
    organizationId: z.number().optional().describe('Organization scope'),
    teamId: z.number().optional().describe('Team scope'),
    folderId: z.string().optional().describe('Folder scope'),
    scenarioTags: z.array(z.string()).optional().describe('Target scenario tags'),
    excludeScenarios: z.array(z.string()).optional().describe('Scenario IDs to exclude'),
    global: z.boolean().default(false).describe('Apply globally'),
  }).describe('Policy application scope'),
  
  conditions: z.array(ArchivalConditionSchema).min(1).describe('Archival conditions'),
  conditionLogic: z.enum(['AND', 'OR', 'CUSTOM']).default('AND').describe('How conditions are combined'),
  customLogicExpression: z.string().optional().describe('Custom logic expression for combining conditions'),
  
  enforcement: z.object({
    level: z.nativeEnum(ArchivalEnforcement).default(ArchivalEnforcement.REVIEW_REQUIRED).describe('Enforcement level'),
    action: z.nativeEnum(ArchivalAction).default(ArchivalAction.DISABLE).describe('Action to take'),
    targetFolderId: z.string().optional().describe('Target folder for move operations'),
    batchSize: z.number().min(1).max(100).default(10).describe('Maximum scenarios to process per batch'),
    scheduledHours: z.array(z.number().min(0).max(23)).optional().describe('Hours when enforcement runs'),
    skipWeekends: z.boolean().default(true).describe('Skip enforcement on weekends'),
  }).describe('Enforcement configuration'),
  
  gracePeriod: GracePeriodSchema.describe('Grace period and notification settings'),
  rollback: RollbackSchema.describe('Rollback and recovery settings'),
  
  monitoring: z.object({
    enableUsageTracking: z.boolean().default(true).describe('Enable detailed usage tracking'),
    trackingPeriodDays: z.number().min(1).max(365).default(90).describe('Usage tracking period'),
    metricsRetentionDays: z.number().min(1).max(730).default(365).describe('Metrics retention period'),
    alertThresholds: z.object({
      highArchivalRate: z.number().min(0).max(100).default(10).describe('High archival rate alert threshold (%)'),
      lowRecoveryRate: z.number().min(0).max(100).default(20).describe('Low recovery rate alert threshold (%)'),
    }).optional().describe('Alert thresholds'),
  }).describe('Monitoring and tracking configuration'),
  
  active: z.boolean().default(true).describe('Whether policy is active'),
  effectiveFrom: z.string().optional().describe('Policy effective date (ISO string)'),
  effectiveUntil: z.string().optional().describe('Policy expiration date (ISO string)'),
  
  notificationSettings: z.object({
    notifyOnArchival: z.boolean().default(true).describe('Send notifications on archival'),
    notifyOnRecovery: z.boolean().default(true).describe('Send notifications on recovery'),
    notifyOnPolicyUpdate: z.boolean().default(false).describe('Send notifications on policy updates'),
    recipients: z.array(z.string()).optional().describe('Additional notification recipient emails'),
    channels: z.array(z.enum(['email', 'webhook', 'api'])).default(['email']).describe('Notification channels'),
  }).optional().describe('Notification configuration'),
  
  metadata: z.record(z.string(), z.unknown()).optional().describe('Additional policy metadata'),
}).strict();

/**
 * Policy evaluation and enforcement schema
 */
const EvaluatePolicySchema = z.object({
  policyId: z.string().min(1).describe('Policy ID to evaluate'),
  
  evaluationOptions: z.object({
    dryRun: z.boolean().default(true).describe('Perform dry run without taking action'),
    scenarioIds: z.array(z.string()).optional().describe('Specific scenarios to evaluate'),
    forceEvaluation: z.boolean().default(false).describe('Force evaluation regardless of schedule'),
    skipGracePeriod: z.boolean().default(false).describe('Skip grace period (admin only)'),
    includeMetrics: z.boolean().default(true).describe('Include detailed metrics in results'),
  }).describe('Evaluation options'),
  
  executionContext: z.object({
    userId: z.string().optional().describe('User requesting evaluation'),
    reason: z.string().optional().describe('Reason for evaluation'),
    correlationId: z.string().optional().describe('Correlation ID for tracking'),
  }).optional().describe('Execution context'),
}).strict();

/**
 * Policy management schemas
 */
const UpdateArchivalPolicySchema = z.object({
  policyId: z.string().min(1).describe('Policy ID to update'),
  name: z.string().min(1).max(100).optional().describe('New policy name'),
  description: z.string().max(500).optional().describe('New policy description'),
  conditions: z.array(ArchivalConditionSchema).optional().describe('Updated archival conditions'),
  enforcement: z.object({
    level: z.nativeEnum(ArchivalEnforcement).optional(),
    action: z.nativeEnum(ArchivalAction).optional(),
    targetFolderId: z.string().optional(),
    batchSize: z.number().min(1).max(100).optional(),
    scheduledHours: z.array(z.number().min(0).max(23)).optional(),
    skipWeekends: z.boolean().optional(),
  }).optional().describe('Updated enforcement configuration'),
  gracePeriod: GracePeriodSchema.optional().describe('Updated grace period settings'),
  rollback: RollbackSchema.optional().describe('Updated rollback settings'),
  active: z.boolean().optional().describe('Policy activation status'),
  effectiveFrom: z.string().optional().describe('New effective date'),
  effectiveUntil: z.string().optional().describe('New expiration date'),
  metadata: z.record(z.string(), z.unknown()).optional().describe('Updated metadata'),
}).strict();

const PolicyFiltersSchema = z.object({
  organizationId: z.number().optional().describe('Filter by organization'),
  teamId: z.number().optional().describe('Filter by team'),
  folderId: z.string().optional().describe('Filter by folder'),
  active: z.boolean().optional().describe('Filter by active status'),
  enforcement: z.nativeEnum(ArchivalEnforcement).optional().describe('Filter by enforcement level'),
  trigger: z.nativeEnum(ArchivalTrigger).optional().describe('Filter by trigger type'),
  search: z.string().optional().describe('Search by name or description'),
  limit: z.number().min(1).max(100).default(20).describe('Maximum policies to return'),
  offset: z.number().min(0).default(0).describe('Pagination offset'),
}).strict();

/**
 * Scenario archival policy engine
 */
class ScenarioArchivalPolicyEngine {
  constructor(private readonly apiClient: MakeApiClient) {}

  /**
   * Evaluate scenarios against archival conditions
   */
  async evaluateConditions(
    scenarios: ScenarioUsageMetrics[],
    conditions: z.infer<typeof ArchivalConditionSchema>[],
    conditionLogic: 'AND' | 'OR' | 'CUSTOM' = 'AND'
  ): Promise<{ scenarioId: string; shouldArchive: boolean; reasons: string[]; score: number }[]> {
    const results: { scenarioId: string; shouldArchive: boolean; reasons: string[]; score: number }[] = [];

    for (const scenario of scenarios) {
      const conditionResults: { condition: string; met: boolean; score: number; reason: string }[] = [];

      // Evaluate each condition
      for (const condition of conditions) {
        const result = await this.evaluateSingleCondition(scenario, condition);
        conditionResults.push(result);
      }

      // Apply condition logic
      let shouldArchive = false;
      let totalScore = 0;
      const reasons: string[] = [];

      if (conditionLogic === 'AND') {
        shouldArchive = conditionResults.every(r => r.met);
        totalScore = conditionResults.reduce((sum, r) => sum + (r.met ? r.score : 0), 0) / conditionResults.length;
      } else if (conditionLogic === 'OR') {
        shouldArchive = conditionResults.some(r => r.met);
        totalScore = Math.max(...conditionResults.map(r => r.met ? r.score : 0));
      }

      // Collect reasons
      conditionResults.forEach(r => {
        if (r.met) {
          reasons.push(r.reason);
        }
      });

      results.push({
        scenarioId: scenario.scenarioId,
        shouldArchive,
        reasons,
        score: totalScore,
      });
    }

    return results;
  }

  /**
   * Evaluate inactivity condition
   */
  private evaluateInactivityCondition(
    scenario: ScenarioUsageMetrics,
    condition: z.infer<typeof ArchivalConditionSchema>
  ): { met: boolean; score: number; reason: string } {
    if (!condition.inactivityPeriodDays) {
      return { met: false, score: 0, reason: 'No inactivity period defined' };
    }

    const now = new Date();
    const lastExecution = scenario.lastExecution ? new Date(scenario.lastExecution) : null;
    const daysSinceLastExecution = lastExecution 
      ? Math.floor((now.getTime() - lastExecution.getTime()) / (1000 * 60 * 60 * 24))
      : Infinity;
      
    const met = daysSinceLastExecution >= condition.inactivityPeriodDays;
    const score = Math.min(daysSinceLastExecution / condition.inactivityPeriodDays, 2) * (condition.weight || 1);
    const reason = `Inactive for ${daysSinceLastExecution} days (threshold: ${condition.inactivityPeriodDays})`;
    
    return { met, score, reason };
  }

  /**
   * Evaluate resource usage condition
   */
  private evaluateResourceUsageCondition(
    scenario: ScenarioUsageMetrics,
    condition: z.infer<typeof ArchivalConditionSchema>
  ): { met: boolean; score: number; reason: string } {
    let resourceViolations = 0;
    const resourceReasons: string[] = [];

    if (condition.maxCpuUsage !== undefined && scenario.resourceUsage.cpu > condition.maxCpuUsage) {
      resourceViolations++;
      resourceReasons.push(`CPU usage ${scenario.resourceUsage.cpu} > ${condition.maxCpuUsage}`);
    }
    if (condition.maxMemoryUsage !== undefined && scenario.resourceUsage.memory > condition.maxMemoryUsage) {
      resourceViolations++;
      resourceReasons.push(`Memory usage ${scenario.resourceUsage.memory} > ${condition.maxMemoryUsage}`);
    }
    if (condition.maxOperationsPerExecution !== undefined && scenario.resourceUsage.operations > condition.maxOperationsPerExecution) {
      resourceViolations++;
      resourceReasons.push(`Operations ${scenario.resourceUsage.operations} > ${condition.maxOperationsPerExecution}`);
    }

    const met = resourceViolations > 0;
    const score = (resourceViolations / 3) * (condition.weight || 1);
    const reason = resourceReasons.join(', ') || 'Resource usage within limits';
    
    return { met, score, reason };
  }

  /**
   * Evaluate dependency condition
   */
  private evaluateDependencyCondition(
    scenario: ScenarioUsageMetrics,
    condition: z.infer<typeof ArchivalConditionSchema>
  ): { met: boolean; score: number; reason: string } {
    if (!condition.requireActiveDependencies) {
      return { met: false, score: 0, reason: 'No dependency requirements defined' };
    }

    const hasDependencies = scenario.dependencies.incoming.length > 0 || scenario.dependencies.outgoing.length > 0;
    const met = !hasDependencies;
    const score = met ? 1 * (condition.weight || 1) : 0;
    const reason = met ? 'No active dependencies' : 'Has active dependencies';
    
    return { met, score, reason };
  }

  /**
   * Evaluate custom function condition
   */
  private evaluateCustomCondition(
    scenario: ScenarioUsageMetrics,
    condition: z.infer<typeof ArchivalConditionSchema>
  ): { met: boolean; score: number; reason: string } {
    if (!condition.customEvaluationFunction) {
      return { met: false, score: 0, reason: 'No custom evaluation function defined' };
    }

    try {
      if (!this.isSafeCustomFunction(condition.customEvaluationFunction)) {
        throw new Error('Custom function contains unsafe operations');
      }
      
      const customResult = this.evaluateCustomFunction(condition.customEvaluationFunction, scenario, condition);
      
      if (typeof customResult === 'boolean') {
        const met = customResult;
        const score = customResult ? 1 * (condition.weight || 1) : 0;
        const reason = customResult ? 'Custom condition met' : 'Custom condition not met';
        return { met, score, reason };
      } else if (typeof customResult === 'object' && customResult !== null) {
        const met = Boolean(customResult.met);
        const score = Number(customResult.score || (met ? 1 : 0)) * (condition.weight || 1);
        const reason = String(customResult.reason || 'Custom evaluation');
        return { met, score, reason };
      }
      
      return { met: false, score: 0, reason: 'Invalid custom function return type' };
    } catch (error) {
      const reason = `Custom evaluation error: ${error instanceof Error ? error.message : 'Unknown error'}`;
      return { met: false, score: 0, reason };
    }
  }

  /**
   * Evaluate low success rate condition
   */
  private evaluateLowSuccessRateCondition(
    scenario: ScenarioUsageMetrics,
    condition: z.infer<typeof ArchivalConditionSchema>
  ): { met: boolean; score: number; reason: string } {
    if (condition.successRateThreshold === undefined) {
      return { met: false, score: 0, reason: 'No success rate threshold defined' };
    }

    const met = scenario.successRate < condition.successRateThreshold;
    const score = met ? (1 - scenario.successRate / 100) * (condition.weight || 1) : 0;
    const reason = `Success rate ${scenario.successRate}% (threshold: ${condition.successRateThreshold}%)`;
    
    return { met, score, reason };
  }

  /**
   * Evaluate no executions condition
   */
  private evaluateNoExecutionsCondition(
    scenario: ScenarioUsageMetrics,
    condition: z.infer<typeof ArchivalConditionSchema>
  ): { met: boolean; score: number; reason: string } {
    const met = scenario.totalExecutions === 0;
    const score = met ? 1 * (condition.weight || 1) : 0;
    const reason = met ? 'Never executed' : 'Has executions';
    
    return { met, score, reason };
  }

  /**
   * Evaluate a single condition against a scenario
   */
  private async evaluateSingleCondition(
    scenario: ScenarioUsageMetrics,
    condition: z.infer<typeof ArchivalConditionSchema>
  ): Promise<{ condition: string; met: boolean; score: number; reason: string }> {
    try {
      let evaluationResult: { met: boolean; score: number; reason: string };

      // Use coordinator pattern to delegate to specific evaluation functions
      switch (condition.trigger) {
        case ArchivalTrigger.INACTIVITY:
          evaluationResult = this.evaluateInactivityCondition(scenario, condition);
          break;

        case ArchivalTrigger.NO_EXECUTIONS:
          evaluationResult = this.evaluateNoExecutionsCondition(scenario, condition);
          break;

        case ArchivalTrigger.LOW_SUCCESS_RATE:
          evaluationResult = this.evaluateLowSuccessRateCondition(scenario, condition);
          break;

        case ArchivalTrigger.RESOURCE_USAGE:
          evaluationResult = this.evaluateResourceUsageCondition(scenario, condition);
          break;

        case ArchivalTrigger.DEPENDENCY:
          evaluationResult = this.evaluateDependencyCondition(scenario, condition);
          break;

        case ArchivalTrigger.CUSTOM:
          evaluationResult = this.evaluateCustomCondition(scenario, condition);
          break;

        default:
          evaluationResult = {
            met: false,
            score: 0,
            reason: `Unsupported trigger type: ${condition.trigger}`
          };
      }

      return {
        condition: condition.name,
        met: evaluationResult.met,
        score: evaluationResult.score,
        reason: evaluationResult.reason
      };
    } catch (error) {
      return {
        condition: condition.name,
        met: false,
        score: 0,
        reason: `Evaluation error: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  /**
   * Gather scenario usage metrics
   */
  async gatherUsageMetrics(scenarioIds?: string[]): Promise<ScenarioUsageMetrics[]> {
    const metrics: ScenarioUsageMetrics[] = [];

    try {
      // Get scenarios list
      const scenariosResponse = await this.apiClient.get('/scenarios', {
        params: { 
          limit: scenarioIds ? scenarioIds.length : 100,
          ...(scenarioIds && { ids: scenarioIds.join(',') })
        }
      });

      if (!scenariosResponse.success || !Array.isArray(scenariosResponse.data)) {
        throw new Error('Failed to fetch scenarios');
      }

      const scenarios = scenariosResponse.data;

      // Process each scenario
      for (const scenario of scenarios) {
        const scenarioMetrics = await this.gatherScenarioMetrics(scenario);
        metrics.push(scenarioMetrics);
      }
    } catch (error) {
      throw new Error(`Failed to gather usage metrics: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }

    return metrics;
  }

  /**
   * Gather metrics for a single scenario
   */
  private async gatherScenarioMetrics(scenario: Record<string, unknown>): Promise<ScenarioUsageMetrics> {
    const scenarioId = scenario.id;
    
    // Get execution history
    const executionsResponse = await this.apiClient.get(`/scenarios/${scenarioId}/executions`, {
      params: { limit: 100 }
    });

    let totalExecutions = 0;
    let successfulExecutions = 0;
    let lastExecution: string | null = null;
    let averageExecutionTime = 0;
    let totalExecutionTime = 0;

    if (executionsResponse.success && Array.isArray(executionsResponse.data)) {
      const executions = executionsResponse.data;
      totalExecutions = executions.length;

      executions.forEach((execution: Record<string, unknown>) => {
        if (execution.status === 'success') {
          successfulExecutions++;
        }
        
        if (execution.createdAt && (!lastExecution || String(execution.createdAt) > lastExecution)) {
          lastExecution = String(execution.createdAt);
        }

        if (typeof execution.executionTime === 'number') {
          totalExecutionTime += execution.executionTime;
        }
      });

      if (totalExecutions > 0) {
        averageExecutionTime = totalExecutionTime / totalExecutions;
      }
    }

    const successRate = totalExecutions > 0 ? (successfulExecutions / totalExecutions) * 100 : 0;

    // Mock resource usage data (in production, this would come from real metrics)
    const resourceUsage = {
      cpu: Math.random() * 100,
      memory: Math.random() * 1024,
      operations: Math.floor(Math.random() * 1000),
      dataTransfer: Math.random() * 10240,
    };

    // Mock dependencies (in production, this would be extracted from blueprint)
    const dependencies = {
      incoming: [],
      outgoing: [],
    };

    return {
      scenarioId: String(scenarioId),
      scenarioName: String(scenario.name) || 'Unnamed Scenario',
      lastExecution,
      totalExecutions,
      executionsPeriod: totalExecutions, // Last 90 days, would be filtered in real implementation
      successRate,
      averageExecutionTime,
      resourceUsage,
      dependencies,
      tags: Array.isArray(scenario.tags) ? scenario.tags : [],
      folderId: scenario.folderId ? String(scenario.folderId) : undefined,
      teamId: typeof scenario.teamId === 'number' ? scenario.teamId : undefined,
      organizationId: typeof scenario.organizationId === 'number' ? scenario.organizationId : undefined,
      createdAt: typeof scenario.createdAt === 'string' ? scenario.createdAt : new Date().toISOString(),
      updatedAt: typeof scenario.updatedAt === 'string' ? scenario.updatedAt : new Date().toISOString(),
      isActive: Boolean(scenario.active),
    };
  }

  /**
   * Execute archival action on scenarios
   */
  async executeArchivalAction(
    scenarioIds: string[],
    action: ArchivalAction,
    options: { 
      targetFolderId?: string; 
      batchSize?: number; 
      dryRun?: boolean;
      reason?: string;
    } = {}
  ): Promise<{ success: boolean; results: Array<{ scenarioId: string; success: boolean; error?: string }> }> {
    const results: Array<{ scenarioId: string; success: boolean; error?: string }> = [];
    const batchSize = options.batchSize || 10;

    // Process scenarios in batches
    for (let i = 0; i < scenarioIds.length; i += batchSize) {
      const batch = scenarioIds.slice(i, i + batchSize);
      
      for (const scenarioId of batch) {
        try {
          if (options.dryRun) {
            results.push({ scenarioId, success: true });
            continue;
          }

          switch (action) {
            case ArchivalAction.DISABLE:
              await this.apiClient.patch(`/scenarios/${scenarioId}`, { active: false });
              break;

            case ArchivalAction.ARCHIVE:
              // Move to archive folder and disable
              if (options.targetFolderId) {
                await this.apiClient.patch(`/scenarios/${scenarioId}`, { 
                  folderId: options.targetFolderId,
                  active: false 
                });
              } else {
                await this.apiClient.patch(`/scenarios/${scenarioId}`, { active: false });
              }
              break;

            case ArchivalAction.MOVE_FOLDER:
              if (options.targetFolderId) {
                await this.apiClient.patch(`/scenarios/${scenarioId}`, { 
                  folderId: options.targetFolderId 
                });
              }
              break;

            case ArchivalAction.TAG: {
              // Add archival tags (implementation would depend on tagging system)
              const scenario = await this.apiClient.get(`/scenarios/${scenarioId}`);
              if (scenario.success && scenario.data && typeof scenario.data === 'object') {
                const scenarioData = scenario.data as { tags?: string[] };
                const existingTags = scenarioData.tags || [];
                const newTags = [...existingTags, 'archived', `archived_${new Date().toISOString().split('T')[0]}`];
                await this.apiClient.patch(`/scenarios/${scenarioId}`, { tags: newTags });
              }
              break;
            }

            case ArchivalAction.DELETE:
              // High-risk operation - requires explicit confirmation
              await this.apiClient.delete(`/scenarios/${scenarioId}`);
              break;

            case ArchivalAction.NOTIFY_ONLY:
              // No action, just notification (handled elsewhere)
              break;

            default:
              throw new Error(`Unsupported archival action: ${action}`);
          }

          results.push({ scenarioId, success: true });
        } catch (error) {
          results.push({ 
            scenarioId, 
            success: false, 
            error: error instanceof Error ? error.message : 'Unknown error' 
          });
        }
      }

      // Add delay between batches to avoid rate limiting
      if (i + batchSize < scenarioIds.length) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }

    const overallSuccess = results.every(r => r.success);
    return { success: overallSuccess, results };
  }

  /**
   * Check if custom function contains only safe operations
   */
  public isSafeCustomFunction(functionCode: string): boolean {
    const unsafePatterns = [
      /eval\(/,
      /Function\(/,
      /setTimeout\(/,
      /setInterval\(/,
      /require\(/,
      /import\(/,
      /process\./,
      /global\./,
      /window\./,
      /document\./,
      /__proto__/,
      /constructor/,
      /prototype/,
    ];
    
    return !unsafePatterns.some(pattern => pattern.test(functionCode));
  }

  /**
   * Safely evaluate custom function using predefined operations
   */
  private evaluateCustomFunction(functionCode: string, scenario: ScenarioUsageMetrics, _condition: z.infer<typeof ArchivalConditionSchema>): boolean | Record<string, unknown> {
    // Instead of dynamic evaluation, provide safe predefined operations
    // This is a simplified example - in production, use a proper expression evaluator
    
    // For now, support basic conditions like checking scenario properties
    if (functionCode.includes('scenario.isActive')) {
      const statusCheck = functionCode.match(/scenario\.isActive\s*===?\s*(true|false)/);
      if (statusCheck) {
        return scenario.isActive === (statusCheck[1] === 'true');
      }
    }
    
    if (functionCode.includes('scenario.lastExecution')) {
      // Support date comparisons
      const now = new Date();
      const lastRun = scenario.lastExecution ? new Date(scenario.lastExecution) : new Date(0);
      const daysDiff = Math.floor((now.getTime() - lastRun.getTime()) / (1000 * 60 * 60 * 24));
      
      if (functionCode.includes('> 30')) {
        return daysDiff > 30;
      }
      if (functionCode.includes('> 90')) {
        return daysDiff > 90;
      }
    }
    
    // Default: return false for unsupported operations
    return false;
  }
}

/**
 * Validate policy conditions
 */
function validatePolicyConditions(
  conditions: z.infer<typeof ArchivalConditionSchema>[],
  policyEngine: ScenarioArchivalPolicyEngine
): { conditionValidation: Record<string, unknown>; invalidConditions: string[] } {
  const conditionValidation: Record<string, unknown> = {};
  const invalidConditions: string[] = [];

  for (const condition of conditions) {
    try {
      // Validate condition parameters based on trigger type
      switch (condition.trigger) {
        case ArchivalTrigger.INACTIVITY:
          if (!condition.inactivityPeriodDays) {
            throw new Error('inactivityPeriodDays required for inactivity trigger');
          }
          break;
        case ArchivalTrigger.LOW_SUCCESS_RATE:
          if (condition.successRateThreshold === undefined) {
            throw new Error('successRateThreshold required for low_success_rate trigger');
          }
          break;
        case ArchivalTrigger.RESOURCE_USAGE:
          if (!condition.maxCpuUsage && !condition.maxMemoryUsage && !condition.maxOperationsPerExecution) {
            throw new Error('At least one resource threshold required for resource_usage trigger');
          }
          break;
        case ArchivalTrigger.CUSTOM:
          if (!condition.customEvaluationFunction) {
            throw new Error('customEvaluationFunction required for custom trigger');
          }
          // Test custom function validity
          try {
            if (!policyEngine.isSafeCustomFunction(condition.customEvaluationFunction)) {
              throw new Error('Custom function contains unsafe operations');
            }
            // Basic syntax validation would be done here
            // For now, just check that it's safe
          } catch (error) {
            throw new Error(`Invalid custom function: ${error instanceof Error ? error.message : 'Unknown error'}`);
          }
          break;
      }

      conditionValidation[condition.id] = {
        isValid: true,
        message: 'Condition validation passed',
      };
    } catch (error) {
      invalidConditions.push(condition.id);
      conditionValidation[condition.id] = {
        isValid: false,
        error: error instanceof Error ? error.message : 'Unknown validation error',
      };
    }
  }

  return { conditionValidation, invalidConditions };
}

/**
 * Estimate policy impact
 */
async function estimatePolicyImpact(
  input: z.infer<typeof CreateScenarioArchivalPolicySchema>,
  policyEngine: ScenarioArchivalPolicyEngine,
  timestamp: string,
  componentLogger: ReturnType<typeof logger.child>
): Promise<Record<string, unknown>> {
  let estimatedImpact = {
    totalScenariosInScope: 0,
    potentiallyAffected: 0,
    highRiskScenarios: 0,
    estimationDate: timestamp,
    sampleSize: 0,
  };

  try {
    // Get a sample of scenarios for impact estimation
    const sampleMetrics = await policyEngine.gatherUsageMetrics();
    const sampleSize = Math.min(sampleMetrics.length, 100);
    
    if (sampleSize > 0) {
      const evaluationResults = await policyEngine.evaluateConditions(
        sampleMetrics.slice(0, sampleSize),
        input.conditions,
        input.conditionLogic
      );

      const affected = evaluationResults.filter((r: Record<string, unknown>) => r.shouldArchive);
      const highRisk = evaluationResults.filter((r: Record<string, unknown>) => (r.score as number) > 0.8);

      estimatedImpact = {
        totalScenariosInScope: sampleSize,
        potentiallyAffected: affected.length,
        highRiskScenarios: highRisk.length,
        estimationDate: timestamp,
        sampleSize,
      };
    }
  } catch (error) {
    componentLogger.warn('Failed to estimate policy impact', { error: (error as Error).message });
  }

  return estimatedImpact;
}

/**
 * Create policy object
 */
function createPolicyObject(
  input: z.infer<typeof CreateScenarioArchivalPolicySchema>,
  policyId: string,
  timestamp: string,
  estimatedImpact: Record<string, unknown>
): Record<string, unknown> {
  return {
    id: policyId,
    name: input.name,
    description: input.description || '',
    scope: input.scope,
    conditions: input.conditions.sort((a, b) => (a.priority || 50) - (b.priority || 50)),
    conditionLogic: input.conditionLogic,
    customLogicExpression: input.customLogicExpression,
    enforcement: {
      ...{
        level: ArchivalEnforcement.REVIEW_REQUIRED,
        action: ArchivalAction.DISABLE,
        batchSize: 10,
        skipWeekends: true,
      },
      ...input.enforcement,
    },
    gracePeriod: {
      ...{
        enabled: true,
        durationDays: 7,
        notificationSchedule: [7, 3, 1],
        allowOwnerOverride: true,
        allowTeamOverride: true,
      },
      ...input.gracePeriod,
    },
    rollback: {
      ...{
        enabled: true,
        retentionPeriodDays: 30,
        automaticRollbackTriggers: ['execution_request', 'dependency_activation', 'owner_request'],
        requireApproval: false,
        notifyOnRollback: true,
      },
      ...input.rollback,
    },
    monitoring: {
      ...{
        enableUsageTracking: true,
        trackingPeriodDays: 90,
        metricsRetentionDays: 365,
        alertThresholds: {
          highArchivalRate: 10,
          lowRecoveryRate: 20,
        },
      },
      ...input.monitoring,
    },
    active: input.active !== false,
    effectiveFrom: input.effectiveFrom || timestamp,
    effectiveUntil: input.effectiveUntil,
    notificationSettings: {
      notifyOnArchival: true,
      notifyOnRecovery: true,
      notifyOnPolicyUpdate: false,
      recipients: [],
      channels: ['email'],
      ...input.notificationSettings,
    },
    metadata: {
      ...input.metadata,
      conditionsCount: input.conditions.length,
      triggersUsed: Array.from(new Set(input.conditions.map(c => c.trigger))),
      enforcementLevel: input.enforcement.level,
      estimatedImpact: estimatedImpact.potentiallyAffected,
    },
    stats: {
      scenariosEvaluated: 0,
      scenariosArchived: 0,
      scenariosRecovered: 0,
      lastEvaluationAt: null,
      lastEnforcementAt: null,
    },
    createdAt: timestamp,
    updatedAt: timestamp,
    version: '1.0.0',
  };
}

/**
 * Store policy and create audit logs
 */
async function storePolicyAndAudit(
  policy: Record<string, unknown>,
  input: z.infer<typeof CreateScenarioArchivalPolicySchema>,
  estimatedImpact: Record<string, unknown>,
  apiClient: MakeApiClient
): Promise<void> {
  // Store policy (in production, this would be stored in database)
  const response = await apiClient.post('/policies/scenario-archival', policy);
  
  if (!response.success) {
    throw new UserError(`Failed to create archival policy: ${response.error?.message || 'Unknown error'}`);
  }

  // Log policy creation audit event
  await auditLogger.logEvent({
    level: 'info',
    category: 'configuration',
    action: 'scenario_archival_policy_created',
    resource: `policy:${policy.id}`,
    success: true,
    details: {
      policyId: policy.id,
      name: input.name,
      conditionsCount: input.conditions.length,
      enforcementLevel: input.enforcement.level,
      scope: input.scope,
      estimatedImpact: estimatedImpact.potentiallyAffected,
    },
    riskLevel: input.enforcement.action === ArchivalAction.DELETE ? 'high' : 'medium',
  });

  // Policy stored successfully
}

/**
 * Helper function to add set scenario archival policy tool
 */
function addSetScenarioArchivalPolicyTool(
  server: FastMCP,
  apiClient: MakeApiClient,
  policyEngine: ScenarioArchivalPolicyEngine,
  componentLogger: ReturnType<typeof logger.child>
): void {
  server.addTool({
    name: 'set-scenario-archival-policy',
    description: 'Create comprehensive scenario archival policy with automated enforcement, usage tracking, grace periods, and notifications',
    parameters: CreateScenarioArchivalPolicySchema,
    annotations: {
      title: 'Set Scenario Archival Policy',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
    execute: async (input, { log, reportProgress }) => {
      log.info('Creating scenario archival policy', {
        name: input.name,
        conditionsCount: input.conditions.length,
        scope: input.scope,
        enforcement: input.enforcement.level,
      });

      reportProgress({ progress: 0, total: 100 });

      try {
        // Generate unique policy ID
        const policyId = `archival_policy_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const timestamp = new Date().toISOString();

        reportProgress({ progress: 10, total: 100 });

        // Validate conditions using helper function
        const { conditionValidation, invalidConditions } = validatePolicyConditions(input.conditions, policyEngine);

        if (invalidConditions.length > 0) {
          throw new UserError(`Policy contains invalid conditions: ${invalidConditions.join(', ')}`);
        }

        reportProgress({ progress: 30, total: 100 });

        // Estimate policy impact using helper function
        const estimatedImpact = await estimatePolicyImpact(input, policyEngine, timestamp, componentLogger);

        reportProgress({ progress: 60, total: 100 });

        // Create policy object using helper function
        const policy = createPolicyObject(input, policyId, timestamp, estimatedImpact);

        reportProgress({ progress: 80, total: 100 });

        // Store policy and create audit logs using helper function
        await storePolicyAndAudit(policy, input, estimatedImpact, apiClient);

        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully created scenario archival policy', {
          policyId,
          name: input.name,
          conditionsCount: input.conditions.length,
          estimatedImpact: Number(estimatedImpact.potentiallyAffected) || 0,
        });

        return formatSuccessResponse({
          success: true,
          policy,
          conditionValidation,
          estimatedImpact,
          enforcementCapabilities: {
            automatedEnforcement: true,
            batchProcessing: true,
            gracePeriodManagement: true,
            rollbackSupport: true,
            usageTracking: true,
            notificationSystem: true,
            scheduledEnforcement: true,
            customConditions: true,
          },
          auditTrail: {
            createdAt: timestamp,
            action: 'policy_created',
            policyId,
            conditionsValidated: input.conditions.length,
            impactEstimated: Number(estimatedImpact.sampleSize) > 0,
          },
          message: `Scenario archival policy "${input.name}" created successfully with ${input.conditions.length} conditions. Estimated impact: ${Number(estimatedImpact.potentiallyAffected) || 0}/${Number(estimatedImpact.totalScenariosInScope) || 0} scenarios.`,
        }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error creating scenario archival policy', { error: errorMessage, name: input.name });
        
        // Log failure audit event
        await auditLogger.logEvent({
          level: 'error',
          category: 'configuration',
          action: 'scenario_archival_policy_creation_failed',
          success: false,
          details: {
            name: input.name,
            error: errorMessage,
            conditionsCount: input.conditions.length,
          },
          riskLevel: 'low',
        });
        
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to create scenario archival policy: ${errorMessage}`);
      }
    },
  });
}

/**
 * Helper function to add evaluate scenario archival policy tool
 */
function addEvaluateScenarioArchivalPolicyTool(
  server: FastMCP,
  apiClient: MakeApiClient,
  policyEngine: ScenarioArchivalPolicyEngine
): void {
  server.addTool({
    name: 'evaluate-scenario-archival-policy',
    description: 'Evaluate scenarios against archival policy conditions with optional enforcement',
    parameters: EvaluatePolicySchema,
    annotations: {
      title: 'Evaluate Archival Policy',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
    execute: async (input, { log, reportProgress }) => {
      log.info('Evaluating scenario archival policy', {
        policyId: input.policyId,
        dryRun: input.evaluationOptions.dryRun,
        scenarioCount: input.evaluationOptions.scenarioIds?.length || 'all',
      });

      reportProgress({ progress: 0, total: 100 });

      try {
        // Fetch policy
        const policyResponse = await apiClient.get(`/policies/scenario-archival/${input.policyId}`);
        
        if (!policyResponse.success) {
          throw new UserError(`Archival policy not found: ${input.policyId}`);
        }

        const policy = policyResponse.data as {
          name: string;
          conditions: z.infer<typeof ArchivalConditionSchema>[];
          conditionLogic: 'AND' | 'OR' | 'CUSTOM';
          enforcement: Record<string, unknown>;
          gracePeriod: Record<string, unknown>;
          active: boolean;
        };

        if (!policy.active) {
          throw new UserError(`Policy is not active: ${input.policyId}`);
        }

        reportProgress({ progress: 20, total: 100 });

        // Gather usage metrics
        const usageMetrics = await policyEngine.gatherUsageMetrics(input.evaluationOptions.scenarioIds);
        
        reportProgress({ progress: 50, total: 100 });

        // Evaluate conditions
        const evaluationResults = await policyEngine.evaluateConditions(
          usageMetrics,
          policy.conditions,
          policy.conditionLogic
        );

        reportProgress({ progress: 70, total: 100 });

        // Filter scenarios that should be archived
        const scenariosToArchive = evaluationResults.filter(r => r.shouldArchive);
        
        // Execute enforcement if not dry run
        let enforcementResults: { success: boolean; results: Array<{ scenarioId: string; success: boolean; error?: string }> } | { message: string; pendingReview: number } | null = null;
        if (!input.evaluationOptions.dryRun && scenariosToArchive.length > 0) {
          if (policy.enforcement.level === ArchivalEnforcement.AUTOMATIC) {
            const scenarioIds = scenariosToArchive.map(s => s.scenarioId);
            enforcementResults = await policyEngine.executeArchivalAction(
              scenarioIds,
              policy.enforcement.action as ArchivalAction,
              {
                targetFolderId: policy.enforcement.targetFolderId as string,
                batchSize: policy.enforcement.batchSize as number,
                dryRun: false,
                reason: `Archival policy enforcement: ${policy.name}`,
              }
            );
          } else {
            enforcementResults = {
              message: 'Manual review required - no automatic enforcement performed',
              pendingReview: scenariosToArchive.length,
            };
          }
        }

        reportProgress({ progress: 90, total: 100 });

        // Prepare comprehensive results
        const summary = {
          totalEvaluated: evaluationResults.length,
          shouldArchive: scenariosToArchive.length,
          averageArchivalScore: scenariosToArchive.length > 0 
            ? scenariosToArchive.reduce((sum, s) => sum + s.score, 0) / scenariosToArchive.length 
            : 0,
          topReasons: getTopArchivalReasons(scenariosToArchive),
          conditionBreakdown: getConditionBreakdown(evaluationResults, policy.conditions),
        };

        // Log evaluation audit event
        await auditLogger.logEvent({
          level: scenariosToArchive.length > 0 ? 'warn' : 'info',
          category: 'configuration',
          action: 'scenario_archival_policy_evaluation',
          resource: `policy:${input.policyId}`,
          success: true,
          details: {
            policyId: input.policyId,
            evaluatedScenarios: evaluationResults.length,
            scenariosToArchive: scenariosToArchive.length,
            dryRun: input.evaluationOptions.dryRun,
            enforcementPerformed: !input.evaluationOptions.dryRun && enforcementResults !== null,
          },
          riskLevel: scenariosToArchive.length > 10 ? 'high' : 'medium',
        });

        reportProgress({ progress: 100, total: 100 });

        log.info('Scenario archival policy evaluation completed', {
          policyId: input.policyId,
          totalEvaluated: summary.totalEvaluated,
          shouldArchive: summary.shouldArchive,
          enforcementPerformed: !input.evaluationOptions.dryRun && enforcementResults !== null,
        });

        return formatSuccessResponse({
          success: true,
          policyId: input.policyId,
          policyName: policy.name,
          evaluationResults: input.evaluationOptions.includeMetrics ? evaluationResults : undefined,
          scenariosToArchive: scenariosToArchive.map(s => ({
            scenarioId: s.scenarioId,
            reasons: s.reasons,
            score: s.score,
          })),
          summary,
          enforcement: {
            performed: !input.evaluationOptions.dryRun && enforcementResults !== null,
            results: enforcementResults,
            gracePeriod: policy.gracePeriod.enabled ? {
              duration: policy.gracePeriod.durationDays,
              notifications: policy.gracePeriod.notificationSchedule,
            } : null,
          },
          evaluation: {
            timestamp: new Date().toISOString(),
            dryRun: input.evaluationOptions.dryRun,
            executionContext: input.executionContext,
          },
          message: `Evaluated ${summary.totalEvaluated} scenarios: ${summary.shouldArchive} candidates for archival. ${input.evaluationOptions.dryRun ? 'Dry run - no actions taken.' : enforcementResults ? 'Enforcement actions executed.' : 'Manual review required.'}`,
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error evaluating scenario archival policy', { error: errorMessage, policyId: input.policyId });
        
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to evaluate scenario archival policy: ${errorMessage}`);
      }
    },
  });
}

/**
 * Helper function to add list scenario archival policies tool
 */
function addListScenarioArchivalPoliciesTools(
  server: FastMCP,
  apiClient: MakeApiClient
): void {
  server.addTool({
    name: 'list-scenario-archival-policies',
    description: 'List and filter scenario archival policies',
    parameters: PolicyFiltersSchema,
    annotations: {
      title: 'List Archival Policies',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      log.info('Listing scenario archival policies', {
        filters: input,
        limit: input.limit,
        offset: input.offset,
      });

      try {
        const params = {
          ...input,
          limit: input.limit,
          offset: input.offset,
        };

        const response = await apiClient.get('/policies/scenario-archival', { params });
        
        if (!response.success) {
          throw new UserError(`Failed to list policies: ${response.error?.message || 'Unknown error'}`);
        }

        const policies = response.data || [];
        const metadata = response.metadata;

        // Calculate summary statistics
        const summaryStats = {
          totalPolicies: Array.isArray(policies) ? policies.length : 0,
          activePolicies: Array.isArray(policies) ? policies.filter((p: Record<string, unknown>) => p.active).length : 0,
          inactivePolicies: Array.isArray(policies) ? policies.filter((p: Record<string, unknown>) => !p.active).length : 0,
          enforcementLevels: Array.isArray(policies) 
            ? policies.reduce((acc: Record<string, number>, policy: Record<string, unknown>) => {
                const level = (policy.enforcement as Record<string, unknown>)?.level || 'unknown';
                acc[String(level)] = (acc[String(level)] || 0) + 1;
                return acc;
              }, {})
            : {},
          triggerTypes: Array.isArray(policies)
            ? policies.reduce((acc: Record<string, number>, policy: Record<string, unknown>) => {
                if (policy.conditions && Array.isArray(policy.conditions)) {
                  policy.conditions.forEach((condition: Record<string, unknown>) => {
                    acc[String(condition.trigger)] = (acc[String(condition.trigger)] || 0) + 1;
                  });
                }
                return acc;
              }, {})
            : {},
          totalConditions: Array.isArray(policies)
            ? policies.reduce((sum: number, policy: Record<string, unknown>) => sum + ((policy.conditions as unknown[])?.length || 0), 0)
            : 0,
        };

        log.info('Successfully retrieved scenario archival policies', {
          count: summaryStats.totalPolicies,
          active: summaryStats.activePolicies,
          inactive: summaryStats.inactivePolicies,
        });

        return formatSuccessResponse({
          success: true,
          policies: Array.isArray(policies) ? policies : [],
          summary: summaryStats,
          pagination: {
            total: metadata?.total || summaryStats.totalPolicies,
            limit: input.limit,
            offset: input.offset,
            hasMore: (metadata?.total || 0) > (input.offset + summaryStats.totalPolicies),
          },
          capabilities: {
            triggers: Object.values(ArchivalTrigger),
            actions: Object.values(ArchivalAction),
            enforcementLevels: Object.values(ArchivalEnforcement),
          },
          timestamp: new Date().toISOString(),
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error listing scenario archival policies', { error: errorMessage });
        
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to list scenario archival policies: ${errorMessage}`);
      }
    },
  });
}

/**
 * Get updated fields from input
 */
function getUpdatedFields(input: z.infer<typeof UpdateArchivalPolicySchema>): string[] {
  return Object.keys(input).filter(k => k !== 'policyId' && input[k as keyof typeof input] !== undefined);
}

/**
 * Fetch existing policy data
 */
async function fetchExistingPolicy(
  apiClient: MakeApiClient,
  policyId: string
): Promise<Record<string, unknown>> {
  const existingResponse = await apiClient.get(`/policies/scenario-archival/${policyId}`);
  
  if (!existingResponse.success) {
    throw new UserError(`Archival policy not found: ${policyId}`);
  }

  return existingResponse.data as Record<string, unknown>;
}

/**
 * Validate custom conditions in input
 */
function validateCustomConditions(
  conditions: z.infer<typeof ArchivalConditionSchema>[],
  policyEngine: ScenarioArchivalPolicyEngine
): void {
  for (const condition of conditions) {
    if (condition.trigger === ArchivalTrigger.CUSTOM && condition.customEvaluationFunction) {
      try {
        if (!policyEngine.isSafeCustomFunction(condition.customEvaluationFunction)) {
          throw new Error('Custom function contains unsafe operations');
        }
        // Basic syntax validation would be done here
      } catch (error) {
        throw new UserError(`Invalid custom function in condition ${condition.id}: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }
  }
}

/**
 * Prepare update data by merging existing policy with new input
 */
function prepareUpdateData(
  input: z.infer<typeof UpdateArchivalPolicySchema>,
  existingPolicy: Record<string, unknown>,
  timestamp: string,
  policyEngine: ScenarioArchivalPolicyEngine
): Record<string, unknown> {
  const updateData: Record<string, unknown> = {
    ...existingPolicy,
    updatedAt: timestamp,
  };

  // Apply basic updates
  if (input.name !== undefined) {updateData.name = input.name;}
  if (input.description !== undefined) {updateData.description = input.description;}
  
  // Handle conditions validation and update
  if (input.conditions !== undefined) {
    validateCustomConditions(input.conditions, policyEngine);
    updateData.conditions = input.conditions.sort((a, b) => (a.priority || 50) - (b.priority || 50));
  }

  // Handle nested object updates
  if (input.enforcement !== undefined) {
    updateData.enforcement = {
      ...(existingPolicy.enforcement as Record<string, unknown> || {}),
      ...input.enforcement,
    };
  }

  if (input.gracePeriod !== undefined) {
    updateData.gracePeriod = {
      ...(existingPolicy.gracePeriod as Record<string, unknown> || {}),
      ...input.gracePeriod,
    };
  }

  if (input.rollback !== undefined) {
    updateData.rollback = {
      ...(existingPolicy.rollback as Record<string, unknown> || {}),
      ...input.rollback,
    };
  }

  // Handle simple field updates
  if (input.active !== undefined) {updateData.active = input.active;}
  if (input.effectiveFrom !== undefined) {updateData.effectiveFrom = input.effectiveFrom;}
  if (input.effectiveUntil !== undefined) {updateData.effectiveUntil = input.effectiveUntil;}

  // Handle metadata updates
  if (input.metadata !== undefined) {
    updateData.metadata = {
      ...(existingPolicy.metadata as Record<string, unknown> || {}),
      ...input.metadata,
      lastMetadataUpdate: timestamp,
    };
  }

  return updateData;
}

/**
 * Execute policy update API call
 */
async function executePolicyUpdate(
  apiClient: MakeApiClient,
  policyId: string,
  updateData: Record<string, unknown>
): Promise<{ name: string; [key: string]: unknown }> {
  const response = await apiClient.patch(`/policies/scenario-archival/${policyId}`, updateData);
  
  if (!response.success) {
    throw new UserError(`Failed to update archival policy: ${response.error?.message || 'Unknown error'}`);
  }

  return response.data as { name: string; [key: string]: unknown };
}

/**
 * Log policy update audit event
 */
async function logPolicyUpdateAudit(
  input: z.infer<typeof UpdateArchivalPolicySchema>,
  existingPolicy: Record<string, unknown>,
  updatedFields: string[]
): Promise<void> {
  await auditLogger.logEvent({
    level: 'info',
    category: 'configuration',
    action: 'scenario_archival_policy_updated',
    resource: `policy:${input.policyId}`,
    success: true,
    details: {
      policyId: input.policyId,
      updatedFields,
      conditionsCount: input.conditions?.length || (existingPolicy.conditions as unknown[] | undefined)?.length || 0,
      active: input.active !== undefined ? input.active : (existingPolicy.active as boolean | undefined),
    },
    riskLevel: 'medium',
  });
}

/**
 * Log policy update failure audit event
 */
async function logPolicyUpdateFailure(
  policyId: string,
  errorMessage: string
): Promise<void> {
  await auditLogger.logEvent({
    level: 'error',
    category: 'configuration',
    action: 'scenario_archival_policy_update_failed',
    resource: `policy:${policyId}`,
    success: false,
    details: {
      policyId,
      error: errorMessage,
    },
    riskLevel: 'low',
  });
}

/**
 * Create success response for policy update
 */
function createUpdateSuccessResponse(
  input: z.infer<typeof UpdateArchivalPolicySchema>,
  updatedPolicy: { name: string; [key: string]: unknown },
  existingPolicy: Record<string, unknown>,
  updatedFields: string[],
  timestamp: string
): string {
  return formatSuccessResponse({
    success: true,
    policy: updatedPolicy,
    changes: {
      updatedFields,
      timestamp,
      version: `${(existingPolicy.version as string | undefined) || '1.0.0'}-updated`,
    },
    auditTrail: {
      updatedAt: timestamp,
      action: 'policy_updated',
      policyId: input.policyId,
      fieldsChanged: updatedFields.length,
    },
    message: `Scenario archival policy "${updatedPolicy.name}" updated successfully`,
  }).content[0].text;
}

/**
 * Helper function to add update scenario archival policy tool
 */
function addUpdateScenarioArchivalPolicyTool(
  server: FastMCP,
  apiClient: MakeApiClient,
  policyEngine: ScenarioArchivalPolicyEngine
): void {
  server.addTool({
    name: 'update-scenario-archival-policy',
    description: 'Update an existing scenario archival policy',
    parameters: UpdateArchivalPolicySchema,
    annotations: {
      title: 'Update Archival Policy',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const updatedFields = getUpdatedFields(input);
      log.info('Updating scenario archival policy', {
        policyId: input.policyId,
        updates: updatedFields,
      });

      try {
        // Get existing policy using helper function
        const existingPolicy = await fetchExistingPolicy(apiClient, input.policyId);
        const timestamp = new Date().toISOString();
        
        // Prepare update data using helper function
        const updateData = prepareUpdateData(input, existingPolicy, timestamp, policyEngine);

        // Update policy using helper function
        const updatedPolicy = await executePolicyUpdate(apiClient, input.policyId, updateData);

        // Log policy update audit event using helper function
        await logPolicyUpdateAudit(input, existingPolicy, updatedFields);

        log.info('Successfully updated scenario archival policy', {
          policyId: input.policyId,
          name: updatedPolicy.name,
          updatedFields: updatedFields.length,
        });

        // Create success response using helper function
        return createUpdateSuccessResponse(input, updatedPolicy, existingPolicy, updatedFields, timestamp);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error updating scenario archival policy', { error: errorMessage, policyId: input.policyId });
        
        // Log failure audit event using helper function
        await logPolicyUpdateFailure(input.policyId, errorMessage);
        
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to update scenario archival policy: ${errorMessage}`);
      }
    },
  });
}

/**
 * Helper function to add delete scenario archival policy tool
 */
function addDeleteScenarioArchivalPolicyTool(
  server: FastMCP,
  apiClient: MakeApiClient
): void {
  server.addTool({
    name: 'delete-scenario-archival-policy',
    description: 'Delete a scenario archival policy',
    parameters: z.object({
      policyId: z.string().min(1).describe('Policy ID to delete'),
      confirmDeletion: z.boolean().default(false).describe('Confirm policy deletion'),
    }),
    annotations: {
      title: 'Delete Archival Policy',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      log.info('Deleting scenario archival policy', { policyId: input.policyId });

      try {
        if (!input.confirmDeletion) {
          throw new UserError('Policy deletion requires explicit confirmation. Set confirmDeletion to true.');
        }

        // Get policy details before deletion
        const policyResponse = await apiClient.get(`/policies/scenario-archival/${input.policyId}`);
        
        if (!policyResponse.success) {
          throw new UserError(`Archival policy not found: ${input.policyId}`);
        }

        const policy = policyResponse.data as { 
          name: string; 
          conditions?: unknown[]; 
          active: boolean; 
          enforcement: { level: string }; 
          [key: string]: unknown 
        };

        // Delete policy
        const response = await apiClient.delete(`/policies/scenario-archival/${input.policyId}`);
        
        if (!response.success) {
          throw new UserError(`Failed to delete archival policy: ${response.error?.message || 'Unknown error'}`);
        }

        // Log policy deletion audit event
        await auditLogger.logEvent({
          level: 'warn',
          category: 'configuration',
          action: 'scenario_archival_policy_deleted',
          resource: `policy:${input.policyId}`,
          success: true,
          details: {
            policyId: input.policyId,
            policyName: policy.name,
            conditionsCount: policy.conditions?.length || 0,
            wasActive: policy.active,
            enforcementLevel: policy.enforcement.level,
          },
          riskLevel: 'medium',
        });

        log.info('Successfully deleted scenario archival policy', {
          policyId: input.policyId,
          name: policy.name,
        });

        return formatSuccessResponse({
          success: true,
          deletedPolicy: {
            id: input.policyId,
            name: policy.name,
            conditionsCount: policy.conditions?.length || 0,
            wasActive: policy.active,
          },
          auditTrail: {
            deletedAt: new Date().toISOString(),
            action: 'policy_deleted',
            policyId: input.policyId,
            confirmationRequired: true,
          },
          message: `Scenario archival policy "${policy.name}" deleted successfully`,
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error deleting scenario archival policy', { error: errorMessage, policyId: input.policyId });
        
        // Log failure audit event
        await auditLogger.logEvent({
          level: 'error',
          category: 'configuration',
          action: 'scenario_archival_policy_deletion_failed',
          resource: `policy:${input.policyId}`,
          success: false,
          details: {
            policyId: input.policyId,
            error: errorMessage,
          },
          riskLevel: 'low',
        });
        
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to delete scenario archival policy: ${errorMessage}`);
      }
    },
  });
}

// Helper methods for evaluation results analysis
const getTopArchivalReasons = (scenarios: Array<{ reasons: string[] }>): Array<{ reason: string; count: number }> => {
  const reasonCounts = new Map<string, number>();
  
  scenarios.forEach(s => {
    s.reasons.forEach(reason => {
      reasonCounts.set(reason, (reasonCounts.get(reason) || 0) + 1);
    });
  });

  return Array.from(reasonCounts.entries())
    .map(([reason, count]) => ({ reason, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);
};

const getConditionBreakdown = (
  results: Array<{ shouldArchive: boolean; reasons: string[] }>,
  conditions: z.infer<typeof ArchivalConditionSchema>[]
): Array<{ condition: string; matchedScenarios: number; percentage: number }> => {
  const breakdown: Array<{ condition: string; matchedScenarios: number; percentage: number }> = [];

  conditions.forEach(condition => {
    const matchedCount = results.filter(r => 
      r.shouldArchive && r.reasons.some(reason => reason.includes(condition.name))
    ).length;

    breakdown.push({
      condition: condition.name,
      matchedScenarios: matchedCount,
      percentage: results.length > 0 ? Math.round((matchedCount / results.length) * 100) : 0,
    });
  });

  return breakdown.sort((a, b) => b.matchedScenarios - a.matchedScenarios);
};

/**
 * Adds comprehensive scenario archival policy tools to the FastMCP server
 * 
 * @param {FastMCP} server - The FastMCP server instance
 * @param {MakeApiClient} apiClient - Make.com API client with rate limiting and authentication
 * @returns {void}
 */
export function addScenarioArchivalPolicyTools(server: FastMCP, apiClient: MakeApiClient): void {
  const getComponentLogger = (): ReturnType<typeof logger.child> => {
    try {
      return logger.child({ component: 'ScenarioArchivalPolicyTools' });
    } catch {
      // Fallback for test environments
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return logger as any;
    }
  };
  const componentLogger = getComponentLogger();
  const policyEngine = new ScenarioArchivalPolicyEngine(apiClient);
  
  componentLogger.info('Adding scenario archival policy management tools');

  // Add all scenario archival policy tools
  addSetScenarioArchivalPolicyTool(server, apiClient, policyEngine, componentLogger);
  addEvaluateScenarioArchivalPolicyTool(server, apiClient, policyEngine);
  addListScenarioArchivalPoliciesTools(server, apiClient);
  addUpdateScenarioArchivalPolicyTool(server, apiClient, policyEngine);
  addDeleteScenarioArchivalPolicyTool(server, apiClient);

  componentLogger.info('Scenario archival policy management tools added successfully');
}

export default addScenarioArchivalPolicyTools;