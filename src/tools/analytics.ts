/**
 * Analytics and audit log access tools for Make.com FastMCP Server
 * Comprehensive tools for accessing analytics data, audit logs, execution history, and performance metrics
 */

import { FastMCP, UserError } from 'fastmcp';
import { z } from 'zod';
import MakeApiClient from '../lib/make-api-client.js';
import { MakeAnalytics, MakeAuditLog, MakeScenarioLog, MakeIncompleteExecution, MakeHookLog, MakeExecution } from '../types/index.js';
import logger from '../lib/logger.js';
import { formatSuccessResponse } from '../utils/response-formatter.js';

// Input validation schemas
const AnalyticsFiltersSchema = z.object({
  organizationId: z.number().min(1).describe('Organization ID for analytics'),
  startDate: z.string().optional().describe('Start date for analytics period (ISO format)'),
  endDate: z.string().optional().describe('End date for analytics period (ISO format)'),
  period: z.enum(['day', 'week', 'month', 'quarter', 'year']).default('month').describe('Analytics period granularity'),
  includeUsage: z.boolean().default(true).describe('Include usage statistics'),
  includePerformance: z.boolean().default(true).describe('Include performance metrics'),
  includeBilling: z.boolean().default(true).describe('Include billing information'),
}).strict();

const AuditLogFiltersSchema = z.object({
  organizationId: z.number().min(1).optional().describe('Filter by organization ID'),
  teamId: z.number().min(1).optional().describe('Filter by team ID'),
  userId: z.number().min(1).optional().describe('Filter by user ID'),
  action: z.string().optional().describe('Filter by action type'),
  resource: z.string().optional().describe('Filter by resource type'),
  startDate: z.string().optional().describe('Start date for log search (ISO format)'),
  endDate: z.string().optional().describe('End date for log search (ISO format)'),
  limit: z.number().min(1).max(1000).default(100).describe('Maximum number of logs to return'),
  offset: z.number().min(0).default(0).describe('Number of logs to skip for pagination'),
}).strict();

const ScenarioLogFiltersSchema = z.object({
  scenarioId: z.number().min(1).describe('Scenario ID to get logs for'),
  executionId: z.number().min(1).optional().describe('Filter by specific execution ID'),
  level: z.enum(['info', 'warning', 'error', 'debug']).optional().describe('Filter by log level'),
  startDate: z.string().optional().describe('Start date for log search (ISO format)'),
  endDate: z.string().optional().describe('End date for log search (ISO format)'),
  limit: z.number().min(1).max(1000).default(100).describe('Maximum number of logs to return'),
  offset: z.number().min(0).default(0).describe('Number of logs to skip for pagination'),
}).strict();

const ExecutionHistoryFiltersSchema = z.object({
  scenarioId: z.number().min(1).optional().describe('Filter by scenario ID'),
  organizationId: z.number().min(1).optional().describe('Filter by organization ID'),
  teamId: z.number().min(1).optional().describe('Filter by team ID'),
  status: z.enum(['success', 'error', 'warning', 'incomplete']).optional().describe('Filter by execution status'),
  startDate: z.string().optional().describe('Start date for execution search (ISO format)'),
  endDate: z.string().optional().describe('End date for execution search (ISO format)'),
  limit: z.number().min(1).max(1000).default(100).describe('Maximum number of executions to return'),
  offset: z.number().min(0).default(0).describe('Number of executions to skip for pagination'),
}).strict();

const IncompleteExecutionFiltersSchema = z.object({
  scenarioId: z.number().min(1).optional().describe('Filter by scenario ID'),
  organizationId: z.number().min(1).optional().describe('Filter by organization ID'),
  status: z.enum(['waiting', 'paused', 'failed']).optional().describe('Filter by incomplete execution status'),
  canResume: z.boolean().optional().describe('Filter by resumable status'),
  limit: z.number().min(1).max(100).default(20).describe('Maximum number of incomplete executions to return'),
  offset: z.number().min(0).default(0).describe('Number of incomplete executions to skip for pagination'),
}).strict();

const HookLogFiltersSchema = z.object({
  hookId: z.number().min(1).describe('Hook ID to get logs for'),
  success: z.boolean().optional().describe('Filter by success/failure status'),
  method: z.string().optional().describe('Filter by HTTP method'),
  startDate: z.string().optional().describe('Start date for log search (ISO format)'),
  endDate: z.string().optional().describe('End date for log search (ISO format)'),
  limit: z.number().min(1).max(1000).default(100).describe('Maximum number of logs to return'),
  offset: z.number().min(0).default(0).describe('Number of logs to skip for pagination'),
}).strict();

const ExportDataSchema = z.object({
  organizationId: z.number().min(1).describe('Organization ID for data export'),
  dataType: z.enum(['analytics', 'audit_logs', 'execution_history', 'scenario_logs']).describe('Type of data to export'),
  format: z.enum(['json', 'csv', 'xlsx']).default('json').describe('Export format'),
  startDate: z.string().describe('Start date for data export (ISO format)'),
  endDate: z.string().describe('End date for data export (ISO format)'),
  includeDetails: z.boolean().default(true).describe('Include detailed data in export'),
}).strict();

/**
 * Add analytics and audit log tools to FastMCP server
 */
export function addAnalyticsTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'AnalyticsTools' });
  
  componentLogger.info('Adding analytics and audit log tools');

  // Get organization analytics
  server.addTool({
    name: 'get-organization-analytics',
    description: 'Get comprehensive analytics data for an organization',
    parameters: AnalyticsFiltersSchema,
    annotations: {
      title: 'Organization Analytics',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, context) => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} }, reportProgress: _reportProgress = (): void => {} } = context || {};
      const { organizationId, startDate, endDate, period, includeUsage, includePerformance, includeBilling } = input;

      if (log && log.info) {
        log.info('Getting organization analytics', {
          organizationId,
          period,
          startDate,
          endDate,
        });
      }

      try {
        const params: Record<string, unknown> = {
          period,
          includeUsage,
          includePerformance,
          includeBilling,
        };

        if (startDate) params.startDate = startDate;
        if (endDate) params.endDate = endDate;

        const response = await apiClient.get(`/analytics/${organizationId}`, { params });

        if (!response.success) {
          throw new UserError(`Failed to get analytics: ${response.error?.message || 'Unknown error'}`);
        }

        const analytics = response.data as MakeAnalytics;
        if (!analytics) {
          throw new UserError('Analytics data not available');
        }

        if (log && log.info) {
          log.info('Successfully retrieved analytics', {
            organizationId,
            period: analytics.period,
            executions: analytics.usage.executions,
            operations: analytics.usage.operations,
          });
        }

        return formatSuccessResponse({
          analytics,
          summary: {
            totalExecutions: analytics.usage.executions,
            totalOperations: analytics.usage.operations,
            successRate: Math.round((analytics.usage.successfulExecutions / analytics.usage.executions) * 100),
            averageExecutionTime: analytics.performance.averageExecutionTime,
            operationsUtilization: Math.round((analytics.billing.operationsUsed / analytics.billing.operationsLimit) * 100),
          },
        }, "Organization analytics retrieved successfully");
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (log && log.error) {
          log.error('Error getting analytics', { organizationId, error: errorMessage });
        }
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to get organization analytics: ${errorMessage}`);
      }
    },
  });

  // List audit logs
  server.addTool({
    name: 'list-audit-logs',
    description: 'List and filter audit logs for security and compliance monitoring',
    parameters: AuditLogFiltersSchema,
    annotations: {
      title: 'List Audit Logs',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, context) => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} }, reportProgress: _reportProgress = (): void => {} } = context || {};
      const { organizationId, teamId, userId, action, resource, startDate, endDate, limit, offset } = input;

      if (log && log.info) {
        log.info('Listing audit logs', {
          organizationId,
          teamId,
          userId,
          action,
          resource,
          limit,
          offset,
        });
      }

      try {
        const params: Record<string, unknown> = {
          limit,
          offset,
        };

        if (organizationId) params.organizationId = organizationId;
        if (teamId) params.teamId = teamId;
        if (userId) params.userId = userId;
        if (action) params.action = action;
        if (resource) params.resource = resource;
        if (startDate) params.startDate = startDate;
        if (endDate) params.endDate = endDate;

        const response = await apiClient.get('/audit-logs', { params });

        if (!response.success) {
          throw new UserError(`Failed to list audit logs: ${response.error?.message || 'Unknown error'}`);
        }

        const auditLogs = response.data as MakeAuditLog[] || [];
        const metadata = response.metadata;

        if (log && log.info) {
          log.info('Successfully retrieved audit logs', {
            count: auditLogs.length,
            total: metadata?.total,
          });
        }

        // Create summary statistics
        const summary = {
          totalLogs: metadata?.total || auditLogs.length,
          actionTypes: [...new Set(auditLogs.map(log => log.action))],
          resourceTypes: [...new Set(auditLogs.map(log => log.resource))],
          uniqueUsers: [...new Set(auditLogs.map(log => log.userId))].length,
          dateRange: auditLogs.length > 0 ? {
            earliest: auditLogs[auditLogs.length - 1]?.timestamp,
            latest: auditLogs[0]?.timestamp,
          } : null,
        };

        return formatSuccessResponse({
          auditLogs,
          summary,
          pagination: {
            total: metadata?.total || auditLogs.length,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + auditLogs.length),
          },
        }, "Audit logs retrieved successfully");
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (log && log.error) {
          log.error('Error listing audit logs', { error: errorMessage });
        }
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to list audit logs: ${errorMessage}`);
      }
    },
  });

  // Get audit log details
  server.addTool({
    name: 'get-audit-log',
    description: 'Get detailed information about a specific audit log entry',
    annotations: {
      title: 'Get Audit Log Details',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    parameters: z.object({
      logId: z.number().min(1).describe('Audit log ID to retrieve'),
    }),
    execute: async (input, context) => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} }, reportProgress: _reportProgress = (): void => {} } = context || {};
      const { logId } = input;

      if (log && log.info) {
        log.info('Getting audit log details', { logId });
      }

      try {
        const response = await apiClient.get(`/audit-logs/${logId}`);

        if (!response.success) {
          throw new UserError(`Failed to get audit log: ${response.error?.message || 'Unknown error'}`);
        }

        const auditLog = response.data as MakeAuditLog;
        if (!auditLog) {
          throw new UserError(`Audit log with ID ${logId} not found`);
        }

        if (log && log.info) {
          log.info('Successfully retrieved audit log', {
            logId,
            action: auditLog.action,
            resource: auditLog.resource,
            userId: auditLog.userId,
          });
        }

        return formatSuccessResponse({ auditLog }, "Audit log details retrieved successfully").content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (log && log.error) {
          log.error('Error getting audit log', { logId, error: errorMessage });
        }
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to get audit log details: ${errorMessage}`);
      }
    },
  });

  // Get scenario logs
  server.addTool({
    name: 'get-scenario-logs',
    description: 'Get execution logs for a specific scenario',
    annotations: {
      title: 'Get Scenario Logs',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    parameters: ScenarioLogFiltersSchema,
    execute: async (input, context) => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} }, reportProgress: _reportProgress = (): void => {} } = context || {};
      const { scenarioId, executionId, level, startDate, endDate, limit, offset } = input;

      if (log && log.info) {
        log.info('Getting scenario logs', {
          scenarioId,
          executionId,
          level,
          limit,
          offset,
        });
      }

      try {
        const params: Record<string, unknown> = {
          limit,
          offset,
        };

        if (executionId) params.executionId = executionId;
        if (level) params.level = level;
        if (startDate) params.startDate = startDate;
        if (endDate) params.endDate = endDate;

        const response = await apiClient.get(`/scenarios/${scenarioId}/logs`, { params });

        if (!response.success) {
          throw new UserError(`Failed to get scenario logs: ${response.error?.message || 'Unknown error'}`);
        }

        const scenarioLogs = response.data as MakeScenarioLog[] || [];
        const metadata = response.metadata;

        if (log && log.info) {
          log.info('Successfully retrieved scenario logs', {
            scenarioId,
            count: scenarioLogs.length,
            total: metadata?.total,
          });
        }

        // Create log level summary
        const summary = {
          totalLogs: metadata?.total || scenarioLogs.length,
          logLevels: {
            info: scenarioLogs.filter(log => log.level === 'info').length,
            warning: scenarioLogs.filter(log => log.level === 'warning').length,
            error: scenarioLogs.filter(log => log.level === 'error').length,
            debug: scenarioLogs.filter(log => log.level === 'debug').length,
          },
          uniqueExecutions: [...new Set(scenarioLogs.map(log => log.executionId))].length,
          uniqueModules: [...new Set(scenarioLogs.map(log => log.moduleName).filter(Boolean))],
        };

        return formatSuccessResponse({
          scenarioLogs,
          summary,
          pagination: {
            total: metadata?.total || scenarioLogs.length,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + scenarioLogs.length),
          },
        }, "Scenario logs retrieved successfully");
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (log && log.error) {
          log.error('Error getting scenario logs', { scenarioId, error: errorMessage });
        }
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to get scenario logs: ${errorMessage}`);
      }
    },
  });

  // Get execution history
  server.addTool({
    name: 'get-execution-history',
    description: 'Get comprehensive execution history with filtering and analytics',
    annotations: {
      title: 'Execution History',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    parameters: ExecutionHistoryFiltersSchema,
    execute: async (input, context) => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} }, reportProgress: _reportProgress = (): void => {} } = context || {};
      const { scenarioId, organizationId, teamId, status, startDate, endDate, limit, offset } = input;

      if (log && log.info) {
        log.info('Getting execution history', {
          scenarioId,
          organizationId,
          teamId,
          status,
          limit,
          offset,
        });
      }

      try {
        const params: Record<string, unknown> = {
          limit,
          offset,
        };

        if (scenarioId) params.scenarioId = scenarioId;
        if (organizationId) params.organizationId = organizationId;
        if (teamId) params.teamId = teamId;
        if (status) params.status = status;
        if (startDate) params.startDate = startDate;
        if (endDate) params.endDate = endDate;

        let endpoint = '/executions';
        if (scenarioId) {
          endpoint = `/scenarios/${scenarioId}/executions`;
        }

        const response = await apiClient.get(endpoint, { params });

        if (!response.success) {
          throw new UserError(`Failed to get execution history: ${response.error?.message || 'Unknown error'}`);
        }

        const executions = response.data as MakeExecution[] || [];
        const metadata = response.metadata;

        if (log && log.info) {
          log.info('Successfully retrieved execution history', {
            count: executions.length,
            total: metadata?.total,
          });
        }

        // Calculate performance metrics
        const summary = {
          totalExecutions: metadata?.total || executions.length,
          statusBreakdown: {
            success: executions.filter(exec => exec.status === 'success').length,
            error: executions.filter(exec => exec.status === 'error').length,
            warning: executions.filter(exec => exec.status === 'warning').length,
            incomplete: executions.filter(exec => exec.status === 'incomplete').length,
          },
          totalOperations: executions.reduce((sum, exec) => sum + exec.operations, 0),
          totalDataTransfer: executions.reduce((sum, exec) => sum + exec.dataTransfer, 0),
          averageExecutionTime: executions.length > 0 ? executions
            .filter(exec => exec.finishedAt)
            .reduce((sum, exec) => {
              const startTime = new Date(exec.startedAt).getTime();
              const endTime = new Date(exec.finishedAt!).getTime();
              return sum + (endTime - startTime);
            }, 0) / executions.filter(exec => exec.finishedAt).length : 0,
        };

        return formatSuccessResponse({
          executions,
          summary,
          pagination: {
            total: metadata?.total || executions.length,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + executions.length),
          },
        }, "Execution history retrieved successfully");
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (log && log.error) {
          log.error('Error getting execution history', { error: errorMessage });
        }
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to get execution history: ${errorMessage}`);
      }
    },
  });

  // List incomplete executions
  server.addTool({
    name: 'list-incomplete-executions',
    description: 'List and manage incomplete executions that require attention',
    annotations: {
      title: 'Incomplete Executions',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    parameters: IncompleteExecutionFiltersSchema,
    execute: async (input, context) => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} }, reportProgress: _reportProgress = (): void => {} } = context || {};
      const { scenarioId, organizationId, status, canResume, limit, offset } = input;

      if (log && log.info) {
        log.info('Listing incomplete executions', {
          scenarioId,
          organizationId,
          status,
          canResume,
          limit,
          offset,
        });
      }

      try {
        const params: Record<string, unknown> = {
          limit,
          offset,
        };

        if (scenarioId) params.scenarioId = scenarioId;
        if (organizationId) params.organizationId = organizationId;
        if (status) params.status = status;
        if (canResume !== undefined) params.canResume = canResume;

        const response = await apiClient.get('/incomplete-executions', { params });

        if (!response.success) {
          throw new UserError(`Failed to list incomplete executions: ${response.error?.message || 'Unknown error'}`);
        }

        const incompleteExecutions = response.data as MakeIncompleteExecution[] || [];
        const metadata = response.metadata;

        if (log && log.info) {
          log.info('Successfully retrieved incomplete executions', {
            count: incompleteExecutions.length,
            total: metadata?.total,
          });
        }

        const summary = {
          totalIncomplete: metadata?.total || incompleteExecutions.length,
          statusBreakdown: {
            waiting: incompleteExecutions.filter(exec => exec.status === 'waiting').length,
            paused: incompleteExecutions.filter(exec => exec.status === 'paused').length,
            failed: incompleteExecutions.filter(exec => exec.status === 'failed').length,
          },
          resumableCount: incompleteExecutions.filter(exec => exec.canResume).length,
          totalOperationsAffected: incompleteExecutions.reduce((sum, exec) => sum + exec.operations, 0),
          uniqueScenarios: [...new Set(incompleteExecutions.map(exec => exec.scenarioId))].length,
        };

        return formatSuccessResponse({
          incompleteExecutions,
          summary,
          pagination: {
            total: metadata?.total || incompleteExecutions.length,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + incompleteExecutions.length),
          },
        }, "Incomplete executions retrieved successfully");
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (log && log.error) {
          log.error('Error listing incomplete executions', { error: errorMessage });
        }
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to list incomplete executions: ${errorMessage}`);
      }
    },
  });

  // Resolve incomplete execution
  server.addTool({
    name: 'resolve-incomplete-execution',
    description: 'Resolve or retry an incomplete execution',
    annotations: {
      title: 'Resolve Incomplete Execution',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    parameters: z.object({
      executionId: z.number().min(1).describe('Incomplete execution ID to resolve'),
      action: z.enum(['retry', 'skip', 'cancel']).describe('Action to take on the incomplete execution'),
      reason: z.string().optional().describe('Reason for the resolution action'),
    }),
    execute: async (input, context) => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} }, reportProgress: _reportProgress = (): void => {} } = context || {};
      const { executionId, action, reason } = input;

      if (log && log.info) {
        log.info('Resolving incomplete execution', { executionId, action });
      }

      try {
        const resolveData = {
          action,
          reason,
        };

        const response = await apiClient.post(`/incomplete-executions/${executionId}/resolve`, resolveData);

        if (!response.success) {
          throw new UserError(`Failed to resolve incomplete execution: ${response.error?.message || 'Unknown error'}`);
        }

        const result = response.data as Record<string, unknown>;

        if (log && log.info) {
          log.info('Successfully resolved incomplete execution', {
            executionId,
            action,
            newStatus: String(result?.status || 'unknown'),
          });
        }

        return formatSuccessResponse({
          result,
        }, `Incomplete execution ${executionId} ${action} successfully`).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (log && log.error) {
          log.error('Error resolving incomplete execution', { executionId, error: errorMessage });
        }
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to resolve incomplete execution: ${errorMessage}`);
      }
    },
  });

  // Get hook logs
  server.addTool({
    name: 'get-hook-logs',
    description: 'Get webhook execution logs for debugging and monitoring',
    annotations: {
      title: 'Get Webhook Logs',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    parameters: HookLogFiltersSchema,
    execute: async (input, context) => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} }, reportProgress: _reportProgress = (): void => {} } = context || {};
      const { hookId, success, method, startDate, endDate, limit, offset } = input;

      if (log && log.info) {
        log.info('Getting hook logs', {
          hookId,
          success,
          method,
          limit,
          offset,
        });
      }

      try {
        const params: Record<string, unknown> = {
          limit,
          offset,
        };

        if (success !== undefined) params.success = success;
        if (method) params.method = method;
        if (startDate) params.startDate = startDate;
        if (endDate) params.endDate = endDate;

        const response = await apiClient.get(`/hooks/${hookId}/logs`, { params });

        if (!response.success) {
          throw new UserError(`Failed to get hook logs: ${response.error?.message || 'Unknown error'}`);
        }

        const hookLogs = response.data as MakeHookLog[] || [];
        const metadata = response.metadata;

        if (log && log.info) {
          log.info('Successfully retrieved hook logs', {
            hookId,
            count: hookLogs.length,
            total: metadata?.total,
          });
        }

        const summary = {
          totalLogs: metadata?.total || hookLogs.length,
          successRate: hookLogs.length > 0 ? 
            Math.round((hookLogs.filter(log => log.success).length / hookLogs.length) * 100) : 0,
          methodBreakdown: hookLogs.reduce((acc: Record<string, number>, log) => {
            acc[log.method] = (acc[log.method] || 0) + 1;
            return acc;
          }, {}),
          averageProcessingTime: hookLogs.length > 0 ? 
            hookLogs.reduce((sum, log) => sum + log.processingTime, 0) / hookLogs.length : 0,
          errorCount: hookLogs.filter(log => !log.success).length,
        };

        return formatSuccessResponse({
          hookLogs,
          summary,
          pagination: {
            total: metadata?.total || hookLogs.length,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + hookLogs.length),
          },
        }, "Hook logs retrieved successfully");
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (log && log.error) {
          log.error('Error getting hook logs', { hookId, error: errorMessage });
        }
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to get hook logs: ${errorMessage}`);
      }
    },
  });

  // Export analytics data
  server.addTool({
    name: 'export-analytics-data',
    description: 'Export analytics, audit logs, or execution data for external analysis',
    annotations: {
      title: 'Export Analytics Data',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    parameters: ExportDataSchema,
    execute: async (input, context) => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} }, reportProgress: _reportProgress = (): void => {} } = context || {};
      const { organizationId, dataType, format, startDate, endDate, includeDetails } = input;

      if (log && log.info) {
        log.info('Exporting analytics data', {
          organizationId,
          dataType,
          format,
          startDate,
          endDate,
        });
      }

      try {
        const exportData = {
          dataType,
          format,
          startDate,
          endDate,
          includeDetails,
        };

        const response = await apiClient.post(`/organizations/${organizationId}/export`, exportData);

        if (!response.success) {
          throw new UserError(`Failed to export data: ${response.error?.message || 'Unknown error'}`);
        }

        const exportResult = response.data as Record<string, unknown>;

        if (log && log.info) {
          log.info('Successfully initiated data export', {
            organizationId,
            dataType,
            format,
            exportId: String(exportResult?.exportId || 'unknown'),
          });
        }

        return formatSuccessResponse({
          exportResult,
          downloadUrl: exportResult?.downloadUrl,
          estimatedCompletionTime: exportResult?.estimatedCompletionTime,
        }, `Data export initiated successfully. Export ID: ${exportResult?.exportId}`).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (log && log.error) {
          log.error('Error exporting data', { organizationId, dataType, error: errorMessage });
        }
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to export analytics data: ${errorMessage}`);
      }
    },
  });

  // Get performance metrics
  server.addTool({
    name: 'get-performance-metrics',
    description: 'Get detailed performance metrics and trends',
    annotations: {
      title: 'Performance Metrics',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    parameters: z.object({
      organizationId: z.number().min(1).describe('Organization ID for metrics'),
      metric: z.enum(['execution_time', 'operations_per_minute', 'success_rate', 'data_transfer', 'all']).default('all').describe('Specific metric to retrieve'),
      period: z.enum(['hour', 'day', 'week', 'month']).default('day').describe('Aggregation period'),
      startDate: z.string().optional().describe('Start date for metrics (ISO format)'),
      endDate: z.string().optional().describe('End date for metrics (ISO format)'),
    }),
    execute: async (input, context) => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} }, reportProgress: _reportProgress = (): void => {} } = context || {};
      const { organizationId, metric, period, startDate, endDate } = input;

      if (log && log.info) {
        log.info('Getting performance metrics', {
          organizationId,
          metric,
          period,
        });
      }

      try {
        const params: Record<string, unknown> = {
          metric,
          period,
        };

        if (startDate) params.startDate = startDate;
        if (endDate) params.endDate = endDate;

        const response = await apiClient.get(`/organizations/${organizationId}/metrics`, { params });

        if (!response.success) {
          throw new UserError(`Failed to get performance metrics: ${response.error?.message || 'Unknown error'}`);
        }

        const metrics = response.data as Record<string, unknown>;

        if (log && log.info) {
          log.info('Successfully retrieved performance metrics', {
            organizationId,
            metric,
            dataPoints: (metrics?.dataPoints as unknown[])?.length || 0,
          });
        }

        return formatSuccessResponse({
          metrics,
          analysis: {
            trend: metrics?.trend || 'stable',
            currentValue: metrics?.currentValue,
            percentageChange: metrics?.percentageChange,
            recommendations: (metrics?.recommendations as unknown[]) || [],
          },
        }, "Performance metrics retrieved successfully");
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (log && log.error) {
          log.error('Error getting performance metrics', { organizationId, error: errorMessage });
        }
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to get performance metrics: ${errorMessage}`);
      }
    },
  });

  componentLogger.info('Analytics and audit log tools added successfully');
}

export default addAnalyticsTools;