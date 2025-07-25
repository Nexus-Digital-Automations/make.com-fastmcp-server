/**
 * Custom Variable Management Tools for Make.com FastMCP Server
 * Comprehensive tools for managing custom variables at organization, team, and scenario levels
 */

import { FastMCP, UserError } from 'fastmcp';
import { z } from 'zod';
import MakeApiClient from '../lib/make-api-client.js';
import { MakeVariable, MakeIncompleteExecution } from '../types/index.js';
import logger from '../lib/logger.js';

// Extended variable types for comprehensive management
export interface MakeCustomVariable extends MakeVariable {
  organizationId?: number;
  teamId?: number;
  scenarioId?: number;
  description?: string;
  tags?: string[];
  lastModified: string;
  modifiedBy: number;
  version: number;
}

// Input validation schemas
const VariableCreateSchema = z.object({
  name: z.string().min(1).max(100).describe('Variable name (1-100 characters)'),
  value: z.any().describe('Variable value (string, number, boolean, or JSON object)'),
  type: z.enum(['string', 'number', 'boolean', 'json']).describe('Variable data type'),
  scope: z.enum(['organization', 'team', 'scenario']).describe('Variable scope level'),
  organizationId: z.number().min(1).optional().describe('Organization ID (required for organization scope)'),
  teamId: z.number().min(1).optional().describe('Team ID (required for team/scenario scope)'),
  scenarioId: z.number().min(1).optional().describe('Scenario ID (required for scenario scope)'),
  description: z.string().max(500).optional().describe('Variable description (max 500 characters)'),
  tags: z.array(z.string()).default([]).describe('Variable tags for organization'),
  isEncrypted: z.boolean().default(false).describe('Whether to encrypt variable value'),
}).strict();

const VariableUpdateSchema = z.object({
  variableId: z.number().min(1).describe('Variable ID to update'),
  name: z.string().min(1).max(100).optional().describe('New variable name'),
  value: z.any().optional().describe('New variable value'),
  type: z.enum(['string', 'number', 'boolean', 'json']).optional().describe('New variable data type'),
  description: z.string().max(500).optional().describe('New variable description'),
  tags: z.array(z.string()).optional().describe('New variable tags'),
  isEncrypted: z.boolean().optional().describe('Update encryption setting'),
}).strict();

const VariableListSchema = z.object({
  scope: z.enum(['organization', 'team', 'scenario', 'all']).default('all').describe('Filter by variable scope'),
  organizationId: z.number().min(1).optional().describe('Filter by organization ID'),
  teamId: z.number().min(1).optional().describe('Filter by team ID'),
  scenarioId: z.number().min(1).optional().describe('Filter by scenario ID'),
  namePattern: z.string().optional().describe('Filter by name pattern (supports wildcards)'),
  tags: z.array(z.string()).optional().describe('Filter by tags (AND operation)'),
  type: z.enum(['string', 'number', 'boolean', 'json']).optional().describe('Filter by variable type'),
  isEncrypted: z.boolean().optional().describe('Filter by encryption status'),
  limit: z.number().min(1).max(1000).default(100).describe('Maximum number of variables to return'),
  offset: z.number().min(0).default(0).describe('Number of variables to skip for pagination'),
  sortBy: z.enum(['name', 'createdAt', 'lastModified', 'scope']).default('name').describe('Sort field'),
  sortOrder: z.enum(['asc', 'desc']).default('asc').describe('Sort order'),
}).strict();

const VariableBulkOperationSchema = z.object({
  operation: z.enum(['delete', 'update_tags', 'change_scope', 'bulk_encrypt']).describe('Bulk operation type'),
  variableIds: z.array(z.number().min(1)).min(1).max(100).describe('Array of variable IDs (max 100)'),
  operationData: z.record(z.any()).optional().describe('Operation-specific data'),
}).strict();

const VariableExportSchema = z.object({
  scope: z.enum(['organization', 'team', 'scenario', 'all']).default('all').describe('Export scope'),
  organizationId: z.number().min(1).optional().describe('Organization ID for scoped export'),
  teamId: z.number().min(1).optional().describe('Team ID for scoped export'),
  scenarioId: z.number().min(1).optional().describe('Scenario ID for scoped export'),
  format: z.enum(['json', 'csv', 'env']).default('json').describe('Export format'),
  includeEncrypted: z.boolean().default(false).describe('Include encrypted variables (values will be masked)'),
  includeMetadata: z.boolean().default(true).describe('Include metadata (tags, description, etc.)'),
}).strict();

/**
 * Validate variable scope consistency
 */
function validateVariableScope(input: Record<string, unknown>): void {
  const { scope, organizationId, teamId, scenarioId } = input;
  
  if (scope === 'organization' && !organizationId) {
    throw new UserError('Organization ID is required for organization scope variables');
  }
  
  if (scope === 'team' && (!organizationId || !teamId)) {
    throw new UserError('Organization ID and Team ID are required for team scope variables');
  }
  
  if (scope === 'scenario' && (!organizationId || !teamId || !scenarioId)) {
    throw new UserError('Organization ID, Team ID, and Scenario ID are required for scenario scope variables');
  }
}

/**
 * Format variable value based on type
 */
function formatVariableValue(value: unknown, type: string): unknown {
  switch (type) {
    case 'string':
      return String(value);
    case 'number': {
      const num = Number(value);
      if (isNaN(num)) {
        throw new UserError(`Invalid number value: ${value}`);
      }
      return num;
    }
    case 'boolean':
      if (typeof value === 'boolean') return value;
      if (typeof value === 'string') {
        const lower = value.toLowerCase();
        if (lower === 'true' || lower === '1') return true;
        if (lower === 'false' || lower === '0') return false;
      }
      throw new UserError(`Invalid boolean value: ${value}`);
    case 'json':
      if (typeof value === 'object') return value;
      if (typeof value === 'string') {
        try {
          return JSON.parse(value);
        } catch {
          throw new UserError(`Invalid JSON value: ${value}`);
        }
      }
      throw new UserError(`Invalid JSON value: ${value}`);
    default:
      return value;
  }
}

/**
 * Add custom variable management tools to FastMCP server
 */
export function addVariableTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'VariableTools' });
  
  componentLogger.info('Adding custom variable management tools');

  // Create custom variable
  server.addTool({
    name: 'create-custom-variable',
    description: 'Create a new custom variable at organization, team, or scenario level',
    parameters: VariableCreateSchema,
    execute: async (input, { log }) => {
      const { name, value, type, scope, organizationId, teamId, scenarioId, description, tags, isEncrypted } = input;

      log.info('Creating custom variable', {
        name,
        type,
        scope,
        organizationId,
        teamId,
        scenarioId,
        isEncrypted,
      });

      try {
        // Validate scope consistency
        validateVariableScope(input);

        // Format value according to type
        const formattedValue = formatVariableValue(value, type);

        const variableData = {
          name,
          value: formattedValue,
          type,
          scope,
          description,
          tags,
          isEncrypted,
          ...(organizationId && { organizationId }),
          ...(teamId && { teamId }),
          ...(scenarioId && { scenarioId }),
        };

        // Determine API endpoint based on scope
        let endpoint = '/variables';
        if (scope === 'organization' && organizationId) {
          endpoint = `/organizations/${organizationId}/variables`;
        } else if (scope === 'team' && teamId) {
          endpoint = `/teams/${teamId}/variables`;
        } else if (scope === 'scenario' && scenarioId) {
          endpoint = `/scenarios/${scenarioId}/variables`;
        }

        const response = await apiClient.post(endpoint, variableData);

        if (!response.success) {
          throw new UserError(`Failed to create variable: ${response.error?.message || 'Unknown error'}`);
        }

        const variable = response.data as MakeCustomVariable;
        if (!variable) {
          throw new UserError('Variable creation failed - no data returned');
        }

        log.info('Successfully created custom variable', {
          variableId: variable.id,
          name: variable.name,
          scope: variable.scope,
        });

        return JSON.stringify({
          variable,
          message: `Custom variable "${name}" created successfully`,
          warning: isEncrypted ? 'Variable value is encrypted and cannot be retrieved in plain text' : undefined,
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error creating custom variable', { name, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to create custom variable: ${errorMessage}`);
      }
    },
  });

  // List custom variables
  server.addTool({
    name: 'list-custom-variables',
    description: 'List and filter custom variables with comprehensive search capabilities',
    parameters: VariableListSchema,
    execute: async (input, { log }) => {
      const { scope, organizationId, teamId, scenarioId, namePattern, tags, type, isEncrypted, limit, offset, sortBy, sortOrder } = input;

      log.info('Listing custom variables', {
        scope,
        organizationId,
        teamId,
        scenarioId,
        limit,
        offset,
      });

      try {
        const params: Record<string, unknown> = {
          limit,
          offset,
          sortBy,
          sortOrder,
        };

        if (scope !== 'all') params.scope = scope;
        if (organizationId) params.organizationId = organizationId;
        if (teamId) params.teamId = teamId;
        if (scenarioId) params.scenarioId = scenarioId;
        if (namePattern) params.namePattern = namePattern;
        if (tags && tags.length > 0) params.tags = tags.join(',');
        if (type) params.type = type;
        if (isEncrypted !== undefined) params.isEncrypted = isEncrypted;

        let endpoint = '/variables';
        if (scope === 'organization' && organizationId) {
          endpoint = `/organizations/${organizationId}/variables`;
        } else if (scope === 'team' && teamId) {
          endpoint = `/teams/${teamId}/variables`;
        } else if (scope === 'scenario' && scenarioId) {
          endpoint = `/scenarios/${scenarioId}/variables`;
        }

        const response = await apiClient.get(endpoint, { params });

        if (!response.success) {
          throw new UserError(`Failed to list variables: ${response.error?.message || 'Unknown error'}`);
        }

        const variables = response.data as MakeCustomVariable[] || [];
        const metadata = response.metadata;

        log.info('Successfully retrieved custom variables', {
          count: variables.length,
          total: metadata?.total,
        });

        // Create summary statistics
        const summary = {
          totalVariables: metadata?.total || variables.length,
          scopeBreakdown: {
            organization: variables.filter(v => v.scope === 'global').length,
            team: variables.filter(v => v.scope === 'team').length,
            scenario: variables.filter(v => v.scope === 'scenario').length,
          },
          typeBreakdown: {
            string: variables.filter(v => v.type === 'string').length,
            number: variables.filter(v => v.type === 'number').length,
            boolean: variables.filter(v => v.type === 'boolean').length,
            json: variables.filter(v => v.type === 'json').length,
          },
          encryptedCount: variables.filter(v => v.isEncrypted).length,
          uniqueTags: [...new Set(variables.flatMap(v => (v as MakeCustomVariable).tags || []))],
        };

        return JSON.stringify({
          variables: variables.map(v => ({
            ...v,
            value: v.isEncrypted ? '[ENCRYPTED]' : v.value,
          })),
          summary,
          pagination: {
            total: metadata?.total || variables.length,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + variables.length),
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error listing custom variables', { error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to list custom variables: ${errorMessage}`);
      }
    },
  });

  // Get custom variable details
  server.addTool({
    name: 'get-custom-variable',
    description: 'Get detailed information about a specific custom variable',
    parameters: z.object({
      variableId: z.number().min(1).describe('Variable ID to retrieve'),
      includeUsage: z.boolean().default(false).describe('Include usage statistics'),
    }),
    execute: async (input, { log }) => {
      const { variableId, includeUsage } = input;

      log.info('Getting custom variable details', { variableId });

      try {
        const response = await apiClient.get(`/variables/${variableId}`);

        if (!response.success) {
          throw new UserError(`Failed to get variable: ${response.error?.message || 'Unknown error'}`);
        }

        const variable = response.data as MakeCustomVariable;
        if (!variable) {
          throw new UserError(`Variable with ID ${variableId} not found`);
        }

        let usage = null;
        if (includeUsage) {
          try {
            const usageResponse = await apiClient.get(`/variables/${variableId}/usage`);
            if (usageResponse.success) {
              usage = usageResponse.data;
            }
          } catch (error) {
            log.warn('Failed to retrieve variable usage statistics', { variableId });
          }
        }

        log.info('Successfully retrieved custom variable', {
          variableId,
          name: variable.name,
          scope: variable.scope,
          type: variable.type,
        });

        return JSON.stringify({
          variable: {
            ...variable,
            value: variable.isEncrypted ? '[ENCRYPTED]' : variable.value,
          },
          usage,
          metadata: {
            canEdit: true, // This would be determined by user permissions
            canDelete: variable.scope !== 'organization', // Example business rule
            lastAccessed: usage?.lastAccessed,
            accessCount: usage?.accessCount || 0,
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error getting custom variable', { variableId, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to get custom variable details: ${errorMessage}`);
      }
    },
  });

  // Update custom variable
  server.addTool({
    name: 'update-custom-variable',
    description: 'Update an existing custom variable',
    parameters: VariableUpdateSchema,
    execute: async (input, { log }) => {
      const { variableId, name, value, type, description, tags, isEncrypted } = input;

      log.info('Updating custom variable', { variableId, name });

      try {
        const updateData: Record<string, unknown> = {};

        if (name !== undefined) updateData.name = name;
        if (value !== undefined && type !== undefined) {
          updateData.value = formatVariableValue(value, type);
          updateData.type = type;
        } else if (value !== undefined) {
          // Get current variable to determine type
          const currentResponse = await apiClient.get(`/variables/${variableId}`);
          if (!currentResponse.success) {
            throw new UserError('Failed to retrieve current variable for type validation');
          }
          const currentVariable = currentResponse.data as MakeCustomVariable;
          updateData.value = formatVariableValue(value, currentVariable.type);
        } else if (type !== undefined) {
          updateData.type = type;
        }

        if (description !== undefined) updateData.description = description;
        if (tags !== undefined) updateData.tags = tags;
        if (isEncrypted !== undefined) updateData.isEncrypted = isEncrypted;

        if (Object.keys(updateData).length === 0) {
          throw new UserError('No update data provided');
        }

        const response = await apiClient.put(`/variables/${variableId}`, updateData);

        if (!response.success) {
          throw new UserError(`Failed to update variable: ${response.error?.message || 'Unknown error'}`);
        }

        const updatedVariable = response.data as MakeCustomVariable;

        log.info('Successfully updated custom variable', {
          variableId,
          name: updatedVariable.name,
          changes: Object.keys(updateData),
        });

        return JSON.stringify({
          variable: {
            ...updatedVariable,
            value: updatedVariable.isEncrypted ? '[ENCRYPTED]' : updatedVariable.value,
          },
          message: `Variable "${updatedVariable.name}" updated successfully`,
          changes: Object.keys(updateData),
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error updating custom variable', { variableId, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to update custom variable: ${errorMessage}`);
      }
    },
  });

  // Delete custom variable
  server.addTool({
    name: 'delete-custom-variable',
    description: 'Delete a custom variable',
    parameters: z.object({
      variableId: z.number().min(1).describe('Variable ID to delete'),
      force: z.boolean().default(false).describe('Force delete even if variable is in use'),
    }),
    execute: async (input, { log }) => {
      const { variableId, force } = input;

      log.info('Deleting custom variable', { variableId, force });

      try {
        // Check if variable is in use (unless force delete)
        if (!force) {
          const usageResponse = await apiClient.get(`/variables/${variableId}/usage`);
          if (usageResponse.success && usageResponse.data?.usageCount > 0) {
            throw new UserError(`Variable is currently in use (${usageResponse.data.usageCount} references). Use force=true to delete anyway.`);
          }
        }

        const response = await apiClient.delete(`/variables/${variableId}`);

        if (!response.success) {
          throw new UserError(`Failed to delete variable: ${response.error?.message || 'Unknown error'}`);
        }

        log.info('Successfully deleted custom variable', { variableId });

        return JSON.stringify({
          message: `Variable ${variableId} deleted successfully`,
          variableId,
          forced: force,
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error deleting custom variable', { variableId, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to delete custom variable: ${errorMessage}`);
      }
    },
  });

  // Bulk operations on variables
  server.addTool({
    name: 'bulk-variable-operations',
    description: 'Perform bulk operations on multiple custom variables',
    parameters: VariableBulkOperationSchema,
    execute: async (input, { log }) => {
      const { operation, variableIds, operationData } = input;

      log.info('Performing bulk variable operation', {
        operation,
        variableCount: variableIds.length,
      });

      try {
        const bulkData = {
          operation,
          variableIds,
          operationData: operationData || {},
        };

        const response = await apiClient.post('/variables/bulk', bulkData);

        if (!response.success) {
          throw new UserError(`Failed to perform bulk operation: ${response.error?.message || 'Unknown error'}`);
        }

        const result = response.data;

        log.info('Successfully completed bulk variable operation', {
          operation,
          affected: result?.affected || variableIds.length,
          failed: result?.failed || 0,
        });

        return JSON.stringify({
          result,
          message: `Bulk ${operation} completed successfully`,
          summary: {
            requested: variableIds.length,
            successful: result?.affected || 0,
            failed: result?.failed || 0,
            errors: result?.errors || [],
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error performing bulk variable operation', { operation, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to perform bulk variable operation: ${errorMessage}`);
      }
    },
  });

  // Export variables
  server.addTool({
    name: 'export-custom-variables',
    description: 'Export custom variables in various formats for backup or migration',
    parameters: VariableExportSchema,
    execute: async (input, { log }) => {
      const { scope, organizationId, teamId, scenarioId, format, includeEncrypted, includeMetadata } = input;

      log.info('Exporting custom variables', {
        scope,
        format,
        includeEncrypted,
        includeMetadata,
      });

      try {
        const exportData = {
          scope,
          format,
          includeEncrypted,
          includeMetadata,
          ...(organizationId && { organizationId }),
          ...(teamId && { teamId }),
          ...(scenarioId && { scenarioId }),
        };

        const response = await apiClient.post('/variables/export', exportData);

        if (!response.success) {
          throw new UserError(`Failed to export variables: ${response.error?.message || 'Unknown error'}`);
        }

        const exportResult = response.data;

        log.info('Successfully exported custom variables', {
          format,
          variableCount: exportResult?.count,
          exportId: exportResult?.exportId,
        });

        return JSON.stringify({
          exportResult,
          message: `Variables exported successfully in ${format} format`,
          download: {
            url: exportResult?.downloadUrl,
            expiresAt: exportResult?.expiresAt,
            filename: exportResult?.filename,
          },
          summary: {
            totalVariables: exportResult?.count || 0,
            encryptedVariables: exportResult?.encryptedCount || 0,
            format: format,
            includeMetadata,
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error exporting custom variables', { scope, format, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to export custom variables: ${errorMessage}`);
      }
    },
  });

  // Test variable resolution
  server.addTool({
    name: 'test-variable-resolution',
    description: 'Test variable resolution and scope inheritance for debugging',
    parameters: z.object({
      variableName: z.string().min(1).describe('Variable name to test resolution for'),
      context: z.object({
        organizationId: z.number().min(1).optional(),
        teamId: z.number().min(1).optional(),
        scenarioId: z.number().min(1).optional(),
      }).describe('Context for variable resolution'),
      includeInheritance: z.boolean().default(true).describe('Show inheritance chain'),
    }),
    execute: async (input, { log }) => {
      const { variableName, context, includeInheritance } = input;

      log.info('Testing variable resolution', {
        variableName,
        context,
      });

      try {
        const testData = {
          variableName,
          context,
          includeInheritance,
        };

        const response = await apiClient.post('/variables/test-resolution', testData);

        if (!response.success) {
          throw new UserError(`Failed to test variable resolution: ${response.error?.message || 'Unknown error'}`);
        }

        const result = response.data;

        log.info('Successfully tested variable resolution', {
          variableName,
          resolved: !!result?.resolvedVariable,
          scope: result?.resolvedVariable?.scope,
        });

        return JSON.stringify({
          resolution: result,
          summary: {
            variableName,
            context,
            resolved: !!result?.resolvedVariable,
            resolvedScope: result?.resolvedVariable?.scope,
            value: result?.resolvedVariable?.isEncrypted ? '[ENCRYPTED]' : result?.resolvedVariable?.value,
            inheritanceChain: result?.inheritanceChain || [],
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error testing variable resolution', { variableName, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to test variable resolution: ${errorMessage}`);
      }
    },
  });

  // Incomplete execution recovery tools
  
  // List incomplete executions with recovery options
  server.addTool({
    name: 'list-incomplete-executions-with-recovery',
    description: 'List incomplete executions with detailed recovery analysis and options',
    parameters: z.object({
      scenarioId: z.number().min(1).optional().describe('Filter by scenario ID'),
      organizationId: z.number().min(1).optional().describe('Filter by organization ID'),
      teamId: z.number().min(1).optional().describe('Filter by team ID'),
      status: z.enum(['waiting', 'paused', 'failed', 'all']).default('all').describe('Filter by status'),
      ageHours: z.number().min(0).optional().describe('Filter by execution age in hours'),
      canResume: z.boolean().optional().describe('Filter by resumable status'),
      includeRecoveryPlan: z.boolean().default(true).describe('Include recovery recommendations'),
      limit: z.number().min(1).max(100).default(20).describe('Maximum number of executions to return'),
      offset: z.number().min(0).default(0).describe('Number of executions to skip for pagination'),
    }),
    execute: async (input, { log }) => {
      const { scenarioId, organizationId, teamId, status, ageHours, canResume, includeRecoveryPlan, limit, offset } = input;

      log.info('Listing incomplete executions with recovery options', {
        scenarioId,
        organizationId,
        teamId,
        status,
        includeRecoveryPlan,
      });

      try {
        const params: Record<string, unknown> = {
          limit,
          offset,
          includeRecoveryPlan,
        };

        if (scenarioId) params.scenarioId = scenarioId;
        if (organizationId) params.organizationId = organizationId;
        if (teamId) params.teamId = teamId;
        if (status !== 'all') params.status = status;
        if (ageHours !== undefined) params.ageHours = ageHours;
        if (canResume !== undefined) params.canResume = canResume;

        const response = await apiClient.get('/incomplete-executions', { params });

        if (!response.success) {
          throw new UserError(`Failed to list incomplete executions: ${response.error?.message || 'Unknown error'}`);
        }

        const incompleteExecutions = response.data as MakeIncompleteExecution[] || [];
        const metadata = response.metadata;

        // Generate recovery analysis for each execution
        const executionsWithRecovery = await Promise.all(
          incompleteExecutions.map(async (execution) => {
            let recoveryPlan = null;
            
            if (includeRecoveryPlan) {
              try {
                const recoveryResponse = await apiClient.get(`/incomplete-executions/${execution.id}/recovery-analysis`);
                if (recoveryResponse.success) {
                  recoveryPlan = recoveryResponse.data;
                }
              } catch (error) {
                log.warn('Failed to get recovery plan', { executionId: execution.id });
              }
            }

            return {
              ...execution,
              recoveryPlan,
              age: Math.floor((Date.now() - new Date(execution.stoppedAt).getTime()) / (1000 * 60 * 60)), // hours
              priority: execution.operations > 1000 ? 'high' : execution.operations > 100 ? 'medium' : 'low',
            };
          })
        );

        const summary = {
          totalIncomplete: metadata?.total || incompleteExecutions.length,
          statusBreakdown: {
            waiting: incompleteExecutions.filter(exec => exec.status === 'waiting').length,
            paused: incompleteExecutions.filter(exec => exec.status === 'paused').length,
            failed: incompleteExecutions.filter(exec => exec.status === 'failed').length,
          },
          recoveryBreakdown: {
            canResume: incompleteExecutions.filter(exec => exec.canResume).length,
            requiresIntervention: incompleteExecutions.filter(exec => !exec.canResume).length,
          },
          impactAnalysis: {
            totalOperationsAffected: incompleteExecutions.reduce((sum, exec) => sum + exec.operations, 0),
            totalDataTransferAffected: incompleteExecutions.reduce((sum, exec) => sum + exec.dataTransfer, 0),
            uniqueScenarios: [...new Set(incompleteExecutions.map(exec => exec.scenarioId))].length,
            oldestExecution: incompleteExecutions.length > 0 ? 
              Math.max(...incompleteExecutions.map(exec => 
                Math.floor((Date.now() - new Date(exec.stoppedAt).getTime()) / (1000 * 60 * 60))
              )) : 0,
          },
        };

        log.info('Successfully retrieved incomplete executions with recovery plans', {
          count: incompleteExecutions.length,
          resumable: summary.recoveryBreakdown.canResume,
        });

        return JSON.stringify({
          incompleteExecutions: executionsWithRecovery,
          summary,
          pagination: {
            total: metadata?.total || incompleteExecutions.length,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + incompleteExecutions.length),
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error listing incomplete executions', { error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to list incomplete executions with recovery: ${errorMessage}`);
      }
    },
  });

  // Bulk resolve incomplete executions
  server.addTool({
    name: 'bulk-resolve-incomplete-executions',
    description: 'Resolve multiple incomplete executions with batch operations',
    parameters: z.object({
      executionIds: z.array(z.number().min(1)).min(1).max(50).describe('Array of execution IDs to resolve (max 50)'),
      action: z.enum(['retry', 'skip', 'cancel', 'auto']).describe('Action to take (auto will choose best action per execution)'),
      options: z.object({
        retryWithModifications: z.boolean().default(false).describe('Apply modifications before retry'),
        skipFailedModules: z.boolean().default(false).describe('Skip failed modules during retry'),
        preserveState: z.boolean().default(true).describe('Preserve execution state where possible'),
        notifyOnCompletion: z.boolean().default(false).describe('Send notification when batch completes'),
      }).default({}).describe('Bulk operation options'),
      reason: z.string().max(500).optional().describe('Reason for bulk resolution'),
    }),
    execute: async (input, { log, reportProgress }) => {
      const { executionIds, action, options, reason } = input;

      log.info('Bulk resolving incomplete executions', {
        count: executionIds.length,
        action,
        options,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        const bulkData = {
          executionIds,
          action,
          options: {
            ...options,
            retryWithModifications: options?.retryWithModifications ?? false,
            skipFailedModules: options?.skipFailedModules ?? false,
            preserveState: options?.preserveState ?? true,
            notifyOnCompletion: options?.notifyOnCompletion ?? false,
          },
          reason,
          timestamp: new Date().toISOString(),
        };

        reportProgress({ progress: 25, total: 100 });

        const response = await apiClient.post('/incomplete-executions/bulk-resolve', bulkData);

        if (!response.success) {
          throw new UserError(`Failed to bulk resolve executions: ${response.error?.message || 'Unknown error'}`);
        }

        const result = response.data;
        reportProgress({ progress: 75, total: 100 });

        // Get updated status for resolved executions
        const statusUpdates = await Promise.all(
          executionIds.slice(0, 10).map(async (id) => { // Limit to first 10 for performance
            try {
              const statusResponse = await apiClient.get(`/executions/${id}/status`);
              return {
                executionId: id,
                newStatus: statusResponse.success ? statusResponse.data?.status : 'unknown',
              };
            } catch (error) {
              return { executionId: id, newStatus: 'error' };
            }
          })
        );

        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully completed bulk resolve operation', {
          requested: executionIds.length,
          successful: result?.successful || 0,
          failed: result?.failed || 0,
        });

        return JSON.stringify({
          result,
          statusUpdates,
          summary: {
            requestedCount: executionIds.length,
            successfulResolutions: result?.successful || 0,
            failedResolutions: result?.failed || 0,
            action: action,
            batchId: result?.batchId,
            estimatedCompletionTime: result?.estimatedCompletionTime,
          },
          message: `Bulk resolution initiated for ${executionIds.length} executions`,
          errors: result?.errors || [],
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error in bulk resolve operation', { error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to bulk resolve incomplete executions: ${errorMessage}`);
      }
    },
  });

  // Analyze execution failure patterns
  server.addTool({
    name: 'analyze-execution-failure-patterns',
    description: 'Analyze patterns in incomplete executions to identify systemic issues',
    parameters: z.object({
      organizationId: z.number().min(1).optional().describe('Analyze for specific organization'),
      teamId: z.number().min(1).optional().describe('Analyze for specific team'),
      timeRange: z.object({
        startDate: z.string().describe('Analysis start date (ISO format)'),
        endDate: z.string().describe('Analysis end date (ISO format)'),
      }).describe('Time range for analysis'),
      includeRecommendations: z.boolean().default(true).describe('Include improvement recommendations'),
      groupBy: z.enum(['scenario', 'module', 'error_type', 'time']).default('scenario').describe('How to group failure analysis'),
    }),
    execute: async (input, { log, reportProgress }) => {
      const { organizationId, teamId, timeRange, includeRecommendations, groupBy } = input;

      log.info('Analyzing execution failure patterns', {
        organizationId,
        teamId,
        timeRange,
        groupBy,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        const analysisData = {
          organizationId,
          teamId,
          timeRange,
          groupBy,
          includeRecommendations,
        };

        reportProgress({ progress: 25, total: 100 });

        const response = await apiClient.post('/incomplete-executions/failure-analysis', analysisData);

        if (!response.success) {
          throw new UserError(`Failed to analyze failure patterns: ${response.error?.message || 'Unknown error'}`);
        }

        const analysis = response.data;
        reportProgress({ progress: 75, total: 100 });

        // Generate additional insights
        const insights = {
          totalFailures: analysis?.totalFailures || 0,
          failureRate: analysis?.failureRate || 0,
          mostCommonErrors: analysis?.topErrors?.slice(0, 5) || [],
          mostAffectedScenarios: analysis?.topScenarios?.slice(0, 5) || [],
          timePatterns: analysis?.timePatterns || {},
          recoverySuccess: analysis?.recoveryStats?.successRate || 0,
          operationalImpact: {
            operationsLost: analysis?.operationsLost || 0,
            dataTransferLost: analysis?.dataTransferLost || 0,
            estimatedCost: analysis?.estimatedCost || 0,
          },
        };

        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully completed failure pattern analysis', {
          totalFailures: insights.totalFailures,
          failureRate: insights.failureRate,
          analysisTimeRange: timeRange,
        });

        return JSON.stringify({
          analysis,
          insights,
          recommendations: includeRecommendations ? analysis?.recommendations || [] : undefined,
          summary: {
            analysisTimeRange: timeRange,
            groupBy,
            totalFailures: insights.totalFailures,
            failureRate: `${(insights.failureRate * 100).toFixed(2)}%`,
            topIssue: insights.mostCommonErrors[0]?.error || 'No dominant error pattern',
            actionableRecommendations: analysis?.recommendations?.filter((r: { priority: string }) => r.priority === 'high').length || 0,
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error analyzing failure patterns', { error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to analyze execution failure patterns: ${errorMessage}`);
      }
    },
  });

  // Create recovery automation rules
  server.addTool({
    name: 'create-recovery-automation-rule',
    description: 'Create automated recovery rules for common failure scenarios',
    parameters: z.object({
      name: z.string().min(1).max(100).describe('Rule name'),
      description: z.string().max(500).optional().describe('Rule description'),
      conditions: z.object({
        errorPatterns: z.array(z.string()).optional().describe('Error message patterns to match'),
        scenarioIds: z.array(z.number().min(1)).optional().describe('Specific scenario IDs'),
        moduleTypes: z.array(z.string()).optional().describe('Module types to target'),
        maxAge: z.number().min(0).optional().describe('Maximum execution age in hours'),
        minOperations: z.number().min(0).optional().describe('Minimum operations threshold'),
      }).describe('Conditions that trigger the rule'),
      actions: z.object({
        primaryAction: z.enum(['retry', 'skip', 'cancel', 'notify']).describe('Primary recovery action'),
        retryConfig: z.object({
          maxRetries: z.number().min(1).max(5).default(3),
          delayMinutes: z.number().min(0).max(1440).default(5),
          modifyOnRetry: z.boolean().default(false),
        }).optional().describe('Retry configuration'),
        notificationConfig: z.object({
          recipients: z.array(z.string()).describe('Notification recipients'),
          severity: z.enum(['low', 'medium', 'high']).default('medium'),
          includeContext: z.boolean().default(true),
        }).optional().describe('Notification configuration'),
      }).describe('Actions to take when conditions are met'),
      isActive: z.boolean().default(true).describe('Whether rule is active'),
      priority: z.number().min(1).max(100).default(50).describe('Rule priority (1-100, higher = more priority)'),
    }),
    execute: async (input, { log }) => {
      const { name, description, conditions, actions, isActive, priority } = input;

      log.info('Creating recovery automation rule', { name, isActive, priority });

      try {
        const ruleData = {
          name,
          description,
          conditions,
          actions,
          isActive,
          priority,
          createdAt: new Date().toISOString(),
        };

        const response = await apiClient.post('/recovery-automation-rules', ruleData);

        if (!response.success) {
          throw new UserError(`Failed to create recovery rule: ${response.error?.message || 'Unknown error'}`);
        }

        const rule = response.data;

        log.info('Successfully created recovery automation rule', {
          ruleId: rule?.id,
          name,
          primaryAction: actions.primaryAction,
        });

        return JSON.stringify({
          rule,
          message: `Recovery automation rule "${name}" created successfully`,
          summary: {
            ruleId: rule?.id,
            name,
            primaryAction: actions.primaryAction,
            isActive,
            priority,
            conditionCount: Object.keys(conditions).length,
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error creating recovery automation rule', { name, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to create recovery automation rule: ${errorMessage}`);
      }
    },
  });

  componentLogger.info('Custom variable management and incomplete execution recovery tools added successfully');
}

export default addVariableTools;