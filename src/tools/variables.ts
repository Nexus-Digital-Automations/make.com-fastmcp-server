/**
 * Custom Variable Management Tools for Make.com FastMCP Server
 * Comprehensive tools for managing custom variables at organization, team, and scenario levels
 */

import { FastMCP, UserError } from 'fastmcp';
import { z } from 'zod';
import MakeApiClient from '../lib/make-api-client.js';
import { MakeVariable, MakeIncompleteExecution } from '../types/index.js';
import logger from '../lib/logger.js';
import { formatSuccessResponse } from '../utils/response-formatter.js';

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
  operationData: z.record(z.string(), z.any()).optional().describe('Operation-specific data'),
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
      if (typeof value === 'boolean') {return value;}
      if (typeof value === 'string') {
        const lower = value.toLowerCase();
        if (lower === 'true' || lower === '1') {return true;}
        if (lower === 'false' || lower === '0') {return false;}
      }
      throw new UserError(`Invalid boolean value: ${value}`);
    case 'json':
      if (typeof value === 'object') {return value;}
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
 * Add create custom variable tool
 */
function addCreateCustomVariableTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'create-custom-variable',
    description: 'Create a new custom variable at organization, team, or scenario level',
    parameters: VariableCreateSchema,
    annotations: {
      title: 'Create Custom Variable',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
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

        return formatSuccessResponse({
          variable,
          message: `Custom variable "${name}" created successfully`,
          warning: isEncrypted ? 'Variable value is encrypted and cannot be retrieved in plain text' : undefined,
        }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error creating custom variable', { name, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to create custom variable: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add custom variable management tools to FastMCP server
 */
export function addVariableTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'VariableTools' });
  
  componentLogger.info('Adding custom variable management tools');

  // Add core variable tools
  addCreateCustomVariableTool(server, apiClient);
  addListCustomVariablesTool(server, apiClient);
  addGetCustomVariableTool(server, apiClient);
  addUpdateCustomVariableTool(server, apiClient);
  addDeleteCustomVariableTool(server, apiClient);
  addBulkVariableOperationsTool(server, apiClient);
  addExportCustomVariablesTool(server, apiClient);
  addTestVariableResolutionTool(server, apiClient);
  
  // Add execution recovery tools
  addListIncompleteExecutionsTool(server, apiClient);
  addBulkResolveIncompleteExecutionsTool(server, apiClient);
  addAnalyzeExecutionFailurePatternsTool(server, apiClient);
  addCreateRecoveryAutomationRuleTool(server, apiClient);
  
  componentLogger.info('Custom variable management and incomplete execution recovery tools added successfully');
}

/**
 * Build API parameters for variable list request
 */
function buildVariableListParams(input: Record<string, unknown>): Record<string, unknown> {
  const { scope, organizationId, teamId, scenarioId, namePattern, tags, type, isEncrypted, limit, offset, sortBy, sortOrder } = input;
  
  const params: Record<string, unknown> = {
    limit,
    offset,
    sortBy,
    sortOrder,
  };

  if (scope !== 'all') {params.scope = scope;}
  if (organizationId) {params.organizationId = organizationId;}
  if (teamId) {params.teamId = teamId;}
  if (scenarioId) {params.scenarioId = scenarioId;}
  if (namePattern) {params.namePattern = namePattern;}
  if (tags && Array.isArray(tags) && tags.length > 0) {params.tags = tags.join(',');}
  if (type) {params.type = type;}
  if (isEncrypted !== undefined) {params.isEncrypted = isEncrypted;}

  return params;
}

/**
 * Determine API endpoint based on scope and IDs
 */
function getVariableListEndpoint(scope: string, organizationId?: number, teamId?: number, scenarioId?: number): string {
  if (scope === 'organization' && organizationId) {
    return `/organizations/${organizationId}/variables`;
  }
  if (scope === 'team' && teamId) {
    return `/teams/${teamId}/variables`;
  }
  if (scope === 'scenario' && scenarioId) {
    return `/scenarios/${scenarioId}/variables`;
  }
  return '/variables';
}

/**
 * Create summary statistics for variable list response
 */
function createVariableListSummary(variables: MakeCustomVariable[], metadata?: Record<string, unknown>): Record<string, unknown> {
  return {
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
    uniqueTags: Array.from(new Set(variables.flatMap(v => v.tags || []))),
  };
}

/**
 * Format variables response with encrypted value masking
 */
function formatVariablesResponse(
  variables: MakeCustomVariable[],
  summary: Record<string, unknown>,
  metadata?: Record<string, unknown>,
  limit?: number,
  offset?: number
): Record<string, unknown> {
  return {
    variables: variables.map(v => ({
      ...v,
      value: v.isEncrypted ? '[ENCRYPTED]' : v.value,
    })),
    summary,
    pagination: {
      total: metadata?.total || variables.length,
      limit,
      offset,
      hasMore: (typeof metadata?.total === 'number' ? metadata.total : 0) > ((offset || 0) + variables.length),
    },
  };
}

/**
 * Add list custom variables tool
 */
function addListCustomVariablesTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'list-custom-variables',
    description: 'List and filter custom variables with comprehensive search capabilities',
    parameters: VariableListSchema,
    annotations: {
      title: 'List Custom Variables',
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { scope, organizationId, teamId, scenarioId, limit, offset } = input;

      log.info('Listing custom variables', {
        scope,
        organizationId,
        teamId,
        scenarioId,
        limit,
        offset,
      });

      try {
        const params = buildVariableListParams(input);
        const endpoint = getVariableListEndpoint(scope as string, organizationId, teamId, scenarioId);

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

        const summary = createVariableListSummary(variables, metadata);
        const formattedResponse = formatVariablesResponse(variables, summary, metadata, limit, offset);

        return formatSuccessResponse(formattedResponse);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error listing custom variables', { error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to list custom variables: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add get custom variable tool
 */
function addGetCustomVariableTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'get-custom-variable',
    description: 'Get detailed information about a specific custom variable',
    parameters: z.object({
      variableId: z.number().min(1).describe('Variable ID to retrieve'),
      includeUsage: z.boolean().default(false).describe('Include usage statistics'),
    }),
    annotations: {
      title: 'Get Custom Variable Details',
      readOnlyHint: true,
      openWorldHint: true,
    },
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

        let usage: Record<string, unknown> | null = null;
        if (includeUsage) {
          try {
            const usageResponse = await apiClient.get(`/variables/${variableId}/usage`);
            if (usageResponse.success) {
              usage = usageResponse.data as Record<string, unknown>;
            }
          } catch {
            log.warn('Failed to retrieve variable usage statistics', { variableId });
          }
        }

        log.info('Successfully retrieved custom variable', {
          variableId,
          name: variable.name,
          scope: variable.scope,
          type: variable.type,
        });

        return formatSuccessResponse({
          variable: {
            ...variable,
            value: variable.isEncrypted ? '[ENCRYPTED]' : variable.value,
          },
          usage,
          metadata: {
            canEdit: true, // This would be determined by user permissions
            canDelete: variable.scope !== 'global', // Example business rule - fixed comparison
            lastAccessed: usage?.lastAccessed,
            accessCount: Number(usage?.accessCount || 0),
          },
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error getting custom variable', { variableId, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to get custom variable details: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add update custom variable tool
 */
function addUpdateCustomVariableTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'update-custom-variable',
    description: 'Update an existing custom variable',
    parameters: VariableUpdateSchema,
    annotations: {
      title: 'Update Custom Variable',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { variableId, name, value, type, description, tags, isEncrypted } = input;

      log.info('Updating custom variable', { variableId, name });

      try {
        const updateData: Record<string, unknown> = {};

        if (name !== undefined) {updateData.name = name;}
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

        if (description !== undefined) {updateData.description = description;}
        if (tags !== undefined) {updateData.tags = tags;}
        if (isEncrypted !== undefined) {updateData.isEncrypted = isEncrypted;}

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

        return formatSuccessResponse({
          variable: {
            ...updatedVariable,
            value: updatedVariable.isEncrypted ? '[ENCRYPTED]' : updatedVariable.value,
          },
          message: `Variable "${updatedVariable.name}" updated successfully`,
          changes: Object.keys(updateData),
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error updating custom variable', { variableId, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to update custom variable: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add delete custom variable tool
 */
function addDeleteCustomVariableTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'delete-custom-variable',
    description: 'Delete a custom variable',
    parameters: z.object({
      variableId: z.number().min(1).describe('Variable ID to delete'),
      force: z.boolean().default(false).describe('Force delete even if variable is in use'),
    }),
    annotations: {
      title: 'Delete Custom Variable',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { variableId, force } = input;

      log.info('Deleting custom variable', { variableId, force });

      try {
        // Check if variable is in use (unless force delete)
        if (!force) {
          const usageResponse = await apiClient.get(`/variables/${variableId}/usage`);
          if (usageResponse.success && Number((usageResponse.data as Record<string, unknown>)?.usageCount) > 0) {
            throw new UserError(`Variable is currently in use (${(usageResponse.data as Record<string, unknown>).usageCount} references). Use force=true to delete anyway.`);
          }
        }

        const response = await apiClient.delete(`/variables/${variableId}`);

        if (!response.success) {
          throw new UserError(`Failed to delete variable: ${response.error?.message || 'Unknown error'}`);
        }

        log.info('Successfully deleted custom variable', { variableId });

        return formatSuccessResponse({
          message: `Variable ${variableId} deleted successfully`,
          variableId,
          forced: force,
        }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error deleting custom variable', { variableId, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to delete custom variable: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add bulk variable operations tool
 */
function addBulkVariableOperationsTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'bulk-variable-operations',
    description: 'Perform bulk operations on multiple custom variables',
    parameters: VariableBulkOperationSchema,
    annotations: {
      title: 'Bulk Variable Operations',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
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

        // Type guard for bulk operation result
        const bulkResult = result && typeof result === 'object' ? result as Record<string, unknown> : {};
        const affected = typeof bulkResult.affected === 'number' ? bulkResult.affected : variableIds.length;
        const failed = typeof bulkResult.failed === 'number' ? bulkResult.failed : 0;
        const errors = Array.isArray(bulkResult.errors) ? bulkResult.errors : [];

        log.info('Successfully completed bulk variable operation', {
          operation,
          affected,
          failed,
        });

        return formatSuccessResponse({
          result,
          message: `Bulk ${operation} completed successfully`,
          summary: {
            requested: variableIds.length,
            successful: affected,
            failed,
            errors,
          },
        }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error performing bulk variable operation', { operation, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to perform bulk variable operation: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add export custom variables tool
 */
function addExportCustomVariablesTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'export-custom-variables',
    description: 'Export custom variables in various formats for backup or migration',
    parameters: VariableExportSchema,
    annotations: {
      title: 'Export Custom Variables',
      readOnlyHint: true,
      openWorldHint: true,
    },
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

        // Type guard for export result
        const exportResponseData = exportResult && typeof exportResult === 'object' ? exportResult as Record<string, unknown> : {};
        const count = typeof exportResponseData.count === 'number' ? exportResponseData.count : 0;
        const exportId = typeof exportResponseData.exportId === 'string' ? exportResponseData.exportId : '';
        const downloadUrl = typeof exportResponseData.downloadUrl === 'string' ? exportResponseData.downloadUrl : '';
        const expiresAt = typeof exportResponseData.expiresAt === 'string' ? exportResponseData.expiresAt : '';
        const filename = typeof exportResponseData.filename === 'string' ? exportResponseData.filename : '';
        const encryptedCount = typeof exportResponseData.encryptedCount === 'number' ? exportResponseData.encryptedCount : 0;

        log.info('Successfully exported custom variables', {
          format,
          variableCount: count,
          exportId,
        });

        return formatSuccessResponse({
          exportResult,
          message: `Variables exported successfully in ${format} format`,
          download: {
            url: downloadUrl,
            expiresAt,
            filename,
          },
          summary: {
            totalVariables: count,
            encryptedVariables: encryptedCount,
            format: format,
            includeMetadata,
          },
        }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error exporting custom variables', { scope, format, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to export custom variables: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add test variable resolution tool
 */
function addTestVariableResolutionTool(server: FastMCP, apiClient: MakeApiClient): void {
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
    annotations: {
      title: 'Test Variable Resolution',
      readOnlyHint: true,
      openWorldHint: true,
    },
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

        // Type guard for resolution result
        const resolutionData = result && typeof result === 'object' ? result as Record<string, unknown> : {};
        const resolvedVariable = resolutionData.resolvedVariable && typeof resolutionData.resolvedVariable === 'object' 
          ? resolutionData.resolvedVariable as Record<string, unknown> : null;
        const inheritanceChain = Array.isArray(resolutionData.inheritanceChain) ? resolutionData.inheritanceChain : [];

        log.info('Successfully tested variable resolution', {
          variableName,
          resolved: !!resolvedVariable,
          scope: resolvedVariable && typeof resolvedVariable.scope === 'string' ? resolvedVariable.scope : undefined,
        });

        return formatSuccessResponse({
          resolution: result,
          summary: {
            variableName,
            context,
            resolved: !!resolvedVariable,
            resolvedScope: resolvedVariable ? resolvedVariable.scope : undefined,
            value: resolvedVariable?.isEncrypted ? '[ENCRYPTED]' : (resolvedVariable ? resolvedVariable.value : undefined),
            inheritanceChain,
          },
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error testing variable resolution', { variableName, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to test variable resolution: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add list incomplete executions tool
 */
function addListIncompleteExecutionsTool(server: FastMCP, apiClient: MakeApiClient): void {
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
    annotations: {
      title: 'List Incomplete Executions with Recovery Options',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
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

        if (scenarioId) {params.scenarioId = scenarioId;}
        if (organizationId) {params.organizationId = organizationId;}
        if (teamId) {params.teamId = teamId;}
        if (status !== 'all') {params.status = status;}
        if (ageHours !== undefined) {params.ageHours = ageHours;}
        if (canResume !== undefined) {params.canResume = canResume;}

        const response = await apiClient.get('/incomplete-executions', { params });

        if (!response.success) {
          throw new UserError(`Failed to list incomplete executions: ${response.error?.message || 'Unknown error'}`);
        }

        const incompleteExecutions = response.data as MakeIncompleteExecution[] || [];
        const metadata = response.metadata;

        // Generate recovery analysis for each execution
        const executionsWithRecovery = await Promise.all(
          incompleteExecutions.map(async (execution) => {
            let recoveryPlan: unknown = null;
            
            if (includeRecoveryPlan) {
              try {
                const recoveryResponse = await apiClient.get(`/incomplete-executions/${execution.id}/recovery-analysis`);
                if (recoveryResponse.success) {
                  recoveryPlan = recoveryResponse.data;
                }
              } catch {
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
            uniqueScenarios: Array.from(new Set(incompleteExecutions.map(exec => exec.scenarioId))).length,
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

        return formatSuccessResponse({
          incompleteExecutions: executionsWithRecovery,
          summary,
          pagination: {
            total: metadata?.total || incompleteExecutions.length,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + incompleteExecutions.length),
          },
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error listing incomplete executions', { error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to list incomplete executions with recovery: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add bulk resolve incomplete executions tool
 */
function addBulkResolveIncompleteExecutionsTool(server: FastMCP, apiClient: MakeApiClient): void {
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
      }).default(() => ({ retryWithModifications: false, skipFailedModules: false, preserveState: true, notifyOnCompletion: false })).describe('Bulk operation options'),
      reason: z.string().max(500).optional().describe('Reason for bulk resolution'),
    }),
    annotations: {
      title: 'Bulk Resolve Incomplete Executions',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
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
        
        // Type guard for bulk resolve result
        const resolveResult = result && typeof result === 'object' ? result as Record<string, unknown> : {};
        const successful = typeof resolveResult.successful === 'number' ? resolveResult.successful : 0;
        const failed = typeof resolveResult.failed === 'number' ? resolveResult.failed : 0;
        
        reportProgress({ progress: 75, total: 100 });

        // Get updated status for resolved executions
        const statusUpdates = await Promise.all(
          executionIds.slice(0, 10).map(async (id) => { // Limit to first 10 for performance
            try {
              const statusResponse = await apiClient.get(`/executions/${id}/status`);
              return {
                executionId: id,
                newStatus: statusResponse.success && statusResponse.data && typeof statusResponse.data === 'object' && 'status' in statusResponse.data 
                  ? (statusResponse.data as Record<string, unknown>).status : 'unknown',
              };
            } catch {
              return { executionId: id, newStatus: 'error' };
            }
          })
        );

        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully completed bulk resolve operation', {
          requested: executionIds.length,
          successful,
          failed,
        });

        // Additional type guards for remaining properties
        const batchId = typeof resolveResult.batchId === 'string' ? resolveResult.batchId : undefined;
        const estimatedCompletionTime = typeof resolveResult.estimatedCompletionTime === 'string' ? resolveResult.estimatedCompletionTime : undefined;
        const errors = Array.isArray(resolveResult.errors) ? resolveResult.errors : [];

        return formatSuccessResponse({
          result,
          statusUpdates,
          summary: {
            requestedCount: executionIds.length,
            successfulResolutions: successful,
            failedResolutions: failed,
            action: action,
            batchId: batchId,
            estimatedCompletionTime: estimatedCompletionTime,
          },
          message: `Bulk resolution initiated for ${executionIds.length} executions`,
          errors: errors,
        }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error in bulk resolve operation', { error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to bulk resolve incomplete executions: ${errorMessage}`);
      }
    },
  });
}

/**
 * Extract and validate analysis data from API response
 */
function extractAnalysisData(analysis: unknown): Record<string, unknown> {
  const analysisData = analysis && typeof analysis === 'object' ? analysis as Record<string, unknown> : {};
  
  return {
    totalFailures: typeof analysisData.totalFailures === 'number' ? analysisData.totalFailures : 0,
    failureRate: typeof analysisData.failureRate === 'number' ? analysisData.failureRate : 0,
    topErrors: Array.isArray(analysisData.topErrors) ? analysisData.topErrors : [],
    topScenarios: Array.isArray(analysisData.topScenarios) ? analysisData.topScenarios : [],
    timePatterns: analysisData.timePatterns && typeof analysisData.timePatterns === 'object' ? analysisData.timePatterns : {},
    recoveryStats: analysisData.recoveryStats && typeof analysisData.recoveryStats === 'object' ? analysisData.recoveryStats as Record<string, unknown> : {},
    operationsLost: typeof analysisData.operationsLost === 'number' ? analysisData.operationsLost : 0,
    dataTransferLost: typeof analysisData.dataTransferLost === 'number' ? analysisData.dataTransferLost : 0,
    estimatedCost: typeof analysisData.estimatedCost === 'number' ? analysisData.estimatedCost : 0,
    recommendations: Array.isArray(analysisData.recommendations) ? analysisData.recommendations : [],
  };
}

/**
 * Generate insights from extracted analysis data
 */
function generateAnalysisInsights(data: Record<string, unknown>): Record<string, unknown> {
  const topErrors = Array.isArray(data.topErrors) ? data.topErrors : [];
  const topScenarios = Array.isArray(data.topScenarios) ? data.topScenarios : [];
  const recoveryStats = data.recoveryStats && typeof data.recoveryStats === 'object' ? data.recoveryStats as Record<string, unknown> : {};
  
  return {
    totalFailures: data.totalFailures,
    failureRate: data.failureRate,
    mostCommonErrors: topErrors.slice(0, 5),
    mostAffectedScenarios: topScenarios.slice(0, 5),
    timePatterns: data.timePatterns,
    recoverySuccess: typeof recoveryStats.successRate === 'number' ? recoveryStats.successRate : 0,
    operationalImpact: {
      operationsLost: data.operationsLost,
      dataTransferLost: data.dataTransferLost,
      estimatedCost: data.estimatedCost,
    },
  };
}

/**
 * Create analysis summary response
 */
function createAnalysisSummary(
  insights: Record<string, unknown>,
  recommendations: unknown[],
  timeRange: Record<string, unknown>,
  groupBy: string
): Record<string, unknown> {
  const mostCommonErrors = Array.isArray(insights.mostCommonErrors) ? insights.mostCommonErrors : [];
  const failureRate = typeof insights.failureRate === 'number' ? insights.failureRate : 0;
  
  return {
    analysisTimeRange: timeRange,
    groupBy,
    totalFailures: insights.totalFailures,
    failureRate: `${(failureRate * 100).toFixed(2)}%`,
    topIssue: mostCommonErrors[0]?.error || 'No dominant error pattern',
    actionableRecommendations: recommendations.filter((r: unknown) => 
      typeof r === 'object' && r !== null && 'priority' in r && (r as { priority: string }).priority === 'high'
    ).length || 0,
  };
}

/**
 * Add analyze execution failure patterns tool
 */
function addAnalyzeExecutionFailurePatternsTool(server: FastMCP, apiClient: MakeApiClient): void {
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
    annotations: {
      title: 'Analyze Execution Failure Patterns',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
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

        const requestData = {
          organizationId,
          teamId,
          timeRange,
          groupBy,
          includeRecommendations,
        };

        reportProgress({ progress: 25, total: 100 });

        const response = await apiClient.post('/incomplete-executions/failure-analysis', requestData);

        if (!response.success) {
          throw new UserError(`Failed to analyze failure patterns: ${response.error?.message || 'Unknown error'}`);
        }

        const analysis = response.data;
        reportProgress({ progress: 75, total: 100 });

        const extractedData = extractAnalysisData(analysis);
        const insights = generateAnalysisInsights(extractedData);
        
        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully completed failure pattern analysis', {
          totalFailures: insights.totalFailures as number,
          failureRate: insights.failureRate as number,
          analysisTimeRange: timeRange,
        });

        const recommendations = extractedData.recommendations as unknown[];
        const summary = createAnalysisSummary(insights, recommendations, timeRange as Record<string, unknown>, groupBy as string);

        return formatSuccessResponse({
          analysis,
          insights,
          recommendations: includeRecommendations ? recommendations : undefined,
          summary,
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error analyzing failure patterns', { error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to analyze execution failure patterns: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add create recovery automation rule tool
 */
function addCreateRecoveryAutomationRuleTool(server: FastMCP, apiClient: MakeApiClient): void {
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
    annotations: {
      title: 'Create Recovery Automation Rule',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
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
        
        // Type guard for rule result
        const ruleResponse = rule && typeof rule === 'object' ? rule as Record<string, unknown> : {};
        const ruleId = typeof ruleResponse.id === 'string' ? ruleResponse.id : 'unknown';

        log.info('Successfully created recovery automation rule', {
          ruleId: ruleId,
          name,
          primaryAction: actions.primaryAction,
        });

        return formatSuccessResponse({
          rule,
          message: `Recovery automation rule "${name}" created successfully`,
          summary: {
            ruleId: ruleId,
            name,
            primaryAction: actions.primaryAction,
            isActive,
            priority,
            conditionCount: Object.keys(conditions).length,
          },
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error creating recovery automation rule', { name, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to create recovery automation rule: ${errorMessage}`);
      }
    },
  });
}

export default addVariableTools;