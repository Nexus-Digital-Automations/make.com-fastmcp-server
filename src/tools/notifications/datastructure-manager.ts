/**
 * Data Structure Management Tools for Make.com FastMCP Server
 * Handles custom data structures for validation and transformation
 */

import { FastMCP, UserError } from 'fastmcp';
import { z } from 'zod';
import MakeApiClient from '../../lib/make-api-client.js';
import logger from '../../lib/logger.js';
import { formatSuccessResponse } from '../../utils/response-formatter.js';
import {
  MakeCustomDataStructure,
  DataStructureUpdateData,
  DataStructureListResponse,
  DataStructureDependency,
  DataStructureDependencyResponse,
  DataStructureArchiveInfo,
  DataStructureArchiveResponse,
  DataStructureWithStats,
} from '../notifications.js';

// Data structure validation schema
const DataStructureSchema = z.object({
  name: z.string().min(1).max(100).describe('Data structure name'),
  description: z.string().max(500).optional().describe('Data structure description'),
  type: z.enum(['schema', 'template', 'validation', 'transformation']).describe('Structure type'),
  organizationId: z.number().min(1).optional().describe('Organization ID'),
  teamId: z.number().min(1).optional().describe('Team ID'),
  scope: z.enum(['global', 'organization', 'team', 'personal']).default('personal').describe('Access scope'),
  structure: z.object({
    schema: z.any().describe('JSON Schema definition'),
    version: z.string().default('1.0.0').describe('Schema version'),
    format: z.enum(['json', 'xml', 'yaml', 'csv', 'custom']).default('json').describe('Data format'),
  }).describe('Structure definition'),
  validation: z.object({
    enabled: z.boolean().default(true).describe('Enable validation'),
    strict: z.boolean().default(false).describe('Strict validation mode'),
    rules: z.array(z.object({
      field: z.string().min(1).describe('Field path'),
      type: z.enum(['required', 'format', 'range', 'custom']).describe('Rule type'),
      parameters: z.any().optional().describe('Rule parameters'),
      message: z.string().describe('Error message'),
    })).default([]).describe('Validation rules'),
  }).optional().describe('Validation configuration'),
  transformation: z.object({
    enabled: z.boolean().default(false).describe('Enable transformation'),
    mappings: z.array(z.object({
      source: z.string().min(1).describe('Source field path'),
      target: z.string().min(1).describe('Target field path'),
      function: z.string().optional().describe('Transformation function'),
      parameters: z.any().optional().describe('Function parameters'),
    })).default([]).describe('Field mappings'),
    filters: z.array(z.object({
      field: z.string().min(1).describe('Field to filter'),
      operator: z.string().min(1).describe('Filter operator'),
      value: z.any().describe('Filter value'),
    })).default([]).describe('Data filters'),
  }).optional().describe('Transformation configuration'),
}).strict();

/**
 * Add data structure management tools to FastMCP server
 */
export function addDataStructureTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'DataStructureTools' });
  
  componentLogger.info('Adding data structure management tools');

  // Create custom data structure
  server.addTool({
    name: 'create-data-structure',
    description: 'Create a custom data structure for validation and transformation',
    parameters: DataStructureSchema,
    annotations: {
      title: 'Create Custom Data Structure',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false, // Each structure creation is unique
      openWorldHint: false, // Internal data structure management
    },
    execute: async (input, context): Promise<string> => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} }, reportProgress = (): void => {} } = context || {};
      const { name, description, type, organizationId, teamId, scope, structure, validation, transformation } = input;

      if (log?.info) {
        log.info('Creating custom data structure', {
          name,
          type,
          scope,
          organizationId,
          teamId,
          format: structure.format,
        });
      }

      try {
        if (reportProgress) {
          reportProgress({ progress: 0, total: 100 });
        }

        // Validate JSON Schema if provided
        if (structure.schema && typeof structure.schema === 'object') {
          try {
            JSON.stringify(structure.schema);
          } catch {
            throw new UserError('Invalid JSON Schema provided');
          }
        }

        const dataStructureData = {
          name,
          description,
          type,
          organizationId,
          teamId,
          scope,
          structure: {
            schema: structure.schema,
            version: structure.version || '1.0.0',
            format: structure.format || 'json',
          },
          validation: validation ? {
            enabled: validation.enabled !== false,
            strict: validation.strict || false,
            rules: validation.rules || [],
          } : { enabled: true, strict: false, rules: [] },
          transformation: transformation ? {
            enabled: transformation.enabled || false,
            mappings: transformation.mappings || [],
            filters: transformation.filters || [],
          } : { enabled: false, mappings: [], filters: [] },
        };

        if (reportProgress) {
          reportProgress({ progress: 50, total: 100 });
        }

        let endpoint = '/data-structures';
        if (organizationId) {
          endpoint = `/organizations/${organizationId}/data-structures`;
        } else if (teamId) {
          endpoint = `/teams/${teamId}/data-structures`;
        }

        const response = await apiClient.post(endpoint, dataStructureData);

        if (!response.success) {
          throw new UserError(`Failed to create data structure: ${response.error?.message || 'Unknown error'}`);
        }

        const dataStructure = response.data as MakeCustomDataStructure;
        if (!dataStructure) {
          throw new UserError('Data structure creation failed - no data returned');
        }

        if (reportProgress) {
          reportProgress({ progress: 100, total: 100 });
        }

        if (log?.info) {
          log.info('Successfully created custom data structure', {
            dataStructureId: dataStructure.id,
            name: dataStructure.name,
            type: dataStructure.type,
            scope: dataStructure.scope,
          });
        }

        return formatSuccessResponse({
          dataStructure,
          message: `Data structure "${name}" created successfully`,
          summary: {
            id: dataStructure.id,
            name: dataStructure.name,
            type: dataStructure.type,
            scope: dataStructure.scope,
            format: dataStructure.structure.format,
            version: dataStructure.structure.version,
            validationEnabled: dataStructure.validation.enabled,
            transformationEnabled: dataStructure.transformation.enabled,
          },
          configuration: {
            validationRules: dataStructure.validation.rules.length,
            transformationMappings: dataStructure.transformation.mappings.length,
            transformationFilters: dataStructure.transformation.filters.length,
          },
          usage: {
            validateUrl: `/data-structures/${dataStructure.id}/validate`,
            transformUrl: `/data-structures/${dataStructure.id}/transform`,
            testUrl: `/data-structures/${dataStructure.id}/test`,
          },
        }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (log?.error) {
          log.error('Error creating data structure', { name, error: errorMessage });
        }
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to create data structure: ${errorMessage}`);
      }
    },
  });

  // List custom data structures
  server.addTool({
    name: 'list-data-structures',
    description: 'List and filter custom data structures with comprehensive filtering and search',
    parameters: z.object({
      type: z.enum(['schema', 'template', 'validation', 'transformation', 'all']).default('all').describe('Filter by structure type'),
      scope: z.enum(['global', 'organization', 'team', 'personal', 'all']).default('all').describe('Filter by access scope'),
      organizationId: z.number().min(1).optional().describe('Filter by organization ID'),
      teamId: z.number().min(1).optional().describe('Filter by team ID'),
      format: z.enum(['json', 'xml', 'yaml', 'csv', 'custom', 'all']).default('all').describe('Filter by data format'),
      search: z.string().max(200).optional().describe('Search in name and description'),
      includeValidation: z.boolean().default(true).describe('Include validation configuration'),
      includeTransformation: z.boolean().default(true).describe('Include transformation details'),
      limit: z.number().min(1).max(100).default(20).describe('Maximum structures to return'),
      offset: z.number().min(0).default(0).describe('Structures to skip for pagination'),
      sortBy: z.enum(['createdAt', 'updatedAt', 'name', 'type']).default('createdAt').describe('Sort field'),
      sortOrder: z.enum(['asc', 'desc']).default('desc').describe('Sort order'),
    }),
    annotations: {
      title: 'List Custom Data Structures',
      readOnlyHint: true,
      openWorldHint: false, // Internal data structure listing
    },
    execute: async (input, context) => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} } } = context || {};
      const { type, scope, organizationId, teamId, format, search, includeValidation, includeTransformation, limit, offset, sortBy, sortOrder } = input;

      if (log?.info) {
        log.info('Listing custom data structures', {
          type,
          scope,
          organizationId,
          teamId,
          format,
          search,
          limit,
          offset,
        });
      }

      try {
        const params: Record<string, unknown> = {
          limit,
          offset,
          sortBy,
          sortOrder,
          includeValidation,
          includeTransformation,
        };

        if (type !== 'all') {params.type = type;}
        if (scope !== 'all') {params.scope = scope;}
        if (format !== 'all') {params.format = format;}
        if (search) {params.search = search;}
        if (organizationId) {params.organizationId = organizationId;}
        if (teamId) {params.teamId = teamId;}

        let endpoint = '/data-structures';
        if (organizationId) {
          endpoint = `/organizations/${organizationId}/data-structures`;
        } else if (teamId) {
          endpoint = `/teams/${teamId}/data-structures`;
        }

        const response = await apiClient.get(endpoint, { params });

        if (!response.success) {
          throw new UserError(`Failed to list data structures: ${response.error?.message || 'Unknown error'}`);
        }

        const data = response.data as DataStructureListResponse;

        if (!data?.dataStructures) {
          throw new UserError('Invalid response format from data structures API');
        }

        if (log?.info) {
          log.info('Successfully listed data structures', {
            count: data.dataStructures.length,
            total: data.pagination.total,
            filters: data.filters,
          });
        }

        return formatSuccessResponse({
          dataStructures: data.dataStructures,
          pagination: data.pagination,
          filters: data.filters,
          summary: {
            totalFound: data.pagination.total,
            currentPage: Math.floor(offset / limit) + 1,
            totalPages: Math.ceil(data.pagination.total / limit),
            hasMore: data.pagination.hasMore,
          },
          statistics: {
            byType: data.dataStructures.reduce((acc, ds) => {
              acc[ds.type] = (acc[ds.type] || 0) + 1;
              return acc;
            }, {} as Record<string, number>),
            byScope: data.dataStructures.reduce((acc, ds) => {
              acc[ds.scope] = (acc[ds.scope] || 0) + 1;
              return acc;
            }, {} as Record<string, number>),
            byFormat: data.dataStructures.reduce((acc, ds) => {
              acc[ds.structure.format] = (acc[ds.structure.format] || 0) + 1;
              return acc;
            }, {} as Record<string, number>),
          },
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (log?.error) {
          log.error('Error listing data structures', { error: errorMessage });
        }
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to list data structures: ${errorMessage}`);
      }
    },
  });

  // Get custom data structure by ID
  server.addTool({
    name: 'get-data-structure',
    description: 'Retrieve detailed information about a specific custom data structure',
    parameters: z.object({
      dataStructureId: z.number().min(1).describe('Data structure ID'),
      organizationId: z.number().min(1).optional().describe('Organization ID (for scoped access)'),
      teamId: z.number().min(1).optional().describe('Team ID (for scoped access)'),
      includeUsageStats: z.boolean().default(true).describe('Include usage statistics'),
      includeValidationHistory: z.boolean().default(false).describe('Include validation history'),
      includeTransformationHistory: z.boolean().default(false).describe('Include transformation history'),
    }),
    annotations: {
      title: 'Get Data Structure Details',
      readOnlyHint: true,
      openWorldHint: false, // Internal data structure retrieval
    },
    execute: async (input, context): Promise<string> => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} }, reportProgress = (): void => {} } = context || {};
      const { dataStructureId, organizationId, teamId, includeUsageStats, includeValidationHistory, includeTransformationHistory } = input;

      if (log?.info) {
        log.info('Getting data structure details', {
          dataStructureId,
          organizationId,
          teamId,
          includeUsageStats,
          includeValidationHistory,
          includeTransformationHistory,
        });
      }

      try {
        if (reportProgress) {
          reportProgress({ progress: 0, total: 100 });
        }

        let endpoint = `/data-structures/${dataStructureId}`;
        if (organizationId) {
          endpoint = `/organizations/${organizationId}/data-structures/${dataStructureId}`;
        } else if (teamId) {
          endpoint = `/teams/${teamId}/data-structures/${dataStructureId}`;
        }

        const params: Record<string, unknown> = {
          includeUsageStats,
          includeValidationHistory,
          includeTransformationHistory,
        };

        const response = await apiClient.get(endpoint, { params });

        if (!response.success) {
          throw new UserError(`Failed to get data structure: ${response.error?.message || 'Unknown error'}`);
        }

        if (reportProgress) {
          reportProgress({ progress: 50, total: 100 });
        }

        const dataStructure = response.data as DataStructureWithStats;

        if (!dataStructure) {
          throw new UserError('Data structure not found or access denied');
        }

        if (reportProgress) {
          reportProgress({ progress: 100, total: 100 });
        }

        if (log?.info) {
          log.info('Successfully retrieved data structure', {
            dataStructureId: dataStructure.id,
            name: dataStructure.name,
            type: dataStructure.type,
            scope: dataStructure.scope,
          });
        }

        return formatSuccessResponse({
          dataStructure,
          metadata: {
            id: dataStructure.id,
            name: dataStructure.name,
            type: dataStructure.type,
            scope: dataStructure.scope,
            format: dataStructure.structure.format,
            version: dataStructure.structure.version,
            createdAt: dataStructure.createdAt,
            updatedAt: dataStructure.updatedAt,
          },
          configuration: {
            validation: {
              enabled: dataStructure.validation.enabled,
              strict: dataStructure.validation.strict,
              rulesCount: dataStructure.validation.rules.length,
            },
            transformation: {
              enabled: dataStructure.transformation.enabled,
              mappingsCount: dataStructure.transformation.mappings.length,
              filtersCount: dataStructure.transformation.filters.length,
            },
          },
          usage: dataStructure.usage || null,
          operations: {
            validateUrl: `/data-structures/${dataStructure.id}/validate`,
            transformUrl: `/data-structures/${dataStructure.id}/transform`,
            testUrl: `/data-structures/${dataStructure.id}/test`,
            updateUrl: `/data-structures/${dataStructure.id}`,
            deleteUrl: `/data-structures/${dataStructure.id}`,
          },
        }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (log?.error) {
          log.error('Error getting data structure', { dataStructureId, error: errorMessage });
        }
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to get data structure: ${errorMessage}`);
      }
    },
  });

  // Update custom data structure
  server.addTool({
    name: 'update-data-structure',
    description: 'Update an existing custom data structure configuration',
    parameters: z.object({
      dataStructureId: z.number().min(1).describe('Data structure ID to update'),
      organizationId: z.number().min(1).optional().describe('Organization ID (for scoped access)'),
      teamId: z.number().min(1).optional().describe('Team ID (for scoped access)'),
      name: z.string().min(1).max(100).optional().describe('Updated structure name'),
      description: z.string().max(500).optional().describe('Updated description'),
      structure: z.object({
        schema: z.any().optional().describe('Updated JSON Schema definition'),
        version: z.string().optional().describe('Updated schema version'),
        format: z.enum(['json', 'xml', 'yaml', 'csv', 'custom']).optional().describe('Updated data format'),
      }).optional().describe('Updated structure definition'),
      validation: z.object({
        enabled: z.boolean().optional().describe('Enable/disable validation'),
        strict: z.boolean().optional().describe('Strict validation mode'),
        rules: z.array(z.object({
          field: z.string().min(1).describe('Field path'),
          type: z.enum(['required', 'format', 'range', 'custom']).describe('Rule type'),
          parameters: z.any().optional().describe('Rule parameters'),
          message: z.string().describe('Error message'),
        })).optional().describe('Updated validation rules'),
      }).optional().describe('Updated validation configuration'),
      transformation: z.object({
        enabled: z.boolean().optional().describe('Enable/disable transformation'),
        mappings: z.array(z.object({
          source: z.string().describe('Source field path'),
          target: z.string().describe('Target field path'),
          type: z.enum(['direct', 'computed', 'lookup', 'constant']).describe('Mapping type'),
          parameters: z.any().optional().describe('Mapping parameters'),
        })).optional().describe('Updated field mappings'),
        filters: z.array(z.object({
          field: z.string().describe('Field to filter'),
          operator: z.enum(['equals', 'contains', 'startsWith', 'endsWith', 'gt', 'lt', 'gte', 'lte', 'in', 'notIn']).describe('Filter operator'),
          value: z.unknown().describe('Filter value'),
          caseSensitive: z.boolean().optional().describe('Case sensitive comparison'),
        })).optional().describe('Updated filters'),
      }).optional().describe('Updated transformation configuration'),
    }),
    annotations: {
      title: 'Update Data Structure Configuration',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true, // Same updates produce same result
      openWorldHint: false, // Internal data structure management
    },
    execute: async (input, context): Promise<string> => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} }, reportProgress = (): void => {} } = context || {};
      const { dataStructureId, organizationId, teamId, name, description, structure, validation, transformation } = input;

      if (log?.info) {
        log.info('Updating data structure', {
          dataStructureId,
          organizationId,
          teamId,
          updates: {
            name: !!name,
            description: !!description,
            structure: !!structure,
            validation: !!validation,
            transformation: !!transformation,
          },
        });
      }

      try {
        if (reportProgress) {
          reportProgress({ progress: 0, total: 100 });
        }

        // Validate JSON Schema if provided in updates
        if (structure?.schema && typeof structure.schema === 'object') {
          try {
            JSON.stringify(structure.schema);
          } catch {
            throw new UserError('Invalid JSON Schema provided in update');
          }
        }

        const updateData: DataStructureUpdateData = {};
        
        if (name) {updateData.name = name;}
        if (description !== undefined) {updateData.description = description;}
        
        if (structure) {
          updateData.structure = {};
          if (structure.schema) {updateData.structure.schema = structure.schema;}
          if (structure.version) {updateData.structure.version = structure.version;}
          if (structure.format) {updateData.structure.format = structure.format;}
        }
        
        if (validation) {
          updateData.validation = {};
          if (validation.enabled !== undefined) {updateData.validation.enabled = validation.enabled;}
          if (validation.strict !== undefined) {updateData.validation.strict = validation.strict;}
          if (validation.rules) {updateData.validation.rules = validation.rules;}
        }
        
        if (transformation) {
          updateData.transformation = {};
          if (transformation.enabled !== undefined) {updateData.transformation.enabled = transformation.enabled;}
          if (transformation.mappings) {updateData.transformation.mappings = transformation.mappings;}
          if (transformation.filters) {updateData.transformation.filters = transformation.filters.map(filter => ({
            field: filter.field,
            operator: filter.operator,
            value: filter.value,
            caseSensitive: filter.caseSensitive
          }));}
        }

        if (reportProgress) {
          reportProgress({ progress: 30, total: 100 });
        }

        let endpoint = `/data-structures/${dataStructureId}`;
        if (organizationId) {
          endpoint = `/organizations/${organizationId}/data-structures/${dataStructureId}`;
        } else if (teamId) {
          endpoint = `/teams/${teamId}/data-structures/${dataStructureId}`;
        }

        const response = await apiClient.patch(endpoint, updateData);

        if (!response.success) {
          throw new UserError(`Failed to update data structure: ${response.error?.message || 'Unknown error'}`);
        }

        if (reportProgress) {
          reportProgress({ progress: 80, total: 100 });
        }

        const updatedDataStructure = response.data as MakeCustomDataStructure;
        if (!updatedDataStructure) {
          throw new UserError('Data structure update failed - no data returned');
        }

        if (reportProgress) {
          reportProgress({ progress: 100, total: 100 });
        }

        if (log?.info) {
          log.info('Successfully updated data structure', {
            dataStructureId: updatedDataStructure.id,
            name: updatedDataStructure.name,
            type: updatedDataStructure.type,
            updatedFields: Object.keys(updateData),
          });
        }

        return formatSuccessResponse({
          dataStructure: updatedDataStructure,
          message: `Data structure "${updatedDataStructure.name}" updated successfully`,
          changes: {
            fieldsUpdated: Object.keys(updateData),
            previousVersion: structure?.version,
            newVersion: updatedDataStructure.structure.version,
            lastModified: updatedDataStructure.updatedAt,
          },
          configuration: {
            validation: {
              enabled: updatedDataStructure.validation.enabled,
              strict: updatedDataStructure.validation.strict,
              rulesCount: updatedDataStructure.validation.rules.length,
            },
            transformation: {
              enabled: updatedDataStructure.transformation.enabled,
              mappingsCount: updatedDataStructure.transformation.mappings.length,
              filtersCount: updatedDataStructure.transformation.filters.length,
            },
          },
          operations: {
            validateUrl: `/data-structures/${updatedDataStructure.id}/validate`,
            transformUrl: `/data-structures/${updatedDataStructure.id}/transform`,
            testUrl: `/data-structures/${updatedDataStructure.id}/test`,
          },
        }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (log?.error) {
          log.error('Error updating data structure', { dataStructureId, error: errorMessage });
        }
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to update data structure: ${errorMessage}`);
      }
    },
  });

  // Delete custom data structure
  server.addTool({
    name: 'delete-data-structure',
    description: 'Delete a custom data structure with optional dependency checking and confirmation',
    parameters: z.object({
      dataStructureId: z.number().min(1).describe('Data structure ID to delete'),
      organizationId: z.number().min(1).optional().describe('Organization ID (for scoped access)'),
      teamId: z.number().min(1).optional().describe('Team ID (for scoped access)'),
      force: z.boolean().default(false).describe('Force deletion even if dependencies exist'),
      checkDependencies: z.boolean().default(true).describe('Check for dependencies before deletion'),
      confirmationCode: z.string().optional().describe('Confirmation code for safety (if required)'),
      archiveBeforeDelete: z.boolean().default(true).describe('Create archive backup before deletion'),
    }),
    annotations: {
      title: 'Delete Data Structure',
      readOnlyHint: false,
      destructiveHint: true, // Permanently removes data structure
      idempotentHint: true, // Multiple deletes of same structure have same effect
      openWorldHint: false, // Internal data structure management
    },
    execute: async (input, context): Promise<string> => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} }, reportProgress = (): void => {} } = context || {};
      const { dataStructureId, organizationId, teamId, force, checkDependencies, confirmationCode, archiveBeforeDelete } = input;

      if (log?.info) {
        log.info('Deleting data structure', {
          dataStructureId,
          organizationId,
          teamId,
          force,
          checkDependencies,
          archiveBeforeDelete,
        });
      }

      try {
        if (reportProgress) {
          reportProgress({ progress: 0, total: 100 });
        }

        let endpoint = `/data-structures/${dataStructureId}`;
        if (organizationId) {
          endpoint = `/organizations/${organizationId}/data-structures/${dataStructureId}`;
        } else if (teamId) {
          endpoint = `/teams/${teamId}/data-structures/${dataStructureId}`;
        }

        // Get current data structure for reference
        const getResponse = await apiClient.get(endpoint);
        if (!getResponse.success) {
          throw new UserError(`Data structure not found: ${getResponse.error?.message || 'Unknown error'}`);
        }

        const dataStructure = getResponse.data as MakeCustomDataStructure;
        if (reportProgress) {
          reportProgress({ progress: 20, total: 100 });
        }

        // Check dependencies if requested
        let dependencies: DataStructureDependency[] = [];

        if (checkDependencies) {
          const depResponse = await apiClient.get(`${endpoint}/dependencies`);
          if (depResponse.success && depResponse?.data) {
            dependencies = (depResponse.data as DataStructureDependencyResponse).dependencies || [];
          }

          if (dependencies.length > 0 && !force) {
            const dependencyList = dependencies.map(dep => 
              `- ${dep.type} "${dep.name}" (${dep.id}) - ${dep.usage}`
            ).join('\n');

            throw new UserError(
              `Cannot delete data structure "${dataStructure.name}" because it has dependencies:\n${dependencyList}\n\nUse force=true to delete anyway, or remove dependencies first.`
            );
          }
        }

        if (reportProgress) {
          reportProgress({ progress: 40, total: 100 });
        }

        // Create archive if requested
        let archiveInfo: DataStructureArchiveInfo | null = null;
        if (archiveBeforeDelete) {
          try {
            const archiveResponse = await apiClient.post(`${endpoint}/archive`, {
              reason: 'Pre-deletion backup',
              includeHistory: true,
            });
            if (archiveResponse.success && archiveResponse?.data) {
              const archiveData = archiveResponse.data as DataStructureArchiveResponse;
              archiveInfo = {
                archiveId: archiveData.archiveId,
                archiveUrl: archiveData.downloadUrl,
              };
            }
          } catch (archiveError) {
            log.warn('Failed to create archive before deletion', { error: String(archiveError) });
          }
        }

        if (reportProgress) {
          reportProgress({ progress: 60, total: 100 });
        }

        // Perform deletion
        const deleteParams: Record<string, unknown> = {
          force,
          confirmationCode: confirmationCode || undefined,
        };

        const deleteResponse = await apiClient.delete(endpoint, { params: deleteParams });

        if (!deleteResponse.success) {
          throw new UserError(`Failed to delete data structure: ${deleteResponse.error?.message || 'Unknown error'}`);
        }

        if (reportProgress) {
          reportProgress({ progress: 100, total: 100 });
        }

        if (log?.info) {
          log.info('Successfully deleted data structure', {
            dataStructureId: dataStructure.id,
            name: dataStructure.name,
            type: dataStructure.type,
            hadDependencies: dependencies.length > 0,
            archiveCreated: !!archiveInfo,
          });
        }

        return formatSuccessResponse({
          message: `Data structure "${dataStructure.name}" deleted successfully`,
          deletedStructure: {
            id: dataStructure.id,
            name: dataStructure.name,
            type: dataStructure.type,
            scope: dataStructure.scope,
            format: dataStructure.structure.format,
            deletedAt: new Date().toISOString(),
          },
          dependencies: dependencies.length > 0 ? {
            count: dependencies.length,
            items: dependencies,
            forcedDeletion: force,
          } : null,
          archive: archiveInfo ? {
            created: true,
            archiveId: archiveInfo.archiveId,
            downloadUrl: archiveInfo.archiveUrl,
            expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(), // 30 days
          } : null,
          recovery: {
            canRestore: !!archiveInfo,
            restoreInstructions: archiveInfo ? 
              'Use the archive download URL to restore this data structure if needed within 30 days.' :
              'No archive was created. This deletion cannot be undone.',
          },
        }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (log?.error) {
          log.error('Error deleting data structure', { dataStructureId, error: errorMessage });
        }
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to delete data structure: ${errorMessage}`);
      }
    },
  });

  componentLogger.info('Data structure management tools added successfully');
}

export default addDataStructureTools;