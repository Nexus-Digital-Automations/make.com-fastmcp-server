/**
 * Folder Organization Tools for Make.com FastMCP Server
 * Comprehensive tools for managing folders, data stores, and resource organization
 */

import { FastMCP, UserError } from 'fastmcp';
import { z } from 'zod';
import MakeApiClient from '../lib/make-api-client.js';
import logger from '../lib/logger.js';

// Extended folder and data store types
export interface MakeFolder {
  id: number;
  name: string;
  description?: string;
  parentId?: number;
  path: string;
  organizationId?: number;
  teamId?: number; 
  type: 'template' | 'scenario' | 'connection' | 'mixed';
  permissions: {
    read: string[];
    write: string[];
    admin: string[];
  };
  itemCount: {
    templates: number;
    scenarios: number;
    connections: number;
    subfolders: number;
    total: number;
  };
  metadata: {
    size: number; // bytes
    lastActivity: string;
    mostActiveItem?: {
      type: string;
      id: number;
      name: string;
      activity: number;
    };
  };
  createdAt: string;
  updatedAt: string;
  createdBy: number;
  createdByName: string;
}

export interface MakeDataStructure {
  id: number;
  name: string;
  description?: string;
  organizationId?: number;
  teamId?: number;
  specification: Array<{
    name: string;
    type: 'text' | 'number' | 'boolean' | 'date' | 'array' | 'collection';
    required?: boolean;
    default?: unknown;
    constraints?: {
      minLength?: number;
      maxLength?: number;
      minimum?: number;
      maximum?: number;
      pattern?: string;
      enum?: unknown[];
    };
    spec?: Array<unknown>; // For nested collections and arrays
  }>;
  strict: boolean;
  usage: {
    dataStoresCount: number;
    totalRecords: number;
    lastUsed?: string;
  };
  validation: {
    enabled: boolean;
    rules: string[];
    lastValidation?: string;
    validationErrors?: number;
  };
  createdAt: string;
  updatedAt: string;
  createdBy: number;
}

export interface MakeDataStore {
  id: number;
  name: string;
  description?: string;
  type: 'data_structure' | 'key_value' | 'queue' | 'cache';
  organizationId?: number;
  teamId?: number;
  structure: {
    fields?: Array<{
      name: string;
      type: 'string' | 'number' | 'boolean' | 'date' | 'object' | 'array';
      required: boolean;
      defaultValue?: unknown;
      validation?: {
        min?: number;
        max?: number;
        pattern?: string;
        enum?: unknown[];
      };
    }>;
    indexes?: Array<{
      fields: string[];
      unique: boolean;
      name: string;
    }>;
  };
  settings: {
    maxSize: number; // MB
    ttl?: number; // seconds
    autoCleanup: boolean;
    encryption: boolean;
    compression: boolean;
  };
  usage: {
    recordCount: number;
    sizeUsed: number; // bytes
    operationsToday: number;
    lastOperation: string;
  };
  permissions: {
    read: string[];
    write: string[];
    admin: string[];
  };
  createdAt: string;
  updatedAt: string;
  createdBy: number;
}

// Input validation schemas
const FolderCreateSchema = z.object({
  name: z.string().min(1).max(100).describe('Folder name (1-100 characters)'),
  description: z.string().max(500).optional().describe('Folder description (max 500 characters)'),
  parentId: z.number().min(1).optional().describe('Parent folder ID (for nested folders)'),
  type: z.enum(['template', 'scenario', 'connection', 'mixed']).default('mixed').describe('Folder content type'),
  organizationId: z.number().min(1).optional().describe('Organization ID (for organization folders)'),
  teamId: z.number().min(1).optional().describe('Team ID (for team folders)'),
  permissions: z.object({
    read: z.array(z.string()).default([]).describe('User/team IDs with read access'),
    write: z.array(z.string()).default([]).describe('User/team IDs with write access'),
    admin: z.array(z.string()).default([]).describe('User/team IDs with admin access'),
  }).default({}).describe('Folder permissions'),
}).strict();


const FolderListSchema = z.object({
  parentId: z.number().min(1).optional().describe('List folders under this parent (null for root)'),
  type: z.enum(['template', 'scenario', 'connection', 'mixed', 'all']).default('all').describe('Filter by folder type'),
  organizationId: z.number().min(1).optional().describe('Filter by organization ID'),
  teamId: z.number().min(1).optional().describe('Filter by team ID'),
  searchQuery: z.string().max(100).optional().describe('Search in folder names and descriptions'),
  includeEmpty: z.boolean().default(true).describe('Include empty folders'),
  includeContents: z.boolean().default(false).describe('Include folder contents summary'),
  limit: z.number().min(1).max(1000).default(100).describe('Maximum number of folders to return'),
  offset: z.number().min(0).default(0).describe('Number of folders to skip for pagination'),
  sortBy: z.enum(['name', 'createdAt', 'updatedAt', 'itemCount', 'lastActivity']).default('name').describe('Sort field'),
  sortOrder: z.enum(['asc', 'desc']).default('asc').describe('Sort order'),
}).strict();

const DataStoreCreateSchema = z.object({
  name: z.string().min(1).max(100).describe('Data store name (1-100 characters)'),
  description: z.string().max(500).optional().describe('Data store description (max 500 characters)'),
  type: z.enum(['data_structure', 'key_value', 'queue', 'cache']).describe('Data store type'),
  organizationId: z.number().min(1).optional().describe('Organization ID (for organization data stores)'),
  teamId: z.number().min(1).optional().describe('Team ID (for team data stores)'),
  structure: z.object({
    fields: z.array(z.object({
      name: z.string().min(1).max(50).describe('Field name'),
      type: z.enum(['string', 'number', 'boolean', 'date', 'object', 'array']).describe('Field data type'),
      required: z.boolean().default(false).describe('Whether field is required'),
      defaultValue: z.any().optional().describe('Default field value'),
      validation: z.object({
        min: z.number().optional().describe('Minimum value/length'),
        max: z.number().optional().describe('Maximum value/length'),
        pattern: z.string().optional().describe('Regex pattern for validation'),
        enum: z.array(z.any()).optional().describe('Allowed values'),
      }).optional().describe('Field validation rules'),
    })).optional().describe('Data structure fields (for data_structure type)'),
    indexes: z.array(z.object({
      fields: z.array(z.string().min(1)).min(1).describe('Fields to index'),
      unique: z.boolean().default(false).describe('Whether index should be unique'),
      name: z.string().min(1).max(50).describe('Index name'),
    })).optional().describe('Database indexes'),
  }).optional().describe('Data structure definition'),
  settings: z.object({
    maxSize: z.number().min(1).max(10000).default(100).describe('Maximum size in MB'),
    ttl: z.number().min(60).optional().describe('Time to live in seconds'),
    autoCleanup: z.boolean().default(false).describe('Enable automatic cleanup'),
    encryption: z.boolean().default(false).describe('Enable data encryption'),
    compression: z.boolean().default(false).describe('Enable data compression'),
  }).default({}).describe('Data store settings'),
  permissions: z.object({
    read: z.array(z.string()).default([]).describe('User/team IDs with read access'),
    write: z.array(z.string()).default([]).describe('User/team IDs with write access'),
    admin: z.array(z.string()).default([]).describe('User/team IDs with admin access'),
  }).default({}).describe('Data store permissions'),
}).strict();

const MoveItemsSchema = z.object({
  items: z.array(z.object({
    type: z.enum(['template', 'scenario', 'connection', 'folder']).describe('Item type'),
    id: z.number().min(1).describe('Item ID'),
  })).min(1).max(100).describe('Items to move (max 100)'),
  targetFolderId: z.number().min(1).optional().describe('Target folder ID (null for root)'),
  copyInsteadOfMove: z.boolean().default(false).describe('Copy items instead of moving them'),
}).strict();

const DataStructureFieldSchema: z.ZodType<any> = z.object({
  name: z.string().min(1).max(50).describe('Field name'),
  type: z.enum(['text', 'number', 'boolean', 'date', 'array', 'collection']).describe('Field data type'),
  required: z.boolean().default(false).describe('Whether field is required'),
  default: z.unknown().optional().describe('Default field value'),
  constraints: z.object({
    minLength: z.number().min(0).optional().describe('Minimum text length'),
    maxLength: z.number().min(1).optional().describe('Maximum text length'),
    minimum: z.number().optional().describe('Minimum numeric value'),
    maximum: z.number().optional().describe('Maximum numeric value'),
    pattern: z.string().optional().describe('Regex pattern for text validation'),
    enum: z.array(z.unknown()).optional().describe('Allowed values'),
  }).optional().describe('Field validation constraints'),
  spec: z.array(z.lazy(() => DataStructureFieldSchema)).optional().describe('Nested field specification for collections/arrays'),
}).strict();

const DataStructureCreateSchema = z.object({
  name: z.string().min(1).max(100).describe('Data structure name (1-100 characters)'),
  description: z.string().max(500).optional().describe('Data structure description (max 500 characters)'),
  organizationId: z.number().min(1).optional().describe('Organization ID (for organization data structures)'),
  teamId: z.number().min(1).optional().describe('Team ID (for team data structures)'),
  specification: z.array(DataStructureFieldSchema).min(1).describe('Field specifications'),
  strict: z.boolean().default(true).describe('Enable strict validation mode'),
}).strict();

const DataStructureListSchema = z.object({
  organizationId: z.number().min(1).optional().describe('Filter by organization ID'),
  teamId: z.number().min(1).optional().describe('Filter by team ID'),
  searchQuery: z.string().max(100).optional().describe('Search in structure names and descriptions'),
  includeUsage: z.boolean().default(true).describe('Include usage statistics'),
  includeValidation: z.boolean().default(false).describe('Include validation details'),
  limit: z.number().min(1).max(1000).default(100).describe('Maximum number of structures to return'),
  offset: z.number().min(0).default(0).describe('Number of structures to skip for pagination'),
  sortBy: z.enum(['name', 'createdAt', 'updatedAt', 'usageCount', 'lastUsed']).default('name').describe('Sort field'),
  sortOrder: z.enum(['asc', 'desc']).default('asc').describe('Sort order'),
}).strict();

const DataStructureUpdateSchema = z.object({
  id: z.number().min(1).describe('Data structure ID to update'),
  name: z.string().min(1).max(100).optional().describe('Updated structure name'),
  description: z.string().max(500).optional().describe('Updated structure description'),
  specification: z.array(DataStructureFieldSchema).optional().describe('Updated field specifications'),
  strict: z.boolean().optional().describe('Updated strict validation mode'),
  migrationOptions: z.object({
    preserveData: z.boolean().default(true).describe('Preserve existing data during migration'),
    backupFirst: z.boolean().default(true).describe('Create backup before migration'),
    validateBeforeUpdate: z.boolean().default(true).describe('Validate structure before applying'),
  }).default({}).describe('Migration configuration'),
}).strict();

/**
 * Add folder organization and data store tools to FastMCP server
 */
export function addFolderTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'FolderTools' });
  
  componentLogger.info('Adding folder organization and data store tools');

  // Create folder
  server.addTool({
    name: 'create-folder',
    description: 'Create a new folder for organizing templates, scenarios, and connections',
    annotations: {
      title: 'Create Folder',
      idempotentHint: true,
      openWorldHint: true,
    },
    parameters: FolderCreateSchema,
    execute: async (input, { log }) => {
      const { name, description, parentId, type, organizationId, teamId, permissions } = input;

      log.info('Creating folder', {
        name,
        type,
        parentId,
        organizationId,
        teamId,
      });

      try {
        // Validate parent folder exists if specified
        if (parentId) {
          const parentResponse = await apiClient.get(`/folders/${parentId}`);
          if (!parentResponse.success) {
            throw new UserError(`Parent folder with ID ${parentId} not found`);
          }
        }

        const folderData = {
          name,
          description,
          parentId,
          type,
          organizationId,
          teamId,
          permissions: {
            ...permissions,
            read: permissions?.read ?? [],
            write: permissions?.write ?? [],
            admin: permissions?.admin ?? [],
          },
        };

        let endpoint = '/folders';
        if (organizationId) {
          endpoint = `/organizations/${organizationId}/folders`;
        } else if (teamId) {
          endpoint = `/teams/${teamId}/folders`;
        }

        const response = await apiClient.post(endpoint, folderData);

        if (!response.success) {
          throw new UserError(`Failed to create folder: ${response.error?.message || 'Unknown error'}`);
        }

        const folder = response.data as MakeFolder;
        if (!folder) {
          throw new UserError('Folder creation failed - no data returned');
        }

        log.info('Successfully created folder', {
          folderId: folder.id,
          name: folder.name,
          type: folder.type,
          path: folder.path,
        });

        return JSON.stringify({
          folder,
          message: `Folder "${name}" created successfully`,
          organization: {
            path: folder.path,
            type: folder.type,
            permissions: {
              readAccess: folder.permissions.read.length,
              writeAccess: folder.permissions.write.length,
              adminAccess: folder.permissions.admin.length,
            },
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error creating folder', { name, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to create folder: ${errorMessage}`);
      }
    },
  });

  // List folders
  server.addTool({
    name: 'list-folders',
    description: 'List and filter folders with organizational hierarchy',
    annotations: {
      title: 'List Folders',
      readOnlyHint: true,
      openWorldHint: true,
    },
    parameters: FolderListSchema,
    execute: async (input, { log }) => {
      const { parentId, type, organizationId, teamId, searchQuery, includeEmpty, includeContents, limit, offset, sortBy, sortOrder } = input;

      log.info('Listing folders', {
        parentId,
        type,
        searchQuery,
        limit,
        offset,
      });

      try {
        const params: Record<string, unknown> = {
          limit,
          offset,
          sortBy,
          sortOrder,
          includeEmpty,
          includeContents,
        };

        if (parentId) params.parentId = parentId;
        if (type !== 'all') params.type = type;
        if (organizationId) params.organizationId = organizationId;
        if (teamId) params.teamId = teamId;
        if (searchQuery) params.search = searchQuery;

        const response = await apiClient.get('/folders', { params });

        if (!response.success) {
          throw new UserError(`Failed to list folders: ${response.error?.message || 'Unknown error'}`);
        }

        const folders = response.data as MakeFolder[] || [];
        const metadata = response.metadata;

        log.info('Successfully retrieved folders', {
          count: folders.length,
          total: metadata?.total,
        });

        // Create folder hierarchy visualization
        const hierarchy = buildFolderHierarchy(folders);

        // Create summary statistics
        const summary = {
          totalFolders: metadata?.total || folders.length,
          typeBreakdown: {
            template: folders.filter(f => f.type === 'template').length,
            scenario: folders.filter(f => f.type === 'scenario').length,
            connection: folders.filter(f => f.type === 'connection').length,
            mixed: folders.filter(f => f.type === 'mixed').length,
          },
          contentSummary: {
            totalItems: folders.reduce((sum, f) => sum + f.itemCount.total, 0),
            templates: folders.reduce((sum, f) => sum + f.itemCount.templates, 0),
            scenarios: folders.reduce((sum, f) => sum + f.itemCount.scenarios, 0),
            connections: folders.reduce((sum, f) => sum + f.itemCount.connections, 0),
            subfolders: folders.reduce((sum, f) => sum + f.itemCount.subfolders, 0),
          },
          emptyFolders: folders.filter(f => f.itemCount.total === 0).length,
          largestFolder: folders.reduce((max, f) => 
            f.itemCount.total > (max?.itemCount.total || 0) ? f : max, folders[0]),
          mostRecentActivity: folders
            .filter(f => f.metadata.lastActivity)
            .sort((a, b) => new Date(b.metadata.lastActivity).getTime() - new Date(a.metadata.lastActivity).getTime())[0],
        };

        return JSON.stringify({
          folders,
          hierarchy: includeContents ? hierarchy : undefined,
          summary,
          pagination: {
            total: metadata?.total || folders.length,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + folders.length),
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error listing folders', { error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to list folders: ${errorMessage}`);
      }
    },
  });

  // Get folder contents
  server.addTool({
    name: 'get-folder-contents',
    description: 'Get detailed contents of a specific folder',
    annotations: {
      title: 'Get Folder Contents',
      readOnlyHint: true,
      openWorldHint: true,
    },
    parameters: z.object({
      folderId: z.number().min(1).describe('Folder ID to get contents for'),
      contentType: z.enum(['all', 'templates', 'scenarios', 'connections', 'subfolders']).default('all').describe('Filter content type'),
      includeMetadata: z.boolean().default(true).describe('Include item metadata'),
      limit: z.number().min(1).max(1000).default(100).describe('Maximum number of items to return'),
      offset: z.number().min(0).default(0).describe('Number of items to skip for pagination'),
    }),
    execute: async (input, { log }) => {
      const { folderId, contentType, includeMetadata, limit, offset } = input;

      log.info('Getting folder contents', { folderId, contentType });

      try {
        const params: Record<string, unknown> = {
          contentType,
          includeMetadata,
          limit,
          offset,
        };

        const response = await apiClient.get(`/folders/${folderId}/contents`, { params });

        if (!response.success) {
          throw new UserError(`Failed to get folder contents: ${response.error?.message || 'Unknown error'}`);
        }

        const contents = response.data as Record<string, unknown>;
        const metadata = response.metadata;

        log.info('Successfully retrieved folder contents', {
          folderId,
          itemCount: (contents?.items as unknown[])?.length || 0,
        });

        return JSON.stringify({
          folder: contents?.folder,
          contents: (contents?.items as unknown[]) || [],
          summary: {
            totalItems: metadata?.total || 0,
            itemBreakdown: contents?.breakdown || {},
            folderInfo: {
              name: (contents?.folder as Record<string, unknown>)?.name,
              path: (contents?.folder as Record<string, unknown>)?.path,
              type: (contents?.folder as Record<string, unknown>)?.type,
            },
          },
          pagination: {
            total: metadata?.total || 0,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + ((contents?.items as unknown[])?.length || 0)),
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error getting folder contents', { folderId, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to get folder contents: ${errorMessage}`);
      }
    },
  });

  // Move items between folders
  server.addTool({
    name: 'move-items',
    description: 'Move or copy items between folders with bulk operations',
    parameters: MoveItemsSchema,
    execute: async (input, { log, reportProgress }) => {
      const { items, targetFolderId, copyInsteadOfMove } = input;

      log.info('Moving/copying items', {
        itemCount: items.length,
        targetFolderId,
        operation: copyInsteadOfMove ? 'copy' : 'move',
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        // Validate target folder exists if specified
        if (targetFolderId) {
          const targetResponse = await apiClient.get(`/folders/${targetFolderId}`);
          if (!targetResponse.success) {
            throw new UserError(`Target folder with ID ${targetFolderId} not found`);
          }
        }

        reportProgress({ progress: 25, total: 100 });

        const moveData = {
          items,
          targetFolderId,
          operation: copyInsteadOfMove ? 'copy' : 'move',
        };

        const response = await apiClient.post('/folders/move-items', moveData);

        if (!response.success) {
          throw new UserError(`Failed to ${copyInsteadOfMove ? 'copy' : 'move'} items: ${response.error?.message || 'Unknown error'}`);
        }

        const result = response.data as Record<string, unknown>;
        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully moved/copied items', {
          operation: copyInsteadOfMove ? 'copy' : 'move',
          successful: Number(result?.successful || 0),
          failed: Number(result?.failed || 0),
        });

        return JSON.stringify({
          result,
          message: `Successfully ${copyInsteadOfMove ? 'copied' : 'moved'} ${result?.successful || 0} items`,
          summary: {
            operation: copyInsteadOfMove ? 'copy' : 'move',
            requestedItems: items.length,
            successfulOperations: result?.successful || 0,
            failedOperations: result?.failed || 0,
            targetFolder: targetFolderId ? result?.targetFolderName : 'Root',
          },
          errors: result?.errors || [],
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error moving/copying items', { error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to ${copyInsteadOfMove ? 'copy' : 'move'} items: ${errorMessage}`);
      }
    },
  });

  // Create data store
  server.addTool({
    name: 'create-data-store',
    description: 'Create a new data store for persistent data management',
    parameters: DataStoreCreateSchema,
    execute: async (input, { log }) => {
      const { name, description, type, organizationId, teamId, structure, settings, permissions } = input;

      log.info('Creating data store', {
        name,
        type,
        organizationId,
        teamId,
      });

      try {
        // Validate structure for data_structure type
        if (type === 'data_structure') {
          if (!structure?.fields || structure.fields.length === 0) {
            throw new UserError('Data structure type requires field definitions');
          }
          
          // Validate field names are unique
          const fieldNames = structure.fields.map(f => f.name);
          if (new Set(fieldNames).size !== fieldNames.length) {
            throw new UserError('Field names must be unique within the data structure');
          }
        }

        const dataStoreData = {
          name,
          description,
          type,
          organizationId,
          teamId,
          structure: structure || {},
          settings: {
            ...settings,
            maxSize: settings?.maxSize ?? 100,
            autoCleanup: settings?.autoCleanup ?? false,
            encryption: settings?.encryption ?? false,
            compression: settings?.compression ?? false,
          },
          permissions: {
            ...permissions,
            read: permissions?.read ?? [],
            write: permissions?.write ?? [],
            admin: permissions?.admin ?? [],
          },
        };

        let endpoint = '/data-stores';
        if (organizationId) {
          endpoint = `/organizations/${organizationId}/data-stores`;
        } else if (teamId) {
          endpoint = `/teams/${teamId}/data-stores`;
        }

        const response = await apiClient.post(endpoint, dataStoreData);

        if (!response.success) {
          throw new UserError(`Failed to create data store: ${response.error?.message || 'Unknown error'}`);
        }

        const dataStore = response.data as MakeDataStore;
        if (!dataStore) {
          throw new UserError('Data store creation failed - no data returned');
        }

        log.info('Successfully created data store', {
          dataStoreId: dataStore.id,
          name: dataStore.name,
          type: dataStore.type,
        });

        return JSON.stringify({
          dataStore,
          message: `Data store "${name}" created successfully`,
          configuration: {
            type: dataStore.type,
            maxSize: `${dataStore.settings.maxSize} MB`,
            encryption: dataStore.settings.encryption,
            compression: dataStore.settings.compression,
            fieldCount: dataStore.structure.fields?.length || 0,
            indexCount: dataStore.structure.indexes?.length || 0,
          },
          permissions: {
            readAccess: dataStore.permissions.read.length,
            writeAccess: dataStore.permissions.write.length,
            adminAccess: dataStore.permissions.admin.length,
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error creating data store', { name, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to create data store: ${errorMessage}`);
      }
    },
  });

  // List data stores
  server.addTool({
    name: 'list-data-stores',
    description: 'List and filter data stores with usage information',
    parameters: z.object({
      type: z.enum(['data_structure', 'key_value', 'queue', 'cache', 'all']).default('all').describe('Filter by data store type'),
      organizationId: z.number().min(1).optional().describe('Filter by organization ID'),
      teamId: z.number().min(1).optional().describe('Filter by team ID'),
      includeUsage: z.boolean().default(true).describe('Include usage statistics'),
      includeStructure: z.boolean().default(false).describe('Include data structure details'),
      limit: z.number().min(1).max(1000).default(100).describe('Maximum number of data stores to return'),
      offset: z.number().min(0).default(0).describe('Number of data stores to skip for pagination'),
      sortBy: z.enum(['name', 'type', 'createdAt', 'recordCount', 'sizeUsed']).default('name').describe('Sort field'),
      sortOrder: z.enum(['asc', 'desc']).default('asc').describe('Sort order'),
    }),
    execute: async (input, { log }) => {
      const { type, organizationId, teamId, includeUsage, includeStructure, limit, offset, sortBy, sortOrder } = input;

      log.info('Listing data stores', {
        type,
        organizationId,
        teamId,
        limit,
        offset,
      });

      try {
        const params: Record<string, unknown> = {
          limit,
          offset,
          sortBy,
          sortOrder,
          includeUsage,
          includeStructure,
        };

        if (type !== 'all') params.type = type;
        if (organizationId) params.organizationId = organizationId;
        if (teamId) params.teamId = teamId;

        const response = await apiClient.get('/data-stores', { params });

        if (!response.success) {
          throw new UserError(`Failed to list data stores: ${response.error?.message || 'Unknown error'}`);
        }

        const dataStores = response.data as MakeDataStore[] || [];
        const metadata = response.metadata;

        log.info('Successfully retrieved data stores', {
          count: dataStores.length,
          total: metadata?.total,
        });

        // Create summary statistics
        const summary = {
          totalDataStores: metadata?.total || dataStores.length,
          typeBreakdown: {
            data_structure: dataStores.filter(ds => ds.type === 'data_structure').length,
            key_value: dataStores.filter(ds => ds.type === 'key_value').length,
            queue: dataStores.filter(ds => ds.type === 'queue').length,
            cache: dataStores.filter(ds => ds.type === 'cache').length,
          },
          usageSummary: includeUsage ? {
            totalRecords: dataStores.reduce((sum, ds) => sum + ds.usage.recordCount, 0),
            totalSizeUsed: dataStores.reduce((sum, ds) => sum + ds.usage.sizeUsed, 0),
            totalOperationsToday: dataStores.reduce((sum, ds) => sum + ds.usage.operationsToday, 0),
            mostActiveStore: dataStores.reduce((max, ds) => 
              ds.usage.operationsToday > (max?.usage.operationsToday || 0) ? ds : max, dataStores[0]),
          } : undefined,
          storageAnalysis: {
            totalCapacity: dataStores.reduce((sum, ds) => sum + ds.settings.maxSize * 1024 * 1024, 0), // bytes
            totalUsed: dataStores.reduce((sum, ds) => sum + ds.usage.sizeUsed, 0),
            utilizationRate: dataStores.length > 0 ? 
              (dataStores.reduce((sum, ds) => sum + (ds.usage.sizeUsed / (ds.settings.maxSize * 1024 * 1024)), 0) / dataStores.length * 100).toFixed(2) + '%' : '0%',
          },
        };

        return JSON.stringify({
          dataStores,
          summary,
          pagination: {
            total: metadata?.total || dataStores.length,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + dataStores.length),
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error listing data stores', { error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to list data stores: ${errorMessage}`);
      }
    },
  });

  // List data structures
  server.addTool({
    name: 'list-data-structures',
    description: 'List and filter data structures with usage and validation information',
    parameters: DataStructureListSchema,
    execute: async (input, { log }) => {
      const { organizationId, teamId, searchQuery, includeUsage, includeValidation, limit, offset, sortBy, sortOrder } = input;

      log.info('Listing data structures', {
        organizationId,
        teamId,
        searchQuery,
        limit,
        offset,
      });

      try {
        const params: Record<string, unknown> = {
          limit,
          offset,
          sortBy,
          sortOrder,
          includeUsage,
          includeValidation,
        };

        if (organizationId) params.organizationId = organizationId;
        if (teamId) params.teamId = teamId;
        if (searchQuery) params.search = searchQuery;

        const response = await apiClient.get('/data-structures', { params });

        if (!response.success) {
          throw new UserError(`Failed to list data structures: ${response.error?.message || 'Unknown error'}`);
        }

        const dataStructures = response.data as MakeDataStructure[] || [];
        const metadata = response.metadata;

        log.info('Successfully retrieved data structures', {
          count: dataStructures.length,
          total: metadata?.total,
        });

        // Create summary statistics
        const summary = {
          totalStructures: metadata?.total || dataStructures.length,
          fieldTypeBreakdown: {} as Record<string, number>,
          usageSummary: includeUsage ? {
            totalDataStores: dataStructures.reduce((sum, ds) => sum + ds.usage.dataStoresCount, 0),
            totalRecords: dataStructures.reduce((sum, ds) => sum + ds.usage.totalRecords, 0),
            mostUsedStructure: dataStructures.reduce((max, ds) => 
              ds.usage.dataStoresCount > (max?.usage.dataStoresCount || 0) ? ds : max, dataStructures[0]),
          } : undefined,
          validationSummary: includeValidation ? {
            strictModeEnabled: dataStructures.filter(ds => ds.strict).length,
            structuresWithErrors: dataStructures.filter(ds => (ds.validation.validationErrors || 0) > 0).length,
            avgFieldsPerStructure: dataStructures.length > 0 ? 
              (dataStructures.reduce((sum, ds) => sum + ds.specification.length, 0) / dataStructures.length).toFixed(1) : '0',
          } : undefined,
        };

        // Count field types
        dataStructures.forEach(structure => {
          structure.specification.forEach(field => {
            const fieldType = field.type;
            summary.fieldTypeBreakdown[fieldType] = (summary.fieldTypeBreakdown[fieldType] || 0) + 1;
          });
        });

        return JSON.stringify({
          dataStructures,
          summary,
          pagination: {
            total: metadata?.total || dataStructures.length,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + dataStructures.length),
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error listing data structures', { error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to list data structures: ${errorMessage}`);
      }
    },
  });

  // Get data structure details
  server.addTool({
    name: 'get-data-structure',
    description: 'Get detailed information about a specific data structure',
    parameters: z.object({
      id: z.number().min(1).describe('Data structure ID'),
      includeUsage: z.boolean().default(true).describe('Include usage statistics'),
      includeValidation: z.boolean().default(true).describe('Include validation details'),
      includeDataStores: z.boolean().default(false).describe('Include associated data stores'),
    }),
    execute: async (input, { log }) => {
      const { id, includeUsage, includeValidation, includeDataStores } = input;

      log.info('Getting data structure', { id });

      try {
        const params: Record<string, unknown> = {
          includeUsage,
          includeValidation,
          includeDataStores,
        };

        const response = await apiClient.get(`/data-structures/${id}`, { params });

        if (!response.success) {
          throw new UserError(`Failed to get data structure: ${response.error?.message || 'Unknown error'}`);
        }

        const dataStructure = response.data as MakeDataStructure;
        if (!dataStructure) {
          throw new UserError(`Data structure with ID ${id} not found`);
        }

        log.info('Successfully retrieved data structure', {
          id: dataStructure.id,
          name: dataStructure.name,
          fieldCount: dataStructure.specification.length,
        });

        // Analyze field complexity
        const analysis = {
          fieldAnalysis: {
            totalFields: dataStructure.specification.length,
            requiredFields: dataStructure.specification.filter(f => f.required).length,
            fieldsWithConstraints: dataStructure.specification.filter(f => f.constraints).length,
            fieldTypes: dataStructure.specification.reduce((types, field) => {
              types[field.type] = (types[field.type] || 0) + 1;
              return types;
            }, {} as Record<string, number>),
            complexFields: dataStructure.specification.filter(f => f.type === 'collection' || f.type === 'array').length,
          },
          validationComplexity: {
            strictMode: dataStructure.strict,
            validationRules: dataStructure.validation.rules.length,
            hasErrors: (dataStructure.validation.validationErrors || 0) > 0,
            errorCount: dataStructure.validation.validationErrors || 0,
          },
        };

        const result: Record<string, unknown> = {
          dataStructure,
          analysis,
        };

        const extendedResponse = response as typeof response & { dataStores?: Array<{ usage: { recordCount: number } }> };
        if (includeDataStores && extendedResponse.dataStores) {
          result.associatedDataStores = extendedResponse.dataStores;
          result.dataStoresSummary = {
            count: extendedResponse.dataStores.length,
            totalRecords: extendedResponse.dataStores.reduce((sum, ds) => sum + ds.usage.recordCount, 0),
          };
        }

        return JSON.stringify(result, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error getting data structure', { id, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to get data structure: ${errorMessage}`);
      }
    },
  });

  // Create data structure
  server.addTool({
    name: 'create-data-structure',
    description: 'Create a new data structure with field specifications and validation rules',
    parameters: DataStructureCreateSchema,
    execute: async (input, { log }) => {
      const { name, description, organizationId, teamId, specification, strict } = input;

      log.info('Creating data structure', {
        name,
        fieldCount: specification.length,
        organizationId,
        teamId,
        strict,
      });

      try {
        // Validate field specifications
        const fieldNames = specification.map(f => f.name);
        if (new Set(fieldNames).size !== fieldNames.length) {
          throw new UserError('Field names must be unique within the data structure');
        }

        // Validate field constraints
        for (const field of specification) {
          if (field.constraints) {
            if (field.constraints.minLength !== undefined && field.constraints.maxLength !== undefined) {
              if (field.constraints.minLength > field.constraints.maxLength) {
                throw new UserError(`Field "${field.name}": minLength cannot be greater than maxLength`);
              }
            }
            if (field.constraints.minimum !== undefined && field.constraints.maximum !== undefined) {
              if (field.constraints.minimum > field.constraints.maximum) {
                throw new UserError(`Field "${field.name}": minimum cannot be greater than maximum`);
              }
            }
          }
        }

        const structureData = {
          name,
          description,
          organizationId,
          teamId,
          specification,
          strict,
        };

        let endpoint = '/data-structures';
        if (organizationId) {
          endpoint = `/organizations/${organizationId}/data-structures`;
        } else if (teamId) {
          endpoint = `/teams/${teamId}/data-structures`;
        }

        const response = await apiClient.post(endpoint, structureData);

        if (!response.success) {
          throw new UserError(`Failed to create data structure: ${response.error?.message || 'Unknown error'}`);
        }

        const dataStructure = response.data as MakeDataStructure;
        if (!dataStructure) {
          throw new UserError('Data structure creation failed - no data returned');
        }

        log.info('Successfully created data structure', {
          id: dataStructure.id,
          name: dataStructure.name,
          fieldCount: dataStructure.specification.length,
        });

        return JSON.stringify({
          dataStructure,
          message: `Data structure "${name}" created successfully`,
          configuration: {
            fieldCount: dataStructure.specification.length,
            requiredFields: dataStructure.specification.filter(f => f.required).length,
            strictMode: dataStructure.strict,
            complexFields: dataStructure.specification.filter(f => f.type === 'collection' || f.type === 'array').length,
          },
          validationRules: dataStructure.validation.rules,
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error creating data structure', { name, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to create data structure: ${errorMessage}`);
      }
    },
  });

  // Update data structure
  server.addTool({
    name: 'update-data-structure',
    description: 'Update an existing data structure with migration support',
    parameters: DataStructureUpdateSchema,
    execute: async (input, { log, reportProgress }) => {
      const { id, name, description, specification, strict, migrationOptions } = input;

      log.info('Updating data structure', {
        id,
        name,
        hasNewSpecification: !!specification,
        migrationOptions,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        // Get current structure for validation
        const currentResponse = await apiClient.get(`/data-structures/${id}`);
        if (!currentResponse.success) {
          throw new UserError(`Data structure with ID ${id} not found`);
        }

        const currentStructure = currentResponse.data as MakeDataStructure;
        reportProgress({ progress: 25, total: 100 });

        // Validate migration if specification is changing
        if (specification && migrationOptions.validateBeforeUpdate) {
          log.info('Validating structure migration', { id });
          
          // Check for breaking changes
          const breakingChanges = validateStructureChanges(currentStructure.specification, specification);
          if (breakingChanges.length > 0 && !migrationOptions.preserveData) {
            throw new UserError(`Breaking changes detected that may cause data loss: ${breakingChanges.join(', ')}`);
          }
        }

        reportProgress({ progress: 50, total: 100 });

        const updateData: Record<string, unknown> = {};
        if (name) updateData.name = name;
        if (description !== undefined) updateData.description = description;
        if (specification) updateData.specification = specification;
        if (strict !== undefined) updateData.strict = strict;
        if (Object.keys(migrationOptions).length > 0) updateData.migrationOptions = migrationOptions;

        const response = await apiClient.patch(`/data-structures/${id}`, updateData);

        if (!response.success) {
          throw new UserError(`Failed to update data structure: ${response.error?.message || 'Unknown error'}`);
        }

        const updatedStructure = response.data as MakeDataStructure;
        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully updated data structure', {
          id: updatedStructure.id,
          name: updatedStructure.name,
          fieldCount: updatedStructure.specification.length,
        });

        return JSON.stringify({
          dataStructure: updatedStructure,
          message: `Data structure "${updatedStructure.name}" updated successfully`,
          changes: {
            nameChanged: currentStructure.name !== updatedStructure.name,
            specificationChanged: JSON.stringify(currentStructure.specification) !== JSON.stringify(updatedStructure.specification),
            strictModeChanged: currentStructure.strict !== updatedStructure.strict,
            fieldCount: {
              before: currentStructure.specification.length,
              after: updatedStructure.specification.length,
            },
          },
          migration: (response as typeof response & { migration?: unknown }).migration || null,
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error updating data structure', { id, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to update data structure: ${errorMessage}`);
      }
    },
  });

  // Delete data structure
  server.addTool({
    name: 'delete-data-structure',
    description: 'Delete a data structure with dependency checking and confirmation',
    parameters: z.object({
      id: z.number().min(1).describe('Data structure ID to delete'),
      force: z.boolean().default(false).describe('Force deletion even with associated data stores'),
      confirmDeletion: z.boolean().default(false).describe('Confirm deletion of the data structure'),
    }),
    execute: async (input, { log }) => {
      const { id, force, confirmDeletion } = input;

      log.info('Deleting data structure', { id, force, confirmDeletion });

      try {
        // Get structure details and check dependencies
        const structureResponse = await apiClient.get(`/data-structures/${id}`, {
          params: { includeDataStores: true }
        });
        
        if (!structureResponse.success) {
          throw new UserError(`Data structure with ID ${id} not found`);
        }

        const dataStructure = structureResponse.data as MakeDataStructure;
        const extendedStructureResponse = structureResponse as typeof structureResponse & { dataStores?: Array<{ id: number; name: string }> };
        const associatedStores = extendedStructureResponse.dataStores || [];

        // Check for dependencies
        if (associatedStores.length > 0 && !force) {
          throw new UserError(
            `Cannot delete data structure "${dataStructure.name}" - it has ${associatedStores.length} associated data stores. ` +
            `Use force=true to delete anyway or delete the data stores first. ` +
            `Associated stores: ${associatedStores.map(s => s.name).join(', ')}`
          );
        }

        // Require confirmation for deletion
        if (!confirmDeletion) {
          return JSON.stringify({
            action: 'confirmation_required',
            dataStructure: {
              id: dataStructure.id,
              name: dataStructure.name,
              fieldCount: dataStructure.specification.length,
            },
            dependencies: {
              dataStoresCount: associatedStores.length,
              dataStores: associatedStores.map(s => ({ id: s.id, name: s.name })),
            },
            warning: associatedStores.length > 0 ? 
              'This data structure has associated data stores that will become invalid after deletion.' : 
              'This action cannot be undone.',
            nextStep: 'Call this tool again with confirmDeletion=true to proceed with deletion',
          }, null, 2);
        }

        const response = await apiClient.delete(`/data-structures/${id}`, {
          data: { force }
        });

        if (!response.success) {
          throw new UserError(`Failed to delete data structure: ${response.error?.message || 'Unknown error'}`);
        }

        log.info('Successfully deleted data structure', {
          id,
          name: dataStructure.name,
          hadDependencies: associatedStores.length > 0,
        });

        return JSON.stringify({
          message: `Data structure "${dataStructure.name}" deleted successfully`,
          deletedStructure: {
            id: dataStructure.id,
            name: dataStructure.name,
            fieldCount: dataStructure.specification.length,
          },
          impact: {
            affectedDataStores: associatedStores.length,
            dataStoresInvalidated: force ? associatedStores.map(s => s.name) : [],
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error deleting data structure', { id, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to delete data structure: ${errorMessage}`);
      }
    },
  });

  // Get data store details
  server.addTool({
    name: 'get-data-store',
    description: 'Get detailed information about a specific data store',
    parameters: z.object({
      id: z.number().min(1).describe('Data store ID'),
      includeStructure: z.boolean().default(true).describe('Include data structure details'),
      includeUsage: z.boolean().default(true).describe('Include usage statistics'),
      includeRecords: z.boolean().default(false).describe('Include sample records'),
      recordsLimit: z.number().min(1).max(100).default(10).describe('Number of sample records to include'),
    }),
    execute: async (input, { log }) => {
      const { id, includeStructure, includeUsage, includeRecords, recordsLimit } = input;

      log.info('Getting data store', { id });

      try {
        const params: Record<string, unknown> = {
          includeStructure,
          includeUsage,
          includeRecords,
          recordsLimit,
        };

        const response = await apiClient.get(`/data-stores/${id}`, { params });

        if (!response.success) {
          throw new UserError(`Failed to get data store: ${response.error?.message || 'Unknown error'}`);
        }

        const dataStore = response.data as MakeDataStore;
        if (!dataStore) {
          throw new UserError(`Data store with ID ${id} not found`);
        }

        log.info('Successfully retrieved data store', {
          id: dataStore.id,
          name: dataStore.name,
          type: dataStore.type,
          recordCount: dataStore.usage.recordCount,
        });

        // Calculate utilization metrics
        const utilizationMetrics = {
          storageUtilization: {
            maxSize: dataStore.settings.maxSize * 1024 * 1024, // Convert MB to bytes
            currentSize: dataStore.usage.sizeUsed,
            utilizationPercentage: ((dataStore.usage.sizeUsed / (dataStore.settings.maxSize * 1024 * 1024)) * 100).toFixed(2) + '%',
            availableSpace: (dataStore.settings.maxSize * 1024 * 1024) - dataStore.usage.sizeUsed,
          },
          activityMetrics: {
            recordCount: dataStore.usage.recordCount,
            operationsToday: dataStore.usage.operationsToday,
            lastOperation: dataStore.usage.lastOperation,
            averageOperationsPerRecord: dataStore.usage.recordCount > 0 ? 
              (dataStore.usage.operationsToday / dataStore.usage.recordCount).toFixed(2) : '0',
          },
        };

        const result: Record<string, unknown> = {
          dataStore,
          metrics: utilizationMetrics,
        };

        const extendedResponse = response as typeof response & { 
          dataStructure?: MakeDataStructure;
          sampleRecords?: unknown[];
        };
        
        if (includeStructure && extendedResponse.dataStructure) {
          result.dataStructure = extendedResponse.dataStructure;
          result.structureSummary = {
            fieldCount: extendedResponse.dataStructure.specification.length,
            strictMode: extendedResponse.dataStructure.strict,
            validationEnabled: extendedResponse.dataStructure.validation.enabled,
          };
        }

        if (includeRecords && extendedResponse.sampleRecords) {
          result.sampleRecords = extendedResponse.sampleRecords;
          result.recordsSummary = {
            sampleCount: extendedResponse.sampleRecords.length,
            totalRecords: dataStore.usage.recordCount,
          };
        }

        return JSON.stringify(result, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error getting data store', { id, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to get data store: ${errorMessage}`);
      }
    },
  });

  // Update data store
  server.addTool({
    name: 'update-data-store',
    description: 'Update data store configuration and settings',
    parameters: z.object({
      id: z.number().min(1).describe('Data store ID to update'),
      name: z.string().min(1).max(100).optional().describe('Updated data store name'),
      description: z.string().max(500).optional().describe('Updated data store description'),
      settings: z.object({
        maxSize: z.number().min(1).max(10000).optional().describe('Updated maximum size in MB'),
        ttl: z.number().min(60).optional().describe('Updated time to live in seconds'),
        autoCleanup: z.boolean().optional().describe('Updated auto cleanup setting'),
        encryption: z.boolean().optional().describe('Updated encryption setting'),
        compression: z.boolean().optional().describe('Updated compression setting'),
      }).optional().describe('Updated data store settings'),
      permissions: z.object({
        read: z.array(z.string()).optional().describe('Updated read permissions'),
        write: z.array(z.string()).optional().describe('Updated write permissions'),
        admin: z.array(z.string()).optional().describe('Updated admin permissions'),
      }).optional().describe('Updated permissions'),
    }),
    execute: async (input, { log }) => {
      const { id, name, description, settings, permissions } = input;

      log.info('Updating data store', { id, name, settings });

      try {
        // Get current data store for comparison
        const currentResponse = await apiClient.get(`/data-stores/${id}`);
        if (!currentResponse.success) {
          throw new UserError(`Data store with ID ${id} not found`);
        }

        const currentStore = currentResponse.data as MakeDataStore;

        const updateData: Record<string, unknown> = {};
        if (name) updateData.name = name;
        if (description !== undefined) updateData.description = description;
        if (settings) updateData.settings = { ...currentStore.settings, ...settings };
        if (permissions) updateData.permissions = { ...currentStore.permissions, ...permissions };

        const response = await apiClient.patch(`/data-stores/${id}`, updateData);

        if (!response.success) {
          throw new UserError(`Failed to update data store: ${response.error?.message || 'Unknown error'}`);
        }

        const updatedStore = response.data as MakeDataStore;

        log.info('Successfully updated data store', {
          id: updatedStore.id,
          name: updatedStore.name,
          type: updatedStore.type,
        });

        return JSON.stringify({
          dataStore: updatedStore,
          message: `Data store "${updatedStore.name}" updated successfully`,
          changes: {
            nameChanged: currentStore.name !== updatedStore.name,
            settingsChanged: JSON.stringify(currentStore.settings) !== JSON.stringify(updatedStore.settings),
            permissionsChanged: JSON.stringify(currentStore.permissions) !== JSON.stringify(updatedStore.permissions),
            sizeLimitChanged: currentStore.settings.maxSize !== updatedStore.settings.maxSize,
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error updating data store', { id, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to update data store: ${errorMessage}`);
      }
    },
  });

  // Delete data store
  server.addTool({
    name: 'delete-data-store',
    description: 'Delete a data store with data preservation options',
    parameters: z.object({
      id: z.number().min(1).describe('Data store ID to delete'),
      confirmDeletion: z.boolean().default(false).describe('Confirm deletion of the data store'),
      exportData: z.boolean().default(false).describe('Export data before deletion'),
      exportFormat: z.enum(['json', 'csv']).default('json').describe('Export format for data backup'),
    }),
    execute: async (input, { log, reportProgress }) => {
      const { id, confirmDeletion, exportData, exportFormat } = input;

      log.info('Deleting data store', { id, confirmDeletion, exportData });

      try {
        reportProgress({ progress: 0, total: 100 });

        // Get data store details
        const storeResponse = await apiClient.get(`/data-stores/${id}`);
        if (!storeResponse.success) {
          throw new UserError(`Data store with ID ${id} not found`);
        }

        const dataStore = storeResponse.data as MakeDataStore;
        reportProgress({ progress: 25, total: 100 });

        // Require confirmation for deletion
        if (!confirmDeletion) {
          return JSON.stringify({
            action: 'confirmation_required',
            dataStore: {
              id: dataStore.id,
              name: dataStore.name,
              type: dataStore.type,
              recordCount: dataStore.usage.recordCount,
              sizeUsed: dataStore.usage.sizeUsed,
            },
            warning: `This will permanently delete all ${dataStore.usage.recordCount} records in the data store.`,
            recommendation: dataStore.usage.recordCount > 0 ? 
              'Consider exporting data first by setting exportData=true' : 
              'Data store appears to be empty, safe to delete',
            nextStep: 'Call this tool again with confirmDeletion=true to proceed with deletion',
          }, null, 2);
        }

        let exportResult = null;
        if (exportData && dataStore.usage.recordCount > 0) {
          reportProgress({ progress: 50, total: 100 });
          log.info('Exporting data before deletion', { id, format: exportFormat });
          
          const exportResponse = await apiClient.get(`/data-stores/${id}/export`, {
            params: { format: exportFormat }
          });
          
          if (exportResponse.success) {
            exportResult = {
              format: exportFormat,
              recordCount: dataStore.usage.recordCount,
              exportData: exportResponse.data,
              timestamp: new Date().toISOString(),
            };
          }
        }

        reportProgress({ progress: 75, total: 100 });

        const response = await apiClient.delete(`/data-stores/${id}`);

        if (!response.success) {
          throw new UserError(`Failed to delete data store: ${response.error?.message || 'Unknown error'}`);
        }

        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully deleted data store', {
          id,
          name: dataStore.name,
          recordsDeleted: dataStore.usage.recordCount,
          dataExported: !!exportResult,
        });

        const result: Record<string, unknown> = {
          message: `Data store "${dataStore.name}" deleted successfully`,
          deletedStore: {
            id: dataStore.id,
            name: dataStore.name,
            type: dataStore.type,
            recordCount: dataStore.usage.recordCount,
            sizeUsed: dataStore.usage.sizeUsed,
          },
        };

        if (exportResult) {
          result.dataExport = exportResult;
        }

        return JSON.stringify(result, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error deleting data store', { id, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to delete data store: ${errorMessage}`);
      }
    },
  });

  componentLogger.info('Folder organization, data store, and data structure lifecycle management tools added successfully');
}

// Helper function to validate structure changes for migration
function validateStructureChanges(currentSpec: Array<{ name: string; type: string; required?: boolean }>, 
                                 newSpec: Array<{ name: string; type: string; required?: boolean }>): string[] {
  const breakingChanges: string[] = [];
  
  // Check for removed fields
  const currentFields = new Set(currentSpec.map(f => f.name));
  const newFields = new Set(newSpec.map(f => f.name));
  
  for (const fieldName of currentFields) {
    if (!newFields.has(fieldName)) {
      breakingChanges.push(`Field "${fieldName}" removed`);
    }
  }
  
  // Check for type changes
  const currentFieldMap = new Map(currentSpec.map(f => [f.name, f]));
  const newFieldMap = new Map(newSpec.map(f => [f.name, f]));
  
  for (const [fieldName, currentField] of currentFieldMap) {
    const newField = newFieldMap.get(fieldName);
    if (newField) {
      if (currentField.type !== newField.type) {
        breakingChanges.push(`Field "${fieldName}" type changed from ${currentField.type} to ${newField.type}`);
      }
      if (!currentField.required && newField.required) {
        breakingChanges.push(`Field "${fieldName}" changed from optional to required`);
      }
    }
  }
  
  return breakingChanges;
}

// Helper function to build folder hierarchy
function buildFolderHierarchy(folders: MakeFolder[]): Array<MakeFolder & { children: Array<unknown> }> {
  const folderMap = new Map<number, MakeFolder & { children: Array<unknown> }>();
  const rootFolders: Array<MakeFolder & { children: Array<unknown> }> = [];

  // First pass: create folder objects
  folders.forEach(folder => {
    folderMap.set(folder.id, {
      ...folder,
      children: [],
    });
  });

  // Second pass: build hierarchy
  folders.forEach(folder => {
    const folderNode = folderMap.get(folder.id);
    if (!folderNode) return;
    
    if (folder.parentId) {
      const parent = folderMap.get(folder.parentId);
      if (parent) {
        parent.children.push(folderNode);
      } else {
        rootFolders.push(folderNode);
      }
    } else {
      rootFolders.push(folderNode);
    }
  });

  return rootFolders;
}

export default addFolderTools;