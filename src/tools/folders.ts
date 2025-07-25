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
            read: [],
            write: [],
            admin: [],
            ...permissions,
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

        const contents = response.data;
        const metadata = response.metadata;

        log.info('Successfully retrieved folder contents', {
          folderId,
          itemCount: contents?.items?.length || 0,
        });

        return JSON.stringify({
          folder: contents?.folder,
          contents: contents?.items || [],
          summary: {
            totalItems: metadata?.total || 0,
            itemBreakdown: contents?.breakdown || {},
            folderInfo: {
              name: contents?.folder?.name,
              path: contents?.folder?.path,
              type: contents?.folder?.type,
            },
          },
          pagination: {
            total: metadata?.total || 0,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + (contents?.items?.length || 0)),
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

        const result = response.data;
        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully moved/copied items', {
          operation: copyInsteadOfMove ? 'copy' : 'move',
          successful: result?.successful || 0,
          failed: result?.failed || 0,
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
            maxSize: 100,
            autoCleanup: false,
            encryption: false,
            compression: false,
            ...settings,
          },
          permissions: {
            read: [],
            write: [],
            admin: [],
            ...permissions,
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

  componentLogger.info('Folder organization and data store tools added successfully');
}

// Helper function to build folder hierarchy
function buildFolderHierarchy(folders: MakeFolder[]): Array<MakeFolder & { children: Array<MakeFolder & { children?: Array<unknown> }> }> {
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