/**
 * Folder Organization Tools for Make.com FastMCP Server
 * Updated to use modular architecture from folders module refactoring
 */

import { FastMCP } from 'fastmcp';
import { MakeApiClient } from '../lib/make-api-client.js';
import logger from '../lib/logger.js';
import { z } from 'zod';
import type { ToolExecutionContext } from '../types/index.js';

// Import the modular tools from the refactored folders module
import { foldersTools } from './folders/tools/index.js';

/**
 * Add folder organization and data store tools to FastMCP server
 * Uses the new modular architecture with FoldersManager core business logic
 */
export function addFolderTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'FolderTools' });
  
  componentLogger.info('Adding modular folder organization and data store tools');

  // Create context for tools
  const createToolContext = (executionContext: ToolExecutionContext): {
    server: FastMCP;
    apiClient: MakeApiClient;
    logger: typeof componentLogger;
    log: ToolExecutionContext['log'];
    reportProgress: ToolExecutionContext['reportProgress'];
    config: {
      enabled: boolean;
      maxRetries: number;
      timeout: number;
    };
  } => ({
    server,
    apiClient,
    logger: componentLogger,
    log: executionContext.log,
    reportProgress: executionContext.reportProgress,
    config: {
      enabled: true,
      maxRetries: 3,
      timeout: 30000
    }
  });

  // Register all folder tools using the modular implementation
  // (toolContext will be created within each execute function)

  // Create Folder
  server.addTool({
    name: 'create-folder',
    description: 'Create a new folder for organizing templates, scenarios, and connections',
    annotations: {
      title: 'Create Folder',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    parameters: z.object({
      name: z.string().min(1).max(100).describe('Folder name (1-100 characters)'),
      description: z.string().max(500).optional().describe('Folder description (max 500 characters)'),
      parentId: z.number().min(1).optional().describe('Parent folder ID (for nested folders)'),
      type: z.enum(['template', 'scenario', 'connection', 'mixed']).describe('Folder content type'),
      organizationId: z.number().min(1).optional().describe('Organization ID (for organization folders)'),
      teamId: z.number().min(1).optional().describe('Team ID (for team folders)'),
      permissions: z.object({
        read: z.array(z.string()).describe('User/team IDs with read access'),
        write: z.array(z.string()).describe('User/team IDs with write access'),
        admin: z.array(z.string()).describe('User/team IDs with admin access'),
      }).optional().describe('Folder permissions')
    }),
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      const result = await foldersTools.createfolder(toolContext, args as Record<string, unknown>);
      if (result.error) {
        throw new Error(result.error);
      }
      return result.message || 'Folder created successfully';
    }
  });

  // List Folders
  server.addTool({
    name: 'list-folders',
    description: 'List and filter folders with organizational hierarchy',
    annotations: {
      title: 'List Folders',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    parameters: z.object({
      parentId: z.number().min(1).optional().describe('List folders under this parent (null for root)'),
      type: z.enum(['template', 'scenario', 'connection', 'mixed', 'all']).optional().describe('Filter by folder type'),
      organizationId: z.number().min(1).optional().describe('Filter by organization ID'),
      teamId: z.number().min(1).optional().describe('Filter by team ID'),
      searchQuery: z.string().max(100).optional().describe('Search in folder names and descriptions'),
      includeEmpty: z.boolean().optional().describe('Include empty folders'),
      includeContents: z.boolean().optional().describe('Include folder contents summary'),
      limit: z.number().min(1).max(1000).optional().describe('Maximum number of folders to return'),
      offset: z.number().min(0).optional().describe('Number of folders to skip for pagination'),
      sortBy: z.enum(['name', 'createdAt', 'updatedAt', 'itemCount', 'lastActivity']).optional().describe('Sort field'),
      sortOrder: z.enum(['asc', 'desc']).optional().describe('Sort order')
    }),
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      const result = await foldersTools.listfolders(toolContext, args as Record<string, unknown>);
      if (result.error) {
        throw new Error(result.error);
      }
      return result.message || 'Folders retrieved successfully';
    }
  });

  // Get Folder Contents
  server.addTool({
    name: 'get-folder-contents',
    description: 'Get detailed contents of a specific folder',
    annotations: {
      title: 'Get Folder Contents',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    parameters: z.object({
      folderId: z.number().min(1).describe('Folder ID to get contents for'),
      includeSubfolders: z.boolean().optional().describe('Include subfolders in contents'),
      includeTemplates: z.boolean().optional().describe('Include templates in contents'),
      includeScenarios: z.boolean().optional().describe('Include scenarios in contents'),
      includeConnections: z.boolean().optional().describe('Include connections in contents'),
      limit: z.number().min(1).max(1000).optional().describe('Maximum number of items to return'),
      offset: z.number().min(0).optional().describe('Number of items to skip for pagination')
    }),
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      const result = await foldersTools.getfoldercontents(toolContext, args as Record<string, unknown>);
      if (result.error) {
        throw new Error(result.error);
      }
      return result.message || 'Folder contents retrieved successfully';
    }
  });

  // Move Items
  server.addTool({
    name: 'move-items',
    description: 'Move or copy items between folders with bulk operations',
    annotations: {
      title: 'Move Items',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
    parameters: z.object({
      items: z.array(z.object({
        type: z.enum(['template', 'scenario', 'connection', 'folder']).describe('Item type'),
        id: z.number().min(1).describe('Item ID')
      })).min(1).max(100).describe('Items to move (max 100)'),
      targetFolderId: z.number().min(1).optional().describe('Target folder ID (null for root)'),
      copyInsteadOfMove: z.boolean().optional().describe('Copy items instead of moving them')
    }),
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      const result = await foldersTools.moveitems(toolContext, args as Record<string, unknown>);
      if (result.error) {
        throw new Error(result.error);
      }
      return result.message || 'Items moved/copied successfully';
    }
  });

  // Create Data Store
  server.addTool({
    name: 'create-data-store',
    description: 'Create a new data store for persistent data management',
    annotations: {
      title: 'Create Data Store',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
    parameters: z.object({
      name: z.string().min(1).max(100).describe('Data store name (1-100 characters)'),
      description: z.string().max(500).optional().describe('Data store description (max 500 characters)'),
      type: z.enum(['data_structure', 'key_value', 'queue', 'cache']).describe('Data store type'),
      organizationId: z.number().min(1).optional().describe('Organization ID (for organization data stores)'),
      teamId: z.number().min(1).optional().describe('Team ID (for team data stores)'),
      structure: z.object({
        fields: z.array(z.object({
          name: z.string().min(1).max(50).describe('Field name'),
          type: z.enum(['string', 'number', 'boolean', 'date', 'object', 'array']).describe('Field data type'),
          required: z.boolean().optional().describe('Whether field is required'),
          defaultValue: z.unknown().optional().describe('Default field value'),
          validation: z.object({
            min: z.number().optional().describe('Minimum value/length'),
            max: z.number().optional().describe('Maximum value/length'),
            pattern: z.string().optional().describe('Regex pattern for validation'),
            enum: z.array(z.unknown()).optional().describe('Allowed values')
          }).optional()
        })).optional().describe('Data structure fields (for data_structure type)'),
        indexes: z.array(z.object({
          fields: z.array(z.string()).min(1).describe('Fields to index'),
          unique: z.boolean().optional().describe('Whether index should be unique'),
          name: z.string().min(1).max(50).describe('Index name')
        })).optional().describe('Database indexes')
      }).optional().describe('Data structure definition'),
      settings: z.object({
        maxSize: z.number().min(1).max(10000).describe('Maximum size in MB'),
        ttl: z.number().min(60).optional().describe('Time to live in seconds'),
        autoCleanup: z.boolean().describe('Enable automatic cleanup'),
        encryption: z.boolean().describe('Enable data encryption'),
        compression: z.boolean().describe('Enable data compression')
      }),
      permissions: z.object({
        read: z.array(z.string()).describe('User/team IDs with read access'),
        write: z.array(z.string()).describe('User/team IDs with write access'),
        admin: z.array(z.string()).describe('User/team IDs with admin access')
      })
    }),
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      const result = await foldersTools.createdatastore(toolContext, args as Record<string, unknown>);
      if (result.error) {
        throw new Error(result.error);
      }
      return result.message || 'Data store created successfully';
    }
  });

  // List Data Stores
  server.addTool({
    name: 'list-data-stores',
    description: 'List and filter data stores with usage information',
    annotations: {
      title: 'List Data Stores',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    parameters: z.object({
      type: z.enum(['data_structure', 'key_value', 'queue', 'cache', 'all']).optional().describe('Filter by data store type'),
      organizationId: z.number().min(1).optional().describe('Filter by organization ID'),
      teamId: z.number().min(1).optional().describe('Filter by team ID'),
      searchQuery: z.string().max(100).optional().describe('Search in data store names and descriptions'),
      limit: z.number().min(1).max(1000).optional().describe('Maximum number of data stores to return'),
      offset: z.number().min(0).optional().describe('Number of data stores to skip for pagination'),
      sortBy: z.enum(['name', 'createdAt', 'updatedAt', 'recordCount', 'sizeUsed']).optional().describe('Sort field'),
      sortOrder: z.enum(['asc', 'desc']).optional().describe('Sort order')
    }),
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      const result = await foldersTools.listdatastores(toolContext, args as Record<string, unknown>);
      if (result.error) {
        throw new Error(result.error);
      }
      return result.message || 'Data stores retrieved successfully';
    }
  });

  // List Data Structures
  server.addTool({
    name: 'list-data-structures',
    description: 'List and filter data structures with usage and validation information',
    annotations: {
      title: 'List Data Structures',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    parameters: z.object({
      organizationId: z.number().min(1).optional().describe('Filter by organization ID'),
      teamId: z.number().min(1).optional().describe('Filter by team ID'),
      searchQuery: z.string().max(100).optional().describe('Search in structure names and descriptions'),
      limit: z.number().min(1).max(1000).optional().describe('Maximum number of structures to return'),
      offset: z.number().min(0).optional().describe('Number of structures to skip for pagination'),
      sortBy: z.enum(['name', 'createdAt', 'updatedAt', 'usage']).optional().describe('Sort field'),
      sortOrder: z.enum(['asc', 'desc']).optional().describe('Sort order')
    }),
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      const result = await foldersTools.listdatastructures(toolContext, args as Record<string, unknown>);
      if (result.error) {
        throw new Error(result.error);
      }
      return result.message || 'Data structures retrieved successfully';
    }
  });

  // Get Data Structure
  server.addTool({
    name: 'get-data-structure',
    description: 'Get detailed information about a specific data structure',
    annotations: {
      title: 'Get Data Structure',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    parameters: z.object({
      id: z.number().min(1).describe('Data structure ID')
    }),
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      const result = await foldersTools.getdatastructure(toolContext, args as Record<string, unknown>);
      if (result.error) {
        throw new Error(result.error);
      }
      return result.message || 'Data structure retrieved successfully';
    }
  });

  // Create Data Structure
  server.addTool({
    name: 'create-data-structure',
    description: 'Create a new data structure with field specifications and validation rules',
    annotations: {
      title: 'Create Data Structure',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
    parameters: z.object({
      name: z.string().min(1).max(100).describe('Data structure name (1-100 characters)'),
      description: z.string().max(500).optional().describe('Data structure description (max 500 characters)'),
      organizationId: z.number().min(1).optional().describe('Organization ID (for organization data structures)'),
      teamId: z.number().min(1).optional().describe('Team ID (for team data structures)'),
      specification: z.array(z.object({
        name: z.string().min(1).max(50).describe('Field name'),
        type: z.enum(['text', 'number', 'boolean', 'date', 'array', 'collection']).describe('Field data type'),
        required: z.boolean().optional().describe('Whether field is required'),
        default: z.unknown().optional().describe('Default field value'),
        constraints: z.object({
          minLength: z.number().min(0).optional().describe('Minimum text length'),
          maxLength: z.number().min(1).optional().describe('Maximum text length'),
          minimum: z.number().optional().describe('Minimum numeric value'),
          maximum: z.number().optional().describe('Maximum numeric value'),
          pattern: z.string().optional().describe('Regex pattern for text validation'),
          enum: z.array(z.unknown()).optional().describe('Allowed values')
        }).optional()
      })).min(1).describe('Field specifications'),
      strict: z.boolean().optional().describe('Enable strict validation mode'),
      validation: z.object({
        enabled: z.boolean().optional().describe('Enable validation'),
        rules: z.array(z.string()).optional().describe('Validation rules')
      }).optional()
    }),
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      const result = await foldersTools.createdatastructure(toolContext, args as Record<string, unknown>);
      if (result.error) {
        throw new Error(result.error);
      }
      return result.message || 'Data structure created successfully';
    }
  });

  // Update Data Structure
  server.addTool({
    name: 'update-data-structure',
    description: 'Update an existing data structure with migration support',
    annotations: {
      title: 'Update Data Structure',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    parameters: z.object({
      id: z.number().min(1).describe('Data structure ID to update'),
      name: z.string().min(1).max(100).optional().describe('Updated structure name'),
      description: z.string().max(500).optional().describe('Updated structure description'),
      specification: z.array(z.object({
        name: z.string().min(1).max(50).describe('Field name'),
        type: z.enum(['text', 'number', 'boolean', 'date', 'array', 'collection']).describe('Field data type'),
        required: z.boolean().optional().describe('Whether field is required'),
        default: z.unknown().optional().describe('Default field value')
      })).optional().describe('Updated field specifications'),
      strict: z.boolean().optional().describe('Updated strict validation mode'),
      validation: z.object({
        enabled: z.boolean().optional().describe('Enable validation'),
        rules: z.array(z.string()).optional().describe('Validation rules')
      }).optional()
    }),
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      const result = await foldersTools.updatedatastructure(toolContext, args as Record<string, unknown>);
      if (result.error) {
        throw new Error(result.error);
      }
      return result.message || 'Data structure updated successfully';
    }
  });

  // Delete Data Structure
  server.addTool({
    name: 'delete-data-structure',
    description: 'Delete a data structure with dependency checking and confirmation',
    annotations: {
      title: 'Delete Data Structure',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    parameters: z.object({
      id: z.number().min(1).describe('Data structure ID to delete')
    }),
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      const result = await foldersTools.deletedatastructure(toolContext, args as Record<string, unknown>);
      if (result.error) {
        throw new Error(result.error);
      }
      return result.message || 'Data structure deleted successfully';
    }
  });

  // Get Data Store
  server.addTool({
    name: 'get-data-store',
    description: 'Get detailed information about a specific data store',
    annotations: {
      title: 'Get Data Store',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    parameters: z.object({
      id: z.number().min(1).describe('Data store ID')
    }),
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      const result = await foldersTools.getdatastore(toolContext, args as Record<string, unknown>);
      if (result.error) {
        throw new Error(result.error);
      }
      return result.message || 'Data store retrieved successfully';
    }
  });

  // Update Data Store
  server.addTool({
    name: 'update-data-store',
    description: 'Update data store configuration and settings',
    annotations: {
      title: 'Update Data Store',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    parameters: z.object({
      id: z.number().min(1).describe('Data store ID to update'),
      name: z.string().min(1).max(100).optional().describe('Updated data store name'),
      description: z.string().max(500).optional().describe('Updated data store description'),
      settings: z.object({
        maxSize: z.number().min(1).max(10000).optional().describe('Updated maximum size in MB'),
        ttl: z.number().min(60).optional().describe('Updated time to live in seconds'),
        autoCleanup: z.boolean().optional().describe('Updated auto cleanup setting'),
        encryption: z.boolean().optional().describe('Updated encryption setting'),
        compression: z.boolean().optional().describe('Updated compression setting')
      }).optional(),
      permissions: z.object({
        read: z.array(z.string()).optional().describe('Updated read permissions'),
        write: z.array(z.string()).optional().describe('Updated write permissions'),
        admin: z.array(z.string()).optional().describe('Updated admin permissions')
      }).optional()
    }),
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      const result = await foldersTools.updatedatastore(toolContext, args as Record<string, unknown>);
      if (result.error) {
        throw new Error(result.error);
      }
      return result.message || 'Data store updated successfully';
    }
  });

  // Delete Data Store
  server.addTool({
    name: 'delete-data-store',
    description: 'Delete a data store with data preservation options',
    annotations: {
      title: 'Delete Data Store',
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    parameters: z.object({
      id: z.number().min(1).describe('Data store ID to delete')
    }),
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      const result = await foldersTools.deletedatastore(toolContext, args as Record<string, unknown>);
      if (result.error) {
        throw new Error(result.error);
      }
      return result.message || 'Data store deleted successfully';
    }
  });

  componentLogger.info('Modular folder organization, data store, and data structure tools added successfully');
}

export default addFolderTools;