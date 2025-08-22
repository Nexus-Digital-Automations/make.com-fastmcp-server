/**
 * Folder Organization Tools for Make.com FastMCP Server
 * Updated to use modular architecture from folders module refactoring
 */

import { FastMCP } from 'fastmcp';
import { MakeApiClient } from '../lib/make-api-client.js';
import logger from '../lib/logger.js';

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
  const createToolContext = (executionContext: { log: any; reportProgress: any }): any => ({
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
    parameters: {
      type: 'object',
      properties: {
        name: { type: 'string', minLength: 1, maxLength: 100, description: 'Folder name (1-100 characters)' },
        description: { type: 'string', maxLength: 500, description: 'Folder description (max 500 characters)' },
        parentId: { type: 'number', minimum: 1, description: 'Parent folder ID (for nested folders)' },
        type: { type: 'string', enum: ['template', 'scenario', 'connection', 'mixed'], description: 'Folder content type' },
        organizationId: { type: 'number', minimum: 1, description: 'Organization ID (for organization folders)' },
        teamId: { type: 'number', minimum: 1, description: 'Team ID (for team folders)' },
        permissions: {
          type: 'object',
          properties: {
            read: { type: 'array', items: { type: 'string' }, description: 'User/team IDs with read access' },
            write: { type: 'array', items: { type: 'string' }, description: 'User/team IDs with write access' },
            admin: { type: 'array', items: { type: 'string' }, description: 'User/team IDs with admin access' },
          },
          description: 'Folder permissions'
        }
      },
      required: ['name', 'type']
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      const result = await foldersTools.createfolder(toolContext, args);
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
    parameters: {
      type: 'object',
      properties: {
        parentId: { type: 'number', minimum: 1, description: 'List folders under this parent (null for root)' },
        type: { type: 'string', enum: ['template', 'scenario', 'connection', 'mixed', 'all'], description: 'Filter by folder type' },
        organizationId: { type: 'number', minimum: 1, description: 'Filter by organization ID' },
        teamId: { type: 'number', minimum: 1, description: 'Filter by team ID' },
        searchQuery: { type: 'string', maxLength: 100, description: 'Search in folder names and descriptions' },
        includeEmpty: { type: 'boolean', description: 'Include empty folders' },
        includeContents: { type: 'boolean', description: 'Include folder contents summary' },
        limit: { type: 'number', minimum: 1, maximum: 1000, description: 'Maximum number of folders to return' },
        offset: { type: 'number', minimum: 0, description: 'Number of folders to skip for pagination' },
        sortBy: { type: 'string', enum: ['name', 'createdAt', 'updatedAt', 'itemCount', 'lastActivity'], description: 'Sort field' },
        sortOrder: { type: 'string', enum: ['asc', 'desc'], description: 'Sort order' }
      }
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      const result = await foldersTools.listfolders(toolContext, args);
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
    parameters: {
      type: 'object',
      properties: {
        folderId: { type: 'number', minimum: 1, description: 'Folder ID to get contents for' },
        includeSubfolders: { type: 'boolean', description: 'Include subfolders in contents' },
        includeTemplates: { type: 'boolean', description: 'Include templates in contents' },
        includeScenarios: { type: 'boolean', description: 'Include scenarios in contents' },
        includeConnections: { type: 'boolean', description: 'Include connections in contents' },
        limit: { type: 'number', minimum: 1, maximum: 1000, description: 'Maximum number of items to return' },
        offset: { type: 'number', minimum: 0, description: 'Number of items to skip for pagination' }
      },
      required: ['folderId']
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      const result = await foldersTools.getfoldercontents(toolContext, args);
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
    parameters: {
      type: 'object',
      properties: {
        items: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              type: { type: 'string', enum: ['template', 'scenario', 'connection', 'folder'], description: 'Item type' },
              id: { type: 'number', minimum: 1, description: 'Item ID' }
            },
            required: ['type', 'id']
          },
          minItems: 1,
          maxItems: 100,
          description: 'Items to move (max 100)'
        },
        targetFolderId: { type: 'number', minimum: 1, description: 'Target folder ID (null for root)' },
        copyInsteadOfMove: { type: 'boolean', description: 'Copy items instead of moving them' }
      },
      required: ['items']
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      const result = await foldersTools.moveitems(toolContext, args);
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
    parameters: {
      type: 'object',
      properties: {
        name: { type: 'string', minLength: 1, maxLength: 100, description: 'Data store name (1-100 characters)' },
        description: { type: 'string', maxLength: 500, description: 'Data store description (max 500 characters)' },
        type: { type: 'string', enum: ['data_structure', 'key_value', 'queue', 'cache'], description: 'Data store type' },
        organizationId: { type: 'number', minimum: 1, description: 'Organization ID (for organization data stores)' },
        teamId: { type: 'number', minimum: 1, description: 'Team ID (for team data stores)' },
        structure: {
          type: 'object',
          properties: {
            fields: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  name: { type: 'string', minLength: 1, maxLength: 50, description: 'Field name' },
                  type: { type: 'string', enum: ['string', 'number', 'boolean', 'date', 'object', 'array'], description: 'Field data type' },
                  required: { type: 'boolean', description: 'Whether field is required' },
                  defaultValue: { description: 'Default field value' },
                  validation: {
                    type: 'object',
                    properties: {
                      min: { type: 'number', description: 'Minimum value/length' },
                      max: { type: 'number', description: 'Maximum value/length' },
                      pattern: { type: 'string', description: 'Regex pattern for validation' },
                      enum: { type: 'array', description: 'Allowed values' }
                    }
                  }
                },
                required: ['name', 'type']
              },
              description: 'Data structure fields (for data_structure type)'
            },
            indexes: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  fields: { type: 'array', items: { type: 'string' }, minItems: 1, description: 'Fields to index' },
                  unique: { type: 'boolean', description: 'Whether index should be unique' },
                  name: { type: 'string', minLength: 1, maxLength: 50, description: 'Index name' }
                },
                required: ['fields', 'name']
              },
              description: 'Database indexes'
            }
          },
          description: 'Data structure definition'
        },
        settings: {
          type: 'object',
          properties: {
            maxSize: { type: 'number', minimum: 1, maximum: 10000, description: 'Maximum size in MB' },
            ttl: { type: 'number', minimum: 60, description: 'Time to live in seconds' },
            autoCleanup: { type: 'boolean', description: 'Enable automatic cleanup' },
            encryption: { type: 'boolean', description: 'Enable data encryption' },
            compression: { type: 'boolean', description: 'Enable data compression' }
          },
          required: ['maxSize', 'autoCleanup', 'encryption', 'compression']
        },
        permissions: {
          type: 'object',
          properties: {
            read: { type: 'array', items: { type: 'string' }, description: 'User/team IDs with read access' },
            write: { type: 'array', items: { type: 'string' }, description: 'User/team IDs with write access' },
            admin: { type: 'array', items: { type: 'string' }, description: 'User/team IDs with admin access' }
          },
          required: ['read', 'write', 'admin']
        }
      },
      required: ['name', 'type', 'settings', 'permissions']
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      const result = await foldersTools.createdatastore(toolContext, args);
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
    parameters: {
      type: 'object',
      properties: {
        type: { type: 'string', enum: ['data_structure', 'key_value', 'queue', 'cache', 'all'], description: 'Filter by data store type' },
        organizationId: { type: 'number', minimum: 1, description: 'Filter by organization ID' },
        teamId: { type: 'number', minimum: 1, description: 'Filter by team ID' },
        searchQuery: { type: 'string', maxLength: 100, description: 'Search in data store names and descriptions' },
        limit: { type: 'number', minimum: 1, maximum: 1000, description: 'Maximum number of data stores to return' },
        offset: { type: 'number', minimum: 0, description: 'Number of data stores to skip for pagination' },
        sortBy: { type: 'string', enum: ['name', 'createdAt', 'updatedAt', 'recordCount', 'sizeUsed'], description: 'Sort field' },
        sortOrder: { type: 'string', enum: ['asc', 'desc'], description: 'Sort order' }
      }
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      const result = await foldersTools.listdatastores(toolContext, args);
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
    parameters: {
      type: 'object',
      properties: {
        organizationId: { type: 'number', minimum: 1, description: 'Filter by organization ID' },
        teamId: { type: 'number', minimum: 1, description: 'Filter by team ID' },
        searchQuery: { type: 'string', maxLength: 100, description: 'Search in structure names and descriptions' },
        limit: { type: 'number', minimum: 1, maximum: 1000, description: 'Maximum number of structures to return' },
        offset: { type: 'number', minimum: 0, description: 'Number of structures to skip for pagination' },
        sortBy: { type: 'string', enum: ['name', 'createdAt', 'updatedAt', 'usage'], description: 'Sort field' },
        sortOrder: { type: 'string', enum: ['asc', 'desc'], description: 'Sort order' }
      }
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      const result = await foldersTools.listdatastructures(toolContext, args);
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
    parameters: {
      type: 'object',
      properties: {
        id: { type: 'number', minimum: 1, description: 'Data structure ID' }
      },
      required: ['id']
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      const result = await foldersTools.getdatastructure(toolContext, args);
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
    parameters: {
      type: 'object',
      properties: {
        name: { type: 'string', minLength: 1, maxLength: 100, description: 'Data structure name (1-100 characters)' },
        description: { type: 'string', maxLength: 500, description: 'Data structure description (max 500 characters)' },
        organizationId: { type: 'number', minimum: 1, description: 'Organization ID (for organization data structures)' },
        teamId: { type: 'number', minimum: 1, description: 'Team ID (for team data structures)' },
        specification: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              name: { type: 'string', minLength: 1, maxLength: 50, description: 'Field name' },
              type: { type: 'string', enum: ['text', 'number', 'boolean', 'date', 'array', 'collection'], description: 'Field data type' },
              required: { type: 'boolean', description: 'Whether field is required' },
              default: { description: 'Default field value' },
              constraints: {
                type: 'object',
                properties: {
                  minLength: { type: 'number', minimum: 0, description: 'Minimum text length' },
                  maxLength: { type: 'number', minimum: 1, description: 'Maximum text length' },
                  minimum: { type: 'number', description: 'Minimum numeric value' },
                  maximum: { type: 'number', description: 'Maximum numeric value' },
                  pattern: { type: 'string', description: 'Regex pattern for text validation' },
                  enum: { type: 'array', description: 'Allowed values' }
                }
              }
            },
            required: ['name', 'type']
          },
          minItems: 1,
          description: 'Field specifications'
        },
        strict: { type: 'boolean', description: 'Enable strict validation mode' },
        validation: {
          type: 'object',
          properties: {
            enabled: { type: 'boolean', description: 'Enable validation' },
            rules: { type: 'array', items: { type: 'string' }, description: 'Validation rules' }
          }
        }
      },
      required: ['name', 'specification']
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      const result = await foldersTools.createdatastructure(toolContext, args);
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
    parameters: {
      type: 'object',
      properties: {
        id: { type: 'number', minimum: 1, description: 'Data structure ID to update' },
        name: { type: 'string', minLength: 1, maxLength: 100, description: 'Updated structure name' },
        description: { type: 'string', maxLength: 500, description: 'Updated structure description' },
        specification: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              name: { type: 'string', minLength: 1, maxLength: 50, description: 'Field name' },
              type: { type: 'string', enum: ['text', 'number', 'boolean', 'date', 'array', 'collection'], description: 'Field data type' },
              required: { type: 'boolean', description: 'Whether field is required' },
              default: { description: 'Default field value' }
            },
            required: ['name', 'type']
          },
          description: 'Updated field specifications'
        },
        strict: { type: 'boolean', description: 'Updated strict validation mode' },
        validation: {
          type: 'object',
          properties: {
            enabled: { type: 'boolean', description: 'Enable validation' },
            rules: { type: 'array', items: { type: 'string' }, description: 'Validation rules' }
          }
        }
      },
      required: ['id']
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      const result = await foldersTools.updatedatastructure(toolContext, args);
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
    parameters: {
      type: 'object',
      properties: {
        id: { type: 'number', minimum: 1, description: 'Data structure ID to delete' }
      },
      required: ['id']
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      const result = await foldersTools.deletedatastructure(toolContext, args);
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
    parameters: {
      type: 'object',
      properties: {
        id: { type: 'number', minimum: 1, description: 'Data store ID' }
      },
      required: ['id']
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      const result = await foldersTools.getdatastore(toolContext, args);
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
    parameters: {
      type: 'object',
      properties: {
        id: { type: 'number', minimum: 1, description: 'Data store ID to update' },
        name: { type: 'string', minLength: 1, maxLength: 100, description: 'Updated data store name' },
        description: { type: 'string', maxLength: 500, description: 'Updated data store description' },
        settings: {
          type: 'object',
          properties: {
            maxSize: { type: 'number', minimum: 1, maximum: 10000, description: 'Updated maximum size in MB' },
            ttl: { type: 'number', minimum: 60, description: 'Updated time to live in seconds' },
            autoCleanup: { type: 'boolean', description: 'Updated auto cleanup setting' },
            encryption: { type: 'boolean', description: 'Updated encryption setting' },
            compression: { type: 'boolean', description: 'Updated compression setting' }
          }
        },
        permissions: {
          type: 'object',
          properties: {
            read: { type: 'array', items: { type: 'string' }, description: 'Updated read permissions' },
            write: { type: 'array', items: { type: 'string' }, description: 'Updated write permissions' },
            admin: { type: 'array', items: { type: 'string' }, description: 'Updated admin permissions' }
          }
        }
      },
      required: ['id']
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      const result = await foldersTools.updatedatastore(toolContext, args);
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
    parameters: {
      type: 'object',
      properties: {
        id: { type: 'number', minimum: 1, description: 'Data store ID to delete' }
      },
      required: ['id']
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(context);
      const result = await foldersTools.deletedatastore(toolContext, args);
      if (result.error) {
        throw new Error(result.error);
      }
      return result.message || 'Data store deleted successfully';
    }
  });

  componentLogger.info('Modular folder organization, data store, and data structure tools added successfully');
}

export default addFolderTools;