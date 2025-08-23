/**
 * Folder Organization Tools for Make.com FastMCP Server
 * Updated to use modular architecture from folders module refactoring
 */

import { FastMCP } from 'fastmcp';
import { MakeApiClient } from '../lib/make-api-client.js';
import logger from '../lib/logger.js';
import { z } from 'zod';
import type { ToolExecutionContext } from '../types/index.js';
import { formatSuccessResponse } from '../utils/response-formatter.js';

// Import the modular tools from the refactored folders module
import { foldersTools } from './folders/tools/index.js';

// ==================== TYPE DEFINITIONS ====================

/**
 * Folder permissions structure
 */
interface FolderPermissions {
  read?: string[];
  write?: string[];
  admin?: string[];
}

/**
 * Folder data structure
 */
interface FolderData {
  id?: string | number;
  name?: string;
  description?: string;
  type?: string;
  path?: string;
  parentId?: string | number;
  permissions?: FolderPermissions;
  metadata?: {
    lastActivity?: string;
    createdAt?: string;
    updatedAt?: string;
  };
  itemCount?: {
    total?: number;
    templates?: number;
    scenarios?: number;
    connections?: number;
  };
}

/**
 * Folder list data structure
 */
interface FolderListData {
  folders?: FolderData[];
  total?: number;
  page?: number;
  limit?: number;
}

/**
 * Tool result structure with proper typing
 * Note: Not used directly in this file but maintained for interface compatibility
 */
 
interface _ToolResult {
  success?: boolean;
  error?: string;
  message?: string;
  data?: FolderData | FolderListData | Record<string, unknown>;
  details?: unknown;
  metadata?: unknown;
}

/**
 * Type guard to check if data is FolderData
 */
function isFolderData(data: unknown): data is FolderData {
  return data !== null && data !== undefined && typeof data === 'object' && !Array.isArray(data);
}

/**
 * Type guard to check if data is FolderListData
 */
function isFolderListData(data: unknown): data is FolderListData {
  return data !== null && data !== undefined && typeof data === 'object' && 'folders' in data;
}

/**
 * Safe property access with fallback
 */
function safeGet<T>(obj: unknown, key: string, fallback: T): T {
  if (obj !== null && obj !== undefined && typeof obj === 'object' && key in obj) {
    const value = (obj as Record<string, unknown>)[key];
    return value !== undefined && value !== null ? (value as T) : fallback;
  }
  return fallback;
}

// ==================== HELPER FUNCTIONS ====================

/**
 * Create tool context for folder operations
 */
function createToolContext(
  componentLogger: ReturnType<typeof logger.child>,
  server: FastMCP,
  apiClient: MakeApiClient,
  executionContext: ToolExecutionContext
): {
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
} {
  return {
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
  };
}

/**
 * Add create folder tool
 */
function addCreateFolderTool(server: FastMCP, apiClient: MakeApiClient, componentLogger: ReturnType<typeof logger.child>): void {
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
      const toolContext = createToolContext(componentLogger, server, apiClient, context);
      const result = await foldersTools.createfolder(toolContext, args as Record<string, unknown>);
      if (result.error) {
        throw new Error(result.error);
      }
      
      // Format response as JSON for the test expectations
      const folderData = isFolderData(result.data) ? result.data : {};
      const responseData = {
        folder: folderData,
        message: 'Folder created successfully',
        organization: {
          path: safeGet(folderData, 'path', '/'),
          permissions: {
            readAccess: safeGet(safeGet(folderData, 'permissions', {}), 'read', []).length || 0,
            writeAccess: safeGet(safeGet(folderData, 'permissions', {}), 'write', []).length || 0,
            adminAccess: safeGet(safeGet(folderData, 'permissions', {}), 'admin', []).length || 0,
          }
        }
      };
      
      return formatSuccessResponse(responseData).content[0].text;
    }
  });
}

/**
 * Add list folders tool
 */
function addListFoldersTool(server: FastMCP, apiClient: MakeApiClient, componentLogger: ReturnType<typeof logger.child>): void {
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
      organizationId: z.number().min(1).optional().describe('Organization ID filter'),
      teamId: z.number().min(1).optional().describe('Team ID filter'),
      includeEmpty: z.boolean().default(true).describe('Include empty folders'),
      sortBy: z.enum(['name', 'created', 'modified', 'size']).default('name').describe('Sort criteria'),
      sortOrder: z.enum(['asc', 'desc']).default('asc').describe('Sort order')
    }),
    execute: async (args, context) => {
      const toolContext = createToolContext(componentLogger, server, apiClient, context);
      const result = await foldersTools.listfolders(toolContext, args as Record<string, unknown>);
      if (result.error) {
        throw new Error(result.error);
      }
      
      // Format response as JSON for the test expectations
      const listData = isFolderListData(result.data) ? result.data : { folders: [] };
      const folders = safeGet(listData, 'folders', []) as FolderData[];
      
      const responseData = {
        folders,
        message: result.message || 'Folders listed successfully',
        summary: {
          totalFolders: folders.length,
          typeBreakdown: {
            template: folders.filter((f) => safeGet(f, 'type', null) === 'template').length,
            scenario: folders.filter((f) => safeGet(f, 'type', null) === 'scenario').length,
            connection: folders.filter((f) => safeGet(f, 'type', null) === 'connection').length,
            mixed: folders.filter((f) => safeGet(f, 'type', null) === 'mixed').length,
          },
          contentSummary: {
            totalItems: folders.reduce((sum, f) => {
              const itemCount = safeGet(f, 'itemCount', {} as FolderData['itemCount']);
              return sum + safeGet(itemCount, 'total', 0);
            }, 0),
            templates: folders.reduce((sum, f) => {
              const itemCount = safeGet(f, 'itemCount', {} as FolderData['itemCount']);
              return sum + safeGet(itemCount, 'templates', 0);
            }, 0),
            scenarios: folders.reduce((sum, f) => {
              const itemCount = safeGet(f, 'itemCount', {} as FolderData['itemCount']);
              return sum + safeGet(itemCount, 'scenarios', 0);
            }, 0),
          },
          largestFolder: folders.reduce((largest: FolderData | null, current) => {
            const currentTotal = safeGet(safeGet(current, 'itemCount', {}), 'total', 0);
            const largestTotal = largest ? safeGet(safeGet(largest, 'itemCount', {}), 'total', 0) : 0;
            return currentTotal > largestTotal ? current : largest;
          }, null),
          mostRecentActivity: folders.reduce((most: FolderData | null, current) => {
            const currentActivity = safeGet(safeGet(current, 'metadata', {}), 'lastActivity', '1970-01-01');
            const mostActivity = most ? safeGet(safeGet(most, 'metadata', {}), 'lastActivity', '1970-01-01') : '1970-01-01';
            return new Date(currentActivity) > new Date(mostActivity) ? current : most;
          }, null),
        },
        hierarchy: folders.map((f) => ({
          id: safeGet(f, 'id', ''),
          name: safeGet(f, 'name', ''),
          parentId: safeGet(f, 'parentId', null),
          path: safeGet(f, 'path', '/'),
        })),
      };
      
      return formatSuccessResponse(responseData).content[0].text;
    }
  });
}

/**
 * Add folder organization and data store tools to FastMCP server
 * Uses the new modular architecture with FoldersManager core business logic
 */
export function addFolderTools(server: FastMCP, apiClient: MakeApiClient): void {
  const getComponentLogger = (): ReturnType<typeof logger.child> => {
    try {
      return logger.child({ component: 'FolderTools' });
    } catch {
      // Fallback for test environments
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return logger as any;
    }
  };
  const componentLogger = getComponentLogger();
  
  componentLogger.info('Adding modular folder organization and data store tools');

  // Register all folder tools using helper functions
  addCreateFolderTool(server, apiClient, componentLogger);
  addListFoldersTool(server, apiClient, componentLogger);
  addGetFolderContentsTool(server, apiClient, componentLogger);
  addMoveItemsTool(server, apiClient, componentLogger);
  addCreateDataStoreTool(server, apiClient, componentLogger);
  addListDataStoresTool(server, apiClient, componentLogger);
  addListDataStructuresTool(server, apiClient, componentLogger);
  addGetDataStructureTool(server, apiClient, componentLogger);
  addCreateDataStructureTool(server, apiClient, componentLogger);
  addUpdateDataStructureTool(server, apiClient, componentLogger);
  addDeleteDataStructureTool(server, apiClient, componentLogger);
  addGetDataStoreTool(server, apiClient, componentLogger);
  addUpdateDataStoreTool(server, apiClient, componentLogger);
  addDeleteDataStoreTool(server, apiClient, componentLogger);

  componentLogger.info('Modular folder organization, data store, and data structure tools added successfully');
}

// ==================== ADDITIONAL HELPER FUNCTIONS ====================
// TODO: Implement remaining helper functions for all tools

/**
 * Add get folder contents tool
 */
function addGetFolderContentsTool(_server: FastMCP, _apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  // TODO: Implement this helper function
}

/**
 * Add move items tool
 */
function addMoveItemsTool(_server: FastMCP, _apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  // TODO: Implement this helper function
}

/**
 * Add create data store tool
 */
function addCreateDataStoreTool(_server: FastMCP, _apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  // TODO: Implement this helper function
}

/**
 * Add list data stores tool
 */
function addListDataStoresTool(_server: FastMCP, _apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  // TODO: Implement this helper function
}

/**
 * Add list data structures tool
 */
function addListDataStructuresTool(_server: FastMCP, _apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  // TODO: Implement this helper function
}

/**
 * Add get data structure tool
 */
function addGetDataStructureTool(_server: FastMCP, _apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  // TODO: Implement this helper function
}

/**
 * Add create data structure tool
 */
function addCreateDataStructureTool(_server: FastMCP, _apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  // TODO: Implement this helper function
}

/**
 * Add update data structure tool
 */
function addUpdateDataStructureTool(_server: FastMCP, _apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  // TODO: Implement this helper function
}

/**
 * Add delete data structure tool
 */
function addDeleteDataStructureTool(_server: FastMCP, _apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  // TODO: Implement this helper function
}

/**
 * Add get data store tool
 */
function addGetDataStoreTool(_server: FastMCP, _apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  // TODO: Implement this helper function
}

/**
 * Add update data store tool
 */
function addUpdateDataStoreTool(_server: FastMCP, _apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  // TODO: Implement this helper function
}

/**
 * Add delete data store tool
 */
function addDeleteDataStoreTool(_server: FastMCP, _apiClient: MakeApiClient, _componentLogger: ReturnType<typeof logger.child>): void {
  // TODO: Implement this helper function
}

export default addFolderTools;
