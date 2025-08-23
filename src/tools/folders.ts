/**
 * Folder Organization Tools for Make.com FastMCP Server
 * Updated to use modular architecture from folders module refactoring
 */

import { FastMCP } from "fastmcp";
import { MakeApiClient } from "../lib/make-api-client.js";
import logger from "../lib/logger.js";
import { z } from "zod";
import type { ToolExecutionContext } from "../types/index.js";
import { formatSuccessResponse } from "../utils/response-formatter.js";

// Import the modular tools from the refactored folders module
import { foldersTools } from "./folders/tools/index.js";

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
  return (
    data !== null &&
    data !== undefined &&
    typeof data === "object" &&
    !Array.isArray(data)
  );
}

/**
 * Type guard to check if data is FolderListData
 */
function isFolderListData(data: unknown): data is FolderListData {
  return (
    data !== null &&
    data !== undefined &&
    typeof data === "object" &&
    "folders" in data
  );
}

/**
 * Safe property access with fallback
 */
function safeGet<T>(obj: unknown, key: string, fallback: T): T {
  if (
    obj !== null &&
    obj !== undefined &&
    typeof obj === "object" &&
    key in obj
  ) {
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
  executionContext: ToolExecutionContext,
): {
  server: FastMCP;
  apiClient: MakeApiClient;
  logger: typeof componentLogger;
  log: ToolExecutionContext["log"];
  reportProgress: ToolExecutionContext["reportProgress"];
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
      timeout: 30000,
    },
  };
}

/**
 * Add create folder tool
 */
function addCreateFolderTool(
  server: FastMCP,
  apiClient: MakeApiClient,
  componentLogger: ReturnType<typeof logger.child>,
): void {
  server.addTool({
    name: "create-folder",
    description:
      "Create a new folder for organizing templates, scenarios, and connections",
    annotations: {
      title: "Create Folder",
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    parameters: z.object({
      name: z
        .string()
        .min(1)
        .max(100)
        .describe("Folder name (1-100 characters)"),
      description: z
        .string()
        .max(500)
        .optional()
        .describe("Folder description (max 500 characters)"),
      parentId: z
        .number()
        .min(1)
        .optional()
        .describe("Parent folder ID (for nested folders)"),
      type: z
        .enum(["template", "scenario", "connection", "mixed"])
        .describe("Folder content type"),
      organizationId: z
        .number()
        .min(1)
        .optional()
        .describe("Organization ID (for organization folders)"),
      teamId: z
        .number()
        .min(1)
        .optional()
        .describe("Team ID (for team folders)"),
      permissions: z
        .object({
          read: z.array(z.string()).describe("User/team IDs with read access"),
          write: z
            .array(z.string())
            .describe("User/team IDs with write access"),
          admin: z
            .array(z.string())
            .describe("User/team IDs with admin access"),
        })
        .optional()
        .describe("Folder permissions"),
    }),
    execute: async (args, context) => {
      const toolContext = createToolContext(
        componentLogger,
        server,
        apiClient,
        context,
      );
      const result = await foldersTools.createfolder(
        toolContext,
        args as Record<string, unknown>,
      );
      if (result.error) {
        // Pass through the specific error message
        throw new Error(result.error);
      }

      // Format response as JSON for the test expectations
      const folderData = isFolderData(result.data) ? result.data : {};
      const responseData = {
        folder: folderData,
        message: "Folder created successfully",
        organization: {
          path: safeGet(folderData, "path", "/"),
          permissions: {
            readAccess:
              safeGet(safeGet(folderData, "permissions", {}), "read", [])
                .length || 0,
            writeAccess:
              safeGet(safeGet(folderData, "permissions", {}), "write", [])
                .length || 0,
            adminAccess:
              safeGet(safeGet(folderData, "permissions", {}), "admin", [])
                .length || 0,
          },
        },
      };

      return formatSuccessResponse(responseData).content[0].text;
    },
  });
}

/**
 * Add list folders tool
 */
function addListFoldersTool(
  server: FastMCP,
  apiClient: MakeApiClient,
  componentLogger: ReturnType<typeof logger.child>,
): void {
  server.addTool({
    name: "list-folders",
    description: "List and filter folders with organizational hierarchy",
    annotations: {
      title: "List Folders",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    parameters: z.object({
      parentId: z
        .number()
        .min(1)
        .optional()
        .describe("List folders under this parent (null for root)"),
      type: z
        .enum(["template", "scenario", "connection", "mixed", "all"])
        .optional()
        .describe("Filter by folder type"),
      organizationId: z
        .number()
        .min(1)
        .optional()
        .describe("Organization ID filter"),
      teamId: z.number().min(1).optional().describe("Team ID filter"),
      includeEmpty: z.boolean().default(true).describe("Include empty folders"),
      includeContents: z
        .boolean()
        .default(false)
        .describe("Include folder contents in results"),
      searchQuery: z
        .string()
        .optional()
        .describe("Search query to filter folders"),
      limit: z
        .number()
        .min(1)
        .max(1000)
        .default(50)
        .describe("Maximum number of results to return"),
      offset: z
        .number()
        .min(0)
        .default(0)
        .describe("Number of results to skip"),
      sortBy: z
        .enum(["name", "created", "modified", "size", "lastActivity"])
        .default("name")
        .describe("Sort criteria"),
      sortOrder: z.enum(["asc", "desc"]).default("asc").describe("Sort order"),
    }),
    execute: async (args, context) => {
      const toolContext = createToolContext(
        componentLogger,
        server,
        apiClient,
        context,
      );
      const result = await foldersTools.listfolders(
        toolContext,
        args as Record<string, unknown>,
      );
      if (result.error) {
        // Pass through the specific error message
        throw new Error(result.error);
      }

      // Format response as JSON for the test expectations
      const listData = isFolderListData(result.data)
        ? result.data
        : { folders: [] };
      const folders = safeGet(listData, "folders", []) as FolderData[];

      const responseData = {
        folders,
        message: result.message || "Folders listed successfully",
        summary: {
          totalFolders: folders.length,
          typeBreakdown: {
            template: folders.filter(
              (f) => safeGet(f, "type", null) === "template",
            ).length,
            scenario: folders.filter(
              (f) => safeGet(f, "type", null) === "scenario",
            ).length,
            connection: folders.filter(
              (f) => safeGet(f, "type", null) === "connection",
            ).length,
            mixed: folders.filter((f) => safeGet(f, "type", null) === "mixed")
              .length,
          },
          contentSummary: {
            totalItems: folders.reduce((sum, f) => {
              const itemCount = safeGet(
                f,
                "itemCount",
                {} as FolderData["itemCount"],
              );
              return sum + safeGet(itemCount, "total", 0);
            }, 0),
            templates: folders.reduce((sum, f) => {
              const itemCount = safeGet(
                f,
                "itemCount",
                {} as FolderData["itemCount"],
              );
              return sum + safeGet(itemCount, "templates", 0);
            }, 0),
            scenarios: folders.reduce((sum, f) => {
              const itemCount = safeGet(
                f,
                "itemCount",
                {} as FolderData["itemCount"],
              );
              return sum + safeGet(itemCount, "scenarios", 0);
            }, 0),
          },
          largestFolder: folders.reduce(
            (largest: FolderData | null, current) => {
              const currentTotal = safeGet(
                safeGet(current, "itemCount", {}),
                "total",
                0,
              );
              const largestTotal = largest
                ? safeGet(safeGet(largest, "itemCount", {}), "total", 0)
                : 0;
              return currentTotal > largestTotal ? current : largest;
            },
            null,
          ),
          mostRecentActivity: folders.reduce(
            (most: FolderData | null, current) => {
              const currentActivity = safeGet(
                safeGet(current, "metadata", {}),
                "lastActivity",
                "1970-01-01",
              );
              const mostActivity = most
                ? safeGet(
                    safeGet(most, "metadata", {}),
                    "lastActivity",
                    "1970-01-01",
                  )
                : "1970-01-01";
              return new Date(currentActivity) > new Date(mostActivity)
                ? current
                : most;
            },
            null,
          ),
        },
        hierarchy: folders.map((f) => ({
          id: safeGet(f, "id", ""),
          name: safeGet(f, "name", ""),
          parentId: safeGet(f, "parentId", null),
          path: safeGet(f, "path", "/"),
        })),
      };

      return formatSuccessResponse(responseData).content[0].text;
    },
  });
}

/**
 * Add folder organization and data store tools to FastMCP server
 * Uses the new modular architecture with FoldersManager core business logic
 */
export function addFolderTools(
  server: FastMCP,
  apiClient: MakeApiClient,
): void {
  const getComponentLogger = (): ReturnType<typeof logger.child> => {
    try {
      return logger.child({ component: "FolderTools" });
    } catch {
      // Fallback for test environments
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return logger as any;
    }
  };
  const componentLogger = getComponentLogger();

  componentLogger.info(
    "Adding modular folder organization and data store tools",
  );

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

  componentLogger.info(
    "Modular folder organization, data store, and data structure tools added successfully",
  );
}

// ==================== ADDITIONAL HELPER FUNCTIONS ====================

/**
 * Add get folder contents tool
 */
function addGetFolderContentsTool(
  server: FastMCP,
  apiClient: MakeApiClient,
  componentLogger: ReturnType<typeof logger.child>,
): void {
  server.addTool({
    name: "get-folder-contents",
    description:
      "Get contents of a specific folder including files, subfolders, and metadata",
    parameters: z.object({
      folderId: z.number().min(1).describe("Folder ID to get contents from"),
      includeSubfolders: z
        .boolean()
        .optional()
        .describe("Include subfolders in results"),
      includeMetadata: z
        .boolean()
        .optional()
        .describe("Include metadata for each item"),
    }),
    annotations: {
      title: "Get Folder Contents",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(
        componentLogger,
        server,
        apiClient,
        context,
      );
      const result = await foldersTools.getfoldercontents(
        toolContext,
        args as Record<string, unknown>,
      );
      if (result.error) {
        throw new Error(result.error);
      }
      return formatSuccessResponse(result.data || {}).content[0].text;
    },
  });
}

/**
 * Add move items tool
 */
function addMoveItemsTool(
  server: FastMCP,
  apiClient: MakeApiClient,
  componentLogger: ReturnType<typeof logger.child>,
): void {
  server.addTool({
    name: "move-items",
    description:
      "Move items (templates, scenarios, connections) between folders",
    parameters: z.object({
      itemIds: z.array(z.number()).describe("Array of item IDs to move"),
      targetFolderId: z.number().min(1).describe("Target folder ID"),
      itemType: z
        .enum(["template", "scenario", "connection"])
        .describe("Type of items being moved"),
    }),
    annotations: {
      title: "Move Items",
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(
        componentLogger,
        server,
        apiClient,
        context,
      );
      const result = await foldersTools.moveitems(
        toolContext,
        args as Record<string, unknown>,
      );
      if (result.error) {
        throw new Error(result.error);
      }
      return formatSuccessResponse(result.data || {}).content[0].text;
    },
  });
}

/**
 * Add create data store tool
 */
function addCreateDataStoreTool(
  server: FastMCP,
  apiClient: MakeApiClient,
  componentLogger: ReturnType<typeof logger.child>,
): void {
  server.addTool({
    name: "create-data-store",
    description: "Create a new data store for persistent data management",
    parameters: z.object({
      name: z.string().min(1).max(100).describe("Data store name"),
      description: z
        .string()
        .max(500)
        .optional()
        .describe("Data store description"),
      type: z
        .enum(["key-value", "document", "relational"])
        .describe("Data store type"),
      organizationId: z.number().min(1).optional().describe("Organization ID"),
      teamId: z.number().min(1).optional().describe("Team ID"),
    }),
    annotations: {
      title: "Create Data Store",
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(
        componentLogger,
        server,
        apiClient,
        context,
      );
      const result = await foldersTools.createdatastore(
        toolContext,
        args as Record<string, unknown>,
      );
      if (result.error) {
        throw new Error(result.error);
      }
      return formatSuccessResponse(result.data || {}).content[0].text;
    },
  });
}

/**
 * Add list data stores tool
 */
function addListDataStoresTool(
  server: FastMCP,
  apiClient: MakeApiClient,
  componentLogger: ReturnType<typeof logger.child>,
): void {
  server.addTool({
    name: "list-data-stores",
    description: "List available data stores with filtering and metadata",
    parameters: z.object({
      organizationId: z
        .number()
        .min(1)
        .optional()
        .describe("Filter by organization ID"),
      teamId: z.number().min(1).optional().describe("Filter by team ID"),
      type: z
        .enum(["key-value", "document", "relational"])
        .optional()
        .describe("Filter by data store type"),
      includeMetadata: z
        .boolean()
        .optional()
        .describe("Include metadata in results"),
    }),
    annotations: {
      title: "List Data Stores",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(
        componentLogger,
        server,
        apiClient,
        context,
      );
      const result = await foldersTools.listdatastores(
        toolContext,
        args as Record<string, unknown>,
      );
      if (result.error) {
        throw new Error(result.error);
      }
      return formatSuccessResponse(result.data || {}).content[0].text;
    },
  });
}

/**
 * Add list data structures tool
 */
function addListDataStructuresTool(
  server: FastMCP,
  apiClient: MakeApiClient,
  componentLogger: ReturnType<typeof logger.child>,
): void {
  server.addTool({
    name: "list-data-structures",
    description: "List data structures with schema information and metadata",
    parameters: z.object({
      dataStoreId: z
        .number()
        .min(1)
        .optional()
        .describe("Filter by data store ID"),
      organizationId: z
        .number()
        .min(1)
        .optional()
        .describe("Filter by organization ID"),
      teamId: z.number().min(1).optional().describe("Filter by team ID"),
      includeSchema: z
        .boolean()
        .optional()
        .describe("Include schema information"),
    }),
    annotations: {
      title: "List Data Structures",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(
        componentLogger,
        server,
        apiClient,
        context,
      );
      const result = await foldersTools.listdatastructures(
        toolContext,
        args as Record<string, unknown>,
      );
      if (result.error) {
        throw new Error(result.error);
      }
      return formatSuccessResponse(result.data || {}).content[0].text;
    },
  });
}

/**
 * Add get data structure tool
 */
function addGetDataStructureTool(
  server: FastMCP,
  apiClient: MakeApiClient,
  componentLogger: ReturnType<typeof logger.child>,
): void {
  server.addTool({
    name: "get-data-structure",
    description: "Get detailed information about a specific data structure",
    parameters: z.object({
      dataStructureId: z
        .number()
        .min(1)
        .describe("Data structure ID to retrieve"),
      includeSchema: z
        .boolean()
        .optional()
        .describe("Include detailed schema information"),
      includeData: z.boolean().optional().describe("Include sample data"),
    }),
    annotations: {
      title: "Get Data Structure",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(
        componentLogger,
        server,
        apiClient,
        context,
      );
      const result = await foldersTools.getdatastructure(
        toolContext,
        args as Record<string, unknown>,
      );
      if (result.error) {
        throw new Error(result.error);
      }
      return formatSuccessResponse(result.data || {}).content[0].text;
    },
  });
}

/**
 * Add create data structure tool
 */
function addCreateDataStructureTool(
  server: FastMCP,
  apiClient: MakeApiClient,
  componentLogger: ReturnType<typeof logger.child>,
): void {
  server.addTool({
    name: "create-data-structure",
    description: "Create a new data structure with schema definition",
    parameters: z.object({
      name: z.string().min(1).max(100).describe("Data structure name"),
      description: z
        .string()
        .max(500)
        .optional()
        .describe("Data structure description"),
      dataStoreId: z
        .number()
        .min(1)
        .describe("Data store ID to create structure in"),
      schema: z
        .record(z.string(), z.any())
        .describe("Data structure schema definition"),
      organizationId: z.number().min(1).optional().describe("Organization ID"),
    }),
    annotations: {
      title: "Create Data Structure",
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(
        componentLogger,
        server,
        apiClient,
        context,
      );
      const result = await foldersTools.createdatastructure(
        toolContext,
        args as Record<string, unknown>,
      );
      if (result.error) {
        throw new Error(result.error);
      }
      return formatSuccessResponse(result.data || {}).content[0].text;
    },
  });
}

/**
 * Add update data structure tool
 */
function addUpdateDataStructureTool(
  server: FastMCP,
  apiClient: MakeApiClient,
  componentLogger: ReturnType<typeof logger.child>,
): void {
  server.addTool({
    name: "update-data-structure",
    description: "Update an existing data structure schema and properties",
    parameters: z.object({
      dataStructureId: z
        .number()
        .min(1)
        .describe("Data structure ID to update"),
      name: z
        .string()
        .min(1)
        .max(100)
        .optional()
        .describe("Updated data structure name"),
      description: z
        .string()
        .max(500)
        .optional()
        .describe("Updated description"),
      schema: z
        .record(z.string(), z.any())
        .optional()
        .describe("Updated schema definition"),
    }),
    annotations: {
      title: "Update Data Structure",
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(
        componentLogger,
        server,
        apiClient,
        context,
      );
      const result = await foldersTools.updatedatastructure(
        toolContext,
        args as Record<string, unknown>,
      );
      if (result.error) {
        throw new Error(result.error);
      }
      return formatSuccessResponse(result.data || {}).content[0].text;
    },
  });
}

/**
 * Add delete data structure tool
 */
function addDeleteDataStructureTool(
  server: FastMCP,
  apiClient: MakeApiClient,
  componentLogger: ReturnType<typeof logger.child>,
): void {
  server.addTool({
    name: "delete-data-structure",
    description: "Delete a data structure and all associated data",
    parameters: z.object({
      dataStructureId: z
        .number()
        .min(1)
        .describe("Data structure ID to delete"),
      confirmDeletion: z
        .boolean()
        .describe("Confirmation that data will be permanently deleted"),
      cascadeDelete: z
        .boolean()
        .optional()
        .describe("Delete all dependent data"),
    }),
    annotations: {
      title: "Delete Data Structure",
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(
        componentLogger,
        server,
        apiClient,
        context,
      );
      const result = await foldersTools.deletedatastructure(
        toolContext,
        args as Record<string, unknown>,
      );
      if (result.error) {
        throw new Error(result.error);
      }
      return formatSuccessResponse(result.data || {}).content[0].text;
    },
  });
}

/**
 * Add get data store tool
 */
function addGetDataStoreTool(
  server: FastMCP,
  apiClient: MakeApiClient,
  componentLogger: ReturnType<typeof logger.child>,
): void {
  server.addTool({
    name: "get-data-store",
    description: "Get detailed information about a specific data store",
    parameters: z.object({
      dataStoreId: z.number().min(1).describe("Data store ID to retrieve"),
      includeMetadata: z
        .boolean()
        .optional()
        .describe("Include metadata information"),
      includeStructures: z
        .boolean()
        .optional()
        .describe("Include data structures list"),
    }),
    annotations: {
      title: "Get Data Store",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(
        componentLogger,
        server,
        apiClient,
        context,
      );
      const result = await foldersTools.getdatastore(
        toolContext,
        args as Record<string, unknown>,
      );
      if (result.error) {
        throw new Error(result.error);
      }
      return formatSuccessResponse(result.data || {}).content[0].text;
    },
  });
}

/**
 * Add update data store tool
 */
function addUpdateDataStoreTool(
  server: FastMCP,
  apiClient: MakeApiClient,
  componentLogger: ReturnType<typeof logger.child>,
): void {
  server.addTool({
    name: "update-data-store",
    description: "Update data store configuration and metadata",
    parameters: z.object({
      dataStoreId: z.number().min(1).describe("Data store ID to update"),
      name: z
        .string()
        .min(1)
        .max(100)
        .optional()
        .describe("Updated data store name"),
      description: z
        .string()
        .max(500)
        .optional()
        .describe("Updated description"),
      configuration: z
        .record(z.string(), z.any())
        .optional()
        .describe("Updated configuration settings"),
    }),
    annotations: {
      title: "Update Data Store",
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(
        componentLogger,
        server,
        apiClient,
        context,
      );
      const result = await foldersTools.updatedatastore(
        toolContext,
        args as Record<string, unknown>,
      );
      if (result.error) {
        throw new Error(result.error);
      }
      return formatSuccessResponse(result.data || {}).content[0].text;
    },
  });
}

/**
 * Add delete data store tool
 */
function addDeleteDataStoreTool(
  server: FastMCP,
  apiClient: MakeApiClient,
  componentLogger: ReturnType<typeof logger.child>,
): void {
  server.addTool({
    name: "delete-data-store",
    description: "Delete a data store and all its contents permanently",
    parameters: z.object({
      dataStoreId: z.number().min(1).describe("Data store ID to delete"),
      confirmDeletion: z
        .boolean()
        .describe("Confirmation that all data will be permanently deleted"),
      cascadeDelete: z
        .boolean()
        .optional()
        .describe("Delete all structures and data"),
    }),
    annotations: {
      title: "Delete Data Store",
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    },
    execute: async (args, context) => {
      const toolContext = createToolContext(
        componentLogger,
        server,
        apiClient,
        context,
      );
      const result = await foldersTools.deletedatastore(
        toolContext,
        args as Record<string, unknown>,
      );
      if (result.error) {
        throw new Error(result.error);
      }
      return formatSuccessResponse(result.data || {}).content[0].text;
    },
  });
}

export default addFolderTools;
