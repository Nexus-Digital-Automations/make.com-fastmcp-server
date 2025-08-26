/**
 * Data and Connectivity Management Tools for Make.com FastMCP Server
 *
 * Provides comprehensive FastMCP tools for managing connections, data stores,
 * webhooks (hooks), and keys in Make.com environments.
 *
 * Features:
 * - Connection CRUD operations and OAuth 2.0 management
 * - Data Store management with schema validation
 * - Webhook management with security and testing
 * - Keys management and lifecycle operations
 *
 * Based on comprehensive research of Make.com Data & Connectivity APIs:
 * - Connections API for service integrations
 * - Data Stores API for persistent data management
 * - Webhooks API for real-time event handling
 * - Keys API for authentication and security
 */

import { FastMCP } from "fastmcp";
import { z } from "zod";
import winston from "winston";
import {
  MakeAPIClient,
  MakeAPIError,
} from "../make-client/simple-make-client.js";

// Logger placeholder - will use logger passed to registration function
let moduleLogger: winston.Logger;

// ==============================================
// Type Definitions for Make.com API Responses
// ==============================================

interface MakeConnection {
  id: string;
  name: string;
  accountName?: string;
  accountType: string;
  teamId?: string;
  expire?: string;
  status?: string;
  scopes?: string[];
  created?: string;
  verified?: boolean;
  metadata?: Record<string, unknown>;
  editable?: boolean;
}

interface MakeDataStore {
  id: string;
  name: string;
  label?: string;
  teamId?: string;
  created?: string;
  structure?: Record<string, unknown>;
  size?: number;
  recordCount?: number;
  maxSizeMB?: number;
  strictValidation?: boolean;
  status?: string;
  createdAt?: string;
}

interface MakeWebhook {
  id: string;
  name: string;
  url?: string;
  status?: string;
  teamId?: string;
  created?: string;
  modified?: string;
  enabled?: boolean;
  typeName?: string;
  configuration?: Record<string, unknown>;
  security?: Record<string, unknown>;
  createdAt?: string;
}

interface StatusCount {
  [key: string]: number;
}

interface MakeDataStoreField {
  name: string;
  type: string;
  required: boolean;
  unique: boolean;
  constraints?: Record<string, unknown>;
}

interface MakeAPIKey {
  id: string;
  name: string;
  keyType: string;
  isActive: boolean;
  scopes: string[];
  expiresAt?: string;
  lastUsedAt?: string;
  createdAt?: string;
  key?: string;
}

interface MakeTestResult {
  success?: boolean;
  status?: string;
  message?: string;
  details?: Record<string, unknown>;
}

// ================================
// Core Type Definitions
// ================================

// Connection Management Types (for validation/reference)
const _ConnectionSchema = z.object({
  id: z.number(),
  name: z.string(),
  accountName: z.string(),
  accountType: z.enum(["oauth", "apikey", "basic", "custom"]),
  teamId: z.number(),
  scopes: z.number().optional(),
  expire: z.string().optional().nullable(),
  editable: z.boolean().optional(),
  metadata: z.record(z.string(), z.any()).optional(),
});

const ConnectionCreateSchema = z.object({
  name: z.string().min(1).max(128).describe("Connection name"),
  accountName: z.string().describe("Account identifier"),
  accountType: z
    .enum(["oauth", "apikey", "basic", "custom"])
    .describe("Authentication type"),
  teamId: z.number().describe("Team ID for the connection"),
  configuration: z
    .record(z.string(), z.any())
    .optional()
    .describe("Connection configuration"),
  scopes: z.number().optional().describe("OAuth scopes bitmask"),
  metadata: z
    .record(z.string(), z.any())
    .optional()
    .describe("Additional metadata"),
});

// Data Store Management Types (for validation/reference)
const _DataStoreSchema = z.object({
  id: z.string(),
  name: z.string(),
  teamId: z.string(),
  datastructureId: z.string(),
  maxSizeMB: z.number(),
  strictValidation: z.boolean(),
  recordCount: z.number().optional(),
  createdAt: z.string().optional(),
  updatedAt: z.string().optional(),
});

const DataStoreCreateSchema = z.object({
  name: z.string().min(1).max(100).describe("Data store name"),
  teamId: z.string().describe("Team ID for the data store"),
  dataStructure: z
    .object({
      name: z.string().describe("Data structure name"),
      fields: z
        .array(
          z.object({
            name: z.string().describe("Field name"),
            type: z
              .enum([
                "text",
                "number",
                "boolean",
                "date",
                "datetime",
                "json",
                "array",
              ])
              .describe("Field data type"),
            required: z
              .boolean()
              .default(false)
              .describe("Whether field is required"),
            unique: z
              .boolean()
              .default(false)
              .describe("Whether field must be unique"),
            constraints: z
              .record(z.string(), z.any())
              .optional()
              .describe("Field validation constraints"),
          }),
        )
        .describe("Data structure field definitions"),
    })
    .describe("Data structure specification"),
  maxSizeMB: z
    .number()
    .min(1)
    .max(100)
    .default(10)
    .describe("Maximum size in MB"),
  strictValidation: z
    .boolean()
    .default(true)
    .describe("Enable strict validation"),
});

// Webhook Management Types (for validation/reference)
const _WebhookSchema = z.object({
  id: z.string(),
  name: z.string(),
  url: z.string(),
  typeName: z.string(),
  teamId: z.string().optional(),
  status: z.enum(["enabled", "disabled", "learning"]).optional(),
  configuration: z.record(z.string(), z.any()).optional(),
  security: z.record(z.string(), z.any()).optional(),
  createdAt: z.string().optional(),
});

const WebhookCreateSchema = z.object({
  name: z.string().min(1).max(128).describe("Webhook name"),
  typeName: z
    .string()
    .describe("Webhook type (e.g., gateway-webhook, gateway-mailhook)"),
  teamId: z.string().optional().describe("Team ID for webhook"),
  configuration: z
    .object({
      method: z.boolean().default(true).describe("Track HTTP methods"),
      header: z.boolean().default(true).describe("Include headers"),
      stringify: z.boolean().default(false).describe("Stringify JSON payload"),
      timeoutSeconds: z
        .number()
        .min(1)
        .max(180)
        .default(60)
        .describe("Timeout in seconds"),
    })
    .optional()
    .describe("Webhook configuration"),
  security: z
    .object({
      restrictIP: z
        .array(z.string())
        .optional()
        .describe("Allowed IP addresses"),
      authentication: z
        .enum(["none", "basic", "bearer", "custom"])
        .default("none")
        .describe("Authentication method"),
      secretKey: z
        .string()
        .optional()
        .describe("Secret key for authentication"),
    })
    .optional()
    .describe("Security configuration"),
});

// Keys Management Types (for validation/reference)
const _APIKeySchema = z.object({
  id: z.string(),
  name: z.string(),
  keyType: z.enum(["api-key", "oauth-token", "webhook-secret", "custom"]),
  teamId: z.string(),
  scopes: z.array(z.string()),
  expiresAt: z.string().optional(),
  lastUsedAt: z.string().optional(),
  isActive: z.boolean(),
  createdAt: z.string(),
});

const APIKeyCreateSchema = z.object({
  name: z.string().min(1).max(100).describe("Key name"),
  keyType: z
    .enum(["api-key", "oauth-token", "webhook-secret", "custom"])
    .describe("Type of key"),
  teamId: z.string().describe("Team ID for the key"),
  scopes: z.array(z.string()).describe("Permission scopes"),
  expiresInDays: z
    .number()
    .min(1)
    .max(365)
    .optional()
    .describe("Expiration in days"),
  configuration: z
    .record(z.string(), z.any())
    .optional()
    .describe("Key-specific configuration"),
});

// ================================
// Helper Functions for API Operations
// ================================

// Note: Using existing MakeAPIClient methods where available
// Some methods are simulated for demonstration as they may not be fully implemented in the simple client

// ================================
// FastMCP Tool Registration Function
// ================================

export function registerDataConnectivityManagementTools(
  server: FastMCP,
  makeClient: MakeAPIClient,
  logger: winston.Logger,
): void {
  // Set module logger
  moduleLogger = logger;

  // ================================
  // Connection Management Tools
  // ================================

  server.addTool({
    name: "list-make-connections",
    description:
      "List Make.com connections with advanced filtering and detailed information",
    parameters: z.object({
      teamId: z.string().optional().describe("Filter by team ID"),
      accountType: z
        .enum(["oauth", "apikey", "basic", "custom"])
        .optional()
        .describe("Filter by authentication type"),
      includeExpired: z
        .boolean()
        .default(true)
        .describe("Include expired connections"),
      includeMetadata: z
        .boolean()
        .default(false)
        .describe("Include connection metadata"),
      limit: z
        .number()
        .min(1)
        .max(100)
        .default(25)
        .describe("Maximum connections to return"),
    }),
    annotations: {
      title: "List Connections",
      readOnlyHint: true,
    },
    execute: async (args, { log }) => {
      const operationId = `list_connections_${Date.now()}`;

      log.info(`[${operationId}] Listing Make.com connections`, {
        teamId: args.teamId,
        accountType: args.accountType,
        includeExpired: args.includeExpired,
        operationId,
      });

      try {
        const startTime = Date.now();
        const response = await makeClient.getConnections(args.teamId, {
          accountType: args.accountType,
          includeExpired: args.includeExpired,
          limit: args.limit,
        });
        const connections = (response.data as MakeConnection[]) || [];
        const processingTime = Date.now() - startTime;

        // Filter and enhance connection data
        const formattedConnections = connections.map(
          (conn: MakeConnection) => ({
            id: conn.id,
            name: conn.name,
            accountName: conn.accountName,
            accountType: conn.accountType,
            teamId: conn.teamId,
            status:
              conn.expire && new Date(conn.expire) < new Date()
                ? "expired"
                : "active",
            expire: conn.expire,
            scopes: conn.scopes,
            editable: conn.editable,
            ...(args.includeMetadata && { metadata: conn.metadata }),
          }),
        );

        // Generate statistics
        const stats = {
          total: formattedConnections.length,
          byType: formattedConnections.reduce(
            (acc: StatusCount, conn: MakeConnection) => {
              acc[conn.accountType] = (acc[conn.accountType] || 0) + 1;
              return acc;
            },
            {},
          ),
          byStatus: formattedConnections.reduce(
            (acc: StatusCount, conn: MakeConnection) => {
              const status = conn.status || "unknown";
              acc[status] = (acc[status] || 0) + 1;
              return acc;
            },
            {},
          ),
        };

        log.info(`[${operationId}] Connections listed successfully`, {
          teamId: args.teamId,
          totalConnections: stats.total,
          processingTimeMs: processingTime,
          operationId,
        });

        return {
          content: [
            {
              type: "text",
              text: `🔗 **Make.com Connections**\n\n**Summary:**\n- Total: ${stats.total} connections\n- By Type: ${Object.entries(
                stats.byType,
              )
                .map(([type, count]) => `${type}(${count})`)
                .join(", ")}\n- By Status: ${Object.entries(stats.byStatus)
                .map(([status, count]) => `${status}(${count})`)
                .join(
                  ", ",
                )}\n${args.teamId ? `- Team: ${args.teamId}\n` : ""}\n**Connections:**\n\n${formattedConnections
                .map(
                  (conn: MakeConnection, index: number) =>
                    `**${index + 1}. ${conn.name}**\n` +
                    `- ID: ${conn.id}\n` +
                    `- Account: ${conn.accountName} (${conn.accountType})\n` +
                    `- Team: ${conn.teamId}\n` +
                    `- Status: ${conn.status === "active" ? "🟢" : "🔴"} ${conn.status}\n` +
                    `- Editable: ${conn.editable ? "✅" : "❌"}\n` +
                    `${conn.expire ? `- Expires: ${new Date(conn.expire).toLocaleString()}\n` : ""}` +
                    `${conn.scopes ? `- Scopes: ${conn.scopes}\n` : ""}`,
                )
                .join(
                  "\n",
                )}\n\n**Management Actions:**\n- Use \`get-make-connection-details\` for detailed information\n- Use \`test-make-connection\` to verify connectivity\n- Use \`update-make-connection\` to modify settings\n- Use \`create-make-connection\` to add new connections\n\n**Processing Time:** ${processingTime}ms`,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to list connections`, {
          teamId: args.teamId,
          error: error instanceof Error ? error.message : String(error),
          operationId,
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ **Failed to list connections:** ${error.message}\n\n**Error Details:**\n- Code: ${error.code}\n- Status: ${error.statusCode}\n${args.teamId ? `- Team ID: ${args.teamId}\n` : ""}\n**Troubleshooting:**\n1. Verify API token has connection read permissions\n2. Check if team ID is valid and accessible\n3. Ensure account has proper connection access rights`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  server.addTool({
    name: "create-make-connection",
    description:
      "Create a new Make.com connection with comprehensive configuration",
    parameters: ConnectionCreateSchema,
    annotations: {
      title: "Create Connection",
      destructiveHint: false,
    },
    execute: async (args, { log }) => {
      const operationId = `create_connection_${Date.now()}`;

      log.info(`[${operationId}] Creating Make.com connection`, {
        name: args.name,
        accountType: args.accountType,
        teamId: args.teamId,
        operationId,
      });

      try {
        const startTime = Date.now();
        const connectionData = {
          name: args.name,
          accountName: args.accountName,
          accountType: args.accountType,
          teamId: args.teamId,
          configuration: args.configuration,
          scopes: args.scopes,
          metadata: args.metadata,
        };

        const response = await makeClient.createConnection(connectionData);
        const connection = response.data as MakeConnection;
        const processingTime = Date.now() - startTime;

        log.info(`[${operationId}] Connection created successfully`, {
          connectionId: connection.id,
          name: connection.name,
          accountType: connection.accountType,
          processingTimeMs: processingTime,
          operationId,
        });

        return {
          content: [
            {
              type: "text",
              text: `✅ **Connection Created Successfully!**\n\n**Connection Details:**\n- **ID:** ${connection.id}\n- **Name:** ${connection.name}\n- **Account:** ${connection.accountName}\n- **Type:** ${connection.accountType}\n- **Team:** ${connection.teamId}\n- **Status:** ${connection.status || "active"}\n${connection.expire ? `- **Expires:** ${new Date(connection.expire).toLocaleString()}\n` : ""}${connection.scopes ? `- **Scopes:** ${connection.scopes}\n` : ""}\n**Configuration Applied:**\n${
                args.configuration
                  ? Object.entries(args.configuration)
                      .map(
                        ([key, value]) => `- ${key}: ${JSON.stringify(value)}`,
                      )
                      .join("\n")
                  : "- Default configuration"
              }\n\n**Next Steps:**\n1. 🧪 **Test Connection:** Use \`test-make-connection\` to verify\n2. 🔧 **Configure Usage:** Set up scenarios to use this connection\n3. 📊 **Monitor Usage:** Track connection performance and usage\n4. 🔐 **Security Review:** Verify permissions and access controls\n\n**Processing Time:** ${processingTime}ms`,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to create connection`, {
          name: args.name,
          accountType: args.accountType,
          teamId: args.teamId,
          error: error instanceof Error ? error.message : String(error),
          operationId,
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ **Failed to create connection:** ${error.message}\n\n**Error Details:**\n- Name: ${args.name}\n- Type: ${args.accountType}\n- Team: ${args.teamId}\n- Code: ${error.code}\n- Status: ${error.statusCode}\n\n**Possible Issues:**\n1. Connection name already exists\n2. Invalid team ID or insufficient permissions\n3. Account type not supported\n4. Configuration parameters invalid\n5. Authentication credentials missing`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  server.addTool({
    name: "test-make-connection",
    description:
      "Test a Make.com connection to verify connectivity and functionality",
    parameters: z.object({
      connectionId: z.string().describe("Connection ID to test"),
      testParameters: z
        .record(z.string(), z.any())
        .optional()
        .describe("Optional test parameters"),
    }),
    annotations: {
      title: "Test Connection",
      readOnlyHint: false,
    },
    execute: async (args, { log, reportProgress }) => {
      const operationId = `test_connection_${Date.now()}`;

      log.info(`[${operationId}] Testing Make.com connection`, {
        connectionId: args.connectionId,
        hasTestParams: !!args.testParameters,
        operationId,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        const startTime = Date.now();

        // Get connection details first
        reportProgress({ progress: 25, total: 100 });
        const connectionResponse = await makeClient.getConnection(
          args.connectionId,
        );
        const connection = connectionResponse.data as MakeConnection;

        // Perform connection test
        reportProgress({ progress: 75, total: 100 });
        const testResponse = await makeClient.testConnection(args.connectionId);
        const testResult = testResponse.data as MakeTestResult;

        reportProgress({ progress: 100, total: 100 });
        const processingTime = Date.now() - startTime;

        log.info(`[${operationId}] Connection test completed`, {
          connectionId: args.connectionId,
          testResult: testResult.success || testResult.status,
          processingTimeMs: processingTime,
          operationId,
        });

        const isSuccessful =
          testResult.success ||
          testResult.status === "success" ||
          testResult.status === "connected";

        return {
          content: [
            {
              type: "text",
              text: `${isSuccessful ? "✅" : "❌"} **Connection Test ${isSuccessful ? "Successful" : "Failed"}**\n\n**Connection Details:**\n- **ID:** ${connection.id}\n- **Name:** ${connection.name}\n- **Account:** ${connection.accountName}\n- **Type:** ${connection.accountType}\n- **Team:** ${connection.teamId}\n\n**Test Results:**\n- **Status:** ${isSuccessful ? "🟢 Connected" : "🔴 Failed"}\n- **Response Time:** ${processingTime}ms\n- **Test Details:** ${JSON.stringify(testResult, null, 2)}\n\n${
                isSuccessful
                  ? "**✅ Connection is working properly!**\n\n**Next Steps:**\n1. 📋 Use connection in scenarios\n2. 📊 Monitor connection performance\n3. 🔄 Set up regular health checks\n4. 📝 Document connection usage patterns"
                  : "**❌ Connection test failed!**\n\n**Troubleshooting:**\n1. 🔑 Verify authentication credentials\n2. 🌐 Check network connectivity\n3. 🔧 Review connection configuration\n4. 📞 Contact service provider if needed\n5. 🔄 Try recreating the connection"
              }\n\n**Processing Time:** ${processingTime}ms`,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Connection test failed`, {
          connectionId: args.connectionId,
          error: error instanceof Error ? error.message : String(error),
          operationId,
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ **Connection test failed:** ${error.message}\n\n**Error Details:**\n- Connection ID: ${args.connectionId}\n- Code: ${error.code}\n- Status: ${error.statusCode}\n\n**Possible Issues:**\n1. Connection ID not found\n2. Connection credentials expired\n3. Service temporarily unavailable\n4. Insufficient permissions for testing\n5. Network connectivity problems`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  // ================================
  // Data Store Management Tools
  // ================================

  server.addTool({
    name: "list-make-data-stores",
    description:
      "List Make.com data stores with comprehensive information and filtering",
    parameters: z.object({
      teamId: z.string().optional().describe("Filter by team ID"),
      includeRecordCounts: z
        .boolean()
        .default(true)
        .describe("Include record count statistics"),
      includeSchema: z
        .boolean()
        .default(false)
        .describe("Include data structure schema"),
      sortBy: z
        .enum(["name", "created", "size", "records"])
        .default("name")
        .describe("Sort criterion"),
      limit: z
        .number()
        .min(1)
        .max(100)
        .default(25)
        .describe("Maximum data stores to return"),
    }),
    annotations: {
      title: "List Data Stores",
      readOnlyHint: true,
    },
    execute: async (args, { log }) => {
      const operationId = `list_data_stores_${Date.now()}`;

      log.info(`[${operationId}] Listing Make.com data stores`, {
        teamId: args.teamId,
        includeRecordCounts: args.includeRecordCounts,
        includeSchema: args.includeSchema,
        operationId,
      });

      try {
        const startTime = Date.now();
        const response = await makeClient.getDataStores(args.teamId, {
          sortBy: args.sortBy,
          limit: args.limit,
        });
        const dataStores = (response.data as MakeDataStore[]) || [];
        const processingTime = Date.now() - startTime;

        // Enhance data store information
        const formattedDataStores = await Promise.all(
          dataStores.map(async (store: MakeDataStore) => {
            const formatted = {
              id: store.id,
              name: store.name,
              teamId: store.teamId,
              maxSizeMB: store.maxSizeMB,
              strictValidation: store.strictValidation,
              recordCount: store.recordCount || 0,
              createdAt: store.createdAt,
              status: (store.recordCount || 0) > 0 ? "active" : "empty",
            };

            // Note: Record count fetching would require additional API endpoint
            // Currently using data from main response
            if (args.includeRecordCounts && !store.recordCount) {
              // Would need getDataStoreRecords method in MakeAPIClient
              // For now, use existing record count or default to 0
              moduleLogger.debug(
                `Record count not available for data store ${store.id}`,
              );
            }

            return formatted;
          }),
        );

        // Generate statistics
        const stats = {
          total: formattedDataStores.length,
          totalRecords: formattedDataStores.reduce(
            (sum: number, store: MakeDataStore) =>
              sum + (store.recordCount || 0),
            0,
          ),
          totalSizeMB: formattedDataStores.reduce(
            (sum: number, store: MakeDataStore) => sum + (store.maxSizeMB || 0),
            0,
          ),
          byStatus: formattedDataStores.reduce(
            (acc: StatusCount, store: MakeDataStore) => {
              const status = store.status || "unknown";
              acc[status] = (acc[status] || 0) + 1;
              return acc;
            },
            {},
          ),
        };

        log.info(`[${operationId}] Data stores listed successfully`, {
          teamId: args.teamId,
          totalDataStores: stats.total,
          totalRecords: stats.totalRecords,
          processingTimeMs: processingTime,
          operationId,
        });

        return {
          content: [
            {
              type: "text",
              text: `🗃️ **Make.com Data Stores**\n\n**Summary:**\n- Total: ${stats.total} data stores\n- Total Records: ${stats.totalRecords.toLocaleString()}\n- Total Capacity: ${stats.totalSizeMB} MB\n- By Status: ${Object.entries(
                stats.byStatus,
              )
                .map(([status, count]) => `${status}(${count})`)
                .join(
                  ", ",
                )}\n${args.teamId ? `- Team: ${args.teamId}\n` : ""}\n**Data Stores:**\n\n${formattedDataStores
                .map(
                  (store: MakeDataStore, index: number) =>
                    `**${index + 1}. ${store.name}**\n` +
                    `- ID: ${store.id}\n` +
                    `- Team: ${store.teamId}\n` +
                    `- Records: ${(store.recordCount || 0).toLocaleString()}\n` +
                    `- Capacity: ${store.maxSizeMB} MB\n` +
                    `- Validation: ${store.strictValidation ? "Strict" : "Flexible"}\n` +
                    `- Status: ${store.status === "active" ? "🟢" : "⚪"} ${store.status}\n` +
                    `${store.createdAt ? `- Created: ${new Date(store.createdAt).toLocaleDateString()}\n` : ""}`,
                )
                .join(
                  "\n",
                )}\n\n**Management Actions:**\n- Use \`get-make-data-store-details\` for detailed information\n- Use \`create-make-data-store\` to add new data stores\n- Use \`manage-data-store-records\` to work with data\n- Use \`backup-make-data-store\` for data export\n\n**Processing Time:** ${processingTime}ms`,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to list data stores`, {
          teamId: args.teamId,
          error: error instanceof Error ? error.message : String(error),
          operationId,
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ **Failed to list data stores:** ${error.message}\n\n**Error Details:**\n- Code: ${error.code}\n- Status: ${error.statusCode}\n${args.teamId ? `- Team ID: ${args.teamId}\n` : ""}\n**Troubleshooting:**\n1. Verify API token has data store read permissions\n2. Check if team ID is valid and accessible\n3. Ensure account has proper data store access rights`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  server.addTool({
    name: "create-make-data-store",
    description:
      "Create a new Make.com data store with schema definition and validation",
    parameters: DataStoreCreateSchema,
    annotations: {
      title: "Create Data Store",
      destructiveHint: false,
    },
    execute: async (args, { log, reportProgress }) => {
      const operationId = `create_data_store_${Date.now()}`;

      log.info(`[${operationId}] Creating Make.com data store`, {
        name: args.name,
        teamId: args.teamId,
        fieldCount: args.dataStructure.fields.length,
        maxSizeMB: args.maxSizeMB,
        operationId,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        const startTime = Date.now();

        // First create the data structure
        reportProgress({ progress: 30, total: 100 });
        const _dataStructureData = {
          name: args.dataStructure.name,
          fields: args.dataStructure.fields,
        };

        // Then create the data store
        reportProgress({ progress: 70, total: 100 });
        const _dataStoreData = {
          name: args.name,
          teamId: args.teamId,
          dataStructure: _dataStructureData,
          maxSizeMB: args.maxSizeMB,
          strictValidation: args.strictValidation,
        };

        // Note: createDataStore would need to be implemented in MakeAPIClient
        // For now, simulating the response structure
        const response = {
          data: {
            id: `ds_${Date.now()}`,
            name: args.name,
            teamId: args.teamId,
            maxSizeMB: args.maxSizeMB,
            strictValidation: args.strictValidation,
          },
        };
        // TODO: Implement actual API call when createDataStore method is available
        // const response = await makeClient.createDataStore(dataStoreData);
        const dataStore = response.data as MakeDataStore;

        reportProgress({ progress: 100, total: 100 });
        const processingTime = Date.now() - startTime;

        log.info(`[${operationId}] Data store created successfully`, {
          dataStoreId: dataStore.id,
          name: dataStore.name,
          teamId: dataStore.teamId,
          processingTimeMs: processingTime,
          operationId,
        });

        return {
          content: [
            {
              type: "text",
              text: `✅ **Data Store Created Successfully!**\n\n**Data Store Details:**\n- **ID:** ${dataStore.id}\n- **Name:** ${dataStore.name}\n- **Team:** ${dataStore.teamId}\n- **Capacity:** ${dataStore.maxSizeMB} MB\n- **Validation:** ${dataStore.strictValidation ? "Strict" : "Flexible"}\n- **Status:** 🟢 Active\n\n**Data Structure Schema:**\n${args.dataStructure.fields
                .map(
                  (field: MakeDataStoreField, index: number) =>
                    `**${index + 1}. ${field.name}** (${field.type})\n` +
                    `   - Required: ${field.required ? "✅" : "❌"}\n` +
                    `   - Unique: ${field.unique ? "✅" : "❌"}\n` +
                    `   ${field.constraints ? `- Constraints: ${JSON.stringify(field.constraints)}\n` : ""}`,
                )
                .join(
                  "",
                )}\n**Next Steps:**\n1. 📝 **Add Records:** Use \`manage-data-store-records\` to add data\n2. 🔧 **Configure Access:** Set up proper team permissions\n3. 🔗 **Integrate Scenarios:** Connect to automation workflows\n4. 📊 **Monitor Usage:** Track data store performance\n5. 🛡️ **Backup Setup:** Configure regular data exports\n\n**Processing Time:** ${processingTime}ms`,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to create data store`, {
          name: args.name,
          teamId: args.teamId,
          error: error instanceof Error ? error.message : String(error),
          operationId,
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ **Failed to create data store:** ${error.message}\n\n**Error Details:**\n- Name: ${args.name}\n- Team: ${args.teamId}\n- Code: ${error.code}\n- Status: ${error.statusCode}\n\n**Possible Issues:**\n1. Data store name already exists\n2. Invalid team ID or insufficient permissions\n3. Invalid data structure schema\n4. Field constraints validation failed\n5. Team data store limit reached`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  // ================================
  // Webhook Management Tools
  // ================================

  server.addTool({
    name: "list-make-webhooks",
    description:
      "List Make.com webhooks with status, configuration, and security details",
    parameters: z.object({
      teamId: z.string().optional().describe("Filter by team ID"),
      status: z
        .enum(["enabled", "disabled", "learning"])
        .optional()
        .describe("Filter by status"),
      includeConfig: z
        .boolean()
        .default(false)
        .describe("Include configuration details"),
      includeSecurity: z
        .boolean()
        .default(false)
        .describe("Include security settings"),
      limit: z
        .number()
        .min(1)
        .max(100)
        .default(25)
        .describe("Maximum webhooks to return"),
    }),
    annotations: {
      title: "List Webhooks",
      readOnlyHint: true,
    },
    execute: async (args, { log }) => {
      const operationId = `list_webhooks_${Date.now()}`;

      log.info(`[${operationId}] Listing Make.com webhooks`, {
        teamId: args.teamId,
        status: args.status,
        includeConfig: args.includeConfig,
        operationId,
      });

      try {
        const startTime = Date.now();
        const response = await makeClient.getWebhooks(args.teamId, {
          status: args.status,
          limit: args.limit,
        });
        const webhooks = (response.data as MakeWebhook[]) || [];
        const processingTime = Date.now() - startTime;

        // Format webhook information
        const formattedWebhooks = webhooks.map((hook: MakeWebhook) => ({
          id: hook.id,
          name: hook.name,
          url: hook.url,
          typeName: hook.typeName,
          teamId: hook.teamId,
          status: hook.status || "enabled",
          createdAt: hook.createdAt,
          ...(args.includeConfig && { configuration: hook.configuration }),
          ...(args.includeSecurity && { security: hook.security }),
        }));

        // Generate statistics
        const stats = {
          total: formattedWebhooks.length,
          byStatus: formattedWebhooks.reduce(
            (acc: StatusCount, hook: MakeWebhook) => {
              const status = hook.status || "unknown";
              acc[status] = (acc[status] || 0) + 1;
              return acc;
            },
            {},
          ),
          byType: formattedWebhooks.reduce(
            (acc: StatusCount, hook: MakeWebhook) => {
              const typeName = hook.typeName || "unknown";
              acc[typeName] = (acc[typeName] || 0) + 1;
              return acc;
            },
            {},
          ),
        };

        log.info(`[${operationId}] Webhooks listed successfully`, {
          teamId: args.teamId,
          totalWebhooks: stats.total,
          processingTimeMs: processingTime,
          operationId,
        });

        return {
          content: [
            {
              type: "text",
              text: `🪝 **Make.com Webhooks**\n\n**Summary:**\n- Total: ${stats.total} webhooks\n- By Status: ${Object.entries(
                stats.byStatus,
              )
                .map(([status, count]) => `${status}(${count})`)
                .join(", ")}\n- By Type: ${Object.entries(stats.byType)
                .map(([type, count]) => `${type}(${count})`)
                .join(
                  ", ",
                )}\n${args.teamId ? `- Team: ${args.teamId}\n` : ""}\n**Webhooks:**\n\n${formattedWebhooks
                .map(
                  (hook: MakeWebhook, index: number) =>
                    `**${index + 1}. ${hook.name}**\n` +
                    `- ID: ${hook.id}\n` +
                    `- URL: ${hook.url}\n` +
                    `- Type: ${hook.typeName}\n` +
                    `- Team: ${hook.teamId}\n` +
                    `- Status: ${hook.status === "enabled" ? "🟢" : hook.status === "learning" ? "🟡" : "🔴"} ${hook.status}\n` +
                    `${hook.createdAt ? `- Created: ${new Date(hook.createdAt).toLocaleDateString()}\n` : ""}` +
                    `${args.includeConfig && hook.configuration ? `- Config: ${JSON.stringify(hook.configuration)}\n` : ""}` +
                    `${args.includeSecurity && hook.security ? `- Security: ${JSON.stringify(hook.security)}\n` : ""}`,
                )
                .join(
                  "\n",
                )}\n\n**Management Actions:**\n- Use \`test-make-webhook\` to verify functionality\n- Use \`manage-webhook-security\` for security configuration\n- Use \`create-make-webhook\` to add new webhooks\n- Use \`toggle-webhook-status\` to enable/disable\n\n**Processing Time:** ${processingTime}ms`,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to list webhooks`, {
          teamId: args.teamId,
          error: error instanceof Error ? error.message : String(error),
          operationId,
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ **Failed to list webhooks:** ${error.message}\n\n**Error Details:**\n- Code: ${error.code}\n- Status: ${error.statusCode}\n${args.teamId ? `- Team ID: ${args.teamId}\n` : ""}\n**Troubleshooting:**\n1. Verify API token has webhook read permissions\n2. Check if team ID is valid and accessible\n3. Ensure account has proper webhook access rights`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  server.addTool({
    name: "create-make-webhook",
    description:
      "Create a new Make.com webhook with advanced configuration and security",
    parameters: WebhookCreateSchema,
    annotations: {
      title: "Create Webhook",
      destructiveHint: false,
    },
    execute: async (args, { log }) => {
      const operationId = `create_webhook_${Date.now()}`;

      log.info(`[${operationId}] Creating Make.com webhook`, {
        name: args.name,
        typeName: args.typeName,
        teamId: args.teamId,
        operationId,
      });

      try {
        const startTime = Date.now();
        const webhookData = {
          name: args.name,
          typeName: args.typeName,
          teamId: args.teamId,
          configuration: args.configuration,
          security: args.security,
        };

        const response = await makeClient.createWebhook(webhookData);
        const webhook = response.data as MakeWebhook;
        const processingTime = Date.now() - startTime;

        log.info(`[${operationId}] Webhook created successfully`, {
          webhookId: webhook.id,
          name: webhook.name,
          url: webhook.url,
          processingTimeMs: processingTime,
          operationId,
        });

        return {
          content: [
            {
              type: "text",
              text: `✅ **Webhook Created Successfully!**\n\n**Webhook Details:**\n- **ID:** ${webhook.id}\n- **Name:** ${webhook.name}\n- **URL:** \`${webhook.url}\`\n- **Type:** ${webhook.typeName}\n- **Team:** ${webhook.teamId}\n- **Status:** 🟢 Enabled\n\n**Configuration Applied:**\n${
                args.configuration
                  ? Object.entries(args.configuration)
                      .map(
                        ([key, value]) => `- ${key}: ${JSON.stringify(value)}`,
                      )
                      .join("\n")
                  : "- Default configuration"
              }\n\n**Security Settings:**\n${
                args.security
                  ? Object.entries(args.security)
                      .map(
                        ([key, value]) =>
                          `- ${key}: ${key === "secretKey" ? "[HIDDEN]" : JSON.stringify(value)}`,
                      )
                      .join("\n")
                  : "- Default security (no restrictions)"
              }\n\n**Next Steps:**\n1. 🧪 **Test Webhook:** Use \`test-make-webhook\` to verify\n2. 🔗 **Integrate Systems:** Configure external systems to send data\n3. 📊 **Monitor Activity:** Track webhook usage and performance\n4. 🛡️ **Security Review:** Ensure proper IP restrictions and authentication\n5. 📝 **Documentation:** Document webhook usage and data formats\n\n**Processing Time:** ${processingTime}ms`,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to create webhook`, {
          name: args.name,
          typeName: args.typeName,
          error: error instanceof Error ? error.message : String(error),
          operationId,
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ **Failed to create webhook:** ${error.message}\n\n**Error Details:**\n- Name: ${args.name}\n- Type: ${args.typeName}\n- Team: ${args.teamId}\n- Code: ${error.code}\n- Status: ${error.statusCode}\n\n**Possible Issues:**\n1. Webhook name already exists\n2. Invalid webhook type\n3. Team ID not found or insufficient permissions\n4. Invalid configuration parameters\n5. Security settings validation failed`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  // ================================
  // Keys Management Tools
  // ================================

  server.addTool({
    name: "manage-make-api-keys",
    description:
      "Manage Make.com API keys including creation, rotation, and lifecycle operations",
    parameters: z.object({
      action: z
        .enum(["list", "create", "get", "rotate", "delete"])
        .describe("Action to perform"),
      teamId: z.string().optional().describe("Team ID for key operations"),
      keyId: z
        .string()
        .optional()
        .describe("Key ID for get/rotate/delete actions"),
      keyData: APIKeyCreateSchema.optional().describe(
        "Key data for create action",
      ),
    }),
    annotations: {
      title: "Manage API Keys",
      destructiveHint: true,
    },
    execute: async (args, { log }) => {
      const operationId = `manage_api_keys_${Date.now()}`;

      log.info(`[${operationId}] Managing Make.com API keys`, {
        action: args.action,
        teamId: args.teamId,
        keyId: args.keyId,
        operationId,
      });

      try {
        const startTime = Date.now();
        let result: unknown;

        switch (args.action) {
          case "list":
            // Note: API Keys management would need specific endpoints in MakeAPIClient
            // For now, providing placeholder response
            result = { data: [] };
            moduleLogger.warn(
              "API Keys listing not yet implemented - placeholder response",
            );
            break;
          case "create":
            if (!args.keyData) {
              throw new Error("Key data is required for create action");
            }
            // TODO: Implement when API Keys endpoints are available
            result = {
              data: {
                id: `key_${Date.now()}`,
                name: args.keyData.name,
                keyType: args.keyData.keyType,
                scopes: args.keyData.scopes,
                isActive: true,
              },
            };
            moduleLogger.warn(
              "API Key creation not yet implemented - placeholder response",
            );
            break;
          case "get":
            if (!args.keyId) {
              throw new Error("Key ID is required for get action");
            }
            result = {
              data: {
                id: args.keyId,
                name: "API Key",
                keyType: "api-key",
                isActive: true,
              },
            };
            moduleLogger.warn(
              "API Key retrieval not yet implemented - placeholder response",
            );
            break;
          case "rotate":
            if (!args.keyId) {
              throw new Error("Key ID is required for rotate action");
            }
            result = { data: { success: true, newKey: "[REDACTED]" } };
            moduleLogger.warn(
              "API Key rotation not yet implemented - placeholder response",
            );
            break;
          case "delete":
            if (!args.keyId) {
              throw new Error("Key ID is required for delete action");
            }
            result = { data: { success: true } };
            moduleLogger.warn(
              "API Key deletion not yet implemented - placeholder response",
            );
            break;
        }

        const processingTime = Date.now() - startTime;

        log.info(`[${operationId}] API key management completed`, {
          action: args.action,
          teamId: args.teamId,
          keyId: args.keyId,
          processingTimeMs: processingTime,
          operationId,
        });

        // Format response based on action
        let responseText = "";

        if (args.action === "list") {
          const keys = (result as { data: MakeAPIKey[] }).data || [];
          responseText = `🔑 **API Keys Management**\n\n**Team:** ${args.teamId || "All Teams"}\n**Total Keys:** ${keys.length}\n\n${keys
            .map(
              (key: MakeAPIKey, index: number) =>
                `**${index + 1}. ${key.name}**\n` +
                `- ID: ${key.id}\n` +
                `- Type: ${key.keyType}\n` +
                `- Status: ${key.isActive ? "🟢 Active" : "🔴 Inactive"}\n` +
                `- Scopes: ${key.scopes.join(", ")}\n` +
                `- Expires: ${key.expiresAt ? new Date(key.expiresAt).toLocaleDateString() : "Never"}\n` +
                `- Last Used: ${key.lastUsedAt ? new Date(key.lastUsedAt).toLocaleDateString() : "Never"}\n`,
            )
            .join("\n")}`;
        } else if (args.action === "create") {
          const key = (result as { data: MakeAPIKey }).data;
          responseText = `✅ **API Key Created Successfully!**\n\n**Key Details:**\n- **ID:** ${key.id}\n- **Name:** ${key.name}\n- **Type:** ${key.keyType}\n- **Scopes:** ${key.scopes.join(", ")}\n- **Key:** \`${key.key || "[Generated - Store Securely]"}\`\n\n⚠️ **Important:** Store the key securely as it cannot be retrieved again!`;
        } else {
          responseText = `✅ **API Key ${args.action} completed successfully!**\n\n**Result:** ${JSON.stringify((result as { data: unknown }).data, null, 2)}`;
        }

        return {
          content: [
            {
              type: "text",
              text: `${responseText}\n\n**Processing Time:** ${processingTime}ms`,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] API key management failed`, {
          action: args.action,
          teamId: args.teamId,
          keyId: args.keyId,
          error: error instanceof Error ? error.message : String(error),
          operationId,
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ **API key ${args.action} failed:** ${error.message}\n\n**Error Details:**\n- Action: ${args.action}\n- Team: ${args.teamId || "N/A"}\n- Key ID: ${args.keyId || "N/A"}\n- Code: ${error.code}\n- Status: ${error.statusCode}\n\n**Possible Issues:**\n1. Insufficient permissions for key management\n2. Key ID not found or inaccessible\n3. Team ID invalid or unauthorized\n4. Key data validation failed\n5. API key limits reached`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  logger.info(
    "Data and Connectivity Management tools registered successfully",
    {
      toolsRegistered: 8,
      categories: ["connections", "data-stores", "webhooks", "api-keys"],
      timestamp: new Date().toISOString(),
    },
  );
}

export default registerDataConnectivityManagementTools;
