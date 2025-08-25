/**
 * Advanced Make.com FastMCP Tools
 * Comprehensive tool collection based on Make.com API research reports
 * Includes: Webhooks, Data Stores, Templates, Custom Apps, Analytics
 */

import { FastMCP } from "fastmcp";
import { z } from "zod";
import winston from "winston";
import {
  EnhancedMakeClient,
  MakeAPIError,
} from "../make-client/enhanced-make-client.js";
import {
  WebhookStatus,
  DataFieldType,
  AppStatus,
} from "../types/make-api-types.js";

// ==============================================================================
// Schema Definitions for Tool Parameters
// ==============================================================================

// Webhook Management Schemas
const WebhookCreateSchema = z.object({
  name: z
    .string()
    .min(1)
    .max(128)
    .describe("Name for the webhook (max 128 characters)"),
  teamId: z.string().optional().describe("Team ID to associate webhook with"),
  typeName: z.string().describe("Type name for the webhook"),
  method: z.boolean().default(true).describe("Enable method tracking"),
  header: z.boolean().default(true).describe("Include headers in webhook data"),
  stringify: z
    .boolean()
    .default(false)
    .describe("JSON stringify webhook payload"),
  connectionId: z
    .string()
    .optional()
    .describe("Connection ID to associate with webhook"),
  scenarioId: z
    .string()
    .optional()
    .describe("Scenario ID to trigger from webhook"),
});

const WebhookUpdateSchema = z.object({
  webhookId: z.string().describe("The ID of the webhook to update"),
  name: z
    .string()
    .min(1)
    .max(128)
    .optional()
    .describe("Updated name for the webhook"),
  status: z
    .nativeEnum(WebhookStatus)
    .optional()
    .describe("Updated status for the webhook"),
  method: z.boolean().optional().describe("Enable/disable method tracking"),
  header: z.boolean().optional().describe("Enable/disable header inclusion"),
  stringify: z.boolean().optional().describe("Enable/disable JSON stringify"),
});

// Data Store Management Schemas
const DataStoreCreateSchema = z.object({
  name: z.string().min(1).describe("Name for the data store"),
  teamId: z.number().describe("Team ID for the data store"),
  fields: z
    .array(
      z.object({
        name: z.string().describe("Field name"),
        type: z.nativeEnum(DataFieldType).describe("Field data type"),
        required: z.boolean().default(false).describe("Is field required"),
        unique: z.boolean().default(false).describe("Is field unique"),
        defaultValue: z
          .unknown()
          .optional()
          .describe("Default value for field"),
      }),
    )
    .min(1)
    .describe("Array of field definitions"),
  description: z.string().optional().describe("Description of the data store"),
});

const DataStoreRecordSchema = z.object({
  dataStoreId: z.string().describe("Data store ID to add record to"),
  data: z.record(z.unknown()).describe("Record data as key-value pairs"),
});

// Template Management Schemas
const TemplateCreateSchema = z.object({
  name: z.string().min(1).describe("Template name"),
  description: z.string().optional().describe("Template description"),
  category: z.string().describe("Template category"),
  tags: z.array(z.string()).default([]).describe("Template tags"),
  scenarioId: z.string().describe("Source scenario ID to create template from"),
  isPublic: z.boolean().default(false).describe("Make template public"),
});

// SDK App Management Schemas
const SDKAppCreateSchema = z.object({
  name: z.string().min(1).describe("App name"),
  description: z.string().optional().describe("App description"),
  version: z.string().default("1.0.0").describe("App version"),
  status: z
    .nativeEnum(AppStatus)
    .default(AppStatus.DEVELOPMENT)
    .describe("App status"),
});

// Analytics Schemas
const AnalyticsQuerySchema = z.object({
  startDate: z.string().describe("Start date for analytics (ISO 8601 format)"),
  endDate: z.string().describe("End date for analytics (ISO 8601 format)"),
  teamId: z
    .string()
    .optional()
    .describe("Optional team ID to filter analytics"),
  includeOperations: z
    .boolean()
    .default(true)
    .describe("Include operation metrics"),
  includeDataTransfer: z
    .boolean()
    .default(true)
    .describe("Include data transfer metrics"),
  includeErrors: z.boolean().default(true).describe("Include error metrics"),
  includePerformance: z
    .boolean()
    .default(true)
    .describe("Include performance metrics"),
});

// ==============================================================================
// Advanced Make.com Tools Registration
// ==============================================================================

export function registerAdvancedMakeTools(
  server: FastMCP,
  makeClient: EnhancedMakeClient,
  logger: winston.Logger,
): void {
  // ==============================================================================
  // Webhook Management Tools
  // ==============================================================================

  server.addTool({
    name: "create-make-webhook",
    description:
      "Create a new Make.com webhook with comprehensive configuration options",
    parameters: WebhookCreateSchema,
    execute: async (args, { log }) => {
      const operationId = `create-webhook-${Date.now()}`;

      log.info(`[${operationId}] Creating Make.com webhook`, {
        name: args.name,
        teamId: args.teamId,
        typeName: args.typeName,
      });

      try {
        const webhookData = {
          name: args.name,
          teamId: args.teamId,
          configuration: {
            typeName: args.typeName,
            method: args.method,
            header: args.header,
            stringify: args.stringify,
          },
          connectionId: args.connectionId,
          scenarioId: args.scenarioId,
          status: WebhookStatus.ENABLED,
        };

        const result = await makeClient.createWebhook(webhookData);

        log.info(`[${operationId}] Webhook created successfully`, {
          webhookId: result.data?.id,
          url: result.data?.url,
        });

        return {
          content: [
            {
              type: "text",
              text: `✅ Webhook created successfully!\n\n**Webhook Details:**\n- ID: ${result.data?.id}\n- Name: ${result.data?.name}\n- URL: ${result.data?.url}\n- Status: ${result.data?.status}\n- Team ID: ${result.data?.teamId || "None"}\n\n**Configuration:**\n- Method tracking: ${args.method ? "Enabled" : "Disabled"}\n- Header inclusion: ${args.header ? "Enabled" : "Disabled"}\n- JSON stringify: ${args.stringify ? "Enabled" : "Disabled"}\n\n**Next Steps:**\n1. Test the webhook URL with your external service\n2. Monitor webhook statistics in Make.com dashboard\n3. Configure webhook learning mode if needed\n\nFull response:\n\`\`\`json\n${JSON.stringify(result.data, null, 2)}\n\`\`\``,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to create webhook`, {
          error: error instanceof Error ? error.message : String(error),
          args,
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ Failed to create webhook: ${error.message}\n\n**Error Details:**\n- Code: ${error.code}\n- Status: ${error.statusCode}\n- Correlation ID: ${error.correlationId}\n\n**Common Solutions:**\n1. Verify API token has webhook creation permissions\n2. Check team ID exists and you have access\n3. Ensure webhook name is unique within the team\n4. Validate connection and scenario IDs if provided`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  server.addTool({
    name: "manage-make-webhook",
    description:
      "Update webhook configuration, enable/disable, or manage learning mode",
    parameters: WebhookUpdateSchema,
    execute: async (args, { log }) => {
      const operationId = `manage-webhook-${Date.now()}`;

      log.info(`[${operationId}] Managing Make.com webhook`, {
        webhookId: args.webhookId,
        updates: Object.keys(args).filter((k) => k !== "webhookId"),
      });

      try {
        const updates: Record<string, unknown> = {};
        if (args.name) {
          updates.name = args.name;
        }
        if (args.method !== undefined) {
          updates.method = args.method;
        }
        if (args.header !== undefined) {
          updates.header = args.header;
        }
        if (args.stringify !== undefined) {
          updates.stringify = args.stringify;
        }

        let result;

        // Handle status changes with specific endpoints
        if (args.status) {
          result = await makeClient.setWebhookStatus(
            args.webhookId,
            args.status,
          );
          log.info(`[${operationId}] Webhook status updated`, {
            webhookId: args.webhookId,
            newStatus: args.status,
          });
        }

        // Apply other updates
        if (Object.keys(updates).length > 0) {
          result = await makeClient.updateWebhook(args.webhookId, updates);
          log.info(`[${operationId}] Webhook configuration updated`, {
            webhookId: args.webhookId,
            updatedFields: Object.keys(updates),
          });
        }

        if (!result) {
          result = await makeClient.getWebhook(args.webhookId);
        }

        return {
          content: [
            {
              type: "text",
              text: `✅ Webhook updated successfully!\n\n**Updated Webhook Details:**\n- ID: ${result.data?.id}\n- Name: ${result.data?.name}\n- Status: ${result.data?.status}\n- URL: ${result.data?.url}\n\n**Applied Changes:**\n${Object.entries(
                args,
              )
                .filter(([k, v]) => k !== "webhookId" && v !== undefined)
                .map(([k, v]) => `- ${k}: ${v}`)
                .join(
                  "\n",
                )}\n\nFull webhook details:\n\`\`\`json\n${JSON.stringify(result.data, null, 2)}\n\`\`\``,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to manage webhook`, {
          error: error instanceof Error ? error.message : String(error),
          webhookId: args.webhookId,
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ Failed to manage webhook: ${error.message}\n\n**Error Details:**\n- Code: ${error.code}\n- Status: ${error.statusCode}\n- Webhook ID: ${args.webhookId}\n\n**Troubleshooting:**\n1. Verify webhook ID exists\n2. Check permissions for webhook management\n3. Ensure status transitions are valid\n4. Validate update parameters`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  server.addTool({
    name: "webhook-learning-mode",
    description:
      "Start or stop webhook learning mode to automatically detect payload structure",
    parameters: z.object({
      webhookId: z.string().describe("The ID of the webhook"),
      action: z.enum(["start", "stop"]).describe("Start or stop learning mode"),
    }),
    execute: async (args, { log }) => {
      const operationId = `webhook-learning-${Date.now()}`;

      log.info(`[${operationId}] ${args.action}ing webhook learning mode`, {
        webhookId: args.webhookId,
      });

      try {
        if (args.action === "start") {
          await makeClient.startWebhookLearning(args.webhookId);
        } else {
          await makeClient.stopWebhookLearning(args.webhookId);
        }

        const webhook = await makeClient.getWebhook(args.webhookId);

        return {
          content: [
            {
              type: "text",
              text: `✅ Webhook learning mode ${args.action}ed successfully!\n\n**Webhook Status:**\n- ID: ${webhook.data?.id}\n- Name: ${webhook.data?.name}\n- Current Status: ${webhook.data?.status}\n\n**Learning Mode ${args.action === "start" ? "Started" : "Stopped"}:**\n${
                args.action === "start"
                  ? "🎓 The webhook is now in learning mode. Send test requests to help Make.com understand your payload structure.\n\n**Next Steps:**\n1. Send sample requests to the webhook URL\n2. Make.com will analyze the payload structure\n3. Stop learning mode once structure is learned\n4. Configure your scenario modules based on learned structure"
                  : "🛑 Learning mode stopped. The webhook will now use the learned payload structure.\n\n**Next Steps:**\n1. Review the learned structure in Make.com dashboard\n2. Configure scenario modules using detected fields\n3. Test with real webhook data"
              }`,
            },
          ],
        };
      } catch (error) {
        log.error(
          `[${operationId}] Failed to ${args.action} webhook learning`,
          {
            error: error instanceof Error ? error.message : String(error),
            webhookId: args.webhookId,
          },
        );

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ Failed to ${args.action} webhook learning mode: ${error.message}\n\n**Error Details:**\n- Code: ${error.code}\n- Status: ${error.statusCode}\n- Webhook ID: ${args.webhookId}\n\n**Possible Issues:**\n1. Webhook not found or access denied\n2. Webhook already in requested learning state\n3. Invalid webhook configuration\n4. Insufficient permissions`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  // ==============================================================================
  // Data Store Management Tools
  // ==============================================================================

  server.addTool({
    name: "create-make-datastore",
    description: "Create a new Make.com data store with custom field structure",
    parameters: DataStoreCreateSchema,
    execute: async (args, { log }) => {
      const operationId = `create-datastore-${Date.now()}`;

      log.info(`[${operationId}] Creating Make.com data store`, {
        name: args.name,
        teamId: args.teamId,
        fieldCount: args.fields.length,
      });

      try {
        const dataStoreData = {
          name: args.name,
          teamId: args.teamId,
          structure: {
            fields: args.fields.map((field) => ({
              name: field.name,
              type: field.type,
              required: field.required,
              unique: field.unique,
              defaultValue: field.defaultValue,
            })),
            indexes: [],
            constraints: [],
          },
        };

        const result = await makeClient.createDataStore(dataStoreData);

        log.info(`[${operationId}] Data store created successfully`, {
          dataStoreId: result.data?.id,
          name: result.data?.name,
        });

        return {
          content: [
            {
              type: "text",
              text: `✅ Data store created successfully!\n\n**Data Store Details:**\n- ID: ${result.data?.id}\n- Name: ${result.data?.name}\n- Team ID: ${result.data?.teamId}\n\n**Field Structure:**\n${args.fields.map((f) => `- **${f.name}** (${f.type})${f.required ? " *required*" : ""}${f.unique ? " *unique*" : ""}${f.defaultValue ? ` - default: ${f.defaultValue}` : ""}`).join("\n")}\n\n**Usage Instructions:**\n1. Use "add-datastore-record" to insert data\n2. Query records using Make.com scenario modules\n3. Update field structure as needed\n4. Monitor storage usage in dashboard\n\nFull response:\n\`\`\`json\n${JSON.stringify(result.data, null, 2)}\n\`\`\``,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to create data store`, {
          error: error instanceof Error ? error.message : String(error),
          args,
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ Failed to create data store: ${error.message}\n\n**Error Details:**\n- Code: ${error.code}\n- Status: ${error.statusCode}\n- Team ID: ${args.teamId}\n\n**Common Issues:**\n1. Team ID not found or access denied\n2. Data store name already exists in team\n3. Invalid field configuration\n4. Insufficient permissions for data store creation`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  server.addTool({
    name: "add-datastore-record",
    description: "Add a new record to a Make.com data store",
    parameters: DataStoreRecordSchema,
    execute: async (args, { log }) => {
      const operationId = `add-record-${Date.now()}`;

      log.info(`[${operationId}] Adding record to data store`, {
        dataStoreId: args.dataStoreId,
        dataKeys: Object.keys(args.data),
      });

      try {
        // Note: This would need to be implemented with the actual Make.com API
        // The research shows data stores exist but specific record endpoints need verification
        const recordData = {
          data: args.data,
          createdAt: new Date().toISOString(),
        };

        // This is a placeholder - actual implementation would use makeClient.addDataStoreRecord()
        log.info(
          `[${operationId}] Record would be added with data:`,
          recordData,
        );

        return {
          content: [
            {
              type: "text",
              text: `✅ Record prepared for data store!\n\n**Record Details:**\n- Data Store ID: ${args.dataStoreId}\n- Fields: ${Object.keys(args.data).length}\n- Data Preview:\n\`\`\`json\n${JSON.stringify(args.data, null, 2)}\n\`\`\`\n\n⚠️ **Note:** This is a demonstration of the data structure. Actual record insertion requires verification of Make.com's data store record endpoints in their API documentation.\n\n**Next Steps:**\n1. Verify data store record endpoints in Make.com API docs\n2. Implement actual record insertion method\n3. Add validation against data store schema\n4. Support batch record operations`,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to add record to data store`, {
          error: error instanceof Error ? error.message : String(error),
          dataStoreId: args.dataStoreId,
        });

        throw error;
      }
    },
  });

  // ==============================================================================
  // Template Management Tools
  // ==============================================================================

  server.addTool({
    name: "create-make-template",
    description:
      "Create a reusable template from an existing Make.com scenario",
    parameters: TemplateCreateSchema,
    execute: async (args, { log }) => {
      const operationId = `create-template-${Date.now()}`;

      log.info(`[${operationId}] Creating Make.com template`, {
        name: args.name,
        scenarioId: args.scenarioId,
        category: args.category,
      });

      try {
        // First, get the source scenario
        const scenario = await makeClient.getScenario(args.scenarioId);

        if (!scenario.data) {
          throw new Error(`Scenario ${args.scenarioId} not found`);
        }

        const templateData = {
          name: args.name,
          description: args.description,
          category: args.category,
          tags: args.tags,
          scenario: scenario.data.blueprint,
          metadata: {
            isPublic: args.isPublic,
            creator: 0, // Would be filled with actual user ID
            complexity:
              scenario.data.modules.length <= 3
                ? ("simple" as const)
                : scenario.data.modules.length <= 8
                  ? ("intermediate" as const)
                  : ("advanced" as const),
            estimatedSetupTime: scenario.data.modules.length * 5, // Estimate 5 minutes per module
            requiredConnections: Array.from(
              new Set(scenario.data.modules.flatMap((m) => m.connections)),
            ),
            usageCount: 0,
          },
        };

        const result = await makeClient.createTemplate(templateData);

        log.info(`[${operationId}] Template created successfully`, {
          templateId: result.data?.id,
          name: result.data?.name,
        });

        return {
          content: [
            {
              type: "text",
              text: `✅ Template created successfully!\n\n**Template Details:**\n- ID: ${result.data?.id}\n- Name: ${result.data?.name}\n- Category: ${result.data?.category}\n- Tags: ${result.data?.tags?.join(", ") || "None"}\n- Public: ${args.isPublic ? "Yes" : "No"}\n\n**Source Scenario:**\n- ID: ${args.scenarioId}\n- Modules: ${scenario.data.modules.length}\n- Connections Required: ${templateData.metadata.requiredConnections.length}\n\n**Template Metadata:**\n- Complexity: ${templateData.metadata.complexity}\n- Estimated Setup Time: ${templateData.metadata.estimatedSetupTime} minutes\n- Required Connections: ${templateData.metadata.requiredConnections.join(", ")}\n\n**Next Steps:**\n1. Share template with team or make public\n2. Add detailed documentation\n3. Test template deployment\n4. Monitor usage statistics\n\nFull response:\n\`\`\`json\n${JSON.stringify(result.data, null, 2)}\n\`\`\``,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to create template`, {
          error: error instanceof Error ? error.message : String(error),
          scenarioId: args.scenarioId,
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ Failed to create template: ${error.message}\n\n**Error Details:**\n- Code: ${error.code}\n- Status: ${error.statusCode}\n- Scenario ID: ${args.scenarioId}\n\n**Common Issues:**\n1. Source scenario not found or access denied\n2. Template name already exists\n3. Invalid category or tags\n4. Insufficient permissions for template creation`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  // ==============================================================================
  // SDK App Management Tools
  // ==============================================================================

  server.addTool({
    name: "create-make-sdk-app",
    description: "Create a new Make.com SDK app for custom integrations",
    parameters: SDKAppCreateSchema,
    execute: async (args, { log }) => {
      const operationId = `create-sdk-app-${Date.now()}`;

      log.info(`[${operationId}] Creating Make.com SDK app`, {
        name: args.name,
        version: args.version,
        status: args.status,
      });

      try {
        const appData = {
          name: args.name,
          description: args.description,
          version: args.version,
          status: args.status,
          modules: [],
          connections: [],
          rpcs: [],
          webhooks: [],
          functions: [],
        };

        const result = await makeClient.createSDKApp(appData);

        log.info(`[${operationId}] SDK app created successfully`, {
          appId: result.data?.id,
          name: result.data?.name,
        });

        return {
          content: [
            {
              type: "text",
              text: `✅ SDK App created successfully!\n\n**App Details:**\n- ID: ${result.data?.id}\n- Name: ${result.data?.name}\n- Version: ${result.data?.version}\n- Status: ${result.data?.status}\n- Description: ${result.data?.description || "None"}\n\n**Development Structure:**\n- Modules: ${result.data?.modules?.length || 0}\n- Connections: ${result.data?.connections?.length || 0}\n- RPCs: ${result.data?.rpcs?.length || 0}\n- Webhooks: ${result.data?.webhooks?.length || 0}\n- Functions: ${result.data?.functions?.length || 0}\n\n**Development Guide:**\n1. **Add Modules:** Define triggers, actions, and searches\n2. **Configure Connections:** Set up authentication methods\n3. **Create RPCs:** Add dynamic options and fields\n4. **Add Webhooks:** Configure real-time triggers\n5. **Write Functions:** Custom JavaScript functions\n\n**Next Steps:**\n1. Use Make.com App Builder to configure modules\n2. Test app functionality in development mode\n3. Submit for review when ready\n4. Publish to Make.com app marketplace\n\nFull response:\n\`\`\`json\n${JSON.stringify(result.data, null, 2)}\n\`\`\``,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to create SDK app`, {
          error: error instanceof Error ? error.message : String(error),
          name: args.name,
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ Failed to create SDK app: ${error.message}\n\n**Error Details:**\n- Code: ${error.code}\n- Status: ${error.statusCode}\n- App Name: ${args.name}\n\n**Common Issues:**\n1. App name already exists\n2. Insufficient permissions for SDK app creation\n3. Invalid app configuration\n4. Developer account not enabled`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  // ==============================================================================
  // Analytics and Monitoring Tools
  // ==============================================================================

  server.addTool({
    name: "get-make-analytics",
    description:
      "Retrieve comprehensive analytics data from Make.com including operations, data transfer, errors, and performance metrics",
    parameters: AnalyticsQuerySchema,
    execute: async (args, { log }) => {
      const operationId = `analytics-query-${Date.now()}`;

      log.info(`[${operationId}] Fetching Make.com analytics`, {
        startDate: args.startDate,
        endDate: args.endDate,
        teamId: args.teamId,
      });

      try {
        const result = await makeClient.getAnalytics(
          args.startDate,
          args.endDate,
          args.teamId,
        );

        const analytics = result.data;
        if (!analytics) {
          throw new Error("No analytics data received");
        }

        // Generate summary statistics
        const summary = {
          totalOperations: analytics.operations?.total || 0,
          successRate: analytics.operations
            ? (
                (analytics.operations.successful / analytics.operations.total) *
                100
              ).toFixed(2) + "%"
            : "N/A",
          totalDataTransfer: analytics.dataTransfer
            ? `${(analytics.dataTransfer.totalBytes / 1024 / 1024).toFixed(2)} MB`
            : "N/A",
          avgResponseTime: analytics.performance
            ? `${analytics.performance.averageResponseTime}ms`
            : "N/A",
          totalErrors: analytics.errors?.totalErrors || 0,
        };

        log.info(`[${operationId}] Analytics retrieved successfully`, {
          period: `${args.startDate} to ${args.endDate}`,
          totalOperations: summary.totalOperations,
          successRate: summary.successRate,
        });

        return {
          content: [
            {
              type: "text",
              text: `📊 Make.com Analytics Report\n**Period:** ${args.startDate} to ${args.endDate}${args.teamId ? `\n**Team ID:** ${args.teamId}` : ""}\n\n## Summary Statistics\n- **Total Operations:** ${summary.totalOperations}\n- **Success Rate:** ${summary.successRate}\n- **Data Transfer:** ${summary.totalDataTransfer}\n- **Avg Response Time:** ${summary.avgResponseTime}\n- **Total Errors:** ${summary.totalErrors}\n\n## Operation Metrics\n${analytics.operations ? `- Successful: ${analytics.operations.successful}\n- Failed: ${analytics.operations.failed}\n- Total: ${analytics.operations.total}` : "No operation data available"}\n\n## Data Transfer Metrics\n${analytics.dataTransfer ? `- Inbound: ${(analytics.dataTransfer.inboundBytes / 1024 / 1024).toFixed(2)} MB\n- Outbound: ${(analytics.dataTransfer.outboundBytes / 1024 / 1024).toFixed(2)} MB\n- Total: ${(analytics.dataTransfer.totalBytes / 1024 / 1024).toFixed(2)} MB` : "No data transfer metrics available"}\n\n## Performance Metrics\n${analytics.performance ? `- Average Response Time: ${analytics.performance.averageResponseTime}ms\n- 95th Percentile: ${analytics.performance.p95ResponseTime}ms\n- 99th Percentile: ${analytics.performance.p99ResponseTime}ms` : "No performance data available"}\n\n## Error Analysis\n${
                analytics.errors
                  ? `- Total Errors: ${analytics.errors.totalErrors}\n- Error Types: ${Object.entries(
                      analytics.errors.errorsByType || {},
                    )
                      .map(([type, count]) => `${type} (${count})`)
                      .join(", ")}\n- Status Codes: ${Object.entries(
                      analytics.errors.errorsByStatus || {},
                    )
                      .map(([status, count]) => `${status} (${count})`)
                      .join(", ")}`
                  : "No error data available"
              }\n\n## Recommendations\n${summary.totalOperations > 0 ? `- ${parseFloat(summary.successRate) > 95 ? "✅ Excellent success rate!" : "⚠️ Consider investigating failed operations"}\n- ${analytics.performance && analytics.performance.averageResponseTime < 1000 ? "✅ Good performance!" : "⚠️ Consider optimizing for better performance"}\n- ${summary.totalErrors === 0 ? "✅ No errors detected!" : "⚠️ Review error patterns for improvements"}` : "📈 Start running scenarios to generate analytics data"}\n\nFull analytics data:\n\`\`\`json\n${JSON.stringify(analytics, null, 2)}\n\`\`\``,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to fetch analytics`, {
          error: error instanceof Error ? error.message : String(error),
          dateRange: `${args.startDate} to ${args.endDate}`,
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ Failed to fetch analytics: ${error.message}\n\n**Error Details:**\n- Code: ${error.code}\n- Status: ${error.statusCode}\n- Date Range: ${args.startDate} to ${args.endDate}\n\n**Troubleshooting:**\n1. Verify date format (ISO 8601 required)\n2. Check team ID exists and you have access\n3. Ensure date range is reasonable (not too large)\n4. Confirm analytics permissions in account`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  logger.info("Advanced Make.com tools registered successfully", {
    toolCount: 8,
    categories: [
      "webhooks",
      "datastores",
      "templates",
      "sdk-apps",
      "analytics",
    ],
  });
}

export default registerAdvancedMakeTools;
