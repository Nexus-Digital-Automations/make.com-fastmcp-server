/**
 * Scenario and Execution Management Tools for Make.com FastMCP Server
 *
 * Comprehensive FastMCP tools for scenario CRUD operations, blueprint management,
 * scheduling, monitoring, logs analysis, and incomplete executions management.
 *
 * Features:
 * - Complete scenario CRUD operations with advanced filtering
 * - Blueprint management and validation
 * - Scenario scheduling and automation control
 * - Advanced logs analysis and monitoring
 * - Comprehensive incomplete executions management
 * - Health monitoring and performance analytics
 *
 * Based on comprehensive Make.com API research:
 * - Scenarios API for full lifecycle management
 * - Executions API for monitoring and control
 * - Analytics API for performance insights
 * - Billing Administration APIs for usage tracking
 */

import { FastMCP } from "fastmcp";
import { z } from "zod";
import winston from "winston";
import { MakeAPIClient } from "../make-client/simple-make-client.js";

// Logger placeholder - will use logger passed to registration function
let _moduleLogger: winston.Logger;

// ================================
// Core Type Definitions and Schemas
// ================================

// Scenario Management Schemas
const ScenarioCreateSchema = z.object({
  name: z
    .string()
    .min(1)
    .max(255)
    .describe("Scenario name (max 255 characters)"),
  teamId: z.string().describe("Team ID to create scenario in"),
  blueprint: z
    .record(z.string(), z.any())
    .describe("Scenario blueprint configuration"),
  description: z.string().optional().describe("Scenario description"),
  folder: z.string().optional().describe("Folder to organize scenario in"),
  scheduling: z
    .object({
      type: z.enum(["immediately", "indefinitely", "interval", "times"]),
      interval: z.number().optional(),
      unit: z.enum(["minute", "hour", "day", "week", "month"]).optional(),
      times: z.number().optional(),
      startDate: z.string().optional(),
      endDate: z.string().optional(),
    })
    .optional()
    .describe("Scenario scheduling configuration"),
  isActive: z.boolean().default(false).describe("Start scenario as active"),
});

const ScenarioUpdateSchema = z.object({
  scenarioId: z.string().describe("Scenario ID to update"),
  name: z.string().optional().describe("Updated scenario name"),
  blueprint: z
    .record(z.string(), z.any())
    .optional()
    .describe("Updated blueprint configuration"),
  description: z.string().optional().describe("Updated description"),
  folder: z.string().optional().describe("Updated folder location"),
  scheduling: z
    .object({
      type: z.enum(["immediately", "indefinitely", "interval", "times"]),
      interval: z.number().optional(),
      unit: z.enum(["minute", "hour", "day", "week", "month"]).optional(),
      times: z.number().optional(),
      startDate: z.string().optional(),
      endDate: z.string().optional(),
    })
    .optional()
    .describe("Updated scheduling configuration"),
});

const ScenarioListSchema = z.object({
  teamId: z.string().optional().describe("Filter by team ID"),
  status: z
    .enum(["active", "inactive", "paused", "error"])
    .optional()
    .describe("Filter by scenario status"),
  folder: z.string().optional().describe("Filter by folder"),
  search: z.string().optional().describe("Search scenarios by name"),
  tags: z.array(z.string()).optional().describe("Filter by tags"),
  limit: z.number().min(1).max(100).default(25).describe("Results limit"),
  offset: z.number().min(0).default(0).describe("Results offset"),
  sortBy: z
    .enum(["name", "createdAt", "updatedAt", "status", "lastExecution"])
    .default("updatedAt")
    .describe("Sort field"),
  sortDir: z.enum(["asc", "desc"]).default("desc").describe("Sort direction"),
});

const ScenarioExecutionSchema = z.object({
  scenarioId: z.string().describe("Scenario ID to execute"),
  waitForCompletion: z
    .boolean()
    .default(false)
    .describe("Wait for execution to complete"),
  inputData: z
    .record(z.string(), z.any())
    .optional()
    .describe("Input data for the execution"),
  timeout: z
    .number()
    .min(5)
    .max(300)
    .default(30)
    .describe("Execution timeout in seconds"),
});

// Blueprint Management Schemas
const BlueprintValidationSchema = z.object({
  blueprint: z.record(z.string(), z.any()).describe("Blueprint to validate"),
  strictMode: z
    .boolean()
    .default(false)
    .describe("Enable strict validation mode"),
  checkConnections: z
    .boolean()
    .default(true)
    .describe("Validate connection references"),
  checkModules: z
    .boolean()
    .default(true)
    .describe("Validate module configurations"),
});

const BlueprintOptimizationSchema = z.object({
  scenarioId: z.string().describe("Scenario ID to optimize blueprint for"),
  optimizationType: z
    .enum(["performance", "cost", "reliability", "maintainability"])
    .describe("Type of optimization to apply"),
  analysisDepth: z
    .enum(["basic", "detailed", "comprehensive"])
    .default("detailed")
    .describe("Depth of analysis to perform"),
});

// Execution Monitoring Schemas
const _ExecutionLogsSchema = z.object({
  scenarioId: z.string().describe("Scenario ID for logs"),
  executionId: z.string().optional().describe("Specific execution ID"),
  dateRange: z
    .object({
      from: z.string().describe("Start date (ISO format)"),
      to: z.string().describe("End date (ISO format)"),
    })
    .optional()
    .describe("Date range for logs"),
  status: z
    .enum(["success", "error", "warning", "running", "stopped"])
    .optional()
    .describe("Filter by execution status"),
  limit: z.number().min(1).max(1000).default(100).describe("Results limit"),
  includeDetails: z
    .boolean()
    .default(true)
    .describe("Include detailed execution data"),
});

const _IncompleteExecutionsSchema = z.object({
  scenarioId: z.string().optional().describe("Filter by scenario ID"),
  teamId: z.string().optional().describe("Filter by team ID"),
  dateRange: z
    .object({
      from: z.string().describe("Start date (ISO format)"),
      to: z.string().describe("End date (ISO format)"),
    })
    .optional()
    .describe("Date range for incomplete executions"),
  errorTypes: z.array(z.string()).optional().describe("Filter by error types"),
  limit: z.number().min(1).max(100).default(25).describe("Results limit"),
  includeBlueprints: z
    .boolean()
    .default(false)
    .describe("Include scenario blueprints"),
});

// Analytics and Monitoring Schemas
const _ScenarioAnalyticsSchema = z.object({
  scenarioId: z.string().optional().describe("Specific scenario ID"),
  teamId: z.string().optional().describe("Team ID for analytics"),
  dateRange: z
    .object({
      from: z.string().describe("Start date (ISO format)"),
      to: z.string().describe("End date (ISO format)"),
    })
    .describe("Date range for analytics"),
  metrics: z
    .array(
      z.enum([
        "executions",
        "success_rate",
        "performance",
        "costs",
        "errors",
        "data_transfer",
      ]),
    )
    .default(["executions", "success_rate", "performance"])
    .describe("Metrics to include"),
  granularity: z
    .enum(["hour", "day", "week", "month"])
    .default("day")
    .describe("Data granularity"),
});

// ================================
// Tool Implementation Functions
// ================================

/**
 * Register all scenario and execution management tools with the FastMCP server
 */
export function registerScenarioExecutionManagementTools(
  server: FastMCP,
  makeClient: MakeAPIClient,
  logger: winston.Logger,
): void {
  _moduleLogger = logger;

  // ================================
  // Scenario CRUD Operations
  // ================================

  server.addTool({
    name: "list-scenarios-advanced",
    description:
      "List Make.com scenarios with comprehensive filtering, search, and sorting capabilities",
    parameters: ScenarioListSchema,
    annotations: {
      title: "Advanced Scenario Listing",
      readOnlyHint: true,
      openWorldHint: false,
    },
    execute: async (args, { log, reportProgress }) => {
      const operationId = `list-scenarios-${Date.now()}`;

      log.info(`[${operationId}] Starting advanced scenario listing`, {
        filters: args,
        correlationId: operationId,
      });

      reportProgress({ progress: 10, total: 100 });

      try {
        // Build query parameters
        const queryParams: Record<string, any> = {
          limit: args.limit,
          offset: args.offset,
          sortBy: args.sortBy,
          sortDir: args.sortDir,
        };

        if (args.teamId) {
          queryParams.teamId = args.teamId;
        }
        if (args.status) {
          queryParams.status = args.status;
        }
        if (args.folder) {
          queryParams.folder = args.folder;
        }
        if (args.search) {
          queryParams.search = args.search;
        }
        if (args.tags) {
          queryParams.tags = args.tags.join(",");
        }

        reportProgress({ progress: 30, total: 100 });

        // Execute API request
        const response = await makeClient.getScenarios(
          args.teamId,
          queryParams,
        );
        const scenarios = response.data || [];

        reportProgress({ progress: 70, total: 100 });

        // Generate insights
        const statusCounts = scenarios.reduce((acc: any, scenario: any) => {
          acc[scenario.status] = (acc[scenario.status] || 0) + 1;
          return acc;
        }, {});

        const recentActivity = scenarios.filter((s: any) => {
          const lastExecution = new Date(s.lastExecutionAt);
          const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
          return lastExecution > dayAgo;
        }).length;

        reportProgress({ progress: 100, total: 100 });

        log.info(`[${operationId}] Successfully listed scenarios`, {
          count: scenarios.length,
          statusBreakdown: statusCounts,
          correlationId: operationId,
        });

        return {
          content: [
            {
              type: "text",
              text: `📋 **Advanced Scenario Listing Results**

**Summary:**
- Total Found: ${scenarios.length} scenarios
- Status Breakdown: ${
                Object.entries(statusCounts)
                  .map(([status, count]) => `${status}(${count})`)
                  .join(", ") || "None"
              }
- Recent Activity: ${recentActivity} scenarios executed in last 24h

**Filters Applied:**
${
  Object.entries(args)
    .filter(
      ([_, v]) =>
        v !== undefined && v !== "" && (Array.isArray(v) ? v.length > 0 : true),
    )
    .map(([k, v]) => `- ${k}: ${Array.isArray(v) ? v.join(", ") : v}`)
    .join("\n") || "- None"
}

**Scenarios:**
${
  scenarios
    .map(
      (scenario: any, i: number) => `**${i + 1}. ${scenario.name}**
- ID: \`${scenario.id}\`
- Status: ${getStatusEmoji(scenario.status)} ${scenario.status}
- Team: ${scenario.teamId || "Default"}
- Last Execution: ${scenario.lastExecutionAt ? new Date(scenario.lastExecutionAt).toLocaleString() : "Never"}
- Success Rate: ${scenario.successRate ? `${(scenario.successRate * 100).toFixed(1)}%` : "N/A"}
- Created: ${scenario.createdAt ? new Date(scenario.createdAt).toLocaleDateString() : "N/A"}
${scenario.description ? `- Description: ${scenario.description}` : ""}
${scenario.folder ? `- Folder: ${scenario.folder}` : ""}`,
    )
    .join("\n\n") || "No scenarios found"
}

**Next Steps:**
- Use \`get-scenario-details\` to view full scenario information
- Use \`execute-scenario\` to run scenarios
- Use \`get-scenario-analytics\` for performance insights

**API Status:** ${makeClient.getRateLimitStatus().remaining} requests remaining`,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to list scenarios`, {
          error: error instanceof Error ? error.message : String(error),
          correlationId: operationId,
        });

        return {
          content: [
            {
              type: "text",
              text: `❌ **Failed to list scenarios**

**Error:** ${error instanceof Error ? error.message : String(error)}

**Troubleshooting:**
1. Verify API token has scenario read permissions
2. Check team ID exists if provided
3. Ensure status filter values are valid
4. Try reducing the limit or removing filters

**Debug Info:**
- Operation ID: ${operationId}
- Filters: ${JSON.stringify(args, null, 2)}`,
            },
          ],
        };
      }
    },
  });

  server.addTool({
    name: "get-scenario-details",
    description:
      "Get comprehensive details for a specific Make.com scenario including blueprint, scheduling, and analytics",
    parameters: z.object({
      scenarioId: z.string().describe("Scenario ID to get details for"),
      includeBlueprint: z
        .boolean()
        .default(true)
        .describe("Include full blueprint configuration"),
      includeAnalytics: z
        .boolean()
        .default(true)
        .describe("Include recent performance analytics"),
      includeConnections: z
        .boolean()
        .default(true)
        .describe("Include connection information"),
      includeModules: z
        .boolean()
        .default(true)
        .describe("Include detailed module information"),
    }),
    annotations: {
      title: "Detailed Scenario Information",
      readOnlyHint: true,
      openWorldHint: false,
    },
    execute: async (args, { log, reportProgress }) => {
      const operationId = `get-scenario-${Date.now()}`;

      log.info(`[${operationId}] Getting scenario details`, {
        scenarioId: args.scenarioId,
        includes: {
          blueprint: args.includeBlueprint,
          analytics: args.includeAnalytics,
          connections: args.includeConnections,
          modules: args.includeModules,
        },
        correlationId: operationId,
      });

      reportProgress({ progress: 20, total: 100 });

      try {
        // Get basic scenario information
        const scenarioResponse = await makeClient.getScenarios(undefined, {
          scenarioId: args.scenarioId,
        });

        const scenario = scenarioResponse.data?.[0];
        if (!scenario) {
          throw new Error(`Scenario ${args.scenarioId} not found`);
        }

        reportProgress({ progress: 50, total: 100 });

        // Collect additional information based on options
        const details: any = {
          scenario,
          blueprint: null,
          analytics: null,
          connections: null,
          modules: null,
        };

        if (args.includeAnalytics) {
          try {
            const analyticsResponse = await makeClient.getAnalytics({
              scenarioId: args.scenarioId,
              startDate: new Date(
                Date.now() - 30 * 24 * 60 * 60 * 1000,
              ).toISOString(),
              endDate: new Date().toISOString(),
            });
            details.analytics = analyticsResponse.data;
          } catch (error) {
            log.warn(`[${operationId}] Failed to fetch analytics`, {
              error: error instanceof Error ? error.message : String(error),
            });
          }
        }

        reportProgress({ progress: 80, total: 100 });

        if (args.includeConnections && scenario.connections) {
          details.connections = scenario.connections;
        }

        if (args.includeModules && scenario.modules) {
          details.modules = scenario.modules;
        }

        if (args.includeBlueprint && scenario.blueprint) {
          details.blueprint = scenario.blueprint;
        }

        reportProgress({ progress: 100, total: 100 });

        log.info(`[${operationId}] Successfully retrieved scenario details`, {
          scenarioId: args.scenarioId,
          hasAnalytics: !!details.analytics,
          hasBlueprint: !!details.blueprint,
          correlationId: operationId,
        });

        return {
          content: [
            {
              type: "text",
              text: generateScenarioDetailsText(details, operationId),
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to get scenario details`, {
          error: error instanceof Error ? error.message : String(error),
          scenarioId: args.scenarioId,
          correlationId: operationId,
        });

        return {
          content: [
            {
              type: "text",
              text: `❌ **Failed to get scenario details**

**Error:** ${error instanceof Error ? error.message : String(error)}

**Troubleshooting:**
1. Verify scenario ID is correct: \`${args.scenarioId}\`
2. Check you have read access to the scenario
3. Ensure the scenario exists and hasn't been deleted
4. Try with reduced detail options

**Operation ID:** ${operationId}`,
            },
          ],
        };
      }
    },
  });

  server.addTool({
    name: "create-scenario",
    description:
      "Create a new Make.com scenario with blueprint, scheduling, and configuration",
    parameters: ScenarioCreateSchema,
    annotations: {
      title: "Create New Scenario",
      readOnlyHint: false,
      destructiveHint: false,
      openWorldHint: false,
    },
    execute: async (args, { log, reportProgress }) => {
      const operationId = `create-scenario-${Date.now()}`;

      log.info(`[${operationId}] Creating new scenario`, {
        name: args.name,
        teamId: args.teamId,
        hasBlueprint: !!args.blueprint,
        hasScheduling: !!args.scheduling,
        correlationId: operationId,
      });

      reportProgress({ progress: 20, total: 100 });

      try {
        // Prepare scenario data
        const scenarioData: any = {
          name: args.name,
          teamId: args.teamId,
          blueprint: args.blueprint,
          isActive: args.isActive,
        };

        if (args.description) {
          scenarioData.description = args.description;
        }

        if (args.folder) {
          scenarioData.folder = args.folder;
        }

        if (args.scheduling) {
          scenarioData.scheduling = args.scheduling;
        }

        reportProgress({ progress: 50, total: 100 });

        // Create the scenario
        const response = await makeClient.post("/scenarios", scenarioData);
        const newScenario = response.data;

        reportProgress({ progress: 90, total: 100 });

        // If scheduling was provided and scenario should be active, activate it
        if (args.isActive && args.scheduling) {
          try {
            await makeClient.patch(`/scenarios/${newScenario.id}`, {
              status: "active",
            });
            newScenario.status = "active";
          } catch (error) {
            log.warn(`[${operationId}] Failed to activate scenario`, {
              scenarioId: newScenario.id,
              error: error instanceof Error ? error.message : String(error),
            });
          }
        }

        reportProgress({ progress: 100, total: 100 });

        log.info(`[${operationId}] Successfully created scenario`, {
          scenarioId: newScenario.id,
          name: newScenario.name,
          status: newScenario.status,
          correlationId: operationId,
        });

        return {
          content: [
            {
              type: "text",
              text: `✅ **Scenario Created Successfully!**

**Scenario Details:**
- **ID:** \`${newScenario.id}\`
- **Name:** ${newScenario.name}
- **Status:** ${getStatusEmoji(newScenario.status)} ${newScenario.status}
- **Team:** ${args.teamId}
- **Created:** ${new Date().toLocaleString()}

**Configuration:**
${args.description ? `- **Description:** ${args.description}\n` : ""}${args.folder ? `- **Folder:** ${args.folder}\n` : ""}${args.scheduling ? `- **Scheduling:** ${args.scheduling.type} ${args.scheduling.interval ? `every ${args.scheduling.interval} ${args.scheduling.unit}(s)` : ""}\n` : ""}

**Blueprint Summary:**
- Modules: ${Object.keys(args.blueprint?.modules || {}).length}
- Connections: ${Object.keys(args.blueprint?.connections || {}).length}
- Configuration Size: ${JSON.stringify(args.blueprint).length} characters

**Next Steps:**
1. ${args.isActive ? "✅ Scenario is active and ready" : "🔄 Use `update-scenario-status` to activate"}
2. 📊 Use \`get-scenario-analytics\` to monitor performance
3. 🔍 Use \`get-scenario-details\` to view full configuration
4. ⚡ Use \`execute-scenario\` to test functionality

**Operation ID:** ${operationId}`,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to create scenario`, {
          error: error instanceof Error ? error.message : String(error),
          scenarioName: args.name,
          correlationId: operationId,
        });

        return {
          content: [
            {
              type: "text",
              text: `❌ **Failed to create scenario**

**Error:** ${error instanceof Error ? error.message : String(error)}

**Troubleshooting:**
1. Verify you have scenario creation permissions for team \`${args.teamId}\`
2. Check blueprint configuration is valid
3. Ensure scenario name is unique within the team
4. Validate scheduling configuration if provided

**Scenario Details:**
- Name: ${args.name}
- Team ID: ${args.teamId}
- Blueprint Size: ${JSON.stringify(args.blueprint).length} characters

**Operation ID:** ${operationId}`,
            },
          ],
        };
      }
    },
  });

  server.addTool({
    name: "update-scenario",
    description:
      "Update an existing Make.com scenario's configuration, blueprint, or settings",
    parameters: ScenarioUpdateSchema,
    annotations: {
      title: "Update Scenario Configuration",
      readOnlyHint: false,
      destructiveHint: true,
      openWorldHint: false,
    },
    execute: async (args, { log, reportProgress }) => {
      const operationId = `update-scenario-${Date.now()}`;

      log.info(`[${operationId}] Updating scenario`, {
        scenarioId: args.scenarioId,
        updates: Object.keys(args).filter(
          (k) => k !== "scenarioId" && (args as any)[k] !== undefined,
        ),
        correlationId: operationId,
      });

      reportProgress({ progress: 20, total: 100 });

      try {
        // Prepare update data
        const updateData: any = {};

        if (args.name !== undefined) {
          updateData.name = args.name;
        }
        if (args.blueprint !== undefined) {
          updateData.blueprint = args.blueprint;
        }
        if (args.description !== undefined) {
          updateData.description = args.description;
        }
        if (args.folder !== undefined) {
          updateData.folder = args.folder;
        }
        if (args.scheduling !== undefined) {
          updateData.scheduling = args.scheduling;
        }

        reportProgress({ progress: 50, total: 100 });

        // Update the scenario
        const response = await makeClient.patch(
          `/scenarios/${args.scenarioId}`,
          updateData,
        );
        const updatedScenario = response.data;

        reportProgress({ progress: 100, total: 100 });

        log.info(`[${operationId}] Successfully updated scenario`, {
          scenarioId: args.scenarioId,
          updatedFields: Object.keys(updateData),
          correlationId: operationId,
        });

        return {
          content: [
            {
              type: "text",
              text: `✅ **Scenario Updated Successfully!**

**Scenario:** ${updatedScenario.name} (\`${args.scenarioId}\`)
**Status:** ${getStatusEmoji(updatedScenario.status)} ${updatedScenario.status}
**Last Updated:** ${new Date().toLocaleString()}

**Updates Applied:**
${Object.entries(updateData)
  .map(([key, value]) => {
    if (key === "blueprint") {
      return `- **Blueprint:** Updated (${JSON.stringify(value).length} characters)`;
    } else if (key === "scheduling") {
      return `- **Scheduling:** ${(value as any).type} ${(value as any).interval ? `every ${(value as any).interval} ${(value as any).unit}(s)` : ""}`;
    } else {
      return `- **${key}:** ${value}`;
    }
  })
  .join("\n")}

**Configuration Summary:**
- Total Modules: ${updatedScenario.modules?.length || 0}
- Total Connections: ${updatedScenario.connections?.length || 0}
- Team: ${updatedScenario.teamId}

**Next Steps:**
1. 🔄 Restart scenario if currently running to apply changes
2. 📊 Monitor performance with \`get-scenario-analytics\`
3. ⚡ Test updated functionality with \`execute-scenario\`

**Operation ID:** ${operationId}`,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to update scenario`, {
          error: error instanceof Error ? error.message : String(error),
          scenarioId: args.scenarioId,
          correlationId: operationId,
        });

        return {
          content: [
            {
              type: "text",
              text: `❌ **Failed to update scenario**

**Error:** ${error instanceof Error ? error.message : String(error)}

**Troubleshooting:**
1. Verify scenario ID exists: \`${args.scenarioId}\`
2. Check you have edit permissions for this scenario
3. Ensure blueprint configuration is valid if updating
4. Verify scheduling configuration if updating

**Attempted Updates:**
${Object.entries(args)
  .filter(([k, v]) => k !== "scenarioId" && v !== undefined)
  .map(
    ([k, v]) =>
      `- ${k}: ${typeof v === "object" ? JSON.stringify(v).substring(0, 100) + "..." : v}`,
  )
  .join("\n")}

**Operation ID:** ${operationId}`,
            },
          ],
        };
      }
    },
  });

  server.addTool({
    name: "delete-scenario",
    description:
      "Permanently delete a Make.com scenario (with confirmation required)",
    parameters: z.object({
      scenarioId: z.string().describe("Scenario ID to delete"),
      confirmed: z
        .boolean()
        .describe(
          "Confirmation that you want to permanently delete this scenario",
        ),
      reason: z.string().optional().describe("Optional reason for deletion"),
    }),
    annotations: {
      title: "Delete Scenario",
      readOnlyHint: false,
      destructiveHint: true,
      openWorldHint: false,
    },
    execute: async (args, { log }) => {
      const operationId = `delete-scenario-${Date.now()}`;

      if (!args.confirmed) {
        return {
          content: [
            {
              type: "text",
              text: `⚠️ **Scenario Deletion Requires Confirmation**

To permanently delete scenario \`${args.scenarioId}\`, you must set the \`confirmed\` parameter to \`true\`.

**Warning:** This action cannot be undone. The scenario and all its execution history will be permanently removed.

**Before deleting, consider:**
1. Exporting the scenario configuration as backup
2. Checking if other scenarios depend on this one
3. Reviewing recent execution logs for important data
4. Notifying team members who use this scenario`,
            },
          ],
        };
      }

      log.info(`[${operationId}] Deleting scenario`, {
        scenarioId: args.scenarioId,
        reason: args.reason,
        correlationId: operationId,
      });

      try {
        // Get scenario info before deletion for logging
        let scenarioInfo;
        try {
          const response = await makeClient.getScenarios(undefined, {
            scenarioId: args.scenarioId,
          });
          scenarioInfo = response.data?.[0];
        } catch {
          log.warn(
            `[${operationId}] Could not fetch scenario info before deletion`,
          );
        }

        // Delete the scenario
        await makeClient.delete(`/scenarios/${args.scenarioId}`);

        log.info(`[${operationId}] Successfully deleted scenario`, {
          scenarioId: args.scenarioId,
          scenarioName: scenarioInfo?.name,
          reason: args.reason,
          correlationId: operationId,
        });

        return {
          content: [
            {
              type: "text",
              text: `✅ **Scenario Deleted Successfully**

**Deleted Scenario:**
- **ID:** \`${args.scenarioId}\`
${scenarioInfo ? `- **Name:** ${scenarioInfo.name}\n- **Status:** ${scenarioInfo.status}\n- **Team:** ${scenarioInfo.teamId}` : ""}
- **Deleted:** ${new Date().toLocaleString()}
${args.reason ? `- **Reason:** ${args.reason}` : ""}

**Important Notes:**
- ❌ This action cannot be undone
- 📊 All execution history has been permanently removed
- 🔗 Any webhooks or connections may need to be updated
- 👥 Team members should be notified of this change

**Operation ID:** ${operationId}`,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to delete scenario`, {
          error: error instanceof Error ? error.message : String(error),
          scenarioId: args.scenarioId,
          correlationId: operationId,
        });

        return {
          content: [
            {
              type: "text",
              text: `❌ **Failed to delete scenario**

**Error:** ${error instanceof Error ? error.message : String(error)}

**Troubleshooting:**
1. Verify scenario ID exists: \`${args.scenarioId}\`
2. Check you have delete permissions for this scenario
3. Ensure scenario is not currently running
4. Try stopping the scenario first if it's active

**Operation ID:** ${operationId}`,
            },
          ],
        };
      }
    },
  });

  // ================================
  // Scenario Execution and Control
  // ================================

  server.addTool({
    name: "execute-scenario",
    description:
      "Execute a Make.com scenario on-demand with optional input data and monitoring",
    parameters: ScenarioExecutionSchema,
    annotations: {
      title: "Execute Scenario",
      readOnlyHint: false,
      destructiveHint: false,
      openWorldHint: true,
    },
    execute: async (args, { log, reportProgress }) => {
      const operationId = `execute-scenario-${Date.now()}`;

      log.info(`[${operationId}] Starting scenario execution`, {
        scenarioId: args.scenarioId,
        waitForCompletion: args.waitForCompletion,
        hasInputData: !!args.inputData,
        timeout: args.timeout,
        correlationId: operationId,
      });

      reportProgress({ progress: 10, total: 100 });

      try {
        // Prepare execution data
        const executionData: any = {
          scenarioId: args.scenarioId,
        };

        if (args.inputData) {
          executionData.inputData = args.inputData;
        }

        reportProgress({ progress: 30, total: 100 });

        // Start scenario execution
        const executeResponse = await makeClient.post(
          `/scenarios/${args.scenarioId}/execute`,
          executionData,
        );

        const execution = executeResponse.data;
        const executionId = execution.id;

        log.info(`[${operationId}] Scenario execution started`, {
          scenarioId: args.scenarioId,
          executionId,
          correlationId: operationId,
        });

        reportProgress({ progress: 50, total: 100 });

        if (!args.waitForCompletion) {
          reportProgress({ progress: 100, total: 100 });

          return {
            content: [
              {
                type: "text",
                text: `⚡ **Scenario Execution Started**

**Execution Details:**
- **Scenario ID:** \`${args.scenarioId}\`
- **Execution ID:** \`${executionId}\`
- **Started:** ${new Date().toLocaleString()}
- **Mode:** Asynchronous (not waiting for completion)

${
  args.inputData
    ? `**Input Data:**
\`\`\`json
${JSON.stringify(args.inputData, null, 2)}
\`\`\``
    : "**Input Data:** None provided"
}

**Monitoring:**
- Use \`get-execution-status\` with execution ID \`${executionId}\` to check progress
- Use \`get-execution-logs\` to view detailed execution logs
- Use \`stop-scenario-execution\` to halt execution if needed

**Operation ID:** ${operationId}`,
              },
            ],
          };
        }

        // Wait for completion with timeout
        const startTime = Date.now();
        const timeoutMs = args.timeout * 1000;
        let executionStatus = "running";
        let executionResult = null;

        while (
          executionStatus === "running" &&
          Date.now() - startTime < timeoutMs
        ) {
          await new Promise((resolve) => setTimeout(resolve, 2000)); // Wait 2 seconds

          try {
            const statusResponse = await makeClient.get(
              `/scenarios/${args.scenarioId}/executions/${executionId}`,
            );
            const statusData = statusResponse.data;
            executionStatus = statusData.status;
            executionResult = statusData;

            const elapsed = (Date.now() - startTime) / 1000;
            const progressPercent = Math.min(
              90,
              50 + (elapsed / args.timeout) * 40,
            );
            reportProgress({ progress: progressPercent, total: 100 });
          } catch (error) {
            log.warn(`[${operationId}] Failed to check execution status`, {
              executionId,
              error: error instanceof Error ? error.message : String(error),
            });
          }
        }

        reportProgress({ progress: 100, total: 100 });

        if (executionStatus === "running") {
          log.info(`[${operationId}] Execution timeout reached`, {
            scenarioId: args.scenarioId,
            executionId,
            timeout: args.timeout,
            correlationId: operationId,
          });

          return {
            content: [
              {
                type: "text",
                text: `⏰ **Execution Timeout Reached**

**Execution Details:**
- **Scenario ID:** \`${args.scenarioId}\`
- **Execution ID:** \`${executionId}\`
- **Status:** Still running after ${args.timeout} seconds
- **Started:** ${new Date(startTime).toLocaleString()}

**Next Steps:**
1. Use \`get-execution-status\` to continue monitoring: \`${executionId}\`
2. Use \`get-execution-logs\` to check progress and debug issues
3. Consider increasing timeout for long-running scenarios
4. Use \`stop-scenario-execution\` if execution is stuck

**Operation ID:** ${operationId}`,
              },
            ],
          };
        }

        log.info(`[${operationId}] Scenario execution completed`, {
          scenarioId: args.scenarioId,
          executionId,
          status: executionStatus,
          duration: (Date.now() - startTime) / 1000,
          correlationId: operationId,
        });

        const success =
          executionStatus === "success" || executionStatus === "completed";

        return {
          content: [
            {
              type: "text",
              text: `${success ? "✅" : "❌"} **Scenario Execution ${success ? "Completed Successfully" : "Failed"}**

**Execution Summary:**
- **Scenario ID:** \`${args.scenarioId}\`
- **Execution ID:** \`${executionId}\`
- **Status:** ${getStatusEmoji(executionStatus)} ${executionStatus}
- **Duration:** ${((Date.now() - startTime) / 1000).toFixed(1)} seconds
- **Completed:** ${new Date().toLocaleString()}

**Results:**
${
  executionResult
    ? `- **Operations:** ${executionResult.operationsCount || 0}
- **Data Processed:** ${executionResult.dataProcessed ? `${(executionResult.dataProcessed / 1024).toFixed(2)} KB` : "N/A"}
- **Modules Executed:** ${executionResult.modulesExecuted || 0}
${executionResult.errors ? `- **Errors:** ${executionResult.errors.length}` : ""}`
    : "- Detailed results not available"
}

${
  !success && executionResult?.error
    ? `**Error Details:**
\`\`\`
${executionResult.error}
\`\`\``
    : ""
}

**Next Steps:**
${success ? "- ✅ Review execution logs for detailed results" : "- 🔍 Use `get-execution-logs` to debug the failure"}
- 📊 Use \`get-scenario-analytics\` to track performance trends
- 🔄 Modify scenario configuration if needed

**Operation ID:** ${operationId}`,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to execute scenario`, {
          error: error instanceof Error ? error.message : String(error),
          scenarioId: args.scenarioId,
          correlationId: operationId,
        });

        return {
          content: [
            {
              type: "text",
              text: `❌ **Failed to execute scenario**

**Error:** ${error instanceof Error ? error.message : String(error)}

**Troubleshooting:**
1. Verify scenario ID exists: \`${args.scenarioId}\`
2. Check scenario is active and properly configured
3. Ensure all required connections are valid
4. Verify input data format if provided

**Execution Details:**
- Scenario ID: ${args.scenarioId}
- Input Data: ${args.inputData ? "Provided" : "None"}
- Wait for completion: ${args.waitForCompletion}

**Operation ID:** ${operationId}`,
            },
          ],
        };
      }
    },
  });

  server.addTool({
    name: "update-scenario-status",
    description:
      "Update a Make.com scenario's status (active, inactive, paused)",
    parameters: z.object({
      scenarioId: z.string().describe("Scenario ID to update status for"),
      status: z
        .enum(["active", "inactive", "paused"])
        .describe("New status for the scenario"),
      reason: z
        .string()
        .optional()
        .describe("Optional reason for status change"),
    }),
    annotations: {
      title: "Update Scenario Status",
      readOnlyHint: false,
      destructiveHint: false,
      openWorldHint: false,
    },
    execute: async (args, { log }) => {
      const operationId = `update-status-${Date.now()}`;

      log.info(`[${operationId}] Updating scenario status`, {
        scenarioId: args.scenarioId,
        newStatus: args.status,
        reason: args.reason,
        correlationId: operationId,
      });

      try {
        const updateData: any = { status: args.status };
        if (args.reason) {
          updateData.statusChangeReason = args.reason;
        }

        const response = await makeClient.patch(
          `/scenarios/${args.scenarioId}`,
          updateData,
        );

        const updatedScenario = response.data;

        log.info(`[${operationId}] Successfully updated scenario status`, {
          scenarioId: args.scenarioId,
          oldStatus: updatedScenario.previousStatus,
          newStatus: args.status,
          correlationId: operationId,
        });

        return {
          content: [
            {
              type: "text",
              text: `✅ **Scenario Status Updated**

**Scenario:** ${updatedScenario.name} (\`${args.scenarioId}\`)
**Status Change:** ${updatedScenario.previousStatus ? `${getStatusEmoji(updatedScenario.previousStatus)} ${updatedScenario.previousStatus}` : "Unknown"} → ${getStatusEmoji(args.status)} ${args.status}
**Updated:** ${new Date().toLocaleString()}
${args.reason ? `**Reason:** ${args.reason}` : ""}

**Impact:**
${
  args.status === "active"
    ? "🟢 Scenario is now active and will execute based on its triggers"
    : args.status === "paused"
      ? "🟡 Scenario is paused - existing executions will complete but no new ones will start"
      : "⚪ Scenario is inactive and will not execute"
}

**Next Steps:**
- Monitor scenario performance with \`get-scenario-analytics\`
- View recent activity with \`get-execution-logs\`
- Test functionality with \`execute-scenario\`

**Operation ID:** ${operationId}`,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to update scenario status`, {
          error: error instanceof Error ? error.message : String(error),
          scenarioId: args.scenarioId,
          correlationId: operationId,
        });

        return {
          content: [
            {
              type: "text",
              text: `❌ **Failed to update scenario status**

**Error:** ${error instanceof Error ? error.message : String(error)}

**Troubleshooting:**
1. Verify scenario ID exists: \`${args.scenarioId}\`
2. Check you have edit permissions for this scenario
3. Ensure the scenario is not in an error state
4. Try refreshing scenario data first

**Requested Change:**
- Scenario ID: ${args.scenarioId}
- New Status: ${args.status}
- Reason: ${args.reason || "Not provided"}

**Operation ID:** ${operationId}`,
            },
          ],
        };
      }
    },
  });

  // ================================
  // Blueprint Management and Validation
  // ================================

  server.addTool({
    name: "validate-scenario-blueprint",
    description:
      "Validate a scenario blueprint configuration for errors and best practices",
    parameters: BlueprintValidationSchema,
    annotations: {
      title: "Blueprint Validation",
      readOnlyHint: true,
      openWorldHint: false,
    },
    execute: async (args, { log, reportProgress }) => {
      const operationId = `validate-blueprint-${Date.now()}`;

      log.info(`[${operationId}] Starting blueprint validation`, {
        blueprintSize: JSON.stringify(args.blueprint).length,
        strictMode: args.strictMode,
        checkConnections: args.checkConnections,
        checkModules: args.checkModules,
        correlationId: operationId,
      });

      reportProgress({ progress: 20, total: 100 });

      try {
        const validationResults = {
          isValid: true,
          errors: [] as string[],
          warnings: [] as string[],
          suggestions: [] as string[],
          analysis: {
            moduleCount: 0,
            connectionCount: 0,
            complexity: 0,
            estimatedCost: 0,
          },
        };

        // Basic structure validation
        if (!args.blueprint || typeof args.blueprint !== "object") {
          validationResults.isValid = false;
          validationResults.errors.push("Blueprint must be a valid object");
          return {
            content: [
              {
                type: "text",
                text: `❌ **Blueprint Validation Results**

**Overall Status:** 🔴 Invalid

**Analysis Summary:**
- **Error:** Blueprint must be a valid object

**Operation ID:** ${operationId}`,
              },
            ],
          };
        }

        reportProgress({ progress: 40, total: 100 });

        // Validate modules
        if (args.checkModules && args.blueprint.modules) {
          const modules = Array.isArray(args.blueprint.modules)
            ? args.blueprint.modules
            : Object.values(args.blueprint.modules);

          validationResults.analysis.moduleCount = modules.length;

          modules.forEach((module: any, index: number) => {
            if (!module.id) {
              validationResults.errors.push(
                `Module ${index + 1}: Missing required 'id' field`,
              );
              validationResults.isValid = false;
            }

            if (!module.type) {
              validationResults.errors.push(
                `Module ${index + 1}: Missing required 'type' field`,
              );
              validationResults.isValid = false;
            }

            if (module.type === "webhook" && !module.url) {
              validationResults.warnings.push(
                `Module ${index + 1}: Webhook module should have a URL`,
              );
            }

            if (
              module.parameters &&
              Object.keys(module.parameters).length === 0
            ) {
              validationResults.suggestions.push(
                `Module ${index + 1}: Consider adding parameters for better functionality`,
              );
            }
          });
        }

        reportProgress({ progress: 60, total: 100 });

        // Validate connections
        if (args.checkConnections && args.blueprint.connections) {
          const connections = Array.isArray(args.blueprint.connections)
            ? args.blueprint.connections
            : Object.values(args.blueprint.connections);

          validationResults.analysis.connectionCount = connections.length;

          connections.forEach((connection: any, index: number) => {
            if (!connection.id) {
              validationResults.errors.push(
                `Connection ${index + 1}: Missing required 'id' field`,
              );
              validationResults.isValid = false;
            }

            if (!connection.type) {
              validationResults.errors.push(
                `Connection ${index + 1}: Missing required 'type' field`,
              );
              validationResults.isValid = false;
            }
          });
        }

        reportProgress({ progress: 80, total: 100 });

        // Calculate complexity score
        validationResults.analysis.complexity =
          validationResults.analysis.moduleCount * 2 +
          validationResults.analysis.connectionCount * 1.5;

        // Estimate cost (rough calculation)
        validationResults.analysis.estimatedCost = Math.ceil(
          validationResults.analysis.moduleCount * 0.1 +
            validationResults.analysis.connectionCount * 0.05,
        );

        // Add suggestions based on analysis
        if (validationResults.analysis.moduleCount > 20) {
          validationResults.suggestions.push(
            "Consider breaking this scenario into smaller, more manageable scenarios",
          );
        }

        if (validationResults.analysis.complexity > 50) {
          validationResults.suggestions.push(
            "High complexity scenario - ensure thorough testing",
          );
        }

        reportProgress({ progress: 100, total: 100 });

        log.info(`[${operationId}] Blueprint validation completed`, {
          isValid: validationResults.isValid,
          errorCount: validationResults.errors.length,
          warningCount: validationResults.warnings.length,
          complexity: validationResults.analysis.complexity,
          correlationId: operationId,
        });

        return {
          content: [
            {
              type: "text",
              text: `${validationResults.isValid ? "✅" : "❌"} **Blueprint Validation Results**

**Overall Status:** ${validationResults.isValid ? "🟢 Valid" : "🔴 Invalid"}

**Analysis Summary:**
- **Modules:** ${validationResults.analysis.moduleCount}
- **Connections:** ${validationResults.analysis.connectionCount}
- **Complexity Score:** ${validationResults.analysis.complexity}
- **Estimated Cost:** ${validationResults.analysis.estimatedCost} operations

${
  validationResults.errors.length > 0
    ? `**❌ Errors (${validationResults.errors.length}):**
${validationResults.errors.map((error: string, i: number) => `${i + 1}. ${error}`).join("\n")}`
    : ""
}

${
  validationResults.warnings.length > 0
    ? `**⚠️ Warnings (${validationResults.warnings.length}):**
${validationResults.warnings.map((warning: string, i: number) => `${i + 1}. ${warning}`).join("\n")}`
    : ""
}

${
  validationResults.suggestions.length > 0
    ? `**💡 Suggestions (${validationResults.suggestions.length}):**
${validationResults.suggestions.map((suggestion: string, i: number) => `${i + 1}. ${suggestion}`).join("\n")}`
    : ""
}

**Recommendations:**
${
  validationResults.isValid
    ? "✅ Blueprint is valid and ready for deployment"
    : "🔴 Fix all errors before using this blueprint"
}

${
  validationResults.analysis.complexity > 50
    ? "⚠️ High complexity scenario - ensure thorough testing"
    : validationResults.analysis.complexity > 25
      ? "🟡 Moderate complexity - standard testing recommended"
      : "🟢 Low complexity - minimal testing required"
}

**Operation ID:** ${operationId}`,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Blueprint validation failed`, {
          error: error instanceof Error ? error.message : String(error),
          correlationId: operationId,
        });

        return {
          content: [
            {
              type: "text",
              text: `❌ **Blueprint Validation Failed**

**Error:** ${error instanceof Error ? error.message : String(error)}

**Possible Issues:**
1. Blueprint format is invalid or corrupted
2. Blueprint is too large to process
3. Required fields are missing or malformed

**Operation ID:** ${operationId}`,
            },
          ],
        };
      }
    },
  });

  server.addTool({
    name: "optimize-scenario-blueprint",
    description:
      "Analyze and provide optimization recommendations for a scenario blueprint",
    parameters: BlueprintOptimizationSchema,
    annotations: {
      title: "Blueprint Optimization",
      readOnlyHint: true,
      openWorldHint: false,
    },
    execute: async (args, { log, reportProgress }) => {
      const operationId = `optimize-blueprint-${Date.now()}`;

      log.info(`[${operationId}] Starting blueprint optimization analysis`, {
        scenarioId: args.scenarioId,
        optimizationType: args.optimizationType,
        analysisDepth: args.analysisDepth,
        correlationId: operationId,
      });

      reportProgress({ progress: 20, total: 100 });

      try {
        // Get scenario details
        const scenarioResponse = await makeClient.getScenarios(undefined, {
          scenarioId: args.scenarioId,
        });

        const scenario = scenarioResponse.data?.[0];
        if (!scenario) {
          throw new Error(`Scenario ${args.scenarioId} not found`);
        }

        reportProgress({ progress: 50, total: 100 });

        const optimizations = {
          currentAnalysis: {
            moduleCount: scenario.modules?.length || 0,
            connectionCount: scenario.connections?.length || 0,
            complexity: 0,
            estimatedCost: 0,
          },
          recommendations: [] as string[],
          potentialSavings: {
            operations: 0,
            cost: 0,
            performance: 0,
          },
          optimizationLevel: "none" as string,
        };

        // Analyze based on optimization type
        switch (args.optimizationType) {
          case "performance":
            optimizations.recommendations.push(
              "Consider caching frequently accessed data",
              "Use filters early in the workflow to reduce data processing",
              "Combine multiple API calls where possible",
              "Implement error handling to prevent unnecessary retries",
            );
            break;

          case "cost":
            optimizations.recommendations.push(
              "Review module usage - remove unnecessary operations",
              "Use webhooks instead of polling where possible",
              "Implement data validation to prevent processing invalid records",
              "Consider batch processing for large datasets",
            );
            break;

          case "reliability":
            optimizations.recommendations.push(
              "Add comprehensive error handling modules",
              "Implement retry logic with exponential backoff",
              "Use data validation before processing",
              "Add monitoring and alerting modules",
            );
            break;

          case "maintainability":
            optimizations.recommendations.push(
              "Add descriptive names and comments to modules",
              "Group related functionality into sub-scenarios",
              "Use consistent data transformation patterns",
              "Document complex logic with notes",
            );
            break;
        }

        // Calculate optimization level
        const complexityScore =
          optimizations.currentAnalysis.moduleCount * 2 +
          optimizations.currentAnalysis.connectionCount;

        if (complexityScore < 10) {
          optimizations.optimizationLevel = "minimal";
        } else if (complexityScore < 25) {
          optimizations.optimizationLevel = "moderate";
        } else {
          optimizations.optimizationLevel = "significant";
        }

        reportProgress({ progress: 100, total: 100 });

        log.info(`[${operationId}] Blueprint optimization analysis completed`, {
          scenarioId: args.scenarioId,
          recommendationCount: optimizations.recommendations.length,
          optimizationLevel: optimizations.optimizationLevel,
          correlationId: operationId,
        });

        return {
          content: [
            {
              type: "text",
              text: `🔧 **Blueprint Optimization Analysis**

**Scenario:** ${scenario.name} (\`${args.scenarioId}\`)
**Optimization Focus:** ${args.optimizationType}
**Analysis Depth:** ${args.analysisDepth}

**Current Analysis:**
- **Modules:** ${optimizations.currentAnalysis.moduleCount}
- **Connections:** ${optimizations.currentAnalysis.connectionCount}
- **Complexity Score:** ${complexityScore}
- **Optimization Potential:** ${optimizations.optimizationLevel}

**${args.optimizationType.charAt(0).toUpperCase() + args.optimizationType.slice(1)} Recommendations:**
${optimizations.recommendations.map((rec, i) => `${i + 1}. ${rec}`).join("\n")}

**Implementation Priority:**
${
  optimizations.optimizationLevel === "significant"
    ? "🔴 **High Priority** - Significant optimization potential identified"
    : optimizations.optimizationLevel === "moderate"
      ? "🟡 **Medium Priority** - Moderate optimization opportunities available"
      : "🟢 **Low Priority** - Scenario is already well-optimized"
}

**Next Steps:**
1. Review recommendations and prioritize by impact
2. Implement changes in a test environment first
3. Monitor performance before and after changes
4. Use \`validate-scenario-blueprint\` after modifications

**Operation ID:** ${operationId}`,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Blueprint optimization failed`, {
          error: error instanceof Error ? error.message : String(error),
          scenarioId: args.scenarioId,
          correlationId: operationId,
        });

        return {
          content: [
            {
              type: "text",
              text: `❌ **Blueprint Optimization Failed**

**Error:** ${error instanceof Error ? error.message : String(error)}

**Troubleshooting:**
1. Verify scenario ID exists: \`${args.scenarioId}\`
2. Check you have read access to the scenario
3. Ensure scenario has a valid blueprint
4. Try with a different analysis depth

**Operation ID:** ${operationId}`,
            },
          ],
        };
      }
    },
  });
}

// ================================
// Helper Functions
// ================================

function getStatusEmoji(status: string): string {
  switch (status?.toLowerCase()) {
    case "active":
      return "🟢";
    case "inactive":
      return "⚪";
    case "paused":
      return "🟡";
    case "error":
      return "🔴";
    case "running":
      return "🔄";
    default:
      return "❓";
  }
}

function generateScenarioDetailsText(
  details: any,
  operationId: string,
): string {
  const scenario = details.scenario;

  return `🔍 **Detailed Scenario Information**

**Basic Information:**
- **Name:** ${scenario.name}
- **ID:** \`${scenario.id}\`
- **Status:** ${getStatusEmoji(scenario.status)} ${scenario.status}
- **Team:** ${scenario.teamId}
- **Created:** ${scenario.createdAt ? new Date(scenario.createdAt).toLocaleString() : "N/A"}
- **Updated:** ${scenario.updatedAt ? new Date(scenario.updatedAt).toLocaleString() : "N/A"}
${scenario.description ? `- **Description:** ${scenario.description}` : ""}
${scenario.folder ? `- **Folder:** ${scenario.folder}` : ""}

**Execution Summary:**
- **Last Execution:** ${scenario.lastExecutionAt ? new Date(scenario.lastExecutionAt).toLocaleString() : "Never"}
- **Success Rate:** ${scenario.successRate ? `${(scenario.successRate * 100).toFixed(1)}%` : "N/A"}
- **Total Executions:** ${scenario.totalExecutions || 0}

**Configuration:**
- **Modules:** ${scenario.modules?.length || 0}
- **Connections:** ${scenario.connections?.length || 0}
- **Webhooks:** ${scenario.webhooks?.length || 0}

${
  details.analytics
    ? `**Recent Analytics (30 days):**
- **Executions:** ${details.analytics.totalExecutions || 0}
- **Success Rate:** ${details.analytics.successRate ? `${(details.analytics.successRate * 100).toFixed(1)}%` : "N/A"}
- **Avg Duration:** ${details.analytics.averageDuration ? `${details.analytics.averageDuration}ms` : "N/A"}
- **Data Processed:** ${details.analytics.dataProcessed ? `${(details.analytics.dataProcessed / 1024 / 1024).toFixed(2)} MB` : "N/A"}
`
    : ""
}

**Next Actions:**
- Use \`execute-scenario\` to run this scenario
- Use \`get-scenario-analytics\` for performance insights
- Use \`update-scenario\` to modify configuration
- Use \`get-execution-logs\` to review recent activity

**Operation ID:** ${operationId}`;
}

export default registerScenarioExecutionManagementTools;
