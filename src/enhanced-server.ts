#!/usr/bin/env node

/**
 * Enhanced Make.com FastMCP Server
 * Production-ready server with comprehensive Make.com API integration
 * Based on research reports and existing stable implementation
 */

import { FastMCP } from "fastmcp";
import { z } from "zod";
import dotenv from "dotenv";
import winston from "winston";
import DailyRotateFile from "winston-daily-rotate-file";

// Import our enhanced Make.com API client and tools (temporarily using compatible client)
import { MakeAPIClient } from "./make-client/simple-make-client.js";

// Import tool registration functions
import { registerDevelopmentCustomizationTools } from "./tools/development-customization-tools.js";
import { registerAIAgentManagementTools } from "./tools/ai-agent-management-tools.js";
import { registerUserAccessManagementTools } from "./tools/user-access-management-tools.js";
import { registerDataConnectivityManagementTools } from "./tools/data-connectivity-management-tools.js";
import { registerBillingAdministrationTools } from "./tools/billing-administration-tools.js";

// Load environment variables
dotenv.config();

// Ensure logs directory exists
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "..");
const logsDir = path.join(projectRoot, "logs");

try {
  if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
  }
} catch {
  // Continue execution - Winston will handle logging to console only
}

// ==============================================================================
// Local Interface Definitions
// ==============================================================================

interface WebhookData {
  name: string;
  teamId?: string;
  typeName: string;
  method: boolean;
  header: boolean;
  stringify: boolean;
  connectionId?: string;
  scenarioId?: string;
}

interface _DataStoreField {
  name: string;
  type:
    | "string"
    | "number"
    | "boolean"
    | "date"
    | "datetime"
    | "json"
    | "array";
  required: boolean;
  unique: boolean;
  defaultValue?: unknown;
}

interface _TemplateData {
  name: string;
  description?: string;
  category: string;
  tags: string[];
  scenarioId: string;
  isPublic: boolean;
}

// ==============================================================================
// Enhanced Logger Configuration
// ==============================================================================

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json(),
  ),
  transports: [
    ...(process.env.ENABLE_CONSOLE_LOGGING === "true"
      ? [
          new winston.transports.Console({
            format: winston.format.combine(
              winston.format.colorize(),
              winston.format.simple(),
            ),
          }),
        ]
      : []),
    ...(process.env.LOG_FILE_ENABLED !== "false"
      ? [
          new DailyRotateFile({
            filename: path.join(logsDir, "enhanced-make-server-%DATE%.log"),
            datePattern: "YYYY-MM-DD",
            zippedArchive: true,
            maxSize: "20m",
            maxFiles: "30d",
            format: winston.format.combine(
              winston.format.timestamp(),
              winston.format.json(),
            ),
          }),
        ]
      : []),
  ],
});

// Old MakeAPIClient class removed - now using imported version from simple-make-client.ts

// ==============================================================================
// Initialize FastMCP Server and Client
// ==============================================================================

const server = new FastMCP({
  name: "Enhanced Make.com FastMCP Server",
  version: "1.1.0",
});

// Validate environment configuration
if (!process.env.MAKE_API_KEY) {
  logger.error("MAKE_API_KEY environment variable is required");
  process.exit(1);
}

const makeClient = new MakeAPIClient(
  {
    apiToken: process.env.MAKE_API_KEY,
    zone: process.env.MAKE_ZONE || "eu1",
    apiVersion: "v2",
    timeout: parseInt(process.env.MAKE_TIMEOUT || "30000"),
    retryConfig: {
      maxRetries: parseInt(process.env.MAKE_RETRIES || "3"),
      retryDelay: 1000,
      backoffMultiplier: 2,
      maxRetryDelay: 10000,
    },
    rateLimitConfig: {
      maxRequests: parseInt(process.env.MAKE_RATE_LIMIT || "60"),
      windowMs: 60000,
      skipSuccessfulRequests: false,
      skipFailedRequests: false,
    },
  },
  logger,
);

logger.info("Enhanced Make.com API client initialized");

// ==============================================================================
// Core Scenario Tools (Enhanced)
// ==============================================================================

server.addTool({
  name: "list-scenarios-enhanced",
  description: "List Make.com scenarios with enhanced filtering and pagination",
  parameters: z.object({
    limit: z
      .number()
      .min(1)
      .max(100)
      .optional()
      .describe("Maximum scenarios to return"),
    teamId: z.string().optional().describe("Filter by team ID"),
    status: z
      .enum(["active", "inactive", "paused", "error"])
      .optional()
      .describe("Filter by status"),
    search: z.string().optional().describe("Search scenarios by name"),
  }),
  execute: async (args, { log }) => {
    const operationId = `list-scenarios-${Date.now()}`;

    log.info(`[${operationId}] Listing scenarios with enhanced filters`, {
      limit: args.limit,
      teamId: args.teamId,
      status: args.status,
      search: args.search,
    });

    try {
      const params: Record<string, unknown> = {};
      if (args.limit) {
        params.limit = args.limit;
      }
      if (args.teamId) {
        params.teamId = args.teamId;
      }
      if (args.status) {
        params.status = args.status;
      }
      if (args.search) {
        params.search = args.search;
      }

      const response = await makeClient.getScenarios(
        params.teamId as string | undefined,
        params,
      );
      const scenarios = response.data;

      log.info(
        `[${operationId}] Retrieved ${scenarios?.length || 0} scenarios`,
      );

      return {
        content: [
          {
            type: "text",
            text: `📋 **Enhanced Scenarios List**\n\n**Found:** ${scenarios?.length || 0} scenarios\n**Filters Applied:** ${
              Object.entries(args)
                .filter(([_, v]) => v !== undefined)
                .map(([k, v]) => `${k}: ${v}`)
                .join(", ") || "None"
            }\n\n${
              scenarios
                ?.map(
                  (s: unknown, i: number) =>
                    `**${i + 1}. ${(s as Record<string, unknown>).name}**\n` +
                    `- ID: \`${(s as Record<string, unknown>).id}\`\n` +
                    `- Status: ${(s as Record<string, unknown>).status}\n` +
                    `- Team: ${(s as Record<string, unknown>).teamId || "N/A"}\n` +
                    `- Last Modified: ${(s as Record<string, unknown>).updatedAt || "N/A"}\n`,
                )
                .join("\n") || "No scenarios found"
            }\n\n**API Rate Limit:** ${makeClient.getRateLimitStatus().remaining} requests remaining\n\nFull response:\n\`\`\`json\n${JSON.stringify(scenarios ?? [], null, 2)}\n\`\`\``,
          },
        ],
      };
    } catch (error) {
      log.error(`[${operationId}] Failed to list scenarios`, {
        error: error instanceof Error ? error.message : String(error),
      });

      return {
        content: [
          {
            type: "text",
            text: `❌ **Failed to list scenarios:** ${error instanceof Error ? error.message : String(error)}\n\n**Troubleshooting:**\n1. Verify API token is valid\n2. Check team ID exists if provided\n3. Ensure status filter is valid\n4. Try without filters to test basic connectivity`,
          },
        ],
      };
    }
  },
});

// ==============================================================================
// Enhanced Webhook Management Tools
// ==============================================================================

server.addTool({
  name: "create-webhook-enhanced",
  description: "Create a Make.com webhook with advanced configuration options",
  parameters: z.object({
    name: z
      .string()
      .min(1)
      .max(128)
      .describe("Webhook name (max 128 characters)"),
    teamId: z.string().optional().describe("Team ID for webhook"),
    typeName: z.string().describe("Webhook type identifier"),
    method: z.boolean().default(true).describe("Track HTTP methods"),
    header: z.boolean().default(true).describe("Include headers"),
    stringify: z.boolean().default(false).describe("Stringify JSON payload"),
    connectionId: z.string().optional().describe("Associated connection ID"),
    scenarioId: z.string().optional().describe("Scenario to trigger"),
  }),
  execute: async (args, { log }) => {
    const operationId = `create-webhook-${Date.now()}`;

    log.info(`[${operationId}] Creating enhanced webhook`, {
      name: args.name,
      typeName: args.typeName,
      teamId: args.teamId,
    });

    try {
      const webhookData: WebhookData = {
        name: args.name,
        teamId: args.teamId,
        typeName: args.typeName,
        method: args.method,
        header: args.header,
        stringify: args.stringify,
        connectionId: args.connectionId,
        scenarioId: args.scenarioId,
      };

      const response = await makeClient.createWebhook(webhookData);
      const webhook = response.data;

      log.info(`[${operationId}] Webhook created successfully`, {
        webhookId: webhook.id,
        url: webhook.url,
      });

      return {
        content: [
          {
            type: "text",
            text: `✅ **Webhook Created Successfully!**\n\n**Webhook Details:**\n- **ID:** \`${webhook.id}\`\n- **Name:** ${webhook.name}\n- **URL:** \`${webhook.url}\`\n- **Status:** ${webhook.status || "enabled"}\n\n**Configuration:**\n- Method tracking: ${args.method ? "✅" : "❌"}\n- Header inclusion: ${args.header ? "✅" : "❌"}\n- JSON stringify: ${args.stringify ? "✅" : "❌"}\n- Team ID: ${args.teamId || "None"}\n- Connection ID: ${args.connectionId || "None"}\n- Scenario ID: ${args.scenarioId || "None"}\n\n**Next Steps:**\n1. 🔗 **Test the webhook** by sending a POST request to the URL\n2. 📊 **Monitor activity** in the Make.com dashboard\n3. 🎓 **Use learning mode** to auto-detect payload structure\n4. ⚙️ **Configure scenario** to process webhook data\n\n**Rate Limit Status:** ${makeClient.getRateLimitStatus().remaining} requests remaining`,
          },
        ],
      };
    } catch (error) {
      log.error(`[${operationId}] Failed to create webhook`, {
        error: error instanceof Error ? error.message : String(error),
        webhookName: args.name,
      });

      return {
        content: [
          {
            type: "text",
            text: `❌ **Failed to create webhook:** ${error instanceof Error ? error.message : String(error)}\n\n**Common Issues:**\n1. **Authentication:** Check API token permissions\n2. **Team Access:** Verify team ID exists and you have access\n3. **Duplicate Name:** Webhook names must be unique within team\n4. **Invalid Config:** Check webhook configuration parameters\n\n**Debug Info:**\n- Name: ${args.name}\n- Type: ${args.typeName}\n- Team: ${args.teamId || "Default"}`,
          },
        ],
      };
    }
  },
});

server.addTool({
  name: "list-webhooks-enhanced",
  description: "List Make.com webhooks with detailed information and filtering",
  parameters: z.object({
    teamId: z.string().optional().describe("Filter by team ID"),
    status: z
      .enum(["enabled", "disabled", "learning"])
      .optional()
      .describe("Filter by status"),
    limit: z
      .number()
      .min(1)
      .max(50)
      .optional()
      .describe("Maximum webhooks to return"),
  }),
  execute: async (args, { log }) => {
    const operationId = `list-webhooks-${Date.now()}`;

    log.info(`[${operationId}] Listing webhooks with filters`, {
      teamId: args.teamId,
      status: args.status,
      limit: args.limit,
    });

    try {
      const params: Record<string, unknown> = {};
      if (args.teamId) {
        params.teamId = args.teamId;
      }
      if (args.status) {
        params.status = args.status;
      }
      if (args.limit) {
        params.limit = args.limit;
      }

      const response = await makeClient.getWebhooks(
        params.teamId as string | undefined,
        params,
      );
      const webhooks = response.data;

      log.info(`[${operationId}] Retrieved ${webhooks?.length || 0} webhooks`);

      const webhookList =
        webhooks
          ?.map(
            (w: any, i: number) =>
              `**${i + 1}. ${w.name}**\n` +
              `- ID: \`${w.id}\`\n` +
              `- URL: \`${w.url}\`\n` +
              `- Status: ${w.status}\n` +
              `- Type: ${w.typeName || "N/A"}\n` +
              `- Team: ${w.teamId || "Default"}\n` +
              `- Created: ${w.createdAt || "N/A"}\n`,
          )
          .join("\n") || "No webhooks found";

      const statusCounts = webhooks?.reduce((acc: any, w: any) => {
        acc[w.status] = (acc[w.status] || 0) + 1;
        return acc;
      }, {});

      return {
        content: [
          {
            type: "text",
            text: `🪝 **Enhanced Webhooks List**\n\n**Summary:**\n- Total: ${webhooks?.length || 0} webhooks\n- Status Breakdown: ${Object.entries(
              statusCounts || {},
            )
              .map(([status, count]) => `${status}: ${count}`)
              .join(", ")}\n- Filters: ${
              Object.entries(args)
                .filter(([_, v]) => v !== undefined)
                .map(([k, v]) => `${k}: ${v}`)
                .join(", ") || "None"
            }\n\n**Webhooks:**\n${webhookList}\n\n**Management Commands:**\n- Use \`manage-webhook-enhanced\` to enable/disable webhooks\n- Use \`webhook-learning-mode\` to start/stop learning\n- Use \`delete-webhook\` to remove webhooks\n\n**Rate Limit:** ${makeClient.getRateLimitStatus().remaining} requests remaining`,
          },
        ],
      };
    } catch (error) {
      log.error(`[${operationId}] Failed to list webhooks`, {
        error: error instanceof Error ? error.message : String(error),
      });

      return {
        content: [
          {
            type: "text",
            text: `❌ **Failed to list webhooks:** ${error instanceof Error ? error.message : String(error)}\n\n**Troubleshooting:**\n1. Check API token permissions\n2. Verify team ID if provided\n3. Ensure status filter is valid\n4. Try without filters first`,
          },
        ],
      };
    }
  },
});

// ==============================================================================
// Enhanced Analytics and Monitoring
// ==============================================================================

server.addTool({
  name: "get-enhanced-analytics",
  description:
    "Get comprehensive Make.com analytics with advanced metrics and insights",
  parameters: z.object({
    startDate: z.string().describe("Start date (ISO format: YYYY-MM-DD)"),
    endDate: z.string().describe("End date (ISO format: YYYY-MM-DD)"),
    teamId: z.string().optional().describe("Filter by team ID"),
    includeDetails: z
      .boolean()
      .default(true)
      .describe("Include detailed breakdowns"),
    metricTypes: z
      .array(z.enum(["operations", "data_transfer", "errors", "performance"]))
      .optional()
      .describe("Specific metrics to include"),
  }),
  execute: async (args, { log }) => {
    const operationId = `analytics-${Date.now()}`;

    log.info(`[${operationId}] Fetching enhanced analytics`, {
      dateRange: `${args.startDate} to ${args.endDate}`,
      teamId: args.teamId,
      includeDetails: args.includeDetails,
    });

    try {
      const params: any = {
        startDate: args.startDate,
        endDate: args.endDate,
        includeDetails: args.includeDetails,
      };
      if (args.teamId) {
        params.teamId = args.teamId;
      }
      if (args.metricTypes) {
        params.metrics = args.metricTypes.join(",");
      }

      const response = await makeClient.getAnalytics(params);
      const analytics = response.data;

      // Generate insights
      const insights = {
        totalOperations: analytics.operations?.total || 0,
        successRate: analytics.operations?.total
          ? (
              (analytics.operations.successful / analytics.operations.total) *
              100
            ).toFixed(2) + "%"
          : "N/A",
        dataTransferMB: analytics.dataTransfer
          ? (analytics.dataTransfer.totalBytes / 1024 / 1024).toFixed(2) + " MB"
          : "N/A",
        avgResponseTime: analytics.performance?.averageResponseTime
          ? analytics.performance.averageResponseTime + "ms"
          : "N/A",
        errorRate: analytics.operations?.total
          ? (
              (analytics.operations.failed / analytics.operations.total) *
              100
            ).toFixed(2) + "%"
          : "N/A",
      };

      // Performance assessment
      const performance = {
        successRating:
          parseFloat(insights.successRate) >= 95
            ? "🟢 Excellent"
            : parseFloat(insights.successRate) >= 90
              ? "🟡 Good"
              : "🔴 Needs Attention",
        errorRating:
          parseFloat(insights.errorRate) <= 5
            ? "🟢 Low"
            : parseFloat(insights.errorRate) <= 10
              ? "🟡 Moderate"
              : "🔴 High",
        responseRating:
          analytics.performance?.averageResponseTime <= 1000
            ? "🟢 Fast"
            : analytics.performance?.averageResponseTime <= 3000
              ? "🟡 Moderate"
              : "🔴 Slow",
      };

      log.info(`[${operationId}] Analytics generated with insights`, {
        totalOperations: insights.totalOperations,
        successRate: insights.successRate,
      });

      return {
        content: [
          {
            type: "text",
            text: `📊 **Enhanced Analytics Report**\n\n**Period:** ${args.startDate} to ${args.endDate}${args.teamId ? `\n**Team:** ${args.teamId}` : ""}\n\n## 📈 Key Metrics\n- **Total Operations:** ${insights.totalOperations}\n- **Success Rate:** ${insights.successRate} ${performance.successRating}\n- **Error Rate:** ${insights.errorRate} ${performance.errorRating}\n- **Data Transfer:** ${insights.dataTransferMB}\n- **Avg Response:** ${insights.avgResponseTime} ${performance.responseRating}\n\n## 🔍 Detailed Breakdown\n${analytics.operations ? `**Operations:**\n- Successful: ${analytics.operations.successful}\n- Failed: ${analytics.operations.failed}\n- Total: ${analytics.operations.total}` : "No operation data"}\n\n${analytics.dataTransfer ? `**Data Transfer:**\n- Inbound: ${(analytics.dataTransfer.inboundBytes / 1024 / 1024).toFixed(2)} MB\n- Outbound: ${(analytics.dataTransfer.outboundBytes / 1024 / 1024).toFixed(2)} MB\n- Total: ${(analytics.dataTransfer.totalBytes / 1024 / 1024).toFixed(2)} MB` : "No transfer data"}\n\n${
              analytics.errors
                ? `**Error Analysis:**\n- Total Errors: ${analytics.errors.totalErrors}\n- By Type: ${Object.entries(
                    analytics.errors.errorsByType || {},
                  )
                    .map(([type, count]) => `${type}(${count})`)
                    .join(", ")}\n- By Status: ${Object.entries(
                    analytics.errors.errorsByStatus || {},
                  )
                    .map(([status, count]) => `${status}(${count})`)
                    .join(", ")}`
                : "No error data"
            }\n\n## 💡 Recommendations\n${insights.totalOperations > 0 ? `${parseFloat(insights.successRate) > 95 ? "✅ Excellent performance! Your scenarios are running smoothly." : "⚠️ Consider investigating failed operations to improve success rate."}\n${analytics.performance?.averageResponseTime ? (analytics.performance.averageResponseTime < 1000 ? "✅ Great response times!" : "⚠️ Consider optimizing scenarios for better performance.") : ""}\n${analytics.errors?.totalErrors === 0 ? "✅ No errors detected - great job!" : "⚠️ Review error patterns and implement better error handling."}` : "📈 Start running scenarios to generate meaningful analytics!"}\n\n**API Rate Limit:** ${makeClient.getRateLimitStatus().remaining} requests remaining\n\nFull analytics data:\n\`\`\`json\n${JSON.stringify(analytics, null, 2)}\n\`\`\``,
          },
        ],
      };
    } catch (error) {
      log.error(`[${operationId}] Failed to fetch analytics`, {
        error: error instanceof Error ? error.message : String(error),
        dateRange: `${args.startDate} to ${args.endDate}`,
      });

      return {
        content: [
          {
            type: "text",
            text: `❌ **Failed to fetch analytics:** ${error instanceof Error ? error.message : String(error)}\n\n**Troubleshooting:**\n1. **Date Format:** Use ISO format (YYYY-MM-DD)\n2. **Date Range:** Ensure end date is after start date\n3. **Team Access:** Verify team ID if provided\n4. **Permissions:** Check analytics access permissions\n\n**Debug Info:**\n- Start Date: ${args.startDate}\n- End Date: ${args.endDate}\n- Team ID: ${args.teamId || "All teams"}`,
          },
        ],
      };
    }
  },
});

// ==============================================================================
// System Health and Status Tools
// ==============================================================================

server.addTool({
  name: "system-health-check",
  description:
    "Perform comprehensive health check of Make.com API connectivity and server status",
  parameters: z.object({
    includeRateLimit: z
      .boolean()
      .default(true)
      .describe("Include rate limit information"),
    testConnections: z
      .boolean()
      .default(false)
      .describe("Test API connectivity with sample requests"),
  }),
  execute: async (args, { log }) => {
    const operationId = `health-check-${Date.now()}`;

    log.info(`[${operationId}] Performing system health check`, {
      includeRateLimit: args.includeRateLimit,
      testConnections: args.testConnections,
    });

    const healthData: any = {
      timestamp: new Date().toISOString(),
      server: {
        status: "operational",
        uptime: process.uptime(),
        memory: process.memoryUsage(),
      },
      makeApi: {
        baseURL: process.env.MAKE_BASE_URL || "https://eu1.make.com/api/v2",
        tokenConfigured: !!process.env.MAKE_API_KEY,
        status: "unknown",
      },
      rateLimit: null,
      connectivity: null,
    };

    try {
      // Rate limit check
      if (args.includeRateLimit) {
        healthData.rateLimit = makeClient.getRateLimitStatus();
      }

      // Basic connectivity test
      if (args.testConnections) {
        try {
          const _testResponse = await makeClient.getOrganizations();
          healthData.makeApi.status = "connected";
          healthData.connectivity = {
            organizations: "accessible",
            lastTest: new Date().toISOString(),
          };
        } catch (error) {
          healthData.makeApi.status = "error";
          healthData.connectivity = {
            error: error instanceof Error ? error.message : String(error),
            lastTest: new Date().toISOString(),
          };
        }
      }

      // Overall health assessment
      const isHealthy =
        healthData.makeApi.tokenConfigured &&
        healthData.makeApi.status !== "error" &&
        (healthData.rateLimit?.remaining > 10 || !args.includeRateLimit);

      log.info(`[${operationId}] Health check completed`, {
        overall: isHealthy ? "healthy" : "degraded",
        apiStatus: healthData.makeApi.status,
        rateLimit: healthData.rateLimit?.remaining,
      });

      return {
        content: [
          {
            type: "text",
            text: `${isHealthy ? "✅" : "⚠️"} **System Health Check**\n\n**Overall Status:** ${isHealthy ? "🟢 Healthy" : "🟡 Degraded"}\n**Timestamp:** ${healthData.timestamp}\n\n## 🖥️ Server Status\n- **Status:** ${healthData.server.status}\n- **Uptime:** ${Math.round(healthData.server.uptime)} seconds\n- **Memory Usage:** ${Math.round(healthData.server.memory.heapUsed / 1024 / 1024)} MB\n- **Memory Total:** ${Math.round(healthData.server.memory.heapTotal / 1024 / 1024)} MB\n\n## 🔌 Make.com API\n- **Base URL:** ${healthData.makeApi.baseURL}\n- **Token Configured:** ${healthData.makeApi.tokenConfigured ? "✅" : "❌"}\n- **Connection Status:** ${healthData.makeApi.status === "connected" ? "🟢 Connected" : healthData.makeApi.status === "error" ? "🔴 Error" : "⚪ Not Tested"}\n\n${healthData.rateLimit ? `## 📊 Rate Limit Status\n- **Remaining:** ${healthData.rateLimit.remaining} requests\n- **Limit:** ${healthData.rateLimit.limit} requests/minute\n- **Reset In:** ${healthData.rateLimit.resetIn} seconds\n- **Status:** ${healthData.rateLimit.remaining > 20 ? "🟢 Good" : healthData.rateLimit.remaining > 5 ? "🟡 Low" : "🔴 Critical"}\n` : ""}\n${healthData.connectivity ? `## 🌐 Connectivity Test\n${healthData.connectivity.error ? `- **Error:** ${healthData.connectivity.error}\n- **Recommendations:**\n  1. Verify API token is valid\n  2. Check network connectivity\n  3. Confirm Make.com API is operational\n  4. Review API permissions` : `- **Organizations API:** ${healthData.connectivity.organizations}\n- **Last Test:** ${healthData.connectivity.lastTest}\n- **Status:** 🟢 All systems operational`}\n` : ""}\n## 💡 Recommendations\n${!healthData.makeApi.tokenConfigured ? "❌ **Configure MAKE_API_KEY** in environment variables\n" : ""}${healthData.rateLimit?.remaining < 10 ? "⚠️ **Rate limit low** - consider reducing request frequency\n" : ""}${healthData.makeApi.status === "error" ? "🔴 **API connectivity issues** - check token and network\n" : ""}${isHealthy ? "✅ **System is healthy** - all checks passed!" : ""}\n\nFull health data:\n\`\`\`json\n${JSON.stringify(healthData, null, 2)}\n\`\`\``,
          },
        ],
      };
    } catch (error) {
      log.error(`[${operationId}] Health check failed`, {
        error: error instanceof Error ? error.message : String(error),
      });

      return {
        content: [
          {
            type: "text",
            text: `🔴 **Health Check Failed**\n\n**Error:** ${error instanceof Error ? error.message : String(error)}\n\n**System Status:** 🔴 Critical\n**Timestamp:** ${new Date().toISOString()}\n\n**Immediate Actions Required:**\n1. 🔑 Check MAKE_API_KEY environment variable\n2. 🌐 Verify network connectivity\n3. 🔍 Review server logs for detailed errors\n4. 📞 Contact Make.com support if API is down\n\n**Debug Information:**\n- Server uptime: ${Math.round(process.uptime())} seconds\n- Memory usage: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)} MB\n- Base URL: ${process.env.MAKE_BASE_URL || "https://eu1.make.com/api/v2"}`,
          },
        ],
      };
    }
  },
});

// ==============================================================================
// Add Resource for Enhanced Server Documentation
// ==============================================================================

server.addResource({
  uri: "enhanced-make-server://docs/overview",
  name: "Enhanced Make.com Server Overview",
  mimeType: "text/markdown",
  load: async () => {
    return {
      text: `# Enhanced Make.com FastMCP Server

## Overview
This enhanced server provides comprehensive integration with Make.com API, featuring:

### 🚀 Core Features
- **Enhanced Scenario Management** - Advanced filtering, search, and status management
- **Webhook Management** - Create, configure, and monitor webhooks with learning mode
- **Analytics & Monitoring** - Comprehensive analytics with insights and recommendations  
- **System Health Checks** - Monitor API connectivity, rate limits, and server health
- **Production Logging** - Structured logging with correlation IDs and performance metrics

### 🔧 Enhanced Tools Available
1. **list-scenarios-enhanced** - Advanced scenario listing with filters
2. **create-webhook-enhanced** - Full-featured webhook creation
3. **list-webhooks-enhanced** - Comprehensive webhook management
4. **get-enhanced-analytics** - Advanced analytics with insights
5. **system-health-check** - Complete system health monitoring

### 📊 Advanced Features
- **Rate Limiting** - Intelligent rate limit tracking and monitoring
- **Error Handling** - Detailed error classification and recovery suggestions
- **Performance Monitoring** - Request timing and performance insights
- **Correlation Tracking** - Unique IDs for request tracing and debugging

### 🛠️ Configuration
Set these environment variables:
- **MAKE_API_KEY** (required) - Your Make.com API token
- **MAKE_BASE_URL** (optional) - API base URL (default: eu1.make.com)
- **LOG_LEVEL** (optional) - Logging level (default: info)
- **ENABLE_CONSOLE_LOGGING** (optional) - Enable console logs (default: false)

### 📈 Getting Started
1. Configure environment variables
2. Use system-health-check to verify connectivity
3. Explore scenarios with list-scenarios-enhanced
4. Create webhooks with create-webhook-enhanced
5. Monitor with get-enhanced-analytics

### 🎯 Best Practices
- Monitor rate limits regularly
- Use correlation IDs for debugging
- Enable detailed logging in development
- Perform health checks before critical operations
- Review analytics regularly for optimization opportunities
`,
    };
  },
});

// ==============================================================================
// Register Additional Tool Modules
// ==============================================================================

// Register Development and Customization Tools
registerDevelopmentCustomizationTools(server, makeClient, logger);

// Register AI Agent Management Tools
registerAIAgentManagementTools(server, makeClient, logger);

// Register User and Access Management Tools
registerUserAccessManagementTools(server, makeClient, logger);

// Register Data and Connectivity Management Tools
registerDataConnectivityManagementTools(server, makeClient, logger);

// Register Billing and Administration Tools
registerBillingAdministrationTools(server, makeClient, logger);

// Note: Additional tool modules temporarily disabled until TypeScript issues are resolved
// registerAdvancedMakeTools(server, makeClient, logger);

// ==============================================================================
// Start Enhanced Server
// ==============================================================================

server.start({
  transportType: "stdio",
});

const startupMessage = [
  "🚀 Enhanced Make.com FastMCP Server started successfully",
  `📊 Environment: ${process.env.NODE_ENV || "development"}`,
  `🌐 API Base URL: ${process.env.MAKE_BASE_URL || "https://eu1.make.com/api/v2"}`,
  `📝 Log Level: ${process.env.LOG_LEVEL || "info"}`,
  `⚙️  Enhanced Features: Scenarios, Webhooks, Analytics, Health Monitoring, Development & Customization, AI Agent Management, User & Access Management, Data & Connectivity Management`,
  `🔧 Core Tools: ${["list-scenarios-enhanced", "create-webhook-enhanced", "list-webhooks-enhanced", "get-enhanced-analytics", "system-health-check"].length} enhanced tools`,
  `🛠️  Development Tools: ${["create-make-custom-app", "list-make-custom-apps", "create-make-app-module", "create-make-app-rpc", "create-make-template", "create-advanced-webhook", "publish-make-custom-app"].length} custom development tools`,
  `🤖 AI Agent Tools: ${["create-ai-agent", "start-ai-agent", "manage-agent-context", "configure-agent-llm", "configure-agent-monitoring", "configure-agent-auth", "configure-agent-cache", "configure-agent-testing"].length} comprehensive AI agent management tools`,
  `👥 User & Access Tools: ${["list-make-organizations", "get-make-organization-details", "list-make-teams", "create-make-team", "invite-make-user", "manage-make-permissions", "get-make-user-activity"].length} comprehensive user and access management tools`,
  `🔗 Data & Connectivity Tools: ${["list-make-connections", "create-make-connection", "test-make-connection", "list-make-data-stores", "create-make-data-store", "list-make-webhooks", "create-make-webhook", "manage-make-api-keys"].length} comprehensive data and connectivity management tools`,
  `📚 Resources: Enhanced documentation and guides`,
  "✅ Ready for comprehensive Make.com automation and development tasks!",
];

startupMessage.forEach((msg) => logger.info(msg));

export default server;
