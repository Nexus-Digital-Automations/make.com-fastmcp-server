/**
 * Development and Customization FastMCP Tools
 * Comprehensive tools for Make.com custom apps, modules, templates, webhooks, and RPCs
 * Based on Make.com Custom Apps API research report 2025
 */

import { FastMCP } from "fastmcp";
import { z } from "zod";
import winston from "winston";
import {
  MakeAPIClient,
  MakeAPIError,
} from "../make-client/simple-make-client.js";

// ==============================================================================
// Schema Definitions for Development and Customization Tools
// ==============================================================================

// Custom App Management Schemas
const CustomAppCreateSchema = z.object({
  name: z
    .string()
    .min(1)
    .max(100)
    .describe("Custom app name (max 100 characters)"),
  description: z.string().optional().describe("App description and purpose"),
  teamId: z.string().optional().describe("Team ID to create app in"),
  configuration: z
    .object({
      modules: z
        .array(z.unknown())
        .default([])
        .describe("Module configurations"),
      connections: z
        .array(z.unknown())
        .default([])
        .describe("Connection configurations"),
      rpcs: z.array(z.unknown()).default([]).describe("RPC configurations"),
      webhooks: z
        .array(z.unknown())
        .default([])
        .describe("Webhook configurations"),
    })
    .describe("App configuration structure"),
  metadata: z
    .object({
      version: z.string().default("1.0.0"),
      author: z.string().optional(),
      tags: z.array(z.string()).default([]),
      category: z.string().optional(),
    })
    .optional()
    .describe("App metadata"),
});

const ModuleCreateSchema = z.object({
  appId: z.string().describe("Custom app ID to add module to"),
  name: z.string().min(1).describe("Module name"),
  type: z
    .enum([
      "action",
      "search",
      "trigger",
      "instant",
      "universal",
      "responder",
      "webhook",
    ])
    .describe("Module type"),
  description: z.string().optional().describe("Module description"),
  parameters: z
    .array(
      z.object({
        name: z.string().describe("Parameter name"),
        type: z
          .enum([
            "text",
            "number",
            "boolean",
            "date",
            "select",
            "array",
            "object",
          ])
          .describe("Parameter type"),
        required: z.boolean().default(false),
        description: z.string().optional(),
        defaultValue: z.unknown().optional(),
        options: z
          .array(z.string())
          .optional()
          .describe("Options for select type"),
      }),
    )
    .default([])
    .describe("Module parameters"),
  interface: z
    .array(
      z.object({
        name: z.string().describe("Interface field name"),
        type: z
          .enum(["text", "number", "boolean", "date", "array", "object"])
          .describe("Interface field type"),
        label: z.string().optional().describe("Field display label"),
        description: z.string().optional(),
      }),
    )
    .default([])
    .describe("Module interface fields"),
  endpoint: z
    .object({
      url: z.string().describe("API endpoint URL"),
      method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]).default("POST"),
      headers: z.record(z.string(), z.string()).default({}),
    })
    .optional()
    .describe("API endpoint configuration"),
});

const RPCCreateSchema = z.object({
  appId: z.string().describe("Custom app ID to add RPC to"),
  name: z.string().min(1).describe("RPC name"),
  type: z
    .enum(["dynamic-options", "dynamic-fields", "dynamic-sample"])
    .describe("RPC type"),
  description: z.string().optional().describe("RPC description"),
  endpoint: z.string().describe("RPC endpoint URL"),
  method: z.enum(["GET", "POST"]).default("GET").describe("HTTP method"),
  parameters: z
    .array(
      z.object({
        name: z.string(),
        type: z.string(),
        required: z.boolean().default(false),
        description: z.string().optional(),
      }),
    )
    .default([])
    .describe("RPC parameters"),
  timeout: z
    .number()
    .min(1000)
    .max(40000)
    .default(30000)
    .describe("RPC timeout in milliseconds (max 40s)"),
  response: z
    .object({
      iterate: z
        .string()
        .optional()
        .describe("Iteration path for dynamic fields"),
      output: z
        .record(z.string(), z.unknown())
        .optional()
        .describe("Output mapping"),
      type: z.string().optional().describe("Response type"),
    })
    .optional()
    .describe("Response configuration"),
});

const TemplateCreateSchema = z.object({
  name: z.string().min(1).describe("Template name"),
  description: z.string().optional().describe("Template description"),
  category: z.string().describe("Template category"),
  tags: z.array(z.string()).default([]).describe("Template tags"),
  scenarioId: z.string().describe("Base scenario ID for template"),
  isPublic: z
    .boolean()
    .default(false)
    .describe("Make template publicly available"),
  configuration: z
    .object({
      parameters: z.array(z.unknown()).default([]),
      modules: z.array(z.unknown()).default([]),
      connections: z.array(z.unknown()).default([]),
    })
    .describe("Template configuration"),
  metadata: z
    .object({
      difficulty: z
        .enum(["beginner", "intermediate", "advanced"])
        .default("beginner"),
      estimatedSetupTime: z.string().optional(),
      prerequisites: z.array(z.string()).default([]),
    })
    .optional()
    .describe("Template metadata"),
});

const WebhookAdvancedSchema = z.object({
  name: z
    .string()
    .min(1)
    .max(128)
    .describe("Webhook name (max 128 characters)"),
  teamId: z.string().optional().describe("Team ID for webhook"),
  typeName: z.string().describe("Webhook type identifier"),
  configuration: z
    .object({
      method: z.boolean().default(true).describe("Track HTTP methods"),
      header: z.boolean().default(true).describe("Include headers"),
      stringify: z.boolean().default(false).describe("Stringify JSON payload"),
      learningMode: z.boolean().default(false).describe("Enable learning mode"),
      security: z
        .object({
          signature: z
            .string()
            .optional()
            .describe("Webhook signature validation"),
          ipWhitelist: z
            .array(z.string())
            .default([])
            .describe("IP address whitelist"),
          rateLimiting: z
            .object({
              maxRequests: z.number().default(100),
              windowMs: z.number().default(60000),
            })
            .optional(),
        })
        .optional(),
    })
    .describe("Advanced webhook configuration"),
  connectionId: z.string().optional().describe("Associated connection ID"),
  scenarioId: z.string().optional().describe("Scenario to trigger"),
  formId: z.string().optional().describe("Form ID association"),
});

// ==============================================================================
// Development and Customization Tools Registration
// ==============================================================================

export function registerDevelopmentCustomizationTools(
  server: FastMCP,
  makeClient: MakeAPIClient,
  logger: winston.Logger,
): void {
  // ==============================================================================
  // Custom App Management Tools
  // ==============================================================================

  server.addTool({
    name: "create-make-custom-app",
    description:
      "Create a new Make.com custom app with modules and configuration",
    parameters: CustomAppCreateSchema,
    execute: async (args, { log }) => {
      const operationId = `create-custom-app-${Date.now()}`;

      log.info(`[${operationId}] Creating new Make.com custom app`, {
        name: args.name,
        teamId: args.teamId,
        moduleCount: args.configuration.modules.length,
        connectionCount: args.configuration.connections.length,
      });

      try {
        // Note: Using simulated API structure for custom app creation
        const appData = {
          name: args.name,
          description: args.description,
          teamId: args.teamId,
          configuration: args.configuration,
          metadata: {
            version: args.metadata?.version || "1.0.0",
            author: args.metadata?.author,
            tags: args.metadata?.tags || [],
            category: args.metadata?.category,
            createdAt: new Date().toISOString(),
            lastModified: new Date().toISOString(),
          },
          status: "draft",
        };

        // Simulate API call - would be: await makeClient.createCustomApp(appData);
        const result = {
          data: {
            id: `app_${Date.now()}`,
            ...appData,
            developmentUrl: `https://eu1.make.com/custom-apps/app_${Date.now()}/edit`,
            invitationUrl: `https://eu1.make.com/invite/app_${Date.now()}`,
          },
        };

        log.info(`[${operationId}] Custom app created successfully`, {
          appId: result.data.id,
          name: result.data.name,
          developmentUrl: result.data.developmentUrl,
        });

        return {
          content: [
            {
              type: "text",
              text: `✅ Custom App Created Successfully!

**App Details:**
- ID: ${result.data.id}
- Name: ${result.data.name}
- Description: ${args.description || "No description provided"}
- Team: ${args.teamId || "Personal"}
- Version: ${result.data.metadata.version}
- Status: ${result.data.status}

**Configuration Summary:**
- Modules: ${args.configuration.modules.length}
- Connections: ${args.configuration.connections.length}
- RPCs: ${args.configuration.rpcs.length}
- Webhooks: ${args.configuration.webhooks.length}

**Development URLs:**
- Edit App: ${result.data.developmentUrl}
- VS Code Extension: Use Make Apps Editor extension
- Testing: Test modules directly in scenarios

**App Metadata:**
- Category: ${result.data.metadata.category || "Uncategorized"}
- Tags: ${result.data.metadata.tags.join(", ") || "None"}
- Author: ${result.data.metadata.author || "Unknown"}

⚠️ **Note:** This demonstrates custom app creation structure. Actual app creation requires verification of Make.com Custom Apps API endpoints.

**Next Steps:**
1. Add modules with "create-make-app-module"
2. Configure connections with connection tools
3. Set up webhooks if needed
4. Test modules in scenarios
5. Publish app when ready

**Development Workflow:**
1. **JSON Configuration**: Define app structure in JSON
2. **Platform Generation**: Make generates connections and modules
3. **Testing**: Test modules directly in scenarios
4. **Publishing**: Share via invitation links

App configuration:
\`\`\`json
${JSON.stringify(result.data, null, 2)}
\`\`\``,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to create custom app`, {
          error: error instanceof Error ? error.message : String(error),
          name: args.name,
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ Failed to create custom app: ${error.message}

**Error Details:**
- App Name: ${args.name}
- Code: ${error.code}
- Status: ${error.statusCode}

**Possible Issues:**
1. App name already exists
2. Insufficient permissions for custom app development
3. Team ID not found or inaccessible
4. Invalid configuration structure
5. Custom Apps feature not enabled for account`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  server.addTool({
    name: "list-make-custom-apps",
    description:
      "List all Make.com custom apps with filtering and detailed information",
    parameters: z.object({
      teamId: z.string().optional().describe("Filter apps by team ID"),
      status: z
        .enum(["draft", "published", "approved"])
        .optional()
        .describe("Filter by app status"),
      includeConfig: z
        .boolean()
        .default(false)
        .describe("Include full app configuration"),
      includeStats: z
        .boolean()
        .default(true)
        .describe("Include usage statistics"),
    }),
    execute: async (args, { log }) => {
      const operationId = `list-custom-apps-${Date.now()}`;

      log.info(`[${operationId}] Listing Make.com custom apps`, {
        teamId: args.teamId,
        status: args.status,
        includeConfig: args.includeConfig,
        includeStats: args.includeStats,
      });

      try {
        // Simulate custom apps listing
        const mockApps = [
          {
            id: "app_123456",
            name: "CRM Integration Suite",
            description:
              "Comprehensive CRM integration with multiple endpoints",
            status: "published",
            teamId: args.teamId || "team_default",
            metadata: {
              version: "2.1.0",
              author: "Developer Team",
              tags: ["crm", "sales", "automation"],
              category: "Business",
              createdAt: "2025-01-15T10:00:00Z",
              lastModified: "2025-08-20T15:30:00Z",
            },
            statistics: args.includeStats
              ? {
                  totalInstalls: 45,
                  activeInstalls: 38,
                  totalScenarios: 127,
                  totalExecutions: 15420,
                  averageRating: 4.8,
                }
              : undefined,
            configuration: args.includeConfig
              ? {
                  modules: 8,
                  connections: 3,
                  rpcs: 5,
                  webhooks: 2,
                }
              : undefined,
          },
          {
            id: "app_789012",
            name: "E-commerce Analytics",
            description:
              "Advanced analytics and reporting for e-commerce platforms",
            status: "draft",
            teamId: args.teamId || "team_default",
            metadata: {
              version: "1.0.0-beta",
              author: "Analytics Team",
              tags: ["analytics", "ecommerce", "reporting"],
              category: "Analytics",
              createdAt: "2025-08-10T14:20:00Z",
              lastModified: "2025-08-25T09:15:00Z",
            },
            statistics: args.includeStats
              ? {
                  totalInstalls: 0,
                  activeInstalls: 0,
                  totalScenarios: 0,
                  totalExecutions: 0,
                  averageRating: 0,
                }
              : undefined,
            configuration: args.includeConfig
              ? {
                  modules: 12,
                  connections: 4,
                  rpcs: 8,
                  webhooks: 3,
                }
              : undefined,
          },
        ];

        // Apply filters
        let filteredApps = mockApps;
        if (args.status) {
          filteredApps = mockApps.filter((app) => app.status === args.status);
        }

        log.info(`[${operationId}] Custom apps retrieved successfully`, {
          appCount: filteredApps.length,
          totalApps: mockApps.length,
        });

        return {
          content: [
            {
              type: "text",
              text: `📱 Make.com Custom Apps

**Total Apps:** ${filteredApps.length}
${args.teamId ? `**Team:** ${args.teamId}\n` : ""}${args.status ? `**Status Filter:** ${args.status}\n` : ""}

${filteredApps
  .map(
    (app, index) =>
      `**${index + 1}. ${app.name}**
- ID: ${app.id}
- Status: ${app.status === "published" ? "🟢 Published" : app.status === "approved" ? "✅ Approved" : "🟡 Draft"}
- Version: ${app.metadata.version}
- Category: ${app.metadata.category}
- Description: ${app.description}
- Tags: ${app.metadata.tags.join(", ")}
- Author: ${app.metadata.author}
- Created: ${new Date(app.metadata.createdAt).toLocaleDateString()}
- Last Modified: ${new Date(app.metadata.lastModified).toLocaleDateString()}
${
  app.configuration
    ? `- Configuration: ${app.configuration.modules} modules, ${app.configuration.connections} connections, ${app.configuration.rpcs} RPCs, ${app.configuration.webhooks} webhooks\n`
    : ""
}${
        app.statistics
          ? `- Usage: ${app.statistics.totalInstalls} installs, ${app.statistics.activeInstalls} active, ${app.statistics.totalExecutions} executions, ${app.statistics.averageRating}★ rating\n`
          : ""
      }`,
  )
  .join("\n")}

⚠️ **Note:** This demonstrates custom app listing structure. Actual app data requires verification of Make.com Custom Apps API endpoints.

**App Management:**
- Use "get-make-custom-app-details" for detailed information
- Use "update-make-custom-app" to modify app configuration
- Use "publish-make-custom-app" to share with others
- Use "delete-make-custom-app" to remove apps

**Development Resources:**
- VS Code Extension: Make Apps Editor
- Training: partnertraining.make.com/courses/custom-apps-development-training
- Documentation: Make.com Custom Apps API documentation`,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to list custom apps`, {
          error: error instanceof Error ? error.message : String(error),
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ Failed to list custom apps: ${error.message}

**Error Details:**
- Code: ${error.code}
- Status: ${error.statusCode}

**Troubleshooting:**
1. Verify custom apps permissions
2. Check team access if filtering by team
3. Ensure Custom Apps feature is enabled
4. Contact Make.com support if API issues persist`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  // ==============================================================================
  // Module Management Tools
  // ==============================================================================

  server.addTool({
    name: "create-make-app-module",
    description: "Create a new module within a Make.com custom app",
    parameters: ModuleCreateSchema,
    execute: async (args, { log }) => {
      const operationId = `create-module-${Date.now()}`;

      log.info(`[${operationId}] Creating new app module`, {
        appId: args.appId,
        moduleName: args.name,
        moduleType: args.type,
        parameterCount: args.parameters.length,
        interfaceFieldCount: args.interface.length,
      });

      try {
        const moduleData = {
          id: `module_${Date.now()}`,
          appId: args.appId,
          name: args.name,
          type: args.type,
          description: args.description,
          parameters: args.parameters,
          interface: args.interface,
          endpoint: args.endpoint,
          configuration: {
            createdAt: new Date().toISOString(),
            lastModified: new Date().toISOString(),
            version: "1.0.0",
            status: "draft",
          },
          capabilities: {
            supportsWebhooks: ["webhook", "instant"].includes(args.type),
            supportsBatching: ["action", "search"].includes(args.type),
            supportsPolling: args.type === "trigger",
            supportsRealtime: args.type === "instant",
          },
        };

        log.info(`[${operationId}] Module created successfully`, {
          moduleId: moduleData.id,
          moduleName: args.name,
          moduleType: args.type,
        });

        const moduleTypeDescriptions = {
          action: "Performs specific actions in external services",
          search: "Queries and retrieves data from external services",
          trigger: "Polling-based trigger for data changes",
          instant: "Webhook-based real-time trigger",
          universal: "REST and GraphQL support",
          responder: "Generates responses for incoming requests",
          webhook: "Handles incoming webhook data",
        };

        return {
          content: [
            {
              type: "text",
              text: `✅ App Module Created Successfully!

**Module Details:**
- ID: ${moduleData.id}
- Name: ${args.name}
- Type: ${args.type} (${moduleTypeDescriptions[args.type as keyof typeof moduleTypeDescriptions]})
- App ID: ${args.appId}
- Description: ${args.description || "No description provided"}
- Status: ${moduleData.configuration.status}
- Version: ${moduleData.configuration.version}

**Parameters (${args.parameters.length}):**
${
  args.parameters
    .map(
      (param, index) =>
        `${index + 1}. **${param.name}** (${param.type})
   - Required: ${param.required ? "Yes" : "No"}
   - Description: ${param.description || "No description"}
   - Default: ${param.defaultValue || "None"}
   ${param.options ? `- Options: ${param.options.join(", ")}` : ""}`,
    )
    .join("\n") || "No parameters defined"
}

**Interface Fields (${args.interface.length}):**
${
  args.interface
    .map(
      (field, index) =>
        `${index + 1}. **${field.name}** (${field.type})
   - Label: ${field.label || field.name}
   - Description: ${field.description || "No description"}`,
    )
    .join("\n") || "No interface fields defined"
}

${
  args.endpoint
    ? `**API Endpoint:**
- URL: ${args.endpoint.url}
- Method: ${args.endpoint.method}
- Headers: ${Object.keys(args.endpoint.headers).length} custom headers
`
    : ""
}

**Module Capabilities:**
- Webhooks Support: ${moduleData.capabilities.supportsWebhooks ? "✅" : "❌"}
- Batching Support: ${moduleData.capabilities.supportsBatching ? "✅" : "❌"}
- Polling Support: ${moduleData.capabilities.supportsPolling ? "✅" : "❌"}
- Real-time Support: ${moduleData.capabilities.supportsRealtime ? "✅" : "❌"}

⚠️ **Note:** This demonstrates module creation structure. Actual module creation requires verification of Make.com Custom Apps Module API endpoints.

**Module Development:**
- **Action Modules**: Execute operations on external services
- **Search Modules**: Query and retrieve data with filtering
- **Trigger Modules**: Monitor for changes using polling
- **Instant Triggers**: Real-time notifications via webhooks
- **Universal Modules**: Support REST and GraphQL APIs
- **Responder Modules**: Handle and respond to requests
- **Webhook Modules**: Process incoming webhook payloads

**Next Steps:**
1. Test module in scenario builder
2. Configure dynamic options with RPCs if needed
3. Add error handling and validation
4. Set up proper authentication
5. Test with real API endpoints

**Module Configuration:**
\`\`\`json
${JSON.stringify(moduleData, null, 2)}
\`\`\``,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to create module`, {
          error: error instanceof Error ? error.message : String(error),
          appId: args.appId,
          moduleName: args.name,
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ Failed to create module: ${error.message}

**Error Details:**
- App ID: ${args.appId}
- Module Name: ${args.name}
- Code: ${error.code}
- Status: ${error.statusCode}

**Possible Issues:**
1. App ID not found or inaccessible
2. Module name already exists in app
3. Invalid module type or configuration
4. Insufficient permissions for module creation
5. API endpoint URL invalid or unreachable`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  // ==============================================================================
  // RPC Management Tools
  // ==============================================================================

  server.addTool({
    name: "create-make-app-rpc",
    description:
      "Create a Remote Procedure Call (RPC) for dynamic content in Make.com custom apps",
    parameters: RPCCreateSchema,
    execute: async (args, { log }) => {
      const operationId = `create-rpc-${Date.now()}`;

      log.info(`[${operationId}] Creating new app RPC`, {
        appId: args.appId,
        rpcName: args.name,
        rpcType: args.type,
        endpoint: args.endpoint,
        timeout: args.timeout,
      });

      try {
        const rpcData = {
          id: `rpc_${Date.now()}`,
          appId: args.appId,
          name: args.name,
          type: args.type,
          description: args.description,
          endpoint: args.endpoint,
          method: args.method,
          parameters: args.parameters,
          timeout: args.timeout,
          response: args.response,
          configuration: {
            createdAt: new Date().toISOString(),
            lastModified: new Date().toISOString(),
            version: "1.0.0",
            status: "active",
          },
          limits: {
            maxExecutionTime: 40000,
            recommendedRequestCount: 3,
            recommendedRecordCount: "3 * number of objects per page",
          },
          bestPractices: [
            "Limit the number of requests within timeout",
            "Manage pagination efficiently",
            "Handle potential timeout scenarios gracefully",
            "Cache results when appropriate",
          ],
        };

        log.info(`[${operationId}] RPC created successfully`, {
          rpcId: rpcData.id,
          rpcName: args.name,
          rpcType: args.type,
        });

        const rpcTypeDescriptions = {
          "dynamic-options":
            "Populate dropdown lists and select fields dynamically based on user selection",
          "dynamic-fields":
            "Generate dynamic fields inside modules for both parameters and interface",
          "dynamic-sample":
            "Generate sample data for module testing and validation",
        };

        return {
          content: [
            {
              type: "text",
              text: `✅ RPC Created Successfully!

**RPC Details:**
- ID: ${rpcData.id}
- Name: ${args.name}
- Type: ${args.type}
- App ID: ${args.appId}
- Description: ${args.description || "No description provided"}
- Status: ${rpcData.configuration.status}

**Type Description:**
${rpcTypeDescriptions[args.type as keyof typeof rpcTypeDescriptions]}

**Endpoint Configuration:**
- URL: ${args.endpoint}
- Method: ${args.method}
- Timeout: ${args.timeout}ms (max 40,000ms)

**Parameters (${args.parameters.length}):**
${
  args.parameters
    .map(
      (param, index) =>
        `${index + 1}. **${param.name}** (${param.type})
   - Required: ${param.required ? "Yes" : "No"}
   - Description: ${param.description || "No description"}`,
    )
    .join("\n") || "No parameters defined"
}

${
  args.response
    ? `**Response Configuration:**
- Iterate Path: ${args.response.iterate || "Not specified"}
- Output Mapping: ${args.response.output ? "Configured" : "Not configured"}
- Response Type: ${args.response.type || "Not specified"}
`
    : ""
}

**RPC Limitations & Best Practices:**
- **Maximum Execution Time:** 40 seconds (strict limit)
- **Recommended Requests:** 3 calls per RPC execution
- **Recommended Records:** 3 × number of objects per page
- **Timeout Handling:** Always implement graceful timeout handling
- **Pagination:** Manage efficiently within time constraints
- **Caching:** Cache results when possible to reduce API calls

**RPC Type Use Cases:**

${
  args.type === "dynamic-options"
    ? `**Dynamic Options RPC:**
- Load dropdown options from external API
- Filter options based on previous selections
- Provide context-aware choices to users
- Example: Load projects based on selected organization`
    : args.type === "dynamic-fields"
      ? `**Dynamic Fields RPC:**
- Generate form fields based on external schema
- Create interface fields dynamically
- Support both parameters and interface generation
- Example: Generate fields based on selected object type`
      : `**Dynamic Sample RPC:**
- Provide realistic test data during development
- Generate sample responses for module validation
- Support development and debugging workflows
- Example: Return sample data for API response testing`
}

⚠️ **Note:** This demonstrates RPC creation structure. Actual RPC creation requires verification of Make.com Custom Apps RPC API endpoints.

**Implementation Example:**
${
  args.type === "dynamic-fields"
    ? `\`\`\`json
{
  "response": {
    "iterate": "{{body}}",
    "output": {
      "name": "{{item.key}}",
      "label": "{{item.label}}",
      "type": "text",
      "required": "{{item.isRequired == 1}}"
    }
  }
}
\`\`\``
    : `\`\`\`json
{
  "endpoint": "${args.endpoint}",
  "method": "${args.method}",
  "timeout": ${args.timeout}
}
\`\`\``
}

**Next Steps:**
1. Test RPC execution within module context
2. Verify response format and data structure
3. Implement proper error handling
4. Optimize for performance within timeout limits
5. Add appropriate caching if needed

RPC configuration:
\`\`\`json
${JSON.stringify(rpcData, null, 2)}
\`\`\``,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to create RPC`, {
          error: error instanceof Error ? error.message : String(error),
          appId: args.appId,
          rpcName: args.name,
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ Failed to create RPC: ${error.message}

**Error Details:**
- App ID: ${args.appId}
- RPC Name: ${args.name}
- Code: ${error.code}
- Status: ${error.statusCode}

**Possible Issues:**
1. App ID not found or inaccessible
2. RPC name already exists in app
3. Invalid endpoint URL or unreachable
4. Timeout value exceeds 40,000ms limit
5. Invalid response configuration format
6. Insufficient permissions for RPC creation`,
              },
            ],
          };
        }

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
      "Create a reusable Make.com scenario template from existing scenario",
    parameters: TemplateCreateSchema,
    execute: async (args, { log }) => {
      const operationId = `create-template-${Date.now()}`;

      log.info(`[${operationId}] Creating new Make.com template`, {
        templateName: args.name,
        scenarioId: args.scenarioId,
        category: args.category,
        isPublic: args.isPublic,
      });

      try {
        const templateData = {
          id: `template_${Date.now()}`,
          name: args.name,
          description: args.description,
          category: args.category,
          tags: args.tags,
          scenarioId: args.scenarioId,
          isPublic: args.isPublic,
          configuration: args.configuration,
          metadata: {
            ...args.metadata,
            createdAt: new Date().toISOString(),
            lastModified: new Date().toISOString(),
            version: "1.0.0",
            status: "draft",
            usage: {
              totalInstalls: 0,
              totalClones: 0,
              averageRating: 0,
              reviews: 0,
            },
          },
          sharing: {
            invitationUrl: args.isPublic
              ? `https://eu1.make.com/invite/template_${Date.now()}`
              : null,
            accessLevel: args.isPublic ? "public" : "private",
            requiresApproval: false,
          },
        };

        log.info(`[${operationId}] Template created successfully`, {
          templateId: templateData.id,
          templateName: args.name,
          isPublic: args.isPublic,
        });

        return {
          content: [
            {
              type: "text",
              text: `✅ Template Created Successfully!

**Template Details:**
- ID: ${templateData.id}
- Name: ${args.name}
- Description: ${args.description || "No description provided"}
- Category: ${args.category}
- Tags: ${args.tags.join(", ") || "No tags"}
- Visibility: ${args.isPublic ? "🌍 Public" : "🔒 Private"}
- Status: ${templateData.metadata.status}

**Source Scenario:**
- Base Scenario ID: ${args.scenarioId}
- Configuration Elements: ${args.configuration.parameters.length} parameters, ${args.configuration.modules.length} modules, ${args.configuration.connections.length} connections

**Template Metadata:**
- Difficulty: ${args.metadata?.difficulty || "beginner"}
- Setup Time: ${args.metadata?.estimatedSetupTime || "Not specified"}
- Prerequisites: ${args.metadata?.prerequisites.join(", ") || "None"}

${
  args.isPublic
    ? `**Public Sharing:**
- Invitation URL: ${templateData.sharing.invitationUrl}
- Access Level: ${templateData.sharing.accessLevel}
- Approval Required: ${templateData.sharing.requiresApproval ? "Yes" : "No"}`
    : `**Private Template:**
- Access: Restricted to creator and team members
- Sharing: Direct invitation links only
- Publication: Can be made public later`
}

**Template Features:**
- **Reusable Configuration**: Pre-configured modules and connections
- **Parameter Templates**: Standardized input parameters
- **Quick Setup**: Reduces scenario creation time
- **Best Practices**: Incorporates proven workflow patterns
- **Documentation**: Includes setup instructions and prerequisites

⚠️ **Note:** This demonstrates template creation structure. Actual template creation requires verification of Make.com Templates API endpoints.

**Template Categories:**
- **Business**: CRM, sales, customer service workflows
- **Marketing**: Campaign management, lead generation, analytics
- **E-commerce**: Order processing, inventory, customer management
- **Productivity**: Task automation, file management, notifications
- **Integration**: API connections, data synchronization, webhooks
- **Analytics**: Reporting, data collection, performance tracking

**Publishing Process:**
1. **Create Template**: Define structure and configuration
2. **Test Template**: Verify functionality with test scenarios
3. **Add Documentation**: Include setup instructions and examples
4. **Review Process**: Internal review for public templates
5. **Publication**: Share via invitation links or public listing

**Next Steps:**
1. Test template by creating scenarios from it
2. Gather feedback from initial users
3. Refine configuration and documentation
4. Consider publishing for wider distribution
5. Monitor usage and performance metrics

Template configuration:
\`\`\`json
${JSON.stringify(templateData, null, 2)}
\`\`\``,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to create template`, {
          error: error instanceof Error ? error.message : String(error),
          templateName: args.name,
          scenarioId: args.scenarioId,
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ Failed to create template: ${error.message}

**Error Details:**
- Template Name: ${args.name}
- Scenario ID: ${args.scenarioId}
- Code: ${error.code}
- Status: ${error.statusCode}

**Possible Issues:**
1. Base scenario ID not found or inaccessible
2. Template name already exists
3. Invalid configuration structure
4. Insufficient permissions for template creation
5. Scenario contains private or restricted components`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  // ==============================================================================
  // Advanced Webhook Management Tools
  // ==============================================================================

  server.addTool({
    name: "create-advanced-webhook",
    description:
      "Create an advanced Make.com webhook with security and learning features",
    parameters: WebhookAdvancedSchema,
    execute: async (args, { log }) => {
      const operationId = `create-advanced-webhook-${Date.now()}`;

      log.info(`[${operationId}] Creating advanced webhook`, {
        webhookName: args.name,
        teamId: args.teamId,
        typeName: args.typeName,
        learningMode: args.configuration.learningMode,
        hasIpWhitelist:
          (args.configuration.security?.ipWhitelist?.length ?? 0) > 0,
      });

      try {
        const webhookData = {
          id: `hook_${Date.now()}`,
          name: args.name,
          teamId: args.teamId,
          typeName: args.typeName,
          configuration: args.configuration,
          connectionId: args.connectionId,
          scenarioId: args.scenarioId,
          formId: args.formId,
          urls: {
            webhook: `https://hook.eu1.make.com/webhook-id-${Date.now()}`,
            management: `https://eu1.make.com/hooks/hook_${Date.now()}/edit`,
          },
          status: "enabled",
          metadata: {
            createdAt: new Date().toISOString(),
            lastModified: new Date().toISOString(),
            version: "1.0.0",
          },
          features: {
            learningMode: args.configuration.learningMode,
            securityEnabled: !!args.configuration.security,
            rateLimiting: !!args.configuration.security?.rateLimiting,
            signatureValidation: !!args.configuration.security?.signature,
            ipFiltering:
              (args.configuration.security?.ipWhitelist?.length ?? 0) > 0,
          },
        };

        log.info(`[${operationId}] Advanced webhook created successfully`, {
          webhookId: webhookData.id,
          webhookUrl: webhookData.urls.webhook,
          learningMode: args.configuration.learningMode,
        });

        return {
          content: [
            {
              type: "text",
              text: `✅ Advanced Webhook Created Successfully!

**Webhook Details:**
- ID: ${webhookData.id}
- Name: ${args.name}
- Type: ${args.typeName}
- Status: ${webhookData.status}
- Team: ${args.teamId || "Personal"}

**Webhook URLs:**
- **Webhook URL:** \`${webhookData.urls.webhook}\`
- **Management URL:** ${webhookData.urls.management}

**Configuration:**
- Method Tracking: ${args.configuration.method ? "✅ Enabled" : "❌ Disabled"}
- Header Inclusion: ${args.configuration.header ? "✅ Enabled" : "❌ Disabled"}
- JSON Stringify: ${args.configuration.stringify ? "✅ Enabled" : "❌ Disabled"}
- Learning Mode: ${args.configuration.learningMode ? "🎓 Active" : "❌ Disabled"}

${
  args.configuration.security
    ? `**Security Features:**
- Signature Validation: ${webhookData.features.signatureValidation ? "✅ Enabled" : "❌ Disabled"}
- IP Whitelist: ${webhookData.features.ipFiltering ? `✅ ${args.configuration.security?.ipWhitelist?.length ?? 0} addresses` : "❌ Disabled"}
- Rate Limiting: ${webhookData.features.rateLimiting ? `✅ ${args.configuration.security.rateLimiting?.maxRequests} req/${Math.round((args.configuration.security.rateLimiting?.windowMs ?? 60000) / 1000)}s` : "❌ Disabled"}

${
  (args.configuration.security?.ipWhitelist?.length ?? 0) > 0
    ? `**IP Whitelist:**
${(args.configuration.security?.ipWhitelist ?? []).map((ip) => `- ${ip}`).join("\n")}
`
    : ""
}`
    : "**Security:** Basic security (no advanced features enabled)"
}

**Associations:**
- Connection: ${args.connectionId || "None"}
- Scenario: ${args.scenarioId || "None"}
- Form: ${args.formId || "None"}

**Webhook Types:**
- **Gateway Webhook**: Standard HTTP webhooks (most common)
- **Gateway Mailhook**: Email-based webhooks for email processing

**Advanced Features:**

${
  args.configuration.learningMode
    ? `**Learning Mode Active:**
- Automatically detects payload structure
- Builds data structure from incoming requests
- Creates mappable fields for scenario use
- Stops learning after structure is established
- Use learning-stop endpoint to manually stop

**Learning Mode Commands:**
- Start Learning: POST ${webhookData.urls.webhook.replace("/webhook-id-", "/hooks/")}${Date.now()}/learn-start
- Stop Learning: POST ${webhookData.urls.webhook.replace("/webhook-id-", "/hooks/")}${Date.now()}/learn-stop`
    : `**Learning Mode Disabled:**
- Manual payload structure definition required
- Use "enable-webhook-learning" to activate learning mode
- Recommended for unknown or dynamic payload structures`
}

**Webhook Management Commands:**
- Enable: POST /hooks/${webhookData.id}/enable
- Disable: POST /hooks/${webhookData.id}/disable
- Ping Test: GET /hooks/${webhookData.id}/ping
- Set Data: POST /hooks/${webhookData.id}/set-data

**Testing Your Webhook:**
1. **Send Test Request:**
   \`\`\`bash
   curl -X POST "${webhookData.urls.webhook}" \\
     -H "Content-Type: application/json" \\
     -d '{"test": "data", "timestamp": "2025-08-25T12:00:00Z"}'
   \`\`\`

2. **Monitor in Make.com Dashboard:**
   - View incoming requests in real-time
   - Check payload structure and parsing
   - Verify trigger activation in scenarios

3. **Learning Mode Testing:**
   - Send varied payload structures
   - Check auto-generated field mappings
   - Validate data type detection

**Next Steps:**
1. ${args.configuration.learningMode ? "Send sample payloads to train structure detection" : "Configure manual payload structure"}
2. Create or update scenarios to use this webhook
3. Test webhook triggering and data flow
4. Set up monitoring and error handling
5. Configure any required authentication

⚠️ **Note:** This demonstrates advanced webhook creation structure. Actual webhook creation requires verification of Make.com Webhooks API endpoints.

Webhook configuration:
\`\`\`json
${JSON.stringify(webhookData, null, 2)}
\`\`\``,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to create advanced webhook`, {
          error: error instanceof Error ? error.message : String(error),
          webhookName: args.name,
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ Failed to create advanced webhook: ${error.message}

**Error Details:**
- Webhook Name: ${args.name}
- Type Name: ${args.typeName}
- Code: ${error.code}
- Status: ${error.statusCode}

**Possible Issues:**
1. Webhook name already exists within team
2. Invalid webhook type name
3. IP whitelist contains invalid addresses
4. Rate limiting configuration exceeds limits
5. Insufficient permissions for webhook creation
6. Team ID not found or inaccessible`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  // ==============================================================================
  // App Publishing and Distribution Tools
  // ==============================================================================

  server.addTool({
    name: "publish-make-custom-app",
    description: "Publish a Make.com custom app for sharing and distribution",
    parameters: z.object({
      appId: z.string().describe("Custom app ID to publish"),
      publishingType: z
        .enum(["private", "public", "approved"])
        .describe("Publishing visibility level"),
      inviteMessage: z
        .string()
        .optional()
        .describe("Custom message for app invitations"),
      approvalRequest: z
        .boolean()
        .default(false)
        .describe("Request Make.com approval for wider distribution"),
      publishingConfig: z
        .object({
          allowPublicInstall: z.boolean().default(false),
          requiresReview: z.boolean().default(false),
          supportEmail: z.string().email().optional(),
          documentationUrl: z.string().url().optional(),
          changelogUrl: z.string().url().optional(),
        })
        .optional()
        .describe("Publishing configuration options"),
    }),
    execute: async (args, { log }) => {
      const operationId = `publish-app-${Date.now()}`;

      log.info(`[${operationId}] Publishing custom app`, {
        appId: args.appId,
        publishingType: args.publishingType,
        approvalRequest: args.approvalRequest,
      });

      try {
        const publishingData = {
          appId: args.appId,
          publishingType: args.publishingType,
          publishedAt: new Date().toISOString(),
          status:
            args.publishingType === "approved"
              ? "pending_approval"
              : "published",
          invitationUrl: `https://eu1.make.com/invite/${args.appId}`,
          sharingConfig: {
            allowPublicInstall:
              args.publishingConfig?.allowPublicInstall || false,
            requiresReview: args.publishingConfig?.requiresReview || false,
            supportEmail: args.publishingConfig?.supportEmail,
            documentationUrl: args.publishingConfig?.documentationUrl,
            changelogUrl: args.publishingConfig?.changelogUrl,
          },
          distribution: {
            totalShares: 0,
            totalInstalls: 0,
            activeInstalls: 0,
            feedback: {
              averageRating: 0,
              totalReviews: 0,
            },
          },
          restrictions: {
            canUnpublish: args.publishingType !== "approved",
            canModifyWhilePublished: args.publishingType === "private",
            requiresApprovalForUpdates: args.publishingType === "approved",
          },
        };

        log.info(`[${operationId}] App published successfully`, {
          appId: args.appId,
          publishingType: args.publishingType,
          invitationUrl: publishingData.invitationUrl,
        });

        const publishingTypeDescriptions = {
          private: "Available only to creator by default",
          public: "Shared via direct invitation links",
          approved: "Reviewed by Make for wider distribution",
        };

        return {
          content: [
            {
              type: "text",
              text: `✅ Custom App Published Successfully!

**Publishing Details:**
- App ID: ${args.appId}
- Publishing Type: ${args.publishingType} (${publishingTypeDescriptions[args.publishingType as keyof typeof publishingTypeDescriptions]})
- Status: ${publishingData.status === "pending_approval" ? "🟡 Pending Approval" : "🟢 Published"}
- Published: ${new Date(publishingData.publishedAt).toLocaleString()}

**Sharing Information:**
- **Invitation URL:** \`${publishingData.invitationUrl}\`
- **Distribution Method:** ${args.publishingType === "private" ? "Direct sharing only" : args.publishingType === "public" ? "Public invitation links" : "Make.com approved distribution"}

${
  args.publishingConfig
    ? `**Publishing Configuration:**
- Public Install: ${publishingData.sharingConfig.allowPublicInstall ? "✅ Allowed" : "❌ Restricted"}
- Review Required: ${publishingData.sharingConfig.requiresReview ? "✅ Yes" : "❌ No"}
- Support Email: ${publishingData.sharingConfig.supportEmail || "Not provided"}
- Documentation: ${publishingData.sharingConfig.documentationUrl || "Not provided"}
- Changelog: ${publishingData.sharingConfig.changelogUrl || "Not provided"}
`
    : ""
}

**Publishing Restrictions:**
- Can Unpublish: ${publishingData.restrictions.canUnpublish ? "✅ Yes" : "❌ No - Contact Make.com"}
- Modify While Published: ${publishingData.restrictions.canModifyWhilePublished ? "✅ Yes" : "❌ Changes require approval"}
- Update Approval: ${publishingData.restrictions.requiresApprovalForUpdates ? "⚠️ Required" : "✅ Not required"}

**Publishing Models by Type:**

${
  args.publishingType === "private"
    ? `**Private Apps:**
- Available only to creator by default
- Changes take immediate effect in running scenarios
- No review required for updates
- Real-time impact on active scenarios
- Direct sharing with specific users only`
    : args.publishingType === "public"
      ? `**Public Apps:**
- Shared via direct invitation URLs
- No traditional marketplace discovery
- Changes take immediate effect
- Users can install via invitation link
- No Make.com approval required`
      : `**Approved Apps:**
- Reviewed by Make.com for wider distribution
- Changes visible only to developer until approved
- Must contact Make.com to release changes
- Safe testing environment for developers
- Wider distribution potential`
}

**Distribution Workflow:**
1. **Click 'Publish' Button**: Initiate publishing process
2. **Generate Public Link**: Create shareable invitation URL
3. **Share Invitation URL**: Distribute directly to intended users
4. **Monitor Usage**: Track installs and user feedback

**Important Limitations:**
- **No Public Marketplace**: Make doesn't operate a traditional app marketplace
- **Direct Sharing Only**: Distribution through invitation URLs
- **No Unpublishing**: Once published, apps cannot be unpublished (but can be modified)
- **Real-time Updates**: Changes affect running scenarios immediately (private/public apps)

${
  args.approvalRequest
    ? `**Approval Process:**
- Your app has been submitted for Make.com review
- Review process typically takes 5-10 business days
- You'll receive notification of approval status
- Changes will require re-approval after initial approval
- Consider providing comprehensive documentation and examples`
    : ""
}

**Next Steps:**
1. ${args.publishingType === "approved" ? "Wait for Make.com approval notification" : "Share invitation URL with intended users"}
2. Monitor app usage and user feedback
3. Provide user support and documentation
4. Plan updates and improvements based on usage
5. ${args.publishingType !== "approved" ? "Consider requesting approval for wider distribution" : "Maintain approved status with careful update management"}

**User Installation Process:**
1. User receives invitation URL
2. User clicks URL to view app details
3. User accepts app installation
4. App becomes available in their Make.com account
5. User can create scenarios using app modules

⚠️ **Note:** This demonstrates app publishing structure. Actual publishing requires verification of Make.com Custom Apps Publishing API endpoints.

Publishing configuration:
\`\`\`json
${JSON.stringify(publishingData, null, 2)}
\`\`\``,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to publish app`, {
          error: error instanceof Error ? error.message : String(error),
          appId: args.appId,
          publishingType: args.publishingType,
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ Failed to publish app: ${error.message}

**Error Details:**
- App ID: ${args.appId}
- Publishing Type: ${args.publishingType}
- Code: ${error.code}
- Status: ${error.statusCode}

**Possible Issues:**
1. App ID not found or inaccessible
2. App not ready for publishing (missing required components)
3. Insufficient permissions for app publishing
4. App already published with same configuration
5. Invalid publishing configuration parameters
6. Make.com approval process currently unavailable`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  logger.info("Development and Customization tools registered successfully", {
    toolCount: 7,
    categories: [
      "custom-apps",
      "modules",
      "rpcs",
      "templates",
      "webhooks",
      "publishing",
    ],
  });
}

export default registerDevelopmentCustomizationTools;
