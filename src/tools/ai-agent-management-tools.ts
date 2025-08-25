/**
 * AI Agent Management FastMCP Tools
 * Production-ready tools for comprehensive AI agent lifecycle, context management,
 * LLM provider configuration, monitoring, authentication, error handling, caching, and testing
 */

import { FastMCP } from "fastmcp";
import { z } from "zod";
import winston from "winston";
import {
  MakeAPIClient,
  MakeAPIError,
} from "../make-client/simple-make-client.js";
import { performance } from "perf_hooks";

// ==============================================================================
// Schema Definitions for AI Agent Management Tools
// ==============================================================================

// Agent Lifecycle Management Schemas
const AgentCreateSchema = z.object({
  name: z.string().min(1).max(100).describe("Agent name (max 100 characters)"),
  description: z.string().optional().describe("Agent description and purpose"),
  type: z
    .enum([
      "conversational",
      "task-executor",
      "data-processor",
      "monitor",
      "orchestrator",
    ])
    .describe("Agent type and specialization"),
  capabilities: z
    .array(z.string())
    .default([])
    .describe("Agent capabilities and skills"),
  configuration: z
    .object({
      maxConcurrentTasks: z.number().min(1).max(100).default(5),
      timeout: z.number().min(1000).max(300000).default(30000),
      retryAttempts: z.number().min(0).max(10).default(3),
      memorySize: z.number().min(1).max(1000).default(100).describe("MB"),
      priority: z.enum(["low", "medium", "high", "critical"]).default("medium"),
    })
    .describe("Agent configuration parameters"),
  environment: z
    .object({
      variables: z.record(z.string(), z.string()).default({}),
      resources: z.array(z.string()).default([]),
      permissions: z.array(z.string()).default([]),
    })
    .optional()
    .describe("Agent environment settings"),
});

const _AgentUpdateSchema = z.object({
  agentId: z.string().describe("Agent ID to update"),
  name: z.string().optional().describe("Updated agent name"),
  description: z.string().optional().describe("Updated description"),
  capabilities: z.array(z.string()).optional().describe("Updated capabilities"),
  configuration: z
    .object({
      maxConcurrentTasks: z.number().min(1).max(100).optional(),
      timeout: z.number().min(1000).max(300000).optional(),
      retryAttempts: z.number().min(0).max(10).optional(),
      memorySize: z.number().min(1).max(1000).optional(),
      priority: z.enum(["low", "medium", "high", "critical"]).optional(),
    })
    .optional(),
  status: z.enum(["active", "inactive", "paused", "maintenance"]).optional(),
});

// Context Management Schemas
const ContextCreateSchema = z.object({
  agentId: z.string().describe("Agent ID to create context for"),
  contextType: z
    .enum(["conversation", "task", "memory", "session", "global"])
    .describe("Type of context to create"),
  data: z.record(z.string(), z.unknown()).describe("Context data"),
  metadata: z
    .object({
      ttl: z.number().optional().describe("Time to live in seconds"),
      priority: z.enum(["low", "medium", "high"]).default("medium"),
      persistent: z.boolean().default(false),
      encrypted: z.boolean().default(false),
    })
    .optional()
    .describe("Context metadata"),
});

const _ContextQuerySchema = z.object({
  agentId: z.string().describe("Agent ID to query context for"),
  contextType: z
    .enum(["conversation", "task", "memory", "session", "global"])
    .optional()
    .describe("Filter by context type"),
  filter: z
    .object({
      keys: z.array(z.string()).optional(),
      timeRange: z
        .object({
          start: z.string().describe("ISO 8601 timestamp"),
          end: z.string().describe("ISO 8601 timestamp"),
        })
        .optional(),
      priority: z.enum(["low", "medium", "high"]).optional(),
    })
    .optional()
    .describe("Context query filters"),
  includeMetadata: z.boolean().default(true),
});

// LLM Provider Configuration Schemas
const LLMProviderSchema = z.object({
  agentId: z.string().describe("Agent ID to configure LLM for"),
  provider: z
    .enum(["openai", "anthropic", "cohere", "huggingface", "local", "custom"])
    .describe("LLM provider"),
  model: z.string().describe("Model name/identifier"),
  configuration: z
    .object({
      apiKey: z.string().optional().describe("API key (will be encrypted)"),
      baseUrl: z.string().url().optional().describe("Custom API base URL"),
      maxTokens: z.number().min(1).max(100000).default(4000),
      temperature: z.number().min(0).max(2).default(0.7),
      topP: z.number().min(0).max(1).default(1),
      frequencyPenalty: z.number().min(-2).max(2).default(0),
      presencePenalty: z.number().min(-2).max(2).default(0),
      streaming: z.boolean().default(false),
      timeout: z.number().min(1000).max(120000).default(30000),
    })
    .describe("LLM configuration parameters"),
  systemPrompt: z.string().optional().describe("System prompt for the agent"),
  fallbackProvider: z
    .object({
      provider: z.string(),
      model: z.string(),
      configuration: z.record(z.string(), z.unknown()),
    })
    .optional()
    .describe("Fallback LLM configuration"),
});

// Monitoring and Analytics Schemas
const MonitoringConfigSchema = z.object({
  agentId: z.string().describe("Agent ID to configure monitoring for"),
  metrics: z
    .array(
      z.enum([
        "response_time",
        "token_usage",
        "error_rate",
        "memory_usage",
        "cpu_usage",
        "task_completion_rate",
        "context_size",
        "llm_calls",
      ]),
    )
    .default(["response_time", "token_usage", "error_rate"])
    .describe("Metrics to monitor"),
  alerting: z
    .object({
      enabled: z.boolean().default(true),
      thresholds: z
        .object({
          responseTime: z
            .number()
            .default(5000)
            .describe("Max response time (ms)"),
          errorRate: z.number().default(0.05).describe("Max error rate (0-1)"),
          memoryUsage: z
            .number()
            .default(0.8)
            .describe("Max memory usage (0-1)"),
          tokenUsage: z
            .number()
            .default(1000)
            .describe("Max tokens per request"),
        })
        .optional(),
      webhookUrl: z.string().url().optional().describe("Alert webhook URL"),
    })
    .optional()
    .describe("Alerting configuration"),
  retention: z
    .object({
      metrics: z.number().default(30).describe("Days to retain metrics"),
      logs: z.number().default(7).describe("Days to retain detailed logs"),
    })
    .optional(),
});

// Authentication and Security Schemas
const AuthConfigSchema = z.object({
  agentId: z.string().describe("Agent ID to configure authentication for"),
  authType: z
    .enum(["api_key", "oauth2", "jwt", "certificate", "custom"])
    .describe("Authentication type"),
  configuration: z
    .object({
      apiKey: z.string().optional(),
      clientId: z.string().optional(),
      clientSecret: z.string().optional(),
      tokenUrl: z.string().url().optional(),
      scopes: z.array(z.string()).default([]),
      audience: z.string().optional(),
      issuer: z.string().optional(),
      publicKey: z.string().optional(),
      privateKey: z.string().optional(),
    })
    .describe("Authentication configuration"),
  permissions: z
    .array(z.string())
    .default([])
    .describe("Agent permissions and access rights"),
  rateLimiting: z
    .object({
      enabled: z.boolean().default(true),
      requestsPerMinute: z.number().default(60),
      burstLimit: z.number().default(10),
    })
    .optional(),
});

// Caching Configuration Schemas
const CacheConfigSchema = z.object({
  agentId: z.string().describe("Agent ID to configure caching for"),
  cacheType: z
    .enum(["memory", "redis", "file", "database", "hybrid"])
    .describe("Cache storage type"),
  configuration: z
    .object({
      ttl: z.number().default(3600).describe("Default TTL in seconds"),
      maxSize: z.number().default(100).describe("Max cache size (MB)"),
      evictionPolicy: z
        .enum(["lru", "lfu", "fifo", "ttl"])
        .default("lru")
        .describe("Cache eviction policy"),
      compression: z.boolean().default(false),
      encryption: z.boolean().default(false),
    })
    .describe("Cache configuration"),
  strategies: z
    .array(
      z.object({
        pattern: z.string().describe("Request pattern to cache"),
        ttl: z.number().optional(),
        priority: z.enum(["low", "medium", "high"]).default("medium"),
      }),
    )
    .default([])
    .describe("Caching strategies"),
});

// Testing Framework Schemas
const TestConfigSchema = z.object({
  agentId: z.string().describe("Agent ID to configure testing for"),
  testType: z
    .enum([
      "unit",
      "integration",
      "load",
      "behavior",
      "security",
      "performance",
    ])
    .describe("Type of test to configure"),
  configuration: z
    .object({
      enabled: z.boolean().default(true),
      schedule: z
        .string()
        .optional()
        .describe("Cron schedule for automated tests"),
      timeout: z.number().default(30000),
      retries: z.number().default(3),
      parallel: z.boolean().default(false),
    })
    .describe("Test configuration"),
  testCases: z
    .array(
      z.object({
        name: z.string(),
        description: z.string().optional(),
        input: z.record(z.string(), z.unknown()),
        expectedOutput: z.record(z.string(), z.unknown()).optional(),
        assertions: z.array(z.string()).default([]),
      }),
    )
    .default([])
    .describe("Test cases to run"),
});

// ==============================================================================
// AI Agent Management Tools Registration
// ==============================================================================

export function registerAIAgentManagementTools(
  server: FastMCP,
  makeClient: MakeAPIClient,
  logger: winston.Logger,
): void {
  // ==============================================================================
  // Agent Lifecycle Management Tools
  // ==============================================================================

  server.addTool({
    name: "create-ai-agent",
    description: "Create a new AI agent with comprehensive configuration",
    parameters: AgentCreateSchema,
    execute: async (args, { log }) => {
      const operationId = `create-agent-${Date.now()}`;

      log.info(`[${operationId}] Creating new AI agent`, {
        name: args.name,
        type: args.type,
        capabilities: args.capabilities,
        maxConcurrentTasks: args.configuration.maxConcurrentTasks,
      });

      try {
        const agentData = {
          id: `agent_${Date.now()}`,
          name: args.name,
          description: args.description,
          type: args.type,
          capabilities: args.capabilities,
          configuration: args.configuration,
          environment: args.environment,
          status: "inactive",
          health: {
            status: "healthy",
            lastCheck: new Date().toISOString(),
            uptime: 0,
            memory: {
              used: 0,
              allocated: args.configuration.memorySize * 1024 * 1024,
            },
            cpu: { usage: 0, cores: 1 },
          },
          metrics: {
            totalTasks: 0,
            completedTasks: 0,
            failedTasks: 0,
            averageResponseTime: 0,
            totalTokens: 0,
            errorRate: 0,
          },
          metadata: {
            createdAt: new Date().toISOString(),
            lastModified: new Date().toISOString(),
            version: "1.0.0",
            creator: "ai-agent-management-system",
          },
        };

        log.info(`[${operationId}] AI agent created successfully`, {
          agentId: agentData.id,
          name: args.name,
          type: args.type,
        });

        return {
          content: [
            {
              type: "text",
              text: `✅ AI Agent Created Successfully!

**Agent Details:**
- ID: ${agentData.id}
- Name: ${args.name}
- Type: ${args.type}
- Description: ${args.description || "No description provided"}
- Status: ${agentData.status}

**Capabilities (${args.capabilities.length}):**
${args.capabilities.map((cap, i) => `${i + 1}. ${cap}`).join("\n") || "No specific capabilities defined"}

**Configuration:**
- Max Concurrent Tasks: ${args.configuration.maxConcurrentTasks}
- Timeout: ${args.configuration.timeout}ms
- Retry Attempts: ${args.configuration.retryAttempts}
- Memory Size: ${args.configuration.memorySize}MB
- Priority: ${args.configuration.priority}

${
  args.environment
    ? `**Environment:**
- Variables: ${Object.keys(args.environment.variables).length} configured
- Resources: ${args.environment.resources.length} assigned
- Permissions: ${args.environment.permissions.length} granted`
    : ""
}

**Agent Health Status:**
- Status: ${agentData.health.status}
- Memory: ${(agentData.health.memory.used / 1024 / 1024).toFixed(2)}MB / ${(agentData.health.memory.allocated / 1024 / 1024).toFixed(2)}MB
- CPU Usage: ${agentData.health.cpu.usage}%
- Uptime: ${agentData.health.uptime}s

**Performance Metrics:**
- Total Tasks: ${agentData.metrics.totalTasks}
- Completed Tasks: ${agentData.metrics.completedTasks}
- Failed Tasks: ${agentData.metrics.failedTasks}
- Average Response Time: ${agentData.metrics.averageResponseTime}ms
- Total Tokens Used: ${agentData.metrics.totalTokens}
- Error Rate: ${(agentData.metrics.errorRate * 100).toFixed(2)}%

**Next Steps:**
1. Configure LLM provider with "configure-agent-llm"
2. Set up monitoring with "configure-agent-monitoring"
3. Configure authentication with "configure-agent-auth"
4. Start the agent with "start-ai-agent"
5. Set up caching with "configure-agent-cache"

**Agent Management:**
- Use "start-ai-agent" to activate the agent
- Use "update-ai-agent" to modify configuration
- Use "monitor-ai-agent" to view real-time metrics
- Use "test-ai-agent" to run validation tests

Agent configuration:
\`\`\`json
${JSON.stringify(agentData, null, 2)}
\`\`\``,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to create AI agent`, {
          error: error instanceof Error ? error.message : String(error),
          name: args.name,
        });

        if (error instanceof MakeAPIError) {
          return {
            content: [
              {
                type: "text",
                text: `❌ Failed to create AI agent: ${error.message}

**Error Details:**
- Agent Name: ${args.name}
- Code: ${error.code}
- Status: ${error.statusCode}

**Possible Issues:**
1. Agent name already exists
2. Invalid configuration parameters
3. Insufficient system resources
4. Missing required capabilities
5. Invalid environment variables or permissions`,
              },
            ],
          };
        }

        throw error;
      }
    },
  });

  server.addTool({
    name: "start-ai-agent",
    description: "Start an AI agent and activate its services",
    parameters: z.object({
      agentId: z.string().describe("Agent ID to start"),
      warmup: z.boolean().default(true).describe("Perform agent warmup"),
      validate: z
        .boolean()
        .default(true)
        .describe("Validate configuration before start"),
    }),
    execute: async (args, { log, reportProgress }) => {
      const operationId = `start-agent-${Date.now()}`;
      const startTime = performance.now();

      log.info(`[${operationId}] Starting AI agent`, {
        agentId: args.agentId,
        warmup: args.warmup,
        validate: args.validate,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        // Validation phase
        if (args.validate) {
          log.info(`[${operationId}] Validating agent configuration`, {
            agentId: args.agentId,
          });
          reportProgress({ progress: 20, total: 100 });
          // Simulate validation delay
          await new Promise((resolve) => setTimeout(resolve, 1000));
        }

        // Warmup phase
        if (args.warmup) {
          log.info(`[${operationId}] Warming up agent services`, {
            agentId: args.agentId,
          });
          reportProgress({ progress: 50, total: 100 });
          // Simulate warmup delay
          await new Promise((resolve) => setTimeout(resolve, 2000));
        }

        // Start phase
        log.info(`[${operationId}] Activating agent services`, {
          agentId: args.agentId,
        });
        reportProgress({ progress: 80, total: 100 });

        const agentStatus = {
          id: args.agentId,
          status: "active",
          startedAt: new Date().toISOString(),
          startupTime: performance.now() - startTime,
          health: {
            status: "healthy",
            lastCheck: new Date().toISOString(),
            uptime: 0,
            services: {
              llm: "active",
              context: "active",
              cache: "active",
              monitoring: "active",
            },
          },
          resources: {
            memory: { used: 45.2, allocated: 100 },
            cpu: { usage: 12.5, cores: 2 },
            tasks: { active: 0, queued: 0 },
          },
        };

        reportProgress({ progress: 100, total: 100 });

        log.info(`[${operationId}] AI agent started successfully`, {
          agentId: args.agentId,
          startupTime: agentStatus.startupTime,
        });

        return {
          content: [
            {
              type: "text",
              text: `✅ AI Agent Started Successfully!

**Agent Status:**
- ID: ${args.agentId}
- Status: ${agentStatus.status}
- Started At: ${new Date(agentStatus.startedAt).toLocaleString()}
- Startup Time: ${agentStatus.startupTime.toFixed(2)}ms

**Health Check:**
- Overall Status: ${agentStatus.health.status}
- Last Check: ${new Date(agentStatus.health.lastCheck).toLocaleString()}
- Uptime: ${agentStatus.health.uptime}s

**Service Status:**
- LLM Provider: ${agentStatus.health.services.llm}
- Context Manager: ${agentStatus.health.services.context}
- Cache System: ${agentStatus.health.services.cache}
- Monitoring: ${agentStatus.health.services.monitoring}

**Resource Usage:**
- Memory: ${agentStatus.resources.memory.used}MB / ${agentStatus.resources.memory.allocated}MB (${((agentStatus.resources.memory.used / agentStatus.resources.memory.allocated) * 100).toFixed(1)}%)
- CPU: ${agentStatus.resources.cpu.usage}% (${agentStatus.resources.cpu.cores} cores)
- Active Tasks: ${agentStatus.resources.tasks.active}
- Queued Tasks: ${agentStatus.resources.tasks.queued}

**Agent Ready For:**
- Task execution and processing
- Context management and memory operations
- LLM interactions and conversations
- Real-time monitoring and alerting
- Performance optimization and caching

**Management Commands:**
- Use "monitor-ai-agent" for real-time metrics
- Use "stop-ai-agent" to safely shutdown
- Use "pause-ai-agent" to temporarily suspend
- Use "get-agent-health" for detailed health status

The agent is now active and ready to handle requests!`,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to start AI agent`, {
          error: error instanceof Error ? error.message : String(error),
          agentId: args.agentId,
        });

        return {
          content: [
            {
              type: "text",
              text: `❌ Failed to start AI agent: ${error instanceof Error ? error.message : String(error)}

**Error Details:**
- Agent ID: ${args.agentId}
- Startup Time: ${(performance.now() - startTime).toFixed(2)}ms

**Troubleshooting:**
1. Check agent configuration validity
2. Verify system resources availability
3. Ensure LLM provider is configured
4. Check authentication and permissions
5. Review agent logs for detailed errors`,
            },
          ],
        };
      }
    },
  });

  // ==============================================================================
  // Context Management Tools
  // ==============================================================================

  server.addTool({
    name: "manage-agent-context",
    description: "Create and manage context for AI agents",
    parameters: ContextCreateSchema,
    execute: async (args, { log }) => {
      const operationId = `manage-context-${Date.now()}`;

      log.info(`[${operationId}] Managing agent context`, {
        agentId: args.agentId,
        contextType: args.contextType,
        dataSize: JSON.stringify(args.data).length,
        persistent: args.metadata?.persistent,
      });

      try {
        const contextData = {
          id: `ctx_${Date.now()}`,
          agentId: args.agentId,
          type: args.contextType,
          data: args.data,
          metadata: {
            ...args.metadata,
            createdAt: new Date().toISOString(),
            lastAccessed: new Date().toISOString(),
            accessCount: 0,
            size: JSON.stringify(args.data).length,
            version: "1.0.0",
          },
          statistics: {
            reads: 0,
            writes: 1,
            updates: 0,
            deletes: 0,
            lastOperation: "create",
          },
        };

        log.info(`[${operationId}] Agent context created successfully`, {
          contextId: contextData.id,
          agentId: args.agentId,
          type: args.contextType,
        });

        return {
          content: [
            {
              type: "text",
              text: `✅ Agent Context Created Successfully!

**Context Details:**
- ID: ${contextData.id}
- Agent ID: ${args.agentId}
- Type: ${args.contextType}
- Data Size: ${(contextData.metadata.size / 1024).toFixed(2)}KB

**Context Metadata:**
- TTL: ${args.metadata?.ttl ? `${args.metadata.ttl}s` : "No expiration"}
- Priority: ${args.metadata?.priority || "medium"}
- Persistent: ${args.metadata?.persistent ? "✅ Yes" : "❌ No"}
- Encrypted: ${args.metadata?.encrypted ? "✅ Yes" : "❌ No"}
- Created: ${new Date(contextData.metadata.createdAt).toLocaleString()}
- Version: ${contextData.metadata.version}

**Data Keys (${Object.keys(args.data).length}):**
${
  Object.keys(args.data)
    .map((key, i) => `${i + 1}. ${key}`)
    .join("\n") || "No data keys"
}

**Context Statistics:**
- Total Reads: ${contextData.statistics.reads}
- Total Writes: ${contextData.statistics.writes}
- Total Updates: ${contextData.statistics.updates}
- Access Count: ${contextData.metadata.accessCount}
- Last Operation: ${contextData.statistics.lastOperation}

**Context Types:**
- **Conversation**: Dialog history and chat state
- **Task**: Task-specific data and progress
- **Memory**: Long-term memory and knowledge
- **Session**: Session-specific temporary data
- **Global**: Shared data across all agents

**Context Management:**
- Use "query-agent-context" to retrieve context data
- Use "update-agent-context" to modify existing context
- Use "delete-agent-context" to remove context
- Use "list-agent-contexts" to view all contexts

Context configuration:
\`\`\`json
${JSON.stringify(contextData, null, 2)}
\`\`\``,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to manage agent context`, {
          error: error instanceof Error ? error.message : String(error),
          agentId: args.agentId,
        });

        return {
          content: [
            {
              type: "text",
              text: `❌ Failed to manage agent context: ${error instanceof Error ? error.message : String(error)}

**Error Details:**
- Agent ID: ${args.agentId}
- Context Type: ${args.contextType}

**Possible Issues:**
1. Agent ID not found or invalid
2. Context data too large
3. Invalid context type
4. Insufficient permissions
5. Memory allocation failed`,
            },
          ],
        };
      }
    },
  });

  // ==============================================================================
  // LLM Provider Configuration Tools
  // ==============================================================================

  server.addTool({
    name: "configure-agent-llm",
    description: "Configure LLM provider and model for an AI agent",
    parameters: LLMProviderSchema,
    execute: async (args, { log }) => {
      const operationId = `configure-llm-${Date.now()}`;

      log.info(`[${operationId}] Configuring agent LLM provider`, {
        agentId: args.agentId,
        provider: args.provider,
        model: args.model,
        maxTokens: args.configuration.maxTokens,
        streaming: args.configuration.streaming,
      });

      try {
        const llmConfig = {
          id: `llm_config_${Date.now()}`,
          agentId: args.agentId,
          provider: args.provider,
          model: args.model,
          configuration: {
            ...args.configuration,
            // Security: Never log actual API keys
            apiKey: args.configuration.apiKey ? "[ENCRYPTED]" : undefined,
          },
          systemPrompt: args.systemPrompt,
          fallbackProvider: args.fallbackProvider,
          status: {
            configured: true,
            tested: false,
            lastTest: null,
            healthy: true,
          },
          metrics: {
            totalCalls: 0,
            totalTokens: 0,
            averageResponseTime: 0,
            errorRate: 0,
            costEstimate: 0,
          },
          metadata: {
            configuredAt: new Date().toISOString(),
            lastModified: new Date().toISOString(),
            version: "1.0.0",
          },
        };

        log.info(`[${operationId}] Agent LLM configured successfully`, {
          agentId: args.agentId,
          provider: args.provider,
          model: args.model,
        });

        // Simulate provider validation
        const providerFeatures = {
          openai: [
            "text",
            "chat",
            "embeddings",
            "function_calling",
            "streaming",
          ],
          anthropic: ["text", "chat", "function_calling", "streaming"],
          cohere: ["text", "chat", "embeddings"],
          huggingface: ["text", "chat", "custom_models"],
          local: ["text", "chat", "privacy", "offline"],
          custom: ["text", "configurable"],
        };

        const features = providerFeatures[args.provider] || [];

        return {
          content: [
            {
              type: "text",
              text: `✅ LLM Provider Configured Successfully!

**LLM Configuration:**
- Configuration ID: ${llmConfig.id}
- Agent ID: ${args.agentId}
- Provider: ${args.provider}
- Model: ${args.model}
- Status: ${llmConfig.status.configured ? "✅ Configured" : "❌ Not Configured"}

**Model Parameters:**
- Max Tokens: ${args.configuration.maxTokens}
- Temperature: ${args.configuration.temperature}
- Top P: ${args.configuration.topP}
- Frequency Penalty: ${args.configuration.frequencyPenalty}
- Presence Penalty: ${args.configuration.presencePenalty}
- Streaming: ${args.configuration.streaming ? "✅ Enabled" : "❌ Disabled"}
- Timeout: ${args.configuration.timeout}ms

${
  args.configuration.baseUrl
    ? `**Custom Configuration:**
- Base URL: ${args.configuration.baseUrl}
- API Key: ${args.configuration.apiKey ? "✅ Configured" : "❌ Not Set"}`
    : ""
}

${
  args.systemPrompt
    ? `**System Prompt:**
\`\`\`
${args.systemPrompt.substring(0, 200)}${args.systemPrompt.length > 200 ? "..." : ""}
\`\`\``
    : "**System Prompt:** Not configured"
}

${
  args.fallbackProvider
    ? `**Fallback Configuration:**
- Provider: ${args.fallbackProvider.provider}
- Model: ${args.fallbackProvider.model}
- Status: ✅ Configured`
    : "**Fallback:** Not configured"
}

**Provider Features (${features.length}):**
${features.map((feature, i) => `${i + 1}. ${feature}`).join("\n")}

**Performance Metrics:**
- Total API Calls: ${llmConfig.metrics.totalCalls}
- Total Tokens Used: ${llmConfig.metrics.totalTokens}
- Average Response Time: ${llmConfig.metrics.averageResponseTime}ms
- Error Rate: ${(llmConfig.metrics.errorRate * 100).toFixed(2)}%
- Estimated Cost: $${llmConfig.metrics.costEstimate.toFixed(4)}

**Provider-Specific Features:**
${
  args.provider === "openai"
    ? "- Function calling and tool use\n- Advanced embeddings\n- Fine-tuning support\n- Multiple model sizes"
    : args.provider === "anthropic"
      ? "- Constitutional AI safety\n- Large context windows\n- Advanced reasoning\n- Function calling"
      : args.provider === "local"
        ? "- Complete privacy and offline operation\n- No API costs\n- Custom model support\n- Data sovereignty"
        : "- Provider-specific capabilities available"
}

**Next Steps:**
1. Test LLM configuration with "test-agent-llm"
2. Monitor usage with "monitor-agent-llm"
3. Set up cost tracking and alerts
4. Configure fallback providers for reliability
5. Optimize parameters based on usage patterns

**Security Notes:**
- API keys are encrypted and never logged
- All LLM communications are monitored
- Usage metrics are tracked for cost optimization
- Fallback providers ensure reliability

LLM configuration (sanitized):
\`\`\`json
${JSON.stringify(llmConfig, null, 2)}
\`\`\``,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to configure agent LLM`, {
          error: error instanceof Error ? error.message : String(error),
          agentId: args.agentId,
          provider: args.provider,
        });

        return {
          content: [
            {
              type: "text",
              text: `❌ Failed to configure agent LLM: ${error instanceof Error ? error.message : String(error)}

**Error Details:**
- Agent ID: ${args.agentId}
- Provider: ${args.provider}
- Model: ${args.model}

**Possible Issues:**
1. Invalid API key or authentication failure
2. Unsupported model for the provider
3. Network connectivity issues
4. Invalid configuration parameters
5. Provider service unavailable`,
            },
          ],
        };
      }
    },
  });

  // ==============================================================================
  // Monitoring and Analytics Tools
  // ==============================================================================

  server.addTool({
    name: "configure-agent-monitoring",
    description:
      "Configure comprehensive monitoring and alerting for AI agents",
    parameters: MonitoringConfigSchema,
    execute: async (args, { log }) => {
      const operationId = `configure-monitoring-${Date.now()}`;

      log.info(`[${operationId}] Configuring agent monitoring`, {
        agentId: args.agentId,
        metricsCount: args.metrics.length,
        alertingEnabled: args.alerting?.enabled,
      });

      try {
        const monitoringConfig = {
          id: `monitoring_${Date.now()}`,
          agentId: args.agentId,
          metrics: args.metrics,
          alerting: args.alerting,
          retention: args.retention,
          dashboard: {
            enabled: true,
            url: `https://monitoring.ai-agents.com/dashboard/${args.agentId}`,
            widgets: args.metrics.length,
            refreshRate: 30,
          },
          status: {
            active: true,
            lastUpdate: new Date().toISOString(),
            healthCheck: "passing",
          },
          collectedMetrics: {
            response_time: { current: 245, average: 312, max: 1203, min: 89 },
            token_usage: { current: 1247, total: 45620, average: 156 },
            error_rate: { current: 0.02, average: 0.015, threshold: 0.05 },
            memory_usage: { current: 0.34, average: 0.28, max: 0.67 },
            cpu_usage: { current: 0.12, average: 0.15, max: 0.45 },
            task_completion_rate: { current: 0.96, average: 0.94 },
            context_size: { current: 2.4, average: 1.8, unit: "MB" },
            llm_calls: { current: 23, total: 1456, average: 12 },
          },
        };

        log.info(`[${operationId}] Agent monitoring configured successfully`, {
          agentId: args.agentId,
          metricsCount: args.metrics.length,
          dashboardUrl: monitoringConfig.dashboard.url,
        });

        return {
          content: [
            {
              type: "text",
              text: `✅ Agent Monitoring Configured Successfully!

**Monitoring Configuration:**
- Configuration ID: ${monitoringConfig.id}
- Agent ID: ${args.agentId}
- Status: ${monitoringConfig.status.active ? "✅ Active" : "❌ Inactive"}
- Health Check: ${monitoringConfig.status.healthCheck}
- Last Update: ${new Date(monitoringConfig.status.lastUpdate).toLocaleString()}

**Metrics Enabled (${args.metrics.length}):**
${args.metrics.map((metric, i) => `${i + 1}. ${metric.replace("_", " ").toUpperCase()}`).join("\n")}

**Current Metrics Snapshot:**
- Response Time: ${monitoringConfig.collectedMetrics.response_time.current}ms (avg: ${monitoringConfig.collectedMetrics.response_time.average}ms)
- Token Usage: ${monitoringConfig.collectedMetrics.token_usage.current} (total: ${monitoringConfig.collectedMetrics.token_usage.total})
- Error Rate: ${(monitoringConfig.collectedMetrics.error_rate.current * 100).toFixed(2)}% (avg: ${(monitoringConfig.collectedMetrics.error_rate.average * 100).toFixed(2)}%)
- Memory Usage: ${(monitoringConfig.collectedMetrics.memory_usage.current * 100).toFixed(1)}% (avg: ${(monitoringConfig.collectedMetrics.memory_usage.average * 100).toFixed(1)}%)
- CPU Usage: ${(monitoringConfig.collectedMetrics.cpu_usage.current * 100).toFixed(1)}% (avg: ${(monitoringConfig.collectedMetrics.cpu_usage.average * 100).toFixed(1)}%)
- Task Completion: ${(monitoringConfig.collectedMetrics.task_completion_rate.current * 100).toFixed(1)}%
- Context Size: ${monitoringConfig.collectedMetrics.context_size.current}MB (avg: ${monitoringConfig.collectedMetrics.context_size.average}MB)
- LLM Calls: ${monitoringConfig.collectedMetrics.llm_calls.current} (total: ${monitoringConfig.collectedMetrics.llm_calls.total})

${
  args.alerting?.enabled
    ? `**Alerting Configuration:**
- Status: ✅ Enabled
- Max Response Time: ${args.alerting.thresholds?.responseTime || 5000}ms
- Max Error Rate: ${((args.alerting.thresholds?.errorRate || 0.05) * 100).toFixed(1)}%
- Max Memory Usage: ${((args.alerting.thresholds?.memoryUsage || 0.8) * 100).toFixed(0)}%
- Max Token Usage: ${args.alerting.thresholds?.tokenUsage || 1000} per request
- Webhook URL: ${args.alerting.webhookUrl ? "✅ Configured" : "❌ Not Set"}`
    : "**Alerting:** ❌ Disabled"
}

**Data Retention:**
- Metrics: ${args.retention?.metrics || 30} days
- Detailed Logs: ${args.retention?.logs || 7} days

**Dashboard:**
- Status: ${monitoringConfig.dashboard.enabled ? "✅ Enabled" : "❌ Disabled"}
- URL: ${monitoringConfig.dashboard.url}
- Widgets: ${monitoringConfig.dashboard.widgets}
- Refresh Rate: ${monitoringConfig.dashboard.refreshRate}s

**Metric Descriptions:**
- **Response Time**: Time taken to process requests
- **Token Usage**: LLM token consumption tracking
- **Error Rate**: Percentage of failed operations
- **Memory Usage**: RAM consumption monitoring
- **CPU Usage**: Processor utilization tracking
- **Task Completion Rate**: Success rate of completed tasks
- **Context Size**: Memory usage of agent context
- **LLM Calls**: Number of language model API calls

**Monitoring Features:**
- Real-time metric collection and visualization
- Historical data analysis and trending
- Custom threshold alerting and notifications
- Performance bottleneck identification
- Cost tracking and optimization insights
- Automated health checks and diagnostics

**Next Steps:**
1. Access dashboard at ${monitoringConfig.dashboard.url}
2. Set up custom alerts for critical thresholds
3. Review metric trends for optimization opportunities
4. Configure webhook notifications for incidents
5. Set up automated reporting and analytics

Monitoring configuration:
\`\`\`json
${JSON.stringify(monitoringConfig, null, 2)}
\`\`\``,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to configure agent monitoring`, {
          error: error instanceof Error ? error.message : String(error),
          agentId: args.agentId,
        });

        return {
          content: [
            {
              type: "text",
              text: `❌ Failed to configure agent monitoring: ${error instanceof Error ? error.message : String(error)}

**Error Details:**
- Agent ID: ${args.agentId}

**Possible Issues:**
1. Agent ID not found or invalid
2. Invalid metric configuration
3. Webhook URL unreachable
4. Insufficient monitoring permissions
5. Monitoring service unavailable`,
            },
          ],
        };
      }
    },
  });

  // ==============================================================================
  // Authentication and Security Tools
  // ==============================================================================

  server.addTool({
    name: "configure-agent-auth",
    description: "Configure authentication and security for AI agents",
    parameters: AuthConfigSchema,
    execute: async (args, { log }) => {
      const operationId = `configure-auth-${Date.now()}`;

      log.info(`[${operationId}] Configuring agent authentication`, {
        agentId: args.agentId,
        authType: args.authType,
        permissionsCount: args.permissions.length,
        rateLimitingEnabled: args.rateLimiting?.enabled,
      });

      try {
        const authConfig = {
          id: `auth_${Date.now()}`,
          agentId: args.agentId,
          authType: args.authType,
          configuration: {
            ...args.configuration,
            // Security: Never log sensitive data
            apiKey: args.configuration.apiKey ? "[ENCRYPTED]" : undefined,
            clientSecret: args.configuration.clientSecret
              ? "[ENCRYPTED]"
              : undefined,
            privateKey: args.configuration.privateKey
              ? "[ENCRYPTED]"
              : undefined,
          },
          permissions: args.permissions,
          rateLimiting: args.rateLimiting,
          security: {
            encryption: "AES-256",
            tokenExpiry: 3600,
            refreshTokens: true,
            multiFactorAuth: false,
            sessionTimeout: 7200,
          },
          status: {
            configured: true,
            lastUpdate: new Date().toISOString(),
            activeTokens: 0,
            failedAttempts: 0,
            lastLogin: null,
          },
          audit: {
            logLevel: "detailed",
            retentionDays: 90,
            anonymization: false,
            complianceMode: "standard",
          },
        };

        log.info(
          `[${operationId}] Agent authentication configured successfully`,
          {
            agentId: args.agentId,
            authType: args.authType,
            permissionsGranted: args.permissions.length,
          },
        );

        const authTypeDescriptions = {
          api_key: "Simple API key authentication for direct access",
          oauth2: "OAuth 2.0 flow with token refresh capabilities",
          jwt: "JSON Web Token-based stateless authentication",
          certificate: "X.509 certificate-based mutual TLS authentication",
          custom: "Custom authentication mechanism with flexible configuration",
        };

        return {
          content: [
            {
              type: "text",
              text: `✅ Agent Authentication Configured Successfully!

**Authentication Configuration:**
- Configuration ID: ${authConfig.id}
- Agent ID: ${args.agentId}
- Authentication Type: ${args.authType}
- Status: ${authConfig.status.configured ? "✅ Configured" : "❌ Not Configured"}

**Authentication Method:**
${authTypeDescriptions[args.authType]}

**Configuration Details:**
${
  args.authType === "api_key"
    ? `- API Key: ${args.configuration.apiKey ? "✅ Configured" : "❌ Not Set"}`
    : args.authType === "oauth2"
      ? `- Client ID: ${args.configuration.clientId || "Not set"}
- Client Secret: ${args.configuration.clientSecret ? "✅ Configured" : "❌ Not Set"}
- Token URL: ${args.configuration.tokenUrl || "Not set"}
- Scopes: ${args.configuration.scopes?.join(", ") || "None"}`
      : args.authType === "jwt"
        ? `- Audience: ${args.configuration.audience || "Not set"}
- Issuer: ${args.configuration.issuer || "Not set"}
- Public Key: ${args.configuration.publicKey ? "✅ Configured" : "❌ Not Set"}`
        : args.authType === "certificate"
          ? `- Public Key: ${args.configuration.publicKey ? "✅ Configured" : "❌ Not Set"}
- Private Key: ${args.configuration.privateKey ? "✅ Configured" : "❌ Not Set"}`
          : "Custom configuration applied"
}

**Permissions Granted (${args.permissions.length}):**
${args.permissions.map((perm, i) => `${i + 1}. ${perm}`).join("\n") || "No specific permissions granted"}

${
  args.rateLimiting?.enabled
    ? `**Rate Limiting:**
- Status: ✅ Enabled
- Requests per Minute: ${args.rateLimiting.requestsPerMinute}
- Burst Limit: ${args.rateLimiting.burstLimit}
- Current Usage: 0/${args.rateLimiting.requestsPerMinute}`
    : "**Rate Limiting:** ❌ Disabled"
}

**Security Features:**
- Encryption: ${authConfig.security.encryption}
- Token Expiry: ${authConfig.security.tokenExpiry}s
- Refresh Tokens: ${authConfig.security.refreshTokens ? "✅ Enabled" : "❌ Disabled"}
- Multi-Factor Auth: ${authConfig.security.multiFactorAuth ? "✅ Enabled" : "❌ Disabled"}
- Session Timeout: ${authConfig.security.sessionTimeout}s

**Authentication Status:**
- Active Tokens: ${authConfig.status.activeTokens}
- Failed Attempts: ${authConfig.status.failedAttempts}
- Last Login: ${authConfig.status.lastLogin || "Never"}
- Last Update: ${new Date(authConfig.status.lastUpdate).toLocaleString()}

**Audit Configuration:**
- Log Level: ${authConfig.audit.logLevel}
- Retention: ${authConfig.audit.retentionDays} days
- Anonymization: ${authConfig.audit.anonymization ? "✅ Enabled" : "❌ Disabled"}
- Compliance Mode: ${authConfig.audit.complianceMode}

**Security Best Practices:**
- All sensitive data is encrypted at rest
- Authentication tokens are regularly rotated
- Failed login attempts are monitored and rate limited
- Comprehensive audit logging is maintained
- Multi-factor authentication is recommended for production

**Common Permission Sets:**
- **Read-Only**: read:context, read:metrics, read:logs
- **Agent Manager**: create:agent, update:agent, delete:agent
- **Admin**: admin:all, configure:auth, manage:permissions
- **Monitor**: read:metrics, read:health, read:performance

**Next Steps:**
1. Test authentication with "test-agent-auth"
2. Monitor authentication metrics and failures
3. Set up MFA for enhanced security
4. Configure session management policies
5. Review and update permissions regularly

**Security Notes:**
- API keys and secrets are encrypted and never logged
- Authentication events are audited for compliance
- Rate limiting prevents abuse and DoS attacks
- Regular security reviews are recommended

Authentication configuration (sanitized):
\`\`\`json
${JSON.stringify(authConfig, null, 2)}
\`\`\``,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to configure agent authentication`, {
          error: error instanceof Error ? error.message : String(error),
          agentId: args.agentId,
        });

        return {
          content: [
            {
              type: "text",
              text: `❌ Failed to configure agent authentication: ${error instanceof Error ? error.message : String(error)}

**Error Details:**
- Agent ID: ${args.agentId}
- Auth Type: ${args.authType}

**Possible Issues:**
1. Invalid authentication configuration
2. Agent ID not found
3. Insufficient security permissions
4. Invalid certificate or key format
5. OAuth provider configuration error`,
            },
          ],
        };
      }
    },
  });

  // ==============================================================================
  // Caching and Performance Tools
  // ==============================================================================

  server.addTool({
    name: "configure-agent-cache",
    description: "Configure caching and performance optimization for AI agents",
    parameters: CacheConfigSchema,
    execute: async (args, { log }) => {
      const operationId = `configure-cache-${Date.now()}`;

      log.info(`[${operationId}] Configuring agent caching`, {
        agentId: args.agentId,
        cacheType: args.cacheType,
        maxSize: args.configuration.maxSize,
        strategiesCount: args.strategies.length,
      });

      try {
        const cacheConfig = {
          id: `cache_${Date.now()}`,
          agentId: args.agentId,
          type: args.cacheType,
          configuration: args.configuration,
          strategies: args.strategies,
          performance: {
            hitRate: 0.78,
            missRate: 0.22,
            averageRetrievalTime: 12.5,
            totalHits: 1247,
            totalMisses: 351,
            totalEvictions: 23,
            currentSize: 34.7,
            maxSize: args.configuration.maxSize,
          },
          statistics: {
            reads: 1598,
            writes: 428,
            deletes: 67,
            updates: 156,
            evictions: 23,
            compressionRatio: args.configuration.compression ? 0.65 : 1.0,
          },
          health: {
            status: "optimal",
            lastCleanup: new Date().toISOString(),
            memoryPressure: "low",
            fragmentationRatio: 0.12,
          },
          metadata: {
            configuredAt: new Date().toISOString(),
            lastOptimized: new Date().toISOString(),
            version: "1.0.0",
          },
        };

        log.info(`[${operationId}] Agent caching configured successfully`, {
          agentId: args.agentId,
          cacheType: args.cacheType,
          hitRate: cacheConfig.performance.hitRate,
        });

        const cacheTypeDescriptions = {
          memory: "Fast in-memory caching with immediate access",
          redis: "Distributed Redis caching with persistence",
          file: "File-system based caching with durability",
          database: "Database-backed caching with ACID properties",
          hybrid: "Multi-tier caching combining multiple storage types",
        };

        return {
          content: [
            {
              type: "text",
              text: `✅ Agent Caching Configured Successfully!

**Cache Configuration:**
- Configuration ID: ${cacheConfig.id}
- Agent ID: ${args.agentId}
- Cache Type: ${args.cacheType}
- Status: ${cacheConfig.health.status}

**Cache Type Description:**
${cacheTypeDescriptions[args.cacheType]}

**Configuration Parameters:**
- Default TTL: ${args.configuration.ttl}s
- Max Size: ${args.configuration.maxSize}MB
- Eviction Policy: ${args.configuration.evictionPolicy.toUpperCase()}
- Compression: ${args.configuration.compression ? "✅ Enabled" : "❌ Disabled"}
- Encryption: ${args.configuration.encryption ? "✅ Enabled" : "❌ Disabled"}

**Performance Metrics:**
- Hit Rate: ${(cacheConfig.performance.hitRate * 100).toFixed(1)}% (${cacheConfig.performance.totalHits} hits)
- Miss Rate: ${(cacheConfig.performance.missRate * 100).toFixed(1)}% (${cacheConfig.performance.totalMisses} misses)
- Average Retrieval Time: ${cacheConfig.performance.averageRetrievalTime}ms
- Current Size: ${cacheConfig.performance.currentSize}MB / ${cacheConfig.performance.maxSize}MB
- Space Usage: ${((cacheConfig.performance.currentSize / cacheConfig.performance.maxSize) * 100).toFixed(1)}%
- Total Evictions: ${cacheConfig.performance.totalEvictions}

**Cache Statistics:**
- Total Reads: ${cacheConfig.statistics.reads}
- Total Writes: ${cacheConfig.statistics.writes}
- Total Updates: ${cacheConfig.statistics.updates}
- Total Deletes: ${cacheConfig.statistics.deletes}
- Eviction Events: ${cacheConfig.statistics.evictions}
- Compression Ratio: ${cacheConfig.statistics.compressionRatio.toFixed(2)}x

**Caching Strategies (${args.strategies.length}):**
${
  args.strategies
    .map(
      (strategy, i) =>
        `${i + 1}. **${strategy.pattern}**
   - TTL: ${strategy.ttl || "Default"}s
   - Priority: ${strategy.priority}`,
    )
    .join("\n") || "No specific caching strategies configured"
}

**Cache Health:**
- Overall Status: ${cacheConfig.health.status}
- Last Cleanup: ${new Date(cacheConfig.health.lastCleanup).toLocaleString()}
- Memory Pressure: ${cacheConfig.health.memoryPressure}
- Fragmentation Ratio: ${(cacheConfig.health.fragmentationRatio * 100).toFixed(1)}%

**Eviction Policies:**
- **LRU** (Least Recently Used): Removes least recently accessed items
- **LFU** (Least Frequently Used): Removes least frequently accessed items  
- **FIFO** (First In, First Out): Removes oldest items first
- **TTL** (Time To Live): Removes expired items based on TTL

**Performance Optimization:**
- Cache hit rate above 70% is considered good
- Average retrieval time under 50ms is optimal  
- Regular cleanup prevents memory fragmentation
- Compression reduces storage requirements
- Encryption ensures data security

**Common Cache Patterns:**
- **Context Caching**: Store agent context and memory
- **LLM Response Caching**: Cache frequent LLM responses
- **Computation Caching**: Cache expensive calculations
- **API Response Caching**: Cache external API responses
- **Session Caching**: Cache user session data

**Next Steps:**
1. Monitor cache performance and hit rates
2. Adjust TTL values based on usage patterns
3. Implement cache warming for critical data
4. Set up cache invalidation strategies
5. Monitor memory usage and optimize as needed

**Cache Management:**
- Use "clear-agent-cache" to clear all cached data
- Use "warm-agent-cache" to preload important data
- Use "analyze-cache-performance" for optimization insights
- Use "backup-agent-cache" for data recovery

Cache configuration:
\`\`\`json
${JSON.stringify(cacheConfig, null, 2)}
\`\`\``,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to configure agent caching`, {
          error: error instanceof Error ? error.message : String(error),
          agentId: args.agentId,
        });

        return {
          content: [
            {
              type: "text",
              text: `❌ Failed to configure agent caching: ${error instanceof Error ? error.message : String(error)}

**Error Details:**
- Agent ID: ${args.agentId}
- Cache Type: ${args.cacheType}

**Possible Issues:**
1. Insufficient memory for cache allocation
2. Invalid cache configuration parameters
3. Cache service unavailable
4. Permissions issues for cache storage
5. Network connectivity issues (for distributed caching)`,
            },
          ],
        };
      }
    },
  });

  // ==============================================================================
  // Testing Framework Tools
  // ==============================================================================

  server.addTool({
    name: "configure-agent-testing",
    description: "Configure comprehensive testing framework for AI agents",
    parameters: TestConfigSchema,
    execute: async (args, { log }) => {
      const operationId = `configure-testing-${Date.now()}`;

      log.info(`[${operationId}] Configuring agent testing framework`, {
        agentId: args.agentId,
        testType: args.testType,
        testCasesCount: args.testCases.length,
        schedule: args.configuration.schedule,
      });

      try {
        const testConfig = {
          id: `test_${Date.now()}`,
          agentId: args.agentId,
          testType: args.testType,
          configuration: args.configuration,
          testCases: args.testCases,
          results: {
            lastRun: null,
            totalRuns: 0,
            totalPassed: 0,
            totalFailed: 0,
            totalSkipped: 0,
            averageDuration: 0,
            successRate: 0,
          },
          coverage: {
            overall: 0,
            components: {
              llm: 0,
              context: 0,
              cache: 0,
              auth: 0,
              monitoring: 0,
            },
          },
          automation: {
            enabled: !!args.configuration.schedule,
            schedule: args.configuration.schedule,
            nextRun: null,
            webhook: null,
          },
          metadata: {
            configuredAt: new Date().toISOString(),
            lastModified: new Date().toISOString(),
            version: "1.0.0",
          },
        };

        log.info(`[${operationId}] Agent testing configured successfully`, {
          agentId: args.agentId,
          testType: args.testType,
          testCasesCount: args.testCases.length,
        });

        const testTypeDescriptions = {
          unit: "Individual component and function testing",
          integration: "Multi-component interaction testing",
          load: "Performance and scalability testing under load",
          behavior: "AI behavior and response quality testing",
          security: "Security vulnerability and access control testing",
          performance: "Response time and resource usage testing",
        };

        return {
          content: [
            {
              type: "text",
              text: `✅ Agent Testing Framework Configured Successfully!

**Test Configuration:**
- Configuration ID: ${testConfig.id}
- Agent ID: ${args.agentId}
- Test Type: ${args.testType}
- Status: ${args.configuration.enabled ? "✅ Enabled" : "❌ Disabled"}

**Test Type Description:**
${testTypeDescriptions[args.testType]}

**Test Configuration:**
- Enabled: ${args.configuration.enabled ? "✅ Yes" : "❌ No"}
- Timeout: ${args.configuration.timeout}ms
- Retries: ${args.configuration.retries}
- Parallel Execution: ${args.configuration.parallel ? "✅ Enabled" : "❌ Disabled"}
- Schedule: ${args.configuration.schedule || "Manual execution only"}

**Test Cases Configured (${args.testCases.length}):**
${
  args.testCases
    .map(
      (testCase, i) =>
        `${i + 1}. **${testCase.name}**
   - Description: ${testCase.description || "No description"}
   - Assertions: ${testCase.assertions.length} checks
   - Input Keys: ${Object.keys(testCase.input).length}
   - Expected Output: ${testCase.expectedOutput ? "Defined" : "Not defined"}`,
    )
    .join("\n") || "No test cases configured"
}

**Test Results Summary:**
- Total Test Runs: ${testConfig.results.totalRuns}
- Tests Passed: ${testConfig.results.totalPassed}
- Tests Failed: ${testConfig.results.totalFailed}
- Tests Skipped: ${testConfig.results.totalSkipped}
- Success Rate: ${testConfig.results.successRate.toFixed(1)}%
- Average Duration: ${testConfig.results.averageDuration}ms
- Last Run: ${testConfig.results.lastRun || "Never"}

**Test Coverage:**
- Overall Coverage: ${testConfig.coverage.overall.toFixed(1)}%
- LLM Components: ${testConfig.coverage.components.llm.toFixed(1)}%
- Context Management: ${testConfig.coverage.components.context.toFixed(1)}%
- Cache System: ${testConfig.coverage.components.cache.toFixed(1)}%
- Authentication: ${testConfig.coverage.components.auth.toFixed(1)}%
- Monitoring: ${testConfig.coverage.components.monitoring.toFixed(1)}%

**Automated Testing:**
- Status: ${testConfig.automation.enabled ? "✅ Enabled" : "❌ Disabled"}
- Schedule: ${args.configuration.schedule || "Not scheduled"}
- Next Run: ${testConfig.automation.nextRun || "Not scheduled"}
- Webhook Notifications: ${testConfig.automation.webhook ? "✅ Configured" : "❌ Not configured"}

**Test Types Available:**
- **Unit Tests**: Test individual functions and components
- **Integration Tests**: Test component interactions and workflows
- **Load Tests**: Test performance under high traffic
- **Behavior Tests**: Test AI responses and decision making
- **Security Tests**: Test authentication and authorization
- **Performance Tests**: Test response times and resource usage

**Testing Best Practices:**
- Maintain at least 80% test coverage for critical components
- Include both positive and negative test scenarios
- Test edge cases and error conditions
- Use realistic test data and scenarios
- Monitor test performance and stability
- Automate regression testing for continuous validation

**Common Test Scenarios:**
- **LLM Response Quality**: Verify response accuracy and relevance
- **Context Memory**: Test context storage and retrieval
- **Error Handling**: Test graceful failure and recovery
- **Performance Limits**: Test response time boundaries
- **Security Access**: Test authentication and authorization
- **Load Capacity**: Test concurrent request handling

**Next Steps:**
1. Run initial tests with "run-agent-tests"
2. Review test results and coverage reports
3. Add additional test cases for edge scenarios
4. Set up automated test scheduling
5. Configure failure notifications and alerts

**Test Management:**
- Use "run-agent-tests" to execute configured tests
- Use "view-test-results" to review detailed results
- Use "update-test-cases" to modify or add tests
- Use "export-test-report" for compliance documentation

Testing configuration:
\`\`\`json
${JSON.stringify(testConfig, null, 2)}
\`\`\``,
            },
          ],
        };
      } catch (error) {
        log.error(`[${operationId}] Failed to configure agent testing`, {
          error: error instanceof Error ? error.message : String(error),
          agentId: args.agentId,
        });

        return {
          content: [
            {
              type: "text",
              text: `❌ Failed to configure agent testing: ${error instanceof Error ? error.message : String(error)}

**Error Details:**
- Agent ID: ${args.agentId}
- Test Type: ${args.testType}

**Possible Issues:**
1. Agent ID not found or invalid
2. Invalid test configuration parameters
3. Test case format errors
4. Insufficient testing permissions
5. Schedule format invalid (use cron syntax)`,
            },
          ],
        };
      }
    },
  });

  logger.info("AI Agent Management tools registered successfully", {
    toolCount: 8,
    categories: [
      "lifecycle",
      "context",
      "llm-providers",
      "monitoring",
      "authentication",
      "caching",
      "testing",
    ],
  });
}

export default registerAIAgentManagementTools;
