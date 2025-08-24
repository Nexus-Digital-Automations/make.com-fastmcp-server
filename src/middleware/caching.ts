/**
 * Caching middleware for FastMCP server with intelligent response caching
 * Integrates with Redis cache and provides automatic cache management for API responses
 */

import { FastMCP } from "fastmcp";
import { z } from "zod";
import RedisCache, { CacheConfig, defaultCacheConfig } from "../lib/cache.js";
import logger from "../lib/logger.js";
import metrics from "../lib/metrics.js";

// Enhanced TypeScript interfaces for type safety
export interface FastMCPToolConfig<TParams extends z.ZodSchema, TResult> {
  name: string;
  description: string;
  parameters: TParams;
  annotations?: ToolAnnotations;
  execute: (
    args: z.infer<TParams>,
    context?: ToolExecutionContext,
  ) => Promise<TResult>;
}

export interface ToolExecutionContext {
  requestId?: string;
  metadata?: Record<string, unknown>;
  auth?: AuthContext;
  [key: string]: unknown;
}

export interface AuthContext {
  userId?: string;
  role?: string;
  permissions?: string[];
  token?: string;
}

export interface ToolAnnotations {
  title?: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

// Enhanced response type interfaces
export interface CacheableApiResponse<TData = unknown> {
  success: boolean;
  data?: TData;
  error?: ApiError;
  metadata?: ResponseMetadata;
}

export interface ApiError {
  message: string;
  code?: string;
  details?: Record<string, unknown>;
}

export interface ResponseMetadata {
  timestamp: string;
  requestId?: string;
  version?: string;
  cached?: boolean;
  cacheKey?: string;
}

export interface SuccessResponse<TData> extends CacheableApiResponse<TData> {
  success: true;
  data: TData;
}

export interface ErrorResponse extends CacheableApiResponse<never> {
  success: false;
  error: ApiError;
}

// Enhanced operation context
export interface OperationContext {
  toolContext?: ToolExecutionContext;
  requestMetadata?: Record<string, unknown>;
  cacheHint?: CacheHint;
  [key: string]: unknown;
}

export interface CacheHint {
  forceRefresh?: boolean;
  customTtl?: number;
  additionalTags?: string[];
}

// Type guards for runtime validation
export function isCacheableResponse<T>(
  response: unknown,
): response is CacheableApiResponse<T> {
  return (
    typeof response === "object" &&
    response !== null &&
    "success" in response &&
    typeof (response as CacheableApiResponse).success === "boolean"
  );
}

export function isSuccessResponse<T>(
  response: CacheableApiResponse<T>,
): response is SuccessResponse<T> {
  return response.success === true && response.data !== undefined;
}

export function isErrorResponse<T>(
  response: CacheableApiResponse<T>,
): response is ErrorResponse {
  return response.success === false && response.error !== undefined;
}

export function isToolExecutionContext(
  context: unknown,
): context is ToolExecutionContext {
  return (
    typeof context === "object" &&
    context !== null &&
    ((context as ToolExecutionContext).requestId === undefined ||
      typeof (context as ToolExecutionContext).requestId === "string")
  );
}

export interface CachingMiddlewareConfig {
  cache: CacheConfig;
  strategies: {
    [operation: string]: CacheStrategy;
  };
  defaultStrategy: CacheStrategy;
  enableConditionalCaching: boolean;
  enableEtagSupport: boolean;
  toolWrapping: {
    enabled: boolean;
    mode: "all" | "selective" | "explicit";
    includedTools?: string[];
    excludedTools?: string[];
    defaultEnabled: boolean;
  };
}

// Enhanced cache strategy with better typing
export interface CacheStrategy<
  TParams = Record<string, unknown>,
  TResponse = CacheableApiResponse,
> {
  enabled: boolean;
  ttl: number;
  tags: string[];
  keyGenerator?: (
    operation: string,
    params: TParams,
    context?: OperationContext,
  ) => string;
  shouldCache?: (
    operation: string,
    params: TParams,
    response: TResponse,
  ) => boolean;
  invalidateOn?: string[];

  // Advanced typing features
  responseValidator?: (response: unknown) => response is TResponse;
  parameterSchema?: z.ZodSchema<TParams>;
}

export interface CachedResponse<T = unknown> {
  data: T;
  etag: string;
  timestamp: number;
  operation: string;
  params: Record<string, unknown>;
}

export class CachingMiddleware {
  private readonly cache: RedisCache;
  private readonly config: CachingMiddlewareConfig;
  private readonly componentLogger: ReturnType<typeof logger.child>;
  private readonly operationMetrics = new Map<
    string,
    { hits: number; misses: number; errors: number }
  >();
  private server?: FastMCP;

  constructor(config?: Partial<CachingMiddlewareConfig>) {
    this.config = {
      cache: defaultCacheConfig,
      strategies: {
        // Scenario operations - medium TTL, scenario tags
        list_scenarios: {
          enabled: true,
          ttl: 1800, // 30 minutes
          tags: ["scenarios"],
          invalidateOn: [
            "scenario:create",
            "scenario:update",
            "scenario:delete",
          ],
        },
        get_scenario: {
          enabled: true,
          ttl: 3600, // 1 hour
          tags: ["scenarios"],
          invalidateOn: ["scenario:update", "scenario:delete"],
        },

        // User operations - short TTL due to permissions
        list_users: {
          enabled: true,
          ttl: 900, // 15 minutes
          tags: ["users"],
          invalidateOn: ["user:update", "user:create", "user:delete"],
        },
        get_user: {
          enabled: true,
          ttl: 1800, // 30 minutes
          tags: ["users"],
          invalidateOn: ["user:update", "user:delete"],
        },

        // Analytics - very short TTL due to frequent updates
        get_analytics: {
          enabled: true,
          ttl: 300, // 5 minutes
          tags: ["analytics"],
          invalidateOn: ["scenario:execute", "data:update"],
        },
        get_execution_history: {
          enabled: true,
          ttl: 600, // 10 minutes
          tags: ["analytics", "executions"],
          invalidateOn: ["scenario:execute"],
        },

        // Connection operations - medium TTL
        list_connections: {
          enabled: true,
          ttl: 1800, // 30 minutes
          tags: ["connections"],
          invalidateOn: [
            "connection:create",
            "connection:update",
            "connection:delete",
          ],
        },
        get_connection: {
          enabled: true,
          ttl: 3600, // 1 hour
          tags: ["connections"],
          invalidateOn: ["connection:update", "connection:delete"],
        },

        // Template operations - long TTL, rarely change
        list_templates: {
          enabled: true,
          ttl: 7200, // 2 hours
          tags: ["templates"],
          invalidateOn: [
            "template:create",
            "template:update",
            "template:delete",
          ],
        },
        get_template: {
          enabled: true,
          ttl: 14400, // 4 hours
          tags: ["templates"],
          invalidateOn: ["template:update", "template:delete"],
        },

        // Organization/team operations - medium TTL
        list_organizations: {
          enabled: true,
          ttl: 3600, // 1 hour
          tags: ["organizations"],
          invalidateOn: ["org:update", "team:update"],
        },
        list_teams: {
          enabled: true,
          ttl: 1800, // 30 minutes
          tags: ["teams"],
          invalidateOn: ["team:create", "team:update", "team:delete"],
        },
      },
      defaultStrategy: {
        enabled: true,
        ttl: 1800, // 30 minutes default
        tags: ["default"],
        invalidateOn: [],
      },
      enableConditionalCaching: true,
      enableEtagSupport: true,
      toolWrapping: {
        enabled: true,
        mode: "selective",
        excludedTools: ["cache-status", "cache-invalidate", "cache-warmup"], // Don't cache cache management tools
        defaultEnabled: true,
      },
      ...config,
    };

    this.componentLogger = logger.child({ component: "CachingMiddleware" });
    this.cache = new RedisCache(this.config.cache);
    this.initializeMetrics();
  }

  /**
   * Initialize cache metrics tracking
   */
  private initializeMetrics(): void {
    // Initialize metrics for each operation strategy
    Object.keys(this.config.strategies).forEach((operation) => {
      this.operationMetrics.set(operation, { hits: 0, misses: 0, errors: 0 });
    });
  }

  /**
   * Apply caching middleware to FastMCP server
   */
  public apply(server: FastMCP): void {
    this.componentLogger.info("Applying caching middleware to FastMCP server");

    // Store server reference for cache management tools
    this.server = server;

    // Wrap tool execution with caching
    this.wrapServerTools();

    // Add cache management tools
    this.addCacheManagementTools();

    this.componentLogger.info("Caching middleware applied successfully");
  }

  /**
   * Wrap existing tools with caching logic using registration interception
   */
  private wrapServerTools(): void {
    if (!this.config.toolWrapping.enabled || !this.server) {
      this.componentLogger.info(
        "Tool wrapping disabled or server not available",
      );
      return;
    }

    this.componentLogger.info("Enabling automatic tool wrapping with caching", {
      mode: this.config.toolWrapping.mode,
      excludedTools: this.config.toolWrapping.excludedTools?.length || 0,
    });

    // Store original addTool method
    const originalAddTool = this.server.addTool.bind(this.server);

    // Replace with caching-aware version using registration interception pattern
    this.server.addTool = (<
      TParams extends z.ZodSchema,
      TResult extends CacheableApiResponse,
    >(
      toolConfig: FastMCPToolConfig<TParams, TResult>,
    ) => {
      if (this.shouldWrapTool(toolConfig.name)) {
        const wrappedTool = this.createCachedTool(toolConfig);
        this.componentLogger.debug("Tool wrapped with caching", {
          toolName: toolConfig.name,
        });
        return originalAddTool(wrappedTool);
      } else {
        this.componentLogger.debug("Tool not wrapped - excluded or disabled", {
          toolName: toolConfig.name,
        });
        return originalAddTool(toolConfig);
      }
    }) as typeof this.server.addTool;

    this.componentLogger.info(
      "Tool wrapping interception enabled successfully",
    );
  }

  /**
   * Add cache management tools to server
   */
  private addCacheManagementTools(): void {
    if (!this.server || typeof this.server.addTool !== "function") {
      this.componentLogger.error(
        "FastMCP server not available for cache tool registration",
      );
      return;
    }

    this.componentLogger.info(
      "Registering cache management tools with FastMCP server",
    );

    // Cache status tool
    this.server.addTool({
      name: "cache-status",
      description: "Get cache system status and statistics",
      annotations: {
        title: "Cache Status",
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
      parameters: z.object({}),
      execute: async () => {
        try {
          const stats = await this.cache.getStats();
          const health = await this.cache.healthCheck();
          const operationStats = Object.fromEntries(this.operationMetrics);

          const result = {
            success: true,
            data: {
              health,
              stats,
              operationStats,
              strategies: Object.keys(this.config.strategies),
              config: {
                compression: this.config.cache.compression,
                ttl: this.config.cache.ttl,
              },
            },
            timestamp: new Date().toISOString(),
          };

          return JSON.stringify(result, null, 2);
        } catch (error) {
          const result = {
            success: false,
            error: {
              message: "Failed to get cache status",
              details: error instanceof Error ? error.message : "Unknown error",
            },
            timestamp: new Date().toISOString(),
          };

          return JSON.stringify(result, null, 2);
        }
      },
    });

    // Cache invalidation tool
    this.server.addTool({
      name: "cache-invalidate",
      description: "Invalidate cache entries based on trigger patterns",
      annotations: {
        title: "Cache Invalidate",
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: false,
      },
      parameters: z.object({
        trigger: z
          .string()
          .min(1)
          .describe("Invalidation trigger (e.g., scenario:update)"),
        context: z
          .record(z.string(), z.string())
          .optional()
          .describe("Optional context for pattern expansion"),
      }),
      execute: async (args) => {
        try {
          const { trigger, context } = args;
          const deletedCount = await this.cache.invalidate(trigger, context);

          this.componentLogger.info("Cache invalidated via tool", {
            trigger,
            deletedCount,
          });

          const result = {
            success: true,
            data: {
              trigger,
              deletedCount,
              timestamp: new Date().toISOString(),
            },
          };

          return JSON.stringify(result, null, 2);
        } catch (error) {
          const result = {
            success: false,
            error: {
              message: "Failed to invalidate cache",
              details: error instanceof Error ? error.message : "Unknown error",
            },
            timestamp: new Date().toISOString(),
          };

          return JSON.stringify(result, null, 2);
        }
      },
    });

    // Cache warm-up tool
    this.server.addTool({
      name: "cache-warmup",
      description: "Warm up cache with predefined data sets",
      annotations: {
        title: "Cache Warmup",
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
      parameters: z.object({
        operations: z
          .array(z.string())
          .optional()
          .describe(
            'List of operations to warm up (e.g., ["list_scenarios", "list_users"])',
          ),
      }),
      execute: async (args) => {
        try {
          const operations =
            args.operations || Object.keys(this.config.strategies);
          const warmupData = await this.generateWarmupData(operations);
          const successCount = await this.cache.warmUp(warmupData);

          const result = {
            success: true,
            data: {
              operations,
              totalItems: warmupData.length,
              successfulItems: successCount,
              timestamp: new Date().toISOString(),
            },
          };

          return JSON.stringify(result, null, 2);
        } catch (error) {
          const result = {
            success: false,
            error: {
              message: "Failed to warm up cache",
              details: error instanceof Error ? error.message : "Unknown error",
            },
            timestamp: new Date().toISOString(),
          };

          return JSON.stringify(result, null, 2);
        }
      },
    });

    this.componentLogger.info(
      "Cache management tools registered successfully",
      {
        tools: ["cache-status", "cache-invalidate", "cache-warmup"],
      },
    );
  }

  /**
   * Determine if a tool should be wrapped with caching based on configuration
   */
  private shouldWrapTool(toolName: string): boolean {
    const config = this.config.toolWrapping;

    if (!config.enabled) {
      return false;
    }

    // Check excluded tools first
    if (config.excludedTools?.includes(toolName)) {
      return false;
    }

    // Check mode-specific logic
    switch (config.mode) {
      case "all":
        return true;
      case "selective":
        // If includedTools is specified, only wrap those tools
        if (config.includedTools?.length) {
          return config.includedTools.includes(toolName);
        }
        // Otherwise use default enabled setting
        return config.defaultEnabled;
      case "explicit":
        // Only wrap tools explicitly listed in includedTools
        return config.includedTools?.includes(toolName) || false;
      default:
        return config.defaultEnabled;
    }
  }

  /**
   * Create a cached version of a tool by wrapping its execute function
   */
  private createCachedTool<
    TParams extends z.ZodSchema,
    TResult extends CacheableApiResponse,
  >(
    toolConfig: FastMCPToolConfig<TParams, TResult>,
  ): FastMCPToolConfig<TParams, TResult> {
    const originalExecute = toolConfig.execute;
    const toolName = toolConfig.name;

    // Get caching strategy for this tool
    const strategy = this.getToolStrategy(toolName);

    return {
      ...toolConfig,
      execute: async (
        args: z.infer<TParams>,
        context?: ToolExecutionContext,
      ): Promise<TResult> => {
        // Apply caching strategy based on tool name and configuration
        if (!strategy.enabled) {
          // Strategy disabled, execute without caching
          return originalExecute(args, context);
        }

        try {
          // Use existing wrapWithCache method for consistent caching behavior
          return await this.wrapWithCache(
            toolName,
            args as Record<string, unknown>,
            () => originalExecute(args, context),
            { toolContext: context },
          );
        } catch (error) {
          // On caching error, fallback to direct execution
          this.componentLogger.error(
            "Cache wrapper error, falling back to direct execution",
            {
              toolName,
              error: error instanceof Error ? error.message : "Unknown error",
            },
          );
          return originalExecute(args, context);
        }
      },
    };
  }

  /**
   * Get caching strategy for a specific tool
   */
  private getToolStrategy(toolName: string): CacheStrategy {
    // Check for tool-specific strategy first
    if (this.config.strategies[toolName]) {
      return this.config.strategies[toolName];
    }

    // Map common tool naming patterns to existing strategies
    const strategyMappings: Record<string, string> = {
      "list-scenarios": "list_scenarios",
      "get-scenario": "get_scenario",
      "list-users": "list_users",
      "get-user": "get_user",
      "list-connections": "list_connections",
      "get-connection": "get_connection",
      "list-templates": "list_templates",
      "get-template": "get_template",
      "list-organizations": "list_organizations",
      "list-teams": "list_teams",
      "get-analytics": "get_analytics",
      "get-execution-history": "get_execution_history",
    };

    const mappedStrategy = strategyMappings[toolName];
    if (mappedStrategy && this.config.strategies[mappedStrategy]) {
      return this.config.strategies[mappedStrategy];
    }

    // Fall back to default strategy
    return this.config.defaultStrategy;
  }

  /**
   * Wrap operation with caching logic
   */
  public async wrapWithCache<T extends CacheableApiResponse>(
    operation: string,
    params: Record<string, unknown>,
    executor: () => Promise<T>,
    context?: OperationContext,
  ): Promise<T> {
    const strategy =
      this.config.strategies[operation] || this.config.defaultStrategy;

    if (!strategy.enabled) {
      return executor();
    }

    const startTime = Date.now();
    const cacheKey = this.generateCacheKey(
      operation,
      params,
      context,
      strategy,
    );

    try {
      // Try to get from cache
      const cached = await this.cache.get<CachedResponse<T>>(cacheKey);

      if (cached && this.isCacheValid(cached, strategy)) {
        this.recordCacheHit(operation, Date.now() - startTime);

        this.componentLogger.debug("Cache hit", {
          operation,
          cacheKey,
          age: Date.now() - cached.timestamp,
        });

        return cached.data;
      }

      // Cache miss - execute operation
      const result = await executor();

      // Check if response should be cached
      if (this.shouldCacheResponse(operation, params, result, strategy)) {
        const cachedResponse: CachedResponse<T> = {
          data: result,
          etag: this.generateEtag(result),
          timestamp: Date.now(),
          operation,
          params,
        };

        // Store in cache with strategy TTL and tags
        await this.cache.set(
          cacheKey,
          cachedResponse,
          strategy.ttl,
          strategy.tags,
        );

        this.componentLogger.debug("Cached response", {
          operation,
          cacheKey,
          ttl: strategy.ttl,
          tags: strategy.tags,
        });
      }

      this.recordCacheMiss(operation, Date.now() - startTime);
      return result;
    } catch (error) {
      this.recordCacheError(operation);
      this.componentLogger.error("Cache operation error", {
        operation,
        cacheKey,
        error: error instanceof Error ? error.message : "Unknown error",
      });

      // Execute operation without caching on cache error
      return executor();
    }
  }

  /**
   * Generate cache key for operation
   */
  private generateCacheKey(
    operation: string,
    params: Record<string, unknown>,
    context?: Record<string, unknown>,
    strategy?: CacheStrategy,
  ): string {
    if (strategy?.keyGenerator) {
      return strategy.keyGenerator(operation, params, context);
    }

    // Default key generation
    const paramsHash = this.hashParams(params);
    const contextStr = context ? `:${this.hashParams(context)}` : "";

    return this.cache.generateKey(
      "operation",
      `${operation}:${paramsHash}${contextStr}`,
    );
  }

  /**
   * Generate hash for parameters
   */
  private hashParams(params: Record<string, unknown>): string {
    const sorted = Object.entries(params)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
      .join("&");

    return Buffer.from(sorted).toString("base64").slice(0, 16);
  }

  /**
   * Check if cached response is still valid
   */
  private isCacheValid<T>(
    cached: CachedResponse<T>,
    strategy: CacheStrategy,
  ): boolean {
    if (!this.config.enableConditionalCaching) {
      return true;
    }

    const age = Date.now() - cached.timestamp;
    const maxAge = strategy.ttl * 1000;

    return age < maxAge;
  }

  /**
   * Determine if response should be cached
   */
  private shouldCacheResponse<T extends CacheableApiResponse>(
    operation: string,
    params: Record<string, unknown>,
    response: T,
    strategy: CacheStrategy,
  ): boolean {
    if (strategy.shouldCache) {
      // Use type guard for safe validation
      if (isCacheableResponse(response)) {
        return strategy.shouldCache(operation, params, response);
      }
      return false;
    }

    // Default caching logic with type guards
    if (isCacheableResponse(response)) {
      // Don't cache error responses
      if (isErrorResponse(response)) {
        return false;
      }

      // Don't cache empty responses
      if (
        response.data &&
        Array.isArray(response.data) &&
        response.data.length === 0
      ) {
        return false;
      }
    }

    return true;
  }

  /**
   * Generate ETag for response
   */
  private generateEtag<T>(data: T): string {
    const content = JSON.stringify(data);
    const hash = Buffer.from(content).toString("base64");
    return `"${hash.slice(0, 16)}"`;
  }

  /**
   * Generate warm-up data for specified operations
   */
  private async generateWarmupData(
    operations: string[],
  ): Promise<Array<{ key: string; data: unknown; ttl?: number }>> {
    const warmupData: Array<{ key: string; data: unknown; ttl?: number }> = [];

    // This would be expanded based on actual application needs
    // For now, we'll generate some common cache keys

    operations.forEach((operation) => {
      const strategy = this.config.strategies[operation];
      if (strategy) {
        // Generate sample cache entries for common parameter combinations
        const sampleParams = this.getSampleParams(operation);
        sampleParams.forEach((params) => {
          const key = this.generateCacheKey(
            operation,
            params,
            undefined,
            strategy,
          );
          warmupData.push({
            key,
            data: { placeholder: true, operation, params }, // Placeholder data
            ttl: strategy.ttl,
          });
        });
      }
    });

    return warmupData;
  }

  /**
   * Get sample parameters for operation warm-up
   */
  private getSampleParams(operation: string): Record<string, unknown>[] {
    const commonParams: Record<string, Record<string, unknown>[]> = {
      list_scenarios: [{ limit: 50 }, { limit: 100 }, { teamId: "default" }],
      list_users: [{ limit: 50 }, { role: "admin" }, { teamId: "default" }],
      list_connections: [{ limit: 50 }, { type: "webhook" }],
      list_templates: [{ category: "automation" }, { limit: 25 }],
    };

    return commonParams[operation] || [{}];
  }

  /**
   * Record cache hit metrics
   */
  private recordCacheHit(operation: string, responseTime: number): void {
    const opMetrics = this.operationMetrics.get(operation);
    if (opMetrics) {
      opMetrics.hits++;
      this.operationMetrics.set(operation, opMetrics);
    }

    metrics.recordCacheHit("operation_cache", { operation });
    metrics.recordToolExecution(operation, "success", responseTime / 1000);
  }

  /**
   * Record cache miss metrics
   */
  private recordCacheMiss(operation: string, responseTime: number): void {
    const opMetrics = this.operationMetrics.get(operation);
    if (opMetrics) {
      opMetrics.misses++;
      this.operationMetrics.set(operation, opMetrics);
    }

    metrics.recordCacheMiss("operation_cache", { operation });
    metrics.recordToolExecution(operation, "success", responseTime / 1000);
  }

  /**
   * Record cache error metrics
   */
  private recordCacheError(operation: string): void {
    const opMetrics = this.operationMetrics.get(operation);
    if (opMetrics) {
      opMetrics.errors++;
      this.operationMetrics.set(operation, opMetrics);
    }

    metrics.recordError("cache", "operation_cache_error", "CachingMiddleware");
  }

  /**
   * Invalidate cache for specific operation patterns
   */
  public async invalidateOperationCache(
    operation: string,
    context?: Record<string, string>,
  ): Promise<number> {
    const strategy = this.config.strategies[operation];
    if (!strategy?.invalidateOn) {
      return 0;
    }

    let totalDeleted = 0;
    for (const trigger of strategy.invalidateOn) {
      const deleted = await this.cache.invalidate(trigger, context);
      totalDeleted += deleted;
    }

    this.componentLogger.info("Operation cache invalidated", {
      operation,
      totalDeleted,
      triggers: strategy.invalidateOn,
    });

    return totalDeleted;
  }

  /**
   * Get cache statistics for specific operations
   */
  public getOperationStats(): Record<
    string,
    { hits: number; misses: number; errors: number; hitRate: number }
  > {
    const stats: Record<
      string,
      { hits: number; misses: number; errors: number; hitRate: number }
    > = {};

    this.operationMetrics.forEach((metrics, operation) => {
      const total = metrics.hits + metrics.misses;
      const hitRate = total > 0 ? metrics.hits / total : 0;

      stats[operation] = {
        ...metrics,
        hitRate: Math.round(hitRate * 10000) / 100, // Percentage with 2 decimal places
      };
    });

    return stats;
  }

  /**
   * Health check for caching middleware
   */
  public async healthCheck(): Promise<{
    healthy: boolean;
    cache: boolean;
    middleware: boolean;
  }> {
    try {
      const cacheHealth = await this.cache.healthCheck();

      return {
        healthy: cacheHealth.healthy,
        cache: cacheHealth.healthy,
        middleware: true,
      };
    } catch (error) {
      this.componentLogger.error(
        "Caching middleware health check failed",
        error as Record<string, unknown>,
      );
      return {
        healthy: false,
        cache: false,
        middleware: false,
      };
    }
  }

  /**
   * Shutdown caching middleware
   */
  public async shutdown(): Promise<void> {
    this.componentLogger.info("Shutting down caching middleware");
    await this.cache.shutdown();
    this.operationMetrics.clear();
  }
}

export default CachingMiddleware;
