/**
 * Enhanced Rate Limit Manager - Phase 3
 * Integrates RateLimitParser for comprehensive header processing and dynamic capacity updates
 */

import { v4 as uuidv4 } from "uuid";
import * as winston from "winston";

// Import base RateLimitManager and its types
import {
  RateLimitManager,
  RateLimitConfig,
  RateLimitInfo as BaseLimitInfo,
  RateLimitError,
} from "./rate-limit-manager.js";

// Import type for delegation methods
type RateLimitMetrics = ReturnType<RateLimitManager["getMetrics"]>;
type QueueStatus = ReturnType<RateLimitManager["getQueueStatus"]>;
import {
  RateLimitParser,
  RateLimitInfo as ParsedRateLimitInfo,
} from "./rate-limiting/rate-limit-parser.js";

// Enhanced configuration interface
export interface EnhancedRateLimitConfig extends RateLimitConfig {
  // RateLimitParser specific configuration
  headerParsingEnabled?: boolean; // Default true - parse rate limit headers
  dynamicCapacity?: boolean; // Default true - update capacity from headers
  headerUpdateInterval?: number; // How often to update from headers (seconds)
  approachingLimitThreshold?: number; // Default 0.1 (warn at 90% usage)

  // Advanced header processing options
  headerFormats?: string[]; // Supported header formats
  headerPriority?: string[]; // Priority order for header parsing
  headerFallback?: boolean; // Fall back to legacy parsing if RateLimitParser fails
}

// Enhanced rate limit info with additional fields
export interface EnhancedRateLimitInfo extends BaseLimitInfo {
  limit?: number;
  remaining?: number;
  resetTime?: number;
  window?: number;
}

// Enhanced metrics interface
export interface EnhancedRateLimitMetrics {
  // Base metrics from RateLimitManager
  totalRequests: number;
  rateLimitedRequests: number;
  averageDelayMs: number;
  maxDelayMs: number;
  queueSize: number;
  activeRequests: number;
  successRate: number;
  lastResetTime: Date;

  // TokenBucket metrics (if enabled)
  tokenBucket?: {
    tokens: number;
    capacity: number;
    successRate: number;
    utilizationRate: number;
  };

  // BackoffStrategy metrics (if enabled)
  backoffStrategy?: {
    totalRetries: number;
    averageDelay: number;
    successfulRetries: number;
    failedRetries: number;
  };

  // RateLimitParser specific metrics
  rateLimitParser: {
    headersProcessed: number;
    dynamicUpdatesApplied: number;
    supportedHeaderFormats: string[];
    lastHeaderUpdate: Date | null;
    approachingLimitWarnings: number;
    headerParsingFailures: number;
    successfulHeaderParsing: number;
  };
}

export class EnhancedRateLimitManager {
  private rateLimitManager: RateLimitManager;
  private enhancedConfig: EnhancedRateLimitConfig;
  private logger: winston.Logger;
  private headerProcessingCount = 0;
  private dynamicUpdateCount = 0;
  private lastHeaderUpdateTime: Date | null = null;
  private approachingLimitWarningCount = 0;
  private headerParsingFailureCount = 0;
  private successfulHeaderParsingCount = 0;

  constructor(config: Partial<EnhancedRateLimitConfig> = {}) {
    // Set enhanced configuration defaults
    const enhancedDefaults: Partial<EnhancedRateLimitConfig> = {
      headerParsingEnabled: true,
      dynamicCapacity: true,
      headerUpdateInterval: 300, // 5 minutes
      approachingLimitThreshold: 0.1, // Warn at 90% usage
      headerFormats: ["X-RateLimit-*", "Retry-After", "RateLimit-*"],
      headerPriority: [
        "x-ratelimit-limit",
        "x-rate-limit-limit",
        "ratelimit-limit",
      ],
      headerFallback: true,
    };

    // Merge enhanced defaults with provided config
    const finalConfig = { ...enhancedDefaults, ...config };

    // Initialize base RateLimitManager using composition
    this.rateLimitManager = new RateLimitManager(finalConfig);

    this.enhancedConfig = finalConfig as EnhancedRateLimitConfig;

    // Initialize enhanced logging
    this.logger = winston.createLogger({
      level: "info",
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json(),
      ),
      defaultMeta: { component: "EnhancedRateLimitManager" },
      transports: [
        new winston.transports.Console({
          silent: true, // Always silent to prevent JSON-RPC protocol contamination
        }),
      ],
    });

    // Initialize enhanced logging
    this.logger.info(
      "EnhancedRateLimitManager initialized with RateLimitParser integration",
      {
        operationId: uuidv4(),
        headerParsingEnabled: this.enhancedConfig.headerParsingEnabled,
        dynamicCapacity: this.enhancedConfig.dynamicCapacity,
        approachingLimitThreshold:
          this.enhancedConfig.approachingLimitThreshold,
        supportedFormats: this.enhancedConfig.headerFormats,
        component: "EnhancedRateLimitManager",
        phase: "Phase 3 Integration",
      },
    );
  }

  /**
   * Delegate to base RateLimitManager executeWithRateLimit method
   */
  async executeWithRateLimit<T>(
    operation: string,
    requestFn: () => Promise<T>,
    options: {
      priority?: "normal" | "high" | "low";
      correlationId?: string;
      endpoint?: string;
    } = {},
  ): Promise<T> {
    const operationId = uuidv4();

    this.logger.debug(
      `[${operationId}] Enhanced rate limit execution starting`,
      {
        operationId,
        operation,
        options,
        component: "EnhancedRateLimitManager",
      },
    );

    try {
      // Execute the request through the base rate limit manager
      const result = await this.rateLimitManager.executeWithRateLimit(
        operation,
        requestFn,
        options,
      );

      this.logger.debug(
        `[${operationId}] Enhanced rate limit execution completed successfully`,
        {
          operationId,
          operation,
          component: "EnhancedRateLimitManager",
        },
      );

      return result;
    } catch (error) {
      // Check if this is a rate limit error and enhance it with parsed information
      if (error instanceof RateLimitError || this.isRateLimitError(error)) {
        this.enhanceRateLimitError(error, operationId);
      }
      throw error;
    }
  }

  /**
   * Check if error is a rate limit error (similar to base class private method)
   */
  private isRateLimitError(error: unknown): boolean {
    if (!error || typeof error !== "object") {
      return false;
    }

    const errorObj = error as Record<string, unknown>;
    const response = errorObj.response as Record<string, unknown> | undefined;

    return (
      response?.status === 429 ||
      errorObj.code === "RATE_LIMITED" ||
      (typeof errorObj.message === "string" &&
        errorObj.message.includes("rate limit")) ||
      (typeof errorObj.message === "string" &&
        errorObj.message.includes("too many requests"))
    );
  }

  /**
   * Enhance rate limit error with parsed header information
   */
  private enhanceRateLimitError(error: unknown, operationId: string): void {
    const errorObj = error as Record<string, unknown>;
    const response = errorObj?.response as Record<string, unknown>;
    if (response?.headers && this.enhancedConfig.headerParsingEnabled) {
      this.headerProcessingCount++;

      try {
        const parsedInfo = RateLimitParser.parseHeaders(
          response.headers as Record<string, string | string[]>,
        );
        if (parsedInfo) {
          this.successfulHeaderParsingCount++;

          // Update token bucket with server-provided limits
          this.updateTokenBucketFromHeaders(parsedInfo, operationId);

          // Check if approaching rate limit threshold
          this.checkApproachingLimit(parsedInfo, operationId);

          this.logger.info(
            `[${operationId}] Enhanced rate limit error with parser information`,
            {
              operationId,
              parsedLimit: parsedInfo.limit,
              remaining: parsedInfo.remaining,
              resetTime: parsedInfo.reset,
              retryAfter: parsedInfo.retryAfter,
              window: parsedInfo.window,
              component: "RateLimitParser",
            },
          );
        } else {
          this.headerParsingFailureCount++;
          this.logger.debug(
            `[${operationId}] RateLimitParser could not enhance error with header info`,
            {
              operationId,
              availableHeaders: Object.keys(
                response.headers as Record<string, unknown>,
              ),
            },
          );
        }
      } catch (parseError) {
        this.headerParsingFailureCount++;
        this.logger.warn(
          `[${operationId}] RateLimitParser error during error enhancement`,
          {
            operationId,
            error: (parseError as Error).message,
            component: "EnhancedRateLimitManager",
          },
        );
      }
    }
  }

  /**
   * Update TokenBucket with server-provided rate limit information
   * Note: Since TokenBucket is private in base class, we need to access it through advanced status
   */
  private updateTokenBucketFromHeaders(
    rateLimitInfo: ParsedRateLimitInfo,
    operationId: string,
  ): void {
    if (!this.enhancedConfig.dynamicCapacity) {
      this.logger.debug(`[${operationId}] Dynamic capacity updates disabled`, {
        operationId,
        dynamicCapacity: this.enhancedConfig.dynamicCapacity,
      });
      return;
    }

    // Check if TokenBucket is available through the advanced components
    const advancedStatus = this.rateLimitManager.getAdvancedComponentsStatus();

    if (rateLimitInfo.limit > 0 && advancedStatus.tokenBucket.initialized) {
      const windowSeconds = rateLimitInfo.window || 3600; // Default to 1 hour

      // Since we can't directly access the TokenBucket, we'll use the updateConfig method
      // to indirectly influence token bucket behavior through configuration updates
      const newCapacity = Math.max(10, Math.floor(rateLimitInfo.limit * 0.8));
      const newRefillRate = Math.max(0.1, rateLimitInfo.limit / windowSeconds);

      try {
        this.rateLimitManager.updateConfig({
          requestsPerWindow: rateLimitInfo.limit,
          tokenBucket: {
            enabled: true,
            safetyMargin: 0.8,
            synchronizeWithHeaders: true,
            initialCapacity: newCapacity,
            initialRefillRate: newRefillRate,
          },
        });

        this.dynamicUpdateCount++;
        this.lastHeaderUpdateTime = new Date();

        this.logger.info(
          `[${operationId}] TokenBucket configuration updated from server headers`,
          {
            operationId,
            limit: rateLimitInfo.limit,
            remaining: rateLimitInfo.remaining,
            window: windowSeconds,
            newCapacity,
            newRefillRate,
            dynamicUpdateCount: this.dynamicUpdateCount,
            category: "RATE_LIMIT_PARSER",
          },
        );
      } catch (error) {
        this.logger.warn(
          `[${operationId}] Failed to update TokenBucket configuration`,
          {
            operationId,
            error: (error as Error).message,
            component: "EnhancedRateLimitManager",
          },
        );
      }
    } else {
      this.logger.debug(
        `[${operationId}] TokenBucket not available for updates`,
        {
          operationId,
          tokenBucketInitialized: advancedStatus.tokenBucket.initialized,
          tokenBucketEnabled: advancedStatus.tokenBucket.enabled,
        },
      );
    }
  }

  /**
   * Check if approaching rate limit threshold and issue warnings
   */
  private checkApproachingLimit(
    rateLimitInfo: ParsedRateLimitInfo,
    operationId: string,
  ): void {
    const threshold = this.enhancedConfig.approachingLimitThreshold || 0.1;

    if (RateLimitParser.isApproachingLimit(rateLimitInfo, threshold)) {
      this.approachingLimitWarningCount++;

      const utilizationRate =
        ((rateLimitInfo.limit - rateLimitInfo.remaining) /
          rateLimitInfo.limit) *
        100;

      this.logger.warn(`[${operationId}] Approaching rate limit threshold`, {
        operationId,
        limit: rateLimitInfo.limit,
        remaining: rateLimitInfo.remaining,
        utilizationRate: utilizationRate.toFixed(1) + "%",
        threshold: 100 - threshold * 100 + "%",
        warningCount: this.approachingLimitWarningCount,
        category: "RATE_LIMIT_WARNING",
      });
    }
  }

  /**
   * Process successful response headers for proactive rate limit updates
   */
  public updateFromResponseHeaders(
    headers: Record<string, string | string[]>,
  ): void {
    const operationId = uuidv4();

    if (!this.enhancedConfig.headerParsingEnabled) {
      this.logger.debug(
        `[${operationId}] Header parsing disabled, skipping response header processing`,
        {
          operationId,
          headerParsingEnabled: this.enhancedConfig.headerParsingEnabled,
        },
      );
      return;
    }

    this.logger.debug(
      `[${operationId}] Processing successful response headers`,
      {
        operationId,
        availableHeaders: Object.keys(headers),
        component: "EnhancedRateLimitManager",
      },
    );

    try {
      const parsedInfo = RateLimitParser.parseHeaders(headers);
      if (parsedInfo) {
        this.headerProcessingCount++;
        this.successfulHeaderParsingCount++;

        // Update token bucket with current API state
        this.updateTokenBucketFromHeaders(parsedInfo, operationId);

        // Check if approaching rate limit threshold
        this.checkApproachingLimit(parsedInfo, operationId);

        this.logger.info(
          `[${operationId}] Successfully processed response headers`,
          {
            operationId,
            limit: parsedInfo.limit,
            remaining: parsedInfo.remaining,
            resetTime: parsedInfo.reset,
            utilizationRate:
              parsedInfo.limit > 0
                ? (
                    ((parsedInfo.limit - parsedInfo.remaining) /
                      parsedInfo.limit) *
                    100
                  ).toFixed(1) + "%"
                : "unknown",
            component: "RateLimitParser",
          },
        );
      } else {
        this.headerParsingFailureCount++;
        this.logger.debug(
          `[${operationId}] No parseable rate limit information in response headers`,
          {
            operationId,
            availableHeaders: Object.keys(headers),
          },
        );
      }
    } catch (error) {
      this.headerParsingFailureCount++;
      this.logger.warn(`[${operationId}] Error processing response headers`, {
        operationId,
        error: (error as Error).message,
        component: "EnhancedRateLimitManager",
      });
    }
  }

  /**
   * Get enhanced metrics including RateLimitParser effectiveness
   */
  public getEnhancedMetrics(): EnhancedRateLimitMetrics {
    const baseMetrics = this.rateLimitManager.getMetrics();

    return {
      ...baseMetrics,
      rateLimitParser: {
        headersProcessed: this.headerProcessingCount,
        dynamicUpdatesApplied: this.dynamicUpdateCount,
        supportedHeaderFormats: this.enhancedConfig.headerFormats || [],
        lastHeaderUpdate: this.lastHeaderUpdateTime,
        approachingLimitWarnings: this.approachingLimitWarningCount,
        headerParsingFailures: this.headerParsingFailureCount,
        successfulHeaderParsing: this.successfulHeaderParsingCount,
      },
    };
  }

  /**
   * Get RateLimitParser specific status information
   */
  public getRateLimitParserStatus(): {
    enabled: boolean;
    dynamicCapacityEnabled: boolean;
    headerProcessingCount: number;
    successfulParsingRate: number;
    lastUpdate: Date | null;
    supportedFormats: string[];
    configuration: {
      headerParsingEnabled: boolean;
      dynamicCapacity: boolean;
      approachingLimitThreshold: number;
      headerUpdateInterval: number;
    };
  } {
    const totalAttempts =
      this.successfulHeaderParsingCount + this.headerParsingFailureCount;
    const successfulParsingRate =
      totalAttempts > 0
        ? (this.successfulHeaderParsingCount / totalAttempts) * 100
        : 0;

    return {
      enabled: this.enhancedConfig.headerParsingEnabled || false,
      dynamicCapacityEnabled: this.enhancedConfig.dynamicCapacity || false,
      headerProcessingCount: this.headerProcessingCount,
      successfulParsingRate,
      lastUpdate: this.lastHeaderUpdateTime,
      supportedFormats: this.enhancedConfig.headerFormats || [],
      configuration: {
        headerParsingEnabled: this.enhancedConfig.headerParsingEnabled || false,
        dynamicCapacity: this.enhancedConfig.dynamicCapacity || false,
        approachingLimitThreshold:
          this.enhancedConfig.approachingLimitThreshold || 0.1,
        headerUpdateInterval: this.enhancedConfig.headerUpdateInterval || 300,
      },
    };
  }

  /**
   * Enhanced configuration update with RateLimitParser specific options
   */
  public updateEnhancedConfig(updates: Partial<EnhancedRateLimitConfig>): void {
    const operationId = uuidv4();
    const oldConfig = { ...this.enhancedConfig };

    // Update enhanced configuration
    this.enhancedConfig = { ...this.enhancedConfig, ...updates };

    // Update base configuration through composition
    this.rateLimitManager.updateConfig(updates);

    this.logger.info(`[${operationId}] Enhanced configuration updated`, {
      operationId,
      updates,
      oldHeaderParsingEnabled: oldConfig.headerParsingEnabled,
      newHeaderParsingEnabled: this.enhancedConfig.headerParsingEnabled,
      oldDynamicCapacity: oldConfig.dynamicCapacity,
      newDynamicCapacity: this.enhancedConfig.dynamicCapacity,
      component: "EnhancedRateLimitManager",
    });
  }

  /**
   * Force a header-based update (useful for testing or manual sync)
   */
  public forceHeaderUpdate(
    headers: Record<string, string | string[]>,
  ): boolean {
    const operationId = uuidv4();

    this.logger.info(`[${operationId}] Forcing header update`, {
      operationId,
      availableHeaders: Object.keys(headers),
      component: "EnhancedRateLimitManager",
    });

    try {
      const parsedInfo = RateLimitParser.parseHeaders(headers);
      if (parsedInfo) {
        this.updateTokenBucketFromHeaders(parsedInfo, operationId);

        const advancedStatus =
          this.rateLimitManager.getAdvancedComponentsStatus();

        this.logger.info(
          `[${operationId}] Forced header update completed successfully`,
          {
            operationId,
            parsedInfo,
            tokenBucketUpdated: advancedStatus.tokenBucket.initialized,
          },
        );

        return true;
      }

      this.logger.warn(
        `[${operationId}] Forced header update failed - no parseable information`,
        {
          operationId,
          availableHeaders: Object.keys(headers),
        },
      );

      return false;
    } catch (error) {
      this.logger.error(`[${operationId}] Forced header update error`, {
        operationId,
        error: (error as Error).message,
        component: "EnhancedRateLimitManager",
      });

      return false;
    }
  }

  /**
   * Reset parser-specific metrics
   */
  public resetParserMetrics(): void {
    const operationId = uuidv4();

    this.headerProcessingCount = 0;
    this.dynamicUpdateCount = 0;
    this.approachingLimitWarningCount = 0;
    this.headerParsingFailureCount = 0;
    this.successfulHeaderParsingCount = 0;
    this.lastHeaderUpdateTime = null;

    this.logger.info(`[${operationId}] RateLimitParser metrics reset`, {
      operationId,
      component: "EnhancedRateLimitManager",
    });
  }

  // Delegate methods to base RateLimitManager for compatibility

  /**
   * Delegate to base RateLimitManager getMetrics method
   */
  public getMetrics(): RateLimitMetrics {
    return this.rateLimitManager.getMetrics();
  }

  /**
   * Delegate to base RateLimitManager getQueueStatus method
   */
  public getQueueStatus(): QueueStatus {
    return this.rateLimitManager.getQueueStatus();
  }

  /**
   * Delegate to base RateLimitManager clearQueue method
   */
  public clearQueue(): void {
    return this.rateLimitManager.clearQueue();
  }

  /**
   * Delegate to base RateLimitManager updateConfig method
   */
  public updateConfig(updates: Partial<RateLimitConfig>): void {
    // Update base configuration
    this.rateLimitManager.updateConfig(updates);

    // Update enhanced configuration if it includes enhanced properties
    const enhancedUpdates = updates as Partial<EnhancedRateLimitConfig>;
    if ("headerParsingEnabled" in updates || "dynamicCapacity" in updates) {
      this.enhancedConfig = { ...this.enhancedConfig, ...enhancedUpdates };
    }
  }

  /**
   * Delegate to base RateLimitManager getRateLimitStatus method
   */
  public getRateLimitStatus() {
    return this.rateLimitManager.getRateLimitStatus();
  }

  /**
   * Delegate to base RateLimitManager getAdvancedComponentsStatus method
   */
  public getAdvancedComponentsStatus() {
    return this.rateLimitManager.getAdvancedComponentsStatus();
  }
}

// Enhanced configuration preset for Make.com API with comprehensive parsing
export const ENHANCED_MAKE_API_CONFIG: EnhancedRateLimitConfig = {
  // Base rate limiting configuration
  maxRetries: 3,
  baseDelayMs: 2000,
  maxDelayMs: 300000,
  backoffMultiplier: 2.5,
  maxConcurrentRequests: 8,
  requestWindowMs: 60000,
  requestsPerWindow: 50,
  maxQueueSize: 500,
  queueTimeoutMs: 600000,
  enableMetrics: true,
  alertThresholdMs: 60000,

  // Advanced components
  enableAdvancedComponents: true,
  tokenBucket: {
    enabled: true,
    safetyMargin: 0.8,
    synchronizeWithHeaders: true,
    initialCapacity: 40,
    initialRefillRate: 0.67,
  },
  headerParsing: {
    enabled: true,
    preferServerHeaders: true,
  },
  backoffStrategy: {
    enabled: true,
    baseDelay: 2000,
    maxDelay: 300000,
    maxRetries: 3,
    jitterFactor: 0.15,
    useServerGuidedDelay: true,
    backoffMultiplier: 2.5,
  },

  // Enhanced RateLimitParser configuration
  headerParsingEnabled: true,
  dynamicCapacity: true,
  headerUpdateInterval: 300, // 5 minutes
  approachingLimitThreshold: 0.1, // Warn at 90% usage
  headerFormats: [
    "X-RateLimit-Limit",
    "X-RateLimit-Remaining",
    "X-RateLimit-Reset",
    "X-RateLimit-Reset-After",
    "Retry-After",
    "RateLimit-Limit",
    "RateLimit-Remaining",
    "RateLimit-Reset",
  ],
  headerPriority: [
    "x-ratelimit-limit",
    "x-rate-limit-limit",
    "ratelimit-limit",
  ],
  headerFallback: true,
};
