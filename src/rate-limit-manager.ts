/**
 * Rate Limit Management System for Make.com API
 * Implements intelligent request throttling and backoff strategies
 */

import { performance } from "perf_hooks";
import { v4 as uuidv4 } from "uuid";
import * as winston from "winston";

// Advanced rate limiting components
import { TokenBucket } from "./rate-limiting/token-bucket.js";
import {
  RateLimitParser,
  RateLimitInfo as ParsedRateLimitInfo,
} from "./rate-limiting/rate-limit-parser.js";
import {
  BackoffStrategy,
  BackoffConfig,
  BackoffResult,
} from "./rate-limiting/backoff-strategy.js";

// Rate limiting configuration interface
export interface RateLimitConfig {
  // Base configuration
  maxRetries: number;
  baseDelayMs: number;
  maxDelayMs: number;
  backoffMultiplier: number;

  // Concurrent request management
  maxConcurrentRequests: number;
  requestWindowMs: number;
  requestsPerWindow: number;

  // Queue configuration
  maxQueueSize: number;
  queueTimeoutMs: number;

  // Monitoring and alerting
  enableMetrics: boolean;
  alertThresholdMs: number;

  // Advanced features configuration
  enableAdvancedComponents?: boolean;
  tokenBucket?: {
    enabled: boolean;
    safetyMargin: number; // 0.8 = use 80% of available rate limit
    synchronizeWithHeaders: boolean;
    initialCapacity?: number; // Override default capacity
    initialRefillRate?: number; // Override default refill rate
  };
  headerParsing?: {
    enabled: boolean;
    preferServerHeaders: boolean; // Prefer server rate limit headers over fallback
  };
  backoffStrategy?: {
    enabled: boolean;
    baseDelay: number;
    maxDelay: number;
    maxRetries: number;
    jitterFactor: number;
    useServerGuidedDelay: boolean; // Use Retry-After headers when available
    backoffMultiplier?: number; // Optional: exponential backoff multiplier
  };
}

// Rate limit detection result
export interface RateLimitInfo {
  isRateLimited: boolean;
  retryAfterMs?: number;
  remainingRequests?: number;
  resetTimeMs?: number;
  quotaType?: string;
}

// Request queue item
interface QueuedRequest {
  id: string;
  operation: string;
  execute: () => Promise<unknown>;
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  timestamp: number;
  priority: "normal" | "high" | "low";
  retryCount: number;
}

// Rate limit metrics
interface RateLimitMetrics {
  totalRequests: number;
  rateLimitedRequests: number;
  averageDelayMs: number;
  maxDelayMs: number;
  queueSize: number;
  activeRequests: number;
  successRate: number;
  lastResetTime: Date;
  // Advanced metrics
  tokenBucket?: {
    tokens: number;
    capacity: number;
    successRate: number;
    utilizationRate: number;
  };
}

// Rate limit error
export class RateLimitError extends Error {
  constructor(
    message: string,
    public readonly retryAfterMs: number,
    public readonly correlationId: string,
  ) {
    super(message);
    this.name = "RateLimitError";
  }
}

export class RateLimitManager {
  private config: RateLimitConfig;
  private requestQueue: QueuedRequest[] = [];
  private activeRequests = 0;
  private requestHistory: number[] = [];
  private metrics: RateLimitMetrics;
  private processingQueue = false;
  private logger: winston.Logger;

  // Rate limit state
  private globalRateLimitUntil = 0;
  private endpointLimits = new Map<string, number>();

  // Advanced rate limiting components
  private tokenBucket?: TokenBucket;
  private lastKnownRateLimit?: ParsedRateLimitInfo;
  private backoffStrategy?: BackoffStrategy;

  constructor(config: Partial<RateLimitConfig> = {}) {
    this.config = {
      maxRetries: 3,
      baseDelayMs: 1000,
      maxDelayMs: 60000,
      backoffMultiplier: 2,
      maxConcurrentRequests: 10,
      requestWindowMs: 60000, // 1 minute
      requestsPerWindow: 100,
      maxQueueSize: 1000,
      queueTimeoutMs: 300000, // 5 minutes
      enableMetrics: true,
      alertThresholdMs: 30000,
      // Advanced features defaults
      enableAdvancedComponents: true,
      tokenBucket: {
        enabled: true,
        safetyMargin: 0.8, // Use 80% of available rate limit
        synchronizeWithHeaders: true,
      },
      headerParsing: {
        enabled: true,
        preferServerHeaders: true,
      },
      backoffStrategy: {
        enabled: true,
        baseDelay: 1000, // 1 second base delay
        maxDelay: 60000, // 60 seconds max delay
        maxRetries: 3, // 3 retry attempts
        jitterFactor: 0.1, // 10% jitter
        useServerGuidedDelay: true, // Use Retry-After headers when available
        backoffMultiplier: 2, // Exponential backoff multiplier
      },
      ...config,
    };

    this.metrics = {
      totalRequests: 0,
      rateLimitedRequests: 0,
      averageDelayMs: 0,
      maxDelayMs: 0,
      queueSize: 0,
      activeRequests: 0,
      successRate: 1.0,
      lastResetTime: new Date(),
    };

    // Initialize logger first (needed by advanced components)
    this.logger = winston.createLogger({
      level: "info",
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json(),
      ),
      defaultMeta: { component: "RateLimitManager" },
      transports: [
        new winston.transports.Console({
          silent: process.env.NODE_ENV === "test",
        }),
      ],
    });

    // Initialize advanced components if enabled
    this.initializeAdvancedComponents();

    // Start queue processor
    this.startQueueProcessor();

    // Clean up old request history every minute
    setInterval(() => {
      this.cleanupRequestHistory();
    }, 60000);
  }

  /**
   * Initialize advanced components (TokenBucket, etc.)
   */
  private initializeAdvancedComponents(): void {
    if (!this.config.enableAdvancedComponents) {
      this.logger.info("Advanced rate limiting components disabled", {
        enableAdvancedComponents: this.config.enableAdvancedComponents,
      });
      return;
    }

    // Initialize TokenBucket if enabled
    if (this.config.tokenBucket?.enabled) {
      const tokenBucketConfig = {
        capacity:
          this.config.tokenBucket.initialCapacity ||
          this.config.requestsPerWindow,
        refillRate:
          this.config.tokenBucket.initialRefillRate ||
          this.config.requestsPerWindow / (this.config.requestWindowMs / 1000),
        safetyMargin: this.config.tokenBucket.safetyMargin,
      };

      this.tokenBucket = new TokenBucket(tokenBucketConfig);

      this.logger.info(
        "TokenBucket initialized for pre-emptive rate limiting",
        {
          operationId: uuidv4(),
          tokenBucketConfig,
          component: "RateLimitManager",
          initializationStatus: "success",
        },
      );
    }

    // Initialize BackoffStrategy if enabled
    if (this.config.backoffStrategy?.enabled) {
      const backoffConfig: BackoffConfig = {
        baseDelay: this.config.backoffStrategy.baseDelay,
        maxDelay: this.config.backoffStrategy.maxDelay,
        maxRetries: this.config.backoffStrategy.maxRetries,
        jitterFactor: this.config.backoffStrategy.jitterFactor,
        backoffMultiplier: this.config.backoffStrategy.backoffMultiplier || 2,
      };

      this.backoffStrategy = new BackoffStrategy(backoffConfig);

      this.logger.info(
        "BackoffStrategy initialized for intelligent retry logic",
        {
          operationId: uuidv4(),
          backoffConfig,
          component: "RateLimitManager",
          initializationStatus: "success",
        },
      );
    }

    this.logger.info("Advanced rate limiting components initialized", {
      operationId: uuidv4(),
      tokenBucketEnabled: this.config.tokenBucket?.enabled,
      headerParsingEnabled: this.config.headerParsing?.enabled,
      backoffStrategyEnabled: this.config.backoffStrategy?.enabled,
      component: "RateLimitManager",
    });
  }

  /**
   * Execute a request with rate limiting protection
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
    const requestId = uuidv4();
    const correlationId = options.correlationId || requestId;

    this.metrics.totalRequests++;

    // Check if we can make the request immediately
    if (this.canMakeRequestNow(options.endpoint)) {
      try {
        return await this.executeRequestDirectly(
          operation,
          requestFn,
          correlationId,
          0,
        );
      } catch (error) {
        if (this.isRateLimitError(error)) {
          // Rate limited, queue for retry
          return this.queueRequest(
            requestId,
            operation,
            requestFn,
            options.priority || "normal",
            correlationId,
          );
        }
        throw error;
      }
    } else {
      // Queue the request
      return this.queueRequest(
        requestId,
        operation,
        requestFn,
        options.priority || "normal",
        correlationId,
      );
    }
  }

  /**
   * Check if we can make a request now without rate limiting
   */
  private canMakeRequestNow(endpoint?: string): boolean {
    const operationId = uuidv4();

    this.logger.debug(`[${operationId}] Starting rate limit check`, {
      operationId,
      endpoint,
      timestamp: new Date().toISOString(),
      component: "RateLimitManager",
    });

    // Check global rate limit
    if (Date.now() < this.globalRateLimitUntil) {
      this.logger.debug(
        `[${operationId}] Request blocked by global rate limit`,
        {
          operationId,
          globalRateLimitUntil: this.globalRateLimitUntil,
          waitTimeMs: this.globalRateLimitUntil - Date.now(),
        },
      );
      return false;
    }

    // Check endpoint-specific rate limit
    if (endpoint) {
      const endpointLimit = this.endpointLimits.get(endpoint);
      if (endpointLimit && Date.now() < endpointLimit) {
        this.logger.debug(
          `[${operationId}] Request blocked by endpoint-specific rate limit`,
          {
            operationId,
            endpoint,
            endpointLimitUntil: endpointLimit,
            waitTimeMs: endpointLimit - Date.now(),
          },
        );
        return false;
      }
    }

    // Check concurrent request limit
    if (this.activeRequests >= this.config.maxConcurrentRequests) {
      this.logger.debug(
        `[${operationId}] Request blocked by concurrent request limit`,
        {
          operationId,
          activeRequests: this.activeRequests,
          maxConcurrentRequests: this.config.maxConcurrentRequests,
        },
      );
      return false;
    }

    // Advanced component: Check TokenBucket if enabled
    if (
      this.config.enableAdvancedComponents &&
      this.config.tokenBucket?.enabled &&
      this.tokenBucket
    ) {
      const tokenAvailable = this.tokenBucket.tryConsume(1);
      if (!tokenAvailable) {
        const timeUntilTokens = this.tokenBucket.getTimeUntilTokensAvailable(1);
        this.logger.debug(
          `[${operationId}] Request blocked by TokenBucket - insufficient tokens`,
          {
            operationId,
            tokenBucketState: this.tokenBucket.getState(),
            timeUntilTokensMs: timeUntilTokens,
            component: "TokenBucket",
          },
        );
        return false;
      }

      this.logger.debug(`[${operationId}] TokenBucket allowed request`, {
        operationId,
        tokenBucketState: this.tokenBucket.getState(),
        component: "TokenBucket",
      });
    } else {
      // Fallback: Check request window limit (legacy behavior)
      const now = Date.now();
      const windowStart = now - this.config.requestWindowMs;
      const recentRequests = this.requestHistory.filter(
        (time) => time > windowStart,
      );

      if (recentRequests.length >= this.config.requestsPerWindow) {
        this.logger.debug(
          `[${operationId}] Request blocked by window limit (legacy behavior)`,
          {
            operationId,
            recentRequestsCount: recentRequests.length,
            requestsPerWindow: this.config.requestsPerWindow,
            windowMs: this.config.requestWindowMs,
          },
        );
        return false;
      }
    }

    this.logger.debug(
      `[${operationId}] Rate limit check passed - request allowed`,
      {
        operationId,
        endpoint,
        activeRequests: this.activeRequests,
        tokenBucketEnabled: this.config.tokenBucket?.enabled,
      },
    );
    return true;
  }

  /**
   * Execute request directly with retry logic
   */
  private async executeRequestDirectly<T>(
    operation: string,
    requestFn: () => Promise<T>,
    correlationId: string,
    retryCount: number,
  ): Promise<T> {
    this.activeRequests++;
    const startTime = performance.now();

    try {
      const result = await requestFn();

      // Track successful request
      this.requestHistory.push(Date.now());

      // Update metrics
      const duration = performance.now() - startTime;
      this.updateMetrics(duration, true);

      return result;
    } catch (error) {
      const duration = performance.now() - startTime;
      this.updateMetrics(duration, false);

      if (this.isRateLimitError(error)) {
        const rateLimitInfo = this.extractRateLimitInfo(error);
        this.handleRateLimit(rateLimitInfo, correlationId);

        // Enhanced: Use BackoffStrategy for intelligent retry logic
        if (retryCount < this.config.maxRetries) {
          const backoffResult = this.calculateIntelligentBackoffDelay(
            retryCount,
            error,
            rateLimitInfo,
            correlationId,
          );

          if (!backoffResult.shouldRetry) {
            throw new RateLimitError(
              `Request rate limited - ${backoffResult.reason}`,
              backoffResult.delay,
              correlationId,
            );
          }

          this.logger.warn(
            `Rate limited for operation ${operation}, retrying in ${backoffResult.delay}ms - ${backoffResult.reason}`,
            {
              correlationId,
              operation,
              retryCount,
              delayMs: backoffResult.delay,
              backoffReason: backoffResult.reason,
              attempt: backoffResult.attempt,
              maxRetries: this.config.maxRetries,
            },
          );

          await this.sleep(backoffResult.delay);
          return this.executeRequestDirectly(
            operation,
            requestFn,
            correlationId,
            retryCount + 1,
          );
        } else {
          throw new RateLimitError(
            `Request rate limited after ${this.config.maxRetries} retries`,
            rateLimitInfo.retryAfterMs || this.config.baseDelayMs,
            correlationId,
          );
        }
      }

      throw error;
    } finally {
      this.activeRequests--;
    }
  }

  /**
   * Queue a request for later execution
   */
  private async queueRequest<T>(
    requestId: string,
    operation: string,
    requestFn: () => Promise<T>,
    priority: "normal" | "high" | "low",
    correlationId: string,
  ): Promise<T> {
    if (this.requestQueue.length >= this.config.maxQueueSize) {
      throw new Error(`Request queue full (${this.config.maxQueueSize} items)`);
    }

    return new Promise<T>((resolve, reject) => {
      const queuedRequest: QueuedRequest = {
        id: requestId,
        operation,
        execute: requestFn,
        resolve: resolve as (value: unknown) => void,
        reject,
        timestamp: Date.now(),
        priority,
        retryCount: 0,
      };

      // Insert based on priority
      this.insertRequestByPriority(queuedRequest);
      this.metrics.queueSize = this.requestQueue.length;

      this.logger.info(`Request queued for operation ${operation}`, {
        correlationId,
        queueSize: this.requestQueue.length,
        priority,
      });

      // Set timeout for queued request
      setTimeout(() => {
        const index = this.requestQueue.findIndex(
          (req) => req.id === requestId,
        );
        if (index >= 0) {
          this.requestQueue.splice(index, 1);
          this.metrics.queueSize = this.requestQueue.length;
          reject(
            new Error(
              `Request timeout after ${this.config.queueTimeoutMs}ms in queue`,
            ),
          );
        }
      }, this.config.queueTimeoutMs);
    });
  }

  /**
   * Insert request into queue based on priority
   */
  private insertRequestByPriority(request: QueuedRequest): void {
    const priorityOrder = { high: 0, normal: 1, low: 2 };
    const requestPriority = priorityOrder[request.priority];

    let insertIndex = this.requestQueue.length;
    for (let i = 0; i < this.requestQueue.length; i++) {
      const queuePriority = priorityOrder[this.requestQueue[i].priority];
      if (requestPriority < queuePriority) {
        insertIndex = i;
        break;
      }
    }

    this.requestQueue.splice(insertIndex, 0, request);
  }

  /**
   * Start the queue processor
   */
  private startQueueProcessor(): void {
    setInterval(async () => {
      if (!this.processingQueue && this.requestQueue.length > 0) {
        await this.processQueue();
      }
    }, 100); // Check every 100ms
  }

  /**
   * Process queued requests
   */
  private async processQueue(): Promise<void> {
    this.processingQueue = true;

    try {
      while (this.requestQueue.length > 0) {
        const request = this.requestQueue[0];

        if (!this.canMakeRequestNow()) {
          break; // Wait for rate limits to clear
        }

        // Remove from queue
        this.requestQueue.shift();
        this.metrics.queueSize = this.requestQueue.length;

        try {
          const result = await this.executeRequestDirectly(
            request.operation,
            request.execute,
            `queue-${request.id}`,
            request.retryCount,
          );
          request.resolve(result);
        } catch (error) {
          if (
            this.isRateLimitError(error) &&
            request.retryCount < this.config.maxRetries
          ) {
            // Re-queue with incremented retry count
            request.retryCount++;
            this.insertRequestByPriority(request);
            this.metrics.queueSize = this.requestQueue.length;
          } else {
            request.reject(error as Error);
          }
        }

        // Small delay between processing requests
        await this.sleep(50);
      }
    } finally {
      this.processingQueue = false;
    }
  }

  /**
   * Check if error is a rate limit error
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
   * Classify error type for intelligent backoff decisions
   */
  private classifyError(
    error: unknown,
  ): "rate_limit" | "server_error" | "timeout" | "client_error" | "unknown" {
    const operationId = uuidv4();

    this.logger.debug(
      `[${operationId}] Classifying error for backoff strategy`,
      {
        operationId,
        hasError: !!error,
        errorType: typeof error,
      },
    );

    if (!error || typeof error !== "object") {
      return "unknown";
    }

    const errorObj = error as Record<string, unknown>;
    const response = errorObj.response as Record<string, unknown> | undefined;
    const status = response?.status as number | undefined;
    const code = errorObj.code as string | undefined;
    const message = errorObj.message as string | undefined;

    // Rate limit errors (429 or specific rate limit codes/messages)
    if (
      status === 429 ||
      code === "RATE_LIMITED" ||
      (message &&
        (message.includes("rate limit") ||
          message.includes("too many requests")))
    ) {
      this.logger.debug(`[${operationId}] Error classified as rate_limit`, {
        operationId,
        status,
        code,
        messageSnippet: message?.substring(0, 100),
      });
      return "rate_limit";
    }

    // Server errors (5xx)
    if (status && status >= 500 && status < 600) {
      this.logger.debug(`[${operationId}] Error classified as server_error`, {
        operationId,
        status,
      });
      return "server_error";
    }

    // Client errors (4xx, excluding 429 which is rate limit)
    if (status && status >= 400 && status < 500 && status !== 429) {
      this.logger.debug(`[${operationId}] Error classified as client_error`, {
        operationId,
        status,
      });
      return "client_error";
    }

    // Timeout errors
    if (
      code === "ETIMEDOUT" ||
      code === "TIMEOUT" ||
      code === "ECONNRESET" ||
      code === "ECONNREFUSED" ||
      (message &&
        (message.includes("timeout") ||
          message.includes("connection reset") ||
          message.includes("connection refused")))
    ) {
      this.logger.debug(`[${operationId}] Error classified as timeout`, {
        operationId,
        code,
        messageSnippet: message?.substring(0, 100),
      });
      return "timeout";
    }

    this.logger.debug(`[${operationId}] Error classified as unknown`, {
      operationId,
      status,
      code,
      messageSnippet: message?.substring(0, 100),
    });
    return "unknown";
  }

  /**
   * Extract rate limit information from error response
   * Enhanced with RateLimitParser for better accuracy
   */
  private extractRateLimitInfo(error: unknown): RateLimitInfo {
    const operationId = uuidv4();

    this.logger.debug(
      `[${operationId}] Extracting rate limit information from error`,
      {
        operationId,
        component: "RateLimitManager",
        hasError: !!error,
      },
    );

    if (!error || typeof error !== "object") {
      this.logger.debug(
        `[${operationId}] No error object available, returning default rate limit info`,
        {
          operationId,
        },
      );
      return { isRateLimited: true };
    }

    const errorObj = error as Record<string, unknown>;
    const response = errorObj.response as Record<string, unknown> | undefined;
    const headers = (response?.headers as Record<string, string>) || {};

    // Enhanced: Use RateLimitParser if advanced components are enabled
    if (
      this.config.enableAdvancedComponents &&
      this.config.headerParsing?.enabled
    ) {
      const parsedInfo = RateLimitParser.parseHeaders(headers);

      if (parsedInfo) {
        this.logger.info(
          `[${operationId}] Rate limit info parsed successfully with RateLimitParser`,
          {
            operationId,
            parsedInfo,
            component: "RateLimitParser",
          },
        );

        // Store the parsed info for future use
        this.lastKnownRateLimit = parsedInfo;

        // Update TokenBucket if enabled and we have good data
        if (
          this.config.tokenBucket?.synchronizeWithHeaders &&
          this.tokenBucket &&
          parsedInfo.limit > 0
        ) {
          const windowSeconds = parsedInfo.window || 3600; // Default to 1 hour if not specified
          this.tokenBucket.updateFromRateLimit(
            parsedInfo.limit,
            parsedInfo.remaining,
            windowSeconds,
          );

          this.logger.info(
            `[${operationId}] TokenBucket synchronized with API headers`,
            {
              operationId,
              limit: parsedInfo.limit,
              remaining: parsedInfo.remaining,
              windowSeconds,
              tokenBucketState: this.tokenBucket.getState(),
            },
          );
        }

        // Convert to legacy format for backward compatibility
        return {
          isRateLimited: true,
          retryAfterMs: parsedInfo.retryAfter
            ? parsedInfo.retryAfter * 1000
            : RateLimitParser.getTimeUntilReset(parsedInfo),
          remainingRequests: parsedInfo.remaining,
          resetTimeMs:
            parsedInfo.reset > 0 ? parsedInfo.reset * 1000 : undefined,
          quotaType: "parsed-headers",
        };
      }

      this.logger.debug(
        `[${operationId}] RateLimitParser could not parse headers, falling back to legacy parsing`,
        {
          operationId,
          headers: Object.keys(headers),
        },
      );
    }

    // Legacy fallback parsing (maintained for backward compatibility)
    this.logger.debug(
      `[${operationId}] Using legacy rate limit header parsing`,
      {
        operationId,
        advancedComponentsEnabled: this.config.enableAdvancedComponents,
        headerParsingEnabled: this.config.headerParsing?.enabled,
      },
    );

    // Try various header formats used by different APIs
    let retryAfterMs: number | undefined;
    const retryAfter =
      headers["retry-after"] ||
      headers["Retry-After"] ||
      headers["x-retry-after"];

    if (retryAfter) {
      // Could be seconds or timestamp
      const retryAfterNum = parseInt(retryAfter, 10);
      if (retryAfterNum < 1000000000) {
        // Assume seconds
        retryAfterMs = retryAfterNum * 1000;
      } else {
        // Assume timestamp
        retryAfterMs = Math.max(0, retryAfterNum - Date.now());
      }
    }

    const remainingRequests = parseInt(
      headers["x-ratelimit-remaining"] ||
        headers["x-rate-limit-remaining"] ||
        headers["ratelimit-remaining"] ||
        "0",
      10,
    );

    const resetTime = parseInt(
      headers["x-ratelimit-reset"] ||
        headers["x-rate-limit-reset"] ||
        headers["ratelimit-reset"] ||
        "0",
      10,
    );

    this.logger.debug(`[${operationId}] Legacy rate limit parsing completed`, {
      operationId,
      retryAfterMs,
      remainingRequests: isNaN(remainingRequests)
        ? undefined
        : remainingRequests,
      resetTimeMs: resetTime ? resetTime * 1000 : undefined,
    });

    return {
      isRateLimited: true,
      retryAfterMs,
      remainingRequests: isNaN(remainingRequests)
        ? undefined
        : remainingRequests,
      resetTimeMs: resetTime ? resetTime * 1000 : undefined,
      quotaType: headers["x-quota-type"] || "unknown",
    };
  }

  /**
   * Handle rate limit by updating internal state
   * Enhanced with BackoffStrategy context
   */
  private handleRateLimit(
    rateLimitInfo: RateLimitInfo,
    correlationId: string,
  ): void {
    const operationId = uuidv4();
    this.metrics.rateLimitedRequests++;

    const now = Date.now();
    const waitTimeMs = rateLimitInfo.retryAfterMs || this.config.baseDelayMs;

    // Update global rate limit
    this.globalRateLimitUntil = Math.max(
      this.globalRateLimitUntil,
      now + waitTimeMs,
    );

    this.logger.warn(`[${operationId}] Rate limit detected and handled`, {
      operationId,
      correlationId,
      waitTimeMs,
      remainingRequests: rateLimitInfo.remainingRequests,
      resetTimeMs: rateLimitInfo.resetTimeMs,
      quotaType: rateLimitInfo.quotaType,
      backoffStrategyEnabled: !!this.backoffStrategy,
      component: "RateLimitManager",
    });

    // Enhanced: Sync with BackoffStrategy if enabled
    if (this.backoffStrategy && rateLimitInfo) {
      const parsedInfo = this.convertToBackoffRateLimitInfo(rateLimitInfo);
      if (parsedInfo) {
        this.logger.debug(
          `[${operationId}] Rate limit context available for BackoffStrategy`,
          {
            operationId,
            correlationId,
            parsedInfo,
          },
        );
      }
    }

    // Trigger alert if delay is significant
    if (waitTimeMs > this.config.alertThresholdMs) {
      this.logger.error(
        `[${operationId}] Significant rate limit delay detected`,
        {
          operationId,
          correlationId,
          delayMs: waitTimeMs,
          thresholdMs: this.config.alertThresholdMs,
          backoffStrategyEnabled: !!this.backoffStrategy,
        },
      );
    }
  }

  /**
   * Calculate intelligent backoff delay using BackoffStrategy
   * Enhanced with error type classification and server-guided delays
   */
  private calculateIntelligentBackoffDelay(
    retryCount: number,
    error: unknown,
    rateLimitInfo: RateLimitInfo,
    correlationId: string,
  ): BackoffResult {
    const operationId = uuidv4();

    this.logger.debug(
      `[${operationId}] Calculating intelligent backoff delay`,
      {
        operationId,
        correlationId,
        retryCount,
        backoffStrategyEnabled: !!this.backoffStrategy,
        useServerGuidedDelay: this.config.backoffStrategy?.useServerGuidedDelay,
      },
    );

    // Enhanced: Use BackoffStrategy if available
    if (
      this.config.enableAdvancedComponents &&
      this.config.backoffStrategy?.enabled &&
      this.backoffStrategy
    ) {
      const errorType = this.classifyError(error);
      const parsedRateLimitInfo =
        this.convertToBackoffRateLimitInfo(rateLimitInfo);

      this.logger.info(
        `[${operationId}] Using BackoffStrategy for intelligent retry calculation`,
        {
          operationId,
          correlationId,
          retryCount,
          errorType,
          hasRateLimitInfo: !!parsedRateLimitInfo,
          useServerGuidedDelay:
            this.config.backoffStrategy.useServerGuidedDelay,
        },
      );

      const backoffResult = this.backoffStrategy.calculateAdaptiveDelay(
        retryCount,
        this.config.backoffStrategy.useServerGuidedDelay
          ? parsedRateLimitInfo
          : undefined,
        errorType,
      );

      this.logger.info(`[${operationId}] BackoffStrategy calculated delay`, {
        operationId,
        correlationId,
        backoffResult,
        errorType,
      });

      return backoffResult;
    }

    // Fallback: Legacy exponential backoff calculation
    this.logger.debug(
      `[${operationId}] Using legacy backoff calculation (BackoffStrategy disabled)`,
      {
        operationId,
        correlationId,
        advancedComponentsEnabled: this.config.enableAdvancedComponents,
        backoffStrategyEnabled: this.config.backoffStrategy?.enabled,
      },
    );

    // Use provided retry-after if available
    if (rateLimitInfo.retryAfterMs) {
      const delayMs = Math.min(
        rateLimitInfo.retryAfterMs,
        this.config.maxDelayMs,
      );
      return {
        delay: delayMs,
        attempt: retryCount + 1,
        shouldRetry: retryCount < this.config.maxRetries,
        reason: `Server-specified retry-after: ${rateLimitInfo.retryAfterMs}ms (legacy)`,
      };
    }

    // Calculate exponential backoff
    const exponentialDelay =
      this.config.baseDelayMs *
      Math.pow(this.config.backoffMultiplier, retryCount);

    // Add jitter to prevent thundering herd
    const jitter = Math.random() * 1000;
    const finalDelay = Math.min(
      exponentialDelay + jitter,
      this.config.maxDelayMs,
    );

    return {
      delay: finalDelay,
      attempt: retryCount + 1,
      shouldRetry: retryCount < this.config.maxRetries,
      reason: `Legacy exponential backoff (attempt ${retryCount + 1}/${this.config.maxRetries})`,
    };
  }

  /**
   * Convert legacy RateLimitInfo to BackoffStrategy RateLimitInfo format
   */
  private convertToBackoffRateLimitInfo(
    rateLimitInfo: RateLimitInfo,
  ): ParsedRateLimitInfo | undefined {
    if (!rateLimitInfo || !rateLimitInfo.isRateLimited) {
      return undefined;
    }

    // Convert from legacy format to BackoffStrategy format
    const parsedInfo: ParsedRateLimitInfo = {
      limit: 0, // Not available in legacy format
      remaining: rateLimitInfo.remainingRequests || 0,
      reset: rateLimitInfo.resetTimeMs ? rateLimitInfo.resetTimeMs / 1000 : 0,
      retryAfter: rateLimitInfo.retryAfterMs
        ? rateLimitInfo.retryAfterMs / 1000
        : undefined,
      resetAfter: undefined, // Not available in legacy format
      window: undefined, // Not available in legacy format
      // quota: rateLimitInfo.quotaType, // Not part of ParsedRateLimitInfo interface
    };

    this.logger.debug(
      "Converted legacy RateLimitInfo to BackoffStrategy format",
      {
        legacyInfo: rateLimitInfo,
        parsedInfo,
      },
    );

    return parsedInfo;
  }

  /**
   * Update metrics
   */
  private updateMetrics(duration: number, success: boolean): void {
    if (!this.config.enableMetrics) {
      return;
    }

    this.metrics.averageDelayMs = (this.metrics.averageDelayMs + duration) / 2;
    this.metrics.maxDelayMs = Math.max(this.metrics.maxDelayMs, duration);
    this.metrics.activeRequests = this.activeRequests;
    this.metrics.successRate = success
      ? (this.metrics.successRate + 1) / 2
      : this.metrics.successRate * 0.9; // Decay on failure
  }

  /**
   * Clean up old request history
   */
  private cleanupRequestHistory(): void {
    const cutoff = Date.now() - this.config.requestWindowMs;
    this.requestHistory = this.requestHistory.filter((time) => time > cutoff);
  }

  /**
   * Sleep utility
   */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Get current metrics
   * Enhanced with TokenBucket statistics
   */
  getMetrics(): RateLimitMetrics {
    const baseMetrics: RateLimitMetrics = {
      ...this.metrics,
      queueSize: this.requestQueue.length,
      activeRequests: this.activeRequests,
    };

    // Add TokenBucket metrics if enabled
    if (this.config.enableAdvancedComponents && this.tokenBucket) {
      const bucketStats = this.tokenBucket.getStatistics();
      baseMetrics.tokenBucket = {
        tokens: bucketStats.state.tokens,
        capacity: bucketStats.config.capacity,
        successRate: bucketStats.stats.successRate,
        utilizationRate: bucketStats.stats.utilizationRate,
      };

      this.logger.debug("TokenBucket metrics included in rate limit metrics", {
        tokenBucket: baseMetrics.tokenBucket,
        component: "RateLimitManager",
      });
    }

    return baseMetrics;
  }

  /**
   * Get queue status
   */
  getQueueStatus(): {
    size: number;
    activeRequests: number;
    oldestRequestAge: number;
    priorityBreakdown: Record<string, number>;
  } {
    const now = Date.now();
    const priorityBreakdown = { high: 0, normal: 0, low: 0 };

    this.requestQueue.forEach((req) => {
      priorityBreakdown[req.priority]++;
    });

    const oldestRequestAge =
      this.requestQueue.length > 0
        ? now - Math.min(...this.requestQueue.map((req) => req.timestamp))
        : 0;

    return {
      size: this.requestQueue.length,
      activeRequests: this.activeRequests,
      oldestRequestAge,
      priorityBreakdown,
    };
  }

  /**
   * Clear queue (emergency use)
   */
  clearQueue(): void {
    const clearedRequests = this.requestQueue.length;
    this.requestQueue.forEach((req) => {
      req.reject(new Error("Queue cleared"));
    });
    this.requestQueue = [];
    this.metrics.queueSize = 0;

    this.logger.warn("Request queue cleared", {
      clearedRequests,
      reason: "manual-clear",
    });
  }

  /**
   * Update configuration at runtime
   * Enhanced to reinitialize advanced components if needed
   */
  updateConfig(updates: Partial<RateLimitConfig>): void {
    const oldConfig = { ...this.config };
    this.config = { ...this.config, ...updates };

    // Reinitialize advanced components if their config changed
    if (
      updates.enableAdvancedComponents !== undefined ||
      updates.tokenBucket !== undefined ||
      updates.headerParsing !== undefined ||
      updates.backoffStrategy !== undefined
    ) {
      this.logger.info(
        "Advanced components configuration changed, reinitializing",
        {
          oldAdvancedEnabled: oldConfig.enableAdvancedComponents,
          newAdvancedEnabled: this.config.enableAdvancedComponents,
          tokenBucketUpdated: !!updates.tokenBucket,
          headerParsingUpdated: !!updates.headerParsing,
          backoffStrategyUpdated: !!updates.backoffStrategy,
        },
      );

      this.initializeAdvancedComponents();
    }

    // Update BackoffStrategy configuration if it exists and relevant config changed
    if (this.backoffStrategy && updates.backoffStrategy) {
      const backoffConfig: Partial<BackoffConfig> = {};

      if (updates.backoffStrategy.baseDelay !== undefined) {
        backoffConfig.baseDelay = updates.backoffStrategy.baseDelay;
      }
      if (updates.backoffStrategy.maxDelay !== undefined) {
        backoffConfig.maxDelay = updates.backoffStrategy.maxDelay;
      }
      if (updates.backoffStrategy.maxRetries !== undefined) {
        backoffConfig.maxRetries = updates.backoffStrategy.maxRetries;
      }
      if (updates.backoffStrategy.jitterFactor !== undefined) {
        backoffConfig.jitterFactor = updates.backoffStrategy.jitterFactor;
      }
      if (updates.backoffStrategy.backoffMultiplier !== undefined) {
        backoffConfig.backoffMultiplier =
          updates.backoffStrategy.backoffMultiplier;
      }

      if (Object.keys(backoffConfig).length > 0) {
        this.backoffStrategy.updateConfig(backoffConfig);

        this.logger.info("BackoffStrategy configuration updated dynamically", {
          updatedConfig: backoffConfig,
          component: "BackoffStrategy",
        });
      }
    }

    // Update TokenBucket configuration if it exists and relevant config changed
    if (this.tokenBucket && updates.tokenBucket) {
      this.tokenBucket.updateConfig({
        safetyMargin: updates.tokenBucket.safetyMargin,
      });

      this.logger.info("TokenBucket configuration updated dynamically", {
        updatedConfig: updates.tokenBucket,
      });
    }

    this.logger.info("Rate limit configuration updated", {
      updates,
      component: "RateLimitManager",
    });
  }

  /**
   * Get current rate limit status
   */
  getRateLimitStatus(): {
    globalRateLimitActive: boolean;
    globalRateLimitUntil: number;
    endpointLimits: Array<{ endpoint: string; limitUntil: number }>;
    requestsInWindow: number;
    canMakeRequest: boolean;
  } {
    const now = Date.now();
    const windowStart = now - this.config.requestWindowMs;
    const requestsInWindow = this.requestHistory.filter(
      (time) => time > windowStart,
    ).length;

    return {
      globalRateLimitActive: now < this.globalRateLimitUntil,
      globalRateLimitUntil: this.globalRateLimitUntil,
      endpointLimits: Array.from(this.endpointLimits.entries()).map(
        ([endpoint, limitUntil]) => ({
          endpoint,
          limitUntil,
        }),
      ),
      requestsInWindow,
      canMakeRequest: this.canMakeRequestNow(),
    };
  }

  /**
   * Get advanced components status and configuration
   * Enhanced with BackoffStrategy status
   */
  getAdvancedComponentsStatus(): {
    enabled: boolean;
    tokenBucket: {
      enabled: boolean;
      initialized: boolean;
      state?: {
        tokens: number;
        lastRefill: number;
        totalConsumed: number;
        totalRequested: number;
      };
      statistics?: {
        config: {
          capacity: number;
          refillRate: number;
          safetyMargin: number;
        };
        state: {
          tokens: number;
          lastRefill: number;
          totalConsumed: number;
          totalRequested: number;
        };
        stats: {
          successRate: number;
          averageTokensPerSecond: number;
          utilizationRate: number;
        };
      };
    };
    headerParsing: {
      enabled: boolean;
      lastParsedInfo?: ParsedRateLimitInfo;
    };
    backoffStrategy: {
      enabled: boolean;
      initialized: boolean;
      config?: BackoffConfig;
      useServerGuidedDelay: boolean;
    };
    featureFlags: {
      enableAdvancedComponents: boolean;
      tokenBucketEnabled: boolean;
      headerParsingEnabled: boolean;
      backoffStrategyEnabled: boolean;
    };
  } {
    const tokenBucketEnabled =
      this.config.enableAdvancedComponents && this.config.tokenBucket?.enabled;

    const backoffStrategyEnabled =
      this.config.enableAdvancedComponents &&
      this.config.backoffStrategy?.enabled;

    return {
      enabled: !!this.config.enableAdvancedComponents,
      tokenBucket: {
        enabled: !!tokenBucketEnabled,
        initialized: !!this.tokenBucket,
        state: this.tokenBucket?.getState(),
        statistics: this.tokenBucket?.getStatistics(),
      },
      headerParsing: {
        enabled: !!(
          this.config.enableAdvancedComponents &&
          this.config.headerParsing?.enabled
        ),
        lastParsedInfo: this.lastKnownRateLimit,
      },
      backoffStrategy: {
        enabled: !!backoffStrategyEnabled,
        initialized: !!this.backoffStrategy,
        config: this.backoffStrategy?.getConfig(),
        useServerGuidedDelay:
          !!this.config.backoffStrategy?.useServerGuidedDelay,
      },
      featureFlags: {
        enableAdvancedComponents: !!this.config.enableAdvancedComponents,
        tokenBucketEnabled: !!tokenBucketEnabled,
        headerParsingEnabled: !!(
          this.config.enableAdvancedComponents &&
          this.config.headerParsing?.enabled
        ),
        backoffStrategyEnabled: !!backoffStrategyEnabled,
      },
    };
  }
}

// Default configuration for Make.com API with advanced features
export const MAKE_API_RATE_LIMIT_CONFIG: RateLimitConfig = {
  // Base configuration
  maxRetries: 3,
  baseDelayMs: 2000, // Start with 2 second delay
  maxDelayMs: 300000, // Max 5 minutes
  backoffMultiplier: 2.5,
  maxConcurrentRequests: 8, // Conservative for Make.com
  requestWindowMs: 60000, // 1 minute window
  requestsPerWindow: 50, // Conservative request limit
  maxQueueSize: 500,
  queueTimeoutMs: 600000, // 10 minutes queue timeout
  enableMetrics: true,
  alertThresholdMs: 60000, // Alert if delays exceed 1 minute

  // Advanced features configuration for Make.com
  enableAdvancedComponents: true,
  tokenBucket: {
    enabled: true,
    safetyMargin: 0.8, // Use 80% of available rate limit for conservative operation
    synchronizeWithHeaders: true,
    initialCapacity: 40, // 80% of 50 requests per window for safety
    initialRefillRate: 0.67, // 40 requests / 60 seconds = ~0.67 requests per second
  },
  headerParsing: {
    enabled: true,
    preferServerHeaders: true, // Always prefer server-provided rate limit headers
  },
  backoffStrategy: {
    enabled: true,
    baseDelay: 2000, // 2 second base delay for Make.com API
    maxDelay: 300000, // 5 minutes max delay
    maxRetries: 3, // 3 retry attempts
    jitterFactor: 0.15, // 15% jitter for Make.com API (higher spread)
    useServerGuidedDelay: true, // Always use Retry-After headers when available
    backoffMultiplier: 2.5, // Match the existing configuration
  },
};

// Backward compatibility configuration (legacy behavior)
export const LEGACY_MAKE_API_RATE_LIMIT_CONFIG: RateLimitConfig = {
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
  // Disable advanced features for legacy compatibility
  enableAdvancedComponents: false,
  backoffStrategy: {
    enabled: false,
    baseDelay: 2000,
    maxDelay: 300000,
    maxRetries: 3,
    jitterFactor: 0.1,
    useServerGuidedDelay: false,
    backoffMultiplier: 2.5,
  },
};
