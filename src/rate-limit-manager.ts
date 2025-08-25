/**
 * Rate Limit Management System for Make.com API
 * Implements intelligent request throttling and backoff strategies
 */

import { performance } from "perf_hooks";
import { v4 as uuidv4 } from "uuid";
import winston from "winston";

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

    // Initialize logger
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

    // Start queue processor
    this.startQueueProcessor();

    // Clean up old request history every minute
    setInterval(() => {
      this.cleanupRequestHistory();
    }, 60000);
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
    // Check global rate limit
    if (Date.now() < this.globalRateLimitUntil) {
      return false;
    }

    // Check endpoint-specific rate limit
    if (endpoint) {
      const endpointLimit = this.endpointLimits.get(endpoint);
      if (endpointLimit && Date.now() < endpointLimit) {
        return false;
      }
    }

    // Check concurrent request limit
    if (this.activeRequests >= this.config.maxConcurrentRequests) {
      return false;
    }

    // Check request window limit
    const now = Date.now();
    const windowStart = now - this.config.requestWindowMs;
    const recentRequests = this.requestHistory.filter(
      (time) => time > windowStart,
    );

    if (recentRequests.length >= this.config.requestsPerWindow) {
      return false;
    }

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

        // Retry with exponential backoff if we haven't exceeded max retries
        if (retryCount < this.config.maxRetries) {
          const delayMs = this.calculateBackoffDelay(retryCount, rateLimitInfo);

          console.warn(
            `Rate limited for operation ${operation}, retrying in ${delayMs}ms (attempt ${retryCount + 1}/${this.config.maxRetries})`,
            {
              correlationId,
              operation,
              retryCount,
              delayMs,
            },
          );

          await this.sleep(delayMs);
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
   * Extract rate limit information from error response
   */
  private extractRateLimitInfo(error: unknown): RateLimitInfo {
    if (!error || typeof error !== "object") {
      return { isRateLimited: true };
    }

    const errorObj = error as Record<string, unknown>;
    const response = errorObj.response as Record<string, unknown> | undefined;
    const headers = (response?.headers as Record<string, string>) || {};

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
   */
  private handleRateLimit(
    rateLimitInfo: RateLimitInfo,
    correlationId: string,
  ): void {
    this.metrics.rateLimitedRequests++;

    const now = Date.now();
    const waitTimeMs = rateLimitInfo.retryAfterMs || this.config.baseDelayMs;

    // Update global rate limit
    this.globalRateLimitUntil = Math.max(
      this.globalRateLimitUntil,
      now + waitTimeMs,
    );

    console.warn("Rate limit detected and handled", {
      correlationId,
      waitTimeMs,
      remainingRequests: rateLimitInfo.remainingRequests,
      resetTimeMs: rateLimitInfo.resetTimeMs,
      quotaType: rateLimitInfo.quotaType,
    });

    // Trigger alert if delay is significant
    if (waitTimeMs > this.config.alertThresholdMs) {
      console.error("Significant rate limit delay detected", {
        correlationId,
        delayMs: waitTimeMs,
        thresholdMs: this.config.alertThresholdMs,
      });
    }
  }

  /**
   * Calculate exponential backoff delay
   */
  private calculateBackoffDelay(
    retryCount: number,
    rateLimitInfo: RateLimitInfo,
  ): number {
    // Use provided retry-after if available
    if (rateLimitInfo.retryAfterMs) {
      return Math.min(rateLimitInfo.retryAfterMs, this.config.maxDelayMs);
    }

    // Calculate exponential backoff
    const exponentialDelay =
      this.config.baseDelayMs *
      Math.pow(this.config.backoffMultiplier, retryCount);

    // Add jitter to prevent thundering herd
    const jitter = Math.random() * 1000;

    return Math.min(exponentialDelay + jitter, this.config.maxDelayMs);
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
   */
  getMetrics(): RateLimitMetrics {
    return {
      ...this.metrics,
      queueSize: this.requestQueue.length,
      activeRequests: this.activeRequests,
    };
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
   */
  updateConfig(updates: Partial<RateLimitConfig>): void {
    this.config = { ...this.config, ...updates };
    this.logger.info("Rate limit configuration updated", updates);
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
}

// Default configuration for Make.com API
export const MAKE_API_RATE_LIMIT_CONFIG: RateLimitConfig = {
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
};
