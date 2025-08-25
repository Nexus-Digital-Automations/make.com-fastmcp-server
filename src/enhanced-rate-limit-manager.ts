/**
 * Enhanced Rate Limit Manager
 * Extends the base RateLimitManager with advanced TokenBucket integration
 * for superior pre-emptive rate limiting capabilities
 */

import { performance } from "perf_hooks";
import { v4 as uuidv4 } from "uuid";
import winston from "winston";

// Base rate limiting components
import { RateLimitManager, RateLimitConfig } from "./rate-limit-manager";
import { TokenBucket } from "./rate-limiting/token-bucket";
import { RateLimitParser } from "./rate-limiting/rate-limit-parser";

/**
 * Enhanced configuration interface extending base RateLimitConfig
 */
export interface EnhancedRateLimitConfig extends RateLimitConfig {
  // Enhanced TokenBucket configuration
  safetyMargin?: number; // Default 0.85 (85% utilization)
  dynamicCapacity?: boolean; // Update capacity from API headers
  preemptiveThreshold?: number; // Start queuing at this utilization level (0.9 = 90%)

  // Enhanced monitoring
  metricsCollection?: {
    detailed: boolean; // Collect detailed timing metrics
    historySize: number; // Number of historical data points to keep
  };

  // Adaptive behavior
  adaptiveSafetyMargin?: boolean; // Adjust safety margin based on API behavior
  learningMode?: boolean; // Learn from API responses to optimize parameters
}

/**
 * Enhanced metrics interface with additional TokenBucket insights
 */
export interface EnhancedRateLimitMetrics {
  // Base metrics (inherited)
  totalRequests: number;
  rateLimitedRequests: number;
  averageDelayMs: number;
  maxDelayMs: number;
  queueSize: number;
  activeRequests: number;
  successRate: number;
  lastResetTime: Date;

  // Enhanced TokenBucket metrics
  tokenBucket: {
    availableTokens: number;
    capacity: number;
    utilizationRate: number;
    safetyMarginActive: boolean;
    timeUntilNextToken: number;
    tokensConsumedPerSecond: number;
    preemptiveBlockCount: number;
  };

  // Performance insights
  performance: {
    averageResponseTime: number;
    p95ResponseTime: number;
    p99ResponseTime: number;
    requestsPerSecond: number;
    rateLimitAvoidanceRate: number; // % of requests that avoided rate limiting
  };

  // Adaptive learning metrics
  adaptive?: {
    currentSafetyMargin: number;
    adjustmentCount: number;
    lastAdjustment: Date;
    effectivenessScore: number; // How well the current settings perform
  };
}

/**
 * Enhanced Rate Limit Manager with superior pre-emptive rate limiting
 *
 * Key enhancements over base RateLimitManager:
 * - More intelligent pre-emptive token consumption
 * - Adaptive safety margin based on API behavior
 * - Enhanced metrics and monitoring
 * - Better integration with dynamic API rate limits
 * - Predictive rate limiting based on historical patterns
 */
export class EnhancedRateLimitManager extends RateLimitManager {
  private enhancedConfig: EnhancedRateLimitConfig;
  private tokenBucket: TokenBucket;
  private logger: winston.Logger;

  // Enhanced tracking
  private responseTimes: number[] = [];
  private preemptiveBlockCount = 0;
  private adaptiveMetrics = {
    adjustmentCount: 0,
    lastAdjustment: new Date(),
    effectivenessScore: 1.0,
    currentSafetyMargin: 0.85,
  };

  constructor(config: EnhancedRateLimitConfig) {
    // Initialize base RateLimitManager with enhanced configuration
    const baseConfig: RateLimitConfig = {
      ...config,
      // Ensure advanced components are enabled for TokenBucket integration
      enableAdvancedComponents: true,
      tokenBucket: {
        enabled: true,
        safetyMargin: config.safetyMargin || 0.85,
        synchronizeWithHeaders: true,
        initialCapacity: config.requestsPerWindow,
        initialRefillRate:
          config.requestsPerWindow / (config.requestWindowMs / 1000),
      },
      headerParsing: {
        enabled: true,
        preferServerHeaders: true,
      },
    };

    super(baseConfig);

    this.enhancedConfig = {
      // Default enhanced configuration
      safetyMargin: 0.85, // Use 85% of available capacity
      dynamicCapacity: true,
      preemptiveThreshold: 0.9, // Start being more conservative at 90% utilization
      metricsCollection: {
        detailed: true,
        historySize: 1000,
      },
      adaptiveSafetyMargin: true,
      learningMode: true,
      ...config,
    };

    // Initialize enhanced TokenBucket
    this.initializeEnhancedTokenBucket();

    // Initialize enhanced logger
    this.logger = winston.createLogger({
      level: "info",
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json(),
      ),
      defaultMeta: { component: "EnhancedRateLimitManager" },
      transports: [
        new winston.transports.Console({
          silent: process.env.NODE_ENV === "test",
        }),
      ],
    });

    const operationId = uuidv4();
    this.logger.info(
      `[${operationId}] Enhanced Rate Limit Manager initialized`,
      {
        operationId,
        config: {
          safetyMargin: this.enhancedConfig.safetyMargin,
          dynamicCapacity: this.enhancedConfig.dynamicCapacity,
          preemptiveThreshold: this.enhancedConfig.preemptiveThreshold,
          adaptiveSafetyMargin: this.enhancedConfig.adaptiveSafetyMargin,
          learningMode: this.enhancedConfig.learningMode,
        },
        tokenBucketState: this.tokenBucket.getState(),
      },
    );

    // Start adaptive learning if enabled
    if (this.enhancedConfig.adaptiveSafetyMargin) {
      this.startAdaptiveLearning();
    }
  }

  /**
   * Initialize enhanced TokenBucket with optimized configuration
   */
  private initializeEnhancedTokenBucket(): void {
    const operationId = uuidv4();

    this.logger.debug(`[${operationId}] Initializing enhanced TokenBucket`, {
      operationId,
      requestsPerWindow: this.enhancedConfig.requestsPerWindow,
      requestWindowMs: this.enhancedConfig.requestWindowMs,
      safetyMargin: this.enhancedConfig.safetyMargin,
    });

    // Calculate optimal token bucket parameters
    const refillRate =
      this.enhancedConfig.requestsPerWindow /
      (this.enhancedConfig.requestWindowMs / 1000);
    const capacity = Math.max(10, this.enhancedConfig.requestsPerWindow);

    this.tokenBucket = new TokenBucket({
      capacity,
      refillRate,
      safetyMargin: this.enhancedConfig.safetyMargin || 0.85,
    });

    this.logger.info(
      `[${operationId}] Enhanced TokenBucket initialized successfully`,
      {
        operationId,
        capacity,
        refillRate,
        safetyMargin: this.enhancedConfig.safetyMargin,
        initialState: this.tokenBucket.getState(),
      },
    );
  }

  /**
   * Enhanced pre-emptive request validation using TokenBucket
   * Overrides base implementation with more intelligent logic
   */
  protected canMakeRequestNow(endpoint?: string): boolean {
    const operationId = uuidv4();
    const startTime = performance.now();

    this.logger.debug(`[${operationId}] Starting enhanced rate limit check`, {
      operationId,
      endpoint,
      timestamp: new Date().toISOString(),
    });

    // First, check base constraints (concurrent requests, global limits, etc.)
    if (!super.canMakeRequestNow(endpoint)) {
      this.logger.debug(
        `[${operationId}] Request blocked by base rate limit constraints`,
        {
          operationId,
          checkDuration: performance.now() - startTime,
        },
      );
      return false;
    }

    // Enhanced: Pre-emptive TokenBucket check with dynamic thresholds
    const tokenState = this.tokenBucket.getState();
    const currentUtilization = this.calculateUtilization(tokenState);

    // Apply pre-emptive threshold logic
    if (
      currentUtilization >= (this.enhancedConfig.preemptiveThreshold || 0.9)
    ) {
      const timeUntilTokens = this.tokenBucket.getTimeUntilTokensAvailable(1);

      if (timeUntilTokens > 0) {
        this.preemptiveBlockCount++;

        this.logger.info(
          `[${operationId}] Request pre-emptively blocked by enhanced TokenBucket`,
          {
            operationId,
            currentUtilization,
            preemptiveThreshold: this.enhancedConfig.preemptiveThreshold,
            timeUntilTokensMs: timeUntilTokens,
            tokenState,
            preemptiveBlockCount: this.preemptiveBlockCount,
          },
        );

        return false;
      }
    }

    // Attempt to consume token with enhanced safety checks
    const tokenConsumed = this.tokenBucket.tryConsume(1);

    if (!tokenConsumed) {
      const timeUntilTokens = this.tokenBucket.getTimeUntilTokensAvailable(1);

      this.logger.debug(
        `[${operationId}] TokenBucket rejected request - insufficient tokens`,
        {
          operationId,
          tokenState: this.tokenBucket.getState(),
          timeUntilTokensMs: timeUntilTokens,
          currentSafetyMargin: this.adaptiveMetrics.currentSafetyMargin,
        },
      );

      return false;
    }

    this.logger.debug(`[${operationId}] Enhanced rate limit check passed`, {
      operationId,
      endpoint,
      tokenState: this.tokenBucket.getState(),
      currentUtilization,
      checkDuration: performance.now() - startTime,
    });

    return true;
  }

  /**
   * Calculate current utilization rate of the TokenBucket
   */
  private calculateUtilization(tokenState: {
    tokens: number;
    lastRefill: number;
    totalConsumed: number;
    totalRequested: number;
  }): number {
    const maxUsableTokens = Math.floor(
      this.tokenBucket.getStatistics().config.capacity *
        this.adaptiveMetrics.currentSafetyMargin,
    );
    return maxUsableTokens > 0
      ? (maxUsableTokens - tokenState.tokens) / maxUsableTokens
      : 0;
  }

  /**
   * Enhanced request execution with detailed performance tracking
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
    const correlationId = options.correlationId || operationId;
    const startTime = performance.now();

    this.logger.info(
      `[${operationId}] Starting enhanced rate-limited request execution`,
      {
        operationId,
        correlationId,
        operation,
        endpoint: options.endpoint,
        priority: options.priority || "normal",
        tokenBucketState: this.tokenBucket.getState(),
      },
    );

    try {
      // Execute using base implementation with enhanced error handling
      const result = await super.executeWithRateLimit(
        operation,
        requestFn,
        options,
      );

      // Track successful execution metrics
      const duration = performance.now() - startTime;
      this.trackResponseTime(duration);

      this.logger.info(
        `[${operationId}] Enhanced rate-limited request completed successfully`,
        {
          operationId,
          correlationId,
          duration,
          operation,
          tokenBucketState: this.tokenBucket.getState(),
        },
      );

      return result;
    } catch (error) {
      const duration = performance.now() - startTime;
      this.trackResponseTime(duration, false);

      // Enhanced error analysis and learning
      if (this.isRateLimitError(error)) {
        await this.handleEnhancedRateLimit(error, correlationId, operationId);
      }

      this.logger.error(
        `[${operationId}] Enhanced rate-limited request failed`,
        {
          operationId,
          correlationId,
          duration,
          operation,
          error: error instanceof Error ? error.message : String(error),
          tokenBucketState: this.tokenBucket.getState(),
        },
      );

      throw error;
    }
  }

  /**
   * Enhanced rate limit error handling with learning capabilities
   */
  private async handleEnhancedRateLimit(
    error: unknown,
    correlationId: string,
    operationId: string,
  ): Promise<void> {
    this.logger.warn(`[${operationId}] Enhanced rate limit error detected`, {
      operationId,
      correlationId,
      error: error instanceof Error ? error.message : String(error),
    });

    // Extract enhanced rate limit information
    const errorObj = error as Record<string, unknown>;
    const response = errorObj.response as Record<string, unknown> | undefined;
    const headers = (response?.headers as Record<string, string>) || {};

    // Parse rate limit headers for enhanced learning
    const parsedInfo = RateLimitParser.parseHeaders(headers);

    if (parsedInfo) {
      // Update TokenBucket with real API data
      const windowSeconds = parsedInfo.window || 3600;
      this.tokenBucket.updateFromRateLimit(
        parsedInfo.limit,
        parsedInfo.remaining,
        windowSeconds,
      );

      this.logger.info(
        `[${operationId}] TokenBucket synchronized with API rate limit headers`,
        {
          operationId,
          parsedInfo,
          tokenBucketState: this.tokenBucket.getState(),
        },
      );

      // Adaptive learning: adjust safety margin if needed
      if (this.enhancedConfig.learningMode) {
        this.learnFromRateLimit(parsedInfo, operationId);
      }
    }
  }

  /**
   * Learn from rate limit responses to optimize future behavior
   */
  private learnFromRateLimit(
    rateLimitInfo: {
      limit: number;
      remaining: number;
      reset: number;
      window?: number;
    },
    operationId: string,
  ): void {
    if (!this.enhancedConfig.adaptiveSafetyMargin) {
      return;
    }

    // Calculate how close we were to the actual limit
    const utilizationAtRateLimit =
      (rateLimitInfo.limit - rateLimitInfo.remaining) / rateLimitInfo.limit;

    // If we got rate limited while being conservative, we need to be even more conservative
    if (utilizationAtRateLimit > this.adaptiveMetrics.currentSafetyMargin) {
      this.adaptiveMetrics.currentSafetyMargin = Math.max(
        0.6,
        this.adaptiveMetrics.currentSafetyMargin * 0.9,
      );
      this.adaptiveMetrics.adjustmentCount++;
      this.adaptiveMetrics.lastAdjustment = new Date();

      // Update TokenBucket with new safety margin
      this.tokenBucket.updateConfig({
        safetyMargin: this.adaptiveMetrics.currentSafetyMargin,
      });

      this.logger.info(
        `[${operationId}] Adaptive safety margin decreased for better rate limit avoidance`,
        {
          operationId,
          newSafetyMargin: this.adaptiveMetrics.currentSafetyMargin,
          utilizationAtRateLimit,
          adjustmentCount: this.adaptiveMetrics.adjustmentCount,
        },
      );
    }
  }

  /**
   * Track response times for performance metrics
   */
  private trackResponseTime(duration: number, _success: boolean = true): void {
    if (!this.enhancedConfig.metricsCollection?.detailed) {
      return;
    }

    this.responseTimes.push(duration);

    // Maintain history size limit
    const historySize =
      this.enhancedConfig.metricsCollection?.historySize || 1000;
    if (this.responseTimes.length > historySize) {
      this.responseTimes = this.responseTimes.slice(-historySize);
    }
  }

  /**
   * Start adaptive learning process
   */
  private startAdaptiveLearning(): void {
    // Check every 5 minutes for optimization opportunities
    setInterval(() => {
      this.performAdaptiveTuning();
    }, 300000);

    this.logger.info(
      "Adaptive learning started for Enhanced Rate Limit Manager",
      {
        interval: "5 minutes",
        currentSafetyMargin: this.adaptiveMetrics.currentSafetyMargin,
      },
    );
  }

  /**
   * Perform adaptive tuning based on collected metrics
   */
  private performAdaptiveTuning(): void {
    const operationId = uuidv4();
    const now = new Date();
    const timeSinceLastAdjustment =
      now.getTime() - this.adaptiveMetrics.lastAdjustment.getTime();

    // Only adjust if we haven't adjusted recently and have enough data
    if (timeSinceLastAdjustment < 600000 || this.responseTimes.length < 100) {
      // 10 minutes minimum
      return;
    }

    const currentMetrics = this.getEnhancedMetrics();
    const currentSuccessRate = currentMetrics.successRate;
    const currentUtilization = currentMetrics.tokenBucket.utilizationRate;

    // If we're being too conservative (very low utilization, high success rate), relax safety margin
    if (
      currentSuccessRate > 0.98 &&
      currentUtilization < 0.5 &&
      this.adaptiveMetrics.currentSafetyMargin < 0.9
    ) {
      this.adaptiveMetrics.currentSafetyMargin = Math.min(
        0.9,
        this.adaptiveMetrics.currentSafetyMargin * 1.05,
      );
      this.tokenBucket.updateConfig({
        safetyMargin: this.adaptiveMetrics.currentSafetyMargin,
      });

      this.logger.info(
        `[${operationId}] Adaptive safety margin increased for better throughput`,
        {
          operationId,
          newSafetyMargin: this.adaptiveMetrics.currentSafetyMargin,
          successRate: currentSuccessRate,
          utilization: currentUtilization,
        },
      );

      this.adaptiveMetrics.adjustmentCount++;
      this.adaptiveMetrics.lastAdjustment = now;
    }
  }

  /**
   * Get enhanced metrics including detailed TokenBucket and performance insights
   */
  getEnhancedMetrics(): EnhancedRateLimitMetrics {
    const baseMetrics = super.getMetrics();
    const tokenStats = this.tokenBucket.getStatistics();
    const tokenState = this.tokenBucket.getState();

    // Calculate performance metrics
    const avgResponseTime =
      this.responseTimes.length > 0
        ? this.responseTimes.reduce((a, b) => a + b, 0) /
          this.responseTimes.length
        : 0;

    const sortedTimes = [...this.responseTimes].sort((a, b) => a - b);
    const p95ResponseTime =
      sortedTimes.length > 0
        ? sortedTimes[Math.floor(sortedTimes.length * 0.95)]
        : 0;
    const p99ResponseTime =
      sortedTimes.length > 0
        ? sortedTimes[Math.floor(sortedTimes.length * 0.99)]
        : 0;

    const requestsPerSecond =
      this.responseTimes.length > 0 && this.responseTimes.length > 1
        ? this.responseTimes.length /
          ((Date.now() - (Date.now() - this.responseTimes.length * 1000)) /
            1000)
        : 0;

    // Calculate rate limit avoidance rate
    const totalRequestAttempts =
      baseMetrics.totalRequests + this.preemptiveBlockCount;
    const rateLimitAvoidanceRate =
      totalRequestAttempts > 0
        ? (totalRequestAttempts - baseMetrics.rateLimitedRequests) /
          totalRequestAttempts
        : 1.0;

    const enhancedMetrics: EnhancedRateLimitMetrics = {
      ...baseMetrics,
      tokenBucket: {
        availableTokens: tokenState.tokens,
        capacity: tokenStats.config.capacity,
        utilizationRate: tokenStats.stats.utilizationRate,
        safetyMarginActive:
          tokenState.tokens <
          tokenStats.config.capacity * tokenStats.config.safetyMargin,
        timeUntilNextToken: this.tokenBucket.getTimeUntilTokensAvailable(1),
        tokensConsumedPerSecond: tokenStats.stats.averageTokensPerSecond,
        preemptiveBlockCount: this.preemptiveBlockCount,
      },
      performance: {
        averageResponseTime: avgResponseTime,
        p95ResponseTime,
        p99ResponseTime,
        requestsPerSecond,
        rateLimitAvoidanceRate,
      },
    };

    // Add adaptive metrics if enabled
    if (this.enhancedConfig.adaptiveSafetyMargin) {
      enhancedMetrics.adaptive = {
        currentSafetyMargin: this.adaptiveMetrics.currentSafetyMargin,
        adjustmentCount: this.adaptiveMetrics.adjustmentCount,
        lastAdjustment: this.adaptiveMetrics.lastAdjustment,
        effectivenessScore: this.adaptiveMetrics.effectivenessScore,
      };
    }

    return enhancedMetrics;
  }

  /**
   * Update enhanced configuration at runtime
   */
  updateEnhancedConfig(updates: Partial<EnhancedRateLimitConfig>): void {
    const operationId = uuidv4();

    this.logger.info(
      `[${operationId}] Updating enhanced rate limit configuration`,
      {
        operationId,
        updates,
      },
    );

    this.enhancedConfig = { ...this.enhancedConfig, ...updates };

    // Update base configuration as well
    super.updateConfig(updates);

    // Update TokenBucket if safety margin changed
    if (updates.safetyMargin !== undefined) {
      this.adaptiveMetrics.currentSafetyMargin = updates.safetyMargin;
      this.tokenBucket.updateConfig({ safetyMargin: updates.safetyMargin });

      this.logger.info(`[${operationId}] TokenBucket safety margin updated`, {
        operationId,
        newSafetyMargin: updates.safetyMargin,
        tokenBucketState: this.tokenBucket.getState(),
      });
    }

    // Reinitialize TokenBucket if major parameters changed
    if (
      updates.requestsPerWindow !== undefined ||
      updates.requestWindowMs !== undefined
    ) {
      this.initializeEnhancedTokenBucket();

      this.logger.info(
        `[${operationId}] TokenBucket reinitialized due to capacity/rate changes`,
        {
          operationId,
          newTokenBucketState: this.tokenBucket.getState(),
        },
      );
    }
  }

  /**
   * Get comprehensive status including enhanced components
   */
  getEnhancedStatus(): {
    base: any;
    enhanced: {
      tokenBucket: any;
      adaptiveMetrics: typeof this.adaptiveMetrics;
      performance: {
        responseTimeHistory: number;
        preemptiveBlockCount: number;
        currentUtilization: number;
      };
      config: EnhancedRateLimitConfig;
    };
  } {
    const baseStatus = super.getAdvancedComponentsStatus();
    const tokenState = this.tokenBucket.getState();
    const currentUtilization = this.calculateUtilization(tokenState);

    return {
      base: baseStatus,
      enhanced: {
        tokenBucket: {
          ...this.tokenBucket.getStatistics(),
          state: tokenState,
        },
        adaptiveMetrics: { ...this.adaptiveMetrics },
        performance: {
          responseTimeHistory: this.responseTimes.length,
          preemptiveBlockCount: this.preemptiveBlockCount,
          currentUtilization,
        },
        config: { ...this.enhancedConfig },
      },
    };
  }

  /**
   * Force synchronization with latest API rate limit information
   */
  synchronizeWithApiLimits(
    limit: number,
    remaining: number,
    windowSeconds: number = 3600,
  ): void {
    const operationId = uuidv4();

    this.logger.info(
      `[${operationId}] Forcing TokenBucket synchronization with API limits`,
      {
        operationId,
        limit,
        remaining,
        windowSeconds,
        beforeState: this.tokenBucket.getState(),
      },
    );

    this.tokenBucket.updateFromRateLimit(limit, remaining, windowSeconds);

    this.logger.info(`[${operationId}] TokenBucket synchronized successfully`, {
      operationId,
      afterState: this.tokenBucket.getState(),
      statistics: this.tokenBucket.getStatistics(),
    });
  }
}

/**
 * Factory function for creating EnhancedRateLimitManager with common configurations
 */
export class EnhancedRateLimitManagerFactory {
  /**
   * Create a conservative configuration optimized for reliability
   */
  static createConservative(
    baseConfig: Partial<EnhancedRateLimitConfig> = {},
  ): EnhancedRateLimitManager {
    const config: EnhancedRateLimitConfig = {
      maxRetries: 3,
      baseDelayMs: 2000,
      maxDelayMs: 300000,
      backoffMultiplier: 2.5,
      maxConcurrentRequests: 5,
      requestWindowMs: 60000,
      requestsPerWindow: 30,
      maxQueueSize: 200,
      queueTimeoutMs: 600000,
      enableMetrics: true,
      alertThresholdMs: 30000,
      safetyMargin: 0.75, // Very conservative
      dynamicCapacity: true,
      preemptiveThreshold: 0.8, // Block early
      adaptiveSafetyMargin: true,
      learningMode: true,
      ...baseConfig,
    };

    return new EnhancedRateLimitManager(config);
  }

  /**
   * Create a balanced configuration optimized for performance and reliability
   */
  static createBalanced(
    baseConfig: Partial<EnhancedRateLimitConfig> = {},
  ): EnhancedRateLimitManager {
    const config: EnhancedRateLimitConfig = {
      maxRetries: 3,
      baseDelayMs: 1500,
      maxDelayMs: 300000,
      backoffMultiplier: 2,
      maxConcurrentRequests: 8,
      requestWindowMs: 60000,
      requestsPerWindow: 50,
      maxQueueSize: 500,
      queueTimeoutMs: 600000,
      enableMetrics: true,
      alertThresholdMs: 60000,
      safetyMargin: 0.85, // Balanced safety
      dynamicCapacity: true,
      preemptiveThreshold: 0.9, // Standard threshold
      adaptiveSafetyMargin: true,
      learningMode: true,
      ...baseConfig,
    };

    return new EnhancedRateLimitManager(config);
  }

  /**
   * Create an aggressive configuration optimized for maximum throughput
   */
  static createAggressive(
    baseConfig: Partial<EnhancedRateLimitConfig> = {},
  ): EnhancedRateLimitManager {
    const config: EnhancedRateLimitConfig = {
      maxRetries: 4,
      baseDelayMs: 1000,
      maxDelayMs: 180000,
      backoffMultiplier: 1.8,
      maxConcurrentRequests: 12,
      requestWindowMs: 60000,
      requestsPerWindow: 80,
      maxQueueSize: 1000,
      queueTimeoutMs: 300000,
      enableMetrics: true,
      alertThresholdMs: 90000,
      safetyMargin: 0.92, // More aggressive
      dynamicCapacity: true,
      preemptiveThreshold: 0.95, // Allow higher utilization
      adaptiveSafetyMargin: true,
      learningMode: true,
      ...baseConfig,
    };

    return new EnhancedRateLimitManager(config);
  }
}

// Export default configuration for Make.com API with enhanced features
export const ENHANCED_MAKE_API_CONFIG: EnhancedRateLimitConfig = {
  // Base configuration optimized for Make.com
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

  // Enhanced features
  safetyMargin: 0.85, // Use 85% of available capacity
  dynamicCapacity: true,
  preemptiveThreshold: 0.9,
  metricsCollection: {
    detailed: true,
    historySize: 1000,
  },
  adaptiveSafetyMargin: true,
  learningMode: true,

  // Advanced components (inherited from base)
  enableAdvancedComponents: true,
  tokenBucket: {
    enabled: true,
    safetyMargin: 0.85,
    synchronizeWithHeaders: true,
  },
  headerParsing: {
    enabled: true,
    preferServerHeaders: true,
  },
};
