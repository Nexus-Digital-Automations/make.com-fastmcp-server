/**
 * Backoff Strategy Implementation
 * Provides intelligent backoff algorithms for rate limit retry logic
 */

import { RateLimitInfo } from "./rate-limit-parser.js";

export interface BackoffConfig {
  baseDelay: number; // Initial delay in milliseconds
  maxDelay: number; // Maximum delay in milliseconds
  maxRetries: number; // Maximum number of retry attempts
  jitterFactor: number; // Jitter percentage (0.1 = 10%)
  backoffMultiplier: number; // Exponential backoff multiplier (default: 2)
}

export interface BackoffResult {
  delay: number; // Calculated delay in milliseconds
  attempt: number; // Current attempt number
  shouldRetry: boolean; // Whether to attempt retry
  reason: string; // Reason for delay calculation
}

export class BackoffStrategy {
  constructor(private config: BackoffConfig) {}

  /**
   * Calculate delay for exponential backoff with jitter
   */
  calculateDelay(
    attempt: number,
    customConfig?: Partial<BackoffConfig>,
  ): BackoffResult {
    const effectiveConfig = { ...this.config, ...customConfig };

    // Check if we've exceeded max retries
    if (attempt >= effectiveConfig.maxRetries) {
      return {
        delay: 0,
        attempt,
        shouldRetry: false,
        reason: `Maximum retries (${effectiveConfig.maxRetries}) exceeded`,
      };
    }

    // Calculate exponential backoff delay
    const exponentialDelay = Math.min(
      effectiveConfig.baseDelay *
        Math.pow(effectiveConfig.backoffMultiplier, attempt),
      effectiveConfig.maxDelay,
    );

    // Add jitter to prevent thundering herd effect
    const jitter =
      exponentialDelay * effectiveConfig.jitterFactor * (Math.random() - 0.5);
    const finalDelay = Math.max(0, Math.floor(exponentialDelay + jitter));

    return {
      delay: finalDelay,
      attempt: attempt + 1,
      shouldRetry: true,
      reason: `Exponential backoff (attempt ${attempt + 1}/${effectiveConfig.maxRetries})`,
    };
  }

  /**
   * Calculate delay based on rate limit headers
   */
  calculateFromRateLimit(
    rateLimitInfo: RateLimitInfo,
    attempt: number = 0,
    customConfig?: Partial<BackoffConfig>,
  ): BackoffResult {
    const effectiveConfig = { ...this.config, ...customConfig };

    // Check max retries first
    if (attempt >= effectiveConfig.maxRetries) {
      return {
        delay: 0,
        attempt,
        shouldRetry: false,
        reason: `Maximum retries (${effectiveConfig.maxRetries}) exceeded`,
      };
    }

    // Use Retry-After header if available (most authoritative)
    if (rateLimitInfo.retryAfter && rateLimitInfo.retryAfter > 0) {
      const retryAfterMs = rateLimitInfo.retryAfter * 1000;
      const cappedDelay = Math.min(retryAfterMs, effectiveConfig.maxDelay);

      return {
        delay: cappedDelay,
        attempt: attempt + 1,
        shouldRetry: true,
        reason: `Server-specified retry-after: ${rateLimitInfo.retryAfter}s`,
      };
    }

    // Use reset time if available
    if (rateLimitInfo.reset && rateLimitInfo.reset > 0) {
      const currentTime = Math.floor(Date.now() / 1000);
      const timeUntilReset = Math.max(0, rateLimitInfo.reset - currentTime);
      const resetDelayMs = Math.min(
        timeUntilReset * 1000,
        effectiveConfig.maxDelay,
      );

      if (resetDelayMs > 0) {
        return {
          delay: resetDelayMs,
          attempt: attempt + 1,
          shouldRetry: true,
          reason: `Waiting for rate limit reset: ${timeUntilReset}s`,
        };
      }
    }

    // Use resetAfter if available
    if (rateLimitInfo.resetAfter && rateLimitInfo.resetAfter > 0) {
      const resetAfterMs = Math.min(
        rateLimitInfo.resetAfter * 1000,
        effectiveConfig.maxDelay,
      );

      return {
        delay: resetAfterMs,
        attempt: attempt + 1,
        shouldRetry: true,
        reason: `Waiting for rate limit reset: ${rateLimitInfo.resetAfter}s`,
      };
    }

    // Fall back to exponential backoff
    return this.calculateDelay(attempt, customConfig);
  }

  /**
   * Calculate delay with rate limit context awareness
   */
  calculateAdaptiveDelay(
    attempt: number,
    rateLimitInfo?: RateLimitInfo,
    errorType?:
      | "rate_limit"
      | "server_error"
      | "timeout"
      | "client_error"
      | "unknown",
  ): BackoffResult {
    // Use rate limit headers if available and error is rate limit related
    if (rateLimitInfo && errorType === "rate_limit") {
      return this.calculateFromRateLimit(rateLimitInfo, attempt);
    }

    // Adjust backoff based on error type
    let customConfig: Partial<BackoffConfig> = {};

    switch (errorType) {
      case "server_error":
        // Slower backoff for server errors (5xx)
        customConfig = {
          baseDelay: this.config.baseDelay * 2,
          backoffMultiplier: 1.5,
        };
        break;

      case "timeout":
        // Moderate backoff for timeouts
        customConfig = {
          baseDelay: this.config.baseDelay * 1.5,
          jitterFactor: this.config.jitterFactor * 2, // More jitter for timeouts
        };
        break;

      case "rate_limit":
        // Standard backoff for rate limits without headers
        customConfig = {
          baseDelay: Math.max(this.config.baseDelay, 5000), // Minimum 5 seconds for rate limits
        };
        break;

      default:
        // Use default config for unknown errors
        break;
    }

    return this.calculateDelay(attempt, customConfig);
  }

  /**
   * Check if we should retry based on error type and attempt count
   */
  shouldRetry(
    attempt: number,
    errorType?:
      | "rate_limit"
      | "server_error"
      | "timeout"
      | "client_error"
      | "unknown",
  ): boolean {
    // Never retry if we've hit max attempts
    if (attempt >= this.config.maxRetries) {
      return false;
    }

    // Don't retry client errors (4xx except 429)
    if (errorType === "client_error") {
      return false;
    }

    // Always retry rate limits, server errors, and timeouts
    return ["rate_limit", "server_error", "timeout", "unknown"].includes(
      errorType || "unknown",
    );
  }

  /**
   * Get backoff statistics for monitoring
   */
  getStatistics(attempts: BackoffResult[]): {
    totalAttempts: number;
    totalDelay: number;
    averageDelay: number;
    successRate: number;
    reasons: Record<string, number>;
  } {
    const totalAttempts = attempts.length;
    const totalDelay = attempts.reduce(
      (sum, attempt) => sum + attempt.delay,
      0,
    );
    const averageDelay = totalAttempts > 0 ? totalDelay / totalAttempts : 0;

    // Count successful retries (those that resulted in shouldRetry: true)
    const successfulRetries = attempts.filter((a) => a.shouldRetry).length;
    const successRate =
      totalAttempts > 0 ? successfulRetries / totalAttempts : 0;

    // Count reasons
    const reasons: Record<string, number> = {};
    attempts.forEach((attempt) => {
      reasons[attempt.reason] = (reasons[attempt.reason] || 0) + 1;
    });

    return {
      totalAttempts,
      totalDelay,
      averageDelay,
      successRate,
      reasons,
    };
  }

  /**
   * Update backoff configuration
   */
  updateConfig(newConfig: Partial<BackoffConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }

  /**
   * Get current configuration
   */
  getConfig(): BackoffConfig {
    return { ...this.config };
  }
}

/**
 * Factory for creating backoff strategies with common configurations
 */
export class BackoffStrategyFactory {
  /**
   * Create a conservative backoff strategy (safer, slower)
   */
  static createConservative(): BackoffStrategy {
    return new BackoffStrategy({
      baseDelay: 2000, // 2 seconds
      maxDelay: 60000, // 1 minute
      maxRetries: 5, // 5 attempts
      jitterFactor: 0.15, // 15% jitter
      backoffMultiplier: 2, // Double each time
    });
  }

  /**
   * Create a balanced backoff strategy (recommended)
   */
  static createBalanced(): BackoffStrategy {
    return new BackoffStrategy({
      baseDelay: 1000, // 1 second
      maxDelay: 30000, // 30 seconds
      maxRetries: 3, // 3 attempts
      jitterFactor: 0.1, // 10% jitter
      backoffMultiplier: 2, // Double each time
    });
  }

  /**
   * Create an aggressive backoff strategy (faster retry, higher risk)
   */
  static createAggressive(): BackoffStrategy {
    return new BackoffStrategy({
      baseDelay: 500, // 500ms
      maxDelay: 15000, // 15 seconds
      maxRetries: 2, // 2 attempts
      jitterFactor: 0.05, // 5% jitter
      backoffMultiplier: 1.5, // 1.5x each time
    });
  }

  /**
   * Create a backoff strategy optimized for rate limits
   */
  static createForRateLimits(): BackoffStrategy {
    return new BackoffStrategy({
      baseDelay: 5000, // 5 seconds (rate limits need longer waits)
      maxDelay: 120000, // 2 minutes
      maxRetries: 4, // 4 attempts
      jitterFactor: 0.2, // 20% jitter (more spread)
      backoffMultiplier: 1.8, // Slightly less aggressive
    });
  }

  /**
   * Create a custom backoff strategy from configuration
   */
  static createCustom(config: Partial<BackoffConfig>): BackoffStrategy {
    const defaultConfig: BackoffConfig = {
      baseDelay: 1000,
      maxDelay: 30000,
      maxRetries: 3,
      jitterFactor: 0.1,
      backoffMultiplier: 2,
    };

    return new BackoffStrategy({ ...defaultConfig, ...config });
  }
}

/**
 * Utility function to sleep/delay execution
 */
export function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, Math.max(0, ms)));
}

/**
 * Async retry wrapper with backoff strategy
 */
export async function retryWithBackoff<T>(
  operation: () => Promise<T>,
  strategy: BackoffStrategy,
  context?: {
    operationName?: string;
    rateLimitInfo?: RateLimitInfo;
    errorClassifier?: (
      error: Error,
    ) => "rate_limit" | "server_error" | "timeout" | "client_error" | "unknown";
  },
): Promise<T> {
  let attempt = 0;
  let lastError: Error | undefined;

  while (attempt < strategy.getConfig().maxRetries + 1) {
    try {
      return await operation();
    } catch (error) {
      lastError = error as Error;

      const errorType = context?.errorClassifier
        ? context.errorClassifier(error as Error)
        : "unknown";

      if (!strategy.shouldRetry(attempt, errorType)) {
        throw error;
      }

      const backoffResult = strategy.calculateAdaptiveDelay(
        attempt,
        context?.rateLimitInfo,
        errorType,
      );

      if (!backoffResult.shouldRetry) {
        throw error;
      }

      // Log retry attempt
      if (context?.operationName) {
        console.warn(
          `Retrying ${context.operationName} after ${backoffResult.delay}ms - ${backoffResult.reason}`,
          {
            attempt: backoffResult.attempt,
            maxRetries: strategy.getConfig().maxRetries,
            errorType,
          },
        );
      }

      await delay(backoffResult.delay);
      attempt = backoffResult.attempt;
    }
  }

  throw lastError;
}
