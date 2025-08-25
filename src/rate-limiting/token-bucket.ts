/**
 * Token Bucket Algorithm Implementation
 * Provides pre-emptive rate limiting to prevent API rate limit errors
 */

export interface TokenBucketConfig {
  capacity: number; // Maximum number of tokens in bucket
  refillRate: number; // Tokens added per second
  safetyMargin: number; // Percentage of capacity to use (0.8 = 80%)
}

export interface TokenBucketState {
  tokens: number;
  lastRefill: number;
  totalConsumed: number;
  totalRequested: number;
}

export class TokenBucket {
  private tokens: number;
  private lastRefill: number;
  private totalConsumed: number = 0;
  private totalRequested: number = 0;

  constructor(private config: TokenBucketConfig) {
    this.tokens = config.capacity;
    this.lastRefill = Date.now();
  }

  /**
   * Attempt to consume tokens from the bucket
   * Returns true if tokens were successfully consumed
   */
  tryConsume(tokensRequested: number = 1): boolean {
    this.totalRequested++;
    this.refill();

    const maxUsableTokens = Math.floor(
      this.config.capacity * this.config.safetyMargin,
    );
    const availableTokens = Math.min(this.tokens, maxUsableTokens);

    if (availableTokens >= tokensRequested) {
      this.tokens -= tokensRequested;
      this.totalConsumed++;
      return true;
    }

    return false;
  }

  /**
   * Get current state of the token bucket
   */
  getState(): TokenBucketState {
    this.refill(); // Ensure current state
    return {
      tokens: this.tokens,
      lastRefill: this.lastRefill,
      totalConsumed: this.totalConsumed,
      totalRequested: this.totalRequested,
    };
  }

  /**
   * Get time in milliseconds until tokens are available
   */
  getTimeUntilTokensAvailable(tokensRequested: number = 1): number {
    this.refill();

    const maxUsableTokens = Math.floor(
      this.config.capacity * this.config.safetyMargin,
    );
    const availableTokens = Math.min(this.tokens, maxUsableTokens);

    if (availableTokens >= tokensRequested) {
      return 0; // Tokens are already available
    }

    const tokensNeeded = tokensRequested - availableTokens;
    const timeToRefill = (tokensNeeded / this.config.refillRate) * 1000; // Convert to milliseconds

    return Math.ceil(timeToRefill);
  }

  /**
   * Update bucket configuration dynamically
   */
  updateConfig(newConfig: Partial<TokenBucketConfig>): void {
    this.refill(); // Update with current state first

    if (newConfig.capacity !== undefined) {
      // Adjust current tokens proportionally
      const ratio = newConfig.capacity / this.config.capacity;
      this.tokens = Math.min(this.tokens * ratio, newConfig.capacity);
      this.config.capacity = newConfig.capacity;
    }

    if (newConfig.refillRate !== undefined) {
      this.config.refillRate = newConfig.refillRate;
    }

    if (newConfig.safetyMargin !== undefined) {
      this.config.safetyMargin = Math.max(
        0.1,
        Math.min(1.0, newConfig.safetyMargin),
      );
    }
  }

  /**
   * Update bucket based on actual rate limit information from API response
   */
  updateFromRateLimit(
    limit: number,
    remaining: number,
    windowSeconds: number = 3600,
  ): void {
    // Calculate actual usage rate
    const used = limit - remaining;
    const _usageRate = used / windowSeconds; // requests per second (monitored but not actively used)

    // Update refill rate to match API's actual rate
    const newRefillRate = Math.max(0.1, limit / windowSeconds);

    // Update capacity to match API's limit with safety margin
    const newCapacity = Math.max(10, Math.floor(limit * 0.9));

    // Sync current tokens with actual remaining requests
    const syncedTokens = Math.min(remaining, newCapacity);

    this.updateConfig({
      capacity: newCapacity,
      refillRate: newRefillRate,
    });

    // Sync token count with actual API state
    this.tokens = syncedTokens;
    this.lastRefill = Date.now();
  }

  /**
   * Reset bucket to full capacity
   */
  reset(): void {
    this.tokens = this.config.capacity;
    this.lastRefill = Date.now();
  }

  /**
   * Get bucket statistics for monitoring
   */
  getStatistics(): {
    config: TokenBucketConfig;
    state: TokenBucketState;
    stats: {
      successRate: number;
      averageTokensPerSecond: number;
      utilizationRate: number;
    };
  } {
    const state = this.getState();
    const successRate =
      this.totalRequested > 0 ? this.totalConsumed / this.totalRequested : 1;

    const runtimeSeconds = (Date.now() - this.lastRefill) / 1000;
    const averageTokensPerSecond =
      runtimeSeconds > 0 ? this.totalConsumed / runtimeSeconds : 0;

    const maxUsableTokens = Math.floor(
      this.config.capacity * this.config.safetyMargin,
    );
    const utilizationRate =
      maxUsableTokens > 0
        ? (maxUsableTokens - state.tokens) / maxUsableTokens
        : 0;

    return {
      config: { ...this.config },
      state,
      stats: {
        successRate,
        averageTokensPerSecond,
        utilizationRate,
      },
    };
  }

  /**
   * Refill tokens based on time elapsed
   */
  private refill(): void {
    const now = Date.now();
    const timeDelta = (now - this.lastRefill) / 1000; // Convert to seconds

    if (timeDelta > 0) {
      const tokensToAdd = timeDelta * this.config.refillRate;
      this.tokens = Math.min(this.config.capacity, this.tokens + tokensToAdd);
      this.lastRefill = now;
    }
  }
}

/**
 * Factory for creating token buckets with common configurations
 */
export class TokenBucketFactory {
  /**
   * Create a conservative token bucket (low risk)
   */
  static createConservative(): TokenBucket {
    return new TokenBucket({
      capacity: 50,
      refillRate: 0.5, // 0.5 tokens per second
      safetyMargin: 0.7, // Use only 70% of capacity
    });
  }

  /**
   * Create a balanced token bucket (medium risk)
   */
  static createBalanced(): TokenBucket {
    return new TokenBucket({
      capacity: 100,
      refillRate: 1, // 1 token per second
      safetyMargin: 0.8, // Use 80% of capacity
    });
  }

  /**
   * Create an aggressive token bucket (higher throughput)
   */
  static createAggressive(): TokenBucket {
    return new TokenBucket({
      capacity: 200,
      refillRate: 2, // 2 tokens per second
      safetyMargin: 0.9, // Use 90% of capacity
    });
  }

  /**
   * Create a token bucket based on known API limits
   */
  static createFromApiLimits(
    requestsPerHour: number,
    safetyMargin: number = 0.8,
  ): TokenBucket {
    const requestsPerSecond = requestsPerHour / 3600;
    const capacity = Math.max(10, Math.floor(requestsPerHour * 0.1)); // 10% of hourly limit as capacity

    return new TokenBucket({
      capacity,
      refillRate: requestsPerSecond,
      safetyMargin,
    });
  }
}
