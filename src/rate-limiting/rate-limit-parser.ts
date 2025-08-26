/**
 * Rate Limit Header Parser
 * Parses standard rate limit headers from HTTP responses
 */

export interface RateLimitInfo {
  limit: number; // X-RateLimit-Limit - Total request limit
  remaining: number; // X-RateLimit-Remaining - Remaining requests
  reset: number; // X-RateLimit-Reset - Reset timestamp
  resetAfter?: number; // X-RateLimit-Reset-After - Seconds until reset
  retryAfter?: number; // Retry-After - Seconds to wait (from 429 responses)
  window?: number; // Rate limit window in seconds
}

export class RateLimitParser {
  /**
   * Parse rate limit information from HTTP response headers
   */
  static parseHeaders(
    headers: Record<string, string | string[]>,
  ): RateLimitInfo | null {
    // Normalize headers to lowercase for consistent access
    const normalizedHeaders: Record<string, string> = {};
    Object.entries(headers).forEach(([key, value]) => {
      normalizedHeaders[key.toLowerCase()] = Array.isArray(value)
        ? value[0]
        : value;
    });

    // Try to extract rate limit information from various header formats
    const limit = this.parseInteger(
      normalizedHeaders["x-ratelimit-limit"] ||
        normalizedHeaders["x-rate-limit-limit"] ||
        normalizedHeaders["ratelimit-limit"],
    );

    const remaining = this.parseInteger(
      normalizedHeaders["x-ratelimit-remaining"] ||
        normalizedHeaders["x-rate-limit-remaining"] ||
        normalizedHeaders["ratelimit-remaining"],
    );

    const reset = this.parseInteger(
      normalizedHeaders["x-ratelimit-reset"] ||
        normalizedHeaders["x-rate-limit-reset"] ||
        normalizedHeaders["ratelimit-reset"],
    );

    const resetAfter = this.parseInteger(
      normalizedHeaders["x-ratelimit-reset-after"] ||
        normalizedHeaders["x-rate-limit-reset-after"] ||
        normalizedHeaders["ratelimit-reset-after"],
    );

    const retryAfter = this.parseInteger(normalizedHeaders["retry-after"]);

    // If we have at least limit information, return the parsed data
    if (limit !== null && limit > 0) {
      const rateLimitInfo: RateLimitInfo = {
        limit,
        remaining: remaining ?? 0,
        reset: reset ?? 0,
      };

      if (resetAfter !== null) {
        rateLimitInfo.resetAfter = resetAfter;
      }

      if (retryAfter !== null) {
        rateLimitInfo.retryAfter = retryAfter;
      }

      // Calculate window if we have reset information
      if (reset && reset > 0) {
        const currentTime = Math.floor(Date.now() / 1000);
        rateLimitInfo.window = Math.max(0, reset - currentTime);
      }

      return rateLimitInfo;
    }

    // If no structured rate limit headers, check for Retry-After only (429 responses)
    if (retryAfter !== null && retryAfter > 0) {
      return {
        limit: 0,
        remaining: 0,
        reset: 0,
        retryAfter,
      };
    }

    return null;
  }

  /**
   * Parse integer from string header value
   */
  private static parseInteger(value: string | undefined): number | null {
    if (!value || typeof value !== "string") {
      return null;
    }

    const parsed = parseInt(value.trim(), 10);
    return isNaN(parsed) ? null : parsed;
  }

  /**
   * Check if rate limit is approaching threshold
   */
  static isApproachingLimit(
    rateLimitInfo: RateLimitInfo,
    thresholdPercentage: number = 0.2,
  ): boolean {
    if (rateLimitInfo.limit === 0) {
      return false;
    }

    const usedPercentage =
      (rateLimitInfo.limit - rateLimitInfo.remaining) / rateLimitInfo.limit;
    return usedPercentage >= 1 - thresholdPercentage;
  }

  /**
   * Get time until rate limit reset in milliseconds
   */
  static getTimeUntilReset(rateLimitInfo: RateLimitInfo): number {
    const currentTime = Math.floor(Date.now() / 1000);

    // Use resetAfter if available (more reliable)
    if (rateLimitInfo.resetAfter && rateLimitInfo.resetAfter > 0) {
      return rateLimitInfo.resetAfter * 1000;
    }

    // Use reset timestamp
    if (rateLimitInfo.reset && rateLimitInfo.reset > currentTime) {
      return (rateLimitInfo.reset - currentTime) * 1000;
    }

    // Use retryAfter as fallback
    if (rateLimitInfo.retryAfter && rateLimitInfo.retryAfter > 0) {
      return rateLimitInfo.retryAfter * 1000;
    }

    // Default to 1 minute if no timing information available
    return 60000;
  }

  /**
   * Create a formatted string representation of rate limit status
   */
  static formatStatus(rateLimitInfo: RateLimitInfo): string {
    const remaining = rateLimitInfo.remaining;
    const limit = rateLimitInfo.limit;
    const resetTime =
      rateLimitInfo.reset > 0
        ? new Date(rateLimitInfo.reset * 1000).toISOString()
        : "unknown";

    if (limit > 0) {
      const percentage = Math.round((remaining / limit) * 100);
      return `${remaining}/${limit} requests remaining (${percentage}%) - resets at ${resetTime}`;
    }

    if (rateLimitInfo.retryAfter) {
      return `Rate limited - retry after ${rateLimitInfo.retryAfter} seconds`;
    }

    return "Rate limit status unknown";
  }

  /**
   * Log rate limit information for debugging
   */
  static logRateLimitInfo(
    rateLimitInfo: RateLimitInfo,
    logger?: { info: (message: string, meta?: unknown) => void },
  ): void {
    const logMessage = `Rate Limit Status: ${this.formatStatus(rateLimitInfo)}`;

    if (logger && typeof logger.info === "function") {
      logger.info(logMessage, {
        rateLimitInfo,
        category: "RATE_LIMITING",
      });
    } else {
      // console.warn(logMessage); // Removed to prevent JSON-RPC protocol contamination
    }
  }
}
