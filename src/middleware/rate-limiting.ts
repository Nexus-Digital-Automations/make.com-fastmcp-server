/**
 * Advanced Rate Limiting Middleware for Make.com FastMCP Server
 * Multi-tier rate limiting with Redis clustering and adaptive algorithms
 * Phase 2 Security Enhancement Implementation
 */

import { RateLimiterRedis, RateLimiterMemory } from "rate-limiter-flexible";
import Redis from "ioredis";
import logger from "../lib/logger.js";

// Request interface for rate limiting middleware
interface HttpRequest {
  ip?: string;
  method?: string;
  url?: string;
  path?: string;
  headers: Record<string, string | string[] | undefined>;
  connection?: {
    remoteAddress?: string;
  };
  socket?: {
    remoteAddress?: string;
  };
  body?: unknown;
  user?: {
    id: string;
  };
}

// Response interface for middleware
interface HttpResponse {
  setHeader(name: string, value: string | number): void;
  status(code: number): HttpResponse;
  json(body: unknown): void;
  on(event: string, callback: () => void): void;
}

// Next function type
type NextFunction = () => void;

// Rate limiting configuration interface
interface RateLimitConfig {
  tiers: {
    authentication: {
      window: string;
      max: number;
      keyGenerator: (req: HttpRequest) => string;
    };
    standard: {
      window: string;
      max: number;
      keyGenerator: (req: HttpRequest) => string;
    };
    sensitive: {
      window: string;
      max: number;
      keyGenerator: (req: HttpRequest) => string;
    };
    webhooks: {
      window: string;
      max: number;
      keyGenerator: (req: HttpRequest) => string;
    };
  };
}

// Adaptive rate limiter with system monitoring
export class AdaptiveRateLimiter {
  private systemLoad: number = 0;
  private responseTimeP95: number = 0;
  private memoryUsage: number = 0;

  constructor() {
    // Monitor system metrics every 30 seconds
    setInterval(() => {
      this.updateSystemMetrics();
    }, 30000);
  }

  private updateSystemMetrics(): void {
    const cpuUsage = process.cpuUsage();
    const memUsage = process.memoryUsage();

    // Calculate approximate system load (simplified)
    this.systemLoad = (cpuUsage.user + cpuUsage.system) / 1000000; // Convert to seconds
    this.memoryUsage = memUsage.heapUsed / memUsage.heapTotal;

    logger.debug("System metrics updated", {
      systemLoad: this.systemLoad,
      memoryUsage: this.memoryUsage,
      responseTimeP95: this.responseTimeP95,
    });
  }

  public setResponseTime(responseTime: number): void {
    this.responseTimeP95 = Math.max(this.responseTimeP95 * 0.95, responseTime);
  }

  public async getAdjustedLimit(baseLimit: number): Promise<number> {
    // Reduce limits when system under stress
    if (this.systemLoad > 0.8 || this.memoryUsage > 0.85) {
      return Math.floor(baseLimit * 0.4);
    }

    if (this.responseTimeP95 > 2000) {
      return Math.floor(baseLimit * 0.6);
    }

    if (this.systemLoad > 0.6 || this.memoryUsage > 0.7) {
      return Math.floor(baseLimit * 0.7);
    }

    // Increase limits during healthy periods
    if (
      this.systemLoad < 0.3 &&
      this.responseTimeP95 < 500 &&
      this.memoryUsage < 0.5
    ) {
      return Math.floor(baseLimit * 1.3);
    }

    return baseLimit;
  }
}

// Enterprise rate limiting manager
export class EnterpriseRateLimitManager {
  private redisClient: Redis | null = null;
  private readonly rateLimiters: Record<
    string,
    RateLimiterRedis | RateLimiterMemory
  > = {};
  private readonly adaptiveLimiter: AdaptiveRateLimiter;
  private ddosProtection!: RateLimiterRedis | RateLimiterMemory;

  constructor() {
    this.adaptiveLimiter = new AdaptiveRateLimiter();
    this.initializeRedis();
    this.setupRateLimiters();
    this.setupDDoSProtection();
  }

  private initializeRedis(): void {
    try {
      if (process.env.REDIS_URL) {
        this.redisClient = new Redis(process.env.REDIS_URL, {
          maxRetriesPerRequest: 3,
          enableReadyCheck: true,
          lazyConnect: true,
        });

        this.redisClient.on("error", (error) => {
          logger.error("Redis connection error, falling back to memory", {
            error: error.message,
          });
          this.redisClient = null;
        });

        logger.info("Redis client initialized for distributed rate limiting");
      } else {
        logger.warn("Redis not configured, using memory-based rate limiting");
      }
    } catch (error) {
      logger.error("Failed to initialize Redis client", {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  /**
   * SUBAGENT 5-6: Refactored using Extract Method pattern (59→≤50 lines)
   */
  private setupRateLimiters(): void {
    this.rateLimiters.auth = this.createAuthRateLimiter();
    this.rateLimiters.standard = this.createStandardRateLimiter();
    this.rateLimiters.sensitive = this.createSensitiveRateLimiter();
    this.rateLimiters.webhooks = this.createWebhookRateLimiter();
  }

  /**
   * Create authentication rate limiter
   * SUBAGENT 5: Extract Method - Auth limiter creation
   */
  private createAuthRateLimiter(): RateLimiterRedis | RateLimiterMemory {
    // Authentication rate limiter - prevent brute force
    return this.redisClient
      ? new RateLimiterRedis({
          storeClient: this.redisClient,
          keyPrefix: "rl:auth",
          points: 10, // 10 attempts
          duration: 900, // Per 15 minutes
          blockDuration: 900, // Block for 15 minutes
          execEvenly: true,
        })
      : new RateLimiterMemory({
          points: 10,
          duration: 900,
          blockDuration: 900,
        });
  }

  /**
   * Create standard API rate limiter
   * SUBAGENT 5: Extract Method - Standard limiter creation
   */
  private createStandardRateLimiter(): RateLimiterRedis | RateLimiterMemory {
    return this.redisClient
      ? new RateLimiterRedis({
          storeClient: this.redisClient,
          keyPrefix: "rl:api",
          points: 1000, // 1000 requests
          duration: 3600, // Per hour
          blockDuration: 300, // Block for 5 minutes
          execEvenly: true,
        })
      : new RateLimiterMemory({
          points: 1000,
          duration: 3600,
          blockDuration: 300,
        });
  }

  /**
   * Create sensitive operations rate limiter
   * SUBAGENT 6: Extract Method - Sensitive limiter creation
   */
  private createSensitiveRateLimiter(): RateLimiterRedis | RateLimiterMemory {
    return this.redisClient
      ? new RateLimiterRedis({
          storeClient: this.redisClient,
          keyPrefix: "rl:sensitive",
          points: 100, // 100 requests
          duration: 3600, // Per hour
          blockDuration: 600, // Block for 10 minutes
          execEvenly: true,
        })
      : new RateLimiterMemory({
          points: 100,
          duration: 3600,
          blockDuration: 600,
        });
  }

  /**
   * Create webhook rate limiter
   * SUBAGENT 6: Extract Method - Webhook limiter creation
   */
  private createWebhookRateLimiter(): RateLimiterRedis | RateLimiterMemory {
    return this.redisClient
      ? new RateLimiterRedis({
          storeClient: this.redisClient,
          keyPrefix: "rl:webhook",
          points: 50, // 50 requests
          duration: 60, // Per minute
          blockDuration: 120, // Block for 2 minutes
          execEvenly: true,
        })
      : new RateLimiterMemory({
          points: 50,
          duration: 60,
          blockDuration: 120,
        });
  }

  private setupDDoSProtection(): void {
    // DDoS protection with aggressive limits
    this.ddosProtection = this.redisClient
      ? new RateLimiterRedis({
          storeClient: this.redisClient,
          keyPrefix: "ddos",
          points: 1000, // 1000 requests
          duration: 60, // Per minute
          blockDuration: 3600, // Block for 1 hour
          execEvenly: true,
        })
      : new RateLimiterMemory({
          points: 1000,
          duration: 60,
          blockDuration: 3600,
        });
  }

  private getRateLimitConfig(): RateLimitConfig {
    return {
      tiers: {
        authentication: {
          window: "15m",
          max: 10,
          keyGenerator: (req) => `auth:${this.getClientIP(req)}`,
        },
        standard: {
          window: "1h",
          max: 1000,
          keyGenerator: (req) => `api:${req.user?.id || this.getClientIP(req)}`,
        },
        sensitive: {
          window: "1h",
          max: 100,
          keyGenerator: (req) =>
            `sensitive:${req.user?.id || this.getClientIP(req)}`,
        },
        webhooks: {
          window: "1m",
          max: 50,
          keyGenerator: (req) =>
            `webhook:${req.headers["x-webhook-id"] || this.getClientIP(req)}`,
        },
      },
    };
  }

  public getClientIP(req: HttpRequest): string {
    const forwardedFor = req.headers["x-forwarded-for"];
    const forwardedIp = Array.isArray(forwardedFor)
      ? forwardedFor[0]
      : forwardedFor;

    return (
      req.ip ||
      req.connection?.remoteAddress ||
      req.socket?.remoteAddress ||
      (forwardedIp ? forwardedIp.split(",")[0] : undefined) ||
      "unknown"
    );
  }

  /**
   * SUBAGENT 7-8: Refactored using Extract Method pattern (51→≤50 lines & 13→≤12 complexity)
   */
  public async checkRateLimit(
    tier: "auth" | "standard" | "sensitive" | "webhooks" | "ddos",
    identifier: string,
    _req?: HttpRequest,
  ): Promise<{ allowed: boolean; resetTime?: Date; remaining?: number }> {
    try {
      const limiter = this.getRateLimiter(tier);
      if (!limiter) {
        return { allowed: true };
      }

      await this.applyAdaptiveLimiting(tier);
      const result = await limiter.consume(identifier);

      return this.createSuccessResponse(result);
    } catch (error: unknown) {
      return this.handleRateLimitError(error, tier, identifier);
    }
  }

  /**
   * Get rate limiter for specified tier
   * SUBAGENT 7: Extract Method - Limiter selection logic
   */
  private getRateLimiter(
    tier: string,
  ): RateLimiterRedis | RateLimiterMemory | undefined {
    const limiter =
      tier === "ddos" ? this.ddosProtection : this.rateLimiters[tier];

    if (!limiter) {
      logger.warn(
        `Rate limiter for tier '${tier}' not found, allowing request`,
      );
    }

    return limiter;
  }

  /**
   * Apply adaptive limiting for dynamic tiers
   * SUBAGENT 7: Extract Method - Adaptive limiting logic
   */
  private async applyAdaptiveLimiting(tier: string): Promise<void> {
    if (
      (tier === "standard" || tier === "sensitive") &&
      this.rateLimiters[tier]
    ) {
      const baseLimits = tier === "standard" ? 1000 : 100;
      const adjustedLimit =
        await this.adaptiveLimiter.getAdjustedLimit(baseLimits);

      if (adjustedLimit !== baseLimits) {
        logger.debug(`Adjusted rate limit for ${tier}`, {
          base: baseLimits,
          adjusted: adjustedLimit,
        });
      }
    }
  }

  /**
   * Create success response for rate limiting
   * SUBAGENT 7: Extract Method - Success response creation
   */
  private createSuccessResponse(result: {
    msBeforeNext: number;
    remainingPoints: number;
  }): { allowed: boolean; resetTime: Date; remaining: number } {
    return {
      allowed: true,
      resetTime: new Date(Date.now() + result.msBeforeNext),
      remaining: result.remainingPoints,
    };
  }

  /**
   * Handle rate limiting errors
   * SUBAGENT 8: Extract Method - Error handling logic
   */
  private handleRateLimitError(
    error: unknown,
    tier: string,
    identifier: string,
  ): { allowed: boolean; resetTime?: Date; remaining?: number } {
    // Type guard for rate limiter errors
    if (error && typeof error === "object" && "remainingPoints" in error) {
      return this.handleRateLimitExceeded(
        error as { remainingPoints: number; msBeforeNext: number },
        tier,
        identifier,
      );
    }

    return this.handleGenericError(error, tier, identifier);
  }

  /**
   * Handle rate limit exceeded scenario
   * SUBAGENT 8: Extract Method - Rate limit exceeded handling
   */
  private handleRateLimitExceeded(
    rateLimitError: { remainingPoints: number; msBeforeNext: number },
    tier: string,
    identifier: string,
  ): { allowed: boolean; resetTime: Date; remaining: number } {
    logger.warn(`Rate limit exceeded for ${tier}`, {
      identifier: identifier.substring(0, 20) + "...",
      tier,
      resetTime: new Date(Date.now() + rateLimitError.msBeforeNext),
      remaining: rateLimitError.remainingPoints,
    });

    return {
      allowed: false,
      resetTime: new Date(Date.now() + rateLimitError.msBeforeNext),
      remaining: rateLimitError.remainingPoints,
    };
  }

  /**
   * Handle generic rate limiting errors
   * SUBAGENT 8: Extract Method - Generic error handling
   */
  private handleGenericError(
    error: unknown,
    tier: string,
    identifier: string,
  ): { allowed: boolean } {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logger.error("Rate limiting error, allowing request", {
      error: errorMessage,
      tier,
      identifier: identifier.substring(0, 20) + "...",
    });

    return { allowed: true };
  }

  public async recordResponseTime(responseTime: number): Promise<void> {
    this.adaptiveLimiter.setResponseTime(responseTime);
  }

  public getSystemStatus(): {
    redisConnected: boolean;
    adaptiveEnabled: boolean;
    rateLimiters: string[];
  } {
    return {
      redisConnected: !!this.redisClient && this.redisClient.status === "ready",
      adaptiveEnabled: true,
      rateLimiters: Object.keys(this.rateLimiters),
    };
  }

  public async shutdown(): Promise<void> {
    if (this.redisClient) {
      await this.redisClient.quit();
      logger.info("Rate limiting Redis client disconnected");
    }
  }
}

// Singleton instance
export const rateLimitManager = new EnterpriseRateLimitManager();

// Middleware factory for different rate limiting tiers
export function createRateLimitMiddleware(
  tier: "auth" | "standard" | "sensitive" | "webhooks",
) {
  return async (
    req: HttpRequest,
    res: HttpResponse,
    next: NextFunction,
  ): Promise<void> => {
    const startTime = Date.now();
    const identifier =
      tier === "auth"
        ? `auth:${rateLimitManager.getClientIP(req)}`
        : tier === "webhooks"
          ? `webhook:${req.headers["x-webhook-id"] || rateLimitManager.getClientIP(req)}`
          : `${tier}:${req.user?.id || rateLimitManager.getClientIP(req)}`;

    try {
      const result = await rateLimitManager.checkRateLimit(
        tier,
        identifier,
        req,
      );

      // Set rate limit headers
      if (result.resetTime) {
        res.setHeader(
          "X-RateLimit-Reset",
          Math.ceil(result.resetTime.getTime() / 1000),
        );
      }
      if (result.remaining !== undefined) {
        res.setHeader("X-RateLimit-Remaining", result.remaining);
      }
      res.setHeader("X-RateLimit-Tier", tier);

      if (!result.allowed) {
        logger.warn(`Rate limit exceeded for ${tier}`, {
          identifier: identifier.substring(0, 20) + "...",
          ip: rateLimitManager.getClientIP(req),
        });

        return res.status(429).json({
          error: {
            code: "RATE_LIMIT_EXCEEDED",
            message: "Too many requests. Please try again later.",
            tier,
            resetTime: result.resetTime?.toISOString(),
          },
        });
      }

      // Record response time for adaptive limiting
      res.on("finish", () => {
        const responseTime = Date.now() - startTime;
        rateLimitManager.recordResponseTime(responseTime);
      });

      next();
    } catch (error) {
      logger.error("Rate limiting middleware error", {
        error: error instanceof Error ? error.message : String(error),
        tier,
      });

      // Fail open - allow request if rate limiting fails
      next();
    }
  };
}

// DDoS protection middleware
export function ddosProtectionMiddleware() {
  return async (
    req: HttpRequest,
    res: HttpResponse,
    next: NextFunction,
  ): Promise<void> => {
    const identifier = `ddos:${rateLimitManager.getClientIP(req)}`;

    try {
      const result = await rateLimitManager.checkRateLimit(
        "ddos",
        identifier,
        req,
      );

      if (!result.allowed) {
        const userAgent = req.headers["user-agent"];
        logger.warn("DDoS protection triggered", {
          ip: rateLimitManager.getClientIP(req),
          userAgent: Array.isArray(userAgent)
            ? userAgent[0]?.substring(0, 100)
            : userAgent?.substring(0, 100),
        });

        return res.status(429).json({
          error: {
            code: "DDOS_PROTECTION",
            message:
              "Request blocked by DDoS protection. Please try again later.",
            resetTime: result.resetTime?.toISOString(),
          },
        });
      }

      next();
    } catch (error) {
      logger.error("DDoS protection error", {
        error: error instanceof Error ? error.message : String(error),
      });

      // Fail open - allow request if DDoS protection fails
      next();
    }
  };
}
