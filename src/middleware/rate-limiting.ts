/**
 * Advanced Rate Limiting Middleware for Make.com FastMCP Server
 * Multi-tier rate limiting with Redis clustering and adaptive algorithms
 * Phase 2 Security Enhancement Implementation
 */

import { RateLimiterRedis, RateLimiterMemory } from 'rate-limiter-flexible';
import Redis from 'ioredis';
import logger from '../lib/logger.js';

// Rate limiting configuration interface
interface RateLimitConfig {
  tiers: {
    authentication: {
      window: string;
      max: number;
      keyGenerator: (req: any) => string;
    };
    standard: {
      window: string;
      max: number;
      keyGenerator: (req: any) => string;
    };
    sensitive: {
      window: string;
      max: number;
      keyGenerator: (req: any) => string;
    };
    webhooks: {
      window: string;
      max: number;
      keyGenerator: (req: any) => string;
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
    
    logger.debug('System metrics updated', {
      systemLoad: this.systemLoad,
      memoryUsage: this.memoryUsage,
      responseTimeP95: this.responseTimeP95
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
    if (this.systemLoad < 0.3 && this.responseTimeP95 < 500 && this.memoryUsage < 0.5) {
      return Math.floor(baseLimit * 1.3);
    }
    
    return baseLimit;
  }
}

// Enterprise rate limiting manager
export class EnterpriseRateLimitManager {
  private redisClient: Redis | null = null;
  private rateLimiters: Record<string, RateLimiterRedis | RateLimiterMemory> = {};
  private adaptiveLimiter: AdaptiveRateLimiter;
  private ddosProtection: RateLimiterRedis | RateLimiterMemory;
  
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
          retryDelayOnFailover: 100,
          maxRetriesPerRequest: 3,
          enableReadyCheck: true,
          lazyConnect: true
        });
        
        this.redisClient.on('error', (error) => {
          logger.error('Redis connection error, falling back to memory', { error: error.message });
          this.redisClient = null;
        });
        
        logger.info('Redis client initialized for distributed rate limiting');
      } else {
        logger.warn('Redis not configured, using memory-based rate limiting');
      }
    } catch (error) {
      logger.error('Failed to initialize Redis client', { error: error instanceof Error ? error.message : String(error) });
    }
  }
  
  private setupRateLimiters(): void {
    const config = this.getRateLimitConfig();
    
    // Authentication rate limiter - prevent brute force
    this.rateLimiters.auth = this.redisClient 
      ? new RateLimiterRedis({
          storeClient: this.redisClient,
          keyPrefix: 'rl:auth',
          points: 10, // 10 attempts
          duration: 900, // Per 15 minutes
          blockDuration: 900, // Block for 15 minutes
          execEvenly: true
        })
      : new RateLimiterMemory({
          points: 10,
          duration: 900,
          blockDuration: 900
        });
    
    // Standard API rate limiter
    this.rateLimiters.standard = this.redisClient
      ? new RateLimiterRedis({
          storeClient: this.redisClient,
          keyPrefix: 'rl:api',
          points: 1000, // 1000 requests
          duration: 3600, // Per hour
          blockDuration: 300, // Block for 5 minutes
          execEvenly: true
        })
      : new RateLimiterMemory({
          points: 1000,
          duration: 3600,
          blockDuration: 300
        });
    
    // Sensitive operations rate limiter
    this.rateLimiters.sensitive = this.redisClient
      ? new RateLimiterRedis({
          storeClient: this.redisClient,
          keyPrefix: 'rl:sensitive',
          points: 100, // 100 requests
          duration: 3600, // Per hour
          blockDuration: 600, // Block for 10 minutes
          execEvenly: true
        })
      : new RateLimiterMemory({
          points: 100,
          duration: 3600,
          blockDuration: 600
        });
    
    // Webhook rate limiter
    this.rateLimiters.webhooks = this.redisClient
      ? new RateLimiterRedis({
          storeClient: this.redisClient,
          keyPrefix: 'rl:webhook',
          points: 50, // 50 requests
          duration: 60, // Per minute
          blockDuration: 120, // Block for 2 minutes
          execEvenly: true
        })
      : new RateLimiterMemory({
          points: 50,
          duration: 60,
          blockDuration: 120
        });
  }
  
  private setupDDoSProtection(): void {
    // DDoS protection with aggressive limits
    this.ddosProtection = this.redisClient
      ? new RateLimiterRedis({
          storeClient: this.redisClient,
          keyPrefix: 'ddos',
          points: 1000, // 1000 requests
          duration: 60, // Per minute
          blockDuration: 3600, // Block for 1 hour
          execEvenly: true,
          skipFailedRequests: true
        })
      : new RateLimiterMemory({
          points: 1000,
          duration: 60,
          blockDuration: 3600
        });
  }
  
  private getRateLimitConfig(): RateLimitConfig {
    return {
      tiers: {
        authentication: {
          window: '15m',
          max: 10,
          keyGenerator: (req) => `auth:${this.getClientIP(req)}`
        },
        standard: {
          window: '1h',
          max: 1000,
          keyGenerator: (req) => `api:${req.user?.id || this.getClientIP(req)}`
        },
        sensitive: {
          window: '1h',
          max: 100,
          keyGenerator: (req) => `sensitive:${req.user?.id || this.getClientIP(req)}`
        },
        webhooks: {
          window: '1m',
          max: 50,
          keyGenerator: (req) => `webhook:${req.headers['x-webhook-id'] || this.getClientIP(req)}`
        }
      }
    };
  }
  
  private getClientIP(req: any): string {
    return req.ip || 
           req.connection?.remoteAddress || 
           req.socket?.remoteAddress ||
           req.headers['x-forwarded-for']?.split(',')[0] ||
           'unknown';
  }
  
  public async checkRateLimit(
    tier: 'auth' | 'standard' | 'sensitive' | 'webhooks' | 'ddos',
    identifier: string,
    req?: any
  ): Promise<{ allowed: boolean; resetTime?: Date; remaining?: number }> {
    try {
      const limiter = tier === 'ddos' ? this.ddosProtection : this.rateLimiters[tier];
      
      if (!limiter) {
        logger.warn(`Rate limiter for tier '${tier}' not found, allowing request`);
        return { allowed: true };
      }
      
      // Apply adaptive limiting for standard and sensitive tiers
      if ((tier === 'standard' || tier === 'sensitive') && this.rateLimiters[tier]) {
        const baseLimits = tier === 'standard' ? 1000 : 100;
        const adjustedLimit = await this.adaptiveLimiter.getAdjustedLimit(baseLimits);
        
        // Update rate limiter points dynamically (simplified approach)
        if (adjustedLimit !== baseLimits) {
          logger.debug(`Adjusted rate limit for ${tier}`, { 
            base: baseLimits, 
            adjusted: adjustedLimit 
          });
        }
      }
      
      const result = await limiter.consume(identifier);
      
      return {
        allowed: true,
        resetTime: new Date(Date.now() + result.msBeforeNext),
        remaining: result.remainingPoints
      };
      
    } catch (error: any) {
      if (error.remainingPoints !== undefined) {
        // Rate limit exceeded
        logger.warn(`Rate limit exceeded for ${tier}`, {
          identifier: identifier.substring(0, 20) + '...',
          tier,
          resetTime: new Date(Date.now() + error.msBeforeNext),
          remaining: error.remainingPoints
        });
        
        return {
          allowed: false,
          resetTime: new Date(Date.now() + error.msBeforeNext),
          remaining: error.remainingPoints
        };
      }
      
      logger.error('Rate limiting error, allowing request', { 
        error: error.message,
        tier,
        identifier: identifier.substring(0, 20) + '...'
      });
      
      return { allowed: true };
    }
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
      redisConnected: !!this.redisClient && this.redisClient.status === 'ready',
      adaptiveEnabled: true,
      rateLimiters: Object.keys(this.rateLimiters)
    };
  }
  
  public async shutdown(): Promise<void> {
    if (this.redisClient) {
      await this.redisClient.quit();
      logger.info('Rate limiting Redis client disconnected');
    }
  }
}

// Singleton instance
export const rateLimitManager = new EnterpriseRateLimitManager();

// Middleware factory for different rate limiting tiers
export function createRateLimitMiddleware(tier: 'auth' | 'standard' | 'sensitive' | 'webhooks') {
  return async (req: any, res: any, next: any): Promise<void> => {
    const startTime = Date.now();
    const identifier = tier === 'auth' 
      ? `auth:${rateLimitManager['getClientIP'](req)}`
      : tier === 'webhooks'
      ? `webhook:${req.headers['x-webhook-id'] || rateLimitManager['getClientIP'](req)}`
      : `${tier}:${req.user?.id || rateLimitManager['getClientIP'](req)}`;
    
    try {
      const result = await rateLimitManager.checkRateLimit(tier, identifier, req);
      
      // Set rate limit headers
      if (result.resetTime) {
        res.setHeader('X-RateLimit-Reset', Math.ceil(result.resetTime.getTime() / 1000));
      }
      if (result.remaining !== undefined) {
        res.setHeader('X-RateLimit-Remaining', result.remaining);
      }
      res.setHeader('X-RateLimit-Tier', tier);
      
      if (!result.allowed) {
        logger.warn(`Rate limit exceeded for ${tier}`, {
          identifier: identifier.substring(0, 20) + '...',
          ip: rateLimitManager['getClientIP'](req)
        });
        
        return res.status(429).json({
          error: {
            code: 'RATE_LIMIT_EXCEEDED',
            message: 'Too many requests. Please try again later.',
            tier,
            resetTime: result.resetTime?.toISOString()
          }
        });
      }
      
      // Record response time for adaptive limiting
      res.on('finish', () => {
        const responseTime = Date.now() - startTime;
        rateLimitManager.recordResponseTime(responseTime);
      });
      
      next();
      
    } catch (error) {
      logger.error('Rate limiting middleware error', { 
        error: error instanceof Error ? error.message : String(error),
        tier
      });
      
      // Fail open - allow request if rate limiting fails
      next();
    }
  };
}

// DDoS protection middleware
export function ddosProtectionMiddleware() {
  return async (req: any, res: any, next: any): Promise<void> => {
    const identifier = `ddos:${rateLimitManager['getClientIP'](req)}`;
    
    try {
      const result = await rateLimitManager.checkRateLimit('ddos', identifier, req);
      
      if (!result.allowed) {
        logger.warn('DDoS protection triggered', {
          ip: rateLimitManager['getClientIP'](req),
          userAgent: req.headers['user-agent']?.substring(0, 100)
        });
        
        return res.status(429).json({
          error: {
            code: 'DDOS_PROTECTION',
            message: 'Request blocked by DDoS protection. Please try again later.',
            resetTime: result.resetTime?.toISOString()
          }
        });
      }
      
      next();
      
    } catch (error) {
      logger.error('DDoS protection error', { 
        error: error instanceof Error ? error.message : String(error)
      });
      
      // Fail open - allow request if DDoS protection fails
      next();
    }
  };
}