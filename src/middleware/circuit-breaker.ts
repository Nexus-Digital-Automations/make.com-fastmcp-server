/**
 * Advanced Circuit Breaker and DDoS Protection Middleware
 * Implements circuit breaker patterns and sophisticated DDoS mitigation
 * Phase 2 Security Enhancement Implementation
 */

import CircuitBreaker from 'opossum';
import { RateLimiterRedis, RateLimiterMemory } from 'rate-limiter-flexible';
import Redis from 'ioredis';
import logger from '../lib/logger.js';

// Circuit breaker configuration interface
interface CircuitBreakerConfig {
  timeout: number;
  errorThresholdPercentage: number;
  resetTimeout: number;
  rollingCountTimeout: number;
  rollingCountBuckets: number;
  volumeThreshold: number;
}

// Request pattern interface
interface RequestPattern {
  timestamp: number;
  endpoint: string;
  method: string;
  userAgent: string;
  contentLength: number;
  successful?: boolean;
}

// IP reputation data interface
interface IPReputationData {
  riskScore: number;
  requestCount: number;
  lastSeen: number;
  blockedCount: number;
  patterns: string[];
}

// Advanced DDoS protection with behavioral analysis
export class AdvancedDDoSProtection {
  private redisClient: Redis | null = null;
  private rateLimiters: Map<string, RateLimiterRedis | RateLimiterMemory> = new Map();
  private behaviorAnalyzer: BehaviorAnalyzer;
  private ipReputation: Map<string, IPReputationData> = new Map();
  
  constructor() {
    this.initializeRedis();
    this.behaviorAnalyzer = new BehaviorAnalyzer();
    this.setupRateLimiters();
    this.startIPReputationCleanup();
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
          logger.error('DDoS Protection Redis error, falling back to memory', { 
            error: error.message 
          });
          this.redisClient = null;
        });
      }
    } catch (error) {
      logger.error('Failed to initialize DDoS protection Redis client', { 
        error: error instanceof Error ? error.message : String(error) 
      });
    }
  }
  
  private setupRateLimiters(): void {
    // Global DDoS protection
    const globalLimiter = this.redisClient
      ? new RateLimiterRedis({
          storeClient: this.redisClient,
          keyPrefix: 'ddos:global',
          points: 10000, // 10k requests
          duration: 60, // Per minute
          blockDuration: 300, // Block for 5 minutes
          execEvenly: true
        })
      : new RateLimiterMemory({
          points: 10000,
          duration: 60,
          blockDuration: 300
        });
    
    this.rateLimiters.set('global', globalLimiter);
    
    // IP-based DDoS protection
    const ipLimiter = this.redisClient
      ? new RateLimiterRedis({
          storeClient: this.redisClient,
          keyPrefix: 'ddos:ip',
          points: 1000, // 1k requests per IP
          duration: 60, // Per minute
          blockDuration: 600, // Block for 10 minutes
          execEvenly: true
        })
      : new RateLimiterMemory({
          points: 1000,
          duration: 60,
          blockDuration: 600
        });
    
    this.rateLimiters.set('ip', ipLimiter);
    
    // Suspicious behavior limiter
    const suspiciousLimiter = this.redisClient
      ? new RateLimiterRedis({
          storeClient: this.redisClient,
          keyPrefix: 'ddos:suspicious',
          points: 100, // 100 requests for suspicious IPs
          duration: 60,
          blockDuration: 3600, // Block for 1 hour
          execEvenly: true
        })
      : new RateLimiterMemory({
          points: 100,
          duration: 60,
          blockDuration: 3600
        });
    
    this.rateLimiters.set('suspicious', suspiciousLimiter);
  }
  
  public async checkDDoSProtection(req: any): Promise<{
    allowed: boolean;
    reason?: string;
    blockDuration?: number;
    riskScore?: number;
  }> {
    const clientIP = this.getClientIP(req);
    const userAgent = req.headers['user-agent'] || '';
    
    try {
      // Analyze behavior patterns
      const behaviorAnalysis = await this.behaviorAnalyzer.analyzeRequest(req, clientIP);
      
      // Update IP reputation
      this.updateIPReputation(clientIP, behaviorAnalysis);
      
      // Check global rate limit first
      const globalLimiter = this.rateLimiters.get('global')!;
      await globalLimiter.consume('global');
      
      // Determine which limiter to use based on IP reputation
      const ipReputation = this.ipReputation.get(clientIP);
      const isSuspicious = ipReputation && ipReputation.riskScore > 0.7;
      
      const limiterKey = isSuspicious ? 'suspicious' : 'ip';
      const limiter = this.rateLimiters.get(limiterKey)!;
      
      await limiter.consume(clientIP);
      
      // Log successful request for behavior analysis
      this.behaviorAnalyzer.recordSuccessfulRequest(clientIP, req);
      
      return {
        allowed: true,
        riskScore: ipReputation?.riskScore || 0
      };
      
    } catch (error: any) {
      if (error.remainingPoints !== undefined) {
        // Rate limit exceeded
        const reason = error.totalHits > (error.points * 2) ? 'aggressive_ddos' : 'rate_limit_exceeded';
        
        logger.warn('DDoS protection triggered', {
          clientIP: this.hashIP(clientIP),
          userAgent: userAgent.substring(0, 100),
          reason,
          remainingPoints: error.remainingPoints,
          resetTime: new Date(Date.now() + error.msBeforeNext),
          endpoint: req.path,
          method: req.method
        });
        
        // Increase IP reputation risk for blocked requests
        this.updateIPReputation(clientIP, { riskScore: 0.3, isBlocked: true });
        
        return {
          allowed: false,
          reason,
          blockDuration: Math.ceil(error.msBeforeNext / 1000),
          riskScore: this.ipReputation.get(clientIP)?.riskScore || 0
        };
      }
      
      logger.error('DDoS protection error', {
        error: error.message,
        clientIP: this.hashIP(clientIP)
      });
      
      // Fail open for technical errors
      return { allowed: true, riskScore: 0 };
    }
  }
  
  private getClientIP(req: any): string {
    return req.ip ||
           req.connection?.remoteAddress ||
           req.socket?.remoteAddress ||
           req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
           req.headers['x-real-ip'] ||
           'unknown';
  }
  
  private updateIPReputation(ip: string, analysis: any): void {
    const existing = this.ipReputation.get(ip) || {
      riskScore: 0,
      requestCount: 0,
      lastSeen: Date.now(),
      blockedCount: 0,
      patterns: []
    };
    
    existing.requestCount++;
    existing.lastSeen = Date.now();
    
    if (analysis.isBlocked) {
      existing.blockedCount++;
    }
    
    if (analysis.riskScore !== undefined) {
      // Exponential moving average for risk score
      existing.riskScore = existing.riskScore * 0.8 + analysis.riskScore * 0.2;
    }
    
    this.ipReputation.set(ip, existing);
  }
  
  private hashIP(ip: string): string {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(ip + (process.env.IP_HASH_SALT || 'default-salt')).digest('hex').substring(0, 16);
  }
  
  private startIPReputationCleanup(): void {
    setInterval(() => {
      const now = Date.now();
      const maxAge = 24 * 60 * 60 * 1000; // 24 hours
      
      for (const [ip, data] of this.ipReputation.entries()) {
        if (now - data.lastSeen > maxAge) {
          this.ipReputation.delete(ip);
        }
      }
    }, 60 * 60 * 1000); // Clean up every hour
  }
  
  public getStats(): {
    trackedIPs: number;
    suspiciousIPs: number;
    redisConnected: boolean;
  } {
    const suspiciousCount = Array.from(this.ipReputation.values())
      .filter(data => data.riskScore > 0.7).length;
    
    return {
      trackedIPs: this.ipReputation.size,
      suspiciousIPs: suspiciousCount,
      redisConnected: !!this.redisClient && this.redisClient.status === 'ready'
    };
  }
}

// Behavioral analysis for detecting bot patterns
class BehaviorAnalyzer {
  private requestPatterns: Map<string, RequestPattern[]> = new Map();
  
  async analyzeRequest(req: any, clientIP: string): Promise<{
    riskScore: number;
    patterns: string[];
    isBot?: boolean;
  }> {
    const patterns = this.requestPatterns.get(clientIP) || [];
    const now = Date.now();
    
    // Add current request to pattern
    patterns.push({
      timestamp: now,
      endpoint: req.path,
      method: req.method,
      userAgent: req.headers['user-agent'] || '',
      contentLength: parseInt(req.headers['content-length'] || '0', 10)
    });
    
    // Keep only recent patterns (last 5 minutes)
    const recentPatterns = patterns.filter(p => now - p.timestamp < 5 * 60 * 1000);
    this.requestPatterns.set(clientIP, recentPatterns.slice(-100)); // Keep max 100 patterns
    
    return this.calculateRiskScore(recentPatterns);
  }
  
  recordSuccessfulRequest(clientIP: string, _req: any): void {
    // Update patterns for successful requests
    const patterns = this.requestPatterns.get(clientIP) || [];
    const lastPattern = patterns[patterns.length - 1];
    
    if (lastPattern) {
      lastPattern.successful = true;
    }
  }
  
  private calculateRiskScore(patterns: RequestPattern[]): {
    riskScore: number;
    patterns: string[];
    isBot?: boolean;
  } {
    if (patterns.length < 3) {
      return { riskScore: 0, patterns: [] };
    }
    
    let riskScore = 0;
    const detectedPatterns: string[] = [];
    
    // High frequency requests
    const requestsPerMinute = patterns.length / 5;
    if (requestsPerMinute > 100) {
      riskScore += 0.4;
      detectedPatterns.push('high_frequency');
    }
    
    // Same endpoint repeated rapidly
    const endpointCounts = patterns.reduce((acc, p) => {
      acc[p.endpoint] = (acc[p.endpoint] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    
    const maxEndpointCount = Math.max(...Object.values(endpointCounts));
    if (maxEndpointCount > patterns.length * 0.8) {
      riskScore += 0.3;
      detectedPatterns.push('endpoint_hammering');
    }
    
    // Suspicious user agent patterns
    const userAgents = new Set(patterns.map(p => p.userAgent));
    if (userAgents.size === 1) {
      const userAgent = Array.from(userAgents)[0];
      if (!userAgent || userAgent.length < 10 || /bot|crawler|spider/i.test(userAgent)) {
        riskScore += 0.2;
        detectedPatterns.push('suspicious_user_agent');
      }
    }
    
    // Perfect timing patterns (likely bot)
    const intervals = patterns.slice(1).map((p, i) => p.timestamp - patterns[i].timestamp);
    const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const intervalVariance = intervals.reduce((acc, interval) => 
      acc + Math.pow(interval - avgInterval, 2), 0) / intervals.length;
    
    if (intervalVariance < avgInterval * 0.1 && patterns.length > 10) {
      riskScore += 0.3;
      detectedPatterns.push('perfect_timing');
    }
    
    // No successful requests (all errors)
    const successfulRequests = patterns.filter(p => p.successful).length;
    if (successfulRequests === 0 && patterns.length > 10) {
      riskScore += 0.2;
      detectedPatterns.push('all_failed_requests');
    }
    
    return {
      riskScore: Math.min(riskScore, 1.0),
      patterns: detectedPatterns,
      isBot: riskScore > 0.6
    };
  }
}

// Enterprise circuit breaker manager
export class EnterpriseCircuitBreakerManager {
  private circuitBreakers: Map<string, CircuitBreaker> = new Map();
  private defaultConfig: CircuitBreakerConfig;
  
  constructor(config?: Partial<CircuitBreakerConfig>) {
    this.defaultConfig = {
      timeout: 3000, // 3 second timeout
      errorThresholdPercentage: 50, // Trip at 50% error rate
      resetTimeout: 30000, // Try again after 30 seconds
      rollingCountTimeout: 10000, // 10 second rolling window
      rollingCountBuckets: 10, // Number of buckets in rolling window
      volumeThreshold: 10, // Minimum requests before circuit can trip
      ...config
    };
  }
  
  public createCircuitBreaker(name: string, operation: Function, config?: Partial<CircuitBreakerConfig>): CircuitBreaker {
    const finalConfig = { ...this.defaultConfig, ...config };
    
    const breaker = new CircuitBreaker(operation, {
      timeout: finalConfig.timeout,
      errorThresholdPercentage: finalConfig.errorThresholdPercentage,
      resetTimeout: finalConfig.resetTimeout,
      rollingCountTimeout: finalConfig.rollingCountTimeout,
      rollingCountBuckets: finalConfig.rollingCountBuckets,
      volumeThreshold: finalConfig.volumeThreshold
    });
    
    // Event handlers for logging
    breaker.on('open', () => {
      logger.warn(`Circuit breaker opened for ${name}`, {
        circuitBreaker: name,
        state: 'open'
      });
    });
    
    breaker.on('halfOpen', () => {
      logger.info(`Circuit breaker half-open for ${name}`, {
        circuitBreaker: name,
        state: 'half-open'
      });
    });
    
    breaker.on('close', () => {
      logger.info(`Circuit breaker closed for ${name}`, {
        circuitBreaker: name,
        state: 'closed'
      });
    });
    
    breaker.on('reject', () => {
      logger.debug(`Circuit breaker rejected request for ${name}`, {
        circuitBreaker: name,
        action: 'rejected'
      });
    });
    
    this.circuitBreakers.set(name, breaker);
    return breaker;
  }
  
  public getCircuitBreaker(name: string): CircuitBreaker | undefined {
    return this.circuitBreakers.get(name);
  }
  
  public getAllStats(): Record<string, any> {
    const stats: Record<string, any> = {};
    
    for (const [name, breaker] of this.circuitBreakers.entries()) {
      stats[name] = {
        state: breaker.state,
        stats: breaker.stats.toJSON()
      };
    }
    
    return stats;
  }
  
  public async shutdown(): Promise<void> {
    for (const [name, breaker] of this.circuitBreakers.entries()) {
      breaker.shutdown();
      logger.info(`Circuit breaker ${name} shut down`);
    }
    this.circuitBreakers.clear();
  }
}

// Singleton instances
export const ddosProtection = new AdvancedDDoSProtection();
export const circuitBreakerManager = new EnterpriseCircuitBreakerManager();

// Middleware factory for DDoS protection
export function createDDoSProtectionMiddleware() {
  return async (req: any, res: any, next: any): Promise<void> => {
    try {
      const result = await ddosProtection.checkDDoSProtection(req);
      
      if (!result.allowed) {
        const statusCode = result.reason === 'aggressive_ddos' ? 503 : 429;
        
        // Set appropriate headers
        res.setHeader('Retry-After', result.blockDuration || 300);
        res.setHeader('X-DDoS-Protection', 'active');
        res.setHeader('X-Risk-Score', (result.riskScore || 0).toFixed(2));
        
        return res.status(statusCode).json({
          error: {
            code: result.reason?.toUpperCase() || 'DDOS_PROTECTION',
            message: 'Request blocked by DDoS protection',
            retryAfter: result.blockDuration || 300
          }
        });
      }
      
      // Add risk score to request for other middleware
      req.riskScore = result.riskScore;
      
      next();
      
    } catch (error) {
      logger.error('DDoS protection middleware error', {
        error: error instanceof Error ? error.message : String(error)
      });
      
      // Fail open
      next();
    }
  };
}