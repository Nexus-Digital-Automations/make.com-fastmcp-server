/**
 * Security Middleware Integration Hub
 * Centralized export and configuration for all security enhancements
 * Phase 2 Security Enhancement Implementation
 */

// Import all security middleware components
import { rateLimitManager, createRateLimitMiddleware, ddosProtectionMiddleware } from './rate-limiting.js';
import { securityHeadersManager, createSecurityMiddleware, createCSRFMiddleware } from './security-headers.js';
import { errorSanitizationMiddleware, developmentErrorHandler } from './error-sanitization.js';
import { ddosProtection, circuitBreakerManager, createDDoSProtectionMiddleware } from './circuit-breaker.js';
import { securityMonitoring, createSecurityMonitoringMiddleware } from './security-monitoring.js';
import logger from '../lib/logger.js';

// Security configuration interface
interface SecurityConfig {
  rateLimiting: {
    enabled: boolean;
    redis: {
      enabled: boolean;
      url?: string;
    };
    tiers: {
      auth: boolean;
      standard: boolean;
      sensitive: boolean;
      webhooks: boolean;
    };
  };
  ddosProtection: {
    enabled: boolean;
    behaviorAnalysis: boolean;
    ipReputation: boolean;
  };
  headers: {
    enabled: boolean;
    contentValidation: boolean;
    requestSizing: boolean;
    csrf: boolean;
    securityAudit: boolean;
  };
  errorSanitization: {
    enabled: boolean;
    developmentMode: boolean;
    logSanitization: boolean;
  };
  circuitBreaker: {
    enabled: boolean;
    makeApi: boolean;
    externalServices: boolean;
  };
  monitoring: {
    enabled: boolean;
    realTimeAlerts: boolean;
    metricsCollection: boolean;
  };
}

// Integrated security management class
export class IntegratedSecurityManager {
  private config: SecurityConfig;
  
  constructor(config?: Partial<SecurityConfig>) {
    this.config = {
      rateLimiting: {
        enabled: true,
        redis: {
          enabled: !!process.env.REDIS_URL,
          url: process.env.REDIS_URL
        },
        tiers: {
          auth: true,
          standard: true,
          sensitive: true,
          webhooks: true
        }
      },
      ddosProtection: {
        enabled: true,
        behaviorAnalysis: true,
        ipReputation: true
      },
      headers: {
        enabled: true,
        contentValidation: true,
        requestSizing: true,
        csrf: process.env.NODE_ENV !== 'test',
        securityAudit: true
      },
      errorSanitization: {
        enabled: true,
        developmentMode: process.env.NODE_ENV === 'development',
        logSanitization: true
      },
      circuitBreaker: {
        enabled: true,
        makeApi: true,
        externalServices: true
      },
      monitoring: {
        enabled: true,
        realTimeAlerts: true,
        metricsCollection: true
      },
      ...config
    };
    
    this.initialize();
  }
  
  private initialize(): void {
    logger.info('Initializing integrated security manager', {
      rateLimiting: this.config.rateLimiting.enabled,
      ddosProtection: this.config.ddosProtection.enabled,
      headers: this.config.headers.enabled,
      errorSanitization: this.config.errorSanitization.enabled,
      circuitBreaker: this.config.circuitBreaker.enabled,
      monitoring: this.config.monitoring.enabled
    });
  }
  
  public getSecurityMiddlewareStack(): any[] {
    const middlewares: any[] = [];
    
    // 1. Security monitoring (first to track all requests)
    if (this.config.monitoring.enabled) {
      middlewares.push(createSecurityMonitoringMiddleware());
    }
    
    // 2. DDoS protection (early filtering)
    if (this.config.ddosProtection.enabled) {
      middlewares.push(createDDoSProtectionMiddleware());
    }
    
    // 3. Security headers (comprehensive header protection)
    if (this.config.headers.enabled) {
      middlewares.push(createSecurityMiddleware());
      
      if (this.config.headers.contentValidation) {
        middlewares.push(securityHeadersManager.getContentTypeValidation());
      }
      
      if (this.config.headers.requestSizing) {
        middlewares.push(securityHeadersManager.getRequestSizeLimiter());
      }
      
      if (this.config.headers.csrf) {
        middlewares.push(createCSRFMiddleware());
      }
    }
    
    // 4. Rate limiting (after headers but before business logic)
    if (this.config.rateLimiting.enabled) {
      if (this.config.rateLimiting.tiers.standard) {
        middlewares.push(createRateLimitMiddleware('standard'));
      }
    }
    
    return middlewares;
  }
  
  public getAuthSecurityMiddleware(): any[] {
    const middlewares: any[] = [];
    
    if (this.config.rateLimiting.enabled && this.config.rateLimiting.tiers.auth) {
      middlewares.push(createRateLimitMiddleware('auth'));
    }
    
    return middlewares;
  }
  
  public getSensitiveEndpointMiddleware(): any[] {
    const middlewares: any[] = [];
    
    if (this.config.rateLimiting.enabled && this.config.rateLimiting.tiers.sensitive) {
      middlewares.push(createRateLimitMiddleware('sensitive'));
    }
    
    return middlewares;
  }
  
  public getWebhookMiddleware(): any[] {
    const middlewares: any[] = [];
    
    if (this.config.rateLimiting.enabled && this.config.rateLimiting.tiers.webhooks) {
      middlewares.push(createRateLimitMiddleware('webhooks'));
    }
    
    return middlewares;
  }
  
  public getErrorHandlingMiddleware(): any[] {
    const middlewares: any[] = [];
    
    if (this.config.errorSanitization.enabled) {
      if (this.config.errorSanitization.developmentMode) {
        middlewares.push(developmentErrorHandler());
      } else {
        middlewares.push(errorSanitizationMiddleware());
      }
    }
    
    return middlewares;
  }
  
  public async initializeCircuitBreakers(apiClient: any): Promise<void> {
    if (!this.config.circuitBreaker.enabled) {
      return;
    }
    
    if (this.config.circuitBreaker.makeApi && apiClient) {
      // Create circuit breaker for Make.com API calls
      const _makeApiBreaker = circuitBreakerManager.createCircuitBreaker(
        'make-api',
        async (...args: unknown[]) => {
          const [operation, ...restArgs] = args;
          if (typeof operation !== 'string') {
            throw new Error('First argument must be a string operation name');
          }
          return await (apiClient as any)[operation](...restArgs);
        },
        {
          timeout: 10000, // 10 second timeout for API calls
          errorThresholdPercentage: 60, // Trip at 60% error rate for external API
          resetTimeout: 60000, // Try again after 1 minute
          volumeThreshold: 5 // Minimum 5 requests before circuit can trip
        }
      );
      
      logger.info('Circuit breaker initialized for Make.com API');
    }
  }
  
  public getSecurityStatus(): {
    rateLimiting: any;
    ddosProtection: any;
    circuitBreakers: any;
    monitoring: any;
    overall: string;
  } {
    const status = {
      rateLimiting: this.config.rateLimiting.enabled ? rateLimitManager.getSystemStatus() : { enabled: false },
      ddosProtection: this.config.ddosProtection.enabled ? ddosProtection.getStats() : { enabled: false },
      circuitBreakers: this.config.circuitBreaker.enabled ? circuitBreakerManager.getAllStats() : { enabled: false },
      monitoring: this.config.monitoring.enabled ? securityMonitoring.getSecuritySummary() : { enabled: false },
      overall: 'healthy'
    };
    
    // Determine overall health
    let issues = 0;
    
    if (this.config.rateLimiting.enabled && 'redisConnected' in status.rateLimiting && !status.rateLimiting.redisConnected && this.config.rateLimiting.redis.enabled) {
      issues++;
    }
    
    if (this.config.monitoring.enabled && 'currentRiskScore' in status.monitoring && status.monitoring.currentRiskScore > 70) {
      issues++;
    }
    
    if (issues === 0) {
      status.overall = 'healthy';
    } else if (issues <= 2) {
      status.overall = 'degraded';
    } else {
      status.overall = 'unhealthy';
    }
    
    return status;
  }
  
  public async shutdown(): Promise<void> {
    logger.info('Shutting down security systems');
    
    const shutdownPromises: Promise<void>[] = [];
    
    if (this.config.rateLimiting.enabled) {
      shutdownPromises.push(rateLimitManager.shutdown());
    }
    
    if (this.config.circuitBreaker.enabled) {
      shutdownPromises.push(circuitBreakerManager.shutdown());
    }
    
    if (this.config.monitoring.enabled) {
      securityMonitoring.shutdown();
    }
    
    await Promise.all(shutdownPromises);
    
    logger.info('Security systems shutdown completed');
  }
  
  public updateConfig(newConfig: Partial<SecurityConfig>): void {
    this.config = { ...this.config, ...newConfig };
    logger.info('Security configuration updated', newConfig);
  }
  
  public getConfig(): SecurityConfig {
    return { ...this.config };
  }
}

// Singleton security manager
export const securityManager = new IntegratedSecurityManager();

// Export all security components for individual use
export {
  rateLimitManager,
  createRateLimitMiddleware,
  ddosProtectionMiddleware,
  securityHeadersManager,
  createSecurityMiddleware,
  createCSRFMiddleware,
  errorSanitizationMiddleware,
  developmentErrorHandler,
  ddosProtection,
  circuitBreakerManager,
  createDDoSProtectionMiddleware,
  securityMonitoring,
  createSecurityMonitoringMiddleware
};

// Utility functions
export function createSecurityHealthCheck() {
  return async (): Promise<{
    healthy: boolean;
    status: any;
    timestamp: string;
  }> => {
    const status = securityManager.getSecurityStatus();
    
    return {
      healthy: status.overall === 'healthy',
      status,
      timestamp: new Date().toISOString()
    };
  };
}

export function validateSecurityConfiguration(): {
  valid: boolean;
  issues: string[];
  warnings: string[];
} {
  const issues: string[] = [];
  const warnings: string[] = [];
  const config = securityManager.getConfig();
  
  // Check for critical configuration issues
  if (config.rateLimiting.enabled && config.rateLimiting.redis.enabled && !process.env.REDIS_URL) {
    issues.push('Redis rate limiting enabled but REDIS_URL not configured');
  }
  
  if (config.headers.csrf && !process.env.SESSION_SECRET) {
    warnings.push('CSRF protection enabled but SESSION_SECRET not configured');
  }
  
  if (process.env.NODE_ENV === 'production' && config.errorSanitization.developmentMode) {
    warnings.push('Development error handling enabled in production');
  }
  
  // Check for security best practices
  if (!config.headers.enabled) {
    warnings.push('Security headers disabled - not recommended for production');
  }
  
  if (!config.monitoring.enabled) {
    warnings.push('Security monitoring disabled - reduced visibility into threats');
  }
  
  return {
    valid: issues.length === 0,
    issues,
    warnings
  };
}