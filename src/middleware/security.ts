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
  headers: {
    enabled: boolean;
    csrf: boolean;
    contentValidation: boolean;
    requestSizing: boolean;
  };
  ddosProtection: {
    enabled: boolean;
    behaviorAnalysis: boolean;
  };
  monitoring: {
    enabled: boolean;
    alerts: boolean;
    metrics: boolean;
  };
  circuitBreaker: {
    enabled: boolean;
    makeApi: boolean;
  };
  errorSanitization: {
    enabled: boolean;
    developmentMode: boolean;
  };
}

// Default security configuration
const DEFAULT_SECURITY_CONFIG: SecurityConfig = {
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
  headers: {
    enabled: true,
    csrf: true,
    contentValidation: true,
    requestSizing: true
  },
  ddosProtection: {
    enabled: true,
    behaviorAnalysis: true
  },
  monitoring: {
    enabled: true,
    alerts: true,
    metrics: true
  },
  circuitBreaker: {
    enabled: true,
    makeApi: true
  },
  errorSanitization: {
    enabled: true,
    developmentMode: process.env.NODE_ENV === 'development'
  }
};

// Integrated security middleware manager
export class IntegratedSecurityManager {
  private config: SecurityConfig;
  private initialized: boolean = false;
  
  constructor(config?: Partial<SecurityConfig>) {
    this.config = { ...DEFAULT_SECURITY_CONFIG, ...config };
    logger.info('Security manager initialized', {
      rateLimiting: this.config.rateLimiting.enabled,
      headers: this.config.headers.enabled,
      ddosProtection: this.config.ddosProtection.enabled,
      monitoring: this.config.monitoring.enabled,
      circuitBreaker: this.config.circuitBreaker.enabled,
      errorSanitization: this.config.errorSanitization.enabled
    });
  }
  
  public getSecurityMiddlewareStack(): any[] {
    const middlewares: any[] = [];\n    \n    // 1. Security monitoring (first to track all requests)\n    if (this.config.monitoring.enabled) {\n      middlewares.push(createSecurityMonitoringMiddleware());\n    }\n    \n    // 2. DDoS protection (early filtering)\n    if (this.config.ddosProtection.enabled) {\n      middlewares.push(createDDoSProtectionMiddleware());\n    }\n    \n    // 3. Security headers (comprehensive header protection)\n    if (this.config.headers.enabled) {\n      middlewares.push(createSecurityMiddleware());\n      \n      if (this.config.headers.contentValidation) {\n        middlewares.push(securityHeadersManager.getContentTypeValidation());\n      }\n      \n      if (this.config.headers.requestSizing) {\n        middlewares.push(securityHeadersManager.getRequestSizeLimiter());\n      }\n      \n      if (this.config.headers.csrf) {\n        middlewares.push(createCSRFMiddleware());\n      }\n    }\n    \n    // 4. Rate limiting (after headers but before business logic)\n    if (this.config.rateLimiting.enabled) {\n      if (this.config.rateLimiting.tiers.standard) {\n        middlewares.push(createRateLimitMiddleware('standard'));\n      }\n    }\n    \n    return middlewares;\n  }\n  \n  public getAuthSecurityMiddleware(): any[] {\n    const middlewares: any[] = [];\n    \n    if (this.config.rateLimiting.enabled && this.config.rateLimiting.tiers.auth) {\n      middlewares.push(createRateLimitMiddleware('auth'));\n    }\n    \n    return middlewares;\n  }\n  \n  public getSensitiveEndpointMiddleware(): any[] {\n    const middlewares: any[] = [];\n    \n    if (this.config.rateLimiting.enabled && this.config.rateLimiting.tiers.sensitive) {\n      middlewares.push(createRateLimitMiddleware('sensitive'));\n    }\n    \n    return middlewares;\n  }\n  \n  public getWebhookMiddleware(): any[] {\n    const middlewares: any[] = [];\n    \n    if (this.config.rateLimiting.enabled && this.config.rateLimiting.tiers.webhooks) {\n      middlewares.push(createRateLimitMiddleware('webhooks'));\n    }\n    \n    return middlewares;\n  }\n  \n  public getErrorHandlingMiddleware(): any[] {\n    const middlewares: any[] = [];\n    \n    if (this.config.errorSanitization.enabled) {\n      if (this.config.errorSanitization.developmentMode) {\n        middlewares.push(developmentErrorHandler());\n      } else {\n        middlewares.push(errorSanitizationMiddleware());\n      }\n    }\n    \n    return middlewares;\n  }\n  \n  public async initializeCircuitBreakers(apiClient: any): Promise<void> {\n    if (!this.config.circuitBreaker.enabled) {\n      return;\n    }\n    \n    if (this.config.circuitBreaker.makeApi && apiClient) {\n      // Create circuit breaker for Make.com API calls\n      const makeApiBreaker = circuitBreakerManager.createCircuitBreaker(\n        'make-api',\n        async (operation: string, ...args: any[]) => {\n          return await apiClient[operation](...args);\n        },\n        {\n          timeout: 10000, // 10 second timeout for API calls\n          errorThresholdPercentage: 60, // Trip at 60% error rate for external API\n          resetTimeout: 60000, // Try again after 1 minute\n          volumeThreshold: 5 // Minimum 5 requests before circuit can trip\n        }\n      );\n      \n      logger.info('Circuit breaker initialized for Make.com API');\n    }\n  }\n  \n  public getSecurityStatus(): {\n    rateLimiting: any;\n    ddosProtection: any;\n    circuitBreakers: any;\n    monitoring: any;\n    overall: string;\n  } {\n    const status = {\n      rateLimiting: this.config.rateLimiting.enabled ? rateLimitManager.getSystemStatus() : { enabled: false },\n      ddosProtection: this.config.ddosProtection.enabled ? ddosProtection.getStats() : { enabled: false },\n      circuitBreakers: this.config.circuitBreaker.enabled ? circuitBreakerManager.getAllStats() : { enabled: false },\n      monitoring: this.config.monitoring.enabled ? securityMonitoring.getSecuritySummary() : { enabled: false },\n      overall: 'healthy'\n    };\n    \n    // Determine overall health\n    let issues = 0;\n    \n    if (this.config.rateLimiting.enabled && !status.rateLimiting.redisConnected && this.config.rateLimiting.redis.enabled) {\n      issues++;\n    }\n    \n    if (this.config.monitoring.enabled && status.monitoring.currentRiskScore > 70) {\n      issues++;\n    }\n    \n    if (issues === 0) {\n      status.overall = 'healthy';\n    } else if (issues <= 2) {\n      status.overall = 'degraded';\n    } else {\n      status.overall = 'unhealthy';\n    }\n    \n    return status;\n  }\n  \n  public async shutdown(): Promise<void> {\n    logger.info('Shutting down security systems');\n    \n    const shutdownPromises: Promise<void>[] = [];\n    \n    if (this.config.rateLimiting.enabled) {\n      shutdownPromises.push(rateLimitManager.shutdown());\n    }\n    \n    if (this.config.circuitBreaker.enabled) {\n      shutdownPromises.push(circuitBreakerManager.shutdown());\n    }\n    \n    if (this.config.monitoring.enabled) {\n      securityMonitoring.shutdown();\n    }\n    \n    await Promise.all(shutdownPromises);\n    \n    logger.info('Security systems shutdown completed');\n  }\n  \n  public updateConfig(newConfig: Partial<SecurityConfig>): void {\n    this.config = { ...this.config, ...newConfig };\n    logger.info('Security configuration updated', newConfig);\n  }\n  \n  public getConfig(): SecurityConfig {\n    return { ...this.config };\n  }\n}\n\n// Singleton security manager\nexport const securityManager = new IntegratedSecurityManager();\n\n// Export all security components for individual use\nexport {\n  rateLimitManager,\n  createRateLimitMiddleware,\n  ddosProtectionMiddleware,\n  securityHeadersManager,\n  createSecurityMiddleware,\n  createCSRFMiddleware,\n  errorSanitizationMiddleware,\n  developmentErrorHandler,\n  ddosProtection,\n  circuitBreakerManager,\n  createDDoSProtectionMiddleware,\n  securityMonitoring,\n  createSecurityMonitoringMiddleware\n};\n\n// Utility functions\nexport function createSecurityHealthCheck() {\n  return async (): Promise<{\n    healthy: boolean;\n    status: any;\n    timestamp: string;\n  }> => {\n    const status = securityManager.getSecurityStatus();\n    \n    return {\n      healthy: status.overall === 'healthy',\n      status,\n      timestamp: new Date().toISOString()\n    };\n  };\n}\n\nexport function validateSecurityConfiguration(): {\n  valid: boolean;\n  issues: string[];\n  warnings: string[];\n} {\n  const issues: string[] = [];\n  const warnings: string[] = [];\n  const config = securityManager.getConfig();\n  \n  // Check for critical configuration issues\n  if (config.rateLimiting.enabled && config.rateLimiting.redis.enabled && !process.env.REDIS_URL) {\n    issues.push('Redis rate limiting enabled but REDIS_URL not configured');\n  }\n  \n  if (config.headers.csrf && !process.env.SESSION_SECRET) {\n    warnings.push('CSRF protection enabled but SESSION_SECRET not configured');\n  }\n  \n  if (process.env.NODE_ENV === 'production' && config.errorSanitization.developmentMode) {\n    warnings.push('Development error handling enabled in production');\n  }\n  \n  // Check for security best practices\n  if (!config.headers.enabled) {\n    warnings.push('Security headers disabled - not recommended for production');\n  }\n  \n  if (!config.monitoring.enabled) {\n    warnings.push('Security monitoring disabled - reduced visibility into threats');\n  }\n  \n  return {\n    valid: issues.length === 0,\n    issues,\n    warnings\n  };\n}"