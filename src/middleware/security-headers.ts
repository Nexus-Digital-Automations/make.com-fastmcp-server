/**
 * Comprehensive Security Headers Middleware with Helmet.js Enterprise Configuration
 * Implements CSP, HSTS, CSRF protection, and advanced security policies
 * Phase 2 Security Enhancement Implementation
 */

import helmet from 'helmet';
import csrf from 'csurf';
import logger from '../lib/logger.js';

// Security configuration interface
interface SecurityConfig {
  environment: 'development' | 'production' | 'test';
  allowedOrigins: string[];
  trustedDomains: string[];
  cspReportUri?: string;
  enableCSRF: boolean;
}

// Enterprise security headers manager
export class SecurityHeadersManager {
  private config: SecurityConfig;
  private helmetInstance: any;
  private csrfProtection: any;
  
  constructor(config?: Partial<SecurityConfig>) {
    this.config = {
      environment: (process.env.NODE_ENV as any) || 'development',
      allowedOrigins: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
      trustedDomains: process.env.TRUSTED_DOMAINS?.split(',') || ['make.com', 'eu1.make.com'],
      cspReportUri: process.env.CSP_REPORT_URI,
      enableCSRF: process.env.ENABLE_CSRF !== 'false',
      ...config
    };
    
    this.setupHelmet();
    this.setupCSRF();
    
    logger.info('Security headers manager initialized', {
      environment: this.config.environment,
      allowedOrigins: this.config.allowedOrigins.length,
      trustedDomains: this.config.trustedDomains.length,
      csrfEnabled: this.config.enableCSRF
    });
  }
  
  private setupHelmet(): void {
    this.helmetInstance = helmet({
      // Content Security Policy - Strict enterprise configuration
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: [
            "'self'",
            "'unsafe-inline'", // Required for some admin interfaces
            "https:"
          ],
          scriptSrc: [
            "'self'",
            "'strict-dynamic'",
            ...(this.config.environment === 'development' ? ["'unsafe-eval'"] : [])
          ],
          imgSrc: [
            "'self'",
            "data:",
            "https:",
            ...this.config.trustedDomains.map(domain => `https://*.${domain}`)
          ],
          connectSrc: [
            "'self'",
            "https://api.make.com",
            "https://eu1.make.com",
            "https://us1.make.com",
            ...this.config.trustedDomains.map(domain => `https://*.${domain}`),
            ...(this.config.environment === 'development' ? ['ws:', 'wss:'] : [])
          ],
          fontSrc: [
            "'self'",
            "https:",
            "data:"
          ],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'"],
          frameSrc: ["'none'"],
          childSrc: ["'none'"],
          workerSrc: ["'self'"],
          frameAncestors: ["'none'"],
          formAction: ["'self'"],
          baseUri: ["'self'"],
          upgradeInsecureRequests: this.config.environment === 'production' ? [] : undefined
        },
        reportOnly: this.config.environment === 'development',
        ...(this.config.cspReportUri && {
          reportUri: this.config.cspReportUri
        })
      },
      
      // HTTP Strict Transport Security
      hsts: {
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true
      },
      
      // Prevent clickjacking
      frameguard: {
        action: 'deny'
      },
      
      // Prevent MIME type sniffing
      noSniff: true,
      
      // XSS Protection
      xssFilter: true,
      
      // Referrer Policy - Strict privacy protection
      referrerPolicy: {
        policy: 'strict-origin-when-cross-origin'
      },
      
      // Cross-Origin Policies
      crossOriginOpenerPolicy: {
        policy: 'same-origin'
      },
      
      crossOriginResourcePolicy: {
        policy: 'same-origin'
      },
      
      crossOriginEmbedderPolicy: this.config.environment === 'production' ? {
        policy: 'require-corp'
      } : false,
      
      // Hide X-Powered-By header
      hidePoweredBy: true,
      
      // DNS Prefetch Control
      dnsPrefetchControl: {
        allow: false
      },
      
      // Download Options (IE8+)
      ieNoOpen: true,
      
      // Origin Agent Cluster
      originAgentCluster: true,
      
      // Permissions Policy (formerly Feature Policy)
      permissionsPolicy: {
        camera: [],
        microphone: [],
        geolocation: [],
        payment: [],
        usb: [],
        bluetooth: [],
        magnetometer: [],
        accelerometer: [],
        gyroscope: [],
        ambient_light_sensor: []
      }
    });
  }
  
  private setupCSRF(): void {
    if (this.config.enableCSRF) {
      this.csrfProtection = csrf({
        cookie: {
          httpOnly: true,
          secure: this.config.environment === 'production',
          sameSite: 'strict',
          maxAge: 3600000, // 1 hour
          signed: true
        },
        sessionKey: 'session',
        value: (req: any) => {
          // Extract CSRF token from multiple possible locations
          return req.body._csrf ||
                 req.query._csrf ||
                 req.headers['csrf-token'] ||
                 req.headers['x-csrf-token'] ||
                 req.headers['x-xsrf-token'];
        },
        ignoreMethods: ['GET', 'HEAD', 'OPTIONS'],
        skip: (req: any) => {
          // Skip CSRF for API endpoints that use other authentication
          const isApiEndpoint = req.path.startsWith('/api/');
          const hasApiAuth = req.headers['x-api-key'] || req.headers['authorization'];
          return isApiEndpoint && hasApiAuth;
        }
      });
    }
  }
  
  // Main security headers middleware
  public getSecurityMiddleware() {
    return (req: any, res: any, next: any) => {
      // Apply Helmet security headers
      this.helmetInstance(req, res, (err: any) => {
        if (err) {
          logger.error('Helmet middleware error', { error: err.message });
          return next(err);
        }
        
        // Apply additional custom security headers
        this.applyCustomSecurityHeaders(req, res);
        
        next();
      });
    };
  }
  
  // CSRF protection middleware
  public getCSRFMiddleware() {
    if (!this.config.enableCSRF) {
      return (req: any, res: any, next: any) => next();
    }
    
    return (req: any, res: any, next: any) => {
      this.csrfProtection(req, res, (err: any) => {
        if (err) {
          logger.warn('CSRF protection triggered', {
            ip: req.ip,
            userAgent: req.headers['user-agent']?.substring(0, 100),
            endpoint: req.path,
            method: req.method
          });
          
          return res.status(403).json({
            error: {
              code: 'CSRF_TOKEN_INVALID',
              message: 'Invalid CSRF token. Please refresh the page and try again.'
            }
          });
        }
        
        // Add CSRF token to response for client use
        if (req.csrfToken) {
          res.locals.csrfToken = req.csrfToken();
        }
        
        next();
      });
    };
  }
  
  private applyCustomSecurityHeaders(req: any, res: any): void {
    // API versioning header
    res.setHeader('X-API-Version', '1.0');
    
    // Security policy enforcement
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
    res.setHeader('X-Download-Options', 'noopen');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    
    // Rate limiting information (will be set by rate limiting middleware)
    if (req.rateLimit) {
      res.setHeader('X-RateLimit-Limit', req.rateLimit.limit || 'unknown');
      res.setHeader('X-RateLimit-Remaining', req.rateLimit.remaining || 'unknown');
      res.setHeader('X-RateLimit-Reset', req.rateLimit.reset || 'unknown');
    }
    
    // CORS security for production
    if (this.config.environment === 'production') {
      const origin = req.headers.origin;
      if (origin && this.config.allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
      } else {
        res.setHeader('Access-Control-Allow-Origin', 'null');
      }
      
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods', 'GET,HEAD,PUT,PATCH,POST,DELETE');
      res.setHeader('Access-Control-Allow-Headers', 'Origin,X-Requested-With,Content-Type,Accept,Authorization,X-API-Key,X-CSRF-Token');
    } else {
      // More permissive CORS for development
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', '*');
    }
    
    // Security audit headers
    res.setHeader('X-Security-Enhanced', 'true');
    res.setHeader('X-Security-Version', '2.0');
    
    // Cache control for sensitive endpoints
    if (this.isSensitiveEndpoint(req.path)) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }
  }
  
  private isSensitiveEndpoint(path: string): boolean {
    const sensitivePatterns = [
      '/api/auth',
      '/api/users',
      '/api/billing',
      '/api/connections',
      '/api/credentials',
      '/api/secrets',
      '/api/permissions'
    ];
    
    return sensitivePatterns.some(pattern => path.startsWith(pattern));
  }
  
  // Content type validation middleware
  public getContentTypeValidation() {
    return (req: any, res: any, next: any) => {
      // Only validate content type for requests with body
      if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
        const contentType = req.headers['content-type'];
        
        // Allow common content types
        const allowedTypes = [
          'application/json',
          'application/x-www-form-urlencoded',
          'multipart/form-data',
          'text/plain'
        ];
        
        if (contentType && !allowedTypes.some(type => contentType.includes(type))) {
          logger.warn('Invalid content type detected', {
            contentType,
            ip: req.ip,
            endpoint: req.path,
            method: req.method
          });
          
          return res.status(415).json({
            error: {
              code: 'UNSUPPORTED_MEDIA_TYPE',
              message: 'Content type not supported',
              allowedTypes
            }
          });
        }
      }
      
      next();
    };
  }
  
  // Request size limiting middleware
  public getRequestSizeLimiter() {
    return (req: any, res: any, next: any) => {
      const maxSize = 50 * 1024 * 1024; // 50MB max request size
      const contentLength = parseInt(req.headers['content-length'] || '0', 10);
      
      if (contentLength > maxSize) {
        logger.warn('Request size limit exceeded', {
          contentLength,
          maxSize,
          ip: req.ip,
          endpoint: req.path
        });
        
        return res.status(413).json({
          error: {
            code: 'PAYLOAD_TOO_LARGE',
            message: 'Request payload too large',
            maxSize: `${maxSize / (1024 * 1024)}MB`
          }
        });
      }
      
      next();
    };
  }
  
  // Security audit middleware
  public getSecurityAuditMiddleware() {
    return (req: any, res: any, next: any) => {
      const startTime = Date.now();
      
      // Log security-relevant requests
      if (this.isSecurityRelevantRequest(req)) {
        logger.info('Security audit log', {
          correlationId: req.headers['x-correlation-id'] || 'unknown',
          method: req.method,
          endpoint: req.path,
          ip: this.hashIP(req.ip || 'unknown'),
          userAgent: req.headers['user-agent']?.substring(0, 200),
          userId: req.user?.id,
          sessionId: req.sessionID,
          timestamp: new Date().toISOString(),
          securityHeaders: {
            hasCSRF: !!req.headers['x-csrf-token'],
            hasAuth: !!(req.headers['authorization'] || req.headers['x-api-key']),
            contentType: req.headers['content-type'],
            origin: req.headers['origin']
          }
        });
      }
      
      // Track response time for security monitoring
      res.on('finish', () => {
        const responseTime = Date.now() - startTime;
        
        // Log slow responses as potential security indicators
        if (responseTime > 5000) {
          logger.warn('Slow response detected', {
            responseTime,
            endpoint: req.path,
            method: req.method,
            statusCode: res.statusCode
          });
        }
      });
      
      next();
    };
  }
  
  private isSecurityRelevantRequest(req: any): boolean {
    const securityEndpoints = [
      '/api/auth',
      '/api/users',
      '/api/permissions',
      '/api/billing',
      '/api/connections',
      '/api/credentials'
    ];
    
    return securityEndpoints.some(endpoint => req.path.startsWith(endpoint)) ||
           req.method !== 'GET' ||
           !!req.headers['authorization'] ||
           !!req.headers['x-api-key'];
  }
  
  private hashIP(ip: string): string {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(ip + (process.env.IP_HASH_SALT || 'default-salt')).digest('hex').substring(0, 16);
  }
  
  public getConfig(): SecurityConfig {
    return { ...this.config };
  }
  
  public updateConfig(newConfig: Partial<SecurityConfig>): void {
    this.config = { ...this.config, ...newConfig };
    this.setupHelmet();
    this.setupCSRF();
    
    logger.info('Security configuration updated', {
      environment: this.config.environment,
      allowedOrigins: this.config.allowedOrigins.length,
      csrfEnabled: this.config.enableCSRF
    });
  }
}

// Singleton instance
export const securityHeadersManager = new SecurityHeadersManager();

// Middleware factory functions
export function createSecurityMiddleware(config?: Partial<SecurityConfig>) {
  const manager = config ? new SecurityHeadersManager(config) : securityHeadersManager;
  return manager.getSecurityMiddleware();
}

export function createCSRFMiddleware(config?: Partial<SecurityConfig>) {
  const manager = config ? new SecurityHeadersManager(config) : securityHeadersManager;
  return manager.getCSRFMiddleware();
}

export function createContentTypeValidation() {
  return securityHeadersManager.getContentTypeValidation();
}

export function createRequestSizeLimiter() {
  return securityHeadersManager.getRequestSizeLimiter();
}

export function createSecurityAuditMiddleware() {
  return securityHeadersManager.getSecurityAuditMiddleware();
}

// Utility for checking if request passes security requirements
export function validateSecurityHeaders(req: any): { valid: boolean; issues: string[] } {
  const issues: string[] = [];
  
  // Check for required security headers in sensitive endpoints
  if (securityHeadersManager['isSensitiveEndpoint'](req.path)) {
    if (!req.headers['x-csrf-token'] && ['POST', 'PUT', 'DELETE'].includes(req.method)) {
      issues.push('Missing CSRF token for sensitive endpoint');
    }
    
    if (!req.headers['authorization'] && !req.headers['x-api-key']) {
      issues.push('Missing authentication for sensitive endpoint');
    }
  }
  
  return {
    valid: issues.length === 0,
    issues
  };
}