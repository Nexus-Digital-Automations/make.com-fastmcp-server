/**
 * Comprehensive Security Headers Middleware with Helmet.js Enterprise Configuration
 * Implements CSP, HSTS, CSRF protection, and advanced security policies
 * Phase 2 Security Enhancement Implementation
 */

import helmet from 'helmet';
import { doubleCsrf } from 'csrf-csrf';
import type { Request, Response, NextFunction as ExpressNextFunction } from 'express';
import logger from '../lib/logger.js';

// Express-compatible types for middleware
interface ExtendedRequest extends Request {
  sessionID?: string;
  user?: { id: string };
  csrfToken?: () => string;
}

type HttpRequest = ExtendedRequest;
type HttpResponse = Response;
type NextFunction = ExpressNextFunction;

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
  private helmetInstance: (req: HttpRequest, res: HttpResponse, next: NextFunction) => void = () => {};
  private csrfUtilities: { generateCsrfToken: (req: HttpRequest, res: HttpResponse) => string; doubleCsrfProtection: (req: HttpRequest, res: HttpResponse, next: NextFunction) => void } | null = null;
  
  constructor(config?: Partial<SecurityConfig>) {
    this.config = {
      environment: (process.env.NODE_ENV as 'development' | 'production' | 'test') || 'development',
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
          ...(this.config.environment === 'production' && { upgradeInsecureRequests: [] })
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
      originAgentCluster: true
    });
  }
  
  private setupCSRF(): void {
    if (this.config.enableCSRF) {
      // Configure Double CSRF protection
      this.csrfUtilities = doubleCsrf({
        getSecret: () => process.env.CSRF_SECRET || 'default-csrf-secret-change-in-production',
        getSessionIdentifier: (req: HttpRequest) => req.sessionID || req.ip || 'anonymous',
        cookieName: '_csrf',
        cookieOptions: {
          httpOnly: false, // Client needs to read this for token access
          secure: this.config.environment === 'production',
          sameSite: 'strict',
          path: '/',
          maxAge: 3600000 // 1 hour
        },
        ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
        getCsrfTokenFromRequest: (req: HttpRequest): string => {
          // Extract CSRF token from multiple possible locations
          const token = req.body?._csrf ||
                       req.query?._csrf ||
                       req.headers?.['csrf-token'] ||
                       req.headers?.['x-csrf-token'] ||
                       req.headers?.['x-xsrf-token'] ||
                       '';
          return String(token || '');
        },
        errorConfig: {
          statusCode: 403,
          message: 'Invalid CSRF token. Please refresh the page and try again.',
          code: 'CSRF_TOKEN_INVALID'
        }
      });
    }
  }
  
  // Main security headers middleware
  public getSecurityMiddleware(): (req: HttpRequest, res: HttpResponse, next: NextFunction) => void {
    return (req: HttpRequest, res: HttpResponse, next: NextFunction) => {
      // Apply Helmet security headers
      this.helmetInstance(req, res, (err: unknown) => {
        if (err) {
          logger.error('Helmet middleware error', { error: err instanceof Error ? err.message : String(err) });
          return next(err);
        }
        
        // Apply additional custom security headers
        this.applyCustomSecurityHeaders(req, res);
        
        next();
      });
    };
  }
  
  // CSRF protection middleware
  public getCSRFMiddleware(): (req: HttpRequest, res: HttpResponse, next: NextFunction) => void {
    if (!this.config.enableCSRF || !this.csrfUtilities) {
      return (req: HttpRequest, res: HttpResponse, next: NextFunction) => next();
    }
    
    return (req: HttpRequest, res: HttpResponse, next: NextFunction) => {
      if (!this.csrfUtilities) {
        return next();
      }
      
      // For safe methods (GET, HEAD), generate and set CSRF token
      if (req.method === 'GET' || req.method === 'HEAD') {
        const csrfToken = this.csrfUtilities.generateCsrfToken(req, res);
        
        // Add token to request for access
        req.csrfToken = (): string => csrfToken;
        
        // Add token to response locals for templates
        if (res.locals) {
          res.locals.csrfToken = csrfToken;
        }
        
        return next();
      }
      
      // For unsafe methods, use the built-in protection middleware
      this.csrfUtilities.doubleCsrfProtection(req, res, (err: unknown) => {
        if (err) {
          logger.warn('CSRF protection triggered', {
            ip: req.ip,
            userAgent: ((): string => {
              const ua = req.headers['user-agent'];
              const userAgent = typeof ua === 'string' ? ua : Array.isArray(ua) ? ua[0] : '';
              return userAgent?.substring(0, 100) || '';
            })(),
            endpoint: req.path,
            method: req.method,
            error: err instanceof Error ? err.message : String(err)
          });
          
          // Error already handled by doubleCsrfProtection
          return;
        }
        
        next();
      });
    };
  }
  
  private applyCustomSecurityHeaders(req: HttpRequest, res: HttpResponse): void {
    const request = req as {
      headers: Record<string, string | string[] | undefined>;
      path?: string;
      rateLimit?: { limit?: string | number; remaining?: string | number; reset?: string | number };
    };
    const response = res as {
      setHeader(name: string, value: string | number): void;
    };
    
    // API versioning header
    response.setHeader('X-API-Version', '1.0');
    
    // Security policy enforcement
    response.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
    response.setHeader('X-Download-Options', 'noopen');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    
    // Rate limiting information (will be set by rate limiting middleware)
    if (request.rateLimit) {
      response.setHeader('X-RateLimit-Limit', request.rateLimit.limit || 'unknown');
      response.setHeader('X-RateLimit-Remaining', request.rateLimit.remaining || 'unknown');
      response.setHeader('X-RateLimit-Reset', request.rateLimit.reset || 'unknown');
    }
    
    // CORS security for production
    if (this.config.environment === 'production') {
      const origin = request.headers.origin;
      const originString = Array.isArray(origin) ? origin[0] : origin;
      if (originString && this.config.allowedOrigins.includes(originString)) {
        response.setHeader('Access-Control-Allow-Origin', originString);
      } else {
        response.setHeader('Access-Control-Allow-Origin', 'null');
      }
      
      response.setHeader('Access-Control-Allow-Credentials', 'true');
      response.setHeader('Access-Control-Allow-Methods', 'GET,HEAD,PUT,PATCH,POST,DELETE');
      response.setHeader('Access-Control-Allow-Headers', 'Origin,X-Requested-With,Content-Type,Accept,Authorization,X-API-Key,X-CSRF-Token');
    } else {
      // More permissive CORS for development
      response.setHeader('Access-Control-Allow-Origin', '*');
      response.setHeader('Access-Control-Allow-Methods', 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS');
      response.setHeader('Access-Control-Allow-Headers', '*');
    }
    
    // Security audit headers
    response.setHeader('X-Security-Enhanced', 'true');
    response.setHeader('X-Security-Version', '2.0');
    
    // Cache control for sensitive endpoints
    if (request.path && this.isSensitiveEndpoint(request.path)) {
      response.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
      response.setHeader('Pragma', 'no-cache');
      response.setHeader('Expires', '0');
    }
  }
  
  private isSensitiveEndpoint(path: string | undefined): boolean {
    const sensitivePatterns = [
      '/api/auth',
      '/api/users',
      '/api/billing',
      '/api/connections',
      '/api/credentials',
      '/api/secrets',
      '/api/permissions'
    ];
    
    return path ? sensitivePatterns.some(pattern => path.startsWith(pattern)) : false;
  }
  
  // Content type validation middleware
  public getContentTypeValidation(): (req: HttpRequest, res: HttpResponse, next: NextFunction) => void {
    return (req: HttpRequest, res: HttpResponse, next: NextFunction) => {
      // Only validate content type for requests with body
      if (req.method && ['POST', 'PUT', 'PATCH'].includes(req.method)) {
        const contentType = req.headers['content-type'];
        const contentTypeString = Array.isArray(contentType) ? contentType[0] : contentType;
        
        // Allow common content types
        const allowedTypes = [
          'application/json',
          'application/x-www-form-urlencoded',
          'multipart/form-data',
          'text/plain'
        ];
        
        if (contentTypeString && !allowedTypes.some(type => contentTypeString.includes(type))) {
          logger.warn('Invalid content type detected', {
            contentType: contentTypeString,
            ip: req.ip,
            endpoint: req.path,
            method: req.method
          });
          
          res.status(415).json({
            error: {
              code: 'UNSUPPORTED_MEDIA_TYPE',
              message: 'Content type not supported',
              allowedTypes
            }
          });
          return;
        }
      }
      
      next();
    };
  }
  
  // Request size limiting middleware
  public getRequestSizeLimiter(): (req: HttpRequest, res: HttpResponse, next: NextFunction) => void {
    return (req: HttpRequest, res: HttpResponse, next: NextFunction) => {
      const maxSize = 50 * 1024 * 1024; // 50MB max request size
      const contentLengthHeader = req.headers['content-length'];
      const contentLengthValue = Array.isArray(contentLengthHeader) ? contentLengthHeader[0] : contentLengthHeader;
      const contentLength = parseInt(contentLengthValue || '0', 10);
      
      if (contentLength > maxSize) {
        logger.warn('Request size limit exceeded', {
          contentLength,
          maxSize,
          ip: req.ip,
          endpoint: req.path
        });
        
        res.status(413).json({
          error: {
            code: 'PAYLOAD_TOO_LARGE',
            message: 'Request payload too large',
            maxSize: `${maxSize / (1024 * 1024)}MB`
          }
        });
        return;
      }
      
      next();
    };
  }
  
  // Security audit middleware
  public getSecurityAuditMiddleware(): (req: HttpRequest, res: HttpResponse, next: NextFunction) => void {
    return (req: HttpRequest, res: HttpResponse, next: NextFunction) => {
      const startTime = Date.now();
      
      // Log security-relevant requests
      if (this.isSecurityRelevantRequest(req)) {
        const correlationId = req.headers['x-correlation-id'];
        const userAgent = req.headers['user-agent'];
        const contentType = req.headers['content-type'];
        const origin = req.headers.origin;
        const reqWithSession = req as unknown as { sessionID?: string };
        
        logger.info('Security audit log', {
          correlationId: (Array.isArray(correlationId) ? correlationId[0] : correlationId) || 'unknown',
          method: req.method,
          endpoint: req.path,
          ip: this.hashIP(req.ip || 'unknown'),
          userAgent: (Array.isArray(userAgent) ? userAgent[0] : userAgent)?.substring(0, 200),
          userId: req.user?.id,
          sessionId: reqWithSession.sessionID,
          timestamp: new Date().toISOString(),
          securityHeaders: {
            hasCSRF: !!req.headers['x-csrf-token'],
            hasAuth: !!(req.headers.authorization || req.headers['x-api-key']),
            contentType: Array.isArray(contentType) ? contentType[0] : contentType,
            origin: Array.isArray(origin) ? origin[0] : origin
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
  
  private isSecurityRelevantRequest(req: HttpRequest): boolean {
    const securityEndpoints = [
      '/api/auth',
      '/api/users',
      '/api/permissions',
      '/api/billing',
      '/api/connections',
      '/api/credentials'
    ];
    
    return securityEndpoints.some(endpoint => req.path?.startsWith(endpoint)) ||
           req.method !== 'GET' ||
           !!req.headers.authorization ||
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
export function createSecurityMiddleware(config?: Partial<SecurityConfig>): (req: HttpRequest, res: HttpResponse, next: NextFunction) => void {
  const manager = config ? new SecurityHeadersManager(config) : securityHeadersManager;
  return manager.getSecurityMiddleware();
}

export function createCSRFMiddleware(config?: Partial<SecurityConfig>): (req: HttpRequest, res: HttpResponse, next: NextFunction) => void {
  const manager = config ? new SecurityHeadersManager(config) : securityHeadersManager;
  return manager.getCSRFMiddleware();
}

export function createContentTypeValidation(): (req: HttpRequest, res: HttpResponse, next: NextFunction) => void {
  return securityHeadersManager.getContentTypeValidation();
}

export function createRequestSizeLimiter(): (req: HttpRequest, res: HttpResponse, next: NextFunction) => void {
  return securityHeadersManager.getRequestSizeLimiter();
}

export function createSecurityAuditMiddleware(): (req: HttpRequest, res: HttpResponse, next: NextFunction) => void {
  return securityHeadersManager.getSecurityAuditMiddleware();
}

// Utility for checking if request passes security requirements
export function validateSecurityHeaders(req: HttpRequest): { valid: boolean; issues: string[] } {
  const issues: string[] = [];
  
  // Check for required security headers in sensitive endpoints
  if (req.path && securityHeadersManager.isSensitiveEndpoint(req.path)) {
    if (!req.headers['x-csrf-token'] && req.method && ['POST', 'PUT', 'DELETE'].includes(req.method)) {
      issues.push('Missing CSRF token for sensitive endpoint');
    }
    
    if (!req.headers.authorization && !req.headers['x-api-key']) {
      issues.push('Missing authentication for sensitive endpoint');
    }
  }
  
  return {
    valid: issues.length === 0,
    issues
  };
}