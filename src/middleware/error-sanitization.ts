/**
 * Advanced Error Information Sanitization Middleware
 * Prevents information disclosure while maintaining audit capabilities
 * Phase 2 Security Enhancement Implementation
 */

import crypto from 'crypto';
import logger from '../lib/logger.js';
import { MakeServerError } from '../utils/errors.js';

// Secure error response interface
interface SecureErrorResponse {
  error: {
    code: string;
    message: string;
    timestamp: string;
    correlationId: string;
    // No stack traces or internal details exposed
  };
  success: false;
}

// Request context interface
interface RequestContext {
  correlationId?: string;
  endpoint: string;
  method: string;
  userId?: string;
  ip: string;
  userAgent?: string;
  sessionId?: string;
}

// Custom error types for categorization
export class ValidationError extends Error {
  constructor(message: string, public details?: any) {
    super(message);
    this.name = 'ValidationError';
  }
}

export class AuthenticationError extends Error {
  constructor(message: string, public details?: any) {
    super(message);
    this.name = 'AuthenticationError';
  }
}

export class AuthorizationError extends Error {
  constructor(message: string, public details?: any) {
    super(message);
    this.name = 'AuthorizationError';
  }
}

export class RateLimitError extends Error {
  constructor(message: string, public details?: any) {
    super(message);
    this.name = 'RateLimitError';
  }
}

export class ExternalApiError extends Error {
  constructor(message: string, public details?: any) {
    super(message);
    this.name = 'ExternalApiError';
  }
}

// Enhanced error sanitizer with information disclosure prevention
export class ErrorSanitizer {
  private static readonly SAFE_ERROR_MESSAGES = {
    VALIDATION_ERROR: 'Invalid input provided',
    AUTHENTICATION_ERROR: 'Authentication failed',
    AUTHORIZATION_ERROR: 'Access denied',
    RATE_LIMIT_ERROR: 'Too many requests',
    INTERNAL_ERROR: 'An internal error occurred',
    EXTERNAL_API_ERROR: 'External service unavailable',
    NETWORK_ERROR: 'Network connectivity issue',
    TIMEOUT_ERROR: 'Request timeout',
    NOT_FOUND_ERROR: 'Resource not found',
    CONFLICT_ERROR: 'Resource conflict',
    QUOTA_EXCEEDED: 'Resource quota exceeded'
  } as const;
  
  private static readonly DANGEROUS_PATTERNS = [
    /password\s*[:=]\s*[^\s,}]+/gi,
    /api[_-]?key\s*[:=]\s*[^\s,}]+/gi,
    /secret\s*[:=]\s*[^\s,}]+/gi,
    /token\s*[:=]\s*[^\s,}]+/gi,
    /authorization\s*:\s*[^\s,}]+/gi,
    /mysql|postgresql|database|connection/gi,
    /file:\/\/|\/etc\/|\/var\/|\/home\//gi,
    /stack trace|call stack/gi
  ];
  
  static sanitizeError(error: Error, context: RequestContext): SecureErrorResponse {
    const correlationId = context.correlationId || this.generateCorrelationId();
    
    // Log full error details for internal debugging with sanitized sensitive data
    this.logFullError(error, context, correlationId);
    
    // Return sanitized error to client
    return {
      error: {
        code: this.mapErrorCode(error),
        message: this.getSafeErrorMessage(error),
        timestamp: new Date().toISOString(),
        correlationId
      },
      success: false
    };
  }
  
  private static logFullError(error: Error, context: RequestContext, correlationId: string): void {
    // Sanitize error message and stack for logging
    const sanitizedMessage = this.sanitizeForLogging(error.message);
    const sanitizedStack = error.stack ? this.sanitizeForLogging(error.stack) : undefined;
    
    logger.error('Error occurred', {
      correlationId,
      error: {
        name: error.name,
        message: sanitizedMessage,
        stack: sanitizedStack,
        code: (error as any).code
      },
      context: {
        endpoint: context.endpoint,
        method: context.method,
        userId: context.userId,
        ip: this.hashIP(context.ip),
        userAgent: context.userAgent ? this.sanitizeUserAgent(context.userAgent) : undefined,
        sessionId: context.sessionId ? this.hashValue(context.sessionId) : undefined
      },
      metadata: {
        nodeVersion: process.version,
        platform: process.platform,
        memory: process.memoryUsage(),
        uptime: process.uptime()
      }
    });
  }
  
  private static mapErrorCode(error: Error): string {
    if (error instanceof ValidationError) return 'VALIDATION_ERROR';
    if (error instanceof AuthenticationError) return 'AUTHENTICATION_ERROR';
    if (error instanceof AuthorizationError) return 'AUTHORIZATION_ERROR';
    if (error instanceof RateLimitError) return 'RATE_LIMIT_ERROR';
    if (error instanceof ExternalApiError) return 'EXTERNAL_API_ERROR';
    
    // Map common error patterns
    if (error.message.includes('timeout')) return 'TIMEOUT_ERROR';
    if (error.message.includes('not found') || error.message.includes('404')) return 'NOT_FOUND_ERROR';
    if (error.message.includes('conflict') || error.message.includes('409')) return 'CONFLICT_ERROR';
    if (error.message.includes('quota') || error.message.includes('limit')) return 'QUOTA_EXCEEDED';
    if (error.message.includes('network') || error.message.includes('ECONNREFUSED')) return 'NETWORK_ERROR';
    
    return 'INTERNAL_ERROR';
  }
  
  private static getSafeErrorMessage(error: Error): string {
    const errorCode = this.mapErrorCode(error);
    return this.SAFE_ERROR_MESSAGES[errorCode as keyof typeof this.SAFE_ERROR_MESSAGES];
  }
  
  private static hashIP(ip: string): string {
    return crypto.createHash('sha256').update(ip + process.env.IP_HASH_SALT || 'default-salt').digest('hex').substring(0, 16);
  }
  
  private static hashValue(value: string): string {
    return crypto.createHash('sha256').update(value).digest('hex').substring(0, 16);
  }
  
  private static generateCorrelationId(): string {
    return crypto.randomBytes(16).toString('hex');
  }
  
  private static sanitizeForLogging(input: string): string {
    let sanitized = input;
    
    // Remove dangerous patterns
    this.DANGEROUS_PATTERNS.forEach(pattern => {
      sanitized = sanitized.replace(pattern, '[FILTERED]');
    });
    
    // Remove potential file paths
    sanitized = sanitized.replace(/[A-Za-z]:\\\\[^\\s]+|\/[^\\s]+/g, '[PATH]');
    
    // Remove potential SQL queries
    sanitized = sanitized.replace(/(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\\s+[^;]+;?/gi, '[SQL_QUERY]');
    
    // Truncate long inputs
    if (sanitized.length > 2000) {
      sanitized = sanitized.substring(0, 2000) + '[TRUNCATED]';
    }
    
    return sanitized;
  }
  
  private static sanitizeUserAgent(userAgent: string): string {
    // Keep only basic browser/OS info, remove detailed version numbers that could indicate vulnerabilities
    return userAgent.substring(0, 200).replace(/[\\r\\n\\x00-\\x1f]/g, '');
  }
  
  static sanitizeHeaders(headers: Record<string, any>): Record<string, any> {
    const sanitized: Record<string, any> = {};
    const sensitiveHeaders = ['authorization', 'x-api-key', 'cookie', 'x-auth-token'];
    
    for (const [key, value] of Object.entries(headers)) {
      if (sensitiveHeaders.includes(key.toLowerCase())) {
        sanitized[key] = '[REDACTED]';
      } else {
        sanitized[key] = typeof value === 'string' ? value.substring(0, 200) : value;
      }
    }
    
    return sanitized;
  }
}\n\n// Log injection prevention utility\nexport class LogSanitizer {\n  private static readonly DANGEROUS_PATTERNS = [\n    /\\r\\n|\\r|\\n/g, // CRLF injection\n    /\\x1b\\[[0-9;]*m/g, // ANSI escape sequences\n    /[\\x00-\\x1f\\x7f]/g, // Control characters\n    /<script[^>]*>.*?<\\/script>/gi, // Script tags\n    /javascript:/gi, // JavaScript protocol\n    /data:.*base64/gi, // Data URIs\n    /%[0-9a-f]{2}/gi, // URL encoded characters that could be malicious\n    /\\\\[\"'`]/g // Escaped quotes that could break log parsing\n  ];\n  \n  static sanitizeForLogging(input: string): string {\n    let sanitized = String(input);\n    \n    // Remove dangerous patterns\n    this.DANGEROUS_PATTERNS.forEach(pattern => {\n      sanitized = sanitized.replace(pattern, '[FILTERED]');\n    });\n    \n    // Truncate long inputs\n    if (sanitized.length > 1000) {\n      sanitized = sanitized.substring(0, 1000) + '[TRUNCATED]';\n    }\n    \n    return sanitized;\n  }\n  \n  static sanitizeObject(obj: any, maxDepth: number = 3): any {\n    if (maxDepth <= 0) {\n      return '[MAX_DEPTH_REACHED]';\n    }\n    \n    if (typeof obj === 'string') {\n      return this.sanitizeForLogging(obj);\n    }\n    \n    if (typeof obj !== 'object' || obj === null) {\n      return obj;\n    }\n    \n    if (Array.isArray(obj)) {\n      return obj.slice(0, 100).map(item => this.sanitizeObject(item, maxDepth - 1));\n    }\n    \n    const sanitized: Record<string, any> = {};\n    const entries = Object.entries(obj).slice(0, 50); // Limit object size\n    \n    for (const [key, value] of entries) {\n      const sanitizedKey = this.sanitizeForLogging(key);\n      sanitized[sanitizedKey] = this.sanitizeObject(value, maxDepth - 1);\n    }\n    \n    return sanitized;\n  }\n}\n\n// Secure error handling middleware\nexport function errorSanitizationMiddleware() {\n  return (error: Error, req: any, res: any, next: any): void => {\n    const context: RequestContext = {\n      correlationId: req.headers['x-correlation-id'] || req.correlationId,\n      endpoint: req.path || req.url,\n      method: req.method,\n      userId: req.user?.id,\n      ip: req.ip || req.connection?.remoteAddress || 'unknown',\n      userAgent: req.headers['user-agent'],\n      sessionId: req.sessionID\n    };\n    \n    const sanitizedError = ErrorSanitizer.sanitizeError(error, context);\n    \n    // Determine appropriate HTTP status code\n    let statusCode = 500;\n    if (error instanceof ValidationError) statusCode = 400;\n    if (error instanceof AuthenticationError) statusCode = 401;\n    if (error instanceof AuthorizationError) statusCode = 403;\n    if (error instanceof RateLimitError) statusCode = 429;\n    if (error.message.includes('not found')) statusCode = 404;\n    if (error.message.includes('conflict')) statusCode = 409;\n    \n    // Add security headers\n    res.setHeader('X-Content-Type-Options', 'nosniff');\n    res.setHeader('X-Frame-Options', 'DENY');\n    res.setHeader('X-XSS-Protection', '1; mode=block');\n    \n    res.status(statusCode).json(sanitizedError);\n  };\n}\n\n// Utility for safe error creation with automatic sanitization\nexport function createSafeError(\n  message: string,\n  type: 'validation' | 'authentication' | 'authorization' | 'rateLimit' | 'external' | 'internal' = 'internal',\n  details?: any\n): Error {\n  const sanitizedMessage = LogSanitizer.sanitizeForLogging(message);\n  const sanitizedDetails = details ? LogSanitizer.sanitizeObject(details) : undefined;\n  \n  switch (type) {\n    case 'validation':\n      return new ValidationError(sanitizedMessage, sanitizedDetails);\n    case 'authentication':\n      return new AuthenticationError(sanitizedMessage, sanitizedDetails);\n    case 'authorization':\n      return new AuthorizationError(sanitizedMessage, sanitizedDetails);\n    case 'rateLimit':\n      return new RateLimitError(sanitizedMessage, sanitizedDetails);\n    case 'external':\n      return new ExternalApiError(sanitizedMessage, sanitizedDetails);\n    default:\n      return new Error(sanitizedMessage);\n  }\n}\n\n// Development mode error handler with enhanced security\nexport function developmentErrorHandler() {\n  return (error: Error, req: any, res: any, next: any): void => {\n    const isDevelopment = process.env.NODE_ENV === 'development';\n    \n    const context: RequestContext = {\n      correlationId: req.headers['x-correlation-id'] || req.correlationId,\n      endpoint: req.path || req.url,\n      method: req.method,\n      userId: req.user?.id,\n      ip: req.ip || req.connection?.remoteAddress || 'unknown',\n      userAgent: req.headers['user-agent'],\n      sessionId: req.sessionID\n    };\n    \n    // Always sanitize for production\n    const sanitizedError = ErrorSanitizer.sanitizeError(error, context);\n    \n    // In development, add additional debug info but still sanitized\n    if (isDevelopment) {\n      const debugInfo = {\n        ...sanitizedError,\n        debug: {\n          errorType: error.constructor.name,\n          sanitizedStack: error.stack ? LogSanitizer.sanitizeForLogging(error.stack) : undefined,\n          context: LogSanitizer.sanitizeObject(context),\n          timestamp: new Date().toISOString()\n        }\n      };\n      \n      res.status(500).json(debugInfo);\n    } else {\n      res.status(500).json(sanitizedError);\n    }\n  };\n}"