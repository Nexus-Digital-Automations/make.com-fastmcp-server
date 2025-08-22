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

// Custom error types for sanitization
class ValidationError extends Error {
  constructor(message: string, public details?: any) {
    super(message);
    this.name = 'ValidationError';
  }
}

class AuthenticationError extends Error {
  constructor(message: string, public details?: any) {
    super(message);
    this.name = 'AuthenticationError';
  }
}

class AuthorizationError extends Error {
  constructor(message: string, public details?: any) {
    super(message);
    this.name = 'AuthorizationError';
  }
}

class RateLimitError extends Error {
  constructor(message: string, public details?: any) {
    super(message);
    this.name = 'RateLimitError';
  }
}

class ExternalApiError extends Error {
  constructor(message: string, public details?: any) {
    super(message);
    this.name = 'ExternalApiError';
  }
}

// Main error sanitization class
export class ErrorSanitizer {
  private static readonly SENSITIVE_PATTERNS = [
    // Database connection strings
    /mongodb:\/\/[^\/\s]+/gi,
    /postgresql:\/\/[^\/\s]+/gi,
    /mysql:\/\/[^\/\s]+/gi,
    
    // API keys and tokens
    /[A-Za-z0-9]{20,}/g, // Generic tokens
    /sk_[A-Za-z0-9]+/g, // Stripe keys
    /pk_[A-Za-z0-9]+/g, // Stripe public keys
    
    // File paths that might contain usernames
    /\/Users\/[^\/\s]+/g,
    /\/home\/[^\/\s]+/g,
    /C:\\Users\\[^\\\/\s]+/g,
    
    // IP addresses (partial obfuscation)
    /\b(\d{1,3}\.)\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,
    
    // Email addresses (partial obfuscation)
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    
    // Password-like strings
    /password['":][\s]*['"][^'"]+['"]/gi,
    /pass['":][\s]*['"][^'"]+['"]/gi,
    /secret['":][\s]*['"][^'"]+['"]/gi,
    
    // JSON Web Tokens
    /eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+\/=]*/g
  ];

  private static readonly SAFE_ERROR_MESSAGES = {
    ValidationError: 'Invalid input provided. Please check your request and try again.',
    AuthenticationError: 'Authentication failed. Please verify your credentials.',
    AuthorizationError: 'Access denied. You do not have permission to perform this action.',
    RateLimitError: 'Too many requests. Please wait before trying again.',
    ExternalApiError: 'External service unavailable. Please try again later.',
    DatabaseError: 'Data operation failed. Please try again.',
    NetworkError: 'Network connectivity issue. Please check your connection.',
    default: 'An unexpected error occurred. Please try again or contact support.'
  };

  static sanitizeError(error: Error, context: RequestContext): SecureErrorResponse {
    const correlationId = context.correlationId || this.generateCorrelationId();
    
    // Determine error type and appropriate safe message
    const errorType = error.constructor.name;
    const safeMessage = this.getSafeErrorMessage(errorType, error.message);
    
    // Generate error code
    const errorCode = this.generateErrorCode(errorType, error.message);
    
    // Log full error details securely for debugging
    this.logErrorForAudit(error, context, correlationId);
    
    return {
      error: {
        code: errorCode,
        message: safeMessage,
        timestamp: new Date().toISOString(),
        correlationId
      },
      success: false
    };
  }

  private static getSafeErrorMessage(errorType: string, originalMessage: string): string {
    // Check if it's a known safe error type with specific message
    if (errorType in this.SAFE_ERROR_MESSAGES) {
      return this.SAFE_ERROR_MESSAGES[errorType as keyof typeof this.SAFE_ERROR_MESSAGES];
    }
    
    // For unknown errors, check if the message looks safe to expose
    if (this.isSafeMessage(originalMessage)) {
      return this.sanitizeMessage(originalMessage);
    }
    
    return this.SAFE_ERROR_MESSAGES.default;
  }

  private static isSafeMessage(message: string): boolean {
    // Message is safe if it doesn't contain sensitive patterns
    return !this.SENSITIVE_PATTERNS.some(pattern => pattern.test(message)) &&
           message.length < 200 &&
           !message.includes('node_modules') &&
           !message.includes('stack trace') &&
           !message.includes('internal error');
  }

  private static sanitizeMessage(message: string): string {
    let sanitized = message;
    
    // Remove sensitive patterns
    this.SENSITIVE_PATTERNS.forEach(pattern => {
      sanitized = sanitized.replace(pattern, '[REDACTED]');
    });
    
    // Truncate if too long
    if (sanitized.length > 150) {
      sanitized = sanitized.substring(0, 150) + '...';
    }
    
    return sanitized;
  }

  private static generateErrorCode(errorType: string, message: string): string {
    const typeCode = errorType.replace('Error', '').toUpperCase();
    const hash = crypto.createHash('md5').update(message).digest('hex').substring(0, 8);
    return `${typeCode}_${hash}`;
  }

  private static generateCorrelationId(): string {
    return `err_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
  }

  private static logErrorForAudit(error: Error, context: RequestContext, correlationId: string): void {
    // Sanitize context for logging
    const sanitizedContext = this.sanitizeContext(context);
    
    logger.error('Error occurred', {
      correlationId,
      errorType: error.constructor.name,
      message: this.sanitizeMessage(error.message),
      stack: error.stack ? this.sanitizeStackTrace(error.stack) : undefined,
      context: sanitizedContext,
      timestamp: new Date().toISOString()
    });
  }

  private static sanitizeStackTrace(stack: string): string {
    // Remove sensitive file paths and keep only relevant stack information
    return stack
      .split('\n')
      .slice(0, 10) // Limit stack trace length
      .map(line => {
        // Remove absolute paths, keep only relative paths and function names
        return line.replace(/\/[^\/\s]*\/[^\/\s]*\/[^\/\s]*/g, '[PATH]');
      })
      .join('\n');
  }

  private static sanitizeContext(context: RequestContext): Partial<RequestContext> {
    return {
      endpoint: context.endpoint?.substring(0, 100),
      method: context.method,
      userId: context.userId ? `user_${crypto.createHash('md5').update(context.userId).digest('hex').substring(0, 8)}` : undefined,
      ip: context.ip ? this.obfuscateIP(context.ip) : 'unknown',
      userAgent: context.userAgent?.substring(0, 100),
      sessionId: context.sessionId ? `session_${crypto.createHash('md5').update(context.sessionId).digest('hex').substring(0, 8)}` : undefined
    };
  }

  private static obfuscateIP(ip: string): string {
    // Obfuscate last octet of IPv4 or last groups of IPv6
    if (ip.includes('.')) {
      const parts = ip.split('.');
      if (parts.length === 4) {
        return `${parts[0]}.${parts[1]}.${parts[2]}.xxx`;
      }
    }
    return ip.substring(0, ip.length - 4) + 'xxxx';
  }

  static sanitizeHeaders(headers: Record<string, any>): Record<string, any> {
    const sanitized: Record<string, any> = {};
    const sensitiveHeaders = [
      'authorization',
      'cookie',
      'x-api-key',
      'x-auth-token',
      'x-csrf-token',
      'x-session-id'
    ];
    
    for (const [key, value] of Object.entries(headers)) {
      if (sensitiveHeaders.includes(key.toLowerCase())) {
        sanitized[key] = '[REDACTED]';
      } else {
        sanitized[key] = typeof value === 'string' ? value.substring(0, 200) : value;
      }
    }
    
    return sanitized;
  }
}

// Log injection prevention utility
export class LogSanitizer {
  private static readonly DANGEROUS_PATTERNS = [
    /\r\n|\r|\n/g, // CRLF injection
    /\x1b\[[0-9;]*m/g, // ANSI escape sequences
    /[\x00-\x1f\x7f]/g, // Control characters
    /<script[^>]*>.*?<\/script>/gi, // Script tags
    /javascript:/gi, // JavaScript protocol
    /data:.*base64/gi, // Data URIs
    /%[0-9a-f]{2}/gi, // URL encoded characters that could be malicious
    /\\["'`]/g // Escaped quotes that could break log parsing
  ];
  
  static sanitizeForLogging(input: string): string {
    let sanitized = String(input);
    
    // Remove dangerous patterns
    this.DANGEROUS_PATTERNS.forEach(pattern => {
      sanitized = sanitized.replace(pattern, '[FILTERED]');
    });
    
    // Truncate long inputs
    if (sanitized.length > 1000) {
      sanitized = sanitized.substring(0, 1000) + '[TRUNCATED]';
    }
    
    return sanitized;
  }
  
  static sanitizeObject(obj: any, maxDepth: number = 3): any {
    if (maxDepth <= 0) {
      return '[MAX_DEPTH_REACHED]';
    }
    
    if (typeof obj === 'string') {
      return this.sanitizeForLogging(obj);
    }
    
    if (typeof obj !== 'object' || obj === null) {
      return obj;
    }
    
    if (Array.isArray(obj)) {
      return obj.slice(0, 100).map(item => this.sanitizeObject(item, maxDepth - 1));
    }
    
    const sanitized: Record<string, any> = {};
    const entries = Object.entries(obj).slice(0, 50); // Limit object size
    
    for (const [key, value] of entries) {
      const sanitizedKey = this.sanitizeForLogging(key);
      sanitized[sanitizedKey] = this.sanitizeObject(value, maxDepth - 1);
    }
    
    return sanitized;
  }
}

// Secure error handling middleware
export function errorSanitizationMiddleware() {
  return (error: Error, req: any, res: any, next: any): void => {
    const context: RequestContext = {
      correlationId: req.headers['x-correlation-id'] || req.correlationId,
      endpoint: req.path || req.url,
      method: req.method,
      userId: req.user?.id,
      ip: req.ip || req.connection?.remoteAddress || 'unknown',
      userAgent: req.headers['user-agent'],
      sessionId: req.sessionID
    };
    
    const sanitizedError = ErrorSanitizer.sanitizeError(error, context);
    
    // Determine appropriate HTTP status code
    let statusCode = 500;
    if (error instanceof ValidationError) statusCode = 400;
    if (error instanceof AuthenticationError) statusCode = 401;
    if (error instanceof AuthorizationError) statusCode = 403;
    if (error instanceof RateLimitError) statusCode = 429;
    if (error.message.includes('not found')) statusCode = 404;
    if (error.message.includes('conflict')) statusCode = 409;
    
    // Add security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    
    res.status(statusCode).json(sanitizedError);
  };
}

// Utility for safe error creation with automatic sanitization
export function createSafeError(
  message: string,
  type: 'validation' | 'authentication' | 'authorization' | 'rateLimit' | 'external' | 'internal' = 'internal',
  details?: any
): Error {
  const sanitizedMessage = LogSanitizer.sanitizeForLogging(message);
  const sanitizedDetails = details ? LogSanitizer.sanitizeObject(details) : undefined;
  
  switch (type) {
    case 'validation':
      return new ValidationError(sanitizedMessage, sanitizedDetails);
    case 'authentication':
      return new AuthenticationError(sanitizedMessage, sanitizedDetails);
    case 'authorization':
      return new AuthorizationError(sanitizedMessage, sanitizedDetails);
    case 'rateLimit':
      return new RateLimitError(sanitizedMessage, sanitizedDetails);
    case 'external':
      return new ExternalApiError(sanitizedMessage, sanitizedDetails);
    default:
      return new Error(sanitizedMessage);
  }
}

// Development mode error handler with enhanced security
export function developmentErrorHandler() {
  return (error: Error, req: any, res: any, next: any): void => {
    const isDevelopment = process.env.NODE_ENV === 'development';
    
    const context: RequestContext = {
      correlationId: req.headers['x-correlation-id'] || req.correlationId,
      endpoint: req.path || req.url,
      method: req.method,
      userId: req.user?.id,
      ip: req.ip || req.connection?.remoteAddress || 'unknown',
      userAgent: req.headers['user-agent'],
      sessionId: req.sessionID
    };
    
    // Always sanitize for production
    const sanitizedError = ErrorSanitizer.sanitizeError(error, context);
    
    // In development, add additional debug info but still sanitized
    if (isDevelopment) {
      const debugInfo = {
        ...sanitizedError,
        debug: {
          errorType: error.constructor.name,
          sanitizedStack: error.stack ? LogSanitizer.sanitizeForLogging(error.stack) : undefined,
          context: LogSanitizer.sanitizeObject(context),
          timestamp: new Date().toISOString()
        }
      };
      
      res.status(500).json(debugInfo);
    } else {
      res.status(500).json(sanitizedError);
    }
  };
}