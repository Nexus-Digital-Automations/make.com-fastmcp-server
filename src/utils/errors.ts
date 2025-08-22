/**
 * Enhanced error handling system for Make.com FastMCP Server
 * Provides structured error handling with correlation IDs, context tracking, and recovery mechanisms
 * Now standardized around FastMCP UserError for full protocol compliance
 */

import { randomUUID } from 'crypto';
import { UserError } from 'fastmcp';

// Error context interface for better error tracking
export interface ErrorContext {
  correlationId?: string;
  operation?: string;
  component?: string;
  userId?: string;
  sessionId?: string;
  requestId?: string;
  traceId?: string;
  userAgent?: string;
  ipAddress?: string;
  metadata?: Record<string, unknown>;
}

// Re-export FastMCP UserError as the primary error class
export { UserError } from 'fastmcp';

// Enhanced UserError wrapper with correlation IDs and context for Make.com server
export class MakeServerError extends UserError {
  public readonly code: string;
  public readonly statusCode: number;
  public readonly isOperational: boolean;
  public readonly details?: Record<string, unknown>;
  public readonly correlationId: string;
  public readonly timestamp: string;
  public readonly context: ErrorContext;

  constructor(
    message: string,
    code: string = 'INTERNAL_ERROR',
    statusCode: number = 500,
    isOperational: boolean = true,
    details?: Record<string, unknown>,
    context?: ErrorContext
  ) {
    super(message);
    this.name = 'MakeServerError';
    this.code = code;
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.details = details;
    this.correlationId = context?.correlationId || randomUUID();
    this.timestamp = new Date().toISOString();
    this.context = {
      correlationId: this.correlationId,
      ...context,
    };
    
    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, MakeServerError.prototype);
    
    // Capture stack trace
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, MakeServerError);
    }
  }

  // Get structured error information
  public toStructuredError(): {
    name: string;
    message: string;
    code: string;
    statusCode: number;
    correlationId: string;
    timestamp: string;
    context: ErrorContext;
    details?: Record<string, unknown>;
    stack?: string;
  } {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      statusCode: this.statusCode,
      correlationId: this.correlationId,
      timestamp: this.timestamp,
      context: this.context,
      details: this.details,
      stack: process.env.NODE_ENV === 'development' ? this.stack : undefined,
    };
  }

  // Create child error with inherited context
  public createChildError(
    message: string,
    code?: string,
    statusCode?: number,
    details?: Record<string, unknown>,
    additionalContext?: Partial<ErrorContext>
  ): MakeServerError {
    return new MakeServerError(
      message,
      code || this.code,
      statusCode || this.statusCode,
      this.isOperational,
      details,
      { ...this.context, ...additionalContext }
    );
  }
}

// Enhanced UserError interface with additional metadata
export interface EnhancedUserError extends UserError {
  code: string;
  statusCode: number;
  details?: Record<string, unknown>;
  correlationId: string;
  context: ErrorContext;
  timestamp: string;
  isOperational?: boolean;
  retryAfter?: number;
  service?: string;
  originalError?: Error;
  operation?: string;
  timeoutMs?: number;
}

// UserError factory functions to replace custom error classes
// These maintain the same interface but use UserError internally

export function createValidationError(message: string, details?: Record<string, unknown>, context?: ErrorContext): EnhancedUserError {
  const correlationId = context?.correlationId || randomUUID();
  const errorMessage = `[VALIDATION_ERROR:${correlationId}] ${message}`;
  const userError = new UserError(errorMessage) as EnhancedUserError;
  
  // Attach additional metadata
  userError.code = 'VALIDATION_ERROR';
  userError.statusCode = 400;
  userError.details = details;
  userError.correlationId = correlationId;
  userError.context = { correlationId, ...context };
  userError.timestamp = new Date().toISOString();
  userError.isOperational = true;
  
  return userError;
}

export function createAuthenticationError(message: string = 'Authentication failed', details?: Record<string, unknown>, context?: ErrorContext): EnhancedUserError {
  const correlationId = context?.correlationId || randomUUID();
  const errorMessage = `[AUTHENTICATION_ERROR:${correlationId}] ${message}`;
  const userError = new UserError(errorMessage) as EnhancedUserError;
  
  // Attach additional metadata
  userError.code = 'AUTHENTICATION_ERROR';
  userError.statusCode = 401;
  userError.details = details;
  userError.correlationId = correlationId;
  userError.context = { correlationId, ...context };
  userError.timestamp = new Date().toISOString();
  userError.isOperational = true;
  
  return userError;
}

export function createAuthorizationError(message: string = 'Insufficient permissions', details?: Record<string, unknown>, context?: ErrorContext): EnhancedUserError {
  const correlationId = context?.correlationId || randomUUID();
  const errorMessage = `[AUTHORIZATION_ERROR:${correlationId}] ${message}`;
  const userError = new UserError(errorMessage) as EnhancedUserError;
  
  // Attach additional metadata
  userError.code = 'AUTHORIZATION_ERROR';
  userError.statusCode = 403;
  userError.details = details;
  userError.correlationId = correlationId;
  userError.context = { correlationId, ...context };
  userError.timestamp = new Date().toISOString();
  userError.isOperational = true;
  
  return userError;
}

export function createNotFoundError(resource: string = 'Resource', details?: Record<string, unknown>, context?: ErrorContext): EnhancedUserError {
  const correlationId = context?.correlationId || randomUUID();
  const errorMessage = `[NOT_FOUND:${correlationId}] ${resource} not found`;
  const userError = new UserError(errorMessage) as EnhancedUserError;
  
  // Attach additional metadata
  userError.code = 'NOT_FOUND';
  userError.statusCode = 404;
  userError.details = details;
  userError.correlationId = correlationId;
  userError.context = { correlationId, ...context };
  userError.timestamp = new Date().toISOString();
  userError.isOperational = true;
  
  return userError;
}

export function createConflictError(message: string, details?: Record<string, unknown>, context?: ErrorContext): EnhancedUserError {
  const correlationId = context?.correlationId || randomUUID();
  const errorMessage = `[CONFLICT:${correlationId}] ${message}`;
  const userError = new UserError(errorMessage) as EnhancedUserError;
  
  // Attach additional metadata
  userError.code = 'CONFLICT';
  userError.statusCode = 409;
  userError.details = details;
  userError.correlationId = correlationId;
  userError.context = { correlationId, ...context };
  userError.timestamp = new Date().toISOString();
  userError.isOperational = true;
  
  return userError;
}

export function createRateLimitError(message: string = 'Rate limit exceeded', retryAfter?: number, details?: Record<string, unknown>, context?: ErrorContext): EnhancedUserError {
  const correlationId = context?.correlationId || randomUUID();
  const errorMessage = `[RATE_LIMIT:${correlationId}] ${message}`;
  const userError = new UserError(errorMessage) as EnhancedUserError;
  
  // Attach additional metadata
  userError.code = 'RATE_LIMIT';
  userError.statusCode = 429;
  userError.retryAfter = retryAfter;
  userError.details = details;
  userError.correlationId = correlationId;
  userError.context = { correlationId, ...context };
  userError.timestamp = new Date().toISOString();
  userError.isOperational = true;
  
  return userError;
}

export function createExternalServiceError(service: string, message: string, originalError?: Error, details?: Record<string, unknown>, context?: ErrorContext): EnhancedUserError {
  const correlationId = context?.correlationId || randomUUID();
  const errorMessage = `[EXTERNAL_SERVICE_ERROR:${correlationId}] ${service} error: ${message}`;
  const userError = new UserError(errorMessage) as EnhancedUserError;
  
  // Attach additional metadata
  userError.code = 'EXTERNAL_SERVICE_ERROR';
  userError.statusCode = 502;
  userError.service = service;
  userError.originalError = originalError;
  userError.details = details;
  userError.correlationId = correlationId;
  userError.context = { correlationId, ...context };
  userError.timestamp = new Date().toISOString();
  userError.isOperational = true;
  
  return userError;
}

export function createConfigurationError(message: string, details?: Record<string, unknown>, context?: ErrorContext): EnhancedUserError {
  const correlationId = context?.correlationId || randomUUID();
  const errorMessage = `[CONFIGURATION_ERROR:${correlationId}] ${message}`;
  const userError = new UserError(errorMessage) as EnhancedUserError;
  
  // Attach additional metadata
  userError.code = 'CONFIGURATION_ERROR';
  userError.statusCode = 500;
  userError.isOperational = false;
  userError.details = details;
  userError.correlationId = correlationId;
  userError.context = { correlationId, ...context };
  userError.timestamp = new Date().toISOString();
  
  return userError;
}

export function createTimeoutError(operation: string, timeoutMs: number, details?: Record<string, unknown>, context?: ErrorContext): EnhancedUserError {
  const correlationId = context?.correlationId || randomUUID();
  const errorMessage = `[TIMEOUT:${correlationId}] Operation '${operation}' timed out after ${timeoutMs}ms`;
  const userError = new UserError(errorMessage) as EnhancedUserError;
  
  // Attach additional metadata
  userError.code = 'TIMEOUT';
  userError.statusCode = 408;
  userError.operation = operation;
  userError.timeoutMs = timeoutMs;
  userError.details = details;
  userError.correlationId = correlationId;
  userError.context = { correlationId, ...context };
  userError.timestamp = new Date().toISOString();
  userError.isOperational = true;
  
  return userError;
}

// Legacy class exports (deprecated but maintained for backward compatibility)
export class ValidationError extends UserError {
  constructor(message: string, details?: Record<string, unknown>, context?: ErrorContext) {
    const userError = createValidationError(message, details, context);
    super(userError.message);
    Object.assign(this, userError);
    this.name = 'ValidationError';
  }
}

export class AuthenticationError extends UserError {
  constructor(message: string = 'Authentication failed', details?: Record<string, unknown>, context?: ErrorContext) {
    const userError = createAuthenticationError(message, details, context);
    super(userError.message);
    Object.assign(this, userError);
    this.name = 'AuthenticationError';
  }
}

export class AuthorizationError extends UserError {
  constructor(message: string = 'Insufficient permissions', details?: Record<string, unknown>, context?: ErrorContext) {
    const userError = createAuthorizationError(message, details, context);
    super(userError.message);
    Object.assign(this, userError);
    this.name = 'AuthorizationError';
  }
}

export class NotFoundError extends UserError {
  constructor(resource: string = 'Resource', details?: Record<string, unknown>, context?: ErrorContext) {
    const userError = createNotFoundError(resource, details, context);
    super(userError.message);
    Object.assign(this, userError);
    this.name = 'NotFoundError';
  }
}

export class ConflictError extends UserError {
  constructor(message: string, details?: Record<string, unknown>, context?: ErrorContext) {
    const userError = createConflictError(message, details, context);
    super(userError.message);
    Object.assign(this, userError);
    this.name = 'ConflictError';
  }
}

export class RateLimitError extends UserError {
  public readonly retryAfter?: number;

  constructor(message: string = 'Rate limit exceeded', retryAfter?: number, details?: Record<string, unknown>, context?: ErrorContext) {
    const userError = createRateLimitError(message, retryAfter, details, context);
    super(userError.message);
    Object.assign(this, userError);
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
  }
}

export class ExternalServiceError extends UserError {
  public readonly service: string;
  public readonly originalError?: Error;

  constructor(service: string, message: string, originalError?: Error, details?: Record<string, unknown>, context?: ErrorContext) {
    const userError = createExternalServiceError(service, message, originalError, details, context);
    super(userError.message);
    Object.assign(this, userError);
    this.name = 'ExternalServiceError';
    this.service = service;
    this.originalError = originalError;
  }
}

export class ConfigurationError extends UserError {
  constructor(message: string, details?: Record<string, unknown>, context?: ErrorContext) {
    const userError = createConfigurationError(message, details, context);
    super(userError.message);
    Object.assign(this, userError);
    this.name = 'ConfigurationError';
  }
}

export class TimeoutError extends UserError {
  public readonly operation: string;
  public readonly timeoutMs: number;

  constructor(operation: string, timeoutMs: number, details?: Record<string, unknown>, context?: ErrorContext) {
    const userError = createTimeoutError(operation, timeoutMs, details, context);
    super(userError.message);
    Object.assign(this, userError);
    this.name = 'TimeoutError';
    this.operation = operation;
    this.timeoutMs = timeoutMs;
  }
}

// Error handling utilities compatible with UserError
export function isOperationalError(error: Error): boolean {
  // Check for MakeServerError first
  if (error instanceof MakeServerError) {
    return error.isOperational;
  }
  
  // Check for UserError with metadata
  if (error instanceof UserError && 'isOperational' in error) {
    return (error as EnhancedUserError).isOperational || true;
  }
  
  // Default to operational for UserError (client-facing errors)
  if (error instanceof UserError) {
    return true;
  }
  
  return false;
}

export function getErrorStatusCode(error: Error): number {
  // Check for MakeServerError first
  if (error instanceof MakeServerError) {
    return error.statusCode;
  }
  
  // Check for UserError with metadata
  if (error instanceof UserError && 'statusCode' in error) {
    return (error as EnhancedUserError).statusCode;
  }
  
  // Default status code for UserError is 400 (bad request)
  if (error instanceof UserError) {
    return 400;
  }
  
  return 500;
}

export function getErrorCode(error: Error): string {
  // Check for MakeServerError first
  if (error instanceof MakeServerError) {
    return error.code;
  }
  
  // Check for UserError with metadata
  if (error instanceof UserError && 'code' in error) {
    return (error as EnhancedUserError).code;
  }
  
  // Extract code from UserError message if formatted with correlation ID
  if (error instanceof UserError) {
    const match = error.message.match(/^\[([^:]+):[^\]]+\]/);
    if (match) {
      return match[1];
    }
    return 'USER_ERROR';
  }
  
  return 'UNKNOWN_ERROR';
}

export function getErrorCorrelationId(error: Error): string | undefined {
  // Check for MakeServerError first
  if (error instanceof MakeServerError) {
    return error.correlationId;
  }
  
  // Check for UserError with metadata
  if (error instanceof UserError && 'correlationId' in error) {
    return (error as EnhancedUserError).correlationId;
  }
  
  // Extract correlation ID from UserError message if formatted
  if (error instanceof UserError) {
    const match = error.message.match(/^\[[^:]+:([^\]]+)\]/);
    if (match) {
      return match[1];
    }
  }
  
  return undefined;
}

export function serializeError(error: Error): {
  name: string;
  message: string;
  code: string;
  statusCode: number;
  correlationId?: string;
  details?: Record<string, unknown>;
  stack?: string;
} {
  const serialized = {
    name: error.name,
    message: error.message,
    code: getErrorCode(error),
    statusCode: getErrorStatusCode(error),
    correlationId: getErrorCorrelationId(error),
    details: 'details' in error ? (error as EnhancedUserError).details : undefined,
    stack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
  };

  return serialized;
}

// Enhanced error factory functions with UserError compliance
export function createValidationErrorForField(field: string, value: unknown, expected: string): EnhancedUserError {
  return createValidationError(`Invalid ${field}: expected ${expected}, got ${typeof value}`, {
    field,
    value,
    expected,
  });
}

export function createNotFoundErrorForResource(resource: string, id: string | number): EnhancedUserError {
  return createNotFoundError(`${resource} with ID ${id}`, { resource, id });
}

export function createConflictErrorForResource(resource: string, field: string, value: unknown): EnhancedUserError {
  return createConflictError(`${resource} with ${field} '${value}' already exists`, {
    resource,
    field,
    value,
  });
}

export function createExternalServiceErrorForOperation(service: string, operation: string, originalError: Error): EnhancedUserError {
  return createExternalServiceError(
    service,
    `Failed to ${operation}`,
    originalError,
    { operation, originalMessage: originalError?.message }
  );
}

// Error handler for unhandled promise rejections and uncaught exceptions
export function setupGlobalErrorHandlers(): void {
  process.on('unhandledRejection', (reason: unknown, promise: Promise<unknown>) => {
    // Use stderr to avoid interfering with MCP stdio protocol
    process.stderr.write(`Unhandled Rejection at: ${promise} reason: ${reason}\n`);
    // Log error but don't exit in production
    if (process.env.NODE_ENV !== 'production') {
      process.exit(1);
    }
  });

  process.on('uncaughtException', (error: Error) => {
    // Use stderr to avoid interfering with MCP stdio protocol
    process.stderr.write(`Uncaught Exception: ${error}\n`);
    // Always exit on uncaught exception
    process.exit(1);
  });
}