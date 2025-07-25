/**
 * Enhanced error handling system for Make.com FastMCP Server
 * Provides structured error handling with correlation IDs, context tracking, and recovery mechanisms
 */

import { randomUUID } from 'crypto';

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

// Enhanced base error class with correlation IDs and context
export class MakeServerError extends Error {
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

export class ValidationError extends MakeServerError {
  constructor(message: string, details?: Record<string, unknown>, context?: ErrorContext) {
    super(message, 'VALIDATION_ERROR', 400, true, details, context);
    this.name = 'ValidationError';
    Object.setPrototypeOf(this, ValidationError.prototype);
  }
}

export class AuthenticationError extends MakeServerError {
  constructor(message: string = 'Authentication failed', details?: Record<string, unknown>, context?: ErrorContext) {
    super(message, 'AUTHENTICATION_ERROR', 401, true, details, context);
    this.name = 'AuthenticationError';
    Object.setPrototypeOf(this, AuthenticationError.prototype);
  }
}

export class AuthorizationError extends MakeServerError {
  constructor(message: string = 'Insufficient permissions', details?: Record<string, unknown>, context?: ErrorContext) {
    super(message, 'AUTHORIZATION_ERROR', 403, true, details, context);
    this.name = 'AuthorizationError';
    Object.setPrototypeOf(this, AuthorizationError.prototype);
  }
}

export class NotFoundError extends MakeServerError {
  constructor(resource: string = 'Resource', details?: Record<string, unknown>, context?: ErrorContext) {
    super(`${resource} not found`, 'NOT_FOUND', 404, true, details, context);
    this.name = 'NotFoundError';
    Object.setPrototypeOf(this, NotFoundError.prototype);
  }
}

export class ConflictError extends MakeServerError {
  constructor(message: string, details?: Record<string, unknown>, context?: ErrorContext) {
    super(message, 'CONFLICT', 409, true, details, context);
    this.name = 'ConflictError';
    Object.setPrototypeOf(this, ConflictError.prototype);
  }
}

export class RateLimitError extends MakeServerError {
  public readonly retryAfter?: number;

  constructor(message: string = 'Rate limit exceeded', retryAfter?: number, details?: Record<string, unknown>, context?: ErrorContext) {
    super(message, 'RATE_LIMIT', 429, true, details, context);
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
    Object.setPrototypeOf(this, RateLimitError.prototype);
  }
}

export class ExternalServiceError extends MakeServerError {
  public readonly service: string;
  public readonly originalError?: Error;

  constructor(service: string, message: string, originalError?: Error, details?: Record<string, unknown>, context?: ErrorContext) {
    super(`${service} error: ${message}`, 'EXTERNAL_SERVICE_ERROR', 502, true, details, context);
    this.name = 'ExternalServiceError';
    this.service = service;
    this.originalError = originalError;
    Object.setPrototypeOf(this, ExternalServiceError.prototype);
  }
}

export class ConfigurationError extends MakeServerError {
  constructor(message: string, details?: Record<string, unknown>, context?: ErrorContext) {
    super(message, 'CONFIGURATION_ERROR', 500, false, details, context);
    this.name = 'ConfigurationError';
    Object.setPrototypeOf(this, ConfigurationError.prototype);
  }
}

export class TimeoutError extends MakeServerError {
  public readonly operation: string;
  public readonly timeoutMs: number;

  constructor(operation: string, timeoutMs: number, details?: Record<string, unknown>, context?: ErrorContext) {
    super(`Operation '${operation}' timed out after ${timeoutMs}ms`, 'TIMEOUT', 408, true, details, context);
    this.name = 'TimeoutError';
    this.operation = operation;
    this.timeoutMs = timeoutMs;
    Object.setPrototypeOf(this, TimeoutError.prototype);
  }
}

// Error handling utilities
export function isOperationalError(error: Error): boolean {
  if (error instanceof MakeServerError) {
    return error.isOperational;
  }
  return false;
}

export function getErrorStatusCode(error: Error): number {
  if (error instanceof MakeServerError) {
    return error.statusCode;
  }
  return 500;
}

export function getErrorCode(error: Error): string {
  if (error instanceof MakeServerError) {
    return error.code;
  }
  return 'UNKNOWN_ERROR';
}

export function serializeError(error: Error): {
  name: string;
  message: string;
  code: string;
  statusCode: number;
  details?: Record<string, unknown>;
  stack?: string;
} {
  const serialized = {
    name: error.name,
    message: error.message,
    code: getErrorCode(error),
    statusCode: getErrorStatusCode(error),
    details: error instanceof MakeServerError ? error.details : undefined,
    stack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
  };

  return serialized;
}

// Error factory functions
export function createValidationError(field: string, value: unknown, expected: string): ValidationError {
  return new ValidationError(`Invalid ${field}: expected ${expected}, got ${typeof value}`, {
    field,
    value,
    expected,
  });
}

export function createNotFoundError(resource: string, id: string | number): NotFoundError {
  return new NotFoundError(`${resource} with ID ${id}`, { resource, id });
}

export function createConflictError(resource: string, field: string, value: unknown): ConflictError {
  return new ConflictError(`${resource} with ${field} '${value}' already exists`, {
    resource,
    field,
    value,
  });
}

export function createExternalServiceError(service: string, operation: string, originalError: Error): ExternalServiceError {
  return new ExternalServiceError(
    service,
    `Failed to ${operation}`,
    originalError,
    { operation, originalMessage: originalError?.message }
  );
}

// Error handler for unhandled promise rejections and uncaught exceptions
export function setupGlobalErrorHandlers(): void {
  process.on('unhandledRejection', (reason: unknown, promise: Promise<unknown>) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    // Log error but don't exit in production
    if (process.env.NODE_ENV !== 'production') {
      process.exit(1);
    }
  });

  process.on('uncaughtException', (error: Error) => {
    console.error('Uncaught Exception:', error);
    // Always exit on uncaught exception
    process.exit(1);
  });
}