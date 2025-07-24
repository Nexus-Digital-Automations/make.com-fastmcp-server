/**
 * Custom error classes for Make.com FastMCP Server
 * Provides structured error handling with proper error types
 */

export class MakeServerError extends Error {
  public readonly code: string;
  public readonly statusCode: number;
  public readonly isOperational: boolean;
  public readonly details?: any;

  constructor(
    message: string,
    code: string = 'INTERNAL_ERROR',
    statusCode: number = 500,
    isOperational: boolean = true,
    details?: any
  ) {
    super(message);
    this.name = 'MakeServerError';
    this.code = code;
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.details = details;
    
    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, MakeServerError.prototype);
    
    // Capture stack trace
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, MakeServerError);
    }
  }
}

export class ValidationError extends MakeServerError {
  constructor(message: string, details?: any) {
    super(message, 'VALIDATION_ERROR', 400, true, details);
    this.name = 'ValidationError';
    Object.setPrototypeOf(this, ValidationError.prototype);
  }
}

export class AuthenticationError extends MakeServerError {
  constructor(message: string = 'Authentication failed', details?: any) {
    super(message, 'AUTHENTICATION_ERROR', 401, true, details);
    this.name = 'AuthenticationError';
    Object.setPrototypeOf(this, AuthenticationError.prototype);
  }
}

export class AuthorizationError extends MakeServerError {
  constructor(message: string = 'Insufficient permissions', details?: any) {
    super(message, 'AUTHORIZATION_ERROR', 403, true, details);
    this.name = 'AuthorizationError';
    Object.setPrototypeOf(this, AuthorizationError.prototype);
  }
}

export class NotFoundError extends MakeServerError {
  constructor(resource: string = 'Resource', details?: any) {
    super(`${resource} not found`, 'NOT_FOUND', 404, true, details);
    this.name = 'NotFoundError';
    Object.setPrototypeOf(this, NotFoundError.prototype);
  }
}

export class ConflictError extends MakeServerError {
  constructor(message: string, details?: any) {
    super(message, 'CONFLICT', 409, true, details);
    this.name = 'ConflictError';
    Object.setPrototypeOf(this, ConflictError.prototype);
  }
}

export class RateLimitError extends MakeServerError {
  public readonly retryAfter?: number;

  constructor(message: string = 'Rate limit exceeded', retryAfter?: number, details?: any) {
    super(message, 'RATE_LIMIT', 429, true, details);
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
    Object.setPrototypeOf(this, RateLimitError.prototype);
  }
}

export class ExternalServiceError extends MakeServerError {
  public readonly service: string;
  public readonly originalError?: any;

  constructor(service: string, message: string, originalError?: any, details?: any) {
    super(`${service} error: ${message}`, 'EXTERNAL_SERVICE_ERROR', 502, true, details);
    this.name = 'ExternalServiceError';
    this.service = service;
    this.originalError = originalError;
    Object.setPrototypeOf(this, ExternalServiceError.prototype);
  }
}

export class ConfigurationError extends MakeServerError {
  constructor(message: string, details?: any) {
    super(message, 'CONFIGURATION_ERROR', 500, false, details);
    this.name = 'ConfigurationError';
    Object.setPrototypeOf(this, ConfigurationError.prototype);
  }
}

export class TimeoutError extends MakeServerError {
  public readonly operation: string;
  public readonly timeoutMs: number;

  constructor(operation: string, timeoutMs: number, details?: any) {
    super(`Operation '${operation}' timed out after ${timeoutMs}ms`, 'TIMEOUT', 408, true, details);
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
  details?: any;
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
export function createValidationError(field: string, value: any, expected: string): ValidationError {
  return new ValidationError(`Invalid ${field}: expected ${expected}, got ${typeof value}`, {
    field,
    value,
    expected,
  });
}

export function createNotFoundError(resource: string, id: string | number): NotFoundError {
  return new NotFoundError(`${resource} with ID ${id}`, { resource, id });
}

export function createConflictError(resource: string, field: string, value: any): ConflictError {
  return new ConflictError(`${resource} with ${field} '${value}' already exists`, {
    resource,
    field,
    value,
  });
}

export function createExternalServiceError(service: string, operation: string, originalError: any): ExternalServiceError {
  return new ExternalServiceError(
    service,
    `Failed to ${operation}`,
    originalError,
    { operation, originalMessage: originalError?.message }
  );
}

// Error handler for unhandled promise rejections and uncaught exceptions
export function setupGlobalErrorHandlers(): void {
  process.on('unhandledRejection', (reason: any, promise: Promise<any>) => {
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