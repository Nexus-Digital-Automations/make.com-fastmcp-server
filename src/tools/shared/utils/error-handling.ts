/**
 * @fileoverview Error handling utilities for FastMCP tools
 * Standardized error handling patterns and utilities
 */

import { UserError } from 'fastmcp';
import { ApiError, OperationResult } from '../types/api-client.js';

/**
 * Standard error categories
 */
export enum ErrorCategory {
  VALIDATION = 'validation',
  AUTHENTICATION = 'authentication',
  AUTHORIZATION = 'authorization',
  NOT_FOUND = 'not_found',
  CONFLICT = 'conflict',
  RATE_LIMIT = 'rate_limit',
  INTERNAL = 'internal',
  NETWORK = 'network',
  TIMEOUT = 'timeout',
  QUOTA_EXCEEDED = 'quota_exceeded',
  INTEGRATION = 'integration',
}

/**
 * Standard error codes
 */
export enum ErrorCode {
  // Validation errors
  INVALID_INPUT = 'invalid_input',
  MISSING_REQUIRED_FIELD = 'missing_required_field',
  INVALID_FORMAT = 'invalid_format',
  VALUE_OUT_OF_RANGE = 'value_out_of_range',

  // Authentication errors
  INVALID_TOKEN = 'invalid_token',
  TOKEN_EXPIRED = 'token_expired',
  UNAUTHORIZED = 'unauthorized',
  FORBIDDEN = 'forbidden',

  // Resource errors
  RESOURCE_NOT_FOUND = 'resource_not_found',
  RESOURCE_ALREADY_EXISTS = 'resource_already_exists',
  RESOURCE_LOCKED = 'resource_locked',
  RESOURCE_DELETED = 'resource_deleted',

  // Rate limiting
  RATE_LIMIT_EXCEEDED = 'rate_limit_exceeded',
  QUOTA_EXCEEDED = 'quota_exceeded',

  // Network errors
  NETWORK_ERROR = 'network_error',
  TIMEOUT = 'timeout',
  SERVICE_UNAVAILABLE = 'service_unavailable',

  // Internal errors
  INTERNAL_ERROR = 'internal_error',
  DATABASE_ERROR = 'database_error',
  CONFIGURATION_ERROR = 'configuration_error',
}

/**
 * Structured error information
 */
export interface ErrorInfo {
  category: ErrorCategory;
  code: ErrorCode;
  message: string;
  field?: string;
  details?: Record<string, any>;
  context?: Record<string, any>;
  timestamp?: Date;
  requestId?: string;
}

/**
 * Extended UserError with additional context
 */
export class FastMCPError extends UserError {
  public readonly category: ErrorCategory;
  public readonly code: ErrorCode;
  public readonly field?: string;
  public readonly details?: Record<string, any>;
  public readonly context?: Record<string, any>;
  public readonly timestamp: Date;
  public readonly requestId?: string;

  constructor(info: ErrorInfo, cause?: Error) {
    super(info.message, { cause });
    this.category = info.category;
    this.code = info.code;
    this.field = info.field;
    this.details = info.details;
    this.context = info.context;
    this.timestamp = info.timestamp || new Date();
    this.requestId = info.requestId;
    this.name = 'FastMCPError';
  }

  /**
   * Convert to API error format
   */
  toApiError(): ApiError {
    return {
      code: this.code,
      message: this.message,
      field: this.field,
      details: {
        category: this.category,
        timestamp: this.timestamp.toISOString(),
        requestId: this.requestId,
        ...this.details,
      },
    };
  }

  /**
   * Convert to operation result format
   */
  toOperationResult<T = any>(): OperationResult<T> {
    return {
      success: false,
      error: this.message,
      errors: [this.toApiError()],
    };
  }
}

/**
 * Create validation error
 */
export function createValidationError(
  message: string,
  field?: string,
  details?: Record<string, any>
): FastMCPError {
  return new FastMCPError({
    category: ErrorCategory.VALIDATION,
    code: ErrorCode.INVALID_INPUT,
    message,
    field,
    details,
  });
}

/**
 * Create not found error
 */
export function createNotFoundError(
  resource: string,
  identifier?: string | number,
  details?: Record<string, any>
): FastMCPError {
  const message = identifier 
    ? `${resource} with identifier '${identifier}' not found`
    : `${resource} not found`;

  return new FastMCPError({
    category: ErrorCategory.NOT_FOUND,
    code: ErrorCode.RESOURCE_NOT_FOUND,
    message,
    details: {
      resource,
      identifier,
      ...details,
    },
  });
}

/**
 * Create authentication error
 */
export function createAuthenticationError(
  message: string = 'Authentication failed',
  details?: Record<string, any>
): FastMCPError {
  return new FastMCPError({
    category: ErrorCategory.AUTHENTICATION,
    code: ErrorCode.UNAUTHORIZED,
    message,
    details,
  });
}

/**
 * Create authorization error
 */
export function createAuthorizationError(
  message: string = 'Access forbidden',
  resource?: string,
  action?: string,
  details?: Record<string, any>
): FastMCPError {
  return new FastMCPError({
    category: ErrorCategory.AUTHORIZATION,
    code: ErrorCode.FORBIDDEN,
    message,
    details: {
      resource,
      action,
      ...details,
    },
  });
}

/**
 * Create rate limit error
 */
export function createRateLimitError(
  resetTime?: number,
  details?: Record<string, any>
): FastMCPError {
  const message = resetTime
    ? `Rate limit exceeded. Try again after ${new Date(resetTime * 1000).toISOString()}`
    : 'Rate limit exceeded. Please try again later';

  return new FastMCPError({
    category: ErrorCategory.RATE_LIMIT,
    code: ErrorCode.RATE_LIMIT_EXCEEDED,
    message,
    details: {
      resetTime,
      ...details,
    },
  });
}

/**
 * Create network error
 */
export function createNetworkError(
  message: string = 'Network error occurred',
  originalError?: Error,
  details?: Record<string, any>
): FastMCPError {
  return new FastMCPError({
    category: ErrorCategory.NETWORK,
    code: ErrorCode.NETWORK_ERROR,
    message,
    details: {
      originalError: originalError?.message,
      ...details,
    },
  }, originalError);
}

/**
 * Create timeout error
 */
export function createTimeoutError(
  operation: string,
  timeout: number,
  details?: Record<string, any>
): FastMCPError {
  return new FastMCPError({
    category: ErrorCategory.TIMEOUT,
    code: ErrorCode.TIMEOUT,
    message: `Operation '${operation}' timed out after ${timeout}ms`,
    details: {
      operation,
      timeout,
      ...details,
    },
  });
}

/**
 * Create internal error
 */
export function createInternalError(
  message: string = 'Internal server error',
  originalError?: Error,
  details?: Record<string, any>
): FastMCPError {
  return new FastMCPError({
    category: ErrorCategory.INTERNAL,
    code: ErrorCode.INTERNAL_ERROR,
    message,
    details: {
      originalError: originalError?.message,
      stack: originalError?.stack,
      ...details,
    },
  }, originalError);
}

/**
 * Handle and convert common error types to FastMCPError
 */
export function handleError(
  error: unknown,
  context?: Record<string, any>
): FastMCPError {
  // Already a FastMCPError
  if (error instanceof FastMCPError) {
    return error;
  }

  // Already a UserError
  if (error instanceof UserError) {
    return new FastMCPError({
      category: ErrorCategory.INTERNAL,
      code: ErrorCode.INTERNAL_ERROR,
      message: error.message,
      context,
    }, error);
  }

  // Standard Error
  if (error instanceof Error) {
    // Check for specific error types based on message patterns
    if (error.message.includes('timeout')) {
      return new FastMCPError({
        category: ErrorCategory.TIMEOUT,
        code: ErrorCode.TIMEOUT,
        message: error.message,
        context,
      }, error);
    }

    if (error.message.includes('network') || error.message.includes('fetch')) {
      return new FastMCPError({
        category: ErrorCategory.NETWORK,
        code: ErrorCode.NETWORK_ERROR,
        message: error.message,
        context,
      }, error);
    }

    if (error.message.includes('unauthorized') || error.message.includes('401')) {
      return new FastMCPError({
        category: ErrorCategory.AUTHENTICATION,
        code: ErrorCode.UNAUTHORIZED,
        message: error.message,
        context,
      }, error);
    }

    if (error.message.includes('forbidden') || error.message.includes('403')) {
      return new FastMCPError({
        category: ErrorCategory.AUTHORIZATION,
        code: ErrorCode.FORBIDDEN,
        message: error.message,
        context,
      }, error);
    }

    if (error.message.includes('not found') || error.message.includes('404')) {
      return new FastMCPError({
        category: ErrorCategory.NOT_FOUND,
        code: ErrorCode.RESOURCE_NOT_FOUND,
        message: error.message,
        context,
      }, error);
    }

    // Generic error
    return new FastMCPError({
      category: ErrorCategory.INTERNAL,
      code: ErrorCode.INTERNAL_ERROR,
      message: error.message,
      context,
    }, error);
  }

  // Unknown error type
  return new FastMCPError({
    category: ErrorCategory.INTERNAL,
    code: ErrorCode.INTERNAL_ERROR,
    message: String(error) || 'Unknown error occurred',
    context,
  });
}

/**
 * Execute operation with error handling
 */
export async function executeWithErrorHandling<T>(
  operation: () => Promise<T>,
  context?: Record<string, any>
): Promise<OperationResult<T>> {
  try {
    const data = await operation();
    return {
      success: true,
      data,
    };
  } catch (error) {
    const handledError = handleError(error, context);
    return handledError.toOperationResult<T>();
  }
}

/**
 * Execute operation and throw FastMCPError on failure
 */
export async function executeOrThrow<T>(
  operation: () => Promise<T>,
  context?: Record<string, any>
): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    throw handleError(error, context);
  }
}

/**
 * Retry operation with exponential backoff
 */
export async function retryOperation<T>(
  operation: () => Promise<T>,
  options: {
    maxRetries?: number;
    baseDelay?: number;
    maxDelay?: number;
    backoffFactor?: number;
    retryCondition?: (error: Error) => boolean;
  } = {}
): Promise<T> {
  const {
    maxRetries = 3,
    baseDelay = 1000,
    maxDelay = 10000,
    backoffFactor = 2,
    retryCondition = (error) => 
      error.message.includes('network') || 
      error.message.includes('timeout') ||
      error.message.includes('503') ||
      error.message.includes('502'),
  } = options;

  let lastError: Error;
  
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      
      if (attempt === maxRetries || !retryCondition(lastError)) {
        break;
      }

      const delay = Math.min(baseDelay * Math.pow(backoffFactor, attempt), maxDelay);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  throw handleError(lastError!, {
    maxRetries,
    attempts: maxRetries + 1,
  });
}

/**
 * Log error with structured information
 */
export function logError(
  error: FastMCPError,
  logger: any,
  additionalContext?: Record<string, any>
): void {
  const errorInfo = {
    category: error.category,
    code: error.code,
    message: error.message,
    field: error.field,
    timestamp: error.timestamp,
    requestId: error.requestId,
    details: error.details,
    context: error.context,
    ...additionalContext,
  };

  switch (error.category) {
    case ErrorCategory.VALIDATION:
    case ErrorCategory.NOT_FOUND:
      logger.warn?.('Tool error occurred', errorInfo);
      break;
    
    case ErrorCategory.AUTHENTICATION:
    case ErrorCategory.AUTHORIZATION:
      logger.warn?.('Access error occurred', errorInfo);
      break;
    
    case ErrorCategory.RATE_LIMIT:
    case ErrorCategory.QUOTA_EXCEEDED:
      logger.info?.('Rate limit error occurred', errorInfo);
      break;
    
    default:
      logger.error?.('Unexpected error occurred', errorInfo);
      break;
  }
}