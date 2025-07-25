/**
 * Centralized error response formatting for Make.com FastMCP Server
 * Provides consistent error response structure with correlation tracking
 */

import { randomUUID } from 'crypto';
import { MakeServerError, ErrorContext } from './errors.js';
import logger from '../lib/logger.js';

export interface ErrorResponse {
  error: {
    message: string;
    code: string;
    statusCode: number;
    correlationId: string;
    timestamp: string;
    context?: ErrorContext;
    details?: Record<string, unknown>;
    stack?: string;
  };
  success: false;
}

export interface SuccessResponse<T = unknown> {
  data: T;
  success: true;
  correlationId?: string;
  timestamp: string;
}

export type ApiResponse<T = unknown> = SuccessResponse<T> | ErrorResponse;

/**
 * Format error into standardized response structure
 */
export function formatErrorResponse(
  error: Error | MakeServerError,
  correlationId?: string
): ErrorResponse {
  const componentLogger = logger.child({ 
    component: 'ErrorResponseFormatter',
    correlationId: correlationId || (error instanceof MakeServerError ? error.correlationId : undefined)
  });

  let formattedError: ErrorResponse['error'];

  if (error instanceof MakeServerError) {
    // Use structured error information from MakeServerError
    const structured = error.toStructuredError();
    formattedError = {
      message: structured.message,
      code: structured.code,
      statusCode: structured.statusCode,
      correlationId: structured.correlationId,
      timestamp: structured.timestamp,
      context: structured.context,
      details: structured.details,
      stack: structured.stack,
    };

    componentLogger.error('Formatted MakeServerError', {
      code: structured.code,
      statusCode: structured.statusCode,
      correlationId: structured.correlationId,
    });
  } else {
    // Handle generic Error objects
    const errorCorrelationId = correlationId || randomUUID();
    formattedError = {
      message: error.message || 'Internal server error',
      code: 'UNKNOWN_ERROR',
      statusCode: 500,
      correlationId: errorCorrelationId,
      timestamp: new Date().toISOString(),
      details: {
        name: error.name,
        originalMessage: error.message,
      },
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
    };

    componentLogger.error('Formatted generic Error', {
      code: 'UNKNOWN_ERROR',
      correlationId: errorCorrelationId,
      originalError: error.name,
    });
  }

  return {
    error: formattedError,
    success: false,
  };
}

/**
 * Format successful response with correlation tracking
 */
export function formatSuccessResponse<T>(
  data: T,
  correlationId?: string
): SuccessResponse<T> {
  return {
    data,
    success: true,
    correlationId,
    timestamp: new Date().toISOString(),
  };
}

/**
 * Express middleware for handling errors with correlation tracking
 */
export function errorHandlerMiddleware() {
  return (error: Error, req: Record<string, unknown>, res: Record<string, unknown>): void => {
    const correlationId = (req.correlationId as string) || (req.headers as Record<string, string>)?.['x-correlation-id'] || randomUUID();
    
    const componentLogger = logger.child({ 
      component: 'ErrorMiddleware',
      correlationId,
      operation: `${req.method as string} ${req.path as string}`,
    });

    const errorResponse = formatErrorResponse(error, correlationId);

    componentLogger.error('Request error handled', {
      method: req.method as string,
      path: req.path as string,
      statusCode: errorResponse.error.statusCode,
      errorCode: errorResponse.error.code,
    });

    (res as any).status(errorResponse.error.statusCode).json(errorResponse);
  };
}

/**
 * Correlation ID middleware for request tracking
 */
export function correlationMiddleware() {
  return (req: Record<string, unknown>, res: Record<string, unknown>, next: () => void): void => {
    const correlationId = (req.headers as Record<string, string>)?.['x-correlation-id'] || randomUUID();
    req.correlationId = correlationId;
    (res as any).set('X-Correlation-ID', correlationId);
    next();
  };
}

/**
 * Helper function to create error responses for tools
 */
export function createToolErrorResponse(
  error: Error | MakeServerError,
  operation: string,
  correlationId?: string
): string {
  const componentLogger = logger.child({ 
    component: 'ToolErrorHandler',
    operation,
    correlationId: correlationId || (error instanceof MakeServerError ? error.correlationId : undefined)
  });

  const errorResponse = formatErrorResponse(error, correlationId);

  componentLogger.error('Tool operation failed', {
    operation,
    errorCode: errorResponse.error.code,
    statusCode: errorResponse.error.statusCode,
  });

  return JSON.stringify(errorResponse, null, 2);
}

/**
 * Helper function to create success responses for tools
 */
export function createToolSuccessResponse<T>(
  data: T,
  operation: string,
  correlationId?: string
): string {
  const componentLogger = logger.child({ 
    component: 'ToolSuccessHandler',
    operation,
    correlationId,
  });

  const successResponse = formatSuccessResponse(data, correlationId);

  componentLogger.info('Tool operation succeeded', {
    operation,
    hasData: !!data,
  });

  return JSON.stringify(successResponse, null, 2);
}

/**
 * Utility to extract correlation ID from various sources
 */
export function extractCorrelationId(context: {
  headers?: Record<string, string>;
  correlationId?: string;
  session?: Record<string, unknown>;
}): string {
  return (
    context.correlationId ||
    context.headers?.['x-correlation-id'] ||
    (context.session?.correlationId as string) ||
    randomUUID()
  );
}