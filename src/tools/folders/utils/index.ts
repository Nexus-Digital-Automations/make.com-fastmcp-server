/**
 * Utility functions for folders module
 * Generated on 2025-08-22T09:20:06.378Z
 */

import type { FoldersResult } from '../types/index.js';

/**
 * Create a standardized success result
 */
export function createSuccessResult(data?: unknown, message?: string): FoldersResult {
  return {
    success: true,
    data,
    message: message || 'Operation completed successfully',
    metadata: {
      operationId: generateOperationId('folders'),
      timestamp: new Date()
    }
  };
}

/**
 * Create a standardized error result
 */
export function createErrorResult(error: string | Error, data?: unknown): FoldersResult {
  const errorMessage = error instanceof Error ? error.message : error;
  
  return {
    success: false,
    data,
    message: 'Operation failed',
    errors: [errorMessage],
    metadata: {
      operationId: generateOperationId('folders'),
      timestamp: new Date()
    }
  };
}

/**
 * Generate unique operation ID
 */
export function generateOperationId(prefix = 'folders'): string {
  return `${prefix}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * Safe JSON parsing with error handling
 */
export function safeJsonParse<T = unknown>(json: string, defaultValue?: T): T | undefined {
  try {
    return JSON.parse(json) as T;
  } catch (error) {
    return defaultValue;
  }
}

/**
 * Deep clone object safely
 */
export function deepClone<T>(obj: T): T {
  if (obj === null || typeof obj !== 'object') {
    return obj;
  }

  if (obj instanceof Date) {
    return new Date(obj.getTime()) as T;
  }

  if (obj instanceof Array) {
    return obj.map(item => deepClone(item)) as T;
  }

  if (typeof obj === 'object') {
    const cloned = {} as T;
    Object.keys(obj).forEach(key => {
      (cloned as any)[key] = deepClone((obj as any)[key]);
    });
    return cloned;
  }

  return obj;
}

/**
 * Retry async operation with exponential backoff
 */
export async function retryOperation<T>(
  operation: () => Promise<T>,
  options: {
    maxRetries?: number;
    baseDelay?: number;
    maxDelay?: number;
    backoffMultiplier?: number;
  } = {}
): Promise<T> {
  const {
    maxRetries = 3,
    baseDelay = 1000,
    maxDelay = 10000,
    backoffMultiplier = 2
  } = options;

  let lastError: Error;
  
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      
      if (attempt === maxRetries) {
        throw lastError;
      }

      const delay = Math.min(baseDelay * Math.pow(backoffMultiplier, attempt), maxDelay);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  throw lastError!;
}

/**
 * Validate required environment variables
 */
export function validateEnvironmentVariables(requiredVars: string[]): void {
  const missing = requiredVars.filter(varName => !process.env[varName]);
  
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
}

/**
 * Sanitize sensitive data for logging
 */
export function sanitizeForLogging(data: unknown): unknown {
  if (typeof data !== 'object' || data === null) {
    return data;
  }

  const sensitiveKeys = ['password', 'token', 'key', 'secret', 'auth', 'credential'];
  const sanitized = deepClone(data);

  function sanitizeObject(obj: any): void {
    if (typeof obj !== 'object' || obj === null) return;

    Object.keys(obj).forEach(key => {
      const lowerKey = key.toLowerCase();
      
      if (sensitiveKeys.some(sensitive => lowerKey.includes(sensitive))) {
        obj[key] = '[REDACTED]';
      } else if (typeof obj[key] === 'object') {
        sanitizeObject(obj[key]);
      }
    });
  }

  sanitizeObject(sanitized);
  return sanitized;
}
