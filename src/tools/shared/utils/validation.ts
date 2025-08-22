/**
 * @fileoverview Common validation utilities for FastMCP tools
 * Standardized validation patterns and helpers
 */

import { z, ZodSchema, ZodError, ZodIssue } from 'zod';
import { UserError } from 'fastmcp';
import { ApiError } from '../types/api-client.js';

/**
 * Validation result interface
 */
export interface ValidationResult<T> {
  success: boolean;
  data?: T;
  errors?: ValidationError[];
}

/**
 * Custom validation error
 */
export interface ValidationError {
  field: string;
  message: string;
  code: string;
  value?: unknown;
}

/**
 * Validation options
 */
export interface ValidationOptions {
  allowUnknown?: boolean;
  stripUnknown?: boolean;
  errorMessage?: string;
  context?: string;
}

/**
 * Validate input data against a Zod schema
 * @param schema - Zod schema to validate against
 * @param data - Data to validate
 * @param options - Validation options
 * @returns Validation result
 */
export function validateInput<T>(
  schema: ZodSchema<T>,
  data: unknown,
  options: ValidationOptions = {}
): ValidationResult<T> {
  try {
    const validatedData = schema.parse(data);
    return {
      success: true,
      data: validatedData,
    };
  } catch (error) {
    if (error instanceof ZodError) {
      const validationErrors: ValidationError[] = error.issues.map((err: ZodIssue) => ({
        field: err.path.map(p => String(p)).join('.') || 'root',
        message: err.message,
        code: err.code,
        value: err.path.length > 0 ? getNestedValue(data, err.path.map(p => String(p))) : data,
      }));

      return {
        success: false,
        errors: validationErrors,
      };
    }

    return {
      success: false,
      errors: [{
        field: 'root',
        message: options.errorMessage || 'Validation failed',
        code: 'validation_error',
        value: data,
      }],
    };
  }
}

/**
 * Validate input and throw UserError on validation failure
 * @param schema - Zod schema to validate against
 * @param data - Data to validate
 * @param options - Validation options
 * @returns Validated data
 * @throws UserError on validation failure
 */
export function validateInputOrThrow<T>(
  schema: ZodSchema<T>,
  data: unknown,
  options: ValidationOptions = {}
): T {
  const result = validateInput(schema, data, options);
  
  if (!result.success) {
    const context = options.context ? `${options.context}: ` : '';
    const errorMessages = result.errors?.map(err => `${err.field}: ${err.message}`).join(', ') || 'Validation failed';
    throw new UserError(`${context}${errorMessages}`);
  }
  
  return result.data!;
}

/**
 * Sanitize string input
 * @param input - Input string to sanitize
 * @param options - Sanitization options
 * @returns Sanitized string
 */
export function sanitizeString(
  input: string,
  options: {
    trim?: boolean;
    lowercase?: boolean;
    maxLength?: number;
    allowEmpty?: boolean;
  } = {}
): string {
  let sanitized = input;

  if (options.trim !== false) {
    sanitized = sanitized.trim();
  }

  if (options.lowercase) {
    sanitized = sanitized.toLowerCase();
  }

  if (options.maxLength && sanitized.length > options.maxLength) {
    sanitized = sanitized.substring(0, options.maxLength);
  }

  if (!options.allowEmpty && sanitized.length === 0) {
    throw new UserError('String cannot be empty');
  }

  return sanitized;
}

/**
 * Validate and sanitize ID parameter
 * @param id - ID to validate
 * @param type - Type of ID for error messages
 * @returns Validated ID
 */
export function validateId(id: unknown, type: string = 'ID'): number {
  const idSchema = z.number().positive().int();
  
  try {
    return validateInputOrThrow(idSchema, id, {
      context: type,
      errorMessage: `${type} must be a positive integer`,
    });
  } catch {
    // Try to parse string numbers
    if (typeof id === 'string' && /^\d+$/.test(id)) {
      const parsed = parseInt(id, 10);
      if (parsed > 0) {
        return parsed;
      }
    }
    throw new UserError(`Invalid ${type}: must be a positive integer`);
  }
}

/**
 * Validate team ID parameter
 * @param teamId - Team ID to validate
 * @returns Validated team ID
 */
export function validateTeamId(teamId: unknown): number {
  return validateId(teamId, 'Team ID');
}

/**
 * Validate organization ID parameter
 * @param orgId - Organization ID to validate
 * @returns Validated organization ID
 */
export function validateOrganizationId(orgId: unknown): number {
  return validateId(orgId, 'Organization ID');
}

/**
 * Validate pagination parameters
 * @param params - Pagination parameters
 * @returns Validated pagination parameters
 */
export function validatePaginationParams(params: {
  limit?: unknown;
  offset?: unknown;
} = {}): { limit: number; offset: number } {
  const paginationSchema = z.object({
    limit: z.number().min(1).max(1000).default(100),
    offset: z.number().min(0).default(0),
  });

  const result = validateInputOrThrow(paginationSchema, params, {
    context: 'Pagination parameters',
  });

  return {
    limit: result.limit ?? 100,
    offset: result.offset ?? 0,
  };
}

/**
 * Validate date range parameters
 * @param params - Date range parameters
 * @returns Validated date range
 */
export function validateDateRange(params: {
  from: unknown;
  to: unknown;
}): { from: string; to: string } {
  const dateRangeSchema = z.object({
    from: z.string().datetime(),
    to: z.string().datetime(),
  }).refine(data => new Date(data.from) < new Date(data.to), {
    message: "From date must be before to date",
  });

  return validateInputOrThrow(dateRangeSchema, params, {
    context: 'Date range',
  });
}

/**
 * Convert validation errors to API errors
 * @param errors - Validation errors
 * @returns API errors
 */
export function validationErrorsToApiErrors(errors: ValidationError[]): ApiError[] {
  return errors.map(error => ({
    code: error.code,
    message: error.message,
    field: error.field,
    details: {
      value: error.value,
    },
  }));
}

/**
 * Format validation errors for user display
 * @param errors - Validation errors
 * @returns Formatted error message
 */
export function formatValidationErrors(errors: ValidationError[]): string {
  return errors
    .map(error => `${error.field}: ${error.message}`)
    .join(', ');
}

/**
 * Check if value is empty (null, undefined, empty string, empty array, empty object)
 * @param value - Value to check
 * @returns True if empty
 */
export function isEmpty(value: unknown): boolean {
  if (value === null || value === undefined) {
    return true;
  }

  if (typeof value === 'string') {
    return value.trim().length === 0;
  }

  if (Array.isArray(value)) {
    return value.length === 0;
  }

  if (typeof value === 'object') {
    return Object.keys(value).length === 0;
  }

  return false;
}

/**
 * Get nested value from object using path array
 * @param obj - Object to get value from
 * @param path - Path array
 * @returns Nested value
 */
function getNestedValue(obj: unknown, path: string[]): unknown {
  return path.reduce((current, key) => {
    if (current && typeof current === 'object' && key in current) {
      return (current as Record<string, unknown>)[key];
    }
    return undefined;
  }, obj);
}

/**
 * Common validation schemas
 */
export const CommonSchemas = {
  /**
   * Non-empty string schema
   */
  nonEmptyString: z.string().min(1, 'String cannot be empty').trim(),

  /**
   * Optional non-empty string schema
   */
  optionalNonEmptyString: z.string().min(1, 'String cannot be empty').trim().optional(),

  /**
   * Email schema
   */
  email: z.string().email('Invalid email format').trim().toLowerCase(),

  /**
   * URL schema
   */
  url: z.string().url('Invalid URL format').trim(),

  /**
   * Positive integer schema
   */
  positiveInt: z.number().positive().int(),

  /**
   * Non-negative integer schema
   */
  nonNegativeInt: z.number().nonnegative().int(),

  /**
   * Boolean schema with string conversion
   */
  booleanString: z.union([
    z.boolean(),
    z.string().transform((val) => {
      if (val.toLowerCase() === 'true') return true;
      if (val.toLowerCase() === 'false') return false;
      throw new Error('Invalid boolean value');
    }),
  ]),

  /**
   * Date string schema
   */
  dateString: z.string().datetime(),

  /**
   * JSON string schema
   */
  jsonString: z.string().transform((str, ctx) => {
    try {
      return JSON.parse(str);
    } catch {
      ctx.addIssue({ code: 'custom', message: 'Invalid JSON string' });
      return z.NEVER;
    }
  }),
};