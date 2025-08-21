/**
 * @fileoverview Shared API client types for Make.com FastMCP tools
 * Common interfaces and types used across all tools for API interactions
 */

import { z } from 'zod';

/**
 * Common API response structure from Make.com
 */
export interface ApiResponse<T = any> {
  data: T;
  message?: string;
  status: 'success' | 'error';
  errors?: ApiError[];
  meta?: {
    pagination?: PaginationInfo;
    total?: number;
    limit?: number;
    offset?: number;
  };
}

/**
 * API error structure
 */
export interface ApiError {
  code: string;
  message: string;
  field?: string;
  details?: Record<string, any>;
}

/**
 * Pagination information
 */
export interface PaginationInfo {
  page: number;
  per_page: number;
  total_pages: number;
  total_items: number;
  has_next: boolean;
  has_prev: boolean;
}

/**
 * Common filtering options for list operations
 */
export interface FilterOptions {
  limit?: number;
  offset?: number;
  search?: string;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
  team_id?: number;
  organization_id?: number;
  created_after?: string;
  created_before?: string;
  updated_after?: string;
  updated_before?: string;
}

/**
 * Common API request options
 */
export interface ApiRequestOptions {
  timeout?: number;
  retries?: number;
  headers?: Record<string, string>;
  params?: Record<string, any>;
  validateResponse?: boolean;
}

/**
 * Rate limiting information from API responses
 */
export interface RateLimitInfo {
  limit: number;
  remaining: number;
  reset: number;
  retry_after?: number;
}

/**
 * API client authentication context
 */
export interface AuthContext {
  access_token?: string;
  refresh_token?: string;
  token_type?: string;
  expires_at?: number;
  scopes?: string[];
  team_id?: number;
  organization_id?: number;
}

/**
 * Common Zod schemas for validation
 */
export const FilterOptionsSchema = z.object({
  limit: z.number().min(1).max(1000).optional().default(100),
  offset: z.number().min(0).optional().default(0),
  search: z.string().min(1).max(255).optional(),
  sort_by: z.string().min(1).max(50).optional(),
  sort_order: z.enum(['asc', 'desc']).optional().default('asc'),
  team_id: z.number().positive().optional(),
  organization_id: z.number().positive().optional(),
  created_after: z.string().datetime().optional(),
  created_before: z.string().datetime().optional(),
  updated_after: z.string().datetime().optional(),
  updated_before: z.string().datetime().optional(),
}).strict();

/**
 * Common validation schema for IDs
 */
export const IdSchema = z.number().positive();

/**
 * Common validation schema for string IDs
 */
export const StringIdSchema = z.string().min(1).max(255);

/**
 * Team ID validation schema
 */
export const TeamIdSchema = z.number().positive();

/**
 * Organization ID validation schema
 */
export const OrganizationIdSchema = z.number().positive();

/**
 * Date range validation schema
 */
export const DateRangeSchema = z.object({
  from: z.string().datetime(),
  to: z.string().datetime(),
}).refine(data => new Date(data.from) < new Date(data.to), {
  message: "From date must be before to date",
});

/**
 * Common success response types
 */
export type SuccessResponse<T = any> = ApiResponse<T> & {
  status: 'success';
};

export type ErrorResponse = ApiResponse<null> & {
  status: 'error';
  errors: ApiError[];
};

/**
 * Generic list response type
 */
export type ListResponse<T> = SuccessResponse<T[]> & {
  meta: {
    pagination: PaginationInfo;
    total: number;
    limit: number;
    offset: number;
  };
};

/**
 * Generic single item response type
 */
export type ItemResponse<T> = SuccessResponse<T>;

/**
 * Common operation result types
 */
export interface OperationResult<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  errors?: ApiError[];
}