/**
 * @fileoverview Shared types index
 * Clean exports for all shared type definitions
 */

// Tool context and execution interfaces
export type {
  ToolContext,
  ToolExecutionContext,
  ToolDefinition,
} from './tool-context.js';

// API client types
export type {
  ApiResponse,
  ApiError,
  PaginationInfo,
  FilterOptions,
  ApiRequestOptions,
  RateLimitInfo,
  AuthContext,
  SuccessResponse,
  ErrorResponse,
  ListResponse,
  ItemResponse,
  OperationResult,
} from './api-client.js';

// Export schemas for validation
export {
  FilterOptionsSchema,
  IdSchema,
  StringIdSchema,
  TeamIdSchema,
  OrganizationIdSchema,
  DateRangeSchema,
} from './api-client.js';