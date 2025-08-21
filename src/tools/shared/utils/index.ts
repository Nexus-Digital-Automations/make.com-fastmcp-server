/**
 * @fileoverview Shared utilities index
 * Clean exports for all shared utility functions
 */

// Validation utilities
export {
  validateInput,
  validateInputOrThrow,
  sanitizeString,
  validateId,
  validateTeamId,
  validateOrganizationId,
  validatePaginationParams,
  validateDateRange,
  validationErrorsToApiErrors,
  formatValidationErrors,
  isEmpty,
  CommonSchemas,
} from './validation.js';

export type {
  ValidationResult,
  ValidationError,
  ValidationOptions,
} from './validation.js';

// Error handling utilities
export {
  ErrorCategory,
  ErrorCode,
  FastMCPError,
  createValidationError,
  createNotFoundError,
  createAuthenticationError,
  createAuthorizationError,
  createRateLimitError,
  createNetworkError,
  createTimeoutError,
  createInternalError,
  handleError,
  executeWithErrorHandling,
  executeOrThrow,
  retryOperation,
  logError,
} from './error-handling.js';

export type {
  ErrorInfo,
} from './error-handling.js';