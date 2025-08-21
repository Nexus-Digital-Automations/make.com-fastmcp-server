/**
 * @fileoverview Comprehensive Test Suite for Shared Utilities
 * Tests the shared utility components used across tool modules
 */

import { describe, expect, test, beforeEach, afterEach, jest } from '@jest/globals';
import { z } from 'zod';
import type { Mock } from 'jest-mock';

// Import shared utilities
import {
  validateInput,
  validateInputOrThrow,
  validatePaginationParams,
  validateDateRange,
  validateTeamId,
  validateOrganizationId
} from '../../src/tools/shared/utils/validation.js';

import {
  FastMCPError,
  createAuthenticationError,
  createValidationError,
  createAPIError,
  createRateLimitError,
  createInternalError,
  handleError,
  retryWithBackoff
} from '../../src/tools/shared/utils/error-handling.js';

import {
  ToolContext,
  ToolDefinition,
  ToolExecutionContext
} from '../../src/tools/shared/types/tool-context.js';

import {
  ApiResponse,
  ApiError,
  PaginationInfo
} from '../../src/tools/shared/types/api-client.js';

describe('Shared Utilities Test Suite', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Validation Utilities', () => {
    const testSchema = z.object({
      name: z.string().min(1),
      age: z.number().min(0).max(120),
      email: z.string().email()
    });

    test('should validate input successfully with valid data', () => {
      const validData = {
        name: 'John Doe',
        age: 30,
        email: 'john@example.com'
      };

      const result = validateInput(testSchema, validData);

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.name).toBe('John Doe');
        expect(result.data.age).toBe(30);
        expect(result.data.email).toBe('john@example.com');
      }
    });

    test('should return validation error with invalid data', () => {
      const invalidData = {
        name: '',
        age: -5,
        email: 'invalid-email'
      };

      const result = validateInput(testSchema, invalidData);

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.message).toContain('validation');
        expect(result.error.details).toBeDefined();
      }
    });

    test('should throw validation error with validateInputOrThrow', () => {
      const invalidData = {
        name: '',
        age: -5,
        email: 'invalid-email'
      };

      expect(() => {
        validateInputOrThrow(testSchema, invalidData, { context: 'Test validation' });
      }).toThrow(FastMCPError);
    });

    test('should validate pagination parameters with defaults', () => {
      const params = {};
      const result = validatePaginationParams(params);

      expect(result.limit).toBe(100);
      expect(result.offset).toBe(0);
    });

    test('should validate pagination parameters with custom values', () => {
      const params = {
        limit: 50,
        offset: 25
      };
      const result = validatePaginationParams(params);

      expect(result.limit).toBe(50);
      expect(result.offset).toBe(25);
    });

    test('should validate date range parameters', () => {
      const params = {
        from: '2025-01-01',
        to: '2025-12-31'
      };

      expect(() => {
        validateDateRange(params);
      }).not.toThrow();
    });

    test('should validate team ID', () => {
      const teamId = 123;
      const result = validateTeamId(teamId);

      expect(result).toBe(123);
    });

    test('should validate organization ID', () => {
      const orgId = 456;
      const result = validateOrganizationId(orgId);

      expect(result).toBe(456);
    });

    test('should throw error for invalid team ID', () => {
      expect(() => {
        validateTeamId('invalid');
      }).toThrow(FastMCPError);
    });
  });

  describe('Error Handling Utilities', () => {
    test('should create FastMCPError with proper structure', () => {
      const error = new FastMCPError(
        'Test error',
        'VALIDATION_ERROR',
        { field: 'test' }
      );

      expect(error.message).toBe('Test error');
      expect(error.code).toBe('VALIDATION_ERROR');
      expect(error.context).toEqual({ field: 'test' });
      expect(error.timestamp).toBeInstanceOf(Date);
      expect(error.errorId).toBeDefined();
    });

    test('should create authentication error', () => {
      const error = createAuthenticationError('Invalid token');

      expect(error.code).toBe('AUTHENTICATION_ERROR');
      expect(error.message).toBe('Invalid token');
      expect(error.context.category).toBe('authentication');
    });

    test('should create validation error', () => {
      const error = createValidationError('Invalid input', { field: 'email' });

      expect(error.code).toBe('VALIDATION_ERROR');
      expect(error.message).toBe('Invalid input');
      expect(error.context.details).toEqual({ field: 'email' });
    });

    test('should create API error', () => {
      const error = createAPIError('API failure', 500, 'INTERNAL_ERROR');

      expect(error.code).toBe('API_ERROR');
      expect(error.message).toBe('API failure');
      expect(error.context.statusCode).toBe(500);
      expect(error.context.apiErrorCode).toBe('INTERNAL_ERROR');
    });

    test('should create rate limit error', () => {
      const error = createRateLimitError(60);

      expect(error.code).toBe('RATE_LIMIT_ERROR');
      expect(error.context.retryAfter).toBe(60);
    });

    test('should create internal error', () => {
      const originalError = new Error('Original error');
      const error = createInternalError('Internal failure', originalError);

      expect(error.code).toBe('INTERNAL_ERROR');
      expect(error.message).toBe('Internal failure');
      expect(error.context.originalError).toBe('Original error');
    });

    test('should handle known FastMCPError', () => {
      const originalError = new FastMCPError('Test error', 'VALIDATION_ERROR');
      const result = handleError(originalError, 'Test context');

      expect(result).toBe(originalError);
    });

    test('should handle unknown error', () => {
      const originalError = new Error('Unknown error');
      const result = handleError(originalError, 'Test context');

      expect(result).toBeInstanceOf(FastMCPError);
      expect(result.code).toBe('INTERNAL_ERROR');
    });

    test('should retry with backoff successfully', async () => {
      let attemptCount = 0;
      const operation = jest.fn(() => {
        attemptCount++;
        if (attemptCount < 3) {
          throw new Error('Temporary failure');
        }
        return 'success';
      }) as Mock;

      const result = await retryWithBackoff(operation, {
        maxAttempts: 3,
        baseDelay: 10,
        maxDelay: 100
      });

      expect(result).toBe('success');
      expect(operation).toHaveBeenCalledTimes(3);
    });

    test('should fail after max retry attempts', async () => {
      const operation = jest.fn(() => {
        throw new Error('Persistent failure');
      }) as Mock;

      await expect(retryWithBackoff(operation, {
        maxAttempts: 2,
        baseDelay: 10,
        maxDelay: 100
      })).rejects.toThrow('Persistent failure');

      expect(operation).toHaveBeenCalledTimes(2);
    });
  });

  describe('Type Definitions', () => {
    test('should create valid ToolContext', () => {
      const mockServer = {} as any;
      const mockApiClient = {} as any;
      const mockLogger = {
        debug: jest.fn(),
        info: jest.fn(),
        warn: jest.fn(),
        error: jest.fn()
      };

      const toolContext: ToolContext = {
        server: mockServer,
        apiClient: mockApiClient,
        logger: mockLogger
      };

      expect(toolContext.server).toBe(mockServer);
      expect(toolContext.apiClient).toBe(mockApiClient);
      expect(toolContext.logger).toBe(mockLogger);
    });

    test('should create valid ToolDefinition', () => {
      const toolDefinition: ToolDefinition = {
        name: 'test-tool',
        description: 'Test tool description',
        parameters: z.object({}),
        annotations: {
          title: 'Test Tool',
          readOnlyHint: true,
          openWorldHint: false
        },
        execute: async () => 'test result'
      };

      expect(toolDefinition.name).toBe('test-tool');
      expect(toolDefinition.description).toBe('Test tool description');
      expect(toolDefinition.annotations.title).toBe('Test Tool');
      expect(typeof toolDefinition.execute).toBe('function');
    });

    test('should create valid ToolExecutionContext', () => {
      const executionContext: ToolExecutionContext = {
        log: {
          info: jest.fn(),
          warn: jest.fn(),
          error: jest.fn(),
          debug: jest.fn()
        },
        reportProgress: jest.fn(),
        session: { id: 'test-session' }
      };

      expect(executionContext.log).toBeDefined();
      expect(executionContext.reportProgress).toBeDefined();
      expect(executionContext.session).toEqual({ id: 'test-session' });
    });

    test('should create valid ApiResponse', () => {
      const apiResponse: ApiResponse<{ data: string }> = {
        success: true,
        data: { data: 'test' },
        pagination: {
          page: 1,
          limit: 10,
          total: 50,
          hasMore: true
        },
        metadata: {
          requestId: 'req-123',
          timestamp: new Date().toISOString(),
          version: '1.0.0'
        }
      };

      expect(apiResponse.success).toBe(true);
      expect(apiResponse.data.data).toBe('test');
      expect(apiResponse.pagination?.page).toBe(1);
      expect(apiResponse.metadata?.requestId).toBe('req-123');
    });

    test('should create valid ApiError', () => {
      const apiError: ApiError = {
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Validation failed',
          details: { field: 'email' }
        },
        metadata: {
          requestId: 'req-456',
          timestamp: new Date().toISOString(),
          version: '1.0.0'
        }
      };

      expect(apiError.success).toBe(false);
      expect(apiError.error.code).toBe('VALIDATION_ERROR');
      expect(apiError.error.message).toBe('Validation failed');
      expect(apiError.metadata?.requestId).toBe('req-456');
    });

    test('should create valid PaginationInfo', () => {
      const pagination: PaginationInfo = {
        page: 2,
        limit: 25,
        total: 100,
        hasMore: true,
        nextPage: 3,
        prevPage: 1,
        totalPages: 4
      };

      expect(pagination.page).toBe(2);
      expect(pagination.limit).toBe(25);
      expect(pagination.total).toBe(100);
      expect(pagination.hasMore).toBe(true);
      expect(pagination.nextPage).toBe(3);
      expect(pagination.prevPage).toBe(1);
      expect(pagination.totalPages).toBe(4);
    });
  });

  describe('Integration Tests', () => {
    test('should work together in typical workflow', async () => {
      // Simulate a typical tool execution workflow
      const mockLogger = {
        debug: jest.fn(),
        info: jest.fn(),
        warn: jest.fn(),
        error: jest.fn()
      };

      const mockApiClient = {
        get: jest.fn().mockResolvedValue({
          success: true,
          data: { items: [] },
          pagination: { page: 1, limit: 10, total: 0, hasMore: false }
        })
      };

      const toolContext: ToolContext = {
        server: {} as any,
        apiClient: mockApiClient,
        logger: mockLogger
      };

      // Validate input
      const inputSchema = z.object({
        query: z.string().min(1),
        limit: z.number().min(1).max(100).default(10)
      });

      const inputData = { query: 'test', limit: 5 };
      const validationResult = validateInput(inputSchema, inputData);

      expect(validationResult.success).toBe(true);

      if (validationResult.success) {
        // Simulate API call
        try {
          const response = await mockApiClient.get('/test', {
            params: validationResult.data
          });

          expect(response.success).toBe(true);
          expect(mockApiClient.get).toHaveBeenCalledWith('/test', {
            params: { query: 'test', limit: 5 }
          });
        } catch (error) {
          // Handle error using error utilities
          const handledError = handleError(error, 'Test workflow');
          expect(handledError).toBeInstanceOf(FastMCPError);
        }
      }
    });

    test('should handle error scenarios gracefully', async () => {
      const mockApiClient = {
        get: jest.fn().mockRejectedValue(new Error('Network error'))
      };

      // Simulate error handling in tool execution
      try {
        await mockApiClient.get('/test');
      } catch (error) {
        const handledError = handleError(error, 'Network operation');
        
        expect(handledError).toBeInstanceOf(FastMCPError);
        expect(handledError.code).toBe('INTERNAL_ERROR');
        expect(handledError.context.operation).toBe('Network operation');
      }
    });

    test('should validate complex nested structures', () => {
      const complexSchema = z.object({
        user: z.object({
          id: z.number(),
          profile: z.object({
            name: z.string(),
            settings: z.object({
              notifications: z.boolean(),
              theme: z.enum(['light', 'dark'])
            })
          })
        }),
        metadata: z.record(z.string(), z.unknown())
      });

      const validData = {
        user: {
          id: 123,
          profile: {
            name: 'Test User',
            settings: {
              notifications: true,
              theme: 'dark' as const
            }
          }
        },
        metadata: {
          source: 'api',
          version: '1.0.0'
        }
      };

      const result = validateInput(complexSchema, validData);

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.user.id).toBe(123);
        expect(result.data.user.profile.name).toBe('Test User');
        expect(result.data.user.profile.settings.theme).toBe('dark');
        expect(result.data.metadata.source).toBe('api');
      }
    });
  });

  describe('Performance Tests', () => {
    test('should validate large datasets efficiently', () => {
      const schema = z.array(z.object({
        id: z.number(),
        name: z.string(),
        value: z.number()
      }));

      const largeDataset = Array.from({ length: 1000 }, (_, i) => ({
        id: i,
        name: `Item ${i}`,
        value: Math.random() * 100
      }));

      const startTime = Date.now();
      const result = validateInput(schema, largeDataset);
      const duration = Date.now() - startTime;

      expect(result.success).toBe(true);
      expect(duration).toBeLessThan(100); // Should complete within 100ms
    });

    test('should handle error creation efficiently', () => {
      const startTime = Date.now();

      for (let i = 0; i < 100; i++) {
        createValidationError(`Error ${i}`, { index: i });
      }

      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(50); // Should complete within 50ms
    });
  });
});