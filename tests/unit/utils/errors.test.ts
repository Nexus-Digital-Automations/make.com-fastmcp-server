/**
 * Comprehensive unit tests for errors.ts module
 * Ensures 100% test coverage for critical error handling functionality
 */

import {
  MakeServerError,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  ExternalServiceError,
  ConfigurationError,
  TimeoutError,
  isOperationalError,
  getErrorStatusCode,
  getErrorCode,
  serializeError,
  createValidationError,
  createNotFoundError,
  createConflictError,
  createExternalServiceError,
  setupGlobalErrorHandlers,
  type ErrorContext,
} from '../../../src/utils/errors.js';

describe('Error Handling System - Comprehensive Test Suite', () => {
  const mockContext: ErrorContext = {
    correlationId: 'test-correlation-id',
    operation: 'test-operation',
    component: 'test-component',
    userId: 'test-user-123',
    sessionId: 'test-session-456',
    requestId: 'test-request-789',
    traceId: 'test-trace-abc',
    userAgent: 'test-agent',
    ipAddress: '127.0.0.1',
    metadata: { test: 'data' },
  };

  describe('MakeServerError - Base Error Class', () => {
    it('should create error with all parameters', () => {
      const error = new MakeServerError(
        'Test error message',
        'TEST_CODE',
        400,
        true,
        { detail: 'test' },
        mockContext
      );

      expect(error.name).toBe('MakeServerError');
      expect(error.message).toBe('Test error message');
      expect(error.code).toBe('TEST_CODE');
      expect(error.statusCode).toBe(400);
      expect(error.isOperational).toBe(true);
      expect(error.details).toEqual({ detail: 'test' });
      expect(error.correlationId).toBe('test-correlation-id');
      expect(error.context).toMatchObject(mockContext);
      expect(error.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z$/);
    });

    it('should create error with default values', () => {
      const error = new MakeServerError('Test message');

      expect(error.code).toBe('INTERNAL_ERROR');
      expect(error.statusCode).toBe(500);
      expect(error.isOperational).toBe(true);
      expect(error.details).toBeUndefined();
      expect(error.correlationId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
      expect(error.context.correlationId).toBe(error.correlationId);
    });

    it('should generate unique correlation IDs', () => {
      const error1 = new MakeServerError('Test 1');
      const error2 = new MakeServerError('Test 2');

      expect(error1.correlationId).not.toBe(error2.correlationId);
    });

    it('should maintain proper prototype chain', () => {
      const error = new MakeServerError('Test');
      expect(error instanceof MakeServerError).toBe(true);
      expect(error instanceof Error).toBe(true);
    });

    it('should create structured error object', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      try {
        const error = new MakeServerError(
          'Test error',
          'TEST_CODE',
          400,
          true,
          { detail: 'test' },
          mockContext
        );

        const structured = error.toStructuredError();

        expect(structured).toEqual({
          name: 'MakeServerError',
          message: 'Test error',
          code: 'TEST_CODE',
          statusCode: 400,
          correlationId: 'test-correlation-id',
          timestamp: error.timestamp,
          context: mockContext,
          details: { detail: 'test' },
          stack: expect.any(String), // In development environment
        });
      } finally {
        process.env.NODE_ENV = originalEnv;
      }
    });

    it('should hide stack trace in production', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      try {
        const error = new MakeServerError('Test');
        const structured = error.toStructuredError();
        expect(structured.stack).toBeUndefined();
      } finally {
        process.env.NODE_ENV = originalEnv;
      }
    });

    it('should create child error with inherited context', () => {
      const parentError = new MakeServerError(
        'Parent error',
        'PARENT_CODE',
        400,
        true,
        { parent: 'data' },
        mockContext
      );

      const childError = parentError.createChildError(
        'Child error',
        'CHILD_CODE',
        500,
        { child: 'data' },
        { operation: 'child-operation' }
      );

      expect(childError.message).toBe('Child error');
      expect(childError.code).toBe('CHILD_CODE');
      expect(childError.statusCode).toBe(500);
      expect(childError.details).toEqual({ child: 'data' });
      expect(childError.correlationId).toBe(parentError.correlationId);
      expect(childError.context.operation).toBe('child-operation');
      expect(childError.context.userId).toBe(mockContext.userId);
    });

    it('should create child error with default values from parent', () => {
      const parentError = new MakeServerError('Parent', 'PARENT_CODE', 400);
      const childError = parentError.createChildError('Child');

      expect(childError.code).toBe('PARENT_CODE');
      expect(childError.statusCode).toBe(400);
      expect(childError.isOperational).toBe(true);
    });
  });

  describe('Specific Error Classes', () => {
    describe('ValidationError', () => {
      it('should create validation error with correct defaults', () => {
        const error = new ValidationError('Invalid input', { field: 'name' }, mockContext);

        expect(error.name).toBe('ValidationError');
        expect(error.code).toBe('VALIDATION_ERROR');
        expect(error.statusCode).toBe(400);
        expect(error.isOperational).toBe(true);
        expect(error.details).toEqual({ field: 'name' });
        expect(error instanceof ValidationError).toBe(true);
        expect(error instanceof MakeServerError).toBe(true);
      });
    });

    describe('AuthenticationError', () => {
      it('should create authentication error with default message', () => {
        const error = new AuthenticationError();

        expect(error.message).toBe('Authentication failed');
        expect(error.code).toBe('AUTHENTICATION_ERROR');
        expect(error.statusCode).toBe(401);
      });

      it('should create authentication error with custom message', () => {
        const error = new AuthenticationError('Custom auth error');
        expect(error.message).toBe('Custom auth error');
      });
    });

    describe('AuthorizationError', () => {
      it('should create authorization error with default message', () => {
        const error = new AuthorizationError();

        expect(error.message).toBe('Insufficient permissions');
        expect(error.code).toBe('AUTHORIZATION_ERROR');
        expect(error.statusCode).toBe(403);
      });

      it('should create authorization error with custom message', () => {
        const error = new AuthorizationError('Custom auth error');
        expect(error.message).toBe('Custom auth error');
      });
    });

    describe('NotFoundError', () => {
      it('should create not found error with default resource', () => {
        const error = new NotFoundError();
        expect(error.message).toBe('Resource not found');
        expect(error.code).toBe('NOT_FOUND');
        expect(error.statusCode).toBe(404);
      });

      it('should create not found error with custom resource', () => {
        const error = new NotFoundError('User');
        expect(error.message).toBe('User not found');
      });
    });

    describe('ConflictError', () => {
      it('should create conflict error', () => {
        const error = new ConflictError('Resource already exists');

        expect(error.message).toBe('Resource already exists');
        expect(error.code).toBe('CONFLICT');
        expect(error.statusCode).toBe(409);
      });
    });

    describe('RateLimitError', () => {
      it('should create rate limit error with default message', () => {
        const error = new RateLimitError();

        expect(error.message).toBe('Rate limit exceeded');
        expect(error.code).toBe('RATE_LIMIT');
        expect(error.statusCode).toBe(429);
        expect(error.retryAfter).toBeUndefined();
      });

      it('should create rate limit error with retry after', () => {
        const error = new RateLimitError('Custom rate limit', 60);
        expect(error.retryAfter).toBe(60);
      });
    });

    describe('ExternalServiceError', () => {
      it('should create external service error', () => {
        const originalError = new Error('Original error');
        const error = new ExternalServiceError(
          'PaymentAPI',
          'Failed to process payment',
          originalError,
          { transactionId: '123' }
        );

        expect(error.message).toBe('PaymentAPI error: Failed to process payment');
        expect(error.code).toBe('EXTERNAL_SERVICE_ERROR');
        expect(error.statusCode).toBe(502);
        expect(error.service).toBe('PaymentAPI');
        expect(error.originalError).toBe(originalError);
        expect(error.details).toEqual({ transactionId: '123' });
      });
    });

    describe('ConfigurationError', () => {
      it('should create configuration error', () => {
        const error = new ConfigurationError('Invalid config');

        expect(error.message).toBe('Invalid config');
        expect(error.code).toBe('CONFIGURATION_ERROR');
        expect(error.statusCode).toBe(500);
        expect(error.isOperational).toBe(false);
      });
    });

    describe('TimeoutError', () => {
      it('should create timeout error', () => {
        const error = new TimeoutError('database-query', 5000, { query: 'SELECT *' });

        expect(error.message).toBe("Operation 'database-query' timed out after 5000ms");
        expect(error.code).toBe('TIMEOUT');
        expect(error.statusCode).toBe(408);
        expect(error.operation).toBe('database-query');
        expect(error.timeoutMs).toBe(5000);
        expect(error.details).toEqual({ query: 'SELECT *' });
      });
    });
  });

  describe('Error Utility Functions', () => {
    describe('isOperationalError', () => {
      it('should return true for operational MakeServerError', () => {
        const error = new MakeServerError('Test', 'TEST', 400, true);
        expect(isOperationalError(error)).toBe(true);
      });

      it('should return false for non-operational MakeServerError', () => {
        const error = new MakeServerError('Test', 'TEST', 500, false);
        expect(isOperationalError(error)).toBe(false);
      });

      it('should return false for regular Error', () => {
        const error = new Error('Regular error');
        expect(isOperationalError(error)).toBe(false);
      });
    });

    describe('getErrorStatusCode', () => {
      it('should return status code from MakeServerError', () => {
        const error = new ValidationError('Test');
        expect(getErrorStatusCode(error)).toBe(400);
      });

      it('should return 500 for regular Error', () => {
        const error = new Error('Regular error');
        expect(getErrorStatusCode(error)).toBe(500);
      });
    });

    describe('getErrorCode', () => {
      it('should return code from MakeServerError', () => {
        const error = new ValidationError('Test');
        expect(getErrorCode(error)).toBe('VALIDATION_ERROR');
      });

      it('should return UNKNOWN_ERROR for regular Error', () => {
        const error = new Error('Regular error');
        expect(getErrorCode(error)).toBe('UNKNOWN_ERROR');
      });
    });

    describe('serializeError', () => {
      it('should serialize MakeServerError with details', () => {
        const originalEnv = process.env.NODE_ENV;
        process.env.NODE_ENV = 'development';

        try {
          const error = new ValidationError('Test validation', { field: 'name' });
          const serialized = serializeError(error);

          expect(serialized).toEqual({
            name: 'ValidationError',
            message: 'Test validation',
            code: 'VALIDATION_ERROR',
            statusCode: 400,
            details: { field: 'name' },
            stack: expect.any(String),
          });
        } finally {
          process.env.NODE_ENV = originalEnv;
        }
      });

      it('should serialize regular Error without details', () => {
        const originalEnv = process.env.NODE_ENV;
        process.env.NODE_ENV = 'development';

        try {
          const error = new Error('Regular error');
          const serialized = serializeError(error);

          expect(serialized).toEqual({
            name: 'Error',
            message: 'Regular error',
            code: 'UNKNOWN_ERROR',
            statusCode: 500,
            details: undefined,
            stack: expect.any(String),
          });
        } finally {
          process.env.NODE_ENV = originalEnv;
        }
      });

      it('should hide stack in production', () => {
        const originalEnv = process.env.NODE_ENV;
        process.env.NODE_ENV = 'production';

        try {
          const error = new Error('Test');
          const serialized = serializeError(error);
          expect(serialized.stack).toBeUndefined();
        } finally {
          process.env.NODE_ENV = originalEnv;
        }
      });
    });
  });

  describe('Error Factory Functions', () => {
    describe('createValidationError', () => {
      it('should create validation error with field details', () => {
        const error = createValidationError('email', 'invalid-email', 'valid email address');

        expect(error instanceof ValidationError).toBe(true);
        expect(error.message).toBe('Invalid email: expected valid email address, got string');
        expect(error.details).toEqual({
          field: 'email',
          value: 'invalid-email',
          expected: 'valid email address',
        });
      });
    });

    describe('createNotFoundError', () => {
      it('should create not found error with resource and ID', () => {
        const error = createNotFoundError('User', 123);

        expect(error instanceof NotFoundError).toBe(true);
        expect(error.message).toBe('User with ID 123 not found');
        expect(error.details).toEqual({
          resource: 'User',
          id: 123,
        });
      });

      it('should handle string ID', () => {
        const error = createNotFoundError('Document', 'abc-123');
        expect(error.message).toBe('Document with ID abc-123 not found');
        expect(error.details).toEqual({
          resource: 'Document',
          id: 'abc-123',
        });
      });
    });

    describe('createConflictError', () => {
      it('should create conflict error with field details', () => {
        const error = createConflictError('User', 'email', 'test@example.com');

        expect(error instanceof ConflictError).toBe(true);
        expect(error.message).toBe("User with email 'test@example.com' already exists");
        expect(error.details).toEqual({
          resource: 'User',
          field: 'email',
          value: 'test@example.com',
        });
      });
    });

    describe('createExternalServiceError', () => {
      it('should create external service error with operation details', () => {
        const originalError = new Error('Connection refused');
        const error = createExternalServiceError('PaymentAPI', 'process payment', originalError);

        expect(error instanceof ExternalServiceError).toBe(true);
        expect(error.message).toBe('PaymentAPI error: Failed to process payment');
        expect(error.service).toBe('PaymentAPI');
        expect(error.originalError).toBe(originalError);
        expect(error.details).toEqual({
          operation: 'process payment',
          originalMessage: 'Connection refused',
        });
      });
    });
  });

  describe('Global Error Handlers', () => {
    let originalProcessExit: typeof process.exit;
    let originalConsoleError: typeof console.error;
    let exitMock: jest.MockedFunction<typeof process.exit>;
    let consoleErrorMock: jest.MockedFunction<typeof console.error>;

    beforeEach(() => {
      originalProcessExit = process.exit;
      originalConsoleError = console.error;
      exitMock = jest.fn() as any;
      consoleErrorMock = jest.fn();
      process.exit = exitMock;
      console.error = consoleErrorMock;
    });

    afterEach(() => {
      process.exit = originalProcessExit;
      console.error = originalConsoleError;
      process.removeAllListeners('unhandledRejection');
      process.removeAllListeners('uncaughtException');
    });

    it('should setup global error handlers', () => {
      setupGlobalErrorHandlers();

      expect(process.listenerCount('unhandledRejection')).toBe(1);
      expect(process.listenerCount('uncaughtException')).toBe(1);
    });

    it('should handle unhandled rejection in development', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      try {
        setupGlobalErrorHandlers();
        
        const testPromise = Promise.resolve();
        const testReason = new Error('Test rejection');
        
        process.emit('unhandledRejection', testReason, testPromise);

        expect(consoleErrorMock).toHaveBeenCalledWith(
          'Unhandled Rejection at:',
          testPromise,
          'reason:',
          testReason
        );
        expect(exitMock).toHaveBeenCalledWith(1);
      } finally {
        process.env.NODE_ENV = originalEnv;
      }
    });

    it('should handle unhandled rejection in production without exit', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      try {
        setupGlobalErrorHandlers();
        
        const testPromise = Promise.resolve();
        const testReason = new Error('Test rejection');
        
        process.emit('unhandledRejection', testReason, testPromise);

        expect(consoleErrorMock).toHaveBeenCalled();
        expect(exitMock).not.toHaveBeenCalled();
      } finally {
        process.env.NODE_ENV = originalEnv;
      }
    });

    it('should handle uncaught exception and always exit', () => {
      setupGlobalErrorHandlers();
      
      const testError = new Error('Test uncaught exception');
      process.emit('uncaughtException', testError);

      expect(consoleErrorMock).toHaveBeenCalledWith('Uncaught Exception:', testError);
      expect(exitMock).toHaveBeenCalledWith(1);
    });
  });
});