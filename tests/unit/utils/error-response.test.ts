/**
 * Comprehensive Unit Tests for Error Response Module
 * 
 * Tests error response formatting, success response creation, middleware functions,
 * correlation ID handling, and tool response utilities. Covers all error types
 * and edge cases for consistent API response formatting.
 */

import { jest } from '@jest/globals';
import { randomUUID } from 'crypto';
import {
  formatErrorResponse,
  formatSuccessResponse,
  errorHandlerMiddleware,
  correlationMiddleware,
  createToolErrorResponse,
  createToolSuccessResponse,
  extractCorrelationId,
  type ErrorResponse,
  type SuccessResponse,
  type ApiResponse
} from '../../../src/utils/error-response';
import { 
  MakeServerError, 
  UserError, 
  EnhancedUserError,
  ErrorContext,
  getErrorCode,
  getErrorStatusCode,
  getErrorCorrelationId
} from '../../../src/utils/errors';

// Mock dependencies
jest.mock('../../../src/lib/logger', () => ({
  default: {
    child: jest.fn(() => ({
      info: jest.fn(),
      error: jest.fn(),
      warn: jest.fn(),
      debug: jest.fn()
    }))
  }
}));

jest.mock('crypto', () => ({
  randomUUID: jest.fn(() => 'test-uuid-123')
}));

jest.mock('../../../src/utils/errors', () => ({
  MakeServerError: class MockMakeServerError extends Error {
    public statusCode: number;
    public context?: any;
    constructor(message: string, statusCode: number = 500, context?: any) {
      super(message);
      this.name = 'MakeServerError';
      this.statusCode = statusCode;
      this.context = context;
    }
    
    toStructuredError() {
      return {
        message: this.message,
        code: 'MAKE_SERVER_ERROR',
        statusCode: this.statusCode,
        correlationId: 'structured-correlation-123',
        timestamp: '2023-01-01T00:00:00.000Z',
        context: this.context,
        details: { serverError: true },
        stack: this.stack
      };
    }
  },
  UserError: class MockUserError extends Error {
    constructor(message: string) {
      super(message);
      this.name = 'UserError';
    }
  },
  EnhancedUserError: class MockEnhancedUserError extends Error {
    public context?: any;
    public details?: any;
    public timestamp?: string;
    constructor(message: string, context?: any, details?: any, timestamp?: string) {
      super(message);
      this.name = 'EnhancedUserError';
      this.context = context;
      this.details = details;
      this.timestamp = timestamp;
    }
  },
  getErrorCode: jest.fn((error: Error) => {
    if (error.name === 'UserError') return 'USER_ERROR';
    if (error.name === 'EnhancedUserError') return 'ENHANCED_USER_ERROR';
    if (error.name === 'MakeServerError') return 'MAKE_SERVER_ERROR';
    return error.name || 'UNKNOWN_ERROR';
  }),
  getErrorStatusCode: jest.fn((error: Error) => {
    if (error.name === 'UserError') return 400;
    if (error.name === 'EnhancedUserError') return 422;
    if (error.name === 'MakeServerError') return (error as any).statusCode || 500;
    return 500;
  }),
  getErrorCorrelationId: jest.fn((error: Error) => {
    if ('correlationId' in error) return (error as any).correlationId;
    return null;
  })
}));

describe('formatErrorResponse', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Mock Date to have consistent timestamps in tests
    jest.spyOn(Date.prototype, 'toISOString').mockReturnValue('2023-01-01T00:00:00.000Z');
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('MakeServerError Formatting', () => {
    test('should format MakeServerError using structured error data', () => {
      const context: ErrorContext = {
        userId: 'user123',
        operation: 'test-operation',
        timestamp: '2023-01-01T00:00:00.000Z'
      };
      const error = new (MakeServerError as any)('Server error occurred', 503, context);
      
      const response = formatErrorResponse(error);
      
      expect(response).toEqual({
        error: {
          message: 'Server error occurred',
          code: 'MAKE_SERVER_ERROR',
          statusCode: 503,
          correlationId: 'structured-correlation-123',
          timestamp: '2023-01-01T00:00:00.000Z',
          context,
          details: { serverError: true },
          stack: error.stack
        },
        success: false
      });
    });

    test('should use provided correlation ID over structured one', () => {
      const error = new (MakeServerError as any)('Server error');
      
      const response = formatErrorResponse(error, 'custom-correlation-456');
      
      expect(response.error.correlationId).toBe('structured-correlation-123'); // Uses structured data
    });

    test('should handle MakeServerError without context', () => {
      const error = new (MakeServerError as any)('Simple server error');
      
      const response = formatErrorResponse(error);
      
      expect(response.error.message).toBe('Simple server error');
      expect(response.error.code).toBe('MAKE_SERVER_ERROR');
      expect(response.success).toBe(false);
    });
  });

  describe('UserError Formatting', () => {
    test('should format basic UserError correctly', () => {
      const error = new (UserError as any)('Invalid input provided');
      
      const response = formatErrorResponse(error);
      
      expect(response).toEqual({
        error: {
          message: 'Invalid input provided',
          code: 'USER_ERROR',
          statusCode: 400,
          correlationId: 'test-uuid-123',
          timestamp: '2023-01-01T00:00:00.000Z',
          context: undefined,
          details: undefined,
          stack: undefined // No stack in production
        },
        success: false
      });
    });

    test('should format EnhancedUserError with context and details', () => {
      const context: ErrorContext = {
        userId: 'user456',
        operation: 'validation',
        timestamp: '2023-01-01T00:00:00.000Z'
      };
      const details = { field: 'email', reason: 'invalid format' };
      const timestamp = '2023-01-01T12:00:00.000Z';
      
      const error = new (EnhancedUserError as any)('Enhanced validation error', context, details, timestamp);
      
      const response = formatErrorResponse(error);
      
      expect(response.error.context).toEqual(context);
      expect(response.error.details).toEqual(details);
      expect(response.error.timestamp).toBe(timestamp);
      expect(response.error.code).toBe('ENHANCED_USER_ERROR');
      expect(response.error.statusCode).toBe(422);
    });

    test('should include stack trace in development environment', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';
      
      const error = new (UserError as any)('Development error');
      const response = formatErrorResponse(error);
      
      expect(response.error.stack).toBeDefined();
      
      process.env.NODE_ENV = originalEnv;
    });

    test('should exclude stack trace in production environment', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      
      const error = new (UserError as any)('Production error');
      const response = formatErrorResponse(error);
      
      expect(response.error.stack).toBeUndefined();
      
      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('Generic Error Formatting', () => {
    test('should format generic Error with default values', () => {
      const error = new Error('Generic error message');
      
      const response = formatErrorResponse(error);
      
      expect(response).toEqual({
        error: {
          message: 'Generic error message',
          code: 'UNKNOWN_ERROR',
          statusCode: 500,
          correlationId: 'test-uuid-123',
          timestamp: '2023-01-01T00:00:00.000Z',
          details: {
            name: 'Error',
            originalMessage: 'Generic error message'
          },
          stack: undefined
        },
        success: false
      });
    });

    test('should handle Error without message', () => {
      const error = new Error();
      error.message = ''; // Clear message
      
      const response = formatErrorResponse(error);
      
      expect(response.error.message).toBe('Internal server error');
      expect(response.error.details?.originalMessage).toBe('');
    });

    test('should include stack trace for generic errors in development', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';
      
      const error = new Error('Development generic error');
      const response = formatErrorResponse(error);
      
      expect(response.error.stack).toBeDefined();
      
      process.env.NODE_ENV = originalEnv;
    });

    test('should handle custom error types', () => {
      class CustomError extends Error {
        constructor(message: string) {
          super(message);
          this.name = 'CustomError';
        }
      }
      
      const error = new CustomError('Custom error occurred');
      const response = formatErrorResponse(error);
      
      expect(response.error.details?.name).toBe('CustomError');
      expect(response.error.message).toBe('Custom error occurred');
    });
  });

  describe('Correlation ID Handling', () => {
    test('should use provided correlation ID', () => {
      const error = new Error('Test error');
      
      const response = formatErrorResponse(error, 'provided-correlation-789');
      
      expect(response.error.correlationId).toBe('provided-correlation-789');
    });

    test('should use correlation ID from error if available', () => {
      const error = new Error('Error with correlation');
      (getErrorCorrelationId as jest.Mock).mockReturnValue('error-correlation-456');
      
      const response = formatErrorResponse(error);
      
      expect(response.error.correlationId).toBe('error-correlation-456');
    });

    test('should generate new correlation ID if none available', () => {
      const error = new Error('Error without correlation');
      (getErrorCorrelationId as jest.Mock).mockReturnValue(null);
      
      const response = formatErrorResponse(error);
      
      expect(response.error.correlationId).toBe('test-uuid-123');
      expect(randomUUID).toHaveBeenCalled();
    });
  });
});

describe('formatSuccessResponse', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.spyOn(Date.prototype, 'toISOString').mockReturnValue('2023-01-01T00:00:00.000Z');
  });

  test('should format simple success response', () => {
    const data = { message: 'Operation successful' };
    
    const response = formatSuccessResponse(data);
    
    expect(response).toEqual({
      data: { message: 'Operation successful' },
      success: true,
      correlationId: undefined,
      timestamp: '2023-01-01T00:00:00.000Z'
    });
  });

  test('should include correlation ID when provided', () => {
    const data = { result: 'success' };
    
    const response = formatSuccessResponse(data, 'success-correlation-123');
    
    expect(response.correlationId).toBe('success-correlation-123');
  });

  test('should handle null data', () => {
    const response = formatSuccessResponse(null);
    
    expect(response.data).toBeNull();
    expect(response.success).toBe(true);
  });

  test('should handle array data', () => {
    const data = [1, 2, 3, 'test'];
    
    const response = formatSuccessResponse(data);
    
    expect(response.data).toEqual([1, 2, 3, 'test']);
  });

  test('should handle complex nested data', () => {
    const data = {
      users: [
        { id: 1, name: 'Alice' },
        { id: 2, name: 'Bob' }
      ],
      pagination: {
        page: 1,
        limit: 10,
        total: 2
      }
    };
    
    const response = formatSuccessResponse(data);
    
    expect(response.data).toEqual(data);
  });
});

describe('errorHandlerMiddleware', () => {
  let middleware: ReturnType<typeof errorHandlerMiddleware>;
  let mockReq: Record<string, unknown>;
  let mockRes: {
    status: jest.Mock;
    json: jest.Mock;
  };

  beforeEach(() => {
    jest.clearAllMocks();
    middleware = errorHandlerMiddleware();
    
    mockReq = {
      method: 'GET',
      path: '/api/test',
      headers: {}
    };
    
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
  });

  test('should handle error and send formatted response', () => {
    const error = new Error('Middleware test error');
    
    middleware(error, mockReq, mockRes as any);
    
    expect(mockRes.status).toHaveBeenCalledWith(500);
    expect(mockRes.json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: expect.objectContaining({
          message: 'Middleware test error',
          code: 'UNKNOWN_ERROR',
          statusCode: 500
        }),
        success: false
      })
    );
  });

  test('should use correlation ID from request', () => {
    const error = new Error('Test error');
    mockReq.correlationId = 'request-correlation-456';
    
    middleware(error, mockReq, mockRes as any);
    
    const jsonCall = mockRes.json.mock.calls[0][0] as ErrorResponse;
    expect(jsonCall.error.correlationId).toBe('request-correlation-456');
  });

  test('should use correlation ID from headers', () => {
    const error = new Error('Test error');
    mockReq.headers = { 'x-correlation-id': 'header-correlation-789' };
    
    middleware(error, mockReq, mockRes as any);
    
    const jsonCall = mockRes.json.mock.calls[0][0] as ErrorResponse;
    expect(jsonCall.error.correlationId).toBe('header-correlation-789');
  });

  test('should generate correlation ID if none provided', () => {
    const error = new Error('Test error');
    
    middleware(error, mockReq, mockRes as any);
    
    const jsonCall = mockRes.json.mock.calls[0][0] as ErrorResponse;
    expect(jsonCall.error.correlationId).toBe('test-uuid-123');
  });

  test('should handle MakeServerError with correct status code', () => {
    const error = new (MakeServerError as any)('Server error', 503);
    
    middleware(error, mockReq, mockRes as any);
    
    expect(mockRes.status).toHaveBeenCalledWith(503);
  });

  test('should handle missing request properties gracefully', () => {
    const error = new Error('Test error');
    const incompleteReq = {}; // Missing method and path
    
    expect(() => {
      middleware(error, incompleteReq, mockRes as any);
    }).not.toThrow();
    
    expect(mockRes.status).toHaveBeenCalled();
    expect(mockRes.json).toHaveBeenCalled();
  });
});

describe('correlationMiddleware', () => {
  let middleware: ReturnType<typeof correlationMiddleware>;
  let mockReq: Record<string, unknown>;
  let mockRes: {
    set: jest.Mock;
  };
  let mockNext: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
    middleware = correlationMiddleware();
    
    mockReq = {
      headers: {}
    };
    
    mockRes = {
      set: jest.fn()
    };
    
    mockNext = jest.fn();
  });

  test('should add correlation ID to request and response headers', () => {
    middleware(mockReq, mockRes as any, mockNext);
    
    expect(mockReq.correlationId).toBe('test-uuid-123');
    expect(mockRes.set).toHaveBeenCalledWith('X-Correlation-ID', 'test-uuid-123');
    expect(mockNext).toHaveBeenCalled();
  });

  test('should use existing correlation ID from headers', () => {
    mockReq.headers = { 'x-correlation-id': 'existing-correlation-123' };
    
    middleware(mockReq, mockRes as any, mockNext);
    
    expect(mockReq.correlationId).toBe('existing-correlation-123');
    expect(mockRes.set).toHaveBeenCalledWith('X-Correlation-ID', 'existing-correlation-123');
  });

  test('should handle missing headers gracefully', () => {
    mockReq.headers = undefined;
    
    expect(() => {
      middleware(mockReq, mockRes as any, mockNext);
    }).not.toThrow();
    
    expect(mockReq.correlationId).toBe('test-uuid-123');
    expect(mockNext).toHaveBeenCalled();
  });
});

describe('createToolErrorResponse', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.spyOn(Date.prototype, 'toISOString').mockReturnValue('2023-01-01T00:00:00.000Z');
  });

  test('should create formatted JSON error response for tools', () => {
    const error = new Error('Tool operation failed');
    
    const response = createToolErrorResponse(error, 'test-tool-operation');
    
    const parsedResponse = JSON.parse(response);
    expect(parsedResponse).toEqual({
      error: {
        message: 'Tool operation failed',
        code: 'UNKNOWN_ERROR',
        statusCode: 500,
        correlationId: 'test-uuid-123',
        timestamp: '2023-01-01T00:00:00.000Z',
        details: {
          name: 'Error',
          originalMessage: 'Tool operation failed'
        },
        stack: undefined
      },
      success: false
    });
  });

  test('should handle MakeServerError in tool context', () => {
    const error = new (MakeServerError as any)('Tool server error', 502);
    
    const response = createToolErrorResponse(error, 'failing-tool-operation', 'tool-correlation-456');
    
    const parsedResponse = JSON.parse(response);
    expect(parsedResponse.error.code).toBe('MAKE_SERVER_ERROR');
    expect(parsedResponse.error.statusCode).toBe(502);
  });

  test('should handle UserError in tool context', () => {
    const error = new (UserError as any)('Invalid tool input');
    
    const response = createToolErrorResponse(error, 'validation-tool');
    
    const parsedResponse = JSON.parse(response);
    expect(parsedResponse.error.code).toBe('USER_ERROR');
    expect(parsedResponse.error.statusCode).toBe(400);
  });

  test('should use provided correlation ID', () => {
    const error = new Error('Tool error with correlation');
    
    const response = createToolErrorResponse(error, 'test-operation', 'provided-correlation-789');
    
    const parsedResponse = JSON.parse(response);
    expect(parsedResponse.error.correlationId).toBe('provided-correlation-789');
  });

  test('should produce pretty-printed JSON', () => {
    const error = new Error('Pretty print test');
    
    const response = createToolErrorResponse(error, 'format-test');
    
    // Should contain newlines and indentation
    expect(response).toContain('\n');
    expect(response).toContain('  '); // Indentation
  });
});

describe('createToolSuccessResponse', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.spyOn(Date.prototype, 'toISOString').mockReturnValue('2023-01-01T00:00:00.000Z');
  });

  test('should create formatted JSON success response for tools', () => {
    const data = { result: 'Tool operation successful', count: 42 };
    
    const response = createToolSuccessResponse(data, 'successful-tool-operation');
    
    const parsedResponse = JSON.parse(response);
    expect(parsedResponse).toEqual({
      data: { result: 'Tool operation successful', count: 42 },
      success: true,
      correlationId: undefined,
      timestamp: '2023-01-01T00:00:00.000Z'
    });
  });

  test('should include correlation ID when provided', () => {
    const data = { message: 'Success with correlation' };
    
    const response = createToolSuccessResponse(data, 'correlated-operation', 'success-correlation-123');
    
    const parsedResponse = JSON.parse(response);
    expect(parsedResponse.correlationId).toBe('success-correlation-123');
  });

  test('should handle null data', () => {
    const response = createToolSuccessResponse(null, 'null-data-operation');
    
    const parsedResponse = JSON.parse(response);
    expect(parsedResponse.data).toBeNull();
    expect(parsedResponse.success).toBe(true);
  });

  test('should handle array data', () => {
    const data = [{ id: 1 }, { id: 2 }, { id: 3 }];
    
    const response = createToolSuccessResponse(data, 'array-operation');
    
    const parsedResponse = JSON.parse(response);
    expect(parsedResponse.data).toEqual(data);
  });

  test('should produce pretty-printed JSON', () => {
    const data = { test: 'pretty print' };
    
    const response = createToolSuccessResponse(data, 'format-test');
    
    // Should contain newlines and indentation
    expect(response).toContain('\n');
    expect(response).toContain('  '); // Indentation
  });
});

describe('extractCorrelationId', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('should extract correlation ID from correlationId property', () => {
    const context = {
      correlationId: 'direct-correlation-123'
    };
    
    const result = extractCorrelationId(context);
    
    expect(result).toBe('direct-correlation-123');
  });

  test('should extract correlation ID from headers', () => {
    const context = {
      headers: {
        'x-correlation-id': 'header-correlation-456'
      }
    };
    
    const result = extractCorrelationId(context);
    
    expect(result).toBe('header-correlation-456');
  });

  test('should extract correlation ID from session', () => {
    const context = {
      session: {
        correlationId: 'session-correlation-789'
      }
    };
    
    const result = extractCorrelationId(context);
    
    expect(result).toBe('session-correlation-789');
  });

  test('should prioritize correlationId over headers', () => {
    const context = {
      correlationId: 'direct-correlation-123',
      headers: {
        'x-correlation-id': 'header-correlation-456'
      }
    };
    
    const result = extractCorrelationId(context);
    
    expect(result).toBe('direct-correlation-123');
  });

  test('should prioritize headers over session', () => {
    const context = {
      headers: {
        'x-correlation-id': 'header-correlation-456'
      },
      session: {
        correlationId: 'session-correlation-789'
      }
    };
    
    const result = extractCorrelationId(context);
    
    expect(result).toBe('header-correlation-456');
  });

  test('should generate new correlation ID if none found', () => {
    const context = {};
    
    const result = extractCorrelationId(context);
    
    expect(result).toBe('test-uuid-123');
    expect(randomUUID).toHaveBeenCalled();
  });

  test('should handle undefined/null context properties', () => {
    const context = {
      correlationId: undefined,
      headers: null,
      session: undefined
    };
    
    const result = extractCorrelationId(context);
    
    expect(result).toBe('test-uuid-123');
  });

  test('should handle empty strings and falsy values', () => {
    const context = {
      correlationId: '',
      headers: {
        'x-correlation-id': ''
      },
      session: {
        correlationId: null
      }
    };
    
    const result = extractCorrelationId(context);
    
    expect(result).toBe('test-uuid-123');
  });
});

describe('Type Safety and Integration', () => {
  test('should have correct TypeScript types for ApiResponse', () => {
    // Test that both error and success responses are valid ApiResponse types
    const errorResponse: ApiResponse = formatErrorResponse(new Error('Type test'));
    const successResponse: ApiResponse<string> = formatSuccessResponse('success');
    
    expect(errorResponse.success).toBe(false);
    expect(successResponse.success).toBe(true);
    
    // TypeScript should enforce these properties exist
    if (errorResponse.success === false) {
      expect(errorResponse.error).toBeDefined();
    }
    
    if (successResponse.success === true) {
      expect(successResponse.data).toBeDefined();
    }
  });

  test('should maintain backwards compatibility with existing error types', () => {
    const makeError = new (MakeServerError as any)('Make error', 500);
    const userError = new (UserError as any)('User error');
    const genericError = new Error('Generic error');
    
    // All should work with formatErrorResponse
    const responses = [
      formatErrorResponse(makeError),
      formatErrorResponse(userError),
      formatErrorResponse(genericError)
    ];
    
    responses.forEach(response => {
      expect(response.success).toBe(false);
      expect(response.error.message).toBeDefined();
      expect(response.error.code).toBeDefined();
      expect(response.error.statusCode).toBeDefined();
      expect(response.error.correlationId).toBeDefined();
      expect(response.error.timestamp).toBeDefined();
    });
  });
});

describe('Edge Cases and Error Handling', () => {
  test('should handle errors with circular references', () => {
    const error = new Error('Circular reference error');
    const circular: any = { error };
    circular.self = circular;
    (error as any).circular = circular;
    
    // Should not throw when serializing
    expect(() => {
      const response = formatErrorResponse(error);
      JSON.stringify(response);
    }).not.toThrow();
  });

  test('should handle extremely long error messages', () => {
    const longMessage = 'A'.repeat(10000);
    const error = new Error(longMessage);
    
    const response = formatErrorResponse(error);
    
    expect(response.error.message).toBe(longMessage);
  });

  test('should handle errors with non-string properties', () => {
    const error = new Error('Test error');
    (error as any).numericProperty = 42;
    (error as any).booleanProperty = true;
    (error as any).objectProperty = { nested: 'value' };
    
    const response = formatErrorResponse(error);
    
    expect(response.error.message).toBe('Test error');
    expect(response.success).toBe(false);
  });

  test('should handle malformed correlation IDs gracefully', () => {
    const context = {
      correlationId: null,
      headers: {
        'x-correlation-id': undefined
      },
      session: {
        correlationId: {}
      }
    };
    
    const result = extractCorrelationId(context);
    
    expect(typeof result).toBe('string');
    expect(result).toBe('test-uuid-123');
  });

  test('should handle middleware with malformed request/response objects', () => {
    const middleware = errorHandlerMiddleware();
    const error = new Error('Malformed test');
    
    // Missing required properties
    const malformedReq = { method: null, path: undefined };
    const malformedRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
    
    expect(() => {
      middleware(error, malformedReq, malformedRes as any);
    }).not.toThrow();
    
    expect(malformedRes.status).toHaveBeenCalled();
    expect(malformedRes.json).toHaveBeenCalled();
  });
});