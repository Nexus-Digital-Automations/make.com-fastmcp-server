"use strict";
/**
 * Enhanced error handling system for Make.com FastMCP Server
 * Provides structured error handling with correlation IDs, context tracking, and recovery mechanisms
 * Now standardized around FastMCP UserError for full protocol compliance
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.TimeoutError = exports.ConfigurationError = exports.ExternalServiceError = exports.RateLimitError = exports.ConflictError = exports.NotFoundError = exports.AuthorizationError = exports.AuthenticationError = exports.ValidationError = exports.MakeServerError = exports.UserError = void 0;
exports.createValidationError = createValidationError;
exports.createAuthenticationError = createAuthenticationError;
exports.createAuthorizationError = createAuthorizationError;
exports.createNotFoundError = createNotFoundError;
exports.createConflictError = createConflictError;
exports.createRateLimitError = createRateLimitError;
exports.createExternalServiceError = createExternalServiceError;
exports.createConfigurationError = createConfigurationError;
exports.createTimeoutError = createTimeoutError;
exports.isOperationalError = isOperationalError;
exports.getErrorStatusCode = getErrorStatusCode;
exports.getErrorCode = getErrorCode;
exports.getErrorCorrelationId = getErrorCorrelationId;
exports.serializeError = serializeError;
exports.createValidationErrorForField = createValidationErrorForField;
exports.createNotFoundErrorForResource = createNotFoundErrorForResource;
exports.createConflictErrorForResource = createConflictErrorForResource;
exports.createExternalServiceErrorForOperation = createExternalServiceErrorForOperation;
exports.setupGlobalErrorHandlers = setupGlobalErrorHandlers;
const crypto_1 = require("crypto");
const fastmcp_1 = require("fastmcp");
// Re-export FastMCP UserError as the primary error class
var fastmcp_2 = require("fastmcp");
Object.defineProperty(exports, "UserError", { enumerable: true, get: function () { return fastmcp_2.UserError; } });
// Enhanced UserError wrapper with correlation IDs and context for Make.com server
class MakeServerError extends fastmcp_1.UserError {
    constructor(message, code = 'INTERNAL_ERROR', statusCode = 500, isOperational = true, details, context) {
        super(message);
        this.name = 'MakeServerError';
        this.code = code;
        this.statusCode = statusCode;
        this.isOperational = isOperational;
        this.details = details;
        this.correlationId = (context === null || context === void 0 ? void 0 : context.correlationId) || (0, crypto_1.randomUUID)();
        this.timestamp = new Date().toISOString();
        this.context = {
            correlationId: this.correlationId,
            ...context,
        };
        // Ensure proper prototype chain for instanceof checks
        Object.setPrototypeOf(this, MakeServerError.prototype);
        // Capture stack trace
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, MakeServerError);
        }
    }
    // Get structured error information
    toStructuredError() {
        return {
            name: this.name,
            message: this.message,
            code: this.code,
            statusCode: this.statusCode,
            correlationId: this.correlationId,
            timestamp: this.timestamp,
            context: this.context,
            details: this.details,
            stack: process.env.NODE_ENV === 'development' ? this.stack : undefined,
        };
    }
    // Create child error with inherited context
    createChildError(message, code, statusCode, details, additionalContext) {
        return new MakeServerError(message, code || this.code, statusCode || this.statusCode, this.isOperational, details, { ...this.context, ...additionalContext });
    }
}
exports.MakeServerError = MakeServerError;
// UserError factory functions to replace custom error classes
// These maintain the same interface but use UserError internally
function createValidationError(message, details, context) {
    const correlationId = (context === null || context === void 0 ? void 0 : context.correlationId) || (0, crypto_1.randomUUID)();
    const errorMessage = `[VALIDATION_ERROR:${correlationId}] ${message}`;
    const userError = new fastmcp_1.UserError(errorMessage);
    // Attach additional metadata
    userError.code = 'VALIDATION_ERROR';
    userError.statusCode = 400;
    userError.details = details;
    userError.correlationId = correlationId;
    userError.context = { correlationId, ...context };
    userError.timestamp = new Date().toISOString();
    userError.isOperational = true;
    return userError;
}
function createAuthenticationError(message = 'Authentication failed', details, context) {
    const correlationId = (context === null || context === void 0 ? void 0 : context.correlationId) || (0, crypto_1.randomUUID)();
    const errorMessage = `[AUTHENTICATION_ERROR:${correlationId}] ${message}`;
    const userError = new fastmcp_1.UserError(errorMessage);
    // Attach additional metadata
    userError.code = 'AUTHENTICATION_ERROR';
    userError.statusCode = 401;
    userError.details = details;
    userError.correlationId = correlationId;
    userError.context = { correlationId, ...context };
    userError.timestamp = new Date().toISOString();
    userError.isOperational = true;
    return userError;
}
function createAuthorizationError(message = 'Insufficient permissions', details, context) {
    const correlationId = (context === null || context === void 0 ? void 0 : context.correlationId) || (0, crypto_1.randomUUID)();
    const errorMessage = `[AUTHORIZATION_ERROR:${correlationId}] ${message}`;
    const userError = new fastmcp_1.UserError(errorMessage);
    // Attach additional metadata
    userError.code = 'AUTHORIZATION_ERROR';
    userError.statusCode = 403;
    userError.details = details;
    userError.correlationId = correlationId;
    userError.context = { correlationId, ...context };
    userError.timestamp = new Date().toISOString();
    userError.isOperational = true;
    return userError;
}
function createNotFoundError(resource = 'Resource', details, context) {
    const correlationId = (context === null || context === void 0 ? void 0 : context.correlationId) || (0, crypto_1.randomUUID)();
    const errorMessage = `[NOT_FOUND:${correlationId}] ${resource} not found`;
    const userError = new fastmcp_1.UserError(errorMessage);
    // Attach additional metadata
    userError.code = 'NOT_FOUND';
    userError.statusCode = 404;
    userError.details = details;
    userError.correlationId = correlationId;
    userError.context = { correlationId, ...context };
    userError.timestamp = new Date().toISOString();
    userError.isOperational = true;
    return userError;
}
function createConflictError(message, details, context) {
    const correlationId = (context === null || context === void 0 ? void 0 : context.correlationId) || (0, crypto_1.randomUUID)();
    const errorMessage = `[CONFLICT:${correlationId}] ${message}`;
    const userError = new fastmcp_1.UserError(errorMessage);
    // Attach additional metadata
    userError.code = 'CONFLICT';
    userError.statusCode = 409;
    userError.details = details;
    userError.correlationId = correlationId;
    userError.context = { correlationId, ...context };
    userError.timestamp = new Date().toISOString();
    userError.isOperational = true;
    return userError;
}
function createRateLimitError(message = 'Rate limit exceeded', retryAfter, details, context) {
    const correlationId = (context === null || context === void 0 ? void 0 : context.correlationId) || (0, crypto_1.randomUUID)();
    const errorMessage = `[RATE_LIMIT:${correlationId}] ${message}`;
    const userError = new fastmcp_1.UserError(errorMessage);
    // Attach additional metadata
    userError.code = 'RATE_LIMIT';
    userError.statusCode = 429;
    userError.retryAfter = retryAfter;
    userError.details = details;
    userError.correlationId = correlationId;
    userError.context = { correlationId, ...context };
    userError.timestamp = new Date().toISOString();
    userError.isOperational = true;
    return userError;
}
function createExternalServiceError(service, message, originalError, details, context) {
    const correlationId = (context === null || context === void 0 ? void 0 : context.correlationId) || (0, crypto_1.randomUUID)();
    const errorMessage = `[EXTERNAL_SERVICE_ERROR:${correlationId}] ${service} error: ${message}`;
    const userError = new fastmcp_1.UserError(errorMessage);
    // Attach additional metadata
    userError.code = 'EXTERNAL_SERVICE_ERROR';
    userError.statusCode = 502;
    userError.service = service;
    userError.originalError = originalError;
    userError.details = details;
    userError.correlationId = correlationId;
    userError.context = { correlationId, ...context };
    userError.timestamp = new Date().toISOString();
    userError.isOperational = true;
    return userError;
}
function createConfigurationError(message, details, context) {
    const correlationId = (context === null || context === void 0 ? void 0 : context.correlationId) || (0, crypto_1.randomUUID)();
    const errorMessage = `[CONFIGURATION_ERROR:${correlationId}] ${message}`;
    const userError = new fastmcp_1.UserError(errorMessage);
    // Attach additional metadata
    userError.code = 'CONFIGURATION_ERROR';
    userError.statusCode = 500;
    userError.isOperational = false;
    userError.details = details;
    userError.correlationId = correlationId;
    userError.context = { correlationId, ...context };
    userError.timestamp = new Date().toISOString();
    return userError;
}
function createTimeoutError(operation, timeoutMs, details, context) {
    const correlationId = (context === null || context === void 0 ? void 0 : context.correlationId) || (0, crypto_1.randomUUID)();
    const errorMessage = `[TIMEOUT:${correlationId}] Operation '${operation}' timed out after ${timeoutMs}ms`;
    const userError = new fastmcp_1.UserError(errorMessage);
    // Attach additional metadata
    userError.code = 'TIMEOUT';
    userError.statusCode = 408;
    userError.operation = operation;
    userError.timeoutMs = timeoutMs;
    userError.details = details;
    userError.correlationId = correlationId;
    userError.context = { correlationId, ...context };
    userError.timestamp = new Date().toISOString();
    userError.isOperational = true;
    return userError;
}
// Legacy class exports (deprecated but maintained for backward compatibility)
class ValidationError extends fastmcp_1.UserError {
    constructor(message, details, context) {
        const userError = createValidationError(message, details, context);
        super(userError.message);
        Object.assign(this, userError);
        this.name = 'ValidationError';
    }
}
exports.ValidationError = ValidationError;
class AuthenticationError extends fastmcp_1.UserError {
    constructor(message = 'Authentication failed', details, context) {
        const userError = createAuthenticationError(message, details, context);
        super(userError.message);
        Object.assign(this, userError);
        this.name = 'AuthenticationError';
    }
}
exports.AuthenticationError = AuthenticationError;
class AuthorizationError extends fastmcp_1.UserError {
    constructor(message = 'Insufficient permissions', details, context) {
        const userError = createAuthorizationError(message, details, context);
        super(userError.message);
        Object.assign(this, userError);
        this.name = 'AuthorizationError';
    }
}
exports.AuthorizationError = AuthorizationError;
class NotFoundError extends fastmcp_1.UserError {
    constructor(resource = 'Resource', details, context) {
        const userError = createNotFoundError(resource, details, context);
        super(userError.message);
        Object.assign(this, userError);
        this.name = 'NotFoundError';
    }
}
exports.NotFoundError = NotFoundError;
class ConflictError extends fastmcp_1.UserError {
    constructor(message, details, context) {
        const userError = createConflictError(message, details, context);
        super(userError.message);
        Object.assign(this, userError);
        this.name = 'ConflictError';
    }
}
exports.ConflictError = ConflictError;
class RateLimitError extends fastmcp_1.UserError {
    constructor(message = 'Rate limit exceeded', retryAfter, details, context) {
        const userError = createRateLimitError(message, retryAfter, details, context);
        super(userError.message);
        Object.assign(this, userError);
        this.name = 'RateLimitError';
        this.retryAfter = retryAfter;
    }
}
exports.RateLimitError = RateLimitError;
class ExternalServiceError extends fastmcp_1.UserError {
    constructor(service, message, originalError, details, context) {
        const userError = createExternalServiceError(service, message, originalError, details, context);
        super(userError.message);
        Object.assign(this, userError);
        this.name = 'ExternalServiceError';
        this.service = service;
        this.originalError = originalError;
    }
}
exports.ExternalServiceError = ExternalServiceError;
class ConfigurationError extends fastmcp_1.UserError {
    constructor(message, details, context) {
        const userError = createConfigurationError(message, details, context);
        super(userError.message);
        Object.assign(this, userError);
        this.name = 'ConfigurationError';
    }
}
exports.ConfigurationError = ConfigurationError;
class TimeoutError extends fastmcp_1.UserError {
    constructor(operation, timeoutMs, details, context) {
        const userError = createTimeoutError(operation, timeoutMs, details, context);
        super(userError.message);
        Object.assign(this, userError);
        this.name = 'TimeoutError';
        this.operation = operation;
        this.timeoutMs = timeoutMs;
    }
}
exports.TimeoutError = TimeoutError;
// Error handling utilities compatible with UserError
function isOperationalError(error) {
    // Check for MakeServerError first
    if (error instanceof MakeServerError) {
        return error.isOperational;
    }
    // Check for UserError with metadata
    if (error instanceof fastmcp_1.UserError && 'isOperational' in error) {
        return error.isOperational || true;
    }
    // Default to operational for UserError (client-facing errors)
    if (error instanceof fastmcp_1.UserError) {
        return true;
    }
    return false;
}
function getErrorStatusCode(error) {
    // Check for MakeServerError first
    if (error instanceof MakeServerError) {
        return error.statusCode;
    }
    // Check for UserError with metadata
    if (error instanceof fastmcp_1.UserError && 'statusCode' in error) {
        return error.statusCode;
    }
    // Default status code for UserError is 400 (bad request)
    if (error instanceof fastmcp_1.UserError) {
        return 400;
    }
    return 500;
}
function getErrorCode(error) {
    // Check for MakeServerError first
    if (error instanceof MakeServerError) {
        return error.code;
    }
    // Check for UserError with metadata
    if (error instanceof fastmcp_1.UserError && 'code' in error) {
        return error.code;
    }
    // Extract code from UserError message if formatted with correlation ID
    if (error instanceof fastmcp_1.UserError) {
        const match = error.message.match(/^\[([^:]+):[^\]]+\]/);
        if (match) {
            return match[1];
        }
        return 'USER_ERROR';
    }
    return 'UNKNOWN_ERROR';
}
function getErrorCorrelationId(error) {
    // Check for MakeServerError first
    if (error instanceof MakeServerError) {
        return error.correlationId;
    }
    // Check for UserError with metadata
    if (error instanceof fastmcp_1.UserError && 'correlationId' in error) {
        return error.correlationId;
    }
    // Extract correlation ID from UserError message if formatted
    if (error instanceof fastmcp_1.UserError) {
        const match = error.message.match(/^\[[^:]+:([^\]]+)\]/);
        if (match) {
            return match[1];
        }
    }
    return undefined;
}
function serializeError(error) {
    const serialized = {
        name: error.name,
        message: error.message,
        code: getErrorCode(error),
        statusCode: getErrorStatusCode(error),
        correlationId: getErrorCorrelationId(error),
        details: 'details' in error ? error.details : undefined,
        stack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
    };
    return serialized;
}
// Enhanced error factory functions with UserError compliance
function createValidationErrorForField(field, value, expected) {
    return createValidationError(`Invalid ${field}: expected ${expected}, got ${typeof value}`, {
        field,
        value,
        expected,
    });
}
function createNotFoundErrorForResource(resource, id) {
    return createNotFoundError(`${resource} with ID ${id}`, { resource, id });
}
function createConflictErrorForResource(resource, field, value) {
    return createConflictError(`${resource} with ${field} '${value}' already exists`, {
        resource,
        field,
        value,
    });
}
function createExternalServiceErrorForOperation(service, operation, originalError) {
    return createExternalServiceError(service, `Failed to ${operation}`, originalError, { operation, originalMessage: originalError === null || originalError === void 0 ? void 0 : originalError.message });
}
// Error handler for unhandled promise rejections and uncaught exceptions
function setupGlobalErrorHandlers() {
    process.on('unhandledRejection', (reason, promise) => {
        console.error('Unhandled Rejection at:', promise, 'reason:', reason);
        // Log error but don't exit in production
        if (process.env.NODE_ENV !== 'production') {
            process.exit(1);
        }
    });
    process.on('uncaughtException', (error) => {
        console.error('Uncaught Exception:', error);
        // Always exit on uncaught exception
        process.exit(1);
    });
}
