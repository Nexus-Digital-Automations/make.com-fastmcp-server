/**
 * Comprehensive Unit Tests for Logger Module
 * 
 * Tests structured logging functionality, log levels, context management,
 * child loggers, ID generation, performance logging, and file-based output.
 * Covers singleton behavior, filtering, file system integration, and error handling.
 */

import { jest } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';

// Set up global mock variables that will be hoisted
const mockGetLogLevel = jest.fn();
const mockGetLogsDirectory = jest.fn();

// Mock filesystem first
jest.mock('fs');
const mockFs = fs as jest.Mocked<typeof fs>;

// Mock config module with properly hoisted factory
jest.mock('../../../src/lib/config.js', () => {
  return {
    __esModule: true,
    default: {
      getLogLevel: () => 'info',
      getConfig: jest.fn(),
      getMakeConfig: jest.fn(),
      isAuthEnabled: jest.fn().mockReturnValue(false),
      getAuthSecret: jest.fn(),
      getRateLimitConfig: jest.fn(),
      isDevelopment: jest.fn().mockReturnValue(false),
      isProduction: jest.fn().mockReturnValue(false),
      isTest: jest.fn().mockReturnValue(true),
      validateEnvironment: jest.fn(),
      getConfigurationReport: jest.fn()
    },
    configManager: {
      getLogLevel: () => 'info',
      getConfig: jest.fn(),
      getMakeConfig: jest.fn(),
      isAuthEnabled: jest.fn().mockReturnValue(false),
      getAuthSecret: jest.fn(),
      getRateLimitConfig: jest.fn(),
      isDevelopment: jest.fn().mockReturnValue(false),
      isProduction: jest.fn().mockReturnValue(false),
      isTest: jest.fn().mockReturnValue(true),
      validateEnvironment: jest.fn(),
      getConfigurationReport: jest.fn()
    },
    ConfigManager: {
      getInstance: jest.fn(() => ({
        getLogLevel: () => 'info',
        getConfig: jest.fn(),
        getMakeConfig: jest.fn(),
        isAuthEnabled: jest.fn().mockReturnValue(false),
        getAuthSecret: jest.fn(),
        getRateLimitConfig: jest.fn(),
        isDevelopment: jest.fn().mockReturnValue(false),
        isProduction: jest.fn().mockReturnValue(false),
        isTest: jest.fn().mockReturnValue(true),
        validateEnvironment: jest.fn(),
        getConfigurationReport: jest.fn()
      }))
    }
  };
});

// Mock path resolver 
jest.mock('../../../src/utils/path-resolver.js', () => ({
  getLogsDirectory: () => '/mock/logs'
}));

// Now import logger after mocks are set up
import { logger, Logger, type LogLevel, type LogContext, type LogEntry } from '../../../src/lib/logger.js';

describe('Logger', () => {
  let stderrWriteSpy: jest.SpyInstance;

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Mock filesystem operations
    mockFs.existsSync.mockReturnValue(true);
    mockFs.mkdirSync.mockImplementation(() => undefined);
    mockFs.appendFileSync.mockImplementation(() => undefined);
    
    // Mock stderr for error logging
    stderrWriteSpy = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
    
    // Mock Date.now and toISOString for consistent timestamps
    jest.spyOn(Date, 'now').mockReturnValue(1609459200000); // Jan 1, 2021 00:00:00 UTC
    jest.spyOn(Date.prototype, 'toISOString').mockReturnValue('2023-01-01T00:00:00.000Z');
    
    // Mock Math.random for consistent ID generation
    jest.spyOn(Math, 'random').mockReturnValue(0.5);
    
    // Reset logger to clean state for each test
    logger.setLogLevel('info');
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Singleton Pattern', () => {
    test('should return the same instance', () => {
      const instance1 = Logger.getInstance();
      const instance2 = Logger.getInstance();
      
      expect(instance1).toBe(instance2);
      expect(instance1).toBe(logger);
    });

    test('should maintain state across getInstance calls', () => {
      const instance1 = Logger.getInstance();
      instance1.setLogLevel('error');
      
      const instance2 = Logger.getInstance();
      expect(instance2.getLogLevel()).toBe('error');
    });

    test('should prevent direct instantiation', () => {
      // Logger constructor is private, so we test through getInstance
      const instance1 = Logger.getInstance();
      const instance2 = Logger.getInstance();
      
      // Both should be the same object reference
      expect(Object.is(instance1, instance2)).toBe(true);
    });
  });

  describe('Log Level Management', () => {
    test('should initialize with config log level', () => {
      expect(logger.getLogLevel()).toBe('info');
    });

    test('should allow setting log level', () => {
      logger.setLogLevel('debug');
      expect(logger.getLogLevel()).toBe('debug');
      
      logger.setLogLevel('error');
      expect(logger.getLogLevel()).toBe('error');
    });

    test('should filter logs based on level', () => {
      logger.setLogLevel('warn');
      
      logger.debug('Debug message');
      logger.info('Info message');
      logger.warn('Warning message');
      logger.error('Error message');
      
      // Only warn and error should create file writes
      expect(mockFs.appendFileSync).toHaveBeenCalledTimes(2);
      // Only errors should write to stderr
      expect(stderrWriteSpy).toHaveBeenCalledTimes(1);
    });

    test('should log all levels when set to debug', () => {
      logger.setLogLevel('debug');
      
      logger.debug('Debug message');
      logger.info('Info message');
      logger.warn('Warning message');
      logger.error('Error message');
      
      // All 4 levels should write to file
      expect(mockFs.appendFileSync).toHaveBeenCalledTimes(4);
      // Only error should write to stderr
      expect(stderrWriteSpy).toHaveBeenCalledTimes(1);
    });

    test('should only log errors when set to error level', () => {
      logger.setLogLevel('error');
      
      logger.debug('Debug message');
      logger.info('Info message');
      logger.warn('Warning message');
      logger.error('Error message');
      
      // Only error should write to file
      expect(mockFs.appendFileSync).toHaveBeenCalledTimes(1);
      // Only error should write to stderr
      expect(stderrWriteSpy).toHaveBeenCalledTimes(1);
    });
  });

  describe('Basic Logging Methods', () => {
    beforeEach(() => {
      logger.setLogLevel('debug');
    });

    test('should log debug messages to file', () => {
      logger.debug('Debug test message');
      
      expect(mockFs.appendFileSync).toHaveBeenCalledWith(
        '/mock/logs/server.log',
        expect.stringContaining('[2023-01-01T00:00:00.000Z] DEBUG: Debug test message')
      );
      expect(stderrWriteSpy).not.toHaveBeenCalled();
    });

    test('should log info messages to file', () => {
      logger.info('Info test message');
      
      expect(mockFs.appendFileSync).toHaveBeenCalledWith(
        '/mock/logs/server.log',
        expect.stringContaining('[2023-01-01T00:00:00.000Z] INFO: Info test message')
      );
      expect(stderrWriteSpy).not.toHaveBeenCalled();
    });

    test('should log warning messages to file only', () => {
      logger.warn('Warning test message');
      
      expect(mockFs.appendFileSync).toHaveBeenCalledWith(
        '/mock/logs/server.log',
        expect.stringContaining('[2023-01-01T00:00:00.000Z] WARN: Warning test message')
      );
      expect(stderrWriteSpy).not.toHaveBeenCalled();
    });

    test('should log error messages to both file and stderr', () => {
      logger.error('Error test message');
      
      const expectedLog = expect.stringContaining('[2023-01-01T00:00:00.000Z] ERROR: Error test message');
      expect(mockFs.appendFileSync).toHaveBeenCalledWith('/mock/logs/server.log', expectedLog);
      expect(stderrWriteSpy).toHaveBeenCalledWith(expectedLog);
    });
  });

  describe('Data and Context Logging', () => {
    beforeEach(() => {
      logger.setLogLevel('debug');
    });

    test('should log with data object', () => {
      const data = { userId: '123', action: 'login' };
      
      logger.info('User action', data);
      
      expect(mockFs.appendFileSync).toHaveBeenCalledWith(
        '/mock/logs/server.log',
        expect.stringContaining('User action | Data: {"userId":"123","action":"login"}')
      );
    });

    test('should log with context', () => {
      const context: LogContext = {
        component: 'auth',
        operation: 'login',
        correlationId: 'corr-123'
      };
      
      logger.info('Login attempt', undefined, context);
      
      const logCall = mockFs.appendFileSync.mock.calls[0][1] as string;
      expect(logCall).toContain('[corr:corr-123]');
      expect(logCall).toContain('[auth]');
      expect(logCall).toContain('[login]');
    });

    test('should log with both data and context', () => {
      const data = { username: 'testuser' };
      const context: LogContext = {
        component: 'auth',
        sessionId: 'sess-456',
        userId: 'user-789'
      };
      
      logger.info('Login successful', data, context);
      
      const logCall = mockFs.appendFileSync.mock.calls[0][1] as string;
      expect(logCall).toContain('[auth]');
      expect(logCall).toContain('[session:sess-456]');
      expect(logCall).toContain('[user:user-789]');
      expect(logCall).toContain('| Data: {"username":"testuser"}');
    });

    test('should handle empty data and context gracefully', () => {
      logger.info('Simple message', {}, {});
      
      expect(mockFs.appendFileSync).toHaveBeenCalledWith(
        '/mock/logs/server.log',
        '[2023-01-01T00:00:00.000Z] INFO: Simple message\n'
      );
    });
  });

  describe('ID Generation', () => {
    test('should generate correlation ID with correct format', () => {
      const correlationId = logger.generateCorrelationId();
      
      expect(correlationId).toMatch(/^corr_\d+_[a-z0-9]+$/);
      expect(correlationId).toContain('corr_1609459200000_');
    });

    test('should generate trace ID with correct format', () => {
      const traceId = logger.generateTraceId();
      
      expect(traceId).toMatch(/^trace_\d+_[a-z0-9]+$/);
      expect(traceId).toContain('trace_1609459200000_');
    });

    test('should generate span ID with correct format', () => {
      const spanId = logger.generateSpanId();
      
      expect(spanId).toMatch(/^span_[a-z0-9]+$/);
    });

    test('should generate request ID with correct format', () => {
      const requestId = logger.generateRequestId();
      
      expect(requestId).toMatch(/^req_\d+_[a-z0-9]+$/);
      expect(requestId).toContain('req_1609459200000_');
    });
  });

  describe('Correlation Logging', () => {
    beforeEach(() => {
      logger.setLogLevel('debug');
    });

    test('should log with auto-generated correlation ID', () => {
      const correlationId = logger.logWithCorrelation('info', 'Test message');
      
      expect(correlationId).toMatch(/^corr_\d+_[a-z0-9]+$/);
      expect(mockFs.appendFileSync).toHaveBeenCalledWith(
        '/mock/logs/server.log',
        expect.stringContaining(`[corr:${correlationId}]`)
      );
    });

    test('should use provided correlation ID', () => {
      const providedId = 'custom-correlation-123';
      const context: LogContext = { correlationId: providedId };
      
      const returnedId = logger.logWithCorrelation('info', 'Test message', undefined, context);
      
      expect(returnedId).toBe(providedId);
      expect(mockFs.appendFileSync).toHaveBeenCalledWith(
        '/mock/logs/server.log',
        expect.stringContaining('[corr:custom-correlation-123]')
      );
    });
  });

  describe('Performance Logging', () => {
    beforeEach(() => {
      logger.setLogLevel('debug');
    });

    test('should log operation duration', () => {
      const startTime = Date.now() - 1500; // 1.5 seconds ago
      
      logger.logDuration('info', 'database-query', startTime);
      
      const logCall = mockFs.appendFileSync.mock.calls[0][1] as string;
      expect(logCall).toContain('Operation completed: database-query');
      expect(logCall).toContain('[1.500s]');
      expect(logCall).toContain('| Data: {"duration":1.5}');
    });

    test('should handle zero duration', () => {
      const startTime = Date.now();
      
      logger.logDuration('info', 'instant-operation', startTime);
      
      const logCall = mockFs.appendFileSync.mock.calls[0][1] as string;
      expect(logCall).toContain('[0.000s]');
    });
  });

  describe('File System Integration', () => {
    beforeEach(() => {
      logger.setLogLevel('debug');
    });

    test('should create logs directory if it does not exist', () => {
      mockFs.existsSync.mockReturnValue(false);
      
      logger.info('Test message');
      
      expect(mockFs.mkdirSync).toHaveBeenCalledWith('/mock/logs', { recursive: true });
      expect(mockFs.appendFileSync).toHaveBeenCalledWith(
        '/mock/logs/server.log',
        expect.stringContaining('Test message')
      );
    });

    test('should handle file write errors gracefully', () => {
      mockFs.appendFileSync.mockImplementation(() => {
        throw new Error('File write failed');
      });
      
      // Should not throw when file write fails
      expect(() => {
        logger.info('Test message');
      }).not.toThrow();
      
      // Should write fallback error to stderr
      expect(stderrWriteSpy).toHaveBeenCalledWith(
        expect.stringContaining('LOGGER_ERROR: Error: File write failed')
      );
    });

    test('should write to correct log file path', () => {
      logger.info('Test message');
      
      expect(mockFs.appendFileSync).toHaveBeenCalledWith(
        '/mock/logs/server.log',
        expect.any(String)
      );
    });

    test('should append newline to log entries', () => {
      logger.info('Test message');
      
      expect(mockFs.appendFileSync).toHaveBeenCalledWith(
        '/mock/logs/server.log',
        expect.stringMatching(/\n$/)
      );
    });

    test('should only write errors to stderr', () => {
      logger.debug('Debug message');
      logger.info('Info message');
      logger.warn('Warning message');
      logger.error('Error message');
      
      // Only error should write to stderr
      expect(stderrWriteSpy).toHaveBeenCalledTimes(1);
      expect(stderrWriteSpy).toHaveBeenCalledWith(
        expect.stringContaining('ERROR: Error message')
      );
    });
  });

  describe('Child Logger Creation', () => {
    beforeEach(() => {
      logger.setLogLevel('debug');
    });

    test('should create child logger with inherited context', () => {
      const childContext: LogContext = {
        component: 'database',
        operation: 'query'
      };
      
      const childLogger = logger.child(childContext);
      childLogger.info('Database query');
      
      const logCall = mockFs.appendFileSync.mock.calls[0][1] as string;
      expect(logCall).toContain('[database]');
      expect(logCall).toContain('[query]');
    });
  });

  describe('Edge Cases and Error Handling', () => {
    beforeEach(() => {
      logger.setLogLevel('debug');
    });

    test('should handle circular references in data', () => {
      const circularData: any = { name: 'test' };
      circularData.self = circularData;
      
      // Should not throw when logging (JSON.stringify will handle circular refs)
      expect(() => {
        logger.info('Circular data test', circularData);
      }).not.toThrow();
      
      expect(mockFs.appendFileSync).toHaveBeenCalled();
    });

    test('should handle undefined and null values', () => {
      logger.info('Undefined test', undefined, undefined);
      logger.info('Null test', null as any, null as any);
      
      expect(mockFs.appendFileSync).toHaveBeenCalledTimes(2);
    });

    test('should handle empty strings', () => {
      logger.info('');
      
      expect(mockFs.appendFileSync).toHaveBeenCalledWith(
        '/mock/logs/server.log',
        '[2023-01-01T00:00:00.000Z] INFO: \n'
      );
    });

    test('should handle very long messages', () => {
      const longMessage = 'A'.repeat(10000);
      
      logger.info(longMessage);
      
      expect(mockFs.appendFileSync).toHaveBeenCalledWith(
        '/mock/logs/server.log',
        expect.stringContaining(longMessage)
      );
    });
  });

  describe('Performance Considerations', () => {
    test('should not format logs when level is filtered', () => {
      logger.setLogLevel('error');
      
      const formatSpy = jest.spyOn(Date.prototype, 'toISOString');
      
      logger.debug('Filtered debug message');
      logger.info('Filtered info message');
      
      // toISOString should not be called for filtered logs
      expect(formatSpy).not.toHaveBeenCalled();
      expect(mockFs.appendFileSync).not.toHaveBeenCalled();
    });
  });
});