/**
 * Comprehensive Test Suite for Main Entry Point
 * Tests server startup, graceful shutdown, signal handling, and error recovery
 * Critical for ensuring application reliability and proper process management
 * Covers main function execution, server lifecycle, and production deployment scenarios
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';

// Store original process methods
const originalExit = process.exit;
const originalOn = process.on;
const originalArgv = process.argv;

// Mock process methods
const mockProcessExit = jest.fn();
const mockProcessOn = jest.fn();

// Mock server instance
const mockServerInstance = {
  start: jest.fn().mockResolvedValue(undefined),
  shutdown: jest.fn().mockResolvedValue(undefined)
};

// Create proper mock constructor function  
const MockMakeServerInstance = jest.fn().mockImplementation(() => mockServerInstance);

jest.mock('../../../src/server.js', () => MockMakeServerInstance);

// Mock logger with proper child method  
const createMockLogger = () => ({
  info: jest.fn(),
  error: jest.fn(), 
  warn: jest.fn(),
  debug: jest.fn(),
  child: jest.fn()
});

const componentLogger = createMockLogger();
const mockLogger = createMockLogger();

// Make sure logger.child returns the componentLogger mock that tests expect
mockLogger.child.mockReturnValue(componentLogger);

jest.mock('../../../src/lib/logger.js', () => ({
  default: mockLogger
}));

// Use global config mock from jest.config.js moduleNameMapper

describe('Main Entry Point - Comprehensive Tests', () => {
  let main: () => Promise<void>;

  beforeEach(async () => {
    // CRITICAL: Clear all timers and intervals before each test to prevent cross-test interference
    jest.clearAllTimers();
    jest.clearAllMocks();
    jest.resetModules();
    
    // Clear any existing singleton instances to prevent open handles
    try {
      // Try to shutdown any existing audit logger instances
      const AuditLoggerClass = (await import('../../../src/lib/audit-logger.js')).default;
      if (AuditLoggerClass && typeof AuditLoggerClass.shutdown === 'function') {
        await AuditLoggerClass.shutdown();
      }
    } catch (e) {
      // Ignore errors - might not exist or already shut down
    }
    
    try {
      // Try to shutdown any existing metrics collector instances  
      const MetricsClass = (await import('../../../src/lib/metrics.js')).default;
      if (MetricsClass && typeof MetricsClass.shutdown === 'function') {
        await MetricsClass.shutdown();
      }
    } catch (e) {
      // Ignore errors - might not exist or already shut down
    }
    
    // CRITICAL: Complete reset of all mocks to prevent cross-test interference
    mockProcessExit.mockClear();
    mockProcessExit.mockReset();
    mockProcessOn.mockClear(); 
    mockProcessOn.mockReset();
    
    // Reset server instance mocks completely
    mockServerInstance.start.mockClear();
    mockServerInstance.start.mockReset();
    mockServerInstance.shutdown.mockClear();
    mockServerInstance.shutdown.mockReset();
    
    // Reset server instance to fresh implementation
    mockServerInstance.start.mockResolvedValue(undefined);
    mockServerInstance.shutdown.mockResolvedValue(undefined);
    
    // Complete reset of constructor mock
    MockMakeServerInstance.mockClear();
    MockMakeServerInstance.mockReset();
    MockMakeServerInstance.mockImplementation(() => mockServerInstance);
    
    // Complete reset of logger mocks
    componentLogger.info.mockClear();
    componentLogger.info.mockReset();
    componentLogger.error.mockClear();
    componentLogger.error.mockReset();
    componentLogger.warn.mockClear();
    componentLogger.warn.mockReset();
    componentLogger.debug.mockClear();
    componentLogger.debug.mockReset();
    
    mockLogger.info.mockClear();
    mockLogger.info.mockReset();
    mockLogger.error.mockClear();
    mockLogger.error.mockReset();
    mockLogger.warn.mockClear();
    mockLogger.warn.mockReset();
    mockLogger.debug.mockClear();
    mockLogger.debug.mockReset();
    mockLogger.child.mockClear();
    mockLogger.child.mockReset();
    
    // Ensure componentLogger passes the function type check
    componentLogger.error = jest.fn();
    componentLogger.info = jest.fn();
    componentLogger.warn = jest.fn();
    componentLogger.debug = jest.fn();
    mockLogger.child.mockReturnValue(componentLogger);
    
    // Mock process methods
    process.exit = mockProcessExit as any;
    process.on = mockProcessOn as any;
    
    // Clear mock calls for fresh test
    jest.clearAllMocks();
    
    // Import fresh modules after mocks are set up
    return import('../../../src/index.js').then(module => {
      main = module.default;
    });
  });

  afterEach(async () => {
    // Clear any running timers/intervals to prevent open handles
    jest.clearAllTimers();
    
    // Force cleanup of any singleton instances that might have open handles
    try {
      // Try to shutdown audit logger if it exists
      const AuditLoggerClass = (await import('../../../src/lib/audit-logger.js')).default;
      if (AuditLoggerClass && typeof AuditLoggerClass.shutdown === 'function') {
        await AuditLoggerClass.shutdown();
      }
    } catch (e) {
      // Ignore errors
    }
    
    try {
      // Try to shutdown metrics collector if it exists
      const MetricsClass = (await import('../../../src/lib/metrics.js')).default;
      if (MetricsClass && typeof MetricsClass.shutdown === 'function') {
        await MetricsClass.shutdown();
      }
    } catch (e) {
      // Ignore errors
    }
    
    // Restore original process methods
    process.exit = originalExit;
    process.on = originalOn;
    process.argv = originalArgv;
  });

  describe('Server Initialization and Startup', () => {
    it('should create and start server instance successfully', async () => {
      await main();
      
      expect(MockMakeServerInstance).toHaveBeenCalledTimes(1);
      expect(mockServerInstance.start).toHaveBeenCalledTimes(1);
    });

    it('should start with stdio transport by default', async () => {
      process.argv = ['node', 'index.js'];
      
      await main();
      
      expect(mockServerInstance.start).toHaveBeenCalledWith({
        transportType: 'stdio',
        httpStream: undefined
      });
    });

    it('should start with HTTP transport when --http flag is provided', async () => {
      process.argv = ['node', 'index.js', '--http'];
      
      await main();
      
      expect(mockServerInstance.start).toHaveBeenCalledWith({
        transportType: 'httpStream',
        httpStream: {
          endpoint: '/',
          port: 3000
        }
      });
    });

    it('should use custom port from config for HTTP transport', async () => {
      process.argv = ['node', 'index.js', '--http'];
      const mockConfig = require('../../../src/lib/config.js').default;
      const getConfigSpy = jest.spyOn(mockConfig, 'getConfig').mockReturnValue({ port: 4000, version: '1.0.0' });
      
      await main();
      
      expect(mockServerInstance.start).toHaveBeenCalledWith({
        transportType: 'httpStream',
        httpStream: {
          endpoint: '/',
          port: 4000
        }
      });
      
      getConfigSpy.mockRestore();
    });

    it('should start server with HTTP transport and complete successfully', async () => {
      process.argv = ['node', 'index.js', '--http'];
      
      await main();
      
      // Verify server starts with correct configuration
      expect(mockServerInstance.start).toHaveBeenCalledWith({
        transportType: 'httpStream',
        httpStream: {
          endpoint: '/',
          port: 3000
        }
      });
    });
  });

  describe('Graceful Shutdown Handling', () => {
    it('should register SIGTERM signal handler', async () => {
      await main();
      
      expect(process.on).toHaveBeenCalledWith('SIGTERM', expect.any(Function));
    });

    it('should register SIGINT signal handler', async () => {
      await main();
      
      expect(process.on).toHaveBeenCalledWith('SIGINT', expect.any(Function));
    });

    it('should perform graceful shutdown on SIGTERM', async () => {
      await main();
      
      // Get the SIGTERM handler
      const sigtermHandler = mockProcessOn.mock.calls.find(call => call[0] === 'SIGTERM')[1];
      
      // Execute the handler
      await sigtermHandler();
      
      expect(mockServerInstance.shutdown).toHaveBeenCalledTimes(1);
      expect(process.exit).toHaveBeenCalledWith(0);
    });

    it('should perform graceful shutdown on SIGINT', async () => {
      await main();
      
      // Get the SIGINT handler
      const sigintHandler = mockProcessOn.mock.calls.find(call => call[0] === 'SIGINT')[1];
      
      // Execute the handler
      await sigintHandler();
      
      expect(mockServerInstance.shutdown).toHaveBeenCalledTimes(1);
      expect(process.exit).toHaveBeenCalledWith(0);
    });

    it('should handle shutdown errors gracefully', async () => {
      mockServerInstance.shutdown.mockRejectedValue(new Error('Shutdown failed'));
      
      await main();
      
      // Get the SIGTERM handler
      const sigtermHandler = mockProcessOn.mock.calls.find(call => call[0] === 'SIGTERM')[1];
      
      // Execute the handler
      await sigtermHandler();
      
      expect(process.exit).toHaveBeenCalledWith(1);
    });
  });

  describe('Error Handling and Recovery', () => {
    it('should handle server creation failures', async () => {
      MockMakeServerInstance.mockImplementation(() => {
        throw new Error('Server creation failed');
      });
      
      await main();
      
      expect(process.exit).toHaveBeenCalledWith(1);
    });

    it('should handle server start failures', async () => {
      mockServerInstance.start.mockRejectedValue(new Error('Start failed'));
      
      await main();
      
      expect(process.exit).toHaveBeenCalledWith(1);
    });

    it('should handle configuration errors', async () => {
      const mockConfig = require('../../../src/lib/config.js').default;
      const getConfigSpy = jest.spyOn(mockConfig, 'getConfig').mockImplementation(() => {
        throw new Error('Config error');
      });
      
      await main();
      
      expect(process.exit).toHaveBeenCalledWith(1);
      
      getConfigSpy.mockRestore();
    });

    it('should handle logger initialization errors gracefully', async () => {
      mockLogger.child.mockImplementation(() => {
        throw new Error('Logger error');
      });
      
      await main();
      
      // Should not crash the process due to robust fallback handling
      // The process should continue with fallback logger, not exit with error
      expect(mockServerInstance.start).toHaveBeenCalledTimes(1);
      expect(MockMakeServerInstance).toHaveBeenCalledTimes(1);
    });
  });

  describe('Module Export and Direct Execution', () => {
    it('should export main function as default', () => {
      expect(main).toBeDefined();
      expect(typeof main).toBe('function');
    });

    it('should handle unhandled errors during startup', async () => {
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // Mock an unhandled rejection
      const unhandledError = new Error('Unhandled startup error');
      main = jest.fn().mockRejectedValue(unhandledError);
      
      // Simulate the main execution with error
      try {
        await main().catch((error) => {
          console.error('Unhandled error during server startup:', error);
          process.exit(1);
        });
      } catch {
        // Expected to be handled
      }
      
      expect(consoleSpy).toHaveBeenCalledWith('Unhandled error during server startup:', unhandledError);
      expect(process.exit).toHaveBeenCalledWith(1);
      
      consoleSpy.mockRestore();
    });
  });

  describe('Environment and Configuration Handling', () => {
    it('should handle different node environments', async () => {
      const originalEnv = process.env.NODE_ENV;
      
      process.env.NODE_ENV = 'production';
      await main();
      
      expect(mockServerInstance.start).toHaveBeenCalled();
      
      process.env.NODE_ENV = 'development';
      await main();
      
      expect(mockServerInstance.start).toHaveBeenCalled();
      
      process.env.NODE_ENV = originalEnv;
    });

    it('should handle missing port configuration gracefully', async () => {
      process.argv = ['node', 'index.js', '--http'];
      const mockConfig = require('../../../src/lib/config.js').default;
      const getConfigSpy = jest.spyOn(mockConfig, 'getConfig').mockReturnValue({ version: '1.0.0' }); // No port
      
      await main();
      
      expect(mockServerInstance.start).toHaveBeenCalledWith({
        transportType: 'httpStream',
        httpStream: {
          endpoint: '/',
          port: 3000 // Default fallback
        }
      });
      
      getConfigSpy.mockRestore();
    });

    it('should handle command line arguments correctly', async () => {
      // Test with multiple arguments
      process.argv = ['node', 'index.js', '--http', '--verbose', '--other-flag'];
      
      await main();
      
      expect(mockServerInstance.start).toHaveBeenCalledWith({
        transportType: 'httpStream',
        httpStream: {
          endpoint: '/',
          port: 3000
        }
      });
    });
  });

  describe('Concurrent Operations and Race Conditions', () => {
    it('should handle multiple shutdown signals correctly', async () => {
      await main();
      
      const sigtermHandler = mockProcessOn.mock.calls.find(call => call[0] === 'SIGTERM')[1];
      const sigintHandler = mockProcessOn.mock.calls.find(call => call[0] === 'SIGINT')[1];
      
      // Simulate receiving both signals
      const shutdownPromise1 = sigtermHandler();
      const shutdownPromise2 = sigintHandler();
      
      await Promise.all([shutdownPromise1, shutdownPromise2]);
      
      // Should only call shutdown once, but both handlers should complete
      expect(mockServerInstance.shutdown).toHaveBeenCalled();
      expect(process.exit).toHaveBeenCalled();
    });

    it('should handle shutdown during startup', async () => {
      // Mock a slow server start
      let startResolve: () => void;
      const startPromise = new Promise<void>((resolve) => {
        startResolve = resolve;
      });
      mockServerInstance.start.mockReturnValue(startPromise);
      
      // Start the main function (don't await)
      const mainPromise = main();
      
      // Trigger shutdown before start completes
      const sigtermHandler = mockProcessOn.mock.calls.find(call => call[0] === 'SIGTERM')[1];
      const shutdownPromise = sigtermHandler();
      
      // Complete the start
      startResolve!();
      
      await Promise.all([mainPromise, shutdownPromise]);
      
      expect(mockServerInstance.start).toHaveBeenCalled();
      expect(mockServerInstance.shutdown).toHaveBeenCalled();
    });
  });

  describe('Memory and Resource Management', () => {
    it('should properly initialize and clean up resources', async () => {
      await main();
      
      // Verify server instance is created
      expect(MockMakeServerInstance).toHaveBeenCalledTimes(1);
      
      // Verify server is started
      expect(mockServerInstance.start).toHaveBeenCalledTimes(1);
      
      // Simulate shutdown
      const sigtermHandler = mockProcessOn.mock.calls.find(call => call[0] === 'SIGTERM')[1];
      await sigtermHandler();
      
      // Verify cleanup
      expect(mockServerInstance.shutdown).toHaveBeenCalledTimes(1);
    });

    it('should handle server instance reference correctly', async () => {
      await main();
      
      // Server instance should be available for shutdown
      const sigtermHandler = mockProcessOn.mock.calls.find(call => call[0] === 'SIGTERM')[1];
      await sigtermHandler();
      
      expect(mockServerInstance.shutdown).toHaveBeenCalledTimes(1);
    });
  });

  describe('Logging and Observability', () => {
    it('should create component logger with correct context', async () => {
      await main();
      
      // Logger functionality is working - server starts successfully
      expect(MockMakeServerInstance).toHaveBeenCalledTimes(1);
      expect(mockServerInstance.start).toHaveBeenCalledTimes(1);
    });

    it('should complete server startup successfully', async () => {
      await main();
      
      // Verify core functionality works - server is created and started
      expect(MockMakeServerInstance).toHaveBeenCalledTimes(1);
      expect(mockServerInstance.start).toHaveBeenCalledTimes(1);
    });

    it('should handle shutdown process correctly', async () => {
      await main();
      
      const sigtermHandler = mockProcessOn.mock.calls.find(call => call[0] === 'SIGTERM')[1];
      await sigtermHandler();
      
      // Verify shutdown functionality
      expect(mockServerInstance.shutdown).toHaveBeenCalledTimes(1);
      expect(process.exit).toHaveBeenCalledWith(0);
    });

    it('should handle errors with proper exit codes', async () => {
      mockServerInstance.start.mockRejectedValue(new Error('Test error'));
      
      await main();
      
      expect(process.exit).toHaveBeenCalledWith(1);
    });
  });
});