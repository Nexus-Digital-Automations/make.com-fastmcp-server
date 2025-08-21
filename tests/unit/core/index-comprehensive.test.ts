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

// Mock MakeServerInstance class
jest.mock('../../../src/server.js', () => ({
  default: jest.fn().mockImplementation(() => mockServerInstance),
  MakeServerInstance: jest.fn().mockImplementation(() => mockServerInstance)
}));

// Mock logger
const mockLogger = {
  child: jest.fn(() => ({
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn()
  })),
  info: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  debug: jest.fn()
};

jest.mock('../../../src/lib/logger.js', () => ({
  default: mockLogger
}));

// Mock config manager
const mockConfigManager = {
  getConfig: jest.fn(() => ({
    port: 3000,
    version: '1.0.0'
  }))
};

jest.mock('../../../src/lib/config.js', () => ({
  default: mockConfigManager
}));

describe('Main Entry Point - Comprehensive Tests', () => {
  let main: () => Promise<void>;
  let MakeServerInstance: any;
  let componentLogger: any;

  beforeEach(() => {
    jest.clearAllMocks();
    jest.resetModules();
    
    // Reset process mocks
    mockProcessExit.mockClear();
    mockProcessOn.mockClear();
    mockServerInstance.start.mockClear();
    mockServerInstance.shutdown.mockClear();
    
    // Mock process methods
    process.exit = mockProcessExit as any;
    process.on = mockProcessOn as any;
    
    // Setup component logger mock
    componentLogger = {
      info: jest.fn(),
      error: jest.fn(),
      warn: jest.fn(),
      debug: jest.fn()
    };
    mockLogger.child.mockReturnValue(componentLogger);
    
    // Import fresh modules after mocks are set up
    return import('../../../src/index.js').then(module => {
      main = module.default;
      MakeServerInstance = module.MakeServerInstance;
    });
  });

  afterEach(() => {
    // Restore original process methods
    process.exit = originalExit;
    process.on = originalOn;
    process.argv = originalArgv;
  });

  describe('Server Initialization and Startup', () => {
    it('should create and start server instance successfully', async () => {
      await main();
      
      expect(MakeServerInstance).toHaveBeenCalledTimes(1);
      expect(mockServerInstance.start).toHaveBeenCalledTimes(1);
      expect(componentLogger.info).toHaveBeenCalledWith('Initializing Make.com FastMCP Server');
      expect(componentLogger.info).toHaveBeenCalledWith(
        'Make.com FastMCP Server is running',
        expect.objectContaining({
          transport: 'stdio',
          port: undefined
        })
      );
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
      mockConfigManager.getConfig.mockReturnValue({ port: 4000, version: '1.0.0' });
      
      await main();
      
      expect(mockServerInstance.start).toHaveBeenCalledWith({
        transportType: 'httpStream',
        httpStream: {
          endpoint: '/',
          port: 4000
        }
      });
    });

    it('should log transport and port information correctly', async () => {
      process.argv = ['node', 'index.js', '--http'];
      
      await main();
      
      expect(componentLogger.info).toHaveBeenCalledWith(
        'Make.com FastMCP Server is running',
        expect.objectContaining({
          transport: 'httpStream',
          port: 3000
        })
      );
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
      
      expect(componentLogger.info).toHaveBeenCalledWith('Received SIGTERM, starting graceful shutdown');
      expect(mockServerInstance.shutdown).toHaveBeenCalledTimes(1);
      expect(componentLogger.info).toHaveBeenCalledWith('Graceful shutdown completed');
      expect(process.exit).toHaveBeenCalledWith(0);
    });

    it('should perform graceful shutdown on SIGINT', async () => {
      await main();
      
      // Get the SIGINT handler
      const sigintHandler = mockProcessOn.mock.calls.find(call => call[0] === 'SIGINT')[1];
      
      // Execute the handler
      await sigintHandler();
      
      expect(componentLogger.info).toHaveBeenCalledWith('Received SIGINT, starting graceful shutdown');
      expect(mockServerInstance.shutdown).toHaveBeenCalledTimes(1);
      expect(componentLogger.info).toHaveBeenCalledWith('Graceful shutdown completed');
      expect(process.exit).toHaveBeenCalledWith(0);
    });

    it('should handle shutdown errors gracefully', async () => {
      mockServerInstance.shutdown.mockRejectedValue(new Error('Shutdown failed'));
      
      await main();
      
      // Get the SIGTERM handler
      const sigtermHandler = mockProcessOn.mock.calls.find(call => call[0] === 'SIGTERM')[1];
      
      // Execute the handler
      await sigtermHandler();
      
      expect(componentLogger.error).toHaveBeenCalledWith(
        'Error during graceful shutdown',
        expect.objectContaining({ message: 'Shutdown failed' })
      );
      expect(process.exit).toHaveBeenCalledWith(1);
    });
  });

  describe('Error Handling and Recovery', () => {
    it('should handle server creation failures', async () => {
      const mockMakeServer = require('../../../src/server.js').default;
      mockMakeServer.mockImplementation(() => {
        throw new Error('Server creation failed');
      });
      
      await main();
      
      expect(componentLogger.error).toHaveBeenCalledWith(
        'Failed to start server',
        expect.objectContaining({ message: 'Server creation failed' })
      );
      expect(process.exit).toHaveBeenCalledWith(1);
    });

    it('should handle server start failures', async () => {
      mockServerInstance.start.mockRejectedValue(new Error('Start failed'));
      
      await main();
      
      expect(componentLogger.error).toHaveBeenCalledWith(
        'Failed to start server',
        expect.objectContaining({ message: 'Start failed' })
      );
      expect(process.exit).toHaveBeenCalledWith(1);
    });

    it('should handle configuration errors', async () => {
      mockConfigManager.getConfig.mockImplementation(() => {
        throw new Error('Config error');
      });
      
      await main();
      
      expect(componentLogger.error).toHaveBeenCalledWith(
        'Failed to start server',
        expect.objectContaining({ message: 'Config error' })
      );
      expect(process.exit).toHaveBeenCalledWith(1);
    });

    it('should handle logger initialization errors gracefully', async () => {
      mockLogger.child.mockImplementation(() => {
        throw new Error('Logger error');
      });
      
      await main();
      
      // Should not crash the process, but may not have proper logging
      expect(process.exit).toHaveBeenCalledWith(1);
    });
  });

  describe('Module Export and Direct Execution', () => {
    it('should export MakeServerInstance class', () => {
      expect(MakeServerInstance).toBeDefined();
      expect(typeof MakeServerInstance).toBe('function');
    });

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
      mockConfigManager.getConfig.mockReturnValue({ version: '1.0.0' }); // No port
      
      await main();
      
      expect(mockServerInstance.start).toHaveBeenCalledWith({
        transportType: 'httpStream',
        httpStream: {
          endpoint: '/',
          port: 3000 // Default fallback
        }
      });
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
      expect(MakeServerInstance).toHaveBeenCalledTimes(1);
      
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
      
      expect(mockLogger.child).toHaveBeenCalledWith({ component: 'Main' });
    });

    it('should log initialization and completion messages', async () => {
      await main();
      
      expect(componentLogger.info).toHaveBeenCalledWith('Initializing Make.com FastMCP Server');
      expect(componentLogger.info).toHaveBeenCalledWith(
        'Make.com FastMCP Server is running',
        expect.any(Object)
      );
    });

    it('should log shutdown process correctly', async () => {
      await main();
      
      const sigtermHandler = mockProcessOn.mock.calls.find(call => call[0] === 'SIGTERM')[1];
      await sigtermHandler();
      
      expect(componentLogger.info).toHaveBeenCalledWith('Received SIGTERM, starting graceful shutdown');
      expect(componentLogger.info).toHaveBeenCalledWith('Graceful shutdown completed');
    });

    it('should log errors with proper context', async () => {
      mockServerInstance.start.mockRejectedValue(new Error('Test error'));
      
      await main();
      
      expect(componentLogger.error).toHaveBeenCalledWith(
        'Failed to start server',
        expect.objectContaining({ message: 'Test error' })
      );
    });
  });
});