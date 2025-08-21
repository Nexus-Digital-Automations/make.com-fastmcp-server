/**
 * @fileoverview End-to-end tests for tool registration and execution
 * Tests complete tool lifecycle from registration to execution with middleware integration
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { FastMCP } from 'fastmcp';
import { z } from 'zod';

// Mock comprehensive FastMCP server functionality
const mockFastMCPInstance = {
  addTool: jest.fn(),
  removeTool: jest.fn(),
  getTool: jest.fn(),
  listTools: jest.fn(),
  on: jest.fn(),
  emit: jest.fn(),
  start: jest.fn(),
  stop: jest.fn(),
  // Tool execution methods
  executeTool: jest.fn(),
  validateTool: jest.fn(),
  // Middleware management
  use: jest.fn(),
  removeMiddleware: jest.fn(),
  // Connection management
  getActiveConnections: jest.fn(),
  broadcastToConnections: jest.fn()
};

// Mock middleware instances
const mockCachingMiddleware = {
  apply: jest.fn(),
  wrapWithCache: jest.fn(),
  invalidateOperationCache: jest.fn(),
  getOperationStats: jest.fn(),
  healthCheck: jest.fn().mockResolvedValue({ healthy: true }),
  shutdown: jest.fn()
};

const mockMonitoringMiddleware = {
  initializeServerMonitoring: jest.fn(),
  wrapToolExecution: jest.fn(),
  monitorAuthentication: jest.fn(), 
  monitorMakeApiCall: jest.fn(),
  getMonitoringStats: jest.fn().mockReturnValue({
    activeConnections: 0,
    activeToolExecutions: 0,
    metricsHealth: Promise.resolve({ healthy: true })
  }),
  healthCheck: jest.fn().mockResolvedValue({ healthy: true }),
  shutdown: jest.fn()
};

// Mock API client
const mockApiClient = {
  get: jest.fn(),
  post: jest.fn(),
  put: jest.fn(),
  delete: jest.fn(),
  patch: jest.fn(),
  healthCheck: jest.fn().mockResolvedValue(true),
  getRateLimiterStatus: jest.fn().mockReturnValue({ running: 0, queued: 0 }),
  shutdown: jest.fn()
};

// Mock tool implementations
const createMockTool = (name: string, complexity: 'simple' | 'complex' = 'simple') => {
  const baseTool = {
    name,
    description: `${name} tool for testing`,
    annotations: {
      title: `${name} Tool`,
      readOnlyHint: name.includes('get') || name.includes('list'),
      destructiveHint: name.includes('delete') || name.includes('remove'),
      idempotentHint: name.includes('get') || name.includes('status'),
      openWorldHint: false
    }
  };

  if (complexity === 'simple') {
    return {
      ...baseTool,
      parameters: z.object({
        id: z.string().optional(),
        limit: z.number().min(1).max(100).default(50).optional()
      }),
      execute: jest.fn().mockResolvedValue({
        success: true,
        data: { message: `${name} executed successfully`, id: 'test-123' }
      })
    };
  } else {
    return {
      ...baseTool,
      parameters: z.object({
        config: z.object({
          name: z.string().min(1),
          settings: z.record(z.string(), z.unknown()).optional(),
          options: z.object({
            async: z.boolean().default(false),
            timeout: z.number().min(100).max(30000).default(5000),
            retries: z.number().min(0).max(5).default(3)
          }).optional()
        }),
        context: z.object({
          userId: z.string().optional(),
          sessionId: z.string().optional(),
          permissions: z.array(z.string()).optional()
        }).optional()
      }),
      execute: jest.fn().mockImplementation(async (args) => {
        // Simulate complex processing
        await new Promise(resolve => setTimeout(resolve, 100));
        
        if (args.config.options?.async) {
          return {
            success: true,
            data: {
              message: `${name} started asynchronously`,
              taskId: `task-${Date.now()}`,
              status: 'running'
            }
          };
        }
        
        return {
          success: true,
          data: {
            message: `${name} executed with complex config`,
            config: args.config,
            result: { processed: true, timestamp: new Date().toISOString() }
          }
        };
      })
    };
  }
};

describe('Tool Registration and Execution - End-to-End Tests', () => {
  let server: typeof mockFastMCPInstance;
  let cachingMiddleware: typeof mockCachingMiddleware;
  let monitoringMiddleware: typeof mockMonitoringMiddleware;
  let apiClient: typeof mockApiClient;
  let registeredTools: Map<string, any>;

  beforeEach(() => {
    jest.clearAllMocks();
    
    server = { ...mockFastMCPInstance };
    cachingMiddleware = { ...mockCachingMiddleware };
    monitoringMiddleware = { ...mockMonitoringMiddleware };
    apiClient = { ...mockApiClient };
    registeredTools = new Map();

    // Simulate tool registration
    server.addTool.mockImplementation((tool) => {
      registeredTools.set(tool.name, tool);
      return tool;
    });

    server.getTool.mockImplementation((name) => {
      return registeredTools.get(name);
    });

    server.listTools.mockImplementation(() => {
      return Array.from(registeredTools.values());
    });

    server.removeTool.mockImplementation((name) => {
      const existed = registeredTools.has(name);
      registeredTools.delete(name);
      return existed;
    });

    // Reset middleware mocks
    cachingMiddleware.apply.mockClear();
    monitoringMiddleware.initializeServerMonitoring.mockClear();
    
    // Reset wrapper functions
    cachingMiddleware.wrapWithCache.mockImplementation(async (op, params, executor) => {
      return await executor();
    });
    
    monitoringMiddleware.wrapToolExecution.mockImplementation((toolName, op, executor) => {
      return executor;
    });
  });

  afterEach(() => {
    registeredTools.clear();
    jest.restoreAllMocks();
  });

  describe('Tool Registration Lifecycle', () => {
    it('should register tools with comprehensive metadata and validation', () => {
      const toolCategories = [
        { category: 'scenarios', tools: ['list-scenarios', 'get-scenario', 'create-scenario', 'delete-scenario'] },
        { category: 'users', tools: ['list-users', 'get-user', 'update-user'] },
        { category: 'templates', tools: ['list-templates', 'get-template', 'clone-template'] },
        { category: 'analytics', tools: ['get-analytics', 'generate-report'] }
      ];

      toolCategories.forEach(({ category, tools }) => {
        tools.forEach(toolName => {
          const tool = createMockTool(toolName, toolName.includes('create') ? 'complex' : 'simple');
          
          server.addTool(tool);
          
          expect(server.addTool).toHaveBeenCalledWith(tool);
          expect(registeredTools.has(toolName)).toBe(true);
          
          const registeredTool = registeredTools.get(toolName);
          expect(registeredTool).toEqual(tool);
          expect(registeredTool.name).toBe(toolName);
          expect(registeredTool.description).toContain(toolName);
          expect(registeredTool.parameters).toBeDefined();
          expect(typeof registeredTool.execute).toBe('function');
        });
      });

      // Verify all tools were registered
      const allTools = server.listTools();
      expect(allTools).toHaveLength(14); // Total from all categories
      
      // Verify tool metadata
      allTools.forEach(tool => {
        expect(tool.annotations).toBeDefined();
        expect(tool.annotations.title).toBeDefined();
        expect(typeof tool.annotations.readOnlyHint).toBe('boolean');
        expect(typeof tool.annotations.destructiveHint).toBe('boolean');
      });
    });

    it('should handle tool registration conflicts and updates', () => {
      const originalTool = createMockTool('test-tool');
      const updatedTool = {
        ...createMockTool('test-tool'),
        description: 'Updated test tool with enhanced functionality',
        version: '2.0'
      };

      // Register original tool
      server.addTool(originalTool);
      expect(registeredTools.get('test-tool')).toEqual(originalTool);

      // Update tool (replace existing)
      server.addTool(updatedTool);
      const currentTool = registeredTools.get('test-tool');
      expect(currentTool.description).toBe(updatedTool.description);
      expect(currentTool.version).toBe('2.0');

      // Verify tool list reflects update
      const tools = server.listTools();
      expect(tools).toHaveLength(1);
      expect(tools[0]).toEqual(updatedTool);
    });

    it('should validate tool schemas and reject invalid registrations', () => {
      const invalidTools = [
        {
          name: 'invalid-no-execute',
          description: 'Tool missing execute function',
          parameters: z.object({})
          // Missing execute function
        },
        {
          name: '', // Empty name
          description: 'Tool with empty name',
          parameters: z.object({}),
          execute: jest.fn()
        },
        {
          // Missing name
          description: 'Tool with no name property',
          parameters: z.object({}),
          execute: jest.fn()
        }
      ];

      // Mock validation to simulate real behavior
      server.validateTool = jest.fn().mockImplementation((tool) => {
        if (!tool.name || tool.name.length === 0) {
          throw new Error('Tool name is required');
        }
        if (typeof tool.execute !== 'function') {
          throw new Error('Tool execute function is required');
        }
        return true;
      });

      invalidTools.forEach((invalidTool, index) => {
        expect(() => {
          server.validateTool(invalidTool);
        }).toThrow();
      });
    });

    it('should support tool categories and organize by functionality', () => {
      const functionalCategories = [
        {
          category: 'read_operations',
          tools: [
            { name: 'list-items', readOnly: true },
            { name: 'get-status', readOnly: true },
            { name: 'search-data', readOnly: true }
          ]
        },
        {
          category: 'write_operations', 
          tools: [
            { name: 'create-item', destructive: false },
            { name: 'update-item', destructive: false },
            { name: 'delete-item', destructive: true }
          ]
        },
        {
          category: 'system_operations',
          tools: [
            { name: 'health-check', readOnly: true, idempotent: true },
            { name: 'cache-clear', destructive: true, idempotent: false }
          ]
        }
      ];

      functionalCategories.forEach(({ category, tools }) => {
        tools.forEach(({ name, readOnly, destructive, idempotent }) => {
          const tool = {
            ...createMockTool(name),
            annotations: {
              ...createMockTool(name).annotations,
              readOnlyHint: readOnly || false,
              destructiveHint: destructive || false,
              idempotentHint: idempotent !== false
            },
            category
          };

          server.addTool(tool);
        });
      });

      // Verify categorization
      const allTools = server.listTools();
      const readOnlyTools = allTools.filter(t => t.annotations.readOnlyHint);
      const destructiveTools = allTools.filter(t => t.annotations.destructiveHint);
      const idempotentTools = allTools.filter(t => t.annotations.idempotentHint);

      expect(readOnlyTools).toHaveLength(3);
      expect(destructiveTools).toHaveLength(2);
      expect(idempotentTools).toHaveLength(6); // Most tools are idempotent by default
    });
  });

  describe('Middleware Integration During Registration', () => {
    it('should apply caching middleware during tool registration', () => {
      cachingMiddleware.apply(server);
      
      const cachableTools = [
        { name: 'list-scenarios', cachable: true, ttl: 1800 },
        { name: 'get-user-profile', cachable: true, ttl: 3600 },
        { name: 'get-system-status', cachable: true, ttl: 300 }
      ];

      // Mock tool wrapping behavior
      let wrappedToolCount = 0;
      server.addTool.mockImplementation((tool) => {
        if (cachableTools.some(t => t.name === tool.name)) {
          // Simulate caching middleware wrapping the tool
          const originalExecute = tool.execute;
          tool.execute = async (args: any, context: any) => {
            return await cachingMiddleware.wrapWithCache(
              tool.name,
              args,
              () => originalExecute(args, context)
            );
          };
          wrappedToolCount++;
        }
        registeredTools.set(tool.name, tool);
        return tool;
      });

      // Register cachable tools
      cachableTools.forEach(({ name }) => {
        const tool = createMockTool(name);
        server.addTool(tool);
      });

      expect(cachingMiddleware.apply).toHaveBeenCalledWith(server);
      expect(wrappedToolCount).toBe(cachableTools.length);

      // Verify wrapped tools can be executed
      cachableTools.forEach(({ name }) => {
        const tool = server.getTool(name);
        expect(tool).toBeDefined();
        expect(typeof tool.execute).toBe('function');
      });
    });

    it('should apply monitoring middleware during tool registration', () => {
      monitoringMiddleware.initializeServerMonitoring(server);
      
      const monitoredTools = [
        { name: 'critical-operation', monitoring: 'detailed' },
        { name: 'user-action', monitoring: 'standard' },
        { name: 'background-task', monitoring: 'minimal' }
      ];

      // Mock monitoring wrapper
      let monitoredToolCount = 0;
      server.addTool.mockImplementation((tool) => {
        const monitorConfig = monitoredTools.find(t => t.name === tool.name);
        if (monitorConfig) {
          // Simulate monitoring middleware wrapping
          const originalExecute = tool.execute;
          const wrappedExecute = monitoringMiddleware.wrapToolExecution(
            tool.name,
            'tool-execution',
            originalExecute
          );
          
          tool.execute = wrappedExecute;
          monitoredToolCount++;
        }
        registeredTools.set(tool.name, tool);
        return tool;
      });

      // Register monitored tools
      monitoredTools.forEach(({ name }) => {
        const tool = createMockTool(name);
        server.addTool(tool);
      });

      expect(monitoringMiddleware.initializeServerMonitoring).toHaveBeenCalledWith(server);
      expect(monitoredToolCount).toBe(monitoredTools.length);

      // Verify monitoring stats include the tools
      const stats = monitoringMiddleware.getMonitoringStats();
      expect(stats).toHaveProperty('activeConnections');
      expect(stats).toHaveProperty('activeToolExecutions');
    });

    it('should chain multiple middleware applications', () => {
      // Apply middleware in sequence
      cachingMiddleware.apply(server);
      monitoringMiddleware.initializeServerMonitoring(server);
      
      // Mock chained middleware behavior
      server.addTool.mockImplementation((tool) => {
        let wrappedExecute = tool.execute;
        
        // Apply monitoring wrapper first
        wrappedExecute = monitoringMiddleware.wrapToolExecution(
          tool.name,
          'chained-execution',
          wrappedExecute
        );
        
        // Apply caching wrapper second (outer layer)
        const finalExecute = async (args: any, context: any) => {
          return await cachingMiddleware.wrapWithCache(
            tool.name,
            args,
            () => wrappedExecute(args, context)
          );
        };
        
        tool.execute = finalExecute;
        registeredTools.set(tool.name, tool);
        return tool;
      });

      const chainedTool = createMockTool('chained-middleware-tool');
      server.addTool(chainedTool);

      const registeredTool = server.getTool('chained-middleware-tool');
      expect(registeredTool.execute).not.toBe(chainedTool.execute);
      
      // Verify both middleware were applied
      expect(cachingMiddleware.apply).toHaveBeenCalled();
      expect(monitoringMiddleware.initializeServerMonitoring).toHaveBeenCalled();
    });
  });

  describe('Tool Execution with Parameter Validation', () => {
    it('should execute simple tools with parameter validation', async () => {
      const simpleTools = [
        {
          name: 'get-item',
          params: { id: 'item-123' },
          expectedSuccess: true
        },
        {
          name: 'list-items',
          params: { limit: 25 },
          expectedSuccess: true
        },
        {
          name: 'list-items',
          params: { limit: 150 }, // Exceeds max limit
          expectedSuccess: false
        }
      ];

      for (const testCase of simpleTools) {
        const tool = createMockTool(testCase.name);
        server.addTool(tool);
        
        // Mock parameter validation
        server.executeTool = jest.fn().mockImplementation(async (name, params) => {
          const registeredTool = server.getTool(name);
          if (!registeredTool) {
            throw new Error(`Tool ${name} not found`);
          }
          
          try {
            // Simulate parameter validation
            const validatedParams = registeredTool.parameters.parse(params);
            return await registeredTool.execute(validatedParams);
          } catch (error) {
            throw new Error(`Parameter validation failed: ${error.message}`);
          }
        });

        if (testCase.expectedSuccess) {
          const result = await server.executeTool(testCase.name, testCase.params);
          expect(result.success).toBe(true);
          expect(result.data.message).toContain('executed successfully');
        } else {
          await expect(server.executeTool(testCase.name, testCase.params))
            .rejects.toThrow('Parameter validation failed');
        }
      }
    });

    it('should execute complex tools with nested parameter validation', async () => {
      const complexTool = createMockTool('complex-configuration', 'complex');
      server.addTool(complexTool);
      
      const testCases = [
        {
          name: 'valid_complex_config',
          params: {
            config: {
              name: 'test-config',
              settings: {
                feature1: true,
                feature2: 'enabled',
                timeout: 5000
              },
              options: {
                async: false,
                timeout: 10000,
                retries: 2
              }
            },
            context: {
              userId: 'user-123',
              sessionId: 'session-456',
              permissions: ['read', 'write']
            }
          },
          expectedSuccess: true
        },
        {
          name: 'minimal_valid_config',
          params: {
            config: {
              name: 'minimal-config'
            }
          },
          expectedSuccess: true
        },
        {
          name: 'invalid_config_name',
          params: {
            config: {
              name: '' // Empty name should fail
            }
          },
          expectedSuccess: false
        },
        {
          name: 'invalid_timeout_range',
          params: {
            config: {
              name: 'test-config',
              options: {
                timeout: 50 // Below minimum
              }
            }
          },
          expectedSuccess: false
        }
      ];

      server.executeTool = jest.fn().mockImplementation(async (name, params) => {
        const registeredTool = server.getTool(name);
        try {
          const validatedParams = registeredTool.parameters.parse(params);
          return await registeredTool.execute(validatedParams);
        } catch (error) {
          throw new Error(`Validation failed: ${error.message}`);
        }
      });

      for (const testCase of testCases) {
        if (testCase.expectedSuccess) {
          const result = await server.executeTool('complex-configuration', testCase.params);
          expect(result.success).toBe(true);
          expect(result.data.config).toBeDefined();
        } else {
          await expect(server.executeTool('complex-configuration', testCase.params))
            .rejects.toThrow('Validation failed');
        }
      }
    });

    it('should handle tool execution errors and provide detailed diagnostics', async () => {
      const errorScenarios = [
        {
          name: 'timeout-tool',
          errorType: 'timeout',
          mockError: new Error('Operation timed out after 5000ms')
        },
        {
          name: 'auth-tool',
          errorType: 'authentication',
          mockError: Object.assign(new Error('Authentication failed'), { name: 'AuthenticationError' })
        },
        {
          name: 'validation-tool', 
          errorType: 'validation',
          mockError: new Error('Required field missing: email')
        },
        {
          name: 'external-tool',
          errorType: 'external_service',
          mockError: Object.assign(new Error('External API unavailable'), { status: 503 })
        }
      ];

      for (const scenario of errorScenarios) {
        const tool = {
          ...createMockTool(scenario.name),
          execute: jest.fn().mockRejectedValue(scenario.mockError)
        };
        
        server.addTool(tool);
        
        server.executeTool = jest.fn().mockImplementation(async (name, params) => {
          const registeredTool = server.getTool(name);
          try {
            return await registeredTool.execute(params);
          } catch (error) {
            // Enhanced error reporting
            throw {
              name: 'ToolExecutionError',
              message: error.message,
              toolName: name,
              errorType: scenario.errorType,
              originalError: error,
              timestamp: new Date().toISOString()
            };
          }
        });

        try {
          await server.executeTool(scenario.name, {});
          fail('Expected tool execution to throw an error');
        } catch (error) {
          expect(error.name).toBe('ToolExecutionError');
          expect(error.toolName).toBe(scenario.name);
          expect(error.errorType).toBe(scenario.errorType);
          expect(error.originalError).toBe(scenario.mockError);
        }
      }
    });
  });

  describe('Tool Execution with Middleware Effects', () => {
    it('should execute tools with caching middleware effects', async () => {
      const cachingTestScenarios = [
        {
          name: 'cache-miss-scenario',
          tool: 'list-scenarios',
          params: { limit: 50 },
          cacheState: 'miss',
          expectedCacheCall: true
        },
        {
          name: 'cache-hit-scenario',
          tool: 'get-scenario',
          params: { id: 'scenario-123' },
          cacheState: 'hit',
          expectedCacheCall: false
        },
        {
          name: 'cache-disabled-scenario',
          tool: 'delete-scenario',
          params: { id: 'scenario-456' },
          cacheState: 'disabled',
          expectedCacheCall: false
        }
      ];

      // Setup caching behavior
      cachingMiddleware.wrapWithCache.mockImplementation(async (operation, params, executor) => {
        const scenario = cachingTestScenarios.find(s => s.tool === operation);
        if (scenario?.cacheState === 'hit') {
          return {
            success: true,
            data: { message: 'Cached result', cached: true },
            fromCache: true
          };
        } else if (scenario?.cacheState === 'miss') {
          const result = await executor();
          return { ...result, fromCache: false };
        }
        return await executor();
      });

      for (const scenario of cachingTestScenarios) {
        const tool = createMockTool(scenario.tool);
        
        // Apply caching wrapper
        const originalExecute = tool.execute;
        tool.execute = async (args: any) => {
          return await cachingMiddleware.wrapWithCache(
            scenario.tool,
            args,
            () => originalExecute(args)
          );
        };
        
        server.addTool(tool);
        
        server.executeTool = jest.fn().mockImplementation(async (name, params) => {
          const registeredTool = server.getTool(name);
          return await registeredTool.execute(params);
        });

        const result = await server.executeTool(scenario.tool, scenario.params);
        
        expect(result.success).toBe(true);
        
        if (scenario.cacheState === 'hit') {
          expect(result.fromCache).toBe(true);
          expect(result.data.cached).toBe(true);
        } else if (scenario.cacheState === 'miss') {
          expect(result.fromCache).toBe(false);
        }
        
        expect(cachingMiddleware.wrapWithCache).toHaveBeenCalledWith(
          scenario.tool,
          scenario.params,
          expect.any(Function)
        );
      }
    });

    it('should execute tools with monitoring middleware effects', async () => {
      const monitoringScenarios = [
        {
          name: 'fast-execution',
          tool: 'get-status',
          duration: 50,
          expectedCategory: 'fast'
        },
        {
          name: 'slow-execution',
          tool: 'generate-report',
          duration: 2000,
          expectedCategory: 'slow'
        },
        {
          name: 'error-execution',
          tool: 'failing-operation',
          duration: 100,
          shouldFail: true
        }
      ];

      // Setup monitoring behavior
      monitoringMiddleware.wrapToolExecution.mockImplementation((toolName, operation, executor) => {
        return async (...args) => {
          const startTime = Date.now();
          try {
            const result = await executor(...args);
            const duration = Date.now() - startTime;
            
            // Mock metrics recording
            console.log(`Tool ${toolName} executed successfully in ${duration}ms`);
            return result;
          } catch (error) {
            const duration = Date.now() - startTime;
            console.log(`Tool ${toolName} failed after ${duration}ms:`, error.message);
            throw error;
          }
        };
      });

      for (const scenario of monitoringScenarios) {
        const tool = createMockTool(scenario.tool);
        
        if (scenario.shouldFail) {
          tool.execute = jest.fn().mockRejectedValue(new Error('Simulated failure'));
        } else {
          // Add artificial delay
          const originalExecute = tool.execute;
          tool.execute = jest.fn().mockImplementation(async (args) => {
            await new Promise(resolve => setTimeout(resolve, scenario.duration));
            return await originalExecute(args);
          });
        }
        
        // Apply monitoring wrapper
        tool.execute = monitoringMiddleware.wrapToolExecution(
          scenario.tool,
          'monitored-execution',
          tool.execute
        );
        
        server.addTool(tool);
        
        server.executeTool = jest.fn().mockImplementation(async (name, params) => {
          const registeredTool = server.getTool(name);
          return await registeredTool.execute(params);
        });

        if (scenario.shouldFail) {
          await expect(server.executeTool(scenario.tool, {}))
            .rejects.toThrow('Simulated failure');
        } else {
          const startTime = Date.now();
          const result = await server.executeTool(scenario.tool, {});
          const actualDuration = Date.now() - startTime;
          
          expect(result.success).toBe(true);
          expect(actualDuration).toBeGreaterThanOrEqual(scenario.duration);
        }
        
        expect(monitoringMiddleware.wrapToolExecution).toHaveBeenCalledWith(
          scenario.tool,
          'monitored-execution',
          expect.any(Function)
        );
      }
    });

    it('should execute tools with combined middleware effects (caching + monitoring)', async () => {
      const combinedScenarios = [
        {
          name: 'cached-monitored-success',
          tool: 'get-user-profile',
          params: { userId: 'user-123' },
          cacheHit: false,
          expectSuccess: true
        },
        {
          name: 'cached-monitored-cache-hit',
          tool: 'get-user-profile',
          params: { userId: 'user-123' }, // Same params - should hit cache
          cacheHit: true,
          expectSuccess: true
        },
        {
          name: 'monitored-cache-error',
          tool: 'complex-operation',
          params: { config: { name: 'test' } },
          cacheHit: false,
          expectSuccess: false,
          shouldFail: true
        }
      ];

      // Setup combined middleware behavior
      let cacheStore = new Map();
      
      cachingMiddleware.wrapWithCache.mockImplementation(async (operation, params, executor) => {
        const cacheKey = `${operation}:${JSON.stringify(params)}`;
        const scenario = combinedScenarios.find(s => s.tool === operation);
        
        if (scenario?.cacheHit && cacheStore.has(cacheKey)) {
          return {
            success: true,
            data: cacheStore.get(cacheKey),
            fromCache: true
          };
        }
        
        try {
          const result = await executor();
          cacheStore.set(cacheKey, result.data);
          return { ...result, fromCache: false };
        } catch (error) {
          throw error;
        }
      });

      monitoringMiddleware.wrapToolExecution.mockImplementation((toolName, operation, executor) => {
        return async (...args) => {
          const startTime = Date.now();
          try {
            const result = await executor(...args);
            const duration = Date.now() - startTime;
            console.log(`[MONITOR] ${toolName} succeeded in ${duration}ms`);
            return result;
          } catch (error) {
            const duration = Date.now() - startTime;
            console.log(`[MONITOR] ${toolName} failed in ${duration}ms`);
            throw error;
          }
        };
      });

      for (const scenario of combinedScenarios) {
        const tool = createMockTool(scenario.tool, 'complex');
        
        if (scenario.shouldFail) {
          tool.execute = jest.fn().mockRejectedValue(new Error('Complex operation failed'));
        }
        
        // Apply monitoring wrapper first (inner layer)
        tool.execute = monitoringMiddleware.wrapToolExecution(
          scenario.tool,
          'combined-execution',
          tool.execute
        );
        
        // Apply caching wrapper second (outer layer)
        const originalExecute = tool.execute;
        tool.execute = async (args: any) => {
          return await cachingMiddleware.wrapWithCache(
            scenario.tool,
            args,
            () => originalExecute(args)
          );
        };
        
        server.addTool(tool);
        
        server.executeTool = jest.fn().mockImplementation(async (name, params) => {
          const registeredTool = server.getTool(name);
          return await registeredTool.execute(params);
        });

        if (scenario.expectSuccess) {
          const result = await server.executeTool(scenario.tool, scenario.params);
          expect(result.success).toBe(true);
          
          if (scenario.cacheHit) {
            expect(result.fromCache).toBe(true);
          } else {
            expect(result.fromCache).toBe(false);
          }
        } else {
          await expect(server.executeTool(scenario.tool, scenario.params))
            .rejects.toThrow();
        }
      }
    });
  });

  describe('Tool Lifecycle Management', () => {
    it('should support dynamic tool registration and deregistration', () => {
      const dynamicTools = [
        'dynamic-tool-1',
        'dynamic-tool-2', 
        'dynamic-tool-3'
      ];

      // Register tools dynamically
      dynamicTools.forEach(name => {
        const tool = createMockTool(name);
        server.addTool(tool);
        expect(registeredTools.has(name)).toBe(true);
      });

      expect(server.listTools()).toHaveLength(3);

      // Deregister tools
      const removedTool = server.removeTool('dynamic-tool-2');
      expect(removedTool).toBe(true);
      expect(registeredTools.has('dynamic-tool-2')).toBe(false);
      expect(server.listTools()).toHaveLength(2);

      // Attempt to remove non-existent tool
      const notRemoved = server.removeTool('non-existent-tool');
      expect(notRemoved).toBe(false);
    });

    it('should handle server lifecycle events during tool operations', () => {
      const lifecycleEvents = ['start', 'stop', 'restart'];
      const tools = ['persistent-tool', 'lifecycle-aware-tool'];

      // Register lifecycle-aware tools
      tools.forEach(name => {
        const tool = createMockTool(name);
        server.addTool(tool);
      });

      // Mock server lifecycle methods
      server.start.mockResolvedValue('Server started successfully');
      server.stop.mockResolvedValue('Server stopped gracefully');

      lifecycleEvents.forEach(async (event) => {
        if (event === 'start') {
          await server.start();
          expect(server.start).toHaveBeenCalled();
        } else if (event === 'stop') {
          await server.stop();
          expect(server.stop).toHaveBeenCalled();
        }
        
        // Tools should remain registered across lifecycle events
        expect(server.listTools()).toHaveLength(2);
      });
    });
  });

  describe('Performance and Concurrency', () => {
    it('should handle concurrent tool executions efficiently', async () => {
      const concurrentScenarios = [
        {
          name: 'low_concurrency',
          toolCount: 5,
          concurrentExecutions: 3
        },
        {
          name: 'medium_concurrency',
          toolCount: 10,
          concurrentExecutions: 7
        },
        {
          name: 'high_concurrency',
          toolCount: 20,
          concurrentExecutions: 15
        }
      ];

      for (const scenario of concurrentScenarios) {
        // Register multiple tools
        const tools = [];
        for (let i = 0; i < scenario.toolCount; i++) {
          const tool = createMockTool(`concurrent-tool-${i}`);
          // Add artificial processing time
          const originalExecute = tool.execute;
          tool.execute = jest.fn().mockImplementation(async (args) => {
            await new Promise(resolve => setTimeout(resolve, 50 + Math.random() * 100));
            const result = await originalExecute(args);
            return { ...result, processedBy: `tool-${i}` };
          });
          
          server.addTool(tool);
          tools.push(tool);
        }

        // Execute tools concurrently
        server.executeTool = jest.fn().mockImplementation(async (name, params) => {
          const tool = server.getTool(name);
          return await tool.execute(params);
        });

        const startTime = Date.now();
        const concurrentPromises = [];
        
        for (let i = 0; i < scenario.concurrentExecutions; i++) {
          const toolIndex = i % scenario.toolCount;
          const promise = server.executeTool(`concurrent-tool-${toolIndex}`, {
            executionId: i,
            scenario: scenario.name
          });
          concurrentPromises.push(promise);
        }

        const results = await Promise.allSettled(concurrentPromises);
        const totalDuration = Date.now() - startTime;
        
        // Verify all executions completed
        const successfulResults = results.filter(r => r.status === 'fulfilled');
        expect(successfulResults).toHaveLength(scenario.concurrentExecutions);
        
        // Verify concurrent execution was efficient
        const maxSequentialTime = scenario.concurrentExecutions * 150; // 150ms per execution
        expect(totalDuration).toBeLessThan(maxSequentialTime);
        
        console.log(`${scenario.name}: ${scenario.concurrentExecutions} executions in ${totalDuration}ms`);
      }
    });

    it('should maintain tool execution isolation and prevent interference', async () => {
      const isolationTests = [
        {
          name: 'state_isolation',
          tools: ['stateful-tool-1', 'stateful-tool-2'],
          sharedResource: new Map() // Simulate shared state
        },
        {
          name: 'error_isolation',
          tools: ['failing-tool', 'succeeding-tool'],
          sharedResource: { errorCount: 0 }
        },
        {
          name: 'performance_isolation',
          tools: ['fast-tool', 'slow-tool'],
          sharedResource: { executionTimes: [] }
        }
      ];

      for (const test of isolationTests) {
        test.tools.forEach((toolName, index) => {
          const tool = createMockTool(toolName);
          
          if (toolName.includes('stateful')) {
            tool.execute = jest.fn().mockImplementation(async (args) => {
              const key = `${toolName}-state`;
              test.sharedResource.set(key, args);
              return {
                success: true,
                data: {
                  message: `${toolName} executed`,
                  state: test.sharedResource.get(key)
                }
              };
            });
          } else if (toolName.includes('failing')) {
            tool.execute = jest.fn().mockRejectedValue(new Error('Intentional failure'));
          } else if (toolName.includes('slow')) {
            tool.execute = jest.fn().mockImplementation(async (args) => {
              const startTime = Date.now();
              await new Promise(resolve => setTimeout(resolve, 200));
              const duration = Date.now() - startTime;
              test.sharedResource.executionTimes.push(duration);
              return { success: true, data: { duration } };
            });
          } else {
            // Fast tool
            tool.execute = jest.fn().mockImplementation(async (args) => {
              const startTime = Date.now();
              const duration = Date.now() - startTime;
              test.sharedResource.executionTimes?.push(duration);
              return { success: true, data: { duration } };
            });
          }
          
          server.addTool(tool);
        });

        server.executeTool = jest.fn().mockImplementation(async (name, params) => {
          const tool = server.getTool(name);
          return await tool.execute(params);
        });

        // Execute tools and verify isolation
        if (test.name === 'state_isolation') {
          await server.executeTool('stateful-tool-1', { data: 'tool1-data' });
          await server.executeTool('stateful-tool-2', { data: 'tool2-data' });
          
          expect(test.sharedResource.get('stateful-tool-1-state')).toEqual({ data: 'tool1-data' });
          expect(test.sharedResource.get('stateful-tool-2-state')).toEqual({ data: 'tool2-data' });
        } else if (test.name === 'error_isolation') {
          // Failing tool should not affect succeeding tool
          await expect(server.executeTool('failing-tool', {})).rejects.toThrow();
          const successResult = await server.executeTool('succeeding-tool', {});
          expect(successResult.success).toBe(true);
        } else if (test.name === 'performance_isolation') {
          // Execute both tools concurrently
          const [fastResult, slowResult] = await Promise.allSettled([
            server.executeTool('fast-tool', {}),
            server.executeTool('slow-tool', {})
          ]);
          
          expect(fastResult.status).toBe('fulfilled');
          expect(slowResult.status).toBe('fulfilled');
          expect(test.sharedResource.executionTimes).toHaveLength(2);
        }
      }
    });
  });

  describe('Integration Health and Diagnostics', () => {
    it('should provide comprehensive health check across all registered tools', async () => {
      const healthCheckTools = [
        { name: 'healthy-tool', healthy: true },
        { name: 'degraded-tool', healthy: true, performance: 'degraded' },
        { name: 'unhealthy-tool', healthy: false }
      ];

      healthCheckTools.forEach(({ name, healthy, performance }) => {
        const tool = createMockTool(name);
        
        if (!healthy) {
          tool.execute = jest.fn().mockRejectedValue(new Error('Tool health check failed'));
        } else if (performance === 'degraded') {
          const originalExecute = tool.execute;
          tool.execute = jest.fn().mockImplementation(async (args) => {
            await new Promise(resolve => setTimeout(resolve, 1000)); // Slow response
            return await originalExecute(args);
          });
        }
        
        server.addTool(tool);
      });

      // Mock comprehensive health check
      server.performHealthCheck = jest.fn().mockImplementation(async () => {
        const tools = server.listTools();
        const healthResults = [];
        
        for (const tool of tools) {
          try {
            const startTime = Date.now();
            await tool.execute({ healthCheck: true });
            const duration = Date.now() - startTime;
            
            healthResults.push({
              name: tool.name,
              healthy: true,
              responseTime: duration,
              status: duration > 500 ? 'degraded' : 'healthy'
            });
          } catch (error) {
            healthResults.push({
              name: tool.name,
              healthy: false,
              error: error.message,
              status: 'unhealthy'
            });
          }
        }
        
        const healthyCount = healthResults.filter(r => r.healthy).length;
        const totalCount = healthResults.length;
        
        return {
          overall: healthyCount === totalCount ? 'healthy' : healthyCount > 0 ? 'degraded' : 'unhealthy',
          healthyTools: healthyCount,
          totalTools: totalCount,
          tools: healthResults,
          middleware: {
            caching: await cachingMiddleware.healthCheck(),
            monitoring: await monitoringMiddleware.healthCheck()
          }
        };
      });

      const healthReport = await server.performHealthCheck();
      
      expect(healthReport.totalTools).toBe(3);
      expect(healthReport.healthyTools).toBe(2); // healthy-tool and degraded-tool
      expect(healthReport.overall).toBe('degraded'); // Due to unhealthy-tool
      expect(healthReport.middleware.caching.healthy).toBe(true);
      expect(healthReport.middleware.monitoring.healthy).toBe(true);
      
      const unhealthyTool = healthReport.tools.find(t => t.name === 'unhealthy-tool');
      expect(unhealthyTool.healthy).toBe(false);
      expect(unhealthyTool.error).toBeDefined();
    });

    it('should provide detailed diagnostic information for troubleshooting', () => {
      const diagnosticTools = [
        'diagnostic-tool-1',
        'diagnostic-tool-2',
        'diagnostic-tool-3'
      ];

      diagnosticTools.forEach(name => {
        const tool = createMockTool(name);
        server.addTool(tool);
      });

      server.getDiagnosticInfo = jest.fn().mockImplementation(() => {
        const tools = server.listTools();
        return {
          server: {
            version: '1.0.0',
            uptime: 3600000, // 1 hour
            activeConnections: monitoringMiddleware.getMonitoringStats().activeConnections,
            registeredTools: tools.length
          },
          tools: tools.map(tool => ({
            name: tool.name,
            description: tool.description,
            parameters: Object.keys(tool.parameters.shape || {}),
            annotations: tool.annotations,
            category: tool.category || 'uncategorized'
          })),
          middleware: {
            caching: {
              enabled: true,
              stats: cachingMiddleware.getOperationStats()
            },
            monitoring: {
              enabled: true,
              stats: monitoringMiddleware.getMonitoringStats()
            }
          },
          apiClient: {
            healthy: apiClient.healthCheck(),
            rateLimiter: apiClient.getRateLimiterStatus()
          }
        };
      });

      const diagnostics = server.getDiagnosticInfo();
      
      expect(diagnostics.server.registeredTools).toBe(3);
      expect(diagnostics.tools).toHaveLength(3);
      expect(diagnostics.middleware.caching.enabled).toBe(true);
      expect(diagnostics.middleware.monitoring.enabled).toBe(true);
      expect(diagnostics.apiClient).toBeDefined();
      
      diagnostics.tools.forEach(tool => {
        expect(tool.name).toBeDefined();
        expect(tool.description).toBeDefined();
        expect(tool.annotations).toBeDefined();
      });
    });
  });
});
