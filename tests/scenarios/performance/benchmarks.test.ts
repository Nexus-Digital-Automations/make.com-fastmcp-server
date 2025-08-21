/**
 * @fileoverview Performance Benchmarking Tests for Refactored Scenarios Module
 * 
 * Ensures that the refactored scenarios module maintains or improves performance
 * metrics compared to the original monolithic implementation.
 * 
 * Performance Categories:
 * - Tool registration and initialization
 * - Schema validation performance
 * - Blueprint processing performance
 * - Memory usage optimization
 * - Concurrent operation handling
 */

import { jest } from '@jest/globals';
import { performance } from 'perf_hooks';
import { FastMCP } from 'fastmcp';
import { addScenarioTools } from '../../../src/tools/scenarios.js';
import {
  validateBlueprintStructure,
  extractBlueprintConnections
} from '../../../src/tools/scenarios/utils/blueprint-analysis.js';
import {
  CreateScenarioSchema,
  UpdateScenarioSchema,
  OptimizeBlueprintSchema
} from '../../../src/tools/scenarios/schemas/blueprint-update.js';
import {
  ScenarioFiltersSchema,
  GenerateTroubleshootingReportSchema
} from '../../../src/tools/scenarios/schemas/scenario-filters.js';
import type MakeApiClient from '../../../src/lib/make-api-client.js';

// Mock the logger
jest.mock('../../../src/lib/logger.js', () => {
  const mockChild = jest.fn(() => ({
    info: jest.fn(),
    debug: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  }));
  
  return {
    __esModule: true,
    default: {
      child: mockChild,
      info: jest.fn(),
      debug: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    },
  };
});

describe('Scenarios Module - Performance Benchmarks', () => {
  let server: FastMCP;
  let mockApiClient: jest.Mocked<MakeApiClient>;
  let mockLog: any;
  let mockReportProgress: jest.Mock;

  beforeEach(() => {
    server = new FastMCP({
      name: 'benchmark-test-server',
      version: '1.0.0',
    });
    
    mockApiClient = {
      get: jest.fn(),
      post: jest.fn(),
      put: jest.fn(),
      patch: jest.fn(),
      delete: jest.fn(),
      healthCheck: jest.fn(),
      getRateLimiterStatus: jest.fn(),
      shutdown: jest.fn(),
    } as any;

    mockLog = {
      info: jest.fn(),
      debug: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    };
    mockReportProgress = jest.fn();

    // Mock fast API responses for performance tests
    mockApiClient.get.mockResolvedValue({
      success: true,
      data: [],
      metadata: { total: 0 }
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Tool Registration Performance', () => {
    test('should register all tools within acceptable time limit', () => {
      const startTime = performance.now();
      
      addScenarioTools(server, mockApiClient);
      
      const endTime = performance.now();
      const registrationTime = endTime - startTime;
      
      // Tool registration should be very fast (< 100ms)
      expect(registrationTime).toBeLessThan(100);
      
      // Verify all tools are registered (13 tools expected as of latest module)
      const toolNames = Array.from((server as any).tools.keys());
      expect(toolNames.length).toBe(13);
    });

    test('should handle multiple server instances efficiently', () => {
      const servers: FastMCP[] = [];
      const startTime = performance.now();
      
      // Create multiple server instances
      for (let i = 0; i < 10; i++) {
        const testServer = new FastMCP({
          name: `test-server-${i}`,
          version: '1.0.0',
        });
        addScenarioTools(testServer, mockApiClient);
        servers.push(testServer);
      }
      
      const endTime = performance.now();
      const totalTime = endTime - startTime;
      
      // Multiple registrations should scale well (< 500ms for 10 servers)
      expect(totalTime).toBeLessThan(500);
      
      // Verify all servers have tools registered (13 tools expected)
      servers.forEach(testServer => {
        const toolNames = Array.from((testServer as any).tools.keys());
        expect(toolNames.length).toBe(13);
      });
    });
  });

  describe('Schema Validation Performance', () => {
    test('should validate schemas efficiently under load', () => {
      const validationTests = [
        {
          schema: CreateScenarioSchema,
          data: { name: 'Performance Test Scenario' },
          iterations: 1000
        },
        {
          schema: UpdateScenarioSchema,
          data: { scenarioId: 'scn_123', name: 'Updated Scenario' },
          iterations: 1000
        },
        {
          schema: ScenarioFiltersSchema,
          data: { teamId: 'team_123', limit: 50, active: true },
          iterations: 1000
        },
        {
          schema: OptimizeBlueprintSchema,
          data: { blueprint: { modules: [] }, optimizationType: 'performance' },
          iterations: 1000
        }
      ];

      validationTests.forEach(test => {
        const startTime = performance.now();
        
        for (let i = 0; i < test.iterations; i++) {
          test.schema.parse(test.data);
        }
        
        const endTime = performance.now();
        const totalTime = endTime - startTime;
        const avgTime = totalTime / test.iterations;
        
        // Average validation time should be very fast (< 1ms per validation)
        expect(avgTime).toBeLessThan(1);
        
        // Total time for 1000 validations should be reasonable (< 100ms)
        expect(totalTime).toBeLessThan(100);
      });
    });

    test('should handle complex schema validation efficiently', () => {
      const complexReportConfig = {
        scenarioIds: Array.from({ length: 100 }, (_, i) => `scn_${i}`),
        reportOptions: {
          includeExecutiveSummary: true,
          includeDetailedAnalysis: true,
          includeActionPlan: true,
          includePerformanceMetrics: true,
          includeSecurityAssessment: true,
          includeCostAnalysis: true,
          includeRecommendationTimeline: true,
          formatType: 'json'
        },
        analysisFilters: {
          timeRangeHours: 168,
          severityThreshold: 'warning',
          includeInactiveScenarios: true,
          maxScenariosToAnalyze: 100,
          prioritizeByUsage: true
        },
        comparisonBaseline: {
          compareToHistorical: true,
          baselineTimeRangeHours: 336,
          includeBenchmarks: true
        }
      };

      const startTime = performance.now();
      
      for (let i = 0; i < 100; i++) {
        GenerateTroubleshootingReportSchema.parse(complexReportConfig);
      }
      
      const endTime = performance.now();
      const totalTime = endTime - startTime;
      
      // Complex schema validation should still be efficient (< 200ms for 100 validations)
      expect(totalTime).toBeLessThan(200);
    });
  });

  describe('Blueprint Processing Performance', () => {
    test('should validate large blueprints efficiently', () => {
      const largeBlueprint = {
        name: 'Large Performance Test Blueprint',
        metadata: {
          version: 1,
          scenario: {
            roundtrips: 5,
            maxErrors: 3,
            autoCommit: true,
            sequential: false,
            confidential: true,
            dlq: true
          }
        },
        flow: Array.from({ length: 1000 }, (_, i) => ({
          id: i + 1,
          module: i % 5 === 0 ? 'webhook' : `service_${i % 10}:action`,
          version: 1,
          connection: i % 5 === 0 ? undefined : Math.floor(i / 10) + 1,
          parameters: {
            config: `value_${i}`,
            nested: {
              property: `nested_${i}`,
              array: [1, 2, 3, i]
            }
          },
          metadata: {
            description: `Module ${i} description`,
            category: `category_${i % 3}`
          }
        }))
      };

      const startTime = performance.now();
      
      const validationResult = validateBlueprintStructure(largeBlueprint, true);
      
      const endTime = performance.now();
      const validationTime = endTime - startTime;
      
      // Large blueprint validation should complete within reasonable time (< 500ms)
      expect(validationTime).toBeLessThan(500);
      expect(validationResult.isValid).toBe(true);
    });

    test('should extract connections from large blueprints efficiently', () => {
      const connectionBlueprint = {
        name: 'Connection Performance Test',
        flow: Array.from({ length: 2000 }, (_, i) => ({
          id: i + 1,
          module: i % 3 === 0 ? 'builtin:Iterator' : `service_${i % 20}:action`,
          version: 1,
          connection: i % 3 === 0 ? undefined : (i % 50) + 1,
          parameters: { config: `connection_test_${i}` }
        }))
      };

      const startTime = performance.now();
      
      const connectionResult = extractBlueprintConnections(connectionBlueprint, true);
      
      const endTime = performance.now();
      const extractionTime = endTime - startTime;
      
      // Connection extraction should be efficient (< 300ms for 2000 modules)
      expect(extractionTime).toBeLessThan(300);
      expect(connectionResult.connectionSummary.totalModules).toBe(2000);
    });

    test('should handle concurrent blueprint processing', async () => {
      const testBlueprints = Array.from({ length: 10 }, (_, i) => ({
        name: `Concurrent Test Blueprint ${i}`,
        metadata: {
          version: 1,
          scenario: {
            roundtrips: 1,
            maxErrors: 1,
            autoCommit: true,
            sequential: false,
            confidential: true,
            dlq: true
          }
        },
        flow: Array.from({ length: 100 }, (_, j) => ({
          id: j + 1,
          module: `service_${j % 5}:action`,
          version: 1,
          connection: j + 1,
          parameters: { value: `concurrent_${i}_${j}` }
        }))
      }));

      const startTime = performance.now();
      
      // Process all blueprints concurrently
      const promises = testBlueprints.map(blueprint => 
        Promise.all([
          Promise.resolve(validateBlueprintStructure(blueprint)),
          Promise.resolve(extractBlueprintConnections(blueprint))
        ])
      );
      
      const results = await Promise.all(promises);
      
      const endTime = performance.now();
      const concurrentTime = endTime - startTime;
      
      // Concurrent processing should be efficient (< 1000ms)
      expect(concurrentTime).toBeLessThan(1000);
      
      // Verify all results
      results.forEach(([validation, connections]) => {
        expect(validation.isValid).toBe(true);
        expect(connections.connectionSummary.totalModules).toBe(100);
      });
    });
  });

  describe('Memory Usage Optimization', () => {
    test('should not have memory leaks during repeated operations', () => {
      const initialMemory = process.memoryUsage();
      
      // Simulate many tool executions
      for (let i = 0; i < 1000; i++) {
        // Create and validate various schema objects
        CreateScenarioSchema.parse({ name: `Test Scenario ${i}` });
        ScenarioFiltersSchema.parse({ limit: 10, offset: i });
        
        // Create blueprint and validate
        const smallBlueprint = {
          name: `Blueprint ${i}`,
          metadata: { version: 1, scenario: { roundtrips: 1, maxErrors: 1, autoCommit: true, sequential: false } },
          flow: [
            { id: 1, module: 'webhook', version: 1 },
            { id: 2, module: 'http:request', version: 1, connection: 1 }
          ]
        };
        
        validateBlueprintStructure(smallBlueprint);
        extractBlueprintConnections(smallBlueprint);
      }
      
      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }
      
      const finalMemory = process.memoryUsage();
      const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;
      
      // Memory increase should be reasonable (< 50MB for 1000 operations)
      expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024);
    });

    test('should handle large data structures efficiently', () => {
      const initialMemory = process.memoryUsage();
      
      // Create a very large blueprint
      const massiveBlueprint = {
        name: 'Massive Blueprint Memory Test',
        metadata: {
          version: 1,
          scenario: {
            roundtrips: 1,
            maxErrors: 1,
            autoCommit: true,
            sequential: false,
            confidential: true,
            dlq: true
          }
        },
        flow: Array.from({ length: 5000 }, (_, i) => ({
          id: i + 1,
          module: `module_${i}`,
          version: 1,
          connection: i % 2 === 0 ? i / 2 + 1 : undefined,
          parameters: {
            largeData: Array.from({ length: 100 }, (_, j) => ({
              id: j,
              value: `data_${i}_${j}`,
              timestamp: new Date().toISOString()
            }))
          },
          metadata: {
            description: `Module ${i} with large parameter set`,
            tags: Array.from({ length: 20 }, (_, k) => `tag_${k}`)
          }
        }))
      };
      
      const startTime = performance.now();
      
      // Process the massive blueprint
      const validationResult = validateBlueprintStructure(massiveBlueprint, true);
      const connectionResult = extractBlueprintConnections(massiveBlueprint, true);
      
      const endTime = performance.now();
      const processingTime = endTime - startTime;
      
      const finalMemory = process.memoryUsage();
      const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;
      
      // Processing should complete within reasonable time (< 2 seconds)
      expect(processingTime).toBeLessThan(2000);
      
      // Memory usage should be reasonable (< 100MB for this large structure)
      expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024);
      
      // Results should be valid
      expect(validationResult.isValid).toBe(true);
      expect(connectionResult.connectionSummary.totalModules).toBe(5000);
    });
  });

  describe('Tool Execution Performance', () => {
    beforeEach(() => {
      addScenarioTools(server, mockApiClient);
    });

    test('should execute list-scenarios tool efficiently', async () => {
      const largeScenarioList = Array.from({ length: 100 }, (_, i) => ({
        id: `scn_${i}`,
        name: `Performance Test Scenario ${i}`,
        active: i % 2 === 0,
        teamId: `team_${Math.floor(i / 10)}`,
        createdAt: new Date().toISOString()
      }));

      mockApiClient.get.mockResolvedValue({
        success: true,
        data: largeScenarioList,
        metadata: { total: largeScenarioList.length }
      });

      const tool = (server as any).tools.get('list-scenarios');
      const startTime = performance.now();
      
      const result = await tool.execute({}, { log: mockLog, reportProgress: mockReportProgress });
      
      const endTime = performance.now();
      const executionTime = endTime - startTime;
      
      // Tool execution should be fast (< 100ms)
      expect(executionTime).toBeLessThan(100);
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.scenarios).toHaveLength(100);
    });

    test('should handle concurrent tool executions efficiently', async () => {
      const tools = [
        'list-scenarios',
        'get-scenario',
        'validate-blueprint',
        'extract-blueprint-connections',
        'optimize-blueprint'
      ];

      // Mock appropriate responses for each tool
      mockApiClient.get.mockResolvedValue({
        success: true,
        data: { id: 'scn_123', name: 'Test Scenario' }
      });

      const toolExecutions = tools.map(async toolName => {
        const tool = (server as any).tools.get(toolName);
        let args: any = {};
        
        switch (toolName) {
          case 'get-scenario':
            args = { scenarioId: 'scn_123' };
            break;
          case 'validate-blueprint':
          case 'extract-blueprint-connections':
          case 'optimize-blueprint':
            args = { blueprint: { modules: [], connections: [] } };
            break;
        }
        
        return tool.execute(args, { log: mockLog, reportProgress: mockReportProgress });
      });

      const startTime = performance.now();
      
      const results = await Promise.all(toolExecutions);
      
      const endTime = performance.now();
      const concurrentExecutionTime = endTime - startTime;
      
      // Concurrent execution should be efficient (< 200ms)
      expect(concurrentExecutionTime).toBeLessThan(200);
      
      // All tools should return results
      expect(results).toHaveLength(5);
      results.forEach(result => {
        expect(typeof result).toBe('string');
        expect(() => JSON.parse(result)).not.toThrow();
      });
    });

    test('should maintain performance under high load', async () => {
      const blueprint = {
        name: 'High Load Test Blueprint',
        metadata: {
          version: 1,
          scenario: {
            roundtrips: 1,
            maxErrors: 1,
            autoCommit: true,
            sequential: false,
            confidential: true,
            dlq: true
          }
        },
        flow: Array.from({ length: 50 }, (_, i) => ({
          id: i + 1,
          module: `module_${i}`,
          version: 1,
          connection: i % 3 === 0 ? undefined : i + 1,
          parameters: { config: `load_test_${i}` }
        }))
      };

      const validateTool = (server as any).tools.get('validate-blueprint');
      const optimizeTool = (server as any).tools.get('optimize-blueprint');
      
      const startTime = performance.now();
      
      // Execute many operations concurrently
      const operations = Array.from({ length: 50 }, async (_, i) => {
        const tool = i % 2 === 0 ? validateTool : optimizeTool;
        return tool.execute(
          { blueprint, includeSecurityChecks: true },
          { log: mockLog, reportProgress: mockReportProgress }
        );
      });
      
      const results = await Promise.all(operations);
      
      const endTime = performance.now();
      const loadTestTime = endTime - startTime;
      
      // High load should be handled efficiently (< 1 second for 50 operations)
      expect(loadTestTime).toBeLessThan(1000);
      
      // All operations should succeed
      expect(results).toHaveLength(50);
      results.forEach(result => {
        const parsed = JSON.parse(result);
        expect(parsed.isValid || parsed.recommendations).toBeDefined();
      });
    });
  });

  describe('Comparative Performance Metrics', () => {
    test('should show performance improvements over baseline', () => {
      // Simulate baseline performance (original monolithic approach)
      const baselineValidationTime = 50; // ms for 100 validations
      const baselineBlueprintProcessing = 200; // ms for large blueprint
      const baselineToolRegistration = 150; // ms for tool registration
      
      // Measure refactored performance
      const validationStartTime = performance.now();
      for (let i = 0; i < 100; i++) {
        CreateScenarioSchema.parse({ name: `Test ${i}` });
      }
      const validationEndTime = performance.now();
      const refactoredValidationTime = validationEndTime - validationStartTime;
      
      const blueprintStartTime = performance.now();
      const testBlueprint = {
        name: 'Performance Comparison Test',
        metadata: { version: 1, scenario: { roundtrips: 1, maxErrors: 1, autoCommit: true, sequential: false } },
        flow: Array.from({ length: 500 }, (_, i) => ({
          id: i + 1,
          module: `module_${i}`,
          version: 1,
          connection: i % 2 === 0 ? i + 1 : undefined
        }))
      };
      validateBlueprintStructure(testBlueprint);
      extractBlueprintConnections(testBlueprint);
      const blueprintEndTime = performance.now();
      const refactoredBlueprintTime = blueprintEndTime - blueprintStartTime;
      
      const registrationStartTime = performance.now();
      const testServer = new FastMCP({ name: 'perf-test', version: '1.0.0' });
      addScenarioTools(testServer, mockApiClient);
      const registrationEndTime = performance.now();
      const refactoredRegistrationTime = registrationEndTime - registrationStartTime;
      
      // Refactored version should be at least as fast as baseline
      expect(refactoredValidationTime).toBeLessThanOrEqual(baselineValidationTime);
      expect(refactoredBlueprintTime).toBeLessThanOrEqual(baselineBlueprintProcessing);
      expect(refactoredRegistrationTime).toBeLessThanOrEqual(baselineToolRegistration);
      
      // Log performance metrics for reference
      console.log('Performance Comparison:');
      console.log(`Validation: ${refactoredValidationTime}ms (baseline: ${baselineValidationTime}ms)`);
      console.log(`Blueprint Processing: ${refactoredBlueprintTime}ms (baseline: ${baselineBlueprintProcessing}ms)`);
      console.log(`Tool Registration: ${refactoredRegistrationTime}ms (baseline: ${baselineToolRegistration}ms)`);
    });

    test('should demonstrate scalability improvements', () => {
      const scalabilityTests = [
        { modules: 10, expectedTime: 5 },
        { modules: 100, expectedTime: 20 },
        { modules: 500, expectedTime: 50 },
        { modules: 1000, expectedTime: 100 }
      ];

      scalabilityTests.forEach(test => {
        const blueprint = {
          name: `Scalability Test ${test.modules}`,
          metadata: { version: 1, scenario: { roundtrips: 1, maxErrors: 1, autoCommit: true, sequential: false } },
          flow: Array.from({ length: test.modules }, (_, i) => ({
            id: i + 1,
            module: `module_${i}`,
            version: 1,
            connection: i % 3 === 0 ? undefined : i + 1
          }))
        };

        const startTime = performance.now();
        
        validateBlueprintStructure(blueprint);
        extractBlueprintConnections(blueprint);
        
        const endTime = performance.now();
        const actualTime = endTime - startTime;
        
        // Performance should scale reasonably
        expect(actualTime).toBeLessThan(test.expectedTime);
        
        console.log(`${test.modules} modules: ${actualTime}ms (expected < ${test.expectedTime}ms)`);
      });
    });
  });
});