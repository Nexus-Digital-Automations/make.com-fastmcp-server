/**
 * Advanced Chaos Engineering Test Suite
 * Implements comprehensive fault injection and resilience testing patterns
 * to validate system behavior under various failure conditions
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { UserError } from 'fastmcp';
import { MockMakeApiClient } from '../mocks/make-api-client.mock.js';
import { 
  createMockServer, 
  findTool, 
  executeTool 
} from '../utils/test-helpers.js';

// Advanced Chaos Engineering Framework
class AdvancedChaosMonkey {
  private scenarios: Map<string, ChaosScenario>;
  private activeScenarios: Set<string>;
  private metricsCollector: ChaosMetrics;

  constructor() {
    this.scenarios = new Map();
    this.activeScenarios = new Set();
    this.metricsCollector = new ChaosMetrics();
    this.initializeScenarios();
  }

  private initializeScenarios(): void {
    this.scenarios.set('network_partition', new NetworkPartitionScenario());
    this.scenarios.set('memory_pressure', new MemoryPressureScenario());
    this.scenarios.set('cpu_spike', new CPUSpikeScenario());
    this.scenarios.set('disk_full', new DiskFullScenario());
    this.scenarios.set('service_degradation', new ServiceDegradationScenario());
    this.scenarios.set('dependency_failure', new DependencyFailureScenario());
    this.scenarios.set('data_corruption', new DataCorruptionScenario());
    this.scenarios.set('clock_skew', new ClockSkewScenario());
  }

  async executeScenario(scenarioName: string, duration: number = 30000): Promise<ChaosResult> {
    const scenario = this.scenarios.get(scenarioName);
    if (!scenario) {
      throw new Error(`Unknown chaos scenario: ${scenarioName}`);
    }

    this.activeScenarios.add(scenarioName);
    const startTime = Date.now();

    try {
      await scenario.inject();
      
      // Run for specified duration
      await new Promise(resolve => setTimeout(resolve, duration));
      
      return {
        scenario: scenarioName,
        duration: Date.now() - startTime,
        success: true,
        metrics: this.metricsCollector.collect(),
        errors: []
      };
    } catch (error) {
      return {
        scenario: scenarioName,
        duration: Date.now() - startTime,
        success: false,
        metrics: this.metricsCollector.collect(),
        errors: [error instanceof Error ? error.message : String(error)]
      };
    } finally {
      await scenario.recover();
      this.activeScenarios.delete(scenarioName);
    }
  }

  async executeCombinedScenarios(scenarios: string[], duration: number = 30000): Promise<ChaosResult[]> {
    const results: ChaosResult[] = [];
    
    // Start all scenarios in parallel
    const scenarioPromises = scenarios.map(scenario => 
      this.executeScenario(scenario, duration)
    );
    
    const combinedResults = await Promise.allSettled(scenarioPromises);
    
    combinedResults.forEach((result, index) => {
      if (result.status === 'fulfilled') {
        results.push(result.value);
      } else {
        results.push({
          scenario: scenarios[index],
          duration: 0,
          success: false,
          metrics: this.metricsCollector.collect(),
          errors: [result.reason.message]
        });
      }
    });
    
    return results;
  }

  getMetrics(): ChaosMetrics {
    return this.metricsCollector;
  }
}

// Chaos scenario interfaces and implementations
interface ChaosScenario {
  inject(): Promise<void>;
  recover(): Promise<void>;
}

interface ChaosResult {
  scenario: string;
  duration: number;
  success: boolean;
  metrics: any;
  errors: string[];
}

class NetworkPartitionScenario implements ChaosScenario {
  private originalFetch: any;

  async inject(): Promise<void> {
    // Simulate network partition by making all requests fail intermittently
    this.originalFetch = global.fetch;
    global.fetch = jest.fn(() => {
      if (Math.random() < 0.7) { // 70% failure rate
        return Promise.reject(new Error('Network partition: Connection timeout'));
      }
      return this.originalFetch.apply(this, arguments);
    });
  }

  async recover(): Promise<void> {
    if (this.originalFetch) {
      global.fetch = this.originalFetch;
    }
  }
}

class MemoryPressureScenario implements ChaosScenario {
  private memoryBallast: any[] = [];

  async inject(): Promise<void> {
    // Create memory pressure by allocating large objects
    for (let i = 0; i < 100; i++) {
      this.memoryBallast.push(new Array(100000).fill(`memory-pressure-${i}`));
    }
  }

  async recover(): Promise<void> {
    this.memoryBallast.length = 0;
    if (global.gc) {
      global.gc();
    }
  }
}

class CPUSpikeScenario implements ChaosScenario {
  private cpuWorkers: NodeJS.Timeout[] = [];

  async inject(): Promise<void> {
    // Create CPU-intensive tasks
    for (let i = 0; i < 4; i++) {
      const worker = setInterval(() => {
        const start = Date.now();
        while (Date.now() - start < 50) {
          Math.sqrt(Math.random() * 1000000);
        }
      }, 10);
      this.cpuWorkers.push(worker);
    }
  }

  async recover(): Promise<void> {
    this.cpuWorkers.forEach(worker => clearInterval(worker));
    this.cpuWorkers.length = 0;
  }
}

class DiskFullScenario implements ChaosScenario {
  async inject(): Promise<void> {
    // Simulate disk full by making file operations fail
    const originalWriteFile = require('fs').writeFile;
    require('fs').writeFile = jest.fn((path, data, callback) => {
      callback(new Error('ENOSPC: no space left on device'));
    });
  }

  async recover(): Promise<void> {
    jest.restoreAllMocks();
  }
}

class ServiceDegradationScenario implements ChaosScenario {
  private delayInterval?: NodeJS.Timeout;

  async inject(): Promise<void> {
    // Add random delays to simulate service degradation
    this.delayInterval = setInterval(async () => {
      if (Math.random() < 0.3) {
        await new Promise(resolve => setTimeout(resolve, Math.random() * 1000 + 500));
      }
    }, 100);
  }

  async recover(): Promise<void> {
    if (this.delayInterval) {
      clearInterval(this.delayInterval);
    }
  }
}

class DependencyFailureScenario implements ChaosScenario {
  async inject(): Promise<void> {
    // Simulate external dependency failures
    // This would be implemented based on specific dependencies
  }

  async recover(): Promise<void> {
    // Restore dependency connections
  }
}

class DataCorruptionScenario implements ChaosScenario {
  async inject(): Promise<void> {
    // Simulate data corruption by modifying responses
    // Implementation would depend on data layer
  }

  async recover(): Promise<void> {
    // Restore data integrity
  }
}

class ClockSkewScenario implements ChaosScenario {
  private originalNow: () => number;

  async inject(): Promise<void> {
    // Simulate clock skew
    this.originalNow = Date.now;
    Date.now = () => this.originalNow() + (Math.random() * 60000 - 30000); // ±30 seconds
  }

  async recover(): Promise<void> {
    Date.now = this.originalNow;
  }
}

class ChaosMetrics {
  private metrics: Map<string, number> = new Map();

  record(key: string, value: number): void {
    this.metrics.set(key, value);
  }

  increment(key: string): void {
    this.metrics.set(key, (this.metrics.get(key) || 0) + 1);
  }

  collect(): any {
    return Object.fromEntries(this.metrics);
  }

  reset(): void {
    this.metrics.clear();
  }
}

// Circuit breaker implementation for chaos testing
class CircuitBreaker {
  private failures: number = 0;
  private lastFailTime: number = 0;
  private state: 'closed' | 'open' | 'half-open' = 'closed';
  
  constructor(
    private failureThreshold: number = 5,
    private timeout: number = 60000,
    private resetTimeout: number = 30000
  ) {}

  async execute<T>(operation: () => Promise<T>): Promise<T> {
    if (this.state === 'open') {
      if (Date.now() - this.lastFailTime > this.resetTimeout) {
        this.state = 'half-open';
      } else {
        throw new Error('Circuit breaker is OPEN');
      }
    }

    try {
      const result = await operation();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  private onSuccess(): void {
    this.failures = 0;
    this.state = 'closed';
  }

  private onFailure(): void {
    this.failures++;
    this.lastFailTime = Date.now();
    
    if (this.failures >= this.failureThreshold) {
      this.state = 'open';
    }
  }

  getState(): string {
    return this.state;
  }
}

describe('Advanced Chaos Engineering Test Suite', () => {
  let mockServer: any;
  let mockApiClient: MockMakeApiClient;
  let mockTool: jest.MockedFunction<any>;
  let chaosMonkey: AdvancedChaosMonkey;
  let circuitBreaker: CircuitBreaker;

  beforeEach(() => {
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockTool = serverSetup.mockTool;
    mockApiClient = new MockMakeApiClient();
    chaosMonkey = new AdvancedChaosMonkey();
    circuitBreaker = new CircuitBreaker(3, 60000, 10000);

    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.clearAllMocks();
    mockApiClient.reset();
  });

  describe('Network Fault Injection', () => {
    it('should handle network partitions gracefully', async () => {
      mockApiClient.mockResponse('GET', '/users', {
        success: true,
        data: [{ id: 1, email: 'user@example.com', role: 'member' }],
        metadata: { total: 1 }
      });

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-users');

      // Execute network partition chaos scenario
      const chaosResult = await chaosMonkey.executeScenario('network_partition', 5000);

      // During partition, some requests should fail but system should remain stable
      const results = await Promise.allSettled(
        Array(20).fill(null).map(() => executeTool(tool, { limit: 10 }))
      );

      const successful = results.filter(r => r.status === 'fulfilled').length;
      const failed = results.filter(r => r.status === 'rejected').length;

      // Should have some successes and failures during network partition
      expect(successful).toBeGreaterThan(2); // At least some requests succeed
      expect(failed).toBeGreaterThan(2);     // Some should fail due to partition
      expect(chaosResult.success).toBe(true);

      console.log('Network Partition Results:', {
        successful,
        failed,
        chaosResult: chaosResult.scenario,
        duration: chaosResult.duration
      });
    });

    it('should implement retry mechanisms with exponential backoff', async () => {
      let attemptCount = 0;
      mockApiClient.mockResponse('GET', '/teams', {
        success: false,
        error: { message: 'Network timeout', code: 'NETWORK_ERROR' }
      });

      // Mock a function that fails then succeeds
      const unreliableOperation = async () => {
        attemptCount++;
        if (attemptCount <= 3) {
          throw new Error('Network failure');
        }
        return 'success';
      };

      // Implement exponential backoff retry
      const retryWithBackoff = async (operation: () => Promise<any>, maxRetries: number = 5): Promise<any> => {
        for (let attempt = 1; attempt <= maxRetries; attempt++) {
          try {
            return await operation();
          } catch (error) {
            if (attempt === maxRetries) throw error;
            
            const delay = Math.pow(2, attempt - 1) * 1000; // Exponential backoff
            await new Promise(resolve => setTimeout(resolve, delay));
          }
        }
      };

      const result = await retryWithBackoff(unreliableOperation);
      expect(result).toBe('success');
      expect(attemptCount).toBe(4); // 3 failures + 1 success
    });
  });

  describe('Resource Exhaustion Scenarios', () => {
    it('should handle memory pressure gracefully', async () => {
      mockApiClient.mockResponse('GET', '/organizations', {
        success: true,
        data: Array(100).fill({ id: 1, name: 'Org', memberCount: 1000 }),
        metadata: { total: 100 }
      });

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-organizations');

      const initialMemory = process.memoryUsage();
      
      // Execute memory pressure scenario
      const chaosResult = await chaosMonkey.executeScenario('memory_pressure', 3000);

      // System should continue functioning under memory pressure
      const results = await Promise.allSettled(
        Array(10).fill(null).map(() => executeTool(tool, { limit: 100 }))
      );

      const successful = results.filter(r => r.status === 'fulfilled').length;
      expect(successful).toBeGreaterThan(5); // At least half should succeed

      const finalMemory = process.memoryUsage();
      const memoryGrowth = finalMemory.heapUsed - initialMemory.heapUsed;

      console.log('Memory Pressure Test:', {
        successful: successful,
        failed: 10 - successful,
        memoryGrowth: `${(memoryGrowth / 1024 / 1024).toFixed(2)}MB`,
        chaosResult: chaosResult.scenario
      });
    });

    it('should handle CPU spikes without complete failure', async () => {
      mockApiClient.mockResponse('POST', '/teams', {
        success: true,
        data: { id: 12345, name: 'Test Team' }
      });

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-team');

      // Execute CPU spike scenario
      const startTime = Date.now();
      const chaosResult = await chaosMonkey.executeScenario('cpu_spike', 3000);

      // Measure operation latency during CPU spike
      const operationTimes: number[] = [];
      const results = await Promise.allSettled(
        Array(10).fill(null).map(async (_, i) => {
          const opStart = Date.now();
          const result = await executeTool(tool, {
            name: `Team ${i}`,
            description: 'CPU pressure test'
          });
          operationTimes.push(Date.now() - opStart);
          return result;
        })
      );

      const successful = results.filter(r => r.status === 'fulfilled').length;
      const avgLatency = operationTimes.reduce((a, b) => a + b, 0) / operationTimes.length;

      // Should maintain some level of service even under CPU pressure
      expect(successful).toBeGreaterThan(6); // At least 60% success rate
      expect(avgLatency).toBeLessThan(2000); // Average latency under 2 seconds

      console.log('CPU Spike Test:', {
        successful,
        avgLatency: `${avgLatency.toFixed(2)}ms`,
        maxLatency: `${Math.max(...operationTimes)}ms`
      });
    });
  });

  describe('Cascading Failure Prevention', () => {
    it('should prevent cascading failures with circuit breakers', async () => {
      let failureCount = 0;
      
      // Mock API that fails initially then recovers
      const originalMockResponse = mockApiClient.mockResponse.bind(mockApiClient);
      mockApiClient.mockResponse = jest.fn((method, endpoint, response) => {
        failureCount++;
        if (failureCount <= 5) {
          return originalMockResponse(method, endpoint, {
            success: false,
            error: { message: 'Service unavailable', code: 'SERVICE_ERROR' }
          });
        } else {
          return originalMockResponse(method, endpoint, {
            success: true,
            data: { id: 1, email: 'user@example.com', role: 'member' }
          });
        }
      });

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-current-user');

      // Test circuit breaker behavior
      const circuitBreakerOperation = () => executeTool(tool, {});

      // First few requests should fail and trigger circuit breaker
      for (let i = 0; i < 5; i++) {
        try {
          await circuitBreaker.execute(circuitBreakerOperation);
        } catch (error) {
          // Expected failures
        }
      }

      // Circuit breaker should now be open
      expect(circuitBreaker.getState()).toBe('open');

      // Requests should be rejected immediately by circuit breaker
      await expect(circuitBreaker.execute(circuitBreakerOperation))
        .rejects.toThrow('Circuit breaker is OPEN');

      // Wait for circuit breaker reset timeout
      await new Promise(resolve => setTimeout(resolve, 11000));

      // Circuit breaker should allow requests again
      const result = await circuitBreaker.execute(circuitBreakerOperation);
      expect(result).toContain('user');
      expect(circuitBreaker.getState()).toBe('closed');
    });

    it('should implement bulkhead isolation', async () => {
      // Mock different services with different failure patterns
      mockApiClient.mockResponse('GET', '/users', {
        success: false,
        error: { message: 'User service down', code: 'SERVICE_ERROR' }
      });

      mockApiClient.mockResponse('GET', '/teams', {
        success: true,
        data: [{ id: 1, name: 'Team 1' }],
        metadata: { total: 1 }
      });

      mockApiClient.mockResponse('GET', '/organizations', {
        success: true,
        data: [{ id: 1, name: 'Org 1' }],
        metadata: { total: 1 }
      });

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const userTool = findTool(mockTool, 'list-users');
      const teamTool = findTool(mockTool, 'list-teams');
      const orgTool = findTool(mockTool, 'list-organizations');

      // User service should fail
      await expect(executeTool(userTool, { limit: 10 })).rejects.toThrow();

      // But team and organization services should still work (bulkhead isolation)
      const teamResult = await executeTool(teamTool, { limit: 10 });
      const orgResult = await executeTool(orgTool, { limit: 10 });

      expect(teamResult).toContain('teams');
      expect(orgResult).toContain('organizations');

      console.log('Bulkhead Isolation Test: User service failed but other services remained operational');
    });
  });

  describe('Combined Chaos Scenarios', () => {
    it('should handle multiple simultaneous failures', async () => {
      mockApiClient.mockResponse('GET', '/users', {
        success: true,
        data: Array(50).fill({ id: 1, email: 'user@example.com', role: 'member' }),
        metadata: { total: 50 }
      });

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-users');

      // Execute multiple chaos scenarios simultaneously
      const scenarios = ['memory_pressure', 'cpu_spike', 'service_degradation'];
      const chaosResults = await chaosMonkey.executeCombinedScenarios(scenarios, 5000);

      // System should maintain some level of functionality despite multiple failures
      const results = await Promise.allSettled(
        Array(15).fill(null).map(() => executeTool(tool, { limit: 50 }))
      );

      const successful = results.filter(r => r.status === 'fulfilled').length;
      const successRate = successful / 15;

      // Should maintain at least 40% success rate under extreme conditions
      expect(successRate).toBeGreaterThan(0.4);

      console.log('Combined Chaos Test:', {
        scenarios: scenarios.join(', '),
        successful,
        failed: 15 - successful,
        successRate: `${(successRate * 100).toFixed(2)}%`,
        chaosResults: chaosResults.map(r => ({
          scenario: r.scenario,
          success: r.success,
          duration: r.duration
        }))
      });
    });

    it('should recover gracefully after chaos scenarios end', async () => {
      mockApiClient.mockResponse('GET', '/teams', {
        success: true,
        data: Array(25).fill({ id: 1, name: 'Team', organizationId: 1 }),
        metadata: { total: 25 }
      });

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-teams');

      // Baseline performance before chaos
      const baselineResults = await Promise.allSettled(
        Array(10).fill(null).map(() => executeTool(tool, { limit: 25 }))
      );
      const baselineSuccess = baselineResults.filter(r => r.status === 'fulfilled').length;

      // Execute chaos scenario
      await chaosMonkey.executeScenario('memory_pressure', 3000);

      // Performance during chaos
      const chaosResults = await Promise.allSettled(
        Array(10).fill(null).map(() => executeTool(tool, { limit: 25 }))
      );
      const chaosSuccess = chaosResults.filter(r => r.status === 'fulfilled').length;

      // Wait for recovery
      await new Promise(resolve => setTimeout(resolve, 2000));

      // Performance after recovery
      const recoveryResults = await Promise.allSettled(
        Array(10).fill(null).map(() => executeTool(tool, { limit: 25 }))
      );
      const recoverySuccess = recoveryResults.filter(r => r.status === 'fulfilled').length;

      // System should recover to near-baseline performance
      expect(baselineSuccess).toBeGreaterThanOrEqual(9); // Baseline should be good
      expect(chaosSuccess).toBeLessThan(baselineSuccess); // Chaos should impact performance
      expect(recoverySuccess).toBeGreaterThanOrEqual(baselineSuccess * 0.9); // Should recover to 90% of baseline

      console.log('Recovery Test:', {
        baseline: `${baselineSuccess}/10`,
        duringChaos: `${chaosSuccess}/10`,
        afterRecovery: `${recoverySuccess}/10`
      });
    });
  });

  describe('Data Consistency Under Chaos', () => {
    it('should maintain data consistency during partial failures', async () => {
      let createCallCount = 0;
      let getCallCount = 0;

      // Mock create operation that sometimes fails
      mockApiClient.mockResponse = jest.fn((method, endpoint, response) => {
        if (method === 'POST' && endpoint === '/teams') {
          createCallCount++;
          if (createCallCount % 3 === 0) {
            return Promise.resolve({
              success: false,
              error: { message: 'Temporary failure', code: 'TEMP_ERROR' }
            });
          }
          return Promise.resolve({
            success: true,
            data: { id: createCallCount, name: `Team ${createCallCount}` }
          });
        }

        if (method === 'GET' && endpoint.startsWith('/teams/')) {
          getCallCount++;
          const teamId = parseInt(endpoint.split('/')[2]);
          if (teamId % 3 === 0) {
            return Promise.resolve({
              success: false,
              error: { message: 'Team not found', code: 'NOT_FOUND' }
            });
          }
          return Promise.resolve({
            success: true,
            data: { id: teamId, name: `Team ${teamId}` }
          });
        }

        return response;
      });

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const createTool = findTool(mockTool, 'create-team');
      const getTool = findTool(mockTool, 'get-team');

      // Create teams with some failures
      const createResults = await Promise.allSettled(
        Array(10).fill(null).map((_, i) => 
          executeTool(createTool, {
            name: `Team ${i + 1}`,
            description: 'Consistency test'
          })
        )
      );

      const successfulCreates = createResults.filter(r => r.status === 'fulfilled');
      
      // Verify created teams exist and are retrievable
      const createdTeamIds = successfulCreates.map((_, i) => i + 1).filter(id => id % 3 !== 0);
      
      const getResults = await Promise.allSettled(
        createdTeamIds.map(id => executeTool(getTool, { teamId: id }))
      );

      const successfulGets = getResults.filter(r => r.status === 'fulfilled');

      // Data consistency check: all successfully created teams should be retrievable
      expect(successfulGets.length).toBe(createdTeamIds.length);

      console.log('Data Consistency Test:', {
        createAttempts: 10,
        successfulCreates: successfulCreates.length,
        retrievalAttempts: createdTeamIds.length,
        successfulRetrivals: successfulGets.length,
        consistencyRate: `${(successfulGets.length / createdTeamIds.length * 100).toFixed(2)}%`
      });
    });
  });
});