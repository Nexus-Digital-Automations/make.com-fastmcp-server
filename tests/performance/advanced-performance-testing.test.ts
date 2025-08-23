/**
 * Advanced Performance Testing Suite
 * Implements comprehensive performance testing patterns including load testing,
 * stress testing, and chaos engineering for performance validation
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { MockMakeApiClient } from '../mocks/make-api-client.mock.js';
import { 
  createMockServer, 
  findTool, 
  executeTool 
} from '../utils/test-helpers.js';

// Performance testing utilities
class StressTest {
  private concurrent: number;
  private duration: number;
  private rampUp: number;

  constructor(config: { concurrent?: number; duration?: number; rampUp?: number }) {
    this.concurrent = config.concurrent || 100;
    this.duration = config.duration || 60000;
    this.rampUp = config.rampUp || 10000;
  }

  async run(testFunction: () => Promise<any>): Promise<{
    successful: number;
    failed: number;
    latencies: number[];
    errors: string[];
    avgLatency: number;
    p95Latency: number;
    p99Latency: number;
    successRate: number;
  }> {
    const results = {
      successful: 0,
      failed: 0,
      latencies: [] as number[],
      errors: [] as string[]
    };

    const startTime = Date.now();
    const workers: Promise<void>[] = [];

    // Ramp up workers gradually
    for (let i = 0; i < this.concurrent; i++) {
      await new Promise(resolve => 
        setTimeout(resolve, this.rampUp / this.concurrent)
      );
      
      workers.push(this.worker(testFunction, results, startTime));
    }

    await Promise.all(workers);

    return {
      ...results,
      avgLatency: results.latencies.length > 0 
        ? results.latencies.reduce((a, b) => a + b, 0) / results.latencies.length 
        : 0,
      p95Latency: this.percentile(results.latencies, 0.95),
      p99Latency: this.percentile(results.latencies, 0.99),
      successRate: results.successful / (results.successful + results.failed)
    };
  }

  private async worker(
    testFunction: () => Promise<any>, 
    results: { successful: number; failed: number; latencies: number[]; errors: string[] }, 
    startTime: number
  ): Promise<void> {
    while (Date.now() - startTime < this.duration) {
      const requestStart = Date.now();
      
      try {
        await testFunction();
        results.successful++;
        results.latencies.push(Date.now() - requestStart);
      } catch (error) {
        results.failed++;
        results.errors.push(error instanceof Error ? error.message : String(error));
      }
      
      // Small delay to prevent overwhelming
      await new Promise(resolve => setTimeout(resolve, 1));
    }
  }

  private percentile(arr: number[], p: number): number {
    if (arr.length === 0) return 0;
    const sorted = [...arr].sort((a, b) => a - b);
    const index = Math.ceil(sorted.length * p) - 1;
    return sorted[Math.max(0, index)];
  }
}

// Memory usage tracker
class MemoryTracker {
  private baseline: NodeJS.MemoryUsage;
  private samples: NodeJS.MemoryUsage[] = [];

  constructor() {
    this.baseline = process.memoryUsage();
  }

  sample(): void {
    this.samples.push(process.memoryUsage());
  }

  getStats(): {
    peakHeapUsed: number;
    avgHeapUsed: number;
    heapGrowth: number;
    peakRSS: number;
    avgRSS: number;
    rssGrowth: number;
  } {
    if (this.samples.length === 0) {
      return {
        peakHeapUsed: 0,
        avgHeapUsed: 0,
        heapGrowth: 0,
        peakRSS: 0,
        avgRSS: 0,
        rssGrowth: 0
      };
    }

    const heapUsed = this.samples.map(s => s.heapUsed);
    const rss = this.samples.map(s => s.rss);

    return {
      peakHeapUsed: Math.max(...heapUsed),
      avgHeapUsed: heapUsed.reduce((a, b) => a + b, 0) / heapUsed.length,
      heapGrowth: Math.max(...heapUsed) - this.baseline.heapUsed,
      peakRSS: Math.max(...rss),
      avgRSS: rss.reduce((a, b) => a + b, 0) / rss.length,
      rssGrowth: Math.max(...rss) - this.baseline.rss
    };
  }
}

// Performance chaos engineering
class PerformanceChaos {
  async simulateSlowNetwork(delayMs: number = 1000): Promise<void> {
    await new Promise(resolve => setTimeout(resolve, delayMs));
  }

  async simulateMemoryPressure(): Promise<void> {
    // Simulate memory pressure by creating large objects
    const memoryPressure: any[] = [];
    for (let i = 0; i < 1000; i++) {
      memoryPressure.push(new Array(1000).fill('memory-pressure-test'));
    }
    
    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }
    
    // Clean up
    memoryPressure.length = 0;
  }

  async simulateCPUIntensiveTask(): Promise<void> {
    const start = Date.now();
    while (Date.now() - start < 100) {
      // CPU intensive calculation
      Math.sqrt(Math.random() * 1000000);
    }
  }
}

describe('Advanced Performance Testing Suite', () => {
  let mockServer: any;
  let mockApiClient: MockMakeApiClient;
  let mockTool: jest.MockedFunction<any>;
  let memoryTracker: MemoryTracker;
  let chaos: PerformanceChaos;

  // Set longer timeout for performance tests
  beforeAll(() => {
    jest.setTimeout(180000); // 3 minutes for complex performance tests
  });

  afterAll(() => {
    jest.setTimeout(5000); // Reset to default
  });

  beforeEach(() => {
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockTool = serverSetup.mockTool;
    mockApiClient = new MockMakeApiClient();
    memoryTracker = new MemoryTracker();
    chaos = new PerformanceChaos();

    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.clearAllMocks();
    mockApiClient.reset();
  });

  describe('Load Testing', () => {
    it('should handle 100 concurrent users with acceptable performance', async () => {
      mockApiClient.mockResponse('GET', '/users', {
        success: true,
        data: Array(50).fill(null).map((_, i) => ({
          id: i + 1,
          email: `user${i}@example.com`,
          role: 'member'
        })),
        metadata: { total: 50 }
      });

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-users');
      
      const stress = new StressTest({
        concurrent: 100,
        duration: 10000, // 10 seconds
        rampUp: 2000     // 2 second ramp-up
      });

      const results = await stress.run(async () => {
        memoryTracker.sample();
        return await executeTool(tool, { limit: 20 });
      });

      // Performance assertions
      expect(results.successRate).toBeGreaterThan(0.95); // 95% success rate
      expect(results.avgLatency).toBeLessThan(500);       // Average < 500ms
      expect(results.p95Latency).toBeLessThan(1000);      // 95th percentile < 1s
      expect(results.p99Latency).toBeLessThan(2000);      // 99th percentile < 2s

      // Memory usage assertions
      const memStats = memoryTracker.getStats();
      expect(memStats.heapGrowth).toBeLessThan(150 * 1024 * 1024); // < 150MB growth for 100 concurrent users
      
      console.log('Load Test Results:', {
        successful: results.successful,
        failed: results.failed,
        successRate: `${(results.successRate * 100).toFixed(2)}%`,
        avgLatency: `${results.avgLatency.toFixed(2)}ms`,
        p95Latency: `${results.p95Latency}ms`,
        p99Latency: `${results.p99Latency}ms`,
        memoryGrowth: `${(memStats.heapGrowth / 1024 / 1024).toFixed(2)}MB`
      });
    }, 20000); // 20 second timeout for this specific test

    it('should maintain performance with large datasets', async () => {
      // Mock large dataset response
      const largeDataset = Array(1000).fill(null).map((_, i) => ({
        id: i + 1,
        email: `user${i}@example.com`,
        role: i % 3 === 0 ? 'admin' : i % 3 === 1 ? 'member' : 'viewer',
        teams: Array(Math.floor(Math.random() * 5) + 1).fill(null).map((_, j) => ({
          id: j + 1,
          name: `Team ${j + 1}`,
          role: 'member'
        })),
        organizations: Array(Math.floor(Math.random() * 3) + 1).fill(null).map((_, k) => ({
          id: k + 1,
          name: `Org ${k + 1}`,
          role: 'member'
        }))
      }));

      mockApiClient.mockResponse('GET', '/users', {
        success: true,
        data: largeDataset,
        metadata: { total: 1000 }
      });

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-users');

      const startTime = Date.now();
      const result = await executeTool(tool, { limit: 100 });
      const executionTime = Date.now() - startTime;

      // Should handle large dataset efficiently
      expect(executionTime).toBeLessThan(1000); // < 1 second
      expect(result).toContain('users');
      
      const parsed = JSON.parse(result);
      expect(parsed.users).toHaveLength(100);
      expect(parsed.pagination.total).toBe(1000);
    });

    it('should handle concurrent operations on different resources', async () => {
      // Mock responses for different endpoints
      mockApiClient.mockResponse('GET', '/users', {
        success: true,
        data: Array(20).fill({ id: 1, email: 'user@example.com', role: 'member' }),
        metadata: { total: 20 }
      });

      mockApiClient.mockResponse('GET', '/teams', {
        success: true,
        data: Array(10).fill({ id: 1, name: 'Team 1', organizationId: 1 }),
        metadata: { total: 10 }
      });

      mockApiClient.mockResponse('GET', '/organizations', {
        success: true,
        data: Array(5).fill({ id: 1, name: 'Org 1' }),
        metadata: { total: 5 }
      });

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const listUserssTool = findTool(mockTool, 'list-users');
      const listTeamsTool = findTool(mockTool, 'list-teams');
      const listOrgsTool = findTool(mockTool, 'list-organizations');

      const concurrentOperations = [
        () => executeTool(listUserssTool, { limit: 20 }),
        () => executeTool(listTeamsTool, { limit: 10 }),
        () => executeTool(listOrgsTool, { limit: 5 })
      ];

      const startTime = Date.now();
      
      // Run 50 concurrent mixed operations
      const promises = Array(50).fill(null).map(() => {
        const operation = concurrentOperations[Math.floor(Math.random() * concurrentOperations.length)];
        return operation();
      });

      const results = await Promise.allSettled(promises);
      const executionTime = Date.now() - startTime;

      const successful = results.filter(r => r.status === 'fulfilled').length;
      const failed = results.filter(r => r.status === 'rejected').length;

      expect(successful).toBeGreaterThan(45); // At least 90% success
      expect(failed).toBeLessThan(5);
      expect(executionTime).toBeLessThan(3000); // Complete within 3 seconds
    });
  });

  describe('Stress Testing', () => {
    it('should gracefully handle resource exhaustion', async () => {
      mockApiClient.mockResponse('POST', '/teams', {
        success: true,
        data: { id: 12345, name: 'Test Team' }
      });

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-team');

      // Simulate resource exhaustion with many concurrent requests
      const stress = new StressTest({
        concurrent: 200,  // High concurrency
        duration: 5000,   // 5 seconds
        rampUp: 1000      // Fast ramp-up
      });

      const results = await stress.run(async () => {
        await chaos.simulateMemoryPressure();
        return await executeTool(tool, {
          name: `Team ${Date.now()}`,
          description: 'Stress test team'
        });
      });

      // Should maintain some level of service even under stress
      expect(results.successRate).toBeGreaterThan(0.70); // At least 70% success under stress
      expect(results.avgLatency).toBeLessThan(2000);     // Average < 2s under stress
      
      console.log('Stress Test Results:', {
        totalRequests: results.successful + results.failed,
        successRate: `${(results.successRate * 100).toFixed(2)}%`,
        avgLatency: `${results.avgLatency.toFixed(2)}ms`,
        p99Latency: `${results.p99Latency}ms`
      });
    }, 15000); // 15 second timeout for stress test

    it('should handle memory leaks during extended operations', async () => {
      mockApiClient.mockResponse('GET', '/users', {
        success: true,
        data: Array(100).fill({ id: 1, email: 'user@example.com', role: 'member' }),
        metadata: { total: 100 }
      });

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-users');

      const initialMemory = process.memoryUsage();
      
      // Run many operations to detect memory leaks
      for (let i = 0; i < 100; i++) {
        await executeTool(tool, { limit: 100 });
        
        if (i % 10 === 0) {
          memoryTracker.sample();
          
          // Force garbage collection if available
          if (global.gc) {
            global.gc();
          }
        }
      }

      const finalMemory = process.memoryUsage();
      const memoryGrowth = finalMemory.heapUsed - initialMemory.heapUsed;

      // Memory growth should be reasonable (< 20MB for 100 operations)
      expect(memoryGrowth).toBeLessThan(20 * 1024 * 1024);

      console.log('Memory Leak Test:', {
        initialHeap: `${(initialMemory.heapUsed / 1024 / 1024).toFixed(2)}MB`,
        finalHeap: `${(finalMemory.heapUsed / 1024 / 1024).toFixed(2)}MB`,
        growth: `${(memoryGrowth / 1024 / 1024).toFixed(2)}MB`
      });
    });
  });

  describe('Performance Under Chaos', () => {
    it('should maintain performance with network latency', async () => {
      // Mock slow network responses
      const originalMockResponse = mockApiClient.mockResponse.bind(mockApiClient);
      mockApiClient.mockResponse = jest.fn(async (method, endpoint, response) => {
        await chaos.simulateSlowNetwork(Math.random() * 500 + 100); // 100-600ms delay
        return originalMockResponse(method, endpoint, response);
      });

      mockApiClient.mockResponse('GET', '/users', {
        success: true,
        data: Array(10).fill({ id: 1, email: 'user@example.com', role: 'member' }),
        metadata: { total: 10 }
      });

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-users');

      const stress = new StressTest({
        concurrent: 20,
        duration: 5000,
        rampUp: 1000
      });

      const results = await stress.run(async () => {
        return await executeTool(tool, { limit: 10 });
      });

      // Should handle network latency gracefully
      expect(results.successRate).toBeGreaterThan(0.90);
      expect(results.avgLatency).toBeLessThan(1000); // Account for simulated latency
    });

    it('should handle CPU-intensive concurrent operations', async () => {
      mockApiClient.mockResponse('GET', '/organizations', {
        success: true,
        data: Array(50).fill(null).map((_, i) => ({
          id: i + 1,
          name: `Organization ${i + 1}`,
          memberCount: Math.floor(Math.random() * 1000) + 100,
          teamCount: Math.floor(Math.random() * 50) + 10
        })),
        metadata: { total: 50 }
      });

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-organizations');

      const stress = new StressTest({
        concurrent: 30,
        duration: 5000,
        rampUp: 1000
      });

      const results = await stress.run(async () => {
        await chaos.simulateCPUIntensiveTask();
        return await executeTool(tool, { limit: 50 });
      });

      // Should maintain reasonable performance even with CPU pressure
      expect(results.successRate).toBeGreaterThan(0.85);
      expect(results.p95Latency).toBeLessThan(1500);
    });
  });

  describe('Scalability Testing', () => {
    it('should scale linearly with increasing load', async () => {
      mockApiClient.mockResponse('GET', '/teams', {
        success: true,
        data: Array(25).fill({ id: 1, name: 'Team', organizationId: 1 }),
        metadata: { total: 25 }
      });

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-teams');

      const testScenarios = [
        { concurrent: 10, expectedTime: 3000 },
        { concurrent: 20, expectedTime: 4000 },
        { concurrent: 40, expectedTime: 6000 }
      ];

      for (const scenario of testScenarios) {
        const stress = new StressTest({
          concurrent: scenario.concurrent,
          duration: 3000,
          rampUp: 500
        });

        const startTime = Date.now();
        const results = await stress.run(async () => {
          return await executeTool(tool, { limit: 25 });
        });
        const totalTime = Date.now() - startTime;

        // Verify linear scaling characteristics
        expect(results.successRate).toBeGreaterThan(0.90);
        expect(totalTime).toBeLessThan(scenario.expectedTime);

        console.log(`Scalability Test (${scenario.concurrent} concurrent):`, {
          successRate: `${(results.successRate * 100).toFixed(2)}%`,
          avgLatency: `${results.avgLatency.toFixed(2)}ms`,
          totalTime: `${totalTime}ms`
        });
      }
    });

    it('should handle burst traffic patterns', async () => {
      mockApiClient.mockResponse('POST', '/organizations', {
        success: true,
        data: { id: 12345, name: 'New Organization' }
      });

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-organization');

      // Simulate burst pattern: quiet -> spike -> quiet
      const burstResults: any[] = [];

      // Quiet period (low load)
      const quietStress = new StressTest({
        concurrent: 5,
        duration: 2000,
        rampUp: 500
      });

      const quietResults = await quietStress.run(async () => {
        return await executeTool(tool, {
          name: `Org ${Date.now()}`,
          description: 'Quiet period org'
        });
      });

      burstResults.push({ phase: 'quiet', ...quietResults });

      // Burst period (high load)
      const burstStress = new StressTest({
        concurrent: 50,
        duration: 3000,
        rampUp: 500
      });

      const spikeResults = await burstStress.run(async () => {
        return await executeTool(tool, {
          name: `Burst Org ${Date.now()}`,
          description: 'Burst period org'
        });
      });

      burstResults.push({ phase: 'burst', ...spikeResults });

      // Recovery period (back to low load)
      const recoveryResults = await quietStress.run(async () => {
        return await executeTool(tool, {
          name: `Recovery Org ${Date.now()}`,
          description: 'Recovery period org'
        });
      });

      burstResults.push({ phase: 'recovery', ...recoveryResults });

      // Verify system handles burst and recovers
      expect(quietResults.successRate).toBeGreaterThan(0.95);
      expect(spikeResults.successRate).toBeGreaterThan(0.80); // Lower during burst
      expect(recoveryResults.successRate).toBeGreaterThan(0.95); // Should recover

      console.log('Burst Traffic Test:', burstResults.map(r => ({
        phase: r.phase,
        successRate: `${(r.successRate * 100).toFixed(2)}%`,
        avgLatency: `${r.avgLatency.toFixed(2)}ms`
      })));
    });
  });

  describe('Resource Efficiency', () => {
    it('should optimize resource usage for batch operations', async () => {
      const batchSize = 100;
      const batchData = Array(batchSize).fill(null).map((_, i) => ({
        id: i + 1,
        email: `batchuser${i}@example.com`,
        role: 'member'
      }));

      mockApiClient.mockResponse('GET', '/users', {
        success: true,
        data: batchData,
        metadata: { total: batchSize }
      });

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-users');

      const memoryBefore = process.memoryUsage();
      const startTime = Date.now();

      // Execute batch operation
      const result = await executeTool(tool, { limit: batchSize });

      const executionTime = Date.now() - startTime;
      const memoryAfter = process.memoryUsage();
      const memoryUsed = memoryAfter.heapUsed - memoryBefore.heapUsed;

      // Verify efficient batch processing
      expect(executionTime).toBeLessThan(500); // Should be fast
      expect(memoryUsed).toBeLessThan(10 * 1024 * 1024); // < 10MB for batch
      
      const parsed = JSON.parse(result);
      expect(parsed.users).toHaveLength(batchSize);

      console.log('Batch Operation Efficiency:', {
        batchSize,
        executionTime: `${executionTime}ms`,
        memoryUsed: `${(memoryUsed / 1024 / 1024).toFixed(2)}MB`,
        throughput: `${(batchSize / executionTime * 1000).toFixed(2)} ops/sec`
      });
    });

    it('should handle pagination efficiently', async () => {
      const totalRecords = 1000;
      const pageSize = 50;
      const totalPages = Math.ceil(totalRecords / pageSize);

      // Mock paginated responses
      for (let page = 0; page < totalPages; page++) {
        const offset = page * pageSize;
        const pageData = Array(pageSize).fill(null).map((_, i) => ({
          id: offset + i + 1,
          name: `Team ${offset + i + 1}`,
          organizationId: 1
        }));

        mockApiClient.mockResponse('GET', '/teams', {
          success: true,
          data: pageData,
          metadata: { 
            total: totalRecords,
            limit: pageSize,
            offset: offset,
            hasMore: page < totalPages - 1
          }
        });
      }

      const { addPermissionTools } = await import('../../src/tools/permissions.js');
      addPermissionTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-teams');

      const paginationTimes: number[] = [];
      const memoryUsage: number[] = [];

      // Test pagination performance across all pages
      for (let page = 0; page < Math.min(totalPages, 10); page++) { // Test first 10 pages
        const offset = page * pageSize;
        const startTime = Date.now();
        const memoryBefore = process.memoryUsage().heapUsed;

        const result = await executeTool(tool, { 
          limit: pageSize,
          offset: offset
        });

        const executionTime = Date.now() - startTime;
        const memoryAfter = process.memoryUsage().heapUsed;
        
        paginationTimes.push(executionTime);
        memoryUsage.push(memoryAfter - memoryBefore);

        const parsed = JSON.parse(result);
        expect(parsed.teams).toHaveLength(pageSize);
        expect(parsed.pagination.offset).toBe(offset);
      }

      // Verify consistent pagination performance
      const avgTime = paginationTimes.reduce((a, b) => a + b, 0) / paginationTimes.length;
      const maxTime = Math.max(...paginationTimes);
      const avgMemory = memoryUsage.reduce((a, b) => a + b, 0) / memoryUsage.length;

      expect(avgTime).toBeLessThan(200); // Average < 200ms per page
      expect(maxTime).toBeLessThan(500); // Max < 500ms per page
      expect(avgMemory).toBeLessThan(1024 * 1024); // < 1MB per page

      console.log('Pagination Efficiency:', {
        pagestested: paginationTimes.length,
        avgTime: `${avgTime.toFixed(2)}ms`,
        maxTime: `${maxTime}ms`,
        avgMemory: `${(avgMemory / 1024).toFixed(2)}KB`
      });
    });
  });
});