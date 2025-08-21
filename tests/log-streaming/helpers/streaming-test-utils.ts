/**
 * Streaming-specific test utilities for log-streaming module
 * Provides specialized testing patterns for real-time streaming, event handling, and performance testing
 */

import { EventEmitter } from 'events';
import { expect } from '@jest/globals';
import { MakeLogEntry } from '../../../src/tools/log-streaming/types/streaming.js';

/**
 * Mock event emitter for streaming tests
 */
export class MockStreamEmitter extends EventEmitter {
  private isActive = false;
  private streamId: string;
  private intervalId?: NodeJS.Timeout;

  constructor(streamId: string = `mock_stream_${Date.now()}`) {
    super();
    this.streamId = streamId;
  }

  start(updateInterval: number = 100): void {
    if (this.isActive) {
      throw new Error('Stream already active');
    }

    this.isActive = true;
    this.emit('stream:started', { streamId: this.streamId, timestamp: new Date() });

    this.intervalId = setInterval(() => {
      if (this.isActive) {
        this.emit('stream:data', {
          streamId: this.streamId,
          timestamp: new Date(),
          data: this.generateMockLogEntry(),
        });
      }
    }, updateInterval);
  }

  stop(): void {
    if (!this.isActive) {
      throw new Error('Stream not active');
    }

    this.isActive = false;
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = undefined;
    }

    this.emit('stream:stopped', { streamId: this.streamId, timestamp: new Date() });
  }

  simulateError(error: Error): void {
    this.emit('stream:error', {
      streamId: this.streamId,
      error,
      timestamp: new Date(),
    });
  }

  simulateBurst(count: number, interval: number = 10): void {
    for (let i = 0; i < count; i++) {
      setTimeout(() => {
        this.emit('stream:data', {
          streamId: this.streamId,
          timestamp: new Date(),
          data: this.generateMockLogEntry(),
          burst: true,
        });
      }, i * interval);
    }
  }

  private generateMockLogEntry(): MakeLogEntry {
    return {
      id: `log_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date().toISOString(),
      level: 'info',
      message: `Mock log entry at ${new Date().toISOString()}`,
      module: { id: 'mock_module', name: 'Mock Module' },
      executionId: `exec_${this.streamId}`,
      data: { processed: Math.floor(Math.random() * 100) },
      metrics: {
        processingTime: Math.floor(Math.random() * 1000),
        operations: Math.floor(Math.random() * 10),
        dataSize: Math.floor(Math.random() * 10000),
      },
    };
  }

  getStreamId(): string {
    return this.streamId;
  }

  isStreamActive(): boolean {
    return this.isActive;
  }
}

/**
 * Streaming assertion utilities
 */
export const StreamingAssertions = {
  /**
   * Assert that streaming updates occur within expected timeframe
   */
  async expectStreamingUpdates(
    emitter: EventEmitter,
    expectedCount: number,
    timeoutMs: number = 5000
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      let updateCount = 0;
      const timeout = setTimeout(() => {
        reject(new Error(`Expected ${expectedCount} updates, received ${updateCount} within ${timeoutMs}ms`));
      }, timeoutMs);

      emitter.on('stream:data', () => {
        updateCount++;
        if (updateCount >= expectedCount) {
          clearTimeout(timeout);
          resolve();
        }
      });
    });
  },

  /**
   * Assert streaming performance meets benchmarks
   */
  async expectStreamingPerformance(
    testFn: () => Promise<any>,
    expectedLatency: number,
    expectedThroughput: number
  ): Promise<void> {
    const startTime = process.hrtime.bigint();
    const result = await testFn();
    const endTime = process.hrtime.bigint();

    const latency = Number(endTime - startTime) / 1_000_000; // Convert to ms
    expect(latency).toBeLessThanOrEqual(expectedLatency);

    // If result has throughput data, validate it
    if (result && typeof result === 'object' && 'throughput' in result) {
      expect(result.throughput).toBeGreaterThanOrEqual(expectedThroughput);
    }
  },

  /**
   * Assert that streaming handles backpressure correctly
   */
  async expectBackpressureHandling(
    emitter: MockStreamEmitter,
    burstSize: number,
    maxLatency: number = 1000
  ): Promise<void> {
    const startTime = Date.now();
    let processedCount = 0;

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error(`Backpressure handling failed: processed ${processedCount}/${burstSize} in ${maxLatency}ms`));
      }, maxLatency);

      emitter.on('stream:data', () => {
        processedCount++;
        if (processedCount >= burstSize) {
          const endTime = Date.now();
          const totalTime = endTime - startTime;
          
          clearTimeout(timeout);
          expect(totalTime).toBeLessThanOrEqual(maxLatency);
          expect(processedCount).toBe(burstSize);
          resolve();
        }
      });

      // Simulate burst
      emitter.simulateBurst(burstSize);
    });
  },

  /**
   * Assert that stream properly handles errors and recovery
   */
  async expectErrorRecovery(
    emitter: MockStreamEmitter,
    error: Error,
    recoveryTimeMs: number = 1000
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      let errorReceived = false;
      let dataAfterError = false;

      const timeout = setTimeout(() => {
        if (!errorReceived) {
          reject(new Error('Expected error was not received'));
        } else if (!dataAfterError) {
          reject(new Error('Stream did not recover after error'));
        }
      }, recoveryTimeMs);

      emitter.on('stream:error', () => {
        errorReceived = true;
      });

      emitter.on('stream:data', () => {
        if (errorReceived && !dataAfterError) {
          dataAfterError = true;
          clearTimeout(timeout);
          resolve();
        }
      });

      // Start stream and simulate error
      emitter.start(100);
      setTimeout(() => emitter.simulateError(error), 200);
    });
  },
};

/**
 * Export format testing utilities
 */
export const ExportFormatUtils = {
  /**
   * Validate JSON export format
   */
  validateJsonExport(exportData: string, expectedFields: string[]): void {
    expect(() => JSON.parse(exportData)).not.toThrow();
    
    const parsed = JSON.parse(exportData);
    expect(parsed).toBeInstanceOf(Object);
    
    expectedFields.forEach(field => {
      expect(parsed).toHaveProperty(field);
    });
  },

  /**
   * Validate CSV export format
   */
  validateCsvExport(exportData: string, expectedHeaders: string[]): void {
    const lines = exportData.split('\n').filter(line => line.trim());
    expect(lines.length).toBeGreaterThan(0);
    
    const headers = lines[0].split(',').map(h => h.trim().replace(/"/g, ''));
    expectedHeaders.forEach(header => {
      expect(headers).toContain(header);
    });

    // Validate data rows have correct number of columns
    if (lines.length > 1) {
      const dataRow = lines[1].split(',');
      expect(dataRow.length).toBe(headers.length);
    }
  },

  /**
   * Validate Parquet-like binary format (simplified check)
   */
  validateParquetExport(exportData: Buffer, expectedSchema: Record<string, string>): void {
    expect(exportData).toBeInstanceOf(Buffer);
    expect(exportData.length).toBeGreaterThan(0);
    
    // Basic validation - in real implementation would use parquet library
    const header = exportData.slice(0, 4).toString();
    expect(header).toMatch(/PAR1|PQRT/); // Common parquet magic numbers
  },

  /**
   * Test export format generation performance
   */
  async testExportPerformance(
    exportFn: () => Promise<string | Buffer>,
    dataSize: number,
    maxTimeMs: number
  ): Promise<{ duration: number; throughput: number }> {
    const startTime = process.hrtime.bigint();
    const result = await exportFn();
    const endTime = process.hrtime.bigint();

    const duration = Number(endTime - startTime) / 1_000_000; // Convert to ms
    expect(duration).toBeLessThanOrEqual(maxTimeMs);

    const throughput = dataSize / (duration / 1000); // Records per second
    return { duration, throughput };
  },
};

/**
 * Memory usage testing utilities for streaming
 */
export const MemoryTestUtils = {
  /**
   * Monitor memory usage during streaming operation
   */
  async monitorMemoryUsage<T>(
    operation: () => Promise<T>,
    maxMemoryMB: number = 100
  ): Promise<{ result: T; peakMemoryMB: number; memoryGrowthMB: number }> {
    const initialMemory = process.memoryUsage();
    let peakMemory = initialMemory;

    // Monitor memory every 100ms during operation
    const memoryMonitor = setInterval(() => {
      const currentMemory = process.memoryUsage();
      if (currentMemory.heapUsed > peakMemory.heapUsed) {
        peakMemory = currentMemory;
      }
    }, 100);

    try {
      const result = await operation();
      
      clearInterval(memoryMonitor);
      
      const peakMemoryMB = peakMemory.heapUsed / (1024 * 1024);
      const memoryGrowthMB = (peakMemory.heapUsed - initialMemory.heapUsed) / (1024 * 1024);

      expect(peakMemoryMB).toBeLessThanOrEqual(maxMemoryMB);

      return { result, peakMemoryMB, memoryGrowthMB };
    } finally {
      clearInterval(memoryMonitor);
    }
  },

  /**
   * Test for memory leaks in streaming operations
   */
  async testMemoryLeaks(
    operationFactory: () => () => Promise<void>,
    iterations: number = 10,
    maxGrowthMB: number = 10
  ): Promise<void> {
    const initialMemory = process.memoryUsage().heapUsed;
    
    for (let i = 0; i < iterations; i++) {
      const operation = operationFactory();
      await operation();
      
      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }
    }

    const finalMemory = process.memoryUsage().heapUsed;
    const memoryGrowthMB = (finalMemory - initialMemory) / (1024 * 1024);

    expect(memoryGrowthMB).toBeLessThanOrEqual(maxGrowthMB);
  },
};

/**
 * Concurrent streaming test utilities
 */
export const ConcurrentStreamingUtils = {
  /**
   * Test multiple concurrent streams
   */
  async testConcurrentStreams(
    streamCount: number,
    duration: number = 2000,
    expectedTotalEvents: number
  ): Promise<void> {
    const streams: MockStreamEmitter[] = [];
    let totalEvents = 0;

    // Create and start multiple streams
    for (let i = 0; i < streamCount; i++) {
      const stream = new MockStreamEmitter(`concurrent_stream_${i}`);
      stream.on('stream:data', () => totalEvents++);
      stream.start(100);
      streams.push(stream);
    }

    // Run for specified duration
    await new Promise(resolve => setTimeout(resolve, duration));

    // Stop all streams
    streams.forEach(stream => stream.stop());

    expect(totalEvents).toBeGreaterThanOrEqual(expectedTotalEvents);
  },

  /**
   * Test stream coordination and synchronization
   */
  async testStreamSynchronization(
    streams: MockStreamEmitter[],
    coordinatorFn: (streams: MockStreamEmitter[]) => Promise<void>
  ): Promise<void> {
    const startTime = Date.now();
    
    await coordinatorFn(streams);
    
    const endTime = Date.now();
    const duration = endTime - startTime;

    // Verify all streams are properly coordinated
    streams.forEach(stream => {
      expect(stream.isStreamActive()).toBe(false);
    });

    expect(duration).toBeLessThan(10000); // Should complete within 10 seconds
  },
};