/**
 * Mock factory functions for log-streaming module testing
 * Provides specialized mocks for streaming, EventEmitter patterns, and external system integrations
 */

import { jest } from '@jest/globals';
import { EventEmitter } from 'events';
import type MakeApiClient from '../../../src/lib/make-api-client.js';
import type { ToolContext } from '../../../src/tools/shared/types/tool-context.js';
import { MakeLogEntry } from '../../../src/tools/log-streaming/types/streaming.js';
import { MockStreamEmitter } from './streaming-test-utils.js';

/**
 * Create enhanced mock API client for streaming operations
 */
export function createStreamingMockApiClient(): jest.Mocked<MakeApiClient> {
  const mockClient = {
    get: jest.fn(),
    post: jest.fn(),
    put: jest.fn(),
    delete: jest.fn(),
    patch: jest.fn(),
  } as jest.Mocked<MakeApiClient>;

  // Setup default streaming-specific responses
  mockClient.get.mockImplementation((endpoint: string) => {
    if (endpoint.includes('/executions')) {
      return Promise.resolve({
        success: true,
        data: [{
          id: 'exec_123',
          status: 'running',
          progress: 50,
          startTime: new Date().toISOString(),
        }],
      });
    }
    
    if (endpoint.includes('/logs')) {
      return Promise.resolve({
        success: true,
        data: generateMockLogs(5),
      });
    }

    if (endpoint.includes('/modules')) {
      return Promise.resolve({
        success: true,
        data: [
          { id: 'module_1', name: 'HTTP Module', status: 'completed' },
          { id: 'module_2', name: 'Transform Module', status: 'running' },
        ],
      });
    }

    return Promise.resolve({ success: true, data: {} });
  });

  return mockClient;
}

/**
 * Create enhanced tool context for streaming tests
 */
export function createStreamingToolContext(overrides: Partial<ToolContext> = {}): ToolContext {
  return {
    server: {} as never,
    apiClient: createStreamingMockApiClient(),
    logger: createStreamingMockLogger(),
    ...overrides,
  };
}

/**
 * Create mock logger with streaming-specific methods
 */
export function createStreamingMockLogger() {
  const logger = {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
    child: jest.fn(),
  };

  logger.child.mockReturnValue(logger);
  return logger;
}

/**
 * Generate mock log entries for testing
 */
export function generateMockLogs(count: number = 5): MakeLogEntry[] {
  const logs: MakeLogEntry[] = [];
  const baseTime = Date.now();

  for (let i = 0; i < count; i++) {
    logs.push({
      id: `log_${i + 1}`,
      timestamp: new Date(baseTime + i * 1000).toISOString(),
      level: i % 3 === 0 ? 'error' : i % 2 === 0 ? 'warn' : 'info',
      message: `Mock log entry ${i + 1}`,
      module: {
        id: `module_${(i % 3) + 1}`,
        name: ['HTTP Module', 'Transform Module', 'Database Module'][i % 3],
      },
      executionId: 'exec_123',
      data: { step: i + 1, processed: Math.random() * 100 },
      metrics: {
        processingTime: 100 + Math.random() * 500,
        operations: Math.floor(Math.random() * 10),
        dataSize: Math.floor(Math.random() * 10000),
      },
      error: i % 3 === 0 ? {
        message: `Mock error ${i + 1}`,
        code: 'MOCK_ERROR',
      } : undefined,
    });
  }

  return logs;
}

/**
 * Mock external monitoring system
 */
export class MockExternalMonitoringSystem extends EventEmitter {
  private endpoints: Map<string, any> = new Map();
  private webhooks: Array<{ url: string; events: string[] }> = [];
  private isConnected = false;

  async connect(config: { url: string; apiKey: string }): Promise<void> {
    // Simulate connection delay
    await new Promise(resolve => setTimeout(resolve, 100));
    this.isConnected = true;
    this.emit('connected', { timestamp: new Date() });
  }

  async disconnect(): Promise<void> {
    this.isConnected = false;
    this.endpoints.clear();
    this.webhooks = [];
    this.emit('disconnected', { timestamp: new Date() });
  }

  async createEndpoint(name: string, config: any): Promise<{ endpointId: string; url: string }> {
    if (!this.isConnected) {
      throw new Error('Not connected to monitoring system');
    }

    const endpointId = `endpoint_${Date.now()}`;
    const url = `https://monitoring.example.com/endpoints/${endpointId}`;
    
    this.endpoints.set(endpointId, { name, config, url, created: new Date() });
    this.emit('endpointCreated', { endpointId, name });

    return { endpointId, url };
  }

  async sendLogs(endpointId: string, logs: MakeLogEntry[]): Promise<{ sent: number; failed: number }> {
    if (!this.isConnected) {
      throw new Error('Not connected to monitoring system');
    }

    const endpoint = this.endpoints.get(endpointId);
    if (!endpoint) {
      throw new Error(`Endpoint not found: ${endpointId}`);
    }

    // Simulate some failures
    const sent = logs.length - Math.floor(Math.random() * 2);
    const failed = logs.length - sent;

    this.emit('logsSent', { endpointId, sent, failed, timestamp: new Date() });

    return { sent, failed };
  }

  async registerWebhook(url: string, events: string[]): Promise<{ webhookId: string }> {
    const webhookId = `webhook_${Date.now()}`;
    this.webhooks.push({ url, events });
    this.emit('webhookRegistered', { webhookId, url, events });

    return { webhookId };
  }

  simulateWebhookEvent(event: string, data: any): void {
    this.webhooks.forEach(webhook => {
      if (webhook.events.includes(event)) {
        this.emit('webhookTriggered', {
          url: webhook.url,
          event,
          data,
          timestamp: new Date(),
        });
      }
    });
  }

  isSystemConnected(): boolean {
    return this.isConnected;
  }

  getEndpoints(): Array<{ id: string; name: string; url: string }> {
    return Array.from(this.endpoints.entries()).map(([id, endpoint]) => ({
      id,
      name: endpoint.name,
      url: endpoint.url,
    }));
  }
}

/**
 * Mock stream processor for performance testing
 */
export class MockStreamProcessor {
  private processingRate: number;
  private errorRate: number;
  private latency: number;
  private isProcessing = false;

  constructor(options: {
    processingRate?: number; // logs per second
    errorRate?: number; // 0-1 error probability
    latency?: number; // ms delay
  } = {}) {
    this.processingRate = options.processingRate || 100;
    this.errorRate = options.errorRate || 0.05;
    this.latency = options.latency || 50;
  }

  async processLog(log: MakeLogEntry): Promise<{ processed: boolean; error?: string; processingTime: number }> {
    const startTime = process.hrtime.bigint();

    // Simulate processing latency
    await new Promise(resolve => setTimeout(resolve, this.latency));

    // Simulate processing errors
    const hasError = Math.random() < this.errorRate;
    
    const endTime = process.hrtime.bigint();
    const processingTime = Number(endTime - startTime) / 1_000_000;

    if (hasError) {
      return {
        processed: false,
        error: `Processing error for log ${log.id}`,
        processingTime,
      };
    }

    return {
      processed: true,
      processingTime,
    };
  }

  async processBatch(logs: MakeLogEntry[]): Promise<{
    processed: number;
    failed: number;
    totalTime: number;
    throughput: number;
  }> {
    const startTime = process.hrtime.bigint();
    this.isProcessing = true;

    let processed = 0;
    let failed = 0;

    // Process logs with rate limiting
    const batchSize = Math.ceil(this.processingRate / 10); // Process in batches
    for (let i = 0; i < logs.length; i += batchSize) {
      const batch = logs.slice(i, i + batchSize);
      
      const results = await Promise.all(
        batch.map(log => this.processLog(log))
      );

      results.forEach(result => {
        if (result.processed) {
          processed++;
        } else {
          failed++;
        }
      });

      // Rate limiting delay
      if (i + batchSize < logs.length) {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }

    const endTime = process.hrtime.bigint();
    const totalTime = Number(endTime - startTime) / 1_000_000;
    const throughput = logs.length / (totalTime / 1000);

    this.isProcessing = false;

    return { processed, failed, totalTime, throughput };
  }

  setProcessingRate(rate: number): void {
    this.processingRate = rate;
  }

  setErrorRate(rate: number): void {
    this.errorRate = Math.max(0, Math.min(1, rate));
  }

  setLatency(latency: number): void {
    this.latency = Math.max(0, latency);
  }

  isCurrentlyProcessing(): boolean {
    return this.isProcessing;
  }
}

/**
 * Mock export service for testing different output formats
 */
export class MockExportService {
  private exportHistory: Array<{
    format: string;
    recordCount: number;
    timestamp: Date;
    size: number;
  }> = [];

  async exportToJson(data: any[]): Promise<{ data: string; size: number; mimeType: string }> {
    const jsonData = JSON.stringify(data, null, 2);
    const size = Buffer.byteLength(jsonData, 'utf8');

    this.exportHistory.push({
      format: 'json',
      recordCount: data.length,
      timestamp: new Date(),
      size,
    });

    return {
      data: jsonData,
      size,
      mimeType: 'application/json',
    };
  }

  async exportToCsv(data: any[], headers?: string[]): Promise<{ data: string; size: number; mimeType: string }> {
    const csvHeaders = headers || Object.keys(data[0] || {});
    let csvData = csvHeaders.join(',') + '\n';

    data.forEach(row => {
      const values = csvHeaders.map(header => {
        const value = row[header] || '';
        return typeof value === 'string' && value.includes(',') ? `"${value}"` : value;
      });
      csvData += values.join(',') + '\n';
    });

    const size = Buffer.byteLength(csvData, 'utf8');

    this.exportHistory.push({
      format: 'csv',
      recordCount: data.length,
      timestamp: new Date(),
      size,
    });

    return {
      data: csvData,
      size,
      mimeType: 'text/csv',
    };
  }

  async exportToParquet(data: any[]): Promise<{ data: Buffer; size: number; mimeType: string }> {
    // Mock parquet export - in reality would use parquet library
    const mockParquetHeader = Buffer.from('PAR1', 'utf8');
    const mockData = Buffer.from(JSON.stringify(data), 'utf8');
    const mockFooter = Buffer.from('PAR1', 'utf8');
    
    const parquetData = Buffer.concat([mockParquetHeader, mockData, mockFooter]);

    this.exportHistory.push({
      format: 'parquet',
      recordCount: data.length,
      timestamp: new Date(),
      size: parquetData.length,
    });

    return {
      data: parquetData,
      size: parquetData.length,
      mimeType: 'application/octet-stream',
    };
  }

  getExportHistory(): Array<{
    format: string;
    recordCount: number;
    timestamp: Date;
    size: number;
  }> {
    return [...this.exportHistory];
  }

  clearHistory(): void {
    this.exportHistory = [];
  }

  async validateExportIntegrity(format: string, data: string | Buffer, originalData: any[]): Promise<{
    isValid: boolean;
    errors: string[];
  }> {
    const errors: string[] = [];

    switch (format) {
      case 'json':
        try {
          const parsed = JSON.parse(data as string);
          if (!Array.isArray(parsed)) {
            errors.push('JSON data is not an array');
          } else if (parsed.length !== originalData.length) {
            errors.push(`Record count mismatch: expected ${originalData.length}, got ${parsed.length}`);
          }
        } catch (error) {
          errors.push(`Invalid JSON: ${error.message}`);
        }
        break;

      case 'csv':
        const lines = (data as string).split('\n').filter(line => line.trim());
        if (lines.length - 1 !== originalData.length) { // -1 for header
          errors.push(`CSV record count mismatch: expected ${originalData.length}, got ${lines.length - 1}`);
        }
        break;

      case 'parquet':
        const buffer = data as Buffer;
        if (!buffer.slice(0, 4).equals(Buffer.from('PAR1'))) {
          errors.push('Invalid parquet header');
        }
        if (!buffer.slice(-4).equals(Buffer.from('PAR1'))) {
          errors.push('Invalid parquet footer');
        }
        break;

      default:
        errors.push(`Unsupported format: ${format}`);
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }
}

/**
 * Performance test factory for streaming operations
 */
export const StreamingPerformanceFactory = {
  createLoadTestScenario(options: {
    logCount: number;
    duration: number;
    concurrentStreams: number;
  }) {
    return {
      name: `Load Test - ${options.logCount} logs, ${options.concurrentStreams} streams`,
      config: options,
      async execute(): Promise<{
        throughput: number;
        latency: number;
        errors: number;
        memoryUsage: number;
      }> {
        const startTime = process.hrtime.bigint();
        const initialMemory = process.memoryUsage().heapUsed;

        // Simulate concurrent streaming
        const streams = Array(options.concurrentStreams)
          .fill(0)
          .map(() => new MockStreamEmitter());

        let totalLogs = 0;
        let errors = 0;

        const streamPromises = streams.map(async stream => {
          try {
            stream.start(100);
            await new Promise(resolve => setTimeout(resolve, options.duration));
            stream.stop();
            totalLogs += options.logCount / options.concurrentStreams;
          } catch (error) {
            errors++;
          }
        });

        await Promise.all(streamPromises);

        const endTime = process.hrtime.bigint();
        const finalMemory = process.memoryUsage().heapUsed;

        const totalTime = Number(endTime - startTime) / 1_000_000; // ms
        const throughput = totalLogs / (totalTime / 1000); // logs/second
        const latency = totalTime / totalLogs; // ms per log
        const memoryUsage = (finalMemory - initialMemory) / (1024 * 1024); // MB

        return { throughput, latency, errors, memoryUsage };
      },
    };
  },

  createMemoryStressTest(options: {
    batchSize: number;
    iterations: number;
  }) {
    return {
      name: `Memory Stress Test - ${options.batchSize} × ${options.iterations}`,
      config: options,
      async execute(): Promise<{
        peakMemoryMB: number;
        memoryGrowthMB: number;
        gcCount: number;
      }> {
        const initialMemory = process.memoryUsage();
        let peakMemory = initialMemory;
        let gcCount = 0;

        for (let i = 0; i < options.iterations; i++) {
          // Generate large batch of logs
          const logs = generateMockLogs(options.batchSize);
          
          // Process logs
          const processor = new MockStreamProcessor();
          await processor.processBatch(logs);

          // Monitor memory
          const currentMemory = process.memoryUsage();
          if (currentMemory.heapUsed > peakMemory.heapUsed) {
            peakMemory = currentMemory;
          }

          // Force garbage collection if available
          if (global.gc && i % 10 === 0) {
            global.gc();
            gcCount++;
          }
        }

        const peakMemoryMB = peakMemory.heapUsed / (1024 * 1024);
        const memoryGrowthMB = (peakMemory.heapUsed - initialMemory.heapUsed) / (1024 * 1024);

        return { peakMemoryMB, memoryGrowthMB, gcCount };
      },
    };
  },
};