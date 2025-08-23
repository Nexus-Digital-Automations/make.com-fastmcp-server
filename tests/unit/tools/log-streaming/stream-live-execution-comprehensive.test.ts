/**
 * @fileoverview Comprehensive test suite for Live Execution Streaming
 * Tests real-time log streaming, monitoring, and execution tracking
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { createStreamLiveExecutionTool } from '../../../../src/tools/log-streaming/tools/stream-live-execution.js';
import { ToolContext } from '../../../../src/tools/shared/types/tool-context.js';
import { UserError } from 'fastmcp';

// Mock dependencies
const mockApiClient = {
  post: jest.fn(),
  get: jest.fn(),
  put: jest.fn(),
  delete: jest.fn(),
};

const mockLogger = {
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
};

const mockServer = {
  addTool: jest.fn(),
};

describe('Live Execution Streaming - Comprehensive Tests', () => {
  let toolContext: ToolContext;

  beforeEach(() => {
    toolContext = {
      server: mockServer as any,
      apiClient: mockApiClient as any,
      logger: mockLogger,
    };
    
    // Reset all mocks
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('Tool Registration and Structure', () => {
    it('should create tool with correct configuration', () => {
      const tool = createStreamLiveExecutionTool(toolContext);
      
      expect(tool.name).toBe('stream_live_execution');
      expect(tool.description).toContain('real-time');
      expect(tool.parameters).toBeDefined();
      expect(tool.annotations).toBeDefined();
      expect(typeof tool.execute).toBe('function');
    });

    it('should have proper streaming annotations', () => {
      const tool = createStreamLiveExecutionTool(toolContext);
      
      expect(tool.annotations.title).toBeDefined();
      expect(tool.annotations.readOnlyHint).toBe(true);
      expect(tool.annotations.destructiveHint).toBe(false);
      expect(tool.annotations.openWorldHint).toBe(true);
    });
  });

  describe('Parameter Validation', () => {
    it('should validate required scenario ID', async () => {
      const tool = createStreamLiveExecutionTool(toolContext);
      
      await expect(tool.execute({
        // Missing scenarioId
        outputFormat: 'json'
      }, { log: mockLogger })).rejects.toThrow();
    });

    it('should validate output format options', async () => {
      const tool = createStreamLiveExecutionTool(toolContext);
      
      await expect(tool.execute({
        scenarioId: 'scenario-123',
        outputFormat: 'invalid-format' as any
      }, { log: mockLogger })).rejects.toThrow();
    });

    it('should validate log level options', async () => {
      const tool = createStreamLiveExecutionTool(toolContext);
      
      await expect(tool.execute({
        scenarioId: 'scenario-123',
        outputFormat: 'json',
        logLevel: 'invalid-level' as any
      }, { log: mockLogger })).rejects.toThrow();
    });

    it('should accept valid streaming configuration', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          streamId: 'stream-123',
          status: 'active',
          websocketUrl: 'wss://api.example.com/stream/stream-123'
        }
      });

      const tool = createStreamLiveExecutionTool(toolContext);
      
      const result = await tool.execute({
        scenarioId: 'scenario-123',
        outputFormat: 'json',
        logLevel: 'info',
        includeMetadata: true,
        maxDuration: 3600
      }, { log: mockLogger });

      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
    });
  });

  describe('Live Streaming Configuration', () => {
    beforeEach(() => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          streamId: 'stream-live-123',
          status: 'active',
          websocketUrl: 'wss://api.example.com/stream/stream-live-123',
          scenarioId: 'scenario-123',
          startTime: '2024-01-15T10:00:00Z'
        }
      });
    });

    it('should start basic live execution stream', async () => {
      const tool = createStreamLiveExecutionTool(toolContext);
      
      const result = await tool.execute({
        scenarioId: 'scenario-123',
        outputFormat: 'json',
        logLevel: 'info',
        includeMetadata: false
      }, { log: mockLogger });

      expect(mockApiClient.post).toHaveBeenCalledWith(
        '/log-streaming/live/start',
        expect.objectContaining({
          scenarioId: 'scenario-123',
          outputFormat: 'json',
          logLevel: 'info',
          includeMetadata: false
        })
      );

      const parsed = JSON.parse(result);
      expect(parsed.stream).toBeDefined();
      expect(parsed.stream.streamId).toBe('stream-live-123');
      expect(parsed.stream.websocketUrl).toContain('wss://');
    });

    it('should configure advanced streaming with filters', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          streamId: 'filtered-stream-456',
          status: 'active',
          filters: {
            modules: ['webhook', 'http'],
            events: ['execution_start', 'execution_complete', 'error'],
            logLevel: 'warn'
          }
        }
      });

      const tool = createStreamLiveExecutionTool(toolContext);
      
      const result = await tool.execute({
        scenarioId: 'scenario-456',
        outputFormat: 'json',
        logLevel: 'warn',
        includeMetadata: true,
        filterModules: ['webhook', 'http'],
        filterEvents: ['execution_start', 'execution_complete', 'error'],
        maxDuration: 1800
      }, { log: mockLogger });

      expect(mockApiClient.post).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          filterModules: ['webhook', 'http'],
          filterEvents: ['execution_start', 'execution_complete', 'error'],
          maxDuration: 1800
        })
      );

      const parsed = JSON.parse(result);
      expect(parsed.filters).toBeDefined();
      expect(parsed.filters.modules).toContain('webhook');
    });

    it('should configure streaming with performance monitoring', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          streamId: 'perf-stream-789',
          status: 'active',
          monitoring: {
            enabled: true,
            metrics: ['execution_time', 'memory_usage', 'cpu_usage'],
            alerts: ['high_latency', 'memory_threshold']
          }
        }
      });

      const tool = createStreamLiveExecutionTool(toolContext);
      
      const result = await tool.execute({
        scenarioId: 'scenario-789',
        outputFormat: 'json',
        logLevel: 'debug',
        includeMetadata: true,
        enablePerformanceMonitoring: true,
        performanceMetrics: ['execution_time', 'memory_usage'],
        enableAlerts: true
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.monitoring.enabled).toBe(true);
      expect(parsed.monitoring.metrics).toContain('execution_time');
    });
  });

  describe('Output Format Configuration', () => {
    it('should configure JSON output format', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          streamId: 'json-stream-123',
          status: 'active',
          format: {
            type: 'json',
            schema: 'structured',
            prettified: false
          }
        }
      });

      const tool = createStreamLiveExecutionTool(toolContext);
      
      const result = await tool.execute({
        scenarioId: 'scenario-123',
        outputFormat: 'json',
        logLevel: 'info',
        jsonPrettified: false
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.format.type).toBe('json');
      expect(parsed.format.prettified).toBe(false);
    });

    it('should configure text output format', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          streamId: 'text-stream-123',
          status: 'active',
          format: {
            type: 'text',
            template: 'custom',
            delimiter: '\\n'
          }
        }
      });

      const tool = createStreamLiveExecutionTool(toolContext);
      
      const result = await tool.execute({
        scenarioId: 'scenario-123',
        outputFormat: 'text',
        logLevel: 'info',
        textFormat: 'custom',
        delimiter: '\\n'
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.format.type).toBe('text');
      expect(parsed.format.template).toBe('custom');
    });

    it('should configure CSV output format', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          streamId: 'csv-stream-123',
          status: 'active',
          format: {
            type: 'csv',
            headers: true,
            separator: ',',
            columns: ['timestamp', 'level', 'module', 'message']
          }
        }
      });

      const tool = createStreamLiveExecutionTool(toolContext);
      
      const result = await tool.execute({
        scenarioId: 'scenario-123',
        outputFormat: 'csv',
        logLevel: 'info',
        includeHeaders: true,
        csvSeparator: ',',
        selectColumns: ['timestamp', 'level', 'module', 'message']
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.format.type).toBe('csv');
      expect(parsed.format.headers).toBe(true);
      expect(parsed.format.columns).toContain('timestamp');
    });
  });

  describe('Real-time Filtering and Processing', () => {
    it('should configure module-specific filtering', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          streamId: 'module-filter-123',
          status: 'active',
          filters: {
            includeModules: ['webhook', 'http', 'email'],
            excludeModules: ['delay', 'sleep'],
            moduleConfig: {
              webhook: { includeHeaders: true },
              http: { includeResponseTime: true }
            }
          }
        }
      });

      const tool = createStreamLiveExecutionTool(toolContext);
      
      const result = await tool.execute({
        scenarioId: 'scenario-123',
        outputFormat: 'json',
        logLevel: 'info',
        filterModules: ['webhook', 'http', 'email'],
        excludeModules: ['delay', 'sleep'],
        moduleSpecificConfig: {
          webhook: { includeHeaders: true },
          http: { includeResponseTime: true }
        }
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.filters.includeModules).toContain('webhook');
      expect(parsed.filters.excludeModules).toContain('delay');
    });

    it('should configure event-type filtering', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          streamId: 'event-filter-123',
          status: 'active',
          filters: {
            events: {
              include: ['execution_start', 'execution_complete', 'error', 'warning'],
              exclude: ['debug', 'trace'],
              priority: 'include_first'
            }
          }
        }
      });

      const tool = createStreamLiveExecutionTool(toolContext);
      
      const result = await tool.execute({
        scenarioId: 'scenario-123',
        outputFormat: 'json',
        logLevel: 'warn',
        filterEvents: ['execution_start', 'execution_complete', 'error'],
        excludeEvents: ['debug', 'trace'],
        eventPriority: 'include_first'
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.filters.events.include).toContain('execution_start');
      expect(parsed.filters.events.exclude).toContain('debug');
    });

    it('should configure time-based filtering', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          streamId: 'time-filter-123',
          status: 'active',
          timeFilters: {
            startTime: '2024-01-15T10:00:00Z',
            endTime: '2024-01-15T12:00:00Z',
            timezone: 'UTC',
            bufferWindow: '30s'
          }
        }
      });

      const tool = createStreamLiveExecutionTool(toolContext);
      
      const result = await tool.execute({
        scenarioId: 'scenario-123',
        outputFormat: 'json',
        logLevel: 'info',
        startTime: '2024-01-15T10:00:00Z',
        endTime: '2024-01-15T12:00:00Z',
        timezone: 'UTC',
        bufferWindow: 30
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.timeFilters.startTime).toBeDefined();
      expect(parsed.timeFilters.timezone).toBe('UTC');
    });
  });

  describe('Performance and Monitoring', () => {
    it('should configure throughput monitoring', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          streamId: 'throughput-stream-123',
          status: 'active',
          performance: {
            throughput: {
              current: '1000 events/sec',
              peak: '2500 events/sec',
              average: '850 events/sec'
            },
            latency: {
              p50: '50ms',
              p95: '150ms',
              p99: '300ms'
            }
          }
        }
      });

      const tool = createStreamLiveExecutionTool(toolContext);
      
      const result = await tool.execute({
        scenarioId: 'scenario-123',
        outputFormat: 'json',
        logLevel: 'info',
        enablePerformanceMonitoring: true,
        monitorThroughput: true,
        monitorLatency: true
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.performance.throughput).toBeDefined();
      expect(parsed.performance.latency).toBeDefined();
    });

    it('should configure resource usage monitoring', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          streamId: 'resource-stream-123',
          status: 'active',
          resources: {
            memory: {
              current: '256MB',
              peak: '512MB',
              limit: '1GB'
            },
            cpu: {
              current: '15%',
              peak: '45%',
              cores: 4
            },
            bandwidth: {
              upstream: '10Mbps',
              downstream: '25Mbps'
            }
          }
        }
      });

      const tool = createStreamLiveExecutionTool(toolContext);
      
      const result = await tool.execute({
        scenarioId: 'scenario-123',
        outputFormat: 'json',
        logLevel: 'info',
        enablePerformanceMonitoring: true,
        monitorResources: true,
        resourceThresholds: {
          memory: '800MB',
          cpu: '80%'
        }
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.resources.memory).toBeDefined();
      expect(parsed.resources.cpu).toBeDefined();
    });

    it('should handle high-volume streaming scenarios', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          streamId: 'high-volume-stream-123',
          status: 'active',
          configuration: {
            bufferSize: '10MB',
            batchSize: 1000,
            compressionEnabled: true,
            sampling: {
              enabled: true,
              rate: 0.1,
              strategy: 'adaptive'
            }
          }
        }
      });

      const tool = createStreamLiveExecutionTool(toolContext);
      
      const result = await tool.execute({
        scenarioId: 'high-volume-scenario',
        outputFormat: 'json',
        logLevel: 'info',
        enableCompression: true,
        bufferSize: '10MB',
        batchSize: 1000,
        enableSampling: true,
        samplingRate: 0.1
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.configuration.compressionEnabled).toBe(true);
      expect(parsed.configuration.sampling.enabled).toBe(true);
    });
  });

  describe('Error Handling', () => {
    it('should handle scenario not found errors', async () => {
      mockApiClient.post.mockResolvedValue({
        success: false,
        error: { message: 'Scenario not found', code: 'SCENARIO_NOT_FOUND' }
      });

      const tool = createStreamLiveExecutionTool(toolContext);
      
      await expect(tool.execute({
        scenarioId: 'nonexistent-scenario',
        outputFormat: 'json',
        logLevel: 'info'
      }, { log: mockLogger })).rejects.toThrow(UserError);
    });

    it('should handle streaming service unavailable', async () => {
      mockApiClient.post.mockRejectedValue(new Error('Streaming service unavailable'));

      const tool = createStreamLiveExecutionTool(toolContext);
      
      await expect(tool.execute({
        scenarioId: 'scenario-123',
        outputFormat: 'json',
        logLevel: 'info'
      }, { log: mockLogger })).rejects.toThrow(UserError);

      expect(mockLogger.error).toHaveBeenCalledWith(
        expect.stringContaining('Failed to start live execution stream'),
        expect.any(Object)
      );
    });

    it('should handle invalid permissions', async () => {
      mockApiClient.post.mockResolvedValue({
        success: false,
        error: { message: 'Insufficient permissions to stream scenario', code: 'PERMISSION_DENIED' }
      });

      const tool = createStreamLiveExecutionTool(toolContext);
      
      await expect(tool.execute({
        scenarioId: 'restricted-scenario',
        outputFormat: 'json',
        logLevel: 'info'
      }, { log: mockLogger })).rejects.toThrow(UserError);
    });

    it('should handle stream capacity exceeded', async () => {
      mockApiClient.post.mockResolvedValue({
        success: false,
        error: { message: 'Streaming capacity exceeded', code: 'CAPACITY_EXCEEDED' }
      });

      const tool = createStreamLiveExecutionTool(toolContext);
      
      await expect(tool.execute({
        scenarioId: 'scenario-123',
        outputFormat: 'json',
        logLevel: 'debug', // High verbosity
        maxDuration: 86400 // 24 hours
      }, { log: mockLogger })).rejects.toThrow(UserError);
    });
  });

  describe('Integration and Compatibility', () => {
    it('should integrate with existing monitoring systems', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          streamId: 'integrated-stream-123',
          status: 'active',
          integrations: {
            prometheus: {
              enabled: true,
              endpoint: '/metrics',
              labels: ['scenario_id', 'module_type']
            },
            grafana: {
              dashboard_id: 'stream-monitoring-123',
              url: 'https://grafana.example.com/d/stream-monitoring-123'
            }
          }
        }
      });

      const tool = createStreamLiveExecutionTool(toolContext);
      
      const result = await tool.execute({
        scenarioId: 'scenario-123',
        outputFormat: 'json',
        logLevel: 'info',
        enablePrometheusMetrics: true,
        prometheusLabels: ['scenario_id', 'module_type'],
        createGrafanaDashboard: true
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.integrations.prometheus.enabled).toBe(true);
      expect(parsed.integrations.grafana).toBeDefined();
    });

    it('should configure webhook notifications', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          streamId: 'webhook-stream-123',
          status: 'active',
          webhooks: {
            onStart: 'https://hooks.example.com/stream/start',
            onComplete: 'https://hooks.example.com/stream/complete',
            onError: 'https://hooks.example.com/stream/error',
            retryPolicy: {
              maxRetries: 3,
              backoffMultiplier: 2
            }
          }
        }
      });

      const tool = createStreamLiveExecutionTool(toolContext);
      
      const result = await tool.execute({
        scenarioId: 'scenario-123',
        outputFormat: 'json',
        logLevel: 'info',
        webhookOnStart: 'https://hooks.example.com/stream/start',
        webhookOnComplete: 'https://hooks.example.com/stream/complete',
        webhookOnError: 'https://hooks.example.com/stream/error',
        webhookRetries: 3
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.webhooks.onStart).toBeDefined();
      expect(parsed.webhooks.retryPolicy.maxRetries).toBe(3);
    });

    it('should support multiple concurrent streams', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: { streamId: 'stream-123', status: 'active' }
      });

      const tool = createStreamLiveExecutionTool(toolContext);
      
      const streams = Array(5).fill(0).map(async (_, i) => {
        return tool.execute({
          scenarioId: `scenario-${i}`,
          outputFormat: 'json',
          logLevel: 'info'
        }, { log: mockLogger });
      });

      const results = await Promise.allSettled(streams);
      const successful = results.filter(r => r.status === 'fulfilled');
      
      expect(successful).toHaveLength(5);
    });
  });

  describe('Security and Access Control', () => {
    it('should validate stream access permissions', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          streamId: 'secure-stream-123',
          status: 'active',
          security: {
            encryption: 'TLS 1.3',
            authentication: 'required',
            authorization: 'rbac',
            accessToken: 'stream-token-***'
          }
        }
      });

      const tool = createStreamLiveExecutionTool(toolContext);
      
      const result = await tool.execute({
        scenarioId: 'secure-scenario',
        outputFormat: 'json',
        logLevel: 'info',
        requireAuthentication: true,
        encryptionLevel: 'high'
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.security.encryption).toBe('TLS 1.3');
      expect(parsed.security.authentication).toBe('required');
    });

    it('should handle data privacy and masking', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          streamId: 'privacy-stream-123',
          status: 'active',
          privacy: {
            dataClassification: 'sensitive',
            maskingEnabled: true,
            maskedFields: ['email', 'phone', 'ssn'],
            retentionPolicy: '30d'
          }
        }
      });

      const tool = createStreamLiveExecutionTool(toolContext);
      
      const result = await tool.execute({
        scenarioId: 'privacy-scenario',
        outputFormat: 'json',
        logLevel: 'info',
        enableDataMasking: true,
        maskSensitiveFields: ['email', 'phone', 'ssn'],
        dataRetention: '30d'
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.privacy.maskingEnabled).toBe(true);
      expect(parsed.privacy.maskedFields).toContain('email');
    });
  });
});