/**
 * Core Functionality Test Suite for Monitoring Middleware
 * Tests metrics collection, performance tracking, alerting, and health monitoring
 * Critical for ensuring observability and system health monitoring reliability
 * Covers request tracking, response time analysis, error monitoring, and resource usage
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { MonitoringConfig, MetricData, HealthStatus, AlertRule } from '../../../src/middleware/monitoring.js';

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

// Mock performance monitoring
jest.mock('../../../src/lib/performance-monitor.js', () => ({
  default: {
    startTimer: jest.fn(() => ({
      end: jest.fn(() => 150) // Mock 150ms duration
    })),
    recordMetric: jest.fn(),
    getMetrics: jest.fn(() => ({
      averageResponseTime: 120,
      totalRequests: 100,
      errorRate: 0.05
    }))
  }
}));

describe('Monitoring Middleware - Core Functionality Tests', () => {
  let MonitoringManager: any;
  let monitor: any;
  let componentLogger: any;

  beforeEach(async () => {
    jest.clearAllMocks();
    jest.resetModules();
    
    // Setup component logger mock
    componentLogger = {
      info: jest.fn(),
      error: jest.fn(),
      warn: jest.fn(),
      debug: jest.fn()
    };
    mockLogger.child.mockReturnValue(componentLogger);
    
    // Import the module after mocks are set up
    const monitoringModule = await import('../../../src/middleware/monitoring.js');
    MonitoringManager = monitoringModule.MonitoringManager;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Monitoring Manager Initialization', () => {
    it('should create monitoring manager with default configuration', () => {
      monitor = new MonitoringManager();
      
      expect(monitor).toBeDefined();
      expect(mockLogger.child).toHaveBeenCalledWith({ component: 'MonitoringManager' });
    });

    it('should create monitoring manager with custom configuration', () => {
      const config: MonitoringConfig = {
        enableMetrics: true,
        enableHealthChecks: true,
        enableAlerting: true,
        metricsRetentionDays: 7,
        healthCheckIntervalMs: 30000,
        alertThresholds: {
          errorRate: 0.1,
          responseTime: 5000,
          memoryUsage: 0.9
        }
      };
      
      monitor = new MonitoringManager(config);
      
      expect(monitor).toBeDefined();
      expect(monitor.getConfig()).toMatchObject(config);
    });

    it('should use default configuration when none provided', () => {
      monitor = new MonitoringManager();
      
      const config = monitor.getConfig();
      expect(config.enableMetrics).toBe(true);
      expect(config.enableHealthChecks).toBe(true);
      expect(config.enableAlerting).toBe(true);
      expect(config.metricsRetentionDays).toBe(30);
      expect(config.healthCheckIntervalMs).toBe(60000);
    });

    it('should validate configuration parameters', () => {
      const invalidConfigs = [
        { metricsRetentionDays: -1 },
        { healthCheckIntervalMs: -1 },
        { alertThresholds: { errorRate: -0.1 } },
        { alertThresholds: { errorRate: 1.1 } },
        { alertThresholds: { responseTime: -100 } }
      ];
      
      invalidConfigs.forEach(config => {
        expect(() => new MonitoringManager(config as MonitoringConfig))
          .toThrow('Invalid monitoring configuration');
      });
    });
  });

  describe('Metrics Collection', () => {
    beforeEach(() => {
      monitor = new MonitoringManager();
    });

    it('should record request metrics successfully', () => {
      const requestData = {
        method: 'GET',
        path: '/api/scenarios',
        statusCode: 200,
        responseTime: 150,
        userAgent: 'test-client',
        timestamp: Date.now()
      };
      
      monitor.recordRequest(requestData);
      
      const metrics = monitor.getMetrics();
      expect(metrics.requests.total).toBe(1);
      expect(metrics.requests.successful).toBe(1);
      expect(metrics.responses.averageTime).toBeGreaterThan(0);
      
      expect(componentLogger.debug).toHaveBeenCalledWith('Request recorded', expect.objectContaining({
        method: 'GET',
        path: '/api/scenarios',
        statusCode: 200
      }));
    });

    it('should record error metrics correctly', () => {
      const errorData = {
        method: 'POST',
        path: '/api/scenarios',
        statusCode: 500,
        responseTime: 75,
        error: 'Internal server error',
        timestamp: Date.now()
      };
      
      monitor.recordRequest(errorData);
      
      const metrics = monitor.getMetrics();
      expect(metrics.requests.total).toBe(1);
      expect(metrics.requests.errors).toBe(1);
      expect(metrics.errors.total).toBe(1);
      
      expect(componentLogger.warn).toHaveBeenCalledWith('Error request recorded', expect.objectContaining({
        statusCode: 500,
        error: 'Internal server error'
      }));
    });

    it('should calculate response time percentiles', () => {
      const responseTimes = [50, 100, 150, 200, 300, 500, 1000];
      
      responseTimes.forEach((time, index) => {
        monitor.recordRequest({
          method: 'GET',
          path: `/api/test/${index}`,
          statusCode: 200,
          responseTime: time,
          timestamp: Date.now()
        });
      });
      
      const metrics = monitor.getMetrics();
      expect(metrics.responses.p50).toBeDefined();
      expect(metrics.responses.p95).toBeDefined();
      expect(metrics.responses.p99).toBeDefined();
      expect(metrics.responses.p50).toBeLessThan(metrics.responses.p95);
      expect(metrics.responses.p95).toBeLessThan(metrics.responses.p99);
    });

    it('should track endpoint-specific metrics', () => {
      monitor.recordRequest({
        method: 'GET',
        path: '/api/scenarios',
        statusCode: 200,
        responseTime: 100,
        timestamp: Date.now()
      });
      
      monitor.recordRequest({
        method: 'POST',
        path: '/api/connections',
        statusCode: 201,
        responseTime: 200,
        timestamp: Date.now()
      });
      
      const endpointMetrics = monitor.getEndpointMetrics();
      expect(endpointMetrics['/api/scenarios']).toBeDefined();
      expect(endpointMetrics['/api/connections']).toBeDefined();
      expect(endpointMetrics['/api/scenarios'].averageResponseTime).toBe(100);
      expect(endpointMetrics['/api/connections'].averageResponseTime).toBe(200);
    });

    it('should aggregate metrics by time periods', () => {
      const now = Date.now();
      const hoursAgo = now - (2 * 60 * 60 * 1000); // 2 hours ago
      
      monitor.recordRequest({
        method: 'GET',
        path: '/api/test',
        statusCode: 200,
        responseTime: 100,
        timestamp: hoursAgo
      });
      
      monitor.recordRequest({
        method: 'GET',
        path: '/api/test',
        statusCode: 200,
        responseTime: 150,
        timestamp: now
      });
      
      const hourlyMetrics = monitor.getMetricsByTimeRange('1h');
      const dailyMetrics = monitor.getMetricsByTimeRange('24h');
      
      expect(hourlyMetrics.requests.total).toBe(1); // Only recent request
      expect(dailyMetrics.requests.total).toBe(2); // Both requests
    });
  });

  describe('Health Monitoring', () => {
    beforeEach(() => {
      monitor = new MonitoringManager();
    });

    it('should perform health checks and return status', async () => {
      const healthStatus = await monitor.getHealthStatus();
      
      expect(healthStatus).toBeDefined();
      expect(healthStatus.status).toMatch(/^(healthy|degraded|unhealthy)$/);
      expect(healthStatus.timestamp).toBeDefined();
      expect(healthStatus.checks).toBeDefined();
      expect(Array.isArray(healthStatus.checks)).toBe(true);
    });

    it('should check system resources in health status', async () => {
      const healthStatus = await monitor.getHealthStatus();
      
      const memoryCheck = healthStatus.checks.find(check => check.name === 'memory');
      const cpuCheck = healthStatus.checks.find(check => check.name === 'cpu');
      
      expect(memoryCheck).toBeDefined();
      expect(memoryCheck!.status).toMatch(/^(pass|fail)$/);
      expect(memoryCheck!.metrics).toBeDefined();
      
      expect(cpuCheck).toBeDefined();
      expect(cpuCheck!.status).toMatch(/^(pass|fail)$/);
    });

    it('should check external dependencies in health status', async () => {
      const healthStatus = await monitor.getHealthStatus();
      
      const apiCheck = healthStatus.checks.find(check => check.name === 'external_api');
      expect(apiCheck).toBeDefined();
      expect(apiCheck!.status).toMatch(/^(pass|fail)$/);
    });

    it('should determine overall health based on check results', async () => {
      // Mock failing health checks
      jest.spyOn(process, 'memoryUsage').mockReturnValue({
        rss: 1024 * 1024 * 1024, // 1GB
        heapTotal: 512 * 1024 * 1024,
        heapUsed: 500 * 1024 * 1024, // High memory usage
        external: 0,
        arrayBuffers: 0
      });
      
      const healthStatus = await monitor.getHealthStatus();
      
      // Should be degraded or unhealthy due to high memory usage
      expect(['degraded', 'unhealthy']).toContain(healthStatus.status);
    });

    it('should cache health check results', async () => {
      const firstCheck = await monitor.getHealthStatus();
      const secondCheck = await monitor.getHealthStatus();
      
      // Should be identical if cached properly
      expect(firstCheck.timestamp).toBe(secondCheck.timestamp);
    });

    it('should refresh health check cache after interval', async () => {
      monitor = new MonitoringManager({ healthCheckIntervalMs: 100 }); // 100ms cache
      
      const firstCheck = await monitor.getHealthStatus();
      
      // Wait for cache to expire
      await new Promise(resolve => setTimeout(resolve, 150));
      
      const secondCheck = await monitor.getHealthStatus();
      
      expect(secondCheck.timestamp).toBeGreaterThan(firstCheck.timestamp);
    });
  });

  describe('Alerting System', () => {
    beforeEach(() => {
      monitor = new MonitoringManager({
        enableAlerting: true,
        alertThresholds: {
          errorRate: 0.1, // 10%
          responseTime: 1000, // 1 second
          memoryUsage: 0.8 // 80%
        }
      });
    });

    it('should trigger error rate alerts', () => {
      // Record requests with high error rate
      for (let i = 0; i < 10; i++) {
        monitor.recordRequest({
          method: 'GET',
          path: '/api/test',
          statusCode: i < 3 ? 500 : 200, // 30% error rate
          responseTime: 100,
          timestamp: Date.now()
        });
      }
      
      const alerts = monitor.getActiveAlerts();
      const errorRateAlert = alerts.find(alert => alert.type === 'error_rate');
      
      expect(errorRateAlert).toBeDefined();
      expect(errorRateAlert!.severity).toBe('warning');
      expect(componentLogger.warn).toHaveBeenCalledWith('Alert triggered', expect.objectContaining({
        type: 'error_rate'
      }));
    });

    it('should trigger response time alerts', () => {
      monitor.recordRequest({
        method: 'GET',
        path: '/api/slow',
        statusCode: 200,
        responseTime: 2000, // 2 seconds - above threshold
        timestamp: Date.now()
      });
      
      const alerts = monitor.getActiveAlerts();
      const responseTimeAlert = alerts.find(alert => alert.type === 'response_time');
      
      expect(responseTimeAlert).toBeDefined();
      expect(responseTimeAlert!.severity).toBe('warning');
    });

    it('should resolve alerts when conditions improve', () => {
      // Trigger alert
      monitor.recordRequest({
        method: 'GET',
        path: '/api/test',
        statusCode: 500,
        responseTime: 100,
        timestamp: Date.now()
      });
      
      let alerts = monitor.getActiveAlerts();
      expect(alerts.length).toBeGreaterThan(0);
      
      // Record successful requests to improve metrics
      for (let i = 0; i < 20; i++) {
        monitor.recordRequest({
          method: 'GET',
          path: '/api/test',
          statusCode: 200,
          responseTime: 100,
          timestamp: Date.now()
        });
      }
      
      alerts = monitor.getActiveAlerts();
      const errorRateAlert = alerts.find(alert => alert.type === 'error_rate');
      expect(errorRateAlert).toBeUndefined(); // Should be resolved
    });

    it('should support custom alert rules', () => {
      const customRule: AlertRule = {
        name: 'high_throughput',
        condition: (metrics) => metrics.requests.total > 100,
        severity: 'info',
        message: 'High throughput detected'
      };
      
      monitor.addAlertRule(customRule);
      
      // Generate enough requests to trigger custom rule
      for (let i = 0; i < 101; i++) {
        monitor.recordRequest({
          method: 'GET',
          path: '/api/test',
          statusCode: 200,
          responseTime: 50,
          timestamp: Date.now()
        });
      }
      
      const alerts = monitor.getActiveAlerts();
      const customAlert = alerts.find(alert => alert.type === 'high_throughput');
      
      expect(customAlert).toBeDefined();
      expect(customAlert!.severity).toBe('info');
    });

    it('should disable alerting when configured', () => {
      monitor = new MonitoringManager({ enableAlerting: false });
      
      // Record high error rate
      for (let i = 0; i < 10; i++) {
        monitor.recordRequest({
          method: 'GET',
          path: '/api/test',
          statusCode: 500,
          responseTime: 100,
          timestamp: Date.now()
        });
      }
      
      const alerts = monitor.getActiveAlerts();
      expect(alerts.length).toBe(0);
    });
  });

  describe('Performance Tracking', () => {
    beforeEach(() => {
      monitor = new MonitoringManager();
    });

    it('should track request timing accurately', () => {
      const timer = monitor.startTimer('test_operation');
      
      // Simulate operation
      setTimeout(() => {
        const duration = timer.end();
        expect(duration).toBeGreaterThan(0);
        expect(typeof duration).toBe('number');
      }, 10);
    });

    it('should record custom metrics', () => {
      monitor.recordCustomMetric('database_connections', 25);
      monitor.recordCustomMetric('queue_size', 150);
      
      const customMetrics = monitor.getCustomMetrics();
      expect(customMetrics.database_connections).toBe(25);
      expect(customMetrics.queue_size).toBe(150);
    });

    it('should calculate moving averages for metrics', () => {
      const values = [10, 20, 30, 40, 50];
      
      values.forEach(value => {
        monitor.recordCustomMetric('test_metric', value);
      });
      
      const metrics = monitor.getCustomMetrics();
      expect(metrics.test_metric_avg).toBeDefined();
      expect(metrics.test_metric_avg).toBeCloseTo(30, 1); // Average of values
    });

    it('should track memory usage over time', () => {
      const memoryHistory = monitor.getMemoryHistory();
      
      expect(Array.isArray(memoryHistory)).toBe(true);
      expect(memoryHistory.length).toBeGreaterThan(0);
      
      const latestMemory = memoryHistory[memoryHistory.length - 1];
      expect(latestMemory.timestamp).toBeDefined();
      expect(latestMemory.heapUsed).toBeGreaterThan(0);
      expect(latestMemory.heapTotal).toBeGreaterThan(0);
    });

    it('should track CPU usage patterns', () => {
      const cpuHistory = monitor.getCpuHistory();
      
      expect(Array.isArray(cpuHistory)).toBe(true);
      
      if (cpuHistory.length > 0) {
        const latestCpu = cpuHistory[cpuHistory.length - 1];
        expect(latestCpu.timestamp).toBeDefined();
        expect(latestCpu.usage).toBeGreaterThanOrEqual(0);
        expect(latestCpu.usage).toBeLessThanOrEqual(100);
      }
    });
  });

  describe('Data Retention and Cleanup', () => {
    beforeEach(() => {
      monitor = new MonitoringManager({ metricsRetentionDays: 1 }); // 1 day retention
    });

    it('should clean up old metrics based on retention policy', () => {
      const oldTimestamp = Date.now() - (2 * 24 * 60 * 60 * 1000); // 2 days ago
      
      monitor.recordRequest({
        method: 'GET',
        path: '/api/old',
        statusCode: 200,
        responseTime: 100,
        timestamp: oldTimestamp
      });
      
      monitor.recordRequest({
        method: 'GET',
        path: '/api/new',
        statusCode: 200,
        responseTime: 100,
        timestamp: Date.now()
      });
      
      monitor.cleanupOldMetrics();
      
      const metrics = monitor.getMetrics();
      expect(metrics.requests.total).toBe(1); // Only recent request should remain
    });

    it('should manage memory usage by limiting stored data', () => {
      // Record many requests to test memory management
      for (let i = 0; i < 1000; i++) {
        monitor.recordRequest({
          method: 'GET',
          path: `/api/test/${i}`,
          statusCode: 200,
          responseTime: 100,
          timestamp: Date.now()
        });
      }
      
      const initialSize = monitor.getDataSize();
      monitor.cleanupOldMetrics();
      const finalSize = monitor.getDataSize();
      
      expect(finalSize).toBeLessThanOrEqual(initialSize);
    });
  });

  describe('Error Handling and Edge Cases', () => {
    beforeEach(() => {
      monitor = new MonitoringManager();
    });

    it('should handle invalid request data gracefully', () => {
      const invalidRequests = [
        {}, // Missing required fields
        { method: 'INVALID' }, // Invalid method
        { statusCode: 'not_a_number' }, // Invalid status code
        { responseTime: -100 } // Negative response time
      ];
      
      invalidRequests.forEach(request => {
        expect(() => monitor.recordRequest(request as any)).not.toThrow();
      });
    });

    it('should handle health check failures gracefully', async () => {
      // Mock health check failure
      jest.spyOn(process, 'memoryUsage').mockImplementation(() => {
        throw new Error('Memory check failed');
      });
      
      const healthStatus = await monitor.getHealthStatus();
      
      expect(healthStatus.status).toBe('degraded');
      expect(componentLogger.error).toHaveBeenCalledWith(
        'Health check error',
        expect.any(Object)
      );
    });

    it('should handle timer errors gracefully', () => {
      const timer = monitor.startTimer('test');
      
      // Call end multiple times
      const duration1 = timer.end();
      const duration2 = timer.end();
      
      expect(duration1).toBeGreaterThan(0);
      expect(duration2).toBe(0); // Second call should return 0
    });

    it('should handle metrics calculation errors', () => {
      // Record invalid data that might cause calculation errors
      monitor.recordRequest({
        method: 'GET',
        path: '/api/test',
        statusCode: 200,
        responseTime: Infinity,
        timestamp: Date.now()
      });
      
      expect(() => monitor.getMetrics()).not.toThrow();
    });

    it('should handle concurrent access safely', () => {
      const operations = [];
      
      // Simulate concurrent operations
      for (let i = 0; i < 100; i++) {
        operations.push(() => monitor.recordRequest({
          method: 'GET',
          path: `/api/test/${i}`,
          statusCode: 200,
          responseTime: Math.random() * 1000,
          timestamp: Date.now()
        }));
        operations.push(() => monitor.getMetrics());
        operations.push(() => monitor.getHealthStatus());
      }
      
      // Execute all operations
      operations.forEach(op => op());
      
      // Monitoring should remain in consistent state
      expect(() => monitor.getMetrics()).not.toThrow();
      expect(monitor.getMetrics().requests.total).toBeGreaterThan(0);
    });
  });

  describe('Configuration Management', () => {
    it('should allow runtime configuration updates', () => {
      monitor = new MonitoringManager();
      
      const newConfig: MonitoringConfig = {
        enableMetrics: false,
        enableHealthChecks: true,
        enableAlerting: false,
        metricsRetentionDays: 7,
        healthCheckIntervalMs: 30000
      };
      
      monitor.updateConfig(newConfig);
      const currentConfig = monitor.getConfig();
      
      expect(currentConfig).toMatchObject(newConfig);
      expect(componentLogger.info).toHaveBeenCalledWith('Monitoring configuration updated', newConfig);
    });

    it('should validate configuration during updates', () => {
      monitor = new MonitoringManager();
      
      const invalidConfig = { metricsRetentionDays: -5 };
      
      expect(() => monitor.updateConfig(invalidConfig as MonitoringConfig))
        .toThrow('Invalid monitoring configuration');
    });

    it('should apply new thresholds after configuration update', () => {
      monitor = new MonitoringManager();
      
      monitor.updateConfig({
        alertThresholds: {
          errorRate: 0.05, // 5% - very low threshold
          responseTime: 500,
          memoryUsage: 0.7
        }
      });
      
      // Record request with 10% error rate
      for (let i = 0; i < 10; i++) {
        monitor.recordRequest({
          method: 'GET',
          path: '/api/test',
          statusCode: i < 1 ? 500 : 200, // 10% error rate
          responseTime: 100,
          timestamp: Date.now()
        });
      }
      
      const alerts = monitor.getActiveAlerts();
      const errorRateAlert = alerts.find(alert => alert.type === 'error_rate');
      
      expect(errorRateAlert).toBeDefined(); // Should trigger with new low threshold
    });
  });
});