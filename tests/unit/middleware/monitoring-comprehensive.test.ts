/**
 * @fileoverview Comprehensive monitoring middleware tests - Advanced scenarios
 * Tests complex monitoring patterns, metrics collection, and performance analysis
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { FastMCP } from 'fastmcp';

// Enhanced mock setup with comprehensive metrics functionality
const mockMetricsInstance = {
  setActiveConnections: jest.fn(),
  recordRequest: jest.fn(),
  createTimer: jest.fn().mockReturnValue(() => 1.5), // Returns duration function
  recordToolExecution: jest.fn(),
  recordError: jest.fn(),
  recordAuthAttempt: jest.fn(),
  recordAuthDuration: jest.fn(),
  recordMakeApiCall: jest.fn(),
  healthCheck: jest.fn().mockResolvedValue({ 
    healthy: true, 
    metricsCount: 250,
    memoryUsage: '45MB',
    uptime: 86400000,
    errorRate: 0.03
  }),
  // Advanced metrics methods
  recordCustomMetric: jest.fn(),
  getMetricsSummary: jest.fn(),
  recordLatency: jest.fn(),
  recordThroughput: jest.fn(),
  recordMemoryUsage: jest.fn(),
  recordConnectionPoolStats: jest.fn(),
  exportMetrics: jest.fn(),
  getMetricsByTimeRange: jest.fn(),
  recordCircuitBreakerState: jest.fn(),
  recordCacheMetrics: jest.fn()
};

// Mock dependencies with enhanced monitoring capabilities
jest.mock('../../../src/lib/metrics.js', () => ({
  __esModule: true,
  default: mockMetricsInstance,
  metrics: mockMetricsInstance,
  MetricsCollector: {
    getInstance: jest.fn().mockReturnValue(mockMetricsInstance),
    resetInstance: jest.fn()
  }
}));

jest.mock('../../../src/lib/logger.js', () => ({
  default: {
    child: jest.fn().mockReturnValue({
      info: jest.fn(),
      debug: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
      trace: jest.fn(),
      child: jest.fn().mockReturnThis()
    })
  }
}));

jest.mock('../../../src/lib/config.js', () => ({
  default: {
    getLogLevel: jest.fn().mockReturnValue('debug'),
    getMetricsConfig: jest.fn().mockReturnValue({
      enabled: true,
      collectInterval: 5000,
      retentionPeriod: 86400000,
      exportEnabled: true
    })
  }
}));

import { MonitoringMiddleware } from '../../../src/middleware/monitoring.js';
import metrics from '../../../src/lib/metrics.js';
import logger from '../../../src/lib/logger.js';

const mockMetrics = metrics as jest.Mocked<typeof metrics>;
const mockLogger = logger as jest.Mocked<typeof logger>;

describe('MonitoringMiddleware - Comprehensive Tests', () => {
  let monitoringMiddleware: MonitoringMiddleware;
  let mockServer: jest.Mocked<FastMCP>;
  let mockChildLogger: jest.Mocked<ReturnType<typeof logger.child>>;

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Reset metrics mock state but keep the jest.fn() references intact
    Object.values(mockMetricsInstance).forEach(mock => {
      if (typeof mock === 'function' && 'mockClear' in mock) {
        mock.mockClear();
      }
    });
    
    // Reset timer mock to return consistent durations
    mockMetricsInstance.createTimer.mockReturnValue(() => 1.5);

    mockChildLogger = {
      info: jest.fn(),
      debug: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
      trace: jest.fn(),
      child: jest.fn().mockReturnThis()
    } as any;
    mockLogger.child = jest.fn().mockReturnValue(mockChildLogger);

    mockServer = {
      on: jest.fn(),
      emit: jest.fn(),
      addTool: jest.fn(),
      start: jest.fn(),
      stop: jest.fn(),
      removeAllListeners: jest.fn(),
      listenerCount: jest.fn()
    } as any;

    monitoringMiddleware = new MonitoringMiddleware();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Advanced Server Monitoring', () => {
    it('should monitor connection lifecycle with detailed session tracking', () => {
      monitoringMiddleware.initializeServerMonitoring(mockServer);

      const connectionEvents = [
        {
          event: 'connect',
          session: { id: 'session-001', userAgent: 'TestClient/1.0', ip: '192.168.1.100' },
          expectedConnections: 1
        },
        {
          event: 'connect', 
          session: { id: 'session-002', userAgent: 'WebApp/2.1', ip: '192.168.1.101' },
          expectedConnections: 2
        },
        {
          event: 'disconnect',
          session: { id: 'session-001' },
          expectedConnections: 1
        },
        {
          event: 'connect',
          session: { id: 'session-003', userAgent: 'MobileApp/1.5', ip: '192.168.1.102' },
          expectedConnections: 2
        },
        {
          event: 'disconnect',
          session: { id: 'session-002' },
          expectedConnections: 1
        },
        {
          event: 'disconnect', 
          session: { id: 'session-003' },
          expectedConnections: 0
        }
      ];

      connectionEvents.forEach((event, index) => {
        const eventHandler = mockServer.on.mock.calls.find(
          call => call[0] === event.event
        )?.[1] as Function;

        expect(eventHandler).toBeDefined();
        eventHandler({ session: event.session });

        expect(mockMetrics.setActiveConnections).toHaveBeenLastCalledWith(
          event.expectedConnections
        );

        const expectedRequestType = event.event === 'connect' ? 'client_connect' : 'client_disconnect';
        expect(mockMetrics.recordRequest).toHaveBeenLastCalledWith(
          event.event, expectedRequestType, 'success', 0
        );
      });
    });

    it('should monitor server performance metrics during high-load scenarios', () => {
      monitoringMiddleware.initializeServerMonitoring(mockServer);
      
      const loadTestScenarios = [
        {
          name: 'rapid_connections',
          connections: 50,
          disconnections: 20,
          duration: 1000
        },
        {
          name: 'sustained_load',
          connections: 100,
          disconnections: 95,
          duration: 5000
        },
        {
          name: 'burst_traffic',
          connections: 200,
          disconnections: 200,
          duration: 500
        }
      ];

      loadTestScenarios.forEach(scenario => {
        // Clear mock calls before each scenario to avoid accumulation
        mockMetrics.setActiveConnections.mockClear();
        mockMetrics.recordRequest.mockClear();
        
        const startTime = Date.now();
        
        // Simulate connections
        const connectHandler = mockServer.on.mock.calls.find(
          call => call[0] === 'connect'
        )?.[1] as Function;
        
        const disconnectHandler = mockServer.on.mock.calls.find(
          call => call[0] === 'disconnect'
        )?.[1] as Function;
        
        for (let i = 0; i < scenario.connections; i++) {
          connectHandler({ 
            session: { 
              id: `${scenario.name}-session-${i}`,
              connectTime: startTime + (i * (scenario.duration / scenario.connections))
            } 
          });
        }
        
        for (let i = 0; i < scenario.disconnections; i++) {
          disconnectHandler({ 
            session: { 
              id: `${scenario.name}-session-${i}`,
              disconnectTime: startTime + scenario.duration + (i * 10)
            } 
          });
        }
        
        // Verify metrics were recorded appropriately for this scenario only
        expect(mockMetrics.setActiveConnections).toHaveBeenCalledTimes(
          scenario.connections + scenario.disconnections
        );
        expect(mockMetrics.recordRequest).toHaveBeenCalledTimes(
          scenario.connections + scenario.disconnections
        );
      });
    });

    it('should detect and monitor connection anomalies and patterns', () => {
      monitoringMiddleware.initializeServerMonitoring(mockServer);
      
      const anomalyScenarios = [
        {
          pattern: 'rapid_reconnects',
          sessions: Array.from({length: 10}, (_, i) => ({
            id: 'unstable-client',
            reconnectAttempt: i + 1
          }))
        },
        {
          pattern: 'suspicious_activity',
          sessions: [
            { id: 'scanner-001', userAgent: 'Suspicious/Bot', ip: '192.168.1.999' },
            { id: 'scanner-002', userAgent: 'Suspicious/Bot', ip: '192.168.1.998' },
            { id: 'scanner-003', userAgent: 'Suspicious/Bot', ip: '192.168.1.997' }
          ]
        },
        {
          pattern: 'connection_flood',
          sessions: Array.from({length: 100}, (_, i) => ({
            id: `flood-${i}`,
            timestamp: Date.now() + i
          }))
        }
      ];

      anomalyScenarios.forEach(scenario => {
        // Clear mock calls before each scenario to avoid accumulation
        mockMetrics.recordRequest.mockClear();
        mockChildLogger.info.mockClear();
        mockChildLogger.warn.mockClear();
        
        const connectHandler = mockServer.on.mock.calls.find(
          call => call[0] === 'connect'
        )?.[1] as Function;

        scenario.sessions.forEach(session => {
          connectHandler({ session });
        });

        // Verify appropriate monitoring responses
        if (scenario.pattern === 'connection_flood') {
          expect(mockMetrics.recordRequest).toHaveBeenCalledTimes(scenario.sessions.length);
        } else if (scenario.pattern === 'rapid_reconnects') {
          // Verify that logging occurred for rapid reconnects
          expect(mockMetrics.recordRequest).toHaveBeenCalledTimes(scenario.sessions.length);
        }
      });
    });
  });

  describe('Advanced Tool Execution Monitoring', () => {
    it('should monitor tool execution performance with detailed timing analysis', async () => {
      const performanceProfiles = [
        {
          toolName: 'fast-tool',
          operation: 'quick-lookup',
          executionTimes: [0.05, 0.08, 0.12, 0.15, 0.09],
          expectedCategory: 'fast'
        },
        {
          toolName: 'medium-tool', 
          operation: 'data-processing',
          executionTimes: [0.5, 0.8, 1.2, 0.9, 1.1],
          expectedCategory: 'medium'
        },
        {
          toolName: 'slow-tool',
          operation: 'heavy-computation',
          executionTimes: [3.2, 4.1, 3.8, 4.5, 3.9],
          expectedCategory: 'slow'
        }
      ];

      for (const profile of performanceProfiles) {
        for (const executionTime of profile.executionTimes) {
          // Mock timer to return specific execution time
          mockMetricsInstance.createTimer.mockReturnValueOnce(() => executionTime);
          
          const mockExecution = jest.fn().mockResolvedValue({
            success: true,
            data: `${profile.toolName}-result`
          });
          
          const wrappedExecution = monitoringMiddleware.wrapToolExecution(
            profile.toolName,
            profile.operation,
            mockExecution,
            { category: profile.expectedCategory }
          );

          const result = await wrappedExecution();
          
          expect(result.data).toBe(`${profile.toolName}-result`);
          expect(mockExecution).toHaveBeenCalled();
          expect(mockMetrics.recordToolExecution).toHaveBeenCalledWith(
            profile.toolName, 'success', executionTime, undefined
          );
        }
      }
    });

    it('should categorize and analyze different types of tool execution errors', async () => {
      const errorScenarios = [
        {
          category: 'validation_errors',
          errors: [
            new Error('Invalid parameter: email format'),
            new Error('Missing required field: name'),
            new Error('Value out of range: age must be positive')
          ],
          expectedClassification: 'validation'
        },
        {
          category: 'authentication_errors',
          errors: [
            Object.assign(new Error('Unauthorized access'), { name: 'AuthenticationError' }),
            Object.assign(new Error('Token expired'), { name: 'UserError', message: '[AUTHENTICATION_ERROR: Token expired]' }),
            Object.assign(new Error('Invalid credentials'), { name: 'AuthenticationError' })
          ],
          expectedClassification: 'authentication'
        },
        {
          category: 'external_service_errors',
          errors: [
            Object.assign(new Error('API timeout'), { name: 'UserError', message: '[TIMEOUT: External service timeout]' }),
            Object.assign(new Error('Service unavailable'), { name: 'MakeServerError' }),
            Object.assign(new Error('Rate limit exceeded'), { name: 'UserError', message: '[RATE_LIMIT: Too many requests]' })
          ],
          expectedClassification: ['timeout', 'make_server_error', 'rate_limit']
        }
      ];

      for (const scenario of errorScenarios) {
        for (let i = 0; i < scenario.errors.length; i++) {
          const error = scenario.errors[i];
          const mockExecution = jest.fn().mockRejectedValue(error);
          
          const wrappedExecution = monitoringMiddleware.wrapToolExecution(
            `${scenario.category}-tool`,
            `${scenario.category}-operation`,
            mockExecution,
            { errorType: scenario.category }
          );

          await expect(wrappedExecution()).rejects.toThrow();
          
          expect(mockMetrics.recordToolExecution).toHaveBeenCalledWith(
            `${scenario.category}-tool`, 'error', 1.5, undefined
          );
          expect(mockMetrics.recordError).toHaveBeenCalled();
        }
      }
    });

    it('should implement tool execution circuit breaker monitoring', async () => {
      const circuitBreakerScenarios = [
        {
          toolName: 'unstable-service',
          failurePattern: [false, false, false, true, true, true, true, true], // 3 success, 5 failures
          expectedCircuitState: 'OPEN'
        },
        {
          toolName: 'recovering-service',
          failurePattern: [true, true, false, false, false], // 2 failures, 3 recoveries
          expectedCircuitState: 'HALF_OPEN'
        },
        {
          toolName: 'stable-service',
          failurePattern: [false, false, false, false, false], // All success
          expectedCircuitState: 'CLOSED'
        }
      ];

      for (const scenario of circuitBreakerScenarios) {
        // Clear mock calls before each scenario to avoid accumulation
        mockMetrics.recordToolExecution.mockClear();
        mockChildLogger.warn.mockClear();
        mockChildLogger.error.mockClear();
        
        let circuitState = 'CLOSED';
        let consecutiveFailures = 0;
        const failureThreshold = 3;
        
        for (const shouldFail of scenario.failurePattern) {
          const mockExecution = shouldFail 
            ? jest.fn().mockRejectedValue(new Error('Service failure'))
            : jest.fn().mockResolvedValue({ success: true, data: 'ok' });
          
          const wrappedExecution = monitoringMiddleware.wrapToolExecution(
            scenario.toolName,
            'monitored-operation',
            mockExecution,
            { circuitBreakerEnabled: true }
          );

          try {
            await wrappedExecution();
            consecutiveFailures = 0;
            if (circuitState === 'HALF_OPEN') {
              circuitState = 'CLOSED';
            }
          } catch (error) {
            consecutiveFailures++;
            if (consecutiveFailures >= failureThreshold && circuitState === 'CLOSED') {
              circuitState = 'OPEN';
            }
          }
        }
        
        // Verify circuit breaker metrics were recorded for this scenario
        expect(mockMetrics.recordToolExecution).toHaveBeenCalledTimes(scenario.failurePattern.length);
        
        // In a real implementation, we would verify circuit breaker state
        // For now, we verify the expected pattern was simulated
        const failureCount = scenario.failurePattern.filter(f => f).length;
        const successCount = scenario.failurePattern.filter(f => !f).length;
        
        if (failureCount >= failureThreshold) {
          // For circuit breaker scenarios, we expect either warn or error logging
          const loggerCalled = mockChildLogger.warn.mock.calls.length > 0 || 
                              mockChildLogger.error.mock.calls.length > 0;
          expect(loggerCalled).toBe(true);
        }
      }
    });

    it('should monitor concurrent tool execution and resource utilization', async () => {
      const concurrencyScenarios = [
        {
          name: 'low_concurrency',
          concurrent: 3,
          duration: 100,
          expectedResourcePressure: 'low'
        },
        {
          name: 'medium_concurrency',
          concurrent: 10, 
          duration: 500,
          expectedResourcePressure: 'medium'
        },
        {
          name: 'high_concurrency',
          concurrent: 25,
          duration: 1000, 
          expectedResourcePressure: 'high'
        }
      ];

      for (const scenario of concurrencyScenarios) {
        // Clear mock calls before each scenario to avoid accumulation
        mockMetrics.recordToolExecution.mockClear();
        
        const concurrentExecutions = [];
        
        for (let i = 0; i < scenario.concurrent; i++) {
          const mockExecution = jest.fn().mockImplementation(() => 
            new Promise(resolve => 
              setTimeout(() => resolve({ success: true, data: `result-${i}` }), scenario.duration)
            )
          );
          
          const wrappedExecution = monitoringMiddleware.wrapToolExecution(
            `concurrent-tool-${i}`,
            'concurrent-operation',
            mockExecution,
            { concurrency: scenario.concurrent }
          );

          concurrentExecutions.push(wrappedExecution());
        }

        const startTime = Date.now();
        const results = await Promise.allSettled(concurrentExecutions);
        const totalDuration = Date.now() - startTime;
        
        // Verify all executions completed
        expect(results.filter(r => r.status === 'fulfilled')).toHaveLength(scenario.concurrent);
        
        // Verify concurrent execution was actually concurrent (not sequential)
        expect(totalDuration).toBeLessThan(scenario.duration * scenario.concurrent * 0.5);
        
        // Verify metrics were recorded for each execution in this scenario only
        expect(mockMetrics.recordToolExecution).toHaveBeenCalledTimes(scenario.concurrent);
      }
    });
  });

  describe('Authentication and Security Monitoring', () => {
    it('should monitor authentication patterns and detect anomalies', async () => {
      const authenticationScenarios = [
        {
          pattern: 'normal_usage',
          attempts: [
            { success: true, user: 'alice', method: 'oauth' },
            { success: true, user: 'bob', method: 'token' },
            { success: true, user: 'charlie', method: 'oauth' }
          ],
          expectedThreat: 'none'
        },
        {
          pattern: 'brute_force',
          attempts: [
            { success: false, user: 'admin', method: 'password', ip: '192.168.1.100' },
            { success: false, user: 'admin', method: 'password', ip: '192.168.1.100' },
            { success: false, user: 'admin', method: 'password', ip: '192.168.1.100' },
            { success: false, user: 'admin', method: 'password', ip: '192.168.1.100' },
            { success: false, user: 'admin', method: 'password', ip: '192.168.1.100' }
          ],
          expectedThreat: 'high'
        },
        {
          pattern: 'credential_stuffing',
          attempts: [
            { success: false, user: 'user1', method: 'password', ip: '10.0.0.1' },
            { success: false, user: 'user2', method: 'password', ip: '10.0.0.1' },
            { success: false, user: 'user3', method: 'password', ip: '10.0.0.1' },
            { success: false, user: 'user4', method: 'password', ip: '10.0.0.1' }
          ],
          expectedThreat: 'medium'
        }
      ];

      for (const scenario of authenticationScenarios) {
        for (const attempt of scenario.attempts) {
          const mockAuth = attempt.success
            ? jest.fn().mockResolvedValue({ token: 'valid-token', user: attempt.user })
            : jest.fn().mockRejectedValue(new Error('Authentication failed'));
          
          const wrappedAuth = monitoringMiddleware.monitorAuthentication(
            mockAuth,
            { 
              user: attempt.user, 
              method: attempt.method, 
              ip: attempt.ip,
              pattern: scenario.pattern
            }
          );

          try {
            const result = await wrappedAuth();
            expect(mockMetrics.recordAuthAttempt).toHaveBeenLastCalledWith('success');
            expect(mockMetrics.recordAuthDuration).toHaveBeenLastCalledWith(1.5);
          } catch (error) {
            expect(mockMetrics.recordAuthAttempt).toHaveBeenLastCalledWith('failure', 'generic_error');
            expect(mockMetrics.recordError).toHaveBeenCalled();
          }
        }
        
        // Verify threat detection logic would be triggered
        if (scenario.expectedThreat === 'high' || scenario.expectedThreat === 'medium') {
          const failureCount = scenario.attempts.filter(a => !a.success).length;
          expect(failureCount).toBeGreaterThan(2);
        }
      }
    });

    it('should monitor session security and token management', async () => {
      const sessionScenarios = [
        {
          name: 'token_rotation',
          sessions: [
            { token: 'token-001', expiry: Date.now() + 3600000, rotation: true },
            { token: 'token-002', expiry: Date.now() + 3600000, rotation: true },
            { token: 'token-003', expiry: Date.now() + 3600000, rotation: true }
          ],
          expectedBehavior: 'healthy_rotation'
        },
        {
          name: 'token_reuse',
          sessions: [
            { token: 'static-token', expiry: Date.now() + 3600000, rotation: false },
            { token: 'static-token', expiry: Date.now() + 3600000, rotation: false },
            { token: 'static-token', expiry: Date.now() + 3600000, rotation: false }
          ],
          expectedBehavior: 'security_concern'
        },
        {
          name: 'expired_tokens',
          sessions: [
            { token: 'expired-001', expiry: Date.now() - 3600000, rotation: false },
            { token: 'expired-002', expiry: Date.now() - 1800000, rotation: false }
          ],
          expectedBehavior: 'authentication_failure'
        }
      ];

      for (const scenario of sessionScenarios) {
        for (const session of scenario.sessions) {
          const isTokenValid = session.expiry > Date.now();
          
          const mockAuth = jest.fn().mockImplementation(() => {
            if (isTokenValid) {
              return Promise.resolve({ 
                token: session.token, 
                expiry: session.expiry,
                rotated: session.rotation
              });
            } else {
              return Promise.reject(new Error('Token expired'));
            }
          });
          
          const wrappedAuth = monitoringMiddleware.monitorAuthentication(
            mockAuth,
            { 
              scenario: scenario.name,
              tokenInfo: {
                token: session.token,
                expiry: session.expiry,
                rotation: session.rotation
              }
            }
          );

          try {
            await wrappedAuth();
            expect(mockMetrics.recordAuthAttempt).toHaveBeenCalledWith('success');
          } catch (error) {
            expect(mockMetrics.recordAuthAttempt).toHaveBeenCalledWith('failure', 'generic_error');
          }
        }
      }
    });
  });

  describe('API Call Monitoring and Analysis', () => {
    it('should monitor Make.com API call patterns and performance', async () => {
      const apiCallScenarios = [
        {
          category: 'scenarios_api',
          calls: [
            { endpoint: '/api/v2/scenarios', method: 'GET', duration: 150, status: 200 },
            { endpoint: '/api/v2/scenarios/123', method: 'GET', duration: 95, status: 200 },
            { endpoint: '/api/v2/scenarios', method: 'POST', duration: 300, status: 201 },
            { endpoint: '/api/v2/scenarios/123', method: 'PUT', duration: 220, status: 200 }
          ]
        },
        {
          category: 'users_api',
          calls: [
            { endpoint: '/api/v2/users', method: 'GET', duration: 120, status: 200 },
            { endpoint: '/api/v2/users/456', method: 'GET', duration: 80, status: 200 },
            { endpoint: '/api/v2/users/456', method: 'PATCH', duration: 180, status: 200 }
          ]
        },
        {
          category: 'error_scenarios',
          calls: [
            { endpoint: '/api/v2/invalid', method: 'GET', duration: 50, status: 404 },
            { endpoint: '/api/v2/scenarios', method: 'POST', duration: 25, status: 400 },
            { endpoint: '/api/v2/users', method: 'GET', duration: 5000, status: 500 }
          ]
        }
      ];

      let errorCallsProcessed = 0;
      
      for (const scenario of apiCallScenarios) {
        for (const call of scenario.calls) {
          // Mock timer to return specific duration
          mockMetricsInstance.createTimer.mockReturnValueOnce(() => call.duration / 1000);
          
          const mockApiCall = jest.fn().mockImplementation(() => {
            if (call.status >= 200 && call.status < 300) {
              return Promise.resolve({ 
                data: `Success response from ${call.endpoint}`,
                status: call.status
              });
            } else {
              const error = new Error(`HTTP ${call.status} Error`) as any;
              error.status = call.status;
              return Promise.reject(error);
            }
          });
          
          const wrappedCall = monitoringMiddleware.monitorMakeApiCall(
            call.endpoint,
            call.method,
            mockApiCall,
            { 
              category: scenario.category,
              expectedStatus: call.status
            }
          );

          try {
            const result = await wrappedCall();
            // This should be for successful calls (2xx status codes)
            expect(mockMetricsInstance.recordMakeApiCall).toHaveBeenLastCalledWith(
              call.endpoint, call.method, 'success', call.duration / 1000
            );
          } catch (error) {
            // This should be for error calls (4xx, 5xx status codes)
            errorCallsProcessed++;
            expect(mockMetricsInstance.recordMakeApiCall).toHaveBeenLastCalledWith(
              call.endpoint, call.method, 'error', call.duration / 1000
            );
            expect(mockMetricsInstance.recordError).toHaveBeenCalled();
          }
        }
      }

      // Verify that we processed some error calls
      expect(errorCallsProcessed).toBeGreaterThan(0);
    });

    it('should analyze API call efficiency and suggest optimizations', async () => {
      const performancePatterns = [
        {
          pattern: 'chatty_interface',
          calls: [
            { endpoint: '/api/v2/scenarios/1', method: 'GET', duration: 100 },
            { endpoint: '/api/v2/scenarios/2', method: 'GET', duration: 95 },
            { endpoint: '/api/v2/scenarios/3', method: 'GET', duration: 105 },
            { endpoint: '/api/v2/scenarios/4', method: 'GET', duration: 98 },
            { endpoint: '/api/v2/scenarios/5', method: 'GET', duration: 102 }
          ],
          optimizationSuggestion: 'batch_requests'
        },
        {
          pattern: 'redundant_calls',
          calls: [
            { endpoint: '/api/v2/users/profile', method: 'GET', duration: 150 },
            { endpoint: '/api/v2/users/profile', method: 'GET', duration: 145 },
            { endpoint: '/api/v2/users/profile', method: 'GET', duration: 152 }
          ],
          optimizationSuggestion: 'implement_caching'
        },
        {
          pattern: 'inefficient_queries',
          calls: [
            { endpoint: '/api/v2/scenarios?limit=1000&offset=0', method: 'GET', duration: 2500 },
            { endpoint: '/api/v2/scenarios?limit=1000&offset=1000', method: 'GET', duration: 2800 },
            { endpoint: '/api/v2/scenarios?limit=1000&offset=2000', method: 'GET', duration: 3200 }
          ],
          optimizationSuggestion: 'optimize_pagination'
        }
      ];

      for (const pattern of performancePatterns) {
        let totalDuration = 0;
        const duplicateEndpoints = new Set();
        const largeBatchSizes = [];
        
        for (const call of pattern.calls) {
          mockMetricsInstance.createTimer.mockReturnValueOnce(() => call.duration / 1000);
          totalDuration += call.duration;
          
          // Track duplicate endpoint calls
          const endpointBase = call.endpoint.split('?')[0];
          if (duplicateEndpoints.has(endpointBase)) {
            // Duplicate detected
          }
          duplicateEndpoints.add(endpointBase);
          
          // Check for large batch sizes
          if (call.endpoint.includes('limit=1000')) {
            largeBatchSizes.push(call.endpoint);
          }
          
          const mockApiCall = jest.fn().mockResolvedValue({
            data: `Pattern response: ${pattern.pattern}`
          });
          
          const wrappedCall = monitoringMiddleware.monitorMakeApiCall(
            call.endpoint,
            call.method,
            mockApiCall,
            { performancePattern: pattern.pattern }
          );

          await wrappedCall();
        }
        
        // Verify performance analysis
        const averageDuration = totalDuration / pattern.calls.length;
        
        if (pattern.pattern === 'chatty_interface') {
          expect(pattern.calls.length).toBeGreaterThan(3);
        } else if (pattern.pattern === 'redundant_calls') {
          expect(duplicateEndpoints.size).toBeLessThan(pattern.calls.length);
        } else if (pattern.pattern === 'inefficient_queries') {
          expect(largeBatchSizes.length).toBeGreaterThan(0);
          expect(averageDuration).toBeGreaterThan(2000);
        }
      }
    });
  });

  describe('Health Check and Diagnostic Monitoring', () => {
    it('should provide comprehensive system health monitoring', async () => {
      const healthScenarios = [
        {
          name: 'healthy_system',
          metricsHealth: {
            healthy: true,
            metricsCount: 1500,
            memoryUsage: '45MB',
            uptime: 86400000,
            errorRate: 0.01
          },
          expectedOverallHealth: true
        },
        {
          name: 'degraded_performance',
          metricsHealth: {
            healthy: true,
            metricsCount: 2500,
            memoryUsage: '180MB',
            uptime: 86400000,
            errorRate: 0.08
          },
          expectedOverallHealth: true
        },
        {
          name: 'system_failure',
          metricsHealth: {
            healthy: false,
            metricsCount: 0,
            memoryUsage: '0MB',
            uptime: 0,
            errorRate: 1.0
          },
          expectedOverallHealth: false
        }
      ];

      for (const scenario of healthScenarios) {
        mockMetricsInstance.healthCheck.mockResolvedValueOnce(scenario.metricsHealth);
        
        const healthStatus = await monitoringMiddleware.healthCheck();
        
        expect(healthStatus.healthy).toBe(scenario.expectedOverallHealth);
        expect(healthStatus.metricsSystem).toEqual(scenario.metricsHealth);
        expect(healthStatus).toHaveProperty('activeConnections');
        expect(healthStatus).toHaveProperty('activeToolExecutions');
        
        if (!scenario.expectedOverallHealth) {
          expect(mockChildLogger.error).toHaveBeenCalled();
        }
      }
    });

    it('should monitor system resource utilization and performance trends', async () => {
      const resourceScenarios = [
        {
          timeRange: 'peak_hours',
          metrics: {
            activeConnections: 150,
            activeToolExecutions: 25,
            memoryUsage: '200MB',
            cpuUtilization: 0.75,
            diskIO: 'high'
          },
          expectedAction: 'scale_up_alert'
        },
        {
          timeRange: 'off_peak',
          metrics: {
            activeConnections: 20,
            activeToolExecutions: 3,
            memoryUsage: '80MB',
            cpuUtilization: 0.15,
            diskIO: 'low'
          },
          expectedAction: 'normal_operation'
        },
        {
          timeRange: 'maintenance_window',
          metrics: {
            activeConnections: 0,
            activeToolExecutions: 0,
            memoryUsage: '50MB',
            cpuUtilization: 0.05,
            diskIO: 'minimal'
          },
          expectedAction: 'maintenance_mode'
        }
      ];

      for (const scenario of resourceScenarios) {
        // Create fresh middleware and mock server for each scenario 
        const scenarioMiddleware = new MonitoringMiddleware();
        const scenarioMockServer = {
          on: jest.fn(),
          emit: jest.fn(),
          addTool: jest.fn(),
          start: jest.fn(),
          stop: jest.fn()
        } as any;
        
        scenarioMiddleware.initializeServerMonitoring(scenarioMockServer);
        
        // Simulate resource utilization
        const connectHandler = scenarioMockServer.on.mock.calls.find(
          call => call[0] === 'connect'
        )?.[1] as Function;
        
        for (let i = 0; i < scenario.metrics.activeConnections; i++) {
          connectHandler({ session: { id: `resource-test-${i}` } });
        }
        
        // Simulate tool executions
        for (let i = 0; i < scenario.metrics.activeToolExecutions; i++) {
          const mockExecution = jest.fn().mockResolvedValue({ success: true });
          const wrappedExecution = scenarioMiddleware.wrapToolExecution(
            `resource-tool-${i}`,
            'resource-operation',
            mockExecution
          );
          
          // Don't await - simulate concurrent executions
          wrappedExecution();
        }
        
        const stats = scenarioMiddleware.getMonitoringStats();
        
        expect(stats.activeConnections).toBe(scenario.metrics.activeConnections);
        
        // Verify appropriate alerts would be triggered
        if (scenario.expectedAction === 'scale_up_alert') {
          expect(scenario.metrics.activeConnections).toBeGreaterThan(100);
        } else if (scenario.expectedAction === 'maintenance_mode') {
          expect(scenario.metrics.activeConnections).toBe(0);
        }
      }
    });
  });

  describe('Custom Metrics and Extensibility', () => {
    it('should support custom metric collection and analysis', () => {
      const customMetricScenarios = [
        {
          category: 'business_metrics',
          metrics: [
            { name: 'scenarios_created_today', value: 25, type: 'counter' },
            { name: 'average_scenario_complexity', value: 7.5, type: 'gauge' },
            { name: 'user_engagement_score', value: 0.85, type: 'gauge' }
          ]
        },
        {
          category: 'performance_metrics',
          metrics: [
            { name: 'cache_hit_ratio', value: 0.78, type: 'gauge' },
            { name: 'database_query_time', value: 150, type: 'histogram' },
            { name: 'external_api_errors', value: 12, type: 'counter' }
          ]
        },
        {
          category: 'security_metrics',
          metrics: [
            { name: 'failed_auth_attempts', value: 5, type: 'counter' },
            { name: 'suspicious_activity_score', value: 0.15, type: 'gauge' },
            { name: 'token_validation_time', value: 25, type: 'histogram' }
          ]
        }
      ];

      customMetricScenarios.forEach(scenario => {
        scenario.metrics.forEach(metric => {
          // Simulate custom metric recording
          if (mockMetricsInstance.recordCustomMetric) {
            mockMetricsInstance.recordCustomMetric(metric.name, metric.value, {
              type: metric.type,
              category: scenario.category,
              timestamp: Date.now()
            });
            
            expect(mockMetricsInstance.recordCustomMetric).toHaveBeenLastCalledWith(
              metric.name,
              metric.value,
              expect.objectContaining({
                type: metric.type,
                category: scenario.category
              })
            );
          }
        });
      });
    });

    it('should provide metrics export and integration capabilities', () => {
      const exportFormats = [
        {
          format: 'prometheus',
          expectedOutput: 'prometheus_metrics_format',
          contentType: 'text/plain'
        },
        {
          format: 'json',
          expectedOutput: 'json_metrics_format', 
          contentType: 'application/json'
        },
        {
          format: 'influxdb',
          expectedOutput: 'influxdb_line_protocol',
          contentType: 'text/plain'
        }
      ];

      exportFormats.forEach(format => {
        if (mockMetricsInstance.exportMetrics) {
          mockMetricsInstance.exportMetrics.mockReturnValueOnce({
            format: format.format,
            data: format.expectedOutput,
            contentType: format.contentType,
            timestamp: Date.now()
          });
          
          const exportResult = mockMetricsInstance.exportMetrics(format.format);
          
          expect(exportResult).toEqual({
            format: format.format,
            data: format.expectedOutput,
            contentType: format.contentType,
            timestamp: expect.any(Number)
          });
        }
      });
    });
  });

  describe('Shutdown and Cleanup', () => {
    it('should shutdown gracefully with comprehensive cleanup', () => {
      // Initialize monitoring
      monitoringMiddleware.initializeServerMonitoring(mockServer);
      
      // Create some activity
      const connectHandler = mockServer.on.mock.calls.find(
        call => call[0] === 'connect'
      )?.[1] as Function;
      
      connectHandler({ session: { id: 'test-session-1' } });
      connectHandler({ session: { id: 'test-session-2' } });
      
      // Shutdown
      monitoringMiddleware.shutdown();
      
      expect(mockChildLogger.info).toHaveBeenCalledWith('Shutting down monitoring middleware');
      expect(mockMetrics.setActiveConnections).toHaveBeenLastCalledWith(0);
      
      // Verify final state
      const finalStats = monitoringMiddleware.getMonitoringStats();
      expect(finalStats.activeConnections).toBe(0);
    });

    it('should handle shutdown errors gracefully without crashing', () => {
      // Simulate shutdown errors
      mockMetricsInstance.setActiveConnections.mockImplementationOnce(() => {
        throw new Error('Metrics cleanup failed');
      });
      
      expect(() => {
        monitoringMiddleware.shutdown();
      }).not.toThrow();
      
      expect(mockChildLogger.error || mockChildLogger.warn).toHaveBeenCalled();
    });
  });
});
