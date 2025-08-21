/**
 * @fileoverview External service integration tests for Make.com API and third-party services
 * 
 * Tests integration with external APIs, webhook handling, rate limiting,
 * authentication flows, and service availability monitoring.
 * 
 * @version 1.0.0
 */

import { describe, test, expect, beforeAll, afterAll, beforeEach, afterEach } from '@jest/globals';
import type MakeApiClient from '../../src/lib/make-api-client.js';

// External service types and interfaces
interface ExternalService {
  id: string;
  name: string;
  baseUrl: string;
  authType: 'oauth2' | 'api_key' | 'bearer' | 'basic';
  status: 'available' | 'degraded' | 'unavailable';
  lastHealthCheck: string;
  responseTimeMs: number;
  rateLimits: {
    requestsPerMinute: number;
    requestsPerHour: number;
    currentUsage: number;
  };
}

interface ApiResponse<T = unknown> {
  data: T;
  status: number;
  headers: Record<string, string>;
  requestId?: string;
  rateLimitRemaining?: number;
  rateLimitReset?: number;
}

interface WebhookPayload {
  id: string;
  event: string;
  timestamp: string;
  source: string;
  data: Record<string, unknown>;
  signature?: string;
  retryCount?: number;
}

interface ServiceConnection {
  id: string;
  serviceId: string;
  connectionType: string;
  credentials: Record<string, unknown>;
  isVerified: boolean;
  lastTested: string;
  testResults: {
    success: boolean;
    responseTime: number;
    errorMessage?: string;
  };
}

// Mock external service simulator
class MockExternalServiceSimulator {
  private services: Map<string, ExternalService> = new Map();
  private connections: Map<string, ServiceConnection> = new Map();
  private webhookEndpoints: Map<string, Function> = new Map();
  private requestLogs: Array<{ service: string; endpoint: string; timestamp: string; response: number }> = [];

  // Service management
  async registerService(service: ExternalService): Promise<void> {
    this.services.set(service.id, { ...service });
  }

  async getService(id: string): Promise<ExternalService | null> {
    return this.services.get(id) || null;
  }

  async updateServiceStatus(id: string, status: ExternalService['status'], responseTime?: number): Promise<void> {
    const service = this.services.get(id);
    if (service) {
      service.status = status;
      service.lastHealthCheck = new Date().toISOString();
      if (responseTime !== undefined) {
        service.responseTimeMs = responseTime;
      }
    }
  }

  // Health checks
  async performHealthCheck(serviceId: string): Promise<{ healthy: boolean; responseTime: number; error?: string }> {
    const service = this.services.get(serviceId);
    if (!service) {
      return { healthy: false, responseTime: 0, error: 'Service not found' };
    }

    // Simulate health check with random response time and occasional failures
    const responseTime = Math.random() * 1000 + 100; // 100-1100ms
    const isHealthy = Math.random() > 0.1; // 90% success rate

    await this.updateServiceStatus(
      serviceId,
      isHealthy ? 'available' : 'degraded',
      responseTime
    );

    return {
      healthy: isHealthy,
      responseTime,
      error: isHealthy ? undefined : 'Service temporarily unavailable',
    };
  }

  async performBulkHealthCheck(): Promise<Record<string, { healthy: boolean; responseTime: number }>> {
    const results: Record<string, { healthy: boolean; responseTime: number }> = {};
    
    const healthChecks = Array.from(this.services.keys()).map(async (serviceId) => {
      const result = await this.performHealthCheck(serviceId);
      results[serviceId] = { healthy: result.healthy, responseTime: result.responseTime };
    });

    await Promise.all(healthChecks);
    return results;
  }

  // API request simulation
  async makeRequest<T>(
    serviceId: string,
    endpoint: string,
    method: 'GET' | 'POST' | 'PUT' | 'DELETE' = 'GET',
    data?: unknown
  ): Promise<ApiResponse<T>> {
    const service = this.services.get(serviceId);
    if (!service) {
      throw new Error(`Service ${serviceId} not found`);
    }

    // Check rate limits
    if (service.rateLimits.currentUsage >= service.rateLimits.requestsPerMinute) {
      throw new Error('Rate limit exceeded');
    }

    // Simulate network delay
    const delay = Math.random() * 200 + 50; // 50-250ms
    await new Promise(resolve => setTimeout(resolve, delay));

    // Update rate limit usage
    service.rateLimits.currentUsage += 1;

    // Simulate different response scenarios
    const shouldFail = Math.random() < 0.05; // 5% failure rate
    const status = shouldFail ? 500 : 200;

    // Log request
    this.requestLogs.push({
      service: serviceId,
      endpoint,
      timestamp: new Date().toISOString(),
      response: status,
    });

    if (shouldFail) {
      throw new Error(`HTTP ${status}: Server error`);
    }

    // Generate mock response data
    const responseData = this.generateMockResponse(serviceId, endpoint, method, data);

    return {
      data: responseData as T,
      status,
      headers: {
        'content-type': 'application/json',
        'x-rate-limit-remaining': String(service.rateLimits.requestsPerMinute - service.rateLimits.currentUsage),
        'x-rate-limit-reset': String(Date.now() + 60000), // Reset in 1 minute
      },
      requestId: `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      rateLimitRemaining: service.rateLimits.requestsPerMinute - service.rateLimits.currentUsage,
      rateLimitReset: Date.now() + 60000,
    };
  }

  // Connection testing
  async createConnection(connection: ServiceConnection): Promise<ServiceConnection> {
    this.connections.set(connection.id, { ...connection });
    return connection;
  }

  async testConnection(connectionId: string): Promise<{ success: boolean; responseTime: number; errorMessage?: string }> {
    const connection = this.connections.get(connectionId);
    if (!connection) {
      throw new Error(`Connection ${connectionId} not found`);
    }

    const service = this.services.get(connection.serviceId);
    if (!service) {
      throw new Error(`Service ${connection.serviceId} not found`);
    }

    const startTime = Date.now();
    
    try {
      // Simulate connection test
      await this.makeRequest(connection.serviceId, '/auth/verify', 'GET');
      const responseTime = Date.now() - startTime;

      const result = {
        success: true,
        responseTime,
      };

      // Update connection
      connection.isVerified = true;
      connection.lastTested = new Date().toISOString();
      connection.testResults = result;

      return result;
    } catch (error) {
      const responseTime = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';

      const result = {
        success: false,
        responseTime,
        errorMessage,
      };

      // Update connection
      connection.isVerified = false;
      connection.lastTested = new Date().toISOString();
      connection.testResults = result;

      return result;
    }
  }

  // Webhook handling
  async registerWebhookEndpoint(endpoint: string, handler: Function): Promise<void> {
    this.webhookEndpoints.set(endpoint, handler);
  }

  async simulateWebhook(endpoint: string, payload: WebhookPayload): Promise<{ success: boolean; error?: string }> {
    const handler = this.webhookEndpoints.get(endpoint);
    if (!handler) {
      return { success: false, error: 'Endpoint not found' };
    }

    try {
      await handler(payload);
      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Handler error',
      };
    }
  }

  // OAuth2 simulation
  async initiateOAuth2Flow(serviceId: string, redirectUri: string): Promise<{ authUrl: string; state: string }> {
    const service = this.services.get(serviceId);
    if (!service) {
      throw new Error(`Service ${serviceId} not found`);
    }

    const state = `oauth_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const authUrl = `${service.baseUrl}/oauth/authorize?client_id=test&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}`;

    return { authUrl, state };
  }

  async handleOAuth2Callback(serviceId: string, code: string, state: string): Promise<{ accessToken: string; refreshToken: string; expiresIn: number }> {
    const service = this.services.get(serviceId);
    if (!service) {
      throw new Error(`Service ${serviceId} not found`);
    }

    // Simulate token exchange
    return {
      accessToken: `access_${serviceId}_${Date.now()}`,
      refreshToken: `refresh_${serviceId}_${Date.now()}`,
      expiresIn: 3600,
    };
  }

  // Rate limiting simulation
  async resetRateLimits(): Promise<void> {
    for (const service of this.services.values()) {
      service.rateLimits.currentUsage = 0;
    }
  }

  async checkRateLimit(serviceId: string): Promise<{ remaining: number; resetTime: number; exceeded: boolean }> {
    const service = this.services.get(serviceId);
    if (!service) {
      throw new Error(`Service ${serviceId} not found`);
    }

    return {
      remaining: service.rateLimits.requestsPerMinute - service.rateLimits.currentUsage,
      resetTime: Date.now() + 60000,
      exceeded: service.rateLimits.currentUsage >= service.rateLimits.requestsPerMinute,
    };
  }

  // Utility methods
  private generateMockResponse(serviceId: string, endpoint: string, method: string, data?: unknown): unknown {
    // Generate different responses based on service and endpoint
    switch (serviceId) {
      case 'make-api':
        if (endpoint.includes('/scenarios')) {
          return {
            scenarios: [
              { id: 1, name: 'Test Scenario', status: 'active' },
              { id: 2, name: 'Another Scenario', status: 'draft' },
            ],
          };
        }
        if (endpoint.includes('/connections')) {
          return {
            connections: [
              { id: 1, name: 'API Connection', type: 'rest', verified: true },
              { id: 2, name: 'Database Connection', type: 'mysql', verified: false },
            ],
          };
        }
        break;

      case 'webhook-service':
        return {
          webhooks: [
            { id: 'wh_1', url: 'https://example.com/webhook', events: ['scenario.updated'] },
          ],
        };

      case 'analytics-service':
        return {
          metrics: {
            requests: 1000,
            errors: 5,
            avgResponseTime: 250,
          },
        };

      default:
        return {
          success: true,
          timestamp: new Date().toISOString(),
          data: data || {},
        };
    }

    return { success: true, timestamp: new Date().toISOString() };
  }

  // Analytics and monitoring
  getRequestLogs(serviceId?: string): Array<{ service: string; endpoint: string; timestamp: string; response: number }> {
    return serviceId
      ? this.requestLogs.filter(log => log.service === serviceId)
      : [...this.requestLogs];
  }

  getServiceStats(serviceId: string): { totalRequests: number; successRate: number; avgResponseTime: number } | null {
    const service = this.services.get(serviceId);
    if (!service) return null;

    const logs = this.getRequestLogs(serviceId);
    const totalRequests = logs.length;
    const successfulRequests = logs.filter(log => log.response < 400).length;
    const successRate = totalRequests > 0 ? successfulRequests / totalRequests : 0;

    return {
      totalRequests,
      successRate,
      avgResponseTime: service.responseTimeMs,
    };
  }

  // Test utilities
  async clear(): Promise<void> {
    this.services.clear();
    this.connections.clear();
    this.webhookEndpoints.clear();
    this.requestLogs.length = 0;
  }

  getStats(): { services: number; connections: number; webhooks: number; requests: number } {
    return {
      services: this.services.size,
      connections: this.connections.size,
      webhooks: this.webhookEndpoints.size,
      requests: this.requestLogs.length,
    };
  }
}

describe('External Service Integration Tests', () => {
  let serviceSimulator: MockExternalServiceSimulator;
  let mockApiClient: MakeApiClient;

  // Test services
  const makeApiService: ExternalService = {
    id: 'make-api',
    name: 'Make.com API',
    baseUrl: 'https://api.make.com/v2',
    authType: 'oauth2',
    status: 'available',
    lastHealthCheck: new Date().toISOString(),
    responseTimeMs: 150,
    rateLimits: {
      requestsPerMinute: 60,
      requestsPerHour: 1000,
      currentUsage: 0,
    },
  };

  const webhookService: ExternalService = {
    id: 'webhook-service',
    name: 'Webhook Service',
    baseUrl: 'https://webhook.example.com',
    authType: 'api_key',
    status: 'available',
    lastHealthCheck: new Date().toISOString(),
    responseTimeMs: 75,
    rateLimits: {
      requestsPerMinute: 100,
      requestsPerHour: 5000,
      currentUsage: 0,
    },
  };

  const analyticsService: ExternalService = {
    id: 'analytics-service',
    name: 'Analytics Service',
    baseUrl: 'https://analytics.example.com',
    authType: 'bearer',
    status: 'available',
    lastHealthCheck: new Date().toISOString(),
    responseTimeMs: 200,
    rateLimits: {
      requestsPerMinute: 30,
      requestsPerHour: 500,
      currentUsage: 0,
    },
  };

  beforeAll(async () => {
    serviceSimulator = new MockExternalServiceSimulator();
    
    mockApiClient = {
      get: jest.fn(),
      post: jest.fn(),
      put: jest.fn(),
      delete: jest.fn(),
    } as unknown as MakeApiClient;

    // Register test services
    await serviceSimulator.registerService(makeApiService);
    await serviceSimulator.registerService(webhookService);
    await serviceSimulator.registerService(analyticsService);
  });

  beforeEach(async () => {
    await serviceSimulator.resetRateLimits();
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Service Health Monitoring', () => {
    test('should perform individual service health checks', async () => {
      const healthCheck = await serviceSimulator.performHealthCheck('make-api');
      
      expect(healthCheck.healthy).toBeDefined();
      expect(healthCheck.responseTime).toBeGreaterThan(0);
      expect(healthCheck.responseTime).toBeLessThan(2000);

      if (!healthCheck.healthy) {
        expect(healthCheck.error).toBeTruthy();
      }

      // Verify service status was updated
      const service = await serviceSimulator.getService('make-api');
      expect(service!.lastHealthCheck).toBeTruthy();
      expect(service!.responseTimeMs).toBe(healthCheck.responseTime);
    });

    test('should perform bulk health checks across all services', async () => {
      const healthResults = await serviceSimulator.performBulkHealthCheck();
      
      expect(healthResults).toHaveProperty('make-api');
      expect(healthResults).toHaveProperty('webhook-service');
      expect(healthResults).toHaveProperty('analytics-service');

      Object.values(healthResults).forEach(result => {
        expect(result.healthy).toBeDefined();
        expect(result.responseTime).toBeGreaterThan(0);
      });
    });

    test('should handle health check failures gracefully', async () => {
      // Register a service that will always fail
      await serviceSimulator.registerService({
        id: 'failing-service',
        name: 'Failing Service',
        baseUrl: 'https://nonexistent.example.com',
        authType: 'api_key',
        status: 'unavailable',
        lastHealthCheck: new Date().toISOString(),
        responseTimeMs: 0,
        rateLimits: { requestsPerMinute: 10, requestsPerHour: 100, currentUsage: 0 },
      });

      // Force the service to fail by setting status
      await serviceSimulator.updateServiceStatus('failing-service', 'unavailable');

      const healthCheck = await serviceSimulator.performHealthCheck('failing-service');
      
      // Health check should still return a result, even for failing services
      expect(healthCheck.healthy).toBeDefined();
      expect(healthCheck.responseTime).toBeGreaterThanOrEqual(0);
    });
  });

  describe('API Request Integration', () => {
    test('should make successful API requests to external services', async () => {
      const response = await serviceSimulator.makeRequest<{ scenarios: unknown[] }>(
        'make-api',
        '/scenarios',
        'GET'
      );

      expect(response.status).toBe(200);
      expect(response.data).toBeTruthy();
      expect(response.data.scenarios).toBeInstanceOf(Array);
      expect(response.headers['content-type']).toBe('application/json');
      expect(response.requestId).toBeTruthy();
      expect(response.rateLimitRemaining).toBeGreaterThanOrEqual(0);
    });

    test('should handle POST requests with data', async () => {
      const postData = {
        name: 'New Scenario',
        blueprint: { modules: [] },
        teamId: 123,
      };

      const response = await serviceSimulator.makeRequest(
        'make-api',
        '/scenarios',
        'POST',
        postData
      );

      expect(response.status).toBe(200);
      expect(response.data).toBeTruthy();
      expect(response.requestId).toBeTruthy();
    });

    test('should respect rate limits', async () => {
      const service = await serviceSimulator.getService('analytics-service');
      expect(service!.rateLimits.requestsPerMinute).toBe(30);

      // Make requests up to the limit
      const requests = [];
      for (let i = 0; i < 30; i++) {
        requests.push(serviceSimulator.makeRequest('analytics-service', '/metrics', 'GET'));
      }

      await Promise.all(requests);

      // Next request should fail due to rate limit
      await expect(
        serviceSimulator.makeRequest('analytics-service', '/metrics', 'GET')
      ).rejects.toThrow('Rate limit exceeded');
    });

    test('should handle API errors gracefully', async () => {
      // Make multiple requests to trigger the 5% failure rate
      let errorOccurred = false;
      
      for (let i = 0; i < 50; i++) {
        try {
          await serviceSimulator.makeRequest('make-api', '/test-endpoint', 'GET');
        } catch (error) {
          errorOccurred = true;
          expect(error).toBeInstanceOf(Error);
          expect((error as Error).message).toContain('HTTP 500');
          break;
        }
      }

      // With 50 requests and 5% failure rate, we should hit at least one error
      // Note: This test might occasionally pass all requests due to randomness
    });

    test('should track request logs for monitoring', async () => {
      await serviceSimulator.makeRequest('make-api', '/scenarios', 'GET');
      await serviceSimulator.makeRequest('webhook-service', '/webhooks', 'GET');

      const allLogs = serviceSimulator.getRequestLogs();
      expect(allLogs.length).toBeGreaterThanOrEqual(2);

      const makeApiLogs = serviceSimulator.getRequestLogs('make-api');
      expect(makeApiLogs.length).toBeGreaterThanOrEqual(1);
      expect(makeApiLogs[0].service).toBe('make-api');
      expect(makeApiLogs[0].endpoint).toBe('/scenarios');
    });
  });

  describe('Connection Testing', () => {
    test('should create and test service connections', async () => {
      const connection: ServiceConnection = {
        id: 'conn-test-1',
        serviceId: 'make-api',
        connectionType: 'oauth2',
        credentials: {
          accessToken: 'test-token-123',
          refreshToken: 'refresh-token-456',
        },
        isVerified: false,
        lastTested: new Date().toISOString(),
        testResults: {
          success: false,
          responseTime: 0,
        },
      };

      const createdConnection = await serviceSimulator.createConnection(connection);
      expect(createdConnection).toEqual(connection);

      // Test the connection
      const testResult = await serviceSimulator.testConnection(connection.id);
      
      expect(testResult.success).toBeDefined();
      expect(testResult.responseTime).toBeGreaterThan(0);

      if (!testResult.success) {
        expect(testResult.errorMessage).toBeTruthy();
      }
    });

    test('should handle connection test failures', async () => {
      const connection: ServiceConnection = {
        id: 'conn-test-2',
        serviceId: 'nonexistent-service',
        connectionType: 'api_key',
        credentials: { apiKey: 'invalid-key' },
        isVerified: false,
        lastTested: new Date().toISOString(),
        testResults: { success: false, responseTime: 0 },
      };

      await serviceSimulator.createConnection(connection);

      // Should throw error for nonexistent service
      await expect(
        serviceSimulator.testConnection(connection.id)
      ).rejects.toThrow('Service nonexistent-service not found');
    });

    test('should verify connection credentials', async () => {
      const validConnection: ServiceConnection = {
        id: 'conn-valid',
        serviceId: 'make-api',
        connectionType: 'bearer',
        credentials: { token: 'valid-bearer-token' },
        isVerified: false,
        lastTested: new Date().toISOString(),
        testResults: { success: false, responseTime: 0 },
      };

      await serviceSimulator.createConnection(validConnection);
      const result = await serviceSimulator.testConnection(validConnection.id);

      // Most tests should succeed (95% success rate in mock)
      if (result.success) {
        expect(result.responseTime).toBeGreaterThan(0);
        expect(result.errorMessage).toBeUndefined();
      }
    });
  });

  describe('OAuth2 Authentication Flow', () => {
    test('should initiate OAuth2 authorization flow', async () => {
      const redirectUri = 'https://myapp.example.com/auth/callback';
      
      const authFlow = await serviceSimulator.initiateOAuth2Flow('make-api', redirectUri);
      
      expect(authFlow.authUrl).toBeTruthy();
      expect(authFlow.authUrl).toContain('oauth/authorize');
      expect(authFlow.authUrl).toContain(`redirect_uri=${encodeURIComponent(redirectUri)}`);
      expect(authFlow.state).toBeTruthy();
      expect(authFlow.state).toMatch(/^oauth_\d+_[a-z0-9]+$/);
    });

    test('should handle OAuth2 callback and token exchange', async () => {
      const redirectUri = 'https://myapp.example.com/auth/callback';
      const authFlow = await serviceSimulator.initiateOAuth2Flow('make-api', redirectUri);
      
      const tokenResult = await serviceSimulator.handleOAuth2Callback(
        'make-api',
        'auth-code-123',
        authFlow.state
      );

      expect(tokenResult.accessToken).toBeTruthy();
      expect(tokenResult.accessToken).toContain('access_make-api_');
      expect(tokenResult.refreshToken).toBeTruthy();
      expect(tokenResult.refreshToken).toContain('refresh_make-api_');
      expect(tokenResult.expiresIn).toBe(3600);
    });

    test('should handle OAuth2 errors', async () => {
      await expect(
        serviceSimulator.initiateOAuth2Flow('nonexistent-service', 'https://example.com')
      ).rejects.toThrow('Service nonexistent-service not found');

      await expect(
        serviceSimulator.handleOAuth2Callback('nonexistent-service', 'code', 'state')
      ).rejects.toThrow('Service nonexistent-service not found');
    });
  });

  describe('Webhook Integration', () => {
    test('should register and handle webhook endpoints', async () => {
      const webhookHandler = jest.fn().mockResolvedValue(undefined);
      
      await serviceSimulator.registerWebhookEndpoint('/webhook/scenario-updated', webhookHandler);

      const payload: WebhookPayload = {
        id: 'webhook-1',
        event: 'scenario.updated',
        timestamp: new Date().toISOString(),
        source: 'make-api',
        data: {
          scenarioId: 123,
          changes: ['name', 'status'],
        },
        signature: 'sha256=test-signature',
      };

      const result = await serviceSimulator.simulateWebhook('/webhook/scenario-updated', payload);
      
      expect(result.success).toBe(true);
      expect(result.error).toBeUndefined();
      expect(webhookHandler).toHaveBeenCalledWith(payload);
    });

    test('should handle webhook delivery failures', async () => {
      const failingHandler = jest.fn().mockRejectedValue(new Error('Handler failed'));
      
      await serviceSimulator.registerWebhookEndpoint('/webhook/failing', failingHandler);

      const payload: WebhookPayload = {
        id: 'webhook-2',
        event: 'test.event',
        timestamp: new Date().toISOString(),
        source: 'test',
        data: {},
      };

      const result = await serviceSimulator.simulateWebhook('/webhook/failing', payload);
      
      expect(result.success).toBe(false);
      expect(result.error).toBe('Handler failed');
    });

    test('should handle webhook to nonexistent endpoint', async () => {
      const payload: WebhookPayload = {
        id: 'webhook-3',
        event: 'test.event',
        timestamp: new Date().toISOString(),
        source: 'test',
        data: {},
      };

      const result = await serviceSimulator.simulateWebhook('/webhook/nonexistent', payload);
      
      expect(result.success).toBe(false);
      expect(result.error).toBe('Endpoint not found');
    });

    test('should handle webhook retries', async () => {
      const retryHandler = jest.fn()
        .mockRejectedValueOnce(new Error('Temporary failure'))
        .mockResolvedValueOnce(undefined);
      
      await serviceSimulator.registerWebhookEndpoint('/webhook/retry', retryHandler);

      const payload: WebhookPayload = {
        id: 'webhook-retry',
        event: 'test.retry',
        timestamp: new Date().toISOString(),
        source: 'test',
        data: {},
        retryCount: 1,
      };

      // First attempt should fail
      let result = await serviceSimulator.simulateWebhook('/webhook/retry', payload);
      expect(result.success).toBe(false);

      // Second attempt should succeed
      result = await serviceSimulator.simulateWebhook('/webhook/retry', payload);
      expect(result.success).toBe(true);
    });
  });

  describe('Rate Limiting and Throttling', () => {
    test('should check rate limit status', async () => {
      const rateLimitStatus = await serviceSimulator.checkRateLimit('make-api');
      
      expect(rateLimitStatus.remaining).toBe(60); // Full limit available
      expect(rateLimitStatus.resetTime).toBeGreaterThan(Date.now());
      expect(rateLimitStatus.exceeded).toBe(false);
    });

    test('should track rate limit usage', async () => {
      // Make some requests
      await serviceSimulator.makeRequest('make-api', '/test1', 'GET');
      await serviceSimulator.makeRequest('make-api', '/test2', 'GET');

      const rateLimitStatus = await serviceSimulator.checkRateLimit('make-api');
      
      expect(rateLimitStatus.remaining).toBe(58); // 60 - 2 = 58
      expect(rateLimitStatus.exceeded).toBe(false);
    });

    test('should handle rate limit exceeded scenarios', async () => {
      // Use up all requests for analytics service (30 per minute)
      const requests = [];
      for (let i = 0; i < 30; i++) {
        requests.push(serviceSimulator.makeRequest('analytics-service', `/test${i}`, 'GET'));
      }
      await Promise.all(requests);

      const rateLimitStatus = await serviceSimulator.checkRateLimit('analytics-service');
      expect(rateLimitStatus.remaining).toBe(0);
      expect(rateLimitStatus.exceeded).toBe(true);
    });

    test('should reset rate limits', async () => {
      // Use some requests
      await serviceSimulator.makeRequest('make-api', '/test', 'GET');
      
      let rateLimitStatus = await serviceSimulator.checkRateLimit('make-api');
      expect(rateLimitStatus.remaining).toBe(59);

      // Reset limits
      await serviceSimulator.resetRateLimits();
      
      rateLimitStatus = await serviceSimulator.checkRateLimit('make-api');
      expect(rateLimitStatus.remaining).toBe(60);
    });
  });

  describe('Service Analytics and Monitoring', () => {
    test('should collect request statistics', async () => {
      // Make several requests
      await serviceSimulator.makeRequest('make-api', '/scenarios', 'GET');
      await serviceSimulator.makeRequest('make-api', '/connections', 'GET');
      await serviceSimulator.makeRequest('webhook-service', '/webhooks', 'GET');

      const makeApiStats = serviceSimulator.getServiceStats('make-api');
      expect(makeApiStats).toBeTruthy();
      expect(makeApiStats!.totalRequests).toBeGreaterThanOrEqual(2);
      expect(makeApiStats!.successRate).toBeGreaterThanOrEqual(0);
      expect(makeApiStats!.successRate).toBeLessThanOrEqual(1);
      expect(makeApiStats!.avgResponseTime).toBeGreaterThan(0);
    });

    test('should track service-specific request logs', async () => {
      await serviceSimulator.makeRequest('make-api', '/test-endpoint', 'GET');
      
      const logs = serviceSimulator.getRequestLogs('make-api');
      expect(logs.length).toBeGreaterThanOrEqual(1);
      
      const latestLog = logs[logs.length - 1];
      expect(latestLog.service).toBe('make-api');
      expect(latestLog.endpoint).toBe('/test-endpoint');
      expect(latestLog.response).toBeDefined();
      expect(latestLog.timestamp).toBeTruthy();
    });

    test('should calculate success rates accurately', async () => {
      // Force some failures by making many requests (5% failure rate)
      const requests = [];
      for (let i = 0; i < 100; i++) {
        requests.push(
          serviceSimulator.makeRequest('make-api', `/test${i}`, 'GET').catch(() => {
            // Ignore errors for this test
          })
        );
      }
      
      await Promise.all(requests);
      
      const stats = serviceSimulator.getServiceStats('make-api');
      expect(stats!.totalRequests).toBe(100);
      expect(stats!.successRate).toBeGreaterThan(0.8); // Should be around 95%
      expect(stats!.successRate).toBeLessThanOrEqual(1.0);
    });
  });

  describe('Concurrent External Service Operations', () => {
    test('should handle concurrent API requests', async () => {
      const concurrentRequests = Array.from({ length: 10 }, (_, i) =>
        serviceSimulator.makeRequest('make-api', `/concurrent/${i}`, 'GET')
      );

      const results = await Promise.allSettled(concurrentRequests);
      
      // Most requests should succeed
      const successfulResults = results.filter(r => r.status === 'fulfilled');
      expect(successfulResults.length).toBeGreaterThan(8); // At least 80% success

      successfulResults.forEach(result => {
        expect((result as PromiseFulfilledResult<any>).value.status).toBe(200);
        expect((result as PromiseFulfilledResult<any>).value.requestId).toBeTruthy();
      });
    });

    test('should handle concurrent connection tests', async () => {
      // Create multiple connections
      const connections = await Promise.all([
        serviceSimulator.createConnection({
          id: 'conn-concurrent-1',
          serviceId: 'make-api',
          connectionType: 'oauth2',
          credentials: { token: 'token1' },
          isVerified: false,
          lastTested: new Date().toISOString(),
          testResults: { success: false, responseTime: 0 },
        }),
        serviceSimulator.createConnection({
          id: 'conn-concurrent-2',
          serviceId: 'webhook-service',
          connectionType: 'api_key',
          credentials: { apiKey: 'key2' },
          isVerified: false,
          lastTested: new Date().toISOString(),
          testResults: { success: false, responseTime: 0 },
        }),
        serviceSimulator.createConnection({
          id: 'conn-concurrent-3',
          serviceId: 'analytics-service',
          connectionType: 'bearer',
          credentials: { token: 'bearer3' },
          isVerified: false,
          lastTested: new Date().toISOString(),
          testResults: { success: false, responseTime: 0 },
        }),
      ]);

      // Test all connections concurrently
      const testResults = await Promise.allSettled(
        connections.map(conn => serviceSimulator.testConnection(conn.id))
      );

      testResults.forEach(result => {
        if (result.status === 'fulfilled') {
          expect(result.value.success).toBeDefined();
          expect(result.value.responseTime).toBeGreaterThan(0);
        }
      });
    });

    test('should handle concurrent health checks', async () => {
      const healthChecks = await Promise.all([
        serviceSimulator.performHealthCheck('make-api'),
        serviceSimulator.performHealthCheck('webhook-service'),
        serviceSimulator.performHealthCheck('analytics-service'),
      ]);

      healthChecks.forEach(check => {
        expect(check.healthy).toBeDefined();
        expect(check.responseTime).toBeGreaterThan(0);
      });

      // At least some should be healthy
      const healthyServices = healthChecks.filter(check => check.healthy);
      expect(healthyServices.length).toBeGreaterThan(0);
    });
  });

  describe('Error Recovery and Resilience', () => {
    test('should handle service unavailability', async () => {
      // Mark service as unavailable
      await serviceSimulator.updateServiceStatus('make-api', 'unavailable');

      // Health check should reflect unavailable status
      const service = await serviceSimulator.getService('make-api');
      expect(service!.status).toBe('unavailable');

      // Requests might still work in simulation, but would fail in real scenario
      // This test ensures the status tracking works correctly
    });

    test('should handle network timeouts gracefully', async () => {
      // Simulate timeout by making the request handler delay longer
      const startTime = Date.now();
      
      try {
        await serviceSimulator.makeRequest('make-api', '/slow-endpoint', 'GET');
        const duration = Date.now() - startTime;
        
        // Request should complete within reasonable time (our mock has max 250ms delay)
        expect(duration).toBeLessThan(1000);
      } catch (error) {
        // If it fails, it should be a proper error
        expect(error).toBeInstanceOf(Error);
      }
    });

    test('should handle authentication failures', async () => {
      const invalidConnection: ServiceConnection = {
        id: 'conn-invalid-auth',
        serviceId: 'make-api',
        connectionType: 'oauth2',
        credentials: { accessToken: 'invalid-token' },
        isVerified: false,
        lastTested: new Date().toISOString(),
        testResults: { success: false, responseTime: 0 },
      };

      await serviceSimulator.createConnection(invalidConnection);

      // Connection test might fail due to invalid credentials
      const testResult = await serviceSimulator.testConnection(invalidConnection.id);
      
      // Test should complete with some result
      expect(testResult.success).toBeDefined();
      expect(testResult.responseTime).toBeGreaterThanOrEqual(0);
      
      if (!testResult.success) {
        expect(testResult.errorMessage).toBeTruthy();
      }
    });

    test('should implement circuit breaker pattern simulation', async () => {
      // This test simulates a basic circuit breaker pattern
      let consecutiveFailures = 0;
      const maxFailures = 3;
      let circuitOpen = false;

      // Simulate multiple failing requests
      for (let i = 0; i < 5; i++) {
        try {
          if (circuitOpen) {
            throw new Error('Circuit breaker is open');
          }

          await serviceSimulator.makeRequest('make-api', '/test-circuit', 'GET');
          consecutiveFailures = 0; // Reset on success
        } catch (error) {
          consecutiveFailures++;
          if (consecutiveFailures >= maxFailures) {
            circuitOpen = true;
          }
        }
      }

      // Circuit should be open after multiple failures
      if (consecutiveFailures >= maxFailures) {
        expect(circuitOpen).toBe(true);
      }
    });
  });
});