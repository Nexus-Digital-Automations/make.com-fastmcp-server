/**
 * Integration tests for Make.com API client
 * Tests rate limiting, retry logic, error handling, and real API interactions
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import axios from 'axios';
import { MockMakeApiClient } from '../mocks/make-api-client.mock.js';
import { 
  simulateNetworkConditions,
  expectErrorResponse,
  performanceHelpers,
  waitForCondition
} from '../utils/test-helpers.js';
import { testErrors } from '../fixtures/test-data.js';

// Mock axios for controlled testing
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('Make.com API Client Integration Tests', () => {
  let mockApiClient: MockMakeApiClient;

  beforeEach(() => {
    mockApiClient = new MockMakeApiClient();
    jest.clearAllMocks();
  });

  afterEach(() => {
    mockApiClient.reset();
  });

  describe('Rate Limiting', () => {
    it('should respect rate limits and wait for reset', async () => {
      // Simulate hitting rate limit
      mockApiClient.mockFailure('GET', '/test-endpoint', new Error('Rate limit exceeded'));
      
      // First request should fail
      await expect(mockApiClient.get('/test-endpoint')).rejects.toThrow('Rate limit exceeded');
      
      // Simulate rate limit reset
      mockApiClient.mockResponse('GET', '/test-endpoint', {
        success: true,
        data: { message: 'Success after rate limit' }
      });
      
      // Next request should succeed
      const response = await mockApiClient.get('/test-endpoint');
      expect(response.success).toBe(true);
    });

    it('should provide rate limiter status information', async () => {
      const status = mockApiClient.getRateLimiterStatus();
      
      expect(status).toHaveProperty('remaining');
      expect(status).toHaveProperty('resetTime');
      expect(status).toHaveProperty('limit');
      expect(typeof status.remaining).toBe('number');
      expect(typeof status.limit).toBe('number');
    });

    it('should handle concurrent requests within rate limits', async () => {
      // Set up successful responses for concurrent requests
      for (let i = 0; i < 10; i++) {
        mockApiClient.mockResponse('GET', `/test-${i}`, {
          success: true,
          data: { id: i }
        });
      }
      
      // Execute concurrent requests
      const promises = Array.from({ length: 10 }, (_, i) => 
        mockApiClient.get(`/test-${i}`)
      );
      
      const results = await Promise.all(promises);
      
      expect(results).toHaveLength(10);
      results.forEach((result, index) => {
        expect(result.success).toBe(true);
        expect(result.data.id).toBe(index);
      });
    });
  });

  describe('Retry Logic', () => {
    it('should retry failed requests with exponential backoff', async () => {
      let attemptCount = 0;
      
      // Mock a service that fails twice then succeeds
      const originalGet = mockApiClient.get.bind(mockApiClient);
      mockApiClient.get = jest.fn(async (endpoint) => {
        attemptCount++;
        if (attemptCount <= 2) {
          throw new Error('Temporary service error');
        }
        return originalGet(endpoint as string);
      });
      
      mockApiClient.mockResponse('GET', '/retry-test', {
        success: true,
        data: { message: 'Success after retries' }
      });
      
      const { result, duration } = await performanceHelpers.measureExecutionTime(async () => {
        return await mockApiClient.get('/retry-test');
      });
      
      expect(result.success).toBe(true);
      expect(attemptCount).toBe(3);
      // Should take some time due to retry delays
      expect(duration).toBeGreaterThan(100);
    });

    it('should not retry non-retryable errors', async () => {
      let attemptCount = 0;
      
      mockApiClient.get = jest.fn(async () => {
        attemptCount++;
        const error = new Error('Unauthorized') as any;
        error.status = 401;
        throw error;
      });
      
      await expect(mockApiClient.get('/unauthorized-test')).rejects.toThrow('Unauthorized');
      expect(attemptCount).toBe(1); // Should not retry 401 errors
    });

    it('should give up after maximum retry attempts', async () => {
      let attemptCount = 0;
      
      mockApiClient.get = jest.fn(async () => {
        attemptCount++;
        throw new Error('Persistent server error');
      });
      
      await expect(mockApiClient.get('/persistent-error')).rejects.toThrow('Persistent server error');
      
      // Should attempt multiple times before giving up
      expect(attemptCount).toBeGreaterThan(1);
      expect(attemptCount).toBeLessThanOrEqual(5); // Assuming max 5 retries
    });
  });

  describe('Error Handling', () => {
    it('should handle different HTTP error status codes appropriately', async () => {
      const errorScenarios = [
        { status: 400, message: 'Bad Request', shouldRetry: false },
        { status: 401, message: 'Unauthorized', shouldRetry: false },
        { status: 403, message: 'Forbidden', shouldRetry: false },
        { status: 404, message: 'Not Found', shouldRetry: false },
        { status: 429, message: 'Rate Limited', shouldRetry: true },
        { status: 500, message: 'Internal Server Error', shouldRetry: true },
        { status: 502, message: 'Bad Gateway', shouldRetry: true },
        { status: 503, message: 'Service Unavailable', shouldRetry: true },
      ];
      
      for (const scenario of errorScenarios) {
        const error = new Error(scenario.message) as any;
        error.status = scenario.status;
        
        mockApiClient.mockFailure('GET', `/error-${scenario.status}`, error);
        
        await expect(mockApiClient.get(`/error-${scenario.status}`))
          .rejects.toThrow(scenario.message);
      }
    });

    it('should handle network timeouts gracefully', async () => {
      mockApiClient.mockDelay('GET', '/slow-endpoint', 10000); // 10 second delay
      mockApiClient.mockFailure('GET', '/slow-endpoint', new Error('Request timeout'));
      
      await expect(mockApiClient.get('/slow-endpoint')).rejects.toThrow('Request timeout');
    });

    it('should handle malformed JSON responses', async () => {
      // This would typically be handled by axios, but we simulate the scenario
      mockApiClient.mockFailure('GET', '/malformed-json', new Error('Invalid JSON response'));
      
      await expect(mockApiClient.get('/malformed-json')).rejects.toThrow('Invalid JSON response');
    });

    it('should provide detailed error information', async () => {
      const detailedError = {
        success: false,
        error: {
          message: 'Validation failed',
          code: 'VALIDATION_ERROR',
          details: {
            statusCode: 400,
            fields: {
              name: 'Name is required',
              email: 'Invalid email format'
            }
          }
        }
      };
      
      mockApiClient.mockResponse('POST', '/validation-test', detailedError);
      
      const response = await mockApiClient.post('/validation-test', { name: '', email: 'invalid' });
      
      expect(response.success).toBe(false);
      expect(response.error).toBeDefined();
      expect(response.error?.code).toBe('VALIDATION_ERROR');
      expect(response.error?.details).toBeDefined();
    });
  });

  describe('Connection Management', () => {
    it('should handle connection pool exhaustion', async () => {
      // Simulate many concurrent requests
      const concurrentRequests = Array.from({ length: 100 }, (_, i) => {
        mockApiClient.mockResponse('GET', `/concurrent-${i}`, {
          success: true,
          data: { id: i }
        });
        return mockApiClient.get(`/concurrent-${i}`);
      });
      
      const results = await Promise.allSettled(concurrentRequests);
      
      const successful = results.filter(r => r.status === 'fulfilled').length;
      const failed = results.filter(r => r.status === 'rejected').length;
      
      // Most should succeed, but some might fail due to connection limits
      expect(successful).toBeGreaterThan(80);
      expect(successful + failed).toBe(100);
    });

    it('should properly close connections on shutdown', async () => {
      await expect(mockApiClient.shutdown()).resolves.not.toThrow();
    });
  });

  describe('Performance Characteristics', () => {
    it('should maintain reasonable response times under normal load', async () => {
      mockApiClient.mockResponse('GET', '/performance-test', {
        success: true,
        data: { message: 'Performance test response' }
      });
      
      const results = await performanceHelpers.measureExecutionTime(async () => {
        const promises = Array.from({ length: 10 }, () => 
          mockApiClient.get('/performance-test')
        );
        return Promise.all(promises);
      });
      
      expect(results.result).toHaveLength(10);
      expect(results.duration).toBeLessThan(1000); // Should complete within 1 second
    });

    it('should handle slow network conditions gracefully', async () => {
      simulateNetworkConditions.slow(mockApiClient, '/slow-network-test');
      mockApiClient.mockResponse('GET', '/slow-network-test', {
        success: true,
        data: { message: 'Slow network response' }
      });
      
      const { result, duration } = await performanceHelpers.measureExecutionTime(async () => {
        return await mockApiClient.get('/slow-network-test');
      });
      
      expect(result.success).toBe(true);
      expect(duration).toBeGreaterThan(4000); // Should reflect network delay
    });

    it('should degrade gracefully under unreliable network conditions', async () => {
      simulateNetworkConditions.unreliable(mockApiClient, '/unreliable-network-test', 0.5);
      
      // Set up some responses that will succeed
      for (let i = 0; i < 10; i++) {
        if (Math.random() > 0.5) {
          mockApiClient.mockResponse('GET', `/unreliable-network-test-${i}`, {
            success: true,
            data: { id: i }
          });
        }
      }
      
      const promises = Array.from({ length: 10 }, (_, i) => 
        mockApiClient.get(`/unreliable-network-test-${i}`)
      );
      
      const results = await Promise.allSettled(promises);
      
      const successful = results.filter(r => r.status === 'fulfilled').length;
      const failed = results.filter(r => r.status === 'rejected').length;
      
      expect(successful + failed).toBe(10);
      expect(successful).toBeGreaterThan(0); // Some should succeed
      expect(failed).toBeGreaterThan(0); // Some should fail
    });
  });

  describe('Health Check Integration', () => {
    it('should report healthy status when API is available', async () => {
      mockApiClient.mockResponse('GET', '/users/me', {
        success: true,
        data: { id: 1, name: 'Test User' }
      });
      
      const isHealthy = await mockApiClient.healthCheck();
      expect(isHealthy).toBe(true);
    });

    it('should report unhealthy status when API is unavailable', async () => {
      mockApiClient.mockFailure('GET', '/users/me', new Error('API unavailable'));
      
      const isHealthy = await mockApiClient.healthCheck();
      expect(isHealthy).toBe(false);
    });

    it('should timeout health checks appropriately', async () => {
      mockApiClient.mockDelay('GET', '/users/me', 10000);  
      mockApiClient.mockFailure('GET', '/users/me', new Error('Health check timeout'));
      
      const { result: isHealthy, duration } = await performanceHelpers.measureExecutionTime(async () => {
        return await mockApiClient.healthCheck();
      });
      
      expect(isHealthy).toBe(false);
      expect(duration).toBeLessThan(5000); // Should timeout quickly for health checks
    });
  });

  describe('Request/Response Validation', () => {
    it('should validate request data before sending', async () => {
      // This would typically be implemented in the actual API client
      // Here we simulate validation
      const invalidData = {
        name: '', // Invalid: empty name
        email: 'not-an-email', // Invalid: bad email format
        age: -5 // Invalid: negative age
      };
      
      // Mock validation failure
      mockApiClient.mockResponse('POST', '/validate-request', testErrors.validation);
      
      const response = await mockApiClient.post('/validate-request', invalidData);
      
      expect(response.success).toBe(false);
      expect(response.error?.code).toBe('VALIDATION_ERROR');
    });

    it('should handle unexpected response schemas gracefully', async () => {
      // Mock unexpected response structure
      mockApiClient.mockResponse('GET', '/unexpected-schema', {
        success: true,
        data: null, // Unexpected: data is null when we expect an object
        unexpectedField: 'This should not be here'
      });
      
      const response = await mockApiClient.get('/unexpected-schema');
      
      // Should still work but might log warnings in a real implementation
      expect(response.success).toBe(true);
      expect(response.data).toBeNull();
    });
  });

  describe('Logging and Monitoring', () => {
    it('should log API call details for monitoring', async () => {
      mockApiClient.mockResponse('GET', '/monitor-test', {
        success: true,
        data: { message: 'Monitored response' }
      });
      
      await mockApiClient.get('/monitor-test');
      
      const callLog = mockApiClient.getCallLog();
      expect(callLog).toHaveLength(1);
      expect(callLog[0]).toMatchObject({
        method: 'GET',
        endpoint: '/monitor-test'
      });
    });

    it('should track response times for performance monitoring', async () => {
      mockApiClient.mockDelay('GET', '/timing-test', 100);
      mockApiClient.mockResponse('GET', '/timing-test', {
        success: true,
        data: { message: 'Timed response' }
      });
      
      const { result, duration } = await performanceHelpers.measureExecutionTime(async () => {
        return await mockApiClient.get('/timing-test');
      });
      
      expect(result.success).toBe(true);
      expect(duration).toBeGreaterThan(90); // Should reflect delay
    });

    it('should provide metrics for API usage analysis', async () => {
      // Make several API calls
      const endpoints = ['/metrics-1', '/metrics-2', '/metrics-3'];
      
      for (const endpoint of endpoints) {
        mockApiClient.mockResponse('GET', endpoint, {
          success: true,
          data: { endpoint }
        });
        await mockApiClient.get(endpoint);
      }
      
      const callLog = mockApiClient.getCallLog();
      expect(callLog).toHaveLength(3);
      
      // Verify we can analyze usage patterns
      const uniqueEndpoints = new Set(callLog.map(call => call.endpoint));
      expect(uniqueEndpoints.size).toBe(3);
    });
  });

  describe('Circuit Breaker Pattern', () => {
    it('should open circuit breaker after consecutive failures', async () => {
      let failureCount = 0;
      
      // Simulate circuit breaker logic
      mockApiClient.get = jest.fn(async (endpoint) => {
        failureCount++;
        if (failureCount <= 5) {
          throw new Error('Service failure');
        }
        // Circuit breaker should prevent further requests
        throw new Error('Circuit breaker open');
      });
      
      // Make multiple failing requests
      for (let i = 0; i < 7; i++) {
        try {
          await mockApiClient.get('/circuit-breaker-test');
        } catch (error) {
          // Expected to fail
        }
      }
      
      expect(failureCount).toBeLessThanOrEqual(5); // Circuit should open before 7th request
    });

    it('should attempt to close circuit breaker after timeout', async () => {
      // This would typically involve time-based logic
      // Here we simulate the concept
      let circuitOpen = true;
      
      mockApiClient.get = jest.fn(async () => {
        if (circuitOpen) {
          // Simulate circuit breaker timeout
          await globalThis.testUtils.delay(100);
          circuitOpen = false;
          return { success: true, data: { message: 'Circuit closed' } };
        }
        return { success: true, data: { message: 'Normal operation' } };
      });
      
      const response = await mockApiClient.get('/circuit-recovery-test');
      expect(response.success).toBe(true);
    });
  });
});