/**
 * Enhanced Integration tests for Make.com API client
 * Tests rate limiting, retry logic, error handling, circuit breaker patterns, and resilience
 * Follows advanced testing patterns from TESTING mode guidelines
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import axios from 'axios';
import Bottleneck from 'bottleneck';
import MakeApiClient from '../../src/lib/make-api-client.js';
import { MakeApiConfig } from '../../src/types/index.js';
import { MockMakeApiClient } from '../mocks/make-api-client.mock.js';
import { 
  simulateNetworkConditions,
  expectErrorResponse,
  performanceHelpers,
  waitForCondition,
  createTestEnvironment
} from '../utils/test-helpers.js';
import { testErrors } from '../fixtures/test-data.js';

// Mock axios for controlled testing
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

// Enhanced chaos testing class for fault injection
class ChaosMonkey {
  private failureRate: number;
  private latencyMs: number;
  private scenarios: string[];

  constructor(config: { failureRate?: number; latencyMs?: number; scenarios?: string[] }) {
    this.failureRate = config.failureRate || 0.1;
    this.latencyMs = config.latencyMs || 5000;
    this.scenarios = config.scenarios || ['latency', 'error', 'timeout'];
  }

  async wrapApiClient(client: MakeApiClient): Promise<MakeApiClient> {
    return new Proxy(client, {
      get: (target, prop) => {
        if (typeof target[prop as keyof MakeApiClient] !== 'function') {
          return target[prop as keyof MakeApiClient];
        }

        return async (...args: unknown[]) => {
          // Randomly inject failures
          if (Math.random() < this.failureRate) {
            const scenario = this.scenarios[Math.floor(Math.random() * this.scenarios.length)];
            await this.injectFailure(scenario);
          }

          return (target[prop as keyof MakeApiClient] as Function)(...args);
        };
      }
    });
  }

  private async injectFailure(scenario: string): Promise<void> {
    switch (scenario) {
      case 'latency':
        await new Promise(resolve => setTimeout(resolve, this.latencyMs));
        break;
      case 'error':
        throw new Error('Chaos: Service temporarily unavailable');
      case 'timeout':
        await new Promise(resolve => setTimeout(resolve, 30000));
        throw new Error('Chaos: Request timeout');
      case 'partial':
        throw new Error('Chaos: Partial response');
    }
  }
}

// Test configuration for real API client
const testConfig: MakeApiConfig = {
  baseUrl: 'https://api.make.com/api/v2',
  apiKey: 'test_api_key_for_integration_tests',
  timeout: 5000,
  retries: 3
};

describe('Make.com API Client Integration Tests', () => {
  let mockApiClient: MockMakeApiClient;
  let realApiClient: MakeApiClient;
  let testEnvironment: ReturnType<typeof createTestEnvironment>;

  beforeEach(() => {
    mockApiClient = new MockMakeApiClient();
    realApiClient = new MakeApiClient(testConfig);
    testEnvironment = createTestEnvironment();
    jest.clearAllMocks();
  });

  afterEach(async () => {
    mockApiClient.reset();
    await testEnvironment.cleanup();
    await realApiClient.shutdown();
  });

  describe('Enhanced Rate Limiting Tests', () => {
    it('should respect Make.com rate limits (10 req/sec)', async () => {
      // Mock responses for rapid fire requests
      for (let i = 0; i < 15; i++) {
        mockApiClient.mockResponse('GET', `/rate-test-${i}`, {
          success: true,
          data: { id: i, timestamp: Date.now() }
        });
      }

      const startTime = Date.now();
      const promises = Array.from({ length: 15 }, (_, i) => 
        realApiClient.get(`/rate-test-${i}`)
      );
      
      const results = await Promise.allSettled(promises);
      const endTime = Date.now();
      const duration = endTime - startTime;
      
      // Should take at least 1 second for 15 requests (10 req/sec limit)
      expect(duration).toBeGreaterThan(1000);
      
      const successful = results.filter(r => r.status === 'fulfilled').length;
      expect(successful).toBeGreaterThan(10); // Most should succeed
    });

    it('should handle 429 Rate Limit Exceeded responses properly', async () => {
      const rateLimitError = new Error('Rate limit exceeded') as any;
      rateLimitError.status = 429;
      rateLimitError.response = {
        status: 429,
        headers: {
          'retry-after': '60',
          'x-ratelimit-remaining': '0',
          'x-ratelimit-reset': String(Date.now() + 60000)
        }
      };
      
      // First few requests succeed
      for (let i = 0; i < 3; i++) {
        mockApiClient.mockResponse('GET', `/burst-${i}`, {
          success: true,
          data: { id: i }
        });
      }
      
      // Then rate limit kicks in
      mockApiClient.mockFailure('GET', '/burst-3', rateLimitError);
      
      const results: Array<{ success: boolean; data?: any; error?: any }> = [];
      for (let i = 0; i < 4; i++) {
        try {
          const response = await mockApiClient.get(`/burst-${i}`);
          results.push({ success: true, data: response });
        } catch (error) {
          results.push({ success: false, error });
        }
      }
      
      expect(results.slice(0, 3).every(r => r.success)).toBe(true);
      expect(results[3].success).toBe(false);
      expect((results[3].error as any).status).toBe(429);
    });

    it('should provide accurate rate limiter status from real client', async () => {
      const status = realApiClient.getRateLimiterStatus();
      
      expect(status).toHaveProperty('running');
      expect(status).toHaveProperty('queued');
      expect(typeof status.running).toBe('number');
      expect(typeof status.queued).toBe('number');
      expect(status.running).toBeGreaterThanOrEqual(0);
      expect(status.queued).toBeGreaterThanOrEqual(0);
    });

    it('should handle reservoir refill correctly', async () => {
      // Make a burst of requests to test reservoir behavior
      const burstSize = 20;
      const responses = [];
      
      for (let i = 0; i < burstSize; i++) {
        mockApiClient.mockResponse('GET', `/reservoir-${i}`, {
          success: true,
          data: { id: i, burst: true }
        });
      }
      
      const { result: burstResults, duration } = await performanceHelpers.measureExecutionTime(async () => {
        const promises = Array.from({ length: burstSize }, (_, i) => 
          realApiClient.get(`/reservoir-${i}`)
        );
        return Promise.allSettled(promises);
      });
      
      const successful = burstResults.filter(r => r.status === 'fulfilled').length;
      
      // Should throttle requests appropriately
      expect(duration).toBeGreaterThan(1000); // Throttling should add delay
      expect(successful).toBeGreaterThan(burstSize * 0.8); // Most should succeed
    });

    it('should handle concurrent request limit (maxConcurrent: 5)', async () => {
      const concurrentCount = 10;
      const delayedResponses = [];
      
      // Set up responses with artificial delays
      for (let i = 0; i < concurrentCount; i++) {
        mockApiClient.mockDelay('GET', `/concurrent-${i}`, 200);
        mockApiClient.mockResponse('GET', `/concurrent-${i}`, {
          success: true,
          data: { id: i, concurrent: true }
        });
      }
      
      const { result: concurrentResults, duration } = await performanceHelpers.measureExecutionTime(async () => {
        const promises = Array.from({ length: concurrentCount }, (_, i) => 
          realApiClient.get(`/concurrent-${i}`)
        );
        return Promise.allSettled(promises);
      });
      
      // With maxConcurrent: 5, requests should be batched
      expect(duration).toBeGreaterThan(400); // At least 2 batches * 200ms delay
      expect(concurrentResults.filter(r => r.status === 'fulfilled')).toHaveLength(concurrentCount);
    });

    it('should recover gracefully from rate limit bursts', async () => {
      let requestCount = 0;
      const maxRequests = 12;
      
      // Simulate bursty traffic with recovery
      const burstTest = async () => {
        const results: Array<{ success: boolean; attempt: number; data?: any; error?: any }> = [];
        
        for (let i = 0; i < maxRequests; i++) {
          requestCount++;
          
          // Simulate rate limiting after 8 requests
          if (requestCount > 8 && requestCount <= 10) {
            const rateLimitError = new Error('Rate limit exceeded') as any;
            rateLimitError.status = 429;
            mockApiClient.mockFailure('GET', `/burst-recovery-${i}`, rateLimitError);
          } else {
            mockApiClient.mockResponse('GET', `/burst-recovery-${i}`, {
              success: true,
              data: { id: i, recovered: requestCount > 10 }
            });
          }
          
          try {
            const response = await realApiClient.get(`/burst-recovery-${i}`);
            results.push({ success: true, attempt: i, data: response });
          } catch (error) {
            results.push({ success: false, attempt: i, error });
          }
        }
        
        return results;
      };
      
      const { result: burstResults, duration } = await performanceHelpers.measureExecutionTime(burstTest);
      
      const successful = burstResults.filter(r => r.success).length;
      const failed = burstResults.filter(r => !r.success).length;
      
      expect(successful).toBeGreaterThan(8); // Should recover after rate limit
      expect(failed).toBeLessThanOrEqual(3); // Only rate limited requests should fail
      expect(duration).toBeGreaterThan(1000); // Should take time due to rate limiting
    });
  });

  describe('Advanced Retry Logic with Exponential Backoff', () => {
    it('should implement exponential backoff with jitter for transient failures', async () => {
      let attemptCount = 0;
      const attemptTimestamps: number[] = [];
      
      // Create chaos-enhanced API client for realistic failure simulation
      const chaosClient = await new ChaosMonkey({
        failureRate: 0.6,
        latencyMs: 100,
        scenarios: ['error', 'timeout']
      }).wrapApiClient(realApiClient);
      
      // Mock responses that fail initially then succeed
      const originalGet = realApiClient.get.bind(realApiClient);
      const mockedGet = jest.fn(async (endpoint: string) => {
        attemptCount++;
        attemptTimestamps.push(Date.now());
        
        // Fail first 3 attempts with retryable errors
        if (attemptCount <= 3) {
          const error = new Error('Service temporarily unavailable') as any;
          error.status = 503;
          error.retryable = true;
          throw error;
        }
        
        // Fourth attempt succeeds
        return {
          success: true,
          data: { message: 'Success after exponential backoff', attempts: attemptCount }
        };
      });
      
      (realApiClient as any).get = mockedGet;
      
      const { result, duration } = await performanceHelpers.measureExecutionTime(async () => {
        return await realApiClient.get('/exponential-backoff-test');
      });
      
      // Verify exponential backoff timing
      expect(attemptCount).toBe(4);
      expect(result.success).toBe(true);
      expect(duration).toBeGreaterThan(1000); // Should include backoff delays
      
      // Verify exponential delay pattern (1s, 2s, 4s base + jitter)
      if (attemptTimestamps.length >= 4) {
        const delay1 = attemptTimestamps[1] - attemptTimestamps[0];
        const delay2 = attemptTimestamps[2] - attemptTimestamps[1];
        const delay3 = attemptTimestamps[3] - attemptTimestamps[2];
        
        expect(delay2).toBeGreaterThan(delay1);
        expect(delay3).toBeGreaterThan(delay2);
      }
      
      // Restore original method
      (realApiClient as any).get = originalGet;
    });

    it('should not retry non-retryable HTTP status codes', async () => {
      const nonRetryableStatuses = [400, 401, 403, 404, 422];
      
      for (const status of nonRetryableStatuses) {
        let attemptCount = 0;
        
        const mockedMethod = jest.fn(async () => {
          attemptCount++;
          const error = new Error(`HTTP ${status} Error`) as any;
          error.status = status;
          error.retryable = false;
          throw error;
        });
        
        (realApiClient as any).get = mockedMethod;
        
        try {
          await realApiClient.get(`/non-retryable-${status}`);
        } catch (error) {
          expect((error as any).status).toBe(status);
        }
        
        expect(attemptCount).toBe(1); // Should not retry non-retryable errors
      }
    });

    it('should retry retryable HTTP status codes with proper intervals', async () => {
      const retryableStatuses = [429, 500, 502, 503, 504];
      
      for (const status of retryableStatuses) {
        let attemptCount = 0;
        const startTime = Date.now();
        
        const mockedMethod = jest.fn(async () => {
          attemptCount++;
          if (attemptCount <= 2) {
            const error = new Error(`HTTP ${status} Error`) as any;
            error.status = status;
            error.retryable = true;
            throw error;
          }
          return {
            success: true,
            data: { message: `Recovered from ${status}`, attempts: attemptCount }
          };
        });
        
        (realApiClient as any).get = mockedMethod;
        
        const response = await realApiClient.get(`/retryable-${status}`);
        const duration = Date.now() - startTime;
        
        expect(response.success).toBe(true);
        expect(attemptCount).toBe(3);
        expect(duration).toBeGreaterThan(500); // Should include retry delays
      }
    });

    it('should respect maximum retry attempts and fail gracefully', async () => {
      let attemptCount = 0;
      const maxRetries = 3;
      
      const persistentFailure = jest.fn(async () => {
        attemptCount++;
        const error = new Error('Persistent infrastructure failure') as any;
        error.status = 503;
        error.retryable = true;
        throw error;
      });
      
      (realApiClient as any).post = persistentFailure;
      
      const { result, duration } = await performanceHelpers.measureExecutionTime(async () => {
        try {
          return await realApiClient.post('/persistent-failure-test', { data: 'test' });
        } catch (error) {
          return { success: false, error };
        }
      });
      
      expect(result.success).toBe(false);
      expect(attemptCount).toBe(maxRetries + 1); // Initial attempt + retries
      expect(duration).toBeGreaterThan(3000); // Should reflect multiple retry delays
    });

    it('should handle network timeouts with appropriate retry strategy', async () => {
      let attemptCount = 0;
      const timeoutScenarios = ['ECONNRESET', 'ETIMEDOUT', 'ENOTFOUND'];
      
      const networkFailure = jest.fn(async () => {
        attemptCount++;
        const scenario = timeoutScenarios[Math.floor(Math.random() * timeoutScenarios.length)];
        
        if (attemptCount <= 2) {
          const error = new Error(`Network error: ${scenario}`) as any;
          error.code = scenario;
          error.retryable = true;
          throw error;
        }
        
        return {
          success: true,
          data: { message: 'Network recovered', attempts: attemptCount }
        };
      });
      
      (realApiClient as any).put = networkFailure;
      
      const response = await realApiClient.put('/network-recovery-test', { data: 'test' });
      
      expect(response.success).toBe(true);
      expect(attemptCount).toBe(3);
      expect((response.data as any).attempts).toBe(3);
    });

    it('should apply jitter to prevent thundering herd', async () => {
      const concurrentRequests = 5;
      const retryTimestamps: number[][] = [];
      
      // Create multiple failing requests that will retry
      const failingRequests = Array.from({ length: concurrentRequests }, (_, index) => {
        let requestAttempts = 0;
        const requestTimestamps: number[] = [];
        
        const failingMethod = jest.fn(async () => {
          requestAttempts++;
          requestTimestamps.push(Date.now());
          
          if (requestAttempts <= 2) {
            const error = new Error('Concurrent failure') as any;
            error.status = 500;
            error.retryable = true;
            throw error;
          }
          
          return {
            success: true,
            data: { index, attempts: requestAttempts }
          };
        });
        
        return {
          execute: () => {
            (realApiClient as any).get = failingMethod;
            return realApiClient.get(`/jitter-test-${index}`);
          },
          getTimestamps: () => requestTimestamps
        };
      });
      
      // Execute all requests concurrently
      const startTime = Date.now();
      const results = await Promise.all(
        failingRequests.map(req => req.execute())
      );
      const endTime = Date.now();
      
      // Collect all retry timestamps
      failingRequests.forEach(req => {
        retryTimestamps.push(req.getTimestamps());
      });
      
      // Verify all requests eventually succeeded
      expect(results.every(r => r.success)).toBe(true);
      
      // Verify jitter caused different retry timings
      if (retryTimestamps.length >= 2) {
        const firstRetryDelays = retryTimestamps.map(stamps => 
          stamps.length > 1 ? stamps[1] - stamps[0] : 0
        ).filter(delay => delay > 0);
        
        // With jitter, retry delays should vary
        const uniqueDelays = new Set(firstRetryDelays);
        expect(uniqueDelays.size).toBeGreaterThan(1);
      }
    });

    it('should handle mixed success/failure scenarios in retry logic', async () => {
      const endpoints = [
        '/mixed-success-1',
        '/mixed-failure-1', 
        '/mixed-success-2',
        '/mixed-failure-2',
        '/mixed-recovery'
      ];
      
      const results: Array<{ endpoint: string; success: boolean; response?: any; error?: any }> = [];
      
      for (let i = 0; i < endpoints.length; i++) {
        let attemptCount = 0;
        
        const mixedBehavior = jest.fn(async () => {
          attemptCount++;
          
          // Different behavior per endpoint
          switch (i) {
            case 0: // Immediate success
              return { success: true, data: { endpoint: endpoints[i] } };
            case 1: // Permanent failure
              const permError = new Error('Permanent failure') as any;
              permError.status = 403;
              permError.retryable = false;
              throw permError;
            case 2: // Success after 1 retry
              if (attemptCount <= 1) {
                const tempError = new Error('Temporary failure') as any;
                tempError.status = 500;
                tempError.retryable = true;
                throw tempError;
              }
              return { success: true, data: { endpoint: endpoints[i], attempts: attemptCount } };
            case 3: // Multiple retries then permanent failure
              if (attemptCount <= 2) {
                const retryError = new Error('Retryable error') as any;
                retryError.status = 503;
                retryError.retryable = true;
                throw retryError;
              }
              const finalError = new Error('Final failure') as any;
              finalError.status = 500;
              finalError.retryable = true;
              throw finalError;
            case 4: // Recovery after max retries - 1
              if (attemptCount <= 2) {
                const recoveryError = new Error('Recovery in progress') as any;
                recoveryError.status = 502;
                recoveryError.retryable = true;
                throw recoveryError;
              }
              return { success: true, data: { endpoint: endpoints[i], recovered: true } };
            default:
              return { success: true, data: { endpoint: endpoints[i] } };
          }
        });
        
        (realApiClient as any).get = mixedBehavior;
        
        try {
          const response = await realApiClient.get(endpoints[i]);
          results.push({ endpoint: endpoints[i], success: true, response });
        } catch (error) {
          results.push({ endpoint: endpoints[i], success: false, error });
        }
      }
      
      // Verify expected outcomes
      expect(results[0].success).toBe(true); // Immediate success
      expect(results[1].success).toBe(false); // Permanent failure
      expect(results[2].success).toBe(true); // Success after retry
      expect(results[3].success).toBe(false); // Multiple retries then failure
      expect(results[4].success).toBe(true); // Recovery after retries
    });
  });

  describe('Comprehensive Error Handling and Network Failure Scenarios', () => {
    it('should handle all HTTP status codes with appropriate retry behavior', async () => {
      const errorScenarios = [
        // 4xx Client Errors (non-retryable)
        { status: 400, message: 'Bad Request', shouldRetry: false, category: 'client' },
        { status: 401, message: 'Unauthorized', shouldRetry: false, category: 'auth' },
        { status: 403, message: 'Forbidden', shouldRetry: false, category: 'auth' },
        { status: 404, message: 'Not Found', shouldRetry: false, category: 'client' },
        { status: 409, message: 'Conflict', shouldRetry: false, category: 'client' },
        { status: 410, message: 'Gone', shouldRetry: false, category: 'client' },
        { status: 422, message: 'Unprocessable Entity', shouldRetry: false, category: 'validation' },
        { status: 429, message: 'Too Many Requests', shouldRetry: true, category: 'rate_limit' },
        
        // 5xx Server Errors (retryable)
        { status: 500, message: 'Internal Server Error', shouldRetry: true, category: 'server' },
        { status: 501, message: 'Not Implemented', shouldRetry: false, category: 'server' },
        { status: 502, message: 'Bad Gateway', shouldRetry: true, category: 'server' },
        { status: 503, message: 'Service Unavailable', shouldRetry: true, category: 'server' },
        { status: 504, message: 'Gateway Timeout', shouldRetry: true, category: 'server' },
        { status: 507, message: 'Insufficient Storage', shouldRetry: true, category: 'server' },
      ];
      
      for (const scenario of errorScenarios) {
        let attemptCount = 0;
        
        const errorHandler = jest.fn(async () => {
          attemptCount++;
          const error = new Error(scenario.message) as any;
          error.status = scenario.status;
          error.retryable = scenario.shouldRetry;
          error.category = scenario.category;
          throw error;
        });
        
        (realApiClient as any).get = errorHandler;
        
        try {
          await realApiClient.get(`/error-${scenario.status}`);
          fail(`Expected error ${scenario.status} to be thrown`);
        } catch (error) {
          expect((error as any).status).toBe(scenario.status);
          expect((error as any).message).toContain(scenario.message);
          
          if (scenario.shouldRetry) {
            expect(attemptCount).toBeGreaterThan(1); // Should have retried
          } else {
            expect(attemptCount).toBe(1); // Should not retry
          }
        }
      }
    });

    it('should handle network-level failures with appropriate error categorization', async () => {
      const networkFailures = [
        { code: 'ECONNRESET', message: 'Connection reset by peer', retryable: true },
        { code: 'ETIMEDOUT', message: 'Request timeout', retryable: true },
        { code: 'ENOTFOUND', message: 'DNS lookup failed', retryable: true },
        { code: 'ECONNREFUSED', message: 'Connection refused', retryable: true },
        { code: 'EHOSTUNREACH', message: 'Host unreachable', retryable: true },
        { code: 'ENETUNREACH', message: 'Network unreachable', retryable: true },
        { code: 'EPIPE', message: 'Broken pipe', retryable: true },
        { code: 'EADDRINUSE', message: 'Address in use', retryable: false },
      ];
      
      for (const failure of networkFailures) {
        let attemptCount = 0;
        
        const networkError = jest.fn(async () => {
          attemptCount++;
          const error = new Error(failure.message) as any;
          error.code = failure.code;
          error.retryable = failure.retryable;
          throw error;
        });
        
        (realApiClient as any).post = networkError;
        
        try {
          await realApiClient.post(`/network-error-${failure.code.toLowerCase()}`, { test: 'data' });
          fail(`Expected network error ${failure.code} to be thrown`);
        } catch (error) {
          expect((error as any).code).toBe(failure.code);
          expect((error as any).message).toContain(failure.message);
          
          if (failure.retryable) {
            expect(attemptCount).toBeGreaterThan(1);
          } else {
            expect(attemptCount).toBe(1);
          }
        }
      }
    });

    it('should handle partial response failures and malformed data', async () => {
      const malformedScenarios = [
        {
          name: 'truncated_json',
          error: new SyntaxError('Unexpected end of JSON input'),
          description: 'Partial JSON response'
        },
        {
          name: 'invalid_json',
          error: new SyntaxError('Unexpected token in JSON'),
          description: 'Malformed JSON structure'
        },
        {
          name: 'empty_response',
          error: new Error('Empty response body'),
          description: 'No response data'
        },
        {
          name: 'corrupted_data',
          error: new Error('Response validation failed'),
          description: 'Data integrity check failed'
        }
      ];
      
      for (const scenario of malformedScenarios) {
        let attemptCount = 0;
        
        const malformedHandler = jest.fn(async () => {
          attemptCount++;
          // Simulate parsing/validation error
          throw scenario.error;
        });
        
        (realApiClient as any).put = malformedHandler;
        
        try {
          await realApiClient.put(`/malformed-${scenario.name}`, { test: 'data' });
          fail(`Expected ${scenario.name} error to be thrown`);
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect((error as Error).message).toContain(scenario.error.message);
          // Data parsing errors should not be retried
          expect(attemptCount).toBe(1);
        }
      }
    });

    it('should provide comprehensive error context and debugging information', async () => {
      const detailedError = {
        success: false,
        error: {
          message: 'Multiple validation failures detected',
          code: 'VALIDATION_ERROR',
          timestamp: new Date().toISOString(),
          requestId: 'req_12345',
          details: {
            statusCode: 400,
            validationErrors: [
              {
                field: 'name',
                message: 'Name is required and must be at least 3 characters',
                code: 'REQUIRED_FIELD',
                value: ''
              },
              {
                field: 'email',
                message: 'Invalid email format',
                code: 'INVALID_FORMAT',
                value: 'invalid-email'
              },
              {
                field: 'age',
                message: 'Age must be between 18 and 120',
                code: 'OUT_OF_RANGE',
                value: -5
              }
            ],
            suggestedActions: [
              'Verify all required fields are provided',
              'Check field format requirements',
              'Consult API documentation for valid values'
            ]
          },
          metadata: {
            endpoint: '/validation-test',
            method: 'POST',
            userAgent: 'MakeApiClient/1.0',
            correlationId: 'corr_67890'
          }
        }
      };
      
      mockApiClient.mockResponse('POST', '/detailed-validation-test', detailedError);
      
      const response = await mockApiClient.post('/detailed-validation-test', {
        name: '',
        email: 'invalid-email',
        age: -5
      });
      
      expect(response.success).toBe(false);
      expect(response.error).toBeDefined();
      expect(response.error?.code).toBe('VALIDATION_ERROR');
      expect(response.error?.details?.validationErrors).toHaveLength(3);
      expect(response.error?.details?.suggestedActions).toHaveLength(3);
      expect(response.error?.metadata?.correlationId).toBe('corr_67890');
    });

    it('should handle timeout scenarios with configurable thresholds', async () => {
      const timeoutScenarios = [
        { name: 'connection_timeout', duration: 5000, type: 'connection' },
        { name: 'read_timeout', duration: 10000, type: 'read' },
        { name: 'response_timeout', duration: 30000, type: 'response' }
      ];
      
      for (const scenario of timeoutScenarios) {
        let attemptCount = 0;
        
        const timeoutHandler = jest.fn(async () => {
          attemptCount++;
          
          // Simulate timeout after specified duration
          await new Promise(resolve => setTimeout(resolve, scenario.duration));
          
          const timeoutError = new Error(`${scenario.type} timeout after ${scenario.duration}ms`) as any;
          timeoutError.code = 'TIMEOUT';
          timeoutError.type = scenario.type;
          timeoutError.duration = scenario.duration;
          timeoutError.retryable = true;
          
          throw timeoutError;
        });
        
        (realApiClient as any).delete = timeoutHandler;
        
        const { result, duration } = await performanceHelpers.measureExecutionTime(async () => {
          try {
            await realApiClient.delete(`/timeout-${scenario.name}`);
            return { success: true };
          } catch (error) {
            return { success: false, error };
          }
        });
        
        expect(result.success).toBe(false);
        expect((result.error as any).code).toBe('TIMEOUT');
        expect((result.error as any).type).toBe(scenario.type);
        expect(attemptCount).toBeGreaterThan(1); // Should retry timeouts
        expect(duration).toBeGreaterThan(scenario.duration); // Should reflect timeout duration
      }
    });

    it('should handle cascading failure scenarios', async () => {
      const cascadingFailures = [
        { attempt: 1, error: { status: 503, message: 'Service temporarily unavailable' } },
        { attempt: 2, error: { status: 502, message: 'Bad gateway - upstream timeout' } },
        { attempt: 3, error: { status: 500, message: 'Internal server error - database connection failed' } },
        { attempt: 4, success: true, data: { message: 'Service recovered', failureCount: 3 } }
      ];
      
      let attemptCount = 0;
      
      const cascadingHandler = jest.fn(async () => {
        attemptCount++;
        const scenario = cascadingFailures[attemptCount - 1];
        
        if (scenario.success) {
          return {
            success: true,
            data: scenario.data
          };
        } else {
          const error = new Error(scenario.error?.message || 'Test error') as any;
          error.status = scenario.error?.status || 500;
          error.retryable = true;
          throw error;
        }
      });
      
      (realApiClient as any).patch = cascadingHandler;
      
      const { result, duration } = await performanceHelpers.measureExecutionTime(async () => {
        return await realApiClient.patch('/cascading-failure-test', { data: 'test' });
      });
      
      expect(result.success).toBe(true);
      expect(result.data?.message).toBe('Service recovered');
      expect(result.data?.failureCount).toBe(3);
      expect(attemptCount).toBe(4);
      expect(duration).toBeGreaterThan(3000); // Should include retry delays
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

  describe('Advanced Performance and Stress Testing', () => {
    it('should maintain acceptable performance under high concurrent load', async () => {
      const concurrentUsers = 50;
      const requestsPerUser = 5;
      const totalRequests = concurrentUsers * requestsPerUser;
      
      // Set up responses for load testing
      for (let i = 0; i < totalRequests; i++) {
        mockApiClient.mockResponse('GET', `/load-test-${i}`, {
          success: true,
          data: { 
            id: i, 
            timestamp: Date.now(),
            message: 'High load response'
          }
        });
      }
      
      const { result: loadResults, duration } = await performanceHelpers.measureExecutionTime(async () => {
        // Simulate concurrent users making multiple requests
        const userPromises = Array.from({ length: concurrentUsers }, async (_, userIndex) => {
          const userRequests: Promise<any>[] = [];
          
          for (let reqIndex = 0; reqIndex < requestsPerUser; reqIndex++) {
            const requestId = userIndex * requestsPerUser + reqIndex;
            userRequests.push(
              realApiClient.get(`/load-test-${requestId}`)
            );
          }
          
          return Promise.allSettled(userRequests);
        });
        
        return Promise.all(userPromises);
      });
      
      // Analyze results
      const allResults = loadResults.flat();
      const successful = allResults.filter(r => r.status === 'fulfilled').length;
      const failed = allResults.filter(r => r.status === 'rejected').length;
      const successRate = successful / totalRequests;
      
      expect(successRate).toBeGreaterThan(0.95); // 95% success rate under load
      expect(duration).toBeLessThan(10000); // Complete within 10 seconds
      expect(successful + failed).toBe(totalRequests);
    });

    it('should handle memory pressure and resource exhaustion gracefully', async () => {
      const largePayloadSize = 1024 * 100; // 100KB payloads
      const requestBursts = 10;
      const burstSize = 20;
      
      // Create large payloads to simulate memory pressure
      const largePayload = {
        data: 'x'.repeat(largePayloadSize),
        metadata: {
          size: largePayloadSize,
          type: 'memory_pressure_test',
          chunks: Array.from({ length: 100 }, (_, i) => `chunk_${i}_${'data'.repeat(50)}`)
        }
      };
      
      const memoryResults: Array<{ burst: number; successful: number; failed: number; duration: number; successRate: number }> = [];
      
      for (let burst = 0; burst < requestBursts; burst++) {
        // Set up responses for this burst
        for (let i = 0; i < burstSize; i++) {
          mockApiClient.mockResponse('POST', `/memory-test-${burst}-${i}`, {
            success: true,
            data: { processed: true, burst, request: i }
          });
        }
        
        const { result: burstResults, duration } = await performanceHelpers.measureExecutionTime(async () => {
          const promises = Array.from({ length: burstSize }, (_, i) => 
            realApiClient.post(`/memory-test-${burst}-${i}`, largePayload)
          );
          return Promise.allSettled(promises);
        });
        
        const burstSuccessful = burstResults.filter(r => r.status === 'fulfilled').length;
        const burstFailed = burstResults.filter(r => r.status === 'rejected').length;
        
        memoryResults.push({
          burst: burst + 1,
          successful: burstSuccessful,
          failed: burstFailed,
          duration,
          successRate: burstSuccessful / burstSize
        });
        
        // Brief pause between bursts to allow cleanup
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      
      // Verify system handled memory pressure
      const avgSuccessRate = memoryResults.reduce((sum, r) => sum + r.successRate, 0) / requestBursts;
      const avgDuration = memoryResults.reduce((sum, r) => sum + r.duration, 0) / requestBursts;
      
      expect(avgSuccessRate).toBeGreaterThan(0.90); // 90% success rate under memory pressure
      expect(avgDuration).toBeLessThan(5000); // Average burst time under 5 seconds
    });

    it('should demonstrate linear performance degradation under increasing load', async () => {
      const loadLevels = [10, 25, 50, 100, 200];
      const performanceBaseline: Array<{ loadLevel: number; duration: number; successful: number; throughput: number; avgResponseTime: number; successRate: number }> = [];
      
      for (const loadLevel of loadLevels) {
        // Set up responses for this load level
        for (let i = 0; i < loadLevel; i++) {
          mockApiClient.mockResponse('GET', `/scaling-test-${loadLevel}-${i}`, {
            success: true,
            data: { id: i, loadLevel, processed: true }
          });
        }
        
        const { result: loadResults, duration } = await performanceHelpers.measureExecutionTime(async () => {
          const promises = Array.from({ length: loadLevel }, (_, i) => 
            realApiClient.get(`/scaling-test-${loadLevel}-${i}`)
          );
          return Promise.allSettled(promises);
        });
        
        const successful = loadResults.filter(r => r.status === 'fulfilled').length;
        const throughput = successful / (duration / 1000); // requests per second
        const avgResponseTime = duration / successful;
        
        performanceBaseline.push({
          loadLevel,
          duration,
          successful,
          throughput,
          avgResponseTime,
          successRate: successful / loadLevel
        });
        
        // Small delay between load tests
        await new Promise(resolve => setTimeout(resolve, 200));
      }
      
      // Analyze scaling characteristics
      expect(performanceBaseline).toHaveLength(loadLevels.length);
      
      // Verify success rates remain high across all load levels
      performanceBaseline.forEach(baseline => {
        expect(baseline.successRate).toBeGreaterThan(0.95);
      });
      
      // Verify response time doesn't degrade too severely
      const baselineResponseTime = performanceBaseline[0].avgResponseTime;
      const highLoadResponseTime = performanceBaseline[performanceBaseline.length - 1].avgResponseTime;
      const degradationRatio = highLoadResponseTime / baselineResponseTime;
      
      expect(degradationRatio).toBeLessThan(5); // Less than 5x degradation
    });

    it('should handle network condition variations with adaptive performance', async () => {
      const networkConditions = [
        { name: 'excellent', latency: 10, jitter: 2, packetLoss: 0 },
        { name: 'good', latency: 50, jitter: 10, packetLoss: 0.001 },
        { name: 'fair', latency: 150, jitter: 30, packetLoss: 0.01 },
        { name: 'poor', latency: 300, jitter: 100, packetLoss: 0.05 },
        { name: 'terrible', latency: 1000, jitter: 500, packetLoss: 0.1 }
      ];
      
      const networkPerformance: Array<{ condition: string; expectedLatency: number; packetLoss: number; successful: number; failed: number; actualDuration: number; successRate: number; avgResponseTime: number }> = [];
      
      for (const condition of networkConditions) {
        const requestCount = 20;
        
        // Simulate network conditions
        for (let i = 0; i < requestCount; i++) {
          const shouldDrop = Math.random() < condition.packetLoss;
          const networkDelay = condition.latency + (Math.random() - 0.5) * condition.jitter;
          
          if (shouldDrop) {
            mockApiClient.mockFailure('GET', `/network-${condition.name}-${i}`, 
              new Error('Network packet loss'));
          } else {
            mockApiClient.mockDelay('GET', `/network-${condition.name}-${i}`, networkDelay);
            mockApiClient.mockResponse('GET', `/network-${condition.name}-${i}`, {
              success: true,
              data: { condition: condition.name, delay: networkDelay }
            });
          }
        }
        
        const { result: conditionResults, duration } = await performanceHelpers.measureExecutionTime(async () => {
          const promises = Array.from({ length: requestCount }, (_, i) => 
            realApiClient.get(`/network-${condition.name}-${i}`)
          );
          return Promise.allSettled(promises);
        });
        
        const successful = conditionResults.filter(r => r.status === 'fulfilled').length;
        const failed = conditionResults.filter(r => r.status === 'rejected').length;
        
        networkPerformance.push({
          condition: condition.name,
          expectedLatency: condition.latency,
          packetLoss: condition.packetLoss,
          successful,
          failed,
          actualDuration: duration,
          successRate: successful / requestCount,
          avgResponseTime: duration / successful
        });
        
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      
      // Verify adaptive behavior under different network conditions
      expect(networkPerformance).toHaveLength(networkConditions.length);
      
      // Excellent conditions should have near-perfect performance
      const excellentPerf = networkPerformance.find(p => p.condition === 'excellent');
      expect(excellentPerf?.successRate).toBeGreaterThan(0.95);
      
      // Even terrible conditions should maintain some success
      const terriblePerf = networkPerformance.find(p => p.condition === 'terrible');
      expect(terriblePerf?.successRate).toBeGreaterThan(0.7);
      
      // Response times should correlate with network latency
      const sortedByLatency = networkPerformance.sort((a, b) => a.expectedLatency - b.expectedLatency);
      for (let i = 1; i < sortedByLatency.length; i++) {
        const current = sortedByLatency[i];
        const previous = sortedByLatency[i - 1];
        expect(current.avgResponseTime).toBeGreaterThanOrEqual(previous.avgResponseTime * 0.8);
      }
    });

    it('should maintain stability during extended stress testing with chaos injection', async () => {
      const testDuration = 5000; // 5 second stress test
      const requestInterval = 50; // Request every 50ms
      const chaosRate = 0.3; // 30% chaos injection
      
      const stressResults = [];
      let requestCounter = 0;
      const startTime = Date.now();
      
      // Initialize chaos monkey for extended stress testing
      const stressChaos = new ChaosMonkey({
        failureRate: chaosRate,
        latencyMs: 2000,
        scenarios: ['latency', 'error', 'timeout', 'partial']
      });
      
      const chaosClient = await stressChaos.wrapApiClient(realApiClient);
      
      // Run stress test for specified duration
      const stressTestPromise = new Promise<void>((resolve) => {
        const intervalId = setInterval(async () => {
          if (Date.now() - startTime > testDuration) {
            clearInterval(intervalId);
            resolve();
            return;
          }
          
          requestCounter++;
          const requestId = `stress-${requestCounter}`;
          
          // Set up response (may be affected by chaos)
          mockApiClient.mockResponse('POST', `/stress-test-${requestCounter}`, {
            success: true,
            data: { 
              id: requestCounter,
              timestamp: Date.now(),
              duration: Date.now() - startTime
            }
          });
          
          try {
            const response = await chaosClient.post(`/stress-test-${requestCounter}`, {
              requestId,
              timestamp: Date.now()
            });
            
            stressResults.push({
              requestId: requestCounter,
              success: true,
              duration: Date.now() - startTime,
              response: response.data
            });
          } catch (error) {
            stressResults.push({
              requestId: requestCounter,
              success: false,
              duration: Date.now() - startTime,
              error: (error as Error).message
            });
          }
        }, requestInterval);
      });
      
      await stressTestPromise;
      
      // Analyze stress test results
      const totalRequests = stressResults.length;
      const successful = stressResults.filter(r => r.success).length;
      const failed = stressResults.filter(r => !r.success).length;
      const overallSuccessRate = successful / totalRequests;
      
      // Verify system maintained stability under stress
      expect(totalRequests).toBeGreaterThan(50); // Should have made many requests
      expect(overallSuccessRate).toBeGreaterThan(0.6); // 60% success rate under chaos
      expect(successful + failed).toBe(totalRequests);
      
      // Verify no catastrophic failures (system didn't crash)
      expect(stressResults[stressResults.length - 1].duration).toBeGreaterThan(testDuration * 0.9);
    });

    it('should provide comprehensive performance metrics and monitoring data', async () => {
      const metricsCollector = {
        requests: [],
        errors: [],
        responseTimePercentiles: { p50: 0, p90: 0, p95: 0, p99: 0 },
        throughputHistory: [],
        errorRateHistory: [],
        resourceUtilization: []
      };
      
      const testRequests = 100;
      const batchSize = 10;
      
      for (let batch = 0; batch < testRequests / batchSize; batch++) {
        const batchStartTime = Date.now();
        const batchPromises = [];
        
        for (let i = 0; i < batchSize; i++) {
          const requestId = batch * batchSize + i;
          
          // Vary response times and success rates for realistic metrics
          const responseTime = Math.random() * 1000 + 100;
          const shouldSucceed = Math.random() > 0.1; // 90% success rate
          
          if (shouldSucceed) {
            mockApiClient.mockDelay('GET', `/metrics-${requestId}`, responseTime);
            mockApiClient.mockResponse('GET', `/metrics-${requestId}`, {
              success: true,
              data: { id: requestId, responseTime }
            });
          } else {
            mockApiClient.mockFailure('GET', `/metrics-${requestId}`, 
              new Error('Simulated error for metrics'));
          }
          
          const requestPromise = realApiClient.get(`/metrics-${requestId}`);
          batchPromises.push(
            requestPromise
              .then(response => ({
                success: true,
                requestId,
                responseTime: Date.now() - batchStartTime,
                data: response.data
              }))
              .catch(error => ({
                success: false,
                requestId,
                responseTime: Date.now() - batchStartTime,
                error: error.message
              }))
          );
        }
        
        const batchResults = await Promise.all(batchPromises);
        const batchDuration = Date.now() - batchStartTime;
        
        // Collect metrics
        batchResults.forEach(result => {
          metricsCollector.requests.push(result);
          if (!result.success) {
            metricsCollector.errors.push(result);
          }
        });
        
        const batchSuccessful = batchResults.filter(r => r.success).length;
        const batchThroughput = batchSuccessful / (batchDuration / 1000);
        const batchErrorRate = (batchSize - batchSuccessful) / batchSize;
        
        metricsCollector.throughputHistory.push(batchThroughput);
        metricsCollector.errorRateHistory.push(batchErrorRate);
        
        // Simulate resource utilization tracking
        metricsCollector.resourceUtilization.push({
          cpu: Math.random() * 0.3 + 0.1, // 10-40% CPU
          memory: Math.random() * 0.2 + 0.2, // 20-40% memory
          network: batchThroughput / 100 // Network utilization based on throughput
        });
        
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      
      // Calculate response time percentiles
      const responseTimes = metricsCollector.requests
        .filter(r => r.success)
        .map(r => r.responseTime)
        .sort((a, b) => a - b);
      
      if (responseTimes.length > 0) {
        metricsCollector.responseTimePercentiles = {
          p50: responseTimes[Math.floor(responseTimes.length * 0.5)],
          p90: responseTimes[Math.floor(responseTimes.length * 0.9)],
          p95: responseTimes[Math.floor(responseTimes.length * 0.95)],
          p99: responseTimes[Math.floor(responseTimes.length * 0.99)]
        };
      }
      
      // Verify comprehensive metrics collection
      expect(metricsCollector.requests).toHaveLength(testRequests);
      expect(metricsCollector.throughputHistory).toHaveLength(testRequests / batchSize);
      expect(metricsCollector.errorRateHistory).toHaveLength(testRequests / batchSize);
      expect(metricsCollector.resourceUtilization).toHaveLength(testRequests / batchSize);
      
      // Verify performance characteristics
      const avgThroughput = metricsCollector.throughputHistory.reduce((a, b) => a + b, 0) / metricsCollector.throughputHistory.length;
      const avgErrorRate = metricsCollector.errorRateHistory.reduce((a, b) => a + b, 0) / metricsCollector.errorRateHistory.length;
      
      expect(avgThroughput).toBeGreaterThan(5); // At least 5 requests per second
      expect(avgErrorRate).toBeLessThan(0.15); // Less than 15% error rate
      expect(metricsCollector.responseTimePercentiles.p95).toBeLessThan(2000); // 95th percentile under 2s
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

  describe('Advanced Circuit Breaker Pattern Integration', () => {
    it('should open circuit breaker after consecutive failures and prevent cascading failures', async () => {
      let failureCount = 0;
      let circuitState = 'CLOSED';
      const failureThreshold = 5;
      const circuitBreakerTimeout = 2000;
      let lastFailureTime = 0;
      
      // Enhanced circuit breaker simulation with ChaosMonkey
      const chaosClient = await new ChaosMonkey({
        failureRate: 0.8,
        scenarios: ['error', 'timeout']
      }).wrapApiClient(realApiClient);
      
      const circuitBreakerHandler = jest.fn(async (endpoint: string) => {
        const now = Date.now();
        
        // Check if circuit should be half-open (after timeout)
        if (circuitState === 'OPEN' && now - lastFailureTime > circuitBreakerTimeout) {
          circuitState = 'HALF_OPEN';
        }
        
        // Block requests if circuit is open
        if (circuitState === 'OPEN') {
          const error = new Error('Circuit breaker is OPEN - blocking request') as any;
          error.code = 'CIRCUIT_BREAKER_OPEN';
          error.circuitState = circuitState;
          throw error;
        }
        
        try {
          failureCount++;
          
          // Simulate service failures
          if (failureCount <= failureThreshold + 2) {
            lastFailureTime = now;
            const error = new Error('Service consistently failing') as any;
            error.status = 503;
            error.retryable = true;
            throw error;
          }
          
          // Reset circuit breaker on success
          if (circuitState === 'HALF_OPEN') {
            circuitState = 'CLOSED';
            failureCount = 0;
          }
          
          return {
            success: true,
            data: { message: 'Service recovered', circuitState, failureCount }
          };
        } catch (error) {
          // Open circuit after threshold failures
          if (failureCount >= failureThreshold && circuitState === 'CLOSED') {
            circuitState = 'OPEN';
            lastFailureTime = now;
          }
          throw error;
        }
      });
      
      (realApiClient as any).get = circuitBreakerHandler;
      
      const requestResults = [];
      
      // Make requests that should trigger circuit breaker
      for (let i = 0; i < 10; i++) {
        try {
          const response = await realApiClient.get(`/circuit-breaker-test-${i}`);
          requestResults.push({ attempt: i + 1, success: true, response });
        } catch (error) {
          requestResults.push({ 
            attempt: i + 1, 
            success: false, 
            error: (error as any).message,
            code: (error as any).code,
            circuitState: (error as any).circuitState
          });
        }
        
        // Small delay between requests
        await new Promise(resolve => setTimeout(resolve, 50));
      }
      
      // Verify circuit breaker behavior
      const circuitOpenRequests = requestResults.filter(r => 
        !r.success && r.code === 'CIRCUIT_BREAKER_OPEN'
      );
      
      expect(circuitOpenRequests.length).toBeGreaterThan(0); // Some requests should be blocked
      expect(failureCount).toBeGreaterThanOrEqual(failureThreshold); // Should reach failure threshold
    });

    it('should transition through circuit breaker states (CLOSED -> OPEN -> HALF_OPEN -> CLOSED)', async () => {
      let circuitState = 'CLOSED';
      let failureCount = 0;
      let successCount = 0;
      const failureThreshold = 3;
      const halfOpenTimeout = 1000;
      let lastStateChange = Date.now();
      
      const stateTransitionHandler = jest.fn(async (endpoint: string) => {
        const now = Date.now();
        
        // State transition logic
        switch (circuitState) {
          case 'CLOSED':
            // Normal operation - fail until threshold
            if (failureCount < failureThreshold) {
              failureCount++;
              const error = new Error(`Failure ${failureCount}/${failureThreshold}`) as any;
              error.status = 500;
              throw error;
            } else {
              circuitState = 'OPEN';
              lastStateChange = now;
              const error = new Error('Circuit opened due to failures') as any;
              error.code = 'CIRCUIT_OPENED';
              throw error;
            }
            
          case 'OPEN':
            // Block requests, transition to HALF_OPEN after timeout
            if (now - lastStateChange > halfOpenTimeout) {
              circuitState = 'HALF_OPEN';
              lastStateChange = now;
              successCount = 0;
            }
            const blockError = new Error('Circuit breaker OPEN') as any;
            blockError.code = 'CIRCUIT_BLOCKED';
            throw blockError;
            
          case 'HALF_OPEN':
            // Allow limited requests, close on success
            successCount++;
            if (successCount >= 2) {
              circuitState = 'CLOSED';
              failureCount = 0;
              lastStateChange = now;
            }
            return {
              success: true,
              data: { 
                message: 'Half-open request succeeded', 
                circuitState, 
                successCount 
              }
            };
            
          default:
            return { success: true, data: { message: 'Default response' } };
        }
      });
      
      (realApiClient as any).post = stateTransitionHandler;
      
      const stateHistory = [];
      
      // Test state transitions over time
      for (let i = 0; i < 8; i++) {
        try {
          const response = await realApiClient.post(`/state-transition-${i}`, { test: i });
          stateHistory.push({ 
            attempt: i + 1, 
            success: true, 
            circuitState, 
            response: response.data 
          });
        } catch (error) {
          stateHistory.push({ 
            attempt: i + 1, 
            success: false, 
            circuitState, 
            error: (error as any).message,
            code: (error as any).code
          });
        }
        
        // Wait between attempts
        if (i === 3) await new Promise(resolve => setTimeout(resolve, halfOpenTimeout + 100));
        else await new Promise(resolve => setTimeout(resolve, 100));
      }
      
      // Verify state transitions occurred
      const states = stateHistory.map(h => h.circuitState);
      expect(states).toContain('CLOSED');
      expect(states).toContain('OPEN');
      expect(states).toContain('HALF_OPEN');
      
      // Verify final recovery
      const finalStates = stateHistory.slice(-2);
      expect(finalStates.some(s => s.success)).toBe(true);
    });

    it('should implement circuit breaker with bulkhead isolation for different endpoints', async () => {
      const endpointCircuits = new Map();
      const initializeCircuit = (endpoint: string) => ({
        state: 'CLOSED',
        failureCount: 0,
        lastFailureTime: 0,
        threshold: 3
      });
      
      const bulkheadHandler = jest.fn(async (endpoint: string) => {
        if (!endpointCircuits.has(endpoint)) {
          endpointCircuits.set(endpoint, initializeCircuit(endpoint));
        }
        
        const circuit = endpointCircuits.get(endpoint);
        const now = Date.now();
        
        // Simulate different failure patterns per endpoint
        const endpointBehaviors = {
          '/users': { shouldFail: circuit.failureCount < 2, errorStatus: 503 },
          '/orders': { shouldFail: circuit.failureCount < 4, errorStatus: 500 },
          '/inventory': { shouldFail: false, errorStatus: null }
        };
        
        const behavior = endpointBehaviors[endpoint as keyof typeof endpointBehaviors] || 
          { shouldFail: false, errorStatus: null };
        
        if (circuit.state === 'OPEN' && now - circuit.lastFailureTime < 2000) {
          const error = new Error(`Circuit OPEN for ${endpoint}`) as any;
          error.code = 'CIRCUIT_OPEN';
          error.endpoint = endpoint;
          throw error;
        }
        
        if (behavior.shouldFail) {
          circuit.failureCount++;
          circuit.lastFailureTime = now;
          
          if (circuit.failureCount >= circuit.threshold) {
            circuit.state = 'OPEN';
          }
          
          const error = new Error(`${endpoint} service failure`) as any;
          error.status = behavior.errorStatus;
          error.endpoint = endpoint;
          throw error;
        }
        
        // Success - reset circuit
        circuit.state = 'CLOSED';
        circuit.failureCount = 0;
        
        return {
          success: true,
          data: { 
            endpoint,
            message: 'Request succeeded',
            circuitState: circuit.state
          }
        };
      });
      
      const testEndpoints = ['/users', '/orders', '/inventory'];
      const results: Array<{ round: number; endpoint: string; success: boolean; response?: any; error?: any; code?: any }> = [];
      
      // Test bulkhead isolation - failures in one endpoint shouldn't affect others
      for (let round = 0; round < 3; round++) {
        for (const endpoint of testEndpoints) {
          (realApiClient as any).get = bulkheadHandler;
          
          try {
            const response = await realApiClient.get(endpoint);
            results.push({ 
              round: round + 1, 
              endpoint, 
              success: true, 
              response: response.data 
            });
          } catch (error) {
            results.push({ 
              round: round + 1, 
              endpoint, 
              success: false, 
              error: (error as any).message,
              code: (error as any).code
            });
          }
        }
        
        await new Promise(resolve => setTimeout(resolve, 100));
      }
      
      // Verify bulkhead isolation
      const userResults = results.filter(r => r.endpoint === '/users');
      const orderResults = results.filter(r => r.endpoint === '/orders');
      const inventoryResults = results.filter(r => r.endpoint === '/inventory');
      
      // Users and orders should have some failures, inventory should not
      expect(userResults.some(r => !r.success)).toBe(true);
      expect(orderResults.some(r => !r.success)).toBe(true);
      expect(inventoryResults.every(r => r.success)).toBe(true);
    });

    it('should provide circuit breaker metrics and monitoring data', async () => {
      const circuitMetrics = {
        totalRequests: 0,
        successfulRequests: 0,
        failedRequests: 0,
        circuitOpenCount: 0,
        circuitHalfOpenCount: 0,
        circuitClosedCount: 0,
        averageResponseTime: 0,
        lastFailureTime: null as number | null,
        requestTimes: [] as number[]
      };
      
      let currentState = 'CLOSED';
      
      const metricsHandler = jest.fn(async (endpoint: string) => {
        const startTime = Date.now();
        circuitMetrics.totalRequests++;
        
        try {
          // Simulate different response times and success rates
          const responseTime = Math.random() * 1000 + 100;
          await new Promise(resolve => setTimeout(resolve, responseTime));
          
          if (circuitMetrics.totalRequests <= 5 && Math.random() < 0.7) {
            throw new Error('Simulated service failure');
          }
          
          circuitMetrics.successfulRequests++;
          currentState = 'CLOSED';
          circuitMetrics.circuitClosedCount++;
          
          const duration = Date.now() - startTime;
          circuitMetrics.requestTimes.push(duration);
          circuitMetrics.averageResponseTime = 
            circuitMetrics.requestTimes.reduce((a, b) => a + b, 0) / circuitMetrics.requestTimes.length;
          
          return {
            success: true,
            data: { 
              message: 'Success with metrics',
              metrics: { ...circuitMetrics, currentState }
            }
          };
        } catch (error) {
          circuitMetrics.failedRequests++;
          circuitMetrics.lastFailureTime = Date.now();
          
          if (circuitMetrics.failedRequests >= 3) {
            currentState = 'OPEN';
            circuitMetrics.circuitOpenCount++;
          }
          
          (error as any).metrics = { ...circuitMetrics, currentState };
          throw error;
        }
      });
      
      (realApiClient as any).put = metricsHandler;
      
      const testResults = [];
      
      // Generate requests to collect metrics
      for (let i = 0; i < 10; i++) {
        try {
          const response = await realApiClient.put(`/metrics-test-${i}`, { data: i });
          testResults.push({ attempt: i + 1, success: true, metrics: response.data.metrics });
        } catch (error) {
          testResults.push({ 
            attempt: i + 1, 
            success: false, 
            metrics: (error as any).metrics 
          });
        }
        
        await new Promise(resolve => setTimeout(resolve, 50));
      }
      
      // Verify metrics collection
      const finalMetrics = testResults[testResults.length - 1].metrics;
      
      expect(finalMetrics.totalRequests).toBe(10);
      expect(finalMetrics.successfulRequests + finalMetrics.failedRequests).toBe(10);
      expect(finalMetrics.averageResponseTime).toBeGreaterThan(0);
      expect(typeof finalMetrics.lastFailureTime).toBe('number');
      expect(finalMetrics.circuitOpenCount + finalMetrics.circuitClosedCount).toBeGreaterThan(0);
    });
  });
});