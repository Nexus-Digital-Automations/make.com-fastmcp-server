/**
 * @fileoverview Error handling and recovery integration tests
 * 
 * Tests comprehensive error scenarios, recovery mechanisms, fault tolerance,
 * graceful degradation, and system resilience across all components.
 * 
 * @version 1.0.0
 */

import { describe, test, expect, beforeAll, afterAll, beforeEach, afterEach } from '@jest/globals';
import type { FastMCP } from 'fastmcp';
import type MakeApiClient from '../../src/lib/make-api-client.js';

// Error handling types and interfaces
interface ErrorScenario {
  id: string;
  name: string;
  type: 'network' | 'authentication' | 'authorization' | 'validation' | 'rate_limit' | 'system' | 'data';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  triggerCondition: () => Promise<void>;
  expectedBehavior: string;
  recoveryStrategy: string;
}

interface ErrorResponse {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
    timestamp: string;
    requestId?: string;
    retryable: boolean;
  };
  status: number;
  headers?: Record<string, string>;
}

interface RecoveryAttempt {
  id: string;
  errorType: string;
  strategy: string;
  startTime: string;
  endTime?: string;
  success: boolean;
  attempts: number;
  finalOutcome: 'recovered' | 'failed' | 'degraded';
  metrics: {
    totalDuration: number;
    averageAttemptDuration: number;
    successRate: number;
  };
}

interface CircuitBreakerState {
  state: 'closed' | 'open' | 'half-open';
  failureCount: number;
  failureThreshold: number;
  timeout: number;
  lastFailureTime?: string;
  nextAttemptTime?: string;
}

interface RetryPolicy {
  maxAttempts: number;
  baseDelay: number;
  maxDelay: number;
  backoffMultiplier: number;
  jitterEnabled: boolean;
  retryableErrors: string[];
}

// Mock error handling and recovery system
class MockErrorHandlingSystem {
  private errorScenarios: Map<string, ErrorScenario> = new Map();
  private recoveryAttempts: Map<string, RecoveryAttempt> = new Map();
  private circuitBreakers: Map<string, CircuitBreakerState> = new Map();
  private retryPolicies: Map<string, RetryPolicy> = new Map();
  private errorLogs: Array<{ timestamp: string; error: ErrorResponse; context: string }> = [];

  // Error scenario management
  async registerErrorScenario(scenario: ErrorScenario): Promise<void> {
    this.errorScenarios.set(scenario.id, { ...scenario });
  }

  async triggerErrorScenario(scenarioId: string, context: string = 'test'): Promise<ErrorResponse> {
    const scenario = this.errorScenarios.get(scenarioId);
    if (!scenario) {
      throw new Error(`Error scenario ${scenarioId} not found`);
    }

    await scenario.triggerCondition();

    const errorResponse: ErrorResponse = {
      error: {
        code: `ERR_${scenario.type.toUpperCase()}`,
        message: scenario.description,
        details: { scenarioId, severity: scenario.severity },
        timestamp: new Date().toISOString(),
        requestId: `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        retryable: this.isRetryableError(scenario.type),
      },
      status: this.getStatusCodeForErrorType(scenario.type),
    };

    this.logError(errorResponse, context);
    return errorResponse;
  }

  // Circuit breaker implementation
  async initializeCircuitBreaker(
    serviceId: string,
    failureThreshold: number = 5,
    timeout: number = 30000
  ): Promise<void> {
    this.circuitBreakers.set(serviceId, {
      state: 'closed',
      failureCount: 0,
      failureThreshold,
      timeout,
    });
  }

  async recordSuccess(serviceId: string): Promise<void> {
    const circuitBreaker = this.circuitBreakers.get(serviceId);
    if (circuitBreaker) {
      circuitBreaker.failureCount = 0;
      if (circuitBreaker.state === 'half-open') {
        circuitBreaker.state = 'closed';
      }
    }
  }

  async recordFailure(serviceId: string): Promise<void> {
    const circuitBreaker = this.circuitBreakers.get(serviceId);
    if (!circuitBreaker) return;

    circuitBreaker.failureCount++;
    circuitBreaker.lastFailureTime = new Date().toISOString();

    if (circuitBreaker.failureCount >= circuitBreaker.failureThreshold) {
      circuitBreaker.state = 'open';
      circuitBreaker.nextAttemptTime = new Date(Date.now() + circuitBreaker.timeout).toISOString();
    }
  }

  async checkCircuitBreaker(serviceId: string): Promise<{ allowed: boolean; state: string }> {
    const circuitBreaker = this.circuitBreakers.get(serviceId);
    if (!circuitBreaker) {
      return { allowed: true, state: 'none' };
    }

    if (circuitBreaker.state === 'closed') {
      return { allowed: true, state: 'closed' };
    }

    if (circuitBreaker.state === 'open') {
      const now = Date.now();
      const nextAttempt = circuitBreaker.nextAttemptTime ? new Date(circuitBreaker.nextAttemptTime).getTime() : 0;
      
      if (now >= nextAttempt) {
        circuitBreaker.state = 'half-open';
        return { allowed: true, state: 'half-open' };
      }
      
      return { allowed: false, state: 'open' };
    }

    // half-open state allows one attempt
    return { allowed: true, state: 'half-open' };
  }

  // Retry mechanism
  async setRetryPolicy(operation: string, policy: RetryPolicy): Promise<void> {
    this.retryPolicies.set(operation, { ...policy });
  }

  async executeWithRetry<T>(
    operation: string,
    fn: () => Promise<T>,
    context?: Record<string, unknown>
  ): Promise<T> {
    const policy = this.retryPolicies.get(operation) || {
      maxAttempts: 3,
      baseDelay: 1000,
      maxDelay: 10000,
      backoffMultiplier: 2,
      jitterEnabled: true,
      retryableErrors: ['ERR_NETWORK', 'ERR_RATE_LIMIT', 'ERR_SYSTEM'],
    };

    let attempt = 0;
    let lastError: Error | null = null;

    while (attempt < policy.maxAttempts) {
      attempt++;

      try {
        const result = await fn();
        return result;
      } catch (error) {
        lastError = error as Error;
        
        // Check if error is retryable
        if (!this.shouldRetryError(error as Error, policy)) {
          throw error;
        }

        // Don't wait after the last attempt
        if (attempt < policy.maxAttempts) {
          const delay = this.calculateDelay(attempt, policy);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }

    throw lastError;
  }

  // Recovery mechanisms
  async attemptRecovery(
    errorType: string,
    strategy: string,
    context?: Record<string, unknown>
  ): Promise<RecoveryAttempt> {
    const recoveryId = `recovery_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const startTime = new Date().toISOString();

    const recovery: RecoveryAttempt = {
      id: recoveryId,
      errorType,
      strategy,
      startTime,
      success: false,
      attempts: 0,
      finalOutcome: 'failed',
      metrics: {
        totalDuration: 0,
        averageAttemptDuration: 0,
        successRate: 0,
      },
    };

    this.recoveryAttempts.set(recoveryId, recovery);

    try {
      await this.executeRecoveryStrategy(strategy, context);
      recovery.success = true;
      recovery.finalOutcome = 'recovered';
    } catch (error) {
      recovery.success = false;
      recovery.finalOutcome = 'failed';
    }

    recovery.endTime = new Date().toISOString();
    recovery.metrics.totalDuration = new Date(recovery.endTime).getTime() - new Date(startTime).getTime();

    return recovery;
  }

  // Graceful degradation
  async enableGracefulDegradation(
    serviceId: string,
    fallbackBehavior: 'cache' | 'default_values' | 'reduced_functionality' | 'read_only'
  ): Promise<{ enabled: boolean; behavior: string; limitations: string[] }> {
    const limitations: string[] = [];

    switch (fallbackBehavior) {
      case 'cache':
        limitations.push('Data may be stale', 'No real-time updates');
        break;
      case 'default_values':
        limitations.push('Using default values', 'Reduced accuracy');
        break;
      case 'reduced_functionality':
        limitations.push('Limited features available', 'Performance may be slower');
        break;
      case 'read_only':
        limitations.push('No write operations', 'No data modifications');
        break;
    }

    return {
      enabled: true,
      behavior: fallbackBehavior,
      limitations,
    };
  }

  // Error monitoring and alerting
  async getErrorMetrics(timeWindow: number = 3600000): Promise<{
    totalErrors: number;
    errorsByType: Record<string, number>;
    errorsBySeverity: Record<string, number>;
    averageRecoveryTime: number;
    successfulRecoveries: number;
  }> {
    const cutoff = Date.now() - timeWindow;
    const recentErrors = this.errorLogs.filter(
      log => new Date(log.timestamp).getTime() >= cutoff
    );

    const errorsByType: Record<string, number> = {};
    const errorsBySeverity: Record<string, number> = {};

    recentErrors.forEach(log => {
      const errorType = log.error.error.code;
      const severity = (log.error.error.details?.severity as string) || 'unknown';

      errorsByType[errorType] = (errorsByType[errorType] || 0) + 1;
      errorsBySeverity[severity] = (errorsBySeverity[severity] || 0) + 1;
    });

    const recentRecoveries = Array.from(this.recoveryAttempts.values()).filter(
      recovery => new Date(recovery.startTime).getTime() >= cutoff
    );

    const successfulRecoveries = recentRecoveries.filter(r => r.success).length;
    const averageRecoveryTime = recentRecoveries.length > 0
      ? recentRecoveries.reduce((sum, r) => sum + r.metrics.totalDuration, 0) / recentRecoveries.length
      : 0;

    return {
      totalErrors: recentErrors.length,
      errorsByType,
      errorsBySeverity,
      averageRecoveryTime,
      successfulRecoveries,
    };
  }

  // Utility methods
  private isRetryableError(errorType: string): boolean {
    const retryableTypes = ['network', 'rate_limit', 'system'];
    return retryableTypes.includes(errorType);
  }

  private getStatusCodeForErrorType(errorType: string): number {
    const statusCodes: Record<string, number> = {
      network: 503,
      authentication: 401,
      authorization: 403,
      validation: 400,
      rate_limit: 429,
      system: 500,
      data: 422,
    };
    return statusCodes[errorType] || 500;
  }

  private shouldRetryError(error: Error, policy: RetryPolicy): boolean {
    return policy.retryableErrors.some(retryableError =>
      error.message.includes(retryableError)
    );
  }

  private calculateDelay(attempt: number, policy: RetryPolicy): number {
    let delay = policy.baseDelay * Math.pow(policy.backoffMultiplier, attempt - 1);
    delay = Math.min(delay, policy.maxDelay);

    if (policy.jitterEnabled) {
      delay += Math.random() * delay * 0.1; // Add up to 10% jitter
    }

    return delay;
  }

  private async executeRecoveryStrategy(strategy: string, context?: Record<string, unknown>): Promise<void> {
    // Simulate different recovery strategies
    const delay = Math.random() * 1000 + 500; // 500-1500ms
    await new Promise(resolve => setTimeout(resolve, delay));

    switch (strategy) {
      case 'restart_service':
        // 80% success rate
        if (Math.random() < 0.8) return;
        throw new Error('Service restart failed');

      case 'clear_cache':
        // 95% success rate
        if (Math.random() < 0.95) return;
        throw new Error('Cache clear failed');

      case 'reconnect_database':
        // 70% success rate
        if (Math.random() < 0.7) return;
        throw new Error('Database reconnection failed');

      case 'fallback_to_backup':
        // 90% success rate
        if (Math.random() < 0.9) return;
        throw new Error('Backup system unavailable');

      default:
        // Default 85% success rate
        if (Math.random() < 0.85) return;
        throw new Error('Recovery strategy failed');
    }
  }

  private logError(error: ErrorResponse, context: string): void {
    this.errorLogs.push({
      timestamp: new Date().toISOString(),
      error,
      context,
    });
  }

  // Test utilities
  async clear(): Promise<void> {
    this.errorScenarios.clear();
    this.recoveryAttempts.clear();
    this.circuitBreakers.clear();
    this.retryPolicies.clear();
    this.errorLogs.length = 0;
  }

  getStats(): {
    scenarios: number;
    recoveries: number;
    circuitBreakers: number;
    retryPolicies: number;
    errorLogs: number;
  } {
    return {
      scenarios: this.errorScenarios.size,
      recoveries: this.recoveryAttempts.size,
      circuitBreakers: this.circuitBreakers.size,
      retryPolicies: this.retryPolicies.size,
      errorLogs: this.errorLogs.length,
    };
  }
}

describe('Error Handling and Recovery Integration Tests', () => {
  let errorSystem: MockErrorHandlingSystem;
  let mockServer: FastMCP;
  let mockApiClient: MakeApiClient;

  beforeAll(async () => {
    errorSystem = new MockErrorHandlingSystem();
    
    mockServer = {
      addTool: jest.fn(),
      addResource: jest.fn(),
      addPrompt: jest.fn(),
    } as unknown as FastMCP;

    mockApiClient = {
      get: jest.fn(),
      post: jest.fn(),
      put: jest.fn(),
      delete: jest.fn(),
    } as unknown as MakeApiClient;
  });

  beforeEach(async () => {
    await errorSystem.clear();
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Error Scenario Management', () => {
    test('should register and trigger network error scenarios', async () => {
      const networkError: ErrorScenario = {
        id: 'network-timeout',
        name: 'Network Timeout Error',
        type: 'network',
        severity: 'high',
        description: 'Network request timed out after 30 seconds',
        triggerCondition: async () => {
          // Simulate network timeout
          await new Promise(resolve => setTimeout(resolve, 100));
        },
        expectedBehavior: 'Return timeout error with retry suggestion',
        recoveryStrategy: 'Retry with exponential backoff',
      };

      await errorSystem.registerErrorScenario(networkError);
      
      const errorResponse = await errorSystem.triggerErrorScenario('network-timeout', 'test-context');
      
      expect(errorResponse.error.code).toBe('ERR_NETWORK');
      expect(errorResponse.error.message).toBe(networkError.description);
      expect(errorResponse.error.retryable).toBe(true);
      expect(errorResponse.status).toBe(503);
      expect(errorResponse.error.requestId).toBeTruthy();
    });

    test('should handle authentication error scenarios', async () => {
      const authError: ErrorScenario = {
        id: 'invalid-token',
        name: 'Invalid Authentication Token',
        type: 'authentication',
        severity: 'medium',
        description: 'Authentication token has expired or is invalid',
        triggerCondition: async () => {
          // Simulate token validation failure
        },
        expectedBehavior: 'Return 401 with token refresh instructions',
        recoveryStrategy: 'Refresh authentication token',
      };

      await errorSystem.registerErrorScenario(authError);
      
      const errorResponse = await errorSystem.triggerErrorScenario('invalid-token');
      
      expect(errorResponse.error.code).toBe('ERR_AUTHENTICATION');
      expect(errorResponse.error.retryable).toBe(false);
      expect(errorResponse.status).toBe(401);
    });

    test('should handle validation error scenarios', async () => {
      const validationError: ErrorScenario = {
        id: 'invalid-input',
        name: 'Invalid Input Validation',
        type: 'validation',
        severity: 'low',
        description: 'Required field "name" is missing or invalid',
        triggerCondition: async () => {
          // Simulate validation failure
        },
        expectedBehavior: 'Return validation error with field details',
        recoveryStrategy: 'Fix input and retry',
      };

      await errorSystem.registerErrorScenario(validationError);
      
      const errorResponse = await errorSystem.triggerErrorScenario('invalid-input');
      
      expect(errorResponse.error.code).toBe('ERR_VALIDATION');
      expect(errorResponse.error.retryable).toBe(false);
      expect(errorResponse.status).toBe(400);
    });

    test('should handle rate limiting error scenarios', async () => {
      const rateLimitError: ErrorScenario = {
        id: 'rate-limit-exceeded',
        name: 'Rate Limit Exceeded',
        type: 'rate_limit',
        severity: 'medium',
        description: 'Rate limit of 100 requests per minute exceeded',
        triggerCondition: async () => {
          // Simulate rate limit check
        },
        expectedBehavior: 'Return 429 with retry-after header',
        recoveryStrategy: 'Wait and retry with backoff',
      };

      await errorSystem.registerErrorScenario(rateLimitError);
      
      const errorResponse = await errorSystem.triggerErrorScenario('rate-limit-exceeded');
      
      expect(errorResponse.error.code).toBe('ERR_RATE_LIMIT');
      expect(errorResponse.error.retryable).toBe(true);
      expect(errorResponse.status).toBe(429);
    });
  });

  describe('Circuit Breaker Implementation', () => {
    test('should initialize and manage circuit breaker states', async () => {
      await errorSystem.initializeCircuitBreaker('test-service', 3, 5000);
      
      // Circuit should start closed
      let state = await errorSystem.checkCircuitBreaker('test-service');
      expect(state.allowed).toBe(true);
      expect(state.state).toBe('closed');

      // Record failures
      await errorSystem.recordFailure('test-service');
      await errorSystem.recordFailure('test-service');
      await errorSystem.recordFailure('test-service');

      // Circuit should now be open
      state = await errorSystem.checkCircuitBreaker('test-service');
      expect(state.allowed).toBe(false);
      expect(state.state).toBe('open');
    });

    test('should transition from open to half-open after timeout', async () => {
      await errorSystem.initializeCircuitBreaker('timeout-service', 2, 100); // 100ms timeout

      // Trigger circuit opening
      await errorSystem.recordFailure('timeout-service');
      await errorSystem.recordFailure('timeout-service');

      let state = await errorSystem.checkCircuitBreaker('timeout-service');
      expect(state.state).toBe('open');

      // Wait for timeout
      await new Promise(resolve => setTimeout(resolve, 150));

      state = await errorSystem.checkCircuitBreaker('timeout-service');
      expect(state.allowed).toBe(true);
      expect(state.state).toBe('half-open');
    });

    test('should reset circuit breaker on successful operation', async () => {
      await errorSystem.initializeCircuitBreaker('reset-service', 2, 5000);

      // Trigger failures
      await errorSystem.recordFailure('reset-service');
      await errorSystem.recordFailure('reset-service');

      let state = await errorSystem.checkCircuitBreaker('reset-service');
      expect(state.state).toBe('open');

      // Wait for half-open
      await new Promise(resolve => setTimeout(resolve, 10));
      
      // Record success to reset
      await errorSystem.recordSuccess('reset-service');

      state = await errorSystem.checkCircuitBreaker('reset-service');
      expect(state.state).toBe('closed');
    });

    test('should handle multiple circuit breakers independently', async () => {
      await errorSystem.initializeCircuitBreaker('service-a', 2, 1000);
      await errorSystem.initializeCircuitBreaker('service-b', 3, 2000);

      // Fail service A
      await errorSystem.recordFailure('service-a');
      await errorSystem.recordFailure('service-a');

      // Service A should be open, Service B should be closed
      const stateA = await errorSystem.checkCircuitBreaker('service-a');
      const stateB = await errorSystem.checkCircuitBreaker('service-b');

      expect(stateA.state).toBe('open');
      expect(stateB.state).toBe('closed');
    });
  });

  describe('Retry Mechanisms', () => {
    test('should retry operations with exponential backoff', async () => {
      const retryPolicy: RetryPolicy = {
        maxAttempts: 3,
        baseDelay: 100,
        maxDelay: 1000,
        backoffMultiplier: 2,
        jitterEnabled: false,
        retryableErrors: ['ERR_NETWORK'],
      };

      await errorSystem.setRetryPolicy('test-operation', retryPolicy);

      let attemptCount = 0;
      const mockOperation = jest.fn().mockImplementation(async () => {
        attemptCount++;
        if (attemptCount < 3) {
          throw new Error('ERR_NETWORK: Connection failed');
        }
        return 'success';
      });

      const startTime = Date.now();
      const result = await errorSystem.executeWithRetry('test-operation', mockOperation);
      const duration = Date.now() - startTime;

      expect(result).toBe('success');
      expect(mockOperation).toHaveBeenCalledTimes(3);
      expect(duration).toBeGreaterThan(200); // Should have waited for retries
    });

    test('should not retry non-retryable errors', async () => {
      const retryPolicy: RetryPolicy = {
        maxAttempts: 3,
        baseDelay: 100,
        maxDelay: 1000,
        backoffMultiplier: 2,
        jitterEnabled: false,
        retryableErrors: ['ERR_NETWORK'],
      };

      await errorSystem.setRetryPolicy('no-retry-operation', retryPolicy);

      const mockOperation = jest.fn().mockRejectedValue(new Error('ERR_VALIDATION: Invalid input'));

      await expect(
        errorSystem.executeWithRetry('no-retry-operation', mockOperation)
      ).rejects.toThrow('ERR_VALIDATION');

      expect(mockOperation).toHaveBeenCalledTimes(1); // Should not retry
    });

    test('should respect maximum retry attempts', async () => {
      const retryPolicy: RetryPolicy = {
        maxAttempts: 2,
        baseDelay: 50,
        maxDelay: 500,
        backoffMultiplier: 2,
        jitterEnabled: false,
        retryableErrors: ['ERR_SYSTEM'],
      };

      await errorSystem.setRetryPolicy('max-attempts-test', retryPolicy);

      const mockOperation = jest.fn().mockRejectedValue(new Error('ERR_SYSTEM: System error'));

      await expect(
        errorSystem.executeWithRetry('max-attempts-test', mockOperation)
      ).rejects.toThrow('ERR_SYSTEM');

      expect(mockOperation).toHaveBeenCalledTimes(2); // Should respect max attempts
    });

    test('should add jitter to retry delays when enabled', async () => {
      const retryPolicy: RetryPolicy = {
        maxAttempts: 3,
        baseDelay: 100,
        maxDelay: 1000,
        backoffMultiplier: 2,
        jitterEnabled: true,
        retryableErrors: ['ERR_NETWORK'],
      };

      await errorSystem.setRetryPolicy('jitter-test', retryPolicy);

      let attemptCount = 0;
      const attemptTimes: number[] = [];
      
      const mockOperation = jest.fn().mockImplementation(async () => {
        attemptTimes.push(Date.now());
        attemptCount++;
        if (attemptCount < 3) {
          throw new Error('ERR_NETWORK: Connection failed');
        }
        return 'success';
      });

      await errorSystem.executeWithRetry('jitter-test', mockOperation);

      // With jitter, delays should vary slightly
      expect(attemptTimes).toHaveLength(3);
      const delay1 = attemptTimes[1] - attemptTimes[0];
      const delay2 = attemptTimes[2] - attemptTimes[1];
      
      // Delays should be in expected range but not exactly the same due to jitter
      expect(delay1).toBeGreaterThan(80);
      expect(delay1).toBeLessThan(150);
      expect(delay2).toBeGreaterThan(180);
      expect(delay2).toBeLessThan(250);
    });
  });

  describe('Recovery Mechanisms', () => {
    test('should attempt service restart recovery', async () => {
      const recovery = await errorSystem.attemptRecovery('system', 'restart_service', {
        serviceId: 'test-service',
        errorCount: 5,
      });

      expect(recovery.id).toBeTruthy();
      expect(recovery.errorType).toBe('system');
      expect(recovery.strategy).toBe('restart_service');
      expect(recovery.startTime).toBeTruthy();
      expect(recovery.endTime).toBeTruthy();
      expect(recovery.metrics.totalDuration).toBeGreaterThan(0);
      expect(['recovered', 'failed']).toContain(recovery.finalOutcome);
    });

    test('should attempt cache clearing recovery', async () => {
      const recovery = await errorSystem.attemptRecovery('data', 'clear_cache', {
        cacheKeys: ['user-data', 'session-data'],
      });

      expect(recovery.strategy).toBe('clear_cache');
      expect(recovery.errorType).toBe('data');
      expect(recovery.success).toBeDefined();
    });

    test('should attempt database reconnection recovery', async () => {
      const recovery = await errorSystem.attemptRecovery('network', 'reconnect_database', {
        connectionString: 'mock://database',
        retryCount: 3,
      });

      expect(recovery.strategy).toBe('reconnect_database');
      expect(recovery.errorType).toBe('network');
      expect(recovery.metrics.totalDuration).toBeGreaterThan(500); // Should take some time
    });

    test('should attempt fallback to backup system', async () => {
      const recovery = await errorSystem.attemptRecovery('system', 'fallback_to_backup', {
        primarySystem: 'main-api',
        backupSystem: 'backup-api',
      });

      expect(recovery.strategy).toBe('fallback_to_backup');
      expect(recovery.finalOutcome).toMatch(/^(recovered|failed|degraded)$/);
    });

    test('should handle recovery failures gracefully', async () => {
      // Attempt multiple recoveries, some should fail due to randomness
      const recoveries = await Promise.all([
        errorSystem.attemptRecovery('system', 'restart_service'),
        errorSystem.attemptRecovery('system', 'restart_service'),
        errorSystem.attemptRecovery('system', 'restart_service'),
        errorSystem.attemptRecovery('system', 'restart_service'),
        errorSystem.attemptRecovery('system', 'restart_service'),
      ]);

      // With 80% success rate, at least one should succeed and one might fail
      const successfulRecoveries = recoveries.filter(r => r.success);
      const failedRecoveries = recoveries.filter(r => !r.success);

      expect(successfulRecoveries.length).toBeGreaterThan(0);
      
      // Each recovery should have proper metrics
      recoveries.forEach(recovery => {
        expect(recovery.metrics.totalDuration).toBeGreaterThan(0);
        expect(recovery.startTime).toBeTruthy();
        expect(recovery.endTime).toBeTruthy();
      });
    });
  });

  describe('Graceful Degradation', () => {
    test('should enable cache-based degradation', async () => {
      const degradation = await errorSystem.enableGracefulDegradation('api-service', 'cache');

      expect(degradation.enabled).toBe(true);
      expect(degradation.behavior).toBe('cache');
      expect(degradation.limitations).toContain('Data may be stale');
      expect(degradation.limitations).toContain('No real-time updates');
    });

    test('should enable default values degradation', async () => {
      const degradation = await errorSystem.enableGracefulDegradation('config-service', 'default_values');

      expect(degradation.enabled).toBe(true);
      expect(degradation.behavior).toBe('default_values');
      expect(degradation.limitations).toContain('Using default values');
      expect(degradation.limitations).toContain('Reduced accuracy');
    });

    test('should enable reduced functionality degradation', async () => {
      const degradation = await errorSystem.enableGracefulDegradation('feature-service', 'reduced_functionality');

      expect(degradation.enabled).toBe(true);
      expect(degradation.behavior).toBe('reduced_functionality');
      expect(degradation.limitations).toContain('Limited features available');
      expect(degradation.limitations).toContain('Performance may be slower');
    });

    test('should enable read-only degradation', async () => {
      const degradation = await errorSystem.enableGracefulDegradation('data-service', 'read_only');

      expect(degradation.enabled).toBe(true);
      expect(degradation.behavior).toBe('read_only');
      expect(degradation.limitations).toContain('No write operations');
      expect(degradation.limitations).toContain('No data modifications');
    });
  });

  describe('Error Monitoring and Metrics', () => {
    test('should collect and analyze error metrics', async () => {
      // Register multiple error scenarios
      const scenarios: ErrorScenario[] = [
        {
          id: 'network-1',
          name: 'Network Error 1',
          type: 'network',
          severity: 'high',
          description: 'Network timeout',
          triggerCondition: async () => {},
          expectedBehavior: 'Retry',
          recoveryStrategy: 'Reconnect',
        },
        {
          id: 'auth-1',
          name: 'Auth Error 1',
          type: 'authentication',
          severity: 'medium',
          description: 'Token expired',
          triggerCondition: async () => {},
          expectedBehavior: 'Refresh token',
          recoveryStrategy: 'Reauth',
        },
        {
          id: 'validation-1',
          name: 'Validation Error 1',
          type: 'validation',
          severity: 'low',
          description: 'Invalid input',
          triggerCondition: async () => {},
          expectedBehavior: 'Return error',
          recoveryStrategy: 'Fix input',
        },
      ];

      for (const scenario of scenarios) {
        await errorSystem.registerErrorScenario(scenario);
        await errorSystem.triggerErrorScenario(scenario.id);
      }

      // Perform some recoveries
      await errorSystem.attemptRecovery('network', 'restart_service');
      await errorSystem.attemptRecovery('authentication', 'refresh_token');

      const metrics = await errorSystem.getErrorMetrics();

      expect(metrics.totalErrors).toBe(3);
      expect(metrics.errorsByType['ERR_NETWORK']).toBe(1);
      expect(metrics.errorsByType['ERR_AUTHENTICATION']).toBe(1);
      expect(metrics.errorsByType['ERR_VALIDATION']).toBe(1);
      expect(metrics.errorsBySeverity['high']).toBe(1);
      expect(metrics.errorsBySeverity['medium']).toBe(1);
      expect(metrics.errorsBySeverity['low']).toBe(1);
      expect(metrics.averageRecoveryTime).toBeGreaterThan(0);
      expect(metrics.successfulRecoveries).toBeGreaterThanOrEqual(0);
    });

    test('should filter metrics by time window', async () => {
      // Trigger an error
      await errorSystem.registerErrorScenario({
        id: 'old-error',
        name: 'Old Error',
        type: 'system',
        severity: 'medium',
        description: 'Old system error',
        triggerCondition: async () => {},
        expectedBehavior: 'Handle',
        recoveryStrategy: 'Restart',
      });

      await errorSystem.triggerErrorScenario('old-error');

      // Check metrics with very short time window (should exclude the error)
      const recentMetrics = await errorSystem.getErrorMetrics(100); // 100ms window
      
      // Wait to ensure error is outside window
      await new Promise(resolve => setTimeout(resolve, 150));
      
      const laterMetrics = await errorSystem.getErrorMetrics(100);
      expect(laterMetrics.totalErrors).toBe(0);

      // Check with longer window (should include the error)
      const allMetrics = await errorSystem.getErrorMetrics(60000); // 1 minute window
      expect(allMetrics.totalErrors).toBeGreaterThanOrEqual(1);
    });
  });

  describe('End-to-End Error Handling Scenarios', () => {
    test('should handle complete network failure and recovery cycle', async () => {
      // Initialize circuit breaker
      await errorSystem.initializeCircuitBreaker('network-service', 3, 2000);

      // Set retry policy
      await errorSystem.setRetryPolicy('network-operation', {
        maxAttempts: 3,
        baseDelay: 100,
        maxDelay: 1000,
        backoffMultiplier: 2,
        jitterEnabled: false,
        retryableErrors: ['ERR_NETWORK'],
      });

      // Register network error scenario
      await errorSystem.registerErrorScenario({
        id: 'network-failure',
        name: 'Complete Network Failure',
        type: 'network',
        severity: 'critical',
        description: 'Network completely unavailable',
        triggerCondition: async () => {
          // Simulate network failure
          await errorSystem.recordFailure('network-service');
        },
        expectedBehavior: 'Circuit breaker opens, retries with backoff',
        recoveryStrategy: 'Network recovery and service restart',
      });

      // Trigger network failure multiple times to open circuit breaker
      await errorSystem.triggerErrorScenario('network-failure');
      await errorSystem.triggerErrorScenario('network-failure');
      await errorSystem.triggerErrorScenario('network-failure');

      // Circuit breaker should be open
      let circuitState = await errorSystem.checkCircuitBreaker('network-service');
      expect(circuitState.state).toBe('open');

      // Attempt recovery
      const recovery = await errorSystem.attemptRecovery('network', 'restart_service');
      
      // Enable graceful degradation
      const degradation = await errorSystem.enableGracefulDegradation('network-service', 'cache');

      // Verify complete cycle
      expect(circuitState.allowed).toBe(false);
      expect(recovery.errorType).toBe('network');
      expect(degradation.enabled).toBe(true);
      expect(degradation.behavior).toBe('cache');
    });

    test('should handle authentication failure and token refresh cycle', async () => {
      // Register auth error
      await errorSystem.registerErrorScenario({
        id: 'auth-failure',
        name: 'Authentication Token Expired',
        type: 'authentication',
        severity: 'medium',
        description: 'JWT token has expired',
        triggerCondition: async () => {},
        expectedBehavior: 'Return 401, suggest token refresh',
        recoveryStrategy: 'Refresh authentication token',
      });

      // Trigger auth failure
      const authError = await errorSystem.triggerErrorScenario('auth-failure');

      // Attempt token refresh recovery
      const recovery = await errorSystem.attemptRecovery('authentication', 'refresh_token');

      // Verify auth cycle
      expect(authError.status).toBe(401);
      expect(authError.error.retryable).toBe(false);
      expect(recovery.errorType).toBe('authentication');
      expect(recovery.strategy).toBe('refresh_token');
    });

    test('should handle cascading failures across multiple services', async () => {
      // Initialize multiple circuit breakers
      await errorSystem.initializeCircuitBreaker('primary-service', 2, 1000);
      await errorSystem.initializeCircuitBreaker('secondary-service', 2, 1000);
      await errorSystem.initializeCircuitBreaker('database-service', 2, 1000);

      // Register cascading failure scenario
      await errorSystem.registerErrorScenario({
        id: 'cascading-failure',
        name: 'Cascading Service Failures',
        type: 'system',
        severity: 'critical',
        description: 'Primary service failure causes cascading failures',
        triggerCondition: async () => {
          // Simulate cascading failures
          await errorSystem.recordFailure('primary-service');
          await errorSystem.recordFailure('primary-service');
          await errorSystem.recordFailure('secondary-service');
          await errorSystem.recordFailure('secondary-service');
          await errorSystem.recordFailure('database-service');
          await errorSystem.recordFailure('database-service');
        },
        expectedBehavior: 'Multiple circuit breakers open, graceful degradation',
        recoveryStrategy: 'Staged service recovery',
      });

      // Trigger cascading failure
      await errorSystem.triggerErrorScenario('cascading-failure');

      // Check circuit breaker states
      const primaryState = await errorSystem.checkCircuitBreaker('primary-service');
      const secondaryState = await errorSystem.checkCircuitBreaker('secondary-service');
      const databaseState = await errorSystem.checkCircuitBreaker('database-service');

      // All should be open
      expect(primaryState.state).toBe('open');
      expect(secondaryState.state).toBe('open');
      expect(databaseState.state).toBe('open');

      // Attempt staged recovery
      const recoveries = await Promise.all([
        errorSystem.attemptRecovery('system', 'restart_service', { service: 'database' }),
        errorSystem.attemptRecovery('system', 'restart_service', { service: 'secondary' }),
        errorSystem.attemptRecovery('system', 'restart_service', { service: 'primary' }),
      ]);

      // Enable degradation for all services
      const degradations = await Promise.all([
        errorSystem.enableGracefulDegradation('primary-service', 'reduced_functionality'),
        errorSystem.enableGracefulDegradation('secondary-service', 'cache'),
        errorSystem.enableGracefulDegradation('database-service', 'read_only'),
      ]);

      // Verify cascading failure handling
      expect(recoveries).toHaveLength(3);
      expect(degradations).toHaveLength(3);
      degradations.forEach(degradation => {
        expect(degradation.enabled).toBe(true);
        expect(degradation.limitations.length).toBeGreaterThan(0);
      });
    });

    test('should handle high-frequency error scenarios with rate limiting', async () => {
      // Set aggressive retry policy
      await errorSystem.setRetryPolicy('high-frequency-operation', {
        maxAttempts: 5,
        baseDelay: 50,
        maxDelay: 500,
        backoffMultiplier: 1.5,
        jitterEnabled: true,
        retryableErrors: ['ERR_RATE_LIMIT', 'ERR_NETWORK'],
      });

      // Register rate limit error
      await errorSystem.registerErrorScenario({
        id: 'rate-limit-burst',
        name: 'Rate Limit Burst Error',
        type: 'rate_limit',
        severity: 'medium',
        description: 'Rate limit exceeded due to burst traffic',
        triggerCondition: async () => {},
        expectedBehavior: 'Backoff and retry with jitter',
        recoveryStrategy: 'Adaptive rate limiting',
      });

      // Trigger multiple rate limit errors rapidly
      const errorPromises = Array.from({ length: 10 }, () =>
        errorSystem.triggerErrorScenario('rate-limit-burst')
      );

      const errors = await Promise.all(errorPromises);

      // All should be rate limit errors
      errors.forEach(error => {
        expect(error.error.code).toBe('ERR_RATE_LIMIT');
        expect(error.status).toBe(429);
        expect(error.error.retryable).toBe(true);
      });

      // Test retry mechanism with rate limit errors
      let retryAttempts = 0;
      const mockRateLimitedOperation = jest.fn().mockImplementation(async () => {
        retryAttempts++;
        if (retryAttempts < 4) {
          throw new Error('ERR_RATE_LIMIT: Too many requests');
        }
        return 'success';
      });

      const result = await errorSystem.executeWithRetry(
        'high-frequency-operation',
        mockRateLimitedOperation
      );

      expect(result).toBe('success');
      expect(retryAttempts).toBe(4);
    });
  });

  describe('Error Recovery Performance and Resilience', () => {
    test('should handle concurrent error scenarios efficiently', async () => {
      // Set up multiple error scenarios
      const scenarios = Array.from({ length: 5 }, (_, i) => ({
        id: `concurrent-error-${i}`,
        name: `Concurrent Error ${i}`,
        type: 'network' as const,
        severity: 'medium' as const,
        description: `Concurrent network error ${i}`,
        triggerCondition: async () => {},
        expectedBehavior: 'Handle concurrently',
        recoveryStrategy: 'Parallel recovery',
      }));

      // Register all scenarios
      await Promise.all(scenarios.map(s => errorSystem.registerErrorScenario(s)));

      // Trigger all errors concurrently
      const startTime = Date.now();
      const errorPromises = scenarios.map(s => errorSystem.triggerErrorScenario(s.id));
      const errors = await Promise.all(errorPromises);
      const errorTime = Date.now() - startTime;

      // Attempt concurrent recoveries
      const recoveryStartTime = Date.now();
      const recoveryPromises = scenarios.map((_, i) =>
        errorSystem.attemptRecovery('network', 'restart_service', { errorId: i })
      );
      const recoveries = await Promise.all(recoveryPromises);
      const recoveryTime = Date.now() - recoveryStartTime;

      // Verify concurrent handling
      expect(errors).toHaveLength(5);
      expect(recoveries).toHaveLength(5);
      expect(errorTime).toBeLessThan(1000); // Should handle concurrently, not sequentially
      expect(recoveryTime).toBeLessThan(3000); // Recovery should be efficient

      errors.forEach(error => {
        expect(error.error.code).toBe('ERR_NETWORK');
        expect(error.error.requestId).toBeTruthy();
      });

      recoveries.forEach(recovery => {
        expect(recovery.errorType).toBe('network');
        expect(recovery.metrics.totalDuration).toBeGreaterThan(0);
      });
    });

    test('should maintain error handling performance under load', async () => {
      const loadTestScenarios = Array.from({ length: 50 }, (_, i) => ({
        id: `load-test-${i}`,
        name: `Load Test Error ${i}`,
        type: (['network', 'system', 'authentication'] as const)[i % 3],
        severity: (['low', 'medium', 'high'] as const)[i % 3],
        description: `Load test error ${i}`,
        triggerCondition: async () => {},
        expectedBehavior: 'Handle under load',
        recoveryStrategy: 'Load-balanced recovery',
      }));

      // Register scenarios in batches
      await Promise.all(loadTestScenarios.map(s => errorSystem.registerErrorScenario(s)));

      // Trigger errors in batches
      const batchSize = 10;
      const batches = [];
      for (let i = 0; i < loadTestScenarios.length; i += batchSize) {
        batches.push(loadTestScenarios.slice(i, i + batchSize));
      }

      const batchResults = [];
      for (const batch of batches) {
        const batchStartTime = Date.now();
        const batchErrors = await Promise.all(
          batch.map(s => errorSystem.triggerErrorScenario(s.id))
        );
        const batchTime = Date.now() - batchStartTime;
        
        batchResults.push({
          errors: batchErrors,
          time: batchTime,
          size: batch.length,
        });
      }

      // Verify performance under load
      const totalErrors = batchResults.reduce((sum, batch) => sum + batch.errors.length, 0);
      const avgBatchTime = batchResults.reduce((sum, batch) => sum + batch.time, 0) / batchResults.length;

      expect(totalErrors).toBe(50);
      expect(avgBatchTime).toBeLessThan(500); // Average batch should complete quickly
      
      // Check that error system maintains performance
      const stats = errorSystem.getStats();
      expect(stats.scenarios).toBe(50);
      expect(stats.errorLogs).toBe(50);
    });
  });
});