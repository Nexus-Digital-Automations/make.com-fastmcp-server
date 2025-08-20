# Comprehensive Error Handling and Resilience Patterns for Production FastMCP Servers Integrating with Make.com

**Research Date**: 2025-08-20  
**Task ID**: task_1755667046202_lii141pb8  
**Research Scope**: FastMCP Error Handling Standards, Make.com Integration Resilience, Production Resilience Patterns, Error Monitoring & Observability

## Executive Summary

This comprehensive research provides production-ready error handling and resilience frameworks for FastMCP servers integrating with Make.com. The research was conducted using 10 concurrent specialized research agents covering all aspects of error handling, from FastMCP-specific patterns to industry-standard observability practices.

## Research Methodology

The research was conducted using concurrent specialized agents focusing on:
1. FastMCP Error Handling Standards
2. Make.com API Integration Resilience  
3. Circuit Breaker Pattern Implementation
4. Exponential Backoff and Retry Logic
5. Structured Logging and Correlation ID Systems
6. Error Analytics and Monitoring Integration
7. Health Check and Monitoring Endpoints
8. Graceful Degradation Strategies
9. API Platform Error Standards
10. Production Monitoring and Alerting

## 🔴 1. FastMCP Error Handling Standards

### UserError Implementation Patterns

FastMCP provides streamlined error handling that abstracts protocol complexities while maintaining robust error management capabilities.

#### Key Implementation Principles

**Built-in Error Management**
FastMCP automatically handles protocol-level errors, allowing developers to focus on business logic rather than protocol implementation details.

**Custom Exception Classes**
```typescript
class MakeAPIError extends Error {
  constructor(
    message: string, 
    public code: string, 
    public statusCode: number,
    public correlationId?: string
  ) {
    super(message);
    this.name = 'MakeAPIError';
    this.correlationId = correlationId || randomUUID();
  }
}

class MakeAuthenticationError extends MakeAPIError {
  constructor(message: string, correlationId?: string) {
    super(message, 'MAKE_AUTH_ERROR', 401, correlationId);
  }
}

class MakeRateLimitError extends MakeAPIError {
  constructor(message: string, public retryAfter: number, correlationId?: string) {
    super(message, 'MAKE_RATE_LIMIT', 429, correlationId);
  }
}
```

**Comprehensive Error Wrapping**
All tool functions should implement comprehensive error handling:

```typescript
async function executeMakeTool(operation: string, params: unknown): Promise<unknown> {
  const correlationId = randomUUID();
  const logger = createLogger({ operation, correlationId });
  
  try {
    logger.info('Starting Make.com API operation', { params });
    
    const result = await makeApiCall(operation, params);
    
    logger.info('Make.com API operation completed successfully');
    return result;
    
  } catch (error) {
    logger.error('Make.com API operation failed', { error: error.message });
    
    if (error instanceof ConnectionError) {
      throw new MakeAPIError(
        'Failed to connect to Make.com API',
        'CONNECTION_ERROR',
        502,
        correlationId
      );
    }
    
    if (error instanceof TimeoutError) {
      throw new MakeAPIError(
        'Make.com API request timed out',
        'TIMEOUT_ERROR',
        408,
        correlationId
      );
    }
    
    if (error.status === 401) {
      throw new MakeAuthenticationError(
        'Invalid Make.com API credentials',
        correlationId
      );
    }
    
    if (error.status === 429) {
      const retryAfter = error.headers['retry-after'] || 60;
      throw new MakeRateLimitError(
        'Make.com API rate limit exceeded',
        parseInt(retryAfter),
        correlationId
      );
    }
    
    // Generic error fallback
    throw new MakeAPIError(
      `Make.com API error: ${error.message}`,
      'UNKNOWN_ERROR',
      error.status || 500,
      correlationId
    );
  }
}
```

### Tool Execution Error Reporting

FastMCP tools should implement standardized error reporting:

```typescript
import { UserError } from '@fastmcp/core';

async function listScenarios(): Promise<string> {
  try {
    const scenarios = await executeMakeTool('scenarios', { limit: 100 });
    return JSON.stringify(scenarios, null, 2);
    
  } catch (error) {
    if (error instanceof MakeAPIError) {
      throw new UserError(
        `Failed to list scenarios: ${error.message}`,
        error.correlationId
      );
    }
    
    throw new UserError(
      'An unexpected error occurred while listing scenarios',
      error.correlationId || randomUUID()
    );
  }
}
```

### Client-Server Communication Error Recovery

FastMCP handles protocol-level communication errors automatically, but application-level recovery should be implemented:

```typescript
class FastMCPErrorRecovery {
  private static retryableOperations = new Set([
    'list-scenarios', 'get-scenario', 'list-connections'
  ]);
  
  static async withRecovery<T>(
    operation: string,
    fn: () => Promise<T>,
    maxRetries = 3
  ): Promise<T> {
    if (!this.retryableOperations.has(operation)) {
      return fn();
    }
    
    let lastError: Error;
    
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        return await fn();
      } catch (error) {
        lastError = error;
        
        if (attempt === maxRetries || !this.isRetryableError(error)) {
          break;
        }
        
        const delay = Math.min(1000 * Math.pow(2, attempt), 10000);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
    
    throw lastError;
  }
  
  private static isRetryableError(error: Error): boolean {
    if (error instanceof MakeAPIError) {
      return [408, 429, 500, 502, 503, 504].includes(error.statusCode);
    }
    return false;
  }
}
```

## 🌐 2. Make.com Integration Resilience

### Webhook Delivery Failure Handling

Make.com's webhook system requires robust failure handling due to its current limitations and architectural constraints.

#### Break Error Handler Implementation

The Break Error Handler is Make.com's primary mechanism for handling temporary failures:

```typescript
interface MakeWebhookConfig {
  breakErrorHandler: {
    enabled: true,
    retryCount: 3,
    retryInterval: 300000, // 5 minutes
    fallbackAction: 'queue' | 'discard' | 'notify'
  }
}

class MakeWebhookHandler {
  async handleWebhook(data: unknown): Promise<void> {
    const correlationId = randomUUID();
    const logger = createLogger({ component: 'WebhookHandler', correlationId });
    
    try {
      await this.processWebhookData(data);
      logger.info('Webhook processed successfully');
      
    } catch (error) {
      logger.error('Webhook processing failed', { error: error.message });
      
      if (this.isRetryableError(error)) {
        throw new MakeAPIError(
          'Temporary webhook processing failure - will retry',
          'WEBHOOK_RETRY',
          502,
          correlationId
        );
      }
      
      // Non-retryable error - log and discard
      logger.error('Non-retryable webhook error - discarding', {
        error: error.message,
        data: JSON.stringify(data).substring(0, 1000)
      });
    }
  }
  
  private isRetryableError(error: Error): boolean {
    // Network-related errors that can be retried
    if (error.code === 'ECONNRESET' || error.code === 'ETIMEDOUT') {
      return true;
    }
    
    // Server errors that might be temporary
    if (error instanceof MakeAPIError) {
      return [429, 500, 502, 503, 504].includes(error.statusCode);
    }
    
    return false;
  }
}
```

#### Webhook Retry Strategies

Due to Make.com's limitations with the "Throw" directive, implement custom retry logic:

```typescript
class MakeWebhookRetryManager {
  private retryQueue: Array<{
    id: string;
    data: unknown;
    attempts: number;
    nextRetry: Date;
    correlationId: string;
  }> = [];
  
  async enqueueForRetry(data: unknown, correlationId: string): Promise<void> {
    const retryItem = {
      id: randomUUID(),
      data,
      attempts: 0,
      nextRetry: new Date(Date.now() + 30000), // 30 seconds
      correlationId
    };
    
    this.retryQueue.push(retryItem);
    logger.info('Webhook queued for retry', { 
      retryId: retryItem.id,
      correlationId 
    });
  }
  
  async processRetryQueue(): Promise<void> {
    const now = new Date();
    const readyToRetry = this.retryQueue.filter(item => item.nextRetry <= now);
    
    for (const item of readyToRetry) {
      try {
        await this.retryWebhook(item);
        this.removeFromQueue(item.id);
        
      } catch (error) {
        await this.handleRetryFailure(item, error);
      }
    }
  }
  
  private async handleRetryFailure(item: any, error: Error): Promise<void> {
    item.attempts++;
    
    if (item.attempts >= 5) {
      logger.error('Webhook retry exhausted', {
        retryId: item.id,
        correlationId: item.correlationId,
        finalError: error.message
      });
      this.removeFromQueue(item.id);
      return;
    }
    
    // Exponential backoff
    const backoffMs = Math.min(30000 * Math.pow(2, item.attempts), 1800000); // Max 30 min
    item.nextRetry = new Date(Date.now() + backoffMs);
    
    logger.warn('Webhook retry failed, scheduling next attempt', {
      retryId: item.id,
      attempts: item.attempts,
      nextRetry: item.nextRetry
    });
  }
}
```

### API Timeout and Retry Strategies

Implement comprehensive timeout and retry mechanisms for Make.com API calls:

```typescript
interface MakeAPIRetryConfig {
  maxRetries: number;
  baseDelay: number;
  maxDelay: number;
  timeoutMs: number;
  retryableStatusCodes: number[];
}

class MakeAPIClient {
  private config: MakeAPIRetryConfig = {
    maxRetries: 3,
    baseDelay: 1000,
    maxDelay: 30000,
    timeoutMs: 30000,
    retryableStatusCodes: [408, 429, 500, 502, 503, 504]
  };
  
  async makeRequest<T>(
    endpoint: string,
    options: RequestOptions
  ): Promise<T> {
    const correlationId = options.correlationId || randomUUID();
    
    return retryWithBackoff(
      async () => {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.config.timeoutMs);
        
        try {
          const response = await fetch(`https://api.make.com/v2/${endpoint}`, {
            ...options,
            signal: controller.signal,
            headers: {
              'Authorization': `Bearer ${this.apiKey}`,
              'X-Correlation-ID': correlationId,
              ...options.headers
            }
          });
          
          clearTimeout(timeoutId);
          
          if (!response.ok) {
            throw new MakeAPIError(
              `Make.com API error: ${response.statusText}`,
              'API_ERROR',
              response.status,
              correlationId
            );
          }
          
          return response.json();
          
        } catch (error) {
          clearTimeout(timeoutId);
          
          if (error.name === 'AbortError') {
            throw new MakeAPIError(
              'Make.com API request timed out',
              'TIMEOUT',
              408,
              correlationId
            );
          }
          
          throw error;
        }
      },
      {
        maxRetries: this.config.maxRetries,
        baseDelay: this.config.baseDelay,
        maxDelay: this.config.maxDelay,
        retryCondition: (error) => this.isRetryableError(error)
      },
      correlationId
    );
  }
  
  private isRetryableError(error: Error): boolean {
    if (error instanceof MakeAPIError) {
      return this.config.retryableStatusCodes.includes(error.statusCode);
    }
    
    // Network errors
    if (error.code === 'ECONNRESET' || error.code === 'ETIMEDOUT') {
      return true;
    }
    
    return false;
  }
}
```

### Data Synchronization Error Recovery

Implement robust data synchronization with conflict resolution:

```typescript
class MakeDataSyncManager {
  async syncScenarios(scenarios: Scenario[]): Promise<SyncResult> {
    const correlationId = randomUUID();
    const syncResults: SyncResult = {
      successful: [],
      failed: [],
      conflicts: [],
      correlationId
    };
    
    for (const scenario of scenarios) {
      try {
        const result = await this.syncSingleScenario(scenario, correlationId);
        syncResults.successful.push(result);
        
      } catch (error) {
        if (error instanceof MakeAPIError && error.statusCode === 409) {
          // Conflict detected
          const conflict = await this.handleSyncConflict(scenario, error);
          syncResults.conflicts.push(conflict);
        } else {
          syncResults.failed.push({
            scenarioId: scenario.id,
            error: error.message,
            correlationId
          });
        }
      }
    }
    
    return syncResults;
  }
  
  private async handleSyncConflict(
    scenario: Scenario,
    conflictError: MakeAPIError
  ): Promise<ConflictResolution> {
    // Fetch current server state
    const serverScenario = await this.fetchScenario(scenario.id);
    
    // Apply conflict resolution strategy
    const resolution = this.resolveConflict(scenario, serverScenario);
    
    switch (resolution.strategy) {
      case 'client-wins':
        return this.forceSyncScenario(scenario);
      
      case 'server-wins':
        return { ...resolution, resolvedScenario: serverScenario };
      
      case 'merge':
        const merged = this.mergeScenarios(scenario, serverScenario);
        return this.syncSingleScenario(merged);
      
      default:
        throw new MakeAPIError(
          'Unable to resolve sync conflict',
          'SYNC_CONFLICT',
          409
        );
    }
  }
}
```

## 🏗️ 3. Production Resilience Patterns

### Circuit Breaker Implementation

Circuit breakers prevent cascade failures and provide fast failure responses:

```typescript
interface CircuitBreakerMetrics {
  requestCount: number;
  successCount: number;
  failureCount: number;
  consecutiveFailures: number;
  lastFailureTime?: Date;
  lastSuccessTime?: Date;
  stateChanges: Array<{
    from: CircuitBreakerState;
    to: CircuitBreakerState;
    timestamp: Date;
    reason: string;
  }>;
}

class AdvancedCircuitBreaker {
  private metrics: CircuitBreakerMetrics = {
    requestCount: 0,
    successCount: 0,
    failureCount: 0,
    consecutiveFailures: 0,
    stateChanges: []
  };
  
  constructor(
    private name: string,
    private options: CircuitBreakerOptions
  ) {}
  
  async execute<T>(
    operation: () => Promise<T>,
    context?: { correlationId?: string; operation?: string }
  ): Promise<T> {
    const correlationId = context?.correlationId || randomUUID();
    const logger = createLogger({ 
      component: 'CircuitBreaker',
      circuitName: this.name,
      correlationId 
    });
    
    this.metrics.requestCount++;
    
    if (this.state === 'OPEN') {
      if (Date.now() < this.nextAttempt) {
        logger.warn('Circuit breaker is OPEN - request blocked', {
          nextAttempt: new Date(this.nextAttempt),
          consecutiveFailures: this.metrics.consecutiveFailures
        });
        
        throw new CircuitBreakerError(
          `Circuit breaker '${this.name}' is OPEN`,
          this.name,
          this.getMetrics()
        );
      } else {
        this.changeState('HALF_OPEN', 'Reset timeout reached');
      }
    }
    
    const startTime = Date.now();
    
    try {
      const result = await Promise.race([
        operation(),
        this.createTimeoutPromise()
      ]);
      
      const duration = Date.now() - startTime;
      this.onSuccess(duration);
      
      logger.info('Circuit breaker operation succeeded', {
        duration,
        state: this.state
      });
      
      return result;
      
    } catch (error) {
      const duration = Date.now() - startTime;
      this.onFailure(error, duration);
      
      logger.error('Circuit breaker operation failed', {
        error: error.message,
        duration,
        state: this.state,
        consecutiveFailures: this.metrics.consecutiveFailures
      });
      
      throw error;
    }
  }
  
  private onSuccess(duration: number): void {
    this.metrics.successCount++;
    this.metrics.consecutiveFailures = 0;
    this.metrics.lastSuccessTime = new Date();
    
    if (this.state === 'HALF_OPEN') {
      this.successCount++;
      if (this.successCount >= this.options.successThreshold) {
        this.changeState('CLOSED', 'Success threshold reached');
        this.successCount = 0;
      }
    }
  }
  
  private onFailure(error: Error, duration: number): void {
    this.metrics.failureCount++;
    this.metrics.consecutiveFailures++;
    this.metrics.lastFailureTime = new Date();
    
    if (this.metrics.consecutiveFailures >= this.options.failureThreshold) {
      this.changeState('OPEN', `Failure threshold reached (${this.metrics.consecutiveFailures})`);
      this.nextAttempt = Date.now() + this.options.resetTimeout;
    }
  }
  
  private changeState(newState: CircuitBreakerState, reason: string): void {
    const oldState = this.state;
    this.state = newState;
    
    this.metrics.stateChanges.push({
      from: oldState,
      to: newState,
      timestamp: new Date(),
      reason
    });
    
    // Keep only recent state changes
    if (this.metrics.stateChanges.length > 100) {
      this.metrics.stateChanges = this.metrics.stateChanges.slice(-100);
    }
    
    logger.info('Circuit breaker state changed', {
      from: oldState,
      to: newState,
      reason,
      metrics: this.getMetrics()
    });
  }
  
  getMetrics(): CircuitBreakerMetrics & { state: CircuitBreakerState } {
    return {
      ...this.metrics,
      state: this.state
    };
  }
}
```

### Graceful Degradation Strategies

Implement progressive degradation based on system health:

```typescript
interface DegradationLevel {
  level: 'normal' | 'degraded' | 'minimal' | 'emergency';
  disabledFeatures: string[];
  maxConcurrency: number;
  cacheOnly: boolean;
  readOnly: boolean;
}

class GracefulDegradationManager {
  private currentLevel: DegradationLevel = {
    level: 'normal',
    disabledFeatures: [],
    maxConcurrency: 100,
    cacheOnly: false,
    readOnly: false
  };
  
  private healthChecks = new Map<string, () => Promise<boolean>>();
  
  async evaluateDegradationLevel(): Promise<DegradationLevel> {
    const healthResults = await this.runHealthChecks();
    const healthyServices = healthResults.filter(r => r.healthy).length;
    const totalServices = healthResults.length;
    const healthPercentage = totalServices > 0 ? healthyServices / totalServices : 1;
    
    if (healthPercentage >= 0.9) {
      return this.setDegradationLevel('normal');
    } else if (healthPercentage >= 0.7) {
      return this.setDegradationLevel('degraded');
    } else if (healthPercentage >= 0.5) {
      return this.setDegradationLevel('minimal');
    } else {
      return this.setDegradationLevel('emergency');
    }
  }
  
  private setDegradationLevel(level: DegradationLevel['level']): DegradationLevel {
    const newLevel: DegradationLevel = this.getDegradationConfig(level);
    
    if (newLevel.level !== this.currentLevel.level) {
      logger.warn('System degradation level changed', {
        from: this.currentLevel.level,
        to: newLevel.level,
        disabledFeatures: newLevel.disabledFeatures
      });
      
      this.currentLevel = newLevel;
      this.notifyDegradationChange(newLevel);
    }
    
    return this.currentLevel;
  }
  
  private getDegradationConfig(level: DegradationLevel['level']): DegradationLevel {
    switch (level) {
      case 'normal':
        return {
          level: 'normal',
          disabledFeatures: [],
          maxConcurrency: 100,
          cacheOnly: false,
          readOnly: false
        };
      
      case 'degraded':
        return {
          level: 'degraded',
          disabledFeatures: ['analytics', 'notifications', 'exports'],
          maxConcurrency: 50,
          cacheOnly: false,
          readOnly: false
        };
      
      case 'minimal':
        return {
          level: 'minimal',
          disabledFeatures: ['analytics', 'notifications', 'exports', 'search', 'bulk-operations'],
          maxConcurrency: 20,
          cacheOnly: true,
          readOnly: false
        };
      
      case 'emergency':
        return {
          level: 'emergency',
          disabledFeatures: ['analytics', 'notifications', 'exports', 'search', 'bulk-operations', 'writes'],
          maxConcurrency: 5,
          cacheOnly: true,
          readOnly: true
        };
    }
  }
  
  isFeatureEnabled(featureName: string): boolean {
    return !this.currentLevel.disabledFeatures.includes(featureName);
  }
  
  checkWriteOperations(): void {
    if (this.currentLevel.readOnly) {
      throw new MakeAPIError(
        'System is in read-only mode due to degraded performance',
        'READ_ONLY_MODE',
        503
      );
    }
  }
}
```

### Health Check and Monitoring Endpoints

Comprehensive health monitoring with dependency validation:

```typescript
interface HealthCheckResult {
  name: string;
  status: 'pass' | 'warn' | 'fail';
  responseTime: number;
  message: string;
  details?: Record<string, unknown>;
  lastSuccess?: Date;
  consecutiveFailures?: number;
}

class ComprehensiveHealthMonitor {
  private checks = new Map<string, HealthCheck>();
  private cache = new Map<string, { result: HealthCheckResult; timestamp: number }>();
  private readonly cacheMaxAge = 30000; // 30 seconds
  
  addCheck(name: string, check: HealthCheck): void {
    this.checks.set(name, check);
  }
  
  async performHealthCheck(
    includeDetails = false,
    timeout = 5000
  ): Promise<{
    status: 'healthy' | 'degraded' | 'unhealthy';
    timestamp: string;
    checks: HealthCheckResult[];
    summary: {
      total: number;
      passed: number;
      warned: number;
      failed: number;
    };
    uptime: number;
    version: string;
  }> {
    const checkPromises = Array.from(this.checks.entries()).map(
      async ([name, check]) => {
        try {
          return await this.executeHealthCheck(name, check, timeout);
        } catch (error) {
          return {
            name,
            status: 'fail' as const,
            responseTime: timeout,
            message: `Health check failed: ${error.message}`,
            details: includeDetails ? { error: error.message } : undefined
          };
        }
      }
    );
    
    const results = await Promise.all(checkPromises);
    
    const summary = {
      total: results.length,
      passed: results.filter(r => r.status === 'pass').length,
      warned: results.filter(r => r.status === 'warn').length,
      failed: results.filter(r => r.status === 'fail').length
    };
    
    let overallStatus: 'healthy' | 'degraded' | 'unhealthy';
    if (summary.failed > 0) {
      overallStatus = 'unhealthy';
    } else if (summary.warned > 0) {
      overallStatus = 'degraded';
    } else {
      overallStatus = 'healthy';
    }
    
    return {
      status: overallStatus,
      timestamp: new Date().toISOString(),
      checks: results,
      summary,
      uptime: process.uptime(),
      version: process.env.npm_package_version || '1.0.0'
    };
  }
  
  private async executeHealthCheck(
    name: string,
    check: HealthCheck,
    timeout: number
  ): Promise<HealthCheckResult> {
    // Check cache first
    const cached = this.cache.get(name);
    if (cached && Date.now() - cached.timestamp < this.cacheMaxAge) {
      return cached.result;
    }
    
    const startTime = Date.now();
    
    try {
      const result = await Promise.race([
        check.execute(),
        new Promise<never>((_, reject) => 
          setTimeout(() => reject(new Error('Health check timeout')), timeout)
        )
      ]);
      
      const responseTime = Date.now() - startTime;
      const healthResult: HealthCheckResult = {
        name,
        status: result.status || 'pass',
        responseTime,
        message: result.message || 'Health check passed',
        details: result.details,
        lastSuccess: result.status === 'pass' ? new Date() : undefined
      };
      
      // Cache the result
      this.cache.set(name, { result: healthResult, timestamp: Date.now() });
      
      return healthResult;
      
    } catch (error) {
      const responseTime = Date.now() - startTime;
      const healthResult: HealthCheckResult = {
        name,
        status: 'fail',
        responseTime,
        message: `Health check failed: ${error.message}`,
        consecutiveFailures: (cached?.result.consecutiveFailures || 0) + 1
      };
      
      this.cache.set(name, { result: healthResult, timestamp: Date.now() });
      
      return healthResult;
    }
  }
  
  // Specific health checks for Make.com integration
  createMakeAPIHealthCheck(): HealthCheck {
    return {
      async execute(): Promise<{ status: string; message: string; details?: unknown }> {
        try {
          const response = await fetch('https://api.make.com/v2/organizations', {
            method: 'GET',
            headers: {
              'Authorization': `Bearer ${process.env.MAKE_API_KEY}`,
              'User-Agent': 'FastMCP-HealthCheck/1.0'
            },
            signal: AbortSignal.timeout(3000)
          });
          
          if (response.ok) {
            return {
              status: 'pass',
              message: 'Make.com API is accessible',
              details: { statusCode: response.status }
            };
          } else {
            return {
              status: 'warn',
              message: `Make.com API returned ${response.status}`,
              details: { statusCode: response.status, statusText: response.statusText }
            };
          }
          
        } catch (error) {
          return {
            status: 'fail',
            message: `Make.com API unreachable: ${error.message}`,
            details: { error: error.message }
          };
        }
      }
    };
  }
  
  createDatabaseHealthCheck(): HealthCheck {
    return {
      async execute(): Promise<{ status: string; message: string; details?: unknown }> {
        try {
          // Example database ping
          const startTime = Date.now();
          const result = await db.raw('SELECT 1 as health_check');
          const queryTime = Date.now() - startTime;
          
          if (result && result.length > 0) {
            return {
              status: queryTime < 1000 ? 'pass' : 'warn',
              message: `Database responsive in ${queryTime}ms`,
              details: { queryTime, result: result[0] }
            };
          } else {
            return {
              status: 'fail',
              message: 'Database query returned no results'
            };
          }
          
        } catch (error) {
          return {
            status: 'fail',
            message: `Database health check failed: ${error.message}`,
            details: { error: error.message }
          };
        }
      }
    };
  }
}
```

## 📊 4. Error Monitoring & Observability

### Structured Logging and Correlation IDs

Implement comprehensive logging with correlation tracking:

```typescript
interface LogContext {
  correlationId: string;
  traceId?: string;
  spanId?: string;
  component: string;
  operation: string;
  userId?: string;
  sessionId?: string;
  requestId?: string;
  metadata?: Record<string, unknown>;
}

class StructuredLogger {
  private static instance: StructuredLogger;
  private logger: winston.Logger;
  
  private constructor() {
    this.logger = winston.createLogger({
      level: process.env.LOG_LEVEL || 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json(),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
          const logEntry = {
            timestamp,
            level: level.toUpperCase(),
            message,
            ...meta
          };
          
          // Mask sensitive data
          return JSON.stringify(this.maskSensitiveData(logEntry));
        })
      ),
      transports: [
        new winston.transports.Console(),
        new winston.transports.File({ 
          filename: 'logs/error.log', 
          level: 'error',
          maxsize: 10485760, // 10MB
          maxFiles: 5
        }),
        new winston.transports.File({ 
          filename: 'logs/combined.log',
          maxsize: 10485760,
          maxFiles: 5
        })
      ]
    });
  }
  
  static getInstance(): StructuredLogger {
    if (!StructuredLogger.instance) {
      StructuredLogger.instance = new StructuredLogger();
    }
    return StructuredLogger.instance;
  }
  
  createLogger(context: Partial<LogContext>): LoggerInstance {
    const correlationId = context.correlationId || randomUUID();
    
    return {
      info: (message: string, data?: unknown) => {
        this.log('info', message, { ...context, correlationId, data });
      },
      
      warn: (message: string, data?: unknown) => {
        this.log('warn', message, { ...context, correlationId, data });
      },
      
      error: (message: string, error?: Error | unknown, data?: unknown) => {
        const errorInfo = error instanceof Error ? {
          errorName: error.name,
          errorMessage: error.message,
          errorStack: error.stack
        } : { error };
        
        this.log('error', message, { ...context, correlationId, ...errorInfo, data });
      },
      
      debug: (message: string, data?: unknown) => {
        this.log('debug', message, { ...context, correlationId, data });
      },
      
      child: (additionalContext: Partial<LogContext>) => {
        return this.createLogger({ ...context, ...additionalContext });
      }
    };
  }
  
  private log(level: string, message: string, context: LogContext & { data?: unknown }): void {
    this.logger.log(level, message, {
      correlationId: context.correlationId,
      traceId: context.traceId,
      spanId: context.spanId,
      component: context.component,
      operation: context.operation,
      userId: context.userId,
      sessionId: context.sessionId,
      requestId: context.requestId,
      metadata: context.metadata,
      data: context.data
    });
  }
  
  private maskSensitiveData(obj: any): any {
    const sensitiveKeys = [
      'password', 'token', 'secret', 'key', 'auth', 'authorization',
      'apiKey', 'api_key', 'accessToken', 'access_token', 'refreshToken'
    ];
    
    if (typeof obj !== 'object' || obj === null) {
      return obj;
    }
    
    if (Array.isArray(obj)) {
      return obj.map(item => this.maskSensitiveData(item));
    }
    
    const masked = { ...obj };
    
    for (const key in masked) {
      if (sensitiveKeys.some(sensitive => 
          key.toLowerCase().includes(sensitive.toLowerCase()))) {
        masked[key] = '[REDACTED]';
      } else if (typeof masked[key] === 'object') {
        masked[key] = this.maskSensitiveData(masked[key]);
      }
    }
    
    return masked;
  }
}
```

### Metrics Collection and Analysis

Implement comprehensive metrics collection with Prometheus integration:

```typescript
interface MetricsCollector {
  // Counter metrics
  requestsTotal: prometheus.Counter<string>;
  errorsTotal: prometheus.Counter<string>;
  toolExecutionsTotal: prometheus.Counter<string>;
  
  // Histogram metrics
  requestDuration: prometheus.Histogram<string>;
  toolExecutionDuration: prometheus.Histogram<string>;
  makeApiCallDuration: prometheus.Histogram<string>;
  
  // Gauge metrics
  activeConnections: prometheus.Gauge<string>;
  memoryUsage: prometheus.Gauge<string>;
  cpuUsage: prometheus.Gauge<string>;
  circuitBreakerState: prometheus.Gauge<string>;
}

class ComprehensiveMetrics {
  private static instance: ComprehensiveMetrics;
  private registry: prometheus.Registry;
  private metrics: MetricsCollector;
  
  private constructor() {
    this.registry = new prometheus.Registry();
    this.initializeMetrics();
    this.startSystemMetricsCollection();
  }
  
  static getInstance(): ComprehensiveMetrics {
    if (!ComprehensiveMetrics.instance) {
      ComprehensiveMetrics.instance = new ComprehensiveMetrics();
    }
    return ComprehensiveMetrics.instance;
  }
  
  private initializeMetrics(): void {
    // Request metrics
    this.metrics.requestsTotal = new prometheus.Counter({
      name: 'fastmcp_requests_total',
      help: 'Total number of requests',
      labelNames: ['method', 'endpoint', 'status', 'user_id'],
      registers: [this.registry]
    });
    
    this.metrics.errorsTotal = new prometheus.Counter({
      name: 'fastmcp_errors_total',
      help: 'Total number of errors',
      labelNames: ['error_code', 'component', 'operation', 'severity'],
      registers: [this.registry]
    });
    
    this.metrics.toolExecutionsTotal = new prometheus.Counter({
      name: 'fastmcp_tool_executions_total',
      help: 'Total number of tool executions',
      labelNames: ['tool_name', 'status', 'user_id'],
      registers: [this.registry]
    });
    
    // Duration metrics
    this.metrics.requestDuration = new prometheus.Histogram({
      name: 'fastmcp_request_duration_seconds',
      help: 'Request duration in seconds',
      labelNames: ['method', 'endpoint', 'status'],
      buckets: [0.1, 0.5, 1, 2, 5, 10, 30],
      registers: [this.registry]
    });
    
    this.metrics.toolExecutionDuration = new prometheus.Histogram({
      name: 'fastmcp_tool_execution_duration_seconds',
      help: 'Tool execution duration in seconds',
      labelNames: ['tool_name', 'status'],
      buckets: [0.1, 0.5, 1, 2, 5, 10, 30, 60],
      registers: [this.registry]
    });
    
    this.metrics.makeApiCallDuration = new prometheus.Histogram({
      name: 'fastmcp_make_api_call_duration_seconds',
      help: 'Make.com API call duration in seconds',
      labelNames: ['endpoint', 'method', 'status'],
      buckets: [0.1, 0.5, 1, 2, 5, 10, 30],
      registers: [this.registry]
    });
    
    // System metrics
    this.metrics.activeConnections = new prometheus.Gauge({
      name: 'fastmcp_active_connections',
      help: 'Number of active connections',
      registers: [this.registry]
    });
    
    this.metrics.memoryUsage = new prometheus.Gauge({
      name: 'fastmcp_memory_usage_bytes',
      help: 'Memory usage in bytes',
      labelNames: ['type'],
      registers: [this.registry]
    });
    
    this.metrics.cpuUsage = new prometheus.Gauge({
      name: 'fastmcp_cpu_usage_ratio',
      help: 'CPU usage ratio',
      registers: [this.registry]
    });
    
    this.metrics.circuitBreakerState = new prometheus.Gauge({
      name: 'fastmcp_circuit_breaker_state',
      help: 'Circuit breaker state (0=closed, 1=half-open, 2=open)',
      labelNames: ['circuit_name'],
      registers: [this.registry]
    });
  }
  
  // Metric recording methods
  recordRequest(method: string, endpoint: string, status: string, duration: number, userId?: string): void {
    this.metrics.requestsTotal.inc({ method, endpoint, status, user_id: userId || 'anonymous' });
    this.metrics.requestDuration.observe({ method, endpoint, status }, duration);
  }
  
  recordError(errorCode: string, component: string, operation: string, severity: string): void {
    this.metrics.errorsTotal.inc({ error_code: errorCode, component, operation, severity });
  }
  
  recordToolExecution(toolName: string, status: string, duration: number, userId?: string): void {
    this.metrics.toolExecutionsTotal.inc({ tool_name: toolName, status, user_id: userId || 'anonymous' });
    this.metrics.toolExecutionDuration.observe({ tool_name: toolName, status }, duration);
  }
  
  recordMakeApiCall(endpoint: string, method: string, status: string, duration: number): void {
    this.metrics.makeApiCallDuration.observe({ endpoint, method, status }, duration);
  }
  
  updateCircuitBreakerState(circuitName: string, state: CircuitBreakerState): void {
    const stateValue = state === 'CLOSED' ? 0 : state === 'HALF_OPEN' ? 1 : 2;
    this.metrics.circuitBreakerState.set({ circuit_name: circuitName }, stateValue);
  }
  
  updateActiveConnections(count: number): void {
    this.metrics.activeConnections.set(count);
  }
  
  private startSystemMetricsCollection(): void {
    setInterval(() => {
      const memoryUsage = process.memoryUsage();
      this.metrics.memoryUsage.set({ type: 'heap_used' }, memoryUsage.heapUsed);
      this.metrics.memoryUsage.set({ type: 'heap_total' }, memoryUsage.heapTotal);
      this.metrics.memoryUsage.set({ type: 'rss' }, memoryUsage.rss);
      this.metrics.memoryUsage.set({ type: 'external' }, memoryUsage.external);
      
      const cpuUsage = process.cpuUsage();
      const cpuPercent = (cpuUsage.user + cpuUsage.system) / 1000000; // Convert to seconds
      this.metrics.cpuUsage.set(cpuPercent);
    }, 10000); // Every 10 seconds
  }
  
  getMetrics(): string {
    return this.registry.metrics();
  }
  
  getRegistry(): prometheus.Registry {
    return this.registry;
  }
}
```

### Error Analytics and Pattern Recognition

Advanced error analytics with pattern recognition and trend analysis:

```typescript
interface ErrorPattern {
  signature: string;
  count: number;
  firstSeen: Date;
  lastSeen: Date;
  affectedComponents: Set<string>;
  affectedUsers: Set<string>;
  correlatedErrors: string[];
  resolutionHistory: Array<{
    timestamp: Date;
    resolution: string;
    duration: number;
  }>;
}

class AdvancedErrorAnalytics {
  private patterns = new Map<string, ErrorPattern>();
  private errorEvents: ErrorEvent[] = [];
  private correlationWindows = new Map<string, ErrorEvent[]>();
  private readonly maxPatterns = 1000;
  private readonly maxEvents = 10000;
  private readonly correlationWindowMs = 300000; // 5 minutes
  
  recordError(error: Error | MakeServerError, context: ErrorContext): void {
    const errorEvent: ErrorEvent = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      correlationId: context.correlationId || randomUUID(),
      code: error instanceof MakeServerError ? error.code : 'UNKNOWN_ERROR',
      message: error.message,
      statusCode: error instanceof MakeServerError ? error.statusCode : 500,
      component: context.component,
      operation: context.operation,
      userId: context.userId,
      sessionId: context.sessionId,
      context,
      resolved: false
    };
    
    this.errorEvents.push(errorEvent);
    this.updateErrorPatterns(errorEvent);
    this.detectCorrelations(errorEvent);
    
    // Cleanup old events
    if (this.errorEvents.length > this.maxEvents) {
      this.errorEvents = this.errorEvents.slice(-this.maxEvents);
    }
  }
  
  private updateErrorPatterns(errorEvent: ErrorEvent): void {
    const signature = this.generateErrorSignature(errorEvent);
    
    if (!this.patterns.has(signature)) {
      this.patterns.set(signature, {
        signature,
        count: 0,
        firstSeen: new Date(errorEvent.timestamp),
        lastSeen: new Date(errorEvent.timestamp),
        affectedComponents: new Set(),
        affectedUsers: new Set(),
        correlatedErrors: [],
        resolutionHistory: []
      });
    }
    
    const pattern = this.patterns.get(signature)!;
    pattern.count++;
    pattern.lastSeen = new Date(errorEvent.timestamp);
    
    if (errorEvent.component) {
      pattern.affectedComponents.add(errorEvent.component);
    }
    
    if (errorEvent.userId) {
      pattern.affectedUsers.add(errorEvent.userId);
    }
    
    // Cleanup old patterns
    if (this.patterns.size > this.maxPatterns) {
      const oldestPattern = Array.from(this.patterns.entries())
        .sort(([, a], [, b]) => a.lastSeen.getTime() - b.lastSeen.getTime())[0];
      this.patterns.delete(oldestPattern[0]);
    }
  }
  
  private generateErrorSignature(errorEvent: ErrorEvent): string {
    // Create normalized signature for pattern matching
    const normalizedMessage = errorEvent.message
      .replace(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/g, 'TIMESTAMP')
      .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, 'UUID')
      .replace(/\b\d+\b/g, 'NUMBER')
      .replace(/\/[\w\-._]+\//g, '/PATH/')
      .replace(/user_\w+/g, 'USER_ID')
      .replace(/session_\w+/g, 'SESSION_ID');
    
    return `${errorEvent.code}:${errorEvent.component}:${normalizedMessage}`;
  }
  
  private detectCorrelations(errorEvent: ErrorEvent): void {
    const windowKey = this.getCorrelationWindowKey(errorEvent.timestamp);
    
    if (!this.correlationWindows.has(windowKey)) {
      this.correlationWindows.set(windowKey, []);
    }
    
    const windowEvents = this.correlationWindows.get(windowKey)!;
    windowEvents.push(errorEvent);
    
    // Look for correlations within the window
    if (windowEvents.length >= 2) {
      this.analyzeCorrelations(windowEvents);
    }
    
    // Cleanup old windows
    const cutoffTime = Date.now() - this.correlationWindowMs * 2;
    for (const [key, events] of this.correlationWindows) {
      const windowTime = new Date(events[0]?.timestamp).getTime();
      if (windowTime < cutoffTime) {
        this.correlationWindows.delete(key);
      }
    }
  }
  
  private analyzeCorrelations(events: ErrorEvent[]): void {
    // Group events by various attributes to find correlations
    const correlations = {
      byUser: this.groupBy(events, 'userId'),
      byComponent: this.groupBy(events, 'component'),
      byOperation: this.groupBy(events, 'operation'),
      bySession: this.groupBy(events, 'sessionId')
    };
    
    // Update pattern correlations
    for (const [attribute, groups] of Object.entries(correlations)) {
      for (const [key, groupEvents] of Object.entries(groups)) {
        if (groupEvents.length >= 2) {
          this.updatePatternCorrelations(groupEvents);
        }
      }
    }
  }
  
  private updatePatternCorrelations(correlatedEvents: ErrorEvent[]): void {
    const signatures = correlatedEvents.map(e => this.generateErrorSignature(e));
    
    for (const signature of signatures) {
      const pattern = this.patterns.get(signature);
      if (pattern) {
        const otherSignatures = signatures.filter(s => s !== signature);
        pattern.correlatedErrors.push(...otherSignatures);
        
        // Keep only unique correlations and limit size
        pattern.correlatedErrors = [...new Set(pattern.correlatedErrors)].slice(-20);
      }
    }
  }
  
  getErrorTrends(timeRangeHours = 24): {
    timeline: Array<{ hour: string; errorCount: number; errorRate: number }>;
    topPatterns: Array<{
      signature: string;
      count: number;
      trend: 'increasing' | 'stable' | 'decreasing';
      severity: 'low' | 'medium' | 'high' | 'critical';
    }>;
    correlationInsights: Array<{
      primaryError: string;
      correlatedErrors: string[];
      strength: number;
      occurrences: number;
    }>;
  } {
    const now = Date.now();
    const timeRangeMs = timeRangeHours * 3600000;
    const relevantEvents = this.errorEvents.filter(
      e => now - new Date(e.timestamp).getTime() < timeRangeMs
    );
    
    // Generate timeline
    const timeline = this.generateTimeline(relevantEvents, timeRangeHours);
    
    // Analyze top patterns
    const topPatterns = this.analyzeTopPatterns(relevantEvents);
    
    // Generate correlation insights
    const correlationInsights = this.generateCorrelationInsights();
    
    return { timeline, topPatterns, correlationInsights };
  }
  
  private generateTimeline(events: ErrorEvent[], hours: number): Array<{ hour: string; errorCount: number; errorRate: number }> {
    const timeline: Array<{ hour: string; errorCount: number; errorRate: number }> = [];
    const hourMs = 3600000;
    const now = Date.now();
    
    for (let i = hours - 1; i >= 0; i--) {
      const hourStart = now - (i * hourMs);
      const hourEnd = hourStart + hourMs;
      const hourKey = new Date(hourStart).toISOString().substring(0, 13) + ':00:00.000Z';
      
      const hourEvents = events.filter(e => {
        const eventTime = new Date(e.timestamp).getTime();
        return eventTime >= hourStart && eventTime < hourEnd;
      });
      
      timeline.push({
        hour: hourKey,
        errorCount: hourEvents.length,
        errorRate: hourEvents.length / 3600 // errors per second
      });
    }
    
    return timeline;
  }
  
  private analyzeTopPatterns(events: ErrorEvent[]): Array<{
    signature: string;
    count: number;
    trend: 'increasing' | 'stable' | 'decreasing';
    severity: 'low' | 'medium' | 'high' | 'critical';
  }> {
    const patternCounts = new Map<string, number>();
    
    events.forEach(event => {
      const signature = this.generateErrorSignature(event);
      patternCounts.set(signature, (patternCounts.get(signature) || 0) + 1);
    });
    
    return Array.from(patternCounts.entries())
      .map(([signature, count]) => {
        const pattern = this.patterns.get(signature);
        return {
          signature,
          count,
          trend: this.calculateTrend(signature, events),
          severity: this.calculateSeverity(count, pattern)
        };
      })
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }
  
  private calculateTrend(signature: string, recentEvents: ErrorEvent[]): 'increasing' | 'stable' | 'decreasing' {
    const pattern = this.patterns.get(signature);
    if (!pattern) return 'stable';
    
    const now = Date.now();
    const oneHourAgo = now - 3600000;
    const twoHoursAgo = now - 7200000;
    
    const recentCount = recentEvents.filter(e => 
      this.generateErrorSignature(e) === signature &&
      new Date(e.timestamp).getTime() > oneHourAgo
    ).length;
    
    const previousCount = recentEvents.filter(e => 
      this.generateErrorSignature(e) === signature &&
      new Date(e.timestamp).getTime() > twoHoursAgo &&
      new Date(e.timestamp).getTime() <= oneHourAgo
    ).length;
    
    if (recentCount > previousCount * 1.5) return 'increasing';
    if (recentCount < previousCount * 0.5) return 'decreasing';
    return 'stable';
  }
  
  private calculateSeverity(count: number, pattern?: ErrorPattern): 'low' | 'medium' | 'high' | 'critical' {
    const userImpact = pattern?.affectedUsers.size || 0;
    const componentImpact = pattern?.affectedComponents.size || 0;
    
    if (count > 100 || userImpact > 50 || componentImpact > 5) return 'critical';
    if (count > 50 || userImpact > 20 || componentImpact > 3) return 'high';
    if (count > 10 || userImpact > 5 || componentImpact > 1) return 'medium';
    return 'low';
  }
  
  private generateCorrelationInsights(): Array<{
    primaryError: string;
    correlatedErrors: string[];
    strength: number;
    occurrences: number;
  }> {
    const insights: Array<{
      primaryError: string;
      correlatedErrors: string[];
      strength: number;
      occurrences: number;
    }> = [];
    
    for (const [signature, pattern] of this.patterns) {
      if (pattern.correlatedErrors.length > 0) {
        const correlationCounts = new Map<string, number>();
        
        pattern.correlatedErrors.forEach(correlated => {
          correlationCounts.set(correlated, (correlationCounts.get(correlated) || 0) + 1);
        });
        
        const topCorrelations = Array.from(correlationCounts.entries())
          .sort(([, a], [, b]) => b - a)
          .slice(0, 5);
        
        if (topCorrelations.length > 0) {
          insights.push({
            primaryError: signature,
            correlatedErrors: topCorrelations.map(([sig]) => sig),
            strength: topCorrelations[0][1] / pattern.count,
            occurrences: pattern.count
          });
        }
      }
    }
    
    return insights
      .sort((a, b) => b.strength * b.occurrences - a.strength * a.occurrences)
      .slice(0, 10);
  }
  
  // Utility methods
  private getCorrelationWindowKey(timestamp: string): string {
    const time = new Date(timestamp).getTime();
    const windowStart = Math.floor(time / this.correlationWindowMs) * this.correlationWindowMs;
    return new Date(windowStart).toISOString();
  }
  
  private groupBy<T>(array: T[], key: keyof T): Record<string, T[]> {
    return array.reduce((groups, item) => {
      const groupKey = String(item[key] || 'unknown');
      if (!groups[groupKey]) {
        groups[groupKey] = [];
      }
      groups[groupKey].push(item);
      return groups;
    }, {} as Record<string, T[]>);
  }
}
```

## 🚨 Production Monitoring and Alerting Framework

### Alert Configuration and Management

Comprehensive alerting with graduated severity and escalation procedures:

```typescript
interface AlertRule {
  id: string;
  name: string;
  description: string;
  query: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  threshold: number;
  operator: 'gt' | 'lt' | 'eq' | 'gte' | 'lte';
  duration: string;
  labels: Record<string, string>;
  annotations: Record<string, string>;
  enabled: boolean;
  cooldownMs: number;
}

interface AlertManager {
  rules: AlertRule[];
  activeAlerts: Map<string, Alert>;
  escalationPolicies: Map<string, EscalationPolicy>;
}

class ProductionAlertManager {
  private activeAlerts = new Map<string, Alert>();
  private alertHistory: Alert[] = [];
  private escalationPolicies = new Map<string, EscalationPolicy>();
  private notificationChannels = new Map<string, NotificationChannel>();
  
  constructor() {
    this.initializeDefaultPolicies();
    this.initializeNotificationChannels();
  }
  
  private initializeDefaultPolicies(): void {
    // Critical alert escalation
    this.escalationPolicies.set('critical', {
      levels: [
        { delay: 0, channels: ['pagerduty', 'phone', 'slack-critical'] },
        { delay: 300000, channels: ['incident-commander', 'engineering-manager'] }, // 5 min
        { delay: 600000, channels: ['executive-escalation'] } // 10 min
      ],
      responseTimeTarget: 300000, // 5 minutes
      autoEscalate: true
    });
    
    // High priority escalation
    this.escalationPolicies.set('high', {
      levels: [
        { delay: 0, channels: ['pagerduty', 'slack-alerts'] },
        { delay: 900000, channels: ['team-lead', 'engineering-manager'] } // 15 min
      ],
      responseTimeTarget: 900000, // 15 minutes
      autoEscalate: true
    });
    
    // Medium priority escalation
    this.escalationPolicies.set('medium', {
      levels: [
        { delay: 0, channels: ['slack-alerts', 'email'] },
        { delay: 3600000, channels: ['team-lead'] } // 1 hour
      ],
      responseTimeTarget: 3600000, // 1 hour
      autoEscalate: false
    });
    
    // Low priority (informational)
    this.escalationPolicies.set('low', {
      levels: [
        { delay: 0, channels: ['slack-info'] }
      ],
      responseTimeTarget: 86400000, // 24 hours
      autoEscalate: false
    });
  }
  
  private getProductionAlertRules(): AlertRule[] {
    return [
      // Critical System Alerts
      {
        id: 'service-down',
        name: 'Service Down',
        description: 'FastMCP server is not responding',
        query: 'up{job="fastmcp-server"} == 0',
        severity: 'critical',
        threshold: 0,
        operator: 'eq',
        duration: '1m',
        labels: { team: 'platform', service: 'fastmcp' },
        annotations: {
          summary: 'FastMCP server is down',
          description: 'The FastMCP server has been down for more than 1 minute',
          runbook: 'https://runbooks.company.com/fastmcp-server-down'
        },
        enabled: true,
        cooldownMs: 300000
      },
      
      {
        id: 'high-error-rate',
        name: 'High Error Rate',
        description: 'Error rate exceeds 5%',
        query: 'rate(fastmcp_errors_total[5m]) / rate(fastmcp_requests_total[5m]) * 100',
        severity: 'critical',
        threshold: 5,
        operator: 'gt',
        duration: '2m',
        labels: { team: 'platform', service: 'fastmcp' },
        annotations: {
          summary: 'High error rate detected',
          description: 'Error rate is {{ $value }}% over the last 5 minutes',
          runbook: 'https://runbooks.company.com/high-error-rate'
        },
        enabled: true,
        cooldownMs: 600000
      },
      
      {
        id: 'make-api-errors',
        name: 'Make.com API Errors',
        description: 'High number of Make.com API errors',
        query: 'rate(fastmcp_make_api_call_duration_seconds_count{status=~"4..|5.."}[5m])',
        severity: 'high',
        threshold: 10,
        operator: 'gt',
        duration: '3m',
        labels: { team: 'platform', service: 'make-integration' },
        annotations: {
          summary: 'Make.com API experiencing errors',
          description: 'Make.com API error rate: {{ $value }} errors/second',
          runbook: 'https://runbooks.company.com/make-api-errors'
        },
        enabled: true,
        cooldownMs: 900000
      },
      
      // Performance Alerts
      {
        id: 'high-response-time',
        name: 'High Response Time',
        description: 'P95 response time exceeds threshold',
        query: 'histogram_quantile(0.95, rate(fastmcp_request_duration_seconds_bucket[5m]))',
        severity: 'high',
        threshold: 2.0,
        operator: 'gt',
        duration: '5m',
        labels: { team: 'platform', category: 'performance' },
        annotations: {
          summary: 'High response time detected',
          description: '95th percentile response time is {{ $value }}s',
          runbook: 'https://runbooks.company.com/high-response-time'
        },
        enabled: true,
        cooldownMs: 600000
      },
      
      {
        id: 'circuit-breaker-open',
        name: 'Circuit Breaker Open',
        description: 'Circuit breaker is in open state',
        query: 'fastmcp_circuit_breaker_state',
        severity: 'high',
        threshold: 2,
        operator: 'eq',
        duration: '1m',
        labels: { team: 'platform', category: 'resilience' },
        annotations: {
          summary: 'Circuit breaker {{ $labels.circuit_name }} is open',
          description: 'Circuit breaker has opened due to failures',
          runbook: 'https://runbooks.company.com/circuit-breaker-open'
        },
        enabled: true,
        cooldownMs: 300000
      },
      
      // Resource Alerts
      {
        id: 'high-memory-usage',
        name: 'High Memory Usage',
        description: 'Memory usage exceeds 85%',
        query: 'fastmcp_memory_usage_bytes{type="heap_used"} / fastmcp_memory_usage_bytes{type="heap_total"} * 100',
        severity: 'medium',
        threshold: 85,
        operator: 'gt',
        duration: '5m',
        labels: { team: 'platform', category: 'resources' },
        annotations: {
          summary: 'High memory usage',
          description: 'Memory usage is {{ $value }}%',
          runbook: 'https://runbooks.company.com/high-memory-usage'
        },
        enabled: true,
        cooldownMs: 1800000
      },
      
      {
        id: 'queue-length-growing',
        name: 'Queue Length Growing',
        description: 'Request queue length is growing rapidly',
        query: 'increase(fastmcp_queue_length[10m])',
        severity: 'medium',
        threshold: 100,
        operator: 'gt',
        duration: '5m',
        labels: { team: 'platform', category: 'performance' },
        annotations: {
          summary: 'Queue length growing rapidly',
          description: 'Queue length increased by {{ $value }} in 10 minutes',
          runbook: 'https://runbooks.company.com/queue-length-growing'
        },
        enabled: true,
        cooldownMs: 1200000
      }
    ];
  }
  
  async evaluateAlerts(): Promise<void> {
    const rules = this.getProductionAlertRules();
    
    for (const rule of rules) {
      if (!rule.enabled) continue;
      
      try {
        const isTriggered = await this.evaluateRule(rule);
        
        if (isTriggered) {
          await this.triggerAlert(rule);
        } else {
          await this.resolveAlert(rule.id);
        }
      } catch (error) {
        logger.error('Failed to evaluate alert rule', {
          ruleId: rule.id,
          error: error.message
        });
      }
    }
  }
  
  private async triggerAlert(rule: AlertRule): Promise<void> {
    const existingAlert = this.activeAlerts.get(rule.id);
    
    // Check cooldown period
    if (existingAlert && Date.now() - existingAlert.lastTriggered.getTime() < rule.cooldownMs) {
      return;
    }
    
    const alert: Alert = {
      id: randomUUID(),
      ruleId: rule.id,
      name: rule.name,
      description: rule.description,
      severity: rule.severity,
      status: 'firing',
      triggeredAt: new Date(),
      lastTriggered: new Date(),
      labels: rule.labels,
      annotations: rule.annotations,
      escalationLevel: 0,
      acknowledged: false,
      acknowledgedBy: undefined,
      acknowledgedAt: undefined,
      resolvedAt: undefined
    };
    
    this.activeAlerts.set(rule.id, alert);
    this.alertHistory.push(alert);
    
    logger.error('Alert triggered', {
      alertId: alert.id,
      ruleId: rule.id,
      severity: rule.severity,
      name: rule.name
    });
    
    await this.sendNotification(alert);
    await this.startEscalation(alert);
  }
  
  private async sendNotification(alert: Alert): Promise<void> {
    const policy = this.escalationPolicies.get(alert.severity);
    if (!policy) return;
    
    const level = policy.levels[alert.escalationLevel];
    if (!level) return;
    
    for (const channelName of level.channels) {
      const channel = this.notificationChannels.get(channelName);
      if (channel) {
        try {
          await channel.send(alert);
        } catch (error) {
          logger.error('Failed to send notification', {
            channel: channelName,
            alertId: alert.id,
            error: error.message
          });
        }
      }
    }
  }
  
  private async startEscalation(alert: Alert): Promise<void> {
    const policy = this.escalationPolicies.get(alert.severity);
    if (!policy || !policy.autoEscalate) return;
    
    // Schedule escalation
    setTimeout(async () => {
      const currentAlert = this.activeAlerts.get(alert.ruleId);
      if (currentAlert && !currentAlert.acknowledged && currentAlert.status === 'firing') {
        await this.escalateAlert(currentAlert);
      }
    }, policy.levels[alert.escalationLevel]?.delay || 0);
  }
  
  private async escalateAlert(alert: Alert): Promise<void> {
    const policy = this.escalationPolicies.get(alert.severity);
    if (!policy) return;
    
    alert.escalationLevel++;
    
    if (alert.escalationLevel < policy.levels.length) {
      logger.warn('Escalating alert', {
        alertId: alert.id,
        newLevel: alert.escalationLevel,
        severity: alert.severity
      });
      
      await this.sendNotification(alert);
      await this.startEscalation(alert);
    } else {
      logger.error('Alert escalation exhausted', {
        alertId: alert.id,
        severity: alert.severity
      });
    }
  }
  
  async acknowledgeAlert(ruleId: string, acknowledgedBy: string): Promise<boolean> {
    const alert = this.activeAlerts.get(ruleId);
    if (!alert || alert.acknowledged) {
      return false;
    }
    
    alert.acknowledged = true;
    alert.acknowledgedBy = acknowledgedBy;
    alert.acknowledgedAt = new Date();
    
    logger.info('Alert acknowledged', {
      alertId: alert.id,
      acknowledgedBy,
      severity: alert.severity
    });
    
    return true;
  }
  
  private async resolveAlert(ruleId: string): Promise<void> {
    const alert = this.activeAlerts.get(ruleId);
    if (!alert) return;
    
    alert.status = 'resolved';
    alert.resolvedAt = new Date();
    
    this.activeAlerts.delete(ruleId);
    
    logger.info('Alert resolved', {
      alertId: alert.id,
      duration: alert.resolvedAt.getTime() - alert.triggeredAt.getTime(),
      severity: alert.severity
    });
  }
  
  getActiveAlerts(): Alert[] {
    return Array.from(this.activeAlerts.values());
  }
  
  getAlertHistory(limit = 100): Alert[] {
    return this.alertHistory
      .sort((a, b) => b.triggeredAt.getTime() - a.triggeredAt.getTime())
      .slice(0, limit);
  }
}
```

## Implementation Roadmap

### Phase 1: Foundation (Week 1-2)
1. **Implement Structured Logging**
   - Deploy correlation ID system
   - Set up log aggregation
   - Configure sensitive data masking

2. **Basic Error Handling**
   - Implement MakeServerError class hierarchy
   - Add basic retry mechanisms
   - Create error response formatting

### Phase 2: Resilience Patterns (Week 3-4)
3. **Circuit Breakers**
   - Implement circuit breaker factory
   - Add Make.com API circuit breakers
   - Configure failure thresholds

4. **Health Monitoring**
   - Create health check endpoints
   - Add dependency monitoring
   - Set up metrics collection

### Phase 3: Advanced Monitoring (Week 5-6)
5. **Metrics and Analytics**
   - Deploy Prometheus integration
   - Implement error analytics
   - Create performance dashboards

6. **Alerting System**
   - Configure alert rules
   - Set up escalation policies
   - Integrate notification channels

### Phase 4: Production Hardening (Week 7-8)
7. **Graceful Degradation**
   - Implement feature flagging
   - Add bulkhead patterns
   - Configure degradation levels

8. **Comprehensive Testing**
   - Load testing with failures
   - Chaos engineering
   - Disaster recovery testing

## Success Metrics

### Error Rate Targets
- **Normal Operations**: < 1% error rate
- **Degraded Mode**: < 5% error rate
- **Recovery Time**: < 15 minutes for critical issues

### Performance Targets
- **P95 Response Time**: < 2 seconds
- **P99 Response Time**: < 5 seconds
- **Throughput**: > 1000 requests/minute

### Availability Targets
- **Uptime**: 99.9% availability
- **MTTR**: < 15 minutes mean time to recovery
- **MTBF**: > 30 days mean time between failures

## Conclusion

This comprehensive error handling and resilience framework provides enterprise-grade reliability for production FastMCP servers integrating with Make.com. The implementation combines industry best practices with specific considerations for FastMCP architecture and Make.com API characteristics.

Key highlights:
- **Proactive Error Prevention**: Circuit breakers, timeouts, and retry logic
- **Rapid Issue Detection**: Comprehensive monitoring and alerting
- **Fast Recovery**: Automated failover and graceful degradation
- **Continuous Improvement**: Error analytics and pattern recognition

The framework ensures high availability, proper incident response, and continuous optimization for production environments.