/**
 * Concurrent Integration Management Agent Example
 * Demonstrates cross-service coordination, API integration, and health monitoring
 */

import { ConcurrentIntegrationAgent } from '../utils/concurrent-integration-agent.js';
import { 
  ServiceConfig, 
  ApiRequestContext, 
  BatchApiOperation,
  IntegrationAgentConfig 
} from '../types/integration-types.js';
import logger from '../lib/logger.js';

/**
 * Example integration management scenario
 * Shows how to orchestrate multiple services with concurrent operations
 */
export class IntegrationExample {
  private agent: ConcurrentIntegrationAgent;

  constructor() {
    // Initialize agent with custom configuration
    const config: Partial<IntegrationAgentConfig> = {
      name: 'ExampleIntegrationAgent',
      maxWorkers: 4,
      workerPool: {
        minWorkers: 2,
        maxWorkers: 4,
        idleTimeoutMs: 30000,
        taskTimeoutMs: 45000
      },
      healthMonitoring: {
        enabled: true,
        defaultIntervalMs: 10000, // 10 seconds for demo
        batchSize: 5,
        concurrency: 2
      },
      metrics: {
        enabled: true,
        collectionIntervalMs: 30000, // 30 seconds for demo
        retentionPeriodMs: 60 * 60 * 1000 // 1 hour
      },
      logging: {
        level: 'info',
        includeMetrics: true,
        includePerformance: true
      }
    };

    this.agent = new ConcurrentIntegrationAgent(config);
    this.setupEventListeners();
  }

  /**
   * Run the complete integration example
   */
  public async run(): Promise<void> {
    try {
      logger.info('Starting Integration Management Agent Example');

      // Initialize the agent
      await this.agent.initialize();

      // Register multiple services
      await this.registerExampleServices();

      // Demonstrate concurrent API operations
      await this.demonstrateConcurrentOperations();

      // Show batch operations
      await this.demonstrateBatchOperations();

      // Display health monitoring
      await this.demonstrateHealthMonitoring();

      // Show credential synchronization
      await this.demonstrateCredentialSync();

      // Display metrics and status
      await this.displayMetricsAndStatus();

      logger.info('Integration example completed successfully');

    } catch (error) {
      logger.error('Integration example failed', {
        error: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }

  /**
   * Register example services for demonstration
   */
  private async registerExampleServices(): Promise<void> {
    logger.info('Registering example services');

    // Database service example
    const databaseService: ServiceConfig = {
      id: 'postgres-db',
      name: 'PostgreSQL Database',
      type: 'database',
      version: '14.0',
      endpoints: [
        {
          id: 'primary',
          url: 'postgresql://localhost:5432/makedb',
          method: 'GET',
          active: true,
          weight: 1,
          healthCheckPath: '/health'
        },
        {
          id: 'replica',
          url: 'postgresql://localhost:5433/makedb',
          method: 'GET',
          active: false,
          weight: 0.5,
          healthCheckPath: '/health'
        }
      ],
      authentication: {
        type: 'basic',
        config: {
          username: 'makeuser',
          password: process.env.DB_PASSWORD || 'password'
        },
        rotation: {
          enabled: true,
          intervalDays: 90,
          warningDays: 7
        }
      },
      healthCheck: {
        enabled: true,
        intervalMs: 15000,
        timeoutMs: 5000,
        path: '/health',
        expectedStatusCodes: [200],
        method: 'GET',
        retries: 2,
        failureThreshold: 3,
        recoveryThreshold: 2
      },
      circuitBreaker: {
        enabled: true,
        failureThreshold: 5,
        successThreshold: 3,
        openTimeoutMs: 30000,
        halfOpenTimeoutMs: 15000,
        requestVolumeThreshold: 5,
        errorThresholdPercentage: 60,
        monitoringWindowMs: 60000
      },
      rateLimiting: {
        enabled: true,
        maxRequests: 100,
        windowMs: 60000,
        strategy: 'sliding_window'
      },
      timeouts: {
        connectionMs: 3000,
        requestMs: 10000,
        keepAliveMs: 30000,
        dnsLookupMs: 1000
      },
      retry: {
        enabled: true,
        maxAttempts: 2,
        baseDelayMs: 500,
        maxDelayMs: 5000,
        strategy: 'exponential',
        jitter: {
          enabled: true,
          maxMs: 500
        },
        retryableErrors: ['ECONNRESET', 'ETIMEDOUT']
      },
      metadata: {
        provider: 'PostgreSQL',
        region: 'us-east-1',
        environment: 'development'
      },
      tags: ['database', 'primary-storage', 'relational'],
      enabled: true,
      priority: 'critical',
      sla: {
        availability: 99.9,
        maxResponseTimeMs: 100,
        throughput: 1000,
        errorRate: 0.1,
        rtoMinutes: 5,
        rpoMinutes: 1
      }
    };

    // API service example
    const apiService: ServiceConfig = {
      id: 'external-api',
      name: 'External REST API',
      type: 'api',
      version: '2.1',
      endpoints: [
        {
          id: 'v2-primary',
          url: 'https://api.example.com/v2',
          method: 'GET',
          active: true,
          weight: 1,
          healthCheckPath: '/status'
        }
      ],
      authentication: {
        type: 'api_key',
        config: {
          keyLocation: 'header',
          keyName: 'X-API-Key',
          keyPrefix: ''
        }
      },
      healthCheck: {
        enabled: true,
        intervalMs: 20000,
        timeoutMs: 8000,
        path: '/status',
        expectedStatusCodes: [200, 204],
        method: 'GET',
        retries: 3,
        failureThreshold: 2,
        recoveryThreshold: 2
      },
      circuitBreaker: {
        enabled: true,
        failureThreshold: 3,
        successThreshold: 2,
        openTimeoutMs: 45000,
        halfOpenTimeoutMs: 20000,
        requestVolumeThreshold: 8,
        errorThresholdPercentage: 50,
        monitoringWindowMs: 120000
      },
      rateLimiting: {
        enabled: true,
        maxRequests: 1000,
        windowMs: 60000,
        strategy: 'token_bucket',
        burstSize: 100
      },
      timeouts: {
        connectionMs: 5000,
        requestMs: 30000,
        keepAliveMs: 60000,
        dnsLookupMs: 2000
      },
      retry: {
        enabled: true,
        maxAttempts: 3,
        baseDelayMs: 1000,
        maxDelayMs: 8000,
        strategy: 'exponential',
        jitter: {
          enabled: true,
          maxMs: 1000
        },
        retryableErrors: ['ECONNRESET', 'ETIMEDOUT', 'ENOTFOUND', '429', '503']
      },
      metadata: {
        provider: 'ExampleAPI',
        region: 'global',
        category: 'integration'
      },
      tags: ['api', 'external', 'integration'],
      enabled: true,
      priority: 'high',
      sla: {
        availability: 99.5,
        maxResponseTimeMs: 2000,
        throughput: 500,
        errorRate: 2.0,
        rtoMinutes: 10,
        rpoMinutes: 5
      }
    };

    // Storage service example
    const storageService: ServiceConfig = {
      id: 'redis-cache',
      name: 'Redis Cache',
      type: 'storage',
      version: '7.0',
      endpoints: [
        {
          id: 'primary-cache',
          url: 'redis://localhost:6379/0',
          method: 'GET',
          active: true,
          weight: 1,
          healthCheckPath: '/ping'
        }
      ],
      authentication: {
        type: 'none',
        config: {}
      },
      healthCheck: {
        enabled: true,
        intervalMs: 10000,
        timeoutMs: 3000,
        path: '/ping',
        expectedStatusCodes: [200],
        method: 'GET',
        retries: 1,
        failureThreshold: 3,
        recoveryThreshold: 1
      },
      circuitBreaker: {
        enabled: true,
        failureThreshold: 5,
        successThreshold: 2,
        openTimeoutMs: 20000,
        halfOpenTimeoutMs: 10000,
        requestVolumeThreshold: 10,
        errorThresholdPercentage: 40,
        monitoringWindowMs: 60000
      },
      rateLimiting: {
        enabled: false,
        maxRequests: 10000,
        windowMs: 60000,
        strategy: 'fixed_window'
      },
      timeouts: {
        connectionMs: 2000,
        requestMs: 5000,
        keepAliveMs: 30000
      },
      retry: {
        enabled: true,
        maxAttempts: 2,
        baseDelayMs: 100,
        maxDelayMs: 1000,
        strategy: 'linear',
        jitter: {
          enabled: false,
          maxMs: 0
        },
        retryableErrors: ['ECONNRESET', 'ETIMEDOUT']
      },
      metadata: {
        provider: 'Redis',
        region: 'us-east-1',
        category: 'cache'
      },
      tags: ['cache', 'in-memory', 'fast-access'],
      enabled: true,
      priority: 'high',
      sla: {
        availability: 99.8,
        maxResponseTimeMs: 10,
        throughput: 10000,
        errorRate: 0.5,
        rtoMinutes: 2,
        rpoMinutes: 0
      }
    };

    // Register all services
    await Promise.all([
      this.agent.registerService(databaseService),
      this.agent.registerService(apiService),
      this.agent.registerService(storageService)
    ]);

    logger.info('Example services registered successfully', {
      serviceCount: 3
    });
  }

  /**
   * Demonstrate concurrent API operations
   */
  private async demonstrateConcurrentOperations(): Promise<void> {
    logger.info('Demonstrating concurrent API operations');

    const requests: ApiRequestContext[] = [
      {
        id: 'req-001',
        serviceId: 'postgres-db',
        endpointId: 'primary',
        priority: 'high',
        timeout: 10000,
        correlationId: 'demo-001',
        userContext: {
          userId: 'user-123',
          organizationId: 'org-456'
        },
        metadata: {
          operation: 'get_user_data',
          table: 'users'
        }
      },
      {
        id: 'req-002',
        serviceId: 'external-api',
        endpointId: 'v2-primary',
        priority: 'normal',
        timeout: 15000,
        correlationId: 'demo-001',
        userContext: {
          userId: 'user-123',
          organizationId: 'org-456'
        },
        metadata: {
          operation: 'get_profile',
          endpoint: '/users/123/profile'
        }
      },
      {
        id: 'req-003',
        serviceId: 'redis-cache',
        endpointId: 'primary-cache',
        priority: 'normal',
        timeout: 5000,
        correlationId: 'demo-001',
        userContext: {
          userId: 'user-123',
          organizationId: 'org-456'
        },
        metadata: {
          operation: 'get_cached_data',
          key: 'user:123:profile'
        }
      }
    ];

    try {
      // Execute requests concurrently
      const startTime = Date.now();
      const responses = await Promise.all(
        requests.map(request => this.agent.executeApiRequest(request))
      );
      const totalTime = Date.now() - startTime;

      logger.info('Concurrent operations completed', {
        requestCount: requests.length,
        totalTime: `${totalTime}ms`,
        averageTime: `${(totalTime / requests.length).toFixed(2)}ms`,
        responses: responses.map(r => ({
          requestId: r.request.id,
          serviceId: r.request.serviceId,
          success: r.response.success,
          responseTime: `${r.responseTime.toFixed(2)}ms`
        }))
      });

    } catch (error) {
      logger.error('Concurrent operations failed', {
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }

  /**
   * Demonstrate batch operations
   */
  private async demonstrateBatchOperations(): Promise<void> {
    logger.info('Demonstrating batch operations');

    const batchRequests: ApiRequestContext[] = [
      {
        id: 'batch-001',
        serviceId: 'external-api',
        endpointId: 'v2-primary',
        priority: 'normal',
        timeout: 10000,
        metadata: { operation: 'get_data', resource: 'users' }
      },
      {
        id: 'batch-002',
        serviceId: 'external-api',
        endpointId: 'v2-primary',
        priority: 'normal',
        timeout: 10000,
        metadata: { operation: 'get_data', resource: 'orders' }
      },
      {
        id: 'batch-003',
        serviceId: 'external-api',
        endpointId: 'v2-primary',
        priority: 'low',
        timeout: 15000,
        metadata: { operation: 'get_data', resource: 'analytics' }
      }
    ];

    const batchOperation: BatchApiOperation = {
      id: 'demo-batch-001',
      requests: batchRequests,
      strategy: 'parallel',
      maxConcurrency: 2,
      timeout: 30000,
      failureStrategy: 'continue_on_error'
    };

    try {
      const startTime = Date.now();
      const results = await this.agent.executeBatchOperation(batchOperation);
      const totalTime = Date.now() - startTime;

      const successCount = results.filter(r => r.response.success).length;
      const failureCount = results.length - successCount;

      logger.info('Batch operation completed', {
        batchId: batchOperation.id,
        strategy: batchOperation.strategy,
        totalRequests: results.length,
        successCount,
        failureCount,
        totalTime: `${totalTime}ms`,
        averageResponseTime: `${(results.reduce((sum, r) => sum + r.responseTime, 0) / results.length).toFixed(2)}ms`
      });

    } catch (error) {
      logger.error('Batch operation failed', {
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }

  /**
   * Demonstrate health monitoring
   */
  private async demonstrateHealthMonitoring(): Promise<void> {
    logger.info('Demonstrating health monitoring');

    try {
      // Wait a moment for health checks to run
      await new Promise(resolve => setTimeout(resolve, 2000));

      // Get health status for all services
      const healthStatuses = await this.agent.getAllServiceHealth();

      logger.info('Service health status', {
        totalServices: healthStatuses.size,
        healthBreakdown: Array.from(healthStatuses.entries()).map(([serviceId, health]) => ({
          serviceId,
          status: health.status,
          score: health.score,
          responseTime: `${health.responseTime.toFixed(2)}ms`,
          lastChecked: health.lastChecked.toISOString(),
          consecutiveFailures: health.consecutiveFailures,
          consecutiveSuccesses: health.consecutiveSuccesses
        }))
      });

      // Check individual service health
      const dbHealth = await this.agent.getServiceHealth('postgres-db');
      logger.info('Database service health details', {
        serviceId: dbHealth.serviceId,
        status: dbHealth.status,
        score: dbHealth.score,
        trend: dbHealth.trend,
        details: dbHealth.details
      });

    } catch (error) {
      logger.error('Health monitoring demonstration failed', {
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }

  /**
   * Demonstrate credential synchronization
   */
  private async demonstrateCredentialSync(): Promise<void> {
    logger.info('Demonstrating credential synchronization');

    try {
      // Simulate credential rotation across services
      await this.agent.synchronizeCredentials('cred-api-key-001', [
        'postgres-db',
        'external-api'
      ]);

      logger.info('Credential synchronization completed', {
        credentialId: 'cred-api-key-001',
        affectedServices: ['postgres-db', 'external-api']
      });

    } catch (error) {
      logger.error('Credential synchronization failed', {
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }

  /**
   * Display metrics and status
   */
  private async displayMetricsAndStatus(): Promise<void> {
    logger.info('Displaying agent metrics and status');

    try {
      // Get agent status
      const status = await this.agent.getStatus();
      logger.info('Integration agent status', status);

      // Get metrics for each service
      for (const serviceId of ['postgres-db', 'external-api', 'redis-cache']) {
        try {
          const metrics = await this.agent.getServiceMetrics(serviceId);
          if (metrics.length > 0) {
            const latestMetrics = metrics[metrics.length - 1];
            logger.info(`Service metrics: ${serviceId}`, {
              timestamp: latestMetrics.timestamp.toISOString(),
              requests: latestMetrics.requests,
              responseTime: latestMetrics.responseTime,
              availability: latestMetrics.availability,
              circuitBreaker: latestMetrics.circuitBreaker
            });
          }
        } catch (error) {
          logger.warn(`No metrics available for service: ${serviceId}`);
        }
      }

    } catch (error) {
      logger.error('Failed to display metrics and status', {
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }

  /**
   * Setup event listeners to monitor agent activities
   */
  private setupEventListeners(): void {
    this.agent.on('initialized', () => {
      logger.info('Integration agent initialized');
    });

    this.agent.on('service_registered', (event) => {
      logger.info('Service registered', {
        serviceId: event.serviceId,
        serviceName: event.config.name
      });
    });

    this.agent.on('service_health_change', (event) => {
      logger.info('Service health changed', {
        serviceId: event.serviceId,
        oldStatus: event.oldStatus,
        newStatus: event.newStatus,
        timestamp: event.timestamp
      });
    });

    this.agent.on('circuit_breaker_state_change', (event) => {
      logger.warn('Circuit breaker state changed', {
        serviceId: event.serviceId,
        oldState: event.oldState,
        newState: event.newState,
        reason: event.reason
      });
    });

    this.agent.on('credential_sync', (event) => {
      logger.info('Credential synchronization completed', {
        credentialId: event.credentialId,
        serviceIds: event.serviceIds
      });
    });

    this.agent.on('batch_complete', (event) => {
      logger.info('Batch operation completed', {
        batchId: event.batch.id,
        requestCount: event.batch.requests.length,
        responseCount: event.responses.length
      });
    });
  }

  /**
   * Cleanup and shutdown
   */
  public async shutdown(): Promise<void> {
    logger.info('Shutting down integration example');
    await this.agent.shutdown();
  }
}

/**
 * Run the integration example if this file is executed directly
 */
if (require.main === module) {
  const example = new IntegrationExample();
  
  // Handle graceful shutdown
  process.on('SIGINT', async () => {
    logger.info('Received SIGINT, shutting down gracefully');
    await example.shutdown();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    logger.info('Received SIGTERM, shutting down gracefully');
    await example.shutdown();
    process.exit(0);
  });

  // Run the example
  example.run().catch(async (error) => {
    logger.error('Integration example failed', {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined
    });
    await example.shutdown();
    process.exit(1);
  });
}

export default IntegrationExample;