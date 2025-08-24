/**
 * Concurrent Integration Management Agent
 * Advanced cross-service coordination, API integration, and service health monitoring
 * using Worker Threads for parallel processing and concurrent operations
 */

import { Worker, isMainThread, parentPort, workerData } from 'worker_threads';
import { EventEmitter } from 'events';
import { createHash, randomBytes } from 'crypto';
import { URL } from 'url';
import logger from '../lib/logger.js';
import { MakeApiClient } from '../lib/make-api-client.js';
import {
  ServiceConfig,
  ServiceHealthStatus,
  IntegrationContext,
  IntegrationWorkerMessage,
  IntegrationWorkerResponse,
  IntegrationEvent,
  ApiRequestContext,
  ApiResponseContext,
  BatchApiOperation,
  ServiceDependencyGraph,
  CircuitBreakerState,
  ServiceMetrics,
  IntegrationAgentConfig,
  IIntegrationAgent,
  ServiceOperationResult,
  CredentialMetadata,
  ConnectionPool
} from '../types/integration-types.js';
import { ApiResponse } from '../types/index.js';

/**
 * Main Concurrent Integration Management Agent
 * Orchestrates cross-service coordination with parallel processing capabilities
 */
export class ConcurrentIntegrationAgent extends EventEmitter implements IIntegrationAgent {
  private readonly workers: Map<string, Worker> = new Map();
  private readonly maxWorkers: number = 6;
  private readonly workerPool: Worker[] = [];
  private readonly taskQueue: IntegrationWorkerMessage[] = [];
  private readonly pendingTasks: Map<string, { resolve: Function; reject: Function; timeout?: NodeJS.Timeout }> = new Map();
  
  // Integration context
  private readonly context: IntegrationContext;
  
  // Performance tracking
  private readonly metrics: Map<string, ServiceMetrics[]> = new Map();
  private metricsInterval?: NodeJS.Timeout;
  private healthCheckInterval?: NodeJS.Timeout;
  
  // State management
  private isInitialized: boolean = false;
  private isShutdown: boolean = false;
  private readonly startTime: Date = new Date();
  
  // Configuration
  private readonly config: IntegrationAgentConfig;

  constructor(config?: Partial<IntegrationAgentConfig>) {
    super();
    
    // Initialize configuration with defaults
    this.config = {
      name: 'IntegrationAgent',
      maxWorkers: 6,
      workerPool: {
        minWorkers: 2,
        maxWorkers: 6,
        idleTimeoutMs: 30000,
        taskTimeoutMs: 30000
      },
      serviceDiscovery: {
        enabled: true,
        intervalMs: 30000,
        sources: ['static']
      },
      healthMonitoring: {
        enabled: true,
        defaultIntervalMs: 15000,
        batchSize: 10,
        concurrency: 3
      },
      metrics: {
        enabled: true,
        collectionIntervalMs: 60000,
        retentionPeriodMs: 24 * 60 * 60 * 1000 // 24 hours
      },
      cache: {
        enabled: true,
        maxSize: 1000,
        defaultTtlMs: 5 * 60 * 1000 // 5 minutes
      },
      logging: {
        level: 'info',
        includeMetrics: true,
        includePerformance: true
      },
      ...config
    };

    // Initialize integration context
    this.context = {
      services: new Map(),
      dependencies: {
        nodes: new Map(),
        edges: [],
        updateOrder: [],
        criticalPath: []
      },
      credentials: new Map(),
      healthStatus: new Map(),
      circuitBreakers: new Map(),
      connections: new Map(),
      metrics: new Map(),
      configCache: new Map()
    };
  }

  /**
   * Initialize the integration agent
   */
  public async initialize(): Promise<void> {
    if (this.isInitialized) {
      return;
    }

    try {
      logger.info('Initializing Concurrent Integration Agent', {
        config: this.config.name,
        maxWorkers: this.config.maxWorkers
      });

      // Initialize worker pool
      await this.createWorkerPool();
      
      // Start health monitoring if enabled
      if (this.config.healthMonitoring.enabled) {
        this.startHealthMonitoring();
      }
      
      // Start metrics collection if enabled
      if (this.config.metrics.enabled) {
        this.startMetricsCollection();
      }
      
      // Initialize default Make.com service
      await this.initializeMakeService();
      
      this.isInitialized = true;
      
      logger.info('Concurrent Integration Agent initialized successfully', {
        workers: this.workerPool.length,
        services: this.context.services.size,
        healthMonitoring: this.config.healthMonitoring.enabled,
        metricsCollection: this.config.metrics.enabled
      });

      this.emit('initialized');
    } catch (error) {
      logger.error('Failed to initialize Concurrent Integration Agent', {
        error: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }

  /**
   * Initialize Make.com service configuration
   */
  private async initializeMakeService(): Promise<void> {
    const makeService: ServiceConfig = {
      id: 'make-api',
      name: 'Make.com API',
      type: 'api',
      version: '1.0.0',
      endpoints: [
        {
          id: 'api-v1',
          url: process.env.MAKE_API_URL || 'https://api.make.com/v1',
          method: 'GET',
          active: true,
          weight: 1,
          healthCheckPath: '/ping'
        }
      ],
      authentication: {
        type: 'api_key',
        config: {
          keyLocation: 'header',
          keyName: 'Authorization',
          keyPrefix: 'Token '
        }
      },
      healthCheck: {
        enabled: true,
        intervalMs: 30000,
        timeoutMs: 10000,
        path: '/ping',
        expectedStatusCodes: [200, 204],
        method: 'GET',
        retries: 2,
        failureThreshold: 3,
        recoveryThreshold: 2
      },
      circuitBreaker: {
        enabled: true,
        failureThreshold: 5,
        successThreshold: 3,
        openTimeoutMs: 60000,
        halfOpenTimeoutMs: 30000,
        requestVolumeThreshold: 10,
        errorThresholdPercentage: 50,
        monitoringWindowMs: 300000
      },
      rateLimiting: {
        enabled: true,
        maxRequests: 600,
        windowMs: 60000,
        strategy: 'sliding_window'
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
        maxDelayMs: 10000,
        strategy: 'exponential',
        jitter: {
          enabled: true,
          maxMs: 1000
        },
        retryableErrors: ['ECONNRESET', 'ETIMEDOUT', 'ENOTFOUND', 'EAI_AGAIN']
      },
      metadata: {
        provider: 'Make.com',
        region: 'global',
        category: 'automation'
      },
      tags: ['automation', 'workflows', 'integration'],
      enabled: true,
      priority: 'high',
      sla: {
        availability: 99.9,
        maxResponseTimeMs: 2000,
        throughput: 100,
        errorRate: 1.0,
        rtoMinutes: 15,
        rpoMinutes: 5
      }
    };

    await this.registerService(makeService);
  }

  /**
   * Create worker pool for parallel processing
   */
  private async createWorkerPool(): Promise<void> {
    const workerScript = new URL('./integration-worker.js', import.meta.url);
    
    for (let i = 0; i < this.config.maxWorkers; i++) {
      const worker = new Worker(workerScript, {
        workerData: { 
          workerId: i,
          config: this.config
        }
      });

      worker.on('message', (message: IntegrationWorkerResponse) => {
        this.handleWorkerMessage(message);
      });

      worker.on('error', (error) => {
        logger.error(`Integration worker ${i} error`, { 
          workerId: i,
          error: error.message 
        });
        this.replaceWorker(i);
      });

      worker.on('exit', (code) => {
        if (code !== 0 && !this.isShutdown) {
          logger.warn(`Integration worker ${i} stopped with exit code ${code}`);
          this.replaceWorker(i);
        }
      });

      this.workerPool.push(worker);
      this.workers.set(`worker-${i}`, worker);
    }

    logger.info('Integration worker pool created', {
      workerCount: this.workerPool.length
    });
  }

  /**
   * Replace a failed worker
   */
  private replaceWorker(index: number): void {
    if (this.isShutdown) {
      return;
    }

    const oldWorker = this.workerPool[index];
    if (oldWorker) {
      oldWorker.terminate();
    }

    const workerScript = new URL('./integration-worker.js', import.meta.url);
    const newWorker = new Worker(workerScript, {
      workerData: { 
        workerId: index,
        config: this.config
      }
    });

    newWorker.on('message', (message: IntegrationWorkerResponse) => {
      this.handleWorkerMessage(message);
    });

    newWorker.on('error', (error) => {
      logger.error(`Replacement integration worker ${index} error`, { 
        workerId: index,
        error: error.message 
      });
    });

    this.workerPool[index] = newWorker;
    this.workers.set(`worker-${index}`, newWorker);

    logger.info('Integration worker replaced', {
      workerId: index
    });
  }

  /**
   * Handle worker message responses
   */
  private handleWorkerMessage(message: IntegrationWorkerResponse): void {
    const pendingTask = this.pendingTasks.get(message.id);
    if (pendingTask) {
      this.pendingTasks.delete(message.id);
      
      // Clear timeout
      if (pendingTask.timeout) {
        clearTimeout(pendingTask.timeout);
      }
      
      if (message.error) {
        pendingTask.reject(new Error(message.error.message));
      } else {
        pendingTask.resolve(message.data);
      }
    }
  }

  /**
   * Register a service with the integration agent
   */
  public async registerService(config: ServiceConfig): Promise<void> {
    try {
      // Validate service configuration
      this.validateServiceConfig(config);
      
      // Store service configuration
      this.context.services.set(config.id, config);
      
      // Initialize health status
      this.context.healthStatus.set(config.id, {
        serviceId: config.id,
        status: 'unknown',
        score: 0,
        lastChecked: new Date(),
        responseTime: 0,
        details: {},
        trend: 'stable',
        consecutiveFailures: 0,
        consecutiveSuccesses: 0,
        history: []
      });
      
      // Initialize circuit breaker state
      if (config.circuitBreaker.enabled) {
        this.context.circuitBreakers.set(config.id, {
          serviceId: config.id,
          state: 'closed',
          failureCount: 0,
          successCount: 0,
          lastStateChange: new Date(),
          nextEvaluation: new Date(),
          windowStart: new Date(),
          requestCount: 0
        });
      }
      
      // Initialize connection pool
      this.context.connections.set(config.id, {
        serviceId: config.id,
        activeConnections: 0,
        maxPoolSize: 10,
        stats: {
          created: 0,
          destroyed: 0,
          reused: 0,
          timeouts: 0
        },
        config: {
          maxIdleTime: 30000,
          keepAlive: true,
          maxSockets: 10
        }
      });
      
      logger.info('Service registered successfully', {
        serviceId: config.id,
        serviceName: config.name,
        serviceType: config.type,
        enabled: config.enabled
      });
      
      this.emit('service_registered', { serviceId: config.id, config });
      
      // Perform initial health check
      if (config.enabled && config.healthCheck.enabled) {
        setImmediate(() => this.performHealthCheck(config.id));
      }
    } catch (error) {
      logger.error('Failed to register service', {
        serviceId: config.id,
        error: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }

  /**
   * Validate service configuration
   */
  private validateServiceConfig(config: ServiceConfig): void {
    if (!config.id || !config.name || !config.type) {
      throw new Error('Service configuration missing required fields: id, name, type');
    }
    
    if (!config.endpoints || config.endpoints.length === 0) {
      throw new Error('Service configuration must have at least one endpoint');
    }
    
    for (const endpoint of config.endpoints) {
      if (!endpoint.id || !endpoint.url) {
        throw new Error('Service endpoint missing required fields: id, url');
      }
    }
  }

  /**
   * Unregister a service
   */
  public async unregisterService(serviceId: string): Promise<void> {
    try {
      const config = this.context.services.get(serviceId);
      if (!config) {
        throw new Error(`Service ${serviceId} not found`);
      }
      
      // Remove from all contexts
      this.context.services.delete(serviceId);
      this.context.healthStatus.delete(serviceId);
      this.context.circuitBreakers.delete(serviceId);
      this.context.connections.delete(serviceId);
      this.context.metrics.delete(serviceId);
      
      logger.info('Service unregistered successfully', {
        serviceId,
        serviceName: config.name
      });
      
      this.emit('service_unregistered', { serviceId, config });
    } catch (error) {
      logger.error('Failed to unregister service', {
        serviceId,
        error: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }

  /**
   * Execute API request through the integration layer
   */
  public async executeApiRequest(
    context: ApiRequestContext, 
    data?: unknown
  ): Promise<ApiResponseContext> {
    try {
      // Validate request context
      const service = this.context.services.get(context.serviceId);
      if (!service) {
        throw new Error(`Service ${context.serviceId} not found`);
      }
      
      if (!service.enabled) {
        throw new Error(`Service ${context.serviceId} is disabled`);
      }
      
      // Check circuit breaker
      const circuitBreakerState = this.context.circuitBreakers.get(context.serviceId);
      if (circuitBreakerState && circuitBreakerState.state === 'open') {
        throw new Error(`Circuit breaker is open for service ${context.serviceId}`);
      }
      
      // Execute request through worker
      const taskId = this.generateTaskId();
      const workerMessage: IntegrationWorkerMessage = {
        type: 'api_request',
        data: {
          context,
          requestData: data,
          serviceConfig: service
        },
        id: taskId,
        priority: context.priority,
        timeout: context.timeout
      };
      
      const response = await this.executeWorkerTask<ApiResponseContext>(workerMessage);
      
      // Update circuit breaker on success
      if (circuitBreakerState) {
        this.updateCircuitBreakerSuccess(context.serviceId);
      }
      
      // Update metrics
      this.updateServiceMetrics(context.serviceId, {
        successful: true,
        responseTime: response.responseTime,
        timestamp: response.timestamp
      });
      
      return response;
    } catch (error) {
      // Update circuit breaker on failure
      const circuitBreakerState = this.context.circuitBreakers.get(context.serviceId);
      if (circuitBreakerState) {
        this.updateCircuitBreakerFailure(context.serviceId);
      }
      
      // Update metrics
      this.updateServiceMetrics(context.serviceId, {
        successful: false,
        error: error instanceof Error ? error.message : String(error),
        timestamp: new Date()
      });
      
      logger.error('API request execution failed', {
        serviceId: context.serviceId,
        requestId: context.id,
        error: error instanceof Error ? error.message : String(error)
      });
      
      throw error;
    }
  }

  /**
   * Execute batch API operations
   */
  public async executeBatchOperation(batch: BatchApiOperation): Promise<ApiResponseContext[]> {
    try {
      const taskId = this.generateTaskId();
      const workerMessage: IntegrationWorkerMessage = {
        type: 'batch_operation',
        data: batch,
        id: taskId,
        priority: 'normal',
        timeout: batch.timeout
      };
      
      const responses = await this.executeWorkerTask<ApiResponseContext[]>(workerMessage);
      
      logger.info('Batch operation completed', {
        batchId: batch.id,
        requestCount: batch.requests.length,
        responseCount: responses.length,
        strategy: batch.strategy
      });
      
      this.emit('batch_complete', { batch, responses });
      return responses;
    } catch (error) {
      logger.error('Batch operation failed', {
        batchId: batch.id,
        error: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }

  /**
   * Get service health status
   */
  public async getServiceHealth(serviceId: string): Promise<ServiceHealthStatus> {
    const healthStatus = this.context.healthStatus.get(serviceId);
    if (!healthStatus) {
      throw new Error(`Service ${serviceId} not found`);
    }
    
    // Trigger immediate health check if status is old
    const now = new Date();
    const healthAge = now.getTime() - healthStatus.lastChecked.getTime();
    if (healthAge > 60000) { // 1 minute
      await this.performHealthCheck(serviceId);
      return this.context.healthStatus.get(serviceId)!;
    }
    
    return healthStatus;
  }

  /**
   * Get all service health statuses
   */
  public async getAllServiceHealth(): Promise<Map<string, ServiceHealthStatus>> {
    return new Map(this.context.healthStatus);
  }

  /**
   * Synchronize credentials across services
   */
  public async synchronizeCredentials(credentialId: string, serviceIds: string[]): Promise<void> {
    try {
      const taskId = this.generateTaskId();
      const workerMessage: IntegrationWorkerMessage = {
        type: 'credential_sync',
        data: {
          credentialId,
          serviceIds,
          services: Array.from(this.context.services.entries())
            .filter(([id]) => serviceIds.includes(id))
            .map(([_, config]) => config)
        },
        id: taskId,
        priority: 'high',
        timeout: 30000
      };
      
      await this.executeWorkerTask(workerMessage);
      
      logger.info('Credential synchronization completed', {
        credentialId,
        serviceCount: serviceIds.length
      });
      
      this.emit('credential_sync', { credentialId, serviceIds });
    } catch (error) {
      logger.error('Credential synchronization failed', {
        credentialId,
        serviceIds,
        error: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }

  /**
   * Get service metrics
   */
  public async getServiceMetrics(
    serviceId: string, 
    timeRange?: { start: Date; end: Date }
  ): Promise<ServiceMetrics[]> {
    const metrics = this.metrics.get(serviceId) || [];
    
    if (!timeRange) {
      return metrics;
    }
    
    return metrics.filter(metric => 
      metric.timestamp >= timeRange.start && 
      metric.timestamp <= timeRange.end
    );
  }

  /**
   * Get integration agent status
   */
  public async getStatus(): Promise<{
    healthy: boolean;
    services: number;
    activeWorkers: number;
    pendingTasks: number;
    uptime: number;
  }> {
    const healthyWorkers = this.workerPool.filter(worker => worker.threadId !== undefined).length;
    const uptime = Date.now() - this.startTime.getTime();
    
    return {
      healthy: this.isInitialized && healthyWorkers >= Math.ceil(this.config.maxWorkers * 0.5),
      services: this.context.services.size,
      activeWorkers: healthyWorkers,
      pendingTasks: this.pendingTasks.size,
      uptime: Math.floor(uptime / 1000) // seconds
    };
  }

  /**
   * Perform health check for a service
   */
  private async performHealthCheck(serviceId: string): Promise<void> {
    try {
      const service = this.context.services.get(serviceId);
      if (!service?.healthCheck.enabled) {
        return;
      }
      
      const taskId = this.generateTaskId();
      const workerMessage: IntegrationWorkerMessage = {
        type: 'health_check',
        data: {
          serviceId,
          serviceConfig: service
        },
        id: taskId,
        priority: 'normal',
        timeout: service.healthCheck.timeoutMs
      };
      
      const healthResult = await this.executeWorkerTask<ServiceHealthStatus>(workerMessage);
      
      // Update health status
      const currentHealth = this.context.healthStatus.get(serviceId);
      const oldStatus = currentHealth?.status;
      
      this.context.healthStatus.set(serviceId, healthResult);
      
      // Emit health change event if status changed
      if (oldStatus && oldStatus !== healthResult.status) {
        this.emit('service_health_change', {
          type: 'service_health_change',
          serviceId,
          oldStatus,
          newStatus: healthResult.status,
          timestamp: new Date(),
          details: healthResult
        } as IntegrationEvent);
      }
      
    } catch (error) {
      logger.error('Health check failed', {
        serviceId,
        error: error instanceof Error ? error.message : String(error)
      });
      
      // Mark service as unhealthy
      const currentHealth = this.context.healthStatus.get(serviceId);
      if (currentHealth) {
        currentHealth.status = 'unhealthy';
        currentHealth.consecutiveFailures++;
        currentHealth.consecutiveSuccesses = 0;
        currentHealth.lastChecked = new Date();
      }
    }
  }

  /**
   * Start health monitoring
   */
  private startHealthMonitoring(): void {
    this.healthCheckInterval = setInterval(async () => {
      const services = Array.from(this.context.services.values())
        .filter(service => service.enabled && service.healthCheck.enabled);
      
      // Batch health checks for efficiency
      const batchSize = this.config.healthMonitoring.batchSize;
      for (let i = 0; i < services.length; i += batchSize) {
        const batch = services.slice(i, i + batchSize);
        
        // Execute health checks in parallel with limited concurrency
        const promises = batch.map(service => this.performHealthCheck(service.id));
        await Promise.allSettled(promises);
      }
    }, this.config.healthMonitoring.defaultIntervalMs);
    
    logger.info('Health monitoring started', {
      intervalMs: this.config.healthMonitoring.defaultIntervalMs,
      batchSize: this.config.healthMonitoring.batchSize
    });
  }

  /**
   * Start metrics collection
   */
  private startMetricsCollection(): void {
    this.metricsInterval = setInterval(() => {
      this.collectServiceMetrics();
    }, this.config.metrics.collectionIntervalMs);
    
    logger.info('Metrics collection started', {
      intervalMs: this.config.metrics.collectionIntervalMs
    });
  }

  /**
   * Collect service metrics
   */
  private collectServiceMetrics(): void {
    for (const [serviceId, service] of this.context.services) {
      if (!service.enabled) {
        continue;
      }
      
      const healthStatus = this.context.healthStatus.get(serviceId);
      const circuitBreaker = this.context.circuitBreakers.get(serviceId);
      
      const metrics: ServiceMetrics = {
        serviceId,
        timestamp: new Date(),
        requests: {
          total: 0,
          successful: 0,
          failed: 0,
          rate: 0
        },
        responseTime: {
          mean: healthStatus?.responseTime || 0,
          p50: healthStatus?.responseTime || 0,
          p95: healthStatus?.responseTime || 0,
          p99: healthStatus?.responseTime || 0,
          max: healthStatus?.responseTime || 0
        },
        errors: {
          total: healthStatus?.consecutiveFailures || 0,
          rate: 0,
          types: {}
        },
        availability: {
          uptime: 0,
          downtime: 0,
          percentage: healthStatus?.status === 'healthy' ? 100 : 0
        },
        circuitBreaker: circuitBreaker ? {
          state: circuitBreaker.state,
          failureRate: circuitBreaker.requestCount > 0 ? 
            (circuitBreaker.failureCount / circuitBreaker.requestCount) * 100 : 0,
          requestCount: circuitBreaker.requestCount
        } : undefined
      };
      
      // Store metrics
      let serviceMetrics = this.metrics.get(serviceId);
      if (!serviceMetrics) {
        serviceMetrics = [];
        this.metrics.set(serviceId, serviceMetrics);
      }
      
      serviceMetrics.push(metrics);
      
      // Keep only recent metrics (based on retention period)
      const retentionCutoff = new Date(Date.now() - this.config.metrics.retentionPeriodMs);
      const filteredMetrics = serviceMetrics.filter(m => m.timestamp > retentionCutoff);
      this.metrics.set(serviceId, filteredMetrics);
    }
  }

  /**
   * Update circuit breaker on success
   */
  private updateCircuitBreakerSuccess(serviceId: string): void {
    const state = this.context.circuitBreakers.get(serviceId);
    if (!state) {return;}
    
    state.successCount++;
    state.requestCount++;
    
    if (state.state === 'half_open') {
      const service = this.context.services.get(serviceId);
      if (service && state.successCount >= service.circuitBreaker.successThreshold) {
        state.state = 'closed';
        state.failureCount = 0;
        state.successCount = 0;
        state.lastStateChange = new Date();
        
        logger.info('Circuit breaker closed', { serviceId });
        this.emit('circuit_breaker_state_change', {
          type: 'circuit_breaker_state_change',
          serviceId,
          oldState: 'half_open',
          newState: 'closed',
          timestamp: new Date(),
          reason: 'Success threshold reached',
          details: state
        } as IntegrationEvent);
      }
    }
  }

  /**
   * Update circuit breaker on failure
   */
  private updateCircuitBreakerFailure(serviceId: string): void {
    const state = this.context.circuitBreakers.get(serviceId);
    if (!state) {return;}
    
    const service = this.context.services.get(serviceId);
    if (!service) {return;}
    
    state.failureCount++;
    state.requestCount++;
    
    // Check if we should open the circuit
    if (state.state === 'closed' && 
        state.requestCount >= service.circuitBreaker.requestVolumeThreshold) {
      const errorRate = (state.failureCount / state.requestCount) * 100;
      
      if (errorRate >= service.circuitBreaker.errorThresholdPercentage) {
        state.state = 'open';
        state.lastStateChange = new Date();
        state.nextEvaluation = new Date(Date.now() + service.circuitBreaker.openTimeoutMs);
        
        logger.warn('Circuit breaker opened', { 
          serviceId,
          errorRate: `${errorRate.toFixed(2)}%`
        });
        
        this.emit('circuit_breaker_state_change', {
          type: 'circuit_breaker_state_change',
          serviceId,
          oldState: 'closed',
          newState: 'open',
          timestamp: new Date(),
          reason: `Error rate ${errorRate.toFixed(2)}% exceeded threshold`,
          details: state
        } as IntegrationEvent);
      }
    } else if (state.state === 'half_open') {
      state.state = 'open';
      state.lastStateChange = new Date();
      state.nextEvaluation = new Date(Date.now() + service.circuitBreaker.openTimeoutMs);
      
      logger.warn('Circuit breaker reopened', { serviceId });
    }
  }

  /**
   * Update service metrics with operation result
   */
  private updateServiceMetrics(serviceId: string, result: {
    successful: boolean;
    responseTime?: number;
    error?: string;
    timestamp: Date;
  }): void {
    // Store in context metrics for real-time access
    const operationMetrics = {
      timestamp: result.timestamp,
      successful: result.successful,
      responseTime: result.responseTime || 0,
      error: result.error
    };
    
    this.context.metrics.set(`${serviceId}_last_operation`, operationMetrics);
  }

  /**
   * Execute a worker task
   */
  private async executeWorkerTask<T = unknown>(message: IntegrationWorkerMessage): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      // Set up timeout
      const timeout = setTimeout(() => {
        this.pendingTasks.delete(message.id);
        reject(new Error(`Worker task timeout after ${message.timeout}ms`));
      }, message.timeout);
      
      // Store pending task
      this.pendingTasks.set(message.id, { resolve, reject, timeout });
      
      // Add to queue and process
      this.taskQueue.push(message);
      this.processTaskQueue();
    });
  }

  /**
   * Process worker task queue
   */
  private processTaskQueue(): void {
    if (this.taskQueue.length === 0) {
      return;
    }

    // Find available worker
    const availableWorker = this.workerPool.find(worker => worker.threadId !== undefined);
    if (availableWorker && this.taskQueue.length > 0) {
      const task = this.taskQueue.shift();
      if (task) {
        availableWorker.postMessage(task);
      }
    }

    // Schedule next processing if there are remaining tasks
    if (this.taskQueue.length > 0) {
      setImmediate(() => this.processTaskQueue());
    }
  }

  /**
   * Generate unique task ID
   */
  private generateTaskId(): string {
    return `task_${Date.now()}_${randomBytes(4).toString('hex')}`;
  }

  /**
   * Shutdown the integration agent
   */
  public async shutdown(): Promise<void> {
    if (this.isShutdown) {
      return;
    }

    this.isShutdown = true;
    logger.info('Shutting down Concurrent Integration Agent');

    try {
      // Clear intervals
      if (this.healthCheckInterval) {
        clearInterval(this.healthCheckInterval);
      }
      if (this.metricsInterval) {
        clearInterval(this.metricsInterval);
      }

      // Clear pending timeouts
      for (const [taskId, task] of this.pendingTasks) {
        if (task.timeout) {
          clearTimeout(task.timeout);
        }
        task.reject(new Error('Integration agent shutting down'));
      }
      this.pendingTasks.clear();

      // Terminate workers
      await Promise.all(
        this.workerPool.map(async (worker) => {
          try {
            await worker.terminate();
          } catch (error) {
            logger.error('Error terminating worker', { error });
          }
        })
      );

      this.workers.clear();
      this.workerPool.length = 0;
      this.taskQueue.length = 0;

      logger.info('Concurrent Integration Agent shutdown completed');
      this.emit('shutdown');
    } catch (error) {
      logger.error('Error during integration agent shutdown', {
        error: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }
}

// Singleton instance
export const concurrentIntegrationAgent = new ConcurrentIntegrationAgent();

export default ConcurrentIntegrationAgent;