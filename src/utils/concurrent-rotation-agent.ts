/**
 * Concurrent Credential Rotation Agent
 * Implements Worker Thread-based concurrent credential rotation with batch processing,
 * external service integration, and comprehensive lifecycle management
 */

import { Worker, isMainThread, parentPort, workerData } from "worker_threads";
import { EventEmitter } from "events";
import * as crypto from "crypto";
import { promisify } from "util";
import logger from "../lib/logger.js";
import { secureConfigManager } from "../lib/secure-config.js";
import type {
  CredentialRotationRequest,
  RotationBatch,
  RotationResult,
  RotationError,
  ExternalServiceConfig,
  ExternalServiceUpdate,
  ValidationRule,
  ValidationResult,
  WorkerMessage,
  WorkerResponse,
  AgentStatus,
  RotationManagerConfig,
} from "../types/rotation-types.js";

const sleep = promisify(setTimeout);

/**
 * Priority queue for credential rotation requests
 */
class RotationPriorityQueue {
  private readonly queues: Map<string, CredentialRotationRequest[]> = new Map();
  private readonly priorities = [
    "emergency",
    "critical",
    "high",
    "normal",
    "low",
  ];

  constructor() {
    // Initialize priority queues
    for (const priority of this.priorities) {
      this.queues.set(priority, []);
    }
  }

  enqueue(request: CredentialRotationRequest): void {
    const queue = this.queues.get(request.priority);
    if (queue) {
      // Sort by scheduled time if provided
      if (request.scheduledFor) {
        const insertIndex = queue.findIndex(
          (req) => req.scheduledFor && req.scheduledFor > request.scheduledFor!,
        );
        if (insertIndex === -1) {
          queue.push(request);
        } else {
          queue.splice(insertIndex, 0, request);
        }
      } else {
        queue.push(request);
      }
    }
  }

  dequeue(): CredentialRotationRequest | null {
    for (const priority of this.priorities) {
      const queue = this.queues.get(priority)!;
      if (queue.length > 0) {
        // Check if scheduled time has passed
        const request = queue[0];
        if (!request.scheduledFor || request.scheduledFor <= new Date()) {
          return queue.shift()!;
        }
      }
    }
    return null;
  }

  isEmpty(): boolean {
    return this.priorities.every(
      (priority) => this.queues.get(priority)!.length === 0,
    );
  }

  size(): number {
    return this.priorities.reduce(
      (total, priority) => total + this.queues.get(priority)!.length,
      0,
    );
  }

  peek(): CredentialRotationRequest | null {
    for (const priority of this.priorities) {
      const queue = this.queues.get(priority)!;
      if (queue.length > 0) {
        return queue[0];
      }
    }
    return null;
  }

  getQueueSizes(): Record<string, number> {
    const sizes: Record<string, number> = {};
    for (const [priority, queue] of this.queues) {
      sizes[priority] = queue.length;
    }
    return sizes;
  }
}

/**
 * Worker thread pool for concurrent rotation operations
 */
class WorkerThreadPool {
  private workers: Worker[] = [];
  private availableWorkers: Worker[] = [];
  private readonly busyWorkers: Set<Worker> = new Set();
  private readonly workerMessageMap: Map<
    string,
    (response: WorkerResponse) => void
  > = new Map();
  private readonly componentLogger;

  constructor(
    private readonly maxWorkers: number,
    private readonly workerScript: string,
  ) {
    this.componentLogger = logger.child({ component: "WorkerThreadPool" });
  }

  async initialize(): Promise<void> {
    this.componentLogger.info("Initializing worker thread pool", {
      maxWorkers: this.maxWorkers,
    });

    for (let i = 0; i < this.maxWorkers; i++) {
      await this.createWorker();
    }
  }

  private async createWorker(): Promise<Worker> {
    const worker = new Worker(this.workerScript, {
      workerData: { workerId: crypto.randomUUID() },
    });

    worker.on("message", (response: WorkerResponse) => {
      const callback = this.workerMessageMap.get(response.messageId);
      if (callback) {
        callback(response);
        this.workerMessageMap.delete(response.messageId);
      }

      // Return worker to available pool
      if (this.busyWorkers.has(worker)) {
        this.busyWorkers.delete(worker);
        this.availableWorkers.push(worker);
      }
    });

    worker.on("error", (error) => {
      this.componentLogger.error("Worker thread error", {
        workerId: workerData?.workerId,
        error: error.message,
      });

      // Remove failed worker and create replacement
      this.removeWorker(worker);
      this.createWorker().catch((err) =>
        this.componentLogger.error("Failed to create replacement worker", {
          error: err.message,
        }),
      );
    });

    worker.on("exit", (code) => {
      if (code !== 0) {
        this.componentLogger.warn("Worker thread exited with error", {
          workerId: workerData?.workerId,
          exitCode: code,
        });
      }
      this.removeWorker(worker);
    });

    this.workers.push(worker);
    this.availableWorkers.push(worker);

    return worker;
  }

  private removeWorker(worker: Worker): void {
    const workerIndex = this.workers.indexOf(worker);
    if (workerIndex !== -1) {
      this.workers.splice(workerIndex, 1);
    }

    const availableIndex = this.availableWorkers.indexOf(worker);
    if (availableIndex !== -1) {
      this.availableWorkers.splice(availableIndex, 1);
    }

    this.busyWorkers.delete(worker);
  }

  async executeTask<T = Record<string, unknown>>(
    message: WorkerMessage,
  ): Promise<T> {
    return new Promise((resolve, reject) => {
      const worker = this.availableWorkers.pop();
      if (!worker) {
        reject(new Error("No available workers"));
        return;
      }

      this.busyWorkers.add(worker);

      // Set up response handler
      this.workerMessageMap.set(
        message.messageId,
        (response: WorkerResponse) => {
          if (response.success) {
            resolve(response.result as T);
          } else {
            reject(new Error(response.error?.message || "Worker task failed"));
          }
        },
      );

      // Set up timeout
      const timeout = setTimeout(() => {
        this.workerMessageMap.delete(message.messageId);
        if (this.busyWorkers.has(worker)) {
          this.busyWorkers.delete(worker);
          this.availableWorkers.push(worker);
        }
        reject(new Error("Worker task timeout"));
      }, message.responseTimeout || 30000);

      // Send message to worker
      worker.postMessage(message);

      // Clear timeout when response is received
      const originalCallback = this.workerMessageMap.get(message.messageId);
      if (originalCallback) {
        this.workerMessageMap.set(
          message.messageId,
          (response: WorkerResponse) => {
            clearTimeout(timeout);
            originalCallback(response);
          },
        );
      }
    });
  }

  getStatus(): {
    totalWorkers: number;
    availableWorkers: number;
    busyWorkers: number;
    pendingTasks: number;
  } {
    return {
      totalWorkers: this.workers.length,
      availableWorkers: this.availableWorkers.length,
      busyWorkers: this.busyWorkers.size,
      pendingTasks: this.workerMessageMap.size,
    };
  }

  async shutdown(): Promise<void> {
    this.componentLogger.info("Shutting down worker thread pool");

    // Send shutdown message to all workers
    const shutdownPromises = this.workers.map(async (worker) => {
      const shutdownMessage: WorkerMessage = {
        type: "shutdown",
        messageId: crypto.randomUUID(),
        correlationId: crypto.randomUUID(),
        timestamp: new Date(),
        sourceAgent: "rotation_manager",
        targetAgent: "worker",
        payload: {},
        requiresResponse: false,
      };

      worker.postMessage(shutdownMessage);

      // Wait for worker to terminate gracefully
      return new Promise<void>((resolve) => {
        const timeout = setTimeout(() => {
          worker.terminate();
          resolve();
        }, 5000);

        worker.on("exit", () => {
          clearTimeout(timeout);
          resolve();
        });
      });
    });

    await Promise.all(shutdownPromises);
    this.workers = [];
    this.availableWorkers = [];
    this.busyWorkers.clear();
    this.workerMessageMap.clear();
  }
}

/**
 * External service integration manager
 */
class ExternalServiceManager {
  private readonly componentLogger;

  constructor() {
    this.componentLogger = logger.child({
      component: "ExternalServiceManager",
    });
  }

  async updateCredentialInService(
    serviceConfig: ExternalServiceConfig,
    oldCredentialId: string,
    newCredential: string,
    _correlationId: string,
  ): Promise<ExternalServiceUpdate> {
    const startTime = new Date();

    try {
      this.componentLogger.info("Updating credential in external service", {
        serviceId: serviceConfig.serviceId,
        serviceName: serviceConfig.serviceName,
        updateMethod: serviceConfig.updateMethod,
        correlationId: _correlationId,
      });

      let result: ExternalServiceUpdate;

      switch (serviceConfig.updateMethod) {
        case "rest_api":
          result = await this.updateViaRestApi(
            serviceConfig,
            newCredential,
            startTime,
            _correlationId,
          );
          break;
        case "database_update":
          result = await this.updateViaDatabase(
            serviceConfig,
            newCredential,
            startTime,
            _correlationId,
          );
          break;
        case "file_replacement":
          result = await this.updateViaFile(
            serviceConfig,
            newCredential,
            startTime,
            _correlationId,
          );
          break;
        case "custom_script":
          result = await this.updateViaCustomScript(
            serviceConfig,
            newCredential,
            startTime,
            _correlationId,
          );
          break;
        default:
          throw new Error(
            `Unsupported update method: ${serviceConfig.updateMethod}`,
          );
      }

      // Perform health check if configured
      if (serviceConfig.healthCheckEndpoint) {
        const healthCheck = await this.performHealthCheck(
          serviceConfig,
          _correlationId,
        );
        if (!healthCheck.success) {
          result.success = false;
          result.errorMessage = `Health check failed: ${healthCheck.errorMessage}`;
        }
      }

      this.componentLogger.info("External service update completed", {
        serviceId: serviceConfig.serviceId,
        success: result.success,
        responseTimeMs: result.responseTimeMs,
        correlationId: _correlationId,
      });

      return result;
    } catch (error) {
      const responseTimeMs = Date.now() - startTime.getTime();

      this.componentLogger.error("External service update failed", {
        serviceId: serviceConfig.serviceId,
        error: error instanceof Error ? error.message : "Unknown error",
        responseTimeMs,
        correlationId: _correlationId,
      });

      return {
        serviceId: serviceConfig.serviceId,
        serviceName: serviceConfig.serviceName,
        updateMethod: serviceConfig.updateMethod,
        startedAt: startTime,
        completedAt: new Date(),
        responseTimeMs,
        success: false,
        errorMessage: error instanceof Error ? error.message : "Unknown error",
        rollbackSupported: serviceConfig.rollbackSupported,
      };
    }
  }

  private async updateViaRestApi(
    serviceConfig: ExternalServiceConfig,
    newCredential: string,
    startTime: Date,
    _correlationId: string,
  ): Promise<ExternalServiceUpdate> {
    // Implementation would make HTTP request to update credential
    // For now, simulating the operation

    await sleep(100 + Math.random() * 200); // Simulate network delay

    const success = Math.random() > 0.05; // 95% success rate

    return {
      serviceId: serviceConfig.serviceId,
      serviceName: serviceConfig.serviceName,
      updateMethod: serviceConfig.updateMethod,
      requestPayload: {
        credential: "[REDACTED]",
        endpoint: serviceConfig.updateEndpoint,
      },
      responsePayload: success
        ? { status: "updated" }
        : { error: "Update failed" },
      startedAt: startTime,
      completedAt: new Date(),
      responseTimeMs: Date.now() - startTime.getTime(),
      success,
      httpStatusCode: success ? 200 : 500,
      errorMessage: success ? undefined : "Simulated update failure",
      rollbackSupported: serviceConfig.rollbackSupported,
    };
  }

  private async updateViaDatabase(
    serviceConfig: ExternalServiceConfig,
    _newCredential: string,
    startTime: Date,
    _correlationId: string,
  ): Promise<ExternalServiceUpdate> {
    // Implementation would execute database update
    await sleep(50 + Math.random() * 100); // Simulate database operation

    const success = Math.random() > 0.02; // 98% success rate

    return {
      serviceId: serviceConfig.serviceId,
      serviceName: serviceConfig.serviceName,
      updateMethod: serviceConfig.updateMethod,
      startedAt: startTime,
      completedAt: new Date(),
      responseTimeMs: Date.now() - startTime.getTime(),
      success,
      errorMessage: success ? undefined : "Database update failed",
      rollbackSupported: serviceConfig.rollbackSupported,
    };
  }

  private async updateViaFile(
    serviceConfig: ExternalServiceConfig,
    _newCredential: string,
    startTime: Date,
    _correlationId: string,
  ): Promise<ExternalServiceUpdate> {
    // Implementation would update configuration file
    await sleep(20 + Math.random() * 50); // Simulate file operation

    const success = Math.random() > 0.01; // 99% success rate

    return {
      serviceId: serviceConfig.serviceId,
      serviceName: serviceConfig.serviceName,
      updateMethod: serviceConfig.updateMethod,
      startedAt: startTime,
      completedAt: new Date(),
      responseTimeMs: Date.now() - startTime.getTime(),
      success,
      errorMessage: success ? undefined : "File update failed",
      rollbackSupported: serviceConfig.rollbackSupported,
    };
  }

  private async updateViaCustomScript(
    serviceConfig: ExternalServiceConfig,
    _newCredential: string,
    startTime: Date,
    _correlationId: string,
  ): Promise<ExternalServiceUpdate> {
    // Implementation would execute custom script
    await sleep(200 + Math.random() * 300); // Simulate script execution

    const success = Math.random() > 0.03; // 97% success rate

    return {
      serviceId: serviceConfig.serviceId,
      serviceName: serviceConfig.serviceName,
      updateMethod: serviceConfig.updateMethod,
      startedAt: startTime,
      completedAt: new Date(),
      responseTimeMs: Date.now() - startTime.getTime(),
      success,
      errorMessage: success ? undefined : "Custom script execution failed",
      rollbackSupported: serviceConfig.rollbackSupported,
    };
  }

  private async performHealthCheck(
    _serviceConfig: ExternalServiceConfig,
    _correlationId: string,
  ): Promise<{ success: boolean; errorMessage?: string }> {
    try {
      // Simulate health check
      await sleep(50 + Math.random() * 100);
      const success = Math.random() > 0.1; // 90% success rate

      return {
        success,
        errorMessage: success
          ? undefined
          : "Health check endpoint returned error",
      };
    } catch (error) {
      return {
        success: false,
        errorMessage:
          error instanceof Error ? error.message : "Health check failed",
      };
    }
  }
}

/**
 * Validation engine for pre/post rotation checks
 */
class ValidationEngine {
  private readonly componentLogger;

  constructor() {
    this.componentLogger = logger.child({ component: "ValidationEngine" });
  }

  async validateCredential(
    credentialId: string,
    newCredential: string,
    rules: ValidationRule[],
    correlationId: string,
  ): Promise<ValidationResult[]> {
    const results: ValidationResult[] = [];

    for (const rule of rules) {
      const result = await this.executeValidationRule(
        credentialId,
        newCredential,
        rule,
        correlationId,
      );
      results.push(result);

      // Stop on first failure if rule is critical
      if (!result.success && rule.type === "authentication") {
        this.componentLogger.warn(
          "Critical validation failed, stopping validation",
          {
            credentialId,
            ruleId: rule.id,
            correlationId,
          },
        );
        break;
      }
    }

    return results;
  }

  private async executeValidationRule(
    credentialId: string,
    newCredential: string,
    rule: ValidationRule,
    correlationId: string,
  ): Promise<ValidationResult> {
    const startTime = new Date();
    let attemptNumber = 1;
    let lastError: string | undefined;

    while (attemptNumber <= rule.maxRetries) {
      try {
        this.componentLogger.debug("Executing validation rule", {
          credentialId,
          ruleId: rule.id,
          ruleName: rule.name,
          attemptNumber,
          correlationId,
        });

        let success = false;
        let responsePayload: Record<string, unknown> | undefined;

        switch (rule.type) {
          case "connectivity":
            success = await this.testConnectivity(rule, newCredential);
            responsePayload = { connected: success };
            break;
          case "authentication":
            success = await this.testAuthentication(rule, newCredential);
            responsePayload = { authenticated: success };
            break;
          case "authorization":
            success = await this.testAuthorization(rule, newCredential);
            responsePayload = { authorized: success };
            break;
          case "custom": {
            const customResult = await this.executeCustomValidation(
              rule,
              newCredential,
            );
            success = customResult.success;
            responsePayload = customResult.payload;
            break;
          }
        }

        const endTime = new Date();

        return {
          ruleId: rule.id,
          ruleName: rule.name,
          success,
          testEndpoint: rule.testEndpoint,
          requestPayload: rule.testPayload,
          responsePayload,
          startedAt: startTime,
          completedAt: endTime,
          responseTimeMs: endTime.getTime() - startTime.getTime(),
          attemptNumber,
          finalAttempt: true,
        };
      } catch (error) {
        lastError = error instanceof Error ? error.message : "Unknown error";

        if (attemptNumber < rule.maxRetries) {
          this.componentLogger.warn("Validation rule failed, retrying", {
            credentialId,
            ruleId: rule.id,
            attemptNumber,
            error: lastError,
            correlationId,
          });

          await sleep(rule.retryInterval);
          attemptNumber++;
        } else {
          break;
        }
      }
    }

    // All attempts failed
    const endTime = new Date();

    return {
      ruleId: rule.id,
      ruleName: rule.name,
      success: false,
      testEndpoint: rule.testEndpoint,
      requestPayload: rule.testPayload,
      startedAt: startTime,
      completedAt: endTime,
      responseTimeMs: endTime.getTime() - startTime.getTime(),
      errorMessage: lastError,
      attemptNumber,
      finalAttempt: true,
    };
  }

  private async testConnectivity(
    _rule: ValidationRule,
    _credential: string,
  ): Promise<boolean> {
    // Simulate connectivity test
    await sleep(20 + Math.random() * 80);
    return Math.random() > 0.05; // 95% success rate
  }

  private async testAuthentication(
    _rule: ValidationRule,
    _credential: string,
  ): Promise<boolean> {
    // Simulate authentication test
    await sleep(50 + Math.random() * 150);
    return Math.random() > 0.1; // 90% success rate
  }

  private async testAuthorization(
    _rule: ValidationRule,
    _credential: string,
  ): Promise<boolean> {
    // Simulate authorization test
    await sleep(30 + Math.random() * 100);
    return Math.random() > 0.08; // 92% success rate
  }

  private async executeCustomValidation(
    _rule: ValidationRule,
    _credential: string,
  ): Promise<{ success: boolean; payload?: Record<string, unknown> }> {
    // Simulate custom validation
    await sleep(100 + Math.random() * 200);

    const success = Math.random() > 0.15; // 85% success rate
    return {
      success,
      payload: { customValidation: success, timestamp: new Date() },
    };
  }
}

/**
 * Main Concurrent Rotation Agent
 * Coordinates all rotation operations with worker thread pool
 */
export class ConcurrentRotationAgent extends EventEmitter {
  private readonly componentLogger;
  private readonly queue: RotationPriorityQueue;
  private readonly workerPool: WorkerThreadPool;
  private readonly externalServiceManager: ExternalServiceManager;
  private readonly validationEngine: ValidationEngine;

  private isRunning = false;
  private shutdownRequested = false;
  private readonly config: RotationManagerConfig;
  private readonly status: AgentStatus;

  // Performance tracking
  private readonly startTime = new Date();
  private totalOperationsProcessed = 0;
  private totalProcessingTimeMs = 0;
  private errorCount = 0;

  // Active operations tracking
  private readonly activeRotations: Map<string, Date> = new Map();
  private readonly completedRotations: RotationResult[] = [];
  private readonly failedRotations: RotationError[] = [];

  constructor(config: RotationManagerConfig) {
    super();
    this.config = config;
    this.componentLogger = logger.child({
      component: "ConcurrentRotationAgent",
    });
    this.queue = new RotationPriorityQueue();
    this.workerPool = new WorkerThreadPool(
      config.maxWorkerThreads,
      __filename, // Use current file as worker script
    );
    this.externalServiceManager = new ExternalServiceManager();
    this.validationEngine = new ValidationEngine();

    this.status = {
      agentId: "rotation_manager",
      agentType: "rotation",
      status: "starting",
      lastHeartbeat: new Date(),
      startedAt: this.startTime,
      activeOperations: 0,
      totalOperationsProcessed: 0,
      averageProcessingTimeMs: 0,
      errorRate: 0,
      memoryUsageMB: 0,
      cpuUsagePercent: 0,
      workerThreadCount: config.maxWorkerThreads,
      pendingMessages: 0,
      processedMessages: 0,
      failedMessages: 0,
    };
  }

  async initialize(): Promise<void> {
    this.componentLogger.info("Initializing Concurrent Rotation Agent", {
      maxWorkerThreads: this.config.maxWorkerThreads,
      defaultConcurrency: this.config.defaultConcurrency,
    });

    try {
      await this.workerPool.initialize();
      this.status.status = "healthy";
      this.emit("initialized");

      this.componentLogger.info(
        "Concurrent Rotation Agent initialized successfully",
      );
    } catch (error) {
      this.status.status = "error";
      this.status.lastError = {
        timestamp: new Date(),
        message: error instanceof Error ? error.message : "Unknown error",
        code: "INITIALIZATION_FAILED",
      };
      throw error;
    }
  }

  async start(): Promise<void> {
    if (this.isRunning) {
      this.componentLogger.warn("Agent is already running");
      return;
    }

    this.isRunning = true;
    this.shutdownRequested = false;
    this.status.status = "healthy";

    this.componentLogger.info("Starting Concurrent Rotation Agent");

    // Start processing loop
    this.processQueue().catch((error) => {
      this.componentLogger.error("Queue processing error", {
        error: error.message,
      });
      this.status.status = "error";
      this.emit("error", error);
    });

    // Start health monitoring
    this.startHealthMonitoring();

    this.emit("started");
  }

  async stop(): Promise<void> {
    this.componentLogger.info("Stopping Concurrent Rotation Agent");

    this.shutdownRequested = true;
    this.status.status = "shutting_down";

    // Wait for active operations to complete
    const maxWaitTime = 30000; // 30 seconds
    const startWaitTime = Date.now();

    while (
      this.activeRotations.size > 0 &&
      Date.now() - startWaitTime < maxWaitTime
    ) {
      this.componentLogger.info("Waiting for active operations to complete", {
        activeOperations: this.activeRotations.size,
      });
      await sleep(1000);
    }

    // Shutdown worker pool
    await this.workerPool.shutdown();

    this.isRunning = false;
    this.emit("stopped");

    this.componentLogger.info("Concurrent Rotation Agent stopped");
  }

  enqueueRotation(request: CredentialRotationRequest): void {
    this.componentLogger.info("Enqueueing rotation request", {
      credentialId: request.credentialId,
      priority: request.priority,
      scheduledFor: request.scheduledFor?.toISOString(),
    });

    this.queue.enqueue(request);
    this.emit("rotation_enqueued", request);
  }

  enqueueBatch(batch: RotationBatch): void {
    this.componentLogger.info("Enqueueing rotation batch", {
      batchId: batch.batchId,
      requestCount: batch.requests.length,
      priority: batch.priority,
    });

    for (const request of batch.requests) {
      request.priority = batch.priority; // Inherit batch priority
      this.queue.enqueue(request);
    }

    this.emit("batch_enqueued", batch);
  }

  private async processQueue(): Promise<void> {
    while (this.isRunning && !this.shutdownRequested) {
      try {
        if (this.queue.isEmpty()) {
          await sleep(100); // Check queue every 100ms
          continue;
        }

        // Check if we have capacity for more concurrent operations
        const currentConcurrency = this.activeRotations.size;
        if (currentConcurrency >= this.config.defaultConcurrency) {
          await sleep(10); // Brief wait before checking again
          continue;
        }

        const request = this.queue.dequeue();
        if (!request) {
          continue;
        }

        // Process rotation request
        this.processRotationRequest(request).catch((error) => {
          this.componentLogger.error("Rotation processing error", {
            credentialId: request.credentialId,
            error: error.message,
          });
          this.recordFailedRotation(request, error);
        });
      } catch (error) {
        this.componentLogger.error("Queue processing loop error", {
          error: error instanceof Error ? error.message : "Unknown error",
        });
        await sleep(1000); // Wait before retrying
      }
    }
  }

  private async processRotationRequest(
    request: CredentialRotationRequest,
  ): Promise<void> {
    const startTime = new Date();
    this.activeRotations.set(request.credentialId, startTime);
    this.status.activeOperations = this.activeRotations.size;

    const correlationId = crypto.randomUUID();

    try {
      this.componentLogger.info("Processing rotation request", {
        credentialId: request.credentialId,
        correlationId,
      });

      // Step 1: Pre-rotation validation
      let preValidationResults: ValidationResult[] = [];
      if (
        request.preRotationValidation &&
        request.preRotationValidation.length > 0
      ) {
        const currentCredential = await secureConfigManager.getCredential(
          request.credentialId,
          request.userId,
        );
        preValidationResults = await this.validationEngine.validateCredential(
          request.credentialId,
          currentCredential,
          request.preRotationValidation,
          correlationId,
        );

        // Check if any critical validation failed
        const criticalFailure = preValidationResults.find(
          (result) =>
            !result.success &&
            request.preRotationValidation?.find(
              (rule) => rule.id === result.ruleId,
            )?.type === "authentication",
        );

        if (criticalFailure) {
          throw new Error(
            `Pre-rotation validation failed: ${criticalFailure.errorMessage}`,
          );
        }
      }

      // Step 2: Perform credential rotation
      const newCredentialId = await secureConfigManager.rotateCredential(
        request.credentialId,
        {
          newValue: request.newValue,
          gracePeriod: request.gracePeriod,
          userId: request.userId,
        },
      );

      const newCredential = await secureConfigManager.getCredential(
        newCredentialId,
        request.userId,
      );

      // Step 3: Update external services
      const externalServiceUpdates: ExternalServiceUpdate[] = [];
      if (request.externalServices && request.externalServices.length > 0) {
        for (const serviceConfig of request.externalServices) {
          const update =
            await this.externalServiceManager.updateCredentialInService(
              serviceConfig,
              request.credentialId,
              newCredential,
              correlationId,
            );
          externalServiceUpdates.push(update);

          // Fail fast if critical service update fails
          if (!update.success && !serviceConfig.rollbackSupported) {
            throw new Error(
              `External service update failed: ${update.errorMessage}`,
            );
          }
        }
      }

      // Step 4: Post-rotation validation
      let postValidationResults: ValidationResult[] = [];
      if (
        request.postRotationValidation &&
        request.postRotationValidation.length > 0
      ) {
        postValidationResults = await this.validationEngine.validateCredential(
          newCredentialId,
          newCredential,
          request.postRotationValidation,
          correlationId,
        );

        // Check if any validation failed
        const validationFailure = postValidationResults.find(
          (result) => !result.success,
        );
        if (validationFailure) {
          this.componentLogger.warn("Post-rotation validation failed", {
            credentialId: newCredentialId,
            ruleId: validationFailure.ruleId,
            error: validationFailure.errorMessage,
          });
          // Continue anyway, but log the issue
        }
      }

      // Step 5: Record successful rotation
      const completedTime = new Date();
      const processingTime = completedTime.getTime() - startTime.getTime();

      const result: RotationResult = {
        credentialId: newCredentialId,
        oldCredentialId: request.credentialId,
        newCredentialId,
        startedAt: startTime,
        completedAt: completedTime,
        processingTimeMs: processingTime,
        externalServiceUpdates,
        preValidationResults,
        postValidationResults,
        auditEventIds: [correlationId],
      };

      this.recordSuccessfulRotation(result);
      this.emit("rotation_completed", result);

      this.componentLogger.info("Rotation completed successfully", {
        oldCredentialId: request.credentialId,
        newCredentialId,
        processingTimeMs: processingTime,
        correlationId,
      });
    } catch (error) {
      const completedTime = new Date();
      const processingTime = completedTime.getTime() - startTime.getTime();

      const rotationError: RotationError = {
        credentialId: request.credentialId,
        errorCode: "ROTATION_FAILED",
        errorMessage: error instanceof Error ? error.message : "Unknown error",
        phase: "rotation",
        attemptNumber: 1,
        timestamp: completedTime,
        stack: error instanceof Error ? error.stack : undefined,
        context: { request, correlationId },
        recoverable: true,
        rollbackRequired: false,
        rollbackCompleted: false,
      };

      this.recordFailedRotation(request, error, rotationError);
      this.emit("rotation_failed", rotationError);

      this.componentLogger.error("Rotation failed", {
        credentialId: request.credentialId,
        error: rotationError.errorMessage,
        processingTimeMs: processingTime,
        correlationId,
      });
    } finally {
      // Clean up active rotation tracking
      this.activeRotations.delete(request.credentialId);
      this.status.activeOperations = this.activeRotations.size;
      this.updatePerformanceMetrics();
    }
  }

  private recordSuccessfulRotation(result: RotationResult): void {
    this.completedRotations.push(result);
    this.totalOperationsProcessed++;
    this.totalProcessingTimeMs += result.processingTimeMs;
    this.status.totalOperationsProcessed = this.totalOperationsProcessed;
    this.status.averageProcessingTimeMs = Math.round(
      this.totalProcessingTimeMs / this.totalOperationsProcessed,
    );
  }

  private recordFailedRotation(
    request: CredentialRotationRequest,
    error: unknown,
    rotationError?: RotationError,
  ): void {
    if (rotationError) {
      this.failedRotations.push(rotationError);
    }

    this.totalOperationsProcessed++;
    this.errorCount++;
    this.status.totalOperationsProcessed = this.totalOperationsProcessed;
    this.status.errorRate = this.errorCount / this.totalOperationsProcessed;
    this.status.lastError = {
      timestamp: new Date(),
      message: error instanceof Error ? error.message : "Unknown error",
      code: rotationError?.errorCode || "UNKNOWN_ERROR",
    };
  }

  private updatePerformanceMetrics(): void {
    // Update memory usage (simplified)
    const memoryUsage = process.memoryUsage();
    this.status.memoryUsageMB = Math.round(memoryUsage.heapUsed / 1024 / 1024);

    // Update heartbeat
    this.status.lastHeartbeat = new Date();

    // Update worker thread status
    const workerStatus = this.workerPool.getStatus();
    this.status.pendingMessages = workerStatus.pendingTasks;
  }

  private startHealthMonitoring(): void {
    const healthCheckInterval = setInterval(() => {
      if (this.shutdownRequested) {
        clearInterval(healthCheckInterval);
        return;
      }

      this.updatePerformanceMetrics();

      // Emit health status
      this.emit("health_update", {
        status: this.status,
        queueSizes: this.queue.getQueueSizes(),
        workerStatus: this.workerPool.getStatus(),
      });
    }, this.config.metricsCollectionIntervalMs || 5000);
  }

  getStatus(): AgentStatus {
    return { ...this.status };
  }

  getQueueStatus(): {
    totalPending: number;
    queueSizes: Record<string, number>;
    activeOperations: number;
  } {
    return {
      totalPending: this.queue.size(),
      queueSizes: this.queue.getQueueSizes(),
      activeOperations: this.activeRotations.size,
    };
  }

  getPerformanceMetrics(): {
    totalOperationsProcessed: number;
    averageProcessingTimeMs: number;
    errorRate: number;
    successfulRotations: number;
    failedRotations: number;
  } {
    return {
      totalOperationsProcessed: this.totalOperationsProcessed,
      averageProcessingTimeMs: this.status.averageProcessingTimeMs,
      errorRate: this.status.errorRate,
      successfulRotations: this.completedRotations.length,
      failedRotations: this.failedRotations.length,
    };
  }
}

// Worker thread implementation for when running in worker context
if (!isMainThread && parentPort) {
  // Worker thread logic for processing rotation tasks
  const workerId = workerData?.workerId || "unknown";
  const workerLogger = logger.child({ component: "RotationWorker", workerId });

  parentPort.on("message", async (message: WorkerMessage) => {
    const startTime = Date.now();

    try {
      workerLogger.debug("Processing worker message", {
        messageType: message.type,
        messageId: message.messageId,
      });

      let result: Record<string, unknown>;

      switch (message.type) {
        case "rotation_request":
          // Process individual rotation in worker thread
          result = await processRotationInWorker(message.payload);
          break;
        case "validation_request":
          // Process validation in worker thread
          result = await processValidationInWorker(message.payload);
          break;
        case "external_update_request":
          // Process external service update in worker thread
          result = await processExternalUpdateInWorker(message.payload);
          break;
        case "shutdown":
          workerLogger.info("Worker shutting down");
          process.exit(0);
          break;
        default:
          throw new Error(`Unsupported message type: ${message.type}`);
      }

      const response: WorkerResponse = {
        messageId: message.messageId,
        correlationId: message.correlationId,
        timestamp: new Date(),
        sourceAgent: workerId,
        success: true,
        result,
        processingTimeMs: Date.now() - startTime,
      };

      parentPort!.postMessage(response);
    } catch (error) {
      const response: WorkerResponse = {
        messageId: message.messageId,
        correlationId: message.correlationId,
        timestamp: new Date(),
        sourceAgent: workerId,
        success: false,
        error: {
          code: "WORKER_ERROR",
          message: error instanceof Error ? error.message : "Unknown error",
          stack: error instanceof Error ? error.stack : undefined,
        },
        processingTimeMs: Date.now() - startTime,
      };

      parentPort!.postMessage(response);
    }
  });

  // Worker-specific functions
  async function processRotationInWorker(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    // Implementation would handle rotation logic in worker thread
    return { status: "rotated", credentialId: payload.credentialId };
  }

  async function processValidationInWorker(
    _payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    // Implementation would handle validation logic in worker thread
    return { status: "validated", results: [] };
  }

  async function processExternalUpdateInWorker(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    // Implementation would handle external service updates in worker thread
    return { status: "updated", services: payload.services || [] };
  }

  workerLogger.info("Rotation worker initialized", { workerId });
}

export default ConcurrentRotationAgent;
