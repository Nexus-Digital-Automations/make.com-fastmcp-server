/**
 * Rotation Coordinator Agent - Central orchestrator for credential rotation operations
 * Manages Worker Thread pools, coordinates batch operations, and handles lifecycle management
 */

import { Worker } from "worker_threads";
import {
  RotationAgentBase,
  AgentConfig,
  AgentMessage,
} from "../rotation-agent-base.js";
import type {
  CredentialRotationRequest,
  RotationBatch,
  RotationPolicy,
} from "../../types/rotation-types.js";
import * as crypto from "crypto";
import * as os from "os";
import * as path from "path";

/**
 * Worker thread pool for concurrent rotation operations
 */
class RotationWorkerPool {
  private readonly workers: Worker[] = [];
  private readonly availableWorkers: Worker[] = [];
  private readonly busyWorkers: Set<Worker> = new Set();
  private readonly workerMessageMap: Map<string, (parameter: unknown) => void> =
    new Map();
  private readonly componentLogger;

  constructor(
    private readonly maxWorkers: number,
    private readonly workerTimeoutMs: number,
    private readonly componentLogger: unknown,
  ) {
    this.componentLogger = componentLogger.child({
      component: "RotationWorkerPool",
    });
  }

  async initialize(): Promise<void> {
    this.componentLogger.info("Initializing worker thread pool", {
      maxWorkers: this.maxWorkers,
    });

    // Create worker script path - we'll create a separate worker file
    const workerScriptPath = path.join(
      process.cwd(),
      "dist/utils/workers/rotation-worker.js",
    );

    for (let i = 0; i < this.maxWorkers; i++) {
      await this.createWorker(workerScriptPath);
    }

    this.componentLogger.info("Worker thread pool initialized", {
      totalWorkers: this.workers.length,
      availableWorkers: this.availableWorkers.length,
    });
  }

  private async createWorker(scriptPath: string): Promise<Worker> {
    const worker = new Worker(scriptPath, {
      workerData: { workerId: crypto.randomUUID() },
    });

    worker.on('message', (response: unknown) => {
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
        error: error.message,
      });
      this.removeWorker(worker);

      // Create replacement worker
      this.createWorker(scriptPath).catch((err) =>
        this.componentLogger.error("Failed to create replacement worker", {
          error: err.message,
        }),
      );
    });

    worker.on("exit", (code) => {
      if (code !== 0) {
        this.componentLogger.warn("Worker thread exited with error", {
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

  async executeTask(
    taskType: string,
    taskData: Record<string, unknown>,
    timeoutMs?: number,
  ): Promise<Record<string, unknown>> {
    if (this.availableWorkers.length === 0) {
      throw new Error("No available workers");
    }

    const worker = this.availableWorkers.pop()!;
    this.busyWorkers.add(worker);

    const messageId = crypto.randomUUID();
    const timeout = timeoutMs || this.workerTimeoutMs;

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.workerMessageMap.delete(messageId);
        this.busyWorkers.delete(worker);
        this.availableWorkers.push(worker);
        reject(new Error(`Worker task timeout after ${timeout}ms`));
      }, timeout);

      this.workerMessageMap.set(parameter: unknown) => {
        clearTimeout(timer);
        if (response.success) {
          resolve(response.data);
        } else {
          reject(new Error(response.error));
        }
      });

      worker.postMessage({
        messageId,
        type: taskType,
        data: taskData,
      });
    });
  }

  getStatus(): Record<string, unknown> {
    return {
      totalWorkers: this.workers.length,
      availableWorkers: this.availableWorkers.length,
      busyWorkers: this.busyWorkers.size,
      pendingTasks: this.workerMessageMap.size,
    };
  }

  async shutdown(): Promise<void> {
    this.componentLogger.info("Shutting down worker pool");

    // Terminate all workers
    await Promise.all(this.workers.map((worker) => worker.terminate()));

    this.workers.clear();
    this.availableWorkers.clear();
    this.busyWorkers.clear();
    this.workerMessageMap.clear();

    this.componentLogger.info("Worker pool shutdown completed");
  }
}

/**
 * Priority queue for rotation batches
 */
class BatchPriorityQueue {
  private readonly queues: Map<string, RotationBatch[]> = new Map();
  private readonly priorities = [
    "emergency",
    "critical",
    "high",
    "normal",
    "low",
  ];

  constructor() {
    this.priorities.forEach((priority) => {
      this.queues.set(priority, []);
    });
  }

  enqueue(batch: RotationBatch): void {
    const queue = this.queues.get(batch.priority);
    if (queue) {
      queue.push(batch);
    }
  }

  dequeue(): RotationBatch | null {
    for (const priority of this.priorities) {
      const queue = this.queues.get(priority)!;
      if (queue.length > 0) {
        return queue.shift()!;
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

  getQueueSizes(): Record<string, number> {
    const sizes: Record<string, number> = {};
    for (const [priority, queue] of this.queues) {
      sizes[priority] = queue.length;
    }
    return sizes;
  }
}

/**
 * Rotation Coordinator Agent configuration
 */
export interface RotationCoordinatorConfig extends AgentConfig {
  maxWorkerThreads?: number;
  workerTimeoutMs?: number;
  maxQueueSize?: number;
  batchProcessingIntervalMs?: number;
  defaultConcurrency?: number;
  maxBatchSize?: number;
  performanceThresholds?: {
    maxRotationTimeMs: number;
    maxMemoryUsageMB: number;
    maxCpuUsagePercent: number;
    maxErrorRate: number;
  };
}

/**
 * Rotation Coordinator Agent - orchestrates all rotation operations
 */
export class RotationCoordinatorAgent extends RotationAgentBase {
  private readonly config: RotationCoordinatorConfig;
  private workerPool?: RotationWorkerPool;
  private readonly batchQueue: BatchPriorityQueue;
  private readonly activeBatches: Map<string, RotationBatch> = new Map();
  private readonly policies: Map<string, RotationPolicy> = new Map();

  // Performance tracking
  private rotationCount = 0;
  private totalRotationTime = 0;
  private failedRotationCount = 0;

  // Processing control
  private batchProcessingTimer?: NodeJS.Timeout;
  private isProcessing = false;

  constructor(config: RotationCoordinatorConfig) {
    super({
      ...config,
      role: "rotation",
    });

    this.config = config;
    this.batchQueue = new BatchPriorityQueue();

    this.componentLogger.info("Rotation Coordinator Agent created", {
      maxWorkerThreads: config.maxWorkerThreads,
      maxQueueSize: config.maxQueueSize,
    });
  }

  protected async initializeAgent(): Promise<void> {
    this.componentLogger.info("Initializing Rotation Coordinator Agent");

    // Initialize worker pool
    const workerCount =
      this.config.maxWorkerThreads || Math.min(4, os.cpus().length);
    const workerTimeout = this.config.workerTimeoutMs || 30000;

    this.workerPool = new RotationWorkerPool(
      workerCount,
      workerTimeout,
      this.componentLogger,
    );

    await this.workerPool.initialize();

    // Start batch processing
    this.startBatchProcessing();

    // Load default policies
    this.loadDefaultPolicies();

    this.componentLogger.info(
      "Rotation Coordinator Agent initialized successfully",
    );
  }

  protected async shutdownAgent(): Promise<void> {
    this.componentLogger.info("Shutting down Rotation Coordinator Agent");

    // Stop batch processing
    if (this.batchProcessingTimer) {
      clearInterval(this.batchProcessingTimer);
    }

    // Wait for active batches to complete or timeout
    if (this.activeBatches.size > 0) {
      this.componentLogger.info("Waiting for active batches to complete", {
        activeBatches: this.activeBatches.size,
      });

      // Wait up to 30 seconds for completion
      const timeout = 30000;
      const start = Date.now();

      while (this.activeBatches.size > 0 && Date.now() - start < timeout) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    }

    // Shutdown worker pool
    if (this.workerPool) {
      await this.workerPool.shutdown();
    }

    this.componentLogger.info("Rotation Coordinator Agent shutdown completed");
  }

  protected async processMessage(
    message: AgentMessage,
  ): Promise<Record<string, unknown>> {
    const { type, payload } = message;

    switch (type) {
      case "rotate_credential":
        return this.handleSingleRotation(payload);

      case "rotate_batch":
        return this.handleBatchRotation(payload);

      case "get_rotation_status":
        return this.getRotationStatus(payload);

      case "add_policy":
        return this.addRotationPolicy(payload);

      case "get_queue_status":
        return this.getQueueStatus();

      case "perform_rotation":
      case "perform_emergency_rotation":
        return this.performRotation(
          payload,
          type === "perform_emergency_rotation",
        );

      default:
        throw new Error(`Unknown message type: ${type}`);
    }
  }

  private async handleSingleRotation(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const request = payload as CredentialRotationRequest;

    // Create single-item batch
    const batch: RotationBatch = {
      batchId: `single_${crypto.randomUUID()}`,
      createdAt: new Date(),
      status: "pending",
      requests: [request],
      concurrency: 1,
      priority: request.priority,
      processedCount: 0,
      successCount: 0,
      failedCount: 0,
    };

    // Queue for processing
    this.batchQueue.enqueue(batch);

    return { batchId: batch.batchId, queued: true };
  }

  private async handleBatchRotation(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const batch = payload as RotationBatch;

    // Validate batch
    if (!batch.requests || batch.requests.length === 0) {
      throw new Error("Batch must contain at least one rotation request");
    }

    const maxBatchSize = this.config.maxBatchSize || 50;
    if (batch.requests.length > maxBatchSize) {
      throw new Error(
        `Batch size ${batch.requests.length} exceeds maximum ${maxBatchSize}`,
      );
    }

    // Queue for processing
    this.batchQueue.enqueue(batch);

    return {
      batchId: batch.batchId,
      queued: true,
      requests: batch.requests.length,
    };
  }

  private async performRotation(
    payload: Record<string, unknown>,
    emergency = false,
  ): Promise<Record<string, unknown>> {
    if (!this.workerPool) {
      throw new Error("Worker pool not initialized");
    }

    const startTime = Date.now();

    try {
      const result = await this.workerPool.executeTask(
        emergency ? "emergency_rotation" : "rotation",
        payload,
        emergency ? 15000 : 60000, // Emergency rotations have shorter timeout
      );

      const duration = Date.now() - startTime;
      this.rotationCount++;
      this.totalRotationTime += duration;

      this.componentLogger.info("Rotation completed successfully", {
        credentialId: payload.credentialId,
        emergency,
        durationMs: duration,
      });

      return {
        ...result,
        performanceMs: duration,
        emergency,
      };
    } catch (error) {
      this.failedRotationCount++;

      this.componentLogger.error("Rotation failed", {
        credentialId: payload.credentialId,
        emergency,
        error: error instanceof Error ? error.message : "Unknown error",
      });

      throw error;
    }
  }

  private getRotationStatus(
    payload: Record<string, unknown>,
  ): Record<string, unknown> {
    const { credentialId } = payload;

    // Find in active batches
    for (const [batchId, batch] of this.activeBatches) {
      const request = batch.requests.find(
        (r) => r.credentialId === credentialId,
      );
      if (request) {
        return {
          credentialId,
          status: batch.status,
          batchId,
          priority: request.priority,
        };
      }
    }

    return {
      credentialId,
      status: "not_found",
    };
  }

  private addRotationPolicy(
    payload: Record<string, unknown>,
  ): Record<string, unknown> {
    const policy = payload as RotationPolicy;

    this.policies.set(policy.id, policy);

    this.componentLogger.info("Rotation policy added", {
      policyId: policy.id,
      type: policy.type,
      enabled: policy.enabled,
    });

    return { policyId: policy.id, added: true };
  }

  private getQueueStatus(): Record<string, unknown> {
    return {
      queueSizes: this.batchQueue.getQueueSizes(),
      totalQueued: this.batchQueue.size(),
      activeBatches: this.activeBatches.size,
      workerPoolStatus: this.workerPool?.getStatus(),
      performance: this.getPerformanceMetrics(),
    };
  }

  private startBatchProcessing(): void {
    const intervalMs = this.config.batchProcessingIntervalMs || 1000;

    this.batchProcessingTimer = setInterval(async () => {
      if (this.isProcessing || this.batchQueue.isEmpty()) {
        return;
      }

      try {
        this.isProcessing = true;
        await this.processBatchQueue();
      } catch (error) {
        this.componentLogger.error("Batch processing error", {
          error: error instanceof Error ? error.message : "Unknown error",
        });
      } finally {
        this.isProcessing = false;
      }
    }, intervalMs);
  }

  private async processBatchQueue(): Promise<void> {
    const batch = this.batchQueue.dequeue();
    if (!batch) {
      return;
    }

    this.componentLogger.info("Processing rotation batch", {
      batchId: batch.batchId,
      requests: batch.requests.length,
      priority: batch.priority,
    });

    batch.status = "processing";
    this.activeBatches.set(batch.batchId, batch);

    try {
      // Process batch with specified concurrency
      await this.processBatch(batch);

      batch.status = "completed";
      this.componentLogger.info("Batch processing completed", {
        batchId: batch.batchId,
        successCount: batch.successCount,
        failedCount: batch.failedCount,
      });
    } catch (error) {
      batch.status = "failed";
      this.componentLogger.error("Batch processing failed", {
        batchId: batch.batchId,
        error: error instanceof Error ? error.message : "Unknown error",
      });
    } finally {
      this.activeBatches.delete(batch.batchId);
    }
  }

  private async processBatch(batch: RotationBatch): Promise<void> {
    if (!this.workerPool) {
      throw new Error("Worker pool not initialized");
    }

    const concurrency = Math.min(batch.concurrency, batch.requests.length);
    const _semaphore = new Array(concurrency).fill(null);

    // Process requests in parallel with controlled concurrency
    const processRequest = async (
      request: CredentialRotationRequest,
    ): Promise<void> => {
      try {
        await this.workerPool!.executeTask("rotation", request);
        batch.successCount++;
        this.componentLogger.debug("Batch item completed", {
          batchId: batch.batchId,
          credentialId: request.credentialId,
        });
      } catch (error) {
        batch.failedCount++;
        this.componentLogger.error("Batch item failed", {
          batchId: batch.batchId,
          credentialId: request.credentialId,
          error: error instanceof Error ? error.message : "Unknown error",
        });
      } finally {
        batch.processedCount++;
      }
    };

    // Use Promise.all with controlled concurrency
    const promises: Promise<void>[] = [];

    for (let i = 0; i < batch.requests.length; i += concurrency) {
      const chunk = batch.requests.slice(i, i + concurrency);
      const chunkPromises = chunk.map(processRequest);
      promises.push(...chunkPromises);

      // Wait for this chunk to complete before starting the next
      if (i + concurrency < batch.requests.length) {
        await Promise.all(chunkPromises);
      }
    }

    // Wait for all remaining requests
    await Promise.all(promises);
  }

  private loadDefaultPolicies(): void {
    const defaultPolicies: RotationPolicy[] = [
      {
        id: "api_key_enhanced",
        name: "Enhanced API Key Rotation",
        type: "time_based",
        enabled: true,
        interval: 90 * 24 * 60 * 60 * 1000, // 90 days
        gracePeriod: 7 * 24 * 60 * 60 * 1000, // 7 days
        notifyBeforeExpiry: 14 * 24 * 60 * 60 * 1000, // 14 days
        maxAge: 180 * 24 * 60 * 60 * 1000, // 180 days
        maxRetries: 3,
        retryInterval: 5 * 60 * 1000, // 5 minutes
      },
      {
        id: "emergency",
        name: "Emergency Credential Rotation",
        type: "emergency",
        enabled: true,
        gracePeriod: 5 * 60 * 1000, // 5 minutes
        notifyBeforeExpiry: 0, // Immediate
        maxAge: 15 * 60 * 1000, // 15 minutes max age
        maxRetries: 1,
        retryInterval: 30 * 1000, // 30 seconds
      },
    ];

    defaultPolicies.forEach((policy) => {
      this.policies.set(policy.id, policy);
    });

    this.componentLogger.info("Default rotation policies loaded", {
      policies: defaultPolicies.map((p) => p.id),
    });
  }

  public override getPerformanceMetrics(): Record<string, unknown> {
    const baseMetrics = super.getPerformanceMetrics();
    const avgRotationTime =
      this.rotationCount > 0 ? this.totalRotationTime / this.rotationCount : 0;

    return {
      ...baseMetrics,
      rotationMetrics: {
        totalRotations: this.rotationCount,
        failedRotations: this.failedRotationCount,
        successRate:
          this.rotationCount > 0
            ? (this.rotationCount - this.failedRotationCount) /
              this.rotationCount
            : 0,
        avgRotationTimeMs: Math.round(avgRotationTime),
      },
      queueMetrics: {
        queueSizes: this.batchQueue.getQueueSizes(),
        activeBatches: this.activeBatches.size,
      },
      workerPoolMetrics: this.workerPool?.getStatus(),
    };
  }
}

export default RotationCoordinatorAgent;
