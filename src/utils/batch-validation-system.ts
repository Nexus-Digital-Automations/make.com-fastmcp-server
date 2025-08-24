/**
 * @fileoverview Batch Validation System for Parallel Credential Processing
 *
 * Implements high-performance batch processing capabilities for credential validation
 * with intelligent load balancing, failure recovery, and comprehensive analytics.
 */

import { EventEmitter } from "events";
import * as crypto from "crypto";
import { performance } from "perf_hooks";
import logger from "../lib/logger.js";
import {
  ConcurrentValidationAgent,
  ValidationJob,
  EnhancedValidationResult,
} from "./concurrent-validation-agent.js";
import {
  BatchValidationRequest,
  BatchValidationResult,
  BatchInsights,
  CommonIssue,
  CredentialType,
  SecuritySeverity,
  ComplianceFramework,
  SecurityGrade,
} from "../types/credential-validation.js";

/**
 * Batch processing statistics
 */
interface BatchProcessingStats {
  batchId: string;
  startTime: number;
  endTime?: number;
  totalJobs: number;
  completedJobs: number;
  failedJobs: number;
  averageProcessingTime: number;
  throughput: number;
  memoryUsage: number;
  cpuUsage: number;
}

/**
 * Batch validation configuration
 */
interface BatchValidationConfig {
  /** Maximum concurrent batches */
  maxConcurrentBatches: number;
  /** Default batch timeout */
  defaultBatchTimeoutMs: number;
  /** Maximum batch size */
  maxBatchSize: number;
  /** Enable batch analytics */
  enableAnalytics: boolean;
  /** Enable performance monitoring */
  enablePerformanceMonitoring: boolean;
  /** Retry configuration */
  retryConfig: {
    maxRetries: number;
    retryDelayMs: number;
    exponentialBackoff: boolean;
  };
  /** Load balancing strategy */
  loadBalancingStrategy:
    | "round-robin"
    | "least-loaded"
    | "credential-type"
    | "adaptive";
}

/**
 * Batch processing context
 */
interface BatchContext {
  batchId: string;
  request: BatchValidationRequest;
  startTime: number;
  jobResults: Map<string, EnhancedValidationResult | Error>;
  completedJobs: Set<string>;
  failedJobs: Set<string>;
  skippedJobs: Set<string>;
  processingStats: BatchProcessingStats;
  agents: Map<string, ConcurrentValidationAgent>;
  options: Required<BatchValidationRequest["options"]>;
}

/**
 * Load balancing metrics per agent
 */
interface AgentLoadMetrics {
  agentId: string;
  queueLength: number;
  activeJobs: number;
  averageProcessingTime: number;
  successRate: number;
  specializations: CredentialType[];
  load: number; // 0-1
}

/**
 * High-performance batch validation system
 */
export class BatchValidationSystem extends EventEmitter {
  private readonly agents: Map<string, ConcurrentValidationAgent> = new Map();
  private readonly activeBatches: Map<string, BatchContext> = new Map();
  private readonly batchHistory: Map<string, BatchValidationResult> = new Map();
  private readonly config: BatchValidationConfig;
  private readonly componentLogger: ReturnType<typeof logger.child>;
  private metricsInterval?: NodeJS.Timeout;
  private cleanupInterval?: NodeJS.Timeout;

  constructor(config: Partial<BatchValidationConfig> = {}) {
    super();

    this.componentLogger = logger.child({ component: "BatchValidationSystem" });

    this.config = {
      maxConcurrentBatches: config.maxConcurrentBatches || 10,
      defaultBatchTimeoutMs: config.defaultBatchTimeoutMs || 300000, // 5 minutes
      maxBatchSize: config.maxBatchSize || 1000,
      enableAnalytics: config.enableAnalytics ?? true,
      enablePerformanceMonitoring: config.enablePerformanceMonitoring ?? true,
      retryConfig: {
        maxRetries: config.retryConfig?.maxRetries || 3,
        retryDelayMs: config.retryConfig?.retryDelayMs || 1000,
        exponentialBackoff: config.retryConfig?.exponentialBackoff ?? true,
      },
      loadBalancingStrategy: config.loadBalancingStrategy || "adaptive",
    };

    this.initializeSystem();
  }

  /**
   * Initialize the batch validation system
   */
  private initializeSystem(): void {
    // Start performance monitoring if enabled
    if (this.config.enablePerformanceMonitoring) {
      this.startPerformanceMonitoring();
    }

    // Start cleanup process
    this.startCleanupProcess();

    this.componentLogger.info("Batch validation system initialized", {
      maxConcurrentBatches: this.config.maxConcurrentBatches,
      maxBatchSize: this.config.maxBatchSize,
      loadBalancingStrategy: this.config.loadBalancingStrategy,
    });
  }

  /**
   * Register a validation agent with the system
   */
  public registerAgent(
    agentId: string,
    agent: ConcurrentValidationAgent,
    specializations: CredentialType[] = [],
  ): void {
    this.agents.set(agentId, agent);

    // Store specializations for load balancing
    (agent as any).specializations = specializations;

    this.componentLogger.info("Validation agent registered", {
      agentId,
      specializations,
    });

    this.emit("agentRegistered", { agentId, specializations });
  }

  /**
   * Unregister a validation agent
   */
  public async unregisterAgent(agentId: string): Promise<void> {
    const agent = this.agents.get(agentId);
    if (!agent) {
      throw new Error(`Agent ${agentId} not found`);
    }

    // Shutdown the agent gracefully
    await agent.shutdown(30000);
    this.agents.delete(agentId);

    this.componentLogger.info("Validation agent unregistered", { agentId });
    this.emit("agentUnregistered", { agentId });
  }

  /**
   * Process a batch validation request
   */
  public async processBatch(request: BatchValidationRequest): Promise<string> {
    // Validate request
    this.validateBatchRequest(request);

    // Check concurrent batch limit
    if (this.activeBatches.size >= this.config.maxConcurrentBatches) {
      throw new Error(
        `Maximum concurrent batches limit reached (${this.config.maxConcurrentBatches})`,
      );
    }

    const batchId = request.batchId || `batch_${crypto.randomUUID()}`;

    // Create batch context
    const batchContext: BatchContext = {
      batchId,
      request,
      startTime: performance.now(),
      jobResults: new Map(),
      completedJobs: new Set(),
      failedJobs: new Set(),
      skippedJobs: new Set(),
      processingStats: {
        batchId,
        startTime: performance.now(),
        totalJobs: request.jobs.length,
        completedJobs: 0,
        failedJobs: 0,
        averageProcessingTime: 0,
        throughput: 0,
        memoryUsage: 0,
        cpuUsage: 0,
      },
      agents: new Map(this.agents),
      options: {
        parallel: request.options?.parallel ?? true,
        maxConcurrency:
          request.options?.maxConcurrency || Math.min(8, request.jobs.length),
        stopOnError: request.options?.stopOnError ?? false,
        batchTimeoutMs:
          request.options?.batchTimeoutMs || this.config.defaultBatchTimeoutMs,
      },
    };

    this.activeBatches.set(batchId, batchContext);

    this.componentLogger.info("Batch processing started", {
      batchId,
      jobCount: request.jobs.length,
      parallel: batchContext.options.parallel,
      maxConcurrency: batchContext.options.maxConcurrency,
    });

    this.emit("batchStarted", { batchId, jobCount: request.jobs.length });

    // Start batch processing (don't await to allow async processing)
    this.executeBatch(batchContext).catch((error) => {
      this.componentLogger.error("Batch processing error", { batchId, error });
      this.emit("batchFailed", { batchId, error });
    });

    return batchId;
  }

  /**
   * Get the result of a batch processing request
   */
  public getBatchResult(batchId: string): BatchValidationResult | null {
    // Check if batch is still active
    const activeContext = this.activeBatches.get(batchId);
    if (activeContext) {
      return this.createPartialBatchResult(activeContext);
    }

    // Check completed batches
    return this.batchHistory.get(batchId) || null;
  }

  /**
   * Wait for a batch to complete
   */
  public async waitForBatch(
    batchId: string,
    timeoutMs?: number,
  ): Promise<BatchValidationResult> {
    const existingResult = this.getBatchResult(batchId);
    if (existingResult && existingResult.status !== "completed") {
      return existingResult;
    }

    return new Promise((resolve, reject) => {
      const timeout = timeoutMs
        ? setTimeout(() => {
            this.removeListener("batchCompleted", completedHandler);
            this.removeListener("batchFailed", failedHandler);
            reject(
              new Error(`Batch ${batchId} wait timeout after ${timeoutMs}ms`),
            );
          }, timeoutMs)
        : null;

      const completedHandler = (result: {
        batchId: string;
        result: BatchValidationResult;
      }): void => {
        if (result.batchId === batchId) {
          if (timeout) {
            clearTimeout(timeout);
          }
          this.removeListener("batchCompleted", completedHandler);
          this.removeListener("batchFailed", failedHandler);
          resolve(result.result);
        }
      };

      const failedHandler = (error: {
        batchId: string;
        error: Error;
      }): void => {
        if (error.batchId === batchId) {
          if (timeout) {
            clearTimeout(timeout);
          }
          this.removeListener("batchCompleted", completedHandler);
          this.removeListener("batchFailed", failedHandler);
          reject(error.error);
        }
      };

      this.on("batchCompleted", completedHandler);
      this.on("batchFailed", failedHandler);
    });
  }

  /**
   * Cancel a batch processing request
   */
  public async cancelBatch(batchId: string): Promise<boolean> {
    const batchContext = this.activeBatches.get(batchId);
    if (!batchContext) {
      return false;
    }

    this.componentLogger.info("Cancelling batch", { batchId });

    // Mark batch as cancelled and create result
    const result = this.createBatchResult(batchContext, "cancelled");
    this.batchHistory.set(batchId, result);
    this.activeBatches.delete(batchId);

    this.emit("batchCancelled", { batchId });
    return true;
  }

  /**
   * Get current system metrics
   */
  public getSystemMetrics(): {
    activeBatches: number;
    totalAgents: number;
    systemLoad: number;
    throughput: number;
    memoryUsageMB: number;
    cpuUsagePercent: number;
  } {
    const activeBatches = this.activeBatches.size;
    const totalAgents = this.agents.size;

    // Calculate system load
    let totalLoad = 0;
    for (const agent of this.agents.values()) {
      const metrics = agent.getMetrics();
      totalLoad +=
        (metrics.queueLength + metrics.activeWorkers) /
        (metrics.activeWorkers || 1);
    }
    const systemLoad = totalAgents > 0 ? totalLoad / totalAgents : 0;

    // Calculate throughput (jobs/sec across all agents)
    let totalThroughput = 0;
    for (const agent of this.agents.values()) {
      const metrics = agent.getMetrics();
      totalThroughput += metrics.throughputPerSecond;
    }

    // Get system resource usage
    const process = globalThis.process;
    let memoryUsageMB = 0;
    let cpuUsagePercent = 0;

    if (process?.memoryUsage) {
      const memUsage = process.memoryUsage();
      memoryUsageMB = Math.round(memUsage.heapUsed / 1024 / 1024);
    }

    if (process?.cpuUsage) {
      const cpuUsage = process.cpuUsage();
      cpuUsagePercent = (cpuUsage.user + cpuUsage.system) / 10000; // Convert to percentage
    }

    return {
      activeBatches,
      totalAgents,
      systemLoad: Math.min(1, systemLoad),
      throughput: totalThroughput,
      memoryUsageMB,
      cpuUsagePercent,
    };
  }

  /**
   * Get batch processing history
   */
  public getBatchHistory(limit?: number): BatchValidationResult[] {
    const results = Array.from(this.batchHistory.values()).sort(
      (a, b) =>
        b.summary.totalProcessingTimeMs - a.summary.totalProcessingTimeMs,
    );

    return limit ? results.slice(0, limit) : results;
  }

  /**
   * Shutdown the batch validation system
   */
  public async shutdown(timeoutMs: number = 60000): Promise<void> {
    this.componentLogger.info("Shutting down batch validation system", {
      activeBatches: this.activeBatches.size,
      totalAgents: this.agents.size,
    });

    // Clear intervals
    if (this.metricsInterval) {
      clearInterval(this.metricsInterval);
    }
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }

    // Cancel all active batches
    for (const batchId of this.activeBatches.keys()) {
      await this.cancelBatch(batchId);
    }

    // Shutdown all agents
    const shutdownPromises = Array.from(this.agents.entries()).map(
      async ([agentId, agent]) => {
        try {
          await agent.shutdown(timeoutMs / this.agents.size);
          this.componentLogger.debug("Agent shutdown complete", { agentId });
        } catch (error) {
          this.componentLogger.error("Error shutting down agent", {
            agentId,
            error,
          });
        }
      },
    );

    await Promise.allSettled(shutdownPromises);

    // Clear data structures
    this.agents.clear();
    this.activeBatches.clear();

    this.componentLogger.info("Batch validation system shutdown complete");
  }

  /**
   * Validate batch request
   */
  private validateBatchRequest(request: BatchValidationRequest): void {
    if (!request.jobs || request.jobs.length === 0) {
      throw new Error("Batch request must contain at least one job");
    }

    if (request.jobs.length > this.config.maxBatchSize) {
      throw new Error(
        `Batch size exceeds maximum allowed (${this.config.maxBatchSize})`,
      );
    }

    // Validate individual jobs
    for (const job of request.jobs) {
      if (!job.id || !job.type || !job.credential) {
        throw new Error("Each job must have id, type, and credential");
      }
    }

    if (this.agents.size === 0) {
      throw new Error("No validation agents registered");
    }
  }

  /**
   * Execute batch processing
   */
  private async executeBatch(context: BatchContext): Promise<void> {
    const { batchId, options } = context;

    try {
      // Set batch timeout
      const batchTimeout = setTimeout(() => {
        this.handleBatchTimeout(batchId);
      }, options.batchTimeoutMs);

      if (options.parallel) {
        await this.processJobsInParallel(context);
      } else {
        await this.processJobsSequentially(context);
      }

      clearTimeout(batchTimeout);

      // Complete batch processing
      const result = this.createBatchResult(context, "completed");
      this.batchHistory.set(batchId, result);
      this.activeBatches.delete(batchId);

      this.componentLogger.info("Batch processing completed", {
        batchId,
        totalJobs: result.summary.total,
        successful: result.summary.successful,
        failed: result.summary.failed,
        processingTimeMs: result.summary.totalProcessingTimeMs,
      });

      this.emit("batchCompleted", { batchId, result });
    } catch (error) {
      // Handle batch failure
      const result = this.createBatchResult(context, "failed");
      this.batchHistory.set(batchId, result);
      this.activeBatches.delete(batchId);

      this.componentLogger.error("Batch processing failed", { batchId, error });
      this.emit("batchFailed", { batchId, error });
    }
  }

  /**
   * Process jobs in parallel with load balancing
   */
  private async processJobsInParallel(context: BatchContext): Promise<void> {
    const { request, options } = context;
    const semaphore = new Semaphore(options.maxConcurrency);

    const jobPromises = request.jobs.map(async (job) => {
      await semaphore.acquire();

      try {
        await this.processJob(context, job);
      } catch (error) {
        this.handleJobError(context, job, error as Error);

        if (options.stopOnError) {
          throw error;
        }
      } finally {
        semaphore.release();
      }
    });

    await Promise.allSettled(jobPromises);
  }

  /**
   * Process jobs sequentially
   */
  private async processJobsSequentially(context: BatchContext): Promise<void> {
    const { request, options } = context;

    for (const job of request.jobs) {
      try {
        await this.processJob(context, job);
      } catch (error) {
        this.handleJobError(context, job, error as Error);

        if (options.stopOnError) {
          throw error;
        }
      }
    }
  }

  /**
   * Process individual job with load balancing
   */
  private async processJob(
    context: BatchContext,
    job: ValidationJob,
  ): Promise<void> {
    const agent = this.selectOptimalAgent(job, context);
    if (!agent) {
      throw new Error(`No suitable agent available for job ${job.id}`);
    }

    const startTime = performance.now();

    try {
      // Submit job to selected agent
      await agent.submitJob(job);

      // Wait for job completion
      const result = await agent.waitForJob(job.id, 30000);

      // Store result
      context.jobResults.set(job.id, result);
      context.completedJobs.add(job.id);
      context.processingStats.completedJobs++;

      // Update processing time
      const processingTime = performance.now() - startTime;
      this.updateProcessingStats(context, processingTime);

      this.componentLogger.debug("Job completed", {
        batchId: context.batchId,
        jobId: job.id,
        processingTimeMs: processingTime,
        score: result.score,
      });
    } catch (error) {
      // Handle job failure
      context.jobResults.set(job.id, error as Error);
      context.failedJobs.add(job.id);
      context.processingStats.failedJobs++;

      this.componentLogger.error("Job failed", {
        batchId: context.batchId,
        jobId: job.id,
        error,
      });

      throw error;
    }
  }

  /**
   * Select optimal agent based on load balancing strategy
   */
  private selectOptimalAgent(
    job: ValidationJob,
    context: BatchContext,
  ): ConcurrentValidationAgent | null {
    const availableAgents = Array.from(context.agents.values());

    if (availableAgents.length === 0) {
      return null;
    }

    switch (this.config.loadBalancingStrategy) {
      case "round-robin":
        return this.selectRoundRobinAgent(availableAgents);

      case "least-loaded":
        return this.selectLeastLoadedAgent(availableAgents);

      case "credential-type":
        return this.selectCredentialTypeAgent(job, availableAgents);

      case "adaptive":
        return this.selectAdaptiveAgent(job, availableAgents);

      default:
        return availableAgents[0];
    }
  }

  /**
   * Round-robin agent selection
   */
  private selectRoundRobinAgent(
    agents: ConcurrentValidationAgent[],
  ): ConcurrentValidationAgent {
    // Simple round-robin implementation
    const index = Math.floor(Math.random() * agents.length);
    return agents[index];
  }

  /**
   * Least loaded agent selection
   */
  private selectLeastLoadedAgent(
    agents: ConcurrentValidationAgent[],
  ): ConcurrentValidationAgent {
    let bestAgent = agents[0];
    let minLoad = Infinity;

    for (const agent of agents) {
      const metrics = agent.getMetrics();
      const load = metrics.queueLength + metrics.activeWorkers * 2;

      if (load < minLoad) {
        minLoad = load;
        bestAgent = agent;
      }
    }

    return bestAgent;
  }

  /**
   * Credential type specialized agent selection
   */
  private selectCredentialTypeAgent(
    job: ValidationJob,
    agents: ConcurrentValidationAgent[],
  ): ConcurrentValidationAgent {
    // Find agents specialized for this credential type
    const specializedAgents = agents.filter((agent) => {
      const specializations =
        ((agent as unknown).specializations as CredentialType[]) || [];
      return specializations.includes(job.type);
    });

    if (specializedAgents.length > 0) {
      return this.selectLeastLoadedAgent(specializedAgents);
    }

    // Fall back to least loaded if no specialization found
    return this.selectLeastLoadedAgent(agents);
  }

  /**
   * Adaptive agent selection using multiple factors
   */
  private selectAdaptiveAgent(
    job: ValidationJob,
    agents: ConcurrentValidationAgent[],
  ): ConcurrentValidationAgent {
    const loadMetrics = agents.map((agent) =>
      this.calculateAgentLoadMetrics(agent, job.type),
    );

    // Score each agent based on multiple factors
    let bestAgent = agents[0];
    let bestScore = -Infinity;

    for (let i = 0; i < agents.length; i++) {
      const agent = agents[i];
      const metrics = loadMetrics[i];

      // Calculate composite score
      let score = 0;

      // Prefer lower load (40% weight)
      score += (1 - metrics.load) * 40;

      // Prefer specialized agents (30% weight)
      const hasSpecialization = metrics.specializations.includes(job.type);
      score += hasSpecialization ? 30 : 0;

      // Prefer higher success rate (20% weight)
      score += metrics.successRate * 20;

      // Prefer faster processing (10% weight)
      const avgTime = metrics.averageProcessingTime || 1000;
      score += (1000 / avgTime) * 10;

      if (score > bestScore) {
        bestScore = score;
        bestAgent = agent;
      }
    }

    return bestAgent;
  }

  /**
   * Calculate agent load metrics
   */
  private calculateAgentLoadMetrics(
    agent: ConcurrentValidationAgent,
  ): AgentLoadMetrics {
    const metrics = agent.getMetrics();
    const specializations =
      ((agent as unknown).specializations as CredentialType[]) || [];

    return {
      agentId: `agent_${Math.random().toString(36).substring(2, 8)}`,
      queueLength: metrics.queueLength,
      activeJobs: metrics.queueLength, // Approximation
      averageProcessingTime: metrics.averageProcessingTimeMs,
      successRate:
        metrics.completedJobs / (metrics.completedJobs + metrics.failedJobs) ||
        1,
      specializations,
      load:
        (metrics.queueLength + metrics.activeWorkers) /
        Math.max(1, metrics.activeWorkers),
    };
  }

  /**
   * Handle job error during processing
   */
  private handleJobError(
    context: BatchContext,
    job: ValidationJob,
    error: Error,
  ): void {
    context.jobResults.set(job.id, error);
    context.failedJobs.add(job.id);
    context.processingStats.failedJobs++;

    this.componentLogger.warn("Job error in batch", {
      batchId: context.batchId,
      jobId: job.id,
      error: error.message,
    });

    this.emit("jobError", { batchId: context.batchId, jobId: job.id, error });
  }

  /**
   * Handle batch timeout
   */
  private handleBatchTimeout(batchId: string): void {
    const context = this.activeBatches.get(batchId);
    if (!context) {
      return;
    }

    this.componentLogger.warn("Batch timeout", { batchId });

    const result = this.createBatchResult(context, "timeout");
    this.batchHistory.set(batchId, result);
    this.activeBatches.delete(batchId);

    this.emit("batchTimeout", { batchId, result });
  }

  /**
   * Update processing statistics
   */
  private updateProcessingStats(
    context: BatchContext,
    processingTime: number,
  ): void {
    const stats = context.processingStats;

    // Update average processing time
    if (stats.completedJobs === 1) {
      stats.averageProcessingTime = processingTime;
    } else {
      stats.averageProcessingTime =
        (stats.averageProcessingTime * (stats.completedJobs - 1) +
          processingTime) /
        stats.completedJobs;
    }

    // Update throughput
    const elapsedTime = (performance.now() - stats.startTime) / 1000; // seconds
    stats.throughput = stats.completedJobs / elapsedTime;
  }

  /**
   * Create batch result from context
   */
  private createBatchResult(
    context: BatchContext,
    status: BatchValidationResult["status"],
  ): BatchValidationResult {
    const endTime = performance.now();
    const totalProcessingTime = endTime - context.startTime;

    const summary = {
      total: context.request.jobs.length,
      successful: context.completedJobs.size,
      failed: context.failedJobs.size,
      skipped: context.skippedJobs.size,
      totalProcessingTimeMs: totalProcessingTime,
      averageProcessingTimeMs: context.processingStats.averageProcessingTime,
    };

    // Generate batch insights if enabled
    let batchInsights: BatchInsights | undefined;
    if (this.config.enableAnalytics) {
      batchInsights = this.generateBatchInsights(context);
    }

    return {
      batchId: context.batchId,
      status,
      summary,
      results: context.jobResults,
      batchInsights,
    };
  }

  /**
   * Create partial batch result for active batches
   */
  private createPartialBatchResult(
    context: BatchContext,
  ): BatchValidationResult {
    const currentTime = performance.now();
    const elapsedTime = currentTime - context.startTime;

    const summary = {
      total: context.request.jobs.length,
      successful: context.completedJobs.size,
      failed: context.failedJobs.size,
      skipped: context.skippedJobs.size,
      totalProcessingTimeMs: elapsedTime,
      averageProcessingTimeMs: context.processingStats.averageProcessingTime,
    };

    return {
      batchId: context.batchId,
      status: "completed", // Will be updated when actually completed
      summary,
      results: context.jobResults,
      batchInsights: undefined, // Not generated for partial results
    };
  }

  /**
   * Generate comprehensive batch insights
   */
  private generateBatchInsights(context: BatchContext): BatchInsights {
    const results = Array.from(context.jobResults.values()).filter(
      (result): result is EnhancedValidationResult =>
        !(result instanceof Error),
    );

    // Calculate score distribution
    const scoreDistribution = {
      "A+": 0,
      A: 0,
      B: 0,
      C: 0,
      D: 0,
      F: 0,
    };

    // Calculate risk distribution
    const riskDistribution = {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0,
    };

    // Track common issues
    const issueTracker = new Map<string, number>();
    const complianceFrameworks = new Set<ComplianceFramework>();

    for (const result of results) {
      // Score distribution
      const grade = this.calculateSecurityGrade(result.score);
      scoreDistribution[grade]++;

      // Risk distribution
      if (result.riskAnalysis) {
        riskDistribution[result.riskAnalysis.overallRisk]++;
      }

      // Track common issues
      for (const error of result.errors) {
        issueTracker.set(
          error.message,
          (issueTracker.get(error.message) || 0) + 1,
        );
      }
      for (const warning of result.warnings) {
        issueTracker.set(
          warning.message,
          (issueTracker.get(warning.message) || 0) + 1,
        );
      }

      // Compliance frameworks
      if (result.complianceResults) {
        for (const compliance of result.complianceResults) {
          complianceFrameworks.add(compliance.framework);
        }
      }
    }

    // Generate common issues
    const commonIssues: CommonIssue[] = Array.from(issueTracker.entries())
      .sort(([, a], [, b]) => b - a)
      .slice(0, 10)
      .map(([description, count]) => ({
        type: "validation_issue",
        description,
        affectedCount: count,
        affectedPercentage: (count / results.length) * 100,
        severity: this.determineSeverityFromDescription(description),
        batchRemediation: this.generateBatchRemediation(description),
      }));

    // Generate batch-level recommendations
    const batchRecommendations = this.generateBatchRecommendations(
      commonIssues,
      riskDistribution,
    );

    return {
      scoreDistribution,
      commonIssues,
      complianceSummary: Array.from(complianceFrameworks),
      riskDistribution,
      batchRecommendations,
    };
  }

  /**
   * Calculate security grade from score
   */
  private calculateSecurityGrade(score: number): SecurityGrade {
    if (score >= 95) {
      return "A+";
    }
    if (score >= 85) {
      return "A";
    }
    if (score >= 75) {
      return "B";
    }
    if (score >= 65) {
      return "C";
    }
    if (score >= 50) {
      return "D";
    }
    return "F";
  }

  /**
   * Determine severity from issue description
   */
  private determineSeverityFromDescription(
    description: string,
  ): SecuritySeverity {
    const lowerDescription = description.toLowerCase();

    if (
      lowerDescription.includes("critical") ||
      lowerDescription.includes("expired")
    ) {
      return "critical";
    }
    if (
      lowerDescription.includes("weak") ||
      lowerDescription.includes("vulnerable")
    ) {
      return "high";
    }
    if (
      lowerDescription.includes("warning") ||
      lowerDescription.includes("deprecated")
    ) {
      return "medium";
    }
    return "low";
  }

  /**
   * Generate batch-level remediation steps
   */
  private generateBatchRemediation(issueDescription: string): string[] {
    const remediation: string[] = [];
    const lowerDescription = issueDescription.toLowerCase();

    if (lowerDescription.includes("entropy")) {
      remediation.push(
        "Implement organization-wide secure credential generation policy",
      );
      remediation.push("Deploy automated credential strength validation");
    }

    if (lowerDescription.includes("expired")) {
      remediation.push("Implement automated credential rotation system");
      remediation.push("Set up expiration monitoring and alerts");
    }

    if (lowerDescription.includes("weak")) {
      remediation.push("Enforce stronger credential requirements");
      remediation.push("Provide security training to development teams");
    }

    return remediation.length > 0
      ? remediation
      : ["Review and update credential management policies"];
  }

  /**
   * Generate batch-level recommendations
   */
  private generateBatchRecommendations(
    commonIssues: CommonIssue[],
    riskDistribution: Record<string, number>,
  ): string[] {
    const recommendations: string[] = [];

    // Analyze risk distribution
    const totalRisks = Object.values(riskDistribution).reduce(
      (sum: number, count: number) => sum + count,
      0,
    );
    const highRiskPercentage =
      totalRisks > 0
        ? ((riskDistribution.high + riskDistribution.critical) / totalRisks) *
          100
        : 0;

    if (highRiskPercentage > 30) {
      recommendations.push(
        "Immediate organization-wide credential audit required",
      );
      recommendations.push(
        "Implement emergency credential rotation procedures",
      );
    }

    // Analyze common issues
    const criticalIssues = commonIssues.filter(
      (issue) => issue.severity === "critical",
    );
    if (criticalIssues.length > 0) {
      recommendations.push(
        "Address critical security issues immediately across all affected systems",
      );
    }

    const highVolumeIssues = commonIssues.filter(
      (issue) => issue.affectedPercentage > 50,
    );
    if (highVolumeIssues.length > 0) {
      recommendations.push(
        "Implement automated remediation for systemic issues affecting majority of credentials",
      );
    }

    // General recommendations
    if (recommendations.length === 0) {
      recommendations.push(
        "Continue regular credential validation and monitoring",
      );
      recommendations.push(
        "Consider implementing automated credential management policies",
      );
    }

    return recommendations;
  }

  /**
   * Start performance monitoring
   */
  private startPerformanceMonitoring(): void {
    this.metricsInterval = setInterval(() => {
      this.collectPerformanceMetrics();
    }, 30000); // Every 30 seconds
  }

  /**
   * Collect performance metrics
   */
  private collectPerformanceMetrics(): void {
    const systemMetrics = this.getSystemMetrics();

    this.componentLogger.debug("Performance metrics", systemMetrics);
    this.emit("performanceMetrics", systemMetrics);
  }

  /**
   * Start cleanup process for completed batches
   */
  private startCleanupProcess(): void {
    this.cleanupInterval = setInterval(() => {
      this.cleanupCompletedBatches();
    }, 300000); // Every 5 minutes
  }

  /**
   * Clean up old batch history to manage memory
   */
  private cleanupCompletedBatches(): void {
    const maxHistorySize = 100;
    const historySize = this.batchHistory.size;

    if (historySize > maxHistorySize) {
      const sortedEntries = Array.from(this.batchHistory.entries()).sort(
        ([, a], [, b]) =>
          b.summary.totalProcessingTimeMs - a.summary.totalProcessingTimeMs,
      );

      // Keep only the most recent entries
      const toKeep = sortedEntries.slice(0, maxHistorySize);
      this.batchHistory.clear();

      for (const [batchId, result] of toKeep) {
        this.batchHistory.set(batchId, result);
      }

      this.componentLogger.debug("Cleaned up batch history", {
        previousSize: historySize,
        newSize: this.batchHistory.size,
      });
    }
  }
}

/**
 * Simple semaphore implementation for concurrency control
 */
class Semaphore {
  private permits: number;
  private readonly waitQueue: Array<() => void> = [];

  constructor(permits: number) {
    this.permits = permits;
  }

  async acquire(): Promise<void> {
    return new Promise<void>((resolve) => {
      if (this.permits > 0) {
        this.permits--;
        resolve();
      } else {
        this.waitQueue.push(resolve);
      }
    });
  }

  release(): void {
    this.permits++;

    const next = this.waitQueue.shift();
    if (next) {
      this.permits--;
      next();
    }
  }
}

/**
 * Factory function to create batch validation system
 */
export function createBatchValidationSystem(
  config?: Partial<BatchValidationConfig>,
): BatchValidationSystem {
  return new BatchValidationSystem(config);
}

// Export singleton instance for convenience
export const batchValidationSystem = new BatchValidationSystem();

export default BatchValidationSystem;
