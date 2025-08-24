/**
 * @fileoverview Concurrent Credential Validation Agent
 * 
 * Implements high-performance concurrent credential validation using Worker Threads.
 * Provides enterprise-grade validation capabilities with parallel processing,
 * resource pooling, and comprehensive security assessment.
 */

import { Worker, isMainThread, parentPort, workerData } from 'worker_threads';
import { EventEmitter } from 'events';
import * as crypto from 'crypto';
import * as path from 'path';
import { fileURLToPath } from 'url';
import logger from '../lib/logger.js';
import { 
  CredentialSecurityValidator,
  CredentialValidationResult
} from '../lib/credential-security-validator.js';

// Get current file path for ESM compatibility
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Validation job interface for worker thread communication
 */
export interface ValidationJob {
  id: string;
  type: 'api_key' | 'password' | 'certificate' | 'token' | 'secret' | 'ssh_key' | 'jwt' | 'oauth_token' | 'database_password' | 'encryption_key';
  credential: string;
  context?: {
    service?: string;
    environment?: 'production' | 'staging' | 'development';
    userId?: string;
    organizationId?: string;
    metadata?: Record<string, unknown>;
  };
  options?: {
    strictMode?: boolean;
    complianceFrameworks?: string[];
    customRules?: ValidationRule[];
    timeoutMs?: number;
  };
}

/**
 * Validation result with extended metadata
 */
export interface EnhancedValidationResult extends CredentialValidationResult {
  jobId: string;
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  processingTimeMs: number;
  workerId: string;
  timestamp: Date;
  complianceResults?: ComplianceAssessment[];
  riskAnalysis?: RiskAnalysis;
  remediationSteps?: RemediationStep[];
}

/**
 * Custom validation rule interface
 */
export interface ValidationRule {
  id: string;
  name: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  pattern?: RegExp;
  validator?: (credential: string, context?: ValidationJob['context']) => boolean;
  message: string;
}

/**
 * Compliance framework assessment
 */
export interface ComplianceAssessment {
  framework: 'SOC2' | 'ISO27001' | 'PCI-DSS' | 'GDPR' | 'HIPAA' | 'FedRAMP';
  compliant: boolean;
  score: number;
  requirements: ComplianceRequirement[];
  gaps: string[];
  recommendations: string[];
}

/**
 * Compliance requirement details
 */
export interface ComplianceRequirement {
  id: string;
  description: string;
  status: 'compliant' | 'non-compliant' | 'partial' | 'not-applicable';
  evidence?: string;
  remediation?: string;
}

/**
 * Risk analysis results
 */
export interface RiskAnalysis {
  overallRisk: 'low' | 'medium' | 'high' | 'critical';
  riskFactors: RiskFactor[];
  mitigationStrategies: string[];
  priorityScore: number;
  exposurePaths: string[];
}

/**
 * Individual risk factor
 */
export interface RiskFactor {
  category: 'entropy' | 'pattern' | 'exposure' | 'age' | 'privilege' | 'compliance';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  impact: string;
  likelihood: number; // 0-1
  mitigation?: string;
}

/**
 * Remediation step for security improvements
 */
export interface RemediationStep {
  priority: 'immediate' | 'high' | 'medium' | 'low';
  action: string;
  description: string;
  estimatedEffort: 'low' | 'medium' | 'high';
  category: 'regeneration' | 'rotation' | 'monitoring' | 'policy' | 'training';
  timeline?: string;
}

/**
 * Worker pool configuration
 */
export interface WorkerPoolConfig {
  maxWorkers: number;
  minWorkers: number;
  maxQueueSize: number;
  workerIdleTimeoutMs: number;
  jobTimeoutMs: number;
  retryAttempts: number;
  healthCheckIntervalMs: number;
}

/**
 * Performance metrics for monitoring
 */
export interface ValidationMetrics {
  totalJobs: number;
  completedJobs: number;
  failedJobs: number;
  averageProcessingTimeMs: number;
  throughputPerSecond: number;
  queueLength: number;
  activeWorkers: number;
  memoryUsageMB: number;
  cpuUsage: number;
}

/**
 * Worker status information
 */
interface WorkerInfo {
  id: string;
  worker: Worker;
  busy: boolean;
  lastActivity: Date;
  jobsCompleted: number;
  jobsFailed: number;
  startTime: Date;
}

/**
 * Main concurrent validation agent class
 */
export class ConcurrentValidationAgent extends EventEmitter {
  private readonly workers: Map<string, WorkerInfo> = new Map();
  private readonly jobQueue: ValidationJob[] = [];
  private readonly activeJobs: Map<string, { job: ValidationJob; startTime: Date; workerId: string }> = new Map();
  private readonly completedJobs: Map<string, EnhancedValidationResult> = new Map();
  private readonly config: WorkerPoolConfig;
  private readonly metrics: ValidationMetrics;
  private healthCheckInterval?: NodeJS.Timeout;
  private readonly componentLogger: ReturnType<typeof logger.child>;

  constructor(config: Partial<WorkerPoolConfig> = {}) {
    super();
    
    this.componentLogger = logger.child({ component: 'ConcurrentValidationAgent' });
    
    this.config = {
      maxWorkers: config.maxWorkers || 8,
      minWorkers: config.minWorkers || 2,
      maxQueueSize: config.maxQueueSize || 1000,
      workerIdleTimeoutMs: config.workerIdleTimeoutMs || 300000, // 5 minutes
      jobTimeoutMs: config.jobTimeoutMs || 30000, // 30 seconds
      retryAttempts: config.retryAttempts || 3,
      healthCheckIntervalMs: config.healthCheckIntervalMs || 60000 // 1 minute
    };

    this.metrics = {
      totalJobs: 0,
      completedJobs: 0,
      failedJobs: 0,
      averageProcessingTimeMs: 0,
      throughputPerSecond: 0,
      queueLength: 0,
      activeWorkers: 0,
      memoryUsageMB: 0,
      cpuUsage: 0
    };

    this.initializeWorkerPool();
    this.startHealthCheck();

    this.componentLogger.info('Concurrent Validation Agent initialized', {
      maxWorkers: this.config.maxWorkers,
      minWorkers: this.config.minWorkers,
      maxQueueSize: this.config.maxQueueSize
    });
  }

  /**
   * Initialize the worker pool with minimum workers
   */
  private async initializeWorkerPool(): Promise<void> {
    for (let i = 0; i < this.config.minWorkers; i++) {
      await this.createWorker();
    }
  }

  /**
   * Create a new worker thread
   */
  private async createWorker(): Promise<string> {
    const workerId = `worker_${crypto.randomUUID()}`;
    
    try {
      const worker = new Worker(__filename, {
        workerData: { isWorker: true },
        transferList: []
      });

      const workerInfo: WorkerInfo = {
        id: workerId,
        worker,
        busy: false,
        lastActivity: new Date(),
        jobsCompleted: 0,
        jobsFailed: 0,
        startTime: new Date()
      };

      // Set up worker event handlers
      worker.on('message', (result: EnhancedValidationResult) => {
        this.handleWorkerResult(workerId, result);
      });

      worker.on('error', (error) => {
        this.handleWorkerError(workerId, error);
      });

      worker.on('exit', (code) => {
        this.handleWorkerExit(workerId, code);
      });

      this.workers.set(workerId, workerInfo);
      this.metrics.activeWorkers = this.workers.size;

      this.componentLogger.debug('Worker created', { workerId });
      
      return workerId;
    } catch (error) {
      this.componentLogger.error('Failed to create worker', { workerId, error });
      throw error;
    }
  }

  /**
   * Submit a validation job for processing
   */
  public async submitJob(job: ValidationJob): Promise<string> {
    if (this.jobQueue.length >= this.config.maxQueueSize) {
      throw new Error(`Job queue full (${this.config.maxQueueSize} jobs)`);
    }

    // Validate job structure
    if (!job.id || !job.type || !job.credential) {
      throw new Error('Invalid job structure: id, type, and credential are required');
    }

    // Add job to queue
    this.jobQueue.push(job);
    this.metrics.totalJobs++;
    this.metrics.queueLength = this.jobQueue.length;

    this.componentLogger.debug('Job submitted', { 
      jobId: job.id, 
      type: job.type,
      queueLength: this.jobQueue.length 
    });

    // Emit event for monitoring
    this.emit('jobSubmitted', job);

    // Try to assign job to available worker
    await this.assignJobToWorker();

    return job.id;
  }

  /**
   * Submit multiple jobs for batch processing
   */
  public async submitBatch(jobs: ValidationJob[]): Promise<string[]> {
    if (jobs.length === 0) {
      return [];
    }

    if (this.jobQueue.length + jobs.length > this.config.maxQueueSize) {
      throw new Error(`Batch would exceed queue capacity (${this.config.maxQueueSize} jobs)`);
    }

    const jobIds: string[] = [];
    
    for (const job of jobs) {
      if (!job.id) {
        job.id = `batch_${crypto.randomUUID()}`;
      }
      jobIds.push(await this.submitJob(job));
    }

    this.componentLogger.info('Batch submitted', { 
      batchSize: jobs.length,
      queueLength: this.jobQueue.length 
    });

    return jobIds;
  }

  /**
   * Get validation result by job ID
   */
  public getResult(jobId: string): EnhancedValidationResult | null {
    return this.completedJobs.get(jobId) || null;
  }

  /**
   * Get results for multiple job IDs
   */
  public getBatchResults(jobIds: string[]): Map<string, EnhancedValidationResult | null> {
    const results = new Map<string, EnhancedValidationResult | null>();
    
    for (const jobId of jobIds) {
      results.set(jobId, this.getResult(jobId));
    }
    
    return results;
  }

  /**
   * Wait for a job to complete
   */
  public async waitForJob(jobId: string, timeoutMs: number = 30000): Promise<EnhancedValidationResult> {
    return new Promise((resolve, reject) => {
      // Check if already completed
      const existing = this.completedJobs.get(jobId);
      if (existing) {
        resolve(existing);
        return;
      }

      // Set up timeout
      const timeout = setTimeout(() => {
        this.removeListener('jobCompleted', jobCompletedHandler);
        this.removeListener('jobFailed', jobFailedHandler);
        reject(new Error(`Job ${jobId} timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      // Set up completion handlers
      const jobCompletedHandler = (result: EnhancedValidationResult) => {
        if (result.jobId === jobId) {
          clearTimeout(timeout);
          this.removeListener('jobCompleted', jobCompletedHandler);
          this.removeListener('jobFailed', jobFailedHandler);
          resolve(result);
        }
      };

      const jobFailedHandler = (error: { jobId: string; error: Error }) => {
        if (error.jobId === jobId) {
          clearTimeout(timeout);
          this.removeListener('jobCompleted', jobCompletedHandler);
          this.removeListener('jobFailed', jobFailedHandler);
          reject(error.error);
        }
      };

      this.on('jobCompleted', jobCompletedHandler);
      this.on('jobFailed', jobFailedHandler);
    });
  }

  /**
   * Wait for multiple jobs to complete
   */
  public async waitForBatch(jobIds: string[], timeoutMs: number = 60000): Promise<Map<string, EnhancedValidationResult | Error>> {
    const results = new Map<string, EnhancedValidationResult | Error>();
    
    const promises = jobIds.map(async (jobId) => {
      try {
        const result = await this.waitForJob(jobId, timeoutMs);
        results.set(jobId, result);
      } catch (error) {
        results.set(jobId, error as Error);
      }
    });

    await Promise.allSettled(promises);
    return results;
  }

  /**
   * Get current performance metrics
   */
  public getMetrics(): ValidationMetrics {
    this.updateMetrics();
    return { ...this.metrics };
  }

  /**
   * Get detailed worker status
   */
  public getWorkerStatus(): Array<{
    id: string;
    busy: boolean;
    jobsCompleted: number;
    jobsFailed: number;
    uptimeMs: number;
    lastActivityMs: number;
  }> {
    const now = new Date();
    return Array.from(this.workers.values()).map(worker => ({
      id: worker.id,
      busy: worker.busy,
      jobsCompleted: worker.jobsCompleted,
      jobsFailed: worker.jobsFailed,
      uptimeMs: now.getTime() - worker.startTime.getTime(),
      lastActivityMs: now.getTime() - worker.lastActivity.getTime()
    }));
  }

  /**
   * Gracefully shutdown the validation agent
   */
  public async shutdown(timeoutMs: number = 30000): Promise<void> {
    this.componentLogger.info('Shutting down concurrent validation agent', {
      activeJobs: this.activeJobs.size,
      queuedJobs: this.jobQueue.length,
      workers: this.workers.size
    });

    // Clear health check interval
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }

    // Wait for active jobs to complete or timeout
    const shutdownPromise = this.waitForActiveJobsToComplete();
    const timeoutPromise = new Promise<void>((resolve) => {
      setTimeout(resolve, timeoutMs);
    });

    await Promise.race([shutdownPromise, timeoutPromise]);

    // Terminate all workers
    const terminationPromises = Array.from(this.workers.values()).map(async (workerInfo) => {
      try {
        await workerInfo.worker.terminate();
        this.componentLogger.debug('Worker terminated', { workerId: workerInfo.id });
      } catch (error) {
        this.componentLogger.error('Error terminating worker', { 
          workerId: workerInfo.id, 
          error 
        });
      }
    });

    await Promise.allSettled(terminationPromises);

    // Clear all data structures
    this.workers.clear();
    this.jobQueue.length = 0;
    this.activeJobs.clear();

    this.componentLogger.info('Concurrent validation agent shutdown complete');
  }

  /**
   * Assign next job to available worker
   */
  private async assignJobToWorker(): Promise<void> {
    if (this.jobQueue.length === 0) {
      return;
    }

    // Find available worker
    let availableWorker: WorkerInfo | null = null;
    for (const worker of this.workers.values()) {
      if (!worker.busy) {
        availableWorker = worker;
        break;
      }
    }

    // Create new worker if none available and under max limit
    if (!availableWorker && this.workers.size < this.config.maxWorkers) {
      const workerId = await this.createWorker();
      availableWorker = this.workers.get(workerId) || null;
    }

    if (!availableWorker) {
      // No workers available, job will wait in queue
      return;
    }

    // Assign job to worker
    const job = this.jobQueue.shift();
    if (!job) {
      return;
    }

    availableWorker.busy = true;
    availableWorker.lastActivity = new Date();

    // Track active job
    this.activeJobs.set(job.id, {
      job,
      startTime: new Date(),
      workerId: availableWorker.id
    });

    // Send job to worker
    try {
      availableWorker.worker.postMessage({
        type: 'validateCredential',
        jobId: job.id,
        job
      });

      this.metrics.queueLength = this.jobQueue.length;

      this.componentLogger.debug('Job assigned to worker', {
        jobId: job.id,
        workerId: availableWorker.id,
        queueLength: this.jobQueue.length
      });

      // Set job timeout
      setTimeout(() => {
        if (this.activeJobs.has(job.id)) {
          this.handleJobTimeout(job.id);
        }
      }, this.config.jobTimeoutMs);

    } catch (error) {
      // Release worker and requeue job
      availableWorker.busy = false;
      this.jobQueue.unshift(job);
      this.activeJobs.delete(job.id);
      
      this.componentLogger.error('Error sending job to worker', {
        jobId: job.id,
        workerId: availableWorker.id,
        error
      });
    }
  }

  /**
   * Handle worker result message
   */
  private handleWorkerResult(workerId: string, result: EnhancedValidationResult): void {
    const worker = this.workers.get(workerId);
    const activeJob = this.activeJobs.get(result.jobId);

    if (!worker || !activeJob) {
      this.componentLogger.warn('Received result for unknown worker or job', {
        workerId,
        jobId: result.jobId
      });
      return;
    }

    // Update worker status
    worker.busy = false;
    worker.lastActivity = new Date();
    worker.jobsCompleted++;

    // Calculate processing time
    const processingTimeMs = new Date().getTime() - activeJob.startTime.getTime();
    result.processingTimeMs = processingTimeMs;
    result.workerId = workerId;

    // Store completed result
    this.completedJobs.set(result.jobId, result);
    this.activeJobs.delete(result.jobId);

    // Update metrics
    this.metrics.completedJobs++;
    this.updateAverageProcessingTime(processingTimeMs);

    this.componentLogger.debug('Job completed', {
      jobId: result.jobId,
      workerId,
      processingTimeMs,
      score: result.score
    });

    // Emit completion event
    this.emit('jobCompleted', result);

    // Try to assign next job
    this.assignJobToWorker().catch((error) => {
      this.componentLogger.error('Error assigning next job', { error });
    });
  }

  /**
   * Handle worker error
   */
  private handleWorkerError(workerId: string, error: Error): void {
    const worker = this.workers.get(workerId);
    if (!worker) {
      return;
    }

    this.componentLogger.error('Worker error', { workerId, error });

    // Find active job for this worker
    let failedJobId: string | null = null;
    for (const [jobId, activeJob] of this.activeJobs.entries()) {
      if (activeJob.workerId === workerId) {
        failedJobId = jobId;
        break;
      }
    }

    if (failedJobId) {
      const activeJob = this.activeJobs.get(failedJobId);
      if (activeJob) {
        this.activeJobs.delete(failedJobId);
        
        // Emit failure event
        this.emit('jobFailed', { jobId: failedJobId, error });
        
        // Update metrics
        this.metrics.failedJobs++;
        worker.jobsFailed++;

        // Requeue job for retry if attempts remain
        if (!activeJob.job.options?.timeoutMs || activeJob.job.options.timeoutMs > 0) {
          this.jobQueue.unshift(activeJob.job);
          this.metrics.queueLength = this.jobQueue.length;
        }
      }
    }

    // Mark worker as not busy
    worker.busy = false;
    worker.lastActivity = new Date();
  }

  /**
   * Handle worker exit
   */
  private handleWorkerExit(workerId: string, code: number): void {
    const worker = this.workers.get(workerId);
    if (!worker) {
      return;
    }

    this.componentLogger.info('Worker exited', { workerId, code });

    // Remove worker from pool
    this.workers.delete(workerId);
    this.metrics.activeWorkers = this.workers.size;

    // Handle any active job for this worker
    for (const [jobId, activeJob] of this.activeJobs.entries()) {
      if (activeJob.workerId === workerId) {
        this.activeJobs.delete(jobId);
        
        // Requeue job
        this.jobQueue.unshift(activeJob.job);
        this.metrics.queueLength = this.jobQueue.length;

        this.emit('jobFailed', { 
          jobId, 
          error: new Error(`Worker ${workerId} exited unexpectedly`) 
        });
        break;
      }
    }

    // Create replacement worker if below minimum
    if (this.workers.size < this.config.minWorkers) {
      this.createWorker().catch((error) => {
        this.componentLogger.error('Error creating replacement worker', { error });
      });
    }
  }

  /**
   * Handle job timeout
   */
  private handleJobTimeout(jobId: string): void {
    const activeJob = this.activeJobs.get(jobId);
    if (!activeJob) {
      return;
    }

    this.componentLogger.warn('Job timed out', { 
      jobId, 
      workerId: activeJob.workerId,
      timeoutMs: this.config.jobTimeoutMs 
    });

    // Remove from active jobs
    this.activeJobs.delete(jobId);
    
    // Mark worker as not busy
    const worker = this.workers.get(activeJob.workerId);
    if (worker) {
      worker.busy = false;
      worker.jobsFailed++;
    }

    // Update metrics
    this.metrics.failedJobs++;

    // Emit timeout event
    this.emit('jobFailed', { 
      jobId, 
      error: new Error(`Job timed out after ${this.config.jobTimeoutMs}ms`) 
    });
  }

  /**
   * Start health check monitoring
   */
  private startHealthCheck(): void {
    this.healthCheckInterval = setInterval(() => {
      this.performHealthCheck();
    }, this.config.healthCheckIntervalMs);
  }

  /**
   * Perform health check on workers
   */
  private performHealthCheck(): void {
    const now = new Date();
    const idleWorkers: string[] = [];

    for (const [workerId, worker] of this.workers.entries()) {
      const idleTime = now.getTime() - worker.lastActivity.getTime();
      
      if (!worker.busy && idleTime > this.config.workerIdleTimeoutMs) {
        idleWorkers.push(workerId);
      }
    }

    // Terminate idle workers (but keep minimum)
    const workersToTerminate = Math.max(0, idleWorkers.length - this.config.minWorkers);
    
    for (let i = 0; i < workersToTerminate; i++) {
      const workerId = idleWorkers[i];
      const worker = this.workers.get(workerId);
      
      if (worker) {
        this.componentLogger.debug('Terminating idle worker', { workerId });
        
        worker.worker.terminate().catch((error) => {
          this.componentLogger.error('Error terminating idle worker', { workerId, error });
        });
        
        this.workers.delete(workerId);
      }
    }

    this.metrics.activeWorkers = this.workers.size;
    this.updateMetrics();
  }

  /**
   * Update performance metrics
   */
  private updateMetrics(): void {
    const process = globalThis.process;
    
    if (process?.memoryUsage) {
      const memUsage = process.memoryUsage();
      this.metrics.memoryUsageMB = Math.round(memUsage.heapUsed / 1024 / 1024);
    }

    if (process?.cpuUsage) {
      const cpuUsage = process.cpuUsage();
      this.metrics.cpuUsage = (cpuUsage.user + cpuUsage.system) / 1000;
    }

    this.metrics.queueLength = this.jobQueue.length;
    this.metrics.activeWorkers = this.workers.size;

    // Calculate throughput (jobs per second over last minute)
    const completedInLastMinute = this.metrics.completedJobs; // Simplified
    this.metrics.throughputPerSecond = completedInLastMinute / 60;
  }

  /**
   * Update average processing time
   */
  private updateAverageProcessingTime(newTime: number): void {
    const currentAverage = this.metrics.averageProcessingTimeMs;
    const totalCompleted = this.metrics.completedJobs;
    
    if (totalCompleted === 1) {
      this.metrics.averageProcessingTimeMs = newTime;
    } else {
      this.metrics.averageProcessingTimeMs = 
        ((currentAverage * (totalCompleted - 1)) + newTime) / totalCompleted;
    }
  }

  /**
   * Wait for all active jobs to complete
   */
  private async waitForActiveJobsToComplete(): Promise<void> {
    return new Promise<void>((resolve) => {
      if (this.activeJobs.size === 0) {
        resolve();
        return;
      }

      const checkCompletion = () => {
        if (this.activeJobs.size === 0) {
          resolve();
        } else {
          setTimeout(checkCompletion, 100);
        }
      };

      checkCompletion();
    });
  }
}

// Worker thread implementation
if (!isMainThread && workerData?.isWorker) {
  const validator = new CredentialSecurityValidator();
  
  parentPort?.on('message', async (message) => {
    if (message.type === 'validateCredential') {
      try {
        const result = await performCredentialValidation(
          validator,
          message.jobId,
          message.job
        );
        
        parentPort?.postMessage(result);
      } catch (error) {
        parentPort?.postMessage({
          jobId: message.jobId,
          error: error instanceof Error ? error.message : 'Unknown error',
          isValid: false,
          score: 0,
          errors: ['Worker validation failed'],
          warnings: [],
          strengths: [],
          weaknesses: ['Worker validation error'],
          recommendations: ['Retry validation']
        });
      }
    }
  });
}

/**
 * Perform credential validation in worker thread
 */
async function performCredentialValidation(
  validator: CredentialSecurityValidator,
  jobId: string,
  job: ValidationJob
): Promise<EnhancedValidationResult> {
  const startTime = Date.now();
  
  // Base validation using existing validator
  let baseResult: CredentialValidationResult;
  
  switch (job.type) {
    case 'api_key':
      baseResult = validator.validateMakeApiKey(job.credential);
      break;
    default:
      // For other types, use the same validation logic for now
      baseResult = validator.validateMakeApiKey(job.credential);
      break;
  }
  
  // Enhance with additional analysis
  const complianceResults = await analyzeCompliance(job, baseResult);
  const riskAnalysis = await performRiskAnalysis(job, baseResult);
  const remediationSteps = generateRemediationSteps(baseResult, riskAnalysis);
  
  const grade = baseResult.score >= 95 ? 'A+' :
                baseResult.score >= 85 ? 'A' :
                baseResult.score >= 75 ? 'B' :
                baseResult.score >= 65 ? 'C' :
                baseResult.score >= 50 ? 'D' : 'F';

  const result: EnhancedValidationResult = {
    ...baseResult,
    jobId,
    grade,
    processingTimeMs: Date.now() - startTime,
    workerId: 'worker_thread', // Will be updated by main thread
    timestamp: new Date(),
    complianceResults,
    riskAnalysis,
    remediationSteps
  };
  
  return result;
}

/**
 * Analyze compliance against various frameworks
 */
async function analyzeCompliance(
  job: ValidationJob,
  baseResult: CredentialValidationResult
): Promise<ComplianceAssessment[]> {
  const assessments: ComplianceAssessment[] = [];
  const frameworks = job.options?.complianceFrameworks || ['SOC2', 'ISO27001'];
  
  for (const framework of frameworks) {
    let assessment: ComplianceAssessment;
    
    switch (framework) {
      case 'SOC2':
        assessment = analyzeSoc2Compliance(baseResult);
        break;
      case 'ISO27001':
        assessment = analyzeIso27001Compliance(baseResult);
        break;
      case 'PCI-DSS':
        assessment = analyzePciDssCompliance(baseResult);
        break;
      default:
        continue;
    }
    
    assessments.push(assessment);
  }
  
  return assessments;
}

/**
 * Analyze SOC 2 compliance
 */
function analyzeSoc2Compliance(result: CredentialValidationResult): ComplianceAssessment {
  const requirements: ComplianceRequirement[] = [
    {
      id: 'CC6.1',
      description: 'Logical and physical access controls',
      status: result.score >= 70 ? 'compliant' : 'non-compliant',
      evidence: result.score >= 70 ? 'Strong credential validation' : 'Weak credential detected'
    },
    {
      id: 'CC6.2',
      description: 'Authentication and authorization',
      status: result.isValid ? 'compliant' : 'non-compliant',
      evidence: result.isValid ? 'Credential format valid' : 'Invalid credential format'
    }
  ];
  
  const compliantCount = requirements.filter(r => r.status === 'compliant').length;
  const score = Math.round((compliantCount / requirements.length) * 100);
  
  return {
    framework: 'SOC2',
    compliant: score >= 80,
    score,
    requirements,
    gaps: requirements
      .filter(r => r.status !== 'compliant')
      .map(r => r.description),
    recommendations: score < 80 ? [
      'Implement stronger credential policies',
      'Enable multi-factor authentication',
      'Regular credential rotation'
    ] : []
  };
}

/**
 * Analyze ISO 27001 compliance
 */
function analyzeIso27001Compliance(result: CredentialValidationResult): ComplianceAssessment {
  const requirements: ComplianceRequirement[] = [
    {
      id: 'A.9.4.3',
      description: 'Password management system',
      status: result.score >= 80 ? 'compliant' : 'partial',
      evidence: `Security score: ${result.score}/100`
    },
    {
      id: 'A.10.1.1',
      description: 'Cryptographic policy',
      status: result.strengths.length > 0 ? 'compliant' : 'non-compliant',
      evidence: `Strengths identified: ${result.strengths.length}`
    }
  ];
  
  const compliantCount = requirements.filter(r => r.status === 'compliant').length;
  const score = Math.round((compliantCount / requirements.length) * 100);
  
  return {
    framework: 'ISO27001',
    compliant: score >= 85,
    score,
    requirements,
    gaps: requirements
      .filter(r => r.status !== 'compliant')
      .map(r => r.description),
    recommendations: score < 85 ? [
      'Implement comprehensive cryptographic controls',
      'Document credential management procedures',
      'Regular security assessments'
    ] : []
  };
}

/**
 * Analyze PCI DSS compliance
 */
function analyzePciDssCompliance(result: CredentialValidationResult): ComplianceAssessment {
  const requirements: ComplianceRequirement[] = [
    {
      id: '8.2.3',
      description: 'Strong authentication parameters',
      status: result.score >= 80 ? 'compliant' : 'non-compliant',
      evidence: `Authentication strength score: ${result.score}/100`
    },
    {
      id: '8.2.4',
      description: 'Password/passphrase requirements',
      status: result.errors.length === 0 ? 'compliant' : 'non-compliant',
      evidence: `Validation errors: ${result.errors.length}`
    }
  ];
  
  const compliantCount = requirements.filter(r => r.status === 'compliant').length;
  const score = Math.round((compliantCount / requirements.length) * 100);
  
  return {
    framework: 'PCI-DSS',
    compliant: score >= 90,
    score,
    requirements,
    gaps: requirements
      .filter(r => r.status !== 'compliant')
      .map(r => r.description),
    recommendations: score < 90 ? [
      'Implement PCI DSS compliant credential policies',
      'Regular credential strength validation',
      'Secure credential storage mechanisms'
    ] : []
  };
}

/**
 * Perform comprehensive risk analysis
 */
async function performRiskAnalysis(
  job: ValidationJob,
  result: CredentialValidationResult
): Promise<RiskAnalysis> {
  const riskFactors: RiskFactor[] = [];
  
  // Entropy risk
  if (result.weaknesses.some(w => w.includes('entropy'))) {
    riskFactors.push({
      category: 'entropy',
      severity: 'high',
      description: 'Low entropy credential detected',
      impact: 'Credential susceptible to brute force attacks',
      likelihood: 0.8,
      mitigation: 'Regenerate with cryptographically secure random generator'
    });
  }
  
  // Pattern risk
  if (result.warnings.some(w => w.includes('pattern'))) {
    riskFactors.push({
      category: 'pattern',
      severity: 'medium',
      description: 'Predictable patterns detected',
      impact: 'Credential may be guessable',
      likelihood: 0.6,
      mitigation: 'Avoid common patterns and dictionary words'
    });
  }
  
  // Exposure risk
  if (result.warnings.some(w => w.includes('exposure'))) {
    riskFactors.push({
      category: 'exposure',
      severity: 'high',
      description: 'Potential exposure risk identified',
      impact: 'Credential may be compromised',
      likelihood: 0.7,
      mitigation: 'Rotate credential immediately and audit access logs'
    });
  }
  
  // Calculate overall risk
  const maxSeverity = riskFactors.reduce((max, factor) => {
    const severityOrder = { low: 1, medium: 2, high: 3, critical: 4 };
    return severityOrder[factor.severity] > severityOrder[max] ? factor.severity : max;
  }, 'low' as RiskFactor['severity']);
  
  const overallRisk = result.score < 40 ? 'critical' :
                     result.score < 60 ? 'high' :
                     result.score < 80 ? 'medium' : 'low';
  
  return {
    overallRisk,
    riskFactors,
    mitigationStrategies: riskFactors.map(f => f.mitigation).filter(Boolean) as string[],
    priorityScore: Math.max(0, 100 - result.score),
    exposurePaths: [
      'API requests',
      'Configuration files',
      'Environment variables',
      'Log files'
    ]
  };
}

/**
 * Generate remediation steps based on analysis
 */
function generateRemediationSteps(
  result: CredentialValidationResult,
  riskAnalysis: RiskAnalysis
): RemediationStep[] {
  const steps: RemediationStep[] = [];
  
  if (result.score < 40) {
    steps.push({
      priority: 'immediate',
      action: 'Regenerate credential',
      description: 'Current credential has critical security issues',
      estimatedEffort: 'low',
      category: 'regeneration',
      timeline: 'Within 24 hours'
    });
  }
  
  if (riskAnalysis.overallRisk === 'high' || riskAnalysis.overallRisk === 'critical') {
    steps.push({
      priority: 'high',
      action: 'Implement credential monitoring',
      description: 'Set up real-time monitoring for credential usage',
      estimatedEffort: 'medium',
      category: 'monitoring',
      timeline: 'Within 1 week'
    });
  }
  
  if (result.recommendations.some(r => r.includes('rotation'))) {
    steps.push({
      priority: 'medium',
      action: 'Establish rotation policy',
      description: 'Implement automatic credential rotation',
      estimatedEffort: 'high',
      category: 'policy',
      timeline: 'Within 30 days'
    });
  }
  
  return steps;
}

/**
 * Factory function to create concurrent validation agent
 */
export function createConcurrentValidationAgent(config?: Partial<WorkerPoolConfig>): ConcurrentValidationAgent {
  return new ConcurrentValidationAgent(config);
}

// Export singleton instance for convenience
export const concurrentValidationAgent = new ConcurrentValidationAgent();

export default ConcurrentValidationAgent;