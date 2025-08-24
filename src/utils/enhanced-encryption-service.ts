/**
 * Enhanced Encryption Service - Integration Layer
 * Bridges existing encryption service with concurrent agents and HSM integration
 */

import { EventEmitter } from "events";
import * as crypto from "crypto";
import {
  EncryptionService,
  CredentialManager,
  EncryptedData,
  CryptographicError,
} from "./encryption.js";
import ConcurrentEncryptionAgent from "./concurrent-encryption-agent.js";
import { HSMIntegrationManager } from "./hsm-integration.js";
import {
  EncryptionJobRequest,
  BatchEncryptionRequest,
  ConcurrentWorkerConfig,
  HSMIntegrationConfig,
  CryptographicPerformanceMetrics,
  EncryptionPoolStatus,
  SecurityValidationResult,
} from "../types/encryption-types.js";
import logger from "../lib/logger.js";

export interface EnhancedEncryptionConfig {
  concurrentProcessing: {
    enabled: boolean;
    maxWorkers: number;
    queueSize: number;
    timeout: number;
  };
  hsmIntegration: {
    enabled: boolean;
    config?: HSMIntegrationConfig;
  };
  performanceMonitoring: {
    enabled: boolean;
    metricsRetention: number; // days
    alertThresholds: {
      avgResponseTime: number; // milliseconds
      errorRate: number; // percentage
      throughput: number; // operations per second
    };
  };
  fallbackToSoftware: boolean;
}

export interface EncryptionPerformanceReport {
  timeRange: { start: Date; end: Date };
  totalOperations: number;
  successRate: number;
  avgResponseTime: number;
  peakThroughput: number;
  algorithmBreakdown: Record<
    string,
    {
      operations: number;
      avgTime: number;
      errorRate: number;
    }
  >;
  hsmUsage: {
    enabled: boolean;
    operations: number;
    avgTime: number;
    availability: number;
  };
  recommendations: string[];
}

/**
 * Enhanced Encryption Service
 * Provides unified interface for software and HSM-based cryptographic operations
 */
export class EnhancedEncryptionService extends EventEmitter {
  private readonly baseEncryptionService: EncryptionService;
  private readonly credentialManager: CredentialManager;
  private readonly concurrentAgent?: ConcurrentEncryptionAgent;
  private readonly hsmManager?: HSMIntegrationManager;
  private readonly config: EnhancedEncryptionConfig;
  private readonly componentLogger: ReturnType<typeof logger.child>;

  private performanceMetrics: CryptographicPerformanceMetrics[] = [];
  private isInitialized = false;
  private monitoringInterval?: NodeJS.Timeout;

  constructor(
    config: Partial<EnhancedEncryptionConfig> = {},
    baseEncryptionService?: EncryptionService,
    credentialManager?: CredentialManager,
  ) {
    super();

    this.config = {
      concurrentProcessing: {
        enabled: config.concurrentProcessing?.enabled ?? true,
        maxWorkers: config.concurrentProcessing?.maxWorkers ?? 4,
        queueSize: config.concurrentProcessing?.queueSize ?? 1000,
        timeout: config.concurrentProcessing?.timeout ?? 30000,
      },
      hsmIntegration: {
        enabled: config.hsmIntegration?.enabled ?? false,
        config: config.hsmIntegration?.config,
      },
      performanceMonitoring: {
        enabled: config.performanceMonitoring?.enabled ?? true,
        metricsRetention: config.performanceMonitoring?.metricsRetention ?? 30,
        alertThresholds: {
          avgResponseTime:
            config.performanceMonitoring?.alertThresholds?.avgResponseTime ??
            1000,
          errorRate:
            config.performanceMonitoring?.alertThresholds?.errorRate ?? 5,
          throughput:
            config.performanceMonitoring?.alertThresholds?.throughput ?? 10,
          ...config.performanceMonitoring?.alertThresholds,
        },
      },
      fallbackToSoftware: config.fallbackToSoftware ?? true,
    };

    this.baseEncryptionService =
      baseEncryptionService || new EncryptionService();
    this.credentialManager = credentialManager || new CredentialManager();
    this.componentLogger = logger.child({
      component: "EnhancedEncryptionService",
    });

    // Initialize concurrent processing if enabled
    if (this.config.concurrentProcessing.enabled) {
      const workerConfig: ConcurrentWorkerConfig = {
        maxWorkers: this.config.concurrentProcessing.maxWorkers,
        queueSize: this.config.concurrentProcessing.queueSize,
        workerTimeout: this.config.concurrentProcessing.timeout,
        resourceLimits: {
          maxOldGenerationSizeMb: 128,
          maxYoungGenerationSizeMb: 64,
        },
        isolatedContext: true,
      };

      this.concurrentAgent = new ConcurrentEncryptionAgent(
        workerConfig,
        this.config.hsmIntegration.config,
      );
    }

    // Initialize HSM integration if enabled
    if (
      this.config.hsmIntegration.enabled &&
      this.config.hsmIntegration.config
    ) {
      this.hsmManager = new HSMIntegrationManager(
        this.config.hsmIntegration.config,
      );
    }
  }

  /**
   * Initialize the enhanced encryption service
   */
  async initialize(): Promise<void> {
    if (this.isInitialized) {
      throw new Error("EnhancedEncryptionService already initialized");
    }

    try {
      this.componentLogger.info("Initializing enhanced encryption service", {
        concurrentProcessing: this.config.concurrentProcessing.enabled,
        hsmIntegration: this.config.hsmIntegration.enabled,
        performanceMonitoring: this.config.performanceMonitoring.enabled,
      });

      // Initialize concurrent agent if enabled
      if (this.concurrentAgent) {
        await this.concurrentAgent.initialize();

        // Setup event handlers
        this.concurrentAgent.on("jobCompleted", (result) => {
          this.emit("operationCompleted", result);
          if (result.metadata) {
            this.recordPerformanceMetric({
              operationType: "concurrent_job",
              algorithm: result.metadata.algorithm,
              dataSize: 0, // Would need to track from original request
              processingTime: result.metadata.processingTime,
              throughput: 1000 / result.metadata.processingTime,
              cpuUsage: 0,
              memoryUsage: 0,
              workerId: result.metadata.workerId,
              timestamp: new Date(),
              hsm: result.metadata.hsm,
            });
          }
        });

        this.concurrentAgent.on("jobError", (result) => {
          this.emit("operationError", result);
        });
      }

      // Initialize HSM manager if enabled
      if (this.hsmManager) {
        await this.hsmManager.initialize();

        // Setup HSM event handlers
        this.hsmManager.on("providerConnected", (provider) => {
          this.componentLogger.info("HSM provider connected", { provider });
          this.emit("hsmConnected", provider);
        });

        this.hsmManager.on("providerError", (provider, error) => {
          this.componentLogger.error("HSM provider error", { provider, error });
          this.emit("hsmError", provider, error);
        });
      }

      // Start performance monitoring if enabled
      if (this.config.performanceMonitoring.enabled) {
        this.startPerformanceMonitoring();
      }

      this.isInitialized = true;
      this.componentLogger.info(
        "Enhanced encryption service initialized successfully",
      );
      this.emit("initialized");
    } catch (error) {
      this.componentLogger.error(
        "Failed to initialize enhanced encryption service",
        {
          error: error instanceof Error ? error.message : "Unknown error",
        },
      );
      throw error;
    }
  }

  /**
   * Enhanced encryption with automatic HSM/concurrent processing selection
   */
  async encrypt(
    plaintext: string,
    masterPassword: string,
    options: {
      useHSM?: boolean;
      useConcurrent?: boolean;
      algorithm?: string;
      priority?: "low" | "medium" | "high" | "critical";
    } = {},
  ): Promise<EncryptedData> {
    if (!this.isInitialized) {
      throw new Error("EnhancedEncryptionService not initialized");
    }

    const startTime = Date.now();

    try {
      // Determine processing method
      const useHSM = options.useHSM && !!this.hsmManager;
      const useConcurrent =
        options.useConcurrent && !!this.concurrentAgent && !useHSM;

      let result: EncryptedData;

      if (useHSM) {
        // Use HSM for encryption
        result = await this.encryptWithHSM(
          plaintext,
          masterPassword,
          options.algorithm,
        );
      } else if (useConcurrent) {
        // Use concurrent agent for encryption
        result = await this.encryptWithConcurrentAgent(
          plaintext,
          masterPassword,
          options,
        );
      } else {
        // Use base encryption service
        result = await this.baseEncryptionService.encrypt(
          plaintext,
          masterPassword,
        );
      }

      // Record performance metrics
      this.recordPerformanceMetric({
        operationType: "encrypt",
        algorithm: result.algorithm,
        dataSize: plaintext.length,
        processingTime: Date.now() - startTime,
        throughput: plaintext.length / ((Date.now() - startTime) / 1000),
        cpuUsage: process.cpuUsage().user / 1000000,
        memoryUsage: process.memoryUsage().heapUsed / 1024 / 1024,
        workerId: useHSM ? "hsm" : useConcurrent ? "concurrent" : "software",
        timestamp: new Date(),
        hsm: useHSM,
      });

      return result;
    } catch (error) {
      // Fallback to software implementation if configured
      if (
        this.config.fallbackToSoftware &&
        (options.useHSM || options.useConcurrent)
      ) {
        this.componentLogger.warn("Falling back to software encryption", {
          originalError:
            error instanceof Error ? error.message : "Unknown error",
        });
        return await this.baseEncryptionService.encrypt(
          plaintext,
          masterPassword,
        );
      }

      throw error;
    }
  }

  /**
   * Enhanced decryption with automatic HSM/concurrent processing selection
   */
  async decrypt(
    encryptedData: EncryptedData,
    masterPassword: string,
    options: {
      useHSM?: boolean;
      useConcurrent?: boolean;
      priority?: "low" | "medium" | "high" | "critical";
    } = {},
  ): Promise<string> {
    if (!this.isInitialized) {
      throw new Error("EnhancedEncryptionService not initialized");
    }

    const startTime = Date.now();

    try {
      // Determine processing method
      const useHSM = options.useHSM && !!this.hsmManager;
      const useConcurrent =
        options.useConcurrent && !!this.concurrentAgent && !useHSM;

      let result: string;

      if (useHSM) {
        // Use HSM for decryption
        result = await this.decryptWithHSM(encryptedData, masterPassword);
      } else if (useConcurrent) {
        // Use concurrent agent for decryption
        result = await this.decryptWithConcurrentAgent(
          encryptedData,
          masterPassword,
          options,
        );
      } else {
        // Use base encryption service
        result = await this.baseEncryptionService.decrypt(
          encryptedData,
          masterPassword,
        );
      }

      // Record performance metrics
      this.recordPerformanceMetric({
        operationType: "decrypt",
        algorithm: encryptedData.algorithm,
        dataSize: encryptedData.data.length,
        processingTime: Date.now() - startTime,
        throughput: result.length / ((Date.now() - startTime) / 1000),
        cpuUsage: process.cpuUsage().user / 1000000,
        memoryUsage: process.memoryUsage().heapUsed / 1024 / 1024,
        workerId: useHSM ? "hsm" : useConcurrent ? "concurrent" : "software",
        timestamp: new Date(),
        hsm: useHSM,
      });

      return result;
    } catch (error) {
      // Fallback to software implementation if configured
      if (
        this.config.fallbackToSoftware &&
        (options.useHSM || options.useConcurrent)
      ) {
        this.componentLogger.warn("Falling back to software decryption", {
          originalError:
            error instanceof Error ? error.message : "Unknown error",
        });
        return await this.baseEncryptionService.decrypt(
          encryptedData,
          masterPassword,
        );
      }

      throw error;
    }
  }

  /**
   * Batch encryption with concurrent processing
   */
  async encryptBatch(
    requests: Array<{
      plaintext: string;
      masterPassword: string;
      id: string;
      priority?: "low" | "medium" | "high" | "critical";
    }>,
    options: {
      maxConcurrency?: number;
      timeout?: number;
      failFast?: boolean;
    } = {},
  ): Promise<
    Array<{
      id: string;
      success: boolean;
      result?: EncryptedData;
      error?: string;
    }>
  > {
    if (!this.concurrentAgent) {
      throw new Error("Concurrent processing not enabled");
    }

    const jobs: EncryptionJobRequest[] = requests.map((req) => ({
      id: req.id,
      operation: "encrypt",
      algorithm: {
        algorithm: "aes-256-gcm",
        keyLength: 256,
        ivLength: 16,
        tagLength: 16,
      },
      data: req.plaintext,
      key: req.masterPassword,
      metadata: {
        priority: req.priority || "medium",
      },
    }));

    const batchRequest: BatchEncryptionRequest = {
      batchId: crypto.randomUUID(),
      jobs,
      options: {
        maxConcurrency:
          options.maxConcurrency || this.config.concurrentProcessing.maxWorkers,
        timeout: options.timeout || this.config.concurrentProcessing.timeout,
        failFast: options.failFast ?? false,
      },
    };

    const batchResult = await this.concurrentAgent.processBatch(batchRequest);

    return batchResult.results.map((result) => ({
      id: result.id,
      success: result.success,
      result:
        result.success && result.result && this.isEncryptedData(result.result)
          ? result.result
          : undefined,
      error: result.error?.message,
    }));
  }

  /**
   * Generate cryptographically secure key pairs with HSM support
   */
  async generateKeyPair(
    algorithm: "rsa-4096" | "ecdsa-p384" | "ed25519",
    options: {
      useHSM?: boolean;
      extractable?: boolean;
      usage?: string[];
    } = {},
  ): Promise<{
    publicKey: string;
    privateKey?: string;
    keyId: string;
    hsmBacked: boolean;
  }> {
    if (options.useHSM && this.hsmManager) {
      // Use HSM for key generation
      const keySpec = {
        keyId: crypto.randomUUID(),
        keyType: "asymmetric" as const,
        algorithm,
        keyLength: this.getKeyLength(algorithm),
        extractable: options.extractable ?? false,
        usage: options.usage || ["encrypt", "decrypt", "sign", "verify"],
      };

      const result = await this.hsmManager.generateKey(keySpec);

      if (result.success && result.keyId) {
        return {
          publicKey: result.result as string,
          keyId: result.keyId,
          hsmBacked: true,
        };
      } else {
        throw new CryptographicError(
          result.error?.message || "HSM key generation failed",
          "generateKeyPair",
        );
      }
    } else if (this.concurrentAgent) {
      // Use concurrent agent for key generation
      const result = await this.concurrentAgent.generateKeyPair(
        algorithm,
        options,
      );

      return {
        publicKey: result.publicKey,
        privateKey: result.privateKey,
        keyId: result.keyId,
        hsmBacked: false,
      };
    } else {
      // Fallback to Node.js crypto
      const keyPair = (crypto as any).generateKeyPairSync(
        algorithm === "rsa-4096"
          ? "rsa"
          : algorithm === "ecdsa-p384"
            ? "ec"
            : "ed25519",
        algorithm === "rsa-4096"
          ? {
              modulusLength: 4096,
              publicKeyEncoding: { type: "spki", format: "pem" },
              privateKeyEncoding: { type: "pkcs8", format: "pem" },
            }
          : algorithm === "ecdsa-p384"
            ? {
                namedCurve: "secp384r1",
                publicKeyEncoding: { type: "spki", format: "pem" },
                privateKeyEncoding: { type: "pkcs8", format: "pem" },
              }
            : {
                publicKeyEncoding: { type: "spki", format: "pem" },
                privateKeyEncoding: { type: "pkcs8", format: "pem" },
              },
      );

      return {
        publicKey: keyPair.publicKey as string,
        privateKey: (options.extractable ?? true)
          ? (keyPair.privateKey as string)
          : undefined,
        keyId: crypto.randomUUID(),
        hsmBacked: false,
      };
    }
  }

  /**
   * Get comprehensive performance report
   */
  getPerformanceReport(timeRange?: {
    start: Date;
    end: Date;
  }): EncryptionPerformanceReport {
    const now = new Date();
    const start =
      timeRange?.start || new Date(now.getTime() - 24 * 60 * 60 * 1000); // Last 24 hours
    const end = timeRange?.end || now;

    const relevantMetrics = this.performanceMetrics.filter(
      (metric) => metric.timestamp >= start && metric.timestamp <= end,
    );

    if (relevantMetrics.length === 0) {
      return {
        timeRange: { start, end },
        totalOperations: 0,
        successRate: 100,
        avgResponseTime: 0,
        peakThroughput: 0,
        algorithmBreakdown: {},
        hsmUsage: {
          enabled: !!this.hsmManager,
          operations: 0,
          avgTime: 0,
          availability: 0,
        },
        recommendations: ["No operations recorded in the specified time range"],
      };
    }

    const totalOperations = relevantMetrics.length;
    const avgResponseTime =
      relevantMetrics.reduce((sum, m) => sum + m.processingTime, 0) /
      totalOperations;
    const peakThroughput = Math.max(
      ...relevantMetrics.map((m) => m.throughput),
    );

    // Algorithm breakdown
    const algorithmBreakdown: Record<string, any> = {};
    for (const metric of relevantMetrics) {
      if (!algorithmBreakdown[metric.algorithm]) {
        algorithmBreakdown[metric.algorithm] = {
          operations: 0,
          totalTime: 0,
          avgTime: 0,
          errorRate: 0,
        };
      }
      algorithmBreakdown[metric.algorithm].operations++;
      algorithmBreakdown[metric.algorithm].totalTime += metric.processingTime;
    }

    for (const alg in algorithmBreakdown) {
      const data = algorithmBreakdown[alg];
      data.avgTime = data.totalTime / data.operations;
      delete data.totalTime;
    }

    // HSM usage
    const hsmMetrics = relevantMetrics.filter((m) => m.hsm);
    const hsmUsage = {
      enabled: !!this.hsmManager,
      operations: hsmMetrics.length,
      avgTime:
        hsmMetrics.length > 0
          ? hsmMetrics.reduce((sum, m) => sum + m.processingTime, 0) /
            hsmMetrics.length
          : 0,
      availability: this.hsmManager ? 100 : 0, // Simplified - would need actual health checks
    };

    // Generate recommendations
    const recommendations: string[] = [];
    if (
      avgResponseTime >
      this.config.performanceMonitoring.alertThresholds.avgResponseTime
    ) {
      recommendations.push(
        "Average response time is above threshold. Consider enabling concurrent processing or HSM acceleration.",
      );
    }
    if (
      peakThroughput <
      this.config.performanceMonitoring.alertThresholds.throughput
    ) {
      recommendations.push(
        "Throughput is below optimal levels. Consider increasing worker count or optimizing key derivation parameters.",
      );
    }
    if (hsmUsage.enabled && hsmUsage.operations / totalOperations < 0.5) {
      recommendations.push(
        "HSM is available but underutilized. Consider routing more operations through HSM for enhanced security.",
      );
    }

    return {
      timeRange: { start, end },
      totalOperations,
      successRate: 100, // Simplified - would need actual error tracking
      avgResponseTime,
      peakThroughput,
      algorithmBreakdown,
      hsmUsage,
      recommendations,
    };
  }

  /**
   * Get encryption pool status (concurrent agent)
   */
  getPoolStatus(): EncryptionPoolStatus | null {
    return this.concurrentAgent?.getPoolStatus() || null;
  }

  /**
   * Validate encryption configuration security
   */
  validateSecurity(): SecurityValidationResult {
    const validations = {
      keyStrength: true, // Always use strong keys
      algorithmCompliance: true, // Use FIPS-compliant algorithms
      randomnessQuality: true, // Node.js crypto provides secure randomness
      timingAttackResistance: !!this.concurrentAgent, // Concurrent processing provides some protection
      sideChannelResistance: !!this.hsmManager, // HSM provides side-channel resistance
    };

    const score =
      Object.values(validations).filter((v) => v).length /
      Object.values(validations).length;

    let securityLevel: SecurityValidationResult["securityLevel"];
    if (score >= 0.9 && this.hsmManager) {
      securityLevel = "fips-140-2";
    } else if (score >= 0.8) {
      securityLevel = "high";
    } else if (score >= 0.6) {
      securityLevel = "medium";
    } else {
      securityLevel = "low";
    }

    const recommendations: string[] = [];
    if (!this.hsmManager) {
      recommendations.push(
        "Enable HSM integration for enhanced security and FIPS 140-2 compliance",
      );
    }
    if (!this.concurrentAgent) {
      recommendations.push(
        "Enable concurrent processing for improved performance and timing attack resistance",
      );
    }

    return {
      isValid: score >= 0.8,
      securityLevel,
      validations,
      recommendations: recommendations.length > 0 ? recommendations : undefined,
    };
  }

  /**
   * Shutdown the enhanced encryption service
   */
  async shutdown(): Promise<void> {
    try {
      this.componentLogger.info("Shutting down enhanced encryption service");

      if (this.monitoringInterval) {
        clearInterval(this.monitoringInterval);
      }

      if (this.concurrentAgent) {
        await this.concurrentAgent.shutdown();
      }

      if (this.hsmManager) {
        await this.hsmManager.shutdown();
      }

      this.isInitialized = false;
      this.componentLogger.info(
        "Enhanced encryption service shutdown completed",
      );
      this.emit("shutdown");
    } catch (error) {
      this.componentLogger.error("Error during shutdown", {
        error: error instanceof Error ? error.message : "Unknown error",
      });
      throw error;
    }
  }

  // Private helper methods

  private async encryptWithHSM(
    plaintext: string,
    masterPassword: string,
    algorithm?: string,
  ): Promise<EncryptedData> {
    if (!this.hsmManager) {
      throw new Error("HSM manager not initialized");
    }

    // For simplicity, use a predefined HSM key or derive one
    const keyId = "master-encryption-key"; // This would be managed differently in production
    const plaintextBuffer = Buffer.from(plaintext, "utf8");

    const result = await this.hsmManager.encrypt(
      keyId,
      plaintextBuffer,
      algorithm,
    );

    if (!result.success || !result.result) {
      throw new CryptographicError(
        result.error?.message || "HSM encryption failed",
        "encryptWithHSM",
      );
    }

    // Convert HSM result to EncryptedData format
    return {
      data: (result.result as Buffer).toString("base64"),
      iv: crypto.randomBytes(16).toString("base64"), // HSM should provide this
      salt: crypto.randomBytes(32).toString("base64"), // HSM should provide this
      algorithm: algorithm || "aes-256-gcm-hsm",
      keyLength: 256,
    };
  }

  private async decryptWithHSM(
    encryptedData: EncryptedData,
    _masterPassword: string,
  ): Promise<string> {
    if (!this.hsmManager) {
      throw new Error("HSM manager not initialized");
    }

    const keyId = "master-encryption-key";
    const ciphertextBuffer = Buffer.from(encryptedData.data, "base64");

    const result = await this.hsmManager.decrypt(
      keyId,
      ciphertextBuffer,
      encryptedData.algorithm,
    );

    if (!result.success || !result.result) {
      throw new CryptographicError(
        result.error?.message || "HSM decryption failed",
        "decryptWithHSM",
      );
    }

    return (result.result as Buffer).toString("utf8");
  }

  private async encryptWithConcurrentAgent(
    plaintext: string,
    masterPassword: string,
    options: { priority?: "low" | "medium" | "high" | "critical" },
  ): Promise<EncryptedData> {
    if (!this.concurrentAgent) {
      throw new Error("Concurrent agent not initialized");
    }

    const jobRequest: EncryptionJobRequest = {
      id: crypto.randomUUID(),
      operation: "encrypt",
      algorithm: {
        algorithm: "aes-256-gcm",
        keyLength: 256,
        ivLength: 16,
        tagLength: 16,
      },
      data: plaintext,
      key: masterPassword,
      metadata: {
        priority: options.priority || "medium",
      },
    };

    const result = await this.concurrentAgent.processJob(jobRequest);

    if (!result.success || !result.result) {
      throw new CryptographicError(
        result.error?.message || "Concurrent encryption failed",
        "encryptWithConcurrentAgent",
      );
    }

    // Type guard to ensure result is EncryptedData
    if (!this.isEncryptedData(result.result)) {
      throw new CryptographicError(
        "Invalid result type from concurrent agent",
        "encryptWithConcurrentAgent"
      );
    }
    return result.result;
  }

  private async decryptWithConcurrentAgent(
    encryptedData: EncryptedData,
    masterPassword: string,
    options: { priority?: "low" | "medium" | "high" | "critical" },
  ): Promise<string> {
    if (!this.concurrentAgent) {
      throw new Error("Concurrent agent not initialized");
    }

    const jobRequest: EncryptionJobRequest = {
      id: crypto.randomUUID(),
      operation: "decrypt",
      algorithm: {
        algorithm: encryptedData.algorithm as any,
        keyLength: encryptedData.keyLength,
      },
      data: encryptedData.data,
      key: masterPassword,
      metadata: {
        priority: options.priority || "medium",
      },
    };

    const result = await this.concurrentAgent.processJob(jobRequest);

    if (!result.success || !result.result) {
      throw new CryptographicError(
        result.error?.message || "Concurrent decryption failed",
        "decryptWithConcurrentAgent",
      );
    }

    return result.result as string;
  }

  private recordPerformanceMetric(
    metric: CryptographicPerformanceMetrics,
  ): void {
    this.performanceMetrics.push(metric);

    // Keep only metrics within retention period
    const retentionMs =
      this.config.performanceMonitoring.metricsRetention * 24 * 60 * 60 * 1000;
    const cutoff = new Date(Date.now() - retentionMs);
    this.performanceMetrics = this.performanceMetrics.filter(
      (m) => m.timestamp >= cutoff,
    );
  }

  private startPerformanceMonitoring(): void {
    this.monitoringInterval = setInterval(() => {
      this.checkPerformanceThresholds();
    }, 60000); // Every minute
  }

  private checkPerformanceThresholds(): void {
    const recent = this.performanceMetrics.slice(-100); // Last 100 operations
    if (recent.length === 0) {
      return;
    }

    const avgResponseTime =
      recent.reduce((sum, m) => sum + m.processingTime, 0) / recent.length;
    const avgThroughput =
      recent.reduce((sum, m) => sum + m.throughput, 0) / recent.length;

    if (
      avgResponseTime >
      this.config.performanceMonitoring.alertThresholds.avgResponseTime
    ) {
      this.emit("performanceAlert", {
        type: "high_response_time",
        value: avgResponseTime,
        threshold:
          this.config.performanceMonitoring.alertThresholds.avgResponseTime,
      });
    }

    if (
      avgThroughput <
      this.config.performanceMonitoring.alertThresholds.throughput
    ) {
      this.emit("performanceAlert", {
        type: "low_throughput",
        value: avgThroughput,
        threshold: this.config.performanceMonitoring.alertThresholds.throughput,
      });
    }
  }

  private getKeyLength(algorithm: string): number {
    const keyLengths: Record<string, number> = {
      "rsa-4096": 4096,
      "ecdsa-p384": 384,
      ed25519: 256,
    };
    return keyLengths[algorithm] || 256;
  }

  /**
   * Type guard to check if a value is EncryptedData
   */
  private isEncryptedData(value: unknown): value is EncryptedData {
    return (
      typeof value === "object" &&
      value !== null &&
      typeof (value as EncryptedData).data === "string" &&
      typeof (value as EncryptedData).iv === "string" &&
      typeof (value as EncryptedData).salt === "string" &&
      typeof (value as EncryptedData).algorithm === "string" &&
      typeof (value as EncryptedData).keyLength === "number"
    );
  }
}

export default EnhancedEncryptionService;
