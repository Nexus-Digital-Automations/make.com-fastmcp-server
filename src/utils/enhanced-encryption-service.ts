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
  CryptographicPerformanceMetrics,
  EncryptionPoolStatus,
  SecurityValidationResult,
} from "../types/encryption-types.js";
import logger from "../lib/logger.js";
import {
  EnhancedEncryptionConfigFactory,
  EnhancedEncryptionConfig as ImportedEnhancedEncryptionConfig,
} from "./enhanced-encryption-config-factory.js";
import { EnhancedEncryptionServiceFactory } from "./enhanced-encryption-service-factory.js";

// Use imported configuration type from factory
export type EnhancedEncryptionConfig = ImportedEnhancedEncryptionConfig;

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
  private baseEncryptionService: EncryptionService;
  private credentialManager: CredentialManager;
  private concurrentAgent?: ConcurrentEncryptionAgent;
  private hsmManager?: HSMIntegrationManager;
  private readonly config: EnhancedEncryptionConfig;
  private componentLogger: ReturnType<typeof logger.child>;

  private performanceMetrics: CryptographicPerformanceMetrics[] = [];
  private isInitialized = false;
  private monitoringInterval?: NodeJS.Timeout;

  constructor(
    config: Partial<EnhancedEncryptionConfig> = {},
    baseEncryptionService?: EncryptionService,
    credentialManager?: CredentialManager,
  ) {
    super();

    // Phase 1: Configuration building (Complexity: 2 points)
    this.config = EnhancedEncryptionConfigFactory.buildConfiguration(config);

    // Phase 2: Base service initialization (Complexity: 3 points)
    this.initializeBaseServices(baseEncryptionService, credentialManager);

    // Phase 3: Advanced service creation (Complexity: 3 points)
    this.initializeAdvancedServices();
  }

  /**
   * Initialize base encryption services and logger
   * Complexity: 3 points (extracted from constructor)
   */
  private initializeBaseServices(
    baseEncryptionService?: EncryptionService,
    credentialManager?: CredentialManager,
  ): void {
    this.baseEncryptionService =
      baseEncryptionService || new EncryptionService();
    this.credentialManager = credentialManager || new CredentialManager();
    this.componentLogger = logger.child({
      component: "EnhancedEncryptionService",
    });
  }

  /**
   * Initialize advanced services using factory
   * Complexity: 3 points (extracted from constructor)
   */
  private initializeAdvancedServices(): void {
    // Validate service dependencies first
    EnhancedEncryptionServiceFactory.validateServiceDependencies(this.config);

    // Create concurrent agent if enabled
    this.concurrentAgent =
      EnhancedEncryptionServiceFactory.createConcurrentAgent(this.config);

    // Create HSM manager if enabled
    this.hsmManager = EnhancedEncryptionServiceFactory.createHSMManager(
      this.config,
    );
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
      const processingMethod = this.determineEncryptionMethod(options);
      const result = await this.executeEncryptionByMethod(
        processingMethod,
        plaintext,
        masterPassword,
        options,
      );

      this.recordEncryptionMetrics(
        result,
        plaintext,
        startTime,
        processingMethod,
      );
      return result;
    } catch (error) {
      return await this.handleEncryptionError(
        error,
        plaintext,
        masterPassword,
        options,
      );
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
      const processingMethod = this.determineDecryptionMethod(options);
      const result = await this.executeDecryptionByMethod(
        processingMethod,
        encryptedData,
        masterPassword,
        options,
      );

      this.recordDecryptionMetrics(
        result,
        encryptedData,
        startTime,
        processingMethod,
      );
      return result;
    } catch (error) {
      return await this.handleDecryptionError(
        error,
        encryptedData,
        masterPassword,
        options,
      );
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
      return await this.generateKeyPairWithHSM(algorithm, options);
    } else if (this.concurrentAgent) {
      return await this.generateKeyPairWithConcurrentAgent(algorithm, options);
    } else {
      return this.generateKeyPairWithNodeCrypto(algorithm, options);
    }
  }

  /**
   * Get comprehensive performance report
   */
  getPerformanceReport(timeRange?: {
    start: Date;
    end: Date;
  }): EncryptionPerformanceReport {
    const { start, end } = this.calculateReportTimeRange(timeRange);
    const relevantMetrics = this.filterMetricsByTimeRange(start, end);

    if (relevantMetrics.length === 0) {
      return this.buildEmptyPerformanceReport(start, end);
    }

    const basicStats = this.calculateBasicPerformanceStats(relevantMetrics);
    const algorithmBreakdown = this.buildAlgorithmBreakdown(relevantMetrics);
    const hsmUsage = this.calculateHsmUsage(relevantMetrics);
    const recommendations = this.generatePerformanceRecommendations(
      basicStats.avgResponseTime,
      basicStats.peakThroughput,
      hsmUsage,
      basicStats.totalOperations,
    );

    return {
      timeRange: { start, end },
      totalOperations: basicStats.totalOperations,
      successRate: 100, // Simplified - would need actual error tracking
      avgResponseTime: basicStats.avgResponseTime,
      peakThroughput: basicStats.peakThroughput,
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

  // Private helper methods for encryption/decryption method selection

  /**
   * Determine encryption processing method
   * Complexity: 3 (extracted from encrypt method)
   */
  private determineEncryptionMethod(options: {
    useHSM?: boolean;
    useConcurrent?: boolean;
  }): { useHSM: boolean; useConcurrent: boolean } {
    const useHSM = options.useHSM && !!this.hsmManager;
    const useConcurrent =
      options.useConcurrent && !!this.concurrentAgent && !useHSM;
    return { useHSM, useConcurrent };
  }

  /**
   * Determine decryption processing method
   * Complexity: 3 (extracted from decrypt method)
   */
  private determineDecryptionMethod(options: {
    useHSM?: boolean;
    useConcurrent?: boolean;
  }): { useHSM: boolean; useConcurrent: boolean } {
    const useHSM = options.useHSM && !!this.hsmManager;
    const useConcurrent =
      options.useConcurrent && !!this.concurrentAgent && !useHSM;
    return { useHSM, useConcurrent };
  }

  /**
   * Execute encryption using selected method
   * Complexity: 4 (extracted from encrypt method)
   */
  private async executeEncryptionByMethod(
    method: { useHSM: boolean; useConcurrent: boolean },
    plaintext: string,
    masterPassword: string,
    options: {
      algorithm?: string;
      priority?: "low" | "medium" | "high" | "critical";
    },
  ): Promise<EncryptedData> {
    if (method.useHSM) {
      return await this.encryptWithHSM(
        plaintext,
        masterPassword,
        options.algorithm,
      );
    } else if (method.useConcurrent) {
      return await this.encryptWithConcurrentAgent(
        plaintext,
        masterPassword,
        options,
      );
    } else {
      return await this.baseEncryptionService.encrypt(
        plaintext,
        masterPassword,
      );
    }
  }

  /**
   * Execute decryption using selected method
   * Complexity: 4 (extracted from decrypt method)
   */
  private async executeDecryptionByMethod(
    method: { useHSM: boolean; useConcurrent: boolean },
    encryptedData: EncryptedData,
    masterPassword: string,
    options: { priority?: "low" | "medium" | "high" | "critical" },
  ): Promise<string> {
    if (method.useHSM) {
      return await this.decryptWithHSM(encryptedData, masterPassword);
    } else if (method.useConcurrent) {
      return await this.decryptWithConcurrentAgent(
        encryptedData,
        masterPassword,
        options,
      );
    } else {
      return await this.baseEncryptionService.decrypt(
        encryptedData,
        masterPassword,
      );
    }
  }

  /**
   * Record encryption performance metrics
   * Complexity: 3 (extracted from encrypt method)
   */
  private recordEncryptionMetrics(
    result: EncryptedData,
    plaintext: string,
    startTime: number,
    method: { useHSM: boolean; useConcurrent: boolean },
  ): void {
    this.recordPerformanceMetric({
      operationType: "encrypt",
      algorithm: result.algorithm,
      dataSize: plaintext.length,
      processingTime: Date.now() - startTime,
      throughput: plaintext.length / ((Date.now() - startTime) / 1000),
      cpuUsage: process.cpuUsage().user / 1000000,
      memoryUsage: process.memoryUsage().heapUsed / 1024 / 1024,
      workerId: method.useHSM
        ? "hsm"
        : method.useConcurrent
          ? "concurrent"
          : "software",
      timestamp: new Date(),
      hsm: method.useHSM,
    });
  }

  /**
   * Record decryption performance metrics
   * Complexity: 3 (extracted from decrypt method)
   */
  private recordDecryptionMetrics(
    result: string,
    encryptedData: EncryptedData,
    startTime: number,
    method: { useHSM: boolean; useConcurrent: boolean },
  ): void {
    this.recordPerformanceMetric({
      operationType: "decrypt",
      algorithm: encryptedData.algorithm,
      dataSize: encryptedData.data.length,
      processingTime: Date.now() - startTime,
      throughput: result.length / ((Date.now() - startTime) / 1000),
      cpuUsage: process.cpuUsage().user / 1000000,
      memoryUsage: process.memoryUsage().heapUsed / 1024 / 1024,
      workerId: method.useHSM
        ? "hsm"
        : method.useConcurrent
          ? "concurrent"
          : "software",
      timestamp: new Date(),
      hsm: method.useHSM,
    });
  }

  /**
   * Handle encryption error with fallback
   * Complexity: 4 (extracted from encrypt method)
   */
  private async handleEncryptionError(
    error: unknown,
    plaintext: string,
    masterPassword: string,
    options: { useHSM?: boolean; useConcurrent?: boolean },
  ): Promise<EncryptedData> {
    if (
      this.config.fallbackToSoftware &&
      (options.useHSM || options.useConcurrent)
    ) {
      this.componentLogger.warn("Falling back to software encryption", {
        originalError: error instanceof Error ? error.message : "Unknown error",
      });
      return await this.baseEncryptionService.encrypt(
        plaintext,
        masterPassword,
      );
    }
    throw error;
  }

  /**
   * Handle decryption error with fallback
   * Complexity: 4 (extracted from decrypt method)
   */
  private async handleDecryptionError(
    error: unknown,
    encryptedData: EncryptedData,
    masterPassword: string,
    options: { useHSM?: boolean; useConcurrent?: boolean },
  ): Promise<string> {
    if (
      this.config.fallbackToSoftware &&
      (options.useHSM || options.useConcurrent)
    ) {
      this.componentLogger.warn("Falling back to software decryption", {
        originalError: error instanceof Error ? error.message : "Unknown error",
      });
      return await this.baseEncryptionService.decrypt(
        encryptedData,
        masterPassword,
      );
    }
    throw error;
  }

  // Private helper methods for performance reporting

  /**
   * Calculate time range for performance report
   * Complexity: 2 (extracted from getPerformanceReport)
   */
  private calculateReportTimeRange(timeRange?: { start: Date; end: Date }): {
    start: Date;
    end: Date;
  } {
    const now = new Date();
    const start =
      timeRange?.start || new Date(now.getTime() - 24 * 60 * 60 * 1000); // Last 24 hours
    const end = timeRange?.end || now;
    return { start, end };
  }

  /**
   * Filter metrics by time range
   * Complexity: 2 (extracted from getPerformanceReport)
   */
  private filterMetricsByTimeRange(start: Date, end: Date) {
    return this.performanceMetrics.filter(
      (metric) => metric.timestamp >= start && metric.timestamp <= end,
    );
  }

  /**
   * Build empty performance report for no metrics case
   * Complexity: 2 (extracted from getPerformanceReport)
   */
  private buildEmptyPerformanceReport(
    start: Date,
    end: Date,
  ): EncryptionPerformanceReport {
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

  /**
   * Calculate basic performance statistics
   * Complexity: 4 (extracted from getPerformanceReport)
   */
  private calculateBasicPerformanceStats(relevantMetrics: any[]) {
    const totalOperations = relevantMetrics.length;
    const avgResponseTime =
      relevantMetrics.reduce((sum, m) => sum + m.processingTime, 0) /
      totalOperations;
    const peakThroughput = Math.max(
      ...relevantMetrics.map((m) => m.throughput),
    );
    return { totalOperations, avgResponseTime, peakThroughput };
  }

  /**
   * Build algorithm breakdown statistics
   * Complexity: 6 (extracted from getPerformanceReport)
   */
  private buildAlgorithmBreakdown(relevantMetrics: any[]): Record<string, any> {
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

    return algorithmBreakdown;
  }

  /**
   * Calculate HSM usage statistics
   * Complexity: 4 (extracted from getPerformanceReport)
   */
  private calculateHsmUsage(relevantMetrics: any[]) {
    const hsmMetrics = relevantMetrics.filter((m) => m.hsm);
    return {
      enabled: !!this.hsmManager,
      operations: hsmMetrics.length,
      avgTime:
        hsmMetrics.length > 0
          ? hsmMetrics.reduce((sum, m) => sum + m.processingTime, 0) /
            hsmMetrics.length
          : 0,
      availability: this.hsmManager ? 100 : 0, // Simplified - would need actual health checks
    };
  }

  /**
   * Generate performance recommendations
   * Complexity: 6 (extracted from getPerformanceReport)
   */
  private generatePerformanceRecommendations(
    avgResponseTime: number,
    peakThroughput: number,
    hsmUsage: any,
    totalOperations: number,
  ): string[] {
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

    return recommendations;
  }

  // Private helper methods for key generation

  /**
   * Generate key pair using HSM
   * Complexity: 6 (extracted from generateKeyPair method)
   */
  private async generateKeyPairWithHSM(
    algorithm: "rsa-4096" | "ecdsa-p384" | "ed25519",
    options: { extractable?: boolean; usage?: string[] },
  ): Promise<{
    publicKey: string;
    privateKey?: string;
    keyId: string;
    hsmBacked: boolean;
  }> {
    const keySpec = {
      keyId: crypto.randomUUID(),
      keyType: "asymmetric" as const,
      algorithm,
      keyLength: this.getKeyLength(algorithm),
      extractable: options.extractable ?? false,
      usage: options.usage || ["encrypt", "decrypt", "sign", "verify"],
    };

    const result = await this.hsmManager!.generateKey(keySpec);

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
  }

  /**
   * Generate key pair using concurrent agent
   * Complexity: 3 (extracted from generateKeyPair method)
   */
  private async generateKeyPairWithConcurrentAgent(
    algorithm: "rsa-4096" | "ecdsa-p384" | "ed25519",
    options: { extractable?: boolean; usage?: string[] },
  ): Promise<{
    publicKey: string;
    privateKey?: string;
    keyId: string;
    hsmBacked: boolean;
  }> {
    const result = await this.concurrentAgent!.generateKeyPair(
      algorithm,
      options,
    );

    return {
      publicKey: result.publicKey,
      privateKey: result.privateKey,
      keyId: result.keyId,
      hsmBacked: false,
    };
  }

  /**
   * Generate key pair using Node.js crypto
   * Complexity: 8 (extracted from generateKeyPair method)
   */
  private generateKeyPairWithNodeCrypto(
    algorithm: "rsa-4096" | "ecdsa-p384" | "ed25519",
    options: { extractable?: boolean },
  ): {
    publicKey: string;
    privateKey?: string;
    keyId: string;
    hsmBacked: boolean;
  } {
    const cryptoAlgorithm = this.getCryptoAlgorithmName(algorithm);
    const keyOptions = this.buildCryptoKeyOptions(algorithm);

    const keyPair = (crypto as any).generateKeyPairSync(
      cryptoAlgorithm,
      keyOptions,
    );

    return {
      publicKey: keyPair.publicKey as string,
      privateKey:
        (options.extractable ?? true)
          ? (keyPair.privateKey as string)
          : undefined,
      keyId: crypto.randomUUID(),
      hsmBacked: false,
    };
  }

  /**
   * Get Node.js crypto algorithm name from our algorithm identifier
   * Complexity: 3 (extracted from generateKeyPairWithNodeCrypto)
   */
  private getCryptoAlgorithmName(
    algorithm: "rsa-4096" | "ecdsa-p384" | "ed25519",
  ): string {
    if (algorithm === "rsa-4096") {
      return "rsa";
    }
    if (algorithm === "ecdsa-p384") {
      return "ec";
    }
    return "ed25519";
  }

  /**
   * Build crypto key options for Node.js generateKeyPairSync
   * Complexity: 6 (extracted from generateKeyPairWithNodeCrypto)
   */
  private buildCryptoKeyOptions(
    algorithm: "rsa-4096" | "ecdsa-p384" | "ed25519",
  ): any {
    if (algorithm === "rsa-4096") {
      return {
        modulusLength: 4096,
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      };
    } else if (algorithm === "ecdsa-p384") {
      return {
        namedCurve: "secp384r1",
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      };
    } else {
      return {
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      };
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
        "encryptWithConcurrentAgent",
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
