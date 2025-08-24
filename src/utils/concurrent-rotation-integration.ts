/**
 * Integration adapter that connects the 5-agent concurrent rotation architecture
 * with the existing secure-config and credential-management systems
 */

import { EventEmitter } from "events";
import { RotationCoordinatorAgent } from "./agents/rotation-coordinator-agent.js";
import { ValidationAgent } from "./agents/validation-agent.js";
import { EncryptionAgent } from "./agents/encryption-agent.js";
import { SecurityMonitorAgent } from "./agents/security-monitor-agent.js";
import { IntegrationManagementAgent } from "./agents/integration-management-agent.js";
import { RotationMessageBus } from "./rotation-message-bus.js";
import type {
  RotationBatch,
  RotationManagerConfig,
} from "../types/rotation-types.js";
import logger from "../lib/logger.js";

/**
 * Concurrent Rotation Agent - Adapter for the 5-agent architecture
 * This class implements the interface expected by secure-config.ts
 */
export class ConcurrentRotationAgent extends EventEmitter {
  private readonly componentLogger: ReturnType<typeof logger.child>;
  private readonly messageBus: RotationMessageBus;
  private readonly agents: {
    coordinator: RotationCoordinatorAgent;
    validation: ValidationAgent;
    encryption: EncryptionAgent;
    security: SecurityMonitorAgent;
    integration: IntegrationManagementAgent;
  };

  private initialized = false;
  private started = false;
  private readonly config: RotationManagerConfig;

  // Performance tracking
  private totalRotations = 0;
  private successfulRotations = 0;
  private failedRotations = 0;
  private startTime = new Date();

  constructor(config: RotationManagerConfig) {
    super();

    this.config = config;
    this.componentLogger = logger.child({
      component: "ConcurrentRotationAgent",
    });

    // Initialize message bus
    this.messageBus = new RotationMessageBus();

    // Create all 5 agents with appropriate configuration
    this.agents = {
      coordinator: new RotationCoordinatorAgent({
        agentId: "concurrent_coordinator",
        role: "rotation",
        maxWorkerThreads: config.maxWorkerThreads || 4,
        workerTimeoutMs: config.workerTimeoutMs || 30000,
        maxQueueSize: config.maxQueueSize || 1000,
        defaultConcurrency: config.defaultConcurrency || 3,
        maxBatchSize: config.maxBatchSize || 50,
      }),

      validation: new ValidationAgent({
        agentId: "concurrent_validation",
        role: "validation",
        defaultTimeout: 10000,
        maxRetries: 3,
        retryDelay: 1000,
        strictMode: true,
        enableCustomValidation: true,
        validationCacheEnabled: true,
        validationCacheTTLMs: 300000,
      }),

      encryption: new EncryptionAgent({
        agentId: "concurrent_encryption",
        role: "encryption",
        defaultAlgorithm: "aes-256-gcm",
        keyRotationIntervalMs: config.encryptionKeyRotationIntervalMs,
        maxKeyAge: 90 * 24 * 60 * 60 * 1000,
        enableHardwareSecurityModule: false, // Default to false for compatibility
        keyStorageEnabled: true,
        credentialGenerationDefaults: {
          length: 32,
          includeSpecialChars: true,
          excludeSimilarChars: true,
        },
      }),

      security: new SecurityMonitorAgent({
        agentId: "concurrent_security",
        role: "security",
        auditLogPath: "./audit/rotation-security.log",
        enableRealTimeMonitoring: true,
        alertThresholds: {
          criticalEventsPerHour: 10,
          suspiciousActivitiesPerHour: 5,
          failedRotationsPerHour: 15,
        },
        complianceStandards: ["pci_dss", "gdpr", "sox"],
        securityScanIntervalMs: 60 * 60 * 1000, // 1 hour
        retentionPeriodDays: config.auditRetentionDays,
        encryptAuditLogs: config.auditLogEncryption,
      }),

      integration: new IntegrationManagementAgent({
        agentId: "concurrent_integration",
        role: "integration",
        defaultTimeout: config.externalServiceTimeoutMs,
        maxConcurrentConnections: 10, // Use reasonable default
        connectionPoolSize: 5,
        enableWebhooks: false, // Default to false for compatibility
        webhookRetryAttempts: config.maxExternalServiceRetries,
        serviceSyncIntervalMs: config.externalServiceHealthCheckIntervalMs,
        enableCircuitBreaker: true,
        circuitBreakerThreshold: 5,
        enableRateLimiting: true,
        rateLimitRequestsPerSecond: 10,
      }),
    };

    this.setupEventHandlers();

    this.componentLogger.info("ConcurrentRotationAgent created", {
      maxWorkerThreads: config.maxWorkerThreads,
      maxBatchSize: config.maxBatchSize,
      auditLogEncryption: config.auditLogEncryption,
    });
  }

  /**
   * Initialize all agents and the message bus
   */
  async initialize(): Promise<void> {
    if (this.initialized) {
      this.componentLogger.warn("Agent already initialized");
      return;
    }

    this.componentLogger.info(
      "Initializing 5-agent concurrent rotation system",
    );

    try {
      // Register all agents with message bus
      this.messageBus.registerAgent(this.agents.coordinator);
      this.messageBus.registerAgent(this.agents.validation);
      this.messageBus.registerAgent(this.agents.encryption);
      this.messageBus.registerAgent(this.agents.security);
      this.messageBus.registerAgent(this.agents.integration);

      // Initialize all agents in parallel for efficiency
      await Promise.all([
        this.agents.coordinator.initialize(),
        this.agents.validation.initialize(),
        this.agents.encryption.initialize(),
        this.agents.security.initialize(),
        this.agents.integration.initialize(),
      ]);

      this.initialized = true;
      this.componentLogger.info("All 5 agents initialized successfully");
    } catch (error) {
      this.componentLogger.error("Failed to initialize agents", {
        error: error instanceof Error ? error.message : "Unknown error",
      });
      throw error;
    }
  }

  /**
   * Start all agents
   */
  async start(): Promise<void> {
    if (!this.initialized) {
      throw new Error("Must initialize before starting");
    }

    if (this.started) {
      this.componentLogger.warn("Agent already started");
      return;
    }

    this.componentLogger.info("Starting 5-agent concurrent rotation system");

    try {
      // Start all agents in parallel
      await Promise.all([
        this.agents.coordinator.start(),
        this.agents.validation.start(),
        this.agents.encryption.start(),
        this.agents.security.start(),
        this.agents.integration.start(),
      ]);

      this.started = true;
      this.startTime = new Date();

      this.componentLogger.info("All 5 agents started successfully");
      this.emit("system_ready", { timestamp: new Date() });
    } catch (error) {
      this.componentLogger.error("Failed to start agents", {
        error: error instanceof Error ? error.message : "Unknown error",
      });
      throw error;
    }
  }

  /**
   * Stop all agents gracefully
   */
  async stop(): Promise<void> {
    if (!this.started) {
      this.componentLogger.warn("Agent not started");
      return;
    }

    this.componentLogger.info("Stopping 5-agent concurrent rotation system");

    try {
      // Stop all agents in parallel
      await Promise.all([
        this.agents.coordinator.stop(),
        this.agents.validation.stop(),
        this.agents.encryption.stop(),
        this.agents.security.stop(),
        this.agents.integration.stop(),
      ]);

      // Shutdown message bus
      await this.messageBus.shutdown();

      this.started = false;
      this.componentLogger.info("All 5 agents stopped successfully");
      this.emit("system_stopped", { timestamp: new Date() });
    } catch (error) {
      this.componentLogger.error("Error stopping agents", {
        error: error instanceof Error ? error.message : "Unknown error",
      });
      throw error;
    }
  }

  /**
   * Enqueue a rotation batch for processing
   */
  enqueueBatch(batch: RotationBatch): void {
    if (!this.started) {
      throw new Error("Agent must be started before enqueueing batches");
    }

    this.componentLogger.info("Enqueueing rotation batch", {
      batchId: batch.batchId,
      requests: batch.requests.length,
      priority: batch.priority,
    });

    // Execute the complete rotation workflow using the message bus
    this.messageBus
      .executeWorkflow("complete_credential_rotation", {
        batch,
        timestamp: new Date().toISOString(),
      })
      .then((result) => {
        this.totalRotations += batch.requests.length;
        this.successfulRotations += batch.requests.length; // Assume success for now

        this.emit("rotation_completed", {
          batchId: batch.batchId,
          results: result,
          timestamp: new Date(),
        });

        this.componentLogger.info("Rotation batch completed", {
          batchId: batch.batchId,
          results: Object.keys(result).length,
        });
      })
      .catch((error) => {
        this.failedRotations += batch.requests.length;

        this.emit("rotation_failed", {
          batchId: batch.batchId,
          error: error.message,
          timestamp: new Date(),
        });

        this.componentLogger.error("Rotation batch failed", {
          batchId: batch.batchId,
          error: error.message,
        });
      });
  }

  /**
   * Get current system status
   */
  getStatus(): { enabled: boolean; [key: string]: unknown } {
    return {
      enabled: this.started,
      initialized: this.initialized,
      uptime: this.started ? Date.now() - this.startTime.getTime() : 0,
      agents: {
        coordinator: this.agents.coordinator.getStatus(),
        validation: this.agents.validation.getStatus(),
        encryption: this.agents.encryption.getStatus(),
        security: this.agents.security.getStatus(),
        integration: this.agents.integration.getStatus(),
      },
      messageBusStats: this.messageBus.getStatistics(),
      rotationStats: {
        totalRotations: this.totalRotations,
        successfulRotations: this.successfulRotations,
        failedRotations: this.failedRotations,
        successRate:
          this.totalRotations > 0
            ? this.successfulRotations / this.totalRotations
            : 0,
      },
    };
  }

  /**
   * Get queue status from all agents
   */
  getQueueStatus(): { [key: string]: unknown } {
    return {
      messageBusQueues: this.messageBus.getStatistics().queueSizes,
      coordinatorQueues:
        this.agents.coordinator.getPerformanceMetrics().queueMetrics,
      activeWorkflows: this.messageBus.getStatistics().activeWorkflowExecutions,
      pendingMessages: this.messageBus.getStatistics().pendingMessages,
    };
  }

  /**
   * Get performance metrics from all agents
   */
  getPerformanceMetrics(): { [key: string]: unknown } {
    return {
      system: {
        uptime: this.started ? Date.now() - this.startTime.getTime() : 0,
        totalRotations: this.totalRotations,
        successfulRotations: this.successfulRotations,
        failedRotations: this.failedRotations,
        successRate:
          this.totalRotations > 0
            ? this.successfulRotations / this.totalRotations
            : 0,
      },
      agents: {
        coordinator: this.agents.coordinator.getPerformanceMetrics(),
        validation: this.agents.validation.getPerformanceMetrics(),
        encryption: this.agents.encryption.getPerformanceMetrics(),
        security: this.agents.security.getPerformanceMetrics(),
        integration: this.agents.integration.getPerformanceMetrics(),
      },
      messageBus: this.messageBus.getStatistics(),
    };
  }

  /**
   * Setup event handlers for inter-agent communication
   */
  private setupEventHandlers(): void {
    // Set up workflow completion handlers
    this.messageBus.on("workflow_completed", (result) => {
      this.emit("rotation_completed", result);
    });

    this.messageBus.on("workflow_failed", (error) => {
      this.emit("rotation_failed", error);
    });

    // Set up agent health monitoring
    Object.values(this.agents).forEach((agent) => {
      agent.on("agent_ready", (status) => {
        this.componentLogger.debug("Agent ready", status);
      });

      agent.on("agent_error", (error) => {
        this.componentLogger.error("Agent error", error);
        this.emit("agent_error", error);
      });
    });
  }
}

/**
 * Create a configured ConcurrentRotationAgent instance
 */
export function createConcurrentRotationAgent(
  config: Partial<RotationManagerConfig> = {},
): ConcurrentRotationAgent {
  const defaultConfig: RotationManagerConfig = {
    // Worker thread configuration
    maxWorkerThreads: 4,
    workerTimeoutMs: 30000,
    workerHealthCheckIntervalMs: 10000,

    // Queue configuration
    defaultConcurrency: 3,
    maxQueueSize: 1000,
    priorityLevels: 5,

    // Batch processing
    defaultBatchSize: 10,
    maxBatchSize: 50,
    batchTimeoutMs: 60000,

    // External service integration
    externalServiceTimeoutMs: 30000,
    maxExternalServiceRetries: 3,
    externalServiceHealthCheckIntervalMs: 30000,

    // Audit and logging
    auditRetentionDays: 90,
    logLevel: "info" as const,

    // Performance monitoring
    metricsCollectionIntervalMs: 60000,
    performanceThresholds: {
      maxRotationTimeMs: 30000,
      maxMemoryUsageMB: 512,
      maxCpuUsagePercent: 80,
      maxErrorRate: 5,
    },

    // Security
    encryptionKeyRotationIntervalMs: 24 * 60 * 60 * 1000, // 24 hours
    auditLogEncryption: true,
    secureMemoryWipe: true,
  };

  const finalConfig = { ...defaultConfig, ...config };
  return new ConcurrentRotationAgent(finalConfig);
}

export default ConcurrentRotationAgent;
