/**
 * Base class for all credential rotation agents in the 5-agent architecture
 * Provides common functionality for inter-agent communication, lifecycle management, and monitoring
 */

import { EventEmitter } from "events";
// Worker thread imports removed - not used in base class
import * as crypto from "crypto";
import logger from "../lib/logger.js";

/**
 * Common agent configuration interface
 */
export interface AgentConfig {
  agentId?: string;
  role: "rotation" | "validation" | "encryption" | "security" | "integration";
  maxConcurrency?: number;
  timeoutMs?: number;
  retryAttempts?: number;
  healthCheckIntervalMs?: number;
  metricsEnabled?: boolean;
}

/**
 * Message types for inter-agent communication
 */
export interface AgentMessage {
  messageId: string;
  timestamp: Date;
  fromAgent: string;
  toAgent: string;
  type: string;
  payload: Record<string, unknown>;
  replyTo?: string;
  correlationId?: string;
}

/**
 * Agent response interface
 */
export interface AgentResponse {
  messageId: string;
  replyTo: string;
  timestamp: Date;
  success: boolean;
  data?: Record<string, unknown>;
  error?: string;
  performanceMetrics?: {
    processingTimeMs: number;
    memoryUsageMB: number;
    cpuUsagePercent?: number;
  };
}

/**
 * Agent status interface
 */
export interface AgentStatus {
  agentId: string;
  role: string;
  status:
    | "initializing"
    | "running"
    | "paused"
    | "error"
    | "stopping"
    | "stopped";
  uptime: number;
  lastHeartbeat: Date;
  activeOperations: number;
  totalOperationsProcessed: number;
  errorCount: number;
  avgProcessingTimeMs: number;
  memoryUsageMB: number;
  cpuUsagePercent?: number;
}

/**
 * Base agent class with common functionality
 */
export abstract class RotationAgentBase extends EventEmitter {
  protected readonly agentId: string;
  protected readonly role: AgentConfig["role"];
  protected readonly config: AgentConfig;
  protected readonly componentLogger: ReturnType<typeof logger.child>;
  protected status: AgentStatus["status"] = "initializing";

  // Performance tracking
  private readonly startTime: Date = new Date();
  private totalOperationsProcessed = 0;
  private errorCount = 0;
  private activeOperations = 0;
  private processingTimes: number[] = [];
  private lastHeartbeat = new Date();
  private healthCheckTimer?: NodeJS.Timeout;

  // Message handling
  private readonly pendingMessages: Map<
    string,
    (response: AgentResponse) => void
  > = new Map();
  private readonly messageTimeout = 30000; // 30 seconds default timeout

  constructor(config: AgentConfig) {
    super();

    this.config = config;
    this.role = config.role;
    this.agentId =
      config.agentId || `${config.role}_${crypto.randomUUID().slice(0, 8)}`;

    this.componentLogger = logger.child({
      component: `${this.role.charAt(0).toUpperCase() + this.role.slice(1)}Agent`,
      agentId: this.agentId,
    });

    // Set max listeners to prevent memory leaks in high-concurrent scenarios
    this.setMaxListeners(100);

    this.setupMessageHandling();
    this.startHealthCheck();

    this.componentLogger.info("Agent initialized", {
      agentId: this.agentId,
      role: this.role,
      config: this.config,
    });
  }

  /**
   * Abstract method for processing agent-specific messages
   */
  protected abstract processMessage(
    message: AgentMessage,
  ): Promise<Record<string, unknown>>;

  /**
   * Abstract method for agent-specific initialization
   */
  protected abstract initializeAgent(): Promise<void>;

  /**
   * Abstract method for agent-specific shutdown
   */
  protected abstract shutdownAgent(): Promise<void>;

  /**
   * Initialize the agent
   */
  public async initialize(): Promise<void> {
    this.componentLogger.info("Starting agent initialization");

    try {
      this.status = "initializing";
      await this.initializeAgent();
      this.status = "running";
      this.lastHeartbeat = new Date();

      this.componentLogger.info("Agent initialization completed successfully");
      this.emit("agent_ready", { agentId: this.agentId, role: this.role });
    } catch (error) {
      this.status = "error";
      this.errorCount++;
      this.componentLogger.error("Agent initialization failed", {
        error: error instanceof Error ? error.message : "Unknown error",
      });
      throw error;
    }
  }

  /**
   * Start the agent
   */
  public async start(): Promise<void> {
    if (this.status !== "running") {
      await this.initialize();
    }

    this.componentLogger.info("Agent started and ready for operations");
    this.emit("agent_started", this.getStatus());
  }

  /**
   * Stop the agent
   */
  public async stop(): Promise<void> {
    this.componentLogger.info("Stopping agent");

    try {
      this.status = "stopping";

      // Stop health check timer
      if (this.healthCheckTimer) {
        clearInterval(this.healthCheckTimer);
      }

      // Cancel all pending messages
      for (const [messageId, callback] of this.pendingMessages) {
        callback({
          messageId: crypto.randomUUID(),
          replyTo: messageId,
          timestamp: new Date(),
          success: false,
          error: "Agent stopping - operation cancelled",
        });
      }
      this.pendingMessages.clear();

      // Perform agent-specific shutdown
      await this.shutdownAgent();

      this.status = "stopped";
      this.componentLogger.info("Agent stopped successfully");
      this.emit("agent_stopped", { agentId: this.agentId, role: this.role });
    } catch (error) {
      this.status = "error";
      this.errorCount++;
      this.componentLogger.error("Error during agent shutdown", {
        error: error instanceof Error ? error.message : "Unknown error",
      });
      throw error;
    }
  }

  /**
   * Send a message to another agent
   */
  public async sendMessage(
    toAgent: string,
    type: string,
    payload: Record<string, unknown>,
    timeoutMs?: number,
  ): Promise<Record<string, unknown>> {
    const messageId = crypto.randomUUID();
    const message: AgentMessage = {
      messageId,
      timestamp: new Date(),
      fromAgent: this.agentId,
      toAgent,
      type,
      payload,
      correlationId: crypto.randomUUID(),
    };

    return new Promise((resolve, reject) => {
      const timeout = timeoutMs || this.messageTimeout;
      const timer = setTimeout(() => {
        this.pendingMessages.delete(messageId);
        reject(new Error(`Message timeout after ${timeout}ms`));
      }, timeout);

      this.pendingMessages.set(messageId, (response: AgentResponse) => {
        clearTimeout(timer);
        if (response.success) {
          resolve(response.data || {});
        } else {
          reject(new Error(response.error || "Unknown error"));
        }
      });

      this.emit("send_message", message);
    });
  }

  /**
   * Handle incoming messages
   */
  public async handleMessage(message: AgentMessage): Promise<void> {
    const startTime = Date.now();
    this.activeOperations++;

    try {
      this.componentLogger.debug("Processing message", {
        messageId: message.messageId,
        type: message.type,
        fromAgent: message.fromAgent,
      });

      const result = await this.processMessage(message);
      const processingTime = Date.now() - startTime;

      // Track performance metrics
      this.processingTimes.push(processingTime);
      if (this.processingTimes.length > 1000) {
        this.processingTimes = this.processingTimes.slice(-1000); // Keep last 1000 measurements
      }

      const response: AgentResponse = {
        messageId: crypto.randomUUID(),
        replyTo: message.messageId,
        timestamp: new Date(),
        success: true,
        data: result,
        performanceMetrics: {
          processingTimeMs: processingTime,
          memoryUsageMB: process.memoryUsage().heapUsed / (1024 * 1024),
        },
      };

      this.totalOperationsProcessed++;
      this.lastHeartbeat = new Date();

      this.emit("send_response", response);

      this.componentLogger.debug("Message processed successfully", {
        messageId: message.messageId,
        processingTimeMs: processingTime,
      });
    } catch (error) {
      const processingTime = Date.now() - startTime;
      this.errorCount++;

      this.componentLogger.error("Message processing failed", {
        messageId: message.messageId,
        error: error instanceof Error ? error.message : "Unknown error",
      });

      const errorResponse: AgentResponse = {
        messageId: crypto.randomUUID(),
        replyTo: message.messageId,
        timestamp: new Date(),
        success: false,
        error: error instanceof Error ? error.message : "Unknown error",
        performanceMetrics: {
          processingTimeMs: processingTime,
          memoryUsageMB: process.memoryUsage().heapUsed / (1024 * 1024),
        },
      };

      this.emit("send_response", errorResponse);
    } finally {
      this.activeOperations--;
    }
  }

  /**
   * Handle message responses
   */
  public handleResponse(response: AgentResponse): void {
    const callback = this.pendingMessages.get(response.replyTo);
    if (callback) {
      this.pendingMessages.delete(response.replyTo);
      callback(response);
    }
  }

  /**
   * Get current agent status
   */
  public getStatus(): AgentStatus {
    const memUsage = process.memoryUsage();
    const avgProcessingTime =
      this.processingTimes.length > 0
        ? this.processingTimes.reduce((a, b) => a + b) /
          this.processingTimes.length
        : 0;

    return {
      agentId: this.agentId,
      role: this.role,
      status: this.status,
      uptime: Date.now() - this.startTime.getTime(),
      lastHeartbeat: this.lastHeartbeat,
      activeOperations: this.activeOperations,
      totalOperationsProcessed: this.totalOperationsProcessed,
      errorCount: this.errorCount,
      avgProcessingTimeMs: Math.round(avgProcessingTime),
      memoryUsageMB: Math.round(memUsage.heapUsed / (1024 * 1024)),
    };
  }

  /**
   * Get performance metrics
   */
  public getPerformanceMetrics(): Record<string, unknown> {
    const memUsage = process.memoryUsage();
    const avgProcessingTime =
      this.processingTimes.length > 0
        ? this.processingTimes.reduce((a, b) => a + b) /
          this.processingTimes.length
        : 0;

    return {
      agentId: this.agentId,
      role: this.role,
      uptime: Date.now() - this.startTime.getTime(),
      totalOperationsProcessed: this.totalOperationsProcessed,
      errorCount: this.errorCount,
      errorRate:
        this.totalOperationsProcessed > 0
          ? this.errorCount / this.totalOperationsProcessed
          : 0,
      avgProcessingTimeMs: Math.round(avgProcessingTime),
      activeOperations: this.activeOperations,
      memoryUsage: {
        heapUsedMB: Math.round(memUsage.heapUsed / (1024 * 1024)),
        heapTotalMB: Math.round(memUsage.heapTotal / (1024 * 1024)),
        rssUsageMB: Math.round(memUsage.rss / (1024 * 1024)),
      },
      lastHeartbeat: this.lastHeartbeat,
    };
  }

  /**
   * Setup message handling
   */
  private setupMessageHandling(): void {
    this.on("message_received", this.handleMessage.bind(this));
    this.on("response_received", this.handleResponse.bind(this));
  }

  /**
   * Start health check monitoring
   */
  private startHealthCheck(): void {
    const interval = this.config.healthCheckIntervalMs || 10000; // 10 seconds default

    this.healthCheckTimer = setInterval(() => {
      this.lastHeartbeat = new Date();

      const status = this.getStatus();
      this.emit("heartbeat", status);

      // Log health status periodically
      if (this.config.metricsEnabled !== false) {
        this.componentLogger.debug("Agent health check", {
          status: status.status,
          activeOperations: status.activeOperations,
          memoryUsageMB: status.memoryUsageMB,
          uptime: status.uptime,
        });
      }
    }, interval);
  }
}

export default RotationAgentBase;
