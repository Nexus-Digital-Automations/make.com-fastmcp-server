/**
 * Integration Management Agent - Handles external service integration, API coordination, webhook management, and service synchronization
 * Ensures credential rotations are properly propagated to all external systems and services
 */

import {
  RotationAgentBase,
  AgentConfig,
  AgentMessage,
} from "../rotation-agent-base.js";
import type { WebhookConfig } from "../../types/rotation-types.js";
import * as crypto from "crypto";
import { promisify } from "util";

const sleep = promisify(setTimeout);

/**
 * Integration operation types
 */
type _IntegrationOperationType =
  | "update_service"
  | "sync_credentials"
  | "validate_connection"
  | "send_webhook"
  | "batch_update"
  | "rollback_update";

/**
 * Service connection status
 */
type ConnectionStatus =
  | "connected"
  | "disconnected"
  | "error"
  | "timeout"
  | "unauthorized";

/**
 * External service configuration
 */
interface ExternalServiceConfig {
  serviceId: string;
  serviceName: string;
  baseUrl: string;
  authType: "api_key" | "oauth" | "basic" | "bearer" | "custom";
  authConfig: Record<string, unknown>;
  endpoints: {
    updateCredential: string;
    validateConnection: string;
    getStatus: string;
  };
  retryPolicy: {
    maxRetries: number;
    retryDelay: number;
    backoffMultiplier: number;
  };
  timeout: number;
  enabled: boolean;
  priority: number;
  metadata?: Record<string, unknown>;
}

/**
 * Integration result interface
 */
interface IntegrationResult {
  serviceId: string;
  success: boolean;
  status: ConnectionStatus;
  data?: Record<string, unknown>;
  error?: string;
  responseTime: number;
  timestamp: Date;
  retryAttempts: number;
}

/**
 * Batch operation result
 */
interface BatchOperationResult {
  batchId: string;
  totalServices: number;
  successfulUpdates: number;
  failedUpdates: number;
  results: IntegrationResult[];
  duration: number;
  timestamp: Date;
}

/**
 * Webhook delivery result
 */
interface WebhookDeliveryResult {
  webhookId: string;
  url: string;
  success: boolean;
  statusCode?: number;
  responseTime: number;
  error?: string;
  retryAttempts: number;
  timestamp: Date;
}

/**
 * Integration Management Agent configuration
 */
export interface IntegrationManagementConfig extends AgentConfig {
  defaultTimeout?: number;
  maxConcurrentConnections?: number;
  connectionPoolSize?: number;
  enableWebhooks?: boolean;
  webhookRetryAttempts?: number;
  serviceSyncIntervalMs?: number;
  enableCircuitBreaker?: boolean;
  circuitBreakerThreshold?: number;
  enableRateLimiting?: boolean;
  rateLimitRequestsPerSecond?: number;
}

/**
 * Circuit breaker for service reliability
 */
class ServiceCircuitBreaker {
  private failures = 0;
  private lastFailureTime?: Date;
  private state: "closed" | "open" | "half_open" = "closed";

  constructor(
    private readonly threshold: number,
    private readonly timeout: number,
  ) {}

  canExecute(): boolean {
    if (this.state === "closed") {
      return true;
    }

    if (this.state === "open") {
      const now = new Date();
      if (
        this.lastFailureTime &&
        now.getTime() - this.lastFailureTime.getTime() > this.timeout
      ) {
        this.state = "half_open";
        return true;
      }
      return false;
    }

    // half_open - allow one request
    return true;
  }

  onSuccess(): void {
    this.failures = 0;
    this.state = "closed";
    this.lastFailureTime = undefined;
  }

  onFailure(): void {
    this.failures++;
    this.lastFailureTime = new Date();

    if (this.failures >= this.threshold) {
      this.state = "open";
    }
  }

  getState(): { state: string; failures: number; lastFailure?: Date } {
    return {
      state: this.state,
      failures: this.failures,
      lastFailure: this.lastFailureTime,
    };
  }
}

/**
 * Rate limiter for API calls
 */
class RateLimiter {
  private requests: Date[] = [];

  constructor(private readonly requestsPerSecond: number) {}

  canMakeRequest(): boolean {
    const now = new Date();
    const oneSecondAgo = new Date(now.getTime() - 1000);

    // Remove requests older than 1 second
    this.requests = this.requests.filter(
      (requestTime) => requestTime > oneSecondAgo,
    );

    return this.requests.length < this.requestsPerSecond;
  }

  recordRequest(): void {
    this.requests.push(new Date());
  }

  getStatus(): { currentRequests: number; limit: number; resetTime: Date } {
    const now = new Date();
    const oneSecondAgo = new Date(now.getTime() - 1000);
    const currentRequests = this.requests.filter(
      (requestTime) => requestTime > oneSecondAgo,
    ).length;

    return {
      currentRequests,
      limit: this.requestsPerSecond,
      resetTime: new Date(now.getTime() + 1000),
    };
  }
}

/**
 * Integration Management Agent - handles all external service integrations
 */
export class IntegrationManagementAgent extends RotationAgentBase {
  private readonly config: IntegrationManagementConfig;
  private readonly externalServices: Map<string, ExternalServiceConfig> =
    new Map();
  private readonly circuitBreakers: Map<string, ServiceCircuitBreaker> =
    new Map();
  private readonly rateLimiters: Map<string, RateLimiter> = new Map();
  private readonly webhookConfigs: Map<string, WebhookConfig> = new Map();

  // Performance tracking
  private integrationCount = 0;
  private successfulIntegrations = 0;
  private failedIntegrations = 0;
  private totalIntegrationTime = 0;
  private webhookDeliveries = 0;
  private successfulWebhooks = 0;

  // Connection management
  private activeConnections = 0;
  private readonly connectionPool: Map<string, any> = new Map();
  private serviceSyncTimer?: NodeJS.Timeout;

  constructor(config: IntegrationManagementConfig) {
    super({
      ...config,
      role: "integration",
    });

    this.config = config;
    this.setupDefaultExternalServices();

    this.componentLogger.info("Integration Management Agent created", {
      maxConcurrentConnections: config.maxConcurrentConnections,
      enableWebhooks: config.enableWebhooks,
      circuitBreakerEnabled: config.enableCircuitBreaker,
    });
  }

  protected async initializeAgent(): Promise<void> {
    this.componentLogger.info("Initializing Integration Management Agent");

    // Initialize circuit breakers for each service
    if (this.config.enableCircuitBreaker) {
      this.setupCircuitBreakers();
    }

    // Initialize rate limiters
    if (this.config.enableRateLimiting) {
      this.setupRateLimiters();
    }

    // Start service synchronization
    if (this.config.serviceSyncIntervalMs) {
      this.startServiceSync();
    }

    // Test connectivity to all configured services
    await this.testAllServiceConnections();

    this.componentLogger.info(
      "Integration Management Agent initialized successfully",
    );
  }

  protected async shutdownAgent(): Promise<void> {
    this.componentLogger.info("Shutting down Integration Management Agent");

    // Stop service sync timer
    if (this.serviceSyncTimer) {
      clearInterval(this.serviceSyncTimer);
    }

    // Close all active connections
    this.connectionPool.clear();
    this.activeConnections = 0;

    this.componentLogger.info(
      "Integration Management Agent shutdown completed",
    );
  }

  protected async processMessage(
    message: AgentMessage,
  ): Promise<Record<string, unknown>> {
    const { type, payload } = message;

    switch (type) {
      case "update_external_services":
        return this.updateExternalServices(payload);

      case "sync_credential_to_service":
        return this.syncCredentialToService(payload);

      case "validate_service_connections":
        return this.validateServiceConnections(payload);

      case "send_webhook_notification":
        return this.sendWebhookNotification(payload);

      case "batch_update_services":
        return this.batchUpdateServices(payload);

      case "rollback_service_update":
        return this.rollbackServiceUpdate(payload);

      case "get_integration_status":
        return this.getIntegrationStatus();

      case "configure_external_service":
        return this.configureExternalService(payload);

      case "test_service_connection":
        return this.testServiceConnection(payload);

      default:
        throw new Error(`Unknown message type: ${type}`);
    }
  }

  /**
   * Update external services with new credentials
   */
  private async updateExternalServices(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const {
      credentialId,
      oldCredentialId,
      newCredentialId,
      targetServices,
      rotationType = "standard",
    } = payload;

    const startTime = Date.now();

    this.componentLogger.info("Starting external service updates", {
      credentialId,
      newCredentialId,
      rotationType,
      targetServices: Array.isArray(targetServices)
        ? targetServices.length
        : "all",
    });

    try {
      const servicesToUpdate = targetServices
        ? (targetServices as string[])
            .map((id) => this.externalServices.get(id))
            .filter(Boolean)
        : Array.from(this.externalServices.values()).filter(
            (service) => service.enabled,
          );

      if (servicesToUpdate.length === 0) {
        throw new Error("No enabled external services configured for update");
      }

      // Sort by priority
      servicesToUpdate.sort((a, b) => b!.priority - a!.priority);

      const batchId = crypto.randomUUID();
      const maxConcurrent = this.config.maxConcurrentConnections || 5;
      const results: IntegrationResult[] = [];

      // Process services in batches to respect concurrency limits
      for (let i = 0; i < servicesToUpdate.length; i += maxConcurrent) {
        const batch = servicesToUpdate.slice(i, i + maxConcurrent);

        const batchPromises = batch.map((service) =>
          this.updateSingleService(service!, {
            credentialId: credentialId as string,
            oldCredentialId: oldCredentialId as string,
            newCredentialId: newCredentialId as string,
            rotationType,
          }),
        );

        const batchResults = await Promise.all(batchPromises);
        results.push(...batchResults);
      }

      const duration = Date.now() - startTime;
      const successfulUpdates = results.filter((r) => r.success).length;
      const failedUpdates = results.length - successfulUpdates;

      this.integrationCount += results.length;
      this.successfulIntegrations += successfulUpdates;
      this.failedIntegrations += failedUpdates;
      this.totalIntegrationTime += duration;

      const batchResult: BatchOperationResult = {
        batchId,
        totalServices: servicesToUpdate.length,
        successfulUpdates,
        failedUpdates,
        results,
        duration,
        timestamp: new Date(),
      };

      this.componentLogger.info("External service updates completed", {
        batchId,
        totalServices: servicesToUpdate.length,
        successfulUpdates,
        failedUpdates,
        durationMs: duration,
      });

      // Send webhook notifications if enabled
      if (this.config.enableWebhooks) {
        await this.notifyWebhookSubscribers("credential_rotation_completed", {
          credentialId,
          newCredentialId,
          batchResult,
        });
      }

      return {
        success: successfulUpdates > 0,
        ...batchResult,
        summary: {
          successRate: successfulUpdates / servicesToUpdate.length,
          avgResponseTime:
            results.reduce((sum, r) => sum + r.responseTime, 0) /
            results.length,
        },
      };
    } catch (error) {
      const duration = Date.now() - startTime;

      this.componentLogger.error("External service updates failed", {
        credentialId,
        error: error instanceof Error ? error.message : "Unknown error",
        durationMs: duration,
      });

      return {
        success: false,
        error:
          error instanceof Error ? error.message : "Unknown integration error",
        duration,
        timestamp: new Date(),
      };
    }
  }

  /**
   * Sync credential to a specific service
   */
  private async syncCredentialToService(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const { serviceId, credentialData, credentialId } = payload;

    if (!serviceId || !credentialData) {
      throw new Error("Service ID and credential data are required");
    }

    const service = this.externalServices.get(serviceId as string);
    if (!service) {
      throw new Error(`External service not found: ${serviceId}`);
    }

    const result = await this.updateSingleService(service, {
      credentialId: credentialId as string,
      newCredentialId: credentialId as string,
      credentialData,
    });

    return {
      success: result.success,
      serviceId: result.serviceId,
      status: result.status,
      responseTime: result.responseTime,
      error: result.error,
    };
  }

  /**
   * Validate connections to all external services
   */
  private async validateServiceConnections(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const { serviceIds } = payload;
    const startTime = Date.now();

    this.componentLogger.info("Validating service connections", {
      serviceIds: serviceIds ? (serviceIds as string[]).length : "all",
    });

    try {
      const servicesToTest = serviceIds
        ? (serviceIds as string[])
            .map((id) => this.externalServices.get(id))
            .filter(Boolean)
        : Array.from(this.externalServices.values());

      const validationResults = await Promise.all(
        servicesToTest.map((service) =>
          this.validateSingleConnection(service!),
        ),
      );

      const duration = Date.now() - startTime;
      const connectedServices = validationResults.filter(
        (r) => r.status === "connected",
      ).length;

      this.componentLogger.info("Service connection validation completed", {
        totalServices: servicesToTest.length,
        connectedServices,
        durationMs: duration,
      });

      return {
        success: true,
        totalServices: servicesToTest.length,
        connectedServices,
        disconnectedServices: servicesToTest.length - connectedServices,
        results: validationResults,
        duration,
        timestamp: new Date(),
      };
    } catch (error) {
      const duration = Date.now() - startTime;

      this.componentLogger.error("Service connection validation failed", {
        error: error instanceof Error ? error.message : "Unknown error",
        durationMs: duration,
      });

      return {
        success: false,
        error:
          error instanceof Error ? error.message : "Unknown validation error",
        duration,
      };
    }
  }

  /**
   * Send webhook notification
   */
  private async sendWebhookNotification(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const { eventType, data, webhookUrls } = payload;
    const startTime = Date.now();

    if (!this.config.enableWebhooks) {
      return {
        success: false,
        error: "Webhook notifications are disabled",
      };
    }

    this.componentLogger.info("Sending webhook notifications", {
      eventType,
      webhookCount: Array.isArray(webhookUrls) ? webhookUrls.length : 0,
    });

    try {
      const urls = (webhookUrls as string[]) || [];
      const deliveryResults: WebhookDeliveryResult[] = [];

      for (const url of urls) {
        const result = await this.deliverWebhook(url, {
          eventType,
          timestamp: new Date().toISOString(),
          data,
        });

        deliveryResults.push(result);
      }

      const duration = Date.now() - startTime;
      const successfulDeliveries = deliveryResults.filter(
        (r) => r.success,
      ).length;

      this.webhookDeliveries += deliveryResults.length;
      this.successfulWebhooks += successfulDeliveries;

      this.componentLogger.info("Webhook notifications completed", {
        totalWebhooks: deliveryResults.length,
        successfulDeliveries,
        durationMs: duration,
      });

      return {
        success: successfulDeliveries > 0,
        totalWebhooks: deliveryResults.length,
        successfulDeliveries,
        failedDeliveries: deliveryResults.length - successfulDeliveries,
        results: deliveryResults,
        duration,
      };
    } catch (error) {
      const duration = Date.now() - startTime;

      this.componentLogger.error("Webhook notification failed", {
        eventType,
        error: error instanceof Error ? error.message : "Unknown error",
        durationMs: duration,
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : "Unknown webhook error",
        duration,
      };
    }
  }

  /**
   * Batch update multiple services
   */
  private async batchUpdateServices(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const { operations } = payload;

    if (!Array.isArray(operations)) {
      throw new Error("Operations array is required for batch updates");
    }

    const startTime = Date.now();
    const batchId = crypto.randomUUID();

    this.componentLogger.info("Starting batch service updates", {
      batchId,
      operationCount: operations.length,
    });

    try {
      const results = await Promise.all(
        operations.map(async (operation, index) => {
          try {
            return await this.processIntegrationOperation(
              operation as Record<string, unknown>,
            );
          } catch (error) {
            return {
              operationIndex: index,
              success: false,
              error: error instanceof Error ? error.message : "Unknown error",
            };
          }
        }),
      );

      const duration = Date.now() - startTime;
      const successfulOperations = results.filter((r) => r.success).length;

      return {
        success: true,
        batchId,
        totalOperations: operations.length,
        successfulOperations,
        failedOperations: operations.length - successfulOperations,
        results,
        duration,
      };
    } catch (error) {
      const duration = Date.now() - startTime;

      return {
        success: false,
        batchId,
        error: error instanceof Error ? error.message : "Unknown batch error",
        duration,
      };
    }
  }

  /**
   * Rollback service update
   */
  private async rollbackServiceUpdate(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const { serviceId, previousCredentialId, rollbackReason } = payload;

    this.componentLogger.warn("Rolling back service update", {
      serviceId,
      previousCredentialId,
      rollbackReason,
    });

    const service = this.externalServices.get(serviceId as string);
    if (!service) {
      throw new Error(`Service not found for rollback: ${serviceId}`);
    }

    try {
      // Simulate rollback operation
      const result = await this.updateSingleService(service, {
        credentialId: previousCredentialId as string,
        newCredentialId: previousCredentialId as string,
        isRollback: true,
      });

      this.componentLogger.info("Service update rollback completed", {
        serviceId,
        success: result.success,
      });

      return {
        success: result.success,
        serviceId,
        rolledBackTo: previousCredentialId,
        rollbackReason,
        timestamp: new Date(),
      };
    } catch (error) {
      this.componentLogger.error("Service update rollback failed", {
        serviceId,
        error: error instanceof Error ? error.message : "Unknown error",
      });

      throw error;
    }
  }

  /**
   * Get integration status and metrics
   */
  private getIntegrationStatus(): Record<string, unknown> {
    const avgIntegrationTime =
      this.integrationCount > 0
        ? this.totalIntegrationTime / this.integrationCount
        : 0;

    const successRate =
      this.integrationCount > 0
        ? this.successfulIntegrations / this.integrationCount
        : 0;

    const webhookSuccessRate =
      this.webhookDeliveries > 0
        ? this.successfulWebhooks / this.webhookDeliveries
        : 0;

    return {
      agentStatus: this.status,
      serviceIntegration: {
        totalServices: this.externalServices.size,
        enabledServices: Array.from(this.externalServices.values()).filter(
          (s) => s.enabled,
        ).length,
        activeConnections: this.activeConnections,
        connectionPoolSize: this.connectionPool.size,
      },
      operationMetrics: {
        totalIntegrations: this.integrationCount,
        successfulIntegrations: this.successfulIntegrations,
        failedIntegrations: this.failedIntegrations,
        successRate,
        avgIntegrationTimeMs: Math.round(avgIntegrationTime),
      },
      webhookMetrics: {
        enabled: this.config.enableWebhooks,
        totalDeliveries: this.webhookDeliveries,
        successfulDeliveries: this.successfulWebhooks,
        successRate: webhookSuccessRate,
      },
      circuitBreakerStatus: this.getCircuitBreakerStatus(),
      rateLimiterStatus: this.getRateLimiterStatus(),
    };
  }

  /**
   * Configure external service
   */
  private async configureExternalService(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const serviceConfig = payload as ExternalServiceConfig;

    if (!serviceConfig.serviceId || !serviceConfig.serviceName) {
      throw new Error("Service ID and name are required");
    }

    // Setup circuit breaker if enabled
    if (this.config.enableCircuitBreaker) {
      this.circuitBreakers.set(
        serviceConfig.serviceId,
        new ServiceCircuitBreaker(
          this.config.circuitBreakerThreshold || 5,
          30000, // 30 second timeout
        ),
      );
    }

    // Setup rate limiter if enabled
    if (this.config.enableRateLimiting) {
      this.rateLimiters.set(
        serviceConfig.serviceId,
        new RateLimiter(this.config.rateLimitRequestsPerSecond || 10),
      );
    }

    this.externalServices.set(serviceConfig.serviceId, serviceConfig);

    this.componentLogger.info("External service configured", {
      serviceId: serviceConfig.serviceId,
      serviceName: serviceConfig.serviceName,
      enabled: serviceConfig.enabled,
    });

    // Test the connection
    const connectionTest = await this.validateSingleConnection(serviceConfig);

    return {
      success: true,
      serviceId: serviceConfig.serviceId,
      configured: true,
      connectionTest,
    };
  }

  /**
   * Test connection to a specific service
   */
  private async testServiceConnection(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const { serviceId } = payload;

    const service = this.externalServices.get(serviceId as string);
    if (!service) {
      throw new Error(`Service not found: ${serviceId}`);
    }

    const result = await this.validateSingleConnection(service);

    return {
      success: result.success,
      serviceId,
      status: result.status,
      responseTime: result.responseTime,
      error: result.error,
    };
  }

  // Helper methods for service operations

  private async updateSingleService(
    service: ExternalServiceConfig,
    updateData: Record<string, unknown>,
  ): Promise<IntegrationResult> {
    const startTime = Date.now();
    let retryAttempts = 0;

    // Check circuit breaker
    const circuitBreaker = this.circuitBreakers.get(service.serviceId);
    if (circuitBreaker && !circuitBreaker.canExecute()) {
      return {
        serviceId: service.serviceId,
        success: false,
        status: "error",
        error: "Circuit breaker is open",
        responseTime: 0,
        timestamp: new Date(),
        retryAttempts: 0,
      };
    }

    // Check rate limiter
    const rateLimiter = this.rateLimiters.get(service.serviceId);
    if (rateLimiter && !rateLimiter.canMakeRequest()) {
      return {
        serviceId: service.serviceId,
        success: false,
        status: "error",
        error: "Rate limit exceeded",
        responseTime: 0,
        timestamp: new Date(),
        retryAttempts: 0,
      };
    }

    while (retryAttempts <= service.retryPolicy.maxRetries) {
      try {
        this.activeConnections++;

        if (rateLimiter) {
          rateLimiter.recordRequest();
        }

        // Simulate API call to external service
        const requestDelay = Math.random() * 200 + 100; // 100-300ms
        await sleep(requestDelay);

        // Simulate occasional failures for testing
        const success = Math.random() > 0.1; // 90% success rate

        if (!success) {
          throw new Error("Simulated service communication error");
        }

        const responseTime = Date.now() - startTime;

        if (circuitBreaker) {
          circuitBreaker.onSuccess();
        }

        return {
          serviceId: service.serviceId,
          success: true,
          status: "connected",
          data: {
            credentialUpdated: updateData.newCredentialId,
            updateTimestamp: new Date().toISOString(),
            serviceResponse: {
              status: "success",
              message: "Credential updated successfully",
            },
          },
          responseTime,
          timestamp: new Date(),
          retryAttempts,
        };
      } catch (error) {
        retryAttempts++;

        if (circuitBreaker) {
          circuitBreaker.onFailure();
        }

        if (retryAttempts <= service.retryPolicy.maxRetries) {
          const delay =
            service.retryPolicy.retryDelay *
            Math.pow(service.retryPolicy.backoffMultiplier, retryAttempts - 1);
          await sleep(delay);
        } else {
          return {
            serviceId: service.serviceId,
            success: false,
            status: "error",
            error: error instanceof Error ? error.message : "Unknown error",
            responseTime: Date.now() - startTime,
            timestamp: new Date(),
            retryAttempts: retryAttempts - 1,
          };
        }
      } finally {
        this.activeConnections--;
      }
    }

    return {
      serviceId: service.serviceId,
      success: false,
      status: "error",
      error: "Max retries exceeded",
      responseTime: Date.now() - startTime,
      timestamp: new Date(),
      retryAttempts: service.retryPolicy.maxRetries,
    };
  }

  private async validateSingleConnection(
    service: ExternalServiceConfig,
  ): Promise<IntegrationResult> {
    const startTime = Date.now();

    try {
      // Simulate connection validation
      const validationDelay = Math.random() * 100 + 50; // 50-150ms
      await sleep(validationDelay);

      // Simulate occasional connection issues
      const connectionSuccess = Math.random() > 0.05; // 95% success rate

      const responseTime = Date.now() - startTime;

      return {
        serviceId: service.serviceId,
        success: connectionSuccess,
        status: connectionSuccess ? "connected" : "disconnected",
        data: connectionSuccess
          ? {
              serviceName: service.serviceName,
              baseUrl: service.baseUrl,
              lastConnected: new Date().toISOString(),
            }
          : undefined,
        error: connectionSuccess ? undefined : "Connection validation failed",
        responseTime,
        timestamp: new Date(),
        retryAttempts: 0,
      };
    } catch (error) {
      return {
        serviceId: service.serviceId,
        success: false,
        status: "error",
        error:
          error instanceof Error ? error.message : "Unknown connection error",
        responseTime: Date.now() - startTime,
        timestamp: new Date(),
        retryAttempts: 0,
      };
    }
  }

  private async deliverWebhook(
    url: string,
    _payload: Record<string, unknown>,
  ): Promise<WebhookDeliveryResult> {
    const startTime = Date.now();
    const webhookId = crypto.randomUUID();
    let retryAttempts = 0;
    const maxRetries = this.config.webhookRetryAttempts || 3;

    while (retryAttempts <= maxRetries) {
      try {
        // Simulate HTTP request to webhook URL
        const deliveryDelay = Math.random() * 300 + 100; // 100-400ms
        await sleep(deliveryDelay);

        // Simulate occasional webhook failures
        const success = Math.random() > 0.1; // 90% success rate
        const statusCode = success ? 200 : 500;

        if (!success) {
          throw new Error(`HTTP ${statusCode}: Webhook delivery failed`);
        }

        return {
          webhookId,
          url,
          success: true,
          statusCode,
          responseTime: Date.now() - startTime,
          retryAttempts,
          timestamp: new Date(),
        };
      } catch (error) {
        retryAttempts++;

        if (retryAttempts <= maxRetries) {
          await sleep(1000 * retryAttempts); // Exponential backoff
        } else {
          return {
            webhookId,
            url,
            success: false,
            responseTime: Date.now() - startTime,
            error:
              error instanceof Error ? error.message : "Unknown webhook error",
            retryAttempts: retryAttempts - 1,
            timestamp: new Date(),
          };
        }
      }
    }

    return {
      webhookId,
      url,
      success: false,
      responseTime: Date.now() - startTime,
      error: "Max retries exceeded",
      retryAttempts: maxRetries,
      timestamp: new Date(),
    };
  }

  private async processIntegrationOperation(
    operation: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const { type, serviceId, data } = operation;

    const service = this.externalServices.get(serviceId as string);
    if (!service) {
      throw new Error(`Service not found: ${serviceId}`);
    }

    switch (type) {
      case "update_credential": {
        const result = await this.updateSingleService(
          service,
          data as Record<string, unknown>,
        );
        return { success: result.success, serviceId, result };
      }

      case "validate_connection": {
        const validation = await this.validateSingleConnection(service);
        return { success: validation.success, serviceId, validation };
      }

      default:
        throw new Error(`Unknown operation type: ${type}`);
    }
  }

  private async notifyWebhookSubscribers(
    eventType: string,
    data: Record<string, unknown>,
  ): Promise<void> {
    const webhookUrls = Array.from(this.webhookConfigs.values())
      .filter((config) => config.events.includes(eventType))
      .map((config) => config.url);

    if (webhookUrls.length > 0) {
      await this.sendWebhookNotification({
        eventType,
        data,
        webhookUrls,
      });
    }
  }

  private setupDefaultExternalServices(): void {
    const defaultServices: ExternalServiceConfig[] = [
      {
        serviceId: "make_com_api",
        serviceName: "Make.com API",
        baseUrl: "https://api.make.com",
        authType: "api_key",
        authConfig: {
          headerName: "Authorization",
          valuePrefix: "Bearer ",
        },
        endpoints: {
          updateCredential: "/v2/credentials/{id}",
          validateConnection: "/v2/credentials/{id}/test",
          getStatus: "/v2/status",
        },
        retryPolicy: {
          maxRetries: 3,
          retryDelay: 1000,
          backoffMultiplier: 2,
        },
        timeout: 30000,
        enabled: true,
        priority: 1,
      },
      {
        serviceId: "auth_service",
        serviceName: "Authentication Service",
        baseUrl: "https://auth.example.com",
        authType: "oauth",
        authConfig: {
          clientId: "mcp_client",
          scope: "credential_management",
        },
        endpoints: {
          updateCredential: "/api/v1/credentials",
          validateConnection: "/api/v1/health",
          getStatus: "/api/v1/status",
        },
        retryPolicy: {
          maxRetries: 2,
          retryDelay: 500,
          backoffMultiplier: 1.5,
        },
        timeout: 15000,
        enabled: true,
        priority: 2,
      },
    ];

    defaultServices.forEach((service) => {
      this.externalServices.set(service.serviceId, service);
    });
  }

  private setupCircuitBreakers(): void {
    for (const [serviceId] of this.externalServices) {
      this.circuitBreakers.set(
        serviceId,
        new ServiceCircuitBreaker(
          this.config.circuitBreakerThreshold || 5,
          30000, // 30 second timeout
        ),
      );
    }
  }

  private setupRateLimiters(): void {
    for (const [serviceId] of this.externalServices) {
      this.rateLimiters.set(
        serviceId,
        new RateLimiter(this.config.rateLimitRequestsPerSecond || 10),
      );
    }
  }

  private startServiceSync(): void {
    const interval = this.config.serviceSyncIntervalMs!;

    this.serviceSyncTimer = setInterval(async () => {
      try {
        await this.validateServiceConnections({});
      } catch (error) {
        this.componentLogger.error("Automatic service sync failed", {
          error: error instanceof Error ? error.message : "Unknown error",
        });
      }
    }, interval);
  }

  private async testAllServiceConnections(): Promise<void> {
    const enabledServices = Array.from(this.externalServices.values()).filter(
      (s) => s.enabled,
    );

    this.componentLogger.info("Testing connections to all services", {
      serviceCount: enabledServices.length,
    });

    const results = await Promise.all(
      enabledServices.map((service) => this.validateSingleConnection(service)),
    );

    const connectedCount = results.filter((r) => r.success).length;

    this.componentLogger.info("Service connection test completed", {
      totalServices: enabledServices.length,
      connectedServices: connectedCount,
      disconnectedServices: enabledServices.length - connectedCount,
    });
  }

  private getCircuitBreakerStatus(): Record<string, unknown> {
    const status: Record<string, unknown> = {};

    for (const [serviceId, circuitBreaker] of this.circuitBreakers) {
      status[serviceId] = circuitBreaker.getState();
    }

    return status;
  }

  private getRateLimiterStatus(): Record<string, unknown> {
    const status: Record<string, unknown> = {};

    for (const [serviceId, rateLimiter] of this.rateLimiters) {
      status[serviceId] = rateLimiter.getStatus();
    }

    return status;
  }

  public override getPerformanceMetrics(): Record<string, unknown> {
    const baseMetrics = super.getPerformanceMetrics();
    const avgIntegrationTime =
      this.integrationCount > 0
        ? this.totalIntegrationTime / this.integrationCount
        : 0;
    const successRate =
      this.integrationCount > 0
        ? this.successfulIntegrations / this.integrationCount
        : 0;

    return {
      ...baseMetrics,
      integrationMetrics: {
        totalIntegrations: this.integrationCount,
        successfulIntegrations: this.successfulIntegrations,
        failedIntegrations: this.failedIntegrations,
        successRate,
        avgIntegrationTimeMs: Math.round(avgIntegrationTime),
      },
      serviceMetrics: {
        totalServices: this.externalServices.size,
        enabledServices: Array.from(this.externalServices.values()).filter(
          (s) => s.enabled,
        ).length,
        activeConnections: this.activeConnections,
        connectionPoolSize: this.connectionPool.size,
      },
      webhookMetrics: {
        totalDeliveries: this.webhookDeliveries,
        successfulDeliveries: this.successfulWebhooks,
        successRate:
          this.webhookDeliveries > 0
            ? this.successfulWebhooks / this.webhookDeliveries
            : 0,
      },
    };
  }
}

export default IntegrationManagementAgent;
