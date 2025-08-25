/**
 * Enhanced Make.com API Client
 * Production-ready client with comprehensive authentication, error handling, and rate limiting
 * Based on comprehensive Make.com API research reports
 */

import axios, {
  AxiosInstance,
  AxiosRequestConfig,
  AxiosResponse,
  AxiosError,
} from "axios";
import winston from "winston";
import { v4 as uuidv4 } from "uuid";
import { performance } from "perf_hooks";

// Import our comprehensive type definitions
import {
  APIResponse,
  MakeClientConfig,
  Organization,
  Team,
  Scenario,
  Connection,
  Webhook,
  DataStore,
  Template,
  SDKApp,
  RateLimitStatus,
  AnalyticsData,
  ScenarioStatus,
  WebhookStatus,
  PaginationParams,
} from "../types/make-api-types.js";

// ==============================================================================
// Configuration and Constants
// ==============================================================================

const DEFAULT_CONFIG: Partial<MakeClientConfig> = {
  zone: "eu1",
  apiVersion: "v2",
  timeout: 30000,
  retryConfig: {
    maxRetries: 3,
    retryDelay: 1000,
    backoffMultiplier: 2,
    maxRetryDelay: 10000,
  },
  rateLimitConfig: {
    maxRequests: 100,
    windowMs: 60000,
    skipSuccessfulRequests: false,
    skipFailedRequests: false,
  },
};

export enum MakeAPIErrorCode {
  AUTHENTICATION_ERROR = "AUTHENTICATION_ERROR",
  AUTHORIZATION_ERROR = "AUTHORIZATION_ERROR",
  RATE_LIMIT_ERROR = "RATE_LIMIT_ERROR",
  NOT_FOUND_ERROR = "NOT_FOUND_ERROR",
  VALIDATION_ERROR = "VALIDATION_ERROR",
  SERVER_ERROR = "SERVER_ERROR",
  NETWORK_ERROR = "NETWORK_ERROR",
  TIMEOUT_ERROR = "TIMEOUT_ERROR",
  UNKNOWN_ERROR = "UNKNOWN_ERROR",
}

export class MakeAPIError extends Error {
  constructor(
    message: string,
    public readonly code: MakeAPIErrorCode,
    public readonly statusCode?: number,
    public readonly response?: unknown,
    public readonly correlationId?: string,
  ) {
    super(message);
    this.name = "MakeAPIError";
  }
}

// ==============================================================================
// Enhanced Make.com API Client
// ==============================================================================

export class EnhancedMakeClient {
  private axiosInstance: AxiosInstance;
  private config: MakeClientConfig;
  private logger: winston.Logger;
  private rateLimitTracker: Map<string, { count: number; resetTime: number }> =
    new Map();

  constructor(config: MakeClientConfig, logger?: winston.Logger) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.logger = logger || this.createDefaultLogger();
    this.axiosInstance = this.createAxiosInstance();

    this.logger.info("Enhanced Make.com API client initialized", {
      zone: this.config.zone,
      timeout: this.config.timeout,
      rateLimitMaxRequests: this.config.rateLimitConfig?.maxRequests,
    });
  }

  // ==============================================================================
  // Configuration and Setup
  // ==============================================================================

  private createDefaultLogger(): winston.Logger {
    return winston.createLogger({
      level: "info",
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json(),
      ),
      transports: [
        new winston.transports.Console({
          format: winston.format.simple(),
        }),
      ],
    });
  }

  private createAxiosInstance(): AxiosInstance {
    const baseURL = `https://${this.config.zone}.make.com/api/${this.config.apiVersion}`;

    const instance = axios.create({
      baseURL,
      timeout: this.config.timeout,
      headers: {
        "Content-Type": "application/json",
        "User-Agent": "FastMCP-Make-Client/1.0.0",
        ...(this.config.apiToken && {
          Authorization: `Bearer ${this.config.apiToken}`,
        }),
      },
    });

    // Request interceptor for logging and rate limiting
    instance.interceptors.request.use(
      async (config) => {
        const correlationId = uuidv4();
        config.metadata = { correlationId, startTime: performance.now() };

        // Check rate limiting
        await this.checkRateLimit();

        this.logger.debug("Make.com API request started", {
          correlationId,
          method: config.method?.toUpperCase(),
          url: config.url,
          baseURL: config.baseURL,
        });

        return config;
      },
      (error) => {
        this.logger.error("Request interceptor error", {
          error: error.message,
        });
        return Promise.reject(error);
      },
    );

    // Response interceptor for logging and error handling
    instance.interceptors.response.use(
      (response) => {
        const { correlationId, startTime } = response.config.metadata || {};
        const duration = startTime ? performance.now() - startTime : 0;

        this.logger.info("Make.com API request completed", {
          correlationId,
          status: response.status,
          duration: Math.round(duration),
          method: response.config.method?.toUpperCase(),
          url: response.config.url,
        });

        // Update rate limit tracking from headers
        this.updateRateLimitFromHeaders(response.headers);

        return response;
      },
      (error) => {
        const { correlationId, startTime } = error.config?.metadata || {};
        const duration = startTime ? performance.now() - startTime : 0;

        this.logger.error("Make.com API request failed", {
          correlationId,
          error: error.message,
          status: error.response?.status,
          duration: Math.round(duration),
          method: error.config?.method?.toUpperCase(),
          url: error.config?.url,
          responseData: error.response?.data,
        });

        return Promise.reject(this.handleAPIError(error, correlationId));
      },
    );

    return instance;
  }

  // ==============================================================================
  // Error Handling
  // ==============================================================================

  private handleAPIError(
    error: AxiosError,
    correlationId?: string,
  ): MakeAPIError {
    if (error.code === "ECONNABORTED" || error.code === "ENOTFOUND") {
      return new MakeAPIError(
        `Network error: ${error.message}`,
        MakeAPIErrorCode.NETWORK_ERROR,
        undefined,
        undefined,
        correlationId,
      );
    }

    if (error.code === "ETIMEDOUT" || error.message.includes("timeout")) {
      return new MakeAPIError(
        `Request timeout: ${error.message}`,
        MakeAPIErrorCode.TIMEOUT_ERROR,
        undefined,
        undefined,
        correlationId,
      );
    }

    const status = error.response?.status;
    const responseData = error.response?.data;

    switch (status) {
      case 401:
        return new MakeAPIError(
          `Authentication failed: ${responseData?.message || "Invalid or expired token"}`,
          MakeAPIErrorCode.AUTHENTICATION_ERROR,
          status,
          responseData,
          correlationId,
        );

      case 403:
        return new MakeAPIError(
          `Authorization failed: ${responseData?.message || "Insufficient permissions"}`,
          MakeAPIErrorCode.AUTHORIZATION_ERROR,
          status,
          responseData,
          correlationId,
        );

      case 404:
        return new MakeAPIError(
          `Resource not found: ${responseData?.message || "The requested resource does not exist"}`,
          MakeAPIErrorCode.NOT_FOUND_ERROR,
          status,
          responseData,
          correlationId,
        );

      case 422:
        return new MakeAPIError(
          `Validation error: ${responseData?.message || "Invalid request data"}`,
          MakeAPIErrorCode.VALIDATION_ERROR,
          status,
          responseData,
          correlationId,
        );

      case 429:
        return new MakeAPIError(
          `Rate limit exceeded: ${responseData?.message || "Too many requests"}`,
          MakeAPIErrorCode.RATE_LIMIT_ERROR,
          status,
          responseData,
          correlationId,
        );

      case 500:
      case 502:
      case 503:
      case 504:
        return new MakeAPIError(
          `Server error: ${responseData?.message || "Internal server error"}`,
          MakeAPIErrorCode.SERVER_ERROR,
          status,
          responseData,
          correlationId,
        );

      default:
        return new MakeAPIError(
          `API error: ${responseData?.message || error.message || "Unknown error"}`,
          MakeAPIErrorCode.UNKNOWN_ERROR,
          status,
          responseData,
          correlationId,
        );
    }
  }

  // ==============================================================================
  // Rate Limiting
  // ==============================================================================

  private async checkRateLimit(): Promise<void> {
    const rateLimitConfig = this.config.rateLimitConfig!;
    const now = Date.now();
    const windowStart = now - rateLimitConfig.windowMs;

    // Clean up old entries
    for (const [key, data] of this.rateLimitTracker.entries()) {
      if (data.resetTime < windowStart) {
        this.rateLimitTracker.delete(key);
      }
    }

    // Count current requests in window
    const currentRequests = Array.from(this.rateLimitTracker.values())
      .filter((data) => data.resetTime > windowStart)
      .reduce((sum, data) => sum + data.count, 0);

    if (currentRequests >= rateLimitConfig.maxRequests) {
      const oldestEntry = Math.min(
        ...Array.from(this.rateLimitTracker.values()).map((d) => d.resetTime),
      );
      const waitTime = Math.max(
        0,
        oldestEntry + rateLimitConfig.windowMs - now,
      );

      this.logger.warn("Rate limit reached, waiting", {
        waitTime,
        currentRequests,
        maxRequests: rateLimitConfig.maxRequests,
      });

      if (waitTime > 0) {
        await new Promise((resolve) => setTimeout(resolve, waitTime));
      }
    }

    // Track this request
    const trackingKey = uuidv4();
    this.rateLimitTracker.set(trackingKey, { count: 1, resetTime: now });
  }

  private updateRateLimitFromHeaders(headers: Record<string, string>): void {
    // Make.com typically returns rate limit info in headers
    const remaining = headers["x-ratelimit-remaining"];
    const reset = headers["x-ratelimit-reset"];
    const limit = headers["x-ratelimit-limit"];

    if (remaining && reset && limit) {
      this.logger.debug("Rate limit info from headers", {
        remaining: parseInt(remaining),
        reset: parseInt(reset),
        limit: parseInt(limit),
      });
    }
  }

  public getRateLimitStatus(): RateLimitStatus {
    const rateLimitConfig = this.config.rateLimitConfig!;
    const now = Date.now();
    const windowStart = now - rateLimitConfig.windowMs;

    const currentRequests = Array.from(this.rateLimitTracker.values())
      .filter((data) => data.resetTime > windowStart)
      .reduce((sum, data) => sum + data.count, 0);

    const remaining = Math.max(
      0,
      rateLimitConfig.maxRequests - currentRequests,
    );
    const oldestEntry = Math.min(
      ...Array.from(this.rateLimitTracker.values()).map((d) => d.resetTime),
    );
    const resetTime = new Date(
      oldestEntry + rateLimitConfig.windowMs,
    ).toISOString();

    return {
      allowed: remaining > 0,
      remaining,
      resetTime,
      retryAfter:
        remaining > 0
          ? 0
          : Math.ceil((oldestEntry + rateLimitConfig.windowMs - now) / 1000),
    };
  }

  // ==============================================================================
  // Generic API Request Methods
  // ==============================================================================

  private async request<T>(
    method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
    endpoint: string,
    data?: unknown,
    params?: Record<string, unknown>,
  ): Promise<APIResponse<T>> {
    try {
      const config: AxiosRequestConfig = {
        method,
        url: endpoint,
        ...(data && { data }),
        ...(params && { params }),
      };

      const response: AxiosResponse<T> =
        await this.axiosInstance.request(config);

      return {
        data: response.data,
        meta: {
          requestId: response.config.metadata?.correlationId,
          processedAt: new Date().toISOString(),
          version: this.config.apiVersion,
        },
      };
    } catch (error) {
      if (error instanceof MakeAPIError) {
        throw error;
      }
      throw new MakeAPIError(
        `Unexpected error: ${error.message}`,
        MakeAPIErrorCode.UNKNOWN_ERROR,
        undefined,
        undefined,
        uuidv4(),
      );
    }
  }

  // ==============================================================================
  // Organization Management
  // ==============================================================================

  public async getOrganizations(): Promise<APIResponse<Organization[]>> {
    this.logger.info("Fetching user organizations");
    return this.request<Organization[]>("GET", "/organizations");
  }

  public async getOrganization(
    organizationId: string,
  ): Promise<APIResponse<Organization>> {
    this.logger.info("Fetching organization details", { organizationId });
    return this.request<Organization>(
      "GET",
      `/organizations/${organizationId}`,
    );
  }

  // ==============================================================================
  // Team Management
  // ==============================================================================

  public async getTeams(organizationId?: string): Promise<APIResponse<Team[]>> {
    this.logger.info("Fetching teams", { organizationId });
    const endpoint = organizationId
      ? `/organizations/${organizationId}/teams`
      : "/teams";
    return this.request<Team[]>("GET", endpoint);
  }

  public async getTeam(teamId: string): Promise<APIResponse<Team>> {
    this.logger.info("Fetching team details", { teamId });
    return this.request<Team>("GET", `/teams/${teamId}`);
  }

  public async createTeam(data: Partial<Team>): Promise<APIResponse<Team>> {
    this.logger.info("Creating new team", { name: data.name });
    return this.request<Team>("POST", "/teams", data);
  }

  public async updateTeam(
    teamId: string,
    data: Partial<Team>,
  ): Promise<APIResponse<Team>> {
    this.logger.info("Updating team", { teamId, updates: Object.keys(data) });
    return this.request<Team>("PATCH", `/teams/${teamId}`, data);
  }

  public async deleteTeam(teamId: string): Promise<APIResponse<void>> {
    this.logger.info("Deleting team", { teamId });
    return this.request<void>("DELETE", `/teams/${teamId}`);
  }

  // ==============================================================================
  // Scenario Management
  // ==============================================================================

  public async getScenarios(
    teamId?: string,
    pagination?: PaginationParams,
  ): Promise<APIResponse<Scenario[]>> {
    this.logger.info("Fetching scenarios", { teamId, pagination });
    const endpoint = teamId ? `/teams/${teamId}/scenarios` : "/scenarios";
    return this.request<Scenario[]>("GET", endpoint, undefined, pagination);
  }

  public async getScenario(scenarioId: string): Promise<APIResponse<Scenario>> {
    this.logger.info("Fetching scenario details", { scenarioId });
    return this.request<Scenario>("GET", `/scenarios/${scenarioId}`);
  }

  public async createScenario(
    data: Partial<Scenario>,
  ): Promise<APIResponse<Scenario>> {
    this.logger.info("Creating new scenario", {
      name: data.name,
      teamId: data.teamId,
    });
    return this.request<Scenario>("POST", "/scenarios", data);
  }

  public async updateScenario(
    scenarioId: string,
    data: Partial<Scenario>,
  ): Promise<APIResponse<Scenario>> {
    this.logger.info("Updating scenario", {
      scenarioId,
      updates: Object.keys(data),
    });
    return this.request<Scenario>("PATCH", `/scenarios/${scenarioId}`, data);
  }

  public async deleteScenario(scenarioId: string): Promise<APIResponse<void>> {
    this.logger.info("Deleting scenario", { scenarioId });
    return this.request<void>("DELETE", `/scenarios/${scenarioId}`);
  }

  public async runScenario(
    scenarioId: string,
  ): Promise<APIResponse<{ executionId: string }>> {
    this.logger.info("Running scenario", { scenarioId });
    return this.request<{ executionId: string }>(
      "POST",
      `/scenarios/${scenarioId}/run`,
    );
  }

  public async setScenarioStatus(
    scenarioId: string,
    status: ScenarioStatus,
  ): Promise<APIResponse<Scenario>> {
    this.logger.info("Setting scenario status", { scenarioId, status });
    return this.request<Scenario>("PATCH", `/scenarios/${scenarioId}`, {
      status,
    });
  }

  // ==============================================================================
  // Connection Management
  // ==============================================================================

  public async getConnections(
    teamId?: string,
    pagination?: PaginationParams,
  ): Promise<APIResponse<Connection[]>> {
    this.logger.info("Fetching connections", { teamId, pagination });
    const endpoint = teamId ? `/teams/${teamId}/connections` : "/connections";
    return this.request<Connection[]>("GET", endpoint, undefined, pagination);
  }

  public async getConnection(
    connectionId: string,
  ): Promise<APIResponse<Connection>> {
    this.logger.info("Fetching connection details", { connectionId });
    return this.request<Connection>("GET", `/connections/${connectionId}`);
  }

  public async createConnection(
    data: Partial<Connection>,
  ): Promise<APIResponse<Connection>> {
    this.logger.info("Creating new connection", {
      name: data.name,
      service: data.service,
    });
    return this.request<Connection>("POST", "/connections", data);
  }

  public async updateConnection(
    connectionId: string,
    data: Partial<Connection>,
  ): Promise<APIResponse<Connection>> {
    this.logger.info("Updating connection", {
      connectionId,
      updates: Object.keys(data),
    });
    return this.request<Connection>(
      "PATCH",
      `/connections/${connectionId}`,
      data,
    );
  }

  public async deleteConnection(
    connectionId: string,
  ): Promise<APIResponse<void>> {
    this.logger.info("Deleting connection", { connectionId });
    return this.request<void>("DELETE", `/connections/${connectionId}`);
  }

  public async testConnection(
    connectionId: string,
  ): Promise<APIResponse<{ isValid: boolean; message: string }>> {
    this.logger.info("Testing connection", { connectionId });
    return this.request<{ isValid: boolean; message: string }>(
      "POST",
      `/connections/${connectionId}/test`,
    );
  }

  // ==============================================================================
  // Webhook Management
  // ==============================================================================

  public async getWebhooks(
    teamId?: string,
    pagination?: PaginationParams,
  ): Promise<APIResponse<Webhook[]>> {
    this.logger.info("Fetching webhooks", { teamId, pagination });
    const endpoint = teamId ? `/teams/${teamId}/hooks` : "/hooks";
    return this.request<Webhook[]>("GET", endpoint, undefined, pagination);
  }

  public async getWebhook(webhookId: string): Promise<APIResponse<Webhook>> {
    this.logger.info("Fetching webhook details", { webhookId });
    return this.request<Webhook>("GET", `/hooks/${webhookId}`);
  }

  public async createWebhook(
    data: Partial<Webhook>,
  ): Promise<APIResponse<Webhook>> {
    this.logger.info("Creating new webhook", {
      name: data.name,
      url: data.url,
    });
    return this.request<Webhook>("POST", "/hooks", data);
  }

  public async updateWebhook(
    webhookId: string,
    data: Partial<Webhook>,
  ): Promise<APIResponse<Webhook>> {
    this.logger.info("Updating webhook", {
      webhookId,
      updates: Object.keys(data),
    });
    return this.request<Webhook>("PATCH", `/hooks/${webhookId}`, data);
  }

  public async deleteWebhook(webhookId: string): Promise<APIResponse<void>> {
    this.logger.info("Deleting webhook", { webhookId });
    return this.request<void>("DELETE", `/hooks/${webhookId}`);
  }

  public async setWebhookStatus(
    webhookId: string,
    status: WebhookStatus,
  ): Promise<APIResponse<Webhook>> {
    this.logger.info("Setting webhook status", { webhookId, status });
    const endpoint =
      status === WebhookStatus.ENABLED
        ? `/hooks/${webhookId}/enable`
        : `/hooks/${webhookId}/disable`;
    return this.request<Webhook>("POST", endpoint);
  }

  public async startWebhookLearning(
    webhookId: string,
  ): Promise<APIResponse<void>> {
    this.logger.info("Starting webhook learning mode", { webhookId });
    return this.request<void>("POST", `/hooks/${webhookId}/learn-start`);
  }

  public async stopWebhookLearning(
    webhookId: string,
  ): Promise<APIResponse<void>> {
    this.logger.info("Stopping webhook learning mode", { webhookId });
    return this.request<void>("POST", `/hooks/${webhookId}/learn-stop`);
  }

  // ==============================================================================
  // Data Store Management
  // ==============================================================================

  public async getDataStores(
    teamId?: string,
    pagination?: PaginationParams,
  ): Promise<APIResponse<DataStore[]>> {
    this.logger.info("Fetching data stores", { teamId, pagination });
    const endpoint = teamId ? `/teams/${teamId}/data-stores` : "/data-stores";
    return this.request<DataStore[]>("GET", endpoint, undefined, pagination);
  }

  public async getDataStore(
    dataStoreId: string,
  ): Promise<APIResponse<DataStore>> {
    this.logger.info("Fetching data store details", { dataStoreId });
    return this.request<DataStore>("GET", `/data-stores/${dataStoreId}`);
  }

  public async createDataStore(
    data: Partial<DataStore>,
  ): Promise<APIResponse<DataStore>> {
    this.logger.info("Creating new data store", { name: data.name });
    return this.request<DataStore>("POST", "/data-stores", data);
  }

  public async updateDataStore(
    dataStoreId: string,
    data: Partial<DataStore>,
  ): Promise<APIResponse<DataStore>> {
    this.logger.info("Updating data store", {
      dataStoreId,
      updates: Object.keys(data),
    });
    return this.request<DataStore>(
      "PATCH",
      `/data-stores/${dataStoreId}`,
      data,
    );
  }

  public async deleteDataStore(
    dataStoreId: string,
  ): Promise<APIResponse<void>> {
    this.logger.info("Deleting data store", { dataStoreId });
    return this.request<void>("DELETE", `/data-stores/${dataStoreId}`);
  }

  // ==============================================================================
  // Template Management
  // ==============================================================================

  public async getTemplates(
    category?: string,
    pagination?: PaginationParams,
  ): Promise<APIResponse<Template[]>> {
    this.logger.info("Fetching templates", { category, pagination });
    const params = { ...pagination, ...(category && { category }) };
    return this.request<Template[]>("GET", "/templates", undefined, params);
  }

  public async getTemplate(templateId: string): Promise<APIResponse<Template>> {
    this.logger.info("Fetching template details", { templateId });
    return this.request<Template>("GET", `/templates/${templateId}`);
  }

  public async createTemplate(
    data: Partial<Template>,
  ): Promise<APIResponse<Template>> {
    this.logger.info("Creating new template", {
      name: data.name,
      category: data.category,
    });
    return this.request<Template>("POST", "/templates", data);
  }

  public async updateTemplate(
    templateId: string,
    data: Partial<Template>,
  ): Promise<APIResponse<Template>> {
    this.logger.info("Updating template", {
      templateId,
      updates: Object.keys(data),
    });
    return this.request<Template>("PATCH", `/templates/${templateId}`, data);
  }

  public async deleteTemplate(templateId: string): Promise<APIResponse<void>> {
    this.logger.info("Deleting template", { templateId });
    return this.request<void>("DELETE", `/templates/${templateId}`);
  }

  // ==============================================================================
  // SDK App Management
  // ==============================================================================

  public async getSDKApps(
    pagination?: PaginationParams,
  ): Promise<APIResponse<SDKApp[]>> {
    this.logger.info("Fetching SDK apps", { pagination });
    return this.request<SDKApp[]>("GET", "/sdk-apps", undefined, pagination);
  }

  public async getSDKApp(appId: string): Promise<APIResponse<SDKApp>> {
    this.logger.info("Fetching SDK app details", { appId });
    return this.request<SDKApp>("GET", `/sdk-apps/${appId}`);
  }

  public async createSDKApp(
    data: Partial<SDKApp>,
  ): Promise<APIResponse<SDKApp>> {
    this.logger.info("Creating new SDK app", { name: data.name });
    return this.request<SDKApp>("POST", "/sdk-apps", data);
  }

  public async updateSDKApp(
    appId: string,
    data: Partial<SDKApp>,
  ): Promise<APIResponse<SDKApp>> {
    this.logger.info("Updating SDK app", { appId, updates: Object.keys(data) });
    return this.request<SDKApp>("PATCH", `/sdk-apps/${appId}`, data);
  }

  public async deleteSDKApp(appId: string): Promise<APIResponse<void>> {
    this.logger.info("Deleting SDK app", { appId });
    return this.request<void>("DELETE", `/sdk-apps/${appId}`);
  }

  // ==============================================================================
  // Analytics and Monitoring
  // ==============================================================================

  public async getAnalytics(
    startDate: string,
    endDate: string,
    teamId?: string,
  ): Promise<APIResponse<AnalyticsData>> {
    this.logger.info("Fetching analytics data", { startDate, endDate, teamId });
    const params = { startDate, endDate, ...(teamId && { teamId }) };
    return this.request<AnalyticsData>("GET", "/analytics", undefined, params);
  }

  // ==============================================================================
  // Health and Status
  // ==============================================================================

  public async healthCheck(): Promise<
    APIResponse<{ status: "ok" | "error"; timestamp: string }>
  > {
    this.logger.debug("Performing health check");
    return this.request<{ status: "ok" | "error"; timestamp: string }>(
      "GET",
      "/health",
    );
  }
}

export default EnhancedMakeClient;
