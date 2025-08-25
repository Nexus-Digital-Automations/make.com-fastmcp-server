/**
 * Simple Make.com API Client
 * Compatibility layer for FastMCP tools integration
 */

import axios, { AxiosInstance } from "axios";
import winston from "winston";
import { v4 as uuidv4 } from "uuid";
import { performance } from "perf_hooks";

// ==============================================================================
// Simple Types for Compatibility
// ==============================================================================

export interface MakeClientConfig {
  apiToken?: string;
  zone?: string;
  apiVersion?: string;
  timeout?: number;
  retryConfig?: {
    maxRetries: number;
    retryDelay: number;
    backoffMultiplier: number;
    maxRetryDelay: number;
  };
  rateLimitConfig?: {
    maxRequests: number;
    windowMs: number;
    skipSuccessfulRequests: boolean;
    skipFailedRequests: boolean;
  };
}

export interface APIResponse<T = any> {
  data?: T;
  error?: any;
  status?: number;
}

export class MakeAPIError extends Error {
  public code: string;
  public statusCode: number;
  public details?: any;

  constructor(
    message: string,
    code: string,
    statusCode: number,
    details?: any,
  ) {
    super(message);
    this.name = "MakeAPIError";
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
  }
}

// ==============================================================================
// Simple Make API Client Implementation
// ==============================================================================

export class MakeAPIClient {
  private config: MakeClientConfig;
  private axios: AxiosInstance;
  private requestCount = 0;
  private resetTime = Date.now() + 60000;
  private logger: winston.Logger;

  constructor(config: MakeClientConfig, logger?: winston.Logger) {
    this.config = config;
    this.logger = logger || winston.createLogger({ silent: true });

    const baseURL = `https://${config.zone || "eu1"}.make.com/api/${config.apiVersion || "v2"}`;

    this.axios = axios.create({
      baseURL,
      timeout: config.timeout || 30000,
      headers: {
        Authorization: `Bearer ${config.apiToken}`,
        "Content-Type": "application/json",
      },
    });

    // Request interceptor for logging
    this.axios.interceptors.request.use((config: any) => {
      const correlationId = uuidv4();
      config.correlationId = correlationId;
      config.startTime = performance.now();

      this.logger.debug("Make.com API request started", {
        correlationId,
        method: config.method?.toUpperCase(),
        url: config.url,
      });

      return config;
    });

    // Response interceptor for logging and rate limiting
    this.axios.interceptors.response.use(
      (response: any) => {
        const { correlationId, startTime } = response.config;
        const duration = startTime ? performance.now() - startTime : 0;

        this.logger.info("Make.com API request completed", {
          correlationId,
          status: response.status,
          duration: Math.round(duration),
          method: response.config.method?.toUpperCase(),
          url: response.config.url,
        });

        this.updateRateLimit();
        return response;
      },
      (error: any) => {
        const { correlationId, startTime } = error.config || {};
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

        return Promise.reject(this.formatError(error));
      },
    );
  }

  private updateRateLimit() {
    if (Date.now() > this.resetTime) {
      this.requestCount = 0;
      this.resetTime = Date.now() + 60000;
    }
    this.requestCount++;
  }

  private formatError(error: any): MakeAPIError {
    const status = error.response?.status;
    const data = error.response?.data;

    switch (status) {
      case 401:
        return new MakeAPIError(
          `Authentication failed: ${data?.message || "Invalid token"}`,
          "AUTH_ERROR",
          401,
          data,
        );
      case 403:
        return new MakeAPIError(
          `Access denied: ${data?.message || "Insufficient permissions"}`,
          "PERMISSION_ERROR",
          403,
          data,
        );
      case 404:
        return new MakeAPIError(
          `Resource not found: ${data?.message || "Not found"}`,
          "NOT_FOUND",
          404,
          data,
        );
      case 429:
        return new MakeAPIError(
          `Rate limit exceeded: ${data?.message || "Too many requests"}`,
          "RATE_LIMIT",
          429,
          data,
        );
      default:
        return new MakeAPIError(
          `API error: ${data?.message || error.message}`,
          "API_ERROR",
          status || 500,
          data,
        );
    }
  }

  getRateLimitStatus() {
    const now = Date.now();
    const remaining = Math.max(0, 100 - this.requestCount);
    const resetIn = Math.max(0, this.resetTime - now);

    return {
      remaining,
      resetIn: Math.ceil(resetIn / 1000),
      limit: 100,
    };
  }

  // ==============================================================================
  // API Methods for Compatibility
  // ==============================================================================

  async getScenarios(teamId?: string, params?: any): Promise<APIResponse> {
    const queryParams: any = { ...params };
    if (teamId) {
      queryParams.teamId = teamId;
    }

    try {
      const response = await this.axios.get("/scenarios", {
        params: queryParams,
      });
      return { data: response.data, status: response.status };
    } catch (error) {
      throw this.formatError(error);
    }
  }

  async createWebhook(webhookData: any): Promise<APIResponse> {
    try {
      const response = await this.axios.post("/hooks", webhookData);
      return { data: response.data, status: response.status };
    } catch (error) {
      throw this.formatError(error);
    }
  }

  async getWebhooks(teamId?: string, params?: any): Promise<APIResponse> {
    const queryParams: any = { ...params };
    if (teamId) {
      queryParams.teamId = teamId;
    }

    try {
      const response = await this.axios.get("/hooks", { params: queryParams });
      return { data: response.data, status: response.status };
    } catch (error) {
      throw this.formatError(error);
    }
  }

  async getAnalytics(params?: any): Promise<APIResponse> {
    try {
      const response = await this.axios.get("/analytics", { params });
      return { data: response.data, status: response.status };
    } catch (error) {
      throw this.formatError(error);
    }
  }

  async getOrganizations(): Promise<APIResponse> {
    try {
      const response = await this.axios.get("/organizations");
      return { data: response.data, status: response.status };
    } catch (error) {
      throw this.formatError(error);
    }
  }

  async getOrganization(orgId: string): Promise<APIResponse> {
    try {
      const response = await this.axios.get(`/organizations/${orgId}`);
      return { data: response.data, status: response.status };
    } catch (error) {
      throw this.formatError(error);
    }
  }

  async getTeams(orgId?: string): Promise<APIResponse> {
    const endpoint = orgId ? `/organizations/${orgId}/teams` : "/teams";
    try {
      const response = await this.axios.get(endpoint);
      return { data: response.data, status: response.status };
    } catch (error) {
      throw this.formatError(error);
    }
  }

  async createTeam(teamData: any): Promise<APIResponse> {
    try {
      const response = await this.axios.post("/teams", teamData);
      return { data: response.data, status: response.status };
    } catch (error) {
      throw this.formatError(error);
    }
  }

  async getConnections(
    teamId?: string,
    pagination?: any,
  ): Promise<APIResponse> {
    const params: any = { ...pagination };
    if (teamId) {
      params.teamId = teamId;
    }

    try {
      const response = await this.axios.get("/connections", { params });
      return { data: response.data, status: response.status };
    } catch (error) {
      throw this.formatError(error);
    }
  }

  async createConnection(connectionData: any): Promise<APIResponse> {
    try {
      const response = await this.axios.post("/connections", connectionData);
      return { data: response.data, status: response.status };
    } catch (error) {
      throw this.formatError(error);
    }
  }

  async testConnection(connectionId: string): Promise<APIResponse> {
    try {
      const response = await this.axios.post(
        `/connections/${connectionId}/test`,
      );
      return { data: response.data, status: response.status };
    } catch (error) {
      throw this.formatError(error);
    }
  }

  async getConnection(connectionId: string): Promise<APIResponse> {
    try {
      const response = await this.axios.get(`/connections/${connectionId}`);
      return { data: response.data, status: response.status };
    } catch (error) {
      throw this.formatError(error);
    }
  }

  async getDataStores(teamId?: string, pagination?: any): Promise<APIResponse> {
    const params: any = { ...pagination };
    if (teamId) {
      params.teamId = teamId;
    }

    try {
      const response = await this.axios.get("/data-stores", { params });
      return { data: response.data, status: response.status };
    } catch (error) {
      throw this.formatError(error);
    }
  }

  async getDataStore(dataStoreId: string): Promise<APIResponse> {
    try {
      const response = await this.axios.get(`/data-stores/${dataStoreId}`);
      return { data: response.data, status: response.status };
    } catch (error) {
      throw this.formatError(error);
    }
  }
}

export default MakeAPIClient;
