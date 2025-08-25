/**
 * Enhanced Make.com API Client Tests
 * Comprehensive test suite for the EnhancedMakeClient
 */

import {
  describe,
  it,
  expect,
  beforeEach,
  jest,
  afterEach,
} from "@jest/globals";
import axios, { AxiosError } from "axios";
import winston from "winston";
import {
  EnhancedMakeClient,
  MakeAPIError,
  MakeAPIErrorCode,
} from "../make-client/enhanced-make-client.js";
import {
  MakeClientConfig,
  ScenarioStatus,
  WebhookStatus,
} from "../types/make-api-types.js";

// Mock axios
jest.mock("axios");
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe("EnhancedMakeClient", () => {
  let client: EnhancedMakeClient;
  let mockLogger: winston.Logger;
  let mockAxiosInstance: any;

  const defaultConfig: MakeClientConfig = {
    apiToken: "test-token",
    zone: "eu1",
    apiVersion: "v2",
    timeout: 5000,
    retryConfig: {
      maxRetries: 2,
      retryDelay: 100,
      backoffMultiplier: 2,
      maxRetryDelay: 1000,
    },
    rateLimitConfig: {
      maxRequests: 10,
      windowMs: 60000,
      skipSuccessfulRequests: false,
      skipFailedRequests: false,
    },
  };

  beforeEach(() => {
    // Mock logger
    mockLogger = {
      info: jest.fn(),
      debug: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
    } as any;

    // Mock axios instance
    mockAxiosInstance = {
      request: jest.fn(),
      interceptors: {
        request: {
          use: jest.fn(),
        },
        response: {
          use: jest.fn(),
        },
      },
    };

    mockedAxios.create = jest.fn().mockReturnValue(mockAxiosInstance);

    client = new EnhancedMakeClient(defaultConfig, mockLogger);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("Client Initialization", () => {
    it("should initialize with correct configuration", () => {
      expect(mockedAxios.create).toHaveBeenCalledWith({
        baseURL: "https://eu1.make.com/api/v2",
        timeout: 5000,
        headers: {
          "Content-Type": "application/json",
          "User-Agent": "FastMCP-Make-Client/1.0.0",
          Authorization: "Bearer test-token",
        },
      });
    });

    it("should setup request and response interceptors", () => {
      expect(mockAxiosInstance.interceptors.request.use).toHaveBeenCalled();
      expect(mockAxiosInstance.interceptors.response.use).toHaveBeenCalled();
    });

    it("should log successful initialization", () => {
      expect(mockLogger.info).toHaveBeenCalledWith(
        "Enhanced Make.com API client initialized",
        expect.objectContaining({
          zone: "eu1",
          timeout: 5000,
        }),
      );
    });
  });

  describe("Error Handling", () => {
    it("should handle 401 authentication errors", async () => {
      const axiosError = new AxiosError("Unauthorized", "401", {} as any, {}, {
        status: 401,
        data: { message: "Invalid token" },
      } as any);

      mockAxiosInstance.request.mockRejectedValue(axiosError);

      await expect(client.getOrganizations()).rejects.toThrow(MakeAPIError);
      await expect(client.getOrganizations()).rejects.toMatchObject({
        code: MakeAPIErrorCode.AUTHENTICATION_ERROR,
        statusCode: 401,
        message: expect.stringContaining("Authentication failed"),
      });
    });

    it("should handle 403 authorization errors", async () => {
      const axiosError = new AxiosError("Forbidden", "403", {} as any, {}, {
        status: 403,
        data: { message: "Insufficient permissions" },
      } as any);

      mockAxiosInstance.request.mockRejectedValue(axiosError);

      await expect(client.getOrganizations()).rejects.toThrow(MakeAPIError);
      await expect(client.getOrganizations()).rejects.toMatchObject({
        code: MakeAPIErrorCode.AUTHORIZATION_ERROR,
        statusCode: 403,
      });
    });

    it("should handle 429 rate limit errors", async () => {
      const axiosError = new AxiosError(
        "Too Many Requests",
        "429",
        {} as any,
        {},
        {
          status: 429,
          data: { message: "Rate limit exceeded" },
        } as any,
      );

      mockAxiosInstance.request.mockRejectedValue(axiosError);

      await expect(client.getOrganizations()).rejects.toThrow(MakeAPIError);
      await expect(client.getOrganizations()).rejects.toMatchObject({
        code: MakeAPIErrorCode.RATE_LIMIT_ERROR,
        statusCode: 429,
      });
    });

    it("should handle network errors", async () => {
      const axiosError = new AxiosError("Network Error", "ECONNABORTED");
      mockAxiosInstance.request.mockRejectedValue(axiosError);

      await expect(client.getOrganizations()).rejects.toThrow(MakeAPIError);
      await expect(client.getOrganizations()).rejects.toMatchObject({
        code: MakeAPIErrorCode.NETWORK_ERROR,
      });
    });

    it("should handle timeout errors", async () => {
      const axiosError = new AxiosError("Request timeout", "ETIMEDOUT");
      mockAxiosInstance.request.mockRejectedValue(axiosError);

      await expect(client.getOrganizations()).rejects.toThrow(MakeAPIError);
      await expect(client.getOrganizations()).rejects.toMatchObject({
        code: MakeAPIErrorCode.TIMEOUT_ERROR,
      });
    });
  });

  describe("Organization Management", () => {
    it("should fetch organizations successfully", async () => {
      const mockOrganizations = [
        { id: 1, name: "Test Org", organizationId: 1 },
        { id: 2, name: "Another Org", organizationId: 2 },
      ];

      mockAxiosInstance.request.mockResolvedValue({
        data: mockOrganizations,
        config: { metadata: { correlationId: "test-id" } },
      });

      const result = await client.getOrganizations();

      expect(result.data).toEqual(mockOrganizations);
      expect(result.meta).toMatchObject({
        requestId: "test-id",
        version: "v2",
      });
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: "GET",
        url: "/organizations",
      });
    });

    it("should fetch specific organization", async () => {
      const mockOrganization = { id: 1, name: "Test Org", organizationId: 1 };

      mockAxiosInstance.request.mockResolvedValue({
        data: mockOrganization,
        config: { metadata: { correlationId: "test-id" } },
      });

      const result = await client.getOrganization("1");

      expect(result.data).toEqual(mockOrganization);
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: "GET",
        url: "/organizations/1",
      });
    });
  });

  describe("Team Management", () => {
    it("should fetch all teams", async () => {
      const mockTeams = [
        { id: 1, name: "Team 1", organizationId: 1 },
        { id: 2, name: "Team 2", organizationId: 1 },
      ];

      mockAxiosInstance.request.mockResolvedValue({
        data: mockTeams,
        config: { metadata: { correlationId: "test-id" } },
      });

      const result = await client.getTeams();

      expect(result.data).toEqual(mockTeams);
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: "GET",
        url: "/teams",
      });
    });

    it("should fetch teams for specific organization", async () => {
      const mockTeams = [{ id: 1, name: "Team 1", organizationId: 1 }];

      mockAxiosInstance.request.mockResolvedValue({
        data: mockTeams,
        config: { metadata: { correlationId: "test-id" } },
      });

      const result = await client.getTeams("1");

      expect(result.data).toEqual(mockTeams);
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: "GET",
        url: "/organizations/1/teams",
      });
    });

    it("should create new team", async () => {
      const teamData = { name: "New Team", organizationId: 1 };
      const mockCreatedTeam = { id: 3, ...teamData };

      mockAxiosInstance.request.mockResolvedValue({
        data: mockCreatedTeam,
        config: { metadata: { correlationId: "test-id" } },
      });

      const result = await client.createTeam(teamData);

      expect(result.data).toEqual(mockCreatedTeam);
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: "POST",
        url: "/teams",
        data: teamData,
      });
    });
  });

  describe("Scenario Management", () => {
    it("should fetch scenarios with pagination", async () => {
      const mockScenarios = [
        { id: 1, name: "Scenario 1", status: ScenarioStatus.ACTIVE },
        { id: 2, name: "Scenario 2", status: ScenarioStatus.INACTIVE },
      ];

      mockAxiosInstance.request.mockResolvedValue({
        data: mockScenarios,
        config: { metadata: { correlationId: "test-id" } },
      });

      const pagination = { "pg[limit]": 10, "pg[offset]": 0 };
      const result = await client.getScenarios(undefined, pagination);

      expect(result.data).toEqual(mockScenarios);
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: "GET",
        url: "/scenarios",
        params: pagination,
      });
    });

    it("should run scenario", async () => {
      const mockResponse = { executionId: "exec-123" };

      mockAxiosInstance.request.mockResolvedValue({
        data: mockResponse,
        config: { metadata: { correlationId: "test-id" } },
      });

      const result = await client.runScenario("scenario-123");

      expect(result.data).toEqual(mockResponse);
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: "POST",
        url: "/scenarios/scenario-123/run",
      });
    });

    it("should set scenario status", async () => {
      const mockScenario = {
        id: 1,
        name: "Test Scenario",
        status: ScenarioStatus.PAUSED,
      };

      mockAxiosInstance.request.mockResolvedValue({
        data: mockScenario,
        config: { metadata: { correlationId: "test-id" } },
      });

      const result = await client.setScenarioStatus("1", ScenarioStatus.PAUSED);

      expect(result.data).toEqual(mockScenario);
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: "PATCH",
        url: "/scenarios/1",
        data: { status: ScenarioStatus.PAUSED },
      });
    });
  });

  describe("Connection Management", () => {
    it("should test connection", async () => {
      const mockResponse = { isValid: true, message: "Connection is valid" };

      mockAxiosInstance.request.mockResolvedValue({
        data: mockResponse,
        config: { metadata: { correlationId: "test-id" } },
      });

      const result = await client.testConnection("conn-123");

      expect(result.data).toEqual(mockResponse);
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: "POST",
        url: "/connections/conn-123/test",
      });
    });
  });

  describe("Webhook Management", () => {
    it("should create webhook", async () => {
      const webhookData = {
        name: "Test Webhook",
        url: "https://example.com/webhook",
        status: WebhookStatus.ENABLED,
      };
      const mockCreatedWebhook = { id: "webhook-123", ...webhookData };

      mockAxiosInstance.request.mockResolvedValue({
        data: mockCreatedWebhook,
        config: { metadata: { correlationId: "test-id" } },
      });

      const result = await client.createWebhook(webhookData);

      expect(result.data).toEqual(mockCreatedWebhook);
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: "POST",
        url: "/hooks",
        data: webhookData,
      });
    });

    it("should start webhook learning", async () => {
      mockAxiosInstance.request.mockResolvedValue({
        data: undefined,
        config: { metadata: { correlationId: "test-id" } },
      });

      const result = await client.startWebhookLearning("webhook-123");

      expect(result.data).toBeUndefined();
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: "POST",
        url: "/hooks/webhook-123/learn-start",
      });
    });

    it("should set webhook status", async () => {
      const mockWebhook = { id: "webhook-123", status: WebhookStatus.DISABLED };

      mockAxiosInstance.request.mockResolvedValue({
        data: mockWebhook,
        config: { metadata: { correlationId: "test-id" } },
      });

      const result = await client.setWebhookStatus(
        "webhook-123",
        WebhookStatus.DISABLED,
      );

      expect(result.data).toEqual(mockWebhook);
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: "POST",
        url: "/hooks/webhook-123/disable",
      });
    });
  });

  describe("Analytics", () => {
    it("should fetch analytics data", async () => {
      const mockAnalytics = {
        operations: { total: 100, successful: 95, failed: 5 },
        dataTransfer: {
          totalBytes: 1024000,
          inboundBytes: 512000,
          outboundBytes: 512000,
        },
        errors: { totalErrors: 5 },
        performance: {
          averageResponseTime: 250,
          p95ResponseTime: 500,
          p99ResponseTime: 1000,
        },
      };

      mockAxiosInstance.request.mockResolvedValue({
        data: mockAnalytics,
        config: { metadata: { correlationId: "test-id" } },
      });

      const result = await client.getAnalytics(
        "2023-01-01",
        "2023-01-31",
        "team-123",
      );

      expect(result.data).toEqual(mockAnalytics);
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: "GET",
        url: "/analytics",
        params: {
          startDate: "2023-01-01",
          endDate: "2023-01-31",
          teamId: "team-123",
        },
      });
    });
  });

  describe("Rate Limiting", () => {
    it("should track rate limit status", () => {
      const status = client.getRateLimitStatus();

      expect(status).toMatchObject({
        allowed: expect.any(Boolean),
        remaining: expect.any(Number),
        resetTime: expect.any(String),
        retryAfter: expect.any(Number),
      });
    });
  });

  describe("Health Check", () => {
    it("should perform health check", async () => {
      const mockHealthResponse = {
        status: "ok" as const,
        timestamp: "2023-01-01T00:00:00Z",
      };

      mockAxiosInstance.request.mockResolvedValue({
        data: mockHealthResponse,
        config: { metadata: { correlationId: "test-id" } },
      });

      const result = await client.healthCheck();

      expect(result.data).toEqual(mockHealthResponse);
      expect(mockAxiosInstance.request).toHaveBeenCalledWith({
        method: "GET",
        url: "/health",
      });
    });
  });
});
