# Make.com Billing and Administration FastMCP Tools - Implementation Guide

## Overview

This comprehensive implementation guide provides essential patterns, structures, and code examples needed to implement Make.com billing and administration FastMCP tools immediately. Based on extensive research of Make.com's billing API and audit logs capabilities, this guide focuses on the most critical components for production-ready implementation.

## Table of Contents

1. [Core Architecture](#core-architecture)
2. [Key TypeScript Interfaces](#key-typescript-interfaces)
3. [Essential Tools (Priority Implementation)](#essential-tools-priority-implementation)
4. [API Client Pattern](#api-client-pattern)
5. [Authentication Setup](#authentication-setup)
6. [Performance Patterns](#performance-patterns)

## Core Architecture

### System Structure

```typescript
// Project structure for billing implementation
src/
├── billing/
│   ├── client.ts              // Core API client
│   ├── interfaces.ts          // TypeScript interfaces
│   ├── tools/                 // FastMCP tool definitions
│   │   ├── subscription.ts    // Subscription management tools
│   │   ├── payments.ts        // Payment history tools
│   │   ├── invoices.ts        // Invoice management tools
│   │   └── index.ts           // Tool exports
│   ├── cache/                 // Caching layer
│   │   ├── billing-cache.ts   // Subscription/payment cache
│   │   └── cache-manager.ts   // Cache lifecycle management
│   └── utils/
│       ├── validators.ts      // Input validation
│       ├── formatters.ts      // Response formatting
│       └── error-handlers.ts  // Error management
├── audit/
│   ├── client.ts              // Audit logs API client
│   ├── interfaces.ts          // Audit data models
│   ├── tools/                 // Audit FastMCP tools
│   │   ├── logs.ts            // Log retrieval tools
│   │   ├── analysis.ts        // Log analysis tools
│   │   └── index.ts           // Tool exports
│   └── parsers/
│       ├── log-parser.ts      // Log format parsing
│       └── event-classifier.ts // Event categorization
└── shared/
    ├── rate-limiting/         // Enhanced rate limiting (existing)
    ├── monitoring/            // System monitoring (existing)
    └── config/                // Configuration management
```

### Component Integration Pattern

```typescript
// Core integration with existing FastMCP server
import { FastMCP } from "fastmcp";
import { EnhancedRateLimitManager } from "./enhanced-rate-limit-manager.js";
import { MakeBillingClient } from "./billing/client.js";
import { MakeAuditClient } from "./audit/client.js";
import { billingTools } from "./billing/tools/index.js";
import { auditTools } from "./audit/tools/index.js";

export class MakeAdministrationServer {
  private server: FastMCP;
  private rateLimitManager: EnhancedRateLimitManager;
  private billingClient: MakeBillingClient;
  private auditClient: MakeAuditClient;

  constructor(config: MakeAdminConfig) {
    // Initialize with existing rate limiting
    this.rateLimitManager = new EnhancedRateLimitManager({
      enableAdvancedComponents: true,
      tokenBucket: {
        enabled: true,
        safetyMargin: 0.8,
        synchronizeWithHeaders: true,
      },
    });

    // Initialize FastMCP server
    this.server = new FastMCP({
      name: "Make.com Administration Server",
      version: "1.0.0",
    });

    // Initialize API clients
    this.billingClient = new MakeBillingClient(config.billing);
    this.auditClient = new MakeAuditClient(config.audit);
  }

  async initialize(): Promise<void> {
    // Register billing tools
    for (const tool of billingTools) {
      this.server.addTool(tool);
    }

    // Register audit tools
    for (const tool of auditTools) {
      this.server.addTool(tool);
    }

    // Start server
    await this.server.listen();
  }
}
```

## Key TypeScript Interfaces

### Core Billing Data Models

```typescript
// src/billing/interfaces.ts

// Base configuration
export interface MakeBillingConfig {
  apiToken: string;
  organizationId: string;
  region: "us" | "eu";
  baseUrl?: string;
  timeout?: number;
  retryAttempts?: number;
}

// Subscription management interfaces
export interface SubscriptionDetails {
  id: string;
  status: "active" | "cancelled" | "past_due" | "trialing";
  product: {
    id: string;
    name: string;
    description: string;
  };
  price: {
    id: string;
    amount: number;
    currency: string;
    interval: "month" | "year";
    intervalCount: number;
  };
  nextBillingDate: string;
  currentPeriodStart: string;
  currentPeriodEnd: string;
  coupon?: {
    id: string;
    code: string;
    discountType: "percentage" | "fixed";
    discountValue: number;
    validUntil?: string;
  };
  trial?: {
    trialStart: string;
    trialEnd: string;
    trialDaysLeft: number;
  };
}

// Payment data models
export interface PaymentRecord {
  invoiceNumber: string;
  creationDate: string;
  paymentStatus: "paid" | "pending" | "failed";
  paymentMethod: string;
  totalAmount: number;
  currency: string;
  invoiceUrl: string;
  lineItems?: InvoiceLineItem[];
}

export interface InvoiceLineItem {
  id: string;
  description: string;
  quantity: number;
  unitPrice: number;
  amount: number;
  period?: {
    start: string;
    end: string;
  };
}

// Payment operations
export interface SinglePaymentRequest {
  priceId: string;
  quantity: number;
  couponCode?: string;
  customerDetails?: CustomerDetails;
}

export interface CustomerDetails {
  name?: string;
  email?: string;
  paymentMethodId?: string;
  address?: Address;
}

export interface Address {
  line1: string;
  line2?: string;
  city: string;
  state?: string;
  postalCode: string;
  country: string;
}

// Response interfaces
export interface PaymentsResponse {
  payments: PaymentRecord[];
  pagination: {
    total: number;
    page: number;
    limit: number;
  };
}

export interface SinglePaymentResponse {
  paymentId: string;
  status: "created" | "processing" | "completed" | "failed";
  amount: number;
  currency: string;
  paymentUrl?: string;
}
```

### Audit Log Interfaces

```typescript
// src/audit/interfaces.ts

export interface MakeAuditConfig {
  apiToken: string;
  organizationId: string;
  region: "us" | "eu";
  logRetentionDays?: number;
}

// Audit log data models
export interface AuditLogEntry {
  id: string;
  timestamp: string;
  userId: string;
  organizationId: string;
  action: string;
  resource: {
    type: string;
    id: string;
    name?: string;
  };
  details: Record<string, any>;
  ipAddress?: string;
  userAgent?: string;
  sessionId?: string;
}

export interface AuditLogQuery {
  startDate?: string;
  endDate?: string;
  userId?: string;
  action?: string;
  resourceType?: string;
  resourceId?: string;
  limit?: number;
  offset?: number;
}

export interface AuditLogResponse {
  entries: AuditLogEntry[];
  totalCount: number;
  pagination: {
    offset: number;
    limit: number;
    hasMore: boolean;
  };
}

// Audit analysis interfaces
export interface AuditAnalysis {
  period: {
    start: string;
    end: string;
  };
  summary: {
    totalEvents: number;
    uniqueUsers: number;
    topActions: Array<{ action: string; count: number }>;
    topResources: Array<{ resourceType: string; count: number }>;
  };
  trends: {
    dailyActivity: Array<{ date: string; count: number }>;
    userActivity: Array<{ userId: string; count: number }>;
  };
  securityEvents: AuditLogEntry[];
}
```

## Essential Tools (Priority Implementation)

### 1. Subscription Management Tools

```typescript
// src/billing/tools/subscription.ts
import { z } from "zod";
import { MakeBillingClient } from "../client.js";

export const subscriptionTools = [
  {
    name: "make_get_subscription",
    description: "Get current subscription details for a Make organization",
    inputSchema: {
      type: "object",
      properties: {
        organizationId: {
          type: "string",
          description: "Make organization ID",
        },
      },
      required: ["organizationId"],
    },
    handler: async (
      params: { organizationId: string },
      client: MakeBillingClient,
    ) => {
      try {
        const subscription = await client.getSubscription(
          params.organizationId,
        );
        return {
          success: true,
          data: subscription,
        };
      } catch (error) {
        return {
          success: false,
          error: error.message,
          details: error.details,
        };
      }
    },
  },

  {
    name: "make_update_subscription",
    description: "Update existing subscription plan or payment method",
    inputSchema: {
      type: "object",
      properties: {
        organizationId: {
          type: "string",
          description: "Make organization ID",
        },
        priceId: {
          type: "string",
          description: "New price plan ID",
        },
        prorationBehavior: {
          type: "string",
          enum: ["create_prorations", "none"],
          description: "How to handle prorations",
          default: "create_prorations",
        },
      },
      required: ["organizationId"],
    },
    handler: async (params: any, client: MakeBillingClient) => {
      try {
        const updatedSubscription = await client.updateSubscription(
          params.organizationId,
          {
            priceId: params.priceId,
            prorationBehavior: params.prorationBehavior,
          },
        );
        return {
          success: true,
          data: updatedSubscription,
        };
      } catch (error) {
        return {
          success: false,
          error: error.message,
        };
      }
    },
  },

  {
    name: "make_cancel_subscription",
    description: "Cancel active subscription",
    inputSchema: {
      type: "object",
      properties: {
        organizationId: {
          type: "string",
          description: "Make organization ID",
        },
        atPeriodEnd: {
          type: "boolean",
          description: "Cancel at end of billing period",
          default: true,
        },
        reason: {
          type: "string",
          description: "Cancellation reason",
        },
      },
      required: ["organizationId"],
    },
    handler: async (params: any, client: MakeBillingClient) => {
      try {
        await client.cancelSubscription(
          params.organizationId,
          params.atPeriodEnd,
          params.reason,
        );
        return {
          success: true,
          message: "Subscription cancellation initiated",
        };
      } catch (error) {
        return {
          success: false,
          error: error.message,
        };
      }
    },
  },
];
```

### 2. Payment Management Tools

```typescript
// src/billing/tools/payments.ts
export const paymentTools = [
  {
    name: "make_get_payments",
    description: "Retrieve payment history for a Make organization",
    inputSchema: {
      type: "object",
      properties: {
        organizationId: {
          type: "string",
          description: "Make organization ID",
        },
        limit: {
          type: "number",
          description: "Number of payments to retrieve",
          default: 10,
          minimum: 1,
          maximum: 100,
        },
        page: {
          type: "number",
          description: "Page number for pagination",
          default: 1,
          minimum: 1,
        },
        startDate: {
          type: "string",
          description: "Filter payments from this date (ISO 8601)",
        },
        endDate: {
          type: "string",
          description: "Filter payments to this date (ISO 8601)",
        },
      },
      required: ["organizationId"],
    },
    handler: async (params: any, client: MakeBillingClient) => {
      try {
        const payments = await client.getPayments(params.organizationId, {
          limit: params.limit,
          page: params.page,
          startDate: params.startDate,
          endDate: params.endDate,
        });
        return {
          success: true,
          data: payments,
        };
      } catch (error) {
        return {
          success: false,
          error: error.message,
        };
      }
    },
  },

  {
    name: "make_create_single_payment",
    description: "Create a one-time payment for additional services",
    inputSchema: {
      type: "object",
      properties: {
        organizationId: {
          type: "string",
          description: "Make organization ID",
        },
        priceId: {
          type: "string",
          description: "Product price ID to purchase",
        },
        quantity: {
          type: "number",
          description: "Quantity to purchase",
          minimum: 1,
        },
        couponCode: {
          type: "string",
          description: "Optional coupon code",
        },
      },
      required: ["organizationId", "priceId", "quantity"],
    },
    handler: async (params: any, client: MakeBillingClient) => {
      try {
        const payment = await client.createSinglePayment(
          params.organizationId,
          {
            priceId: params.priceId,
            quantity: params.quantity,
            couponCode: params.couponCode,
          },
        );
        return {
          success: true,
          data: payment,
        };
      } catch (error) {
        return {
          success: false,
          error: error.message,
        };
      }
    },
  },
];
```

### 3. Audit Log Tools

```typescript
// src/audit/tools/logs.ts
export const auditLogTools = [
  {
    name: "make_get_audit_logs",
    description: "Retrieve audit logs for organization activities",
    inputSchema: {
      type: "object",
      properties: {
        organizationId: {
          type: "string",
          description: "Make organization ID",
        },
        startDate: {
          type: "string",
          description: "Filter logs from this date (ISO 8601)",
        },
        endDate: {
          type: "string",
          description: "Filter logs to this date (ISO 8601)",
        },
        userId: {
          type: "string",
          description: "Filter by specific user ID",
        },
        action: {
          type: "string",
          description: "Filter by specific action type",
        },
        resourceType: {
          type: "string",
          description: "Filter by resource type (scenario, connection, etc.)",
        },
        limit: {
          type: "number",
          description: "Number of log entries to retrieve",
          default: 50,
          minimum: 1,
          maximum: 1000,
        },
      },
      required: ["organizationId"],
    },
    handler: async (params: any, client: MakeAuditClient) => {
      try {
        const logs = await client.getAuditLogs(params.organizationId, {
          startDate: params.startDate,
          endDate: params.endDate,
          userId: params.userId,
          action: params.action,
          resourceType: params.resourceType,
          limit: params.limit,
        });
        return {
          success: true,
          data: logs,
        };
      } catch (error) {
        return {
          success: false,
          error: error.message,
        };
      }
    },
  },

  {
    name: "make_analyze_audit_logs",
    description: "Analyze audit logs for patterns and insights",
    inputSchema: {
      type: "object",
      properties: {
        organizationId: {
          type: "string",
          description: "Make organization ID",
        },
        period: {
          type: "object",
          properties: {
            start: { type: "string", description: "Analysis start date" },
            end: { type: "string", description: "Analysis end date" },
          },
          required: ["start", "end"],
        },
        analysisType: {
          type: "string",
          enum: ["activity", "security", "performance", "compliance"],
          description: "Type of analysis to perform",
          default: "activity",
        },
      },
      required: ["organizationId", "period"],
    },
    handler: async (params: any, client: MakeAuditClient) => {
      try {
        const analysis = await client.analyzeAuditLogs(
          params.organizationId,
          params.period,
          params.analysisType,
        );
        return {
          success: true,
          data: analysis,
        };
      } catch (error) {
        return {
          success: false,
          error: error.message,
        };
      }
    },
  },
];
```

### 4. Invoice Management Tools

```typescript
// src/billing/tools/invoices.ts
export const invoiceTools = [
  {
    name: "make_download_invoice",
    description: "Download invoice PDF for a specific payment",
    inputSchema: {
      type: "object",
      properties: {
        organizationId: {
          type: "string",
          description: "Make organization ID",
        },
        invoiceNumber: {
          type: "string",
          description: "Invoice number to download",
        },
      },
      required: ["organizationId", "invoiceNumber"],
    },
    handler: async (params: any, client: MakeBillingClient) => {
      try {
        const invoiceData = await client.downloadInvoice(
          params.organizationId,
          params.invoiceNumber,
        );
        return {
          success: true,
          data: {
            invoiceNumber: params.invoiceNumber,
            downloadUrl: invoiceData.downloadUrl,
            contentType: "application/pdf",
            size: invoiceData.size,
          },
        };
      } catch (error) {
        return {
          success: false,
          error: error.message,
        };
      }
    },
  },
];
```

## API Client Pattern

### Core Billing API Client

```typescript
// src/billing/client.ts
import axios, { AxiosInstance, AxiosResponse } from "axios";
import { EnhancedRateLimitManager } from "../enhanced-rate-limit-manager.js";
import {
  MakeBillingConfig,
  SubscriptionDetails,
  PaymentsResponse,
  SinglePaymentRequest,
  SinglePaymentResponse,
} from "./interfaces.js";

export class MakeBillingClient {
  private httpClient: AxiosInstance;
  private rateLimitManager: EnhancedRateLimitManager;
  private config: MakeBillingConfig;

  constructor(config: MakeBillingConfig) {
    this.config = config;

    // Initialize HTTP client with proper configuration
    this.httpClient = axios.create({
      baseURL: config.baseUrl || this.getDefaultBaseUrl(config.region),
      timeout: config.timeout || 30000,
      headers: {
        Authorization: `Token ${config.apiToken}`,
        "Content-Type": "application/json",
        "User-Agent": "Make-FastMCP-Server/1.0.0",
      },
    });

    // Initialize enhanced rate limiting
    this.rateLimitManager = new EnhancedRateLimitManager({
      enableAdvancedComponents: true,
      requestsPerWindow: 120, // Adjust based on Make.com plan
      windowSizeSeconds: 60,
      tokenBucket: {
        enabled: true,
        safetyMargin: 0.8,
        synchronizeWithHeaders: true,
        initialCapacity: 96, // 80% of 120 RPM
        initialRefillRate: 2.0, // 120 requests per 60 seconds
      },
    });

    // Set up response interceptors for rate limiting
    this.setupInterceptors();
  }

  private getDefaultBaseUrl(region: "us" | "eu"): string {
    return region === "us"
      ? "https://us2.make.com/api/v2"
      : "https://eu2.make.com/api/v2";
  }

  private setupInterceptors(): void {
    // Request interceptor - rate limiting
    this.httpClient.interceptors.request.use(
      async (config) => {
        // Apply rate limiting before request
        await this.rateLimitManager.executeWithRateLimit(
          `${config.method?.toUpperCase()} ${config.url}`,
          async () => Promise.resolve(),
          { priority: "normal" },
        );
        return config;
      },
      (error) => Promise.reject(error),
    );

    // Response interceptor - handle rate limiting headers
    this.httpClient.interceptors.response.use(
      (response) => {
        // Update rate limiting from response headers
        if (this.rateLimitManager.updateFromResponseHeaders) {
          this.rateLimitManager.updateFromResponseHeaders(response.headers);
        }
        return response;
      },
      async (error) => {
        // Handle rate limit errors
        if (error.response?.status === 429) {
          const retryAfter = parseInt(
            error.response.headers["retry-after"] || "60",
          );
          throw new MakeBillingError(429, "Rate limit exceeded", {
            retryAfter,
          });
        }
        throw new MakeBillingError(
          error.response?.status || 500,
          error.response?.data?.message || error.message,
          error.response?.data,
        );
      },
    );
  }

  // Core API methods
  async getSubscription(organizationId: string): Promise<SubscriptionDetails> {
    const response = await this.httpClient.get(
      `/organizations/${organizationId}/subscription`,
    );
    return response.data;
  }

  async updateSubscription(
    organizationId: string,
    updates: { priceId?: string; prorationBehavior?: string },
  ): Promise<SubscriptionDetails> {
    const response = await this.httpClient.patch(
      `/organizations/${organizationId}/subscription`,
      updates,
    );
    return response.data;
  }

  async cancelSubscription(
    organizationId: string,
    atPeriodEnd: boolean = true,
    reason?: string,
  ): Promise<void> {
    const params = new URLSearchParams({
      at_period_end: atPeriodEnd.toString(),
    });
    if (reason) params.set("reason", reason);

    await this.httpClient.delete(
      `/organizations/${organizationId}/subscription?${params}`,
    );
  }

  async getPayments(
    organizationId: string,
    options: {
      limit?: number;
      page?: number;
      startDate?: string;
      endDate?: string;
    } = {},
  ): Promise<PaymentsResponse> {
    const params = new URLSearchParams();
    if (options.limit) params.set("limit", options.limit.toString());
    if (options.page) params.set("page", options.page.toString());
    if (options.startDate) params.set("start_date", options.startDate);
    if (options.endDate) params.set("end_date", options.endDate);

    const response = await this.httpClient.get(
      `/organizations/${organizationId}/payments?${params}`,
    );
    return response.data;
  }

  async createSinglePayment(
    organizationId: string,
    request: SinglePaymentRequest,
  ): Promise<SinglePaymentResponse> {
    const response = await this.httpClient.post(
      `/organizations/${organizationId}/single-payment-create`,
      request,
    );
    return response.data;
  }

  async applyCoupon(organizationId: string, couponCode: string): Promise<any> {
    const response = await this.httpClient.post(
      `/organizations/${organizationId}/subscription/coupon-apply`,
      { couponCode },
    );
    return response.data;
  }

  async downloadInvoice(
    organizationId: string,
    invoiceNumber: string,
  ): Promise<{ downloadUrl: string; size: number }> {
    // This would typically return a URL or stream for the PDF
    const response = await this.httpClient.get(
      `/organizations/${organizationId}/invoices/${invoiceNumber}/download`,
    );
    return response.data;
  }

  // Health check method
  async healthCheck(): Promise<{ status: string; latency: number }> {
    const start = Date.now();
    try {
      await this.httpClient.get("/health");
      return {
        status: "healthy",
        latency: Date.now() - start,
      };
    } catch (error) {
      return {
        status: "unhealthy",
        latency: Date.now() - start,
      };
    }
  }
}

// Custom error class for billing operations
export class MakeBillingError extends Error {
  constructor(
    public statusCode: number,
    public apiMessage: string,
    public details?: any,
  ) {
    super(`Make Billing API Error (${statusCode}): ${apiMessage}`);
    this.name = "MakeBillingError";
  }
}
```

## Authentication Setup

### Environment Configuration

```typescript
// src/shared/config/auth.ts
export interface MakeAuthConfig {
  billing: {
    apiToken: string;
    organizationId: string;
    region: "us" | "eu";
  };
  audit: {
    apiToken: string;
    organizationId: string;
    region: "us" | "eu";
  };
}

export function loadAuthConfig(): MakeAuthConfig {
  // Validate required environment variables
  const requiredEnvVars = [
    "MAKE_BILLING_API_TOKEN",
    "MAKE_BILLING_ORG_ID",
    "MAKE_AUDIT_API_TOKEN",
    "MAKE_AUDIT_ORG_ID",
  ];

  for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
      throw new Error(`Missing required environment variable: ${envVar}`);
    }
  }

  return {
    billing: {
      apiToken: process.env.MAKE_BILLING_API_TOKEN!,
      organizationId: process.env.MAKE_BILLING_ORG_ID!,
      region: (process.env.MAKE_BILLING_REGION as "us" | "eu") || "eu",
    },
    audit: {
      apiToken: process.env.MAKE_AUDIT_API_TOKEN!,
      organizationId: process.env.MAKE_AUDIT_ORG_ID!,
      region: (process.env.MAKE_AUDIT_REGION as "us" | "eu") || "eu",
    },
  };
}
```

### Token Management

```typescript
// src/shared/config/token-manager.ts
export class MakeTokenManager {
  private tokens: Map<string, { token: string; expires?: Date }> = new Map();

  setToken(service: string, token: string, expiresAt?: Date): void {
    this.tokens.set(service, { token, expires: expiresAt });
  }

  getToken(service: string): string | null {
    const tokenInfo = this.tokens.get(service);
    if (!tokenInfo) return null;

    // Check if token is expired
    if (tokenInfo.expires && tokenInfo.expires < new Date()) {
      this.tokens.delete(service);
      return null;
    }

    return tokenInfo.token;
  }

  isTokenValid(service: string): boolean {
    return this.getToken(service) !== null;
  }

  refreshToken(service: string, newToken: string, expiresAt?: Date): void {
    this.setToken(service, newToken, expiresAt);
  }
}

export const tokenManager = new MakeTokenManager();
```

## Performance Patterns

### Intelligent Caching Layer

```typescript
// src/billing/cache/billing-cache.ts
export interface CacheEntry<T> {
  data: T;
  timestamp: number;
  ttl: number; // Time to live in milliseconds
}

export class BillingCache {
  private cache = new Map<string, CacheEntry<any>>();
  private readonly DEFAULT_TTL = 5 * 60 * 1000; // 5 minutes

  set<T>(key: string, data: T, ttl: number = this.DEFAULT_TTL): void {
    this.cache.set(key, {
      data,
      timestamp: Date.now(),
      ttl,
    });
  }

  get<T>(key: string): T | null {
    const entry = this.cache.get(key);
    if (!entry) return null;

    // Check if entry has expired
    if (Date.now() - entry.timestamp > entry.ttl) {
      this.cache.delete(key);
      return null;
    }

    return entry.data as T;
  }

  invalidate(pattern: string): void {
    const regex = new RegExp(pattern);
    for (const key of this.cache.keys()) {
      if (regex.test(key)) {
        this.cache.delete(key);
      }
    }
  }

  clear(): void {
    this.cache.clear();
  }

  // Cache-specific methods for billing data
  cacheSubscription(orgId: string, subscription: SubscriptionDetails): void {
    this.set(`subscription:${orgId}`, subscription, 10 * 60 * 1000); // 10 minutes
  }

  getCachedSubscription(orgId: string): SubscriptionDetails | null {
    return this.get<SubscriptionDetails>(`subscription:${orgId}`);
  }

  cachePayments(orgId: string, params: any, payments: PaymentsResponse): void {
    const cacheKey = `payments:${orgId}:${this.hashParams(params)}`;
    this.set(cacheKey, payments, 2 * 60 * 1000); // 2 minutes for payment history
  }

  getCachedPayments(orgId: string, params: any): PaymentsResponse | null {
    const cacheKey = `payments:${orgId}:${this.hashParams(params)}`;
    return this.get<PaymentsResponse>(cacheKey);
  }

  private hashParams(params: any): string {
    return Buffer.from(JSON.stringify(params)).toString("base64");
  }
}
```

### Enhanced Rate Limiting Integration

```typescript
// src/shared/rate-limiting/billing-rate-limiter.ts
import { EnhancedRateLimitManager } from "../../enhanced-rate-limit-manager.js";

export class BillingRateLimitManager extends EnhancedRateLimitManager {
  constructor() {
    super({
      // Make.com specific configuration
      requestsPerWindow: 120, // Pro plan: 120 RPM
      windowSizeSeconds: 60,

      // Enhanced components
      enableAdvancedComponents: true,

      // TokenBucket for pre-emptive limiting
      tokenBucket: {
        enabled: true,
        safetyMargin: 0.8, // Use 80% of available requests
        synchronizeWithHeaders: true,
        initialCapacity: 96, // 80% of 120 RPM
        initialRefillRate: 2.0, // 120 requests per 60 seconds
        adaptiveRefill: true,
      },

      // BackoffStrategy for intelligent retries
      backoffStrategy: {
        enabled: true,
        initialDelayMs: 1000,
        maxDelayMs: 30000,
        backoffFactor: 2.0,
        jitter: true,
        maxRetries: 3,
      },

      // Header parsing for dynamic updates
      headerParsingEnabled: true,
      dynamicCapacity: true,
      approachingLimitThreshold: 0.1, // Warn at 90% usage
    });
  }

  // Billing-specific rate limiting methods
  async executeBillingRequest<T>(
    operation: string,
    requestFn: () => Promise<T>,
    priority: "high" | "normal" | "low" = "normal",
  ): Promise<T> {
    return this.executeWithRateLimit(`billing:${operation}`, requestFn, {
      priority,
    });
  }

  async executeAuditRequest<T>(
    operation: string,
    requestFn: () => Promise<T>,
  ): Promise<T> {
    return this.executeWithRateLimit(
      `audit:${operation}`,
      requestFn,
      { priority: "low" }, // Audit requests typically lower priority
    );
  }
}
```

### Request Optimization Patterns

```typescript
// src/shared/utils/request-optimizer.ts
export class RequestOptimizer {
  private requestQueue: Array<() => Promise<any>> = [];
  private processing = false;

  // Batch multiple requests together
  async batchRequests<T>(
    requests: Array<() => Promise<T>>,
    batchSize: number = 5,
  ): Promise<T[]> {
    const results: T[] = [];

    for (let i = 0; i < requests.length; i += batchSize) {
      const batch = requests.slice(i, i + batchSize);
      const batchResults = await Promise.all(batch.map((request) => request()));
      results.push(...batchResults);

      // Brief delay between batches to respect rate limits
      if (i + batchSize < requests.length) {
        await this.delay(100);
      }
    }

    return results;
  }

  // Request deduplication
  private pendingRequests = new Map<string, Promise<any>>();

  async deduplicatedRequest<T>(
    key: string,
    requestFn: () => Promise<T>,
  ): Promise<T> {
    if (this.pendingRequests.has(key)) {
      return this.pendingRequests.get(key)!;
    }

    const promise = requestFn().finally(() => {
      this.pendingRequests.delete(key);
    });

    this.pendingRequests.set(key, promise);
    return promise;
  }

  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
```

### Performance Monitoring

```typescript
// src/shared/monitoring/billing-metrics.ts
export interface BillingMetrics {
  requests: {
    total: number;
    successful: number;
    failed: number;
    rateLimited: number;
  };
  performance: {
    averageLatency: number;
    p95Latency: number;
    slowestEndpoint: string;
  };
  cache: {
    hitRate: number;
    totalHits: number;
    totalMisses: number;
  };
  billing: {
    subscriptionsQueried: number;
    paymentsRetrieved: number;
    invoicesDownloaded: number;
  };
}

export class BillingMetricsCollector {
  private metrics: BillingMetrics = {
    requests: { total: 0, successful: 0, failed: 0, rateLimited: 0 },
    performance: { averageLatency: 0, p95Latency: 0, slowestEndpoint: "" },
    cache: { hitRate: 0, totalHits: 0, totalMisses: 0 },
    billing: {
      subscriptionsQueried: 0,
      paymentsRetrieved: 0,
      invoicesDownloaded: 0,
    },
  };

  recordRequest(success: boolean, latency: number, endpoint: string): void {
    this.metrics.requests.total++;
    if (success) {
      this.metrics.requests.successful++;
    } else {
      this.metrics.requests.failed++;
    }

    // Update performance metrics
    this.updateLatencyMetrics(latency, endpoint);
  }

  recordRateLimit(): void {
    this.metrics.requests.rateLimited++;
  }

  recordCacheHit(): void {
    this.metrics.cache.totalHits++;
    this.updateCacheHitRate();
  }

  recordCacheMiss(): void {
    this.metrics.cache.totalMisses++;
    this.updateCacheHitRate();
  }

  private updateLatencyMetrics(latency: number, endpoint: string): void {
    // Simplified metrics update - in production, use proper percentile calculation
    this.metrics.performance.averageLatency =
      (this.metrics.performance.averageLatency + latency) / 2;
  }

  private updateCacheHitRate(): void {
    const total = this.metrics.cache.totalHits + this.metrics.cache.totalMisses;
    this.metrics.cache.hitRate =
      total > 0 ? this.metrics.cache.totalHits / total : 0;
  }

  getMetrics(): BillingMetrics {
    return { ...this.metrics };
  }

  reset(): void {
    this.metrics = {
      requests: { total: 0, successful: 0, failed: 0, rateLimited: 0 },
      performance: { averageLatency: 0, p95Latency: 0, slowestEndpoint: "" },
      cache: { hitRate: 0, totalHits: 0, totalMisses: 0 },
      billing: {
        subscriptionsQueried: 0,
        paymentsRetrieved: 0,
        invoicesDownloaded: 0,
      },
    };
  }
}
```

## Implementation Checklist

### Phase 1: Core Infrastructure (Week 1)

- [ ] Set up TypeScript interfaces and data models
- [ ] Implement `MakeBillingClient` with rate limiting integration
- [ ] Create essential subscription management tools
- [ ] Set up authentication and configuration management
- [ ] Implement basic caching layer

### Phase 2: Payment & Invoice Management (Week 1-2)

- [ ] Implement payment history tools
- [ ] Create single payment processing tools
- [ ] Add invoice download and management tools
- [ ] Implement comprehensive error handling

### Phase 3: Audit Logs (Week 2)

- [ ] Create `MakeAuditClient` for log retrieval
- [ ] Implement audit log analysis tools
- [ ] Add log filtering and search capabilities
- [ ] Create audit reporting functionality

### Phase 4: Advanced Features (Week 2-3)

- [ ] Implement intelligent caching with TTL management
- [ ] Add request optimization and batching
- [ ] Create comprehensive performance monitoring
- [ ] Add health checking and diagnostics

### Phase 5: Testing & Documentation (Week 3)

- [ ] Unit tests for all API clients and tools
- [ ] Integration tests with Make.com API
- [ ] Performance testing and optimization
- [ ] Complete API documentation and usage examples

## Getting Started

1. **Install dependencies**:

   ```bash
   npm install axios zod winston uuid
   npm install --save-dev @types/uuid
   ```

2. **Set up environment variables**:

   ```bash
   # .env
   MAKE_BILLING_API_TOKEN=your_billing_token
   MAKE_BILLING_ORG_ID=your_org_id
   MAKE_BILLING_REGION=eu
   MAKE_AUDIT_API_TOKEN=your_audit_token
   MAKE_AUDIT_ORG_ID=your_org_id
   MAKE_AUDIT_REGION=eu
   ```

3. **Initialize the server**:

   ```typescript
   import { MakeAdministrationServer } from "./src/admin-server.js";
   import { loadAuthConfig } from "./src/shared/config/auth.js";

   const config = loadAuthConfig();
   const server = new MakeAdministrationServer(config);
   await server.initialize();
   ```

This implementation guide provides a solid foundation for building production-ready Make.com billing and administration FastMCP tools with enterprise-grade performance, security, and reliability features.
