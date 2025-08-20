/**
 * Type definitions for Make.com FastMCP Server
 * Comprehensive types for Make.com API integration
 */

import { FastMCP } from 'fastmcp';
import { z } from 'zod';

// FastMCP Server Types
export type FastMCPServer = FastMCP<any>;
export type ToolParameters = z.ZodType<any>;

// Tool creation function type
export type ToolCreationFunction<T = any> = (apiClient: T) => {
  name: string;
  description: string;
  parameters: ToolParameters;
  execute: (args: any, context?: any) => Promise<string>;
};

// Server interface for tool registration
export interface ToolServer {
  addTool: <Params extends ToolParameters>(tool: {
    name: string;
    description: string;
    parameters: Params;
    execute: (args: z.infer<Params>, context?: any) => Promise<string>;
  }) => void;
}

export interface MakeApiConfig {
  apiKey: string;
  baseUrl: string;
  teamId?: string;
  organizationId?: string;
  timeout?: number;
  retries?: number;
}

export interface RateLimitConfig {
  maxRequests: number;
  windowMs: number;
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
}

export interface ServerConfig {
  name: string;
  version: string;
  port?: number;
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
  authentication?: {
    enabled: boolean;
    secret?: string;
  };
  rateLimit?: RateLimitConfig;
  make: MakeApiConfig;
}

export interface MakeScenario {
  id: number;
  name: string;
  teamId: number;
  folderId?: number;
  blueprint: Record<string, unknown>;
  scheduling: {
    type: 'immediate' | 'indefinitely' | 'on-demand';
    interval?: number;
  };
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface MakeConnection {
  id: number;
  name: string;
  accountName: string;
  service: string;
  metadata: Record<string, unknown>;
  isValid: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface MakeTemplate {
  id: number;
  name: string;
  description?: string;
  category?: string;
  blueprint: Record<string, unknown>;
  tags: string[];
  isPublic: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface MakeExecution {
  id: number;
  scenarioId: number;
  status: 'success' | 'error' | 'warning' | 'incomplete';
  startedAt: string;
  finishedAt?: string;
  operations: number;
  dataTransfer: number;
  error?: {
    message: string;
    code?: string;
    details?: Record<string, unknown>;
  };
}

export interface MakeUser {
  id: number;
  name: string;
  email: string;
  role: 'admin' | 'member' | 'viewer';
  teamId: number;
  organizationId?: number;
  permissions: string[];
  isActive: boolean;
}

export interface MakeWebhook {
  id: number;
  name: string;
  url: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  headers?: Record<string, string>;
  isActive: boolean;
  scenarioId?: number;
  createdAt: string;
}

export interface MakeVariable {
  id: number;
  name: string;
  value: unknown;
  type: 'string' | 'number' | 'boolean' | 'json';
  scope: 'global' | 'team' | 'scenario';
  isEncrypted: boolean;
  createdAt: string;
}

export interface ApiResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: {
    message: string;
    code?: string;
    details?: Record<string, unknown>;
  };
  metadata?: {
    total?: number;
    page?: number;
    limit?: number;
  };
}

export interface ToolExecutionContext {
  log: {
    debug: (message: string, data?: unknown) => void;
    info: (message: string, data?: unknown) => void;
    warn: (message: string, data?: unknown) => void;
    error: (message: string, data?: unknown) => void;
  };
  reportProgress: (progress: { progress: number; total: number }) => void;
  session?: Record<string, unknown>;
}

export interface MakeApiError extends Error {
  code?: string;
  status?: number;
  details?: Record<string, unknown>;
  retryable: boolean;
}

export interface MakeAnalytics {
  organizationId: number;
  period: {
    startDate: string;
    endDate: string;
  };
  usage: {
    operations: number;
    dataTransfer: number;
    executions: number;
    successfulExecutions: number;
    failedExecutions: number;
  };
  performance: {
    averageExecutionTime: number;
    averageOperationsPerExecution: number;
    topScenarios: Array<{
      scenarioId: number;
      name: string;
      executions: number;
      operations: number;
    }>;
  };
  billing: {
    operationsUsed: number;
    operationsLimit: number;
    dataTransferUsed: number;
    dataTransferLimit: number;
  };
}

export interface MakeAuditLog {
  id: number;
  timestamp: string;
  userId: number;
  userName: string;
  action: string;
  resource: string;
  resourceId?: number;
  details: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
  organizationId?: number;
  teamId?: number;
}

export interface MakeScenarioLog {
  id: number;
  scenarioId: number;
  executionId: number;
  timestamp: string;
  level: 'info' | 'warning' | 'error' | 'debug';
  message: string;
  moduleId?: number;
  moduleName?: string;
  data?: Record<string, unknown>;
}

export interface MakeIncompleteExecution {
  id: number;
  scenarioId: number;
  scenarioName: string;
  startedAt: string;
  stoppedAt: string;
  reason: string;
  status: 'waiting' | 'paused' | 'failed';
  operations: number;
  dataTransfer: number;
  lastModuleId?: number;
  lastModuleName?: string;
  error?: {
    message: string;
    code?: string;
    details?: Record<string, unknown>;
  };
  canResume: boolean;
}

export interface MakeHookLog {
  id: number;
  hookId: number;
  timestamp: string;
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: unknown;
  response?: {
    status: number;
    headers: Record<string, string>;
    body?: unknown;
  };
  processingTime: number;
  success: boolean;
  error?: string;
}

export interface MakeCustomApp {
  id: number;
  name: string;
  description?: string;
  version: string;
  status: 'draft' | 'testing' | 'published' | 'deprecated' | 'suspended';
  organizationId?: number;
  teamId?: number;
  configuration: {
    type: 'connector' | 'trigger' | 'action' | 'transformer' | 'full_app';
    runtime: 'nodejs' | 'python' | 'php' | 'custom';
    environment: {
      variables: Record<string, string>;
      secrets: string[];
      dependencies: Record<string, string>;
    };
    endpoints: Array<{
      name: string;
      method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
      path: string;
      description?: string;
      parameters: Record<string, unknown>;
      responses: Record<string, unknown>;
    }>;
    authentication: {
      type: 'none' | 'api_key' | 'oauth2' | 'basic_auth' | 'custom';
      configuration: Record<string, unknown>;
    };
    ui: {
      icon?: string;
      color?: string;
      description?: string;
      category?: string;
    };
  };
  usage: {
    installations: number;
    executions: number;
    averageResponseTime: number;
    errorRate: number;
    lastUsed?: string;
  };
  createdAt: string;
  updatedAt: string;
  createdBy: number;
  createdByName: string;
}

export interface MakeSDKApp {
  id: number;
  name: string;
  description?: string;
  version: string;
  publisher: string;
  category: 'productivity' | 'integration' | 'automation' | 'analytics' | 'communication' | 'utility' | 'custom';
  status: 'available' | 'installed' | 'updating' | 'deprecated' | 'suspended';
  organizationId?: number;
  teamId?: number;
  installation: {
    installedAt?: string;
    installedBy?: number;
    installedByName?: string;
    version: string;
    autoUpdate: boolean;
    configuration: Record<string, unknown>;
    permissions: {
      granted: string[];
      requested: string[];
      denied: string[];
    };
  };
  usage: {
    installations: number;
    rating: number;
    reviews: number;
    activeUsers: number;
    executions: number;
    lastUsed?: string;
  };
  security: {
    verified: boolean;
    sandboxed: boolean;
    permissions: string[];
    dataAccess: 'none' | 'read' | 'write' | 'full';
    networkAccess: boolean;
  };
  createdAt: string;
  updatedAt: string;
  publishedAt: string;
}

export interface MakeBillingAccount {
  id: number;
  organizationId: number;
  organizationName: string;
  accountStatus: 'active' | 'suspended' | 'cancelled' | 'pending';
  billingPlan: {
    name: string;
    type: 'free' | 'starter' | 'professional' | 'team' | 'enterprise';
    price: number;
    currency: string;
    billingCycle: 'monthly' | 'annual';
  };
  usage: {
    currentPeriod: {
      startDate: string;
      endDate: string;
      operations: {
        used: number;
        limit: number;
        percentage: number;
      };
    };
  };
  billing: {
    nextBillingDate: string;
    currentBalance: number;
    paymentStatus: 'current' | 'overdue' | 'failed' | 'processing';
    autoRenewal: boolean;
  };
  createdAt: string;
  updatedAt: string;
}

export interface MakeNotification {
  id: number;
  type: 'system' | 'billing' | 'security' | 'scenario' | 'team' | 'marketing' | 'custom';
  category: 'info' | 'warning' | 'error' | 'success' | 'reminder' | 'alert';
  priority: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  message: string;
  status: 'draft' | 'scheduled' | 'sent' | 'delivered' | 'failed' | 'cancelled';
  channels: {
    email: boolean;
    inApp: boolean;
    sms: boolean;
    webhook: boolean;
  };
  delivery: {
    totalRecipients: number;
    successfulDeliveries: number;
    failedDeliveries: number;
  };
  createdAt: string;
  updatedAt: string;
  createdBy: number;
}