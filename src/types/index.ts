/**
 * Type definitions for Make.com FastMCP Server
 * Comprehensive types for Make.com API integration
 */

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
  blueprint: any;
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
  metadata: Record<string, any>;
  isValid: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface MakeTemplate {
  id: number;
  name: string;
  description?: string;
  category?: string;
  blueprint: any;
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
    details?: any;
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
  value: any;
  type: 'string' | 'number' | 'boolean' | 'json';
  scope: 'global' | 'team' | 'scenario';
  isEncrypted: boolean;
  createdAt: string;
}

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: {
    message: string;
    code?: string;
    details?: any;
  };
  metadata?: {
    total?: number;
    page?: number;
    limit?: number;
  };
}

export interface ToolExecutionContext {
  log: {
    debug: (message: string, data?: any) => void;
    info: (message: string, data?: any) => void;
    warn: (message: string, data?: any) => void;
    error: (message: string, data?: any) => void;
  };
  reportProgress: (progress: { progress: number; total: number }) => void;
  session?: any;
}

export interface MakeApiError extends Error {
  code?: string;
  status?: number;
  details?: any;
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
  details: Record<string, any>;
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
  data?: Record<string, any>;
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
    details?: any;
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
  body?: any;
  response?: {
    status: number;
    headers: Record<string, string>;
    body?: any;
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
      parameters: any;
      responses: any;
    }>;
    authentication: {
      type: 'none' | 'api_key' | 'oauth2' | 'basic_auth' | 'custom';
      configuration: Record<string, any>;
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
    configuration: Record<string, any>;
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