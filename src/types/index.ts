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