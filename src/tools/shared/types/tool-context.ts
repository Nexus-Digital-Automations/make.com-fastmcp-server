/**
 * @fileoverview Shared tool execution context
 * Standardized dependency injection interface for FastMCP tools
 */

import { FastMCP, type SerializableValue } from 'fastmcp';
import { ZodSchema } from 'zod';
import MakeApiClient from '../../../lib/make-api-client.js';
import { Logger } from '../../../lib/logger.js';

/**
 * Core dependency injection context for tools
 */
export interface ToolContext {
  server: FastMCP;
  apiClient: MakeApiClient;
  logger: {
    debug?: (message: string, data?: SerializableValue) => void;
    info?: (message: string, data?: SerializableValue) => void;
    warn?: (message: string, data?: SerializableValue) => void;
    error?: (message: string, data?: SerializableValue) => void;
  };
}

/**
 * Enhanced tool context with additional services
 */
export interface EnhancedToolContext extends ToolContext {
  cache?: CacheService;
  metrics?: MetricsService;
  config?: ConfigService;
  diagnostics?: DiagnosticsService;
}

/**
 * Runtime execution context passed to tool functions
 */
export interface ToolExecutionContext {
  log?: {
    info?: (message: string, data?: SerializableValue) => void;
    warn?: (message: string, data?: SerializableValue) => void;
    error?: (message: string, data?: SerializableValue) => void;
    debug?: (message: string, data?: SerializableValue) => void;
  };
  reportProgress?: (progress: { progress: number; total: number }) => void;
  session?: Record<string, unknown>;
}

/**
 * Standard tool definition interface
 */
export interface ToolDefinition {
  name: string;
  description: string;
  parameters: ZodSchema; // More specific than any
  annotations: ToolAnnotations;
  execute: (args: unknown, context: ToolExecutionContext) => Promise<string>;
}

/**
 * FastMCP tool annotations
 */
export interface ToolAnnotations {
  title: string;
  readOnlyHint: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint: boolean;
}

/**
 * Tool factory function type
 */
export type ToolFactory = (context: ToolContext) => ToolDefinition;

/**
 * Enhanced tool factory with additional context
 */
export type EnhancedToolFactory = (context: EnhancedToolContext) => ToolDefinition;

/**
 * Tool registration function type
 */
export type ToolRegistrationFunction = (server: FastMCP, apiClient: MakeApiClient) => void;

/**
 * Cache service interface
 */
export interface CacheService {
  get<T = unknown>(key: string): Promise<T | null>;
  set<T = unknown>(key: string, value: T, ttl?: number): Promise<void>;
  delete(key: string): Promise<void>;
  clear(): Promise<void>;
  has(key: string): Promise<boolean>;
}

/**
 * Metrics service interface
 */
export interface MetricsService {
  counter(name: string, labels?: Record<string, string>): void;
  gauge(name: string, value: number, labels?: Record<string, string>): void;
  histogram(name: string, value: number, labels?: Record<string, string>): void;
  timer(name: string, labels?: Record<string, string>): () => void;
}

/**
 * Configuration service interface
 */
export interface ConfigService {
  get<T = unknown>(key: string, defaultValue?: T): T;
  has(key: string): boolean;
  set(key: string, value: unknown): void;
  getAll(): Record<string, unknown>;
}

/**
 * Diagnostics service interface
 */
export interface DiagnosticsService {
  checkHealth(): Promise<HealthStatus>;
  getMetrics(): Promise<DiagnosticMetrics>;
  runDiagnostics(): Promise<DiagnosticResult[]>;
}

/**
 * Health status interface
 */
export interface HealthStatus {
  healthy: boolean;
  timestamp: Date;
  services: Record<string, ServiceHealth>;
  uptime: number;
}

/**
 * Service health status
 */
export interface ServiceHealth {
  healthy: boolean;
  message?: string;
  responseTime?: number;
  details?: Record<string, unknown>;
}

/**
 * Diagnostic metrics
 */
export interface DiagnosticMetrics {
  memory: {
    used: number;
    total: number;
    percentage: number;
  };
  cpu: {
    usage: number;
    load: number[];
  };
  requests: {
    total: number;
    successful: number;
    failed: number;
    averageResponseTime: number;
  };
  errors: {
    count: number;
    rate: number;
    types: Record<string, number>;
  };
}

/**
 * Diagnostic result
 */
export interface DiagnosticResult {
  name: string;
  category: 'performance' | 'security' | 'configuration' | 'connectivity';
  status: 'pass' | 'warn' | 'fail';
  message: string;
  details?: Record<string, unknown>;
  recommendations?: string[];
}

/**
 * Convert Logger instance to ToolContext compatible logger
 */
export function createToolContextLogger(logger: Logger): ToolContext['logger'] {
  return {
    debug: (message: string, data?: SerializableValue): void => {
      const logData = data && typeof data === 'object' && data !== null && !Array.isArray(data) 
        ? data as Record<string, unknown>
        : data !== undefined ? { data } : undefined;
      logger.debug(message, logData);
    },
    info: (message: string, data?: SerializableValue): void => {
      const logData = data && typeof data === 'object' && data !== null && !Array.isArray(data) 
        ? data as Record<string, unknown>
        : data !== undefined ? { data } : undefined;
      logger.info(message, logData);
    },
    warn: (message: string, data?: SerializableValue): void => {
      const logData = data && typeof data === 'object' && data !== null && !Array.isArray(data) 
        ? data as Record<string, unknown>
        : data !== undefined ? { data } : undefined;
      logger.warn(message, logData);
    },
    error: (message: string, data?: SerializableValue): void => {
      const logData = data && typeof data === 'object' && data !== null && !Array.isArray(data) 
        ? data as Record<string, unknown>
        : data !== undefined ? { data } : undefined;
      logger.error(message, logData);
    },
  };
}