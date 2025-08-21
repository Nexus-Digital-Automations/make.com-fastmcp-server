/**
 * @fileoverview Streaming-related types for log streaming tools
 * Type definitions for real-time log streaming functionality
 */

import { SerializableValue } from 'fastmcp';

export interface Logger {
  debug: (message: string, data?: SerializableValue) => void;
  info: (message: string, data?: SerializableValue) => void;
  warn: (message: string, data?: SerializableValue) => void;
  error: (message: string, data?: SerializableValue) => void;
}

export interface LogMetadata {
  timestamp: string;
  level: string;
  scenarioId?: string;
  executionId?: string;
  [key: string]: unknown;
}

export interface StreamingLogEntry {
  id: string;
  timestamp: string;
  level: 'info' | 'warn' | 'error' | 'debug';
  message: string;
  scenarioId?: string;
  executionId?: string;
  metadata: LogMetadata;
}

export interface LogFilter {
  level?: string[];
  scenarioId?: string;
  executionId?: string;
  startTime?: string;
  endTime?: string;
  searchTerm?: string;
}

export interface ExecutionSummary {
  executionId: string;
  status: string;
  duration: number;
  stepsCompleted: number;
  totalSteps: number;
  errors: unknown[];
}

export interface SystemOverview {
  totalScenarios: number;
  activeExecutions: number;
  systemHealth: string;
  performanceMetrics: Record<string, unknown>;
}

// Enhanced log entry structure based on Make.com API
export interface MakeLogEntry {
  id: string;
  executionId: string;
  scenarioId: number;
  organizationId: number;
  teamId: number;
  timestamp: string;
  executionStartTime: string;
  moduleStartTime?: string;
  moduleEndTime?: string;
  level: 'info' | 'warning' | 'error' | 'debug';
  category: 'execution' | 'module' | 'connection' | 'validation' | 'system';
  message: string;
  details?: Record<string, unknown>;
  module: {
    id: string;
    name: string;
    type: string;
    position: number;
  };
  execution: {
    scenarioName: string;
    triggeredBy: string;
    isManual: boolean;
    progress: {
      completedModules: number;
      totalModules: number;
      percentage: number;
    };
  };
  performance: {
    processingTime: number;
    memoryUsage?: number;
    apiCalls?: number;
    dataProcessed?: number;
  };
  connection?: {
    connectionId: string;
    connectionName: string;
    authType: string;
    isActive: boolean;
    lastTested?: string;
  };
  error?: {
    code: string;
    message: string;
    type: 'connection' | 'validation' | 'execution' | 'system' | 'timeout' | 'rate_limit';
    retryable: boolean;
    stack?: string;
    context?: Record<string, unknown>;
  };
  tags?: string[];
  custom?: Record<string, unknown>;
}