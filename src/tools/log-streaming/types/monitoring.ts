/**
 * @fileoverview Monitoring types for log streaming tools
 * Type definitions for monitoring, analytics, and performance tracking
 */

export interface CustomMetric {
  name?: string;
  field?: string;
  aggregation?: 'count' | 'sum' | 'avg' | 'min' | 'max' | 'distinct';
  filters?: Record<string, unknown>;
  timeWindow?: string;
}

export interface AnalyticsConfig {
  enabled?: boolean;
  includePerformanceMetrics?: boolean;
  includePredictiveAnalysis?: boolean;
  customMetrics?: CustomMetric[];
  anomalyDetection?: {
    enabled: boolean;
    sensitivity: number;
    algorithms: string[];
  };
  features?: {
    realTimeAnalysis?: boolean;
    predictiveInsights?: boolean;
    anomalyDetection?: boolean;
    performanceAnalysis?: boolean;
    errorCorrelation?: boolean;
    performanceOptimization?: boolean;
  };
  type?: 'standard' | 'advanced' | 'enterprise';
}

export interface PerformanceMetrics {
  processingTime: number;
  memoryUsage?: number;
  apiCalls?: number;
  dataProcessed?: number;
  throughput?: number;
  errorRate?: number;
  responseTime?: number;
  queueDepth?: number;
}

export interface MonitoringAlert {
  id: string;
  type: 'performance' | 'error' | 'anomaly' | 'threshold';
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  timestamp: string;
  scenarioId?: string;
  executionId?: string;
  threshold?: {
    metric: string;
    value: number;
    condition: 'gt' | 'lt' | 'eq' | 'gte' | 'lte';
  };
  resolution?: {
    status: 'open' | 'acknowledged' | 'resolved';
    resolvedAt?: string;
    resolvedBy?: string;
    notes?: string;
  };
}

export interface RealtimeMetrics {
  timestamp: string;
  activeExecutions: number;
  averageExecutionTime: number;
  errorRate: number;
  throughput: number;
  memoryUsage: number;
  cpuUsage?: number;
  queueLength: number;
  connectionHealthScore: number;
}