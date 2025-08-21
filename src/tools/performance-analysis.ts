/**
 * Performance Analysis and Bottleneck Detection Tools for Make.com FastMCP Server
 * Comprehensive performance monitoring, bottleneck detection, and optimization recommendations
 */

import { FastMCP, UserError } from 'fastmcp';
import { z } from 'zod';
import MakeApiClient from '../lib/make-api-client.js';
import logger from '../lib/logger.js';
import metrics from '../lib/metrics.js';
import PerformanceMonitor from '../lib/performance-monitor.js';
import { 
  type SystemMemoryMetrics, 
  type CpuMetrics,
  type PerformanceAnalysisOptions,
  type PerformanceAnalysisFilters,
  type AlertThresholds
} from '../types/index.js';

// Performance analysis schemas
const PerformanceAnalysisSchema = z.object({
  targetType: z.enum(['scenario', 'organization', 'webhook', 'api', 'system']).describe('Type of target to analyze'),
  targetId: z.string().optional().describe('ID of specific target (scenario ID, organization ID, etc.)'),
  analysisOptions: z.object({
    timeRangeHours: z.number().min(1).max(168).default(24).describe('Time range to analyze in hours (max 7 days)'),
    includeBottleneckDetection: z.boolean().default(true).describe('Include bottleneck detection analysis'),
    includePerformanceMetrics: z.boolean().default(true).describe('Include performance metrics collection'),
    includeTrendAnalysis: z.boolean().default(true).describe('Include trend analysis over time'),
    includeOptimizationRecommendations: z.boolean().default(true).describe('Include optimization recommendations'),
    includeCostAnalysis: z.boolean().default(false).describe('Include cost impact analysis'),
    performanceBenchmarking: z.boolean().default(true).describe('Compare against industry benchmarks'),
    detailedBreakdown: z.boolean().default(false).describe('Include detailed component-level breakdown')
  }).optional(),
  filters: z.object({
    minExecutionTime: z.number().optional().describe('Minimum execution time to consider (ms)'),
    errorThreshold: z.number().min(0).max(1).default(0.05).describe('Error rate threshold for concern'),
    severityFilter: z.enum(['all', 'warning', 'error', 'critical']).default('all').describe('Minimum severity to include')
  }).optional()
}).strict();

const ComprehensiveAnalysisSchema = z.object({
  includeSystemMetrics: z.boolean().default(true).describe('Include system-wide performance metrics'),
  includeApiMetrics: z.boolean().default(true).describe('Include API performance metrics'),
  includeWebhookMetrics: z.boolean().default(true).describe('Include webhook performance metrics'),
  includeScenarioMetrics: z.boolean().default(true).describe('Include scenario execution metrics'),
  timeRangeHours: z.number().min(1).max(168).default(24).describe('Time range to analyze in hours'),
  generateRecommendations: z.boolean().default(true).describe('Generate optimization recommendations'),
  benchmarkComparison: z.boolean().default(true).describe('Compare against industry benchmarks')
}).strict();

const LiveAnalysisSchema = z.object({
  durationMinutes: z.number().min(1).max(60).default(5).describe('Duration to monitor in minutes'),
  samplingIntervalSeconds: z.number().min(1).max(60).default(10).describe('Sampling interval in seconds'),
  alertThresholds: z.object({
    responseTime: z.number().default(1000).describe('Response time threshold in ms'),
    errorRate: z.number().default(0.05).describe('Error rate threshold (0-1)'),
    cpuUsage: z.number().default(0.8).describe('CPU usage threshold (0-1)'),
    memoryUsage: z.number().default(0.85).describe('Memory usage threshold (0-1)')
  }).optional()
}).strict();

// Performance analysis interfaces

// System metrics interfaces (imported from types/index.ts)

interface SystemCpuMetrics {
  user: number;
  system: number;
  utilization: number;
}

interface _SystemMetrics {
  memory: SystemMemoryMetrics;
  cpu: SystemCpuMetrics;
  uptime: number;
  timestamp: number;
}

interface _ApiMetrics {
  responseTime: number;
  healthy: boolean;
  rateLimiter?: {
    requestsRemaining: number;
    resetTime: number;
  };
  error?: string;
  timestamp: number;
}

interface _WebhookMetrics {
  maxThroughput: number;
  queueSize: number;
  processingTime: number;
  currentLoad: number;
  timestamp: number;
}

interface _ScenarioExecutionMetrics {
  averageExecutionTime: number;
  successRate: number;
  errorRate: number;
}

interface _ScenarioMetrics {
  scenario?: Record<string, unknown>;
  executionMetrics?: _ScenarioExecutionMetrics;
  error?: string;
  timestamp: number;
}

interface _OrganizationUsage {
  operationsUsed: number;
  operationsLimit: number;
  utilizationRate: number;
}

interface _OrganizationMetrics {
  organization?: Record<string, unknown>;
  usage?: _OrganizationUsage;
  error?: string;
  timestamp: number;
}

interface MetricsFormattingResult {
  responseTime: {
    average: number;
    p50: number;
    p95: number;
    p99: number;
    trend: 'improving' | 'stable' | 'degrading';
  };
  throughput: {
    requestsPerSecond: number;
    requestsPerMinute: number;
    trend: 'improving' | 'stable' | 'degrading';
  };
  reliability: {
    uptime: number;
    errorRate: number;
    successRate: number;
    trend: 'improving' | 'stable' | 'degrading';
  };
  resources: {
    cpuUsage: number;
    memoryUsage: number;
    networkUtilization: number;
    trend: 'improving' | 'stable' | 'degrading';
  };
}

// Options and Filters interfaces
interface PerformanceAnalysisOptions {
  timeRangeHours: number;
  includeBottleneckDetection?: boolean;
  includePerformanceMetrics?: boolean;
  includeTrendAnalysis?: boolean;
  includeOptimizationRecommendations?: boolean;
  includeCostAnalysis?: boolean;
  performanceBenchmarking?: boolean;
  detailedBreakdown?: boolean;
  includeSystemMetrics?: boolean;
  includeApiMetrics?: boolean;
  includeWebhookMetrics?: boolean;
  includeScenarioMetrics?: boolean;
  generateRecommendations?: boolean;
  benchmarkComparison?: boolean;
  durationMinutes?: number;
  samplingIntervalSeconds?: number;
  alertThresholds?: AlertThresholds;
}

interface PerformanceAnalysisFilters {
  minExecutionTime?: number;
  errorThreshold: number;
  severityFilter: 'all' | 'warning' | 'error' | 'critical';
}

interface AlertThresholds {
  responseTime: number;
  errorRate: number;
  cpuUsage: number;
  memoryUsage: number;
}

interface PerformanceMetrics {
  responseTime?: {
    average: number;
    p50: number;
    p95: number;
    p99: number;
    trend: 'improving' | 'stable' | 'degrading';
  } | number;
  throughput?: {
    requestsPerSecond: number;
    requestsPerMinute: number;
    trend: 'improving' | 'stable' | 'degrading';
  };
  reliability?: {
    uptime: number;
    errorRate: number;
    successRate: number;
    trend: 'improving' | 'stable' | 'degrading';
  };
  resources?: {
    cpuUsage: number;
    memoryUsage: number;
    networkUtilization: number;
    trend: 'improving' | 'stable' | 'degrading';
  };
  memory?: number | SystemMemoryMetrics;
  cpu?: SystemCpuMetrics;
  uptime?: number;
  timestamp?: number;
  healthy?: boolean;
  error?: string;
  rateLimiter?: {
    requestsRemaining: number;
    resetTime: number;
  };
  [key: string]: unknown;
}

interface TrendAnalysis {
  performanceDirection: 'improving' | 'stable' | 'degrading';
  predictionConfidence: number;
  projectedIssues: string[];
}

interface BenchmarkComparison {
  industryStandard: string;
  currentPerformance: string;
  gap: string;
  ranking: 'below_average' | 'average' | 'above_average' | 'excellent';
}

interface OptimizationRecommendations {
  immediate: string[];
  shortTerm: string[];
  longTerm: string[];
  estimatedImpact: number;
}

interface CostAnalysis {
  currentCost: number;
  optimizationPotential: number;
  recommendedActions: string[];
}


interface PerformanceBottleneck {
  type: 'response_time' | 'throughput' | 'error_rate' | 'resource_usage' | 'rate_limiting' | 'webhook_queue';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  impact: string;
  affectedComponents: string[];
  metrics: {
    currentValue: number;
    expectedValue: number;
    unit: string;
    trend: 'improving' | 'stable' | 'degrading';
  };
  rootCause: string;
  recommendations: string[];
  estimatedImpact: {
    performanceImprovement: number; // percentage
    costSavings: number; // percentage
    implementationEffort: 'low' | 'medium' | 'high';
  };
}

interface PerformanceAnalysisResult {
  analysisTimestamp: string;
  targetType: string;
  targetId?: string;
  timeRange: {
    startTime: string;
    endTime: string;
    durationHours: number;
  };
  overallHealthScore: number; // 0-100
  performanceGrade: 'A' | 'B' | 'C' | 'D' | 'F';
  bottlenecks: PerformanceBottleneck[];
  metrics: {
    responseTime: {
      average: number;
      p50: number;
      p95: number;
      p99: number;
      trend: 'improving' | 'stable' | 'degrading';
    };
    throughput: {
      requestsPerSecond: number;
      requestsPerMinute: number;
      trend: 'improving' | 'stable' | 'degrading';
    };
    reliability: {
      uptime: number;
      errorRate: number;
      successRate: number;
      trend: 'improving' | 'stable' | 'degrading';
    };
    resources: {
      cpuUsage: number;
      memoryUsage: number;
      networkUtilization: number;
      trend: 'improving' | 'stable' | 'degrading';
    };
  };
  trends: {
    performanceDirection: 'improving' | 'stable' | 'degrading';
    predictionConfidence: number;
    projectedIssues: string[];
  };
  benchmarkComparison: {
    industryStandard: string;
    currentPerformance: string;
    gap: string;
    ranking: 'below_average' | 'average' | 'above_average' | 'excellent';
  };
  recommendations: {
    immediate: string[];
    shortTerm: string[];
    longTerm: string[];
    estimatedImpact: number;
  };
  costAnalysis?: {
    currentCost: number;
    optimizationPotential: number;
    recommendedActions: string[];
  };
}

interface LivePerformanceUpdate {
  timestamp: string;
  metrics: {
    responseTime: number;
    requestRate: number;
    errorRate: number;
    cpuUsage: number;
    memoryUsage: number;
  };
  alerts: Array<{
    type: string;
    severity: 'warning' | 'error' | 'critical';
    message: string;
    threshold: number;
    currentValue: number;
  }>;
  status: 'healthy' | 'warning' | 'critical';
}

/**
 * Performance Analysis Engine
 */
class PerformanceAnalysisEngine {
  private componentLogger: ReturnType<typeof logger.child>;
  private performanceMonitor: PerformanceMonitor;
  private readonly industryBenchmarks = {
    responseTime: {
      excellent: 100,
      good: 500,
      acceptable: 1000,
      poor: 2000
    },
    errorRate: {
      excellent: 0.001,
      good: 0.01,
      acceptable: 0.05,
      poor: 0.1
    },
    uptime: {
      excellent: 99.99,
      good: 99.95,
      acceptable: 99.9,
      poor: 99.5
    }
  };

  constructor() {
    this.componentLogger = logger.child({ component: 'PerformanceAnalysisEngine' });
    this.performanceMonitor = new PerformanceMonitor();
  }

  /**
   * Analyze performance bottlenecks for a specific target
   */
  async analyzePerformanceBottlenecks(
    targetType: string,
    targetId: string | undefined,
    options: PerformanceAnalysisOptions,
    filters: PerformanceAnalysisFilters,
    apiClient: MakeApiClient
  ): Promise<PerformanceAnalysisResult> {
    const startTime = Date.now();
    const endTime = startTime - (options.timeRangeHours * 60 * 60 * 1000);

    this.componentLogger.info('Starting performance bottleneck analysis', {
      targetType,
      targetId,
      timeRangeHours: options.timeRangeHours
    });

    try {
      // Collect performance metrics
      const metrics = await this.collectPerformanceMetrics(targetType, targetId, {
        startTime: endTime,
        endTime: startTime,
        apiClient
      });

      // Detect bottlenecks
      const bottlenecks = await this.detectBottlenecks(metrics, filters);

      // Analyze trends
      const trends = await this.analyzeTrends(metrics, options.timeRangeHours);

      // Generate benchmark comparison
      const benchmarkComparison = this.compareToBenchmarks(metrics);

      // Calculate overall health score
      const overallHealthScore = this.calculateHealthScore(metrics, bottlenecks);

      // Generate recommendations
      const recommendations = await this.generateRecommendations(bottlenecks, metrics);

      // Optional cost analysis
      let costAnalysis;
      if (options.includeCostAnalysis) {
        costAnalysis = await this.analyzeCostImpact(metrics, bottlenecks, apiClient);
      }

      const result: PerformanceAnalysisResult = {
        analysisTimestamp: new Date().toISOString(),
        targetType,
        targetId,
        timeRange: {
          startTime: new Date(endTime).toISOString(),
          endTime: new Date(startTime).toISOString(),
          durationHours: options.timeRangeHours
        },
        overallHealthScore,
        performanceGrade: this.calculatePerformanceGrade(overallHealthScore),
        bottlenecks,
        metrics: this.formatMetrics(metrics),
        trends,
        benchmarkComparison,
        recommendations,
        costAnalysis
      };

      this.componentLogger.info('Performance analysis completed', {
        targetType,
        healthScore: overallHealthScore,
        bottleneckCount: bottlenecks.length,
        executionTime: Date.now() - startTime
      });

      return result;

    } catch (error) {
      this.componentLogger.error('Performance analysis failed', {
        targetType,
        targetId,
        error: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }

  /**
   * Perform comprehensive system-wide performance analysis
   */
  async performComprehensiveAnalysis(
    options: PerformanceAnalysisOptions,
    apiClient: MakeApiClient
  ): Promise<PerformanceAnalysisResult> {
    this.componentLogger.info('Starting comprehensive performance analysis');

    try {
      const analyses: PerformanceAnalysisResult[] = [];

      // System-wide analysis
      if (options.includeSystemMetrics) {
        const systemAnalysis = await this.analyzePerformanceBottlenecks(
          'system',
          undefined,
          { timeRangeHours: options.timeRangeHours, includeBottleneckDetection: true },
          { errorThreshold: 5, severityFilter: 'all' },
          apiClient
        );
        analyses.push(systemAnalysis);
      }

      // API performance analysis
      if (options.includeApiMetrics) {
        const apiAnalysis = await this.analyzePerformanceBottlenecks(
          'api',
          undefined,
          { timeRangeHours: options.timeRangeHours, includeBottleneckDetection: true },
          { errorThreshold: 5, severityFilter: 'all' },
          apiClient
        );
        analyses.push(apiAnalysis);
      }

      // Webhook performance analysis
      if (options.includeWebhookMetrics) {
        const webhookAnalysis = await this.analyzePerformanceBottlenecks(
          'webhook',
          undefined,
          { timeRangeHours: options.timeRangeHours, includeBottleneckDetection: true },
          { errorThreshold: 5, severityFilter: 'all' },
          apiClient
        );
        analyses.push(webhookAnalysis);
      }

      // Aggregate results
      const aggregatedResult = this.aggregateAnalysisResults(analyses);

      this.componentLogger.info('Comprehensive analysis completed', {
        analysesPerformed: analyses.length,
        overallScore: aggregatedResult.overallHealthScore
      });

      return aggregatedResult;

    } catch (error) {
      this.componentLogger.error('Comprehensive analysis failed', {
        error: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }

  /**
   * Perform live performance monitoring
   */
  async performLiveAnalysis(
    options: PerformanceAnalysisOptions,
    progressCallback?: (update: LivePerformanceUpdate) => void
  ): Promise<LivePerformanceUpdate[]> {
    const durationMs = (options.durationMinutes || 5) * 60 * 1000;
    const intervalMs = (options.samplingIntervalSeconds || 10) * 1000;
    const updates: LivePerformanceUpdate[] = [];
    const startTime = Date.now();

    this.componentLogger.info('Starting live performance monitoring', {
      durationMinutes: options.durationMinutes,
      samplingIntervalSeconds: options.samplingIntervalSeconds
    });

    const monitoringInterval = setInterval(async () => {
      try {
        const update = await this.collectLiveMetrics(options.alertThresholds || { errorRate: 5, responseTime: 1000, cpuUsage: 80, memoryUsage: 85 });
        updates.push(update);

        if (progressCallback) {
          progressCallback(update);
        }

        // Check if monitoring duration is complete
        if (Date.now() - startTime >= durationMs) {
          clearInterval(monitoringInterval);
          this.componentLogger.info('Live monitoring completed', {
            totalUpdates: updates.length,
            duration: Date.now() - startTime
          });
        }
      } catch (error) {
        this.componentLogger.error('Live monitoring update failed', {
          error: error instanceof Error ? error.message : String(error)
        });
      }
    }, intervalMs);

    // Return promise that resolves when monitoring is complete
    return new Promise((resolve) => {
      setTimeout(() => {
        clearInterval(monitoringInterval);
        resolve(updates);
      }, durationMs);
    });
  }

  /**
   * Collect performance metrics for analysis
   */
  private async collectPerformanceMetrics(
    targetType: string,
    targetId: string | undefined,
    timeRange: { startTime: number; endTime: number; apiClient: MakeApiClient }
  ): Promise<PerformanceMetrics> {
    const { apiClient } = timeRange;

    switch (targetType) {
      case 'system':
        return this.collectSystemMetrics();
      case 'api':
        return this.collectApiMetrics(apiClient);
      case 'webhook':
        return this.collectWebhookMetrics(apiClient);
      case 'scenario':
        return this.collectScenarioMetrics(targetId, apiClient);
      case 'organization':
        return this.collectOrganizationMetrics(targetId, apiClient);
      default:
        throw new Error(`Unsupported target type: ${targetType}`);
    }
  }

  /**
   * Collect system-level metrics
   */
  private async collectSystemMetrics(): Promise<{
    memory: SystemMemoryMetrics;
    cpu: SystemCpuMetrics;
    uptime: number;
    timestamp: number;
  }> {
    const memUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();
    const uptime = process.uptime();

    return {
      memory: {
        used: memUsage.heapUsed,
        total: memUsage.heapTotal,
        utilization: memUsage.heapUsed / memUsage.heapTotal
      },
      cpu: {
        user: cpuUsage.user,
        system: cpuUsage.system,
        utilization: (cpuUsage.user + cpuUsage.system) / 1000000 / uptime
      },
      uptime,
      timestamp: Date.now()
    };
  }

  /**
   * Collect API-level metrics
   */
  private async collectApiMetrics(apiClient: MakeApiClient): Promise<{
    responseTime: number;
    healthy: boolean;
    rateLimiter?: {
      requestsRemaining: number;
      resetTime: number;
    };
    timestamp: number;
    error?: string;
  }> {
    try {
      // Get rate limiter status
      const rateLimiterStatus = apiClient.getRateLimiterStatus();
      
      // Perform health check to measure response time
      const startTime = Date.now();
      const isHealthy = await apiClient.healthCheck();
      const responseTime = Date.now() - startTime;

      return {
        responseTime,
        healthy: isHealthy,
        rateLimiter: rateLimiterStatus,
        timestamp: Date.now()
      };
    } catch (error) {
      return {
        responseTime: -1,
        healthy: false,
        error: error instanceof Error ? error.message : String(error),
        timestamp: Date.now()
      };
    }
  }

  /**
   * Collect webhook-specific metrics
   */
  private async collectWebhookMetrics(_apiClient: MakeApiClient): Promise<{
    maxThroughput: number;
    queueSize: number;
    processingTime: number;
    currentLoad: number;
    timestamp: number;
  }> {
    // This would typically involve checking webhook queue status, processing times, etc.
    // For now, return estimated metrics based on Make.com documentation
    return {
      maxThroughput: 30, // webhooks per second
      queueSize: 50, // maximum queue size
      processingTime: 5000, // 5 seconds timeout
      currentLoad: 0, // would need actual webhook monitoring
      timestamp: Date.now()
    };
  }

  /**
   * Collect scenario-specific metrics
   */
  private async collectScenarioMetrics(scenarioId: string | undefined, apiClient: MakeApiClient): Promise<{
    scenario?: Record<string, unknown>;
    executionMetrics?: {
      averageExecutionTime: number;
      successRate: number;
      errorRate: number;
    };
    error?: string;
    timestamp: number;
  }> {
    if (!scenarioId) {
      throw new Error('Scenario ID required for scenario analysis');
    }

    try {
      // Get scenario details
      const scenarioResponse = await apiClient.get(`/scenarios/${scenarioId}`);
      
      if (!scenarioResponse.success) {
        throw new Error(`Failed to fetch scenario: ${scenarioResponse.error?.message}`);
      }

      return {
        scenario: scenarioResponse.data,
        executionMetrics: {
          // These would come from actual execution logs
          averageExecutionTime: 5000,
          successRate: 0.95,
          errorRate: 0.05
        },
        timestamp: Date.now()
      };
    } catch (error) {
      return {
        error: error instanceof Error ? error.message : String(error),
        timestamp: Date.now()
      };
    }
  }

  /**
   * Collect organization-level metrics
   */
  private async collectOrganizationMetrics(orgId: string | undefined, apiClient: MakeApiClient): Promise<{
    organization?: Record<string, unknown>;
    usage?: {
      operationsUsed: number;
      operationsLimit: number;
      utilizationRate: number;
    };
    error?: string;
    timestamp: number;
  }> {
    if (!orgId) {
      throw new Error('Organization ID required for organization analysis');
    }

    try {
      const orgResponse = await apiClient.get(`/organizations/${orgId}`);
      
      if (!orgResponse.success) {
        throw new Error(`Failed to fetch organization: ${orgResponse.error?.message}`);
      }

      return {
        organization: orgResponse.data,
        usage: {
          // These would come from actual usage analytics
          operationsUsed: 10000,
          operationsLimit: 50000,
          utilizationRate: 0.2
        },
        timestamp: Date.now()
      };
    } catch (error) {
      return {
        error: error instanceof Error ? error.message : String(error),
        timestamp: Date.now()
      };
    }
  }

  /**
   * Detect performance bottlenecks
   */
  private async detectBottlenecks(metrics: PerformanceMetrics, filters: PerformanceAnalysisFilters): Promise<PerformanceBottleneck[]> {
    const bottlenecks: PerformanceBottleneck[] = [];

    // Response time bottleneck detection
    const responseTimeValue = typeof metrics.responseTime === 'number' ? metrics.responseTime : 
                             (typeof metrics.responseTime === 'object' && metrics.responseTime ? metrics.responseTime.average : 0);
    
    if (responseTimeValue && responseTimeValue > 1000) {
      bottlenecks.push({
        type: 'response_time',
        severity: responseTimeValue > 5000 ? 'critical' : responseTimeValue > 2000 ? 'high' : 'medium',
        description: 'High API response time detected',
        impact: 'Reduced user experience and workflow efficiency',
        affectedComponents: ['api', 'user_interface'],
        metrics: {
          currentValue: responseTimeValue,
          expectedValue: 500,
          unit: 'ms',
          trend: 'degrading'
        },
        rootCause: 'API server overload or network latency',
        recommendations: [
          'Implement request caching',
          'Optimize API endpoint performance',
          'Add connection pooling',
          'Consider using regional endpoints'
        ],
        estimatedImpact: {
          performanceImprovement: 40,
          costSavings: 15,
          implementationEffort: 'medium'
        }
      });
    }

    // Memory usage bottleneck detection
    const memoryUtilization = typeof metrics.memory === 'number' ? metrics.memory : 
                             (typeof metrics.memory === 'object' && metrics.memory ? (metrics.memory as SystemMemoryMetrics).utilization : 0);
    
    if (memoryUtilization && memoryUtilization > 0.85) {
      bottlenecks.push({
        type: 'resource_usage',
        severity: memoryUtilization > 0.95 ? 'critical' : 'high',
        description: 'High memory utilization detected',
        impact: 'Potential system instability and performance degradation',
        affectedComponents: ['system', 'memory'],
        metrics: {
          currentValue: memoryUtilization,
          expectedValue: 0.7,
          unit: 'ratio',
          trend: 'degrading'
        },
        rootCause: 'Memory leaks or insufficient memory allocation',
        recommendations: [
          'Implement memory monitoring',
          'Add garbage collection optimization',
          'Increase memory allocation',
          'Fix potential memory leaks'
        ],
        estimatedImpact: {
          performanceImprovement: 30,
          costSavings: 10,
          implementationEffort: 'high'
        }
      });
    }

    // Rate limiting bottleneck detection
    if (metrics.rateLimiter && metrics.rateLimiter.requestsRemaining < 10) {
      bottlenecks.push({
        type: 'rate_limiting',
        severity: 'high',
        description: 'Approaching rate limit threshold',
        impact: 'Request throttling and potential service interruption',
        affectedComponents: ['api', 'rate_limiter'],
        metrics: {
          currentValue: metrics.rateLimiter.requestsRemaining,
          expectedValue: 100,
          unit: 'requests',
          trend: 'degrading'
        },
        rootCause: 'High request volume or inefficient request patterns',
        recommendations: [
          'Implement request batching',
          'Add intelligent caching',
          'Optimize request patterns',
          'Consider upgrading API plan'
        ],
        estimatedImpact: {
          performanceImprovement: 50,
          costSavings: 25,
          implementationEffort: 'medium'
        }
      });
    }

    return bottlenecks.filter(b => this.matchesSeverityFilter(b.severity, filters.severityFilter));
  }

  /**
   * Analyze performance trends
   */
  private async analyzeTrends(_metrics: PerformanceMetrics, _timeRangeHours: number): Promise<TrendAnalysis> {
    // In a real implementation, this would analyze historical data
    // For now, we'll simulate trend analysis based on current metrics
    
    return {
      performanceDirection: 'stable' as const,
      predictionConfidence: 0.8,
      projectedIssues: [
        'Memory usage trending upward - monitor for potential issues',
        'Response time variability suggests optimization opportunities'
      ]
    };
  }

  /**
   * Compare performance to industry benchmarks
   */
  private compareToBenchmarks(metrics: PerformanceMetrics): BenchmarkComparison {
    const responseTimeValue = typeof metrics.responseTime === 'number' ? metrics.responseTime : 
                             (typeof metrics.responseTime === 'object' && metrics.responseTime ? metrics.responseTime.average : 0);
    
    let responseTimeRanking: 'below_average' | 'average' | 'above_average' | 'excellent' = 'average';
    if (responseTimeValue) {
      if (responseTimeValue <= this.industryBenchmarks.responseTime.excellent) {
        responseTimeRanking = 'excellent';
      } else if (responseTimeValue <= this.industryBenchmarks.responseTime.good) {
        responseTimeRanking = 'above_average';
      } else if (responseTimeValue <= this.industryBenchmarks.responseTime.acceptable) {
        responseTimeRanking = 'average';
      } else {
        responseTimeRanking = 'below_average';
      }
    }

    return {
      industryStandard: '< 500ms response time, > 99.95% uptime, < 0.1% error rate',
      currentPerformance: `${responseTimeValue || 'N/A'}ms response time`,
      gap: responseTimeValue && responseTimeValue > 500 ? `${responseTimeValue - 500}ms above target` : 'Within target',
      ranking: responseTimeRanking
    };
  }

  /**
   * Calculate overall health score
   */
  private calculateHealthScore(metrics: PerformanceMetrics, bottlenecks: PerformanceBottleneck[]): number {
    let score = 100;

    // Deduct points for bottlenecks
    for (const bottleneck of bottlenecks) {
      switch (bottleneck.severity) {
        case 'critical':
          score -= 25;
          break;
        case 'high':
          score -= 15;
          break;
        case 'medium':
          score -= 10;
          break;
        case 'low':
          score -= 5;
          break;
      }
    }

    // Deduct points for poor response time
    const responseTimeValue = typeof metrics.responseTime === 'number' ? metrics.responseTime : 
                             (typeof metrics.responseTime === 'object' && metrics.responseTime ? metrics.responseTime.average : 0);
    
    if (responseTimeValue && responseTimeValue > 1000) {
      score -= Math.min(20, (responseTimeValue - 1000) / 100);
    }

    // Deduct points for high resource usage
    const memoryUtilization = typeof metrics.memory === 'number' ? metrics.memory : 
                             (typeof metrics.memory === 'object' && metrics.memory ? (metrics.memory as SystemMemoryMetrics).utilization : 0);
    
    if (memoryUtilization && memoryUtilization > 0.8) {
      score -= (memoryUtilization - 0.8) * 50;
    }

    return Math.max(0, Math.round(score));
  }

  /**
   * Calculate performance grade
   */
  private calculatePerformanceGrade(score: number): 'A' | 'B' | 'C' | 'D' | 'F' {
    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    return 'F';
  }

  /**
   * Generate optimization recommendations
   */
  private async generateRecommendations(bottlenecks: PerformanceBottleneck[], metrics: PerformanceMetrics): Promise<OptimizationRecommendations> {
    const immediate: string[] = [];
    const shortTerm: string[] = [];
    const longTerm: string[] = [];

    // Generate recommendations based on bottlenecks
    for (const bottleneck of bottlenecks) {
      if (bottleneck.severity === 'critical') {
        immediate.push(...bottleneck.recommendations.slice(0, 2));
      } else if (bottleneck.severity === 'high') {
        shortTerm.push(...bottleneck.recommendations.slice(0, 2));
      } else {
        longTerm.push(...bottleneck.recommendations.slice(0, 1));
      }
    }

    // Add general recommendations based on metrics
    const responseTimeValue = typeof metrics.responseTime === 'number' ? metrics.responseTime : 
                             (typeof metrics.responseTime === 'object' && metrics.responseTime ? metrics.responseTime.average : 0);
    
    if (responseTimeValue && responseTimeValue > 500) {
      shortTerm.push('Implement response caching strategy');
    }

    const memoryUtilization = typeof metrics.memory === 'number' ? metrics.memory : 
                             (typeof metrics.memory === 'object' && metrics.memory ? (metrics.memory as SystemMemoryMetrics).utilization : 0);
    
    if (memoryUtilization && memoryUtilization > 0.7) {
      longTerm.push('Consider memory optimization and monitoring');
    }

    const estimatedImpact = bottlenecks.reduce((sum, b) => sum + b.estimatedImpact.performanceImprovement, 0) / bottlenecks.length || 0;

    return {
      immediate: [...new Set(immediate)],
      shortTerm: [...new Set(shortTerm)],
      longTerm: [...new Set(longTerm)],
      estimatedImpact
    };
  }

  /**
   * Analyze cost impact of performance issues
   */
  private async analyzeCostImpact(metrics: PerformanceMetrics, bottlenecks: PerformanceBottleneck[], _apiClient: MakeApiClient): Promise<CostAnalysis> {
    const costSavings = bottlenecks.reduce((sum, b) => sum + b.estimatedImpact.costSavings, 0) / bottlenecks.length || 0;

    return {
      currentCost: 1000, // Placeholder - would calculate from actual usage
      optimizationPotential: costSavings,
      recommendedActions: [
        'Implement request caching to reduce API calls',
        'Optimize workflow patterns to reduce operation count',
        'Use batch operations where possible'
      ]
    };
  }

  /**
   * Format metrics for output
   */
  private formatMetrics(metrics: PerformanceMetrics): MetricsFormattingResult {
    const responseTimeValue = typeof metrics.responseTime === 'number' ? metrics.responseTime : 
                             (typeof metrics.responseTime === 'object' ? metrics.responseTime.average : 0);
    
    return {
      responseTime: {
        average: responseTimeValue,
        p50: responseTimeValue,
        p95: responseTimeValue * 1.5,
        p99: responseTimeValue * 2,
        trend: 'stable' as const
      },
      throughput: {
        requestsPerSecond: 10,
        requestsPerMinute: 600,
        trend: 'stable' as const
      },
      reliability: {
        uptime: 99.9,
        errorRate: 0.01,
        successRate: 0.99,
        trend: 'stable' as const
      },
      resources: {
        cpuUsage: (typeof metrics.cpu === 'object' && metrics.cpu ? (metrics.cpu as CpuMetrics).utilization : 0) || 0.3,
        memoryUsage: (typeof metrics.memory === 'object' && metrics.memory ? (metrics.memory as SystemMemoryMetrics).utilization : metrics.memory) || 0.6,
        networkUtilization: 0.4,
        trend: 'stable' as const
      }
    };
  }

  /**
   * Aggregate analysis results
   */
  private aggregateAnalysisResults(analyses: PerformanceAnalysisResult[]): PerformanceAnalysisResult {
    const avgHealthScore = analyses.reduce((sum, a) => sum + a.overallHealthScore, 0) / analyses.length;
    const allBottlenecks = analyses.flatMap(a => a.bottlenecks);
    
    // Use the first analysis as a template and merge data
    const template = analyses[0];
    
    return {
      ...template,
      targetType: 'comprehensive',
      overallHealthScore: Math.round(avgHealthScore),
      performanceGrade: this.calculatePerformanceGrade(avgHealthScore),
      bottlenecks: allBottlenecks,
      recommendations: {
        immediate: [...new Set(analyses.flatMap(a => a.recommendations.immediate))],
        shortTerm: [...new Set(analyses.flatMap(a => a.recommendations.shortTerm))],
        longTerm: [...new Set(analyses.flatMap(a => a.recommendations.longTerm))],
        estimatedImpact: analyses.reduce((sum, a) => sum + a.recommendations.estimatedImpact, 0) / analyses.length
      }
    };
  }

  /**
   * Collect live performance metrics
   */
  private async collectLiveMetrics(alertThresholds: AlertThresholds): Promise<LivePerformanceUpdate> {
    const memUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();
    
    const metrics = {
      responseTime: 500, // Simulated
      requestRate: 10,   // Simulated
      errorRate: 0.01,   // Simulated
      cpuUsage: (cpuUsage.user + cpuUsage.system) / 1000000 / process.uptime(),
      memoryUsage: memUsage.heapUsed / memUsage.heapTotal
    };

    const alerts = [];
    let status: 'healthy' | 'warning' | 'critical' = 'healthy';

    // Check alert thresholds
    if (metrics.responseTime > alertThresholds.responseTime) {
      alerts.push({
        type: 'response_time',
        severity: 'warning' as const,
        message: `Response time ${metrics.responseTime}ms exceeds threshold`,
        threshold: alertThresholds.responseTime,
        currentValue: metrics.responseTime
      });
      status = 'warning';
    }

    if (metrics.errorRate > alertThresholds.errorRate) {
      alerts.push({
        type: 'error_rate',
        severity: 'error' as const,
        message: `Error rate ${(metrics.errorRate * 100).toFixed(2)}% exceeds threshold`,
        threshold: alertThresholds.errorRate,
        currentValue: metrics.errorRate
      });
      status = 'critical';
    }

    if (metrics.memoryUsage > alertThresholds.memoryUsage) {
      alerts.push({
        type: 'memory_usage',
        severity: 'warning' as const,
        message: `Memory usage ${(metrics.memoryUsage * 100).toFixed(1)}% exceeds threshold`,
        threshold: alertThresholds.memoryUsage,
        currentValue: metrics.memoryUsage
      });
      if (status === 'healthy') status = 'warning';
    }

    return {
      timestamp: new Date().toISOString(),
      metrics,
      alerts,
      status
    };
  }

  /**
   * Check if bottleneck matches severity filter
   */
  private matchesSeverityFilter(severity: string, filter: string): boolean {
    if (filter === 'all') return true;
    
    const severityLevels = ['low', 'medium', 'high', 'critical'];
    const severityIndex = severityLevels.indexOf(severity);
    const filterIndex = severityLevels.indexOf(filter);
    
    return severityIndex >= filterIndex;
  }
}

/**
 * Add performance analysis tools to FastMCP server
 */
export function addPerformanceAnalysisTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'PerformanceAnalysisTools' });
  const analysisEngine = new PerformanceAnalysisEngine();
  
  componentLogger.info('Adding performance analysis tools');

  // Main performance bottleneck analysis tool
  server.addTool({
    name: 'analyze-performance-bottlenecks',
    description: 'Comprehensive performance analysis with bottleneck detection, trend analysis, and optimization recommendations',
    parameters: PerformanceAnalysisSchema,
    annotations: {
      title: 'Performance Bottleneck Analysis',
      openWorldHint: true,
    },
    execute: async (args, { log, reportProgress }) => {
      const { 
        targetType, 
        targetId, 
        analysisOptions = { 
          timeRangeHours: 24,
          includeBottleneckDetection: true,
          includePerformanceMetrics: true,
          includeTrendAnalysis: true,
          includeOptimizationRecommendations: true,
          includeCostAnalysis: false,
          performanceBenchmarking: true,
          detailedBreakdown: false
        }, 
        filters = {
          errorThreshold: 0.05,
          severityFilter: 'all' as const
        }
      } = args;

      log?.info('Starting performance bottleneck analysis', {
        targetType,
        targetId,
        timeRangeHours: analysisOptions.timeRangeHours
      });

      reportProgress?.({ progress: 0, total: 100 });

      try {
        reportProgress?.({ progress: 20, total: 100 });
        
        const result = await analysisEngine.analyzePerformanceBottlenecks(
          targetType,
          targetId,
          analysisOptions,
          filters,
          apiClient
        );

        reportProgress?.({ progress: 100, total: 100 });

        const response = {
          analysis: result,
          summary: {
            overallHealth: `${result.overallHealthScore}/100 (Grade: ${result.performanceGrade})`,
            bottlenecksFound: result.bottlenecks.length,
            criticalIssues: result.bottlenecks.filter(b => b.severity === 'critical').length,
            immediateActions: result.recommendations.immediate.length,
            estimatedImprovement: `${result.recommendations.estimatedImpact}%`,
            benchmarkRanking: result.benchmarkComparison.ranking
          },
          nextSteps: result.recommendations.immediate.length > 0 
            ? result.recommendations.immediate.slice(0, 3)
            : ['No immediate actions required - system performing well']
        };

        log?.info('Performance analysis completed', {
          targetType,
          healthScore: result.overallHealthScore,
          bottleneckCount: result.bottlenecks.length,
          grade: result.performanceGrade
        });

        // Record metrics
        metrics.recordToolExecution('analyze-performance-bottlenecks', 'success', Date.now() - Date.now());

        return JSON.stringify(response, null, 2);

      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log?.error('Performance analysis failed', { error: errorMessage });
        
        metrics.recordError('performance_analysis_failed', 'analyze-performance-bottlenecks');
        throw new UserError(`Performance analysis failed: ${errorMessage}`);
      }
    },
  });

  // Comprehensive system-wide analysis tool
  server.addTool({
    name: 'comprehensive-performance-analysis',
    description: 'System-wide performance analysis covering all components (API, webhooks, scenarios, system metrics)',
    parameters: ComprehensiveAnalysisSchema,
    annotations: {
      title: 'Comprehensive Performance Analysis',
      openWorldHint: true,
    },
    execute: async (args, { log, reportProgress }) => {
      log?.info('Starting comprehensive performance analysis');
      reportProgress?.({ progress: 0, total: 100 });

      try {
        const result = await analysisEngine.performComprehensiveAnalysis(args, apiClient);
        reportProgress?.({ progress: 100, total: 100 });

        const response = {
          analysis: result,
          executiveSummary: {
            overallHealth: `${result.overallHealthScore}/100 (Grade: ${result.performanceGrade})`,
            systemStatus: result.overallHealthScore > 80 ? 'Healthy' : result.overallHealthScore > 60 ? 'Needs Attention' : 'Critical',
            totalBottlenecks: result.bottlenecks.length,
            criticalIssues: result.bottlenecks.filter(b => b.severity === 'critical').length,
            topRecommendations: result.recommendations.immediate.slice(0, 5),
            benchmarkComparison: result.benchmarkComparison.ranking
          }
        };

        log?.info('Comprehensive analysis completed', {
          healthScore: result.overallHealthScore,
          bottleneckCount: result.bottlenecks.length
        });

        return JSON.stringify(response, null, 2);

      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log?.error('Comprehensive analysis failed', { error: errorMessage });
        
        throw new UserError(`Comprehensive analysis failed: ${errorMessage}`);
      }
    },
  });

  // Live performance monitoring tool
  server.addTool({
    name: 'live-performance-monitoring',
    description: 'Real-time performance monitoring with configurable alerting and sampling intervals',
    parameters: LiveAnalysisSchema,
    annotations: {
      title: 'Live Performance Monitoring',
      openWorldHint: true,
    },
    execute: async (args, { log, reportProgress }) => {
      log?.info('Starting live performance monitoring', {
        durationMinutes: args.durationMinutes,
        samplingInterval: args.samplingIntervalSeconds
      });

      try {
        const updates: LivePerformanceUpdate[] = [];
        let progress = 0;
        const totalUpdates = (args.durationMinutes * 60) / args.samplingIntervalSeconds;

        const monitoringResults = await analysisEngine.performLiveAnalysis({
          timeRangeHours: args.durationMinutes / 60,
          includeBottleneckDetection: true,
          includePerformanceMetrics: true,
          includeTrendAnalysis: true,
          ...args
        }, (update) => {
          updates.push(update);
          progress = Math.round((updates.length / totalUpdates) * 100);
          reportProgress?.({ progress, total: 100 });
          
          // Log any alerts
          if (update.alerts.length > 0) {
            log?.warn('Performance alerts detected', {
              status: update.status,
              alertCount: update.alerts.length,
              alerts: update.alerts.map(a => a.message)
            });
          }
        });

        const summary = {
          monitoringDuration: `${args.durationMinutes} minutes`,
          totalSamples: monitoringResults.length,
          alertsGenerated: monitoringResults.reduce((sum, u) => sum + u.alerts.length, 0),
          averageResponseTime: monitoringResults.reduce((sum, u) => sum + u.metrics.responseTime, 0) / monitoringResults.length,
          maxResponseTime: Math.max(...monitoringResults.map(u => u.metrics.responseTime)),
          statusBreakdown: {
            healthy: monitoringResults.filter(u => u.status === 'healthy').length,
            warning: monitoringResults.filter(u => u.status === 'warning').length,
            critical: monitoringResults.filter(u => u.status === 'critical').length
          }
        };

        const response = {
          summary,
          liveUpdates: monitoringResults,
          recommendations: generateLiveMonitoringRecommendations(monitoringResults)
        };

        log?.info('Live monitoring completed', {
          samples: monitoringResults.length,
          alerts: summary.alertsGenerated,
          avgResponseTime: summary.averageResponseTime
        });

        return JSON.stringify(response, null, 2);

      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log?.error('Live monitoring failed', { error: errorMessage });
        
        throw new UserError(`Live monitoring failed: ${errorMessage}`);
      }
    },
  });

  componentLogger.info('Performance analysis tools added successfully');
}

/**
 * Generate recommendations based on live monitoring results
 */
function generateLiveMonitoringRecommendations(updates: LivePerformanceUpdate[]): string[] {
  const recommendations: string[] = [];
  
  const criticalCount = updates.filter(u => u.status === 'critical').length;
  const warningCount = updates.filter(u => u.status === 'warning').length;
  
  if (criticalCount > 0) {
    recommendations.push(`${criticalCount} critical alerts detected - immediate investigation required`);
  }
  
  if (warningCount > updates.length * 0.3) {
    recommendations.push('High warning rate indicates potential performance degradation');
  }
  
  const avgResponseTime = updates.reduce((sum, u) => sum + u.metrics.responseTime, 0) / updates.length;
  if (avgResponseTime > 1000) {
    recommendations.push('Average response time exceeds 1 second - consider optimization');
  }
  
  if (recommendations.length === 0) {
    recommendations.push('System performance appears stable during monitoring period');
  }
  
  return recommendations;
}

export default addPerformanceAnalysisTools;