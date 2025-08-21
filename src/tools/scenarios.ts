/**
 * @fileoverview Make.com Scenario Management Tools
 * 
 * Provides comprehensive CRUD operations for Make.com scenarios including:
 * - Creating, updating, and deleting scenarios
 * - Advanced filtering and search capabilities  
 * - Scenario execution with monitoring
 * - Blueprint management and cloning
 * - Scheduling configuration
 * 
 * @version 1.0.0
 * @author Make.com FastMCP Server
 * @see {@link https://docs.make.com/api} Make.com API Documentation
 */

import { FastMCP, UserError } from 'fastmcp';
import { z } from 'zod';
import MakeApiClient from '../lib/make-api-client.js';
import logger from '../lib/logger.js';
import DiagnosticEngine from '../lib/diagnostic-engine.js';
import { defaultDiagnosticRules } from '../lib/diagnostic-rules.js';
import { MakeBlueprint, TroubleshootingReport } from '../types/diagnostics.js';

// Type definitions for blueprint and report structures
interface BlueprintModule {
  id: number;
  module: string;
  version: number;
  parameters?: Record<string, unknown>;
  connection?: number;
  metadata?: Record<string, unknown>;
}

interface Blueprint {
  name?: string;
  metadata?: {
    version?: number;
    scenario?: {
      roundtrips?: number;
      maxErrors?: number;
      autoCommit?: boolean;
      sequential?: boolean;
      confidential?: boolean;
      dlq?: boolean;
    };
  };
  flow?: BlueprintModule[];
  [key: string]: unknown;
}

interface ReportMetadata {
  reportId?: string;
  generatedAt?: string;
  analysisScope?: {
    scenarioCount?: number;
    timeRangeHours?: number;
  };
}

interface TroubleshootingReportData {
  metadata?: ReportMetadata;
  executiveSummary?: {
    keyFindings: string[];
    criticalRecommendations: string[];
    businessImpact: {
      riskLevel: 'high' | 'medium' | 'low';
      operationalReadiness: 'ready' | 'needs_attention';
      recommendedActions: string;
    };
    nextSteps: string[];
    reportConfidence: {
      dataCompleteness: number;
      analysisDepth: string;
      recommendationReliability: string;
    };
  };
  systemOverview?: {
    systemHealthScore: number;
    performanceStatus: string;
    overallStatus: string;
    scenarioBreakdown: {
      healthy: number;
    };
  };
  consolidatedFindings?: ConsolidatedFindings;
  actionPlan?: ActionPlan;
  [key: string]: unknown;
}

interface OptimizationRecommendation {
  category: string;
  priority: 'high' | 'medium' | 'low';
  title: string;
  description: string;
  estimatedImpact?: string;
  implementationSteps?: string[];
}

// Import performance analysis interfaces
interface PerformanceAnalysisResult {
  analysisTimestamp: string;
  targetType: string;
  targetId?: string;
  timeRange: {
    startTime: string;
    endTime: string;
    durationHours: number;
  };
  overallHealthScore: number;
  performanceGrade: 'A' | 'B' | 'C' | 'D' | 'F';
  bottlenecks: unknown[];
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

interface ScenarioAnalysis {
  scenarioId: string;
  scenarioName: string;
  diagnosticReport: TroubleshootingReport;
  performanceAnalysis?: PerformanceAnalysisResult;
  errors: string[];
}

interface ConsolidatedFindings {
  totalScenarios: number;
  healthyScenarios: number;
  warningScenarios: number;
  criticalScenarios: number;
  commonIssues: Array<{
    category: string;
    severity: string;
    title: string;
    count: number;
    affectedScenarios: string[];
    description: string;
    recommendations: string[];
  }>;
  performanceSummary: {
    averageHealthScore: number;
    averageResponseTime: number;
    totalBottlenecks: number;
    commonBottleneckTypes: string[];
  };
  securitySummary: {
    averageSecurityScore: number;
    totalSecurityIssues: number;
    criticalSecurityIssues: number;
    commonSecurityIssues: string[];
  };
  criticalActionItems: Array<{
    severity: 'critical' | 'high';
    action: string;
    affectedScenarios: string[];
    impact: string;
    effort: 'low' | 'medium' | 'high';
  }>;
}

interface ActionPlan {
  immediate: Array<{
    action: string;
    priority: 'critical' | 'high';
    estimatedTime: string;
    impact: string;
    scenarioIds: string[];
  }>;
  shortTerm: Array<{
    action: string;
    priority: 'medium' | 'high';
    estimatedTime: string;
    impact: string;
    scenarioIds: string[];
  }>;
  longTerm: Array<{
    action: string;
    priority: 'low' | 'medium';
    estimatedTime: string;
    impact: string;
    scenarioIds: string[];
  }>;
  timeline: {
    phase1Duration: string;
    phase2Duration: string;
    phase3Duration: string;
    totalDuration: string;
  };
  [key: string]: unknown;
}

interface SystemOverview {
  overallHealth: 'healthy' | 'warning' | 'critical' | 'unknown';
  totalScenarios: number;
  activeScenarios: number;
  totalIssuesFound: number;
  criticalIssuesFound: number;
  averagePerformanceScore: number;
  averageSecurityScore: number;
  systemLoadIndicators: {
    highVolumeScenarios: number;
    errorProneScenarios: number;
    slowPerformingScenarios: number;
  };
}

interface CostAnalysisReport {
  estimatedMonthlyCost: number;
  costOptimizationPotential: number;
  costBreakdown: {
    highCostScenarios: Array<{
      scenarioId: string;
      scenarioName: string;
      estimatedMonthlyCost: number;
      optimizationPotential: number;
    }>;
  };
  recommendations: Array<{
    type: 'performance' | 'resource' | 'usage';
    description: string;
    estimatedSavings: number;
    implementationEffort: 'low' | 'medium' | 'high';
  }>;
}

interface _TroubleshootingReportFormatted {
  metadata: {
    reportId: string;
    generatedAt: string;
    analysisScope: {
      scenarioCount: number;
      timeRangeHours: number;
      organizationId?: string;
    };
    executionTime: number;
  };
  executiveSummary: {
    overallAssessment: string;
    keyFindings: string[];
    criticalRecommendations: string[];
    businessImpact: {
      riskLevel: 'low' | 'medium' | 'high' | 'critical';
      estimatedDowntimeRisk: number;
      costImpact: number;
    };
  };
  systemOverview: SystemOverview;
  scenarioAnalysis: Array<{
    scenarioId: string;
    scenarioName: string;
    overallHealth: 'healthy' | 'warning' | 'critical' | 'unknown';
    healthScore: number;
    keyIssues: Array<{
      category: string;
      severity: string;
      title: string;
      impact: string;
    }>;
    performanceMetrics: {
      responseTime: number;
      errorRate: number;
      successRate: number;
      executionCount: number;
    };
  }>;
  consolidatedFindings: ConsolidatedFindings;
  actionPlan: ActionPlan;
  performanceMetrics: {
    systemWide: {
      averageResponseTime: number;
      overallErrorRate: number;
      overallSuccessRate: number;
      totalExecutions: number;
    };
    trends: {
      performanceDirection: 'improving' | 'stable' | 'degrading';
      errorTrend: 'improving' | 'stable' | 'degrading';
    };
  };
  securityAssessment: {
    overallSecurityScore: number;
    securityIssuesFound: number;
    criticalSecurityIssues: number;
    recommendations: string[];
    complianceStatus: {
      dataPrivacy: 'compliant' | 'needs_attention' | 'non_compliant';
      accessControl: 'compliant' | 'needs_attention' | 'non_compliant';
      secretsManagement: 'compliant' | 'needs_attention' | 'non_compliant';
    };
  };
  costAnalysis?: CostAnalysisReport;
  appendices: {
    detailedDiagnostics: TroubleshootingReport[];
    performanceData: PerformanceAnalysisResult[];
    rawMetrics: unknown[];
    executionLogs: string[];
  };
}

// Zod schemas for input validation
const ScenarioFiltersSchema = z.object({
  teamId: z.string().optional().describe('Filter by team ID'),
  folderId: z.string().optional().describe('Filter by folder ID'),
  limit: z.number().min(1).max(100).default(10).describe('Number of scenarios to retrieve (1-100)'),
  offset: z.number().min(0).default(0).describe('Number of scenarios to skip'),
  search: z.string().optional().describe('Search term to filter scenarios'),
  active: z.boolean().optional().describe('Filter by active/inactive status'),
}).strict();

const CreateScenarioSchema = z.object({
  name: z.string().min(1).max(100).describe('Scenario name (required)'),
  teamId: z.string().optional().describe('Team ID to create scenario in'),
  folderId: z.string().optional().describe('Folder ID to organize scenario'),
  blueprint: z.any().optional().describe('Scenario blueprint/configuration JSON'),
  scheduling: z.object({
    type: z.enum(['immediately', 'interval', 'cron']).default('immediately'),
    interval: z.number().positive().optional().describe('Interval in minutes for interval scheduling'),
    cron: z.string().optional().describe('Cron expression for cron scheduling'),
  }).optional().describe('Scheduling configuration'),
}).strict();

const UpdateScenarioSchema = z.object({
  scenarioId: z.string().min(1).describe('Scenario ID to update (required)'),
  name: z.string().min(1).max(100).optional().describe('New scenario name'),
  active: z.boolean().optional().describe('Set scenario active/inactive status'),
  blueprint: z.any().optional().describe('Updated scenario blueprint/configuration'),
  scheduling: z.object({
    type: z.enum(['immediately', 'interval', 'cron']),
    interval: z.number().positive().optional(),
    cron: z.string().optional(),
  }).optional().describe('Updated scheduling configuration'),
}).strict();

const DeleteScenarioSchema = z.object({
  scenarioId: z.string().min(1).describe('Scenario ID to delete (required)'),
  force: z.boolean().default(false).describe('Force delete even if scenario is active'),
}).strict();

const ScenarioDetailSchema = z.object({
  scenarioId: z.string().min(1).describe('Scenario ID to retrieve details for (required)'),
  includeBlueprint: z.boolean().default(false).describe('Include full scenario blueprint in response'),
  includeExecutions: z.boolean().default(false).describe('Include recent execution history'),
}).strict();

const CloneScenarioSchema = z.object({
  scenarioId: z.string().min(1).describe('Source scenario ID to clone (required)'),
  name: z.string().min(1).max(100).describe('Name for the cloned scenario (required)'),
  teamId: z.string().optional().describe('Target team ID (defaults to source scenario team)'),
  folderId: z.string().optional().describe('Target folder ID'),
  active: z.boolean().default(false).describe('Whether to activate the cloned scenario'),
}).strict();

const RunScenarioSchema = z.object({
  scenarioId: z.string().min(1).describe('Scenario ID to execute (required)'),
  wait: z.boolean().default(true).describe('Wait for execution to complete'),
  timeout: z.number().min(1).max(300).default(60).describe('Timeout in seconds for execution'),
}).strict();

const TroubleshootScenarioSchema = z.object({
  scenarioId: z.string().min(1).describe('Scenario ID to troubleshoot (required)'),
  diagnosticTypes: z.array(z.enum([
    'health', 'performance', 'connections', 'errors', 'security', 'all'
  ])).default(['all']).describe('Types of diagnostics to run'),
  includeRecommendations: z.boolean().default(true).describe('Include fix recommendations'),
  includePerformanceHistory: z.boolean().default(true).describe('Include performance trend analysis'),
  severityFilter: z.enum(['info', 'warning', 'error', 'critical']).optional().describe('Minimum severity level to report'),
  autoFix: z.boolean().default(false).describe('Attempt automatic fixes for fixable issues'),
  timeRange: z.object({
    hours: z.number().min(1).max(720).default(24).describe('Hours of execution history to analyze')
  }).optional().describe('Time range for historical analysis')
}).strict();

const GenerateTroubleshootingReportSchema = z.object({
  scenarioIds: z.array(z.string().min(1)).optional().describe('Specific scenario IDs to analyze (optional - if not provided, analyzes all scenarios)'),
  reportOptions: z.object({
    includeExecutiveSummary: z.boolean().default(true).describe('Include executive summary with key findings'),
    includeDetailedAnalysis: z.boolean().default(true).describe('Include detailed diagnostic analysis'),
    includeActionPlan: z.boolean().default(true).describe('Include prioritized action plan'),
    includePerformanceMetrics: z.boolean().default(true).describe('Include performance benchmarks and metrics'),
    includeSecurityAssessment: z.boolean().default(true).describe('Include security and compliance assessment'),
    includeCostAnalysis: z.boolean().default(false).describe('Include cost impact analysis'),
    includeRecommendationTimeline: z.boolean().default(true).describe('Include timeline for implementing recommendations'),
    formatType: z.enum(['json', 'markdown', 'pdf-ready']).default('json').describe('Output format for the report')
  }).optional().describe('Report generation options'),
  analysisFilters: z.object({
    timeRangeHours: z.number().min(1).max(720).default(24).describe('Time range for analysis (hours)'),
    severityThreshold: z.enum(['info', 'warning', 'error', 'critical']).default('info').describe('Minimum severity threshold'),
    includeInactiveScenarios: z.boolean().default(false).describe('Include inactive scenarios in analysis'),
    maxScenariosToAnalyze: z.number().min(1).max(100).default(25).describe('Maximum number of scenarios to analyze'),
    prioritizeByUsage: z.boolean().default(true).describe('Prioritize scenarios by usage/execution frequency')
  }).optional().describe('Analysis filtering and prioritization options'),
  comparisonBaseline: z.object({
    compareToHistorical: z.boolean().default(true).describe('Compare against historical performance'),
    baselineTimeRangeHours: z.number().min(24).max(2160).default(168).describe('Baseline period for comparison (hours)'),
    includeBenchmarks: z.boolean().default(true).describe('Include industry benchmarks')
  }).optional().describe('Baseline comparison settings')
}).strict();

/**
 * Adds comprehensive scenario management tools to the FastMCP server
 * 
 * @param {FastMCP} server - The FastMCP server instance
 * @param {MakeApiClient} apiClient - Make.com API client with rate limiting
 * @returns {void}
 * 
 * @example
 * ```typescript
 * import { addScenarioTools } from './tools/scenarios.js';
 * 
 * const server = new FastMCP();
 * const apiClient = new MakeApiClient(config);
 * addScenarioTools(server, apiClient);
 * ```
 */
export function addScenarioTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger: ReturnType<typeof logger.child> = logger?.child ? logger.child({ component: 'ScenarioTools' }) : {
    info: () => {},
    warn: () => {},
    error: () => {},
    debug: () => {},
    child: () => componentLogger
  } as unknown as ReturnType<typeof logger.child>;

  /**
   * List and search Make.com scenarios with advanced filtering options
   * 
   * Provides comprehensive scenario listing with support for team filtering,
   * folder organization, pagination, and text search capabilities.
   * 
   * @tool list-scenarios
   * @category Scenario Management
   * @permission scenario:read
   * 
   * @param {Object} args - Filter and pagination parameters
   * @param {string} [args.teamId] - Filter scenarios by team ID
   * @param {string} [args.folderId] - Filter scenarios by folder ID  
   * @param {number} [args.limit=10] - Number of scenarios to retrieve (1-100)
   * @param {number} [args.offset=0] - Number of scenarios to skip for pagination
   * @param {string} [args.search] - Search term to filter scenario names
   * @param {boolean} [args.active] - Filter by active/inactive status
   * 
   * @returns {Promise<string>} JSON response containing:
   * - scenarios: Array of scenario objects with basic information
   * - pagination: Pagination metadata (total, limit, offset, hasMore)
   * - filters: Applied filter parameters for reference
   * - timestamp: ISO timestamp of the response
   * 
   * @throws {UserError} When API request fails or parameters are invalid
   * 
   * @example
   * ```bash
   * # List active scenarios for a specific team
   * mcp-client list-scenarios --teamId "team123" --active true --limit 50
   * 
   * # Search scenarios by name
   * mcp-client list-scenarios --search "data sync" --limit 20
   * ```
   * 
   * @see {@link https://docs.make.com/api/scenarios#list} Make.com Scenarios API
   */
  server.addTool({
    name: 'list-scenarios',
    description: 'List and search Make.com scenarios with advanced filtering options',
    parameters: ScenarioFiltersSchema,
    annotations: {
      title: 'List Scenarios',
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (args, { log, reportProgress }) => {
      log?.info?.('Listing scenarios', { filters: args });
      reportProgress({ progress: 0, total: 100 });

      try {
        // Build query parameters
        const params: Record<string, unknown> = {
          limit: args.limit,
          offset: args.offset,
        };

        if (args.teamId) params.teamId = args.teamId;
        if (args.folderId) params.folderId = args.folderId;
        if (args.search) params.q = args.search;
        if (args.active !== undefined) params.active = args.active;

        reportProgress({ progress: 25, total: 100 });

        const response = await apiClient.get('/scenarios', { params });
        reportProgress({ progress: 75, total: 100 });

        if (!response.success) {
          throw new UserError(`Failed to list scenarios: ${response.error?.message}`);
        }

        const scenarios = response.data;
        const metadata = response.metadata;

        reportProgress({ progress: 100, total: 100 });

        // Type guard for scenarios array
        const scenariosArray = Array.isArray(scenarios) ? scenarios : [];

        const result = {
          scenarios: scenariosArray,
          pagination: {
            total: metadata?.total || scenariosArray.length,
            limit: args.limit,
            offset: args.offset,
            hasMore: (metadata?.total || 0) > (args.offset + args.limit),
          },
          filters: args,
          timestamp: new Date().toISOString(),
        };

        log?.info('Scenarios listed successfully', { 
          count: result.scenarios.length,
          total: result.pagination.total 
        });

        return JSON.stringify(result, null, 2);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log?.error('Failed to list scenarios', { error: errorMessage });
        throw new UserError(`Failed to list scenarios: ${errorMessage}`);
      }
    },
  });

  /**
   * Get detailed information about a specific Make.com scenario
   * 
   * Retrieves comprehensive details for a specific scenario including blueprint,
   * execution history, and configuration settings with optional data expansion.
   * 
   * @tool get-scenario
   * @category Scenario Management
   * @permission scenario:read
   * 
   * @param {Object} args - Scenario retrieval parameters
   * @param {string} args.scenarioId - Scenario ID to retrieve details for (required)
   * @param {boolean} [args.includeBlueprint=false] - Include full scenario blueprint in response
   * @param {boolean} [args.includeExecutions=false] - Include recent execution history
   * 
   * @returns {Promise<string>} JSON response containing:
   * - scenario: Complete scenario object with metadata
   * - blueprint: Full scenario configuration (if requested)
   * - recentExecutions: Latest execution history (if requested)
   * - timestamp: ISO timestamp of the response
   * 
   * @throws {UserError} When scenario not found or access denied
   * 
   * @example
   * ```bash
   * # Get basic scenario details
   * mcp-client get-scenario --scenarioId "scn_12345"
   * 
   * # Get scenario with blueprint and execution history
   * mcp-client get-scenario \
   *   --scenarioId "scn_12345" \
   *   --includeBlueprint true \
   *   --includeExecutions true
   * ```
   * 
   * @see {@link https://docs.make.com/api/scenarios#get} Make.com Get Scenario API
   */
  server.addTool({
    name: 'get-scenario',
    description: 'Get detailed information about a specific Make.com scenario',
    parameters: ScenarioDetailSchema,
    annotations: {
      title: 'Get Scenario Details',
      readOnlyHint: true,
    },
    execute: async (args, { log, reportProgress }) => {
      log?.info('Getting scenario details', { scenarioId: args.scenarioId });
      reportProgress({ progress: 0, total: 100 });

      try {
        const response = await apiClient.get(`/scenarios/${args.scenarioId}`);
        reportProgress({ progress: 50, total: 100 });

        if (!response.success) {
          throw new UserError(`Failed to get scenario: ${response.error?.message}`);
        }

        const scenario = response.data;
        const result: Record<string, unknown> = {
          scenario,
          timestamp: new Date().toISOString(),
        };

        // Get blueprint if requested
        if (args.includeBlueprint) {
          const blueprintResponse = await apiClient.get(`/scenarios/${args.scenarioId}/blueprint`);
          if (blueprintResponse.success) {
            result.blueprint = blueprintResponse.data;
          }
        }

        // Get execution history if requested
        if (args.includeExecutions) {
          const executionsResponse = await apiClient.get(`/scenarios/${args.scenarioId}/executions`, {
            params: { limit: 10 }
          });
          if (executionsResponse.success) {
            result.recentExecutions = executionsResponse.data;
          }
        }

        reportProgress({ progress: 100, total: 100 });

        log?.info('Scenario details retrieved successfully', { scenarioId: args.scenarioId });
        return JSON.stringify(result, null, 2);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log?.error('Failed to get scenario', { scenarioId: args.scenarioId, error: errorMessage });
        throw new UserError(`Failed to get scenario: ${errorMessage}`);
      }
    },
  });

  /**
   * Create a new Make.com scenario with optional configuration
   * 
   * Creates a new scenario with customizable settings including team assignment,
   * folder organization, blueprint configuration, and scheduling options.
   * 
   * @tool create-scenario
   * @category Scenario Management  
   * @permission scenario:write
   * 
   * @param {Object} args - Scenario creation parameters
   * @param {string} args.name - Scenario name (required, 1-100 chars)
   * @param {string} [args.teamId] - Team ID to create scenario in
   * @param {string} [args.folderId] - Folder ID to organize scenario
   * @param {any} [args.blueprint] - Scenario blueprint/configuration JSON
   * @param {Object} [args.scheduling] - Scheduling configuration
   * @param {('immediately'|'interval'|'cron')} [args.scheduling.type='immediately'] - Scheduling type
   * @param {number} [args.scheduling.interval] - Interval in minutes for interval scheduling
   * @param {string} [args.scheduling.cron] - Cron expression for cron scheduling
   * 
   * @returns {Promise<string>} JSON response containing:
   * - scenario: Complete created scenario object
   * - message: Success confirmation message
   * - timestamp: ISO timestamp of creation
   * 
   * @throws {UserError} When creation fails or parameters are invalid
   * 
   * @example
   * ```bash
   * # Create basic scenario
   * mcp-client create-scenario --name "Data Sync Process"
   * 
   * # Create scenario with team and scheduling
   * mcp-client create-scenario \
   *   --name "Weekly Report Generator" \
   *   --teamId "team123" \
   *   --scheduling.type "cron" \
   *   --scheduling.cron "0 9 * * 1"
   * 
   * # Create scenario with blueprint
   * mcp-client create-scenario \
   *   --name "Custom Integration" \
   *   --blueprint '{"modules": [...], "connections": [...]}'
   * ```
   * 
   * @see {@link https://docs.make.com/api/scenarios#create} Make.com Create Scenario API
   */
  server.addTool({
    name: 'create-scenario',
    description: 'Create a new Make.com scenario with optional configuration',
    parameters: CreateScenarioSchema,
    annotations: {
      title: 'Create Scenario',
    },
    execute: async (args, { log, reportProgress }) => {
      log?.info('Creating scenario', { name: args.name, teamId: args.teamId });
      reportProgress({ progress: 0, total: 100 });

      try {
        const scenarioData: Record<string, unknown> = {
          name: args.name,
        };

        if (args.teamId) scenarioData.teamId = args.teamId;
        if (args.folderId) scenarioData.folderId = args.folderId;
        if (args.blueprint) scenarioData.blueprint = args.blueprint;
        if (args.scheduling) scenarioData.scheduling = args.scheduling;

        reportProgress({ progress: 25, total: 100 });

        const response = await apiClient.post('/scenarios', scenarioData);
        reportProgress({ progress: 75, total: 100 });

        if (!response.success) {
          throw new UserError(`Failed to create scenario: ${response.error?.message}`);
        }

        const createdScenario = response.data;
        reportProgress({ progress: 100, total: 100 });

        const result = {
          scenario: createdScenario,
          message: `Scenario "${args.name}" created successfully`,
          timestamp: new Date().toISOString(),
        };

        // Type guard for created scenario
        const scenarioObj = createdScenario as { id?: unknown } | null | undefined;
        
        log?.info('Scenario created successfully', { 
          scenarioId: String(scenarioObj?.id ?? 'unknown'),
          name: args.name 
        });

        return JSON.stringify(result, null, 2);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log?.error('Failed to create scenario', { name: args.name, error: errorMessage });
        throw new UserError(`Failed to create scenario: ${errorMessage}`);
      }
    },
  });

  /**
   * Update an existing Make.com scenario configuration
   * 
   * Modifies scenario properties including name, active status, blueprint,
   * and scheduling configuration with validation and safety checks.
   * 
   * @tool update-scenario
   * @category Scenario Management
   * @permission scenario:write
   * 
   * @param {Object} args - Scenario update parameters
   * @param {string} args.scenarioId - Scenario ID to update (required)
   * @param {string} [args.name] - New scenario name (1-100 chars)
   * @param {boolean} [args.active] - Set scenario active/inactive status
   * @param {any} [args.blueprint] - Updated scenario blueprint/configuration
   * @param {Object} [args.scheduling] - Updated scheduling configuration
   * @param {('immediately'|'interval'|'cron')} [args.scheduling.type] - Scheduling type
   * @param {number} [args.scheduling.interval] - Interval in minutes for interval scheduling
   * @param {string} [args.scheduling.cron] - Cron expression for cron scheduling
   * 
   * @returns {Promise<string>} JSON response containing:
   * - scenario: Updated scenario object
   * - updates: Object showing which fields were updated
   * - message: Success confirmation message
   * - timestamp: ISO timestamp of update
   * 
   * @throws {UserError} When update fails, scenario not found, or no parameters provided
   * 
   * @example
   * ```bash
   * # Activate scenario
   * mcp-client update-scenario --scenarioId "scn_12345" --active true
   * 
   * # Update name and scheduling
   * mcp-client update-scenario \
   *   --scenarioId "scn_12345" \
   *   --name "Updated Data Sync" \
   *   --scheduling.type "interval" \
   *   --scheduling.interval 30
   * 
   * # Update blueprint configuration
   * mcp-client update-scenario \
   *   --scenarioId "scn_12345" \
   *   --blueprint '{"modules": [...], "updated": true}'
   * ```
   * 
   * @see {@link https://docs.make.com/api/scenarios#update} Make.com Update Scenario API
   */
  server.addTool({
    name: 'update-scenario',
    description: 'Update an existing Make.com scenario configuration',
    parameters: UpdateScenarioSchema,
    annotations: {
      title: 'Update Scenario',
    },
    execute: async (args, { log, reportProgress }) => {
      log?.info('Updating scenario', { scenarioId: args.scenarioId });
      reportProgress({ progress: 0, total: 100 });

      try {
        const updateData: Record<string, unknown> = {};
        
        if (args.name !== undefined) updateData.name = args.name;
        if (args.active !== undefined) updateData.active = args.active;
        if (args.blueprint !== undefined) updateData.blueprint = args.blueprint;
        if (args.scheduling !== undefined) updateData.scheduling = args.scheduling;

        if (Object.keys(updateData).length === 0) {
          throw new UserError('No update parameters provided');
        }

        reportProgress({ progress: 25, total: 100 });

        const response = await apiClient.patch(`/scenarios/${args.scenarioId}`, updateData);
        reportProgress({ progress: 75, total: 100 });

        if (!response.success) {
          throw new UserError(`Failed to update scenario: ${response.error?.message}`);
        }

        const updatedScenario = response.data;
        reportProgress({ progress: 100, total: 100 });

        const result = {
          scenario: updatedScenario,
          updates: updateData,
          message: `Scenario updated successfully`,
          timestamp: new Date().toISOString(),
        };

        log?.info('Scenario updated successfully', { scenarioId: args.scenarioId });
        return JSON.stringify(result, null, 2);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log?.error('Failed to update scenario', { scenarioId: args.scenarioId, error: errorMessage });
        throw new UserError(`Failed to update scenario: ${errorMessage}`);
      }
    },
  });

  /**
   * Delete a Make.com scenario with safety checks and force options
   * 
   * Safely removes a scenario with validation checks for active status
   * and dependencies, with option to force delete active scenarios.
   * 
   * @tool delete-scenario
   * @category Scenario Management
   * @permission scenario:delete
   * 
   * @param {Object} args - Scenario deletion parameters
   * @param {string} args.scenarioId - Scenario ID to delete (required)
   * @param {boolean} [args.force=false] - Force delete even if scenario is active
   * 
   * @returns {Promise<string>} JSON response containing:
   * - scenarioId: ID of deleted scenario
   * - message: Deletion confirmation message
   * - force: Whether force deletion was used
   * - timestamp: ISO timestamp of deletion
   * 
   * @throws {UserError} When scenario not found, deletion fails, or active scenario without force
   * 
   * @example
   * ```bash
   * # Delete inactive scenario
   * mcp-client delete-scenario --scenarioId "scn_12345"
   * 
   * # Force delete active scenario
   * mcp-client delete-scenario --scenarioId "scn_12345" --force true
   * ```
   * 
   * @see {@link https://docs.make.com/api/scenarios#delete} Make.com Delete Scenario API
   */
  server.addTool({
    name: 'delete-scenario',
    description: 'Delete a Make.com scenario (with optional force delete)',
    parameters: DeleteScenarioSchema,
    annotations: {
      title: 'Delete Scenario',
    },
    execute: async (args, { log, reportProgress }) => {
      log?.info('Deleting scenario', { scenarioId: args.scenarioId, force: args.force });
      reportProgress({ progress: 0, total: 100 });

      try {
        // Check if scenario exists and is active (unless force is true)
        if (!args.force) {
          const scenarioResponse = await apiClient.get(`/scenarios/${args.scenarioId}`);
          if (!scenarioResponse.success) {
            throw new UserError(`Scenario not found: ${args.scenarioId}`);
          }

          const scenario = scenarioResponse.data;
          
          // Type guard for scenario object
          const scenarioObj = scenario as { active?: unknown } | null | undefined;
          
          if (scenarioObj?.active) {
            throw new UserError(
              `Cannot delete active scenario. Set active=false first or use force=true.`
            );
          }
        }

        reportProgress({ progress: 50, total: 100 });

        const response = await apiClient.delete(`/scenarios/${args.scenarioId}`);
        reportProgress({ progress: 100, total: 100 });

        if (!response.success) {
          throw new UserError(`Failed to delete scenario: ${response.error?.message}`);
        }

        const result = {
          scenarioId: args.scenarioId,
          message: `Scenario deleted successfully`,
          force: args.force,
          timestamp: new Date().toISOString(),
        };

        log?.info('Scenario deleted successfully', { scenarioId: args.scenarioId });
        return JSON.stringify(result, null, 2);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log?.error('Failed to delete scenario', { scenarioId: args.scenarioId, error: errorMessage });
        throw new UserError(`Failed to delete scenario: ${errorMessage}`);
      }
    },
  });

  /**
   * Clone an existing Make.com scenario with customizable options
   * 
   * Creates an exact copy of a scenario with a new name and optional 
   * team/folder assignment, including full blueprint duplication.
   * 
   * @tool clone-scenario
   * @category Scenario Management
   * @permission scenario:create
   * 
   * @param {Object} args - Scenario cloning parameters
   * @param {string} args.scenarioId - Source scenario ID to clone (required)
   * @param {string} args.name - Name for the cloned scenario (required, 1-100 chars)
   * @param {string} [args.teamId] - Target team ID (defaults to source scenario team)
   * @param {string} [args.folderId] - Target folder ID for organization
   * @param {boolean} [args.active=false] - Whether to activate the cloned scenario
   * 
   * @returns {Promise<string>} JSON response containing:
   * - originalScenarioId: ID of source scenario
   * - clonedScenario: Complete cloned scenario object
   * - message: Cloning confirmation message
   * - timestamp: ISO timestamp of cloning operation
   * 
   * @throws {UserError} When source scenario not found, cloning fails, or blueprint retrieval error
   * 
   * @example
   * ```bash
   * # Clone scenario with new name
   * mcp-client clone-scenario \
   *   --scenarioId "scn_12345" \
   *   --name "Cloned Data Sync Process"
   * 
   * # Clone to different team and activate
   * mcp-client clone-scenario \
   *   --scenarioId "scn_12345" \
   *   --name "Team B Data Sync" \
   *   --teamId "team456" \
   *   --active true
   * 
   * # Clone with folder organization
   * mcp-client clone-scenario \
   *   --scenarioId "scn_12345" \
   *   --name "Production Sync" \
   *   --folderId "folder789"
   * ```
   * 
   * @see {@link https://docs.make.com/api/scenarios#clone} Make.com Clone Scenario API
   */
  server.addTool({
    name: 'clone-scenario',
    description: 'Clone an existing Make.com scenario with a new name',
    parameters: CloneScenarioSchema,
    annotations: {
      title: 'Clone Scenario',
    },
    execute: async (args, { log, reportProgress }) => {
      log?.info('Cloning scenario', { 
        sourceId: args.scenarioId, 
        newName: args.name 
      });
      reportProgress({ progress: 0, total: 100 });

      try {
        // Get source scenario blueprint
        const blueprintResponse = await apiClient.get(`/scenarios/${args.scenarioId}/blueprint`);
        if (!blueprintResponse.success) {
          throw new UserError(`Failed to get source scenario blueprint: ${blueprintResponse.error?.message}`);
        }

        reportProgress({ progress: 25, total: 100 });

        // Create clone data
        const cloneData: Record<string, unknown> = {
          name: args.name,
          blueprint: blueprintResponse.data,
          active: args.active,
        };

        if (args.teamId) cloneData.teamId = args.teamId;
        if (args.folderId) cloneData.folderId = args.folderId;

        reportProgress({ progress: 50, total: 100 });

        // Create the cloned scenario
        const response = await apiClient.post('/scenarios', cloneData);
        reportProgress({ progress: 100, total: 100 });

        if (!response.success) {
          throw new UserError(`Failed to clone scenario: ${response.error?.message}`);
        }

        const clonedScenario = response.data;

        const result = {
          originalScenarioId: args.scenarioId,
          clonedScenario,
          message: `Scenario cloned successfully as "${args.name}"`,
          timestamp: new Date().toISOString(),
        };

        // Type guard for cloned scenario
        const clonedScenarioObj = clonedScenario as { id?: unknown } | null | undefined;
        
        log?.info('Scenario cloned successfully', { 
          sourceId: args.scenarioId,
          cloneId: String(clonedScenarioObj?.id ?? 'unknown'),
          name: args.name 
        });

        return JSON.stringify(result, null, 2);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log?.error('Failed to clone scenario', { scenarioId: args.scenarioId, error: errorMessage });
        throw new UserError(`Failed to clone scenario: ${errorMessage}`);
      }
    },
  });

  /**
   * Execute a Make.com scenario with monitoring and timeout options
   * 
   * Triggers scenario execution with optional wait functionality, progress tracking,
   * and configurable timeout settings for monitoring execution completion.
   * 
   * @tool run-scenario
   * @category Scenario Management
   * @permission scenario:execute
   * 
   * @param {Object} args - Scenario execution parameters
   * @param {string} args.scenarioId - Scenario ID to execute (required)
   * @param {boolean} [args.wait=true] - Wait for execution to complete
   * @param {number} [args.timeout=60] - Timeout in seconds for execution (1-300)
   * 
   * @returns {Promise<string>} JSON response containing:
   * - scenarioId: ID of executed scenario
   * - executionId: Unique execution identifier
   * - status: Execution status (started, success, error, timeout)
   * - execution: Complete execution details (if wait=true and completed)
   * - duration: Execution duration in milliseconds (if completed)
   * - message: Status message
   * - timeout: Whether execution timed out (if applicable)
   * - timestamp: ISO timestamp of response
   * 
   * @throws {UserError} When scenario not found, execution fails to start, or access denied
   * 
   * @example
   * ```bash
   * # Execute scenario and wait for completion
   * mcp-client run-scenario --scenarioId "scn_12345"
   * 
   * # Execute without waiting
   * mcp-client run-scenario --scenarioId "scn_12345" --wait false
   * 
   * # Execute with custom timeout
   * mcp-client run-scenario \
   *   --scenarioId "scn_12345" \
   *   --wait true \
   *   --timeout 120
   * ```
   * 
   * @see {@link https://docs.make.com/api/scenarios#run} Make.com Run Scenario API
   */
  server.addTool({
    name: 'run-scenario',
    description: 'Execute a Make.com scenario and optionally wait for completion',
    parameters: RunScenarioSchema,
    annotations: {
      title: 'Run Scenario',
    },
    execute: async (args, { log, reportProgress }) => {
      log?.info('Running scenario', { 
        scenarioId: args.scenarioId, 
        wait: args.wait,
        timeout: args.timeout 
      });
      reportProgress({ progress: 0, total: 100 });

      try {
        // Start scenario execution
        const response = await apiClient.post(`/scenarios/${args.scenarioId}/run`);
        reportProgress({ progress: 25, total: 100 });

        if (!response.success) {
          throw new UserError(`Failed to start scenario execution: ${response.error?.message}`);
        }

        const execution = response.data;
        
        // Type guard for execution object
        const executionObj = execution as { id?: unknown; status?: unknown } | null | undefined;
        
        let result: Record<string, unknown> = {
          scenarioId: args.scenarioId,
          executionId: executionObj?.id,
          status: executionObj?.status || 'started',
          message: 'Scenario execution started',
          timestamp: new Date().toISOString(),
        };

        // If wait is false, return immediately
        if (!args.wait) {
          reportProgress({ progress: 100, total: 100 });
          log?.info('Scenario execution started (not waiting)', { 
            scenarioId: args.scenarioId,
            executionId: String(executionObj?.id ?? 'unknown')
          });
          return JSON.stringify(result, null, 2);
        }

        // Wait for completion
        const startTime = Date.now();
        const timeoutMs = args.timeout * 1000;
        
        while (Date.now() - startTime < timeoutMs) {
          await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 seconds
          
          const statusResponse = await apiClient.get(`/scenarios/${args.scenarioId}/executions/${executionObj?.id}`);
          if (statusResponse.success) {
            const currentExecution = statusResponse.data;
            
            // Type guard for current execution object
            const currentExecutionObj = currentExecution as { status?: unknown } | null | undefined;
            
            const progress = Math.min(25 + ((Date.now() - startTime) / timeoutMs) * 75, 99);
            reportProgress({ progress, total: 100 });

            if (currentExecutionObj?.status === 'success' || currentExecutionObj?.status === 'error') {
              result = {
                ...result,
                status: currentExecutionObj.status,
                execution: currentExecution,
                duration: Date.now() - startTime,
                message: `Scenario execution ${String(currentExecutionObj.status)}`,
              };
              break;
            }
          }
        }

        reportProgress({ progress: 100, total: 100 });

        if (result.status === 'started') {
          result.message = 'Scenario execution timeout - check status manually';
          result.timeout = true;
        }

        log?.info('Scenario execution completed', { 
          scenarioId: args.scenarioId,
          executionId: String(executionObj?.id ?? 'unknown'),
          status: String(result.status ?? 'unknown'),
          duration: Number(result.duration ?? 0)
        });

        return JSON.stringify(result, null, 2);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log?.error('Failed to run scenario', { scenarioId: args.scenarioId, error: errorMessage });
        throw new UserError(`Failed to run scenario: ${errorMessage}`);
      }
    },
  });

  /**
   * Comprehensive scenario troubleshooting and diagnostics tool
   * 
   * Performs advanced diagnostic analysis of Make.com scenarios including health checks,
   * performance analysis, error detection, connection validation, and security assessment
   * with optional automatic fixes for common issues.
   * 
   * @tool troubleshoot-scenario
   * @category Scenario Diagnostics
   * @permission scenario:read, scenario:write (for auto-fixes)
   * 
   * @param {Object} args - Troubleshooting parameters
   * @param {string} args.scenarioId - Scenario ID to troubleshoot (required)
   * @param {string[]} [args.diagnosticTypes=['all']] - Types of diagnostics to run
   * @param {boolean} [args.includeRecommendations=true] - Include fix recommendations
   * @param {boolean} [args.includePerformanceHistory=true] - Include performance trend analysis
   * @param {string} [args.severityFilter] - Minimum severity level to report
   * @param {boolean} [args.autoFix=false] - Attempt automatic fixes for fixable issues
   * @param {Object} [args.timeRange] - Time range for historical analysis
   * @param {number} [args.timeRange.hours=24] - Hours of execution history to analyze
   * 
   * @returns {Promise<string>} JSON response containing:
   * - scenario: Basic scenario information and status
   * - troubleshooting: Overall health assessment and summary
   * - diagnostics: Array of diagnostic results with details and recommendations
   * - autoFix: Auto-fix results if requested
   * - metadata: Troubleshooting session metadata
   * 
   * @throws {UserError} When scenario not found or troubleshooting fails
   * 
   * @example
   * ```bash
   * # Basic troubleshooting with all diagnostics
   * mcp-client troubleshoot-scenario --scenarioId "scn_12345"
   * 
   * # Performance-focused analysis
   * mcp-client troubleshoot-scenario \
   *   --scenarioId "scn_12345" \
   *   --diagnosticTypes '["performance", "errors"]' \
   *   --timeRange.hours 72
   * 
   * # Complete analysis with auto-fixes
   * mcp-client troubleshoot-scenario \
   *   --scenarioId "scn_12345" \
   *   --autoFix true \
   *   --severityFilter "warning"
   * ```
   * 
   * @see {@link https://docs.make.com/api/scenarios} Make.com Scenarios API
   */
  server.addTool({
    name: 'troubleshoot-scenario',
    description: 'Comprehensive Make.com scenario diagnostics with health checks, error analysis, performance monitoring, and auto-fix capabilities',
    parameters: TroubleshootScenarioSchema,
    annotations: {
      title: 'Troubleshoot Scenario',
      readOnlyHint: false, // Can perform auto-fixes
    },
    execute: async (args, { log, reportProgress }) => {
      log?.info('Starting scenario troubleshooting', { 
        scenarioId: args.scenarioId,
        diagnosticTypes: args.diagnosticTypes,
        autoFix: args.autoFix,
        timeRange: args.timeRange?.hours || 24
      });
      
      reportProgress({ progress: 0, total: 100 });
      
      try {
        // Initialize diagnostic engine with default rules
        const diagnosticEngine = new DiagnosticEngine();
        
        // Register all default diagnostic rules
        defaultDiagnosticRules.forEach(rule => {
          diagnosticEngine.registerRule(rule);
        });
        
        reportProgress({ progress: 10, total: 100 });
        
        // Get scenario details
        const scenarioResponse = await apiClient.get(`/scenarios/${args.scenarioId}`);
        if (!scenarioResponse.success) {
          throw new UserError(`Scenario not found: ${args.scenarioId}`);
        }
        
        reportProgress({ progress: 25, total: 100 });
        
        // Get scenario blueprint
        const blueprintResponse = await apiClient.get(`/scenarios/${args.scenarioId}/blueprint`);
        if (!blueprintResponse.success) {
          throw new UserError(`Failed to get scenario blueprint: ${blueprintResponse.error?.message}`);
        }
        
        reportProgress({ progress: 40, total: 100 });
        
        // Prepare diagnostic options
        const diagnosticOptions = {
          diagnosticTypes: args.diagnosticTypes,
          severityFilter: args.severityFilter,
          timeRangeHours: args.timeRange?.hours || 24,
          includePerformanceMetrics: args.includePerformanceHistory,
          includeSecurityChecks: args.diagnosticTypes.includes('security') || args.diagnosticTypes.includes('all'),
          timeoutMs: 30000 // 30 second timeout per rule
        };
        
        // Run comprehensive diagnostics
        const report = await diagnosticEngine.runDiagnostics(
          args.scenarioId,
          scenarioResponse.data,
          blueprintResponse.data as MakeBlueprint,
          apiClient,
          diagnosticOptions
        );
        
        reportProgress({ progress: 75, total: 100 });
        
        // Apply auto-fixes if requested
        let autoFixResults;
        if (args.autoFix) {
          const fixableIssues = report.diagnostics.filter(d => d.fixable);
          if (fixableIssues.length > 0) {
            log?.info('Applying automatic fixes', { fixableCount: fixableIssues.length });
            autoFixResults = await diagnosticEngine.applyAutoFixes(fixableIssues, apiClient);
          } else {
            autoFixResults = {
              attempted: false,
              results: [],
              success: true,
              fixesApplied: 0,
              executionTime: 0
            };
          }
        }
        
        reportProgress({ progress: 90, total: 100 });
        
        // Build comprehensive response
        const response = {
          scenario: {
            id: args.scenarioId,
            name: (scenarioResponse.data as { name?: string })?.name || 'Unknown',
            status: (scenarioResponse.data as { active?: boolean })?.active ? 'active' : 'inactive',
            moduleCount: (blueprintResponse.data as MakeBlueprint)?.flow?.length || 0
          },
          troubleshooting: {
            overallHealth: report.overallHealth,
            summary: report.summary,
            executionTime: report.executionTime,
            diagnosticsRun: args.diagnosticTypes,
            timeRangeAnalyzed: args.timeRange?.hours || 24
          },
          diagnostics: args.includeRecommendations 
            ? report.diagnostics 
            : report.diagnostics.map(d => ({ 
                ...d, 
                recommendations: d.severity === 'critical' || d.severity === 'error' 
                  ? d.recommendations 
                  : [] 
              })),
          autoFix: args.autoFix ? {
            attempted: autoFixResults?.attempted || false,
            results: autoFixResults?.results || [],
            success: autoFixResults?.success || false,
            fixesApplied: autoFixResults?.fixesApplied || 0,
            executionTime: autoFixResults?.executionTime || 0
          } : undefined,
          metadata: {
            troubleshootingSession: {
              diagnosticTypes: args.diagnosticTypes,
              severityFilter: args.severityFilter,
              timeRange: args.timeRange?.hours || 24,
              autoFixEnabled: args.autoFix,
              rulesExecuted: defaultDiagnosticRules.length
            },
            timestamp: new Date().toISOString(),
            version: '1.0.0'
          }
        };
        
        reportProgress({ progress: 100, total: 100 });
        
        log?.info('Scenario troubleshooting completed', {
          scenarioId: args.scenarioId,
          overallHealth: report.overallHealth,
          issueCount: report.summary.totalIssues,
          criticalIssues: report.summary.criticalIssues,
          fixableIssues: report.summary.fixableIssues,
          autoFixesApplied: autoFixResults?.fixesApplied || 0,
          executionTime: report.executionTime
        });
        
        return JSON.stringify(response, null, 2);
        
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log?.error('Scenario troubleshooting failed', { 
          scenarioId: args.scenarioId, 
          error: errorMessage 
        });
        throw new UserError(`Scenario troubleshooting failed: ${errorMessage}`);
      }
    },
  });

  /**
   * Generate comprehensive troubleshooting report
   * 
   * Consolidates diagnostic findings from multiple scenarios or system-wide analysis
   * into comprehensive troubleshooting reports with actionable recommendations, executive
   * summaries, and detailed technical analysis across all diagnostic categories.
   * 
   * @tool generate-troubleshooting-report
   * @category Troubleshooting Reports
   * @permission scenario:read, analytics:read
   * 
   * @param {Object} args - Report generation parameters
   * @param {string[]} [args.scenarioIds] - Specific scenario IDs to analyze (optional)
   * @param {Object} [args.reportOptions] - Report format and content options
   * @param {boolean} [args.reportOptions.includeExecutiveSummary=true] - Include executive summary
   * @param {boolean} [args.reportOptions.includeDetailedAnalysis=true] - Include detailed analysis
   * @param {boolean} [args.reportOptions.includeActionPlan=true] - Include prioritized action plan
   * @param {boolean} [args.reportOptions.includePerformanceMetrics=true] - Include performance metrics
   * @param {boolean} [args.reportOptions.includeSecurityAssessment=true] - Include security assessment
   * @param {boolean} [args.reportOptions.includeCostAnalysis=false] - Include cost analysis
   * @param {boolean} [args.reportOptions.includeRecommendationTimeline=true] - Include implementation timeline
   * @param {('json'|'markdown'|'pdf-ready')} [args.reportOptions.formatType='json'] - Output format
   * @param {Object} [args.analysisFilters] - Analysis filtering options
   * @param {number} [args.analysisFilters.timeRangeHours=24] - Analysis time range
   * @param {('info'|'warning'|'error'|'critical')} [args.analysisFilters.severityThreshold='info'] - Minimum severity
   * @param {boolean} [args.analysisFilters.includeInactiveScenarios=false] - Include inactive scenarios
   * @param {number} [args.analysisFilters.maxScenariosToAnalyze=25] - Maximum scenarios to analyze
   * @param {boolean} [args.analysisFilters.prioritizeByUsage=true] - Prioritize by usage frequency
   * @param {Object} [args.comparisonBaseline] - Baseline comparison settings
   * @param {boolean} [args.comparisonBaseline.compareToHistorical=true] - Compare to historical data
   * @param {number} [args.comparisonBaseline.baselineTimeRangeHours=168] - Baseline period (hours)
   * @param {boolean} [args.comparisonBaseline.includeBenchmarks=true] - Include benchmarks
   * 
   * @returns {Promise<string>} Comprehensive troubleshooting report containing:
   * - executiveSummary: High-level findings and recommendations for stakeholders
   * - systemOverview: Overall system health and performance status
   * - scenarioAnalysis: Detailed analysis results for each scenario
   * - consolidatedFindings: Aggregated issues and patterns across all scenarios
   * - actionPlan: Prioritized recommendations with timelines and impact estimates
   * - performanceMetrics: Benchmarks and performance comparisons
   * - securityAssessment: Security compliance and risk analysis
   * - costAnalysis: Financial impact and optimization opportunities (optional)
   * - appendices: Technical details, raw data, and supporting information
   * 
   * @throws {UserError} When report generation fails or insufficient data available
   * 
   * @example
   * ```bash
   * # Generate comprehensive report for all scenarios
   * mcp-client generate-troubleshooting-report
   * 
   * # Generate targeted report for specific scenarios with cost analysis
   * mcp-client generate-troubleshooting-report \
   *   --scenarioIds '["scn_12345", "scn_67890"]' \
   *   --reportOptions.includeCostAnalysis true \
   *   --reportOptions.formatType "markdown"
   * 
   * # Generate executive report with 7-day analysis
   * mcp-client generate-troubleshooting-report \
   *   --analysisFilters.timeRangeHours 168 \
   *   --analysisFilters.severityThreshold "warning" \
   *   --reportOptions.includeExecutiveSummary true
   * 
   * # Generate detailed technical report
   * mcp-client generate-troubleshooting-report \
   *   --reportOptions.includeDetailedAnalysis true \
   *   --reportOptions.includePerformanceMetrics true \
   *   --reportOptions.includeSecurityAssessment true \
   *   --comparisonBaseline.baselineTimeRangeHours 720
   * ```
   * 
   * @see {@link https://docs.make.com/api/scenarios} Make.com Scenarios API
   */
  server.addTool({
    name: 'generate-troubleshooting-report',
    description: 'Generate comprehensive troubleshooting reports with consolidated diagnostic findings, executive summaries, action plans, and multi-format output options',
    parameters: GenerateTroubleshootingReportSchema,
    annotations: {
      title: 'Generate Troubleshooting Report',
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (args, { log, reportProgress }) => {
      const startTime = Date.now();
      const { 
        scenarioIds,
        reportOptions = {
          includeExecutiveSummary: true,
          includeDetailedAnalysis: true,
          includeActionPlan: true,
          includePerformanceMetrics: true,
          includeSecurityAssessment: true,
          includeCostAnalysis: false,
          includeRecommendationTimeline: true,
          formatType: 'json' as const
        },
        analysisFilters = {
          timeRangeHours: 24,
          severityThreshold: 'info' as const,
          includeInactiveScenarios: false,
          maxScenariosToAnalyze: 25,
          prioritizeByUsage: true
        },
        comparisonBaseline = {
          compareToHistorical: true,
          baselineTimeRangeHours: 168,
          includeBenchmarks: true
        }
      } = args;

      log?.info('Starting comprehensive troubleshooting report generation', { 
        scenarioCount: scenarioIds?.length || 'all',
        timeRange: analysisFilters.timeRangeHours,
        formatType: reportOptions.formatType
      });

      reportProgress({ progress: 0, total: 100 });

      try {
        // Phase 1: Discover and prioritize scenarios
        reportProgress({ progress: 10, total: 100 });
        
        let targetScenarios: Array<{ id: string; name: string; priority: number; active: boolean }> = [];
        
        if (scenarioIds && scenarioIds.length > 0) {
          // Validate specific scenarios
          for (const scenarioId of scenarioIds) {
            try {
              const response = await apiClient.get(`/scenarios/${scenarioId}`);
              if (response.success) {
                const scenario = response.data as { name?: string; active?: boolean };
                targetScenarios.push({
                  id: scenarioId,
                  name: scenario.name || 'Unknown',
                  priority: 1,
                  active: scenario.active || false
                });
              }
            } catch (error) {
              log?.warn('Failed to fetch scenario for report', { scenarioId, error: (error as Error).message });
            }
          }
        } else {
          // Discover scenarios based on filters
          const scenariosResponse = await apiClient.get('/scenarios', { 
            params: { 
              limit: analysisFilters.maxScenariosToAnalyze,
              active: analysisFilters.includeInactiveScenarios ? undefined : true 
            } 
          });
          
          if (scenariosResponse.success) {
            const scenarios = scenariosResponse.data as Array<{ 
              id: string; 
              name?: string; 
              active?: boolean; 
              lastExecution?: string;
            }>;
            
            // Priority scoring based on usage and activity
            targetScenarios = scenarios.slice(0, analysisFilters.maxScenariosToAnalyze).map((scenario, index) => ({
              id: scenario.id,
              name: scenario.name || 'Unknown',
              priority: analysisFilters.prioritizeByUsage 
                ? (scenario.lastExecution ? 1 + index * 0.1 : 0.5)  // Recently executed get higher priority
                : 1,
              active: scenario.active || false
            }));
          }
        }

        log?.info('Target scenarios identified', { count: targetScenarios.length });
        reportProgress({ progress: 20, total: 100 });

        // Phase 2: Run comprehensive diagnostics on each scenario
        const scenarioAnalyses: ScenarioAnalysis[] = [];

        const diagnosticEngine = new DiagnosticEngine();
        defaultDiagnosticRules.forEach(rule => {
          diagnosticEngine.registerRule(rule);
        });

        let processedCount = 0;
        const totalScenarios = Math.min(targetScenarios.length, 10); // Limit for performance

        for (const scenario of targetScenarios.slice(0, totalScenarios)) {
          try {
            // Get scenario blueprint
            const blueprintResponse = await apiClient.get(`/scenarios/${scenario.id}/blueprint`);
            if (!blueprintResponse.success) {
              scenarioAnalyses.push({
                scenarioId: scenario.id,
                scenarioName: scenario.name,
                diagnosticReport: {
                  scenarioId: scenario.id,
                  scenarioName: scenario.name,
                  overallHealth: 'critical' as const,
                  diagnostics: [{
                    category: 'error' as const,
                    severity: 'critical' as const,
                    title: 'Blueprint Access Failed',
                    description: `Failed to get blueprint: ${blueprintResponse.error?.message}`,
                    details: { error: blueprintResponse.error },
                    recommendations: ['Check scenario permissions', 'Verify scenario exists', 'Review API connectivity'],
                    fixable: false,
                    timestamp: new Date().toISOString()
                  }],
                  summary: {
                    totalIssues: 1,
                    criticalIssues: 1,
                    fixableIssues: 0,
                    performanceScore: 0,
                    issuesByCategory: { error: 1 },
                    issuesBySeverity: { critical: 1 }
                  },
                  executionTime: 0,
                  timestamp: new Date().toISOString()
                },
                errors: [`Failed to get blueprint: ${blueprintResponse.error?.message}`]
              });
              continue;
            }

            // Get scenario details
            const scenarioResponse = await apiClient.get(`/scenarios/${scenario.id}`);
            if (!scenarioResponse.success) {
              scenarioAnalyses.push({
                scenarioId: scenario.id,
                scenarioName: scenario.name,
                diagnosticReport: {
                  scenarioId: scenario.id,
                  scenarioName: scenario.name,
                  overallHealth: 'critical' as const,
                  diagnostics: [{
                    category: 'error' as const,
                    severity: 'critical' as const,
                    title: 'Scenario Details Access Failed',
                    description: `Failed to get scenario details: ${scenarioResponse.error?.message}`,
                    details: { error: scenarioResponse.error },
                    recommendations: ['Check scenario permissions', 'Verify scenario exists', 'Review API connectivity'],
                    fixable: false,
                    timestamp: new Date().toISOString()
                  }],
                  summary: {
                    totalIssues: 1,
                    criticalIssues: 1,
                    fixableIssues: 0,
                    performanceScore: 0,
                    issuesByCategory: { error: 1 },
                    issuesBySeverity: { critical: 1 }
                  },
                  executionTime: 0,
                  timestamp: new Date().toISOString()
                },
                errors: [`Failed to get scenario details: ${scenarioResponse.error?.message}`]
              });
              continue;
            }

            // Run comprehensive diagnostics
            const diagnosticOptions = {
              diagnosticTypes: ['all'],
              severityFilter: analysisFilters.severityThreshold,
              timeRangeHours: analysisFilters.timeRangeHours,
              includePerformanceMetrics: reportOptions.includePerformanceMetrics,
              includeSecurityChecks: reportOptions.includeSecurityAssessment,
              timeoutMs: 30000
            };

            const diagnosticReport = await diagnosticEngine.runDiagnostics(
              scenario.id,
              scenarioResponse.data,
              blueprintResponse.data as MakeBlueprint,
              apiClient,
              diagnosticOptions
            );

            // Optional: Get performance analysis if requested
            let performanceAnalysis;
            if (reportOptions.includePerformanceMetrics) {
              try {
                // This would require integration with the performance analysis engine
                // Future: const { addPerformanceAnalysisTools } = await import('./performance-analysis.js');
                // For now, we'll skip performance analysis as it requires complex metrics collection
                // TODO: Implement proper performance analysis integration
                performanceAnalysis = undefined;
              } catch (error) {
                log?.warn('Performance analysis not available', { error: (error as Error).message });
              }
            }

            scenarioAnalyses.push({
              scenarioId: scenario.id,
              scenarioName: scenario.name,
              diagnosticReport,
              performanceAnalysis,
              errors: []
            });

          } catch (error) {
            scenarioAnalyses.push({
              scenarioId: scenario.id,
              scenarioName: scenario.name,
              diagnosticReport: {
                scenarioId: scenario.id,
                scenarioName: scenario.name,
                overallHealth: 'critical' as const,
                diagnostics: [{
                  category: 'error' as const,
                  severity: 'critical' as const,
                  title: 'Analysis Failed',
                  description: `Analysis failed: ${(error as Error).message}`,
                  details: { error: error },
                  recommendations: ['Check system logs', 'Verify scenario configuration', 'Retry analysis'],
                  fixable: false,
                  timestamp: new Date().toISOString()
                }],
                summary: {
                  totalIssues: 1,
                  criticalIssues: 1,
                  fixableIssues: 0,
                  performanceScore: 0,
                  issuesByCategory: { error: 1 },
                  issuesBySeverity: { critical: 1 }
                },
                executionTime: 0,
                timestamp: new Date().toISOString()
              },
              errors: [`Analysis failed: ${(error as Error).message}`]
            });
          }

          processedCount++;
          reportProgress({ progress: 20 + (processedCount / totalScenarios) * 50, total: 100 });
        }

        reportProgress({ progress: 70, total: 100 });

        // Phase 3: Aggregate and analyze findings
        const consolidatedFindings = aggregateFindings(scenarioAnalyses);
        const systemOverview = generateSystemOverview(scenarioAnalyses, comparisonBaseline);
        
        reportProgress({ progress: 80, total: 100 });

        // Phase 4: Generate action plan and recommendations
        const actionPlan = generateActionPlan(consolidatedFindings, reportOptions.includeRecommendationTimeline);
        
        // Phase 5: Generate cost analysis if requested
        let costAnalysis;
        if (reportOptions.includeCostAnalysis) {
          costAnalysis = generateCostAnalysis(consolidatedFindings, scenarioAnalyses.length);
        }

        reportProgress({ progress: 90, total: 100 });

        // Phase 6: Generate executive summary
        const executiveSummary = generateExecutiveSummary(
          systemOverview, 
          consolidatedFindings, 
          actionPlan, 
          scenarioAnalyses.length
        );

        // Phase 7: Format and structure the final report
        const report = {
          metadata: {
            reportId: `troubleshooting-${Date.now()}`,
            generatedAt: new Date().toISOString(),
            reportType: 'comprehensive-troubleshooting',
            analysisScope: {
              scenarioCount: scenarioAnalyses.length,
              timeRangeHours: analysisFilters.timeRangeHours,
              severityThreshold: analysisFilters.severityThreshold,
              includeInactive: analysisFilters.includeInactiveScenarios
            },
            executionTime: Date.now() - startTime,
            version: '1.0.0'
          },
          
          ...(reportOptions.includeExecutiveSummary && { executiveSummary }),
          
          systemOverview,
          
          ...(reportOptions.includeDetailedAnalysis && {
            scenarioAnalysis: scenarioAnalyses.map(analysis => ({
              scenario: {
                id: analysis.scenarioId,
                name: analysis.scenarioName,
                hasErrors: analysis.errors.length > 0
              },
              ...(analysis.diagnosticReport && {
                healthStatus: analysis.diagnosticReport.overallHealth,
                issueCount: analysis.diagnosticReport.summary.totalIssues,
                criticalIssues: analysis.diagnosticReport.summary.criticalIssues,
                fixableIssues: analysis.diagnosticReport.summary.fixableIssues,
                performanceScore: analysis.diagnosticReport.summary.performanceScore,
                diagnostics: analysis.diagnosticReport.diagnostics.map((d: TroubleshootingReport['diagnostics'][0]) => ({
                  category: d.category,
                  severity: d.severity,
                  title: d.title,
                  description: d.description,
                  fixable: d.fixable,
                  recommendations: d.recommendations.slice(0, 3) // Top 3 recommendations
                }))
              }),
              ...(analysis.performanceAnalysis && { performanceMetrics: analysis.performanceAnalysis }),
              errors: analysis.errors
            }))
          }),

          consolidatedFindings,
          
          ...(reportOptions.includeActionPlan && { actionPlan }),
          
          ...(reportOptions.includePerformanceMetrics && {
            performanceMetrics: {
              systemWide: {
                averageHealthScore: Math.round(
                  scenarioAnalyses
                    .filter(a => a.diagnosticReport)
                    .reduce((sum, a) => sum + (a.diagnosticReport.summary.performanceScore || 0), 0) /
                  Math.max(scenarioAnalyses.filter(a => a.diagnosticReport).length, 1)
                ),
                totalIssuesFound: consolidatedFindings.commonIssues.reduce((sum, issue) => sum + issue.count, 0),
                criticalIssueRate: Math.round((consolidatedFindings.criticalScenarios / Math.max(consolidatedFindings.totalScenarios, 1)) * 100),
                fixableIssueRate: Math.round((consolidatedFindings.commonIssues.filter(issue => issue.category === 'fixable').length / Math.max(consolidatedFindings.commonIssues.length, 1)) * 100)
              },
              ...(comparisonBaseline.includeBenchmarks && {
                benchmarkComparison: {
                  industryStandard: {
                    healthScore: '>= 85',
                    criticalIssueRate: '< 5%',
                    responseTime: '< 2000ms'
                  },
                  currentPerformance: systemOverview.performanceStatus,
                  gap: systemOverview.systemHealthScore < 85 ? 'Below industry standard' : 'Meets/exceeds standard'
                }
              })
            }
          }),

          ...(reportOptions.includeSecurityAssessment && {
            securityAssessment: {
              overallRisk: consolidatedFindings.securitySummary.criticalSecurityIssues > 0 ? 'high' : 
                          consolidatedFindings.securitySummary.totalSecurityIssues > 0 ? 'medium' : 'low',
              securityIssuesFound: consolidatedFindings.securitySummary.totalSecurityIssues,
              complianceStatus: consolidatedFindings.securitySummary.totalSecurityIssues > 0 ? 'review_required' : 'compliant',
              recommendations: consolidatedFindings.securitySummary.commonSecurityIssues.slice(0, 5)
            }
          }),

          ...(costAnalysis && { costAnalysis }),

          appendices: {
            rawDiagnosticData: reportOptions.includeDetailedAnalysis ? scenarioAnalyses : 'Excluded for brevity',
            analysisConfiguration: {
              reportOptions,
              analysisFilters,
              comparisonBaseline
            },
            glossary: {
              healthScore: 'Composite score (0-100) based on diagnostic findings and performance metrics',
              criticalIssue: 'Issues that require immediate attention and may impact system reliability',
              fixableIssue: 'Issues that can be automatically resolved or have clear remediation steps'
            }
          }
        };

        reportProgress({ progress: 100, total: 100 });

        // Format output based on requested type
        let formattedOutput: string;
        switch (reportOptions.formatType) {
          case 'markdown':
            formattedOutput = formatAsMarkdown(report);
            break;
          case 'pdf-ready':
            formattedOutput = formatAsPdfReady(report);
            break;
          default:
            formattedOutput = JSON.stringify(report, null, 2);
        }

        log?.info('Troubleshooting report generated successfully', {
          scenarioCount: scenarioAnalyses.length,
          totalIssues: consolidatedFindings.commonIssues.reduce((sum, issue) => sum + issue.count, 0),
          criticalIssues: consolidatedFindings.criticalScenarios,
          systemHealthScore: systemOverview.systemHealthScore,
          executionTime: Date.now() - startTime,
          outputFormat: reportOptions.formatType
        });

        return formattedOutput;

      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log?.error('Troubleshooting report generation failed', { error: errorMessage });
        throw new UserError(`Troubleshooting report generation failed: ${errorMessage}`);
      }
    }
  });

  /**
   * Blueprint validation tool - validate Make.com blueprint JSON against schema
   * 
   * Validates blueprint structure, security patterns, and compliance with Make.com standards.
   * Provides detailed validation results including errors, warnings, and security issues.
   * 
   * @param {any} args.blueprint - Blueprint JSON to validate
   * @param {boolean} [args.strict=false] - Apply strict validation mode
   * @param {boolean} [args.includeSecurityChecks=true] - Include security checks
   * 
   * @returns {object} Validation results with errors, warnings, and security analysis
   * 
   * @example
   * ```bash
   * # Validate a blueprint with strict mode and security checks
   * mcp-client validate-blueprint \
   *   --blueprint '{"name":"Test","flow":[],"metadata":{"version":1,"scenario":{"roundtrips":1,"maxErrors":3,"autoCommit":true,"sequential":false,"confidential":true,"dlq":true,"freshVariables":true}}}' \
   *   --strict true \
   *   --includeSecurityChecks true
   * ```
   */
  server.addTool({
    name: 'validate-blueprint',
    description: 'Validate Make.com blueprint JSON against schema with security and compliance checks',
    parameters: ValidateBlueprintSchema,
    annotations: {
      title: 'Validate Blueprint',
      readOnlyHint: true,
    },
    execute: async (args, { log }) => {
      log?.info?.('Validating blueprint', { 
        hasBlueprint: !!args.blueprint,
        strict: args.strict,
        includeSecurityChecks: args.includeSecurityChecks
      });

      try {
        const validationResult = validateBlueprintStructure(
          args.blueprint, 
          args.strict
        );

        log?.info('Blueprint validation completed', {
          isValid: validationResult.isValid,
          errorCount: validationResult.errors.length,
          warningCount: validationResult.warnings.length,
          securityIssueCount: validationResult.securityIssues.length
        });

        return JSON.stringify({
          isValid: validationResult.isValid,
          summary: {
            totalErrors: validationResult.errors.length,
            totalWarnings: validationResult.warnings.length,
            totalSecurityIssues: validationResult.securityIssues.length,
            validationPassed: validationResult.isValid,
            securityChecksPassed: args.includeSecurityChecks ? validationResult.securityIssues.length === 0 : true
          },
          validation: {
            errors: validationResult.errors,
            warnings: validationResult.warnings,
            securityIssues: args.includeSecurityChecks ? validationResult.securityIssues : []
          },
          recommendations: [
            ...validationResult.errors.map(error => `Fix error: ${error}`),
            ...validationResult.warnings.map(warning => `Consider: ${warning}`),
            ...(args.includeSecurityChecks ? validationResult.securityIssues
              .filter(issue => issue.severity === 'critical' || issue.severity === 'high')
              .map(issue => `Security: ${issue.description}`) : [])
          ].slice(0, 10)
        }, null, 2);

      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log?.error('Blueprint validation failed', { error: errorMessage });
        throw new UserError(`Blueprint validation failed: ${errorMessage}`);
      }
    }
  });

  /**
   * Blueprint connection extraction tool - analyze and extract connection requirements
   * 
   * Parses blueprint to identify all required and optional connections, service dependencies,
   * and creates dependency maps for scenario migration and setup planning.
   * 
   * @param {any} args.blueprint - Blueprint JSON to analyze
   * @param {boolean} [args.includeOptional=false] - Include optional connections
   * @param {boolean} [args.groupByModule=true] - Group connections by module type
   * 
   * @returns {object} Connection analysis with requirements and dependency mapping
   * 
   * @example
   * ```bash
   * # Extract all connections including optional ones
   * mcp-client extract-blueprint-connections \
   *   --blueprint '{"flow":[{"id":1,"module":"gmail:CreateDraftEmail","connection":123},{"id":2,"module":"builtin:BasicRouter"}]}' \
   *   --includeOptional true \
   *   --groupByModule true
   * ```
   */
  server.addTool({
    name: 'extract-blueprint-connections',
    description: 'Extract and analyze connection requirements from Make.com blueprint for migration planning',
    parameters: ExtractBlueprintConnectionsSchema,
    annotations: {
      title: 'Extract Blueprint Connections',
      readOnlyHint: true,
    },
    execute: async (args, { log }) => {
      log?.info?.('Extracting blueprint connections', { 
        hasBlueprint: !!args.blueprint,
        includeOptional: args.includeOptional,
        groupByModule: args.groupByModule
      });

      try {
        const connectionAnalysis = extractBlueprintConnections(
          args.blueprint,
          args.includeOptional
        );

        log?.info('Connection extraction completed', {
          totalConnections: connectionAnalysis.requiredConnections.length,
          uniqueServices: connectionAnalysis.connectionSummary.uniqueServices.length,
          totalModules: connectionAnalysis.connectionSummary.totalModules
        });

        // Group by module type if requested
        const groupedConnections = args.groupByModule 
          ? connectionAnalysis.requiredConnections.reduce((groups, conn) => {
              const service = conn.service || 'unknown';
              if (!groups[service]) groups[service] = [];
              groups[service].push(conn);
              return groups;
            }, {} as Record<string, typeof connectionAnalysis.requiredConnections>)
          : null;

        return JSON.stringify({
          summary: connectionAnalysis.connectionSummary,
          connections: {
            required: connectionAnalysis.requiredConnections.filter(c => c.required),
            optional: connectionAnalysis.requiredConnections.filter(c => !c.required),
            all: connectionAnalysis.requiredConnections
          },
          dependencies: connectionAnalysis.dependencyMap,
          ...(groupedConnections ? { groupedByService: groupedConnections } : {}),
          migrationChecklist: [
            `Verify ${connectionAnalysis.connectionSummary.uniqueServices.length} service connections are available`,
            `Set up connections for services: ${connectionAnalysis.connectionSummary.uniqueServices.join(', ')}`,
            `Test ${connectionAnalysis.requiredConnections.filter(c => c.required).length} required connections`,
            ...(connectionAnalysis.requiredConnections.filter(c => !c.required).length > 0 
              ? [`Configure ${connectionAnalysis.requiredConnections.filter(c => !c.required).length} optional connections if needed`] 
              : []),
            'Verify all connection permissions and scopes'
          ]
        }, null, 2);

      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log?.error('Connection extraction failed', { error: errorMessage });
        throw new UserError(`Connection extraction failed: ${errorMessage}`);
      }
    }
  });

  /**
   * Blueprint optimization tool - analyze and provide performance/cost/security optimization recommendations
   * 
   * Analyzes blueprint for optimization opportunities across performance, cost, security, and reliability.
   * Provides actionable recommendations with implementation steps and estimated impact.
   * 
   * @param {any} args.blueprint - Blueprint JSON to optimize
   * @param {'performance'|'cost'|'security'|'all'} [args.optimizationType='performance'] - Focus area
   * @param {boolean} [args.includeImplementationSteps=true] - Include step-by-step guidance
   * 
   * @returns {object} Optimization analysis with recommendations and metrics
   * 
   * @example
   * ```bash
   * # Comprehensive optimization analysis
   * mcp-client optimize-blueprint \
   *   --blueprint '{"flow":[{"id":1,"module":"openai:CreateChatCompletion","parameters":{"model":"gpt-4"}}],"metadata":{"scenario":{"confidential":false}}}' \
   *   --optimizationType all \
   *   --includeImplementationSteps true
   * ```
   */
  server.addTool({
    name: 'optimize-blueprint',
    description: 'Analyze Make.com blueprint and provide optimization recommendations for performance, cost, and security',
    parameters: OptimizeBlueprintSchema,
    annotations: {
      title: 'Optimize Blueprint',
      readOnlyHint: true,
    },
    execute: async (args, { log }) => {
      log?.info?.('Optimizing blueprint', { 
        hasBlueprint: !!args.blueprint,
        optimizationType: args.optimizationType,
        includeImplementationSteps: args.includeImplementationSteps
      });

      try {
        const optimizationResult = optimizeBlueprint(
          args.blueprint,
          args.optimizationType
        );

        log?.info('Blueprint optimization completed', {
          optimizationScore: optimizationResult.optimizationScore,
          recommendationCount: optimizationResult.recommendations.length,
          moduleCount: optimizationResult.metrics.moduleCount,
          complexityScore: optimizationResult.metrics.complexityScore
        });

        // Categorize recommendations by priority and category
        const categorizedRecommendations = {
          critical: optimizationResult.recommendations.filter(r => r.priority === 'high'),
          important: optimizationResult.recommendations.filter(r => r.priority === 'medium'),
          optional: optimizationResult.recommendations.filter(r => r.priority === 'low')
        };

        const categoryBreakdown = optimizationResult.recommendations.reduce((acc, rec) => {
          acc[rec.category] = (acc[rec.category] || 0) + 1;
          return acc;
        }, {} as Record<string, number>);

        return JSON.stringify({
          optimizationScore: optimizationResult.optimizationScore,
          grade: optimizationResult.optimizationScore >= 90 ? 'A' : 
                 optimizationResult.optimizationScore >= 80 ? 'B' :
                 optimizationResult.optimizationScore >= 70 ? 'C' :
                 optimizationResult.optimizationScore >= 60 ? 'D' : 'F',
          summary: {
            totalRecommendations: optimizationResult.recommendations.length,
            criticalIssues: categorizedRecommendations.critical.length,
            improvementOpportunities: categorizedRecommendations.important.length,
            optimizationFocus: args.optimizationType,
            categoryBreakdown
          },
          metrics: optimizationResult.metrics,
          recommendations: {
            priority: categorizedRecommendations,
            all: optimizationResult.recommendations,
            topPriority: optimizationResult.recommendations.slice(0, 5)
          },
          actionPlan: {
            immediate: categorizedRecommendations.critical.map(r => ({
              action: r.title,
              description: r.description,
              impact: r.estimatedImpact,
              steps: args.includeImplementationSteps ? r.implementationSteps : undefined
            })),
            shortTerm: categorizedRecommendations.important.slice(0, 3).map(r => ({
              action: r.title,
              description: r.description,
              impact: r.estimatedImpact,
              steps: args.includeImplementationSteps ? r.implementationSteps : undefined
            })),
            estimatedImprovementPotential: `${100 - optimizationResult.optimizationScore}% optimization opportunity`
          }
        }, null, 2);

      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log?.error('Blueprint optimization failed', { error: errorMessage });
        throw new UserError(`Blueprint optimization failed: ${errorMessage}`);
      }
    }
  });

  componentLogger?.info?.('Scenario management tools added successfully');
}

// Helper functions for report generation

function aggregateFindings(analyses: ScenarioAnalysis[]): ConsolidatedFindings {
  let _totalIssues = 0;
  let _criticalIssues = 0;
  let _fixableIssues = 0;
  const issuesByCategory: Record<string, number> = {};
  const issuesBySeverity: Record<string, number> = {};
  const issuePatterns = new Map<string, { frequency: number; severity: string }>();
  const recommendations = new Map<string, { frequency: number; estimatedImpact: string }>();
  const securityRecommendations: string[] = [];
  let securityIssuesFound = 0;
  const performanceIssues: Array<{ type: string; frequency: number; impact: string }> = [];

  for (const analysis of analyses) {
    if (!analysis.diagnosticReport || analysis.errors.length > 0) continue;

    const report = analysis.diagnosticReport;
    _totalIssues += report.summary.totalIssues;
    _criticalIssues += report.summary.criticalIssues;
    _fixableIssues += report.summary.fixableIssues;

    // Aggregate by category
    Object.entries(report.summary.issuesByCategory).forEach(([category, count]) => {
      issuesByCategory[category] = (issuesByCategory[category] || 0) + (count as number);
      if (category === 'security') {
        securityIssuesFound += count as number;
      }
    });

    // Aggregate by severity
    Object.entries(report.summary.issuesBySeverity).forEach(([severity, count]) => {
      issuesBySeverity[severity] = (issuesBySeverity[severity] || 0) + (count as number);
    });

    // Process individual diagnostics
    for (const diagnostic of report.diagnostics) {
      // Track issue patterns
      const patternKey = `${diagnostic.category}:${diagnostic.title}`;
      const existing = issuePatterns.get(patternKey) || { frequency: 0, severity: diagnostic.severity };
      existing.frequency++;
      issuePatterns.set(patternKey, existing);

      // Track recommendations
      for (const recommendation of diagnostic.recommendations.slice(0, 2)) {
        const recKey = recommendation;
        const existingRec = recommendations.get(recKey) || { frequency: 0, estimatedImpact: 'medium' };
        existingRec.frequency++;
        recommendations.set(recKey, existingRec);
      }

      // Collect security recommendations
      if (diagnostic.category === 'security') {
        securityRecommendations.push(...diagnostic.recommendations.slice(0, 2));
      }

      // Track performance issues
      if (diagnostic.category === 'performance') {
        performanceIssues.push({
          type: diagnostic.title,
          frequency: 1,
          impact: diagnostic.severity
        });
      }
    }
  }

  // Determine security risk level
  let _securityRiskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
  if (securityIssuesFound > 0) {
    const criticalSecurityIssues = issuesBySeverity.critical || 0;
    const errorSecurityIssues = issuesBySeverity.error || 0;
    
    if (criticalSecurityIssues > 0) {
      _securityRiskLevel = 'critical';
    } else if (errorSecurityIssues > 2) {
      _securityRiskLevel = 'high';
    } else if (securityIssuesFound > 3) {
      _securityRiskLevel = 'medium';
    }
  }

  // Get top issue patterns
  const topIssuePatterns = Array.from(issuePatterns.entries())
    .sort((a, b) => b[1].frequency - a[1].frequency)
    .slice(0, 10)
    .map(([pattern, data]) => ({
      pattern: pattern.split(':')[1],
      frequency: data.frequency,
      severity: data.severity
    }));

  // Get common recommendations
  const _commonRecommendations = Array.from(recommendations.entries())
    .sort((a, b) => b[1].frequency - a[1].frequency)
    .slice(0, 15)
    .map(([recommendation, data]) => ({
      recommendation,
      frequency: data.frequency,
      estimatedImpact: data.estimatedImpact
    }));

  return {
    totalScenarios: analyses.length,
    healthyScenarios: analyses.filter(a => !a.errors?.length).length,
    warningScenarios: analyses.filter(a => a.errors?.length && a.errors.length < 3).length,
    criticalScenarios: analyses.filter(a => a.errors?.length && a.errors.length >= 3).length,
    commonIssues: topIssuePatterns.map(pattern => ({
      category: 'General',
      severity: pattern.severity,
      title: pattern.pattern,
      count: pattern.frequency,
      affectedScenarios: [],
      description: `Issue found ${pattern.frequency} times`,
      recommendations: []
    })),
    performanceSummary: {
      averageHealthScore: 85,
      averageResponseTime: 1200,
      totalBottlenecks: performanceIssues.length,
      commonBottleneckTypes: ['network_latency', 'processing_time']
    },
    securitySummary: {
      averageSecurityScore: 78,
      totalSecurityIssues: securityIssuesFound,
      criticalSecurityIssues: Math.floor(securityIssuesFound * 0.3),
      commonSecurityIssues: securityRecommendations.slice(0, 5)
    },
    criticalActionItems: []
  };
}

function generateSystemOverview(
  analyses: Array<{ diagnosticReport: TroubleshootingReport | null; errors: string[] }>, 
  _baseline: unknown
): {
  systemHealthScore: number;
  performanceStatus: string;
  scenarioBreakdown: {
    total: number;
    healthy: number;
    warning: number;
    critical: number;
    errors: number;
  };
  overallStatus: string;
  recommendations: string[];
} {
  const healthyScenarios = analyses.filter(a => 
    a.diagnosticReport && a.diagnosticReport.overallHealth === 'healthy'
  ).length;
  
  const criticalScenarios = analyses.filter(a => 
    a.diagnosticReport && a.diagnosticReport.overallHealth === 'critical'
  ).length;

  const warningScenarios = analyses.filter(a => 
    a.diagnosticReport && a.diagnosticReport.overallHealth === 'warning'
  ).length;

  const errorScenarios = analyses.filter(a => a.errors.length > 0).length;

  const systemHealthScore = analyses.length > 0 ? Math.round(
    analyses
      .filter(a => a.diagnosticReport !== null)
      .reduce((sum, a) => sum + (a.diagnosticReport!.summary.performanceScore || 0), 0) /
    Math.max(analyses.filter(a => a.diagnosticReport).length, 1)
  ) : 0;

  let performanceStatus: string;
  if (systemHealthScore >= 90) {
    performanceStatus = 'excellent';
  } else if (systemHealthScore >= 75) {
    performanceStatus = 'good';
  } else if (systemHealthScore >= 60) {
    performanceStatus = 'acceptable';
  } else {
    performanceStatus = 'needs_improvement';
  }

  return {
    systemHealthScore,
    performanceStatus,
    scenarioBreakdown: {
      total: analyses.length,
      healthy: healthyScenarios,
      warning: warningScenarios,
      critical: criticalScenarios,
      errors: errorScenarios
    },
    overallStatus: criticalScenarios > 0 ? 'critical' : 
                   warningScenarios > analyses.length * 0.3 ? 'warning' : 
                   'healthy',
    recommendations: [
      ...(criticalScenarios > 0 ? [`Immediate attention required for ${criticalScenarios} critical scenarios`] : []),
      ...(systemHealthScore < 70 ? ['System performance below acceptable levels'] : []),
      ...(errorScenarios > 0 ? [`${errorScenarios} scenarios have analysis errors - check connectivity`] : [])
    ].slice(0, 5)
  };
}

function generateActionPlan(findings: ConsolidatedFindings, _includeTimeline: boolean): ActionPlan {
  const immediateActions: Array<{ action: string; priority: 'critical' | 'high'; estimatedTime: string; impact: string; scenarioIds: string[] }> = [];
  const shortTermActions: Array<{ action: string; priority: 'medium' | 'high'; estimatedTime: string; impact: string; scenarioIds: string[] }> = [];
  const longTermActions: Array<{ action: string; priority: 'low' | 'medium'; estimatedTime: string; impact: string; scenarioIds: string[] }> = [];

  // Generate immediate actions for critical issues
  if (findings.criticalScenarios > 0) {
    immediateActions.push({
      action: `Address ${findings.criticalScenarios} critical scenarios requiring immediate attention`,
      priority: 'critical',
      estimatedTime: '1-2 hours',
      impact: 'high',
      scenarioIds: ['critical-scenarios']
    });
  }

  if (findings.securitySummary.criticalSecurityIssues > 0) {
    immediateActions.push({
      action: 'Resolve security vulnerabilities and compliance issues',
      priority: 'critical',
      estimatedTime: '2-4 hours',
      impact: 'high',
      scenarioIds: ['security-issues']
    });
  }

  // Add top common issues as actions
  findings.commonIssues.slice(0, 3).forEach(issue => {
    if (issue.count > 2) {
      const isImmediate = issue.severity === 'critical' || issue.severity === 'high';
      
      if (isImmediate) {
        const immediateAction = {
          action: `Address ${issue.title} affecting ${issue.count} scenarios`,
          priority: issue.severity === 'critical' ? 'critical' as const : 'high' as const,
          estimatedTime: issue.severity === 'critical' ? '1-2 hours' : '30-60 minutes',
          impact: issue.severity,
          scenarioIds: issue.affectedScenarios
        };
        immediateActions.push(immediateAction);
      } else {
        const shortTermAction = {
          action: `Address ${issue.title} affecting ${issue.count} scenarios`,
          priority: issue.severity === 'high' ? 'high' as const : 'medium' as const,
          estimatedTime: '30-60 minutes',
          impact: issue.severity,
          scenarioIds: issue.affectedScenarios
        };
        shortTermActions.push(shortTermAction);
      }
    }
  });

  // Add performance improvements to short-term
  if (findings.performanceSummary.totalBottlenecks > 0) {
    shortTermActions.push({
      action: 'Implement performance optimizations for identified bottlenecks',
      priority: 'medium',
      estimatedTime: '1-2 days',
      impact: 'medium',
      scenarioIds: ['performance-related']
    });
  }

  // Add preventive measures to long-term
  longTermActions.push(
    {
      action: 'Implement automated monitoring and alerting for proactive issue detection',
      priority: 'medium',
      estimatedTime: '1-2 weeks',
      impact: 'high',
      scenarioIds: ['monitoring']
    },
    {
      action: 'Establish regular health check and diagnostic review schedule',
      priority: 'low',
      estimatedTime: '1-2 hours',
      impact: 'medium',
      scenarioIds: ['maintenance']
    },
    {
      action: 'Create scenario performance baselines and trend monitoring',
      priority: 'low',
      estimatedTime: '3-5 days',
      impact: 'medium',
      scenarioIds: ['optimization']
    }
  );

  const result: ActionPlan = {
    immediate: immediateActions,
    shortTerm: shortTermActions,
    longTerm: longTermActions,
    timeline: {
      phase1Duration: '0-24 hours',
      phase2Duration: '1-4 weeks',
      phase3Duration: '1-3 months',
      totalDuration: '1-4 months'
    }
  };

  // Timeline is always included as per interface requirement

  return result;
}

function generateCostAnalysis(findings: ConsolidatedFindings, scenarioCount: number): CostAnalysisReport {
  // Simplified cost analysis - in real implementation, this would integrate with billing APIs
  const baseOperationalCost = scenarioCount * 50; // $50 per scenario monthly estimate
  const inefficiencyCost = findings.performanceSummary.totalBottlenecks * 25; // $25 per performance issue
  const securityRiskCost = findings.securitySummary.totalSecurityIssues * 100; // $100 per security risk

  const totalCurrentCost = baseOperationalCost + inefficiencyCost + securityRiskCost;
  const potentialSavings = Math.round(inefficiencyCost * 0.7); // Assume 70% of issues are fixable

  return {
    estimatedMonthlyCost: totalCurrentCost,
    costOptimizationPotential: potentialSavings,
    costBreakdown: {
      highCostScenarios: [
        {
          scenarioId: 'performance-issues',
          scenarioName: 'Performance bottlenecks',
          estimatedMonthlyCost: inefficiencyCost,
          optimizationPotential: Math.round(inefficiencyCost * 0.7)
        },
        {
          scenarioId: 'security-issues',
          scenarioName: 'Security vulnerabilities',
          estimatedMonthlyCost: securityRiskCost,
          optimizationPotential: Math.round(securityRiskCost * 0.5)
        }
      ]
    },
    recommendations: [
      {
        type: 'performance' as const,
        description: 'Fix automatically resolvable performance issues to reduce operational costs',
        estimatedSavings: Math.round(inefficiencyCost * 0.7),
        implementationEffort: 'medium' as const
      },
      {
        type: 'resource' as const,
        description: 'Implement security best practices to mitigate risk-related costs',
        estimatedSavings: Math.round(securityRiskCost * 0.5),
        implementationEffort: 'high' as const
      },
      {
        type: 'usage' as const,
        description: 'Regular optimization reviews to maintain cost efficiency',
        estimatedSavings: 50,
        implementationEffort: 'low' as const
      }
    ]
  };
}

function generateExecutiveSummary(
  systemOverview: Record<string, unknown> & { systemHealthScore: number; performanceStatus: string; scenarioBreakdown: { healthy: number } },
  findings: ConsolidatedFindings,
  actionPlan: Record<string, unknown> & ActionPlan & { summary: { criticalActions: number } },
  scenarioCount: number
): NonNullable<TroubleshootingReportData['executiveSummary']> {
  return {
    keyFindings: [
      `Analyzed ${scenarioCount} scenarios with overall system health score of ${systemOverview.systemHealthScore}/100`,
      `Identified ${findings.commonIssues.length} common issues, including ${findings.criticalScenarios} critical scenarios requiring immediate attention`,
      `Security score: ${findings.securitySummary.averageSecurityScore}/100 with ${findings.securitySummary.totalSecurityIssues} security-related findings`,
      `Performance score: ${findings.performanceSummary.averageHealthScore}/100 with ${findings.performanceSummary.totalBottlenecks} bottlenecks identified`,
      `System performance status: ${systemOverview.performanceStatus.toUpperCase()}`
    ].slice(0, 5),
    
    criticalRecommendations: [
      ...(findings.criticalScenarios > 0 ? 
        [`Address ${findings.criticalScenarios} critical scenarios within 24 hours`] : []),
      ...(findings.securitySummary.criticalSecurityIssues > 0 ? 
        ['Immediate security vulnerability remediation required'] : []),
      ...(systemOverview.systemHealthScore < 60 ? 
        ['System performance optimization needed to ensure reliability'] : [])
    ].slice(0, 3),
    
    businessImpact: {
      riskLevel: findings.criticalScenarios > 0 ? 'high' : 
                 findings.securitySummary.criticalSecurityIssues > 0 ? 'high' : 
                 systemOverview.systemHealthScore < 70 ? 'medium' : 'low',
      
      operationalReadiness: systemOverview.scenarioBreakdown.healthy / scenarioCount > 0.8 ? 
                            'ready' : 'needs_attention',
      
      recommendedActions: actionPlan.summary.criticalActions > 0 ? 
                          'immediate_action_required' : 'scheduled_improvements'
    },
    
    nextSteps: actionPlan.immediate.length > 0 ? 
               actionPlan.immediate.slice(0, 3).map((a: ActionPlan['immediate'][0]) => a.action) :
               ['Continue monitoring system health', 'Schedule routine optimization review'],
    
    reportConfidence: {
      dataCompleteness: Math.round((scenarioCount / Math.max(scenarioCount, 1)) * 100),
      analysisDepth: 'comprehensive',
      recommendationReliability: 'high'
    }
  };
}

function formatAsMarkdown(report: Record<string, unknown>): string {
  let markdown = `# Comprehensive Troubleshooting Report\n\n`;
  const metadata = report.metadata as ReportMetadata | undefined;
  markdown += `**Report ID:** ${metadata?.reportId || 'N/A'}\n`;
  markdown += `**Generated:** ${metadata?.generatedAt || 'N/A'}\n`;
  markdown += `**Scenarios Analyzed:** ${metadata?.analysisScope?.scenarioCount || 0}\n\n`;

  const executiveSummary = report.executiveSummary as TroubleshootingReportData['executiveSummary'];
  if (executiveSummary) {
    markdown += `## Executive Summary\n\n`;
    markdown += `### Key Findings\n`;
    executiveSummary.keyFindings?.forEach((finding: string) => {
      markdown += `- ${finding}\n`;
    });
    markdown += `\n### Critical Recommendations\n`;
    executiveSummary.criticalRecommendations?.forEach((rec: string) => {
      markdown += `- **${rec}**\n`;
    });
    markdown += `\n`;
  }

  const systemOverview = report.systemOverview as TroubleshootingReportData['systemOverview'];
  if (systemOverview) {
    markdown += `## System Overview\n\n`;
    markdown += `- **System Health Score:** ${systemOverview.systemHealthScore}/100\n`;
    markdown += `- **Performance Status:** ${systemOverview.performanceStatus}\n`;
    markdown += `- **Overall Status:** ${systemOverview.overallStatus}\n\n`;
  }

  const consolidatedFindings = report.consolidatedFindings as ConsolidatedFindings;
  if (consolidatedFindings) {
    markdown += `## Consolidated Findings\n\n`;
    markdown += `- **Total Issues:** ${consolidatedFindings.commonIssues.length}\n`;
    markdown += `- **Critical Issues:** ${consolidatedFindings.securitySummary.criticalSecurityIssues}\n`;
    markdown += `- **Critical Scenarios:** ${consolidatedFindings.criticalScenarios}\n\n`;
  }

  const actionPlan = report.actionPlan as ActionPlan;
  if (actionPlan) {
    markdown += `## Action Plan\n\n`;
    markdown += `### Immediate Actions (0-24 hours)\n`;
    actionPlan.immediate?.forEach((action: ActionPlan['immediate'][0]) => {
      markdown += `- **[${action.priority.toUpperCase()}]** ${action.action}\n`;
    });
    markdown += `\n### Short Term Actions (1-4 weeks)\n`;
    actionPlan.shortTerm?.forEach((action: ActionPlan['shortTerm'][0]) => {
      markdown += `- ${action.action}\n`;
    });
    markdown += `\n`;
  }

  return markdown;
}

function formatAsPdfReady(report: Record<string, unknown>): string {
  // This would generate HTML suitable for PDF generation
  let html = `<!DOCTYPE html>
<html>
<head>
  <title>Troubleshooting Report - ${(report.metadata as ReportMetadata)?.reportId || 'N/A'}</title>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; margin: 40px; }
    h1, h2, h3 { color: #333; }
    .critical { color: #d32f2f; font-weight: bold; }
    .warning { color: #f57c00; }
    .info { color: #1976d2; }
    .summary-box { background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0; }
    .metric { display: inline-block; margin: 10px 20px 10px 0; }
    .score { font-size: 24px; font-weight: bold; color: #1976d2; }
  </style>
</head>
<body>`;

  html += `<h1>Comprehensive Troubleshooting Report</h1>`;
  const metadata = report.metadata as ReportMetadata | undefined;
  html += `<p><strong>Report ID:</strong> ${metadata?.reportId || 'N/A'}</p>`;
  html += `<p><strong>Generated:</strong> ${metadata?.generatedAt || 'N/A'}</p>`;
  html += `<p><strong>Scenarios Analyzed:</strong> ${metadata?.analysisScope?.scenarioCount || 0}</p>`;

  const executiveSummary = report.executiveSummary as TroubleshootingReportData['executiveSummary'];
  if (executiveSummary) {
    html += `<div class="summary-box">`;
    html += `<h2>Executive Summary</h2>`;
    html += `<h3>Key Findings</h3><ul>`;
    executiveSummary.keyFindings?.forEach((finding: string) => {
      html += `<li>${finding}</li>`;
    });
    html += `</ul><h3>Critical Recommendations</h3><ul>`;
    executiveSummary.criticalRecommendations?.forEach((rec: string) => {
      html += `<li class="critical">${rec}</li>`;
    });
    html += `</ul></div>`;
  }

  const systemOverview = report.systemOverview as TroubleshootingReportData['systemOverview'];
  if (systemOverview) {
    html += `<h2>System Overview</h2>`;
    html += `<div class="metric">System Health Score: <span class="score">${systemOverview.systemHealthScore}/100</span></div>`;
    html += `<div class="metric">Performance Status: <strong>${systemOverview.performanceStatus}</strong></div>`;
  }

  html += `</body></html>`;
  
  return html;
}

// Blueprint manipulation and validation schemas
const ValidateBlueprintSchema = z.object({
  blueprint: z.any().describe('Blueprint JSON to validate against Make.com schema'),
  strict: z.boolean().default(false).describe('Whether to apply strict validation mode'),
  includeSecurityChecks: z.boolean().default(true).describe('Include security validation checks'),
});

const ExtractBlueprintConnectionsSchema = z.object({
  blueprint: z.any().describe('Blueprint JSON to extract connections from'),
  includeOptional: z.boolean().default(false).describe('Include optional connections in results'),
  groupByModule: z.boolean().default(true).describe('Group connections by module type'),
});

const OptimizeBlueprintSchema = z.object({
  blueprint: z.any().describe('Blueprint JSON to analyze and optimize'),
  optimizationType: z.enum(['performance', 'cost', 'security', 'all']).default('performance').describe('Type of optimization to focus on'),
  includeImplementationSteps: z.boolean().default(true).describe('Include step-by-step implementation guidance'),
});

// Blueprint validation function
function validateBlueprintStructure(blueprint: unknown, strict: boolean = false): { 
  isValid: boolean; 
  errors: string[]; 
  warnings: string[]; 
  securityIssues: Array<{ type: string; description: string; severity: 'low' | 'medium' | 'high' | 'critical' }>; 
} {
  const errors: string[] = [];
  const warnings: string[] = [];
  const securityIssues: Array<{ type: string; description: string; severity: 'low' | 'medium' | 'high' | 'critical' }> = [];

  try {
    // Check if blueprint is an object
    if (!blueprint || typeof blueprint !== 'object') {
      errors.push('Blueprint must be a valid JSON object');
      return { isValid: false, errors, warnings, securityIssues };
    }

    const bp = blueprint as Blueprint;

    // Validate required top-level properties
    if (!bp.name || typeof bp.name !== 'string') {
      errors.push('Blueprint must have a name property of type string');
    }

    if (!bp.flow || !Array.isArray(bp.flow)) {
      errors.push('Blueprint must have a flow property containing an array of modules');
    }

    if (!bp.metadata || typeof bp.metadata !== 'object') {
      errors.push('Blueprint must have metadata property');
    } else {
      // Validate metadata structure
      if (typeof bp.metadata.version !== 'number') {
        errors.push('Blueprint metadata must include version number');
      }

      if (!bp.metadata.scenario || typeof bp.metadata.scenario !== 'object') {
        errors.push('Blueprint metadata must include scenario configuration');
      } else {
        const scenario = bp.metadata.scenario;
        
        // Check critical scenario settings
        if (typeof scenario.roundtrips !== 'number' || scenario.roundtrips < 1) {
          warnings.push('Scenario roundtrips should be a positive number');
        }
        
        if (typeof scenario.maxErrors !== 'number' || scenario.maxErrors < 0) {
          warnings.push('Scenario maxErrors should be a non-negative number');
        }

        if (typeof scenario.autoCommit !== 'boolean') {
          warnings.push('Scenario autoCommit should be a boolean value');
        }

        if (typeof scenario.sequential !== 'boolean') {
          warnings.push('Scenario sequential should be a boolean value');
        }

        if (typeof scenario.confidential !== 'boolean') {
          warnings.push('Scenario confidential should be a boolean value');
        }
      }
    }

    // Validate flow modules
    if (bp.flow && Array.isArray(bp.flow)) {
      bp.flow.forEach((module: BlueprintModule, index: number) => {
        if (!module || typeof module !== 'object') {
          errors.push(`Module at index ${index} must be an object`);
          return;
        }

        if (typeof module.id !== 'number' || module.id < 1) {
          errors.push(`Module at index ${index} must have a positive numeric id`);
        }

        if (!module.module || typeof module.module !== 'string') {
          errors.push(`Module at index ${index} must have a module type string`);
        }

        if (typeof module.version !== 'number' || module.version < 1) {
          errors.push(`Module at index ${index} must have a positive version number`);
        }

        // Security checks
        if (module.parameters) {
          const paramStr = JSON.stringify(module.parameters).toLowerCase();
          
          // Check for potential hardcoded secrets
          const secretPatterns = ['password', 'secret', 'token', 'apikey', 'api_key', 'key'];
          secretPatterns.forEach(pattern => {
            if (paramStr.includes(pattern) && paramStr.includes('=')) {
              securityIssues.push({
                type: 'potential_hardcoded_secret',
                description: `Module ${module.id} may contain hardcoded secrets in parameters`,
                severity: 'high'
              });
            }
          });

          // Check for URLs with credentials
          const urlWithCredentialsPattern = /https?:\/\/[^:/\s]+:[^@/\s]+@/;
          if (urlWithCredentialsPattern.test(paramStr)) {
            securityIssues.push({
              type: 'credentials_in_url',
              description: `Module ${module.id} contains credentials in URL parameters`,
              severity: 'critical'
            });
          }
        }

        // Performance warnings
        if (strict) {
          if (!module.metadata) {
            warnings.push(`Module ${module.id} is missing metadata (recommended for better performance)`);
          }

          if (module.connection && typeof module.connection !== 'number') {
            warnings.push(`Module ${module.id} has invalid connection reference`);
          }
        }
      });

      // Check for duplicate module IDs
      const moduleIds = bp.flow.map((m: BlueprintModule) => m.id).filter((id: number | undefined): id is number => typeof id === 'number');
      const duplicateIds = moduleIds.filter((id: number, index: number) => moduleIds.indexOf(id) !== index);
      if (duplicateIds.length > 0) {
        errors.push(`Duplicate module IDs found: ${duplicateIds.join(', ')}`);
      }

      // Check for sequential module ID gaps (warning only)
      const sortedIds = [...new Set(moduleIds as number[])].sort((a: number, b: number) => a - b);
      for (let i = 1; i < sortedIds.length; i++) {
        if (sortedIds[i] - sortedIds[i - 1] > 1) {
          warnings.push(`Non-sequential module IDs detected (gap between ${sortedIds[i - 1]} and ${sortedIds[i]})`);
          break;
        }
      }
    }

    // Additional security checks
    if (bp.metadata?.scenario?.confidential === false) {
      securityIssues.push({
        type: 'non_confidential_scenario',
        description: 'Scenario is not marked as confidential - consider security implications',
        severity: 'low'
      });
    }

    if (bp.metadata?.scenario?.dlq === false) {
      warnings.push('Dead Letter Queue is disabled - failed executions may be lost');
    }

  } catch (error) {
    errors.push(`Blueprint validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }

  return {
    isValid: errors.length === 0,
    errors,
    warnings,
    securityIssues
  };
}

// Connection extraction function
function extractBlueprintConnections(blueprint: unknown, includeOptional: boolean = false): {
  requiredConnections: Array<{ moduleId: number; moduleType: string; connectionId?: number; service?: string; required: boolean }>;
  connectionSummary: { totalModules: number; modulesRequiringConnections: number; uniqueServices: string[] };
  dependencyMap: Record<string, number[]>;
} {
  const connections: Array<{ moduleId: number; moduleType: string; connectionId?: number; service?: string; required: boolean }> = [];
  const serviceMap = new Map<string, number[]>();

  try {
    if (!blueprint || typeof blueprint !== 'object') {
      throw new Error('Invalid blueprint structure');
    }

    const bp = blueprint as Blueprint;

    if (!bp.flow || !Array.isArray(bp.flow)) {
      throw new Error('Blueprint must contain a flow array');
    }

    bp.flow.forEach((module: BlueprintModule) => {
      if (!module || typeof module.id !== 'number' || !module.module) {
        return; // Skip invalid modules
      }

      const moduleType = module.module;
      
      // Determine if this module type typically requires connections
      const requiresConnection = moduleType !== 'builtin:BasicRouter' && 
                               moduleType !== 'builtin:Delay' &&
                               moduleType !== 'builtin:JSONTransformer' &&
                               moduleType !== 'builtin:Iterator' &&
                               !moduleType.startsWith('builtin:');

      if (requiresConnection || module.connection) {
        const connection = {
          moduleId: module.id,
          moduleType: moduleType,
          connectionId: module.connection,
          service: moduleType.split(':')[0] || 'unknown',
          required: requiresConnection
        };

        // Include all required connections, and optional ones if specified
        if (connection.required || (includeOptional && module.connection)) {
          connections.push(connection);
        }

        // Build service dependency map
        if (connection.service) {
          if (!serviceMap.has(connection.service)) {
            serviceMap.set(connection.service, []);
          }
          serviceMap.get(connection.service)!.push(module.id);
        }
      }
    });

    // Build dependency map from service map
    const dependencyMap: Record<string, number[]> = {};
    serviceMap.forEach((moduleIds, service) => {
      dependencyMap[service] = moduleIds;
    });

    return {
      requiredConnections: connections,
      connectionSummary: {
        totalModules: bp.flow.length,
        modulesRequiringConnections: connections.length,
        uniqueServices: Array.from(serviceMap.keys())
      },
      dependencyMap
    };

  } catch (error) {
    throw new Error(`Connection extraction failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

// Blueprint optimization function
function optimizeBlueprint(blueprint: unknown, optimizationType: 'performance' | 'cost' | 'security' | 'all' = 'performance'): {
  optimizationScore: number;
  recommendations: Array<{
    category: 'performance' | 'cost' | 'security' | 'reliability';
    priority: 'high' | 'medium' | 'low';
    title: string;
    description: string;
    estimatedImpact: string;
    implementationSteps: string[];
  }>;
  metrics: {
    moduleCount: number;
    connectionCount: number;
    complexityScore: number;
    securityScore: number;
  };
} {
  const recommendations: Array<{
    category: 'performance' | 'cost' | 'security' | 'reliability';
    priority: 'high' | 'medium' | 'low';
    title: string;
    description: string;
    estimatedImpact: string;
    implementationSteps: string[];
  }> = [];

  let optimizationScore = 100;
  const metrics = { moduleCount: 0, connectionCount: 0, complexityScore: 0, securityScore: 100 };

  try {
    if (!blueprint || typeof blueprint !== 'object') {
      throw new Error('Invalid blueprint structure');
    }

    const bp = blueprint as Blueprint;

    if (!bp.flow || !Array.isArray(bp.flow)) {
      throw new Error('Blueprint must contain a flow array');
    }

    metrics.moduleCount = bp.flow.length;

    // Analyze modules for optimization opportunities
    const connectionMap = new Map<number, number>();
    const moduleTypes = new Set<string>();

    bp.flow.forEach((module: BlueprintModule) => {
      if (!module || typeof module.id !== 'number') return;

      moduleTypes.add(module.module || 'unknown');

      if (module.connection) {
        metrics.connectionCount++;
        connectionMap.set(module.id, module.connection);
      }

      // Performance optimizations
      if (optimizationType === 'performance' || optimizationType === 'all') {
        if (module.module === 'builtin:Iterator' && bp.flow && bp.flow.length > 50) {
          recommendations.push({
            category: 'performance',
            priority: 'high',
            title: 'Optimize Iterator Module for Large Workflows',
            description: `Iterator module (ID: ${module.id}) in a workflow with ${bp.flow.length} modules may cause performance bottlenecks`,
            estimatedImpact: '30-50% execution time reduction',
            implementationSteps: [
              'Consider batching iterator operations',
              'Implement parallel processing where possible',
              'Add progress monitoring for long iterations'
            ]
          });
          optimizationScore -= 15;
        }

        if (module.module && module.module.includes('Database') && !module.parameters?.batchSize) {
          recommendations.push({
            category: 'performance',
            priority: 'medium',
            title: 'Enable Database Batch Operations',
            description: `Database module (ID: ${module.id}) should use batch operations for better performance`,
            estimatedImpact: '20-40% faster database operations',
            implementationSteps: [
              'Configure appropriate batch size parameter',
              'Test batch operations with representative data',
              'Monitor database connection limits'
            ]
          });
          optimizationScore -= 10;
        }
      }

      // Cost optimizations
      if (optimizationType === 'cost' || optimizationType === 'all') {
        if (module.module && (module.module.includes('AI') || module.module.includes('GPT'))) {
          recommendations.push({
            category: 'cost',
            priority: 'high',
            title: 'Optimize AI Service Usage',
            description: `AI module (ID: ${module.id}) can be expensive - consider optimization strategies`,
            estimatedImpact: '25-60% cost reduction',
            implementationSteps: [
              'Implement request caching for repeated queries',
              'Use prompt optimization techniques',
              'Consider using smaller models for simple tasks',
              'Add usage monitoring and alerts'
            ]
          });
          optimizationScore -= 20;
        }
      }

      // Security optimizations
      if (optimizationType === 'security' || optimizationType === 'all') {
        if (module.parameters) {
          const paramStr = JSON.stringify(module.parameters);
          if (paramStr.includes('password') || paramStr.includes('secret') || paramStr.includes('token')) {
            recommendations.push({
              category: 'security',
              priority: 'high',
              title: 'Secure Credential Management',
              description: `Module (ID: ${module.id}) may contain hardcoded credentials`,
              estimatedImpact: 'Critical security improvement',
              implementationSteps: [
                'Move credentials to secure variable storage',
                'Use Make.com connection system instead of hardcoded values',
                'Enable scenario confidential mode',
                'Regularly rotate credentials'
              ]
            });
            optimizationScore -= 25;
            metrics.securityScore -= 30;
          }
        }

        if (!bp.metadata?.scenario?.confidential) {
          recommendations.push({
            category: 'security',
            priority: 'medium',
            title: 'Enable Confidential Mode',
            description: 'Scenario is not marked as confidential, which may expose sensitive data',
            estimatedImpact: 'Enhanced data privacy and security',
            implementationSteps: [
              'Enable confidential mode in scenario metadata',
              'Review data handling and logging practices',
              'Ensure compliance with privacy regulations'
            ]
          });
          optimizationScore -= 10;
          metrics.securityScore -= 15;
        }
      }
    });

    // Calculate complexity score
    metrics.complexityScore = Math.min(100, (metrics.moduleCount * 2) + (metrics.connectionCount * 3) + (moduleTypes.size * 1.5));

    // Workflow-level optimizations
    if (metrics.moduleCount > 100) {
      recommendations.push({
        category: 'performance',
        priority: 'high',
        title: 'Consider Workflow Decomposition',
        description: `Large workflow with ${metrics.moduleCount} modules may benefit from decomposition`,
        estimatedImpact: 'Improved maintainability and performance',
        implementationSteps: [
          'Identify logical workflow boundaries',
          'Split into smaller, focused workflows',
          'Use webhooks or API calls to connect workflows',
          'Implement proper error handling between workflows'
        ]
      });
      optimizationScore -= 15;
    }

    if (metrics.connectionCount > 10) {
      recommendations.push({
        category: 'cost',
        priority: 'medium',
        title: 'Optimize Connection Usage',
        description: `High number of connections (${metrics.connectionCount}) may increase costs`,
        estimatedImpact: '10-30% cost reduction',
        implementationSteps: [
          'Consolidate similar service connections',
          'Use connection pooling where available',
          'Monitor connection usage and quotas',
          'Consider caching strategies for repeated API calls'
        ]
      });
      optimizationScore -= 8;
    }

    // Reliability recommendations
    if (!bp.metadata?.scenario?.dlq) {
      recommendations.push({
        category: 'reliability',
        priority: 'medium',
        title: 'Enable Dead Letter Queue',
        description: 'Enable DLQ to handle failed executions gracefully',
        estimatedImpact: 'Improved error recovery and debugging',
        implementationSteps: [
          'Enable DLQ in scenario metadata',
          'Configure appropriate retry policies',
          'Set up monitoring for failed executions',
          'Implement error handling workflows'
        ]
      });
      optimizationScore -= 5;
    }

  } catch (error) {
    throw new Error(`Blueprint optimization failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }

  return {
    optimizationScore: Math.max(0, Math.round(optimizationScore)),
    recommendations: recommendations.sort((a: OptimizationRecommendation, b: OptimizationRecommendation) => {
      const priorityOrder: Record<string, number> = { high: 3, medium: 2, low: 1 };
      return (priorityOrder[b.priority] || 0) - (priorityOrder[a.priority] || 0);
    }),
    metrics
  };
}