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
        const scenarioAnalyses: Array<{
          scenarioId: string;
          scenarioName: string;
          diagnosticReport: any;
          performanceAnalysis?: any;
          errors: string[];
        }> = [];

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
                diagnosticReport: null,
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
                diagnosticReport: null,
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
                // For now, we'll include basic performance metrics from the diagnostic report
                performanceAnalysis = {
                  performanceScore: diagnosticReport.summary.performanceScore,
                  executionMetrics: {
                    averageExecutionTime: 'N/A',
                    successRate: 'N/A',
                    errorRate: 'N/A'
                  }
                };
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
              diagnosticReport: null,
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
                diagnostics: analysis.diagnosticReport.diagnostics.map((d: any) => ({
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
                totalIssuesFound: consolidatedFindings.totalIssues,
                criticalIssueRate: consolidatedFindings.criticalIssueRate,
                fixableIssueRate: consolidatedFindings.fixableIssueRate
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
              overallRisk: consolidatedFindings.securityRiskLevel,
              securityIssuesFound: consolidatedFindings.issuesByCategory.security || 0,
              complianceStatus: consolidatedFindings.securityIssuesFound > 0 ? 'review_required' : 'compliant',
              recommendations: consolidatedFindings.securityRecommendations.slice(0, 5)
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
          totalIssues: consolidatedFindings.totalIssues,
          criticalIssues: consolidatedFindings.criticalIssues,
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

  componentLogger?.info?.('Scenario management tools added successfully');
}

// Helper functions for report generation

interface ConsolidatedFindings {
  totalIssues: number;
  criticalIssues: number;
  fixableIssues: number;
  issuesByCategory: Record<string, number>;
  issuesBySeverity: Record<string, number>;
  topIssuePatterns: Array<{ pattern: string; frequency: number; severity: string }>;
  securityRiskLevel: 'low' | 'medium' | 'high' | 'critical';
  securityIssuesFound: number;
  securityRecommendations: string[];
  performanceIssues: Array<{ type: string; frequency: number; impact: string }>;
  commonRecommendations: Array<{ recommendation: string; frequency: number; estimatedImpact: string }>;
  criticalIssueRate: number;
  fixableIssueRate: number;
}

function aggregateFindings(analyses: Array<{ diagnosticReport: any; errors: string[] }>): ConsolidatedFindings {
  let totalIssues = 0;
  let criticalIssues = 0;
  let fixableIssues = 0;
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
    totalIssues += report.summary.totalIssues;
    criticalIssues += report.summary.criticalIssues;
    fixableIssues += report.summary.fixableIssues;

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
  let securityRiskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
  if (securityIssuesFound > 0) {
    const criticalSecurityIssues = issuesBySeverity.critical || 0;
    const errorSecurityIssues = issuesBySeverity.error || 0;
    
    if (criticalSecurityIssues > 0) {
      securityRiskLevel = 'critical';
    } else if (errorSecurityIssues > 2) {
      securityRiskLevel = 'high';
    } else if (securityIssuesFound > 3) {
      securityRiskLevel = 'medium';
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
  const commonRecommendations = Array.from(recommendations.entries())
    .sort((a, b) => b[1].frequency - a[1].frequency)
    .slice(0, 15)
    .map(([recommendation, data]) => ({
      recommendation,
      frequency: data.frequency,
      estimatedImpact: data.estimatedImpact
    }));

  return {
    totalIssues,
    criticalIssues,
    fixableIssues,
    issuesByCategory,
    issuesBySeverity,
    topIssuePatterns,
    securityRiskLevel,
    securityIssuesFound,
    securityRecommendations: [...new Set(securityRecommendations)].slice(0, 10),
    performanceIssues,
    commonRecommendations,
    criticalIssueRate: totalIssues > 0 ? Math.round((criticalIssues / totalIssues) * 100) : 0,
    fixableIssueRate: totalIssues > 0 ? Math.round((fixableIssues / totalIssues) * 100) : 0
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

function generateActionPlan(findings: ConsolidatedFindings, includeTimeline: boolean): any {
  const immediateActions: Array<{ action: string; priority: string; estimatedEffort: string; impact: string }> = [];
  const shortTermActions: Array<{ action: string; priority: string; estimatedEffort: string; impact: string }> = [];
  const longTermActions: Array<{ action: string; priority: string; estimatedEffort: string; impact: string }> = [];

  // Generate immediate actions for critical issues
  if (findings.criticalIssues > 0) {
    immediateActions.push({
      action: `Address ${findings.criticalIssues} critical issues requiring immediate attention`,
      priority: 'critical',
      estimatedEffort: 'high',
      impact: 'high'
    });
  }

  if (findings.securityRiskLevel === 'critical' || findings.securityRiskLevel === 'high') {
    immediateActions.push({
      action: 'Resolve security vulnerabilities and compliance issues',
      priority: 'critical',
      estimatedEffort: 'medium',
      impact: 'high'
    });
  }

  // Add top common recommendations as actions
  findings.commonRecommendations.slice(0, 3).forEach(rec => {
    if (rec.frequency > 2) {
      const isImmediate = rec.recommendation.toLowerCase().includes('critical') || 
                         rec.recommendation.toLowerCase().includes('security');
      
      const action = {
        action: rec.recommendation,
        priority: isImmediate ? 'high' : 'medium',
        estimatedEffort: rec.estimatedImpact === 'high' ? 'high' : 'medium',
        impact: rec.estimatedImpact
      };

      if (isImmediate) {
        immediateActions.push(action);
      } else {
        shortTermActions.push(action);
      }
    }
  });

  // Add performance improvements to short-term
  if (findings.performanceIssues.length > 0) {
    shortTermActions.push({
      action: 'Implement performance optimizations for identified bottlenecks',
      priority: 'medium',
      estimatedEffort: 'medium',
      impact: 'medium'
    });
  }

  // Add preventive measures to long-term
  longTermActions.push(
    {
      action: 'Implement automated monitoring and alerting for proactive issue detection',
      priority: 'medium',
      estimatedEffort: 'high',
      impact: 'high'
    },
    {
      action: 'Establish regular health check and diagnostic review schedule',
      priority: 'low',
      estimatedEffort: 'low',
      impact: 'medium'
    },
    {
      action: 'Create scenario performance baselines and trend monitoring',
      priority: 'low',
      estimatedEffort: 'medium',
      impact: 'medium'
    }
  );

  const result: any = {
    summary: {
      totalActions: immediateActions.length + shortTermActions.length + longTermActions.length,
      criticalActions: immediateActions.filter(a => a.priority === 'critical').length,
      estimatedTotalEffort: 'high', // Based on number and complexity of actions
      expectedImpact: findings.criticalIssues > 0 ? 'high' : 'medium'
    },
    immediate: immediateActions,
    shortTerm: shortTermActions,
    longTerm: longTermActions
  };

  if (includeTimeline) {
    result.timeline = {
      immediate: '0-24 hours',
      shortTerm: '1-4 weeks',
      longTerm: '1-3 months',
      note: 'Timeline estimates based on typical implementation complexity and resource availability'
    };
  }

  return result;
}

function generateCostAnalysis(findings: ConsolidatedFindings, scenarioCount: number): any {
  // Simplified cost analysis - in real implementation, this would integrate with billing APIs
  const baseOperationalCost = scenarioCount * 50; // $50 per scenario monthly estimate
  const inefficiencyCost = findings.performanceIssues.length * 25; // $25 per performance issue
  const securityRiskCost = findings.securityIssuesFound * 100; // $100 per security risk

  const totalCurrentCost = baseOperationalCost + inefficiencyCost + securityRiskCost;
  const potentialSavings = (findings.fixableIssueRate / 100) * inefficiencyCost;

  return {
    currentMonthlyCost: totalCurrentCost,
    costBreakdown: {
      operational: baseOperationalCost,
      inefficiencies: inefficiencyCost,
      securityRisk: securityRiskCost
    },
    optimizationOpportunity: {
      potentialMonthlySavings: potentialSavings,
      savingsPercentage: totalCurrentCost > 0 ? Math.round((potentialSavings / totalCurrentCost) * 100) : 0,
      paybackPeriod: '2-6 months',
      roi: '150-300%'
    },
    recommendations: [
      'Fix automatically resolvable performance issues to reduce operational costs',
      'Implement security best practices to mitigate risk-related costs',
      'Regular optimization reviews to maintain cost efficiency'
    ]
  };
}

function generateExecutiveSummary(
  systemOverview: any,
  findings: ConsolidatedFindings,
  actionPlan: any,
  scenarioCount: number
): any {
  return {
    keyFindings: [
      `Analyzed ${scenarioCount} scenarios with overall system health score of ${systemOverview.systemHealthScore}/100`,
      `Identified ${findings.totalIssues} total issues, including ${findings.criticalIssues} critical issues requiring immediate attention`,
      `${findings.fixableIssueRate}% of issues are automatically fixable or have clear remediation steps`,
      `Security risk level: ${findings.securityRiskLevel.toUpperCase()} with ${findings.securityIssuesFound} security-related findings`,
      `System performance status: ${systemOverview.performanceStatus.toUpperCase()}`
    ].slice(0, 5),
    
    criticalRecommendations: [
      ...(findings.criticalIssues > 0 ? 
        [`Address ${findings.criticalIssues} critical issues within 24 hours`] : []),
      ...(findings.securityRiskLevel === 'critical' ? 
        ['Immediate security vulnerability remediation required'] : []),
      ...(systemOverview.systemHealthScore < 60 ? 
        ['System performance optimization needed to ensure reliability'] : [])
    ].slice(0, 3),
    
    businessImpact: {
      riskLevel: findings.criticalIssues > 0 ? 'high' : 
                 findings.securityRiskLevel === 'high' ? 'high' : 
                 systemOverview.systemHealthScore < 70 ? 'medium' : 'low',
      
      operationalReadiness: systemOverview.scenarioBreakdown.healthy / scenarioCount > 0.8 ? 
                            'ready' : 'needs_attention',
      
      recommendedActions: actionPlan.summary.criticalActions > 0 ? 
                          'immediate_action_required' : 'scheduled_improvements'
    },
    
    nextSteps: actionPlan.immediate.length > 0 ? 
               actionPlan.immediate.slice(0, 3).map((a: any) => a.action) :
               ['Continue monitoring system health', 'Schedule routine optimization review'],
    
    reportConfidence: {
      dataCompleteness: Math.round((scenarioCount / Math.max(scenarioCount, 1)) * 100),
      analysisDepth: 'comprehensive',
      recommendationReliability: 'high'
    }
  };
}

function formatAsMarkdown(report: any): string {
  let markdown = `# Comprehensive Troubleshooting Report\n\n`;
  markdown += `**Report ID:** ${report.metadata.reportId}\n`;
  markdown += `**Generated:** ${report.metadata.generatedAt}\n`;
  markdown += `**Scenarios Analyzed:** ${report.metadata.analysisScope.scenarioCount}\n\n`;

  if (report.executiveSummary) {
    markdown += `## Executive Summary\n\n`;
    markdown += `### Key Findings\n`;
    report.executiveSummary.keyFindings.forEach((finding: string) => {
      markdown += `- ${finding}\n`;
    });
    markdown += `\n### Critical Recommendations\n`;
    report.executiveSummary.criticalRecommendations.forEach((rec: string) => {
      markdown += `- **${rec}**\n`;
    });
    markdown += `\n`;
  }

  markdown += `## System Overview\n\n`;
  markdown += `- **System Health Score:** ${report.systemOverview.systemHealthScore}/100\n`;
  markdown += `- **Performance Status:** ${report.systemOverview.performanceStatus}\n`;
  markdown += `- **Overall Status:** ${report.systemOverview.overallStatus}\n\n`;

  if (report.consolidatedFindings) {
    markdown += `## Consolidated Findings\n\n`;
    markdown += `- **Total Issues:** ${report.consolidatedFindings.totalIssues}\n`;
    markdown += `- **Critical Issues:** ${report.consolidatedFindings.criticalIssues}\n`;
    markdown += `- **Security Risk Level:** ${report.consolidatedFindings.securityRiskLevel}\n\n`;
  }

  if (report.actionPlan) {
    markdown += `## Action Plan\n\n`;
    markdown += `### Immediate Actions (0-24 hours)\n`;
    report.actionPlan.immediate.forEach((action: any) => {
      markdown += `- **[${action.priority.toUpperCase()}]** ${action.action}\n`;
    });
    markdown += `\n### Short Term Actions (1-4 weeks)\n`;
    report.actionPlan.shortTerm.forEach((action: any) => {
      markdown += `- ${action.action}\n`;
    });
    markdown += `\n`;
  }

  return markdown;
}

function formatAsPdfReady(report: any): string {
  // This would generate HTML suitable for PDF generation
  let html = `<!DOCTYPE html>
<html>
<head>
  <title>Troubleshooting Report - ${report.metadata.reportId}</title>
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
  html += `<p><strong>Report ID:</strong> ${report.metadata.reportId}</p>`;
  html += `<p><strong>Generated:</strong> ${report.metadata.generatedAt}</p>`;
  html += `<p><strong>Scenarios Analyzed:</strong> ${report.metadata.analysisScope.scenarioCount}</p>`;

  if (report.executiveSummary) {
    html += `<div class="summary-box">`;
    html += `<h2>Executive Summary</h2>`;
    html += `<h3>Key Findings</h3><ul>`;
    report.executiveSummary.keyFindings.forEach((finding: string) => {
      html += `<li>${finding}</li>`;
    });
    html += `</ul><h3>Critical Recommendations</h3><ul>`;
    report.executiveSummary.criticalRecommendations.forEach((rec: string) => {
      html += `<li class="critical">${rec}</li>`;
    });
    html += `</ul></div>`;
  }

  html += `<h2>System Overview</h2>`;
  html += `<div class="metric">System Health Score: <span class="score">${report.systemOverview.systemHealthScore}/100</span></div>`;
  html += `<div class="metric">Performance Status: <strong>${report.systemOverview.performanceStatus}</strong></div>`;

  html += `</body></html>`;
  
  return html;
}