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

  componentLogger?.info?.('Scenario management tools added successfully');
}