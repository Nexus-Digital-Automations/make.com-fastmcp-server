/**
 * Make.com Scenario Management Tools
 * Provides comprehensive CRUD operations for Make.com scenarios
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

export function addScenarioTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'ScenarioTools' });

  // List scenarios with advanced filtering
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
      log.info('Listing scenarios', { filters: args });
      reportProgress({ progress: 0, total: 100 });

      try {
        // Build query parameters
        const params: Record<string, any> = {
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

        const result = {
          scenarios: scenarios || [],
          pagination: {
            total: metadata?.total || scenarios?.length || 0,
            limit: args.limit,
            offset: args.offset,
            hasMore: (metadata?.total || 0) > (args.offset + args.limit),
          },
          filters: args,
          timestamp: new Date().toISOString(),
        };

        log.info('Scenarios listed successfully', { 
          count: result.scenarios.length,
          total: result.pagination.total 
        });

        return JSON.stringify(result, null, 2);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Failed to list scenarios', { error: errorMessage });
        throw new UserError(`Failed to list scenarios: ${errorMessage}`);
      }
    },
  });

  // Get detailed scenario information
  server.addTool({
    name: 'get-scenario',
    description: 'Get detailed information about a specific Make.com scenario',
    parameters: ScenarioDetailSchema,
    annotations: {
      title: 'Get Scenario Details',
      readOnlyHint: true,
    },
    execute: async (args, { log, reportProgress }) => {
      log.info('Getting scenario details', { scenarioId: args.scenarioId });
      reportProgress({ progress: 0, total: 100 });

      try {
        const response = await apiClient.get(`/scenarios/${args.scenarioId}`);
        reportProgress({ progress: 50, total: 100 });

        if (!response.success) {
          throw new UserError(`Failed to get scenario: ${response.error?.message}`);
        }

        const scenario = response.data;
        const result: any = {
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

        log.info('Scenario details retrieved successfully', { scenarioId: args.scenarioId });
        return JSON.stringify(result, null, 2);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Failed to get scenario', { scenarioId: args.scenarioId, error: errorMessage });
        throw new UserError(`Failed to get scenario: ${errorMessage}`);
      }
    },
  });

  // Create new scenario
  server.addTool({
    name: 'create-scenario',
    description: 'Create a new Make.com scenario with optional configuration',
    parameters: CreateScenarioSchema,
    annotations: {
      title: 'Create Scenario',
    },
    execute: async (args, { log, reportProgress }) => {
      log.info('Creating scenario', { name: args.name, teamId: args.teamId });
      reportProgress({ progress: 0, total: 100 });

      try {
        const scenarioData: any = {
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

        log.info('Scenario created successfully', { 
          scenarioId: createdScenario?.id,
          name: args.name 
        });

        return JSON.stringify(result, null, 2);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Failed to create scenario', { name: args.name, error: errorMessage });
        throw new UserError(`Failed to create scenario: ${errorMessage}`);
      }
    },
  });

  // Update existing scenario
  server.addTool({
    name: 'update-scenario',
    description: 'Update an existing Make.com scenario configuration',
    parameters: UpdateScenarioSchema,
    annotations: {
      title: 'Update Scenario',
    },
    execute: async (args, { log, reportProgress }) => {
      log.info('Updating scenario', { scenarioId: args.scenarioId });
      reportProgress({ progress: 0, total: 100 });

      try {
        const updateData: any = {};
        
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

        log.info('Scenario updated successfully', { scenarioId: args.scenarioId });
        return JSON.stringify(result, null, 2);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Failed to update scenario', { scenarioId: args.scenarioId, error: errorMessage });
        throw new UserError(`Failed to update scenario: ${errorMessage}`);
      }
    },
  });

  // Delete scenario
  server.addTool({
    name: 'delete-scenario',
    description: 'Delete a Make.com scenario (with optional force delete)',
    parameters: DeleteScenarioSchema,
    annotations: {
      title: 'Delete Scenario',
    },
    execute: async (args, { log, reportProgress }) => {
      log.info('Deleting scenario', { scenarioId: args.scenarioId, force: args.force });
      reportProgress({ progress: 0, total: 100 });

      try {
        // Check if scenario exists and is active (unless force is true)
        if (!args.force) {
          const scenarioResponse = await apiClient.get(`/scenarios/${args.scenarioId}`);
          if (!scenarioResponse.success) {
            throw new UserError(`Scenario not found: ${args.scenarioId}`);
          }

          const scenario = scenarioResponse.data;
          if (scenario.active) {
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

        log.info('Scenario deleted successfully', { scenarioId: args.scenarioId });
        return JSON.stringify(result, null, 2);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Failed to delete scenario', { scenarioId: args.scenarioId, error: errorMessage });
        throw new UserError(`Failed to delete scenario: ${errorMessage}`);
      }
    },
  });

  // Clone scenario
  server.addTool({
    name: 'clone-scenario',
    description: 'Clone an existing Make.com scenario with a new name',
    parameters: CloneScenarioSchema,
    annotations: {
      title: 'Clone Scenario',
    },
    execute: async (args, { log, reportProgress }) => {
      log.info('Cloning scenario', { 
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
        const cloneData: any = {
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

        log.info('Scenario cloned successfully', { 
          sourceId: args.scenarioId,
          cloneId: clonedScenario?.id,
          name: args.name 
        });

        return JSON.stringify(result, null, 2);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Failed to clone scenario', { scenarioId: args.scenarioId, error: errorMessage });
        throw new UserError(`Failed to clone scenario: ${errorMessage}`);
      }
    },
  });

  // Run scenario
  server.addTool({
    name: 'run-scenario',
    description: 'Execute a Make.com scenario and optionally wait for completion',
    parameters: RunScenarioSchema,
    annotations: {
      title: 'Run Scenario',
    },
    execute: async (args, { log, reportProgress }) => {
      log.info('Running scenario', { 
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
        let result: any = {
          scenarioId: args.scenarioId,
          executionId: execution.id,
          status: execution.status || 'started',
          message: 'Scenario execution started',
          timestamp: new Date().toISOString(),
        };

        // If wait is false, return immediately
        if (!args.wait) {
          reportProgress({ progress: 100, total: 100 });
          log.info('Scenario execution started (not waiting)', { 
            scenarioId: args.scenarioId,
            executionId: execution.id 
          });
          return JSON.stringify(result, null, 2);
        }

        // Wait for completion
        const startTime = Date.now();
        const timeoutMs = args.timeout * 1000;
        
        while (Date.now() - startTime < timeoutMs) {
          await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 seconds
          
          const statusResponse = await apiClient.get(`/scenarios/${args.scenarioId}/executions/${execution.id}`);
          if (statusResponse.success) {
            const currentExecution = statusResponse.data;
            const progress = Math.min(25 + ((Date.now() - startTime) / timeoutMs) * 75, 99);
            reportProgress({ progress, total: 100 });

            if (currentExecution.status === 'success' || currentExecution.status === 'error') {
              result = {
                ...result,
                status: currentExecution.status,
                execution: currentExecution,
                duration: Date.now() - startTime,
                message: `Scenario execution ${currentExecution.status}`,
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

        log.info('Scenario execution completed', { 
          scenarioId: args.scenarioId,
          executionId: execution.id,
          status: result.status,
          duration: result.duration 
        });

        return JSON.stringify(result, null, 2);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Failed to run scenario', { scenarioId: args.scenarioId, error: errorMessage });
        throw new UserError(`Failed to run scenario: ${errorMessage}`);
      }
    },
  });

  componentLogger.info('Scenario management tools added successfully');
}