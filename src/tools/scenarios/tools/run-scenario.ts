/**
 * @fileoverview Run Scenario Tool Implementation
 * Execute Make.com scenarios with monitoring and timeout control
 */

import { UserError } from 'fastmcp';
import { RunScenarioSchema } from '../schemas/scenario-filters.js';
import { ToolContext, ToolDefinition } from '../../shared/types/tool-context.js';
import { formatSuccessResponse } from '../../../utils/response-formatter.js';
import MakeApiClient from '../../../lib/make-api-client.js';

// Type definitions
interface LogInterface {
  info?: (message: string, meta?: unknown) => void;
  error?: (message: string, meta?: unknown) => void;
  warn?: (message: string, meta?: unknown) => void;
  debug?: (message: string, meta?: unknown) => void;
}

interface RunScenarioArgs {
  scenarioId: string;
  wait?: boolean;
  timeout?: number;
}

interface ScenarioData {
  id: string;
  name: string;
  active: boolean;
  team?: { id: string; name: string };
}

interface ExecutionData {
  executionId: string;
  status: string;
  startedAt: string;
  scenario: { id: string; name: string };
}

interface FinalResult {
  scenario: {
    id: string;
    name: string;
    team?: { id: string; name: string };
  };
  execution: {
    id: string;
    status: string;
    startedAt: string;
    completedAt?: string;
    duration?: number;
    result?: unknown;
  };
  metadata: {
    waitForCompletion: boolean;
    timeoutSeconds?: number;
    executionTimestamp: string;
  };
}

/**
 * Validate scenario existence and active status
 */
async function validateScenario(
  apiClient: MakeApiClient,
  scenarioId: string,
  log?: LogInterface
): Promise<ScenarioData> {
  const scenarioResponse = await apiClient.get(`/scenarios/${scenarioId}`);
  if (!scenarioResponse.success) {
    throw new UserError(`Scenario not found: ${scenarioId}`);
  }
  
  const scenario = scenarioResponse.data as ScenarioData;
  
  if (!scenario.active) {
    throw new UserError(`Cannot execute inactive scenario: ${scenarioId}`);
  }
  
  log?.info?.('Scenario validated successfully', { 
    scenarioId: scenario.id, 
    scenarioName: scenario.name 
  });
  
  return scenario;
}

/**
 * Execute scenario and get initial execution data
 */
async function executeScenario(
  apiClient: MakeApiClient,
  scenarioId: string,
  wait: boolean,
  log?: LogInterface
): Promise<ExecutionData> {
  log?.info?.('Executing scenario', { scenarioId });
  
  const executionResponse = await apiClient.post(`/scenarios/${scenarioId}/run`, {
    wait
  });
  
  if (!executionResponse.success) {
    throw new UserError(`Failed to start scenario execution: ${executionResponse.error?.message || 'Unknown error'}`);
  }
  
  const executionData = executionResponse.data as ExecutionData;
  
  log?.info?.('Scenario execution started', { 
    scenarioId, 
    executionId: executionData.executionId 
  });
  
  return executionData;
}

/**
 * Poll for execution completion with timeout handling
 */
async function pollExecutionStatus(
  apiClient: MakeApiClient,
  scenarioId: string,
  executionId: string,
  timeoutSeconds: number,
  reportProgress?: (progress: { progress: number; total: number }) => void,
  log?: LogInterface
): Promise<{ status: string; completedAt?: string; duration?: number; result?: unknown }> {
  const startTime = Date.now();
  const timeoutMs = timeoutSeconds * 1000;
  let attempts = 0;
  const maxAttempts = Math.ceil(timeoutSeconds / 2);
  
  log?.info?.('Waiting for scenario execution to complete', { 
    executionId,
    timeoutSeconds 
  });
  
  while (attempts < maxAttempts) {
    await new Promise(resolve => setTimeout(resolve, 2000));
    attempts++;
    
    const progress = 50 + (attempts / maxAttempts) * 45;
    reportProgress?.({ progress: Math.min(95, progress), total: 100 });
    
    try {
      const statusResponse = await apiClient.get(`/scenarios/${scenarioId}/executions/${executionId}`);
      
      if (statusResponse.success) {
        const statusData = statusResponse.data as {
          id: string;
          status: string;
          startedAt: string;
          completedAt?: string;
          result?: unknown;
          error?: unknown;
        };
        
        let duration: number | undefined;
        if (statusData.completedAt) {
          duration = Math.round(
            (new Date(statusData.completedAt).getTime() - new Date(statusData.startedAt).getTime()) / 1000
          );
        }
        
        if (['completed', 'error', 'stopped', 'failed'].includes(statusData.status)) {
          log?.info?.('Scenario execution completed', {
            executionId,
            status: statusData.status,
            duration
          });
          
          return {
            status: statusData.status,
            completedAt: statusData.completedAt,
            duration,
            result: statusData.result
          };
        }
      }
      
      if (Date.now() - startTime > timeoutMs) {
        log?.warn?.('Scenario execution timeout reached', { 
          executionId,
          timeoutSeconds
        });
        return { status: 'timeout' };
      }
      
    } catch (statusError) {
      log?.warn?.('Failed to check execution status', { 
        executionId,
        error: statusError instanceof Error ? statusError.message : String(statusError)
      });
    }
  }
  
  if (attempts >= maxAttempts) {
    log?.warn?.('Maximum polling attempts reached', { 
      executionId,
      attempts
    });
    return { status: 'timeout' };
  }
  
  return { status: 'unknown' };
}

/**
 * Assemble final result from scenario and execution data
 */
function assembleFinalResult(
  scenario: ScenarioData,
  executionData: ExecutionData,
  executionStatus: { status: string; completedAt?: string; duration?: number; result?: unknown },
  args: RunScenarioArgs
): FinalResult {
  return {
    scenario: {
      id: scenario.id,
      name: scenario.name,
      team: scenario.team
    },
    execution: {
      id: executionData.executionId,
      status: executionStatus.status,
      startedAt: executionData.startedAt,
      completedAt: executionStatus.completedAt,
      duration: executionStatus.duration,
      result: executionStatus.result
    },
    metadata: {
      waitForCompletion: args.wait || false,
      timeoutSeconds: args.timeout,
      executionTimestamp: new Date().toISOString()
    }
  };
}

/**
 * Create run scenario tool configuration
 */
export function createRunScenarioTool(context: ToolContext): ToolDefinition {
  const { apiClient, logger: _logger } = context;
  
  return {
    name: 'run-scenario',
    description: 'Execute Make.com scenarios with monitoring, timeout control, and execution tracking',
    parameters: RunScenarioSchema,
    annotations: {
      title: 'Run Scenario',
      readOnlyHint: false, // Executes scenarios, not read-only
      openWorldHint: false,
    },
    execute: async (args: unknown, context): Promise<string> => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} }, reportProgress = (): void => {} } = context || {};
      const typedArgs = args as RunScenarioArgs;
      
      log?.info?.('Starting scenario execution', { 
        scenarioId: typedArgs.scenarioId,
        wait: typedArgs.wait,
        timeout: typedArgs.timeout
      });
      
      try {
        reportProgress?.({ progress: 0, total: 100 });
        
        // Step 1: Validate scenario
        const scenario = await validateScenario(apiClient, typedArgs.scenarioId, log);
        reportProgress?.({ progress: 20, total: 100 });
        
        // Step 2: Execute scenario
        const executionData = await executeScenario(apiClient, typedArgs.scenarioId, typedArgs.wait || false, log);
        reportProgress?.({ progress: 50, total: 100 });
        
        // Step 3: Handle polling if waiting for completion
        let executionStatus = {
          status: executionData.status,
          completedAt: undefined as string | undefined,
          duration: undefined as number | undefined,
          result: undefined as unknown
        };
        
        if (typedArgs.wait) {
          const timeoutSeconds = typedArgs.timeout || 300;
          executionStatus = await pollExecutionStatus(
            apiClient,
            typedArgs.scenarioId,
            executionData.executionId,
            timeoutSeconds,
            reportProgress,
            log
          );
        }
        
        // Step 4: Assemble final result
        const finalResult = assembleFinalResult(scenario, executionData, executionStatus, typedArgs);
        
        reportProgress?.({ progress: 100, total: 100 });
        
        log?.info?.('Scenario execution request completed', {
          scenarioId: typedArgs.scenarioId,
          executionId: executionData.executionId,
          finalStatus: finalResult.execution.status,
          waitedForCompletion: typedArgs.wait,
          duration: finalResult.execution.duration
        });
        
        return formatSuccessResponse(finalResult).content[0].text;
        
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log?.error?.('Scenario execution failed', { 
          scenarioId: typedArgs.scenarioId,
          error: errorMessage 
        });
        throw new UserError(`Scenario execution failed: ${errorMessage}`);
      }
    }
  };
}