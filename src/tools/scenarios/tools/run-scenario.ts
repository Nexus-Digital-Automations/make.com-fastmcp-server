/**
 * @fileoverview Run Scenario Tool Implementation
 * Executes a Make.com scenario with monitoring and timeout options
 */

import { UserError } from 'fastmcp';
import { RunScenarioSchema } from '../schemas/scenario-crud.js';
import { ToolContext, ToolDefinition } from '../../shared/types/tool-context.js';

/**
 * Create run scenario tool configuration
 */
export function createRunScenarioTool(context: ToolContext): ToolDefinition {
  const { apiClient, logger } = context;
  
  return {
    name: 'run-scenario',
    description: 'Execute a Make.com scenario and optionally wait for completion',
    parameters: RunScenarioSchema,
    annotations: {
      title: 'Run Scenario',
      readOnlyHint: false,
      openWorldHint: false,
    },
    execute: async (args: unknown, { log, reportProgress }) => {
      const typedArgs = args as {
        scenarioId: string;
        wait?: boolean;
        timeout?: number;
      };
      
      log?.info?.('Running scenario', { 
        scenarioId: typedArgs.scenarioId, 
        wait: typedArgs.wait,
        timeout: typedArgs.timeout 
      });
      reportProgress?.({ progress: 0, total: 100 });

      try {
        // Start scenario execution
        const response = await apiClient.post(`/scenarios/${typedArgs.scenarioId}/run`);
        reportProgress?.({ progress: 25, total: 100 });

        if (!response.success) {
          throw new UserError(`Failed to start scenario execution: ${response.error?.message}`);
        }

        const execution = response.data;
        
        // Type guard for execution object
        const executionObj = execution as { id?: unknown; status?: unknown } | null | undefined;
        
        let result: Record<string, unknown> = {
          scenarioId: typedArgs.scenarioId,
          executionId: executionObj?.id,
          status: executionObj?.status || 'started',
          message: 'Scenario execution started',
          timestamp: new Date().toISOString(),
        };

        // If wait is false, return immediately
        if (!typedArgs.wait) {
          reportProgress?.({ progress: 100, total: 100 });
          log?.info?.('Scenario execution started (not waiting)', { 
            scenarioId: typedArgs.scenarioId,
            executionId: String(executionObj?.id ?? 'unknown')
          });
          return JSON.stringify(result, null, 2);
        }

        // Wait for completion
        const startTime = Date.now();
        const timeoutMs = (typedArgs.timeout || 60) * 1000;
        
        while (Date.now() - startTime < timeoutMs) {
          await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 seconds
          
          const statusResponse = await apiClient.get(`/scenarios/${typedArgs.scenarioId}/executions/${executionObj?.id}`);
          if (statusResponse.success) {
            const currentExecution = statusResponse.data;
            
            // Type guard for current execution object
            const currentExecutionObj = currentExecution as { status?: unknown } | null | undefined;
            
            const progress = Math.min(25 + ((Date.now() - startTime) / timeoutMs) * 75, 99);
            reportProgress?.({ progress, total: 100 });

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

        reportProgress?.({ progress: 100, total: 100 });

        if (result.status === 'started') {
          result.message = 'Scenario execution timeout - check status manually';
          result.timeout = true;
        }

        log?.info?.('Scenario execution completed', { 
          scenarioId: typedArgs.scenarioId,
          executionId: String(executionObj?.id ?? 'unknown'),
          status: String(result.status ?? 'unknown'),
          duration: Number(result.duration ?? 0)
        });

        return JSON.stringify(result, null, 2);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        logger.error?.('Failed to run scenario', { 
          scenarioId: typedArgs.scenarioId, 
          error: errorMessage 
        });
        throw new UserError(`Failed to run scenario: ${errorMessage}`);
      }
    },
  };
}