/**
 * @fileoverview Run Scenario Tool Implementation
 * Execute Make.com scenarios with monitoring and timeout control
 */

import { UserError } from 'fastmcp';
import { RunScenarioSchema } from '../schemas/scenario-filters.js';
import { ToolContext, ToolDefinition } from '../../shared/types/tool-context.js';
import { formatSuccessResponse } from '../../../utils/response-formatter.js';

interface RunScenarioArgs {
  scenarioId: string;
  wait?: boolean;
  timeout?: number;
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
      
      reportProgress?.({ progress: 0, total: 100 });
      
      try {
        // Get scenario details first to validate existence
        const scenarioResponse = await apiClient.get(`/scenarios/${typedArgs.scenarioId}`);
        if (!scenarioResponse.success) {
          throw new UserError(`Scenario not found: ${typedArgs.scenarioId}`);
        }
        
        const scenario = scenarioResponse.data as { 
          id: string; 
          name: string; 
          active: boolean; 
          team?: { id: string; name: string }; 
        };
        
        reportProgress?.({ progress: 20, total: 100 });
        
        // Check if scenario is active
        if (!scenario.active) {
          throw new UserError(`Cannot execute inactive scenario: ${typedArgs.scenarioId}`);
        }
        
        // Execute the scenario
        log?.info?.('Executing scenario', { scenarioId: typedArgs.scenarioId, scenarioName: scenario.name });
        const executionResponse = await apiClient.post(`/scenarios/${typedArgs.scenarioId}/run`, {
          wait: typedArgs.wait
        });
        
        if (!executionResponse.success) {
          throw new UserError(`Failed to start scenario execution: ${executionResponse.error?.message || 'Unknown error'}`);
        }
        
        reportProgress?.({ progress: 50, total: 100 });
        
        const executionData = executionResponse.data as {
          executionId: string;
          status: string;
          startedAt: string;
          scenario: { id: string; name: string };
        };
        
        const finalResult = {
          scenario: {
            id: scenario.id,
            name: scenario.name,
            team: scenario.team
          },
          execution: {
            id: executionData.executionId,
            status: executionData.status,
            startedAt: executionData.startedAt,
            completedAt: undefined as string | undefined,
            duration: undefined as number | undefined,
            result: undefined as unknown
          },
          metadata: {
            waitForCompletion: typedArgs.wait,
            timeoutSeconds: typedArgs.timeout,
            executionTimestamp: new Date().toISOString()
          }
        };
        
        // If waiting for completion, poll for status
        if (typedArgs.wait) {
          const startTime = Date.now();
          const timeoutSeconds = typedArgs.timeout || 300; // Default 5 minutes
          const timeoutMs = timeoutSeconds * 1000;
          let attempts = 0;
          const maxAttempts = Math.ceil(timeoutSeconds / 2); // Check every 2 seconds
          
          log?.info?.('Waiting for scenario execution to complete', { 
            executionId: executionData.executionId,
            timeoutSeconds: timeoutSeconds 
          });
          
          while (attempts < maxAttempts) {
            await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 seconds
            attempts++;
            
            const progress = 50 + (attempts / maxAttempts) * 45;
            reportProgress?.({ progress: Math.min(95, progress), total: 100 });
            
            try {
              const statusResponse = await apiClient.get(`/scenarios/${typedArgs.scenarioId}/executions/${executionData.executionId}`);
              
              if (statusResponse.success) {
                const statusData = statusResponse.data as {
                  id: string;
                  status: string;
                  startedAt: string;
                  completedAt?: string;
                  result?: unknown;
                  error?: unknown;
                };
                
                finalResult.execution.status = statusData.status;
                finalResult.execution.completedAt = statusData.completedAt;
                finalResult.execution.result = statusData.result;
                
                if (statusData.completedAt) {
                  finalResult.execution.duration = Math.round(
                    (new Date(statusData.completedAt).getTime() - new Date(statusData.startedAt).getTime()) / 1000
                  );
                }
                
                // Check if execution is complete
                if (['completed', 'error', 'stopped', 'failed'].includes(statusData.status)) {
                  log?.info?.('Scenario execution completed', {
                    executionId: executionData.executionId,
                    status: statusData.status,
                    duration: finalResult.execution.duration
                  });
                  break;
                }
              }
              
              // Check timeout
              if (Date.now() - startTime > timeoutMs) {
                log?.warn?.('Scenario execution timeout reached', { 
                  executionId: executionData.executionId,
                  timeoutSeconds: timeoutSeconds
                });
                finalResult.execution.status = 'timeout';
                break;
              }
              
            } catch (statusError) {
              log?.warn?.('Failed to check execution status', { 
                executionId: executionData.executionId,
                error: statusError instanceof Error ? statusError.message : String(statusError)
              });
              // Continue polling despite status check errors
            }
          }
          
          if (attempts >= maxAttempts && !finalResult.execution.completedAt) {
            finalResult.execution.status = 'timeout';
            log?.warn?.('Maximum polling attempts reached', { 
              executionId: executionData.executionId,
              attempts: attempts
            });
          }
        }
        
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