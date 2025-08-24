/**
 * Procedures Tool - Refactored Extract Method Pattern
 * Reduced complexity from 25 to 8-12 through method extraction
 */

import { z } from 'zod';
import { apiClient } from '../lib/make-api-client.js';
import { formatSuccessResponse } from '../lib/response-formatter.js';
import { UserError } from '../lib/errors.js';
import type { 
  RemoteProcedureCreateSchema, 
  MakeRemoteProcedure,
  ToolContext,
  ProgressReporter,
  Logger
} from './types.js';

/**
 * Procedure creation context - extracted for type safety
 */
interface ProcedureCreationContext {
  log: Logger;
  reportProgress: ProgressReporter;
}

/**
 * Procedure creation parameters - organized for clarity
 */
interface ProcedureCreationParams {
  name: string;
  description: string;
  type: string;
  category: string;
  organizationId?: string;
  teamId?: string;
  configuration: any;
  input: any;
  output: any;
  monitoring: any;
  security: any;
}

/**
 * Endpoint resolver - extracted method (Complexity: 3)
 */
function resolveEndpoint(organizationId?: string, teamId?: string): string {
  if (organizationId) {
    return `/organizations/${organizationId}/remote-procedures`;
  }
  if (teamId) {
    return `/teams/${teamId}/remote-procedures`;
  }
  return '/remote-procedures';
}

/**
 * Procedure data builder - extracted method (Complexity: 2)
 */
function buildProcedureData(params: ProcedureCreationParams): any {
  return {
    name: params.name,
    description: params.description,
    type: params.type,
    category: params.category,
    organizationId: params.organizationId,
    teamId: params.teamId,
    configuration: params.configuration,
    input: params.input,
    output: params.output,
    monitoring: buildProcedureMonitoring(params.monitoring),
    security: buildProcedureSecurity(params.security),
    status: 'active',
  };
}

/**
 * Response formatter - extracted method (Complexity: 4)
 */
function formatProcedureResponse(procedure: MakeRemoteProcedure, name: string): string {
  return formatSuccessResponse({
    procedure: {
      ...procedure,
      configuration: {
        ...procedure.configuration,
        // Mask sensitive credentials
        endpoint: procedure.configuration.endpoint ? {
          ...procedure.configuration.endpoint,
          authentication: {
            ...procedure.configuration.endpoint.authentication,
            credentials: procedure.configuration.endpoint.authentication.credentials ? 
              '[CREDENTIALS_STORED]' : undefined,
          },
        } : undefined,
        script: procedure.configuration.script ? {
          ...procedure.configuration.script,
          code: '[SCRIPT_CODE_STORED]',
        } : undefined,
      },
    },
    message: `Remote procedure "${name}" created successfully`,
    configuration: {
      type: procedure.type,
      category: procedure.category,
      healthCheckEnabled: procedure.monitoring.healthCheck.enabled,
      alertsConfigured: procedure.monitoring.alerts.length,
      rateLimitingEnabled: procedure.security.rateLimiting.enabled,
      approvalRequired: procedure.security.requiresApproval,
    },
    testUrl: `/remote-procedures/${procedure.id}/test`,
  }).content[0].text;
}

/**
 * Progress reporter helper - extracted method (Complexity: 2)
 */
function reportStageProgress(reportProgress: ProgressReporter, stage: number, total: number = 100): void {
  if (reportProgress) {
    reportProgress({ progress: stage, total });
  }
}

/**
 * Logger helper - extracted method (Complexity: 2)
 */
function logInfo(log: Logger, message: string, data?: any): void {
  if (log?.info) {
    log.info(message, data);
  }
}

/**
 * Logger error helper - extracted method (Complexity: 2)
 */
function logError(log: Logger, message: string, data?: any): void {
  if (log?.error) {
    log.error(message, data);
  }
}

/**
 * API call executor - extracted method (Complexity: 5)
 */
async function createProcedureViaAPI(
  endpoint: string, 
  procedureData: any, 
  context: ProcedureCreationContext
): Promise<MakeRemoteProcedure> {
  const response = await apiClient.post(endpoint, procedureData);

  if (!response.success) {
    throw new UserError(`Failed to create remote procedure: ${response.error?.message || 'Unknown error'}`);
  }

  const procedure = response.data as MakeRemoteProcedure;
  if (!procedure) {
    throw new UserError('Remote procedure creation failed - no data returned');
  }

  return procedure;
}

/**
 * Refactored execute method - Complexity: 8 (reduced from 25)
 */
export async function createRemoteProcedure(
  input: ProcedureCreationParams,
  context: ToolContext
): Promise<string> {
  const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} }, reportProgress = (): void => {} } = context || {};
  
  logInfo(log, 'Creating remote procedure', {
    name: input.name,
    type: input.type,
    category: input.category,
    organizationId: input.organizationId,
    teamId: input.teamId,
  });

  try {
    reportStageProgress(reportProgress, 0);
    
    // Validate configuration based on procedure type
    validateProcedureConfiguration(input.type, input.configuration);
    reportStageProgress(reportProgress, 25);

    // Build procedure data
    const procedureData = buildProcedureData(input);
    reportStageProgress(reportProgress, 50);

    // Determine API endpoint
    const endpoint = resolveEndpoint(input.organizationId, input.teamId);
    
    // Create procedure via API
    const procedure = await createProcedureViaAPI(endpoint, procedureData, { log, reportProgress });
    reportStageProgress(reportProgress, 100);

    logInfo(log, 'Successfully created remote procedure', {
      procedureId: procedure.id,
      name: procedure.name,
      type: procedure.type,
      category: procedure.category,
    });

    return formatProcedureResponse(procedure, input.name);
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logError(log, 'Error creating remote procedure', { name: input.name, error: errorMessage });
    
    if (error instanceof UserError) {
      throw error;
    }
    throw new UserError(`Failed to create remote procedure: ${errorMessage}`);
  }
}

// Helper functions that need to be imported or implemented
declare function validateProcedureConfiguration(type: string, configuration: any): void;
declare function buildProcedureMonitoring(monitoring: any): any;
declare function buildProcedureSecurity(security: any): any;