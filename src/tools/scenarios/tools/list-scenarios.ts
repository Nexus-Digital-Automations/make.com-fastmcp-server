/**
 * @fileoverview List Scenarios Tool Implementation
 * Single-responsibility tool with focused functionality for listing and searching scenarios
 */

import { UserError } from 'fastmcp';
import { ScenarioFiltersSchema } from '../schemas/scenario-filters.js';
import { ToolContext, ToolDefinition } from '../../shared/types/tool-context.js';
import { formatSuccessResponse } from '../../../utils/response-formatter.js';
import type MakeApiClient from '../../../lib/make-api-client.js';

/**
 * Create list scenarios tool configuration
 */
export function createListScenariosTools(context: ToolContext): ToolDefinition {
  const { apiClient } = context;
  
  return {
    name: 'list-scenarios',
    description: 'List and search Make.com scenarios with advanced filtering options',
    parameters: ScenarioFiltersSchema,
    annotations: {
      title: 'List Scenarios',
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (args: unknown, context): Promise<string> => {
      const { log = { info: (): void => {}, error: (): void => {}, warn: (): void => {}, debug: (): void => {} }, reportProgress = (): void => {} } = context || {};
      log?.info?.('Listing scenarios', JSON.stringify(args));
      reportProgress?.({ progress: 0, total: 100 });

      try {
        const argsTyped = parseListScenariosArgs(args);
        const params = buildQueryParameters(argsTyped);
        
        reportProgress?.({ progress: 25, total: 100 });
        
        const response = await fetchScenariosWithParams(apiClient, params, reportProgress);
        const result = formatScenariosResponse(response, argsTyped, args);
        
        reportProgress?.({ progress: 100, total: 100 });
        logSuccessfulListing(log, result);
        return formatSuccessResponse(result).content[0].text;
      } catch (error) {
        handleListingError(log, error);
        throw error;
      }
    },
  };
}

/**
 * Parse and validate list scenarios arguments
 */
function parseListScenariosArgs(args: unknown): {
  limit?: number;
  offset?: number;
  teamId?: string;
  folderId?: string;
  search?: string;
  active?: boolean;
} {
  return args as {
    limit?: number;
    offset?: number;
    teamId?: string;
    folderId?: string;
    search?: string;
    active?: boolean;
  };
}

/**
 * Build query parameters for scenarios API
 */
function buildQueryParameters(argsTyped: {
  limit?: number;
  offset?: number;
  teamId?: string;
  folderId?: string;
  search?: string;
  active?: boolean;
}): Record<string, unknown> {
  const params: Record<string, unknown> = {
    limit: argsTyped.limit ?? 10,
    offset: argsTyped.offset ?? 0,
  };

  if (argsTyped.teamId) { params.teamId = argsTyped.teamId; }
  if (argsTyped.folderId) { params.folderId = argsTyped.folderId; }
  if (argsTyped.search) { params.q = argsTyped.search; }
  if (argsTyped.active !== undefined) { params.active = argsTyped.active; }

  return params;
}

/**
 * Fetch scenarios with query parameters
 */
async function fetchScenariosWithParams(
  apiClient: MakeApiClient,
  params: Record<string, unknown>,
  reportProgress?: (progress: { progress: number; total: number }) => void
): Promise<{ success: boolean; data: unknown; metadata: unknown; error?: { message: string } }> {
  const response = await apiClient.get('/scenarios', { params });
  reportProgress?.({ progress: 75, total: 100 });

  if (!response.success) {
    throw new UserError(`Failed to list scenarios: ${response.error?.message}`);
  }

  return response;
}

/**
 * Format scenarios response data
 */
function formatScenariosResponse(
  response: { data: unknown; metadata: unknown },
  argsTyped: { limit?: number; offset?: number },
  originalArgs: unknown
): {
  scenarios: unknown[];
  pagination: {
    total: number;
    limit?: number;
    offset?: number;
    hasMore: boolean;
  };
  filters: unknown;
  timestamp: string;
} {
  const scenarios = response.data;
  const metadata = response.metadata;

  // Type guard for scenarios array
  const scenariosArray = Array.isArray(scenarios) ? scenarios : [];

  return {
    scenarios: scenariosArray,
    pagination: {
      total: (metadata as { total?: number })?.total || scenariosArray.length,
      limit: argsTyped.limit,
      offset: argsTyped.offset,
      hasMore: ((metadata as { total?: number })?.total || 0) > ((argsTyped.offset || 0) + (argsTyped.limit || 20)),
    },
    filters: originalArgs,
    timestamp: new Date().toISOString(),
  };
}

/**
 * Log successful scenarios listing
 */
function logSuccessfulListing(
  log: { info?: (message: string, meta?: unknown) => void },
  result: { scenarios: unknown[]; pagination: { total: number } }
): void {
  log?.info?.('Scenarios listed successfully', { 
    count: result.scenarios.length,
    total: result.pagination.total 
  });
}

/**
 * Handle listing errors
 */
function handleListingError(
  log: { error?: (message: string, meta?: unknown) => void },
  error: unknown
): void {
  const errorMessage = error instanceof Error ? error.message : String(error);
  log?.error?.('Failed to list scenarios', { error: errorMessage });
  
  if (!(error instanceof UserError)) {
    throw new UserError(`Failed to list scenarios: ${errorMessage}`);
  }
}