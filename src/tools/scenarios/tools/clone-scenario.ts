/**
 * @fileoverview Clone Scenario Tool Implementation
 * Clones an existing Make.com scenario with customizable options
 */

import { UserError } from "fastmcp";
import { CloneScenarioSchema } from "../schemas/blueprint-update.js";
import {
  ToolContext,
  ToolDefinition,
} from "../../shared/types/tool-context.js";
import { formatSuccessResponse } from "../../../utils/response-formatter.js";
import type MakeApiClient from "../../../lib/make-api-client.js";

/**
 * Validate and parse clone scenario arguments
 */
function validateAndParseArgs(args: unknown) {
  try {
    return CloneScenarioSchema.parse(args);
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Invalid parameters provided";
    throw new UserError(`Invalid parameters: ${errorMessage}`);
  }
}

/**
 * Fetch source scenario blueprint
 */
async function fetchSourceBlueprint(
  apiClient: MakeApiClient,
  scenarioId: string,
  reportProgress?: (progress: { progress: number; total: number }) => void,
) {
  const blueprintResponse = await apiClient.get(
    `/scenarios/${scenarioId}/blueprint`,
  );
  if (!blueprintResponse.success) {
    throw new UserError(
      `Failed to get source scenario blueprint: ${blueprintResponse.error?.message}`,
    );
  }
  reportProgress?.({ progress: 25, total: 100 });
  return blueprintResponse.data;
}

/**
 * Build clone data object
 */
function buildCloneData(
  typedArgs: {
    scenarioId: string;
    name: string;
    teamId?: string;
    folderId?: string;
    active?: boolean;
  },
  blueprint: unknown,
) {
  const cloneData: Record<string, unknown> = {
    name: typedArgs.name,
    blueprint,
    active: typedArgs.active,
  };

  if (typedArgs.teamId) {
    cloneData.teamId = typedArgs.teamId;
  }
  if (typedArgs.folderId) {
    cloneData.folderId = typedArgs.folderId;
  }

  return cloneData;
}

/**
 * Create the cloned scenario via API
 */
async function createClonedScenario(
  apiClient: MakeApiClient,
  cloneData: Record<string, unknown>,
  reportProgress?: (progress: { progress: number; total: number }) => void,
) {
  reportProgress?.({ progress: 50, total: 100 });

  const response = await apiClient.post("/scenarios", cloneData);
  reportProgress?.({ progress: 100, total: 100 });

  if (!response.success) {
    throw new UserError(`Failed to clone scenario: ${response.error?.message}`);
  }

  return response.data;
}

/**
 * Format the clone result
 */
function formatCloneResult(
  typedArgs: { scenarioId: string; name: string },
  clonedScenario: unknown,
) {
  return {
    originalScenarioId: typedArgs.scenarioId,
    clonedScenario,
    message: `Scenario cloned successfully as "${typedArgs.name}"`,
    timestamp: new Date().toISOString(),
  };
}

/**
 * Log successful clone operation
 */
function logCloneSuccess(
  log: { info?: (message: string, meta?: unknown) => void },
  typedArgs: { scenarioId: string; name: string },
  clonedScenario: unknown,
) {
  const clonedScenarioObj = clonedScenario as
    | { id?: unknown }
    | null
    | undefined;
  log?.info?.("Scenario cloned successfully", {
    sourceId: typedArgs.scenarioId,
    cloneId: String(clonedScenarioObj?.id ?? "unknown"),
    name: typedArgs.name,
  });
}

/**
 * Create clone scenario tool configuration
 */
export function createCloneScenarioTool(context: ToolContext): ToolDefinition {
  const { apiClient } = context;

  return {
    name: "clone-scenario",
    description: "Clone an existing Make.com scenario with a new name",
    parameters: CloneScenarioSchema,
    annotations: {
      title: "Clone Scenario",
      readOnlyHint: false,
      openWorldHint: false,
    },
    execute: async (args: unknown, context): Promise<string> => {
      const {
        log = {
          info: (): void => {},
          error: (): void => {},
          warn: (): void => {},
          debug: (): void => {},
        },
        reportProgress = (): void => {},
      } = context || {};

      const typedArgs = validateAndParseArgs(args);

      log?.info?.("Cloning scenario", {
        sourceId: typedArgs.scenarioId,
        newName: typedArgs.name,
      });
      reportProgress?.({ progress: 0, total: 100 });

      try {
        const blueprint = await fetchSourceBlueprint(
          apiClient,
          typedArgs.scenarioId,
          reportProgress,
        );
        const cloneData = buildCloneData(typedArgs, blueprint);
        const clonedScenario = await createClonedScenario(
          apiClient,
          cloneData,
          reportProgress,
        );
        const result = formatCloneResult(typedArgs, clonedScenario);

        logCloneSuccess(log, typedArgs, clonedScenario);
        return formatSuccessResponse(result).content[0].text;
      } catch (error) {
        const errorMessage =
          error instanceof Error ? error.message : String(error);
        log?.error?.("Failed to clone scenario", {
          scenarioId: typedArgs.scenarioId,
          error: errorMessage,
        });
        throw new UserError(`Failed to clone scenario: ${errorMessage}`);
      }
    },
  };
}
