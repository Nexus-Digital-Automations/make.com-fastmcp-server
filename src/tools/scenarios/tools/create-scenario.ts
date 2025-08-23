/**
 * @fileoverview Create Scenario Tool Implementation
 * Creates a new Make.com scenario with optional configuration
 */

import { UserError } from "fastmcp";
import { CreateScenarioSchema } from "../schemas/blueprint-update.js";
import {
  ToolContext,
  ToolDefinition,
} from "../../shared/types/tool-context.js";
import { formatSuccessResponse } from "../../../utils/response-formatter.js";
import type MakeApiClient from "../../../lib/make-api-client.js";

/**
 * Validate and parse create scenario arguments
 */
function validateAndParseArgs(args: unknown) {
  try {
    return CreateScenarioSchema.parse(args);
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Invalid parameters provided";
    throw new UserError(`Invalid parameters: ${errorMessage}`);
  }
}

/**
 * Build scenario data object for creation
 */
function buildScenarioData(typedArgs: {
  name: string;
  teamId?: string;
  folderId?: string;
  blueprint?: unknown;
  scheduling?: unknown;
}) {
  const scenarioData: Record<string, unknown> = { name: typedArgs.name };

  if (typedArgs.teamId) {
    scenarioData.teamId = typedArgs.teamId;
  }
  if (typedArgs.folderId) {
    scenarioData.folderId = typedArgs.folderId;
  }
  if (typedArgs.blueprint) {
    scenarioData.blueprint = typedArgs.blueprint;
  }
  if (typedArgs.scheduling) {
    scenarioData.scheduling = typedArgs.scheduling;
  }

  return scenarioData;
}

/**
 * Create scenario via API
 */
async function createScenarioViaApi(
  apiClient: MakeApiClient,
  scenarioData: Record<string, unknown>,
  reportProgress?: (progress: { progress: number; total: number }) => void,
) {
  reportProgress?.({ progress: 25, total: 100 });

  const response = await apiClient.post("/scenarios", scenarioData);
  reportProgress?.({ progress: 75, total: 100 });

  if (!response.success) {
    throw new UserError(
      `Failed to create scenario: ${response.error?.message}`,
    );
  }

  reportProgress?.({ progress: 100, total: 100 });
  return response.data;
}

/**
 * Format creation result
 */
function formatCreationResult(
  typedArgs: { name: string },
  createdScenario: unknown,
) {
  return {
    scenario: createdScenario,
    message: `Scenario "${typedArgs.name}" created successfully`,
    timestamp: new Date().toISOString(),
  };
}

/**
 * Log successful scenario creation
 */
function logCreationSuccess(
  log: { info?: (message: string, meta?: unknown) => void },
  typedArgs: { name: string },
  createdScenario: unknown,
) {
  const scenarioObj = createdScenario as { id?: unknown } | null | undefined;
  log?.info?.("Scenario created successfully", {
    scenarioId: String(scenarioObj?.id ?? "unknown"),
    name: typedArgs.name,
  });
}

/**
 * Create scenario tool configuration
 */
export function createScenarioTool(context: ToolContext): ToolDefinition {
  const { apiClient } = context;

  return {
    name: "create-scenario",
    description: "Create a new Make.com scenario with optional configuration",
    parameters: CreateScenarioSchema,
    annotations: {
      title: "Create Scenario",
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

      log?.info?.("Creating scenario", {
        name: typedArgs.name,
        teamId: typedArgs.teamId,
      });
      reportProgress?.({ progress: 0, total: 100 });

      try {
        const scenarioData = buildScenarioData(typedArgs);
        const createdScenario = await createScenarioViaApi(
          apiClient,
          scenarioData,
          reportProgress,
        );
        const result = formatCreationResult(typedArgs, createdScenario);

        logCreationSuccess(log, typedArgs, createdScenario);
        return formatSuccessResponse(result).content[0].text;
      } catch (error) {
        const errorMessage =
          error instanceof Error ? error.message : String(error);
        log?.error?.("Failed to create scenario", {
          name: typedArgs.name,
          error: errorMessage,
        });
        throw new UserError(`Failed to create scenario: ${errorMessage}`);
      }
    },
  };
}
