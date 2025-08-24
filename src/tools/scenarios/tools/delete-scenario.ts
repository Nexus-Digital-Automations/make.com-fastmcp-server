/**
 * @fileoverview Delete Scenario Tool Implementation
 * Deletes a Make.com scenario with safety checks and force options
 */

import { UserError } from "fastmcp";
import { z } from "zod";
import { DeleteScenarioSchema } from "../schemas/blueprint-update.js";
import {
  ToolContext,
  ToolDefinition,
} from "../../shared/types/tool-context.js";
import { formatSuccessResponse } from "../../../utils/response-formatter.js";
import type MakeApiClient from "../../../lib/make-api-client.js";

type ProgressReporter = (progress: { progress: number; total: number }) => void;

/**
 * Validate and parse delete scenario arguments
 */
function validateAndParseArgs(
  args: unknown,
): z.infer<typeof DeleteScenarioSchema> {
  try {
    return DeleteScenarioSchema.parse(args);
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Invalid parameters provided";
    throw new UserError(`Invalid parameters: ${errorMessage}`);
  }
}

/**
 * Check scenario status before deletion (unless forcing)
 */
async function checkScenarioStatus(
  apiClient: MakeApiClient,
  scenarioId: string,
  force: boolean,
  reportProgress?: ProgressReporter,
): Promise<void> {
  if (force) {
    return; // Skip status check when forcing
  }

  reportProgress?.({ progress: 10, total: 100 });
  const statusResponse = await apiClient.get(`/scenarios/${scenarioId}`);

  if (!statusResponse.success) {
    throw new UserError(
      `Cannot verify scenario status: ${statusResponse.error?.message || "Scenario not found"}`,
    );
  }

  if (statusResponse.data) {
    const scenario = statusResponse.data as { active?: boolean };
    if (scenario.active) {
      throw new UserError(
        "Cannot delete active scenario. Use --force true to override, or deactivate scenario first.",
      );
    }
  }
}

/**
 * Delete scenario via API
 */
async function deleteScenarioViaApi(
  apiClient: MakeApiClient,
  scenarioId: string,
  reportProgress?: ProgressReporter,
): Promise<void> {
  reportProgress?.({ progress: 50, total: 100 });

  const response = await apiClient.delete(`/scenarios/${scenarioId}`);
  reportProgress?.({ progress: 90, total: 100 });

  if (!response.success) {
    throw new UserError(
      `Failed to delete scenario: ${response.error?.message}`,
    );
  }
}

/**
 * Format deletion result
 */
function formatDeletionResult(
  scenarioId: string,
  force: boolean,
): {
  scenarioId: string;
  message: string;
  force: boolean;
  timestamp: string;
} {
  return {
    scenarioId,
    message: `Scenario deleted successfully`,
    force: Boolean(force),
    timestamp: new Date().toISOString(),
  };
}

/**
 * Create delete scenario tool configuration
 */
export function createDeleteScenarioTool(context: ToolContext): ToolDefinition {
  const { apiClient } = context;

  return {
    name: "delete-scenario",
    description:
      "Delete a Make.com scenario with safety checks and force options",
    parameters: DeleteScenarioSchema,
    annotations: {
      title: "Delete Scenario",
      readOnlyHint: false,
      destructiveHint: true,
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

      log?.info?.("Deleting scenario", {
        scenarioId: typedArgs.scenarioId,
        force: typedArgs.force,
      });
      reportProgress?.({ progress: 0, total: 100 });

      try {
        await checkScenarioStatus(
          apiClient,
          typedArgs.scenarioId,
          typedArgs.force,
          reportProgress,
        );

        await deleteScenarioViaApi(
          apiClient,
          typedArgs.scenarioId,
          reportProgress,
        );

        reportProgress?.({ progress: 100, total: 100 });

        const result = formatDeletionResult(
          typedArgs.scenarioId,
          typedArgs.force,
        );

        log?.info?.("Scenario deleted successfully", {
          scenarioId: typedArgs.scenarioId,
          force: typedArgs.force,
        });

        return formatSuccessResponse(result).content[0].text;
      } catch (error) {
        const errorMessage =
          error instanceof Error ? error.message : String(error);
        log?.error?.("Failed to delete scenario", {
          scenarioId: typedArgs.scenarioId,
          error: errorMessage,
        });
        throw new UserError(`Failed to delete scenario: ${errorMessage}`);
      }
    },
  };
}
