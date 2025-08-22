/**
 * Response formatting utilities for FastMCP tools
 * Ensures consistent response formats and prevents JSON parsing errors
 */

export interface ToolResponse {
  content: Array<{
    type: 'text';
    text: string;
  }>;
}

/**
 * Format a data object as a proper FastMCP tool response
 * This prevents JSON parsing errors caused by returning JSON.stringify() directly
 */
export function formatToolResponse(data: unknown): ToolResponse {
  return {
    content: [
      {
        type: 'text',
        text: typeof data === 'string' ? data : JSON.stringify(data, null, 2),
      },
    ],
  };
}

/**
 * Format a success response with structured data
 */
export function formatSuccessResponse(data: unknown, message?: string): ToolResponse {
  const response = {
    success: true,
    ...(message && { message }),
    ...(typeof data === 'object' && data !== null ? data : { data }),
  };

  return formatToolResponse(response);
}

/**
 * Format an error response
 */
export function formatErrorResponse(error: string | Error, code?: string): ToolResponse {
  const response = {
    success: false,
    error: error instanceof Error ? error.message : error,
    ...(code && { code }),
  };

  return formatToolResponse(response);
}

/**
 * Legacy JSON string response formatter - converts JSON.stringify returns to proper format
 * Use this to migrate existing tools that return JSON.stringify() directly
 */
export function convertLegacyJsonResponse(jsonString: string): ToolResponse {
  try {
    // If it's already a valid JSON string, parse and reformat
    const parsed = JSON.parse(jsonString);
    return formatToolResponse(parsed);
  } catch {
    // If it's not valid JSON, treat as plain text
    return formatToolResponse(jsonString);
  }
}

/**
 * Validate that a response is in the correct FastMCP format
 */
export function validateToolResponse(response: unknown): boolean {
  if (typeof response === 'string') {
    return true; // Plain strings are valid
  }

  if (typeof response === 'object' && response !== null) {
    const obj = response as Record<string, unknown>;
    return (
      'content' in obj &&
      Array.isArray(obj.content) &&
      obj.content.every(
        (item) =>
          typeof item === 'object' &&
          item !== null &&
          'type' in item &&
          'text' in item &&
          item.type === 'text' &&
          typeof item.text === 'string'
      )
    );
  }

  return false;
}