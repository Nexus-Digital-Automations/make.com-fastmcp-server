/**
 * @fileoverview Shared tool execution context
 * Standardized dependency injection interface for FastMCP tools
 */

import { FastMCP } from 'fastmcp';
import MakeApiClient from '../../../lib/make-api-client.js';

export interface ToolContext {
  server: FastMCP;
  apiClient: MakeApiClient;
  logger: any; // Using any to match existing logger type
}

export interface ToolExecutionContext {
  log?: {
    info?: (message: string, data?: any) => void;
    warn?: (message: string, data?: any) => void;
    error?: (message: string, data?: any) => void;
    debug?: (message: string, data?: any) => void;
  };
  reportProgress?: (progress: { progress: number; total: number }) => void;
  session?: any;
}

export interface ToolDefinition {
  name: string;
  description: string;
  parameters: any; // Zod schema
  annotations: {
    title: string;
    readOnlyHint: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
    openWorldHint: boolean;
  };
  execute: (args: unknown, context: ToolExecutionContext) => Promise<string>;
}