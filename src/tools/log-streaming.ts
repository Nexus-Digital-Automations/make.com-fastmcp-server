/**
 * @fileoverview Real-Time Log Streaming Tools for Make.com FastMCP Server
 * 
 * COMPATIBILITY LAYER - This file has been refactored into modular architecture.
 * The actual implementation is now distributed across focused modules in ./log-streaming/
 * 
 * Provides comprehensive log streaming capabilities including:
 * - Real-time scenario execution log streaming
 * - Historical log querying with advanced filtering
 * - Live execution monitoring with SSE
 * - Log export for external analysis tools
 * - Multi-format log output (JSON, structured, plain text)
 * 
 * @version 2.0.0 (Modular Architecture)
 * @author Make.com FastMCP Server
 * @see {@link https://docs.make.com/api} Make.com API Documentation
 */

// Re-export everything from the modular implementation
export { addLogStreamingTools, default } from './log-streaming/index.js';

// Re-export all types and schemas for backward compatibility
export * from './log-streaming/types/index.js';
export * from './log-streaming/schemas/index.js';
export * from './log-streaming/utils/stream-processor.js';