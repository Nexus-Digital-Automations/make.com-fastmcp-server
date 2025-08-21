/**
 * @fileoverview Make.com Scenario Management Tools - Legacy Compatibility Layer
 * 
 * This file provides backward compatibility by re-exporting the new modular
 * scenario management implementation. The actual implementation has been
 * refactored into a modular architecture located in ./scenarios/index.js
 * 
 * @deprecated Use the modular implementation directly from ./scenarios/index.js
 * @version 2.0.0 (Refactored - Compatibility Layer)
 * @author Make.com FastMCP Server
 * @see {@link https://docs.make.com/api} Make.com API Documentation
 */

// Re-export everything from the modular implementation
export { addScenarioTools, default } from './scenarios/index.js';

// Re-export all types and schemas for backward compatibility
export * from './scenarios/types/index.js';
export * from './scenarios/schemas/index.js';