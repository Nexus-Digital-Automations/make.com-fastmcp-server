/**
 * @fileoverview Centralized tool exports for scenario management
 * @description Aggregates and re-exports all scenario tool creation functions
 */

// Import all tool creation functions
export { createTroubleshootScenarioTool } from './troubleshoot-scenario.js';
export { createGenerateTroubleshootingReportTool } from './generate-troubleshooting-report.js';
export { createValidateBlueprintTool } from './validate-blueprint.js';
export { createExtractBlueprintConnectionsTool } from './extract-blueprint-connections.js';
export { createOptimizeBlueprintTool } from './optimize-blueprint.js';

/**
 * Collection of all scenario tool creation functions for easy access
 */
export const ScenarioTools = {
  troubleshooting: {
    createTroubleshootScenarioTool,
    createGenerateTroubleshootingReportTool,
  },
  blueprints: {
    createValidateBlueprintTool,
    createExtractBlueprintConnectionsTool,
    createOptimizeBlueprintTool,
  },
} as const;

/**
 * Array of all tool creation functions for batch processing
 */
export const ALL_SCENARIO_TOOLS = [
  createTroubleshootScenarioTool,
  createGenerateTroubleshootingReportTool,
  createValidateBlueprintTool,
  createExtractBlueprintConnectionsTool,
  createOptimizeBlueprintTool,
] as const;

/**
 * Tool metadata for documentation and registration
 */
export const TOOL_METADATA = {
  'troubleshoot-scenario': {
    category: 'Troubleshooting',
    complexity: 'high',
    permissions: ['scenario:read', 'analytics:read'],
    canModify: true,
    description: 'Comprehensive scenario diagnostics with auto-fix capabilities'
  },
  'generate-troubleshooting-report': {
    category: 'Troubleshooting Reports',
    complexity: 'high',
    permissions: ['scenario:read', 'analytics:read'],
    canModify: false,
    description: 'Generate comprehensive troubleshooting reports with multiple formats'
  },
  'validate-blueprint': {
    category: 'Blueprint Validation',
    complexity: 'medium',
    permissions: ['blueprint:read'],
    canModify: false,
    description: 'Validate blueprint structure and security compliance'
  },
  'extract-blueprint-connections': {
    category: 'Blueprint Analysis',
    complexity: 'medium',
    permissions: ['blueprint:read'],
    canModify: false,
    description: 'Extract and analyze blueprint connection requirements'
  },
  'optimize-blueprint': {
    category: 'Blueprint Optimization',
    complexity: 'medium',
    permissions: ['blueprint:read'],
    canModify: false,
    description: 'Analyze and optimize blueprints for performance and cost'
  }
} as const;