/**
 * @fileoverview Constants for scenarios module
 * Centralized constants and configuration values for scenario operations
 */

/**
 * Scenario operation timeouts in milliseconds
 */
export const TIMEOUTS = {
  LIST_SCENARIOS: 30000,
  GET_SCENARIO: 15000,
  CREATE_SCENARIO: 45000,
  UPDATE_SCENARIO: 30000,
  DELETE_SCENARIO: 20000,
  CLONE_SCENARIO: 60000,
  ANALYZE_BLUEPRINT: 120000,
  OPTIMIZE_BLUEPRINT: 90000,
  TROUBLESHOOT_SCENARIO: 180000,
  GENERATE_REPORT: 300000
} as const;

/**
 * Default pagination settings
 */
export const PAGINATION = {
  DEFAULT_LIMIT: 20,
  MAX_LIMIT: 100,
  DEFAULT_OFFSET: 0
} as const;

/**
 * Scenario status values
 */
export const SCENARIO_STATUS = {
  ACTIVE: 'active',
  INACTIVE: 'inactive',
  DRAFT: 'draft',
  ARCHIVED: 'archived',
  ERROR: 'error'
} as const;

/**
 * Blueprint validation severity levels
 */
export const VALIDATION_SEVERITY = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info'
} as const;

/**
 * Optimization recommendation priorities
 */
export const OPTIMIZATION_PRIORITY = {
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low'
} as const;

/**
 * Optimization categories
 */
export const OPTIMIZATION_CATEGORIES = {
  PERFORMANCE: 'performance',
  COST: 'cost',
  RELIABILITY: 'reliability',
  SECURITY: 'security',
  MAINTAINABILITY: 'maintainability'
} as const;

/**
 * Troubleshooting report formats
 */
export const REPORT_FORMATS = {
  DETAILED: 'detailed',
  EXECUTIVE: 'executive',
  TECHNICAL: 'technical',
  SUMMARY: 'summary'
} as const;

/**
 * Health score thresholds
 */
export const HEALTH_THRESHOLDS = {
  HEALTHY: 80,
  WARNING: 60,
  CRITICAL: 40
} as const;

/**
 * Security assessment levels
 */
export const SECURITY_LEVELS = {
  SECURE: 'secure',
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical'
} as const;

/**
 * Performance grades
 */
export const PERFORMANCE_GRADES = {
  A_PLUS: 'A+',
  A: 'A',
  B_PLUS: 'B+',
  B: 'B',
  C_PLUS: 'C+',
  C: 'C',
  D_PLUS: 'D+',
  D: 'D',
  F: 'F'
} as const;

/**
 * Module types that typically require connections
 */
export const CONNECTION_REQUIRED_MODULES = [
  'http',
  'google-sheets',
  'slack',
  'email',
  'database',
  'webhook',
  'api',
  'oauth'
] as const;

/**
 * Built-in module types that don't require connections
 */
export const BUILTIN_MODULES = [
  'builtin:BasicRouter',
  'builtin:Delay',
  'builtin:JSONTransformer',
  'builtin:Iterator',
  'builtin:Filter',
  'builtin:Aggregator',
  'builtin:DataStore',
  'builtin:MimeMessage'
] as const;

/**
 * Error codes for scenario operations
 */
export const ERROR_CODES = {
  SCENARIO_NOT_FOUND: 'SCENARIO_NOT_FOUND',
  INVALID_BLUEPRINT: 'INVALID_BLUEPRINT',
  VALIDATION_FAILED: 'VALIDATION_FAILED',
  OPTIMIZATION_FAILED: 'OPTIMIZATION_FAILED',
  TROUBLESHOOTING_FAILED: 'TROUBLESHOOTING_FAILED',
  INSUFFICIENT_PERMISSIONS: 'INSUFFICIENT_PERMISSIONS',
  RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',
  INVALID_PARAMETERS: 'INVALID_PARAMETERS'
} as const;

/**
 * Tool annotations for FastMCP
 */
export const TOOL_ANNOTATIONS = {
  LIST_SCENARIOS: {
    title: 'List Scenarios',
    readOnlyHint: true,
    openWorldHint: true
  },
  GET_SCENARIO: {
    title: 'Get Scenario Details',
    readOnlyHint: true,
    openWorldHint: false
  },
  CREATE_SCENARIO: {
    title: 'Create Scenario',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: false
  },
  UPDATE_SCENARIO: {
    title: 'Update Scenario',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false
  },
  DELETE_SCENARIO: {
    title: 'Delete Scenario',
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: true,
    openWorldHint: false
  },
  CLONE_SCENARIO: {
    title: 'Clone Scenario',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: false
  },
  ANALYZE_BLUEPRINT: {
    title: 'Analyze Blueprint',
    readOnlyHint: true,
    openWorldHint: false
  },
  OPTIMIZE_BLUEPRINT: {
    title: 'Optimize Blueprint',
    readOnlyHint: true,
    openWorldHint: false
  },
  TROUBLESHOOT_SCENARIO: {
    title: 'Troubleshoot Scenario',
    readOnlyHint: true,
    openWorldHint: false
  },
  GENERATE_TROUBLESHOOTING_REPORT: {
    title: 'Generate Troubleshooting Report',
    readOnlyHint: true,
    openWorldHint: false
  }
} as const;

/**
 * Default analysis options
 */
export const DEFAULT_ANALYSIS_OPTIONS = {
  STRICT_VALIDATION: false,
  INCLUDE_SECURITY_CHECKS: true,
  INCLUDE_PERFORMANCE_ANALYSIS: true,
  INCLUDE_DEPENDENCY_MAPPING: false,
  TIME_RANGE_HOURS: 24,
  INCLUDE_EXECUTIVE_SUMMARY: true,
  INCLUDE_SECURITY_ASSESSMENT: true
} as const;

/**
 * Version information
 */
export const VERSION_INFO = {
  SCENARIOS_MODULE_VERSION: '1.0.0',
  API_VERSION: 'v1',
  COMPATIBILITY_VERSION: '^1.0.0'
} as const;