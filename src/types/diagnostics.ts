/**
 * @fileoverview Diagnostic types and interfaces for Make.com scenario troubleshooting
 * 
 * Provides comprehensive type definitions for the diagnostic system including
 * diagnostic results, rules, reports, and auto-fix capabilities.
 * 
 * @version 1.0.0
 * @author Make.com FastMCP Server
 */

import type MakeApiClient from '../lib/make-api-client.js';

export interface DiagnosticResult {
  /** Diagnostic category */
  category: 'health' | 'performance' | 'error' | 'connection' | 'security';
  /** Issue severity level */
  severity: 'info' | 'warning' | 'error' | 'critical';
  /** Short descriptive title */
  title: string;
  /** Detailed description of the issue */
  description: string;
  /** Additional diagnostic details */
  details: Record<string, unknown>;
  /** Actionable recommendations to fix the issue */
  recommendations: string[];
  /** Whether the issue can be automatically fixed */
  fixable: boolean;
  /** Auto-fix action identifier if fixable */
  autoFixAction?: string;
  /** Module ID if issue is module-specific */
  moduleId?: number;
  /** Timestamp when diagnostic was performed */
  timestamp: string;
}

export interface TroubleshootingReport {
  /** Scenario identifier */
  scenarioId: string;
  /** Scenario name */
  scenarioName: string;
  /** Overall health assessment */
  overallHealth: 'healthy' | 'warning' | 'critical' | 'unknown';
  /** Array of diagnostic results */
  diagnostics: DiagnosticResult[];
  /** Summary statistics */
  summary: {
    /** Total number of issues found */
    totalIssues: number;
    /** Number of critical issues */
    criticalIssues: number;
    /** Number of automatically fixable issues */
    fixableIssues: number;
    /** Performance score (0-100) */
    performanceScore: number;
    /** Issues by category */
    issuesByCategory: Record<string, number>;
    /** Issues by severity */
    issuesBySeverity: Record<string, number>;
  };
  /** Diagnostic execution time in milliseconds */
  executionTime: number;
  /** Report generation timestamp */
  timestamp: string;
}

export interface DiagnosticRule {
  /** Unique rule identifier */
  id: string;
  /** Human-readable rule name */
  name: string;
  /** Diagnostic category this rule belongs to */
  category: 'health' | 'performance' | 'error' | 'connection' | 'security';
  /** Default severity level for issues found by this rule */
  severity: 'info' | 'warning' | 'error' | 'critical';
  /** Rule execution function */
  check: (context: DiagnosticContext) => Promise<DiagnosticResult | null>;
  /** Other rules this rule depends on */
  dependencies?: string[];
  /** Whether this rule is enabled */
  enabled: boolean;
  /** Estimated execution time in milliseconds */
  estimatedDuration?: number;
}

export interface DiagnosticContext {
  /** Scenario ID being diagnosed */
  scenarioId: string;
  /** Scenario data from API */
  scenario: unknown;
  /** Scenario blueprint configuration */
  blueprint: MakeBlueprint;
  /** API client for additional data */
  apiClient: MakeApiClient;
  /** Diagnostic options */
  options: DiagnosticOptions;
  /** Execution cache for performance */
  cache: Map<string, unknown>;
  /** Logger instance */
  logger?: unknown;
}

export interface DiagnosticOptions {
  /** Types of diagnostics to run */
  diagnosticTypes: string[];
  /** Minimum severity level to report */
  severityFilter?: 'info' | 'warning' | 'error' | 'critical';
  /** Hours of execution history to analyze */
  timeRangeHours: number;
  /** Whether to include detailed performance metrics */
  includePerformanceMetrics: boolean;
  /** Whether to include security checks */
  includeSecurityChecks: boolean;
  /** Maximum execution time for diagnostics */
  timeoutMs: number;
}

export interface MakeBlueprint {
  /** Scenario name */
  name: string;
  /** Scenario description */
  description?: string;
  /** Blueprint version */
  version?: string;
  /** Array of scenario modules */
  flow: ModuleDefinition[];
  /** Blueprint metadata */
  metadata: {
    /** Metadata version */
    version: number;
    /** Scenario execution settings */
    scenario: {
      /** Maximum execution cycles */
      roundtrips: number;
      /** Error tolerance threshold */
      maxErrors: number;
      /** Automatic transaction commit */
      autoCommit: boolean;
      /** Sequential vs parallel execution */
      sequential: boolean;
      /** Privacy/security designation */
      confidential: boolean;
      /** Dead letter queue enabled */
      dlq: boolean;
      /** Fresh variables on each execution */
      freshVariables: boolean;
    };
  };
}

export interface ModuleDefinition {
  /** Unique module identifier */
  id: number;
  /** Module type identifier */
  module: string;
  /** Module version */
  version: number;
  /** Module configuration parameters */
  parameters?: Record<string, unknown>;
  /** Connection identifier */
  connection?: number;
  /** Module metadata */
  metadata?: {
    /** Designer positioning */
    designer?: {
      x: number;
      y: number;
    };
    /** Restore configuration */
    restore?: Record<string, unknown>;
    /** Parameter definitions */
    parameters?: unknown[];
    /** Expected data structure */
    expect?: unknown[];
  };
  /** Router routes for routing modules */
  routes?: Array<{
    /** Routing condition */
    condition: string;
    /** Target module IDs */
    target: number[];
  }>;
}

export interface AutoFixResult {
  /** Whether auto-fix was attempted */
  attempted: boolean;
  /** Array of fix results */
  results: AutoFixAction[];
  /** Overall success status */
  success: boolean;
  /** Total fixes applied */
  fixesApplied: number;
  /** Execution time for auto-fixes */
  executionTime: number;
}

export interface AutoFixAction {
  /** Issue title that was fixed */
  issueTitle: string;
  /** Auto-fix action that was applied */
  action: string;
  /** Whether the fix was successful */
  success: boolean;
  /** Fix result message */
  message: string;
  /** Error details if fix failed */
  error?: string;
  /** Fix execution time */
  duration: number;
}

export interface PerformanceMetrics {
  /** Average execution duration */
  averageDuration: number;
  /** Maximum execution duration */
  maxDuration: number;
  /** Minimum execution duration */
  minDuration: number;
  /** 95th percentile duration */
  p95Duration: number;
  /** Success rate percentage */
  successRate: number;
  /** Error rate percentage */
  errorRate: number;
  /** Total executions analyzed */
  totalExecutions: number;
  /** Executions in time range */
  executionsInRange: number;
  /** Performance trend */
  trend: 'improving' | 'stable' | 'degrading' | 'unknown';
}

export interface ConnectionHealthStatus {
  /** Connection ID */
  connectionId: number;
  /** Connection status */
  status: 'verified' | 'unverified' | 'expired' | 'error';
  /** Whether connection is working */
  isWorking: boolean;
  /** Last verification time */
  lastVerified?: string;
  /** Error message if connection failed */
  error?: string;
  /** Connection type/service */
  service?: string;
  /** OAuth scopes */
  scopes?: string[];
}

export interface SecurityAssessment {
  /** Overall security score (0-100) */
  securityScore: number;
  /** Whether hardcoded secrets were detected */
  hasHardcodedSecrets: boolean;
  /** Number of modules with excessive permissions */
  excessivePermissions: number;
  /** Whether scenario is marked confidential */
  isConfidential: boolean;
  /** Security recommendations */
  recommendations: string[];
  /** Detected security issues */
  securityIssues: Array<{
    /** Issue type */
    type: string;
    /** Issue description */
    description: string;
    /** Affected module ID */
    moduleId?: number;
    /** Issue severity */
    severity: 'low' | 'medium' | 'high' | 'critical';
  }>;
}

export interface ErrorPattern {
  /** Error type or code */
  errorType: string;
  /** Number of occurrences */
  count: number;
  /** Error message pattern */
  message: string;
  /** Affected module IDs */
  moduleIds: number[];
  /** First occurrence timestamp */
  firstSeen: string;
  /** Last occurrence timestamp */
  lastSeen: string;
  /** Error frequency trend */
  trend: 'increasing' | 'stable' | 'decreasing';
}