/**
 * @fileoverview Troubleshoot Scenario Tool Implementation
 * Comprehensive scenario diagnostics with health checks, error analysis, and auto-fix capabilities
 */

import { UserError } from 'fastmcp';
import { TroubleshootScenarioSchema } from '../schemas/troubleshooting.js';
import { ToolContext, ToolDefinition } from '../types/tool-context.js';
import DiagnosticEngine from '../../../lib/diagnostic-engine.js';
import { defaultDiagnosticRules } from '../../../lib/diagnostic-rules.js';
import { MakeBlueprint } from '../../../types/diagnostics.js';

/**
 * Create troubleshoot scenario tool configuration
 */
export function createTroubleshootScenarioTool(context: ToolContext): ToolDefinition {
  const { apiClient, logger } = context;
  
  return {
    name: 'troubleshoot-scenario',
    description: 'Comprehensive Make.com scenario diagnostics with health checks, error analysis, performance monitoring, and auto-fix capabilities',
    parameters: TroubleshootScenarioSchema,
    annotations: {
      title: 'Troubleshoot Scenario',
      readOnlyHint: false, // Can perform auto-fixes
    },
    execute: async (args, { log, reportProgress }) => {
      log?.info('Starting scenario troubleshooting', { 
        scenarioId: args.scenarioId,
        diagnosticTypes: args.diagnosticTypes,
        autoFix: args.autoFix,
        timeRange: args.timeRange?.hours || 24
      });
      
      reportProgress({ progress: 0, total: 100 });
      
      try {
        // Initialize diagnostic engine with default rules
        const diagnosticEngine = new DiagnosticEngine();
        
        // Register all default diagnostic rules
        defaultDiagnosticRules.forEach(rule => {
          diagnosticEngine.registerRule(rule);
        });
        
        reportProgress({ progress: 10, total: 100 });
        
        // Get scenario details
        const scenarioResponse = await apiClient.get(`/scenarios/${args.scenarioId}`);
        if (!scenarioResponse.success) {
          throw new UserError(`Scenario not found: ${args.scenarioId}`);
        }
        
        reportProgress({ progress: 25, total: 100 });
        
        // Get scenario blueprint
        const blueprintResponse = await apiClient.get(`/scenarios/${args.scenarioId}/blueprint`);
        if (!blueprintResponse.success) {
          throw new UserError(`Failed to get scenario blueprint: ${blueprintResponse.error?.message}`);
        }
        
        reportProgress({ progress: 40, total: 100 });
        
        // Prepare diagnostic options
        const diagnosticOptions = {
          diagnosticTypes: args.diagnosticTypes,
          severityFilter: args.severityFilter,
          timeRangeHours: args.timeRange?.hours || 24,
          includePerformanceMetrics: args.includePerformanceHistory,
          includeSecurityChecks: args.diagnosticTypes.includes('security') || args.diagnosticTypes.includes('all'),
          timeoutMs: 30000 // 30 second timeout per rule
        };
        
        // Run comprehensive diagnostics
        const report = await diagnosticEngine.runDiagnostics(
          args.scenarioId,
          scenarioResponse.data,
          blueprintResponse.data as MakeBlueprint,
          apiClient,
          diagnosticOptions
        );
        
        reportProgress({ progress: 75, total: 100 });
        
        // Apply auto-fixes if requested
        let autoFixResults;
        if (args.autoFix) {
          const fixableIssues = report.diagnostics.filter(d => d.fixable);
          if (fixableIssues.length > 0) {
            log?.info('Applying automatic fixes', { fixableCount: fixableIssues.length });
            autoFixResults = await diagnosticEngine.applyAutoFixes(fixableIssues, apiClient);
          } else {
            autoFixResults = {
              attempted: false,
              results: [],
              success: true,
              fixesApplied: 0,
              executionTime: 0
            };
          }
        }
        
        reportProgress({ progress: 90, total: 100 });
        
        // Build comprehensive response
        const response = {
          scenario: {
            id: args.scenarioId,
            name: (scenarioResponse.data as { name?: string })?.name || 'Unknown',
            status: (scenarioResponse.data as { active?: boolean })?.active ? 'active' : 'inactive',
            moduleCount: (blueprintResponse.data as MakeBlueprint)?.flow?.length || 0
          },
          troubleshooting: {
            overallHealth: report.overallHealth,
            summary: report.summary,
            executionTime: report.executionTime,
            diagnosticsRun: args.diagnosticTypes,
            timeRangeAnalyzed: args.timeRange?.hours || 24
          },
          diagnostics: args.includeRecommendations 
            ? report.diagnostics 
            : report.diagnostics.map(d => ({ 
                ...d, 
                recommendations: d.severity === 'critical' || d.severity === 'error' 
                  ? d.recommendations 
                  : [] 
              })),
          autoFix: args.autoFix ? {
            attempted: autoFixResults?.attempted || false,
            results: autoFixResults?.results || [],
            success: autoFixResults?.success || false,
            fixesApplied: autoFixResults?.fixesApplied || 0,
            executionTime: autoFixResults?.executionTime || 0
          } : undefined,
          metadata: {
            troubleshootingSession: {
              diagnosticTypes: args.diagnosticTypes,
              severityFilter: args.severityFilter,
              timeRange: args.timeRange?.hours || 24,
              autoFixEnabled: args.autoFix,
              rulesExecuted: defaultDiagnosticRules.length
            },
            timestamp: new Date().toISOString(),
            version: '1.0.0'
          }
        };
        
        reportProgress({ progress: 100, total: 100 });
        
        log?.info('Scenario troubleshooting completed', {
          scenarioId: args.scenarioId,
          overallHealth: report.overallHealth,
          issueCount: report.summary.totalIssues,
          criticalIssues: report.summary.criticalIssues,
          fixableIssues: report.summary.fixableIssues,
          autoFixesApplied: autoFixResults?.fixesApplied || 0,
          executionTime: report.executionTime
        });
        
        return JSON.stringify(response, null, 2);
        
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log?.error('Scenario troubleshooting failed', { 
          scenarioId: args.scenarioId, 
          error: errorMessage 
        });
        throw new UserError(`Scenario troubleshooting failed: ${errorMessage}`);
      }
    },
  };
}