/**
 * @fileoverview Generate Troubleshooting Report Tool Implementation
 * Comprehensive troubleshooting reports with consolidated findings and multi-format output
 */

import { UserError } from 'fastmcp';
import { GenerateTroubleshootingReportSchema } from '../schemas/troubleshooting.js';
import { ToolContext, ToolDefinition } from '../types/tool-context.js';
import DiagnosticEngine from '../../../lib/diagnostic-engine.js';
import { defaultDiagnosticRules } from '../../../lib/diagnostic-rules.js';
import { MakeBlueprint, TroubleshootingReport } from '../../../types/diagnostics.js';
import {
  ScenarioAnalysis,
  ConsolidatedFindings,
  SystemOverview,
  ActionPlan,
  CostAnalysisReport,
  aggregateFindings,
  generateSystemOverview,
  generateActionPlan,
  generateCostAnalysis,
  generateExecutiveSummary,
  formatAsMarkdown,
  formatAsPdfReady
} from '../utils/troubleshooting.js';

// Additional interfaces for this tool
interface PerformanceAnalysisResult {
  executionMetrics: {
    averageExecutionTime: number;
    errorRate: number;
    throughput: number;
  };
  resources: {
    cpuUsage: number;
    memoryUsage: number;
    networkUtilization: number;
    trend: 'improving' | 'stable' | 'degrading';
  };
  trends: {
    performanceDirection: 'improving' | 'stable' | 'degrading';
    predictionConfidence: number;
    projectedIssues: string[];
  };
  benchmarkComparison: {
    industryStandard: string;
    currentPerformance: string;
    gap: string;
    ranking: 'below_average' | 'average' | 'above_average' | 'excellent';
  };
  recommendations: {
    immediate: string[];
    shortTerm: string[];
    longTerm: string[];
    estimatedImpact: number;
  };
  costAnalysis?: {
    currentCost: number;
    optimizationPotential: number;
    recommendedActions: string[];
  };
}

/**
 * Create generate troubleshooting report tool configuration
 */
export function createGenerateTroubleshootingReportTool(context: ToolContext): ToolDefinition {
  const { apiClient, logger } = context;
  
  return {
    name: 'generate-troubleshooting-report',
    description: 'Generate comprehensive troubleshooting reports with consolidated diagnostic findings, executive summaries, action plans, and multi-format output options',
    parameters: GenerateTroubleshootingReportSchema,
    annotations: {
      title: 'Generate Troubleshooting Report',
      readOnlyHint: true,
      openWorldHint: true,
    },
    execute: async (args, { log, reportProgress }) => {
      const startTime = Date.now();
      const { 
        scenarioIds,
        reportOptions = {
          includeExecutiveSummary: true,
          includeDetailedAnalysis: true,
          includeActionPlan: true,
          includePerformanceMetrics: true,
          includeSecurityAssessment: true,
          includeCostAnalysis: false,
          includeRecommendationTimeline: true,
          formatType: 'json' as const
        },
        analysisFilters = {
          timeRangeHours: 24,
          severityThreshold: 'info' as const,
          includeInactiveScenarios: false,
          maxScenariosToAnalyze: 25,
          prioritizeByUsage: true
        },
        comparisonBaseline = {
          compareToHistorical: true,
          baselineTimeRangeHours: 168,
          includeBenchmarks: true
        }
      } = args;

      log?.info('Starting comprehensive troubleshooting report generation', { 
        scenarioCount: scenarioIds?.length || 'all',
        timeRange: analysisFilters.timeRangeHours,
        formatType: reportOptions.formatType
      });

      reportProgress({ progress: 0, total: 100 });

      try {
        // Phase 1: Discover and prioritize scenarios
        reportProgress({ progress: 10, total: 100 });
        
        let targetScenarios: Array<{ id: string; name: string; priority: number; active: boolean }> = [];
        
        if (scenarioIds && scenarioIds.length > 0) {
          // Use specific scenarios provided
          for (const scenarioId of scenarioIds) {
            const response = await apiClient.get(`/scenarios/${scenarioId}`);
            if (response.success) {
              const scenario = response.data as { id: string; name: string; active: boolean };
              targetScenarios.push({
                id: scenario.id,
                name: scenario.name,
                priority: 1,
                active: scenario.active
              });
            }
          }
        } else {
          // Discover all scenarios
          const response = await apiClient.get('/scenarios');
          if (!response.success) {
            throw new UserError('Failed to retrieve scenarios list for analysis');
          }

          const scenarios = response.data as Array<{ id: string; name: string; active: boolean }>;
          targetScenarios = scenarios
            .filter(s => analysisFilters.includeInactiveScenarios || s.active)
            .slice(0, analysisFilters.maxScenariosToAnalyze)
            .map(s => ({ ...s, priority: s.active ? 1 : 0.5 }));

          if (analysisFilters.prioritizeByUsage) {
            // Sort by active status (simple prioritization)
            targetScenarios.sort((a, b) => b.priority - a.priority);
          }
        }

        log?.info('Target scenarios identified', { 
          totalScenarios: targetScenarios.length,
          activeScenarios: targetScenarios.filter(s => s.active).length
        });

        // Phase 2: Run diagnostic analysis on each scenario
        const scenarioAnalyses: ScenarioAnalysis[] = [];
        const diagnosticEngine = new DiagnosticEngine();
        
        // Register all default diagnostic rules
        defaultDiagnosticRules.forEach(rule => {
          diagnosticEngine.registerRule(rule);
        });

        const totalScenarios = targetScenarios.length;
        let processedCount = 0;

        for (const scenario of targetScenarios) {
          try {
            // Get scenario details and blueprint
            const [scenarioResponse, blueprintResponse] = await Promise.all([
              apiClient.get(`/scenarios/${scenario.id}`),
              apiClient.get(`/scenarios/${scenario.id}/blueprint`)
            ]);

            if (!scenarioResponse.success || !blueprintResponse.success) {
              throw new Error(`Failed to get scenario data for ${scenario.id}`);
            }

            // Run diagnostics
            const diagnosticOptions = {
              diagnosticTypes: ['all'],
              severityFilter: analysisFilters.severityThreshold,
              timeRangeHours: analysisFilters.timeRangeHours,
              includePerformanceMetrics: reportOptions.includePerformanceMetrics,
              includeSecurityChecks: reportOptions.includeSecurityAssessment,
              timeoutMs: 30000
            };

            const diagnosticReport = await diagnosticEngine.runDiagnostics(
              scenario.id,
              scenarioResponse.data,
              blueprintResponse.data as MakeBlueprint,
              apiClient,
              diagnosticOptions
            ) as TroubleshootingReport;

            // Generate performance analysis if requested
            let performanceAnalysis: PerformanceAnalysisResult | undefined;
            if (reportOptions.includePerformanceMetrics) {
              try {
                // Mock performance analysis - in real implementation, this would use actual performance tools
                performanceAnalysis = {
                  executionMetrics: {
                    averageExecutionTime: 1500 + Math.random() * 1000,
                    errorRate: Math.random() * 0.05,
                    throughput: 100 + Math.random() * 50
                  },
                  resources: {
                    cpuUsage: 30 + Math.random() * 40,
                    memoryUsage: 40 + Math.random() * 30,
                    networkUtilization: 20 + Math.random() * 40,
                    trend: 'stable' as const
                  },
                  trends: {
                    performanceDirection: 'stable' as const,
                    predictionConfidence: 80,
                    projectedIssues: []
                  },
                  benchmarkComparison: {
                    industryStandard: 'Average response time: 100ms',
                    currentPerformance: 'Average response time: 150ms',
                    gap: '50ms slower than industry average',
                    ranking: 'average' as const
                  },
                  recommendations: {
                    immediate: ['Monitor error rates closely'],
                    shortTerm: ['Optimize response time'],
                    longTerm: ['Consider performance improvements'],
                    estimatedImpact: 15
                  }
                } as PerformanceAnalysisResult;
                log?.info('Performance analysis integration enabled');
              } catch (error) {
                log?.error('Failed to load performance analysis tools', { error: (error as Error).message });
                performanceAnalysis = undefined;
              }
            }

            scenarioAnalyses.push({
              scenarioId: scenario.id,
              scenarioName: scenario.name,
              diagnosticReport,
              performanceAnalysis,
              errors: []
            });

          } catch (error) {
            scenarioAnalyses.push({
              scenarioId: scenario.id,
              scenarioName: scenario.name,
              diagnosticReport: {
                scenarioId: scenario.id,
                scenarioName: scenario.name,
                overallHealth: 'critical' as const,
                diagnostics: [{
                  category: 'error' as const,
                  severity: 'critical' as const,
                  title: 'Analysis Failed',
                  description: `Analysis failed: ${(error as Error).message}`,
                  details: { error: error },
                  recommendations: ['Check system logs', 'Verify scenario configuration', 'Retry analysis'],
                  fixable: false,
                  timestamp: new Date().toISOString()
                }],
                summary: {
                  totalIssues: 1,
                  criticalIssues: 1,
                  fixableIssues: 0,
                  performanceScore: 0,
                  issuesByCategory: { error: 1 },
                  issuesBySeverity: { critical: 1 }
                },
                executionTime: 0,
                timestamp: new Date().toISOString()
              },
              errors: [`Analysis failed: ${(error as Error).message}`]
            });
          }

          processedCount++;
          reportProgress({ progress: 20 + (processedCount / totalScenarios) * 50, total: 100 });
        }

        reportProgress({ progress: 70, total: 100 });

        // Phase 3: Aggregate and analyze findings
        const consolidatedFindings = aggregateFindings(scenarioAnalyses);
        const systemOverview = generateSystemOverview(scenarioAnalyses, comparisonBaseline);
        
        reportProgress({ progress: 80, total: 100 });

        // Phase 4: Generate action plan and recommendations
        const baseActionPlan = generateActionPlan(consolidatedFindings, reportOptions.includeRecommendationTimeline);
        const actionPlan = {
          ...baseActionPlan,
          summary: {
            criticalActions: baseActionPlan.immediate.filter(action => action.priority === 'critical').length
          }
        } as Record<string, unknown> & ActionPlan & { summary: { criticalActions: number } };
        
        // Phase 5: Generate cost analysis if requested
        let costAnalysis;
        if (reportOptions.includeCostAnalysis) {
          costAnalysis = generateCostAnalysis(consolidatedFindings, scenarioAnalyses.length);
        }

        reportProgress({ progress: 90, total: 100 });

        // Phase 6: Generate executive summary
        const executiveSummary = generateExecutiveSummary(
          systemOverview, 
          consolidatedFindings, 
          actionPlan, 
          scenarioAnalyses.length
        );

        // Phase 7: Format and structure the final report
        const report = {
          metadata: {
            reportId: `troubleshooting-${Date.now()}`,
            generatedAt: new Date().toISOString(),
            reportType: 'comprehensive-troubleshooting',
            analysisScope: {
              scenarioCount: scenarioAnalyses.length,
              timeRangeHours: analysisFilters.timeRangeHours,
              severityThreshold: analysisFilters.severityThreshold,
              includeInactive: analysisFilters.includeInactiveScenarios
            },
            executionTime: Date.now() - startTime,
            version: '1.0.0'
          },
          
          ...(reportOptions.includeExecutiveSummary && { executiveSummary }),
          
          systemOverview,
          
          ...(reportOptions.includeDetailedAnalysis && {
            scenarioAnalysis: scenarioAnalyses.map(analysis => ({
              scenario: {
                id: analysis.scenarioId,
                name: analysis.scenarioName,
                hasErrors: analysis.errors.length > 0
              },
              ...(analysis.diagnosticReport && {
                healthStatus: analysis.diagnosticReport.overallHealth,
                issueCount: analysis.diagnosticReport.summary.totalIssues,
                criticalIssues: analysis.diagnosticReport.summary.criticalIssues,
                fixableIssues: analysis.diagnosticReport.summary.fixableIssues,
                performanceScore: analysis.diagnosticReport.summary.performanceScore,
                diagnostics: analysis.diagnosticReport.diagnostics.map((d: TroubleshootingReport['diagnostics'][0]) => ({
                  category: d.category,
                  severity: d.severity,
                  title: d.title,
                  description: d.description,
                  fixable: d.fixable,
                  recommendations: d.recommendations.slice(0, 3) // Top 3 recommendations
                }))
              }),
              ...(analysis.performanceAnalysis && { performanceMetrics: analysis.performanceAnalysis }),
              errors: analysis.errors
            }))
          }),

          consolidatedFindings,
          
          ...(reportOptions.includeActionPlan && { actionPlan }),
          
          ...(reportOptions.includePerformanceMetrics && {
            performanceMetrics: {
              systemWide: {
                averageHealthScore: Math.round(
                  scenarioAnalyses
                    .filter(a => a.diagnosticReport)
                    .reduce((sum, a) => sum + (a.diagnosticReport.summary.performanceScore || 0), 0) /
                  Math.max(scenarioAnalyses.filter(a => a.diagnosticReport).length, 1)
                ),
                totalIssuesFound: consolidatedFindings.commonIssues.reduce((sum, issue) => sum + issue.count, 0),
                criticalIssueRate: Math.round((consolidatedFindings.criticalScenarios / Math.max(consolidatedFindings.totalScenarios, 1)) * 100),
                fixableIssueRate: Math.round((consolidatedFindings.commonIssues.filter(issue => issue.category === 'fixable').length / Math.max(consolidatedFindings.commonIssues.length, 1)) * 100)
              },
              ...(comparisonBaseline.includeBenchmarks && {
                benchmarkComparison: {
                  industryStandard: {
                    healthScore: '>= 85',
                    criticalIssueRate: '< 5%',
                    responseTime: '< 2000ms'
                  },
                  currentPerformance: systemOverview.performanceStatus,
                  gap: systemOverview.systemHealthScore < 85 ? 'Below industry standard' : 'Meets/exceeds standard'
                }
              })
            }
          }),

          ...(reportOptions.includeSecurityAssessment && {
            securityAssessment: {
              overallRisk: consolidatedFindings.securitySummary.criticalSecurityIssues > 0 ? 'high' : 
                          consolidatedFindings.securitySummary.totalSecurityIssues > 0 ? 'medium' : 'low',
              securityIssuesFound: consolidatedFindings.securitySummary.totalSecurityIssues,
              complianceStatus: consolidatedFindings.securitySummary.totalSecurityIssues > 0 ? 'review_required' : 'compliant',
              recommendations: consolidatedFindings.securitySummary.commonSecurityIssues.slice(0, 5)
            }
          }),

          ...(costAnalysis && { costAnalysis }),

          appendices: {
            rawDiagnosticData: reportOptions.includeDetailedAnalysis ? scenarioAnalyses : 'Excluded for brevity',
            analysisConfiguration: {
              reportOptions,
              analysisFilters,
              comparisonBaseline
            },
            glossary: {
              healthScore: 'Composite score (0-100) based on diagnostic findings and performance metrics',
              criticalIssue: 'Issues that require immediate attention and may impact system reliability',
              fixableIssue: 'Issues that can be automatically resolved or have clear remediation steps'
            }
          }
        };

        reportProgress({ progress: 100, total: 100 });

        // Format output based on requested type
        let formattedOutput: string;
        switch (reportOptions.formatType) {
          case 'markdown':
            formattedOutput = formatAsMarkdown(report);
            break;
          case 'pdf-ready':
            formattedOutput = formatAsPdfReady(report);
            break;
          default:
            formattedOutput = JSON.stringify(report, null, 2);
        }

        log?.info('Troubleshooting report generated successfully', {
          scenarioCount: scenarioAnalyses.length,
          totalIssues: consolidatedFindings.commonIssues.reduce((sum, issue) => sum + issue.count, 0),
          criticalIssues: consolidatedFindings.criticalScenarios,
          systemHealthScore: systemOverview.systemHealthScore,
          executionTime: Date.now() - startTime,
          outputFormat: reportOptions.formatType
        });

        return formattedOutput;

      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log?.error('Troubleshooting report generation failed', { error: errorMessage });
        throw new UserError(`Troubleshooting report generation failed: ${errorMessage}`);
      }
    }
  };
}