/**
 * @fileoverview Troubleshooting Logic Utilities
 * 
 * Provides troubleshooting analysis, report generation, and findings aggregation
 * for Make.com scenarios. Includes comprehensive reporting and formatting capabilities.
 * 
 * @version 1.0.0
 */

import { TroubleshootingReport } from '../../../types/diagnostics.js';

// Type definitions for troubleshooting reports
export interface ScenarioAnalysis {
  scenarioId: string;
  scenarioName: string;
  diagnosticReport: TroubleshootingReport;
  performanceAnalysis?: PerformanceAnalysisResult;
  errors: string[];
}

export interface PerformanceAnalysisResult {
  analysisTimestamp: string;
  targetType: string;
  targetId?: string;
  timeRange: {
    startTime: string;
    endTime: string;
    durationHours: number;
  };
  overallHealthScore: number;
  performanceGrade: 'A' | 'B' | 'C' | 'D' | 'F';
  bottlenecks: unknown[];
  metrics: {
    responseTime: {
      average: number;
      p50: number;
      p95: number;
      p99: number;
      trend: 'improving' | 'stable' | 'degrading';
    };
    throughput: {
      requestsPerSecond: number;
      requestsPerMinute: number;
      trend: 'improving' | 'stable' | 'degrading';
    };
    reliability: {
      uptime: number;
      errorRate: number;
      successRate: number;
      trend: 'improving' | 'stable' | 'degrading';
    };
    resources: {
      cpuUsage: number;
      memoryUsage: number;
      networkUtilization: number;
      trend: 'improving' | 'stable' | 'degrading';
    };
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

export interface ConsolidatedFindings {
  totalScenarios: number;
  healthyScenarios: number;
  warningScenarios: number;
  criticalScenarios: number;
  totalIssues: number;
  criticalIssues: number;
  securityRiskLevel: string;
  commonIssues: Array<{
    category: string;
    severity: string;
    title: string;
    count: number;
    affectedScenarios: string[];
    description: string;
    recommendations: string[];
  }>;
  performanceSummary: {
    averageHealthScore: number;
    averageResponseTime: number;
    totalBottlenecks: number;
    commonBottleneckTypes: string[];
  };
  securitySummary: {
    averageSecurityScore: number;
    totalSecurityIssues: number;
    criticalSecurityIssues: number;
    commonSecurityIssues: string[];
  };
  criticalActionItems: Array<{
    severity: 'critical' | 'high';
    action: string;
    affectedScenarios: string[];
    impact: string;
    effort: 'low' | 'medium' | 'high';
  }>;
}

export interface ActionPlan {
  immediate: Array<{
    action: string;
    priority: 'critical' | 'high';
    estimatedTime: string;
    impact: string;
    scenarioIds: string[];
  }>;
  shortTerm: Array<{
    action: string;
    priority: 'medium' | 'high';
    estimatedTime: string;
    impact: string;
    scenarioIds: string[];
  }>;
  longTerm: Array<{
    action: string;
    priority: 'low' | 'medium';
    estimatedTime: string;
    impact: string;
    scenarioIds: string[];
  }>;
  timeline: {
    phase1Duration: string;
    phase2Duration: string;
    phase3Duration: string;
    totalDuration: string;
  };
  [key: string]: unknown;
}

export interface SystemOverview {
  overallHealth: 'healthy' | 'warning' | 'critical' | 'unknown';
  totalScenarios: number;
  activeScenarios: number;
  totalIssuesFound: number;
  criticalIssuesFound: number;
  averagePerformanceScore: number;
  averageSecurityScore: number;
  systemLoadIndicators: {
    highVolumeScenarios: number;
    errorProneScenarios: number;
    slowPerformingScenarios: number;
  };
}

export interface CostAnalysisReport {
  estimatedMonthlyCost: number;
  costOptimizationPotential: number;
  costBreakdown: {
    highCostScenarios: Array<{
      scenarioId: string;
      scenarioName: string;
      estimatedMonthlyCost: number;
      optimizationPotential: number;
    }>;
  };
  recommendations: Array<{
    type: 'performance' | 'resource' | 'usage';
    description: string;
    estimatedSavings: number;
    implementationEffort: 'low' | 'medium' | 'high';
  }>;
}

export interface ReportMetadata {
  reportId?: string;
  generatedAt?: string;
  analysisScope?: {
    scenarioCount?: number;
    timeRangeHours?: number;
  };
}

export interface TroubleshootingReportData {
  metadata?: ReportMetadata;
  executiveSummary?: {
    keyFindings: string[];
    criticalRecommendations: string[];
    businessImpact: {
      riskLevel: 'high' | 'medium' | 'low';
      operationalReadiness: 'ready' | 'needs_attention';
      recommendedActions: string;
    };
    nextSteps: string[];
    reportConfidence: {
      dataCompleteness: number;
      analysisDepth: string;
      recommendationReliability: string;
    };
  };
  systemOverview?: {
    systemHealthScore: number;
    performanceStatus: string;
    overallStatus: string;
    scenarioBreakdown: {
      healthy: number;
    };
  };
  consolidatedFindings?: ConsolidatedFindings;
  actionPlan?: ActionPlan;
  [key: string]: unknown;
}

// Aggregation function for troubleshooting findings
export function aggregateFindings(analyses: ScenarioAnalysis[]): ConsolidatedFindings {
  const findings: ConsolidatedFindings = {
    totalScenarios: analyses.length,
    healthyScenarios: 0,
    warningScenarios: 0,
    criticalScenarios: 0,
    totalIssues: 0,
    criticalIssues: 0,
    securityRiskLevel: 'low',
    commonIssues: [],
    performanceSummary: {
      averageHealthScore: 0,
      averageResponseTime: 0,
      totalBottlenecks: 0,
      commonBottleneckTypes: []
    },
    securitySummary: {
      averageSecurityScore: 0,
      totalSecurityIssues: 0,
      criticalSecurityIssues: 0,
      commonSecurityIssues: []
    },
    criticalActionItems: []
  };

  if (analyses.length === 0) {
    return findings;
  }

  // Track issues and their frequency
  const issueTracker = new Map<string, {
    category: string;
    severity: string;
    title: string;
    count: number;
    affectedScenarios: string[];
    description: string;
    recommendations: string[];
  }>();

  const bottleneckTypes = new Map<string, number>();
  const securityIssues = new Map<string, number>();
  let totalHealthScore = 0;
  let totalResponseTime = 0;
  let totalSecurityScore = 0;
  let scenariosWithPerformanceData = 0;

  analyses.forEach((analysis) => {
    const report = analysis.diagnosticReport;
    const perf = analysis.performanceAnalysis;

    // Categorize scenario health
    if (perf) {
      if (perf.overallHealthScore >= 80) {
        findings.healthyScenarios++;
      } else if (perf.overallHealthScore >= 60) {
        findings.warningScenarios++;
      } else {
        findings.criticalScenarios++;
      }

      totalHealthScore += perf.overallHealthScore;
      totalResponseTime += perf.metrics.responseTime.average;
      scenariosWithPerformanceData++;

      // Track bottlenecks
      perf.bottlenecks.forEach((bottleneck: any) => {
        if (bottleneck.type) {
          bottleneckTypes.set(bottleneck.type, (bottleneckTypes.get(bottleneck.type) || 0) + 1);
        }
      });
    }

    // Process diagnostic issues
    if (report.issues && Array.isArray(report.issues)) {
      report.issues.forEach((issue: any) => {
        const issueKey = `${issue.category}-${issue.title}`;
        
        if (issueTracker.has(issueKey)) {
          const existing = issueTracker.get(issueKey)!;
          existing.count++;
          if (!existing.affectedScenarios.includes(analysis.scenarioId)) {
            existing.affectedScenarios.push(analysis.scenarioId);
          }
        } else {
          issueTracker.set(issueKey, {
            category: issue.category || 'unknown',
            severity: issue.severity || 'medium',
            title: issue.title || 'Unknown Issue',
            count: 1,
            affectedScenarios: [analysis.scenarioId],
            description: issue.description || 'No description available',
            recommendations: Array.isArray(issue.recommendations) ? issue.recommendations : []
          });
        }

        findings.totalIssues++;
        if (issue.severity === 'critical' || issue.severity === 'high') {
          findings.criticalIssues++;
        }

        // Track security issues
        if (issue.category === 'security' || issue.category === 'compliance') {
          const securityKey = issue.title || 'Unknown Security Issue';
          securityIssues.set(securityKey, (securityIssues.get(securityKey) || 0) + 1);
          if (issue.severity === 'critical') {
            findings.securitySummary.criticalSecurityIssues++;
          }
        }
      });
    }

    // Process errors
    analysis.errors.forEach(error => {
      const issueKey = `error-${error}`;
      if (!issueTracker.has(issueKey)) {
        issueTracker.set(issueKey, {
          category: 'error',
          severity: 'high',
          title: error,
          count: 1,
          affectedScenarios: [analysis.scenarioId],
          description: `Runtime error: ${error}`,
          recommendations: ['Investigate error cause', 'Implement error handling', 'Monitor for recurrence']
        });
        findings.totalIssues++;
        findings.criticalIssues++;
      }
    });
  });

  // Convert issue tracker to array and sort by count
  findings.commonIssues = Array.from(issueTracker.values())
    .sort((a, b) => b.count - a.count)
    .slice(0, 20); // Top 20 most common issues

  // Calculate averages
  if (scenariosWithPerformanceData > 0) {
    findings.performanceSummary.averageHealthScore = Math.round(totalHealthScore / scenariosWithPerformanceData);
    findings.performanceSummary.averageResponseTime = Math.round(totalResponseTime / scenariosWithPerformanceData);
  }

  findings.performanceSummary.totalBottlenecks = Array.from(bottleneckTypes.values()).reduce((sum, count) => sum + count, 0);
  findings.performanceSummary.commonBottleneckTypes = Array.from(bottleneckTypes.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([type]) => type);

  // Security summary
  findings.securitySummary.totalSecurityIssues = Array.from(securityIssues.values()).reduce((sum, count) => sum + count, 0);
  findings.securitySummary.commonSecurityIssues = Array.from(securityIssues.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([issue]) => issue);

  // Estimate average security score
  if (findings.securitySummary.totalSecurityIssues === 0) {
    findings.securitySummary.averageSecurityScore = 95;
  } else if (findings.securitySummary.criticalSecurityIssues > 0) {
    findings.securitySummary.averageSecurityScore = Math.max(30, 80 - (findings.securitySummary.criticalSecurityIssues * 15));
  } else {
    findings.securitySummary.averageSecurityScore = Math.max(50, 85 - (findings.securitySummary.totalSecurityIssues * 5));
  }

  // Determine overall security risk level
  if (findings.securitySummary.criticalSecurityIssues > 0) {
    findings.securityRiskLevel = 'high';
  } else if (findings.securitySummary.totalSecurityIssues > 5) {
    findings.securityRiskLevel = 'medium';
  } else {
    findings.securityRiskLevel = 'low';
  }

  // Generate critical action items
  findings.criticalActionItems = findings.commonIssues
    .filter(issue => issue.severity === 'critical' || issue.severity === 'high')
    .slice(0, 10)
    .map(issue => ({
      severity: issue.severity as 'critical' | 'high',
      action: `Address ${issue.title}`,
      affectedScenarios: issue.affectedScenarios,
      impact: `Affects ${issue.count} scenarios`,
      effort: issue.count > 5 ? 'high' : issue.count > 2 ? 'medium' : 'low'
    }));

  return findings;
}

// System overview generation function
export function generateSystemOverview(
  findings: ConsolidatedFindings,
  _includeDetailedMetrics: boolean = true
): SystemOverview & { systemHealthScore: number; performanceStatus: string; overallStatus: string; scenarioBreakdown: { healthy: number } } {
  const overview = {
    overallHealth: 'healthy' as 'healthy' | 'warning' | 'critical' | 'unknown',
    totalScenarios: findings.totalScenarios,
    activeScenarios: findings.totalScenarios, // Assuming all analyzed scenarios are active
    totalIssuesFound: findings.totalIssues,
    criticalIssuesFound: findings.criticalIssues,
    averagePerformanceScore: findings.performanceSummary.averageHealthScore,
    averageSecurityScore: findings.securitySummary.averageSecurityScore,
    systemLoadIndicators: {
      highVolumeScenarios: 0,
      errorProneScenarios: findings.criticalScenarios,
      slowPerformingScenarios: Math.max(0, findings.totalScenarios - findings.healthyScenarios)
    },
    // Additional properties for compatibility
    systemHealthScore: 0,
    performanceStatus: 'unknown',
    overallStatus: 'unknown',
    scenarioBreakdown: {
      healthy: findings.healthyScenarios
    }
  };

  // Calculate system health score
  let healthScore = 100;
  
  if (findings.criticalIssues > 0) {
    healthScore -= findings.criticalIssues * 10;
  }
  
  if (findings.totalIssues > 0) {
    healthScore -= Math.min(30, findings.totalIssues * 2);
  }
  
  if (findings.performanceSummary.averageHealthScore < 80) {
    healthScore -= (80 - findings.performanceSummary.averageHealthScore) * 0.5;
  }
  
  if (findings.securitySummary.averageSecurityScore < 80) {
    healthScore -= (80 - findings.securitySummary.averageSecurityScore) * 0.3;
  }

  overview.systemHealthScore = Math.max(0, Math.round(healthScore));
  overview.averagePerformanceScore = overview.systemHealthScore;

  // Determine overall health status
  if (overview.systemHealthScore >= 80) {
    overview.overallHealth = 'healthy';
    overview.overallStatus = 'Healthy';
    overview.performanceStatus = 'Good';
  } else if (overview.systemHealthScore >= 60) {
    overview.overallHealth = 'warning';
    overview.overallStatus = 'Needs Attention';
    overview.performanceStatus = 'Fair';
  } else {
    overview.overallHealth = 'critical';
    overview.overallStatus = 'Critical';
    overview.performanceStatus = 'Poor';
  }

  return overview;
}

// Action plan generation function
export function generateActionPlan(findings: ConsolidatedFindings, _includeTimeline: boolean): ActionPlan & { summary: { criticalActions: number } } {
  const actionPlan: ActionPlan & { summary: { criticalActions: number } } = {
    immediate: [],
    shortTerm: [],
    longTerm: [],
    timeline: {
      phase1Duration: '24-72 hours',
      phase2Duration: '1-4 weeks', 
      phase3Duration: '1-3 months',
      totalDuration: '3-4 months'
    },
    summary: {
      criticalActions: 0
    }
  };

  // Generate immediate actions from critical issues
  findings.commonIssues
    .filter(issue => issue.severity === 'critical')
    .slice(0, 5)
    .forEach(issue => {
      actionPlan.immediate.push({
        action: `URGENT: ${issue.title}`,
        priority: 'critical',
        estimatedTime: '2-8 hours',
        impact: `Critical issue affecting ${issue.affectedScenarios.length} scenarios`,
        scenarioIds: issue.affectedScenarios
      });
      actionPlan.summary.criticalActions++;
    });

  // Generate immediate actions from high severity issues
  findings.commonIssues
    .filter(issue => issue.severity === 'high')
    .slice(0, 10)
    .forEach(issue => {
      actionPlan.immediate.push({
        action: issue.title,
        priority: 'high',
        estimatedTime: '4-16 hours',
        impact: `High impact issue affecting ${issue.affectedScenarios.length} scenarios`,
        scenarioIds: issue.affectedScenarios
      });
    });

  // Generate short-term actions from medium severity issues
  findings.commonIssues
    .filter(issue => issue.severity === 'medium')
    .slice(0, 15)
    .forEach(issue => {
      actionPlan.shortTerm.push({
        action: issue.title,
        priority: 'medium',
        estimatedTime: '1-3 days',
        impact: `Medium impact issue affecting ${issue.affectedScenarios.length} scenarios`,
        scenarioIds: issue.affectedScenarios
      });
    });

  // Generate long-term actions from low severity issues and optimizations
  findings.commonIssues
    .filter(issue => issue.severity === 'low')
    .slice(0, 10)
    .forEach(issue => {
      actionPlan.longTerm.push({
        action: issue.title,
        priority: 'low',
        estimatedTime: '1-2 weeks',
        impact: `Optimization affecting ${issue.affectedScenarios.length} scenarios`,
        scenarioIds: issue.affectedScenarios
      });
    });

  // Add performance optimization actions if needed
  if (findings.performanceSummary.averageHealthScore < 70) {
    actionPlan.shortTerm.push({
      action: 'Performance Optimization Initiative',
      priority: 'high',
      estimatedTime: '2-3 weeks',
      impact: 'Improve overall system performance and reliability',
      scenarioIds: findings.commonIssues
        .filter(issue => issue.category === 'performance')
        .flatMap(issue => issue.affectedScenarios)
    });
  }

  // Add security remediation if needed
  if (findings.securitySummary.criticalSecurityIssues > 0) {
    actionPlan.immediate.push({
      action: 'Critical Security Issues Remediation',
      priority: 'critical',
      estimatedTime: '1-2 days',
      impact: 'Address critical security vulnerabilities',
      scenarioIds: findings.commonIssues
        .filter(issue => issue.category === 'security' && issue.severity === 'critical')
        .flatMap(issue => issue.affectedScenarios)
    });
    actionPlan.summary.criticalActions++;
  }

  return actionPlan;
}

// Cost analysis generation function
export function generateCostAnalysis(findings: ConsolidatedFindings, scenarioCount: number): CostAnalysisReport {
  const costAnalysis: CostAnalysisReport = {
    estimatedMonthlyCost: 0,
    costOptimizationPotential: 0,
    costBreakdown: {
      highCostScenarios: []
    },
    recommendations: []
  };

  // Estimate base cost per scenario (rough estimates)
  const baseCostPerScenario = 25; // $25/month per active scenario
  const highComplexityMultiplier = 2.5;
  const mediumComplexityMultiplier = 1.5;

  let totalEstimatedCost = 0;
  let optimizationPotential = 0;

  // Calculate costs based on scenario health and complexity
  const healthyScenariosCost = findings.healthyScenarios * baseCostPerScenario;
  const warningScenariosCost = findings.warningScenarios * baseCostPerScenario * mediumComplexityMultiplier;
  const criticalScenariosCost = findings.criticalScenarios * baseCostPerScenario * highComplexityMultiplier;

  totalEstimatedCost = healthyScenariosCost + warningScenariosCost + criticalScenariosCost;
  
  // Calculate optimization potential
  optimizationPotential += findings.warningScenarios * baseCostPerScenario * 0.3; // 30% savings potential
  optimizationPotential += findings.criticalScenarios * baseCostPerScenario * 0.5; // 50% savings potential

  costAnalysis.estimatedMonthlyCost = Math.round(totalEstimatedCost);
  costAnalysis.costOptimizationPotential = Math.round(optimizationPotential);

  // Generate high cost scenario breakdown
  if (findings.criticalScenarios > 0) {
    findings.commonIssues
      .filter(issue => issue.severity === 'critical' && issue.affectedScenarios.length > 0)
      .slice(0, 10)
      .forEach((issue, index) => {
        costAnalysis.costBreakdown.highCostScenarios.push({
          scenarioId: issue.affectedScenarios[0],
          scenarioName: `Critical Scenario ${index + 1}`,
          estimatedMonthlyCost: Math.round(baseCostPerScenario * highComplexityMultiplier),
          optimizationPotential: Math.round(baseCostPerScenario * highComplexityMultiplier * 0.5)
        });
      });
  }

  // Generate cost optimization recommendations
  if (findings.performanceSummary.totalBottlenecks > 0) {
    costAnalysis.recommendations.push({
      type: 'performance',
      description: 'Optimize scenario performance to reduce execution time and costs',
      estimatedSavings: Math.round(optimizationPotential * 0.4),
      implementationEffort: 'medium'
    });
  }

  if (findings.securitySummary.totalSecurityIssues > 0) {
    costAnalysis.recommendations.push({
      type: 'resource',
      description: 'Consolidate security practices to reduce operational overhead',
      estimatedSavings: Math.round(optimizationPotential * 0.2),
      implementationEffort: 'high'
    });
  }

  if (findings.totalIssues > 10) {
    costAnalysis.recommendations.push({
      type: 'usage',
      description: 'Implement scenario health monitoring to prevent costly failures',
      estimatedSavings: Math.round(optimizationPotential * 0.3),
      implementationEffort: 'low'
    });
  }

  return costAnalysis;
}

// Executive summary generation function
export function generateExecutiveSummary(
  findings: ConsolidatedFindings,
  systemOverview: SystemOverview,
  costAnalysis: CostAnalysisReport
): {
  keyFindings: string[];
  criticalRecommendations: string[];
  businessImpact: {
    riskLevel: 'high' | 'medium' | 'low';
    operationalReadiness: 'ready' | 'needs_attention';
    recommendedActions: string;
  };
  nextSteps: string[];
  reportConfidence: {
    dataCompleteness: number;
    analysisDepth: string;
    recommendationReliability: string;
  };
} {
  const keyFindings: string[] = [];
  const criticalRecommendations: string[] = [];

  // Generate key findings
  keyFindings.push(`Analyzed ${findings.totalScenarios} scenarios with ${findings.totalIssues} total issues identified`);
  
  if (findings.criticalScenarios > 0) {
    keyFindings.push(`${findings.criticalScenarios} scenarios require immediate attention due to critical issues`);
  }
  
  if (findings.performanceSummary.averageHealthScore < 70) {
    keyFindings.push(`System performance is below optimal with average health score of ${findings.performanceSummary.averageHealthScore}/100`);
  }
  
  if (findings.securitySummary.criticalSecurityIssues > 0) {
    keyFindings.push(`${findings.securitySummary.criticalSecurityIssues} critical security issues require immediate remediation`);
  }
  
  if (costAnalysis.costOptimizationPotential > 0) {
    keyFindings.push(`Potential monthly cost savings of $${costAnalysis.costOptimizationPotential} identified through optimization`);
  }

  // Generate critical recommendations
  if (findings.criticalIssues > 0) {
    criticalRecommendations.push(`Address ${findings.criticalIssues} critical issues immediately to prevent system failures`);
  }
  
  if (findings.securityRiskLevel === 'high') {
    criticalRecommendations.push('Implement immediate security hardening measures to reduce risk exposure');
  }
  
  if (findings.performanceSummary.averageHealthScore < 60) {
    criticalRecommendations.push('Execute comprehensive performance optimization program to restore system health');
  }
  
  if (costAnalysis.costOptimizationPotential > 500) {
    criticalRecommendations.push('Prioritize cost optimization initiatives to reduce operational expenses');
  }

  // Determine business impact
  let riskLevel: 'high' | 'medium' | 'low' = 'low';
  let operationalReadiness: 'ready' | 'needs_attention' = 'ready';
  let recommendedActions = 'Continue monitoring and maintaining current system health';

  if (findings.criticalIssues > 0 || systemOverview.overallHealth === 'critical') {
    riskLevel = 'high';
    operationalReadiness = 'needs_attention';
    recommendedActions = 'Immediate action required to address critical issues and restore system stability';
  } else if (findings.totalIssues > 5 || systemOverview.overallHealth === 'warning') {
    riskLevel = 'medium';
    operationalReadiness = 'needs_attention';
    recommendedActions = 'Schedule maintenance window to address identified issues and optimize performance';
  }

  // Generate next steps
  const nextSteps = [
    'Review and prioritize critical action items based on business impact',
    'Allocate resources for immediate issue resolution',
    'Implement monitoring solutions for proactive issue detection',
    'Schedule regular system health assessments'
  ];

  if (findings.securitySummary.criticalSecurityIssues > 0) {
    nextSteps.unshift('Execute emergency security remediation plan');
  }

  // Calculate report confidence
  const dataCompleteness = Math.min(100, (findings.totalScenarios * 10)); // Assume 10+ scenarios gives good completeness
  const analysisDepth = findings.totalScenarios >= 20 ? 'comprehensive' : findings.totalScenarios >= 5 ? 'substantial' : 'basic';
  const recommendationReliability = dataCompleteness >= 80 ? 'high' : dataCompleteness >= 50 ? 'medium' : 'low';

  return {
    keyFindings,
    criticalRecommendations,
    businessImpact: {
      riskLevel,
      operationalReadiness,
      recommendedActions
    },
    nextSteps,
    reportConfidence: {
      dataCompleteness: Math.min(100, dataCompleteness),
      analysisDepth,
      recommendationReliability
    }
  };
}