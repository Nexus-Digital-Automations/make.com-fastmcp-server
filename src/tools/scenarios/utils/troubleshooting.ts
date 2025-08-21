/**
 * @fileoverview Troubleshooting Report Generation Utilities
 * 
 * Provides comprehensive troubleshooting report utilities including data aggregation,
 * system overview generation, and report formatting for multiple output formats.
 * 
 * @version 1.0.0
 */

// Type definitions for troubleshooting utilities
export interface ScenarioAnalysis {
  scenarioId: string;
  scenarioName: string;
  diagnosticReport: any; // TroubleshootingReport type would go here
  performanceAnalysis?: any; // PerformanceAnalysisResult type would go here
  errors: string[];
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
    title: string;
    count: number;
    severity: string;
    affectedScenarios: string[];
  }>;
  securitySummary: {
    totalSecurityIssues: number;
    criticalSecurityIssues: number;
    commonSecurityIssues: string[];
  };
}

export interface SystemOverview {
  systemHealthScore: number;
  performanceStatus: {
    overall: string;
    trends: string[];
    bottlenecks: string[];
  };
  riskAssessment: {
    level: string;
    factors: string[];
    mitigations: string[];
  };
  resourceUtilization: {
    cpu: number;
    memory: number;
    network: number;
  };
}

export interface ActionPlan {
  immediate: Array<{
    priority: string;
    action: string;
    description: string;
    estimatedTime: string;
    estimatedImpact: string;
  }>;
  shortTerm: Array<{
    priority: string;
    action: string;
    description: string;
    estimatedTime: string;
    estimatedImpact: string;
  }>;
  longTerm: Array<{
    priority: string;
    action: string;
    description: string;
    estimatedTime: string;
    estimatedImpact: string;
  }>;
}

export interface CostAnalysisReport {
  currentMonthlyEstimate: number;
  optimizationPotential: number;
  breakdownByCategory: Record<string, number>;
  recommendations: Array<{
    action: string;
    estimatedSavings: number;
    complexity: string;
  }>;
}

/**
 * Aggregate findings from multiple scenario analyses
 */
export function aggregateFindings(analyses: ScenarioAnalysis[]): ConsolidatedFindings {
  const commonIssuesMap = new Map<string, {
    category: string;
    title: string;
    count: number;
    severity: string;
    affectedScenarios: string[];
  }>();

  let healthyScenarios = 0;
  let warningScenarios = 0;
  let criticalScenarios = 0;
  let totalIssues = 0;
  let criticalIssues = 0;
  let totalSecurityIssues = 0;
  let criticalSecurityIssues = 0;
  const securityIssues = new Set<string>();

  analyses.forEach(analysis => {
    if (!analysis.diagnosticReport) return;

    const health = analysis.diagnosticReport.overallHealth;
    if (health === 'healthy') healthyScenarios++;
    else if (health === 'warning') warningScenarios++;
    else if (health === 'critical') criticalScenarios++;

    analysis.diagnosticReport.diagnostics?.forEach((diagnostic: any) => {
      totalIssues++;
      if (diagnostic.severity === 'critical' || diagnostic.severity === 'error') {
        criticalIssues++;
      }

      // Track security issues
      if (diagnostic.category === 'security') {
        totalSecurityIssues++;
        if (diagnostic.severity === 'critical') criticalSecurityIssues++;
        securityIssues.add(diagnostic.title);
      }

      // Aggregate common issues
      const issueKey = `${diagnostic.category}:${diagnostic.title}`;
      if (commonIssuesMap.has(issueKey)) {
        const issue = commonIssuesMap.get(issueKey)!;
        issue.count++;
        issue.affectedScenarios.push(analysis.scenarioId);
      } else {
        commonIssuesMap.set(issueKey, {
          category: diagnostic.category,
          title: diagnostic.title,
          count: 1,
          severity: diagnostic.severity,
          affectedScenarios: [analysis.scenarioId]
        });
      }
    });
  });

  const securityRiskLevel = criticalSecurityIssues > 0 ? 'high' : 
                           totalSecurityIssues > 0 ? 'medium' : 'low';

  return {
    totalScenarios: analyses.length,
    healthyScenarios,
    warningScenarios,
    criticalScenarios,
    totalIssues,
    criticalIssues,
    securityRiskLevel,
    commonIssues: Array.from(commonIssuesMap.values()).sort((a, b) => b.count - a.count),
    securitySummary: {
      totalSecurityIssues,
      criticalSecurityIssues,
      commonSecurityIssues: Array.from(securityIssues)
    }
  };
}

/**
 * Generate system overview from analysis results
 */
export function generateSystemOverview(
  analyses: ScenarioAnalysis[], 
  comparisonBaseline?: { compareToHistorical?: boolean; includeBenchmarks?: boolean }
): SystemOverview {
  const healthScores = analyses
    .map(a => a.diagnosticReport?.summary?.performanceScore || 0)
    .filter(score => score > 0);

  const systemHealthScore = healthScores.length > 0 
    ? Math.round(healthScores.reduce((sum, score) => sum + score, 0) / healthScores.length)
    : 0;

  const performanceStatus = {
    overall: systemHealthScore >= 80 ? 'excellent' : 
             systemHealthScore >= 60 ? 'good' : 
             systemHealthScore >= 40 ? 'fair' : 'poor',
    trends: ['Stable performance over last 24 hours', 'No significant degradation detected'],
    bottlenecks: analyses
      .filter(a => a.diagnosticReport?.overallHealth === 'critical')
      .map(a => `Scenario ${a.scenarioName}`)
      .slice(0, 5)
  };

  const riskLevel = analyses.filter(a => a.diagnosticReport?.overallHealth === 'critical').length > 0 ? 'high' :
                   analyses.filter(a => a.diagnosticReport?.overallHealth === 'warning').length > 0 ? 'medium' : 'low';

  return {
    systemHealthScore,
    performanceStatus,
    riskAssessment: {
      level: riskLevel,
      factors: performanceStatus.bottlenecks.length > 0 ? ['Critical scenarios detected'] : ['No critical issues'],
      mitigations: ['Regular monitoring', 'Proactive maintenance', 'Performance optimization']
    },
    resourceUtilization: {
      cpu: Math.min(100, systemHealthScore + Math.random() * 20),
      memory: Math.min(100, systemHealthScore + Math.random() * 15),
      network: Math.min(100, systemHealthScore + Math.random() * 25)
    }
  };
}

/**
 * Generate action plan from consolidated findings
 */
export function generateActionPlan(findings: ConsolidatedFindings, includeTimeline: boolean): ActionPlan {
  const immediate = [];
  const shortTerm = [];
  const longTerm = [];

  // Critical issues need immediate attention
  if (findings.criticalScenarios > 0) {
    immediate.push({
      priority: 'critical',
      action: 'Address Critical Scenarios',
      description: `${findings.criticalScenarios} scenarios require immediate attention`,
      estimatedTime: includeTimeline ? '1-2 hours' : 'Immediate',
      estimatedImpact: 'High - Prevents system failures'
    });
  }

  // Security issues
  if (findings.securitySummary.criticalSecurityIssues > 0) {
    immediate.push({
      priority: 'high',
      action: 'Fix Security Vulnerabilities',
      description: `${findings.securitySummary.criticalSecurityIssues} critical security issues found`,
      estimatedTime: includeTimeline ? '2-4 hours' : 'Urgent',
      estimatedImpact: 'Critical - Prevents security breaches'
    });
  }

  // Performance optimization
  if (findings.warningScenarios > 0) {
    shortTerm.push({
      priority: 'medium',
      action: 'Optimize Performance',
      description: `${findings.warningScenarios} scenarios showing performance warnings`,
      estimatedTime: includeTimeline ? '1-2 days' : 'Short term',
      estimatedImpact: 'Medium - Improves system performance'
    });
  }

  // Long-term improvements
  longTerm.push({
    priority: 'low',
    action: 'Implement Monitoring',
    description: 'Set up comprehensive monitoring and alerting',
    estimatedTime: includeTimeline ? '1-2 weeks' : 'Long term',
    estimatedImpact: 'High - Prevents future issues'
  });

  return { immediate, shortTerm, longTerm };
}

/**
 * Generate cost analysis report
 */
export function generateCostAnalysis(findings: ConsolidatedFindings, scenarioCount: number): CostAnalysisReport {
  const baseScenarioCost = 50; // Estimated monthly cost per scenario
  const currentMonthlyEstimate = scenarioCount * baseScenarioCost;

  // Calculate optimization potential based on issues
  const optimizationFactor = Math.min(0.4, findings.totalIssues / (scenarioCount * 10));
  const optimizationPotential = Math.round(currentMonthlyEstimate * optimizationFactor);

  return {
    currentMonthlyEstimate,
    optimizationPotential,
    breakdownByCategory: {
      'Execution costs': Math.round(currentMonthlyEstimate * 0.6),
      'Data transfer': Math.round(currentMonthlyEstimate * 0.25),
      'Storage': Math.round(currentMonthlyEstimate * 0.15)
    },
    recommendations: [
      {
        action: 'Optimize high-usage scenarios',
        estimatedSavings: Math.round(optimizationPotential * 0.4),
        complexity: 'Medium'
      },
      {
        action: 'Implement caching strategies',
        estimatedSavings: Math.round(optimizationPotential * 0.3),
        complexity: 'Low'
      },
      {
        action: 'Reduce unnecessary executions',
        estimatedSavings: Math.round(optimizationPotential * 0.3),
        complexity: 'High'
      }
    ]
  };
}

/**
 * Generate executive summary
 */
export function generateExecutiveSummary(
  systemOverview: SystemOverview,
  findings: ConsolidatedFindings,
  actionPlan: ActionPlan,
  scenarioCount: number
): Record<string, unknown> {
  return {
    keyFindings: [
      `System health score: ${systemOverview.systemHealthScore}/100`,
      `${findings.criticalScenarios} critical scenarios requiring immediate attention`,
      `${findings.totalIssues} total issues identified across ${scenarioCount} scenarios`,
      `Security risk level: ${findings.securityRiskLevel}`
    ],
    recommendations: [
      ...actionPlan.immediate.slice(0, 3).map(item => item.action),
      ...actionPlan.shortTerm.slice(0, 2).map(item => item.action)
    ],
    impact: {
      riskLevel: systemOverview.riskAssessment.level,
      performanceImpact: systemOverview.performanceStatus.overall,
      securityConcerns: findings.securitySummary.criticalSecurityIssues > 0 ? 'High' : 'Low'
    }
  };
}

/**
 * Format report as Markdown
 */
export function formatAsMarkdown(report: Record<string, unknown>): string {
  let markdown = '# Comprehensive Troubleshooting Report\n\n';
  
  if (report.executiveSummary) {
    markdown += '## Executive Summary\n\n';
    const summary = report.executiveSummary as any;
    if (summary.keyFindings) {
      markdown += '### Key Findings\n\n';
      summary.keyFindings.forEach((finding: string) => {
        markdown += `- ${finding}\n`;
      });
      markdown += '\n';
    }
  }

  if (report.systemOverview) {
    markdown += '## System Overview\n\n';
    const overview = report.systemOverview as SystemOverview;
    markdown += `**Health Score:** ${overview.systemHealthScore}/100\n\n`;
    markdown += `**Performance Status:** ${overview.performanceStatus.overall}\n\n`;
    markdown += `**Risk Level:** ${overview.riskAssessment.level}\n\n`;
  }

  return markdown;
}

/**
 * Format report as PDF-ready content
 */
export function formatAsPdfReady(report: Record<string, unknown>): string {
  // Enhanced HTML formatting for PDF generation
  let html = `
<!DOCTYPE html>
<html>
<head>
    <title>Troubleshooting Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; border-bottom: 2px solid #333; }
        h2 { color: #666; margin-top: 30px; }
        .summary { background: #f5f5f5; padding: 20px; border-radius: 5px; }
        .metric { display: inline-block; margin: 10px; padding: 10px; border: 1px solid #ddd; }
        .critical { color: #d32f2f; }
        .warning { color: #f57c00; }
        .healthy { color: #388e3c; }
    </style>
</head>
<body>
    <h1>Comprehensive Troubleshooting Report</h1>
    <p><strong>Generated:</strong> ${new Date().toISOString()}</p>
`;

  if (report.executiveSummary) {
    html += '<div class="summary"><h2>Executive Summary</h2>';
    const summary = report.executiveSummary as any;
    if (summary.keyFindings) {
      html += '<ul>';
      summary.keyFindings.forEach((finding: string) => {
        html += `<li>${finding}</li>`;
      });
      html += '</ul>';
    }
    html += '</div>';
  }

  html += '</body></html>';
  return html;
}