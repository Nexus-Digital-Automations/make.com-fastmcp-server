/**
 * @fileoverview Report Formatting Utilities
 * 
 * Provides report formatting capabilities for troubleshooting reports,
 * including Markdown and PDF-ready HTML formatting.
 * 
 * @version 1.0.0
 */

import { ConsolidatedFindings, ActionPlan } from './troubleshooting.js';

// Local interfaces for report formatting
interface ReportMetadata {
  reportId?: string;
  generatedAt?: string;
  analysisScope?: {
    scenarioCount?: number;
    timeRangeHours?: number;
  };
}

interface TroubleshootingReportData {
  metadata?: ReportMetadata;
  executiveSummary?: {
    keyFindings: string[];
    criticalRecommendations: string[];
    businessImpact: {
      riskLevel: 'high' | 'medium' | 'low';
      operationalReadiness: 'ready' | 'needs_attention';
      recommendedActions: string;
    };
  };
  systemOverview?: {
    systemHealthScore: number;
    performanceStatus: string;
    overallStatus: string;
  };
  consolidatedFindings?: ConsolidatedFindings;
  actionPlan?: ActionPlan;
  [key: string]: unknown;
}

// Format report as Markdown
export function formatAsMarkdown(report: Record<string, unknown>): string {
  let markdown = '# Comprehensive Troubleshooting Report\n\n';
  
  // Add metadata if available
  const metadata = report.metadata as ReportMetadata | undefined;
  if (metadata) {
    markdown += `**Report ID:** ${metadata.reportId || 'N/A'}  \n`;
    markdown += `**Generated:** ${metadata.generatedAt || 'N/A'}  \n`;
    markdown += `**Scenarios Analyzed:** ${metadata.analysisScope?.scenarioCount || 0}  \n\n`;
  }

  const executiveSummary = report.executiveSummary as TroubleshootingReportData['executiveSummary'];
  if (executiveSummary) {
    markdown += `## Executive Summary\n\n`;
    
    markdown += `### Key Findings\n`;
    executiveSummary.keyFindings?.forEach((finding: string) => {
      markdown += `- ${finding}\n`;
    });
    
    markdown += `\n### Critical Recommendations\n`;
    executiveSummary.criticalRecommendations?.forEach((rec: string) => {
      markdown += `- **${rec}**\n`;
    });
    
    markdown += `\n### Business Impact\n`;
    if (executiveSummary.businessImpact) {
      markdown += `- **Risk Level:** ${executiveSummary.businessImpact.riskLevel.toUpperCase()}\n`;
      markdown += `- **Operational Readiness:** ${executiveSummary.businessImpact.operationalReadiness}\n`;
      markdown += `- **Recommended Actions:** ${executiveSummary.businessImpact.recommendedActions}\n\n`;
    }
  }

  const systemOverview = report.systemOverview as TroubleshootingReportData['systemOverview'];
  if (systemOverview) {
    markdown += `## System Overview\n\n`;
    markdown += `- **System Health Score:** ${systemOverview.systemHealthScore}/100\n`;
    markdown += `- **Performance Status:** ${systemOverview.performanceStatus}\n`;
    markdown += `- **Overall Status:** ${systemOverview.overallStatus}\n\n`;
  }

  const consolidatedFindings = report.consolidatedFindings as ConsolidatedFindings;
  if (consolidatedFindings) {
    markdown += `## Consolidated Findings\n\n`;
    markdown += `- **Total Issues:** ${consolidatedFindings.commonIssues.length}\n`;
    markdown += `- **Critical Issues:** ${consolidatedFindings.securitySummary.criticalSecurityIssues}\n`;
    markdown += `- **Critical Scenarios:** ${consolidatedFindings.criticalScenarios}\n\n`;
  }

  const actionPlan = report.actionPlan as ActionPlan;
  if (actionPlan) {
    markdown += `## Action Plan\n\n`;
    markdown += `### Immediate Actions (0-24 hours)\n`;
    actionPlan.immediate?.forEach((action: ActionPlan['immediate'][0]) => {
      markdown += `- **[${action.priority.toUpperCase()}]** ${action.action}\n`;
    });
    markdown += `\n### Short Term Actions (1-4 weeks)\n`;
    actionPlan.shortTerm?.forEach((action: ActionPlan['shortTerm'][0]) => {
      markdown += `- ${action.action}\n`;
    });
    markdown += `\n`;
  }

  return markdown;
}

// Format report as PDF-ready HTML
export function formatAsPdfReady(report: Record<string, unknown>): string {
  // This would generate HTML suitable for PDF generation
  let html = `<!DOCTYPE html>
<html>
<head>
  <title>Troubleshooting Report - ${(report.metadata as ReportMetadata)?.reportId || 'N/A'}</title>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; margin: 40px; }
    h1, h2, h3 { color: #333; }
    .critical { color: #d32f2f; font-weight: bold; }
    .warning { color: #f57c00; }
    .info { color: #1976d2; }
    .summary-box { background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0; }
    .metric { display: inline-block; margin: 10px 20px 10px 0; }
    .score { font-size: 24px; font-weight: bold; color: #1976d2; }
  </style>
</head>
<body>`;

  html += `<h1>Comprehensive Troubleshooting Report</h1>`;
  const metadata = report.metadata as ReportMetadata | undefined;
  html += `<p><strong>Report ID:</strong> ${metadata?.reportId || 'N/A'}</p>`;
  html += `<p><strong>Generated:</strong> ${metadata?.generatedAt || 'N/A'}</p>`;
  html += `<p><strong>Scenarios Analyzed:</strong> ${metadata?.analysisScope?.scenarioCount || 0}</p>`;

  const executiveSummary = report.executiveSummary as TroubleshootingReportData['executiveSummary'];
  if (executiveSummary) {
    html += `<div class="summary-box">`;
    html += `<h2>Executive Summary</h2>`;
    html += `<h3>Key Findings</h3><ul>`;
    executiveSummary.keyFindings?.forEach((finding: string) => {
      html += `<li>${finding}</li>`;
    });
    html += `</ul><h3>Critical Recommendations</h3><ul>`;
    executiveSummary.criticalRecommendations?.forEach((rec: string) => {
      html += `<li class="critical">${rec}</li>`;
    });
    html += `</ul></div>`;
  }

  const systemOverview = report.systemOverview as TroubleshootingReportData['systemOverview'];
  if (systemOverview) {
    html += `<h2>System Overview</h2>`;
    html += `<div class="metric">System Health Score: <span class="score">${systemOverview.systemHealthScore}/100</span></div>`;
    html += `<div class="metric">Performance Status: <strong>${systemOverview.performanceStatus}</strong></div>`;
  }

  html += `</body></html>`;
  
  return html;
}