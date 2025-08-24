/**
 * Automated Maintenance Report Generation System
 * Based on comprehensive research report: research-report-task_1756074929016_cbrqv6xki.md
 *
 * Generates comprehensive maintenance reports with vulnerability analysis,
 * package update recommendations, and actionable insights for operational excellence.
 */

import winston from "winston";
import {
  DependencyMonitor,
  VulnerabilityAlert,
  OutdatedPackage,
} from "./dependency-monitor.js";

// Report interfaces based on research specifications
export interface MaintenanceReport {
  timestamp: Date;
  summary: {
    totalDependencies: number;
    vulnerabilities: {
      total: number;
      critical: number;
      high: number;
      moderate: number;
      low: number;
    };
    outdatedPackages: {
      total: number;
      majorUpdates: number;
      minorUpdates: number;
      patchUpdates: number;
    };
    healthStatus: "healthy" | "warning" | "critical";
  };
  vulnerabilityDetails: VulnerabilityAlert[];
  outdatedPackageDetails: OutdatedPackage[];
  recommendations: string[];
  actionItems: Array<{
    priority: "high" | "medium" | "low";
    action: string;
    description: string;
    automated: boolean;
  }>;
  reportMetadata: {
    generationDuration: number;
    scanTools: string[];
    reportVersion: string;
  };
}

export interface ReportExportOptions {
  format: "json" | "text" | "markdown";
  includeDetails: boolean;
  filterSeverity?: "low" | "moderate" | "high" | "critical";
}

/**
 * Enterprise-grade maintenance report generator with comprehensive analysis
 * and multi-format export capabilities integrated with Winston logging
 */
export class MaintenanceReportGenerator {
  private dependencyMonitor: DependencyMonitor;
  private logger: winston.Logger;

  constructor(dependencyMonitor: DependencyMonitor, logger: winston.Logger) {
    this.dependencyMonitor = dependencyMonitor;
    this.logger = logger;
  }

  /**
   * Generate comprehensive maintenance report with vulnerability analysis
   * and actionable recommendations for operational excellence
   */
  async generateReport(): Promise<MaintenanceReport> {
    const startTime = Date.now();
    const timestamp = new Date();

    this.logger.info("Generating maintenance report", {
      correlationId: "maintenance-report",
      timestamp: timestamp.toISOString(),
    });

    try {
      // Perform comprehensive dependency scan
      const scanResult =
        await this.dependencyMonitor.performComprehensiveScan();
      const packageJson = await this.loadPackageJson();

      // Generate comprehensive report analysis
      const report: MaintenanceReport = {
        timestamp,
        summary: this.generateSummary(
          scanResult.vulnerabilities,
          scanResult.outdatedPackages,
          packageJson,
        ),
        vulnerabilityDetails: scanResult.vulnerabilities,
        outdatedPackageDetails: scanResult.outdatedPackages,
        recommendations: this.generateRecommendations(
          scanResult.vulnerabilities,
          scanResult.outdatedPackages,
        ),
        actionItems: this.generateActionItems(
          scanResult.vulnerabilities,
          scanResult.outdatedPackages,
        ),
        reportMetadata: {
          generationDuration: Date.now() - startTime,
          scanTools: ["npm-audit", "npm-outdated"],
          reportVersion: "1.0.0",
        },
      };

      // Log report generation completion
      this.logger.info("Maintenance report generated successfully", {
        correlationId: "maintenance-report",
        summary: {
          healthStatus: report.summary.healthStatus,
          vulnerabilities: report.summary.vulnerabilities.total,
          outdatedPackages: report.summary.outdatedPackages.total,
          recommendations: report.recommendations.length,
          actionItems: report.actionItems.length,
        },
        generationDuration: report.reportMetadata.generationDuration,
        timestamp: report.timestamp.toISOString(),
      });

      return report;
    } catch (error) {
      const generationDuration = Date.now() - startTime;
      this.logger.error("Failed to generate maintenance report", {
        correlationId: "maintenance-report",
        error: error instanceof Error ? error.message : String(error),
        generationDuration,
      });
      throw error;
    }
  }

  /**
   * Generate executive summary with health status assessment
   */
  private generateSummary(
    vulnerabilities: VulnerabilityAlert[],
    outdatedPackages: OutdatedPackage[],
    packageJson: {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    },
  ) {
    // Vulnerability severity breakdown
    const vulnCounts = vulnerabilities.reduce(
      (counts, vuln) => {
        counts[vuln.severity]++;
        counts.total++;
        return counts;
      },
      { total: 0, critical: 0, high: 0, moderate: 0, low: 0 },
    );

    // Package update priority breakdown
    const outdatedCounts = outdatedPackages.reduce(
      (counts, pkg) => {
        const currentMajor = this.getMajorVersion(pkg.currentVersion);
        const latestMajor = this.getMajorVersion(pkg.latestVersion);
        const currentMinor = this.getMinorVersion(pkg.currentVersion);
        const latestMinor = this.getMinorVersion(pkg.latestVersion);

        if (latestMajor > currentMajor) {
          counts.majorUpdates++;
        } else if (latestMinor > currentMinor) {
          counts.minorUpdates++;
        } else {
          counts.patchUpdates++;
        }
        counts.total++;
        return counts;
      },
      { total: 0, majorUpdates: 0, minorUpdates: 0, patchUpdates: 0 },
    );

    // Determine overall health status based on research criteria
    let healthStatus: "healthy" | "warning" | "critical" = "healthy";
    if (vulnCounts.critical > 0 || vulnCounts.high > 0) {
      healthStatus = "critical";
    } else if (vulnCounts.moderate > 0 || outdatedCounts.majorUpdates > 5) {
      healthStatus = "warning";
    }

    return {
      totalDependencies:
        Object.keys(packageJson.dependencies || {}).length +
        Object.keys(packageJson.devDependencies || {}).length,
      vulnerabilities: vulnCounts,
      outdatedPackages: outdatedCounts,
      healthStatus,
    };
  }

  /**
   * Generate comprehensive recommendations based on scan results
   * Prioritized by security impact and maintenance urgency
   */
  private generateRecommendations(
    vulnerabilities: VulnerabilityAlert[],
    outdatedPackages: OutdatedPackage[],
  ): string[] {
    const recommendations: string[] = [];

    // Critical vulnerability recommendations
    const criticalVulns = vulnerabilities.filter(
      (v) => v.severity === "critical",
    );
    const highVulns = vulnerabilities.filter((v) => v.severity === "high");

    if (criticalVulns.length > 0) {
      recommendations.push(
        `🚨 URGENT: Address ${criticalVulns.length} critical vulnerabilities immediately`,
      );
      recommendations.push(
        `💡 Review security impact and plan emergency fixes for: ${criticalVulns.map((v) => v.packageName).join(", ")}`,
      );
    }

    if (highVulns.length > 0) {
      recommendations.push(
        `⚠️ HIGH PRIORITY: Fix ${highVulns.length} high-severity vulnerabilities`,
      );
      recommendations.push(
        `📋 Schedule security updates within 48 hours for: ${highVulns.map((v) => v.packageName).join(", ")}`,
      );
    }

    // Automated fix recommendations
    const autoFixable = vulnerabilities.filter((v) => v.fixAvailable);
    if (autoFixable.length > 0) {
      recommendations.push(
        `🔧 Run 'npm audit fix' to automatically resolve ${autoFixable.length} vulnerabilities`,
      );
      recommendations.push(
        `✅ Automated fixes available for: ${autoFixable.map((v) => v.packageName).join(", ")}`,
      );
    }

    // Package update recommendations
    if (outdatedPackages.length > 0) {
      const majorUpdates = outdatedPackages.filter(
        (p) =>
          this.getMajorVersion(p.latestVersion) >
          this.getMajorVersion(p.currentVersion),
      );

      if (majorUpdates.length > 0) {
        recommendations.push(
          `📦 Review ${majorUpdates.length} packages with major version updates available`,
        );
        recommendations.push(
          `⚠️ Test thoroughly before applying major updates: ${majorUpdates.map((p) => p.packageName).join(", ")}`,
        );
      }

      const minorUpdates = outdatedPackages.filter((p) => {
        const currentMajor = this.getMajorVersion(p.currentVersion);
        const latestMajor = this.getMajorVersion(p.latestVersion);
        const currentMinor = this.getMinorVersion(p.currentVersion);
        const latestMinor = this.getMinorVersion(p.latestVersion);
        return latestMajor === currentMajor && latestMinor > currentMinor;
      });

      if (minorUpdates.length > 0) {
        recommendations.push(
          `🔄 Consider updating ${minorUpdates.length} packages with minor version updates`,
        );
      }
    }

    // General maintenance recommendations (from research report)
    recommendations.push(
      "📊 Review performance metrics for any degradation patterns",
    );
    recommendations.push("🔍 Analyze logs for recurring error patterns");
    recommendations.push("🧹 Clean up log files older than 14 days");
    recommendations.push(
      "🔐 Verify all security configurations and access controls",
    );
    recommendations.push(
      "📈 Monitor dependency update frequency and plan regular maintenance windows",
    );

    return recommendations;
  }

  /**
   * Generate prioritized action items with automation flags
   */
  private generateActionItems(
    vulnerabilities: VulnerabilityAlert[],
    outdatedPackages: OutdatedPackage[],
  ) {
    const actionItems = [];

    // Vulnerability-based actions (highest priority)
    vulnerabilities.forEach((vuln) => {
      const priority =
        vuln.severity === "critical"
          ? "high"
          : vuln.severity === "high"
            ? "high"
            : "medium";

      actionItems.push({
        priority,
        action: `Fix ${vuln.severity} vulnerability in ${vuln.packageName}`,
        description: `${vuln.description} (CVE: ${vuln.cve})`,
        automated: vuln.fixAvailable,
      });
    });

    // Package update actions (medium priority)
    outdatedPackages.forEach((pkg) => {
      const majorUpdate =
        this.getMajorVersion(pkg.latestVersion) >
        this.getMajorVersion(pkg.currentVersion);

      actionItems.push({
        priority: majorUpdate ? "medium" : "low",
        action: `Update ${pkg.packageName}`,
        description: `${pkg.currentVersion} → ${pkg.latestVersion}${majorUpdate ? " (MAJOR VERSION)" : ""}`,
        automated: !majorUpdate && pkg.type !== "devDependencies",
      });
    });

    // Maintenance actions (low priority)
    actionItems.push({
      priority: "low" as const,
      action: "Review dependency licenses",
      description:
        "Ensure all dependencies comply with organization license policies",
      automated: false,
    });

    actionItems.push({
      priority: "low" as const,
      action: "Analyze bundle size impact",
      description:
        "Review dependency tree for bundle size optimization opportunities",
      automated: false,
    });

    return actionItems;
  }

  /**
   * Export report in multiple formats (JSON, Markdown, Text)
   */
  async exportReport(
    report: MaintenanceReport,
    options: ReportExportOptions,
  ): Promise<string> {
    this.logger.info("Exporting maintenance report", {
      correlationId: "maintenance-report-export",
      format: options.format,
      includeDetails: options.includeDetails,
      filterSeverity: options.filterSeverity,
    });

    try {
      let exportedReport: string;

      switch (options.format) {
        case "json":
          exportedReport = this.exportAsJSON(report, options);
          break;
        case "markdown":
          exportedReport = this.exportAsMarkdown(report, options);
          break;
        case "text":
          exportedReport = this.exportAsText(report, options);
          break;
        default:
          throw new Error(`Unsupported export format: ${options.format}`);
      }

      this.logger.info("Maintenance report exported successfully", {
        correlationId: "maintenance-report-export",
        format: options.format,
        reportSize: exportedReport.length,
      });

      return exportedReport;
    } catch (error) {
      this.logger.error("Failed to export maintenance report", {
        correlationId: "maintenance-report-export",
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  }

  private exportAsJSON(
    report: MaintenanceReport,
    options: ReportExportOptions,
  ): string {
    if (options.filterSeverity) {
      const filteredReport = {
        ...report,
        vulnerabilityDetails: report.vulnerabilityDetails.filter(
          (v) => v.severity === options.filterSeverity,
        ),
      };
      return JSON.stringify(filteredReport, null, 2);
    }
    return JSON.stringify(report, null, 2);
  }

  private exportAsMarkdown(
    report: MaintenanceReport,
    _options: ReportExportOptions,
  ): string {
    const statusEmoji =
      report.summary.healthStatus === "healthy"
        ? "✅"
        : report.summary.healthStatus === "warning"
          ? "⚠️"
          : "❌";

    let markdown = `# Dependency Maintenance Report\n\n`;
    markdown += `**Status:** ${statusEmoji} ${report.summary.healthStatus.toUpperCase()}\n`;
    markdown += `**Generated:** ${report.timestamp.toISOString()}\n`;
    markdown += `**Generation Duration:** ${report.reportMetadata.generationDuration}ms\n\n`;

    // Executive Summary
    markdown += `## Executive Summary\n\n`;
    markdown += `- **Total Dependencies:** ${report.summary.totalDependencies}\n`;
    markdown += `- **Vulnerabilities:** ${report.summary.vulnerabilities.total} total (${report.summary.vulnerabilities.critical} critical, ${report.summary.vulnerabilities.high} high)\n`;
    markdown += `- **Outdated Packages:** ${report.summary.outdatedPackages.total} total (${report.summary.outdatedPackages.majorUpdates} major updates)\n\n`;

    // Recommendations
    if (report.recommendations.length > 0) {
      markdown += `## Recommendations\n\n`;
      report.recommendations.forEach((rec) => {
        markdown += `- ${rec}\n`;
      });
      markdown += `\n`;
    }

    // Action Items
    if (report.actionItems.length > 0) {
      markdown += `## Action Items\n\n`;
      const highPriority = report.actionItems.filter(
        (item) => item.priority === "high",
      );
      const mediumPriority = report.actionItems.filter(
        (item) => item.priority === "medium",
      );
      const lowPriority = report.actionItems.filter(
        (item) => item.priority === "low",
      );

      if (highPriority.length > 0) {
        markdown += `### High Priority\n`;
        highPriority.forEach((item) => {
          markdown += `- **${item.action}** ${item.automated ? "(Automated)" : "(Manual)"}\n`;
          markdown += `  - ${item.description}\n`;
        });
        markdown += `\n`;
      }

      if (mediumPriority.length > 0) {
        markdown += `### Medium Priority\n`;
        mediumPriority.forEach((item) => {
          markdown += `- **${item.action}** ${item.automated ? "(Automated)" : "(Manual)"}\n`;
          markdown += `  - ${item.description}\n`;
        });
        markdown += `\n`;
      }

      if (lowPriority.length > 0) {
        markdown += `### Low Priority\n`;
        lowPriority.forEach((item) => {
          markdown += `- **${item.action}** ${item.automated ? "(Automated)" : "(Manual)"}\n`;
          markdown += `  - ${item.description}\n`;
        });
      }
    }

    return markdown;
  }

  private exportAsText(
    report: MaintenanceReport,
    _options: ReportExportOptions,
  ): string {
    const statusSymbol =
      report.summary.healthStatus === "healthy"
        ? "[✓]"
        : report.summary.healthStatus === "warning"
          ? "[!]"
          : "[✗]";

    let text = `DEPENDENCY MAINTENANCE REPORT\n`;
    text += `${"=".repeat(50)}\n\n`;
    text += `Status: ${statusSymbol} ${report.summary.healthStatus.toUpperCase()}\n`;
    text += `Generated: ${report.timestamp.toISOString()}\n`;
    text += `Generation Duration: ${report.reportMetadata.generationDuration}ms\n\n`;

    text += `EXECUTIVE SUMMARY\n`;
    text += `${"-".repeat(20)}\n`;
    text += `Total Dependencies: ${report.summary.totalDependencies}\n`;
    text += `Vulnerabilities: ${report.summary.vulnerabilities.total} (Critical: ${report.summary.vulnerabilities.critical}, High: ${report.summary.vulnerabilities.high})\n`;
    text += `Outdated Packages: ${report.summary.outdatedPackages.total} (Major Updates: ${report.summary.outdatedPackages.majorUpdates})\n\n`;

    if (report.recommendations.length > 0) {
      text += `RECOMMENDATIONS\n`;
      text += `${"-".repeat(15)}\n`;
      report.recommendations.forEach((rec, index) => {
        // Remove emoji characters for plain text output
        const cleanRec = rec.replace(
          /[\u{1F300}-\u{1F6FF}]|[\u{1F900}-\u{1F9FF}]|[\u{2600}-\u{26FF}]|[\u{2700}-\u{27BF}]/gu,
          "",
        );
        text += `${index + 1}. ${cleanRec}\n`;
      });
      text += `\n`;
    }

    return text;
  }

  // Utility methods

  private getMajorVersion(version: string): number {
    const cleaned = version.replace(/^[\^~]/, ""); // Remove semver prefixes
    return parseInt(cleaned.split(".")[0], 10) || 0;
  }

  private getMinorVersion(version: string): number {
    const cleaned = version.replace(/^[\^~]/, ""); // Remove semver prefixes
    return parseInt(cleaned.split(".")[1], 10) || 0;
  }

  private async loadPackageJson(): Promise<{
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  }> {
    const fs = await import("fs");
    try {
      const packageJsonPath = `${process.cwd()}/package.json`;
      const packageJsonContent = await fs.promises.readFile(
        packageJsonPath,
        "utf8",
      );
      return JSON.parse(packageJsonContent);
    } catch (error) {
      this.logger.warn("Failed to load package.json", {
        correlationId: "maintenance-report",
        error: error instanceof Error ? error.message : String(error),
      });
      return { dependencies: {}, devDependencies: {} };
    }
  }
}
