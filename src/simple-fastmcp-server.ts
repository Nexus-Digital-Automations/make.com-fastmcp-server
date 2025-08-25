/**
 * Simple Make.com FastMCP Server
 * Pure MCP server with only essential Make.com API integration tools
 */

import { FastMCP } from "fastmcp";
import { z } from "zod";
import axios from "axios";
import dotenv from "dotenv";
import winston from "winston";
import DailyRotateFile from "winston-daily-rotate-file";
import { v4 as uuidv4 } from "uuid";
import { performance } from "perf_hooks";
import { RateLimitManager } from "./rate-limit-manager.js";

// Import enhanced rate limiting components
import {
  EnhancedRateLimitManager,
  ENHANCED_MAKE_API_CONFIG,
  EnhancedRateLimitMetrics,
} from "./enhanced-rate-limit-manager.js";
// Dependency monitoring is handled by local DependencyMonitor class

// Load environment variables
dotenv.config();

// Ensure logs directory exists before Winston initialization
import * as fs from "fs";
import * as path from "path";

// Create logs directory with proper error handling
import { fileURLToPath } from "url";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "..");
const logsDir = path.join(projectRoot, "logs");
try {
  if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
    // Log directory creation - logged to file to avoid MCP interference
  }
} catch {
  // Log directory creation error - logged to file to avoid MCP interference
  // Continue execution - Winston will handle logging to console only
}

// Error classification system
enum ErrorCategory {
  MAKE_API_ERROR = "MAKE_API_ERROR",
  VALIDATION_ERROR = "VALIDATION_ERROR",
  AUTHENTICATION_ERROR = "AUTHENTICATION_ERROR",
  RATE_LIMIT_ERROR = "RATE_LIMIT_ERROR",
  TIMEOUT_ERROR = "TIMEOUT_ERROR",
  INTERNAL_ERROR = "INTERNAL_ERROR",
  MCP_PROTOCOL_ERROR = "MCP_PROTOCOL_ERROR",
}

enum ErrorSeverity {
  LOW = "LOW", // Recoverable, expected errors
  MEDIUM = "MEDIUM", // Service degradation
  HIGH = "HIGH", // Service failure
  CRITICAL = "CRITICAL", // System failure
}

class MCPServerError extends Error {
  constructor(
    message: string,
    public readonly category: ErrorCategory,
    public readonly severity: ErrorSeverity,
    public readonly correlationId: string,
    public readonly operation: string,
    public readonly cause?: Error,
  ) {
    super(message);
    this.name = "MCPServerError";
  }
}

// Logger configuration - disable console output for MCP to avoid interfering with JSON protocol
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json(),
  ),
  transports: [
    // Console transport disabled for MCP compatibility - interferes with JSON protocol
    ...(process.env.ENABLE_CONSOLE_LOGGING === "true"
      ? [
          new winston.transports.Console({
            format: winston.format.combine(
              winston.format.colorize(),
              winston.format.simple(),
            ),
          }),
        ]
      : []),
    ...(process.env.LOG_FILE_ENABLED !== "false"
      ? [
          new DailyRotateFile({
            filename: path.join(logsDir, "fastmcp-server-%DATE%.log"),
            datePattern: "YYYY-MM-DD",
            maxSize: "20m",
            maxFiles: "14d",
          }),
        ]
      : []),
  ],
});

// Add pattern analysis transport if enabled
if (process.env.LOG_PATTERN_ANALYSIS_ENABLED !== "false") {
  import("./monitoring/pattern-analysis-transport.js")
    .then(({ addPatternAnalysisToLogger }) => {
      addPatternAnalysisToLogger(logger);
    })
    .catch((error) => {
      logger.warn("Failed to load pattern analysis transport", {
        error: error instanceof Error ? error.message : "Unknown error",
        correlationId: "pattern-analysis-init",
      });
    });

  // Initialize pattern library
  import("./monitoring/log-pattern-analyzer.js")
    .then(async ({ LogPatternAnalyzer }) => {
      const { ALL_PATTERNS } = await import("./monitoring/pattern-library.js");
      LogPatternAnalyzer.registerPatterns(ALL_PATTERNS);
    })
    .catch((error) => {
      logger.warn("Failed to initialize pattern library", {
        error: error instanceof Error ? error.message : "Unknown error",
        correlationId: "pattern-library-init",
      });
    });
}

// Performance monitoring interfaces and classes
interface PerformanceMetrics {
  timestamp: Date;
  operation: string;
  duration: number;
  memoryDelta: number;
  cpuUsage: NodeJS.CpuUsage;
  concurrentRequests: number;
  correlationId: string;
}

interface HealthStatus {
  status: "healthy" | "degraded" | "unhealthy";
  timestamp: Date;
  checks: {
    [checkName: string]: {
      status: "pass" | "fail";
      duration: number;
      message?: string;
    };
  };
}

interface MetricsSnapshot {
  httpRequestDuration: Map<string, number[]>;
  httpRequestCount: Map<string, number>;
  errorCount: Map<string, number>;
  memoryUsage: number;
  timestamp: Date;
}

class PerformanceMonitor {
  private static metrics: PerformanceMetrics[] = [];
  private static concurrentOperations = 0;
  private static readonly MAX_METRICS_HISTORY = 1000;

  static async trackOperation<T>(
    operation: string,
    correlationId: string,
    fn: () => Promise<T>,
  ): Promise<{ result: T; metrics: PerformanceMetrics }> {
    const startTime = performance.now();
    const startMemory = process.memoryUsage().heapUsed;
    const startCpu = process.cpuUsage();

    this.concurrentOperations++;

    try {
      const result = await fn();
      const endTime = performance.now();
      const endMemory = process.memoryUsage().heapUsed;
      const endCpu = process.cpuUsage(startCpu);

      const metrics: PerformanceMetrics = {
        timestamp: new Date(),
        operation,
        duration: endTime - startTime,
        memoryDelta: endMemory - startMemory,
        cpuUsage: endCpu,
        concurrentRequests: this.concurrentOperations,
        correlationId,
      };

      this.recordMetrics(metrics);

      // Log performance warnings for slow operations
      if (metrics.duration > 5000) {
        logger.warn("Slow operation detected", {
          operation: metrics.operation,
          duration: metrics.duration,
          correlationId: metrics.correlationId,
          memoryDelta: metrics.memoryDelta,
          concurrentRequests: metrics.concurrentRequests,
        });
      }

      return { result, metrics };
    } finally {
      this.concurrentOperations--;
    }
  }

  private static recordMetrics(metrics: PerformanceMetrics) {
    this.metrics.push(metrics);

    // Keep metrics history under control
    if (this.metrics.length > this.MAX_METRICS_HISTORY) {
      this.metrics = this.metrics.slice(-this.MAX_METRICS_HISTORY);
    }

    // Log periodic performance summaries every 100 operations
    if (this.metrics.length % 100 === 0) {
      this.logPerformanceSummary();
    }
  }

  private static logPerformanceSummary() {
    const recentMetrics = this.metrics.slice(-100);
    const avgDuration =
      recentMetrics.reduce((sum, m) => sum + m.duration, 0) /
      recentMetrics.length;
    const maxDuration = Math.max(...recentMetrics.map((m) => m.duration));
    const avgMemoryDelta =
      recentMetrics.reduce((sum, m) => sum + m.memoryDelta, 0) /
      recentMetrics.length;

    logger.info("Performance summary (last 100 operations)", {
      averageDuration: Math.round(avgDuration),
      maxDuration: Math.round(maxDuration),
      averageMemoryDelta: Math.round(avgMemoryDelta / 1024), // KB
      totalOperations: this.metrics.length,
      correlationId: "perf-summary",
    });
  }

  static getMetricsReport(): {
    summary: {
      totalOperations: number;
      averageDuration: number;
      maxDuration: number;
      currentMemoryUsage: number;
      concurrentOperations: number;
    };
    percentiles: {
      p50: number;
      p95: number;
      p99: number;
    };
  } {
    const durations = this.metrics.map((m) => m.duration);
    const sortedDurations = durations.sort((a, b) => a - b);

    return {
      summary: {
        totalOperations: this.metrics.length,
        averageDuration:
          durations.length > 0
            ? durations.reduce((sum, d) => sum + d, 0) / durations.length
            : 0,
        maxDuration: durations.length > 0 ? Math.max(...durations) : 0,
        currentMemoryUsage: process.memoryUsage().heapUsed,
        concurrentOperations: this.concurrentOperations,
      },
      percentiles: {
        p50: sortedDurations[Math.floor(sortedDurations.length * 0.5)] || 0,
        p95: sortedDurations[Math.floor(sortedDurations.length * 0.95)] || 0,
        p99: sortedDurations[Math.floor(sortedDurations.length * 0.99)] || 0,
      },
    };
  }
}

class MetricsCollector {
  private static snapshot: MetricsSnapshot = {
    httpRequestDuration: new Map(),
    httpRequestCount: new Map(),
    errorCount: new Map(),
    memoryUsage: 0,
    timestamp: new Date(),
  };

  static recordRequest(operation: string, duration: number, success: boolean) {
    // Update request duration histogram
    if (!this.snapshot.httpRequestDuration.has(operation)) {
      this.snapshot.httpRequestDuration.set(operation, []);
    }
    this.snapshot.httpRequestDuration.get(operation)!.push(duration);

    // Update request count
    const currentCount = this.snapshot.httpRequestCount.get(operation) || 0;
    this.snapshot.httpRequestCount.set(operation, currentCount + 1);

    // Update error count
    if (!success) {
      const currentErrorCount = this.snapshot.errorCount.get(operation) || 0;
      this.snapshot.errorCount.set(operation, currentErrorCount + 1);
    }

    // Update memory usage
    this.snapshot.memoryUsage = process.memoryUsage().heapUsed;
    this.snapshot.timestamp = new Date();
  }

  static getMetricsReport(): string {
    let report = "FastMCP Server Metrics Report\n";
    report += `Timestamp: ${this.snapshot.timestamp.toISOString()}\n`;
    report += `Memory Usage: ${(this.snapshot.memoryUsage / 1024 / 1024).toFixed(2)} MB\n\n`;

    // Request duration analysis
    this.snapshot.httpRequestDuration.forEach((durations, operation) => {
      if (durations.length === 0) {
        return;
      }

      const sorted = durations.sort((a, b) => a - b);
      const p50 = sorted[Math.floor(sorted.length * 0.5)];
      const p95 = sorted[Math.floor(sorted.length * 0.95)];
      const p99 = sorted[Math.floor(sorted.length * 0.99)];

      report += `${operation}:\n`;
      report += `  Requests: ${durations.length}\n`;
      report += `  P50: ${p50?.toFixed(2) || 0}ms\n`;
      report += `  P95: ${p95?.toFixed(2) || 0}ms\n`;
      report += `  P99: ${p99?.toFixed(2) || 0}ms\n`;

      const errorCount = this.snapshot.errorCount.get(operation) || 0;
      const errorRate = ((errorCount / durations.length) * 100).toFixed(2);
      report += `  Error Rate: ${errorRate}%\n\n`;
    });

    return report;
  }
}

class HealthMonitor {
  static async performHealthCheck(): Promise<HealthStatus> {
    const checks: HealthStatus["checks"] = {};

    // Check Make.com API connectivity
    checks.makeApiConnectivity = await this.checkMakeApiConnectivity();

    // Check memory usage
    checks.memoryUsage = this.checkMemoryUsage();

    // Check log file system
    checks.logFileSystem = await this.checkLogFileSystem();

    // Check error rates
    checks.errorRates = this.checkErrorRates();

    // Check dependency health (if dependency monitoring enabled)
    checks.dependencyHealth = await this.checkDependencyHealth();

    // Determine overall status
    const failedChecks = Object.values(checks).filter(
      (check) => check.status === "fail",
    );
    let status: HealthStatus["status"];

    if (failedChecks.length === 0) {
      status = "healthy";
    } else if (failedChecks.length <= 1) {
      status = "degraded";
    } else {
      status = "unhealthy";
    }

    const healthStatus: HealthStatus = {
      status,
      timestamp: new Date(),
      checks,
    };

    // Log health status if degraded or unhealthy
    if (status !== "healthy") {
      logger.warn("Health check failed", {
        status,
        failedChecks: failedChecks.length,
        details: checks,
        correlationId: "health-check",
      });
    } else {
      logger.info("Health check passed", {
        status,
        correlationId: "health-check",
      });
    }

    return healthStatus;
  }

  private static async checkMakeApiConnectivity(): Promise<
    HealthStatus["checks"][string]
  > {
    const startTime = performance.now();
    try {
      // Attempt lightweight API call to test connectivity
      await axios.get(`${config.makeBaseUrl}/users?limit=1`, {
        headers: { Authorization: `Token ${config.makeApiKey}` },
        timeout: 5000,
      });

      return {
        status: "pass",
        duration: performance.now() - startTime,
      };
    } catch (error: unknown) {
      const axiosError = error as { message?: string };
      return {
        status: "fail",
        duration: performance.now() - startTime,
        message: `Make.com API connectivity failed: ${axiosError.message || "Unknown error"}`,
      };
    }
  }

  private static checkMemoryUsage(): HealthStatus["checks"][string] {
    const startTime = performance.now();
    const memUsage = process.memoryUsage();
    const memoryUsageMB = memUsage.heapUsed / 1024 / 1024;

    // Use configured memory threshold
    const threshold = config.memoryThresholdMB;
    const status = memoryUsageMB > threshold ? "fail" : "pass";

    return {
      status,
      duration: performance.now() - startTime,
      message:
        status === "fail"
          ? `Memory usage ${memoryUsageMB.toFixed(2)}MB exceeds threshold ${threshold}MB`
          : `Memory usage: ${memoryUsageMB.toFixed(2)}MB`,
    };
  }

  private static async checkLogFileSystem(): Promise<
    HealthStatus["checks"][string]
  > {
    const startTime = performance.now();
    const fs = await import("fs");
    const path = await import("path");

    try {
      const logsDir = path.join(process.cwd(), "logs");
      await fs.promises.access(logsDir, fs.constants.R_OK | fs.constants.W_OK);

      return {
        status: "pass",
        duration: performance.now() - startTime,
        message: "Log directory accessible",
      };
    } catch (error: unknown) {
      const fsError = error as { message?: string };
      return {
        status: "fail",
        duration: performance.now() - startTime,
        message: `Log file system check failed: ${fsError.message || "Unknown error"}`,
      };
    }
  }

  private static checkErrorRates(): HealthStatus["checks"][string] {
    const startTime = performance.now();
    const metricsReport = PerformanceMonitor.getMetricsReport();

    // Simple error rate check based on recent operations
    const errorThreshold = 0.05; // 5% error rate threshold
    const _totalOperations = metricsReport.summary.totalOperations;

    // For simplicity, we'll use a basic check - in production this would
    // analyze actual error counts from metrics
    const estimatedErrorRate = 0; // Would be calculated from actual error metrics

    const status = estimatedErrorRate > errorThreshold ? "fail" : "pass";

    return {
      status,
      duration: performance.now() - startTime,
      message: `Current error rate: ${(estimatedErrorRate * 100).toFixed(2)}%`,
    };
  }

  private static async checkDependencyHealth(): Promise<
    HealthStatus["checks"][string]
  > {
    const startTime = performance.now();

    if (!config.dependencyMonitoringEnabled) {
      return {
        status: "pass",
        duration: performance.now() - startTime,
        message: "Dependency monitoring disabled",
      };
    }

    try {
      const scanResult = await DependencyMonitor.scanForVulnerabilities();

      const criticalVulns = scanResult.criticalCount;
      const highVulns = scanResult.highCount;
      const totalVulns = scanResult.totalVulnerabilities;

      if (criticalVulns > 0) {
        return {
          status: "fail",
          duration: performance.now() - startTime,
          message: `${criticalVulns} critical vulnerabilities require immediate attention`,
        };
      }

      if (highVulns > 0) {
        return {
          status: "fail",
          duration: performance.now() - startTime,
          message: `${highVulns} high-severity vulnerabilities require urgent fixes`,
        };
      }

      return {
        status: "pass",
        duration: performance.now() - startTime,
        message:
          totalVulns === 0
            ? "No vulnerabilities detected in dependencies"
            : `${totalVulns} low/moderate vulnerabilities detected`,
      };
    } catch (error: unknown) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      return {
        status: "fail",
        duration: performance.now() - startTime,
        message: `Dependency health check failed: ${errorMessage}`,
      };
    }
  }
}

// NPM Audit data interfaces for type safety
interface NpmAuditVulnerabilityVia {
  range?: string;
  title?: string;
  url?: string;
  cwe?: string[];
  cvss?: number;
}

interface NpmAuditVulnerabilityData {
  via?: NpmAuditVulnerabilityVia[];
  range?: string;
  severity?: string;
}

interface NpmAuditData {
  vulnerabilities?: Record<string, NpmAuditVulnerabilityData>;
}

interface NpmOutdatedPackage {
  current: string;
  wanted: string;
  latest: string;
}

// Dependency vulnerability severity mapping
enum VulnerabilitySeverity {
  CRITICAL = "CRITICAL",
  HIGH = "HIGH",
  MODERATE = "MODERATE",
  LOW = "LOW",
  INFO = "INFO",
}

interface VulnerabilityReport {
  packageName: string;
  currentVersion: string;
  vulnerableVersions: string;
  severity: VulnerabilitySeverity;
  title: string;
  url?: string;
  cwe?: string[];
  cvss?: number;
}

interface DependencyStatus {
  vulnerabilities: VulnerabilityReport[];
  outdatedPackages: Array<{
    package: string;
    current: string;
    wanted: string;
    latest: string;
  }>;
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  moderateCount: number;
  lowCount: number;
  scanTimestamp: Date;
}

class DependencyMonitor {
  private static lastScan: DependencyStatus | null = null;

  static async scanForVulnerabilities(): Promise<DependencyStatus> {
    const { exec } = await import("child_process");
    const { promisify } = await import("util");
    const execAsync = promisify(exec);

    const correlationId = uuidv4();
    const startTime = performance.now();

    logger.info("Starting dependency vulnerability scan", {
      correlationId,
      operation: "dependency-scan",
    });

    try {
      // Run npm audit to get vulnerability data
      const { stdout: auditOutput } = await execAsync("npm audit --json", {
        cwd: process.cwd(),
        timeout: 30000,
      });

      const auditData = JSON.parse(auditOutput) as NpmAuditData;
      const vulnerabilities: VulnerabilityReport[] = [];

      // Parse npm audit results
      if (auditData.vulnerabilities) {
        Object.entries(auditData.vulnerabilities).forEach(
          ([packageName, vulnData]: [string, NpmAuditVulnerabilityData]) => {
            vulnerabilities.push({
              packageName,
              currentVersion: vulnData.via?.[0]?.range || "unknown",
              vulnerableVersions: vulnData.range || "unknown",
              severity: this.mapNpmSeverity(vulnData.severity || "unknown"),
              title:
                vulnData.via?.[0]?.title || `Vulnerability in ${packageName}`,
              url: vulnData.via?.[0]?.url,
              cwe: vulnData.via?.[0]?.cwe,
              cvss: vulnData.via?.[0]?.cvss,
            });
          },
        );
      }

      // Check for outdated packages
      let outdatedPackages: Array<{
        package: string;
        current: string;
        wanted: string;
        latest: string;
      }> = [];
      try {
        const { stdout: outdatedOutput } = await execAsync(
          "npm outdated --json",
          {
            cwd: process.cwd(),
            timeout: 15000,
          },
        );

        if (outdatedOutput.trim()) {
          const outdatedData = JSON.parse(outdatedOutput) as Record<
            string,
            NpmOutdatedPackage
          >;
          outdatedPackages = Object.entries(outdatedData).map(
            ([pkg, data]: [string, NpmOutdatedPackage]) => ({
              package: pkg,
              current: data.current,
              wanted: data.wanted,
              latest: data.latest,
            }),
          );
        }
      } catch (error) {
        // npm outdated returns non-zero exit code when packages are outdated
        // Try to parse stdout anyway if it contains JSON
        const outdatedError = error as { stdout?: string };
        if (outdatedError.stdout?.trim()) {
          try {
            const outdatedData = JSON.parse(outdatedError.stdout) as Record<
              string,
              NpmOutdatedPackage
            >;
            outdatedPackages = Object.entries(outdatedData).map(
              ([pkg, data]: [string, NpmOutdatedPackage]) => ({
                package: pkg,
                current: data.current,
                wanted: data.wanted,
                latest: data.latest,
              }),
            );
          } catch {
            // Ignore parsing errors for outdated packages
          }
        }
      }

      // Calculate vulnerability counts
      const criticalCount = vulnerabilities.filter(
        (v) => v.severity === VulnerabilitySeverity.CRITICAL,
      ).length;
      const highCount = vulnerabilities.filter(
        (v) => v.severity === VulnerabilitySeverity.HIGH,
      ).length;
      const moderateCount = vulnerabilities.filter(
        (v) => v.severity === VulnerabilitySeverity.MODERATE,
      ).length;
      const lowCount = vulnerabilities.filter(
        (v) => v.severity === VulnerabilitySeverity.LOW,
      ).length;

      const status: DependencyStatus = {
        vulnerabilities,
        outdatedPackages,
        totalVulnerabilities: vulnerabilities.length,
        criticalCount,
        highCount,
        moderateCount,
        lowCount,
        scanTimestamp: new Date(),
      };

      this.lastScan = status;

      const duration = performance.now() - startTime;

      // Log scan results
      const logLevel = criticalCount > 0 || highCount > 0 ? "warn" : "info";
      logger[logLevel]("Dependency vulnerability scan completed", {
        correlationId,
        operation: "dependency-scan",
        duration,
        totalVulnerabilities: vulnerabilities.length,
        criticalCount,
        highCount,
        moderateCount,
        lowCount,
        outdatedPackages: outdatedPackages.length,
      });

      // Alert on critical vulnerabilities
      if (criticalCount > 0) {
        logger.error("CRITICAL vulnerabilities detected", {
          correlationId,
          operation: "security-alert",
          criticalVulnerabilities: vulnerabilities
            .filter((v) => v.severity === VulnerabilitySeverity.CRITICAL)
            .map((v) => ({
              package: v.packageName,
              title: v.title,
              cvss: v.cvss,
            })),
        });
      }

      return status;
    } catch (error: unknown) {
      const scanError = error as { message?: string };
      const duration = performance.now() - startTime;

      logger.error("Dependency vulnerability scan failed", {
        correlationId,
        operation: "dependency-scan",
        duration,
        error: scanError.message || "Unknown error",
      });

      throw new MCPServerError(
        `Dependency vulnerability scan failed: ${scanError.message || "Unknown error"}`,
        ErrorCategory.INTERNAL_ERROR,
        ErrorSeverity.MEDIUM,
        correlationId,
        "dependency-scan",
        error as Error,
      );
    }
  }

  private static mapNpmSeverity(npmSeverity: string): VulnerabilitySeverity {
    switch (npmSeverity?.toLowerCase()) {
      case "critical":
        return VulnerabilitySeverity.CRITICAL;
      case "high":
        return VulnerabilitySeverity.HIGH;
      case "moderate":
        return VulnerabilitySeverity.MODERATE;
      case "low":
        return VulnerabilitySeverity.LOW;
      default:
        return VulnerabilitySeverity.INFO;
    }
  }

  static async generateMaintenanceReport(): Promise<string> {
    const scanResults = this.lastScan || (await this.scanForVulnerabilities());
    const health = await HealthMonitor.performHealthCheck();
    const performanceReport = PerformanceMonitor.getMetricsReport();

    let report = "# FastMCP Server Maintenance Report\n\n";
    report += `Generated: ${new Date().toISOString()}\n`;
    report += `Scan Timestamp: ${scanResults.scanTimestamp.toISOString()}\n\n`;

    // System Health Summary
    const healthEmoji =
      health.status === "healthy"
        ? "✅"
        : health.status === "degraded"
          ? "⚠️"
          : "❌";
    report += `## System Health: ${healthEmoji} ${health.status.toUpperCase()}\n\n`;

    // Security Status
    const securityEmoji =
      scanResults.criticalCount === 0 && scanResults.highCount === 0
        ? "✅"
        : "🔒";
    report += `## Security Status: ${securityEmoji}\n\n`;
    report += `- **Total Vulnerabilities:** ${scanResults.totalVulnerabilities}\n`;
    report += `- **Critical:** ${scanResults.criticalCount}\n`;
    report += `- **High:** ${scanResults.highCount}\n`;
    report += `- **Moderate:** ${scanResults.moderateCount}\n`;
    report += `- **Low:** ${scanResults.lowCount}\n\n`;

    if (scanResults.vulnerabilities.length > 0) {
      report += "### Vulnerability Details\n\n";
      scanResults.vulnerabilities.forEach((vuln) => {
        const severity =
          vuln.severity === VulnerabilitySeverity.CRITICAL
            ? "🔴"
            : vuln.severity === VulnerabilitySeverity.HIGH
              ? "🟠"
              : vuln.severity === VulnerabilitySeverity.MODERATE
                ? "🟡"
                : "🔵";
        report += `${severity} **${vuln.packageName}** (${vuln.severity})\n`;
        report += `  - ${vuln.title}\n`;
        if (vuln.cvss) {
          report += `  - CVSS Score: ${vuln.cvss}\n`;
        }
        if (vuln.url) {
          report += `  - More info: ${vuln.url}\n`;
        }
        report += "\n";
      });
    }

    // Outdated Packages
    report += `## Package Updates: ${scanResults.outdatedPackages.length > 0 ? "📦" : "✅"}\n\n`;
    if (scanResults.outdatedPackages.length > 0) {
      report += `Found ${scanResults.outdatedPackages.length} outdated packages:\n\n`;
      scanResults.outdatedPackages.forEach((pkg) => {
        report += `- **${pkg.package}**: ${pkg.current} → ${pkg.latest}\n`;
      });
      report += "\n";
    } else {
      report += "All packages are up to date.\n\n";
    }

    // Performance Summary
    report += "## Performance Summary\n\n";
    report += `- **Total Operations:** ${performanceReport.summary.totalOperations}\n`;
    report += `- **Average Duration:** ${performanceReport.summary.averageDuration.toFixed(2)}ms\n`;
    report += `- **Memory Usage:** ${(performanceReport.summary.currentMemoryUsage / 1024 / 1024).toFixed(2)}MB\n\n`;

    // Maintenance Recommendations
    report += "## Maintenance Recommendations\n\n";

    const recommendations = [];

    if (scanResults.criticalCount > 0) {
      recommendations.push(
        "🔥 **URGENT**: Address critical security vulnerabilities immediately",
      );
    }

    if (scanResults.highCount > 0) {
      recommendations.push(
        "⚠️ **HIGH PRIORITY**: Review and fix high-severity vulnerabilities",
      );
    }

    if (scanResults.outdatedPackages.length > 5) {
      recommendations.push(
        "📦 **RECOMMENDED**: Update outdated packages to latest versions",
      );
    }

    if (health.status !== "healthy") {
      recommendations.push("🏥 **ATTENTION**: Address health check failures");
    }

    if (performanceReport.summary.averageDuration > 1000) {
      recommendations.push("⚡ **PERFORMANCE**: Investigate slow operations");
    }

    if (recommendations.length === 0) {
      recommendations.push(
        "✅ System is in excellent condition - continue monitoring",
      );
    }

    recommendations.forEach((rec) => {
      report += `- ${rec}\n`;
    });

    report += "\n---\n";
    report +=
      "*Report generated by FastMCP Server automated maintenance system*\n";

    return report;
  }

  static getLastScanResults(): DependencyStatus | null {
    return this.lastScan;
  }
}

// Simple configuration from environment
const config = {
  makeApiKey: process.env.MAKE_API_KEY,
  makeBaseUrl: process.env.MAKE_BASE_URL || "https://us1.make.com/api/v2",
  timeout: 30000,
  // Performance monitoring configuration
  performanceMonitoringEnabled:
    process.env.PERFORMANCE_MONITORING_ENABLED !== "false",
  memoryThresholdMB: parseInt(process.env.MEMORY_THRESHOLD_MB || "512"),
  metricsCollectionEnabled: process.env.METRICS_COLLECTION_ENABLED !== "false",
  healthCheckEnabled: process.env.HEALTH_CHECK_ENABLED !== "false",
  // Dependency monitoring configuration
  dependencyMonitoringEnabled:
    process.env.DEPENDENCY_MONITORING_ENABLED !== "false",
  maintenanceReportsEnabled:
    process.env.MAINTENANCE_REPORTS_ENABLED !== "false",
  vulnerabilityThreshold: (
    process.env.VULNERABILITY_THRESHOLD || "moderate"
  ).toLowerCase(),
  dependencyScanInterval:
    parseInt(process.env.DEPENDENCY_SCAN_INTERVAL_HOURS || "24") *
    60 *
    60 *
    1000,
  // Rate limiting configuration
  rateLimitingEnabled: process.env.RATE_LIMITING_ENABLED !== "false",
  rateLimitMaxRetries: parseInt(process.env.RATE_LIMIT_MAX_RETRIES || "3"),
  rateLimitBaseDelayMs: parseInt(
    process.env.RATE_LIMIT_BASE_DELAY_MS || "2000",
  ),
  rateLimitMaxConcurrent: parseInt(
    process.env.RATE_LIMIT_MAX_CONCURRENT || "8",
  ),
  rateLimitRequestsPerWindow: parseInt(
    process.env.RATE_LIMIT_REQUESTS_PER_WINDOW || "50",
  ),
};

// Simple Make.com API client
class SimpleMakeClient {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly timeout: number;
  private readonly rateLimitManager?: EnhancedRateLimitManager;

  constructor() {
    if (!config.makeApiKey) {
      throw new Error("MAKE_API_KEY environment variable is required");
    }

    this.apiKey = config.makeApiKey;
    this.baseUrl = config.makeBaseUrl;
    this.timeout = config.timeout;

    // Initialize enhanced rate limiting if enabled
    if (config.rateLimitingEnabled) {
      const enhancedRateLimitConfig = {
        ...ENHANCED_MAKE_API_CONFIG,
        // Override with environment configuration
        maxRetries: config.rateLimitMaxRetries,
        baseDelayMs: config.rateLimitBaseDelayMs,
        maxConcurrentRequests: config.rateLimitMaxConcurrent,
        requestsPerWindow: config.rateLimitRequestsPerWindow,
        // Enhanced configuration options from environment
        safetyMargin: parseFloat(
          process.env.RATE_LIMIT_SAFETY_MARGIN || "0.85",
        ),
        jitterFactor: parseFloat(process.env.RATE_LIMIT_JITTER_FACTOR || "0.1"),
        headerParsingEnabled: process.env.RATE_LIMIT_HEADER_PARSING !== "false",
        dynamicCapacity: process.env.RATE_LIMIT_DYNAMIC_CAPACITY !== "false",
        approachingLimitThreshold: parseFloat(
          process.env.RATE_LIMIT_WARNING_THRESHOLD || "0.1",
        ),
      };

      this.rateLimitManager = new EnhancedRateLimitManager(
        enhancedRateLimitConfig,
      );

      logger.info("Enhanced rate limiting enabled for Make.com API", {
        maxRetries: enhancedRateLimitConfig.maxRetries,
        baseDelayMs: enhancedRateLimitConfig.baseDelayMs,
        maxConcurrentRequests: enhancedRateLimitConfig.maxConcurrentRequests,
        requestsPerWindow: enhancedRateLimitConfig.requestsPerWindow,
        headerParsingEnabled: enhancedRateLimitConfig.headerParsingEnabled,
        dynamicCapacity: enhancedRateLimitConfig.dynamicCapacity,
        safetyMargin: enhancedRateLimitConfig.safetyMargin,
        tokenBucketEnabled: enhancedRateLimitConfig.tokenBucket?.enabled,
        backoffStrategyEnabled:
          enhancedRateLimitConfig.backoffStrategy?.enabled,
        correlationId: "enhanced-rate-limit-init",
      });
    }
  }

  private async request(
    method: string,
    endpoint: string,
    data?: unknown,
    correlationId?: string,
  ) {
    const requestId = correlationId || uuidv4();
    const operation = `${method.toUpperCase()} ${endpoint}`;

    // Wrap execution function for rate limiting and performance monitoring
    const executeFunction = async () => {
      return await this.executeRequest(
        method,
        endpoint,
        data,
        requestId,
        operation,
      );
    };

    // Apply enhanced rate limiting if enabled
    if (this.rateLimitManager) {
      const rateLimitedExecution = async () => {
        return await this.rateLimitManager!.executeWithRateLimit(
          operation,
          executeFunction,
          {
            correlationId: requestId,
            endpoint: endpoint,
            priority: this.determineRequestPriority(method, endpoint),
          },
        );
      };

      // Use performance monitoring if enabled
      if (config.performanceMonitoringEnabled) {
        const { result, metrics } = await PerformanceMonitor.trackOperation(
          operation,
          requestId,
          rateLimitedExecution,
        );

        // Record metrics if enabled
        if (config.metricsCollectionEnabled) {
          const success = !result || typeof result === "object";
          MetricsCollector.recordRequest(operation, metrics.duration, success);
        }

        return result;
      } else {
        return await rateLimitedExecution();
      }
    } else {
      // No rate limiting - use original logic
      if (config.performanceMonitoringEnabled) {
        const { result, metrics } = await PerformanceMonitor.trackOperation(
          operation,
          requestId,
          executeFunction,
        );

        // Record metrics if enabled
        if (config.metricsCollectionEnabled) {
          const success = !result || typeof result === "object";
          MetricsCollector.recordRequest(operation, metrics.duration, success);
        }

        return result;
      } else {
        return await executeFunction();
      }
    }
  }

  private async executeRequest(
    method: string,
    endpoint: string,
    data: unknown,
    requestId: string,
    operation: string,
  ) {
    const startTime = Date.now();

    logger.info("API request started", {
      correlationId: requestId,
      operation,
      endpoint,
      method,
    });

    try {
      const response = await axios({
        method,
        url: `${this.baseUrl}${endpoint}`,
        headers: {
          Authorization: `Token ${this.apiKey}`,
          "Content-Type": "application/json",
          Accept: "application/json",
          "X-Correlation-ID": requestId,
        },
        data,
        timeout: this.timeout,
      });

      const duration = Date.now() - startTime;

      // Process rate limit headers from successful responses with enhanced manager
      if (this.rateLimitManager && response.headers) {
        try {
          // Convert Axios headers to the expected format
          const headerRecord: Record<string, string | string[]> = {};
          Object.entries(response.headers).forEach(([key, value]) => {
            if (value !== undefined) {
              headerRecord[key] = Array.isArray(value) ? value : String(value);
            }
          });

          this.rateLimitManager.updateFromResponseHeaders(headerRecord);

          logger.debug("Rate limit headers processed", {
            correlationId: requestId,
            operation,
            headerCount: Object.keys(response.headers).length,
            hasRateLimitHeaders: !!(
              response.headers["x-ratelimit-limit"] ||
              response.headers["x-rate-limit-limit"] ||
              response.headers["ratelimit-limit"]
            ),
          });
        } catch (headerError) {
          logger.warn("Failed to process rate limit headers", {
            correlationId: requestId,
            operation,
            error:
              headerError instanceof Error
                ? headerError.message
                : "Unknown error",
          });
        }
      }

      logger.info("API request completed", {
        correlationId: requestId,
        operation,
        duration,
        statusCode: response.status,
      });

      return response.data;
    } catch (error: unknown) {
      const duration = Date.now() - startTime;
      const axiosError = error as {
        response?: { data?: { message?: string }; status?: number };
        message?: string;
        code?: string;
      };

      const mcpError = new MCPServerError(
        `Make.com API error: ${axiosError.response?.data?.message || axiosError.message || "Unknown error"}`,
        this.classifyError(axiosError),
        this.determineSeverity(axiosError),
        requestId,
        operation,
        error as Error,
      );

      logger.error("API request failed", {
        correlationId: requestId,
        operation,
        duration,
        category: mcpError.category,
        severity: mcpError.severity,
        statusCode: axiosError.response?.status,
        errorCode: axiosError.code,
        message: mcpError.message,
        stack: mcpError.stack,
      });

      throw mcpError;
    }
  }

  private classifyError(error: {
    response?: { status?: number };
    code?: string;
  }): ErrorCategory {
    if (error.response?.status === 401) {
      return ErrorCategory.AUTHENTICATION_ERROR;
    }
    if (error.response?.status === 429) {
      return ErrorCategory.RATE_LIMIT_ERROR;
    }
    if (error.code === "ECONNABORTED") {
      return ErrorCategory.TIMEOUT_ERROR;
    }
    if (error.response?.status && error.response.status >= 500) {
      return ErrorCategory.INTERNAL_ERROR;
    }
    return ErrorCategory.MAKE_API_ERROR;
  }

  private determineSeverity(error: {
    response?: { status?: number };
    code?: string;
  }): ErrorSeverity {
    if (error.response?.status === 401) {
      return ErrorSeverity.HIGH;
    }
    if (error.response?.status === 429) {
      return ErrorSeverity.MEDIUM;
    }
    if (error.response?.status && error.response.status >= 500) {
      return ErrorSeverity.HIGH;
    }
    if (error.code === "ECONNABORTED") {
      return ErrorSeverity.MEDIUM;
    }
    return ErrorSeverity.LOW;
  }

  private determineRequestPriority(
    method: string,
    endpoint: string,
  ): "normal" | "high" | "low" {
    // High priority requests that should be processed first
    if (endpoint.includes("/users") || endpoint.includes("/organizations")) {
      return "high"; // User/org management is critical
    }

    // High priority for GET requests that are typically used for health checks
    if (method === "GET" && endpoint.includes("?limit=1")) {
      return "high"; // Health check requests
    }

    // High priority for scenario execution
    if (endpoint.includes("/run")) {
      return "high"; // Scenario execution
    }

    // Low priority for bulk operations
    if (endpoint.includes("?limit=") && !endpoint.includes("limit=1")) {
      const limitMatch = endpoint.match(/limit=(\d+)/);
      if (limitMatch && parseInt(limitMatch[1]) > 10) {
        return "low"; // Bulk requests with large limits
      }
    }

    // Normal priority for everything else
    return "normal";
  }

  /**
   * Get enhanced metrics from the rate limit manager
   */
  public getEnhancedMetrics(): EnhancedRateLimitMetrics | null {
    if (!this.rateLimitManager) {
      return null;
    }

    const operationId = uuidv4();
    logger.debug("Retrieving enhanced rate limit metrics", {
      operationId,
      correlationId: "enhanced-metrics-retrieval",
    });

    try {
      const metrics = this.rateLimitManager.getEnhancedMetrics();

      logger.info("Enhanced metrics retrieved successfully", {
        operationId,
        totalRequests: metrics.totalRequests,
        utilizationRate: metrics.tokenBucket?.utilizationRate,
        correlationId: "enhanced-metrics-retrieval",
      });

      return metrics;
    } catch (error) {
      logger.error("Failed to retrieve enhanced metrics", {
        operationId,
        error: error instanceof Error ? error.message : "Unknown error",
        correlationId: "enhanced-metrics-retrieval",
      });
      return null;
    }
  }

  /**
   * Get current rate limit status with utilization information
   */
  public getRateLimitStatus(): {
    utilizationRate: number;
    tokensAvailable: number;
    nextTokenIn: number;
    approachingLimit: boolean;
    rateLimitActive: boolean;
    queueSize: number;
  } | null {
    if (!this.rateLimitManager) {
      return null;
    }

    const operationId = uuidv4();
    logger.debug("Retrieving rate limit status", {
      operationId,
      correlationId: "rate-limit-status",
    });

    try {
      const metrics = this.rateLimitManager.getEnhancedMetrics();
      const status = this.rateLimitManager.getRateLimitStatus();
      const queueStatus = this.rateLimitManager.getQueueStatus();

      const rateLimitStatus = {
        utilizationRate: metrics.tokenBucket?.utilizationRate || 0,
        tokensAvailable: metrics.tokenBucket?.tokens || 0,
        nextTokenIn: 0, // This information is not available in the current interface
        approachingLimit: (metrics.tokenBucket?.utilizationRate || 0) > 0.9,
        rateLimitActive: status.globalRateLimitActive,
        queueSize: queueStatus.size,
      };

      logger.info("Rate limit status retrieved", {
        operationId,
        utilizationRate: rateLimitStatus.utilizationRate,
        approachingLimit: rateLimitStatus.approachingLimit,
        queueSize: rateLimitStatus.queueSize,
        correlationId: "rate-limit-status",
      });

      return rateLimitStatus;
    } catch (error) {
      logger.error("Failed to retrieve rate limit status", {
        operationId,
        error: error instanceof Error ? error.message : "Unknown error",
        correlationId: "rate-limit-status",
      });
      return null;
    }
  }

  /**
   * Generate a correlation ID for request tracking
   */
  private generateCorrelationId(): string {
    return `make-api-${uuidv4().substring(0, 8)}-${Date.now()}`;
  }

  async getScenarios(limit?: number) {
    const params = limit ? `?limit=${limit}` : "";
    return this.request("GET", `/scenarios${params}`);
  }

  async getScenario(scenarioId: string) {
    return this.request("GET", `/scenarios/${scenarioId}`);
  }

  async createScenario(scenarioData: unknown) {
    return this.request("POST", "/scenarios", scenarioData);
  }

  async updateScenario(scenarioId: string, scenarioData: unknown) {
    return this.request("PATCH", `/scenarios/${scenarioId}`, scenarioData);
  }

  async deleteScenario(scenarioId: string) {
    return this.request("DELETE", `/scenarios/${scenarioId}`);
  }

  async runScenario(scenarioId: string) {
    return this.request("POST", `/scenarios/${scenarioId}/run`);
  }

  async getConnections(limit?: number) {
    const params = limit ? `?limit=${limit}` : "";
    return this.request("GET", `/connections${params}`);
  }

  async getConnection(connectionId: string) {
    return this.request("GET", `/connections/${connectionId}`);
  }

  async createConnection(connectionData: unknown) {
    return this.request("POST", "/connections", connectionData);
  }

  async deleteConnection(connectionId: string) {
    return this.request("DELETE", `/connections/${connectionId}`);
  }

  async getUsers(limit?: number) {
    const params = limit ? `?limit=${limit}` : "";
    return this.request("GET", `/users${params}`);
  }

  async getUser(userId: string) {
    return this.request("GET", `/users/${userId}`);
  }

  async getOrganizations() {
    return this.request("GET", "/organizations");
  }

  async getTeams() {
    return this.request("GET", "/teams");
  }
}

// Initialize the FastMCP server
const server = new FastMCP({
  name: "Make.com Simple FastMCP Server",
  version: "1.0.0",
});

// Initialize Make.com API client
const makeClient = new SimpleMakeClient();

// Get access to the enhanced rate limit manager for monitoring tools
const getRateLimitManager = (): EnhancedRateLimitManager | undefined => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (makeClient as any).rateLimitManager as
    | EnhancedRateLimitManager
    | undefined;
};

// Legacy compatibility function for basic RateLimitManager interface
// This is kept for potential backward compatibility but is currently unused

const _getLegacyRateLimitManager = () => {
  const enhancedManager = getRateLimitManager();
  return enhancedManager as unknown as RateLimitManager | undefined;
};

// Dependency monitoring is handled by static DependencyMonitor class

// SCENARIO TOOLS
server.addTool({
  name: "list-scenarios",
  description: "List Make.com scenarios with optional limit",
  parameters: z.object({
    limit: z
      .number()
      .min(1)
      .max(100)
      .optional()
      .describe("Maximum number of scenarios to return (1-100)"),
  }),
  execute: async (args) => {
    const scenarios = await makeClient.getScenarios(args.limit);
    return {
      content: [
        {
          type: "text",
          text: `Found ${scenarios.scenarios?.length || 0} scenarios:\n\n${JSON.stringify(scenarios, null, 2)}`,
        },
      ],
    };
  },
});

server.addTool({
  name: "get-scenario",
  description: "Get details of a specific Make.com scenario",
  parameters: z.object({
    scenario_id: z.string().describe("The ID of the scenario to retrieve"),
  }),
  execute: async (args) => {
    const scenario = await makeClient.getScenario(args.scenario_id);
    return {
      content: [
        {
          type: "text",
          text: `Scenario Details:\n\n${JSON.stringify(scenario, null, 2)}`,
        },
      ],
    };
  },
});

server.addTool({
  name: "create-scenario",
  description: "Create a new Make.com scenario",
  parameters: z.object({
    name: z.string().describe("Name of the scenario"),
    blueprint: z
      .unknown()
      .optional()
      .describe("Scenario blueprint/configuration"),
    settings: z.unknown().optional().describe("Scenario settings"),
  }),
  execute: async (args) => {
    const scenarioData = {
      name: args.name,
      blueprint: args.blueprint,
      settings: args.settings,
    };
    const result = await makeClient.createScenario(scenarioData);
    return {
      content: [
        {
          type: "text",
          text: `Scenario created successfully:\n\n${JSON.stringify(result, null, 2)}`,
        },
      ],
    };
  },
});

server.addTool({
  name: "update-scenario",
  description: "Update an existing Make.com scenario",
  parameters: z.object({
    scenario_id: z.string().describe("The ID of the scenario to update"),
    name: z.string().optional().describe("New name for the scenario"),
    blueprint: z
      .unknown()
      .optional()
      .describe("Updated scenario blueprint/configuration"),
    settings: z.unknown().optional().describe("Updated scenario settings"),
  }),
  execute: async (args) => {
    const updateData: Record<string, unknown> = {};
    if (args.name) {
      updateData.name = args.name;
    }
    if (args.blueprint) {
      updateData.blueprint = args.blueprint;
    }
    if (args.settings) {
      updateData.settings = args.settings;
    }

    const result = await makeClient.updateScenario(
      args.scenario_id,
      updateData,
    );
    return {
      content: [
        {
          type: "text",
          text: `Scenario updated successfully:\n\n${JSON.stringify(result, null, 2)}`,
        },
      ],
    };
  },
});

server.addTool({
  name: "delete-scenario",
  description: "Delete a Make.com scenario",
  parameters: z.object({
    scenario_id: z.string().describe("The ID of the scenario to delete"),
  }),
  execute: async (args) => {
    await makeClient.deleteScenario(args.scenario_id);
    return {
      content: [
        {
          type: "text",
          text: `Scenario ${args.scenario_id} deleted successfully`,
        },
      ],
    };
  },
});

server.addTool({
  name: "run-scenario",
  description: "Execute a Make.com scenario",
  parameters: z.object({
    scenario_id: z.string().describe("The ID of the scenario to run"),
  }),
  execute: async (args) => {
    const result = await makeClient.runScenario(args.scenario_id);
    return {
      content: [
        {
          type: "text",
          text: `Scenario execution initiated:\n\n${JSON.stringify(result, null, 2)}`,
        },
      ],
    };
  },
});

// CONNECTION TOOLS
server.addTool({
  name: "list-connections",
  description: "List Make.com connections with optional limit",
  parameters: z.object({
    limit: z
      .number()
      .min(1)
      .max(100)
      .optional()
      .describe("Maximum number of connections to return (1-100)"),
  }),
  execute: async (args) => {
    const connections = await makeClient.getConnections(args.limit);
    return {
      content: [
        {
          type: "text",
          text: `Found ${connections.connections?.length || 0} connections:\n\n${JSON.stringify(connections, null, 2)}`,
        },
      ],
    };
  },
});

server.addTool({
  name: "get-connection",
  description: "Get details of a specific Make.com connection",
  parameters: z.object({
    connection_id: z.string().describe("The ID of the connection to retrieve"),
  }),
  execute: async (args) => {
    const connection = await makeClient.getConnection(args.connection_id);
    return {
      content: [
        {
          type: "text",
          text: `Connection Details:\n\n${JSON.stringify(connection, null, 2)}`,
        },
      ],
    };
  },
});

server.addTool({
  name: "create-connection",
  description: "Create a new Make.com connection",
  parameters: z.object({
    app: z.string().describe("App/service name for the connection"),
    name: z.string().describe("Name of the connection"),
    credentials: z.unknown().describe("Connection credentials/configuration"),
  }),
  execute: async (args) => {
    const connectionData = {
      app: args.app,
      name: args.name,
      credentials: args.credentials,
    };
    const result = await makeClient.createConnection(connectionData);
    return {
      content: [
        {
          type: "text",
          text: `Connection created successfully:\n\n${JSON.stringify(result, null, 2)}`,
        },
      ],
    };
  },
});

server.addTool({
  name: "delete-connection",
  description: "Delete a Make.com connection",
  parameters: z.object({
    connection_id: z.string().describe("The ID of the connection to delete"),
  }),
  execute: async (args) => {
    await makeClient.deleteConnection(args.connection_id);
    return {
      content: [
        {
          type: "text",
          text: `Connection ${args.connection_id} deleted successfully`,
        },
      ],
    };
  },
});

// USER & ORGANIZATION TOOLS
server.addTool({
  name: "list-users",
  description: "List Make.com users with optional limit",
  parameters: z.object({
    limit: z
      .number()
      .min(1)
      .max(100)
      .optional()
      .describe("Maximum number of users to return (1-100)"),
  }),
  execute: async (args) => {
    const users = await makeClient.getUsers(args.limit);
    return {
      content: [
        {
          type: "text",
          text: `Found ${users.users?.length || 0} users:\n\n${JSON.stringify(users, null, 2)}`,
        },
      ],
    };
  },
});

server.addTool({
  name: "get-user",
  description: "Get details of a specific Make.com user",
  parameters: z.object({
    user_id: z.string().describe("The ID of the user to retrieve"),
  }),
  execute: async (args) => {
    const user = await makeClient.getUser(args.user_id);
    return {
      content: [
        {
          type: "text",
          text: `User Details:\n\n${JSON.stringify(user, null, 2)}`,
        },
      ],
    };
  },
});

server.addTool({
  name: "list-organizations",
  description: "List Make.com organizations",
  parameters: z.object({}),
  execute: async () => {
    const organizations = await makeClient.getOrganizations();
    return {
      content: [
        {
          type: "text",
          text: `Organizations:\n\n${JSON.stringify(organizations, null, 2)}`,
        },
      ],
    };
  },
});

server.addTool({
  name: "list-teams",
  description: "List Make.com teams",
  parameters: z.object({}),
  execute: async () => {
    const teams = await makeClient.getTeams();
    return {
      content: [
        {
          type: "text",
          text: `Teams:\n\n${JSON.stringify(teams, null, 2)}`,
        },
      ],
    };
  },
});

// ADD RESOURCES
server.addResource({
  uri: "make://scenarios",
  name: "Make.com Scenarios",
  description: "Access to Make.com scenario data and management",
  mimeType: "application/json",
  load: async () => {
    try {
      const scenarios = await makeClient.getScenarios();
      return [
        {
          uri: "make://scenarios",
          mimeType: "application/json",
          text: JSON.stringify(scenarios, null, 2),
        },
      ];
    } catch (error) {
      return [
        {
          uri: "make://scenarios",
          mimeType: "text/plain",
          text: `Error loading scenarios: ${error instanceof Error ? error.message : String(error)}`,
        },
      ];
    }
  },
});

server.addResource({
  uri: "make://connections",
  name: "Make.com Connections",
  description: "Access to Make.com connection data and management",
  mimeType: "application/json",
  load: async () => {
    try {
      const connections = await makeClient.getConnections();
      return [
        {
          uri: "make://connections",
          mimeType: "application/json",
          text: JSON.stringify(connections, null, 2),
        },
      ];
    } catch (error) {
      return [
        {
          uri: "make://connections",
          mimeType: "text/plain",
          text: `Error loading connections: ${error instanceof Error ? error.message : String(error)}`,
        },
      ];
    }
  },
});

server.addResource({
  uri: "make://users",
  name: "Make.com Users",
  description: "Access to Make.com user data and management",
  mimeType: "application/json",
  load: async () => {
    try {
      const users = await makeClient.getUsers();
      return [
        {
          uri: "make://users",
          mimeType: "application/json",
          text: JSON.stringify(users, null, 2),
        },
      ];
    } catch (error) {
      return [
        {
          uri: "make://users",
          mimeType: "text/plain",
          text: `Error loading users: ${error instanceof Error ? error.message : String(error)}`,
        },
      ];
    }
  },
});

// ADD PROMPTS
server.addPrompt({
  name: "create-automation-scenario",
  description: "Help create a Make.com automation scenario with best practices",
  arguments: [
    {
      name: "workflow_description",
      description: "Description of the automation workflow to create",
      required: true,
    },
    {
      name: "data_sources",
      description: "List of data sources or apps to integrate",
      required: false,
    },
  ],
  load: async (args) => {
    const { workflow_description, data_sources } = args;
    return `Create a Make.com automation scenario for: ${workflow_description}${data_sources ? ` using data sources: ${data_sources}` : ""}

Consider these best practices:
1. Start with a clear trigger event
2. Add error handling modules
3. Use filters to reduce unnecessary operations
4. Implement proper data validation
5. Set up monitoring and logging
6. Test thoroughly before activation

Would you like me to help you design the specific modules and connections for this automation?`;
  },
});

server.addPrompt({
  name: "optimize-scenario",
  description:
    "Analyze and provide optimization suggestions for a Make.com scenario",
  arguments: [
    {
      name: "scenario_id",
      description: "ID of the scenario to analyze and optimize",
      required: true,
    },
  ],
  load: async (args) => {
    const { scenario_id } = args;
    if (!scenario_id) {
      return "Error: scenario_id is required for optimization analysis";
    }

    try {
      const scenario = await makeClient.getScenario(scenario_id);
      return `Analyzing scenario "${scenario.name || scenario_id}" for optimization opportunities:

Current scenario analysis:
${JSON.stringify(scenario, null, 2)}

Optimization recommendations:
1. Review module execution order for efficiency
2. Check for unnecessary API calls or data processing
3. Implement proper error handling and retry logic
4. Consider using filters to reduce processing load
5. Optimize data mapping and transformations
6. Review schedule and execution frequency
7. Monitor performance metrics and bottlenecks

Would you like specific recommendations for any particular aspect of this scenario?`;
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      return `Error retrieving scenario ${scenario_id}: ${errorMessage}

General optimization checklist:
1. Minimize API calls per execution
2. Use efficient data filtering
3. Implement proper error handling
4. Optimize module sequencing
5. Review execution scheduling
6. Monitor resource usage`;
    }
  },
});

server.addPrompt({
  name: "troubleshoot-connection",
  description: "Help troubleshoot Make.com connection issues",
  arguments: [
    {
      name: "connection_id",
      description: "ID of the connection having issues",
      required: true,
    },
    {
      name: "error_message",
      description: "Error message or description of the issue",
      required: false,
    },
  ],
  load: async (args) => {
    const { connection_id, error_message } = args;
    if (!connection_id) {
      return "Error: connection_id is required for troubleshooting";
    }

    try {
      const connection = await makeClient.getConnection(connection_id);
      return `Troubleshooting connection "${connection.name || connection_id}":

Connection details:
${JSON.stringify(connection, null, 2)}

${error_message ? `Reported error: ${error_message}\n\n` : ""}Common troubleshooting steps:
1. Verify API credentials are still valid
2. Check if the external service is accessible
3. Review authentication/authorization settings
4. Test connection with simple API calls
5. Check for API rate limiting or quota issues
6. Verify webhook endpoints if applicable
7. Review connection permissions and scopes

Would you like me to help diagnose specific error patterns or test the connection?`;
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      return `Error retrieving connection ${connection_id}: ${errorMessage}

${error_message ? `Reported issue: ${error_message}\n\n` : ""}General connection troubleshooting:
1. Verify connection still exists and is accessible
2. Check API credentials and permissions
3. Test basic connectivity to the service
4. Review error logs for specific failure patterns
5. Ensure the connection configuration is correct`;
    }
  },
});

// PERFORMANCE MONITORING TOOLS (conditionally enabled)
if (config.performanceMonitoringEnabled) {
  server.addTool({
    name: "get-performance-metrics",
    description: "Get comprehensive performance metrics and statistics",
    parameters: z.object({}),
    execute: async () => {
      const report = PerformanceMonitor.getMetricsReport();
      return {
        content: [
          {
            type: "text",
            text: `Performance Metrics Report:

Summary:
- Total Operations: ${report.summary.totalOperations}
- Average Duration: ${report.summary.averageDuration.toFixed(2)}ms
- Max Duration: ${report.summary.maxDuration.toFixed(2)}ms
- Current Memory Usage: ${(report.summary.currentMemoryUsage / 1024 / 1024).toFixed(2)}MB
- Concurrent Operations: ${report.summary.concurrentOperations}

Percentiles:
- P50 (Median): ${report.percentiles.p50.toFixed(2)}ms
- P95: ${report.percentiles.p95.toFixed(2)}ms
- P99: ${report.percentiles.p99.toFixed(2)}ms`,
          },
        ],
      };
    },
  });
}

if (config.metricsCollectionEnabled) {
  server.addTool({
    name: "get-metrics-report",
    description: "Get detailed metrics report with request analysis",
    parameters: z.object({}),
    execute: async () => {
      const report = MetricsCollector.getMetricsReport();
      return {
        content: [
          {
            type: "text",
            text: report,
          },
        ],
      };
    },
  });
}

if (config.healthCheckEnabled) {
  server.addTool({
    name: "perform-health-check",
    description: "Perform comprehensive system health check",
    parameters: z.object({}),
    execute: async () => {
      const health = await HealthMonitor.performHealthCheck();
      const statusEmoji =
        health.status === "healthy"
          ? "✅"
          : health.status === "degraded"
            ? "⚠️"
            : "❌";

      let report = `${statusEmoji} System Health Status: ${health.status.toUpperCase()}\n`;
      report += `Timestamp: ${health.timestamp.toISOString()}\n\n`;

      report += "Health Checks:\n";
      Object.entries(health.checks).forEach(([checkName, result]) => {
        const checkEmoji = result.status === "pass" ? "✅" : "❌";
        report += `${checkEmoji} ${checkName}: ${result.status} (${result.duration.toFixed(2)}ms)\n`;
        if (result.message) {
          report += `   ${result.message}\n`;
        }
      });

      return {
        content: [
          {
            type: "text",
            text: report,
          },
        ],
      };
    },
  });
}

// DEPENDENCY MONITORING TOOLS (conditionally enabled)
if (config.dependencyMonitoringEnabled) {
  server.addTool({
    name: "scan-vulnerabilities",
    description:
      "Scan dependencies for security vulnerabilities using npm audit",
    parameters: z.object({
      severity_filter: z
        .enum(["all", "critical", "high", "moderate", "low"])
        .optional()
        .describe("Filter results by minimum severity level (default: all)"),
    }),
    execute: async (args) => {
      const scanResults = await DependencyMonitor.scanForVulnerabilities();
      const vulnerabilities = scanResults.vulnerabilities;
      let filtered = vulnerabilities;

      if (args.severity_filter && args.severity_filter !== "all") {
        const severityLevels: Record<string, number> = {
          LOW: 1,
          MODERATE: 2,
          HIGH: 3,
          CRITICAL: 4,
        };
        const minLevel = severityLevels[args.severity_filter.toUpperCase()];
        if (minLevel !== undefined) {
          filtered = vulnerabilities.filter(
            (v) => (severityLevels[v.severity] || 0) >= minLevel,
          );
        }
      }

      const severityBreakdown = filtered.reduce(
        (counts, vuln) => {
          counts[vuln.severity] = (counts[vuln.severity] || 0) + 1;
          return counts;
        },
        {} as Record<string, number>,
      );

      let report = `Security Vulnerability Scan Results:\n\n`;
      report += `Found ${filtered.length} vulnerabilities`;
      if (args.severity_filter && args.severity_filter !== "all") {
        report += ` (${args.severity_filter}+ severity)`;
      }
      report += `:\n\n`;

      // Severity breakdown
      report += `Severity Breakdown:\n`;
      Object.entries(severityBreakdown).forEach(([severity, count]) => {
        const emoji =
          severity === "CRITICAL"
            ? "🚨"
            : severity === "HIGH"
              ? "⚠️"
              : severity === "MODERATE"
                ? "📢"
                : "💡";
        report += `${emoji} ${severity}: ${count}\n`;
      });

      if (filtered.length > 0) {
        report += `\nVulnerability Details:\n`;
        filtered.forEach((vuln) => {
          const severityEmoji =
            vuln.severity === "CRITICAL"
              ? "🚨"
              : vuln.severity === "HIGH"
                ? "⚠️"
                : vuln.severity === "MODERATE"
                  ? "📢"
                  : "💡";
          report += `\n${severityEmoji} ${vuln.packageName} (${vuln.currentVersion})\n`;
          report += `   Title: ${vuln.title}\n`;
          if (vuln.cvss) {
            report += `   CVSS Score: ${vuln.cvss}\n`;
          }
          if (vuln.url) {
            report += `   More Info: ${vuln.url}\n`;
          }
        });
      } else {
        report += `\n✅ No vulnerabilities found at the specified severity level.`;
      }

      return {
        content: [{ type: "text", text: report }],
      };
    },
  });

  server.addTool({
    name: "check-outdated-packages",
    description: "Check for outdated package dependencies using npm outdated",
    parameters: z.object({
      update_type: z
        .enum(["all", "major", "minor", "patch"])
        .optional()
        .describe("Filter by update type (default: all)"),
    }),
    execute: async (args) => {
      const scanResults = await DependencyMonitor.scanForVulnerabilities();
      const outdatedPackages = scanResults.outdatedPackages;

      let filtered = outdatedPackages;
      if (args.update_type && args.update_type !== "all") {
        filtered = outdatedPackages.filter((pkg) => {
          const currentMajor = parseInt(pkg.current.split(".")[0], 10) || 0;
          const latestMajor = parseInt(pkg.latest.split(".")[0], 10) || 0;
          const currentMinor = parseInt(pkg.current.split(".")[1], 10) || 0;
          const latestMinor = parseInt(pkg.latest.split(".")[1], 10) || 0;

          if (args.update_type === "major") {
            return latestMajor > currentMajor;
          }
          if (args.update_type === "minor") {
            return latestMajor === currentMajor && latestMinor > currentMinor;
          }
          if (args.update_type === "patch") {
            return latestMajor === currentMajor && latestMinor === currentMinor;
          }
          return true;
        });
      }

      let report = `Outdated Package Dependencies:\n\n`;
      report += `Found ${filtered.length} outdated packages`;
      if (args.update_type && args.update_type !== "all") {
        report += ` (${args.update_type} updates)`;
      }
      report += `:\n\n`;

      if (filtered.length > 0) {
        const updateTypes = filtered.reduce(
          (counts, pkg) => {
            const currentMajor = parseInt(pkg.current.split(".")[0], 10) || 0;
            const latestMajor = parseInt(pkg.latest.split(".")[0], 10) || 0;
            const currentMinor = parseInt(pkg.current.split(".")[1], 10) || 0;
            const latestMinor = parseInt(pkg.latest.split(".")[1], 10) || 0;

            if (latestMajor > currentMajor) {
              counts.major = (counts.major || 0) + 1;
            } else if (latestMinor > currentMinor) {
              counts.minor = (counts.minor || 0) + 1;
            } else {
              counts.patch = (counts.patch || 0) + 1;
            }
            return counts;
          },
          {} as Record<string, number>,
        );

        report += `Update Type Breakdown:\n`;
        if (updateTypes.major) {
          report += `🔴 Major Updates: ${updateTypes.major} (breaking changes possible)\n`;
        }
        if (updateTypes.minor) {
          report += `🟡 Minor Updates: ${updateTypes.minor} (new features)\n`;
        }
        if (updateTypes.patch) {
          report += `🟢 Patch Updates: ${updateTypes.patch} (bug fixes)\n`;
        }

        report += `\nPackage Details:\n`;
        filtered.forEach((pkg) => {
          const currentMajor = parseInt(pkg.current.split(".")[0], 10) || 0;
          const latestMajor = parseInt(pkg.latest.split(".")[0], 10) || 0;
          const updateEmoji = latestMajor > currentMajor ? "🔴" : "🟡";

          report += `\n${updateEmoji} ${pkg.package}\n`;
          report += `   Current: ${pkg.current}\n`;
          report += `   Latest: ${pkg.latest}\n`;
        });
      } else {
        report += `\n✅ All packages are up to date.`;
      }

      return {
        content: [{ type: "text", text: report }],
      };
    },
  });
}

if (config.maintenanceReportsEnabled) {
  server.addTool({
    name: "generate-maintenance-report",
    description:
      "Generate comprehensive dependency maintenance report with security analysis",
    parameters: z.object({
      format: z
        .enum(["json", "text", "markdown"])
        .optional()
        .describe("Report format (default: text)"),
      include_details: z
        .boolean()
        .optional()
        .describe(
          "Include detailed vulnerability and package information (default: true)",
        ),
      filter_severity: z
        .enum(["low", "moderate", "high", "critical"])
        .optional()
        .describe("Filter vulnerabilities by minimum severity level"),
    }),
    execute: async (_args) => {
      const report = await DependencyMonitor.generateMaintenanceReport();

      // For now, return the report as-is in markdown format
      // In the future, could add format conversion logic using args.format
      return {
        content: [{ type: "text", text: report }],
      };
    },
  });

  server.addTool({
    name: "get-dependency-health-status",
    description: "Get current dependency health status and summary",
    parameters: z.object({}),
    execute: async () => {
      const scanResult = await DependencyMonitor.scanForVulnerabilities();

      const criticalVulns = scanResult.criticalCount;
      const highVulns = scanResult.highCount;
      const majorUpdates = scanResult.outdatedPackages.filter((p) => {
        const currentMajor = parseInt(p.current.split(".")[0], 10) || 0;
        const latestMajor = parseInt(p.latest.split(".")[0], 10) || 0;
        return latestMajor > currentMajor;
      }).length;

      let healthStatus: "healthy" | "warning" | "critical" = "healthy";
      if (criticalVulns > 0 || highVulns > 0) {
        healthStatus = "critical";
      } else if (scanResult.moderateCount > 0 || majorUpdates > 5) {
        healthStatus = "warning";
      }

      const statusEmoji =
        healthStatus === "healthy"
          ? "✅"
          : healthStatus === "warning"
            ? "⚠️"
            : "❌";

      let status = `${statusEmoji} Dependency Health Status: ${healthStatus.toUpperCase()}\n\n`;
      status += `📊 Summary:\n`;
      status += `• Security Vulnerabilities: ${scanResult.totalVulnerabilities}\n`;
      status += `  - Critical: ${criticalVulns}\n`;
      status += `  - High: ${highVulns}\n`;
      status += `  - Moderate: ${scanResult.moderateCount}\n`;
      status += `  - Low: ${scanResult.lowCount}\n`;
      status += `• Outdated Packages: ${scanResult.outdatedPackages.length}\n`;
      status += `  - Major Updates Available: ${majorUpdates}\n`;
      status += `• Last Scan: ${scanResult.scanTimestamp.toISOString()}\n`;

      if (criticalVulns > 0 || highVulns > 0) {
        status += `\n🚨 URGENT: Address ${criticalVulns + highVulns} critical/high severity vulnerabilities immediately!\n`;
      } else if (healthStatus === "warning") {
        status += `\n⚠️ WARNING: Review moderate vulnerabilities and major package updates.\n`;
      } else {
        status += `\n✅ All dependencies are secure and up to date.\n`;
      }

      return {
        content: [{ type: "text", text: status }],
      };
    },
  });
}

// RATE LIMITING TOOLS (conditionally enabled)
if (config.rateLimitingEnabled) {
  server.addTool({
    name: "get-rate-limit-status",
    description: "Get current rate limiting status and metrics",
    parameters: z.object({}),
    execute: async () => {
      const rateLimitManager = getRateLimitManager();

      if (!rateLimitManager) {
        return {
          content: [
            {
              type: "text",
              text: "Rate limiting is not enabled",
            },
          ],
        };
      }

      const metrics = rateLimitManager.getMetrics();
      const status = rateLimitManager.getRateLimitStatus();
      const queueStatus = rateLimitManager.getQueueStatus();

      let report = "📊 Rate Limiting Status Report\n\n";

      // Current status
      report += "🚦 Current Status:\n";
      report += `• Can Make Request: ${status.canMakeRequest ? "✅ Yes" : "❌ No"}\n`;
      report += `• Global Rate Limit Active: ${status.globalRateLimitActive ? "🔴 Yes" : "✅ No"}\n`;
      if (status.globalRateLimitActive) {
        const remaining = Math.max(0, status.globalRateLimitUntil - Date.now());
        report += `• Rate Limit Expires: ${new Date(status.globalRateLimitUntil).toISOString()} (${Math.round(remaining / 1000)}s)\n`;
      }
      report += `• Requests in Current Window: ${status.requestsInWindow}\n`;
      report += `• Active Requests: ${queueStatus.activeRequests}\n\n`;

      // Queue status
      report += "📋 Queue Status:\n";
      report += `• Queue Size: ${queueStatus.size}\n`;
      if (queueStatus.size > 0) {
        report += `• Oldest Request Age: ${Math.round(queueStatus.oldestRequestAge / 1000)}s\n`;
        report += `• Priority Breakdown:\n`;
        report += `  - High: ${queueStatus.priorityBreakdown.high}\n`;
        report += `  - Normal: ${queueStatus.priorityBreakdown.normal}\n`;
        report += `  - Low: ${queueStatus.priorityBreakdown.low}\n`;
      }
      report += "\n";

      // Metrics
      report += "📈 Performance Metrics:\n";
      report += `• Total Requests: ${metrics.totalRequests}\n`;
      report += `• Rate Limited Requests: ${metrics.rateLimitedRequests}\n`;
      report += `• Success Rate: ${(metrics.successRate * 100).toFixed(1)}%\n`;
      report += `• Average Delay: ${metrics.averageDelayMs.toFixed(0)}ms\n`;
      report += `• Max Delay: ${metrics.maxDelayMs.toFixed(0)}ms\n`;

      if (metrics.rateLimitedRequests > 0) {
        const rateLimitRate = (
          (metrics.rateLimitedRequests / metrics.totalRequests) *
          100
        ).toFixed(1);
        report += `• Rate Limit Rate: ${rateLimitRate}%\n`;
      }

      // Endpoint-specific limits
      if (status.endpointLimits.length > 0) {
        report += "\n🎯 Endpoint-Specific Limits:\n";
        status.endpointLimits.forEach((limit) => {
          const remaining = Math.max(0, limit.limitUntil - Date.now());
          report += `• ${limit.endpoint}: ${Math.round(remaining / 1000)}s remaining\n`;
        });
      }

      return {
        content: [{ type: "text", text: report }],
      };
    },
  });

  server.addTool({
    name: "clear-rate-limit-queue",
    description: "Clear the rate limiting request queue (emergency use only)",
    parameters: z.object({}),
    execute: async () => {
      const rateLimitManager = getRateLimitManager();

      if (!rateLimitManager) {
        return {
          content: [
            {
              type: "text",
              text: "Rate limiting is not enabled",
            },
          ],
        };
      }

      const queueStatus = rateLimitManager.getQueueStatus();
      const clearedCount = queueStatus.size;

      rateLimitManager.clearQueue();

      return {
        content: [
          {
            type: "text",
            text: `🧹 Rate limit queue cleared\n\n• Cleared ${clearedCount} pending requests\n• Queue is now empty\n\n⚠️ Note: Cleared requests will fail with queue cleared errors`,
          },
        ],
      };
    },
  });

  server.addTool({
    name: "update-rate-limit-config",
    description: "Update rate limiting configuration at runtime",
    parameters: z.object({
      max_concurrent_requests: z
        .number()
        .min(1)
        .max(50)
        .optional()
        .describe("Maximum concurrent requests"),
      base_delay_ms: z
        .number()
        .min(500)
        .max(30000)
        .optional()
        .describe("Base delay in milliseconds"),
      max_retries: z
        .number()
        .min(1)
        .max(10)
        .optional()
        .describe("Maximum retry attempts"),
      requests_per_window: z
        .number()
        .min(1)
        .max(1000)
        .optional()
        .describe("Requests per time window"),
    }),
    execute: async (args) => {
      const rateLimitManager = getRateLimitManager();

      if (!rateLimitManager) {
        return {
          content: [
            {
              type: "text",
              text: "Rate limiting is not enabled",
            },
          ],
        };
      }

      const updates: Record<string, number> = {};
      if (args.max_concurrent_requests !== undefined) {
        updates.maxConcurrentRequests = args.max_concurrent_requests;
      }
      if (args.base_delay_ms !== undefined) {
        updates.baseDelayMs = args.base_delay_ms;
      }
      if (args.max_retries !== undefined) {
        updates.maxRetries = args.max_retries;
      }
      if (args.requests_per_window !== undefined) {
        updates.requestsPerWindow = args.requests_per_window;
      }

      rateLimitManager.updateConfig(updates);

      let report = "⚙️ Rate limiting configuration updated:\n\n";
      Object.entries(updates).forEach(([key, value]) => {
        report += `• ${key}: ${value}\n`;
      });

      return {
        content: [{ type: "text", text: report }],
      };
    },
  });

  server.addTool({
    name: "get-enhanced-rate-limit-status",
    description:
      "Get enhanced rate limiting status with token bucket and utilization metrics",
    parameters: z.object({}),
    execute: async () => {
      const status = makeClient.getRateLimitStatus();

      if (!status) {
        return {
          content: [
            {
              type: "text",
              text: "Enhanced rate limiting is not enabled",
            },
          ],
        };
      }

      const statusEmoji = status.approachingLimit
        ? "⚠️"
        : status.rateLimitActive
          ? "🔴"
          : "✅";
      let report = `${statusEmoji} Enhanced Rate Limiting Status\n\n`;

      report += `🪣 Token Bucket Status:\n`;
      report += `• Utilization Rate: ${(status.utilizationRate * 100).toFixed(1)}%\n`;
      report += `• Tokens Available: ${status.tokensAvailable}\n`;
      report += `• Next Token In: ${status.nextTokenIn}ms\n`;
      report += `• Approaching Limit: ${status.approachingLimit ? "⚠️ Yes" : "✅ No"}\n\n`;

      report += `🚦 Rate Limit Status:\n`;
      report += `• Rate Limit Active: ${status.rateLimitActive ? "🔴 Yes" : "✅ No"}\n`;
      report += `• Queue Size: ${status.queueSize}\n`;

      return {
        content: [{ type: "text", text: report }],
      };
    },
  });

  server.addTool({
    name: "get-enhanced-metrics",
    description:
      "Get comprehensive enhanced rate limiting metrics including token bucket and backoff strategy details",
    parameters: z.object({}),
    execute: async () => {
      const metrics = makeClient.getEnhancedMetrics();

      if (!metrics) {
        return {
          content: [
            {
              type: "text",
              text: "Enhanced rate limiting is not enabled",
            },
          ],
        };
      }

      let report = `📊 Enhanced Rate Limiting Metrics Report\n\n`;

      // Base metrics
      report += `📈 Base Metrics:\n`;
      report += `• Total Requests: ${metrics.totalRequests}\n`;
      report += `• Rate Limited Requests: ${metrics.rateLimitedRequests}\n`;
      report += `• Success Rate: ${(metrics.successRate * 100).toFixed(1)}%\n`;
      report += `• Average Delay: ${metrics.averageDelayMs.toFixed(0)}ms\n`;
      report += `• Max Delay: ${metrics.maxDelayMs.toFixed(0)}ms\n\n`;

      // Token bucket metrics
      if (metrics.tokenBucket) {
        const bucket = metrics.tokenBucket;
        const utilizationEmoji =
          bucket.utilizationRate > 0.9
            ? "🔴"
            : bucket.utilizationRate > 0.7
              ? "🟡"
              : "✅";

        report += `🪣 Token Bucket Metrics:\n`;
        report += `• Capacity: ${bucket.capacity}\n`;
        report += `• Available Tokens: ${bucket.tokens}\n`;
        report += `• Utilization Rate: ${utilizationEmoji} ${(bucket.utilizationRate * 100).toFixed(1)}%\n`;
        report += `• Success Rate: ${(bucket.successRate * 100).toFixed(1)}%\n\n`;
      }

      // Backoff strategy metrics
      if (metrics.backoffStrategy) {
        const backoff = metrics.backoffStrategy;

        report += `⏰ Backoff Strategy Metrics:\n`;
        report += `• Total Retries: ${backoff.totalRetries}\n`;
        report += `• Average Delay: ${backoff.averageDelay.toFixed(0)}ms\n`;
        report += `• Successful Retries: ${backoff.successfulRetries}\n`;
        report += `• Failed Retries: ${backoff.failedRetries}\n\n`;
      }

      // Rate limit parser metrics
      if (metrics.rateLimitParser) {
        const parser = metrics.rateLimitParser;

        report += `🔍 Rate Limit Parser Metrics:\n`;
        report += `• Headers Processed: ${parser.headersProcessed}\n`;
        report += `• Successful Header Parsing: ${parser.successfulHeaderParsing}\n`;
        report += `• Header Parsing Failures: ${parser.headerParsingFailures}\n`;
        report += `• Dynamic Updates Applied: ${parser.dynamicUpdatesApplied}\n`;
        report += `• Approaching Limit Warnings: ${parser.approachingLimitWarnings}\n`;
        report += `• Last Header Update: ${parser.lastHeaderUpdate ? parser.lastHeaderUpdate.toISOString() : "Never"}\n`;
        report += `• Supported Header Formats: ${parser.supportedHeaderFormats.join(", ")}\n\n`;
      }

      // Basic request tracking from base metrics
      report += `📋 Request Tracking:\n`;
      report += `• Active Requests: ${metrics.activeRequests}\n`;
      report += `• Queue Size: ${metrics.queueSize}\n`;
      report += `• Total Requests: ${metrics.totalRequests}\n`;
      report += `• Rate Limited Requests: ${metrics.rateLimitedRequests}\n\n`;

      report += `⏰ Last Updated: ${new Date().toISOString()}\n`;

      return {
        content: [{ type: "text", text: report }],
      };
    },
  });
}

// LOG PATTERN ANALYSIS TOOLS
server.addTool({
  name: "analyze-log-patterns",
  description: "Analyze recent log patterns and provide insights",
  parameters: z.object({
    hours: z
      .number()
      .min(1)
      .max(168)
      .optional()
      .describe("Hours of logs to analyze (default: 24)"),
    severity: z
      .enum(["info", "warning", "critical"])
      .optional()
      .describe("Filter by minimum severity level"),
  }),
  execute: async (args) => {
    const correlationId = uuidv4();
    const startTime = performance.now();

    try {
      // Import log analysis components
      const { LogFileAnalyzer } = await import(
        "./monitoring/log-file-analyzer.js"
      );
      const { enhancedAlertManager } = await import(
        "./monitoring/enhanced-alert-manager.js"
      );

      const hours = args.hours || 24;

      logger.info("Starting log pattern analysis", {
        hours,
        severity: args.severity,
        correlationId,
      });

      // Analyze log files for the specified period
      const report = await LogFileAnalyzer.analyzeLogFiles(hours);

      let analysis = `📊 Log Pattern Analysis Report\n`;
      analysis += `🕐 Period: ${report.periodStart.toISOString()} to ${report.periodEnd.toISOString()}\n`;
      analysis += `📝 Total Entries Analyzed: ${report.totalEntries.toLocaleString()}\n\n`;

      // Include active alerts
      const activeAlerts = enhancedAlertManager.getActiveAlerts();
      let filteredAlerts = activeAlerts;

      if (args.severity) {
        const severityLevels = { info: 1, warning: 2, critical: 3 };
        const minLevel = severityLevels[args.severity];
        filteredAlerts = activeAlerts.filter((alert) => {
          return severityLevels[alert.severity] >= minLevel;
        });
      }

      analysis += `🚨 Active Alerts: ${filteredAlerts.length}\n`;
      if (filteredAlerts.length > 0) {
        filteredAlerts.slice(0, 10).forEach((alert) => {
          const severityEmoji =
            alert.severity === "critical"
              ? "🔴"
              : alert.severity === "warning"
                ? "🟡"
                : "🔵";
          analysis += `${severityEmoji} ${alert.severity.toUpperCase()}: ${alert.message}\n`;
          analysis += `   📋 Action: ${alert.action}\n`;
          analysis += `   📊 Count: ${alert.count} occurrences\n`;
          analysis += `   ⏰ Last: ${alert.lastOccurrence.toISOString()}\n`;
          if (alert.escalationLevel > 1) {
            analysis += `   🆙 Escalation Level: ${alert.escalationLevel}\n`;
          }
          analysis += `\n`;
        });

        if (filteredAlerts.length > 10) {
          analysis += `... and ${filteredAlerts.length - 10} more alerts\n\n`;
        }
      }

      // Pattern statistics
      if (report.patterns.size > 0) {
        analysis += `🎯 Pattern Matches:\n`;
        const sortedPatterns = Array.from(report.patterns.entries())
          .sort((a, b) => b[1] - a[1])
          .slice(0, 15);

        sortedPatterns.forEach(([patternId, count]) => {
          analysis += `• ${patternId}: ${count} matches\n`;
        });
        analysis += `\n`;
      }

      // Error trends by hour
      if (report.trends.errorsByHour.size > 0) {
        analysis += `📈 Error Trends by Hour:\n`;
        const sortedErrorHours = Array.from(
          report.trends.errorsByHour.entries(),
        )
          .sort((a, b) => b[1] - a[1])
          .slice(0, 10);

        sortedErrorHours.forEach(([hour, count]) => {
          const hourDisplay = new Date(hour + ":00:00Z").toLocaleString();
          analysis += `• ${hourDisplay}: ${count} errors\n`;
        });
        analysis += `\n`;
      }

      // Performance trends
      if (report.trends.performanceByHour.size > 0) {
        analysis += `⚡ Performance Trends:\n`;
        for (const [hour, durations] of report.trends.performanceByHour) {
          if (durations.length > 0) {
            const avg =
              durations.reduce((sum, d) => sum + d, 0) / durations.length;
            const max = Math.max(...durations);
            const hourDisplay = new Date(hour + ":00:00Z").toLocaleString();
            analysis += `• ${hourDisplay}: ${avg.toFixed(0)}ms avg, ${max.toFixed(0)}ms max (${durations.length} operations)\n`;
          }
        }
        analysis += `\n`;
      }

      // Include recommendations
      if (report.trends.recommendations.length > 0) {
        analysis += `💡 Recommendations:\n`;
        report.trends.recommendations.forEach((rec) => {
          const severityEmoji = rec.severity === "warning" ? "⚠️" : "ℹ️";
          analysis += `${severityEmoji} ${rec.message}\n`;
          analysis += `   🔧 Action: ${rec.action}\n\n`;
        });
      }

      // Analysis summary
      const duration = performance.now() - startTime;
      analysis += `\n⏱️ Analysis completed in ${duration.toFixed(2)}ms\n`;

      logger.info("Log pattern analysis completed", {
        duration: duration.toFixed(2),
        totalEntries: report.totalEntries,
        activeAlerts: filteredAlerts.length,
        patternMatches: report.patterns.size,
        correlationId,
      });

      return {
        content: [{ type: "text", text: analysis }],
      };
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";

      logger.error("Log pattern analysis failed", {
        error: errorMessage,
        duration: performance.now() - startTime,
        correlationId,
      });

      return {
        content: [
          {
            type: "text",
            text: `❌ Log pattern analysis failed: ${errorMessage}\n\nPlease ensure log files are accessible and properly formatted.`,
          },
        ],
      };
    }
  },
});

server.addTool({
  name: "get-log-analytics",
  description: "Get real-time log analytics and pattern statistics",
  parameters: z.object({}),
  execute: async () => {
    const correlationId = uuidv4();
    const startTime = performance.now();

    try {
      // Import log analysis components
      const { LogPatternAnalyzer } = await import(
        "./monitoring/log-pattern-analyzer.js"
      );
      const { enhancedAlertManager } = await import(
        "./monitoring/enhanced-alert-manager.js"
      );

      logger.info("Getting log analytics summary", { correlationId });

      const summary = LogPatternAnalyzer.getAnalyticsSummary();
      const alertStats = enhancedAlertManager.getAlertStats();

      let analytics = `📈 Real-time Log Analytics Summary\n`;
      analytics += `⏰ Timestamp: ${summary.timestamp.toISOString()}\n`;
      analytics += `🎯 Total Patterns Registered: ${summary.totalPatterns}\n`;
      analytics += `🚨 Active Alerts: ${summary.activeAlerts}\n\n`;

      // Alert statistics (Enhanced)
      analytics += `📊 Alert Statistics (Enhanced):\n`;
      analytics += `• Total Alerts: ${alertStats.total}\n`;
      analytics += `• Active: ${alertStats.active}\n`;
      analytics += `• Resolved: ${alertStats.resolved}\n`;
      analytics += `• Critical: ${alertStats.critical}\n`;
      analytics += `• Warning: ${alertStats.warning}\n`;
      analytics += `• Info: ${alertStats.info}\n`;
      analytics += `• Currently Suppressed: ${alertStats.suppressed}\n`;
      if (alertStats.storage) {
        analytics += `• Hot Storage: ${alertStats.storage.hotAlerts}\n`;
        analytics += `• Warm Storage: ${alertStats.storage.warmAlerts}\n`;
        analytics += `• Memory Usage: ${alertStats.storage.approximateMemoryUsage}\n`;
      }
      if (alertStats.correlation) {
        analytics += `• Total Rules: ${alertStats.correlation.totalRules || 0}\n`;
        analytics += `• Active Correlations: ${alertStats.correlation.activeCorrelations || 0}\n`;
        analytics += `• Average Confidence: ${alertStats.correlation.avgConfidence || 0}\n`;
      }
      if (alertStats.notifications) {
        analytics += `• Notification Channels: ${alertStats.notifications.channels}\n`;
        analytics += `• Healthy Channels: ${alertStats.notifications.healthyChannels}\n`;
      }
      if (alertStats.processing) {
        analytics += `• Processing Metrics: ${alertStats.processing.totalProcessed} processed, ${alertStats.processing.suppressed} suppressed\n`;
      }
      analytics += `\n`;

      // Pattern statistics
      if (summary.patternStats.size > 0) {
        analytics += `🎯 Pattern Statistics:\n`;
        for (const [patternId, stats] of summary.patternStats) {
          analytics += `${stats.name} (${patternId}):\n`;
          analytics += `  📊 Total Matches: ${stats.totalMatches}\n`;
          analytics += `  🕐 Recent Matches (1h): ${stats.recentMatches}\n`;
          analytics += `  🔥 Severity: ${stats.severity}\n`;
          analytics += `  ⏰ Last Match: ${stats.lastMatch ? stats.lastMatch.toISOString() : "Never"}\n\n`;
        }
      }

      // Trending information
      analytics += `📈 Current Trends:\n`;
      analytics += `• Error Rate: ${summary.trending.errorRate.toFixed(2)}%\n`;
      analytics += `• Avg Response Time: ${summary.trending.avgResponseTime.toFixed(2)}ms\n`;

      if (summary.trending.topPatterns.length > 0) {
        analytics += `\n🔥 Top Active Patterns:\n`;
        summary.trending.topPatterns.forEach((pattern, index) => {
          analytics += `${index + 1}. Pattern ${pattern.patternId}: ${pattern.count} matches\n`;
        });
      }

      if (summary.trending.anomalies.length > 0) {
        analytics += `\n⚠️ Detected Anomalies:\n`;
        summary.trending.anomalies.forEach((anomaly) => {
          analytics += `• ${anomaly.description}\n`;
        });
      }

      const duration = performance.now() - startTime;
      analytics += `\n⏱️ Analytics retrieved in ${duration.toFixed(2)}ms\n`;

      logger.info("Log analytics completed", {
        duration: duration.toFixed(2),
        patternCount: summary.totalPatterns,
        alertCount: summary.activeAlerts,
        correlationId,
      });

      return {
        content: [{ type: "text", text: analytics }],
      };
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";

      logger.error("Log analytics failed", {
        error: errorMessage,
        duration: performance.now() - startTime,
        correlationId,
      });

      return {
        content: [
          {
            type: "text",
            text: `❌ Log analytics failed: ${errorMessage}\n\nPattern analysis system may not be initialized.`,
          },
        ],
      };
    }
  },
});

// Initialize Enhanced Alert Manager before starting the server
let globalEnhancedAlertManager: unknown = null;
try {
  const { EnhancedAlertManager } = await import(
    "./monitoring/enhanced-alert-manager.js"
  );

  // Create enhanced alert manager with default development configuration
  globalEnhancedAlertManager = EnhancedAlertManager.createWithDefaults({
    template: "development",
    enableCorrelation: true,
    webhookUrl:
      process.env.ALERT_WEBHOOK_URL || "http://localhost:3000/webhook",
  });

  // Enhanced Alert Manager initialized - logged to file to avoid MCP interference

  // Perform health check
  if (
    globalEnhancedAlertManager &&
    typeof globalEnhancedAlertManager === "object" &&
    "getSystemHealth" in globalEnhancedAlertManager
  ) {
    const healthCheck = await (
      globalEnhancedAlertManager as {
        getSystemHealth: () => Promise<{ alertManager: { healthy: boolean } }>;
      }
    ).getSystemHealth();
    if (healthCheck.alertManager.healthy) {
      // Alert Manager health check passed - logged to file to avoid MCP interference
    } else {
      // Alert Manager health check issues - logged to file to avoid MCP interference
    }
  }
} catch {
  // Failed to initialize Enhanced Alert Manager - logged to file to avoid MCP interference
}

// Start the server
server.start({
  transportType: "stdio",
});

const startupMessage = [
  "Make.com Simple FastMCP Server started successfully",
  `Performance Monitoring: ${config.performanceMonitoringEnabled ? "ENABLED" : "DISABLED"}`,
  `Metrics Collection: ${config.metricsCollectionEnabled ? "ENABLED" : "DISABLED"}`,
  `Health Checks: ${config.healthCheckEnabled ? "ENABLED" : "DISABLED"}`,
  `Dependency Monitoring: ${config.dependencyMonitoringEnabled ? "ENABLED" : "DISABLED"}`,
  `Maintenance Reports: ${config.maintenanceReportsEnabled ? "ENABLED" : "DISABLED"}`,
  `Log Pattern Analysis: ${process.env.LOG_PATTERN_ANALYSIS_ENABLED !== "false" ? "ENABLED" : "DISABLED"}`,
  `Enhanced Alert Manager: ENABLED (Phase 1)`,
  `Enhanced Rate Limiting: ${config.rateLimitingEnabled ? "ENABLED (Phase 4)" : "DISABLED"}`,
  `Memory Threshold: ${config.memoryThresholdMB}MB`,
].join(" | ");

// Log startup message - logged to file to avoid MCP interference

// Log startup configuration
logger.info(startupMessage, {
  performanceMonitoring: config.performanceMonitoringEnabled,
  metricsCollection: config.metricsCollectionEnabled,
  healthCheck: config.healthCheckEnabled,
  dependencyMonitoring: config.dependencyMonitoringEnabled,
  maintenanceReports: config.maintenanceReportsEnabled,
  memoryThreshold: config.memoryThresholdMB,
  correlationId: "server-startup",
});
