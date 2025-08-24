import { promises as fs } from "fs";
import * as path from "path";
import * as readline from "readline";
// Logger will be injected via import to avoid circular dependency
import { LogPatternAnalyzer } from "./log-pattern-analyzer";
import type { LogEntry } from "./log-pattern-analyzer";

export interface LogAnalysisReport {
  timestamp: Date;
  periodStart: Date;
  periodEnd: Date;
  totalEntries: number;
  patterns: Map<string, number>;
  trends: {
    errorsByHour: Map<string, number>;
    performanceByHour: Map<string, number[]>;
    topErrors: Array<{ message: string; count: number }>;
    recommendations: Array<{
      type: string;
      severity: string;
      message: string;
      action: string;
    }>;
  };
}

export class LogFileAnalyzer {
  private static readonly LOG_DIR = "logs";

  static async analyzeLogFiles(
    hoursBack: number = 24,
  ): Promise<LogAnalysisReport> {
    const report: LogAnalysisReport = {
      timestamp: new Date(),
      periodStart: new Date(Date.now() - hoursBack * 60 * 60 * 1000),
      periodEnd: new Date(),
      totalEntries: 0,
      patterns: new Map(),
      trends: {
        errorsByHour: new Map(),
        performanceByHour: new Map(),
        topErrors: [],
        recommendations: [],
      },
    };

    try {
      // Get log files for analysis period
      const logFiles = await this.getLogFilesInPeriod(hoursBack);

      console.warn(
        `📊 Starting log file analysis: ${hoursBack}h back, ${logFiles.length} files`,
      );

      for (const logFile of logFiles) {
        try {
          await this.analyzeLogFile(path.join(this.LOG_DIR, logFile), report);
        } catch {
          console.warn(`⚠️ Failed to analyze log file: ${logFile}`);
        }
      }

      // Generate insights and recommendations
      this.generateInsights(report);

      console.warn(
        `✅ Log file analysis completed: ${report.totalEntries} entries, ${report.patterns.size} patterns`,
      );
    } catch (error) {
      console.error(
        `❌ Log file analysis failed: ${error instanceof Error ? error.message : "Unknown error"}`,
      );
      throw error;
    }

    return report;
  }

  private static async getLogFilesInPeriod(
    hoursBack: number,
  ): Promise<string[]> {
    try {
      // Check if logs directory exists
      try {
        await fs.access(this.LOG_DIR);
      } catch {
        console.warn(`⚠️ Log directory not found: ${this.LOG_DIR}`);
        return [];
      }

      const files = await fs.readdir(this.LOG_DIR);
      const logFiles = files.filter(
        (file) =>
          file.endsWith(".log") ||
          file.endsWith(".json") ||
          file.match(/\d{4}-\d{2}-\d{2}/),
      );

      const cutoffTime = Date.now() - hoursBack * 60 * 60 * 1000;
      const relevantFiles: string[] = [];

      for (const file of logFiles) {
        try {
          const filePath = path.join(this.LOG_DIR, file);
          const stats = await fs.stat(filePath);

          // Include file if it was modified within the analysis period
          if (stats.mtime.getTime() > cutoffTime) {
            relevantFiles.push(file);
          }
        } catch {
          // Skip file silently
        }
      }

      return relevantFiles.sort();
    } catch (error) {
      console.warn(
        `⚠️ Failed to get log files: ${error instanceof Error ? error.message : "Unknown error"}`,
      );
      return [];
    }
  }

  private static async analyzeLogFile(
    filePath: string,
    report: LogAnalysisReport,
  ): Promise<void> {
    try {
      // Check if file exists and is accessible
      await fs.access(filePath);
    } catch {
      // Skip inaccessible file silently
      return;
    }

    const fileStream = (await import("fs")).createReadStream(filePath);
    const rl = readline.createInterface({
      input: fileStream,
      crlfDelay: Infinity,
    });

    let processedEntries = 0;

    try {
      for await (const line of rl) {
        if (!line.trim()) {
          continue;
        }

        try {
          let entry: LogEntry;

          // Try to parse as JSON first (structured logs)
          if (line.trim().startsWith("{")) {
            const parsed = JSON.parse(line);
            entry = {
              timestamp: new Date(parsed.timestamp || new Date()),
              level: parsed.level || "info",
              message: parsed.message || "",
              correlationId: parsed.correlationId || "unknown",
              operation: parsed.operation,
              category: parsed.category,
              severity: parsed.severity,
              duration: parsed.duration,
              memoryDelta: parsed.memoryDelta,
              statusCode: parsed.statusCode,
              metadata: parsed,
            };
          } else {
            // Handle plain text logs
            entry = {
              timestamp: new Date(),
              level: "info",
              message: line,
              correlationId: "text-log",
              metadata: { originalLine: line },
            };
          }

          // Check if entry is within our analysis period
          if (
            entry.timestamp >= report.periodStart &&
            entry.timestamp <= report.periodEnd
          ) {
            report.totalEntries++;
            processedEntries++;

            // Analyze patterns in this log entry
            const matches = LogPatternAnalyzer.analyzeLogEntry(entry);

            // Update pattern statistics
            matches.forEach((match) => {
              const currentCount = report.patterns.get(match.pattern.id) || 0;
              report.patterns.set(match.pattern.id, currentCount + 1);
            });

            // Update hourly statistics
            this.updateHourlyStats(entry, report);
          }
        } catch {
          // Skip malformed log entries but don't fail the entire analysis
          // Skip malformed entry silently
        }
      }

      if (processedEntries > 0) {
        // Analysis completed silently
      }
    } finally {
      rl.close();
      fileStream.destroy();
    }
  }

  private static updateHourlyStats(
    entry: LogEntry,
    report: LogAnalysisReport,
  ): void {
    const hour = new Date(entry.timestamp).toISOString().substring(0, 13); // YYYY-MM-DDTHH

    // Track errors by hour
    if (entry.level === "error" || entry.level === "warn") {
      const currentCount = report.trends.errorsByHour.get(hour) || 0;
      report.trends.errorsByHour.set(hour, currentCount + 1);
    }

    // Track performance by hour
    if (entry.duration !== undefined && entry.duration > 0) {
      const hourlyPerf = report.trends.performanceByHour.get(hour) || [];
      hourlyPerf.push(entry.duration);
      report.trends.performanceByHour.set(hour, hourlyPerf);
    }
  }

  private static generateInsights(report: LogAnalysisReport): void {
    // Identify error spikes
    const errorHours = Array.from(report.trends.errorsByHour.entries());
    errorHours.sort((a, b) => b[1] - a[1]);

    if (errorHours.length > 0 && errorHours[0][1] > 10) {
      report.trends.recommendations.push({
        type: "error-spike",
        severity: "warning",
        message: `Error spike detected at ${errorHours[0][0]} with ${errorHours[0][1]} errors`,
        action:
          "Investigate error patterns and root causes during this time period",
      });
    }

    // Identify performance degradation
    const avgResponseTimes = new Map<string, number>();
    for (const [hour, durations] of report.trends.performanceByHour) {
      if (durations.length > 0) {
        const avg = durations.reduce((sum, d) => sum + d, 0) / durations.length;
        avgResponseTimes.set(hour, avg);
      }
    }

    const sortedPerf = Array.from(avgResponseTimes.entries()).sort(
      (a, b) => b[1] - a[1],
    );

    if (sortedPerf.length > 0 && sortedPerf[0][1] > 5000) {
      report.trends.recommendations.push({
        type: "performance-degradation",
        severity: "warning",
        message: `Performance degradation detected at ${sortedPerf[0][0]} with ${sortedPerf[0][1].toFixed(2)}ms average response time`,
        action:
          "Review slow operations and optimize performance bottlenecks during this period",
      });
    }

    // Generate top errors list
    // const _errorMessages = new Map<string, number>();
    // This would be populated during log analysis - for now we'll use pattern data
    report.trends.topErrors = Array.from(report.patterns.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([patternId, count]) => ({
        message: `Pattern: ${patternId}`,
        count,
      }));

    // Add general recommendations based on analysis
    if (report.totalEntries === 0) {
      report.trends.recommendations.push({
        type: "no-logs",
        severity: "info",
        message: "No log entries found in the specified time period",
        action:
          "Verify log file location and ensure logging is properly configured",
      });
    } else if (report.patterns.size > 20) {
      report.trends.recommendations.push({
        type: "high-pattern-activity",
        severity: "info",
        message: `High pattern activity detected (${report.patterns.size} different patterns)`,
        action:
          "Review pattern thresholds and consider consolidating similar patterns",
      });
    }
  }

  static async getLogFileStats(): Promise<{
    logDirectory: string;
    totalFiles: number;
    totalSizeBytes: number;
    oldestFile: Date | null;
    newestFile: Date | null;
  }> {
    const stats = {
      logDirectory: this.LOG_DIR,
      totalFiles: 0,
      totalSizeBytes: 0,
      oldestFile: null as Date | null,
      newestFile: null as Date | null,
    };

    try {
      await fs.access(this.LOG_DIR);
      const files = await fs.readdir(this.LOG_DIR);

      for (const file of files) {
        if (
          file.endsWith(".log") ||
          file.endsWith(".json") ||
          file.match(/\d{4}-\d{2}-\d{2}/)
        ) {
          try {
            const filePath = path.join(this.LOG_DIR, file);
            const fileStats = await fs.stat(filePath);

            stats.totalFiles++;
            stats.totalSizeBytes += fileStats.size;

            if (!stats.oldestFile || fileStats.mtime < stats.oldestFile) {
              stats.oldestFile = fileStats.mtime;
            }

            if (!stats.newestFile || fileStats.mtime > stats.newestFile) {
              stats.newestFile = fileStats.mtime;
            }
          } catch {
            // Skip files that can't be accessed
          }
        }
      }
    } catch {
      // Skip directory access error
    }

    return stats;
  }
}
