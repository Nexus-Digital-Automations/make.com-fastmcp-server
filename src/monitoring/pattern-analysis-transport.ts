import winston from "winston";
import TransportStream from "winston-transport";
import { LogPatternAnalyzer } from "./log-pattern-analyzer";
import type { LogEntry } from "./log-pattern-analyzer";

export class PatternAnalysisTransport extends TransportStream {
  private enabled: boolean;
  private analysisCount: number = 0;
  private lastAnalysisTime: Date | null = null;

  constructor(opts?: TransportStream.TransportStreamOptions) {
    super(opts);

    // Check if pattern analysis is enabled (default: true)
    this.enabled = process.env.LOG_PATTERN_ANALYSIS_ENABLED !== "false";

    if (this.enabled) {
      console.warn("🔍 Pattern analysis transport initialized");
    } else {
      console.warn("🚫 Pattern analysis transport disabled by configuration");
    }
  }

  log(info: winston.LogEntry, callback: () => void): void {
    // Skip analysis if disabled
    if (!this.enabled) {
      callback();
      return;
    }

    try {
      // Convert Winston log entry to our LogEntry format
      const entry: LogEntry = {
        timestamp: new Date(info.timestamp || new Date()),
        level: info.level || "info",
        message: info.message || "",
        correlationId: info.correlationId || "unknown",
        operation: info.operation,
        category: info.category,
        severity: info.severity,
        duration: info.duration,
        memoryDelta: info.memoryDelta,
        statusCode: info.statusCode,
        metadata: { ...info },
      };

      // Analyze the log entry for patterns
      const matches = LogPatternAnalyzer.analyzeLogEntry(entry);

      if (matches.length > 0) {
        this.analysisCount++;
        this.lastAnalysisTime = new Date();

        // Log pattern detection (debug level to avoid noise)
        // Silent pattern detection to avoid log noise
      }

      // Increment analysis counter for monitoring
      this.analysisCount++;
    } catch (error) {
      // Log analysis errors but don't break logging pipeline
      console.warn(
        `⚠️ Pattern analysis error: ${error instanceof Error ? error.message : "Unknown error"}`,
      );
    }

    // Always call callback to continue Winston pipeline
    callback();
  }

  // Method to get transport statistics
  getStatistics(): {
    enabled: boolean;
    analysisCount: number;
    lastAnalysisTime: Date | null;
    registeredPatterns: number;
  } {
    return {
      enabled: this.enabled,
      analysisCount: this.analysisCount,
      lastAnalysisTime: this.lastAnalysisTime,
      registeredPatterns: LogPatternAnalyzer.getRegisteredPatterns().length,
    };
  }

  // Method to enable/disable analysis at runtime
  setEnabled(enabled: boolean): void {
    const wasEnabled = this.enabled;
    this.enabled = enabled;

    if (wasEnabled !== enabled) {
      console.warn(
        `🔄 Pattern analysis transport ${enabled ? "enabled" : "disabled"}`,
      );
    }
  }

  // Method to reset statistics
  resetStatistics(): void {
    this.analysisCount = 0;
    this.lastAnalysisTime = null;

    console.warn("📈 Pattern analysis transport statistics reset");
  }

  // Override close method for cleanup
  close(): void {
    if (this.enabled) {
      console.warn(
        `🚪 Pattern analysis transport closing (${this.analysisCount} analyses)`,
      );
    }
    if (super.close) {
      super.close();
    }
  }

  // Health check method
  isHealthy(): boolean {
    return true; // Transport is stateless and always healthy if enabled
  }
}

// Factory function for easy integration
export function createPatternAnalysisTransport(
  options?: TransportStream.TransportStreamOptions,
): PatternAnalysisTransport {
  return new PatternAnalysisTransport(options);
}

// Helper function to add transport to existing logger
export function addPatternAnalysisToLogger(
  targetLogger: winston.Logger,
  options?: TransportStream.TransportStreamOptions,
): PatternAnalysisTransport {
  const transport = createPatternAnalysisTransport(options);
  targetLogger.add(transport);

  console.warn(
    `➕ Pattern analysis transport added to logger (enabled: ${transport.getStatistics().enabled})`,
  );

  return transport;
}
