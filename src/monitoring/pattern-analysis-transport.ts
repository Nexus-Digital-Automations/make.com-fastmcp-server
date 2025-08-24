import * as winston from "winston";
import { LogPatternAnalyzer } from "./log-pattern-analyzer";
import type { LogEntry } from "./log-pattern-analyzer";
import { logger } from "../utils/logger";

export class PatternAnalysisTransport extends winston.Transport {
  private enabled: boolean;
  private analysisCount: number = 0;
  private lastAnalysisTime: Date | null = null;

  constructor(opts?: winston.Transport.TransportStreamOptions) {
    super(opts);
    
    // Check if pattern analysis is enabled (default: true)
    this.enabled = process.env.LOG_PATTERN_ANALYSIS_ENABLED !== "false";
    
    if (this.enabled) {
      logger.info("Pattern analysis transport initialized", {
        correlationId: "pattern-analysis-transport",
      });
    } else {
      logger.info("Pattern analysis transport disabled by configuration", {
        correlationId: "pattern-analysis-transport",
      });
    }
  }

  log(info: any, callback: () => void): void {
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
        logger.debug("Log patterns detected", {
          patterns: matches.map((m) => ({
            name: m.pattern.name,
            severity: m.pattern.severity,
            patternId: m.pattern.id,
          })),
          originalMessage: entry.message.substring(0, 100), // Truncate for safety
          correlationId: entry.correlationId || "pattern-analysis",
        });
      }

      // Increment analysis counter for monitoring
      this.analysisCount++;

    } catch (error) {
      // Log analysis errors but don't break logging pipeline
      logger.warn("Pattern analysis error", {
        error: error instanceof Error ? error.message : "Unknown error",
        originalLevel: info.level,
        correlationId: "pattern-analysis-transport",
      });
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
      logger.info("Pattern analysis transport status changed", {
        enabled,
        correlationId: "pattern-analysis-transport",
      });
    }
  }

  // Method to reset statistics
  resetStatistics(): void {
    this.analysisCount = 0;
    this.lastAnalysisTime = null;
    
    logger.info("Pattern analysis transport statistics reset", {
      correlationId: "pattern-analysis-transport",
    });
  }

  // Override close method for cleanup
  close(): void {
    if (this.enabled) {
      logger.info("Pattern analysis transport closing", {
        finalAnalysisCount: this.analysisCount,
        correlationId: "pattern-analysis-transport",
      });
    }
    super.close();
  }

  // Health check method
  isHealthy(): boolean {
    return true; // Transport is stateless and always healthy if enabled
  }
}

// Factory function for easy integration
export function createPatternAnalysisTransport(
  options?: winston.Transport.TransportStreamOptions,
): PatternAnalysisTransport {
  return new PatternAnalysisTransport(options);
}

// Helper function to add transport to existing logger
export function addPatternAnalysisToLogger(
  targetLogger: winston.Logger,
  options?: winston.Transport.TransportStreamOptions,
): PatternAnalysisTransport {
  const transport = createPatternAnalysisTransport(options);
  targetLogger.add(transport);
  
  logger.info("Pattern analysis transport added to logger", {
    transportEnabled: transport.getStatistics().enabled,
    correlationId: "pattern-analysis-transport",
  });
  
  return transport;
}