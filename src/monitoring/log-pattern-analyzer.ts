import { logger } from "../utils/logger";

export interface LogEntry {
  timestamp: Date;
  level: string;
  message: string;
  correlationId: string;
  operation?: string;
  category?: string;
  severity?: string;
  duration?: number;
  memoryDelta?: number;
  statusCode?: number;
  metadata: Record<string, unknown>;
}

export interface LogPattern {
  id: string;
  name: string;
  pattern: RegExp;
  severity: "info" | "warning" | "critical";
  action: string;
  threshold?: number;
  timeWindowMs?: number;
  suppressionMs?: number;
  description: string;
}

export interface PatternMatch {
  pattern: LogPattern;
  entry: LogEntry;
  matchData: RegExpMatchArray;
  timestamp: Date;
  count: number;
}

export interface LogAnalyticsSummary {
  timestamp: Date;
  totalPatterns: number;
  activeAlerts: number;
  patternStats: Map<string, PatternStatistics>;
  trending: {
    errorRate: number;
    avgResponseTime: number;
    topPatterns: Array<{ patternId: string; count: number }>;
    anomalies: Array<{ type: string; description: string }>;
  };
}

export interface PatternStatistics {
  name: string;
  totalMatches: number;
  recentMatches: number;
  lastMatch: Date | null;
  severity: string;
}

export class LogPatternAnalyzer {
  private static patterns: Map<string, LogPattern> = new Map();
  private static recentMatches: Map<string, PatternMatch[]> = new Map();
  private static readonly MAX_MATCH_HISTORY = 1000;

  static registerPattern(pattern: LogPattern): void {
    this.patterns.set(pattern.id, pattern);
    logger.info("Log pattern registered", {
      patternId: pattern.id,
      name: pattern.name,
      severity: pattern.severity,
      correlationId: "log-analyzer",
    });
  }

  static registerPatterns(patterns: LogPattern[]): void {
    patterns.forEach((pattern) => this.registerPattern(pattern));
    logger.info("Multiple log patterns registered", {
      count: patterns.length,
      correlationId: "log-analyzer",
    });
  }

  static analyzeLogEntry(entry: LogEntry): PatternMatch[] {
    const matches: PatternMatch[] = [];

    for (const [patternId, pattern] of this.patterns) {
      const match = entry.message.match(pattern.pattern);
      if (match) {
        const patternMatch: PatternMatch = {
          pattern,
          entry,
          matchData: match,
          timestamp: new Date(),
          count: 1,
        };

        matches.push(patternMatch);
        this.recordMatch(patternId, patternMatch);

        // Check if pattern exceeds threshold
        if (
          pattern.threshold &&
          this.getPatternCount(patternId, pattern.timeWindowMs) >=
            pattern.threshold
        ) {
          // Import AlertManager dynamically to avoid circular dependency
          import("./alert-manager").then(({ AlertManager }) => {
            AlertManager.triggerAlert(patternMatch);
          });
        }
      }
    }

    return matches;
  }

  private static recordMatch(patternId: string, match: PatternMatch): void {
    if (!this.recentMatches.has(patternId)) {
      this.recentMatches.set(patternId, []);
    }

    const matches = this.recentMatches.get(patternId)!;
    matches.push(match);

    // Maintain sliding window of matches
    if (matches.length > this.MAX_MATCH_HISTORY) {
      matches.splice(0, matches.length - this.MAX_MATCH_HISTORY);
    }
  }

  static getPatternCount(
    patternId: string,
    timeWindowMs: number = 60000,
  ): number {
    const matches = this.recentMatches.get(patternId) || [];
    const cutoff = Date.now() - timeWindowMs;

    return matches.filter((match) => match.timestamp.getTime() > cutoff).length;
  }

  static getAnalyticsSummary(): LogAnalyticsSummary {
    const summary: LogAnalyticsSummary = {
      timestamp: new Date(),
      totalPatterns: this.patterns.size,
      activeAlerts: 0, // Will be updated by AlertManager
      patternStats: new Map(),
      trending: {
        errorRate: this.calculateErrorRate(),
        avgResponseTime: this.calculateAvgResponseTime(),
        topPatterns: this.getTopPatterns(5),
        anomalies: this.detectAnomalies(),
      },
    };

    // Calculate stats for each pattern
    for (const [patternId, pattern] of this.patterns) {
      const matches = this.recentMatches.get(patternId) || [];
      const recent = matches.filter(
        (m) => Date.now() - m.timestamp.getTime() < 3600000,
      ); // Last hour

      summary.patternStats.set(patternId, {
        name: pattern.name,
        totalMatches: matches.length,
        recentMatches: recent.length,
        lastMatch:
          matches.length > 0 ? matches[matches.length - 1].timestamp : null,
        severity: pattern.severity,
      });
    }

    return summary;
  }

  private static calculateErrorRate(): number {
    const allMatches = Array.from(this.recentMatches.values()).flat();
    const recentMatches = allMatches.filter(
      (match) => Date.now() - match.timestamp.getTime() < 3600000,
    );

    if (recentMatches.length === 0) return 0;

    const errorMatches = recentMatches.filter(
      (match) => match.pattern.severity === "critical" || match.pattern.severity === "warning",
    );

    return (errorMatches.length / recentMatches.length) * 100;
  }

  private static calculateAvgResponseTime(): number {
    const allMatches = Array.from(this.recentMatches.values()).flat();
    const recentMatches = allMatches.filter(
      (match) => 
        Date.now() - match.timestamp.getTime() < 3600000 &&
        match.entry.duration !== undefined,
    );

    if (recentMatches.length === 0) return 0;

    const totalDuration = recentMatches.reduce(
      (sum, match) => sum + (match.entry.duration || 0),
      0,
    );

    return totalDuration / recentMatches.length;
  }

  private static getTopPatterns(limit: number): Array<{ patternId: string; count: number }> {
    const patternCounts = new Map<string, number>();

    for (const [patternId, matches] of this.recentMatches) {
      const recentCount = matches.filter(
        (match) => Date.now() - match.timestamp.getTime() < 3600000,
      ).length;
      patternCounts.set(patternId, recentCount);
    }

    return Array.from(patternCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit)
      .map(([patternId, count]) => ({ patternId, count }));
  }

  private static detectAnomalies(): Array<{ type: string; description: string }> {
    const anomalies: Array<{ type: string; description: string }> = [];

    // Check for unusual error rate spikes
    const errorRate = this.calculateErrorRate();
    if (errorRate > 50) {
      anomalies.push({
        type: "error-rate-spike",
        description: `Error rate unusually high at ${errorRate.toFixed(1)}%`,
      });
    }

    // Check for performance degradation
    const avgResponseTime = this.calculateAvgResponseTime();
    if (avgResponseTime > 5000) {
      anomalies.push({
        type: "performance-degradation",
        description: `Average response time elevated at ${avgResponseTime.toFixed(0)}ms`,
      });
    }

    return anomalies;
  }

  static getRegisteredPatterns(): LogPattern[] {
    return Array.from(this.patterns.values());
  }

  static getRecentMatches(patternId?: string): PatternMatch[] {
    if (patternId) {
      return this.recentMatches.get(patternId) || [];
    }

    return Array.from(this.recentMatches.values()).flat();
  }

  static clearHistory(): void {
    this.recentMatches.clear();
    logger.info("Pattern match history cleared", {
      correlationId: "log-analyzer",
    });
  }

  static removePattern(patternId: string): boolean {
    const removed = this.patterns.delete(patternId);
    if (removed) {
      this.recentMatches.delete(patternId);
      logger.info("Pattern removed", {
        patternId,
        correlationId: "log-analyzer",
      });
    }
    return removed;
  }
}