import type { PatternAlert } from "./alert-manager.js";

export interface CorrelationRule {
  id: string;
  name: string;
  sourcePatterns: string[]; // Patterns that trigger correlation
  targetPatterns: string[]; // Patterns to correlate with
  timeWindow: number; // Correlation window in milliseconds
  correlationType: "cascade" | "cluster" | "inhibition";
  action: "suppress" | "merge" | "escalate";
  confidence: number; // Rule confidence (0.0-1.0)
}

export interface AlertCorrelation {
  id: string;
  rootAlertId: string;
  correlatedAlertIds: string[];
  correlationType: string;
  confidence: number;
  suppressedCount: number;
  createdAt: number;
  expiresAt: number;
}

export interface CorrelationEngineConfig {
  correlationWindow: number; // Default correlation time window
  maxActiveCorrelations: number; // Maximum concurrent correlations
  minConfidenceThreshold: number; // Minimum confidence to trigger correlation
  enableLearning: boolean; // Enable pattern learning from correlations
}

export class BasicCorrelationEngine {
  private correlationRules: Map<string, CorrelationRule>;
  private activeCorrelations: Map<string, AlertCorrelation>;
  private correlationWindow: number;
  private config: CorrelationEngineConfig;
  private patternFrequency: Map<string, number[]>; // Track pattern frequencies for learning

  constructor(config: Partial<CorrelationEngineConfig> = {}) {
    this.config = {
      correlationWindow: config.correlationWindow || 300000, // 5 minutes default
      maxActiveCorrelations: config.maxActiveCorrelations || 100,
      minConfidenceThreshold: config.minConfidenceThreshold || 0.7,
      enableLearning: config.enableLearning || true,
    };

    this.correlationWindow = this.config.correlationWindow;
    this.correlationRules = new Map();
    this.activeCorrelations = new Map();
    this.patternFrequency = new Map();

    // Initialize with common correlation rules
    this.initializeBasicRules();

    // Start background cleanup for expired correlations
    this.startBackgroundProcesses();
  }

  private initializeBasicRules(): void {
    // Database connection failures often cascade
    this.addRule({
      id: "database-cascade",
      name: "Database Connection Cascade",
      sourcePatterns: ["DATABASE_CONNECTION_ERROR", "DATABASE_POOL_EXHAUSTED"],
      targetPatterns: [
        "QUERY_TIMEOUT",
        "TRANSACTION_FAILED",
        "CONNECTION_TIMEOUT",
      ],
      timeWindow: 120000, // 2 minutes
      correlationType: "cascade",
      action: "suppress",
      confidence: 0.9,
    });

    // API errors often cluster
    this.addRule({
      id: "api-cluster",
      name: "API Error Clustering",
      sourcePatterns: [
        "MAKE_API_ERROR",
        "MAKE_API_RATE_LIMIT",
        "MAKE_API_TIMEOUT",
      ],
      targetPatterns: [
        "MAKE_API_ERROR",
        "MAKE_API_RATE_LIMIT",
        "MAKE_API_TIMEOUT",
      ],
      timeWindow: 180000, // 3 minutes
      correlationType: "cluster",
      action: "merge",
      confidence: 0.8,
    });

    // Memory issues inhibit performance alerts
    this.addRule({
      id: "memory-performance",
      name: "Memory Performance Inhibition",
      sourcePatterns: [
        "MEMORY_USAGE_HIGH",
        "MEMORY_LEAK_DETECTED",
        "OUT_OF_MEMORY",
      ],
      targetPatterns: [
        "SLOW_PERFORMANCE",
        "REQUEST_TIMEOUT",
        "RESPONSE_TIME_HIGH",
      ],
      timeWindow: 300000, // 5 minutes
      correlationType: "inhibition",
      action: "suppress",
      confidence: 0.85,
    });

    // Security alerts clustering
    this.addRule({
      id: "security-cluster",
      name: "Security Alert Clustering",
      sourcePatterns: [
        "SECURITY_VIOLATION",
        "UNAUTHORIZED_ACCESS",
        "AUTHENTICATION_FAILED",
      ],
      targetPatterns: [
        "SECURITY_VIOLATION",
        "UNAUTHORIZED_ACCESS",
        "AUTHENTICATION_FAILED",
      ],
      timeWindow: 600000, // 10 minutes
      correlationType: "cluster",
      action: "merge",
      confidence: 0.75,
    });

    // File system issues cascade
    this.addRule({
      id: "filesystem-cascade",
      name: "File System Issue Cascade",
      sourcePatterns: ["DISK_SPACE_LOW", "FILE_WRITE_ERROR", "DISK_IO_HIGH"],
      targetPatterns: [
        "LOG_WRITE_FAILED",
        "CONFIG_SAVE_ERROR",
        "TEMP_FILE_ERROR",
      ],
      timeWindow: 240000, // 4 minutes
      correlationType: "cascade",
      action: "suppress",
      confidence: 0.8,
    });

    console.warn(
      `🔗 Initialized ${this.correlationRules.size} correlation rules`,
    );
  }

  addRule(rule: CorrelationRule): void {
    this.correlationRules.set(rule.id, rule);
    console.warn(
      `📋 Added correlation rule: ${rule.name} (${rule.correlationType})`,
    );
  }

  removeRule(ruleId: string): boolean {
    const removed = this.correlationRules.delete(ruleId);
    if (removed) {
      console.warn(`🗑️ Removed correlation rule: ${ruleId}`);
    }
    return removed;
  }

  correlateAlert(newAlert: PatternAlert): AlertCorrelation | null {
    // Clean up expired correlations first
    this.cleanupExpiredCorrelations();

    // Track pattern frequency for learning
    this.trackPatternFrequency(newAlert.patternId);

    // Find applicable rules for this alert's pattern
    const applicableRules = this.findApplicableRules(newAlert.patternId);

    for (const rule of applicableRules) {
      const correlation = this.evaluateRule(rule, newAlert);
      if (correlation) {
        this.activeCorrelations.set(correlation.id, correlation);

        console.warn(
          `🔗 Alert correlation created: ${correlation.id} (${correlation.correlationType}) - ${correlation.correlatedAlertIds.length} alerts`,
        );

        // Learn from successful correlations
        if (this.config.enableLearning) {
          this.learnFromCorrelation(rule, correlation);
        }

        return correlation;
      }
    }

    return null;
  }

  private findApplicableRules(patternId: string): CorrelationRule[] {
    const applicable: CorrelationRule[] = [];

    for (const rule of this.correlationRules.values()) {
      if (
        rule.sourcePatterns.includes(patternId) ||
        rule.targetPatterns.includes(patternId)
      ) {
        applicable.push(rule);
      }
    }

    return applicable.sort((a, b) => b.confidence - a.confidence); // Higher confidence first
  }

  private evaluateRule(
    rule: CorrelationRule,
    newAlert: PatternAlert,
  ): AlertCorrelation | null {
    const relevantAlerts = this.findRelevantAlerts(rule, newAlert);

    if (relevantAlerts.length === 0) {
      return null;
    }

    // Calculate correlation confidence
    const confidence = this.calculateCorrelationConfidence(
      rule,
      newAlert,
      relevantAlerts,
    );

    if (
      confidence >= rule.confidence &&
      confidence >= this.config.minConfidenceThreshold
    ) {
      const rootAlert = this.selectRootAlert(relevantAlerts, newAlert, rule);

      return {
        id: `corr_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        rootAlertId: rootAlert.id,
        correlatedAlertIds: relevantAlerts.map((a) => a.id).concat(newAlert.id),
        correlationType: rule.correlationType,
        confidence: confidence,
        suppressedCount: rule.action === "suppress" ? relevantAlerts.length : 0,
        createdAt: Date.now(),
        expiresAt: Date.now() + rule.timeWindow,
      };
    }

    return null;
  }

  private findRelevantAlerts(
    rule: CorrelationRule,
    newAlert: PatternAlert,
  ): PatternAlert[] {
    const cutoffTime = Date.now() - rule.timeWindow;

    // Get all alerts from a hypothetical alert source
    // In the real implementation, this would come from the AlertManager
    const allAlerts = this.getAllRecentAlerts(cutoffTime);

    return allAlerts.filter(
      (alert) =>
        alert.lastOccurrence.getTime() > cutoffTime &&
        alert.id !== newAlert.id &&
        (rule.targetPatterns.includes(alert.patternId) ||
          rule.sourcePatterns.includes(alert.patternId)) &&
        !alert.resolved,
    );
  }

  private getAllRecentAlerts(_cutoffTime: number): PatternAlert[] {
    // This is a placeholder - in real implementation, this would integrate
    // with the AlertManager or EnhancedAlertStorage
    return [];
  }

  private calculateCorrelationConfidence(
    rule: CorrelationRule,
    newAlert: PatternAlert,
    relevantAlerts: PatternAlert[],
  ): number {
    let confidence = rule.confidence;

    // Adjust confidence based on pattern frequency
    const patternFreq = this.getPatternFrequency(newAlert.patternId);

    // Higher frequency patterns get slight confidence boost for clustering
    if (rule.correlationType === "cluster" && patternFreq > 10) {
      confidence += 0.05;
    }

    // Time proximity boost - closer alerts get higher confidence
    const avgTimeProximity =
      relevantAlerts.reduce((sum, alert) => {
        const timeDiff = Math.abs(
          newAlert.lastOccurrence.getTime() - alert.lastOccurrence.getTime(),
        );
        return sum + (rule.timeWindow - timeDiff) / rule.timeWindow;
      }, 0) / relevantAlerts.length;

    confidence += avgTimeProximity * 0.1;

    // Pattern diversity adjustment
    const uniquePatterns = new Set(relevantAlerts.map((a) => a.patternId));
    if (uniquePatterns.size > 1 && rule.correlationType === "cascade") {
      confidence += 0.05; // Diverse patterns in cascade increase confidence
    }

    // Cap confidence at 0.95 to maintain some uncertainty
    return Math.min(0.95, Math.max(0.0, confidence));
  }

  private selectRootAlert(
    relevantAlerts: PatternAlert[],
    newAlert: PatternAlert,
    rule: CorrelationRule,
  ): PatternAlert {
    const allAlerts = relevantAlerts.concat(newAlert);

    // For cascade correlations, select the earliest alert as root
    if (rule.correlationType === "cascade") {
      return allAlerts.reduce((earliest, alert) =>
        alert.firstOccurrence < earliest.firstOccurrence ? alert : earliest,
      );
    }

    // For cluster correlations, select the most frequent pattern
    if (rule.correlationType === "cluster") {
      return allAlerts.reduce((highest, alert) =>
        alert.count > highest.count ? alert : highest,
      );
    }

    // For inhibition, select the source pattern as root
    const sourceAlert = allAlerts.find((alert) =>
      rule.sourcePatterns.includes(alert.patternId),
    );
    return sourceAlert || allAlerts[0];
  }

  private trackPatternFrequency(patternId: string): void {
    const now = Date.now();
    const hourWindow = 60 * 60 * 1000; // 1 hour

    if (!this.patternFrequency.has(patternId)) {
      this.patternFrequency.set(patternId, []);
    }

    const frequencies = this.patternFrequency.get(patternId)!;
    frequencies.push(now);

    // Keep only entries within the hour window
    const recentFrequencies = frequencies.filter(
      (time) => now - time < hourWindow,
    );
    this.patternFrequency.set(patternId, recentFrequencies);
  }

  private getPatternFrequency(patternId: string): number {
    return this.patternFrequency.get(patternId)?.length || 0;
  }

  private learnFromCorrelation(
    rule: CorrelationRule,
    correlation: AlertCorrelation,
  ): void {
    // Simple learning mechanism - adjust rule confidence based on success
    if (correlation.confidence > rule.confidence) {
      const adjustment = Math.min(
        0.02,
        (correlation.confidence - rule.confidence) * 0.1,
      );
      rule.confidence = Math.min(0.95, rule.confidence + adjustment);

      console.warn(
        `🧠 Rule learning: ${rule.id} confidence increased to ${rule.confidence.toFixed(3)}`,
      );
    }
  }

  private cleanupExpiredCorrelations(): void {
    const now = Date.now();
    const expiredIds: string[] = [];

    for (const [id, correlation] of this.activeCorrelations) {
      if (correlation.expiresAt <= now) {
        expiredIds.push(id);
      }
    }

    for (const id of expiredIds) {
      this.activeCorrelations.delete(id);
    }

    if (expiredIds.length > 0) {
      console.warn(`🧹 Cleaned up ${expiredIds.length} expired correlations`);
    }
  }

  private startBackgroundProcesses(): void {
    // Cleanup expired correlations every 5 minutes
    setInterval(
      () => {
        this.cleanupExpiredCorrelations();
      },
      5 * 60 * 1000,
    );

    // Pattern frequency cleanup every hour
    setInterval(
      () => {
        this.cleanupPatternFrequencies();
      },
      60 * 60 * 1000,
    );
  }

  private cleanupPatternFrequencies(): void {
    const now = Date.now();
    const hourWindow = 60 * 60 * 1000;

    for (const [patternId, frequencies] of this.patternFrequency) {
      const recentFrequencies = frequencies.filter(
        (time) => now - time < hourWindow,
      );

      if (recentFrequencies.length === 0) {
        this.patternFrequency.delete(patternId);
      } else {
        this.patternFrequency.set(patternId, recentFrequencies);
      }
    }
  }

  // Public API methods

  getActiveCorrelations(): AlertCorrelation[] {
    this.cleanupExpiredCorrelations();
    return Array.from(this.activeCorrelations.values()).sort(
      (a, b) => b.createdAt - a.createdAt,
    );
  }

  getCorrelationRules(): CorrelationRule[] {
    return Array.from(this.correlationRules.values());
  }

  getCorrelationStats(): {
    totalRules: number;
    activeCorrelations: number;
    patternFrequencies: number;
    rulesByType: Record<string, number>;
    avgConfidence: number;
  } {
    const rules = Array.from(this.correlationRules.values());
    const rulesByType = rules.reduce(
      (acc, rule) => {
        acc[rule.correlationType] = (acc[rule.correlationType] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>,
    );

    const avgConfidence =
      rules.length > 0
        ? rules.reduce((sum, rule) => sum + rule.confidence, 0) / rules.length
        : 0;

    return {
      totalRules: rules.length,
      activeCorrelations: this.activeCorrelations.size,
      patternFrequencies: this.patternFrequency.size,
      rulesByType,
      avgConfidence: Math.round(avgConfidence * 1000) / 1000,
    };
  }

  getCorrelationById(correlationId: string): AlertCorrelation | null {
    return this.activeCorrelations.get(correlationId) || null;
  }

  forceExpireCorrelation(correlationId: string): boolean {
    const correlation = this.activeCorrelations.get(correlationId);
    if (correlation) {
      correlation.expiresAt = Date.now();
      return true;
    }
    return false;
  }

  // Integration method to set alert source
  setAlertSource(
    getAllRecentAlertsCallback: (cutoffTime: number) => PatternAlert[],
  ): void {
    this.getAllRecentAlerts = getAllRecentAlertsCallback;
  }

  shutdown(): void {
    console.warn("🔄 Shutting down correlation engine...");
    this.activeCorrelations.clear();
    this.patternFrequency.clear();
    console.warn("✅ Correlation engine shutdown complete");
  }
}
