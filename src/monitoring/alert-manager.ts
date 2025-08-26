// Logger will be injected via import to avoid circular dependency
import type { PatternMatch } from "./log-pattern-analyzer.js";

export interface PatternAlert {
  id: string;
  patternId: string;
  severity: "info" | "warning" | "critical";
  message: string;
  action: string;
  count: number;
  firstOccurrence: Date;
  lastOccurrence: Date;
  resolved: boolean;
  suppressedUntil?: Date;
  escalationLevel: number;
}

export interface AlertNotificationPayload {
  alert_id: string;
  pattern: string;
  severity: string;
  message: string;
  action: string;
  count: number;
  timestamp: string;
  escalation_level: number;
}

export class AlertManager {
  private static alerts: Map<string, PatternAlert> = new Map();
  private static readonly MAX_ALERT_HISTORY = 500;

  static triggerAlert(match: PatternMatch): PatternAlert | null {
    const alertId = `${match.pattern.id}-${Date.now()}`;
    const existingAlert = this.findActiveAlert(match.pattern.id);

    // Check if alert is currently suppressed
    if (
      existingAlert &&
      existingAlert.suppressedUntil &&
      new Date() < existingAlert.suppressedUntil
    ) {
      // Update count even when suppressed for accurate reporting
      existingAlert.count++;
      existingAlert.lastOccurrence = new Date();
      return null;
    }

    const alert: PatternAlert = existingAlert || {
      id: alertId,
      patternId: match.pattern.id,
      severity: match.pattern.severity,
      message: `Pattern detected: ${match.pattern.name}`,
      action: match.pattern.action,
      count: 0,
      firstOccurrence: new Date(),
      lastOccurrence: new Date(),
      resolved: false,
      escalationLevel: 1,
    };

    alert.count++;
    alert.lastOccurrence = new Date();

    // Set suppression period if configured
    if (match.pattern.suppressionMs) {
      alert.suppressedUntil = new Date(
        Date.now() + match.pattern.suppressionMs,
      );
    }

    // Handle escalation based on frequency
    if (alert.count > 10) {
      alert.escalationLevel = Math.min(3, Math.floor(alert.count / 10));
    }

    this.alerts.set(alert.id, alert);

    // Maintain alert history limit
    this.enforceAlertHistoryLimit();

    // Log the alert using appropriate level - console output removed to prevent JSON-RPC protocol contamination
    // if (alert.severity === "critical") {
    //   console.error(
    //     `🚨 Pattern alert triggered: ${alert.message} (${alert.severity}) - Count: ${alert.count}`,
    //   );
    // } else {
    //   console.warn(
    //     `🚨 Pattern alert triggered: ${alert.message} (${alert.severity}) - Count: ${alert.count}`,
    //   );
    // }

    // Trigger notification if configured
    this.sendNotification(alert);

    return alert;
  }

  private static findActiveAlert(patternId: string): PatternAlert | null {
    for (const alert of this.alerts.values()) {
      if (alert.patternId === patternId && !alert.resolved) {
        return alert;
      }
    }
    return null;
  }

  private static enforceAlertHistoryLimit(): void {
    const alertArray = Array.from(this.alerts.values());
    if (alertArray.length > this.MAX_ALERT_HISTORY) {
      // Remove oldest resolved alerts first
      const resolvedAlerts = alertArray
        .filter((alert) => alert.resolved)
        .sort(
          (a, b) => a.lastOccurrence.getTime() - b.lastOccurrence.getTime(),
        );

      if (resolvedAlerts.length > 0) {
        const toRemove = Math.min(
          resolvedAlerts.length,
          alertArray.length - this.MAX_ALERT_HISTORY,
        );

        for (let i = 0; i < toRemove; i++) {
          this.alerts.delete(resolvedAlerts[i].id);
        }
      }
    }
  }

  private static sendNotification(alert: PatternAlert): void {
    // Integration point for external notification systems
    // Could integrate with webhooks, email, Slack, etc.

    if (process.env.ALERT_WEBHOOK_URL) {
      // Example webhook integration
      const _payload: AlertNotificationPayload = {
        alert_id: alert.id,
        pattern: alert.patternId,
        severity: alert.severity,
        message: alert.message,
        action: alert.action,
        count: alert.count,
        timestamp: alert.lastOccurrence.toISOString(),
        escalation_level: alert.escalationLevel,
      };

      // Alert notification prepared - output suppressed for MCP compliance

      // Webhook payload logging suppressed for MCP compliance
    }

    // Critical alert notification suppressed for MCP compliance
  }

  static getActiveAlerts(): PatternAlert[] {
    return Array.from(this.alerts.values())
      .filter((alert) => !alert.resolved)
      .sort((a, b) => {
        // Sort by severity first, then by escalation level, then by last occurrence
        const severityOrder = { critical: 3, warning: 2, info: 1 };
        const severityDiff =
          severityOrder[b.severity] - severityOrder[a.severity];
        if (severityDiff !== 0) {
          return severityDiff;
        }

        const escalationDiff = b.escalationLevel - a.escalationLevel;
        if (escalationDiff !== 0) {
          return escalationDiff;
        }

        return b.lastOccurrence.getTime() - a.lastOccurrence.getTime();
      });
  }

  static getAllAlerts(includeResolved: boolean = false): PatternAlert[] {
    const alerts = Array.from(this.alerts.values());

    if (!includeResolved) {
      return alerts.filter((alert) => !alert.resolved);
    }

    return alerts.sort(
      (a, b) => b.lastOccurrence.getTime() - a.lastOccurrence.getTime(),
    );
  }

  static resolveAlert(alertId: string, _reason: string): boolean {
    const alert = this.alerts.get(alertId);
    if (alert && !alert.resolved) {
      alert.resolved = true;

      // Alert resolved - output suppressed for MCP compliance

      return true;
    }
    return false;
  }

  static resolveAlertsByPattern(patternId: string, _reason: string): number {
    let resolvedCount = 0;

    for (const alert of this.alerts.values()) {
      if (alert.patternId === patternId && !alert.resolved) {
        alert.resolved = true;
        resolvedCount++;
      }
    }

    // Pattern alerts resolved - output suppressed for MCP compliance

    return resolvedCount;
  }

  static getAlertById(alertId: string): PatternAlert | null {
    return this.alerts.get(alertId) || null;
  }

  static getAlertsByPattern(patternId: string): PatternAlert[] {
    return Array.from(this.alerts.values())
      .filter((alert) => alert.patternId === patternId)
      .sort((a, b) => b.lastOccurrence.getTime() - a.lastOccurrence.getTime());
  }

  static getAlertStats(): {
    total: number;
    active: number;
    resolved: number;
    critical: number;
    warning: number;
    info: number;
    suppressed: number;
  } {
    const alerts = Array.from(this.alerts.values());
    const now = new Date();

    return {
      total: alerts.length,
      active: alerts.filter((a) => !a.resolved).length,
      resolved: alerts.filter((a) => a.resolved).length,
      critical: alerts.filter((a) => a.severity === "critical").length,
      warning: alerts.filter((a) => a.severity === "warning").length,
      info: alerts.filter((a) => a.severity === "info").length,
      suppressed: alerts.filter(
        (a) => a.suppressedUntil && now < a.suppressedUntil,
      ).length,
    };
  }

  static clearResolvedAlerts(): number {
    const beforeCount = this.alerts.size;
    const toDelete: string[] = [];

    for (const [alertId, alert] of this.alerts) {
      if (alert.resolved) {
        toDelete.push(alertId);
      }
    }

    toDelete.forEach((alertId) => this.alerts.delete(alertId));
    const clearedCount = beforeCount - this.alerts.size;

    // Resolved alerts cleared - output suppressed for MCP compliance

    return clearedCount;
  }

  static clearAllAlerts(): number {
    const clearedCount = this.alerts.size;
    this.alerts.clear();

    // All alerts cleared - output suppressed for MCP compliance

    return clearedCount;
  }

  // Update active alert count in LogPatternAnalyzer summary
  static getActiveAlertCount(): number {
    return this.getActiveAlerts().length;
  }
}
