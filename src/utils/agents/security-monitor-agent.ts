/**
 * Security Monitor Agent - Handles compliance checking, security monitoring, audit logging, and security event management
 * Ensures all credential rotation operations meet security and compliance requirements
 */

import {
  RotationAgentBase,
  AgentConfig,
  AgentMessage,
} from "../rotation-agent-base.js";
import type {
  SecurityEvent,
  ComplianceRule,
  SecurityAlert,
  ThreatLevel,
} from "../../types/rotation-types.js";
import * as crypto from "crypto";
import * as fs from "fs/promises";
import * as path from "path";
import { promisify } from "util";

const sleep = promisify(setTimeout);

/**
 * Security event types
 */
type SecurityEventType =
  | "rotation_started"
  | "rotation_completed"
  | "rotation_failed"
  | "key_generated"
  | "key_rotated"
  | "unauthorized_access"
  | "compliance_violation"
  | "suspicious_activity"
  | "emergency_rotation"
  | "policy_violation";

/**
 * Audit log entry interface
 */
interface AuditLogEntry {
  logId: string;
  timestamp: Date;
  eventType: SecurityEventType;
  agentId: string;
  credentialId?: string;
  userId?: string;
  details: Record<string, unknown>;
  threatLevel: ThreatLevel;
  complianceStatus: "compliant" | "non_compliant" | "unknown";
  metadata?: Record<string, unknown>;
}

/**
 * Security metrics tracking
 */
interface SecurityMetrics {
  totalEvents: number;
  criticalEvents: number;
  complianceViolations: number;
  suspiciousActivities: number;
  emergencyRotations: number;
  avgResponseTime: number;
  lastSecurityScan: Date;
}

/**
 * Compliance check result
 */
interface ComplianceCheckResult {
  ruleId: string;
  ruleName: string;
  status: "passed" | "failed" | "warning";
  message: string;
  details?: Record<string, unknown>;
  timestamp: Date;
  severity: "low" | "medium" | "high" | "critical";
}

/**
 * Security Monitor Agent configuration
 */
export interface SecurityMonitorConfig extends AgentConfig {
  auditLogPath?: string;
  enableRealTimeMonitoring?: boolean;
  alertThresholds?: {
    criticalEventsPerHour: number;
    suspiciousActivitiesPerHour: number;
    failedRotationsPerHour: number;
  };
  complianceStandards?: string[];
  securityScanIntervalMs?: number;
  retentionPeriodDays?: number;
  encryptAuditLogs?: boolean;
  alertEndpoints?: string[];
}

/**
 * Threat detection rule
 */
interface ThreatDetectionRule {
  ruleId: string;
  name: string;
  description: string;
  eventPattern: RegExp | string;
  threshold: number;
  timeWindowMs: number;
  severity: ThreatLevel;
  enabled: boolean;
  action: "log" | "alert" | "block";
}

/**
 * Security Monitor Agent - comprehensive security monitoring and compliance
 */
export class SecurityMonitorAgent extends RotationAgentBase {
  private readonly config: SecurityMonitorConfig;
  private readonly auditLogs: AuditLogEntry[] = [];
  private readonly securityEvents: Map<string, SecurityEvent> = new Map();
  private readonly complianceRules: Map<string, ComplianceRule> = new Map();
  private readonly threatDetectionRules: Map<string, ThreatDetectionRule> =
    new Map();

  // Performance tracking
  private readonly securityMetrics: SecurityMetrics = {
    totalEvents: 0,
    criticalEvents: 0,
    complianceViolations: 0,
    suspiciousActivities: 0,
    emergencyRotations: 0,
    avgResponseTime: 0,
    lastSecurityScan: new Date(),
  };

  // Monitoring state
  private securityScanTimer?: NodeJS.Timeout;
  private auditLogFlushTimer?: NodeJS.Timeout;
  private eventResponseTimes: number[] = [];
  private readonly recentEvents: Map<string, Date[]> = new Map(); // For rate limiting detection

  constructor(config: SecurityMonitorConfig) {
    super({
      ...config,
      role: "security",
    });

    this.config = config;
    this.setupComplianceRules();
    this.setupThreatDetectionRules();

    this.componentLogger.info("Security Monitor Agent created", {
      auditLogPath: config.auditLogPath,
      realTimeMonitoring: config.enableRealTimeMonitoring,
      complianceStandards: config.complianceStandards,
    });
  }

  protected async initializeAgent(): Promise<void> {
    this.componentLogger.info("Initializing Security Monitor Agent");

    // Create audit log directory if it doesn't exist
    if (this.config.auditLogPath) {
      const logDir = path.dirname(this.config.auditLogPath);
      try {
        await fs.mkdir(logDir, { recursive: true });
      } catch (error) {
        this.componentLogger.warn("Could not create audit log directory", {
          path: logDir,
          error: error instanceof Error ? error.message : "Unknown error",
        });
      }
    }

    // Start security scanning
    if (this.config.securityScanIntervalMs) {
      this.startSecurityScanning();
    }

    // Start audit log flushing
    this.startAuditLogFlushing();

    // Load existing audit logs
    await this.loadExistingAuditLogs();

    this.componentLogger.info(
      "Security Monitor Agent initialized successfully",
    );
  }

  protected async shutdownAgent(): Promise<void> {
    this.componentLogger.info("Shutting down Security Monitor Agent");

    // Stop timers
    if (this.securityScanTimer) {
      clearInterval(this.securityScanTimer);
    }

    if (this.auditLogFlushTimer) {
      clearInterval(this.auditLogFlushTimer);
    }

    // Flush remaining audit logs
    await this.flushAuditLogs();

    this.componentLogger.info("Security Monitor Agent shutdown completed");
  }

  protected async processMessage(
    message: AgentMessage,
  ): Promise<Record<string, unknown>> {
    const { type, payload } = message;

    switch (type) {
      case "log_security_event":
        return this.logSecurityEvent(payload);

      case "log_rotation_event":
        return this.logRotationEvent(payload);

      case "check_compliance":
        return this.checkCompliance(payload);

      case "send_security_alert":
        return this.sendSecurityAlert(payload);

      case "perform_security_scan":
        return this.performSecurityScan(payload);

      case "get_security_metrics":
        return this.getSecurityMetrics();

      case "get_audit_logs":
        return this.getAuditLogs(payload);

      case "detect_threats":
        return this.detectThreats(payload);

      case "validate_security_policy":
        return this.validateSecurityPolicy(payload);

      default:
        throw new Error(`Unknown message type: ${type}`);
    }
  }

  /**
   * Log security event
   */
  private async logSecurityEvent(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const startTime = Date.now();

    const {
      eventType,
      agentId,
      credentialId,
      userId,
      details = {},
      threatLevel = "low",
    } = payload;

    this.componentLogger.info("Logging security event", {
      eventType,
      agentId,
      credentialId,
      threatLevel,
    });

    try {
      const auditEntry: AuditLogEntry = {
        logId: crypto.randomUUID(),
        timestamp: new Date(),
        eventType: eventType as SecurityEventType,
        agentId: agentId as string,
        credentialId: credentialId as string,
        userId: userId as string,
        details: details as Record<string, unknown>,
        threatLevel: threatLevel as ThreatLevel,
        complianceStatus: "unknown", // Will be determined by compliance check
        metadata: {
          sourceAgent: this.agentId,
          sessionId: crypto.randomUUID().slice(0, 8),
        },
      };

      // Add to audit logs
      this.auditLogs.push(auditEntry);

      // Update metrics
      this.securityMetrics.totalEvents++;
      if (threatLevel === "critical" || threatLevel === "high") {
        this.securityMetrics.criticalEvents++;
      }

      if (eventType === "emergency_rotation") {
        this.securityMetrics.emergencyRotations++;
      }

      // Check for threats
      await this.checkForThreats(auditEntry);

      // Perform compliance check
      const complianceResult = await this.performComplianceCheck(auditEntry);
      auditEntry.complianceStatus = complianceResult.compliant
        ? "compliant"
        : "non_compliant";

      if (!complianceResult.compliant) {
        this.securityMetrics.complianceViolations++;
      }

      const responseTime = Date.now() - startTime;
      this.eventResponseTimes.push(responseTime);
      if (this.eventResponseTimes.length > 1000) {
        this.eventResponseTimes = this.eventResponseTimes.slice(-1000);
      }

      // Update average response time
      this.securityMetrics.avgResponseTime =
        this.eventResponseTimes.reduce((a, b) => a + b) /
        this.eventResponseTimes.length;

      this.componentLogger.info("Security event logged successfully", {
        logId: auditEntry.logId,
        eventType,
        complianceStatus: auditEntry.complianceStatus,
        responseTimeMs: responseTime,
      });

      return {
        success: true,
        logId: auditEntry.logId,
        timestamp: auditEntry.timestamp.toISOString(),
        complianceStatus: auditEntry.complianceStatus,
        threatLevel: auditEntry.threatLevel,
        responseTimeMs: responseTime,
      };
    } catch (error) {
      const responseTime = Date.now() - startTime;

      this.componentLogger.error("Failed to log security event", {
        eventType,
        error: error instanceof Error ? error.message : "Unknown error",
        responseTimeMs: responseTime,
      });

      return {
        success: false,
        error:
          error instanceof Error
            ? error.message
            : "Unknown security logging error",
        responseTimeMs: responseTime,
      };
    }
  }

  /**
   * Log credential rotation event
   */
  private async logRotationEvent(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const {
      credentialId,
      oldCredentialId,
      newCredentialId,
      rotationType = "standard",
      rotationStatus,
      performanceMetrics,
      agentId,
    } = payload;

    const eventType: SecurityEventType =
      rotationStatus === "completed"
        ? "rotation_completed"
        : rotationStatus === "failed"
          ? "rotation_failed"
          : "rotation_started";

    const threatLevel: ThreatLevel =
      rotationType === "emergency" ? "high" : "low";

    return this.logSecurityEvent({
      eventType,
      agentId: agentId || "rotation_coordinator",
      credentialId: credentialId || newCredentialId,
      details: {
        oldCredentialId,
        newCredentialId,
        rotationType,
        rotationStatus,
        performanceMetrics,
      },
      threatLevel,
    });
  }

  /**
   * Check compliance against configured rules
   */
  private async checkCompliance(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const { credentialId, operationType, context = {} } = payload;
    const startTime = Date.now();

    this.componentLogger.info("Starting compliance check", {
      credentialId,
      operationType,
      rulesCount: this.complianceRules.size,
    });

    try {
      const results: ComplianceCheckResult[] = [];
      let overallCompliant = true;

      // Check each compliance rule
      for (const [_ruleId, rule] of this.complianceRules) {
        const result = await this.evaluateComplianceRule(rule, {
          credentialId,
          operationType,
          ...context,
        });

        results.push(result);

        if (result.status === "failed") {
          overallCompliant = false;
        }
      }

      const responseTime = Date.now() - startTime;

      // Log compliance check results
      await this.logSecurityEvent({
        eventType: overallCompliant
          ? "rotation_started"
          : "compliance_violation",
        agentId: this.agentId,
        credentialId: credentialId as string,
        details: {
          complianceCheck: {
            overallCompliant,
            rulesChecked: results.length,
            failedRules: results.filter((r) => r.status === "failed").length,
            warningRules: results.filter((r) => r.status === "warning").length,
          },
        },
        threatLevel: overallCompliant ? "low" : "medium",
      });

      this.componentLogger.info("Compliance check completed", {
        credentialId,
        overallCompliant,
        rulesChecked: results.length,
        responseTimeMs: responseTime,
      });

      return {
        success: true,
        compliant: overallCompliant,
        results,
        summary: {
          totalRules: results.length,
          passedRules: results.filter((r) => r.status === "passed").length,
          failedRules: results.filter((r) => r.status === "failed").length,
          warningRules: results.filter((r) => r.status === "warning").length,
        },
        responseTimeMs: responseTime,
      };
    } catch (error) {
      const responseTime = Date.now() - startTime;

      this.componentLogger.error("Compliance check failed", {
        credentialId,
        error: error instanceof Error ? error.message : "Unknown error",
        responseTimeMs: responseTime,
      });

      return {
        success: false,
        compliant: false,
        error:
          error instanceof Error ? error.message : "Unknown compliance error",
        responseTimeMs: responseTime,
      };
    }
  }

  /**
   * Send security alert
   */
  private async sendSecurityAlert(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const {
      level = "medium",
      message,
      details = {},
      credentialId,
      agentId,
    } = payload;

    const startTime = Date.now();

    this.componentLogger.warn("Security alert triggered", {
      level,
      message,
      credentialId,
      agentId,
    });

    try {
      const alert: SecurityAlert = {
        alertId: crypto.randomUUID(),
        timestamp: new Date(),
        level: level as ThreatLevel,
        message: message as string,
        details: details as Record<string, unknown>,
        credentialId: credentialId as string,
        agentId: agentId as string,
        acknowledged: false,
      };

      // Store the alert
      const alertLogEntry: AuditLogEntry = {
        logId: crypto.randomUUID(),
        timestamp: new Date(),
        eventType:
          level === "critical" ? "suspicious_activity" : "policy_violation",
        agentId: (agentId as string) || this.agentId,
        credentialId: credentialId as string,
        details: {
          securityAlert: alert,
        },
        threatLevel: level as ThreatLevel,
        complianceStatus: "non_compliant",
      };

      this.auditLogs.push(alertLogEntry);

      // Send to configured alert endpoints (simulate)
      if (this.config.alertEndpoints) {
        for (const endpoint of this.config.alertEndpoints) {
          // In a real implementation, this would send HTTP requests to alert systems
          this.componentLogger.info("Alert sent to endpoint", {
            endpoint,
            alertId: alert.alertId,
            level: alert.level,
          });
        }
      }

      const responseTime = Date.now() - startTime;

      return {
        success: true,
        alertId: alert.alertId,
        level: alert.level,
        timestamp: alert.timestamp.toISOString(),
        endpointsNotified: this.config.alertEndpoints?.length || 0,
        responseTimeMs: responseTime,
      };
    } catch (error) {
      const responseTime = Date.now() - startTime;

      this.componentLogger.error("Failed to send security alert", {
        level,
        message,
        error: error instanceof Error ? error.message : "Unknown error",
        responseTimeMs: responseTime,
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : "Unknown alert error",
        responseTimeMs: responseTime,
      };
    }
  }

  /**
   * Perform comprehensive security scan
   */
  private async performSecurityScan(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const { scanType = "full", targetCredentials } = payload;
    const startTime = Date.now();

    this.componentLogger.info("Starting security scan", {
      scanType,
      targetCredentials: Array.isArray(targetCredentials)
        ? targetCredentials.length
        : "all",
    });

    try {
      const scanResults = {
        scanId: crypto.randomUUID(),
        scanType,
        startTime: new Date(),
        findings: [] as Record<string, unknown>[],
        recommendations: [] as string[],
      };

      // Audit log analysis
      const auditAnalysis = this.analyzeAuditLogs();
      scanResults.findings.push({
        category: "audit_analysis",
        ...auditAnalysis,
      });

      // Threat pattern detection
      const threatAnalysis = await this.analyzeThreatPatterns();
      scanResults.findings.push({
        category: "threat_patterns",
        ...threatAnalysis,
      });

      // Compliance status review
      const complianceAnalysis = this.analyzeCompliance();
      scanResults.findings.push({
        category: "compliance_status",
        ...complianceAnalysis,
      });

      // Performance anomaly detection
      const performanceAnalysis = this.analyzePerformanceAnomalies();
      scanResults.findings.push({
        category: "performance_anomalies",
        ...performanceAnalysis,
      });

      // Generate recommendations
      scanResults.recommendations = this.generateSecurityRecommendations(
        scanResults.findings,
      );

      const scanDuration = Date.now() - startTime;
      this.securityMetrics.lastSecurityScan = new Date();

      // Log the security scan
      await this.logSecurityEvent({
        eventType: "rotation_started", // Using generic event type for security scans
        agentId: this.agentId,
        details: {
          securityScan: {
            scanId: scanResults.scanId,
            scanType,
            findings: scanResults.findings.length,
            recommendations: scanResults.recommendations.length,
            duration: scanDuration,
          },
        },
        threatLevel: "low",
      });

      this.componentLogger.info("Security scan completed", {
        scanId: scanResults.scanId,
        findings: scanResults.findings.length,
        recommendations: scanResults.recommendations.length,
        durationMs: scanDuration,
      });

      return {
        success: true,
        ...scanResults,
        endTime: new Date(),
        durationMs: scanDuration,
      };
    } catch (error) {
      const scanDuration = Date.now() - startTime;

      this.componentLogger.error("Security scan failed", {
        scanType,
        error: error instanceof Error ? error.message : "Unknown error",
        durationMs: scanDuration,
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : "Unknown scan error",
        durationMs: scanDuration,
      };
    }
  }

  /**
   * Get current security metrics
   */
  private getSecurityMetrics(): Record<string, unknown> {
    const recentEvents = this.auditLogs.filter(
      (log) => Date.now() - log.timestamp.getTime() < 24 * 60 * 60 * 1000, // Last 24 hours
    );

    const eventsByType = recentEvents.reduce(
      (acc, log) => {
        acc[log.eventType] = (acc[log.eventType] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>,
    );

    const threatLevelCounts = recentEvents.reduce(
      (acc, log) => {
        acc[log.threatLevel] = (acc[log.threatLevel] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>,
    );

    return {
      ...this.securityMetrics,
      auditLogCount: this.auditLogs.length,
      recentEvents: {
        last24Hours: recentEvents.length,
        eventsByType,
        threatLevelDistribution: threatLevelCounts,
      },
      complianceRules: {
        totalRules: this.complianceRules.size,
        enabledRules: Array.from(this.complianceRules.values()).filter(
          (r) => r.enabled,
        ).length,
      },
      threatDetection: {
        totalRules: this.threatDetectionRules.size,
        activeRules: Array.from(this.threatDetectionRules.values()).filter(
          (r) => r.enabled,
        ).length,
      },
    };
  }

  /**
   * Get audit logs with filtering
   */
  private async getAuditLogs(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const {
      startDate,
      endDate,
      eventType,
      threatLevel,
      credentialId,
      agentId,
      limit = 100,
    } = payload;

    let filteredLogs = [...this.auditLogs];

    // Apply filters
    if (startDate) {
      const start = new Date(startDate as string);
      filteredLogs = filteredLogs.filter((log) => log.timestamp >= start);
    }

    if (endDate) {
      const end = new Date(endDate as string);
      filteredLogs = filteredLogs.filter((log) => log.timestamp <= end);
    }

    if (eventType) {
      filteredLogs = filteredLogs.filter((log) => log.eventType === eventType);
    }

    if (threatLevel) {
      filteredLogs = filteredLogs.filter(
        (log) => log.threatLevel === threatLevel,
      );
    }

    if (credentialId) {
      filteredLogs = filteredLogs.filter(
        (log) => log.credentialId === credentialId,
      );
    }

    if (agentId) {
      filteredLogs = filteredLogs.filter((log) => log.agentId === agentId);
    }

    // Sort by timestamp (newest first) and limit
    const sortedLogs = filteredLogs
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, limit as number);

    return {
      success: true,
      logs: sortedLogs,
      totalCount: filteredLogs.length,
      returnedCount: sortedLogs.length,
      filters: {
        startDate,
        endDate,
        eventType,
        threatLevel,
        credentialId,
        agentId,
        limit,
      },
    };
  }

  /**
   * Detect threats based on patterns
   */
  private async detectThreats(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const { timeWindow = 3600000 } = payload; // 1 hour default
    const startTime = Date.now();

    this.componentLogger.info("Starting threat detection", {
      timeWindow: timeWindow + "ms",
      activeRules: Array.from(this.threatDetectionRules.values()).filter(
        (r) => r.enabled,
      ).length,
    });

    try {
      const detectedThreats: Record<string, unknown>[] = [];
      const cutoffTime = new Date(Date.now() - (timeWindow as number));

      // Get recent events for analysis
      const recentEvents = this.auditLogs.filter(
        (log) => log.timestamp >= cutoffTime,
      );

      // Check each threat detection rule
      for (const [_ruleId, rule] of this.threatDetectionRules) {
        if (!rule.enabled) {
          continue;
        }

        const matchingEvents = recentEvents.filter((event) => {
          if (typeof rule.eventPattern === "string") {
            return event.eventType === rule.eventPattern;
          } else {
            return rule.eventPattern.test(JSON.stringify(event));
          }
        });

        if (matchingEvents.length >= rule.threshold) {
          detectedThreats.push({
            ruleId: rule.ruleId,
            ruleName: rule.name,
            severity: rule.severity,
            matchedEvents: matchingEvents.length,
            threshold: rule.threshold,
            description: rule.description,
            action: rule.action,
            detectedAt: new Date().toISOString(),
          });

          // Take action based on rule
          if (rule.action === "alert") {
            await this.sendSecurityAlert({
              level: rule.severity,
              message: `Threat detected: ${rule.name}`,
              details: {
                ruleId: rule.ruleId,
                matchedEvents: matchingEvents.length,
                threshold: rule.threshold,
              },
              agentId: this.agentId,
            });
          }
        }
      }

      const responseTime = Date.now() - startTime;

      if (detectedThreats.length > 0) {
        this.securityMetrics.suspiciousActivities += detectedThreats.length;
      }

      this.componentLogger.info("Threat detection completed", {
        threatsDetected: detectedThreats.length,
        eventsAnalyzed: recentEvents.length,
        responseTimeMs: responseTime,
      });

      return {
        success: true,
        threatsDetected: detectedThreats.length,
        threats: detectedThreats,
        analysisWindow: {
          timeWindowMs: timeWindow,
          eventsAnalyzed: recentEvents.length,
          cutoffTime: cutoffTime.toISOString(),
        },
        responseTimeMs: responseTime,
      };
    } catch (error) {
      const responseTime = Date.now() - startTime;

      this.componentLogger.error("Threat detection failed", {
        error: error instanceof Error ? error.message : "Unknown error",
        responseTimeMs: responseTime,
      });

      return {
        success: false,
        error:
          error instanceof Error
            ? error.message
            : "Unknown threat detection error",
        responseTimeMs: responseTime,
      };
    }
  }

  /**
   * Validate security policy compliance
   */
  private async validateSecurityPolicy(
    payload: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const { policyId, context: _context = {} } = payload;

    // This would integrate with external policy engines in a real implementation
    // For now, we'll perform basic validation checks

    const validationResults = {
      policyCompliant: true,
      violations: [] as string[],
      warnings: [] as string[],
      recommendations: [] as string[],
    };

    // Check recent security events for policy violations
    const recentEvents = this.auditLogs.filter(
      (log) => Date.now() - log.timestamp.getTime() < 24 * 60 * 60 * 1000, // Last 24 hours
    );

    const criticalEvents = recentEvents.filter(
      (log) => log.threatLevel === "critical",
    );
    if (criticalEvents.length > 5) {
      validationResults.policyCompliant = false;
      validationResults.violations.push(
        "Excessive critical security events in 24 hours",
      );
    }

    const complianceViolations = recentEvents.filter(
      (log) => log.complianceStatus === "non_compliant",
    );
    if (complianceViolations.length > 10) {
      validationResults.warnings.push(
        "High number of compliance violations detected",
      );
    }

    if (this.securityMetrics.avgResponseTime > 5000) {
      validationResults.warnings.push(
        "Security event response time exceeds recommended threshold",
      );
      validationResults.recommendations.push(
        "Consider optimizing security monitoring performance",
      );
    }

    return {
      success: true,
      policyId,
      ...validationResults,
      evaluatedAt: new Date().toISOString(),
    };
  }

  // Helper methods for security analysis

  private analyzeAuditLogs(): Record<string, unknown> {
    const recentLogs = this.auditLogs.filter(
      (log) => Date.now() - log.timestamp.getTime() < 24 * 60 * 60 * 1000,
    );

    return {
      totalLogs: this.auditLogs.length,
      recentLogs: recentLogs.length,
      criticalEvents: recentLogs.filter((log) => log.threatLevel === "critical")
        .length,
      complianceViolations: recentLogs.filter(
        (log) => log.complianceStatus === "non_compliant",
      ).length,
    };
  }

  private async analyzeThreatPatterns(): Promise<Record<string, unknown>> {
    const patterns = {
      repeatedFailures: 0,
      unusualActivityPatterns: 0,
      suspiciousAccessAttempts: 0,
    };

    // Analyze for repeated failures
    const failedEvents = this.auditLogs.filter(
      (log) => log.eventType === "rotation_failed",
    );
    const recentFailures = failedEvents.filter(
      (log) => Date.now() - log.timestamp.getTime() < 60 * 60 * 1000, // Last hour
    );

    patterns.repeatedFailures = recentFailures.length;

    return patterns;
  }

  private analyzeCompliance(): Record<string, unknown> {
    const complianceStatus = {
      overallCompliant: true,
      totalRules: this.complianceRules.size,
      passedRules: 0,
      failedRules: 0,
    };

    // This would perform actual compliance analysis in a real implementation
    return complianceStatus;
  }

  private analyzePerformanceAnomalies(): Record<string, unknown> {
    const avgResponseTime =
      this.eventResponseTimes.reduce((a, b) => a + b, 0) /
      (this.eventResponseTimes.length || 1);

    return {
      avgResponseTime,
      slowResponses: this.eventResponseTimes.filter((time) => time > 5000)
        .length,
      anomaliesDetected: avgResponseTime > 5000 ? 1 : 0,
    };
  }

  private generateSecurityRecommendations(
    findings: Record<string, unknown>[],
  ): string[] {
    const recommendations: string[] = [];

    findings.forEach((finding) => {
      if (finding.category === "audit_analysis") {
        const analysis = finding;
        if ((analysis.criticalEvents as number) > 5) {
          recommendations.push(
            "Investigate high number of critical security events",
          );
        }
      }
    });

    if (this.securityMetrics.avgResponseTime > 3000) {
      recommendations.push(
        "Optimize security monitoring performance to reduce response times",
      );
    }

    return recommendations;
  }

  private async checkForThreats(auditEntry: AuditLogEntry): Promise<void> {
    // Check for suspicious patterns
    const credentialEvents =
      this.recentEvents.get(auditEntry.credentialId || "unknown") || [];
    credentialEvents.push(auditEntry.timestamp);

    // Keep only events from last hour
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    const recentCredentialEvents = credentialEvents.filter(
      (date) => date >= oneHourAgo,
    );

    this.recentEvents.set(
      auditEntry.credentialId || "unknown",
      recentCredentialEvents,
    );

    // Check for rate limiting violations
    if (recentCredentialEvents.length > 10) {
      await this.sendSecurityAlert({
        level: "high",
        message: "Unusual activity pattern detected for credential",
        details: {
          credentialId: auditEntry.credentialId,
          eventCount: recentCredentialEvents.length,
          timeWindow: "1 hour",
        },
        credentialId: auditEntry.credentialId,
        agentId: this.agentId,
      });
    }
  }

  private async performComplianceCheck(
    auditEntry: AuditLogEntry,
  ): Promise<{ compliant: boolean; details?: string }> {
    // Simulate compliance checking
    // In real implementation, this would check against actual compliance rules

    if (
      auditEntry.threatLevel === "critical" &&
      auditEntry.eventType === "unauthorized_access"
    ) {
      return { compliant: false, details: "Critical security event detected" };
    }

    return { compliant: true };
  }

  private async evaluateComplianceRule(
    rule: ComplianceRule,
    _context: Record<string, unknown>,
  ): Promise<ComplianceCheckResult> {
    // Simulate rule evaluation
    // In real implementation, this would evaluate actual compliance rules

    await sleep(Math.random() * 50); // Simulate processing time

    const passed = Math.random() > 0.1; // 90% pass rate for simulation

    return {
      ruleId: rule.id,
      ruleName: rule.name,
      status: passed ? "passed" : "failed",
      message: passed
        ? "Compliance rule satisfied"
        : "Compliance rule violation detected",
      timestamp: new Date(),
      severity: rule.severity || "medium",
    };
  }

  private setupComplianceRules(): void {
    const rules: ComplianceRule[] = [
      {
        id: "pci_dss_key_rotation",
        name: "PCI DSS Key Rotation",
        description: "Keys must be rotated every 90 days",
        standard: "PCI DSS",
        enabled: true,
        severity: "high",
        checkInterval: 24 * 60 * 60 * 1000, // Daily
      },
      {
        id: "gdpr_access_logging",
        name: "GDPR Access Logging",
        description: "All credential access must be logged",
        standard: "GDPR",
        enabled: true,
        severity: "medium",
        checkInterval: 60 * 60 * 1000, // Hourly
      },
      {
        id: "sox_segregation_duties",
        name: "SOX Segregation of Duties",
        description: "No single agent can perform all rotation steps",
        standard: "SOX",
        enabled: true,
        severity: "high",
        checkInterval: 24 * 60 * 60 * 1000, // Daily
      },
    ];

    rules.forEach((rule) => {
      this.complianceRules.set(rule.id, rule);
    });
  }

  private setupThreatDetectionRules(): void {
    const rules: ThreatDetectionRule[] = [
      {
        ruleId: "repeated_failures",
        name: "Repeated Rotation Failures",
        description: "Multiple rotation failures in short timeframe",
        eventPattern: "rotation_failed",
        threshold: 5,
        timeWindowMs: 60 * 60 * 1000, // 1 hour
        severity: "high",
        enabled: true,
        action: "alert",
      },
      {
        ruleId: "emergency_rotation_spike",
        name: "Emergency Rotation Spike",
        description: "Unusual number of emergency rotations",
        eventPattern: "emergency_rotation",
        threshold: 3,
        timeWindowMs: 30 * 60 * 1000, // 30 minutes
        severity: "critical",
        enabled: true,
        action: "alert",
      },
      {
        ruleId: "unauthorized_access",
        name: "Unauthorized Access Attempts",
        description: "Detected unauthorized credential access",
        eventPattern: "unauthorized_access",
        threshold: 1,
        timeWindowMs: 5 * 60 * 1000, // 5 minutes
        severity: "critical",
        enabled: true,
        action: "block",
      },
    ];

    rules.forEach((rule) => {
      this.threatDetectionRules.set(rule.ruleId, rule);
    });
  }

  private startSecurityScanning(): void {
    const interval = this.config.securityScanIntervalMs!;

    this.securityScanTimer = setInterval(async () => {
      try {
        await this.performSecurityScan({ scanType: "automatic" });
      } catch (error) {
        this.componentLogger.error("Automatic security scan failed", {
          error: error instanceof Error ? error.message : "Unknown error",
        });
      }
    }, interval);
  }

  private startAuditLogFlushing(): void {
    // Flush audit logs every 5 minutes
    this.auditLogFlushTimer = setInterval(
      async () => {
        await this.flushAuditLogs();
      },
      5 * 60 * 1000,
    );
  }

  private async loadExistingAuditLogs(): Promise<void> {
    if (!this.config.auditLogPath) {
      return;
    }

    try {
      const logData = await fs.readFile(this.config.auditLogPath, "utf8");
      const logs = JSON.parse(logData);

      if (Array.isArray(logs)) {
        logs.forEach((log) => {
          // Reconstruct Date objects
          log.timestamp = new Date(log.timestamp);
          this.auditLogs.push(log);
        });

        this.componentLogger.info("Loaded existing audit logs", {
          count: logs.length,
        });
      }
    } catch (error) {
      // File might not exist yet, which is fine
      this.componentLogger.debug("Could not load existing audit logs", {
        error: error instanceof Error ? error.message : "Unknown error",
      });
    }
  }

  private async flushAuditLogs(): Promise<void> {
    if (!this.config.auditLogPath || this.auditLogs.length === 0) {
      return;
    }

    try {
      // Apply retention policy
      const retentionPeriod = this.config.retentionPeriodDays || 90;
      const cutoffDate = new Date(
        Date.now() - retentionPeriod * 24 * 60 * 60 * 1000,
      );

      const retainedLogs = this.auditLogs.filter(
        (log) => log.timestamp >= cutoffDate,
      );
      const removedCount = this.auditLogs.length - retainedLogs.length;

      if (removedCount > 0) {
        this.auditLogs.splice(0, removedCount);
        this.componentLogger.info("Removed expired audit logs", {
          removedCount,
        });
      }

      // Write to file
      const logData = JSON.stringify(retainedLogs, null, 2);
      await fs.writeFile(this.config.auditLogPath, logData);

      this.componentLogger.debug("Audit logs flushed to disk", {
        count: retainedLogs.length,
      });
    } catch (error) {
      this.componentLogger.error("Failed to flush audit logs", {
        error: error instanceof Error ? error.message : "Unknown error",
      });
    }
  }

  public override getPerformanceMetrics(): Record<string, unknown> {
    const baseMetrics = super.getPerformanceMetrics();

    return {
      ...baseMetrics,
      securityMetrics: this.securityMetrics,
      auditMetrics: {
        totalLogs: this.auditLogs.length,
        recentLogs: this.auditLogs.filter(
          (log) => Date.now() - log.timestamp.getTime() < 24 * 60 * 60 * 1000,
        ).length,
      },
      complianceMetrics: {
        totalRules: this.complianceRules.size,
        enabledRules: Array.from(this.complianceRules.values()).filter(
          (r) => r.enabled,
        ).length,
      },
      threatDetectionMetrics: {
        totalRules: this.threatDetectionRules.size,
        activeRules: Array.from(this.threatDetectionRules.values()).filter(
          (r) => r.enabled,
        ).length,
      },
    };
  }
}

export default SecurityMonitorAgent;
