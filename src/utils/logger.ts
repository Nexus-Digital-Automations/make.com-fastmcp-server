import winston from "winston";
import DailyRotateFile from "winston-daily-rotate-file";

// Shared logger instance for monitoring components
// Configured to output to files only to avoid MCP protocol interference
export const monitoringLogger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json(),
  ),
  transports: [
    // File-based logging only - no console output to prevent MCP interference
    new DailyRotateFile({
      filename: "logs/monitoring/monitoring-error-%DATE%.log",
      datePattern: "YYYY-MM-DD",
      level: "error",
      maxFiles: "30d",
      maxSize: "100m",
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json(),
      ),
    }),
    new DailyRotateFile({
      filename: "logs/monitoring/monitoring-combined-%DATE%.log",
      datePattern: "YYYY-MM-DD",
      maxFiles: "30d",
      maxSize: "100m",
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json(),
      ),
    }),
    new winston.transports.File({
      filename: "logs/monitoring/monitoring-debug.log",
      level: "debug",
      maxsize: 50 * 1024 * 1024, // 50MB
      maxFiles: 5,
    }),
  ],
  // Explicitly disable console output for monitoring components
  exitOnError: false,
});

// Helper functions for structured logging
export const logPatternRegistration = (
  patternName: string,
  severity: string,
) => {
  monitoringLogger.info("Pattern registered", {
    component: "LogPatternAnalyzer",
    patternName,
    severity,
    action: "pattern_registered",
  });
};

export const logMultiplePatternRegistration = (count: number) => {
  monitoringLogger.info("Multiple patterns registered", {
    component: "LogPatternAnalyzer",
    patternCount: count,
    action: "patterns_registered",
  });
};

export const logPatternHistoryCleared = () => {
  monitoringLogger.info("Pattern match history cleared", {
    component: "LogPatternAnalyzer",
    action: "history_cleared",
  });
};

export const logPatternRemoved = (patternId: string) => {
  monitoringLogger.info("Pattern removed", {
    component: "LogPatternAnalyzer",
    patternId,
    action: "pattern_removed",
  });
};

export const logCorrelationRulesInitialized = (count: number) => {
  monitoringLogger.info("Correlation rules initialized", {
    component: "BasicCorrelationEngine",
    ruleCount: count,
    action: "rules_initialized",
  });
};

export const logCorrelationRuleAdded = (
  ruleName: string,
  correlationType: string,
) => {
  monitoringLogger.info("Correlation rule added", {
    component: "BasicCorrelationEngine",
    ruleName,
    correlationType,
    action: "rule_added",
  });
};

export const logCorrelationRuleRemoved = (ruleId: string) => {
  monitoringLogger.info("Correlation rule removed", {
    component: "BasicCorrelationEngine",
    ruleId,
    action: "rule_removed",
  });
};

export const logAlertCorrelationCreated = (
  correlationId: string,
  correlationType: string,
  alertCount: number,
) => {
  monitoringLogger.info("Alert correlation created", {
    component: "BasicCorrelationEngine",
    correlationId,
    correlationType,
    alertCount,
    action: "correlation_created",
  });
};

export const logRuleLearning = (ruleId: string, confidence: number) => {
  monitoringLogger.info("Rule learning occurred", {
    component: "BasicCorrelationEngine",
    ruleId,
    confidence,
    action: "rule_learning",
  });
};

export const logExpiredCorrelationsCleanup = (count: number) => {
  monitoringLogger.info("Expired correlations cleaned up", {
    component: "BasicCorrelationEngine",
    cleanedCount: count,
    action: "correlations_cleanup",
  });
};

export const logCorrelationEngineShutdown = () => {
  monitoringLogger.info("Correlation engine shutting down", {
    component: "BasicCorrelationEngine",
    action: "engine_shutdown",
  });
};

export const logCorrelationEngineShutdownComplete = () => {
  monitoringLogger.info("Correlation engine shutdown complete", {
    component: "BasicCorrelationEngine",
    action: "shutdown_complete",
  });
};

export const logNotificationChannelAdded = (
  channelId: string,
  channelType: string,
) => {
  monitoringLogger.info("Notification channel added", {
    component: "MultiChannelNotificationManager",
    channelId,
    channelType,
    action: "channel_added",
  });
};

export const logNotificationChannelRemoved = (channelId: string) => {
  monitoringLogger.info("Notification channel removed", {
    component: "MultiChannelNotificationManager",
    channelId,
    action: "channel_removed",
  });
};

export const logNotificationChannelUnhealthy = (
  channelId: string,
  errorCount: number,
) => {
  monitoringLogger.warn("Notification channel marked unhealthy", {
    component: "BaseNotificationChannel",
    channelId,
    errorCount,
    action: "channel_unhealthy",
  });
};

export const logNotificationChannelRestored = (channelId: string) => {
  monitoringLogger.info("Notification channel restored to healthy status", {
    component: "BaseNotificationChannel",
    channelId,
    action: "channel_restored",
  });
};

export const logNotificationChannelHealthCheckFailed = (
  channelId: string,
  error: unknown,
) => {
  monitoringLogger.warn("Health check failed for notification channel", {
    component: "BaseNotificationChannel",
    channelId,
    error: error instanceof Error ? error.message : String(error),
    action: "health_check_failed",
  });
};

export const logNoApplicableChannelsFound = (alertId: string) => {
  monitoringLogger.warn("No applicable notification channels found for alert", {
    component: "MultiChannelNotificationManager",
    alertId,
    action: "no_channels_found",
  });
};

export const logAlertNotificationSummary = (
  alertId: string,
  successfulChannels: number,
  totalChannels: number,
) => {
  monitoringLogger.info("Alert notification summary", {
    component: "MultiChannelNotificationManager",
    alertId,
    successfulChannels,
    totalChannels,
    action: "notification_summary",
  });
};

export const logEmailNotificationSent = (
  alertId: string,
  recipients: string[],
) => {
  monitoringLogger.info("Email notification sent", {
    component: "EmailNotificationChannel",
    alertId,
    recipientCount: recipients.length,
    recipients: recipients.join(", "),
    action: "email_sent",
  });
};

export const logSMSNotificationSent = (
  alertId: string,
  phoneNumbers: string[],
) => {
  monitoringLogger.info("SMS notification sent", {
    component: "SMSNotificationChannel",
    alertId,
    recipientCount: phoneNumbers.length,
    phoneNumbers: phoneNumbers.join(", "),
    action: "sms_sent",
  });
};
