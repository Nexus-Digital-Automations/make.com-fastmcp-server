/**
 * Monitoring Module Index
 * Exports all monitoring classes for dependency vulnerability scanning, maintenance reporting, log pattern analysis, and enhanced alerting
 */

// Core monitoring components
export {
  DependencyMonitor,
  VulnerabilityAlert,
  OutdatedPackage,
  DependencyScanResult,
} from "./dependency-monitor.js";
export {
  MaintenanceReportGenerator,
  MaintenanceReport,
  ReportExportOptions,
} from "./maintenance-report-generator.js";
export {
  LogPatternAnalyzer,
  LogEntry,
  LogPattern,
  PatternMatch,
  LogAnalyticsSummary,
  PatternStatistics,
} from "./log-pattern-analyzer.js";

// Alert management
export {
  AlertManager,
  PatternAlert,
  AlertNotificationPayload,
} from "./alert-manager.js";
export {
  EnhancedAlertManager,
  createEnhancedAlertManager,
  enhancedAlertManager,
  EnhancedAlertTriggerResult,
  AlertProcessingMetrics,
} from "./enhanced-alert-manager.js";

// Enhanced alert storage and archiving
export {
  EnhancedAlertStorage,
  AlertArchiveManager,
  AlertStorageConfig,
  ArchivedAlert,
  CompressedAlert,
} from "./enhanced-alert-storage.js";

// Alert correlation engine
export {
  BasicCorrelationEngine,
  CorrelationRule,
  AlertCorrelation,
  CorrelationEngineConfig,
} from "./alert-correlation-engine.js";

// Multi-channel notifications
export {
  MultiChannelNotificationManager,
  BaseNotificationChannel,
  WebhookNotificationChannel,
  SlackNotificationChannel,
  EmailNotificationChannel,
  SMSNotificationChannel,
  createWebhookChannel,
  createSlackChannel,
  NotificationChannel,
  NotificationResult,
  NotificationSummary,
} from "./multi-channel-notification.js";

// Configuration management
export {
  ConfigurationManager,
  createConfigurationManager,
  EnhancedAlertManagerConfig,
  ConfigValidationError,
} from "./configuration-manager.js";

// Winston integration
export {
  PatternAnalysisTransport,
  createPatternAnalysisTransport,
  addPatternAnalysisToLogger,
} from "./pattern-analysis-transport.js";

// Pattern library
export {
  ALL_PATTERNS,
  CRITICAL_PATTERNS,
  PERFORMANCE_PATTERNS,
  MAKE_API_PATTERNS,
  SECURITY_PATTERNS,
  SYSTEM_PATTERNS,
  PATTERN_CATEGORIES,
  PatternCategory,
  getPatternsByCategory,
  getPatternsBySeverity,
  validatePattern,
} from "./pattern-library.js";
