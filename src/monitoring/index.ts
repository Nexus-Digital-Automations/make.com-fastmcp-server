/**
 * Monitoring Module Index
 * Exports all monitoring classes for dependency vulnerability scanning, maintenance reporting, and log pattern analysis
 */

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
export {
  AlertManager,
  PatternAlert,
  AlertNotificationPayload,
} from "./alert-manager.js";
export {
  PatternAnalysisTransport,
  createPatternAnalysisTransport,
  addPatternAnalysisToLogger,
} from "./pattern-analysis-transport.js";
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
