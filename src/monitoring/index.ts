/**
 * Monitoring Module Index
 * Exports all monitoring classes for dependency vulnerability scanning and maintenance reporting
 */

export {
  DependencyMonitor,
  VulnerabilityAlert,
  OutdatedPackage,
  DependencyScanResult,
} from "./dependency-monitor";
export {
  MaintenanceReportGenerator,
  MaintenanceReport,
  ReportExportOptions,
} from "./maintenance-report-generator";
