/**
 * @fileoverview Security and audit-related type definitions
 * Contains interfaces for secret scanning, breach detection, and compliance
 */

export interface SecretLeakageAlert {
  alertId: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  detectionMethod: string;
  location: string;
  secretType: string;
  confidence: number;
  timestamp: Date;
  status: 'open' | 'investigating' | 'confirmed' | 'false_positive' | 'resolved';
  responseActions: string[];
}

export interface BreachIndicator {
  id: string;
  indicatorId?: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence?: number;
  timestamp?: Date;
  source?: string;
  details?: {
    anomalyType?: string;
    affectedResource?: string;
    riskScore?: number;
    [key: string]: unknown;
  };
  status?: 'active' | 'resolved' | 'false_positive';
  responseActions?: string[];
  description?: string;
  firstDetected?: Date;
  lastSeen?: Date;
  frequency?: number;
  relatedEvents?: string[];
  mitigation?: string[];
  resolved?: boolean;
}

export interface ComplianceReport {
  framework: string;
  reportId: string;
  generatedAt: Date;
  reportingPeriod: {
    start: Date;
    end: Date;
  };
  overallCompliance: number;
  controlStatus: Array<{
    controlId: string;
    name: string;
    status: 'compliant' | 'non_compliant' | 'not_applicable';
    evidence: string[];
    gaps: string[];
  }>;
  auditTrail: {
    totalEvents: number;
    criticalEvents: number;
    complianceViolations: number;
    evidenceIntegrity: boolean;
  };
}

/**
 * Type definitions for secret scanning
 */
export type ScanType = 'repository' | 'runtime' | 'configuration' | 'memory' | 'network';
export type AlertSeverity = 'low' | 'medium' | 'high' | 'critical';

/**
 * Type definitions for breach detection monitoring targets
 */
export type MonitoringTarget = 
  | 'secret_access_patterns'
  | 'authentication_events'
  | 'authorization_failures'
  | 'unusual_api_usage'
  | 'geographic_anomalies'
  | 'time_based_anomalies';

/**
 * Type definitions for audit devices
 */
export type AuditDeviceType = 'file' | 'syslog' | 'socket' | 'elasticsearch' | 'splunk';
export type AuditFormat = 'json' | 'jsonx';

/**
 * Type definitions for compliance frameworks
 */
export type ComplianceFramework = 'soc2' | 'pci_dss' | 'gdpr' | 'hipaa' | 'fisma' | 'iso27001';

/**
 * Type definitions for compliance status
 */
export type ComplianceStatus = 'compliant' | 'non_compliant' | 'not_applicable';