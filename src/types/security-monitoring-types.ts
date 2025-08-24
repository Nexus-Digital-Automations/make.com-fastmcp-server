/**
 * Security Monitoring Type Definitions
 * Comprehensive types for security monitoring, threat detection, and incident management
 */

export * from '../middleware/security-monitoring.js';

// Enhanced security event types
export interface SecurityEventContext {
  correlationId: string;
  sessionId?: string;
  userId?: string;
  orgId?: string;
  requestId?: string;
  traceId?: string;
}

export interface DeviceFingerprint {
  id: string;
  userAgent: string;
  screenResolution: string;
  timezone: string;
  language: string;
  platform: string;
  cookiesEnabled: boolean;
  javaEnabled: boolean;
  hash: string;
  firstSeen: Date;
  lastSeen: Date;
  riskScore: number;
}

export interface NetworkInfo {
  ipAddress: string;
  subnet?: string;
  asn?: number;
  organization?: string;
  isp?: string;
  connectionType?: 'broadband' | 'cellular' | 'satellite' | 'vpn' | 'proxy' | 'tor';
  riskScore: number;
}

export interface GeoLocationInfo {
  country: string;
  countryCode: string;
  region: string;
  regionCode: string;
  city: string;
  postalCode?: string;
  latitude: number;
  longitude: number;
  timezone: string;
  isp: string;
  organization?: string;
  accuracyRadius: number;
  riskScore: number;
}

// Threat intelligence types
export interface ThreatIndicator {
  id: string;
  type: 'ip' | 'domain' | 'url' | 'hash' | 'email' | 'filename' | 'registry_key' | 'mutex' | 'user_agent';
  value: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number; // 0-1
  tlp: 'white' | 'green' | 'amber' | 'red'; // Traffic Light Protocol
  source: string;
  sourceReliability: 'A' | 'B' | 'C' | 'D' | 'E' | 'F'; // Admiral rating
  firstSeen: Date;
  lastSeen: Date;
  tags: string[];
  mitre: {
    tactics?: string[];
    techniques?: string[];
    groups?: string[];
  };
  references: Array<{
    url: string;
    description: string;
    source: string;
  }>;
  active: boolean;
  expiresAt?: Date;
}

export interface ThreatActor {
  id: string;
  name: string;
  aliases: string[];
  description: string;
  sophistication: 'none' | 'minimal' | 'intermediate' | 'advanced' | 'expert' | 'innovator' | 'strategic';
  motivation: 'financial' | 'espionage' | 'sabotage' | 'ideology' | 'notoriety' | 'unknown';
  intendedEffect: 'theft' | 'disruption' | 'destruction' | 'exposure' | 'unauthorized_access';
  primaryVictims: string[];
  geography: string[];
  industries: string[];
  ttp: string[]; // Tactics, Techniques, and Procedures
  tools: string[];
  firstSeen: Date;
  lastActivity: Date;
  active: boolean;
}

export interface AttackPattern {
  id: string;
  name: string;
  description: string;
  killChainPhases: Array<{
    killChain: string;
    phase: string;
  }>;
  mitre: {
    id: string;
    tactics: string[];
    techniques: string[];
    subTechniques?: string[];
  };
  platforms: string[];
  dataSource: string[];
  defenses: string[];
  detection: string;
  mitigation: string[];
  references: string[];
}

// Machine learning and analytics types
export interface AnomalyDetectionConfig {
  algorithm: 'isolation_forest' | 'one_class_svm' | 'local_outlier_factor' | 'statistical' | 'lstm';
  threshold: number;
  sensitivity: 'low' | 'medium' | 'high';
  features: string[];
  trainingPeriod: number; // days
  retrainingFrequency: number; // hours
  minSamples: number;
  contamination: number; // expected outlier ratio
}

export interface MLModelMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  falsePositiveRate: number;
  falseNegativeRate: number;
  auc: number;
  trainingTime: number; // milliseconds
  inferenceTime: number; // milliseconds per prediction
  modelSize: number; // bytes
  lastUpdated: Date;
}

export interface BehaviorProfile {
  entityId: string;
  entityType: 'user' | 'ip' | 'device' | 'session';
  features: Record<string, {
    value: number;
    confidence: number;
    lastUpdated: Date;
    trend: 'increasing' | 'decreasing' | 'stable';
  }>;
  riskScore: number;
  anomalyScore: number;
  lastAnalyzed: Date;
  profileAge: number; // days since first observation
  observationCount: number;
  significantChanges: Array<{
    feature: string;
    oldValue: number;
    newValue: number;
    timestamp: Date;
    significance: number;
  }>;
}

// Incident management types
export interface SecurityIncidentTemplate {
  id: string;
  name: string;
  category: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  playbook: string[];
  requiredRoles: string[];
  sla: {
    acknowledgment: number; // minutes
    investigation: number; // minutes
    containment: number; // minutes
    resolution: number; // hours
  };
  escalationRules: Array<{
    condition: string;
    action: string;
    delay: number; // minutes
  }>;
  communicationPlan: Array<{
    audience: string;
    template: string;
    frequency: string;
  }>;
}

export interface IncidentWorkflow {
  id: string;
  incidentId: string;
  status: 'pending' | 'in_progress' | 'completed' | 'failed' | 'cancelled';
  steps: Array<{
    id: string;
    name: string;
    description: string;
    assignee?: string;
    status: 'pending' | 'in_progress' | 'completed' | 'failed' | 'skipped';
    startTime?: Date;
    endTime?: Date;
    duration?: number;
    notes?: string;
    artifacts?: string[];
    dependencies?: string[];
  }>;
  createdAt: Date;
  updatedAt: Date;
  createdBy: string;
  executionTime: number;
}

export interface SecurityMetricsSnapshot {
  timestamp: Date;
  period: '1m' | '5m' | '15m' | '1h' | '24h';
  
  // Event metrics
  events: {
    total: number;
    byType: Record<string, number>;
    bySeverity: Record<string, number>;
    bySource: Record<string, number>;
  };
  
  // Threat metrics
  threats: {
    detected: number;
    blocked: number;
    investigated: number;
    falsePositives: number;
    truePositives: number;
  };
  
  // Incident metrics
  incidents: {
    created: number;
    resolved: number;
    escalated: number;
    meanTimeToDetection: number;
    meanTimeToResponse: number;
    meanTimeToContainment: number;
    meanTimeToResolution: number;
  };
  
  // System metrics
  system: {
    cpu: number;
    memory: number;
    disk: number;
    network: number;
    throughput: number; // events per second
    latency: number; // average processing time in ms
  };
  
  // Risk metrics
  risk: {
    overallScore: number;
    byCategory: Record<string, number>;
    trend: 'increasing' | 'decreasing' | 'stable';
    topRisks: Array<{
      category: string;
      score: number;
      description: string;
    }>;
  };
}

// SIEM integration types
export interface SIEMEvent {
  timestamp: string;
  source: {
    ip?: string;
    hostname?: string;
    service: string;
    component: string;
  };
  destination?: {
    ip?: string;
    hostname?: string;
    port?: number;
  };
  user?: {
    id?: string;
    name?: string;
    email?: string;
    roles?: string[];
  };
  event: {
    category: string;
    type: string;
    action: string;
    outcome: 'success' | 'failure' | 'unknown';
    severity: number; // 0-10
    riskScore: number; // 0-100
  };
  message: string;
  fields: Record<string, unknown>;
  tags: string[];
  correlationId?: string;
  mitre?: {
    tactics?: string[];
    techniques?: string[];
  };
}

export interface SIEMConnector {
  id: string;
  name: string;
  type: 'splunk' | 'elastic' | 'sentinel' | 'qradar' | 'arcsight' | 'sumo_logic' | 'chronicle';
  config: {
    endpoint: string;
    apiKey?: string;
    token?: string;
    certificate?: string;
    index?: string;
    sourcetype?: string;
  };
  enabled: boolean;
  batchSize: number;
  flushInterval: number; // milliseconds
  retryAttempts: number;
  timeout: number; // milliseconds
  filters: Array<{
    field: string;
    operator: 'eq' | 'ne' | 'gt' | 'lt' | 'contains' | 'regex';
    value: string;
  }>;
  lastSync: Date;
  status: 'connected' | 'disconnected' | 'error';
  errorMessage?: string;
}

// SOAR integration types
export interface SOARPlaybook {
  id: string;
  name: string;
  description: string;
  version: string;
  triggers: Array<{
    type: 'event' | 'incident' | 'schedule' | 'manual';
    conditions: Record<string, unknown>;
  }>;
  actions: Array<{
    id: string;
    name: string;
    type: string;
    parameters: Record<string, unknown>;
    conditions?: Record<string, unknown>;
    timeout: number;
    retries: number;
  }>;
  workflow: Array<{
    from: string;
    to: string;
    condition?: string;
  }>;
  metadata: {
    author: string;
    created: Date;
    modified: Date;
    tags: string[];
    category: string;
    complexity: 'simple' | 'medium' | 'complex';
  };
  enabled: boolean;
  statistics: {
    executions: number;
    successes: number;
    failures: number;
    averageExecutionTime: number;
    lastExecution?: Date;
  };
}

export interface SOARExecution {
  id: string;
  playbookId: string;
  incidentId?: string;
  triggeredBy: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled' | 'timeout';
  startTime: Date;
  endTime?: Date;
  executionTime?: number;
  currentStep?: string;
  context: Record<string, unknown>;
  results: Record<string, unknown>;
  logs: Array<{
    timestamp: Date;
    level: 'info' | 'warn' | 'error' | 'debug';
    message: string;
    step?: string;
    data?: Record<string, unknown>;
  }>;
  error?: {
    message: string;
    step: string;
    stack?: string;
  };
}

// Compliance and audit types
export interface ComplianceFramework {
  id: string;
  name: string;
  version: string;
  description: string;
  controls: ComplianceControl[];
  applicability: {
    industries: string[];
    regions: string[];
    organizationSizes: string[];
  };
  lastUpdated: Date;
}

export interface ComplianceControl {
  id: string;
  frameworkId: string;
  title: string;
  description: string;
  category: string;
  subcategory?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  requirements: string[];
  testProcedures: string[];
  evidence: string[];
  frequency: 'continuous' | 'daily' | 'weekly' | 'monthly' | 'quarterly' | 'annually';
  automatable: boolean;
  dependencies?: string[];
  references: string[];
}

export interface ComplianceAssessment {
  id: string;
  frameworkId: string;
  period: {
    start: Date;
    end: Date;
  };
  status: 'in_progress' | 'completed' | 'failed';
  results: Array<{
    controlId: string;
    status: 'compliant' | 'non_compliant' | 'partially_compliant' | 'not_applicable';
    score: number; // 0-100
    findings: string[];
    evidence: Array<{
      type: string;
      description: string;
      source: string;
      timestamp: Date;
      automated: boolean;
    }>;
    remediationActions?: Array<{
      action: string;
      priority: 'low' | 'medium' | 'high' | 'critical';
      dueDate?: Date;
      assignee?: string;
      status: 'open' | 'in_progress' | 'completed';
    }>;
  }>;
  overallScore: number;
  assessor: string;
  reviewedBy?: string;
  createdAt: Date;
  completedAt?: Date;
  nextAssessment?: Date;
}

// Real-time monitoring types
export interface AlertRule {
  id: string;
  name: string;
  description: string;
  query: string;
  conditions: Array<{
    field: string;
    operator: 'eq' | 'ne' | 'gt' | 'lt' | 'gte' | 'lte' | 'contains' | 'matches';
    value: string | number;
    threshold?: number;
    timeWindow?: number; // minutes
  }>;
  severity: 'low' | 'medium' | 'high' | 'critical';
  enabled: boolean;
  throttle: number; // minutes between alerts
  actions: Array<{
    type: 'email' | 'sms' | 'webhook' | 'slack' | 'pagerduty' | 'ticket';
    config: Record<string, unknown>;
    conditions?: Record<string, unknown>;
  }>;
  tags: string[];
  metadata: {
    author: string;
    created: Date;
    modified: Date;
    category: string;
  };
  statistics: {
    triggered: number;
    lastTriggered?: Date;
    averageTriggersPerDay: number;
    falsePositiveRate: number;
  };
}

export interface Alert {
  id: string;
  ruleId: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'open' | 'acknowledged' | 'investigating' | 'resolved' | 'suppressed';
  assignee?: string;
  createdAt: Date;
  updatedAt: Date;
  acknowledgedAt?: Date;
  resolvedAt?: Date;
  events: string[]; // Related event IDs
  context: Record<string, unknown>;
  tags: string[];
  comments: Array<{
    id: string;
    author: string;
    message: string;
    timestamp: Date;
    type: 'comment' | 'status_change' | 'assignment' | 'escalation';
  }>;
  escalation: {
    level: number;
    escalatedAt?: Date;
    escalatedTo?: string;
    reason?: string;
  };
  resolution: {
    category?: string;
    description?: string;
    rootCause?: string;
    preventiveActions?: string[];
  };
}

// Dashboard and visualization types
export interface SecurityDashboard {
  id: string;
  name: string;
  description: string;
  layout: DashboardLayout;
  widgets: DashboardWidget[];
  filters: DashboardFilter[];
  refreshInterval: number; // seconds
  timeRange: {
    type: 'relative' | 'absolute';
    value: string | { start: Date; end: Date };
  };
  permissions: {
    viewers: string[];
    editors: string[];
    owners: string[];
  };
  metadata: {
    author: string;
    created: Date;
    modified: Date;
    category: string;
    tags: string[];
  };
}

export interface DashboardLayout {
  type: 'grid' | 'flexible';
  columns: number;
  rows: number;
  spacing: number;
}

export interface DashboardWidget {
  id: string;
  type: 'metric' | 'chart' | 'table' | 'map' | 'text' | 'gauge' | 'heatmap';
  title: string;
  position: {
    x: number;
    y: number;
    width: number;
    height: number;
  };
  dataSource: {
    type: string;
    query: string;
    refreshInterval: number;
  };
  visualization: {
    chartType?: 'line' | 'bar' | 'pie' | 'area' | 'scatter';
    aggregation?: 'sum' | 'avg' | 'count' | 'min' | 'max';
    groupBy?: string[];
    colors?: string[];
  };
  thresholds?: Array<{
    value: number;
    color: string;
    operator: 'gt' | 'lt' | 'gte' | 'lte';
  }>;
  alerts?: string[]; // Alert rule IDs
}

export interface DashboardFilter {
  id: string;
  name: string;
  type: 'text' | 'select' | 'multiselect' | 'date' | 'daterange' | 'number';
  field: string;
  options?: Array<{ label: string; value: string }>;
  defaultValue?: unknown;
  required: boolean;
}

// Export all types for convenient importing
export type {
  SecurityEventContext,
  DeviceFingerprint,
  NetworkInfo,
  GeoLocationInfo,
  ThreatIndicator,
  ThreatActor,
  AttackPattern,
  AnomalyDetectionConfig,
  MLModelMetrics,
  BehaviorProfile,
  SecurityIncidentTemplate,
  IncidentWorkflow,
  SecurityMetricsSnapshot,
  SIEMEvent,
  SIEMConnector,
  SOARPlaybook,
  SOARExecution,
  ComplianceFramework,
  ComplianceControl,
  ComplianceAssessment,
  AlertRule,
  Alert,
  SecurityDashboard,
  DashboardLayout,
  DashboardWidget,
  DashboardFilter
};