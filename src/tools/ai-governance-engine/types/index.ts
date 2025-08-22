/**
 * AI Governance Engine Types and Interfaces
 * Extracted from ai-governance-engine.ts for better maintainability
 * Generated on 2025-08-22T09:54:20.000Z
 */

// ==================== INTERFACES & TYPES ====================

export interface GovernanceMetrics {
  complianceScore: number;
  riskScore: number;
  policyViolations: number;
  automatedRemediations: number;
  avgResponseTime: number;
  predictionAccuracy: number;
}

export interface ComplianceFramework {
  id: string;
  name: string;
  version: string;
  controls: Control[];
  riskThreshold: number;
  automatedRemediation: boolean;
}

export interface Control {
  id: string;
  name: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  requirements: string[];
  automatedCheck: boolean;
  remediationActions: string[];
}

export interface RiskAssessment {
  riskId: string;
  category: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  probability: number;
  impact: number;
  riskScore: number;
  indicators: string[];
  mitigationStrategies: string[];
  automatedRemediation: boolean;
  estimatedCost: number;
}

export interface PolicyConflict {
  conflictId: string;
  policies: string[];
  conflictType: 'contradictory' | 'overlapping' | 'redundant' | 'gap';
  severity: 'low' | 'medium' | 'high' | 'critical';
  impact: string;
  resolutionSuggestions: string[];
  automatedResolution: boolean;
}

export interface GovernanceInsight {
  type: 'trend' | 'anomaly' | 'prediction' | 'recommendation';
  title: string;
  description: string;
  severity: 'info' | 'warning' | 'critical';
  confidence: number;
  impact: string;
  actionableSteps: string[];
  timeframe: string;
}

export interface RemediationWorkflow {
  workflowId: string;
  triggeredBy: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  steps: RemediationStep[];
  escalationPath: EscalationStep[];
  automatedExecution: boolean;
  estimatedDuration: number;
  successCriteria: string[];
}

export interface RemediationStep {
  stepId: string;
  action: string;
  description: string;
  automated: boolean;
  duration: number;
  dependencies: string[];
  successCriteria: string[];
}

export interface EscalationStep {
  level: number;
  condition: string;
  action: string;
  stakeholders: string[];
  timeframe: number;
}

// ==================== ML MODEL INTERFACES ====================

export interface MLModel {
  type: string;
  accuracy: number;
  lastTrained: string;
}

export interface EnsembleMLModel extends MLModel {
  type: 'ensemble';
  algorithms: string[];
}

export interface IsolationForestModel extends MLModel {
  type: 'isolation_forest';
  sensitivity: number;
}

export interface ReinforcementLearningModel extends MLModel {
  type: 'reinforcement_learning';
  algorithm: string;
  convergence: number;
}

export type MLModelType = EnsembleMLModel | IsolationForestModel | ReinforcementLearningModel;

export interface PredictionCacheEntry {
  prediction: string;
  confidence: number;
  timestamp: string;
  factors: string[];
  recommendations?: string[];
}

// ==================== COMPLIANCE MONITORING INTERFACES ====================

export interface ComplianceStatus {
  timestamp: string;
  frameworks: FrameworkStatus[];
  overallScore: number;
  riskLevel: string;
  nextAssessment: string;
}

export interface FrameworkStatus {
  name: string;
  status: 'compliant' | 'non-compliant';
  score: number;
  controlsCovered: number;
  violationsCount: number;
  lastAssessment: string;
}

export interface Violation {
  id: string;
  framework: string;
  control: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  detectedAt: string;
  status: 'open' | 'in_progress' | 'resolved';
  automatedRemediation: boolean;
}

export interface CompliancePrediction {
  type: string;
  framework: string;
  prediction: string;
  confidence: number;
  timeframe: string;
  factors: string[];
  recommendations: string[];
}

export interface AutomatedAction {
  violationId: string;
  action: string;
  status: 'pending' | 'executing' | 'executed' | 'failed';
  executedAt: string;
  result: 'success' | 'failure' | 'partial';
}

// ==================== POLICY CONFLICT INTERFACES ====================

export interface PolicyResolutionPlan {
  conflictId: string;
  strategy: string;
  steps: string[];
  estimatedResolution: string;
  stakeholders: string[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
}

export interface ConflictImpactAnalysis {
  conflictId: string;
  affectedSystems: string[];
  businessImpact: string;
  operationalImpact: string;
  complianceRisk: string;
  estimatedCost: number;
  urgency: 'low' | 'medium' | 'high' | 'critical';
}

// ==================== RISK ASSESSMENT INTERFACES ====================

export interface OverallRiskAssessment {
  totalRiskScore: number;
  riskCategories: { [category: string]: number };
  trends: RiskTrend[];
  predictions: RiskPrediction[];
  mitigationPlans: MitigationPlan[];
}

export interface RiskTrend {
  category: string;
  direction: 'increasing' | 'decreasing' | 'stable';
  velocity: number;
  timeframe: string;
}

export interface RiskPrediction {
  category: string;
  predictedScore: number;
  confidence: number;
  timeframe: string;
  influencingFactors: string[];
}

export interface MitigationPlan {
  riskCategory: string;
  strategies: string[];
  priority: 'low' | 'medium' | 'high' | 'critical';
  estimatedEffectiveness: number;
  resources: string[];
  timeline: string;
}

// ==================== DASHBOARD INTERFACES ====================

export interface DashboardConfig {
  userId: string;
  layout: string;
  widgets: DashboardWidget[];
  refreshInterval: number;
  alertSettings: Record<string, unknown>;
}

export interface DashboardWidget {
  id: string;
  type: 'chart' | 'metric' | 'alert' | 'table';
  title: string;
  position: { x: number; y: number };
  size: { width: number; height: number };
  config: Record<string, unknown>;
  dataSource: string;
  refreshRate: number;
}

export interface RealTimeData {
  timestamp: string;
  metrics: GovernanceMetrics;
  alerts: string[];
  forecasts: Forecast[];
}

export interface Forecast {
  metric: string;
  predictions: ForecastPoint[];
  confidence: number;
}

export interface ForecastPoint {
  timestamp: string;
  value: number;
  upperBound: number;
  lowerBound: number;
}

// ==================== ADDITIONAL INTERFACES ====================

export interface TrendAnalysis {
  metric: string;
  direction: 'up' | 'down' | 'stable';
  change: number;
  significance: 'low' | 'medium' | 'high';
  period: string;
}

export interface AlertConfiguration {
  metric: string;
  thresholds: {
    warning: number;
    critical: number;
  };
  enabled: boolean;
  recipients: string[];
}

export interface ComplianceReport {
  generatedAt: string;
  period: string;
  frameworks: FrameworkStatus[];
  violations: Violation[];
  trends: TrendAnalysis[];
  recommendations: string[];
}

export interface GovernanceAuditLog {
  timestamp: string;
  user: string;
  action: string;
  resource: string;
  outcome: 'success' | 'failure';
  details: string;
}

export interface IntegrationConfig {
  system: string;
  endpoint: string;
  authConfig: Record<string, unknown>;
  syncInterval: number;
  enabled: boolean;
}

export interface NotificationSettings {
  userId: string;
  channels: ('email' | 'slack' | 'webhook')[];
  frequency: 'real-time' | 'hourly' | 'daily';
  severity: ('low' | 'medium' | 'high' | 'critical')[];
}

export interface SystemHealth {
  status: 'healthy' | 'degraded' | 'critical';
  components: ComponentHealth[];
  lastCheck: string;
}

export interface ComponentHealth {
  name: string;
  status: 'healthy' | 'degraded' | 'critical';
  responseTime: number;
  errorRate: number;
  lastCheck: string;
}

export interface PerformanceMetrics {
  processingTime: number;
  memoryUsage: number;
  cpuUsage: number;
  throughput: number;
  errorRate: number;
}

// ==================== ADDITIONAL OPTION INTERFACES ====================

export interface CreateFrameworkOptions {
  id?: string;
  name: string;
  version: string;
  controls?: Control[];
  riskThreshold?: number;
  automatedRemediation?: boolean;
}

export interface MonitoringOptions {
  frameworks?: string[];
  realTime?: boolean;
  alerting?: boolean;
  reporting?: boolean;
}

export interface RiskAssessmentOptions {
  categories?: string[];
  severity?: ('low' | 'medium' | 'high' | 'critical')[];
  includeML?: boolean;
  timeframe?: string;
}

export interface RemediationOptions {
  automated?: boolean;
  severity?: ('low' | 'medium' | 'high' | 'critical')[];
  timeout?: number;
}

export interface AnalyticsOptions {
  metrics?: string[];
  timeRange?: string;
  granularity?: 'minute' | 'hour' | 'day' | 'week' | 'month';
  includePredictions?: boolean;
}

export interface ReportGenerationOptions {
  format?: 'json' | 'pdf' | 'csv' | 'html';
  includeCharts?: boolean;
  sections?: string[];
  customization?: Record<string, unknown>;
}

export interface DashboardCustomizationOptions {
  layout?: string;
  widgets?: string[];
  theme?: string;
  filters?: Record<string, unknown>;
}

export interface IntegrationsOptions {
  systems?: string[];
  syncFrequency?: string;
  dataMapping?: Record<string, unknown>;
}

export interface MLTrainingOptions {
  algorithm?: string;
  features?: string[];
  trainingData?: Record<string, unknown>;
  validationSplit?: number;
}

export interface SystemConfigOptions {
  performance?: PerformanceMetrics;
  security?: Record<string, unknown>;
  logging?: Record<string, unknown>;
  monitoring?: Record<string, unknown>;
}

export interface AuditOptions {
  user?: string;
  actions?: string[];
  timeRange?: string;
  resources?: string[];
}