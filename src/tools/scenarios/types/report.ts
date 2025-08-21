/**
 * @fileoverview Report and analysis types for Make.com scenarios
 * Type definitions for diagnostic reports, performance analysis, and troubleshooting
 */

export interface ReportMetadata {
  reportId?: string;
  generatedAt?: string;
  analysisScope?: {
    scenarioCount?: number;
    timeRangeHours?: number;
  };
}

export interface TroubleshootingReportData {
  metadata?: ReportMetadata;
  executiveSummary?: {
    keyFindings: string[];
    criticalRecommendations: string[];
    businessImpact: {
      riskLevel: 'high' | 'medium' | 'low';
      operationalReadiness: 'ready' | 'needs_attention';
      recommendedActions: string;
    };
    nextSteps: string[];
    reportConfidence: {
      dataCompleteness: number;
      analysisDepth: string;
      recommendationReliability: string;
    };
  };
  systemOverview?: {
    systemHealthScore: number;
    performanceStatus: string;
    overallStatus: string;
    scenarioBreakdown: {
      healthy: number;
    };
  };
  consolidatedFindings?: ConsolidatedFindings;
  actionPlan?: ActionPlan;
  [key: string]: unknown;
}

export interface PerformanceAnalysisResult {
  analysisTimestamp: string;
  targetType: string;
  targetId?: string;
  timeRange: {
    startTime: string;
    endTime: string;
    durationHours: number;
  };
  overallHealthScore: number;
  performanceGrade: 'A' | 'B' | 'C' | 'D' | 'F';
  bottlenecks: unknown[];
  metrics: {
    responseTime: {
      average: number;
      p50: number;
      p95: number;
      p99: number;
      trend: 'improving' | 'stable' | 'degrading';
    };
    throughput: {
      requestsPerSecond: number;
      requestsPerMinute: number;
      trend: 'improving' | 'stable' | 'degrading';
    };
    reliability: {
      uptime: number;
      errorRate: number;
      successRate: number;
      trend: 'improving' | 'stable' | 'degrading';
    };
    resources: {
      cpuUsage: number;
      memoryUsage: number;
      networkUtilization: number;
      trend: 'improving' | 'stable' | 'degrading';
    };
  };
  trends: {
    performanceDirection: 'improving' | 'stable' | 'degrading';
    predictionConfidence: number;
    projectedIssues: string[];
  };
  benchmarkComparison: {
    industryStandard: string;
    currentPerformance: string;
    gap: string;
    ranking: 'below_average' | 'average' | 'above_average' | 'excellent';
  };
  recommendations: {
    immediate: string[];
    shortTerm: string[];
    longTerm: string[];
    estimatedImpact: number;
  };
  costAnalysis?: {
    currentCost: number;
    optimizationPotential: number;
    recommendedActions: string[];
  };
}

export interface ScenarioAnalysis {
  scenarioId: string;
  scenarioName: string;
  diagnosticReport: any; // Import from diagnostics.ts
  performanceAnalysis?: PerformanceAnalysisResult;
  errors: string[];
}

export interface ConsolidatedFindings {
  totalScenarios: number;
  healthyScenarios: number;
  warningScenarios: number;
  criticalScenarios: number;
  totalIssues: number;
  criticalIssues: number;
  securityRiskLevel: string;
  commonIssues: Array<{
    category: string;
    severity: string;
    title: string;
    count: number;
    affectedScenarios: string[];
    description: string;
    recommendations: string[];
  }>;
  performanceSummary: {
    averageHealthScore: number;
    averageResponseTime: number;
    totalBottlenecks: number;
    commonBottleneckTypes: string[];
  };
  securitySummary: {
    averageSecurityScore: number;
    totalSecurityIssues: number;
    criticalSecurityIssues: number;
    commonSecurityIssues: string[];
  };
  criticalActionItems: Array<{
    severity: 'critical' | 'high';
    action: string;
    affectedScenarios: string[];
    impact: string;
    effort: 'low' | 'medium' | 'high';
  }>;
}

export interface ActionPlan {
  immediate: Array<{
    action: string;
    priority: 'critical' | 'high';
    estimatedTime: string;
    impact: string;
    scenarioIds: string[];
  }>;
  shortTerm: Array<{
    action: string;
    priority: 'medium' | 'high';
    estimatedTime: string;
    impact: string;
    scenarioIds: string[];
  }>;
  longTerm: Array<{
    action: string;
    priority: 'low' | 'medium';
    estimatedTime: string;
    impact: string;
    scenarioIds: string[];
  }>;
  timeline: {
    phase1Duration: string;
    phase2Duration: string;
    phase3Duration: string;
    totalDuration: string;
  };
  [key: string]: unknown;
}

export interface SystemOverview {
  overallHealth: 'healthy' | 'warning' | 'critical' | 'unknown';
  totalScenarios: number;
  activeScenarios: number;
  totalIssuesFound: number;
  criticalIssuesFound: number;
  averagePerformanceScore: number;
  averageSecurityScore: number;
  systemLoadIndicators: {
    highVolumeScenarios: number;
    errorProneScenarios: number;
    slowPerformingScenarios: number;
  };
}

export interface CostAnalysisReport {
  estimatedMonthlyCost: number;
  costOptimizationPotential: number;
  costBreakdown: {
    highCostScenarios: Array<{
      scenarioId: string;
      scenarioName: string;
      estimatedMonthlyCost: number;
      optimizationPotential: number;
    }>;
  };
  recommendations: Array<{
    type: 'performance' | 'resource' | 'usage';
    description: string;
    estimatedSavings: number;
    implementationEffort: 'low' | 'medium' | 'high';
  }>;
}

export interface _TroubleshootingReportFormatted {
  metadata: {
    reportId: string;
    generatedAt: string;
    analysisScope: {
      scenarioCount: number;
      timeRangeHours: number;
      organizationId?: string;
    };
    executionTime: number;
  };
  executiveSummary: {
    overallAssessment: string;
    keyFindings: string[];
    criticalRecommendations: string[];
    businessImpact: {
      riskLevel: 'low' | 'medium' | 'high' | 'critical';
      estimatedDowntimeRisk: number;
      costImpact: number;
    };
  };
  systemOverview: SystemOverview;
  scenarioAnalysis: Array<{
    scenarioId: string;
    scenarioName: string;
    overallHealth: 'healthy' | 'warning' | 'critical' | 'unknown';
    healthScore: number;
    keyIssues: Array<{
      category: string;
      severity: string;
      title: string;
      impact: string;
    }>;
    performanceMetrics: {
      responseTime: number;
      errorRate: number;
      successRate: number;
      executionCount: number;
    };
  }>;
  consolidatedFindings: ConsolidatedFindings;
  actionPlan: ActionPlan;
  performanceMetrics: {
    systemWide: {
      averageResponseTime: number;
      overallErrorRate: number;
      overallSuccessRate: number;
      totalExecutions: number;
    };
    trends: {
      performanceDirection: 'improving' | 'stable' | 'degrading';
      errorTrend: 'improving' | 'stable' | 'degrading';
    };
  };
  securityAssessment: {
    overallSecurityScore: number;
    securityIssuesFound: number;
    criticalSecurityIssues: number;
    recommendations: string[];
    complianceStatus: {
      dataPrivacy: 'compliant' | 'needs_attention' | 'non_compliant';
      accessControl: 'compliant' | 'needs_attention' | 'non_compliant';
      secretsManagement: 'compliant' | 'needs_attention' | 'non_compliant';
    };
  };
  costAnalysis?: CostAnalysisReport;
  appendices: {
    detailedDiagnostics: any[]; // TroubleshootingReport from diagnostics
    performanceData: PerformanceAnalysisResult[];
    rawMetrics: unknown[];
    executionLogs: string[];
  };
}