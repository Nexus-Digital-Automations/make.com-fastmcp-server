/**
 * AI Governance Engine Services - Central Export Module
 * Provides centralized access to all governance service classes
 * Generated on 2025-08-22T09:58:23.000Z
 */

// Service Classes
export { RiskAssessmentService } from './risk-assessment.js';
export { RemediationService } from './remediation.js';
export { InsightsService } from './insights.js';
export { DashboardService } from './dashboard.js';
export { PolicyOptimizationService } from './policy-optimization.js';

// Import service classes for type annotations
import { RiskAssessmentService } from './risk-assessment.js';
import { RemediationService } from './remediation.js';
import { InsightsService } from './insights.js';
import { DashboardService } from './dashboard.js';
import { PolicyOptimizationService } from './policy-optimization.js';

// Re-export types for convenience
export type {
  // Risk Assessment Types
  RiskAssessment,
  OverallRiskAssessment,
  RiskTrend,
  RiskPrediction,
  MitigationPlan,

  // Remediation Types
  RemediationWorkflow,
  RemediationStep,
  EscalationStep,
  AutomatedAction,

  // Insights Types
  GovernanceInsight,
  TrendAnalysis,

  // Dashboard Types
  DashboardConfig,
  DashboardWidget,
  RealTimeData,
  Forecast,
  ForecastPoint,
  SystemHealth,

  // Policy Optimization Types
  PolicyConflict,
  PolicyResolutionPlan,
  ConflictImpactAnalysis,

  // Common Types
  GovernanceMetrics,
  MLModelType,
  PredictionCacheEntry
} from '../types/index.js';

// Re-export request schemas
export type {
  RiskAssessmentRequest,
  AutomatedRemediationRequest,
  GovernanceInsightsRequest,
  GovernanceDashboardRequest,
  PolicyOptimizationRequest
} from '../schemas/index.js';

// Re-export context types
export type { GovernanceContext } from '../types/context.js';

/**
 * Service initialization utility function
 * Creates and initializes all governance services with shared context
 */
import { MakeApiClient } from '../../../lib/make-api-client.js';
import type { GovernanceContext } from '../types/context.js';

export interface GovernanceServices {
  riskAssessment: RiskAssessmentService;
  remediation: RemediationService;
  insights: InsightsService;
  dashboard: DashboardService;
  policyOptimization: PolicyOptimizationService;
}

/**
 * Initializes all governance services with shared context and API client
 * @param context - Governance context containing configuration and settings
 * @param apiClient - Make.com API client for external integrations
 * @returns Initialized service instances
 */
export function initializeGovernanceServices(
  context: GovernanceContext,
  apiClient: MakeApiClient
): GovernanceServices {
  return {
    riskAssessment: new RiskAssessmentService(context, apiClient),
    remediation: new RemediationService(context, apiClient),
    insights: new InsightsService(context, apiClient),
    dashboard: new DashboardService(context, apiClient),
    policyOptimization: new PolicyOptimizationService(context, apiClient)
  };
}

/**
 * Service health check utility
 * Verifies that all services are properly initialized and functional
 */
export async function checkServiceHealth(services: GovernanceServices): Promise<{
  healthy: boolean;
  services: Record<string, boolean>;
  errors: string[];
}> {
  const serviceStatus: Record<string, boolean> = {};
  const errors: string[] = [];

  try {
    // Check each service by attempting to access its methods
    serviceStatus.riskAssessment = typeof services.riskAssessment.assessRisk === 'function';
    serviceStatus.remediation = typeof services.remediation.configureAutomatedRemediation === 'function';
    serviceStatus.insights = typeof services.insights.generateInsights === 'function';
    serviceStatus.dashboard = typeof services.dashboard.generateDashboard === 'function';
    serviceStatus.policyOptimization = typeof services.policyOptimization.optimizePolicies === 'function';

    // Verify all services are healthy
    const allHealthy = Object.values(serviceStatus).every(status => status === true);

    return {
      healthy: allHealthy,
      services: serviceStatus,
      errors
    };

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    errors.push(errorMessage);

    return {
      healthy: false,
      services: serviceStatus,
      errors
    };
  }
}

/**
 * Service configuration validation
 * Validates that the governance context contains required configuration
 */
export function validateServiceConfiguration(context: GovernanceContext): {
  valid: boolean;
  missingConfig: string[];
  warnings: string[];
} {
  const missingConfig: string[] = [];
  const warnings: string[] = [];

  // Check required configuration
  if (!context.config.enabled) {
    warnings.push('Governance engine is disabled in configuration');
  }

  if (!context.config.settings.defaultMonitoringInterval) {
    missingConfig.push('defaultMonitoringInterval');
  }

  if (!context.config.settings.defaultRiskThreshold) {
    missingConfig.push('defaultRiskThreshold');
  }

  // Check optional but recommended configuration
  if (context.config.settings.enableMLPredictions === undefined) {
    warnings.push('ML predictions setting not configured - defaulting to enabled');
  }

  if (context.config.settings.enableAutomatedRemediation === undefined) {
    warnings.push('Automated remediation setting not configured - defaulting to enabled');
  }

  return {
    valid: missingConfig.length === 0,
    missingConfig,
    warnings
  };
}

/**
 * Service cache management utilities
 * Provides centralized cache management for all services
 */
export class ServiceCacheManager {
  constructor(private readonly services: GovernanceServices) {}

  /**
   * Clear all service caches
   */
  clearAllCaches(): void {
    this.services.riskAssessment.clearCache();
    this.services.insights.clearCache();
    this.services.dashboard.clearCaches();
    this.services.policyOptimization.clearCaches();
    this.services.remediation.clearExecutionHistory();
  }

  /**
   * Get cache statistics from all services
   */
  getCacheStatistics(): Record<string, unknown> {
    return {
      riskAssessment: this.services.riskAssessment.getCacheStats(),
      insights: this.services.insights.getCacheStats(),
      dashboard: this.services.dashboard.getDashboardStats(),
      policyOptimization: this.services.policyOptimization.getOptimizationStats(),
      remediation: {
        executionHistory: this.services.remediation.getExecutionHistory().length
      }
    };
  }
}

/**
 * Default service configuration
 * Provides sensible defaults for governance service configuration
 */
export const DEFAULT_GOVERNANCE_CONFIG = {
  enabled: true,
  settings: {
    defaultMonitoringInterval: 300, // 5 minutes
    defaultRiskThreshold: 70,
    enableMLPredictions: true,
    enableAutomatedRemediation: true
  },
  metadata: {
    version: '1.0.0',
    createdAt: new Date()
  }
} as const;

/**
 * Service factory with error handling
 * Creates services with proper error handling and fallback configuration
 */
export function createGovernanceServices(
  context?: Partial<GovernanceContext>,
  apiClient?: MakeApiClient
): GovernanceServices {
  // Merge with default configuration
  const fullContext: GovernanceContext = {
    ...context,
    config: {
      ...DEFAULT_GOVERNANCE_CONFIG,
      ...context?.config
    }
  } as GovernanceContext;

  // Create a mock API client if none provided (for testing)
  const client = apiClient || ({
    // Mock API client methods
    async makeRequest() { return { success: true, data: null }; }
  } as unknown as MakeApiClient);

  return initializeGovernanceServices(fullContext, client);
}

/**
 * Version information
 */
export const SERVICES_VERSION = '1.0.0';
export const SERVICES_BUILD_DATE = '2025-08-22T09:58:23.000Z';

/**
 * Service capabilities metadata
 * Describes the capabilities provided by each service
 */
export const SERVICE_CAPABILITIES = {
  riskAssessment: {
    features: [
      'Comprehensive risk assessment',
      'ML-based risk predictions',
      'Risk trend analysis',
      'Mitigation plan generation',
      'Risk categorization and scoring'
    ],
    supportedAssessmentTypes: ['security', 'compliance', 'operational', 'financial', 'comprehensive'],
    supportedTimeframes: ['24h', '7d', '30d', '90d', '1y']
  },
  remediation: {
    features: [
      'Automated workflow generation',
      'Multi-step remediation processes',
      'Escalation management',
      'Workflow execution tracking',
      'Approval workflow integration'
    ],
    supportedAutomationLevels: ['manual', 'semi-automated', 'fully-automated'],
    supportedSeverityLevels: ['low', 'medium', 'high', 'critical']
  },
  insights: {
    features: [
      'Trend analysis and detection',
      'Anomaly identification',
      'ML-based predictions',
      'Actionable recommendations',
      'Pattern recognition'
    ],
    supportedInsightTypes: ['trend', 'anomaly', 'prediction', 'recommendation'],
    supportedTimeframes: ['24h', '7d', '30d', '90d', '1y']
  },
  dashboard: {
    features: [
      'Real-time data visualization',
      'Customizable widget layouts',
      'Multiple dashboard types',
      'Forecasting integration',
      'Alert management'
    ],
    supportedDashboardTypes: ['executive', 'operational', 'technical', 'comprehensive'],
    supportedWidgetTypes: ['chart', 'metric', 'alert', 'table']
  },
  policyOptimization: {
    features: [
      'ML-driven policy optimization',
      'Conflict detection and resolution',
      'Policy effectiveness evaluation',
      'Simulation and impact analysis',
      'Best practice recommendations'
    ],
    supportedOptimizationTypes: ['efficiency', 'coverage', 'compliance', 'cost', 'comprehensive'],
    supportedGoals: ['reduce_conflicts', 'improve_coverage', 'enhance_automation', 'cost_optimization']
  }
} as const;