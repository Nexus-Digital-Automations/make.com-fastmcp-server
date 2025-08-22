/**
 * AI Governance Engine Zod Schemas
 * Extracted from ai-governance-engine.ts for better maintainability
 * Generated on 2025-08-22T09:54:20.000Z
 */

import { z } from 'zod';

// ==================== ZOD SCHEMAS ====================

export const ComplianceMonitoringSchema = z.object({
  frameworks: z.array(z.string()).default(['SOC2', 'GDPR', 'HIPAA']),
  monitoringInterval: z.number().min(1).max(3600).default(300),
  realTimeAlerts: z.boolean().default(true),
  automatedRemediation: z.boolean().default(true),
  riskThreshold: z.number().min(0).max(100).default(70),
  includePredictiive: z.boolean().default(true),
  organizationId: z.string().optional(),
  teamId: z.string().optional(),
});

export const PolicyConflictAnalysisSchema = z.object({
  policyScope: z.enum(['organization', 'team', 'user', 'global']).default('organization'),
  conflictTypes: z.array(z.enum(['contradictory', 'overlapping', 'redundant', 'gap'])).default(['contradictory', 'overlapping']),
  analysisDepth: z.enum(['basic', 'comprehensive', 'deep']).default('comprehensive'),
  includeResolutions: z.boolean().default(true),
  automatedResolution: z.boolean().default(false),
  organizationId: z.string().optional(),
  teamId: z.string().optional(),
});

export const RiskAssessmentSchema = z.object({
  assessmentType: z.enum(['security', 'compliance', 'operational', 'financial', 'comprehensive']).default('comprehensive'),
  timeframe: z.enum(['24h', '7d', '30d', '90d', '1y']).default('30d'),
  mlPrediction: z.boolean().default(true),
  includeQuantification: z.boolean().default(true),
  riskCategories: z.array(z.string()).default(['security', 'compliance', 'operational']),
  organizationId: z.string().optional(),
  teamId: z.string().optional(),
});

export const AutomatedRemediationSchema = z.object({
  triggerConditions: z.array(z.string()),
  severity: z.enum(['low', 'medium', 'high', 'critical']).default('medium'),
  automationLevel: z.enum(['manual', 'semi-automated', 'fully-automated']).default('semi-automated'),
  approvalRequired: z.boolean().default(true),
  escalationEnabled: z.boolean().default(true),
  dryRun: z.boolean().default(true),
  organizationId: z.string().optional(),
  teamId: z.string().optional(),
});

export const GovernanceInsightsSchema = z.object({
  timeframe: z.enum(['24h', '7d', '30d', '90d', '1y']).default('30d'),
  insightTypes: z.array(z.enum(['trend', 'anomaly', 'prediction', 'recommendation'])).default(['trend', 'prediction', 'recommendation']),
  mlAnalysis: z.boolean().default(true),
  confidenceThreshold: z.number().min(0).max(100).default(70),
  includeActionable: z.boolean().default(true),
  organizationId: z.string().optional(),
  teamId: z.string().optional(),
});

export const GovernanceDashboardSchema = z.object({
  dashboardType: z.enum(['executive', 'operational', 'technical', 'comprehensive']).default('comprehensive'),
  refreshInterval: z.number().min(60).max(3600).default(300),
  includeRealTime: z.boolean().default(true),
  metricsLevel: z.enum(['summary', 'detailed', 'granular']).default('detailed'),
  includeForecasting: z.boolean().default(true),
  organizationId: z.string().optional(),
  teamId: z.string().optional(),
});

export const PolicyOptimizationSchema = z.object({
  optimizationType: z.enum(['efficiency', 'coverage', 'compliance', 'cost', 'comprehensive']).default('comprehensive'),
  mlOptimization: z.boolean().default(true),
  simulationMode: z.boolean().default(true),
  includeImpactAnalysis: z.boolean().default(true),
  optimizationGoals: z.array(z.string()).default(['reduce_conflicts', 'improve_coverage', 'enhance_automation']),
  organizationId: z.string().optional(),
  teamId: z.string().optional(),
});

export type ComplianceMonitoringRequest = z.infer<typeof ComplianceMonitoringSchema>;
export type PolicyConflictAnalysisRequest = z.infer<typeof PolicyConflictAnalysisSchema>;
export type RiskAssessmentRequest = z.infer<typeof RiskAssessmentSchema>;
export type AutomatedRemediationRequest = z.infer<typeof AutomatedRemediationSchema>;
export type GovernanceInsightsRequest = z.infer<typeof GovernanceInsightsSchema>;
export type GovernanceDashboardRequest = z.infer<typeof GovernanceDashboardSchema>;
export type PolicyOptimizationRequest = z.infer<typeof PolicyOptimizationSchema>;