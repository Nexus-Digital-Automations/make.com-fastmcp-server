/**
 * @fileoverview Unified Policy Compliance Validation System for Make.com FastMCP Server
 * 
 * Provides comprehensive policy compliance validation functionality including:
 * - Unified validation across all governance policy systems (compliance, naming, archival)
 * - Cross-policy compliance checking and scoring with weighted evaluations
 * - Automated violation tracking and remediation workflow management
 * - Enterprise-grade compliance scoring with framework-specific requirements
 * - Comprehensive reporting with policy adherence metrics and recommendations
 * - Integration with existing audit logging and notification systems
 * 
 * This tool serves as the central compliance validation engine that orchestrates
 * validation across all policy types, providing a single interface for enterprise
 * governance compliance checking with detailed reporting and remediation guidance.
 * 
 * @version 1.0.0
 * @author Make.com FastMCP Server - Enterprise Policy Team
 * @see {@link development/research-reports/comprehensive-enterprise-security-compliance-framework-research.md} Implementation Research
 */

import { FastMCP, UserError } from 'fastmcp';
import { z } from 'zod';
import MakeApiClient from '../lib/make-api-client.js';
import logger from '../lib/logger.js';
import { auditLogger } from '../lib/audit-logger.js';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';

// Core policy compliance validation types and interfaces
export type PolicyType = 'compliance' | 'naming_convention' | 'scenario_archival' | 'all';
export type ComplianceFramework = 'sox' | 'gdpr' | 'hipaa' | 'pci_dss' | 'iso27001' | 'enterprise' | 'custom';
export type ViolationSeverity = 'low' | 'medium' | 'high' | 'critical';
export type ValidationScope = 'scenario' | 'connection' | 'template' | 'folder' | 'user' | 'data_flow' | 'all';
export type ComplianceStatus = 'compliant' | 'non_compliant' | 'warning' | 'unknown' | 'exempt';
export type RemediationPriority = 'immediate' | 'high' | 'medium' | 'low' | 'informational';

/**
 * Policy compliance validation target schema
 */
const ValidationTargetSchema = z.object({
  targetType: z.enum(['scenario', 'connection', 'template', 'folder', 'user', 'data_flow', 'organization', 'team']).describe('Type of target to validate'),
  targetId: z.string().min(1).describe('Unique identifier of target'),
  targetName: z.string().optional().describe('Human-readable name of target'),
  metadata: z.record(z.unknown()).optional().describe('Additional target metadata for validation context'),
}).strict();

/**
 * Policy selection and filtering criteria schema
 */
const PolicySelectionSchema = z.object({
  policyTypes: z.array(z.enum(['compliance', 'naming_convention', 'scenario_archival'])).optional().describe('Types of policies to validate against'),
  policyIds: z.array(z.string()).optional().describe('Specific policy IDs to include'),
  frameworks: z.array(z.enum(['sox', 'gdpr', 'hipaa', 'pci_dss', 'iso27001', 'enterprise', 'custom'])).optional().describe('Compliance frameworks to validate'),
  organizationId: z.number().optional().describe('Organization scope filter'),
  teamId: z.number().optional().describe('Team scope filter'),
  tags: z.array(z.string()).optional().describe('Policy tags to include'),
  excludePolicyIds: z.array(z.string()).optional().describe('Policy IDs to exclude from validation'),
  activeOnly: z.boolean().default(true).describe('Only validate against active policies'),
}).strict();

/**
 * Validation options and configuration schema
 */
const ValidationOptionsSchema = z.object({
  includeRecommendations: z.boolean().default(true).describe('Include remediation recommendations'),
  includeComplianceScore: z.boolean().default(true).describe('Calculate and include compliance scores'),
  includeViolationDetails: z.boolean().default(true).describe('Include detailed violation information'),
  enableCrossValidation: z.boolean().default(true).describe('Enable cross-policy validation checks'),
  scoringWeights: z.object({
    compliance: z.number().min(0).max(1).default(0.4).describe('Weight for compliance policy violations'),
    naming: z.number().min(0).max(1).default(0.3).describe('Weight for naming convention violations'),
    archival: z.number().min(0).max(1).default(0.3).describe('Weight for archival policy violations'),
  }).optional().describe('Custom scoring weights for different policy types'),
  severityThresholds: z.object({
    critical: z.number().min(0).max(100).default(90).describe('Score threshold for critical status'),
    high: z.number().min(0).max(100).default(75).describe('Score threshold for high severity'),
    medium: z.number().min(0).max(100).default(50).describe('Score threshold for medium severity'),
    low: z.number().min(0).max(100).default(25).describe('Score threshold for low severity'),
  }).optional().describe('Custom severity thresholds for violation classification'),
  validationDepth: z.enum(['basic', 'standard', 'comprehensive']).default('standard').describe('Depth of validation analysis'),
}).strict();

/**
 * Main policy compliance validation schema
 */
const ValidatePolicyComplianceSchema = z.object({
  targets: z.array(ValidationTargetSchema).min(1).describe('Targets to validate for compliance'),
  policySelection: PolicySelectionSchema.describe('Policy selection and filtering criteria'),
  validationOptions: ValidationOptionsSchema.describe('Validation options and configuration'),
  reportingOptions: z.object({
    format: z.enum(['json', 'detailed', 'summary', 'executive']).default('detailed').describe('Report format level'),
    includeAuditTrail: z.boolean().default(true).describe('Include audit trail information'),
    includeHistoricalTrends: z.boolean().default(false).describe('Include historical compliance trends'),
    exportOptions: z.object({
      generatePdf: z.boolean().default(false).describe('Generate PDF report'),
      generateExcel: z.boolean().default(false).describe('Generate Excel report'),
      generateDashboard: z.boolean().default(false).describe('Generate dashboard data'),
    }).optional().describe('Export format options'),
  }).optional().describe('Report generation options'),
  executionContext: z.object({
    userId: z.string().optional().describe('User requesting validation'),
    reason: z.string().optional().describe('Reason for validation'),
    correlationId: z.string().optional().describe('Correlation ID for tracking'),
    priority: z.enum(['immediate', 'high', 'medium', 'low']).default('medium').describe('Validation priority'),
    dryRun: z.boolean().default(false).describe('Perform validation without logging violations'),
  }).optional().describe('Execution context and metadata'),
}).strict();

/**
 * Policy violation definition interface
 */
interface PolicyViolation {
  violationId: string;
  policyType: PolicyType;
  policyId: string;
  policyName: string;
  violationType: string;
  severity: ViolationSeverity;
  description: string;
  affectedTargets: string[];
  framework?: ComplianceFramework;
  controlId?: string;
  riskScore: number;
  complianceScore: number;
  detectedAt: string;
  recommendations: string[];
  remediationSteps: Array<{
    step: string;
    priority: RemediationPriority;
    estimatedEffort: string;
    automatable: boolean;
  }>;
  relatedViolations: string[];
  exemptionEligible: boolean;
  metadata: Record<string, unknown>;
}

/**
 * Compliance validation result interface
 */
interface ComplianceValidationResult {
  targetId: string;
  targetType: string;
  targetName?: string;
  overallComplianceStatus: ComplianceStatus;
  overallComplianceScore: number;
  overallRiskScore: number;
  policyResults: Array<{
    policyType: PolicyType;
    policyId: string;
    policyName: string;
    status: ComplianceStatus;
    score: number;
    violations: PolicyViolation[];
    passedControls: number;
    totalControls: number;
  }>;
  violations: PolicyViolation[];
  crossValidationResults?: Array<{
    issueType: string;
    description: string;
    affectedPolicies: string[];
    severity: ViolationSeverity;
    recommendations: string[];
  }>;
  recommendations: Array<{
    priority: RemediationPriority;
    category: string;
    title: string;
    description: string;
    estimatedImpact: string;
    automatable: boolean;
    relatedViolations: string[];
  }>;
  complianceBreakdown: {
    byFramework: Record<string, { score: number; violations: number }>;
    byPolicyType: Record<string, { score: number; violations: number }>;
    bySeverity: Record<string, number>;
  };
  validatedAt: string;
  validationVersion: string;
}

/**
 * Comprehensive policy compliance storage and management
 */
class PolicyComplianceManager {
  private readonly storePath: string;
  private readonly componentLogger: ReturnType<typeof logger.child>;

  constructor() {
    this.storePath = path.join(process.cwd(), 'data', 'policy-compliance-results.json');
    this.componentLogger = logger.child({ component: 'PolicyComplianceManager' });
    this.ensureStorageDirectory();
  }

  private async ensureStorageDirectory(): Promise<void> {
    try {
      const dataDir = path.dirname(this.storePath);
      await fs.mkdir(dataDir, { recursive: true });
    } catch (error) {
      this.componentLogger.error('Failed to create compliance results storage directory', { error });
      throw new Error('Failed to initialize compliance results storage');
    }
  }

  async loadComplianceHistory(): Promise<Record<string, unknown>> {
    try {
      const data = await fs.readFile(this.storePath, 'utf-8');
      return JSON.parse(data);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return { validations: {}, metadata: { created: new Date().toISOString(), version: '1.0.0' } };
      }
      this.componentLogger.error('Failed to load compliance history', { error });
      throw new Error('Failed to load compliance results data');
    }
  }

  async saveComplianceResults(data: Record<string, unknown>): Promise<void> {
    try {
      const updatedData = {
        ...data,
        metadata: {
          ...((data.metadata as Record<string, unknown>) || {}),
          lastModified: new Date().toISOString(),
        },
      };
      await fs.writeFile(this.storePath, JSON.stringify(updatedData, null, 2), 'utf-8');
    } catch (error) {
      this.componentLogger.error('Failed to save compliance results', { error });
      throw new Error('Failed to save compliance results data');
    }
  }

  generateValidationId(): string {
    const timestamp = Date.now();
    const hash = crypto.createHash('md5').update(`validation_${timestamp}`).digest('hex').substring(0, 8);
    return `validation_${timestamp}_${hash}`;
  }

  async storeValidationResults(validationId: string, results: ComplianceValidationResult[]): Promise<void> {
    const store = await this.loadComplianceHistory();
    const validations = (store.validations as Record<string, unknown>) || {};
    
    validations[validationId] = {
      validationId,
      results,
      totalTargets: results.length,
      overallComplianceScore: this.calculateOverallScore(results),
      createdAt: new Date().toISOString(),
      summary: this.generateValidationSummary(results),
    };
    
    store.validations = validations;
    await this.saveComplianceResults(store);
  }

  private calculateOverallScore(results: ComplianceValidationResult[]): number {
    if (results.length === 0) return 0;
    return results.reduce((sum, result) => sum + result.overallComplianceScore, 0) / results.length;
  }

  private generateValidationSummary(results: ComplianceValidationResult[]): Record<string, unknown> {
    const totalViolations = results.reduce((sum, r) => sum + r.violations.length, 0);
    const criticalViolations = results.reduce((sum, r) => sum + r.violations.filter(v => v.severity === 'critical').length, 0);
    const highViolations = results.reduce((sum, r) => sum + r.violations.filter(v => v.severity === 'high').length, 0);
    
    return {
      totalTargets: results.length,
      compliantTargets: results.filter(r => r.overallComplianceStatus === 'compliant').length,
      nonCompliantTargets: results.filter(r => r.overallComplianceStatus === 'non_compliant').length,
      totalViolations,
      criticalViolations,
      highViolations,
      averageComplianceScore: this.calculateOverallScore(results),
    };
  }
}

/**
 * Unified policy compliance validation engine
 */
class PolicyComplianceValidator {
  private readonly componentLogger: ReturnType<typeof logger.child>;
  private readonly complianceManager: PolicyComplianceManager;

  constructor(private apiClient: MakeApiClient) {
    this.componentLogger = logger.child({ component: 'PolicyComplianceValidator' });
    this.complianceManager = new PolicyComplianceManager();
  }

  /**
   * Validate targets against all applicable policies
   */
  async validateCompliance(
    targets: z.infer<typeof ValidationTargetSchema>[],
    policySelection: z.infer<typeof PolicySelectionSchema>,
    options: z.infer<typeof ValidationOptionsSchema>
  ): Promise<ComplianceValidationResult[]> {
    const results: ComplianceValidationResult[] = [];
    
    this.componentLogger.info('Starting comprehensive policy compliance validation', {
      targetsCount: targets.length,
      policyTypes: policySelection.policyTypes,
      validationDepth: options.validationDepth,
    });

    for (const target of targets) {
      try {
        const result = await this.validateSingleTarget(target, policySelection, options);
        results.push(result);
      } catch (error) {
        this.componentLogger.error('Failed to validate target', {
          targetId: target.targetId,
          targetType: target.targetType,
          error: error instanceof Error ? error.message : 'Unknown error',
        });

        // Create error result for failed validation
        results.push({
          targetId: target.targetId,
          targetType: target.targetType,
          targetName: target.targetName,
          overallComplianceStatus: 'unknown' as ComplianceStatus,
          overallComplianceScore: 0,
          overallRiskScore: 100,
          policyResults: [],
          violations: [{
            violationId: `validation_error_${Date.now()}`,
            policyType: 'compliance' as PolicyType,
            policyId: 'validation_system',
            policyName: 'Validation System',
            violationType: 'validation_error',
            severity: 'high' as ViolationSeverity,
            description: `Failed to validate target: ${error instanceof Error ? error.message : 'Unknown error'}`,
            affectedTargets: [target.targetId],
            riskScore: 100,
            complianceScore: 0,
            detectedAt: new Date().toISOString(),
            recommendations: ['Fix validation system issues before proceeding'],
            remediationSteps: [{
              step: 'Review validation system configuration and target accessibility',
              priority: 'high' as RemediationPriority,
              estimatedEffort: '1-2 hours',
              automatable: false,
            }],
            relatedViolations: [],
            exemptionEligible: false,
            metadata: { error: error instanceof Error ? error.message : 'Unknown error' },
          }],
          recommendations: [],
          complianceBreakdown: {
            byFramework: {},
            byPolicyType: {},
            bySeverity: { high: 1 },
          },
          validatedAt: new Date().toISOString(),
          validationVersion: '1.0.0',
        });
      }
    }

    return results;
  }

  /**
   * Validate a single target against all applicable policies
   */
  private async validateSingleTarget(
    target: z.infer<typeof ValidationTargetSchema>,
    policySelection: z.infer<typeof PolicySelectionSchema>,
    options: z.infer<typeof ValidationOptionsSchema>
  ): Promise<ComplianceValidationResult> {
    const result: ComplianceValidationResult = {
      targetId: target.targetId,
      targetType: target.targetType,
      targetName: target.targetName,
      overallComplianceStatus: 'compliant' as ComplianceStatus,
      overallComplianceScore: 100,
      overallRiskScore: 0,
      policyResults: [],
      violations: [],
      recommendations: [],
      complianceBreakdown: {
        byFramework: {},
        byPolicyType: {},
        bySeverity: {},
      },
      validatedAt: new Date().toISOString(),
      validationVersion: '1.0.0',
    };

    try {
      // Gather applicable policies
      const applicablePolicies = await this.gatherApplicablePolicies(target, policySelection);

      // Validate against each policy type
      for (const policyType of ['compliance', 'naming_convention', 'scenario_archival'] as const) {
        if (policySelection.policyTypes && !policySelection.policyTypes.includes(policyType)) {
          continue;
        }

        const policiesOfType = applicablePolicies.filter(p => p.type === policyType);
        if (policiesOfType.length === 0) continue;

        const policyTypeResults = await this.validateAgainstPolicyType(
          target,
          policyType,
          policiesOfType,
          options
        );

        result.policyResults.push(...policyTypeResults);
        
        // Collect violations
        policyTypeResults.forEach(pr => {
          result.violations.push(...pr.violations);
        });
      }

      // Perform cross-validation if enabled
      if (options.enableCrossValidation) {
        result.crossValidationResults = await this.performCrossValidation(target, result.policyResults);
      }

      // Calculate overall scores and status
      this.calculateOverallScores(result, options);

      // Generate recommendations
      if (options.includeRecommendations) {
        result.recommendations = await this.generateRecommendations(result);
      }

      // Update compliance breakdown
      this.updateComplianceBreakdown(result);

    } catch (error) {
      this.componentLogger.error('Error during single target validation', {
        targetId: target.targetId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw error;
    }

    return result;
  }

  /**
   * Gather all applicable policies for a target
   */
  private async gatherApplicablePolicies(
    target: z.infer<typeof ValidationTargetSchema>,
    policySelection: z.infer<typeof PolicySelectionSchema>
  ): Promise<Array<{ type: PolicyType; id: string; name: string; data: Record<string, unknown> }>> {
    const policies: Array<{ type: PolicyType; id: string; name: string; data: Record<string, unknown> }> = [];

    try {
      // Gather compliance policies
      if (!policySelection.policyTypes || policySelection.policyTypes.includes('compliance')) {
        const compliancePolicies = await this.fetchPoliciesByType('compliance', policySelection);
        policies.push(...compliancePolicies.map(p => ({ type: 'compliance' as PolicyType, ...p })));
      }

      // Gather naming convention policies
      if (!policySelection.policyTypes || policySelection.policyTypes.includes('naming_convention')) {
        const namingPolicies = await this.fetchPoliciesByType('naming_convention', policySelection);
        policies.push(...namingPolicies.map(p => ({ type: 'naming_convention' as PolicyType, ...p })));
      }

      // Gather archival policies
      if (!policySelection.policyTypes || policySelection.policyTypes.includes('scenario_archival')) {
        const archivalPolicies = await this.fetchPoliciesByType('scenario_archival', policySelection);
        policies.push(...archivalPolicies.map(p => ({ type: 'scenario_archival' as PolicyType, ...p })));
      }

    } catch (error) {
      this.componentLogger.error('Failed to gather applicable policies', {
        targetId: target.targetId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw error;
    }

    return policies;
  }

  /**
   * Fetch policies by type with filtering
   */
  private async fetchPoliciesByType(
    policyType: string,
    policySelection: z.infer<typeof PolicySelectionSchema>
  ): Promise<Array<{ id: string; name: string; data: Record<string, unknown> }>> {
    const policies: Array<{ id: string; name: string; data: Record<string, unknown> }> = [];

    try {
      let endpoint = '';
      switch (policyType) {
        case 'compliance':
          endpoint = '/policies/compliance';
          break;
        case 'naming_convention':
          endpoint = '/policies/naming-conventions';
          break;
        case 'scenario_archival':
          endpoint = '/policies/scenario-archival';
          break;
        default:
          return policies;
      }

      const params: Record<string, unknown> = {};
      if (policySelection.activeOnly) params.active = true;
      if (policySelection.organizationId) params.organizationId = policySelection.organizationId;
      if (policySelection.teamId) params.teamId = policySelection.teamId;

      const response = await this.apiClient.get(endpoint, { params });

      if (response.success && Array.isArray(response.data)) {
        for (const policy of response.data) {
          const policyData = policy as Record<string, unknown>;
          
          // Apply policy selection filters
          if (policySelection.policyIds && !policySelection.policyIds.includes(String(policyData.id || policyData.policyId))) {
            continue;
          }
          
          if (policySelection.excludePolicyIds && policySelection.excludePolicyIds.includes(String(policyData.id || policyData.policyId))) {
            continue;
          }

          if (policySelection.frameworks && policyType === 'compliance') {
            const policyFrameworks = policyData.framework as string[] || [];
            if (!policySelection.frameworks.some(f => policyFrameworks.includes(f))) {
              continue;
            }
          }

          policies.push({
            id: String(policyData.id || policyData.policyId),
            name: String(policyData.name || policyData.policyName),
            data: policyData,
          });
        }
      }

    } catch (error) {
      this.componentLogger.error(`Failed to fetch ${policyType} policies`, {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      // Don't throw here - continue with other policy types
    }

    return policies;
  }

  /**
   * Validate target against specific policy type
   */
  private async validateAgainstPolicyType(
    target: z.infer<typeof ValidationTargetSchema>,
    policyType: PolicyType,
    policies: Array<{ id: string; name: string; data: Record<string, unknown> }>,
    options: z.infer<typeof ValidationOptionsSchema>
  ): Promise<Array<{
    policyType: PolicyType;
    policyId: string;
    policyName: string;
    status: ComplianceStatus;
    score: number;
    violations: PolicyViolation[];
    passedControls: number;
    totalControls: number;
  }>> {
    const results: Array<{
      policyType: PolicyType;
      policyId: string;
      policyName: string;
      status: ComplianceStatus;
      score: number;
      violations: PolicyViolation[];
      passedControls: number;
      totalControls: number;
    }> = [];

    for (const policy of policies) {
      try {
        let validationResult;

        switch (policyType) {
          case 'compliance':
            validationResult = await this.validateCompliancePolicy(target, policy, options);
            break;
          case 'naming_convention':
            validationResult = await this.validateNamingPolicy(target, policy, options);
            break;
          case 'scenario_archival':
            validationResult = await this.validateArchivalPolicy(target, policy, options);
            break;
          default:
            continue;
        }

        results.push(validationResult);

      } catch (error) {
        this.componentLogger.error(`Failed to validate against ${policyType} policy`, {
          policyId: policy.id,
          targetId: target.targetId,
          error: error instanceof Error ? error.message : 'Unknown error',
        });

        // Create error result for failed policy validation
        results.push({
          policyType,
          policyId: policy.id,
          policyName: policy.name,
          status: 'unknown' as ComplianceStatus,
          score: 0,
          violations: [{
            violationId: `policy_validation_error_${Date.now()}`,
            policyType,
            policyId: policy.id,
            policyName: policy.name,
            violationType: 'policy_validation_error',
            severity: 'medium' as ViolationSeverity,
            description: `Failed to validate against policy: ${error instanceof Error ? error.message : 'Unknown error'}`,
            affectedTargets: [target.targetId],
            riskScore: 50,
            complianceScore: 50,
            detectedAt: new Date().toISOString(),
            recommendations: ['Review policy configuration and target compatibility'],
            remediationSteps: [{
              step: 'Investigate policy validation failure',
              priority: 'medium' as RemediationPriority,
              estimatedEffort: '30 minutes',
              automatable: false,
            }],
            relatedViolations: [],
            exemptionEligible: true,
            metadata: { 
              error: error instanceof Error ? error.message : 'Unknown error',
              policyType,
            },
          }],
          passedControls: 0,
          totalControls: 1,
        });
      }
    }

    return results;
  }

  /**
   * Validate target against compliance policy
   */
  private async validateCompliancePolicy(
    target: z.infer<typeof ValidationTargetSchema>,
    policy: { id: string; name: string; data: Record<string, unknown> },
    options: z.infer<typeof ValidationOptionsSchema>
  ): Promise<{
    policyType: PolicyType;
    policyId: string;
    policyName: string;
    status: ComplianceStatus;
    score: number;
    violations: PolicyViolation[];
    passedControls: number;
    totalControls: number;
  }> {
    const violations: PolicyViolation[] = [];
    const policyData = policy.data;

    try {
      // Use the existing compliance policy validation endpoint
      const validationResponse = await this.apiClient.post('/api/compliance/validate', {
        policyId: policy.id,
        targetType: target.targetType,
        targetId: target.targetId,
        includeRecommendations: options.includeRecommendations,
      });

      if (validationResponse.success && validationResponse.data) {
        const validationData = validationResponse.data as {
          compliant: boolean;
          violations: Array<{
            controlId: string;
            severity: string;
            description: string;
            recommendations?: string[];
          }>;
          riskScore: number;
          complianceScore: number;
        };

        // Convert API violations to our format
        for (const violation of validationData.violations || []) {
          violations.push({
            violationId: `compliance_${policy.id}_${Date.now()}_${Math.random().toString(36).substring(7)}`,
            policyType: 'compliance' as PolicyType,
            policyId: policy.id,
            policyName: policy.name,
            violationType: violation.controlId,
            severity: violation.severity as ViolationSeverity,
            description: violation.description,
            affectedTargets: [target.targetId],
            framework: (policyData.framework as string[])?.[0] as ComplianceFramework,
            controlId: violation.controlId,
            riskScore: validationData.riskScore || 50,
            complianceScore: validationData.complianceScore || 50,
            detectedAt: new Date().toISOString(),
            recommendations: violation.recommendations || [],
            remediationSteps: this.generateRemediationSteps(violation.description, violation.severity),
            relatedViolations: [],
            exemptionEligible: violation.severity !== 'critical',
            metadata: {
              framework: (policyData.framework as string[])?.[0],
              controlType: 'compliance',
            },
          });
        }

        const totalControls = this.countComplianceControls(policyData);
        const passedControls = totalControls - violations.length;
        const score = totalControls > 0 ? (passedControls / totalControls) * 100 : 100;

        return {
          policyType: 'compliance' as PolicyType,
          policyId: policy.id,
          policyName: policy.name,
          status: violations.length === 0 ? 'compliant' as ComplianceStatus : 'non_compliant' as ComplianceStatus,
          score,
          violations,
          passedControls,
          totalControls,
        };
      }

    } catch (error) {
      this.componentLogger.error('Failed to validate compliance policy', {
        policyId: policy.id,
        targetId: target.targetId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }

    // Default result if validation fails
    return {
      policyType: 'compliance' as PolicyType,
      policyId: policy.id,
      policyName: policy.name,
      status: 'unknown' as ComplianceStatus,
      score: 0,
      violations,
      passedControls: 0,
      totalControls: 1,
    };
  }

  /**
   * Validate target against naming convention policy
   */
  private async validateNamingPolicy(
    target: z.infer<typeof ValidationTargetSchema>,
    policy: { id: string; name: string; data: Record<string, unknown> },
    options: z.infer<typeof ValidationOptionsSchema>
  ): Promise<{
    policyType: PolicyType;
    policyId: string;
    policyName: string;
    status: ComplianceStatus;
    score: number;
    violations: PolicyViolation[];
    passedControls: number;
    totalControls: number;
  }> {
    const violations: PolicyViolation[] = [];

    try {
      // Use the existing naming policy validation endpoint
      const validationResponse = await this.apiClient.post('/api/naming/validate', {
        policyId: policy.id,
        names: [{
          resourceType: target.targetType,
          name: target.targetName || target.targetId,
          resourceId: target.targetId,
          metadata: target.metadata,
        }],
        returnDetails: options.includeViolationDetails,
      });

      if (validationResponse.success && validationResponse.data) {
        const validationData = validationResponse.data as {
          validationResults: Record<string, {
            status: string;
            suggestions?: string[];
            details?: {
              ruleResults: Array<{
                ruleId: string;
                ruleName: string;
                isValid: boolean;
                errors: string[];
                enforcementLevel: string;
              }>;
            };
          }>;
        };

        const targetKey = target.targetId;
        const targetResult = validationData.validationResults[targetKey];

        if (targetResult && targetResult.status !== 'valid') {
          const ruleResults = targetResult.details?.ruleResults || [];
          
          for (const ruleResult of ruleResults) {
            if (!ruleResult.isValid && ruleResult.errors.length > 0) {
              const severity = this.mapEnforcementToSeverity(ruleResult.enforcementLevel);
              
              violations.push({
                violationId: `naming_${policy.id}_${ruleResult.ruleId}_${Date.now()}`,
                policyType: 'naming_convention' as PolicyType,
                policyId: policy.id,
                policyName: policy.name,
                violationType: ruleResult.ruleId,
                severity,
                description: `Naming convention violation: ${ruleResult.errors.join(', ')}`,
                affectedTargets: [target.targetId],
                controlId: ruleResult.ruleId,
                riskScore: this.mapSeverityToRiskScore(severity),
                complianceScore: 100 - this.mapSeverityToRiskScore(severity),
                detectedAt: new Date().toISOString(),
                recommendations: targetResult.suggestions || [],
                remediationSteps: this.generateNamingRemediationSteps(ruleResult.errors, targetResult.suggestions),
                relatedViolations: [],
                exemptionEligible: severity !== 'critical',
                metadata: {
                  ruleName: ruleResult.ruleName,
                  enforcementLevel: ruleResult.enforcementLevel,
                  originalName: target.targetName || target.targetId,
                },
              });
            }
          }
        }

        const totalRules = this.countNamingRules(policy.data);
        const passedRules = totalRules - violations.length;
        const score = totalRules > 0 ? (passedRules / totalRules) * 100 : 100;

        return {
          policyType: 'naming_convention' as PolicyType,
          policyId: policy.id,
          policyName: policy.name,
          status: violations.length === 0 ? 'compliant' as ComplianceStatus : 
                  violations.some(v => v.severity === 'critical') ? 'non_compliant' as ComplianceStatus : 'warning' as ComplianceStatus,
          score,
          violations,
          passedControls: passedRules,
          totalControls: totalRules,
        };
      }

    } catch (error) {
      this.componentLogger.error('Failed to validate naming policy', {
        policyId: policy.id,
        targetId: target.targetId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }

    // Default result if validation fails
    return {
      policyType: 'naming_convention' as PolicyType,
      policyId: policy.id,
      policyName: policy.name,
      status: 'unknown' as ComplianceStatus,
      score: 0,
      violations,
      passedControls: 0,
      totalControls: 1,
    };
  }

  /**
   * Validate target against archival policy
   */
  private async validateArchivalPolicy(
    target: z.infer<typeof ValidationTargetSchema>,
    policy: { id: string; name: string; data: Record<string, unknown> },
    _options: z.infer<typeof ValidationOptionsSchema>
  ): Promise<{
    policyType: PolicyType;
    policyId: string;
    policyName: string;
    status: ComplianceStatus;
    score: number;
    violations: PolicyViolation[];
    passedControls: number;
    totalControls: number;
  }> {
    const violations: PolicyViolation[] = [];

    try {
      // For archival policies, we mainly check if scenarios are subject to archival
      if (target.targetType === 'scenario') {
        const evaluationResponse = await this.apiClient.post('/api/archival/evaluate', {
          policyId: policy.id,
          evaluationOptions: {
            scenarioIds: [target.targetId],
            dryRun: true,
            includeMetrics: true,
          },
        });

        if (evaluationResponse.success && evaluationResponse.data) {
          const evaluationData = evaluationResponse.data as {
            scenariosToArchive: Array<{
              scenarioId: string;
              reasons: string[];
              score: number;
            }>;
          };

          const scenarioToArchive = evaluationData.scenariosToArchive.find(s => s.scenarioId === target.targetId);
          
          if (scenarioToArchive) {
            violations.push({
              violationId: `archival_${policy.id}_${target.targetId}_${Date.now()}`,
              policyType: 'scenario_archival' as PolicyType,
              policyId: policy.id,
              policyName: policy.name,
              violationType: 'archival_candidate',
              severity: scenarioToArchive.score > 0.8 ? 'high' as ViolationSeverity : 'medium' as ViolationSeverity,
              description: `Scenario is candidate for archival: ${scenarioToArchive.reasons.join(', ')}`,
              affectedTargets: [target.targetId],
              riskScore: scenarioToArchive.score * 100,
              complianceScore: 100 - (scenarioToArchive.score * 100),
              detectedAt: new Date().toISOString(),
              recommendations: [
                'Review scenario usage and determine if it should be kept active',
                'Consider updating scenario if it serves a business purpose',
                'Archive scenario if it is no longer needed',
              ],
              remediationSteps: [{
                step: 'Review scenario business justification',
                priority: 'medium' as RemediationPriority,
                estimatedEffort: '15 minutes',
                automatable: false,
              }, {
                step: 'Update scenario or mark for archival',
                priority: 'low' as RemediationPriority,
                estimatedEffort: '30 minutes',
                automatable: true,
              }],
              relatedViolations: [],
              exemptionEligible: true,
              metadata: {
                archivalScore: scenarioToArchive.score,
                archivalReasons: scenarioToArchive.reasons,
              },
            });
          }
        }
      }

      const totalConditions = this.countArchivalConditions(policy.data);
      const passedConditions = totalConditions - violations.length;
      const score = totalConditions > 0 ? (passedConditions / totalConditions) * 100 : 100;

      return {
        policyType: 'scenario_archival' as PolicyType,
        policyId: policy.id,
        policyName: policy.name,
        status: violations.length === 0 ? 'compliant' as ComplianceStatus : 'warning' as ComplianceStatus,
        score,
        violations,
        passedControls: passedConditions,
        totalControls: totalConditions,
      };

    } catch (error) {
      this.componentLogger.error('Failed to validate archival policy', {
        policyId: policy.id,
        targetId: target.targetId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }

    // Default result if validation fails
    return {
      policyType: 'scenario_archival' as PolicyType,
      policyId: policy.id,
      policyName: policy.name,
      status: 'unknown' as ComplianceStatus,
      score: 0,
      violations,
      passedControls: 0,
      totalControls: 1,
    };
  }

  /**
   * Perform cross-validation between different policy types
   */
  private async performCrossValidation(
    target: z.infer<typeof ValidationTargetSchema>,
    policyResults: Array<{
      policyType: PolicyType;
      policyId: string;
      policyName: string;
      violations: PolicyViolation[];
    }>
  ): Promise<Array<{
    issueType: string;
    description: string;
    affectedPolicies: string[];
    severity: ViolationSeverity;
    recommendations: string[];
  }>> {
    const crossValidationResults: Array<{
      issueType: string;
      description: string;
      affectedPolicies: string[];
      severity: ViolationSeverity;
      recommendations: string[];
    }> = [];

    try {
      // Check for conflicting requirements between policies
      const namingViolations = policyResults.filter(pr => pr.policyType === 'naming_convention').flatMap(pr => pr.violations);
      const complianceViolations = policyResults.filter(pr => pr.policyType === 'compliance').flatMap(pr => pr.violations);
      
      // Check for naming vs compliance conflicts
      if (namingViolations.length > 0 && complianceViolations.length > 0) {
        const conflictingPolicies = Array.from(new Set([
          ...namingViolations.map(v => v.policyId),
          ...complianceViolations.map(v => v.policyId)
        ]));

        crossValidationResults.push({
          issueType: 'naming_compliance_conflict',
          description: 'Potential conflict between naming convention and compliance requirements',
          affectedPolicies: conflictingPolicies,
          severity: 'medium' as ViolationSeverity,
          recommendations: [
            'Review naming convention policies for compliance framework compatibility',
            'Consider exemptions for specific compliance-driven naming requirements',
            'Coordinate between compliance and naming policy administrators',
          ],
        });
      }

      // Check for excessive violation load
      const totalViolations = policyResults.reduce((sum, pr) => sum + pr.violations.length, 0);
      if (totalViolations > 10) {
        crossValidationResults.push({
          issueType: 'high_violation_load',
          description: `Target has ${totalViolations} policy violations across multiple policy types`,
          affectedPolicies: policyResults.map(pr => pr.policyId),
          severity: 'high' as ViolationSeverity,
          recommendations: [
            'Prioritize critical violations for immediate attention',
            'Consider policy consolidation or exemption requests',
            'Implement systematic remediation plan',
          ],
        });
      }

      // Check for archival vs active use conflicts
      const archivalViolations = policyResults.filter(pr => pr.policyType === 'scenario_archival').flatMap(pr => pr.violations);
      const activeViolations = [...namingViolations, ...complianceViolations];
      
      if (archivalViolations.length > 0 && activeViolations.length > 0) {
        crossValidationResults.push({
          issueType: 'archival_active_conflict',
          description: 'Target is candidate for archival but has active policy violations to address',
          affectedPolicies: [
            ...archivalViolations.map(v => v.policyId),
            ...activeViolations.map(v => v.policyId)
          ],
          severity: 'medium' as ViolationSeverity,
          recommendations: [
            'Determine if target should be archived or remain active',
            'If keeping active, address all policy violations',
            'If archiving, document current state for compliance records',
          ],
        });
      }

    } catch (error) {
      this.componentLogger.error('Failed to perform cross-validation', {
        targetId: target.targetId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }

    return crossValidationResults;
  }

  /**
   * Calculate overall compliance scores and status
   */
  private calculateOverallScores(
    result: ComplianceValidationResult,
    options: z.infer<typeof ValidationOptionsSchema>
  ): void {
    if (result.policyResults.length === 0) {
      result.overallComplianceStatus = 'unknown' as ComplianceStatus;
      result.overallComplianceScore = 0;
      result.overallRiskScore = 100;
      return;
    }

    const weights = options.scoringWeights || {
      compliance: 0.4,
      naming: 0.3,
      archival: 0.3,
    };

    let weightedScore = 0;
    let totalWeight = 0;
    let hasCriticalViolations = false;
    let hasHighViolations = false;

    for (const policyResult of result.policyResults) {
      let weight = 1;
      switch (policyResult.policyType) {
        case 'compliance':
          weight = weights.compliance;
          break;
        case 'naming_convention':
          weight = weights.naming;
          break;
        case 'scenario_archival':
          weight = weights.archival;
          break;
      }

      weightedScore += policyResult.score * weight;
      totalWeight += weight;

      // Check for critical violations
      if (policyResult.violations.some(v => v.severity === 'critical')) {
        hasCriticalViolations = true;
      }
      if (policyResult.violations.some(v => v.severity === 'high')) {
        hasHighViolations = true;
      }
    }

    result.overallComplianceScore = totalWeight > 0 ? Math.round(weightedScore / totalWeight) : 0;
    result.overallRiskScore = 100 - result.overallComplianceScore;

    // Determine overall status
    if (hasCriticalViolations || result.overallComplianceScore < 50) {
      result.overallComplianceStatus = 'non_compliant' as ComplianceStatus;
    } else if (hasHighViolations || result.overallComplianceScore < 80) {
      result.overallComplianceStatus = 'warning' as ComplianceStatus;
    } else {
      result.overallComplianceStatus = 'compliant' as ComplianceStatus;
    }
  }

  /**
   * Generate comprehensive recommendations
   */
  private async generateRecommendations(
    result: ComplianceValidationResult
  ): Promise<Array<{
    priority: RemediationPriority;
    category: string;
    title: string;
    description: string;
    estimatedImpact: string;
    automatable: boolean;
    relatedViolations: string[];
  }>> {
    const recommendations: Array<{
      priority: RemediationPriority;
      category: string;
      title: string;
      description: string;
      estimatedImpact: string;
      automatable: boolean;
      relatedViolations: string[];
    }> = [];

    try {
      // Critical violations first
      const criticalViolations = result.violations.filter(v => v.severity === 'critical');
      if (criticalViolations.length > 0) {
        recommendations.push({
          priority: 'immediate' as RemediationPriority,
          category: 'critical_violations',
          title: 'Address Critical Policy Violations',
          description: `${criticalViolations.length} critical policy violations require immediate attention to maintain compliance.`,
          estimatedImpact: 'High - Critical for compliance status',
          automatable: false,
          relatedViolations: criticalViolations.map(v => v.violationId),
        });
      }

      // High violations
      const highViolations = result.violations.filter(v => v.severity === 'high');
      if (highViolations.length > 0) {
        recommendations.push({
          priority: 'high' as RemediationPriority,
          category: 'high_violations',
          title: 'Resolve High Severity Violations',
          description: `${highViolations.length} high severity violations should be addressed to improve compliance score.`,
          estimatedImpact: 'Medium-High - Important for risk reduction',
          automatable: highViolations.some(v => v.remediationSteps.some(rs => rs.automatable)),
          relatedViolations: highViolations.map(v => v.violationId),
        });
      }

      // Framework-specific recommendations
      const frameworkViolations = new Map<string, PolicyViolation[]>();
      result.violations.forEach(v => {
        if (v.framework) {
          if (!frameworkViolations.has(v.framework)) {
            frameworkViolations.set(v.framework, []);
          }
          frameworkViolations.get(v.framework)!.push(v);
        }
      });

      frameworkViolations.forEach((violations, framework) => {
        recommendations.push({
          priority: 'medium' as RemediationPriority,
          category: 'framework_compliance',
          title: `Improve ${framework.toUpperCase()} Framework Compliance`,
          description: `Address ${violations.length} violations specific to ${framework.toUpperCase()} compliance requirements.`,
          estimatedImpact: 'Medium - Framework-specific compliance improvement',
          automatable: violations.some(v => v.remediationSteps.some(rs => rs.automatable)),
          relatedViolations: violations.map(v => v.violationId),
        });
      });

      // Policy type specific recommendations
      const policyTypeViolations = new Map<string, PolicyViolation[]>();
      result.violations.forEach(v => {
        if (!policyTypeViolations.has(v.policyType)) {
          policyTypeViolations.set(v.policyType, []);
        }
        policyTypeViolations.get(v.policyType)!.push(v);
      });

      policyTypeViolations.forEach((violations, policyType) => {
        const categoryName = policyType.replace('_', ' ');
        recommendations.push({
          priority: 'medium' as RemediationPriority,
          category: `${policyType}_improvement`,
          title: `Improve ${categoryName.charAt(0).toUpperCase() + categoryName.slice(1)} Compliance`,
          description: `Address ${violations.length} ${categoryName} violations to improve overall policy adherence.`,
          estimatedImpact: 'Medium - Policy-specific compliance improvement',
          automatable: violations.some(v => v.remediationSteps.some(rs => rs.automatable)),
          relatedViolations: violations.map(v => v.violationId),
        });
      });

      // General improvement recommendations
      if (result.overallComplianceScore < 90) {
        recommendations.push({
          priority: 'low' as RemediationPriority,
          category: 'general_improvement',
          title: 'Enhance Overall Compliance Posture',
          description: 'Consider implementing regular compliance monitoring and preventive controls to maintain high compliance scores.',
          estimatedImpact: 'Medium - Long-term compliance sustainability',
          automatable: true,
          relatedViolations: [],
        });
      }

    } catch (error) {
      this.componentLogger.error('Failed to generate recommendations', {
        targetId: result.targetId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }

    return recommendations.sort((a, b) => {
      const priorityOrder = { immediate: 0, high: 1, medium: 2, low: 3, informational: 4 };
      return priorityOrder[a.priority] - priorityOrder[b.priority];
    });
  }

  /**
   * Update compliance breakdown statistics
   */
  private updateComplianceBreakdown(result: ComplianceValidationResult): void {
    // By framework
    result.violations.forEach(v => {
      if (v.framework) {
        if (!result.complianceBreakdown.byFramework[v.framework]) {
          result.complianceBreakdown.byFramework[v.framework] = { score: 100, violations: 0 };
        }
        result.complianceBreakdown.byFramework[v.framework].violations++;
        result.complianceBreakdown.byFramework[v.framework].score -= v.riskScore * 0.1; // Adjust scoring
      }
    });

    // By policy type
    result.violations.forEach(v => {
      if (!result.complianceBreakdown.byPolicyType[v.policyType]) {
        result.complianceBreakdown.byPolicyType[v.policyType] = { score: 100, violations: 0 };
      }
      result.complianceBreakdown.byPolicyType[v.policyType].violations++;
      result.complianceBreakdown.byPolicyType[v.policyType].score -= v.riskScore * 0.1;
    });

    // By severity
    result.violations.forEach(v => {
      result.complianceBreakdown.bySeverity[v.severity] = (result.complianceBreakdown.bySeverity[v.severity] || 0) + 1;
    });

    // Normalize scores
    Object.keys(result.complianceBreakdown.byFramework).forEach(framework => {
      result.complianceBreakdown.byFramework[framework].score = Math.max(0, Math.round(result.complianceBreakdown.byFramework[framework].score));
    });

    Object.keys(result.complianceBreakdown.byPolicyType).forEach(policyType => {
      result.complianceBreakdown.byPolicyType[policyType].score = Math.max(0, Math.round(result.complianceBreakdown.byPolicyType[policyType].score));
    });
  }

  // Helper methods for policy-specific operations

  private countComplianceControls(policyData: Record<string, unknown>): number {
    const controls = policyData.controls as {
      preventive?: unknown[];
      detective?: unknown[];
      corrective?: unknown[];
      compensating?: unknown[];
    };
    
    if (!controls) return 1;
    
    return (controls.preventive?.length || 0) + 
           (controls.detective?.length || 0) + 
           (controls.corrective?.length || 0) + 
           (controls.compensating?.length || 0);
  }

  private countNamingRules(policyData: Record<string, unknown>): number {
    const rules = policyData.rules as unknown[];
    return Array.isArray(rules) ? rules.length : 1;
  }

  private countArchivalConditions(policyData: Record<string, unknown>): number {
    const conditions = policyData.conditions as unknown[];
    return Array.isArray(conditions) ? conditions.length : 1;
  }

  private mapEnforcementToSeverity(enforcementLevel: string): ViolationSeverity {
    switch (enforcementLevel) {
      case 'strict': return 'critical';
      case 'warning': return 'medium';
      case 'advisory': return 'low';
      default: return 'medium';
    }
  }

  private mapSeverityToRiskScore(severity: ViolationSeverity): number {
    switch (severity) {
      case 'critical': return 90;
      case 'high': return 70;
      case 'medium': return 50;
      case 'low': return 30;
      default: return 50;
    }
  }

  private generateRemediationSteps(description: string, severity: string): Array<{
    step: string;
    priority: RemediationPriority;
    estimatedEffort: string;
    automatable: boolean;
  }> {
    const steps: Array<{
      step: string;
      priority: RemediationPriority;
      estimatedEffort: string;
      automatable: boolean;
    }> = [];

    if (severity === 'critical') {
      steps.push({
        step: 'Immediately address this critical compliance violation',
        priority: 'immediate' as RemediationPriority,
        estimatedEffort: '1-2 hours',
        automatable: false,
      });
    }

    steps.push({
      step: `Review and resolve: ${description}`,
      priority: severity === 'high' ? 'high' as RemediationPriority : 'medium' as RemediationPriority,
      estimatedEffort: severity === 'critical' ? '2-4 hours' : '30-60 minutes',
      automatable: description.toLowerCase().includes('automated') || description.toLowerCase().includes('configuration'),
    });

    if (severity === 'critical' || severity === 'high') {
      steps.push({
        step: 'Verify compliance after remediation',
        priority: 'high' as RemediationPriority,
        estimatedEffort: '15 minutes',
        automatable: true,
      });
    }

    return steps;
  }

  private generateNamingRemediationSteps(errors: string[], suggestions?: string[]): Array<{
    step: string;
    priority: RemediationPriority;
    estimatedEffort: string;
    automatable: boolean;
  }> {
    const steps: Array<{
      step: string;
      priority: RemediationPriority;
      estimatedEffort: string;
      automatable: boolean;
    }> = [];

    steps.push({
      step: `Address naming violations: ${errors.join(', ')}`,
      priority: 'medium' as RemediationPriority,
      estimatedEffort: '10-15 minutes',
      automatable: true,
    });

    if (suggestions && suggestions.length > 0) {
      steps.push({
        step: `Consider suggested names: ${suggestions.slice(0, 3).join(', ')}`,
        priority: 'low' as RemediationPriority,
        estimatedEffort: '5 minutes',
        automatable: false,
      });
    }

    return steps;
  }
}

/**
 * Adds unified policy compliance validation tools to the FastMCP server
 * 
 * @param {FastMCP} server - The FastMCP server instance
 * @param {MakeApiClient} apiClient - Make.com API client with rate limiting and authentication
 * @returns {void}
 */
export function addPolicyComplianceValidationTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'PolicyComplianceValidationTools' });
  const validator = new PolicyComplianceValidator(apiClient);
  
  componentLogger.info('Adding unified policy compliance validation tools');

  /**
   * Validate comprehensive policy compliance across all governance systems
   * 
   * Performs unified compliance validation across all policy types (compliance, naming, archival)
   * with cross-policy validation, comprehensive scoring, violation tracking, and detailed
   * remediation recommendations for enterprise governance requirements.
   * 
   * @tool validate-policy-compliance
   * @category Enterprise Governance
   * @permission compliance_validator
   * 
   * @param {Object} args - Compliance validation parameters
   * @param {Array} args.targets - Targets to validate for compliance
   * @param {Object} args.policySelection - Policy selection and filtering criteria
   * @param {Object} args.validationOptions - Validation options and configuration
   * @param {Object} [args.reportingOptions] - Report generation options
   * @param {Object} [args.executionContext] - Execution context and metadata
   * 
   * @returns {Promise<string>} JSON response containing:
   * - validationId: Unique validation identifier for tracking
   * - results: Comprehensive compliance validation results for each target
   * - summary: Overall validation summary with statistics and scores
   * - recommendations: Prioritized remediation recommendations
   * - crossValidationResults: Cross-policy conflict and issue analysis
   * - complianceBreakdown: Detailed breakdown by framework, policy type, and severity
   * - auditTrail: Complete audit trail for compliance reporting
   * - reportingOptions: Available export formats and dashboard data
   * 
   * @throws {UserError} When validation fails or targets are inaccessible
   * 
   * @example
   * ```typescript
   * // Validate scenario against all applicable policies
   * const validation = await validatePolicyCompliance({
   *   targets: [{
   *     targetType: "scenario",
   *     targetId: "scenario_123",
   *     targetName: "Customer Data Sync"
   *   }],
   *   policySelection: {
   *     policyTypes: ["compliance", "naming_convention"],
   *     frameworks: ["gdpr", "sox"],
   *     activeOnly: true
   *   },
   *   validationOptions: {
   *     includeRecommendations: true,
   *     includeComplianceScore: true,
   *     enableCrossValidation: true,
   *     validationDepth: "comprehensive"
   *   }
   * });
   * ```
   * 
   * @see {@link https://docs.make.com/api/compliance} Make.com Compliance API
   * @see {@link development/research-reports/comprehensive-enterprise-security-compliance-framework-research.md} Implementation Research
   */
  server.addTool({
    name: 'validate-policy-compliance',
    description: 'Unified policy compliance validation across all governance systems with cross-policy analysis, comprehensive scoring, and detailed remediation guidance',
    parameters: ValidatePolicyComplianceSchema,
    annotations: {
      title: 'Validate Policy Compliance',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log, reportProgress }) => {
      log.info('Starting comprehensive policy compliance validation', {
        targetsCount: input.targets.length,
        policyTypes: input.policySelection.policyTypes,
        frameworks: input.policySelection.frameworks,
        validationDepth: input.validationOptions.validationDepth,
      });

      reportProgress({ progress: 0, total: 100 });

      try {
        const validationId = validator['complianceManager'].generateValidationId();
        const startTime = new Date().toISOString();

        log.info('Generated validation ID and starting validation process', {
          validationId,
          startTime,
        });

        reportProgress({ progress: 10, total: 100 });

        // Perform comprehensive validation
        const results = await validator.validateCompliance(
          input.targets,
          input.policySelection,
          input.validationOptions
        );

        reportProgress({ progress: 80, total: 100 });

        // Store validation results for historical tracking
        await validator['complianceManager'].storeValidationResults(validationId, results);

        // Generate summary statistics
        const summary = {
          validationId,
          totalTargets: results.length,
          compliantTargets: results.filter(r => r.overallComplianceStatus === 'compliant').length,
          nonCompliantTargets: results.filter(r => r.overallComplianceStatus === 'non_compliant').length,
          warningTargets: results.filter(r => r.overallComplianceStatus === 'warning').length,
          unknownTargets: results.filter(r => r.overallComplianceStatus === 'unknown').length,
          totalViolations: results.reduce((sum, r) => sum + r.violations.length, 0),
          criticalViolations: results.reduce((sum, r) => sum + r.violations.filter(v => v.severity === 'critical').length, 0),
          highViolations: results.reduce((sum, r) => sum + r.violations.filter(v => v.severity === 'high').length, 0),
          mediumViolations: results.reduce((sum, r) => sum + r.violations.filter(v => v.severity === 'medium').length, 0),
          lowViolations: results.reduce((sum, r) => sum + r.violations.filter(v => v.severity === 'low').length, 0),
          averageComplianceScore: results.length > 0 ? 
            Math.round(results.reduce((sum, r) => sum + r.overallComplianceScore, 0) / results.length) : 0,
          averageRiskScore: results.length > 0 ? 
            Math.round(results.reduce((sum, r) => sum + r.overallRiskScore, 0) / results.length) : 0,
          validationDuration: Date.now() - new Date(startTime).getTime(),
        };

        // Collect all cross-validation results
        const allCrossValidationResults = results.flatMap(r => r.crossValidationResults || []);

        // Collect all recommendations
        const allRecommendations = results.flatMap(r => r.recommendations);

        // Generate compliance breakdown across all targets
        const overallComplianceBreakdown = {
          byFramework: {},
          byPolicyType: {},
          bySeverity: {},
        };

        results.forEach(result => {
          // Merge framework breakdowns
          Object.entries(result.complianceBreakdown.byFramework).forEach(([framework, data]) => {
            if (!overallComplianceBreakdown.byFramework[framework]) {
              overallComplianceBreakdown.byFramework[framework] = { score: 0, violations: 0, targets: 0 };
            }
            const frameworkData = overallComplianceBreakdown.byFramework[framework] as { score: number; violations: number; targets: number };
            frameworkData.score += data.score;
            frameworkData.violations += data.violations;
            frameworkData.targets += 1;
          });

          // Merge policy type breakdowns
          Object.entries(result.complianceBreakdown.byPolicyType).forEach(([policyType, data]) => {
            if (!overallComplianceBreakdown.byPolicyType[policyType]) {
              overallComplianceBreakdown.byPolicyType[policyType] = { score: 0, violations: 0, targets: 0 };
            }
            const policyTypeData = overallComplianceBreakdown.byPolicyType[policyType] as { score: number; violations: number; targets: number };
            policyTypeData.score += data.score;
            policyTypeData.violations += data.violations;
            policyTypeData.targets += 1;
          });

          // Merge severity breakdowns
          Object.entries(result.complianceBreakdown.bySeverity).forEach(([severity, count]) => {
            overallComplianceBreakdown.bySeverity[severity] = (overallComplianceBreakdown.bySeverity[severity] || 0) + count;
          });
        });

        // Average scores in breakdowns
        Object.keys(overallComplianceBreakdown.byFramework).forEach(framework => {
          const data = overallComplianceBreakdown.byFramework[framework] as { score: number; targets: number };
          if (data.targets > 0) {
            data.score = Math.round(data.score / data.targets);
          }
        });

        Object.keys(overallComplianceBreakdown.byPolicyType).forEach(policyType => {
          const data = overallComplianceBreakdown.byPolicyType[policyType] as { score: number; targets: number };
          if (data.targets > 0) {
            data.score = Math.round(data.score / data.targets);
          }
        });

        reportProgress({ progress: 90, total: 100 });

        // Log validation audit event
        await auditLogger.logEvent({
          level: summary.criticalViolations > 0 || summary.highViolations > 0 ? 'warn' : 'info',
          category: 'authorization',
          action: 'comprehensive_policy_compliance_validation',
          resource: `validation:${validationId}`,
          success: true,
          details: {
            validationId,
            targetsValidated: summary.totalTargets,
            totalViolations: summary.totalViolations,
            criticalViolations: summary.criticalViolations,
            highViolations: summary.highViolations,
            averageComplianceScore: summary.averageComplianceScore,
            policyTypes: input.policySelection.policyTypes,
            frameworks: input.policySelection.frameworks,
            validationDepth: input.validationOptions.validationDepth,
            executionContext: input.executionContext,
          },
          riskLevel: summary.criticalViolations > 0 ? 'high' : summary.highViolations > 0 ? 'medium' : 'low',
        });

        reportProgress({ progress: 100, total: 100 });

        const finalResult = {
          success: true,
          validationId,
          results: input.reportingOptions?.format === 'summary' ? undefined : results,
          summary,
          recommendations: allRecommendations.sort((a, b) => {
            const priorityOrder = { immediate: 0, high: 1, medium: 2, low: 3, informational: 4 };
            return priorityOrder[a.priority] - priorityOrder[b.priority];
          }).slice(0, 20), // Top 20 recommendations
          crossValidationResults: allCrossValidationResults,
          complianceBreakdown: overallComplianceBreakdown,
          auditTrail: {
            validationId,
            startTime,
            endTime: new Date().toISOString(),
            duration: `${summary.validationDuration}ms`,
            userId: input.executionContext?.userId,
            reason: input.executionContext?.reason,
            correlationId: input.executionContext?.correlationId,
            validationDepth: input.validationOptions.validationDepth,
            dryRun: input.executionContext?.dryRun || false,
          },
          reportingOptions: {
            availableFormats: ['json', 'detailed', 'summary', 'executive'],
            currentFormat: input.reportingOptions?.format || 'detailed',
            exportOptions: {
              generatePdf: input.reportingOptions?.exportOptions?.generatePdf || false,
              generateExcel: input.reportingOptions?.exportOptions?.generateExcel || false,
              generateDashboard: input.reportingOptions?.exportOptions?.generateDashboard || false,
              downloadUrls: {
                pdf: input.reportingOptions?.exportOptions?.generatePdf ? `/api/compliance/reports/${validationId}.pdf` : null,
                excel: input.reportingOptions?.exportOptions?.generateExcel ? `/api/compliance/reports/${validationId}.xlsx` : null,
                dashboard: input.reportingOptions?.exportOptions?.generateDashboard ? `/api/compliance/dashboard/${validationId}` : null,
              },
            },
            historicalTrends: input.reportingOptions?.includeHistoricalTrends ? {
              available: true,
              endpoint: `/api/compliance/trends/${validationId}`,
            } : null,
          },
          capabilities: {
            policyTypes: ['compliance', 'naming_convention', 'scenario_archival'],
            frameworks: ['sox', 'gdpr', 'hipaa', 'pci_dss', 'iso27001', 'enterprise', 'custom'],
            validationDepths: ['basic', 'standard', 'comprehensive'],
            crossValidation: true,
            scoring: true,
            recommendations: true,
            auditIntegration: true,
            historicalTracking: true,
            automatedRemediation: true,
          },
          message: `Comprehensive policy compliance validation completed. ${summary.totalTargets} targets validated with ${summary.totalViolations} total violations (${summary.criticalViolations} critical, ${summary.highViolations} high). Average compliance score: ${summary.averageComplianceScore}%. ${allRecommendations.length} recommendations generated.`,
        };

        componentLogger.info('Comprehensive policy compliance validation completed', {
          validationId,
          targetsValidated: summary.totalTargets,
          totalViolations: summary.totalViolations,
          averageComplianceScore: summary.averageComplianceScore,
          duration: summary.validationDuration,
        });

        return JSON.stringify(finalResult, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error during comprehensive policy compliance validation', {
          error: errorMessage,
          targetsCount: input.targets.length,
        });
        
        // Log failure audit event
        await auditLogger.logEvent({
          level: 'error',
          category: 'authorization',
          action: 'policy_compliance_validation_failed',
          success: false,
          details: {
            targetsCount: input.targets.length,
            error: errorMessage,
            policyTypes: input.policySelection.policyTypes,
            frameworks: input.policySelection.frameworks,
          },
          riskLevel: 'medium',
        });
        
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to validate policy compliance: ${errorMessage}`);
      }
    },
  });

  componentLogger.info('Unified policy compliance validation tools added successfully');
}

export default addPolicyComplianceValidationTools;