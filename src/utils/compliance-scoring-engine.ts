/**
 * @fileoverview Compliance Scoring Engine with Security Posture Assessment
 * 
 * Implements comprehensive compliance evaluation against multiple security frameworks,
 * risk assessment, and organizational security posture analysis.
 */

import { EventEmitter } from 'events';
import * as crypto from 'crypto';
import logger from '../lib/logger.js';
import {
  ComplianceFramework,
  ComplianceAssessment,
  ComplianceRequirement,
  ComplianceGap,
  SecuritySeverity,
  RiskLevel,
  ValidationContext,
  ExtendedValidationResult,
  ComplianceStatus
} from '../types/credential-validation.js';

/**
 * Security posture assessment result
 */
export interface SecurityPostureAssessment {
  /** Overall security posture grade */
  postureGrade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  /** Numeric score (0-100) */
  postureScore: number;
  /** Assessment timestamp */
  assessmentDate: Date;
  /** Framework compliance results */
  frameworkCompliance: Map<ComplianceFramework, ComplianceAssessment>;
  /** Identified security strengths */
  strengths: SecurityStrength[];
  /** Security weaknesses and gaps */
  weaknesses: SecurityWeakness[];
  /** Risk profile analysis */
  riskProfile: RiskProfile;
  /** Remediation roadmap */
  remediationRoadmap: RemediationRoadmap;
  /** Industry benchmarking */
  industryBenchmark?: IndustryBenchmark;
  /** Trend analysis */
  trendAnalysis?: TrendAnalysis;
  /** Recommendations by priority */
  prioritizedRecommendations: PrioritizedRecommendation[];
}

/**
 * Security strength identification
 */
export interface SecurityStrength {
  /** Strength identifier */
  id: string;
  /** Category of strength */
  category: 'policy' | 'technology' | 'process' | 'people' | 'governance';
  /** Description */
  description: string;
  /** Impact on overall security */
  impact: 'low' | 'medium' | 'high';
  /** Supporting evidence */
  evidence: string[];
  /** Applicable frameworks */
  frameworks: ComplianceFramework[];
  /** Confidence level */
  confidence: number; // 0-1
}

/**
 * Security weakness analysis
 */
export interface SecurityWeakness {
  /** Weakness identifier */
  id: string;
  /** Category of weakness */
  category: 'policy' | 'technology' | 'process' | 'people' | 'governance';
  /** Description */
  description: string;
  /** Risk level */
  riskLevel: RiskLevel;
  /** Potential impact */
  impact: string;
  /** Affected frameworks */
  affectedFrameworks: ComplianceFramework[];
  /** Recommended remediation */
  remediation: string[];
  /** Business impact */
  businessImpact: 'low' | 'medium' | 'high' | 'critical';
  /** Confidence level */
  confidence: number; // 0-1
}

/**
 * Organizational risk profile
 */
export interface RiskProfile {
  /** Overall risk level */
  overallRisk: RiskLevel;
  /** Risk score (0-100) */
  riskScore: number;
  /** Risk categories and their scores */
  categoryRisks: Map<string, RiskCategoryAssessment>;
  /** Risk appetite alignment */
  riskAppetiteAlignment: 'within' | 'above' | 'below';
  /** Residual risk after controls */
  residualRisk: RiskLevel;
  /** Risk trends */
  riskTrends: RiskTrend[];
}

/**
 * Risk category assessment
 */
export interface RiskCategoryAssessment {
  /** Category name */
  category: string;
  /** Risk score for category */
  score: number;
  /** Key risk factors */
  keyRiskFactors: string[];
  /** Control effectiveness */
  controlEffectiveness: 'weak' | 'adequate' | 'strong';
  /** Improvement areas */
  improvementAreas: string[];
}

/**
 * Risk trend analysis
 */
export interface RiskTrend {
  /** Risk category */
  category: string;
  /** Trend direction */
  direction: 'improving' | 'stable' | 'degrading';
  /** Rate of change */
  changeRate: number;
  /** Period of analysis */
  period: string;
  /** Contributing factors */
  factors: string[];
}

/**
 * Remediation roadmap structure
 */
export interface RemediationRoadmap {
  /** Immediate actions (0-30 days) */
  immediate: RemediationPhase;
  /** Short-term actions (1-6 months) */
  shortTerm: RemediationPhase;
  /** Long-term actions (6+ months) */
  longTerm: RemediationPhase;
  /** Total estimated cost */
  totalCost: CostEstimate;
  /** Resource requirements */
  resourceRequirements: ResourceRequirement[];
  /** Success metrics */
  successMetrics: SuccessMetric[];
}

/**
 * Remediation phase details
 */
export interface RemediationPhase {
  /** Phase name */
  phase: string;
  /** Actions in this phase */
  actions: RemediationAction[];
  /** Phase duration */
  duration: string;
  /** Phase cost */
  cost: CostEstimate;
  /** Dependencies */
  dependencies: string[];
  /** Success criteria */
  successCriteria: string[];
}

/**
 * Individual remediation action
 */
export interface RemediationAction {
  /** Action identifier */
  id: string;
  /** Action title */
  title: string;
  /** Detailed description */
  description: string;
  /** Priority level */
  priority: 'critical' | 'high' | 'medium' | 'low';
  /** Estimated effort */
  effort: 'low' | 'medium' | 'high';
  /** Cost estimate */
  cost: CostEstimate;
  /** Resource requirements */
  resources: string[];
  /** Expected outcome */
  expectedOutcome: string;
  /** Risk reduction */
  riskReduction: number; // 0-100
  /** Compliance improvements */
  complianceImprovements: ComplianceFramework[];
}

/**
 * Cost estimation structure
 */
export interface CostEstimate {
  /** Minimum cost */
  minimum: number;
  /** Maximum cost */
  maximum: number;
  /** Most likely cost */
  mostLikely: number;
  /** Currency */
  currency: string;
  /** Confidence level */
  confidence: 'low' | 'medium' | 'high';
  /** Cost breakdown */
  breakdown?: CostBreakdown[];
}

/**
 * Cost breakdown by category
 */
export interface CostBreakdown {
  /** Cost category */
  category: string;
  /** Amount */
  amount: number;
  /** Description */
  description: string;
}

/**
 * Resource requirement specification
 */
export interface ResourceRequirement {
  /** Resource type */
  type: 'human' | 'technology' | 'financial' | 'time';
  /** Skill level required */
  skillLevel?: 'junior' | 'mid' | 'senior' | 'expert';
  /** Quantity needed */
  quantity: number;
  /** Duration required */
  duration: string;
  /** Criticality */
  criticality: 'essential' | 'important' | 'nice-to-have';
}

/**
 * Success metric definition
 */
export interface SuccessMetric {
  /** Metric name */
  name: string;
  /** Target value */
  target: number;
  /** Current baseline */
  baseline?: number;
  /** Unit of measurement */
  unit: string;
  /** Measurement frequency */
  frequency: 'continuous' | 'daily' | 'weekly' | 'monthly' | 'quarterly';
  /** Success criteria */
  successCriteria: string;
}

/**
 * Industry benchmarking data
 */
export interface IndustryBenchmark {
  /** Industry sector */
  industry: string;
  /** Peer comparison */
  peerComparison: 'below-average' | 'average' | 'above-average' | 'best-in-class';
  /** Percentile ranking */
  percentile: number; // 0-100
  /** Key differentiators */
  differentiators: string[];
  /** Areas for improvement */
  improvementAreas: string[];
  /** Best practices from industry */
  bestPractices: string[];
}

/**
 * Trend analysis over time
 */
export interface TrendAnalysis {
  /** Analysis period */
  period: string;
  /** Overall trend */
  overallTrend: 'improving' | 'stable' | 'declining';
  /** Trend confidence */
  trendConfidence: number; // 0-1
  /** Key trend drivers */
  trendDrivers: string[];
  /** Forecast */
  forecast: TrendForecast[];
  /** Recommendations based on trends */
  trendBasedRecommendations: string[];
}

/**
 * Trend forecast
 */
export interface TrendForecast {
  /** Forecast period */
  period: string;
  /** Predicted score */
  predictedScore: number;
  /** Confidence interval */
  confidenceInterval: {
    lower: number;
    upper: number;
  };
  /** Key assumptions */
  assumptions: string[];
}

/**
 * Prioritized recommendation
 */
export interface PrioritizedRecommendation {
  /** Recommendation rank */
  rank: number;
  /** Recommendation title */
  title: string;
  /** Detailed recommendation */
  recommendation: string;
  /** Business justification */
  businessJustification: string;
  /** Implementation complexity */
  complexity: 'low' | 'medium' | 'high';
  /** Expected ROI */
  expectedROI: number;
  /** Timeline */
  timeline: string;
  /** Dependencies */
  dependencies: string[];
  /** Risk if not implemented */
  riskIfNotImplemented: RiskLevel;
}

/**
 * Compliance scoring configuration
 */
export interface ComplianceScoringConfig {
  /** Frameworks to evaluate */
  enabledFrameworks: ComplianceFramework[];
  /** Framework weights for overall score */
  frameworkWeights: Map<ComplianceFramework, number>;
  /** Industry sector for benchmarking */
  industrySector?: string;
  /** Organization size for benchmarking */
  organizationSize?: 'small' | 'medium' | 'large' | 'enterprise';
  /** Risk appetite level */
  riskAppetite: 'conservative' | 'moderate' | 'aggressive';
  /** Enable trend analysis */
  enableTrendAnalysis: boolean;
  /** Historical data retention period */
  historyRetentionDays: number;
}

/**
 * Framework-specific compliance rules
 */
interface FrameworkRules {
  /** Framework identifier */
  framework: ComplianceFramework;
  /** Requirements mapping */
  requirements: Map<string, ComplianceRule>;
  /** Scoring weights */
  weights: Map<string, number>;
  /** Critical requirements that cannot fail */
  criticalRequirements: string[];
}

/**
 * Individual compliance rule
 */
interface ComplianceRule {
  /** Rule identifier */
  id: string;
  /** Rule title */
  title: string;
  /** Rule description */
  description: string;
  /** Severity if non-compliant */
  severity: SecuritySeverity;
  /** Validation function */
  validator: (result: ExtendedValidationResult, context?: ValidationContext) => ComplianceStatus;
  /** Evidence generator */
  evidenceGenerator?: (result: ExtendedValidationResult, context?: ValidationContext) => string;
  /** Remediation suggestions */
  remediation: string[];
}

/**
 * Main compliance scoring engine
 */
export class ComplianceScoringEngine extends EventEmitter {
  private readonly config: ComplianceScoringConfig;
  private readonly frameworkRules: Map<ComplianceFramework, FrameworkRules>;
  private readonly assessmentHistory: Map<string, SecurityPostureAssessment[]> = new Map();
  private readonly componentLogger: ReturnType<typeof logger.child>;

  constructor(config: Partial<ComplianceScoringConfig> = {}) {
    super();
    
    this.componentLogger = logger.child({ component: 'ComplianceScoringEngine' });
    
    this.config = {
      enabledFrameworks: config.enabledFrameworks || ['SOC2', 'ISO27001', 'PCI-DSS'],
      frameworkWeights: config.frameworkWeights || new Map([
        ['SOC2', 0.3],
        ['ISO27001', 0.3],
        ['PCI-DSS', 0.2],
        ['GDPR', 0.1],
        ['HIPAA', 0.1]
      ]),
      industrySector: config.industrySector,
      organizationSize: config.organizationSize,
      riskAppetite: config.riskAppetite || 'moderate',
      enableTrendAnalysis: config.enableTrendAnalysis ?? true,
      historyRetentionDays: config.historyRetentionDays || 365
    };

    this.frameworkRules = new Map();
    this.initializeFrameworkRules();

    this.componentLogger.info('Compliance scoring engine initialized', {
      enabledFrameworks: this.config.enabledFrameworks,
      industrySector: this.config.industrySector,
      riskAppetite: this.config.riskAppetite
    });
  }

  /**
   * Assess compliance for a single credential validation result
   */
  public async assessCompliance(
    result: ExtendedValidationResult,
    context?: ValidationContext
  ): Promise<ComplianceAssessment[]> {
    const assessments: ComplianceAssessment[] = [];

    for (const framework of this.config.enabledFrameworks) {
      const assessment = await this.assessFrameworkCompliance(framework, result, context);
      assessments.push(assessment);
    }

    this.componentLogger.debug('Compliance assessment completed', {
      jobId: result.jobId,
      assessments: assessments.length,
      overallCompliance: assessments.every(a => a.compliant)
    });

    return assessments;
  }

  /**
   * Perform comprehensive security posture assessment
   */
  public async assessSecurityPosture(
    results: ExtendedValidationResult[],
    organizationId?: string
  ): Promise<SecurityPostureAssessment> {
    const assessmentId = `assessment_${crypto.randomUUID()}`;
    
    this.componentLogger.info('Starting security posture assessment', {
      assessmentId,
      organizationId,
      resultCount: results.length
    });

    // Assess compliance across all frameworks
    const frameworkCompliance = new Map<ComplianceFramework, ComplianceAssessment>();
    
    for (const framework of this.config.enabledFrameworks) {
      const aggregatedAssessment = await this.aggregateFrameworkCompliance(framework, results);
      frameworkCompliance.set(framework, aggregatedAssessment);
    }

    // Calculate overall posture score
    const postureScore = this.calculatePostureScore(frameworkCompliance);
    const postureGrade = this.calculatePostureGrade(postureScore);

    // Analyze strengths and weaknesses
    const strengths = await this.identifySecurityStrengths(results, frameworkCompliance);
    const weaknesses = await this.identifySecurityWeaknesses(results, frameworkCompliance);

    // Assess risk profile
    const riskProfile = await this.assessRiskProfile(results, weaknesses);

    // Generate remediation roadmap
    const remediationRoadmap = await this.generateRemediationRoadmap(weaknesses, riskProfile);

    // Industry benchmarking (if configured)
    let industryBenchmark: IndustryBenchmark | undefined;
    if (this.config.industrySector) {
      industryBenchmark = await this.performIndustryBenchmarking(postureScore);
    }

    // Trend analysis (if enabled and historical data available)
    let trendAnalysis: TrendAnalysis | undefined;
    if (this.config.enableTrendAnalysis && organizationId) {
      trendAnalysis = await this.performTrendAnalysis(organizationId, postureScore);
    }

    // Generate prioritized recommendations
    const prioritizedRecommendations = await this.generatePrioritizedRecommendations(
      weaknesses,
      riskProfile,
      industryBenchmark
    );

    const assessment: SecurityPostureAssessment = {
      postureGrade,
      postureScore,
      assessmentDate: new Date(),
      frameworkCompliance,
      strengths,
      weaknesses,
      riskProfile,
      remediationRoadmap,
      industryBenchmark,
      trendAnalysis,
      prioritizedRecommendations
    };

    // Store assessment in history
    if (organizationId) {
      this.storeAssessmentHistory(organizationId, assessment);
    }

    this.componentLogger.info('Security posture assessment completed', {
      assessmentId,
      organizationId,
      postureScore,
      postureGrade,
      riskLevel: riskProfile.overallRisk
    });

    this.emit('postureAssessed', { assessmentId, organizationId, assessment });

    return assessment;
  }

  /**
   * Get assessment history for an organization
   */
  public getAssessmentHistory(organizationId: string): SecurityPostureAssessment[] {
    return this.assessmentHistory.get(organizationId) || [];
  }

  /**
   * Compare two security posture assessments
   */
  public compareAssessments(
    current: SecurityPostureAssessment,
    previous: SecurityPostureAssessment
  ): AssessmentComparison {
    const scoreChange = current.postureScore - previous.postureScore;
    const gradeChange = this.compareGrades(current.postureGrade, previous.postureGrade);
    
    const improvementAreas: string[] = [];
    const regressionAreas: string[] = [];

    // Compare framework compliance
    for (const [framework, currentCompliance] of current.frameworkCompliance) {
      const previousCompliance = previous.frameworkCompliance.get(framework);
      
      if (previousCompliance) {
        const scoreDiff = currentCompliance.score - previousCompliance.score;
        
        if (scoreDiff > 5) {
          improvementAreas.push(`${framework} compliance improved by ${scoreDiff.toFixed(1)} points`);
        } else if (scoreDiff < -5) {
          regressionAreas.push(`${framework} compliance declined by ${Math.abs(scoreDiff).toFixed(1)} points`);
        }
      }
    }

    return {
      scoreChange,
      gradeChange,
      improvementAreas,
      regressionAreas,
      overallTrend: scoreChange > 0 ? 'improving' : scoreChange < 0 ? 'declining' : 'stable',
      riskTrend: this.compareRiskLevels(current.riskProfile.overallRisk, previous.riskProfile.overallRisk)
    };
  }

  /**
   * Initialize compliance rules for each framework
   */
  private initializeFrameworkRules(): void {
    // SOC 2 Type II rules
    this.frameworkRules.set('SOC2', {
      framework: 'SOC2',
      requirements: new Map([
        ['CC6.1', {
          id: 'CC6.1',
          title: 'Logical and Physical Access Controls',
          description: 'Controls over logical and physical access to systems',
          severity: 'high',
          validator: (result) => result.score >= 70 ? 'compliant' : 'non-compliant',
          evidenceGenerator: (result) => `Security score: ${result.score}/100`,
          remediation: ['Implement stronger access controls', 'Regular access reviews']
        }],
        ['CC6.2', {
          id: 'CC6.2',
          title: 'Authentication and Authorization',
          description: 'Strong authentication and authorization mechanisms',
          severity: 'critical',
          validator: (result) => result.isValid ? 'compliant' : 'non-compliant',
          evidenceGenerator: (result) => `Credential validation: ${result.isValid ? 'Pass' : 'Fail'}`,
          remediation: ['Implement multi-factor authentication', 'Credential strength requirements']
        }],
        ['CC6.7', {
          id: 'CC6.7',
          title: 'Data Transmission and Disposal',
          description: 'Secure transmission and disposal of data',
          severity: 'medium',
          validator: (result) => result.warnings.length < 3 ? 'compliant' : 'partial',
          evidenceGenerator: (result) => `Warning count: ${result.warnings.length}`,
          remediation: ['Implement encryption in transit', 'Secure data disposal procedures']
        }]
      ]),
      weights: new Map([['CC6.1', 0.3], ['CC6.2', 0.5], ['CC6.7', 0.2]]),
      criticalRequirements: ['CC6.2']
    });

    // ISO 27001:2022 rules
    this.frameworkRules.set('ISO27001', {
      framework: 'ISO27001',
      requirements: new Map([
        ['A.9.4.3', {
          id: 'A.9.4.3',
          title: 'Password Management System',
          description: 'Password management system requirements',
          severity: 'high',
          validator: (result) => result.score >= 80 ? 'compliant' : 'partial',
          evidenceGenerator: (result) => `Password strength score: ${result.score}/100`,
          remediation: ['Implement password complexity requirements', 'Regular password changes']
        }],
        ['A.10.1.1', {
          id: 'A.10.1.1',
          title: 'Cryptographic Policy',
          description: 'Use of cryptographic controls policy',
          severity: 'high',
          validator: (result) => result.strengths.length > 0 ? 'compliant' : 'non-compliant',
          evidenceGenerator: (result) => `Cryptographic strengths identified: ${result.strengths.length}`,
          remediation: ['Define cryptographic policy', 'Implement strong encryption']
        }],
        ['A.18.1.4', {
          id: 'A.18.1.4',
          title: 'Privacy and Data Protection',
          description: 'Privacy and protection of PII',
          severity: 'critical',
          validator: (result) => result.errors.length === 0 ? 'compliant' : 'non-compliant',
          evidenceGenerator: (result) => `Critical errors: ${result.errors.length}`,
          remediation: ['Implement data classification', 'Privacy by design principles']
        }]
      ]),
      weights: new Map([['A.9.4.3', 0.4], ['A.10.1.1', 0.3], ['A.18.1.4', 0.3]]),
      criticalRequirements: ['A.18.1.4']
    });

    // PCI DSS rules
    this.frameworkRules.set('PCI-DSS', {
      framework: 'PCI-DSS',
      requirements: new Map([
        ['8.2.3', {
          id: '8.2.3',
          title: 'Strong Authentication Parameters',
          description: 'Strong authentication for all system components',
          severity: 'critical',
          validator: (result) => result.score >= 80 ? 'compliant' : 'non-compliant',
          evidenceGenerator: (result) => `Authentication strength: ${result.score}/100`,
          remediation: ['Implement strong authentication', 'Multi-factor authentication']
        }],
        ['8.2.4', {
          id: '8.2.4',
          title: 'Password Requirements',
          description: 'Password complexity and management requirements',
          severity: 'high',
          validator: (result) => result.errors.length === 0 ? 'compliant' : 'non-compliant',
          evidenceGenerator: (result) => `Password validation errors: ${result.errors.length}`,
          remediation: ['Password complexity requirements', 'Regular password rotation']
        }],
        ['3.4', {
          id: '3.4',
          title: 'PAN Rendering',
          description: 'Primary Account Number rendering requirements',
          severity: 'critical',
          validator: (result) => !result.warnings.some(w => w.message.includes('exposure')),
          evidenceGenerator: (result) => `Data exposure warnings: ${result.warnings.filter(w => w.message.includes('exposure')).length}`,
          remediation: ['Implement data masking', 'Secure credential storage']
        }]
      ]),
      weights: new Map([['8.2.3', 0.4], ['8.2.4', 0.3], ['3.4', 0.3]]),
      criticalRequirements: ['8.2.3', '3.4']
    });

    this.componentLogger.debug('Framework rules initialized', {
      frameworks: Array.from(this.frameworkRules.keys())
    });
  }

  /**
   * Assess compliance against a specific framework
   */
  private async assessFrameworkCompliance(
    framework: ComplianceFramework,
    result: ExtendedValidationResult,
    context?: ValidationContext
  ): Promise<ComplianceAssessment> {
    const frameworkRules = this.frameworkRules.get(framework);
    if (!frameworkRules) {
      throw new Error(`Framework ${framework} not supported`);
    }

    const requirements: ComplianceRequirement[] = [];
    const gaps: ComplianceGap[] = [];
    let totalScore = 0;
    let weightSum = 0;

    for (const [requirementId, rule] of frameworkRules.requirements) {
      const status = rule.validator(result, context);
      const evidence = rule.evidenceGenerator?.(result, context) || '';
      const weight = frameworkRules.weights.get(requirementId) || 1;

      const requirement: ComplianceRequirement = {
        id: rule.id,
        title: rule.title,
        description: rule.description,
        status,
        evidence,
        remediation: status !== 'compliant' ? rule.remediation.join('; ') : undefined,
        criticality: rule.severity,
        lastAssessed: new Date()
      };

      requirements.push(requirement);

      // Calculate score contribution
      let scoreContribution = 0;
      switch (status) {
        case 'compliant':
          scoreContribution = 100;
          break;
        case 'partial':
          scoreContribution = 50;
          break;
        case 'non-compliant':
          scoreContribution = 0;
          break;
        case 'not-applicable':
          continue; // Don't include in score calculation
      }

      totalScore += scoreContribution * weight;
      weightSum += weight;

      // Identify gaps
      if (status !== 'compliant' && status !== 'not-applicable') {
        gaps.push({
          id: `gap_${rule.id}`,
          requirementId: rule.id,
          description: `${rule.title} is ${status}`,
          riskLevel: this.mapSeverityToRisk(rule.severity),
          priority: this.mapSeverityToPriority(rule.severity),
          effort: 'medium',
          remediationSteps: rule.remediation,
          targetDate: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000) // 90 days from now
        });
      }
    }

    const score = weightSum > 0 ? Math.round(totalScore / weightSum) : 0;
    const compliant = score >= 80 && gaps.filter(g => g.priority === 'immediate').length === 0;

    // Generate recommendations
    const recommendations = this.generateFrameworkRecommendations(framework, gaps, score);

    return {
      framework,
      compliant,
      score,
      requirements,
      gaps,
      recommendations,
      assessedAt: new Date(),
      nextAssessmentDue: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
    };
  }

  /**
   * Aggregate framework compliance across multiple results
   */
  private async aggregateFrameworkCompliance(
    framework: ComplianceFramework,
    results: ExtendedValidationResult[]
  ): Promise<ComplianceAssessment> {
    if (results.length === 0) {
      throw new Error('No results provided for aggregation');
    }

    const assessments = await Promise.all(
      results.map(result => this.assessFrameworkCompliance(framework, result))
    );

    // Aggregate scores (average)
    const totalScore = assessments.reduce((sum, assessment) => sum + assessment.score, 0);
    const averageScore = Math.round(totalScore / assessments.length);

    // Aggregate compliance (all must be compliant)
    const overallCompliant = assessments.every(assessment => assessment.compliant);

    // Aggregate requirements (take worst case)
    const requirementMap = new Map<string, ComplianceRequirement>();
    for (const assessment of assessments) {
      for (const requirement of assessment.requirements) {
        const existing = requirementMap.get(requirement.id);
        if (!existing || this.getStatusPriority(requirement.status) < this.getStatusPriority(existing.status)) {
          requirementMap.set(requirement.id, requirement);
        }
      }
    }

    // Aggregate gaps (unique gaps)
    const gapMap = new Map<string, ComplianceGap>();
    for (const assessment of assessments) {
      for (const gap of assessment.gaps) {
        if (!gapMap.has(gap.requirementId)) {
          gapMap.set(gap.requirementId, gap);
        }
      }
    }

    // Generate aggregated recommendations
    const allRecommendations = assessments.flatMap(a => a.recommendations);
    const uniqueRecommendations = [...new Set(allRecommendations)];

    return {
      framework,
      compliant: overallCompliant,
      score: averageScore,
      requirements: Array.from(requirementMap.values()),
      gaps: Array.from(gapMap.values()),
      recommendations: uniqueRecommendations,
      assessedAt: new Date(),
      nextAssessmentDue: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)
    };
  }

  /**
   * Calculate overall security posture score
   */
  private calculatePostureScore(frameworkCompliance: Map<ComplianceFramework, ComplianceAssessment>): number {
    let weightedScore = 0;
    let totalWeight = 0;

    for (const [framework, assessment] of frameworkCompliance) {
      const weight = this.config.frameworkWeights.get(framework) || 0.1;
      weightedScore += assessment.score * weight;
      totalWeight += weight;
    }

    return totalWeight > 0 ? Math.round(weightedScore / totalWeight) : 0;
  }

  /**
   * Calculate security posture grade
   */
  private calculatePostureGrade(score: number): SecurityPostureAssessment['postureGrade'] {
    if (score >= 95) {return 'A+';}
    if (score >= 90) {return 'A';}
    if (score >= 80) {return 'B';}
    if (score >= 70) {return 'C';}
    if (score >= 60) {return 'D';}
    return 'F';
  }

  /**
   * Identify security strengths from results
   */
  private async identifySecurityStrengths(
    results: ExtendedValidationResult[],
    frameworkCompliance: Map<ComplianceFramework, ComplianceAssessment>
  ): Promise<SecurityStrength[]> {
    const strengths: SecurityStrength[] = [];
    
    // Analyze high-scoring areas
    const highScoreResults = results.filter(r => r.score >= 80);
    if (highScoreResults.length / results.length >= 0.7) {
      strengths.push({
        id: 'high_credential_strength',
        category: 'technology',
        description: 'Majority of credentials meet high security standards',
        impact: 'high',
        evidence: [`${Math.round((highScoreResults.length / results.length) * 100)}% of credentials score 80+`],
        frameworks: this.config.enabledFrameworks,
        confidence: 0.9
      });
    }

    // Analyze compliant frameworks
    const compliantFrameworks = Array.from(frameworkCompliance.entries())
      .filter(([, assessment]) => assessment.compliant)
      .map(([framework]) => framework);

    if (compliantFrameworks.length > 0) {
      strengths.push({
        id: 'framework_compliance',
        category: 'governance',
        description: 'Strong compliance posture across multiple frameworks',
        impact: 'high',
        evidence: [`Compliant with: ${compliantFrameworks.join(', ')}`],
        frameworks: compliantFrameworks,
        confidence: 0.95
      });
    }

    // Analyze common strengths across results
    const commonStrengths = this.analyzeCommonStrengths(results);
    strengths.push(...commonStrengths);

    return strengths;
  }

  /**
   * Identify security weaknesses from results
   */
  private async identifySecurityWeaknesses(
    results: ExtendedValidationResult[],
    frameworkCompliance: Map<ComplianceFramework, ComplianceAssessment>
  ): Promise<SecurityWeakness[]> {
    const weaknesses: SecurityWeakness[] = [];

    // Analyze low-scoring areas
    const lowScoreResults = results.filter(r => r.score < 60);
    if (lowScoreResults.length > 0) {
      weaknesses.push({
        id: 'weak_credentials',
        category: 'technology',
        description: 'Significant number of weak credentials detected',
        riskLevel: 'high',
        impact: 'High risk of credential compromise',
        affectedFrameworks: this.config.enabledFrameworks,
        remediation: ['Implement credential strength policy', 'Mandatory credential rotation'],
        businessImpact: 'high',
        confidence: 0.9
      });
    }

    // Analyze non-compliant frameworks
    const nonCompliantFrameworks = Array.from(frameworkCompliance.entries())
      .filter(([, assessment]) => !assessment.compliant);

    for (const [framework, assessment] of nonCompliantFrameworks) {
      weaknesses.push({
        id: `non_compliant_${framework.toLowerCase()}`,
        category: 'governance',
        description: `Non-compliance with ${framework} requirements`,
        riskLevel: this.mapScoreToRisk(assessment.score),
        impact: `Regulatory and operational risk due to ${framework} non-compliance`,
        affectedFrameworks: [framework],
        remediation: assessment.recommendations,
        businessImpact: 'critical',
        confidence: 0.85
      });
    }

    // Analyze common weaknesses
    const commonWeaknesses = this.analyzeCommonWeaknesses(results);
    weaknesses.push(...commonWeaknesses);

    return weaknesses;
  }

  /**
   * Assess organizational risk profile
   */
  private async assessRiskProfile(
    results: ExtendedValidationResult[],
    weaknesses: SecurityWeakness[]
  ): Promise<RiskProfile> {
    // Calculate risk scores by category
    const categoryRisks = new Map<string, RiskCategoryAssessment>();

    // Technology risks
    const techRisks = results.filter(r => r.score < 70);
    categoryRisks.set('technology', {
      category: 'Technology',
      score: Math.max(0, 100 - (techRisks.length / results.length) * 100),
      keyRiskFactors: ['Weak credentials', 'Poor entropy', 'Predictable patterns'],
      controlEffectiveness: techRisks.length / results.length < 0.1 ? 'strong' : 
                           techRisks.length / results.length < 0.3 ? 'adequate' : 'weak',
      improvementAreas: ['Credential policy enforcement', 'Automated validation']
    });

    // Process risks
    const processRiskScore = weaknesses.filter(w => w.category === 'process').length > 0 ? 60 : 80;
    categoryRisks.set('process', {
      category: 'Process',
      score: processRiskScore,
      keyRiskFactors: ['Manual processes', 'Inconsistent application'],
      controlEffectiveness: processRiskScore >= 80 ? 'strong' : processRiskScore >= 60 ? 'adequate' : 'weak',
      improvementAreas: ['Process automation', 'Standard procedures']
    });

    // Governance risks
    const govRiskScore = weaknesses.filter(w => w.category === 'governance').length === 0 ? 85 : 55;
    categoryRisks.set('governance', {
      category: 'Governance',
      score: govRiskScore,
      keyRiskFactors: ['Policy gaps', 'Compliance failures'],
      controlEffectiveness: govRiskScore >= 80 ? 'strong' : govRiskScore >= 60 ? 'adequate' : 'weak',
      improvementAreas: ['Policy framework', 'Compliance monitoring']
    });

    // Calculate overall risk
    const categoryScores = Array.from(categoryRisks.values()).map(cat => cat.score);
    const averageScore = categoryScores.reduce((sum, score) => sum + score, 0) / categoryScores.length;
    const riskScore = Math.max(0, 100 - averageScore);
    const overallRisk = this.mapScoreToRisk(averageScore);

    // Assess risk appetite alignment
    const riskAppetiteAlignment = this.assessRiskAppetiteAlignment(riskScore);

    // Calculate residual risk (assuming some controls are in place)
    const residualRisk = this.calculateResidualRisk(overallRisk, categoryRisks);

    return {
      overallRisk,
      riskScore,
      categoryRisks,
      riskAppetiteAlignment,
      residualRisk,
      riskTrends: [] // Would be populated with historical data
    };
  }

  /**
   * Generate comprehensive remediation roadmap
   */
  private async generateRemediationRoadmap(
    weaknesses: SecurityWeakness[],
    riskProfile: RiskProfile
  ): Promise<RemediationRoadmap> {
    // Sort weaknesses by risk and business impact
    const prioritizedWeaknesses = weaknesses.sort((a, b) => {
      const aPriority = this.getWeaknessPriority(a);
      const bPriority = this.getWeaknessPriority(b);
      return bPriority - aPriority;
    });

    const immediate: RemediationAction[] = [];
    const shortTerm: RemediationAction[] = [];
    const longTerm: RemediationAction[] = [];

    for (const weakness of prioritizedWeaknesses) {
      const actions = this.generateRemediationActions(weakness);
      
      for (const action of actions) {
        switch (action.priority) {
          case 'critical':
            immediate.push(action);
            break;
          case 'high':
            shortTerm.push(action);
            break;
          case 'medium':
          case 'low':
            longTerm.push(action);
            break;
        }
      }
    }

    // Calculate costs and timelines
    const immediateCost = this.calculatePhaseCost(immediate);
    const shortTermCost = this.calculatePhaseCost(shortTerm);
    const longTermCost = this.calculatePhaseCost(longTerm);

    const totalCost: CostEstimate = {
      minimum: immediateCost.minimum + shortTermCost.minimum + longTermCost.minimum,
      maximum: immediateCost.maximum + shortTermCost.maximum + longTermCost.maximum,
      mostLikely: immediateCost.mostLikely + shortTermCost.mostLikely + longTermCost.mostLikely,
      currency: 'USD',
      confidence: 'medium'
    };

    return {
      immediate: {
        phase: 'Immediate',
        actions: immediate,
        duration: '0-30 days',
        cost: immediateCost,
        dependencies: [],
        successCriteria: ['Critical vulnerabilities addressed', 'Risk level reduced to acceptable']
      },
      shortTerm: {
        phase: 'Short Term',
        actions: shortTerm,
        duration: '1-6 months',
        cost: shortTermCost,
        dependencies: ['Immediate phase completion'],
        successCriteria: ['Significant risk reduction', 'Process improvements implemented']
      },
      longTerm: {
        phase: 'Long Term',
        actions: longTerm,
        duration: '6+ months',
        cost: longTermCost,
        dependencies: ['Short term phase completion'],
        successCriteria: ['Mature security posture', 'Continuous improvement established']
      },
      totalCost,
      resourceRequirements: this.calculateResourceRequirements([...immediate, ...shortTerm, ...longTerm]),
      successMetrics: this.generateSuccessMetrics(riskProfile)
    };
  }

  /**
   * Perform industry benchmarking
   */
  private async performIndustryBenchmarking(postureScore: number): Promise<IndustryBenchmark> {
    // This would typically connect to industry databases
    // For now, using simulated benchmarking data
    
    const industryAverages = {
      'financial': 85,
      'healthcare': 80,
      'technology': 88,
      'manufacturing': 75,
      'retail': 72,
      'government': 82
    };

    const industryAverage = industryAverages[this.config.industrySector as keyof typeof industryAverages] || 78;
    const percentile = Math.min(99, Math.max(1, Math.round((postureScore / industryAverage) * 50)));
    
    let peerComparison: IndustryBenchmark['peerComparison'];
    if (postureScore >= industryAverage + 15) {
      peerComparison = 'best-in-class';
    } else if (postureScore >= industryAverage + 5) {
      peerComparison = 'above-average';
    } else if (postureScore >= industryAverage - 5) {
      peerComparison = 'average';
    } else {
      peerComparison = 'below-average';
    }

    return {
      industry: this.config.industrySector || 'general',
      peerComparison,
      percentile,
      differentiators: this.getIndustryDifferentiators(peerComparison),
      improvementAreas: this.getIndustryImprovementAreas(peerComparison),
      bestPractices: this.getIndustryBestPractices()
    };
  }

  /**
   * Perform trend analysis using historical data
   */
  private async performTrendAnalysis(organizationId: string, currentScore: number): Promise<TrendAnalysis> {
    const history = this.assessmentHistory.get(organizationId) || [];
    
    if (history.length < 2) {
      // Not enough data for trend analysis
      return {
        period: 'insufficient-data',
        overallTrend: 'stable',
        trendConfidence: 0,
        trendDrivers: [],
        forecast: [],
        trendBasedRecommendations: ['Collect more assessment data for trend analysis']
      };
    }

    const scores = history.map(h => h.postureScore);
    scores.push(currentScore);

    // Simple trend calculation (could be enhanced with more sophisticated analysis)
    const _recentTrend = this.calculateTrend(scores.slice(-3)); // Last 3 assessments
    const overallTrend = this.calculateTrend(scores);

    return {
      period: `${history.length + 1} assessments`,
      overallTrend: overallTrend > 2 ? 'improving' : overallTrend < -2 ? 'declining' : 'stable',
      trendConfidence: Math.min(1, history.length / 5), // Higher confidence with more data
      trendDrivers: this.identifyTrendDrivers(history),
      forecast: this.generateForecast(scores),
      trendBasedRecommendations: this.generateTrendRecommendations(overallTrend, scores)
    };
  }

  /**
   * Generate prioritized recommendations
   */
  private async generatePrioritizedRecommendations(
    weaknesses: SecurityWeakness[],
    riskProfile: RiskProfile,
    industryBenchmark?: IndustryBenchmark
  ): Promise<PrioritizedRecommendation[]> {
    const recommendations: PrioritizedRecommendation[] = [];

    // Generate recommendations from weaknesses
    for (const weakness of weaknesses) {
      recommendations.push({
        rank: 0, // Will be assigned later
        title: `Address ${weakness.description}`,
        recommendation: weakness.remediation.join('. '),
        businessJustification: `Reduce ${weakness.riskLevel} risk and improve security posture`,
        complexity: this.mapBusinessImpactToComplexity(weakness.businessImpact),
        expectedROI: this.calculateExpectedROI(weakness),
        timeline: this.mapRiskToTimeline(weakness.riskLevel),
        dependencies: [],
        riskIfNotImplemented: weakness.riskLevel
      });
    }

    // Add industry-specific recommendations
    if (industryBenchmark?.improvementAreas) {
      for (const area of industryBenchmark.improvementAreas) {
        recommendations.push({
          rank: 0,
          title: `Industry Best Practice: ${area}`,
          recommendation: `Implement industry best practices for ${area}`,
          businessJustification: 'Align with industry standards and improve competitive position',
          complexity: 'medium',
          expectedROI: 1.5,
          timeline: '6-12 months',
          dependencies: [],
          riskIfNotImplemented: 'medium'
        });
      }
    }

    // Priority scoring and ranking
    return this.rankRecommendations(recommendations);
  }

  // Helper methods (implementation details)
  
  private mapSeverityToRisk(severity: SecuritySeverity): RiskLevel {
    const mapping = { 'low': 'low', 'medium': 'medium', 'high': 'high', 'critical': 'critical' } as const;
    return mapping[severity];
  }

  private mapSeverityToPriority(severity: SecuritySeverity): 'immediate' | 'high' | 'medium' | 'low' {
    const mapping = { 'critical': 'immediate', 'high': 'high', 'medium': 'medium', 'low': 'low' } as const;
    return mapping[severity];
  }

  private getStatusPriority(status: ComplianceStatus): number {
    const priorities = { 'non-compliant': 0, 'partial': 1, 'compliant': 2, 'not-applicable': 3 };
    return priorities[status];
  }

  private mapScoreToRisk(score: number): RiskLevel {
    if (score >= 80) {return 'low';}
    if (score >= 60) {return 'medium';}
    if (score >= 40) {return 'high';}
    return 'critical';
  }

  private generateFrameworkRecommendations(framework: ComplianceFramework, gaps: ComplianceGap[], score: number): string[] {
    const recommendations: string[] = [];
    
    if (score < 60) {
      recommendations.push(`Urgent: Comprehensive ${framework} compliance improvement required`);
    }
    
    const criticalGaps = gaps.filter(g => g.priority === 'immediate');
    if (criticalGaps.length > 0) {
      recommendations.push(`Address ${criticalGaps.length} critical compliance gaps immediately`);
    }

    recommendations.push(`Regular ${framework} compliance monitoring and assessment`);
    
    return recommendations;
  }

  private analyzeCommonStrengths(_results: ExtendedValidationResult[]): SecurityStrength[] {
    // Implementation would analyze patterns across results
    return [];
  }

  private analyzeCommonWeaknesses(_results: ExtendedValidationResult[]): SecurityWeakness[] {
    // Implementation would analyze patterns across results
    return [];
  }

  private assessRiskAppetiteAlignment(riskScore: number): 'within' | 'above' | 'below' {
    const riskAppetiteLevels = {
      'conservative': 15,
      'moderate': 25,
      'aggressive': 40
    };
    
    const threshold = riskAppetiteLevels[this.config.riskAppetite];
    
    if (riskScore <= threshold) {return 'within';}
    if (riskScore <= threshold * 1.2) {return 'above';}
    return 'above';
  }

  private calculateResidualRisk(inherentRisk: RiskLevel, controls: Map<string, RiskCategoryAssessment>): RiskLevel {
    // Simplified residual risk calculation
    const controlEffectiveness = Array.from(controls.values())
      .reduce((avg, cat) => avg + (cat.controlEffectiveness === 'strong' ? 0.8 : 
                                   cat.controlEffectiveness === 'adequate' ? 0.6 : 0.4), 0) / controls.size;
    
    const riskReduction = controlEffectiveness * 0.5; // Max 50% risk reduction
    const inherentScore = { 'low': 25, 'medium': 50, 'high': 75, 'critical': 100 }[inherentRisk];
    const residualScore = inherentScore * (1 - riskReduction);
    
    return this.mapScoreToRisk(100 - residualScore);
  }

  private getWeaknessPriority(weakness: SecurityWeakness): number {
    const riskWeight = { 'low': 1, 'medium': 2, 'high': 3, 'critical': 4 }[weakness.riskLevel];
    const impactWeight = { 'low': 1, 'medium': 2, 'high': 3, 'critical': 4 }[weakness.businessImpact];
    return riskWeight * impactWeight * weakness.confidence;
  }

  private generateRemediationActions(weakness: SecurityWeakness): RemediationAction[] {
    // Implementation would generate specific actions based on weakness type
    return [{
      id: `action_${weakness.id}`,
      title: `Remediate ${weakness.category} weakness`,
      description: weakness.description,
      priority: this.mapRiskToPriority(weakness.riskLevel),
      effort: 'medium',
      cost: { minimum: 1000, maximum: 5000, mostLikely: 2500, currency: 'USD', confidence: 'medium' },
      resources: ['Security team', 'Development team'],
      expectedOutcome: `Eliminate ${weakness.riskLevel} risk`,
      riskReduction: 70,
      complianceImprovements: weakness.affectedFrameworks
    }];
  }

  private mapRiskToPriority(risk: RiskLevel): RemediationAction['priority'] {
    const mapping = { 'low': 'low', 'medium': 'medium', 'high': 'high', 'critical': 'critical' } as const;
    return mapping[risk];
  }

  private calculatePhaseCost(actions: RemediationAction[]): CostEstimate {
    const totalMin = actions.reduce((sum, action) => sum + action.cost.minimum, 0);
    const totalMax = actions.reduce((sum, action) => sum + action.cost.maximum, 0);
    const totalMostLikely = actions.reduce((sum, action) => sum + action.cost.mostLikely, 0);

    return {
      minimum: totalMin,
      maximum: totalMax,
      mostLikely: totalMostLikely,
      currency: 'USD',
      confidence: 'medium'
    };
  }

  private calculateResourceRequirements(_actions: RemediationAction[]): ResourceRequirement[] {
    // Implementation would aggregate resource needs
    return [];
  }

  private generateSuccessMetrics(riskProfile: RiskProfile): SuccessMetric[] {
    return [
      {
        name: 'Security Posture Score',
        target: 85,
        baseline: 100 - riskProfile.riskScore,
        unit: 'points',
        frequency: 'monthly',
        successCriteria: 'Score above 85'
      },
      {
        name: 'High Risk Issues',
        target: 0,
        unit: 'count',
        frequency: 'weekly',
        successCriteria: 'Zero high or critical risk issues'
      }
    ];
  }

  private getIndustryDifferentiators(comparison: IndustryBenchmark['peerComparison']): string[] {
    const differentiators = {
      'best-in-class': ['Advanced security controls', 'Proactive threat management', 'Mature governance'],
      'above-average': ['Strong compliance posture', 'Regular security assessments'],
      'average': ['Standard industry practices', 'Basic compliance requirements'],
      'below-average': ['Improvement opportunities exist', 'Enhanced controls needed']
    };
    
    return differentiators[comparison] || [];
  }

  private getIndustryImprovementAreas(comparison: IndustryBenchmark['peerComparison']): string[] {
    if (comparison === 'best-in-class') {return ['Continuous innovation', 'Knowledge sharing'];}
    if (comparison === 'above-average') {return ['Advanced threat detection', 'Automation'];}
    if (comparison === 'average') {return ['Security awareness', 'Process maturity'];}
    return ['Fundamental security controls', 'Compliance framework implementation'];
  }

  private getIndustryBestPractices(): string[] {
    return [
      'Regular security assessments',
      'Continuous monitoring',
      'Employee training programs',
      'Incident response planning',
      'Third-party risk management'
    ];
  }

  private calculateTrend(scores: number[]): number {
    if (scores.length < 2) {return 0;}
    
    const n = scores.length;
    const xSum = (n * (n + 1)) / 2; // Sum of indices
    const ySum = scores.reduce((a, b) => a + b, 0);
    const xySum = scores.reduce((sum, score, i) => sum + score * (i + 1), 0);
    const x2Sum = (n * (n + 1) * (2 * n + 1)) / 6; // Sum of squares of indices
    
    return (n * xySum - xSum * ySum) / (n * x2Sum - xSum * xSum);
  }

  private identifyTrendDrivers(_history: SecurityPostureAssessment[]): string[] {
    // Implementation would analyze what's driving changes
    return ['Policy improvements', 'Technology upgrades', 'Training programs'];
  }

  private generateForecast(_scores: number[]): TrendForecast[] {
    // Implementation would generate statistical forecast
    return [];
  }

  private generateTrendRecommendations(trend: number, _scores: number[]): string[] {
    const recommendations: string[] = [];
    
    if (trend > 0) {
      recommendations.push('Continue current improvement initiatives');
      recommendations.push('Share best practices across organization');
    } else if (trend < 0) {
      recommendations.push('Investigate root causes of declining scores');
      recommendations.push('Implement corrective action plan');
    } else {
      recommendations.push('Identify opportunities for improvement');
      recommendations.push('Benchmark against industry leaders');
    }
    
    return recommendations;
  }

  private mapBusinessImpactToComplexity(impact: SecurityWeakness['businessImpact']): PrioritizedRecommendation['complexity'] {
    const mapping = { 'low': 'low', 'medium': 'medium', 'high': 'high', 'critical': 'high' } as const;
    return mapping[impact];
  }

  private calculateExpectedROI(weakness: SecurityWeakness): number {
    // Implementation would calculate ROI based on risk reduction and cost
    const riskMultipliers = { 'low': 1.2, 'medium': 2.0, 'high': 3.5, 'critical': 5.0 };
    return riskMultipliers[weakness.riskLevel];
  }

  private mapRiskToTimeline(risk: RiskLevel): string {
    const timelines = { 'low': '12+ months', 'medium': '6-12 months', 'high': '3-6 months', 'critical': '0-3 months' };
    return timelines[risk];
  }

  private rankRecommendations(recommendations: PrioritizedRecommendation[]): PrioritizedRecommendation[] {
    return recommendations
      .map((rec, index) => ({
        ...rec,
        rank: index + 1
      }))
      .sort((a, b) => {
        // Sort by expected ROI and risk level
        const aScore = a.expectedROI * (a.riskIfNotImplemented === 'critical' ? 4 : 
                                       a.riskIfNotImplemented === 'high' ? 3 :
                                       a.riskIfNotImplemented === 'medium' ? 2 : 1);
        const bScore = b.expectedROI * (b.riskIfNotImplemented === 'critical' ? 4 : 
                                       b.riskIfNotImplemented === 'high' ? 3 :
                                       b.riskIfNotImplemented === 'medium' ? 2 : 1);
        return bScore - aScore;
      })
      .map((rec, index) => ({ ...rec, rank: index + 1 }));
  }

  private compareGrades(current: SecurityPostureAssessment['postureGrade'], previous: SecurityPostureAssessment['postureGrade']): number {
    const gradeValues = { 'F': 0, 'D': 1, 'C': 2, 'B': 3, 'A': 4, 'A+': 5 };
    return gradeValues[current] - gradeValues[previous];
  }

  private compareRiskLevels(current: RiskLevel, previous: RiskLevel): 'improving' | 'stable' | 'declining' {
    const riskValues = { 'low': 1, 'medium': 2, 'high': 3, 'critical': 4 };
    const currentValue = riskValues[current];
    const previousValue = riskValues[previous];
    
    if (currentValue < previousValue) {return 'improving';}
    if (currentValue > previousValue) {return 'declining';}
    return 'stable';
  }

  private storeAssessmentHistory(organizationId: string, assessment: SecurityPostureAssessment): void {
    const history = this.assessmentHistory.get(organizationId) || [];
    history.push(assessment);
    
    // Keep only recent assessments based on retention policy
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - this.config.historyRetentionDays);
    
    const filteredHistory = history.filter(h => h.assessmentDate >= cutoffDate);
    this.assessmentHistory.set(organizationId, filteredHistory);
  }
}

/**
 * Assessment comparison result
 */
export interface AssessmentComparison {
  scoreChange: number;
  gradeChange: number;
  improvementAreas: string[];
  regressionAreas: string[];
  overallTrend: 'improving' | 'stable' | 'declining';
  riskTrend: 'improving' | 'stable' | 'declining';
}

/**
 * Factory function to create compliance scoring engine
 */
export function createComplianceScoringEngine(config?: Partial<ComplianceScoringConfig>): ComplianceScoringEngine {
  return new ComplianceScoringEngine(config);
}

// Export singleton instance for convenience
export const complianceScoringEngine = new ComplianceScoringEngine();

export default ComplianceScoringEngine;