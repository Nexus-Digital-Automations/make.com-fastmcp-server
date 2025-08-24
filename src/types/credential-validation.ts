/**
 * @fileoverview Comprehensive Type Definitions for Credential Validation
 * 
 * Provides enterprise-grade type definitions for concurrent credential validation,
 * security assessment, compliance checking, and risk analysis.
 */

/**
 * Supported credential types for validation
 */
export type CredentialType = 
  | 'api_key'
  | 'password'
  | 'certificate'
  | 'token'
  | 'secret'
  | 'ssh_key'
  | 'jwt'
  | 'oauth_token'
  | 'database_password'
  | 'encryption_key';

/**
 * Security severity levels
 */
export type SecuritySeverity = 'low' | 'medium' | 'high' | 'critical';

/**
 * Risk levels for threat assessment
 */
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

/**
 * Compliance status values
 */
export type ComplianceStatus = 'compliant' | 'non-compliant' | 'partial' | 'not-applicable';

/**
 * Environment types for context-aware validation
 */
export type Environment = 'production' | 'staging' | 'development' | 'test';

/**
 * Validation priority levels
 */
export type ValidationPriority = 'immediate' | 'high' | 'medium' | 'low';

/**
 * Remediation categories
 */
export type RemediationCategory = 
  | 'regeneration'
  | 'rotation'
  | 'monitoring'
  | 'policy'
  | 'training'
  | 'infrastructure'
  | 'compliance';

/**
 * Supported compliance frameworks
 */
export type ComplianceFramework = 
  | 'SOC2'
  | 'ISO27001'
  | 'PCI-DSS'
  | 'GDPR'
  | 'HIPAA'
  | 'FedRAMP'
  | 'NIST'
  | 'CIS'
  | 'OWASP';

/**
 * Security grade scale
 */
export type SecurityGrade = 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';

/**
 * Certificate validation status
 */
export type CertificateStatus = 
  | 'valid'
  | 'expired'
  | 'revoked'
  | 'self-signed'
  | 'invalid-chain'
  | 'weak-signature'
  | 'invalid-purpose';

/**
 * Extended credential validation context
 */
export interface ValidationContext {
  /** Service or application using the credential */
  service?: string;
  /** Deployment environment */
  environment?: Environment;
  /** User ID associated with the credential */
  userId?: string;
  /** Organization ID for multi-tenant scenarios */
  organizationId?: string;
  /** Geographic region for compliance requirements */
  region?: string;
  /** Industry sector for specialized compliance */
  industry?: string;
  /** Custom metadata for validation rules */
  metadata?: Record<string, unknown>;
  /** IP address of the request origin */
  sourceIp?: string;
  /** User agent information */
  userAgent?: string;
  /** Timestamp of credential creation */
  createdAt?: Date;
  /** Last usage timestamp */
  lastUsed?: Date;
  /** Usage frequency data */
  usageStats?: UsageStatistics;
}

/**
 * Usage statistics for credential assessment
 */
export interface UsageStatistics {
  /** Total number of times used */
  totalUses: number;
  /** Average daily usage */
  dailyAverage: number;
  /** Peak usage periods */
  peakHours: number[];
  /** Geographic usage distribution */
  regions: string[];
  /** Services that use this credential */
  services: string[];
  /** Last 30 days usage trend */
  recentTrend: 'increasing' | 'stable' | 'decreasing';
}

/**
 * Advanced validation options
 */
export interface ValidationOptions {
  /** Enable strict validation mode */
  strictMode?: boolean;
  /** Compliance frameworks to validate against */
  complianceFrameworks?: ComplianceFramework[];
  /** Custom validation rules */
  customRules?: ValidationRule[];
  /** Validation timeout in milliseconds */
  timeoutMs?: number;
  /** Enable deep entropy analysis */
  deepEntropyAnalysis?: boolean;
  /** Check against known breach databases */
  checkBreachDatabases?: boolean;
  /** Validate certificate chains */
  validateCertificateChains?: boolean;
  /** Maximum allowed credential age */
  maxAgeMs?: number;
  /** Required minimum security score */
  minSecurityScore?: number;
  /** Enable real-time threat intelligence */
  enableThreatIntelligence?: boolean;
  /** Industry-specific validation rules */
  industryRules?: IndustryValidationRules;
}

/**
 * Industry-specific validation rules
 */
export interface IndustryValidationRules {
  /** Healthcare industry requirements */
  healthcare?: {
    hipaaCompliance: boolean;
    phiProtection: boolean;
    auditLogging: boolean;
  };
  /** Financial services requirements */
  financial?: {
    pciCompliance: boolean;
    soxCompliance: boolean;
    fraudDetection: boolean;
  };
  /** Government/public sector requirements */
  government?: {
    fedrampCompliance: boolean;
    fismaCompliance: boolean;
    nationalSecurity: boolean;
  };
}

/**
 * Custom validation rule definition
 */
export interface ValidationRule {
  /** Unique rule identifier */
  id: string;
  /** Human-readable rule name */
  name: string;
  /** Detailed description of the rule */
  description: string;
  /** Rule severity level */
  severity: SecuritySeverity;
  /** Category of validation */
  category: 'format' | 'security' | 'compliance' | 'policy' | 'business';
  /** Regular expression pattern (optional) */
  pattern?: RegExp;
  /** Custom validator function (optional) */
  validator?: (credential: string, context?: ValidationContext) => Promise<boolean> | boolean;
  /** Error message when validation fails */
  message: string;
  /** Recommended remediation steps */
  remediation?: string[];
  /** Applicable credential types */
  applicableTypes?: CredentialType[];
  /** Environment restrictions */
  environments?: Environment[];
  /** Compliance framework associations */
  complianceFrameworks?: ComplianceFramework[];
  /** Custom metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Extended validation result with comprehensive analysis
 */
export interface ExtendedValidationResult {
  /** Unique job identifier */
  jobId: string;
  /** Overall validation status */
  isValid: boolean;
  /** Security score (0-100) */
  score: number;
  /** Security grade */
  grade: SecurityGrade;
  /** Processing time in milliseconds */
  processingTimeMs: number;
  /** Worker ID that processed this job */
  workerId: string;
  /** Validation timestamp */
  timestamp: Date;
  
  /** Critical errors that prevent usage */
  errors: ValidationError[];
  /** Warnings about potential issues */
  warnings: ValidationWarning[];
  /** Identified security strengths */
  strengths: SecurityStrength[];
  /** Security weaknesses found */
  weaknesses: SecurityWeakness[];
  /** Recommended actions */
  recommendations: SecurityRecommendation[];
  
  /** Compliance assessment results */
  complianceResults?: ComplianceAssessment[];
  /** Risk analysis results */
  riskAnalysis?: RiskAnalysis;
  /** Remediation action plan */
  remediationSteps?: RemediationStep[];
  /** Threat intelligence findings */
  threatIntelligence?: ThreatIntelligenceResult;
  /** Certificate analysis (for certificate types) */
  certificateAnalysis?: CertificateAnalysisResult;
  /** Entropy analysis results */
  entropyAnalysis?: EntropyAnalysisResult;
  /** Breach database check results */
  breachAnalysis?: BreachAnalysisResult;
}

/**
 * Detailed validation error information
 */
export interface ValidationError {
  /** Error code for programmatic handling */
  code: string;
  /** Human-readable error message */
  message: string;
  /** Error severity level */
  severity: SecuritySeverity;
  /** Category of error */
  category: 'format' | 'security' | 'compliance' | 'policy';
  /** Field or aspect that failed validation */
  field?: string;
  /** Expected value or format */
  expected?: string;
  /** Actual value that caused the error */
  actual?: string;
  /** Remediation suggestions */
  remediation?: string[];
  /** Associated validation rule ID */
  ruleId?: string;
}

/**
 * Validation warning details
 */
export interface ValidationWarning {
  /** Warning code */
  code: string;
  /** Warning message */
  message: string;
  /** Warning category */
  category: 'security' | 'compliance' | 'best-practice' | 'performance';
  /** Impact assessment */
  impact: 'low' | 'medium' | 'high';
  /** Suggested actions */
  suggestions?: string[];
  /** Associated compliance frameworks */
  frameworks?: ComplianceFramework[];
}

/**
 * Security strength identification
 */
export interface SecurityStrength {
  /** Strength identifier */
  id: string;
  /** Description of the strength */
  description: string;
  /** Category of strength */
  category: 'entropy' | 'format' | 'policy' | 'compliance';
  /** Contribution to overall security score */
  scoreContribution: number;
  /** Supporting evidence */
  evidence?: string[];
}

/**
 * Security weakness details
 */
export interface SecurityWeakness {
  /** Weakness identifier */
  id: string;
  /** Description of the weakness */
  description: string;
  /** Risk category */
  category: 'entropy' | 'pattern' | 'exposure' | 'age' | 'privilege';
  /** Risk level */
  riskLevel: RiskLevel;
  /** Potential impact */
  impact: string;
  /** Exploitation likelihood */
  likelihood: number; // 0-1
  /** Mitigation strategies */
  mitigation?: string[];
}

/**
 * Security recommendation with prioritization
 */
export interface SecurityRecommendation {
  /** Recommendation ID */
  id: string;
  /** Priority level */
  priority: ValidationPriority;
  /** Action to take */
  action: string;
  /** Detailed description */
  description: string;
  /** Implementation effort estimate */
  effort: 'low' | 'medium' | 'high';
  /** Category of recommendation */
  category: RemediationCategory;
  /** Implementation timeline */
  timeline?: string;
  /** Expected security improvement */
  securityImprovement: number; // 0-100
  /** Cost-benefit ratio */
  costBenefit?: 'low' | 'medium' | 'high';
}

/**
 * Comprehensive compliance assessment
 */
export interface ComplianceAssessment {
  /** Compliance framework */
  framework: ComplianceFramework;
  /** Overall compliance status */
  compliant: boolean;
  /** Compliance score (0-100) */
  score: number;
  /** Detailed requirements analysis */
  requirements: ComplianceRequirement[];
  /** Identified compliance gaps */
  gaps: ComplianceGap[];
  /** Framework-specific recommendations */
  recommendations: string[];
  /** Assessment timestamp */
  assessedAt: Date;
  /** Next assessment due date */
  nextAssessmentDue?: Date;
}

/**
 * Individual compliance requirement
 */
export interface ComplianceRequirement {
  /** Requirement identifier */
  id: string;
  /** Requirement title */
  title: string;
  /** Detailed description */
  description: string;
  /** Compliance status */
  status: ComplianceStatus;
  /** Supporting evidence */
  evidence?: string;
  /** Remediation steps if non-compliant */
  remediation?: string;
  /** Criticality level */
  criticality: SecuritySeverity;
  /** Last assessment date */
  lastAssessed?: Date;
}

/**
 * Compliance gap identification
 */
export interface ComplianceGap {
  /** Gap identifier */
  id: string;
  /** Requirement that has the gap */
  requirementId: string;
  /** Description of the gap */
  description: string;
  /** Risk level of the gap */
  riskLevel: RiskLevel;
  /** Remediation priority */
  priority: ValidationPriority;
  /** Estimated remediation effort */
  effort: 'low' | 'medium' | 'high';
  /** Remediation steps */
  remediationSteps: string[];
  /** Target completion date */
  targetDate?: Date;
}

/**
 * Comprehensive risk analysis
 */
export interface RiskAnalysis {
  /** Overall risk assessment */
  overallRisk: RiskLevel;
  /** Risk score (0-100) */
  riskScore: number;
  /** Individual risk factors */
  riskFactors: RiskFactor[];
  /** Mitigation strategies */
  mitigationStrategies: MitigationStrategy[];
  /** Priority score for remediation */
  priorityScore: number;
  /** Potential exposure paths */
  exposurePaths: ExposurePath[];
  /** Business impact assessment */
  businessImpact?: BusinessImpactAssessment;
  /** Regulatory impact */
  regulatoryImpact?: RegulatoryImpactAssessment;
}

/**
 * Individual risk factor analysis
 */
export interface RiskFactor {
  /** Risk factor ID */
  id: string;
  /** Risk category */
  category: 'entropy' | 'pattern' | 'exposure' | 'age' | 'privilege' | 'compliance';
  /** Severity level */
  severity: SecuritySeverity;
  /** Risk description */
  description: string;
  /** Potential impact */
  impact: string;
  /** Likelihood of exploitation (0-1) */
  likelihood: number;
  /** Confidence level in assessment (0-1) */
  confidence: number;
  /** Contributing factors */
  contributingFactors?: string[];
  /** Historical precedents */
  precedents?: string[];
  /** Recommended mitigation */
  mitigation?: string;
}

/**
 * Mitigation strategy details
 */
export interface MitigationStrategy {
  /** Strategy ID */
  id: string;
  /** Strategy name */
  name: string;
  /** Implementation approach */
  approach: string;
  /** Effectiveness rating (0-1) */
  effectiveness: number;
  /** Implementation complexity */
  complexity: 'low' | 'medium' | 'high';
  /** Resource requirements */
  resources: ResourceRequirement[];
  /** Timeline for implementation */
  timeline: string;
  /** Success metrics */
  successMetrics?: string[];
}

/**
 * Resource requirement for mitigation
 */
export interface ResourceRequirement {
  /** Resource type */
  type: 'human' | 'financial' | 'technical' | 'time';
  /** Description of requirement */
  description: string;
  /** Estimated quantity */
  quantity?: number;
  /** Unit of measurement */
  unit?: string;
  /** Associated cost */
  cost?: number;
}

/**
 * Potential exposure path
 */
export interface ExposurePath {
  /** Path identifier */
  id: string;
  /** Path description */
  description: string;
  /** Attack vector */
  vector: 'network' | 'local' | 'physical' | 'social' | 'supply-chain';
  /** Likelihood of exploitation */
  likelihood: number; // 0-1
  /** Impact if exploited */
  impact: SecuritySeverity;
  /** Detection difficulty */
  detectability: 'easy' | 'medium' | 'hard' | 'very-hard';
  /** Prevention measures */
  prevention?: string[];
}

/**
 * Business impact assessment
 */
export interface BusinessImpactAssessment {
  /** Financial impact estimate */
  financialImpact: {
    low: number;
    high: number;
    currency: string;
  };
  /** Operational impact */
  operationalImpact: 'minimal' | 'moderate' | 'significant' | 'severe';
  /** Reputation impact */
  reputationImpact: 'minimal' | 'moderate' | 'significant' | 'severe';
  /** Customer impact */
  customerImpact: 'minimal' | 'moderate' | 'significant' | 'severe';
  /** Recovery time estimate */
  recoveryTimeEstimate: string;
  /** Business continuity risk */
  continuityRisk: RiskLevel;
}

/**
 * Regulatory impact assessment
 */
export interface RegulatoryImpactAssessment {
  /** Applicable regulations */
  regulations: string[];
  /** Potential penalties */
  penalties: {
    financial?: number;
    operational?: string;
    legal?: string;
  };
  /** Notification requirements */
  notificationRequired: boolean;
  /** Reporting timeline */
  reportingTimeline?: string;
  /** Regulatory bodies to notify */
  regulatoryBodies?: string[];
}

/**
 * Remediation step with detailed planning
 */
export interface RemediationStep {
  /** Step identifier */
  id: string;
  /** Priority level */
  priority: ValidationPriority;
  /** Action to perform */
  action: string;
  /** Detailed description */
  description: string;
  /** Implementation effort */
  estimatedEffort: 'low' | 'medium' | 'high';
  /** Remediation category */
  category: RemediationCategory;
  /** Implementation timeline */
  timeline?: string;
  /** Prerequisites for this step */
  prerequisites?: string[];
  /** Expected outcome */
  expectedOutcome: string;
  /** Success criteria */
  successCriteria?: string[];
  /** Risk if not implemented */
  riskIfNotImplemented?: RiskLevel;
  /** Cost estimate */
  costEstimate?: {
    amount: number;
    currency: string;
    confidence: 'low' | 'medium' | 'high';
  };
}

/**
 * Threat intelligence analysis result
 */
export interface ThreatIntelligenceResult {
  /** Intelligence sources queried */
  sources: string[];
  /** Known threats identified */
  threats: ThreatIndicator[];
  /** Reputation score */
  reputationScore: number; // 0-100
  /** Analysis confidence */
  confidence: number; // 0-1
  /** Last updated timestamp */
  lastUpdated: Date;
  /** Recommended actions */
  recommendations: string[];
}

/**
 * Threat indicator from intelligence sources
 */
export interface ThreatIndicator {
  /** Indicator type */
  type: 'credential' | 'pattern' | 'source' | 'behavior';
  /** Threat description */
  description: string;
  /** Severity level */
  severity: SecuritySeverity;
  /** Confidence in indicator */
  confidence: number; // 0-1
  /** First seen timestamp */
  firstSeen?: Date;
  /** Last seen timestamp */
  lastSeen?: Date;
  /** Associated campaigns */
  campaigns?: string[];
  /** Mitigation recommendations */
  mitigation?: string[];
}

/**
 * Certificate analysis result
 */
export interface CertificateAnalysisResult {
  /** Certificate status */
  status: CertificateStatus;
  /** Certificate details */
  details: CertificateDetails;
  /** Chain validation results */
  chainValidation: ChainValidationResult[];
  /** Expiry analysis */
  expiryAnalysis: ExpiryAnalysis;
  /** Signature analysis */
  signatureAnalysis: SignatureAnalysis;
  /** Usage validation */
  usageValidation: UsageValidationResult;
  /** Security recommendations */
  recommendations: string[];
}

/**
 * Certificate details structure
 */
export interface CertificateDetails {
  /** Certificate subject */
  subject: string;
  /** Certificate issuer */
  issuer: string;
  /** Serial number */
  serialNumber: string;
  /** Not valid before */
  notBefore: Date;
  /** Not valid after */
  notAfter: Date;
  /** Public key algorithm */
  publicKeyAlgorithm: string;
  /** Signature algorithm */
  signatureAlgorithm: string;
  /** Key size */
  keySize: number;
  /** Extensions */
  extensions?: CertificateExtension[];
}

/**
 * Certificate extension details
 */
export interface CertificateExtension {
  /** Extension OID */
  oid: string;
  /** Extension name */
  name: string;
  /** Critical flag */
  critical: boolean;
  /** Extension value */
  value: string;
}

/**
 * Chain validation result
 */
export interface ChainValidationResult {
  /** Chain level (0 = leaf, 1 = intermediate, etc.) */
  level: number;
  /** Certificate in chain */
  certificate: CertificateDetails;
  /** Validation status */
  status: 'valid' | 'invalid' | 'warning';
  /** Issues found */
  issues: string[];
  /** Trust anchor reached */
  trustAnchor?: boolean;
}

/**
 * Certificate expiry analysis
 */
export interface ExpiryAnalysis {
  /** Days until expiry */
  daysUntilExpiry: number;
  /** Expiry status */
  status: 'valid' | 'expiring-soon' | 'expired';
  /** Renewal recommended */
  renewalRecommended: boolean;
  /** Renewal timeline */
  renewalTimeline?: string;
  /** Auto-renewal available */
  autoRenewalAvailable?: boolean;
}

/**
 * Signature analysis result
 */
export interface SignatureAnalysis {
  /** Signature algorithm */
  algorithm: string;
  /** Algorithm strength */
  strength: 'weak' | 'adequate' | 'strong';
  /** Hash algorithm */
  hashAlgorithm: string;
  /** Signature valid */
  signatureValid: boolean;
  /** Weakness details */
  weaknesses?: string[];
  /** Upgrade recommendations */
  upgradeRecommendations?: string[];
}

/**
 * Usage validation result
 */
export interface UsageValidationResult {
  /** Intended usage valid */
  usageValid: boolean;
  /** Key usage extensions */
  keyUsage?: string[];
  /** Extended key usage */
  extendedKeyUsage?: string[];
  /** Usage violations */
  violations?: string[];
  /** Usage recommendations */
  recommendations?: string[];
}

/**
 * Entropy analysis result
 */
export interface EntropyAnalysisResult {
  /** Shannon entropy value */
  shannonEntropy: number;
  /** Entropy rating */
  entropyRating: 'very-low' | 'low' | 'medium' | 'high' | 'very-high';
  /** Character set analysis */
  characterSetAnalysis: CharacterSetAnalysis;
  /** Pattern analysis */
  patternAnalysis: PatternAnalysis;
  /** Randomness tests */
  randomnessTests: RandomnessTestResult[];
  /** Entropy recommendations */
  recommendations: string[];
}

/**
 * Character set analysis
 */
export interface CharacterSetAnalysis {
  /** Character sets present */
  presentSets: string[];
  /** Character set diversity */
  diversity: number; // 0-1
  /** Distribution analysis */
  distribution: CharacterDistribution[];
  /** Bias detection */
  biasDetected: boolean;
  /** Bias details */
  biasDetails?: string[];
}

/**
 * Character distribution analysis
 */
export interface CharacterDistribution {
  /** Character set name */
  set: string;
  /** Frequency count */
  frequency: number;
  /** Expected frequency */
  expectedFrequency: number;
  /** Deviation from expected */
  deviation: number;
}

/**
 * Pattern analysis result
 */
export interface PatternAnalysis {
  /** Patterns detected */
  patterns: PatternMatch[];
  /** Repetition analysis */
  repetitions: RepetitionAnalysis;
  /** Sequence analysis */
  sequences: SequenceAnalysis;
  /** Dictionary matches */
  dictionaryMatches: DictionaryMatch[];
}

/**
 * Pattern match details
 */
export interface PatternMatch {
  /** Pattern type */
  type: string;
  /** Pattern description */
  description: string;
  /** Match positions */
  positions: number[];
  /** Severity level */
  severity: SecuritySeverity;
  /** Impact on security */
  impact: string;
}

/**
 * Repetition analysis
 */
export interface RepetitionAnalysis {
  /** Repeating sequences found */
  sequences: string[];
  /** Maximum repetition length */
  maxLength: number;
  /** Repetition ratio */
  ratio: number; // 0-1
  /** Impact assessment */
  impact: SecuritySeverity;
}

/**
 * Sequence analysis
 */
export interface SequenceAnalysis {
  /** Sequential patterns */
  patterns: string[];
  /** Longest sequence */
  longestSequence: number;
  /** Sequence types */
  types: ('ascending' | 'descending' | 'keyboard')[];
  /** Security impact */
  impact: SecuritySeverity;
}

/**
 * Dictionary match result
 */
export interface DictionaryMatch {
  /** Matched word */
  word: string;
  /** Dictionary source */
  dictionary: string;
  /** Match confidence */
  confidence: number; // 0-1
  /** Position in credential */
  position: number;
  /** Security implication */
  implication: string;
}

/**
 * Randomness test result
 */
export interface RandomnessTestResult {
  /** Test name */
  testName: string;
  /** Test result */
  result: 'pass' | 'fail' | 'warning';
  /** Test statistic */
  statistic: number;
  /** P-value */
  pValue?: number;
  /** Test interpretation */
  interpretation: string;
}

/**
 * Breach analysis result
 */
export interface BreachAnalysisResult {
  /** Breach databases checked */
  databasesChecked: string[];
  /** Matches found */
  matches: BreachMatch[];
  /** Overall risk assessment */
  riskLevel: RiskLevel;
  /** Recommendations */
  recommendations: string[];
  /** Last check timestamp */
  lastChecked: Date;
}

/**
 * Breach database match
 */
export interface BreachMatch {
  /** Breach database */
  database: string;
  /** Breach name/event */
  breachName: string;
  /** Breach date */
  breachDate: Date;
  /** Match confidence */
  confidence: number; // 0-1
  /** Match type */
  matchType: 'exact' | 'partial' | 'pattern';
  /** Associated data */
  associatedData?: string[];
  /** Severity assessment */
  severity: SecuritySeverity;
}

/**
 * Batch validation request
 */
export interface BatchValidationRequest {
  /** Batch identifier */
  batchId: string;
  /** Jobs in batch */
  jobs: ValidationJob[];
  /** Batch options */
  options?: {
    /** Process jobs in parallel */
    parallel?: boolean;
    /** Maximum concurrency */
    maxConcurrency?: number;
    /** Stop on first error */
    stopOnError?: boolean;
    /** Timeout for entire batch */
    batchTimeoutMs?: number;
  };
}

/**
 * Batch validation result
 */
export interface BatchValidationResult {
  /** Batch identifier */
  batchId: string;
  /** Overall batch status */
  status: 'completed' | 'failed' | 'timeout' | 'cancelled';
  /** Processing summary */
  summary: {
    /** Total jobs in batch */
    total: number;
    /** Successfully processed */
    successful: number;
    /** Failed jobs */
    failed: number;
    /** Skipped jobs */
    skipped: number;
    /** Total processing time */
    totalProcessingTimeMs: number;
    /** Average processing time per job */
    averageProcessingTimeMs: number;
  };
  /** Individual job results */
  results: Map<string, ExtendedValidationResult | Error>;
  /** Batch-level insights */
  batchInsights?: BatchInsights;
}

/**
 * Batch-level insights and analytics
 */
export interface BatchInsights {
  /** Security score distribution */
  scoreDistribution: {
    'A+': number;
    'A': number;
    'B': number;
    'C': number;
    'D': number;
    'F': number;
  };
  /** Common issues across batch */
  commonIssues: CommonIssue[];
  /** Compliance summary */
  complianceSummary: ComplianceFramework[];
  /** Risk distribution */
  riskDistribution: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
  /** Recommendations for batch */
  batchRecommendations: string[];
}

/**
 * Common issue across batch
 */
export interface CommonIssue {
  /** Issue type */
  type: string;
  /** Issue description */
  description: string;
  /** Number of affected credentials */
  affectedCount: number;
  /** Percentage of batch affected */
  affectedPercentage: number;
  /** Severity level */
  severity: SecuritySeverity;
  /** Batch-wide remediation */
  batchRemediation?: string[];
}

/**
 * Validation job for worker processing
 */
export interface ValidationJob {
  /** Unique job identifier */
  id: string;
  /** Type of credential to validate */
  type: CredentialType;
  /** Credential value to validate */
  credential: string;
  /** Validation context */
  context?: ValidationContext;
  /** Validation options */
  options?: ValidationOptions;
  /** Job metadata */
  metadata?: {
    /** Job submission timestamp */
    submittedAt?: Date;
    /** Job source system */
    source?: string;
    /** Priority override */
    priority?: ValidationPriority;
    /** Retry count */
    retryCount?: number;
    /** Parent batch ID */
    batchId?: string;
  };
}

/**
 * Worker pool performance metrics
 */
export interface WorkerPoolMetrics {
  /** Total jobs processed */
  totalJobs: number;
  /** Successfully completed jobs */
  completedJobs: number;
  /** Failed jobs */
  failedJobs: number;
  /** Jobs currently in queue */
  queuedJobs: number;
  /** Jobs currently processing */
  processingJobs: number;
  /** Average processing time */
  averageProcessingTimeMs: number;
  /** Jobs per second throughput */
  throughputPerSecond: number;
  /** Current queue length */
  queueLength: number;
  /** Active worker count */
  activeWorkers: number;
  /** Idle worker count */
  idleWorkers: number;
  /** Memory usage in MB */
  memoryUsageMB: number;
  /** CPU usage percentage */
  cpuUsagePercent: number;
  /** Success rate percentage */
  successRate: number;
  /** Error rate percentage */
  errorRate: number;
}

/**
 * Agent configuration for specialized validation
 */
export interface ValidationAgentConfig {
  /** Agent identifier */
  agentId: string;
  /** Agent specialization */
  specialization: CredentialType[];
  /** Worker pool configuration */
  workerPool: {
    /** Minimum workers */
    minWorkers: number;
    /** Maximum workers */
    maxWorkers: number;
    /** Worker idle timeout */
    idleTimeoutMs: number;
    /** Job timeout */
    jobTimeoutMs: number;
    /** Maximum queue size */
    maxQueueSize: number;
  };
  /** Performance targets */
  performanceTargets: {
    /** Target throughput (jobs/sec) */
    targetThroughput: number;
    /** Maximum latency (ms) */
    maxLatencyMs: number;
    /** Target success rate (%) */
    targetSuccessRate: number;
  };
  /** Integration settings */
  integration: {
    /** Enable threat intelligence */
    enableThreatIntelligence: boolean;
    /** Enable breach database checks */
    enableBreachChecks: boolean;
    /** Enable certificate validation */
    enableCertificateValidation: boolean;
    /** External service timeouts */
    externalServiceTimeoutMs: number;
  };
}