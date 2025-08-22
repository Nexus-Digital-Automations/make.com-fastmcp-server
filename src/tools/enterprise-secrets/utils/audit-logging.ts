/**
 * @fileoverview Audit Logging Utility Module
 * Centralized audit logging utilities for enterprise secrets management compliance
 */

import { auditLogger } from '../../../lib/audit-logger.js';

/**
 * Audit event types for enterprise secrets management
 */
export type EnterpriseSecretsAuditEvent =
  | 'vault_cluster_configured'
  | 'vault_cluster_sealed'
  | 'vault_cluster_unsealed' 
  | 'hsm_configured'
  | 'hsm_key_generated'
  | 'hsm_key_rotated'
  | 'secret_engine_configured'
  | 'secret_generated'
  | 'secret_retrieved'
  | 'secret_rotated'
  | 'rbac_policy_created'
  | 'rbac_policy_modified'
  | 'secret_leakage_detected'
  | 'breach_detection_triggered'
  | 'compliance_report_generated'
  | 'audit_system_configured';

/**
 * Risk levels for audit events
 */
export type AuditRiskLevel = 'low' | 'medium' | 'high' | 'critical';

/**
 * Compliance frameworks
 */
export type ComplianceFramework = 'SOC2' | 'PCI_DSS' | 'GDPR' | 'FIPS_140_2' | 'COMMON_CRITERIA' | 'ISO_27001';

/**
 * Audit event details interface
 */
export interface EnterpriseAuditEventDetails {
  clusterId?: string;
  nodeId?: string;
  provider?: string;
  secretEngine?: string;
  secretPath?: string;
  policyName?: string;
  userId?: string;
  roleId?: string;
  ipAddress?: string;
  userAgent?: string;
  complianceFramework?: ComplianceFramework[];
  [key: string]: unknown;
}

/**
 * Enhanced audit logging for enterprise secrets management
 */
export class EnterpriseAuditLogger {
  private static instance: EnterpriseAuditLogger | null = null;

  private constructor() {}

  public static getInstance(): EnterpriseAuditLogger {
    if (!EnterpriseAuditLogger.instance) {
      EnterpriseAuditLogger.instance = new EnterpriseAuditLogger();
    }
    return EnterpriseAuditLogger.instance;
  }

  /**
   * Log enterprise secrets management audit event
   */
  public async logEvent(
    action: EnterpriseSecretsAuditEvent,
    success: boolean,
    details: EnterpriseAuditEventDetails = {},
    riskLevel: AuditRiskLevel = 'low'
  ): Promise<void> {
    const auditEvent = {
      level: this.determineLogLevel(success, riskLevel),
      category: 'security' as const,
      action,
      success,
      details: {
        ...details,
        timestamp: new Date().toISOString(),
        source: 'enterprise-secrets-management',
        auditVersion: '2.0',
      },
      riskLevel,
    };

    await auditLogger.logEvent(auditEvent);
  }

  /**
   * Log compliance-specific event
   */
  public async logComplianceEvent(
    action: EnterpriseSecretsAuditEvent,
    complianceFramework: ComplianceFramework | ComplianceFramework[],
    success: boolean,
    details: EnterpriseAuditEventDetails = {},
    riskLevel: AuditRiskLevel = 'low'
  ): Promise<void> {
    const frameworks = Array.isArray(complianceFramework) ? complianceFramework : [complianceFramework];
    
    await this.logEvent(action, success, {
      ...details,
      complianceFramework: frameworks,
      complianceRelevant: true,
    }, riskLevel);
  }

  /**
   * Log security violation or breach
   */
  public async logSecurityViolation(
    violation: string,
    details: EnterpriseAuditEventDetails = {},
    riskLevel: AuditRiskLevel = 'high'
  ): Promise<void> {
    await this.logEvent('breach_detection_triggered', false, {
      ...details,
      violation,
      securityIncident: true,
      requiresImmediateAction: riskLevel === 'critical',
    }, riskLevel);
  }

  /**
   * Log access attempt (successful or failed)
   */
  public async logAccessAttempt(
    resourceType: string,
    resourceId: string,
    success: boolean,
    details: EnterpriseAuditEventDetails = {}
  ): Promise<void> {
    const action = success ? 'secret_retrieved' : 'secret_retrieval_failed';
    const riskLevel: AuditRiskLevel = success ? 'low' : 'medium';

    await this.logEvent(action as EnterpriseSecretsAuditEvent, success, {
      ...details,
      resourceType,
      resourceId,
      accessAttempt: true,
    }, riskLevel);
  }

  /**
   * Log administrative action
   */
  public async logAdminAction(
    action: EnterpriseSecretsAuditEvent,
    adminUserId: string,
    targetResource: string,
    details: EnterpriseAuditEventDetails = {}
  ): Promise<void> {
    await this.logEvent(action, true, {
      ...details,
      adminUserId,
      targetResource,
      administrativeAction: true,
      requiresApproval: this.requiresApprovalWorkflow(action),
    }, 'medium');
  }

  /**
   * Log key lifecycle event
   */
  public async logKeyLifecycleEvent(
    operation: 'created' | 'rotated' | 'retired' | 'compromised',
    keyId: string,
    keyType: string,
    details: EnterpriseAuditEventDetails = {}
  ): Promise<void> {
    const actionMap = {
      created: 'hsm_key_generated',
      rotated: 'hsm_key_rotated',
      retired: 'hsm_key_retired',
      compromised: 'hsm_key_compromised'
    } as const;

    const riskLevelMap = {
      created: 'low',
      rotated: 'low', 
      retired: 'medium',
      compromised: 'critical'
    } as const;

    await this.logEvent(
      actionMap[operation] as EnterpriseSecretsAuditEvent,
      operation !== 'compromised',
      {
        ...details,
        keyId,
        keyType,
        keyOperation: operation,
        keyLifecycleEvent: true,
      },
      riskLevelMap[operation]
    );
  }

  /**
   * Generate audit trail summary for compliance reporting
   */
  public async generateAuditTrailSummary(
    _timeRange: { start: Date; end: Date },
    _complianceFramework?: ComplianceFramework
  ): Promise<{
    totalEvents: number;
    eventsByType: Record<string, number>;
    riskDistribution: Record<AuditRiskLevel, number>;
    complianceEvents: number;
    securityViolations: number;
    recommendations: string[];
  }> {
    // This would typically query the audit log database
    // For now, return a mock summary structure
    return {
      totalEvents: 0,
      eventsByType: {},
      riskDistribution: { low: 0, medium: 0, high: 0, critical: 0 },
      complianceEvents: 0,
      securityViolations: 0,
      recommendations: [
        'Review high-risk events for potential security improvements',
        'Ensure regular key rotation policies are being followed',
        'Monitor failed access attempts for patterns',
      ]
    };
  }

  /**
   * Determine log level based on success and risk
   */
  private determineLogLevel(success: boolean, riskLevel: AuditRiskLevel): 'info' | 'warn' | 'error' {
    if (!success || riskLevel === 'critical') {return 'error';}
    if (riskLevel === 'high' || riskLevel === 'medium') {return 'warn';}
    return 'info';
  }

  /**
   * Check if action requires approval workflow
   */
  private requiresApprovalWorkflow(action: EnterpriseSecretsAuditEvent): boolean {
    const highRiskActions = [
      'vault_cluster_configured',
      'hsm_configured',
      'rbac_policy_created',
      'rbac_policy_modified'
    ];
    return highRiskActions.includes(action);
  }
}

/**
 * Audit logging utilities and helpers
 */
export const AuditUtils = {
  /**
   * Create standardized audit context from request
   */
  createAuditContext(request?: {
    ip?: string;
    userAgent?: string;
    userId?: string;
    sessionId?: string;
  }): Partial<EnterpriseAuditEventDetails> {
    return {
      ipAddress: request?.ip,
      userAgent: request?.userAgent,
      userId: request?.userId,
      sessionId: request?.sessionId,
      timestamp: new Date().toISOString(),
    };
  },

  /**
   * Format compliance framework names for audit logs
   */
  formatComplianceFramework(framework: ComplianceFramework): string {
    const formatMap = {
      SOC2: 'SOC 2',
      PCI_DSS: 'PCI DSS',
      GDPR: 'GDPR',
      FIPS_140_2: 'FIPS 140-2',
      COMMON_CRITERIA: 'Common Criteria',
      ISO_27001: 'ISO 27001'
    };
    return formatMap[framework] || framework;
  },

  /**
   * Determine if event requires immediate notification
   */
  requiresImmediateNotification(
    action: EnterpriseSecretsAuditEvent,
    riskLevel: AuditRiskLevel,
    success: boolean
  ): boolean {
    if (riskLevel === 'critical' || !success) {return true;}
    
    const criticalActions = [
      'breach_detection_triggered',
      'secret_leakage_detected'
    ];
    
    return criticalActions.includes(action);
  }
};

/**
 * Export singleton instance for convenience
 */
export const enterpriseAuditLogger = EnterpriseAuditLogger.getInstance();