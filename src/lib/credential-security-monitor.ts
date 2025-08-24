/**
 * Comprehensive credential security monitoring service
 * Integrates validation, rotation, and continuous security assessment
 */

import { EventEmitter } from 'events';
import { credentialSecurityValidator } from './credential-security-validator.js';
import { secureConfigManager } from './secure-config.js';
import logger from './logger.js';

export interface SecurityAlert {
  id: string;
  timestamp: Date;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  type: 'validation_failure' | 'rotation_required' | 'weak_credential' | 'exposure_risk' | 'unauthorized_access' | 'system_anomaly';
  credentialId?: string;
  userId?: string;
  message: string;
  details: Record<string, unknown>;
  remediation: string[];
  acknowledged: boolean;
}

export interface SecurityMetrics {
  totalCredentials: number;
  healthyCredentials: number;
  rotationDueCredentials: number;
  expiredCredentials: number;
  weakCredentials: number;
  averageSecurityScore: number;
  lastMonitoringRun: Date;
  alertsLast24h: number;
  criticalAlertsActive: number;
}

export interface MonitoringPolicy {
  enabled: boolean;
  checkInterval: number; // milliseconds
  securityScoreThreshold: number;
  rotationWarningDays: number;
  alertRetentionDays: number;
  enableContinuousMonitoring: boolean;
  enableAnomalyDetection: boolean;
}

/**
 * Comprehensive credential security monitoring system
 */
export class CredentialSecurityMonitor extends EventEmitter {
  private static instance: CredentialSecurityMonitor;
  private readonly componentLogger: ReturnType<typeof logger.child>;
  private monitoringTimer?: NodeJS.Timeout;
  private readonly alerts: Map<string, SecurityAlert> = new Map();
  private metrics: SecurityMetrics;
  private policy: MonitoringPolicy;
  private isRunning = false;
  
  // Security baselines for anomaly detection
  private readonly securityBaselines: {
    averageScore: number;
    typicalRotationFrequency: number;
    normalAccessPatterns: Map<string, number>;
  } = {
    averageScore: 0,
    typicalRotationFrequency: 0,
    normalAccessPatterns: new Map()
  };

  private constructor() {
    super();
    
    try {
      this.componentLogger = logger.child({ component: 'CredentialSecurityMonitor' });
    } catch {
      // Fallback for test environments
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      this.componentLogger = logger as any;
    }

    // Initialize default policy
    this.policy = {
      enabled: process.env.NODE_ENV !== 'test',
      checkInterval: 15 * 60 * 1000, // 15 minutes
      securityScoreThreshold: 60,
      rotationWarningDays: 14,
      alertRetentionDays: 30,
      enableContinuousMonitoring: process.env.NODE_ENV === 'production',
      enableAnomalyDetection: process.env.NODE_ENV === 'production'
    };

    // Initialize metrics
    this.metrics = {
      totalCredentials: 0,
      healthyCredentials: 0,
      rotationDueCredentials: 0,
      expiredCredentials: 0,
      weakCredentials: 0,
      averageSecurityScore: 0,
      lastMonitoringRun: new Date(),
      alertsLast24h: 0,
      criticalAlertsActive: 0
    };
  }

  public static getInstance(): CredentialSecurityMonitor {
    if (!CredentialSecurityMonitor.instance) {
      CredentialSecurityMonitor.instance = new CredentialSecurityMonitor();
    }
    return CredentialSecurityMonitor.instance;
  }

  /**
   * Start continuous security monitoring
   */
  public async startMonitoring(): Promise<void> {
    if (this.isRunning) {
      this.componentLogger.warn('Security monitoring is already running');
      return;
    }

    if (!this.policy.enabled) {
      this.componentLogger.info('Security monitoring is disabled by policy');
      return;
    }

    try {
      this.isRunning = true;
      
      // Initial security scan
      await this.performSecurityScan();
      
      // Setup periodic monitoring
      if (this.policy.enableContinuousMonitoring) {
        this.monitoringTimer = setInterval(async () => {
          try {
            await this.performSecurityScan();
          } catch (error) {
            this.componentLogger.error('Periodic security scan failed', {
              error: error instanceof Error ? error.message : 'Unknown error'
            });
            
            this.createAlert({
              severity: 'high',
              type: 'system_anomaly',
              message: 'Periodic security scan failed',
              details: { error: error instanceof Error ? error.message : 'Unknown error' },
              remediation: ['Check monitoring system health', 'Verify credential storage connectivity']
            });
          }
        }, this.policy.checkInterval);
      }
      
      this.componentLogger.info('Credential security monitoring started', {
        checkInterval: this.policy.checkInterval,
        continuousMonitoring: this.policy.enableContinuousMonitoring,
        anomalyDetection: this.policy.enableAnomalyDetection
      });
      
      this.emit('monitoring_started');
    } catch (error) {
      this.isRunning = false;
      this.componentLogger.error('Failed to start security monitoring', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Stop security monitoring
   */
  public stopMonitoring(): void {
    if (!this.isRunning) {
      return;
    }

    if (this.monitoringTimer) {
      clearInterval(this.monitoringTimer);
      this.monitoringTimer = undefined;
    }

    this.isRunning = false;
    this.componentLogger.info('Credential security monitoring stopped');
    this.emit('monitoring_stopped');
  }

  /**
   * Perform comprehensive security scan
   */
  public async performSecurityScan(): Promise<SecurityMetrics> {
    try {
      this.componentLogger.debug('Starting comprehensive security scan');
      
      // Reset metrics
      this.metrics = {
        ...this.metrics,
        totalCredentials: 0,
        healthyCredentials: 0,
        rotationDueCredentials: 0,
        expiredCredentials: 0,
        weakCredentials: 0,
        averageSecurityScore: 0,
        lastMonitoringRun: new Date()
      };

      // Scan all credentials in secure storage
      await this.scanStoredCredentials();
      
      // Scan environment variables for unsecured credentials
      await this.scanEnvironmentCredentials();
      
      // Update security baselines
      this.updateSecurityBaselines();
      
      // Cleanup old alerts
      this.cleanupOldAlerts();
      
      this.componentLogger.info('Security scan completed', {
        totalCredentials: this.metrics.totalCredentials,
        healthyCredentials: this.metrics.healthyCredentials,
        averageScore: this.metrics.averageSecurityScore,
        activeAlerts: this.alerts.size
      });
      
      this.emit('scan_completed', this.metrics);
      return this.metrics;
    } catch (error) {
      this.componentLogger.error('Security scan failed', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      
      this.createAlert({
        severity: 'critical',
        type: 'system_anomaly',
        message: 'Comprehensive security scan failed',
        details: { error: error instanceof Error ? error.message : 'Unknown error' },
        remediation: ['Check system connectivity', 'Verify monitoring permissions', 'Review system logs']
      });
      
      throw error;
    }
  }

  /**
   * Scan credentials in secure storage
   */
  private async scanStoredCredentials(): Promise<void> {
    try {
      // This would typically iterate through stored credentials
      // For now, check specific known credentials
      const makeApiKeyCredentialId = process.env.MAKE_API_KEY_CREDENTIAL_ID;
      const authSecretCredentialId = process.env.AUTH_SECRET_CREDENTIAL_ID;

      const credentialIds = [makeApiKeyCredentialId, authSecretCredentialId].filter(Boolean) as string[];
      
      for (const credentialId of credentialIds) {
        await this.scanIndividualCredential(credentialId);
        this.metrics.totalCredentials++;
      }
    } catch (error) {
      this.componentLogger.error('Failed to scan stored credentials', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  /**
   * Scan individual credential
   */
  private async scanIndividualCredential(credentialId: string): Promise<void> {
    try {
      const status = secureConfigManager.getCredentialStatus(credentialId);
      
      if (status.status === 'not_found') {
        this.createAlert({
          severity: 'critical',
          type: 'validation_failure',
          credentialId,
          message: `Credential not found in secure storage: ${credentialId}`,
          details: { credentialId },
          remediation: ['Verify credential storage', 'Re-store missing credential', 'Update environment variables']
        });
        return;
      }

      // Check rotation requirements
      if (status.status === 'expired') {
        this.metrics.expiredCredentials++;
        this.createAlert({
          severity: 'critical',
          type: 'rotation_required',
          credentialId,
          message: `Credential has expired and requires immediate rotation: ${credentialId}`,
          details: { credentialId, status: status.status },
          remediation: ['Rotate credential immediately', 'Update application configuration', 'Verify new credential works']
        });
      } else if (status.status === 'rotation_due') {
        this.metrics.rotationDueCredentials++;
        this.createAlert({
          severity: 'high',
          type: 'rotation_required',
          credentialId,
          message: `Credential rotation is due: ${credentialId}`,
          details: { credentialId, daysUntilExpiry: status.daysUntilRotation },
          remediation: ['Schedule credential rotation', 'Prepare rotation procedure', 'Notify relevant teams']
        });
      } else {
        this.metrics.healthyCredentials++;
      }

      // Validate credential if we can access it (this would require decryption)
      // For security, we don't decrypt here but rely on metadata and previous validations
      
    } catch (error) {
      this.componentLogger.error('Failed to scan individual credential', {
        credentialId,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  /**
   * Scan environment variables for unsecured credentials
   */
  private async scanEnvironmentCredentials(): Promise<void> {
    const envCredentials = [
      { key: 'MAKE_API_KEY', type: 'api_key' as const },
      { key: 'AUTH_SECRET', type: 'secret' as const }
    ];

    for (const { key, type } of envCredentials) {
      const value = process.env[key];
      if (value) {
        await this.validateEnvironmentCredential(key, value, type);
        this.metrics.totalCredentials++;
      }
    }
  }

  /**
   * Validate environment credential
   */
  private async validateEnvironmentCredential(key: string, value: string, type: 'api_key' | 'secret'): Promise<void> {
    try {
      let validation;
      
      if (type === 'api_key') {
        validation = credentialSecurityValidator().validateMakeApiKey(value);
      } else {
        // For other types, create a basic validation
        validation = {
          isValid: value.length >= 32,
          score: value.length >= 64 ? 80 : 50,
          errors: value.length < 32 ? ['Secret too short'] : [],
          warnings: value.length < 64 ? ['Consider longer secret'] : [],
          strengths: [],
          weaknesses: [],
          recommendations: []
        };
      }

      if (!validation.isValid) {
        this.createAlert({
          severity: 'high',
          type: 'validation_failure',
          message: `Environment credential validation failed: ${key}`,
          details: { 
            key, 
            errors: validation.errors,
            score: validation.score 
          },
          remediation: ['Update credential with stronger value', 'Migrate to secure credential storage']
        });
      } else if (validation.score < this.policy.securityScoreThreshold) {
        this.metrics.weakCredentials++;
        this.createAlert({
          severity: 'medium',
          type: 'weak_credential',
          message: `Weak credential detected: ${key} (score: ${validation.score}/100)`,
          details: { 
            key, 
            score: validation.score,
            warnings: validation.warnings,
            recommendations: validation.recommendations
          },
          remediation: validation.recommendations.length > 0 ? validation.recommendations : ['Strengthen credential', 'Use secure generation']
        });
      } else {
        this.metrics.healthyCredentials++;
      }

      // Update average score
      this.metrics.averageSecurityScore = (this.metrics.averageSecurityScore + validation.score) / 2;
      
      // Check for unsecured storage (environment variables should migrate to secure storage)
      this.createAlert({
        severity: 'low',
        type: 'exposure_risk',
        message: `Credential stored in environment variable: ${key}`,
        details: { key },
        remediation: ['Migrate to secure credential storage', 'Remove from environment variables', 'Update configuration']
      });
      
    } catch (error) {
      this.componentLogger.error('Failed to validate environment credential', {
        key,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  /**
   * Create security alert
   */
  private createAlert(alertData: Omit<SecurityAlert, 'id' | 'timestamp' | 'acknowledged'>): void {
    const alert: SecurityAlert = {
      id: this.generateAlertId(),
      timestamp: new Date(),
      acknowledged: false,
      ...alertData
    };

    this.alerts.set(alert.id, alert);
    
    if (alert.severity === 'critical') {
      this.metrics.criticalAlertsActive++;
    }

    this.componentLogger.warn('Security alert created', {
      id: alert.id,
      severity: alert.severity,
      type: alert.type,
      message: alert.message
    });

    this.emit('alert_created', alert);
  }

  /**
   * Update security baselines for anomaly detection
   */
  private updateSecurityBaselines(): void {
    if (!this.policy.enableAnomalyDetection) {
      return;
    }

    // Update average security score baseline
    if (this.metrics.totalCredentials > 0) {
      this.securityBaselines.averageScore = this.metrics.averageSecurityScore;
    }

    // Detect anomalies in security score
    if (this.securityBaselines.averageScore > 0) {
      const scoreDrop = this.securityBaselines.averageScore - this.metrics.averageSecurityScore;
      if (scoreDrop > 20) { // Significant drop in security score
        this.createAlert({
          severity: 'medium',
          type: 'system_anomaly',
          message: `Significant drop in average security score detected: ${scoreDrop.toFixed(1)} points`,
          details: {
            previousScore: this.securityBaselines.averageScore,
            currentScore: this.metrics.averageSecurityScore,
            drop: scoreDrop
          },
          remediation: ['Review recent credential changes', 'Audit credential quality', 'Check for weak credentials']
        });
      }
    }
  }

  /**
   * Cleanup old alerts
   */
  private cleanupOldAlerts(): void {
    const cutoffDate = new Date(Date.now() - this.policy.alertRetentionDays * 24 * 60 * 60 * 1000);
    let cleanedCount = 0;

    for (const [alertId, alert] of this.alerts.entries()) {
      if (alert.timestamp < cutoffDate && alert.acknowledged) {
        this.alerts.delete(alertId);
        cleanedCount++;
      }
    }

    // Update metrics
    this.metrics.alertsLast24h = Array.from(this.alerts.values()).filter(
      alert => alert.timestamp > new Date(Date.now() - 24 * 60 * 60 * 1000)
    ).length;

    this.metrics.criticalAlertsActive = Array.from(this.alerts.values()).filter(
      alert => alert.severity === 'critical' && !alert.acknowledged
    ).length;

    if (cleanedCount > 0) {
      this.componentLogger.debug('Cleaned up old alerts', { count: cleanedCount });
    }
  }

  /**
   * Get current security alerts
   */
  public getAlerts(filter?: {
    severity?: SecurityAlert['severity'];
    type?: SecurityAlert['type'];
    acknowledged?: boolean;
    credentialId?: string;
    limit?: number;
  }): SecurityAlert[] {
    let alerts = Array.from(this.alerts.values());

    if (filter) {
      alerts = alerts.filter(alert => {
        if (filter.severity && alert.severity !== filter.severity) {
          return false;
        }
        if (filter.type && alert.type !== filter.type) {
          return false;
        }
        if (filter.acknowledged !== undefined && alert.acknowledged !== filter.acknowledged) {
          return false;
        }
        if (filter.credentialId && alert.credentialId !== filter.credentialId) {
          return false;
        }
        return true;
      });
    }

    // Sort by timestamp (newest first)
    alerts.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    if (filter?.limit) {
      alerts = alerts.slice(0, filter.limit);
    }

    return alerts;
  }

  /**
   * Acknowledge security alert
   */
  public acknowledgeAlert(alertId: string, userId?: string): boolean {
    const alert = this.alerts.get(alertId);
    if (!alert) {
      return false;
    }

    alert.acknowledged = true;
    
    if (alert.severity === 'critical') {
      this.metrics.criticalAlertsActive = Math.max(0, this.metrics.criticalAlertsActive - 1);
    }

    this.componentLogger.info('Security alert acknowledged', {
      alertId,
      userId,
      alertType: alert.type,
      severity: alert.severity
    });

    this.emit('alert_acknowledged', { alertId, userId, alert });
    return true;
  }

  /**
   * Get current security metrics
   */
  public getMetrics(): SecurityMetrics {
    return { ...this.metrics };
  }

  /**
   * Update monitoring policy
   */
  public updatePolicy(updates: Partial<MonitoringPolicy>): void {
    const oldPolicy = { ...this.policy };
    this.policy = { ...this.policy, ...updates };

    this.componentLogger.info('Monitoring policy updated', {
      oldPolicy,
      newPolicy: this.policy
    });

    // Restart monitoring if interval changed
    if (this.isRunning && updates.checkInterval && updates.checkInterval !== oldPolicy.checkInterval) {
      this.stopMonitoring();
      this.startMonitoring();
    }
  }

  /**
   * Generate unique alert ID
   */
  private generateAlertId(): string {
    return `alert_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
  }

  /**
   * Graceful shutdown
   */
  public async shutdown(): Promise<void> {
    this.stopMonitoring();
    
    // Log final metrics
    this.componentLogger.info('Security monitoring shutdown', {
      finalMetrics: this.metrics,
      activeAlerts: this.alerts.size,
      criticalAlerts: this.metrics.criticalAlertsActive
    });

    this.emit('shutdown_complete');
  }
}

// Export singleton instance
export const credentialSecurityMonitor = CredentialSecurityMonitor.getInstance();

export default credentialSecurityMonitor;