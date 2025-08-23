/**
 * Comprehensive Audit Logging and Compliance Service
 * Provides structured audit trails, compliance reporting, and security monitoring
 */

import { writeFile, readFile, mkdir } from 'fs/promises';
import { existsSync } from 'fs';
import { join } from 'path';
import logger from './logger.js';
import { encryptionService } from '../utils/encryption.js';
import { getAuditLogsDirectory } from '../utils/path-resolver.js';

export interface AuditLogEntry {
  id: string;
  timestamp: Date;
  level: 'info' | 'warn' | 'error' | 'critical';
  category: 'authentication' | 'authorization' | 'data_access' | 'configuration' | 'security' | 'system';
  action: string;
  resource?: string;
  userId?: string;
  userAgent?: string;
  ipAddress?: string;
  sessionId?: string;
  requestId?: string;
  success: boolean;
  details: Record<string, unknown>;
  complianceFlags?: string[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  encrypted?: boolean;
}

export interface ComplianceReport {
  period: {
    startDate: Date;
    endDate: Date;
  };
  summary: {
    totalEvents: number;
    successfulEvents: number;
    failedEvents: number;
    criticalEvents: number;
    highRiskEvents: number;
    uniqueUsers: number;
    uniqueIpAddresses: number;
  };
  categories: Record<string, number>;
  riskLevels: Record<string, number>;
  topFailures: Array<{
    action: string;
    count: number;
    lastOccurrence: Date;
  }>;
  securityIncidents: AuditLogEntry[];
  complianceViolations: Array<{
    type: string;
    count: number;
    entries: AuditLogEntry[];
  }>;
}

export interface AuditConfiguration {
  enableEncryption: boolean;
  retentionDays: number;
  maxFileSize: number; // bytes
  logDirectory: string;
  complianceStandards: string[]; // e.g., ['SOC2', 'GDPR', 'ISO27001']
  alertThresholds: {
    failureRate: number; // percentage
    criticalEventsPerHour: number;
    suspiciousPatterns: number;
  };
}

/**
 * Advanced audit logging service with compliance features
 */
export class AuditLogger {
  private static instance: AuditLogger;
  private _componentLogger: ReturnType<typeof logger.child> | null = null;
  private readonly config: AuditConfiguration;
  private auditBuffer: AuditLogEntry[] = [];
  private bufferFlushInterval: NodeJS.Timeout | null = null;
  private readonly encryptionKey: string;

  private get componentLogger(): ReturnType<typeof logger.child> {
    if (!this._componentLogger) {
      try {
        this._componentLogger = logger.child({ component: 'AuditLogger' });
      } catch {
        // Fallback for test environments where logger.child might not be available
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        this._componentLogger = logger as any;
      }
    }
    return this._componentLogger!;
  }

  private constructor() {
    this.config = this.loadConfiguration();
    this.encryptionKey = this.initializeEncryptionKey();
    // Initialize audit directory asynchronously (don't await to avoid blocking constructor)
    this.initializeAuditDirectory().catch((error) => {
      this.componentLogger.error('Failed to initialize audit directory during startup', {
        error: error.message,
        directory: this.config.logDirectory,
      });
    });
    this.startBufferFlush();
  }

  public static getInstance(): AuditLogger {
    if (!AuditLogger.instance) {
      AuditLogger.instance = new AuditLogger();
    }
    return AuditLogger.instance;
  }

  private loadConfiguration(): AuditConfiguration {
    return {
      enableEncryption: process.env.AUDIT_ENCRYPTION_ENABLED === 'true',
      retentionDays: parseInt(process.env.AUDIT_RETENTION_DAYS || '90'),
      maxFileSize: parseInt(process.env.AUDIT_MAX_FILE_SIZE || '10485760'), // 10MB
      logDirectory: process.env.AUDIT_LOG_DIRECTORY || getAuditLogsDirectory(),
      complianceStandards: (process.env.COMPLIANCE_STANDARDS || 'SOC2,GDPR').split(','),
      alertThresholds: {
        failureRate: parseFloat(process.env.AUDIT_FAILURE_RATE_THRESHOLD || '10'),
        criticalEventsPerHour: parseInt(process.env.AUDIT_CRITICAL_EVENTS_THRESHOLD || '5'),
        suspiciousPatterns: parseInt(process.env.AUDIT_SUSPICIOUS_PATTERNS_THRESHOLD || '3'),
      },
    };
  }

  private initializeEncryptionKey(): string {
    const key = process.env.AUDIT_ENCRYPTION_KEY;
    if (this.config.enableEncryption && (!key || key.length < 32)) {
      const generated = encryptionService.generateSecureSecret(64);
      this.componentLogger.warn('Generated audit encryption key. Set AUDIT_ENCRYPTION_KEY environment variable for production.');
      process.env.AUDIT_ENCRYPTION_KEY = generated;
      return generated;
    }
    return key || '';
  }

  private async initializeAuditDirectory(): Promise<void> {
    try {
      if (!existsSync(this.config.logDirectory)) {
        await mkdir(this.config.logDirectory, { recursive: true });
        this.componentLogger.info('Created audit log directory', {
          directory: this.config.logDirectory,
        });
      }
    } catch (error) {
      this.componentLogger.error('Failed to initialize audit directory', {
        error: error instanceof Error ? error.message : 'Unknown error',
        directory: this.config.logDirectory,
      });
    }
  }

  private startBufferFlush(): void {
    this.bufferFlushInterval = setInterval(async () => {
      await this.flushBuffer();
    }, 5000); // Flush every 5 seconds
  }

  /**
   * Log an audit event
   */
  public async logEvent(entry: Omit<AuditLogEntry, 'id' | 'timestamp'>): Promise<void> {
    const auditEntry: AuditLogEntry = {
      id: crypto.randomUUID(),
      timestamp: new Date(),
      ...entry,
    };

    // Add compliance flags based on the action and data
    auditEntry.complianceFlags = this.determineComplianceFlags(auditEntry);

    // Add to buffer for batch processing
    this.auditBuffer.push(auditEntry);

    // Immediate flush for critical events
    if (auditEntry.level === 'critical' || auditEntry.riskLevel === 'critical') {
      await this.flushBuffer();
      await this.alertCriticalEvent(auditEntry);
    }

    // Log to standard logger for immediate visibility
    const logData = {
      id: auditEntry.id,
      category: auditEntry.category,
      action: auditEntry.action,
      success: auditEntry.success,
      riskLevel: auditEntry.riskLevel,
      userId: auditEntry.userId,
    };

    // Use explicit method calls instead of dynamic calls to avoid method binding issues
    switch (auditEntry.level) {
      case 'critical':
        this.componentLogger.error('Audit event logged', logData);
        break;
      case 'error':
        this.componentLogger.error('Audit event logged', logData);
        break;
      case 'warn':
        this.componentLogger.warn('Audit event logged', logData);
        break;
      case 'info':
        this.componentLogger.info('Audit event logged', logData);
        break;
      default:
        this.componentLogger.info('Audit event logged', logData);
        break;
    }
  }

  /**
   * Flush audit buffer to persistent storage
   */
  private async flushBuffer(): Promise<void> {
    if (this.auditBuffer.length === 0) {return;}

    try {
      const entries = [...this.auditBuffer];
      this.auditBuffer = [];

      const filename = this.generateLogFilename();
      const filepath = join(this.config.logDirectory, filename);

      let logData: string;
      if (this.config.enableEncryption) {
        const encryptedData = await encryptionService.encrypt(
          JSON.stringify(entries),
          this.encryptionKey
        );
        logData = JSON.stringify(encryptedData);
      } else {
        logData = entries.map(entry => JSON.stringify(entry)).join('\n') + '\n';
      }

      await writeFile(filepath, logData, { flag: 'a' });

      this.componentLogger.debug('Audit buffer flushed', {
        entriesCount: entries.length,
        filename,
        encrypted: this.config.enableEncryption,
      });
    } catch (error) {
      this.componentLogger.error('Failed to flush audit buffer', {
        error: error instanceof Error ? error.message : 'Unknown error',
        entriesCount: this.auditBuffer.length,
      });
      // Re-add entries to buffer for retry
      this.auditBuffer.unshift(...this.auditBuffer);
    }
  }

  private generateLogFilename(): string {
    const date = new Date();
    const dateStr = date.toISOString().split('T')[0];
    const hour = date.getHours().toString().padStart(2, '0');
    return `audit-${dateStr}-${hour}.log`;
  }

  private determineComplianceFlags(entry: AuditLogEntry): string[] {
    const flags: string[] = [];

    // GDPR compliance flags
    if (entry.category === 'data_access' || entry.details?.personalData) {
      flags.push('GDPR');
    }

    // SOC2 compliance flags
    if (entry.category === 'security' || entry.category === 'authentication') {
      flags.push('SOC2');
    }

    // ISO27001 compliance flags
    if (entry.riskLevel === 'high' || entry.riskLevel === 'critical') {
      flags.push('ISO27001');
    }

    // PCI DSS flags (if payment data involved)
    if (entry.details?.paymentData || entry.details?.cardData) {
      flags.push('PCI_DSS');
    }

    return flags;
  }

  private async alertCriticalEvent(entry: AuditLogEntry): Promise<void> {
    this.componentLogger.error('CRITICAL AUDIT EVENT DETECTED', {
      auditId: entry.id,
      action: entry.action,
      category: entry.category,
      riskLevel: entry.riskLevel,
      userId: entry.userId,
      details: entry.details,
    });

    // In production, this would integrate with alerting systems
    // like PagerDuty, Slack, or email notifications
  }

  /**
   * Generate compliance report for a given period
   */
  public async generateComplianceReport(
    startDate: Date,
    endDate: Date
  ): Promise<ComplianceReport> {
    try {
      const entries = await this.loadAuditEntries(startDate, endDate);

      const report: ComplianceReport = {
        period: { startDate, endDate },
        summary: {
          totalEvents: entries.length,
          successfulEvents: entries.filter(e => e.success).length,
          failedEvents: entries.filter(e => !e.success).length,
          criticalEvents: entries.filter(e => e.level === 'critical').length,
          highRiskEvents: entries.filter(e => e.riskLevel === 'high' || e.riskLevel === 'critical').length,
          uniqueUsers: new Set(entries.map(e => e.userId).filter(Boolean)).size,
          uniqueIpAddresses: new Set(entries.map(e => e.ipAddress).filter(Boolean)).size,
        },
        categories: this.aggregateByField(entries, 'category'),
        riskLevels: this.aggregateByField(entries, 'riskLevel'),
        topFailures: this.getTopFailures(entries),
        securityIncidents: entries.filter(e => 
          e.category === 'security' && 
          (e.riskLevel === 'high' || e.riskLevel === 'critical')
        ),
        complianceViolations: this.identifyComplianceViolations(entries),
      };

      this.componentLogger.info('Compliance report generated', {
        period: report.period,
        totalEvents: report.summary.totalEvents,
        criticalEvents: report.summary.criticalEvents,
      });

      return report;
    } catch (error) {
      this.componentLogger.error('Failed to generate compliance report', {
        error: error instanceof Error ? error.message : 'Unknown error',
        startDate,
        endDate,
      });
      throw error;
    }
  }

  private async loadAuditEntries(startDate: Date, endDate: Date): Promise<AuditLogEntry[]> {
    const entries: AuditLogEntry[] = [];
    
    // This is a simplified implementation - in production, you'd want
    // to implement efficient querying based on date ranges
    const files = await this.getLogFiles(startDate, endDate);
    
    for (const file of files) {
      try {
        const filepath = join(this.config.logDirectory, file);
        const data = await readFile(filepath, 'utf-8');
        
        let fileEntries: AuditLogEntry[];
        if (this.config.enableEncryption) {
          const encryptedData = JSON.parse(data);
          const decrypted = await encryptionService.decrypt(encryptedData, this.encryptionKey);
          fileEntries = JSON.parse(decrypted);
        } else {
          fileEntries = data.split('\n')
            .filter(line => line.trim())
            .map(line => JSON.parse(line));
        }
        
        entries.push(...fileEntries.filter(entry => {
          const entryDate = new Date(entry.timestamp);
          return entryDate >= startDate && entryDate <= endDate;
        }));
      } catch (error) {
        this.componentLogger.warn('Failed to load audit file', {
          file,
          error: error instanceof Error ? error.message : 'Unknown error',
        });
      }
    }
    
    return entries;
  }

  private async getLogFiles(startDate: Date, endDate: Date): Promise<string[]> {
    // Simplified implementation - would need to scan directory for relevant files
    const files: string[] = [];
    const currentDate = new Date(startDate);
    
    while (currentDate <= endDate) {
      const dateStr = currentDate.toISOString().split('T')[0];
      for (let hour = 0; hour < 24; hour++) {
        const filename = `audit-${dateStr}-${hour.toString().padStart(2, '0')}.log`;
        if (existsSync(join(this.config.logDirectory, filename))) {
          files.push(filename);
        }
      }
      currentDate.setDate(currentDate.getDate() + 1);
    }
    
    return files;
  }

  private aggregateByField(entries: AuditLogEntry[], field: keyof AuditLogEntry): Record<string, number> {
    return entries.reduce((acc, entry) => {
      const value = String(entry[field]);
      acc[value] = (acc[value] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
  }

  private getTopFailures(entries: AuditLogEntry[]): Array<{
    action: string;
    count: number;
    lastOccurrence: Date;
  }> {
    const failures = entries.filter(e => !e.success);
    const actionCounts = this.aggregateByField(failures, 'action');
    
    return Object.entries(actionCounts)
      .map(([action, count]) => ({
        action,
        count,
        lastOccurrence: failures
          .filter(e => e.action === action)
          .reduce((latest, entry) => 
            entry.timestamp > latest ? entry.timestamp : latest, 
            new Date(0)
          ),
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }

  private identifyComplianceViolations(entries: AuditLogEntry[]): Array<{
    type: string;
    count: number;
    entries: AuditLogEntry[];
  }> {
    const violations: Record<string, AuditLogEntry[]> = {};
    
    for (const entry of entries) {
      // Identify potential GDPR violations
      if (entry.complianceFlags?.includes('GDPR') && !entry.success) {
        violations.GDPR_DATA_ACCESS_FAILURE = violations.GDPR_DATA_ACCESS_FAILURE || [];
        violations.GDPR_DATA_ACCESS_FAILURE.push(entry);
      }
      
      // Identify authentication failures (SOC2)
      if (entry.category === 'authentication' && !entry.success) {
        violations.AUTHENTICATION_FAILURE = violations.AUTHENTICATION_FAILURE || [];
        violations.AUTHENTICATION_FAILURE.push(entry);
      }
      
      // Identify excessive access attempts
      if (entry.riskLevel === 'high' && entry.category === 'authorization') {
        violations.UNAUTHORIZED_ACCESS_ATTEMPT = violations.UNAUTHORIZED_ACCESS_ATTEMPT || [];
        violations.UNAUTHORIZED_ACCESS_ATTEMPT.push(entry);
      }
    }
    
    return Object.entries(violations).map(([type, entries]) => ({
      type,
      count: entries.length,
      entries,
    }));
  }

  /**
   * Perform audit log maintenance (cleanup old logs, rotate files)
   */
  public async performMaintenance(): Promise<{
    deletedFiles: number;
    rotatedFiles: number;
    errors: string[];
  }> {
    const result = {
      deletedFiles: 0,
      rotatedFiles: 0,
      errors: [] as string[],
    };

    try {
      // Cleanup old audit logs based on retention policy
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - this.config.retentionDays);

      const allFiles = await this.getLogFiles(new Date(0), new Date());
      
      for (const file of allFiles) {
        try {
          const filepath = join(this.config.logDirectory, file);
          const stats = await import('fs').then(fs => fs.promises.stat(filepath));
          
          if (stats.mtime < cutoffDate) {
            await import('fs').then(fs => fs.promises.unlink(filepath));
            result.deletedFiles++;
          }
        } catch (error) {
          result.errors.push(`Failed to process file ${file}: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
      }

      this.componentLogger.info('Audit log maintenance completed', result);
      return result;
    } catch (error) {
      this.componentLogger.error('Audit log maintenance failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw error;
    }
  }

  /**
   * Shutdown audit logger gracefully
   */
  public async shutdown(): Promise<void> {
    try {
      if (this.bufferFlushInterval) {
        clearInterval(this.bufferFlushInterval);
        this.bufferFlushInterval = null;
      }
      
      await this.flushBuffer();
      
      this.componentLogger.info('Audit logger shutdown completed');
    } catch (error) {
      this.componentLogger.error('Error during audit logger shutdown', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }
}

// Export singleton instance
export const auditLogger = AuditLogger.getInstance();
export default auditLogger;