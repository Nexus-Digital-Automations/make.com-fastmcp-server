/**
 * FastMCP Tools for Audit Logging and Compliance Management
 * Provides tools for audit logging, compliance reporting, and security monitoring
 */

import { z } from 'zod';
import { auditLogger } from '../lib/audit-logger.js';
import logger from '../lib/logger.js';

const componentLogger = logger.child({ component: 'AuditComplianceTools' });

// Input schemas for audit and compliance tools
const LogAuditEventSchema = z.object({
  level: z.enum(['info', 'warn', 'error', 'critical']),
  category: z.enum(['authentication', 'authorization', 'data_access', 'configuration', 'security', 'system']),
  action: z.string().min(1, 'Action is required'),
  resource: z.string().optional(),
  userId: z.string().optional(),
  userAgent: z.string().optional(),
  ipAddress: z.string().optional(),
  sessionId: z.string().optional(),
  requestId: z.string().optional(),
  success: z.boolean(),
  details: z.record(z.unknown()).optional().default({}),
  riskLevel: z.enum(['low', 'medium', 'high', 'critical']),
});

const GenerateComplianceReportSchema = z.object({
  startDate: z.string().refine((date) => !isNaN(Date.parse(date)), {
    message: 'Invalid start date format',
  }),
  endDate: z.string().refine((date) => !isNaN(Date.parse(date)), {
    message: 'Invalid end date format',
  }),
  format: z.enum(['json', 'summary']).optional().default('json'),
});

const MaintenanceSchema = z.object({
  retentionDays: z.number().min(1).max(365).optional(),
});

/**
 * Log an audit event
 */
export const logAuditEventTool = {
  name: 'log_audit_event',
  description: 'Log a security audit event with compliance tracking',
  inputSchema: LogAuditEventSchema,
  handler: async (input: z.infer<typeof LogAuditEventSchema>): Promise<{ success: boolean; eventId: string; timestamp: string; message: string }> => {
    try {
      await auditLogger.logEvent({
        level: input.level,
        category: input.category,
        action: input.action,
        resource: input.resource,
        userId: input.userId,
        userAgent: input.userAgent,
        ipAddress: input.ipAddress,
        sessionId: input.sessionId,
        requestId: input.requestId,
        success: input.success,
        details: input.details,
        riskLevel: input.riskLevel,
      });

      componentLogger.info('Audit event logged via MCP tool', {
        action: input.action,
        category: input.category,
        level: input.level,
        success: input.success,
        riskLevel: input.riskLevel,
      });

      return {
        success: true,
        eventId: `event_${Date.now()}`,
        timestamp: new Date().toISOString(),
        message: 'Audit event logged successfully',
      };
    } catch (error) {
      componentLogger.error('Failed to log audit event via MCP tool', {
        error: error instanceof Error ? error.message : 'Unknown error',
        action: input.action,
        category: input.category,
      });

      return {
        success: false,
        eventId: '',
        timestamp: new Date().toISOString(),
        message: error instanceof Error ? error.message : 'Failed to log audit event',
      };
    }
  },
};

/**
 * Generate compliance report
 */
export const generateComplianceReportTool = {
  name: 'generate_compliance_report',
  description: 'Generate a comprehensive compliance report for audit purposes',
  inputSchema: GenerateComplianceReportSchema,
  handler: async (input: z.infer<typeof GenerateComplianceReportSchema>): Promise<{ success: boolean; report: { period: string; totalEvents: number; criticalEvents: number; securityEvents: number; complianceScore: number; recommendations: string[]; summary: string } }> => {
    try {
      const startDate = new Date(input.startDate);
      const endDate = new Date(input.endDate);

      const report = await auditLogger.generateComplianceReport(startDate, endDate);

      componentLogger.info('Compliance report generated via MCP tool', {
        startDate: input.startDate,
        endDate: input.endDate,
        totalEvents: report.summary.totalEvents,
        criticalEvents: report.summary.criticalEvents,
      });

      if (input.format === 'summary') {
        return {
          success: true,
          report: {
            period: `${input.startDate} to ${input.endDate}`,
            summary: report.summary,
            topCategories: Object.entries(report.categories)
              .sort(([, a], [, b]) => b - a)
              .slice(0, 5)
              .map(([category, count]) => ({ category, count })),
            securityIncidents: report.securityIncidents.length,
            complianceViolations: report.complianceViolations.length,
          },
        };
      }

      return {
        success: true,
        report,
      };
    } catch (error) {
      componentLogger.error('Failed to generate compliance report via MCP tool', {
        error: error instanceof Error ? error.message : 'Unknown error',
        startDate: input.startDate,
        endDate: input.endDate,
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to generate compliance report',
      };
    }
  },
};

/**
 * Perform audit log maintenance
 */
export const performAuditMaintenanceTool = {
  name: 'perform_audit_maintenance',
  description: 'Perform maintenance on audit logs (cleanup, rotation)',
  inputSchema: MaintenanceSchema,
  handler: async (): Promise<{ success: boolean; deletedFiles: number; rotatedFiles: number; compactedFiles: number; freedSpace: number; message: string }> => {
    try {
      const result = await auditLogger.performMaintenance();

      componentLogger.info('Audit maintenance performed via MCP tool', {
        deletedFiles: result.deletedFiles,
        rotatedFiles: result.rotatedFiles,
        errors: result.errors.length,
      });

      return {
        success: true,
        maintenance: {
          deletedFiles: result.deletedFiles,
          rotatedFiles: result.rotatedFiles,
          errors: result.errors,
        },
        message: `Maintenance completed. Deleted ${result.deletedFiles} files, rotated ${result.rotatedFiles} files.`,
      };
    } catch (error) {
      componentLogger.error('Failed to perform audit maintenance via MCP tool', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to perform audit maintenance',
      };
    }
  },
};

/**
 * Get audit configuration
 */
export const getAuditConfigurationTool = {
  name: 'get_audit_configuration',
  description: 'Get current audit logging and compliance configuration',
  inputSchema: z.object({}),
  handler: async (): Promise<{ config: { encryptionEnabled: boolean; retentionDays: number; maxFileSize: number; logDirectory: string; alertingEnabled: boolean; complianceMode: string } }> => {
    try {
      // Access configuration through environment variables
      const config = {
        encryptionEnabled: process.env.AUDIT_ENCRYPTION_ENABLED === 'true',
        retentionDays: parseInt(process.env.AUDIT_RETENTION_DAYS || '90'),
        maxFileSize: parseInt(process.env.AUDIT_MAX_FILE_SIZE || '10485760'),
        logDirectory: process.env.AUDIT_LOG_DIRECTORY || './logs/audit',
        complianceStandards: (process.env.COMPLIANCE_STANDARDS || 'SOC2,GDPR').split(','),
        alertThresholds: {
          failureRate: parseFloat(process.env.AUDIT_FAILURE_RATE_THRESHOLD || '10'),
          criticalEventsPerHour: parseInt(process.env.AUDIT_CRITICAL_EVENTS_THRESHOLD || '5'),
          suspiciousPatterns: parseInt(process.env.AUDIT_SUSPICIOUS_PATTERNS_THRESHOLD || '3'),
        },
      };

      componentLogger.info('Audit configuration retrieved via MCP tool');

      return {
        success: true,
        configuration: config,
      };
    } catch (error) {
      componentLogger.error('Failed to get audit configuration via MCP tool', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to get audit configuration',
      };
    }
  },
};

/**
 * Security health check
 */
export const securityHealthCheckTool = {
  name: 'security_health_check',
  description: 'Perform a comprehensive security health check',
  inputSchema: z.object({
    includeCertificates: z.boolean().optional().default(false),
    includePermissions: z.boolean().optional().default(false),
    includeNetworkConfig: z.boolean().optional().default(false),
  }),
  handler: async (): Promise<{ stats: { totalEvents: number; recentEvents: number; securityEvents: number; failedLogins: number; dataAccess: number; configChanges: number; systemEvents: number } }> => {
    try {
      const healthCheck = {
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'unknown',
        security: {
          httpsEnabled: process.env.HTTPS_ENABLED === 'true',
          authenticationEnabled: process.env.AUTH_ENABLED === 'true',
          encryptionEnabled: process.env.AUDIT_ENCRYPTION_ENABLED === 'true',
          credentialEncryptionEnabled: process.env.CREDENTIAL_MASTER_PASSWORD ? true : false,
        },
        compliance: {
          auditLoggingEnabled: true,
          retentionPolicyConfigured: !!process.env.AUDIT_RETENTION_DAYS,
          complianceStandardsConfigured: !!process.env.COMPLIANCE_STANDARDS,
        },
        configuration: {
          logLevel: process.env.LOG_LEVEL || 'info',
          rateLimitEnabled: !!process.env.RATE_LIMIT_MAX_REQUESTS,
          timeoutConfigured: !!process.env.MAKE_TIMEOUT,
        },
        recommendations: [] as string[],
      };

      // Generate security recommendations
      if (!healthCheck.security.httpsEnabled && process.env.NODE_ENV === 'production') {
        healthCheck.recommendations.push('Enable HTTPS in production environment');
      }

      if (!healthCheck.security.authenticationEnabled && process.env.NODE_ENV === 'production') {
        healthCheck.recommendations.push('Enable authentication in production environment');
      }

      if (!healthCheck.security.encryptionEnabled) {
        healthCheck.recommendations.push('Enable audit log encryption for enhanced security');
      }

      if (!healthCheck.security.credentialEncryptionEnabled) {
        healthCheck.recommendations.push('Configure credential encryption master password');
      }

      if (healthCheck.configuration.logLevel === 'debug' && process.env.NODE_ENV === 'production') {
        healthCheck.recommendations.push('Change log level from debug in production');
      }

      // Log security health check
      await auditLogger.logEvent({
        level: 'info',
        category: 'security',
        action: 'security_health_check',
        success: true,
        details: { 
          recommendationsCount: healthCheck.recommendations.length,
          environment: healthCheck.environment,
        },
        riskLevel: healthCheck.recommendations.length > 3 ? 'high' : 'low',
      });

      componentLogger.info('Security health check performed via MCP tool', {
        recommendationsCount: healthCheck.recommendations.length,
        environment: healthCheck.environment,
      });

      return {
        success: true,
        healthCheck,
        riskLevel: healthCheck.recommendations.length > 3 ? 'high' : 'low',
        summary: `Health check completed. ${healthCheck.recommendations.length} recommendations identified.`,
      };
    } catch (error) {
      componentLogger.error('Failed to perform security health check via MCP tool', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to perform security health check',
      };
    }
  },
};

/**
 * Create security incident report
 */
export const createSecurityIncidentTool = {
  name: 'create_security_incident',
  description: 'Create and log a security incident report',
  inputSchema: z.object({
    title: z.string().min(1, 'Incident title is required'),
    description: z.string().min(1, 'Incident description is required'),
    severity: z.enum(['low', 'medium', 'high', 'critical']),
    category: z.enum(['data_breach', 'unauthorized_access', 'malware', 'phishing', 'other']),
    affectedSystems: z.array(z.string()).optional().default([]),
    affectedUsers: z.array(z.string()).optional().default([]),
    detectionTime: z.string().optional(),
    responseActions: z.array(z.string()).optional().default([]),
  }),
  handler: async (input: {
    title: string;
    description: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    category: 'data_breach' | 'unauthorized_access' | 'malware' | 'phishing' | 'other';
    affectedSystems?: string[];
    affectedUsers?: string[];
    detectionTime?: string;
    responseActions?: string[];
  }): Promise<{ success: boolean; incidentId: string; timestamp: string; message: string; nextSteps: string[] }> => {
    try {
      const incidentId = crypto.randomUUID();
      const timestamp = new Date();

      // Log the security incident
      await auditLogger.logEvent({
        level: input.severity === 'critical' ? 'critical' : 'error',
        category: 'security',
        action: 'security_incident_created',
        success: true,
        details: {
          incidentId,
          title: input.title,
          description: input.description,
          severity: input.severity,
          category: input.category,
          affectedSystems: input.affectedSystems,
          affectedUsers: input.affectedUsers,
          detectionTime: input.detectionTime,
          responseActions: input.responseActions,
        },
        riskLevel: input.severity === 'critical' ? 'critical' : input.severity === 'high' ? 'high' : 'medium',
      });

      componentLogger.error('Security incident created via MCP tool', {
        incidentId,
        title: input.title,
        severity: input.severity,
        category: input.category,
        affectedSystemsCount: input.affectedSystems.length,
        affectedUsersCount: input.affectedUsers.length,
      });

      return {
        success: true,
        incident: {
          id: incidentId,
          title: input.title,
          severity: input.severity,
          category: input.category,
          createdAt: timestamp.toISOString(),
          status: 'open',
        },
        message: `Security incident ${incidentId} created and logged successfully`,
      };
    } catch (error) {
      componentLogger.error('Failed to create security incident via MCP tool', {
        error: error instanceof Error ? error.message : 'Unknown error',
        title: input.title,
        severity: input.severity,
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to create security incident',
      };
    }
  },
};

// Export all audit and compliance tools
export const auditComplianceTools = [
  logAuditEventTool,
  generateComplianceReportTool,
  performAuditMaintenanceTool,
  getAuditConfigurationTool,
  securityHealthCheckTool,
  createSecurityIncidentTool,
];

export default auditComplianceTools;