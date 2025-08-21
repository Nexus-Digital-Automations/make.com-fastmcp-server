/**
 * @fileoverview Comprehensive test suite for Audit System Configuration
 * Tests audit logging, compliance reporting, and security monitoring
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { configureAuditSystemTool } from '../../../../src/tools/enterprise-secrets/tools/configure-audit-system.js';
import { ToolContext } from '../../../../src/tools/shared/types/tool-context.js';
import { UserError } from 'fastmcp';

// Mock dependencies
const mockApiClient = {
  post: jest.fn(),
  get: jest.fn(),
  put: jest.fn(),
  delete: jest.fn(),
};

const mockLogger = {
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
};

const mockServer = {
  addTool: jest.fn(),
};

describe('Audit System Configuration - Comprehensive Tests', () => {
  let toolContext: ToolContext;

  beforeEach(() => {
    toolContext = {
      server: mockServer as any,
      apiClient: mockApiClient as any,
      logger: mockLogger,
    };
    
    // Reset all mocks
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('Tool Registration and Structure', () => {
    it('should create tool with correct configuration', () => {
      const tool = configureAuditSystemTool(toolContext);
      
      expect(tool.name).toBe('configure-audit-system');
      expect(tool.description).toContain('audit system');
      expect(tool.parameters).toBeDefined();
      expect(tool.annotations).toBeDefined();
      expect(typeof tool.execute).toBe('function');
    });

    it('should have proper audit security annotations', () => {
      const tool = configureAuditSystemTool(toolContext);
      
      expect(tool.annotations.title).toBeDefined();
      expect(tool.annotations.readOnlyHint).toBe(false);
      expect(tool.annotations.destructiveHint).toBe(false);
      expect(tool.annotations.openWorldHint).toBe(false);
    });
  });

  describe('Parameter Validation', () => {
    it('should validate required audit name', async () => {
      const tool = configureAuditSystemTool(toolContext);
      
      await expect(tool.execute({
        // Missing auditName
        logLevel: 'info'
      }, { log: mockLogger })).rejects.toThrow();
    });

    it('should validate log level options', async () => {
      const tool = configureAuditSystemTool(toolContext);
      
      await expect(tool.execute({
        auditName: 'test-audit',
        logLevel: 'invalid-level' as any
      }, { log: mockLogger })).rejects.toThrow();
    });

    it('should validate storage backend options', async () => {
      const tool = configureAuditSystemTool(toolContext);
      
      await expect(tool.execute({
        auditName: 'test-audit',
        logLevel: 'info',
        storageBackend: 'invalid-backend' as any
      }, { log: mockLogger })).rejects.toThrow();
    });

    it('should accept valid audit configuration', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          auditId: 'audit-123',
          status: 'configured',
          logLevel: 'info'
        }
      });

      const tool = configureAuditSystemTool(toolContext);
      
      const result = await tool.execute({
        auditName: 'production-audit',
        logLevel: 'info',
        storageBackend: 'file',
        enableCompliance: true,
        retentionPeriod: '7y'
      }, { log: mockLogger });

      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
    });
  });

  describe('Audit System Configuration', () => {
    beforeEach(() => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          auditId: 'audit-system-123',
          status: 'configured',
          logLevel: 'info',
          backend: 'file',
          compliance: true
        }
      });
    });

    it('should configure basic audit system', async () => {
      const tool = configureAuditSystemTool(toolContext);
      
      const result = await tool.execute({
        auditName: 'basic-audit',
        logLevel: 'info',
        storageBackend: 'file',
        enableCompliance: false,
        retentionPeriod: '1y'
      }, { log: mockLogger });

      expect(mockApiClient.post).toHaveBeenCalledWith(
        '/enterprise-secrets/audit/configure',
        expect.objectContaining({
          auditName: 'basic-audit',
          logLevel: 'info',
          storageBackend: 'file',
          enableCompliance: false,
          retentionPeriod: '1y'
        })
      );

      const parsed = JSON.parse(result);
      expect(parsed.audit).toBeDefined();
      expect(parsed.audit.auditId).toBe('audit-system-123');
      expect(parsed.message).toContain('successfully configured');
    });

    it('should configure enterprise audit with compliance', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          auditId: 'enterprise-audit-456',
          status: 'configured',
          compliance: {
            enabled: true,
            standards: ['SOX', 'HIPAA', 'PCI-DSS', 'SOC2'],
            reporting: true
          }
        }
      });

      const tool = configureAuditSystemTool(toolContext);
      
      const result = await tool.execute({
        auditName: 'enterprise-audit',
        logLevel: 'debug',
        storageBackend: 's3',
        enableCompliance: true,
        complianceStandards: ['SOX', 'HIPAA', 'PCI-DSS'],
        retentionPeriod: '7y',
        enableEncryption: true
      }, { log: mockLogger });

      expect(mockApiClient.post).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          enableCompliance: true,
          complianceStandards: ['SOX', 'HIPAA', 'PCI-DSS'],
          enableEncryption: true
        })
      );

      const parsed = JSON.parse(result);
      expect(parsed.compliance).toBeDefined();
      expect(parsed.compliance.standards).toContain('SOX');
    });

    it('should configure audit with centralized logging', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          auditId: 'centralized-audit-789',
          status: 'configured',
          centralized: {
            enabled: true,
            endpoint: 'https://logs.example.com/audit',
            format: 'json'
          }
        }
      });

      const tool = configureAuditSystemTool(toolContext);
      
      const result = await tool.execute({
        auditName: 'centralized-audit',
        logLevel: 'warn',
        storageBackend: 'syslog',
        centralizedLogging: true,
        logFormat: 'json',
        syslogEndpoint: 'https://logs.example.com/audit'
      }, { log: mockLogger });

      expect(mockApiClient.post).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          centralizedLogging: true,
          logFormat: 'json',
          syslogEndpoint: 'https://logs.example.com/audit'
        })
      );

      const parsed = JSON.parse(result);
      expect(parsed.centralized.enabled).toBe(true);
    });
  });

  describe('Log Level and Filtering', () => {
    it('should configure different log levels', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: { auditId: 'audit-123', status: 'configured' }
      });

      const tool = configureAuditSystemTool(toolContext);
      
      const logLevels = ['debug', 'info', 'warn', 'error'];
      
      for (const level of logLevels) {
        await expect(tool.execute({
          auditName: `audit-${level}`,
          logLevel: level as any,
          storageBackend: 'file'
        }, { log: mockLogger })).resolves.toBeDefined();
      }
    });

    it('should configure event filtering', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          auditId: 'filtered-audit-123',
          status: 'configured',
          filtering: {
            includeEvents: ['authentication', 'authorization', 'data-access'],
            excludeEvents: ['heartbeat', 'metrics'],
            sensitiveDataMask: true
          }
        }
      });

      const tool = configureAuditSystemTool(toolContext);
      
      const result = await tool.execute({
        auditName: 'filtered-audit',
        logLevel: 'info',
        storageBackend: 'file',
        includeEvents: ['authentication', 'authorization', 'data-access'],
        excludeEvents: ['heartbeat', 'metrics'],
        maskSensitiveData: true
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.filtering).toBeDefined();
      expect(parsed.filtering.includeEvents).toContain('authentication');
      expect(parsed.filtering.sensitiveDataMask).toBe(true);
    });

    it('should configure real-time alerting', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          auditId: 'alert-audit-123',
          status: 'configured',
          alerting: {
            enabled: true,
            channels: ['email', 'slack', 'webhook'],
            thresholds: {
              errorRate: '5%',
              failedLogins: 5,
              dataExfiltration: 1
            }
          }
        }
      });

      const tool = configureAuditSystemTool(toolContext);
      
      const result = await tool.execute({
        auditName: 'alert-audit',
        logLevel: 'warn',
        storageBackend: 'file',
        enableAlerting: true,
        alertChannels: ['email', 'slack'],
        alertThresholds: {
          errorRate: '5%',
          failedLogins: 5
        }
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.alerting.enabled).toBe(true);
      expect(parsed.alerting.channels).toContain('email');
    });
  });

  describe('Storage Backend Configuration', () => {
    it('should configure file-based storage', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          auditId: 'file-audit-123',
          status: 'configured',
          storage: {
            backend: 'file',
            path: '/var/log/audit',
            rotation: 'daily',
            compression: 'gzip'
          }
        }
      });

      const tool = configureAuditSystemTool(toolContext);
      
      const result = await tool.execute({
        auditName: 'file-audit',
        logLevel: 'info',
        storageBackend: 'file',
        filePath: '/var/log/audit',
        logRotation: 'daily',
        compressionEnabled: true
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.storage.backend).toBe('file');
      expect(parsed.storage.rotation).toBe('daily');
      expect(parsed.storage.compression).toBe('gzip');
    });

    it('should configure S3 cloud storage', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          auditId: 's3-audit-123',
          status: 'configured',
          storage: {
            backend: 's3',
            bucket: 'audit-logs-bucket',
            region: 'us-east-1',
            encryption: 'AES-256'
          }
        }
      });

      const tool = configureAuditSystemTool(toolContext);
      
      const result = await tool.execute({
        auditName: 's3-audit',
        logLevel: 'info',
        storageBackend: 's3',
        s3Bucket: 'audit-logs-bucket',
        s3Region: 'us-east-1',
        enableEncryption: true
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.storage.backend).toBe('s3');
      expect(parsed.storage.bucket).toBe('audit-logs-bucket');
      expect(parsed.storage.encryption).toBe('AES-256');
    });

    it('should configure database storage', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          auditId: 'db-audit-123',
          status: 'configured',
          storage: {
            backend: 'database',
            connectionString: 'postgresql://audit:***@db.example.com/audit',
            tablePrefix: 'audit_',
            indexing: true
          }
        }
      });

      const tool = configureAuditSystemTool(toolContext);
      
      const result = await tool.execute({
        auditName: 'database-audit',
        logLevel: 'info',
        storageBackend: 'database',
        databaseUrl: 'postgresql://audit:password@db.example.com/audit',
        tablePrefix: 'audit_',
        enableIndexing: true
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.storage.backend).toBe('database');
      expect(parsed.storage.indexing).toBe(true);
    });
  });

  describe('Compliance and Regulatory Features', () => {
    it('should configure SOX compliance', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          auditId: 'sox-audit-123',
          status: 'configured',
          compliance: {
            sox: {
              enabled: true,
              section404: true,
              financialReporting: true,
              changeTracking: true
            }
          }
        }
      });

      const tool = configureAuditSystemTool(toolContext);
      
      const result = await tool.execute({
        auditName: 'sox-compliance-audit',
        logLevel: 'debug',
        storageBackend: 'database',
        enableCompliance: true,
        complianceStandards: ['SOX'],
        retentionPeriod: '7y',
        tamperProofing: true
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.compliance.sox.enabled).toBe(true);
      expect(parsed.compliance.sox.section404).toBe(true);
    });

    it('should configure HIPAA compliance', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          auditId: 'hipaa-audit-123',
          status: 'configured',
          compliance: {
            hipaa: {
              enabled: true,
              safeguards: ['administrative', 'physical', 'technical'],
              phi_protection: true,
              breach_notification: true
            }
          }
        }
      });

      const tool = configureAuditSystemTool(toolContext);
      
      const result = await tool.execute({
        auditName: 'hipaa-compliance-audit',
        logLevel: 'info',
        storageBackend: 's3',
        enableCompliance: true,
        complianceStandards: ['HIPAA'],
        retentionPeriod: '6y',
        enableEncryption: true,
        maskSensitiveData: true
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.compliance.hipaa.enabled).toBe(true);
      expect(parsed.compliance.hipaa.phi_protection).toBe(true);
    });

    it('should configure GDPR compliance', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          auditId: 'gdpr-audit-123',
          status: 'configured',
          compliance: {
            gdpr: {
              enabled: true,
              right_to_erasure: true,
              data_portability: true,
              consent_tracking: true,
              breach_notification_72h: true
            }
          }
        }
      });

      const tool = configureAuditSystemTool(toolContext);
      
      const result = await tool.execute({
        auditName: 'gdpr-compliance-audit',
        logLevel: 'info',
        storageBackend: 'file',
        enableCompliance: true,
        complianceStandards: ['GDPR'],
        retentionPeriod: '3y',
        enableDataAnonymization: true
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.compliance.gdpr.enabled).toBe(true);
      expect(parsed.compliance.gdpr.right_to_erasure).toBe(true);
    });
  });

  describe('Error Handling', () => {
    it('should handle storage backend failures', async () => {
      mockApiClient.post.mockRejectedValue(new Error('Storage backend unavailable'));

      const tool = configureAuditSystemTool(toolContext);
      
      await expect(tool.execute({
        auditName: 'failed-storage-audit',
        logLevel: 'info',
        storageBackend: 'database',
        databaseUrl: 'postgresql://broken-db.example.com/audit'
      }, { log: mockLogger })).rejects.toThrow(UserError);

      expect(mockLogger.error).toHaveBeenCalledWith(
        expect.stringContaining('Failed to configure audit system'),
        expect.any(Object)
      );
    });

    it('should handle invalid retention period', async () => {
      const tool = configureAuditSystemTool(toolContext);
      
      await expect(tool.execute({
        auditName: 'invalid-retention-audit',
        logLevel: 'info',
        storageBackend: 'file',
        retentionPeriod: 'invalid-period'
      }, { log: mockLogger })).rejects.toThrow();
    });

    it('should handle compliance configuration errors', async () => {
      mockApiClient.post.mockResolvedValue({
        success: false,
        error: { message: 'Compliance standard not supported', code: 'COMPLIANCE_ERROR' }
      });

      const tool = configureAuditSystemTool(toolContext);
      
      await expect(tool.execute({
        auditName: 'compliance-error-audit',
        logLevel: 'info',
        storageBackend: 'file',
        enableCompliance: true,
        complianceStandards: ['UNKNOWN-STANDARD' as any]
      }, { log: mockLogger })).rejects.toThrow(UserError);
    });

    it('should handle insufficient permissions', async () => {
      mockApiClient.post.mockResolvedValue({
        success: false,
        error: { message: 'Insufficient permissions to configure audit', code: 'PERMISSION_DENIED' }
      });

      const tool = configureAuditSystemTool(toolContext);
      
      await expect(tool.execute({
        auditName: 'permission-error-audit',
        logLevel: 'info',
        storageBackend: 's3',
        s3Bucket: 'restricted-bucket'
      }, { log: mockLogger })).rejects.toThrow(UserError);
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle high-volume audit configurations', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          auditId: 'high-volume-audit-123',
          status: 'configured',
          performance: {
            throughput: '10000 events/sec',
            buffer_size: '1MB',
            batch_processing: true
          }
        }
      });

      const tool = configureAuditSystemTool(toolContext);
      
      const result = await tool.execute({
        auditName: 'high-volume-audit',
        logLevel: 'info',
        storageBackend: 'database',
        enableBatching: true,
        batchSize: 1000,
        bufferSize: '1MB'
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.performance.batch_processing).toBe(true);
      expect(parsed.performance.throughput).toContain('events/sec');
    });

    it('should configure audit system monitoring', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: {
          auditId: 'monitored-audit-123',
          status: 'configured',
          monitoring: {
            enabled: true,
            metrics: ['throughput', 'latency', 'errors', 'storage_usage'],
            health_checks: true,
            dashboard_url: 'https://monitoring.example.com/audit'
          }
        }
      });

      const tool = configureAuditSystemTool(toolContext);
      
      const result = await tool.execute({
        auditName: 'monitored-audit',
        logLevel: 'info',
        storageBackend: 'file',
        enableMonitoring: true,
        monitoringLevel: 'detailed'
      }, { log: mockLogger });

      const parsed = JSON.parse(result);
      expect(parsed.monitoring.enabled).toBe(true);
      expect(parsed.monitoring.metrics).toContain('throughput');
    });

    it('should handle concurrent audit system configurations', async () => {
      mockApiClient.post.mockResolvedValue({
        success: true,
        data: { auditId: 'audit-123', status: 'configured' }
      });

      const tool = configureAuditSystemTool(toolContext);
      
      const configurations = Array(3).fill(0).map(async (_, i) => {
        return tool.execute({
          auditName: `concurrent-audit-${i}`,
          logLevel: 'info',
          storageBackend: 'file'
        }, { log: mockLogger });
      });

      const results = await Promise.allSettled(configurations);
      const successful = results.filter(r => r.status === 'fulfilled');
      
      expect(successful).toHaveLength(3);
    });
  });
});