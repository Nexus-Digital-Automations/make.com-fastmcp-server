/**
 * @fileoverview Security configuration schemas for enterprise secrets management
 * Contains Zod schemas for secret scanning, breach detection, and audit configuration
 */

import { z } from 'zod';

/**
 * Security Policy Configuration Schema
 */
export const SecurityPolicySchema = z.object({
  passwordPolicy: z.object({
    minLength: z.number().min(8).optional().default(12),
    requireUppercase: z.boolean().optional().default(true),
    requireLowercase: z.boolean().optional().default(true),
    requireNumbers: z.boolean().optional().default(true),
    requireSpecialChars: z.boolean().optional().default(true),
    maxAge: z.number().optional().default(90),
  }).optional(),
  encryptionPolicy: z.object({
    algorithm: z.enum(['AES', 'ChaCha20', 'RSA']).optional().default('AES'),
    keySize: z.number().optional().default(256),
    mode: z.enum(['GCM', 'CBC', 'CTR']).optional().default('GCM'),
  }).optional(),
  networkPolicy: z.object({
    tlsVersion: z.enum(['1.2', '1.3']).optional().default('1.3'),
    certificateValidation: z.boolean().optional().default(true),
    cipherSuites: z.array(z.string()).optional(),
  }).optional(),
});

/**
 * Secret Scanning Configuration Schema
 */
export const SecretScanningConfigSchema = z.object({
  scanType: z.enum(['repository', 'runtime', 'configuration', 'memory', 'network']),
  targets: z.array(z.string()).min(1, 'At least one scan target is required'),
  detectionRules: z.object({
    entropyThreshold: z.number().min(0).max(8).optional().default(4.0),
    patternMatching: z.boolean().optional().default(true),
    customPatterns: z.array(z.object({
      name: z.string(),
      pattern: z.string(),
      confidence: z.number().min(0).max(1),
    })).optional(),
    whitelistPatterns: z.array(z.string()).optional(),
  }),
  responseActions: z.object({
    alertSeverity: z.enum(['low', 'medium', 'high', 'critical']).default('high'),
    automaticRevocation: z.boolean().optional().default(false),
    quarantineEnabled: z.boolean().optional().default(true),
    notificationChannels: z.array(z.string()).optional(),
  }),
});

/**
 * Breach Detection Configuration Schema
 */
export const BreachDetectionConfigSchema = z.object({
  detectionMethods: z.object({
    anomalyDetection: z.boolean().default(true),
    patternAnalysis: z.boolean().default(true),
    threatIntelligence: z.boolean().default(true),
    behavioralAnalysis: z.boolean().default(true),
  }),
  monitoringTargets: z.array(z.enum([
    'secret_access_patterns',
    'authentication_events',
    'authorization_failures',
    'unusual_api_usage',
    'geographic_anomalies',
    'time_based_anomalies'
  ])),
  responseConfig: z.object({
    automaticContainment: z.boolean().default(true),
    alertEscalation: z.boolean().default(true),
    forensicCollection: z.boolean().default(true),
    stakeholderNotification: z.boolean().default(true),
  }),
  thresholds: z.object({
    accessFrequencyThreshold: z.number().default(100),
    geographicVelocityKmh: z.number().default(1000),
    failureRateThreshold: z.number().default(0.1),
    anomalyScoreThreshold: z.number().default(0.8),
  }),
});

/**
 * Audit Configuration Schema
 */
export const AuditConfigSchema = z.object({
  auditDevices: z.array(z.object({
    type: z.enum(['file', 'syslog', 'socket', 'elasticsearch', 'splunk']),
    path: z.string(),
    config: z.record(z.string(), z.unknown()),
    format: z.enum(['json', 'jsonx']).optional().default('json'),
    prefix: z.string().optional(),
  })),
  auditFilters: z.object({
    excludeUnauthentic: z.boolean().optional().default(true),
    excludeHealthChecks: z.boolean().optional().default(true),
    sensitiveDataRedaction: z.boolean().optional().default(true),
    customFilters: z.array(z.string()).optional(),
  }),
  retention: z.object({
    retentionPeriodDays: z.number().min(1).default(2555), // 7 years default
    compressionEnabled: z.boolean().optional().default(true),
    encryptionEnabled: z.boolean().optional().default(true),
    immutableStorage: z.boolean().optional().default(true),
  }),
  compliance: z.object({
    frameworks: z.array(z.enum(['soc2', 'pci_dss', 'gdpr', 'hipaa', 'fisma', 'iso27001'])),
    evidenceCollection: z.boolean().optional().default(true),
    reportGeneration: z.boolean().optional().default(true),
  }),
});

/**
 * Compliance Report Generation Schema
 */
export const ComplianceReportSchema = z.object({
  framework: z.enum(['soc2', 'pci_dss', 'gdpr', 'hipaa', 'fisma', 'iso27001']),
});