/**
 * Enhanced configuration manager with secure credential management
 * Extends the base config with encryption, rotation, and audit capabilities
 */

import * as crypto from 'crypto';
import * as os from 'os';
import configManager, { ConfigurationError } from './config.js';
import { encryptionService, credentialManager, CredentialMetadata } from '../utils/encryption.js';
import logger from './logger.js';
import { MakeApiConfig } from '../types/index.js';
import type {
  RotationPolicy,
  CredentialRotationRequest,
  RotationBatch,
  RotationResult,
  RotationError,
  RotationManagerConfig,
  ExternalServiceConfig
} from '../types/rotation-types.js';

export interface SecureCredentialConfig {
  credentialId: string;
  encrypted: boolean;
  lastRotated?: Date;
  nextRotation?: Date;
  rotationInterval?: number; // milliseconds
  autoRotate: boolean;
}

export interface SecureMakeApiConfig extends Omit<MakeApiConfig, 'apiKey'> {
  credentials: {
    apiKey: SecureCredentialConfig;
    authSecret?: SecureCredentialConfig;
  };
}

export interface CredentialRotationPolicy {
  enabled: boolean;
  interval: number; // milliseconds
  gracePeriod: number; // milliseconds
  maxAge: number; // milliseconds
  notifyBeforeExpiry: number; // milliseconds
}

export interface SecurityAuditEvent {
  timestamp: Date;
  event: 'credential_accessed' | 'credential_rotated' | 'credential_expired' | 'unauthorized_access';
  credentialId: string;
  userId?: string;
  source: string;
  success: boolean;
  metadata?: Record<string, unknown>;
}

/**
 * Enhanced configuration manager with secure credential handling
 */
export class SecureConfigManager {
  private static instance: SecureConfigManager;
  private readonly componentLogger: ReturnType<typeof logger.child>;
  private readonly masterPassword: string;
  private readonly rotationPolicies: Map<string, CredentialRotationPolicy> = new Map();
  private securityEvents: SecurityAuditEvent[] = [];
  private readonly rotationTimers: Map<string, NodeJS.Timeout> = new Map();
  
  // Concurrent rotation support
  private concurrentRotationAgent: { 
    initialize(): Promise<void>;
    start(): Promise<void>;
    stop(): Promise<void>;
    enqueueBatch(batch: RotationBatch): void;
    on(event: string, handler: (...args: unknown[]) => void): void;
    off(event: string, handler: (...args: unknown[]) => void): void;
    getStatus(): { enabled: boolean; [key: string]: unknown };
    getQueueStatus(): { [key: string]: unknown };
    getPerformanceMetrics(): { [key: string]: unknown };
  } | null = null; // Lazy loaded to avoid circular dependencies
  private readonly enhancedRotationPolicies: Map<string, RotationPolicy> = new Map();
  private batchRotationEnabled = false;

  private constructor() {
    // Initialize logger with fallback for test environments
    try {
      this.componentLogger = logger?.child ? logger.child({ component: 'SecureConfigManager' }) : {
        info: () => {},
        warn: () => {},
        error: () => {},
        debug: () => {},
        child: () => this.componentLogger
      } as unknown as ReturnType<typeof logger.child>;
    } catch {
      // Fallback logger for test environments
      this.componentLogger = {
        info: () => {},
        warn: () => {},
        error: () => {},
        debug: () => {},
        child: () => this.componentLogger
      } as unknown as ReturnType<typeof logger.child>;
    }
    this.masterPassword = this.initializeMasterPassword();
    this.setupDefaultRotationPolicies();
  }

  public static getInstance(): SecureConfigManager {
    if (!SecureConfigManager.instance) {
      SecureConfigManager.instance = new SecureConfigManager();
    }
    return SecureConfigManager.instance;
  }

  /**
   * Initialize master password for credential encryption
   */
  private initializeMasterPassword(): string {
    // In production, this should come from secure key management service
    const envPassword = process.env.CREDENTIAL_MASTER_PASSWORD;
    if (envPassword && envPassword.length >= 32) {
      return envPassword;
    }

    try {
      // Generate a secure master password if not provided
      const generated = encryptionService.generateSecureSecret(64);
      this.componentLogger.warn('Generated master password for credential encryption. In production, use CREDENTIAL_MASTER_PASSWORD environment variable.');
      
      // Store in environment for this session (not persistent!)
      process.env.CREDENTIAL_MASTER_PASSWORD = generated;
      return generated;
    } catch {
      // Fallback for test environments where encryption service might not be available
      const fallbackPassword = 'test_master_password_' + Math.random().toString(36).substring(2, 15);
      this.componentLogger.warn('Using fallback master password for test environment');
      process.env.CREDENTIAL_MASTER_PASSWORD = fallbackPassword;
      return fallbackPassword;
    }
  }

  /**
   * Setup default rotation policies
   */
  private setupDefaultRotationPolicies(): void {
    // API Key rotation policy
    this.rotationPolicies.set('api_key', {
      enabled: process.env.NODE_ENV === 'production',
      interval: 90 * 24 * 60 * 60 * 1000, // 90 days
      gracePeriod: 7 * 24 * 60 * 60 * 1000, // 7 days
      maxAge: 180 * 24 * 60 * 60 * 1000, // 180 days
      notifyBeforeExpiry: 14 * 24 * 60 * 60 * 1000 // 14 days
    });

    // Auth secret rotation policy
    this.rotationPolicies.set('auth_secret', {
      enabled: process.env.NODE_ENV === 'production',
      interval: 30 * 24 * 60 * 60 * 1000, // 30 days
      gracePeriod: 3 * 24 * 60 * 60 * 1000, // 3 days
      maxAge: 60 * 24 * 60 * 60 * 1000, // 60 days
      notifyBeforeExpiry: 7 * 24 * 60 * 60 * 1000 // 7 days
    });
  }

  /**
   * Securely store a credential with encryption and metadata
   */
  public async storeCredential(
    type: CredentialMetadata['type'],
    service: string,
    value: string,
    options: {
      autoRotate?: boolean;
      rotationInterval?: number;
      userId?: string;
    } = {}
  ): Promise<string> {
    try {
      // Store encrypted credential
      const credentialId = await credentialManager.storeCredential(
        value,
        type,
        service,
        this.masterPassword,
        {
          userId: options.userId,
          expiresIn: options.rotationInterval
        }
      );

      // Setup rotation if enabled
      if (options.autoRotate && options.rotationInterval) {
        this.scheduleRotation(credentialId, options.rotationInterval);
      }

      // Log security event
      this.logSecurityEvent({
        timestamp: new Date(),
        event: 'credential_accessed',
        credentialId,
        userId: options.userId,
        source: 'SecureConfigManager.storeCredential',
        success: true,
        metadata: { type, service, autoRotate: options.autoRotate }
      });

      this.componentLogger.info('Credential stored securely', {
        credentialId,
        type,
        service,
        encrypted: true,
        autoRotate: options.autoRotate
      });

      return credentialId;
    } catch (error) {
      this.logSecurityEvent({
        timestamp: new Date(),
        event: 'credential_accessed',
        credentialId: 'unknown',
        userId: options.userId,
        source: 'SecureConfigManager.storeCredential',
        success: false,
        metadata: { error: error instanceof Error ? error.message : 'Unknown error' }
      });
      throw error;
    }
  }

  /**
   * Retrieve and decrypt a credential
   */
  public async getCredential(credentialId: string, userId?: string): Promise<string> {
    try {
      const credential = await credentialManager.retrieveCredential(
        credentialId,
        this.masterPassword,
        userId
      );

      // Check if credential needs rotation
      const metadata = credentialManager.getCredentialMetadata(credentialId);
      if (metadata) {
        this.checkRotationNeeded(metadata);
      }

      // Log successful access
      this.logSecurityEvent({
        timestamp: new Date(),
        event: 'credential_accessed',
        credentialId,
        userId,
        source: 'SecureConfigManager.getCredential',
        success: true
      });

      return credential;
    } catch (error) {
      // Log failed access
      this.logSecurityEvent({
        timestamp: new Date(),
        event: 'unauthorized_access',
        credentialId,
        userId,
        source: 'SecureConfigManager.getCredential',
        success: false,
        metadata: { error: error instanceof Error ? error.message : 'Unknown error' }
      });
      throw error;
    }
  }

  /**
   * Get Make.com API configuration with secure credential handling
   */
  public async getSecureMakeConfig(userId?: string): Promise<MakeApiConfig> {
    try {
      const baseConfig = configManager.getMakeConfig();
      
      // Check if API key is stored as credential ID
      const apiKeyCredentialId = process.env.MAKE_API_KEY_CREDENTIAL_ID;
      
      if (apiKeyCredentialId) {
        // Retrieve encrypted API key
        const apiKey = await this.getCredential(apiKeyCredentialId, userId);
        return {
          ...baseConfig,
          apiKey
        };
      } else {
        // Fallback to standard configuration
        this.componentLogger.warn('Using non-encrypted API key. Consider migrating to secure credential storage.');
        return baseConfig;
      }
    } catch (error) {
      this.componentLogger.error('Failed to retrieve secure Make.com configuration', {
        error: error instanceof Error ? error.message : 'Unknown error',
        userId
      });
      throw new ConfigurationError('Failed to retrieve secure configuration');
    }
  }

  /**
   * Migrate existing plain-text credentials to encrypted storage
   */
  public async migrateToSecureStorage(userId?: string): Promise<{
    migrated: string[];
    errors: Array<{ credential: string; error: string }>;
  }> {
    const migrated: string[] = [];
    const errors: Array<{ credential: string; error: string }> = [];

    try {
      // Migrate Make.com API key
      const makeConfig = configManager.getMakeConfig();
      if (makeConfig.apiKey && !process.env.MAKE_API_KEY_CREDENTIAL_ID) {
        try {
          const credentialId = await this.storeCredential(
            'api_key',
            'make.com',
            makeConfig.apiKey,
            {
              autoRotate: true,
              rotationInterval: this.rotationPolicies.get('api_key')?.interval,
              userId
            }
          );
          
          // Store credential ID for future use
          process.env.MAKE_API_KEY_CREDENTIAL_ID = credentialId;
          migrated.push('make_api_key');
          
          this.componentLogger.info('Migrated Make.com API key to secure storage', { credentialId });
        } catch (error) {
          errors.push({
            credential: 'make_api_key',
            error: error instanceof Error ? error.message : 'Unknown error'
          });
        }
      }

      // Migrate auth secret
      const authSecret = configManager.getAuthSecret();
      if (authSecret && !process.env.AUTH_SECRET_CREDENTIAL_ID) {
        try {
          const credentialId = await this.storeCredential(
            'secret',
            'auth',
            authSecret,
            {
              autoRotate: true,
              rotationInterval: this.rotationPolicies.get('auth_secret')?.interval,
              userId
            }
          );
          
          // Store credential ID for future use
          process.env.AUTH_SECRET_CREDENTIAL_ID = credentialId;
          migrated.push('auth_secret');
          
          this.componentLogger.info('Migrated auth secret to secure storage', { credentialId });
        } catch (error) {
          errors.push({
            credential: 'auth_secret',
            error: error instanceof Error ? error.message : 'Unknown error'
          });
        }
      }

      return { migrated, errors };
    } catch (error) {
      this.componentLogger.error('Migration to secure storage failed', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new ConfigurationError('Failed to migrate credentials to secure storage');
    }
  }

  /**
   * Rotate a credential immediately
   */
  public async rotateCredential(
    credentialId: string,
    options: {
      newValue?: string;
      gracePeriod?: number;
      userId?: string;
    } = {}
  ): Promise<string> {
    try {
      const metadata = credentialManager.getCredentialMetadata(credentialId);
      if (!metadata) {
        throw new Error(`Credential ${credentialId} not found`);
      }

      // Get rotation policy
      const policy = this.rotationPolicies.get(metadata.type);
      const gracePeriod = options.gracePeriod || policy?.gracePeriod || 24 * 60 * 60 * 1000; // 24 hours default

      // Generate new credential if not provided
      let newValue = options.newValue;
      if (!newValue) {
        newValue = metadata.type === 'api_key' 
          ? encryptionService.generateApiKey('mcp', 32)
          : encryptionService.generateSecureSecret();
      }

      // Rotate the credential
      const newCredentialId = await credentialManager.rotateCredential(
        credentialId,
        this.masterPassword,
        {
          newCredential: newValue,
          gracePeriod,
          userId: options.userId
        }
      );

      // Update environment variable if this is a system credential
      if (process.env.MAKE_API_KEY_CREDENTIAL_ID === credentialId) {
        process.env.MAKE_API_KEY_CREDENTIAL_ID = newCredentialId;
      }
      if (process.env.AUTH_SECRET_CREDENTIAL_ID === credentialId) {
        process.env.AUTH_SECRET_CREDENTIAL_ID = newCredentialId;
      }

      // Schedule next rotation
      if (policy?.enabled && policy.interval) {
        this.scheduleRotation(newCredentialId, policy.interval);
      }

      // Log rotation event
      this.logSecurityEvent({
        timestamp: new Date(),
        event: 'credential_rotated',
        credentialId: newCredentialId,
        userId: options.userId,
        source: 'SecureConfigManager.rotateCredential',
        success: true,
        metadata: {
          oldCredentialId: credentialId,
          gracePeriod,
          service: metadata.service
        }
      });

      this.componentLogger.info('Credential rotated successfully', {
        oldCredentialId: credentialId,
        newCredentialId,
        service: metadata.service,
        gracePeriod
      });

      return newCredentialId;
    } catch (error) {
      this.logSecurityEvent({
        timestamp: new Date(),
        event: 'credential_rotated',
        credentialId,
        userId: options.userId,
        source: 'SecureConfigManager.rotateCredential',
        success: false,
        metadata: { error: error instanceof Error ? error.message : 'Unknown error' }
      });
      throw error;
    }
  }

  /**
   * Schedule automatic credential rotation
   */
  private scheduleRotation(credentialId: string, interval: number): void {
    // Clear existing timer if any
    const existingTimer = this.rotationTimers.get(credentialId);
    if (existingTimer) {
      clearTimeout(existingTimer);
    }

    // Schedule new rotation
    const timer = setTimeout(async () => {
      try {
        await this.rotateCredential(credentialId);
        this.componentLogger.info('Automatic credential rotation completed', { credentialId });
      } catch (error) {
        this.componentLogger.error('Automatic credential rotation failed', {
          credentialId,
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    }, interval);

    this.rotationTimers.set(credentialId, timer);
    this.componentLogger.debug('Scheduled credential rotation', {
      credentialId,
      intervalMs: interval,
      nextRotation: new Date(Date.now() + interval)
    });
  }

  /**
   * Check if credential needs rotation
   */
  private checkRotationNeeded(metadata: CredentialMetadata): void {
    const policy = this.rotationPolicies.get(metadata.type);
    if (!policy?.enabled) {return;}

    const now = new Date();
    const createdAt = metadata.rotationInfo.createdAt;
    const age = now.getTime() - createdAt.getTime();

    // Check if rotation is due
    if (age >= policy.interval) {
      this.componentLogger.warn('Credential rotation overdue', {
        credentialId: metadata.id,
        age: Math.floor(age / (24 * 60 * 60 * 1000)), // days
        service: metadata.service
      });

      // Log expiry event
      this.logSecurityEvent({
        timestamp: now,
        event: 'credential_expired',
        credentialId: metadata.id,
        source: 'SecureConfigManager.checkRotationNeeded',
        success: false,
        metadata: {
          ageMs: age,
          intervalMs: policy.interval,
          service: metadata.service
        }
      });
    }
    // Check if expiry notification is due
    else if (age >= (policy.interval - policy.notifyBeforeExpiry)) {
      const daysUntilExpiry = Math.ceil((policy.interval - age) / (24 * 60 * 60 * 1000));
      this.componentLogger.warn('Credential rotation due soon', {
        credentialId: metadata.id,
        daysUntilExpiry,
        service: metadata.service
      });
    }
  }

  /**
   * Get credential security status
   */
  public getCredentialStatus(credentialId: string): {
    metadata: CredentialMetadata | undefined;
    rotationPolicy: CredentialRotationPolicy | undefined;
    status: 'healthy' | 'rotation_due' | 'expired' | 'not_found';
    nextRotation?: Date;
    daysUntilRotation?: number;
  } {
    const metadata = credentialManager.getCredentialMetadata(credentialId);
    if (!metadata) {
      return {
        metadata: undefined,
        rotationPolicy: undefined,
        status: 'not_found'
      };
    }

    const policy = this.rotationPolicies.get(metadata.type);
    if (!policy) {
      return {
        metadata,
        rotationPolicy: undefined,
        status: 'healthy'
      };
    }

    const now = new Date();
    const age = now.getTime() - metadata.rotationInfo.createdAt.getTime();
    const nextRotation = new Date(metadata.rotationInfo.createdAt.getTime() + policy.interval);
    const daysUntilRotation = Math.ceil((policy.interval - age) / (24 * 60 * 60 * 1000));

    let status: 'healthy' | 'rotation_due' | 'expired';
    if (age >= policy.maxAge) {
      status = 'expired';
    } else if (age >= policy.interval) {
      status = 'rotation_due';
    } else {
      status = 'healthy';
    }

    return {
      metadata,
      rotationPolicy: policy,
      status,
      nextRotation,
      daysUntilRotation
    };
  }

  /**
   * Get security audit events
   */
  public getSecurityEvents(filter?: {
    credentialId?: string;
    userId?: string;
    event?: SecurityAuditEvent['event'];
    startDate?: Date;
    endDate?: Date;
    limit?: number;
  }): SecurityAuditEvent[] {
    let events = [...this.securityEvents];

    if (filter) {
      events = events.filter(event => {
        if (filter.credentialId && event.credentialId !== filter.credentialId) {return false;}
        if (filter.userId && event.userId !== filter.userId) {return false;}
        if (filter.event && event.event !== filter.event) {return false;}
        if (filter.startDate && event.timestamp < filter.startDate) {return false;}
        if (filter.endDate && event.timestamp > filter.endDate) {return false;}
        return true;
      });
    }

    // Sort by timestamp (newest first)
    events.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    // Apply limit
    if (filter?.limit) {
      events = events.slice(0, filter.limit);
    }

    return events;
  }

  /**
   * Cleanup expired credentials and old audit events
   */
  public async cleanup(): Promise<{
    expiredCredentials: number;
    oldEvents: number;
  }> {
    // Cleanup expired credentials
    const expiredCredentials = await credentialManager.cleanupExpiredCredentials();

    // Cleanup old audit events (keep last 30 days)
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const originalEventCount = this.securityEvents.length;
    this.securityEvents = this.securityEvents.filter(event => event.timestamp >= thirtyDaysAgo);
    const oldEvents = originalEventCount - this.securityEvents.length;

    this.componentLogger.info('Credential cleanup completed', {
      expiredCredentials,
      oldEvents
    });

    return { expiredCredentials, oldEvents };
  }

  /**
   * Log security event
   */
  private logSecurityEvent(event: SecurityAuditEvent): void {
    this.securityEvents.push(event);

    // Keep only last 10000 events to prevent memory issues
    if (this.securityEvents.length > 10000) {
      this.securityEvents = this.securityEvents.slice(-10000);
    }

    this.componentLogger.debug('Security event logged', event as unknown as Record<string, unknown>);
  }

  /**
   * Enable concurrent rotation with advanced policies
   */
  public async enableConcurrentRotation(config?: RotationManagerConfig): Promise<void> {
    if (this.batchRotationEnabled) {
      this.componentLogger.warn('Concurrent rotation already enabled');
      return;
    }
    
    try {
      // Lazy load ConcurrentRotationAgent to avoid circular dependencies
      const { ConcurrentRotationAgent } = await import('../utils/concurrent-rotation-agent.js');
      
      const defaultConfig: RotationManagerConfig = {
        maxWorkerThreads: Math.min(4, os.cpus().length),
        workerTimeoutMs: 30000,
        workerHealthCheckIntervalMs: 5000,
        defaultConcurrency: 2,
        maxQueueSize: 1000,
        priorityLevels: 5,
        defaultBatchSize: 10,
        maxBatchSize: 50,
        batchTimeoutMs: 300000,
        externalServiceTimeoutMs: 15000,
        maxExternalServiceRetries: 3,
        externalServiceHealthCheckIntervalMs: 30000,
        auditRetentionDays: 90,
        logLevel: 'info',
        metricsCollectionIntervalMs: 5000,
        performanceThresholds: {
          maxRotationTimeMs: 30000,
          maxMemoryUsageMB: 512,
          maxCpuUsagePercent: 80,
          maxErrorRate: 0.05
        },
        encryptionKeyRotationIntervalMs: 86400000, // 24 hours
        auditLogEncryption: true,
        secureMemoryWipe: true
      };
      
      const finalConfig = { ...defaultConfig, ...config };
      
      this.concurrentRotationAgent = new ConcurrentRotationAgent(finalConfig);
      await this.concurrentRotationAgent.initialize();
      await this.concurrentRotationAgent.start();
      
      this.batchRotationEnabled = true;
      this.setupEnhancedRotationPolicies();
      
      this.componentLogger.info('Concurrent rotation enabled successfully', {
        maxWorkerThreads: finalConfig.maxWorkerThreads,
        defaultConcurrency: finalConfig.defaultConcurrency
      });
      
    } catch (error) {
      this.componentLogger.error('Failed to enable concurrent rotation', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw new ConfigurationError('Failed to enable concurrent rotation');
    }
  }
  
  /**
   * Disable concurrent rotation and fall back to simple rotation
   */
  public async disableConcurrentRotation(): Promise<void> {
    if (!this.batchRotationEnabled || !this.concurrentRotationAgent) {
      return;
    }
    
    try {
      await this.concurrentRotationAgent.stop();
      this.concurrentRotationAgent = null;
      this.batchRotationEnabled = false;
      
      this.componentLogger.info('Concurrent rotation disabled');
    } catch (error) {
      this.componentLogger.error('Error disabling concurrent rotation', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }
  
  /**
   * Setup enhanced rotation policies for concurrent operations
   */
  private setupEnhancedRotationPolicies(): void {
    // API Key enhanced policy
    this.enhancedRotationPolicies.set('api_key_enhanced', {
      id: 'api_key_enhanced',
      name: 'Enhanced API Key Rotation',
      type: 'time_based',
      enabled: process.env.NODE_ENV === 'production',
      interval: 90 * 24 * 60 * 60 * 1000, // 90 days
      gracePeriod: 7 * 24 * 60 * 60 * 1000, // 7 days
      notifyBeforeExpiry: 14 * 24 * 60 * 60 * 1000, // 14 days
      maxAge: 180 * 24 * 60 * 60 * 1000, // 180 days
      maxRetries: 3,
      retryInterval: 5 * 60 * 1000 // 5 minutes
    });
    
    // Auth secret enhanced policy
    this.enhancedRotationPolicies.set('auth_secret_enhanced', {
      id: 'auth_secret_enhanced',
      name: 'Enhanced Auth Secret Rotation',
      type: 'time_based',
      enabled: process.env.NODE_ENV === 'production',
      interval: 30 * 24 * 60 * 60 * 1000, // 30 days
      gracePeriod: 3 * 24 * 60 * 60 * 1000, // 3 days
      notifyBeforeExpiry: 7 * 24 * 60 * 60 * 1000, // 7 days
      maxAge: 60 * 24 * 60 * 60 * 1000, // 60 days
      maxRetries: 3,
      retryInterval: 5 * 60 * 1000 // 5 minutes
    });
    
    // Emergency rotation policy
    this.enhancedRotationPolicies.set('emergency', {
      id: 'emergency',
      name: 'Emergency Credential Rotation',
      type: 'emergency',
      enabled: true,
      gracePeriod: 5 * 60 * 1000, // 5 minutes
      notifyBeforeExpiry: 0, // Immediate
      maxAge: 15 * 60 * 1000, // 15 minutes max age
      maxRetries: 1,
      retryInterval: 30 * 1000 // 30 seconds
    });
  }
  
  /**
   * Rotate credential using concurrent agent if available
   */
  public async rotateCredentialConcurrent(
    credentialId: string,
    options: {
      newValue?: string;
      gracePeriod?: number;
      userId?: string;
      policyId?: string;
      priority?: 'low' | 'normal' | 'high' | 'critical' | 'emergency';
      externalServices?: Array<{
        serviceId: string;
        serviceName: string;
        type: string;
        updateMethod: string;
        endpoint?: string;
        authMethod: string;
        validationTimeout: number;
        rollbackSupported: boolean;
      }>;
    } = {}
  ): Promise<string> {
    if (!this.batchRotationEnabled || !this.concurrentRotationAgent) {
      // Fall back to standard rotation
      return this.rotateCredential(credentialId, options);
    }
    
    try {
      const policyId = options.policyId || 'api_key_enhanced';
      const policy = this.enhancedRotationPolicies.get(policyId);
      
      if (!policy) {
        throw new Error(`Rotation policy not found: ${policyId}`);
      }
      
      const request: CredentialRotationRequest = {
        credentialId,
        policyId,
        priority: options.priority || 'normal',
        newValue: options.newValue,
        gracePeriod: options.gracePeriod || policy.gracePeriod,
        userId: options.userId,
        externalServices: options.externalServices?.map(service => ({
          serviceId: service.serviceId,
          serviceName: service.serviceName,
          type: service.type as ExternalServiceConfig['type'],
          endpoint: service.endpoint,
          authMethod: service.authMethod as ExternalServiceConfig['authMethod'],
          updateMethod: service.updateMethod as ExternalServiceConfig['updateMethod'],
          validationTimeout: service.validationTimeout,
          rollbackSupported: service.rollbackSupported
        }))
      };
      
      // For single credential rotation, create a micro-batch
      const batch: RotationBatch = {
        batchId: `single_${credentialId}_${Date.now()}`,
        createdAt: new Date(),
        status: 'pending',
        requests: [request],
        concurrency: 1,
        priority: request.priority,
        processedCount: 0,
        successCount: 0,
        failedCount: 0
      };
      
      return new Promise((resolve, reject) => {
        // Set up event listeners
        const onCompleted = (result: RotationResult): void => {
          if (result.credentialId === credentialId || result.oldCredentialId === credentialId) {
            this.concurrentRotationAgent.off('rotation_completed', onCompleted);
            this.concurrentRotationAgent.off('rotation_failed', onFailed);
            resolve(result.newCredentialId);
          }
        };
        
        const onFailed = (error: RotationError): void => {
          if (error.credentialId === credentialId) {
            this.concurrentRotationAgent.off('rotation_completed', onCompleted);
            this.concurrentRotationAgent.off('rotation_failed', onFailed);
            reject(new Error(error.errorMessage));
          }
        };
        
        this.concurrentRotationAgent.on('rotation_completed', onCompleted);
        this.concurrentRotationAgent.on('rotation_failed', onFailed);
        
        // Enqueue the rotation
        this.concurrentRotationAgent.enqueueBatch(batch);
        
        // Set timeout
        setTimeout(() => {
          this.concurrentRotationAgent.off('rotation_completed', onCompleted);
          this.concurrentRotationAgent.off('rotation_failed', onFailed);
          reject(new Error('Concurrent rotation timeout'));
        }, policy.gracePeriod || 60000);
      });
      
    } catch (error) {
      this.componentLogger.error('Concurrent rotation failed, falling back to standard rotation', {
        credentialId,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      
      // Fall back to standard rotation
      return this.rotateCredential(credentialId, options);
    }
  }
  
  /**
   * Perform batch rotation of multiple credentials
   */
  public async rotateBatch(
    credentialIds: string[],
    options: {
      policyId?: string;
      priority?: 'low' | 'normal' | 'high' | 'critical' | 'emergency';
      concurrency?: number;
      userId?: string;
    } = {}
  ): Promise<{
    batchId: string;
    successful: string[];
    failed: Array<{ credentialId: string; error: string }>;
  }> {
    if (!this.batchRotationEnabled || !this.concurrentRotationAgent) {
      throw new ConfigurationError('Concurrent rotation not enabled');
    }
    
    const policyId = options.policyId || 'api_key_enhanced';
    const policy = this.enhancedRotationPolicies.get(policyId);
    
    if (!policy) {
      throw new Error(`Rotation policy not found: ${policyId}`);
    }
    
    const requests: CredentialRotationRequest[] = credentialIds.map(credentialId => ({
      credentialId,
      policyId,
      priority: options.priority || 'normal',
      gracePeriod: policy.gracePeriod,
      userId: options.userId
    }));
    
    const batchId = `batch_${Date.now()}_${crypto.randomUUID().slice(0, 8)}`;
    
    const batch: RotationBatch = {
      batchId,
      createdAt: new Date(),
      status: 'pending',
      requests,
      concurrency: Math.min(options.concurrency || 2, requests.length),
      priority: options.priority || 'normal',
      processedCount: 0,
      successCount: 0,
      failedCount: 0
    };
    
    return new Promise((resolve, reject) => {
      const successful: string[] = [];
      const failed: Array<{ credentialId: string; error: string }> = [];
      let completedCount = 0;
      
      const checkCompletion = (): void => {
        if (completedCount === requests.length) {
          this.concurrentRotationAgent.off('rotation_completed', onCompleted);
          this.concurrentRotationAgent.off('rotation_failed', onFailed);
          resolve({ batchId, successful, failed });
        }
      };
      
      const onCompleted = (result: RotationResult): void => {
        if (credentialIds.includes(result.oldCredentialId)) {
          successful.push(result.newCredentialId);
          completedCount++;
          checkCompletion();
        }
      };
      
      const onFailed = (error: RotationError): void => {
        if (credentialIds.includes(error.credentialId)) {
          failed.push({
            credentialId: error.credentialId,
            error: error.errorMessage
          });
          completedCount++;
          checkCompletion();
        }
      };
      
      this.concurrentRotationAgent.on('rotation_completed', onCompleted);
      this.concurrentRotationAgent.on('rotation_failed', onFailed);
      
      // Enqueue the batch
      this.concurrentRotationAgent.enqueueBatch(batch);
      
      // Set timeout
      setTimeout(() => {
        this.concurrentRotationAgent.off('rotation_completed', onCompleted);
        this.concurrentRotationAgent.off('rotation_failed', onFailed);
        reject(new Error('Batch rotation timeout'));
      }, 300000); // 5 minutes timeout
    });
  }
  
  /**
   * Get concurrent rotation agent status
   */
  public getConcurrentRotationStatus(): { enabled: boolean; [key: string]: unknown } {
    if (!this.batchRotationEnabled || !this.concurrentRotationAgent) {
      return { enabled: false };
    }
    
    return {
      enabled: true,
      status: this.concurrentRotationAgent.getStatus(),
      queueStatus: this.concurrentRotationAgent.getQueueStatus(),
      performanceMetrics: this.concurrentRotationAgent.getPerformanceMetrics()
    };
  }
  
  /**
   * Get enhanced rotation policies
   */
  public getEnhancedRotationPolicies(): Map<string, RotationPolicy> {
    return new Map(this.enhancedRotationPolicies);
  }
  
  /**
   * Add or update enhanced rotation policy
   */
  public setEnhancedRotationPolicy(policy: RotationPolicy): void {
    this.enhancedRotationPolicies.set(policy.id, policy);
    this.componentLogger.info('Enhanced rotation policy updated', { policyId: policy.id });
  }
  
  /**
   * Shutdown - clear all timers and concurrent rotation agent
   */
  public async shutdown(): Promise<void> {
    // Stop concurrent rotation agent if running
    if (this.batchRotationEnabled && this.concurrentRotationAgent) {
      await this.disableConcurrentRotation();
    }
    
    // Clear existing timers
    for (const timer of this.rotationTimers.values()) {
      clearTimeout(timer);
    }
    this.rotationTimers.clear();
    
    this.componentLogger.info('SecureConfigManager shutdown completed');
  }
}

// Create singleton instance
let _instance: SecureConfigManager | undefined;

// Export singleton instance getter
export const secureConfigManager = {
  getInstance(): SecureConfigManager {
    if (!_instance) {
      _instance = SecureConfigManager.getInstance();
    }
    return _instance;
  },
  
  // Delegate methods
  async storeCredential(
    type: CredentialMetadata['type'], 
    service: string, 
    value: string, 
    options: { autoRotate?: boolean; rotationInterval?: number; userId?: string } = {}
  ): Promise<string> {
    return this.getInstance().storeCredential(type, service, value, options);
  },
  
  async getCredential(credentialId: string, userId?: string): Promise<string> {
    return this.getInstance().getCredential(credentialId, userId);
  },
  
  async getSecureMakeConfig(userId?: string): Promise<MakeApiConfig> {
    return this.getInstance().getSecureMakeConfig(userId);
  },
  
  async migrateToSecureStorage(userId?: string): Promise<{
    migrated: string[];
    errors: Array<{ credential: string; error: string }>;
  }> {
    return this.getInstance().migrateToSecureStorage(userId);
  },
  
  async rotateCredential(
    credentialId: string, 
    options: { newValue?: string; gracePeriod?: number; userId?: string } = {}
  ): Promise<string> {
    return this.getInstance().rotateCredential(credentialId, options);
  },
  
  getCredentialStatus(credentialId: string): {
    metadata: CredentialMetadata | undefined;
    rotationPolicy: CredentialRotationPolicy | undefined;
    status: 'healthy' | 'rotation_due' | 'expired' | 'not_found';
    nextRotation?: Date;
    daysUntilRotation?: number;
  } {
    return this.getInstance().getCredentialStatus(credentialId);
  },
  
  getSecurityEvents(filter?: {
    credentialId?: string;
    userId?: string;
    event?: SecurityAuditEvent['event'];
    startDate?: Date;
    endDate?: Date;
    limit?: number;
  }): SecurityAuditEvent[] {
    return this.getInstance().getSecurityEvents(filter);
  },
  
  cleanup(): Promise<{
    expiredCredentials: number;
    oldEvents: number;
  }> {
    return this.getInstance().cleanup();
  },
  
  // Concurrent rotation methods
  enableConcurrentRotation(config?: RotationManagerConfig): Promise<void> {
    return this.getInstance().enableConcurrentRotation(config);
  },
  
  disableConcurrentRotation(): Promise<void> {
    return this.getInstance().disableConcurrentRotation();
  },
  
  rotateCredentialConcurrent(
    credentialId: string,
    options: {
      newValue?: string;
      gracePeriod?: number;
      userId?: string;
      policyId?: string;
      priority?: 'low' | 'normal' | 'high' | 'critical' | 'emergency';
      externalServices?: Array<{
        serviceId: string;
        serviceName: string;
        type: string;
        updateMethod: string;
        endpoint?: string;
        authMethod: string;
        validationTimeout: number;
        rollbackSupported: boolean;
      }>;
    }
  ): Promise<string> {
    return this.getInstance().rotateCredentialConcurrent(credentialId, options);
  },
  
  rotateBatch(
    credentialIds: string[],
    options: {
      policyId?: string;
      priority?: 'low' | 'normal' | 'high' | 'critical' | 'emergency';
      concurrency?: number;
      userId?: string;
    }
  ): Promise<{
    batchId: string;
    successful: string[];
    failed: Array<{ credentialId: string; error: string }>;
  }> {
    return this.getInstance().rotateBatch(credentialIds, options);
  },
  
  getConcurrentRotationStatus(): { enabled: boolean; [key: string]: unknown } {
    return this.getInstance().getConcurrentRotationStatus();
  },
  
  getEnhancedRotationPolicies(): Map<string, RotationPolicy> {
    return this.getInstance().getEnhancedRotationPolicies();
  },
  
  setEnhancedRotationPolicy(policy: RotationPolicy): void {
    return this.getInstance().setEnhancedRotationPolicy(policy);
  },
  
  shutdown(): Promise<void> {
    return this.getInstance().shutdown();
  }
};

// Default export
export default secureConfigManager;