/**
 * Enhanced Encryption Service Test Suite
 * Comprehensive testing for concurrent encryption agent and HSM integration
 */

import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals';
import EnhancedEncryptionService from '../enhanced-encryption-service.js';
import ConcurrentEncryptionAgent from '../concurrent-encryption-agent.js';
import { HSMIntegrationManager } from '../hsm-integration.js';
import { EncryptionService, CredentialManager } from '../encryption.js';
import {
  EnhancedEncryptionConfig,
  HSMIntegrationConfig,
  ConcurrentWorkerConfig
} from '../../types/encryption-types.js';

// Mock dependencies
jest.mock('../concurrent-encryption-agent.js');
jest.mock('../hsm-integration.js');
jest.mock('../encryption.js');

const MockConcurrentEncryptionAgent = ConcurrentEncryptionAgent as jest.MockedClass<typeof ConcurrentEncryptionAgent>;
const MockHSMIntegrationManager = HSMIntegrationManager as jest.MockedClass<typeof HSMIntegrationManager>;
const MockEncryptionService = EncryptionService as jest.MockedClass<typeof EncryptionService>;
const MockCredentialManager = CredentialManager as jest.MockedClass<typeof CredentialManager>;

describe('EnhancedEncryptionService', () => {
  let enhancedService: EnhancedEncryptionService;
  let mockBaseService: jest.Mocked<EncryptionService>;
  let mockCredentialManager: jest.Mocked<CredentialManager>;
  let mockConcurrentAgent: jest.Mocked<ConcurrentEncryptionAgent>;
  let mockHSMManager: jest.Mocked<HSMIntegrationManager>;

  const testConfig: EnhancedEncryptionConfig = {
    concurrentProcessing: {
      enabled: true,
      maxWorkers: 2,
      queueSize: 100,
      timeout: 5000
    },
    hsmIntegration: {
      enabled: true,
      config: {
        provider: 'aws-kms',
        credentials: {
          accessKey: 'test-key',
          secretKey: 'test-secret',
          region: 'us-east-1'
        }
      }
    },
    performanceMonitoring: {
      enabled: true,
      metricsRetention: 7,
      alertThresholds: {
        avgResponseTime: 1000,
        errorRate: 5,
        throughput: 10
      }
    },
    fallbackToSoftware: true
  };

  beforeEach(() => {
    // Clear all mocks
    jest.clearAllMocks();

    // Setup mock implementations
    mockBaseService = new MockEncryptionService() as jest.Mocked<EncryptionService>;
    mockCredentialManager = new MockCredentialManager() as jest.Mocked<CredentialManager>;
    
    mockBaseService.encrypt = jest.fn().mockResolvedValue({
      data: 'encrypted-data',
      iv: 'test-iv',
      salt: 'test-salt',
      algorithm: 'aes-256-gcm',
      keyLength: 256
    });

    mockBaseService.decrypt = jest.fn().mockResolvedValue('decrypted-plaintext');

    mockConcurrentAgent = new MockConcurrentEncryptionAgent({} as ConcurrentWorkerConfig) as jest.Mocked<ConcurrentEncryptionAgent>;
    mockConcurrentAgent.initialize = jest.fn().mockResolvedValue(undefined);
    mockConcurrentAgent.processJob = jest.fn().mockResolvedValue({
      id: 'job-1',
      success: true,
      result: {
        data: 'concurrent-encrypted',
        iv: 'concurrent-iv',
        salt: 'concurrent-salt',
        algorithm: 'aes-256-gcm',
        keyLength: 256
      },
      metadata: {
        algorithm: 'aes-256-gcm',
        processingTime: 100,
        workerId: 'worker-1',
        hsm: false
      }
    });

    mockConcurrentAgent.processBatch = jest.fn().mockResolvedValue({
      batchId: 'batch-1',
      totalJobs: 2,
      completedJobs: 2,
      failedJobs: 0,
      processingTime: 200,
      results: [
        {
          id: 'job-1',
          success: true,
          result: { data: 'result1', iv: 'iv1', salt: 'salt1', algorithm: 'aes-256-gcm', keyLength: 256 }
        },
        {
          id: 'job-2',
          success: true,
          result: { data: 'result2', iv: 'iv2', salt: 'salt2', algorithm: 'aes-256-gcm', keyLength: 256 }
        }
      ]
    });

    mockConcurrentAgent.generateKeyPair = jest.fn().mockResolvedValue({
      publicKey: 'public-key-pem',
      privateKey: 'private-key-pem',
      keyId: 'key-123',
      metadata: {
        keyId: 'key-123',
        keyType: 'asymmetric',
        algorithm: 'rsa-4096',
        keyLength: 4096,
        status: 'active',
        createdAt: new Date(),
        securityContext: {
          origin: 'software',
          extractable: true,
          usage: ['encrypt', 'decrypt'],
          clientPermissions: ['read', 'use']
        },
        auditTrail: []
      }
    });

    mockConcurrentAgent.getPoolStatus = jest.fn().mockReturnValue({
      totalWorkers: 2,
      activeWorkers: 2,
      idleWorkers: 2,
      queuedJobs: 0,
      processingJobs: 0,
      totalJobsProcessed: 10,
      successRate: 95,
      avgProcessingTime: 150,
      peakThroughput: 50,
      workerHealthStatus: [
        {
          workerId: 'worker-1',
          status: 'idle',
          activeJobs: 0,
          totalJobsProcessed: 5,
          errorCount: 0,
          uptime: 60000,
          performance: {
            avgProcessingTime: 140,
            throughput: 7.14,
            cpuUsage: 10,
            memoryUsage: 50
          },
          lastHeartbeat: new Date()
        }
      ]
    });

    mockConcurrentAgent.shutdown = jest.fn().mockResolvedValue(undefined);

    mockHSMManager = new MockHSMIntegrationManager({} as HSMIntegrationConfig) as jest.Mocked<HSMIntegrationManager>;
    mockHSMManager.initialize = jest.fn().mockResolvedValue(undefined);
    mockHSMManager.generateKey = jest.fn().mockResolvedValue({
      success: true,
      keyId: 'hsm-key-456',
      result: 'hsm-public-key-pem',
      metadata: {
        operationType: 'generate_key',
        timestamp: new Date(),
        provider: 'aws-kms',
        performance: { duration: 250 }
      }
    });

    mockHSMManager.encrypt = jest.fn().mockResolvedValue({
      success: true,
      result: Buffer.from('hsm-encrypted-data'),
      keyId: 'hsm-key-456',
      metadata: {
        operationType: 'encrypt',
        timestamp: new Date(),
        provider: 'aws-kms',
        performance: { duration: 120, throughput: 1000 }
      }
    });

    mockHSMManager.decrypt = jest.fn().mockResolvedValue({
      success: true,
      result: Buffer.from('hsm-decrypted-plaintext'),
      keyId: 'hsm-key-456',
      metadata: {
        operationType: 'decrypt',
        timestamp: new Date(),
        provider: 'aws-kms',
        performance: { duration: 110, throughput: 1200 }
      }
    });

    mockHSMManager.getStatus = jest.fn().mockResolvedValue({
      provider: 'aws-kms',
      connected: true,
      authenticated: true,
      keySlots: { total: 1000, used: 5, available: 995 },
      performance: { avgResponseTime: 150, operationsPerSecond: 25, errorRate: 1 },
      lastHealthCheck: new Date(),
      firmwareVersion: 'AWS KMS Service',
      serialNumber: 'us-east-1'
    });

    mockHSMManager.shutdown = jest.fn().mockResolvedValue(undefined);

    // Override constructor mocks to return our mock instances
    MockConcurrentEncryptionAgent.mockImplementation(() => mockConcurrentAgent);
    MockHSMIntegrationManager.mockImplementation(() => mockHSMManager);

    enhancedService = new EnhancedEncryptionService(testConfig, mockBaseService, mockCredentialManager);
  });

  afterEach(async () => {
    if (enhancedService) {
      await enhancedService.shutdown();
    }
  });

  describe('Initialization', () => {
    test('should initialize successfully with all components', async () => {
      await enhancedService.initialize();

      expect(mockConcurrentAgent.initialize).toHaveBeenCalledTimes(1);
      expect(mockHSMManager.initialize).toHaveBeenCalledTimes(1);
    });

    test('should initialize with concurrent processing disabled', async () => {
      const config = { ...testConfig, concurrentProcessing: { ...testConfig.concurrentProcessing, enabled: false } };
      const service = new EnhancedEncryptionService(config, mockBaseService, mockCredentialManager);
      
      await service.initialize();
      
      expect(MockConcurrentEncryptionAgent).not.toHaveBeenCalled();
      await service.shutdown();
    });

    test('should initialize with HSM disabled', async () => {
      const config = { ...testConfig, hsmIntegration: { ...testConfig.hsmIntegration, enabled: false } };
      const service = new EnhancedEncryptionService(config, mockBaseService, mockCredentialManager);
      
      await service.initialize();
      
      expect(MockHSMIntegrationManager).not.toHaveBeenCalled();
      await service.shutdown();
    });

    test('should handle initialization failures gracefully', async () => {
      mockConcurrentAgent.initialize.mockRejectedValue(new Error('Worker initialization failed'));

      await expect(enhancedService.initialize()).rejects.toThrow('Worker initialization failed');
    });
  });

  describe('Encryption Operations', () => {
    beforeEach(async () => {
      await enhancedService.initialize();
    });

    test('should perform software encryption by default', async () => {
      const result = await enhancedService.encrypt('test-plaintext', 'master-password');

      expect(mockBaseService.encrypt).toHaveBeenCalledWith('test-plaintext', 'master-password');
      expect(result).toEqual({
        data: 'encrypted-data',
        iv: 'test-iv',
        salt: 'test-salt',
        algorithm: 'aes-256-gcm',
        keyLength: 256
      });
    });

    test('should perform concurrent encryption when requested', async () => {
      const result = await enhancedService.encrypt('test-plaintext', 'master-password', {
        useConcurrent: true,
        priority: 'high'
      });

      expect(mockConcurrentAgent.processJob).toHaveBeenCalledWith(
        expect.objectContaining({
          operation: 'encrypt',
          data: 'test-plaintext',
          key: 'master-password',
          metadata: expect.objectContaining({
            priority: 'high'
          })
        })
      );
      expect(result.data).toBe('concurrent-encrypted');
    });

    test('should perform HSM encryption when requested', async () => {
      const result = await enhancedService.encrypt('test-plaintext', 'master-password', {
        useHSM: true,
        algorithm: 'aes-256-gcm-hsm'
      });

      expect(mockHSMManager.encrypt).toHaveBeenCalledWith(
        'master-encryption-key',
        expect.any(Buffer),
        'aes-256-gcm-hsm'
      );
      expect(result.algorithm).toBe('aes-256-gcm-hsm');
    });

    test('should fallback to software encryption on concurrent failure', async () => {
      mockConcurrentAgent.processJob.mockRejectedValue(new Error('Concurrent processing failed'));

      const result = await enhancedService.encrypt('test-plaintext', 'master-password', {
        useConcurrent: true
      });

      expect(mockBaseService.encrypt).toHaveBeenCalledWith('test-plaintext', 'master-password');
      expect(result.data).toBe('encrypted-data');
    });

    test('should fallback to software encryption on HSM failure', async () => {
      mockHSMManager.encrypt.mockResolvedValue({
        success: false,
        error: { code: 'HSM_ERROR', message: 'HSM operation failed', recoverable: true }
      });

      const result = await enhancedService.encrypt('test-plaintext', 'master-password', {
        useHSM: true
      });

      expect(mockBaseService.encrypt).toHaveBeenCalledWith('test-plaintext', 'master-password');
      expect(result.data).toBe('encrypted-data');
    });
  });

  describe('Decryption Operations', () => {
    beforeEach(async () => {
      await enhancedService.initialize();
    });

    const testEncryptedData = {
      data: 'encrypted-data',
      iv: 'test-iv',
      salt: 'test-salt',
      algorithm: 'aes-256-gcm',
      keyLength: 256
    };

    test('should perform software decryption by default', async () => {
      const result = await enhancedService.decrypt(testEncryptedData, 'master-password');

      expect(mockBaseService.decrypt).toHaveBeenCalledWith(testEncryptedData, 'master-password');
      expect(result).toBe('decrypted-plaintext');
    });

    test('should perform concurrent decryption when requested', async () => {
      mockConcurrentAgent.processJob.mockResolvedValue({
        id: 'decrypt-job',
        success: true,
        result: 'concurrent-decrypted',
        metadata: {
          algorithm: 'aes-256-gcm',
          processingTime: 90,
          workerId: 'worker-1',
          hsm: false
        }
      });

      const result = await enhancedService.decrypt(testEncryptedData, 'master-password', {
        useConcurrent: true,
        priority: 'critical'
      });

      expect(mockConcurrentAgent.processJob).toHaveBeenCalledWith(
        expect.objectContaining({
          operation: 'decrypt',
          data: testEncryptedData,
          key: 'master-password',
          metadata: expect.objectContaining({
            priority: 'critical'
          })
        })
      );
      expect(result).toBe('concurrent-decrypted');
    });

    test('should perform HSM decryption when requested', async () => {
      const result = await enhancedService.decrypt(testEncryptedData, 'master-password', {
        useHSM: true
      });

      expect(mockHSMManager.decrypt).toHaveBeenCalledWith(
        'master-encryption-key',
        expect.any(Buffer),
        testEncryptedData.algorithm
      );
      expect(result).toBe('hsm-decrypted-plaintext');
    });
  });

  describe('Batch Operations', () => {
    beforeEach(async () => {
      await enhancedService.initialize();
    });

    test('should process batch encryption requests', async () => {
      const requests = [
        { id: 'req-1', plaintext: 'data1', masterPassword: 'pass1', priority: 'high' as const },
        { id: 'req-2', plaintext: 'data2', masterPassword: 'pass2', priority: 'medium' as const }
      ];

      const results = await enhancedService.encryptBatch(requests, {
        maxConcurrency: 2,
        timeout: 10000,
        failFast: false
      });

      expect(mockConcurrentAgent.processBatch).toHaveBeenCalledWith(
        expect.objectContaining({
          jobs: expect.arrayContaining([
            expect.objectContaining({
              id: 'req-1',
              operation: 'encrypt',
              data: 'data1',
              key: 'pass1'
            }),
            expect.objectContaining({
              id: 'req-2',
              operation: 'encrypt',
              data: 'data2',
              key: 'pass2'
            })
          ]),
          options: expect.objectContaining({
            maxConcurrency: 2,
            timeout: 10000,
            failFast: false
          })
        })
      );

      expect(results).toHaveLength(2);
      expect(results[0]).toEqual({
        id: 'job-1',
        success: true,
        result: expect.objectContaining({
          data: 'result1'
        })
      });
    });

    test('should throw error when concurrent processing is disabled for batch operations', async () => {
      const config = { ...testConfig, concurrentProcessing: { ...testConfig.concurrentProcessing, enabled: false } };
      const service = new EnhancedEncryptionService(config, mockBaseService, mockCredentialManager);
      await service.initialize();

      const requests = [
        { id: 'req-1', plaintext: 'data1', masterPassword: 'pass1' }
      ];

      await expect(service.encryptBatch(requests)).rejects.toThrow('Concurrent processing not enabled');
      await service.shutdown();
    });
  });

  describe('Key Generation', () => {
    beforeEach(async () => {
      await enhancedService.initialize();
    });

    test('should generate key pairs using HSM when requested', async () => {
      const result = await enhancedService.generateKeyPair('rsa-4096', {
        useHSM: true,
        extractable: false,
        usage: ['encrypt', 'decrypt']
      });

      expect(mockHSMManager.generateKey).toHaveBeenCalledWith(
        expect.objectContaining({
          keyType: 'asymmetric',
          algorithm: 'rsa-4096',
          keyLength: 4096,
          extractable: false,
          usage: ['encrypt', 'decrypt']
        })
      );

      expect(result).toEqual({
        publicKey: 'hsm-public-key-pem',
        keyId: 'hsm-key-456',
        hsmBacked: true
      });
    });

    test('should generate key pairs using concurrent agent when HSM not requested', async () => {
      const result = await enhancedService.generateKeyPair('ecdsa-p384', {
        extractable: true,
        usage: ['sign', 'verify']
      });

      expect(mockConcurrentAgent.generateKeyPair).toHaveBeenCalledWith('ecdsa-p384', {
        extractable: true,
        usage: ['sign', 'verify']
      });

      expect(result).toEqual({
        publicKey: 'public-key-pem',
        privateKey: 'private-key-pem',
        keyId: 'key-123',
        hsmBacked: false
      });
    });

    test('should handle HSM key generation failures', async () => {
      mockHSMManager.generateKey.mockResolvedValue({
        success: false,
        error: { code: 'HSM_KEY_GEN_ERROR', message: 'Key generation failed', recoverable: false }
      });

      await expect(enhancedService.generateKeyPair('rsa-4096', { useHSM: true }))
        .rejects.toThrow('Key generation failed');
    });
  });

  describe('Performance Monitoring', () => {
    beforeEach(async () => {
      await enhancedService.initialize();
    });

    test('should generate performance reports', async () => {
      // Perform some operations to generate metrics
      await enhancedService.encrypt('test1', 'pass1');
      await enhancedService.encrypt('test2', 'pass2', { useConcurrent: true });

      const report = enhancedService.getPerformanceReport();

      expect(report).toEqual(
        expect.objectContaining({
          totalOperations: expect.any(Number),
          successRate: expect.any(Number),
          avgResponseTime: expect.any(Number),
          peakThroughput: expect.any(Number),
          algorithmBreakdown: expect.any(Object),
          hsmUsage: expect.objectContaining({
            enabled: true,
            operations: expect.any(Number),
            avgTime: expect.any(Number),
            availability: expect.any(Number)
          }),
          recommendations: expect.any(Array)
        })
      );
    });

    test('should provide empty report when no operations performed', async () => {
      const report = enhancedService.getPerformanceReport();

      expect(report.totalOperations).toBe(0);
      expect(report.recommendations).toContain('No operations recorded in the specified time range');
    });

    test('should get pool status from concurrent agent', async () => {
      const status = enhancedService.getPoolStatus();

      expect(status).toEqual(
        expect.objectContaining({
          totalWorkers: 2,
          activeWorkers: 2,
          idleWorkers: 2,
          successRate: 95,
          avgProcessingTime: 150
        })
      );
    });

    test('should return null pool status when concurrent processing disabled', async () => {
      const config = { ...testConfig, concurrentProcessing: { ...testConfig.concurrentProcessing, enabled: false } };
      const service = new EnhancedEncryptionService(config, mockBaseService, mockCredentialManager);
      await service.initialize();

      const status = service.getPoolStatus();
      expect(status).toBeNull();

      await service.shutdown();
    });
  });

  describe('Security Validation', () => {
    beforeEach(async () => {
      await enhancedService.initialize();
    });

    test('should validate security configuration with HSM enabled', async () => {
      const validation = enhancedService.validateSecurity();

      expect(validation).toEqual({
        isValid: true,
        securityLevel: 'fips-140-2',
        validations: {
          keyStrength: true,
          algorithmCompliance: true,
          randomnessQuality: true,
          timingAttackResistance: true,
          sideChannelResistance: true
        }
      });
    });

    test('should validate security configuration without HSM', async () => {
      const config = { ...testConfig, hsmIntegration: { ...testConfig.hsmIntegration, enabled: false } };
      const service = new EnhancedEncryptionService(config, mockBaseService, mockCredentialManager);
      await service.initialize();

      const validation = service.validateSecurity();

      expect(validation.securityLevel).toBe('high');
      expect(validation.validations.sideChannelResistance).toBe(false);
      expect(validation.recommendations).toContain('Enable HSM integration for enhanced security and FIPS 140-2 compliance');

      await service.shutdown();
    });
  });

  describe('Event Handling', () => {
    beforeEach(async () => {
      await enhancedService.initialize();
    });

    test('should emit events from concurrent agent', async () => {
      const operationCompletedSpy = jest.fn();
      const operationErrorSpy = jest.fn();

      enhancedService.on('operationCompleted', operationCompletedSpy);
      enhancedService.on('operationError', operationErrorSpy);

      // Simulate concurrent agent events
      const jobResult = {
        id: 'job-1',
        success: true,
        result: 'encrypted-result',
        metadata: {
          algorithm: 'aes-256-gcm',
          processingTime: 100,
          workerId: 'worker-1',
          hsm: false
        }
      };

      mockConcurrentAgent.emit('jobCompleted', jobResult);

      expect(operationCompletedSpy).toHaveBeenCalledWith(jobResult);
    });

    test('should emit events from HSM manager', async () => {
      const hsmConnectedSpy = jest.fn();
      const hsmErrorSpy = jest.fn();

      enhancedService.on('hsmConnected', hsmConnectedSpy);
      enhancedService.on('hsmError', hsmErrorSpy);

      // Simulate HSM manager events
      mockHSMManager.emit('providerConnected', 'aws-kms');
      mockHSMManager.emit('providerError', 'aws-kms', new Error('Connection lost'));

      expect(hsmConnectedSpy).toHaveBeenCalledWith('aws-kms');
      expect(hsmErrorSpy).toHaveBeenCalledWith('aws-kms', expect.any(Error));
    });
  });

  describe('Error Handling and Fallback', () => {
    beforeEach(async () => {
      await enhancedService.initialize();
    });

    test('should not fallback when fallbackToSoftware is disabled', async () => {
      const config = { ...testConfig, fallbackToSoftware: false };
      const service = new EnhancedEncryptionService(config, mockBaseService, mockCredentialManager);
      await service.initialize();

      mockHSMManager.encrypt.mockResolvedValue({
        success: false,
        error: { code: 'HSM_ERROR', message: 'HSM operation failed', recoverable: false }
      });

      await expect(service.encrypt('test-plaintext', 'master-password', { useHSM: true }))
        .rejects.toThrow();

      expect(mockBaseService.encrypt).not.toHaveBeenCalled();
      await service.shutdown();
    });

    test('should handle operation before initialization', async () => {
      const service = new EnhancedEncryptionService(testConfig);

      await expect(service.encrypt('test', 'pass')).rejects.toThrow('EnhancedEncryptionService not initialized');
      await expect(service.decrypt({ data: 'test', iv: 'iv', salt: 'salt', algorithm: 'aes-256-gcm', keyLength: 256 }, 'pass'))
        .rejects.toThrow('EnhancedEncryptionService not initialized');
    });
  });

  describe('Shutdown', () => {
    test('should shutdown all components gracefully', async () => {
      await enhancedService.initialize();
      await enhancedService.shutdown();

      expect(mockConcurrentAgent.shutdown).toHaveBeenCalledTimes(1);
      expect(mockHSMManager.shutdown).toHaveBeenCalledTimes(1);
    });

    test('should handle shutdown errors gracefully', async () => {
      await enhancedService.initialize();
      
      mockConcurrentAgent.shutdown.mockRejectedValue(new Error('Shutdown failed'));

      await expect(enhancedService.shutdown()).rejects.toThrow('Shutdown failed');
    });
  });
});

describe('Integration Tests', () => {
  test('should handle complete encryption/decryption workflow', async () => {
    const config: EnhancedEncryptionConfig = {
      concurrentProcessing: { enabled: false, maxWorkers: 1, queueSize: 10, timeout: 5000 },
      hsmIntegration: { enabled: false },
      performanceMonitoring: { enabled: false, metricsRetention: 1, alertThresholds: { avgResponseTime: 1000, errorRate: 5, throughput: 10 } },
      fallbackToSoftware: true
    };

    // Use real encryption service for integration test
    const realEncryptionService = new EncryptionService();
    const realCredentialManager = new CredentialManager();
    
    const service = new EnhancedEncryptionService(config, realEncryptionService, realCredentialManager);
    await service.initialize();

    const plaintext = 'This is a test message for integration testing';
    const masterPassword = 'test-master-password-123';

    // Encrypt
    const encrypted = await service.encrypt(plaintext, masterPassword);
    expect(encrypted).toEqual(
      expect.objectContaining({
        data: expect.any(String),
        iv: expect.any(String),
        salt: expect.any(String),
        algorithm: 'aes-256-gcm',
        keyLength: 256
      })
    );

    // Decrypt
    const decrypted = await service.decrypt(encrypted, masterPassword);
    expect(decrypted).toBe(plaintext);

    await service.shutdown();
  });
});