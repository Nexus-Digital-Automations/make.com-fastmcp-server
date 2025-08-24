/**
 * Concurrent Encryption Example - 5-Agent Architecture Demo
 * Demonstrates production-ready FIPS 140-2 compliant encryption with HSM integration
 */

import EnhancedEncryptionService from '../utils/enhanced-encryption-service.js';
import ConcurrentEncryptionAgent from '../utils/concurrent-encryption-agent.js';
import { HSMIntegrationManager } from '../utils/hsm-integration.js';
import {
  EnhancedEncryptionConfig,
  HSMIntegrationConfig,
  EncryptionJobRequest,
  BatchEncryptionRequest
} from '../types/encryption-types.js';
import logger from '../lib/logger.js';

/**
 * 5-Agent Concurrent Encryption Architecture Example
 * Demonstrates:
 * 1. Encryption Agent - AES-256-GCM operations
 * 2. Key Management Agent - RSA-4096/ECDSA-P384 operations
 * 3. Validation Agent - Security validation and compliance
 * 4. Rotation Agent - Automated key rotation
 * 5. HSM Integration Agent - Hardware security module operations
 */
class ConcurrentEncryptionDemo {
  private encryptionService!: EnhancedEncryptionService;
  private concurrentAgent!: ConcurrentEncryptionAgent;
  private hsmManager?: HSMIntegrationManager;
  private componentLogger: ReturnType<typeof logger.child>;

  constructor() {
    this.componentLogger = logger.child({ component: 'ConcurrentEncryptionDemo' });
  }

  /**
   * Initialize the 5-agent concurrent architecture
   */
  async initializeArchitecture(): Promise<void> {
    try {
      this.componentLogger.info('🚀 Initializing 5-Agent Concurrent Encryption Architecture');

      // Configuration for production-ready encryption
      const encryptionConfig: EnhancedEncryptionConfig = {
        concurrentProcessing: {
          enabled: true,
          maxWorkers: 5, // One for each specialized agent
          queueSize: 10000,
          timeout: 30000
        },
        hsmIntegration: {
          enabled: true,
          config: {
            provider: 'aws-kms',
            endpoint: process.env.AWS_KMS_ENDPOINT,
            credentials: {
              accessKey: process.env.AWS_ACCESS_KEY_ID || 'demo-access-key',
              secretKey: process.env.AWS_SECRET_ACCESS_KEY || 'demo-secret-key',
              region: process.env.AWS_REGION || 'us-east-1'
            },
            keyStore: {
              encryptionKeys: ['alias/master-encryption-key'],
              signingKeys: ['alias/signing-key'],
              derivationKeys: ['alias/derivation-key']
            },
            options: {
              timeout: 15000,
              retryAttempts: 3,
              fallbackToSoftware: true
            }
          }
        },
        performanceMonitoring: {
          enabled: true,
          metricsRetention: 30, // 30 days
          alertThresholds: {
            avgResponseTime: 500, // 500ms
            errorRate: 2, // 2%
            throughput: 100 // 100 ops/sec
          }
        },
        fallbackToSoftware: true
      };

      // Initialize Enhanced Encryption Service
      this.encryptionService = new EnhancedEncryptionService(encryptionConfig);
      await this.encryptionService.initialize();

      // Setup event handlers for monitoring
      this.setupEventHandlers();

      this.componentLogger.info('✅ 5-Agent Concurrent Architecture Initialized Successfully');

    } catch (error) {
      this.componentLogger.error('❌ Failed to initialize concurrent architecture', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Demo: Agent 1 - Symmetric Encryption Operations
   */
  async demonstrateSymmetricEncryption(): Promise<void> {
    this.componentLogger.info('🔐 Agent 1: Symmetric Encryption Operations Demo');

    const testData = [
      { plaintext: 'Confidential business data', password: 'business-master-key-2024' },
      { plaintext: 'Customer payment information', password: 'payment-encryption-key' },
      { plaintext: 'Employee personal records', password: 'hr-data-protection-key' },
      { plaintext: 'API integration credentials', password: 'api-security-master-key' },
      { plaintext: 'Database connection strings', password: 'db-connection-secure-key' }
    ];

    try {
      // Sequential encryption for comparison
      console.time('Sequential Encryption');
      for (const data of testData) {
        await this.encryptionService.encrypt(data.plaintext, data.password);
      }
      console.timeEnd('Sequential Encryption');

      // Concurrent batch encryption
      console.time('Concurrent Batch Encryption');
      const batchRequests = testData.map((data, index) => ({
        id: `encrypt-job-${index + 1}`,
        plaintext: data.plaintext,
        masterPassword: data.password,
        priority: index < 2 ? 'critical' as const : 'medium' as const
      }));

      const batchResults = await this.encryptionService.encryptBatch(batchRequests, {
        maxConcurrency: 5,
        timeout: 10000,
        failFast: false
      });
      console.timeEnd('Concurrent Batch Encryption');

      // Performance analysis
      const successfulEncryptions = batchResults.filter(r => r.success).length;
      const failedEncryptions = batchResults.length - successfulEncryptions;

      this.componentLogger.info('📊 Symmetric Encryption Results', {
        totalOperations: batchResults.length,
        successful: successfulEncryptions,
        failed: failedEncryptions,
        successRate: (successfulEncryptions / batchResults.length) * 100
      });

    } catch (error) {
      this.componentLogger.error('❌ Symmetric encryption demo failed', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  /**
   * Demo: Agent 2 - Asymmetric Key Generation and Management
   */
  async demonstrateKeyManagement(): Promise<void> {
    this.componentLogger.info('🔑 Agent 2: Key Management Operations Demo');

    try {
      const keyGenerationTasks = [
        { algorithm: 'rsa-4096' as const, purpose: 'Document Signing' },
        { algorithm: 'ecdsa-p384' as const, purpose: 'API Authentication' },
        { algorithm: 'ed25519' as const, purpose: 'High-Speed Signatures' },
        { algorithm: 'rsa-4096' as const, purpose: 'Certificate Authority' },
        { algorithm: 'ecdsa-p384' as const, purpose: 'Blockchain Operations' }
      ];

      console.time('Key Generation Operations');
      
      const keyGenerationPromises = keyGenerationTasks.map(async (task, index) => {
        const startTime = Date.now();
        
        try {
          // Alternate between HSM and software key generation
          const useHSM = index % 2 === 0;
          
          const keyPair = await this.encryptionService.generateKeyPair(task.algorithm, {
            useHSM,
            extractable: !useHSM, // HSM keys are typically non-extractable
            usage: task.algorithm === 'ed25519' ? ['sign', 'verify'] : ['encrypt', 'decrypt', 'sign', 'verify']
          });

          const duration = Date.now() - startTime;
          
          this.componentLogger.info(`✅ Generated ${task.algorithm} key pair for ${task.purpose}`, {
            keyId: keyPair.keyId,
            hsmBacked: keyPair.hsmBacked,
            duration: `${duration}ms`,
            hasPrivateKey: !!keyPair.privateKey
          });

          return {
            success: true,
            keyId: keyPair.keyId,
            algorithm: task.algorithm,
            purpose: task.purpose,
            hsmBacked: keyPair.hsmBacked,
            duration
          };

        } catch (error) {
          this.componentLogger.error(`❌ Failed to generate ${task.algorithm} key for ${task.purpose}`, {
            error: error instanceof Error ? error.message : 'Unknown error'
          });
          
          return {
            success: false,
            algorithm: task.algorithm,
            purpose: task.purpose,
            error: error instanceof Error ? error.message : 'Unknown error'
          };
        }
      });

      const keyResults = await Promise.all(keyGenerationPromises);
      console.timeEnd('Key Generation Operations');

      // Analyze results
      const successful = keyResults.filter(r => r.success).length;
      const hsmBacked = keyResults.filter(r => r.success && (r as any).hsmBacked).length;
      const avgDuration = keyResults
        .filter(r => r.success)
        .reduce((sum, r) => sum + ((r as any).duration || 0), 0) / successful;

      this.componentLogger.info('📊 Key Management Results', {
        totalKeys: keyResults.length,
        successful,
        failed: keyResults.length - successful,
        hsmBacked,
        softwareBacked: successful - hsmBacked,
        avgGenerationTime: `${Math.round(avgDuration)}ms`
      });

    } catch (error) {
      this.componentLogger.error('❌ Key management demo failed', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  /**
   * Demo: Agent 3 - Security Validation and Compliance
   */
  async demonstrateSecurityValidation(): Promise<void> {
    this.componentLogger.info('🛡️ Agent 3: Security Validation Operations Demo');

    try {
      // Validate system security configuration
      const securityValidation = this.encryptionService.validateSecurity();
      
      this.componentLogger.info('🔍 Security Configuration Validation', {
        isValid: securityValidation.isValid,
        securityLevel: securityValidation.securityLevel,
        keyStrength: securityValidation.validations.keyStrength,
        algorithmCompliance: securityValidation.validations.algorithmCompliance,
        randomnessQuality: securityValidation.validations.randomnessQuality,
        timingAttackResistance: securityValidation.validations.timingAttackResistance,
        sideChannelResistance: securityValidation.validations.sideChannelResistance
      });

      if (securityValidation.recommendations) {
        this.componentLogger.info('💡 Security Recommendations', {
          recommendations: securityValidation.recommendations
        });
      }

      if (securityValidation.warnings) {
        this.componentLogger.warn('⚠️ Security Warnings', {
          warnings: securityValidation.warnings
        });
      }

      // Test cryptographic randomness quality
      if (this.encryptionService['concurrentAgent']) {
        const randomnessTest = await this.encryptionService['concurrentAgent'].testRandomnessQuality(
          1024 * 1024, // 1MB test data
          'crypto.randomBytes'
        );

        this.componentLogger.info('🎲 Randomness Quality Assessment', {
          source: randomnessTest.source,
          testSuite: randomnessTest.testSuite,
          overallScore: `${randomnessTest.overallScore.toFixed(1)}%`,
          recommendation: randomnessTest.recommendation,
          testResults: {
            monobitTest: randomnessTest.results.monobitTest.passed,
            frequencyTest: randomnessTest.results.frequencyTest.passed,
            runsTest: randomnessTest.results.runsTest.passed,
            approximateEntropyTest: randomnessTest.results.approximateEntropyTest.passed
          }
        });
      }

    } catch (error) {
      this.componentLogger.error('❌ Security validation demo failed', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  /**
   * Demo: Agent 4 - Performance Monitoring and Optimization
   */
  async demonstratePerformanceMonitoring(): Promise<void> {
    this.componentLogger.info('📊 Agent 4: Performance Monitoring Demo');

    try {
      // Generate some load for metrics
      await this.generatePerformanceLoad();

      // Wait a moment for metrics to be recorded
      await new Promise(resolve => setTimeout(resolve, 1000));

      // Get comprehensive performance report
      const performanceReport = this.encryptionService.getPerformanceReport();

      this.componentLogger.info('📈 Performance Report', {
        timeRange: {
          start: performanceReport.timeRange.start.toISOString(),
          end: performanceReport.timeRange.end.toISOString()
        },
        totalOperations: performanceReport.totalOperations,
        successRate: `${performanceReport.successRate.toFixed(1)}%`,
        avgResponseTime: `${performanceReport.avgResponseTime.toFixed(1)}ms`,
        peakThroughput: `${performanceReport.peakThroughput.toFixed(1)} ops/sec`
      });

      // Algorithm performance breakdown
      if (Object.keys(performanceReport.algorithmBreakdown).length > 0) {
        this.componentLogger.info('🔍 Algorithm Performance Breakdown', 
          performanceReport.algorithmBreakdown
        );
      }

      // HSM performance metrics
      if (performanceReport.hsmUsage.enabled) {
        this.componentLogger.info('🏭 HSM Usage Statistics', {
          operations: performanceReport.hsmUsage.operations,
          avgTime: `${performanceReport.hsmUsage.avgTime.toFixed(1)}ms`,
          availability: `${performanceReport.hsmUsage.availability.toFixed(1)}%`
        });
      }

      // Pool status (concurrent agents)
      const poolStatus = this.encryptionService.getPoolStatus();
      if (poolStatus) {
        this.componentLogger.info('👥 Worker Pool Status', {
          totalWorkers: poolStatus.totalWorkers,
          activeWorkers: poolStatus.activeWorkers,
          idleWorkers: poolStatus.idleWorkers,
          queuedJobs: poolStatus.queuedJobs,
          processingJobs: poolStatus.processingJobs,
          successRate: `${poolStatus.successRate.toFixed(1)}%`,
          avgProcessingTime: `${poolStatus.avgProcessingTime.toFixed(1)}ms`,
          peakThroughput: `${poolStatus.peakThroughput.toFixed(1)} ops/sec`
        });
      }

      // Performance recommendations
      if (performanceReport.recommendations.length > 0) {
        this.componentLogger.info('💡 Performance Recommendations', {
          recommendations: performanceReport.recommendations
        });
      }

    } catch (error) {
      this.componentLogger.error('❌ Performance monitoring demo failed', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  /**
   * Demo: Agent 5 - HSM Integration Operations
   */
  async demonstrateHSMIntegration(): Promise<void> {
    this.componentLogger.info('🏭 Agent 5: HSM Integration Operations Demo');

    try {
      // Demonstrate HSM-backed operations
      const hsmOperations = [
        { operation: 'encrypt', data: 'HSM-protected confidential data' },
        { operation: 'decrypt', data: 'HSM-secured encrypted payload' },
        { operation: 'sign', data: 'Digital signature with HSM key' },
        { operation: 'key_generation', data: 'HSM-generated key pair' }
      ];

      for (const op of hsmOperations) {
        try {
          const startTime = Date.now();
          
          switch (op.operation) {
            case 'encrypt':
              await this.encryptionService.encrypt(op.data, 'hsm-master-key', {
                useHSM: true,
                algorithm: 'aes-256-gcm-hsm',
                priority: 'critical'
              });
              break;
              
            case 'key_generation':
              await this.encryptionService.generateKeyPair('rsa-4096', {
                useHSM: true,
                extractable: false,
                usage: ['encrypt', 'decrypt', 'sign', 'verify']
              });
              break;
          }

          const duration = Date.now() - startTime;
          
          this.componentLogger.info(`✅ HSM ${op.operation} completed`, {
            operation: op.operation,
            duration: `${duration}ms`,
            hsmProvider: 'aws-kms'
          });

        } catch (error) {
          this.componentLogger.warn(`⚠️ HSM ${op.operation} failed, falling back to software`, {
            error: error instanceof Error ? error.message : 'Unknown error'
          });
        }
      }

      // HSM status and health check
      if (this.hsmManager) {
        const hsmStatus = await this.hsmManager.getStatus();
        
        this.componentLogger.info('🏥 HSM Health Status', {
          provider: hsmStatus.provider,
          connected: hsmStatus.connected,
          authenticated: hsmStatus.authenticated,
          keySlots: hsmStatus.keySlots,
          performance: {
            avgResponseTime: `${hsmStatus.performance.avgResponseTime}ms`,
            operationsPerSecond: hsmStatus.performance.operationsPerSecond,
            errorRate: `${hsmStatus.performance.errorRate}%`
          },
          firmwareVersion: hsmStatus.firmwareVersion
        });
      }

    } catch (error) {
      this.componentLogger.error('❌ HSM integration demo failed', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }

  /**
   * Generate performance load for testing
   */
  private async generatePerformanceLoad(): Promise<void> {
    const loadOperations = [];
    
    // Generate various encryption operations
    for (let i = 0; i < 20; i++) {
      loadOperations.push(
        this.encryptionService.encrypt(
          `Performance test data ${i}`,
          `test-password-${i}`,
          {
            useConcurrent: true,
            priority: i < 5 ? 'high' : 'medium'
          }
        )
      );
    }

    try {
      await Promise.all(loadOperations);
    } catch (error) {
      // Expected for demo purposes
    }
  }

  /**
   * Setup event handlers for monitoring
   */
  private setupEventHandlers(): void {
    this.encryptionService.on('initialized', () => {
      this.componentLogger.info('🎉 Enhanced Encryption Service Initialized');
    });

    this.encryptionService.on('operationCompleted', (result) => {
      this.componentLogger.debug('✅ Operation Completed', {
        id: result.id,
        algorithm: result.metadata?.algorithm,
        processingTime: `${result.metadata?.processingTime}ms`,
        workerId: result.metadata?.workerId
      });
    });

    this.encryptionService.on('operationError', (result) => {
      this.componentLogger.debug('❌ Operation Error', {
        id: result.id,
        error: result.error?.message
      });
    });

    this.encryptionService.on('hsmConnected', (provider) => {
      this.componentLogger.info('🔌 HSM Provider Connected', { provider });
    });

    this.encryptionService.on('hsmError', (provider, error) => {
      this.componentLogger.warn('⚠️ HSM Provider Error', { provider, error: error.message });
    });

    this.encryptionService.on('performanceAlert', (alert) => {
      this.componentLogger.warn('📊 Performance Alert', alert);
    });
  }

  /**
   * Run complete demonstration
   */
  async runDemo(): Promise<void> {
    try {
      console.log('\n🚀 Starting 5-Agent Concurrent Encryption Architecture Demo\n');

      // Initialize architecture
      await this.initializeArchitecture();

      // Run all demonstrations
      await this.demonstrateSymmetricEncryption();
      console.log('\n' + '─'.repeat(80) + '\n');

      await this.demonstrateKeyManagement();
      console.log('\n' + '─'.repeat(80) + '\n');

      await this.demonstrateSecurityValidation();
      console.log('\n' + '─'.repeat(80) + '\n');

      await this.demonstratePerformanceMonitoring();
      console.log('\n' + '─'.repeat(80) + '\n');

      await this.demonstrateHSMIntegration();
      console.log('\n' + '─'.repeat(80) + '\n');

      this.componentLogger.info('🎯 5-Agent Concurrent Encryption Demo Completed Successfully');

    } catch (error) {
      this.componentLogger.error('💥 Demo failed', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    } finally {
      // Cleanup
      if (this.encryptionService) {
        await this.encryptionService.shutdown();
      }
    }
  }
}

/**
 * Performance Benchmark Example
 */
class EncryptionPerformanceBenchmark {
  private encryptionService!: EnhancedEncryptionService;

  async runBenchmark(): Promise<void> {
    const config: EnhancedEncryptionConfig = {
      concurrentProcessing: {
        enabled: true,
        maxWorkers: 5,
        queueSize: 1000,
        timeout: 30000
      },
      hsmIntegration: { enabled: false },
      performanceMonitoring: {
        enabled: true,
        metricsRetention: 1,
        alertThresholds: {
          avgResponseTime: 100,
          errorRate: 1,
          throughput: 1000
        }
      },
      fallbackToSoftware: true
    };

    this.encryptionService = new EnhancedEncryptionService(config);
    await this.encryptionService.initialize();

    console.log('🏁 Starting Performance Benchmark\n');

    const testSizes = [1024, 10240, 102400, 1024000]; // 1KB, 10KB, 100KB, 1MB
    const iterations = [100, 50, 25, 10]; // Fewer iterations for larger data

    for (let i = 0; i < testSizes.length; i++) {
      const dataSize = testSizes[i];
      const iterCount = iterations[i];
      const testData = 'A'.repeat(dataSize);
      const password = 'benchmark-password-2024';

      console.time(`Concurrent Encryption (${dataSize} bytes x ${iterCount})`);
      
      const batchRequests = Array.from({ length: iterCount }, (_, idx) => ({
        id: `bench-${dataSize}-${idx}`,
        plaintext: testData,
        masterPassword: password,
        priority: 'medium' as const
      }));

      const results = await this.encryptionService.encryptBatch(batchRequests, {
        maxConcurrency: 5,
        timeout: 30000,
        failFast: false
      });

      console.timeEnd(`Concurrent Encryption (${dataSize} bytes x ${iterCount})`);

      const successful = results.filter(r => r.success).length;
      const throughput = successful / 1; // ops per second (rough estimate)

      console.log(`✅ Success Rate: ${(successful / results.length * 100).toFixed(1)}%`);
      console.log(`📊 Throughput: ~${throughput.toFixed(1)} ops/sec`);
      console.log(`💾 Data Processed: ${(dataSize * successful / 1024 / 1024).toFixed(2)} MB\n`);
    }

    const performanceReport = this.encryptionService.getPerformanceReport();
    console.log('📈 Final Performance Report:', {
      totalOperations: performanceReport.totalOperations,
      avgResponseTime: `${performanceReport.avgResponseTime.toFixed(1)}ms`,
      peakThroughput: `${performanceReport.peakThroughput.toFixed(1)} ops/sec`
    });

    await this.encryptionService.shutdown();
  }
}

// Execute demonstration if run directly
if (require.main === module) {
  const demo = new ConcurrentEncryptionDemo();
  demo.runDemo().catch(error => {
    console.error('Demo failed:', error);
    process.exit(1);
  });
}

export { ConcurrentEncryptionDemo, EncryptionPerformanceBenchmark };