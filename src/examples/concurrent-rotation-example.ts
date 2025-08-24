/**
 * Comprehensive example demonstrating the concurrent credential rotation framework
 * Shows how to use the 5-agent concurrent architecture for credential management
 */

import { secureConfigManager } from "../lib/secure-config.js";
import type {
  RotationPolicy,
  ExternalServiceConfig,
  RotationManagerConfig,
} from "../types/rotation-types.js";
import logger from "../lib/logger.js";

const componentLogger = logger.child({
  component: "ConcurrentRotationExample",
});

/**
 * Example: Basic concurrent rotation setup and usage
 */
export async function basicConcurrentRotationExample(): Promise<void> {
  componentLogger.info("Starting basic concurrent rotation example");

  try {
    // Step 1: Enable concurrent rotation with custom configuration
    const rotationConfig: RotationManagerConfig = {
      maxWorkerThreads: 2,
      workerTimeoutMs: 30000,
      workerHealthCheckIntervalMs: 5000,
      defaultConcurrency: 2,
      maxQueueSize: 100,
      priorityLevels: 5,
      defaultBatchSize: 5,
      maxBatchSize: 20,
      batchTimeoutMs: 120000,
      externalServiceTimeoutMs: 10000,
      maxExternalServiceRetries: 2,
      externalServiceHealthCheckIntervalMs: 15000,
      auditRetentionDays: 30,
      logLevel: "info",
      metricsCollectionIntervalMs: 3000,
      performanceThresholds: {
        maxRotationTimeMs: 15000,
        maxMemoryUsageMB: 256,
        maxCpuUsagePercent: 70,
        maxErrorRate: 0.1,
      },
      encryptionKeyRotationIntervalMs: 3600000, // 1 hour for demo
      auditLogEncryption: true,
      secureMemoryWipe: true,
    };

    await secureConfigManager.enableConcurrentRotation(rotationConfig);
    componentLogger.info("Concurrent rotation enabled successfully");

    // Step 2: Create and store some test credentials
    const credentials: string[] = [];
    for (let i = 1; i <= 5; i++) {
      const credentialId = await secureConfigManager.storeCredential(
        "api_key",
        `test-service-${i}`,
        `test-api-key-${i}-${Date.now()}`,
        {
          autoRotate: true,
          rotationInterval: 24 * 60 * 60 * 1000, // 24 hours
          userId: "example-user",
        },
      );
      credentials.push(credentialId);
      componentLogger.info(`Stored test credential ${i}`, { credentialId });
    }

    // Step 3: Demonstrate individual concurrent rotation
    componentLogger.info("Testing individual concurrent rotation");
    const rotatedCredential =
      await secureConfigManager.rotateCredentialConcurrent(credentials[0], {
        policyId: "api_key_enhanced",
        priority: "high",
        gracePeriod: 5 * 60 * 1000, // 5 minutes
        userId: "example-user",
      });
    componentLogger.info("Individual rotation completed", {
      oldCredential: credentials[0],
      newCredential: rotatedCredential,
    });

    // Step 4: Demonstrate batch rotation
    componentLogger.info("Testing batch rotation");
    const batchResult = await secureConfigManager.rotateBatch(
      credentials.slice(1), // Rotate remaining credentials
      {
        policyId: "api_key_enhanced",
        priority: "normal",
        concurrency: 2,
        userId: "example-user",
      },
    );
    componentLogger.info("Batch rotation completed", batchResult);

    // Step 5: Check rotation status and performance
    const status = secureConfigManager.getConcurrentRotationStatus();
    componentLogger.info("Concurrent rotation status", status);

    // Step 6: Clean up - disable concurrent rotation
    await secureConfigManager.disableConcurrentRotation();
    componentLogger.info("Concurrent rotation disabled");
  } catch (error) {
    componentLogger.error("Basic concurrent rotation example failed", {
      error: error instanceof Error ? error.message : "Unknown error",
    });
    throw error;
  }
}

/**
 * Example: Advanced rotation with external service integration
 */
export async function advancedRotationWithExternalServicesExample(): Promise<void> {
  componentLogger.info(
    "Starting advanced rotation with external services example",
  );

  try {
    // Step 1: Enable concurrent rotation
    await secureConfigManager.enableConcurrentRotation({
      maxWorkerThreads: 4,
      defaultConcurrency: 3,
      maxBatchSize: 10,
    });

    // Step 2: Define external services for credential propagation
    const externalServices: ExternalServiceConfig[] = [
      {
        serviceId: "database-service",
        serviceName: "Application Database",
        type: "database",
        authMethod: "basic",
        updateMethod: "database_update",
        validationTimeout: 5000,
        rollbackSupported: true,
      },
      {
        serviceId: "api-gateway",
        serviceName: "API Gateway Service",
        type: "api",
        endpoint: "https://api-gateway.example.com/credentials",
        authMethod: "bearer",
        updateMethod: "rest_api",
        validationTimeout: 10000,
        rollbackSupported: true,
      },
      {
        serviceId: "config-service",
        serviceName: "Configuration Service",
        type: "custom",
        authMethod: "certificate",
        updateMethod: "custom_script",
        customScript: "update-credential.sh",
        validationTimeout: 8000,
        rollbackSupported: false,
      },
    ];

    // Step 3: Create custom rotation policy for sensitive credentials
    const sensitiveRotationPolicy: RotationPolicy = {
      id: "sensitive_api_key",
      name: "Sensitive API Key Rotation",
      type: "time_based",
      enabled: true,
      interval: 12 * 60 * 60 * 1000, // 12 hours
      gracePeriod: 2 * 60 * 60 * 1000, // 2 hours
      notifyBeforeExpiry: 4 * 60 * 60 * 1000, // 4 hours
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      maxRetries: 3,
      retryInterval: 10 * 60 * 1000, // 10 minutes
    };

    secureConfigManager.setEnhancedRotationPolicy(sensitiveRotationPolicy);
    componentLogger.info("Custom rotation policy created", {
      policyId: sensitiveRotationPolicy.id,
    });

    // Step 4: Store a sensitive credential
    const sensitiveCredentialId = await secureConfigManager.storeCredential(
      "api_key",
      "payment-processor",
      "sensitive-payment-api-key-" + Date.now(),
      {
        autoRotate: true,
        rotationInterval: sensitiveRotationPolicy.interval,
        userId: "security-team",
      },
    );

    // Step 5: Rotate with external service integration
    componentLogger.info("Testing rotation with external service integration");
    const rotatedSensitiveCredential =
      await secureConfigManager.rotateCredentialConcurrent(
        sensitiveCredentialId,
        {
          policyId: "sensitive_api_key",
          priority: "critical",
          gracePeriod: 2 * 60 * 60 * 1000,
          userId: "security-team",
          externalServices,
        },
      );

    componentLogger.info("Advanced rotation with external services completed", {
      oldCredential: sensitiveCredentialId,
      newCredential: rotatedSensitiveCredential,
      externalServicesCount: externalServices.length,
    });

    // Step 6: Monitor performance and status
    const finalStatus = secureConfigManager.getConcurrentRotationStatus();
    componentLogger.info("Final concurrent rotation status", {
      enabled: finalStatus.enabled,
      performanceMetrics: finalStatus.performanceMetrics,
      queueStatus: finalStatus.queueStatus,
    });
  } catch (error) {
    componentLogger.error("Advanced rotation example failed", {
      error: error instanceof Error ? error.message : "Unknown error",
    });
    throw error;
  } finally {
    // Clean up
    await secureConfigManager.disableConcurrentRotation();
  }
}

/**
 * Example: Emergency rotation scenario
 */
export async function emergencyRotationExample(): Promise<void> {
  componentLogger.info("Starting emergency rotation example");

  try {
    // Step 1: Enable concurrent rotation for emergency scenarios
    await secureConfigManager.enableConcurrentRotation({
      maxWorkerThreads: 8,
      defaultConcurrency: 5,
      maxBatchSize: 100,
    });

    // Step 2: Simulate a security incident requiring immediate credential rotation
    const compromisedCredentials: string[] = [];

    // Create multiple potentially compromised credentials
    for (let i = 1; i <= 20; i++) {
      const credentialId = await secureConfigManager.storeCredential(
        "api_key",
        `production-service-${i}`,
        `prod-api-key-${i}-${Date.now()}`,
        {
          autoRotate: true,
          rotationInterval: 7 * 24 * 60 * 60 * 1000, // 7 days normally
          userId: "production-system",
        },
      );
      compromisedCredentials.push(credentialId);
    }

    componentLogger.warn(
      "Security incident detected - initiating emergency rotation",
      {
        compromisedCredentialsCount: compromisedCredentials.length,
      },
    );

    // Step 3: Execute emergency batch rotation with high concurrency
    const emergencyStartTime = Date.now();

    const emergencyRotationResult = await secureConfigManager.rotateBatch(
      compromisedCredentials,
      {
        policyId: "emergency",
        priority: "emergency",
        concurrency: 8, // Maximum concurrency for emergency
        userId: "security-incident-response",
      },
    );

    const emergencyDuration = Date.now() - emergencyStartTime;

    componentLogger.info("Emergency rotation completed", {
      ...emergencyRotationResult,
      durationMs: emergencyDuration,
      averageTimePerCredential: Math.round(
        emergencyDuration / compromisedCredentials.length,
      ),
      successRate:
        (emergencyRotationResult.successfulRotations /
          compromisedCredentials.length) *
        100,
    });

    // Step 4: Verify all credentials were handled
    if (emergencyRotationResult.failedRotations > 0) {
      componentLogger.error(
        "Some credentials failed to rotate during emergency",
        {
          failedCredentials: emergencyRotationResult.failed,
        },
      );

      // In a real scenario, you would trigger additional security measures here
      // such as disabling failed credentials, alerting security teams, etc.
    }

    // Step 5: Generate emergency rotation report
    const postIncidentStatus =
      secureConfigManager.getConcurrentRotationStatus();
    const performanceReport = {
      incident: "credential-compromise-detected",
      credentialsAffected: compromisedCredentials.length,
      rotationResults: emergencyRotationResult,
      performanceMetrics: postIncidentStatus.performanceMetrics,
      duration: emergencyDuration,
      successRate:
        (emergencyRotationResult.successfulRotations /
          compromisedCredentials.length) *
        100,
      timestamp: new Date().toISOString(),
    };

    componentLogger.info(
      "Emergency rotation performance report",
      performanceReport,
    );
  } catch (error) {
    componentLogger.error("Emergency rotation example failed", {
      error: error instanceof Error ? error.message : "Unknown error",
    });
    throw error;
  } finally {
    await secureConfigManager.disableConcurrentRotation();
  }
}

/**
 * Example: Performance benchmarking
 */
export async function performanceBenchmarkExample(): Promise<void> {
  componentLogger.info("Starting performance benchmark example");

  try {
    const credentialCounts = [10, 50, 100];
    const concurrencyLevels = [1, 2, 4, 8];
    const results: Array<{
      credentialCount: number;
      concurrency: number;
      duration: number;
      averageTimePerCredential: number;
      successRate: number;
      performanceMetrics: unknown;
    }> = [];

    for (const credentialCount of credentialCounts) {
      for (const concurrency of concurrencyLevels) {
        componentLogger.info(
          `Benchmarking ${credentialCount} credentials with concurrency ${concurrency}`,
        );

        // Enable concurrent rotation with specific concurrency
        await secureConfigManager.enableConcurrentRotation({
          maxWorkerThreads: Math.max(concurrency, 4),
          defaultConcurrency: concurrency,
          maxBatchSize: credentialCount,
        });

        // Create test credentials
        const testCredentials: string[] = [];
        for (let i = 1; i <= credentialCount; i++) {
          const credentialId = await secureConfigManager.storeCredential(
            "api_key",
            `benchmark-service-${i}`,
            `benchmark-api-key-${i}-${Date.now()}`,
            { userId: "benchmark-test" },
          );
          testCredentials.push(credentialId);
        }

        // Perform timed batch rotation
        const startTime = Date.now();
        const batchResult = await secureConfigManager.rotateBatch(
          testCredentials,
          {
            policyId: "api_key_enhanced",
            priority: "normal",
            concurrency,
            userId: "benchmark-test",
          },
        );
        const duration = Date.now() - startTime;

        // Collect performance metrics
        const status = secureConfigManager.getConcurrentRotationStatus();
        const benchmarkResult = {
          credentialCount,
          concurrency,
          duration,
          averageTimePerCredential: Math.round(duration / credentialCount),
          successRate:
            (batchResult.successfulRotations / credentialCount) * 100,
          performanceMetrics: status.performanceMetrics,
        };

        results.push(benchmarkResult);
        componentLogger.info("Benchmark result", benchmarkResult);

        // Clean up
        await secureConfigManager.disableConcurrentRotation();
        await new Promise((resolve) => setTimeout(resolve, 1000)); // Brief pause between tests
      }
    }

    // Summary report
    componentLogger.info("Performance benchmark summary", {
      totalTests: results.length,
      results: results.map((r) => ({
        config: `${r.credentialCount} credentials, concurrency ${r.concurrency}`,
        duration: `${r.duration}ms`,
        avgPerCredential: `${r.averageTimePerCredential}ms`,
        successRate: `${r.successRate}%`,
      })),
    });

    // Find optimal configuration
    const optimalResult = results.reduce((best, current) => {
      const bestEfficiency = best.credentialCount / best.duration;
      const currentEfficiency = current.credentialCount / current.duration;
      return currentEfficiency > bestEfficiency ? current : best;
    });

    componentLogger.info("Optimal configuration identified", {
      credentialCount: optimalResult.credentialCount,
      concurrency: optimalResult.concurrency,
      duration: optimalResult.duration,
      efficiency: `${Math.round(optimalResult.credentialCount / (optimalResult.duration / 1000))} credentials/second`,
    });
  } catch (error) {
    componentLogger.error("Performance benchmark failed", {
      error: error instanceof Error ? error.message : "Unknown error",
    });
    throw error;
  }
}

/**
 * Run all examples
 */
export async function runAllConcurrentRotationExamples(): Promise<void> {
  componentLogger.info("Running all concurrent rotation examples");

  try {
    await basicConcurrentRotationExample();
    await new Promise((resolve) => setTimeout(resolve, 2000));

    await advancedRotationWithExternalServicesExample();
    await new Promise((resolve) => setTimeout(resolve, 2000));

    await emergencyRotationExample();
    await new Promise((resolve) => setTimeout(resolve, 2000));

    await performanceBenchmarkExample();

    componentLogger.info(
      "All concurrent rotation examples completed successfully",
    );
  } catch (error) {
    componentLogger.error("Concurrent rotation examples failed", {
      error: error instanceof Error ? error.message : "Unknown error",
    });
    throw error;
  }
}

// Export for use in other modules
export default {
  basicConcurrentRotationExample,
  advancedRotationWithExternalServicesExample,
  emergencyRotationExample,
  performanceBenchmarkExample,
  runAllConcurrentRotationExamples,
};
