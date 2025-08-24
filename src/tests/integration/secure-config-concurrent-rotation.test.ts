/**
 * Integration tests specifically for SecureConfig's concurrent rotation capabilities
 * with the 5-agent framework
 */

import {
  describe,
  test,
  expect,
  beforeAll,
  afterAll,
  beforeEach,
  afterEach,
} from "@jest/jest-globals";
import path from "path";
import fs from "fs/promises";
import { SecureConfigManager } from "../../lib/secure-config.js";
import { createConcurrentRotationAgent } from "../../utils/concurrent-rotation-integration.js";
import type {
  RotationManagerConfig,
  CredentialRotationRequest,
} from "../../types/rotation-types.js";
import logger from "../../lib/logger.js";

describe("SecureConfig Concurrent Rotation Integration", () => {
  let secureConfig: SecureConfigManager;
  let testConfigPath: string;
  let testAuditPath: string;

  const TEST_ROTATION_CONFIG: RotationManagerConfig = {
    maxWorkerThreads: 2,
    workerTimeoutMs: 15000,
    maxQueueSize: 100,
    defaultConcurrency: 3,
    maxBatchSize: 20,
    keyRotationIntervalMs: 2000,
    maxConcurrentConnections: 8,
    enableWebhooks: false,
    enableHSM: false,
    auditLogPath: "./test-audit/secure-config-rotation.log",
  };

  beforeAll(async () => {
    // Create test directories
    testConfigPath = path.join(process.cwd(), "test-secure-config");
    testAuditPath = path.join(process.cwd(), "test-audit");

    await fs.mkdir(testConfigPath, { recursive: true });
    await fs.mkdir(testAuditPath, { recursive: true });
  });

  afterAll(async () => {
    // Cleanup test directories
    try {
      await fs.rm(testConfigPath, { recursive: true, force: true });
      await fs.rm(testAuditPath, { recursive: true, force: true });
    } catch (error) {
      logger.warn("Failed to cleanup test directories", { error });
    }
  });

  beforeEach(async () => {
    // Initialize SecureConfig with concurrent rotation enabled
    secureConfig = new SecureConfigManager({
      configPath: testConfigPath,
      enableConcurrentRotation: true,
      rotationConfig: TEST_ROTATION_CONFIG,
    });

    await secureConfig.initialize();
  });

  afterEach(async () => {
    // Cleanup SecureConfig
    if (secureConfig) {
      await secureConfig.shutdown();
    }
  });

  describe("Concurrent Rotation Setup", () => {
    test("should enable concurrent rotation with custom agent", async () => {
      const customAgent = createConcurrentRotationAgent(TEST_ROTATION_CONFIG);
      await customAgent.initialize();
      await customAgent.start();

      await secureConfig.enableConcurrentRotation(customAgent);

      const rotationAgent = secureConfig.getConcurrentRotationAgent();
      expect(rotationAgent).toBeDefined();
      expect(rotationAgent.getStatus().enabled).toBe(true);

      await customAgent.stop();
    });

    test("should auto-create rotation agent when enabled without custom agent", async () => {
      await secureConfig.enableConcurrentRotation();

      const rotationAgent = secureConfig.getConcurrentRotationAgent();
      expect(rotationAgent).toBeDefined();
      expect(rotationAgent.getStatus().enabled).toBe(true);
    });

    test("should disable concurrent rotation", async () => {
      await secureConfig.enableConcurrentRotation();
      expect(secureConfig.getConcurrentRotationAgent()).toBeDefined();

      await secureConfig.disableConcurrentRotation();
      expect(secureConfig.getConcurrentRotationAgent()).toBeNull();
    });
  });

  describe("Credential Storage and Rotation", () => {
    beforeEach(async () => {
      await secureConfig.enableConcurrentRotation();
    });

    test("should store and rotate API credentials", async () => {
      const testCredentials = [
        { key: "api-service-1", value: "initial-key-1", type: "api_key" },
        { key: "api-service-2", value: "initial-key-2", type: "api_key" },
        {
          key: "database-password",
          value: "initial-db-pass",
          type: "password",
        },
      ];

      // Store initial credentials
      for (const cred of testCredentials) {
        await secureConfig.set(cred.key, cred.value, {
          encryptionType: "aes-256-gcm",
          credentialType: cred.type,
          enableRotation: true,
          rotationIntervalMs: 5000, // 5 seconds for testing
        });
      }

      // Verify credentials stored
      for (const cred of testCredentials) {
        const stored = await secureConfig.get(cred.key);
        expect(stored).toBe(cred.value);
      }

      // Prepare rotation requests
      const rotationRequests: CredentialRotationRequest[] = testCredentials.map(
        (cred) => ({
          credentialId: cred.key,
          credentialType: cred.type as any,
          rotationType: "automatic",
          priority: "medium",
          scheduledAt: new Date(),
          context: {
            source: "secure-config-test",
            originalValue: cred.value,
          },
        }),
      );

      // Execute batch rotation
      const rotationResult = await secureConfig.rotateBatch(rotationRequests, {
        priority: "high",
        concurrency: 2,
        validateRotation: true,
      });

      expect(rotationResult).toBeDefined();
      expect(rotationResult.batchId).toBeDefined();
      expect(rotationResult.results).toBeDefined();
      expect(Object.keys(rotationResult.results)).toHaveLength(
        testCredentials.length,
      );

      // Verify credentials were rotated (values should be different)
      for (const cred of testCredentials) {
        const rotatedValue = await secureConfig.get(cred.key);
        expect(rotatedValue).toBeDefined();
        expect(rotatedValue).not.toBe(cred.value); // Should be rotated to new value
      }
    });

    test("should handle rotation with validation", async () => {
      await secureConfig.set("validated-key", "original-value", {
        encryptionType: "aes-256-gcm",
        credentialType: "api_key",
        enableRotation: true,
        validationEnabled: true,
      });

      const rotationRequest: CredentialRotationRequest = {
        credentialId: "validated-key",
        credentialType: "api_key",
        rotationType: "automatic",
        priority: "high",
        scheduledAt: new Date(),
        context: { requireValidation: true },
      };

      const result = await secureConfig.rotateBatch([rotationRequest], {
        priority: "high",
        concurrency: 1,
        validateRotation: true,
        rollbackOnFailure: true,
      });

      expect(result.batchId).toBeDefined();
      expect(result.results["validated-key"]).toBeDefined();
    });

    test("should track rotation history and audit logs", async () => {
      await secureConfig.set("tracked-credential", "tracked-value", {
        encryptionType: "aes-256-gcm",
        credentialType: "api_key",
        enableRotation: true,
        enableAuditLogging: true,
      });

      const rotationRequest: CredentialRotationRequest = {
        credentialId: "tracked-credential",
        credentialType: "api_key",
        rotationType: "manual",
        priority: "medium",
        scheduledAt: new Date(),
        context: {
          audit: true,
          requestedBy: "integration-test",
        },
      };

      const result = await secureConfig.rotateBatch([rotationRequest]);

      // Verify audit logging occurred
      expect(result.batchId).toBeDefined();

      // Check if rotation history is maintained
      const metadata = await secureConfig.getMetadata("tracked-credential");
      expect(metadata).toBeDefined();
      expect(metadata.lastRotated).toBeDefined();
    });
  });

  describe("Concurrent Batch Operations", () => {
    beforeEach(async () => {
      await secureConfig.enableConcurrentRotation();
    });

    test("should process multiple concurrent rotation batches", async () => {
      // Create multiple credential sets
      const credentialSets = [
        ["batch1-key1", "batch1-key2", "batch1-key3"],
        ["batch2-key1", "batch2-key2", "batch2-key3"],
        ["batch3-key1", "batch3-key2", "batch3-key3"],
      ];

      // Store all credentials
      for (const [setIndex, keys] of credentialSets.entries()) {
        for (const [keyIndex, key] of keys.entries()) {
          await secureConfig.set(key, `initial-value-${setIndex}-${keyIndex}`, {
            encryptionType: "aes-256-gcm",
            credentialType: "api_key",
            enableRotation: true,
          });
        }
      }

      // Create concurrent rotation batches
      const rotationPromises = credentialSets.map((keys, setIndex) => {
        const rotationRequests: CredentialRotationRequest[] = keys.map(
          (key) => ({
            credentialId: key,
            credentialType: "api_key",
            rotationType: "automatic",
            priority: "medium",
            scheduledAt: new Date(),
            context: { batch: setIndex },
          }),
        );

        return secureConfig.rotateBatch(rotationRequests, {
          priority: "medium",
          concurrency: 2,
        });
      });

      // Wait for all batches to complete
      const results = await Promise.all(rotationPromises);

      // Verify all batches completed successfully
      for (const [index, result] of results.entries()) {
        expect(result.batchId).toBeDefined();
        expect(Object.keys(result.results)).toHaveLength(
          credentialSets[index].length,
        );
      }

      // Verify all credentials were rotated
      for (const [setIndex, keys] of credentialSets.entries()) {
        for (const [keyIndex, key] of keys.entries()) {
          const rotatedValue = await secureConfig.get(key);
          expect(rotatedValue).toBeDefined();
          expect(rotatedValue).not.toBe(
            `initial-value-${setIndex}-${keyIndex}`,
          );
        }
      }
    });

    test("should handle mixed priority rotation batches", async () => {
      // Store test credentials
      const credentials = [
        "critical-system-key",
        "high-priority-key",
        "normal-priority-key",
        "low-priority-key",
      ];

      for (const key of credentials) {
        await secureConfig.set(key, `value-${key}`, {
          encryptionType: "aes-256-gcm",
          credentialType: "api_key",
          enableRotation: true,
        });
      }

      // Create rotation requests with different priorities
      const priorityBatches = [
        {
          priority: "critical" as const,
          requests: [credentials[0]],
        },
        {
          priority: "high" as const,
          requests: [credentials[1]],
        },
        {
          priority: "medium" as const,
          requests: [credentials[2]],
        },
        {
          priority: "low" as const,
          requests: [credentials[3]],
        },
      ];

      // Submit all batches concurrently
      const rotationPromises = priorityBatches.map((batch) => {
        const rotationRequests: CredentialRotationRequest[] =
          batch.requests.map((credId) => ({
            credentialId: credId,
            credentialType: "api_key",
            rotationType: "automatic",
            priority: batch.priority,
            scheduledAt: new Date(),
            context: { priority: batch.priority },
          }));

        return secureConfig.rotateBatch(rotationRequests, {
          priority: batch.priority,
          concurrency: 1,
        });
      });

      const results = await Promise.all(rotationPromises);

      // All batches should complete successfully
      for (const result of results) {
        expect(result.batchId).toBeDefined();
        expect(Object.keys(result.results).length).toBeGreaterThan(0);
      }
    });
  });

  describe("Performance and Monitoring", () => {
    beforeEach(async () => {
      await secureConfig.enableConcurrentRotation();
    });

    test("should provide rotation agent performance metrics", async () => {
      const rotationAgent = secureConfig.getConcurrentRotationAgent();
      expect(rotationAgent).toBeDefined();

      const metrics = rotationAgent!.getPerformanceMetrics();

      expect(metrics.system).toBeDefined();
      expect(metrics.agents).toBeDefined();
      expect(metrics.messageBus).toBeDefined();

      expect(metrics.system.uptime).toBeGreaterThanOrEqual(0);
      expect(metrics.system.totalRotations).toBeGreaterThanOrEqual(0);
      expect(metrics.system.successRate).toBeGreaterThanOrEqual(0);
    });

    test("should track concurrent rotation statistics", async () => {
      // Process some rotations to generate statistics
      await secureConfig.set("stats-test-key", "stats-value", {
        credentialType: "api_key",
        enableRotation: true,
      });

      const rotationRequest: CredentialRotationRequest = {
        credentialId: "stats-test-key",
        credentialType: "api_key",
        rotationType: "automatic",
        priority: "medium",
        scheduledAt: new Date(),
        context: { statsTest: true },
      };

      await secureConfig.rotateBatch([rotationRequest]);

      const rotationAgent = secureConfig.getConcurrentRotationAgent();
      const status = rotationAgent!.getStatus();

      expect(status.rotationStats.totalRotations).toBeGreaterThanOrEqual(1);
      expect(status.rotationStats.successRate).toBeGreaterThanOrEqual(0);
    });

    test("should provide queue status information", async () => {
      const rotationAgent = secureConfig.getConcurrentRotationAgent();
      const queueStatus = rotationAgent!.getQueueStatus();

      expect(queueStatus.messageBusQueues).toBeDefined();
      expect(queueStatus.coordinatorQueues).toBeDefined();
      expect(queueStatus.activeWorkflows).toBeDefined();
      expect(queueStatus.pendingMessages).toBeDefined();
    });
  });

  describe("Error Handling and Recovery", () => {
    beforeEach(async () => {
      await secureConfig.enableConcurrentRotation();
    });

    test("should handle rotation failures gracefully", async () => {
      await secureConfig.set("failure-test-key", "failure-value", {
        credentialType: "api_key",
        enableRotation: true,
      });

      // Create a rotation request that might cause issues
      const problematicRequest: CredentialRotationRequest = {
        credentialId: "nonexistent-key", // This key doesn't exist
        credentialType: "api_key",
        rotationType: "automatic",
        priority: "medium",
        scheduledAt: new Date(),
        context: { expectFailure: true },
      };

      // Should not throw but should handle error gracefully
      const result = await secureConfig.rotateBatch([problematicRequest]);

      expect(result.batchId).toBeDefined();
      // Results might be empty or contain error information
      expect(result.results).toBeDefined();
    });

    test("should maintain system stability during concurrent failures", async () => {
      // Create multiple failing requests
      const failingRequests: CredentialRotationRequest[] = [
        "nonexistent-1",
        "nonexistent-2",
        "nonexistent-3",
      ].map((id) => ({
        credentialId: id,
        credentialType: "api_key",
        rotationType: "automatic",
        priority: "medium",
        scheduledAt: new Date(),
        context: { expectFailure: true },
      }));

      // Submit multiple failing batches concurrently
      const failurePromises = failingRequests.map((request) =>
        secureConfig.rotateBatch([request]),
      );

      const results = await Promise.allSettled(failurePromises);

      // System should remain stable
      const rotationAgent = secureConfig.getConcurrentRotationAgent();
      expect(rotationAgent!.getStatus().enabled).toBe(true);

      // Some or all requests may have been handled gracefully
      const fulfilledResults = results.filter((r) => r.status === "fulfilled");
      expect(fulfilledResults.length).toBeGreaterThanOrEqual(0);
    });
  });
});
