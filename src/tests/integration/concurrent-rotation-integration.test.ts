/**
 * Integration tests for the 5-agent concurrent credential rotation framework
 * with existing secure-config and credential-management systems
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
import { EventEmitter } from "events";
import path from "path";
import fs from "fs/promises";
import {
  ConcurrentRotationAgent,
  createConcurrentRotationAgent,
} from "../../utils/concurrent-rotation-integration.js";
import { SecureConfigManager } from "../../lib/secure-config.js";
import type {
  RotationBatch,
  CredentialRotationRequest,
  RotationManagerConfig,
} from "../../types/rotation-types.js";
import logger from "../../lib/logger.js";

describe("Concurrent Rotation Integration Tests", () => {
  let agent: ConcurrentRotationAgent;
  let secureConfig: SecureConfigManager;
  let testConfigPath: string;
  let testAuditPath: string;

  const TEST_CONFIG: RotationManagerConfig = {
    maxWorkerThreads: 2,
    workerTimeoutMs: 10000,
    maxQueueSize: 100,
    defaultConcurrency: 2,
    maxBatchSize: 10,
    keyRotationIntervalMs: 1000, // 1 second for testing
    maxConcurrentConnections: 5,
    enableWebhooks: false,
    enableHSM: false,
    auditLogPath: "./test-audit/rotation-security.log",
  };

  beforeAll(async () => {
    // Create test directories
    testConfigPath = path.join(process.cwd(), "test-config");
    testAuditPath = path.join(process.cwd(), "test-audit");

    await fs.mkdir(testConfigPath, { recursive: true });
    await fs.mkdir(testAuditPath, { recursive: true });

    // Initialize SecureConfig with test path
    secureConfig = new SecureConfigManager({
      configPath: testConfigPath,
      enableConcurrentRotation: true,
      rotationConfig: TEST_CONFIG,
    });

    await secureConfig.initialize();
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
    // Create fresh agent instance for each test
    agent = createConcurrentRotationAgent(TEST_CONFIG);
    await agent.initialize();
    await agent.start();
  });

  afterEach(async () => {
    // Stop agent after each test
    if (agent) {
      await agent.stop();
    }
  });

  describe("Agent Initialization and Lifecycle", () => {
    test("should initialize all 5 agents successfully", async () => {
      const status = agent.getStatus();

      expect(status.enabled).toBe(true);
      expect(status.initialized).toBe(true);
      expect(status.agents).toHaveProperty("coordinator");
      expect(status.agents).toHaveProperty("validation");
      expect(status.agents).toHaveProperty("encryption");
      expect(status.agents).toHaveProperty("security");
      expect(status.agents).toHaveProperty("integration");

      // Verify each agent is ready
      expect(status.agents.coordinator.status).toBe("ready");
      expect(status.agents.validation.status).toBe("ready");
      expect(status.agents.encryption.status).toBe("ready");
      expect(status.agents.security.status).toBe("ready");
      expect(status.agents.integration.status).toBe("ready");
    });

    test("should start and stop gracefully", async () => {
      // Agent is already started in beforeEach
      expect(agent.getStatus().enabled).toBe(true);

      await agent.stop();
      expect(agent.getStatus().enabled).toBe(false);

      await agent.start();
      expect(agent.getStatus().enabled).toBe(true);
    });

    test("should prevent double initialization", async () => {
      // Agent is already initialized
      await expect(agent.initialize()).resolves.toBeUndefined();
      expect(agent.getStatus().initialized).toBe(true);
    });
  });

  describe("SecureConfig Integration", () => {
    test("should be compatible with SecureConfig concurrent rotation interface", async () => {
      // Test that our agent implements the expected interface
      expect(typeof agent.enqueueBatch).toBe("function");
      expect(typeof agent.getStatus).toBe("function");
      expect(typeof agent.getQueueStatus).toBe("function");
      expect(typeof agent.getPerformanceMetrics).toBe("function");

      // Test status format matches SecureConfig expectations
      const status = agent.getStatus();
      expect(status).toHaveProperty("enabled");
      expect(typeof status.enabled).toBe("boolean");
    });

    test("should integrate with SecureConfig rotation methods", async () => {
      // Enable concurrent rotation in SecureConfig
      await secureConfig.enableConcurrentRotation(agent);

      // Verify integration
      const rotationAgent = secureConfig.getConcurrentRotationAgent();
      expect(rotationAgent).toBeDefined();
      expect(rotationAgent.getStatus().enabled).toBe(true);
    });

    test("should handle batch rotation through SecureConfig", async () => {
      await secureConfig.enableConcurrentRotation(agent);

      // Create test credentials
      const testCredentials = [
        { key: "test-api-key-1", value: "old-key-1", type: "api_key" },
        { key: "test-api-key-2", value: "old-key-2", type: "api_key" },
      ];

      // Store credentials
      for (const cred of testCredentials) {
        await secureConfig.set(cred.key, cred.value, {
          encryptionType: "aes-256-gcm",
          credentialType: cred.type,
        });
      }

      // Prepare rotation batch
      const rotationRequests = testCredentials.map((cred) => ({
        credentialId: cred.key,
        credentialType: cred.type,
        rotationType: "automatic",
        priority: "medium",
        scheduledAt: new Date(),
        context: { source: "integration-test" },
      })) as CredentialRotationRequest[];

      // Execute batch rotation
      const batchResult = await secureConfig.rotateBatch(rotationRequests, {
        priority: "medium",
        concurrency: 2,
      });

      expect(batchResult).toBeDefined();
      expect(batchResult.batchId).toBeDefined();
      expect(batchResult.results).toBeDefined();
    });
  });

  describe("Message Bus Coordination", () => {
    test("should coordinate between all 5 agents via message bus", async () => {
      const rotationBatch: RotationBatch = {
        batchId: "test-batch-001",
        requests: [
          {
            credentialId: "test-cred-1",
            credentialType: "api_key",
            rotationType: "automatic",
            priority: "medium",
            scheduledAt: new Date(),
            context: { test: true },
          },
        ],
        priority: "medium",
        scheduledAt: new Date(),
        context: { integration: "test" },
      };

      // Set up event listeners to track coordination
      const events: string[] = [];

      agent.on("rotation_completed", () => {
        events.push("rotation_completed");
      });

      agent.on("rotation_failed", () => {
        events.push("rotation_failed");
      });

      // Enqueue batch and wait for processing
      agent.enqueueBatch(rotationBatch);

      // Wait for event processing
      await new Promise((resolve) => setTimeout(resolve, 2000));

      // Verify coordination occurred
      const messageBusStats = agent.getPerformanceMetrics().messageBus;
      expect(messageBusStats.totalMessagesProcessed).toBeGreaterThan(0);
      expect(messageBusStats.totalWorkflowExecutions).toBeGreaterThan(0);
    });

    test("should maintain agent health monitoring", async () => {
      const agentErrors: unknown[] = [];

      agent.on("agent_error", (error) => {
        agentErrors.push(error);
      });

      // Let the system run for a short period
      await new Promise((resolve) => setTimeout(resolve, 1000));

      // Verify no critical errors occurred
      expect(agentErrors.length).toBe(0);

      // Verify all agents are healthy
      const status = agent.getStatus();
      expect(status.agents.coordinator.status).toBe("ready");
      expect(status.agents.validation.status).toBe("ready");
      expect(status.agents.encryption.status).toBe("ready");
      expect(status.agents.security.status).toBe("ready");
      expect(status.agents.integration.status).toBe("ready");
    });
  });

  describe("Performance and Metrics", () => {
    test("should track rotation statistics correctly", async () => {
      const initialStats = agent.getStatus().rotationStats;
      expect(initialStats.totalRotations).toBe(0);
      expect(initialStats.successfulRotations).toBe(0);
      expect(initialStats.failedRotations).toBe(0);

      // Process a test batch
      const rotationBatch: RotationBatch = {
        batchId: "metrics-test-batch",
        requests: [
          {
            credentialId: "metrics-test-cred",
            credentialType: "api_key",
            rotationType: "automatic",
            priority: "medium",
            scheduledAt: new Date(),
            context: { test: "metrics" },
          },
        ],
        priority: "medium",
        scheduledAt: new Date(),
        context: { test: "metrics" },
      };

      agent.enqueueBatch(rotationBatch);

      // Wait for processing
      await new Promise((resolve) => setTimeout(resolve, 1500));

      // Verify statistics updated
      const finalStats = agent.getStatus().rotationStats;
      expect(finalStats.totalRotations).toBeGreaterThan(0);
    });

    test("should provide comprehensive performance metrics", async () => {
      const metrics = agent.getPerformanceMetrics();

      expect(metrics).toHaveProperty("system");
      expect(metrics).toHaveProperty("agents");
      expect(metrics).toHaveProperty("messageBus");

      // Verify system metrics
      expect(metrics.system).toHaveProperty("uptime");
      expect(metrics.system).toHaveProperty("totalRotations");
      expect(metrics.system).toHaveProperty("successRate");

      // Verify agent metrics
      expect(metrics.agents).toHaveProperty("coordinator");
      expect(metrics.agents).toHaveProperty("validation");
      expect(metrics.agents).toHaveProperty("encryption");
      expect(metrics.agents).toHaveProperty("security");
      expect(metrics.agents).toHaveProperty("integration");

      // Verify message bus metrics
      expect(metrics.messageBus).toHaveProperty("totalMessagesProcessed");
      expect(metrics.messageBus).toHaveProperty("totalWorkflowExecutions");
    });

    test("should provide queue status information", async () => {
      const queueStatus = agent.getQueueStatus();

      expect(queueStatus).toHaveProperty("messageBusQueues");
      expect(queueStatus).toHaveProperty("coordinatorQueues");
      expect(queueStatus).toHaveProperty("activeWorkflows");
      expect(queueStatus).toHaveProperty("pendingMessages");
    });
  });

  describe("Error Handling and Recovery", () => {
    test("should handle invalid batch gracefully", async () => {
      const invalidBatch = {
        batchId: "invalid-batch",
        requests: [], // Empty requests
        priority: "medium",
        scheduledAt: new Date(),
        context: {},
      } as RotationBatch;

      // Should not throw error
      expect(() => agent.enqueueBatch(invalidBatch)).not.toThrow();

      // Wait for processing
      await new Promise((resolve) => setTimeout(resolve, 500));

      // Agent should remain healthy
      expect(agent.getStatus().enabled).toBe(true);
    });

    test("should prevent operations on unstarted agent", async () => {
      const unstartedAgent = createConcurrentRotationAgent(TEST_CONFIG);
      await unstartedAgent.initialize();
      // Don't start the agent

      const testBatch: RotationBatch = {
        batchId: "unstarted-test",
        requests: [
          {
            credentialId: "test-cred",
            credentialType: "api_key",
            rotationType: "automatic",
            priority: "medium",
            scheduledAt: new Date(),
            context: {},
          },
        ],
        priority: "medium",
        scheduledAt: new Date(),
        context: {},
      };

      expect(() => unstartedAgent.enqueueBatch(testBatch)).toThrow(
        "Agent must be started",
      );

      await unstartedAgent.stop();
    });
  });

  describe("Configuration and Customization", () => {
    test("should respect configuration parameters", async () => {
      const customConfig: RotationManagerConfig = {
        maxWorkerThreads: 1,
        workerTimeoutMs: 5000,
        maxBatchSize: 5,
        enableWebhooks: true,
        enableHSM: false,
      };

      const customAgent = createConcurrentRotationAgent(customConfig);
      await customAgent.initialize();
      await customAgent.start();

      const status = customAgent.getStatus();
      expect(status.enabled).toBe(true);

      await customAgent.stop();
    });

    test("should use default configuration when not specified", async () => {
      const defaultAgent = createConcurrentRotationAgent();
      await defaultAgent.initialize();
      await defaultAgent.start();

      const status = defaultAgent.getStatus();
      expect(status.enabled).toBe(true);

      await defaultAgent.stop();
    });
  });

  describe("Concurrent Operations", () => {
    test("should handle multiple concurrent batches", async () => {
      const batches: RotationBatch[] = [];

      // Create multiple test batches
      for (let i = 0; i < 3; i++) {
        batches.push({
          batchId: `concurrent-batch-${i}`,
          requests: [
            {
              credentialId: `concurrent-cred-${i}`,
              credentialType: "api_key",
              rotationType: "automatic",
              priority: "medium",
              scheduledAt: new Date(),
              context: { batch: i },
            },
          ],
          priority: "medium",
          scheduledAt: new Date(),
          context: { test: "concurrent", batch: i },
        });
      }

      // Enqueue all batches concurrently
      batches.forEach((batch) => agent.enqueueBatch(batch));

      // Wait for all to process
      await new Promise((resolve) => setTimeout(resolve, 3000));

      // Verify all batches were processed
      const stats = agent.getStatus().rotationStats;
      expect(stats.totalRotations).toBeGreaterThanOrEqual(3);
    });
  });
});
