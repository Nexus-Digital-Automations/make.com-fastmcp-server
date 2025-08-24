/**
 * Integration test runner for concurrent rotation framework
 * Validates integration with existing secure-config and credential-management systems
 */

import { createConcurrentRotationAgent } from "../../utils/concurrent-rotation-integration.js";
import { SecureConfigManager } from "../../lib/secure-config.js";
import type {
  RotationManagerConfig,
  CredentialRotationRequest,
  RotationBatch,
} from "../../types/rotation-types.js";
import logger from "../../lib/logger.js";
import path from "path";
import fs from "fs/promises";

class IntegrationTestRunner {
  private readonly testResults: {
    name: string;
    passed: boolean;
    error?: string;
    duration: number;
  }[] = [];
  private readonly testConfigPath: string;
  private readonly testAuditPath: string;

  constructor() {
    this.testConfigPath = path.join(process.cwd(), "integration-test-config");
    this.testAuditPath = path.join(process.cwd(), "integration-test-audit");
  }

  async setupTestEnvironment(): Promise<void> {
    logger.info("Setting up integration test environment");

    // Create test directories
    await fs.mkdir(this.testConfigPath, { recursive: true });
    await fs.mkdir(this.testAuditPath, { recursive: true });
  }

  async cleanupTestEnvironment(): Promise<void> {
    logger.info("Cleaning up integration test environment");

    try {
      await fs.rm(this.testConfigPath, { recursive: true, force: true });
      await fs.rm(this.testAuditPath, { recursive: true, force: true });
    } catch (error) {
      logger.warn("Failed to cleanup test directories", { error });
    }
  }

  async runTest(testName: string, testFn: () => Promise<void>): Promise<void> {
    logger.info(`Running integration test: ${testName}`);
    const startTime = Date.now();

    try {
      await testFn();
      const duration = Date.now() - startTime;
      this.testResults.push({ name: testName, passed: true, duration });
      logger.info(`✅ Test passed: ${testName} (${duration}ms)`);
    } catch (error) {
      const duration = Date.now() - startTime;
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      this.testResults.push({
        name: testName,
        passed: false,
        error: errorMessage,
        duration,
      });
      logger.error(`❌ Test failed: ${testName} (${duration}ms)`, {
        error: errorMessage,
      });
    }
  }

  async testBasicAgentInitialization(): Promise<void> {
    const config: Partial<RotationManagerConfig> = {
      maxWorkerThreads: 2,
      workerTimeoutMs: 10000,
      maxQueueSize: 50,
      defaultConcurrency: 2,
    };

    const agent = createConcurrentRotationAgent(config);

    await agent.initialize();

    const status = agent.getStatus();
    if (!status.initialized) {
      throw new Error("Agent failed to initialize");
    }

    await agent.start();

    const startedStatus = agent.getStatus();
    if (!startedStatus.enabled) {
      throw new Error("Agent failed to start");
    }

    // Verify all 5 agents are ready
    const agentNames = [
      "coordinator",
      "validation",
      "encryption",
      "security",
      "integration",
    ];
    for (const agentName of agentNames) {
      if (
        !startedStatus.agents[agentName] ||
        startedStatus.agents[agentName].status !== "ready"
      ) {
        throw new Error(`${agentName} agent is not ready`);
      }
    }

    await agent.stop();

    const stoppedStatus = agent.getStatus();
    if (stoppedStatus.enabled) {
      throw new Error("Agent failed to stop");
    }
  }

  async testSecureConfigIntegration(): Promise<void> {
    const rotationConfig: Partial<RotationManagerConfig> = {
      maxWorkerThreads: 2,
      maxBatchSize: 10,
    };

    const secureConfig = new SecureConfigManager({
      configPath: this.testConfigPath,
      enableConcurrentRotation: true,
      rotationConfig,
    });

    await secureConfig.initialize();
    await secureConfig.enableConcurrentRotation();

    const rotationAgent = secureConfig.getConcurrentRotationAgent();
    if (!rotationAgent) {
      throw new Error(
        "Failed to get concurrent rotation agent from SecureConfig",
      );
    }

    if (!rotationAgent.getStatus().enabled) {
      throw new Error("Rotation agent is not enabled in SecureConfig");
    }

    // Store test credential
    await secureConfig.set("integration-test-key", "test-value", {
      credentialType: "api_key",
      enableRotation: true,
    });

    // Verify credential stored
    const storedValue = await secureConfig.get("integration-test-key");
    if (storedValue !== "test-value") {
      throw new Error("Failed to store credential in SecureConfig");
    }

    await secureConfig.shutdown();
  }

  async testBatchRotation(): Promise<void> {
    const rotationConfig: Partial<RotationManagerConfig> = {
      maxWorkerThreads: 2,
      maxBatchSize: 5,
    };

    const secureConfig = new SecureConfigManager({
      configPath: this.testConfigPath,
      enableConcurrentRotation: true,
      rotationConfig,
    });

    await secureConfig.initialize();
    await secureConfig.enableConcurrentRotation();

    // Store multiple test credentials
    const testCredentials = [
      "batch-test-key-1",
      "batch-test-key-2",
      "batch-test-key-3",
    ];

    for (const key of testCredentials) {
      await secureConfig.set(key, `value-${key}`, {
        credentialType: "api_key",
        enableRotation: true,
      });
    }

    // Create rotation requests
    const rotationRequests: CredentialRotationRequest[] = testCredentials.map(
      (key) => ({
        credentialId: key,
        policyId: "test-batch-policy",
        priority: "normal",
        scheduledFor: new Date(),
      }),
    );

    // Execute batch rotation
    const result = await secureConfig.rotateBatch(rotationRequests, {
      priority: "medium",
      concurrency: 2,
    });

    if (!result.batchId) {
      throw new Error("Batch rotation did not return batch ID");
    }

    if (Object.keys(result.results).length !== testCredentials.length) {
      throw new Error(
        `Expected ${testCredentials.length} results, got ${Object.keys(result.results).length}`,
      );
    }

    await secureConfig.shutdown();
  }

  async testConcurrentBatches(): Promise<void> {
    const agent = createConcurrentRotationAgent({
      maxWorkerThreads: 3,
      maxBatchSize: 10,
    });

    await agent.initialize();
    await agent.start();

    // Create multiple concurrent batches
    const batches: RotationBatch[] = [];
    for (let i = 0; i < 3; i++) {
      batches.push({
        batchId: `concurrent-test-batch-${i}`,
        requests: [
          {
            credentialId: `concurrent-cred-${i}`,
            policyId: "concurrent-test-policy",
            priority: "normal",
            scheduledFor: new Date(),
          },
        ],
        priority: "normal",
        scheduledAt: new Date(),
        context: { test: "concurrent" },
      });
    }

    // Enqueue all batches
    batches.forEach((batch) => agent.enqueueBatch(batch));

    // Wait for processing
    await new Promise((resolve) => setTimeout(resolve, 3000));

    // Verify processing occurred
    const status = agent.getStatus();
    if (status.rotationStats.totalRotations === 0) {
      throw new Error("No rotations were processed");
    }

    await agent.stop();
  }

  async testPerformanceMetrics(): Promise<void> {
    const agent = createConcurrentRotationAgent({
      maxWorkerThreads: 2,
    });

    await agent.initialize();
    await agent.start();

    // Get performance metrics
    const metrics = agent.getPerformanceMetrics();

    // Verify metrics structure
    const expectedSections = ["system", "agents", "messageBus"];
    for (const section of expectedSections) {
      if (!metrics[section]) {
        throw new Error(`Missing metrics section: ${section}`);
      }
    }

    const expectedAgents = [
      "coordinator",
      "validation",
      "encryption",
      "security",
      "integration",
    ];
    for (const agentName of expectedAgents) {
      if (!metrics.agents[agentName]) {
        throw new Error(`Missing agent metrics: ${agentName}`);
      }
    }

    // Test queue status
    const queueStatus = agent.getQueueStatus();
    const expectedQueueSections = [
      "messageBusQueues",
      "coordinatorQueues",
      "activeWorkflows",
      "pendingMessages",
    ];
    for (const section of expectedQueueSections) {
      if (!Object.prototype.hasOwnProperty.call(queueStatus, section)) {
        throw new Error(`Missing queue status section: ${section}`);
      }
    }

    await agent.stop();
  }

  printResults(): void {
    logger.info("\n🧪 Integration Test Results:");
    logger.info("=".repeat(50));

    let passedCount = 0;
    let failedCount = 0;
    let totalDuration = 0;

    for (const result of this.testResults) {
      const status = result.passed ? "✅" : "❌";
      const duration = `${result.duration}ms`;

      logger.info(`${status} ${result.name} (${duration})`);
      if (!result.passed && result.error) {
        logger.info(`   Error: ${result.error}`);
      }

      if (result.passed) {
        passedCount++;
      } else {
        failedCount++;
      }
      totalDuration += result.duration;
    }

    logger.info("=".repeat(50));
    logger.info(`📊 Summary: ${passedCount} passed, ${failedCount} failed`);
    logger.info(`⏱️  Total duration: ${totalDuration}ms`);
    logger.info(
      `✨ Success rate: ${((passedCount / this.testResults.length) * 100).toFixed(1)}%`,
    );

    if (failedCount === 0) {
      logger.info(
        "🎉 All integration tests passed! The 5-agent concurrent rotation framework is fully integrated.",
      );
    } else {
      logger.error(
        "❌ Some integration tests failed. Please check the errors above.",
      );
    }
  }

  async runAllTests(): Promise<void> {
    logger.info("🚀 Starting 5-Agent Concurrent Rotation Integration Tests");

    await this.setupTestEnvironment();

    try {
      await this.runTest("Basic Agent Initialization", () =>
        this.testBasicAgentInitialization(),
      );
      await this.runTest("SecureConfig Integration", () =>
        this.testSecureConfigIntegration(),
      );
      await this.runTest("Batch Rotation", () => this.testBatchRotation());
      await this.runTest("Concurrent Batches", () =>
        this.testConcurrentBatches(),
      );
      await this.runTest("Performance Metrics", () =>
        this.testPerformanceMetrics(),
      );
    } finally {
      await this.cleanupTestEnvironment();
    }

    this.printResults();
  }
}

// Run tests if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const runner = new IntegrationTestRunner();
  runner.runAllTests().catch((error) => {
    logger.error("Integration test runner failed", { error });
    process.exit(1);
  });
}

export { IntegrationTestRunner };
