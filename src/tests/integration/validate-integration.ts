/**
 * Quick validation script for concurrent rotation integration
 * Validates the basic integration between 5-agent architecture and existing systems
 */

import { createConcurrentRotationAgent } from "../../utils/concurrent-rotation-integration.js";
import type { RotationManagerConfig } from "../../types/rotation-types.js";
import logger from "../../lib/logger.js";

async function validateIntegration(): Promise<void> {
  logger.info("🔍 Validating 5-Agent Concurrent Rotation Integration");

  try {
    // Test 1: Basic Agent Creation and Initialization
    logger.info("Test 1: Creating ConcurrentRotationAgent...");

    const config: Partial<RotationManagerConfig> = {
      maxWorkerThreads: 2,
      workerTimeoutMs: 10000,
      maxQueueSize: 50,
      defaultConcurrency: 2,
      maxBatchSize: 10,
    };

    const agent = createConcurrentRotationAgent(config);
    logger.info("✅ Agent created successfully");

    // Test 2: Agent Initialization
    logger.info("Test 2: Initializing all 5 agents...");
    await agent.initialize();

    const initStatus = agent.getStatus();
    if (!initStatus.initialized) {
      throw new Error("Agent initialization failed");
    }
    logger.info("✅ All agents initialized successfully");

    // Test 3: Agent Startup
    logger.info("Test 3: Starting all agents...");
    await agent.start();

    const startStatus = agent.getStatus();
    if (!startStatus.enabled) {
      throw new Error("Agent startup failed");
    }
    logger.info("✅ All agents started successfully");

    // Test 4: Verify Agent Readiness
    logger.info("Test 4: Verifying all 5 agents are ready...");
    const agentNames = [
      "coordinator",
      "validation",
      "encryption",
      "security",
      "integration",
    ];

    for (const agentName of agentNames) {
      const agentStatus = startStatus.agents[agentName];
      if (!agentStatus || agentStatus.status !== "ready") {
        throw new Error(
          `Agent ${agentName} is not ready: ${agentStatus?.status || "undefined"}`,
        );
      }
      logger.info(`  ✅ ${agentName} agent is ready`);
    }

    // Test 5: Performance Metrics
    logger.info("Test 5: Checking performance metrics...");
    const metrics = agent.getPerformanceMetrics();

    const requiredSections = ["system", "agents", "messageBus"];
    for (const section of requiredSections) {
      if (!metrics[section]) {
        throw new Error(`Missing metrics section: ${section}`);
      }
    }

    for (const agentName of agentNames) {
      if (!metrics.agents[agentName]) {
        throw new Error(`Missing agent metrics: ${agentName}`);
      }
    }
    logger.info("✅ Performance metrics are comprehensive");

    // Test 6: Queue Status
    logger.info("Test 6: Checking queue status...");
    const queueStatus = agent.getQueueStatus();

    const requiredQueueSections = [
      "messageBusQueues",
      "coordinatorQueues",
      "activeWorkflows",
      "pendingMessages",
    ];
    for (const section of requiredQueueSections) {
      if (!Object.prototype.hasOwnProperty.call(queueStatus, section)) {
        throw new Error(`Missing queue status section: ${section}`);
      }
    }
    logger.info("✅ Queue status is comprehensive");

    // Test 7: Test Batch Processing (Dry Run)
    logger.info("Test 7: Testing batch processing interface...");

    // Create a minimal test batch (won't actually process credentials)
    const testBatch = {
      batchId: "validation-test-batch",
      requests: [
        {
          credentialId: "test-validation-credential",
          policyId: "test-policy",
          priority: "normal" as const,
          scheduledFor: new Date(),
        },
      ],
      priority: "normal" as const,
      scheduledAt: new Date(),
      context: { test: "validation" },
    };

    // This should not throw an error (batch enqueueing interface)
    agent.enqueueBatch(testBatch);
    logger.info("✅ Batch processing interface works correctly");

    // Wait a moment for any async processing
    await new Promise((resolve) => setTimeout(resolve, 1000));

    // Test 8: Agent Shutdown
    logger.info("Test 8: Shutting down agents gracefully...");
    await agent.stop();

    const stopStatus = agent.getStatus();
    if (stopStatus.enabled) {
      throw new Error("Agent shutdown failed");
    }
    logger.info("✅ All agents shut down successfully");

    logger.info("\n🎉 Integration validation completed successfully!");
    logger.info(
      "✨ The 5-agent concurrent rotation framework is properly integrated",
    );
  } catch (error) {
    logger.error("❌ Integration validation failed:", {
      error: error instanceof Error ? error.message : "Unknown error",
      stack: error instanceof Error ? error.stack : undefined,
    });
    throw error;
  }
}

// Run validation if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  validateIntegration()
    .then(() => {
      logger.info("🏆 Validation completed successfully");
      process.exit(0);
    })
    .catch((error) => {
      logger.error("💥 Validation failed", { error });
      process.exit(1);
    });
}

export { validateIntegration };
