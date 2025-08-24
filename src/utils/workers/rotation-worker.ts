/**
 * Worker thread for concurrent credential rotation operations
 * Handles individual credential rotations in isolated worker context
 */

import { parentPort, workerData, isMainThread } from "worker_threads";
import * as crypto from "crypto";

// Don't run this code if not in a worker thread
if (isMainThread) {
  process.exit(1);
}

// Worker configuration
const WORKER_ID = workerData?.workerId || "unknown";
const MAX_MEMORY_MB = 256;
const ROTATION_TIMEOUT_MS = 30000;

// Worker state
let _operationsProcessed = 0;
let _operationsFailed = 0;

/**
 * Credential rotation operation interface
 */
interface RotationOperation {
  messageId: string;
  type: string;
  data: Record<string, unknown>;
}

/**
 * Rotation result interface
 */
interface RotationResult {
  messageId: string;
  success: boolean;
  data?: Record<string, unknown>;
  error?: string;
  performanceMs: number;
  memoryUsageMB: number;
}

/**
 * Simulate credential generation (in real implementation, this would use crypto libraries)
 */
function generateSecureCredential(type: string, length = 32): string {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const prefix = type === "api_key" ? "mcp_" : "";

  let result = prefix;
  for (let i = 0; i < length - prefix.length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }

  return result;
}

/**
 * Simulate credential encryption (in real implementation, this would use proper encryption)
 */
function encryptCredential(credential: string, key: string): string {
  // Simple base64 encoding for demonstration - in production use proper AES-256-GCM
  const combined = credential + ":" + key + ":" + Date.now();
  return Buffer.from(combined).toString("base64");
}

/**
 * Perform credential rotation
 */
async function performRotation(
  credentialId: string,
  newValue?: string,
  options: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const startTime = Date.now();

  try {
    // Simulate rotation steps

    // Step 1: Generate new credential if not provided
    const newCredential = newValue || generateSecureCredential("api_key", 32);

    // Step 2: Encrypt new credential
    const encryptionKey = crypto.randomBytes(32).toString("hex");
    const _encryptedCredential = encryptCredential(
      newCredential,
      encryptionKey,
    );

    // Step 3: Simulate storing encrypted credential
    await new Promise((resolve) => setTimeout(resolve, Math.random() * 100)); // 0-100ms delay

    // Step 4: Simulate validation
    const validationDelay = options.emergency ? 10 : 50; // Emergency rotations are faster
    await new Promise((resolve) =>
      setTimeout(resolve, Math.random() * validationDelay),
    );

    const newCredentialId = `cred_${Date.now()}_${crypto.randomUUID().slice(0, 8)}`;
    const processingTime = Date.now() - startTime;

    return {
      oldCredentialId: credentialId,
      newCredentialId,
      rotationTimestamp: new Date().toISOString(),
      performanceMs: processingTime,
      encrypted: true,
      gracePeriod: options.gracePeriod || 300000, // 5 minutes default
    };
  } catch (error) {
    throw new Error(
      `Rotation failed: ${error instanceof Error ? error.message : "Unknown error"}`,
    );
  }
}

/**
 * Perform emergency rotation (faster, reduced validation)
 */
async function performEmergencyRotation(
  credentialId: string,
  _options: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const startTime = Date.now();

  try {
    // Emergency rotation with minimal steps
    const _newCredential = generateSecureCredential("emergency_api_key", 32);
    const newCredentialId = `emrg_${Date.now()}_${crypto.randomUUID().slice(0, 8)}`;

    // Minimal delay for emergency
    await new Promise((resolve) => setTimeout(resolve, 10));

    const processingTime = Date.now() - startTime;

    return {
      oldCredentialId: credentialId,
      newCredentialId,
      rotationTimestamp: new Date().toISOString(),
      performanceMs: processingTime,
      emergency: true,
      gracePeriod: 60000, // 1 minute for emergency
    };
  } catch (error) {
    throw new Error(
      `Emergency rotation failed: ${error instanceof Error ? error.message : "Unknown error"}`,
    );
  }
}

/**
 * Process a rotation operation
 */
async function processOperation(operation: RotationOperation): Promise<void> {
  const startTime = Date.now();
  const startMemory = process.memoryUsage().heapUsed;

  try {
    let result: Record<string, unknown>;

    switch (operation.type) {
      case "rotation":
        result = await performRotation(
          operation.data.credentialId as string,
          operation.data.newValue as string,
          operation.data,
        );
        break;

      case "emergency_rotation":
        result = await performEmergencyRotation(
          operation.data.credentialId as string,
          operation.data,
        );
        break;

      default:
        throw new Error(`Unknown operation type: ${operation.type}`);
    }

    const processingTime = Date.now() - startTime;
    const memoryUsed =
      (process.memoryUsage().heapUsed - startMemory) / (1024 * 1024);

    _operationsProcessed++;

    const response: RotationResult = {
      messageId: operation.messageId,
      success: true,
      data: result,
      performanceMs: processingTime,
      memoryUsageMB: memoryUsed,
    };

    // Send result back to main thread
    parentPort?.postMessage(response);
  } catch (error) {
    _operationsFailed++;

    const processingTime = Date.now() - startTime;
    const memoryUsed =
      (process.memoryUsage().heapUsed - startMemory) / (1024 * 1024);

    const errorResponse: RotationResult = {
      messageId: operation.messageId,
      success: false,
      error: error instanceof Error ? error.message : "Unknown error",
      performanceMs: processingTime,
      memoryUsageMB: memoryUsed,
    };

    parentPort?.postMessage(errorResponse);
  }
}

/**
 * Monitor worker health and memory usage
 */
function monitorWorkerHealth(): void {
  const memUsage = process.memoryUsage();
  const heapUsedMB = memUsage.heapUsed / (1024 * 1024);

  if (heapUsedMB > MAX_MEMORY_MB) {
    console.error(
      `Worker ${WORKER_ID} memory usage exceeded threshold: ${heapUsedMB}MB`,
    );

    // Send health warning
    parentPort?.postMessage({
      type: "health_warning",
      workerId: WORKER_ID,
      memoryUsageMB: heapUsedMB,
      threshold: MAX_MEMORY_MB,
    });

    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }
  }
}

/**
 * Handle incoming messages from main thread
 */
if (parentPort) {
  parentPort.on("message", async (message: RotationOperation) => {
    // Add timeout protection
    const timeoutId = setTimeout(() => {
      const timeoutResponse: RotationResult = {
        messageId: message.messageId,
        success: false,
        error: `Operation timeout after ${ROTATION_TIMEOUT_MS}ms`,
        performanceMs: ROTATION_TIMEOUT_MS,
        memoryUsageMB: process.memoryUsage().heapUsed / (1024 * 1024),
      };

      parentPort?.postMessage(timeoutResponse);
    }, ROTATION_TIMEOUT_MS);

    try {
      await processOperation(message);
    } finally {
      clearTimeout(timeoutId);
    }
  });

  // Send ready signal
  parentPort.postMessage({
    type: "worker_ready",
    workerId: WORKER_ID,
  });

  // Start health monitoring
  setInterval(monitorWorkerHealth, 5000); // Check every 5 seconds
} else {
  console.error("Worker thread started without parent port");
  process.exit(1);
}

// Handle worker termination
process.on("SIGTERM", () => {
  console.warn(
    `Worker ${WORKER_ID} received SIGTERM, shutting down gracefully`,
  );
  process.exit(0);
});

process.on("SIGINT", () => {
  console.warn(`Worker ${WORKER_ID} received SIGINT, shutting down gracefully`);
  process.exit(0);
});

// Export for type checking (won't be used at runtime in worker)
export {};
