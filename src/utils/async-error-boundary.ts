/**
 * Async Error Boundary and Resource Cleanup Utilities
 * Provides comprehensive error handling and resource management for production systems
 */

import logger from "../lib/logger.js";

export interface ResourceCleanup {
  name: string;
  cleanup: () => Promise<void> | void;
  priority: "high" | "medium" | "low";
  timeout?: number; // ms
}

export interface ErrorBoundaryOptions {
  name: string;
  fallback?: () => Promise<unknown> | unknown;
  onError?: (error: Error, context: ErrorContext) => Promise<void> | void;
  retryAttempts?: number;
  retryDelayMs?: number;
  timeout?: number; // ms
  enableResourceTracking?: boolean;
}

export interface ErrorBoundaryExecuteOptions<T> {
  fallback?: () => Promise<T> | T;
  onError?: (error: Error, context: ErrorContext) => Promise<void> | void;
}

export interface ErrorContext {
  boundaryName: string;
  operation: string;
  attempt: number;
  startTime: number;
  metadata?: Record<string, unknown>;
}

export class AsyncErrorBoundary {
  private static readonly globalResources = new Map<string, ResourceCleanup>();
  private static readonly shutdownHandlers = new Set<() => Promise<void>>();
  private static isShuttingDown = false;

  private readonly resources = new Map<string, ResourceCleanup>();
  private readonly options: Required<ErrorBoundaryOptions>;
  private readonly componentLogger: ReturnType<typeof logger.child>;

  constructor(options: ErrorBoundaryOptions) {
    this.options = {
      fallback: () => null,
      onError: () => {},
      retryAttempts: 0,
      retryDelayMs: 1000,
      timeout: 30000, // 30 seconds default
      enableResourceTracking: true,
      ...options,
    };

    this.componentLogger = logger.child({
      component: "AsyncErrorBoundary",
      boundaryName: this.options.name,
    });

    // Register shutdown handler for this boundary
    AsyncErrorBoundary.shutdownHandlers.add(async () => {
      await this.cleanup();
    });
  }

  /**
   * Execute an async operation within error boundary with retry logic
   */
  async execute<T>(
    operation: () => Promise<T>,
    context: { operation: string; metadata?: Record<string, unknown> } = {
      operation: "unknown",
    },
    executeOptions?: ErrorBoundaryExecuteOptions<T>,
  ): Promise<T> {
    const startTime = Date.now();
    let lastError: Error | undefined;

    for (
      let attempt = 1;
      attempt <= this.options.retryAttempts + 1;
      attempt++
    ) {
      const errorContext: ErrorContext = {
        boundaryName: this.options.name,
        operation: context.operation,
        attempt,
        startTime,
        metadata: context.metadata,
      };

      try {
        // Execute with timeout wrapper
        const result = await this.withTimeout(
          operation(),
          this.options.timeout,
        );

        // Log successful execution on retry
        if (attempt > 1) {
          this.componentLogger.info("Operation succeeded after retry", {
            operation: context.operation,
            attempt,
            duration: Date.now() - startTime,
          });
        }

        return result;
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));

        this.componentLogger.error("Operation failed in error boundary", {
          operation: context.operation,
          attempt,
          error: lastError.message,
          stack: lastError.stack,
          duration: Date.now() - startTime,
        });

        // Call custom error handler
        const errorHandler = executeOptions?.onError || this.options.onError;
        if (errorHandler) {
          try {
            await errorHandler(lastError, errorContext);
          } catch (handlerError) {
            this.componentLogger.error("Error handler threw exception", {
              handlerError:
                handlerError instanceof Error
                  ? handlerError.message
                  : String(handlerError),
            });
          }
        }

        // If this is the last attempt, break to fallback
        if (attempt > this.options.retryAttempts) {
          break;
        }

        // Wait before retry
        if (this.options.retryDelayMs > 0) {
          await this.delay(this.options.retryDelayMs * attempt); // Exponential backoff
        }
      }
    }

    // All retries failed, try fallback
    const fallbackFn = executeOptions?.fallback || this.options.fallback;
    if (fallbackFn) {
      try {
        this.componentLogger.warn(
          "All retry attempts exhausted, executing fallback",
          {
            operation: context.operation,
            totalAttempts: this.options.retryAttempts + 1,
            finalError: lastError?.message,
          },
        );

        const fallbackResult = await fallbackFn();
        return fallbackResult as T;
      } catch (fallbackError) {
        const finalError = new Error(
          `Operation failed after ${this.options.retryAttempts + 1} attempts, and fallback also failed. Original error: ${lastError?.message}. Fallback error: ${fallbackError instanceof Error ? fallbackError.message : String(fallbackError)}`,
        );

        this.componentLogger.error("Fallback execution failed", {
          operation: context.operation,
          originalError: lastError?.message,
          fallbackError:
            fallbackError instanceof Error
              ? fallbackError.message
              : String(fallbackError),
        });

        throw finalError;
      }
    }

    // No fallback available, throw the original error
    const finalError = new Error(
      `Operation failed after ${this.options.retryAttempts + 1} attempts. Original error: ${lastError?.message}`,
    );

    this.componentLogger.error("Operation failed with no fallback", {
      operation: context.operation,
      originalError: lastError?.message,
      totalAttempts: this.options.retryAttempts + 1,
    });

    throw finalError;
  }

  /**
   * Register a resource for cleanup
   */
  registerResource(resource: ResourceCleanup): void {
    if (!this.options.enableResourceTracking) {
      return;
    }

    this.resources.set(resource.name, resource);

    // Also register globally for shutdown cleanup
    AsyncErrorBoundary.globalResources.set(
      `${this.options.name}:${resource.name}`,
      resource,
    );

    this.componentLogger.debug("Resource registered for cleanup", {
      resourceName: resource.name,
      priority: resource.priority,
    });
  }

  /**
   * Unregister a resource (already cleaned up)
   */
  unregisterResource(resourceName: string): void {
    this.resources.delete(resourceName);
    AsyncErrorBoundary.globalResources.delete(
      `${this.options.name}:${resourceName}`,
    );
  }

  /**
   * Execute operation with automatic resource cleanup
   */
  async withResource<T>(
    resource: ResourceCleanup,
    operation: () => Promise<T>,
  ): Promise<T> {
    this.registerResource(resource);

    try {
      const result = await this.execute(operation, {
        operation: `withResource:${resource.name}`,
      });
      return result;
    } finally {
      // Always cleanup resource after operation
      await this.cleanupResource(resource);
      this.unregisterResource(resource.name);
    }
  }

  /**
   * Cleanup specific resource
   */
  private async cleanupResource(resource: ResourceCleanup): Promise<void> {
    try {
      const timeout = resource.timeout || 5000;
      await this.withTimeout(Promise.resolve(resource.cleanup()), timeout);

      this.componentLogger.debug("Resource cleanup successful", {
        resourceName: resource.name,
      });
    } catch (error) {
      this.componentLogger.error("Resource cleanup failed", {
        resourceName: resource.name,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  /**
   * Cleanup all registered resources
   */
  async cleanup(): Promise<void> {
    if (this.resources.size === 0) {
      return;
    }

    this.componentLogger.info("Starting resource cleanup", {
      resourceCount: this.resources.size,
    });

    // Sort by priority: high -> medium -> low
    const priorityOrder: ResourceCleanup["priority"][] = [
      "high",
      "medium",
      "low",
    ];
    const sortedResources = Array.from(this.resources.values()).sort((a, b) => {
      return (
        priorityOrder.indexOf(a.priority) - priorityOrder.indexOf(b.priority)
      );
    });

    // Cleanup resources in priority order
    const cleanupPromises = sortedResources.map((resource) =>
      this.cleanupResource(resource),
    );

    try {
      await Promise.allSettled(cleanupPromises);
      this.resources.clear();

      this.componentLogger.info("Resource cleanup completed", {
        boundaryName: this.options.name,
      });
    } catch (error) {
      this.componentLogger.error("Some resources failed to cleanup", {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  /**
   * Wrap promise with timeout
   */
  private async withTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
  ): Promise<T> {
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => {
        reject(new Error(`Operation timed out after ${timeoutMs}ms`));
      }, timeoutMs);
    });

    return Promise.race([promise, timeoutPromise]);
  }

  /**
   * Simple delay utility
   */
  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Global shutdown handler - cleanup all boundaries and resources
   */
  static async shutdown(): Promise<void> {
    if (AsyncErrorBoundary.isShuttingDown) {
      return;
    }

    AsyncErrorBoundary.isShuttingDown = true;

    logger.info("Initiating global async error boundary shutdown", {
      boundaryCount: AsyncErrorBoundary.shutdownHandlers.size,
      globalResourceCount: AsyncErrorBoundary.globalResources.size,
    });

    // Execute all shutdown handlers
    const shutdownPromises = Array.from(
      AsyncErrorBoundary.shutdownHandlers,
    ).map(async (handler) => {
      try {
        await handler();
      } catch (error) {
        logger.error("Shutdown handler failed", {
          error: error instanceof Error ? error.message : String(error),
        });
      }
    });

    // Wait for all shutdowns with timeout
    try {
      await Promise.race([
        Promise.allSettled(shutdownPromises),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error("Shutdown timeout")), 30000),
        ),
      ]);

      logger.info("Global error boundary shutdown completed");
    } catch (error) {
      logger.error("Global shutdown encountered errors", {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  /**
   * Create a singleton error boundary for specific contexts
   */
  static create(
    name: string,
    options: Omit<ErrorBoundaryOptions, "name"> = {},
  ): AsyncErrorBoundary {
    return new AsyncErrorBoundary({ name, ...options });
  }
}

/**
 * Convenient decorator for adding error boundaries to class methods
 */
export function WithErrorBoundary(
  boundaryName: string,
  options: Omit<ErrorBoundaryOptions, "name"> = {},
) {
  return function (
    target: unknown,
    propertyName: string,
    descriptor: PropertyDescriptor,
  ) {
    const method = descriptor.value as (...args: unknown[]) => Promise<unknown>;
    const boundary = new AsyncErrorBoundary({ name: boundaryName, ...options });

    descriptor.value = async function (...args: unknown[]) {
      return boundary.execute(() => method.apply(this, args), {
        operation: `${(target as { constructor: { name: string } }).constructor.name}.${propertyName}`,
      });
    };

    return descriptor;
  };
}

/**
 * Global process handlers setup
 */
export function setupGlobalErrorHandlers(): void {
  // Handle uncaught exceptions
  process.on("uncaughtException", async (error) => {
    logger.error("Uncaught exception detected", {
      error: error.message,
      stack: error.stack,
    });

    // Attempt graceful shutdown
    try {
      await AsyncErrorBoundary.shutdown();
    } catch (shutdownError) {
      logger.error("Shutdown failed after uncaught exception", {
        shutdownError:
          shutdownError instanceof Error
            ? shutdownError.message
            : String(shutdownError),
      });
    }

    process.exit(1);
  });

  // Handle unhandled promise rejections
  process.on("unhandledRejection", async (reason, _promise) => {
    logger.error("Unhandled promise rejection detected", {
      reason: reason instanceof Error ? reason.message : String(reason),
      stack: reason instanceof Error ? reason.stack : undefined,
    });

    // Don't exit immediately for promise rejections, but log them
    // In production, you might want to implement more sophisticated handling
  });

  // Handle graceful shutdown signals
  ["SIGTERM", "SIGINT"].forEach((signal) => {
    process.on(signal, async () => {
      logger.info(`Received ${signal}, initiating graceful shutdown`);

      try {
        await AsyncErrorBoundary.shutdown();
        process.exit(0);
      } catch (error) {
        logger.error("Graceful shutdown failed", {
          signal,
          error: error instanceof Error ? error.message : String(error),
        });
        process.exit(1);
      }
    });
  });

  logger.info("Global error handlers initialized");
}

// Export singleton instances for common use cases
export const serverBoundary = AsyncErrorBoundary.create("ServerOperations", {
  retryAttempts: 2,
  retryDelayMs: 1000,
  timeout: 60000, // 1 minute for server operations
});

export const databaseBoundary = AsyncErrorBoundary.create(
  "DatabaseOperations",
  {
    retryAttempts: 3,
    retryDelayMs: 500,
    timeout: 30000, // 30 seconds for database operations
  },
);

export const apiBoundary = AsyncErrorBoundary.create("ApiOperations", {
  retryAttempts: 3,
  retryDelayMs: 1000,
  timeout: 45000, // 45 seconds for API operations
});

export const fileBoundary = AsyncErrorBoundary.create("FileOperations", {
  retryAttempts: 2,
  retryDelayMs: 100,
  timeout: 10000, // 10 seconds for file operations
});
