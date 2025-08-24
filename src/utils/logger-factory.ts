/**
 * Logger Factory Utility
 * Centralized logger creation with fallback patterns to eliminate code duplication
 */

import logger from "../lib/logger.js";
import { ComponentLogger, LoggerContext } from "../types/logger.js";

export interface ComponentLoggerOptions {
  component: string;
  serverType?: string;
  metadata?: Record<string, unknown>;
  fallbackStrategy?: "simple" | "console" | "noop";
}

/**
 * Create a component logger with robust fallback handling
 * Eliminates the need for duplicated logger fallback patterns across the codebase
 */
export function createComponentLogger(
  options: ComponentLoggerOptions,
): ComponentLogger {
  const {
    component,
    serverType,
    metadata = {},
    fallbackStrategy = "simple",
  } = options;

  try {
    const childLogger = logger.child({
      component,
      ...(serverType && { serverType }),
      ...metadata,
    });

    // Validate logger has required methods
    if (
      childLogger &&
      typeof childLogger.info === "function" &&
      typeof childLogger.error === "function" &&
      typeof childLogger.warn === "function" &&
      typeof childLogger.debug === "function"
    ) {
      return childLogger as ComponentLogger;
    }

    // Fall through to fallback if validation fails
  } catch {
    // Fall through to fallback on any error
  }

  return createFallbackLogger(fallbackStrategy, {
    component,
    serverType,
    ...metadata,
  });
}

/**
 * Create fallback logger implementation based on strategy
 */
function createFallbackLogger(
  strategy: "simple" | "console" | "noop",
  context?: LoggerContext,
): ComponentLogger {
  const prefix = context ? `[${context.component || "Unknown"}]` : "";

  switch (strategy) {
    case "console":
      return createConsoleLogger(prefix);

    case "noop":
      return createNoOpLogger();

    case "simple":
    default:
      return createSimpleLogger();
  }
}

/**
 * Console-based fallback logger with full implementation
 * Used for environments where full console output is needed
 */
function createConsoleLogger(prefix: string): ComponentLogger {
  return {
    debug: (...args: unknown[]): void => {
      process.stdout.write(`${prefix} DEBUG: ${args.join(" ")}\n`);
    },
    info: (...args: unknown[]): void => {
      if (logger?.info && typeof logger.info === "function") {
        (logger.info as (...args: unknown[]) => void)(...args);
      } else {
        process.stdout.write(`${prefix} INFO: ${args.join(" ")}\n`);
      }
    },
    warn: (...args: unknown[]): void => {
      if (logger?.warn && typeof logger.warn === "function") {
        (logger.warn as (...args: unknown[]) => void)(...args);
      } else {
        process.stderr.write(`${prefix} WARN: ${args.join(" ")}\n`);
      }
    },
    error: (...args: unknown[]): void => {
      if (logger?.error && typeof logger.error === "function") {
        (logger.error as (...args: unknown[]) => void)(...args);
      } else {
        process.stderr.write(`${prefix} ERROR: ${args.join(" ")}\n`);
      }
    },
    child: (options?: Record<string, unknown>): ComponentLogger =>
      createComponentLogger({
        component: "Child",
        metadata: options,
        fallbackStrategy: "console",
      }),
  };
}

/**
 * No-operation fallback logger for test environments
 * Provides silent operation without any output
 */
function createNoOpLogger(): ComponentLogger {
  return {
    debug: (): void => {
      /* no operation */
    },
    info: (): void => {
      /* no operation */
    },
    warn: (): void => {
      /* no operation */
    },
    error: (): void => {
      /* no operation */
    },
    child: (): ComponentLogger => createNoOpLogger(),
  };
}

/**
 * Simple fallback logger that attempts to use base logger
 * Falls back to console if base logger is unavailable
 */
function createSimpleLogger(): ComponentLogger {
  return {
    debug: (...args: unknown[]): void => {
      if (logger?.debug && typeof logger.debug === "function") {
        (logger.debug as (...args: unknown[]) => void)(...args);
      }
      // Silent fallback for debug in simple mode
    },
    info: (...args: unknown[]): void => {
      if (logger?.info && typeof logger.info === "function") {
        (logger.info as (...args: unknown[]) => void)(...args);
      } else {
        process.stdout.write(`${args.join(" ")}\n`);
      }
    },
    warn: (...args: unknown[]): void => {
      if (logger?.warn && typeof logger.warn === "function") {
        (logger.warn as (...args: unknown[]) => void)(...args);
      } else {
        console.warn(...args);
      }
    },
    error: (...args: unknown[]): void => {
      if (logger?.error && typeof logger.error === "function") {
        (logger.error as (...args: unknown[]) => void)(...args);
      } else {
        console.error(...args);
      }
    },
    child: (options?: Record<string, unknown>): ComponentLogger =>
      createComponentLogger({
        component: "Child",
        metadata: options,
        fallbackStrategy: "simple",
      }),
  };
}

/**
 * Environment detection utility
 */
export function detectLoggerEnvironment():
  | "production"
  | "development"
  | "test" {
  const nodeEnv = process.env.NODE_ENV as "production" | "development" | "test";
  return nodeEnv || "development";
}

/**
 * Create logger with environment-aware fallback strategy
 */
export function createEnvironmentAwareLogger(
  component: string,
  metadata?: Record<string, unknown>,
): ComponentLogger {
  const environment = detectLoggerEnvironment();
  const fallbackStrategy = environment === "test" ? "noop" : "console";

  return createComponentLogger({
    component,
    metadata,
    fallbackStrategy,
  });
}
