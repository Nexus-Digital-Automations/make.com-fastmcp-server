/**
 * Logger interface definitions for Make.com FastMCP Server
 * Provides centralized logger types to eliminate 'any' types
 */

/**
 * Standard logger interface that matches the actual logger implementation
 */
export interface ComponentLogger {
  /** Debug level logging */
  debug: (...args: unknown[]) => void;
  /** Info level logging */
  info: (...args: unknown[]) => void;
  /** Warning level logging */
  warn: (...args: unknown[]) => void;
  /** Error level logging */
  error: (...args: unknown[]) => void;
  /** Create child logger with additional context */
  child: (options?: Record<string, unknown>) => ComponentLogger;
}

/**
 * Logger context options for creating child loggers
 */
export interface LoggerContext {
  /** Component name */
  component: string;
  /** Correlation ID for request tracking */
  correlationId?: string;
  /** Operation name */
  operation?: string;
  /** Additional context properties */
  [key: string]: unknown;
}

/**
 * Logger configuration options
 */
export interface LoggerConfig {
  /** Log level threshold */
  level: "debug" | "info" | "warn" | "error" | "fatal";
  /** Output format */
  format?: "json" | "pretty" | "simple";
  /** Enable/disable logging */
  enabled: boolean;
  /** Additional logger-specific configuration */
  options?: Record<string, unknown>;
}

/**
 * Logger factory function type
 */
export type LoggerFactory = (context?: LoggerContext) => ComponentLogger;

/**
 * Console-based fallback logger implementation
 */
export const createFallbackLogger = (
  context?: LoggerContext,
): ComponentLogger => ({
  debug: (..._args: unknown[]): void => {
    // Silent debug fallback for test environments
  },
  info: (..._args: unknown[]): void => {
    // Silent info fallback for test environments
  },
  warn: (...args: unknown[]): void => {
    const prefix = context ? `[${context.component || "Unknown"}]` : "";
    console.warn(prefix, ...args);
  },
  error: (...args: unknown[]): void => {
    const prefix = context ? `[${context.component || "Unknown"}]` : "";
    console.error(prefix, ...args);
  },
  child: (options?: Record<string, unknown>): ComponentLogger =>
    createFallbackLogger({
      ...context,
      ...options,
    } as LoggerContext),
});

/**
 * Type guard to check if object implements ComponentLogger interface
 */
export function isComponentLogger(logger: unknown): logger is ComponentLogger {
  return (
    typeof logger === "object" &&
    logger !== null &&
    "debug" in logger &&
    "info" in logger &&
    "warn" in logger &&
    "error" in logger &&
    "child" in logger &&
    typeof (logger as ComponentLogger).debug === "function" &&
    typeof (logger as ComponentLogger).info === "function" &&
    typeof (logger as ComponentLogger).warn === "function" &&
    typeof (logger as ComponentLogger).error === "function" &&
    typeof (logger as ComponentLogger).child === "function"
  );
}

/**
 * Safe logger factory that ensures type safety
 */
export function createSafeLogger(
  baseLogger: unknown,
  context?: LoggerContext,
): ComponentLogger {
  if (isComponentLogger(baseLogger)) {
    return context ? baseLogger.child(context) : baseLogger;
  }

  return createFallbackLogger(context);
}
