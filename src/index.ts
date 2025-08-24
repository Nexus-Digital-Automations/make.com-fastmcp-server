/**
 * Make.com FastMCP Server Entry Point
 * Initializes and starts the appropriate FastMCP server based on arguments
 * Supports: Core Server, Analytics Server, or Legacy Monolithic Server
 */

import MakeServerInstance from "./server.js";
import CoreServer from "./servers/core-server.js";
import AnalyticsServer from "./servers/analytics-server.js";
import EssentialServer from "./servers/essential-server.js";
import DevelopmentServer from "./servers/development-server.js";
import GovernanceServer from "./servers/governance-server.js";
import EnterpriseServer from "./servers/enterprise-server.js";
import logger from "./lib/logger.js";
import configManager from "./lib/config.js";
import {
  setupGlobalErrorHandlers,
  serverBoundary,
  AsyncErrorBoundary,
} from "./utils/async-error-boundary.js";
import { createComponentLogger } from "./utils/logger-factory.js";

type ServerType = "essential" | "development" | "governance" | "enterprise" | "core" | "analytics" | "legacy" | "both";
type ServerInstance = MakeServerInstance | CoreServer | AnalyticsServer | EssentialServer | DevelopmentServer | GovernanceServer | EnterpriseServer;

function getServerType(): ServerType {
  const args = process.argv;

  if (args.includes("--essential")) {
    return "essential";
  }
  if (args.includes("--development")) {
    return "development";
  }
  if (args.includes("--governance")) {
    return "governance";
  }
  if (args.includes("--enterprise")) {
    return "enterprise";
  }
  if (args.includes("--core")) {
    return "core";
  }
  if (args.includes("--analytics")) {
    return "analytics";
  }
  if (args.includes("--both")) {
    return "both";
  }
  if (args.includes("--legacy")) {
    return "legacy";
  }

  // Default to essential for best performance
  return "essential";
}

function createServerInstance(
  serverType: Exclude<ServerType, "both">,
): ServerInstance {
  switch (serverType) {
    case "essential":
      return new EssentialServer();
    case "development":
      return new DevelopmentServer();
    case "governance":
      return new GovernanceServer();
    case "enterprise":
      return new EnterpriseServer();
    case "core":
      return new CoreServer();
    case "analytics":
      return new AnalyticsServer();
    case "legacy":
    default:
      return new MakeServerInstance();
  }
}

/**
 * Extract Method: Setup graceful shutdown handlers
 * Complexity reduction: ~35 lines → single method call
 */
function setupGracefulShutdownHandlers(
  serverInstance: ServerInstance,
  componentLogger: ReturnType<typeof createComponentLogger>,
): void {
  const gracefulShutdown = async (signal: string): Promise<void> => {
    componentLogger.info(`Received ${signal}, starting graceful shutdown`);

    try {
      await serverInstance.shutdown();
      await AsyncErrorBoundary.shutdown();
      componentLogger.info("Graceful shutdown completed");
      process.exit(0);
    } catch (error) {
      componentLogger.error(
        "Error during graceful shutdown",
        error as Record<string, unknown>,
      );

      try {
        await AsyncErrorBoundary.shutdown();
      } catch (cleanupError) {
        componentLogger.error(
          "Error during emergency cleanup",
          cleanupError as Record<string, unknown>,
        );
      }

      process.exit(1);
    }
  };

  process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
  process.on("SIGINT", () => gracefulShutdown("SIGINT"));
}

/**
 * Extract Method: Determine server port based on server type
 * Complexity reduction: ~20 lines → single method call
 */
function determineServerPort(serverType: Exclude<ServerType, "both">): number {
  switch (serverType) {
    case "essential":
      return 3000;
    case "development":
      return 3001;
    case "governance":
      return 3002;
    case "enterprise":
      return 3003;
    case "analytics":
      return 3001;
    default:
      return configManager().getConfig().port || 3000;
  }
}

/**
 * Extract Method: Configure server transport and HTTP options
 * Complexity reduction: ~10 lines → single method call
 */
function configureServerTransport(port: number): {
  transportType: "stdio" | "httpStream";
  httpOptions?: { endpoint: string; port: number };
} {
  const transportType: "stdio" | "httpStream" = process.argv.includes("--http") ? "httpStream" : "stdio";
  const httpOptions =
    transportType === "httpStream"
      ? { endpoint: "/", port }
      : undefined;

  return { transportType, httpOptions };
}

/**
 * Refactored startSingleServer - Extract Method pattern applied
 * Complexity reduced: 105 lines → 45 lines (57% reduction)
 */
async function startSingleServer(
  serverType: Exclude<ServerType, "both">,
): Promise<void> {
  const componentLogger = createComponentLogger({
    component: "Main",
    serverType,
    fallbackStrategy: "console",
  });

  try {
    componentLogger.info(`Initializing Make.com ${serverType} server`);

    // Create server instance
    const serverInstance = createServerInstance(serverType);

    // Setup graceful shutdown handlers
    setupGracefulShutdownHandlers(serverInstance, componentLogger);

    // Configure server transport and port
    const port = determineServerPort(serverType);
    const { transportType, httpOptions } = configureServerTransport(port);

    // Start the server
    await serverInstance.start({
      transportType,
      httpStream: httpOptions,
    });

    componentLogger.info(`Make.com ${serverType} server is running`, {
      serverType,
      transport: transportType,
      port: httpOptions?.port,
    });
  } catch (error) {
    componentLogger.error(
      `Failed to start ${serverType} server`,
      error as Record<string, unknown>,
    );
    process.exit(1);
  }
}

async function startBothServers(): Promise<void> {
  const componentLogger = createComponentLogger({
    component: "Main",
    metadata: { mode: "dual" },
    fallbackStrategy: "console",
  });

  componentLogger.info("Starting both Core and Analytics servers");

  try {
    // Start both servers in parallel
    const corePromise = startSingleServer("core");
    const analyticsPromise = startSingleServer("analytics");

    await Promise.all([corePromise, analyticsPromise]);

    componentLogger.info("Both servers started successfully", {
      corePort: 3000,
      analyticsPort: 3001,
    });
  } catch (error) {
    componentLogger.error(
      "Failed to start both servers",
      error as Record<string, unknown>,
    );
    process.exit(1);
  }
}

async function main(): Promise<void> {
  // Setup global error handlers and boundaries
  setupGlobalErrorHandlers();

  await serverBoundary.execute(
    async () => {
      const serverType = getServerType();

      logger.info("Starting FastMCP server with error boundaries", {
        serverType,
        nodeVersion: process.version,
        platform: process.platform,
      });

      if (serverType === "both") {
        await startBothServers();
      } else {
        await startSingleServer(serverType);
      }

      logger.info("Server startup completed successfully", { serverType });
    },
    {
      operation: "serverStartup",
      metadata: {
        serverType: getServerType(),
        startTime: Date.now(),
      },
    },
  );
}

// Start the server only when running directly (not in test environment)
function isMainModule(): boolean {
  // In test environment, avoid using import.meta.url
  if (process.env.NODE_ENV === "test" || process.env.JEST_WORKER_ID) {
    return false;
  }

  try {
    // Dynamic import.meta access to avoid Jest parsing issues
    // eslint-disable-next-line no-eval
    const importMeta = (0, eval)("import.meta");
    return importMeta.url === `file://${process.argv[1]}`;
  } catch {
    // Fallback for environments that don't support import.meta
    return false;
  }
}

if (isMainModule()) {
  main().catch((error) => {
    // Use stderr instead of console.error to avoid corrupting MCP stdio protocol
    process.stderr.write(`Unhandled error during server startup: ${error}\n`);
    process.exit(1);
  });
}

export { MakeServerInstance, CoreServer, AnalyticsServer, EssentialServer, DevelopmentServer, GovernanceServer, EnterpriseServer };
export default main;
