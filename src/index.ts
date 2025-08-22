/**
 * Make.com FastMCP Server Entry Point
 * Initializes and starts the FastMCP server with proper error handling
 */

import MakeServerInstance from './server.js';
import logger from './lib/logger.js';
import configManager from './lib/config.js';

async function main(): Promise<void> {
  const componentLogger = logger.child({ component: 'Main' });
  
  try {
    componentLogger.info('Initializing Make.com FastMCP Server');

    // Create server instance
    const serverInstance = new MakeServerInstance();

    // Setup graceful shutdown handlers
    const gracefulShutdown = async (signal: string): Promise<void> => {
      componentLogger.info(`Received ${signal}, starting graceful shutdown`);
      
      try {
        await serverInstance.shutdown();
        componentLogger.info('Graceful shutdown completed');
        process.exit(0);
      } catch (error) {
        componentLogger.error('Error during graceful shutdown', error as Record<string, unknown>);
        process.exit(1);
      }
    };

    // Register shutdown handlers
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));

    // Start the server
    const transportType = process.argv.includes('--http') ? 'httpStream' : 'stdio';
    const httpOptions = transportType === 'httpStream' ? {
      endpoint: '/',
      port: configManager.getConfig().port || 3000,
    } : undefined;

    await serverInstance.start({
      transportType,
      httpStream: httpOptions,
    });

    componentLogger.info('Make.com FastMCP Server is running', {
      transport: transportType,
      port: httpOptions?.port,
    });

  } catch (error) {
    componentLogger.error('Failed to start server', error as Record<string, unknown>);
    process.exit(1);
  }
}

// Start the server only when running directly (not in test environment)
function isMainModule(): boolean {
  // In test environment, avoid using import.meta.url
  if (process.env.NODE_ENV === 'test' || process.env.JEST_WORKER_ID) {
    return false;
  }
  
  try {
    // Use import.meta.url for runtime detection
    return import.meta.url === `file://${process.argv[1]}`;
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

export { MakeServerInstance };
export default main;