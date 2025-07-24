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
        componentLogger.error('Error during graceful shutdown', error);
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
    componentLogger.error('Failed to start server', error);
    process.exit(1);
  }
}

// Start the server
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error('Unhandled error during server startup:', error);
    process.exit(1);
  });
}

export { MakeServerInstance };
export default main;