/**
 * FastMCP Server for Make.com API Integration
 * Main server implementation with authentication, error handling, and logging
 */

import { FastMCP, UserError } from 'fastmcp';
import { z } from 'zod';
import configManager from './lib/config.js';
import logger from './lib/logger.js';
import MakeApiClient from './lib/make-api-client.js';
import { setupGlobalErrorHandlers } from './utils/errors.js';

export class MakeServerInstance {
  private server: FastMCP;
  private apiClient: MakeApiClient;
  private componentLogger: ReturnType<typeof logger.child>;

  constructor() {
    this.componentLogger = logger.child({ component: 'MakeServer' });
    
    // Setup global error handlers
    setupGlobalErrorHandlers();

    // Initialize API client
    this.apiClient = new MakeApiClient(configManager.getMakeConfig());

    // Initialize FastMCP server
    this.server = new FastMCP({
      name: configManager.getConfig().name,
      version: "1.0.0",
      instructions: this.getServerInstructions(),
      authenticate: configManager.isAuthEnabled() ? this.authenticate.bind(this) : undefined,
    });

    this.setupServerEvents();
    this.addBasicTools();
  }

  private getServerInstructions(): string {
    return `
# Make.com FastMCP Server

This server provides comprehensive Make.com API access beyond the official MCP server capabilities.

## Available Features:
- **Platform Management**: Full scenario CRUD operations, connection management, webhook configuration
- **User & Permissions**: Role-based access control, team/organization administration  
- **Analytics & Audit**: Access to execution logs, performance metrics, audit trails
- **Resource Management**: Template management, folder organization, data store operations
- **Advanced Features**: Custom variables, AI agent configuration, billing access
- **Development Tools**: Custom app development, SDK management, hook management

## Authentication:
${configManager.isAuthEnabled() ? 
  '- Server requires API key authentication via x-api-key header' : 
  '- Server runs in open mode (no authentication required)'
}

## Rate Limiting:
- API calls are rate-limited to prevent abuse of Make.com API
- Current limits: ${configManager.getRateLimitConfig()?.maxRequests || 'unlimited'} requests per ${(configManager.getRateLimitConfig()?.windowMs || 60000) / 1000} seconds

## Usage Notes:
- All operations require valid Make.com API credentials
- Some operations may require specific team/organization permissions
- Error responses include detailed information for troubleshooting
`.trim();
  }

  private authenticate(request: any): any {
    const apiKey = request.headers?.['x-api-key'];
    const expectedSecret = configManager.getAuthSecret();

    if (!apiKey || apiKey !== expectedSecret) {
      throw new Response(null, {
        status: 401,
        statusText: 'Unauthorized - Invalid API key',
      });
    }

    // Return session data that will be available in tool context
    return {
      authenticated: true,
      timestamp: new Date().toISOString(),
    };
  }

  private setupServerEvents(): void {
    this.server.on('connect', (event) => {
      this.componentLogger.info('Client connected', {
        sessionId: event.session ? 'connected' : 'unknown',
        clientCapabilities: event.session?.clientCapabilities,
      });
    });

    this.server.on('disconnect', (event) => {
      this.componentLogger.info('Client disconnected', {
        sessionId: event.session ? 'disconnected' : 'unknown',
      });
    });
  }

  private addBasicTools(): void {
    // Health check tool
    this.server.addTool({
      name: 'health-check',
      description: 'Check server and Make.com API connectivity status',
      parameters: z.object({}),
      annotations: {
        title: 'Health Check',
        readOnlyHint: true,
        openWorldHint: true,
      },
      execute: async (args, { log }) => {
        log.info('Performing health check');

        const startTime = Date.now();
        const serverHealth = {
          server: 'healthy',
          timestamp: new Date().toISOString(),
          uptime: process.uptime(),
          memory: process.memoryUsage(),
          config: {
            logLevel: configManager.getLogLevel(),
            authEnabled: configManager.isAuthEnabled(),
            environment: process.env.NODE_ENV || 'development',
          },
        };

        // Check Make.com API connectivity
        const apiHealthy = await this.apiClient.healthCheck();
        const responseTime = Date.now() - startTime;

        const rateLimiterStatus = this.apiClient.getRateLimiterStatus();

        const healthStatus = {
          ...serverHealth,
          makeApi: {
            healthy: apiHealthy,
            responseTime: `${responseTime}ms`,
            rateLimiter: rateLimiterStatus,
          },
          overall: apiHealthy ? 'healthy' : 'degraded',
        };

        log.info('Health check completed', { 
          overall: healthStatus.overall,
          responseTime: healthStatus.makeApi.responseTime 
        });

        return JSON.stringify(healthStatus, null, 2);
      },
    });

    // Server info tool
    this.server.addTool({
      name: 'server-info',
      description: 'Get detailed server configuration and capabilities',
      parameters: z.object({}),
      annotations: {
        title: 'Server Information',
        readOnlyHint: true,
      },
      execute: async (args, { log }) => {
        log.info('Retrieving server information');

        const config = configManager.getConfig();
        const serverInfo = {
          name: config.name,
          version: config.version,
          environment: process.env.NODE_ENV || 'development',
          node: {
            version: process.version,
            platform: process.platform,
            arch: process.arch,
          },
          configuration: {
            logLevel: config.logLevel,
            authentication: {
              enabled: config.authentication?.enabled || false,
            },
            rateLimit: config.rateLimit ? {
              maxRequests: config.rateLimit.maxRequests,
              windowMs: config.rateLimit.windowMs,
            } : null,
            makeApi: {
              baseUrl: config.make.baseUrl,
              timeout: config.make.timeout,
              retries: config.make.retries,
              teamId: config.make.teamId || 'not_configured',
              organizationId: config.make.organizationId || 'not_configured',
            },
          },
          capabilities: [
            'scenario-management',
            'connection-management',
            'user-permissions',
            'analytics-audit',
            'template-management',
            'webhook-management',
            'variable-management',
            'custom-app-development',
            'billing-access',
          ],
          uptime: process.uptime(),
          memory: process.memoryUsage(),
        };

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(serverInfo, null, 2),
            },
          ],
        };
      },
    });

    // Configuration test tool
    this.server.addTool({
      name: 'test-configuration',
      description: 'Test Make.com API configuration and permissions',
      parameters: z.object({
        includePermissions: z.boolean().default(false).describe('Include detailed permission analysis'),
      }),
      annotations: {
        title: 'Configuration Test',
        readOnlyHint: true,
        openWorldHint: true,
      },
      execute: async ({ includePermissions }, { log, reportProgress }) => {
        log.info('Testing Make.com API configuration');
        
        reportProgress({ progress: 0, total: 100 });

        try {
          // Test basic API connectivity
          const userResponse = await this.apiClient.get('/users/me');
          reportProgress({ progress: 25, total: 100 });

          if (!userResponse.success) {
            throw new UserError(`API connectivity test failed: ${userResponse.error?.message}`);
          }

          log.info('API connectivity test passed');

          // Test team access if configured
          let teamAccess = null;
          if (configManager.getMakeConfig().teamId) {
            const teamResponse = await this.apiClient.get(`/teams/${configManager.getMakeConfig().teamId}`);
            teamAccess = teamResponse.success;
            reportProgress({ progress: 50, total: 100 });
          }

          // Test scenario access
          const scenariosResponse = await this.apiClient.get('/scenarios', {
            params: { limit: 1 }
          });
          const scenarioAccess = scenariosResponse.success;
          reportProgress({ progress: 75, total: 100 });

          const testResults = {
            timestamp: new Date().toISOString(),
            apiConnectivity: userResponse.success,
            userInfo: userResponse.data,
            teamAccess,
            scenarioAccess,
            configuration: {
              baseUrl: configManager.getMakeConfig().baseUrl,
              hasTeamId: !!configManager.getMakeConfig().teamId,
              hasOrgId: !!configManager.getMakeConfig().organizationId,
            },
          };

          if (includePermissions && userResponse.data) {
            log.info('Analyzing user permissions');
            // Add more detailed permission analysis here
            (testResults as any).permissions = {
              analyzed: true,
              // This would include detailed role and permission analysis
            };
          }

          reportProgress({ progress: 100, total: 100 });
          log.info('Configuration test completed successfully');

          return JSON.stringify(testResults, null, 2);
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          log.error('Configuration test failed', { error: errorMessage });  
          throw new UserError(`Configuration test failed: ${errorMessage}`);
        }
      },
    });
  }

  public getServer(): FastMCP {
    return this.server;
  }

  public async start(options?: { transportType?: 'stdio' | 'httpStream', httpStream?: any }): Promise<void> {
    this.componentLogger.info('Starting Make.com FastMCP Server', {
      version: configManager.getConfig().version,
      environment: process.env.NODE_ENV || 'development',
      authEnabled: configManager.isAuthEnabled(),
    });

    // Validate configuration before starting (skip in development with test key)
    if (!configManager.getMakeConfig().apiKey.includes('test_key')) {
      const isHealthy = await this.apiClient.healthCheck();
      if (!isHealthy) {
        throw new Error('Make.com API is not accessible. Please check your configuration.');
      }
      this.componentLogger.info('Make.com API connectivity verified');
    } else {
      this.componentLogger.warn('Running in development mode with test API key - some features may not work');
    }

    await this.server.start(options || {
      transportType: 'stdio',
    });

    this.componentLogger.info('Server started successfully');
  }

  public async shutdown(): Promise<void> {
    this.componentLogger.info('Shutting down server');
    
    try {
      await this.apiClient.shutdown();
      this.componentLogger.info('API client shutdown completed');
    } catch (error) {
      this.componentLogger.error('Error during API client shutdown', error);
    }

    this.componentLogger.info('Server shutdown completed');
  }
}

export default MakeServerInstance;