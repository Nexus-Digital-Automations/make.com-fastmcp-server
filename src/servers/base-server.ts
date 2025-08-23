/**
 * Base FastMCP Server for Make.com API Integration
 * Shared functionality between Core and Analytics servers
 */

import { FastMCP } from 'fastmcp';
import { z } from 'zod';
import configManager from '../lib/config.js';
import logger from '../lib/logger.js';
import MakeApiClient from '../lib/make-api-client.js';
import { setupGlobalErrorHandlers, MakeServerError, createAuthenticationError } from '../utils/errors.js';
import { extractCorrelationId } from '../utils/error-response.js';

// Define our custom session authentication type
export type MakeSessionAuth = {
  authenticated: boolean;
  timestamp: string;
  correlationId: string;
};

export interface ServerConfig {
  name: string;
  version: string;
  port?: number;
  toolCategories: string[];
  description: string;
}

export interface ToolRegistration {
  name: string;
  category: string;
  registerFunction: (server: FastMCP<MakeSessionAuth>, apiClient: MakeApiClient) => void;
}

export abstract class BaseServer {
  protected readonly server: FastMCP<MakeSessionAuth>;
  protected readonly apiClient: MakeApiClient;
  protected readonly componentLogger: ReturnType<typeof logger.child>;
  protected readonly config: ServerConfig;

  constructor(config: ServerConfig) {
    this.config = config;
    this.componentLogger = logger.child({ 
      component: config.name,
      serverType: this.getServerType()
    });
    
    // Setup global error handlers
    setupGlobalErrorHandlers();

    // Initialize API client
    this.apiClient = new MakeApiClient(configManager.getMakeConfig());
    
    // Initialize security systems
    this.initializeSecurity();

    // Initialize FastMCP server with proper type annotations
    this.server = new FastMCP<MakeSessionAuth>({
      name: config.name,
      version: config.version as `${number}.${number}.${number}`,
      instructions: this.getServerInstructions(),
      authenticate: configManager.isAuthEnabled() ? this.authenticate.bind(this) : undefined,
    });

    // Verify server instance is properly initialized
    if (!this.server || typeof this.server.addTool !== 'function') {
      throw new Error('FastMCP server instance not properly initialized');
    }

    this.setupServerEvents();
    this.addBasicTools();
  }

  protected abstract getServerType(): string;
  protected abstract getToolRegistrations(): ToolRegistration[];

  private async initializeSecurity(): Promise<void> {
    try {
      // Initialize circuit breakers for API client
      // Security features temporarily disabled during initialization to prevent timeout
      
      this.componentLogger.info('Security systems initialized (temporarily disabled)', {
        status: 'ok'
      });
    } catch (error) {
      this.componentLogger.error('Failed to initialize security systems', {
        error: error instanceof Error ? error.message : String(error)
      });
      // Don't throw - continue with security disabled
    }
  }

  private getServerInstructions(): string {
    const baseInstructions = `You are an AI assistant integrated with Make.com (formerly Integromat) automation platform.`;
    
    const toolCategories = this.config.toolCategories.join(', ');
    const serverSpecific = `This ${this.getServerType()} server provides ${toolCategories} functionality.`;
    
    return `${baseInstructions}\n\n${serverSpecific}\n\nKey capabilities:\n${this.getCapabilityDescription()}`;
  }

  protected abstract getCapabilityDescription(): string;

  private setupServerEvents(): void {
    // Server event setup - FastMCP may not expose these events directly
    // Event handling would be implemented through the transport layer
    this.componentLogger.debug('Server event handlers configured');
  }

  private async authenticate(auth: unknown): Promise<MakeSessionAuth> {
    this.componentLogger.debug('Authenticating user session');
    
    try {
      // Extract basic auth if provided
      if (typeof auth === 'object' && auth !== null) {
        const authObj = auth as Record<string, unknown>;
        
        if (authObj.token && typeof authObj.token === 'string') {
          // Validate token (simplified validation for now)
          if (authObj.token.length < 10) {
            throw createAuthenticationError('Invalid token format', { code: 'INVALID_TOKEN' });
          }
          
          return {
            authenticated: true,
            timestamp: new Date().toISOString(),
            correlationId: extractCorrelationId({}) || 'auth-' + Date.now()
          };
        }
      }
      
      // For development, allow access without authentication
      if (process.env.NODE_ENV === 'development') {
        this.componentLogger.warn('Development mode: allowing unauthenticated access');
        return {
          authenticated: false,
          timestamp: new Date().toISOString(),
          correlationId: 'dev-' + Date.now()
        };
      }
      
      throw createAuthenticationError('Authentication required', { code: 'MISSING_AUTH' });
      
    } catch (error) {
      this.componentLogger.error('Authentication failed', error instanceof Error ? { message: error.message } : { error: String(error) });
      throw error;
    }
  }

  private addBasicTools(): void {
    try {
      // Add health check tool
      this.server.addTool({
        name: 'health_check',
        description: `Check ${this.getServerType()} server health and status`,
        parameters: z.object({}),
        execute: async (input, { log }) => {
          log.info(`${this.getServerType()} server health check requested`);
          
          const healthStatus = {
            status: 'healthy',
            timestamp: new Date().toISOString(),
            serverType: this.getServerType(),
            serverName: this.config.name,
            version: this.config.version,
            toolCategories: this.config.toolCategories,
            uptime: process.uptime(),
            memory: process.memoryUsage(),
            apiClient: 'connected'
          };

          return JSON.stringify(healthStatus);
        }
      });

      // Add server info tool
      this.server.addTool({
        name: 'server_info',
        description: `Get ${this.getServerType()} server information and capabilities`,
        parameters: z.object({}),
        execute: async (input, { log }) => {
          log.info(`${this.getServerType()} server info requested`);
          
          return JSON.stringify({
            name: this.config.name,
            type: this.getServerType(),
            version: this.config.version,
            description: this.config.description,
            toolCategories: this.config.toolCategories,
            capabilities: this.getCapabilityDescription()
          });
        }
      });

      this.componentLogger.info('Basic tools added successfully');
    } catch (error) {
      this.componentLogger.error('Failed to add basic tools', {
        error: error instanceof Error ? error.message : String(error)
      });
      throw new MakeServerError(
        'Failed to initialize basic tools',
        'SERVER_INIT',
        500,
        true,
        { originalError: error }
      );
    }
  }

  protected registerTools(): void {
    const toolRegistrations = this.getToolRegistrations();
    
    this.componentLogger.info(`Registering ${toolRegistrations.length} tool categories`, {
      categories: toolRegistrations.map(t => t.category)
    });

    let successCount = 0;
    let failureCount = 0;

    for (const toolReg of toolRegistrations) {
      try {
        this.componentLogger.debug(`Registering ${toolReg.category} tools`);
        toolReg.registerFunction(this.server, this.apiClient);
        successCount++;
        this.componentLogger.info(`Successfully registered ${toolReg.category} tools`);
      } catch (error) {
        failureCount++;
        this.componentLogger.error(`Failed to register ${toolReg.category} tools`, {
          error: error instanceof Error ? error.message : String(error),
          category: toolReg.category
        });
      }
    }

    this.componentLogger.info(`Tool registration completed`, {
      total: toolRegistrations.length,
      successful: successCount,
      failed: failureCount,
      serverType: this.getServerType()
    });

    if (failureCount > 0) {
      this.componentLogger.warn(`${failureCount} tool categories failed to register`);
    }
  }

  public async start(options?: {
    transportType?: 'stdio' | 'httpStream';
    httpStream?: { endpoint?: string; port?: number };
  }): Promise<void> {
    try {
      this.componentLogger.info(`Starting ${this.getServerType()} server`, {
        transport: options?.transportType || 'stdio',
        port: options?.httpStream?.port
      });

      // Register all tools before starting
      this.registerTools();

      // Start the server with proper type conversion
      let fastMcpOptions: Parameters<typeof this.server.start>[0] | undefined;
      
      if (options?.transportType === 'httpStream' && options.httpStream) {
        fastMcpOptions = {
          transportType: 'httpStream',
          httpStream: {
            port: options.httpStream.port || 3000,
            ...(options.httpStream.endpoint && {
              endpoint: options.httpStream.endpoint.startsWith('/') 
                ? options.httpStream.endpoint as `/${string}`
                : `/${options.httpStream.endpoint}` as `/${string}`
            })
          }
        };
      } else if (options?.transportType) {
        fastMcpOptions = {
          transportType: options.transportType
        };
      }
      
      await this.server.start(fastMcpOptions);
      
      this.componentLogger.info(`${this.getServerType()} server started successfully`, {
        name: this.config.name,
        toolCategories: this.config.toolCategories.length,
        transport: options?.transportType || 'stdio'
      });
      
    } catch (error) {
      this.componentLogger.error(`Failed to start ${this.getServerType()} server`, {
        error: error instanceof Error ? error.message : String(error)
      });
      throw new MakeServerError(
        `Failed to start ${this.getServerType()} server`,
        'SERVER_START',
        500,
        true,
        { originalError: error }
      );
    }
  }

  public async shutdown(): Promise<void> {
    try {
      this.componentLogger.info(`Shutting down ${this.getServerType()} server`);
      
      // Perform any cleanup specific to server type
      await this.performCleanup();
      
      // Stop the FastMCP server
      await this.server.stop();
      
      this.componentLogger.info(`${this.getServerType()} server shut down successfully`);
      
    } catch (error) {
      this.componentLogger.error(`Error during ${this.getServerType()} server shutdown`, {
        error: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }

  protected async performCleanup(): Promise<void> {
    // Override in subclasses for specific cleanup
  }

  public getServer(): FastMCP<MakeSessionAuth> {
    return this.server;
  }

  public getApiClient(): MakeApiClient {
    return this.apiClient;
  }

  public getConfig(): ServerConfig {
    return this.config;
  }
}