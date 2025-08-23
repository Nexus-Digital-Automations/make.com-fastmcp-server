/**
 * Error Boundary Integration Examples
 * Shows how to integrate async error boundaries into existing FastMCP server code
 */

import { AsyncErrorBoundary, serverBoundary, databaseBoundary, apiBoundary, ResourceCleanup, WithErrorBoundary } from '../utils/async-error-boundary.js';
import { MakeApiClient } from '../lib/make-api-client.js';
import logger from '../lib/logger.js';

/**
 * Example 1: Server initialization with error boundary and resource cleanup
 */
export class ServerManager {
  private boundary: AsyncErrorBoundary;
  private apiClients = new Map<string, MakeApiClient>();
  private activeConnections = new Set<any>();

  constructor() {
    this.boundary = new AsyncErrorBoundary({
      name: 'ServerManager',
      retryAttempts: 2,
      retryDelayMs: 1000,
      onError: async (error, context) => {
        logger.error('Server operation failed', {
          operation: context.operation,
          attempt: context.attempt,
          error: error.message
        });
        
        // Custom error handling - maybe notify monitoring service
        await this.notifyMonitoring(error, context);
      }
    });
  }

  /**
   * Start server with comprehensive error handling
   */
  async startServer(): Promise<void> {
    await this.boundary.execute(
      async () => {
        // Register server cleanup resource
        const serverCleanup: ResourceCleanup = {
          name: 'server-instance',
          cleanup: async () => {
            logger.info('Cleaning up server instance...');
            await this.shutdownServer();
          },
          priority: 'high',
          timeout: 10000
        };

        this.boundary.registerResource(serverCleanup);

        // Initialize server components
        await this.initializeComponents();
        await this.startHttpServer();
        await this.registerMcpTools();
        
        logger.info('Server started successfully');
      },
      { operation: 'startServer' }
    );
  }

  /**
   * Add API client with automatic cleanup
   */
  async addApiClient(token: string, clientId: string): Promise<MakeApiClient> {
    return this.boundary.execute(
      async () => {
        const client = new MakeApiClient(token);
        
        // Test connection
        await client.testConnection();
        
        this.apiClients.set(clientId, client);
        
        // Register client cleanup
        const clientCleanup: ResourceCleanup = {
          name: `api-client-${clientId}`,
          cleanup: async () => {
            logger.info(`Cleaning up API client ${clientId}...`);
            if (this.apiClients.has(clientId)) {
              const client = this.apiClients.get(clientId)!;
              await client.disconnect?.();
              this.apiClients.delete(clientId);
            }
          },
          priority: 'medium',
          timeout: 5000
        };

        this.boundary.registerResource(clientCleanup);
        
        return client;
      },
      { operation: 'addApiClient', metadata: { clientId } }
    );
  }

  private async initializeComponents(): Promise<void> {
    // Component initialization logic
  }

  private async startHttpServer(): Promise<void> {
    // HTTP server start logic
  }

  private async registerMcpTools(): Promise<void> {
    // MCP tools registration logic
  }

  private async shutdownServer(): Promise<void> {
    // Server shutdown logic
  }

  private async notifyMonitoring(error: Error, context: any): Promise<void> {
    // Monitoring notification logic
  }
}

/**
 * Example 2: Database operations with error boundaries
 */
export class DatabaseManager {
  @WithErrorBoundary('DatabaseConnection', {
    retryAttempts: 3,
    retryDelayMs: 2000,
    timeout: 30000
  })
  async connectToDatabase(): Promise<any> {
    // Database connection logic
    logger.info('Connecting to database...');
    
    // Simulate connection
    await new Promise(resolve => setTimeout(resolve, 100));
    
    return { connected: true };
  }

  /**
   * Execute database query with resource management
   */
  async executeQuery<T>(query: string, params?: any[]): Promise<T> {
    return databaseBoundary.withResource(
      {
        name: `query-${Date.now()}`,
        cleanup: async () => {
          logger.debug('Cleaning up database query resources');
          // Close cursors, release locks, etc.
        },
        priority: 'high',
        timeout: 5000
      },
      async () => {
        logger.debug('Executing database query', { query: query.substring(0, 100) });
        
        // Simulate query execution
        await new Promise(resolve => setTimeout(resolve, 50));
        
        return { rows: [] } as T;
      }
    );
  }
}

/**
 * Example 3: API operations with circuit breaker pattern
 */
export class ApiManager {
  private circuitBreakerBoundary: AsyncErrorBoundary;

  constructor() {
    this.circuitBreakerBoundary = new AsyncErrorBoundary({
      name: 'ApiCircuitBreaker',
      retryAttempts: 3,
      retryDelayMs: 1000,
      timeout: 30000,
      onError: async (error, context) => {
        // Circuit breaker logic - track failures
        logger.warn('API operation failed, circuit breaker triggered', {
          operation: context.operation,
          attempt: context.attempt,
          error: error.message
        });
      },
      fallback: async () => {
        // Return cached data or safe default
        logger.info('Circuit breaker fallback activated');
        return { data: null, fromCache: true };
      }
    });
  }

  async makeApiCall(endpoint: string, data?: any): Promise<any> {
    return this.circuitBreakerBoundary.execute(
      async () => {
        // Register API call resource for cleanup
        const requestCleanup: ResourceCleanup = {
          name: `api-request-${endpoint}`,
          cleanup: async () => {
            logger.debug('Cleaning up API request resources', { endpoint });
            // Cancel ongoing requests, cleanup connections
          },
          priority: 'medium',
          timeout: 3000
        };

        return this.circuitBreakerBoundary.withResource(requestCleanup, async () => {
          logger.debug('Making API call', { endpoint });
          
          // Simulate API call
          if (Math.random() < 0.2) { // 20% failure rate for demo
            throw new Error('API call failed');
          }
          
          await new Promise(resolve => setTimeout(resolve, 100));
          return { data: 'success', endpoint };
        });
      },
      { operation: 'apiCall', metadata: { endpoint, dataSize: JSON.stringify(data || {}).length } }
    );
  }
}

/**
 * Example 4: File operations with proper resource management
 */
export class FileManager {
  async processFile(filePath: string): Promise<void> {
    return fileBoundary.withResource(
      {
        name: `file-${filePath}`,
        cleanup: async () => {
          logger.debug('Cleaning up file resources', { filePath });
          // Close file handles, cleanup temp files, etc.
        },
        priority: 'high',
        timeout: 5000
      },
      async () => {
        logger.info('Processing file', { filePath });
        
        // Simulate file processing
        await new Promise(resolve => setTimeout(resolve, 200));
        
        logger.info('File processing completed', { filePath });
      }
    );
  }

  @WithErrorBoundary('FileValidation', {
    retryAttempts: 1,
    timeout: 10000
  })
  async validateFile(filePath: string): Promise<boolean> {
    logger.debug('Validating file', { filePath });
    
    // Simulate validation
    await new Promise(resolve => setTimeout(resolve, 50));
    
    return true;
  }
}

/**
 * Example 5: Comprehensive server integration
 */
export class IntegratedServer {
  private serverManager: ServerManager;
  private databaseManager: DatabaseManager;
  private apiManager: ApiManager;
  private fileManager: FileManager;

  constructor() {
    this.serverManager = new ServerManager();
    this.databaseManager = new DatabaseManager();
    this.apiManager = new ApiManager();
    this.fileManager = new FileManager();
  }

  /**
   * Initialize all components with error boundaries
   */
  async initialize(): Promise<void> {
    await serverBoundary.execute(
      async () => {
        // Initialize all components with their own error boundaries
        await Promise.all([
          this.serverManager.startServer(),
          this.databaseManager.connectToDatabase(),
        ]);

        // Add API client
        await this.serverManager.addApiClient('test-token', 'main-client');

        logger.info('Integrated server initialization completed');
      },
      { operation: 'serverInitialization' }
    );
  }

  /**
   * Process incoming requests with full error handling
   */
  async handleRequest(requestData: any): Promise<any> {
    return serverBoundary.execute(
      async () => {
        // Validate request
        await this.fileManager.validateFile(requestData.filePath);
        
        // Query database
        const dbResult = await this.databaseManager.executeQuery(
          'SELECT * FROM requests WHERE id = ?',
          [requestData.id]
        );

        // Make API call
        const apiResult = await this.apiManager.makeApiCall(
          '/api/process',
          requestData
        );

        // Process file if needed
        if (requestData.filePath) {
          await this.fileManager.processFile(requestData.filePath);
        }

        return {
          success: true,
          dbResult,
          apiResult,
          processedAt: new Date().toISOString()
        };
      },
      { 
        operation: 'handleRequest', 
        metadata: { 
          requestId: requestData.id,
          hasFile: !!requestData.filePath 
        } 
      }
    );
  }
}

/**
 * Example usage and setup
 */
export async function setupErrorBoundaryExample(): Promise<void> {
  // Setup global error handlers
  const { setupGlobalErrorHandlers } = await import('../utils/async-error-boundary.js');
  setupGlobalErrorHandlers();

  // Create integrated server
  const server = new IntegratedServer();
  
  try {
    // Initialize with error boundaries
    await server.initialize();
    
    // Handle sample request
    const result = await server.handleRequest({
      id: 'test-123',
      filePath: '/tmp/test-file.txt',
      data: { message: 'Hello World' }
    });
    
    logger.info('Request handled successfully', { result });
    
  } catch (error) {
    logger.error('Server operation failed', {
      error: error instanceof Error ? error.message : String(error)
    });
  }
}