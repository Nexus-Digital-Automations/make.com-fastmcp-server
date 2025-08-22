#!/usr/bin/env node

/**
 * Automated Module Generator
 * Creates complete modular structure with all necessary files
 */

import fs from 'fs';
import path from 'path';
import readline from 'readline';

class ModuleGenerator {
  constructor(basePath = './src/tools') {
    this.basePath = basePath;
  }

  async generateModule(name, options = {}) {
    const {
      tools = [],
      description = '',
      hasTypes = true,
      hasSchemas = true,
      hasServices = true,
      hasUtils = true
    } = options;

    const modulePath = path.join(this.basePath, name);
    
    // Create directory structure
    this.createDirectoryStructure(modulePath, {
      hasTypes,
      hasSchemas,
      hasServices,
      hasUtils
    });

    // Generate files
    if (hasTypes) {
      this.generateTypesFile(modulePath, name, tools);
    }
    
    if (hasSchemas) {
      this.generateSchemasFile(modulePath, name, tools);
    }

    this.generateCoreFile(modulePath, name, tools, description);
    
    if (hasServices) {
      this.generateServicesFile(modulePath, name);
    }
    
    if (hasUtils) {
      this.generateUtilsFile(modulePath, name);
    }

    this.generateToolsFile(modulePath, name, tools);
    this.generateIndexFile(modulePath, name, { hasTypes, hasSchemas, hasServices, hasUtils });
    this.generateTestFile(modulePath, name, tools);

    console.log(`✅ Module '${name}' generated successfully at ${modulePath}`);
    this.printModuleStructure(modulePath);
    
    return modulePath;
  }

  createDirectoryStructure(modulePath, options) {
    const { hasTypes, hasSchemas, hasServices, hasUtils } = options;

    // Create main module directory
    fs.mkdirSync(modulePath, { recursive: true });

    // Create subdirectories
    if (hasTypes) fs.mkdirSync(path.join(modulePath, 'types'), { recursive: true });
    if (hasSchemas) fs.mkdirSync(path.join(modulePath, 'schemas'), { recursive: true });
    fs.mkdirSync(path.join(modulePath, 'core'), { recursive: true });
    if (hasServices) fs.mkdirSync(path.join(modulePath, 'services'), { recursive: true });
    if (hasUtils) fs.mkdirSync(path.join(modulePath, 'utils'), { recursive: true });
    fs.mkdirSync(path.join(modulePath, 'tools'), { recursive: true });

    console.log(`📁 Directory structure created for ${path.basename(modulePath)}`);
  }

  generateTypesFile(modulePath, name, tools) {
    const content = `/**
 * TypeScript type definitions for ${name} module
 * Generated on ${new Date().toISOString()}
 */

import type { ToolContext } from '../../types/index.js';

// Base interfaces for ${name} functionality
export interface ${this.toPascalCase(name)}Config {
  enabled: boolean;
  settings: Record<string, unknown>;
  metadata?: {
    version: string;
    createdAt: Date;
    updatedAt?: Date;
  };
}

export interface ${this.toPascalCase(name)}Context extends ToolContext {
  config: ${this.toPascalCase(name)}Config;
  // Add module-specific context properties
}

export interface ${this.toPascalCase(name)}Result {
  success: boolean;
  data?: unknown;
  message?: string;
  errors?: string[];
  metadata?: {
    operationId: string;
    timestamp: Date;
    duration?: number;
  };
}

// Tool-specific interfaces
${tools.map(tool => `
export interface ${this.toPascalCase(tool)}Request {
  // Define request structure for ${tool}
  [key: string]: unknown;
}

export interface ${this.toPascalCase(tool)}Response extends ${this.toPascalCase(name)}Result {
  // Define response structure for ${tool}
}
`).join('')}

// Event types for module communication
export type ${this.toPascalCase(name)}Event = 
${tools.map(tool => `  | { type: '${tool.replace(/([A-Z])/g, '_$1').toLowerCase()}'; payload: ${this.toPascalCase(tool)}Request }`).join('\n')}
  | { type: 'module_error'; payload: { error: string; context?: unknown } };

// Module state interface
export interface ${this.toPascalCase(name)}State {
  initialized: boolean;
  config: ${this.toPascalCase(name)}Config;
  statistics: {
    totalOperations: number;
    successfulOperations: number;
    failedOperations: number;
    lastOperation?: Date;
  };
}
`;

    fs.writeFileSync(path.join(modulePath, 'types', 'index.ts'), content);
    console.log(`✅ Generated types/index.ts`);
  }

  generateSchemasFile(modulePath, name, tools) {
    const content = `/**
 * Zod validation schemas for ${name} module
 * Generated on ${new Date().toISOString()}
 */

import { z } from 'zod';

// Base schemas
export const ${this.toCamelCase(name)}ConfigSchema = z.object({
  enabled: z.boolean(),
  settings: z.record(z.unknown()),
  metadata: z.object({
    version: z.string(),
    createdAt: z.date(),
    updatedAt: z.date().optional()
  }).optional()
});

export const ${this.toCamelCase(name)}ResultSchema = z.object({
  success: z.boolean(),
  data: z.unknown().optional(),
  message: z.string().optional(),
  errors: z.array(z.string()).optional(),
  metadata: z.object({
    operationId: z.string(),
    timestamp: z.date(),
    duration: z.number().optional()
  }).optional()
});

// Tool-specific schemas
${tools.map(tool => `
export const ${this.toCamelCase(tool)}RequestSchema = z.object({
  // Define validation schema for ${tool} request
});

export const ${this.toCamelCase(tool)}ResponseSchema = ${this.toCamelCase(name)}ResultSchema.extend({
  // Extend with tool-specific response validation
});
`).join('')}

// Validation helper functions
export const validate${this.toPascalCase(name)}Config = (data: unknown) => {
  return ${this.toCamelCase(name)}ConfigSchema.parse(data);
};

export const validate${this.toPascalCase(name)}Result = (data: unknown) => {
  return ${this.toCamelCase(name)}ResultSchema.parse(data);
};

${tools.map(tool => `
export const validate${this.toPascalCase(tool)}Request = (data: unknown) => {
  return ${this.toCamelCase(tool)}RequestSchema.parse(data);
};

export const validate${this.toPascalCase(tool)}Response = (data: unknown) => {
  return ${this.toCamelCase(tool)}ResponseSchema.parse(data);
};
`).join('')}
`;

    fs.writeFileSync(path.join(modulePath, 'schemas', 'index.ts'), content);
    console.log(`✅ Generated schemas/index.ts`);
  }

  generateCoreFile(modulePath, name, tools, description) {
    const content = `/**
 * Core business logic for ${name} module
 * ${description}
 * Generated on ${new Date().toISOString()}
 */

import type { 
  ${this.toPascalCase(name)}Config,
  ${this.toPascalCase(name)}Context,
  ${this.toPascalCase(name)}Result,
  ${this.toPascalCase(name)}State,
  ${this.toPascalCase(name)}Event
} from '../types/index.js';

import { 
  validate${this.toPascalCase(name)}Config,
  validate${this.toPascalCase(name)}Result
} from '../schemas/index.js';

import logger from '../../../lib/logger.js';

/**
 * Core ${name} module class
 * Handles all business logic and state management
 */
export class ${this.toPascalCase(name)}Manager {
  private state: ${this.toPascalCase(name)}State;
  private context: ${this.toPascalCase(name)}Context;

  constructor(context: ${this.toPascalCase(name)}Context) {
    this.context = context;
    this.state = {
      initialized: false,
      config: context.config,
      statistics: {
        totalOperations: 0,
        successfulOperations: 0,
        failedOperations: 0
      }
    };
  }

  /**
   * Initialize the ${name} module
   */
  async initialize(): Promise<${this.toPascalCase(name)}Result> {
    try {
      // Validate configuration
      validate${this.toPascalCase(name)}Config(this.context.config);

      // Perform initialization logic
      await this.setupModule();

      this.state.initialized = true;
      
      logger.info(\`${this.toPascalCase(name)} module initialized successfully\`, {
        module: '${name}',
        config: this.context.config
      });

      return {
        success: true,
        message: '${this.toPascalCase(name)} module initialized successfully',
        metadata: {
          operationId: this.generateOperationId(),
          timestamp: new Date()
        }
      };
    } catch (error) {
      logger.error(\`Failed to initialize ${name} module\`, {
        error: error instanceof Error ? error.message : String(error),
        module: '${name}'
      });

      return {
        success: false,
        message: 'Failed to initialize ${name} module',
        errors: [error instanceof Error ? error.message : String(error)],
        metadata: {
          operationId: this.generateOperationId(),
          timestamp: new Date()
        }
      };
    }
  }

  /**
   * Setup module-specific initialization logic
   */
  private async setupModule(): Promise<void> {
    // Implement module-specific setup logic here
    // This might include:
    // - Setting up database connections
    // - Initializing external service clients
    // - Loading configuration data
    // - Setting up event listeners
  }

${tools.map(tool => `
  /**
   * ${tool} operation handler
   */
  async ${this.toCamelCase(tool)}(request: unknown): Promise<${this.toPascalCase(name)}Result> {
    const operationId = this.generateOperationId();
    const startTime = Date.now();

    try {
      this.incrementStatistics('total');

      // Validate request
      // const validRequest = validate${this.toPascalCase(tool)}Request(request);

      logger.info(\`Starting ${tool} operation\`, {
        operationId,
        module: '${name}',
        operation: '${tool}'
      });

      // Implement ${tool} business logic here
      const result = await this.execute${this.toPascalCase(tool)}(request);

      this.incrementStatistics('successful');

      logger.info(\`${tool} operation completed successfully\`, {
        operationId,
        module: '${name}',
        operation: '${tool}',
        duration: Date.now() - startTime
      });

      return {
        success: true,
        data: result,
        message: '${tool} completed successfully',
        metadata: {
          operationId,
          timestamp: new Date(),
          duration: Date.now() - startTime
        }
      };
    } catch (error) {
      this.incrementStatistics('failed');

      logger.error(\`${tool} operation failed\`, {
        operationId,
        module: '${name}',
        operation: '${tool}',
        error: error instanceof Error ? error.message : String(error),
        duration: Date.now() - startTime
      });

      return {
        success: false,
        message: \`${tool} operation failed\`,
        errors: [error instanceof Error ? error.message : String(error)],
        metadata: {
          operationId,
          timestamp: new Date(),
          duration: Date.now() - startTime
        }
      };
    }
  }

  /**
   * Execute ${tool} business logic
   */
  private async execute${this.toPascalCase(tool)}(request: unknown): Promise<unknown> {
    // TODO: Implement ${tool} business logic
    // This is where the core functionality for ${tool} would be implemented
    
    throw new Error('${tool} implementation not yet completed');
  }
`).join('')}

  /**
   * Get current module state
   */
  getState(): ${this.toPascalCase(name)}State {
    return { ...this.state };
  }

  /**
   * Get module statistics
   */
  getStatistics() {
    return { ...this.state.statistics };
  }

  /**
   * Handle module events
   */
  async handleEvent(event: ${this.toPascalCase(name)}Event): Promise<${this.toPascalCase(name)}Result> {
    try {
      switch (event.type) {
${tools.map(tool => `        case '${tool.replace(/([A-Z])/g, '_$1').toLowerCase()}':
          return await this.${this.toCamelCase(tool)}(event.payload);`).join('\n')}
        
        case 'module_error':
          logger.error('Module error event received', {
            module: '${name}',
            error: event.payload.error,
            context: event.payload.context
          });
          return {
            success: false,
            message: 'Module error handled',
            errors: [event.payload.error],
            metadata: {
              operationId: this.generateOperationId(),
              timestamp: new Date()
            }
          };

        default:
          throw new Error(\`Unknown event type: \${(event as any).type}\`);
      }
    } catch (error) {
      logger.error('Failed to handle event', {
        module: '${name}',
        event: event.type,
        error: error instanceof Error ? error.message : String(error)
      });

      return {
        success: false,
        message: 'Failed to handle event',
        errors: [error instanceof Error ? error.message : String(error)],
        metadata: {
          operationId: this.generateOperationId(),
          timestamp: new Date()
        }
      };
    }
  }

  /**
   * Shutdown the module gracefully
   */
  async shutdown(): Promise<void> {
    logger.info(\`Shutting down ${name} module\`, {
      module: '${name}',
      statistics: this.state.statistics
    });

    // Implement cleanup logic here
    // - Close database connections
    // - Clean up resources
    // - Save state if needed

    this.state.initialized = false;
  }

  /**
   * Generate unique operation ID
   */
  private generateOperationId(): string {
    return \`${name}_\${Date.now()}_\${Math.random().toString(36).substr(2, 9)}\`;
  }

  /**
   * Increment operation statistics
   */
  private incrementStatistics(type: 'total' | 'successful' | 'failed'): void {
    switch (type) {
      case 'total':
        this.state.statistics.totalOperations++;
        this.state.statistics.lastOperation = new Date();
        break;
      case 'successful':
        this.state.statistics.successfulOperations++;
        break;
      case 'failed':
        this.state.statistics.failedOperations++;
        break;
    }
  }
}
`;

    fs.writeFileSync(path.join(modulePath, 'core', 'index.ts'), content);
    console.log(`✅ Generated core/index.ts`);
  }

  generateServicesFile(modulePath, name) {
    const content = `/**
 * External service integrations for ${name} module
 * Generated on ${new Date().toISOString()}
 */

import logger from '../../../lib/logger.js';

/**
 * Service client for external integrations
 */
export class ${this.toPascalCase(name)}ServiceClient {
  private baseUrl: string;
  private headers: Record<string, string>;

  constructor(baseUrl: string, apiKey?: string) {
    this.baseUrl = baseUrl;
    this.headers = {
      'Content-Type': 'application/json',
      'User-Agent': 'Make-FastMCP-${this.toPascalCase(name)}/1.0'
    };

    if (apiKey) {
      this.headers['Authorization'] = \`Bearer \${apiKey}\`;
    }
  }

  /**
   * Make HTTP request to external service
   */
  async makeRequest(endpoint: string, options: {
    method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
    data?: unknown;
    params?: Record<string, string>;
  } = {}): Promise<unknown> {
    const { method = 'GET', data, params } = options;

    try {
      const url = new URL(endpoint, this.baseUrl);
      
      if (params) {
        Object.entries(params).forEach(([key, value]) => {
          url.searchParams.append(key, value);
        });
      }

      const response = await fetch(url.toString(), {
        method,
        headers: this.headers,
        body: data ? JSON.stringify(data) : undefined
      });

      if (!response.ok) {
        throw new Error(\`HTTP \${response.status}: \${response.statusText}\`);
      }

      const result = await response.json();
      
      logger.debug('External service request completed', {
        module: '${name}',
        endpoint,
        method,
        status: response.status
      });

      return result;
    } catch (error) {
      logger.error('External service request failed', {
        module: '${name}',
        endpoint,
        method,
        error: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }

  /**
   * Health check for external service
   */
  async healthCheck(): Promise<boolean> {
    try {
      await this.makeRequest('/health');
      return true;
    } catch (error) {
      logger.warn('External service health check failed', {
        module: '${name}',
        error: error instanceof Error ? error.message : String(error)
      });
      return false;
    }
  }
}

/**
 * Factory function to create service client
 */
export function create${this.toPascalCase(name)}ServiceClient(): ${this.toPascalCase(name)}ServiceClient {
  const baseUrl = process.env.${name.toUpperCase()}_SERVICE_URL || 'http://localhost:3000';
  const apiKey = process.env.${name.toUpperCase()}_API_KEY;
  
  return new ${this.toPascalCase(name)}ServiceClient(baseUrl, apiKey);
}
`;

    fs.writeFileSync(path.join(modulePath, 'services', 'index.ts'), content);
    console.log(`✅ Generated services/index.ts`);
  }

  generateUtilsFile(modulePath, name) {
    const content = `/**
 * Utility functions for ${name} module
 * Generated on ${new Date().toISOString()}
 */

import type { ${this.toPascalCase(name)}Result } from '../types/index.js';

/**
 * Create a standardized success result
 */
export function createSuccessResult(data?: unknown, message?: string): ${this.toPascalCase(name)}Result {
  return {
    success: true,
    data,
    message: message || 'Operation completed successfully',
    metadata: {
      operationId: generateOperationId('${name}'),
      timestamp: new Date()
    }
  };
}

/**
 * Create a standardized error result
 */
export function createErrorResult(error: string | Error, data?: unknown): ${this.toPascalCase(name)}Result {
  const errorMessage = error instanceof Error ? error.message : error;
  
  return {
    success: false,
    data,
    message: 'Operation failed',
    errors: [errorMessage],
    metadata: {
      operationId: generateOperationId('${name}'),
      timestamp: new Date()
    }
  };
}

/**
 * Generate unique operation ID
 */
export function generateOperationId(prefix = '${name}'): string {
  return \`\${prefix}_\${Date.now()}_\${Math.random().toString(36).substr(2, 9)}\`;
}

/**
 * Safe JSON parsing with error handling
 */
export function safeJsonParse<T = unknown>(json: string, defaultValue?: T): T | undefined {
  try {
    return JSON.parse(json) as T;
  } catch (error) {
    return defaultValue;
  }
}

/**
 * Deep clone object safely
 */
export function deepClone<T>(obj: T): T {
  if (obj === null || typeof obj !== 'object') {
    return obj;
  }

  if (obj instanceof Date) {
    return new Date(obj.getTime()) as T;
  }

  if (obj instanceof Array) {
    return obj.map(item => deepClone(item)) as T;
  }

  if (typeof obj === 'object') {
    const cloned = {} as T;
    Object.keys(obj).forEach(key => {
      (cloned as any)[key] = deepClone((obj as any)[key]);
    });
    return cloned;
  }

  return obj;
}

/**
 * Retry async operation with exponential backoff
 */
export async function retryOperation<T>(
  operation: () => Promise<T>,
  options: {
    maxRetries?: number;
    baseDelay?: number;
    maxDelay?: number;
    backoffMultiplier?: number;
  } = {}
): Promise<T> {
  const {
    maxRetries = 3,
    baseDelay = 1000,
    maxDelay = 10000,
    backoffMultiplier = 2
  } = options;

  let lastError: Error;
  
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      
      if (attempt === maxRetries) {
        throw lastError;
      }

      const delay = Math.min(baseDelay * Math.pow(backoffMultiplier, attempt), maxDelay);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  throw lastError!;
}

/**
 * Validate required environment variables
 */
export function validateEnvironmentVariables(requiredVars: string[]): void {
  const missing = requiredVars.filter(varName => !process.env[varName]);
  
  if (missing.length > 0) {
    throw new Error(\`Missing required environment variables: \${missing.join(', ')}\`);
  }
}

/**
 * Sanitize sensitive data for logging
 */
export function sanitizeForLogging(data: unknown): unknown {
  if (typeof data !== 'object' || data === null) {
    return data;
  }

  const sensitiveKeys = ['password', 'token', 'key', 'secret', 'auth', 'credential'];
  const sanitized = deepClone(data);

  function sanitizeObject(obj: any): void {
    if (typeof obj !== 'object' || obj === null) return;

    Object.keys(obj).forEach(key => {
      const lowerKey = key.toLowerCase();
      
      if (sensitiveKeys.some(sensitive => lowerKey.includes(sensitive))) {
        obj[key] = '[REDACTED]';
      } else if (typeof obj[key] === 'object') {
        sanitizeObject(obj[key]);
      }
    });
  }

  sanitizeObject(sanitized);
  return sanitized;
}
`;

    fs.writeFileSync(path.join(modulePath, 'utils', 'index.ts'), content);
    console.log(`✅ Generated utils/index.ts`);
  }

  generateToolsFile(modulePath, name, tools) {
    const content = `/**
 * FastMCP tool implementations for ${name} module
 * Generated on ${new Date().toISOString()}
 */

import type { FastMCPToolContext } from '../../../types/index.js';
import type { ${this.toPascalCase(name)}Context } from '../types/index.js';
import { ${this.toPascalCase(name)}Manager } from '../core/index.js';
import logger from '../../../lib/logger.js';

/**
 * Initialize ${name} module manager
 */
function create${this.toPascalCase(name)}Manager(context: FastMCPToolContext): ${this.toPascalCase(name)}Manager {
  const ${this.toCamelCase(name)}Context: ${this.toPascalCase(name)}Context = {
    ...context,
    config: {
      enabled: true,
      settings: {
        // Add default settings here
      },
      metadata: {
        version: '1.0.0',
        createdAt: new Date()
      }
    }
  };

  return new ${this.toPascalCase(name)}Manager(${this.toCamelCase(name)}Context);
}

${tools.map(tool => `
/**
 * ${tool} FastMCP tool
 */
export async function ${this.toCamelCase(tool)}(context: FastMCPToolContext, args: Record<string, unknown>) {
  const manager = create${this.toPascalCase(name)}Manager(context);
  
  try {
    // Initialize manager if not already done
    const initResult = await manager.initialize();
    if (!initResult.success) {
      return {
        error: 'Failed to initialize ${name} manager',
        details: initResult.errors
      };
    }

    logger.info('${tool} tool called', {
      tool: '${tool}',
      module: '${name}',
      args: Object.keys(args)
    });

    // Execute the operation
    const result = await manager.${this.toCamelCase(tool)}(args);
    
    if (!result.success) {
      return {
        error: result.message || '${tool} operation failed',
        details: result.errors
      };
    }

    return {
      success: true,
      message: result.message,
      data: result.data,
      metadata: result.metadata
    };
  } catch (error) {
    logger.error('${tool} tool error', {
      tool: '${tool}',
      module: '${name}',
      error: error instanceof Error ? error.message : String(error)
    });

    return {
      error: 'Internal error in ${tool} tool',
      details: error instanceof Error ? error.message : String(error)
    };
  } finally {
    await manager.shutdown();
  }
}

${this.toCamelCase(tool)}.metadata = {
  name: '${tool.replace(/([A-Z])/g, '-$1').toLowerCase()}',
  description: 'Execute ${tool} operation in ${name} module',
  parameters: {
    type: 'object',
    properties: {
      // Define tool parameters here
      // Example:
      // id: { type: 'string', description: 'Resource identifier' },
      // options: { type: 'object', description: 'Additional options' }
    },
    required: [
      // List required parameters
    ]
  }
};
`).join('')}

// Export all tools
export const ${this.toCamelCase(name)}Tools = {
${tools.map(tool => `  ${this.toCamelCase(tool)}`).join(',\n')}
};
`;

    fs.writeFileSync(path.join(modulePath, 'tools', 'index.ts'), content);
    console.log(`✅ Generated tools/index.ts`);
  }

  generateIndexFile(modulePath, name, options) {
    const { hasTypes, hasSchemas, hasServices, hasUtils } = options;

    const content = `/**
 * ${name} module entry point
 * Generated on ${new Date().toISOString()}
 */

// Export all module components
${hasTypes ? `export * from './types/index.js';` : ''}
${hasSchemas ? `export * from './schemas/index.js';` : ''}
export * from './core/index.js';
${hasServices ? `export * from './services/index.js';` : ''}
${hasUtils ? `export * from './utils/index.js';` : ''}
export * from './tools/index.js';

// Default export
export { ${this.toPascalCase(name)}Manager } from './core/index.js';
export { ${this.toCamelCase(name)}Tools } from './tools/index.js';

// Module metadata
export const moduleInfo = {
  name: '${name}',
  version: '1.0.0',
  description: 'Modular ${name} implementation for FastMCP server',
  generatedAt: '${new Date().toISOString()}',
  components: {
    types: ${hasTypes},
    schemas: ${hasSchemas},
    core: true,
    services: ${hasServices},
    utils: ${hasUtils},
    tools: true
  }
};
`;

    fs.writeFileSync(path.join(modulePath, 'index.ts'), content);
    console.log(`✅ Generated index.ts`);
  }

  generateTestFile(modulePath, name, tools) {
    const testDir = path.join(modulePath, '__tests__');
    fs.mkdirSync(testDir, { recursive: true });

    const content = `/**
 * Test suite for ${name} module
 * Generated on ${new Date().toISOString()}
 */

import { ${this.toPascalCase(name)}Manager } from '../core/index.js';
import type { ${this.toPascalCase(name)}Context } from '../types/index.js';

// Mock context for testing
const mockContext: ${this.toPascalCase(name)}Context = {
  config: {
    enabled: true,
    settings: {},
    metadata: {
      version: '1.0.0',
      createdAt: new Date()
    }
  },
  // Add other required context properties
} as any;

describe('${this.toPascalCase(name)}Manager', () => {
  let manager: ${this.toPascalCase(name)}Manager;

  beforeEach(() => {
    manager = new ${this.toPascalCase(name)}Manager(mockContext);
  });

  afterEach(async () => {
    await manager.shutdown();
  });

  describe('Initialization', () => {
    it('should initialize successfully', async () => {
      const result = await manager.initialize();
      
      expect(result.success).toBe(true);
      expect(result.message).toContain('initialized successfully');
    });

    it('should have correct initial state', () => {
      const state = manager.getState();
      
      expect(state.initialized).toBe(false);
      expect(state.statistics.totalOperations).toBe(0);
      expect(state.statistics.successfulOperations).toBe(0);
      expect(state.statistics.failedOperations).toBe(0);
    });
  });

${tools.map(tool => `
  describe('${tool}', () => {
    beforeEach(async () => {
      await manager.initialize();
    });

    it('should handle ${tool} request', async () => {
      const request = {
        // Add test request data
      };

      const result = await manager.${this.toCamelCase(tool)}(request);
      
      // Note: This will fail until implementation is complete
      expect(result.success).toBe(false);
      expect(result.errors).toContain('${tool} implementation not yet completed');
    });

    it('should update statistics after ${tool} operation', async () => {
      const request = {};
      const initialStats = manager.getStatistics();

      await manager.${this.toCamelCase(tool)}(request);

      const updatedStats = manager.getStatistics();
      expect(updatedStats.totalOperations).toBe(initialStats.totalOperations + 1);
    });
  });
`).join('')}

  describe('Event Handling', () => {
    beforeEach(async () => {
      await manager.initialize();
    });

    it('should handle unknown event type', async () => {
      const unknownEvent = { type: 'unknown_event', payload: {} } as any;
      
      const result = await manager.handleEvent(unknownEvent);
      
      expect(result.success).toBe(false);
      expect(result.message).toContain('Failed to handle event');
    });
  });

  describe('Statistics', () => {
    it('should provide statistics', () => {
      const stats = manager.getStatistics();
      
      expect(stats).toHaveProperty('totalOperations');
      expect(stats).toHaveProperty('successfulOperations');
      expect(stats).toHaveProperty('failedOperations');
    });
  });
});

// Tool integration tests
describe('${this.toPascalCase(name)} Tools', () => {
  const mockContext = {
    // Add mock FastMCP context
  } as any;

${tools.map(tool => `
  describe('${this.toCamelCase(tool)} tool', () => {
    it('should be defined', async () => {
      const { ${this.toCamelCase(tool)} } = await import('../tools/index.js');
      expect(${this.toCamelCase(tool)}).toBeDefined();
      expect(typeof ${this.toCamelCase(tool)}).toBe('function');
    });

    it('should have correct metadata', async () => {
      const { ${this.toCamelCase(tool)} } = await import('../tools/index.js');
      expect(${this.toCamelCase(tool)}.metadata).toBeDefined();
      expect(${this.toCamelCase(tool)}.metadata.name).toBe('${tool.replace(/([A-Z])/g, '-$1').toLowerCase()}');
    });
  });
`).join('')}
});
`;

    fs.writeFileSync(path.join(testDir, `${name}.test.ts`), content);
    console.log(`✅ Generated __tests__/${name}.test.ts`);
  }

  printModuleStructure(modulePath) {
    console.log(`\n📁 Module structure created:\n`);
    
    const printDirectory = (dirPath, indent = '') => {
      const items = fs.readdirSync(dirPath, { withFileTypes: true });
      items.forEach((item, index) => {
        const isLast = index === items.length - 1;
        const prefix = indent + (isLast ? '└── ' : '├── ');
        const fullPath = path.join(dirPath, item.name);
        
        console.log(`${prefix}${item.name}`);
        
        if (item.isDirectory() && !item.name.startsWith('.')) {
          const newIndent = indent + (isLast ? '    ' : '│   ');
          printDirectory(fullPath, newIndent);
        }
      });
    };

    printDirectory(modulePath);
    console.log('');
  }

  // Interactive CLI
  async runInteractiveGenerator() {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });

    const question = (prompt) => new Promise((resolve) => {
      rl.question(prompt, resolve);
    });

    try {
      console.log('🚀 Interactive Module Generator\n');
      
      const name = await question('Module name (e.g., folders, billing): ');
      const description = await question('Description (optional): ');
      const toolsInput = await question('Tools (comma-separated, e.g., listFolders,createFolder): ');
      
      const tools = toolsInput.split(',').map(t => t.trim()).filter(t => t.length > 0);
      
      const hasTypes = (await question('Include types? (Y/n): ')).toLowerCase() !== 'n';
      const hasSchemas = (await question('Include schemas? (Y/n): ')).toLowerCase() !== 'n';
      const hasServices = (await question('Include services? (Y/n): ')).toLowerCase() !== 'n';
      const hasUtils = (await question('Include utils? (Y/n): ')).toLowerCase() !== 'n';

      console.log('\n🔄 Generating module...\n');

      await this.generateModule(name, {
        tools,
        description,
        hasTypes,
        hasSchemas,
        hasServices,
        hasUtils
      });

      console.log('\n✨ Module generation complete!');
      console.log('\n📋 Next steps:');
      console.log('1. Review the generated code');
      console.log('2. Implement the core business logic');
      console.log('3. Update the tool parameter definitions');
      console.log('4. Run tests to verify the module works');
      console.log('5. Register the tools in your main server file');

    } finally {
      rl.close();
    }
  }

  // Utility methods
  toPascalCase(str) {
    return str
      .split(/[-_\s]/)
      .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
      .join('');
  }

  toCamelCase(str) {
    const pascal = this.toPascalCase(str);
    return pascal.charAt(0).toLowerCase() + pascal.slice(1);
  }
}

// CLI Interface
const generator = new ModuleGenerator();
const args = process.argv.slice(2);

if (args.length === 0) {
  // Interactive mode
  generator.runInteractiveGenerator().catch(console.error);
} else {
  // Command line mode
  let name = args[0];
  let tools = [];
  let description = '';

  // Parse arguments
  for (let i = 1; i < args.length; i++) {
    if (args[i] === '--tools' && args[i + 1]) {
      tools = args[i + 1].split(',').map(t => t.trim());
      i++;
    } else if (args[i] === '--description' && args[i + 1]) {
      description = args[i + 1];
      i++;
    }
  }

  generator.generateModule(name, { tools, description }).catch(console.error);
}

export default ModuleGenerator;