#!/usr/bin/env node
/**
 * Module Generator Script for Make.com FastMCP Server Refactoring
 * 
 * This script generates a complete modular architecture structure for refactoring
 * large TypeScript files into maintainable, focused modules.
 * 
 * Usage:
 *   node scripts/refactoring/module-generator.js --name <module-name> --tools <tool1,tool2,...>
 * 
 * Example:
 *   node scripts/refactoring/module-generator.js --name folders --tools "list-folders,create-folder,update-folder"
 */

const fs = require('fs').promises;
const path = require('path');
const { execSync } = require('child_process');

class ModuleGenerator {
  constructor() {
    this.projectRoot = process.cwd();
    this.templatesDir = path.join(__dirname, 'templates');
  }

  async generateModule(config) {
    console.log(`🚀 Generating module: ${config.name}`);
    console.log(`📝 Description: ${config.description || 'No description provided'}`);
    console.log(`🔧 Tools: ${config.tools.join(', ')}`);

    try {
      // 1. Create directory structure
      await this.createDirectoryStructure(config);
      
      // 2. Generate template files
      await this.generateTemplateFiles(config);
      
      // 3. Update main exports
      await this.updateMainExports(config);
      
      // 4. Generate test templates
      await this.generateTestTemplates(config);
      
      // 5. Update documentation
      await this.updateDocumentation(config);
      
      // 6. Setup initial git tracking
      await this.setupGitTracking(config);

      console.log(`✅ Module ${config.name} generated successfully!`);
      console.log(`\n📋 Next steps:`);
      console.log(`   1. Implement core logic in src/tools/${config.name}/core/`);
      console.log(`   2. Add tool implementations in src/tools/${config.name}/tools/`);
      console.log(`   3. Write tests in tests/unit/tools/${config.name}/`);
      console.log(`   4. Run: npm run test:${config.name}`);
      console.log(`   5. Run: npm run lint:${config.name}`);

    } catch (error) {
      console.error(`❌ Error generating module ${config.name}:`, error.message);
      throw error;
    }
  }

  async createDirectoryStructure(config) {
    const basePath = path.join(this.projectRoot, 'src', 'tools', config.name);
    
    const directories = [
      basePath,
      path.join(basePath, 'types'),
      path.join(basePath, 'schemas'),
      path.join(basePath, 'core'),
      path.join(basePath, 'services'),
      path.join(basePath, 'utils'),
      path.join(basePath, 'tools'),
      // Test directories
      path.join(this.projectRoot, 'tests', 'unit', 'tools', config.name),
      path.join(this.projectRoot, 'tests', 'integration', 'tools', config.name),
      path.join(this.projectRoot, 'tests', 'performance', 'tools', config.name),
    ];

    for (const dir of directories) {
      await fs.mkdir(dir, { recursive: true });
      console.log(`📁 Created directory: ${path.relative(this.projectRoot, dir)}`);
    }
  }

  async generateTemplateFiles(config) {
    const templates = this.getTemplates(config);
    
    for (const [filePath, content] of Object.entries(templates)) {
      const fullPath = path.join(this.projectRoot, filePath);
      await fs.writeFile(fullPath, content, 'utf8');
      console.log(`📄 Generated file: ${filePath}`);
    }
  }

  getTemplates(config) {
    const moduleName = config.name;
    const moduleNamePascal = this.toPascalCase(moduleName);
    const moduleNameCamel = this.toCamelCase(moduleName);
    const toolCount = config.tools.length;
    const toolCategories = JSON.stringify(['CRUD', 'management', 'utilities']);

    return {
      // Main module index
      [`src/tools/${moduleName}/index.ts`]: this.getIndexTemplate(config),
      
      // Type definitions
      [`src/tools/${moduleName}/types/index.ts`]: this.getTypesIndexTemplate(config),
      [`src/tools/${moduleName}/types/core-types.ts`]: this.getCoreTypesTemplate(config),
      [`src/tools/${moduleName}/types/api-types.ts`]: this.getApiTypesTemplate(config),
      [`src/tools/${moduleName}/types/config-types.ts`]: this.getConfigTypesTemplate(config),
      [`src/tools/${moduleName}/types/validation-types.ts`]: this.getValidationTypesTemplate(config),
      
      // Schemas
      [`src/tools/${moduleName}/schemas/index.ts`]: this.getSchemasIndexTemplate(config),
      [`src/tools/${moduleName}/schemas/input-schemas.ts`]: this.getInputSchemasTemplate(config),
      [`src/tools/${moduleName}/schemas/output-schemas.ts`]: this.getOutputSchemasTemplate(config),
      [`src/tools/${moduleName}/schemas/config-schemas.ts`]: this.getConfigSchemasTemplate(config),
      
      // Core logic
      [`src/tools/${moduleName}/core/index.ts`]: this.getCoreIndexTemplate(config),
      [`src/tools/${moduleName}/core/domain-engine.ts`]: this.getDomainEngineTemplate(config),
      [`src/tools/${moduleName}/core/processor.ts`]: this.getProcessorTemplate(config),
      [`src/tools/${moduleName}/core/validator.ts`]: this.getValidatorTemplate(config),
      
      // Services
      [`src/tools/${moduleName}/services/index.ts`]: this.getServicesIndexTemplate(config),
      [`src/tools/${moduleName}/services/api-service.ts`]: this.getApiServiceTemplate(config),
      [`src/tools/${moduleName}/services/data-service.ts`]: this.getDataServiceTemplate(config),
      
      // Utils
      [`src/tools/${moduleName}/utils/index.ts`]: this.getUtilsIndexTemplate(config),
      [`src/tools/${moduleName}/utils/calculations.ts`]: this.getCalculationsTemplate(config),
      [`src/tools/${moduleName}/utils/formatters.ts`]: this.getFormattersTemplate(config),
      [`src/tools/${moduleName}/utils/transformers.ts`]: this.getTransformersTemplate(config),
      
      // Tools
      [`src/tools/${moduleName}/tools/index.ts`]: this.getToolsIndexTemplate(config),
      
      // Individual tool files
      ...this.generateToolFiles(config),
      
      // Constants and README
      [`src/tools/${moduleName}/constants.ts`]: this.getConstantsTemplate(config),
      [`src/tools/${moduleName}/README.md`]: this.getReadmeTemplate(config),
      
      // Test files
      [`tests/unit/tools/${moduleName}/core/domain-engine.test.ts`]: this.getDomainEngineTestTemplate(config),
      [`tests/integration/tools/${moduleName}/module-integration.test.ts`]: this.getIntegrationTestTemplate(config),
      [`tests/performance/tools/${moduleName}/performance-benchmarks.test.ts`]: this.getPerformanceTestTemplate(config),
    };
  }

  generateToolFiles(config) {
    const toolFiles = {};
    
    config.tools.forEach(toolName => {
      const toolFileName = this.toKebabCase(toolName);
      const toolFilePath = `src/tools/${config.name}/tools/${toolFileName}.ts`;
      toolFiles[toolFilePath] = this.getToolTemplate(config, toolName);
    });
    
    return toolFiles;
  }

  // Template generators
  getIndexTemplate(config) {
    const moduleNamePascal = this.toPascalCase(config.name);
    
    return `/**
 * @fileoverview ${moduleNamePascal} Module
 * ${config.description || `${moduleNamePascal} management and operations`}
 * 
 * This module provides comprehensive ${config.name} management capabilities
 * following the modular architecture pattern for maintainability and scalability.
 */

import { FastMCP } from 'fastmcp';
import MakeApiClient from '../../lib/make-api-client.js';
import logger from '../../lib/logger.js';
import { ToolContext } from '../shared/types/tool-context.js';

// Import tool registrations
import { registerTools } from './tools/index.js';

/**
 * Add ${config.name} tools to FastMCP server
 * 
 * @param server - FastMCP server instance
 * @param apiClient - Make.com API client
 */
export function add${moduleNamePascal}Tools(server: FastMCP, apiClient: MakeApiClient): void {
  const moduleLogger = logger.child({ component: '${moduleNamePascal}Tools' });
  
  moduleLogger.info('Adding ${config.name} tools');

  const context: ToolContext = {
    server,
    apiClient,
    logger: moduleLogger,
  };

  registerTools(context);

  moduleLogger.info('${moduleNamePascal} tools added successfully', {
    toolCount: ${config.tools.length},
    categories: ${JSON.stringify(['management', 'operations', 'utilities'])},
    tools: ${JSON.stringify(config.tools)}
  });
}

export default add${moduleNamePascal}Tools;

// Re-export types for external use
export type * from './types/index.js';

// Re-export core functionality
export { ${moduleNamePascal}Engine } from './core/domain-engine.js';
export { ${moduleNamePascal}Processor } from './core/processor.js';
export { ${moduleNamePascal}Validator } from './core/validator.js';
`;
  }

  getTypesIndexTemplate(config) {
    return `/**
 * @fileoverview ${this.toPascalCase(config.name)} Type Definitions
 * 
 * Centralized type definitions for the ${config.name} module.
 * This file aggregates all type definitions for easy importing.
 */

// Core entity and business logic types
export type * from './core-types.js';

// API request/response types
export type * from './api-types.js';

// Configuration and settings types
export type * from './config-types.js';

// Validation and error handling types
export type * from './validation-types.js';
`;
  }

  getCoreTypesTemplate(config) {
    const moduleNamePascal = this.toPascalCase(config.name);
    
    return `/**
 * @fileoverview Core ${moduleNamePascal} Types
 * 
 * Core entity types and business logic interfaces for the ${config.name} module.
 */

import { z } from 'zod';

/**
 * Core ${moduleNamePascal} entity
 */
export interface ${moduleNamePascal}Entity {
  id: string;
  name: string;
  description?: string;
  status: ${moduleNamePascal}Status;
  createdAt: Date;
  updatedAt: Date;
  metadata?: Record<string, unknown>;
}

/**
 * ${moduleNamePascal} status enumeration
 */
export type ${moduleNamePascal}Status = 'active' | 'inactive' | 'pending' | 'error';

/**
 * ${moduleNamePascal} configuration interface
 */
export interface ${moduleNamePascal}Config {
  enabled: boolean;
  options: ${moduleNamePascal}Options;
  limits: ${moduleNamePascal}Limits;
}

/**
 * ${moduleNamePascal} operational options
 */
export interface ${moduleNamePascal}Options {
  autoRefresh: boolean;
  cacheDuration: number;
  retryAttempts: number;
  timeoutMs: number;
}

/**
 * ${moduleNamePascal} operational limits
 */
export interface ${moduleNamePascal}Limits {
  maxItems: number;
  maxSize: number;
  rateLimit: number;
}

/**
 * ${moduleNamePascal} health status
 */
export interface ${moduleNamePascal}HealthStatus {
  healthy: boolean;
  lastChecked: Date;
  responseTime: number;
  details?: Record<string, unknown>;
  issues?: string[];
}

/**
 * ${moduleNamePascal} operation result
 */
export interface ${moduleNamePascal}OperationResult<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  metadata?: {
    timestamp: Date;
    duration: number;
    retryCount?: number;
  };
}
`;
  }

  getApiTypesTemplate(config) {
    const moduleNamePascal = this.toPascalCase(config.name);
    
    return `/**
 * @fileoverview ${moduleNamePascal} API Types
 * 
 * Type definitions for API requests and responses in the ${config.name} module.
 */

import { ${moduleNamePascal}Entity, ${moduleNamePascal}Status } from './core-types.js';

/**
 * Base API request interface
 */
export interface ${moduleNamePascal}ApiRequest {
  requestId?: string;
  timestamp?: Date;
}

/**
 * Base API response interface
 */
export interface ${moduleNamePascal}ApiResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
  metadata?: {
    requestId: string;
    timestamp: Date;
    duration: number;
  };
}

/**
 * List ${config.name} request
 */
export interface List${moduleNamePascal}Request extends ${moduleNamePascal}ApiRequest {
  filters?: {
    status?: ${moduleNamePascal}Status;
    search?: string;
    tags?: string[];
  };
  pagination?: {
    limit: number;
    offset: number;
  };
  sorting?: {
    field: string;
    direction: 'asc' | 'desc';
  };
}

/**
 * List ${config.name} response
 */
export interface List${moduleNamePascal}Response extends ${moduleNamePascal}ApiResponse<${moduleNamePascal}Entity[]> {
  pagination?: {
    total: number;
    limit: number;
    offset: number;
    hasMore: boolean;
  };
}

/**
 * Create ${config.name} request
 */
export interface Create${moduleNamePascal}Request extends ${moduleNamePascal}ApiRequest {
  name: string;
  description?: string;
  options?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

/**
 * Create ${config.name} response
 */
export interface Create${moduleNamePascal}Response extends ${moduleNamePascal}ApiResponse<${moduleNamePascal}Entity> {}

/**
 * Update ${config.name} request
 */
export interface Update${moduleNamePascal}Request extends ${moduleNamePascal}ApiRequest {
  id: string;
  name?: string;
  description?: string;
  status?: ${moduleNamePascal}Status;
  options?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

/**
 * Update ${config.name} response
 */
export interface Update${moduleNamePascal}Response extends ${moduleNamePascal}ApiResponse<${moduleNamePascal}Entity> {}

/**
 * Delete ${config.name} request
 */
export interface Delete${moduleNamePascal}Request extends ${moduleNamePascal}ApiRequest {
  id: string;
  force?: boolean;
}

/**
 * Delete ${config.name} response
 */
export interface Delete${moduleNamePascal}Response extends ${moduleNamePascal}ApiResponse<{ deleted: boolean }> {}
`;
  }

  getConfigTypesTemplate(config) {
    const moduleNamePascal = this.toPascalCase(config.name);
    
    return `/**
 * @fileoverview ${moduleNamePascal} Configuration Types
 * 
 * Configuration interfaces and types for the ${config.name} module.
 */

/**
 * Module-wide configuration
 */
export interface ${moduleNamePascal}ModuleConfig {
  enabled: boolean;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  cache: ${moduleNamePascal}CacheConfig;
  api: ${moduleNamePascal}ApiConfig;
  monitoring: ${moduleNamePascal}MonitoringConfig;
}

/**
 * Cache configuration
 */
export interface ${moduleNamePascal}CacheConfig {
  enabled: boolean;
  ttl: number; // Time to live in seconds
  maxSize: number; // Maximum number of cached items
  strategy: 'lru' | 'lfu' | 'ttl';
}

/**
 * API configuration
 */
export interface ${moduleNamePascal}ApiConfig {
  timeout: number; // Request timeout in milliseconds
  retries: number; // Number of retry attempts
  backoff: {
    initial: number; // Initial backoff delay
    multiplier: number; // Backoff multiplier
    maxDelay: number; // Maximum backoff delay
  };
  rateLimit: {
    requests: number; // Requests per window
    windowMs: number; // Rate limit window in milliseconds
  };
}

/**
 * Monitoring configuration
 */
export interface ${moduleNamePascal}MonitoringConfig {
  enabled: boolean;
  metricsInterval: number; // Metrics collection interval in milliseconds
  healthCheckInterval: number; // Health check interval in milliseconds
  alertThresholds: {
    errorRate: number; // Error rate threshold (0-1)
    responseTime: number; // Response time threshold in milliseconds
    memoryUsage: number; // Memory usage threshold (0-1)
  };
}

/**
 * Runtime configuration that can be updated dynamically
 */
export interface ${moduleNamePascal}RuntimeConfig {
  maintenanceMode: boolean;
  debugMode: boolean;
  featureFlags: {
    [key: string]: boolean;
  };
  overrides: {
    [key: string]: unknown;
  };
}
`;
  }

  getValidationTypesTemplate(config) {
    const moduleNamePascal = this.toPascalCase(config.name);
    
    return `/**
 * @fileoverview ${moduleNamePascal} Validation Types
 * 
 * Validation interfaces and error types for the ${config.name} module.
 */

/**
 * Validation result interface
 */
export interface ${moduleNamePascal}ValidationResult {
  isValid: boolean;
  errors: ${moduleNamePascal}ValidationError[];
  warnings: ${moduleNamePascal}ValidationWarning[];
}

/**
 * Validation error interface
 */
export interface ${moduleNamePascal}ValidationError {
  field: string;
  code: string;
  message: string;
  value?: unknown;
  context?: Record<string, unknown>;
}

/**
 * Validation warning interface
 */
export interface ${moduleNamePascal}ValidationWarning {
  field: string;
  code: string;
  message: string;
  suggestion?: string;
}

/**
 * ${moduleNamePascal} error types
 */
export type ${moduleNamePascal}ErrorType = 
  | 'validation'
  | 'not_found'
  | 'permission_denied'
  | 'rate_limited'
  | 'service_unavailable'
  | 'internal_error';

/**
 * ${moduleNamePascal} error interface
 */
export interface ${moduleNamePascal}Error extends Error {
  code: string;
  type: ${moduleNamePascal}ErrorType;
  details?: Record<string, unknown>;
  cause?: Error;
}

/**
 * ${moduleNamePascal} operation context
 */
export interface ${moduleNamePascal}OperationContext {
  requestId: string;
  userId?: string;
  sessionId?: string;
  timestamp: Date;
  metadata?: Record<string, unknown>;
}
`;
  }

  getToolTemplate(config, toolName) {
    const moduleNamePascal = this.toPascalCase(config.name);
    const toolNamePascal = this.toPascalCase(toolName);
    const toolNameCamel = this.toCamelCase(toolName);
    const toolNameKebab = this.toKebabCase(toolName);
    
    return `/**
 * @fileoverview ${toolNamePascal} Tool Implementation
 * 
 * FastMCP tool for ${toolName} operations in the ${config.name} module.
 * This tool provides a focused, single-responsibility implementation.
 */

import { UserError } from 'fastmcp';
import { z } from 'zod';

import { ToolContext } from '../../shared/types/tool-context.js';
import { ${toolNamePascal}Schema } from '../schemas/input-schemas.js';
import { ${moduleNamePascal}ApiResponse } from '../types/api-types.js';
import { ${moduleNamePascal}Engine } from '../core/domain-engine.js';

/**
 * Create ${toolName} tool configuration
 */
export function create${toolNamePascal}Tool(context: ToolContext) {
  const { apiClient, logger } = context;
  const engine = new ${moduleNamePascal}Engine(apiClient, logger);
  
  return {
    name: '${toolNameKebab}',
    description: 'Handle ${toolName} operations for ${config.name} management',
    parameters: ${toolNamePascal}Schema,
    annotations: {
      title: '${toolNamePascal}',
      readOnlyHint: ${toolName.toLowerCase().includes('list') || toolName.toLowerCase().includes('get')},
      destructiveHint: ${toolName.toLowerCase().includes('delete') || toolName.toLowerCase().includes('remove')},
      openWorldHint: true,
    },
    execute: async (args: unknown, { log, reportProgress }) => {
      const operationId = \`\${Date.now()}-\${Math.random().toString(36).substr(2, 9)}\`;
      
      log?.info?.('Starting ${toolName} operation', { 
        operationId, 
        args: JSON.stringify(args, null, 2) 
      });
      
      reportProgress({ progress: 0, total: 100 });

      try {
        // Input validation
        const validatedArgs = ${toolNamePascal}Schema.parse(args);
        reportProgress({ progress: 20, total: 100 });
        
        // Business logic execution
        log?.info?.('Executing ${toolName} business logic', { operationId });
        const result = await engine.${toolNameCamel}(validatedArgs);
        reportProgress({ progress: 80, total: 100 });
        
        // Response formatting
        const response = format${toolNamePascal}Response(result);
        reportProgress({ progress: 100, total: 100 });
        
        log?.info?.('${toolNamePascal} operation completed successfully', { 
          operationId,
          resultSummary: {
            success: response.success,
            dataType: typeof response.data,
            duration: Date.now() - parseInt(operationId.split('-')[0])
          }
        });
        
        return JSON.stringify(response, null, 2);
        
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        
        logger.error('${toolNamePascal} operation failed', { 
          operationId,
          error: errorMessage,
          stack: error instanceof Error ? error.stack : undefined,
          args: JSON.stringify(args, null, 2)
        });
        
        if (error instanceof UserError) {
          throw error;
        }
        
        throw new UserError(
          \`Failed to execute ${toolName}: \${errorMessage}\`,
          error instanceof Error ? error : undefined
        );
      }
    },
  };
}

/**
 * Format the ${toolName} response for consistent output
 */
function format${toolNamePascal}Response(result: any): ${moduleNamePascal}ApiResponse {
  return {
    success: true,
    data: result,
    metadata: {
      requestId: \`\${Date.now()}-\${Math.random().toString(36).substr(2, 9)}\`,
      timestamp: new Date(),
      duration: 0, // Will be calculated by the caller
    },
  };
}
`;
  }

  getToolsIndexTemplate(config) {
    const toolImports = config.tools.map(toolName => {
      const toolNamePascal = this.toPascalCase(toolName);
      const toolNameKebab = this.toKebabCase(toolName);
      return `import { create${toolNamePascal}Tool } from './${toolNameKebab}.js';`;
    }).join('\n');

    const toolRegistrations = config.tools.map(toolName => {
      const toolNamePascal = this.toPascalCase(toolName);
      return `  server.addTool(create${toolNamePascal}Tool(context));`;
    }).join('\n');

    return `/**
 * @fileoverview ${this.toPascalCase(config.name)} Tool Registration
 * 
 * Central tool registration for all ${config.name} module tools.
 * This module handles the registration of individual FastMCP tools.
 */

import { ToolContext } from '../../shared/types/tool-context.js';

// Import individual tool creators
${toolImports}

/**
 * Register all ${config.name} tools with the FastMCP server
 * 
 * @param context - Tool execution context with server and dependencies
 */
export function registerTools(context: ToolContext): void {
  const { server, logger } = context;

  logger.info('Registering ${config.name} tools', {
    toolCount: ${config.tools.length},
    tools: ${JSON.stringify(config.tools)}
  });

  try {
${toolRegistrations}

    logger.info('All ${config.name} tools registered successfully');
    
  } catch (error) {
    logger.error('Failed to register ${config.name} tools', { error });
    throw error;
  }
}

// Export individual tool creators for testing and selective registration
export {
${config.tools.map(toolName => {
  const toolNamePascal = this.toPascalCase(toolName);
  return `  create${toolNamePascal}Tool,`;
}).join('\n')}
};
`;
  }

  // Helper methods for string transformations
  toPascalCase(str) {
    return str.replace(/(?:^\w|[A-Z]|\b\w)/g, (word, index) => {
      return word.toUpperCase();
    }).replace(/\s+/g, '').replace(/-/g, '');
  }

  toCamelCase(str) {
    const pascal = this.toPascalCase(str);
    return pascal.charAt(0).toLowerCase() + pascal.slice(1);
  }

  toKebabCase(str) {
    return str.replace(/([a-z])([A-Z])/g, '$1-$2').toLowerCase();
  }

  // Additional template methods would go here...
  getSchemasIndexTemplate(config) {
    return `/**
 * @fileoverview ${this.toPascalCase(config.name)} Validation Schemas
 */

export * from './input-schemas.js';
export * from './output-schemas.js';
export * from './config-schemas.js';
`;
  }

  getInputSchemasTemplate(config) {
    const moduleNamePascal = this.toPascalCase(config.name);
    const toolSchemas = config.tools.map(toolName => {
      const toolNamePascal = this.toPascalCase(toolName);
      return `export const ${toolNamePascal}Schema = z.object({
  // Define ${toolName} input schema here
  id: z.string().optional(),
  name: z.string().min(1).max(255).optional(),
});`;
    }).join('\n\n');

    return `/**
 * @fileoverview Input Validation Schemas for ${moduleNamePascal}
 */

import { z } from 'zod';

// Common validation patterns
const IdSchema = z.string().uuid('Invalid ID format');
const NameSchema = z.string().min(1, 'Name is required').max(255, 'Name too long');
const DescriptionSchema = z.string().max(1000, 'Description too long').optional();

// Tool-specific schemas
${toolSchemas}

// Export common schemas for reuse
export {
  IdSchema,
  NameSchema,
  DescriptionSchema,
};
`;
  }

  getOutputSchemasTemplate(config) {
    return `/**
 * @fileoverview Output Validation Schemas for ${this.toPascalCase(config.name)}
 */

import { z } from 'zod';

// Output response schemas would go here
export const ResponseSchema = z.object({
  success: z.boolean(),
  data: z.unknown().optional(),
  error: z.string().optional(),
});
`;
  }

  getConfigSchemasTemplate(config) {
    return `/**
 * @fileoverview Configuration Validation Schemas for ${this.toPascalCase(config.name)}
 */

import { z } from 'zod';

// Configuration schemas would go here
export const ModuleConfigSchema = z.object({
  enabled: z.boolean().default(true),
  logLevel: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
});
`;
  }

  getCoreIndexTemplate(config) {
    return `/**
 * @fileoverview Core Logic Exports for ${this.toPascalCase(config.name)}
 */

export { ${this.toPascalCase(config.name)}Engine } from './domain-engine.js';
export { ${this.toPascalCase(config.name)}Processor } from './processor.js';
export { ${this.toPascalCase(config.name)}Validator } from './validator.js';
`;
  }

  getDomainEngineTemplate(config) {
    const moduleNamePascal = this.toPascalCase(config.name);
    
    return `/**
 * @fileoverview ${moduleNamePascal} Domain Engine
 * 
 * Core business logic engine for ${config.name} operations.
 * This class encapsulates all domain-specific business rules and operations.
 */

import MakeApiClient from '../../../lib/make-api-client.js';
import { Logger } from '../../../lib/logger.js';
import { ${moduleNamePascal}Entity, ${moduleNamePascal}OperationResult } from '../types/core-types.js';

export class ${moduleNamePascal}Engine {
  constructor(
    private apiClient: MakeApiClient,
    private logger: Logger
  ) {}

  /**
   * Core business logic methods will be implemented here
   */
  
${config.tools.map(toolName => {
  const methodName = this.toCamelCase(toolName);
  return `  async ${methodName}(params: any): Promise<${moduleNamePascal}OperationResult> {
    this.logger.info('Executing ${methodName}', { params });
    
    try {
      // Implement ${toolName} business logic here
      const result = await this.perform${this.toPascalCase(toolName)}Operation(params);
      
      return {
        success: true,
        data: result,
        metadata: {
          timestamp: new Date(),
          duration: 0, // Calculate actual duration
        },
      };
    } catch (error) {
      this.logger.error('${methodName} failed', { error, params });
      
      return {
        success: false,
        error: error instanceof Error ? error.message : String(error),
        metadata: {
          timestamp: new Date(),
          duration: 0,
        },
      };
    }
  }

  private async perform${this.toPascalCase(toolName)}Operation(params: any): Promise<any> {
    // TODO: Implement ${toolName} operation logic
    throw new Error('${toolName} operation not implemented');
  }`;
}).join('\n\n')}
}
`;
  }

  // Continue with other template methods...
  getProcessorTemplate(config) {
    const moduleNamePascal = this.toPascalCase(config.name);
    
    return `/**
 * @fileoverview ${moduleNamePascal} Data Processor
 */

export class ${moduleNamePascal}Processor {
  // Data processing logic will be implemented here
}
`;
  }

  getValidatorTemplate(config) {
    const moduleNamePascal = this.toPascalCase(config.name);
    
    return `/**
 * @fileoverview ${moduleNamePascal} Business Rules Validator
 */

export class ${moduleNamePascal}Validator {
  // Validation logic will be implemented here
}
`;
  }

  getServicesIndexTemplate(config) {
    return `/**
 * @fileoverview Services Exports for ${this.toPascalCase(config.name)}
 */

export { ${this.toPascalCase(config.name)}ApiService } from './api-service.js';
export { ${this.toPascalCase(config.name)}DataService } from './data-service.js';
`;
  }

  getApiServiceTemplate(config) {
    return `/**
 * @fileoverview ${this.toPascalCase(config.name)} API Service
 */

export class ${this.toPascalCase(config.name)}ApiService {
  // API integration logic will be implemented here
}
`;
  }

  getDataServiceTemplate(config) {
    return `/**
 * @fileoverview ${this.toPascalCase(config.name)} Data Service
 */

export class ${this.toPascalCase(config.name)}DataService {
  // Data persistence logic will be implemented here
}
`;
  }

  getUtilsIndexTemplate(config) {
    return `/**
 * @fileoverview Utility Exports for ${this.toPascalCase(config.name)}
 */

export * from './calculations.js';
export * from './formatters.js';
export * from './transformers.js';
`;
  }

  getCalculationsTemplate(config) {
    return `/**
 * @fileoverview ${this.toPascalCase(config.name)} Calculations
 */

// Mathematical and business calculation utilities
`;
  }

  getFormattersTemplate(config) {
    return `/**
 * @fileoverview ${this.toPascalCase(config.name)} Formatters
 */

// Data formatting utilities
`;
  }

  getTransformersTemplate(config) {
    return `/**
 * @fileoverview ${this.toPascalCase(config.name)} Transformers
 */

// Data transformation utilities
`;
  }

  getConstantsTemplate(config) {
    const moduleNameUpper = config.name.toUpperCase().replace(/-/g, '_');
    
    return `/**
 * @fileoverview ${this.toPascalCase(config.name)} Constants
 */

export const ${moduleNameUpper}_CONSTANTS = {
  // Module-specific constants will be defined here
  DEFAULT_TIMEOUT: 30000,
  MAX_RETRIES: 3,
  CACHE_TTL: 300000, // 5 minutes
} as const;
`;
  }

  getReadmeTemplate(config) {
    const moduleNamePascal = this.toPascalCase(config.name);
    
    return `# ${moduleNamePascal} Module

${config.description || `${moduleNamePascal} management and operations module`}

## Architecture

This module follows the standard modular architecture pattern:

- \`types/\` - TypeScript type definitions
- \`schemas/\` - Zod validation schemas  
- \`core/\` - Core business logic
- \`services/\` - External service integrations
- \`utils/\` - Utility functions
- \`tools/\` - FastMCP tool implementations

## Tools

${config.tools.map(toolName => `### ${toolName}
${toolName} operations for ${config.name} management.

**Usage**: Available as FastMCP tool \`${this.toKebabCase(toolName)}\`
`).join('\n')}

## Development

### Adding New Tools
1. Create tool implementation in \`tools/new-tool.ts\`
2. Add tool registration in \`tools/index.ts\`
3. Add unit tests in \`tests/unit/tools/${config.name}/new-tool.test.ts\`
4. Update this README

### Testing
\`\`\`bash
npm run test:unit -- --testPathPattern="${config.name}"
npm run test:integration -- --testPathPattern="${config.name}"
\`\`\`

### Performance
\`\`\`bash
npm run test:performance -- --module="${config.name}"
\`\`\`

## API Reference

[Generated API documentation will be available here]
`;
  }

  // Test template methods
  getDomainEngineTestTemplate(config) {
    const moduleNamePascal = this.toPascalCase(config.name);
    
    return `/**
 * @fileoverview ${moduleNamePascal} Domain Engine Tests
 */

import { ${moduleNamePascal}Engine } from '../../../../src/tools/${config.name}/core/domain-engine';

describe('${moduleNamePascal}Engine', () => {
  let engine: ${moduleNamePascal}Engine;
  
  beforeEach(() => {
    const mockApiClient = {} as any;
    const mockLogger = {
      info: jest.fn(),
      error: jest.fn(),
      warn: jest.fn(),
      debug: jest.fn(),
    };
    
    engine = new ${moduleNamePascal}Engine(mockApiClient, mockLogger);
  });

  describe('core functionality', () => {
    it('should be properly instantiated', () => {
      expect(engine).toBeInstanceOf(${moduleNamePascal}Engine);
    });
  });
});
`;
  }

  getIntegrationTestTemplate(config) {
    const moduleNamePascal = this.toPascalCase(config.name);
    
    return `/**
 * @fileoverview ${moduleNamePascal} Integration Tests
 */

describe('${moduleNamePascal} Module Integration', () => {
  // Integration tests will be implemented here
});
`;
  }

  getPerformanceTestTemplate(config) {
    const moduleNamePascal = this.toPascalCase(config.name);
    
    return `/**
 * @fileoverview ${moduleNamePascal} Performance Tests
 */

describe('${moduleNamePascal} Performance', () => {
  // Performance benchmarks will be implemented here
});
`;
  }

  async updateMainExports(config) {
    // Update main tools index to include new module
    const mainIndexPath = path.join(this.projectRoot, 'src', 'tools', 'index.ts');
    
    try {
      let content = '';
      try {
        content = await fs.readFile(mainIndexPath, 'utf8');
      } catch (error) {
        // File doesn't exist, create basic structure
        content = '// Main tools exports\n\n';
      }

      const moduleExport = `export { add${this.toPascalCase(config.name)}Tools } from './${config.name}/index.js';`;
      
      if (!content.includes(moduleExport)) {
        content += `${moduleExport}\n`;
        await fs.writeFile(mainIndexPath, content, 'utf8');
        console.log('📄 Updated main tools index');
      }
    } catch (error) {
      console.warn('⚠️  Could not update main tools index:', error.message);
    }
  }

  async generateTestTemplates(config) {
    // Test templates are already included in getTemplates()
    console.log('📋 Test templates generated');
  }

  async updateDocumentation(config) {
    // Documentation is already included in getTemplates()
    console.log('📚 Documentation generated');
  }

  async setupGitTracking(config) {
    try {
      const modulePath = path.join('src', 'tools', config.name);
      execSync(`git add ${modulePath}`, { cwd: this.projectRoot, stdio: 'pipe' });
      console.log('📦 Added module to git tracking');
    } catch (error) {
      console.warn('⚠️  Could not add module to git:', error.message);
    }
  }
}

// CLI interface
if (require.main === module) {
  const args = process.argv.slice(2);
  const config = {
    name: '',
    description: '',
    tools: [],
  };

  // Parse command line arguments
  for (let i = 0; i < args.length; i += 2) {
    const flag = args[i];
    const value = args[i + 1];

    switch (flag) {
      case '--name':
        config.name = value;
        break;
      case '--description':
        config.description = value;
        break;
      case '--tools':
        config.tools = value.split(',').map(tool => tool.trim());
        break;
    }
  }

  // Validate required parameters
  if (!config.name) {
    console.error('❌ Module name is required. Use --name <module-name>');
    process.exit(1);
  }

  if (config.tools.length === 0) {
    console.error('❌ At least one tool is required. Use --tools <tool1,tool2,...>');
    process.exit(1);
  }

  // Generate the module
  const generator = new ModuleGenerator();
  generator.generateModule(config).catch(error => {
    console.error('❌ Module generation failed:', error);
    process.exit(1);
  });
}

module.exports = { ModuleGenerator };