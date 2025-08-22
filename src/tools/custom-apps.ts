/**
 * Custom App Development Tools for Make.com FastMCP Server
 * Comprehensive tools for custom app creation, configuration, testing, and lifecycle management
 */

import { FastMCP, UserError } from 'fastmcp';
import { z } from 'zod';
import MakeApiClient from '../lib/make-api-client.js';
import logger from '../lib/logger.js';
import { formatSuccessResponse } from '../utils/response-formatter.js';

// Custom app and hook management types
export interface MakeCustomApp {
  id: number;
  name: string;
  description?: string;
  version: string;
  status: 'draft' | 'testing' | 'published' | 'deprecated' | 'suspended';
  organizationId?: number;
  teamId?: number;
  configuration: {
    type: 'connector' | 'trigger' | 'action' | 'transformer' | 'full_app';
    runtime: 'nodejs' | 'python' | 'php' | 'custom';
    environment: {
      variables: Record<string, string>;
      secrets: string[];
      dependencies: Record<string, string>;
    };
    endpoints: Array<{
      name: string;
      method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
      path: string;
      description?: string;
      parameters: Record<string, unknown>; // JSON Schema
      responses: Record<string, unknown>; // JSON Schema
    }>;
    authentication: {
      type: 'none' | 'api_key' | 'oauth2' | 'basic_auth' | 'custom';
      configuration: Record<string, unknown>;
    };
    ui: {
      icon?: string;
      color?: string;
      description?: string;
      category?: string;
    };
  };
  deployment: {
    source: 'git' | 'zip' | 'inline';
    repository?: string;
    branch?: string;
    buildCommand?: string;
    startCommand?: string;
    healthCheckEndpoint?: string;
  };
  testing: {
    testSuite?: string;
    coverageThreshold?: number;
    lastTestRun?: {
      timestamp: string;
      passed: number;
      failed: number;
      coverage: number;
      duration: number;
    };
  };
  usage: {
    installations: number;
    executions: number;
    averageResponseTime: number;
    errorRate: number;
    lastUsed?: string;
  };
  permissions: {
    scopes: string[];
    roles: string[];
    restrictions: Record<string, unknown>;
  };
  createdAt: string;
  updatedAt: string;
  createdBy: number;
  createdByName: string;
}

export interface MakeHook {
  id: number;
  name: string;
  description?: string;
  appId: number;
  appName: string;
  type: 'webhook' | 'polling' | 'instant' | 'custom';
  status: 'active' | 'inactive' | 'testing' | 'error';
  configuration: {
    endpoint: string;
    method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
    headers: Record<string, string>;
    authentication: {
      type: 'none' | 'api_key' | 'bearer' | 'basic' | 'oauth2';
      configuration: Record<string, unknown>;
    };
    polling?: {
      interval: number; // minutes
      strategy: 'incremental' | 'full_scan' | 'timestamp_based';
      parameters: Record<string, unknown>;
    };
  };
  events: Array<{
    name: string;
    description?: string;
    schema: Record<string, unknown>; // JSON Schema for event data
    filters?: Record<string, unknown>;
  }>;
  execution: {
    totalCalls: number;
    successfulCalls: number;
    failedCalls: number;
    averageResponseTime: number;
    lastExecution?: {
      timestamp: string;
      status: 'success' | 'failure' | 'timeout';
      responseTime: number;
      error?: string;
    };
  };
  logs: {
    retention: number; // days
    level: 'debug' | 'info' | 'warn' | 'error';
    destinations: Array<'console' | 'file' | 'webhook' | 'external'>;
  };
  createdAt: string;
  updatedAt: string;
  createdBy: number;
}

export interface MakeCustomFunction {
  id: number;
  name: string;
  description?: string;
  appId?: number;
  type: 'transformer' | 'validator' | 'formatter' | 'calculator' | 'custom';
  language: 'javascript' | 'python' | 'php' | 'custom';
  status: 'draft' | 'testing' | 'published' | 'deprecated';
  code: {
    source: string;
    dependencies: Record<string, string>;
    environment: Record<string, string>;
    timeout: number; // seconds
    memoryLimit: number; // MB
  };
  interface: {
    input: Record<string, unknown>; // JSON Schema
    output: Record<string, unknown>; // JSON Schema
    parameters: Record<string, unknown>;
  };
  testing: {
    testCases: Array<{
      name: string;
      input: unknown;
      expectedOutput: unknown;
      description?: string;
    }>;
    lastTestRun?: {
      timestamp: string;
      passed: number;
      failed: number;
      duration: number;
    };
  };
  deployment: {
    version: string;
    environment: 'development' | 'staging' | 'production';
    instances: number;
    autoScale: boolean;
  };
  monitoring: {
    executions: number;
    averageExecutionTime: number;
    errorRate: number;
    memoryUsage: number;
    cpuUsage: number;
  };
  createdAt: string;
  updatedAt: string;
  createdBy: number;
}

// Input validation schemas
const CustomAppCreateSchema = z.object({
  name: z.string().min(1).max(100).describe('Custom app name (1-100 characters)'),
  description: z.string().max(500).optional().describe('App description (max 500 characters)'),
  type: z.enum(['connector', 'trigger', 'action', 'transformer', 'full_app']).describe('App type'),
  runtime: z.enum(['nodejs', 'python', 'php', 'custom']).default('nodejs').describe('Runtime environment'),
  organizationId: z.number().min(1).optional().describe('Organization ID (for organization apps)'),
  teamId: z.number().min(1).optional().describe('Team ID (for team apps)'),
  configuration: z.object({
    environment: z.object({
      variables: z.record(z.string(), z.string()).default(() => ({})).describe('Environment variables'),
      secrets: z.array(z.string()).default([]).describe('Secret names to be injected'),
      dependencies: z.record(z.string(), z.string()).default(() => ({})).describe('Package dependencies'),
    }).default(() => ({ variables: {}, secrets: [], dependencies: {} })).describe('Environment configuration'),
    endpoints: z.array(z.object({
      name: z.string().min(1).describe('Endpoint name'),
      method: z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']).describe('HTTP method'),
      path: z.string().min(1).describe('Endpoint path'),
      description: z.string().optional().describe('Endpoint description'),
      parameters: z.any().optional().describe('JSON Schema for parameters'),
      responses: z.any().optional().describe('JSON Schema for responses'),
    })).default([]).describe('API endpoints'),
    authentication: z.object({
      type: z.enum(['none', 'api_key', 'oauth2', 'basic_auth', 'custom']).describe('Authentication type'),
      configuration: z.record(z.string(), z.any()).default(() => ({})).describe('Auth configuration'),
    }).default({ type: 'none', configuration: {} }).describe('Authentication settings'),
    ui: z.object({
      icon: z.string().optional().describe('App icon URL or identifier'),
      color: z.string().optional().describe('App theme color'),
      description: z.string().optional().describe('UI description'),
      category: z.string().optional().describe('App category'),
    }).default(() => ({})).describe('UI configuration'),
  }).describe('App configuration'),
  deployment: z.object({
    source: z.enum(['git', 'zip', 'inline']).describe('Source type'),
    repository: z.string().url().optional().describe('Git repository URL'),
    branch: z.string().default('main').optional().describe('Git branch'),
    buildCommand: z.string().optional().describe('Build command'),
    startCommand: z.string().optional().describe('Start command'),
    healthCheckEndpoint: z.string().optional().describe('Health check endpoint'),
  }).optional().describe('Deployment configuration'),
  permissions: z.object({
    scopes: z.array(z.string()).default([]).describe('Permission scopes'),
    roles: z.array(z.string()).default([]).describe('Required roles'),
    restrictions: z.record(z.string(), z.any()).default(() => ({})).describe('Access restrictions'),
  }).default(() => ({ scopes: [], roles: [], restrictions: {} })).describe('App permissions'),
}).strict();

const HookCreateSchema = z.object({
  name: z.string().min(1).max(100).describe('Hook name (1-100 characters)'),
  description: z.string().max(500).optional().describe('Hook description (max 500 characters)'),
  appId: z.number().min(1).describe('Custom app ID this hook belongs to'),
  type: z.enum(['webhook', 'polling', 'instant', 'custom']).describe('Hook type'),
  configuration: z.object({
    endpoint: z.string().url().describe('Hook endpoint URL'),
    method: z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']).default('POST').describe('HTTP method'),
    headers: z.record(z.string(), z.string()).default(() => ({})).describe('HTTP headers'),
    authentication: z.object({
      type: z.enum(['none', 'api_key', 'bearer', 'basic', 'oauth2']).describe('Authentication type'),
      configuration: z.record(z.string(), z.any()).default(() => ({})).describe('Auth configuration'),
    }).describe('Authentication settings'),
    polling: z.object({
      interval: z.number().min(1).max(1440).default(5).describe('Polling interval in minutes'),
      strategy: z.enum(['incremental', 'full_scan', 'timestamp_based']).describe('Polling strategy'),
      parameters: z.record(z.string(), z.any()).default(() => ({})).describe('Polling parameters'),
    }).optional().describe('Polling configuration (for polling hooks)'),
  }).describe('Hook configuration'),
  events: z.array(z.object({
    name: z.string().min(1).describe('Event name'),
    description: z.string().optional().describe('Event description'),
    schema: z.any().describe('JSON Schema for event data'),
    filters: z.record(z.string(), z.any()).optional().describe('Event filters'),
  })).min(1).describe('Events this hook can handle'),
  logs: z.object({
    retention: z.number().min(1).max(365).default(30).describe('Log retention in days'),
    level: z.enum(['debug', 'info', 'warn', 'error']).default('info').describe('Log level'),
    destinations: z.array(z.enum(['console', 'file', 'webhook', 'external'])).default(['console']).describe('Log destinations'),
  }).default({ retention: 30, level: 'info' as const, destinations: ['console' as const] }).describe('Logging configuration'),
}).strict();

const CustomFunctionCreateSchema = z.object({
  name: z.string().min(1).max(100).describe('Function name (1-100 characters)'),
  description: z.string().max(500).optional().describe('Function description (max 500 characters)'),
  appId: z.number().min(1).optional().describe('Custom app ID this function belongs to'),
  type: z.enum(['transformer', 'validator', 'formatter', 'calculator', 'custom']).describe('Function type'),
  language: z.enum(['javascript', 'python', 'php', 'custom']).default('javascript').describe('Programming language'),
  code: z.object({
    source: z.string().min(1).describe('Function source code'),
    dependencies: z.record(z.string(), z.string()).default(() => ({})).describe('Package dependencies'),
    environment: z.record(z.string(), z.string()).default(() => ({})).describe('Environment variables'),
    timeout: z.number().min(1).max(300).default(30).describe('Execution timeout in seconds'),
    memoryLimit: z.number().min(64).max(2048).default(256).describe('Memory limit in MB'),
  }).describe('Code configuration'),
  interface: z.object({
    input: z.any().describe('JSON Schema for input parameters'),
    output: z.any().describe('JSON Schema for output format'),
    parameters: z.record(z.string(), z.any()).default(() => ({})).describe('Additional parameters'),
  }).describe('Function interface'),
  testCases: z.array(z.object({
    name: z.string().min(1).describe('Test case name'),
    input: z.any().describe('Test input data'),
    expectedOutput: z.any().describe('Expected output data'),
    description: z.string().optional().describe('Test case description'),
  })).default([]).describe('Test cases for validation'),
  deployment: z.object({
    environment: z.enum(['development', 'staging', 'production']).default('development').describe('Deployment environment'),
    instances: z.number().min(1).max(10).default(1).describe('Number of instances'),
    autoScale: z.boolean().default(false).describe('Enable auto-scaling'),
  }).default({ environment: 'development' as const, instances: 1, autoScale: false }).describe('Deployment settings'),
}).strict();

/**
 * Add create custom app tool
 */
function addCreateCustomAppTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'create-custom-app',
    description: 'Create a new custom app for Make.com platform with comprehensive configuration',
    parameters: CustomAppCreateSchema,
    annotations: {
      title: 'Create Custom App',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
    execute: async (input, { log, reportProgress }) => {
      const { name, description, type, runtime, organizationId, teamId, configuration, deployment, permissions } = input;

      log.info('Creating custom app', {
        name,
        type,
        runtime,
        organizationId,
        teamId,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        const appData = {
          name,
          description,
          version: '1.0.0',
          configuration: {
            type,
            runtime,
            environment: {
              ...configuration.environment,
              variables: configuration.environment?.variables ?? {},
              secrets: configuration.environment?.secrets ?? [],
              dependencies: configuration.environment?.dependencies ?? {},
            },
            endpoints: configuration.endpoints || [],
            authentication: {
              ...configuration.authentication,
              type: configuration.authentication?.type ?? 'none',
              configuration: configuration.authentication?.configuration ?? {},
            },
            ui: {
              category: 'custom',
              ...configuration.ui,
            },
          },
          deployment: {
            source: 'inline',
            buildCommand: 'npm install',
            startCommand: 'npm start',
            healthCheckEndpoint: '/health',
            ...deployment,
          },
          permissions: {
            ...permissions,
            scopes: permissions?.scopes ?? [],
            roles: permissions?.roles ?? ['developer'],
            restrictions: permissions?.restrictions ?? {},
          },
          organizationId,
          teamId,
          status: 'draft',
        };

        reportProgress({ progress: 50, total: 100 });

        let endpoint = '/custom-apps';
        if (organizationId) {
          endpoint = `/organizations/${organizationId}/custom-apps`;
        } else if (teamId) {
          endpoint = `/teams/${teamId}/custom-apps`;
        }

        const response = await apiClient.post(endpoint, appData);

        if (!response.success) {
          throw new UserError(`Failed to create custom app: ${response.error?.message || 'Unknown error'}`);
        }

        const app = response.data as MakeCustomApp;
        if (!app) {
          throw new UserError('Custom app creation failed - no data returned');
        }

        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully created custom app', {
          appId: app.id,
          name: app.name,
          type: app.configuration.type,
          runtime: app.configuration.runtime,
        });

        return formatSuccessResponse({
          app: {
            ...app,
            configuration: {
              ...app.configuration,
              environment: {
                ...app.configuration.environment,
                secrets: app.configuration.environment.secrets.map(() => '[SECRET_HIDDEN]'),
              },
            },
          },
          message: `Custom app "${name}" created successfully`,
          development: {
            type: app.configuration.type,
            runtime: app.configuration.runtime,
            endpoints: app.configuration.endpoints.length,
            authentication: app.configuration.authentication.type,
            status: app.status,
          },
          nextSteps: [
            'Configure authentication if needed',
            'Add API endpoints and handlers',
            'Set up deployment configuration',
            'Write and run tests',
            'Deploy to staging for testing',
          ],
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error creating custom app', { name, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to create custom app: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add list custom apps tool
 */
function addListCustomAppsTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'list-custom-apps',
    description: 'List and filter custom apps with development status and usage statistics',
    parameters: z.object({
      type: z.enum(['connector', 'trigger', 'action', 'transformer', 'full_app', 'all']).default('all').describe('Filter by app type'),
      status: z.enum(['draft', 'testing', 'published', 'deprecated', 'suspended', 'all']).default('all').describe('Filter by app status'),
      runtime: z.enum(['nodejs', 'python', 'php', 'custom', 'all']).default('all').describe('Filter by runtime'),
      organizationId: z.number().min(1).optional().describe('Filter by organization ID'),
      teamId: z.number().min(1).optional().describe('Filter by team ID'),
      includeUsage: z.boolean().default(true).describe('Include usage statistics'),
      includeConfig: z.boolean().default(false).describe('Include configuration details'),
      limit: z.number().min(1).max(1000).default(100).describe('Maximum number of apps to return'),
      offset: z.number().min(0).default(0).describe('Number of apps to skip for pagination'),
      sortBy: z.enum(['name', 'createdAt', 'usage', 'status', 'type']).default('name').describe('Sort field'),
      sortOrder: z.enum(['asc', 'desc']).default('asc').describe('Sort order'),
    }),
    annotations: {
      title: 'List Custom Apps',
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log }) => {
      const { type, status, runtime, organizationId, teamId, includeUsage, includeConfig, limit, offset, sortBy, sortOrder } = input;

      log.info('Listing custom apps', {
        type,
        status,
        runtime,
        limit,
        offset,
      });

      try {
        const params: Record<string, unknown> = {
          limit,
          offset,
          sortBy,
          sortOrder,
          includeUsage,
          includeConfig,
        };

        if (type !== 'all') {params.type = type;}
        if (status !== 'all') {params.status = status;}
        if (runtime !== 'all') {params.runtime = runtime;}
        if (organizationId) {params.organizationId = organizationId;}
        if (teamId) {params.teamId = teamId;}

        const response = await apiClient.get('/custom-apps', { params });

        if (!response.success) {
          throw new UserError(`Failed to list custom apps: ${response.error?.message || 'Unknown error'}`);
        }

        const apps = response.data as MakeCustomApp[] || [];
        const metadata = response.metadata;

        log.info('Successfully retrieved custom apps', {
          count: apps.length,
          total: metadata?.total,
        });

        // Create development and usage analysis
        const analysis = {
          totalApps: metadata?.total || apps.length,
          typeBreakdown: apps.reduce((acc: Record<string, number>, app) => {
            acc[app.configuration.type] = (acc[app.configuration.type] || 0) + 1;
            return acc;
          }, {}),
          statusBreakdown: apps.reduce((acc: Record<string, number>, app) => {
            acc[app.status] = (acc[app.status] || 0) + 1;
            return acc;
          }, {}),
          runtimeBreakdown: apps.reduce((acc: Record<string, number>, app) => {
            acc[app.configuration.runtime] = (acc[app.configuration.runtime] || 0) + 1;
            return acc;
          }, {}),
          developmentSummary: {
            draftApps: apps.filter(a => a.status === 'draft').length,
            testingApps: apps.filter(a => a.status === 'testing').length,
            publishedApps: apps.filter(a => a.status === 'published').length,
            totalEndpoints: apps.reduce((sum, a) => sum + a.configuration.endpoints.length, 0),
            averageEndpointsPerApp: apps.length > 0 ? 
              apps.reduce((sum, a) => sum + a.configuration.endpoints.length, 0) / apps.length : 0,
          },
          usageSummary: includeUsage ? {
            totalInstallations: apps.reduce((sum, a) => sum + a.usage.installations, 0),
            totalExecutions: apps.reduce((sum, a) => sum + a.usage.executions, 0),
            averageResponseTime: apps.length > 0 ? 
              apps.reduce((sum, a) => sum + a.usage.averageResponseTime, 0) / apps.length : 0,
            averageErrorRate: apps.length > 0 ? 
              apps.reduce((sum, a) => sum + a.usage.errorRate, 0) / apps.length : 0,
            mostUsedApps: apps
              .sort((a, b) => b.usage.executions - a.usage.executions)
              .slice(0, 5)
              .map(a => ({
                id: a.id,
                name: a.name,
                executions: a.usage.executions,
                installations: a.usage.installations,
                errorRate: a.usage.errorRate,
              })),
          } : undefined,
        };

        return formatSuccessResponse({
          apps: apps.map(app => ({
            ...app,
            configuration: {
              ...app.configuration,
              environment: {
                ...app.configuration.environment,
                secrets: '[SECRETS_HIDDEN]',
              },
            },
          })),
          analysis,
          pagination: {
            total: metadata?.total || apps.length,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + apps.length),
          },
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error listing custom apps', { error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to list custom apps: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add create hook tool
 */
function addCreateHookTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'create-hook',
    description: 'Create a webhook or polling hook for custom app event handling',
    parameters: HookCreateSchema,
    annotations: {
      title: 'Create Custom Hook',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
    execute: async (input, { log, reportProgress }) => {
      const { name, description, appId, type, configuration, events, logs } = input;

      log.info('Creating hook', {
        name,
        appId,
        type,
        endpoint: configuration.endpoint,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        const hookData = {
          name,
          description,
          appId,
          type,
          configuration: {
            endpoint: configuration.endpoint,
            method: configuration.method || 'POST',
            headers: configuration.headers || {},
            authentication: {
              ...configuration.authentication,
              type: configuration.authentication?.type ?? 'none',
              configuration: configuration.authentication?.configuration ?? {},
            },
            polling: type === 'polling' ? {
              interval: 5,
              strategy: 'incremental',
              parameters: {},
              ...configuration.polling,
            } : undefined,
          },
          events,
          logs: {
            ...logs,
            retention: logs?.retention ?? 30,
            level: logs?.level ?? 'info',
            destinations: logs?.destinations ?? ['console'],
          },
          status: 'active',
        };

        reportProgress({ progress: 50, total: 100 });

        const response = await apiClient.post('/hooks', hookData);

        if (!response.success) {
          throw new UserError(`Failed to create hook: ${response.error?.message || 'Unknown error'}`);
        }

        const hook = response.data as MakeHook;
        if (!hook) {
          throw new UserError('Hook creation failed - no data returned');
        }

        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully created hook', {
          hookId: hook.id,
          name: hook.name,
          type: hook.type,
          appId: hook.appId,
        });

        return formatSuccessResponse({
          hook: {
            ...hook,
            configuration: {
              ...hook.configuration,
              authentication: {
                ...hook.configuration.authentication,
                configuration: '[AUTH_CONFIG_HIDDEN]',
              },
            },
          },
          message: `Hook "${name}" created successfully`,
          configuration: {
            type: hook.type,
            endpoint: hook.configuration.endpoint,
            method: hook.configuration.method,
            eventsCount: hook.events.length,
            authType: hook.configuration.authentication.type,
          },
          testing: {
            testEndpoint: `/hooks/${hook.id}/test`,
            webhookUrl: hook.type === 'webhook' ? hook.configuration.endpoint : undefined,
            pollingInterval: hook.configuration.polling?.interval,
          },
        }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error creating hook', { name, appId, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to create hook: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add create custom function tool
 */
function addCreateCustomFunctionTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'create-custom-function',
    description: 'Create a custom function for data transformation, validation, or processing',
    parameters: CustomFunctionCreateSchema,
    annotations: {
      title: 'Create Custom Function',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
    execute: async (input, { log, reportProgress }) => {
      const { name, description, appId, type, language, code, interface: functionInterface, testCases, deployment } = input;

      log.info('Creating custom function', {
        name,
        appId,
        type,
        language,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        const functionData = {
          name,
          description,
          appId,
          type,
          language,
          code: {
            source: code.source,
            dependencies: code.dependencies || {},
            environment: code.environment || {},
            timeout: code.timeout || 30,
            memoryLimit: code.memoryLimit || 256,
          },
          interface: functionInterface,
          testing: {
            testCases: testCases || [],
          },
          deployment: {
            ...deployment,
            version: '1.0.0', // Default version for new functions
            environment: deployment?.environment ?? 'development',
            instances: deployment?.instances ?? 1,
            autoScale: deployment?.autoScale ?? false,
          },
          status: 'draft',
        };

        reportProgress({ progress: 50, total: 100 });

        const response = await apiClient.post('/custom-functions', functionData);

        if (!response.success) {
          throw new UserError(`Failed to create custom function: ${response.error?.message || 'Unknown error'}`);
        }

        const customFunction = response.data as MakeCustomFunction;
        if (!customFunction) {
          throw new UserError('Custom function creation failed - no data returned');
        }

        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully created custom function', {
          functionId: customFunction.id,
          name: customFunction.name,
          type: customFunction.type,
          language: customFunction.language,
        });

        return formatSuccessResponse({
          function: {
            ...customFunction,
            code: {
              ...customFunction.code,
              source: '[FUNCTION_CODE_STORED]',
            },
          },
          message: `Custom function "${name}" created successfully`,
          configuration: {
            type: customFunction.type,
            language: customFunction.language,
            timeout: customFunction.code.timeout,
            memoryLimit: customFunction.code.memoryLimit,
            testCases: customFunction.testing.testCases.length,
          },
          deployment: {
            version: customFunction.deployment.version,
            environment: customFunction.deployment.environment,
            instances: customFunction.deployment.instances,
            autoScale: customFunction.deployment.autoScale,
          },
          testing: {
            testEndpoint: `/custom-functions/${customFunction.id}/test`,
            deployEndpoint: `/custom-functions/${customFunction.id}/deploy`,
          },
        }).content[0].text;
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error creating custom function', { name, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to create custom function: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add test custom app tool
 */
function addTestCustomAppTool(server: FastMCP, apiClient: MakeApiClient): void {
  server.addTool({
    name: 'test-custom-app',
    description: 'Run tests for a custom app including endpoints, functions, and hooks',
    parameters: z.object({
      appId: z.number().min(1).describe('Custom app ID to test'),
      testType: z.enum(['unit', 'integration', 'endpoints', 'hooks', 'all']).default('all').describe('Type of tests to run'),
      environment: z.enum(['development', 'staging', 'production']).default('development').describe('Test environment'),
      includePerformance: z.boolean().default(false).describe('Include performance testing'),
      timeout: z.number().min(30).max(600).default(120).describe('Test timeout in seconds'),
    }),
    annotations: {
      title: 'Test Custom App',
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    execute: async (input, { log, reportProgress }) => {
      const { appId, testType, environment, includePerformance, timeout } = input;

      log.info('Testing custom app', { appId, testType, environment });

      try {
        reportProgress({ progress: 0, total: 100 });

        const testData = {
          testType,
          environment,
          includePerformance,
          timeout,
        };

        reportProgress({ progress: 25, total: 100 });

        const response = await apiClient.post(`/custom-apps/${appId}/test`, testData);

        if (!response.success) {
          throw new UserError(`Failed to test custom app: ${response.error?.message || 'Unknown error'}`);
        }

        const testResult = response.data as Record<string, unknown>;
        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully tested custom app', {
          appId,
          testType,
          passed: Number((testResult?.summary as Record<string, unknown>)?.passed || 0),
          failed: Number((testResult?.summary as Record<string, unknown>)?.failed || 0),
        });

        return formatSuccessResponse({
          test: testResult,
          message: `Custom app ${appId} testing completed`,
          summary: {
            appId,
            testType,
            environment,
            totalTests: Number((testResult?.summary as Record<string, unknown>)?.total || 0),
            passed: Number((testResult?.summary as Record<string, unknown>)?.passed || 0),
            failed: Number((testResult?.summary as Record<string, unknown>)?.failed || 0),
            duration: (testResult?.summary as Record<string, unknown>)?.duration,
            coverage: testResult?.coverage,
          },
          results: {
            endpoints: (testResult?.results as Record<string, unknown>)?.endpoints || [],
            functions: (testResult?.results as Record<string, unknown>)?.functions || [],
            hooks: (testResult?.results as Record<string, unknown>)?.hooks || [],
            performance: includePerformance ? (testResult?.results as Record<string, unknown>)?.performance || {} : undefined,
          },
          recommendations: testResult?.recommendations || [],
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error testing custom app', { appId, error: errorMessage });
        if (error instanceof UserError) {throw error;}
        throw new UserError(`Failed to test custom app: ${errorMessage}`);
      }
    },
  });
}

/**
 * Add custom app development and management tools to FastMCP server
 */
export function addCustomAppTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'CustomAppTools' });
  
  componentLogger.info('Adding custom app development and management tools');

  // Add all custom app tools
  addCreateCustomAppTool(server, apiClient);
  addListCustomAppsTool(server, apiClient);
  addCreateHookTool(server, apiClient);
  addCreateCustomFunctionTool(server, apiClient);
  addTestCustomAppTool(server, apiClient);

  componentLogger.info('Custom app development and management tools added successfully');
}

export default addCustomAppTools;