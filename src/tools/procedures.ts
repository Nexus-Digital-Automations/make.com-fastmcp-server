/**
 * Remote Procedure and Device Management Tools for Make.com FastMCP Server
 * Comprehensive tools for managing remote procedures, device configurations, and remote execution
 */

import { FastMCP, UserError } from 'fastmcp';
import { z } from 'zod';
import MakeApiClient from '../lib/make-api-client.js';
import logger from '../lib/logger.js';

// Remote procedure and device management types
export interface MakeRemoteProcedure {
  id: number;
  name: string;
  description?: string;
  type: 'webhook' | 'api_call' | 'script_execution' | 'file_transfer' | 'database_operation';
  category: 'incoming' | 'outgoing' | 'bidirectional';
  organizationId?: number;
  teamId?: number;
  status: 'active' | 'inactive' | 'testing' | 'deprecated' | 'error';
  configuration: {
    endpoint?: {
      url: string;
      method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
      headers: Record<string, string>;
      authentication: {
        type: 'none' | 'api_key' | 'bearer_token' | 'basic_auth' | 'oauth2' | 'certificate';
        credentials?: Record<string, unknown>;
      };
      timeout: number;
      retries: number;
    };
    script?: {
      language: 'javascript' | 'python' | 'bash' | 'powershell';
      code: string;
      runtime: string;
      environment: Record<string, string>;
      workingDirectory?: string;
    };
    fileTransfer?: {
      protocol: 'ftp' | 'sftp' | 'scp' | 'http' | 's3';
      source: string;
      destination: string;
      credentials: Record<string, unknown>;
      encryption: boolean;
    };
    database?: {
      type: 'mysql' | 'postgresql' | 'mongodb' | 'redis' | 'sqlite';
      connectionString: string;
      query: string;
      parameters: Record<string, unknown>;
    };
  };
  input: {
    schema: Record<string, unknown>; // JSON Schema for input validation
    example: unknown;
    required: string[];
  };
  output: {
    schema: Record<string, unknown>; // JSON Schema for output validation
    example: unknown;
  };
  execution: {
    totalRuns: number;
    successfulRuns: number;
    failedRuns: number;
    averageExecutionTime: number;
    lastRun?: {
      timestamp: string;
      status: 'success' | 'failure' | 'timeout' | 'error';
      executionTime: number;
      error?: string;
    };
  };
  monitoring: {
    healthCheck: {
      enabled: boolean;
      interval: number; // seconds
      endpoint?: string;
      expectedResponse?: unknown;
    };
    alerts: Array<{
      type: 'failure_rate' | 'response_time' | 'availability' | 'error_pattern';
      threshold: number;
      recipients: string[];
      enabled: boolean;
    }>;
    logging: {
      level: 'none' | 'basic' | 'detailed' | 'verbose';
      retentionDays: number;
      includePayload: boolean;
    };
  };
  security: {
    rateLimiting: {
      enabled: boolean;
      maxRequests: number;
      windowMs: number;
    };
    ipWhitelist?: string[];
    requiresApproval: boolean;
    encryptPayload: boolean;
  };
  createdAt: string;
  updatedAt: string;
  createdBy: number;
  createdByName: string;
}

export interface MakeDevice {
  id: number;
  name: string;
  type: 'server' | 'workstation' | 'mobile' | 'iot' | 'embedded' | 'virtual';
  category: 'incoming' | 'outgoing' | 'hybrid';
  organizationId?: number;
  teamId?: number;
  status: 'online' | 'offline' | 'maintenance' | 'error' | 'unknown';
  configuration: {
    connection: {
      protocol: 'http' | 'https' | 'websocket' | 'mqtt' | 'tcp' | 'udp';
      host: string;
      port: number;
      path?: string;
      secure: boolean;
    };
    authentication: {
      type: 'none' | 'api_key' | 'certificate' | 'ssh_key' | 'username_password';
      credentials?: Record<string, unknown>;
    };
    capabilities: {
      canReceive: boolean;
      canSend: boolean;
      canExecute: boolean;
      supportedFormats: string[];
      maxPayloadSize: number;
    };
    environment: {
      os?: string;
      version?: string;
      architecture?: string;
      runtime?: string;
      customProperties: Record<string, unknown>;
    };
  };
  procedures: Array<{
    procedureId: number;
    procedureName: string;
    role: 'source' | 'target' | 'processor';
    lastUsed?: string;
  }>;
  monitoring: {
    health: {
      lastSeen: string;
      uptime: number; // seconds
      cpuUsage?: number;
      memoryUsage?: number;
      diskUsage?: number;
      networkLatency?: number;
    };
    alerts: Array<{
      type: 'offline' | 'performance' | 'error' | 'security';
      severity: 'low' | 'medium' | 'high' | 'critical';
      message: string;
      timestamp: string;
      acknowledged: boolean;
    }>;
  };
  createdAt: string;
  updatedAt: string;
  createdBy: number;
}

// Input validation schemas
const RemoteProcedureCreateSchema = z.object({
  name: z.string().min(1).max(100).describe('Procedure name (1-100 characters)'),
  description: z.string().max(500).optional().describe('Procedure description (max 500 characters)'),
  type: z.enum(['webhook', 'api_call', 'script_execution', 'file_transfer', 'database_operation']).describe('Procedure type'),
  category: z.enum(['incoming', 'outgoing', 'bidirectional']).describe('Procedure category'),
  organizationId: z.number().min(1).optional().describe('Organization ID (for organization procedures)'),
  teamId: z.number().min(1).optional().describe('Team ID (for team procedures)'),
  configuration: z.union([
    // Webhook/API call configuration
    z.object({
      endpoint: z.object({
        url: z.string().url().describe('Endpoint URL'),
        method: z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']).describe('HTTP method'),
        headers: z.record(z.string()).default({}).describe('HTTP headers'),
        authentication: z.object({
          type: z.enum(['none', 'api_key', 'bearer_token', 'basic_auth', 'oauth2', 'certificate']).describe('Authentication type'),
          credentials: z.record(z.any()).optional().describe('Authentication credentials'),
        }).describe('Authentication configuration'),
        timeout: z.number().min(1000).max(300000).default(30000).describe('Timeout in milliseconds'),
        retries: z.number().min(0).max(5).default(3).describe('Number of retries'),
      }).describe('Endpoint configuration'),
    }),
    // Script execution configuration
    z.object({
      script: z.object({
        language: z.enum(['javascript', 'python', 'bash', 'powershell']).describe('Script language'),
        code: z.string().min(1).describe('Script code'),
        runtime: z.string().describe('Runtime version'),
        environment: z.record(z.string()).default({}).describe('Environment variables'),
        workingDirectory: z.string().optional().describe('Working directory'),
      }).describe('Script configuration'),
    }),
    // File transfer configuration
    z.object({
      fileTransfer: z.object({
        protocol: z.enum(['ftp', 'sftp', 'scp', 'http', 's3']).describe('Transfer protocol'),
        source: z.string().min(1).describe('Source path or URL'),
        destination: z.string().min(1).describe('Destination path or URL'),
        credentials: z.record(z.any()).describe('Transfer credentials'),
        encryption: z.boolean().default(true).describe('Enable encryption'),
      }).describe('File transfer configuration'),
    }),
    // Database operation configuration
    z.object({
      database: z.object({
        type: z.enum(['mysql', 'postgresql', 'mongodb', 'redis', 'sqlite']).describe('Database type'),
        connectionString: z.string().min(1).describe('Database connection string'),
        query: z.string().min(1).describe('SQL query or operation'),
        parameters: z.record(z.any()).default({}).describe('Query parameters'),
      }).describe('Database configuration'),
    }),
  ]).describe('Procedure configuration'),
  input: z.object({
    schema: z.any().describe('JSON Schema for input validation'),
    example: z.any().describe('Example input data'),
    required: z.array(z.string()).default([]).describe('Required input fields'),
  }).describe('Input specification'),
  output: z.object({
    schema: z.any().describe('JSON Schema for output validation'),
    example: z.any().describe('Example output data'),
  }).describe('Output specification'),
  monitoring: z.object({
    healthCheck: z.object({
      enabled: z.boolean().default(false).describe('Enable health checks'),
      interval: z.number().min(60).max(3600).default(300).describe('Health check interval in seconds'),
      endpoint: z.string().url().optional().describe('Health check endpoint'),
      expectedResponse: z.any().optional().describe('Expected health check response'),
    }).default({}).describe('Health check configuration'),
    alerts: z.array(z.object({
      type: z.enum(['failure_rate', 'response_time', 'availability', 'error_pattern']).describe('Alert type'),
      threshold: z.number().min(0).describe('Alert threshold'),
      recipients: z.array(z.string().email()).min(1).describe('Alert recipients'),
      enabled: z.boolean().default(true).describe('Enable alert'),
    })).default([]).describe('Alert configurations'),
    logging: z.object({
      level: z.enum(['none', 'basic', 'detailed', 'verbose']).default('basic').describe('Logging level'),
      retentionDays: z.number().min(1).max(365).default(30).describe('Log retention in days'),
      includePayload: z.boolean().default(false).describe('Include request/response payload in logs'),
    }).default({}).describe('Logging configuration'),
  }).default({}).describe('Monitoring configuration'),
  security: z.object({
    rateLimiting: z.object({
      enabled: z.boolean().default(false).describe('Enable rate limiting'),
      maxRequests: z.number().min(1).default(100).describe('Maximum requests per window'),
      windowMs: z.number().min(1000).default(60000).describe('Rate limit window in milliseconds'),
    }).default({}).describe('Rate limiting configuration'),
    ipWhitelist: z.array(z.string()).optional().describe('IP whitelist for procedure access'),
    requiresApproval: z.boolean().default(false).describe('Require approval before execution'),
    encryptPayload: z.boolean().default(false).describe('Encrypt procedure payload'),
  }).default({}).describe('Security configuration'),
}).strict();

const DeviceCreateSchema = z.object({
  name: z.string().min(1).max(100).describe('Device name (1-100 characters)'),
  type: z.enum(['server', 'workstation', 'mobile', 'iot', 'embedded', 'virtual']).describe('Device type'),
  category: z.enum(['incoming', 'outgoing', 'hybrid']).describe('Device category'),
  organizationId: z.number().min(1).optional().describe('Organization ID (for organization devices)'),
  teamId: z.number().min(1).optional().describe('Team ID (for team devices)'),
  configuration: z.object({
    connection: z.object({
      protocol: z.enum(['http', 'https', 'websocket', 'mqtt', 'tcp', 'udp']).describe('Connection protocol'),
      host: z.string().min(1).describe('Device host/IP address'),
      port: z.number().min(1).max(65535).describe('Connection port'),
      path: z.string().optional().describe('Connection path (for HTTP/WebSocket)'),
      secure: z.boolean().default(true).describe('Use secure connection'),
    }).describe('Connection configuration'),
    authentication: z.object({
      type: z.enum(['none', 'api_key', 'certificate', 'ssh_key', 'username_password']).describe('Authentication type'),
      credentials: z.record(z.any()).optional().describe('Authentication credentials'),
    }).describe('Authentication configuration'),
    capabilities: z.object({
      canReceive: z.boolean().default(true).describe('Can receive data/commands'),
      canSend: z.boolean().default(true).describe('Can send data/responses'),
      canExecute: z.boolean().default(false).describe('Can execute procedures'),
      supportedFormats: z.array(z.string()).default(['json']).describe('Supported data formats'),
      maxPayloadSize: z.number().min(1024).default(1048576).describe('Maximum payload size in bytes'),
    }).default({}).describe('Device capabilities'),
    environment: z.object({
      os: z.string().optional().describe('Operating system'),
      version: z.string().optional().describe('OS/software version'),
      architecture: z.string().optional().describe('System architecture'),
      runtime: z.string().optional().describe('Runtime environment'),
      customProperties: z.record(z.any()).default({}).describe('Custom device properties'),
    }).default({}).describe('Device environment'),
  }).describe('Device configuration'),
}).strict();

const ProcedureExecuteSchema = z.object({
  procedureId: z.number().min(1).describe('Procedure ID to execute'),
  input: z.any().describe('Input data for the procedure'),
  options: z.object({
    async: z.boolean().default(false).describe('Execute asynchronously'),
    timeout: z.number().min(1000).max(600000).optional().describe('Execution timeout in milliseconds'),
    retries: z.number().min(0).max(5).optional().describe('Number of retries on failure'),
    priority: z.enum(['low', 'normal', 'high', 'urgent']).default('normal').describe('Execution priority'),
  }).default({}).describe('Execution options'),
  metadata: z.object({
    correlationId: z.string().optional().describe('Correlation ID for tracking'),
    source: z.string().optional().describe('Source of the execution request'),
    tags: z.record(z.string()).default({}).describe('Execution tags for categorization'),
  }).default({}).describe('Execution metadata'),
}).strict();

/**
 * Add remote procedure and device management tools to FastMCP server
 */
export function addProcedureTools(server: FastMCP, apiClient: MakeApiClient): void {
  const componentLogger = logger.child({ component: 'ProcedureTools' });
  
  componentLogger.info('Adding remote procedure and device management tools');

  // Create remote procedure
  server.addTool({
    name: 'create-remote-procedure',
    description: 'Create a new remote procedure for webhook, API call, script execution, or other operations',
    parameters: RemoteProcedureCreateSchema,
    execute: async (input, { log, reportProgress }) => {
      const { name, description, type, category, organizationId, teamId, configuration, input: inputSpec, output: outputSpec, monitoring, security } = input;

      log.info('Creating remote procedure', {
        name,
        type,
        category,
        organizationId,
        teamId,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        // Validate configuration based on procedure type
        if (type === 'webhook' || type === 'api_call') {
          if (!('endpoint' in configuration)) {
            throw new UserError(`Endpoint configuration required for ${type} procedures`);
          }
        } else if (type === 'script_execution') {
          if (!('script' in configuration)) {
            throw new UserError('Script configuration required for script_execution procedures');
          }
        }

        reportProgress({ progress: 25, total: 100 });

        const procedureData = {
          name,
          description,
          type,
          category,
          organizationId,
          teamId,
          configuration,
          input: inputSpec,
          output: outputSpec,
          monitoring: {
            healthCheck: { ...monitoring.healthCheck, enabled: monitoring.healthCheck?.enabled ?? false, interval: monitoring.healthCheck?.interval ?? 300 },
            alerts: monitoring.alerts || [],
            logging: { ...monitoring.logging, level: monitoring.logging?.level ?? 'basic', retentionDays: monitoring.logging?.retentionDays ?? 30, includePayload: monitoring.logging?.includePayload ?? false },
          },
          security: {
            rateLimiting: { ...security.rateLimiting, enabled: security.rateLimiting?.enabled ?? false, maxRequests: security.rateLimiting?.maxRequests ?? 100, windowMs: security.rateLimiting?.windowMs ?? 60000 },
            ipWhitelist: security.ipWhitelist,
            requiresApproval: security.requiresApproval || false,
            encryptPayload: security.encryptPayload || false,
          },
          status: 'active',
        };

        reportProgress({ progress: 50, total: 100 });

        let endpoint = '/remote-procedures';
        if (organizationId) {
          endpoint = `/organizations/${organizationId}/remote-procedures`;
        } else if (teamId) {
          endpoint = `/teams/${teamId}/remote-procedures`;
        }

        const response = await apiClient.post(endpoint, procedureData);

        if (!response.success) {
          throw new UserError(`Failed to create remote procedure: ${response.error?.message || 'Unknown error'}`);
        }

        const procedure = response.data as MakeRemoteProcedure;
        if (!procedure) {
          throw new UserError('Remote procedure creation failed - no data returned');
        }

        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully created remote procedure', {
          procedureId: procedure.id,
          name: procedure.name,
          type: procedure.type,
          category: procedure.category,
        });

        return JSON.stringify({
          procedure: {
            ...procedure,
            configuration: {
              ...procedure.configuration,
              // Mask sensitive credentials
              endpoint: procedure.configuration.endpoint ? {
                ...procedure.configuration.endpoint,
                authentication: {
                  ...procedure.configuration.endpoint.authentication,
                  credentials: procedure.configuration.endpoint.authentication.credentials ? 
                    '[CREDENTIALS_STORED]' : undefined,
                },
              } : undefined,
              script: procedure.configuration.script ? {
                ...procedure.configuration.script,
                code: '[SCRIPT_CODE_STORED]',
              } : undefined,
            },
          },
          message: `Remote procedure "${name}" created successfully`,
          configuration: {
            type: procedure.type,
            category: procedure.category,
            healthCheckEnabled: procedure.monitoring.healthCheck.enabled,
            alertsConfigured: procedure.monitoring.alerts.length,
            rateLimitingEnabled: procedure.security.rateLimiting.enabled,
            approvalRequired: procedure.security.requiresApproval,
          },
          testUrl: `/remote-procedures/${procedure.id}/test`,
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error creating remote procedure', { name, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to create remote procedure: ${errorMessage}`);
      }
    },
  });

  // List remote procedures
  server.addTool({
    name: 'list-remote-procedures',
    description: 'List and filter remote procedures with execution statistics and monitoring status',
    parameters: z.object({
      type: z.enum(['webhook', 'api_call', 'script_execution', 'file_transfer', 'database_operation', 'all']).default('all').describe('Filter by procedure type'),
      category: z.enum(['incoming', 'outgoing', 'bidirectional', 'all']).default('all').describe('Filter by procedure category'),
      status: z.enum(['active', 'inactive', 'testing', 'deprecated', 'error', 'all']).default('all').describe('Filter by procedure status'),
      organizationId: z.number().min(1).optional().describe('Filter by organization ID'),
      teamId: z.number().min(1).optional().describe('Filter by team ID'),
      includeStats: z.boolean().default(true).describe('Include execution statistics'),
      includeMonitoring: z.boolean().default(false).describe('Include monitoring configuration'),
      limit: z.number().min(1).max(1000).default(100).describe('Maximum number of procedures to return'),
      offset: z.number().min(0).default(0).describe('Number of procedures to skip for pagination'),
      sortBy: z.enum(['name', 'createdAt', 'lastRun', 'successRate', 'totalRuns']).default('name').describe('Sort field'),
      sortOrder: z.enum(['asc', 'desc']).default('asc').describe('Sort order'),
    }),
    execute: async (input, { log }) => {
      const { type, category, status, organizationId, teamId, includeStats, includeMonitoring, limit, offset, sortBy, sortOrder } = input;

      log.info('Listing remote procedures', {
        type,
        category,
        status,
        limit,
        offset,
      });

      try {
        const params: Record<string, unknown> = {
          limit,
          offset,
          sortBy,
          sortOrder,
          includeStats,
          includeMonitoring,
        };

        if (type !== 'all') params.type = type;
        if (category !== 'all') params.category = category;
        if (status !== 'all') params.status = status;
        if (organizationId) params.organizationId = organizationId;
        if (teamId) params.teamId = teamId;

        const response = await apiClient.get('/remote-procedures', { params });

        if (!response.success) {
          throw new UserError(`Failed to list remote procedures: ${response.error?.message || 'Unknown error'}`);
        }

        const procedures = response.data as MakeRemoteProcedure[] || [];
        const metadata = response.metadata;

        log.info('Successfully retrieved remote procedures', {
          count: procedures.length,
          total: metadata?.total,
        });

        // Create execution and monitoring analysis
        const analysis = {
          totalProcedures: metadata?.total || procedures.length,
          typeBreakdown: procedures.reduce((acc: Record<string, number>, proc) => {
            acc[proc.type] = (acc[proc.type] || 0) + 1;
            return acc;
          }, {}),
          categoryBreakdown: procedures.reduce((acc: Record<string, number>, proc) => {
            acc[proc.category] = (acc[proc.category] || 0) + 1;
            return acc;
          }, {}),
          statusBreakdown: procedures.reduce((acc: Record<string, number>, proc) => {
            acc[proc.status] = (acc[proc.status] || 0) + 1;
            return acc;
          }, {}),
          executionSummary: includeStats ? {
            totalExecutions: procedures.reduce((sum, p) => sum + p.execution.totalRuns, 0),
            successfulExecutions: procedures.reduce((sum, p) => sum + p.execution.successfulRuns, 0),
            failedExecutions: procedures.reduce((sum, p) => sum + p.execution.failedRuns, 0),
            averageSuccessRate: procedures.length > 0 ? 
              procedures.reduce((sum, p) => sum + (p.execution.successfulRuns / Math.max(p.execution.totalRuns, 1)), 0) / procedures.length * 100 : 0,
            averageExecutionTime: procedures.length > 0 ? 
              procedures.reduce((sum, p) => sum + p.execution.averageExecutionTime, 0) / procedures.length : 0,
          } : undefined,
          mostActiveProcedures: includeStats ? procedures
            .sort((a, b) => b.execution.totalRuns - a.execution.totalRuns)
            .slice(0, 5)
            .map(p => ({
              id: p.id,
              name: p.name,
              totalRuns: p.execution.totalRuns,
              successRate: Math.round((p.execution.successfulRuns / Math.max(p.execution.totalRuns, 1)) * 100),
            })) : undefined,
          monitoringSummary: includeMonitoring ? {
            healthChecksEnabled: procedures.filter(p => p.monitoring.healthCheck.enabled).length,
            alertsConfigured: procedures.filter(p => p.monitoring.alerts.length > 0).length,
            totalAlerts: procedures.reduce((sum, p) => sum + p.monitoring.alerts.length, 0),
            proceduresWithRateLimit: procedures.filter(p => p.security.rateLimiting.enabled).length,
          } : undefined,
        };

        return JSON.stringify({
          procedures: procedures.map(proc => ({
            ...proc,
            configuration: {
              ...proc.configuration,
              // Mask sensitive data
              endpoint: proc.configuration.endpoint ? {
                ...proc.configuration.endpoint,
                authentication: {
                  ...proc.configuration.endpoint.authentication,
                  credentials: '[CREDENTIALS_HIDDEN]',
                },
              } : undefined,
              script: proc.configuration.script ? {
                ...proc.configuration.script,
                code: '[SCRIPT_CODE_HIDDEN]',
              } : undefined,
            },
          })),
          analysis,
          pagination: {
            total: metadata?.total || procedures.length,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + procedures.length),
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error listing remote procedures', { error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to list remote procedures: ${errorMessage}`);
      }
    },
  });

  // Execute remote procedure
  server.addTool({
    name: 'execute-remote-procedure',
    description: 'Execute a remote procedure with input data and monitoring',
    parameters: ProcedureExecuteSchema,
    execute: async (input, { log, reportProgress }) => {
      const { procedureId, input: inputData, options, metadata } = input;

      log.info('Executing remote procedure', {
        procedureId,
        async: options.async,
        priority: options.priority,
        correlationId: metadata.correlationId,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        const executionData = {
          input: inputData,
          options: {
            ...options,
            async: options?.async ?? false,
            timeout: options?.timeout ?? 30000,
            retries: options?.retries ?? 3,
            priority: options?.priority ?? 'normal',
          },
          metadata: {
            correlationId: metadata.correlationId || `exec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            source: metadata.source || 'fastmcp',
            tags: metadata.tags || {},
            executedAt: new Date().toISOString(),
          },
        };

        reportProgress({ progress: 25, total: 100 });

        const response = await apiClient.post(`/remote-procedures/${procedureId}/execute`, executionData);

        if (!response.success) {
          throw new UserError(`Failed to execute remote procedure: ${response.error?.message || 'Unknown error'}`);
        }

        const executionResult = response.data as Record<string, unknown>;
        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully executed remote procedure', {
          procedureId,
          executionId: String(executionResult?.executionId || 'unknown'),
          status: String(executionResult?.status || 'unknown'),
          executionTime: Number(executionResult?.executionTime || 0),
        });

        return JSON.stringify({
          execution: executionResult,
          message: `Remote procedure ${procedureId} executed successfully`,
          summary: {
            procedureId,
            executionId: executionResult?.executionId,
            status: executionResult?.status,
            executionTime: executionResult?.executionTime,
            correlationId: executionData.metadata.correlationId,
            async: options.async,
            outputSize: executionResult?.output ? JSON.stringify(executionResult.output).length : 0,
          },
          monitoring: {
            logs: executionResult?.logs || [],
            metrics: executionResult?.metrics || {},
            errors: executionResult?.errors || [],
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error executing remote procedure', { procedureId, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to execute remote procedure: ${errorMessage}`);
      }
    },
  });

  // Create device
  server.addTool({
    name: 'create-device',
    description: 'Register a new device for incoming/outgoing connections and procedure execution',
    parameters: DeviceCreateSchema,
    execute: async (input, { log, reportProgress }) => {
      const { name, type, category, organizationId, teamId, configuration } = input;

      log.info('Creating device', {
        name,
        type,
        category,
        host: configuration.connection.host,
        port: configuration.connection.port,
      });

      try {
        reportProgress({ progress: 0, total: 100 });

        const deviceData = {
          name,
          type,
          category,
          organizationId,
          teamId,
          configuration: {
            connection: {
              ...configuration.connection,
              protocol: configuration.connection?.protocol ?? 'https',
              secure: configuration.connection?.secure ?? true,
            },
            authentication: {
              ...configuration.authentication,
              type: configuration.authentication?.type ?? 'none',
            },
            capabilities: {
              ...configuration.capabilities,
              canReceive: configuration.capabilities?.canReceive ?? true,
              canSend: configuration.capabilities?.canSend ?? true,
              canExecute: configuration.capabilities?.canExecute ?? false,
              supportedFormats: configuration.capabilities?.supportedFormats ?? ['json'],
              maxPayloadSize: configuration.capabilities?.maxPayloadSize ?? 1048576,
            },
            environment: {
              ...configuration.environment,
              customProperties: configuration.environment?.customProperties ?? {},
            },
          },
          status: 'unknown', // Will be determined by initial health check
        };

        reportProgress({ progress: 50, total: 100 });

        let endpoint = '/devices';
        if (organizationId) {
          endpoint = `/organizations/${organizationId}/devices`;
        } else if (teamId) {
          endpoint = `/teams/${teamId}/devices`;
        }

        const response = await apiClient.post(endpoint, deviceData);

        if (!response.success) {
          throw new UserError(`Failed to create device: ${response.error?.message || 'Unknown error'}`);
        }

        const device = response.data as MakeDevice;
        if (!device) {
          throw new UserError('Device creation failed - no data returned');
        }

        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully created device', {
          deviceId: device.id,
          name: device.name,
          type: device.type,
          status: device.status,
        });

        return JSON.stringify({
          device: {
            ...device,
            configuration: {
              ...device.configuration,
              authentication: {
                ...device.configuration.authentication,
                credentials: device.configuration.authentication.credentials ? '[CREDENTIALS_STORED]' : undefined,
              },
            },
          },
          message: `Device "${name}" created successfully`,
          configuration: {
            type: device.type,
            category: device.category,
            connection: `${device.configuration.connection.protocol}://${device.configuration.connection.host}:${device.configuration.connection.port}`,
            capabilities: device.configuration.capabilities,
            environment: {
              os: device.configuration.environment.os,
              version: device.configuration.environment.version,
              architecture: device.configuration.environment.architecture,
            },
          },
          nextSteps: [
            'Configure device authentication if needed',
            'Test device connectivity',
            'Associate device with remote procedures',
            'Set up monitoring and alerts',
          ],
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error creating device', { name, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to create device: ${errorMessage}`);
      }
    },
  });

  // List devices
  server.addTool({
    name: 'list-devices',
    description: 'List and filter registered devices with status and monitoring information',
    parameters: z.object({
      type: z.enum(['server', 'workstation', 'mobile', 'iot', 'embedded', 'virtual', 'all']).default('all').describe('Filter by device type'),
      category: z.enum(['incoming', 'outgoing', 'hybrid', 'all']).default('all').describe('Filter by device category'),
      status: z.enum(['online', 'offline', 'maintenance', 'error', 'unknown', 'all']).default('all').describe('Filter by device status'),
      organizationId: z.number().min(1).optional().describe('Filter by organization ID'),
      teamId: z.number().min(1).optional().describe('Filter by team ID'),
      includeHealth: z.boolean().default(true).describe('Include device health information'),
      includeAlerts: z.boolean().default(false).describe('Include active alerts'),
      limit: z.number().min(1).max(1000).default(100).describe('Maximum number of devices to return'),
      offset: z.number().min(0).default(0).describe('Number of devices to skip for pagination'),
      sortBy: z.enum(['name', 'type', 'status', 'lastSeen', 'createdAt']).default('name').describe('Sort field'),
      sortOrder: z.enum(['asc', 'desc']).default('asc').describe('Sort order'),
    }),
    execute: async (input, { log }) => {
      const { type, category, status, organizationId, teamId, includeHealth, includeAlerts, limit, offset, sortBy, sortOrder } = input;

      log.info('Listing devices', {
        type,
        category,
        status,
        limit,
        offset,
      });

      try {
        const params: Record<string, unknown> = {
          limit,
          offset,
          sortBy,
          sortOrder,
          includeHealth,
          includeAlerts,
        };

        if (type !== 'all') params.type = type;
        if (category !== 'all') params.category = category;
        if (status !== 'all') params.status = status;
        if (organizationId) params.organizationId = organizationId;
        if (teamId) params.teamId = teamId;

        const response = await apiClient.get('/devices', { params });

        if (!response.success) {
          throw new UserError(`Failed to list devices: ${response.error?.message || 'Unknown error'}`);
        }

        const devices = response.data as MakeDevice[] || [];
        const metadata = response.metadata;

        log.info('Successfully retrieved devices', {
          count: devices.length,
          total: metadata?.total,
        });

        // Create device and health analysis
        const analysis = {
          totalDevices: metadata?.total || devices.length,
          typeBreakdown: devices.reduce((acc: Record<string, number>, device) => {
            acc[device.type] = (acc[device.type] || 0) + 1;
            return acc;
          }, {}),
          categoryBreakdown: devices.reduce((acc: Record<string, number>, device) => {
            acc[device.category] = (acc[device.category] || 0) + 1;
            return acc;
          }, {}),
          statusBreakdown: devices.reduce((acc: Record<string, number>, device) => {
            acc[device.status] = (acc[device.status] || 0) + 1;
            return acc;
          }, {}),
          healthSummary: includeHealth ? {
            onlineDevices: devices.filter(d => d.status === 'online').length,
            offlineDevices: devices.filter(d => d.status === 'offline').length,
            devicesWithAlerts: devices.filter(d => d.monitoring.alerts.some(a => !a.acknowledged)).length,
            averageUptime: devices.length > 0 ? 
              devices.reduce((sum, d) => sum + (d.monitoring.health.uptime || 0), 0) / devices.length : 0,
            devicesWithPerformanceData: devices.filter(d => 
              d.monitoring.health.cpuUsage !== undefined || 
              d.monitoring.health.memoryUsage !== undefined
            ).length,
          } : undefined,
          connectivitySummary: {
            protocolBreakdown: devices.reduce((acc: Record<string, number>, device) => {
              acc[device.configuration.connection.protocol] = (acc[device.configuration.connection.protocol] || 0) + 1;
              return acc;
            }, {}),
            secureConnections: devices.filter(d => d.configuration.connection.secure).length,
            authenticatedDevices: devices.filter(d => d.configuration.authentication.type !== 'none').length,
          },
          procedureAssociations: {
            devicesWithProcedures: devices.filter(d => d.procedures.length > 0).length,
            totalProcedureAssociations: devices.reduce((sum, d) => sum + d.procedures.length, 0),
            mostConnectedDevice: devices.reduce((max, d) => 
              d.procedures.length > (max?.procedures.length || 0) ? d : max, devices[0]),
          },
        };

        return JSON.stringify({
          devices: devices.map(device => ({
            ...device,
            configuration: {
              ...device.configuration,
              authentication: {
                ...device.configuration.authentication,
                credentials: '[CREDENTIALS_HIDDEN]',
              },
            },
          })),
          analysis,
          pagination: {
            total: metadata?.total || devices.length,
            limit,
            offset,
            hasMore: (metadata?.total || 0) > (offset + devices.length),
          },
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error listing devices', { error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to list devices: ${errorMessage}`);
      }
    },
  });

  // Test device connectivity
  server.addTool({
    name: 'test-device-connectivity',
    description: 'Test connectivity and health of a registered device',
    parameters: z.object({
      deviceId: z.number().min(1).describe('Device ID to test'),
      testType: z.enum(['ping', 'health_check', 'full_diagnostic', 'authentication']).default('health_check').describe('Type of connectivity test'),
      timeout: z.number().min(1000).max(60000).default(10000).describe('Test timeout in milliseconds'),
      includePerformance: z.boolean().default(true).describe('Include performance metrics in test'),
    }),
    execute: async (input, { log, reportProgress }) => {
      const { deviceId, testType, timeout, includePerformance } = input;

      log.info('Testing device connectivity', { deviceId, testType, timeout });

      try {
        reportProgress({ progress: 0, total: 100 });

        const requestData = {
          testType,
          timeout,
          includePerformance,
        };

        reportProgress({ progress: 25, total: 100 });

        const response = await apiClient.post(`/devices/${deviceId}/test`, requestData);

        if (!response.success) {
          throw new UserError(`Failed to test device connectivity: ${response.error?.message || 'Unknown error'}`);
        }

        const testResult = response.data;
        
        // Type guard for test result
        const testData = testResult && typeof testResult === 'object' ? testResult as Record<string, unknown> : {};
        const success = typeof testData.success === 'boolean' ? testData.success : false;
        const responseTime = typeof testData.responseTime === 'number' ? testData.responseTime : undefined;
        
        reportProgress({ progress: 100, total: 100 });

        log.info('Successfully tested device connectivity', {
          deviceId,
          testType,
          success: success,
          responseTime: responseTime,
        });

        // Additional type guards for summary and diagnostics
        const deviceStatus = typeof testData.deviceStatus === 'string' ? testData.deviceStatus : 'unknown';
        const errors = Array.isArray(testData.errors) ? testData.errors : [];
        const warnings = Array.isArray(testData.warnings) ? testData.warnings : [];
        const recommendations = Array.isArray(testData.recommendations) ? testData.recommendations : [];
        
        const diagnostics = testData.diagnostics && typeof testData.diagnostics === 'object' ? testData.diagnostics as Record<string, unknown> : {};
        const connectivity = diagnostics.connectivity && typeof diagnostics.connectivity === 'object' ? diagnostics.connectivity : {};
        const authentication = diagnostics.authentication && typeof diagnostics.authentication === 'object' ? diagnostics.authentication : {};
        const performance = diagnostics.performance && typeof diagnostics.performance === 'object' ? diagnostics.performance : {};
        const capabilities = diagnostics.capabilities && typeof diagnostics.capabilities === 'object' ? diagnostics.capabilities : {};

        return JSON.stringify({
          test: testResult,
          message: `Device ${deviceId} connectivity test completed`,
          summary: {
            deviceId,
            testType,
            success: success,
            responseTime: responseTime,
            status: deviceStatus,
            errors: errors,
            warnings: warnings,
          },
          diagnostics: {
            connectivity: connectivity,
            authentication: authentication,
            performance: includePerformance ? performance : undefined,
            capabilities: capabilities,
          },
          recommendations: recommendations,
        }, null, 2);
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        log.error('Error testing device connectivity', { deviceId, error: errorMessage });
        if (error instanceof UserError) throw error;
        throw new UserError(`Failed to test device connectivity: ${errorMessage}`);
      }
    },
  });

  componentLogger.info('Remote procedure and device management tools added successfully');
}

export default addProcedureTools;