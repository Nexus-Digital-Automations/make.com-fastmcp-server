/**
 * Unit tests for remote procedure and device management tools
 * Tests procedure execution, device connectivity, configuration validation, and monitoring
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { UserError } from 'fastmcp';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';
import { 
  createMockServer, 
  findTool, 
  executeTool, 
  expectToolCall,
  expectProgressReported,
  expectValidZodParse,
  expectInvalidZodParse
} from '../../utils/test-helpers.js';
import type { 
  MakeRemoteProcedure, 
  MakeDevice 
} from '../../../src/tools/procedures.js';

describe('Remote Procedure and Device Management Tools - Comprehensive Test Suite', () => {
  let mockServer: any;
  let mockApiClient: MockMakeApiClient;
  let mockTool: jest.MockedFunction<any>;
  let mockLog: jest.MockedFunction<any>;
  let mockReportProgress: jest.MockedFunction<any>;

  // Helper to parse response format consistently
  const parseToolResult = (result: any) => {
    const resultText = result.content?.[0]?.text || result;
    return typeof resultText === 'string' ? JSON.parse(resultText) : resultText;
  };

  const testRemoteProcedure: MakeRemoteProcedure = {
    id: 1,
    name: 'Test Webhook Procedure',
    description: 'A test webhook procedure for integration testing',
    type: 'webhook',
    category: 'incoming',
    organizationId: 123,
    teamId: 456,
    status: 'active',
    configuration: {
      endpoint: {
        url: 'https://api.example.com/webhook',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer token'
        },
        authentication: {
          type: 'bearer_token',
          credentials: { token: 'secret-token' }
        },
        timeout: 30000,
        retries: 3
      }
    },
    input: {
      schema: {
        type: 'object',
        properties: {
          data: { type: 'string' },
          priority: { type: 'number' }
        },
        required: ['data']
      },
      example: { data: 'test data', priority: 1 },
      required: ['data']
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          success: { type: 'boolean' },
          result: { type: 'string' }
        }
      },
      example: { success: true, result: 'processed' }
    },
    execution: {
      totalRuns: 150,
      successfulRuns: 142,
      failedRuns: 8,
      averageExecutionTime: 2.5,
      lastRun: {
        timestamp: '2024-01-01T12:00:00Z',
        status: 'success',
        executionTime: 1.8,
        error: undefined
      }
    },
    monitoring: {
      healthCheck: {
        enabled: true,
        interval: 300,
        endpoint: 'https://api.example.com/health',
        expectedResponse: { status: 'ok' }
      },
      alerts: [
        {
          type: 'failure_rate',
          threshold: 0.1,
          recipients: ['admin@example.com'],
          enabled: true
        }
      ],
      logging: {
        level: 'detailed',
        retentionDays: 30,
        includePayload: true
      }
    },
    security: {
      rateLimiting: {
        enabled: true,
        maxRequests: 100,
        windowMs: 60000
      },
      ipWhitelist: ['192.168.1.0/24'],
      requiresApproval: false,
      encryptPayload: true
    },
    createdAt: '2023-12-01T10:00:00Z',
    updatedAt: '2024-01-01T09:00:00Z',
    createdBy: 1,
    createdByName: 'Test User'
  };

  const testScriptProcedure: MakeRemoteProcedure = {
    ...testRemoteProcedure,
    id: 2,
    name: 'Test Script Procedure',
    type: 'script_execution',
    configuration: {
      script: {
        language: 'python',
        code: 'print("Hello World")',
        runtime: 'python3.9',
        environment: {
          PYTHONPATH: '/usr/local/lib',
          DEBUG: 'true'
        },
        workingDirectory: '/tmp/scripts'
      }
    }
  };

  const testDevice: MakeDevice = {
    id: 1,
    name: 'Test Server Device',
    type: 'server',
    category: 'hybrid',
    organizationId: 123,
    teamId: 456,
    status: 'online',
    configuration: {
      connection: {
        protocol: 'https',
        host: 'device.example.com',
        port: 443,
        path: '/api',
        secure: true
      },
      authentication: {
        type: 'api_key',
        credentials: { apiKey: 'device-secret-key' }
      },
      capabilities: {
        canReceive: true,
        canSend: true,
        canExecute: true,
        supportedFormats: ['json', 'xml'],
        maxPayloadSize: 2097152
      },
      environment: {
        os: 'Ubuntu',
        version: '20.04 LTS',
        architecture: 'x86_64',
        runtime: 'Node.js 18.x',
        customProperties: {
          location: 'data-center-1',
          timezone: 'UTC'
        }
      }
    },
    procedures: [
      {
        procedureId: 1,
        procedureName: 'Test Webhook Procedure',
        role: 'target',
        lastUsed: '2024-01-01T11:30:00Z'
      }
    ],
    monitoring: {
      health: {
        lastSeen: '2024-01-01T12:00:00Z',
        uptime: 86400,
        cpuUsage: 45.2,
        memoryUsage: 62.8,
        diskUsage: 33.1,
        networkLatency: 12.5
      },
      alerts: [
        {
          type: 'performance',
          severity: 'medium',
          message: 'High memory usage detected',
          timestamp: '2024-01-01T11:45:00Z',
          acknowledged: false
        }
      ]
    },
    createdAt: '2023-12-01T10:00:00Z',
    updatedAt: '2024-01-01T09:00:00Z',
    createdBy: 1
  };

  beforeEach(() => {
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockTool = serverSetup.mockTool;
    mockApiClient = new MockMakeApiClient();
    mockLog = jest.fn();
    mockReportProgress = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
    mockApiClient.reset();
  });

  describe('Tool Registration and Configuration', () => {
    it('should register all procedure and device management tools with correct configuration', async () => {
      const { addProcedureTools } = await import('../../../src/tools/procedures.js');
      addProcedureTools(mockServer, mockApiClient as any);
      
      const expectedTools = [
        'create-remote-procedure',
        'list-remote-procedures',
        'execute-remote-procedure',
        'create-device',
        'list-devices',
        'test-device-connectivity'
      ];

      expectedTools.forEach(toolName => {
        const tool = findTool(mockTool, toolName);
        expect(tool).toBeDefined();
        expect(tool.name).toBe(toolName);
        expect(tool.description).toBeDefined();
        expect(tool.parameters).toBeDefined();
      });
    });
  });

  describe('Remote Procedure Management', () => {
    describe('create-remote-procedure tool', () => {
      it('should create webhook procedure successfully', async () => {
        mockApiClient.mockResponse('POST', '/remote-procedures', {
          success: true,
          data: testRemoteProcedure
        });

        const { addProcedureTools } = await import('../../../src/tools/procedures.js');
        addProcedureTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-remote-procedure');
        const result = await executeTool(tool, {
          name: 'Test Webhook Procedure',
          description: 'A test webhook procedure for integration testing',
          type: 'webhook',
          category: 'incoming',
          organizationId: 123,
          teamId: 456,
          configuration: {
            endpoint: {
              url: 'https://api.example.com/webhook',
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer token'
              },
              authentication: {
                type: 'bearer_token',
                credentials: { token: 'secret-token' }
              },
              timeout: 30000,
              retries: 3
            }
          },
          input: {
            schema: {
              type: 'object',
              properties: {
                data: { type: 'string' },
                priority: { type: 'number' }
              },
              required: ['data']
            },
            example: { data: 'test data', priority: 1 },
            required: ['data']
          },
          output: {
            schema: {
              type: 'object',
              properties: {
                success: { type: 'boolean' },
                result: { type: 'string' }
              }
            },
            example: { success: true, result: 'processed' }
          },
          monitoring: {
            healthCheck: {
              enabled: true,
              interval: 300,
              endpoint: 'https://api.example.com/health',
              expectedResponse: { status: 'ok' }
            },
            alerts: [{
              type: 'failure_rate',
              threshold: 0.1,
              recipients: ['admin@example.com'],
              enabled: true
            }],
            logging: {
              level: 'detailed',
              retentionDays: 30,
              includePayload: true
            }
          },
          security: {
            rateLimiting: {
              enabled: true,
              maxRequests: 100,
              windowMs: 60000
            },
            ipWhitelist: ['192.168.1.0/24'],
            requiresApproval: false,
            encryptPayload: true
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        expect(result).toContain('Test Webhook Procedure');
        expect(result).toContain('created successfully');
        expect(result).toContain('testUrl');
        expect(result).toContain('[CREDENTIALS_STORED]');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/remote-procedures');
        expect(calls[0].method).toBe('POST');
        expect(calls[0].data.name).toBe('Test Webhook Procedure');
        expect(calls[0].data.type).toBe('webhook');
        
        expectProgressReported(mockReportProgress, [
          { progress: 0, total: 100 },
          { progress: 25, total: 100 },
          { progress: 50, total: 100 },
          { progress: 100, total: 100 }
        ]);
      });

      it('should create script execution procedure successfully', async () => {
        mockApiClient.mockResponse('POST', '/remote-procedures', {
          success: true,
          data: testScriptProcedure
        });

        const { addProcedureTools } = await import('../../../src/tools/procedures.js');
        addProcedureTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-remote-procedure');
        const result = await executeTool(tool, {
          name: 'Test Script Procedure',
          type: 'script_execution',
          category: 'outgoing',
          configuration: {
            script: {
              language: 'python',
              code: 'print("Hello World")',
              runtime: 'python3.9',
              environment: {
                PYTHONPATH: '/usr/local/lib',
                DEBUG: 'true'
              },
              workingDirectory: '/tmp/scripts'
            }
          },
          input: {
            schema: { type: 'object' },
            example: {},
            required: []
          },
          output: {
            schema: { type: 'object' },
            example: {}
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        expect(result).toContain('Test Script Procedure');
        expect(result).toContain('[SCRIPT_CODE_STORED]');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.configuration.script.language).toBe('python');
        expect(calls[0].data.configuration.script.runtime).toBe('python3.9');
      });

      it('should create organization-scoped procedure', async () => {
        const orgId = 789;
        mockApiClient.mockResponse('POST', `/organizations/${orgId}/remote-procedures`, {
          success: true,
          data: { ...testRemoteProcedure, organizationId: orgId }
        });

        const { addProcedureTools } = await import('../../../src/tools/procedures.js');
        addProcedureTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-remote-procedure');
        await executeTool(tool, {
          name: 'Org Procedure',
          type: 'api_call',
          category: 'bidirectional',
          organizationId: orgId,
          configuration: {
            endpoint: {
              url: 'https://api.org.com/endpoint',
              method: 'GET',
              headers: {},
              authentication: { type: 'none' },
              timeout: 15000,
              retries: 1
            }
          },
          input: {
            schema: { type: 'object' },
            example: {},
            required: []
          },
          output: {
            schema: { type: 'object' },
            example: {}
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe(`/organizations/${orgId}/remote-procedures`);
        expect(calls[0].data.organizationId).toBe(orgId);
      });

      it('should validate configuration based on procedure type', async () => {
        const { addProcedureTools } = await import('../../../src/tools/procedures.js');
        addProcedureTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-remote-procedure');
        
        await expect(executeTool(tool, {
          name: 'Invalid Webhook',
          type: 'webhook',
          category: 'incoming',
          configuration: {
            script: { // Wrong configuration type for webhook
              language: 'python',
              code: 'print("test")',
              runtime: 'python3.9',
              environment: {}
            }
          },
          input: { schema: {}, example: {}, required: [] },
          output: { schema: {}, example: {} }
        }, { log: mockLog })).rejects.toThrow('Endpoint configuration required for webhook procedures');
      });

      it('should validate input parameters with Zod schema', async () => {
        const { addProcedureTools } = await import('../../../src/tools/procedures.js');
        addProcedureTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-remote-procedure');
        
        // Test invalid procedure type
        await expectInvalidZodParse(() => 
          executeTool(tool, {
            name: 'Test',
            type: 'invalid-type',
            category: 'incoming',
            configuration: {},
            input: { schema: {}, example: {}, required: [] },
            output: { schema: {}, example: {} }
          }, { log: mockLog })
        );
        
        // Test invalid category
        await expectInvalidZodParse(() => 
          executeTool(tool, {
            name: 'Test',
            type: 'webhook',
            category: 'invalid-category',
            configuration: {},
            input: { schema: {}, example: {}, required: [] },
            output: { schema: {}, example: {} }
          }, { log: mockLog })
        );
        
        // Test empty name
        await expectInvalidZodParse(() => 
          executeTool(tool, {
            name: '',
            type: 'webhook',
            category: 'incoming',
            configuration: {},
            input: { schema: {}, example: {}, required: [] },
            output: { schema: {}, example: {} }
          }, { log: mockLog })
        );
      });
    });

    describe('list-remote-procedures tool', () => {
      it('should list procedures with default filters and analytics', async () => {
        const proceduresList = [
          testRemoteProcedure,
          { ...testScriptProcedure, id: 2, execution: { totalRuns: 75, successfulRuns: 70, failedRuns: 5, averageExecutionTime: 3.2 } },
          { ...testRemoteProcedure, id: 3, type: 'database_operation', status: 'inactive', execution: { totalRuns: 0, successfulRuns: 0, failedRuns: 0, averageExecutionTime: 0 } }
        ];

        mockApiClient.mockResponse('GET', '/remote-procedures', {
          success: true,
          data: proceduresList,
          metadata: { total: 3 }
        });

        const { addProcedureTools } = await import('../../../src/tools/procedures.js');
        addProcedureTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-remote-procedures');
        const result = await executeTool(tool, {}, { log: mockLog });
        
        const parsed = parseToolResult(result);
        expect(parsed.procedures).toHaveLength(3);
        expect(parsed.analysis.totalProcedures).toBe(3);
        expect(parsed.analysis.typeBreakdown.webhook).toBe(2);
        expect(parsed.analysis.typeBreakdown.script_execution).toBe(1);
        expect(parsed.analysis.statusBreakdown.active).toBe(2);
        expect(parsed.analysis.statusBreakdown.inactive).toBe(1);
        expect(parsed.analysis.executionSummary.totalExecutions).toBe(225);
        expect(parsed.analysis.mostActiveProcedures).toHaveLength(3);
        
        // Verify credentials are masked
        expect(parsed.procedures[0].configuration.endpoint.authentication.credentials).toBe('[CREDENTIALS_HIDDEN]');
        expect(parsed.procedures[1].configuration.script.code).toBe('[SCRIPT_CODE_HIDDEN]');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].params.includeStats).toBe(true);
        expect(calls[0].params.limit).toBe(100);
        expect(calls[0].params.sortBy).toBe('name');
      });

      it('should filter procedures by type, category, and status', async () => {
        mockApiClient.mockResponse('GET', '/remote-procedures', {
          success: true,
          data: [testRemoteProcedure],
          metadata: { total: 1 }
        });

        const { addProcedureTools } = await import('../../../src/tools/procedures.js');
        addProcedureTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-remote-procedures');
        await executeTool(tool, {
          type: 'webhook',
          category: 'incoming',
          status: 'active',
          organizationId: 123,
          teamId: 456,
          includeMonitoring: true,
          sortBy: 'lastRun',
          sortOrder: 'desc'
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].params.type).toBe('webhook');
        expect(calls[0].params.category).toBe('incoming');
        expect(calls[0].params.status).toBe('active');
        expect(calls[0].params.organizationId).toBe(123);
        expect(calls[0].params.teamId).toBe(456);
        expect(calls[0].params.includeMonitoring).toBe(true);
        expect(calls[0].params.sortBy).toBe('lastRun');
        expect(calls[0].params.sortOrder).toBe('desc');
      });

      it('should include monitoring summary when requested', async () => {
        const proceduresWithMonitoring = [
          { ...testRemoteProcedure, monitoring: { ...testRemoteProcedure.monitoring, healthCheck: { enabled: true }, alerts: [{}] } },
          { ...testScriptProcedure, monitoring: { healthCheck: { enabled: false }, alerts: [], logging: {} } }
        ];

        mockApiClient.mockResponse('GET', '/remote-procedures', {
          success: true,
          data: proceduresWithMonitoring,
          metadata: { total: 2 }
        });

        const { addProcedureTools } = await import('../../../src/tools/procedures.js');
        addProcedureTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-remote-procedures');
        const result = await executeTool(tool, { includeMonitoring: true }, { log: mockLog });
        
        const parsed = parseToolResult(result);
        expect(parsed.analysis.monitoringSummary.healthChecksEnabled).toBe(1);
        expect(parsed.analysis.monitoringSummary.alertsConfigured).toBe(1);
        expect(parsed.analysis.monitoringSummary.totalAlerts).toBe(1);
      });
    });

    describe('execute-remote-procedure tool', () => {
      it('should execute procedure successfully with monitoring', async () => {
        const executionResult = {
          executionId: 'exec_123',
          status: 'success',
          executionTime: 1.8,
          output: { success: true, result: 'processed data' },
          logs: ['Started execution', 'Processing input', 'Completed successfully'],
          metrics: { cpuUsage: 25.5, memoryUsage: 128 },
          errors: []
        };

        mockApiClient.mockResponse('POST', '/remote-procedures/1/execute', {
          success: true,
          data: executionResult
        });

        const { addProcedureTools } = await import('../../../src/tools/procedures.js');
        addProcedureTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'execute-remote-procedure');
        const result = await executeTool(tool, {
          procedureId: 1,
          input: { data: 'test input', priority: 5 },
          options: {
            async: false,
            timeout: 30000,
            retries: 2,
            priority: 'high'
          },
          metadata: {
            correlationId: 'test-correlation-123',
            source: 'test-client',
            tags: { environment: 'testing', version: '1.0' }
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsed = parseToolResult(result);
        expect(parsed.execution.executionId).toBe('exec_123');
        expect(parsed.execution.status).toBe('success');
        expect(parsed.summary.executionTime).toBe(1.8);
        expect(parsed.summary.correlationId).toBe('test-correlation-123');
        expect(parsed.monitoring.logs).toHaveLength(3);
        expect(parsed.monitoring.metrics.cpuUsage).toBe(25.5);
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/remote-procedures/1/execute');
        expect(calls[0].data.input).toEqual({ data: 'test input', priority: 5 });
        expect(calls[0].data.options.priority).toBe('high');
        expect(calls[0].data.metadata.correlationId).toBe('test-correlation-123');
        
        expectProgressReported(mockReportProgress, [
          { progress: 0, total: 100 },
          { progress: 25, total: 100 },
          { progress: 100, total: 100 }
        ]);
      });

      it('should execute async procedure with correlation tracking', async () => {
        const asyncResult = {
          executionId: 'async_exec_456',
          status: 'submitted',
          correlationId: 'auto-generated-id',
          estimatedCompletion: '2024-01-01T12:05:00Z'
        };

        mockApiClient.mockResponse('POST', '/remote-procedures/2/execute', {
          success: true,
          data: asyncResult
        });

        const { addProcedureTools } = await import('../../../src/tools/procedures.js');
        addProcedureTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'execute-remote-procedure');
        const result = await executeTool(tool, {
          procedureId: 2,
          input: { script_params: { env: 'production' } },
          options: { async: true, priority: 'urgent' }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsed = parseToolResult(result);
        expect(parsed.execution.status).toBe('submitted');
        expect(parsed.summary.async).toBe(true);
        expect(parsed.summary.correlationId).toMatch(/exec_\d+_[a-z0-9]+/);
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.options.async).toBe(true);
        expect(calls[0].data.metadata.source).toBe('fastmcp');
      });

      it('should handle execution failures gracefully', async () => {
        mockApiClient.mockResponse('POST', '/remote-procedures/1/execute', {
          success: false,
          error: { message: 'Procedure execution failed: timeout' }
        });

        const { addProcedureTools } = await import('../../../src/tools/procedures.js');
        addProcedureTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'execute-remote-procedure');
        
        await expect(executeTool(tool, {
          procedureId: 1,
          input: { data: 'test' }
        }, { log: mockLog })).rejects.toThrow('Failed to execute remote procedure: Procedure execution failed: timeout');
      });

      it('should validate execution input parameters', async () => {
        const { addProcedureTools } = await import('../../../src/tools/procedures.js');
        addProcedureTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'execute-remote-procedure');
        
        // Test invalid procedure ID
        await expectInvalidZodParse(() => 
          executeTool(tool, {
            procedureId: 0,
            input: {}
          }, { log: mockLog })
        );
        
        // Test invalid priority
        await expectInvalidZodParse(() => 
          executeTool(tool, {
            procedureId: 1,
            input: {},
            options: { priority: 'invalid-priority' }
          }, { log: mockLog })
        );
        
        // Test invalid timeout
        await expectInvalidZodParse(() => 
          executeTool(tool, {
            procedureId: 1,
            input: {},
            options: { timeout: 500 } // Too low
          }, { log: mockLog })
        );
      });
    });
  });

  describe('Device Management', () => {
    describe('create-device tool', () => {
      it('should create device successfully with full configuration', async () => {
        mockApiClient.mockResponse('POST', '/devices', {
          success: true,
          data: testDevice
        });

        const { addProcedureTools } = await import('../../../src/tools/procedures.js');
        addProcedureTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-device');
        const result = await executeTool(tool, {
          name: 'Test Server Device',
          type: 'server',
          category: 'hybrid',
          organizationId: 123,
          teamId: 456,
          configuration: {
            connection: {
              protocol: 'https',
              host: 'device.example.com',
              port: 443,
              path: '/api',
              secure: true
            },
            authentication: {
              type: 'api_key',
              credentials: { apiKey: 'device-secret-key' }
            },
            capabilities: {
              canReceive: true,
              canSend: true,
              canExecute: true,
              supportedFormats: ['json', 'xml'],
              maxPayloadSize: 2097152
            },
            environment: {
              os: 'Ubuntu',
              version: '20.04 LTS',
              architecture: 'x86_64',
              runtime: 'Node.js 18.x',
              customProperties: {
                location: 'data-center-1',
                timezone: 'UTC'
              }
            }
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        expect(result).toContain('Test Server Device');
        expect(result).toContain('created successfully');
        expect(result).toContain('nextSteps');
        expect(result).toContain('[CREDENTIALS_STORED]');
        
        const parsed = parseToolResult(result);
        expect(parsed.configuration.connection).toBe('https://device.example.com:443');
        expect(parsed.configuration.capabilities.canExecute).toBe(true);
        expect(parsed.configuration.environment.os).toBe('Ubuntu');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/devices');
        expect(calls[0].data.name).toBe('Test Server Device');
        expect(calls[0].data.type).toBe('server');
        expect(calls[0].data.configuration.connection.protocol).toBe('https');
        
        expectProgressReported(mockReportProgress, [
          { progress: 0, total: 100 },
          { progress: 50, total: 100 },
          { progress: 100, total: 100 }
        ]);
      });

      it('should create organization-scoped device', async () => {
        const orgId = 789;
        mockApiClient.mockResponse('POST', `/organizations/${orgId}/devices`, {
          success: true,
          data: { ...testDevice, organizationId: orgId }
        });

        const { addProcedureTools } = await import('../../../src/tools/procedures.js');
        addProcedureTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-device');
        await executeTool(tool, {
          name: 'Org Device',
          type: 'iot',
          category: 'incoming',
          organizationId: orgId,
          configuration: {
            connection: {
              protocol: 'mqtt',
              host: 'iot.org.com',
              port: 1883,
              secure: false
            },
            authentication: { type: 'none' },
            capabilities: { canReceive: true, canSend: false }
          }
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe(`/organizations/${orgId}/devices`);
      });

      it('should create different device types with appropriate configurations', async () => {
        const deviceTypes = [
          { type: 'mobile', protocol: 'websocket', port: 8080 },
          { type: 'iot', protocol: 'mqtt', port: 1883 },
          { type: 'embedded', protocol: 'tcp', port: 9999 },
          { type: 'virtual', protocol: 'http', port: 80 }
        ];

        for (const deviceConfig of deviceTypes) {
          mockApiClient.mockResponse('POST', '/devices', {
            success: true,
            data: { ...testDevice, type: deviceConfig.type }
          });

          const { addProcedureTools } = await import('../../../src/tools/procedures.js');
          addProcedureTools(mockServer, mockApiClient as any);
          
          const tool = findTool(mockTool, 'create-device');
          await executeTool(tool, {
            name: `Test ${deviceConfig.type} Device`,
            type: deviceConfig.type as any,
            category: 'outgoing',
            configuration: {
              connection: {
                protocol: deviceConfig.protocol as any,
                host: `${deviceConfig.type}.example.com`,
                port: deviceConfig.port,
                secure: deviceConfig.protocol.includes('s')
              },
              authentication: { type: 'none' }
            }
          }, { log: mockLog, reportProgress: mockReportProgress });
          
          mockApiClient.reset();
        }
      });

      it('should validate device configuration parameters', async () => {
        const { addProcedureTools } = await import('../../../src/tools/procedures.js');
        addProcedureTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'create-device');
        
        // Test invalid device type
        await expectInvalidZodParse(() => 
          executeTool(tool, {
            name: 'Test Device',
            type: 'invalid-type',
            category: 'incoming',
            configuration: {
              connection: { protocol: 'http', host: 'test.com', port: 80 },
              authentication: { type: 'none' }
            }
          }, { log: mockLog })
        );
        
        // Test invalid port
        await expectInvalidZodParse(() => 
          executeTool(tool, {
            name: 'Test Device',
            type: 'server',
            category: 'incoming',
            configuration: {
              connection: { protocol: 'http', host: 'test.com', port: 0 },
              authentication: { type: 'none' }
            }
          }, { log: mockLog })
        );
        
        // Test empty host
        await expectInvalidZodParse(() => 
          executeTool(tool, {
            name: 'Test Device',
            type: 'server',
            category: 'incoming',
            configuration: {
              connection: { protocol: 'http', host: '', port: 80 },
              authentication: { type: 'none' }
            }
          }, { log: mockLog })
        );
      });
    });

    describe('list-devices tool', () => {
      it('should list devices with comprehensive analytics', async () => {
        const devicesList = [
          testDevice,
          { ...testDevice, id: 2, type: 'iot', status: 'offline', configuration: { ...testDevice.configuration, connection: { ...testDevice.configuration.connection, protocol: 'mqtt' } } },
          { ...testDevice, id: 3, type: 'mobile', category: 'incoming', status: 'maintenance', monitoring: { ...testDevice.monitoring, alerts: [] } }
        ];

        mockApiClient.mockResponse('GET', '/devices', {
          success: true,
          data: devicesList,
          metadata: { total: 3 }
        });

        const { addProcedureTools } = await import('../../../src/tools/procedures.js');
        addProcedureTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-devices');
        const result = await executeTool(tool, {}, { log: mockLog });
        
        const parsed = parseToolResult(result);
        expect(parsed.devices).toHaveLength(3);
        expect(parsed.analysis.totalDevices).toBe(3);
        expect(parsed.analysis.typeBreakdown.server).toBe(1);
        expect(parsed.analysis.typeBreakdown.iot).toBe(1);
        expect(parsed.analysis.typeBreakdown.mobile).toBe(1);
        expect(parsed.analysis.statusBreakdown.online).toBe(1);
        expect(parsed.analysis.statusBreakdown.offline).toBe(1);
        expect(parsed.analysis.statusBreakdown.maintenance).toBe(1);
        expect(parsed.analysis.connectivitySummary.protocolBreakdown.https).toBe(2);
        expect(parsed.analysis.connectivitySummary.protocolBreakdown.mqtt).toBe(1);
        expect(parsed.analysis.connectivitySummary.secureConnections).toBe(2);
        expect(parsed.analysis.procedureAssociations.devicesWithProcedures).toBe(3);
        
        // Verify credentials are masked
        expect(parsed.devices[0].configuration.authentication.credentials).toBe('[CREDENTIALS_HIDDEN]');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].params.includeHealth).toBe(true);
        expect(calls[0].params.sortBy).toBe('name');
      });

      it('should filter devices by type, category, and status', async () => {
        mockApiClient.mockResponse('GET', '/devices', {
          success: true,
          data: [testDevice],
          metadata: { total: 1 }
        });

        const { addProcedureTools } = await import('../../../src/tools/procedures.js');
        addProcedureTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-devices');
        await executeTool(tool, {
          type: 'server',
          category: 'hybrid',
          status: 'online',
          organizationId: 123,
          teamId: 456,
          includeAlerts: true,
          sortBy: 'lastSeen',
          sortOrder: 'desc'
        }, { log: mockLog });
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].params.type).toBe('server');
        expect(calls[0].params.category).toBe('hybrid');
        expect(calls[0].params.status).toBe('online');
        expect(calls[0].params.organizationId).toBe(123);
        expect(calls[0].params.teamId).toBe(456);
        expect(calls[0].params.includeAlerts).toBe(true);
        expect(calls[0].params.sortBy).toBe('lastSeen');
        expect(calls[0].params.sortOrder).toBe('desc');
      });

      it('should include health analytics when requested', async () => {
        const devicesWithHealth = [
          { ...testDevice, status: 'online', monitoring: { ...testDevice.monitoring, health: { ...testDevice.monitoring.health, uptime: 86400 } } },
          { ...testDevice, id: 2, status: 'offline', monitoring: { health: { uptime: 0 }, alerts: [{ acknowledged: false }] } }
        ];

        mockApiClient.mockResponse('GET', '/devices', {
          success: true,
          data: devicesWithHealth,
          metadata: { total: 2 }
        });

        const { addProcedureTools } = await import('../../../src/tools/procedures.js');
        addProcedureTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-devices');
        const result = await executeTool(tool, { includeHealth: true }, { log: mockLog });
        
        const parsed = parseToolResult(result);
        expect(parsed.analysis.healthSummary.onlineDevices).toBe(1);
        expect(parsed.analysis.healthSummary.offlineDevices).toBe(1);
        expect(parsed.analysis.healthSummary.devicesWithAlerts).toBe(1);
        expect(parsed.analysis.healthSummary.averageUptime).toBe(43200);
        expect(parsed.analysis.healthSummary.devicesWithPerformanceData).toBe(1);
      });
    });

    describe('test-device-connectivity tool', () => {
      it('should test device connectivity successfully with diagnostics', async () => {
        const testResult = {
          success: true,
          responseTime: 125,
          deviceStatus: 'online',
          errors: [],
          warnings: ['High memory usage detected'],
          diagnostics: {
            connectivity: {
              ping: { success: true, latency: 12.5 },
              portTest: { success: true, ports: [443] },
              dnsResolution: { success: true, resolvedIp: '203.0.113.1' }
            },
            authentication: {
              validated: true,
              method: 'api_key',
              expiresAt: '2024-12-31T23:59:59Z'
            },
            performance: {
              cpuUsage: 45.2,
              memoryUsage: 82.8,
              diskUsage: 33.1,
              networkLatency: 12.5,
              throughput: 1024000
            },
            capabilities: {
              tested: ['json', 'xml'],
              maxPayloadTest: { success: true, maxSize: 2097152 },
              protocolSupport: { https: true, websocket: false }
            }
          },
          recommendations: [
            'Consider increasing memory allocation',
            'Monitor disk usage trends',
            'Optimize network connectivity'
          ]
        };

        mockApiClient.mockResponse('POST', '/devices/1/test', {
          success: true,
          data: testResult
        });

        const { addProcedureTools } = await import('../../../src/tools/procedures.js');
        addProcedureTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'test-device-connectivity');
        const result = await executeTool(tool, {
          deviceId: 1,
          testType: 'full_diagnostic',
          timeout: 15000,
          includePerformance: true
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsed = parseToolResult(result);
        expect(parsed.test.success).toBe(true);
        expect(parsed.summary.responseTime).toBe(125);
        expect(parsed.summary.status).toBe('online');
        expect(parsed.diagnostics.connectivity.ping.success).toBe(true);
        expect(parsed.diagnostics.authentication.validated).toBe(true);
        expect(parsed.diagnostics.performance.cpuUsage).toBe(45.2);
        expect(parsed.recommendations).toHaveLength(3);
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/devices/1/test');
        expect(calls[0].data.testType).toBe('full_diagnostic');
        expect(calls[0].data.timeout).toBe(15000);
        expect(calls[0].data.includePerformance).toBe(true);
        
        expectProgressReported(mockReportProgress, [
          { progress: 0, total: 100 },
          { progress: 25, total: 100 },
          { progress: 100, total: 100 }
        ]);
      });

      it('should test different connectivity test types', async () => {
        const testTypes = ['ping', 'health_check', 'authentication'];

        for (const testType of testTypes) {
          mockApiClient.mockResponse('POST', '/devices/1/test', {
            success: true,
            data: {
              success: true,
              responseTime: 50,
              testType,
              deviceStatus: 'online'
            }
          });

          const { addProcedureTools } = await import('../../../src/tools/procedures.js');
          addProcedureTools(mockServer, mockApiClient as any);
          
          const tool = findTool(mockTool, 'test-device-connectivity');
          await executeTool(tool, {
            deviceId: 1,
            testType: testType as any,
            timeout: 5000
          }, { log: mockLog, reportProgress: mockReportProgress });
          
          const calls = mockApiClient.getCallLog();
          expect(calls[0].data.testType).toBe(testType);
          
          mockApiClient.reset();
        }
      });

      it('should handle connectivity test failures gracefully', async () => {
        const failedTestResult = {
          success: false,
          responseTime: null,
          deviceStatus: 'error',
          errors: ['Connection timeout', 'Authentication failed'],
          warnings: [],
          diagnostics: {
            connectivity: { ping: { success: false, error: 'Host unreachable' } },
            authentication: { validated: false, error: 'Invalid credentials' }
          }
        };

        mockApiClient.mockResponse('POST', '/devices/1/test', {
          success: true,
          data: failedTestResult
        });

        const { addProcedureTools } = await import('../../../src/tools/procedures.js');
        addProcedureTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'test-device-connectivity');
        const result = await executeTool(tool, {
          deviceId: 1,
          testType: 'health_check'
        }, { log: mockLog, reportProgress: mockReportProgress });
        
        const parsed = parseToolResult(result);
        expect(parsed.summary.success).toBe(false);
        expect(parsed.summary.errors).toHaveLength(2);
        expect(parsed.diagnostics.connectivity.ping.success).toBe(false);
        expect(parsed.diagnostics.authentication.validated).toBe(false);
      });

      it('should validate connectivity test parameters', async () => {
        const { addProcedureTools } = await import('../../../src/tools/procedures.js');
        addProcedureTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'test-device-connectivity');
        
        // Test invalid device ID
        await expectInvalidZodParse(() => 
          executeTool(tool, {
            deviceId: 0,
            testType: 'ping'
          }, { log: mockLog })
        );
        
        // Test invalid test type
        await expectInvalidZodParse(() => 
          executeTool(tool, {
            deviceId: 1,
            testType: 'invalid-test'
          }, { log: mockLog })
        );
        
        // Test invalid timeout
        await expectInvalidZodParse(() => 
          executeTool(tool, {
            deviceId: 1,
            testType: 'ping',
            timeout: 500 // Too low
          }, { log: mockLog })
        );
      });
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle API errors gracefully across all tools', async () => {
      const tools = [
        'create-remote-procedure',
        'list-remote-procedures',
        'execute-remote-procedure',
        'create-device',
        'list-devices',
        'test-device-connectivity'
      ];

      for (const toolName of tools) {
        mockApiClient.mockResponse('*', '*', {
          success: false,
          error: { message: 'Service temporarily unavailable' }
        });

        const { addProcedureTools } = await import('../../../src/tools/procedures.js');
        addProcedureTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, toolName);
        
        let testInput: any = {};
        if (toolName === 'create-remote-procedure') {
          testInput = {
            name: 'Test',
            type: 'webhook',
            category: 'incoming',
            configuration: { endpoint: { url: 'http://test.com', method: 'POST', headers: {}, authentication: { type: 'none' }, timeout: 30000, retries: 3 } },
            input: { schema: {}, example: {}, required: [] },
            output: { schema: {}, example: {} }
          };
        } else if (toolName === 'execute-remote-procedure') {
          testInput = { procedureId: 1, input: {} };
        } else if (toolName === 'create-device') {
          testInput = {
            name: 'Test Device',
            type: 'server',
            category: 'incoming',
            configuration: {
              connection: { protocol: 'http', host: 'test.com', port: 80 },
              authentication: { type: 'none' }
            }
          };
        } else if (toolName === 'test-device-connectivity') {
          testInput = { deviceId: 1 };
        }
        
        await expect(executeTool(tool, testInput, { log: mockLog, reportProgress: mockReportProgress }))
          .rejects.toThrow(UserError);
        
        mockApiClient.reset();
      }
    });

    it('should handle network errors', async () => {
      mockApiClient.mockError('POST', '/remote-procedures', new Error('Network timeout'));

      const { addProcedureTools } = await import('../../../src/tools/procedures.js');
      addProcedureTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-remote-procedure');
      
      await expect(executeTool(tool, {
        name: 'Test',
        type: 'webhook',
        category: 'incoming',
        configuration: { endpoint: { url: 'http://test.com', method: 'POST', headers: {}, authentication: { type: 'none' }, timeout: 30000, retries: 3 } },
        input: { schema: {}, example: {}, required: [] },
        output: { schema: {}, example: {} }
      }, { log: mockLog })).rejects.toThrow('Failed to create remote procedure: Network timeout');
    });

    it('should log operations correctly', async () => {
      mockApiClient.mockResponse('POST', '/remote-procedures', {
        success: true,
        data: testRemoteProcedure
      });

      const { addProcedureTools } = await import('../../../src/tools/procedures.js');
      addProcedureTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-remote-procedure');
      await executeTool(tool, {
        name: 'Test Procedure',
        type: 'webhook',
        category: 'incoming',
        configuration: { endpoint: { url: 'http://test.com', method: 'POST', headers: {}, authentication: { type: 'none' }, timeout: 30000, retries: 3 } },
        input: { schema: {}, example: {}, required: [] },
        output: { schema: {}, example: {} }
      }, { log: mockLog, reportProgress: mockReportProgress });
      
      expect(mockLog).toHaveBeenCalledWith(
        'info',
        'Creating remote procedure',
        expect.objectContaining({
          name: 'Test Procedure',
          type: 'webhook',
          category: 'incoming'
        })
      );
      expect(mockLog).toHaveBeenCalledWith(
        'info',
        'Successfully created remote procedure',
        expect.objectContaining({
          procedureId: 1,
          name: 'Test Webhook Procedure'
        })
      );
    });
  });

  describe('Security and Data Masking', () => {
    it('should mask sensitive credentials in procedure responses', async () => {
      mockApiClient.mockResponse('POST', '/remote-procedures', {
        success: true,
        data: testRemoteProcedure
      });

      const { addProcedureTools } = await import('../../../src/tools/procedures.js');
      addProcedureTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-remote-procedure');
      const result = await executeTool(tool, {
        name: 'Secure Procedure',
        type: 'webhook',
        category: 'incoming',
        configuration: {
          endpoint: {
            url: 'https://secure.api.com/webhook',
            method: 'POST',
            headers: { 'Authorization': 'Bearer super-secret-token' },
            authentication: {
              type: 'bearer_token',
              credentials: { token: 'super-secret-token' }
            },
            timeout: 30000,
            retries: 3
          }
        },
        input: { schema: {}, example: {}, required: [] },
        output: { schema: {}, example: {} }
      }, { log: mockLog, reportProgress: mockReportProgress });
      
      expect(result).toContain('[CREDENTIALS_STORED]');
      expect(result).not.toContain('super-secret-token');
      
      const parsed = parseToolResult(result);
      expect(parsed.procedure.configuration.endpoint.authentication.credentials).toBe('[CREDENTIALS_STORED]');
    });

    it('should mask script code in script procedure responses', async () => {
      mockApiClient.mockResponse('POST', '/remote-procedures', {
        success: true,
        data: testScriptProcedure
      });

      const { addProcedureTools } = await import('../../../src/tools/procedures.js');
      addProcedureTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-remote-procedure');
      const result = await executeTool(tool, {
        name: 'Secret Script',
        type: 'script_execution',
        category: 'outgoing',
        configuration: {
          script: {
            language: 'python',
            code: 'import secret_module\nsecret_module.do_secret_stuff()',
            runtime: 'python3.9',
            environment: { SECRET_KEY: 'very-secret-key' }
          }
        },
        input: { schema: {}, example: {}, required: [] },
        output: { schema: {}, example: {} }
      }, { log: mockLog, reportProgress: mockReportProgress });
      
      expect(result).toContain('[SCRIPT_CODE_STORED]');
      expect(result).not.toContain('secret_module.do_secret_stuff()');
      expect(result).not.toContain('very-secret-key');
    });

    it('should mask device credentials in device responses', async () => {
      mockApiClient.mockResponse('POST', '/devices', {
        success: true,
        data: testDevice
      });

      const { addProcedureTools } = await import('../../../src/tools/procedures.js');
      addProcedureTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'create-device');
      const result = await executeTool(tool, {
        name: 'Secure Device',
        type: 'server',
        category: 'hybrid',
        configuration: {
          connection: {
            protocol: 'https',
            host: 'secure.device.com',
            port: 443,
            secure: true
          },
          authentication: {
            type: 'certificate',
            credentials: {
              certificate: 'secret-certificate-data',
              privateKey: 'secret-private-key'
            }
          }
        }
      }, { log: mockLog, reportProgress: mockReportProgress });
      
      expect(result).toContain('[CREDENTIALS_STORED]');
      expect(result).not.toContain('secret-certificate-data');
      expect(result).not.toContain('secret-private-key');
    });
  });
});