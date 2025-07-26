/**
 * Unit tests for analytics and audit log access tools
 * Tests organization analytics, audit logs, scenario logs, execution history, and performance metrics
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
import { testAnalytics, testAuditLog, testScenarioLog, testExecution, testIncompleteExecution, testHookLog, testErrors } from '../../fixtures/test-data.js';

describe('Analytics and Audit Log Tools - Comprehensive Test Suite', () => {
  let mockServer: any;
  let mockApiClient: MockMakeApiClient;
  let mockTool: jest.MockedFunction<any>;

  beforeEach(() => {
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockTool = serverSetup.mockTool;
    mockApiClient = new MockMakeApiClient();
  });

  afterEach(() => {
    jest.clearAllMocks();
    mockApiClient.reset();
  });

  describe('Tool Registration and Configuration', () => {
    it('should register all analytics and audit tools with correct configuration', async () => {
      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const expectedTools = [
        'get-organization-analytics',
        'list-audit-logs',
        'get-audit-log',
        'get-scenario-logs',
        'get-execution-history',
        'list-incomplete-executions',
        'resolve-incomplete-execution',
        'get-hook-logs',
        'export-analytics-data',
        'get-performance-metrics'
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

  describe('Organization Analytics', () => {
    describe('get-organization-analytics tool', () => {
      it('should get organization analytics with default parameters', async () => {
        mockApiClient.mockResponse('GET', '/analytics/12345', {
          success: true,
          data: testAnalytics
        });

        const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
        addAnalyticsTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-organization-analytics');
        const result = await executeTool(tool, { organizationId: 12345 });
        
        expect(result).toContain(testAnalytics.period);
        expect(result).toContain('totalExecutions');
        expect(result).toContain('successRate');
        expect(result).toContain('operationsUtilization');
      });

      it('should handle custom date range and period filters', async () => {
        mockApiClient.mockResponse('GET', '/analytics/12345', {
          success: true,
          data: testAnalytics
        });

        const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
        addAnalyticsTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-organization-analytics');
        const result = await executeTool(tool, {
          organizationId: 12345,
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z',
          period: 'week',
          includeUsage: true,
          includePerformance: true,
          includeBilling: false
        });

        const calls = mockApiClient.getCallLog();
        expect(calls[0].params.startDate).toBe('2024-01-01T00:00:00Z');
        expect(calls[0].params.endDate).toBe('2024-01-31T23:59:59Z');
        expect(calls[0].params.period).toBe('week');
        expect(calls[0].params.includeBilling).toBe(false);
      });

      it('should validate input parameters with Zod schema', async () => {
        const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
        addAnalyticsTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-organization-analytics');
        
        // Valid parameters
        expectValidZodParse(tool.parameters, {
          organizationId: 12345,
          period: 'month',
          includeUsage: true
        });

        // Invalid parameters
        expectInvalidZodParse(tool.parameters, {
          organizationId: 0 // Invalid: must be >= 1
        });
        
        expectInvalidZodParse(tool.parameters, {
          organizationId: 12345,
          period: 'invalid' // Invalid period
        });
      });

      it('should handle API errors gracefully', async () => {
        mockApiClient.mockResponse('GET', '/analytics/12345', {
          success: false,
          error: testErrors.apiError
        });

        const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
        addAnalyticsTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-organization-analytics');
        
        await expect(executeTool(tool, { organizationId: 12345 }))
          .rejects.toThrow(UserError);
      });
    });
  });

  describe('Audit Log Management', () => {
    describe('list-audit-logs tool', () => {
      it('should list audit logs with default filters', async () => {
        mockApiClient.mockResponse('GET', '/audit-logs', {
          success: true,
          data: [testAuditLog],
          metadata: { total: 1 }
        });

        const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
        addAnalyticsTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-audit-logs');
        const result = await executeTool(tool, {});
        
        expect(result).toContain(testAuditLog.action);
        expect(result).toContain(testAuditLog.resource);
        expect(result).toContain('summary');
        expect(result).toContain('pagination');
      });

      it('should filter audit logs by organization, team, and user', async () => {
        mockApiClient.mockResponse('GET', '/audit-logs', {
          success: true,
          data: [testAuditLog],
          metadata: { total: 1 }
        });

        const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
        addAnalyticsTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-audit-logs');
        const result = await executeTool(tool, {
          organizationId: 12345,
          teamId: 67890,
          userId: 11111,
          action: 'scenario_create',
          resource: 'scenario',
          limit: 50,
          offset: 10
        });

        const calls = mockApiClient.getCallLog();
        expect(calls[0].params.organizationId).toBe(12345);
        expect(calls[0].params.teamId).toBe(67890);
        expect(calls[0].params.userId).toBe(11111);
        expect(calls[0].params.action).toBe('scenario_create');
        expect(calls[0].params.resource).toBe('scenario');
        expect(calls[0].params.limit).toBe(50);
        expect(calls[0].params.offset).toBe(10);
      });

      it('should create comprehensive summary statistics', async () => {
        const auditLogs = [
          { ...testAuditLog, action: 'scenario_create', resource: 'scenario', userId: 1 },
          { ...testAuditLog, action: 'connection_update', resource: 'connection', userId: 2 },
          { ...testAuditLog, action: 'scenario_create', resource: 'scenario', userId: 1 }
        ];

        mockApiClient.mockResponse('GET', '/audit-logs', {
          success: true,
          data: auditLogs,
          metadata: { total: 3 }
        });

        const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
        addAnalyticsTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-audit-logs');
        const result = await executeTool(tool, {});
        
        const parsed = JSON.parse(result);
        expect(parsed.summary.totalLogs).toBe(3);
        expect(parsed.summary.actionTypes).toContain('scenario_create');
        expect(parsed.summary.actionTypes).toContain('connection_update');
        expect(parsed.summary.resourceTypes).toContain('scenario');
        expect(parsed.summary.resourceTypes).toContain('connection');
        expect(parsed.summary.uniqueUsers).toBe(2);
      });
    });

    describe('get-audit-log tool', () => {
      it('should get specific audit log details', async () => {
        mockApiClient.mockResponse('GET', '/audit-logs/12345', {
          success: true,
          data: testAuditLog
        });

        const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
        addAnalyticsTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-audit-log');
        const result = await executeTool(tool, { logId: 12345 });
        
        expect(result).toContain(testAuditLog.action);
        expect(result).toContain(testAuditLog.resource);
        expect(result).toContain(testAuditLog.timestamp);
      });

      it('should handle audit log not found', async () => {
        mockApiClient.mockResponse('GET', '/audit-logs/99999', {
          success: true,
          data: null
        });

        const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
        addAnalyticsTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-audit-log');
        
        await expect(executeTool(tool, { logId: 99999 }))
          .rejects.toThrow('Audit log with ID 99999 not found');
      });
    });
  });

  describe('Scenario Logging', () => {
    describe('get-scenario-logs tool', () => {
      it('should get scenario logs with filtering options', async () => {
        mockApiClient.mockResponse('GET', '/scenarios/12345/logs', {
          success: true,
          data: [testScenarioLog],
          metadata: { total: 1 }
        });

        const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
        addAnalyticsTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-scenario-logs');
        const result = await executeTool(tool, {
          scenarioId: 12345,
          level: 'error',
          limit: 100
        });

        expect(result).toContain(testScenarioLog.message);
        expect(result).toContain('summary');
        expect(result).toContain('logLevels');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/scenarios/12345/logs');
        expect(calls[0].params.level).toBe('error');
        expect(calls[0].params.limit).toBe(100);
      });

      it('should provide comprehensive log level summary', async () => {
        const scenarioLogs = [
          { ...testScenarioLog, level: 'info', executionId: 1, moduleName: 'HTTP' },
          { ...testScenarioLog, level: 'error', executionId: 2, moduleName: 'Filter' },
          { ...testScenarioLog, level: 'warning', executionId: 1, moduleName: 'HTTP' },
          { ...testScenarioLog, level: 'debug', executionId: 3, moduleName: 'Transformer' }
        ];

        mockApiClient.mockResponse('GET', '/scenarios/12345/logs', {
          success: true,
          data: scenarioLogs,
          metadata: { total: 4 }
        });

        const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
        addAnalyticsTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-scenario-logs');
        const result = await executeTool(tool, { scenarioId: 12345 });
        
        const parsed = JSON.parse(result);
        expect(parsed.summary.logLevels.info).toBe(1);
        expect(parsed.summary.logLevels.error).toBe(1);
        expect(parsed.summary.logLevels.warning).toBe(1);
        expect(parsed.summary.logLevels.debug).toBe(1);
        expect(parsed.summary.uniqueExecutions).toBe(3);
        expect(parsed.summary.uniqueModules).toContain('HTTP');
        expect(parsed.summary.uniqueModules).toContain('Filter');
        expect(parsed.summary.uniqueModules).toContain('Transformer');
      });
    });
  });

  describe('Execution History', () => {
    describe('get-execution-history tool', () => {
      it('should get execution history with comprehensive analytics', async () => {
        const executions = [
          { ...testExecution, status: 'success', operations: 10, dataTransfer: 1024, finishedAt: '2024-01-01T12:30:00Z' },
          { ...testExecution, status: 'error', operations: 5, dataTransfer: 512, finishedAt: '2024-01-01T12:35:00Z' },
          { ...testExecution, status: 'success', operations: 15, dataTransfer: 2048, finishedAt: '2024-01-01T12:40:00Z' }
        ];

        mockApiClient.mockResponse('GET', '/executions', {
          success: true,
          data: executions,
          metadata: { total: 3 }
        });

        const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
        addAnalyticsTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-execution-history');
        const result = await executeTool(tool, {
          status: 'success',
          limit: 100
        });

        const parsed = JSON.parse(result);
        expect(parsed.summary.totalExecutions).toBe(3);
        expect(parsed.summary.statusBreakdown.success).toBe(2);
        expect(parsed.summary.statusBreakdown.error).toBe(1);
        expect(parsed.summary.totalOperations).toBe(30);
        expect(parsed.summary.totalDataTransfer).toBe(3584);
        expect(parsed.summary.averageExecutionTime).toBeGreaterThan(0);
      });

      it('should filter by scenario and organization', async () => {
        mockApiClient.mockResponse('GET', '/scenarios/12345/executions', {
          success: true,
          data: [testExecution],
          metadata: { total: 1 }
        });

        const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
        addAnalyticsTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-execution-history');
        const result = await executeTool(tool, {
          scenarioId: 12345,
          organizationId: 67890,
          teamId: 11111
        });

        const calls = mockApiClient.getCallLog();
        expect(calls[0].endpoint).toBe('/scenarios/12345/executions');
        expect(calls[0].params.organizationId).toBe(67890);
        expect(calls[0].params.teamId).toBe(11111);
      });
    });
  });

  describe('Incomplete Execution Management', () => {
    describe('list-incomplete-executions tool', () => {
      it('should list incomplete executions with status breakdown', async () => {
        const incompleteExecutions = [
          { ...testIncompleteExecution, status: 'waiting', canResume: true, operations: 10 },
          { ...testIncompleteExecution, status: 'paused', canResume: true, operations: 5 },
          { ...testIncompleteExecution, status: 'failed', canResume: false, operations: 3 }
        ];

        mockApiClient.mockResponse('GET', '/incomplete-executions', {
          success: true,
          data: incompleteExecutions,
          metadata: { total: 3 }
        });

        const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
        addAnalyticsTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-incomplete-executions');
        const result = await executeTool(tool, {});

        const parsed = JSON.parse(result);
        expect(parsed.summary.totalIncomplete).toBe(3);
        expect(parsed.summary.statusBreakdown.waiting).toBe(1);
        expect(parsed.summary.statusBreakdown.paused).toBe(1);
        expect(parsed.summary.statusBreakdown.failed).toBe(1);
        expect(parsed.summary.resumableCount).toBe(2);
        expect(parsed.summary.totalOperationsAffected).toBe(18);
      });

      it('should filter by resumable status and scenario', async () => {
        mockApiClient.mockResponse('GET', '/incomplete-executions', {
          success: true,
          data: [testIncompleteExecution],
          metadata: { total: 1 }
        });

        const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
        addAnalyticsTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'list-incomplete-executions');
        const result = await executeTool(tool, {
          scenarioId: 12345,
          canResume: true,
          status: 'waiting'
        });

        const calls = mockApiClient.getCallLog();
        expect(calls[0].params.scenarioId).toBe(12345);
        expect(calls[0].params.canResume).toBe(true);
        expect(calls[0].params.status).toBe('waiting');
      });
    });

    describe('resolve-incomplete-execution tool', () => {
      it('should resolve incomplete execution with retry action', async () => {
        mockApiClient.mockResponse('POST', '/incomplete-executions/12345/resolve', {
          success: true,
          data: { status: 'retrying', executionId: 12345 }
        });

        const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
        addAnalyticsTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'resolve-incomplete-execution');
        const result = await executeTool(tool, {
          executionId: 12345,
          action: 'retry',
          reason: 'Temporary network issue resolved'
        });

        expect(result).toContain('retry successfully');
        expect(result).toContain('retrying');
        
        const calls = mockApiClient.getCallLog();
        expect(calls[0].data.action).toBe('retry');
        expect(calls[0].data.reason).toBe('Temporary network issue resolved');
      });

      it('should handle different resolution actions', async () => {
        const actions = ['retry', 'skip', 'cancel'];
        
        for (const action of actions) {
          mockApiClient.mockResponse('POST', `/incomplete-executions/12345/resolve`, {
            success: true,
            data: { status: `${action}ed`, executionId: 12345 }
          });

          const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
          addAnalyticsTools(mockServer, mockApiClient as any);
          
          const tool = findTool(mockTool, 'resolve-incomplete-execution');
          const result = await executeTool(tool, {
            executionId: 12345,
            action: action as 'retry' | 'skip' | 'cancel'
          });

          expect(result).toContain(`${action} successfully`);
          mockApiClient.reset();
        }
      });
    });
  });

  describe('Webhook Logging', () => {
    describe('get-hook-logs tool', () => {
      it('should get webhook logs with performance metrics', async () => {
        const hookLogs = [
          { ...testHookLog, success: true, method: 'POST', processingTime: 150 },
          { ...testHookLog, success: false, method: 'GET', processingTime: 50 },
          { ...testHookLog, success: true, method: 'POST', processingTime: 200 }
        ];

        mockApiClient.mockResponse('GET', '/hooks/12345/logs', {
          success: true,
          data: hookLogs,
          metadata: { total: 3 }
        });

        const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
        addAnalyticsTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-hook-logs');
        const result = await executeTool(tool, { hookId: 12345 });

        const parsed = JSON.parse(result);
        expect(parsed.summary.totalLogs).toBe(3);
        expect(parsed.summary.successRate).toBe(67); // 2/3 * 100, rounded
        expect(parsed.summary.methodBreakdown.POST).toBe(2);
        expect(parsed.summary.methodBreakdown.GET).toBe(1);
        expect(parsed.summary.averageProcessingTime).toBe(133.33333333333334);
        expect(parsed.summary.errorCount).toBe(1);
      });

      it('should filter hook logs by success status and method', async () => {
        mockApiClient.mockResponse('GET', '/hooks/12345/logs', {
          success: true,
          data: [testHookLog],
          metadata: { total: 1 }
        });

        const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
        addAnalyticsTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-hook-logs');
        const result = await executeTool(tool, {
          hookId: 12345,
          success: true,
          method: 'POST',
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z'
        });

        const calls = mockApiClient.getCallLog();
        expect(calls[0].params.success).toBe(true);
        expect(calls[0].params.method).toBe('POST');
        expect(calls[0].params.startDate).toBe('2024-01-01T00:00:00Z');
        expect(calls[0].params.endDate).toBe('2024-01-31T23:59:59Z');
      });
    });
  });

  describe('Data Export', () => {
    describe('export-analytics-data tool', () => {
      it('should export analytics data in different formats', async () => {
        const exportFormats = ['json', 'csv', 'xlsx'];
        
        for (const format of exportFormats) {
          mockApiClient.mockResponse('POST', '/organizations/12345/export', {
            success: true,
            data: {
              exportId: `export_${format}_123`,
              downloadUrl: `https://example.com/export_${format}_123.${format}`,
              estimatedCompletionTime: '2024-01-01T12:30:00Z'
            }
          });

          const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
          addAnalyticsTools(mockServer, mockApiClient as any);
          
          const tool = findTool(mockTool, 'export-analytics-data');
          const result = await executeTool(tool, {
            organizationId: 12345,
            dataType: 'analytics',
            format: format as 'json' | 'csv' | 'xlsx',
            startDate: '2024-01-01T00:00:00Z',
            endDate: '2024-01-31T23:59:59Z'
          });

          expect(result).toContain(`export_${format}_123`);
          expect(result).toContain('downloadUrl');
          expect(result).toContain('estimatedCompletionTime');
          
          mockApiClient.reset();
        }
      });

      it('should export different data types', async () => {
        const dataTypes = ['analytics', 'audit_logs', 'execution_history', 'scenario_logs'];
        
        for (const dataType of dataTypes) {
          mockApiClient.mockResponse('POST', '/organizations/12345/export', {
            success: true,
            data: {
              exportId: `export_${dataType}_123`,
              downloadUrl: `https://example.com/export_${dataType}_123.json`
            }
          });

          const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
          addAnalyticsTools(mockServer, mockApiClient as any);
          
          const tool = findTool(mockTool, 'export-analytics-data');
          const result = await executeTool(tool, {
            organizationId: 12345,
            dataType: dataType as 'analytics' | 'audit_logs' | 'execution_history' | 'scenario_logs',
            startDate: '2024-01-01T00:00:00Z',
            endDate: '2024-01-31T23:59:59Z'
          });

          const calls = mockApiClient.getCallLog();
          expect(calls[0].data.dataType).toBe(dataType);
          
          mockApiClient.reset();
        }
      });
    });
  });

  describe('Performance Metrics', () => {
    describe('get-performance-metrics tool', () => {
      it('should get performance metrics with trend analysis', async () => {
        const metricsData = {
          dataPoints: [
            { timestamp: '2024-01-01T00:00:00Z', value: 100 },
            { timestamp: '2024-01-02T00:00:00Z', value: 120 },
            { timestamp: '2024-01-03T00:00:00Z', value: 110 }
          ],
          trend: 'improving',
          currentValue: 110,
          percentageChange: 10.5,
          recommendations: ['Optimize heavy operations', 'Consider caching strategies']
        };

        mockApiClient.mockResponse('GET', '/organizations/12345/metrics', {
          success: true,
          data: metricsData
        });

        const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
        addAnalyticsTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-performance-metrics');
        const result = await executeTool(tool, {
          organizationId: 12345,
          metric: 'execution_time',
          period: 'day'
        });

        const parsed = JSON.parse(result);
        expect(parsed.metrics.dataPoints).toHaveLength(3);
        expect(parsed.analysis.trend).toBe('improving');
        expect(parsed.analysis.currentValue).toBe(110);
        expect(parsed.analysis.percentageChange).toBe(10.5);
        expect(parsed.analysis.recommendations).toContain('Optimize heavy operations');
      });

      it('should get all metrics when specified', async () => {
        mockApiClient.mockResponse('GET', '/organizations/12345/metrics', {
          success: true,
          data: {
            execution_time: { currentValue: 1500, trend: 'stable' },
            operations_per_minute: { currentValue: 45, trend: 'improving' },
            success_rate: { currentValue: 95.5, trend: 'stable' },
            data_transfer: { currentValue: 1024000, trend: 'increasing' }
          }
        });

        const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
        addAnalyticsTools(mockServer, mockApiClient as any);
        
        const tool = findTool(mockTool, 'get-performance-metrics');
        const result = await executeTool(tool, {
          organizationId: 12345,
          metric: 'all'
        });

        const calls = mockApiClient.getCallLog();
        expect(calls[0].params.metric).toBe('all');
      });
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle API errors gracefully across all tools', async () => {
      const toolsToTest = [
        { name: 'get-organization-analytics', params: { organizationId: 12345 } },
        { name: 'list-audit-logs', params: {} },
        { name: 'get-scenario-logs', params: { scenarioId: 12345 } },
        { name: 'get-execution-history', params: {} },
        { name: 'list-incomplete-executions', params: {} },
        { name: 'get-hook-logs', params: { hookId: 12345 } }
      ];

      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);

      for (const { name, params } of toolsToTest) {
        mockApiClient.mockResponse('GET', '/mock-endpoint', {
          success: false,
          error: testErrors.apiError
        });

        const tool = findTool(mockTool, name);
        await expect(executeTool(tool, params))
          .rejects.toThrow(UserError);
        
        mockApiClient.reset();
      }
    });

    it('should handle network errors', async () => {
      mockApiClient.mockNetworkError();

      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-organization-analytics');
      
      await expect(executeTool(tool, { organizationId: 12345 }))
        .rejects.toThrow(UserError);
    });

    it('should log operations correctly', async () => {
      const mockLog = { info: jest.fn(), error: jest.fn() };
      
      mockApiClient.mockResponse('GET', '/analytics/12345', {
        success: true,
        data: testAnalytics
      });

      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-organization-analytics');
      await executeTool(tool, { organizationId: 12345 }, { log: mockLog });
      
      expect(mockLog.info).toHaveBeenCalledWith(
        expect.stringContaining('Getting organization analytics'),
        expect.objectContaining({ organizationId: 12345 })
      );
      expect(mockLog.info).toHaveBeenCalledWith(
        expect.stringContaining('Successfully retrieved analytics'),
        expect.any(Object)
      );
    });
  });

  describe('Input Validation', () => {
    it('should validate all schema parameters correctly', async () => {
      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);

      // Test analytics filters
      const analyticsSchema = findTool(mockTool, 'get-organization-analytics').parameters;
      expectValidZodParse(analyticsSchema, {
        organizationId: 12345,
        period: 'month',
        includeUsage: true,
        includePerformance: true,
        includeBilling: false
      });

      // Test audit log filters
      const auditSchema = findTool(mockTool, 'list-audit-logs').parameters;
      expectValidZodParse(auditSchema, {
        organizationId: 12345,
        teamId: 67890,
        userId: 11111,
        action: 'scenario_create',
        resource: 'scenario',
        limit: 100,
        offset: 0
      });

      // Test scenario log filters
      const scenarioSchema = findTool(mockTool, 'get-scenario-logs').parameters;
      expectValidZodParse(scenarioSchema, {
        scenarioId: 12345,
        executionId: 67890,
        level: 'error',
        limit: 50
      });

      // Test performance metrics filters
      const metricsSchema = findTool(mockTool, 'get-performance-metrics').parameters;
      expectValidZodParse(metricsSchema, {
        organizationId: 12345,
        metric: 'execution_time',
        period: 'hour'
      });
    });
  });
});