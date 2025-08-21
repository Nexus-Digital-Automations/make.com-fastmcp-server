/**
 * Basic Test Suite for Analytics and Data Intelligence Tools
 * Tests core functionality of analytics, audit logs, performance metrics, and reporting tools
 * Focuses on tool registration, configuration validation, and basic execution patterns
 */

import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { UserError } from 'fastmcp';
import { createMockServer, findTool, executeTool, expectValidZodParse, expectInvalidZodParse } from '../../utils/test-helpers.js';
import { MockMakeApiClient } from '../../mocks/make-api-client.mock.js';
import { testAnalytics, testAuditLog, testScenarioLog, testExecution, testIncompleteExecution, testHookLog, testErrors } from '../../fixtures/test-data.js';

describe('Analytics and Data Intelligence Tools - Basic Tests', () => {
  let mockServer: any;
  let mockTool: jest.MockedFunction<any>;
  let mockApiClient: MockMakeApiClient;

  // Complete test performance metrics for testing
  const testPerformanceMetrics = {
    organizationId: 67890,
    dataPoints: [
      { timestamp: '2024-01-01T00:00:00Z', value: 1200 },
      { timestamp: '2024-01-02T00:00:00Z', value: 1350 },
      { timestamp: '2024-01-03T00:00:00Z', value: 1180 },
      { timestamp: '2024-01-04T00:00:00Z', value: 1420 },
      { timestamp: '2024-01-05T00:00:00Z', value: 1380 }
    ],
    trend: 'improving',
    currentValue: 1380,
    percentageChange: 15.0,
    recommendations: [
      'Optimize data transfer patterns during peak hours',
      'Consider implementing intelligent caching for frequently accessed data',
      'Review execution timeout configurations for better performance'
    ],
    metadata: {
      period: 'daily',
      algorithm: 'trend_analysis',
      confidence: 95,
      lastUpdated: '2024-01-05T12:00:00Z'
    }
  };

  // Complete test export result for testing
  const testExportResult = {
    exportId: 'export_analytics_20240115_001',
    organizationId: 67890,
    dataType: 'analytics',
    format: 'json',
    status: 'initiated',
    downloadUrl: 'https://s3.amazonaws.com/make-exports/analytics_67890_20240115.json',
    estimatedCompletionTime: '2024-01-15T13:30:00Z',
    settings: {
      includeDetails: true,
      compression: 'gzip',
      retentionDays: 30
    },
    progress: {
      percentage: 0,
      stage: 'queued',
      recordsProcessed: 0,
      estimatedTotal: 50000
    },
    createdAt: '2024-01-15T13:00:00Z'
  };

  beforeEach(async () => {
    const serverSetup = createMockServer();
    mockServer = serverSetup.server;
    mockTool = serverSetup.mockTool;
    mockApiClient = new MockMakeApiClient();
    
    // Clear previous mock calls
    mockTool.mockClear();
  });

  afterEach(() => {
    jest.clearAllMocks();
    mockApiClient.reset();
  });

  describe('Tool Registration and Import', () => {
    it('should successfully import and register analytics tools', async () => {
      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      
      // Should not throw an error
      expect(() => {
        addAnalyticsTools(mockServer, mockApiClient as any);
      }).not.toThrow();
      
      // Should call addTool for each analytics tool
      expect(mockTool).toHaveBeenCalled();
      expect(mockTool.mock.calls.length).toBeGreaterThan(0);
    });

    it('should export the expected analytics tools and functions', async () => {
      const analyticsModule = await import('../../../src/tools/analytics.js');
      
      // Check that expected exports exist
      expect(analyticsModule.addAnalyticsTools).toBeDefined();
      expect(typeof analyticsModule.addAnalyticsTools).toBe('function');
      expect(analyticsModule.default).toBeDefined();
      expect(typeof analyticsModule.default).toBe('function');
      
      // Note: TypeScript interfaces are not available at runtime, so we can't test for them
      // This is expected behavior - interfaces exist only during compilation
    });

    it('should register all core analytics and reporting tools', async () => {
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
      });
    });
  });

  describe('Tool Configuration Validation', () => {
    it('should have correct structure for organization analytics tool', async () => {
      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-organization-analytics');
      
      expect(tool.name).toBe('get-organization-analytics');
      expect(tool.description).toContain('comprehensive analytics data');
      expect(tool.parameters).toBeDefined();
      expect(typeof tool.execute).toBe('function');
      expect(tool.annotations?.readOnlyHint).toBe(true);
      expect(tool.annotations?.openWorldHint).toBe(true);
    });

    it('should have correct structure for audit logging tools', async () => {
      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const listAuditTool = findTool(mockTool, 'list-audit-logs');
      expect(listAuditTool.name).toBe('list-audit-logs');
      expect(listAuditTool.description).toContain('audit logs');
      expect(listAuditTool.description).toContain('security and compliance');
      expect(listAuditTool.parameters).toBeDefined();

      const getAuditTool = findTool(mockTool, 'get-audit-log');
      expect(getAuditTool.name).toBe('get-audit-log');
      expect(getAuditTool.description).toContain('detailed information');
      expect(getAuditTool.parameters).toBeDefined();
    });

    it('should have correct structure for execution monitoring tools', async () => {
      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const scenarioLogsTool = findTool(mockTool, 'get-scenario-logs');
      expect(scenarioLogsTool.name).toBe('get-scenario-logs');
      expect(scenarioLogsTool.description).toContain('execution logs');
      expect(scenarioLogsTool.parameters).toBeDefined();

      const executionHistoryTool = findTool(mockTool, 'get-execution-history');
      expect(executionHistoryTool.name).toBe('get-execution-history');
      expect(executionHistoryTool.description).toContain('comprehensive execution history');
      expect(executionHistoryTool.parameters).toBeDefined();

      const incompleteExecutionsTool = findTool(mockTool, 'list-incomplete-executions');
      expect(incompleteExecutionsTool.name).toBe('list-incomplete-executions');
      expect(incompleteExecutionsTool.description).toContain('incomplete executions');
      expect(incompleteExecutionsTool.parameters).toBeDefined();
    });

    it('should have correct structure for performance and export tools', async () => {
      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const performanceTool = findTool(mockTool, 'get-performance-metrics');
      expect(performanceTool.name).toBe('get-performance-metrics');
      expect(performanceTool.description).toContain('performance metrics');
      expect(performanceTool.parameters).toBeDefined();

      const exportTool = findTool(mockTool, 'export-analytics-data');
      expect(exportTool.name).toBe('export-analytics-data');
      expect(exportTool.description).toContain('Export analytics');
      expect(exportTool.parameters).toBeDefined();

      const hookLogsTool = findTool(mockTool, 'get-hook-logs');
      expect(hookLogsTool.name).toBe('get-hook-logs');
      expect(hookLogsTool.description).toContain('webhook execution logs');
      expect(hookLogsTool.parameters).toBeDefined();
    });
  });

  describe('Schema Validation', () => {
    it('should validate organization analytics schema with correct inputs', async () => {
      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-organization-analytics');
      
      // Valid inputs
      const validInputs = [
        { organizationId: 67890 },
        { organizationId: 12345, period: 'month', includeUsage: true },
        { organizationId: 99999, startDate: '2024-01-01T00:00:00Z', endDate: '2024-01-31T23:59:59Z' },
        { organizationId: 55555, period: 'week', includeUsage: false, includePerformance: true, includeBilling: false }
      ];
      
      validInputs.forEach(input => {
        expectValidZodParse(tool.parameters, input);
      });
    });

    it('should reject invalid organization analytics schema inputs', async () => {
      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-organization-analytics');
      
      // Invalid inputs
      const invalidInputs = [
        {}, // organizationId is required
        { organizationId: 0 }, // organizationId must be >= 1
        { organizationId: -1 }, // negative organizationId
        { organizationId: 'invalid' }, // string instead of number
        { organizationId: 12345, period: 'invalid' }, // invalid period
        { organizationId: 12345, unknownField: 'value' }, // unexpected field due to strict schema
      ];
      
      invalidInputs.forEach(input => {
        expectInvalidZodParse(tool.parameters, input);
      });
    });

    it('should validate audit log filters with comprehensive parameters', async () => {
      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-audit-logs');
      
      // Valid audit log filter
      const validFilter = {
        organizationId: 67890,
        teamId: 12345,
        userId: 1001,
        action: 'scenario_create',
        resource: 'scenario',
        startDate: '2024-01-01T00:00:00Z',
        endDate: '2024-01-31T23:59:59Z',
        limit: 100,
        offset: 0
      };
      
      expectValidZodParse(tool.parameters, validFilter);

      // Test edge cases
      expectValidZodParse(tool.parameters, {}); // All fields optional
      expectValidZodParse(tool.parameters, { limit: 1, offset: 0 }); // Minimum limits
      expectValidZodParse(tool.parameters, { limit: 1000, offset: 9999 }); // Maximum limits
    });

    it('should validate scenario log filters with level filtering', async () => {
      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-scenario-logs');
      
      const validScenarioFilter = {
        scenarioId: 2001,
        executionId: 5001,
        level: 'error' as const,
        startDate: '2024-01-01T00:00:00Z',
        endDate: '2024-01-31T23:59:59Z',
        limit: 50,
        offset: 0
      };
      
      expectValidZodParse(tool.parameters, validScenarioFilter);

      // Test log levels
      const logLevels = ['info', 'warning', 'error', 'debug'] as const;
      logLevels.forEach(level => {
        expectValidZodParse(tool.parameters, {
          scenarioId: 2001,
          level
        });
      });
    });

    it('should validate performance metrics schema with metric types', async () => {
      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-performance-metrics');
      
      const validMetricsRequest = {
        organizationId: 67890,
        metric: 'execution_time' as const,
        period: 'day' as const,
        startDate: '2024-01-01T00:00:00Z',
        endDate: '2024-01-31T23:59:59Z'
      };
      
      expectValidZodParse(tool.parameters, validMetricsRequest);

      // Test metric types
      const metricTypes = ['execution_time', 'operations_per_minute', 'success_rate', 'data_transfer', 'all'] as const;
      metricTypes.forEach(metric => {
        expectValidZodParse(tool.parameters, {
          organizationId: 67890,
          metric
        });
      });

      // Test period types
      const periodTypes = ['hour', 'day', 'week', 'month'] as const;
      periodTypes.forEach(period => {
        expectValidZodParse(tool.parameters, {
          organizationId: 67890,
          period
        });
      });
    });

    it('should validate data export schema with format and type options', async () => {
      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'export-analytics-data');
      
      const validExportRequest = {
        organizationId: 67890,
        dataType: 'analytics' as const,
        format: 'json' as const,
        startDate: '2024-01-01T00:00:00Z',
        endDate: '2024-01-31T23:59:59Z',
        includeDetails: true
      };
      
      expectValidZodParse(tool.parameters, validExportRequest);

      // Test data types
      const dataTypes = ['analytics', 'audit_logs', 'execution_history', 'scenario_logs'] as const;
      dataTypes.forEach(dataType => {
        expectValidZodParse(tool.parameters, {
          organizationId: 67890,
          dataType,
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z'
        });
      });

      // Test formats
      const formats = ['json', 'csv', 'xlsx'] as const;
      formats.forEach(format => {
        expectValidZodParse(tool.parameters, {
          organizationId: 67890,
          dataType: 'analytics',
          format,
          startDate: '2024-01-01T00:00:00Z',
          endDate: '2024-01-31T23:59:59Z'
        });
      });
    });
  });

  describe('Basic Tool Execution', () => {
    it('should execute get-organization-analytics successfully with mocked data', async () => {
      mockApiClient.mockResponse('GET', '/analytics/67890', {
        success: true,
        data: testAnalytics
      });

      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-organization-analytics');
      const result = await executeTool(tool, { organizationId: 67890 });
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
      
      const parsedResult = JSON.parse(result);
      expect(parsedResult.analytics).toBeDefined();
      expect(parsedResult.summary).toBeDefined();
      expect(parsedResult.summary.totalExecutions).toBe(testAnalytics.usage.executions);
      expect(parsedResult.summary.totalOperations).toBe(testAnalytics.usage.operations);
      expect(parsedResult.summary.successRate).toBeGreaterThan(0);
      expect(parsedResult.summary.operationsUtilization).toBeGreaterThan(0);
    });

    it('should execute list-audit-logs with filtering parameters', async () => {
      const mockAuditLogs = [
        { ...testAuditLog, action: 'scenario_create', userId: 1001 },
        { ...testAuditLog, action: 'connection_update', userId: 1002 },
        { ...testAuditLog, action: 'user_login', userId: 1001 }
      ];

      mockApiClient.mockResponse('GET', '/audit-logs', {
        success: true,
        data: mockAuditLogs,
        metadata: { total: 3 }
      });

      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-audit-logs');
      const result = await executeTool(tool, {
        organizationId: 67890,
        action: 'scenario_create',
        limit: 50
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.auditLogs).toHaveLength(3);
      expect(parsedResult.summary.totalLogs).toBe(3);
      expect(parsedResult.summary.actionTypes).toContain('scenario_create');
      expect(parsedResult.summary.uniqueUsers).toBe(2);
      expect(parsedResult.pagination.limit).toBe(50);
    });

    it('should execute get-scenario-logs with log level analysis', async () => {
      const mockScenarioLogs = [
        { ...testScenarioLog, level: 'info', executionId: 5001 },
        { ...testScenarioLog, level: 'warning', executionId: 5001 },
        { ...testScenarioLog, level: 'error', executionId: 5002 },
        { ...testScenarioLog, level: 'debug', executionId: 5003 }
      ];

      mockApiClient.mockResponse('GET', '/scenarios/2001/logs', {
        success: true,
        data: mockScenarioLogs,
        metadata: { total: 4 }
      });

      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-scenario-logs');
      const result = await executeTool(tool, {
        scenarioId: 2001,
        level: 'error'
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.scenarioLogs).toHaveLength(4);
      expect(parsedResult.summary.logLevels.info).toBe(1);
      expect(parsedResult.summary.logLevels.warning).toBe(1);
      expect(parsedResult.summary.logLevels.error).toBe(1);
      expect(parsedResult.summary.logLevels.debug).toBe(1);
      expect(parsedResult.summary.uniqueExecutions).toBe(3);
    });

    it('should execute get-execution-history with comprehensive analytics', async () => {
      const mockExecutions = [
        { ...testExecution, status: 'success', operations: 25, dataTransfer: 1024 },
        { ...testExecution, status: 'error', operations: 10, dataTransfer: 512 },
        { ...testExecution, status: 'success', operations: 30, dataTransfer: 2048 }
      ];

      mockApiClient.mockResponse('GET', '/executions', {
        success: true,
        data: mockExecutions,
        metadata: { total: 3 }
      });

      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-execution-history');
      const result = await executeTool(tool, {
        organizationId: 67890,
        status: 'success'
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.executions).toHaveLength(3);
      expect(parsedResult.summary.totalExecutions).toBe(3);
      expect(parsedResult.summary.statusBreakdown.success).toBe(2);
      expect(parsedResult.summary.statusBreakdown.error).toBe(1);
      expect(parsedResult.summary.totalOperations).toBe(65);
      expect(parsedResult.summary.totalDataTransfer).toBe(3584);
    });

    it('should execute list-incomplete-executions with status analysis', async () => {
      const mockIncompleteExecutions = [
        { ...testIncompleteExecution, status: 'waiting', canResume: true, operations: 15 },
        { ...testIncompleteExecution, status: 'paused', canResume: true, operations: 20 },
        { ...testIncompleteExecution, status: 'failed', canResume: false, operations: 5 }
      ];

      mockApiClient.mockResponse('GET', '/incomplete-executions', {
        success: true,
        data: mockIncompleteExecutions,
        metadata: { total: 3 }
      });

      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-incomplete-executions');
      const result = await executeTool(tool, {
        scenarioId: 2001,
        canResume: true
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.incompleteExecutions).toHaveLength(3);
      expect(parsedResult.summary.statusBreakdown.waiting).toBe(1);
      expect(parsedResult.summary.statusBreakdown.paused).toBe(1);
      expect(parsedResult.summary.statusBreakdown.failed).toBe(1);
      expect(parsedResult.summary.resumableCount).toBe(2);
      expect(parsedResult.summary.totalOperationsAffected).toBe(40);
    });

    it('should execute get-performance-metrics with trend analysis', async () => {
      mockApiClient.mockResponse('GET', '/organizations/67890/metrics', {
        success: true,
        data: testPerformanceMetrics
      });

      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-performance-metrics');
      const result = await executeTool(tool, {
        organizationId: 67890,
        metric: 'execution_time',
        period: 'day'
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.metrics.dataPoints).toHaveLength(5);
      expect(parsedResult.analysis.trend).toBe('improving');
      expect(parsedResult.analysis.currentValue).toBe(1380);
      expect(parsedResult.analysis.percentageChange).toBe(15.0);
      expect(parsedResult.analysis.recommendations).toEqual(expect.arrayContaining([
        expect.stringContaining('Optimize data transfer patterns')
      ]));
    });

    it('should execute export-analytics-data with format options', async () => {
      mockApiClient.mockResponse('POST', '/organizations/67890/export', {
        success: true,
        data: testExportResult
      });

      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'export-analytics-data');
      const result = await executeTool(tool, {
        organizationId: 67890,
        dataType: 'analytics',
        format: 'json',
        startDate: '2024-01-01T00:00:00Z',
        endDate: '2024-01-31T23:59:59Z',
        includeDetails: true
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.exportResult.exportId).toBe(testExportResult.exportId);
      expect(parsedResult.downloadUrl).toBe(testExportResult.downloadUrl);
      expect(parsedResult.estimatedCompletionTime).toBe(testExportResult.estimatedCompletionTime);
      expect(parsedResult.message).toContain('export initiated successfully');
    });

    it('should execute get-hook-logs with performance tracking', async () => {
      const mockHookLogs = [
        { ...testHookLog, success: true, method: 'POST', processingTime: 125 },
        { ...testHookLog, success: false, method: 'GET', processingTime: 75 },
        { ...testHookLog, success: true, method: 'POST', processingTime: 200 }
      ];

      mockApiClient.mockResponse('GET', '/hooks/14001/logs', {
        success: true,
        data: mockHookLogs,
        metadata: { total: 3 }
      });

      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-hook-logs');
      const result = await executeTool(tool, {
        hookId: 14001,
        success: true,
        method: 'POST'
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.hookLogs).toHaveLength(3);
      expect(parsedResult.summary.successRate).toBe(67); // 2/3 * 100, rounded
      expect(parsedResult.summary.methodBreakdown.POST).toBe(2);
      expect(parsedResult.summary.methodBreakdown.GET).toBe(1);
      expect(parsedResult.summary.averageProcessingTime).toBeCloseTo(133.33, 1);
      expect(parsedResult.summary.errorCount).toBe(1);
    });
  });

  describe('Error Handling and Data Validation', () => {
    it('should handle API failures gracefully across all analytics tools', async () => {
      const toolsToTest = [
        { name: 'get-organization-analytics', params: { organizationId: 67890 } },
        { name: 'list-audit-logs', params: {} },
        { name: 'get-scenario-logs', params: { scenarioId: 2001 } },
        { name: 'get-execution-history', params: {} },
        { name: 'list-incomplete-executions', params: {} },
        { name: 'get-hook-logs', params: { hookId: 14001 } },
        { name: 'get-performance-metrics', params: { organizationId: 67890 } }
      ];

      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);

      for (const { name, params } of toolsToTest) {
        // Set up specific endpoint failures for each tool
        switch (name) {
          case 'get-organization-analytics':
            mockApiClient.mockFailure('GET', `/analytics/${params.organizationId}`, new Error('API Error'));
            break;
          case 'list-audit-logs':
            mockApiClient.mockFailure('GET', '/audit-logs', new Error('API Error'));
            break;
          case 'get-scenario-logs':
            mockApiClient.mockFailure('GET', `/scenarios/${params.scenarioId}/logs`, new Error('API Error'));
            break;
          case 'get-execution-history':
            mockApiClient.mockFailure('GET', '/executions', new Error('API Error'));
            break;
          case 'list-incomplete-executions':
            mockApiClient.mockFailure('GET', '/incomplete-executions', new Error('API Error'));
            break;
          case 'get-hook-logs':
            mockApiClient.mockFailure('GET', `/hooks/${params.hookId}/logs`, new Error('API Error'));
            break;
          case 'get-performance-metrics':
            mockApiClient.mockFailure('GET', `/organizations/${params.organizationId}/metrics`, new Error('API Error'));
            break;
        }

        const tool = findTool(mockTool, name);
        await expect(executeTool(tool, params))
          .rejects.toThrow(UserError);
        
        mockApiClient.reset();
      }
    });

    it('should handle unauthorized access errors for sensitive analytics data', async () => {
      mockApiClient.mockResponse('GET', '/analytics/67890', testErrors.unauthorized);

      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-organization-analytics');
      
      await expect(executeTool(tool, { organizationId: 67890 }))
        .rejects.toThrow(UserError);
    });

    it('should handle audit log not found scenarios', async () => {
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

    it('should handle network errors during data export', async () => {
      mockApiClient.mockFailure('POST', '/organizations/67890/export', new Error('Network Error'));

      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'export-analytics-data');
      
      await expect(executeTool(tool, {
        organizationId: 67890,
        dataType: 'analytics',
        startDate: '2024-01-01T00:00:00Z',
        endDate: '2024-01-31T23:59:59Z'
      })).rejects.toThrow(UserError);
    });

    it('should validate required fields for incomplete execution resolution', async () => {
      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'resolve-incomplete-execution');
      
      // Test valid parameters first
      expectValidZodParse(tool.parameters, {
        executionId: 12001,
        action: 'retry',
        reason: 'Test reason'
      });
      
      // Test invalid parameters
      expectInvalidZodParse(tool.parameters, {
        action: 'retry' // Missing required executionId
      });

      expectInvalidZodParse(tool.parameters, {
        executionId: 12001,
        action: 'invalid_action' // Invalid action enum
      });
    });

    it('should log analytics operations correctly for audit purposes', async () => {
      const mockLog = { info: jest.fn(), error: jest.fn() };
      
      mockApiClient.mockResponse('GET', '/analytics/67890', {
        success: true,
        data: testAnalytics
      });

      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-organization-analytics');
      await executeTool(tool, { organizationId: 67890 }, { log: mockLog });
      
      expect(mockLog.info).toHaveBeenCalledWith(
        'Getting organization analytics',
        expect.objectContaining({ organizationId: 67890 })
      );
      expect(mockLog.info).toHaveBeenCalledWith(
        'Successfully retrieved analytics',
        expect.any(Object)
      );
    });

    it('should handle empty data sets gracefully', async () => {
      mockApiClient.mockResponse('GET', '/audit-logs', {
        success: true,
        data: [],
        metadata: { total: 0 }
      });

      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'list-audit-logs');
      const result = await executeTool(tool, {});
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.auditLogs).toHaveLength(0);
      expect(parsedResult.summary.totalLogs).toBe(0);
      expect(parsedResult.summary.actionTypes).toHaveLength(0);
      expect(parsedResult.summary.uniqueUsers).toBe(0);
      expect(parsedResult.summary.dateRange).toBeNull();
    });
  });

  describe('Data Analytics Patterns and Business Intelligence', () => {
    it('should provide comprehensive analytics summary with business insights', async () => {
      const comprehensiveAnalytics = {
        ...testAnalytics,
        trends: {
          operationsGrowth: 25.5,
          executionSuccessRate: 94.0,
          averageExecutionTimeImprovement: -12.3,
          costPerOperation: 0.002
        },
        insights: [
          {
            type: 'performance',
            title: 'Execution Time Optimization',
            description: 'Average execution time has improved by 12.3% this month',
            impact: 'positive',
            confidence: 95
          },
          {
            type: 'usage',
            title: 'Operations Growth',
            description: 'Operations usage is growing at 25.5% month-over-month',
            impact: 'neutral',
            confidence: 88
          }
        ]
      };

      mockApiClient.mockResponse('GET', '/analytics/67890', {
        success: true,
        data: comprehensiveAnalytics
      });

      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-organization-analytics');
      const result = await executeTool(tool, {
        organizationId: 67890,
        includeUsage: true,
        includePerformance: true,
        includeBilling: true
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.analytics.trends).toBeDefined();
      expect(parsedResult.analytics.insights).toHaveLength(2);
      expect(parsedResult.summary.successRate).toBeGreaterThan(90);
      expect(parsedResult.summary.operationsUtilization).toBeLessThanOrEqual(100);
    });

    it('should support real-time analytics validation with streaming data patterns', async () => {
      const realtimeMetrics = {
        ...testPerformanceMetrics,
        realtime: {
          currentOperationsPerSecond: 45.7,
          activeExecutions: 23,
          queuedExecutions: 8,
          errorRate: 2.1,
          lastUpdated: '2024-01-15T13:00:15Z'
        },
        alerts: [
          {
            id: 'alert_001',
            type: 'performance_degradation',
            severity: 'medium',
            message: 'Average execution time increased by 15% in the last hour',
            triggeredAt: '2024-01-15T12:45:00Z'
          }
        ]
      };

      mockApiClient.mockResponse('GET', '/organizations/67890/metrics', {
        success: true,
        data: realtimeMetrics
      });

      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-performance-metrics');
      const result = await executeTool(tool, {
        organizationId: 67890,
        metric: 'all',
        period: 'hour'
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.metrics.realtime).toBeDefined();
      expect(parsedResult.metrics.realtime.currentOperationsPerSecond).toBeGreaterThan(0);
      expect(parsedResult.metrics.alerts).toHaveLength(1);
      expect(parsedResult.analysis.trend).toBe('improving');
    });

    it('should handle secure processing of sensitive analytics data', async () => {
      const sensitiveAnalytics = {
        ...testAnalytics,
        security: {
          dataClassification: 'confidential',
          accessLevel: 'admin_only',
          encryptionStatus: 'encrypted_at_rest',
          auditTrail: true
        },
        compliance: {
          gdprCompliant: true,
          hipaaCompliant: false,
          soc2Compliant: true,
          retentionPolicy: '7_years'
        }
      };

      mockApiClient.mockResponse('GET', '/analytics/67890', {
        success: true,
        data: sensitiveAnalytics
      });

      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-organization-analytics');
      const mockLog = { info: jest.fn(), error: jest.fn(), warn: jest.fn() };
      
      const result = await executeTool(tool, { organizationId: 67890 }, { log: mockLog });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.analytics.security).toBeDefined();
      expect(parsedResult.analytics.compliance).toBeDefined();
      
      // Verify audit logging for sensitive data access
      expect(mockLog.info).toHaveBeenCalledWith(
        expect.stringContaining('Getting organization analytics'),
        expect.any(Object)
      );
    });

    it('should validate data aggregation accuracy and reporting consistency', async () => {
      const aggregatedExecutions = Array.from({ length: 100 }, (_, i) => ({
        ...testExecution,
        id: 5000 + i,
        status: i < 95 ? 'success' : 'error',
        operations: Math.floor(Math.random() * 50) + 10,
        dataTransfer: Math.floor(Math.random() * 2048) + 512,
        startedAt: new Date(Date.now() - (i * 3600000)).toISOString(),
        finishedAt: new Date(Date.now() - (i * 3600000) + 30000).toISOString()
      }));

      mockApiClient.mockResponse('GET', '/executions', {
        success: true,
        data: aggregatedExecutions,
        metadata: { total: 100 }
      });

      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-execution-history');
      const result = await executeTool(tool, {
        organizationId: 67890,
        limit: 100
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      
      // Validate aggregation accuracy
      expect(parsedResult.executions).toHaveLength(100);
      expect(parsedResult.summary.totalExecutions).toBe(100);
      expect(parsedResult.summary.statusBreakdown.success).toBe(95);
      expect(parsedResult.summary.statusBreakdown.error).toBe(5);
      
      // Validate calculated metrics
      const totalOps = parsedResult.summary.totalOperations;
      const totalDataTransfer = parsedResult.summary.totalDataTransfer;
      expect(totalOps).toBeGreaterThan(0);
      expect(totalDataTransfer).toBeGreaterThan(0);
      expect(parsedResult.summary.averageExecutionTime).toBeGreaterThan(0);
    });
  });

  describe('Enterprise-Grade Analytics Features', () => {
    it('should support advanced dashboard and visualization data preparation', async () => {
      const dashboardAnalytics = {
        ...testAnalytics,
        dashboard: {
          widgets: [
            {
              id: 'executions_trend',
              type: 'line_chart',
              title: 'Executions Over Time',
              data: [
                { date: '2024-01-01', value: 120 },
                { date: '2024-01-02', value: 135 },
                { date: '2024-01-03', value: 128 }
              ],
              configuration: {
                xAxis: 'date',
                yAxis: 'value',
                color: '#3b82f6'
              }
            },
            {
              id: 'success_rate_gauge',
              type: 'gauge',
              title: 'Success Rate',
              data: { value: 94.0, max: 100 },
              configuration: {
                thresholds: [
                  { min: 0, max: 70, color: '#ef4444' },
                  { min: 70, max: 90, color: '#f59e0b' },
                  { min: 90, max: 100, color: '#10b981' }
                ]
              }
            }
          ],
          filters: {
            available: ['date_range', 'team', 'scenario', 'status'],
            active: ['date_range']
          },
          refreshInterval: 300000,
          lastUpdated: '2024-01-15T13:00:00Z'
        }
      };

      mockApiClient.mockResponse('GET', '/analytics/67890', {
        success: true,
        data: dashboardAnalytics
      });

      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'get-organization-analytics');
      const result = await executeTool(tool, { organizationId: 67890 });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.analytics.dashboard).toBeDefined();
      expect(parsedResult.analytics.dashboard.widgets).toHaveLength(2);
      expect(parsedResult.analytics.dashboard.widgets[0].type).toBe('line_chart');
      expect(parsedResult.analytics.dashboard.widgets[1].type).toBe('gauge');
    });

    it('should support comprehensive data export with enterprise features', async () => {
      const enterpriseExportResult = {
        ...testExportResult,
        enterprise: {
          encryption: {
            algorithm: 'AES-256-GCM',
            keyId: 'key_67890_20240115',
            encrypted: true
          },
          compliance: {
            auditTrail: true,
            dataClassification: 'internal',
            accessLog: 'export_access_20240115.log'
          },
          scheduling: {
            recurring: false,
            timezone: 'UTC',
            notifications: ['admin@company.com']
          }
        },
        metadata: {
          totalRecords: 50000,
          categories: {
            analytics: 15000,
            audit_logs: 20000,
            execution_history: 10000,
            scenario_logs: 5000
          },
          qualityChecks: {
            dataIntegrity: 'passed',
            completeness: 99.8,
            consistency: 'validated'
          }
        }
      };

      mockApiClient.mockResponse('POST', '/organizations/67890/export', {
        success: true,
        data: enterpriseExportResult
      });

      const { addAnalyticsTools } = await import('../../../src/tools/analytics.js');
      addAnalyticsTools(mockServer, mockApiClient as any);
      
      const tool = findTool(mockTool, 'export-analytics-data');
      const result = await executeTool(tool, {
        organizationId: 67890,
        dataType: 'analytics',
        format: 'xlsx',
        startDate: '2024-01-01T00:00:00Z',
        endDate: '2024-01-31T23:59:59Z',
        includeDetails: true
      });
      
      expect(result).toBeDefined();
      const parsedResult = JSON.parse(result);
      expect(parsedResult.exportResult.enterprise).toBeDefined();
      expect(parsedResult.exportResult.enterprise.encryption.encrypted).toBe(true);
      expect(parsedResult.exportResult.metadata.qualityChecks.dataIntegrity).toBe('passed');
      expect(parsedResult.exportResult.metadata.totalRecords).toBe(50000);
    });
  });
});