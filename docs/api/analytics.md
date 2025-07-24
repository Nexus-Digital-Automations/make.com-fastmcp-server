# Analytics & Audit Tools

Comprehensive tools for accessing analytics data, audit logs, execution history, and performance metrics with advanced filtering and data export capabilities.

## Tools Overview

| Tool | Description | Type |
|------|-------------|------|
| `get-organization-analytics` | Get comprehensive analytics data | Read |
| `list-audit-logs` | List security and compliance audit logs | Read |
| `get-audit-log` | Get detailed audit log entry | Read |
| `get-scenario-logs` | Get execution logs for scenarios | Read |
| `get-execution-history` | Get comprehensive execution history | Read |
| `list-incomplete-executions` | List executions requiring attention | Read |
| `resolve-incomplete-execution` | Resolve incomplete executions | Action |
| `get-hook-logs` | Get webhook execution logs | Read |
| `export-analytics-data` | Export data for external analysis | Action |
| `get-performance-metrics` | Get detailed performance metrics | Read |

## Organization Analytics

### `get-organization-analytics`

Get comprehensive analytics data for an organization with usage, performance, and billing insights.

**Parameters:**
```typescript
{
  organizationId: number;     // Organization ID (required)
  startDate?: string;         // Start date (ISO format)
  endDate?: string;           // End date (ISO format)
  period?: 'day' | 'week' | 'month' | 'quarter' | 'year';  // Granularity (default: month)
  includeUsage?: boolean;     // Include usage statistics (default: true)
  includePerformance?: boolean; // Include performance metrics (default: true)
  includeBilling?: boolean;   // Include billing information (default: true)
}
```

**Returns:**
```typescript
{
  analytics: {
    organizationId: number;
    period: string;
    dateRange: {
      startDate: string;
      endDate: string;
    };
    usage: {
      executions: number;
      successfulExecutions: number;
      operations: number;
      dataTransfer: number;
      scenariosActive: number;
    };
    performance: {
      averageExecutionTime: number;
      successRate: number;
      errorRate: number;
      topBottlenecks: Array<{
        scenario: string;
        averageTime: number;
        frequency: number;
      }>;
    };
    billing: {
      operationsUsed: number;
      operationsLimit: number;
      dataTransferUsed: number;
      dataTransferLimit: number;
      currentCost: number;
      projectedCost: number;
    };
  };
  summary: {
    totalExecutions: number;
    totalOperations: number;
    successRate: number;
    averageExecutionTime: number;
    operationsUtilization: number;
  };
}
```

**Example:**
```bash
# Get monthly analytics
mcp-client get-organization-analytics --organizationId 123

# Get quarterly performance data
mcp-client get-organization-analytics \
  --organizationId 123 \
  --period "quarter" \
  --includePerformance true \
  --includeBilling false

# Get analytics for date range
mcp-client get-organization-analytics \
  --organizationId 123 \
  --startDate "2024-01-01" \
  --endDate "2024-01-31"
```

**Use Cases:**
- Executive dashboards
- Performance monitoring
- Capacity planning
- Cost optimization
- Trend analysis

---

### `get-performance-metrics`

Get detailed performance metrics and trends with configurable aggregation periods.

**Parameters:**
```typescript
{
  organizationId: number;     // Organization ID (required)
  metric?: 'execution_time' | 'operations_per_minute' | 'success_rate' | 'data_transfer' | 'all';  // Specific metric (default: all)
  period?: 'hour' | 'day' | 'week' | 'month';  // Aggregation period (default: day)
  startDate?: string;         // Start date (ISO format)
  endDate?: string;           // End date (ISO format)
}
```

**Returns:**
```typescript
{
  metrics: {
    organizationId: number;
    metric: string;
    period: string;
    dataPoints: Array<{
      timestamp: string;
      value: number;
      trend: 'up' | 'down' | 'stable';
    }>;
    currentValue: number;
    percentageChange: number;
    trend: string;
    recommendations: string[];
  };
  analysis: {
    trend: string;
    currentValue: number;
    percentageChange: number;
    recommendations: string[];
  };
}
```

**Example:**
```bash
# Get all performance metrics
mcp-client get-performance-metrics --organizationId 123

# Get specific metric with hourly aggregation
mcp-client get-performance-metrics \
  --organizationId 123 \
  --metric "execution_time" \
  --period "hour"
```

**Use Cases:**
- Performance optimization
- SLA monitoring
- Capacity planning
- Bottleneck identification
- Trend forecasting

## Audit & Compliance

### `list-audit-logs`

List and filter audit logs for security and compliance monitoring with comprehensive search capabilities.

**Parameters:**
```typescript
{
  organizationId?: number;    // Filter by organization ID
  teamId?: number;            // Filter by team ID
  userId?: number;            // Filter by user ID
  action?: string;            // Filter by action type
  resource?: string;          // Filter by resource type
  startDate?: string;         // Start date (ISO format)
  endDate?: string;           // End date (ISO format)
  limit?: number;             // Max logs (1-1000, default: 100)
  offset?: number;            // Logs to skip (default: 0)
}
```

**Returns:**
```typescript
{
  auditLogs: Array<{
    id: number;
    timestamp: string;
    userId: number;
    userName: string;
    action: string;
    resource: string;
    resourceId: string;
    organizationId: number;
    teamId?: number;
    ipAddress: string;
    userAgent: string;
    details: object;
    result: 'success' | 'failure';
  }>;
  summary: {
    totalLogs: number;
    actionTypes: string[];
    resourceTypes: string[];
    uniqueUsers: number;
    dateRange: {
      earliest: string;
      latest: string;
    };
  };
  pagination: {
    total: number;
    limit: number;
    offset: number;
    hasMore: boolean;
  };
}
```

**Example:**
```bash
# List recent audit logs
mcp-client list-audit-logs --limit 50

# Filter by user actions
mcp-client list-audit-logs \
  --userId 123 \
  --action "scenario:create" \
  --startDate "2024-01-01"

# Security audit for organization
mcp-client list-audit-logs \
  --organizationId 456 \
  --action "user:login" \
  --resource "authentication"
```

**Common Actions:**
- `user:login`, `user:logout`
- `scenario:create`, `scenario:update`, `scenario:delete`
- `connection:create`, `connection:test`
- `team:create`, `user:invite`
- `billing:update`, `payment:process`

**Use Cases:**
- Security monitoring
- Compliance reporting
- User activity tracking
- Incident investigation
- Access pattern analysis

---

### `get-audit-log`

Get detailed information about a specific audit log entry with full context.

**Parameters:**
```typescript
{
  logId: number;              // Audit log ID (required)
}
```

**Returns:**
```typescript
{
  auditLog: {
    id: number;
    timestamp: string;
    userId: number;
    userName: string;
    userEmail: string;
    action: string;
    resource: string;
    resourceId: string;
    organizationId: number;
    teamId?: number;
    ipAddress: string;
    userAgent: string;
    sessionId: string;
    details: {
      before?: object;
      after?: object;
      metadata: object;
    };
    result: 'success' | 'failure';
    errorMessage?: string;
    relatedLogs: string[];
  };
}
```

**Example:**
```bash
# Get audit log details
mcp-client get-audit-log --logId 789
```

**Use Cases:**
- Incident investigation
- Change tracking
- Compliance verification
- Forensic analysis
- User support

## Execution Analysis

### `get-execution-history`

Get comprehensive execution history with filtering and performance analytics.

**Parameters:**
```typescript
{
  scenarioId?: number;        // Filter by scenario ID
  organizationId?: number;    // Filter by organization ID
  teamId?: number;            // Filter by team ID
  status?: 'success' | 'error' | 'warning' | 'incomplete';  // Filter by status
  startDate?: string;         // Start date (ISO format)
  endDate?: string;           // End date (ISO format)
  limit?: number;             // Max executions (1-1000, default: 100)
  offset?: number;            // Executions to skip (default: 0)
}
```

**Returns:**
```typescript
{
  executions: Array<{
    id: number;
    scenarioId: number;
    scenarioName: string;
    status: string;
    startedAt: string;
    finishedAt?: string;
    duration: number;
    operations: number;
    dataTransfer: number;
    error?: string;
    userId: number;
    triggeredBy: string;
  }>;
  summary: {
    totalExecutions: number;
    statusBreakdown: {
      success: number;
      error: number;
      warning: number;
      incomplete: number;
    };
    totalOperations: number;
    totalDataTransfer: number;
    averageExecutionTime: number;
  };
  pagination: {
    total: number;
    limit: number;
    offset: number;
    hasMore: boolean;
  };
}
```

**Example:**
```bash
# Get recent executions
mcp-client get-execution-history --limit 100

# Analyze scenario performance
mcp-client get-execution-history \
  --scenarioId 123 \
  --startDate "2024-01-01" \
  --endDate "2024-01-31"

# Find failed executions
mcp-client get-execution-history \
  --status "error" \
  --organizationId 456
```

**Use Cases:**
- Performance analysis
- Error rate monitoring
- Resource utilization tracking
- SLA compliance verification
- Capacity planning

---

### `get-scenario-logs`

Get execution logs for a specific scenario with filtering by execution and log level.

**Parameters:**
```typescript
{
  scenarioId: number;         // Scenario ID (required)
  executionId?: number;       // Filter by specific execution
  level?: 'info' | 'warning' | 'error' | 'debug';  // Filter by log level
  startDate?: string;         // Start date (ISO format)
  endDate?: string;           // End date (ISO format)
  limit?: number;             // Max logs (1-1000, default: 100)
  offset?: number;            // Logs to skip (default: 0)
}
```

**Returns:**
```typescript
{
  scenarioLogs: Array<{
    id: number;
    executionId: number;
    timestamp: string;
    level: string;
    message: string;
    moduleName?: string;
    moduleType?: string;
    data?: object;
    error?: string;
    stackTrace?: string;
  }>;
  summary: {
    totalLogs: number;
    logLevels: {
      info: number;
      warning: number;
      error: number;
      debug: number;
    };
    uniqueExecutions: number;
    uniqueModules: string[];
  };
  pagination: {
    total: number;
    limit: number;
    offset: number;
    hasMore: boolean;
  };
}
```

**Example:**
```bash
# Get all logs for scenario
mcp-client get-scenario-logs --scenarioId 123

# Get error logs only
mcp-client get-scenario-logs \
  --scenarioId 123 \
  --level "error" \
  --limit 50

# Get logs for specific execution
mcp-client get-scenario-logs \
  --scenarioId 123 \
  --executionId 456
```

**Use Cases:**
- Scenario debugging
- Error analysis
- Performance optimization
- Module troubleshooting
- Development support

---

### `list-incomplete-executions`

List and manage incomplete executions that require attention or recovery.

**Parameters:**
```typescript
{
  scenarioId?: number;        // Filter by scenario ID
  organizationId?: number;    // Filter by organization ID
  status?: 'waiting' | 'paused' | 'failed';  // Filter by incomplete status
  canResume?: boolean;        // Filter by resumable status
  limit?: number;             // Max executions (1-100, default: 20)
  offset?: number;            // Executions to skip (default: 0)
}
```

**Returns:**
```typescript
{
  incompleteExecutions: Array<{
    id: number;
    scenarioId: number;
    scenarioName: string;
    status: string;
    startedAt: string;
    pausedAt?: string;
    lastActivity: string;
    operations: number;
    completedSteps: number;
    totalSteps: number;
    canResume: boolean;
    error?: string;
    reason?: string;
  }>;
  summary: {
    totalIncomplete: number;
    statusBreakdown: {
      waiting: number;
      paused: number;
      failed: number;
    };
    resumableCount: number;
    totalOperationsAffected: number;
    uniqueScenarios: number;
  };
  pagination: {
    total: number;
    limit: number;
    offset: number;
    hasMore: boolean;
  };
}
```

**Example:**
```bash
# List all incomplete executions
mcp-client list-incomplete-executions

# Find resumable executions
mcp-client list-incomplete-executions --canResume true

# Filter by scenario
mcp-client list-incomplete-executions --scenarioId 123
```

**Use Cases:**
- Execution recovery management
- System health monitoring
- Resource cleanup
- Performance troubleshooting
- Automated recovery workflows

---

### `resolve-incomplete-execution`

Resolve or retry an incomplete execution with specified action and reason.

**Parameters:**
```typescript
{
  executionId: number;        // Incomplete execution ID (required)
  action: 'retry' | 'skip' | 'cancel';  // Action to take (required)
  reason?: string;            // Reason for the action
}
```

**Returns:**
```typescript
{
  result: {
    executionId: number;
    previousStatus: string;
    newStatus: string;
    action: string;
    reason?: string;
    timestamp: string;
  };
  message: string;
}
```

**Example:**
```bash
# Retry failed execution
mcp-client resolve-incomplete-execution \
  --executionId 789 \
  --action "retry" \
  --reason "Network issue resolved"

# Cancel stuck execution
mcp-client resolve-incomplete-execution \
  --executionId 790 \
  --action "cancel" \
  --reason "Manual intervention required"
```

**Actions:**
- **retry**: Attempt to resume/restart execution
- **skip**: Mark as completed and continue
- **cancel**: Permanently cancel execution

**Use Cases:**
- Manual execution recovery
- Automated error handling
- System maintenance
- Resource cleanup
- Performance optimization

## Webhook Analytics

### `get-hook-logs`

Get webhook execution logs for debugging and monitoring with comprehensive filtering.

**Parameters:**
```typescript
{
  hookId: number;             // Hook ID (required)
  success?: boolean;          // Filter by success/failure
  method?: string;            // Filter by HTTP method
  startDate?: string;         // Start date (ISO format)
  endDate?: string;           // End date (ISO format)
  limit?: number;             // Max logs (1-1000, default: 100)
  offset?: number;            // Logs to skip (default: 0)
}
```

**Returns:**
```typescript
{
  hookLogs: Array<{
    id: number;
    timestamp: string;
    hookId: number;
    url: string;
    method: string;
    statusCode: number;
    success: boolean;
    processingTime: number;
    requestSize: number;
    responseSize: number;
    error?: string;
    retryCount: number;
  }>;
  summary: {
    totalLogs: number;
    successRate: number;
    methodBreakdown: object;
    averageProcessingTime: number;
    errorCount: number;
  };
  pagination: {
    total: number;
    limit: number;
    offset: number;
    hasMore: boolean;
  };
}
```

**Example:**
```bash
# Get webhook logs
mcp-client get-hook-logs --hookId 123

# Find failed webhook calls
mcp-client get-hook-logs --hookId 123 --success false

# Analyze POST requests
mcp-client get-hook-logs --hookId 123 --method "POST"
```

**Use Cases:**
- Webhook debugging
- Integration monitoring
- Performance analysis
- Error rate tracking
- SLA compliance verification

## Data Export

### `export-analytics-data`

Export analytics, audit logs, or execution data for external analysis with multiple format options.

**Parameters:**
```typescript
{
  organizationId: number;     // Organization ID (required)
  dataType: 'analytics' | 'audit_logs' | 'execution_history' | 'scenario_logs';  // Data type (required)
  format?: 'json' | 'csv' | 'xlsx';  // Export format (default: json)
  startDate: string;          // Start date (required, ISO format)
  endDate: string;            // End date (required, ISO format)
  includeDetails?: boolean;   // Include detailed data (default: true)
}
```

**Returns:**
```typescript
{
  exportResult: {
    exportId: string;
    status: 'initiated' | 'processing' | 'completed' | 'failed';
    downloadUrl?: string;
    fileSize?: number;
    recordCount?: number;
    estimatedCompletionTime: string;
  };
  message: string;
  downloadUrl?: string;
  estimatedCompletionTime?: string;
}
```

**Example:**
```bash
# Export analytics data as CSV
mcp-client export-analytics-data \
  --organizationId 123 \
  --dataType "analytics" \
  --format "csv" \
  --startDate "2024-01-01" \
  --endDate "2024-01-31"

# Export audit logs for compliance
mcp-client export-analytics-data \
  --organizationId 123 \
  --dataType "audit_logs" \
  --format "xlsx" \
  --startDate "2024-01-01" \
  --endDate "2024-12-31" \
  --includeDetails true
```

**Export Formats:**
- **JSON**: Full structured data with metadata
- **CSV**: Tabular format for spreadsheet analysis
- **XLSX**: Excel format with multiple sheets

**Use Cases:**
- Compliance reporting
- External analysis
- Data archival
- Business intelligence
- Regulatory audits

## Error Handling

### Common Analytics Errors

**Organization Access Denied**
```json
{
  "error": {
    "code": "ORGANIZATION_ACCESS_DENIED",
    "message": "You don't have permission to access analytics for organization 123",
    "organizationId": 123,
    "requiredPermission": "analytics:read"
  }
}
```

**Invalid Date Range**
```json
{
  "error": {
    "code": "INVALID_DATE_RANGE",
    "message": "Start date must be before end date",
    "startDate": "2024-02-01",
    "endDate": "2024-01-01"
  }
}
```

**Data Not Available**
```json
{
  "error": {
    "code": "DATA_NOT_AVAILABLE",
    "message": "Analytics data not available for the requested period",
    "period": "2023-01-01 to 2023-01-31",
    "reason": "Data retention period exceeded"
  }
}
```

### Export Errors

**Export Size Limit**
```json
{
  "error": {
    "code": "EXPORT_SIZE_LIMIT_EXCEEDED",
    "message": "Export would exceed size limit of 100MB",
    "requestedSize": "150MB",
    "suggestion": "Reduce date range or use filtering"
  }
}
```

**Export Processing Failed**
```json
{
  "error": {
    "code": "EXPORT_PROCESSING_FAILED",
    "message": "Export processing failed due to system error",
    "exportId": "exp_123456",
    "retryable": true
  }
}
```

## Performance Optimization

### Query Optimization
- Use appropriate date ranges to limit data volume
- Apply filters early to reduce processing
- Use pagination for large result sets
- Cache frequently accessed data

### Data Retention
- Analytics data: 2 years retention
- Audit logs: 7 years retention
- Execution logs: 1 year retention
- Export data: 30 days availability

### Rate Limiting
- Analytics queries: 60/hour per organization
- Audit log queries: 120/hour per organization
- Export operations: 10/hour per organization
- Performance metrics: 240/hour per organization

## Best Practices

### Analytics Queries
```bash
# Use specific date ranges
mcp-client get-organization-analytics \
  --organizationId 123 \
  --startDate "2024-01-01" \
  --endDate "2024-01-31"

# Filter by specific metrics
mcp-client get-performance-metrics \
  --organizationId 123 \
  --metric "execution_time"
```

### Audit Monitoring
```bash
# Monitor security events
mcp-client list-audit-logs \
  --action "user:login" \
  --resource "authentication" \
  --startDate "2024-01-01"

# Track specific user activity
mcp-client list-audit-logs \
  --userId 123 \
  --organizationId 456
```

### Data Export
```bash
# Export with appropriate format
mcp-client export-analytics-data \
  --organizationId 123 \
  --dataType "audit_logs" \
  --format "xlsx" \
  --startDate "2024-01-01" \
  --endDate "2024-01-31"
```

This comprehensive documentation provides all the tools needed for effective analytics, monitoring, and compliance management within the Make.com FastMCP server environment.