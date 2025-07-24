# Analytics & Monitoring Workflow Examples

This guide demonstrates comprehensive analytics and monitoring workflows using the Make.com FastMCP server for performance tracking, troubleshooting, and optimization.

## 📊 Organization Analytics Dashboard

### Getting Started with Analytics

```bash
# 1. Basic organization analytics overview
echo '{"id": 1, "method": "tools/call", "params": {"name": "get-organization-analytics", "arguments": {"organizationId": 456, "period": "month", "includeUsage": true, "includePerformance": true, "includeBilling": true}}}' | npx @modelcontextprotocol/cli chat

# Expected response structure:
# {
#   "analytics": {
#     "organizationId": 456,
#     "period": "month",
#     "dateRange": {"startDate": "2024-01-01", "endDate": "2024-01-31"},
#     "usage": {
#       "executions": 12547,
#       "successfulExecutions": 11823,
#       "operations": 45678,
#       "dataTransfer": 2.3,
#       "scenariosActive": 23
#     },
#     "performance": {
#       "averageExecutionTime": 2.4,
#       "successRate": 94.2,
#       "errorRate": 5.8,
#       "topBottlenecks": [...]
#     },
#     "billing": {
#       "operationsUsed": 45678,
#       "operationsLimit": 100000,
#       "currentCost": 127.50,
#       "projectedCost": 152.30
#     }
#   }
# }

# 2. Detailed performance metrics with hourly granularity
echo '{"id": 2, "method": "tools/call", "params": {"name": "get-performance-metrics", "arguments": {"organizationId": 456, "metric": "all", "period": "hour", "startDate": "2024-01-01T00:00:00Z", "endDate": "2024-01-01T23:59:59Z"}}}' | npx @modelcontextprotocol/cli chat
```

### Real-Time Monitoring Dashboard

```bash
# 1. Current system health check
echo '{"id": 1, "method": "tools/call", "params": {"name": "health-check", "arguments": {}}}' | npx @modelcontextprotocol/cli chat

# 2. Active executions monitoring
echo '{"id": 2, "method": "tools/call", "params": {"name": "get-execution-history", "arguments": {"organizationId": 456, "status": "running", "limit": 50}}}' | npx @modelcontextprotocol/cli chat

# 3. Real-time performance metrics
echo '{"id": 3, "method": "tools/call", "params": {"name": "get-performance-metrics", "arguments": {"organizationId": 456, "metric": "operations_per_minute", "period": "hour"}}}' | npx @modelcontextprotocol/cli chat

# 4. Recent failures and errors
echo '{"id": 4, "method": "tools/call", "params": {"name": "get-execution-history", "arguments": {"organizationId": 456, "status": "error", "limit": 25}}}' | npx @modelcontextprotocol/cli chat
```

## 🔍 Deep Dive Analytics

### Scenario Performance Analysis

```bash
# 1. List all scenarios with basic performance metrics
echo '{"id": 1, "method": "tools/call", "params": {"name": "list-scenarios", "arguments": {"organizationId": 456, "limit": 100}}}' | npx @modelcontextprotocol/cli chat

# 2. Detailed analysis of top-performing scenarios
top_scenario_ids=("scn-123" "scn-456" "scn-789")

for scenario_id in "${top_scenario_ids[@]}"; do
    echo "Analyzing scenario: $scenario_id"
    
    # Get execution history
    echo '{"id": 2, "method": "tools/call", "params": {"name": "get-execution-history", "arguments": {"scenarioId": "'$scenario_id'", "limit": 100}}}' | npx @modelcontextprotocol/cli chat
    
    # Get detailed logs
    echo '{"id": 3, "method": "tools/call", "params": {"name": "get-scenario-logs", "arguments": {"scenarioId": "'$scenario_id'", "limit": 50}}}' | npx @modelcontextprotocol/cli chat
    
    # Performance trends
    echo '{"id": 4, "method": "tools/call", "params": {"name": "get-performance-metrics", "arguments": {"organizationId": 456, "metric": "execution_time", "period": "day"}}}' | npx @modelcontextprotocol/cli chat
done
```

### Error Analysis and Root Cause Investigation

```bash
# 1. Comprehensive error analysis
echo '{"id": 1, "method": "tools/call", "params": {"name": "get-execution-history", "arguments": {"organizationId": 456, "status": "error", "startDate": "2024-01-01", "endDate": "2024-01-31", "limit": 500}}}' | npx @modelcontextprotocol/cli chat

# 2. Error patterns by scenario
echo '{"id": 2, "method": "tools/call", "params": {"name": "list-scenarios", "arguments": {"organizationId": 456, "limit": 100}}}' | npx @modelcontextprotocol/cli chat

# For each scenario with errors, get detailed error logs
failing_scenarios=("scn-error-123" "scn-error-456")

for scenario_id in "${failing_scenarios[@]}"; do
    echo "Investigating errors in scenario: $scenario_id"
    
    # Get error-level logs
    echo '{"id": 3, "method": "tools/call", "params": {"name": "get-scenario-logs", "arguments": {"scenarioId": "'$scenario_id'", "level": "error", "limit": 100}}}' | npx @modelcontextprotocol/cli chat
    
    # Get warning-level logs for context
    echo '{"id": 4, "method": "tools/call", "params": {"name": "get-scenario-logs", "arguments": {"scenarioId": "'$scenario_id'", "level": "warning", "limit": 50}}}' | npx @modelcontextprotocol/cli chat
    
    # Check associated connections
    echo '{"id": 5, "method": "tools/call", "params": {"name": "get-scenario", "arguments": {"scenarioId": "'$scenario_id'", "includeBlueprint": true}}}' | npx @modelcontextprotocol/cli chat
done

# 3. Connection health analysis
echo '{"id": 6, "method": "tools/call", "params": {"name": "list-connections", "arguments": {"status": "invalid", "limit": 50}}}' | npx @modelcontextprotocol/cli chat
```

## 🔧 Troubleshooting Workflows

### Incomplete Execution Management

```bash
# 1. List all incomplete executions
echo '{"id": 1, "method": "tools/call", "params": {"name": "list-incomplete-executions", "arguments": {"organizationId": 456, "limit": 100}}}' | npx @modelcontextprotocol/cli chat

# Expected response:
# {
#   "incompleteExecutions": [
#     {
#       "id": 789,
#       "scenarioId": 123,
#       "scenarioName": "Customer Data Sync",
#       "status": "paused",
#       "startedAt": "2024-01-15T10:30:00Z",
#       "pausedAt": "2024-01-15T10:45:00Z",
#       "operations": 15,
#       "completedSteps": 3,
#       "totalSteps": 8,
#       "canResume": true,
#       "error": "Connection timeout",
#       "reason": "Network connectivity issue"
#     }
#   ]
# }

# 2. Analyze resumable executions
echo '{"id": 2, "method": "tools/call", "params": {"name": "list-incomplete-executions", "arguments": {"canResume": true, "limit": 50}}}' | npx @modelcontextprotocol/cli chat

# 3. Resolve incomplete executions systematically
incomplete_execution_ids=("exec-789" "exec-101" "exec-202")

for exec_id in "${incomplete_execution_ids[@]}"; do
    echo "Resolving incomplete execution: $exec_id"
    
    # Try to retry the execution
    echo '{"id": 3, "method": "tools/call", "params": {"name": "resolve-incomplete-execution", "arguments": {"executionId": "'$exec_id'", "action": "retry", "reason": "Network issue resolved, retrying execution"}}}' | npx @modelcontextprotocol/cli chat
    
    # If retry fails, skip with documentation
    # echo '{"id": 4, "method": "tools/call", "params": {"name": "resolve-incomplete-execution", "arguments": {"executionId": "'$exec_id'", "action": "skip", "reason": "Data source temporarily unavailable, skipping this execution"}}}' | npx @modelcontextprotocol/cli chat
done

# 4. Monitor resolution results
echo '{"id": 5, "method": "tools/call", "params": {"name": "get-execution-history", "arguments": {"organizationId": 456, "status": "success", "limit": 20}}}' | npx @modelcontextprotocol/cli chat
```

### Webhook Monitoring and Debugging

```bash
# 1. List all webhooks and their health
echo '{"id": 1, "method": "tools/call", "params": {"name": "list-webhooks", "arguments": {"organizationId": 456, "status": "active", "limit": 50}}}' | npx @modelcontextprotocol/cli chat

# 2. Analyze webhook performance
webhook_ids=("hook-123" "hook-456" "hook-789")

for hook_id in "${webhook_ids[@]}"; do
    echo "Analyzing webhook: $hook_id"
    
    # Get webhook execution logs
    echo '{"id": 2, "method": "tools/call", "params": {"name": "get-hook-logs", "arguments": {"hookId": "'$hook_id'", "limit": 100}}}' | npx @modelcontextprotocol/cli chat
    
    # Check for failed webhook calls
    echo '{"id": 3, "method": "tools/call", "params": {"name": "get-hook-logs", "arguments": {"hookId": "'$hook_id'", "success": false, "limit": 50}}}' | npx @modelcontextprotocol/cli chat
done

# 3. Webhook performance summary
echo '{"id": 4, "method": "tools/call", "params": {"name": "get-hook-logs", "arguments": {"hookId": "hook-123", "startDate": "2024-01-01", "endDate": "2024-01-31"}}}' | npx @modelcontextprotocol/cli chat
```

## 📈 Performance Optimization

### Identifying Performance Bottlenecks

```bash
# 1. Get execution time metrics across all scenarios
echo '{"id": 1, "method": "tools/call", "params": {"name": "get-performance-metrics", "arguments": {"organizationId": 456, "metric": "execution_time", "period": "week"}}}' | npx @modelcontextprotocol/cli chat

# 2. Find scenarios with longest execution times
echo '{"id": 2, "method": "tools/call", "params": {"name": "get-execution-history", "arguments": {"organizationId": 456, "limit": 100}}}' | npx @modelcontextprotocol/cli chat

# 3. Analyze data transfer patterns
echo '{"id": 3, "method": "tools/call", "params": {"name": "get-performance-metrics", "arguments": {"organizationId": 456, "metric": "data_transfer", "period": "day"}}}' | npx @modelcontextprotocol/cli chat

# 4. Success rate analysis
echo '{"id": 4, "method": "tools/call", "params": {"name": "get-performance-metrics", "arguments": {"organizationId": 456, "metric": "success_rate", "period": "month"}}}' | npx @modelcontextprotocol/cli chat

# 5. Operations per minute trends
echo '{"id": 5, "method": "tools/call", "params": {"name": "get-performance-metrics", "arguments": {"organizationId": 456, "metric": "operations_per_minute", "period": "hour"}}}' | npx @modelcontextprotocol/cli chat
```

### Optimization Recommendations Engine

```bash
# 1. Generate comprehensive optimization report
echo '{"id": 1, "method": "tools/call", "params": {"name": "get-organization-analytics", "arguments": {"organizationId": 456, "period": "month", "includeUsage": true, "includePerformance": true}}}' | npx @modelcontextprotocol/cli chat

# 2. Analyze scenario blueprints for optimization opportunities
slow_scenarios=("scn-slow-123" "scn-slow-456")

for scenario_id in "${slow_scenarios[@]}"; do
    echo "Analyzing scenario blueprint: $scenario_id"
    
    # Get scenario details with blueprint
    echo '{"id": 2, "method": "tools/call", "params": {"name": "get-scenario", "arguments": {"scenarioId": "'$scenario_id'", "includeBlueprint": true, "includeExecutions": true}}}' | npx @modelcontextprotocol/cli chat
    
    # Get execution patterns
    echo '{"id": 3, "method": "tools/call", "params": {"name": "get-execution-history", "arguments": {"scenarioId": "'$scenario_id'", "limit": 50}}}' | npx @modelcontextprotocol/cli chat
done

# 3. Connection performance analysis
echo '{"id": 4, "method": "tools/call", "params": {"name": "list-connections", "arguments": {"limit": 100}}}' | npx @modelcontextprotocol/cli chat

# 4. Resource utilization analysis
echo '{"id": 5, "method": "tools/call", "params": {"name": "get-usage-metrics", "arguments": {"organizationId": 456, "period": "current", "breakdown": ["scenario", "app", "team"], "includeProjections": true, "includeRecommendations": true}}}' | npx @modelcontextprotocol/cli chat
```

## 📋 Audit and Compliance

### Comprehensive Audit Trail Analysis

```bash
# 1. Security audit - track all administrative actions
echo '{"id": 1, "method": "tools/call", "params": {"name": "list-audit-logs", "arguments": {"organizationId": 456, "action": "user:role_change", "startDate": "2024-01-01", "endDate": "2024-01-31", "limit": 100}}}' | npx @modelcontextprotocol/cli chat

# 2. Scenario modification tracking
echo '{"id": 2, "method": "tools/call", "params": {"name": "list-audit-logs", "arguments": {"organizationId": 456, "resource": "scenario", "startDate": "2024-01-01", "limit": 200}}}' | npx @modelcontextprotocol/cli chat

# 3. Connection changes audit
echo '{"id": 3, "method": "tools/call", "params": {"name": "list-audit-logs", "arguments": {"organizationId": 456, "action": "connection:create", "limit": 100}}}' | npx @modelcontextprotocol/cli chat

echo '{"id": 4, "method": "tools/call", "params": {"name": "list-audit-logs", "arguments": {"organizationId": 456, "action": "connection:update", "limit": 100}}}' | npx @modelcontextprotocol/cli chat

echo '{"id": 5, "method": "tools/call", "params": {"name": "list-audit-logs", "arguments": {"organizationId": 456, "action": "connection:delete", "limit": 100}}}' | npx @modelcontextprotocol/cli chat

# 4. User activity monitoring
echo '{"id": 6, "method": "tools/call", "params": {"name": "list-audit-logs", "arguments": {"organizationId": 456, "userId": 789, "startDate": "2024-01-01", "limit": 150}}}' | npx @modelcontextprotocol/cli chat

# 5. Team-level audit
echo '{"id": 7, "method": "tools/call", "params": {"name": "list-audit-logs", "arguments": {"teamId": 123, "startDate": "2024-01-01", "limit": 200}}}' | npx @modelcontextprotocol/cli chat
```

### Detailed Audit Log Investigation

```bash
# 1. Investigate specific audit log entries
audit_log_ids=("log-123" "log-456" "log-789")

for log_id in "${audit_log_ids[@]}"; do
    echo "Investigating audit log: $log_id"
    
    # Get detailed audit log entry
    echo '{"id": 1, "method": "tools/call", "params": {"name": "get-audit-log", "arguments": {"logId": "'$log_id'"}}}' | npx @modelcontextprotocol/cli chat
done

# 2. Security event correlation
echo '{"id": 2, "method": "tools/call", "params": {"name": "list-audit-logs", "arguments": {"organizationId": 456, "action": "user:login", "startDate": "2024-01-15T08:00:00Z", "endDate": "2024-01-15T10:00:00Z", "limit": 50}}}' | npx @modelcontextprotocol/cli chat

# 3. Failed authentication attempts
echo '{"id": 3, "method": "tools/call", "params": {"name": "list-audit-logs", "arguments": {"organizationId": 456, "action": "user:login_failed", "limit": 100}}}' | npx @modelcontextprotocol/cli chat
```

## 📊 Data Export and Reporting

### Comprehensive Data Export

```bash
# 1. Export analytics data for external analysis
echo '{"id": 1, "method": "tools/call", "params": {"name": "export-analytics-data", "arguments": {"organizationId": 456, "dataType": "analytics", "format": "csv", "startDate": "2024-01-01", "endDate": "2024-01-31", "includeDetails": true}}}' | npx @modelcontextprotocol/cli chat

# 2. Export audit logs for compliance
echo '{"id": 2, "method": "tools/call", "params": {"name": "export-analytics-data", "arguments": {"organizationId": 456, "dataType": "audit_logs", "format": "xlsx", "startDate": "2024-01-01", "endDate": "2024-12-31", "includeDetails": true}}}' | npx @modelcontextprotocol/cli chat

# 3. Export execution history for performance analysis
echo '{"id": 3, "method": "tools/call", "params": {"name": "export-analytics-data", "arguments": {"organizationId": 456, "dataType": "execution_history", "format": "json", "startDate": "2024-01-01", "endDate": "2024-01-31", "includeDetails": true}}}' | npx @modelcontextprotocol/cli chat

# 4. Export scenario logs for debugging
echo '{"id": 4, "method": "tools/call", "params": {"name": "export-analytics-data", "arguments": {"organizationId": 456, "dataType": "scenario_logs", "format": "csv", "startDate": "2024-01-01", "endDate": "2024-01-31", "includeDetails": false}}}' | npx @modelcontextprotocol/cli chat
```

### Automated Reporting Workflows

```bash
# 1. Daily performance report
echo '{"id": 1, "method": "tools/call", "params": {"name": "get-organization-analytics", "arguments": {"organizationId": 456, "period": "day", "includeUsage": true, "includePerformance": true}}}' | npx @modelcontextprotocol/cli chat

# 2. Weekly executive summary
echo '{"id": 2, "method": "tools/call", "params": {"name": "get-organization-analytics", "arguments": {"organizationId": 456, "period": "week", "includeUsage": true, "includePerformance": true, "includeBilling": true}}}' | npx @modelcontextprotocol/cli chat

# 3. Monthly compliance report
echo '{"id": 3, "method": "tools/call", "params": {"name": "list-audit-logs", "arguments": {"organizationId": 456, "startDate": "2024-01-01", "endDate": "2024-01-31", "limit": 1000}}}' | npx @modelcontextprotocol/cli chat

# 4. Quarterly optimization report
echo '{"id": 4, "method": "tools/call", "params": {"name": "get-usage-metrics", "arguments": {"organizationId": 456, "period": "last_3_months", "breakdown": ["scenario", "team", "time"], "includeProjections": true, "includeRecommendations": true}}}' | npx @modelcontextprotocol/cli chat
```

## 🚨 Proactive Monitoring and Alerting

### Setting up Automated Monitoring

```bash
# 1. Create performance monitoring notifications
echo '{"id": 1, "method": "tools/call", "params": {"name": "create-notification", "arguments": {"type": "system", "category": "warning", "priority": "medium", "title": "Performance Degradation Alert", "message": "System performance has degraded below acceptable thresholds", "recipients": {"teams": [123, 456]}, "channels": {"email": true, "slack": true}, "schedule": {"recurring": {"frequency": "daily", "interval": 1}}}}}' | npx @modelcontextprotocol/cli chat

# 2. Error rate monitoring
echo '{"id": 2, "method": "tools/call", "params": {"name": "create-notification", "arguments": {"type": "system", "category": "alert", "priority": "high", "title": "High Error Rate Alert", "message": "Error rate has exceeded 10% for the past hour", "recipients": {"teams": [123]}, "channels": {"email": true, "slack": true, "sms": true}}}}' | npx @modelcontextprotocol/cli chat

# 3. Usage threshold alerts
echo '{"id": 3, "method": "tools/call", "params": {"name": "create-notification", "arguments": {"type": "billing", "category": "warning", "priority": "medium", "title": "Usage Threshold Alert", "message": "Monthly usage has reached 80% of plan limits", "recipients": {"organizations": [456]}, "channels": {"email": true}}}}' | npx @modelcontextprotocol/cli chat

# 4. Security monitoring
echo '{"id": 4, "method": "tools/call", "params": {"name": "create-notification", "arguments": {"type": "security", "category": "alert", "priority": "critical", "title": "Security Event Alert", "message": "Unusual authentication activity detected", "recipients": {"users": [789]}, "channels": {"email": true, "sms": true}}}}' | npx @modelcontextprotocol/cli chat
```

### Advanced Monitoring Workflows

```bash
# 1. Real-time health monitoring script
#!/bin/bash

# Function to check system health
check_health() {
    health_result=$(echo '{"id": 1, "method": "tools/call", "params": {"name": "health-check", "arguments": {}}}' | npx @modelcontextprotocol/cli chat)
    
    if [[ $health_result == *"healthy"* ]]; then
        echo "System healthy at $(date)"
        return 0
    else
        echo "System health issue detected at $(date): $health_result"
        return 1
    fi
}

# Function to check error rates
check_error_rates() {
    metrics=$(echo '{"id": 1, "method": "tools/call", "params": {"name": "get-performance-metrics", "arguments": {"organizationId": 456, "metric": "success_rate", "period": "hour"}}}' | npx @modelcontextprotocol/cli chat)
    
    # Parse success rate and alert if below threshold
    # Implementation would parse JSON and check thresholds
    echo "Current metrics: $metrics"
}

# Function to monitor incomplete executions
monitor_incomplete_executions() {
    incomplete=$(echo '{"id": 1, "method": "tools/call", "params": {"name": "list-incomplete-executions", "arguments": {"organizationId": 456, "limit": 10}}}' | npx @modelcontextprotocol/cli chat)
    
    # Check if there are any incomplete executions that need attention
    echo "Incomplete executions: $incomplete"
}

# Main monitoring loop
while true; do
    check_health
    check_error_rates
    monitor_incomplete_executions
    
    # Wait 5 minutes before next check
    sleep 300
done
```

## 📈 Trend Analysis and Forecasting

### Historical Trend Analysis

```bash
# 1. 3-month execution trend analysis
months=("2024-01" "2024-02" "2024-03")

for month in "${months[@]}"; do
    echo "Analyzing month: $month"
    
    echo '{"id": 1, "method": "tools/call", "params": {"name": "get-organization-analytics", "arguments": {"organizationId": 456, "startDate": "'$month'-01", "endDate": "'$month'-31", "period": "month", "includeUsage": true, "includePerformance": true}}}' | npx @modelcontextprotocol/cli chat
done

# 2. Weekly performance trends
echo '{"id": 2, "method": "tools/call", "params": {"name": "get-performance-metrics", "arguments": {"organizationId": 456, "metric": "execution_time", "period": "week", "startDate": "2024-01-01", "endDate": "2024-03-31"}}}' | npx @modelcontextprotocol/cli chat

# 3. Usage growth analysis
echo '{"id": 3, "method": "tools/call", "params": {"name": "get-usage-metrics", "arguments": {"organizationId": 456, "period": "last_6_months", "breakdown": ["scenario", "team", "time"], "includeProjections": true}}}' | npx @modelcontextprotocol/cli chat
```

### Predictive Analytics

```bash
# 1. Capacity planning analysis
echo '{"id": 1, "method": "tools/call", "params": {"name": "get-usage-metrics", "arguments": {"organizationId": 456, "period": "last_3_months", "includeProjections": true, "includeRecommendations": true}}}' | npx @modelcontextprotocol/cli chat

# 2. Performance forecast
echo '{"id": 2, "method": "tools/call", "params": {"name": "get-performance-metrics", "arguments": {"organizationId": 456, "metric": "all", "period": "month"}}}' | npx @modelcontextprotocol/cli chat

# 3. Cost projection analysis
echo '{"id": 3, "method": "tools/call", "params": {"name": "get-usage-metrics", "arguments": {"organizationId": 456, "period": "current", "breakdown": ["scenario", "team"], "includeProjections": true}}}' | npx @modelcontextprotocol/cli chat
```

This comprehensive analytics and monitoring workflow provides the foundation for maintaining optimal performance, ensuring reliability, and making data-driven decisions about your Make.com automation infrastructure.