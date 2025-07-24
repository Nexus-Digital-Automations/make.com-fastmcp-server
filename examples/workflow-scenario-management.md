# Scenario Management Workflow Examples

This guide demonstrates complete workflows for managing Make.com scenarios using the FastMCP server.

## 🚀 Complete Scenario Development Workflow

### Step 1: Environment Setup and Validation

```bash
# 1. Check server health and API connectivity
echo '{"id": 1, "method": "tools/call", "params": {"name": "health-check", "arguments": {}}}' | npx @modelcontextprotocol/cli chat

# Expected response:
# {
#   "status": "healthy",
#   "makeApi": "accessible",
#   "rateLimiter": {"remaining": 100, "resetTime": "..."}
# }

# 2. Validate current user permissions
echo '{"id": 2, "method": "tools/call", "params": {"name": "get-current-user", "arguments": {}}}' | npx @modelcontextprotocol/cli chat

# 3. Test Make.com API configuration
echo '{"id": 3, "method": "tools/call", "params": {"name": "test-configuration", "arguments": {}}}' | npx @modelcontextprotocol/cli chat
```

### Step 2: Organize Your Workspace

```bash
# 1. List available teams
echo '{"id": 4, "method": "tools/call", "params": {"name": "list-teams", "arguments": {"organizationId": 456}}}' | npx @modelcontextprotocol/cli chat

# 2. Create a project folder for organization
echo '{"id": 5, "method": "tools/call", "params": {"name": "create-folder", "arguments": {"name": "E-commerce Integration", "description": "Scenarios for e-commerce platform integration", "organizationId": 456}}}' | npx @modelcontextprotocol/cli chat

# 3. Set up team-level variables for the project
echo '{"id": 6, "method": "tools/call", "params": {"name": "create-custom-variable", "arguments": {"key": "ECOMMERCE_API_BASE", "value": "https://api.ecommerce.com/v1", "scope": "team", "teamId": 123, "description": "Base URL for e-commerce API", "isEncrypted": false}}}' | npx @modelcontextprotocol/cli chat

echo '{"id": 7, "method": "tools/call", "params": {"name": "create-custom-variable", "arguments": {"key": "ECOMMERCE_API_KEY", "value": "your-api-key-here", "scope": "team", "teamId": 123, "description": "API key for e-commerce platform", "isEncrypted": true}}}' | npx @modelcontextprotocol/cli chat
```

### Step 3: Set Up Connections

```bash
# 1. Create database connection for customer data
echo '{"id": 8, "method": "tools/call", "params": {"name": "create-connection", "arguments": {"name": "Customer Database", "service": "postgresql", "accountName": "production-db", "credentials": {"host": "db.company.com", "port": 5432, "database": "customers", "username": "make_user", "password": "secure_password"}, "metadata": {"environment": "production", "purpose": "customer-data"}}}}' | npx @modelcontextprotocol/cli chat

# 2. Create e-commerce platform connection
echo '{"id": 9, "method": "tools/call", "params": {"name": "create-connection", "arguments": {"name": "E-commerce Platform", "service": "shopify", "accountName": "mystore", "credentials": {"api_key": "your-shopify-api-key", "password": "your-shopify-password", "shop_domain": "mystore.myshopify.com"}, "metadata": {"store": "main", "region": "us-east"}}}}' | npx @modelcontextprotocol/cli chat

# 3. Create Slack connection for notifications
echo '{"id": 10, "method": "tools/call", "params": {"name": "create-connection", "arguments": {"name": "Team Slack", "service": "slack", "accountName": "company-workspace", "credentials": {"bot_token": "xoxb-your-bot-token", "workspace": "company"}, "metadata": {"channel": "#ecommerce-alerts"}}}}' | npx @modelcontextprotocol/cli chat

# 4. Verify connections are working
echo '{"id": 11, "method": "tools/call", "params": {"name": "list-connections", "arguments": {"status": "valid", "limit": 10}}}' | npx @modelcontextprotocol/cli chat
```

### Step 4: Create and Configure Scenarios

```bash
# 1. Create main customer sync scenario
echo '{"id": 12, "method": "tools/call", "params": {"name": "create-scenario", "arguments": {"name": "Customer Data Sync", "teamId": 123, "folderId": "folder-ecommerce-123", "blueprint": {"modules": [{"app": "postgresql", "module": "select"}, {"app": "shopify", "module": "create-customer"}], "connections": [{"id": "conn-db-123"}, {"id": "conn-shopify-456"}]}, "scheduling": {"type": "interval", "interval": 30}}}}' | npx @modelcontextprotocol/cli chat

# 2. Create order processing scenario
echo '{"id": 13, "method": "tools/call", "params": {"name": "create-scenario", "arguments": {"name": "Order Processing Automation", "teamId": 123, "folderId": "folder-ecommerce-123", "blueprint": {"modules": [{"app": "webhook", "module": "listen"}, {"app": "postgresql", "module": "insert"}, {"app": "slack", "module": "send-message"}]}, "scheduling": {"type": "immediately"}}}}' | npx @modelcontextprotocol/cli chat

# 3. Create inventory monitoring scenario
echo '{"id": 14, "method": "tools/call", "params": {"name": "create-scenario", "arguments": {"name": "Inventory Low Stock Alert", "teamId": 123, "folderId": "folder-ecommerce-123", "scheduling": {"type": "cron", "cron": "0 9 * * *"}}}}' | npx @modelcontextprotocol/cli chat

# 4. List created scenarios to verify
echo '{"id": 15, "method": "tools/call", "params": {"name": "list-scenarios", "arguments": {"teamId": 123, "folderId": "folder-ecommerce-123", "limit": 10}}}' | npx @modelcontextprotocol/cli chat
```

### Step 5: Test and Validate Scenarios

```bash
# 1. Get detailed scenario information
echo '{"id": 16, "method": "tools/call", "params": {"name": "get-scenario", "arguments": {"scenarioId": "scn-customer-sync-123", "includeBlueprint": true, "includeExecutions": true}}}' | npx @modelcontextprotocol/cli chat

# 2. Run customer sync scenario in test mode
echo '{"id": 17, "method": "tools/call", "params": {"name": "run-scenario", "arguments": {"scenarioId": "scn-customer-sync-123", "wait": true, "timeout": 300}}}' | npx @modelcontextprotocol/cli chat

# 3. Check execution logs for any issues
echo '{"id": 18, "method": "tools/call", "params": {"name": "get-scenario-logs", "arguments": {"scenarioId": "scn-customer-sync-123", "level": "error", "limit": 50}}}' | npx @modelcontextprotocol/cli chat

# 4. Monitor execution history
echo '{"id": 19, "method": "tools/call", "params": {"name": "get-execution-history", "arguments": {"scenarioId": "scn-customer-sync-123", "status": "error", "limit": 10}}}' | npx @modelcontextprotocol/cli chat
```

### Step 6: Set Up Monitoring and Alerts

```bash
# 1. Create notification template for scenario failures
echo '{"id": 20, "method": "tools/call", "params": {"name": "create-notification-template", "arguments": {"name": "Scenario Failure Alert", "type": "slack", "category": "scenario", "template": {"body": "🚨 Scenario {{scenarioName}} failed at {{timestamp}}. Error: {{errorMessage}}", "variables": [{"name": "scenarioName", "type": "string", "required": true}, {"name": "timestamp", "type": "string", "required": true}, {"name": "errorMessage", "type": "string", "required": true}]}}}}' | npx @modelcontextprotocol/cli chat

# 2. Set up notification for scenario failures
echo '{"id": 21, "method": "tools/call", "params": {"name": "create-notification", "arguments": {"type": "scenario", "category": "alert", "priority": "high", "title": "E-commerce Scenario Failure", "message": "One of your e-commerce scenarios has failed", "recipients": {"teams": [123]}, "channels": {"email": true, "slack": true}, "templateId": "tmpl-failure-123"}}}' | npx @modelcontextprotocol/cli chat

# 3. Configure email preferences for scenario notifications
echo '{"id": 22, "method": "tools/call", "params": {"name": "update-email-preferences", "arguments": {"preferences": {"scenarios": {"enabled": true, "frequency": "immediate", "categories": {"failures": true, "warnings": true}, "filters": {"onlyMyScenarios": false, "teamIds": [123]}}}}}}' | npx @modelcontextprotocol/cli chat
```

### Step 7: Production Deployment

```bash
# 1. Clone scenarios for production environment
echo '{"id": 23, "method": "tools/call", "params": {"name": "clone-scenario", "arguments": {"scenarioId": "scn-customer-sync-123", "name": "PROD - Customer Data Sync", "teamId": 789, "folderId": "folder-prod-456", "active": false}}}' | npx @modelcontextprotocol/cli chat

# 2. Update production scenario with production variables
echo '{"id": 24, "method": "tools/call", "params": {"name": "create-custom-variable", "arguments": {"key": "PROD_DB_HOST", "value": "prod-db.company.com", "scope": "team", "teamId": 789, "isEncrypted": false}}}' | npx @modelcontextprotocol/cli chat

# 3. Update scenario configuration for production
echo '{"id": 25, "method": "tools/call", "params": {"name": "update-scenario", "arguments": {"scenarioId": "scn-prod-customer-sync-456", "scheduling": {"type": "cron", "cron": "0 */2 * * *"}}}}' | npx @modelcontextprotocol/cli chat

# 4. Activate production scenarios
echo '{"id": 26, "method": "tools/call", "params": {"name": "update-scenario", "arguments": {"scenarioId": "scn-prod-customer-sync-456", "active": true}}}' | npx @modelcontextprotocol/cli chat

# 5. Verify production deployment
echo '{"id": 27, "method": "tools/call", "params": {"name": "list-scenarios", "arguments": {"teamId": 789, "active": true, "limit": 10}}}' | npx @modelcontextprotocol/cli chat
```

## 🔄 Scenario Lifecycle Management

### Development → Staging → Production Pipeline

```bash
# 1. Development Phase: Create and test scenarios
dev_scenario_id="scn-dev-123"

# Create development scenario
echo '{"id": 1, "method": "tools/call", "params": {"name": "create-scenario", "arguments": {"name": "DEV - Data Processing", "teamId": 100, "active": false}}}' | npx @modelcontextprotocol/cli chat

# Test development scenario
echo '{"id": 2, "method": "tools/call", "params": {"name": "run-scenario", "arguments": {"scenarioId": "'$dev_scenario_id'", "wait": true}}}' | npx @modelcontextprotocol/cli chat

# 2. Staging Phase: Clone to staging environment
echo '{"id": 3, "method": "tools/call", "params": {"name": "clone-scenario", "arguments": {"scenarioId": "'$dev_scenario_id'", "name": "STAGING - Data Processing", "teamId": 200, "active": false}}}' | npx @modelcontextprotocol/cli chat

# Run staging tests
staging_scenario_id="scn-staging-456"
echo '{"id": 4, "method": "tools/call", "params": {"name": "run-scenario", "arguments": {"scenarioId": "'$staging_scenario_id'", "wait": true}}}' | npx @modelcontextprotocol/cli chat

# 3. Production Phase: Deploy to production
echo '{"id": 5, "method": "tools/call", "params": {"name": "clone-scenario", "arguments": {"scenarioId": "'$staging_scenario_id'", "name": "PROD - Data Processing", "teamId": 300, "active": true}}}' | npx @modelcontextprotocol/cli chat
```

### Rollback Strategy

```bash
# 1. List scenario versions
echo '{"id": 1, "method": "tools/call", "params": {"name": "list-scenarios", "arguments": {"search": "Data Processing", "limit": 10}}}' | npx @modelcontextprotocol/cli chat

# 2. Deactivate current production scenario
echo '{"id": 2, "method": "tools/call", "params": {"name": "update-scenario", "arguments": {"scenarioId": "scn-prod-new-789", "active": false}}}' | npx @modelcontextprotocol/cli chat

# 3. Reactivate previous version
echo '{"id": 3, "method": "tools/call", "params": {"name": "update-scenario", "arguments": {"scenarioId": "scn-prod-old-456", "active": true}}}' | npx @modelcontextprotocol/cli chat

# 4. Verify rollback success
echo '{"id": 4, "method": "tools/call", "params": {"name": "run-scenario", "arguments": {"scenarioId": "scn-prod-old-456", "wait": true}}}' | npx @modelcontextprotocol/cli chat
```

## 🔧 Advanced Scenario Configuration

### Dynamic Configuration with Variables

```bash
# 1. Create environment-specific variables
environments=("dev" "staging" "prod")
for env in "${environments[@]}"; do
    echo '{"id": 1, "method": "tools/call", "params": {"name": "create-custom-variable", "arguments": {"key": "API_ENDPOINT_'$env'", "value": "https://'$env'-api.company.com", "scope": "organization", "description": "'$env' environment API endpoint"}}}' | npx @modelcontextprotocol/cli chat
    
    echo '{"id": 2, "method": "tools/call", "params": {"name": "create-custom-variable", "arguments": {"key": "DB_CONNECTION_'$env'", "value": "'$env'-db.company.com", "scope": "organization", "description": "'$env' database connection", "isEncrypted": true}}}' | npx @modelcontextprotocol/cli chat
done

# 2. Create scenarios that use environment variables
echo '{"id": 3, "method": "tools/call", "params": {"name": "create-scenario", "arguments": {"name": "{{ENV}} - Customer Sync", "blueprint": {"modules": [{"app": "http", "module": "request", "parameters": {"url": "{{API_ENDPOINT_{{ENV}}}}/customers"}}]}}}}' | npx @modelcontextprotocol/cli chat
```

### Conditional Scenario Execution

```bash
# 1. Create scenario with conditional logic
echo '{"id": 1, "method": "tools/call", "params": {"name": "create-scenario", "arguments": {"name": "Smart Data Processor", "blueprint": {"modules": [{"app": "webhook", "module": "listen"}, {"app": "condition", "module": "if", "parameters": {"condition": "{{data.type}} = customer"}}, {"app": "postgresql", "module": "insert", "route": [{"condition": true}]}, {"app": "slack", "module": "send-message", "route": [{"condition": false}]}]}}}}' | npx @modelcontextprotocol/cli chat

# 2. Test conditional execution with different data types
echo '{"id": 2, "method": "tools/call", "params": {"name": "run-scenario", "arguments": {"scenarioId": "scn-smart-processor-123", "wait": true}}}' | npx @modelcontextprotocol/cli chat
```

## 📊 Scenario Performance Monitoring

### Real-time Monitoring Dashboard

```bash
# 1. Get execution metrics for all scenarios
echo '{"id": 1, "method": "tools/call", "params": {"name": "get-organization-analytics", "arguments": {"organizationId": 456, "period": "day", "includePerformance": true}}}' | npx @modelcontextprotocol/cli chat

# 2. Monitor specific scenario performance
echo '{"id": 2, "method": "tools/call", "params": {"name": "get-execution-history", "arguments": {"scenarioId": "scn-customer-sync-123", "limit": 100}}}' | npx @modelcontextprotocol/cli chat

# 3. Get performance metrics
echo '{"id": 3, "method": "tools/call", "params": {"name": "get-performance-metrics", "arguments": {"organizationId": 456, "metric": "execution_time", "period": "hour"}}}' | npx @modelcontextprotocol/cli chat

# 4. Export performance data for analysis
echo '{"id": 4, "method": "tools/call", "params": {"name": "export-analytics-data", "arguments": {"organizationId": 456, "dataType": "execution_history", "format": "csv", "startDate": "2024-01-01", "endDate": "2024-01-31"}}}' | npx @modelcontextprotocol/cli chat
```

### Automated Performance Alerts

```bash
# 1. Set up performance monitoring notification
echo '{"id": 1, "method": "tools/call", "params": {"name": "create-notification", "arguments": {"type": "system", "category": "warning", "priority": "medium", "title": "Scenario Performance Alert", "message": "Scenario execution time exceeded threshold", "recipients": {"teams": [123]}, "channels": {"email": true}, "schedule": {"recurring": {"frequency": "daily", "interval": 1}}}}}' | npx @modelcontextprotocol/cli chat

# 2. Monitor for incomplete executions
echo '{"id": 2, "method": "tools/call", "params": {"name": "list-incomplete-executions", "arguments": {"scenarioId": 123, "canResume": true}}}' | npx @modelcontextprotocol/cli chat

# 3. Resolve incomplete executions
echo '{"id": 3, "method": "tools/call", "params": {"name": "resolve-incomplete-execution", "arguments": {"executionId": 789, "action": "retry", "reason": "Network issue resolved"}}}' | npx @modelcontextprotocol/cli chat
```

## 🛠️ Maintenance and Optimization

### Regular Maintenance Tasks

```bash
# 1. Clean up old executions (example automation)
echo '{"id": 1, "method": "tools/call", "params": {"name": "get-execution-history", "arguments": {"organizationId": 456, "status": "completed", "limit": 1000}}}' | npx @modelcontextprotocol/cli chat

# 2. Audit scenario configurations
echo '{"id": 2, "method": "tools/call", "params": {"name": "list-audit-logs", "arguments": {"organizationId": 456, "action": "scenario:update", "startDate": "2024-01-01", "limit": 100}}}' | npx @modelcontextprotocol/cli chat

# 3. Review and update custom variables
echo '{"id": 3, "method": "tools/call", "params": {"name": "list-custom-variables", "arguments": {"scope": "organization", "includeUsage": true}}}' | npx @modelcontextprotocol/cli chat

# 4. Optimize scenario scheduling
echo '{"id": 4, "method": "tools/call", "params": {"name": "update-scenario", "arguments": {"scenarioId": "scn-heavy-task-123", "scheduling": {"type": "cron", "cron": "0 2 * * 0"}}}}' | npx @modelcontextprotocol/cli chat
```

### Performance Optimization

```bash
# 1. Identify slow-running scenarios
echo '{"id": 1, "method": "tools/call", "params": {"name": "get-performance-metrics", "arguments": {"organizationId": 456, "metric": "execution_time", "period": "week"}}}' | npx @modelcontextprotocol/cli chat

# 2. Review scenario blueprints for optimization
echo '{"id": 2, "method": "tools/call", "params": {"name": "get-scenario", "arguments": {"scenarioId": "scn-slow-123", "includeBlueprint": true}}}' | npx @modelcontextprotocol/cli chat

# 3. Split complex scenarios into smaller ones
echo '{"id": 3, "method": "tools/call", "params": {"name": "create-scenario", "arguments": {"name": "Data Processing - Part 1", "blueprint": {"modules": [{"app": "postgresql", "module": "select", "parameters": {"limit": 1000}}]}}}}' | npx @modelcontextprotocol/cli chat

echo '{"id": 4, "method": "tools/call", "params": {"name": "create-scenario", "arguments": {"name": "Data Processing - Part 2", "blueprint": {"modules": [{"app": "http", "module": "request"}]}}}}' | npx @modelcontextprotocol/cli chat
```

This comprehensive workflow demonstrates how to manage the complete lifecycle of Make.com scenarios using the FastMCP server, from initial development through production deployment and ongoing maintenance.