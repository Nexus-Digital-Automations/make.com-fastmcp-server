# Make.com FastMCP Server - Usage Examples

This directory contains comprehensive usage examples and tutorials demonstrating how to use the Make.com FastMCP server for common workflows and use cases.

## 📋 Quick Start Examples

### Basic Setup and Health Check

```bash
# 1. Start the FastMCP server
npm run dev

# 2. Test server connectivity
# In another terminal, using the MCP client:
echo '{"id": 1, "method": "tools/call", "params": {"name": "health-check", "arguments": {}}}' | npx @modelcontextprotocol/cli chat

# 3. Get server information
echo '{"id": 2, "method": "tools/call", "params": {"name": "server-info", "arguments": {}}}' | npx @modelcontextprotocol/cli chat
```

## 🚀 Scenario Management Workflows

### Creating and Managing Scenarios

```bash
# List existing scenarios
echo '{"id": 1, "method": "tools/call", "params": {"name": "list-scenarios", "arguments": {"limit": 10}}}' | npx @modelcontextprotocol/cli chat

# Create a new scenario
echo '{"id": 2, "method": "tools/call", "params": {"name": "create-scenario", "arguments": {"name": "Data Sync Process", "teamId": "123"}}}' | npx @modelcontextprotocol/cli chat

# Get scenario details
echo '{"id": 3, "method": "tools/call", "params": {"name": "get-scenario", "arguments": {"scenarioId": "456", "includeBlueprint": true}}}' | npx @modelcontextprotocol/cli chat

# Update scenario configuration
echo '{"id": 4, "method": "tools/call", "params": {"name": "update-scenario", "arguments": {"scenarioId": "456", "active": true, "name": "Updated Data Sync"}}}' | npx @modelcontextprotocol/cli chat

# Clone an existing scenario
echo '{"id": 5, "method": "tools/call", "params": {"name": "clone-scenario", "arguments": {"scenarioId": "456", "name": "Development Data Sync", "active": false}}}' | npx @modelcontextprotocol/cli chat

# Execute a scenario
echo '{"id": 6, "method": "tools/call", "params": {"name": "run-scenario", "arguments": {"scenarioId": "456", "wait": true, "timeout": 120}}}' | npx @modelcontextprotocol/cli chat
```

## 🔗 Connection Management Workflows

### Managing App Connections

```bash
# List all connections
echo '{"id": 1, "method": "tools/call", "params": {"name": "list-connections", "arguments": {"status": "valid", "limit": 20}}}' | npx @modelcontextprotocol/cli chat

# Get connection details
echo '{"id": 2, "method": "tools/call", "params": {"name": "get-connection", "arguments": {"connectionId": 123}}}' | npx @modelcontextprotocol/cli chat

# Create a new Slack connection
echo '{"id": 3, "method": "tools/call", "params": {"name": "create-connection", "arguments": {"name": "Team Slack", "service": "slack", "accountName": "team-workspace", "credentials": {"token": "xoxb-...", "workspace": "team"}}}}' | npx @modelcontextprotocol/cli chat

# Update connection credentials
echo '{"id": 4, "method": "tools/call", "params": {"name": "update-connection", "arguments": {"connectionId": 123, "name": "Updated Slack Connection", "credentials": {"token": "new-token-123"}}}}' | npx @modelcontextprotocol/cli chat
```

## 👥 User & Permission Management

### Managing Users and Teams

```bash
# Get current user information
echo '{"id": 1, "method": "tools/call", "params": {"name": "get-current-user", "arguments": {}}}' | npx @modelcontextprotocol/cli chat

# List users in organization
echo '{"id": 2, "method": "tools/call", "params": {"name": "list-users", "arguments": {"organizationId": 456, "role": "member", "limit": 50}}}' | npx @modelcontextprotocol/cli chat

# Get user details
echo '{"id": 3, "method": "tools/call", "params": {"name": "get-user", "arguments": {"userId": 789}}}' | npx @modelcontextprotocol/cli chat

# Update user role
echo '{"id": 4, "method": "tools/call", "params": {"name": "update-user-role", "arguments": {"userId": 789, "role": "admin", "teamId": 123}}}' | npx @modelcontextprotocol/cli chat

# Create a new team
echo '{"id": 5, "method": "tools/call", "params": {"name": "create-team", "arguments": {"name": "Development Team", "description": "Backend development team", "organizationId": 456}}}' | npx @modelcontextprotocol/cli chat

# Invite user to team
echo '{"id": 6, "method": "tools/call", "params": {"name": "invite-user", "arguments": {"email": "developer@company.com", "role": "member", "teamId": 123}}}' | npx @modelcontextprotocol/cli chat
```

## 📊 Analytics & Monitoring

### Accessing Analytics Data

```bash
# Get organization analytics
echo '{"id": 1, "method": "tools/call", "params": {"name": "get-organization-analytics", "arguments": {"organizationId": 456, "period": "month", "includePerformance": true}}}' | npx @modelcontextprotocol/cli chat

# List audit logs
echo '{"id": 2, "method": "tools/call", "params": {"name": "list-audit-logs", "arguments": {"organizationId": 456, "action": "scenario:create", "limit": 100}}}' | npx @modelcontextprotocol/cli chat

# Get execution history
echo '{"id": 3, "method": "tools/call", "params": {"name": "get-execution-history", "arguments": {"scenarioId": 123, "status": "success", "limit": 50}}}' | npx @modelcontextprotocol/cli chat

# Get scenario logs
echo '{"id": 4, "method": "tools/call", "params": {"name": "get-scenario-logs", "arguments": {"scenarioId": 123, "level": "error", "limit": 100}}}' | npx @modelcontextprotocol/cli chat

# Export analytics data
echo '{"id": 5, "method": "tools/call", "params": {"name": "export-analytics-data", "arguments": {"organizationId": 456, "dataType": "audit_logs", "format": "csv", "startDate": "2024-01-01", "endDate": "2024-01-31"}}}' | npx @modelcontextprotocol/cli chat
```

## 💰 Billing & Usage Information

### Accessing Billing Data

```bash
# Get billing account information
echo '{"id": 1, "method": "tools/call", "params": {"name": "get-billing-account", "arguments": {"includeUsage": true, "includeHistory": true}}}' | npx @modelcontextprotocol/cli chat

# List invoices
echo '{"id": 2, "method": "tools/call", "params": {"name": "list-invoices", "arguments": {"status": "paid", "includeLineItems": true, "limit": 10}}}' | npx @modelcontextprotocol/cli chat

# Get usage metrics
echo '{"id": 3, "method": "tools/call", "params": {"name": "get-usage-metrics", "arguments": {"period": "last_month", "breakdown": ["scenario", "team"], "includeProjections": true}}}' | npx @modelcontextprotocol/cli chat

# Add payment method
echo '{"id": 4, "method": "tools/call", "params": {"name": "add-payment-method", "arguments": {"type": "credit_card", "details": {"cardNumber": "4111111111111111", "expiryMonth": 12, "expiryYear": 2025, "cvv": "123"}, "billingAddress": {"name": "John Doe", "address1": "123 Main St", "city": "New York", "postalCode": "10001", "country": "US"}}}}' | npx @modelcontextprotocol/cli chat
```

## 🔔 Notification Management

### Managing Notifications

```bash
# Create a notification
echo '{"id": 1, "method": "tools/call", "params": {"name": "create-notification", "arguments": {"type": "system", "category": "info", "title": "System Update", "message": "System maintenance completed successfully", "recipients": {"teams": [123]}, "channels": {"email": true, "inApp": true}}}}' | npx @modelcontextprotocol/cli chat

# List notifications
echo '{"id": 2, "method": "tools/call", "params": {"name": "list-notifications", "arguments": {"type": "system", "status": "sent", "limit": 50}}}' | npx @modelcontextprotocol/cli chat

# Get email preferences
echo '{"id": 3, "method": "tools/call", "params": {"name": "get-email-preferences", "arguments": {"includeStats": true}}}' | npx @modelcontextprotocol/cli chat

# Update email preferences
echo '{"id": 4, "method": "tools/call", "params": {"name": "update-email-preferences", "arguments": {"preferences": {"scenarios": {"enabled": true, "frequency": "immediate", "categories": {"failures": true}}}}}}' | npx @modelcontextprotocol/cli chat
```

## 🏷️ Template & Variable Management

### Managing Templates and Variables

```bash
# List custom variables
echo '{"id": 1, "method": "tools/call", "params": {"name": "list-custom-variables", "arguments": {"scope": "organization", "limit": 50}}}' | npx @modelcontextprotocol/cli chat

# Create a custom variable
echo '{"id": 2, "method": "tools/call", "params": {"name": "create-custom-variable", "arguments": {"key": "API_ENDPOINT", "value": "https://api.example.com", "scope": "team", "teamId": 123, "description": "Team API endpoint"}}}' | npx @modelcontextprotocol/cli chat

# List scenario templates
echo '{"id": 3, "method": "tools/call", "params": {"name": "list-scenario-templates", "arguments": {"category": "data-sync", "limit": 20}}}' | npx @modelcontextprotocol/cli chat

# Create scenario from template
echo '{"id": 4, "method": "tools/call", "params": {"name": "create-scenario-from-template", "arguments": {"templateId": 456, "name": "Production Data Sync", "variables": {"endpoint": "https://prod-api.example.com"}}}}' | npx @modelcontextprotocol/cli chat
```

## 🤖 AI Agent Management

### Configuring AI Agents

```bash
# List AI agents
echo '{"id": 1, "method": "tools/call", "params": {"name": "list-ai-agents", "arguments": {"organizationId": 456, "isActive": true}}}' | npx @modelcontextprotocol/cli chat

# Create AI agent
echo '{"id": 2, "method": "tools/call", "params": {"name": "create-ai-agent", "arguments": {"name": "Data Analyzer", "description": "Analyzes incoming data for patterns", "provider": "openai", "model": "gpt-4", "systemPrompt": "You are a data analysis expert."}}}' | npx @modelcontextprotocol/cli chat

# Configure AI agent
echo '{"id": 3, "method": "tools/call", "params": {"name": "configure-ai-agent", "arguments": {"agentId": 789, "configuration": {"temperature": 0.7, "maxTokens": 1000}, "contextWindow": 4000}}}' | npx @modelcontextprotocol/cli chat
```

## 📁 Organization & Folder Management

### Managing Organization Structure

```bash
# List organizations
echo '{"id": 1, "method": "tools/call", "params": {"name": "list-organizations", "arguments": {"limit": 20}}}' | npx @modelcontextprotocol/cli chat

# Create organization
echo '{"id": 2, "method": "tools/call", "params": {"name": "create-organization", "arguments": {"name": "Acme Corporation", "description": "Leading provider of innovative solutions"}}}' | npx @modelcontextprotocol/cli chat

# List folders
echo '{"id": 3, "method": "tools/call", "params": {"name": "list-folders", "arguments": {"organizationId": 456, "parentId": null}}}' | npx @modelcontextprotocol/cli chat

# Create folder
echo '{"id": 4, "method": "tools/call", "params": {"name": "create-folder", "arguments": {"name": "Production Scenarios", "description": "Live production automation scenarios", "organizationId": 456}}}' | npx @modelcontextprotocol/cli chat
```

## 🔧 Advanced Workflows

### Complete Scenario Development Workflow

Here's a complete example of creating a scenario from scratch:

```bash
# 1. Check current user permissions
echo '{"id": 1, "method": "tools/call", "params": {"name": "get-current-user", "arguments": {}}}' | npx @modelcontextprotocol/cli chat

# 2. List available teams
echo '{"id": 2, "method": "tools/call", "params": {"name": "list-teams", "arguments": {"organizationId": 456}}}' | npx @modelcontextprotocol/cli chat

# 3. Create a folder for organization
echo '{"id": 3, "method": "tools/call", "params": {"name": "create-folder", "arguments": {"name": "Data Integration", "organizationId": 456}}}' | npx @modelcontextprotocol/cli chat

# 4. Set up custom variables
echo '{"id": 4, "method": "tools/call", "params": {"name": "create-custom-variable", "arguments": {"key": "SOURCE_API", "value": "https://source.api.com", "scope": "team", "teamId": 123}}}' | npx @modelcontextprotocol/cli chat

# 5. Create connections for data sources
echo '{"id": 5, "method": "tools/call", "params": {"name": "create-connection", "arguments": {"name": "Source Database", "service": "postgresql", "accountName": "production", "credentials": {"host": "db.example.com", "database": "production"}}}}' | npx @modelcontextprotocol/cli chat

# 6. Create the scenario
echo '{"id": 6, "method": "tools/call", "params": {"name": "create-scenario", "arguments": {"name": "Daily Data Sync", "teamId": 123, "folderId": "folder123", "scheduling": {"type": "cron", "cron": "0 2 * * *"}}}}' | npx @modelcontextprotocol/cli chat

# 7. Test the scenario
echo '{"id": 7, "method": "tools/call", "params": {"name": "run-scenario", "arguments": {"scenarioId": "scenario456", "wait": false}}}' | npx @modelcontextprotocol/cli chat

# 8. Monitor execution
echo '{"id": 8, "method": "tools/call", "params": {"name": "get-scenario-logs", "arguments": {"scenarioId": "scenario456", "limit": 10}}}' | npx @modelcontextprotocol/cli chat

# 9. Set up notifications for failures
echo '{"id": 9, "method": "tools/call", "params": {"name": "create-notification", "arguments": {"type": "scenario", "category": "alert", "title": "Scenario Failure Alert", "message": "Data sync scenario failed", "recipients": {"teams": [123]}, "channels": {"email": true, "slack": true}}}}' | npx @modelcontextprotocol/cli chat
```

### Bulk Operations Example

```bash
# Get all scenarios in a team
scenarios=$(echo '{"id": 1, "method": "tools/call", "params": {"name": "list-scenarios", "arguments": {"teamId": 123, "limit": 100}}}' | npx @modelcontextprotocol/cli chat)

# Clone multiple scenarios for development
echo '{"id": 2, "method": "tools/call", "params": {"name": "clone-scenario", "arguments": {"scenarioId": "prod1", "name": "Dev - Scenario 1", "teamId": 456, "active": false}}}' | npx @modelcontextprotocol/cli chat

echo '{"id": 3, "method": "tools/call", "params": {"name": "clone-scenario", "arguments": {"scenarioId": "prod2", "name": "Dev - Scenario 2", "teamId": 456, "active": false}}}' | npx @modelcontextprotocol/cli chat

# Update all development scenarios with test variables
echo '{"id": 4, "method": "tools/call", "params": {"name": "create-custom-variable", "arguments": {"key": "TEST_MODE", "value": "true", "scope": "team", "teamId": 456}}}' | npx @modelcontextprotocol/cli chat
```

## 🐛 Error Handling Examples

### Common Error Scenarios

```bash
# Handle invalid API key
echo '{"id": 1, "method": "tools/call", "params": {"name": "health-check", "arguments": {}}}' | npx @modelcontextprotocol/cli chat
# Response: {"error": "Make.com API is not accessible. Please check your configuration."}

# Handle rate limiting
echo '{"id": 2, "method": "tools/call", "params": {"name": "list-scenarios", "arguments": {"limit": 1000}}}' | npx @modelcontextprotocol/cli chat
# The server automatically handles rate limiting with exponential backoff

# Handle permission errors
echo '{"id": 3, "method": "tools/call", "params": {"name": "delete-organization", "arguments": {"organizationId": 123}}}' | npx @modelcontextprotocol/cli chat
# Response: {"error": "Insufficient permissions to delete organization"}

# Handle validation errors
echo '{"id": 4, "method": "tools/call", "params": {"name": "create-scenario", "arguments": {"name": ""}}}' | npx @modelcontextprotocol/cli chat
# Response: {"error": "Validation failed: name must be at least 1 character"}
```

## 📖 Integration Examples

### Using with Claude Desktop

Add this configuration to your Claude Desktop settings:

```json
{
  "mcpServers": {
    "make-fastmcp": {
      "command": "node",
      "args": ["/path/to/make.com-fastmcp-server/dist/index.js"],
      "env": {
        "MAKE_API_KEY": "your_api_key_here",
        "MAKE_TEAM_ID": "your_team_id",
        "MAKE_ORGANIZATION_ID": "your_org_id",
        "LOG_LEVEL": "info"
      }
    }
  }
}
```

Then in Claude Desktop, you can ask:
- "List my Make.com scenarios"
- "Create a new scenario called 'Customer Data Sync'"
- "Show me the execution logs for scenario 123"
- "Get my organization's usage analytics"

### Using with Custom Scripts

```typescript
// example-script.ts
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

// Connect to the FastMCP server
const transport = new StdioClientTransport({
  command: "tsx",
  args: ["src/index.ts"],
  env: {
    MAKE_API_KEY: process.env.MAKE_API_KEY,
    LOG_LEVEL: "info"
  }
});

// Call tools programmatically
const response = await transport.request({
  method: "tools/call",
  params: {
    name: "list-scenarios",
    arguments: { limit: 10 }
  }
});

console.log("Scenarios:", response.result);
```

## 🔍 Debugging & Troubleshooting

### Enable Debug Logging

```bash
# Set debug level for detailed logging
export LOG_LEVEL=debug
npm run dev

# Check server health
echo '{"id": 1, "method": "tools/call", "params": {"name": "health-check", "arguments": {}}}' | npx @modelcontextprotocol/cli chat

# Test configuration
echo '{"id": 2, "method": "tools/call", "params": {"name": "test-configuration", "arguments": {}}}' | npx @modelcontextprotocol/cli chat
```

### Common Debugging Commands

```bash
# Check API connectivity
curl -H "Authorization: Token YOUR_API_KEY" https://eu1.make.com/api/v2/scenarios

# Test rate limiter status
echo '{"id": 1, "method": "tools/call", "params": {"name": "server-info", "arguments": {}}}' | npx @modelcontextprotocol/cli chat

# Monitor scenario execution in real-time
echo '{"id": 1, "method": "tools/call", "params": {"name": "run-scenario", "arguments": {"scenarioId": "123", "wait": true, "timeout": 300}}}' | npx @modelcontextprotocol/cli chat
```

## 📈 Performance Optimization

### Best Practices

```bash
# Use pagination for large datasets
echo '{"id": 1, "method": "tools/call", "params": {"name": "list-scenarios", "arguments": {"limit": 50, "offset": 0}}}' | npx @modelcontextprotocol/cli chat

# Filter results to reduce data transfer
echo '{"id": 2, "method": "tools/call", "params": {"name": "list-audit-logs", "arguments": {"action": "scenario:create", "startDate": "2024-01-01", "limit": 100}}}' | npx @modelcontextprotocol/cli chat

# Use bulk operations when possible
echo '{"id": 3, "method": "tools/call", "params": {"name": "export-analytics-data", "arguments": {"organizationId": 456, "dataType": "execution_history", "format": "json", "startDate": "2024-01-01", "endDate": "2024-01-31"}}}' | npx @modelcontextprotocol/cli chat
```

## 🎯 Next Steps

After running these examples:

1. **Explore Tool Combinations**: Combine multiple tools to create complex workflows
2. **Set Up Monitoring**: Use analytics tools to monitor your Make.com operations
3. **Create Custom Scripts**: Build automation scripts using the FastMCP server
4. **Configure Notifications**: Set up alerts for important events
5. **Optimize Performance**: Use filtering and pagination for better performance

## 📚 Additional Resources

- [Make.com API Documentation](https://docs.make.com/api)
- [FastMCP Documentation](https://github.com/fastmcp/fastmcp)
- [Model Context Protocol Specification](https://spec.modelcontextprotocol.io/)
- [Claude Desktop Configuration Guide](https://docs.anthropic.com/claude/docs/mcp)

For more advanced examples and specific use cases, check the individual example files in this directory.