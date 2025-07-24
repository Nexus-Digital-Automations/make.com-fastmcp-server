# Connection Management Tools

Comprehensive tools for managing app connections and webhooks in Make.com with secure credential handling and connection testing.

## Tools Overview

| Tool | Description | Type |
|------|-------------|------|
| `list-connections` | List and filter app connections | Read |
| `get-connection` | Get detailed connection information | Read |
| `create-connection` | Create new app connection | Write |
| `update-connection` | Update existing connection | Write |
| `delete-connection` | Remove app connection | Write |
| `test-connection` | Verify connection functionality | Action |
| `list-webhooks` | List webhook configurations | Read |
| `create-webhook` | Create new webhook endpoint | Write |
| `update-webhook` | Update webhook configuration | Write |
| `delete-webhook` | Remove webhook | Write |

## Connection Management

### `list-connections`

List and filter app connections in Make.com with comprehensive filtering options.

**Parameters:**
```typescript
{
  service?: string;           // Filter by service name (e.g., "slack", "gmail")
  status?: 'valid' | 'invalid' | 'all';  // Filter by connection status
  search?: string;            // Search connections by name or account
  limit?: number;             // Max connections (1-100, default: 20)
  offset?: number;            // Connections to skip (default: 0)
}
```

**Returns:**
```typescript
{
  connections: Connection[];
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
# List all Slack connections
mcp-client list-connections --service "slack" --status "valid"

# Search for Gmail connections
mcp-client list-connections --search "gmail" --limit 50
```

**Use Cases:**
- Connection inventory management
- Service-specific connection filtering
- Connection health monitoring
- Bulk connection operations

---

### `get-connection`

Get detailed information about a specific connection including configuration and status.

**Parameters:**
```typescript
{
  connectionId: number;       // Connection ID (required)
}
```

**Returns:**
```typescript
{
  connection: {
    id: number;
    name: string;
    service: string;
    accountName: string;
    status: 'valid' | 'invalid';
    metadata: object;
    createdAt: string;
    updatedAt: string;
  };
}
```

**Example:**
```bash
# Get connection details
mcp-client get-connection --connectionId 12345
```

**Use Cases:**
- Connection debugging
- Configuration review
- Status verification
- Integration setup

---

### `create-connection`

Create a new app connection in Make.com with secure credential handling.

**Parameters:**
```typescript
{
  name: string;               // Connection name (1-100 chars, required)
  service: string;            // Service identifier (required)
  accountName: string;        // Account name/identifier (1-100 chars, required)
  credentials: object;        // Service-specific credentials (required)
  metadata?: object;          // Additional connection metadata
}
```

**Returns:**
```typescript
{
  connection: Connection;
  message: string;
}
```

**Example:**
```bash
# Create Slack connection
mcp-client create-connection \
  --name "Marketing Slack" \
  --service "slack" \
  --accountName "marketing-team" \
  --credentials.token "xoxb-token-here"

# Create Gmail connection
mcp-client create-connection \
  --name "Support Gmail" \
  --service "gmail" \
  --accountName "support@company.com" \
  --credentials.clientId "client-id" \
  --credentials.clientSecret "client-secret"
```

**Security Features:**
- Credential encryption at rest
- Secure transmission protocols
- Access logging and auditing
- Permission-based access control

**Use Cases:**
- Automated connection provisioning
- Service integration setup
- Team onboarding
- Multi-environment deployment

---

### `update-connection`

Update an existing app connection including credentials and metadata.

**Parameters:**
```typescript
{
  connectionId: number;       // Connection ID (required)
  name?: string;              // New connection name (1-100 chars)
  accountName?: string;       // New account name (1-100 chars)
  credentials?: object;       // Updated credentials
  metadata?: object;          // Updated metadata
}
```

**Returns:**
```typescript
{
  connection: Connection;
  message: string;
}
```

**Example:**
```bash
# Update connection name
mcp-client update-connection --connectionId 12345 --name "Updated Marketing Slack"

# Update credentials
mcp-client update-connection \
  --connectionId 12345 \
  --credentials.token "new-token-here"
```

**Use Cases:**
- Credential rotation
- Account migration
- Configuration updates
- Connection maintenance

---

### `delete-connection`

Delete an app connection from Make.com with safety checks.

**Parameters:**
```typescript
{
  connectionId: number;       // Connection ID (required)
}
```

**Returns:**
```typescript
{
  message: string;
}
```

**Example:**
```bash
# Delete connection
mcp-client delete-connection --connectionId 12345
```

**Safety Checks:**
- Verifies connection exists
- Checks for active usage in scenarios
- Provides warnings for dependencies
- Supports confirmation prompts

**Use Cases:**
- Connection cleanup
- Service decommissioning
- Security incident response
- Account consolidation

---

### `test-connection`

Test an app connection to verify it's working correctly with optional endpoint testing.

**Parameters:**
```typescript
{
  connectionId: number;       // Connection ID (required)
  testEndpoint?: string;      // Specific endpoint to test
}
```

**Returns:**
```typescript
{
  connectionId: number;
  isValid: boolean;
  message: string;
  details?: {
    responseTime: number;
    statusCode?: number;
    error?: string;
  };
}
```

**Example:**
```bash
# Basic connection test
mcp-client test-connection --connectionId 12345

# Test specific endpoint
mcp-client test-connection \
  --connectionId 12345 \
  --testEndpoint "/users/me"
```

**Test Features:**
- Connectivity verification
- Authentication validation
- Permission checking
- Performance measurement
- Error diagnostics

**Use Cases:**
- Connection troubleshooting
- Health monitoring
- Setup verification
- Performance testing

## Webhook Management

### `list-webhooks`

List and filter webhooks in Make.com with comprehensive filtering.

**Parameters:**
```typescript
{
  connectionId?: number;      // Filter by connection ID
  scenarioId?: number;        // Filter by scenario ID
  status?: 'active' | 'inactive' | 'all';  // Filter by webhook status
  limit?: number;             // Max webhooks (1-100, default: 20)
  offset?: number;            // Webhooks to skip (default: 0)
}
```

**Returns:**
```typescript
{
  webhooks: Webhook[];
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
# List all active webhooks
mcp-client list-webhooks --status "active"

# List webhooks for specific scenario
mcp-client list-webhooks --scenarioId 12345
```

**Use Cases:**
- Webhook inventory
- Status monitoring
- Connection relationship mapping
- Bulk webhook operations

---

### `create-webhook`

Create a new webhook in Make.com with comprehensive configuration options.

**Parameters:**
```typescript
{
  name: string;               // Webhook name (1-100 chars, required)
  url: string;                // Webhook endpoint URL (required)
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';  // HTTP method (default: POST)
  headers?: object;           // HTTP headers
  connectionId?: number;      // Associated connection ID
  scenarioId?: number;        // Associated scenario ID
  isActive?: boolean;         // Webhook status (default: true)
}
```

**Returns:**
```typescript
{
  webhook: Webhook;
  message: string;
}
```

**Example:**
```bash
# Create basic webhook
mcp-client create-webhook \
  --name "Order Processing" \
  --url "https://api.company.com/webhooks/orders"

# Create webhook with headers and connection
mcp-client create-webhook \
  --name "CRM Integration" \
  --url "https://crm.company.com/webhook" \
  --method "POST" \
  --headers.Authorization "Bearer token123" \
  --connectionId 12345
```

**Configuration Features:**
- Custom HTTP methods and headers
- Connection associations
- Scenario linking
- Status management
- URL validation

**Use Cases:**
- External system integration
- Real-time data synchronization
- Event-driven processing
- API endpoint creation

---

### `update-webhook`

Update an existing webhook configuration including URL and settings.

**Parameters:**
```typescript
{
  webhookId: number;          // Webhook ID (required)
  name?: string;              // New webhook name (1-100 chars)
  url?: string;               // New webhook URL
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';  // New HTTP method
  headers?: object;           // Updated headers
  isActive?: boolean;         // Update webhook status
}
```

**Returns:**
```typescript
{
  webhook: Webhook;
  message: string;
}
```

**Example:**
```bash
# Update webhook URL
mcp-client update-webhook \
  --webhookId 12345 \
  --url "https://api.company.com/v2/webhooks/orders"

# Deactivate webhook
mcp-client update-webhook --webhookId 12345 --isActive false
```

**Use Cases:**
- Endpoint migration
- Configuration updates
- Status management
- Header modifications

---

### `delete-webhook`

Delete a webhook from Make.com with confirmation.

**Parameters:**
```typescript
{
  webhookId: number;          // Webhook ID (required)
}
```

**Returns:**
```typescript
{
  message: string;
}
```

**Example:**
```bash
# Delete webhook
mcp-client delete-webhook --webhookId 12345
```

**Use Cases:**
- Webhook cleanup
- Integration decommissioning
- URL retirement
- Configuration cleanup

## Error Handling

### Common Connection Errors

**Invalid Service**
```json
{
  "error": {
    "code": "INVALID_SERVICE",
    "message": "Service 'unknown-service' is not supported",
    "supportedServices": ["slack", "gmail", "trello", "..."]
  }
}
```

**Authentication Failure**
```json
{
  "error": {
    "code": "AUTH_FAILED",
    "message": "Connection authentication failed",
    "details": "Invalid API key or expired token"
  }
}
```

**Connection Test Failure**
```json
{
  "error": {
    "code": "CONNECTION_TEST_FAILED",
    "message": "Connection test failed with status 401",
    "statusCode": 401,
    "response": "Unauthorized"
  }
}
```

### Webhook Errors

**Invalid URL**
```json
{
  "error": {
    "code": "INVALID_URL",
    "message": "Webhook URL must be a valid HTTPS endpoint",
    "url": "http://insecure-endpoint.com"
  }
}
```

**Webhook Delivery Failure**
```json
{
  "error": {
    "code": "WEBHOOK_DELIVERY_FAILED",
    "message": "Webhook delivery failed after 3 retries",
    "lastError": "Connection timeout",
    "retryCount": 3
  }
}
```

## Security Best Practices

### Credential Management
- Use environment variables for sensitive data
- Implement credential rotation policies
- Audit credential access regularly
- Use service-specific OAuth when available

### Webhook Security
- Always use HTTPS endpoints
- Implement webhook signature verification
- Use IP whitelisting when possible
- Monitor webhook activity logs

### Access Control
- Implement least-privilege access
- Use connection-specific permissions
- Audit connection modifications
- Monitor unusual access patterns

## Performance Optimization

### Connection Pooling
- Reuse existing connections when possible
- Implement connection health monitoring
- Use connection pooling for high-volume operations
- Monitor connection pool metrics

### Webhook Optimization
- Use efficient webhook endpoints
- Implement proper error handling
- Use appropriate timeout values
- Monitor webhook performance metrics

## Monitoring and Alerting

### Connection Health
- Regular connection testing
- Automated health checks
- Failure notification systems
- Performance monitoring

### Webhook Monitoring
- Delivery success rates
- Response time tracking
- Error rate monitoring
- Volume pattern analysis

## Integration Examples

### Slack Integration
```bash
# Create Slack connection
mcp-client create-connection \
  --name "Team Notifications" \
  --service "slack" \
  --accountName "dev-team" \
  --credentials.botToken "xoxb-token"

# Test connection
mcp-client test-connection --connectionId 12345

# Create webhook for notifications
mcp-client create-webhook \
  --name "Build Notifications" \
  --url "https://hooks.slack.com/services/..." \
  --connectionId 12345
```

### Gmail Integration
```bash
# Create Gmail connection with OAuth
mcp-client create-connection \
  --name "Support Email" \
  --service "gmail" \
  --accountName "support@company.com" \
  --credentials.clientId "oauth-client-id" \
  --credentials.clientSecret "oauth-secret"

# Test email connectivity
mcp-client test-connection --connectionId 12346
```

This comprehensive documentation provides developers with all the information needed to effectively use the connection management tools in the Make.com FastMCP server.