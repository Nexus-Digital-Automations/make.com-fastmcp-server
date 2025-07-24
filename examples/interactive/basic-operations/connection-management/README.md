# Connection Management Examples

This directory demonstrates comprehensive connection management operations for external services using the Make.com FastMCP server. Learn how to create, test, update, and manage app connections securely.

## 📁 What You'll Learn

- **Connection CRUD**: Complete connection lifecycle management
- **Credential Handling**: Secure storage and management of API keys and tokens
- **Service Integration**: Connecting to popular services (Gmail, Slack, databases)
- **Connection Testing**: Validate connections and troubleshoot issues
- **Webhook Management**: Configure and monitor webhook endpoints
- **Security Best Practices**: Safe credential handling and access control

## 🚀 Quick Start

```bash
# Run the complete demo
./run-example.sh

# Test specific operations
./run-example.sh --operation list
./run-example.sh --operation create --service "gmail"
./run-example.sh --operation test --connectionId 4001
```

## 📚 Available Examples

### 1. Connection Discovery (`list-and-filter.js`)

**What it demonstrates**:
- List all available connections with filtering
- Search connections by service type and status
- Pagination for large connection lists
- Connection metadata exploration

**Run the example**:
```bash
node list-and-filter.js
# or
./run-example.sh --demo list-filter
```

**Key features**:
- Service-based filtering (gmail, slack, database, etc.)
- Status filtering (valid, invalid, all)
- Text search across connection names
- Pagination support for large datasets

### 2. Service Integration (`create-connections.js`)

**What it demonstrates**:
- Create connections for different service types
- Handle service-specific credential requirements
- Validate connection parameters before creation
- Secure credential storage patterns

**Run the example**:
```bash
node create-connections.js
# or
./run-example.sh --demo create
```

**Supported services**:
```json
{
  "gmail": {
    "credentials": {
      "refresh_token": "your_refresh_token",
      "client_id": "your_client_id",
      "client_secret": "your_client_secret"
    }
  },
  "slack": {
    "credentials": {
      "token": "xoxb-your-bot-token",
      "workspace": "your-workspace"
    }
  },
  "mysql": {
    "credentials": {
      "host": "localhost",
      "port": 3306,
      "username": "user",
      "password": "password",
      "database": "mydb"
    }
  }
}
```

### 3. Connection Testing (`test-connections.js`)

**What it demonstrates**:
- Validate connection health and authentication
- Test service-specific endpoints
- Handle connection failures and retries
- Performance monitoring for connections

**Run the example**:
```bash
node test-connections.js
# or
./run-example.sh --demo test
```

**Testing scenarios**:
- Basic connectivity tests
- Authentication validation
- Service-specific endpoint testing
- Connection performance measurement
- Error handling and recovery

### 4. Credential Management (`update-credentials.js`)

**What it demonstrates**:
- Safely update connection credentials
- Handle credential rotation and expiration
- Validate new credentials before applying
- Maintain connection history and auditing

**Run the example**:
```bash
node update-credentials.js
# or
./run-example.sh --demo credentials
```

**Security features**:
- Encrypted credential storage
- Credential validation before update
- Audit trail for credential changes
- Safe fallback mechanisms

### 5. Webhook Operations (`webhook-management.js`)

**What it demonstrates**:
- Create and configure webhooks
- Monitor webhook delivery status
- Handle webhook authentication and security
- Debug webhook failures

**Run the example**:
```bash
node webhook-management.js
# or
./run-example.sh --demo webhooks
```

**Webhook features**:
```json
{
  "webhook": {
    "name": "Order Notifications",
    "url": "https://your-app.com/webhooks/orders",
    "method": "POST",
    "headers": {
      "Authorization": "Bearer your-token",
      "Content-Type": "application/json"
    },
    "connectionId": 4001,
    "isActive": true
  }
}
```

### 6. Bulk Operations (`bulk-connection-ops.js`)

**What it demonstrates**:
- Create multiple connections efficiently
- Bulk testing and validation
- Mass credential updates
- Connection health monitoring

**Run the example**:
```bash
node bulk-connection-ops.js
# or
./run-example.sh --demo bulk
```

## 📊 Interactive Demo Features

### Service-Specific Demos
Run targeted demos for specific services:

```bash
# Gmail integration demo
./run-example.sh --service gmail --demo integration

# Slack bot connection demo
./run-example.sh --service slack --demo integration

# Database connection demo
./run-example.sh --service mysql --demo integration
```

### Connection Health Dashboard
Monitor all connections with health status:

```bash
./run-example.sh --dashboard --refresh 30
```

### Security Audit Mode
Review connection security and compliance:

```bash
./run-example.sh --security-audit
```

## 🛠️ Customization Guide

### Adding New Service Types

1. **Define service configuration**:
```json
{
  "serviceTypes": {
    "your_service": {
      "name": "Your Service",
      "authType": "oauth2",
      "requiredCredentials": [
        "client_id",
        "client_secret", 
        "refresh_token"
      ],
      "testEndpoint": "https://api.yourservice.com/user",
      "webhookSupport": true
    }
  }
}
```

2. **Add credential validation**:
```javascript
const validateCredentials = {
  your_service: (credentials) => {
    return credentials.client_id && 
           credentials.client_secret && 
           credentials.refresh_token;
  }
};
```

3. **Configure test parameters**:
```javascript
const testConfig = {
  your_service: {
    endpoint: '/user/profile',
    method: 'GET',
    expectedStatus: 200
  }
};
```

### Custom Connection Templates

Create connection templates for common use cases:

```bash
# Generate Gmail template
./run-example.sh --generate-template --service gmail --name "Gmail Marketing"

# Generate Slack template  
./run-example.sh --generate-template --service slack --name "Team Notifications"

# Generate database template
./run-example.sh --generate-template --service mysql --name "Production DB"
```

## 🔍 Expected Outputs

### Connection List Response
```json
{
  "connections": [
    {
      "id": 4001,
      "name": "Gmail Test Connection",
      "accountName": "test@gmail.com",
      "service": "gmail",
      "isValid": true,
      "lastTested": "2024-01-15T10:00:00Z",
      "createdAt": "2024-01-01T10:00:00Z"
    }
  ],
  "pagination": {
    "total": 25,
    "limit": 20,
    "offset": 0,
    "hasMore": true
  }
}
```

### Connection Creation Response
```json
{
  "connection": {
    "id": 4004,
    "name": "New Gmail Connection",
    "accountName": "user@example.com",
    "service": "gmail",
    "isValid": true,
    "metadata": {
      "scopes": ["read", "send"],
      "auth_type": "oauth2"
    },
    "createdAt": "2024-01-15T14:30:00Z"
  },
  "message": "Connection \"New Gmail Connection\" created successfully"
}
```

### Connection Test Results
```json
{
  "connectionId": 4001,
  "isValid": true,
  "message": "Connection test successful",
  "details": {
    "responseTime": 245,
    "statusCode": 200,
    "endpoint": "https://gmail.googleapis.com/gmail/v1/users/me/profile",
    "testTimestamp": "2024-01-15T14:35:00Z"
  }
}
```

### Webhook Creation Response
```json
{
  "webhook": {
    "id": 7001,
    "name": "Order Notifications",
    "url": "https://your-app.com/webhooks/orders",
    "method": "POST",
    "connectionId": 4001,
    "isActive": true,
    "createdAt": "2024-01-15T14:40:00Z"
  },
  "message": "Webhook \"Order Notifications\" created successfully"
}
```

## 🚨 Error Handling Examples

### Common Connection Errors

**Invalid Credentials**:
```json
{
  "error": {
    "message": "Authentication failed - invalid credentials",
    "code": "AUTH_FAILED",
    "details": {
      "service": "gmail",
      "statusCode": 401,
      "suggestion": "Check your refresh token and client credentials"
    }
  }
}
```

**Service Unavailable**:
```json
{
  "error": {
    "message": "Service temporarily unavailable",
    "code": "SERVICE_UNAVAILABLE",
    "details": {
      "service": "slack",
      "statusCode": 503,
      "retryAfter": 60,
      "suggestion": "Try again in a few minutes"
    }
  }
}
```

**Connection Timeout**:
```json
{
  "error": {
    "message": "Connection timeout",
    "code": "TIMEOUT",
    "details": {
      "service": "mysql",
      "timeout": 30000,
      "suggestion": "Check network connectivity and database availability"
    }
  }
}
```

## 🧪 Testing Your Connections

### Validation Tests
Run comprehensive connection tests:

```bash
# Test all connections
./run-example.sh --test --connections all

# Test specific service connections
./run-example.sh --test --service gmail

# Test connection creation and deletion
./run-example.sh --test --operations create,delete
```

### Performance Benchmarks
Measure connection performance:

```bash
# Benchmark connection operations
./run-example.sh --benchmark

# Test connection response times
./run-example.sh --benchmark --metric response-time

# Load test with multiple concurrent connections
./run-example.sh --benchmark --concurrent 10
```

## 📈 Performance Tips

### Optimizing Connection Operations

1. **Cache valid connections** to avoid repeated authentication
2. **Batch connection tests** for efficiency
3. **Use connection pooling** for database connections
4. **Monitor connection health** proactively
5. **Implement retry logic** with exponential backoff

### Connection Pool Management
```javascript
// Example connection pooling configuration
const poolConfig = {
  max: 10,        // Maximum connections in pool
  min: 2,         // Minimum connections in pool
  idle: 30000,    // Close connections after 30s idle
  acquire: 60000, // Max time to get connection
  evict: 1000     // Check for idle connections every second
};
```

## 🔒 Security Best Practices

### Credential Management
- **Never log credentials** in plain text
- **Use environment variables** for sensitive data
- **Rotate credentials regularly**
- **Implement least-privilege access**
- **Monitor for credential exposure**

### Connection Security
- **Use HTTPS for all API connections**
- **Validate SSL certificates**
- **Implement proper authentication flows**
- **Set appropriate timeout values**
- **Log security events for auditing**

## 🔗 Related Examples

- **Scenario Management** (`../scenario-management/`) - Using connections in scenarios
- **Advanced Workflows** (`../../advanced-workflows/`) - Complex connection patterns
- **Security Examples** (`../../security-examples/`) - Advanced security configurations
- **Integration Patterns** (`../../integration-patterns/`) - Real-world service integrations

## 🤝 Next Steps

After mastering connection management:

1. **Template Operations** - Learn to work with reusable templates
2. **User Management** - Understand user and permission systems
3. **Advanced Workflows** - Build complex automation patterns
4. **Integration Patterns** - Implement real-world business scenarios

---

**Ready to connect?** Start with `list-and-filter.js` to explore your existing connections and learn the fundamentals!