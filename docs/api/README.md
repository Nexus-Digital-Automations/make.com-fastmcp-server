# Make.com FastMCP Server - API Reference

A comprehensive FastMCP server providing full Make.com API access with advanced features including scenario management, analytics, billing, notifications, and more.

## Overview

This FastMCP server extends the capabilities of the official Make.com MCP server by providing complete platform management features. All tools are implemented following FastMCP best practices with comprehensive error handling, input validation, and structured logging.

## API Categories

- [**Scenario Management**](./scenarios.md) - CRUD operations for Make.com scenarios
- [**Connection Management**](./connections.md) - App connections and webhook management  
- [**User & Permissions**](./permissions.md) - User roles, teams, and organization management
- [**Analytics & Audit**](./analytics.md) - Analytics data, audit logs, and performance metrics
- [**Billing & Payments**](./billing.md) - Billing information, invoices, and payment methods
- [**Notifications**](./notifications.md) - Multi-channel notifications and email preferences

## Tool Naming Convention

All tools follow a consistent naming pattern:
- `list-*` - Retrieve multiple resources with filtering
- `get-*` - Retrieve a specific resource by ID
- `create-*` - Create a new resource
- `update-*` - Modify an existing resource
- `delete-*` - Remove a resource

## Common Parameters

### Pagination
Most list operations support pagination:
```typescript
{
  limit: number;     // Max items to return (default: 20, max: 100)
  offset: number;    // Items to skip (default: 0)
}
```

### Filtering
Common filter parameters:
```typescript
{
  search?: string;        // Text search
  startDate?: string;     // ISO date string
  endDate?: string;       // ISO date string
  organizationId?: number;
  teamId?: number;
}
```

## Response Format

All tools return JSON responses with consistent structure:

### Success Response
```json
{
  "data": {}, // Main response data
  "metadata": {
    "total": 100,
    "limit": 20,
    "offset": 0
  },
  "timestamp": "2025-01-24T12:00:00Z"
}
```

### Error Handling
All tools implement comprehensive error handling:
- **Validation Errors**: Input parameter validation with specific field information
- **Authentication Errors**: API key and permission issues with helpful messages
- **Rate Limiting**: Automatic handling with retry suggestions
- **Network Errors**: Timeout and connection error handling
- **Business Logic Errors**: Domain-specific error messages

Common error format:
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid parameter: limit must be between 1-100",
    "field": "limit",
    "value": 150
  }
}
```

## Authentication

All tools use the Make.com API key configured in the server environment:
```bash
MAKE_API_KEY=your_api_key_here
MAKE_TEAM_ID=your_team_id     # Optional
MAKE_ORGANIZATION_ID=your_org_id  # Optional
```

## Rate Limiting

The server implements intelligent rate limiting:
- **Default Limits**: 10 requests/second, 600 requests/minute
- **Automatic Retries**: Exponential backoff with jitter
- **Queue Management**: Request queuing to prevent API abuse
- **Health Monitoring**: Real-time rate limiter status

## Progress Reporting

Many tools support progress reporting for long-running operations:
```typescript
// Progress callback in tool execution
reportProgress({ progress: 50, total: 100 });
```

## Logging

All tools provide structured logging with:
- Request/response details
- Performance metrics
- Error context
- User session information

Log levels: `debug`, `info`, `warn`, `error`

## TypeScript Support

Full TypeScript definitions are provided for:
- Input parameters (Zod schemas)
- Response types
- Error types
- Configuration options

## Best Practices

### Input Validation
All tools use Zod schemas for input validation:
```typescript
const Schema = z.object({
  name: z.string().min(1).max(100).describe('Resource name'),
  email: z.string().email().describe('Email address'),
}).strict();
```

### Error Messages
Clear, actionable error messages:
- What went wrong
- Why it happened  
- How to fix it
- Related documentation links

### Resource Management
- Automatic connection pooling
- Request deduplication
- Memory management
- Graceful shutdown handling

## Testing

All tools include comprehensive tests:
- Unit tests with mocked dependencies
- Integration tests with real API calls
- Error scenario testing
- Performance benchmarks

## Security

Security features implemented:
- Input sanitization
- SQL injection prevention
- XSS protection
- Rate limiting
- Authentication validation
- Audit logging

## Performance

Optimization features:
- Connection pooling
- Response caching
- Request batching
- Lazy loading
- Memory optimization

## Monitoring

Built-in monitoring:
- Request metrics
- Error rates
- Performance timings
- Resource usage
- Health checks

## Next Steps

1. Choose a tool category from the links above
2. Review the specific tool documentation
3. Check the usage examples
4. Test with your Make.com account
5. Integrate into your workflows

For support, see the [troubleshooting guide](../troubleshooting.md) or [configuration documentation](../configuration.md).