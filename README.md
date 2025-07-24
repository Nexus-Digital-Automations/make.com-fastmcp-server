# Make.com FastMCP Server

A comprehensive FastMCP server that provides full Make.com API access beyond the capabilities of the official MCP server. This server enables complete platform management, including scenario CRUD operations, user management, analytics access, and advanced development features.

## Features

### 🚀 Platform Management
- **Scenario Management**: Create, modify, delete, and configure scenarios
- **Connection Management**: Manage app connections and webhooks
- **User & Permissions**: Role-based access control and team administration

### 📊 Analytics & Monitoring
- **Execution Analytics**: Access detailed execution logs and performance metrics
- **Audit Logs**: Comprehensive audit trail for all operations
- **Real-time Monitoring**: Server health checks and API status monitoring

### 🛠️ Resource Management
- **Template Management**: Create and manage scenario templates
- **Folder Organization**: Organize scenarios and resources
- **Data Store Operations**: Manage Make.com data stores

### ⚙️ Advanced Features
- **Custom Variables**: Manage global, team, and scenario variables
- **AI Agent Configuration**: Configure AI agents and LLM providers
- **Custom App Development**: SDK management and custom function creation
- **Billing Access**: Access billing information and usage metrics

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd make.com-fastmcp-server

# Install dependencies
npm install

# Copy environment configuration
cp .env.example .env

# Edit .env file with your Make.com API credentials
# Required: MAKE_API_KEY
# Optional: MAKE_TEAM_ID, MAKE_ORGANIZATION_ID
```

## Configuration

### Environment Variables

```bash
# Make.com API Configuration (Required)
MAKE_API_KEY=your_make_api_key_here
MAKE_BASE_URL=https://eu1.make.com/api/v2
MAKE_TEAM_ID=your_team_id_here
MAKE_ORGANIZATION_ID=your_organization_id_here

# Server Configuration
PORT=3000
NODE_ENV=development
LOG_LEVEL=info

# Rate Limiting
RATE_LIMIT_MAX_REQUESTS=100
RATE_LIMIT_WINDOW_MS=60000

# Authentication (Optional)
AUTH_ENABLED=false
AUTH_SECRET=your_auth_secret_here
```

### Make.com API Setup

1. Log in to your Make.com account
2. Go to Settings → API → Generate API Key
3. Copy the API key to your `.env` file
4. Optionally, configure team/organization IDs for scoped access

## Usage

### Development Mode

```bash
# Run with TypeScript directly
npm run dev

# Run with MCP CLI for testing
npx fastmcp dev src/index.ts

# Run with MCP Inspector (Web UI)
npx fastmcp inspect src/index.ts
```

### Production Mode

```bash
# Build the project
npm run build

# Start the server
npm start
```

### Available Scripts

```bash
npm run build        # Compile TypeScript to JavaScript
npm run dev          # Run in development mode with tsx
npm run start        # Run compiled JavaScript
npm run test         # Run test suite
npm run test:watch   # Run tests in watch mode
npm run test:coverage # Run tests with coverage report
npm run lint         # Run ESLint
npm run lint:fix     # Fix ESLint issues automatically
npm run typecheck    # Run TypeScript type checking
npm run inspect      # Run with MCP Inspector
npm run clean        # Clean build directory
```

## Usage with Claude Desktop

Add the following configuration to your Claude Desktop config:

```json
{
  "mcpServers": {
    "make-fastmcp": {
      "command": "npx",
      "args": ["tsx", "/path/to/make.com-fastmcp-server/src/index.ts"],
      "env": {
        "MAKE_API_KEY": "your_api_key_here",
        "MAKE_TEAM_ID": "your_team_id",
        "LOG_LEVEL": "info"
      }
    }
  }
}
```

## Server-Sent Events (SSE) Mode

For remote access, run the server in SSE mode:

```bash
npm run dev -- --sse
```

Then connect with:

```typescript
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";

const transport = new SSEClientTransport(new URL("http://localhost:3000/sse"));
```

## Available Tools

### Basic Tools
- `health-check`: Check server and Make.com API connectivity
- `server-info`: Get detailed server configuration and capabilities
- `test-configuration`: Test Make.com API configuration and permissions

### Platform Management Tools *(Coming Soon)*
- `create-scenario`: Create new Make.com scenarios
- `update-scenario`: Modify existing scenarios  
- `delete-scenario`: Remove scenarios
- `list-scenarios`: Get scenarios with filtering and pagination
- `manage-connections`: Create and manage app connections
- `configure-webhooks`: Set up webhook endpoints
- `manage-users`: User and permission management

### Analytics Tools *(Coming Soon)*
- `get-execution-logs`: Access detailed execution logs
- `get-analytics`: Retrieve performance metrics and analytics  
- `export-audit-logs`: Export audit trail data
- `monitor-performance`: Real-time performance monitoring

### Resource Management Tools *(Coming Soon)*
- `manage-templates`: Create and manage scenario templates
- `organize-folders`: Folder and organization management
- `manage-data-stores`: Data store operations
- `manage-variables`: Custom variable management

## Error Handling

The server provides comprehensive error handling with detailed error responses:

- **Validation Errors**: Input validation with specific field information
- **Authentication Errors**: API key and permission issues
- **Rate Limiting**: Automatic rate limiting with retry logic
- **External Service Errors**: Make.com API error handling with retries
- **Timeout Handling**: Configurable timeouts with graceful degradation

## Rate Limiting

The server implements intelligent rate limiting to respect Make.com API limits:

- **Default Limits**: 10 requests/second, 600 requests/minute
- **Automatic Retries**: Exponential backoff with jitter
- **Queue Management**: Request queuing to prevent API abuse
- **Health Monitoring**: Real-time rate limiter status

## Logging

Structured logging with configurable levels:

```bash
LOG_LEVEL=debug  # debug, info, warn, error
```

Log entries include:
- Timestamp and log level
- Component and operation context
- Session and user information
- Request/response details for debugging

## Security

### Authentication
- Optional API key authentication via `x-api-key` header
- Session management with secure token handling
- Request validation and sanitization

### API Security  
- Rate limiting to prevent abuse
- Input validation using Zod schemas
- Secure credential storage
- Error message sanitization

## Architecture

```
src/
├── index.ts          # Entry point
├── server.ts         # Main FastMCP server implementation
├── lib/              # Core libraries
│   ├── config.ts     # Configuration management
│   ├── logger.ts     # Structured logging
│   └── make-api-client.ts # Make.com API client with rate limiting
├── tools/            # FastMCP tool implementations (coming soon)
├── types/            # TypeScript type definitions
├── utils/            # Utility functions
│   ├── errors.ts     # Custom error classes
│   └── validation.ts # Input validation schemas
└── tests/            # Test suite (coming soon)
```

## Development

### Adding New Tools

1. Create a new file in `src/tools/`
2. Implement the tool using FastMCP patterns
3. Add proper TypeScript types and Zod validation
4. Include comprehensive error handling and logging
5. Add tests in the `tests/` directory

### Code Quality

- **TypeScript**: Strict type checking enabled
- **ESLint**: Code linting with TypeScript rules
- **Prettier**: Code formatting (can be added)
- **Jest**: Testing framework with coverage reporting

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your changes with tests
4. Run the test suite and linting
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Support

For issues and questions:
- Check the troubleshooting section below
- Review Make.com API documentation
- Open an issue on GitHub

## Troubleshooting

### Common Issues

**Invalid API Key**
```
Error: Make.com API is not accessible. Please check your configuration.
```
- Verify your MAKE_API_KEY in the .env file
- Ensure the API key has necessary permissions
- Check if your Make.com account is active

**Rate Limiting**
```
Error: Rate limit exceeded
```
- The server automatically handles rate limiting
- Consider reducing concurrent operations
- Monitor rate limiter status with health-check tool

**Connection Issues**
```
Error: Network error - no response received
```
- Check your internet connection
- Verify MAKE_BASE_URL is correct
- Check if Make.com services are operational

**Permission Denied**
```
Error: Insufficient permissions
```
- Verify your API key has required permissions
- Check team/organization access rights
- Ensure you're targeting the correct team/org IDs

### Debug Mode

Enable debug logging for detailed troubleshooting:

```bash
LOG_LEVEL=debug npm run dev
```

This will show:
- Detailed API request/response logs
- Rate limiter status updates
- Internal operation traces
- Error stack traces