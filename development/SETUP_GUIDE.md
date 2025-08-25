# Make.com FastMCP Server - Setup & Usage Guide

**Version**: 2.0.0 - Enhanced Monitoring Edition  
**Last Updated**: 2025-08-25  
**Status**: Production Ready ✅

## 📋 Table of Contents

- [Quick Start](#quick-start)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Claude Desktop Integration](#claude-desktop-integration)
- [Development Setup](#development-setup)
- [Production Deployment](#production-deployment)
- [Usage Examples](#usage-examples)
- [Troubleshooting](#troubleshooting)
- [Advanced Configuration](#advanced-configuration)

## Quick Start

**Get up and running in 5 minutes:**

1. **Clone and Build**:

   ```bash
   git clone <repository-url>
   cd make.com-fastmcp-server
   npm install
   npm run build
   ```

2. **Set API Key**:

   ```bash
   export MAKE_API_KEY="your_make_api_key_here"
   ```

3. **Start Server**:

   ```bash
   node dist/index.js
   ```

4. **Add to Claude Desktop** (see [Claude Desktop Integration](#claude-desktop-integration))

5. **Start Automating**: Ask Claude to help with Make.com scenarios!

## Prerequisites

### System Requirements

**Minimum Requirements**:

- **Node.js**: Version 18.0 or higher
- **npm**: Version 8.0 or higher
- **Memory**: 256MB available RAM
- **Storage**: 100MB free disk space
- **Network**: Internet connection for Make.com API access

**Recommended**:

- **Node.js**: Version 20.x LTS
- **Memory**: 1GB available RAM (for monitoring features)
- **Storage**: 1GB free disk space (for logs and reports)

### Make.com Account

**Required**:

- Active Make.com account (Free tier or higher)
- API access enabled
- Valid API key

**API Key Generation**:

1. Log in to your Make.com account
2. Navigate to **Profile** → **API**
3. Click **Generate API Key**
4. Copy and securely store your API key
5. Note your region (US1, EU1, etc.)

### Claude Desktop (Optional)

**For MCP Integration**:

- Claude Desktop application
- Version 1.0 or higher
- Administrator access for configuration

## Installation

### Method 1: Direct Clone (Recommended)

```bash
# Clone the repository
git clone <repository-url>
cd make.com-fastmcp-server

# Install dependencies
npm install

# Build TypeScript to JavaScript
npm run build

# Verify installation
node dist/index.js --version
```

### Method 2: npm Package (Future)

```bash
# Install globally (when published)
npm install -g make-fastmcp-server

# Or install locally
npm install make-fastmcp-server
```

### Method 3: Docker (Future)

```bash
# Pull and run Docker image
docker run -e MAKE_API_KEY=your_key_here make-fastmcp-server
```

### Build Verification

**Verify successful build**:

```bash
# Check compiled files exist
ls -la dist/
# Should show: index.js, simple-fastmcp-server.js, *.map files

# Test server starts without errors
node dist/index.js 2>&1 | grep -i "started"
# Should show: FastMCP Server started successfully
```

## Configuration

### Environment Variables

**Required Configuration**:

```bash
# Make.com API credentials
export MAKE_API_KEY="your_api_key_here"

# Make.com API endpoint (regional)
export MAKE_BASE_URL="https://us1.make.com/api/v2"  # US region
# export MAKE_BASE_URL="https://eu1.make.com/api/v2"  # EU region
```

**Optional Performance Tuning**:

```bash
# Performance monitoring (default: true)
export PERFORMANCE_MONITORING_ENABLED=true

# Metrics collection (default: true)
export METRICS_COLLECTION_ENABLED=true

# Memory threshold in MB (default: 512)
export MEMORY_THRESHOLD_MB=512

# Request timeout in seconds (default: 30)
export MAKE_REQUEST_TIMEOUT=30
```

**Optional Logging Configuration**:

```bash
# Log level: error, warn, info, debug (default: info)
export LOG_LEVEL=info

# Enable file logging (default: true)
export LOG_FILE_ENABLED=true

# Enable pattern analysis (default: true)
export LOG_PATTERN_ANALYSIS_ENABLED=true
```

**Optional Feature Toggles**:

```bash
# Health monitoring (default: true)
export HEALTH_CHECK_ENABLED=true

# Dependency monitoring (default: true)
export DEPENDENCY_MONITORING_ENABLED=true

# Maintenance reports (default: true)
export MAINTENANCE_REPORTS_ENABLED=true
```

### Configuration File (.env)

Create `.env` file in project root:

```bash
# Make.com Configuration
MAKE_API_KEY=your_api_key_here
MAKE_BASE_URL=https://us1.make.com/api/v2

# Performance Configuration
PERFORMANCE_MONITORING_ENABLED=true
METRICS_COLLECTION_ENABLED=true
MEMORY_THRESHOLD_MB=1024

# Logging Configuration
LOG_LEVEL=info
LOG_FILE_ENABLED=true
LOG_PATTERN_ANALYSIS_ENABLED=true

# Feature Configuration
HEALTH_CHECK_ENABLED=true
DEPENDENCY_MONITORING_ENABLED=true
MAINTENANCE_REPORTS_ENABLED=true
```

**Load configuration**:

```bash
# Install dotenv support (optional)
npm install dotenv

# Load .env file before starting
node -r dotenv/config dist/index.js
```

### Regional Configuration

**API Endpoint by Region**:

| Region                | Base URL                                |
| --------------------- | --------------------------------------- |
| **US1** (Default)     | `https://us1.make.com/api/v2`           |
| **EU1**               | `https://eu1.make.com/api/v2`           |
| **AU1**               | `https://au1.make.com/api/v2`           |
| **Custom/Enterprise** | `https://your-instance.make.com/api/v2` |

**Region Detection**:
The server automatically detects your region from the API response if not specified.

## Claude Desktop Integration

### Configuration Steps

1. **Locate Claude Desktop config directory**:
   - **macOS**: `~/Library/Application Support/Claude/`
   - **Windows**: `%APPDATA%\Claude\`
   - **Linux**: `~/.config/Claude/`

2. **Edit `claude_desktop_config.json`**:

   ```json
   {
     "mcpServers": {
       "make-fastmcp": {
         "command": "node",
         "args": ["/full/path/to/make.com-fastmcp-server/dist/index.js"],
         "env": {
           "MAKE_API_KEY": "your_api_key_here",
           "MAKE_BASE_URL": "https://us1.make.com/api/v2"
         }
       }
     }
   }
   ```

3. **Restart Claude Desktop**

4. **Verify Integration**:
   - Start a new conversation in Claude Desktop
   - Ask: "What Make.com scenarios do I have?"
   - Claude should list your scenarios

### Alternative Configuration Methods

**Using environment variables**:

```json
{
  "mcpServers": {
    "make-fastmcp": {
      "command": "node",
      "args": ["/full/path/to/dist/index.js"],
      "env": {}
    }
  }
}
```

Then set environment variables in your shell profile.

**Using configuration file**:

```json
{
  "mcpServers": {
    "make-fastmcp": {
      "command": "node",
      "args": ["-r", "dotenv/config", "/full/path/to/dist/index.js"],
      "cwd": "/full/path/to/make.com-fastmcp-server"
    }
  }
}
```

With `.env` file in project directory.

### Testing Integration

**Verify MCP connection**:

1. **Check Claude Desktop logs** (if available)
2. **Test basic functionality**:
   ```
   User: "Show me my Make.com scenarios"
   Claude: [Lists your scenarios using the MCP server]
   ```
3. **Test advanced features**:
   ```
   User: "Help me create an automation to sync Gmail to Slack"
   Claude: [Uses create-automation prompt to help design the workflow]
   ```

## Development Setup

### Development Dependencies

```bash
# Install development dependencies
npm install --include=dev

# Available commands
npm run build          # Compile TypeScript
npm run dev           # Development server with auto-reload
npm run lint          # ESLint code checking
npm run format        # Prettier code formatting
npm run test          # Run test suite (if available)
```

### Development Server

**Start development server**:

```bash
# Development mode with file watching
npm run dev

# Or manually with Node.js debugging
node --inspect dist/index.js

# Debug mode with enhanced logging
LOG_LEVEL=debug node dist/index.js
```

### Code Organization

**Project Structure**:

```
make.com-fastmcp-server/
├── src/
│   ├── index.ts                    # Entry point
│   └── simple-fastmcp-server.ts   # Main server implementation
├── dist/                          # Compiled JavaScript
├── logs/                          # Log files
├── development/                   # Development documentation
│   ├── features.md
│   ├── API_DOCUMENTATION.md
│   ├── MONITORING_GUIDE.md
│   └── SETUP_GUIDE.md
├── package.json
├── tsconfig.json
├── ARCHITECTURE.md
├── CLAUDE.md
└── README.md
```

### Development Workflow

1. **Make changes** to TypeScript files in `src/`
2. **Compile** with `npm run build`
3. **Test changes** with `node dist/index.js`
4. **Lint and format** with `npm run lint` and `npm run format`
5. **Commit changes** with descriptive messages

## Production Deployment

### Deployment Options

#### Option 1: Direct Node.js

```bash
# Production environment setup
export NODE_ENV=production
export MAKE_API_KEY="your_production_api_key"
export LOG_LEVEL=warn

# Start server
node dist/index.js
```

#### Option 2: Process Manager (PM2)

```bash
# Install PM2
npm install -g pm2

# Create ecosystem file
cat > ecosystem.config.js << EOF
module.exports = {
  apps: [{
    name: 'make-fastmcp-server',
    script: 'dist/index.js',
    env: {
      NODE_ENV: 'production',
      MAKE_API_KEY: 'your_api_key_here',
      LOG_LEVEL: 'warn'
    },
    instances: 1,
    autorestart: true,
    watch: false,
    max_memory_restart: '1G',
    error_file: 'logs/error.log',
    out_file: 'logs/out.log',
    log_file: 'logs/combined.log'
  }]
}
EOF

# Start with PM2
pm2 start ecosystem.config.js
pm2 startup  # Enable startup script
pm2 save     # Save configuration
```

#### Option 3: Docker Container (Future)

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY dist/ ./dist/
COPY package*.json ./
RUN npm ci --only=production
EXPOSE 3000
CMD ["node", "dist/index.js"]
```

#### Option 4: Systemd Service

```ini
# /etc/systemd/system/make-fastmcp.service
[Unit]
Description=Make.com FastMCP Server
After=network.target

[Service]
Type=simple
User=nodejs
WorkingDirectory=/opt/make-fastmcp-server
ExecStart=/usr/bin/node dist/index.js
Environment=NODE_ENV=production
Environment=MAKE_API_KEY=your_api_key_here
Environment=LOG_LEVEL=warn
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start service
sudo systemctl enable make-fastmcp.service
sudo systemctl start make-fastmcp.service
sudo systemctl status make-fastmcp.service
```

### Production Monitoring

**Health Monitoring**:

```bash
# Check server health
curl http://localhost:3000/health  # Future feature

# Monitor logs
tail -f logs/fastmcp-server-*.log

# Check performance metrics
grep "FastMCP Server Metrics" logs/fastmcp-server-*.log
```

**Log Management**:

```bash
# Setup log rotation
sudo apt-get install logrotate

# Configure log rotation
cat > /etc/logrotate.d/make-fastmcp << EOF
/opt/make-fastmcp-server/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF
```

### Security Considerations

**API Key Security**:

- Never commit API keys to version control
- Use environment variables or secure key management
- Rotate API keys regularly
- Monitor for unauthorized access

**Network Security**:

- Run on internal network when possible
- Use HTTPS for webhook integrations
- Implement firewall rules as needed
- Monitor for unusual request patterns

## Usage Examples

### Basic Operations

**List Scenarios**:

```
User: "What Make.com scenarios do I have?"

Claude: "I'll get your current Make.com scenarios for you."
[Claude uses get-scenarios tool]

Result: Lists all your automation scenarios with their current status.
```

**Create New Scenario**:

```
User: "Help me create a scenario to email me when someone fills out my contact form"

Claude: "I'll help you create that automation. Let me use the create-automation prompt to design the best approach."
[Claude uses create-automation prompt, then create-scenario tool]

Result: Complete scenario blueprint with webhook trigger and email action.
```

**Check Connection Health**:

```
User: "Are all my app connections working properly?"

Claude: "Let me check the status of all your Make.com connections."
[Claude accesses connections-status resource]

Result: Health status of all your app integrations with any issues highlighted.
```

### Advanced Workflows

**Scenario Debugging**:

```
User: "My Shopify to QuickBooks scenario keeps failing. Can you help debug it?"

Claude: "I'll help troubleshoot your scenario. Let me first get the details and then analyze what might be wrong."
[Claude uses get-scenario tool, then debug-scenario prompt]

Result: Detailed analysis of the scenario with specific recommendations to fix the issues.
```

**Performance Optimization**:

```
User: "My data sync scenario is running slowly. How can I optimize it?"

Claude: "I'll analyze your scenario performance and suggest optimizations."
[Claude uses get-scenario and optimize-workflow prompt]

Result: Specific recommendations to improve scenario speed and efficiency.
```

**Organization Analytics**:

```
User: "Show me our team's Make.com usage and performance metrics"

Claude: "I'll get your organization's usage analytics and performance data."
[Claude accesses organization-overview resource]

Result: Complete dashboard view of operations usage, team activity, and top-performing scenarios.
```

### AI-Powered Assistance

**Automation Design**:

```
User: "I want to automatically create Trello cards from Slack messages that contain 'action item'"

Claude: "I'll design an automation solution for you."
[Uses create-automation prompt with task analysis]

Result: Complete automation blueprint with:
- Slack webhook trigger configuration
- Message filtering logic
- Trello card creation setup
- Error handling recommendations
```

**Workflow Optimization**:

```
User: "This scenario uses too many operations. How can I reduce costs?"

Claude: "Let me analyze your scenario and suggest cost-reduction strategies."
[Uses optimize-workflow prompt focusing on cost-efficiency]

Result: Specific recommendations:
- Module consolidation opportunities
- Alternative app choices
- Data filtering improvements
- Batch processing suggestions
```

## Troubleshooting

### Common Issues

#### 1. Server Won't Start

**Error**: `EROFS: read-only file system, mkdir 'logs/'`
**Solution**:

```bash
# Ensure logs directory exists and is writable
mkdir -p logs
chmod 755 logs

# Or run from a writable directory
cd ~/Documents/make-fastmcp-server
node dist/index.js
```

**Error**: `Cannot find module 'simple-fastmcp-server'`
**Solution**:

```bash
# Rebuild the project
npm run build

# Verify dist directory exists
ls -la dist/
```

#### 2. Authentication Errors

**Error**: `Authentication failed: Invalid API key`
**Solution**:

```bash
# Verify API key is set
echo $MAKE_API_KEY

# Test API key manually
curl -H "Authorization: Token $MAKE_API_KEY" \
     https://us1.make.com/api/v2/scenarios

# Check for correct region
export MAKE_BASE_URL=https://eu1.make.com/api/v2  # If in EU
```

#### 3. Claude Desktop Integration Issues

**Issue**: Claude doesn't recognize the MCP server
**Solutions**:

1. **Check config path**:

   ```bash
   # Verify config file location
   ls -la ~/Library/Application\ Support/Claude/claude_desktop_config.json
   ```

2. **Validate JSON syntax**:

   ```bash
   # Check JSON is valid
   cat ~/Library/Application\ Support/Claude/claude_desktop_config.json | jq .
   ```

3. **Verify absolute paths**:

   ```bash
   # Use full absolute paths, not relative
   "args": ["/Users/yourusername/make.com-fastmcp-server/dist/index.js"]
   ```

4. **Restart Claude Desktop** completely

#### 4. Performance Issues

**Issue**: Slow response times
**Solutions**:

```bash
# Check Make.com API status
curl -I https://us1.make.com/api/v2/scenarios

# Monitor memory usage
echo $MEMORY_THRESHOLD_MB  # Increase if needed

# Check network latency
ping us1.make.com

# Enable debug logging
LOG_LEVEL=debug node dist/index.js
```

#### 5. Memory Issues

**Issue**: High memory usage warnings
**Solutions**:

```bash
# Increase memory threshold
export MEMORY_THRESHOLD_MB=1024

# Disable memory-intensive features temporarily
export PERFORMANCE_MONITORING_ENABLED=false
export METRICS_COLLECTION_ENABLED=false

# Restart Node.js with more memory
node --max-old-space-size=2048 dist/index.js
```

### Debug Mode

**Enable comprehensive debugging**:

```bash
export LOG_LEVEL=debug
export PERFORMANCE_MONITORING_ENABLED=true
node --inspect dist/index.js
```

**Debug information includes**:

- Detailed request/response logging
- Performance metrics for all operations
- Memory usage tracking
- Error stack traces
- Correlation ID tracking

### Log Analysis

**Check server logs**:

```bash
# View recent logs
tail -f logs/fastmcp-server-$(date +%Y-%m-%d).log

# Search for errors
grep -i error logs/fastmcp-server-*.log

# Check performance metrics
grep "Metrics Report" logs/fastmcp-server-*.log
```

**Log format understanding**:

```json
{
  "timestamp": "2025-08-25T10:30:00.000Z",
  "level": "info",
  "message": "Operation completed",
  "correlationId": "req_1234567890",
  "operation": "get-scenarios",
  "duration": 156,
  "success": true
}
```

## Advanced Configuration

### Custom Monitoring Thresholds

**Performance Thresholds**:

```bash
# Custom performance monitoring
export SLOW_OPERATION_THRESHOLD=3000    # 3 seconds
export HIGH_MEMORY_THRESHOLD=100        # 100MB delta
export HIGH_CPU_THRESHOLD=90            # 90% CPU usage
export MAX_CONCURRENT_OPS=30            # Max concurrent operations
```

**Health Check Intervals**:

```bash
# Custom health check timing
export HEALTH_CHECK_INTERVAL=300000     # 5 minutes
export API_CONNECTIVITY_TIMEOUT=10000   # 10 seconds
export DEPENDENCY_CHECK_INTERVAL=3600000 # 1 hour
```

### Custom Log Patterns

**Define custom alert patterns**:

```javascript
// Add to server configuration (future feature)
const customPatterns = [
  {
    name: "Custom Business Logic Error",
    pattern: /business.*logic.*(error|failure)/i,
    category: "business",
    severity: "high",
    threshold: 1,
    timeWindow: 300,
    description: "Business logic errors detected",
  },
];
```

### Webhook Integration (Future)

**Configure webhook notifications**:

```bash
export WEBHOOK_URL="https://your-webhook-endpoint.com/alerts"
export WEBHOOK_SECRET="your_webhook_secret"
export ALERT_WEBHOOK_ENABLED=true
```

### Multi-Instance Deployment

**Load balancing configuration**:

```bash
# Instance identification
export INSTANCE_ID="make-fastmcp-01"
export CLUSTER_NAME="production"

# Distributed logging
export LOG_AGGREGATION_ENDPOINT="https://logs.yourcompany.com"
```

This comprehensive setup guide ensures you can successfully deploy and configure the Make.com FastMCP Server for any environment, from development to enterprise production deployments.
