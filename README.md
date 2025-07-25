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

### Quick Start Configuration

For a minimal setup, you only need a Make.com API key:

```bash
# Copy the example environment file
cp .env.example .env

# Edit with your Make.com credentials
MAKE_API_KEY=your_make_api_key_here
```

### Complete Environment Variables Reference

#### 🔑 Make.com API Configuration (Required)

```bash
# Your Make.com API key - REQUIRED
MAKE_API_KEY=your_make_api_key_here

# Make.com API base URL - defaults to EU region
MAKE_BASE_URL=https://eu1.make.com/api/v2

# Optional: Scope access to specific team/organization
MAKE_TEAM_ID=your_team_id_here
MAKE_ORGANIZATION_ID=your_organization_id_here

# API client timeouts and retries
MAKE_TIMEOUT=30000          # Request timeout in milliseconds (default: 30s)
MAKE_RETRIES=3              # Number of retry attempts (default: 3)
```

#### 🌐 Server Configuration

```bash
# Server port and environment
PORT=3000                   # Server port (default: 3000)
NODE_ENV=development        # Environment: development, production, test
LOG_LEVEL=info             # Logging level: debug, info, warn, error
```

#### ⚡ Rate Limiting Configuration

```bash
# Rate limiting to respect Make.com API limits
RATE_LIMIT_MAX_REQUESTS=100     # Max requests per window (default: 100)
RATE_LIMIT_WINDOW_MS=60000      # Time window in ms (default: 60s)
RATE_LIMIT_SKIP_SUCCESS=false   # Skip counting successful requests
RATE_LIMIT_SKIP_FAILED=false    # Skip counting failed requests
```

#### 🔐 Authentication Configuration (Optional)

```bash
# Enable authentication for the FastMCP server
AUTH_ENABLED=false              # Enable/disable authentication
AUTH_SECRET=your_secret_key     # Secret key for JWT signing (required if enabled)
```

### 🚀 Make.com API Setup Guide

#### Step 1: Generate API Key

1. **Login to Make.com**
   - Navigate to [make.com](https://make.com) and sign in to your account

2. **Access API Settings**
   - Go to **Settings** → **API** in the left sidebar
   - Click **"Generate API Key"** button

3. **Configure API Key**
   - **Name**: Give your API key a descriptive name (e.g., "FastMCP Server")
   - **Permissions**: Ensure the key has the required permissions for your use case
   - **Expiration**: Set appropriate expiration date or leave empty for no expiration

4. **Copy API Key**
   - Copy the generated API key immediately (it won't be shown again)
   - Add it to your `.env` file as `MAKE_API_KEY`

#### Step 2: Identify Your Organization/Team IDs (Optional)

If you want to scope the server to specific teams or organizations:

1. **Find Organization ID**
   - In Make.com, go to **Organization Settings**
   - The organization ID is in the URL: `make.com/organization/{organizationId}/settings`

2. **Find Team ID**
   - Go to **Team Settings** within your organization
   - The team ID is in the URL: `make.com/team/{teamId}/settings`

3. **Add to Configuration**
   ```bash
   MAKE_ORGANIZATION_ID=your_organization_id
   MAKE_TEAM_ID=your_team_id
   ```

#### Step 3: Choose Your Region

Make.com has different regional API endpoints:

```bash
# European Union (default)
MAKE_BASE_URL=https://eu1.make.com/api/v2

# United States
MAKE_BASE_URL=https://us1.make.com/api/v2

# Custom/Enterprise instances
MAKE_BASE_URL=https://your-instance.make.com/api/v2
```

### 🔧 Advanced Configuration

#### Timeout and Retry Configuration

Fine-tune API client behavior for your network conditions:

```bash
# Conservative settings for slow networks
MAKE_TIMEOUT=60000          # 60 second timeout
MAKE_RETRIES=5              # 5 retry attempts

# Aggressive settings for fast networks
MAKE_TIMEOUT=10000          # 10 second timeout
MAKE_RETRIES=2              # 2 retry attempts
```

#### Production Rate Limiting

For production deployments, consider more conservative rate limiting:

```bash
# Production-safe rate limiting
RATE_LIMIT_MAX_REQUESTS=50      # Lower request rate
RATE_LIMIT_WINDOW_MS=60000      # 1-minute window
RATE_LIMIT_SKIP_SUCCESS=true    # Only count failed requests
```

#### Security Hardening

For production deployments:

```bash
# Enable authentication
AUTH_ENABLED=true
AUTH_SECRET=your_strong_random_secret_key_here

# Use production logging
LOG_LEVEL=warn              # Reduce log verbosity
NODE_ENV=production         # Enable production optimizations
```

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

## 🚀 Deployment Guide

### Local Development Deployment

For local development with Claude Desktop integration:

#### Claude Desktop Configuration

Add this configuration to your Claude Desktop config file:

**Configuration File Locations:**
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

**Development Configuration:**
```json
{
  "mcpServers": {
    "make-fastmcp": {
      "command": "npx",
      "args": ["tsx", "/path/to/make.com-fastmcp-server/src/index.ts"],
      "env": {
        "MAKE_API_KEY": "your_api_key_here",
        "MAKE_TEAM_ID": "your_team_id",
        "MAKE_ORGANIZATION_ID": "your_organization_id",
        "MAKE_BASE_URL": "https://eu1.make.com/api/v2",
        "LOG_LEVEL": "info",
        "NODE_ENV": "development"
      }
    }
  }
}
```

**Production Configuration:**
```json
{
  "mcpServers": {
    "make-fastmcp": {
      "command": "node",
      "args": ["/path/to/make.com-fastmcp-server/dist/index.js"],
      "env": {
        "MAKE_API_KEY": "your_api_key_here",
        "MAKE_TEAM_ID": "your_team_id",
        "MAKE_ORGANIZATION_ID": "your_organization_id",
        "MAKE_BASE_URL": "https://eu1.make.com/api/v2",
        "LOG_LEVEL": "warn",
        "NODE_ENV": "production",
        "AUTH_ENABLED": "true",
        "AUTH_SECRET": "your_production_secret"
      }
    }
  }
}
```

### Production Deployment Options

#### Option 1: Direct Server Deployment

**1. Prepare the Server**
```bash
# Clone and build the project
git clone <repository-url>
cd make.com-fastmcp-server
npm install
npm run build

# Set up environment
cp .env.example .env
# Edit .env with your production configuration

# Start with PM2 for process management
npm install -g pm2
pm2 start dist/index.js --name "make-fastmcp"
pm2 save
pm2 startup
```

**2. Nginx Reverse Proxy (Optional)**
```nginx
# /etc/nginx/sites-available/make-fastmcp
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

#### Option 2: Docker Deployment

The project includes a comprehensive Docker setup with multi-stage builds, production optimization, and container orchestration support.

**Prerequisites**
- Docker Engine 20.10+ and Docker Compose 2.0+
- At least 1GB free disk space for image builds
- 512MB RAM for production container

**🐳 Quick Start with Docker**

```bash
# 1. Clone and prepare the project
git clone <repository-url>
cd make.com-fastmcp-server

# 2. Set up environment variables
cp .env.example .env
# Edit .env with your Make.com API credentials

# 3. Build and start production containers
docker-compose up -d

# 4. Verify deployment
docker-compose logs -f make-fastmcp-server
curl -H "Content-Type: application/json" \
     -d '{"method": "tools/call", "params": {"name": "health-check"}}' \
     http://localhost:3000
```

**📁 Docker Configuration Files**

The project includes optimized Docker configuration:

- **`Dockerfile`**: Multi-stage build with 4 stages (dependencies, builder, runtime, development)
- **`docker-compose.yml`**: Production-optimized orchestration with Redis, Nginx proxy
- **`docker-compose.dev.yml`**: Development override with hot reloading and debugging tools
- **`.dockerignore`**: Optimized build context for faster builds

**🚀 Production Deployment**

**1. Production Configuration**
```bash
# Create production environment file
cat > .env.production << EOF
# Make.com API Configuration
MAKE_API_KEY=your_production_api_key_here
MAKE_BASE_URL=https://eu1.make.com/api/v2
MAKE_TEAM_ID=your_team_id
MAKE_ORGANIZATION_ID=your_organization_id

# Production Server Settings
NODE_ENV=production
LOG_LEVEL=warn
PORT=3000

# Security Configuration
AUTH_ENABLED=true
AUTH_SECRET=$(openssl rand -base64 32)

# Conservative Rate Limiting
RATE_LIMIT_MAX_REQUESTS=50
RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_SKIP_SUCCESS=true

# Redis Configuration
REDIS_PASSWORD=$(openssl rand -base64 16)
EOF
```

**2. Full Production Stack**
```bash
# Start complete production stack with caching and proxy
docker-compose --env-file .env.production up -d

# Scale application instances for high availability
docker-compose --env-file .env.production up -d --scale make-fastmcp-server=3

# Monitor deployment health
docker-compose ps
docker-compose logs --tail=50 -f
```

**3. Production Stack Components**

The full production stack includes:

- **FastMCP Server** (Node.js 18 Alpine, multi-stage build)
- **Redis Cache** (7-alpine, password-protected, persistent storage)
- **Nginx Proxy** (Alpine, SSL-ready, load balancing)
- **Health Monitoring** (Built-in health checks for all services)
- **Security Hardening** (Non-root users, minimal attack surface)

**🔧 Development Environment**

**1. Development Setup**
```bash
# Start development environment with hot reloading
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# Start with development tools (Redis Commander, pgAdmin, MailHog)
docker-compose -f docker-compose.yml -f docker-compose.dev.yml --profile tools up -d

# Full development stack with database
docker-compose -f docker-compose.yml -f docker-compose.dev.yml --profile development up -d
```

**2. Development Features**
- **Hot Reloading**: Source code changes trigger automatic restarts
- **Debug Port**: Node.js inspector on port 9229 for IDE debugging
- **Development Tools**:
  - Redis Commander (http://localhost:8081) - Redis database management
  - pgAdmin (http://localhost:8080) - PostgreSQL administration (future feature)
  - MailHog (http://localhost:8025) - Email testing and debugging
- **Relaxed Security**: Authentication disabled, higher rate limits
- **Enhanced Logging**: Debug-level logging with detailed traces

**3. Development Workflow**
```bash
# Live development with mounted volumes
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# View application logs
docker-compose -f docker-compose.yml -f docker-compose.dev.yml logs -f make-fastmcp-server

# Execute commands in development container
docker-compose -f docker-compose.yml -f docker-compose.dev.yml exec make-fastmcp-server npm test
docker-compose -f docker-compose.yml -f docker-compose.dev.yml exec make-fastmcp-server npm run lint

# Interactive shell access
docker-compose -f docker-compose.yml -f docker-compose.dev.yml exec make-fastmcp-server sh

# Debug with Node.js inspector
# 1. Container exposes debug port 9229
# 2. Connect your IDE to localhost:9229
# 3. Set breakpoints in TypeScript source files
```

**📦 Container Images and Build Optimization**

**Multi-Stage Build Architecture**

```dockerfile
# Stage 1: Dependencies (production-only for runtime)
FROM node:18-alpine AS dependencies
# Installs production dependencies with npm ci

# Stage 2: Builder (includes dev dependencies for TypeScript compilation)
FROM node:18-alpine AS builder  
# Compiles TypeScript, then removes dev dependencies

# Stage 3: Runtime (minimal production image)
FROM node:18-alpine AS runtime
# Final 180MB production image with non-root user

# Stage 4: Development (includes dev tools and hot reloading)
FROM node:18-alpine AS development
# Full development environment with debugging capabilities
```

**Build Commands**
```bash
# Build production image (runtime stage)
docker build --target runtime -t make-fastmcp-server:latest .

# Build development image
docker build --target development -t make-fastmcp-server:dev .

# Build with build arguments
docker build --target runtime \
  --build-arg NODE_ENV=production \
  -t make-fastmcp-server:v1.0.0 .

# View image details and size
docker images | grep make-fastmcp-server
docker inspect make-fastmcp-server:latest
```

**🔐 Container Security Features**

**Security Hardening**
- **Non-root User**: Containers run as `fastmcp:nodejs` (UID 1001)
- **Minimal Attack Surface**: Alpine Linux base (5MB) with essential packages only
- **Read-only Filesystem**: Application files mounted read-only where possible
- **Security Options**: `no-new-privileges` flag prevents privilege escalation
- **Resource Limits**: Memory and CPU limits prevent resource exhaustion
- **Health Checks**: Comprehensive health monitoring for early failure detection

**Network Security**
```yaml
# Isolated network with custom subnet
networks:
  make-fastmcp-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16

# Service communication over private network
# External access only through defined ports
```

**📊 Monitoring and Health Checks**

**Application Health Check**
```bash
# Comprehensive health check tests:
# 1. HTTP server responsiveness
# 2. Make.com API connectivity  
# 3. Authentication system status
# 4. Rate limiter health
# 5. Memory and resource usage

# Manual health check
curl http://localhost:3000/health

# Container health status
docker-compose ps
docker inspect --format='{{.State.Health.Status}}' make-fastmcp-server
```

**Log Management**
```bash
# View logs with timestamps
docker-compose logs -t make-fastmcp-server

# Follow logs in real-time
docker-compose logs -f --tail=100 make-fastmcp-server

# Export logs for analysis
docker-compose logs --no-color make-fastmcp-server > fastmcp-logs.txt

# Log rotation configuration in docker-compose.yml
logging:
  driver: "json-file"
  options:
    max-size: "10m"    # Maximum log file size
    max-file: "3"      # Number of log files to retain
```

**🔄 Container Management Operations**

**Deployment Operations**
```bash
# Rolling update with zero downtime
docker-compose pull make-fastmcp-server
docker-compose up -d --no-deps make-fastmcp-server

# Backup and restore volumes
docker run --rm -v make-fastmcp-server_redis-data:/data \
  -v $(pwd)/backup:/backup alpine \
  tar czf /backup/redis-backup-$(date +%Y%m%d).tar.gz -C /data .

# Scale application horizontally
docker-compose up -d --scale make-fastmcp-server=3
```

**Troubleshooting Commands**
```bash
# Container resource usage
docker stats make-fastmcp-server

# Inspect container configuration
docker inspect make-fastmcp-server

# Execute commands inside container
docker-compose exec make-fastmcp-server node -e "console.log(process.env)"

# View container filesystem
docker-compose exec make-fastmcp-server ls -la /app

# Debug network connectivity
docker-compose exec make-fastmcp-server wget -qO- http://redis:6379 || echo "Redis not accessible"
```

**🌐 Advanced Deployment Scenarios**

**Load Balancing with Multiple Instances**
```yaml
# docker-compose.prod.yml
services:
  make-fastmcp-server:
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
```

**SSL/TLS with Nginx Proxy**
```bash
# 1. Generate SSL certificates (example with Let's Encrypt)
mkdir -p nginx/ssl
certbot certonly --standalone -d yourdomain.com

# 2. Configure nginx/nginx.conf for SSL termination
# 3. Start with SSL-enabled nginx
docker-compose -f docker-compose.yml -f docker-compose.ssl.yml up -d
```

**Container Registry Deployment**
```bash
# Tag and push to container registry
docker tag make-fastmcp-server:latest your-registry.com/make-fastmcp-server:v1.0.0
docker push your-registry.com/make-fastmcp-server:v1.0.0

# Deploy from registry
export IMAGE_TAG=v1.0.0
docker-compose up -d
```

**💡 Docker Best Practices**

**Performance Optimization**
- **Layer Caching**: Dockerfile optimized for maximum cache hit ratio
- **Multi-stage Builds**: Separate build and runtime environments
- **Minimal Base Images**: Alpine Linux for smallest possible attack surface
- **Dependency Optimization**: Production builds exclude development dependencies

**Reliability Features**
- **Health Checks**: All services include comprehensive health monitoring
- **Restart Policies**: Automatic restart on failure with backoff
- **Resource Limits**: Prevent any single container from consuming all resources
- **Graceful Shutdown**: Proper signal handling with dumb-init

**Development Experience**
- **Hot Reloading**: Source code changes reflected immediately
- **Debug Support**: Node.js inspector integration for IDE debugging
- **Development Tools**: Redis Commander, pgAdmin, MailHog for testing
- **Volume Mounting**: Live editing without container rebuilding

#### Option 3: Cloud Platform Deployment

**Heroku Deployment**
```bash
# Install Heroku CLI and login
heroku login

# Create Heroku app
heroku create your-make-fastmcp-app

# Set environment variables
heroku config:set MAKE_API_KEY=your_api_key_here
heroku config:set MAKE_BASE_URL=https://eu1.make.com/api/v2
heroku config:set NODE_ENV=production
heroku config:set LOG_LEVEL=warn
heroku config:set AUTH_ENABLED=true
heroku config:set AUTH_SECRET=your_production_secret

# Deploy
git push heroku main
```

**Railway Deployment**
```bash
# Install Railway CLI
npm install -g @railway/cli

# Login and initialize
railway login
railway init

# Set environment variables
railway variables set MAKE_API_KEY=your_api_key_here
railway variables set NODE_ENV=production

# Deploy
railway up
```

**DigitalOcean App Platform**
```yaml
# .do/app.yaml
name: make-fastmcp-server
services:
- name: web
  source_dir: /
  github:
    repo: your-username/make.com-fastmcp-server
    branch: main
  run_command: npm start
  environment_slug: node-js
  instance_count: 1
  instance_size_slug: basic-xxs
  envs:
  - key: MAKE_API_KEY
    scope: RUN_AND_BUILD_TIME
    value: your_api_key_here
  - key: NODE_ENV
    scope: RUN_AND_BUILD_TIME
    value: production
  - key: LOG_LEVEL
    scope: RUN_AND_BUILD_TIME
    value: warn
  http_port: 3000
```

### Production Environment Checklist

Before deploying to production, ensure you have:

- [ ] **Secure API Key**: Use a production Make.com API key with minimal required permissions
- [ ] **Environment Variables**: All production values set, no development defaults
- [ ] **Authentication**: Enable AUTH_ENABLED=true with a strong AUTH_SECRET
- [ ] **Logging**: Set LOG_LEVEL to 'warn' or 'error' to reduce noise
- [ ] **Rate Limiting**: Conservative rate limits to prevent API abuse
- [ ] **Health Checks**: Implement and test health check endpoints
- [ ] **Process Management**: Use PM2, Docker, or platform-managed processes
- [ ] **Monitoring**: Set up application and infrastructure monitoring
- [ ] **Backups**: Plan for configuration and data backup if needed
- [ ] **SSL/TLS**: Use HTTPS in production environments
- [ ] **Firewall**: Restrict access to necessary ports only

### Environment-Specific Configurations

#### Development Environment
```bash
NODE_ENV=development
LOG_LEVEL=debug
AUTH_ENABLED=false
RATE_LIMIT_MAX_REQUESTS=200    # Higher limits for testing
```

#### Staging Environment
```bash
NODE_ENV=staging
LOG_LEVEL=info
AUTH_ENABLED=true
RATE_LIMIT_MAX_REQUESTS=100
# Use staging Make.com credentials if available
```

#### Production Environment
```bash
NODE_ENV=production
LOG_LEVEL=warn
AUTH_ENABLED=true
RATE_LIMIT_MAX_REQUESTS=50     # Conservative production limits
MAKE_TIMEOUT=30000             # Reasonable timeout
MAKE_RETRIES=3                 # Moderate retry attempts
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

## 🔒 Security & Authentication

### Security Overview

The Make.com FastMCP Server implements multiple layers of security to protect your Make.com API credentials and prevent unauthorized access.

### Authentication Methods

#### 1. Server Authentication (Optional)

Enable authentication to secure access to your FastMCP server:

```bash
# Enable authentication in .env file
AUTH_ENABLED=true
AUTH_SECRET=your_strong_secret_key_here
```

**Generate a Secure Secret Key:**
```bash
# Using OpenSSL (recommended)
openssl rand -base64 32

# Using Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"

# Using Python
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

#### 2. API Key Authentication

When authentication is enabled, clients must provide an API key:

```bash
# Include in HTTP headers
x-api-key: your_server_api_key
```

**Example with curl:**
```bash
curl -H "x-api-key: your_server_api_key" \
     -H "Content-Type: application/json" \
     -d '{"method": "tools/call", "params": {"name": "health-check"}}' \
     http://localhost:3000
```

### Make.com API Security

#### API Key Management

**Best Practices:**
- Use dedicated API keys for different environments (development, staging, production)
- Rotate API keys regularly (every 90 days recommended)
- Use minimal required permissions for API keys
- Never commit API keys to version control
- Use environment variables or secure secret management

**API Key Permissions:**
Ensure your Make.com API key has only the minimum required permissions:
- **Scenarios**: Read, create, update (if needed)
- **Connections**: Read, create, update (if needed) 
- **Analytics**: Read (if using analytics features)
- **Teams/Organizations**: Read (for scoped access)

#### Team and Organization Scoping

Limit access by specifying team/organization IDs:

```bash
# Scope to specific organization
MAKE_ORGANIZATION_ID=your_organization_id

# Further scope to specific team
MAKE_TEAM_ID=your_team_id
```

### Network Security

#### Rate Limiting

Protect against API abuse with intelligent rate limiting:

```bash
# Conservative production settings
RATE_LIMIT_MAX_REQUESTS=50      # Requests per window
RATE_LIMIT_WINDOW_MS=60000      # 1-minute window
RATE_LIMIT_SKIP_SUCCESS=true    # Only count failed requests
```

**Rate Limiting Features:**
- Automatic exponential backoff for Make.com API calls
- Request queuing to prevent simultaneous overload
- Circuit breaker pattern for API resilience
- Detailed rate limit status monitoring

#### HTTPS and Transport Security

**For Production Deployments:**
- Always use HTTPS in production environments
- Configure proper SSL/TLS certificates
- Use secure headers (HSTS, CSP, etc.)
- Implement proper CORS policies if needed

**Nginx SSL Configuration Example:**
```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    ssl_certificate /path/to/your/certificate.pem;
    ssl_certificate_key /path/to/your/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### Input Validation and Sanitization

#### Request Validation

All inputs are validated using Zod schemas:

```typescript
// Example validation schema
const createScenarioSchema = z.object({
  name: z.string().min(1).max(255),
  teamId: z.number().int().positive(),
  blueprint: z.object({}).optional(),
  scheduling: z.object({
    type: z.enum(['immediate', 'indefinitely', 'on-demand']),
    interval: z.number().int().positive().optional()
  }).optional()
});
```

#### Error Message Sanitization

Error messages are sanitized to prevent information leakage:
- Internal error details are logged but not exposed to clients
- API keys and sensitive data are redacted from logs
- Stack traces are only shown in development mode

### Logging and Monitoring

#### Security Event Logging

The server logs security-relevant events:
- Authentication attempts (success/failure)
- Rate limiting violations
- API key validation failures
- Unusual request patterns

**Log Format Example:**
```json
{
  "timestamp": "2024-01-15T10:30:00.000Z",
  "level": "warn",
  "event": "auth_failure",
  "ip": "192.168.1.100",
  "userAgent": "Claude Desktop/1.0",
  "reason": "invalid_api_key"
}
```

#### Audit Trail

For compliance and security monitoring:
- All API calls are logged with request/response metadata
- User actions are tracked with timestamps and source IPs
- Critical operations (scenario creation/deletion) are specially logged

### Environment Security

#### Development vs Production

**Development Environment:**
```bash
NODE_ENV=development
AUTH_ENABLED=false          # Optional authentication
LOG_LEVEL=debug             # Detailed logging
RATE_LIMIT_MAX_REQUESTS=200 # Higher limits for testing
```

**Production Environment:**
```bash
NODE_ENV=production
AUTH_ENABLED=true           # Required authentication
LOG_LEVEL=warn              # Minimal logging
RATE_LIMIT_MAX_REQUESTS=50  # Conservative limits
```

#### Container Security

When using Docker:

```dockerfile
# Use non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S make-fastmcp -u 1001
USER make-fastmcp

# Use read-only root filesystem where possible
# Mount writable volumes only where needed
```

### Security Checklist

Before deploying to production:

#### Server Security
- [ ] Authentication enabled (`AUTH_ENABLED=true`)
- [ ] Strong auth secret generated and configured
- [ ] Production logging level set (`LOG_LEVEL=warn`)
- [ ] Rate limiting configured appropriately
- [ ] HTTPS enabled with valid certificates
- [ ] Security headers configured
- [ ] Firewall rules restrict access to necessary ports
- [ ] Regular security updates applied

#### API Security
- [ ] Make.com API key uses minimal required permissions
- [ ] API key rotation schedule established
- [ ] Team/organization scoping configured if needed
- [ ] API timeout and retry settings appropriate
- [ ] No API keys committed to version control
- [ ] Environment variables properly secured

#### Monitoring & Compliance
- [ ] Security event logging enabled
- [ ] Audit trail configured for compliance needs
- [ ] Monitoring/alerting set up for security events
- [ ] Log retention policies established
- [ ] Incident response procedures documented

### Common Security Issues and Solutions

#### Issue: Exposed API Keys
**Problem:** API keys visible in logs or error messages
**Solution:** 
- Use proper log sanitization
- Redact sensitive data in error responses
- Implement structured logging with field filtering

#### Issue: Rate Limit Bypass
**Problem:** Clients bypassing rate limiting
**Solution:**
- Implement rate limiting at multiple layers (application + proxy)
- Use distributed rate limiting for multiple server instances
- Monitor for unusual request patterns

#### Issue: Unauthorized Access
**Problem:** Access to server without proper authentication
**Solution:**
- Enable authentication in production
- Use strong, randomly generated secrets
- Implement proper session management
- Regular security audits

### Advanced Security Features

#### IP Allowlisting (Future Enhancement)
```bash
# Restrict access to specific IPs
ALLOWED_IPS=192.168.1.0/24,10.0.0.0/8
```

#### Request Signing (Future Enhancement)
```bash
# Require request signing for additional security
REQUEST_SIGNING_ENABLED=true
REQUEST_SIGNING_ALGORITHM=HMAC-SHA256
```

For questions about security configuration or to report security issues, please follow responsible disclosure practices.

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