# Docker Setup Guide for Make.com FastMCP Server

## 🐳 Comprehensive Docker Containerization

This project includes a complete Docker setup with multi-stage builds, production optimization, and container orchestration support for the Make.com FastMCP server.

## 📁 Docker Configuration Files

### Core Files
- **`Dockerfile`** - Multi-stage build with 4 optimized stages
- **`docker-compose.yml`** - Production-ready orchestration
- **`docker-compose.dev.yml`** - Development environment with hot reloading
- **`docker-compose.override.yml`** - Customization templates
- **`.dockerignore`** - Build context optimization

### Supporting Files
- **`nginx/nginx.conf`** - Production-ready reverse proxy configuration
- **`scripts/health-check.sh`** - Comprehensive health monitoring script

## 🚀 Quick Start

### Production Deployment
```bash
# 1. Clone and prepare
git clone <repository-url>
cd make.com-fastmcp-server

# 2. Configure environment
cp .env.example .env
# Edit .env with your Make.com API credentials

# 3. Deploy production stack
docker-compose up -d

# 4. Verify deployment
docker-compose logs -f make-fastmcp-server
curl http://localhost:3000/health
```

### Development Environment
```bash
# Start development with hot reloading
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# With development tools (Redis Commander, pgAdmin, MailHog)
docker-compose -f docker-compose.yml -f docker-compose.dev.yml --profile tools up -d
```

## 🏗️ Multi-Stage Build Architecture

### Stage 1: Dependencies
- **Base**: `node:18-alpine`
- **Purpose**: Install production dependencies only
- **Optimization**: Uses `npm ci --only=production` for reproducible builds

### Stage 2: Builder
- **Base**: `node:18-alpine`
- **Purpose**: TypeScript compilation and build process
- **Features**: Includes dev dependencies, compiles TypeScript, then prunes dev deps

### Stage 3: Runtime (Production)
- **Base**: `node:18-alpine`
- **Purpose**: Minimal production image
- **Size**: ~180MB optimized image
- **Security**: Non-root user (`fastmcp:nodejs` UID 1001)
- **Features**: Health checks, signal handling with dumb-init

### Stage 4: Development
- **Base**: `node:18-alpine`
- **Purpose**: Development environment with debugging tools
- **Features**: Hot reloading, debug port (9229), development tools

## 🔐 Security Features

### Container Security
- **Non-root User**: All containers run as `fastmcp:nodejs` (UID 1001)
- **Minimal Attack Surface**: Alpine Linux base (5MB) with essential packages only
- **Security Options**: `no-new-privileges` flag prevents privilege escalation
- **Resource Limits**: Memory and CPU limits prevent resource exhaustion
- **Read-only Filesystem**: Application files mounted read-only where possible

### Network Security
- **Isolated Networks**: Custom bridge network with subnet `172.20.0.0/16`
- **Port Exposure**: Only necessary ports exposed to host
- **Reverse Proxy**: Nginx with SSL termination and security headers
- **Rate Limiting**: Multiple rate limiting zones for different endpoints

### Application Security
- **Health Checks**: Comprehensive health monitoring for early failure detection
- **Signal Handling**: Proper signal handling with dumb-init for graceful shutdown
- **Environment Isolation**: Separate environments for development/production
- **Secret Management**: Environment-based configuration with validation

## 📊 Production Stack Components

### Core Services
1. **FastMCP Server**
   - Node.js 18 Alpine container
   - Multi-stage optimized build
   - Health checks and monitoring
   - Resource limits and security hardening

2. **Redis Cache**
   - Redis 7 Alpine container
   - Password-protected access
   - Persistent storage with volume mounting
   - Memory optimization with LRU eviction

3. **Nginx Reverse Proxy**
   - Alpine-based nginx container
   - SSL/TLS termination ready
   - Load balancing support
   - Security headers and rate limiting

### Development Tools (Optional)
- **Redis Commander** - Redis database management UI
- **pgAdmin** - PostgreSQL administration (future feature)
- **MailHog** - Email testing and debugging

## 🔧 Configuration Options

### Environment Variables
```bash
# Core Configuration
MAKE_API_KEY=your_api_key_here
MAKE_BASE_URL=https://eu1.make.com/api/v2
NODE_ENV=production
LOG_LEVEL=warn

# Security
AUTH_ENABLED=true
AUTH_SECRET=your_secure_secret_here

# Rate Limiting
RATE_LIMIT_MAX_REQUESTS=50
RATE_LIMIT_WINDOW_MS=60000

# Container Configuration
HOST_PORT=3000
CPU_LIMIT=1.0
MEMORY_LIMIT=512M
```

### Resource Limits
```yaml
# Production limits
deploy:
  resources:
    limits:
      cpus: '1.0'
      memory: 512M
    reservations:
      cpus: '0.5'
      memory: 256M
```

## 📈 Health Monitoring

### Built-in Health Checks
- **Application Health**: HTTP endpoint responsiveness
- **Make.com API**: Connectivity and response time validation
- **Rate Limiter**: Status and remaining request monitoring
- **System Resources**: Memory usage and performance metrics

### Health Check Script
```bash
# Basic health check
./scripts/health-check.sh

# Verbose monitoring
./scripts/health-check.sh -v -t 30

# Continuous monitoring
./scripts/health-check.sh -m -i 60
```

### Health Check Features
- **Retry Logic**: Configurable retry attempts with exponential backoff
- **Detailed Analysis**: Comprehensive health data parsing and validation
- **Container Awareness**: Special checks for containerized environments
- **Monitoring Mode**: Continuous health monitoring with configurable intervals
- **Logging**: Structured logging with timestamps and severity levels

## 🚀 Deployment Scenarios

### 1. Basic Production
```bash
# Single instance deployment
docker-compose up -d make-fastmcp-server redis
```

### 2. Full Production Stack
```bash
# With reverse proxy and caching
docker-compose up -d
```

### 3. Scaled Deployment
```bash
# Multiple application instances
docker-compose up -d --scale make-fastmcp-server=3
```

### 4. Development Environment
```bash
# Hot reloading and debugging
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

### 5. Custom Override
```bash
# With custom configurations
docker-compose -f docker-compose.yml -f docker-compose.override.yml up -d
```

## 🔄 Container Management

### Build Operations
```bash
# Build production image
docker build --target runtime -t make-fastmcp-server:latest .

# Build development image
docker build --target development -t make-fastmcp-server:dev .

# Build with custom arguments
docker build --target runtime --build-arg NODE_ENV=production -t make-fastmcp-server:v1.0.0 .
```

### Deployment Operations
```bash
# Rolling update
docker-compose pull && docker-compose up -d --no-deps make-fastmcp-server

# View logs
docker-compose logs -f make-fastmcp-server

# Execute commands in container
docker-compose exec make-fastmcp-server npm test

# Backup volumes
docker run --rm -v fastmcp_redis-data:/data -v $(pwd)/backup:/backup alpine tar czf /backup/redis-backup.tar.gz -C /data .
```

### Monitoring Operations
```bash
# Container status
docker-compose ps

# Resource usage
docker stats make-fastmcp-server

# Health status
docker inspect --format='{{.State.Health.Status}}' make-fastmcp-server

# Network connectivity
docker-compose exec make-fastmcp-server wget -qO- http://redis:6379
```

## 🛠️ Troubleshooting

### Common Issues

#### Container Won't Start
```bash
# Check logs
docker-compose logs make-fastmcp-server

# Check configuration
docker-compose config

# Validate environment
docker-compose exec make-fastmcp-server env | grep MAKE_
```

#### Health Check Failures
```bash
# Manual health check
curl http://localhost:3000/health

# Detailed health analysis
./scripts/health-check.sh -v

# Container health status
docker inspect make-fastmcp-server | jq '.[0].State.Health'
```

#### Performance Issues
```bash
# Resource usage
docker stats --no-stream

# Application logs
docker-compose logs --tail=100 make-fastmcp-server

# Network connectivity
docker-compose exec make-fastmcp-server ping redis
```

### Debug Mode
```bash
# Enable debug logging
export LOG_LEVEL=debug
docker-compose up -d

# Interactive debugging
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d
# Connect debugger to localhost:9229
```

## 📋 Production Checklist

### Pre-deployment
- [ ] Environment variables configured
- [ ] SSL certificates prepared (if using HTTPS)
- [ ] Resource limits appropriate for server capacity
- [ ] Network security rules configured
- [ ] Monitoring and alerting set up

### Security Hardening
- [ ] Authentication enabled (`AUTH_ENABLED=true`)
- [ ] Strong secrets generated and configured
- [ ] Rate limiting configured appropriately
- [ ] Container running as non-root user
- [ ] Unnecessary ports not exposed
- [ ] Log retention policies established

### Performance Optimization
- [ ] Resource limits tuned for workload
- [ ] Redis cache configured and tested
- [ ] Health check intervals optimized
- [ ] Log levels appropriate for environment
- [ ] Image sizes optimized

### Monitoring Setup
- [ ] Health checks enabled and tested
- [ ] Log aggregation configured
- [ ] Performance metrics collection enabled
- [ ] Alerting rules configured
- [ ] Backup procedures established

## 🔗 Integration Examples

### With CI/CD
```yaml
# GitHub Actions example
- name: Build and Deploy
  run: |
    docker build --target runtime -t $IMAGE_TAG .
    docker push $IMAGE_TAG
    docker-compose pull
    docker-compose up -d --no-deps make-fastmcp-server
```

### With Container Registry
```bash
# Tag and push
docker tag make-fastmcp-server:latest registry.example.com/make-fastmcp-server:v1.0.0
docker push registry.example.com/make-fastmcp-server:v1.0.0

# Deploy from registry
export IMAGE_TAG=v1.0.0
docker-compose up -d
```

### With Orchestrators
```yaml
# Kubernetes deployment example
apiVersion: apps/v1
kind: Deployment
metadata:
  name: make-fastmcp-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: make-fastmcp-server
  template:
    metadata:
      labels:
        app: make-fastmcp-server
    spec:
      containers:
      - name: make-fastmcp-server
        image: make-fastmcp-server:latest
        ports:
        - containerPort: 3000
        env:
        - name: MAKE_API_KEY
          valueFrom:
            secretKeyRef:
              name: make-secrets
              key: api-key
```

## 🎯 Best Practices

### Development
- Use development compose file for local development
- Mount source code as volumes for hot reloading
- Use debug port for IDE integration
- Enable verbose logging for troubleshooting

### Production
- Use specific image tags, not 'latest'
- Set appropriate resource limits
- Enable health checks and monitoring
- Use secrets management for sensitive data
- Implement proper backup strategies

### Security
- Run containers as non-root users
- Use minimal base images (Alpine)
- Regularly update base images and dependencies
- Scan images for vulnerabilities
- Implement network segmentation
- Use strong, randomly generated secrets

This comprehensive Docker setup provides a production-ready, secure, and scalable containerization solution for the Make.com FastMCP server with full development support and operational best practices.