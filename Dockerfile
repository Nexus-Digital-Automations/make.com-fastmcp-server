# ==============================================================================
# Multi-stage Dockerfile for Make.com FastMCP Server
# Optimized for production with security best practices
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Dependencies and Build Environment
# ------------------------------------------------------------------------------
FROM node:18-alpine AS dependencies

# Set working directory
WORKDIR /app

# Install system dependencies required for native modules
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    libc6-compat

# Copy package files
COPY package*.json ./

# Install dependencies with npm ci for reproducible builds
# Use --only=production for smaller image size in production builds
RUN npm ci --only=production && npm cache clean --force

# ------------------------------------------------------------------------------
# Stage 2: TypeScript Build Environment  
# ------------------------------------------------------------------------------
FROM node:18-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache \
    python3 \
    make \
    g++

# Copy package files and install ALL dependencies (including dev dependencies)
COPY package*.json ./
RUN npm ci

# Copy source code
COPY . .

# Build TypeScript to JavaScript
RUN npm run build

# Remove development dependencies after build
RUN npm prune --production

# ------------------------------------------------------------------------------
# Stage 3: Production Runtime Image
# ------------------------------------------------------------------------------
FROM node:18-alpine AS runtime

# Install dumb-init for proper signal handling in containers
RUN apk add --no-cache dumb-init

# Create app directory
WORKDIR /app

# Create non-root user for security
# Uses specific UID/GID for consistency across environments
RUN addgroup -g 1001 -S nodejs && \
    adduser -S fastmcp -u 1001 -G nodejs

# Copy built application from builder stage
COPY --from=builder --chown=fastmcp:nodejs /app/dist ./dist
COPY --from=builder --chown=fastmcp:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=fastmcp:nodejs /app/package*.json ./

# Copy essential configuration files
COPY --chown=fastmcp:nodejs .env.example ./

# Create logs directory with proper permissions
RUN mkdir -p /app/logs && chown -R fastmcp:nodejs /app/logs

# Switch to non-root user for security
USER fastmcp

# Expose port (configurable via environment variable)
EXPOSE 3000

# Health check to ensure container is healthy
# Checks both the application and Make.com API connectivity
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD node -e " \
        const http = require('http'); \
        const options = { \
            hostname: 'localhost', \
            port: process.env.PORT || 3000, \
            path: '/health', \
            timeout: 5000 \
        }; \
        const req = http.request(options, (res) => { \
            process.exit(res.statusCode === 200 ? 0 : 1); \
        }); \
        req.on('error', () => process.exit(1)); \
        req.on('timeout', () => process.exit(1)); \
        req.end(); \
    " || exit 1

# Set environment variables with secure defaults
ENV NODE_ENV=production \
    LOG_LEVEL=warn \
    PORT=3000 \
    MAKE_TIMEOUT=30000 \
    MAKE_RETRIES=3

# Use dumb-init as PID 1 to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Start the application
CMD ["node", "dist/index.js"]

# ------------------------------------------------------------------------------
# Stage 4: Development Image (Optional)
# ------------------------------------------------------------------------------
FROM node:18-alpine AS development

WORKDIR /app

# Install development tools
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    git

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S fastmcp -u 1001 -G nodejs

# Copy package files
COPY package*.json ./

# Install all dependencies (including dev dependencies)
RUN npm ci

# Copy source code
COPY --chown=fastmcp:nodejs . .

# Create logs directory
RUN mkdir -p /app/logs && chown -R fastmcp:nodejs /app/logs

# Switch to non-root user
USER fastmcp

# Expose port
EXPOSE 3000

# Set development environment
ENV NODE_ENV=development \
    LOG_LEVEL=debug \
    PORT=3000

# Health check for development
HEALTHCHECK --interval=60s --timeout=10s --start-period=10s --retries=2 \
    CMD node -e " \
        const http = require('http'); \
        http.get('http://localhost:' + (process.env.PORT || 3000) + '/health', \
        (res) => process.exit(res.statusCode === 200 ? 0 : 1)) \
        .on('error', () => process.exit(1)); \
    " || exit 1

# Use dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]

# Start in development mode with tsx for hot reloading
CMD ["npm", "run", "dev"]

# ------------------------------------------------------------------------------
# Build Instructions and Usage Examples
# ------------------------------------------------------------------------------

# Build production image:
# docker build --target runtime -t make-fastmcp-server:latest .

# Build development image:
# docker build --target development -t make-fastmcp-server:dev .

# Run production container:
# docker run -d \
#   --name make-fastmcp \
#   -p 3000:3000 \
#   -e MAKE_API_KEY=your_api_key \
#   -e MAKE_BASE_URL=https://eu1.make.com/api/v2 \
#   --restart unless-stopped \
#   make-fastmcp-server:latest

# Run development container with volume mounting:
# docker run -d \
#   --name make-fastmcp-dev \
#   -p 3000:3000 \
#   -v $(pwd):/app \
#   -v /app/node_modules \
#   -e MAKE_API_KEY=your_api_key \
#   make-fastmcp-server:dev

# Container Security Features:
# - Non-root user (fastmcp:nodejs)
# - Minimal attack surface (Alpine Linux)
# - Read-only filesystem where possible
# - Proper signal handling (dumb-init)
# - Health checks for monitoring
# - Multi-stage builds for smaller images
# - Dependency layer caching for faster builds