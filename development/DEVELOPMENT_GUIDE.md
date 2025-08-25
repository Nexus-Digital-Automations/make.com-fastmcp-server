# Make.com FastMCP Server - Development & Maintenance Guide

**Version**: 2.0.0 - Enhanced Monitoring Edition  
**Last Updated**: 2025-08-25  
**Status**: Production Ready ✅

## 📋 Table of Contents

- [Development Environment Setup](#development-environment-setup)
- [Code Structure & Architecture](#code-structure--architecture)
- [Development Workflow](#development-workflow)
- [Testing Strategy](#testing-strategy)
- [Code Quality Standards](#code-quality-standards)
- [Performance Optimization](#performance-optimization)
- [Security Guidelines](#security-guidelines)
- [Maintenance Procedures](#maintenance-procedures)
- [Deployment Procedures](#deployment-procedures)
- [Troubleshooting & Debugging](#troubleshooting--debugging)

## Development Environment Setup

### Prerequisites

**Required Tools**:

- **Node.js**: Version 18+ (LTS recommended)
- **npm**: Version 8+
- **TypeScript**: Version 5+
- **Git**: Latest version
- **Code Editor**: VS Code, WebStorm, or equivalent with TypeScript support

**Development Dependencies**:

```bash
# Core development tools
npm install -D typescript @types/node
npm install -D eslint @typescript-eslint/parser @typescript-eslint/eslint-plugin
npm install -D prettier eslint-config-prettier eslint-plugin-prettier
npm install -D nodemon ts-node concurrently

# Testing framework (if implementing tests)
npm install -D jest @types/jest ts-jest
npm install -D supertest @types/supertest
```

### Project Setup

**Clone and Initialize**:

```bash
# Clone repository
git clone <repository-url>
cd make.com-fastmcp-server

# Install dependencies
npm install

# Setup development environment
cp .env.example .env  # Create environment file
vim .env              # Configure your API keys and settings

# Build project
npm run build

# Verify setup
npm run test          # Run tests (if available)
npm run lint          # Check code quality
node dist/index.js    # Test server startup
```

**IDE Configuration**:

**VS Code Settings** (`.vscode/settings.json`):

```json
{
  "typescript.preferences.importModuleSpecifier": "relative",
  "typescript.suggest.includeCompletionsForImportStatements": true,
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.fixAll.eslint": true,
    "source.organizeImports": true
  },
  "eslint.validate": ["typescript"],
  "files.exclude": {
    "node_modules": true,
    "dist": true,
    "*.log": true
  }
}
```

**VS Code Extensions**:

- TypeScript and JavaScript Language Features
- ESLint
- Prettier
- GitLens
- Thunder Client (for API testing)

## Code Structure & Architecture

### Project Structure

```
make.com-fastmcp-server/
├── src/
│   ├── index.ts                    # Application entry point
│   └── simple-fastmcp-server.ts   # Main server implementation
├── dist/                          # Compiled JavaScript output
│   ├── index.js
│   ├── simple-fastmcp-server.js
│   └── *.map                      # Source maps
├── logs/                          # Application logs
│   └── fastmcp-server-*.log
├── development/                   # Development documentation
│   ├── features.md
│   ├── API_DOCUMENTATION.md
│   ├── MONITORING_GUIDE.md
│   ├── SETUP_GUIDE.md
│   └── DEVELOPMENT_GUIDE.md
├── node_modules/                  # Dependencies
├── package.json                   # Project configuration
├── tsconfig.json                  # TypeScript configuration
├── eslint.config.js               # ESLint configuration
├── .prettierrc                    # Prettier configuration
├── .gitignore                     # Git ignore rules
├── ARCHITECTURE.md                # Technical architecture
├── CLAUDE.md                      # Project instructions
├── README.md                      # Project overview
└── TODO.json                      # Task management
```

### Core Architecture Components

**1. Entry Point (`index.ts`)**:

- Simple entry point that imports and starts the server
- Command-line argument processing (future enhancement)
- Environment validation
- Graceful startup/shutdown handling

**2. Main Server (`simple-fastmcp-server.ts`)**:

- **Lines 1-95**: Type definitions, interfaces, enums
- **Lines 96-182**: PerformanceMonitor class
- **Lines 183-233**: MetricsCollector class
- **Lines 234-401**: HealthMonitor class
- **Lines 402-648**: DependencyMonitor class
- **Lines 649-668**: SimpleMakeClient class
- **Lines 669-824**: FastMCP server tools, resources, prompts
- **Lines 825+**: Server initialization and startup

### Class Design Patterns

**Singleton Pattern** (Monitoring Classes):

```typescript
class PerformanceMonitor {
  private static metrics: PerformanceMetrics[] = [];
  private static maxHistorySize: number = 1000;

  static async trackOperation<T>(...): Promise<{result: T, metrics: PerformanceMetrics}> {
    // Implementation tracks operations globally
  }
}
```

**Factory Pattern** (Error Creation):

```typescript
class ErrorFactory {
  static createClassifiedError(
    error: Error,
    category: ErrorCategory,
    severity: ErrorSeverity,
    correlationId: string,
  ): ClassifiedError {
    // Standardized error creation
  }
}
```

**Strategy Pattern** (Health Checks):

```typescript
interface HealthCheck {
  name: string;
  check(): Promise<CheckResult>;
}

class HealthMonitor {
  private static checks: HealthCheck[] = [
    new ApiConnectivityCheck(),
    new MemoryUsageCheck(),
    new LogFileSystemCheck(),
    new ErrorRateCheck(),
  ];
}
```

## Development Workflow

### Git Workflow

**Branch Strategy**:

- **`main`**: Production-ready code
- **`develop`**: Integration branch for features
- **`feature/xxx`**: Individual feature development
- **`hotfix/xxx`**: Critical production fixes
- **`release/x.x.x`**: Release preparation

**Commit Convention**:

```bash
# Format: type(scope): description
feat(monitoring): add new health check for API connectivity
fix(client): resolve timeout handling in SimpleMakeClient
docs(api): update tool documentation with new parameters
refactor(performance): extract metrics collection logic
test(health): add unit tests for HealthMonitor class
chore(deps): upgrade TypeScript to v5.0
```

**Development Process**:

1. **Create feature branch**: `git checkout -b feature/new-tool`
2. **Implement changes**: Follow code quality standards
3. **Write tests**: Ensure adequate test coverage
4. **Lint and format**: `npm run lint && npm run format`
5. **Build and test**: `npm run build && npm test`
6. **Commit changes**: Use conventional commit format
7. **Push branch**: `git push origin feature/new-tool`
8. **Create PR**: Detailed description with testing instructions
9. **Code review**: Address feedback and ensure CI passes
10. **Merge**: Squash and merge to develop/main

### Development Scripts

**package.json scripts**:

```json
{
  "scripts": {
    "dev": "concurrently \"tsc -w\" \"nodemon dist/index.js\"",
    "build": "tsc",
    "start": "node dist/index.js",
    "lint": "eslint src/**/*.ts",
    "lint:fix": "eslint src/**/*.ts --fix",
    "format": "prettier --write src/**/*.ts",
    "format:check": "prettier --check src/**/*.ts",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "clean": "rm -rf dist/",
    "prebuild": "npm run clean",
    "postbuild": "cp -r logs dist/ 2>/dev/null || true"
  }
}
```

**Development Commands**:

```bash
# Start development server with auto-reload
npm run dev

# Run code quality checks
npm run lint
npm run format:check

# Fix code quality issues
npm run lint:fix
npm run format

# Build for production
npm run build

# Run tests
npm test
npm run test:watch      # Watch mode
npm run test:coverage   # With coverage report
```

## Testing Strategy

### Test Structure

**Planned Test Organization**:

```
tests/
├── unit/
│   ├── performance-monitor.test.ts
│   ├── health-monitor.test.ts
│   ├── metrics-collector.test.ts
│   ├── dependency-monitor.test.ts
│   └── simple-make-client.test.ts
├── integration/
│   ├── mcp-protocol.test.ts
│   ├── make-api-integration.test.ts
│   └── monitoring-integration.test.ts
├── e2e/
│   ├── full-workflow.test.ts
│   └── claude-desktop-integration.test.ts
├── fixtures/
│   ├── mock-responses.json
│   └── test-scenarios.json
└── helpers/
    ├── test-utils.ts
    └── mock-server.ts
```

### Test Implementation Examples

**Unit Test Example**:

```typescript
// tests/unit/performance-monitor.test.ts
import { PerformanceMonitor } from "../../src/simple-fastmcp-server";

describe("PerformanceMonitor", () => {
  beforeEach(() => {
    PerformanceMonitor.clearMetrics();
  });

  describe("trackOperation", () => {
    it("should track operation timing and memory usage", async () => {
      const mockOperation = jest.fn().mockResolvedValue("test-result");

      const result = await PerformanceMonitor.trackOperation(
        "test-operation",
        "corr-123",
        mockOperation,
      );

      expect(result.result).toBe("test-result");
      expect(result.metrics).toMatchObject({
        operation: "test-operation",
        correlationId: "corr-123",
        duration: expect.any(Number),
        memoryDelta: expect.any(Number),
        success: true,
      });
      expect(mockOperation).toHaveBeenCalled();
    });

    it("should handle operation failures gracefully", async () => {
      const error = new Error("Operation failed");
      const mockOperation = jest.fn().mockRejectedValue(error);

      await expect(
        PerformanceMonitor.trackOperation(
          "failing-operation",
          "corr-456",
          mockOperation,
        ),
      ).rejects.toThrow("Operation failed");

      // Verify metrics still recorded
      const report = PerformanceMonitor.getMetricsReport();
      expect(report).toContain("failing-operation");
    });
  });
});
```

**Integration Test Example**:

```typescript
// tests/integration/make-api-integration.test.ts
import { SimpleMakeClient } from "../../src/simple-fastmcp-server";

describe("SimpleMakeClient Integration", () => {
  let client: SimpleMakeClient;

  beforeEach(() => {
    client = new SimpleMakeClient(
      process.env.TEST_MAKE_API_KEY || "test-key",
      process.env.TEST_MAKE_BASE_URL || "https://us1.make.com/api/v2",
    );
  });

  describe("API connectivity", () => {
    it("should successfully authenticate with Make.com API", async () => {
      const scenarios = await client.getScenarios();
      expect(Array.isArray(scenarios)).toBe(true);
    }, 10000); // 10 second timeout for API calls

    it("should handle authentication errors properly", async () => {
      const invalidClient = new SimpleMakeClient("invalid-key", client.baseUrl);

      await expect(invalidClient.getScenarios()).rejects.toThrow(
        /authentication|unauthorized/i,
      );
    });
  });
});
```

### Test Data Management

**Mock Data Structure**:

```typescript
// tests/fixtures/mock-responses.json
{
  "scenarios": {
    "list": {
      "scenarios": [
        {
          "id": 12345,
          "name": "Test Scenario",
          "status": "active",
          "scheduling": {"type": "indefinitely"},
          "created_at": "2025-01-01T00:00:00Z",
          "updated_at": "2025-01-01T00:00:00Z"
        }
      ]
    },
    "get": {
      "id": 12345,
      "name": "Test Scenario",
      "status": "active",
      "blueprint": {
        "flow": []
      }
    }
  }
}
```

**Test Utilities**:

```typescript
// tests/helpers/test-utils.ts
export class TestUtils {
  static mockMakeApiResponse(endpoint: string, response: any) {
    // Mock HTTP responses for testing
  }

  static createTestCorrelationId(): string {
    return `test-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  static waitForCondition(
    condition: () => boolean,
    timeout: number = 5000,
  ): Promise<void> {
    // Wait for async conditions in tests
  }
}
```

## Code Quality Standards

### TypeScript Configuration

**tsconfig.json**:

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "lib": ["ES2020"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "removeComments": false,
    "noImplicitAny": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "tests"]
}
```

### ESLint Configuration

**eslint.config.js**:

```javascript
import eslint from "@eslint/js";
import tseslint from "typescript-eslint";
import prettier from "eslint-config-prettier";

export default tseslint.config(
  eslint.configs.recommended,
  tseslint.configs.recommendedTypeChecked,
  tseslint.configs.strictTypeChecked,
  prettier,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // Code quality rules
      "prefer-const": "error",
      "no-var": "error",
      "no-console": "warn",

      // TypeScript specific
      "@typescript-eslint/no-unused-vars": "error",
      "@typescript-eslint/explicit-function-return-type": "warn",
      "@typescript-eslint/no-explicit-any": "warn",
      "@typescript-eslint/prefer-nullish-coalescing": "error",
      "@typescript-eslint/prefer-optional-chain": "error",

      // Performance and maintainability
      complexity: ["warn", 10],
      "max-lines-per-function": ["warn", 100],
      "max-params": ["warn", 5],
      "max-nested-callbacks": ["warn", 3],
    },
  },
);
```

### Code Style Guidelines

**Naming Conventions**:

- **Classes**: `PascalCase` (e.g., `PerformanceMonitor`)
- **Functions/Methods**: `camelCase` (e.g., `trackOperation`)
- **Variables**: `camelCase` (e.g., `correlationId`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `MAX_HISTORY_SIZE`)
- **Types/Interfaces**: `PascalCase` (e.g., `PerformanceMetrics`)
- **Enums**: `PascalCase` with `UPPER_SNAKE_CASE` values

**Function Design Principles**:

```typescript
// ✅ Good: Single responsibility, clear naming, typed parameters
async function trackApiCall(
  operation: string,
  correlationId: string,
  apiCall: () => Promise<any>,
): Promise<{ result: any; metrics: PerformanceMetrics }> {
  const startTime = process.hrtime.bigint();
  const startMemory = process.memoryUsage().heapUsed;

  try {
    const result = await apiCall();
    return {
      result,
      metrics: this.calculateMetrics(startTime, startMemory, true),
    };
  } catch (error) {
    this.recordError(error, correlationId);
    throw error;
  }
}

// ❌ Bad: Multiple responsibilities, unclear naming, no error handling
function doStuff(op: string, id: string, fn: any): any {
  const start = Date.now();
  const result = fn();
  console.log(`${op} took ${Date.now() - start}ms`);
  return result;
}
```

**Error Handling Standards**:

```typescript
// ✅ Comprehensive error handling with classification
async function makeApiCall(endpoint: string): Promise<any> {
  const correlationId = generateCorrelationId();

  try {
    const response = await fetch(endpoint, {
      headers: { Authorization: `Token ${this.apiKey}` },
      timeout: this.timeout,
    });

    if (!response.ok) {
      throw this.createClassifiedError(
        new Error(`API call failed: ${response.status}`),
        this.determineErrorCategory(response.status),
        response.status >= 500 ? "CRITICAL" : "HIGH",
        correlationId,
      );
    }

    return await response.json();
  } catch (error) {
    this.logger.error("API call failed", {
      endpoint,
      correlationId,
      error: error.message,
      stack: error.stack,
    });

    throw error;
  }
}
```

## Performance Optimization

### Memory Management

**Memory Optimization Techniques**:

```typescript
class OptimizedMetricsCollector {
  private static readonly MAX_METRICS_HISTORY = 1000;
  private static metrics: Map<string, MetricEntry[]> = new Map();

  static recordMetric(operation: string, metric: MetricEntry): void {
    if (!this.metrics.has(operation)) {
      this.metrics.set(operation, []);
    }

    const operationMetrics = this.metrics.get(operation)!;
    operationMetrics.push(metric);

    // Prevent memory leaks by limiting history
    if (operationMetrics.length > this.MAX_METRICS_HISTORY) {
      operationMetrics.shift(); // Remove oldest entry
    }
  }

  // Periodic cleanup to prevent memory accumulation
  static performCleanup(): void {
    const cutoffTime = Date.now() - 24 * 60 * 60 * 1000; // 24 hours

    for (const [operation, metrics] of this.metrics.entries()) {
      const validMetrics = metrics.filter((m) => m.timestamp > cutoffTime);
      this.metrics.set(operation, validMetrics);
    }
  }
}
```

**CPU Optimization**:

```typescript
// Debounced logging to reduce CPU overhead
class OptimizedLogger {
  private static logQueue: LogEntry[] = [];
  private static flushTimer: NodeJS.Timeout | null = null;

  static log(entry: LogEntry): void {
    this.logQueue.push(entry);

    if (!this.flushTimer) {
      this.flushTimer = setTimeout(() => {
        this.flushLogs();
      }, 100); // Batch logs every 100ms
    }
  }

  private static flushLogs(): void {
    if (this.logQueue.length > 0) {
      // Batch write all queued logs
      const logsToWrite = [...this.logQueue];
      this.logQueue.length = 0;

      this.writeLogsBatch(logsToWrite);
    }

    this.flushTimer = null;
  }
}
```

### Async Optimization

**Promise Optimization**:

```typescript
// ✅ Efficient concurrent operations
async function performHealthChecks(): Promise<HealthStatus> {
  const checks = await Promise.allSettled([
    this.checkApiConnectivity(),
    this.checkMemoryUsage(),
    this.checkLogFileSystem(),
    this.checkErrorRates(),
  ]);

  return this.aggregateHealthResults(checks);
}

// ✅ Controlled concurrency for API calls
async function batchApiCalls<T>(
  operations: (() => Promise<T>)[],
  concurrencyLimit: number = 5,
): Promise<T[]> {
  const results: T[] = [];

  for (let i = 0; i < operations.length; i += concurrencyLimit) {
    const batch = operations.slice(i, i + concurrencyLimit);
    const batchResults = await Promise.all(batch.map((op) => op()));
    results.push(...batchResults);
  }

  return results;
}
```

### Monitoring Performance Impact

**Performance Monitoring Guidelines**:

- **Monitoring overhead**: <5% of total execution time
- **Memory footprint**: <50MB additional heap usage
- **Log file growth**: <10MB per day under normal load
- **CPU impact**: <2% additional CPU usage

## Security Guidelines

### Input Validation

**Parameter Validation**:

```typescript
import { z } from "zod";

// Define strict validation schemas
const ScenarioCreateSchema = z.object({
  name: z.string().min(1).max(255),
  blueprint: z.object({}).passthrough(), // Allow any valid JSON object
  folderId: z.number().int().positive().optional(),
  scheduling: z.object({}).optional(),
});

async function createScenario(params: unknown): Promise<any> {
  // Validate input before processing
  const validatedParams = ScenarioCreateSchema.parse(params);

  // Sanitize string inputs
  const sanitizedName = this.sanitizeString(validatedParams.name);

  return await this.makeApiCall("scenarios", {
    ...validatedParams,
    name: sanitizedName,
  });
}
```

### Secure API Key Handling

**Credential Management**:

```typescript
class SecureCredentialManager {
  private static apiKey: string | undefined;

  static setApiKey(key: string): void {
    if (!key || typeof key !== "string" || key.length < 10) {
      throw new Error("Invalid API key format");
    }
    this.apiKey = key;
  }

  static getApiKey(): string {
    if (!this.apiKey) {
      throw new Error("API key not configured");
    }
    return this.apiKey;
  }

  // Never log or expose API keys
  static maskApiKey(key: string): string {
    if (key.length <= 8) return "****";
    return key.substring(0, 4) + "****" + key.substring(key.length - 4);
  }
}

// ✅ Secure logging - API keys never exposed
logger.info("API request initiated", {
  endpoint: "/scenarios",
  apiKeyMask: SecureCredentialManager.maskApiKey(apiKey),
  correlationId,
});
```

### Error Information Disclosure

**Safe Error Responses**:

```typescript
function createSafeErrorResponse(
  error: Error,
  correlationId: string,
): ErrorResponse {
  // Never expose sensitive information in production
  const isDevelopment = process.env.NODE_ENV === "development";

  return {
    error: {
      category: this.classifyError(error),
      message: isDevelopment ? error.message : "An error occurred",
      correlationId,
      timestamp: new Date().toISOString(),
      retryable: this.isRetryableError(error),
      // Stack traces only in development
      ...(isDevelopment && { stack: error.stack }),
    },
  };
}
```

## Maintenance Procedures

### Regular Maintenance Tasks

**Daily Tasks**:

```bash
# Check system health
npm run health-check

# Review logs for errors
tail -100 logs/fastmcp-server-$(date +%Y-%m-%d).log | grep -i error

# Monitor memory usage
ps aux | grep node

# Check disk space
df -h logs/
```

**Weekly Tasks**:

```bash
# Update dependencies
npm audit
npm outdated

# Rotate old log files
find logs/ -name "*.log" -mtime +7 -delete

# Generate maintenance report
npm run maintenance-report

# Check for security vulnerabilities
npm audit --audit-level=high
```

**Monthly Tasks**:

```bash
# Full dependency update review
npm update --dry-run

# Performance analysis
npm run performance-report

# Security assessment
npm audit --audit-level=moderate

# Backup configuration
cp -r .env ecosystem.config.js backups/$(date +%Y%m%d)/
```

### Dependency Management

**Update Strategy**:

```bash
# 1. Check for updates
npm outdated

# 2. Review changelog for breaking changes
npm view <package-name> versions --json

# 3. Update non-breaking changes first
npm update

# 4. Test major version updates individually
npm install <package-name>@latest
npm test
npm run build

# 5. Update package-lock.json
npm install --package-lock-only
```

**Security Updates**:

```bash
# Check for vulnerabilities
npm audit

# Apply automatic fixes
npm audit fix

# Manual review for breaking fixes
npm audit fix --dry-run

# Force fixes (careful - may break functionality)
npm audit fix --force
```

### Log Management

**Log Rotation Configuration**:

```bash
# /etc/logrotate.d/make-fastmcp
/path/to/make.com-fastmcp-server/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 nodeuser nodeuser
    postrotate
        # Restart server if needed
        systemctl reload make-fastmcp || true
    endscript
}
```

**Log Analysis Tools**:

```bash
# Find error patterns
grep -E "ERROR|CRITICAL" logs/fastmcp-server-*.log | tail -50

# Performance analysis
grep "Operation completed" logs/fastmcp-server-*.log | \
  awk '{print $NF}' | sort -n | tail -10

# Monitor request rates
grep "correlationId" logs/fastmcp-server-*.log | \
  cut -d'"' -f4 | sort | uniq -c | sort -nr
```

## Deployment Procedures

### Production Deployment Checklist

**Pre-deployment Verification**:

- [ ] All tests pass (`npm test`)
- [ ] Code linting passes (`npm run lint`)
- [ ] Build succeeds (`npm run build`)
- [ ] Security audit clean (`npm audit`)
- [ ] Performance benchmarks meet targets
- [ ] Documentation updated
- [ ] Configuration reviewed
- [ ] Backup procedures verified

**Deployment Steps**:

```bash
# 1. Create deployment branch
git checkout -b deploy/v2.0.0
git push origin deploy/v2.0.0

# 2. Production build
NODE_ENV=production npm run build

# 3. Create deployment package
tar -czf make-fastmcp-v2.0.0.tar.gz \
    dist/ package.json package-lock.json \
    ecosystem.config.js .env.production

# 4. Deploy to production server
scp make-fastmcp-v2.0.0.tar.gz prod-server:/opt/deploys/
ssh prod-server "cd /opt/deploys && tar -xzf make-fastmcp-v2.0.0.tar.gz"

# 5. Install dependencies
ssh prod-server "cd /opt/make-fastmcp && npm ci --only=production"

# 6. Start/restart service
ssh prod-server "systemctl restart make-fastmcp"

# 7. Verify deployment
curl -f https://api.yourserver.com/health || echo "Health check failed"
```

### Rollback Procedures

**Quick Rollback**:

```bash
# 1. Identify previous version
ls -la /opt/make-fastmcp/backups/

# 2. Stop current service
systemctl stop make-fastmcp

# 3. Restore previous version
cp -r /opt/make-fastmcp/backups/20250824/* /opt/make-fastmcp/

# 4. Restart service
systemctl start make-fastmcp

# 5. Verify rollback
systemctl status make-fastmcp
curl -f https://api.yourserver.com/health
```

### Environment-Specific Configuration

**Production Configuration**:

```bash
# .env.production
NODE_ENV=production
LOG_LEVEL=warn
PERFORMANCE_MONITORING_ENABLED=true
METRICS_COLLECTION_ENABLED=true
HEALTH_CHECK_ENABLED=true
DEPENDENCY_MONITORING_ENABLED=false  # Reduce overhead
MAINTENANCE_REPORTS_ENABLED=false   # Manual scheduling
MEMORY_THRESHOLD_MB=1024
```

**Staging Configuration**:

```bash
# .env.staging
NODE_ENV=staging
LOG_LEVEL=info
PERFORMANCE_MONITORING_ENABLED=true
METRICS_COLLECTION_ENABLED=true
HEALTH_CHECK_ENABLED=true
DEPENDENCY_MONITORING_ENABLED=true
MAINTENANCE_REPORTS_ENABLED=true
```

## Troubleshooting & Debugging

### Common Issues and Solutions

**Issue 1: Server Won't Start**

```
Error: Cannot find module './simple-fastmcp-server'
```

**Diagnosis**:

```bash
# Check if build completed
ls -la dist/
# Verify package.json main field
cat package.json | grep main
```

**Solution**:

```bash
npm run build
# Or clean and rebuild
npm run clean && npm run build
```

**Issue 2: Memory Leaks**

```
Alert: Memory usage exceeding threshold continuously
```

**Diagnosis**:

```bash
# Monitor memory growth
ps -o pid,vsz,rss,comm -p $(pgrep node)
# Enable heap snapshots
node --inspect dist/index.js
```

**Solution**:

```typescript
// Add periodic cleanup
setInterval(() => {
  PerformanceMonitor.clearOldMetrics();
  MetricsCollector.performCleanup();
}, 60000); // Every minute
```

**Issue 3: API Rate Limiting**

```
Error: Rate limit exceeded (429)
```

**Diagnosis**:

```bash
# Check request patterns
grep "429" logs/fastmcp-server-*.log | wc -l
# Analyze request timing
grep "API call" logs/fastmcp-server-*.log | \
  awk '{print $2}' | sort | uniq -c
```

**Solution**:

```typescript
// Implement exponential backoff
async function makeApiCallWithBackoff(
  endpoint: string,
  retries: number = 3,
): Promise<any> {
  for (let i = 0; i < retries; i++) {
    try {
      return await this.makeApiCall(endpoint);
    } catch (error) {
      if (error.status === 429 && i < retries - 1) {
        const delay = Math.pow(2, i) * 1000; // Exponential backoff
        await new Promise((resolve) => setTimeout(resolve, delay));
        continue;
      }
      throw error;
    }
  }
}
```

### Debug Mode Configuration

**Development Debug Setup**:

```bash
# Enable all debugging features
export LOG_LEVEL=debug
export PERFORMANCE_MONITORING_ENABLED=true
export METRICS_COLLECTION_ENABLED=true

# Start with Node.js debugger
node --inspect-brk dist/index.js

# Connect with Chrome DevTools
# Open chrome://inspect in Chrome browser
```

**Production Debug Mode**:

```bash
# Temporary debug mode (limited time)
export LOG_LEVEL=info  # Don't use debug in production
export CORRELATION_ID_LOGGING=true

# Restart service
systemctl restart make-fastmcp

# Monitor for 10 minutes, then revert
sleep 600 && systemctl restart make-fastmcp
```

### Performance Debugging

**Profiling Tools**:

```bash
# CPU profiling
node --prof dist/index.js
# Process prof file with
node --prof-process isolate-*.log > profile.txt

# Memory profiling
node --inspect --max-old-space-size=4096 dist/index.js
# Take heap snapshots via Chrome DevTools
```

**Performance Analysis**:

```typescript
// Add performance markers for detailed analysis
console.time("scenario-processing");
await processScenarios();
console.timeEnd("scenario-processing");

// Custom performance tracking
const performanceObserver = new PerformanceObserver((list) => {
  for (const entry of list.getEntries()) {
    logger.debug("Performance metric", {
      name: entry.name,
      duration: entry.duration,
      startTime: entry.startTime,
    });
  }
});
performanceObserver.observe({ entryTypes: ["measure", "mark"] });
```

This comprehensive development guide ensures maintainable, secure, and performant code throughout the project lifecycle.
