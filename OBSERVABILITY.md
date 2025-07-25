# Make.com FastMCP Server - Observability Stack

This document describes the comprehensive observability infrastructure implemented for the Make.com FastMCP Server, providing production-ready monitoring, metrics, logging, tracing, and alerting capabilities.

## 🎯 Overview

The observability stack consists of five core components working together to provide complete visibility into system performance, health, and behavior:

1. **Prometheus Metrics Collection** - Performance and operational metrics
2. **Structured Logging with Correlation IDs** - Enhanced logging with request correlation
3. **Health Monitoring Endpoints** - Comprehensive system health checks
4. **Performance Monitoring & Alerting** - Real-time performance tracking with alerts
5. **Distributed Tracing** - Request flow tracking across operations

## 📊 Components

### 1. Prometheus Metrics (`src/lib/metrics.ts`)

**Features:**
- **Counter Metrics**: Request counts, tool executions, errors, authentication attempts
- **Histogram Metrics**: Response times, tool execution durations, API call latencies
- **Gauge Metrics**: Active connections, memory usage, CPU usage, rate limiter state
- **System Metrics**: Automatic collection of Node.js runtime metrics

**Key Metrics:**
```
fastmcp_requests_total - Total requests by method/status/operation
fastmcp_tool_executions_total - Tool executions by tool/status/user
fastmcp_errors_total - Errors by type/operation/tool
fastmcp_request_duration_seconds - Request duration histograms
fastmcp_memory_usage_bytes - Memory usage by type
fastmcp_active_connections - Current active client connections
```

**Usage:**
```typescript
import metrics from './lib/metrics.js';

// Record tool execution
metrics.recordToolExecution('health-check', 'success', 0.125, 'user123');

// Record API call
metrics.recordMakeApiCall('/scenarios', 'GET', 'success', 0.250);

// Create timer for operations
const timer = metrics.createTimer();
// ... operation
const duration = timer();
```

### 2. Structured Logging (`src/lib/logger.ts`)

**Features:**
- **Correlation ID Tracking**: Automatic correlation ID generation and propagation
- **Structured Format**: JSON-compatible structured logging with context
- **Child Loggers**: Contextual logging with inherited metadata
- **Trace Integration**: Automatic trace/span ID inclusion in logs
- **Performance Logging**: Built-in duration tracking utilities

**Log Structure:**
```
[timestamp] LEVEL [corr:correlation_id] [trace:trace_id] [span:span_id] [component] [operation]: message | Data: {...} | Meta: {...}
```

**Usage:**
```typescript
import logger from './lib/logger.js';

// Basic logging with correlation
const correlationId = logger.logWithCorrelation('info', 'Operation started', { userId: '123' });

// Child logger with context
const contextLogger = logger.child({
  component: 'AuthService',
  operation: 'login',
  correlationId
});

contextLogger.info('User authentication attempted', { username: 'john' });

// Performance logging
const startTime = Date.now();
// ... operation
logger.logDuration('info', 'database_query', startTime, { query: 'SELECT * FROM users' });
```

### 3. Health Monitoring (`src/lib/health-monitor.ts`)

**Features:**
- **Multi-level Health Checks**: Basic and detailed health assessments
- **Component Status**: Individual component health validation
- **Metrics Integration**: Health metrics exposed via Prometheus
- **System Information**: Runtime and configuration details

**Health Check Endpoints:**
- `health` - Basic health status
- `health-detailed` - Comprehensive health with component details
- `metrics` - Prometheus metrics export
- `system-info` - System and runtime information

**Health Status Levels:**
- `healthy` - All systems operational
- `degraded` - Warnings present but functional
- `unhealthy` - Critical issues detected

**Usage:**
```typescript
import HealthMonitor from './lib/health-monitor.js';

const healthMonitor = new HealthMonitor(apiClient);
healthMonitor.addHealthTools(server);

// Programmatic health check
const health = await healthMonitor.performHealthCheck();
console.log(`System status: ${health.status}`);
```

### 4. Performance Monitoring (`src/lib/performance-monitor.ts`)

**Features:**
- **Real-time Metrics**: Continuous performance data collection
- **Configurable Thresholds**: Warning and critical alert levels
- **Alert Conditions**: Automated alerting based on performance metrics
- **Historical Data**: Performance trend analysis
- **Alert Management**: Alert lifecycle with cooldown periods

**Default Thresholds:**
```typescript
{
  responseTime: { warning: 1000ms, critical: 5000ms },
  memoryUsage: { warning: 80%, critical: 95% },
  errorRate: { warning: 5%, critical: 15% },
  cpuUsage: { warning: 70%, critical: 90% }
}
```

**Alert Types:**
- **Response Time Alerts**: High latency detection
- **Memory Usage Alerts**: Memory pressure monitoring
- **Error Rate Alerts**: Error spike detection
- **CPU Usage Alerts**: CPU overload detection

**Usage:**
```typescript
import PerformanceMonitor from './lib/performance-monitor.js';

const perfMonitor = new PerformanceMonitor({
  responseTime: { warning: 500, critical: 2000 }
});

perfMonitor.startMonitoring();

// Get performance statistics
const stats = perfMonitor.getPerformanceStats();
const alerts = perfMonitor.getActiveAlerts();
```

### 5. Distributed Tracing (`src/lib/tracing.ts`)

**Features:**
- **Trace Management**: Complete request lifecycle tracking
- **Span Hierarchy**: Parent-child span relationships
- **Context Propagation**: Trace context across service boundaries
- **Trace Analytics**: Performance and error analysis
- **Integration**: Seamless integration with logging and metrics

**Tracing Concepts:**
- **Trace**: Complete request journey
- **Span**: Individual operation within a trace
- **Context**: Trace metadata for propagation
- **Tags**: Span metadata for filtering and analysis

**Usage:**
```typescript
import tracer from './lib/tracing.js';

// Start a new trace
const rootSpan = tracer.startTrace('user_login', 'AuthService');

// Create child spans
const dbSpan = tracer.startSpan(rootSpan, 'database_query', 'DatabaseService');
tracer.setSpanTags(dbSpan, { table: 'users', query_type: 'SELECT' });
tracer.logToSpan(dbSpan, 'info', 'Query executed successfully');
tracer.finishSpan(dbSpan, 'success');

// Trace wrapper for operations
const result = await tracer.trace(
  'api_call',
  'MakeApiClient',
  async (span) => {
    // Operation with automatic span management
    return await apiCall();
  },
  rootSpan
);

tracer.finishSpan(rootSpan, 'success');
```

## 🔧 Integration & Usage

### Unified Observability Manager (`src/lib/observability.ts`)

The `ObservabilityManager` provides a single interface for all observability features:

```typescript
import ObservabilityManager from './lib/observability.js';

const observability = new ObservabilityManager(apiClient, {
  enableMetrics: true,
  enableTracing: true,
  enablePerformanceMonitoring: true,
  enableHealthMonitoring: true,
  performanceThresholds: {
    responseTime: { warning: 1000, critical: 3000 }
  }
});

// Initialize all systems
await observability.initialize(server);

// Instrument operations
const result = await observability.instrument(
  'process_webhook',
  'WebhookProcessor',
  async () => {
    // Your operation here
    return await processWebhook(data);
  }
);

// Monitor API calls
const apiResult = await observability.monitorApiCall(
  '/scenarios',
  'GET',
  () => apiClient.get('/scenarios')
);

// Get comprehensive status
const status = await observability.getObservabilityStatus();
```

### Monitoring Middleware (`src/middleware/monitoring.ts`)

Automatic instrumentation for FastMCP server operations:

```typescript
import monitoring from '../middleware/monitoring.js';

// Initialize server monitoring
monitoring.initializeServerMonitoring(server);

// Wrap tool executions
const instrumentedTool = monitoring.wrapToolExecution(
  'scenario-list',
  'list_scenarios',
  async () => {
    return await listScenarios();
  },
  { userId: 'user123' }
);
```

## 📈 Monitoring & Alerting

### Prometheus Integration

All metrics are exposed in Prometheus format via the `/metrics` endpoint:

```bash
# Scrape metrics
curl http://localhost:3000/metrics

# Example metrics output
fastmcp_requests_total{method="GET",status="success",operation="health_check"} 42
fastmcp_tool_execution_duration_seconds_bucket{tool="health-check",status="success",le="0.1"} 38
fastmcp_memory_usage_bytes{type="heapUsed"} 52428800
```

### Performance Alerts

Automatic alerting based on configurable thresholds:

```typescript
// Alert conditions are automatically created for:
- High response times (>1s warning, >5s critical)
- High memory usage (>80% warning, >95% critical)
- High error rates (>5% warning, >15% critical)
- High CPU usage (>70% warning, >90% critical)

// Custom alert conditions
perfMonitor.addAlertCondition({
  id: 'custom_threshold',
  name: 'Custom Response Time',
  metric: 'response_time',
  threshold: 2000,
  operator: 'gt',
  severity: 'warning',
  enabled: true,
  cooldownMs: 300000
});
```

### Health Monitoring

Comprehensive health checks across all system components:

```json
{
  "status": "healthy",
  "timestamp": "2024-01-20T10:30:00.000Z",
  "version": "1.0.0",
  "uptime": 3600,
  "checks": [
    {
      "name": "server_uptime",
      "status": "pass",
      "responseTime": 0,
      "message": "Server is running"
    },
    {
      "name": "make_api_connectivity",
      "status": "pass", 
      "responseTime": 150,
      "message": "Make.com API is accessible"
    },
    {
      "name": "metrics_system",
      "status": "pass",
      "responseTime": 5,
      "message": "Metrics system: 25 metrics available"
    }
  ],
  "resources": {
    "memory": { "heapUsed": 52428800, "heapTotal": 67108864 },
    "cpu": 0.15,
    "connections": 3
  }
}
```

## 🚀 Deployment & Configuration

### Environment Configuration

Configure observability features via environment variables:

```bash
# Logging
LOG_LEVEL=info

# Performance thresholds
PERF_RESPONSE_TIME_WARNING=1000
PERF_RESPONSE_TIME_CRITICAL=5000
PERF_MEMORY_WARNING=0.8
PERF_MEMORY_CRITICAL=0.95

# Monitoring intervals
PERF_SAMPLING_INTERVAL=30000
TRACE_RETENTION_MS=3600000
```

### Production Deployment

1. **Metrics Collection**: Configure Prometheus to scrape the `/metrics` endpoint
2. **Log Aggregation**: Use structured logging format for log aggregation systems
3. **Alerting**: Set up alert rules based on exported metrics
4. **Dashboards**: Create monitoring dashboards using collected metrics and traces

### Grafana Dashboard Example

```yaml
# Example Grafana dashboard queries
- name: "Request Rate"
  query: "rate(fastmcp_requests_total[5m])"
  
- name: "Error Rate"
  query: "rate(fastmcp_errors_total[5m]) / rate(fastmcp_requests_total[5m])"
  
- name: "Response Time P95"
  query: "histogram_quantile(0.95, rate(fastmcp_request_duration_seconds_bucket[5m]))"
  
- name: "Memory Usage"
  query: "fastmcp_memory_usage_bytes{type='heapUsed'} / fastmcp_memory_usage_bytes{type='heapTotal'}"
```

## 🔍 Troubleshooting

### Common Issues

1. **High Memory Usage**
   - Check performance alerts for memory warnings
   - Review trace retention settings
   - Monitor for memory leaks in long-running operations

2. **High Response Times**
   - Analyze distributed traces for bottlenecks
   - Check Make.com API response times
   - Review database query performance

3. **Missing Metrics**
   - Verify metrics collection is enabled
   - Check for errors in metrics health check
   - Ensure Prometheus scraping is configured

### Debug Logging

Enable debug logging for detailed observability system information:

```bash
LOG_LEVEL=debug
```

This will provide detailed logs for:
- Metric collection operations
- Trace span lifecycle
- Performance monitoring activities
- Health check executions

## 📋 Best Practices

1. **Use Correlation IDs**: Always propagate correlation IDs across operations
2. **Instrument Critical Paths**: Add tracing to important business operations
3. **Monitor Key Metrics**: Focus on response time, error rate, and throughput
4. **Set Appropriate Thresholds**: Configure alerts based on actual usage patterns
5. **Regular Health Checks**: Use health endpoints for automated monitoring
6. **Structured Logging**: Always use structured logging with context
7. **Performance Baseline**: Establish performance baselines before optimization

## 🎉 Summary

The observability stack provides comprehensive monitoring and debugging capabilities for the Make.com FastMCP Server:

- ✅ **Prometheus Metrics**: Production-ready metrics collection
- ✅ **Structured Logging**: Enhanced logging with correlation tracking
- ✅ **Health Monitoring**: Multi-level health assessment
- ✅ **Performance Alerting**: Real-time performance monitoring with alerts
- ✅ **Distributed Tracing**: Complete request flow visibility
- ✅ **Unified Management**: Single interface for all observability features
- ✅ **Production Ready**: Scalable, efficient, and configurable

This implementation follows industry best practices and provides the foundation for maintaining a reliable, observable, and debuggable FastMCP server in production environments.