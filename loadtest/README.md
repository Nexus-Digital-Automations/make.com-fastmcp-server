# FastMCP OAuth Server Load Testing Suite

Comprehensive performance load testing and optimization suite for the Make.com FastMCP server with OAuth 2.1 + PKCE authentication.

## 📋 Overview

This load testing suite implements the research-backed performance validation framework outlined in `../development/research-reports/research-report-task_1756019495588_oazsvqyly.md`. It provides comprehensive testing for OAuth authentication flows, FastMCP tool execution, and integrated system performance under production-level load conditions.

## 🎯 Performance Targets

Based on research analysis, the system targets the following performance criteria:

### OAuth Performance Targets

- **Authorization flow**: < 200ms per request at 50 req/sec
- **Token refresh**: < 100ms per request at 500 req/sec
- **Session validation**: < 50ms per request with 1000 concurrent users
- **Redis operations**: < 10ms per operation under load

### FastMCP Performance Targets

- **Tool execution**: < 500ms per tool under concurrent load
- **WebSocket connections**: Support 1000+ concurrent connections
- **Memory usage**: < 512MB under normal load, < 1GB under stress
- **CPU usage**: < 70% under normal load, < 90% under stress

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   k6 Load Test  │    │  FastMCP Server │    │   Make.com API  │
│     Engine      │◄──►│  (OAuth + MCP)  │◄──►│   Integration   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐    ┌─────────────────┐
│   Prometheus    │    │      Redis      │
│    Metrics      │    │ Session Store   │
└─────────────────┘    └─────────────────┘
         │
         ▼
┌─────────────────┐
│     Grafana     │
│   Dashboards    │
└─────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose
- k6 load testing framework
- Access to Make.com API for integration testing

### 1. Start Infrastructure

```bash
# Start all load testing services
./run-load-tests.sh start

# Services will be available at:
# - FastMCP Server: http://localhost:8080
# - Grafana Dashboard: http://localhost:3000 (admin/admin)
# - Prometheus UI: http://localhost:9090
```

### 2. Run Load Tests

```bash
# Run OAuth-specific load tests
./run-load-tests.sh oauth

# Run FastMCP integration tests
./run-load-tests.sh fastmcp

# Run comprehensive end-to-end test
./run-load-tests.sh comprehensive

# Run complete test suite
./run-load-tests.sh all
```

### 3. Monitor Results

- **Real-time Monitoring**: Open Grafana at http://localhost:3000
- **Metrics Analysis**: View Prometheus at http://localhost:9090
- **Test Results**: Check `./results/` directory for detailed reports

### 4. Clean Up

```bash
# Stop all services and clean up
./run-load-tests.sh stop
```

## 📁 File Structure

```
loadtest/
├── README.md                           # This documentation
├── run-load-tests.sh                  # Main test runner script
├── performance-config.js               # Performance configuration
├── oauth-load-test.js                 # OAuth-specific load tests
├── fastmcp-integration-test.js        # FastMCP integration tests
├── prometheus.yml                     # Prometheus configuration
├── grafana/                           # Grafana configuration
│   ├── provisioning/
│   │   ├── datasources/
│   │   │   └── prometheus.yml         # Prometheus datasource
│   │   └── dashboards/
│   │       └── dashboard.yml          # Dashboard configuration
│   └── dashboards/
│       └── oauth-load-test-dashboard.json  # Load testing dashboard
└── results/                           # Test results directory
    ├── *.json                         # k6 test results
    ├── *.log                          # Test execution logs
    └── *_report.md                    # Generated reports
```

## 🧪 Test Scenarios

### OAuth Load Testing (`oauth-load-test.js`)

**Authorization Flow Testing**

- Pattern: Constant arrival rate
- Rate: 50 authorization flows per second
- Duration: 5 minutes
- Virtual Users: 100-200 (pre-allocated)
- Validates: PKCE flow, session creation, token exchange

**Token Refresh Testing**

- Pattern: Ramping rate
- Stages: 0→100→500→0 requests per second
- Duration: 9 minutes total
- Validates: Refresh token flow, session management

**Session Validation Testing**

- Pattern: Per-VU iterations
- Virtual Users: 1000 concurrent
- Iterations: 10 per user
- Validates: Session lookup, Redis performance

### FastMCP Integration Testing (`fastmcp-integration-test.js`)

**Tool Execution Load Testing**

- Pattern: Ramping virtual users
- Stages: 1→50→100→200→0 users
- Duration: 16 minutes total
- Tests: All FastMCP tools with concurrent execution

**WebSocket Stress Testing**

- Pattern: Constant virtual users
- Virtual Users: 500 concurrent connections
- Duration: 10 minutes
- Tests: Connection establishment, maintenance, cleanup

**Concurrent API Testing**

- Pattern: Per-VU iterations
- Virtual Users: 100
- Iterations: 50 per user
- Tests: Multiple endpoints simultaneously

## 📊 Monitoring and Metrics

### Custom k6 Metrics

```javascript
// OAuth-specific metrics
const oauthErrors = new Counter("oauth_errors");
const oauthSuccessRate = new Rate("oauth_success_rate");
const authFlowDuration = new Trend("oauth_auth_flow_duration");
const tokenRefreshDuration = new Trend("oauth_token_refresh_duration");
const sessionValidationDuration = new Trend(
  "oauth_session_validation_duration",
);

// FastMCP-specific metrics
const fastmcpErrors = new Counter("fastmcp_errors");
const fastmcpSuccessRate = new Rate("fastmcp_success_rate");
const toolExecutionDuration = new Trend("fastmcp_tool_execution_duration");
const webSocketConnectionDuration = new Trend(
  "fastmcp_websocket_connection_duration",
);
```

### Grafana Dashboard Features

- **Real-time OAuth Performance**: Success rates, error counts, response times
- **FastMCP Tool Performance**: Execution times, concurrent users, throughput
- **System Resource Usage**: CPU, memory, network utilization
- **HTTP Performance**: Request rates, status codes, percentile analysis
- **Custom Alerts**: Configurable thresholds for performance regression detection

## 🔧 Configuration

### Environment Variables

```bash
# Required environment variables
FASTMCP_URL=http://localhost:8080           # FastMCP server URL
MAKE_CLIENT_ID=your-make-client-id          # Make.com OAuth client ID
OAUTH_REDIRECT_URI=http://localhost:8080/oauth/callback  # OAuth redirect
REDIS_URL=redis://localhost:6379           # Redis connection URL

# Optional performance tuning
K6_PROMETHEUS_RW_SERVER_URL=http://prometheus:9090/api/v1/write
K6_PROMETHEUS_RW_TREND_AS_NATIVE_HISTOGRAM=true
```

### Performance Configuration

Edit `performance-config.js` to adjust:

- Redis connection pooling settings
- HTTP server optimization parameters
- Rate limiting configurations
- Load testing scenario parameters
- Performance target thresholds

## 📈 Performance Optimization

The suite includes production-ready optimization settings:

### Redis Session Store Optimization

- Connection pooling (10-50 connections)
- L1 local caching with 5-minute TTL
- Session compression for payloads > 1KB
- Daily encryption key rotation

### FastMCP Server Optimization

- HTTP keep-alive and header timeout configuration
- Request compression and ETag support
- Rate limiting (1000 req/min per IP)
- Response caching for cacheable endpoints

### Make.com API Client Optimization

- Connection pooling with keep-alive
- Intelligent rate limiting matching Make.com limits
- Exponential backoff retry policy
- Circuit breaker pattern for failure resilience

## 🚨 Troubleshooting

### Common Issues

**Docker Compose fails to start**

```bash
# Check for port conflicts
docker ps -a
lsof -i :8080 -i :3000 -i :9090 -i :6379

# Clean up previous containers
docker-compose -f docker-compose.loadtest.yml down -v
```

**k6 tests fail with connection errors**

```bash
# Verify FastMCP server is healthy
curl http://localhost:8080/health

# Check Docker network connectivity
docker network ls
docker network inspect <network_name>
```

**High memory usage during tests**

```bash
# Monitor system resources
docker stats

# Adjust test parameters in performance-config.js
# Reduce concurrent virtual users or test duration
```

### Performance Debugging

**Enable detailed logging**

```bash
# Add to docker-compose.loadtest.yml
environment:
  - DEBUG=*
  - LOG_LEVEL=debug
```

**Access container logs**

```bash
# View FastMCP server logs
docker-compose -f docker-compose.loadtest.yml logs fastmcp-server

# View k6 test logs
docker-compose -f docker-compose.loadtest.yml logs k6
```

## 🎯 Production Deployment

### CI/CD Integration

```yaml
# .github/workflows/performance-testing.yml
name: Performance Testing
on:
  pull_request:
    branches: [main]
  schedule:
    - cron: "0 2 * * *" # Daily at 2 AM

jobs:
  performance-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Load Tests
        run: |
          cd loadtest
          ./run-load-tests.sh all
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: performance-results
          path: loadtest/results/
```

### Production Monitoring

Deploy monitoring stack with:

- Prometheus for metrics collection
- Grafana for visualization
- AlertManager for performance alerting
- Custom dashboards for OAuth and FastMCP metrics

## 📚 References

- [Research Report](../development/research-reports/research-report-task_1756019495588_oazsvqyly.md) - Detailed research and implementation strategy
- [k6 Documentation](https://k6.io/docs/) - Load testing framework reference
- [Prometheus Configuration](https://prometheus.io/docs/prometheus/latest/configuration/) - Metrics collection setup
- [Grafana Dashboard](https://grafana.com/docs/grafana/latest/dashboards/) - Visualization and monitoring

## 🤝 Contributing

When adding new load tests:

1. Follow existing patterns in `oauth-load-test.js` and `fastmcp-integration-test.js`
2. Add custom metrics for new functionality
3. Update Grafana dashboards with new metric visualizations
4. Document new test scenarios in this README
5. Update performance targets in `performance-config.js`

## 📄 License

This load testing suite is part of the FastMCP OAuth server project and follows the same license terms.
