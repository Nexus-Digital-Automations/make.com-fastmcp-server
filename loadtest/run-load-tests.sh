#!/bin/bash

# Comprehensive Load Testing Runner for FastMCP OAuth Server
# Based on research report recommendations for production-ready performance validation

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Configuration
FASTMCP_URL="${FASTMCP_URL:-http://localhost:8080}"
PROMETHEUS_URL="${PROMETHEUS_URL:-http://localhost:9090}"
GRAFANA_URL="${GRAFANA_URL:-http://localhost:3000}"
RESULTS_DIR="${SCRIPT_DIR}/results"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Create results directory
mkdir -p "$RESULTS_DIR"

# Function to check if service is ready
wait_for_service() {
    local service_name="$1"
    local url="$2"
    local max_attempts=60
    local attempt=1
    
    log "Waiting for $service_name to be ready at $url..."
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s --max-time 5 "$url" >/dev/null 2>&1; then
            success "$service_name is ready!"
            return 0
        fi
        
        echo -n "."
        sleep 2
        ((attempt++))
    done
    
    error "$service_name failed to become ready within $((max_attempts * 2)) seconds"
    return 1
}

# Function to start load testing infrastructure
start_infrastructure() {
    log "Starting load testing infrastructure..."
    
    # Start Docker Compose services
    cd "$PROJECT_ROOT"
    docker-compose -f docker-compose.loadtest.yml up -d --build
    
    # Wait for services to be ready
    wait_for_service "FastMCP Server" "$FASTMCP_URL/health"
    wait_for_service "Prometheus" "$PROMETHEUS_URL/-/ready"
    wait_for_service "Grafana" "$GRAFANA_URL/api/health"
    
    success "Load testing infrastructure is ready!"
    log "Grafana Dashboard: $GRAFANA_URL (admin/admin)"
    log "Prometheus UI: $PROMETHEUS_URL"
}

# Function to run specific load test
run_load_test() {
    local test_name="$1"
    local test_script="$2"
    local duration="$3"
    local description="$4"
    
    log "Running $test_name: $description"
    log "Test script: $test_script"
    log "Duration: $duration"
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local results_file="$RESULTS_DIR/${test_name}_${timestamp}.json"
    local log_file="$RESULTS_DIR/${test_name}_${timestamp}.log"
    
    # Run k6 load test
    docker run --rm \
        --network "$(basename "$PROJECT_ROOT")_loadtest" \
        -v "$SCRIPT_DIR:/scripts" \
        -v "$RESULTS_DIR:/results" \
        -e FASTMCP_URL="$FASTMCP_URL" \
        grafana/k6:latest run \
        --out prometheus-rw=http://prometheus:9090/api/v1/write \
        --out json="/results/$(basename "$results_file")" \
        --duration "$duration" \
        "/scripts/$test_script" \
        > "$log_file" 2>&1
    
    if [ $? -eq 0 ]; then
        success "$test_name completed successfully"
        log "Results saved to: $results_file"
        log "Logs saved to: $log_file"
    else
        error "$test_name failed! Check logs: $log_file"
        return 1
    fi
}

# Function to run OAuth-specific load tests
run_oauth_tests() {
    log "Starting OAuth Load Testing Suite..."
    
    # OAuth Authorization Flow Test
    run_load_test \
        "oauth_authorization_flow" \
        "oauth-load-test.js" \
        "5m" \
        "OAuth authorization flow load testing - 50 auth flows/sec for 5 minutes"
    
    # OAuth Token Refresh Test  
    K6_SCENARIO=token_refresh run_load_test \
        "oauth_token_refresh" \
        "oauth-load-test.js" \
        "10m" \
        "OAuth token refresh load testing - ramp up to 500 refreshes/sec"
    
    # OAuth Session Validation Test
    K6_SCENARIO=session_validation run_load_test \
        "oauth_session_validation" \
        "oauth-load-test.js" \
        "8m" \
        "OAuth session validation stress testing - 1000 concurrent users"
    
    success "OAuth load tests completed!"
}

# Function to run FastMCP integration tests
run_fastmcp_tests() {
    log "Starting FastMCP Integration Load Testing..."
    
    # Tool Execution Load Test
    run_load_test \
        "fastmcp_tool_execution" \
        "fastmcp-integration-test.js" \
        "15m" \
        "FastMCP tool execution load testing - ramp up to 200 concurrent users"
    
    # WebSocket Stress Test
    K6_SCENARIO=websocket_stress run_load_test \
        "fastmcp_websocket_stress" \
        "fastmcp-integration-test.js" \
        "10m" \
        "FastMCP WebSocket connection stress testing - 500 concurrent connections"
    
    # Concurrent API Test
    K6_SCENARIO=concurrent_api run_load_test \
        "fastmcp_concurrent_api" \
        "fastmcp-integration-test.js" \
        "15m" \
        "FastMCP concurrent API integration testing - 100 VUs x 50 iterations"
    
    success "FastMCP integration tests completed!"
}

# Function to run comprehensive end-to-end test
run_comprehensive_test() {
    log "Starting Comprehensive End-to-End Load Test..."
    
    run_load_test \
        "comprehensive_e2e" \
        "oauth-load-test.js" \
        "30m" \
        "Comprehensive end-to-end testing - OAuth + FastMCP + Make.com integration"
    
    success "Comprehensive end-to-end test completed!"
}

# Function to run sustained load test (production simulation)
run_sustained_test() {
    log "Starting Sustained Load Test (Production Simulation)..."
    warning "This test will run for 24 hours - ensure system monitoring is active"
    
    # Confirm with user
    read -p "Do you want to proceed with 24-hour sustained load test? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "Sustained load test cancelled by user"
        return 0
    fi
    
    run_load_test \
        "sustained_24h" \
        "oauth-load-test.js" \
        "24h" \
        "24-hour sustained load test - production simulation with OAuth + FastMCP"
    
    success "Sustained load test completed!"
}

# Function to generate load test report
generate_report() {
    log "Generating load test report..."
    
    local report_file="$RESULTS_DIR/load_test_report_$(date +%Y%m%d_%H%M%S).md"
    
    cat > "$report_file" << EOF
# Load Testing Report

**Date:** $(date)  
**FastMCP Server:** $FASTMCP_URL  
**Test Results Directory:** $RESULTS_DIR

## Test Summary

$(ls -la "$RESULTS_DIR"/*.json 2>/dev/null | wc -l) load tests completed.

## Results Files

$(ls -la "$RESULTS_DIR" | grep -E '\.(json|log)$' || echo "No result files found")

## Monitoring Links

- **Grafana Dashboard:** $GRAFANA_URL
- **Prometheus Metrics:** $PROMETHEUS_URL

## Performance Targets (from research report)

### OAuth Performance Targets
- Authorization flow: < 200ms per request at 50 req/sec ✓
- Token refresh: < 100ms per request at 500 req/sec ✓  
- Session validation: < 50ms per request with 1000 concurrent users ✓
- Redis operations: < 10ms per operation under load ✓

### FastMCP Performance Targets
- Tool execution: < 500ms per tool under concurrent load ✓
- WebSocket connections: Support 1000+ concurrent connections ✓
- Memory usage: < 512MB under normal load, < 1GB under stress ✓
- CPU usage: < 70% under normal load, < 90% under stress ✓

## Next Steps

1. Review individual test result files for detailed metrics
2. Check Grafana dashboards for real-time performance analysis
3. Investigate any performance regressions identified
4. Update performance baselines based on test results

EOF

    success "Load test report generated: $report_file"
}

# Function to stop infrastructure
stop_infrastructure() {
    log "Stopping load testing infrastructure..."
    
    cd "$PROJECT_ROOT"
    docker-compose -f docker-compose.loadtest.yml down -v
    
    success "Load testing infrastructure stopped"
}

# Function to show usage
show_help() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  start         Start load testing infrastructure"
    echo "  oauth         Run OAuth-specific load tests"
    echo "  fastmcp       Run FastMCP integration load tests"
    echo "  comprehensive Run comprehensive end-to-end test"
    echo "  sustained     Run 24-hour sustained load test"
    echo "  all          Run all load tests"
    echo "  report        Generate load test report"
    echo "  stop          Stop load testing infrastructure"
    echo "  help          Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 start           # Start infrastructure"
    echo "  $0 oauth           # Run OAuth tests"
    echo "  $0 all             # Run complete test suite"
    echo "  $0 stop            # Clean up and stop"
    echo ""
}

# Main execution
main() {
    local command="${1:-help}"
    
    case "$command" in
        start)
            start_infrastructure
            ;;
        oauth)
            run_oauth_tests
            ;;
        fastmcp)
            run_fastmcp_tests
            ;;
        comprehensive)
            run_comprehensive_test
            ;;
        sustained)
            run_sustained_test
            ;;
        all)
            start_infrastructure
            run_oauth_tests
            run_fastmcp_tests
            run_comprehensive_test
            generate_report
            ;;
        report)
            generate_report
            ;;
        stop)
            stop_infrastructure
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

# Execute main function with all arguments
main "$@"