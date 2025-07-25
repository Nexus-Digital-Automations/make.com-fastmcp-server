#!/bin/bash

# ==============================================================================
# Comprehensive Health Check Script for Make.com FastMCP Server
# Production-ready health monitoring with detailed diagnostics
# ==============================================================================

set -euo pipefail

# Configuration
HEALTH_CHECK_URL="${HEALTH_CHECK_URL:-http://localhost:3000/health}"
TIMEOUT="${HEALTH_CHECK_TIMEOUT:-10}"
MAX_RETRIES="${HEALTH_CHECK_RETRIES:-3}"
VERBOSE="${HEALTH_CHECK_VERBOSE:-false}"
LOG_FILE="${HEALTH_CHECK_LOG:-/tmp/fastmcp-health.log}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Verbose logging function
verbose_log() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${BLUE}[DEBUG]${NC} $1" | tee -a "$LOG_FILE"
    fi
}

# Error function
error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

# Success function
success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

# Warning function
warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

# Check if required tools are available
check_dependencies() {
    verbose_log "Checking dependencies..."
    
    local missing_deps=()
    
    command -v curl >/dev/null 2>&1 || missing_deps+=("curl")
    command -v jq >/dev/null 2>&1 || missing_deps+=("jq")
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        error "Missing required dependencies: ${missing_deps[*]}"
        echo "Please install missing dependencies and try again."
        exit 1
    fi
    
    verbose_log "All dependencies are available"
}

# Parse JSON response safely
parse_json() {
    local json_data="$1"
    local key="$2"
    
    echo "$json_data" | jq -r ".$key // empty" 2>/dev/null || echo ""
}

# Perform basic HTTP health check
basic_health_check() {
    verbose_log "Performing basic HTTP health check..."
    
    local response
    local http_code
    local response_time
    
    # Make HTTP request with timeout
    if ! response=$(curl -s -w "%{http_code}|%{time_total}" --max-time "$TIMEOUT" "$HEALTH_CHECK_URL" 2>/dev/null); then
        error "Failed to connect to health check endpoint"
        return 1
    fi
    
    # Parse response
    http_code=$(echo "$response" | tail -1 | cut -d'|' -f1)
    response_time=$(echo "$response" | tail -1 | cut -d'|' -f2)
    response_body=$(echo "$response" | head -n -1)
    
    verbose_log "HTTP Status: $http_code"
    verbose_log "Response Time: ${response_time}s"
    verbose_log "Response Body: $response_body"
    
    # Check HTTP status code
    if [[ "$http_code" != "200" ]]; then
        error "Health check failed with HTTP status: $http_code"
        return 1
    fi
    
    # Check response time
    if (( $(echo "$response_time > 5.0" | bc -l) )); then
        warning "Slow response time: ${response_time}s (threshold: 5.0s)"
    fi
    
    success "Basic health check passed (${response_time}s)"
    echo "$response_body"
    return 0
}

# Detailed health analysis
detailed_health_analysis() {
    local health_data="$1"
    
    verbose_log "Performing detailed health analysis..."
    
    # Parse health check response
    local status=$(parse_json "$health_data" "status")
    local timestamp=$(parse_json "$health_data" "timestamp")
    local server_name=$(parse_json "$health_data" "server.name")
    local server_version=$(parse_json "$health_data" "server.version")
    local uptime=$(parse_json "$health_data" "server.uptime")
    
    # API connectivity
    local api_status=$(parse_json "$health_data" "make_api.status")
    local api_response_time=$(parse_json "$health_data" "make_api.response_time")
    
    # Rate limiter
    local rate_limiter_status=$(parse_json "$health_data" "rate_limiter.status")
    local remaining_requests=$(parse_json "$health_data" "rate_limiter.remaining_requests")
    
    # Memory usage
    local memory_used=$(parse_json "$health_data" "system.memory.used")
    local memory_total=$(parse_json "$health_data" "system.memory.total")
    
    # Validate critical components
    local issues=()
    
    if [[ "$status" != "healthy" ]]; then
        issues+=("Overall status is not healthy: $status")
    fi
    
    if [[ "$api_status" != "connected" ]]; then
        issues+=("Make.com API is not connected: $api_status")
    fi
    
    if [[ -n "$api_response_time" ]] && (( $(echo "$api_response_time > 2000" | bc -l) )); then
        issues+=("Slow Make.com API response: ${api_response_time}ms")
    fi
    
    if [[ "$rate_limiter_status" != "healthy" ]]; then
        issues+=("Rate limiter is not healthy: $rate_limiter_status")
    fi
    
    if [[ -n "$remaining_requests" ]] && (( remaining_requests < 10 )); then
        issues+=("Low remaining requests: $remaining_requests")
    fi
    
    # Memory usage check (if available)
    if [[ -n "$memory_used" && -n "$memory_total" ]]; then
        local memory_percent=$(echo "scale=2; $memory_used * 100 / $memory_total" | bc -l)
        if (( $(echo "$memory_percent > 90" | bc -l) )); then
            issues+=("High memory usage: ${memory_percent}%")
        fi
    fi
    
    # Report results
    if [[ ${#issues[@]} -eq 0 ]]; then
        success "Detailed health analysis passed"
        verbose_log "Server: $server_name v$server_version"
        verbose_log "Uptime: $uptime"
        verbose_log "API Response Time: ${api_response_time}ms"
        verbose_log "Remaining Requests: $remaining_requests"
        return 0
    else
        error "Health issues detected:"
        for issue in "${issues[@]}"; do
            error "  - $issue"
        done
        return 1
    fi
}

# Container-specific health checks
container_health_check() {
    verbose_log "Performing container-specific health checks..."
    
    # Check if running in a container
    if [[ ! -f /.dockerenv ]]; then
        verbose_log "Not running in a container, skipping container checks"
        return 0
    fi
    
    # Check container metrics if available
    local issues=()
    
    # Check disk space
    local disk_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [[ -n "$disk_usage" ]] && (( disk_usage > 90 )); then
        issues+=("High disk usage: ${disk_usage}%")
    fi
    
    # Check if essential files exist
    local essential_files=("/app/dist/index.js" "/app/package.json")
    for file in "${essential_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            issues+=("Missing essential file: $file")
        fi
    done
    
    # Report container health
    if [[ ${#issues[@]} -eq 0 ]]; then
        success "Container health checks passed"
        return 0
    else
        error "Container health issues detected:"
        for issue in "${issues[@]}"; do
            error "  - $issue"
        done
        return 1
    fi
}

# Main health check function with retries
run_health_check() {
    local attempt=1
    local max_attempts=$((MAX_RETRIES + 1))
    
    log "Starting health check (max attempts: $max_attempts)"
    
    while [[ $attempt -le $max_attempts ]]; do
        verbose_log "Health check attempt $attempt/$max_attempts"
        
        # Perform basic health check
        local health_data
        if health_data=$(basic_health_check); then
            # Perform detailed analysis
            if detailed_health_analysis "$health_data"; then
                # Perform container checks
                if container_health_check; then
                    success "All health checks passed on attempt $attempt"
                    return 0
                fi
            fi
        fi
        
        if [[ $attempt -lt $max_attempts ]]; then
            warning "Health check failed, retrying in 5 seconds... (attempt $attempt/$max_attempts)"
            sleep 5
        fi
        
        ((attempt++))
    done
    
    error "Health check failed after $max_attempts attempts"
    return 1
}

# Monitoring mode (continuous health checks)
monitoring_mode() {
    local interval="${HEALTH_CHECK_INTERVAL:-30}"
    
    log "Starting continuous health monitoring (interval: ${interval}s)"
    
    while true; do
        if run_health_check; then
            success "Health monitoring check passed"
        else
            error "Health monitoring check failed"
        fi
        
        verbose_log "Next check in ${interval} seconds..."
        sleep "$interval"
    done
}

# Usage information
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
    -u, --url URL           Health check URL (default: http://localhost:3000/health)
    -t, --timeout SECONDS   Request timeout (default: 10)
    -r, --retries COUNT     Max retries (default: 3)
    -v, --verbose           Enable verbose output
    -m, --monitor           Continuous monitoring mode
    -i, --interval SECONDS  Monitoring interval (default: 30)
    -l, --log-file FILE     Log file path (default: /tmp/fastmcp-health.log)
    -h, --help              Show this help message

Environment Variables:
    HEALTH_CHECK_URL        Health check URL
    HEALTH_CHECK_TIMEOUT    Request timeout in seconds
    HEALTH_CHECK_RETRIES    Maximum number of retries
    HEALTH_CHECK_VERBOSE    Enable verbose output (true/false)
    HEALTH_CHECK_INTERVAL   Monitoring interval in seconds
    HEALTH_CHECK_LOG        Log file path

Examples:
    # Basic health check
    $0

    # Health check with custom URL and verbose output
    $0 -u http://make-fastmcp:3000/health -v

    # Continuous monitoring
    $0 -m -i 60

    # Container health check with custom timeout
    $0 -t 30 -r 5

Exit Codes:
    0 - All health checks passed
    1 - Health check failed
    2 - Invalid arguments or dependencies missing
EOF
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -u|--url)
                HEALTH_CHECK_URL="$2"
                shift 2
                ;;
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -r|--retries)
                MAX_RETRIES="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE="true"
                shift
                ;;
            -m|--monitor)
                MONITOR_MODE="true"
                shift
                ;;
            -i|--interval)
                HEALTH_CHECK_INTERVAL="$2"
                shift 2
                ;;
            -l|--log-file)
                LOG_FILE="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                usage
                exit 2
                ;;
        esac
    done
}

# Main execution
main() {
    # Parse arguments
    parse_arguments "$@"
    
    # Check dependencies
    check_dependencies
    
    # Initialize log file
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    
    log "FastMCP Server Health Check Starting"
    verbose_log "Configuration:"
    verbose_log "  URL: $HEALTH_CHECK_URL"
    verbose_log "  Timeout: ${TIMEOUT}s"
    verbose_log "  Max Retries: $MAX_RETRIES"
    verbose_log "  Log File: $LOG_FILE"
    
    # Run health check or monitoring
    if [[ "${MONITOR_MODE:-false}" == "true" ]]; then
        monitoring_mode
    else
        run_health_check
    fi
}

# Run main function with all arguments
main "$@"