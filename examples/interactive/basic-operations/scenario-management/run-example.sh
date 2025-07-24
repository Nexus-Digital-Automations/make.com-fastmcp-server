#!/bin/bash

# Make.com FastMCP Server - Scenario Management Demo
# Interactive examples for learning scenario operations

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MCP_SERVER="localhost:3000"
DEMO_DATA="$SCRIPT_DIR/demo-data.json"
LOG_FILE="$SCRIPT_DIR/demo.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default options
OPERATION="all"
INTERACTIVE=false
STEP_BY_STEP=false
FORMAT="json"
SIMULATE_ERRORS=false
CUSTOM_DATA=""
TEST_MODE=false
BENCHMARK=false

# Help function
show_help() {
    echo "Make.com FastMCP Server - Scenario Management Demo"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Operations:"
    echo "  --operation OPERATION    Run specific operation (list|create|update|delete|clone|execute|all)"
    echo "  --demo DEMO              Run specific demo (basic-crud|advanced-filtering|execution|blueprints|scheduling|batch)"
    echo ""
    echo "Modes:"
    echo "  --interactive            Run in interactive mode with prompts"
    echo "  --step-by-step          Explain each step before execution"
    echo "  --test                  Run validation tests"
    echo "  --benchmark             Run performance benchmarks"
    echo "  --simulate-errors       Test error handling scenarios"
    echo ""
    echo "Customization:"
    echo "  --format FORMAT         Output format (json|table|detailed)"
    echo "  --custom-data FILE      Use custom demo data file"
    echo "  --teamId ID             Override team ID"
    echo "  --folderId ID           Override folder ID"
    echo "  --scenarioId ID         Target specific scenario ID"
    echo "  --name NAME             Scenario name for operations"
    echo "  --limit NUMBER          Limit for list operations"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Run all demos"
    echo "  $0 --operation list --limit 5        # List 5 scenarios"
    echo "  $0 --demo basic-crud --interactive    # Interactive CRUD demo"
    echo "  $0 --operation execute --scenarioId scn_123  # Execute specific scenario"
    echo "  $0 --test --operation create,list    # Test create and list operations"
    echo ""
}

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
    echo -e "$*"
}

# Error handling
error() {
    log "${RED}ERROR: $*${NC}"
    exit 1
}

# Success message
success() {
    log "${GREEN}✓ $*${NC}"
}

# Info message
info() {
    log "${BLUE}ℹ $*${NC}"
}

# Warning message
warn() {
    log "${YELLOW}⚠ $*${NC}"
}

# Check prerequisites
check_prerequisites() {
    info "Checking prerequisites..."
    
    # Check if MCP CLI is installed
    if ! command -v npx &> /dev/null; then
        error "Node.js and npx are required. Please install Node.js first."
    fi
    
    # Check if jq is available for JSON processing
    if ! command -v jq &> /dev/null; then
        warn "jq not found. Install jq for better JSON formatting: brew install jq"
    fi
    
    # Check if server is running
    if ! curl -s "http://$MCP_SERVER/health" > /dev/null 2>&1; then
        error "FastMCP server is not running on $MCP_SERVER. Please start the server first."
    fi
    
    # Check if demo data exists
    if [[ ! -f "$DEMO_DATA" ]]; then
        error "Demo data file not found: $DEMO_DATA"
    fi
    
    success "Prerequisites check passed"
}

# Execute MCP command
execute_mcp() {
    local tool_name="$1"
    local params="$2"
    local description="$3"
    
    if [[ "$STEP_BY_STEP" == true ]]; then
        info "About to execute: $description"
        info "Tool: $tool_name"
        info "Parameters: $params"
        read -p "Press Enter to continue..."
    fi
    
    info "Executing: $description"
    
    local request="{\"method\": \"tools/call\", \"params\": {\"name\": \"$tool_name\", \"arguments\": $params}}"
    local result
    
    if result=$(echo "$request" | npx @modelcontextprotocol/cli chat 2>&1); then
        case "$FORMAT" in
            "json")
                if command -v jq &> /dev/null; then
                    echo "$result" | jq -r '.result // .'
                else
                    echo "$result"
                fi
                ;;
            "table")
                format_table_output "$result"
                ;;
            "detailed")
                format_detailed_output "$result" "$description"
                ;;
        esac
        return 0
    else
        error "Failed to execute $tool_name: $result"
        return 1
    fi
}

# Format output as table
format_table_output() {
    local result="$1"
    
    if command -v jq &> /dev/null; then
        echo "$result" | jq -r '
            if .scenarios then
                .scenarios[] | [.id, .name, .isActive, .createdAt] | @tsv
            elif .scenario then
                [.scenario.id, .scenario.name, .scenario.isActive, .scenario.createdAt] | @tsv
            else
                .
            end
        ' | column -t -s $'\t'
    else
        echo "$result"
    fi
}

# Format detailed output
format_detailed_output() {
    local result="$1"
    local description="$2"
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Operation: $description"
    echo "Timestamp: $(date)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "$result"
    echo ""
}

# List scenarios
demo_list_scenarios() {
    local filters="$1"
    [[ -z "$filters" ]] && filters='{"limit": 10, "offset": 0}'
    
    execute_mcp "list-scenarios" "$filters" "List scenarios with filtering"
}

# Get scenario details
demo_get_scenario() {
    local scenario_id="$1"
    [[ -z "$scenario_id" ]] && scenario_id="2001"
    
    local params="{\"scenarioId\": \"$scenario_id\", \"includeBlueprint\": true, \"includeExecutions\": true}"
    execute_mcp "get-scenario" "$params" "Get detailed scenario information"
}

# Create scenario
demo_create_scenario() {
    local scenario_name="$1"
    [[ -z "$scenario_name" ]] && scenario_name="Demo Scenario $(date +%s)"
    
    local scenario_data
    scenario_data=$(jq -n \
        --arg name "$scenario_name" \
        --argjson blueprint "$(jq '.scenarios.basic.blueprint' "$DEMO_DATA")" \
        --argjson scheduling "$(jq '.scenarios.basic.scheduling' "$DEMO_DATA")" \
        '{
            name: $name,
            teamId: "12345",
            blueprint: $blueprint,
            scheduling: $scheduling
        }')
    
    execute_mcp "create-scenario" "$scenario_data" "Create new scenario"
}

# Update scenario
demo_update_scenario() {
    local scenario_id="$1"
    local update_data="$2"
    
    [[ -z "$scenario_id" ]] && scenario_id="2001"
    [[ -z "$update_data" ]] && update_data='{"active": true}'
    
    local params
    params=$(jq -n \
        --arg scenarioId "$scenario_id" \
        --argjson updates "$update_data" \
        '{scenarioId: $scenarioId} + $updates')
    
    execute_mcp "update-scenario" "$params" "Update scenario configuration"
}

# Delete scenario
demo_delete_scenario() {
    local scenario_id="$1"
    local force="$2"
    
    [[ -z "$scenario_id" ]] && scenario_id="2001"
    [[ -z "$force" ]] && force="false"
    
    local params="{\"scenarioId\": \"$scenario_id\", \"force\": $force}"
    execute_mcp "delete-scenario" "$params" "Delete scenario"
}

# Clone scenario
demo_clone_scenario() {
    local source_id="$1"
    local new_name="$2"
    
    [[ -z "$source_id" ]] && source_id="2001"
    [[ -z "$new_name" ]] && new_name="Cloned Scenario $(date +%s)"
    
    local params="{\"scenarioId\": \"$source_id\", \"name\": \"$new_name\", \"active\": false}"
    execute_mcp "clone-scenario" "$params" "Clone existing scenario"
}

# Execute scenario
demo_execute_scenario() {
    local scenario_id="$1"
    local wait_for_completion="$2"
    local timeout="$3"
    
    [[ -z "$scenario_id" ]] && scenario_id="2001"
    [[ -z "$wait_for_completion" ]] && wait_for_completion="true"
    [[ -z "$timeout" ]] && timeout="60"
    
    local params="{\"scenarioId\": \"$scenario_id\", \"wait\": $wait_for_completion, \"timeout\": $timeout}"
    execute_mcp "run-scenario" "$params" "Execute scenario and monitor progress"
}

# Run basic CRUD demo
run_basic_crud_demo() {
    info "Starting Basic CRUD Operations Demo"
    echo ""
    
    # List scenarios
    info "1. Listing existing scenarios..."
    demo_list_scenarios '{"limit": 5, "active": true}'
    echo ""
    
    if [[ "$INTERACTIVE" == true ]]; then
        read -p "Press Enter to continue to scenario creation..."
    fi
    
    # Create scenario
    info "2. Creating a new scenario..."
    local new_scenario_name="CRUD Demo $(date +%s)"
    demo_create_scenario "$new_scenario_name"
    echo ""
    
    if [[ "$INTERACTIVE" == true ]]; then
        read -p "Press Enter to continue to scenario update..."
    fi
    
    # Update scenario (activate it)
    info "3. Updating scenario (activating)..."
    demo_update_scenario "2001" '{"active": true}'
    echo ""
    
    if [[ "$INTERACTIVE" == true ]]; then
        read -p "Press Enter to continue to scenario details..."
    fi
    
    # Get detailed scenario info
    info "4. Getting detailed scenario information..."
    demo_get_scenario "2001"
    echo ""
    
    success "Basic CRUD demo completed successfully!"
}

# Run advanced filtering demo
run_advanced_filtering_demo() {
    info "Starting Advanced Filtering Demo"
    echo ""
    
    # Test different filter combinations
    local filters=(
        '{"active": true, "limit": 10}'
        '{"teamId": "12345", "limit": 20}'
        '{"search": "demo", "limit": 15}'
        '{"folderId": "3001", "active": true, "limit": 5}'
    )
    
    local descriptions=(
        "Active scenarios only"
        "Scenarios for specific team"
        "Search scenarios by name"
        "Active scenarios in specific folder"
    )
    
    for i in "${!filters[@]}"; do
        info "$((i+1)). ${descriptions[i]}..."
        demo_list_scenarios "${filters[i]}"
        echo ""
        
        if [[ "$INTERACTIVE" == true ]]; then
            read -p "Press Enter for next filter..."
        fi
    done
    
    success "Advanced filtering demo completed!"
}

# Run execution demo
run_execution_demo() {
    info "Starting Scenario Execution Demo"
    echo ""
    
    # Execute with wait
    info "1. Executing scenario with progress monitoring..."
    demo_execute_scenario "2001" "true" "60"
    echo ""
    
    if [[ "$INTERACTIVE" == true ]]; then
        read -p "Press Enter to continue to async execution..."
    fi
    
    # Execute without wait
    info "2. Executing scenario asynchronously..."
    demo_execute_scenario "2002" "false" "30"
    echo ""
    
    success "Execution demo completed!"
}

# Run blueprint operations demo
run_blueprint_demo() {
    info "Starting Blueprint Operations Demo"
    echo ""
    
    # Create scenario with custom blueprint
    info "1. Creating scenario with e-commerce blueprint..."
    local ecommerce_data
    ecommerce_data=$(jq '.scenarios.ecommerce' "$DEMO_DATA")
    demo_create_scenario "E-commerce Demo $(date +%s)"
    echo ""
    
    # Update blueprint
    info "2. Updating scenario blueprint..."
    local updated_blueprint
    updated_blueprint=$(jq '.updates.updateBlueprint' "$DEMO_DATA")
    demo_update_scenario "2001" "$updated_blueprint"
    echo ""
    
    success "Blueprint demo completed!"
}

# Run scheduling demo
run_scheduling_demo() {
    info "Starting Scheduling Configuration Demo"
    echo ""
    
    # Test different scheduling types
    local scheduling_types=(
        '{"scheduling": {"type": "immediately"}}'
        '{"scheduling": {"type": "interval", "interval": 900}}'
        '{"scheduling": {"type": "cron", "cron": "0 9 * * 1-5"}}'
    )
    
    local descriptions=(
        "Immediate execution"
        "15-minute interval"
        "Weekdays at 9 AM"
    )
    
    for i in "${!scheduling_types[@]}"; do
        info "$((i+1)). Setting up ${descriptions[i]}..."
        demo_update_scenario "200$((i+1))" "${scheduling_types[i]}"
        echo ""
        
        if [[ "$INTERACTIVE" == true ]]; then
            read -p "Press Enter for next scheduling type..."
        fi
    done
    
    success "Scheduling demo completed!"
}

# Run batch operations demo
run_batch_demo() {
    info "Starting Batch Operations Demo"
    echo ""
    
    # Create multiple scenarios
    info "1. Creating multiple scenarios..."
    local scenarios
    scenarios=$(jq -c '.batch.createMultiple[]' "$DEMO_DATA")
    
    local count=1
    while IFS= read -r scenario_data; do
        local name
        name=$(echo "$scenario_data" | jq -r '.name')
        info "Creating scenario $count: $name"
        demo_create_scenario "$name"
        ((count++))
        echo ""
    done <<< "$scenarios"
    
    # Bulk activate scenarios
    info "2. Bulk activating scenarios..."
    demo_update_scenario "2001" '{"active": true}'
    demo_update_scenario "2002" '{"active": true}'
    demo_update_scenario "2003" '{"active": true}'
    echo ""
    
    success "Batch operations demo completed!"
}

# Run validation tests
run_validation_tests() {
    info "Running validation tests..."
    echo ""
    
    local tests_passed=0
    local tests_failed=0
    
    # Test scenario creation
    info "Test 1: Valid scenario creation"
    if demo_create_scenario "Test Scenario $(date +%s)" > /dev/null 2>&1; then
        success "✓ Scenario creation test passed"
        ((tests_passed++))
    else
        error "✗ Scenario creation test failed"
        ((tests_failed++))
    fi
    
    # Test scenario listing
    info "Test 2: Scenario listing"
    if demo_list_scenarios '{"limit": 5}' > /dev/null 2>&1; then
        success "✓ Scenario listing test passed"
        ((tests_passed++))
    else
        error "✗ Scenario listing test failed"
        ((tests_failed++))
    fi
    
    # Test scenario details
    info "Test 3: Scenario details retrieval"
    if demo_get_scenario "2001" > /dev/null 2>&1; then
        success "✓ Scenario details test passed"
        ((tests_passed++))
    else
        error "✗ Scenario details test failed"
        ((tests_failed++))
    fi
    
    echo ""
    info "Test Results: $tests_passed passed, $tests_failed failed"
    
    if [[ $tests_failed -eq 0 ]]; then
        success "All validation tests passed!"
        return 0
    else
        error "Some validation tests failed!"
        return 1
    fi
}

# Run performance benchmarks
run_benchmarks() {
    info "Running performance benchmarks..."
    echo ""
    
    # Benchmark scenario listing
    info "Benchmarking scenario listing..."
    local start_time end_time duration
    
    start_time=$(date +%s%N)
    demo_list_scenarios '{"limit": 100}' > /dev/null 2>&1
    end_time=$(date +%s%N)
    duration=$(((end_time - start_time) / 1000000))
    
    info "Scenario listing (100 items): ${duration}ms"
    
    # Benchmark scenario creation
    info "Benchmarking scenario creation..."
    start_time=$(date +%s%N)
    demo_create_scenario "Benchmark Test $(date +%s)" > /dev/null 2>&1
    end_time=$(date +%s%N)
    duration=$(((end_time - start_time) / 1000000))
    
    info "Scenario creation: ${duration}ms"
    
    success "Benchmarks completed!"
}

# Simulate error scenarios
simulate_errors() {
    info "Simulating error scenarios for testing..."
    echo ""
    
    # Test with invalid scenario ID
    info "1. Testing with non-existent scenario ID..."
    demo_get_scenario "invalid_id" || warn "Expected error for invalid scenario ID"
    echo ""
    
    # Test with invalid parameters
    info "2. Testing with invalid parameters..."
    execute_mcp "create-scenario" '{"invalid": "data"}' "Create scenario with invalid data" || warn "Expected validation error"
    echo ""
    
    # Test unauthorized operation
    info "3. Testing potential permission errors..."
    demo_delete_scenario "2001" "false" || warn "Expected permission or validation error"
    echo ""
    
    success "Error simulation completed!"
}

# Main execution function
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --operation)
                OPERATION="$2"
                shift 2
                ;;
            --demo)
                DEMO="$2"
                shift 2
                ;;
            --interactive)
                INTERACTIVE=true
                shift
                ;;
            --step-by-step)
                STEP_BY_STEP=true
                shift
                ;;
            --format)
                FORMAT="$2"
                shift 2
                ;;
            --simulate-errors)
                SIMULATE_ERRORS=true
                shift
                ;;
            --custom-data)
                CUSTOM_DATA="$2"
                shift 2
                ;;
            --test)
                TEST_MODE=true
                shift
                ;;
            --benchmark)
                BENCHMARK=true
                shift
                ;;
            --teamId)
                TEAM_ID="$2"
                shift 2
                ;;
            --folderId)
                FOLDER_ID="$2"
                shift 2
                ;;
            --scenarioId)
                SCENARIO_ID="$2"
                shift 2
                ;;
            --name)
                SCENARIO_NAME="$2"
                shift 2
                ;;
            --limit)
                LIMIT="$2"
                shift 2
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                error "Unknown option: $1. Use --help for usage information."
                ;;
        esac
    done
    
    # Use custom data file if specified
    [[ -n "$CUSTOM_DATA" ]] && DEMO_DATA="$CUSTOM_DATA"
    
    # Initialize log file
    echo "Make.com FastMCP Scenario Management Demo - $(date)" > "$LOG_FILE"
    
    info "Starting Make.com FastMCP Scenario Management Demo"
    info "Server: $MCP_SERVER"
    info "Demo Data: $DEMO_DATA"
    info "Log File: $LOG_FILE"
    echo ""
    
    # Check prerequisites
    check_prerequisites
    echo ""
    
    # Run based on mode
    if [[ "$TEST_MODE" == true ]]; then
        run_validation_tests
    elif [[ "$BENCHMARK" == true ]]; then
        run_benchmarks
    elif [[ "$SIMULATE_ERRORS" == true ]]; then
        simulate_errors
    elif [[ -n "$DEMO" ]]; then
        case "$DEMO" in
            "basic-crud")
                run_basic_crud_demo
                ;;
            "advanced-filtering")
                run_advanced_filtering_demo
                ;;
            "execution")
                run_execution_demo
                ;;
            "blueprints")
                run_blueprint_demo
                ;;
            "scheduling")
                run_scheduling_demo
                ;;
            "batch")
                run_batch_demo
                ;;
            *)
                error "Unknown demo: $DEMO"
                ;;
        esac
    elif [[ "$OPERATION" != "all" ]]; then
        case "$OPERATION" in
            "list")
                demo_list_scenarios "{\"limit\": ${LIMIT:-10}}"
                ;;
            "create")
                demo_create_scenario "${SCENARIO_NAME:-Demo Scenario}"
                ;;
            "update")
                demo_update_scenario "${SCENARIO_ID:-2001}" '{"active": true}'
                ;;
            "delete")
                demo_delete_scenario "${SCENARIO_ID:-2001}" "false"
                ;;
            "clone")
                demo_clone_scenario "${SCENARIO_ID:-2001}" "${SCENARIO_NAME:-Cloned Scenario}"
                ;;
            "execute")
                demo_execute_scenario "${SCENARIO_ID:-2001}" "true" "60"
                ;;
            "get")
                demo_get_scenario "${SCENARIO_ID:-2001}"
                ;;
            *)
                error "Unknown operation: $OPERATION"
                ;;
        esac
    else
        # Run all demos
        info "Running all scenario management demos..."
        echo ""
        
        run_basic_crud_demo
        echo ""
        
        if [[ "$INTERACTIVE" == true ]]; then
            read -p "Press Enter to continue to advanced filtering demo..."
        fi
        
        run_advanced_filtering_demo
        echo ""
        
        if [[ "$INTERACTIVE" == true ]]; then
            read -p "Press Enter to continue to execution demo..."
        fi
        
        run_execution_demo
        echo ""
        
        success "All scenario management demos completed successfully!"
    fi
    
    info "Demo completed. Check log file for details: $LOG_FILE"
}

# Execute main function
main "$@"