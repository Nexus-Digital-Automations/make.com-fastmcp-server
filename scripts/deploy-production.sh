#!/bin/bash

# ==============================================================================
# Production Deployment Script for Make.com FastMCP Server
# Supports Docker Compose and Kubernetes deployment modes
# ==============================================================================

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="${PROJECT_DIR}/logs/deployment.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ==============================================================================
# Utility Functions
# ==============================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        INFO)  echo -e "${GREEN}[INFO]${NC} $message" ;;
        WARN)  echo -e "${YELLOW}[WARN]${NC} $message" ;;
        ERROR) echo -e "${RED}[ERROR]${NC} $message" ;;
        DEBUG) echo -e "${BLUE}[DEBUG]${NC} $message" ;;
    esac
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

check_prerequisites() {
    log INFO "Checking deployment prerequisites..."
    
    # Check if running in project directory
    if [[ ! -f "$PROJECT_DIR/package.json" ]]; then
        log ERROR "Must be run from project root directory"
        exit 1
    fi
    
    # Check required tools
    local missing_tools=0
    
    if ! command -v docker &> /dev/null; then
        log ERROR "Docker is required but not installed"
        ((missing_tools++))
    fi
    
    if [[ "$DEPLOYMENT_MODE" == "compose" ]] && ! command -v docker-compose &> /dev/null; then
        log ERROR "Docker Compose is required but not installed"
        ((missing_tools++))
    fi
    
    if [[ "$DEPLOYMENT_MODE" == "kubernetes" ]] && ! command -v kubectl &> /dev/null; then
        log ERROR "kubectl is required but not installed"
        ((missing_tools++))
    fi
    
    if ((missing_tools > 0)); then
        log ERROR "Missing $missing_tools required tools. Please install them before proceeding."
        exit 1
    fi
    
    log INFO "Prerequisites check passed"
}

validate_environment() {
    log INFO "Validating environment configuration..."
    
    local missing_vars=0
    local required_vars=(
        "MAKE_API_KEY"
        "AUTH_SECRET"
    )
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            log ERROR "Required environment variable $var is not set"
            ((missing_vars++))
        fi
    done
    
    if ((missing_vars > 0)); then
        log ERROR "Missing $missing_vars required environment variables"
        log INFO "Please set the required variables in your .env file or environment"
        exit 1
    fi
    
    # Validate environment file
    if [[ -f "$PROJECT_DIR/.env" ]]; then
        log INFO "Found .env file, validating configuration"
        source "$PROJECT_DIR/.env"
    else
        log WARN "No .env file found, using environment variables only"
    fi
    
    log INFO "Environment validation passed"
}

build_application() {
    log INFO "Building application for production..."
    
    cd "$PROJECT_DIR"
    
    # Clean previous builds
    log DEBUG "Cleaning previous builds"
    rm -rf dist/
    rm -rf node_modules/.cache/
    
    # Install dependencies
    log DEBUG "Installing production dependencies"
    npm ci --only=production
    
    # Install dev dependencies for build
    log DEBUG "Installing build dependencies"
    npm ci
    
    # Run linting
    log DEBUG "Running linter checks"
    if ! npm run lint; then
        log ERROR "Linting failed. Please fix errors before deploying."
        exit 1
    fi
    
    # Run tests
    log DEBUG "Running test suite"
    if ! npm test; then
        log ERROR "Tests failed. Please fix failing tests before deploying."
        exit 1
    fi
    
    # Build application
    log DEBUG "Building TypeScript application"
    if ! npm run build:prod; then
        log ERROR "Build failed. Please fix build errors before deploying."
        exit 1
    fi
    
    log INFO "Application build completed successfully"
}

build_docker_image() {
    log INFO "Building Docker image for production..."
    
    cd "$PROJECT_DIR"
    
    # Set image tag
    local image_tag="${DOCKER_IMAGE:-make-fastmcp-server}:${IMAGE_VERSION:-production}"
    
    # Build Docker image
    log DEBUG "Building Docker image: $image_tag"
    if ! docker build \
        --target runtime \
        --tag "$image_tag" \
        --build-arg NODE_ENV=production \
        --build-arg BUILD_OPTIMIZATION=true \
        .; then
        log ERROR "Docker image build failed"
        exit 1
    fi
    
    # Tag as latest if specified
    if [[ "${TAG_LATEST:-false}" == "true" ]]; then
        docker tag "$image_tag" "${DOCKER_IMAGE:-make-fastmcp-server}:latest"
        log DEBUG "Tagged image as latest"
    fi
    
    log INFO "Docker image built successfully: $image_tag"
}

deploy_docker_compose() {
    log INFO "Deploying with Docker Compose..."
    
    cd "$PROJECT_DIR"
    
    # Create required directories
    mkdir -p logs data/redis data/prometheus backup/redis monitoring nginx/ssl config
    
    # Generate docker-compose command
    local compose_files=("-f" "docker-compose.prod.yml")
    
    if [[ -f "docker-compose.override.yml" ]]; then
        compose_files+=("-f" "docker-compose.override.yml")
        log DEBUG "Using docker-compose.override.yml"
    fi
    
    # Stop existing deployment
    log DEBUG "Stopping existing containers"
    docker-compose "${compose_files[@]}" down --remove-orphans || true
    
    # Pull/build latest images
    log DEBUG "Building/pulling images"
    docker-compose "${compose_files[@]}" build
    
    # Start services
    log DEBUG "Starting services"
    if ! docker-compose "${compose_files[@]}" up -d; then
        log ERROR "Failed to start Docker Compose services"
        exit 1
    fi
    
    # Wait for services to be healthy
    log INFO "Waiting for services to be healthy..."
    local max_wait=300  # 5 minutes
    local wait_time=0
    
    while ((wait_time < max_wait)); do
        if docker-compose "${compose_files[@]}" ps | grep -q "healthy"; then
            log INFO "Services are healthy"
            break
        fi
        
        if ((wait_time % 30 == 0)); then
            log DEBUG "Still waiting for services to be healthy... (${wait_time}s)"
        fi
        
        sleep 5
        ((wait_time += 5))
    done
    
    if ((wait_time >= max_wait)); then
        log ERROR "Services did not become healthy within $max_wait seconds"
        docker-compose "${compose_files[@]}" logs
        exit 1
    fi
    
    log INFO "Docker Compose deployment completed successfully"
}

deploy_kubernetes() {
    log INFO "Deploying to Kubernetes..."
    
    cd "$PROJECT_DIR"
    
    # Check kubectl connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log ERROR "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    # Apply Kubernetes manifests
    log DEBUG "Applying Kubernetes manifests"
    if ! kubectl apply -f k8s/; then
        log ERROR "Failed to apply Kubernetes manifests"
        exit 1
    fi
    
    # Wait for deployment to be ready
    log INFO "Waiting for deployment to be ready..."
    if ! kubectl wait --for=condition=available --timeout=600s deployment/make-fastmcp-server -n make-fastmcp; then
        log ERROR "Deployment did not become ready within 10 minutes"
        kubectl describe deployment make-fastmcp-server -n make-fastmcp
        kubectl logs -l app=make-fastmcp-server -n make-fastmcp --tail=50
        exit 1
    fi
    
    # Show deployment status
    kubectl get pods -n make-fastmcp
    kubectl get services -n make-fastmcp
    
    log INFO "Kubernetes deployment completed successfully"
}

verify_deployment() {
    log INFO "Verifying deployment..."
    
    local health_url
    local metrics_url
    
    if [[ "$DEPLOYMENT_MODE" == "compose" ]]; then
        health_url="http://localhost:${HOST_PORT:-3000}/health"
        metrics_url="http://localhost:${METRICS_PORT:-9090}/metrics"
    else
        # For Kubernetes, use port-forward for verification
        kubectl port-forward -n make-fastmcp service/make-fastmcp-server 3000:3000 &
        local port_forward_pid=$!
        sleep 5
        health_url="http://localhost:3000/health"
        metrics_url="http://localhost:3000/metrics"
    fi
    
    # Check health endpoint
    log DEBUG "Checking health endpoint: $health_url"
    local health_response
    if health_response=$(curl -s "$health_url" 2>/dev/null); then
        if echo "$health_response" | grep -q '"healthy":true'; then
            log INFO "Health check passed"
        else
            log WARN "Health check returned unhealthy status"
            log DEBUG "Health response: $health_response"
        fi
    else
        log ERROR "Health check failed - endpoint not accessible"
        [[ "$DEPLOYMENT_MODE" == "kubernetes" ]] && kill $port_forward_pid &> /dev/null || true
        exit 1
    fi
    
    # Check metrics endpoint
    log DEBUG "Checking metrics endpoint: $metrics_url"
    if curl -s "$metrics_url" | grep -q "fastmcp_"; then
        log INFO "Metrics endpoint is working"
    else
        log WARN "Metrics endpoint may not be working properly"
    fi
    
    # Clean up port-forward for Kubernetes
    [[ "$DEPLOYMENT_MODE" == "kubernetes" ]] && kill $port_forward_pid &> /dev/null || true
    
    log INFO "Deployment verification completed"
}

show_deployment_info() {
    log INFO "=== Deployment Information ==="
    
    echo -e "${GREEN}Deployment Mode:${NC} $DEPLOYMENT_MODE"
    echo -e "${GREEN}Image Version:${NC} ${IMAGE_VERSION:-production}"
    echo -e "${GREEN}Environment:${NC} ${NODE_ENV:-production}"
    
    if [[ "$DEPLOYMENT_MODE" == "compose" ]]; then
        echo -e "${GREEN}Application URL:${NC} http://localhost:${HOST_PORT:-3000}"
        echo -e "${GREEN}Health Check:${NC} http://localhost:${HOST_PORT:-3000}/health"
        echo -e "${GREEN}Metrics:${NC} http://localhost:${METRICS_PORT:-9090}/metrics"
        echo -e "${GREEN}Prometheus:${NC} http://localhost:${PROMETHEUS_PORT:-9091}"
        
        echo -e "\n${BLUE}Useful Commands:${NC}"
        echo "  View logs:    docker-compose -f docker-compose.prod.yml logs -f"
        echo "  Stop services: docker-compose -f docker-compose.prod.yml down"
        echo "  Restart:      docker-compose -f docker-compose.prod.yml restart"
        
    else
        echo -e "${GREEN}Namespace:${NC} make-fastmcp"
        echo -e "${GREEN}Service:${NC} make-fastmcp-server"
        
        echo -e "\n${BLUE}Useful Commands:${NC}"
        echo "  View pods:    kubectl get pods -n make-fastmcp"
        echo "  View logs:    kubectl logs -l app=make-fastmcp-server -n make-fastmcp -f"
        echo "  Port forward: kubectl port-forward -n make-fastmcp service/make-fastmcp-server 3000:3000"
        echo "  Scale:        kubectl scale deployment make-fastmcp-server --replicas=5 -n make-fastmcp"
    fi
    
    echo -e "\n${GREEN}Deployment completed successfully!${NC}"
}

# ==============================================================================
# Main Deployment Logic
# ==============================================================================

show_usage() {
    cat << EOF
Usage: $0 [OPTIONS] DEPLOYMENT_MODE

Deploy Make.com FastMCP Server to production environment.

DEPLOYMENT_MODE:
  compose     Deploy using Docker Compose
  kubernetes  Deploy to Kubernetes cluster

OPTIONS:
  -h, --help              Show this help message
  -v, --version VERSION   Set image version (default: production)
  -i, --image IMAGE       Set Docker image name (default: make-fastmcp-server)
  --skip-build           Skip application build step
  --skip-tests           Skip test execution
  --tag-latest           Tag Docker image as latest
  --dry-run              Show what would be done without executing

EXAMPLES:
  # Deploy with Docker Compose
  $0 compose

  # Deploy to Kubernetes with custom version
  $0 --version v1.2.3 kubernetes

  # Deploy with custom image name and skip tests
  $0 --image my-registry/fastmcp --skip-tests compose

ENVIRONMENT VARIABLES:
  MAKE_API_KEY           Make.com API key (required)
  AUTH_SECRET            JWT authentication secret (required)
  REDIS_PASSWORD         Redis password (optional)
  HOST_PORT              Host port for Docker Compose (default: 3000)
  METRICS_PORT           Metrics port (default: 9090)
  PROMETHEUS_PORT        Prometheus port (default: 9091)

EOF
}

main() {
    # Default values
    local deployment_mode=""
    local skip_build=false
    local skip_tests=false
    local dry_run=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -v|--version)
                export IMAGE_VERSION="$2"
                shift 2
                ;;
            -i|--image)
                export DOCKER_IMAGE="$2"
                shift 2
                ;;
            --skip-build)
                skip_build=true
                shift
                ;;
            --skip-tests)
                skip_tests=true
                shift
                ;;
            --tag-latest)
                export TAG_LATEST=true
                shift
                ;;
            --dry-run)
                dry_run=true
                shift
                ;;
            compose|kubernetes)
                deployment_mode="$1"
                shift
                ;;
            *)
                log ERROR "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Validate deployment mode
    if [[ -z "$deployment_mode" ]]; then
        log ERROR "Deployment mode is required"
        show_usage
        exit 1
    fi
    
    export DEPLOYMENT_MODE="$deployment_mode"
    
    # Create logs directory
    mkdir -p "$(dirname "$LOG_FILE")"
    
    log INFO "Starting production deployment..."
    log INFO "Deployment mode: $deployment_mode"
    log INFO "Image version: ${IMAGE_VERSION:-production}"
    
    if [[ "$dry_run" == "true" ]]; then
        log INFO "DRY RUN MODE - No actual deployment will be performed"
        return 0
    fi
    
    # Execute deployment steps
    check_prerequisites
    validate_environment
    
    if [[ "$skip_build" != "true" ]]; then
        build_application
        build_docker_image
    else
        log INFO "Skipping build steps as requested"
    fi
    
    case "$deployment_mode" in
        compose)
            deploy_docker_compose
            ;;
        kubernetes)
            deploy_kubernetes
            ;;
    esac
    
    verify_deployment
    show_deployment_info
    
    log INFO "Production deployment completed successfully!"
}

# Run main function with all arguments
main "$@"