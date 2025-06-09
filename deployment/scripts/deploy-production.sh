#!/bin/bash

# Supacrypt Production Deployment Script
# This script automates the deployment of Supacrypt backend service to Kubernetes

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOYMENT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Configuration
NAMESPACE="supacrypt"
DEPLOYMENT_NAME="supacrypt-backend"
DOCKER_IMAGE="supacrypt/backend:1.0.0"

# Azure configuration (to be set via environment variables)
AZURE_KEY_VAULT_URL="${AZURE_KEY_VAULT_URL:-}"
AZURE_TENANT_ID="${AZURE_TENANT_ID:-}"
AZURE_CLIENT_ID="${AZURE_CLIENT_ID:-}"
AZURE_SUBSCRIPTION_ID="${AZURE_SUBSCRIPTION_ID:-}"

# Kubernetes configuration
KUBECTL_CONTEXT="${KUBECTL_CONTEXT:-}"
ENVIRONMENT="${ENVIRONMENT:-production}"

# Check prerequisites
check_prerequisites() {
    log_info "Checking deployment prerequisites..."
    
    # Check kubectl
    if ! command -v kubectl >/dev/null 2>&1; then
        log_error "kubectl is required but not installed"
        exit 1
    fi
    
    # Check Azure CLI
    if ! command -v az >/dev/null 2>&1; then
        log_error "Azure CLI is required but not installed"
        exit 1
    fi
    
    # Check Docker
    if ! command -v docker >/dev/null 2>&1; then
        log_error "Docker is required but not installed"
        exit 1
    fi
    
    # Check required environment variables
    if [[ -z "$AZURE_KEY_VAULT_URL" ]]; then
        log_error "AZURE_KEY_VAULT_URL environment variable is required"
        exit 1
    fi
    
    if [[ -z "$AZURE_TENANT_ID" ]]; then
        log_error "AZURE_TENANT_ID environment variable is required"
        exit 1
    fi
    
    if [[ -z "$AZURE_CLIENT_ID" ]]; then
        log_error "AZURE_CLIENT_ID environment variable is required"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Set kubectl context
set_kubectl_context() {
    if [[ -n "$KUBECTL_CONTEXT" ]]; then
        log_info "Setting kubectl context to: $KUBECTL_CONTEXT"
        kubectl config use-context "$KUBECTL_CONTEXT"
    fi
    
    # Verify cluster connectivity
    if ! kubectl cluster-info >/dev/null 2>&1; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log_success "Kubernetes cluster connectivity verified"
}

# Validate Azure connectivity
validate_azure_connectivity() {
    log_info "Validating Azure connectivity..."
    
    # Check Azure login
    if ! az account show >/dev/null 2>&1; then
        log_info "Azure login required..."
        az login
    fi
    
    # Set subscription if provided
    if [[ -n "$AZURE_SUBSCRIPTION_ID" ]]; then
        az account set --subscription "$AZURE_SUBSCRIPTION_ID"
    fi
    
    # Verify Key Vault access
    VAULT_NAME=$(echo "$AZURE_KEY_VAULT_URL" | sed 's|https://||' | sed 's|\.vault\.azure\.net/||')
    if az keyvault show --name "$VAULT_NAME" >/dev/null 2>&1; then
        log_success "Azure Key Vault access verified"
    else
        log_error "Cannot access Azure Key Vault: $VAULT_NAME"
        exit 1
    fi
}

# Build and push Docker image (if needed)
build_and_push_image() {
    log_info "Checking Docker image availability..."
    
    # Check if image exists locally or in registry
    if docker pull "$DOCKER_IMAGE" >/dev/null 2>&1; then
        log_success "Docker image $DOCKER_IMAGE is available"
        return
    fi
    
    log_warning "Docker image not found, building from source..."
    
    # Build image from backend source
    BACKEND_DIR="$DEPLOYMENT_DIR/../supacrypt-backend-akv"
    if [[ -f "$BACKEND_DIR/Dockerfile" ]]; then
        log_info "Building Docker image from source..."
        cd "$BACKEND_DIR"
        docker build -t "$DOCKER_IMAGE" .
        
        # Push to registry if configured
        if [[ -n "$DOCKER_REGISTRY" ]]; then
            log_info "Pushing image to registry..."
            docker tag "$DOCKER_IMAGE" "$DOCKER_REGISTRY/$DOCKER_IMAGE"
            docker push "$DOCKER_REGISTRY/$DOCKER_IMAGE"
        fi
        
        log_success "Docker image built successfully"
    else
        log_error "Backend source not found at $BACKEND_DIR"
        exit 1
    fi
}

# Generate TLS certificates for development
generate_dev_certificates() {
    log_info "Generating development TLS certificates..."
    
    CERT_DIR="$DEPLOYMENT_DIR/certs"
    mkdir -p "$CERT_DIR"
    
    # Generate self-signed certificate for development
    openssl req -x509 -newkey rsa:4096 -keyout "$CERT_DIR/tls.key" -out "$CERT_DIR/tls.crt" \
        -days 365 -nodes -subj "/CN=supacrypt-backend.supacrypt.svc.cluster.local" \
        -addext "subjectAltName=DNS:supacrypt-backend.supacrypt.svc.cluster.local,DNS:localhost"
    
    log_success "Development certificates generated"
}

# Create Kubernetes secrets
create_secrets() {
    log_info "Creating Kubernetes secrets..."
    
    # Create namespace if it doesn't exist
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # Create Azure credentials secret
    kubectl create secret generic supacrypt-secrets \
        --namespace="$NAMESPACE" \
        --from-literal=azure-key-vault-url="$AZURE_KEY_VAULT_URL" \
        --from-literal=azure-tenant-id="$AZURE_TENANT_ID" \
        --from-literal=azure-client-id="$AZURE_CLIENT_ID" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    # Create TLS secret
    if [[ -f "$DEPLOYMENT_DIR/certs/tls.crt" && -f "$DEPLOYMENT_DIR/certs/tls.key" ]]; then
        kubectl create secret tls supacrypt-tls \
            --namespace="$NAMESPACE" \
            --cert="$DEPLOYMENT_DIR/certs/tls.crt" \
            --key="$DEPLOYMENT_DIR/certs/tls.key" \
            --dry-run=client -o yaml | kubectl apply -f -
    else
        log_warning "TLS certificates not found, generating development certificates..."
        generate_dev_certificates
        kubectl create secret tls supacrypt-tls \
            --namespace="$NAMESPACE" \
            --cert="$DEPLOYMENT_DIR/certs/tls.crt" \
            --key="$DEPLOYMENT_DIR/certs/tls.key" \
            --dry-run=client -o yaml | kubectl apply -f -
    fi
    
    log_success "Kubernetes secrets created"
}

# Deploy application
deploy_application() {
    log_info "Deploying Supacrypt backend service..."
    
    # Update deployment manifest with current image
    MANIFEST_FILE="$DEPLOYMENT_DIR/kubernetes/production-deployment.yaml"
    TEMP_MANIFEST="/tmp/supacrypt-deployment.yaml"
    
    # Replace placeholders in manifest
    sed -e "s|\${AZURE_KEY_VAULT_URL}|$AZURE_KEY_VAULT_URL|g" \
        -e "s|\${AZURE_TENANT_ID}|$AZURE_TENANT_ID|g" \
        -e "s|\${AZURE_CLIENT_ID}|$AZURE_CLIENT_ID|g" \
        -e "s|image: supacrypt/backend:1.0.0|image: $DOCKER_IMAGE|g" \
        "$MANIFEST_FILE" > "$TEMP_MANIFEST"
    
    # Apply the deployment
    kubectl apply -f "$TEMP_MANIFEST"
    
    # Clean up temporary file
    rm "$TEMP_MANIFEST"
    
    log_success "Deployment manifest applied"
}

# Wait for deployment to be ready
wait_for_deployment() {
    log_info "Waiting for deployment to be ready..."
    
    # Wait for deployment to be available
    kubectl rollout status deployment/"$DEPLOYMENT_NAME" --namespace="$NAMESPACE" --timeout=300s
    
    # Wait for pods to be ready
    kubectl wait --for=condition=ready pod -l app="$DEPLOYMENT_NAME" --namespace="$NAMESPACE" --timeout=300s
    
    log_success "Deployment is ready"
}

# Verify deployment
verify_deployment() {
    log_info "Verifying deployment..."
    
    # Check pod status
    kubectl get pods -n "$NAMESPACE" -l app="$DEPLOYMENT_NAME"
    
    # Check service status
    kubectl get services -n "$NAMESPACE"
    
    # Get service endpoint
    SERVICE_IP=$(kubectl get service supacrypt-backend-service -n "$NAMESPACE" -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    if [[ -n "$SERVICE_IP" ]]; then
        log_info "Service endpoint: $SERVICE_IP"
    else
        log_warning "Service endpoint not yet available (LoadBalancer provisioning may take time)"
    fi
    
    # Test health endpoint
    log_info "Testing health endpoint..."
    if kubectl port-forward service/supacrypt-backend-service 8080:80 -n "$NAMESPACE" &
    then
        PORT_FORWARD_PID=$!
        sleep 5
        
        if curl -f http://localhost:8080/health >/dev/null 2>&1; then
            log_success "Health endpoint is responding"
        else
            log_warning "Health endpoint not responding (service may still be starting)"
        fi
        
        kill $PORT_FORWARD_PID 2>/dev/null || true
    fi
    
    log_success "Deployment verification completed"
}

# Setup monitoring (if Prometheus is available)
setup_monitoring() {
    log_info "Setting up monitoring..."
    
    # Check if Prometheus operator is available
    if kubectl get crd servicemonitors.monitoring.coreos.com >/dev/null 2>&1; then
        log_info "Prometheus operator detected, ServiceMonitor will be created"
        # ServiceMonitor is already included in the deployment manifest
        log_success "Monitoring setup completed"
    else
        log_warning "Prometheus operator not found, skipping ServiceMonitor creation"
    fi
}

# Display deployment information
display_deployment_info() {
    echo ""
    echo "🎉 Supacrypt Backend Service Deployment Completed!"
    echo "=================================================="
    echo ""
    echo "Deployment Information:"
    echo "  Namespace: $NAMESPACE"
    echo "  Deployment: $DEPLOYMENT_NAME"
    echo "  Image: $DOCKER_IMAGE"
    echo "  Environment: $ENVIRONMENT"
    echo ""
    echo "Service Information:"
    kubectl get service supacrypt-backend-service -n "$NAMESPACE" -o wide
    echo ""
    echo "Pod Status:"
    kubectl get pods -n "$NAMESPACE" -l app="$DEPLOYMENT_NAME"
    echo ""
    echo "Next Steps:"
    echo "  1. Configure your cryptographic providers to connect to this backend"
    echo "  2. Set up monitoring and alerting"
    echo "  3. Configure load balancing and DNS"
    echo "  4. Deploy client certificates for authentication"
    echo ""
    echo "Useful Commands:"
    echo "  View logs: kubectl logs -f deployment/$DEPLOYMENT_NAME -n $NAMESPACE"
    echo "  Port forward: kubectl port-forward service/supacrypt-backend-service 5051:5051 -n $NAMESPACE"
    echo "  Scale deployment: kubectl scale deployment $DEPLOYMENT_NAME --replicas=5 -n $NAMESPACE"
    echo ""
}

# Cleanup function
cleanup() {
    if [[ -n "${PORT_FORWARD_PID:-}" ]]; then
        kill "$PORT_FORWARD_PID" 2>/dev/null || true
    fi
}

# Set trap for cleanup
trap cleanup EXIT

# Main execution
main() {
    echo "🚀 Starting Supacrypt Production Deployment"
    echo "==========================================="
    
    check_prerequisites
    set_kubectl_context
    validate_azure_connectivity
    build_and_push_image
    create_secrets
    deploy_application
    wait_for_deployment
    verify_deployment
    setup_monitoring
    display_deployment_info
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        --image)
            DOCKER_IMAGE="$2"
            shift 2
            ;;
        --context)
            KUBECTL_CONTEXT="$2"
            shift 2
            ;;
        --environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --namespace NAMESPACE    Kubernetes namespace (default: supacrypt)"
            echo "  --image IMAGE           Docker image to deploy (default: supacrypt/backend:1.0.0)"
            echo "  --context CONTEXT       Kubectl context to use"
            echo "  --environment ENV       Environment name (default: production)"
            echo "  --help                  Show this help message"
            echo ""
            echo "Required Environment Variables:"
            echo "  AZURE_KEY_VAULT_URL     Azure Key Vault URL"
            echo "  AZURE_TENANT_ID         Azure Tenant ID"
            echo "  AZURE_CLIENT_ID         Azure Client ID"
            echo ""
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run main function
main "$@"