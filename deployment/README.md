# Supacrypt Backend Deployment Guide

This guide covers containerization and deployment of the Supacrypt Backend service across multiple environments.

## Quick Start

### Prerequisites
- Docker and Docker Compose
- .NET 9.0 SDK (for local development)
- kubectl (for Kubernetes deployment)
- Azure CLI (for Azure deployment)

### Local Development
```bash
# Build and run in development mode
make run-dev

# Check health
make health-check

# View logs
make logs
```

## Container Architecture

### Multi-Stage Build
The production Dockerfile uses a multi-stage build process:
1. **Build Stage**: Uses `mcr.microsoft.com/dotnet/sdk:9.0-alpine` to compile the application
2. **Runtime Stage**: Uses `mcr.microsoft.com/dotnet/aspnet:9.0-alpine` for minimal runtime footprint

### Security Features
- Non-root user execution (UID 1000)
- Read-only root filesystem support
- Minimal Alpine Linux base image
- No unnecessary packages or tools
- Security scanning with Trivy

### Image Optimization
- Multi-stage builds exclude build dependencies
- .dockerignore minimizes build context
- Alpine Linux for smaller image size
- Optimized layer caching

## Deployment Options

### 1. Docker Compose (Local Development)

#### Standard Mode
```bash
docker-compose up -d
```

#### Development Mode (with file watching)
```bash
docker-compose -f docker-compose.yml -f docker-compose.override.yml up
```

### 2. Kubernetes

#### Deploy
```bash
# Apply all manifests
kubectl apply -k deployment/k8s/

# Or use Makefile
make k8s-deploy
```

#### Configuration
- **Namespace**: `supacrypt`
- **Replicas**: 3 (configurable)
- **Resources**: 256Mi-512Mi memory, 250m-500m CPU
- **Security**: Non-root, read-only filesystem, dropped capabilities

#### Required Secrets
```bash
# Create the vault URI secret
kubectl create secret generic azure-keyvault-config \
  --from-literal=vault-uri="https://your-vault.vault.azure.net/" \
  -n supacrypt

# Create TLS certificate secret (if using mTLS)
kubectl create secret tls supacrypt-tls \
  --cert=path/to/cert.pem \
  --key=path/to/key.pem \
  -n supacrypt
```

### 3. Azure Container Apps

#### Deploy with Bicep
```bash
# Deploy using Azure CLI
az deployment group create \
  --resource-group supacrypt-rg \
  --template-file deployment/azure/main.bicep \
  --parameters @deployment/azure/parameters.json

# Or use Makefile
make azure-deploy
```

#### Features
- **Managed Identity**: Automatic Azure service authentication
- **Auto-scaling**: CPU/memory/HTTP-based scaling rules
- **Health Checks**: Liveness and readiness probes
- **Security**: RBAC integration with Key Vault and Container Registry

## Environment Configuration

### Required Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `AzureKeyVault__VaultUri` | Azure Key Vault URI | Yes |
| `AzureKeyVault__UseManagedIdentity` | Use managed identity for auth | Yes |
| `Security__Mtls__Enabled` | Enable mutual TLS | No |
| `Security__Mtls__RequireClientCertificate` | Require client certificates | No |
| `Observability__Exporters__Otlp__Endpoint` | OpenTelemetry endpoint | No |

### Configuration Sources
1. appsettings.json (embedded)
2. appsettings.{Environment}.json (embedded)
3. Environment variables (runtime)
4. Azure Key Vault (production)
5. User Secrets (development)

## Monitoring and Observability

### Health Checks
- **Liveness**: `/health` - Basic application health
- **Readiness**: `/health/ready` - Application ready to serve requests

### Metrics
- Prometheus metrics exposed at `/metrics`
- OpenTelemetry traces and metrics
- Custom cryptographic operation metrics

### Logging
- Structured logging with Serilog
- JSON format for production
- Console output for development

## Security Considerations

### Container Security
- Non-root user (UID 1000)
- Read-only root filesystem
- Dropped Linux capabilities
- No shell access in production image
- Regular security scanning

### Network Security
- Internal service communication
- mTLS support for client authentication
- Certificate-based authentication
- Network policies in Kubernetes

### Secrets Management
- No secrets in container images
- Azure Key Vault integration
- Kubernetes secrets for configuration
- Managed identity for Azure authentication

## Troubleshooting

### Common Issues

#### Container Won't Start
```bash
# Check logs
docker logs supacrypt-backend

# Or with compose
docker-compose logs supacrypt-backend
```

#### Health Check Failures
```bash
# Manual health check
curl http://localhost:5000/health

# Check container health
docker inspect --format='{{.State.Health.Status}}' supacrypt-backend
```

#### Azure Key Vault Access Issues
- Verify managed identity is assigned
- Check RBAC permissions on Key Vault
- Validate vault URI configuration

### Performance Tuning

#### Resource Limits
Adjust based on workload:
```yaml
resources:
  requests:
    memory: "256Mi"
    cpu: "250m"
  limits:
    memory: "512Mi"
    cpu: "500m"
```

#### Scaling Configuration
- **Horizontal Pod Autoscaler**: Based on CPU/memory utilization
- **Vertical Pod Autoscaler**: Automatic resource right-sizing
- **Container Apps Scaling**: HTTP request-based scaling

## Maintenance

### Updates
1. Build new container image
2. Update image tag in deployment manifests
3. Apply updated manifests
4. Monitor rollout progress

### Backup Considerations
- Cryptographic keys are stored in Azure Key Vault
- Application state is stateless
- Configuration backed up with infrastructure as code

### Monitoring Checklist
- [ ] Container health checks passing
- [ ] Metrics being collected
- [ ] Logs being aggregated
- [ ] Security scans clean
- [ ] Performance within SLA

## Support

For issues with containerization or deployment:
1. Check container logs
2. Verify configuration
3. Test health endpoints
4. Review security settings
5. Consult troubleshooting section