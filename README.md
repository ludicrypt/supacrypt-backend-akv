# Supacrypt Backend - Azure Key Vault

## Overview

A high-performance gRPC backend service built with .NET 9 and .NET Aspire 9.3 that provides cryptographic operations through Azure Key Vault integration. This component serves as the central cryptographic engine for the Supacrypt suite, offering secure key management and cryptographic primitives.

## Features

- gRPC API for cryptographic operations based on the Supacrypt protocol
- Azure Key Vault integration for secure key storage and operations
- .NET Aspire 9.3 integration for observability and service discovery
- High-performance async operations with cancellation support
- Comprehensive logging and OpenTelemetry observability
- Enterprise-grade security controls including mTLS support
- Health checks for service monitoring
- Configuration-driven Azure authentication

## Requirements

- .NET 9.0 SDK (version 9.0.100 or later)
- Azure subscription with Key Vault access
- Azure CLI for local development authentication
- Docker (optional, for containerized development)

## Project Structure

```
supacrypt-backend-akv/
├── src/
│   ├── Supacrypt.Backend/              # Main gRPC service
│   │   ├── Configuration/              # Configuration models and options
│   │   ├── Extensions/                 # Service registration extensions
│   │   ├── Protos/                     # Protocol buffer definitions
│   │   └── Services/                   # gRPC service implementations
│   └── Supacrypt.Backend.AppHost/      # .NET Aspire app host
├── tests/
│   ├── Supacrypt.Backend.Tests/        # Unit tests
│   └── Supacrypt.Backend.IntegrationTests/ # Integration tests
├── Directory.Build.props               # Common build properties
├── Directory.Packages.props            # Central package management
├── global.json                         # .NET SDK version pinning
└── Supacrypt.Backend.sln              # Solution file
```

## Building

### Prerequisites

Ensure you have the required .NET SDK version:

```bash
dotnet --version  # Should be 9.0.100 or later
```

### Build the solution

```bash
# Restore packages
dotnet restore

# Build the solution
dotnet build

# Build in Release mode
dotnet build -c Release
```

### Run the service

```bash
# Run the main service
dotnet run --project src/Supacrypt.Backend

# Or run with Aspire AppHost for full observability
dotnet run --project src/Supacrypt.Backend.AppHost
```

## Configuration

### Required Configuration

The service requires Azure Key Vault configuration. Set these in `appsettings.json` or environment variables:

```json
{
  "AzureKeyVault": {
    "VaultUri": "https://your-keyvault.vault.azure.net/",
    "ClientId": "your-client-id",
    "TenantId": "your-tenant-id"
  }
}
```

### Environment Variables

```bash
# Azure Key Vault
export AzureKeyVault__VaultUri="https://your-keyvault.vault.azure.net/"
export AzureKeyVault__ClientId="your-client-id"
export AzureKeyVault__TenantId="your-tenant-id"

# Optional: Client Secret (use Azure CLI or Managed Identity when possible)
export AzureKeyVault__ClientSecret="your-client-secret"
```

### Development Setup

For local development, authenticate with Azure CLI:

```bash
az login
az account set --subscription your-subscription-id
```

The service will use Azure CLI credentials automatically when no client secret is configured.

## Testing

### Unit Tests

```bash
# Run unit tests
dotnet test tests/Supacrypt.Backend.Tests

# Run with coverage
dotnet test tests/Supacrypt.Backend.Tests --collect:"XPlat Code Coverage"
```

### Integration Tests

```bash
# Run integration tests (requires Azure Key Vault access)
dotnet test tests/Supacrypt.Backend.IntegrationTests

# Run all tests
dotnet test
```

### Test Requirements

Integration tests require:
- Valid Azure Key Vault configuration
- Azure authentication (CLI or service principal)
- Key Vault permissions for key operations

## Development

### Adding New gRPC Services

1. Update the protobuf definition in `src/Supacrypt.Backend/Protos/supacrypt.proto`
2. Rebuild to generate new gRPC stubs
3. Implement the service in `src/Supacrypt.Backend/Services/`
4. Register the service in `Program.cs`

### Configuration Options

New configuration options should:
- Follow the options pattern with validation
- Be documented in the configuration classes
- Include appropriate data annotations
- Be registered in `ServiceCollectionExtensions.cs`

### Health Checks

Health checks are available at `/health` and include:
- Cryptographic service health
- Azure Key Vault connectivity
- Overall service health

## Deployment

### Docker

```bash
# Build Docker image
docker build -t supacrypt-backend .

# Run container
docker run -p 7000:8080 -p 7001:8081 \
  -e AzureKeyVault__VaultUri="https://your-keyvault.vault.azure.net/" \
  -e AzureKeyVault__ClientId="your-client-id" \
  -e AzureKeyVault__TenantId="your-tenant-id" \
  supacrypt-backend
```

### Azure Container Apps

The service is designed for deployment to Azure Container Apps with:
- Managed Identity for Azure Key Vault access
- OpenTelemetry integration for Application Insights
- Health check integration for container orchestration

## Observability

The service includes comprehensive observability through:
- **Logging**: Structured logging with Serilog
- **Metrics**: Performance counters and custom metrics
- **Tracing**: Distributed tracing with OpenTelemetry
- **Health Checks**: Service and dependency health monitoring

### Accessing Metrics

When running with Aspire AppHost:
- Dashboard: http://localhost:15888
- Metrics: OpenTelemetry Protocol (OTLP) endpoint
- Logs: Centralized logging through Aspire

## Security

### mTLS Configuration

For production deployments, enable mutual TLS:

```json
{
  "Security": {
    "mTLS": {
      "Enabled": true,
      "RequireClientCertificate": true,
      "ValidationMode": "ChainTrust",
      "AllowedThumbprints": ["cert-thumbprint-1", "cert-thumbprint-2"]
    }
  }
}
```

### Azure Key Vault Permissions

Required Azure Key Vault permissions:
- **Keys**: Get, List, Create, Delete, Sign, Verify, Encrypt, Decrypt
- **Secrets**: Get, List (if using secrets for configuration)

## Contributing

1. Follow the C# coding standards in `../supacrypt-common/docs/standards/csharp-coding-standards.md`
2. Add appropriate unit and integration tests
3. Update documentation for new features
4. Ensure all health checks pass
5. Validate configuration options with data annotations

## License

MIT License - See [LICENSE](LICENSE) for details