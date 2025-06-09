# Supacrypt Backend Service Integration Tests

## Backend-Specific Integration Tests

This directory contains integration tests specific to the Supacrypt backend service:

- **[Test Orchestrator](test-orchestrator/)** - Python-based test coordination service for backend testing

## Cross-Component Integration Tests

For comprehensive integration tests that span multiple components, see:
- `supacrypt-common/integration-test-environment/` - Cross-component integration testing infrastructure

## Test Categories

### Backend Service Tests
- gRPC API endpoint testing
- Azure Key Vault integration testing
- Authentication and authorization testing
- Performance and load testing
- Security validation testing

### Integration with Other Components
- Provider communication testing
- Cross-platform compatibility testing
- End-to-end workflow testing

## Running Tests

### Backend-Specific Tests
```bash
cd test-orchestrator/
python orchestrator.py
```

### Cross-Component Tests
```bash
cd ../../supacrypt-common/integration-test-environment/
./scripts/quick-start.sh
./scripts/run-integration-tests.sh
```

## Documentation

- **Test Plans**: `supracrypt-common/integration-test-environment/test-plans/`
- **API Documentation**: `supacrypt-common/documentation/api/`
- **Architecture**: `supacrypt-common/documentation/architecture/`