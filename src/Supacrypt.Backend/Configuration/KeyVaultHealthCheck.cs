using Azure;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Polly.CircuitBreaker;
using Supacrypt.Backend.Services.Azure;

namespace Supacrypt.Backend.Configuration;

public class KeyVaultHealthCheck : IHealthCheck
{
    private readonly IAzureKeyVaultClientFactory _clientFactory;
    private readonly IAzureKeyVaultResiliencePolicy _resiliencePolicy;
    private readonly ILogger<KeyVaultHealthCheck> _logger;

    public KeyVaultHealthCheck(
        IAzureKeyVaultClientFactory clientFactory,
        IAzureKeyVaultResiliencePolicy resiliencePolicy,
        ILogger<KeyVaultHealthCheck> logger)
    {
        _clientFactory = clientFactory;
        _resiliencePolicy = resiliencePolicy;
        _logger = logger;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(30));

            _logger.LogDebug("Starting Azure Key Vault health check");

            var client = _clientFactory.CreateKeyClient();
            var pipeline = _resiliencePolicy.GetPipeline<object>();

            // Test connectivity by listing keys (this requires minimal permissions)
            await pipeline.ExecuteAsync(async (ct) =>
            {
                var properties = client.GetPropertiesOfKeysAsync(cancellationToken: ct);
                await properties.AsPages().FirstAsync(cancellationToken: ct);
                return Task.FromResult<object?>(null);
            }, timeoutCts.Token);

            _logger.LogDebug("Azure Key Vault health check completed successfully");
            
            var data = new Dictionary<string, object>
            {
                ["vault_uri"] = client.VaultUri.ToString(),
                ["timestamp"] = DateTimeOffset.UtcNow
            };

            return HealthCheckResult.Healthy("Azure Key Vault is accessible and responsive", data);
        }
        catch (BrokenCircuitException ex)
        {
            _logger.LogWarning("Azure Key Vault health check failed due to circuit breaker: {Message}", ex.Message);
            
            var data = new Dictionary<string, object>
            {
                ["circuit_breaker_state"] = "Open",
                ["timestamp"] = DateTimeOffset.UtcNow
            };

            return HealthCheckResult.Degraded("Azure Key Vault circuit breaker is open", ex, data);
        }
        catch (RequestFailedException ex) when (ex.Status == 401 || ex.Status == 403)
        {
            _logger.LogError("Azure Key Vault health check failed due to authentication/authorization: {Message}", ex.Message);
            
            var data = new Dictionary<string, object>
            {
                ["error_code"] = ex.Status,
                ["azure_error_code"] = ex.ErrorCode ?? "Unknown",
                ["timestamp"] = DateTimeOffset.UtcNow
            };

            return HealthCheckResult.Unhealthy("Azure Key Vault authentication/authorization failed", ex, data);
        }
        catch (RequestFailedException ex) when (ex.Status >= 500)
        {
            _logger.LogWarning("Azure Key Vault health check failed due to server error: {Message}", ex.Message);
            
            var data = new Dictionary<string, object>
            {
                ["error_code"] = ex.Status,
                ["azure_error_code"] = ex.ErrorCode ?? "Unknown",
                ["timestamp"] = DateTimeOffset.UtcNow
            };

            return HealthCheckResult.Degraded("Azure Key Vault server error", ex, data);
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Azure Key Vault health check timed out");
            
            var data = new Dictionary<string, object>
            {
                ["timeout"] = true,
                ["timestamp"] = DateTimeOffset.UtcNow
            };

            return HealthCheckResult.Degraded("Azure Key Vault health check timed out", data: data);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Azure Key Vault health check failed unexpectedly");
            
            var data = new Dictionary<string, object>
            {
                ["error_type"] = ex.GetType().Name,
                ["timestamp"] = DateTimeOffset.UtcNow
            };

            return HealthCheckResult.Unhealthy("Azure Key Vault is not accessible", ex, data);
        }
    }
}