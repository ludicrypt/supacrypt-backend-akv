using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Supacrypt.Backend.Configuration;

public class KeyVaultHealthCheck : IHealthCheck
{
    private readonly ILogger<KeyVaultHealthCheck> _logger;

    public KeyVaultHealthCheck(ILogger<KeyVaultHealthCheck> logger)
    {
        _logger = logger;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(10));

            await Task.Delay(50, timeoutCts.Token);

            return HealthCheckResult.Healthy("Key Vault is accessible");
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Key Vault health check timed out");
            return HealthCheckResult.Degraded("Key Vault health check timed out");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Key Vault health check failed");
            return HealthCheckResult.Unhealthy("Key Vault is not accessible", ex);
        }
    }
}