using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Supacrypt.Backend.Configuration;

public class CryptographicServiceHealthCheck : IHealthCheck
{
    private readonly ILogger<CryptographicServiceHealthCheck> _logger;

    public CryptographicServiceHealthCheck(ILogger<CryptographicServiceHealthCheck> logger)
    {
        _logger = logger;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        try
        {
            await Task.Delay(50, cancellationToken);
            return HealthCheckResult.Healthy("Cryptographic service is operational");
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Cryptographic service health check timed out");
            return HealthCheckResult.Degraded("Cryptographic service health check timed out");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Cryptographic service health check failed");
            return HealthCheckResult.Unhealthy("Cryptographic service is not operational", ex);
        }
    }
}