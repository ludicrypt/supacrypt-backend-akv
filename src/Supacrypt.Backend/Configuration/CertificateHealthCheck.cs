using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Supacrypt.Backend.Services.Security;

namespace Supacrypt.Backend.Configuration;

public class CertificateHealthCheck : IHealthCheck
{
    private readonly ICertificateLoader _certificateLoader;
    private readonly SecurityOptions _options;
    private readonly ILogger<CertificateHealthCheck> _logger;

    public CertificateHealthCheck(
        ICertificateLoader certificateLoader,
        IOptions<SecurityOptions> options,
        ILogger<CertificateHealthCheck> logger)
    {
        _certificateLoader = certificateLoader;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var data = new Dictionary<string, object>
            {
                ["MtlsEnabled"] = _options.Mtls.Enabled,
                ["RequireClientCertificate"] = _options.Mtls.RequireClientCertificate
            };

            // Only check server certificate if mTLS is enabled and server certificate is configured
            if (_options.Mtls.Enabled && !string.IsNullOrEmpty(_options.ServerCertificate.Source))
            {
                try
                {
                    // Check server certificate
                    var serverCert = await _certificateLoader.LoadServerCertificateAsync(_options.ServerCertificate);
                    
                    data["ServerCertificateSubject"] = serverCert.Subject;
                    data["ServerCertificateExpiry"] = serverCert.NotAfter;
                    data["DaysUntilExpiry"] = (serverCert.NotAfter - DateTime.UtcNow).Days;

                    var daysUntilExpiry = (serverCert.NotAfter - DateTime.UtcNow).Days;

                    if (daysUntilExpiry < 0)
                    {
                        return HealthCheckResult.Unhealthy("Server certificate has expired", data: data);
                    }

                    if (daysUntilExpiry < 30)
                    {
                        return HealthCheckResult.Degraded("Server certificate expiring soon", data: data);
                    }

                    data["CertificateValidationStatus"] = "Healthy";
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to load server certificate during health check");
                    data["CertificateValidationStatus"] = "Failed";
                    data["CertificateError"] = ex.Message;
                    return HealthCheckResult.Unhealthy("Failed to load server certificate", ex, data);
                }
            }
            else
            {
                data["CertificateValidationStatus"] = "Not configured or mTLS disabled";
            }

            return HealthCheckResult.Healthy("Certificate configuration is healthy", data: data);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception during certificate health check");
            return HealthCheckResult.Unhealthy("Certificate health check failed", ex);
        }
    }
}