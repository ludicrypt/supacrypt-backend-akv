using Supacrypt.Backend.Services.Security.Interfaces;

namespace Supacrypt.Backend.Services.Security;

public class SecurityEventLogger : ISecurityEventLogger
{
    private readonly ILogger<SecurityEventLogger> _logger;

    public SecurityEventLogger(ILogger<SecurityEventLogger> logger)
    {
        _logger = logger;
    }

    public void LogCertificateValidationSuccess(CertificateValidationResult result)
    {
        _logger.LogInformation("SECURITY_EVENT: Certificate validation successful. " +
            "Subject: {Subject}, Thumbprint: {Thumbprint}, Claims: {@Claims}",
            result.Subject, result.Thumbprint, result.Claims);
    }

    public void LogCertificateValidationFailure(CertificateValidationResult result)
    {
        _logger.LogWarning("SECURITY_EVENT: Certificate validation failed. " +
            "Subject: {Subject}, Thumbprint: {Thumbprint}, Errors: {Errors}",
            result.Subject, result.Thumbprint, string.Join("; ", result.Errors));
    }

    public void LogUnauthorizedAccess(string? thumbprint, string operation)
    {
        _logger.LogWarning("SECURITY_EVENT: Unauthorized access attempt. " +
            "Thumbprint: {Thumbprint}, Operation: {Operation}",
            thumbprint ?? "Unknown", operation);
    }

    public void LogSecurityConfigurationChange(string setting, string oldValue, string newValue)
    {
        _logger.LogInformation("SECURITY_EVENT: Security configuration changed. " +
            "Setting: {Setting}, OldValue: {OldValue}, NewValue: {NewValue}",
            setting, oldValue, newValue);
    }
}