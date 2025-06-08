namespace Supacrypt.Backend.Services.Security.Interfaces;

public interface ISecurityEventLogger
{
    void LogCertificateValidationSuccess(CertificateValidationResult result);
    void LogCertificateValidationFailure(CertificateValidationResult result);
    void LogUnauthorizedAccess(string? thumbprint, string operation);
    void LogSecurityConfigurationChange(string setting, string oldValue, string newValue);
}