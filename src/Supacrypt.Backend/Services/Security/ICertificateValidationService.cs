using System.Security.Cryptography.X509Certificates;
using System.Net.Security;

namespace Supacrypt.Backend.Services.Security;

public interface ICertificateValidationService
{
    Task<CertificateValidationResult> ValidateClientCertificateAsync(
        X509Certificate2 certificate, 
        X509Chain? chain, 
        SslPolicyErrors sslPolicyErrors);
}

public class CertificateValidationResult
{
    public bool IsValid { get; set; }
    public string? Subject { get; set; }
    public string? Thumbprint { get; set; }
    public List<string> Errors { get; set; } = new();
    public Dictionary<string, string> Claims { get; set; } = new();
}