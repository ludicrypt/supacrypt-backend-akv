using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using Microsoft.Extensions.Options;
using Supacrypt.Backend.Configuration;
using Supacrypt.Backend.Services.Security.Interfaces;

namespace Supacrypt.Backend.Services.Security;

public class CertificateValidationService : ICertificateValidationService
{
    private readonly MtlsOptions _options;
    private readonly ISecurityEventLogger _securityEventLogger;
    private readonly ILogger<CertificateValidationService> _logger;

    public CertificateValidationService(
        IOptions<SecurityOptions> securityOptions,
        ISecurityEventLogger securityEventLogger,
        ILogger<CertificateValidationService> logger)
    {
        _options = securityOptions.Value.Mtls;
        _securityEventLogger = securityEventLogger;
        _logger = logger;
    }

    public async Task<CertificateValidationResult> ValidateClientCertificateAsync(
        X509Certificate2 certificate,
        X509Chain? chain,
        SslPolicyErrors sslPolicyErrors)
    {
        var result = new CertificateValidationResult
        {
            Subject = certificate.Subject,
            Thumbprint = certificate.Thumbprint
        };

        try
        {
            // Basic certificate checks
            if (certificate == null)
            {
                result.Errors.Add("Certificate is null");
                return result;
            }

            // Check certificate expiry
            var now = DateTime.UtcNow;
            if (certificate.NotBefore > now)
            {
                result.Errors.Add($"Certificate is not yet valid. Valid from: {certificate.NotBefore:yyyy-MM-dd HH:mm:ss} UTC");
            }

            if (certificate.NotAfter < now)
            {
                result.Errors.Add($"Certificate has expired. Valid until: {certificate.NotAfter:yyyy-MM-dd HH:mm:ss} UTC");
            }

            // Check if certificate is for client authentication
            if (!HasClientAuthenticationUsage(certificate))
            {
                result.Errors.Add("Certificate does not have client authentication usage");
            }

            // Thumbprint allowlist checking
            if (_options.AllowedThumbprints.Count > 0)
            {
                if (!_options.AllowedThumbprints.Contains(certificate.Thumbprint, StringComparer.OrdinalIgnoreCase))
                {
                    result.Errors.Add($"Certificate thumbprint {certificate.Thumbprint} is not in the allowed list");
                }
            }

            // Issuer validation
            if (_options.AllowedIssuers.Count > 0)
            {
                var issuerFound = _options.AllowedIssuers.Any(allowedIssuer =>
                    certificate.Issuer.Contains(allowedIssuer, StringComparison.OrdinalIgnoreCase));

                if (!issuerFound)
                {
                    result.Errors.Add($"Certificate issuer '{certificate.Issuer}' is not in the allowed list");
                }
            }

            // Chain validation
            if (_options.ValidateChain)
            {
                var chainValidationErrors = await ValidateCertificateChainAsync(certificate);
                result.Errors.AddRange(chainValidationErrors);
            }

            // Revocation checking
            if (_options.CheckCertificateRevocation)
            {
                var revocationErrors = await CheckCertificateRevocationAsync(certificate);
                result.Errors.AddRange(revocationErrors);
            }

            // Extract claims from certificate
            ExtractClaimsFromCertificate(certificate, result);

            result.IsValid = result.Errors.Count == 0;

            if (result.IsValid)
            {
                _securityEventLogger.LogCertificateValidationSuccess(result);
                _logger.LogInformation("Certificate validation successful for {Subject} ({Thumbprint})",
                    result.Subject, result.Thumbprint);
            }
            else
            {
                _securityEventLogger.LogCertificateValidationFailure(result);
                _logger.LogWarning("Certificate validation failed for {Subject} ({Thumbprint}): {Errors}",
                    result.Subject, result.Thumbprint, string.Join("; ", result.Errors));
            }

            return result;
        }
        catch (Exception ex)
        {
            result.Errors.Add($"Certificate validation exception: {ex.Message}");
            result.IsValid = false;
            
            _securityEventLogger.LogCertificateValidationFailure(result);
            _logger.LogError(ex, "Exception during certificate validation for {Subject} ({Thumbprint})",
                result.Subject, result.Thumbprint);
            
            return result;
        }
    }

    private static bool HasClientAuthenticationUsage(X509Certificate2 certificate)
    {
        foreach (var extension in certificate.Extensions)
        {
            if (extension is X509EnhancedKeyUsageExtension ekuExtension)
            {
                foreach (var eku in ekuExtension.EnhancedKeyUsages)
                {
                    // Client Authentication OID
                    if (eku.Value == "1.3.6.1.5.5.7.3.2")
                    {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private Task<List<string>> ValidateCertificateChainAsync(X509Certificate2 certificate)
    {
        var errors = new List<string>();

        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = _options.RevocationMode;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

            var chainValid = chain.Build(certificate);

            if (!chainValid)
            {
                foreach (var chainStatus in chain.ChainStatus)
                {
                    errors.Add($"Chain validation error: {chainStatus.Status} - {chainStatus.StatusInformation}");
                }
            }
        }
        catch (Exception ex)
        {
            errors.Add($"Chain validation exception: {ex.Message}");
        }

        return Task.FromResult(errors);
    }

    private Task<List<string>> CheckCertificateRevocationAsync(X509Certificate2 certificate)
    {
        var errors = new List<string>();

        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = _options.RevocationMode;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;

            var chainValid = chain.Build(certificate);

            if (!chainValid)
            {
                foreach (var chainStatus in chain.ChainStatus)
                {
                    if (chainStatus.Status.HasFlag(X509ChainStatusFlags.Revoked))
                    {
                        errors.Add("Certificate has been revoked");
                    }
                    else if (chainStatus.Status.HasFlag(X509ChainStatusFlags.RevocationStatusUnknown))
                    {
                        errors.Add("Certificate revocation status could not be determined");
                    }
                    else if (chainStatus.Status.HasFlag(X509ChainStatusFlags.OfflineRevocation))
                    {
                        errors.Add("Certificate revocation check failed - offline");
                    }
                }
            }
        }
        catch (Exception ex)
        {
            errors.Add($"Revocation check exception: {ex.Message}");
        }

        return Task.FromResult(errors);
    }

    private static void ExtractClaimsFromCertificate(X509Certificate2 certificate, CertificateValidationResult result)
    {
        // Extract common certificate fields as claims
        result.Claims["CertificateThumbprint"] = certificate.Thumbprint;
        result.Claims["CertificateSubject"] = certificate.Subject;
        result.Claims["CertificateIssuer"] = certificate.Issuer;
        result.Claims["CertificateSerialNumber"] = certificate.SerialNumber;
        result.Claims["CertificateNotBefore"] = certificate.NotBefore.ToString("yyyy-MM-ddTHH:mm:ssZ");
        result.Claims["CertificateNotAfter"] = certificate.NotAfter.ToString("yyyy-MM-ddTHH:mm:ssZ");

        // Extract Subject Alternative Names
        foreach (var extension in certificate.Extensions)
        {
            if (extension.Oid?.Value == "2.5.29.17") // Subject Alternative Name
            {
                var sanExtension = extension as X509SubjectAlternativeNameExtension;
                if (sanExtension != null)
                {
                    result.Claims["SubjectAlternativeNames"] = sanExtension.Format(false);
                }
            }
        }

        // Extract custom claims from certificate subject
        var subjectParts = certificate.Subject.Split(',', StringSplitOptions.RemoveEmptyEntries);
        foreach (var part in subjectParts)
        {
            var keyValue = part.Trim().Split('=', 2, StringSplitOptions.RemoveEmptyEntries);
            if (keyValue.Length == 2)
            {
                var key = keyValue[0].Trim();
                var value = keyValue[1].Trim();

                // Map common certificate subject attributes to claims
                switch (key.ToUpperInvariant())
                {
                    case "CN":
                        result.Claims["CommonName"] = value;
                        // Check if this is a provider certificate
                        if (new[] { "PKCS11", "CSP", "KSP", "CTK" }.Contains(value, StringComparer.OrdinalIgnoreCase))
                        {
                            result.Claims["Provider"] = value.ToUpperInvariant();
                        }
                        break;
                    case "O":
                        result.Claims["Organization"] = value;
                        break;
                    case "OU":
                        result.Claims["OrganizationalUnit"] = value;
                        // Check for role in OU
                        if (value.Equals("Admin", StringComparison.OrdinalIgnoreCase))
                        {
                            result.Claims["CertificateRole"] = "Admin";
                        }
                        break;
                    case "C":
                        result.Claims["Country"] = value;
                        break;
                    case "ST":
                        result.Claims["State"] = value;
                        break;
                    case "L":
                        result.Claims["Locality"] = value;
                        break;
                }
            }
        }
    }
}