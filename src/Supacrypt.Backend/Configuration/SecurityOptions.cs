using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Server.Kestrel.Https;

namespace Supacrypt.Backend.Configuration;

public class SecurityOptions
{
    public const string SectionName = "Security";

    public MtlsOptions Mtls { get; set; } = new();
    public CertificateOptions ServerCertificate { get; set; } = new();
    public AuthorizationOptions Authorization { get; set; } = new();
}

public class MtlsOptions
{
    public bool Enabled { get; set; } = true;
    public bool RequireClientCertificate { get; set; } = true;
    public ClientCertificateMode Mode { get; set; } = ClientCertificateMode.RequireCertificate;
    public bool CheckCertificateRevocation { get; set; } = true;
    public List<string> AllowedThumbprints { get; set; } = new();
    public List<string> AllowedIssuers { get; set; } = new();
    public bool ValidateChain { get; set; } = true;
    public X509RevocationMode RevocationMode { get; set; } = X509RevocationMode.Online;
}

public class CertificateOptions
{
    public string Source { get; set; } = "File"; // File, Store, KeyVault
    public string Path { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public string StoreName { get; set; } = "My";
    public string StoreLocation { get; set; } = "CurrentUser";
    public string KeyVaultName { get; set; } = string.Empty;
    public string CertificateName { get; set; } = string.Empty;
}

public class AuthorizationOptions
{
    public bool RequireValidCertificate { get; set; } = true;
    public bool RequireSpecificProvider { get; set; } = false;
    public bool RequireAdminCertificate { get; set; } = false;
    public List<string> AllowedProviders { get; set; } = new() { "PKCS11", "CSP", "KSP", "CTK" };
}