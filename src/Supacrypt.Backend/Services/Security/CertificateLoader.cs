using System.Security.Cryptography.X509Certificates;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Supacrypt.Backend.Configuration;
using Supacrypt.Backend.Exceptions;

namespace Supacrypt.Backend.Services.Security;

public class CertificateLoader : ICertificateLoader
{
    private readonly ILogger<CertificateLoader> _logger;

    public CertificateLoader(ILogger<CertificateLoader> logger)
    {
        _logger = logger;
    }

    public async Task<X509Certificate2> LoadServerCertificateAsync(CertificateOptions options)
    {
        try
        {
            return options.Source.ToLowerInvariant() switch
            {
                "file" => await LoadCertificateFromFileAsync(options.Path, options.Password),
                "store" => await LoadCertificateFromStoreAsync(
                    options.Subject,
                    Enum.Parse<StoreName>(options.StoreName, true),
                    Enum.Parse<StoreLocation>(options.StoreLocation, true)),
                "keyvault" => await LoadCertificateFromKeyVaultAsync(options.KeyVaultName, options.CertificateName),
                _ => throw new ValidationException($"Unsupported certificate source: {options.Source}")
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load server certificate from {Source}", options.Source);
            throw;
        }
    }

    public async Task<X509Certificate2> LoadCertificateFromFileAsync(string path, string? password)
    {
        try
        {
            if (string.IsNullOrEmpty(path))
            {
                throw new ValidationException("Certificate path cannot be empty");
            }

            if (!File.Exists(path))
            {
                throw new ValidationException($"Certificate file not found: {path}");
            }

            _logger.LogInformation("Loading certificate from file: {Path}", path);

            var certificate = string.IsNullOrEmpty(password)
                ? new X509Certificate2(path)
                : new X509Certificate2(path, password);

            ValidateCertificate(certificate);
            
            _logger.LogInformation("Successfully loaded certificate from file. Subject: {Subject}, Thumbprint: {Thumbprint}",
                certificate.Subject, certificate.Thumbprint);

            return certificate;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load certificate from file: {Path}", path);
            throw;
        }
    }

    public async Task<X509Certificate2> LoadCertificateFromStoreAsync(string subject, StoreName storeName, StoreLocation storeLocation)
    {
        try
        {
            if (string.IsNullOrEmpty(subject))
            {
                throw new ValidationException("Certificate subject cannot be empty");
            }

            _logger.LogInformation("Loading certificate from store. Subject: {Subject}, Store: {StoreName}, Location: {StoreLocation}",
                subject, storeName, storeLocation);

            using var store = new X509Store(storeName, storeLocation);
            store.Open(OpenFlags.ReadOnly);

            var certificates = store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, subject, false);

            if (certificates.Count == 0)
            {
                throw new ValidationException($"Certificate with subject '{subject}' not found in store {storeName} at {storeLocation}");
            }

            if (certificates.Count > 1)
            {
                _logger.LogWarning("Multiple certificates found with subject '{Subject}'. Using the first one.", subject);
            }

            var certificate = certificates[0];
            ValidateCertificate(certificate);

            _logger.LogInformation("Successfully loaded certificate from store. Subject: {Subject}, Thumbprint: {Thumbprint}",
                certificate.Subject, certificate.Thumbprint);

            return certificate;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load certificate from store. Subject: {Subject}, Store: {StoreName}, Location: {StoreLocation}",
                subject, storeName, storeLocation);
            throw;
        }
    }

    public async Task<X509Certificate2> LoadCertificateFromKeyVaultAsync(string vaultName, string certificateName)
    {
        try
        {
            if (string.IsNullOrEmpty(vaultName))
            {
                throw new ValidationException("Key Vault name cannot be empty");
            }

            if (string.IsNullOrEmpty(certificateName))
            {
                throw new ValidationException("Certificate name cannot be empty");
            }

            _logger.LogInformation("Loading certificate from Key Vault. Vault: {VaultName}, Certificate: {CertificateName}",
                vaultName, certificateName);

            var vaultUri = $"https://{vaultName}.vault.azure.net/";
            var client = new CertificateClient(new Uri(vaultUri), new DefaultAzureCredential());

            var certificateWithPolicy = await client.GetCertificateAsync(certificateName);
            var certificate = certificateWithPolicy.Value;

            // Download the certificate with private key
            var secretClient = new Azure.Security.KeyVault.Secrets.SecretClient(new Uri(vaultUri), new DefaultAzureCredential());
            var secret = await secretClient.GetSecretAsync(certificateName);

            // Convert the secret value (Base64 encoded PFX) to X509Certificate2
            var pfxBytes = Convert.FromBase64String(secret.Value.Value);
            var x509Certificate = new X509Certificate2(pfxBytes, (string?)null, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);

            ValidateCertificate(x509Certificate);

            _logger.LogInformation("Successfully loaded certificate from Key Vault. Subject: {Subject}, Thumbprint: {Thumbprint}",
                x509Certificate.Subject, x509Certificate.Thumbprint);

            return x509Certificate;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load certificate from Key Vault. Vault: {VaultName}, Certificate: {CertificateName}",
                vaultName, certificateName);
            throw;
        }
    }

    private static void ValidateCertificate(X509Certificate2 certificate)
    {
        var now = DateTime.UtcNow;
        
        if (certificate.NotBefore > now)
        {
            throw new ValidationException($"Certificate is not yet valid. Valid from: {certificate.NotBefore:yyyy-MM-dd HH:mm:ss} UTC");
        }

        if (certificate.NotAfter < now)
        {
            throw new ValidationException($"Certificate has expired. Valid until: {certificate.NotAfter:yyyy-MM-dd HH:mm:ss} UTC");
        }

        if (!certificate.HasPrivateKey)
        {
            throw new ValidationException("Certificate does not have a private key");
        }
    }
}