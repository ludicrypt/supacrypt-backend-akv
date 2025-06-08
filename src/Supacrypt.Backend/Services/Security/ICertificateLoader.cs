using System.Security.Cryptography.X509Certificates;
using Supacrypt.Backend.Configuration;

namespace Supacrypt.Backend.Services.Security;

public interface ICertificateLoader
{
    Task<X509Certificate2> LoadServerCertificateAsync(CertificateOptions options);
    Task<X509Certificate2> LoadCertificateFromFileAsync(string path, string? password);
    Task<X509Certificate2> LoadCertificateFromStoreAsync(string subject, StoreName storeName, StoreLocation storeLocation);
    Task<X509Certificate2> LoadCertificateFromKeyVaultAsync(string vaultName, string certificateName);
}