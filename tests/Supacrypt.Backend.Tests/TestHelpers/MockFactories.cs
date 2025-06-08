using Azure;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Moq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using Supacrypt.Backend.Services.Interfaces;
using Supacrypt.Backend.Observability.Metrics;
using Supacrypt.Backend.Telemetry;
using Microsoft.Extensions.Logging;
using Supacrypt.V1;

namespace Supacrypt.Backend.Tests.TestHelpers;

public static class MockFactories
{
    public static Mock<KeyClient> CreateKeyClient(params KeyVaultKey[] keys)
    {
        var mock = new Mock<KeyClient>();
        var keyDictionary = keys.ToDictionary(k => k.Name, k => k);
        
        mock.Setup(x => x.GetKeyAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((string name, string version, CancellationToken ct) =>
            {
                if (keyDictionary.TryGetValue(name, out var key))
                {
                    return Response.FromValue(key, Mock.Of<Response>());
                }
                throw new RequestFailedException(404, "Key not found");
            });
            
        mock.Setup(x => x.CreateKeyAsync(It.IsAny<string>(), It.IsAny<KeyType>(), It.IsAny<CreateKeyOptions>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((string name, KeyType keyType, CreateKeyOptions options, CancellationToken ct) =>
            {
                var newKey = CreateTestKey(name, keyType);
                keyDictionary[name] = newKey;
                return Response.FromValue(newKey, Mock.Of<Response>());
            });
            
        return mock;
    }
    
    public static KeyVaultKey CreateTestKey(string name, KeyType keyType = KeyType.Rsa)
    {
        var keyProps = new KeyProperties(name)
        {
            Id = new Uri($"{TestConstants.TestVaultUri}keys/{name}"),
            VaultUri = new Uri(TestConstants.TestVaultUri),
            Name = name,
            Enabled = true,
            CreatedOn = DateTimeOffset.UtcNow
        };
        
        JsonWebKey jwk = keyType == KeyType.Rsa 
            ? CreateRsaJsonWebKey() 
            : CreateEcJsonWebKey();
            
        return new KeyVaultKey(name, jwk, keyProps);
    }
    
    private static JsonWebKey CreateRsaJsonWebKey()
    {
        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(false);
        
        return new JsonWebKey(rsa)
        {
            KeyType = KeyType.Rsa,
            KeyOps = { KeyOperation.Sign, KeyOperation.Verify, KeyOperation.Encrypt, KeyOperation.Decrypt }
        };
    }
    
    private static JsonWebKey CreateEcJsonWebKey()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        
        return new JsonWebKey(ecdsa)
        {
            KeyType = KeyType.Ec,
            KeyOps = { KeyOperation.Sign, KeyOperation.Verify }
        };
    }
    
    public static X509Certificate2 CreateTestCertificate(
        string subject = TestConstants.TestSubject,
        bool isValid = true,
        X509KeyUsageFlags usage = X509KeyUsageFlags.DigitalSignature)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        
        request.CertificateExtensions.Add(new X509KeyUsageExtension(usage, critical: true));
        
        var notBefore = isValid ? DateTimeOffset.UtcNow.AddDays(-1) : DateTimeOffset.UtcNow.AddDays(1);
        var notAfter = isValid ? DateTimeOffset.UtcNow.AddDays(365) : DateTimeOffset.UtcNow.AddDays(-1);
        
        return request.CreateSelfSigned(notBefore, notAfter);
    }
    
    public static Mock<IKeyManagementService> CreateKeyManagementService()
    {
        var mock = new Mock<IKeyManagementService>();
        
        mock.Setup(x => x.GenerateKeyAsync(It.IsAny<GenerateKeyRequest>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new GenerateKeyResponse
            {
                Success = new KeyMetadata
                {
                    KeyId = TestConstants.TestKeyId,
                    Name = TestConstants.TestKeyName,
                    Algorithm = KeyAlgorithm.RsaPkcs1V2048,
                    CreatedAt = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTime(DateTime.UtcNow),
                    Enabled = true
                }
            });
            
        return mock;
    }
    
    public static Mock<ICryptographicOperations> CreateCryptographicOperations()
    {
        var mock = new Mock<ICryptographicOperations>();
        
        mock.Setup(x => x.SignDataAsync(It.IsAny<SignDataRequest>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new SignDataResponse
            {
                Success = new SignResult
                {
                    Signature = Google.Protobuf.ByteString.CopyFrom(TestConstants.TestSignature)
                }
            });
            
        mock.Setup(x => x.VerifySignatureAsync(It.IsAny<VerifySignatureRequest>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new VerifySignatureResponse
            {
                Success = new VerifyResult { IsValid = true }
            });
            
        return mock;
    }
    
    public static Mock<ILogger<T>> CreateLogger<T>()
    {
        return new Mock<ILogger<T>>();
    }
    
    public static Mock<CryptoMetrics> CreateCryptoMetrics()
    {
        return new Mock<CryptoMetrics>();
    }
    
    public static Mock<PerformanceTracker> CreatePerformanceTracker()
    {
        return new Mock<PerformanceTracker>();
    }
}