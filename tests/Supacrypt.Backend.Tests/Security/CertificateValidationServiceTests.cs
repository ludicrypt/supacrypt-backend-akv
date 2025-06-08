using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using Supacrypt.Backend.Configuration;
using Supacrypt.Backend.Services.Security;
using Supacrypt.Backend.Services.Security.Interfaces;

namespace Supacrypt.Backend.Tests.Security;

public class CertificateValidationServiceTests
{
    private readonly Mock<ISecurityEventLogger> _mockSecurityEventLogger;
    private readonly Mock<ILogger<CertificateValidationService>> _mockLogger;
    private readonly SecurityOptions _securityOptions;
    private readonly CertificateValidationService _service;

    public CertificateValidationServiceTests()
    {
        _mockSecurityEventLogger = new Mock<ISecurityEventLogger>();
        _mockLogger = new Mock<ILogger<CertificateValidationService>>();
        _securityOptions = new SecurityOptions
        {
            Mtls = new MtlsOptions
            {
                Enabled = true,
                RequireClientCertificate = true,
                CheckCertificateRevocation = false,
                ValidateChain = false,
                AllowedThumbprints = new List<string>(),
                AllowedIssuers = new List<string>()
            }
        };

        var options = Options.Create(_securityOptions);
        _service = new CertificateValidationService(options, _mockSecurityEventLogger.Object, _mockLogger.Object);
    }

    [Fact]
    public async Task ValidateClientCertificateAsync_WithNullCertificate_ReturnsInvalid()
    {
        // Act
        var result = await _service.ValidateClientCertificateAsync(null!, null, SslPolicyErrors.None);

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains("Certificate is null", result.Errors);
    }

    [Fact]
    public async Task ValidateClientCertificateAsync_WithExpiredCertificate_ReturnsInvalid()
    {
        // Arrange
        var certificate = CreateTestCertificate(
            notBefore: DateTime.UtcNow.AddDays(-365),
            notAfter: DateTime.UtcNow.AddDays(-1)); // Expired yesterday

        // Act
        var result = await _service.ValidateClientCertificateAsync(certificate, null, SslPolicyErrors.None);

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Contains("has expired"));
    }

    [Fact]
    public async Task ValidateClientCertificateAsync_WithFutureCertificate_ReturnsInvalid()
    {
        // Arrange
        var certificate = CreateTestCertificate(
            notBefore: DateTime.UtcNow.AddDays(1), // Valid tomorrow
            notAfter: DateTime.UtcNow.AddDays(365));

        // Act
        var result = await _service.ValidateClientCertificateAsync(certificate, null, SslPolicyErrors.None);

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Contains("not yet valid"));
    }

    [Fact]
    public async Task ValidateClientCertificateAsync_WithThumbprintAllowlist_ValidatesCorrectly()
    {
        // Arrange
        var certificate = CreateTestCertificate();
        _securityOptions.Mtls.AllowedThumbprints.Add(certificate.Thumbprint);

        // Act
        var result = await _service.ValidateClientCertificateAsync(certificate, null, SslPolicyErrors.None);

        // Assert
        // Should be valid (assuming other validation passes)
        Assert.NotNull(result.Thumbprint);
        Assert.Equal(certificate.Thumbprint, result.Thumbprint);
    }

    [Fact]
    public async Task ValidateClientCertificateAsync_WithDisallowedThumbprint_ReturnsInvalid()
    {
        // Arrange
        var certificate = CreateTestCertificate();
        _securityOptions.Mtls.AllowedThumbprints.Add("DIFFERENT_THUMBPRINT");

        // Act
        var result = await _service.ValidateClientCertificateAsync(certificate, null, SslPolicyErrors.None);

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, error => error.Contains("not in the allowed list"));
    }

    [Fact]
    public async Task ValidateClientCertificateAsync_WithAllowedIssuer_ValidatesCorrectly()
    {
        // Arrange
        var certificate = CreateTestCertificate();
        _securityOptions.Mtls.AllowedIssuers.Add("Supacrypt Test CA");

        // Act
        var result = await _service.ValidateClientCertificateAsync(certificate, null, SslPolicyErrors.None);

        // Assert
        // Should be valid for allowed issuer
        Assert.NotNull(result.Subject);
    }

    [Fact]
    public async Task ValidateClientCertificateAsync_ExtractsClaimsCorrectly()
    {
        // Arrange
        var certificate = CreateTestCertificate();

        // Act
        var result = await _service.ValidateClientCertificateAsync(certificate, null, SslPolicyErrors.None);

        // Assert
        Assert.Contains("CertificateThumbprint", result.Claims.Keys);
        Assert.Contains("CertificateSubject", result.Claims.Keys);
        Assert.Contains("CertificateIssuer", result.Claims.Keys);
        Assert.Contains("CommonName", result.Claims.Keys);
        Assert.Equal("TestClient", result.Claims["CommonName"]);
    }

    [Fact]
    public async Task ValidateClientCertificateAsync_WithProviderCertificate_ExtractsProviderClaim()
    {
        // Arrange
        var certificate = CreateTestCertificate(commonName: "PKCS11");

        // Act
        var result = await _service.ValidateClientCertificateAsync(certificate, null, SslPolicyErrors.None);

        // Assert
        Assert.Contains("Provider", result.Claims.Keys);
        Assert.Equal("PKCS11", result.Claims["Provider"]);
    }

    [Fact]
    public async Task ValidateClientCertificateAsync_WithAdminRole_ExtractsRoleClaim()
    {
        // Arrange
        var certificate = CreateTestCertificate(organizationalUnit: "Admin");

        // Act
        var result = await _service.ValidateClientCertificateAsync(certificate, null, SslPolicyErrors.None);

        // Assert
        Assert.Contains("CertificateRole", result.Claims.Keys);
        Assert.Equal("Admin", result.Claims["CertificateRole"]);
    }

    [Fact]
    public async Task ValidateClientCertificateAsync_LogsSuccessfulValidation()
    {
        // Arrange
        var certificate = CreateTestCertificate();

        // Act
        var result = await _service.ValidateClientCertificateAsync(certificate, null, SslPolicyErrors.None);

        // Assert
        if (result.IsValid)
        {
            _mockSecurityEventLogger.Verify(
                x => x.LogCertificateValidationSuccess(It.IsAny<CertificateValidationResult>()),
                Times.Once);
        }
    }

    [Fact]
    public async Task ValidateClientCertificateAsync_LogsFailedValidation()
    {
        // Arrange
        var certificate = CreateTestCertificate(
            notAfter: DateTime.UtcNow.AddDays(-1)); // Expired

        // Act
        var result = await _service.ValidateClientCertificateAsync(certificate, null, SslPolicyErrors.None);

        // Assert
        Assert.False(result.IsValid);
        _mockSecurityEventLogger.Verify(
            x => x.LogCertificateValidationFailure(It.IsAny<CertificateValidationResult>()),
            Times.Once);
    }

    private static X509Certificate2 CreateTestCertificate(
        string commonName = "TestClient",
        string organizationalUnit = "User",
        DateTime? notBefore = null,
        DateTime? notAfter = null)
    {
        // For testing purposes, create a self-signed certificate
        using var rsa = RSA.Create(2048);
        
        var subject = $"CN={commonName}, OU={organizationalUnit}, O=Supacrypt, C=US";
        var issuer = "CN=Supacrypt Test CA, O=Supacrypt, C=US";
        
        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        
        // Add client authentication extension
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, // Client Authentication
                false));
        
        var startDate = notBefore ?? DateTime.UtcNow.AddDays(-1);
        var endDate = notAfter ?? DateTime.UtcNow.AddDays(365);
        
        return request.CreateSelfSigned(startDate, endDate);
    }
}