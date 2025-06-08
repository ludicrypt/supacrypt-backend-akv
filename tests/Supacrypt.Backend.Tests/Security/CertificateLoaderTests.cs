using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using Supacrypt.Backend.Configuration;
using Supacrypt.Backend.Services.Security;
using Supacrypt.Backend.Exceptions;

namespace Supacrypt.Backend.Tests.Security;

public class CertificateLoaderTests
{
    private readonly Mock<ILogger<CertificateLoader>> _mockLogger;
    private readonly CertificateLoader _loader;

    public CertificateLoaderTests()
    {
        _mockLogger = new Mock<ILogger<CertificateLoader>>();
        _loader = new CertificateLoader(_mockLogger.Object);
    }

    [Fact]
    public async Task LoadServerCertificateAsync_WithUnsupportedSource_ThrowsValidationException()
    {
        // Arrange
        var options = new CertificateOptions
        {
            Source = "UnsupportedSource"
        };

        // Act & Assert
        await Assert.ThrowsAsync<ValidationException>(
            () => _loader.LoadServerCertificateAsync(options));
    }

    [Fact]
    public async Task LoadCertificateFromFileAsync_WithEmptyPath_ThrowsValidationException()
    {
        // Act & Assert
        await Assert.ThrowsAsync<ValidationException>(
            () => _loader.LoadCertificateFromFileAsync("", null));
    }

    [Fact]
    public async Task LoadCertificateFromFileAsync_WithNonExistentFile_ThrowsValidationException()
    {
        // Arrange
        var nonExistentPath = "/path/that/does/not/exist.pfx";

        // Act & Assert
        await Assert.ThrowsAsync<ValidationException>(
            () => _loader.LoadCertificateFromFileAsync(nonExistentPath, null));
    }

    [Fact]
    public async Task LoadCertificateFromStoreAsync_WithEmptySubject_ThrowsValidationException()
    {
        // Act & Assert
        await Assert.ThrowsAsync<ValidationException>(
            () => _loader.LoadCertificateFromStoreAsync("", StoreName.My, StoreLocation.CurrentUser));
    }

    [Fact]
    public async Task LoadCertificateFromKeyVaultAsync_WithEmptyVaultName_ThrowsValidationException()
    {
        // Act & Assert
        await Assert.ThrowsAsync<ValidationException>(
            () => _loader.LoadCertificateFromKeyVaultAsync("", "cert-name"));
    }

    [Fact]
    public async Task LoadCertificateFromKeyVaultAsync_WithEmptyCertificateName_ThrowsValidationException()
    {
        // Act & Assert
        await Assert.ThrowsAsync<ValidationException>(
            () => _loader.LoadCertificateFromKeyVaultAsync("vault-name", ""));
    }

    [Theory]
    [InlineData("file")]
    [InlineData("FILE")]
    [InlineData("File")]
    public async Task LoadServerCertificateAsync_WithFileSource_IsCaseInsensitive(string source)
    {
        // Arrange
        var options = new CertificateOptions
        {
            Source = source,
            Path = "/non/existent/path.pfx" // Will throw, but we're testing case insensitivity
        };

        // Act & Assert
        var exception = await Assert.ThrowsAsync<ValidationException>(
            () => _loader.LoadServerCertificateAsync(options));
        
        // Should fail because file doesn't exist, not because source is invalid
        Assert.Contains("not found", exception.Message);
    }

    [Theory]
    [InlineData("store")]
    [InlineData("STORE")]
    [InlineData("Store")]
    public async Task LoadServerCertificateAsync_WithStoreSource_IsCaseInsensitive(string source)
    {
        // Arrange
        var options = new CertificateOptions
        {
            Source = source,
            Subject = "CN=NonExistent",
            StoreName = "My",
            StoreLocation = "CurrentUser"
        };

        // Act & Assert
        var exception = await Assert.ThrowsAsync<ValidationException>(
            () => _loader.LoadServerCertificateAsync(options));
        
        // Should fail because certificate doesn't exist in store, not because source is invalid
        Assert.Contains("not found in store", exception.Message);
    }

    [Theory]
    [InlineData("keyvault")]
    [InlineData("KEYVAULT")]
    [InlineData("KeyVault")]
    public async Task LoadServerCertificateAsync_WithKeyVaultSource_IsCaseInsensitive(string source)
    {
        // Arrange
        var options = new CertificateOptions
        {
            Source = source,
            KeyVaultName = "test-vault",
            CertificateName = "test-cert"
        };

        // Act & Assert
        // This will likely throw due to authentication/network issues, but we're testing case insensitivity
        var exception = await Assert.ThrowsAnyAsync<Exception>(
            () => _loader.LoadServerCertificateAsync(options));
        
        // Should not be a ValidationException about unsupported source
        Assert.IsNotType<ValidationException>(exception);
    }
}