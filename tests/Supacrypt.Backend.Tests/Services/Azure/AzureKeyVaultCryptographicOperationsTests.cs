using Azure;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using Supacrypt.Backend.Services.Azure;
using Supacrypt.Backend.Tests.TestHelpers;
using Supacrypt.V1;

namespace Supacrypt.Backend.Tests.Services.Azure;

public class AzureKeyVaultCryptographicOperationsTests
{
    private readonly Mock<KeyClient> _keyClient;
    private readonly Mock<CryptographyClient> _cryptographyClient;
    private readonly Mock<ILogger<AzureKeyVaultCryptographicOperations>> _logger;
    private readonly AzureKeyVaultCryptographicOperations _service;

    public AzureKeyVaultCryptographicOperationsTests()
    {
        _keyClient = MockFactories.CreateKeyClient();
        _cryptographyClient = new Mock<CryptographyClient>();
        _logger = MockFactories.CreateLogger<AzureKeyVaultCryptographicOperations>();
        
        var mockClientFactory = new Mock<IAzureKeyVaultClientFactory>();
        mockClientFactory.Setup(x => x.CreateCryptographyClient(It.IsAny<string>()))
            .Returns(_cryptographyClient.Object);
        
        _service = new AzureKeyVaultCryptographicOperations(_keyClient.Object, mockClientFactory.Object, _logger.Object);
    }

    [Fact]
    public async Task SignDataAsync_WithRsaKey_ReturnsSignature()
    {
        var request = new SignDataRequestBuilder()
            .WithAlgorithm(SignatureAlgorithm.RsaPkcs1V15Sha256)
            .Build();

        var signResult = new SignResult(request.KeyId, TestConstants.TestSignature, SignatureAlgorithm.PS256, Mock.Of<Response>());
        _cryptographyClient.Setup(x => x.SignDataAsync(It.IsAny<SignatureAlgorithm>(), It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(signResult);

        var result = await _service.SignDataAsync(request, TestConstants.TestCorrelationId, CancellationToken.None);

        result.Should().NotBeNull();
        result.Success.Should().NotBeNull();
        result.Success.Signature.ToByteArray().Should().BeEquivalentTo(TestConstants.TestSignature);
        _cryptographyClient.Verify(x => x.SignDataAsync(SignatureAlgorithm.PS256, request.Data.ToByteArray(), CancellationToken.None), Times.Once);
    }

    [Theory]
    [InlineData(SignatureAlgorithm.RsaPkcs1V15Sha256, SignatureAlgorithm.PS256)]
    [InlineData(SignatureAlgorithm.RsaPssV2048Sha256, SignatureAlgorithm.PS256)]
    [InlineData(SignatureAlgorithm.EcdsaP256Sha256, SignatureAlgorithm.ES256)]
    public async Task SignDataAsync_WithDifferentAlgorithms_MapsCorrectly(SignatureAlgorithm requestAlgorithm, SignatureAlgorithm expectedAzureAlgorithm)
    {
        var request = new SignDataRequestBuilder()
            .WithAlgorithm(requestAlgorithm)
            .Build();

        var signResult = new SignResult(request.KeyId, TestConstants.TestSignature, expectedAzureAlgorithm, Mock.Of<Response>());
        _cryptographyClient.Setup(x => x.SignDataAsync(It.IsAny<SignatureAlgorithm>(), It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(signResult);

        await _service.SignDataAsync(request, TestConstants.TestCorrelationId, CancellationToken.None);

        _cryptographyClient.Verify(x => x.SignDataAsync(expectedAzureAlgorithm, request.Data.ToByteArray(), CancellationToken.None), Times.Once);
    }

    [Fact]
    public async Task SignDataAsync_CryptographyClientThrowsException_ReturnsErrorResponse()
    {
        var request = new SignDataRequestBuilder().Build();
        var exception = new RequestFailedException(403, "Forbidden");
        
        _cryptographyClient.Setup(x => x.SignDataAsync(It.IsAny<SignatureAlgorithm>(), It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(exception);

        var result = await _service.SignDataAsync(request, TestConstants.TestCorrelationId, CancellationToken.None);

        result.Should().NotBeNull();
        result.Error.Should().NotBeNull();
        result.Error.Code.Should().Be(ErrorCode.PermissionDenied);
        result.Error.Message.Should().Contain("Forbidden");
    }

    [Fact]
    public async Task VerifySignatureAsync_WithValidSignature_ReturnsTrue()
    {
        var request = new VerifySignatureRequestBuilder().Build();

        var verifyResult = new VerifyResult(request.KeyId, true, SignatureAlgorithm.PS256, Mock.Of<Response>());
        _cryptographyClient.Setup(x => x.VerifyDataAsync(It.IsAny<SignatureAlgorithm>(), It.IsAny<byte[]>(), It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(verifyResult);

        var result = await _service.VerifySignatureAsync(request, TestConstants.TestCorrelationId, CancellationToken.None);

        result.Should().NotBeNull();
        result.Success.Should().NotBeNull();
        result.Success.IsValid.Should().BeTrue();
        _cryptographyClient.Verify(x => x.VerifyDataAsync(
            SignatureAlgorithm.PS256, 
            request.Data.ToByteArray(), 
            request.Signature.ToByteArray(), 
            CancellationToken.None), Times.Once);
    }

    [Fact]
    public async Task VerifySignatureAsync_WithInvalidSignature_ReturnsFalse()
    {
        var request = new VerifySignatureRequestBuilder().Build();

        var verifyResult = new VerifyResult(request.KeyId, false, SignatureAlgorithm.PS256, Mock.Of<Response>());
        _cryptographyClient.Setup(x => x.VerifyDataAsync(It.IsAny<SignatureAlgorithm>(), It.IsAny<byte[]>(), It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(verifyResult);

        var result = await _service.VerifySignatureAsync(request, TestConstants.TestCorrelationId, CancellationToken.None);

        result.Should().NotBeNull();
        result.Success.Should().NotBeNull();
        result.Success.IsValid.Should().BeFalse();
    }

    [Fact]
    public async Task VerifySignatureAsync_CryptographyClientThrowsException_ReturnsErrorResponse()
    {
        var request = new VerifySignatureRequestBuilder().Build();
        var exception = new RequestFailedException(400, "Bad request");
        
        _cryptographyClient.Setup(x => x.VerifyDataAsync(It.IsAny<SignatureAlgorithm>(), It.IsAny<byte[]>(), It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(exception);

        var result = await _service.VerifySignatureAsync(request, TestConstants.TestCorrelationId, CancellationToken.None);

        result.Should().NotBeNull();
        result.Error.Should().NotBeNull();
        result.Error.Code.Should().Be(ErrorCode.InvalidArgument);
    }

    [Fact]
    public async Task EncryptDataAsync_WithValidRequest_ReturnsEncryptedData()
    {
        var request = new EncryptDataRequestBuilder().Build();

        var encryptResult = new EncryptResult(request.KeyId, TestConstants.TestCiphertext, EncryptionAlgorithm.RsaOaep256, Mock.Of<Response>());
        _cryptographyClient.Setup(x => x.EncryptAsync(It.IsAny<EncryptionAlgorithm>(), It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(encryptResult);

        var result = await _service.EncryptDataAsync(request, TestConstants.TestCorrelationId, CancellationToken.None);

        result.Should().NotBeNull();
        result.Success.Should().NotBeNull();
        result.Success.Ciphertext.ToByteArray().Should().BeEquivalentTo(TestConstants.TestCiphertext);
        _cryptographyClient.Verify(x => x.EncryptAsync(EncryptionAlgorithm.RsaOaep256, request.Plaintext.ToByteArray(), CancellationToken.None), Times.Once);
    }

    [Fact]
    public async Task DecryptDataAsync_WithValidRequest_ReturnsDecryptedData()
    {
        var request = new DecryptDataRequestBuilder().Build();

        var decryptResult = new DecryptResult(request.KeyId, TestConstants.TestData, EncryptionAlgorithm.RsaOaep256, Mock.Of<Response>());
        _cryptographyClient.Setup(x => x.DecryptAsync(It.IsAny<EncryptionAlgorithm>(), It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(decryptResult);

        var result = await _service.DecryptDataAsync(request, TestConstants.TestCorrelationId, CancellationToken.None);

        result.Should().NotBeNull();
        result.Success.Should().NotBeNull();
        result.Success.Plaintext.ToByteArray().Should().BeEquivalentTo(TestConstants.TestData);
        _cryptographyClient.Verify(x => x.DecryptAsync(EncryptionAlgorithm.RsaOaep256, request.Ciphertext.ToByteArray(), CancellationToken.None), Times.Once);
    }

    [Theory]
    [InlineData(EncryptionAlgorithm.RsaOaep, EncryptionAlgorithm.RsaOaep)]
    [InlineData(EncryptionAlgorithm.RsaOaep256, EncryptionAlgorithm.RsaOaep256)]
    [InlineData(EncryptionAlgorithm.Rsa15, EncryptionAlgorithm.Rsa15)]
    public async Task EncryptDataAsync_WithDifferentAlgorithms_MapsCorrectly(EncryptionAlgorithm requestAlgorithm, EncryptionAlgorithm expectedAzureAlgorithm)
    {
        var request = new EncryptDataRequestBuilder()
            .WithAlgorithm(requestAlgorithm)
            .Build();

        var encryptResult = new EncryptResult(request.KeyId, TestConstants.TestCiphertext, expectedAzureAlgorithm, Mock.Of<Response>());
        _cryptographyClient.Setup(x => x.EncryptAsync(It.IsAny<EncryptionAlgorithm>(), It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(encryptResult);

        await _service.EncryptDataAsync(request, TestConstants.TestCorrelationId, CancellationToken.None);

        _cryptographyClient.Verify(x => x.EncryptAsync(expectedAzureAlgorithm, request.Plaintext.ToByteArray(), CancellationToken.None), Times.Once);
    }
}