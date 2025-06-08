using Azure;
using Azure.Security.KeyVault.Keys;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using Supacrypt.Backend.Services.Azure;
using Supacrypt.Backend.Tests.TestHelpers;
using Supacrypt.V1;

namespace Supacrypt.Backend.Tests.Services.Azure;

public class AzureKeyVaultKeyManagementServiceTests
{
    private readonly Mock<KeyClient> _keyClient;
    private readonly Mock<ILogger<AzureKeyVaultKeyManagementService>> _logger;
    private readonly AzureKeyVaultKeyManagementService _service;

    public AzureKeyVaultKeyManagementServiceTests()
    {
        _keyClient = MockFactories.CreateKeyClient();
        _logger = MockFactories.CreateLogger<AzureKeyVaultKeyManagementService>();
        _service = new AzureKeyVaultKeyManagementService(_keyClient.Object, _logger.Object);
    }

    [Fact]
    public async Task GenerateKeyAsync_WithRsaKey_ReturnsSuccessResponse()
    {
        var request = new GenerateKeyRequestBuilder()
            .WithAlgorithm(KeyAlgorithm.RsaPkcs1V2048)
            .WithKeySize(RSAKeySize.Rsa2048)
            .Build();

        var testKey = MockFactories.CreateTestKey(request.Name, KeyType.Rsa);
        _keyClient.Setup(x => x.CreateKeyAsync(It.IsAny<string>(), It.IsAny<KeyType>(), It.IsAny<CreateKeyOptions>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(testKey, Mock.Of<Response>()));

        var result = await _service.GenerateKeyAsync(request, TestConstants.TestCorrelationId, CancellationToken.None);

        result.Should().NotBeNull();
        result.Success.Should().NotBeNull();
        result.Success.KeyId.Should().NotBeEmpty();
        result.Success.Name.Should().Be(request.Name);
        result.Success.Algorithm.Should().Be(KeyAlgorithm.RsaPkcs1V2048);
        result.Success.Enabled.Should().BeTrue();
    }

    [Fact]
    public async Task GenerateKeyAsync_WithEcKey_ReturnsSuccessResponse()
    {
        var request = new GenerateKeyRequestBuilder()
            .WithAlgorithm(KeyAlgorithm.EcdsaP256)
            .Build();

        var testKey = MockFactories.CreateTestKey(request.Name, KeyType.Ec);
        _keyClient.Setup(x => x.CreateKeyAsync(It.IsAny<string>(), It.IsAny<KeyType>(), It.IsAny<CreateKeyOptions>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(testKey, Mock.Of<Response>()));

        var result = await _service.GenerateKeyAsync(request, TestConstants.TestCorrelationId, CancellationToken.None);

        result.Should().NotBeNull();
        result.Success.Should().NotBeNull();
        result.Success.Algorithm.Should().Be(KeyAlgorithm.EcdsaP256);
    }

    [Fact]
    public async Task GenerateKeyAsync_WithTags_IncludesTagsInOptions()
    {
        var request = new GenerateKeyRequestBuilder()
            .WithTag("Environment", "Test")
            .WithTag("Owner", "TestSuite")
            .Build();

        var testKey = MockFactories.CreateTestKey(request.Name);
        CreateKeyOptions capturedOptions = null;
        
        _keyClient.Setup(x => x.CreateKeyAsync(It.IsAny<string>(), It.IsAny<KeyType>(), It.IsAny<CreateKeyOptions>(), It.IsAny<CancellationToken>()))
            .Callback<string, KeyType, CreateKeyOptions, CancellationToken>((name, type, options, ct) => capturedOptions = options)
            .ReturnsAsync(Response.FromValue(testKey, Mock.Of<Response>()));

        await _service.GenerateKeyAsync(request, TestConstants.TestCorrelationId, CancellationToken.None);

        capturedOptions.Should().NotBeNull();
        capturedOptions.Tags.Should().ContainKey("Environment").WhoseValue.Should().Be("Test");
        capturedOptions.Tags.Should().ContainKey("Owner").WhoseValue.Should().Be("TestSuite");
    }

    [Fact]
    public async Task GenerateKeyAsync_WithExpiryDate_SetsExpirationDate()
    {
        var expiryDate = DateTime.UtcNow.AddYears(1);
        var request = new GenerateKeyRequestBuilder()
            .WithExpiryDate(expiryDate)
            .Build();

        var testKey = MockFactories.CreateTestKey(request.Name);
        CreateKeyOptions capturedOptions = null;
        
        _keyClient.Setup(x => x.CreateKeyAsync(It.IsAny<string>(), It.IsAny<KeyType>(), It.IsAny<CreateKeyOptions>(), It.IsAny<CancellationToken>()))
            .Callback<string, KeyType, CreateKeyOptions, CancellationToken>((name, type, options, ct) => capturedOptions = options)
            .ReturnsAsync(Response.FromValue(testKey, Mock.Of<Response>()));

        await _service.GenerateKeyAsync(request, TestConstants.TestCorrelationId, CancellationToken.None);

        capturedOptions.Should().NotBeNull();
        capturedOptions.ExpiresOn.Should().BeCloseTo(expiryDate, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task GenerateKeyAsync_KeyClientThrowsException_ReturnsErrorResponse()
    {
        var request = new GenerateKeyRequestBuilder().Build();
        var exception = new RequestFailedException(500, "Internal server error");
        
        _keyClient.Setup(x => x.CreateKeyAsync(It.IsAny<string>(), It.IsAny<KeyType>(), It.IsAny<CreateKeyOptions>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(exception);

        var result = await _service.GenerateKeyAsync(request, TestConstants.TestCorrelationId, CancellationToken.None);

        result.Should().NotBeNull();
        result.Error.Should().NotBeNull();
        result.Error.Code.Should().Be(ErrorCode.InternalError);
        result.Error.Message.Should().Contain("Internal server error");
    }

    [Fact]
    public async Task GetKeyAsync_WithExistingKey_ReturnsSuccessResponse()
    {
        var request = new GetKeyRequestBuilder().Build();
        var testKey = MockFactories.CreateTestKey(TestConstants.TestKeyName);
        
        _keyClient.Setup(x => x.GetKeyAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(testKey, Mock.Of<Response>()));

        var result = await _service.GetKeyAsync(request, TestConstants.TestCorrelationId, CancellationToken.None);

        result.Should().NotBeNull();
        result.Success.Should().NotBeNull();
        result.Success.Metadata.Should().NotBeNull();
        result.Success.Metadata.Name.Should().Be(TestConstants.TestKeyName);
    }

    [Fact]
    public async Task GetKeyAsync_WithNonExistentKey_ReturnsErrorResponse()
    {
        var request = new GetKeyRequestBuilder().WithKeyId("non-existent-key").Build();
        var exception = new RequestFailedException(404, "Key not found");
        
        _keyClient.Setup(x => x.GetKeyAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(exception);

        var result = await _service.GetKeyAsync(request, TestConstants.TestCorrelationId, CancellationToken.None);

        result.Should().NotBeNull();
        result.Error.Should().NotBeNull();
        result.Error.Code.Should().Be(ErrorCode.NotFound);
        result.Error.Message.Should().Contain("Key not found");
    }

    [Fact]
    public async Task GetKeyAsync_WithIncludePublicKeyTrue_IncludesPublicKeyData()
    {
        var request = new GetKeyRequestBuilder()
            .WithIncludePublicKey(true)
            .Build();
        var testKey = MockFactories.CreateTestKey(TestConstants.TestKeyName);
        
        _keyClient.Setup(x => x.GetKeyAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(testKey, Mock.Of<Response>()));

        var result = await _service.GetKeyAsync(request, TestConstants.TestCorrelationId, CancellationToken.None);

        result.Should().NotBeNull();
        result.Success.Should().NotBeNull();
        result.Success.PublicKey.Should().NotBeNull();
        result.Success.PublicKey.KeyData.Should().NotBeEmpty();
    }

    [Fact]
    public async Task GetKeyAsync_WithIncludePublicKeyFalse_ExcludesPublicKeyData()
    {
        var request = new GetKeyRequestBuilder()
            .WithIncludePublicKey(false)
            .Build();
        var testKey = MockFactories.CreateTestKey(TestConstants.TestKeyName);
        
        _keyClient.Setup(x => x.GetKeyAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Response.FromValue(testKey, Mock.Of<Response>()));

        var result = await _service.GetKeyAsync(request, TestConstants.TestCorrelationId, CancellationToken.None);

        result.Should().NotBeNull();
        result.Success.Should().NotBeNull();
        result.Success.PublicKey.Should().BeNull();
    }

    [Fact]
    public async Task ListKeysAsync_WithValidRequest_ReturnsKeyList()
    {
        var request = new ListKeysRequestBuilder()
            .WithPageSize(10)
            .Build();

        var testKeys = new[]
        {
            MockFactories.CreateTestKey("key1"),
            MockFactories.CreateTestKey("key2"),
            MockFactories.CreateTestKey("key3")
        };

        var mockPages = new List<Page<KeyProperties>>();
        var keyProperties = testKeys.Select(k => k.Properties).ToList();
        var mockPage = Page<KeyProperties>.FromValues(keyProperties, null, Mock.Of<Response>());
        mockPages.Add(mockPage);

        var asyncPageable = AsyncPageable<KeyProperties>.FromPages(mockPages);
        
        _keyClient.Setup(x => x.GetPropertiesOfKeysAsync(It.IsAny<CancellationToken>()))
            .Returns(asyncPageable);

        var result = await _service.ListKeysAsync(request, TestConstants.TestCorrelationId, CancellationToken.None);

        result.Should().NotBeNull();
        result.Success.Should().NotBeNull();
        result.Success.Keys.Should().HaveCount(3);
        result.Success.Keys.Should().Contain(k => k.Name == "key1");
        result.Success.Keys.Should().Contain(k => k.Name == "key2");
        result.Success.Keys.Should().Contain(k => k.Name == "key3");
    }

    [Fact]
    public async Task DeleteKeyAsync_WithExistingKey_ReturnsSuccessResponse()
    {
        var request = new DeleteKeyRequestBuilder().Build();
        var deleteOperation = Mock.Of<DeleteKeyOperation>();
        
        _keyClient.Setup(x => x.StartDeleteKeyAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(deleteOperation);

        var result = await _service.DeleteKeyAsync(request, TestConstants.TestCorrelationId, CancellationToken.None);

        result.Should().NotBeNull();
        result.Success.Should().NotBeNull();
        _keyClient.Verify(x => x.StartDeleteKeyAsync(request.KeyId, CancellationToken.None), Times.Once);
    }

    [Fact]
    public async Task DeleteKeyAsync_WithForceDelete_PurgesKey()
    {
        var request = new DeleteKeyRequestBuilder()
            .WithForce(true)
            .Build();
        var deleteOperation = Mock.Of<DeleteKeyOperation>();
        
        _keyClient.Setup(x => x.StartDeleteKeyAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(deleteOperation);

        var result = await _service.DeleteKeyAsync(request, TestConstants.TestCorrelationId, CancellationToken.None);

        result.Should().NotBeNull();
        result.Success.Should().NotBeNull();
        _keyClient.Verify(x => x.StartDeleteKeyAsync(request.KeyId, CancellationToken.None), Times.Once);
        _keyClient.Verify(x => x.PurgeDeletedKeyAsync(request.KeyId, CancellationToken.None), Times.Once);
    }

    [Fact]
    public async Task DeleteKeyAsync_WithNonExistentKey_ReturnsErrorResponse()
    {
        var request = new DeleteKeyRequestBuilder().WithKeyId("non-existent-key").Build();
        var exception = new RequestFailedException(404, "Key not found");
        
        _keyClient.Setup(x => x.StartDeleteKeyAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(exception);

        var result = await _service.DeleteKeyAsync(request, TestConstants.TestCorrelationId, CancellationToken.None);

        result.Should().NotBeNull();
        result.Error.Should().NotBeNull();
        result.Error.Code.Should().Be(ErrorCode.NotFound);
    }
}