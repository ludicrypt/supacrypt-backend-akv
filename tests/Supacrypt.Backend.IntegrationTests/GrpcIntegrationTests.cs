using FluentAssertions;
using Grpc.Core;
using Supacrypt.Backend.IntegrationTests.Fixtures;
using Supacrypt.Backend.Tests.TestHelpers;
using Supacrypt.V1;

namespace Supacrypt.Backend.IntegrationTests;

[Collection("IntegrationTests")]
public class GrpcIntegrationTests : IClassFixture<TestServerFixture>
{
    private readonly TestServerFixture _fixture;
    private readonly SupacryptService.SupacryptServiceClient _client;

    public GrpcIntegrationTests(TestServerFixture fixture)
    {
        _fixture = fixture;
        _client = fixture.Client;
    }

    [Fact]
    public async Task GenerateKey_EndToEndFlow_ReturnsSuccessResponse()
    {
        var request = new GenerateKeyRequestBuilder()
            .WithName($"integration-test-key-{Guid.NewGuid()}")
            .WithAlgorithm(KeyAlgorithm.RsaPkcs1V2048)
            .WithTag("TestType", "Integration")
            .Build();

        var response = await _client.GenerateKeyAsync(request);

        response.Should().NotBeNull();
        response.Success.Should().NotBeNull();
        response.Success.KeyId.Should().NotBeEmpty();
        response.Success.Name.Should().Be(request.Name);
        response.Success.Algorithm.Should().Be(KeyAlgorithm.RsaPkcs1V2048);
        response.Success.Enabled.Should().BeTrue();
        response.Success.CreatedAt.Should().NotBeNull();
    }

    [Fact]
    public async Task SignAndVerify_EndToEndFlow_WorksCorrectly()
    {
        // First generate a key
        var generateRequest = new GenerateKeyRequestBuilder()
            .WithName($"sign-test-key-{Guid.NewGuid()}")
            .WithAlgorithm(KeyAlgorithm.RsaPkcs1V2048)
            .Build();

        var generateResponse = await _client.GenerateKeyAsync(generateRequest);
        generateResponse.Success.Should().NotBeNull();
        var keyId = generateResponse.Success.KeyId;

        // Sign data
        var signRequest = new SignDataRequestBuilder()
            .WithKeyId(keyId)
            .WithData(TestConstants.TestData)
            .WithAlgorithm(SignatureAlgorithm.RsaPkcs1V15Sha256)
            .Build();

        var signResponse = await _client.SignDataAsync(signRequest);
        signResponse.Success.Should().NotBeNull();
        signResponse.Success.Signature.Should().NotBeEmpty();

        // Verify signature
        var verifyRequest = new VerifySignatureRequestBuilder()
            .WithKeyId(keyId)
            .WithData(TestConstants.TestData)
            .WithSignature(signResponse.Success.Signature.ToByteArray())
            .WithAlgorithm(SignatureAlgorithm.RsaPkcs1V15Sha256)
            .Build();

        var verifyResponse = await _client.VerifySignatureAsync(verifyRequest);
        verifyResponse.Success.Should().NotBeNull();
        verifyResponse.Success.IsValid.Should().BeTrue();
    }

    [Fact]
    public async Task EncryptAndDecrypt_EndToEndFlow_WorksCorrectly()
    {
        // Generate a key
        var generateRequest = new GenerateKeyRequestBuilder()
            .WithName($"encrypt-test-key-{Guid.NewGuid()}")
            .WithAlgorithm(KeyAlgorithm.RsaPkcs1V2048)
            .Build();

        var generateResponse = await _client.GenerateKeyAsync(generateRequest);
        var keyId = generateResponse.Success.KeyId;

        // Encrypt data
        var encryptRequest = new EncryptDataRequestBuilder()
            .WithKeyId(keyId)
            .WithPlaintext(TestConstants.TestData)
            .WithAlgorithm(EncryptionAlgorithm.RsaOaep256)
            .Build();

        var encryptResponse = await _client.EncryptDataAsync(encryptRequest);
        encryptResponse.Success.Should().NotBeNull();
        encryptResponse.Success.Ciphertext.Should().NotBeEmpty();

        // Decrypt data
        var decryptRequest = new DecryptDataRequestBuilder()
            .WithKeyId(keyId)
            .WithCiphertext(encryptResponse.Success.Ciphertext.ToByteArray())
            .WithAlgorithm(EncryptionAlgorithm.RsaOaep256)
            .Build();

        var decryptResponse = await _client.DecryptDataAsync(decryptRequest);
        decryptResponse.Success.Should().NotBeNull();
        decryptResponse.Success.Plaintext.ToByteArray().Should().BeEquivalentTo(TestConstants.TestData);
    }

    [Fact]
    public async Task GetKey_AfterGeneration_ReturnsKeyMetadata()
    {
        // Generate a key
        var generateRequest = new GenerateKeyRequestBuilder()
            .WithName($"get-test-key-{Guid.NewGuid()}")
            .WithAlgorithm(KeyAlgorithm.EcdsaP256)
            .WithTag("Purpose", "Testing")
            .Build();

        var generateResponse = await _client.GenerateKeyAsync(generateRequest);
        var keyId = generateResponse.Success.KeyId;

        // Get key metadata
        var getRequest = new GetKeyRequestBuilder()
            .WithKeyId(keyId)
            .WithIncludePublicKey(true)
            .Build();

        var getResponse = await _client.GetKeyAsync(getRequest);
        getResponse.Success.Should().NotBeNull();
        getResponse.Success.Metadata.KeyId.Should().Be(keyId);
        getResponse.Success.Metadata.Name.Should().Be(generateRequest.Name);
        getResponse.Success.Metadata.Algorithm.Should().Be(KeyAlgorithm.EcdsaP256);
        getResponse.Success.PublicKey.Should().NotBeNull();
        getResponse.Success.PublicKey.KeyData.Should().NotBeEmpty();
    }

    [Fact]
    public async Task ListKeys_AfterGeneratingMultipleKeys_ReturnsAllKeys()
    {
        var keyNames = new List<string>();
        
        // Generate multiple keys
        for (int i = 0; i < 3; i++)
        {
            var keyName = $"list-test-key-{i}-{Guid.NewGuid()}";
            keyNames.Add(keyName);
            
            var generateRequest = new GenerateKeyRequestBuilder()
                .WithName(keyName)
                .WithAlgorithm(KeyAlgorithm.RsaPkcs1V2048)
                .Build();

            await _client.GenerateKeyAsync(generateRequest);
        }

        // List keys
        var listRequest = new ListKeysRequestBuilder()
            .WithPageSize(10)
            .WithIncludeDisabled(false)
            .Build();

        var listResponse = await _client.ListKeysAsync(listRequest);
        listResponse.Success.Should().NotBeNull();
        listResponse.Success.Keys.Should().NotBeEmpty();
        
        // Verify our test keys are in the list
        foreach (var keyName in keyNames)
        {
            listResponse.Success.Keys.Should().Contain(k => k.Name == keyName);
        }
    }

    [Fact]
    public async Task DeleteKey_AfterGeneration_RemovesKey()
    {
        // Generate a key
        var generateRequest = new GenerateKeyRequestBuilder()
            .WithName($"delete-test-key-{Guid.NewGuid()}")
            .Build();

        var generateResponse = await _client.GenerateKeyAsync(generateRequest);
        var keyId = generateResponse.Success.KeyId;

        // Delete the key
        var deleteRequest = new DeleteKeyRequestBuilder()
            .WithKeyId(keyId)
            .WithForce(false)
            .Build();

        var deleteResponse = await _client.DeleteKeyAsync(deleteRequest);
        deleteResponse.Success.Should().NotBeNull();

        // Verify key is deleted by trying to get it
        var getRequest = new GetKeyRequestBuilder()
            .WithKeyId(keyId)
            .Build();

        var exception = await Assert.ThrowsAsync<RpcException>(
            async () => await _client.GetKeyAsync(getRequest));
        
        exception.StatusCode.Should().Be(StatusCode.NotFound);
    }

    [Fact]
    public async Task InvalidKeyId_ReturnsNotFoundError()
    {
        var getRequest = new GetKeyRequestBuilder()
            .WithKeyId("non-existent-key-id")
            .Build();

        var exception = await Assert.ThrowsAsync<RpcException>(
            async () => await _client.GetKeyAsync(getRequest));

        exception.StatusCode.Should().Be(StatusCode.NotFound);
        exception.Status.Detail.Should().Contain("Key not found");
    }

    [Fact]
    public async Task InvalidRequest_ReturnsValidationError()
    {
        var invalidRequest = new GenerateKeyRequestBuilder()
            .WithName("") // Invalid empty name
            .Build();

        var exception = await Assert.ThrowsAsync<RpcException>(
            async () => await _client.GenerateKeyAsync(invalidRequest));

        exception.StatusCode.Should().Be(StatusCode.InvalidArgument);
        exception.Status.Detail.Should().NotBeEmpty();
    }

    [Fact]
    public async Task ConcurrentOperations_HandleCorrectly()
    {
        const int concurrentRequests = 5;
        var tasks = new List<Task<GenerateKeyResponse>>();

        // Generate multiple keys concurrently
        for (int i = 0; i < concurrentRequests; i++)
        {
            var request = new GenerateKeyRequestBuilder()
                .WithName($"concurrent-test-key-{i}-{Guid.NewGuid()}")
                .Build();

            tasks.Add(_client.GenerateKeyAsync(request));
        }

        var responses = await Task.WhenAll(tasks);

        // Verify all requests succeeded
        responses.Should().HaveCount(concurrentRequests);
        responses.Should().OnlyContain(r => r.Success != null);
        
        // Verify all keys have unique IDs
        var keyIds = responses.Select(r => r.Success.KeyId).ToList();
        keyIds.Should().OnlyHaveUniqueItems();
    }

    [Fact]
    public async Task CorrelationId_PropagatedThroughRequest()
    {
        var correlationId = Guid.NewGuid().ToString();
        var metadata = new Metadata
        {
            { "correlation-id", correlationId }
        };

        var request = new GenerateKeyRequestBuilder()
            .WithName($"correlation-test-key-{Guid.NewGuid()}")
            .Build();

        var call = _client.GenerateKeyAsync(request, metadata);
        var response = await call;

        response.Success.Should().NotBeNull();
        
        // Check that correlation ID is returned in response trailers
        var trailers = call.GetTrailers();
        trailers.Should().Contain(t => t.Key == "correlation-id" && t.Value == correlationId);
    }
}