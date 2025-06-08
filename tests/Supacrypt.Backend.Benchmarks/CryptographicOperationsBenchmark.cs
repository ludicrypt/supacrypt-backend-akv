using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Grpc.Net.Client;
using Supacrypt.V1;
using Supacrypt.Backend.Tests.TestHelpers;
using Supacrypt.Backend.Services.Interfaces;

namespace Supacrypt.Backend.Benchmarks;

[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net90)]
[MinColumn, MaxColumn, MeanColumn, MedianColumn]
public class CryptographicOperationsBenchmark : IDisposable
{
    private WebApplicationFactory<Program>? _factory;
    private GrpcChannel? _channel;
    private SupacryptService.SupacryptServiceClient? _client;
    private string _testKeyId = null!;
    private byte[] _testSignature = null!;
    private byte[] _testCiphertext = null!;

    [GlobalSetup]
    public async Task Setup()
    {
        _factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.ConfigureServices(services =>
                {
                    // Use mock implementations for consistent benchmarking
                    services.AddSingleton<IKeyManagementService>(provider =>
                        MockFactories.CreateKeyManagementService().Object);
                    
                    services.AddSingleton<ICryptographicOperations>(provider =>
                        MockFactories.CreateCryptographicOperations().Object);
                });
            });

        var httpHandler = _factory.Server.CreateHandler();
        _channel = GrpcChannel.ForAddress(_factory.Server.BaseAddress, new GrpcChannelOptions
        {
            HttpHandler = httpHandler
        });
        
        _client = new SupacryptService.SupacryptServiceClient(_channel);

        // Pre-generate test data
        var generateResponse = await _client.GenerateKeyAsync(new GenerateKeyRequestBuilder().Build());
        _testKeyId = generateResponse.Success.KeyId;

        var signResponse = await _client.SignDataAsync(new SignDataRequestBuilder()
            .WithKeyId(_testKeyId)
            .Build());
        _testSignature = signResponse.Success.Signature.ToByteArray();

        var encryptResponse = await _client.EncryptDataAsync(new EncryptDataRequestBuilder()
            .WithKeyId(_testKeyId)
            .Build());
        _testCiphertext = encryptResponse.Success.Ciphertext.ToByteArray();
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        Dispose();
    }

    [Benchmark]
    public async Task<GenerateKeyResponse> GenerateKey_RSA2048()
    {
        var request = new GenerateKeyRequestBuilder()
            .WithName($"benchmark-key-{Guid.NewGuid()}")
            .WithAlgorithm(KeyAlgorithm.RsaPkcs1V2048)
            .Build();

        return await _client!.GenerateKeyAsync(request);
    }

    [Benchmark]
    public async Task<GenerateKeyResponse> GenerateKey_RSA4096()
    {
        var request = new GenerateKeyRequestBuilder()
            .WithName($"benchmark-key-{Guid.NewGuid()}")
            .WithAlgorithm(KeyAlgorithm.RsaPkcs1V4096)
            .Build();

        return await _client!.GenerateKeyAsync(request);
    }

    [Benchmark]
    public async Task<GenerateKeyResponse> GenerateKey_ECDSA_P256()
    {
        var request = new GenerateKeyRequestBuilder()
            .WithName($"benchmark-key-{Guid.NewGuid()}")
            .WithAlgorithm(KeyAlgorithm.EcdsaP256)
            .Build();

        return await _client!.GenerateKeyAsync(request);
    }

    [Benchmark]
    public async Task<SignDataResponse> SignData_RSA2048()
    {
        var request = new SignDataRequestBuilder()
            .WithKeyId(_testKeyId)
            .WithAlgorithm(SignatureAlgorithm.RsaPkcs1V15Sha256)
            .Build();

        return await _client!.SignDataAsync(request);
    }

    [Benchmark]
    public async Task<SignDataResponse> SignData_RSA_PSS()
    {
        var request = new SignDataRequestBuilder()
            .WithKeyId(_testKeyId)
            .WithAlgorithm(SignatureAlgorithm.RsaPssV2048Sha256)
            .Build();

        return await _client!.SignDataAsync(request);
    }

    [Benchmark]
    public async Task<SignDataResponse> SignData_ECDSA_P256()
    {
        var request = new SignDataRequestBuilder()
            .WithKeyId(_testKeyId)
            .WithAlgorithm(SignatureAlgorithm.EcdsaP256Sha256)
            .Build();

        return await _client!.SignDataAsync(request);
    }

    [Benchmark]
    public async Task<VerifySignatureResponse> VerifySignature_RSA2048()
    {
        var request = new VerifySignatureRequestBuilder()
            .WithKeyId(_testKeyId)
            .WithSignature(_testSignature)
            .WithAlgorithm(SignatureAlgorithm.RsaPkcs1V15Sha256)
            .Build();

        return await _client!.VerifySignatureAsync(request);
    }

    [Benchmark]
    public async Task<VerifySignatureResponse> VerifySignature_ECDSA_P256()
    {
        var request = new VerifySignatureRequestBuilder()
            .WithKeyId(_testKeyId)
            .WithSignature(_testSignature)
            .WithAlgorithm(SignatureAlgorithm.EcdsaP256Sha256)
            .Build();

        return await _client!.VerifySignatureAsync(request);
    }

    [Benchmark]
    public async Task<EncryptDataResponse> EncryptData_RSA_OAEP()
    {
        var request = new EncryptDataRequestBuilder()
            .WithKeyId(_testKeyId)
            .WithAlgorithm(EncryptionAlgorithm.RsaOaep)
            .Build();

        return await _client!.EncryptDataAsync(request);
    }

    [Benchmark]
    public async Task<EncryptDataResponse> EncryptData_RSA_OAEP256()
    {
        var request = new EncryptDataRequestBuilder()
            .WithKeyId(_testKeyId)
            .WithAlgorithm(EncryptionAlgorithm.RsaOaep256)
            .Build();

        return await _client!.EncryptDataAsync(request);
    }

    [Benchmark]
    public async Task<DecryptDataResponse> DecryptData_RSA_OAEP()
    {
        var request = new DecryptDataRequestBuilder()
            .WithKeyId(_testKeyId)
            .WithCiphertext(_testCiphertext)
            .WithAlgorithm(EncryptionAlgorithm.RsaOaep)
            .Build();

        return await _client!.DecryptDataAsync(request);
    }

    [Benchmark]
    public async Task<DecryptDataResponse> DecryptData_RSA_OAEP256()
    {
        var request = new DecryptDataRequestBuilder()
            .WithKeyId(_testKeyId)
            .WithCiphertext(_testCiphertext)
            .WithAlgorithm(EncryptionAlgorithm.RsaOaep256)
            .Build();

        return await _client!.DecryptDataAsync(request);
    }

    [Benchmark]
    public async Task<GetKeyResponse> GetKey_WithPublicKey()
    {
        var request = new GetKeyRequestBuilder()
            .WithKeyId(_testKeyId)
            .WithIncludePublicKey(true)
            .Build();

        return await _client!.GetKeyAsync(request);
    }

    [Benchmark]
    public async Task<GetKeyResponse> GetKey_WithoutPublicKey()
    {
        var request = new GetKeyRequestBuilder()
            .WithKeyId(_testKeyId)
            .WithIncludePublicKey(false)
            .Build();

        return await _client!.GetKeyAsync(request);
    }

    [Benchmark]
    public async Task<ListKeysResponse> ListKeys_Page10()
    {
        var request = new ListKeysRequestBuilder()
            .WithPageSize(10)
            .Build();

        return await _client!.ListKeysAsync(request);
    }

    [Benchmark]
    public async Task<ListKeysResponse> ListKeys_Page100()
    {
        var request = new ListKeysRequestBuilder()
            .WithPageSize(100)
            .Build();

        return await _client!.ListKeysAsync(request);
    }

    [Params(1024, 4096, 16384, 65536)]
    public int DataSize { get; set; }

    [Benchmark]
    public async Task<SignDataResponse> SignData_VariableSize()
    {
        var data = new byte[DataSize];
        new Random(42).NextBytes(data); // Deterministic random data
        
        var request = new SignDataRequestBuilder()
            .WithKeyId(_testKeyId)
            .WithData(data)
            .WithAlgorithm(SignatureAlgorithm.RsaPkcs1V15Sha256)
            .Build();

        return await _client!.SignDataAsync(request);
    }

    public void Dispose()
    {
        _channel?.Dispose();
        _factory?.Dispose();
    }
}