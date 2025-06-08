using NBomber.CSharp;
using NBomber.Contracts;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Grpc.Net.Client;
using Supacrypt.V1;
using Supacrypt.Backend.Tests.TestHelpers;
using Supacrypt.Backend.Services.Interfaces;

namespace Supacrypt.Backend.LoadTests;

public static class LoadTestScenarios
{
    private static WebApplicationFactory<Program>? _factory;
    private static GrpcChannel? _channel;
    private static SupacryptService.SupacryptServiceClient? _client;
    private static readonly List<string> _generatedKeys = new();
    private static readonly Random _random = new();

    public static void Initialize()
    {
        _factory = new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.ConfigureServices(services =>
                {
                    // Use mock implementations for load testing
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
    }

    public static void Cleanup()
    {
        _channel?.Dispose();
        _factory?.Dispose();
    }

    public static Scenario CryptoOperationsScenario()
    {
        return Scenario.Create("crypto_operations", async context =>
        {
            try
            {
                var operation = _random.Next(6);
                return operation switch
                {
                    0 => await GenerateKey(context),
                    1 => await SignData(context),
                    2 => await VerifySignature(context),
                    3 => await EncryptData(context),
                    4 => await DecryptData(context),
                    5 => await ListKeys(context),
                    _ => await GetKey(context)
                };
            }
            catch (Exception ex)
            {
                return Response.Fail(error: ex.Message);
            }
        })
        .WithLoadSimulations(
            Simulation.InjectPerSec(rate: 50, during: TimeSpan.FromMinutes(2)),
            Simulation.KeepConstant(copies: 25, during: TimeSpan.FromMinutes(3)),
            Simulation.InjectPerSec(rate: 100, during: TimeSpan.FromMinutes(2))
        );
    }

    public static Scenario KeyManagementScenario()
    {
        return Scenario.Create("key_management", async context =>
        {
            try
            {
                var operation = _random.Next(4);
                return operation switch
                {
                    0 => await GenerateKey(context),
                    1 => await GetKey(context),
                    2 => await ListKeys(context),
                    _ => await DeleteKey(context)
                };
            }
            catch (Exception ex)
            {
                return Response.Fail(error: ex.Message);
            }
        })
        .WithLoadSimulations(
            Simulation.RampingInject(rate: 100, interval: TimeSpan.FromSeconds(1), during: TimeSpan.FromMinutes(5))
        );
    }

    public static Scenario HighVolumeSigningScenario()
    {
        return Scenario.Create("high_volume_signing", async context =>
        {
            try
            {
                return await SignData(context);
            }
            catch (Exception ex)
            {
                return Response.Fail(error: ex.Message);
            }
        })
        .WithLoadSimulations(
            Simulation.KeepConstant(copies: 100, during: TimeSpan.FromMinutes(5))
        );
    }

    public static Scenario StressTestScenario()
    {
        return Scenario.Create("stress_test", async context =>
        {
            try
            {
                var operation = _random.Next(3);
                return operation switch
                {
                    0 => await SignData(context),
                    1 => await VerifySignature(context),
                    _ => await EncryptData(context)
                };
            }
            catch (Exception ex)
            {
                return Response.Fail(error: ex.Message);
            }
        })
        .WithLoadSimulations(
            Simulation.InjectPerSec(rate: 200, during: TimeSpan.FromMinutes(1)),
            Simulation.KeepConstant(copies: 150, during: TimeSpan.FromMinutes(2)),
            Simulation.InjectPerSec(rate: 300, during: TimeSpan.FromMinutes(1))
        );
    }

    private static async Task<Response> GenerateKey(IScenarioContext context)
    {
        var request = new GenerateKeyRequestBuilder()
            .WithName($"load-test-key-{Guid.NewGuid()}")
            .WithAlgorithm(GetRandomKeyAlgorithm())
            .WithTag("LoadTest", "true")
            .Build();

        var response = await _client!.GenerateKeyAsync(request);
        
        if (response.Success != null)
        {
            lock (_generatedKeys)
            {
                _generatedKeys.Add(response.Success.KeyId);
                // Keep only last 100 keys to avoid memory issues
                if (_generatedKeys.Count > 100)
                {
                    _generatedKeys.RemoveAt(0);
                }
            }
        }

        return Response.Ok(statusCode: response.Success != null ? "200" : "500");
    }

    private static async Task<Response> SignData(IScenarioContext context)
    {
        var keyId = GetRandomKeyId();
        var request = new SignDataRequestBuilder()
            .WithKeyId(keyId)
            .WithData(GenerateRandomData())
            .WithAlgorithm(GetRandomSignatureAlgorithm())
            .Build();

        var response = await _client!.SignDataAsync(request);
        return Response.Ok(statusCode: response.Success != null ? "200" : "500");
    }

    private static async Task<Response> VerifySignature(IScenarioContext context)
    {
        var keyId = GetRandomKeyId();
        var request = new VerifySignatureRequestBuilder()
            .WithKeyId(keyId)
            .WithData(GenerateRandomData())
            .WithSignature(TestConstants.TestSignature)
            .WithAlgorithm(GetRandomSignatureAlgorithm())
            .Build();

        var response = await _client!.VerifySignatureAsync(request);
        return Response.Ok(statusCode: response.Success != null ? "200" : "500");
    }

    private static async Task<Response> EncryptData(IScenarioContext context)
    {
        var keyId = GetRandomKeyId();
        var request = new EncryptDataRequestBuilder()
            .WithKeyId(keyId)
            .WithPlaintext(GenerateRandomData())
            .WithAlgorithm(GetRandomEncryptionAlgorithm())
            .Build();

        var response = await _client!.EncryptDataAsync(request);
        return Response.Ok(statusCode: response.Success != null ? "200" : "500");
    }

    private static async Task<Response> DecryptData(IScenarioContext context)
    {
        var keyId = GetRandomKeyId();
        var request = new DecryptDataRequestBuilder()
            .WithKeyId(keyId)
            .WithCiphertext(TestConstants.TestCiphertext)
            .WithAlgorithm(GetRandomEncryptionAlgorithm())
            .Build();

        var response = await _client!.DecryptDataAsync(request);
        return Response.Ok(statusCode: response.Success != null ? "200" : "500");
    }

    private static async Task<Response> GetKey(IScenarioContext context)
    {
        var keyId = GetRandomKeyId();
        var request = new GetKeyRequestBuilder()
            .WithKeyId(keyId)
            .WithIncludePublicKey(_random.NextDouble() > 0.5)
            .Build();

        var response = await _client!.GetKeyAsync(request);
        return Response.Ok(statusCode: response.Success != null ? "200" : "500");
    }

    private static async Task<Response> ListKeys(IScenarioContext context)
    {
        var request = new ListKeysRequestBuilder()
            .WithPageSize(_random.Next(10, 51)) // Random page size between 10-50
            .WithIncludeDisabled(_random.NextDouble() > 0.8)
            .Build();

        var response = await _client!.ListKeysAsync(request);
        return Response.Ok(statusCode: response.Success != null ? "200" : "500");
    }

    private static async Task<Response> DeleteKey(IScenarioContext context)
    {
        var keyId = GetRandomKeyId();
        var request = new DeleteKeyRequestBuilder()
            .WithKeyId(keyId)
            .WithForce(_random.NextDouble() > 0.7)
            .Build();

        var response = await _client!.DeleteKeyAsync(request);
        return Response.Ok(statusCode: response.Success != null ? "200" : "500");
    }

    private static string GetRandomKeyId()
    {
        lock (_generatedKeys)
        {
            return _generatedKeys.Count > 0 
                ? _generatedKeys[_random.Next(_generatedKeys.Count)]
                : TestConstants.TestKeyId;
        }
    }

    private static KeyAlgorithm GetRandomKeyAlgorithm()
    {
        var algorithms = new[]
        {
            KeyAlgorithm.RsaPkcs1V2048,
            KeyAlgorithm.RsaPkcs1V3072,
            KeyAlgorithm.RsaPkcs1V4096,
            KeyAlgorithm.EcdsaP256,
            KeyAlgorithm.EcdsaP384,
            KeyAlgorithm.EcdsaP521
        };
        return algorithms[_random.Next(algorithms.Length)];
    }

    private static SignatureAlgorithm GetRandomSignatureAlgorithm()
    {
        var algorithms = new[]
        {
            SignatureAlgorithm.RsaPkcs1V15Sha256,
            SignatureAlgorithm.RsaPkcs1V15Sha384,
            SignatureAlgorithm.RsaPkcs1V15Sha512,
            SignatureAlgorithm.RsaPssV2048Sha256,
            SignatureAlgorithm.EcdsaP256Sha256,
            SignatureAlgorithm.EcdsaP384Sha384
        };
        return algorithms[_random.Next(algorithms.Length)];
    }

    private static EncryptionAlgorithm GetRandomEncryptionAlgorithm()
    {
        var algorithms = new[]
        {
            EncryptionAlgorithm.RsaOaep,
            EncryptionAlgorithm.RsaOaep256,
            EncryptionAlgorithm.Rsa15
        };
        return algorithms[_random.Next(algorithms.Length)];
    }

    private static byte[] GenerateRandomData()
    {
        var size = _random.Next(64, 1025); // Random size between 64 bytes and 1KB
        var data = new byte[size];
        _random.NextBytes(data);
        return data;
    }
}