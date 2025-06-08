using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Grpc.Net.Client;
using Supacrypt.V1;
using System.Security.Cryptography.X509Certificates;
using Supacrypt.Backend.Services.Interfaces;
using Supacrypt.Backend.Tests.TestHelpers;

namespace Supacrypt.Backend.IntegrationTests.Fixtures;

public class TestServerFixture : WebApplicationFactory<Program>, IAsyncLifetime
{
    private GrpcChannel? _channel;
    private SupacryptService.SupacryptServiceClient? _client;

    public TestServer Server { get; private set; } = null!;
    public GrpcChannel Channel => _channel ?? throw new InvalidOperationException("Channel not initialized");
    public SupacryptService.SupacryptServiceClient Client => _client ?? throw new InvalidOperationException("Client not initialized");
    public X509Certificate2 TestClientCertificate { get; private set; } = null!;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((context, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["AzureKeyVault:VaultUri"] = TestConstants.TestVaultUri,
                ["AzureKeyVault:UseManagedIdentity"] = "false",
                ["AzureKeyVault:UseMockImplementation"] = "true",
                ["Security:RequireClientCertificate"] = "false", // Disable for integration tests
                ["Logging:LogLevel:Default"] = "Information",
                ["Logging:LogLevel:Supacrypt"] = "Debug"
            });
        });

        builder.ConfigureTestServices(services =>
        {
            // Replace Azure Key Vault services with mock implementations
            services.AddSingleton<IKeyManagementService>(provider =>
                MockFactories.CreateKeyManagementService().Object);
            
            services.AddSingleton<ICryptographicOperations>(provider =>
                MockFactories.CreateCryptographicOperations().Object);
        });

        builder.UseTestServer();
    }

    public async Task InitializeAsync()
    {
        TestClientCertificate = MockFactories.CreateTestCertificate();
        
        Server = base.Server;
        
        var httpHandler = Server.CreateHandler();
        _channel = GrpcChannel.ForAddress(Server.BaseAddress, new GrpcChannelOptions
        {
            HttpHandler = httpHandler,
            LoggerFactory = Services.GetRequiredService<ILoggerFactory>()
        });
        
        _client = new SupacryptService.SupacryptServiceClient(_channel);
        
        await Task.CompletedTask;
    }

    public new async Task DisposeAsync()
    {
        _channel?.Dispose();
        TestClientCertificate?.Dispose();
        await base.DisposeAsync();
    }
}

public class AzureKeyVaultFixture : IAsyncLifetime
{
    public string VaultUri { get; } = TestConstants.TestVaultUri;
    public string TestKeyName { get; } = TestConstants.TestKeyName;
    public bool UseRealAzureKeyVault { get; private set; }
    
    public async Task InitializeAsync()
    {
        // Check if we should use real Azure Key Vault for integration tests
        UseRealAzureKeyVault = Environment.GetEnvironmentVariable("USE_REAL_AZURE_KV") == "true";
        
        if (UseRealAzureKeyVault)
        {
            // Validate Azure credentials are available
            var tenantId = Environment.GetEnvironmentVariable("AZURE_TENANT_ID");
            var clientId = Environment.GetEnvironmentVariable("AZURE_CLIENT_ID");
            var clientSecret = Environment.GetEnvironmentVariable("AZURE_CLIENT_SECRET");
            
            if (string.IsNullOrEmpty(tenantId) || string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
            {
                throw new InvalidOperationException(
                    "Azure credentials not found. Set AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET environment variables.");
            }
        }
        
        await Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        // Clean up any test keys created in real Azure Key Vault
        if (UseRealAzureKeyVault)
        {
            // Implementation would clean up test resources
        }
        
        await Task.CompletedTask;
    }
}

public class TestCertificateFixture : IAsyncLifetime
{
    public X509Certificate2 ValidClientCertificate { get; private set; } = null!;
    public X509Certificate2 ExpiredClientCertificate { get; private set; } = null!;
    public X509Certificate2 InvalidClientCertificate { get; private set; } = null!;
    public X509Certificate2 RootCaCertificate { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        ValidClientCertificate = MockFactories.CreateTestCertificate(
            "CN=Valid Test Client", 
            isValid: true, 
            X509KeyUsageFlags.DigitalSignature);
            
        ExpiredClientCertificate = MockFactories.CreateTestCertificate(
            "CN=Expired Test Client", 
            isValid: false, 
            X509KeyUsageFlags.DigitalSignature);
            
        InvalidClientCertificate = MockFactories.CreateTestCertificate(
            "CN=Invalid Test Client", 
            isValid: true, 
            X509KeyUsageFlags.KeyEncipherment); // Wrong usage
            
        RootCaCertificate = MockFactories.CreateTestCertificate(
            "CN=Test Root CA", 
            isValid: true, 
            X509KeyUsageFlags.KeyCertSign);
        
        await Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        ValidClientCertificate?.Dispose();
        ExpiredClientCertificate?.Dispose();
        InvalidClientCertificate?.Dispose();
        RootCaCertificate?.Dispose();
        
        await Task.CompletedTask;
    }
}