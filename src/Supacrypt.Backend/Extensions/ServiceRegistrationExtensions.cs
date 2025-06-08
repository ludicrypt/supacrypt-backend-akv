using FluentValidation;
using Supacrypt.Backend.Configuration;
using Supacrypt.Backend.Services;
using Supacrypt.Backend.Services.Azure;
using Supacrypt.Backend.Services.Interfaces;
using Supacrypt.Backend.Services.Mock;
using Supacrypt.Backend.Telemetry;
using Supacrypt.Backend.Validation;
using Supacrypt.V1;

namespace Supacrypt.Backend.Extensions;

public static class ServiceRegistrationExtensions
{
    public static IServiceCollection AddSupacryptServices(this IServiceCollection services)
    {
        // Azure Key Vault services
        services.AddSingleton<IAzureKeyVaultClientFactory, AzureKeyVaultClientFactory>();
        services.AddSingleton<IAzureKeyVaultResiliencePolicy, AzureKeyVaultResiliencePolicy>();
        services.AddSingleton<IAzureKeyVaultMetrics, AzureKeyVaultMetrics>();

        // Core services with Azure implementations
        services.AddScoped<IKeyRepository, AzureKeyVaultKeyRepository>();
        services.AddScoped<IKeyManagementService, AzureKeyVaultKeyManagementService>();
        services.AddScoped<ICryptographicOperations, AzureKeyVaultCryptographicOperations>();

        // Performance tracking
        services.AddSingleton<PerformanceTracker>();

        // Validators
        services.AddScoped<IValidator<GenerateKeyRequest>, GenerateKeyRequestValidator>();
        services.AddScoped<IValidator<SignDataRequest>, SignDataRequestValidator>();
        services.AddScoped<IValidator<VerifySignatureRequest>, VerifySignatureRequestValidator>();
        services.AddScoped<IValidator<GetKeyRequest>, GetKeyRequestValidator>();
        services.AddScoped<IValidator<ListKeysRequest>, ListKeysRequestValidator>();
        services.AddScoped<IValidator<DeleteKeyRequest>, DeleteKeyRequestValidator>();
        services.AddScoped<IValidator<EncryptDataRequest>, EncryptDataRequestValidator>();
        services.AddScoped<IValidator<DecryptDataRequest>, DecryptDataRequestValidator>();

        return services;
    }

    public static IServiceCollection AddSupacryptAzureKeyVaultConfiguration(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<AzureKeyVaultOptions>(
            configuration.GetSection(AzureKeyVaultOptions.SectionName));

        return services;
    }

    public static IServiceCollection AddSupacryptGrpc(this IServiceCollection services)
    {
        services.AddGrpc(options =>
        {
            options.MaxReceiveMessageSize = 1024 * 1024 * 4;
            options.MaxSendMessageSize = 1024 * 1024 * 4;
            options.EnableDetailedErrors = true;
        });

        services.AddGrpcReflection();

        return services;
    }
}