using Microsoft.Extensions.Options;
using Supacrypt.Backend.Configuration;

namespace Supacrypt.Backend.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddCryptographicServices(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.Configure<AzureKeyVaultOptions>(
            configuration.GetSection(AzureKeyVaultOptions.SectionName));
        
        services.Configure<SecurityOptions>(
            configuration.GetSection(SecurityOptions.SectionName));
        
        services.Configure<OpenTelemetryOptions>(
            configuration.GetSection(OpenTelemetryOptions.SectionName));

        services.AddSingleton<IValidateOptions<AzureKeyVaultOptions>, AzureKeyVaultOptionsValidator>();

        return services;
    }
}

public class AzureKeyVaultOptionsValidator : IValidateOptions<AzureKeyVaultOptions>
{
    public ValidateOptionsResult Validate(string? name, AzureKeyVaultOptions options)
    {
        var failures = new List<string>();

        if (string.IsNullOrEmpty(options.VaultUri))
        {
            failures.Add("VaultUri is required");
        }

        if (!Uri.TryCreate(options.VaultUri, UriKind.Absolute, out _))
        {
            failures.Add("VaultUri must be a valid URI");
        }

        if (string.IsNullOrEmpty(options.ClientId))
        {
            failures.Add("ClientId is required");
        }

        if (string.IsNullOrEmpty(options.TenantId))
        {
            failures.Add("TenantId is required");
        }

        return failures.Count > 0
            ? ValidateOptionsResult.Fail(failures)
            : ValidateOptionsResult.Success;
    }
}