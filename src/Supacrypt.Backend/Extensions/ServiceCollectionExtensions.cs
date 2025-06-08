using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication.Certificate;
using Supacrypt.Backend.Configuration;
using Supacrypt.Backend.Services.Security;
using Supacrypt.Backend.Services.Security.Interfaces;

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

    public static IServiceCollection AddSupacryptSecurity(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.Configure<SecurityOptions>(configuration.GetSection(SecurityOptions.SectionName));
        
        services.AddSingleton<ICertificateLoader, CertificateLoader>();
        services.AddScoped<ICertificateValidationService, CertificateValidationService>();
        services.AddSingleton<ISecurityEventLogger, SecurityEventLogger>();
        
        services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
            .AddCertificate(options =>
            {
                options.Events = new CertificateAuthenticationEvents
                {
                    OnCertificateValidated = context =>
                    {
                        // Additional validation logic can be added here if needed
                        return Task.CompletedTask;
                    }
                };
            });

        services.AddAuthorization(options =>
        {
            options.AddPolicy("RequireValidCertificate", policy =>
                policy.RequireAuthenticatedUser());

            options.AddPolicy("RequireSpecificProvider", policy =>
                policy.RequireClaim("Provider", "PKCS11", "CSP", "KSP", "CTK"));

            options.AddPolicy("RequireAdminCertificate", policy =>
                policy.RequireClaim("CertificateRole", "Admin"));
        });
        
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