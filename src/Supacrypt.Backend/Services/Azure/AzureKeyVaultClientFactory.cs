using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Microsoft.Extensions.Options;
using Supacrypt.Backend.Configuration;

namespace Supacrypt.Backend.Services.Azure;

public interface IAzureKeyVaultClientFactory
{
    KeyClient CreateKeyClient();
}

public class AzureKeyVaultClientFactory : IAzureKeyVaultClientFactory
{
    private readonly AzureKeyVaultOptions _options;
    private readonly ILogger<AzureKeyVaultClientFactory> _logger;
    private readonly Lazy<KeyClient> _keyClient;

    public AzureKeyVaultClientFactory(
        IOptions<AzureKeyVaultOptions> options,
        ILogger<AzureKeyVaultClientFactory> logger)
    {
        _options = options.Value;
        _logger = logger;
        _keyClient = new Lazy<KeyClient>(CreateKeyClientInternal);
    }

    public KeyClient CreateKeyClient() => _keyClient.Value;

    private KeyClient CreateKeyClientInternal()
    {
        var credential = CreateTokenCredential();
        var vaultUri = new Uri(_options.VaultUri);
        
        var keyClientOptions = new KeyClientOptions()
        {
            Retry =
            {
                Delay = _options.RetryOptions.Delay,
                MaxRetries = _options.RetryOptions.MaxRetries,
                MaxDelay = _options.RetryOptions.MaxDelay,
                Mode = _options.RetryOptions.Mode switch
                {
                    "Fixed" => RetryMode.Fixed,
                    "Exponential" => RetryMode.Exponential,
                    _ => RetryMode.Exponential
                }
            }
        };

        _logger.LogInformation("Creating Azure Key Vault client for vault: {VaultUri}", vaultUri);
        
        return new KeyClient(vaultUri, credential, keyClientOptions);
    }

    private TokenCredential CreateTokenCredential()
    {
        if (_options.UseManagedIdentity)
        {
            _logger.LogInformation("Using Managed Identity for Azure Key Vault authentication");
            return new ManagedIdentityCredential();
        }

        if (!string.IsNullOrEmpty(_options.ClientId) && !string.IsNullOrEmpty(_options.TenantId))
        {
            if (!string.IsNullOrEmpty(_options.ClientSecret))
            {
                _logger.LogInformation("Using Service Principal with Client Secret for Azure Key Vault authentication");
                return new ClientSecretCredential(_options.TenantId, _options.ClientId, _options.ClientSecret);
            }
            
            _logger.LogInformation("Using Service Principal with Certificate for Azure Key Vault authentication");
            return new ClientCertificateCredential(_options.TenantId, _options.ClientId, string.Empty);
        }

        _logger.LogInformation("Using DefaultAzureCredential (includes Azure CLI) for Azure Key Vault authentication");
        return new DefaultAzureCredential(new DefaultAzureCredentialOptions
        {
            ExcludeEnvironmentCredential = false,
            ExcludeInteractiveBrowserCredential = true,
            ExcludeManagedIdentityCredential = false,
            ExcludeSharedTokenCacheCredential = false,
            ExcludeVisualStudioCredential = false,
            ExcludeVisualStudioCodeCredential = false,
            ExcludeAzureCliCredential = false,
            ExcludeAzurePowerShellCredential = true
        });
    }
}