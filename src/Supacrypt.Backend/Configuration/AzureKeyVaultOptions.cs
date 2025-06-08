using System.ComponentModel.DataAnnotations;

namespace Supacrypt.Backend.Configuration;

public class AzureKeyVaultOptions
{
    public const string SectionName = "AzureKeyVault";

    [Required]
    public string VaultUri { get; set; } = string.Empty;

    public string? ClientId { get; set; }
    public string? TenantId { get; set; }
    public string? ClientSecret { get; set; }
    public bool UseManagedIdentity { get; set; } = true;

    public RetryOptions RetryOptions { get; set; } = new();
    public CircuitBreakerOptions CircuitBreaker { get; set; } = new();
}

public class RetryOptions
{
    public int MaxRetries { get; set; } = 3;
    public TimeSpan Delay { get; set; } = TimeSpan.FromSeconds(2);
    public TimeSpan MaxDelay { get; set; } = TimeSpan.FromSeconds(16);
    public string Mode { get; set; } = "Exponential";
}

public class CircuitBreakerOptions
{
    public int HandledEventsAllowedBeforeBreaking { get; set; } = 3;
    public TimeSpan DurationOfBreak { get; set; } = TimeSpan.FromSeconds(30);
}