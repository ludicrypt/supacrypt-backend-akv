namespace Supacrypt.Backend.Configuration;

public class SecurityOptions
{
    public const string SectionName = "Security";

    public MTLSOptions MTLS { get; set; } = new();
}

public class MTLSOptions
{
    public bool Enabled { get; set; } = true;
    public bool RequireClientCertificate { get; set; } = true;
    public string ValidationMode { get; set; } = "ChainTrust";
    public string[] AllowedThumbprints { get; set; } = Array.Empty<string>();
}