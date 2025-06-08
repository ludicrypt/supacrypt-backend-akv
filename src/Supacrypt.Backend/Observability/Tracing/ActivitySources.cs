using System.Diagnostics;
using System.Reflection;

namespace Supacrypt.Backend.Observability.Tracing;

public static class ActivitySources
{
    private static readonly AssemblyName AssemblyName = typeof(ActivitySources).Assembly.GetName();
    private static readonly string Version = AssemblyName.Version?.ToString() ?? "1.0.0";

    public static readonly ActivitySource CryptoOperations = new(
        "Supacrypt.Backend.CryptoOperations", 
        Version);

    public static readonly ActivitySource AzureKeyVault = new(
        "Supacrypt.Backend.AzureKeyVault", 
        Version);

    public static readonly ActivitySource GrpcService = new(
        "Supacrypt.Backend.GrpcService", 
        Version);

    public static readonly ActivitySource HealthChecks = new(
        "Supacrypt.Backend.HealthChecks", 
        Version);

    public static readonly ActivitySource Authentication = new(
        "Supacrypt.Backend.Authentication", 
        Version);

    public static void Dispose()
    {
        CryptoOperations.Dispose();
        AzureKeyVault.Dispose();
        GrpcService.Dispose();
        HealthChecks.Dispose();
        Authentication.Dispose();
    }
}