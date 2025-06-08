using System.ComponentModel.DataAnnotations;

namespace Supacrypt.Backend.Configuration;

public class OpenTelemetryOptions
{
    public const string SectionName = "OpenTelemetry";

    [Required]
    public string ServiceName { get; set; } = "supacrypt-backend";

    [Required]
    public string ServiceVersion { get; set; } = "1.0.0";

    public OtlpOptions Otlp { get; set; } = new();
}

public class OtlpOptions
{
    public string Endpoint { get; set; } = "http://localhost:4317";
}