using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using OpenTelemetry;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using System.Diagnostics;
using System.Reflection;
using Supacrypt.Backend.Configuration;
using Supacrypt.Backend.Observability.Metrics;
using Supacrypt.Backend.Observability.Tracing;
using Supacrypt.Backend.Observability.HealthChecks;

namespace Supacrypt.Backend.Observability;

public static class ObservabilityExtensions
{
    public static IServiceCollection AddSupacryptObservability(
        this IServiceCollection services,
        IConfiguration configuration,
        IHostEnvironment environment)
    {
        var observabilityOptions = configuration.GetSection("Observability").Get<ObservabilityOptions>() 
            ?? new ObservabilityOptions();

        // Register configuration
        services.Configure<ObservabilityOptions>(configuration.GetSection("Observability"));

        // Register metrics services
        services.AddSingleton<CryptoMetrics>();
        services.AddSingleton<AkvMetrics>();
        services.AddSingleton<SystemMetrics>();

        // Register tracing services
        services.AddSingleton<TracingEnricher>();

        // Configure resource attributes
        var resourceBuilder = ResourceBuilder.CreateDefault()
            .AddService(
                serviceName: observabilityOptions.ServiceName ?? "supacrypt-backend",
                serviceVersion: Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "1.0.0",
                serviceInstanceId: Environment.MachineName + "-" + Environment.ProcessId)
            .AddAttributes(new Dictionary<string, object>
            {
                ["deployment.environment"] = environment.EnvironmentName,
                ["service.namespace"] = "supacrypt",
                ["service.component"] = "backend",
                ["host.name"] = Environment.MachineName,
                ["process.pid"] = Environment.ProcessId,
                ["process.command"] = Environment.CommandLine,
                ["telemetry.sdk.name"] = "opentelemetry",
                ["telemetry.sdk.language"] = "dotnet",
                ["telemetry.sdk.version"] = "1.9.0"
            });

        // Add cloud provider attributes if available
        if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("AZURE_RESOURCE_GROUP")))
        {
            resourceBuilder.AddAttributes(new Dictionary<string, object>
            {
                ["cloud.provider"] = "azure",
                ["cloud.platform"] = "azure_app_service",
                ["cloud.region"] = Environment.GetEnvironmentVariable("AZURE_REGION") ?? "unknown",
                ["cloud.resource_id"] = Environment.GetEnvironmentVariable("AZURE_RESOURCE_ID") ?? "unknown"
            });
        }

        // Configure OpenTelemetry
        services.AddOpenTelemetry()
            .ConfigureResource(resource => resource = resourceBuilder)
            .WithTracing(tracing =>
            {
                if (observabilityOptions.Tracing?.Enabled == true)
                {
                    tracing
                        .AddSource(ActivitySources.CryptoOperations.Name)
                        .AddSource(ActivitySources.AzureKeyVault.Name)
                        .AddSource(ActivitySources.GrpcService.Name)
                        .AddSource(ActivitySources.HealthChecks.Name)
                        .AddAspNetCoreInstrumentation(options =>
                        {
                            options.RecordException = true;
                            options.EnableGrpcAspNetCoreSupport = true;
                            options.Filter = httpContext =>
                            {
                                // Filter out health check requests unless debugging
                                if (httpContext.Request.Path.StartsWithSegments("/health"))
                                    return environment.IsDevelopment();
                                return true;
                            };
                        })
                        .AddGrpcClientInstrumentation(options =>
                        {
                            options.RecordException = true;
                        })
                        .AddHttpClientInstrumentation(options =>
                        {
                            options.RecordException = true;
                            options.FilterHttpRequestMessage = request =>
                            {
                                // Only trace Azure Key Vault requests
                                return request.RequestUri?.Host?.Contains("vault.azure.net") == true;
                            };
                        });

                    // Configure sampling
                    var samplingRatio = observabilityOptions.Tracing?.SamplingRatio ?? 0.1;
                    if (environment.IsDevelopment())
                    {
                        samplingRatio = 1.0; // 100% sampling in development
                    }

                    tracing.SetSampler(new TraceIdRatioBasedSampler(samplingRatio));

                    // Add processors
                    tracing.AddProcessor(new BatchActivityExportProcessor(
                        new ConsoleActivityExporter(), 
                        maxQueueSize: 2048,
                        scheduledDelayMilliseconds: 5000,
                        exporterTimeoutMilliseconds: 30000,
                        maxExportBatchSize: 512));

                    // Configure exporters
                    ConfigureTracingExporters(tracing, observabilityOptions, environment);
                }
            })
            .WithMetrics(metrics =>
            {
                if (observabilityOptions.Metrics?.Enabled == true)
                {
                    metrics
                        .AddMeter(CryptoMetrics.MeterName)
                        .AddMeter(AkvMetrics.MeterName)
                        .AddMeter(SystemMetrics.MeterName)
                        .AddAspNetCoreInstrumentation()
                        .AddHttpClientInstrumentation()
                        .AddRuntimeInstrumentation()
                        .AddProcessInstrumentation();

                    // Configure export interval
                    var exportInterval = observabilityOptions.Metrics?.ExportInterval ?? 60000;
                    metrics.AddReader(new PeriodicExportingMetricReader(
                        new ConsoleMetricExporter(),
                        exportIntervalMilliseconds: exportInterval));

                    // Configure exporters
                    ConfigureMetricsExporters(metrics, observabilityOptions, environment);
                }
            })
            .WithLogging(logging =>
            {
                if (observabilityOptions.Logging?.IncludeScopes == true)
                {
                    logging.IncludeScopes = true;
                }
                
                if (observabilityOptions.Logging?.IncludeFormattedMessage == true)
                {
                    logging.IncludeFormattedMessage = true;
                }

                // Configure log exporters
                ConfigureLoggingExporters(logging, observabilityOptions, environment);
            });

        // Add enhanced health checks
        services.AddHealthChecks()
            .AddCheck<ObservabilityHealthCheck>("observability");

        return services;
    }

    private static void ConfigureTracingExporters(
        TracerProviderBuilder tracing,
        ObservabilityOptions options,
        IHostEnvironment environment)
    {
        if (environment.IsDevelopment())
        {
            // Console exporter for development
            tracing.AddConsoleExporter();
        }

        // OTLP exporter configuration
        if (!string.IsNullOrEmpty(options.Exporters?.Otlp?.Endpoint))
        {
            tracing.AddOtlpExporter(otlpOptions =>
            {
                otlpOptions.Endpoint = new Uri(options.Exporters.Otlp.Endpoint);
                otlpOptions.Protocol = OpenTelemetry.Exporter.OtlpExportProtocol.Grpc;
                
                if (!string.IsNullOrEmpty(options.Exporters.Otlp.Headers))
                {
                    otlpOptions.Headers = options.Exporters.Otlp.Headers;
                }

                otlpOptions.TimeoutMilliseconds = options.Exporters.Otlp.Timeout ?? 10000;
            });
        }
    }

    private static void ConfigureMetricsExporters(
        MeterProviderBuilder metrics,
        ObservabilityOptions options,
        IHostEnvironment environment)
    {
        if (environment.IsDevelopment())
        {
            // Console exporter for development
            metrics.AddConsoleExporter();
        }

        // OTLP exporter configuration
        if (!string.IsNullOrEmpty(options.Exporters?.Otlp?.Endpoint))
        {
            metrics.AddOtlpExporter(otlpOptions =>
            {
                otlpOptions.Endpoint = new Uri(options.Exporters.Otlp.Endpoint);
                otlpOptions.Protocol = OpenTelemetry.Exporter.OtlpExportProtocol.Grpc;
                
                if (!string.IsNullOrEmpty(options.Exporters.Otlp.Headers))
                {
                    otlpOptions.Headers = options.Exporters.Otlp.Headers;
                }

                otlpOptions.TimeoutMilliseconds = options.Exporters.Otlp.Timeout ?? 10000;
            });
        }
    }

    private static void ConfigureLoggingExporters(
        OpenTelemetryLoggerOptions logging,
        ObservabilityOptions options,
        IHostEnvironment environment)
    {
        if (environment.IsDevelopment())
        {
            // Console exporter for development
            logging.AddConsoleExporter();
        }

        // OTLP exporter configuration
        if (!string.IsNullOrEmpty(options.Exporters?.Otlp?.Endpoint))
        {
            logging.AddOtlpExporter(otlpOptions =>
            {
                otlpOptions.Endpoint = new Uri(options.Exporters.Otlp.Endpoint);
                otlpOptions.Protocol = OpenTelemetry.Exporter.OtlpExportProtocol.Grpc;
                
                if (!string.IsNullOrEmpty(options.Exporters.Otlp.Headers))
                {
                    otlpOptions.Headers = options.Exporters.Otlp.Headers;
                }

                otlpOptions.TimeoutMilliseconds = options.Exporters.Otlp.Timeout ?? 10000;
            });
        }
    }
}

public class ObservabilityOptions
{
    public string? ServiceName { get; set; } = "supacrypt-backend";
    public MetricsOptions? Metrics { get; set; } = new();
    public TracingOptions? Tracing { get; set; } = new();
    public LoggingOptions? Logging { get; set; } = new();
    public ExportersOptions? Exporters { get; set; } = new();
}

public class MetricsOptions
{
    public bool Enabled { get; set; } = true;
    public int ExportInterval { get; set; } = 60000; // 60 seconds
    public bool Exemplars { get; set; } = true;
}

public class TracingOptions
{
    public bool Enabled { get; set; } = true;
    public double SamplingRatio { get; set; } = 0.1; // 10% sampling
    public bool AlwaysSampleErrors { get; set; } = true;
}

public class LoggingOptions
{
    public bool IncludeScopes { get; set; } = true;
    public bool IncludeFormattedMessage { get; set; } = true;
}

public class ExportersOptions
{
    public OtlpOptions? Otlp { get; set; } = new();
}

public class OtlpOptions
{
    public string Endpoint { get; set; } = "http://localhost:4317";
    public string? Headers { get; set; }
    public int? Timeout { get; set; } = 10000;
}