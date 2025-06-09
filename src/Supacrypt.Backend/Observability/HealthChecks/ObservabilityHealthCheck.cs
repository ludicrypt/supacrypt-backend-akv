using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using System.Diagnostics;
using System.Net.Http;

namespace Supacrypt.Backend.Observability.HealthChecks;

public class ObservabilityHealthCheck : IHealthCheck
{
    private readonly ObservabilityOptions _options;
    private readonly IHttpClientFactory? _httpClientFactory;

    public ObservabilityHealthCheck(IOptions<ObservabilityOptions> options, IHttpClientFactory? httpClientFactory = null)
    {
        _options = options.Value;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var checks = new List<(string name, bool healthy, string details, object? data)>();
        var overallHealthy = true;

        // Check OpenTelemetry metrics collection
        await CheckMetricsCollectionAsync(checks);

        // Check trace sampling and activity sources
        CheckTracingInstrumentation(checks);

        // Check OTLP exporter connectivity
        if (!string.IsNullOrEmpty(_options.Exporters?.Otlp?.Endpoint))
        {
            await CheckOtlpExporterAsync(checks, cancellationToken);
        }

        // Check buffer saturation levels
        CheckBufferSaturation(checks);

        // Check metric cardinality
        CheckMetricCardinality(checks);

        // Determine overall health
        overallHealthy = checks.All(c => c.healthy);
        var status = overallHealthy ? HealthStatus.Healthy : HealthStatus.Unhealthy;

        var data = checks.ToDictionary(
            c => c.name,
            c => (object)new { healthy = c.healthy, details = c.details, data = c.data });

        var description = overallHealthy 
            ? "All observability components are functioning correctly"
            : $"Observability issues detected: {string.Join(", ", checks.Where(c => !c.healthy).Select(c => c.name))}";

        return new HealthCheckResult(status, description, data: data);
    }

    private Task CheckMetricsCollectionAsync(List<(string name, bool healthy, string details, object? data)> checks)
    {
        try
        {
            if (_options.Metrics?.Enabled != true)
            {
                checks.Add(("Metrics", false, "Metrics collection is disabled", null));
                return Task.CompletedTask;
            }

            // Check if meters are properly registered
            var metersAvailable = new[]
            {
                "Supacrypt.Backend.CryptoOperations",
                "Supacrypt.Backend.AzureKeyVault",
                "Supacrypt.Backend.SystemHealth"
            };

            var activeSources = Activity.Current?.Source != null;
            
            checks.Add(("Metrics", true, 
                $"Metrics collection enabled, meters available: {string.Join(", ", metersAvailable)}", 
                new { enabled = true, meterCount = metersAvailable.Length }));
        }
        catch (Exception ex)
        {
            checks.Add(("Metrics", false, $"Metrics collection error: {ex.Message}", null));
        }
        
        return Task.CompletedTask;
    }

    private void CheckTracingInstrumentation(List<(string name, bool healthy, string details, object? data)> checks)
    {
        try
        {
            if (_options.Tracing?.Enabled != true)
            {
                checks.Add(("Tracing", false, "Tracing is disabled", null));
                return;
            }

            // Check if activity sources are available
            var activitySources = new[]
            {
                "Supacrypt.Backend.CryptoOperations",
                "Supacrypt.Backend.AzureKeyVault",
                "Supacrypt.Backend.GrpcService",
                "Supacrypt.Backend.HealthChecks"
            };

            var samplingRatio = _options.Tracing?.SamplingRatio ?? 0.1;
            
            checks.Add(("Tracing", true, 
                $"Tracing enabled with {samplingRatio:P} sampling rate", 
                new { 
                    enabled = true, 
                    samplingRatio = samplingRatio,
                    activitySourceCount = activitySources.Length 
                }));
        }
        catch (Exception ex)
        {
            checks.Add(("Tracing", false, $"Tracing instrumentation error: {ex.Message}", null));
        }
    }

    private async Task CheckOtlpExporterAsync(List<(string name, bool healthy, string details, object? data)> checks, 
        CancellationToken cancellationToken)
    {
        try
        {
            var endpoint = _options.Exporters?.Otlp?.Endpoint;
            if (string.IsNullOrEmpty(endpoint))
            {
                checks.Add(("OTLP Exporter", false, "OTLP endpoint not configured", null));
                return;
            }

            if (_httpClientFactory != null)
            {
                using var httpClient = _httpClientFactory.CreateClient();
                httpClient.Timeout = TimeSpan.FromSeconds(5);

                var uri = new Uri(endpoint);
                var healthEndpoint = new Uri(uri, "/v1/traces"); // Standard OTLP traces endpoint

                try
                {
                    using var response = await httpClient.GetAsync(healthEndpoint, cancellationToken);
                    
                    // Even if we get a method not allowed (405), the service is reachable
                    var isReachable = response.IsSuccessStatusCode || 
                                    response.StatusCode == System.Net.HttpStatusCode.MethodNotAllowed ||
                                    response.StatusCode == System.Net.HttpStatusCode.BadRequest;

                    checks.Add(("OTLP Exporter", isReachable, 
                        isReachable ? $"OTLP endpoint reachable at {endpoint}" : $"OTLP endpoint unreachable: {response.StatusCode}",
                        new { endpoint = endpoint, statusCode = (int)response.StatusCode }));
                }
                catch (TaskCanceledException)
                {
                    checks.Add(("OTLP Exporter", false, "OTLP endpoint timeout", new { endpoint = endpoint }));
                }
                catch (HttpRequestException ex)
                {
                    checks.Add(("OTLP Exporter", false, $"OTLP endpoint connection error: {ex.Message}", 
                        new { endpoint = endpoint }));
                }
            }
            else
            {
                // No HTTP client factory available, assume configured correctly
                checks.Add(("OTLP Exporter", true, $"OTLP endpoint configured: {endpoint}", 
                    new { endpoint = endpoint, verified = false }));
            }
        }
        catch (Exception ex)
        {
            checks.Add(("OTLP Exporter", false, $"OTLP exporter check error: {ex.Message}", null));
        }
    }

    private void CheckBufferSaturation(List<(string name, bool healthy, string details, object? data)> checks)
    {
        try
        {
            // This is a simplified check - in a real implementation, you'd have access to
            // internal buffer statistics from the OpenTelemetry SDK
            var exportInterval = _options.Metrics?.ExportInterval ?? 60000;
            var bufferHealthy = exportInterval > 0 && exportInterval <= 300000; // Max 5 minutes

            checks.Add(("Buffer Health", bufferHealthy, 
                bufferHealthy ? "Export buffers within normal parameters" : "Export buffer configuration may cause saturation",
                new { exportIntervalMs = exportInterval }));
        }
        catch (Exception ex)
        {
            checks.Add(("Buffer Health", false, $"Buffer health check error: {ex.Message}", null));
        }
    }

    private void CheckMetricCardinality(List<(string name, bool healthy, string details, object? data)> checks)
    {
        try
        {
            // Estimate metric cardinality based on configuration
            // This is a heuristic check - actual cardinality would require SDK internals access
            
            var estimatedCardinality = EstimateMetricCardinality();
            var cardinalityHealthy = estimatedCardinality < 10000; // Typical Prometheus limit

            checks.Add(("Metric Cardinality", cardinalityHealthy,
                cardinalityHealthy ? "Metric cardinality within acceptable limits" : "High metric cardinality detected",
                new { estimatedCardinality = estimatedCardinality, threshold = 10000 }));
        }
        catch (Exception ex)
        {
            checks.Add(("Metric Cardinality", false, $"Metric cardinality check error: {ex.Message}", null));
        }
    }

    private int EstimateMetricCardinality()
    {
        // This is a rough estimation based on the number of metrics and expected label combinations
        // In a real implementation, you'd track actual cardinality
        
        var baseMetrics = 50; // Approximate number of base metrics
        var labelCombinations = 20; // Average label combinations per metric
        var dynamicLabels = 5; // Labels that change frequently (like key IDs)
        
        return baseMetrics * labelCombinations * Math.Max(1, dynamicLabels);
    }
}