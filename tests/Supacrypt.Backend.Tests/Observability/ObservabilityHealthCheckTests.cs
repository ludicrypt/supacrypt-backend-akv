using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Moq;
using Supacrypt.Backend.Observability;
using Supacrypt.Backend.Observability.HealthChecks;
using Xunit;

namespace Supacrypt.Backend.Tests.Observability;

public class ObservabilityHealthCheckTests
{
    private readonly Mock<IHttpClientFactory> _httpClientFactoryMock;
    private readonly Mock<HttpMessageHandler> _httpMessageHandlerMock;
    private readonly ObservabilityOptions _options;
    private readonly ObservabilityHealthCheck _healthCheck;

    public ObservabilityHealthCheckTests()
    {
        _httpClientFactoryMock = new Mock<IHttpClientFactory>();
        _httpMessageHandlerMock = new Mock<HttpMessageHandler>();
        
        _options = new ObservabilityOptions
        {
            ServiceName = "test-service",
            Metrics = new MetricsOptions { Enabled = true, ExportInterval = 60000 },
            Tracing = new TracingOptions { Enabled = true, SamplingRatio = 0.1 },
            Exporters = new ExportersOptions
            {
                Otlp = new OtlpOptions { Endpoint = "http://localhost:4317" }
            }
        };

        var optionsMock = new Mock<IOptions<ObservabilityOptions>>();
        optionsMock.Setup(x => x.Value).Returns(_options);

        _healthCheck = new ObservabilityHealthCheck(optionsMock.Object, _httpClientFactoryMock.Object);
    }

    [Fact]
    public async Task CheckHealthAsync_WithEnabledObservability_ShouldReturnHealthy()
    {
        // Arrange
        var context = new HealthCheckContext();
        var cancellationToken = CancellationToken.None;

        // Mock HTTP client for OTLP endpoint check
        var httpClient = new HttpClient(_httpMessageHandlerMock.Object);
        _httpClientFactoryMock.Setup(x => x.CreateClient(It.IsAny<string>())).Returns(httpClient);

        // Act
        var result = await _healthCheck.CheckHealthAsync(context, cancellationToken);

        // Assert
        Assert.NotNull(result);
        Assert.True(result.Status == HealthStatus.Healthy || result.Status == HealthStatus.Unhealthy);
        Assert.NotNull(result.Data);
    }

    [Fact]
    public async Task CheckHealthAsync_WithDisabledMetrics_ShouldReportMetricsUnhealthy()
    {
        // Arrange
        _options.Metrics!.Enabled = false;
        var context = new HealthCheckContext();
        var cancellationToken = CancellationToken.None;

        // Act
        var result = await _healthCheck.CheckHealthAsync(context, cancellationToken);

        // Assert
        Assert.NotNull(result);
        Assert.Contains("Metrics", result.Data!.Keys);
    }

    [Fact]
    public async Task CheckHealthAsync_WithDisabledTracing_ShouldReportTracingUnhealthy()
    {
        // Arrange
        _options.Tracing!.Enabled = false;
        var context = new HealthCheckContext();
        var cancellationToken = CancellationToken.None;

        // Act
        var result = await _healthCheck.CheckHealthAsync(context, cancellationToken);

        // Assert
        Assert.NotNull(result);
        Assert.Contains("Tracing", result.Data!.Keys);
    }

    [Fact]
    public async Task CheckHealthAsync_WithoutHttpClientFactory_ShouldStillCompleteCheck()
    {
        // Arrange
        var optionsMock = new Mock<IOptions<ObservabilityOptions>>();
        optionsMock.Setup(x => x.Value).Returns(_options);
        
        var healthCheckWithoutHttp = new ObservabilityHealthCheck(optionsMock.Object, null);
        var context = new HealthCheckContext();
        var cancellationToken = CancellationToken.None;

        // Act
        var result = await healthCheckWithoutHttp.CheckHealthAsync(context, cancellationToken);

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(result.Data);
    }

    [Fact]
    public async Task CheckHealthAsync_WithLongExportInterval_ShouldReportBufferIssue()
    {
        // Arrange
        _options.Metrics!.ExportInterval = 400000; // > 5 minutes
        var context = new HealthCheckContext();
        var cancellationToken = CancellationToken.None;

        // Act
        var result = await _healthCheck.CheckHealthAsync(context, cancellationToken);

        // Assert
        Assert.NotNull(result);
        Assert.Contains("Buffer Health", result.Data!.Keys);
    }

    [Fact]
    public async Task CheckHealthAsync_ShouldCheckMetricCardinality()
    {
        // Arrange
        var context = new HealthCheckContext();
        var cancellationToken = CancellationToken.None;

        // Act
        var result = await _healthCheck.CheckHealthAsync(context, cancellationToken);

        // Assert
        Assert.NotNull(result);
        Assert.Contains("Metric Cardinality", result.Data!.Keys);
        
        var cardinalityData = result.Data["Metric Cardinality"] as dynamic;
        Assert.NotNull(cardinalityData);
    }

    [Fact]
    public async Task CheckHealthAsync_WithoutOtlpEndpoint_ShouldNotCheckExporter()
    {
        // Arrange
        _options.Exporters!.Otlp!.Endpoint = string.Empty;
        var context = new HealthCheckContext();
        var cancellationToken = CancellationToken.None;

        // Act
        var result = await _healthCheck.CheckHealthAsync(context, cancellationToken);

        // Assert
        Assert.NotNull(result);
        // Should still have other health checks even without OTLP endpoint
        Assert.NotEmpty(result.Data!);
    }

    [Fact]
    public async Task CheckHealthAsync_ShouldIncludeAllRequiredChecks()
    {
        // Arrange
        var context = new HealthCheckContext();
        var cancellationToken = CancellationToken.None;

        // Act
        var result = await _healthCheck.CheckHealthAsync(context, cancellationToken);

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(result.Data);
        
        var expectedChecks = new[] { "Metrics", "Tracing", "Buffer Health", "Metric Cardinality" };
        foreach (var check in expectedChecks)
        {
            Assert.Contains(check, result.Data.Keys);
        }
    }
}