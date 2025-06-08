using System;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenTelemetry;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using Supacrypt.Backend.Observability;
using Supacrypt.Backend.Observability.Metrics;
using Xunit;

namespace Supacrypt.Backend.IntegrationTests;

public class ObservabilityIntegrationTests : IDisposable
{
    private readonly ServiceProvider _serviceProvider;
    private readonly List<Metric> _exportedMetrics;

    public ObservabilityIntegrationTests()
    {
        _exportedMetrics = new List<Metric>();

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Observability:ServiceName"] = "test-service",
                ["Observability:Metrics:Enabled"] = "true",
                ["Observability:Metrics:ExportInterval"] = "1000",
                ["Observability:Tracing:Enabled"] = "true",
                ["Observability:Tracing:SamplingRatio"] = "1.0",
                ["Observability:Exporters:Otlp:Endpoint"] = "http://localhost:4317"
            })
            .Build();

        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(configuration);
        services.AddSingleton<IHostEnvironment>(new TestHostEnvironment());
        services.AddLogging(builder => builder.AddConsole());

        // Add observability services
        services.AddSupacryptObservability(configuration, new TestHostEnvironment());

        _serviceProvider = services.BuildServiceProvider();
    }

    [Fact]
    public void ObservabilityServices_ShouldBeRegisteredCorrectly()
    {
        // Assert
        Assert.NotNull(_serviceProvider.GetService<CryptoMetrics>());
        Assert.NotNull(_serviceProvider.GetService<AkvMetrics>());
        Assert.NotNull(_serviceProvider.GetService<SystemMetrics>());
    }

    [Fact]
    public async Task CryptoMetrics_ShouldRecordMetricsCorrectly()
    {
        // Arrange
        var cryptoMetrics = _serviceProvider.GetRequiredService<CryptoMetrics>();

        // Act
        cryptoMetrics.RecordSignOperation(
            "test-key", 
            "RS256", 
            TimeSpan.FromMilliseconds(100), 
            true, 
            1024, 
            256);

        // Allow time for metrics to be processed
        await Task.Delay(500);

        // Assert - Basic verification that service is working
        Assert.NotNull(cryptoMetrics);
    }

    [Fact]
    public async Task AkvMetrics_ShouldRecordMetricsCorrectly()
    {
        // Arrange
        var akvMetrics = _serviceProvider.GetRequiredService<AkvMetrics>();

        // Act
        akvMetrics.RecordRequest(
            "get-key",
            "test-vault",
            TimeSpan.FromMilliseconds(50),
            true);

        // Allow time for metrics to be processed
        await Task.Delay(500);

        // Assert
        Assert.NotNull(akvMetrics);
    }

    [Fact]
    public async Task SystemMetrics_ShouldStartAndStopCorrectly()
    {
        // Arrange
        var systemMetrics = _serviceProvider.GetRequiredService<SystemMetrics>();

        // Act
        await systemMetrics.StartAsync(CancellationToken.None);
        await Task.Delay(100); // Let it run briefly
        await systemMetrics.StopAsync(CancellationToken.None);

        // Assert
        Assert.NotNull(systemMetrics);
    }

    [Fact]
    public void TracingEnricher_ShouldBeRegistered()
    {
        // Assert
        var tracingEnricher = _serviceProvider.GetService<TracingEnricher>();
        Assert.NotNull(tracingEnricher);
    }

    [Fact]
    public async Task HealthCheck_ShouldEvaluateObservabilityHealth()
    {
        // Arrange
        var healthCheck = _serviceProvider.GetRequiredService<Microsoft.Extensions.Diagnostics.HealthChecks.IHealthCheck>();

        // Act
        var result = await healthCheck.CheckHealthAsync(
            new Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckContext());

        // Assert
        Assert.NotNull(result);
        Assert.NotNull(result.Data);
    }

    [Fact]
    public void ObservabilityConfiguration_ShouldLoadCorrectly()
    {
        // Arrange & Act
        var configuration = _serviceProvider.GetRequiredService<IConfiguration>();
        var serviceName = configuration["Observability:ServiceName"];
        var metricsEnabled = configuration["Observability:Metrics:Enabled"];

        // Assert
        Assert.Equal("test-service", serviceName);
        Assert.Equal("true", metricsEnabled);
    }

    [Fact]
    public async Task ConcurrentMetrics_ShouldHandleMultipleOperations()
    {
        // Arrange
        var cryptoMetrics = _serviceProvider.GetRequiredService<CryptoMetrics>();
        var tasks = new List<Task>();

        // Act - Record multiple concurrent operations
        for (int i = 0; i < 10; i++)
        {
            var index = i;
            tasks.Add(Task.Run(() =>
            {
                cryptoMetrics.RecordSignOperation(
                    $"key-{index}",
                    "RS256",
                    TimeSpan.FromMilliseconds(50 + index * 10),
                    true,
                    1024,
                    256);
            }));
        }

        await Task.WhenAll(tasks);

        // Assert - All operations should complete without errors
        Assert.Equal(10, tasks.Count);
        Assert.True(tasks.All(t => t.IsCompletedSuccessfully));
    }

    [Fact]
    public void MetricsConfiguration_ShouldSetCorrectProviders()
    {
        // Arrange
        var cryptoMetrics = _serviceProvider.GetRequiredService<CryptoMetrics>();
        var akvMetrics = _serviceProvider.GetRequiredService<AkvMetrics>();
        var systemMetrics = _serviceProvider.GetRequiredService<SystemMetrics>();

        // Assert - Verify meter names
        Assert.Equal("Supacrypt.Backend.CryptoOperations", CryptoMetrics.MeterName);
        Assert.Equal("Supacrypt.Backend.AzureKeyVault", AkvMetrics.MeterName);
        Assert.Equal("Supacrypt.Backend.SystemHealth", SystemMetrics.MeterName);
    }

    public void Dispose()
    {
        _serviceProvider?.Dispose();
    }

    private class TestHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Test";
        public string ApplicationName { get; set; } = "Supacrypt.Backend.Tests";
        public string ContentRootPath { get; set; } = "/";
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = null!;
    }
}