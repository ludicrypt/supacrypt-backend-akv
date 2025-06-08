using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Runtime;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Supacrypt.Backend.Observability.Metrics;

public class SystemMetrics : IHostedService, IDisposable
{
    public const string MeterName = "Supacrypt.Backend.SystemHealth";
    private readonly Meter _meter;
    private readonly ILogger<SystemMetrics> _logger;
    private Timer? _metricsTimer;

    // Gauges (using UpDownCounter as .NET doesn't have native Gauge)
    private readonly UpDownCounter<long> _memoryUsage;
    private readonly UpDownCounter<double> _cpuUsage;
    private readonly UpDownCounter<long> _threadCount;
    private readonly UpDownCounter<long> _handleCount;
    private readonly UpDownCounter<long> _gcGen0Collections;
    private readonly UpDownCounter<long> _gcGen1Collections;
    private readonly UpDownCounter<long> _gcGen2Collections;

    // Histograms
    private readonly Histogram<double> _gcDuration;
    private readonly Histogram<double> _healthCheckDuration;

    // Counters
    private readonly Counter<long> _healthCheckCount;
    private readonly Counter<long> _certificateExpirations;

    private readonly Process _currentProcess;
    private long _lastGcGen0Count;
    private long _lastGcGen1Count;
    private long _lastGcGen2Count;

    public SystemMetrics(ILogger<SystemMetrics> logger)
    {
        _logger = logger;
        _meter = new Meter(MeterName, "1.0.0");
        _currentProcess = Process.GetCurrentProcess();

        // Initialize memory metrics
        _memoryUsage = _meter.CreateUpDownCounter<long>(
            "supacrypt.system.memory.usage",
            unit: "bytes",
            description: "Memory usage of the application");

        // Initialize CPU metrics
        _cpuUsage = _meter.CreateUpDownCounter<double>(
            "supacrypt.system.cpu.usage",
            unit: "percent",
            description: "CPU usage percentage");

        // Initialize thread metrics
        _threadCount = _meter.CreateUpDownCounter<long>(
            "supacrypt.system.threads.count",
            description: "Number of threads in the process");

        _handleCount = _meter.CreateUpDownCounter<long>(
            "supacrypt.system.handles.count",
            description: "Number of handles in the process");

        // Initialize garbage collection metrics
        _gcGen0Collections = _meter.CreateUpDownCounter<long>(
            "supacrypt.system.gc.collections.gen0",
            description: "Number of generation 0 garbage collections");

        _gcGen1Collections = _meter.CreateUpDownCounter<long>(
            "supacrypt.system.gc.collections.gen1",
            description: "Number of generation 1 garbage collections");

        _gcGen2Collections = _meter.CreateUpDownCounter<long>(
            "supacrypt.system.gc.collections.gen2",
            description: "Number of generation 2 garbage collections");

        _gcDuration = _meter.CreateHistogram<double>(
            "supacrypt.system.gc.duration",
            unit: "ms",
            description: "Duration of garbage collection pauses");

        // Initialize health check metrics
        _healthCheckDuration = _meter.CreateHistogram<double>(
            "supacrypt.health.check.duration",
            unit: "ms",
            description: "Duration of health check executions");

        _healthCheckCount = _meter.CreateCounter<long>(
            "supacrypt.health.check.count",
            description: "Number of health checks performed");

        _certificateExpirations = _meter.CreateCounter<long>(
            "supacrypt.system.certificate.expirations",
            description: "Number of certificate expiration warnings");

        // Initialize GC counters
        _lastGcGen0Count = GC.CollectionCount(0);
        _lastGcGen1Count = GC.CollectionCount(1);
        _lastGcGen2Count = GC.CollectionCount(2);
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Starting system metrics collection");
        
        // Collect metrics every 30 seconds
        _metricsTimer = new Timer(CollectMetrics, null, TimeSpan.Zero, TimeSpan.FromSeconds(30));
        
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Stopping system metrics collection");
        
        _metricsTimer?.Dispose();
        
        return Task.CompletedTask;
    }

    private void CollectMetrics(object? state)
    {
        try
        {
            CollectMemoryMetrics();
            CollectProcessMetrics();
            CollectGarbageCollectionMetrics();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error collecting system metrics");
        }
    }

    private void CollectMemoryMetrics()
    {
        // Working set memory
        var workingSet = _currentProcess.WorkingSet64;
        _memoryUsage.Add(workingSet, new TagList { ["type"] = "working_set" });

        // Private memory
        var privateMemory = _currentProcess.PrivateMemorySize64;
        _memoryUsage.Add(privateMemory, new TagList { ["type"] = "private" });

        // Virtual memory
        var virtualMemory = _currentProcess.VirtualMemorySize64;
        _memoryUsage.Add(virtualMemory, new TagList { ["type"] = "virtual" });

        // Managed memory
        var managedMemory = GC.GetTotalMemory(false);
        _memoryUsage.Add(managedMemory, new TagList { ["type"] = "managed" });

        // Available memory (approximation)
        var gcInfo = GC.GetGCMemoryInfo();
        var totalAvailableMemory = gcInfo.TotalAvailableMemoryBytes;
        _memoryUsage.Add(totalAvailableMemory, new TagList { ["type"] = "total_available" });
    }

    private void CollectProcessMetrics()
    {
        // Refresh process information
        _currentProcess.Refresh();

        // Thread count
        var threadCount = _currentProcess.Threads.Count;
        _threadCount.Add(threadCount, new TagList());

        // Handle count
        var handleCount = _currentProcess.HandleCount;
        _handleCount.Add(handleCount, new TagList());

        // CPU usage (approximation - would need baseline for accurate calculation)
        var totalProcessorTime = _currentProcess.TotalProcessorTime;
        var cpuUsagePercent = totalProcessorTime.TotalMilliseconds / Environment.TickCount * 100;
        _cpuUsage.Add(Math.Min(cpuUsagePercent, 100), new TagList());
    }

    private void CollectGarbageCollectionMetrics()
    {
        // Check for new collections
        var currentGen0 = GC.CollectionCount(0);
        var currentGen1 = GC.CollectionCount(1);
        var currentGen2 = GC.CollectionCount(2);

        if (currentGen0 > _lastGcGen0Count)
        {
            _gcGen0Collections.Add(currentGen0 - _lastGcGen0Count, new TagList());
            _lastGcGen0Count = currentGen0;
        }

        if (currentGen1 > _lastGcGen1Count)
        {
            _gcGen1Collections.Add(currentGen1 - _lastGcGen1Count, new TagList());
            _lastGcGen1Count = currentGen1;
        }

        if (currentGen2 > _lastGcGen2Count)
        {
            _gcGen2Collections.Add(currentGen2 - _lastGcGen2Count, new TagList());
            _lastGcGen2Count = currentGen2;
        }
    }

    public void RecordHealthCheck(string checkName, string status, TimeSpan duration, 
        Dictionary<string, string>? details = null)
    {
        var tags = new TagList
        {
            ["check_name"] = checkName,
            ["status"] = status
        };

        if (details != null)
        {
            foreach (var detail in details.Take(5)) // Limit to prevent high cardinality
            {
                tags.Add($"detail_{detail.Key}", detail.Value);
            }
        }

        _healthCheckCount.Add(1, tags);
        _healthCheckDuration.Record(duration.TotalMilliseconds, tags);

        // Record binary health status
        var healthStatus = _meter.CreateUpDownCounter<long>(
            "supacrypt.health.check.status",
            description: "Current health check status (1=healthy, 0=unhealthy)");

        var statusValue = status.ToLowerInvariant() == "healthy" ? 1 : 0;
        healthStatus.Add(statusValue, new TagList { ["check_name"] = checkName });
    }

    public void RecordComponentHealth(string componentName, bool isHealthy, string? details = null)
    {
        var componentHealth = _meter.CreateUpDownCounter<long>(
            "supacrypt.health.component.status",
            description: "Health status of individual components");

        var tags = new TagList
        {
            ["component"] = componentName,
            ["status"] = isHealthy ? "healthy" : "unhealthy"
        };

        if (!string.IsNullOrEmpty(details))
        {
            tags.Add("details", details);
        }

        componentHealth.Add(isHealthy ? 1 : 0, tags);
    }

    public void RecordCertificateExpiration(string certificateSubject, DateTime expirationDate, 
        TimeSpan timeUntilExpiration)
    {
        var tags = new TagList
        {
            ["certificate_subject"] = SanitizeCertificateSubject(certificateSubject),
            ["expires_at"] = expirationDate.ToString("yyyy-MM-dd"),
            ["days_until_expiration"] = (int)timeUntilExpiration.TotalDays
        };

        // Record certificate expiration metric
        var certificateExpiry = _meter.CreateHistogram<double>(
            "supacrypt.system.certificate.expiry_days",
            unit: "days",
            description: "Days until certificate expiration");

        certificateExpiry.Record(timeUntilExpiration.TotalDays, tags);

        // Count expiration warnings (less than 30 days)
        if (timeUntilExpiration.TotalDays < 30)
        {
            _certificateExpirations.Add(1, tags);
        }
    }

    public void RecordGarbageCollection(int generation, TimeSpan duration, long memoryBefore, long memoryAfter)
    {
        var tags = new TagList
        {
            ["generation"] = generation,
            ["memory_reclaimed"] = memoryBefore - memoryAfter
        };

        _gcDuration.Record(duration.TotalMilliseconds, tags);

        // Record memory pressure
        var memoryPressure = _meter.CreateHistogram<double>(
            "supacrypt.system.memory.pressure",
            unit: "bytes",
            description: "Memory pressure before garbage collection");

        memoryPressure.Record(memoryBefore, tags);
    }

    public void RecordPerformanceCounter(string counterName, double value, string? category = null, 
        Dictionary<string, object>? additionalTags = null)
    {
        var performanceCounter = _meter.CreateHistogram<double>(
            $"supacrypt.system.performance.{counterName.ToLowerInvariant().Replace(' ', '_')}",
            description: $"Performance counter: {counterName}");

        var tags = new TagList();
        
        if (!string.IsNullOrEmpty(category))
        {
            tags.Add("category", category);
        }

        if (additionalTags != null)
        {
            foreach (var tag in additionalTags)
            {
                tags.Add(tag.Key, tag.Value);
            }
        }

        performanceCounter.Record(value, tags);
    }

    private static string SanitizeCertificateSubject(string subject)
    {
        // Extract just the CN part for privacy
        var parts = subject.Split(',', StringSplitOptions.RemoveEmptyEntries);
        var cnPart = parts.FirstOrDefault(p => p.Trim().StartsWith("CN=", StringComparison.OrdinalIgnoreCase));
        return cnPart?.Substring(3).Trim() ?? "unknown";
    }

    public void Dispose()
    {
        _metricsTimer?.Dispose();
        _currentProcess?.Dispose();
        _meter.Dispose();
    }
}