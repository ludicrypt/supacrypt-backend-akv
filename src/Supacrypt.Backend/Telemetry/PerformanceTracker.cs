using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace Supacrypt.Backend.Telemetry;

public class PerformanceTracker
{
    private readonly ILogger<PerformanceTracker> _logger;
    private readonly Dictionary<string, OperationMetrics> _metrics = new();
    private readonly object _lock = new();

    public PerformanceTracker(ILogger<PerformanceTracker> logger)
    {
        _logger = logger;
    }

    public OperationTracker BeginOperation(string operation, string correlationId, string? keyId = null)
    {
        return new OperationTracker(this, operation, correlationId, keyId);
    }

    private void RecordOperation(string operation, TimeSpan duration, bool success, string? keyId = null)
    {
        lock (_lock)
        {
            if (!_metrics.TryGetValue(operation, out var metrics))
            {
                metrics = new OperationMetrics(operation);
                _metrics[operation] = metrics;
            }

            metrics.RecordOperation(duration, success);
        }

        _logger.LogDebug("Operation {Operation} completed in {Duration}ms (Success: {Success}, KeyId: {KeyId})",
            operation, duration.TotalMilliseconds, success, keyId ?? "N/A");
    }

    public Dictionary<string, OperationMetrics> GetMetrics()
    {
        lock (_lock)
        {
            return new Dictionary<string, OperationMetrics>(_metrics);
        }
    }

    public void LogPerformanceSummary()
    {
        lock (_lock)
        {
            foreach (var kvp in _metrics)
            {
                var metrics = kvp.Value;
                _logger.LogInformation("Performance summary for {Operation}: " +
                    "Count={Count}, Success={SuccessCount}, Failed={FailedCount}, " +
                    "AvgDuration={AvgDuration}ms, MinDuration={MinDuration}ms, MaxDuration={MaxDuration}ms",
                    metrics.Operation, metrics.TotalCount, metrics.SuccessCount, metrics.FailedCount,
                    metrics.AverageDuration.TotalMilliseconds, metrics.MinDuration.TotalMilliseconds, metrics.MaxDuration.TotalMilliseconds);
            }
        }
    }

    public class OperationTracker : IDisposable
    {
        private readonly PerformanceTracker _tracker;
        private readonly string _operation;
        private readonly string _correlationId;
        private readonly string? _keyId;
        private readonly Stopwatch _stopwatch;
        private bool _success;
        private bool _disposed;

        public OperationTracker(PerformanceTracker tracker, string operation, string correlationId, string? keyId)
        {
            _tracker = tracker;
            _operation = operation;
            _correlationId = correlationId;
            _keyId = keyId;
            _stopwatch = Stopwatch.StartNew();
        }

        public void MarkSuccess()
        {
            _success = true;
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _stopwatch.Stop();
                _tracker.RecordOperation(_operation, _stopwatch.Elapsed, _success, _keyId);
                _disposed = true;
            }
        }
    }
}

public class OperationMetrics
{
    private readonly object _lock = new();
    private readonly List<TimeSpan> _durations = new();
    private int _successCount;
    private int _failedCount;

    public OperationMetrics(string operation)
    {
        Operation = operation;
    }

    public string Operation { get; }
    public int TotalCount => _successCount + _failedCount;
    public int SuccessCount => _successCount;
    public int FailedCount => _failedCount;

    public TimeSpan AverageDuration
    {
        get
        {
            lock (_lock)
            {
                return _durations.Count > 0 
                    ? TimeSpan.FromTicks((long)_durations.Average(d => d.Ticks))
                    : TimeSpan.Zero;
            }
        }
    }

    public TimeSpan MinDuration
    {
        get
        {
            lock (_lock)
            {
                return _durations.Count > 0 ? _durations.Min() : TimeSpan.Zero;
            }
        }
    }

    public TimeSpan MaxDuration
    {
        get
        {
            lock (_lock)
            {
                return _durations.Count > 0 ? _durations.Max() : TimeSpan.Zero;
            }
        }
    }

    public void RecordOperation(TimeSpan duration, bool success)
    {
        lock (_lock)
        {
            _durations.Add(duration);
            if (success)
                _successCount++;
            else
                _failedCount++;
        }
    }
}