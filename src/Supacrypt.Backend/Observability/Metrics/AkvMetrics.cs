using System.Diagnostics.Metrics;
using System.Diagnostics;

namespace Supacrypt.Backend.Observability.Metrics;

public class AkvMetrics
{
    public const string MeterName = "Supacrypt.Backend.AzureKeyVault";
    private readonly Meter _meter;

    // Counters
    private readonly Counter<long> _requestCount;
    private readonly Counter<long> _requestErrors;
    private readonly Counter<long> _tokenRefreshCount;
    private readonly Counter<long> _retryAttempts;

    // Histograms
    private readonly Histogram<double> _requestLatency;
    private readonly Histogram<double> _tokenRefreshDuration;

    // Gauges (using UpDownCounter)
    private readonly UpDownCounter<long> _activeConnections;
    private readonly UpDownCounter<long> _connectionPoolSize;
    private readonly UpDownCounter<long> _circuitBreakerState;

    public AkvMetrics()
    {
        _meter = new Meter(MeterName, "1.0.0");

        // Initialize counters
        _requestCount = _meter.CreateCounter<long>(
            "supacrypt.akv.request.count",
            description: "Total number of Azure Key Vault requests");

        _requestErrors = _meter.CreateCounter<long>(
            "supacrypt.akv.request.errors",
            description: "Total number of Azure Key Vault request errors");

        _tokenRefreshCount = _meter.CreateCounter<long>(
            "supacrypt.akv.token.refresh.count",
            description: "Total number of authentication token refreshes");

        _retryAttempts = _meter.CreateCounter<long>(
            "supacrypt.akv.retry.attempts",
            description: "Total number of retry attempts for failed requests");

        // Initialize histograms
        _requestLatency = _meter.CreateHistogram<double>(
            "supacrypt.akv.request.latency",
            unit: "ms",
            description: "Latency of Azure Key Vault requests in milliseconds");

        _tokenRefreshDuration = _meter.CreateHistogram<double>(
            "supacrypt.akv.token.refresh.duration",
            unit: "ms",
            description: "Duration of token refresh operations in milliseconds");

        // Initialize gauges (UpDownCounter)
        _activeConnections = _meter.CreateUpDownCounter<long>(
            "supacrypt.akv.connections.active",
            description: "Number of active connections to Azure Key Vault");

        _connectionPoolSize = _meter.CreateUpDownCounter<long>(
            "supacrypt.akv.connections.pool.size",
            description: "Current connection pool size");

        _circuitBreakerState = _meter.CreateUpDownCounter<long>(
            "supacrypt.akv.circuit_breaker.state",
            description: "Circuit breaker state (0=closed, 1=open, 2=half-open)");
    }

    public void RecordRequest(string operation, string vaultName, TimeSpan duration, bool success, 
        string? errorType = null, int? statusCode = null)
    {
        var tags = new TagList
        {
            { "operation", operation },
            { "vault_name", vaultName },
            { "result", success ? "success" : "error" }
        };

        if (statusCode.HasValue)
        {
            tags.Add("status_code", statusCode.Value);
        }

        // Record request count
        _requestCount.Add(1, tags);

        // Record latency
        _requestLatency.Record(duration.TotalMilliseconds, tags);

        // Record errors separately
        if (!success)
        {
            var errorTags = tags;
            if (!string.IsNullOrEmpty(errorType))
            {
                errorTags.Add("error_type", errorType);
            }
            _requestErrors.Add(1, errorTags);
        }
    }

    public void RecordKeyOperation(string operation, string keyName, string vaultName, TimeSpan duration, 
        bool success, string? keyType = null, int? keySize = null)
    {
        var tags = new TagList
        {
            { "operation", operation },
            { "key_name", SanitizeKeyName(keyName) },
            { "vault_name", vaultName },
            { "result", success ? "success" : "error" }
        };

        if (!string.IsNullOrEmpty(keyType))
        {
            tags.Add("key_type", keyType);
        }

        if (keySize.HasValue)
        {
            tags.Add("key_size", keySize.Value);
        }

        RecordRequest(operation, vaultName, duration, success);
    }

    public void RecordCryptographicOperation(string operation, string keyName, string vaultName, 
        string algorithm, TimeSpan duration, bool success, long? dataSize = null)
    {
        var tags = new TagList
        {
            { "operation", operation },
            { "key_name", SanitizeKeyName(keyName) },
            { "vault_name", vaultName },
            { "algorithm", algorithm },
            { "result", success ? "success" : "error" }
        };

        if (dataSize.HasValue)
        {
            tags.Add("data_size_bytes", dataSize.Value);
        }

        RecordRequest(operation, vaultName, duration, success);
    }

    public void RecordTokenRefresh(string vaultName, TimeSpan duration, bool success, string? errorType = null)
    {
        var tags = new TagList
        {
            { "vault_name", vaultName },
            { "result", success ? "success" : "error" }
        };

        if (!string.IsNullOrEmpty(errorType))
        {
            tags.Add("error_type", errorType);
        }

        _tokenRefreshCount.Add(1, tags);
        _tokenRefreshDuration.Record(duration.TotalMilliseconds, tags);
    }

    public void RecordRetryAttempt(string operation, string vaultName, int attemptNumber, string? errorType = null)
    {
        var tags = new TagList
        {
            { "operation", operation },
            { "vault_name", vaultName },
            { "attempt_number", attemptNumber }
        };

        if (!string.IsNullOrEmpty(errorType))
        {
            tags.Add("error_type", errorType);
        }

        _retryAttempts.Add(1, tags);
    }

    public void RecordConnectionEvent(string vaultName, string eventType)
    {
        var tags = new TagList
        {
            { "vault_name", vaultName },
            { "event", eventType }
        };

        switch (eventType.ToLowerInvariant())
        {
            case "opened":
            case "acquired":
                _activeConnections.Add(1, tags);
                break;
            case "closed":
            case "released":
                _activeConnections.Add(-1, tags);
                break;
        }
    }

    public void SetConnectionPoolSize(string vaultName, int size)
    {
        var tags = new TagList { { "vault_name", vaultName } };
        
        // Reset and set new value (not ideal for gauge, but UpDownCounter limitation)
        _connectionPoolSize.Add(size, tags);
    }

    public void SetCircuitBreakerState(string vaultName, string state)
    {
        var tags = new TagList { { "vault_name", vaultName } };
        
        int stateValue = state.ToLowerInvariant() switch
        {
            "closed" => 0,
            "open" => 1,
            "half-open" => 2,
            _ => -1
        };

        if (stateValue >= 0)
        {
            _circuitBreakerState.Add(stateValue, tags);
        }
    }

    public void RecordRateLimitEvent(string vaultName, TimeSpan waitTime)
    {
        var rateLimitCounter = _meter.CreateCounter<long>(
            "supacrypt.akv.rate_limit.events",
            description: "Number of rate limit events encountered");

        var rateLimitWaitTime = _meter.CreateHistogram<double>(
            "supacrypt.akv.rate_limit.wait_time",
            unit: "ms",
            description: "Time waited due to rate limiting");

        var tags = new TagList { { "vault_name", vaultName } };

        rateLimitCounter.Add(1, tags);
        rateLimitWaitTime.Record(waitTime.TotalMilliseconds, tags);
    }

    public void RecordCacheEvent(string operation, string vaultName, string keyName, bool hit)
    {
        var cacheCounter = _meter.CreateCounter<long>(
            "supacrypt.akv.cache.events",
            description: "Cache hit/miss events for Key Vault operations");

        var tags = new TagList
        {
            { "operation", operation },
            { "vault_name", vaultName },
            { "key_name", SanitizeKeyName(keyName) },
            { "result", hit ? "hit" : "miss" }
        };

        cacheCounter.Add(1, tags);
    }

    public void RecordBatchOperation(string operation, string vaultName, int batchSize, TimeSpan duration, 
        bool success, int? successCount = null)
    {
        var batchCounter = _meter.CreateCounter<long>(
            "supacrypt.akv.batch.operations",
            description: "Batch operations performed on Key Vault");

        var batchDuration = _meter.CreateHistogram<double>(
            "supacrypt.akv.batch.duration",
            unit: "ms",
            description: "Duration of batch operations");

        var tags = new TagList
        {
            { "operation", operation },
            { "vault_name", vaultName },
            { "batch_size", batchSize },
            { "result", success ? "success" : "error" }
        };

        if (successCount.HasValue)
        {
            tags.Add("success_count", successCount.Value);
        }

        batchCounter.Add(1, tags);
        batchDuration.Record(duration.TotalMilliseconds, tags);
    }

    private static string SanitizeKeyName(string keyName)
    {
        if (string.IsNullOrEmpty(keyName) || keyName.Length <= 8)
            return keyName;
            
        return $"{keyName[..4]}...{keyName[^4..]}";
    }

    public void Dispose()
    {
        _meter.Dispose();
    }
}