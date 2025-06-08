using System.Diagnostics;
using System.Diagnostics.Metrics;
using Supacrypt.Backend.Observability.Metrics;

namespace Supacrypt.Backend.Services.Azure;

public interface IAzureKeyVaultMetrics
{
    void RecordOperation(string operation, string keyId, TimeSpan duration, bool success, string? errorType = null);
    void RecordCircuitBreakerState(string state);
    void IncrementRetryAttempt(string operation, int attemptNumber);
}

public class AzureKeyVaultMetrics : IAzureKeyVaultMetrics, IDisposable
{
    private readonly Meter _meter;
    private readonly Counter<long> _operationsTotal;
    private readonly Histogram<double> _operationDuration;
    private readonly Counter<long> _errorsTotal;
    private readonly Gauge<int> _circuitBreakerState;
    private readonly Counter<long> _retryAttempts;

    public AzureKeyVaultMetrics()
    {
        _meter = new Meter("Supacrypt.Backend.AzureKeyVault", "1.0.0");

        _operationsTotal = _meter.CreateCounter<long>(
            "supacrypt.backend.keyvault.operations.total",
            description: "Total number of Azure Key Vault operations");

        _operationDuration = _meter.CreateHistogram<double>(
            "supacrypt.backend.keyvault.operations.duration",
            unit: "ms",
            description: "Duration of Azure Key Vault operations in milliseconds");

        _errorsTotal = _meter.CreateCounter<long>(
            "supacrypt.backend.keyvault.errors.total",
            description: "Total number of Azure Key Vault errors by type");

        _circuitBreakerState = _meter.CreateGauge<int>(
            "supacrypt.backend.keyvault.circuit_breaker.state",
            description: "Current circuit breaker state (0=Closed, 1=Open, 2=HalfOpen)");

        _retryAttempts = _meter.CreateCounter<long>(
            "supacrypt.backend.keyvault.retry.attempts.total",
            description: "Total number of retry attempts for Azure Key Vault operations");
    }

    public void RecordOperation(string operation, string keyId, TimeSpan duration, bool success, string? errorType = null)
    {
        var tags = new TagList
        {
            { "operation", operation },
            { "success", success.ToString().ToLowerInvariant() }
        };

        if (!string.IsNullOrEmpty(keyId))
        {
            // Hash the key ID for privacy while maintaining cardinality for metrics
            tags.Add("key_id_hash", HashKeyId(keyId));
        }

        if (!success && !string.IsNullOrEmpty(errorType))
        {
            tags.Add("error_type", errorType);
            _errorsTotal.Add(1, tags);
        }

        _operationsTotal.Add(1, tags);
        _operationDuration.Record(duration.TotalMilliseconds, tags);
    }

    public void RecordCircuitBreakerState(string state)
    {
        var stateValue = state.ToLowerInvariant() switch
        {
            "closed" => 0,
            "open" => 1,
            "halfopen" => 2,
            _ => -1
        };

        _circuitBreakerState.Record(stateValue, new TagList { { "state", state.ToLowerInvariant() } });
    }

    public void IncrementRetryAttempt(string operation, int attemptNumber)
    {
        _retryAttempts.Add(1, new TagList
        {
            { "operation", operation },
            { "attempt_number", attemptNumber.ToString() }
        });
    }

    private static string HashKeyId(string keyId)
    {
        // Simple hash for metrics - we don't need cryptographic security here
        return Math.Abs(keyId.GetHashCode()).ToString("X8");
    }

    public void Dispose()
    {
        _meter?.Dispose();
    }
}