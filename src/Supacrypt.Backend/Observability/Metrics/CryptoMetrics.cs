using System.Diagnostics.Metrics;

namespace Supacrypt.Backend.Observability.Metrics;

public class CryptoMetrics
{
    public const string MeterName = "Supacrypt.Backend.CryptoOperations";
    private readonly Meter _meter;

    // Counters
    private readonly Counter<long> _operationCount;
    private readonly Counter<long> _operationErrors;
    private readonly Counter<long> _keyUsageCount;

    // Histograms
    private readonly Histogram<double> _operationDuration;
    private readonly Histogram<long> _dataSize;

    // Gauges (using UpDownCounter as closest equivalent)
    private readonly UpDownCounter<long> _activeOperations;

    public CryptoMetrics()
    {
        _meter = new Meter(MeterName, "1.0.0");

        // Initialize counters
        _operationCount = _meter.CreateCounter<long>(
            "supacrypt.crypto.operation.count",
            description: "Total number of cryptographic operations performed");

        _operationErrors = _meter.CreateCounter<long>(
            "supacrypt.crypto.operation.errors",
            description: "Total number of cryptographic operation errors");

        _keyUsageCount = _meter.CreateCounter<long>(
            "supacrypt.crypto.key.usage.count",
            description: "Total number of key usage operations");

        // Initialize histograms
        _operationDuration = _meter.CreateHistogram<double>(
            "supacrypt.crypto.operation.duration",
            unit: "ms",
            description: "Duration of cryptographic operations in milliseconds");

        _dataSize = _meter.CreateHistogram<long>(
            "supacrypt.crypto.data.size",
            unit: "bytes",
            description: "Size of data processed in cryptographic operations");

        // Initialize gauges (UpDownCounter)
        _activeOperations = _meter.CreateUpDownCounter<long>(
            "supacrypt.crypto.operations.active",
            description: "Number of currently active cryptographic operations");
    }

    public void RecordOperation(string operationType, string algorithm, TimeSpan duration, bool success, 
        long? dataSize = null, string? keyId = null)
    {
        var tags = new TagList
        {
            ["operation"] = operationType,
            ["algorithm"] = algorithm,
            ["result"] = success ? "success" : "error"
        };

        // Record operation count
        _operationCount.Add(1, tags);

        // Record errors separately
        if (!success)
        {
            _operationErrors.Add(1, tags);
        }

        // Record duration
        _operationDuration.Record(duration.TotalMilliseconds, tags);

        // Record data size if provided
        if (dataSize.HasValue)
        {
            _dataSize.Record(dataSize.Value, tags);
        }

        // Record key usage if provided
        if (!string.IsNullOrEmpty(keyId))
        {
            var keyTags = new TagList
            {
                ["key_id"] = SanitizeKeyId(keyId),
                ["operation"] = operationType
            };
            _keyUsageCount.Add(1, keyTags);
        }
    }

    public void RecordSignOperation(string keyId, string algorithm, TimeSpan duration, bool success, 
        long dataSize, long? signatureSize = null)
    {
        RecordOperation("sign", algorithm, duration, success, dataSize, keyId);

        if (signatureSize.HasValue)
        {
            var tags = new TagList
            {
                ["operation"] = "sign",
                ["algorithm"] = algorithm
            };
            _dataSize.Record(signatureSize.Value, tags.Add("data_type", "signature"));
        }
    }

    public void RecordVerifyOperation(string keyId, string algorithm, TimeSpan duration, bool success, 
        long dataSize, long signatureSize, bool isValid)
    {
        var tags = new TagList
        {
            ["operation"] = "verify",
            ["algorithm"] = algorithm,
            ["result"] = success ? "success" : "error",
            ["signature_valid"] = isValid
        };

        _operationCount.Add(1, tags);
        _operationDuration.Record(duration.TotalMilliseconds, tags);
        _dataSize.Record(dataSize, tags.Add("data_type", "payload"));
        _dataSize.Record(signatureSize, tags.Add("data_type", "signature"));

        if (!success)
        {
            _operationErrors.Add(1, tags);
        }

        // Record key usage
        var keyTags = new TagList
        {
            ["key_id"] = SanitizeKeyId(keyId),
            ["operation"] = "verify"
        };
        _keyUsageCount.Add(1, keyTags);
    }

    public void RecordEncryptOperation(string keyId, string algorithm, TimeSpan duration, bool success, 
        long plaintextSize, long? ciphertextSize = null)
    {
        RecordOperation("encrypt", algorithm, duration, success, plaintextSize, keyId);

        if (ciphertextSize.HasValue)
        {
            var tags = new TagList
            {
                ["operation"] = "encrypt",
                ["algorithm"] = algorithm
            };
            _dataSize.Record(ciphertextSize.Value, tags.Add("data_type", "ciphertext"));
        }
    }

    public void RecordDecryptOperation(string keyId, string algorithm, TimeSpan duration, bool success, 
        long ciphertextSize, long? plaintextSize = null)
    {
        RecordOperation("decrypt", algorithm, duration, success, ciphertextSize, keyId);

        if (plaintextSize.HasValue)
        {
            var tags = new TagList
            {
                ["operation"] = "decrypt",
                ["algorithm"] = algorithm
            };
            _dataSize.Record(plaintextSize.Value, tags.Add("data_type", "plaintext"));
        }
    }

    public void RecordKeyGeneration(string keyType, int keySize, string algorithm, TimeSpan duration, bool success)
    {
        var tags = new TagList
        {
            ["operation"] = "generate_key",
            ["key_type"] = keyType,
            ["key_size"] = keySize,
            ["algorithm"] = algorithm,
            ["result"] = success ? "success" : "error"
        };

        _operationCount.Add(1, tags);
        _operationDuration.Record(duration.TotalMilliseconds, tags);

        if (!success)
        {
            _operationErrors.Add(1, tags);
        }
    }

    public void RecordActiveOperationStart(string operationType)
    {
        var tags = new TagList { ["operation"] = operationType };
        _activeOperations.Add(1, tags);
    }

    public void RecordActiveOperationEnd(string operationType)
    {
        var tags = new TagList { ["operation"] = operationType };
        _activeOperations.Add(-1, tags);
    }

    public void RecordAlgorithmDistribution(string algorithm, string operationType)
    {
        var algorithmCounter = _meter.CreateCounter<long>(
            "supacrypt.crypto.algorithm.usage",
            description: "Distribution of cryptographic algorithms used");

        var tags = new TagList
        {
            ["algorithm"] = algorithm,
            ["operation"] = operationType
        };

        algorithmCounter.Add(1, tags);
    }

    private static string SanitizeKeyId(string keyId)
    {
        if (string.IsNullOrEmpty(keyId) || keyId.Length <= 8)
            return keyId;
            
        return $"{keyId[..4]}...{keyId[^4..]}";
    }

    public void Dispose()
    {
        _meter.Dispose();
    }
}