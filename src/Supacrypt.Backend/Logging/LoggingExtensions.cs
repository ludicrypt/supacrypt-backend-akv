using Microsoft.Extensions.Logging;

namespace Supacrypt.Backend.Logging;

public static class LoggingExtensions
{
    public static void LogOperationStart(this ILogger logger, string operation, string correlationId, string? keyId = null, object? parameters = null)
    {
        using var scope = logger.BeginScope(new Dictionary<string, object>
        {
            ["Operation"] = operation,
            ["CorrelationId"] = correlationId,
            ["KeyId"] = keyId ?? string.Empty
        });

        logger.LogInformation("Starting operation {Operation} with CorrelationId {CorrelationId}", operation, correlationId);
    }

    public static void LogOperationSuccess(this ILogger logger, string operation, string correlationId, double durationMs, string? keyId = null, object? result = null)
    {
        using var scope = logger.BeginScope(new Dictionary<string, object>
        {
            ["Operation"] = operation,
            ["CorrelationId"] = correlationId,
            ["KeyId"] = keyId ?? string.Empty,
            ["Duration"] = durationMs
        });

        logger.LogInformation("Operation {Operation} completed successfully in {Duration}ms (CorrelationId: {CorrelationId})", 
            operation, durationMs, correlationId);
    }

    public static void LogOperationFailure(this ILogger logger, string operation, string correlationId, Exception exception, double durationMs, string? keyId = null)
    {
        using var scope = logger.BeginScope(new Dictionary<string, object>
        {
            ["Operation"] = operation,
            ["CorrelationId"] = correlationId,
            ["KeyId"] = keyId ?? string.Empty,
            ["Duration"] = durationMs,
            ["ErrorType"] = exception.GetType().Name
        });

        logger.LogError(exception, "Operation {Operation} failed after {Duration}ms (CorrelationId: {CorrelationId})", 
            operation, durationMs, correlationId);
    }

    public static void LogValidationFailure(this ILogger logger, string operation, string correlationId, string validationErrors, string? keyId = null)
    {
        using var scope = logger.BeginScope(new Dictionary<string, object>
        {
            ["Operation"] = operation,
            ["CorrelationId"] = correlationId,
            ["KeyId"] = keyId ?? string.Empty
        });

        logger.LogWarning("Validation failed for operation {Operation} (CorrelationId: {CorrelationId}): {ValidationErrors}", 
            operation, correlationId, validationErrors);
    }

    public static void LogKeyOperation(this ILogger logger, LogLevel level, string operation, string correlationId, string keyId, string algorithm, string message)
    {
        using var scope = logger.BeginScope(new Dictionary<string, object>
        {
            ["Operation"] = operation,
            ["CorrelationId"] = correlationId,
            ["KeyId"] = keyId,
            ["Algorithm"] = algorithm
        });

        logger.Log(level, message);
    }

    public static void LogCryptographicOperation(this ILogger logger, LogLevel level, string operation, string correlationId, string keyId, int dataSize, string message)
    {
        using var scope = logger.BeginScope(new Dictionary<string, object>
        {
            ["Operation"] = operation,
            ["CorrelationId"] = correlationId,
            ["KeyId"] = keyId,
            ["DataSize"] = dataSize
        });

        logger.Log(level, message);
    }

    public static IDisposable? BeginOperationScope(this ILogger logger, string operation, string correlationId, string? keyId = null)
    {
        var scope = new Dictionary<string, object>
        {
            ["Operation"] = operation,
            ["CorrelationId"] = correlationId
        };

        if (!string.IsNullOrEmpty(keyId))
        {
            scope["KeyId"] = keyId;
        }

        return logger.BeginScope(scope);
    }
}