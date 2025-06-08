using Microsoft.Extensions.Logging;
using System.Diagnostics;

namespace Supacrypt.Backend.Logging;

public class OperationLogger : IDisposable
{
    private readonly ILogger _logger;
    private readonly string _operation;
    private readonly string _correlationId;
    private readonly string? _keyId;
    private readonly Stopwatch _stopwatch;
    private readonly IDisposable? _scope;
    private bool _disposed;

    public OperationLogger(ILogger logger, string operation, string correlationId, string? keyId = null)
    {
        _logger = logger;
        _operation = operation;
        _correlationId = correlationId;
        _keyId = keyId;
        _stopwatch = Stopwatch.StartNew();
        
        _scope = _logger.BeginOperationScope(operation, correlationId, keyId);
        _logger.LogOperationStart(operation, correlationId, keyId);
    }

    public void LogSuccess(object? result = null)
    {
        if (!_disposed)
        {
            _stopwatch.Stop();
            _logger.LogOperationSuccess(_operation, _correlationId, _stopwatch.Elapsed.TotalMilliseconds, _keyId, result);
        }
    }

    public void LogFailure(Exception exception)
    {
        if (!_disposed)
        {
            _stopwatch.Stop();
            _logger.LogOperationFailure(_operation, _correlationId, exception, _stopwatch.Elapsed.TotalMilliseconds, _keyId);
        }
    }

    public void LogValidationFailure(string validationErrors)
    {
        if (!_disposed)
        {
            _logger.LogValidationFailure(_operation, _correlationId, validationErrors, _keyId);
        }
    }

    public void LogInformation(string message, params object[] args)
    {
        if (!_disposed)
        {
            _logger.LogInformation(message, args);
        }
    }

    public void LogWarning(string message, params object[] args)
    {
        if (!_disposed)
        {
            _logger.LogWarning(message, args);
        }
    }

    public void LogError(Exception exception, string message, params object[] args)
    {
        if (!_disposed)
        {
            _logger.LogError(exception, message, args);
        }
    }

    public TimeSpan Elapsed => _stopwatch.Elapsed;

    public void Dispose()
    {
        if (!_disposed)
        {
            _stopwatch.Stop();
            _scope?.Dispose();
            _disposed = true;
        }
    }
}