using Supacrypt.V1;

namespace Supacrypt.Backend.Exceptions;

public class KeyManagementException : Exception
{
    public ErrorCode ErrorCode { get; }
    public string? CorrelationId { get; }
    public string? KeyId { get; }

    public KeyManagementException(ErrorCode errorCode, string message, string? correlationId = null, string? keyId = null)
        : base(message)
    {
        ErrorCode = errorCode;
        CorrelationId = correlationId;
        KeyId = keyId;
    }

    public KeyManagementException(ErrorCode errorCode, string message, Exception innerException, string? correlationId = null, string? keyId = null)
        : base(message, innerException)
    {
        ErrorCode = errorCode;
        CorrelationId = correlationId;
        KeyId = keyId;
    }
}