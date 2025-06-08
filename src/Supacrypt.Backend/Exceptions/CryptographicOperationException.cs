using Supacrypt.V1;

namespace Supacrypt.Backend.Exceptions;

public class CryptographicOperationException : Exception
{
    public ErrorCode ErrorCode { get; }
    public string? CorrelationId { get; }
    public string? KeyId { get; }
    public string? Operation { get; }

    public CryptographicOperationException(ErrorCode errorCode, string message, string? operation = null, string? correlationId = null, string? keyId = null)
        : base(message)
    {
        ErrorCode = errorCode;
        Operation = operation;
        CorrelationId = correlationId;
        KeyId = keyId;
    }

    public CryptographicOperationException(ErrorCode errorCode, string message, Exception innerException, string? operation = null, string? correlationId = null, string? keyId = null)
        : base(message, innerException)
    {
        ErrorCode = errorCode;
        Operation = operation;
        CorrelationId = correlationId;
        KeyId = keyId;
    }
}