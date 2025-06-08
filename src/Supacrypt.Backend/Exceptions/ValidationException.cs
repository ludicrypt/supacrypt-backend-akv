namespace Supacrypt.Backend.Exceptions;

public class ValidationException : Exception
{
    public string? CorrelationId { get; }
    public Dictionary<string, string[]> Errors { get; }

    public ValidationException(string message, string? correlationId = null)
        : base(message)
    {
        CorrelationId = correlationId;
        Errors = new Dictionary<string, string[]>();
    }

    public ValidationException(Dictionary<string, string[]> errors, string? correlationId = null)
        : base("Validation failed")
    {
        CorrelationId = correlationId;
        Errors = errors;
    }

    public ValidationException(string message, Dictionary<string, string[]> errors, string? correlationId = null)
        : base(message)
    {
        CorrelationId = correlationId;
        Errors = errors;
    }
}