namespace Supacrypt.Backend.Models;

public class OperationContext
{
    public string CorrelationId { get; set; } = string.Empty;
    public string Operation { get; set; } = string.Empty;
    public string? KeyId { get; set; }
    public DateTime StartTime { get; set; } = DateTime.UtcNow;
    public Dictionary<string, object> Properties { get; set; } = new();
}