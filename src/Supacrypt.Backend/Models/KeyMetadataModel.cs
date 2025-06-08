using Supacrypt.V1;

namespace Supacrypt.Backend.Models;

public class KeyMetadataModel
{
    public string KeyId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public KeyAlgorithm Algorithm { get; set; }
    public KeyParameters? Parameters { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public bool Enabled { get; set; } = true;
    public Dictionary<string, string> Tags { get; set; } = new();
    public List<string> Operations { get; set; } = new();
    public byte[]? PublicKeyData { get; set; }
}