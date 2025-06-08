using System.Collections.Concurrent;
using Supacrypt.Backend.Models;
using Supacrypt.Backend.Services.Interfaces;

namespace Supacrypt.Backend.Services.Mock;

public class MockKeyRepository : IKeyRepository
{
    private readonly ConcurrentDictionary<string, KeyMetadataModel> _keys = new();

    public Task<KeyMetadataModel?> GetKeyMetadataAsync(string keyId, CancellationToken cancellationToken = default)
    {
        _keys.TryGetValue(keyId, out var metadata);
        return Task.FromResult(metadata);
    }

    public Task<IEnumerable<KeyMetadataModel>> ListKeysAsync(
        string? filter = null,
        int? pageSize = null,
        string? pageToken = null,
        bool includeDisabled = false,
        CancellationToken cancellationToken = default)
    {
        var allKeys = _keys.Values.AsEnumerable();

        if (!includeDisabled)
        {
            allKeys = allKeys.Where(k => k.Enabled);
        }

        if (!string.IsNullOrEmpty(filter))
        {
            allKeys = allKeys.Where(k => 
                k.Name.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                k.KeyId.Contains(filter, StringComparison.OrdinalIgnoreCase));
        }

        var offset = GetOffsetFromPageToken(pageToken);
        if (pageSize.HasValue)
        {
            allKeys = allKeys.Skip(offset).Take(pageSize.Value);
        }

        return Task.FromResult(allKeys);
    }

    public Task<KeyMetadataModel> StoreKeyMetadataAsync(KeyMetadataModel metadata, CancellationToken cancellationToken = default)
    {
        metadata.UpdatedAt = DateTime.UtcNow;
        _keys.AddOrUpdate(metadata.KeyId, metadata, (_, existing) =>
        {
            existing.UpdatedAt = metadata.UpdatedAt;
            existing.Enabled = metadata.Enabled;
            existing.Tags = metadata.Tags;
            existing.Operations = metadata.Operations;
            return existing;
        });

        return Task.FromResult(metadata);
    }

    public Task<bool> DeleteKeyMetadataAsync(string keyId, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(_keys.TryRemove(keyId, out _));
    }

    public Task<bool> KeyExistsAsync(string keyId, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(_keys.ContainsKey(keyId));
    }

    public Task<string> GetNextPageTokenAsync(int offset, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(offset.ToString())));
    }

    private static int GetOffsetFromPageToken(string? pageToken)
    {
        if (string.IsNullOrEmpty(pageToken))
            return 0;

        try
        {
            var bytes = Convert.FromBase64String(pageToken);
            var offsetStr = System.Text.Encoding.UTF8.GetString(bytes);
            return int.Parse(offsetStr);
        }
        catch
        {
            return 0;
        }
    }
}