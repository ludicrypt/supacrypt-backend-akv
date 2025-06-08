using Supacrypt.Backend.Models;

namespace Supacrypt.Backend.Services.Interfaces;

public interface IKeyRepository
{
    Task<KeyMetadataModel?> GetKeyMetadataAsync(
        string keyId,
        CancellationToken cancellationToken = default);

    Task<IEnumerable<KeyMetadataModel>> ListKeysAsync(
        string? filter = null,
        int? pageSize = null,
        string? pageToken = null,
        bool includeDisabled = false,
        CancellationToken cancellationToken = default);

    Task<KeyMetadataModel> StoreKeyMetadataAsync(
        KeyMetadataModel metadata,
        CancellationToken cancellationToken = default);

    Task<bool> DeleteKeyMetadataAsync(
        string keyId,
        CancellationToken cancellationToken = default);

    Task<bool> KeyExistsAsync(
        string keyId,
        CancellationToken cancellationToken = default);

    Task<string> GetNextPageTokenAsync(
        int offset,
        CancellationToken cancellationToken = default);
}