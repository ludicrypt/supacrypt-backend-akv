using Supacrypt.V1;

namespace Supacrypt.Backend.Services.Interfaces;

public interface IKeyManagementService
{
    Task<GenerateKeyResponse> GenerateKeyAsync(
        GenerateKeyRequest request,
        string correlationId,
        CancellationToken cancellationToken = default);

    Task<GetKeyResponse> GetKeyAsync(
        GetKeyRequest request,
        string correlationId,
        CancellationToken cancellationToken = default);

    Task<ListKeysResponse> ListKeysAsync(
        ListKeysRequest request,
        string correlationId,
        CancellationToken cancellationToken = default);

    Task<DeleteKeyResponse> DeleteKeyAsync(
        DeleteKeyRequest request,
        string correlationId,
        CancellationToken cancellationToken = default);
}