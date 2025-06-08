using Supacrypt.V1;

namespace Supacrypt.Backend.Services.Interfaces;

public interface ICryptographicOperations
{
    Task<SignDataResponse> SignDataAsync(
        SignDataRequest request,
        string correlationId,
        CancellationToken cancellationToken = default);

    Task<VerifySignatureResponse> VerifySignatureAsync(
        VerifySignatureRequest request,
        string correlationId,
        CancellationToken cancellationToken = default);

    Task<EncryptDataResponse> EncryptDataAsync(
        EncryptDataRequest request,
        string correlationId,
        CancellationToken cancellationToken = default);

    Task<DecryptDataResponse> DecryptDataAsync(
        DecryptDataRequest request,
        string correlationId,
        CancellationToken cancellationToken = default);
}