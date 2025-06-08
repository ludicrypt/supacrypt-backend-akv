using Google.Protobuf.WellKnownTypes;
using Microsoft.Extensions.Logging;
using Supacrypt.V1;
using Supacrypt.Backend.Models;
using Supacrypt.Backend.Services.Interfaces;
using Supacrypt.Backend.ErrorHandling;
using Supacrypt.Backend.Exceptions;
using System.Security.Cryptography;

namespace Supacrypt.Backend.Services.Mock;

public class MockKeyManagementService : IKeyManagementService
{
    private readonly IKeyRepository _keyRepository;
    private readonly ILogger<MockKeyManagementService> _logger;
    private readonly Random _random = new();

    public MockKeyManagementService(IKeyRepository keyRepository, ILogger<MockKeyManagementService> logger)
    {
        _keyRepository = keyRepository;
        _logger = logger;
    }

    public async Task<GenerateKeyResponse> GenerateKeyAsync(
        GenerateKeyRequest request,
        string correlationId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            await SimulateDelay(50, 200, cancellationToken).ConfigureAwait(false);

            var keyId = Guid.NewGuid().ToString();
            var now = DateTime.UtcNow;

            var publicKeyData = GenerateMockPublicKey(request.Algorithm, request.Parameters);

            var metadata = new KeyMetadataModel
            {
                KeyId = keyId,
                Name = request.Name,
                Algorithm = request.Algorithm,
                Parameters = request.Parameters,
                CreatedAt = now,
                UpdatedAt = now,
                Enabled = true,
                Tags = request.Tags.ToDictionary(kvp => kvp.Key, kvp => kvp.Value),
                Operations = request.Operations.ToList(),
                PublicKeyData = publicKeyData
            };

            await _keyRepository.StoreKeyMetadataAsync(metadata, cancellationToken).ConfigureAwait(false);

            var keyMetadata = new KeyMetadata
            {
                KeyId = keyId,
                Name = request.Name,
                Algorithm = request.Algorithm,
                Parameters = request.Parameters,
                CreatedAt = Timestamp.FromDateTime(now),
                UpdatedAt = Timestamp.FromDateTime(now),
                Enabled = true,
                Operations = { request.Operations }
            };
            keyMetadata.Tags.Add(request.Tags);

            var publicKey = new PublicKey
            {
                Algorithm = request.Algorithm,
                KeyData = Google.Protobuf.ByteString.CopyFrom(publicKeyData),
                Parameters = request.Parameters
            };

            return new GenerateKeyResponse
            {
                Success = new GenerateKeySuccess
                {
                    Metadata = keyMetadata,
                    PublicKey = publicKey
                }
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Mock key generation failed: CorrelationId={CorrelationId}", correlationId);
            var errorDetails = ErrorMapper.MapToErrorDetails(ex, correlationId);
            return ErrorResponseBuilder.BuildGenerateKeyError(errorDetails);
        }
    }

    public async Task<GetKeyResponse> GetKeyAsync(
        GetKeyRequest request,
        string correlationId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            await SimulateDelay(30, 100, cancellationToken).ConfigureAwait(false);

            var metadata = await _keyRepository.GetKeyMetadataAsync(request.KeyId, cancellationToken).ConfigureAwait(false);
            if (metadata == null)
            {
                throw new KeyManagementException(
                    ErrorCode.ErrorCodeKeyNotFound,
                    $"Key with ID '{request.KeyId}' not found",
                    correlationId,
                    request.KeyId);
            }

            var keyMetadata = new KeyMetadata
            {
                KeyId = metadata.KeyId,
                Name = metadata.Name,
                Algorithm = metadata.Algorithm,
                Parameters = metadata.Parameters,
                CreatedAt = Timestamp.FromDateTime(metadata.CreatedAt),
                UpdatedAt = Timestamp.FromDateTime(metadata.UpdatedAt),
                Enabled = metadata.Enabled,
                Operations = { metadata.Operations }
            };
            keyMetadata.Tags.Add(metadata.Tags);

            var response = new GetKeyResponse
            {
                Success = new GetKeySuccess
                {
                    Metadata = keyMetadata
                }
            };

            if (request.IncludePublicKey && metadata.PublicKeyData != null)
            {
                response.Success.PublicKey = new PublicKey
                {
                    Algorithm = metadata.Algorithm,
                    KeyData = Google.Protobuf.ByteString.CopyFrom(metadata.PublicKeyData),
                    Parameters = metadata.Parameters
                };
            }

            return response;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Mock get key failed: CorrelationId={CorrelationId}, KeyId={KeyId}", correlationId, request.KeyId);
            var errorDetails = ErrorMapper.MapToErrorDetails(ex, correlationId);
            return ErrorResponseBuilder.BuildGetKeyError(errorDetails);
        }
    }

    public async Task<ListKeysResponse> ListKeysAsync(
        ListKeysRequest request,
        string correlationId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            await SimulateDelay(50, 150, cancellationToken).ConfigureAwait(false);

            var pageSize = request.PageSize > 0 ? (int)request.PageSize : 50;
            var keys = await _keyRepository.ListKeysAsync(
                request.Filter,
                pageSize + 1,
                request.PageToken,
                request.IncludeDisabled,
                cancellationToken).ConfigureAwait(false);

            var keysList = keys.ToList();
            var hasNextPage = keysList.Count > pageSize;
            if (hasNextPage)
            {
                keysList = keysList.Take(pageSize).ToList();
            }

            var keyMetadataList = keysList.Select(k => new KeyMetadata
            {
                KeyId = k.KeyId,
                Name = k.Name,
                Algorithm = k.Algorithm,
                Parameters = k.Parameters,
                CreatedAt = Timestamp.FromDateTime(k.CreatedAt),
                UpdatedAt = Timestamp.FromDateTime(k.UpdatedAt),
                Enabled = k.Enabled,
                Operations = { k.Operations },
                Tags = { k.Tags }
            });

            var response = new ListKeysResponse
            {
                Success = new ListKeysSuccess
                {
                    Keys = { keyMetadataList },
                    TotalCount = (uint)keysList.Count
                }
            };

            if (hasNextPage)
            {
                var nextOffset = GetOffsetFromPageToken(request.PageToken) + pageSize;
                response.Success.NextPageToken = await _keyRepository.GetNextPageTokenAsync(nextOffset, cancellationToken).ConfigureAwait(false);
            }

            return response;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Mock list keys failed: CorrelationId={CorrelationId}", correlationId);
            var errorDetails = ErrorMapper.MapToErrorDetails(ex, correlationId);
            return ErrorResponseBuilder.BuildListKeysError(errorDetails);
        }
    }

    public async Task<DeleteKeyResponse> DeleteKeyAsync(
        DeleteKeyRequest request,
        string correlationId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            await SimulateDelay(30, 100, cancellationToken).ConfigureAwait(false);

            var exists = await _keyRepository.KeyExistsAsync(request.KeyId, cancellationToken).ConfigureAwait(false);
            if (!exists)
            {
                throw new KeyManagementException(
                    ErrorCode.ErrorCodeKeyNotFound,
                    $"Key with ID '{request.KeyId}' not found",
                    correlationId,
                    request.KeyId);
            }

            var deleted = await _keyRepository.DeleteKeyMetadataAsync(request.KeyId, cancellationToken).ConfigureAwait(false);
            if (!deleted)
            {
                throw new KeyManagementException(
                    ErrorCode.ErrorCodeInternalError,
                    $"Failed to delete key with ID '{request.KeyId}'",
                    correlationId,
                    request.KeyId);
            }

            return new DeleteKeyResponse
            {
                Success = new DeleteKeySuccess
                {
                    KeyId = request.KeyId,
                    DeletedAt = Timestamp.FromDateTime(DateTime.UtcNow)
                }
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Mock delete key failed: CorrelationId={CorrelationId}, KeyId={KeyId}", correlationId, request.KeyId);
            var errorDetails = ErrorMapper.MapToErrorDetails(ex, correlationId);
            return ErrorResponseBuilder.BuildDeleteKeyError(errorDetails);
        }
    }

    private async Task SimulateDelay(int minMs, int maxMs, CancellationToken cancellationToken)
    {
        var delay = _random.Next(minMs, maxMs);
        await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
    }

    private static byte[] GenerateMockPublicKey(KeyAlgorithm algorithm, KeyParameters? parameters)
    {
        return algorithm switch
        {
            KeyAlgorithm.KeyAlgorithmRsa => GenerateMockRsaPublicKey(parameters?.RsaParams),
            KeyAlgorithm.KeyAlgorithmEcc or KeyAlgorithm.KeyAlgorithmEcdsa => GenerateMockEccPublicKey(parameters?.EccParams),
            _ => throw new ArgumentException($"Unsupported algorithm: {algorithm}")
        };
    }

    private static byte[] GenerateMockRsaPublicKey(Supacrypt.V1.RSAParameters? rsaParams)
    {
        var keySize = rsaParams?.KeySize switch
        {
            RSAKeySize.RsaKeySize2048 => 2048,
            RSAKeySize.RsaKeySize3072 => 3072,
            RSAKeySize.RsaKeySize4096 => 4096,
            _ => 2048
        };

        using var rsa = RSA.Create(keySize);
        return rsa.ExportRSAPublicKey();
    }

    private static byte[] GenerateMockEccPublicKey(ECCParameters? eccParams)
    {
        var curve = eccParams?.Curve switch
        {
            ECCCurve.EccCurveP256 => ECCurve.NamedCurves.nistP256,
            ECCCurve.EccCurveP384 => ECCurve.NamedCurves.nistP384,
            ECCCurve.EccCurveP521 => ECCurve.NamedCurves.nistP521,
            _ => ECCurve.NamedCurves.nistP256
        };

        using var ecdsa = ECDsa.Create(curve);
        return ecdsa.ExportSubjectPublicKeyInfo();
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