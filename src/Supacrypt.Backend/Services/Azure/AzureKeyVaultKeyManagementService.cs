using Azure;
using Azure.Security.KeyVault.Keys;
using Supacrypt.Backend.Services.Interfaces;
using Supacrypt.V1;
using Google.Protobuf;
using System.Diagnostics;

namespace Supacrypt.Backend.Services.Azure;

public class AzureKeyVaultKeyManagementService : IKeyManagementService
{
    private readonly IAzureKeyVaultClientFactory _clientFactory;
    private readonly IAzureKeyVaultResiliencePolicy _resiliencePolicy;
    private readonly IKeyRepository _keyRepository;
    private readonly ILogger<AzureKeyVaultKeyManagementService> _logger;

    public AzureKeyVaultKeyManagementService(
        IAzureKeyVaultClientFactory clientFactory,
        IAzureKeyVaultResiliencePolicy resiliencePolicy,
        IKeyRepository keyRepository,
        ILogger<AzureKeyVaultKeyManagementService> logger)
    {
        _clientFactory = clientFactory;
        _resiliencePolicy = resiliencePolicy;
        _keyRepository = keyRepository;
        _logger = logger;
    }

    public async Task<GenerateKeyResponse> GenerateKeyAsync(
        GenerateKeyRequest request,
        string correlationId,
        CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();
        
        try
        {
            _logger.LogInformation("Starting key generation for {KeyId} with algorithm {Algorithm}",
                request.KeyId, request.Algorithm);

            var client = _clientFactory.CreateKeyClient();
            var pipeline = _resiliencePolicy.GetPipeline<Response<KeyVaultKey>>();

            // Create the key creation options based on algorithm
            var createKeyOptions = CreateKeyOptions(request);
            
            // Generate the key in Azure Key Vault
            var response = await pipeline.ExecuteAsync(async (ct) =>
                await client.CreateKeyAsync(request.KeyId, createKeyOptions.KeyType, createKeyOptions, ct), cancellationToken);

            if (response?.Value == null)
            {
                throw new InvalidOperationException("Failed to create key in Azure Key Vault");
            }

            var keyVaultKey = response.Value;

            // Extract public key data
            var publicKeyData = ExtractPublicKeyData(keyVaultKey);

            // Store metadata in our repository
            var metadata = new Models.KeyMetadataModel
            {
                KeyId = request.KeyId,
                Name = request.KeyId,
                Algorithm = request.Algorithm,
                Parameters = request.Parameters,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                Enabled = true,
                Tags = request.Tags.ToDictionary(kvp => kvp.Key, kvp => kvp.Value),
                Operations = GetOperationsForAlgorithm(request.Algorithm),
                PublicKeyData = publicKeyData
            };

            await _keyRepository.StoreKeyMetadataAsync(metadata, cancellationToken);

            _logger.LogInformation("Successfully generated key {KeyId} in {Duration}ms",
                request.KeyId, stopwatch.ElapsedMilliseconds);

            return new GenerateKeyResponse
            {
                KeyId = request.KeyId,
                Algorithm = request.Algorithm,
                Parameters = request.Parameters,
                PublicKey = ByteString.CopyFrom(publicKeyData),
                CreatedAt = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTime(DateTime.UtcNow)
            };
        }
        catch (RequestFailedException ex) when (ex.Status == 409)
        {
            _logger.LogWarning("Key {KeyId} already exists", request.KeyId);
            throw new InvalidOperationException($"Key {request.KeyId} already exists", ex);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to generate key {KeyId} after {Duration}ms",
                request.KeyId, stopwatch.ElapsedMilliseconds);
            throw;
        }
    }

    public async Task<GetKeyResponse> GetKeyAsync(
        GetKeyRequest request,
        string correlationId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInformation("Retrieving key {KeyId}", request.KeyId);

            var client = _clientFactory.CreateKeyClient();
            var pipeline = _resiliencePolicy.GetPipeline<Response<KeyVaultKey>>();

            var response = await pipeline.ExecuteAsync(async (ct) =>
                await client.GetKeyAsync(request.KeyId, cancellationToken: ct), cancellationToken);

            if (response?.Value == null)
            {
                throw new KeyNotFoundException($"Key {request.KeyId} not found");
            }

            var keyVaultKey = response.Value;

            // Get metadata from our repository
            var metadata = await _keyRepository.GetKeyMetadataAsync(request.KeyId, cancellationToken);

            var keyResponse = new GetKeyResponse
            {
                KeyId = request.KeyId,
                Algorithm = metadata?.Algorithm ?? MapKeyTypeToAlgorithm(keyVaultKey.KeyType),
                Parameters = metadata?.Parameters ?? CreateDefaultParameters(keyVaultKey),
                Enabled = keyVaultKey.Properties.Enabled ?? true,
                CreatedAt = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTime(
                    keyVaultKey.Properties.CreatedOn?.DateTime ?? DateTime.UtcNow),
                UpdatedAt = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTime(
                    keyVaultKey.Properties.UpdatedOn?.DateTime ?? DateTime.UtcNow)
            };

            // Add tags
            if (keyVaultKey.Properties.Tags != null)
            {
                foreach (var tag in keyVaultKey.Properties.Tags)
                {
                    keyResponse.Tags.Add(tag.Key, tag.Value);
                }
            }

            // Include public key if requested
            if (request.IncludePublicKey)
            {
                var publicKeyData = ExtractPublicKeyData(keyVaultKey);
                keyResponse.PublicKey = ByteString.CopyFrom(publicKeyData);
            }

            _logger.LogInformation("Successfully retrieved key {KeyId}", request.KeyId);
            return keyResponse;
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            _logger.LogWarning("Key {KeyId} not found", request.KeyId);
            throw new KeyNotFoundException($"Key {request.KeyId} not found", ex);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to retrieve key {KeyId}", request.KeyId);
            throw;
        }
    }

    public async Task<ListKeysResponse> ListKeysAsync(
        ListKeysRequest request,
        string correlationId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInformation("Listing keys with filter: {Filter}", request.Filter);

            var keys = await _keyRepository.ListKeysAsync(
                request.Filter,
                request.PageSize == 0 ? null : (int)request.PageSize,
                string.IsNullOrEmpty(request.PageToken) ? null : request.PageToken,
                request.IncludeDisabled,
                cancellationToken);

            var response = new ListKeysResponse();

            foreach (var key in keys)
            {
                var keyInfo = new KeyInfo
                {
                    KeyId = key.KeyId,
                    Algorithm = key.Algorithm,
                    Parameters = key.Parameters,
                    Enabled = key.Enabled,
                    CreatedAt = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTime(key.CreatedAt),
                    UpdatedAt = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTime(key.UpdatedAt)
                };

                foreach (var tag in key.Tags)
                {
                    keyInfo.Tags.Add(tag.Key, tag.Value);
                }

                response.Keys.Add(keyInfo);
            }

            // Generate next page token if we have more results
            if (request.PageSize > 0 && response.Keys.Count >= request.PageSize)
            {
                var nextOffset = GetOffsetFromPageToken(request.PageToken) + (int)request.PageSize;
                response.NextPageToken = await _keyRepository.GetNextPageTokenAsync(nextOffset, cancellationToken);
            }

            _logger.LogInformation("Listed {Count} keys", response.Keys.Count);
            return response;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to list keys");
            throw;
        }
    }

    public async Task<DeleteKeyResponse> DeleteKeyAsync(
        DeleteKeyRequest request,
        string correlationId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInformation("Deleting key {KeyId}", request.KeyId);

            var deleted = await _keyRepository.DeleteKeyMetadataAsync(request.KeyId, cancellationToken);

            if (!deleted)
            {
                throw new KeyNotFoundException($"Key {request.KeyId} not found");
            }

            _logger.LogInformation("Successfully deleted key {KeyId}", request.KeyId);

            return new DeleteKeyResponse
            {
                KeyId = request.KeyId,
                Success = true
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to delete key {KeyId}", request.KeyId);
            throw;
        }
    }

    private static CreateKeyOptions CreateKeyOptions(GenerateKeyRequest request)
    {
        var options = new CreateKeyOptions(KeyType.Rsa)
        {
            ExpiresOn = null,
            NotBefore = null,
            Enabled = true
        };

        // Set key operations
        var operations = GetOperationsForAlgorithm(request.Algorithm);
        foreach (var operation in operations)
        {
            options.KeyOperations.Add(MapOperationToKeyOperation(operation));
        }

        // Set algorithm-specific options
        switch (request.Algorithm)
        {
            case KeyAlgorithm.Rsa:
                options.KeyType = KeyType.Rsa;
                if (request.Parameters?.RsaParams != null)
                {
                    options.KeySize = (int)request.Parameters.RsaParams.KeySize;
                }
                break;

            case KeyAlgorithm.Ec:
                options.KeyType = KeyType.Ec;
                if (request.Parameters?.EccParams != null)
                {
                    options.CurveName = MapEcCurveToKeyVault(request.Parameters.EccParams.Curve);
                }
                break;

            default:
                throw new ArgumentException($"Unsupported algorithm: {request.Algorithm}");
        }

        // Add tags
        foreach (var tag in request.Tags)
        {
            options.Tags.Add(tag.Key, tag.Value);
        }

        return options;
    }

    private static byte[] ExtractPublicKeyData(KeyVaultKey key)
    {
        return key.KeyType switch
        {
            KeyType.Rsa or KeyType.RsaHsm => key.Key.ToRSA()?.ExportRSAPublicKey() ?? Array.Empty<byte>(),
            KeyType.Ec or KeyType.EcHsm => key.Key.ToECDsa()?.ExportSubjectPublicKeyInfo() ?? Array.Empty<byte>(),
            _ => Array.Empty<byte>()
        };
    }

    private static List<string> GetOperationsForAlgorithm(KeyAlgorithm algorithm)
    {
        return algorithm switch
        {
            KeyAlgorithm.Rsa => new List<string> { "sign", "verify", "encrypt", "decrypt" },
            KeyAlgorithm.Ec => new List<string> { "sign", "verify" },
            _ => new List<string> { "sign", "verify" }
        };
    }

    private static KeyOperation MapOperationToKeyOperation(string operation)
    {
        return operation.ToLowerInvariant() switch
        {
            "sign" => KeyOperation.Sign,
            "verify" => KeyOperation.Verify,
            "encrypt" => KeyOperation.Encrypt,
            "decrypt" => KeyOperation.Decrypt,
            _ => KeyOperation.Sign
        };
    }

    private static KeyCurveName MapEcCurveToKeyVault(ECCCurve curve)
    {
        return curve switch
        {
            ECCCurve.P256 => KeyCurveName.P256,
            ECCCurve.P384 => KeyCurveName.P384,
            ECCCurve.P521 => KeyCurveName.P521,
            _ => KeyCurveName.P256
        };
    }

    private static KeyAlgorithm MapKeyTypeToAlgorithm(KeyType keyType)
    {
        return keyType switch
        {
            KeyType.Rsa or KeyType.RsaHsm => KeyAlgorithm.Rsa,
            KeyType.Ec or KeyType.EcHsm => KeyAlgorithm.Ec,
            _ => KeyAlgorithm.Rsa
        };
    }

    private static KeyParameters CreateDefaultParameters(KeyVaultKey key)
    {
        return key.KeyType switch
        {
            KeyType.Rsa or KeyType.RsaHsm => new KeyParameters
            {
                RsaParams = new RsaParameters
                {
                    KeySize = (RsaKeySize)(key.Key.ToRSA()?.KeySize ?? 2048)
                }
            },
            KeyType.Ec or KeyType.EcHsm => new KeyParameters
            {
                EccParams = new EccParameters
                {
                    Curve = key.Key.CurveName switch
                    {
                        KeyCurveName.P256 => ECCCurve.P256,
                        KeyCurveName.P384 => ECCCurve.P384,
                        KeyCurveName.P521 => ECCCurve.P521,
                        _ => ECCCurve.P256
                    }
                }
            },
            _ => new KeyParameters()
        };
    }

    private static int GetOffsetFromPageToken(string? pageToken)
    {
        if (string.IsNullOrEmpty(pageToken))
            return 0;

        try
        {
            var tokenBytes = Convert.FromBase64String(pageToken);
            var tokenString = System.Text.Encoding.UTF8.GetString(tokenBytes);
            return int.TryParse(tokenString, out var offset) ? offset : 0;
        }
        catch
        {
            return 0;
        }
    }
}