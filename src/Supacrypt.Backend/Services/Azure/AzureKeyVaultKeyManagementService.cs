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
                request.Name, request.Algorithm);

            var client = _clientFactory.CreateKeyClient();
            var pipeline = _resiliencePolicy.GetPipeline<Response<KeyVaultKey>>();

            // Create the key creation options based on algorithm
            var (keyType, createKeyOptions) = CreateKeyOptions(request);
            
            // Generate the key in Azure Key Vault
            var response = await pipeline.ExecuteAsync(async (ct) =>
                await client.CreateKeyAsync(request.Name, keyType, createKeyOptions, ct), cancellationToken);

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
                KeyId = request.Name,
                Name = request.Name,
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
                request.Name, stopwatch.ElapsedMilliseconds);

            return new GenerateKeyResponse
            {
                Success = new GenerateKeySuccess
                {
                    Metadata = new KeyMetadata
                    {
                        Name = request.Name,
                        Algorithm = request.Algorithm,
                        Parameters = request.Parameters,
                        CreatedAt = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTime(DateTime.UtcNow),
                        UpdatedAt = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTime(DateTime.UtcNow),
                        Enabled = true
                    },
                    PublicKey = new PublicKey
                    {
                        Algorithm = request.Algorithm,
                        KeyData = ByteString.CopyFrom(publicKeyData),
                        Parameters = request.Parameters
                    }
                }
            };
        }
        catch (RequestFailedException ex) when (ex.Status == 409)
        {
            _logger.LogWarning("Key {KeyId} already exists", request.Name);
            throw new InvalidOperationException($"Key {request.Name} already exists", ex);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to generate key {KeyId} after {Duration}ms",
                request.Name, stopwatch.ElapsedMilliseconds);
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
                Success = new GetKeySuccess
                {
                    Metadata = new KeyMetadata
                    {
                        Name = request.KeyId,
                        Algorithm = metadata?.Algorithm ?? MapKeyTypeToAlgorithm(keyVaultKey.KeyType),
                        Parameters = metadata?.Parameters ?? CreateDefaultParameters(keyVaultKey),
                        Enabled = keyVaultKey.Properties.Enabled ?? true,
                        CreatedAt = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTime(
                            keyVaultKey.Properties.CreatedOn?.DateTime ?? DateTime.UtcNow),
                        UpdatedAt = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTime(
                            keyVaultKey.Properties.UpdatedOn?.DateTime ?? DateTime.UtcNow)
                    }
                }
            };

            // Add tags
            if (keyVaultKey.Properties.Tags != null)
            {
                foreach (var tag in keyVaultKey.Properties.Tags)
                {
                    keyResponse.Success.Metadata.Tags.Add(tag.Key, tag.Value);
                }
            }

            // Include public key if requested
            if (request.IncludePublicKey)
            {
                var publicKeyData = ExtractPublicKeyData(keyVaultKey);
                keyResponse.Success.PublicKey = new PublicKey
                {
                    Algorithm = keyResponse.Success.Metadata.Algorithm,
                    KeyData = ByteString.CopyFrom(publicKeyData),
                    Parameters = keyResponse.Success.Metadata.Parameters
                };
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

            var keyMetadataList = new List<KeyMetadata>();

            foreach (var key in keys)
            {
                var keyMetadata = new KeyMetadata
                {
                    Name = key.KeyId,
                    Algorithm = key.Algorithm,
                    Parameters = key.Parameters,
                    Enabled = key.Enabled,
                    CreatedAt = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTime(key.CreatedAt),
                    UpdatedAt = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTime(key.UpdatedAt)
                };

                foreach (var tag in key.Tags)
                {
                    keyMetadata.Tags.Add(tag.Key, tag.Value);
                }

                keyMetadataList.Add(keyMetadata);
            }

            var response = new ListKeysResponse
            {
                Success = new ListKeysSuccess()
            };

            response.Success.Keys.AddRange(keyMetadataList);

            // Generate next page token if we have more results
            if (request.PageSize > 0 && keyMetadataList.Count >= request.PageSize)
            {
                var nextOffset = GetOffsetFromPageToken(request.PageToken) + (int)request.PageSize;
                response.Success.NextPageToken = await _keyRepository.GetNextPageTokenAsync(nextOffset, cancellationToken);
            }

            _logger.LogInformation("Listed {Count} keys", keyMetadataList.Count);
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
                Success = new DeleteKeySuccess
                {
                    KeyId = request.KeyId,
                    DeletedAt = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTime(DateTime.UtcNow)
                }
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to delete key {KeyId}", request.KeyId);
            throw;
        }
    }

    private static (KeyType keyType, CreateKeyOptions options) CreateKeyOptions(GenerateKeyRequest request)
    {
        KeyType keyType = request.Algorithm switch
        {
            KeyAlgorithm.Rsa => KeyType.Rsa,
            KeyAlgorithm.Ecc => KeyType.Ec,
            KeyAlgorithm.Ecdsa => KeyType.Ec,
            _ => KeyType.Rsa
        };

        var options = new CreateKeyOptions
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
                if (request.Parameters?.RsaParams != null)
                {
                    // Note: Azure Key Vault uses RSA key sizes directly, not the CreateKeyOptions.KeySize
                    // The key size is typically set in the RSA-specific creation parameters
                }
                break;

            case KeyAlgorithm.Ecc:
            case KeyAlgorithm.Ecdsa:
                if (request.Parameters?.EccParams != null)
                {
                    // Note: Azure Key Vault uses CurveName in the EC-specific creation parameters
                    // This will be set when creating EC keys
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

        return (keyType, options);
    }

    private static byte[] ExtractPublicKeyData(KeyVaultKey key)
    {
        if (key.KeyType == KeyType.Rsa || key.KeyType == KeyType.RsaHsm)
        {
            return key.Key.ToRSA()?.ExportRSAPublicKey() ?? Array.Empty<byte>();
        }
        else if (key.KeyType == KeyType.Ec || key.KeyType == KeyType.EcHsm)
        {
            return key.Key.ToECDsa()?.ExportSubjectPublicKeyInfo() ?? Array.Empty<byte>();
        }
        else
        {
            return Array.Empty<byte>();
        }
    }

    private static List<string> GetOperationsForAlgorithm(KeyAlgorithm algorithm)
    {
        return algorithm switch
        {
            KeyAlgorithm.Rsa => new List<string> { "sign", "verify", "encrypt", "decrypt" },
            KeyAlgorithm.Ecc => new List<string> { "sign", "verify" },
            KeyAlgorithm.Ecdsa => new List<string> { "sign", "verify" },
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
        if (keyType == KeyType.Rsa || keyType == KeyType.RsaHsm)
        {
            return KeyAlgorithm.Rsa;
        }
        else if (keyType == KeyType.Ec || keyType == KeyType.EcHsm)
        {
            return KeyAlgorithm.Ecc;
        }
        else
        {
            return KeyAlgorithm.Rsa;
        }
    }

    private static KeyParameters CreateDefaultParameters(KeyVaultKey key)
    {
        if (key.KeyType == KeyType.Rsa || key.KeyType == KeyType.RsaHsm)
        {
            return new KeyParameters
            {
                RsaParams = new RSAParameters
                {
                    KeySize = (RSAKeySize)(key.Key.ToRSA()?.KeySize ?? 2048)
                }
            };
        }
        else if (key.KeyType == KeyType.Ec || key.KeyType == KeyType.EcHsm)
        {
            ECCCurve curve;
            if (key.Key.CurveName == KeyCurveName.P256)
            {
                curve = ECCCurve.P256;
            }
            else if (key.Key.CurveName == KeyCurveName.P384)
            {
                curve = ECCCurve.P384;
            }
            else if (key.Key.CurveName == KeyCurveName.P521)
            {
                curve = ECCCurve.P521;
            }
            else
            {
                curve = ECCCurve.P256;
            }

            return new KeyParameters
            {
                EccParams = new ECCParameters
                {
                    Curve = curve
                }
            };
        }
        else
        {
            return new KeyParameters();
        }
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