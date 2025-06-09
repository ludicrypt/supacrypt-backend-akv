using Azure;
using Azure.Security.KeyVault.Keys;
using Supacrypt.Backend.Models;
using Supacrypt.Backend.Services.Interfaces;
using Supacrypt.V1;
using System.Text;
using System.Text.Json;

namespace Supacrypt.Backend.Services.Azure;

public class AzureKeyVaultKeyRepository : IKeyRepository
{
    private readonly IAzureKeyVaultClientFactory _clientFactory;
    private readonly IAzureKeyVaultResiliencePolicy _resiliencePolicy;
    private readonly ILogger<AzureKeyVaultKeyRepository> _logger;

    public AzureKeyVaultKeyRepository(
        IAzureKeyVaultClientFactory clientFactory,
        IAzureKeyVaultResiliencePolicy resiliencePolicy,
        ILogger<AzureKeyVaultKeyRepository> logger)
    {
        _clientFactory = clientFactory;
        _resiliencePolicy = resiliencePolicy;
        _logger = logger;
    }

    public async Task<KeyMetadataModel?> GetKeyMetadataAsync(
        string keyId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var client = _clientFactory.CreateKeyClient();
            var pipeline = _resiliencePolicy.GetPipeline<Response<KeyVaultKey>>();

            var response = await pipeline.ExecuteAsync(async (ct) =>
                await client.GetKeyAsync(keyId, cancellationToken: ct), cancellationToken);

            if (response?.Value == null)
            {
                _logger.LogWarning("Key not found: {KeyId}", keyId);
                return null;
            }

            return MapToKeyMetadata(response.Value);
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            _logger.LogWarning("Key not found: {KeyId}", keyId);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving key metadata for key: {KeyId}", keyId);
            throw;
        }
    }

    public async Task<IEnumerable<KeyMetadataModel>> ListKeysAsync(
        string? filter = null,
        int? pageSize = null,
        string? pageToken = null,
        bool includeDisabled = false,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var client = _clientFactory.CreateKeyClient();
            var pipeline = _resiliencePolicy.GetPipeline<AsyncPageable<KeyProperties>>();

            var properties = await pipeline.ExecuteAsync<AsyncPageable<KeyProperties>>((ct) =>
                new ValueTask<AsyncPageable<KeyProperties>>(client.GetPropertiesOfKeysAsync(cancellationToken: ct)), cancellationToken);

            var keys = new List<KeyMetadataModel>();
            var skipCount = GetSkipCountFromPageToken(pageToken);
            var currentCount = 0;
            var addedCount = 0;

            await foreach (var keyProperty in properties.WithCancellation(cancellationToken))
            {
                if (currentCount < skipCount)
                {
                    currentCount++;
                    continue;
                }

                if (pageSize.HasValue && addedCount >= pageSize.Value)
                {
                    break;
                }

                // Apply filtering
                if (!string.IsNullOrEmpty(filter) &&
                    !keyProperty.Name.Contains(filter, StringComparison.OrdinalIgnoreCase))
                {
                    currentCount++;
                    continue;
                }

                // Apply enabled filter
                if (!includeDisabled && !keyProperty.Enabled.GetValueOrDefault(true))
                {
                    currentCount++;
                    continue;
                }

                try
                {
                    var keyPipeline = _resiliencePolicy.GetPipeline<Response<KeyVaultKey>>();
                    var keyResponse = await keyPipeline.ExecuteAsync(async (ct) =>
                        await client.GetKeyAsync(keyProperty.Name, cancellationToken: ct), cancellationToken);

                    if (keyResponse?.Value != null)
                    {
                        keys.Add(MapToKeyMetadata(keyResponse.Value));
                        addedCount++;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to retrieve key details for: {KeyName}", keyProperty.Name);
                }

                currentCount++;
            }

            return keys;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error listing keys with filter: {Filter}", filter);
            throw;
        }
    }

    public async Task<KeyMetadataModel> StoreKeyMetadataAsync(
        KeyMetadataModel metadata,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var client = _clientFactory.CreateKeyClient();
            var pipeline = _resiliencePolicy.GetPipeline<Response<KeyVaultKey>>();

            // Azure Key Vault doesn't support storing arbitrary metadata,
            // but we can use tags to store some information
            var tags = new Dictionary<string, string>(metadata.Tags)
            {
                ["supacrypt_algorithm"] = metadata.Algorithm.ToString(),
                ["supacrypt_created_at"] = metadata.CreatedAt.ToString("O"),
                ["supacrypt_updated_at"] = metadata.UpdatedAt.ToString("O"),
                ["supacrypt_enabled"] = metadata.Enabled.ToString(),
                ["supacrypt_operations"] = JsonSerializer.Serialize(metadata.Operations)
            };

            // Get the existing key to update its tags
            var response = await pipeline.ExecuteAsync(async (ct) =>
                await client.GetKeyAsync(metadata.KeyId, cancellationToken: ct), cancellationToken);

            if (response?.Value != null)
            {
                // Update key properties with new tags
                var keyProperties = new KeyProperties(metadata.KeyId)
                {
                    Enabled = metadata.Enabled
                };
                
                // Add tags to the properties
                foreach (var tag in tags)
                {
                    keyProperties.Tags[tag.Key] = tag.Value;
                }

                await pipeline.ExecuteAsync(async (ct) =>
                    await client.UpdateKeyPropertiesAsync(keyProperties, cancellationToken: ct), cancellationToken);

                _logger.LogInformation("Updated key metadata for: {KeyId}", metadata.KeyId);
                return metadata;
            }
            else
            {
                _logger.LogWarning("Cannot store metadata for non-existent key: {KeyId}", metadata.KeyId);
                throw new InvalidOperationException($"Key {metadata.KeyId} does not exist");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error storing key metadata for key: {KeyId}", metadata.KeyId);
            throw;
        }
    }

    public async Task<bool> DeleteKeyMetadataAsync(
        string keyId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var client = _clientFactory.CreateKeyClient();
            var pipeline = _resiliencePolicy.GetPipeline<DeleteKeyOperation>();

            // Start the delete operation (soft delete)
            var deleteOperation = await pipeline.ExecuteAsync(async (ct) =>
                await client.StartDeleteKeyAsync(keyId, cancellationToken: ct), cancellationToken);

            // Wait for the deletion to complete
            await deleteOperation.WaitForCompletionAsync(cancellationToken);

            _logger.LogInformation("Successfully deleted key: {KeyId}", keyId);
            return true;
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            _logger.LogWarning("Key not found for deletion: {KeyId}", keyId);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting key: {KeyId}", keyId);
            throw;
        }
    }

    public async Task<bool> KeyExistsAsync(
        string keyId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var client = _clientFactory.CreateKeyClient();
            var pipeline = _resiliencePolicy.GetPipeline<Response<KeyVaultKey>>();

            var response = await pipeline.ExecuteAsync(async (ct) =>
                await client.GetKeyAsync(keyId, cancellationToken: ct), cancellationToken);

            return response?.Value != null;
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking key existence: {KeyId}", keyId);
            throw;
        }
    }

    public Task<string> GetNextPageTokenAsync(
        int offset,
        CancellationToken cancellationToken = default)
    {
        // Create a base64-encoded token for pagination
        var tokenBytes = Encoding.UTF8.GetBytes(offset.ToString());
        var token = Convert.ToBase64String(tokenBytes);
        return Task.FromResult(token);
    }

    private static KeyMetadataModel MapToKeyMetadata(KeyVaultKey key)
    {
        var metadata = new KeyMetadataModel
        {
            KeyId = key.Name,
            Name = key.Name,
            CreatedAt = key.Properties.CreatedOn?.DateTime ?? DateTime.UtcNow,
            UpdatedAt = key.Properties.UpdatedOn?.DateTime ?? DateTime.UtcNow,
            Enabled = key.Properties.Enabled ?? true,
            Tags = new Dictionary<string, string>(key.Properties.Tags ?? new Dictionary<string, string>()),
            PublicKeyData = key.Key.ToRSA()?.ExportRSAPublicKey() ?? key.Key.ToECDsa()?.ExportSubjectPublicKeyInfo()
        };

        // Map Azure Key Vault key type to our algorithm enum
        if (key.KeyType == KeyType.Rsa || key.KeyType == KeyType.RsaHsm)
        {
            metadata.Algorithm = KeyAlgorithm.Rsa;
        }
        else if (key.KeyType == KeyType.Ec || key.KeyType == KeyType.EcHsm)
        {
            metadata.Algorithm = KeyAlgorithm.Ecc;
        }
        else
        {
            metadata.Algorithm = KeyAlgorithm.Rsa;
        }

        // Extract metadata from tags
        if (metadata.Tags.TryGetValue("supacrypt_algorithm", out var algorithmTag) &&
            Enum.TryParse<KeyAlgorithm>(algorithmTag, out var algorithm))
        {
            metadata.Algorithm = algorithm;
        }

        if (metadata.Tags.TryGetValue("supacrypt_operations", out var operationsTag))
        {
            try
            {
                var operations = JsonSerializer.Deserialize<List<string>>(operationsTag);
                if (operations != null)
                {
                    metadata.Operations = operations;
                }
            }
            catch
            {
                // Fallback to default operations
                metadata.Operations = GetDefaultOperationsForKeyType(key.KeyType);
            }
        }
        else
        {
            metadata.Operations = GetDefaultOperationsForKeyType(key.KeyType);
        }

        // Set key parameters based on key type
        metadata.Parameters = CreateKeyParameters(key);

        return metadata;
    }

    private static List<string> GetDefaultOperationsForKeyType(KeyType keyType)
    {
        if (keyType == KeyType.Rsa || keyType == KeyType.RsaHsm)
        {
            return new List<string> { "sign", "verify", "encrypt", "decrypt" };
        }
        else if (keyType == KeyType.Ec || keyType == KeyType.EcHsm)
        {
            return new List<string> { "sign", "verify" };
        }
        else
        {
            return new List<string> { "sign", "verify" };
        }
    }

    private static KeyParameters CreateKeyParameters(KeyVaultKey key)
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
            return new KeyParameters
            {
                EccParams = new ECCParameters
                {
                    Curve = MapEcCurve(key.Key.CurveName)
                }
            };
        }
        else
        {
            return new KeyParameters();
        }
    }

    private static ECCCurve MapEcCurve(KeyCurveName? curveName)
    {
        if (curveName == KeyCurveName.P256)
        {
            return ECCCurve.P256;
        }
        else if (curveName == KeyCurveName.P384)
        {
            return ECCCurve.P384;
        }
        else if (curveName == KeyCurveName.P521)
        {
            return ECCCurve.P521;
        }
        else
        {
            return ECCCurve.P256;
        }
    }

    private static int GetSkipCountFromPageToken(string? pageToken)
    {
        if (string.IsNullOrEmpty(pageToken))
            return 0;

        try
        {
            var tokenBytes = Convert.FromBase64String(pageToken);
            var tokenString = Encoding.UTF8.GetString(tokenBytes);
            return int.TryParse(tokenString, out var offset) ? offset : 0;
        }
        catch
        {
            return 0;
        }
    }
}